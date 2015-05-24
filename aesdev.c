/* ZSO 2014/2015 Zadanie 2
   Hubert Tarasiuk  */

#include "aesdev.h"

#include <linux/module.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <asm/uaccess.h>
#include <linux/spinlock_types.h>
#include <asm/spinlock_types.h>
#include <asm/spinlock.h>

MODULE_LICENSE ("GPL");

static int major; /* Dynamically assigned major number */
static struct class *dev_class; /* Sysfs class */
static aes128_dev *aes_devs[AESDRV_MAX_DEV_COUNT]; /* Map minor number to device.  */

/* Module should be fail-safe in multi-threading access, therefore I need
   to assure that my context has not been deleted after I entered read/write/ioctl
   handler but before I acquire proper context-related mutex.
   Therefore I use this mutex to atomically check that the context has not been
   deleted and then to acquire context-related mutex.  */
DEFINE_MUTEX (context_erase_mutex);

/* This mutex is used to atomically remove a device and to atomically (check
   that a device exits and create new context). It is also used for open file
   lists on aes devices.  */
DEFINE_MUTEX (dev_remove_mutex);

/*** Kernel structs **********************************************************/
const static struct file_operations aes_fops = {
  .owner = THIS_MODULE,
  .read = file_read,
  .write = file_write,
  .open = file_open,
  .release = file_release,
  .unlocked_ioctl = file_ioctl,
  .compat_ioctl = file_ioctl,
  .llseek = no_llseek
};
const static struct pci_device_id pci_ids[] = {
  {PCI_DEVICE (AESDEV_VENDOR_ID, AESDEV_DEVICE_ID)},
  {0}
};
static struct pci_driver aes_pci = {
  .name = "aesdev",
  .id_table = pci_ids,
  .probe = pci_probe,
  .remove = pci_remove,
  .shutdown = pci_shutdown
};
/*****************************************************************************/

/*** Helpers *****************************************************************/
static void
task_init (aes128_task *task)
{
  memset (task, 0, sizeof (aes128_task));
  INIT_LIST_HEAD (&task->task_list);
}

static void
task_destroy (aes128_task *task) { }

/* Pick completed tasks from device and return total size of data
   available to read by user.  */
static size_t
__move_completed_tasks (aes128_context *context)
{
  aes128_task *task, *temp_task;
  unsigned long flags;
  struct list_head my_tasks;

  DNOTIF_ENTER_FUN;
  might_sleep ();

  INIT_LIST_HEAD (&my_tasks);

  /*** CRITICAL SECTION ****/
  spin_lock_irqsave (&context->aes_dev->lock, flags);

  list_for_each_entry_safe (task,
                            temp_task,
                            &context->aes_dev->completed_list_head,
                            task_list)
  {
    /* Move my tasks to my list.  */
    if (task->context == context)
      {
        list_del (&task->task_list);
        list_add_tail (&task->task_list, &my_tasks);
      }
  }
  spin_unlock_irqrestore (&context->aes_dev->lock, flags);

  /*** END CRITICAL SECTION ****/

  list_for_each_entry_safe (task, temp_task, &my_tasks, task_list)
  {
    KDEBUG ("moving task %p at %d\n", task, task->cmd_index);

    context->buffer.write_tail += task->block_count * sizeof (aes128_block);
    context->buffer.write_tail %= AESDRV_IOBUFF_SIZE;

    context->buffer.read_count += task->block_count * sizeof (aes128_block);
    context->buffer.write_count -= task->block_count * sizeof (aes128_block);
    assert (context->buffer.write_count >= 0);

    assert (context->buffer.read_count > 0
            && context->buffer.read_count <= AESDRV_IOBUFF_SIZE);

    assert (context->buffer.write_count >= 0
            && context->buffer.write_count <= AESDRV_IOBUFF_SIZE);

    list_del (&task->task_list);
    task_destroy (task);
    kfree (task);
  }

  KDEBUG ("returning %d\n", acb_read_count (&context->buffer));

  DNOTIF_LEAVE_FUN;
  return acb_read_count (&context->buffer);
}

static size_t
move_completed_tasks (aes128_context *context)
{
  size_t ret;
  might_sleep ();
  mutex_lock (&context->buffer.common_lock);
  ret = __move_completed_tasks (context);
  mutex_unlock (&context->buffer.common_lock);
  return ret;
}

/* Do NOT use this function without spinlock.  */
__must_check static size_t
__free_task_slots (aes128_dev *aes_dev)
{
  /* I need at least 2 free slots to distinguish all possible situations.  */
  return AESDRV_CMDBUFF_SLOTS - aes_dev->tasks_in_progress - 2;
}

__must_check static size_t
free_task_slots (aes128_dev *aes_dev)
{
  unsigned long irq_flags;
  size_t ret;

  spin_lock_irqsave (&aes_dev->lock, irq_flags);
  ret = __free_task_slots (aes_dev);
  spin_unlock_irqrestore (&aes_dev->lock, irq_flags);

  return ret;
}

__must_check static int
mut_mode (aes128_context *context)
{
  int retval;
  mutex_lock (&context->buffer.common_lock);
  retval = context->mode;
  mutex_unlock (&context->buffer.common_lock);
  return retval;
}
/*****************************************************************************/

/*** AES context *************************************************************/
__must_check static int
context_init (aes128_context *context, aes128_dev *aes_dev)
{
  dma_addr_t temp_dma_addr;
  int ret;

  DNOTIF_ENTER_FUN;

  memset (context, 0, sizeof (aes128_context));

  ret = acb_init (&context->buffer, aes_dev);
  if (IS_ERR_VALUE (ret))
    {
      printk (KERN_WARNING "acb_init\n");
      return ret;
    }

  context->mode = AESDEV_MODE_UNDEF;
  context->aes_dev = aes_dev;
  context->ks_buffer.k_ptr = dma_alloc_coherent (&aes_dev->pci_dev->dev,
                                                 2 * sizeof (aes128_block),
                                                 &temp_dma_addr, GFP_KERNEL);
  context->ks_buffer.d_ptr = temp_dma_addr;
  if (context->ks_buffer.k_ptr == NULL)
    {
      acb_destroy (&context->buffer, aes_dev);
      DNOTIF_LEAVE_FUN;
      return -ENOMEM;
    }

  INIT_LIST_HEAD (&context->lf.file_list);
  list_add_tail (&context->lf.file_list, &aes_dev->file_list_head);

  return 0;
  DNOTIF_LEAVE_FUN;
}

static void
context_destroy (aes128_context *context)
{
  DNOTIF_ENTER_FUN;
  might_sleep ();

  dma_free_coherent (&context->aes_dev->pci_dev->dev,
                     2 * sizeof (aes128_block),
                     context->ks_buffer.k_ptr,
                     context->ks_buffer.d_ptr);

  acb_destroy (&context->buffer, context->aes_dev);

  mutex_lock (&dev_remove_mutex);
  list_del (&context->lf.file_list);
  mutex_unlock (&dev_remove_mutex);

  DNOTIF_LEAVE_FUN;
}

__must_check static inline size_t
__context_busy (aes128_context *context)
{
  DNOTIF_ENTER_FUN;
  __move_completed_tasks (context);
  KDEBUG ("returning %zu write=%d toenc=%d read=%d\n",
          context->buffer.write_count - context->buffer.to_encrypt_count,
          context->buffer.write_count,
          context->buffer.to_encrypt_count,
          context->buffer.read_count);
  DNOTIF_LEAVE_FUN;
  /* How many bytes are currently being encrypted at the device?  */
  return context->buffer.write_count - context->buffer.to_encrypt_count;
}

__must_check static size_t
context_busy (aes128_context *context)
{
  size_t ret;
  DNOTIF_ENTER_FUN;
  might_sleep ();
  mutex_lock (&context->buffer.common_lock);
  ret = __context_busy (context);
  mutex_unlock (&context->buffer.common_lock);
  DNOTIF_LEAVE_FUN;
  return ret;
}
/*****************************************************************************/

/*** Combo buffer ************************************************************/
__must_check static int
acb_init (aes128_combo_buffer *buffer, aes128_dev *aes_dev)
{
  dma_addr_t tmp_dma_addr;

  DNOTIF_ENTER_FUN;
  might_sleep ();

  memset (buffer, 0, sizeof (aes128_combo_buffer));

  /* Start with allocation to avoid cleanup on failure later.  */
  buffer->data.k_ptr = dma_alloc_coherent (&aes_dev->pci_dev->dev,
                                           AESDRV_IOBUFF_SIZE,
                                           &tmp_dma_addr,
                                           GFP_KERNEL);
  if (buffer->data.k_ptr == NULL)
    return -ENOMEM;
  buffer->data.d_ptr = tmp_dma_addr;

  mutex_init (&buffer->read_lock);
  mutex_init (&buffer->write_lock);
  mutex_init (&buffer->common_lock);

  init_waitqueue_head (&buffer->read_queue);
  init_waitqueue_head (&buffer->write_queue);

  DNOTIF_LEAVE_FUN;
  return 0;
}

static void
acb_destroy (aes128_combo_buffer *buffer, aes128_dev *aes_dev)
{
  DNOTIF_ENTER_FUN;
  might_sleep ();

  mutex_destroy (&buffer->read_lock);
  mutex_destroy (&buffer->write_lock);
  mutex_destroy (&buffer->common_lock);

  dma_free_coherent (&aes_dev->pci_dev->dev,
                     AESDRV_IOBUFF_SIZE,
                     buffer->data.k_ptr,
                     buffer->data.d_ptr);

  DNOTIF_LEAVE_FUN;
}

__must_check static inline size_t
acb_read_count (const aes128_combo_buffer *buffer)
{
  return buffer->read_count;
}

__must_check static inline size_t
acb_write_count (const aes128_combo_buffer *buffer)
{
  return buffer->write_count;
}

__must_check static inline size_t
acb_write_count_to_end (const aes128_combo_buffer *buffer)
{
  if (buffer->write_tail + buffer->write_count <= AESDRV_IOBUFF_SIZE)
    return buffer->write_count;
  return AESDRV_IOBUFF_SIZE - buffer->write_tail;
}

__must_check static inline size_t
acb_to_encrypt_count_to_end (const aes128_combo_buffer *buffer)
{
  if (buffer->to_encrypt_tail + buffer->to_encrypt_count <= AESDRV_IOBUFF_SIZE)
    return buffer->to_encrypt_count;
  return AESDRV_IOBUFF_SIZE - buffer->to_encrypt_tail;
}

__must_check static inline size_t
acb_free (const aes128_combo_buffer *buffer)
{
  return AESDRV_IOBUFF_SIZE - buffer->write_count - buffer->read_count;
}

__must_check static size_t
mut_acb_free (aes128_combo_buffer *buffer)
{
  size_t ret;
  mutex_lock (&buffer->common_lock);
  ret = acb_free (buffer);
  mutex_unlock (&buffer->common_lock);
  return ret;
}

__must_check static size_t
acb_free_to_end (const aes128_combo_buffer *buffer)
{
  if (buffer->read_tail == buffer->write_head)
    {
      if (buffer->write_count == 0 && buffer->read_count == 0)
        return AESDRV_IOBUFF_SIZE - buffer->write_head;
      else
        return 0;
    }
  if (buffer->read_tail < buffer->write_head)
    return AESDRV_IOBUFF_SIZE - buffer->write_head;
  else
    return buffer->read_tail - buffer->write_head;
}

__must_check static inline size_t
acb_read_count_to_end (const aes128_combo_buffer *buffer)
{
  if (buffer->read_tail + buffer->read_count <= AESDRV_IOBUFF_SIZE)
    return buffer->read_count;
  return AESDRV_IOBUFF_SIZE - buffer->read_tail;
}
/*****************************************************************************/

/*** Irq handlers ************************************************************/
static irqreturn_t
irq_handler (int irq, void *ptr)
{
  aes128_dev *aes_dev;
  aes128_task *task, *temp_task;
  uint8_t intr;
  uint32_t read_index;
  unsigned long irq_flags;
  char dev_running;

  aes_dev = ptr;

  /*** CRITICAL SECTION ***/
  spin_lock_irqsave (&aes_dev->lock, irq_flags);
  intr = ioread32 (aes_dev->bar0 + AESDEV_INTR) & 0xFF;
  if (!intr)
    {
      spin_unlock_irqrestore (&aes_dev->lock, irq_flags);
      return IRQ_NONE;
    }
  /* All current interrupts will be handled.  */
  iowrite32 (intr, aes_dev->bar0 + AESDEV_INTR);
  /* Check if the device is still running.
     If it is running, it might stop during this handler, but I have written
     to interrupt register before this check, so the interrupt handler would
     be run again.
     If it is not running, it will not start during this handler (spin lock).  */
  dev_running = !!(ioread32 (aes_dev->bar0 + AESDEV_STATUS) & 0x03);

  /* Get the instruction pointer. If it would increase during this handler, it
     would mean that the device is still running, so it will fire another after
     it finishes next command.  */
  read_index = AESDEV_CMD_INDEXOF (aes_dev->cmd_buffer.d_ptr,
                                   ioread32 (aes_dev->bar0 + AESDEV_CMD_READ_PTR));
  assert (read_index < AESDRV_CMDBUFF_SLOTS);

  /* Move completed tasks to completed tasks list.  */
  list_for_each_entry_safe (task, temp_task, &aes_dev->task_list_head, task_list)
  {
    /* Is this task completed?
       If the device is not running, it means that all tasks have been
       completed. Otherwise I keep iterating until I see uncompleted task.  */
    if (dev_running &&
        (task->cmd_index == read_index ||
         (task->cmd_index + 1) % AESDRV_CMDBUFF_SLOTS == read_index))
      break;

    list_del (&task->task_list);
    list_add_tail (&task->task_list, &aes_dev->completed_list_head);
    aes_dev->tasks_in_progress--;
    /* Notify processes waiting for read about new data.  */
    wake_up (&task->context->buffer.read_queue);
  }

  /* It was "my" interrupt, so at least one command has completed.
     Therefore, notify processes waiting for a slot in command queue.  */
  wake_up (&aes_dev->command_queue);

  spin_unlock_irqrestore (&aes_dev->lock, irq_flags);
  /*** END CRITICAL SECTION ***/
  return IRQ_HANDLED;
}
/*****************************************************************************/

/*** File handlers ***********************************************************/
static ssize_t
file_read (struct file *f, char __user *buf, size_t len, loff_t *off)
{
  aes128_context *context;
  size_t to_copy, to_copy1, to_copy2;
  ssize_t retval;
  int _ret_mutex;

  DNOTIF_ENTER_FUN;
  might_sleep ();

  _ret_mutex = mutex_lock_interruptible (&context_erase_mutex);
  if (_ret_mutex != 0)
    return _ret_mutex;
  context = f->private_data;

  if (context == NULL)
    {
      mutex_unlock (&context_erase_mutex);
      return -EBADFD;
    }

  /* read_lock is to provide mutual exclusion inside file_read
     common_lock is to protect context's io buffer */
  _ret_mutex = mutex_lock_interruptible (&context->buffer.read_lock);
  if (_ret_mutex != 0)
    {
      mutex_unlock (&context_erase_mutex);
      return _ret_mutex;
    }

  mutex_unlock (&context_erase_mutex);

  _ret_mutex = mutex_lock_interruptible (&context->buffer.common_lock);
  if (_ret_mutex != 0)
    {
      mutex_unlock (&context->buffer.read_lock);
      return _ret_mutex;
    }

  if (context->mode == AESDEV_MODE_CLOSING)
    {
      retval = -EBADFD;
      goto exit;
    }

  if (context->mode == AESDEV_MODE_UNDEF)
    {
      printk (KERN_WARNING "cannot read with no mode set\n");
      retval = -EINVAL;
      goto exit;
    }

  if (f->f_flags & O_NONBLOCK)
    {
      /* This will accept completed tasks from device and return total number
         of bytes ready to read.  */
      if (__move_completed_tasks (context) == 0)
        {
          KDEBUG ("no data, returning EAGAIN\n");
          retval = -EAGAIN;
          goto exit;
        }
    }
  else
    {
      /* This will accept completed tasks from device and return total number
         of bytes ready to read.  */
      while (__move_completed_tasks (context) == 0)
        {
          int _ret_queue;

          KDEBUG ("going to sleep :(\n");

          /* Let other processes tamper with my buffer, but do not let any
             other process enter read procedure (do not unlock read_lock).  */
          mutex_unlock (&context->buffer.common_lock);

          _ret_queue =
                  wait_event_interruptible (context->buffer.read_queue,
                                            mut_mode (context) == AESDEV_MODE_CLOSING
                                            || move_completed_tasks (context) != 0);
          if (_ret_queue != 0)
            {
              mutex_unlock (&context->buffer.read_lock);
              return _ret_queue;
            }

          _ret_mutex = mutex_lock_interruptible (&context->buffer.common_lock);
          if (_ret_mutex != 0)
            {
              mutex_unlock (&context->buffer.read_lock);
              return _ret_mutex;
            }

          if (context->mode == AESDEV_MODE_CLOSING)
            {
              KDEBUG ("closing in read\n");
              retval = -EBADFD;
              goto exit;
            }
        }
    }
  assert (acb_read_count (&context->buffer) > 0);

  /* to_copy1 -> continous copy from current read tail to end of buffer array
     to_copy2 -> the rest ie. from beginning of buffer array */
  to_copy = min (len, acb_read_count (&context->buffer));
  to_copy1 = min (to_copy, acb_read_count_to_end (&context->buffer));
  to_copy2 = to_copy - to_copy1;

  if (copy_to_user (buf,
                    context->buffer.data.k_ptr + context->buffer.read_tail,
                    to_copy1))
    {
      KDEBUG ("copy_to_user (1)\n");
      retval = -EFAULT;
      goto exit;
    }
  if (to_copy2 && copy_to_user (buf + to_copy1,
                                context->buffer.data.k_ptr,
                                to_copy2))
    {
      KDEBUG ("copy_to_user (2)\n");
      retval = -EFAULT;
      goto exit;
    }

  /* Update buffer pointers and counters.  */
  context->buffer.read_tail += to_copy;
  context->buffer.read_tail %= AESDRV_IOBUFF_SIZE;
  context->buffer.read_count -= to_copy;
  assert (context->buffer.read_count >= 0);

  /* Some space in io buffer was freed, perhaps someone is willing to
     write.  */
  wake_up (&context->buffer.write_queue);

  retval = to_copy;

exit:
  mutex_unlock (&context->buffer.common_lock);
  mutex_unlock (&context->buffer.read_lock);
  DNOTIF_LEAVE_FUN;
  return retval;
}

static ssize_t
file_write (struct file *f, const char __user *buf, size_t len, loff_t *off)
{
  aes128_context *context;
  void __iomem *bar0;
  ssize_t retval;
  size_t to_take;
  aes128_task *task;
  aes128_dev *aes_dev;
  aes128_command *cmd;
  dma_ptr cmd_ptr;
  unsigned long irq_flags;
  int _ret_mutex;

  DNOTIF_ENTER_FUN;
  might_sleep ();

  _ret_mutex = mutex_lock_interruptible (&context_erase_mutex);
  if (_ret_mutex != 0)
    return _ret_mutex;

  context = f->private_data;

  if (context == NULL)
    {
      mutex_unlock (&context_erase_mutex);
      return -EBADFD;
    }

  /* write_lock is to provide mutual exclusion inside file_write
     common_lock is to protect context's io buffer */
  _ret_mutex = mutex_lock_interruptible (&context->buffer.write_lock);
  if (_ret_mutex != 0)
    {
      mutex_unlock (&context_erase_mutex);
      return _ret_mutex;
    }

  mutex_unlock (&context_erase_mutex);

  _ret_mutex = mutex_lock_interruptible (&context->buffer.common_lock);
  if (_ret_mutex != 0)
    {
      mutex_unlock (&context->buffer.write_lock);
      return _ret_mutex;
    }

  aes_dev = context->aes_dev;
  bar0 = aes_dev->bar0;

  if (context->mode == AESDEV_MODE_CLOSING)
    {
      retval = -EBADFD;
      goto exit;
    }

  if (context->mode == AESDEV_MODE_UNDEF)
    {
      printk (KERN_WARNING "cannot write with no mode set\n");
      retval = -EINVAL;
      goto exit;
    }

  while (acb_free (&context->buffer) == 0)
    {
      if (f->f_flags & O_NONBLOCK)
        {
          KDEBUG ("no space in buffer => EAGAIN\n");
          retval = -EAGAIN;
          goto exit;
        }
      else
        {
          int _ret_queue;

          KDEBUG ("no space in buffer => sleep\n");

          mutex_unlock (&context->buffer.common_lock);

          _ret_queue =
                  wait_event_interruptible (context->buffer.write_queue,
                                            mut_mode (context) == AESDEV_MODE_CLOSING
                                            || mut_acb_free (&context->buffer) > 0);
          if (_ret_queue != 0)
            {
              mutex_unlock (&context->buffer.write_lock);
              return _ret_queue;
            }

          _ret_mutex = mutex_lock_interruptible (&context->buffer.common_lock);
          if (_ret_mutex != 0)
            {
              mutex_unlock (&context->buffer.write_lock);
              return _ret_mutex;
            }

          if (context->mode == AESDEV_MODE_CLOSING)
            {
              KDEBUG ("closing in write\n");
              retval = -EBADFD;
              goto exit;
            }
        }
    }

  /* I will only write as much data as possible in continous memory.
     Otherwise, I would have to create two separate tasks.
     acb_free > 0 => acb_free_to_end > 0 */
  to_take = min (acb_free_to_end (&context->buffer), len);
  assert (to_take > 0);
  if (copy_from_user (context->buffer.data.k_ptr + context->buffer.write_head,
                      buf, to_take))
    {
      retval = -EFAULT;
      goto exit;
    }

  /* Update buffer pointers and counters.  */
  context->buffer.write_head += to_take;
  context->buffer.write_head %= AESDRV_IOBUFF_SIZE;
  context->buffer.write_count += to_take;
  context->buffer.to_encrypt_count += to_take;

  assert (acb_to_encrypt_count_to_end (&context->buffer) > 0);

  /* Check if there is enough data to create an encryption task.  */
  if (acb_to_encrypt_count_to_end (&context->buffer) / sizeof (aes128_block) == 0)
    {
      KDEBUG ("not enough data for new task (%zu), returning\n",
              acb_to_encrypt_count_to_end (&context->buffer));
      /* Still I have copied the data to my io buffer.  */
      retval = to_take;
      goto exit;
    }

  task = kmalloc (sizeof (aes128_task), GFP_KERNEL);
  if (!task)
    {
      printk (KERN_WARNING "cannot allocate memory for encryption task\n");
      retval = -ENOMEM;
      goto exit;
    }

  task_init (task);
  task->context = context;
  task->block_count =
          acb_to_encrypt_count_to_end (&context->buffer) / sizeof (aes128_block);
  assert (task->block_count > 0);

  task->inout_buffer.d_ptr =
          context->buffer.data.d_ptr + context->buffer.to_encrypt_tail;
  task->inout_buffer.k_ptr =
          context->buffer.data.k_ptr + context->buffer.to_encrypt_tail;

  /* Update the pointers and counters for next encryption task.  */
  context->buffer.to_encrypt_count -= task->block_count * sizeof (aes128_block);
  context->buffer.to_encrypt_tail += task->block_count * sizeof (aes128_block);
  context->buffer.to_encrypt_tail %= AESDRV_IOBUFF_SIZE;
  assert (context->buffer.to_encrypt_count >= 0);
  assert (context->buffer.to_encrypt_count < sizeof (aes128_block));

  /*** CRITICAL SECTION ***/
  spin_lock_irqsave (&context->aes_dev->lock, irq_flags);
  /* Wait for space in command buffer.
     This wait will not take too long, so skip NONBLOCK support here.  */
  while (__free_task_slots (context->aes_dev) < 1)
    {
      spin_unlock_irqrestore (&context->aes_dev->lock, irq_flags);

      wait_event (context->aes_dev->command_queue,
                  free_task_slots (context->aes_dev) >= 1);

      assert (context->mode != AESDEV_MODE_CLOSING);

      spin_lock_irqsave (&context->aes_dev->lock, irq_flags);
    }

  //KDEBUG ("have slots: %d\n", __free_task_slots (context->aes_dev));

  cmd_ptr.d_ptr = ioread32 (bar0 + AESDEV_CMD_WRITE_PTR);
  cmd_ptr.k_ptr =
          aes_dev->cmd_buffer.k_ptr + (cmd_ptr.d_ptr - aes_dev->cmd_buffer.d_ptr);

  task->cmd_index = AESDEV_CMD_INDEXOF (aes_dev->cmd_buffer.d_ptr, cmd_ptr.d_ptr);

  cmd = (aes128_command *) cmd_ptr.k_ptr;

  /* Use same buffer for both input and output.  */
  cmd->in_ptr = task->inout_buffer.d_ptr;
  cmd->out_ptr = task->inout_buffer.d_ptr;
  cmd->ks_ptr = context->ks_buffer.d_ptr;
  cmd->xfer_val = AESDEV_TASK (task->block_count,
                               0x01, /* Not used, just cannot be 0. */
                               HAS_STATE (context->mode),
                               context->mode);

  /* Save task as active on device's list.  */
  list_add_tail (&task->task_list, &aes_dev->task_list_head);

  /* Increment command write pointer.  */
  cmd_ptr.d_ptr += sizeof (aes128_command);
  if (cmd_ptr.d_ptr == aes_dev->cmd_buffer.d_ptr + AESDRV_CMDBUFF_SIZE)
    cmd_ptr.d_ptr = aes_dev->cmd_buffer.d_ptr;

  aes_dev->tasks_in_progress++;

  /* Commit new command.  */
  iowrite32 ((uint32_t) cmd_ptr.d_ptr, context->aes_dev->bar0 + AESDEV_CMD_WRITE_PTR);

  spin_unlock_irqrestore (&context->aes_dev->lock, irq_flags);
  /*** END CRITICAL SECTION ***/

  retval = to_take;
exit:
  mutex_unlock (&context->buffer.common_lock);
  mutex_unlock (&context->buffer.write_lock);
  DNOTIF_LEAVE_FUN;
  return retval;
}

static int
file_open (struct inode *i, struct file * f)
{
  aes128_dev *aes_dev;
  aes128_context *context;
  int retval;

  DNOTIF_ENTER_FUN;
  might_sleep ();

  retval = mutex_lock_interruptible (&dev_remove_mutex);
  if (retval != 0)
    return retval;

  aes_dev = aes_devs[iminor (i)];
  if (aes_dev == NULL)
    {
      retval = -EBADFD;
      goto exit;
    }

  context = kmalloc (sizeof (aes128_context), GFP_KERNEL);
  if (context == NULL)
    {
      printk (KERN_WARNING "cannot allocate memory for context\n");
      retval = -ENOMEM;
      goto exit;
    }

  /* Start the device if no one was using it before.  */
  if (list_empty (&aes_dev->file_list_head))
    AESDEV_START (aes_dev);

  retval = context_init (context, aes_devs[iminor (i)]);
  if (IS_ERR_VALUE (retval))
    {
      kfree (context);
      printk (KERN_WARNING "context_init\n");
      goto exit;
    }

  f->private_data = context;
  context->lf.f = f;

  KDEBUG ("assigned opened file to device %p at context %p\n",
          context->aes_dev, context);

  retval = 0;
exit:
  mutex_unlock (&dev_remove_mutex);
  DNOTIF_LEAVE_FUN;
  return retval;
}

static int
file_release (struct inode *i, struct file * f)
{
  aes128_context *context;
  aes128_dev *aes_dev;

  DNOTIF_ENTER_FUN;
  might_sleep ();

  mutex_lock (&context_erase_mutex);

  context = f->private_data;
  if (context == NULL)
    {
      mutex_unlock (&context_erase_mutex);
      return -EBADFD;
    }

  mutex_lock (&context->buffer.common_lock);
  context->mode = AESDEV_MODE_CLOSING;
  mutex_unlock (&context->buffer.common_lock);

  /* Remember that this context is destroyed, in case someone enter
     read/write function, but has not acquired a mutex yet.  */
  f->private_data = NULL;

  /* Exit all current reads and writes (to avoid deadlock).  */
  wake_up (&context->buffer.write_queue);
  wake_up (&context->buffer.read_queue);

  mutex_lock (&context->buffer.write_lock);
  mutex_lock (&context->buffer.read_lock);
  mutex_lock (&context->buffer.common_lock);

  /* No one read/write/ioctl after this point.  */

  mutex_unlock (&context_erase_mutex);

  /* Wait for the device to process all tasks.  */
  while (__context_busy (context))
    {
      mutex_unlock (&context->buffer.common_lock);
      wait_event (context->buffer.read_queue, context_busy (context) == 0);
      mutex_lock (&context->buffer.common_lock);
    }

  /* Now it is safe to actually destroy the context.  */
  mutex_unlock (&context->buffer.common_lock);
  mutex_unlock (&context->buffer.read_lock);
  mutex_unlock (&context->buffer.write_lock);

  aes_dev = context->aes_dev;
  context_destroy (context);
  kfree (context);

  mutex_lock (&dev_remove_mutex);
  if (list_empty (&aes_dev->file_list_head))
    AESDEV_STOP (aes_dev);
  mutex_unlock (&dev_remove_mutex);

  DNOTIF_LEAVE_FUN;
  return 0;
}

static long
file_ioctl (struct file *f, unsigned int cmd, unsigned long arg)
{
  aes128_context *context;
  long retval;
  int _ret_mutex;

  DNOTIF_ENTER_FUN;
  might_sleep ();

  _ret_mutex = mutex_lock_interruptible (&context_erase_mutex);
  if (_ret_mutex != 0)
    return _ret_mutex;

  context = f->private_data;

  if (context == NULL)
    {
      mutex_unlock (&context_erase_mutex);
      return -EBADFD;
    }

  KDEBUG ("context=%p mode=0x%x\n", context, context->mode);

  _ret_mutex = mutex_lock_interruptible (&context->buffer.common_lock);
  if (_ret_mutex != 0)
    {
      mutex_unlock (&context_erase_mutex);
      return _ret_mutex;
    }

  mutex_unlock (&context_erase_mutex);

  if (context->mode == AESDEV_MODE_CLOSING)
    {
      retval = -EBADFD;
      goto exit;
    }

  if (cmd == AESDEV_IOCTL_SET_ECB_ENCRYPT)
    context->mode = AESDEV_MODE_ECB_ENCRYPT;
  else if (cmd == AESDEV_IOCTL_SET_ECB_DECRYPT)
    context->mode = AESDEV_MODE_ECB_DECRYPT;
  else if (cmd == AESDEV_IOCTL_SET_CBC_ENCRYPT)
    context->mode = AESDEV_MODE_CBC_ENCRYPT;
  else if (cmd == AESDEV_IOCTL_SET_CBC_DECRYPT)
    context->mode = AESDEV_MODE_CBC_DECRYPT;
  else if (cmd == AESDEV_IOCTL_SET_CFB_ENCRYPT)
    context->mode = AESDEV_MODE_CFB_ENCRYPT;
  else if (cmd == AESDEV_IOCTL_SET_CFB_DECRYPT)
    context->mode = AESDEV_MODE_CFB_DECRYPT;
  else if (cmd == AESDEV_IOCTL_SET_OFB)
    context->mode = AESDEV_MODE_OFB;
  else if (cmd == AESDEV_IOCTL_SET_CTR)
    context->mode = AESDEV_MODE_CTR;
  else if (cmd == AESDEV_IOCTL_GET_STATE)
    {
      if (context->mode == AESDEV_MODE_ECB_DECRYPT ||
          context->mode == AESDEV_MODE_ECB_ENCRYPT ||
          context->mode == AESDEV_MODE_UNDEF)
        {
          /* Other commands will also yield undefined behaviour when
             data is being processed. But no EINVAL in other cases.  */
          KDEBUG ("illegal GET_STATE in current mode\n");
          retval = -EINVAL;
          goto exit;
        }

      if (context->buffer.read_count > 0 || context->buffer.write_count > 0)
        {
          KDEBUG ("illegal GET_STATE with data in buffer\n");
          retval = -EINVAL;
          goto exit;
        }

      if (copy_to_user ((void *) arg,
                        context->ks_buffer.k_ptr + sizeof (aes128_block),
                        sizeof (aes128_block)))
        {
          KDEBUG ("copy_to_user\n");
          retval = -EFAULT;
          goto exit;
        }

      retval = 0;
      goto exit;
    }
  else
    {
      /* Unknow command.  */
      printk (KERN_WARNING "unknown command passed to ioctl\n");
      retval = -EINVAL;
      goto exit;
    }

  /* Read encryption key.  */
  if (copy_from_user (context->ks_buffer.k_ptr, (void *) arg, sizeof (aes128_block)))
    {
      KDEBUG ("copy_from_user\n");
      retval = -EFAULT;
      goto exit;
    }

  /* Read initialization vector.  */
  if (cmd != AESDEV_IOCTL_SET_ECB_ENCRYPT && cmd != AESDEV_IOCTL_SET_ECB_DECRYPT)
    if (copy_from_user (context->ks_buffer.k_ptr + sizeof (aes128_block),
                        ((char *) arg) + sizeof (aes128_block),
                        sizeof (aes128_block)))
      {
        KDEBUG ("copy_from_user\n");
        retval = -EFAULT;
        goto exit;
      }

  retval = 0;
exit:
  mutex_unlock (&context->buffer.common_lock);
  DNOTIF_LEAVE_FUN;
  return retval;
}
/*****************************************************************************/

/*** Device procedures *******************************************************/
__must_check static int
cmd_buffer_init (aes128_dev *aes_dev)
{
  void __iomem *bar0;
  dma_addr_t tmp_dma_addr;

  DNOTIF_ENTER_FUN;
  might_sleep ();
  bar0 = aes_dev->bar0;

  /* Allocate the buffer.  */
  aes_dev->cmd_buffer.k_ptr =
          dma_alloc_coherent (&aes_dev->pci_dev->dev, AESDRV_CMDBUFF_SIZE,
                              &tmp_dma_addr, GFP_KERNEL);
  if (aes_dev->cmd_buffer.k_ptr == NULL)
    return -ENOMEM;
  aes_dev->cmd_buffer.d_ptr = tmp_dma_addr;

  /* Tell device about buffer location.  */
  iowrite32 ((uint32_t) aes_dev->cmd_buffer.d_ptr,
             bar0 + AESDEV_CMD_BEGIN_PTR);
  iowrite32 ((uint32_t) aes_dev->cmd_buffer.d_ptr + AESDRV_CMDBUFF_SIZE,
             bar0 + AESDEV_CMD_END_PTR);
  iowrite32 ((uint32_t) aes_dev->cmd_buffer.d_ptr,
             bar0 + AESDEV_CMD_READ_PTR);
  iowrite32 ((uint32_t) aes_dev->cmd_buffer.d_ptr,
             bar0 + AESDEV_CMD_WRITE_PTR);
  return 0;
}

static void
cmd_buffer_destroy (aes128_dev *aes_dev)
{
  might_sleep ();
  dma_free_coherent (&aes_dev->pci_dev->dev, AESDRV_CMDBUFF_SIZE,
                     aes_dev->cmd_buffer.k_ptr, aes_dev->cmd_buffer.d_ptr);
}
/*****************************************************************************/

/*** PCI handlers ************************************************************/
static int
pci_probe (struct pci_dev *pci_dev, const struct pci_device_id * id)
{
  aes128_dev *aes_dev;
  uint32_t intr;
  int minor, ret;
  void __iomem *ioptr;
  struct device *sys_dev;

  DNOTIF_ENTER_FUN;
  might_sleep ();

  mutex_lock (&dev_remove_mutex);

  /* Find free slot for new device.  */
  for (minor = 0; minor < AESDRV_MAX_DEV_COUNT; ++minor)
    if (aes_devs[minor] == NULL)
      break;

  /* Too many devices in system.  */
  if (minor == AESDRV_MAX_DEV_COUNT)
    return -ENOMEM;

  ret = pci_enable_device (pci_dev);
  if (IS_ERR_VALUE (ret))
    {
      printk (KERN_WARNING "pci_enable_device\n");
      mutex_unlock (&dev_remove_mutex);
      return ret;
    }
  ret = pci_request_regions (pci_dev, "aesdev");
  if (IS_ERR_VALUE (ret))
    {
      printk (KERN_WARNING "pci_request_regions\n");
      pci_disable_device (pci_dev);
      mutex_unlock (&dev_remove_mutex);
      return ret;
    }

  /* Initialize new aes128_device structure.  */
  aes_dev = kmalloc (sizeof (aes128_dev), GFP_KERNEL);
  if (aes_dev == NULL)
    {
      pci_release_regions (pci_dev);
      pci_disable_device (pci_dev);
      mutex_unlock (&dev_remove_mutex);
      return -ENOMEM;
    }
  memset (aes_dev, 0, sizeof (aes128_dev));

  spin_lock_init (&aes_dev->lock);
  init_waitqueue_head (&aes_dev->command_queue);

  INIT_LIST_HEAD (&aes_dev->task_list_head);
  INIT_LIST_HEAD (&aes_dev->completed_list_head);
  INIT_LIST_HEAD (&aes_dev->file_list_head);

  aes_dev->pci_dev = pci_dev;
  aes_dev->minor = minor;

  ioptr = pci_iomap (pci_dev, 0, 0);
  if (IS_ERR_OR_NULL (ioptr))
    {
      printk (KERN_WARNING "pci_iomap\n");
      kfree (aes_dev);
      pci_release_regions (pci_dev);
      pci_disable_device (pci_dev);
      mutex_unlock (&dev_remove_mutex);
      if (ioptr)
        return PTR_ERR (ioptr);
      else
        return -EIO;
    }
  aes_dev->bar0 = ioptr;

  /* These are fail-safe.  */
  pci_set_drvdata (pci_dev, aes_dev);
  pci_set_master (pci_dev);

  /* No cleanup needed for this function.  */
  ret = pci_set_dma_mask (pci_dev, DMA_BIT_MASK (32));
  if (IS_ERR_VALUE (ret))
    {
      printk (KERN_WARNING "pci_set_dma_mask\n");
      pci_clear_master (pci_dev);
      pci_iounmap (pci_dev, ioptr);
      kfree (aes_dev);
      pci_release_regions (pci_dev);
      pci_disable_device (pci_dev);
      mutex_unlock (&dev_remove_mutex);
      return ret;
    }

  /* No cleanup needed for this function.  */
  ret = pci_set_consistent_dma_mask (pci_dev, DMA_BIT_MASK (32));
  if (IS_ERR_VALUE (ret))
    {
      printk (KERN_WARNING "pci_set_consistent_dma_mask\n");
      pci_clear_master (pci_dev);
      pci_iounmap (pci_dev, ioptr);
      kfree (aes_dev);
      pci_release_regions (pci_dev);
      pci_disable_device (pci_dev);
      mutex_unlock (&dev_remove_mutex);
      return ret;
    }

  ret = request_irq (pci_dev->irq, irq_handler, IRQF_SHARED, "aesdev", aes_dev);
  if (IS_ERR_VALUE (ret))
    {
      printk (KERN_WARNING "request_irq\n");
      pci_clear_master (pci_dev);
      pci_iounmap (pci_dev, ioptr);
      kfree (aes_dev);
      pci_release_regions (pci_dev);
      pci_disable_device (pci_dev);
      mutex_unlock (&dev_remove_mutex);
      return ret;
    }

  /* Init data transfer block.  */
  iowrite32 (0x00000000, aes_dev->bar0 + AESDEV_XFER_IN_PTR);
  iowrite32 (0x00000000, aes_dev->bar0 + AESDEV_XFER_OUT_PTR);
  iowrite32 (0x00000000, aes_dev->bar0 + AESDEV_XFER_STATE_PTR);
  iowrite32 (0x00000000, aes_dev->bar0 + AESDEV_XFER_TASK);

  /* Init command buffer.  */
  ret = cmd_buffer_init (aes_dev);
  if (IS_ERR_VALUE (ret))
    {
      printk (KERN_WARNING "cmd_buffer_init\n");
      free_irq (pci_dev->irq, aes_dev);
      pci_clear_master (pci_dev);
      pci_iounmap (pci_dev, ioptr);
      kfree (aes_dev);
      pci_release_regions (pci_dev);
      pci_disable_device (pci_dev);
      mutex_unlock (&dev_remove_mutex);
      return ret;
    }

  /* Clear interrupts.  */
  intr = ioread32 (aes_dev->bar0 + AESDEV_INTR);
  iowrite32 (intr, aes_dev->bar0 + AESDEV_INTR);

  /* Register device in driver.  */
  aes_devs[minor] = aes_dev;

  /* Do this at the very end. Since now, the device is available to user.  */
  sys_dev = device_create (dev_class,
                           NULL,
                           MKDEV (major, minor),
                           NULL,
                           "aes%d",
                           minor);
  if (IS_ERR_OR_NULL (sys_dev))
    {
      printk (KERN_WARNING "device_create\n");
      cmd_buffer_destroy (aes_dev);
      free_irq (pci_dev->irq, aes_dev);
      pci_clear_master (pci_dev);
      pci_iounmap (pci_dev, ioptr);
      kfree (aes_dev);
      pci_release_regions (pci_dev);
      pci_disable_device (pci_dev);
      aes_devs[minor] = NULL;
      mutex_unlock (&dev_remove_mutex);
      if (sys_dev)
        return PTR_ERR (sys_dev);
      else
        return -EIO;
    }
  aes_dev->sys_dev = sys_dev;

  printk (KERN_WARNING "Registered new aesdev\n");
  DNOTIF_LEAVE_FUN;
  mutex_unlock (&dev_remove_mutex);
  return 0;
}

static void
pci_remove (struct pci_dev *pci_dev)
{
  aes128_dev *aes_dev;

  DNOTIF_ENTER_FUN;
  might_sleep ();

  aes_dev = pci_get_drvdata (pci_dev);

  mutex_lock (&dev_remove_mutex);
  aes_devs[aes_dev->minor] = NULL;
  if (!list_empty (&aes_dev->file_list_head))
    panic ("aesdev: Hot-unplug with open contexts not supported! Fatal.\n");
  mutex_unlock (&dev_remove_mutex);

  device_destroy (dev_class, MKDEV (major, aes_dev->minor));
  free_irq (pci_dev->irq, aes_dev);
  cmd_buffer_destroy (aes_dev);
  pci_clear_master (pci_dev);
  pci_iounmap (pci_dev, aes_dev->bar0);

  pci_release_regions (pci_dev);
  pci_disable_device (pci_dev);
  kfree (aes_dev);

  printk (KERN_WARNING "Unregistered aesdev\n");
  DNOTIF_LEAVE_FUN;
}

static void
pci_shutdown (struct pci_dev *dev)
{
  aes128_dev *aes_dev;
  DNOTIF_ENTER_FUN;
  might_sleep ();
  aes_dev = pci_get_drvdata (dev);
  AESDEV_STOP (aes_dev);
  DNOTIF_LEAVE_FUN;
}

/*****************************************************************************/

static int
aesdrv_init (void)
{
  int ret;
  KDEBUG ("hello\n");

  /* Register device major.  */
  major = register_chrdev (0, "aesdev", &aes_fops);
  if (IS_ERR_VALUE (major))
    {
      printk (KERN_WARNING "register_chrdev\n");
      return major;
    }

  /* Sysfs class.  */
  dev_class = class_create (THIS_MODULE, "aesdev");
  if (IS_ERR_OR_NULL (dev_class))
    {
      printk (KERN_WARNING "class_create\n");
      if (dev_class)
        return PTR_ERR (dev_class);
      else
        return -EIO;
    }

  /* Register PCI driver.  */
  ret = pci_register_driver (&aes_pci);
  if (IS_ERR_VALUE (ret))
    {
      printk (KERN_WARNING "pci_register_driver\n");
      return ret;
    }

  return 0;
}

static void
aesdrv_cleanup (void)
{
  DNOTIF_ENTER_FUN;
  might_sleep ();

  /* All devices will be stopped at this point, because all files have
     been closed.  */

  /* This will fire all PCI destructors.  */
  pci_unregister_driver (&aes_pci);
  class_destroy (dev_class);
  unregister_chrdev (major, "aesdev");

  DNOTIF_LEAVE_FUN;
}

module_init (aesdrv_init);
module_exit (aesdrv_cleanup);