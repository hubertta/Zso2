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
static aes128_dev *aes_devs[256]; /* Map minor number to device.  */

/*** Kernel structs **********************************************************/
static struct file_operations aes_fops = {
  .owner = THIS_MODULE,
  .read = file_read,
  .write = file_write,
  .open = file_open,
  .release = file_release,
  .unlocked_ioctl = file_ioctl,
  .compat_ioctl = file_ioctl
};
static struct pci_device_id pci_ids[] = {
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
task_destroy (aes128_task *task)
{
  list_del (&task->task_list);
  kfree (task);
}

/* Pick completed tasks from device and return total size of data
   available to read by user.  */
__must_check static size_t
__move_completed_tasks (aes128_context *context)
{
  aes128_task *task, *temp_task;
  unsigned long flags;
  struct list_head my_tasks;

  DNOTIF_ENTER_FUN;

  INIT_LIST_HEAD (&my_tasks);

  /*** CRITICAL SECTION ****/
  spin_lock_irqsave (&context->aes_dev->lock, flags);

  /* Move my tasks to my list.  */
  list_for_each_entry_safe (task, temp_task, &context->aes_dev->completed_list_head, task_list)
  {
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
    KDEBUG ("moving task %p\n", task);

    context->buffer.write_tail += task->block_count * sizeof (aes128_block);
    context->buffer.write_tail %= AESDRV_IOBUFF_SIZE;

    context->buffer.read_count += task->block_count * sizeof (aes128_block);
    context->buffer.write_count -= task->block_count * sizeof (aes128_block);
    assert (context->buffer.write_count >= 0);

    assert (context->buffer.read_count > 0
            && context->buffer.read_count <= AESDRV_IOBUFF_SIZE);

    assert (context->buffer.write_count >= 0
            && context->buffer.write_count <= AESDRV_IOBUFF_SIZE);

    task_destroy (task);
  }

  KDEBUG ("returning %d\n", acb_read_count (&context->buffer));

  DNOTIF_LEAVE_FUN;
  return acb_read_count (&context->buffer);
}

__must_check static size_t
move_completed_tasks (aes128_context *context)
{
  size_t ret;
  mutex_lock (&context->buffer.common_lock);
  ret = __move_completed_tasks (context);
  mutex_unlock (&context->buffer.common_lock);
  return ret;
}

/*
 Do NOT use this function without spinlock.
 */
__must_check static size_t
__free_task_slots (aes128_dev *aes_dev)
{
  //  return AESDRV_IOBUFF_SIZE - 3 - aes_dev->tasks_in_progress;
  return 3 - aes_dev->tasks_in_progress;
}

__must_check static size_t
free_task_slots (aes128_dev *aes_dev)
{
  unsigned long irq_flags;
  size_t ret;

  /* TODO Czy tu jest potrzebny spinlock?  */
  spin_lock_irqsave (&aes_dev->lock, irq_flags);
  ret = __free_task_slots (aes_dev);
  spin_unlock_irqrestore (&aes_dev->lock, irq_flags);

  return ret;
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

  context->mode = AES_UNDEF;
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

  INIT_LIST_HEAD (&context->context_list);
  list_add (&context->context_list, &aes_dev->context_list_head);

  return 0;
  DNOTIF_LEAVE_FUN;
}

//static void
//context_destroy (aes128_context *context)
//{
//  unsigned long irq_flags;
//  DNOTIF_ENTER_FUN;
//  spin_lock_irqsave (&context->aes_dev->lock, irq_flags);
//  list_del (&context->context_list);
//  spin_unlock_irqrestore (&context->aes_dev->lock, irq_flags);
//  dma_free_coherent (&context->aes_dev->pci_dev->dev,
//                     2 * sizeof (aes128_block),
//                     context->ks_buffer.k_ptr,
//                     context->ks_buffer.d_ptr);
//  acb_destroy (&context->buffer, context->aes_dev);
//  mutex_destroy (&context->lock);
//  kfree (context);
//  DNOTIF_LEAVE_FUN;
//}
/*****************************************************************************/

/*** Combo buffer ************************************************************/
__must_check static int
acb_init (aes128_combo_buffer *buffer, aes128_dev *aes_dev)
{
  dma_addr_t tmp_dma_addr;
  DNOTIF_ENTER_FUN;

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
  mutex_destroy (&buffer->read_lock);
  mutex_destroy (&buffer->write_lock);
  mutex_destroy (&buffer->common_lock);
  dma_free_coherent (&aes_dev->pci_dev->dev,
                     AESDRV_IOBUFF_SIZE,
                     buffer->data.k_ptr,
                     buffer->data.d_ptr);
  /* TODO Deinit waitqueue?  */
  kfree (buffer);
  DNOTIF_LEAVE_FUN;
}

static size_t
acb_read_count (const aes128_combo_buffer *buffer)
{
  return buffer->read_count;
}

static size_t
acb_write_count (const aes128_combo_buffer *buffer)
{
  return buffer->write_count;
}

static size_t
acb_write_count_to_end (const aes128_combo_buffer *buffer)
{
  if (buffer->write_tail + buffer->write_count <= AESDRV_IOBUFF_SIZE)
    return buffer->write_count;
  return AESDRV_IOBUFF_SIZE - buffer->write_tail;
}

static size_t
acb_to_encrypt_count_to_end (const aes128_combo_buffer *buffer)
{
  if (buffer->to_encrypt_tail + buffer->to_encrypt_count <= AESDRV_IOBUFF_SIZE)
    return buffer->to_encrypt_count;
  return AESDRV_IOBUFF_SIZE - buffer->to_encrypt_tail;
}

static size_t
acb_free (const aes128_combo_buffer *buffer)
{
  return AESDRV_IOBUFF_SIZE - buffer->write_count - buffer->read_count;
}

static size_t
mut_acb_free (aes128_combo_buffer *buffer)
{
  size_t ret;
  mutex_lock (&buffer->common_lock);
  ret = acb_free (buffer);
  mutex_unlock (&buffer->common_lock);
  return ret;
}

static size_t
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

static size_t
acb_read_count_to_end (const aes128_combo_buffer *buffer)
{
  if (buffer->read_tail + buffer->read_count <= AESDRV_IOBUFF_SIZE)
    return buffer->read_count;
  return AESDRV_IOBUFF_SIZE - buffer->read_tail;
}

__used
static void
acb_run_tests (aes128_dev *aes_dev)
{
  aes128_combo_buffer buffer;
  if (acb_init (&buffer, aes_dev))
    KDEBUG ("acb_init\n");

  KDEBUG ("read_tail=%d write_tail=%d write_head=%d write_count=%d read_count=%d\n",
          buffer.read_tail, buffer.write_tail, buffer.write_head,
          buffer.write_count, buffer.read_count);
  KDEBUG ("acb_free=%d acb_free_to_end=%d acb_read_count=%d acb_read_count_to_end=%d "
          "acb_write_count=%d acb_write_count_to_end=%d\n",
          acb_free (&buffer),
          acb_free_to_end (&buffer),
          acb_read_count (&buffer),
          acb_read_count_to_end (&buffer),
          acb_write_count (&buffer),
          acb_write_count_to_end (&buffer));
  assert (acb_free (&buffer) == AESDRV_IOBUFF_SIZE);
  assert (acb_free_to_end (&buffer) == AESDRV_IOBUFF_SIZE);
  assert (acb_read_count (&buffer) == 0);
  assert (acb_read_count_to_end (&buffer) == 0);
  assert (acb_write_count (&buffer) == 0);
  assert (acb_write_count_to_end (&buffer) == 0);

  buffer.write_head += 16;
  buffer.write_head %= AESDRV_IOBUFF_SIZE;
  buffer.write_count += 16;

  KDEBUG ("read_tail=%d read_head=%d write_head=%d write_count=%d read_count=%d\n",
          buffer.read_tail, buffer.write_tail, buffer.write_head,
          buffer.write_count, buffer.read_count);
  KDEBUG ("acb_free=%d acb_free_to_end=%d acb_read_count=%d acb_read_count_to_end=%d "
          "acb_write_count=%d acb_write_count_to_end=%d\n",
          acb_free (&buffer),
          acb_free_to_end (&buffer),
          acb_read_count (&buffer),
          acb_read_count_to_end (&buffer),
          acb_write_count (&buffer),
          acb_write_count_to_end (&buffer));
  assert (acb_free (&buffer) == AESDRV_IOBUFF_SIZE - 16);
  assert (acb_free_to_end (&buffer) == AESDRV_IOBUFF_SIZE - 16);
  assert (acb_read_count (&buffer) == 0);
  assert (acb_read_count_to_end (&buffer) == 0);
  assert (acb_write_count (&buffer) == 16);
  assert (acb_write_count_to_end (&buffer) == 16);

  buffer.write_head += 16;
  buffer.write_count += 16;
  buffer.write_head %= AESDRV_IOBUFF_SIZE;

  KDEBUG ("read_tail=%d read_head=%d write_head=%d write_count=%d read_count=%d\n",
          buffer.read_tail, buffer.write_tail, buffer.write_head,
          buffer.write_count, buffer.read_count);
  KDEBUG ("acb_free=%d acb_free_to_end=%d acb_read_count=%d acb_read_count_to_end=%d "
          "acb_write_count=%d acb_write_count_to_end=%d\n",
          acb_free (&buffer),
          acb_free_to_end (&buffer),
          acb_read_count (&buffer),
          acb_read_count_to_end (&buffer),
          acb_write_count (&buffer),
          acb_write_count_to_end (&buffer));
  assert (acb_free (&buffer) == 0);
  assert (acb_free_to_end (&buffer) == 0);
  assert (acb_read_count (&buffer) == 0);
  assert (acb_read_count_to_end (&buffer) == 0);
  assert (acb_write_count (&buffer) == 32);
  assert (acb_write_count_to_end (&buffer) == 32);

  buffer.write_tail += 16;
  buffer.write_tail %= AESDRV_IOBUFF_SIZE;
  buffer.read_count += 16;
  buffer.write_count -= 16;

  KDEBUG ("read_tail=%d read_head=%d write_head=%d write_count=%d read_count=%d\n",
          buffer.read_tail, buffer.write_tail, buffer.write_head,
          buffer.write_count, buffer.read_count);
  KDEBUG ("acb_free=%d acb_free_to_end=%d acb_read_count=%d acb_read_count_to_end=%d "
          "acb_write_count=%d acb_write_count_to_end=%d\n",
          acb_free (&buffer),
          acb_free_to_end (&buffer),
          acb_read_count (&buffer),
          acb_read_count_to_end (&buffer),
          acb_write_count (&buffer),
          acb_write_count_to_end (&buffer));
  assert (acb_free (&buffer) == 0);
  assert (acb_free_to_end (&buffer) == 0);
  assert (acb_read_count (&buffer) == 16);
  assert (acb_read_count_to_end (&buffer) == 16);
  assert (acb_write_count (&buffer) == 16);
  assert (acb_write_count_to_end (&buffer) == 16);

  buffer.write_tail += 16;
  buffer.write_tail %= AESDRV_IOBUFF_SIZE;
  buffer.read_count += 16;
  buffer.write_count -= 16;

  KDEBUG ("read_tail=%d read_head=%d write_head=%d write_count=%d read_count=%d\n",
          buffer.read_tail, buffer.write_tail, buffer.write_head,
          buffer.write_count, buffer.read_count);
  KDEBUG ("acb_free=%d acb_free_to_end=%d acb_read_count=%d acb_read_count_to_end=%d "
          "acb_write_count=%d acb_write_count_to_end=%d\n",
          acb_free (&buffer),
          acb_free_to_end (&buffer),
          acb_read_count (&buffer),
          acb_read_count_to_end (&buffer),
          acb_write_count (&buffer),
          acb_write_count_to_end (&buffer));
  assert (acb_free (&buffer) == 0);
  assert (acb_free_to_end (&buffer) == 0);
  assert (acb_read_count (&buffer) == 32);
  assert (acb_read_count_to_end (&buffer) == 32);
  assert (acb_write_count (&buffer) == 0);
  assert (acb_write_count_to_end (&buffer) == 0);

  buffer.read_tail += 16;
  buffer.read_tail %= AESDRV_IOBUFF_SIZE;
  buffer.read_count -= 16;

  KDEBUG ("read_tail=%d read_head=%d write_head=%d write_count=%d read_count=%d\n",
          buffer.read_tail, buffer.write_tail, buffer.write_head,
          buffer.write_count, buffer.read_count);
  KDEBUG ("acb_free=%d acb_free_to_end=%d acb_read_count=%d acb_read_count_to_end=%d "
          "acb_write_count=%d acb_write_count_to_end=%d\n",
          acb_free (&buffer),
          acb_free_to_end (&buffer),
          acb_read_count (&buffer),
          acb_read_count_to_end (&buffer),
          acb_write_count (&buffer),
          acb_write_count_to_end (&buffer));
  assert (acb_free (&buffer) == 16);
  assert (acb_free_to_end (&buffer) == 16);
  assert (acb_read_count (&buffer) == 16);
  assert (acb_read_count_to_end (&buffer) == 16);
  assert (acb_write_count (&buffer) == 0);
  assert (acb_write_count_to_end (&buffer) == 0);

  buffer.write_head += 16;
  buffer.write_head %= AESDRV_IOBUFF_SIZE;
  buffer.write_count += 16;

  buffer.write_tail += 16;
  buffer.write_tail %= AESDRV_IOBUFF_SIZE;
  buffer.read_count += 16;
  buffer.write_count -= 16;

  KDEBUG ("read_tail=%d read_head=%d write_head=%d write_count=%d read_count=%d\n",
          buffer.read_tail, buffer.write_tail, buffer.write_head,
          buffer.write_count, buffer.read_count);
  KDEBUG ("acb_free=%d acb_free_to_end=%d acb_read_count=%d acb_read_count_to_end=%d "
          "acb_write_count=%d acb_write_count_to_end=%d\n",
          acb_free (&buffer),
          acb_free_to_end (&buffer),
          acb_read_count (&buffer),
          acb_read_count_to_end (&buffer),
          acb_write_count (&buffer),
          acb_write_count_to_end (&buffer));
  assert (acb_free (&buffer) == 0);
  assert (acb_free_to_end (&buffer) == 0);
  assert (acb_read_count (&buffer) == 32);
  assert (acb_read_count_to_end (&buffer) == 16);
  assert (acb_write_count (&buffer) == 0);
  assert (acb_write_count_to_end (&buffer) == 0);
}
/*****************************************************************************/

/*** Irq handlers ************************************************************/
static irqreturn_t
irq_handler (int irq, void *ptr)
{
  aes128_dev *aes_dev;
  aes128_task *task, *temp_task;
  uint8_t intr;
  unsigned long irq_flags;
  char stoi = 0;

  DNOTIF_ENTER_FUN;

  /* TODO Can this be not my pointer?  */
  aes_dev = ptr;

  /*** CRITICAL SECTION ***/
  spin_lock_irqsave (&aes_dev->lock, irq_flags);
  intr = ioread32 (aes_dev->bar0 + AESDEV_INTR) & 0xFF;
  if (!intr)
    {
      spin_unlock_irqrestore (&aes_dev->lock, irq_flags);
      return IRQ_NONE;
    }
  iowrite32 (intr, aes_dev->bar0 + AESDEV_INTR);
  if ((ioread32 (aes_dev->bar0 + AESDEV_STATUS) & 0x03) == 0x00)
    stoi = 1;

  aes_dev->read_index = AESDEV_CMD_INDEXOF (aes_dev->cmd_buffer.d_ptr, ioread32 (aes_dev->bar0 + AESDEV_CMD_READ_PTR));
  assert (aes_dev->read_index < AESDRV_CMDBUFF_SLOTS);

  /* Move completed tasks to completed tasks list.  */
  list_for_each_entry_safe (task, temp_task, &aes_dev->task_list_head, task_list)
  {
    KDEBUG ("intr=0x%02x read_ind=%x task->cmd_index=%x stoi=%x\n",
            intr, aes_dev->read_index, task->cmd_index, stoi);
    KDEBUG ("%d == %d?\n", ((task->cmd_index + 1) % AESDRV_CMDBUFF_SLOTS), aes_dev->read_index);
    //    if (!stoi && ((task->cmd_index + 1) % AESDRV_CMDBUFF_SLOTS) == aes_dev->read_index)
    //      {
    //        assert (!((1 << task->cmd_index) & intr));
    //        KDEBUG ("breaking\n");
    //        break;
    //      }
    //    assert ((1 << task->cmd_index) & intr);
    if ((1 << task->cmd_index) & intr)
      {
        list_del (&task->task_list);
        list_add_tail (&task->task_list, &aes_dev->completed_list_head);
        aes_dev->tasks_in_progress--;
        /* Notify about new data.  */
        wake_up_interruptible (&task->context->buffer.read_queue);
      }
  }

  /* My interrupt => at least one command completed.  */
  wake_up_interruptible (&aes_dev->command_queue);

  /* All interrupts handled.  */
  //  iowrite32 (intr, aes_dev->bar0 + AESDEV_INTR);

  spin_unlock_irqrestore (&aes_dev->lock, irq_flags);
  /*** END CRITICAL SECTION ***/

  DNOTIF_LEAVE_FUN;
  return IRQ_HANDLED;
}
/*****************************************************************************/

/*** File handlers ***********************************************************/
static ssize_t
file_read (struct file *f, char __user *buf, size_t len, loff_t *off)
{
  aes128_context *context;
  size_t to_copy, to_copy1; //, to_copy2;
  ssize_t retval;

  DNOTIF_ENTER_FUN;
  context = f->private_data;

  mutex_lock (&context->buffer.read_lock);
  mutex_lock (&context->buffer.common_lock);

  if (context->mode == AES_UNDEF)
    {
      KDEBUG ("no mode set\n");
      retval = -EINVAL;
      goto exit;
    }

  KDEBUG ("in buffer before=%d\n", acb_read_count (&context->buffer));
  if (f->f_flags & O_NONBLOCK)
    {
      if (__move_completed_tasks (context) == 0)
        {
          KDEBUG ("no data, returning EAGAIN\n");
          retval = -EAGAIN;
          goto exit;
        }
    }
  else
    {
      while (__move_completed_tasks (context) == 0)
        {
          int _ret;
          KDEBUG ("going to sleep :(\n");
          mutex_unlock (&context->buffer.common_lock);
          _ret = wait_event_interruptible (context->buffer.read_queue, move_completed_tasks (context) != 0);
          mutex_lock (&context->buffer.common_lock);
          if (_ret != 0)
            {
              retval = _ret;
              goto exit;
            }
        }
    }
  KDEBUG ("in buffer after=%d\n", acb_read_count (&context->buffer));
  assert (acb_read_count (&context->buffer) > 0);

  to_copy = min (len, acb_read_count (&context->buffer));
  to_copy1 = min (to_copy, acb_read_count_to_end (&context->buffer));
  //  to_copy2 = to_copy - to_copy1;
  if (copy_to_user (buf, context->buffer.data.k_ptr + context->buffer.read_tail, to_copy1))
    {
      KDEBUG ("copy_to_user\n");
      retval = -EFAULT;
      goto exit;
    }
  //  if (to_copy2 && copy_to_user (buf + to_copy1, context->buffer.data.k_ptr, to_copy2))
  //    {
  //      KDEBUG ("copy_to_user\n");
  //      retval = -EFAULT;
  //      goto exit;
  //    }
  context->buffer.read_tail += to_copy1;
  context->buffer.read_tail %= AESDRV_IOBUFF_SIZE;
  context->buffer.read_count -= to_copy1;
  assert (context->buffer.read_count >= 0);
  //  retval = to_copy;
  retval = to_copy;
  wake_up (&context->buffer.write_queue);

exit:
  DNOTIF_LEAVE_FUN;
  mutex_unlock (&context->buffer.common_lock);
  mutex_unlock (&context->buffer.read_lock);
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

  DNOTIF_ENTER_FUN;
  context = f->private_data;
  aes_dev = context->aes_dev;
  bar0 = aes_dev->bar0;

  mutex_lock (&context->buffer.write_lock);
  mutex_lock (&context->buffer.common_lock);

  if (context->mode == AES_UNDEF)
    {
      KDEBUG ("no mode set\n");
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
          int _ret;

          KDEBUG ("no space in buffer => sleep\n");
          mutex_unlock (&context->buffer.common_lock);
          _ret = wait_event_interruptible (context->buffer.write_queue, mut_acb_free (&context->buffer) != 0);
          /* Mam cały czas muteksa na write; czyli nikt mi nie zajął miejsca
             w buforze w tzw. międzyczasie.  */
          mutex_lock (&context->buffer.common_lock);

          if (_ret != 0)
            {
              retval = _ret;
              goto exit;
            }
        }
    }

  to_take = min (acb_free_to_end (&context->buffer), len);
  assert (to_take > 0);
  if (copy_from_user (context->buffer.data.k_ptr + context->buffer.write_head,
                      buf, to_take))
    return -EFAULT;

  context->buffer.write_head += to_take;
  context->buffer.write_head %= AESDRV_IOBUFF_SIZE;
  context->buffer.write_count += to_take;
  context->buffer.to_encrypt_count += to_take;

  assert (acb_to_encrypt_count_to_end (&context->buffer) > 0);
  if (acb_to_encrypt_count_to_end (&context->buffer) / sizeof (aes128_block) == 0)
    {
      KDEBUG ("not enough data for new task (%d), returning\n",
              acb_to_encrypt_count_to_end (&context->buffer));
      retval = to_take;
      goto exit;
    }

  task = kmalloc (sizeof (aes128_task), GFP_KERNEL);
  task_init (task);
  task->context = context;
  task->block_count = acb_to_encrypt_count_to_end (&context->buffer) / sizeof (aes128_block);
  assert (task->block_count > 0);
  task->inout_buffer.d_ptr = context->buffer.data.d_ptr + context->buffer.to_encrypt_tail;
  task->inout_buffer.k_ptr = context->buffer.data.k_ptr + context->buffer.to_encrypt_tail;
  context->buffer.to_encrypt_count -= task->block_count * sizeof (aes128_block);
  context->buffer.to_encrypt_tail += task->block_count * sizeof (aes128_block);
  context->buffer.to_encrypt_tail %= AESDRV_IOBUFF_SIZE;

  /*** CRITICAL SECTION ***/
  spin_lock_irqsave (&context->aes_dev->lock, irq_flags);
  /* Wait for space in command buffer.  */
  while (__free_task_slots (context->aes_dev) < 1)
    {
      int _ret;
      spin_unlock_irqrestore (&context->aes_dev->lock, irq_flags);
      _ret = wait_event_interruptible (context->aes_dev->command_queue,
                                       free_task_slots (context->aes_dev) >= 1);
      if (_ret != 0)
        {
          retval = _ret;
          goto exit;
        }
      spin_lock_irqsave (&context->aes_dev->lock, irq_flags);
    }

  KDEBUG ("have slots %d\n", __free_task_slots (context->aes_dev));

  cmd_ptr.d_ptr = ioread32 (bar0 + AESDEV_CMD_WRITE_PTR);
  cmd_ptr.k_ptr = aes_dev->cmd_buffer.k_ptr + (cmd_ptr.d_ptr - aes_dev->cmd_buffer.d_ptr);

  task->cmd_index = AESDEV_CMD_INDEXOF (aes_dev->cmd_buffer.d_ptr, cmd_ptr.d_ptr);

  cmd = (aes128_command *) cmd_ptr.k_ptr;

  cmd->in_ptr = task->inout_buffer.d_ptr;
  cmd->out_ptr = task->inout_buffer.d_ptr;
  cmd->ks_ptr = context->ks_buffer.d_ptr;
  cmd->xfer_val = AESDEV_TASK (task->block_count,
                               1 << task->cmd_index,
                               //                               0x01,
                               HAS_STATE (context->mode),
                               context->mode);

  /* Save task to active task list on device.  */
  list_add_tail (&task->task_list, &aes_dev->task_list_head);

  /* Increment command write pointer.  */
  cmd_ptr.d_ptr += sizeof (aes128_command);
  if (cmd_ptr.d_ptr == aes_dev->cmd_buffer.d_ptr + AESDRV_CMDBUFF_SIZE)
    cmd_ptr.d_ptr = aes_dev->cmd_buffer.d_ptr;
  aes_dev->tasks_in_progress++;
  iowrite32 ((uint32_t) cmd_ptr.d_ptr, context->aes_dev->bar0 + AESDEV_CMD_WRITE_PTR);

  spin_unlock_irqrestore (&context->aes_dev->lock, irq_flags);
  /*** END CRITICAL SECTION ***/

  retval = to_take;
exit:
  DNOTIF_LEAVE_FUN;
  mutex_unlock (&context->buffer.common_lock);
  mutex_unlock (&context->buffer.write_lock);
  return retval;
}

static int
file_open (struct inode *i, struct file * f)
{
  aes128_context *context;
  int ret;
  DNOTIF_ENTER_FUN;

  context = kmalloc (sizeof (aes128_context), GFP_KERNEL);
  f->private_data = context;
  ret = context_init (context, aes_devs[iminor (i)]);
  if (IS_ERR_VALUE (ret))
    {
      printk (KERN_WARNING "context_init\n");
      return ret;
    }

  KDEBUG ("assigned opened file to device %p at context %p\n", context->aes_dev, context);
  DNOTIF_LEAVE_FUN;
  return 0;
}

static int
file_release (struct inode *i, struct file * f)
{
  DNOTIF_ENTER_FUN;
  //  KDEBUG ("destroing context %p\n", f->private_data);
  //  context_destroy (f->private_data);
  DNOTIF_LEAVE_FUN;
  return 0;
}

static long
file_ioctl (struct file *f, unsigned int cmd, unsigned long arg)
{
  aes128_context *context;
  long retval;

  DNOTIF_ENTER_FUN;
  context = f->private_data;

  KDEBUG ("u context=%p mode=0x%x\n", context, context->mode);
  mutex_lock (&context->buffer.common_lock);

  if /**/ (cmd == AESDEV_IOCTL_SET_ECB_ENCRYPT) context->mode = AES_ECB_ENCRYPT;
  else if (cmd == AESDEV_IOCTL_SET_ECB_DECRYPT) context->mode = AES_ECB_DECRYPT;
  else if (cmd == AESDEV_IOCTL_SET_CBC_ENCRYPT) context->mode = AES_CBC_ENCRYPT;
  else if (cmd == AESDEV_IOCTL_SET_CBC_DECRYPT) context->mode = AES_CBC_DECRYPT;
  else if (cmd == AESDEV_IOCTL_SET_CFB_ENCRYPT) context->mode = AES_CFB_ENCRYPT;
  else if (cmd == AESDEV_IOCTL_SET_CFB_DECRYPT) context->mode = AES_CFB_DECRYPT;
  else if (cmd == AESDEV_IOCTL_SET_OFB) /*****/ context->mode = AES_OFB;
  else if (cmd == AESDEV_IOCTL_SET_CTR) /*****/ context->mode = AES_CTR;
  else if (cmd == AESDEV_IOCTL_GET_STATE)
    {
      if (context->mode == AES_ECB_DECRYPT ||
          context->mode == AES_ECB_ENCRYPT ||
          context->mode == AES_UNDEF)
        {
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

      if (copy_to_user ((void *) arg, context->ks_buffer.k_ptr + sizeof (aes128_block), sizeof (aes128_block)))
        {
          KDEBUG ("copy_to_user\n");
          retval = -EFAULT;
          goto exit;
        }

      retval = 0;
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
init_cmd_buffer (aes128_dev * aes_dev)
{
  void __iomem *bar0;
  dma_addr_t tmp_dma_addr;

  DNOTIF_ENTER_FUN;
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
  aes_dev->read_index = AESDRV_CMDBUFF_SIZE - 1;
  return 0;
}

static int
aes_dev_destroy (aes128_dev * aes_dev)
{
  DNOTIF_ENTER_FUN;

  /* TODO */
  kfree (aes_dev);

  DNOTIF_LEAVE_FUN;
  return 0;
}
/*****************************************************************************/

/*** PCI handlers ************************************************************/
static int
turn_off_device (aes128_dev * aes_dev)
{
  AESDEV_STOP (aes_dev);
  return 0;
}

static int
pci_probe (struct pci_dev *pci_dev, const struct pci_device_id * id)
{
  aes128_dev *aes_dev;
  uint32_t intr;
  int minor, ret;

  DNOTIF_ENTER_FUN;

  /* TODO cleanup on failue.  */

  /* Find free slot for new device.  */
  for (minor = 0; minor < 256; ++minor)
    if (aes_devs[minor] == NULL)
      break;

  /* Too many devices in system.  */
  if (minor == 256)
    return -ENOMEM;

  ret = pci_enable_device (pci_dev);
  if (IS_ERR_VALUE (ret))
    {
      printk (KERN_WARNING "pci_enable_device\n");
      return ret;
    }
  ret = pci_request_regions (pci_dev, "aesdev");
  if (IS_ERR_VALUE (ret))
    {
      printk (KERN_WARNING "pci_request_regions\n");
      return ret;
    }

  /* Initialize new aes128_device structure.  */
  aes_dev = kmalloc (sizeof (aes128_dev), GFP_KERNEL);
  if (aes_dev == NULL)
    return -ENOMEM;

  memset (aes_dev, 0, sizeof (aes128_dev));

  spin_lock_init (&aes_dev->lock);
  init_waitqueue_head (&aes_dev->command_queue);

  INIT_LIST_HEAD (&aes_dev->context_list_head);
  INIT_LIST_HEAD (&aes_dev->task_list_head);
  INIT_LIST_HEAD (&aes_dev->completed_list_head);

  aes_dev->pci_dev = pci_dev;
  aes_dev->minor = minor;

  aes_dev->bar0 = pci_iomap (pci_dev, 0, 0);
  if (IS_ERR_OR_NULL (aes_dev->bar0))
    {
      printk (KERN_WARNING "pci_iomap\n");
      return PTR_ERR (aes_dev->bar0);
    }

  aes_dev->sys_dev = device_create (dev_class, NULL, MKDEV (major, minor), NULL, "aes%d", minor);
  if (IS_ERR_OR_NULL (aes_dev->sys_dev))
    {
      printk (KERN_WARNING "device_create\n");
      return PTR_ERR (aes_dev->sys_dev);
    }

  pci_set_drvdata (pci_dev, aes_dev);
  pci_set_master (pci_dev);

  ret = pci_set_dma_mask (pci_dev, DMA_BIT_MASK (32));
  if (IS_ERR_VALUE (ret))
    {
      printk (KERN_WARNING "pci_set_dma_mask\n");
      return ret;
    }

  ret = pci_set_consistent_dma_mask (pci_dev, DMA_BIT_MASK (32));
  if (IS_ERR_VALUE (ret))
    {
      printk (KERN_WARNING "pci_set_consistent_dma_mask\n");
      return ret;
    }

  ret = request_irq (pci_dev->irq, irq_handler, IRQF_SHARED, "aesdev", aes_dev);
  if (IS_ERR_VALUE (ret))
    {
      printk (KERN_WARNING "request_irq\n");
      return ret;
    }

  /* Wyzeruj blok transferu danych */
  iowrite32 (0x00000000, aes_dev->bar0 + AESDEV_XFER_IN_PTR);
  iowrite32 (0x00000000, aes_dev->bar0 + AESDEV_XFER_OUT_PTR);
  iowrite32 (0x00000000, aes_dev->bar0 + AESDEV_XFER_STATE_PTR);
  iowrite32 (0x00000000, aes_dev->bar0 + AESDEV_XFER_TASK);

  if (init_cmd_buffer (aes_dev))
    panic ("init_cmd_buffer");

  /* Skasuj ewentualne przerwania */
  intr = ioread32 (aes_dev->bar0 + AESDEV_INTR);
  iowrite32 (intr, aes_dev->bar0 + AESDEV_INTR);

  /* Włącz przerwania */
  iowrite32 (0xFF, aes_dev->bar0 + AESDEV_INTR_ENABLE);

  /* Zarejestruj urządzenie w sterowniku */
  aes_devs[minor] = aes_dev;

  /* Startujemy */
  AESDEV_START (aes_dev);

  KDEBUG ("Registered new aesdev\n");
  DNOTIF_LEAVE_FUN;
  return 0;
}

static void
pci_remove (struct pci_dev * pci_dev)
{
  aes128_dev *aes_dev;

  DNOTIF_ENTER_FUN;

  aes_dev = pci_get_drvdata (pci_dev);
  free_irq (pci_dev->irq, aes_dev);
  pci_clear_master (pci_dev);
  pci_iounmap (pci_dev, aes_dev->bar0);
  pci_release_regions (pci_dev);
  pci_disable_device (pci_dev);

  aes_devs[aes_dev->minor] = NULL;
  aes_dev_destroy (aes_dev);

  printk (KERN_WARNING "Unregistered aesdev\n");
  DNOTIF_LEAVE_FUN;
}

static void
pci_shutdown (struct pci_dev * dev)
{
  DNOTIF_ENTER_FUN;
  turn_off_device (pci_get_drvdata (dev));
  DNOTIF_LEAVE_FUN;
}

/*****************************************************************************/

static int
aesdrv_init (void)
{
  int ret;
  assert ("Hello" && 0);
  KDEBUG ("hello\n");

  /* Rejestracja majora */
  major = register_chrdev (0, "aesdev", &aes_fops);
  if (IS_ERR_VALUE (major))
    {
      printk (KERN_WARNING "register_chrdev\n");
      return ret;
    }

  dev_class = class_create (THIS_MODULE, "aesdev");
  if (IS_ERR_OR_NULL (dev_class))
    {
      printk (KERN_WARNING "class_create\n");
      return PTR_ERR (dev_class);
    }

  /* Rejestracja drivera PCI */
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
  int i;

  for (i = 0; i < 256; ++i)
    if (aes_devs[i] != NULL)
      {
        turn_off_device (aes_devs[i]);
        device_destroy (dev_class, MKDEV (major, i));
      }
  class_destroy (dev_class);
  pci_unregister_driver (&aes_pci);
}

module_init (aesdrv_init);
module_exit (aesdrv_cleanup);