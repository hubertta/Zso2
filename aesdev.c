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

/*
 * Insert task into device queue. Sleep if no space in queue.
 */
__attribute__ ((warn_unused_result))
static int
task_enqueue (aes128_task *task)
{
  void __iomem *bar0;
  aes128_command *cmd;
  aes128_context *context;
  aes128_dev *aes_dev;
  aes_dma_addr_t d_write_ptr;
  unsigned long irq_flags;
  DNOTIF_ENTER_FUN;

  context = task->context;
  aes_dev = context->aes_dev;
  bar0 = aes_dev->bar0;

  KDEBUG ("%d commands in progress\n", aes_dev->tasks_in_progress);

  /*** CRITICAL SECTION ****/
  AESDEV_STOP (context->aes_dev);
  spin_lock_irqsave (&context->aes_dev->lock, irq_flags);

  /* Wait until space is available in command buffer.  */
  while (aes_dev->tasks_in_progress >= 7)
    {
      spin_unlock_irqrestore (&context->aes_dev->lock, irq_flags);
      AESDEV_START (context->aes_dev);

      if (context->flags & O_NONBLOCK)
        {
          return -EAGAIN;
        }

      KDEBUG ("going to sleep :(\n");
      wait_event (context->aes_dev->command_queue, aes_dev->tasks_in_progress < 7);
      KDEBUG ("woke up with %d commands in progress\n", aes_dev->tasks_in_progress);

      AESDEV_STOP (context->aes_dev);
      spin_lock_irqsave (&context->aes_dev->lock, irq_flags);
    }

  /* Insert task into active tasks list.  */
  list_add_tail (&task->task_list, &aes_dev->task_list_head);
  aes_dev->tasks_in_progress++;

  /* Get my spot in queue and my index (intr number).  */
  d_write_ptr = ioread32 (bar0 + AESDEV_CMD_WRITE_PTR);
  task->cmd_index = AESDEV_CMD_INDEXOF (aes_dev->d_cmd_buff_ptr, d_write_ptr);

  /* Write command to device */
  cmd = ADD_OFFSET (aes_dev->k_cmd_buff_ptr, (size_t) d_write_ptr - (size_t) aes_dev->d_cmd_buff_ptr);
  cmd->in_ptr = task->d_input_data_ptr;
  cmd->out_ptr = task->d_output_data_ptr;
  cmd->ks_ptr = task->context->d_ks_ptr;
  cmd->xfer_val = AESDEV_TASK (task->block_count, 1 << task->cmd_index, 0x01, task->mode);

  /* Increment write pointer to next command */
  d_write_ptr += sizeof (aes128_command);
  if (d_write_ptr == aes_dev->d_cmd_buff_ptr + AESDRV_CMDBUFF_SIZE)
    d_write_ptr = aes_dev->d_cmd_buff_ptr;
  iowrite32 (d_write_ptr, bar0 + AESDEV_CMD_WRITE_PTR);

  spin_unlock_irqrestore (&context->aes_dev->lock, irq_flags);
  AESDEV_START (context->aes_dev);
  /*** END CRITICAL SECTION ***/

  DNOTIF_LEAVE_FUN;
  return 0;
}

__attribute__ ((warn_unused_result))
static int
task_create (aes128_context *context)
{
  aes128_task *aes_task;
  dma_addr_t temp_dma_addr;
  int ret;

  DNOTIF_ENTER_FUN;

  if (cbuf_cont (&context->write_buffer) < 16)
    {
      return -EINVAL;
    }

  /* Creating new task */
  KDEBUG ("enough data, creating new task!\n");

  aes_task = kmalloc (sizeof (aes128_task), GFP_KERNEL);
  memset (aes_task, 0, sizeof (aes128_task));
  INIT_LIST_HEAD (&aes_task->task_list);

  aes_task->block_count = cbuf_cont (&context->write_buffer) / 16;
  aes_task->context = context;
  aes_task->mode = context->mode;

  KDEBUG ("encrypting %d blocks\n", aes_task->block_count);

  aes_task->k_input_data_ptr =
          dma_alloc_coherent (&context->aes_dev->pci_dev->dev,
                              aes_task->block_count * sizeof (aes128_block),
                              &temp_dma_addr, GFP_KERNEL);
  aes_task->d_input_data_ptr = temp_dma_addr;
  aes_task->k_output_data_ptr =
          dma_alloc_coherent (&context->aes_dev->pci_dev->dev,
                              aes_task->block_count * sizeof (aes128_block),
                              &temp_dma_addr, GFP_KERNEL);
  aes_task->d_output_data_ptr = temp_dma_addr;

  KDEBUG ("DMA alloc ok, copying\n");

  /* Copy data for DMA */
  /* Data blocks */
  cbuf_take (aes_task->k_input_data_ptr,
             &context->write_buffer,
             aes_task->block_count * sizeof (aes128_block));

  KDEBUG ("DMA copied, removing from cbuf\n");
  KDEBUG ("registering task %p in context %p\n", aes_task, context);
  KDEBUG ("enqueing task\n");
  ret = task_enqueue (aes_task);
  KDEBUG ("ret = %d\n", ret);
  DNOTIF_LEAVE_FUN;
  return ret;
}

static int
task_destroy (aes128_task *task)
{
  list_del (&task->task_list);
  dma_free_coherent (&task->context->aes_dev->pci_dev->dev, AESDRV_IOBUFF_SIZE,
                     task->k_input_data_ptr, task->d_input_data_ptr);
  dma_free_coherent (&task->context->aes_dev->pci_dev->dev, AESDRV_IOBUFF_SIZE,
                     task->k_output_data_ptr, task->d_output_data_ptr);
  kfree (task);
  return 0;
}

static int
move_completed_tasks (aes128_context *context)
{
  aes128_task *task, *temp_task;
  unsigned long flags;

  DNOTIF_ENTER_FUN;

  /*** CRITICAL SECTION ****/
  spin_lock_irqsave (&context->aes_dev->lock, flags);

  /* Move my tasks to my list.  */
  list_for_each_entry_safe (task, temp_task, &context->aes_dev->completed_list_head, task_list)
  {
    if (task->context == context)
      {
        list_del (&task->task_list);
        list_add_tail (&task->task_list, &context->completed_list_head);
      }
  }

  spin_unlock_irqrestore (&context->aes_dev->lock, flags);
  /*** END CRITICAL SECTION ****/

  /* Copy from tasks to buffer - as long as space is available.  */
  list_for_each_entry_safe (task, temp_task, &context->completed_list_head, task_list)
  {
    if (cbuf_free (&context->read_buffer) >= task->block_count * sizeof (aes128_block))
      {
        cbuf_add_from_kernel (&context->read_buffer, (char *) task->k_output_data_ptr, task->block_count * sizeof (aes128_block));
        task_destroy (task);
      }
    else
      break;
  }
  DNOTIF_LEAVE_FUN;
  return 0;
}

static size_t
available_read_data (aes128_context *context)
{
  DNOTIF_ENTER_FUN;

  /* If no data is available, try to download some from the device.  */
  if (cbuf_cont (&context->read_buffer) == 0)
    move_completed_tasks (context);

  DNOTIF_LEAVE_FUN;
  return cbuf_cont (&context->read_buffer);
}
/*****************************************************************************/

/*** Circular buffer *********************************************************/

/*
 * Number of free spots in circular buffer.
 */
static inline size_t
cbuf_free (const struct circ_buf *buf)
{
  return CIRC_SPACE (buf->head, buf->tail, AESDRV_IOBUFF_SIZE);
}

/*
 * Number of items in circular buffer.
 */
static inline size_t
cbuf_cont (const struct circ_buf *buf)
{
  return CIRC_CNT (buf->head, buf->tail, AESDRV_IOBUFF_SIZE);
}

/*
 * Copy data from kernel memory space to buffer.
 */
static int
cbuf_add_from_kernel (struct circ_buf *buf, const char *data, size_t len)
{
  size_t len1, len2;
  DNOTIF_ENTER_FUN;
  KDEBUG ("had before %d\n", cbuf_cont (buf));

  if (cbuf_free (buf) < len)
    {
      KDEBUG ("not enough space in buffer!\n");
      return -1;
    }

  len1 = min (len, (size_t) CIRC_SPACE_TO_END (buf->head, buf->tail, AESDRV_IOBUFF_SIZE));
  len2 = len - len1;

  memcpy (buf->buf + buf->head, data, len1);
  if (len2)
    memcpy (buf->buf, data + len1, len2);

  buf->head = (buf->head + len) % AESDRV_IOBUFF_SIZE;

  KDEBUG ("have now %d\n", cbuf_cont (buf));
  DNOTIF_LEAVE_FUN;
  return 0;
}

/*
 * Copy len elements from __user *data to circular buffer.
 */
static int
cbuf_add_from_user (struct circ_buf *buf, const char __user *data, size_t len)
{
  int ret;
  size_t len1, len2;
  DNOTIF_ENTER_FUN;

  if (cbuf_free (buf) < len)
    {
      KDEBUG ("not enough space in buffer!\n");
      return -1;
    }

  KDEBUG ("first user's=%02x\n", data[0] & 0xFF);

  len1 = min (len, (size_t) CIRC_SPACE_TO_END (buf->head, buf->tail, AESDRV_IOBUFF_SIZE));
  len2 = len - len1;

  ret = copy_from_user (buf->buf + buf->head, data, len1);
  ret = copy_from_user (buf->buf, data + len1, len2);

  KDEBUG ("head before=%d tail before=%d len=%d len1=%d len2=%d\n", buf->head, buf->tail, len, len1, len2);
  buf->head = (buf->head + len) % AESDRV_IOBUFF_SIZE;
  KDEBUG ("head after=%d tail after=%d\n", buf->head, buf->tail);

  KDEBUG ("first at tail=%02x last at head=%02x\n", *(buf->buf + buf->tail),
          *(buf->buf + buf->head));

  DNOTIF_LEAVE_FUN;
  return ret;
}

/*
 * Move len elements from buffer to vdest. If vdest == NULL discard.
 */
static int
cbuf_take (void *vdest, struct circ_buf *buf, size_t len)
{
  size_t len1, len2;
  char *dest;

  DNOTIF_ENTER_FUN;
  dest = vdest;

  if (cbuf_cont (buf) < len)
    {
      KDEBUG ("not enough elements in buffer!\n");
      return -1;
    }

  len1 = min (len, (size_t) CIRC_CNT_TO_END (buf->head, buf->tail, AESDRV_IOBUFF_SIZE));
  len2 = len - len1;

  if (dest != NULL)
    {
      memcpy (dest, buf->buf + buf->tail, len1);
      memcpy (dest + len1, buf->buf, len2);
    }

  buf->tail = (buf->tail + len) % AESDRV_IOBUFF_SIZE;

  DNOTIF_LEAVE_FUN;
  return 0;
}

static int
cbuf_take_tail (struct circ_buf *buf, size_t len)
{
  buf->head = (buf->head + AESDRV_IOBUFF_SIZE - len) % AESDRV_IOBUFF_SIZE;
  return 0;
}
/*****************************************************************************/

/*** AES context *************************************************************/
static void
context_init (aes128_context *context, aes128_dev *aes_dev)
{
  dma_addr_t temp_dma_addr;

  DNOTIF_ENTER_FUN;
  memset (context, 0, sizeof (aes128_context));
  context->mode = AES_UNDEF;
  context->read_buffer.buf = kmalloc (AESDRV_IOBUFF_SIZE, GFP_KERNEL);
  context->write_buffer.buf = kmalloc (AESDRV_IOBUFF_SIZE, GFP_KERNEL);
  context->file_open = 1;
  context->aes_dev = aes_dev;
  context->k_ks_ptr = dma_alloc_coherent (&aes_dev->pci_dev->dev,
                                          2 * sizeof (aes128_block),
                                          &temp_dma_addr, GFP_KERNEL);
  context->d_ks_ptr = temp_dma_addr;
  init_waitqueue_head (&context->read_queue);
  init_waitqueue_head (&context->write_queue);
  mutex_init (&context->read_lock);
  mutex_init (&context->write_lock);
  INIT_LIST_HEAD (&context->context_list);
  INIT_LIST_HEAD (&context->completed_list_head);
  list_add (&context->context_list, &aes_dev->context_list_head);
  DNOTIF_LEAVE_FUN;
}

static void
context_destroy (aes128_context *context)
{
  unsigned long irq_flags;
  DNOTIF_ENTER_FUN;
  spin_lock_irqsave (&context->aes_dev->lock, irq_flags);
  list_del (&context->context_list);
  spin_unlock_irqrestore (&context->aes_dev->lock, irq_flags);
  mutex_destroy (&context->read_lock);
  mutex_destroy (&context->write_lock);
  dma_free_coherent (&context->aes_dev->pci_dev->dev,
                     2 * sizeof (aes128_block),
                     context->k_ks_ptr,
                     context->d_ks_ptr);
  kfree (context->read_buffer.buf);
  kfree (context->write_buffer.buf);
  kfree (context);
  DNOTIF_LEAVE_FUN;
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

  DNOTIF_ENTER_FUN;

  /* TODO */
  aes_dev = ptr;

  /*** CRITICAL SECTION ***/
  AESDEV_STOP (aes_dev);
  spin_lock_irqsave (&aes_dev->lock, irq_flags);
  intr = ioread32 (aes_dev->bar0 + AESDEV_INTR) & 0xFF;
  if (!intr)
    {
      spin_unlock_irqrestore (&aes_dev->lock, irq_flags);
      AESDEV_START (aes_dev);
      return IRQ_NONE;
    }

  /* Move completed tasks to completed tasks list.  */
  list_for_each_entry_safe (task, temp_task, &aes_dev->task_list_head, task_list)
  {
    if ((1 << task->cmd_index) & intr)
      {
        list_del (&task->task_list);
        list_add_tail (&task->task_list, &aes_dev->completed_list_head);
        aes_dev->tasks_in_progress--;
        /* Notify about new data.  */
        wake_up (&task->context->read_queue);
      }
  }

  /* My interrupt => at least one command completed.  */
  wake_up (&aes_dev->command_queue);

  /* All interrupts handled.  */
  iowrite32 (intr, aes_dev->bar0 + AESDEV_INTR);

  spin_unlock_irqrestore (&aes_dev->lock, irq_flags);
  AESDEV_START (aes_dev);
  /*** END CRITICAL SECTION ***/
  KDEBUG ("%d commands still in progress\n", aes_dev->tasks_in_progress);

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

  DNOTIF_ENTER_FUN;
  context = f->private_data;
  KDEBUG ("%d bytes in read buffer, len=%zu\n", cbuf_cont (&context->read_buffer), len);
  mutex_lock (&context->read_lock);

  if (context->mode == AES_UNDEF)
    {
      KDEBUG ("no mode set\n");
      retval = -EINVAL;
      goto exit;
    }

  if (f->f_flags & O_NONBLOCK)
    {
      if (available_read_data (context) == 0)
        {
          KDEBUG ("no data, returning EAGAIN\n");
          retval = -EAGAIN;
          goto exit;
        }
    }
  else
    {
      while (available_read_data (context) == 0)
        {
          KDEBUG ("going to sleep :(\n");
          wait_event (context->read_queue, available_read_data (context) != 0);
        }
    }

  to_copy = min (len, cbuf_cont (&context->read_buffer));
  to_copy1 = min (to_copy, (size_t) CIRC_CNT_TO_END (context->read_buffer.head,
                                                     context->read_buffer.tail,
                                                     AESDRV_IOBUFF_SIZE));
  to_copy2 = to_copy - to_copy1;
  if (copy_to_user (buf, context->read_buffer.buf + context->read_buffer.tail, to_copy1))
    {
      KDEBUG ("copy_to_user\n");
      retval = -ENOMEM;
      goto exit;
    }
  if (copy_to_user (buf + to_copy1, context->read_buffer.buf, to_copy2))
    {
      KDEBUG ("copy_to_user\n");
      retval = -ENOMEM;
      goto exit;
    }
  context->read_buffer.tail = (context->read_buffer.tail + to_copy) % AESDRV_IOBUFF_SIZE;

  KDEBUG ("%d bytes were read, %d left in buff\n", to_copy, cbuf_cont (&context->read_buffer));
  retval = to_copy;

exit:
  DNOTIF_LEAVE_FUN;
  mutex_unlock (&context->read_lock);
  return retval;
}

static ssize_t
file_write (struct file *f, const char __user *buf, size_t len, loff_t *off)
{
  aes128_context *context;
  ssize_t retval;
  int to_take;

  DNOTIF_ENTER_FUN;
  context = f->private_data;
  KDEBUG ("%d bytes in write buffer, len=%zu\n", cbuf_cont (&context->write_buffer), len);
  mutex_lock (&context->write_lock);
  if (context->mode == AES_UNDEF)
    {
      KDEBUG ("no mode set\n");
      retval = -EINVAL;
      goto exit;
    }

  KDEBUG ("received %d bytes\n", len);
  KDEBUG ("had before %d in buf\n", cbuf_cont (&context->write_buffer));
  to_take = min (cbuf_free (&context->write_buffer), len);
  cbuf_add_from_user (&context->write_buffer, buf, to_take);
  KDEBUG ("have now %d in buf\n", cbuf_cont (&context->write_buffer));
  KDEBUG ("my context is %p\n", context);
  retval = task_create (context);
  if (retval == 0)
    retval = to_take;
  else
    {
      /* Revert changes.  */
      cbuf_take_tail (&context->write_buffer, to_take);
    }
exit:
  DNOTIF_LEAVE_FUN;
  mutex_unlock (&context->write_lock);
  return retval;
}

static int
file_open (struct inode *i, struct file *f)
{
  aes128_context *context;
  DNOTIF_ENTER_FUN;

  context = kmalloc (sizeof (aes128_context), GFP_KERNEL);
  f->private_data = context;
  context_init (context, aes_devs[iminor (i)]);
  context->flags = f->f_flags;
  KDEBUG ("assigned opened file to device %p at context %p\n", context->aes_dev, context);
  DNOTIF_LEAVE_FUN;
  return 0;
}

static int
file_release (struct inode *i, struct file *f)
{
  /* TODO */
  aes128_context *context;

  DNOTIF_ENTER_FUN;

  context = f->private_data;
  mutex_lock (&context->write_lock);
  mutex_lock (&context->read_lock);
  /* Remember that the file has been closed */
  context->file_open = 0;
  if (context->cmds_in_progress == 0)
    {
      /* Gdy już skończyły się wszystkie operacje a plik
       * jest zamknięty, to mogę bezpiecznie go wywalić z 
       * urządzenia.  */
      mutex_unlock (&context->write_lock);
      mutex_unlock (&context->read_lock);
      context_destroy (f->private_data);
    }
  else
    {
      mutex_unlock (&context->write_lock);
      mutex_unlock (&context->read_lock);
    }
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
  mutex_lock (&context->write_lock);
  mutex_lock (&context->read_lock);

  if (context->mode == AES_UNDEF && cmd == AESDEV_IOCTL_GET_STATE)
    {
      retval = -EINVAL;
      goto exit;
    }

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
          retval = -EINVAL;
          goto exit;
        }

      if (copy_to_user ((void *) arg, &context->k_ks_ptr[1], sizeof (aes128_block)))
        {
          KDEBUG ("copy_to_user\n");
          retval = -ENOMEM;
          goto exit;
        }

      retval = 0;
      goto exit;
    }

  if (copy_from_user (&context->k_ks_ptr[0], (void *) arg, sizeof (aes128_block)))
    {
      KDEBUG ("copy_from_user\n");
      retval = -ENOMEM;
      goto exit;
    }

  if (cmd != AESDEV_IOCTL_SET_ECB_ENCRYPT && cmd != AESDEV_IOCTL_SET_ECB_DECRYPT)
    if (copy_from_user (&context->k_ks_ptr[1], ((char *) arg) + sizeof (aes128_block),
                        sizeof (aes128_block)))
      {
        KDEBUG ("copy_from_user\n");
        retval = -EFAULT;
        goto exit;
      }

  KDEBUG ("cmd=%d mode=%d, arg=%p\n", cmd, context->mode, (void *) arg);
  retval = 0;
exit:
  mutex_unlock (&context->write_lock);
  mutex_unlock (&context->read_lock);
  DNOTIF_LEAVE_FUN;
  return retval;
}
/*****************************************************************************/

/*** Device procedures *******************************************************/
static int
init_cmd_buffer (aes128_dev *aes_dev)
{
  void __iomem *bar0;
  dma_addr_t tmp_dma_addr;

  DNOTIF_ENTER_FUN;

  bar0 = aes_dev->bar0;

  /* TODO: 16-byte alignment */
  aes_dev->k_cmd_buff_ptr =
          dma_alloc_coherent (&aes_dev->pci_dev->dev, AESDRV_CMDBUFF_SIZE,
                              &tmp_dma_addr, GFP_KERNEL);
  aes_dev->d_cmd_buff_ptr = tmp_dma_addr;

  iowrite32 ((uint32_t) aes_dev->d_cmd_buff_ptr, bar0 + AESDEV_CMD_BEGIN_PTR);
  /* TODO: Ostatni czy zaostatni? */
  iowrite32 ((uint32_t) aes_dev->d_cmd_buff_ptr + AESDRV_CMDBUFF_SIZE, bar0 + AESDEV_CMD_END_PTR);
  iowrite32 ((uint32_t) aes_dev->d_cmd_buff_ptr, bar0 + AESDEV_CMD_READ_PTR);
  iowrite32 ((uint32_t) aes_dev->d_cmd_buff_ptr, bar0 + AESDEV_CMD_WRITE_PTR);

  KDEBUG ("write ptr set to %p\n", &aes_dev->d_cmd_buff_ptr);
  DNOTIF_LEAVE_FUN;

  return 0;
}

static int
aes_dev_destroy (aes128_dev *aes_dev)
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
turn_off_device (aes128_dev *aes_dev)
{
  AESDEV_STOP (aes_dev);
  return 0;
}

static int
pci_probe (struct pci_dev *pci_dev, const struct pci_device_id *id)
{
  aes128_dev *aes_dev;
  uint32_t intr;
  int minor;

  DNOTIF_ENTER_FUN;

  /* Find free slot for new device.  */
  for (minor = 0; minor < 256; ++minor)
    if (aes_devs[minor] == NULL)
      break;

  if (pci_enable_device (pci_dev))
    {
      printk (KERN_WARNING "pci_enable_device\n");
      DNOTIF_LEAVE_FUN;
      return -EFAULT;
    }
  if (pci_request_regions (pci_dev, "aesdev"))
    {
      printk (KERN_WARNING "pci_request_regions\n");
      DNOTIF_LEAVE_FUN;
      return -EFAULT;
    }

  /* Initialize new aes128_device structure.  */
  aes_dev = kmalloc (sizeof (aes128_dev), GFP_KERNEL);
  memset (aes_dev, 0, sizeof (aes128_dev));
  spin_lock_init (&aes_dev->lock);
  init_waitqueue_head (&aes_dev->command_queue);
  INIT_LIST_HEAD (&aes_dev->context_list_head);
  INIT_LIST_HEAD (&aes_dev->task_list_head);
  INIT_LIST_HEAD (&aes_dev->completed_list_head);
  aes_dev->pci_dev = pci_dev;
  aes_dev->minor = minor;
  aes_dev->tasks_in_progress = 0;

  aes_dev->bar0 = pci_iomap (pci_dev, 0, 0);
  aes_dev->sys_dev = device_create (dev_class, NULL, MKDEV (major, minor), NULL, "aes%d", minor);

  pci_set_drvdata (pci_dev, aes_dev);

  pci_set_master (pci_dev);
  pci_set_dma_mask (pci_dev, DMA_BIT_MASK (32));
  pci_set_consistent_dma_mask (pci_dev, DMA_BIT_MASK (32));

  if (request_irq (pci_dev->irq, irq_handler, IRQF_SHARED, "aesdev", aes_dev))
    {
      KDEBUG ("request_irq\n");
      DNOTIF_LEAVE_FUN;
      return -EFAULT;
    }

  /* Wyzeruj blok transferu danych */
  iowrite32 (0x00000000, aes_dev->bar0 + AESDEV_XFER_IN_PTR);
  iowrite32 (0x00000000, aes_dev->bar0 + AESDEV_XFER_OUT_PTR);
  iowrite32 (0x00000000, aes_dev->bar0 + AESDEV_XFER_STATE_PTR);
  iowrite32 (0x00000000, aes_dev->bar0 + AESDEV_XFER_TASK);
  init_cmd_buffer (aes_dev);

  /* Skasuj ewentualne przerwania */
  intr = ioread32 (aes_dev->bar0 + AESDEV_INTR);
  iowrite32 (intr, aes_dev->bar0 + AESDEV_INTR);

  /* Zarejestruj urządzenie w sterowniku */
  aes_devs[minor] = aes_dev;

  /* Włącz przerwania */
  iowrite32 (0xFF, aes_dev->bar0 + AESDEV_INTR_ENABLE);

  KDEBUG ("Registered new aesdev\n");
  DNOTIF_LEAVE_FUN;
  return 0;
}

static void
pci_remove (struct pci_dev *pci_dev)
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
pci_shutdown (struct pci_dev *dev)
{
  DNOTIF_ENTER_FUN;
  turn_off_device (pci_get_drvdata (dev));
  DNOTIF_LEAVE_FUN;
}

/*****************************************************************************/

static int
aesdrv_init (void)
{
  DNOTIF_ENTER_FUN;
  KDEBUG ("hello\n");

  /* Rejestracja majora */
  major = register_chrdev (0, "aesdev", &aes_fops);
  dev_class = class_create (THIS_MODULE, "aesdev");

  /* Rejestracja drivera PCI */
  if (pci_register_driver (&aes_pci))
    {
      printk (KERN_WARNING "pci_register_driver\n");
      return -EFAULT;
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
  KDEBUG ("bye\n");
}

module_init (aesdrv_init);
module_exit (aesdrv_cleanup);