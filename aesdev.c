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

static int major;
static int dev_count;
static aes128_dev *aes_devs[256];
static struct class *dev_class;

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
  {PCI_DEVICE (0x1af4, 0x10fc)},
  {0}
};

static struct pci_driver aes_pci = {
  name : "aesdev",
  id_table : pci_ids,
  probe : pci_probe,
  remove : pci_remove,
  suspend : pci_suspend,
  resume : pci_resume,
  shutdown : pci_shutdown
};
/*****************************************************************************/

/*** Helpers *****************************************************************/

/* This function might sleep! */
static int
task_enqueue (aes128_task *task)
{
  void __iomem *bar0;
  aes128_command *cmd;
  aes128_context *context;
  aes128_dev *aes_dev;
  aes_dma_addr_t d_begin_ptr, d_write_ptr, d_read_ptr, d_end_ptr;
  int my_index;
  unsigned long irq_flags;
  KDEBUG ("%s: entering\n", __func__);

  context = task->context;
  aes_dev = context->aes_dev;
  bar0 = aes_dev->bar0;

  /*** CRITICAL SECTION ****/
  AESDEV_STOP (context->aes_dev);
  spin_lock_irqsave (&context->aes_dev->lock, irq_flags);

  d_begin_ptr = ioread32 (bar0 + AESDEV_CMD_BEGIN_PTR);
  d_end_ptr = ioread32 (bar0 + AESDEV_CMD_END_PTR);
  d_write_ptr = ioread32 (bar0 + AESDEV_CMD_WRITE_PTR);
  d_read_ptr = ioread32 (bar0 + AESDEV_CMD_READ_PTR);
  my_index = AESDEV_CMD_INDEXOF (d_begin_ptr, d_write_ptr);

  /* Czekam na miejsce w kolejce poleceń.  */
  while (!list_empty (&aes_dev->task_list_head) &&
         my_index == AESDEV_CMD_INDEXOF (d_begin_ptr, list_first_entry (&aes_dev->task_list_head, aes128_task, task_list)->d_write_ptr))
    {
      /* Brak miejsc na dalsze komendy, czekamy.  */
      context->aes_dev->command_space = 0;
      spin_unlock_irqrestore (&context->aes_dev->lock, irq_flags);
      AESDEV_START (context->aes_dev);

      wait_event (context->aes_dev->command_queue, context->aes_dev->command_space > 0);

      AESDEV_STOP (context->aes_dev);
      spin_lock_irqsave (&context->aes_dev->lock, irq_flags);

      d_write_ptr = ioread32 (bar0 + AESDEV_CMD_WRITE_PTR);
      my_index = AESDEV_CMD_INDEXOF (d_begin_ptr, d_write_ptr);
    }
  list_add_tail (&task->task_list, &aes_dev->task_list_head);

  d_write_ptr = ioread32 (bar0 + AESDEV_CMD_WRITE_PTR);
  /* Write new command to device */
  cmd = (void *) (((char *) task->context->aes_dev->k_cmd_buff_ptr) + (d_write_ptr - d_begin_ptr));
  //  KDEBUG ("%s: current write ptr = %p\n", __func__, cmd);
  cmd->in_ptr = task->d_input_data_ptr;
  cmd->out_ptr = task->d_output_data_ptr;
  cmd->ks_ptr = task->d_ks_ptr;
  cmd->xfer_val = AESDEV_TASK (task->block_count, 1 << my_index, 0x01, task->mode);

  /* Save command pointers for later check if command was completed.  */
  task->d_write_ptr = d_write_ptr;
  task->d_read_ptr = d_read_ptr;

  /* Increment write pointer to next command */
  d_write_ptr += 16;
  if (d_write_ptr == d_end_ptr)
    d_write_ptr = d_begin_ptr;
  iowrite32 (d_write_ptr, bar0 + AESDEV_CMD_WRITE_PTR);

  spin_unlock_irqrestore (&context->aes_dev->lock, irq_flags);
  AESDEV_START (context->aes_dev);
  /*** END CRITICAL SECTION ***/

  //  KDEBUG ("%s: d_read_ptr=%p, d_write_ptr=%p\n", __func__, (void*) ioread32 (bar0 + AESDEV_CMD_READ_PTR), (void*) ioread32 (bar0 + AESDEV_CMD_WRITE_PTR));
  {
    int i;
    KDEBUG ("Data=");
    for (i = 0; i < 16; ++i)
      KDEBUG ("%02x", task->k_input_data_ptr[0].state[i]);
    KDEBUG ("\nKey=");
    for (i = 0; i < 16; ++i)
      KDEBUG ("%02x", task->k_ks_ptr[0].state[i]);
    KDEBUG ("\nState=");
    for (i = 0; i < 16; ++i)
      KDEBUG ("%02x", task->k_ks_ptr[1].state[i]);
    KDEBUG ("\nMode=%d\n", task->mode);
  }

  KDEBUG ("%s: leaving\n", __func__);
  return 0;
}

static int
task_create (aes128_context *context)
{
  KDEBUG ("%s: entering\n", __func__);
  /* Creating new task */
  if (cbuf_cont (&context->write_buffer) >= 16)
    {
      aes128_task *aes_task;
      dma_addr_t temp_dma_addr;

      KDEBUG ("%s: enough data, creating new task!\n", __FUNCTION__);

      aes_task = kmalloc (sizeof (aes128_task), GFP_KERNEL);
      memset (aes_task, 0, sizeof (aes128_task));

      aes_task->block_count = cbuf_cont (&context->write_buffer) / 16;
      aes_task->context = context;
      aes_task->mode = context->mode;
      KDEBUG ("%s: encrypting %d blocks\n", __func__, aes_task->block_count);

      KDEBUG ("%s: dev=%p\n", __func__, &context->aes_dev->pci_dev->dev);

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
      aes_task->k_ks_ptr =
              dma_alloc_coherent (&context->aes_dev->pci_dev->dev,
                                  sizeof (aes128_block) * (HAS_STATE (aes_task->mode) ? 2 : 1),
                                  &temp_dma_addr, GFP_KERNEL);
      aes_task->d_ks_ptr = temp_dma_addr;

      KDEBUG ("%s: DMA alloc ok, copying\n", __func__);

      /* Copy data for DMA */
      /* Data blocks */
      cbuf_take (aes_task->k_input_data_ptr,
                 &context->write_buffer,
                 aes_task->block_count * sizeof (aes128_block));
      /* Key */
      memcpy (aes_task->k_ks_ptr,
              context->key.state,
              sizeof (aes128_block));
      /* State */
      if (HAS_STATE (aes_task->mode))
        {
          KDEBUG ("%s: mode with state, loading iv\n", __func__);
          memcpy (&aes_task->k_ks_ptr[1],
                  context->state.state,
                  sizeof (aes128_block));
        }

      KDEBUG ("%s: DMA copied, removing from cbuf\n", __func__);
      KDEBUG ("%s: registering task %p in context %p\n", __func__,
              (void *) aes_task, (void *) context);

      /* Register task with context.  */
      INIT_LIST_HEAD (&aes_task->task_list);

      KDEBUG ("%s: enqueing task\n", __func__);
      task_enqueue (aes_task);

      context->cmds_in_progress++;

      KDEBUG ("%s: poszlo\n", __FUNCTION__);
    }
  KDEBUG ("%s: leaving\n", __func__);
  return 0;
}

static int
task_destroy (aes128_task *task)
{
  list_del (&task->task_list);
  dma_free_coherent (&task->context->aes_dev->pci_dev->dev, AESDRV_IOBUFF_SIZE,
                     task->k_input_data_ptr, task->d_input_data_ptr);
  dma_free_coherent (&task->context->aes_dev->pci_dev->dev, AESDRV_IOBUFF_SIZE,
                     task->k_output_data_ptr, task->d_output_data_ptr);
  dma_free_coherent (&task->context->aes_dev->pci_dev->dev,
                     sizeof (aes128_block) * (HAS_STATE (task->mode) ? 2 : 1),
                     task->k_ks_ptr, task->d_ks_ptr);
  kfree (task);
  return 0;
}
/*****************************************************************************/

/*** Circular buffer *********************************************************/

/*
 * Number of free spots in circular buffer.
 */
static int
cbuf_free (const struct circ_buf *buf)
{
  KDEBUG ("%s: entering\n", __func__);
  return CIRC_SPACE (buf->head, buf->tail, AESDRV_IOBUFF_SIZE);
}

/*
 * Number of items in circular buffer.
 */
static int
cbuf_cont (const struct circ_buf *buf)
{
  KDEBUG ("%s: entering\n", __func__);
  return CIRC_CNT (buf->head, buf->tail, AESDRV_IOBUFF_SIZE);
}

static int
cbuf_add_from_kernel (struct circ_buf *buf, const char *data, int len)
{
  int len1, len2;
  KDEBUG ("%s: entering\n", __func__);
  KDEBUG ("%s: had before %d\n", __func__, cbuf_cont (buf));

  if (cbuf_free (buf) < len)
    {
      KDEBUG ("%s: not enough space in buffer!\n", __func__);
      return -1;
    }

  len1 = min (len, CIRC_SPACE_TO_END (buf->head, buf->tail, AESDRV_IOBUFF_SIZE));
  len2 = len - len1;

  memcpy (buf->buf + buf->head, data, len1);
  if (len2)
    memcpy (buf->buf, data + len1, len2);

  buf->head = (buf->head + len) % AESDRV_IOBUFF_SIZE;

  KDEBUG ("%s: have now%d\n", __func__, cbuf_cont (buf));
  KDEBUG ("%s: leaving\n", __func__);
  return 0;
}

/*
 * Copy len elements from __user *data to circular buffer.
 */
static int
cbuf_add_from_user (struct circ_buf *buf, const char __user *data, int len)
{
  int ret;
  int len1, len2;
  KDEBUG ("%s: entering\n", __func__);

  if (cbuf_free (buf) < len)
    {
      printk (KERN_WARNING "%s: not enough space in buffer!\n", __FUNCTION__);
      return -1;
    }

  KDEBUG ("%s: first user's=%02x\n", __func__, data[0] & 0xFF);

  len1 = min (len, CIRC_SPACE_TO_END (buf->head, buf->tail, AESDRV_IOBUFF_SIZE));
  len2 = len - len1;
  /* TODO split into two !! */
  ret = copy_from_user (buf->buf + buf->head, data, len1);
  ret = copy_from_user (buf->buf, data + len1, len2);

  KDEBUG ("%s: head before=%d tail before=%d len=%d len1=%d len2=%d\n", __func__, buf->head, buf->tail, len, len1, len2);
  buf->head = (buf->head + len) % AESDRV_IOBUFF_SIZE;
  KDEBUG ("%s: head after=%d tail after=%d\n", __func__, buf->head, buf->tail);

  KDEBUG ("%s: first at tail=%02x last at head=%02x\n", __func__,
          *(buf->buf + buf->tail), *(buf->buf + buf->head));

  KDEBUG ("%s: leaving\n", __func__);
  return ret;
}

/*
 * Remove len elements from circular buffer.
 */
static int
cbuf_take (void *vdest, struct circ_buf *buf, int len)
{
  int len1, len2;
  char *dest;

  dest = vdest;

  KDEBUG ("%s: entering\n", __func__);
  if (cbuf_cont (buf) < len)
    {
      printk (KERN_WARNING "%s: not enough elements in buffer!\n", __FUNCTION__);
      return -1;
    }

  len1 = min (len, CIRC_CNT_TO_END (buf->head, buf->tail, AESDRV_IOBUFF_SIZE));
  len2 = len - len1;

  memcpy (dest, buf->buf + buf->tail, len1);
  memcpy (dest + len1, buf->buf, len2);

  buf->tail = (buf->tail + len) % AESDRV_IOBUFF_SIZE;

  KDEBUG ("%s: leaving\n", __func__);
  return 0;
}
/*****************************************************************************/

/*** Simple list *************************************************************/
static int
move_completed_tasks (aes128_context *context)
{
  aes128_task *task, *temp_task;
  unsigned long flags;

  KDEBUG ("%s: entering\n", __func__);

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

  return 0;
}

static int
available_read_data (aes128_context *context)
{
  KDEBUG ("%s: entering\n", __func__);

  /* If no data is available, try to download some from the device.  */
  if (cbuf_cont (&context->read_buffer) == 0)
    move_completed_tasks (context);

  KDEBUG ("%s: leaving\n", __func__);
  return cbuf_cont (&context->read_buffer);
}
/*****************************************************************************/

/*** AES context *************************************************************/
static void
context_init (aes128_context *context, aes128_dev *aes_dev)
{
  KDEBUG ("%s: entering, dev=%p\n", __func__, aes_dev);
  memset (context, 0, sizeof (aes128_context));
  context->mode = AES_UNDEF;
  context->read_buffer.buf = kmalloc (AESDRV_IOBUFF_SIZE, GFP_KERNEL);
  context->write_buffer.buf = kmalloc (AESDRV_IOBUFF_SIZE, GFP_KERNEL);
  context->file_open = 1;
  context->aes_dev = aes_dev;
  init_waitqueue_head (&context->read_queue);
  init_waitqueue_head (&context->write_queue);
  mutex_init (&context->lock);
  INIT_LIST_HEAD (&context->context_list);
  INIT_LIST_HEAD (&context->completed_list_head);
  list_add (&context->context_list, &aes_dev->context_list_head);
  KDEBUG ("%s: leaving\n", __func__);
}

static void
context_destroy (aes128_context *context)
{
  unsigned long irq_flags;
  KDEBUG ("%s: entering\n", __func__);
  spin_lock_irqsave (&context->aes_dev->lock, irq_flags);
  list_del (&context->context_list);
  spin_unlock_irqrestore (&context->aes_dev->lock, irq_flags);
  mutex_destroy (&context->lock);
  kfree (context->read_buffer.buf);
  kfree (context->write_buffer.buf);
  kfree (context);
  KDEBUG ("%s: leaving\n", __func__);
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

  /* Move completed tasks to another list.  */
  list_for_each_entry_safe (task, temp_task, &aes_dev->task_list_head, task_list)
  {
    int task_index;

    task_index = AESDEV_CMD_INDEXOF (aes_dev->d_cmd_buff_ptr, task->d_write_ptr);
    if ((1 << task_index) & intr)
      {
        list_del (&task->task_list);
        list_add_tail (&task->task_list, &aes_dev->completed_list_head);
        /* Notify about new data.  */
        wake_up (&task->context->read_queue);
      }
  }

  /* My interrupt => at least one command completed.  */
  aes_dev->command_space = 1;
  wake_up (&aes_dev->command_queue);

  /* Reset all interrupts */
  iowrite32 (intr, aes_dev->bar0 + AESDEV_INTR);

  spin_unlock_irqrestore (&aes_dev->lock, irq_flags);
  AESDEV_START (aes_dev);
  /*** END CRITICAL SECTION ***/

  return IRQ_HANDLED;
}
/*****************************************************************************/

/*** File handlers ***********************************************************/
static ssize_t
file_read (struct file *f, char __user *buf, size_t len, loff_t *off)
{
  aes128_context *context;
  int to_copy, to_copy1, to_copy2;
  ssize_t retval;

  KDEBUG ("%s: entering\n", __func__);
  context = f->private_data;
  mutex_lock (&context->lock);

  if (context->mode == AES_UNDEF)
    {
      KDEBUG ("%s: no mode set\n", __FUNCTION__);
      retval = -EINVAL;
      goto exit;
    }

  KDEBUG ("%s: %d bytes in read buffer\n", __func__, cbuf_cont (&context->read_buffer));

  while (available_read_data (context) == 0)
    {
      KDEBUG ("%s: going to sleep :(\n", __func__);
      wait_event (context->read_queue, available_read_data (context) != 0);
    }

  to_copy = min ((int) len, cbuf_cont (&context->read_buffer));
  to_copy1 = min (to_copy, CIRC_CNT_TO_END (context->read_buffer.head,
                                            context->read_buffer.tail,
                                            AESDRV_IOBUFF_SIZE));
  to_copy2 = to_copy - to_copy1;
  if (copy_to_user (buf, context->read_buffer.buf + context->read_buffer.tail, to_copy1))
    {
      KDEBUG ("%s: copy_to_user\n", __func__);
      retval = -ENOMEM;
      goto exit;
    }
  if (copy_to_user (buf + to_copy1, context->read_buffer.buf, to_copy2))
    {
      KDEBUG ("%s: copy_to_user\n", __func__);
      retval = -ENOMEM;
      goto exit;
    }
  context->read_buffer.tail = (context->read_buffer.tail + to_copy) % AESDRV_IOBUFF_SIZE;

  KDEBUG ("%s: %d bytes were read, %d left in buff\n", __func__, to_copy, cbuf_cont (&context->read_buffer));
  KDEBUG ("%s: leaving\n", __func__);
  retval = to_copy;

exit:
  mutex_unlock (&context->lock);
  return retval;
}

static ssize_t
file_write (struct file *f, const char __user *buf, size_t len, loff_t *off)
{
  aes128_context *context;
  ssize_t retval;
  int to_take;

  KDEBUG ("%s: entering\n", __func__);
  context = f->private_data;
  mutex_lock (&context->lock);
  if (context->mode == AES_UNDEF)
    {
      KDEBUG ("%s: no mode set\n", __func__);
      retval = -EINVAL;
      goto exit;
    }

  KDEBUG ("%s: received %d bytes\n", __FUNCTION__, len);
  KDEBUG ("%s: had before %d in buf\n", __FUNCTION__, cbuf_cont (&context->write_buffer));
  to_take = min (cbuf_free (&context->write_buffer), (int) len);
  cbuf_add_from_user (&context->write_buffer, buf, to_take);
  KDEBUG ("%s: have now %d in buf\n", __FUNCTION__, cbuf_cont (&context->write_buffer));
  KDEBUG ("%s: my context is %p\n", __func__, context);
  task_create (context);
  retval = to_take;

exit:
  KDEBUG ("%s: leaving\n", __func__);
  mutex_unlock (&context->lock);
  return retval;
}

static int
file_open (struct inode *i, struct file *f)
{
  aes128_context *context;
  KDEBUG ("%s: entering\n", __func__);

  context = kmalloc (sizeof (aes128_context), GFP_KERNEL);
  f->private_data = context;
  context_init (context, aes_devs[iminor (i)]);
  KDEBUG ("%s: assigned opened file to device %p at context %p\n", __func__, context->aes_dev, context);
  KDEBUG ("%s: leaving\n", __func__);
  return 0;
}

static int
file_release (struct inode *i, struct file *f)
{
  /* TODO */
  aes128_context *context;

  KDEBUG ("%s: entering\n", __func__);

  context = f->private_data;
  mutex_lock (&context->lock);
  /* Remember that the file has been closed */
  context->file_open = 0;
  if (context->cmds_in_progress == 0)
    {
      /* Gdy już skończyły się wszystkie operacje a plik
       * jest zamknięty, to mogę bezpiecznie go wywalić z 
       * urządzenia.  */
      mutex_unlock (&context->lock);
      context_destroy (f->private_data);
    }
  else
    {
      mutex_unlock (&context->lock);
    }
  KDEBUG ("%s: leaving\n", __func__);
  return 0;
}

static long
file_ioctl (struct file *f, unsigned int cmd, unsigned long arg)
{
  aes128_context *context;
  long retval;

  KDEBUG ("%s: entering\n", __func__);

  context = f->private_data;
  mutex_lock (&context->lock);

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
  else if (cmd == AESDEV_IOCTL_SET_OFB) context->mode = AES_OFB;
  else if (cmd == AESDEV_IOCTL_SET_CTR) context->mode = AES_CTR;
  else if (cmd == AESDEV_IOCTL_GET_STATE)
    {
      if (context->mode == AES_ECB_DECRYPT ||
          context->mode == AES_ECB_ENCRYPT ||
          context->mode == AES_UNDEF)
        {
          retval = -EINVAL;
          goto exit;
        }

      KDEBUG ("%s: not supported yet!\n", __FUNCTION__);
      retval = -EFAULT;
      goto exit;
    }

  if (copy_from_user (&context->key, (void *) arg, sizeof (aes128_block)))
    {
      KDEBUG ("%s: copy_from_user\n", __FUNCTION__);
      retval = -ENOMEM;
      goto exit;
    }

  if (cmd != AESDEV_IOCTL_SET_ECB_ENCRYPT && cmd != AESDEV_IOCTL_SET_ECB_DECRYPT)
    if (copy_from_user (&context->state, ((char *) arg) + sizeof (aes128_block),
                        sizeof (aes128_block)))
      {
        KDEBUG ("%s: copy_from_user\n", __FUNCTION__);
        retval = -EFAULT;
        goto exit;
      }

  KDEBUG ("%s: cmd=%d mode=%d, arg=%p\n", __func__, cmd, context->mode, (void *) arg);
  retval = 0;
exit:
  mutex_unlock (&context->lock);
  KDEBUG ("%s: leaving\n", __func__);
  return retval;
}
/*****************************************************************************/

/*** Device procedures *******************************************************/
static int
init_cmd_buffer (aes128_dev *aes_dev)
{
  void __iomem *bar0;
  dma_addr_t tmp_dma_addr;

  KDEBUG ("%s: entering\n", __func__);

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

  KDEBUG ("%s: write ptr set to %p\n", __func__, &aes_dev->d_cmd_buff_ptr);
  KDEBUG ("%s: leaving\n", __func__);

  return 0;
}

static int
aes_dev_destroy (aes128_dev *aes_dev)
{
  KDEBUG ("%s: entering\n", __func__);

  /* TODO */
  kfree (aes_dev);

  KDEBUG ("%s: leaving\n", __func__);
  return 0;
}
/*****************************************************************************/

/*** PCI handlers ************************************************************/
static int
pci_probe (struct pci_dev *pci_dev, const struct pci_device_id *id)
{
  aes128_dev *aes_dev;
  uint32_t intr;

  KDEBUG ("%s: entering\n", __func__);

  if (pci_enable_device (pci_dev))
    {
      printk (KERN_WARNING "pci_enable_device\n");
      return -EFAULT;
    }
  if (pci_request_regions (pci_dev, "aesdev"))
    {
      printk (KERN_WARNING "pci_request_regions\n");
      return -EFAULT;
    }
  aes_dev = kmalloc (sizeof (aes128_dev), GFP_KERNEL);
  memset (aes_dev, 0, sizeof (aes128_dev));
  spin_lock_init (&aes_dev->lock);
  aes_dev->bar0 = pci_iomap (pci_dev, 0, 0);
  aes_dev->sys_dev = device_create (dev_class, NULL, MKDEV (major, dev_count), NULL, "aesdev%d", dev_count);
  aes_dev->pci_dev = pci_dev;
  INIT_LIST_HEAD (&aes_dev->context_list_head);
  INIT_LIST_HEAD (&aes_dev->task_list_head);
  INIT_LIST_HEAD (&aes_dev->completed_list_head);
  init_waitqueue_head (&aes_dev->command_queue);
  pci_set_drvdata (pci_dev, aes_dev);

  pci_set_master (pci_dev);
  pci_set_dma_mask (pci_dev, DMA_BIT_MASK (32));
  pci_set_consistent_dma_mask (pci_dev, DMA_BIT_MASK (32));

  if (request_irq (pci_dev->irq, irq_handler, IRQF_SHARED, "aesdev", aes_dev))
    {
      KDEBUG ("request_irq\n");
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
  aes_devs[dev_count] = aes_dev;
  dev_count++;

  /* Włącz przerwania */
  iowrite32 (0xFF, aes_dev->bar0 + AESDEV_INTR_ENABLE);

  KDEBUG ("Registered new aesdev\n");
  KDEBUG ("%s: leaving\n", __func__);

  return 0;
}

static void
pci_remove (struct pci_dev *pci_dev)
{
  aes128_dev *aes_dev;

  KDEBUG ("%s: entering\n", __func__);

  aes_dev = pci_get_drvdata (pci_dev);
  free_irq (pci_dev->irq, aes_dev);
  pci_clear_master (pci_dev);
  pci_iounmap (pci_dev, aes_dev->bar0);
  pci_release_regions (pci_dev);
  pci_disable_device (pci_dev);

  aes_dev_destroy (aes_dev);

  dev_count--;

  printk (KERN_WARNING "Unregistered aesdev\n");
  KDEBUG ("%s: leaving\n", __func__);
}

static int
pci_resume (struct pci_dev *dev)
{
  KDEBUG ("%s: entering\n", __func__);
  KDEBUG ("%s: leaving\n", __func__);
  return 0;
}

static void
pci_shutdown (struct pci_dev *dev)
{
  KDEBUG ("%s: entering\n", __func__);
  KDEBUG ("%s: leaving\n", __func__);
}

static int
pci_suspend (struct pci_dev *dev, pm_message_t state)
{
  KDEBUG ("%s: entering\n", __func__);
  KDEBUG ("%s: leaving\n", __func__);
  return 0;
}

/*****************************************************************************/

static int
aesdrv_init (void)
{
  KDEBUG ("%s: hello\n", __func__);

  /* Rejestracja majora */
  major = register_chrdev (0, "aesdev", &aes_fops);

  /* Rejestracja urządzenia w kernelu */
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
  pci_unregister_driver (&aes_pci);
  device_destroy (dev_class, MKDEV (major, 0));
  class_destroy (dev_class);
  KDEBUG ("%s: bye\n", __func__);
}

module_init (aesdrv_init);
module_exit (aesdrv_cleanup);