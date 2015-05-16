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
  aes_dma_addr_t d_begin_ptr, d_write_ptr;
  KDEBUG ("%s: entering\n", __func__);

  bar0 = task->context->aes_dev->bar0;

  /* Enqueue commands */
  d_begin_ptr = ioread32 (bar0 + AESDEV_CMD_BEGIN_PTR);
  d_write_ptr = ioread32 (bar0 + AESDEV_CMD_WRITE_PTR);

  cmd = (void *) (((char *) task->context->aes_dev->k_cmd_buff_ptr) + (d_write_ptr - d_begin_ptr));
  KDEBUG ("%s: current write ptr = %p\n", __func__, cmd);
  cmd->in_ptr = task->d_input_data_ptr;
  cmd->out_ptr = task->d_output_data_ptr;
  cmd->ks_ptr = task->d_ks_ptr;
  cmd->xfer_val =
          AESDEV_TASK (task->block_count, 0xFF, 0x01, task->mode);

  KDEBUG ("%s: in_ptr=%p out_ptr=%p ks_ptr=%p\n", __func__, (void *) cmd->in_ptr,
          (void*) cmd->out_ptr, (void*) cmd->ks_ptr);
  KDEBUG ("%s: count=%d intr=%d write_state=%d mode=%d\n", __func__,
          AESDEV_TASK_COUNT (cmd->xfer_val), AESDEV_TASK_INTR (cmd->xfer_val),
          AESDEV_TASK_SAVE (cmd->xfer_val), AESDEV_TASK_MODE (cmd->xfer_val));

  KDEBUG ("%s: d_read_ptr=%p, d_write_ptr=%p\n", __func__, (void*) ioread32 (bar0 + AESDEV_CMD_READ_PTR), (void*) ioread32 (bar0 + AESDEV_CMD_WRITE_PTR));
  KDEBUG ("%s: advancing write ptr\n", __func__);

  advance_cmd_ptr (task);

  KDEBUG ("%s: d_read_ptr=%p, d_write_ptr=%p\n", __func__, (void*) ioread32 (bar0 + AESDEV_CMD_READ_PTR), (void*) ioread32 (bar0 + AESDEV_CMD_WRITE_PTR));

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
  AESDEV_STOP (context->aes_dev);
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
      task_register (context, aes_task);

      KDEBUG ("%s: enqueing task\n", __func__);
      task_enqueue (aes_task);

      context->cmds_in_progress++;

      KDEBUG ("%s: poszlo\n", __FUNCTION__);
    }
  AESDEV_START (context->aes_dev);
  KDEBUG ("%s: leaving\n", __func__);
  return 0;
}

/* This function might sleep! */
static int
advance_cmd_ptr (aes128_task *task)
{
  uint32_t d_begin_ptr, d_end_ptr, d_read_ptr, d_write_ptr;
  void __iomem *bar0;
  KDEBUG ("%s: entering\n", __func__);

  bar0 = task->context->aes_dev->bar0;

  d_begin_ptr = ioread32 (bar0 + AESDEV_CMD_BEGIN_PTR);
  d_end_ptr = ioread32 (bar0 + AESDEV_CMD_END_PTR);
  d_read_ptr = ioread32 (bar0 + AESDEV_CMD_READ_PTR);
  d_write_ptr = ioread32 (bar0 + AESDEV_CMD_WRITE_PTR);

  KDEBUG ("%s: d_write_ptr was %p\n", __func__, (void *) d_write_ptr);

  task->d_write_ptr = d_write_ptr;
  task->d_read_ptr = d_read_ptr;

  d_write_ptr += 16;
  if (d_write_ptr == d_end_ptr)
    {
      KDEBUG ("%s: wrapping around d_write_ptr\n", __func__);
      d_write_ptr = d_begin_ptr;
    }

  KDEBUG ("%s: d_write_ptr will be %p\n", __func__, (void *) d_write_ptr);

  iowrite32 (d_write_ptr, bar0 + AESDEV_CMD_WRITE_PTR);
  KDEBUG ("%s: leaving\n", __func__);

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
__append_task (aes128_task *task, aes128_task *new_task)
{
  KDEBUG ("%s: entering\n", __func__);
  while (task->next_task)
    task = task->next_task;
  task->next_task = new_task;
  KDEBUG ("%s: leaving\n", __func__);
  return 0;
}

static int
__append_context (aes128_context *context, aes128_context *new_context)
{
  KDEBUG ("%s: entering\n", __func__);
  while (context->next_context)
    context = context->next_context;
  context->next_context = new_context;
  KDEBUG ("%s: appended %p to %p\n", __func__, new_context, context);
  KDEBUG ("%s: leaving\n", __func__);
  return 0;
}

static int
task_register (aes128_context *context, aes128_task *task)
{
  KDEBUG ("%s: entering\n", __func__);
  if (context->task_list == NULL)
    {
      context->task_list = task;
      return 0;
    }
  else
    {
      return __append_task (context->task_list, task);
    }
  KDEBUG ("%s: leaving\n", __func__);
}

static int
context_unregister (aes128_dev *aes_dev, aes128_context *context)
{
  aes128_context *temp, *prev;
  KDEBUG ("%s: entering\n", __func__);

  temp = aes_dev->context_list;
  prev = NULL;

  while (temp != context)
    {
      prev = temp;
      temp = temp->next_context;
    }
  if (prev)
    prev->next_context = temp->next_context;
  else
    aes_dev->context_list = temp->next_context;

  KDEBUG ("%s: leaving\n", __func__);
  return 0;
}

static int
context_register (aes128_dev *aes_dev, aes128_context *context)
{
  KDEBUG ("%s: entering\n", __func__);
  KDEBUG ("%s: registering context %p in device %p\n", __func__,
          (void *) context, (void *) aes_dev);
  if (aes_dev->context_list == NULL)
    {
      aes_dev->context_list = context;
      context->next_context = NULL;
      return 0;
    }
  KDEBUG ("%s: leaving\n", __func__);
  return __append_context (aes_dev->context_list, context);
}

static int
handle_task_completed (aes128_task *task)
{
  aes128_context *context;
  KDEBUG ("%s: entering\n", __func__);

  context = task->context;

  KDEBUG ("%s: context=%p task=%p\n", __func__, context, task);

  cbuf_add_from_kernel (&task->context->read_buffer, (char *) task->k_output_data_ptr, sizeof (aes128_block) * task->block_count);
  if (HAS_STATE (task->mode))
    {
      memcpy (task->context->state.state, &task->k_ks_ptr[1], sizeof (aes128_block));
    }

  context->cmds_in_progress--;

  if (cbuf_cont (&context->read_buffer) > 0)
    wake_up (&context->read_queue);

  KDEBUG ("%s: leaving\n", __func__);
  return 0;
}
/*****************************************************************************/

/*** AES context *************************************************************/
static void
context_init (aes128_context *context)
{
  KDEBUG ("%s: entering\n", __func__);
  memset (context, 0, sizeof (aes128_context));
  context->mode = AES_UNDEF;
  context->read_buffer.buf = kmalloc (AESDRV_IOBUFF_SIZE, GFP_KERNEL);
  context->write_buffer.buf = kmalloc (AESDRV_IOBUFF_SIZE, GFP_KERNEL);
  init_waitqueue_head (&context->read_queue);
  init_waitqueue_head (&context->write_queue);
  spin_lock_init (&context->context_lock);
  KDEBUG ("%s: leaving\n", __func__);
}

static void
context_destroy (aes128_context *context)
{
  return;
  KDEBUG ("%s: entering\n", __func__);
  kfree (context->read_buffer.buf);
  kfree (context->write_buffer.buf);
  KDEBUG ("%s: leaving\n", __func__);
}
/*****************************************************************************/

/*** Irq handlers ************************************************************/
static irqreturn_t
irq_handler (int irq, void *ptr)
{
  aes128_dev *aes_dev;
  aes128_context *context;
  aes_dma_addr_t d_read_ptr, d_write_ptr;
  uint8_t intr;
  KDEBUG ("%s: entering\n", __func__);

  KDEBUG ("%s: working...\n", __FUNCTION__);

  aes_dev = ptr;
  
  local_irq_disable();

  AESDEV_STOP (aes_dev);

  intr = ioread32 (aes_dev->bar0 + AESDEV_INTR) & 0xFF;
  if (!intr)
    {
      KDEBUG ("%s: not my interrupt, IRQ_NONE!\n", __FUNCTION__);
      local_irq_enable();
      return IRQ_NONE;
    }

  d_read_ptr = ioread32 (aes_dev->bar0 + AESDEV_CMD_READ_PTR);
  d_write_ptr = ioread32 (aes_dev->bar0 + AESDEV_CMD_WRITE_PTR);

  KDEBUG ("%s: intr=0x%x, handling...\n", __FUNCTION__, intr & 0xFF);

  context = aes_dev->context_list;
  while (context)
    {
      aes128_task *task;
      aes128_task *prev_task;

      spin_lock_irqsave (&context->context_lock, context->intr_flags);

      KDEBUG ("%s: checking context %p\n", __func__, (void *) context);

      task = context->task_list;
      prev_task = NULL;

      while (task)
        {
          KDEBUG ("%s: checking task %p\n", __func__, (void *) task->d_input_data_ptr);
          /* Has this task been already completed? */
          if (d_read_ptr > task->d_write_ptr || d_read_ptr < task->d_read_ptr)
            {
              KDEBUG ("%s: command completed %p\n", __func__, task);
              handle_task_completed (task);

              KDEBUG ("%s: removing task from list\n", __func__);
              /* Remove this task from list */
              if (prev_task)
                prev_task->next_task = task->next_task;
              else
                context->task_list = NULL;
              KDEBUG ("%s: removed\n", __func__);
            }
          prev_task = task;
          task = task->next_task;
        }

      spin_unlock_irqrestore (&context->context_lock, context->intr_flags);

      if (context->file_open == 0 && context->cmds_in_progress == 0)
        {
          aes128_context *next;
          next = context->next_context;
          context_unregister (context->aes_dev, context);
          context_destroy (context);
          kfree (context);
          context = next;
        }
      else
        context = context->next_context;
    }

  /* TODO: Wake up procesess waiting on read. */

  KDEBUG ("%s: resetting interrupts\n", __func__);
  /* Reset all interrupts */
  iowrite32 (intr, aes_dev->bar0 + AESDEV_INTR);

  KDEBUG ("%s: resuming device\n", __func__);

  AESDEV_START (aes_dev);

  KDEBUG ("%s: irq_handler done\n", __func__);
  KDEBUG ("%s: leaving\n", __func__);
  
  local_irq_enable();

  return IRQ_HANDLED;
}
/*****************************************************************************/

/*** File handlers ***********************************************************/
static ssize_t
file_read (struct file *f, char __user *buf, size_t len, loff_t *off)
{
  aes128_context *context;
  int to_copy, to_copy1, to_copy2;
  KDEBUG ("%s: entering\n", __func__);

  context = f->private_data;

  spin_lock_irqsave (&context->context_lock, context->intr_flags);

  if (context->mode == AES_UNDEF)
    {
      KDEBUG ("%s: no mode set\n", __FUNCTION__);
      spin_unlock_irqrestore (&context->context_lock, context->intr_flags);
      return -EINVAL;
    }

  KDEBUG ("%s: %d bytes in read buffer\n", __func__, cbuf_cont (&context->read_buffer));

  while (cbuf_cont (&context->read_buffer) == 0)
    {
      KDEBUG ("%s: going to sleep :(\n", __func__);
      spin_unlock_irqrestore (&context->context_lock, context->intr_flags);
      wait_event (context->read_queue, cbuf_cont (&context->read_buffer) != 0);
      spin_lock_irqsave (&context->context_lock, context->intr_flags);
    }

  to_copy = min ((int) len, cbuf_cont (&context->read_buffer));
  to_copy1 = min (to_copy, CIRC_CNT_TO_END (context->read_buffer.head,
                                            context->read_buffer.tail,
                                            AESDRV_IOBUFF_SIZE));
  to_copy2 = to_copy - to_copy1;
  if (copy_to_user (buf, context->read_buffer.buf + context->read_buffer.tail, to_copy1))
    {
      KDEBUG ("%s: copy_to_user\n", __func__);
      spin_unlock_irqrestore (&context->context_lock, context->intr_flags);
      return -EFAULT;
    }
  if (copy_to_user (buf + to_copy1, context->read_buffer.buf, to_copy2))
    {
      KDEBUG ("%s: copy_to_user\n", __func__);
      spin_unlock_irqrestore (&context->context_lock, context->intr_flags);
      return -EFAULT;
    }
  context->read_buffer.tail = (context->read_buffer.tail + to_copy) % AESDRV_IOBUFF_SIZE;

  KDEBUG ("%s: %d bytes were read, %d left in buff\n", __func__, to_copy, cbuf_cont (&context->read_buffer));
  KDEBUG ("%s: leaving\n", __func__);

  spin_unlock_irqrestore (&context->context_lock, context->intr_flags);
  return to_copy;
}

static ssize_t
file_write (struct file *f, const char __user *buf, size_t len, loff_t *off)
{
  aes128_context *context;
  KDEBUG ("%s: entering\n", __func__);

  context = f->private_data;
  spin_lock_irqsave (&context->context_lock, context->intr_flags);
  if (context->mode == AES_UNDEF)
    {
      KDEBUG ("%s: no mode set\n", __FUNCTION__);
      spin_unlock_irqrestore (&context->context_lock, context->intr_flags);
      return -EINVAL;
    }

  KDEBUG ("%s: received %d bytes\n", __FUNCTION__, len);
  KDEBUG ("%s: had before %d in buf\n", __FUNCTION__, cbuf_cont (&context->write_buffer));
  cbuf_add_from_user (&context->write_buffer, buf, len);
  KDEBUG ("%s: have now %d in buf\n", __FUNCTION__, cbuf_cont (&context->write_buffer));
  KDEBUG ("%s: my context is %p\n", __func__, context);
  task_create (context);

  KDEBUG ("%s: leaving\n", __func__);
  spin_unlock_irqrestore (&context->context_lock, context->intr_flags);
  return len;
}

static int
file_open (struct inode *i, struct file *f)
{
  aes128_context *context;
  KDEBUG ("%s: entering\n", __func__);

  context = kmalloc (sizeof (aes128_context), GFP_KERNEL);
  context_init (context);
  KDEBUG ("%s: aes_file_open: have %d in buf\n", __func__, cbuf_cont (&context->read_buffer));
  context->aes_dev = aes_devs[iminor (i)];
  context->file_open = 1;
  f->private_data = context;
  context_register (context->aes_dev, context);
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
  spin_lock_irqsave (&context->context_lock, context->intr_flags);
  context->file_open = 0;

  KDEBUG ("%s: context %p has %d cmds in progress\n", __func__,
          context, context->cmds_in_progress);

  if (context->cmds_in_progress == 0)
    {
      context_unregister (context->aes_dev, context);
      spin_unlock_irqrestore (&context->context_lock, context->intr_flags);
      context_destroy (f->private_data);
      kfree (f->private_data);
    }
  KDEBUG ("%s: leaving\n", __func__);
  return 0;
}

static long
file_ioctl (struct file *f, unsigned int cmd, unsigned long arg)
{
  aes128_context *context;

  KDEBUG ("%s: entering\n", __func__);

  context = f->private_data;
  spin_lock_irqsave (&context->context_lock, context->intr_flags);

  if (context->mode == AES_UNDEF && cmd == AESDEV_IOCTL_GET_STATE)
    return -EINVAL;

  if (cmd == AESDEV_IOCTL_SET_ECB_ENCRYPT) context->mode = AES_ECB_ENCRYPT;
  else if (cmd == AESDEV_IOCTL_SET_ECB_DECRYPT) context->mode = AES_ECB_DECRYPT;
  else if (cmd == AESDEV_IOCTL_SET_CBC_ENCRYPT) context->mode = AES_CBC_ENCRYPT;
  else if (cmd == AESDEV_IOCTL_SET_CBC_DECRYPT) context->mode = AES_CBC_DECRYPT;
  else if (cmd == AESDEV_IOCTL_SET_CFB_ENCRYPT) context->mode = AES_CBC_DECRYPT;
  else if (cmd == AESDEV_IOCTL_SET_CFB_DECRYPT) context->mode = AES_CBC_DECRYPT;
  else if (cmd == AESDEV_IOCTL_SET_OFB) context->mode = AES_OFB;
  else if (cmd == AESDEV_IOCTL_SET_CTR) context->mode = AES_CTR;
  else if (cmd == AESDEV_IOCTL_GET_STATE)
    {
      if (context->mode == AES_ECB_DECRYPT ||
          context->mode == AES_ECB_ENCRYPT ||
          context->mode == AES_UNDEF)
        {
          spin_unlock_irqrestore (&context->context_lock, context->intr_flags);
          return -EINVAL;
        }

      KDEBUG ("%s: not supported yet!\n", __FUNCTION__);
      spin_unlock_irqrestore (&context->context_lock, context->intr_flags);
      return -EFAULT;
    }

  if (copy_from_user (&context->key, (void *) arg, sizeof (aes128_block)))
    {
      KDEBUG ("%s: copy_from_user\n", __FUNCTION__);
      spin_unlock_irqrestore (&context->context_lock, context->intr_flags);
      return -EFAULT;
    }

  if (cmd != AESDEV_IOCTL_SET_ECB_ENCRYPT && cmd != AESDEV_IOCTL_SET_ECB_DECRYPT)
    if (copy_from_user (&context->state, ((char *) arg) + sizeof (aes128_block),
                        sizeof (aes128_block)))
      {
        KDEBUG ("%s: copy_from_user\n", __FUNCTION__);
        spin_unlock_irqrestore (&context->context_lock, context->intr_flags);
        return -EFAULT;
      }

  KDEBUG ("%s: cmd=%d mode=%d, arg=%p\n", __func__, cmd, context->mode, (void *) arg);

  KDEBUG ("%s: leaving\n", __func__);
  spin_unlock_irqrestore (&context->context_lock, context->intr_flags);
  return 0;
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
  iowrite32 ((uint32_t) (aes_dev->d_cmd_buff_ptr + AESDRV_CMDBUFF_SIZE), bar0 + AESDEV_CMD_END_PTR);
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
  aes_dev->bar0 = pci_iomap (pci_dev, 0, 0);
  aes_dev->sys_dev = device_create (dev_class, NULL, MKDEV (major, dev_count), NULL, "aesdev%d", dev_count);
  aes_dev->pci_dev = pci_dev;
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

  /* Włącz przerwania */
  iowrite32 (0xFF, aes_dev->bar0 + AESDEV_INTR_ENABLE);

  /* Na wszelki wypadek */
  AESDEV_STOP (aes_dev);

  /* Zarejestruj urządzenie w sterowniku */
  aes_devs[dev_count] = aes_dev;
  dev_count++;

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
  KDEBUG ("%s: entering\n", __func__);

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

  KDEBUG ("%s: leaving\n", __func__);

  return 0;
}

static void
aesdrv_cleanup (void)
{
  pci_unregister_driver (&aes_pci);
  device_destroy (dev_class, MKDEV (major, 0));
  class_destroy (dev_class);
}

module_init (aesdrv_init);
module_exit (aesdrv_cleanup);