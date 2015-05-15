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

MODULE_LICENSE ("GPL");

static int major;
static int dev_count;
static aes128_dev *aes_devs[256];
static DECLARE_WAIT_QUEUE_HEAD (big_queue);
static DEFINE_MUTEX (big_mutex);
static struct class *dev_class;

/*** Kernel structs **********************************************************/
static struct file_operations aes_fops = {
  .owner = THIS_MODULE,
  .read = aes_file_read,
  .write = aes_file_write,
  .open = aes_file_open,
  .release = aes_file_release,
  .unlocked_ioctl = aes_file_ioctl,
  .compat_ioctl = aes_file_ioctl
};

static struct pci_device_id aes_pci_ids[] = {
  {PCI_DEVICE (0x1af4, 0x10fc)},
  {0}
};

static struct pci_driver aes_pci = {
  name : "aesdev",
  id_table : aes_pci_ids,
  probe : aes_pci_probe,
  remove : aes_pci_remove,
  suspend : aes_pci_suspend,
  resume : aes_pci_resume,
  shutdown : aes_pci_shutdown
};
/*****************************************************************************/

/*** Helpers *****************************************************************/
static int
aes_load_key (aes128_context *context)
{
  void __iomem *bar0;
  uint8_t *key;
  int i;

  bar0 = context->aes_dev->bar0;
  key = context->key.state;

  for (i = 0; i<sizeof (aes128_block); ++i)
    iowrite8 (*key++, bar0 + AESDEV_AES_KEY (i));

  return 0;
}
/*****************************************************************************/

/*** Circular buffer *********************************************************/

/*
 * Number of free spots in circular buffer.
 */
int
cbuf_free (const struct circ_buf *buf)
{
  return CIRC_SPACE (buf->head, buf->tail, AESDRV_IOBUFF_SIZE);
}

/*
 * Number of items in circular buffer.
 */
int
cbuf_cont (const struct circ_buf *buf)
{
  return CIRC_CNT (buf->head, buf->tail, AESDRV_IOBUFF_SIZE);
}

/*
 * Copy len elements from __user *data to circular buffer.
 */
static int
cbuf_add_from_user (struct circ_buf *buf, const char __user *data, int len)
{
  int ret;

  if (cbuf_free (buf) < len)
    {
      printk (KERN_WARNING "%s: not enough space in buffer!\n", __FUNCTION__);
      return -1;
    }

  ret = copy_from_user (buf->buf, data, len);

  buf->head = (buf->head + len) % AESDRV_IOBUFF_SIZE;

  return ret;
}

/*
 * Remove len elements from circular buffer.
 */
static int
cbuf_take (struct circ_buf *buf, int len)
{
  if (cbuf_cont (buf) < len)
    {
      printk (KERN_WARNING "%s: not enough elements in buffer!\n", __FUNCTION__);
      return -1;
    }

  buf->tail -= len;
  if (buf->tail < 0)
    buf->tail += AESDRV_IOBUFF_SIZE;

  return 0;
}
/*****************************************************************************/

/*** Simple list *************************************************************/
static int
__append_task (aes128_task *task, aes128_task *new_task)
{
  while (task->next_task)
    task = task->next_task;
  task->next_task = new_task;
  return 0;
}

static int
register_task (aes128_context *context, aes128_task *task)
{
  if (context->task_list == NULL)
    {
      context->task_list = task;
      return 0;
    }
  else
    {
      return __append_task (context->task_list, task);
    }
}

static aes128_task *
pop_task (aes128_context *context)
{
  aes128_task *task;

  task = context->task_list;
  if (task == NULL)
    {
      KDEBUG ("%s: poping task from empty task list!\n", __FUNCTION__);
      return NULL;
    }

  context->task_list = task->next_task;

  return task;
}
/*****************************************************************************/

/*** AES context *************************************************************/
static void
init_context (aes128_context *context)
{
  memset (context, 0, sizeof (aes128_context));
  context->mode = AES_UNDEF;
  context->read_buffer.buf = kmalloc (AESDRV_IOBUFF_SIZE, GFP_KERNEL);
  context->write_buffer.buf = kmalloc (AESDRV_IOBUFF_SIZE, GFP_KERNEL);
  mutex_init (&context->mutex);
}

static void
destroy_context (aes128_context *context)
{
  kfree (context->read_buffer.buf);
  kfree (context->write_buffer.buf);
  mutex_destroy (&context->mutex);
}
/*****************************************************************************/

/*** Irq handlers ************************************************************/
__attribute__ ((used))
static irqreturn_t
irq_handler (int irq, void *ptr)
{
  aes128_dev *aes_dev;
  uint32_t r0[4];
  uint32_t r2[4];
  uint8_t intr;

  KDEBUG ("%s: working...\n", __FUNCTION__);

  aes_dev = ptr;
  READ_4REG (r0, aes_dev->bar0);
  READ_4REG (r2, aes_dev->bar0 + 0x40);
  intr = r0[2] & 0xFF;
  if (!intr)
    {
      KDEBUG ("%s: not my interrupt, IRQ_NONE!\n", __FUNCTION__);
      return IRQ_NONE;
    }

  KDEBUG ("%s: intr=0x%x, handling...\n", __FUNCTION__, intr & 0xFF);
  KDEBUG ("%s: %u blocks waiting for encryption\n", __FUNCTION__, (r2[3] >> 12) & 0xFFFFFF);

  /* TODO: Wake up procesess waiting on read. */

  /* Set all interrupts */
  iowrite32 (r0[2], aes_dev->bar0 + 0x08);

  return IRQ_HANDLED;
}
/*****************************************************************************/

/*** File handlers ***********************************************************/
static ssize_t
aes_file_read (struct file *f, char __user *buf, size_t len, loff_t *off)
{
  aes128_context *context;
  aes128_task *task;
  uint32_t r2[4];

  KDEBUG ("%s: working...\n", __FUNCTION__);

  context = f->private_data;
  if (context->mode == AES_UNDEF)
    {
      KDEBUG ("%s: no mode set\n", __FUNCTION__);
      return -EINVAL;
    }

  READ_4REG (r2, context->aes_dev->bar0);
  KDEBUG ("%s: %u blocks waiting for encryption\n", __FUNCTION__, r2[3] >> 12);

  task = pop_task (context);

  if (copy_to_user (buf, task->k_output_data_ptr, task->block_count * 16))
    {
      KDEBUG ("%s: copy_to_user\n", __FUNCTION__);
      return -EFAULT;
    }
  
  /* Save state to context */
  memcpy (context->state.state, task->k_state_ptr, sizeof(aes128_block));
  
  /* Free DMA buffers */
  dma_free_coherent(&context->aes_dev->pci_dev->dev,
                    sizeof(aes128_block) * task->block_count,
                    task->k_input_data_ptr,
                    task->d_input_data_ptr);
  dma_free_coherent(&context->aes_dev->pci_dev->dev,
                    sizeof(aes128_block) * task->block_count,
                    task->k_output_data_ptr,
                    task->d_output_data_ptr);
  dma_free_coherent(&context->aes_dev->pci_dev->dev,
                    sizeof(aes128_block),
                    task->k_state_ptr,
                    task->d_state_ptr);

  return task->block_count * 16;
}

static ssize_t
aes_file_write (struct file *f, const char __user *buf, size_t len, loff_t *off)
{
  aes128_context *context;

  KDEBUG ("%s: received %d bytes\n", __FUNCTION__, len);

  context = f->private_data;

  KDEBUG ("%s: had before %d in buf\n", __FUNCTION__, cbuf_cont (&context->read_buffer));

  cbuf_add_from_user (&context->read_buffer, buf, len);

  KDEBUG ("%s: have now %d in buf\n", __FUNCTION__, cbuf_cont (&context->read_buffer));

  if (cbuf_cont (&context->read_buffer) >= 16)
    {
      aes128_task *aes_task;
      uint32_t r0[4];
      uint32_t r2[4];

      KDEBUG ("%s: enough data, creating new task!\n", __FUNCTION__);

      aes_load_key (context);

      aes_task = kmalloc (sizeof (aes128_task), GFP_KERNEL);
      memset (aes_task, 0, sizeof (aes128_task));

      aes_task->block_count = cbuf_cont (&context->read_buffer) / 16;
      aes_task->context = context;
      KDEBUG ("%s: encrypting %d blocks\n", __FUNCTION__, aes_task->block_count);

      aes_task->k_input_data_ptr =
              dma_alloc_coherent (&context->aes_dev->pci_dev->dev,
                                  aes_task->block_count * sizeof (aes128_block),
                                  &aes_task->d_input_data_ptr, GFP_KERNEL);
      aes_task->k_output_data_ptr =
              dma_alloc_coherent (&context->aes_dev->pci_dev->dev,
                                  aes_task->block_count * sizeof (aes128_block),
                                  &aes_task->d_output_data_ptr, GFP_KERNEL);      
      aes_task->k_state_ptr =
              dma_alloc_coherent (&context->aes_dev->pci_dev->dev,
                                  aes_task->block_count * sizeof (aes128_block),
                                  &aes_task->d_state_ptr, GFP_KERNEL);

      /* Copy data for DMA */
      memcpy (aes_task->k_input_data_ptr,
              context->read_buffer.buf,
              aes_task->block_count * sizeof (aes128_block));
      
      /* Remove data from queue */
      cbuf_take (&context->read_buffer, aes_task->block_count * sizeof (aes128_block));

      /* Prepare transfer block */
      r2[0] = aes_task->d_input_data_ptr;
      r2[1] = aes_task->d_output_data_ptr;
      r2[2] = aes_task->d_state_ptr;
      
      r2[3] = 0x0000;
      /* Set mode */
      r2[3] |= context->mode & 0x03;
      /* Write state */
      r2[3] |= 0x01 << 3;
      /* Set interrupts */
      r2[3] |= 0x01 << 4;
      /* Set block count */
      r2[3] |= ((aes_task->block_count) & 0xFFFFFF) << 12;

      /* Write transfer block */
      KDEBUG ("%s: block_count=%d\n", __FUNCTION__, aes_task->block_count);
      WRITE_4REG (r2, context->aes_dev->bar0 + 0x40);
      KDEBUG ("%s: %u blocks waiting for encryption\n", __FUNCTION__, r2[3] >> 12);

      /* Enable transfer block */
      r0[0] = ioread32 (context->aes_dev->bar0);
      r0[1] = ioread32 (context->aes_dev->bar0 + 0x04);
      r0[2] = ioread32 (context->aes_dev->bar0 + 0x08);
      r0[3] = ioread32 (context->aes_dev->bar0 + 0x0c);
      /* Enable transfer block */
      r0[0] |= 0x01;
      /* Enable all interrupts */
      r0[3] = 0xFF;
      iowrite32 (r0[0], context->aes_dev->bar0);
      iowrite32 (r0[3], context->aes_dev->bar0 + 0x0c);

      KDEBUG ("%s: poszlo\n", __FUNCTION__);

      register_task (context, aes_task);
    }

  return len;
}

static int
aes_file_open (struct inode *i, struct file *f)
{
  aes128_context *context = kmalloc (sizeof (aes128_context), GFP_KERNEL);
  init_context (context);
  printk (KERN_WARNING "aes_file_open: have %d in buf\n", cbuf_cont (&context->read_buffer));
  context->aes_dev = aes_devs[iminor (i)];
  f->private_data = context;
  printk (KERN_WARNING "Assigned opened file to device %p\n", context->aes_dev);
  return 0;
}

static int
aes_file_release (struct inode *i, struct file *f)
{
  destroy_context (f->private_data);
  kfree (f->private_data);
  return 0;
}

static long
aes_file_ioctl (struct file *f, unsigned int cmd, unsigned long arg)
{
  aes128_context *context;

  context = f->private_data;

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
        return -EINVAL;

      KDEBUG ("%s: not supported yet!\n", __FUNCTION__);
      return -EFAULT;
    }

  if (copy_from_user (&context->key, (void *) arg, sizeof (aes128_block)))
    {
      KDEBUG ("%s: copy_from_user\n", __FUNCTION__);
      return -EFAULT;
    }

  if (cmd != AESDEV_IOCTL_SET_ECB_ENCRYPT && cmd != AESDEV_IOCTL_SET_ECB_DECRYPT)
    if (copy_from_user (&context->state, ((char *) arg) + sizeof (aes128_block),
                        sizeof (aes128_block)))
      {
        KDEBUG ("%s: copy_from_user\n", __FUNCTION__);
        return -EFAULT;
      }

  return 0;
}
/*****************************************************************************/

/*** Device procedures *******************************************************/
int
init_cmd_buffer (aes128_dev *aes_dev)
{
  void __iomem *bar0;
  char *k_buffer_ptr;
  dma_addr_t d_buffer_ptr;

  bar0 = aes_dev->bar0;

  /* TODO: 16-byte alignment */
  k_buffer_ptr = dma_alloc_coherent (&aes_dev->pci_dev->dev, AESDRV_CMDBUFF_SIZE,
                                     &d_buffer_ptr, GFP_KERNEL);
  aes_dev->cmd_buff_ptr = k_buffer_ptr;
  aes_dev->d_cmd_buff_ptr = d_buffer_ptr;

  iowrite32 (d_buffer_ptr, bar0 + AESDEV_CMD_BEGIN_PTR);
  /* TODO: Ostatni czy zaostatni? */
  iowrite32 (d_buffer_ptr + AESDRV_CMDBUFF_SIZE, bar0 + AESDEV_CMD_END_PTR);
  iowrite32 (d_buffer_ptr, bar0 + AESDEV_CMD_READ_PTR);
  iowrite32 (d_buffer_ptr, bar0 + AESDEV_CMD_WRITE_PTR);

  return 0;
}

int
schedule_operation (aes128_context *context, dma_addr_t data, dma_addr_t result, dma_addr_t key)
{
  aes128_dev *aes_dev;
  void __iomem *bar0;
  dma_addr_t *write_ptr;
  uint32_t xfer_task;
  uint8_t intr;
  uint32_t count; /* low 3 bytes */
  dma_addr_t d_xfer_ptr;
  uint32_t *k_xfer_ptr;

  aes_dev = context->aes_dev;
  bar0 = aes_dev->bar0;
  write_ptr = (dma_addr_t *) ioread32 (bar0 + AESDEV_CMD_WRITE_PTR);

  intr = 0x01;
  count = 1;
  xfer_task = AESDEV_TASK (count, intr, 0, AESDEV_MODE_ECB_ENCRYPT);

  k_xfer_ptr = dma_alloc_coherent (&aes_dev->pci_dev->dev, sizeof (xfer_task), &d_xfer_ptr, GFP_KERNEL);
  *k_xfer_ptr = xfer_task;

  write_ptr[0] = data;
  write_ptr[1] = result;
  write_ptr[2] = key;
  /* TODO insert IV here */
  write_ptr[3] = d_xfer_ptr;
  write_ptr += 4;

  return 0;
}

int
init_aes_device (aes128_dev *aes_dev)
{
  void __iomem *bar0;

  memset (aes_dev, 0, sizeof (aes128_dev));

  mutex_init (&aes_dev->mutex);

  bar0 = aes_dev->bar0;
  SET_FLAG (bar0 + AESDEV_ENABLE,
            AESDEV_ENABLE_XFER_DATA | AESDEV_ENABLE_FETCH_CMD);
  SET_FLAG (bar0 + AESDEV_INTR_ENABLE, 0xFF);

  return init_cmd_buffer (aes_dev);
}

int
destroy_aes_device (aes128_dev *aes_dev)
{
  mutex_destroy (&aes_dev->mutex);
  return 0;
}
/*****************************************************************************/

/*** PCI handlers ************************************************************/
int
aes_pci_probe (struct pci_dev *pci_dev, const struct pci_device_id *id)
{
  aes128_dev *aes_dev;

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
  aes_dev->bar0 = pci_iomap (pci_dev, 0, 0);
  aes_dev->sys_dev = device_create (dev_class, NULL, MKDEV (major, dev_count), NULL, "aesdev%d", dev_count);
  aes_dev->pci_dev = pci_dev;
  pci_set_drvdata (pci_dev, aes_dev);

  SET_FLAG (aes_dev->bar0 + AESDEV_ENABLE,
            AESDEV_ENABLE_XFER_DATA | AESDEV_ENABLE_FETCH_CMD);
  SET_FLAG (aes_dev->bar0 + AESDEV_INTR_ENABLE, 0xFF);

  pci_set_master (pci_dev);
  pci_set_dma_mask (pci_dev, DMA_BIT_MASK (32));
  pci_set_consistent_dma_mask (pci_dev, DMA_BIT_MASK (32));

  if (request_irq (pci_dev->irq, irq_handler, IRQF_SHARED, "aesdev", aes_dev))
    {
      KDEBUG ("request_irq\n");
      return -EFAULT;
    }

  aes_devs[dev_count] = aes_dev;
  dev_count++;

  KDEBUG ("Registered new aesdev\n");

  return 0;
}

void
aes_pci_remove (struct pci_dev *pci_dev)
{
  aes128_dev *aes_dev;

  aes_dev = pci_get_drvdata (pci_dev);
  free_irq (pci_dev->irq, aes_dev);
  pci_clear_master (pci_dev);
  pci_iounmap (pci_dev, aes_dev->bar0);
  pci_release_regions (pci_dev);
  pci_disable_device (pci_dev);

  kfree (aes_dev);

  dev_count--;

  printk (KERN_WARNING "Unregistered aesdev\n");
}

int
aes_pci_resume (struct pci_dev *dev)
{
  return 0;
}

void
aes_pci_shutdown (struct pci_dev *dev) { }

int
aes_pci_suspend (struct pci_dev *dev, pm_message_t state)
{
  return 0;
}

/*****************************************************************************/

static int
aesdev_init (void)
{
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
aesdev_cleanup (void)
{
  pci_unregister_driver (&aes_pci);
  device_destroy (dev_class, MKDEV (major, 0));
  class_destroy (dev_class);
}

module_init (aesdev_init);
module_exit (aesdev_cleanup);