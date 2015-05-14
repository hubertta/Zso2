#include "aesdev.h"

#include <linux/module.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/kernel.h>
#include <asm/uaccess.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");

static int major;
static int dev_count;
static aes128_dev *aes_devs[256];

static DECLARE_WAIT_QUEUE_HEAD(big_queue);
static DEFINE_MUTEX(big_mutex);

struct class *dev_class;

static struct file_operations aes_fops =
{
  owner: THIS_MODULE,
  read: aes_file_read,
  write: aes_file_write,
  open: aes_file_open,
  release: aes_file_release,
  unlocked_ioctl: aes_file_ioctl,
  compat_ioctl: aes_file_ioctl
};

static struct pci_device_id aes_pci_ids[] =
{
  { PCI_DEVICE(0x1af4, 0x10fc) },
  { 0 }
};

static struct pci_driver aes_pci =
{
  name: "aesdev",
  id_table: aes_pci_ids,
  probe: aes_pci_probe,
  remove: aes_pci_remove,
  suspend: aes_pci_suspend,
  resume: aes_pci_resume,
  shutdown: aes_pci_shutdown
};

static void init_context(aes128_context *context)
{
  memset(context, 0, sizeof(aes128_context));
  context->mode = AES_UNDEF;
  context->read_buffer.buf = kmalloc(AESDRV_IOBUFF_SIZE, GFP_KERNEL);
  context->write_buffer.buf = kmalloc(AESDRV_IOBUFF_SIZE, GFP_KERNEL);
  mutex_init(&context->mutex);
}

static void destroy_context(aes128_context *context)
{
  kfree(context->read_buffer.buf);
  kfree(context->write_buffer.buf);
  mutex_destroy(&context->mutex);
}

/*** File handlers ***********************************************************/
static ssize_t aes_file_read(struct file *f, char __user *buf, size_t len, loff_t *off)
{
  aes128_context *context;
  struct circ_buf *read_buff;
  size_t in_buffer;

  context = f->private_data;
  read_buff = &context->read_buffer;

  while (CIRC_CNT(read_buff->head, read_buff->tail, AESDRV_IOBUFF_SIZE) == 0)
  {
    wait_event(big_queue, CIRC_CNT(read_buff->head, read_buff->tail, AESDRV_IOBUFF_SIZE) == 0);
  }

  in_buffer = CIRC_CNT(read_buff->head, read_buff->tail, AESDRV_IOBUFF_SIZE);

  if (in_buffer)
  {
    size_t to_read;
    size_t to_read_1;       /* Bytes to read until end of buffer */
    size_t to_read_2;       /* Bytes to read from beginning of buffer */

    to_read = min(len, in_buffer);
    to_read_1 = min((int) to_read, CIRC_SPACE_TO_END(read_buff->head, read_buff->tail, AESDRV_IOBUFF_SIZE));
    to_read_2 = to_read - to_read_1;

    if (copy_to_user(buf, read_buff->buf + read_buff->head, to_read_1))
    {
      printk(KERN_WARNING "copy_to_user\n");
      return -ENOMEM;
    }
    if (to_read_2)
      if (copy_to_user(buf + to_read_1, read_buff->buf, to_read_2))
      {
        printk(KERN_WARNING "copy_to_user\n");
        return -ENOMEM;
      }

    read_buff->head += to_read_1;
    if (to_read >= to_read_2)
      read_buff->head = to_read_2;

    return to_read;
  }

  return 0;
}

static ssize_t aes_file_write(struct file *f, const char __user *buf, size_t len, loff_t *off)
{
  aes128_context *context;
  struct circ_buf *write_buff;
  size_t in_buffer;
  size_t to_write;
  size_t to_write_1;
  size_t to_write_2;

  context = f->private_data;
  write_buff = &context->write_buffer;

  while (CIRC_SPACE(write_buff->head, write_buff->tail, AESDRV_IOBUFF_SIZE) == 0)
  {
    wait_event(big_queue, CIRC_SPACE(write_buff->head, write_buff->tail, AESDRV_IOBUFF_SIZE) == 0);
  }

  in_buffer = CIRC_SPACE(write_buff->head, write_buff->tail, AESDRV_IOBUFF_SIZE);
  to_write = min(len, in_buffer);
  to_write_1 = min((int) to_write, CIRC_CNT_TO_END(write_buff->head, write_buff->tail, AESDRV_IOBUFF_SIZE));
  to_write_2 = to_write - to_write_1;

  if (copy_from_user(write_buff->buf + write_buff->head, buf, to_write_1))
  {
    printk(KERN_WARNING "copy_to_user\n");
    return -EFAULT;
  }

  if (to_write_2)
    if (copy_to_user(write_buff->buf, buf, to_write_2))
    {
      printk(KERN_WARNING "copy_to_user\n");
      return -EFAULT;
    }

  write_buff->head += to_write_1;
  /* TODO to jest bug */
  if (to_write >= to_write_1)
    write_buff->head = to_write_2;

  return len;
}

static int aes_file_open(struct inode *i, struct file *f)
{
  aes128_context *context = kmalloc(sizeof(aes128_context), GFP_KERNEL);
  init_context(context);

  context->aes_dev = aes_devs[iminor(i)];
  f->private_data = context;
  printk(KERN_WARNING "Assigned opened file to device %p\n", context->aes_dev);
  return 0;
}

static int aes_file_release(struct inode *i, struct file *f)
{
  destroy_context(f->private_data);
  kfree(f->private_data);
  return 0;
}

static long aes_file_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
  aes128_context *context;

  context = f->private_data;

  if (context->mode == AES_UNDEF && cmd == AESDEV_IOCTL_GET_STATE)
    return -EINVAL;

  if (cmd == AESDEV_IOCTL_SET_ECB_ENCRYPT)
  {
    context->mode = AES_ECB_ENCRYPT;
  }
  else if (cmd == AESDEV_IOCTL_SET_ECB_DECRYPT)
  {
    context->mode = AES_ECB_DECRYPT;
  }
  else if (cmd == AESDEV_IOCTL_SET_CBC_ENCRYPT)
  {
    context->mode = AES_CBC_ENCRYPT;
  }
  else if (cmd == AESDEV_IOCTL_SET_CBC_DECRYPT)
  {
    context->mode = AES_CBC_DECRYPT;
  }
  else if (cmd == AESDEV_IOCTL_SET_CFB_ENCRYPT)
  {
    context->mode = AES_CBC_DECRYPT;
  }
  else if (cmd == AESDEV_IOCTL_SET_CFB_DECRYPT)
  {
    context->mode = AES_CBC_DECRYPT;
  }
  else if (cmd == AESDEV_IOCTL_SET_OFB)
  {
    context->mode = AES_OFB;
  }
  else if (cmd == AESDEV_IOCTL_SET_CTR)
  {
    context->mode = AES_CTR;
  }
  else if (cmd == AESDEV_IOCTL_GET_STATE)
  {
    if (context->mode == AES_ECB_DECRYPT ||
        context->mode == AES_ECB_ENCRYPT ||
        context->mode == AES_UNDEF)
      return -EINVAL;

    printk(KERN_WARNING "Not supported yet!\n");
    return -EINVAL;
  }

  if (copy_from_user(&context->key, (void *) arg, sizeof(aes128_block)))
  {
    printk(KERN_WARNING "copy_from_user\n");
    return -EFAULT;
  }

  if (cmd != AESDEV_IOCTL_SET_ECB_ENCRYPT && cmd != AESDEV_IOCTL_SET_ECB_DECRYPT)
  {
    if (copy_from_user(&context->state, ((char *) arg) + sizeof(aes128_block), sizeof(aes128_block)))
    {
      printk(KERN_WARNING "copy_from_user\n");
    }
  }

  return 0;
}
/*****************************************************************************/

/*** Device procedures *******************************************************/
int init_cmd_buffer(aes128_dev *aes_dev)
{
  void __iomem *bar0;
  char *k_buffer_ptr;
  dma_addr_t d_buffer_ptr;

  bar0 = aes_dev->bar0;

  /* TODO: 16-byte alignment */
  k_buffer_ptr = dma_alloc_coherent(&aes_dev->pci_dev->dev, AESDRV_CMDBUFF_SIZE,
                                    &d_buffer_ptr, GFP_KERNEL);
  aes_dev->cmd_buff_ptr = k_buffer_ptr;
  aes_dev->d_cmd_buff_ptr = d_buffer_ptr;

  iowrite32(d_buffer_ptr, bar0 + AESDEV_CMD_BEGIN_PTR);
  /* TODO: Ostatni czy zaostatni? */
  iowrite32(d_buffer_ptr + AESDRV_CMDBUFF_SIZE, bar0 + AESDEV_CMD_END_PTR);
  iowrite32(d_buffer_ptr, bar0 + AESDEV_CMD_READ_PTR);
  iowrite32(d_buffer_ptr, bar0 + AESDEV_CMD_WRITE_PTR);

  return 0;
}

int init_aes_device(aes128_dev *aes_dev)
{
  void __iomem *bar0;

  memset(aes_dev, 0, sizeof(aes128_dev));

  mutex_init(&aes_dev->mutex);

  bar0 = aes_dev->bar0;
  SET_FLAG(bar0 + AESDEV_ENABLE,
           AESDEV_ENABLE_XFER_DATA | AESDEV_ENABLE_FETCH_CMD);
  SET_FLAG(bar0 + AESDEV_INTR_ENABLE, 0xFF);

  return 0;
}

int destroy_aes_device(aes128_dev *aes_dev)
{
  mutex_destroy(&aes_dev->mutex);

  return 0;
}
/*****************************************************************************/

/*** PCI handlers ************************************************************/
int aes_pci_probe(struct pci_dev *pci_dev, const struct pci_device_id *id)
{
  aes128_dev *aes_dev;

  if (pci_enable_device(pci_dev))
  {
    printk(KERN_WARNING "pci_enable_device\n");
    return -EFAULT;
  }
  if (pci_request_regions(pci_dev, "aesdev"))
  {
    printk(KERN_WARNING "pci_request_regions\n");
    return -EFAULT;
  }
  aes_dev = kmalloc(sizeof(aes128_dev), GFP_KERNEL);
  aes_dev->bar0 = pci_iomap(pci_dev, 0, 0);
  aes_dev->sys_dev = device_create(dev_class, NULL, MKDEV(major, dev_count), NULL, "aesdev%d", dev_count);
  aes_dev->pci_dev = pci_dev;
  pci_set_drvdata(pci_dev, aes_dev);

  pci_set_master(pci_dev);
  pci_set_dma_mask(pci_dev, DMA_BIT_MASK(32));
  pci_set_consistent_dma_mask(pci_dev, DMA_BIT_MASK(32));


  aes_devs[dev_count] = aes_dev;
  dev_count++;

  printk(KERN_WARNING "Registered new aesdev\n");

  return 0;
}

void aes_pci_remove(struct pci_dev *dev)
{
  aes128_dev *aes_dev;

  aes_dev = pci_get_drvdata(dev);
  pci_iounmap(dev, aes_dev->bar0);
  pci_release_regions(dev);
  pci_disable_device(dev);

  kfree(aes_dev);

  printk(KERN_WARNING "Unregistered aesdev\n");
}

int aes_pci_resume(struct pci_dev *dev)
{
  return 0;
}

void aes_pci_shutdown(struct pci_dev *dev)
{
}

int aes_pci_suspend(struct pci_dev *dev, pm_message_t state)
{
  return 0;
}
/*****************************************************************************/

static int aesdev_init(void)
{
  /* Rejestracja majora */
  major = register_chrdev(0, "aesdev", &aes_fops);

  /* Rejestracja urządzenia w kernelu */
  dev_class = class_create(THIS_MODULE, "aesdev");

  /* Rejestracja drivera PCI */
  if (pci_register_driver(&aes_pci))
  {
    printk(KERN_WARNING "pci_register_driver\n");
    return -EFAULT;
  }

  /* Podpięcie pod vendor id i product id */
//   return -EFAULT;
  return 0;
}

static void aesdev_cleanup(void)
{
  pci_unregister_driver(&aes_pci);
  device_destroy(dev_class, MKDEV(major, 0));
  class_destroy(dev_class);
}

module_init(aesdev_init);
module_exit(aesdev_cleanup);