#include "aesdev.h"

#include <linux/module.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");

static int major;

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
}

/*** File handlers ***********************************************************/
static ssize_t aes_file_read(struct file *f, char __user *buf, size_t len, loff_t *off)
{
  return 0;
}

static ssize_t aes_file_write(struct file *f, const char __user *buf, size_t len, loff_t *off)
{
  return len;
}

static int aes_file_open(struct inode *i, struct file *f)
{
  aes128_context *context = kmalloc(sizeof(aes128_context), GFP_KERNEL);
  init_context(context);
  f->private_data = context;
  return 0;
}

static int aes_file_release(struct inode *i, struct file *f)
{
  kfree(f->private_data);
  return 0;
}

static long aes_file_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
  return 0;
}
/*****************************************************************************/


/*** PCI handlers ************************************************************/
int aes_pci_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
  aes128_dev *aes_dev;

  pci_enable_device(dev);
  pci_request_regions(dev, "aesdev");
  aes_dev = kmalloc(sizeof(aes128_dev), GFP_KERNEL);
  aes_dev->bar0 = pci_iomap(dev, 0, 0);
  pci_set_drvdata(dev, aes_dev);

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

}

void aes_pci_shutdown(struct pci_dev *dev)
{

}

int aes_pci_suspend(struct pci_dev *dev, pm_message_t state)
{

}
/*****************************************************************************/
static struct device *dev;
static struct class *dev_class;

static int aesdev_init(void)
{
  /* Rejestracja majora */
  major = register_chrdev(0, "aesdev", &aes_fops);

  /* Rejestracja urządzenia w kernelu */
  dev_class = class_create(THIS_MODULE, "aesdev");
  dev = device_create(dev_class, NULL, MKDEV(major, 0), NULL, "aesdev%d", 0);

  /* Rejestracja drivera PCI */
  pci_register_driver(&aes_pci);

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