#ifndef _AESDEV_H
#define _AESDEV_H

#include "aesdev_ioctl.h"

#include <linux/fs.h>
#include <linux/pci.h>

typedef enum
{
  AES_ECB_ENCRYPT,
  AES_ECB_DECRYPT,
  AES_CBC_ENCRYPT,
  AES_CBC_DECRYPT,
  AES_CFB_ENCRYPT,
  AES_CFB_DECRYPT,
  AES_OFB,
  AES_CTR,
  AES_UNDEF
} AES_MODE;

typedef struct
{
  uint8_t state[0x10];
} aes128_block;

typedef struct
{
  void __iomem *bar0;
} aes128_dev;

typedef struct
{
  AES_MODE mode;
  aes128_block key;
  aes128_block state;
  aes128_dev *aes_dev;
} aes128_context;

/* Module handlers */
static int aesdev_init(void);
static void aesdev_cleanup(void);

/* File operations */
static ssize_t aes_file_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t aes_file_write(struct file *, const char __user *, size_t, loff_t *);
static int aes_file_open(struct inode *, struct file *);
static int aes_file_release(struct inode *, struct file *);
static long aes_file_ioctl(struct file *f, unsigned int cmd, unsigned long arg);

/* PCI operations */
static int aes_pci_probe(struct pci_dev *dev, const struct pci_device_id *id);
static void aes_pci_remove(struct pci_dev *dev);
static int aes_pci_suspend(struct pci_dev *dev, pm_message_t state);
static int aes_pci_resume(struct pci_dev *dev);
static void aes_pci_shutdown(struct pci_dev *dev);

#endif /* _AESDEV_H */