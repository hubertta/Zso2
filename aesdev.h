#ifndef _AESDEV_H
#define _AESDEV_H

#include "aesdev_ioctl.h"
#include "aesdev_defines.h"

#include <linux/fs.h>
#include <linux/pci.h>
#include <linux/circ_buf.h>
#include <linux/wait.h>

typedef struct
{
  uint8_t state[AESDEV_AES_BLOCK_SIZE];
} aes128_block;

typedef struct
{
  void __iomem *bar0;
  struct device *sys_dev;
  struct pci_dev *pci_dev;
  char *cmd_buff_ptr;
  dma_addr_t d_cmd_buff_ptr;
  struct mutex mutex;
} aes128_dev;

typedef struct
{
  AES_MODE mode;
  aes128_block key;
  aes128_block state;
  aes128_dev *aes_dev;
  struct circ_buf write_buffer;
  struct circ_buf read_buffer;
  struct mutex mutex;
} aes128_context;

typedef struct
{
    dma_addr_t d_input_data_ptr;
    dma_addr_t d_output_data_ptr;
    aes128_block k_input_data_ptr;
    aes128_block k_output_data_ptr;
    size_t block_count;
    uint32_t xfer_task;
    aes128_context *context;
} aes128_task;

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