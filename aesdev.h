#ifndef _AESDEV_H
#define _AESDEV_H

#include "aesdev_ioctl.h"

#include <linux/fs.h>
#include <linux/pci.h>
#include <linux/circ_buf.h>
#include <linux/wait.h>

#define AESDEV_VENDOR_ID    0x1af4
#define AESDEV_DEVICE_ID    0x10fc

#define AESDEV_ENABLE     0x000
#define AESDEV_ENABLE_XFER_DATA   0x00000001
#define AESDEV_ENABLE_FETCH_CMD   0x00000002
#define AESDEV_STATUS     0x004
#define AESDEV_STATUS_XFER_DATA   0x00000001
#define AESDEV_STATUS_FETCH_CMD   0x00000002
#define AESDEV_INTR     0x008
#define AESDEV_INTR_ENABLE    0x00c

#define AESDEV_AES_KEY(i)   (0x010 + (i))
#define AESDEV_AES_DATA(i)    (0x020 + (i))
#define AESDEV_AES_STATE(i)   (0x030 + (i))

#define AESDEV_XFER_IN_PTR    0x040
#define AESDEV_XFER_OUT_PTR   0x044
#define AESDEV_XFER_STATE_PTR   0x048
#define AESDEV_XFER_TASK    0x04c

#define AESDEV_TASK(count, intr, save, mode)    ((count) << 12 | (intr) << 4 | (save) << 3 | (mode))
#define AESDEV_TASK_MODE(task)          ((task) & 7)
#define AESDEV_TASK_SAVE(task)          ((task) >> 3 & 1)
#define AESDEV_TASK_INTR(task)          ((task) >> 4 & 0xff)
#define AESDEV_TASK_COUNT(task)         ((task) >> 12 & 0xfffff)
#define AESDEV_TASK_ACTIVE(task)        (!!((task) & ~0x7))

#define AESDEV_MODE_ECB_ENCRYPT   0
#define AESDEV_MODE_ECB_DECRYPT   1
#define AESDEV_MODE_CBC_ENCRYPT   2
#define AESDEV_MODE_CBC_DECRYPT   3
#define AESDEV_MODE_CFB_ENCRYPT   4
#define AESDEV_MODE_CFB_DECRYPT   5
#define AESDEV_MODE_OFB     6
#define AESDEV_MODE_CTR     7

#define AESDEV_CMD_BEGIN_PTR    0x050
#define AESDEV_CMD_END_PTR    0x054
#define AESDEV_CMD_READ_PTR   0x058
#define AESDEV_CMD_WRITE_PTR    0x05c

#define AESDEV_AES_KEY_SIZE   0x10
#define AESDEV_AES_BLOCK_SIZE   0x10

#define AESDRV_IOBUFF_SIZE 0x1000
#define AESDRV_CMDBUFF_SIZE 0x100

#define SET_FLAG(reg, flag)\
  do\
  {\
    unsigned int _current;\
    _current = ioread32(reg);\
    iowrite32(_current & ~(flag), reg);\
  } while (0)
#define RESET_FLAG(reg, flag)\
  do\
  {\
    unsigned int _current;\
    _current = ioread32(reg);\
    iowrite32(_current | (flag), reg);\
  } while (0)

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