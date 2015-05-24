#pragma once

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
#define AESDEV_MODE_UNDEF 8
#define AESDEV_MODE_CLOSING 9

#define AESDEV_CMD_BEGIN_PTR    0x050
#define AESDEV_CMD_END_PTR    0x054
#define AESDEV_CMD_READ_PTR   0x058
#define AESDEV_CMD_WRITE_PTR    0x05c

#define AESDEV_AES_KEY_SIZE   0x10
#define AESDEV_AES_BLOCK_SIZE   0x10

#define AESDEV_BLOCK_CTRL 0x00
#define AESDEV_BLOCK_OP 0x10
#define AESDEV_BLOCK_XFER 0x40
#define AESDEV_BLOCK_CMD 0x50

#define AESDRV_IOBUFF_SIZE (0x100 * sizeof (aes128_block))
#define AESDRV_CMDBUFF_SLOTS (0x40)
#define AESDRV_CMDBUFF_SIZE (AESDRV_CMDBUFF_SLOTS * sizeof (aes128_command))
#define AESDRV_MAX_DEV_COUNT 0xFF

#define AESDEV_STOP(aes_dev) do\
  {\
    iowrite32(0x00000000, aes_dev->bar0);\
    iowrite32(0x00000000, aes_dev->bar0 + AESDEV_INTR_ENABLE);\
  }\
  while (0)

#define AESDEV_START(aes_dev) do\
  {\
    iowrite32(AESDEV_ENABLE_FETCH_CMD | AESDEV_ENABLE_XFER_DATA, aes_dev->bar0);\
    iowrite32(0x000000FF, aes_dev->bar0 + AESDEV_INTR_ENABLE);\
  }\
  while (0)

#define AESDEV_CMD_INDEXOF(begin, write) (((size_t)(write) - (size_t)(begin)) / 16)

#define HAS_STATE(mode) ((mode) != AESDEV_MODE_ECB_ENCRYPT && mode != AESDEV_MODE_ECB_DECRYPT)

#if 0
#define KDEBUG(msg, ...) do\
    {\
        printk(KERN_WARNING "%s: " msg, __func__, ##__VA_ARGS__);\
    } while (0)
#else
#define KDEBUG(...)
#endif

#define DNOTIF_ENTER_FUN KDEBUG ("entering\n")
#define DNOTIF_LEAVE_FUN KDEBUG ("leaving\n")


#if 1
#define assert(b) if (!(b)) printk (KERN_WARNING "ASSERT FAILED: %s\n", #b)
#else
#define assert(b)
#endif