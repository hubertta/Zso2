#ifndef _AESDEV_H
#define _AESDEV_H

#include "aesdev_ioctl.h"
#include "aesdev_defines.h"

#include <linux/list.h>
#include <linux/fs.h>
#include <linux/pci.h>
#include <linux/circ_buf.h>
#include <linux/wait.h>

struct aes128_combo_buffer;     /* Buffer for read/write/encrypted data.  */
struct aes128_block;            /* 16 bytes of data, used for both state,
                                   data and keys.  */
struct aes128_dev;              /* Represents single aes device.  */
struct aes128_context;          /* Corresponds to single struct file.  */
struct aes128_command;          /* Represents one slot in dev's cmd buffer.  */
struct aes128_task;

typedef struct aes128_combo_buffer aes128_combo_buffer;
typedef struct aes128_block aes128_block;
typedef struct aes128_dev aes128_dev;
typedef struct aes128_context aes128_context;
typedef struct aes128_task aes128_task;
typedef struct aes128_command aes128_command;

typedef uint32_t aes_dma_addr_t;    /* Aes device supports 32-bit addresses. */

struct aes128_combo_buffer
{
  size_t read_tail;         /* Start reading encrypted data here.  */
  size_t write_tail;        /* Stop reading encrypted data before this.  */
  size_t write_head;        /* Append new data here.  */
  char *k_data;             /* Kernel address space */
  aes_dma_addr_t d_data;    /* DMA address space */
};

struct aes128_block
{
  uint8_t state[AESDEV_AES_BLOCK_SIZE];
};

struct aes128_dev
{
  void __iomem *bar0;
  struct device *sys_dev;
  struct pci_dev *pci_dev;

  aes128_command *k_cmd_buff_ptr;
  aes_dma_addr_t d_cmd_buff_ptr;

  spinlock_t lock;
  wait_queue_head_t command_queue;

  size_t tasks_in_progress;

  struct list_head context_list_head;
  struct list_head task_list_head;
  struct list_head completed_list_head;
  
  int minor;
};

struct aes128_context
{
  AES_MODE mode;

  aes128_dev *aes_dev;

  struct circ_buf write_buffer;
  struct circ_buf read_buffer;

  wait_queue_head_t read_queue;
  wait_queue_head_t write_queue;

  struct mutex read_lock;       /* Protect read buffer.  */
  struct mutex write_lock;      /* Protect write buffer.  */

  char file_open;               /* Is the file still open?  */
  int cmds_in_progress;         /* How many commands are in device queue?  */
  
  unsigned int flags;           /* Passed to open.  */

  struct list_head context_list;
  struct list_head completed_list_head;

  aes_dma_addr_t d_ks_ptr;      /* Key and state buffer.  */
  aes128_block *k_ks_ptr;
  
};

/* Complete set of information for one command.  */
struct aes128_task
{
  uint32_t d_input_data_ptr;
  aes_dma_addr_t d_output_data_ptr;
  aes128_block *k_input_data_ptr;
  aes128_block *k_output_data_ptr;
  size_t block_count;
  aes128_context *context;
  int cmd_index;
  AES_MODE mode;
  struct list_head task_list;
};

/* This is to reflect single entry in CMD block */
struct aes128_command
{
  uint32_t in_ptr;
  uint32_t out_ptr;
  uint32_t ks_ptr;
  uint32_t xfer_val;
};

/* Module handlers */
static int aesdrv_init (void);
static void aesdrv_cleanup (void);

/* File operations */
static ssize_t file_read (struct file *, char __user *, size_t, loff_t *);
static ssize_t file_write (struct file *, const char __user *, size_t, loff_t *);
static int file_open (struct inode *, struct file *);
static int file_release (struct inode *, struct file *);
static long file_ioctl (struct file *f, unsigned int cmd, unsigned long arg);

/* PCI operations */
static int pci_probe (struct pci_dev *dev, const struct pci_device_id *id);
static void pci_remove (struct pci_dev *dev);
static void pci_shutdown (struct pci_dev *dev);

/* Cyclic buffers */
static size_t cbuf_cont (const struct circ_buf *buf);
static size_t cbuf_free (const struct circ_buf *buf);
static int cbuf_take (void *dest, struct circ_buf *buf, size_t len);
static int cbuf_add_from_kernel (struct circ_buf *buf, const char *data, size_t len);
static int cbuf_add_from_user (struct circ_buf *buf, const char __user *data, size_t len);

#endif /* _AESDEV_H */