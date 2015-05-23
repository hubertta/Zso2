#ifndef _AESDEV_H
#define _AESDEV_H

#include "aesdev_ioctl.h"
#include "aesdev_defines.h"

#include <linux/list.h>
#include <linux/fs.h>
#include <linux/pci.h>
#include <linux/circ_buf.h>
#include <linux/wait.h>

struct aes128_combo_buffer; /* Buffer for read/write/encrypted data.  */
struct aes128_block; /* 16 bytes of data, used for both state,
                                   data and keys.  */
struct aes128_dev; /* Represents single aes device.  */
struct aes128_context; /* Corresponds to single struct file.  */
struct aes128_command; /* Represents one slot in dev's cmd buffer.  */
struct aes128_task;
struct dma_ptr;
struct listed_file;

typedef struct aes128_combo_buffer aes128_combo_buffer;
typedef struct aes128_block aes128_block;
typedef struct aes128_dev aes128_dev;
typedef struct aes128_context aes128_context;
typedef struct aes128_task aes128_task;
typedef struct aes128_command aes128_command;
typedef struct dma_ptr dma_ptr;
typedef struct listed_file listed_file;

typedef uint32_t aes_dma_addr_t; /* Aes device supports 32-bit addresses. */

struct dma_ptr
{
  char *k_ptr; /* Use char * for easy standard-conforming
                                       pointer arithmetics.  */
  aes_dma_addr_t d_ptr;
};

struct aes128_combo_buffer
{
  size_t read_tail; /* Start reading encrypted data here.  */
  size_t write_tail; /* Stop reading encrypted data here.  */
  size_t to_encrypt_tail; /* Start making new task here.  */
  size_t write_head; /* Append new data here.  */
  size_t read_count;
  size_t write_count;
  size_t to_encrypt_count;
  dma_ptr data;

  struct mutex read_lock; /* For read_tail and read_head.  */
  struct mutex write_lock; /* For write_head.  */
  struct mutex common_lock;

  wait_queue_head_t read_queue;
  wait_queue_head_t write_queue;
};

static int acb_init (aes128_combo_buffer *buffer, aes128_dev *aes_dev);
static void acb_destroy (aes128_combo_buffer *buffer, aes128_dev *aes_dev);
static size_t acb_read_count (const aes128_combo_buffer *buffer);
static size_t acb_write_count (const aes128_combo_buffer *buffer);
static size_t acb_free (const aes128_combo_buffer *buffer);
static size_t acb_free_to_end (const aes128_combo_buffer *buffer);
static size_t
acb_read_count_to_end (const aes128_combo_buffer *buffer);

struct aes128_block
{
  uint8_t state[AESDEV_AES_BLOCK_SIZE];
};

struct listed_file
{
  struct list_head file_list;
  struct file *f;
};

struct aes128_dev
{
  void __iomem *bar0;
  struct device *sys_dev;
  struct pci_dev *pci_dev;

  dma_ptr cmd_buffer;

  spinlock_t lock;
  wait_queue_head_t command_queue;
  size_t tasks_in_progress;

  struct list_head task_list_head;
  struct list_head completed_list_head;
  struct list_head file_list_head;

  int minor;
};

struct aes128_context
{
  aes128_dev *aes_dev;
  aes128_combo_buffer buffer;
  int mode;
  dma_ptr ks_buffer; /* Key and state.  */
  listed_file lf;
};

/* Complete set of information for one command.  */
struct aes128_task
{
  dma_ptr inout_buffer;
  size_t block_count;
  aes128_context *context;
  int cmd_index;
  struct list_head task_list;
  aes_dma_addr_t write_ptr;
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

#endif /* _AESDEV_H */