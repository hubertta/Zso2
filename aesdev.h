#ifndef _AESDEV_H
#define _AESDEV_H

#include "aesdev_ioctl.h"
#include "aesdev_defines.h"

#include <linux/list.h>
#include <linux/fs.h>
#include <linux/pci.h>
#include <linux/circ_buf.h>
#include <linux/wait.h>

struct aes128_block;
struct aes128_key;
struct aes128_dev;
struct aes128_context;
struct aes128_task;
struct aes128_command;

typedef struct aes128_block aes128_block;
typedef struct aes128_key aes128_key;
typedef struct aes128_dev aes128_dev;
typedef struct aes128_context aes128_context;
typedef struct aes128_task aes128_task;
typedef struct aes128_command aes128_command;

typedef uint32_t aes_dma_addr_t;

struct aes128_block
{
  uint8_t state[AESDEV_AES_BLOCK_SIZE];
};

struct aes128_key
{
  uint8_t key[AESDEV_AES_KEY_SIZE];
};

struct aes128_dev
{
  void __iomem *bar0;
  struct device *sys_dev;
  struct pci_dev *pci_dev;
  
  aes128_command *k_cmd_buff_ptr;
  aes_dma_addr_t d_cmd_buff_ptr;
  aes_dma_addr_t d_cmd_read_ptr;    /* NEVER go beyond that! */
  aes_dma_addr_t d_cmd_write_ptr;
  aes_dma_addr_t d_cmd_end_ptr;
  
  spinlock_t lock;
  wait_queue_head_t command_queue;
  
  size_t command_space;
  int intr;
  
  struct list_head context_list_head;
};

struct aes128_context
{
  AES_MODE mode;
  
  aes128_block key;
  aes128_block state;
  aes128_dev *aes_dev;
  
  struct circ_buf write_buffer;
  struct circ_buf read_buffer;
  
  wait_queue_head_t read_queue;
  wait_queue_head_t write_queue;
  struct mutex lock;
  
  char file_open;                   /* Is the file still open? */
  int cmds_in_progress;             /* How many commends are in device queue? */
  
  struct list_head context_list;
  struct list_head task_list_head;
};

/* Complete set of information for one command */
struct aes128_task
{
  uint32_t d_input_data_ptr;
  aes_dma_addr_t d_output_data_ptr;
  aes_dma_addr_t d_ks_ptr;
  aes128_block *k_input_data_ptr;
  aes128_block *k_output_data_ptr;
  aes128_block *k_ks_ptr;
  size_t block_count;
  aes128_context *context;
  aes_dma_addr_t d_read_ptr;
  aes_dma_addr_t d_write_ptr;
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
static int pci_suspend (struct pci_dev *dev, pm_message_t state);
static int pci_resume (struct pci_dev *dev);
static void pci_shutdown (struct pci_dev *dev);

/* Cyclic buffers */
static int cbuf_cont (const struct circ_buf *buf);
static int cbuf_free (const struct circ_buf *buf);
static int cbuf_take (void *dest, struct circ_buf *buf, int len);
static int cbuf_add_from_kernel (struct circ_buf *buf, const char *data, int len);
static int cbuf_add_from_user (struct circ_buf *buf, const char __user *data, int len);

#endif /* _AESDEV_H */