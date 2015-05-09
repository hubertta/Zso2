#include <linux/module.h>
#include <linux/device.h>

MODULE_LICENSE("GPL");

static int aesdev_init(void);
static void aesdev_cleanup(void);

module_init(aesdev_init);
module_exit(aesdev_cleanup);

int aesdev_init(void)
{

}

void aesdev_cleanup(void)
{

}
