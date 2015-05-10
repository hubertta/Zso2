#ifndef AESDEV_IOCTL_H
#define AESDEV_IOCTL_H

#ifdef __KERNEL__
#include <linux/kernel.h>
#else
#include <stdint.h>
#endif

#include <linux/ioctl.h>

struct aesdev_ioctl_set_ecb {
  uint8_t key[0x10];
};
struct aesdev_ioctl_set_iv {
  uint8_t key[0x10];
  uint8_t iv[0x10];
};
struct aesdev_ioctl_get_state {
  uint8_t state[0x10];
};
#define AESDEV_IOCTL_SET_ECB_ENCRYPT _IOW('C', 0x00, struct aesdev_ioctl_set_ecb)
#define AESDEV_IOCTL_SET_ECB_DECRYPT _IOW('C', 0x01, struct aesdev_ioctl_set_ecb)
#define AESDEV_IOCTL_SET_CBC_ENCRYPT _IOW('C', 0x02, struct aesdev_ioctl_set_iv)
#define AESDEV_IOCTL_SET_CBC_DECRYPT _IOW('C', 0x03, struct aesdev_ioctl_set_iv)
#define AESDEV_IOCTL_SET_CFB_ENCRYPT _IOW('C', 0x04, struct aesdev_ioctl_set_iv)
#define AESDEV_IOCTL_SET_CFB_DECRYPT _IOW('C', 0x05, struct aesdev_ioctl_set_iv)
#define AESDEV_IOCTL_SET_OFB         _IOW('C', 0x06, struct aesdev_ioctl_set_iv)
#define AESDEV_IOCTL_SET_CTR         _IOW('C', 0x07, struct aesdev_ioctl_set_iv)
#define AESDEV_IOCTL_GET_STATE       _IOR('C', 0x08, struct aesdev_ioctl_get_state)

#endif
