/* 
 * File:   test1.c
 * Author: hubert
 *
 * Created on 16 maj 2015, 10:59
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "aesdev_ioctl.h"

int fd;
const char *test_block = "1111111122222222"; // 31 31 31 31 31 31 31 31 32 32 32 32 32 32 32 32
const char *test_key = "2222222244444444"; // 32 32 32 32 32 32 32 32 34 34 34 34 34 34 34 34
const char *test_iv = "3333333355555555"; // 
const char *test_key_iv = "22222222444444443333333355555555"; // 32 32 32 32 32 32 32 32 34 34 34 34 34 34 34 34
const char *test_enc_block = "\x7d\xe9\x85\x6a\xa1\xc4\x33\xcc\x87\x70\x5e\xab\x7d\x83\x88\xab";
// 7de9856aa1c433cc87705eab7d8388ab

void
do_write (int fd, const char *data, size_t len)
{
  ssize_t written, ret;

  written = 0;

  while (written < len)
    {
      ret = write (fd, data, len - written);
      if (ret < 0)
        {
          perror ("write");
          exit (1);
        }
      if (ret == 0)
        {
          fprintf (stderr, "unexpected EOF in write\n");
          exit (1);
        }
      written += ret;
    }
}

void
do_read (int fd, char *data, size_t len)
{
  ssize_t readed, ret;

  readed = 0;

  while (readed < len)
    {
      ret = read (fd, data + readed, len - readed);
      if (ret < 0)
        {
          perror ("read");
          exit (1);
        }
      if (ret == 0)
        {
          fprintf (stderr, "unexpected EOF in read\n");
          exit (1);
        }
      readed += ret;
    }
}

void
set_mode (int mode, const char *key_iv)
{
  int ret;
  ret = ioctl (fd, mode, key_iv);
  if (ret == -1)
    {
      perror ("ioctl");
      exit (1);
    }
}

void
open_file ()
{
  fd = open ("/dev/aes0", O_RDWR);
  if (fd == -1)
    {
      perror ("open");
      exit (1);
    }
}

char
is_equal (const char *d1, const char *d2, size_t len)
{
  char ok;
  size_t i;

  ok = 1;
  for (i = 0; i < len; ++i) if (d1[i] != d2[i]) ok = 0;

  return ok;
}

void
print_vec (const char *d, size_t len)
{
  int i;
  for (i = 0; i < len; ++i) fprintf (stderr, "%02x", d[i] & 0xFF);
  fprintf (stderr, "\n");
}

void
assert_equal (const char *d1, const char *d2, size_t len)
{
  if (!is_equal (d1, d2, len))
    {
      fprintf (stderr, "is        ");
      print_vec (d1, len);
      fprintf (stderr, "should be ");
      print_vec (d2, len);
    }
}

/*** TESTS *******************************************************************/
void
test_ecb_long ()
{
  const char *key = "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";
  char *all_text;
  const int length = 0x1000;

  set_mode (AESDEV_IOCTL_SET_ECB_ENCRYPT, key);

  all_text = malloc (length);

  /*** Test 1 ***/
  do_write (fd, all_text, length);
  fprintf (stderr, "ECB long written\n");
}

/*****************************************************************************/

int
main ()
{
  open_file ();

  test_ecb_long ();

  close (fd);

  return (EXIT_SUCCESS);
}
