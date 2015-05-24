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
test_ecb ()
{
  const char *text1 = "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a";
  const char *cipher1 = "\x3a\xd7\x7b\xb4\x0d\x7a\x36\x60\xa8\x9e\xca\xf3\x24\x66\xef\x97";

  const char *text2 = "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51";
  const char *cipher2 = "\xf5\xd3\xd5\x85\x03\xb9\x69\x9d\xe7\x85\x89\x5a\x96\xfd\xba\xaf";

  const char *text3 = "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef";
  const char *cipher3 = "\x43\xb1\xcd\x7f\x59\x8e\xce\x23\x88\x1b\x00\xe3\xed\x03\x06\x88";

  const char *text4 = "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10";
  const char *cipher4 = "\x7b\x0c\x78\x5e\x27\xe8\xad\x3f\x82\x23\x20\x71\x04\x72\x5d\xd4";

  const char *key = "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";

  char *all_text, *all_cipher, *all_result;

  int i, ok;

  set_mode (AESDEV_IOCTL_SET_ECB_ENCRYPT, key);

  all_text = malloc (16 * 4);
  all_cipher = malloc (16 * 4);
  all_result = malloc (16 * 4);

  memcpy (all_text, text1, 16);
  memcpy (all_text + 16, text2, 16);
  memcpy (all_text + 32, text3, 16);
  memcpy (all_text + 48, text4, 16);

  memcpy (all_cipher, cipher1, 16);
  memcpy (all_cipher + 16, cipher2, 16);
  memcpy (all_cipher + 32, cipher3, 16);
  memcpy (all_cipher + 48, cipher4, 16);

  /*** Test 1 ***/
  do_write (fd, text1, 16);
  do_write (fd, text2, 16);
  do_write (fd, text3, 16);
  do_write (fd, text4, 16);

  do_read (fd, all_result, 16 * 4);

  fprintf (stderr, "ECB encrypt (1): %s\n", is_equal (all_result, all_cipher, 16 * 4) ? "ok" : "err");
  assert_equal (all_result, all_cipher, 16 * 4);

  /*** Test 2 ***/
  do_write (fd, all_text, 16 * 4);

  do_read (fd, all_result, 16);
  do_read (fd, all_result + 16, 16);
  do_read (fd, all_result + 32, 16);
  do_read (fd, all_result + 48, 16);

  fprintf (stderr, "ECB encrypt (2): %s\n", is_equal (all_result, all_cipher, 16 * 4) ? "ok" : "err");
  assert_equal (all_result, all_cipher, 16 * 4);

  /*** Test 3 ***/
  for (i = 0; i < 16 * 4; ++i)
    do_write (fd, all_text + i, 1);
  do_read (fd, all_result, 16 * 4);

  fprintf (stderr, "ECB encrypt (3): %s\n", is_equal (all_result, all_cipher, 16 * 4) ? "ok" : "err");
  assert_equal (all_result, all_cipher, 16 * 4);

  /*** Test 4 ***/
  for (i = 0, ok = 1; i < 64; ++i)
    {
      do_write (fd, all_text, 64);
      do_read (fd, all_result, 64);
      if (!is_equal (all_result, all_cipher, 64))
        ok = 0;
      assert_equal (all_result, all_cipher, 64);
    }
  fprintf (stderr, "ECB encrypt (4): %s\n", ok ? "ok" : "err");

  /** Test 5 ***/
  for (i = 0; i < 64; ++i)
    do_write (fd, all_text, 64);
  for (i = 0, ok = 1; i < 64 * 64; ++i)
    {
      do_read (fd, all_result + (i % 64), 1);
      if (!is_equal (all_result + (i % 64), all_cipher + (i % 64), 1))
        ok = 0;
      assert_equal (all_result + (i % 64), all_cipher + (i % 64), 1);
    }
  assert_equal (all_result, all_cipher, 64);
  fprintf (stderr, "ECB encrypt (5): %s\n", ok ? "ok" : "err");
}

void
test_cbc ()
{
  const char *iv1 = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
  const char *text1 = "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a";
  const char *cipher1 = "\x76\x49\xab\xac\x81\x19\xb2\x46\xce\xe9\x8e\x9b\x12\xe9\x19\x7d";

  const char *iv2 = "\x76\x49\xAB\xAC\x81\x19\xB2\x46\xCE\xE9\x8E\x9B\x12\xE9\x19\x7D";
  const char *text2 = "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51";
  const char *cipher2 = "\x50\x86\xcb\x9b\x50\x72\x19\xee\x95\xdb\x11\x3a\x91\x76\x78\xb2";

  const char *iv3 = "\x50\x86\xcb\x9b\x50\x72\x19\xee\x95\xdb\x11\x3a\x91\x76\x78\xb2";
  const char *text3 = "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef";
  const char *cipher3 = "\x73\xbe\xd6\xb8\xe3\xc1\x74\x3b\x71\x16\xe6\x9e\x22\x22\x95\x16";

  const char *iv4 = "\x73\xBE\xD6\xB8\xE3\xC1\x74\x3B\x71\x16\xE6\x9E\x22\x22\x95\x16";
  const char *text4 = "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10";
  const char *cipher4 = "\x3f\xf1\xca\xa1\x68\x1f\xac\x09\x12\x0e\xca\x30\x75\x86\xe1\xa7";

  const char *key = "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";

  char *all_text, *all_cipher, *all_result, *key_iv;

  int i, ok;

  all_text = malloc (16 * 4);
  all_cipher = malloc (16 * 4);
  all_result = malloc (16 * 4);
  key_iv = malloc (16 * 2);

  memcpy (key_iv, key, 16);
  ok = 1;

  /*** Test 1 ***/
  memcpy (key_iv + 16, iv1, 16);
  set_mode (AESDEV_IOCTL_SET_CBC_ENCRYPT, key_iv);
  do_write (fd, text1, 16);
  do_read (fd, all_result, 16);
  if (!is_equal (all_result, cipher1, 16)) ok = 0;
  assert_equal (all_result, cipher1, 16);

  do_write (fd, text2, 16);
  do_read (fd, all_result, 16);
  if (!is_equal (all_result, cipher2, 16)) ok = 0;
  assert_equal (all_result, cipher2, 16);

  do_write (fd, text3, 16);
  do_read (fd, all_result, 16);
  if (!is_equal (all_result, cipher3, 16)) ok = 0;
  assert_equal (all_result, cipher3, 16);

  do_write (fd, text4, 16);
  do_read (fd, all_result, 16);
  if (!is_equal (all_result, cipher4, 16)) ok = 0;
  assert_equal (all_result, cipher4, 16);

  fprintf (stderr, "CBC encrypt (1): %s\n", ok ? "ok" : "err");

  /*** Test 2 ***/
  do_write (fd, text3, 16);
  do_write (fd, text2, 16);
  do_write (fd, text1, 16);
  do_read (fd, all_result + 16, 48);
  memcpy (key_iv + 16, iv4, 16);
  set_mode (AESDEV_IOCTL_SET_CBC_DECRYPT, key_iv);
  do_write (fd, all_result, 64);
  do_read (fd, all_result, 64);
  ok = 1;
  if (!is_equal (all_result, text4, 16)) ok = 0;
  if (!is_equal (all_result + 16, text3, 16)) ok = 0;
  if (!is_equal (all_result + 32, text2, 16)) ok = 0;
  if (!is_equal (all_result + 48, text1, 16)) ok = 0;
  assert_equal (all_result, text4, 16);
  assert_equal (all_result + 16, text3, 16);
  assert_equal (all_result + 32, text2, 16);
  assert_equal (all_result + 48, text1, 16);

  fprintf (stderr, "CBC enc/dec (2): %s\n", ok ? "ok" : "err");
}

void
test_cfb ()
{
  const char *iv1 = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
  const char *text1 = "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a";
  const char *cipher1 = "\x3b\x3f\xd9\x2e\xb7\x2d\xad\x20\x33\x34\x49\xf8\xe8\x3c\xfb\x4a";

  const char *iv2 = "\x3B\x3F\xD9\x2E\xB7\x2D\xAD\x20\x33\x34\x49\xF8\xE8\x3C\xFB\x4A";
  const char *text2 = "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51";
  const char *cipher2 = "\xc8\xa6\x45\x37\xa0\xb3\xa9\x3f\xcd\xe3\xcd\xad\x9f\x1c\xe5\x8b";

  const char *iv3 = "\xC8\xA6\x45\x37\xA0\xB3\xA9\x3F\xCD\xE3\xCD\xAD\x9F\x1C\xE5\x8B";
  const char *text3 = "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef";
  const char *cipher3 = "\x26\x75\x1f\x67\xa3\xcb\xb1\x40\xb1\x80\x8c\xf1\x87\xa4\xf4\xdf";

  const char *iv4 = "\x26\x75\x1F\x67\xA3\xCB\xB1\x40\xB1\x80\x8C\xF1\x87\xA4\xF4\xDF";
  const char *text4 = "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10";
  const char *cipher4 = "\xc0\x4b\x05\x35\x7c\x5d\x1c\x0e\xea\xc4\xc6\x6f\x9f\xf7\xf2\xe6";

  const char *key = "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";

  char *all_text, *all_cipher, *all_result, *key_iv;

  int ok;

  all_text = malloc (16 * 4);
  all_cipher = malloc (16 * 4);
  all_result = malloc (16 * 4);
  key_iv = malloc (16 * 2);

  memcpy (key_iv, key, 16);
  ok = 1;

  /*** Test 1 ***/
  memcpy (key_iv + 16, iv1, 16);
  set_mode (AESDEV_IOCTL_SET_CFB_ENCRYPT, key_iv);
  do_write (fd, text1, 16);
  do_read (fd, all_result, 16);
  if (!is_equal (all_result, cipher1, 16)) ok = 0;
  assert_equal (all_result, cipher1, 16);

  do_write (fd, text2, 16);
  do_read (fd, all_result, 16);
  if (!is_equal (all_result, cipher2, 16)) ok = 0;
  assert_equal (all_result, cipher2, 16);

  do_write (fd, text3, 16);
  do_read (fd, all_result, 16);
  if (!is_equal (all_result, cipher3, 16)) ok = 0;
  assert_equal (all_result, cipher3, 16);

  do_write (fd, text4, 16);
  do_read (fd, all_result, 16);
  if (!is_equal (all_result, cipher4, 16)) ok = 0;
  assert_equal (all_result, cipher4, 16);

  fprintf (stderr, "CFB encrypt (1): %s\n", ok ? "ok" : "err");

  /*** Test 2 ***/
  do_write (fd, text3, 16);
  do_write (fd, text2, 16);
  do_write (fd, text1, 16);
  do_read (fd, all_result + 16, 48);
  memcpy (key_iv + 16, iv4, 16);
  set_mode (AESDEV_IOCTL_SET_CFB_DECRYPT, key_iv);
  do_write (fd, all_result, 64);
  do_read (fd, all_result, 64);
  ok = 1;
  if (!is_equal (all_result, text4, 16)) ok = 0;
  if (!is_equal (all_result + 16, text3, 16)) ok = 0;
  if (!is_equal (all_result + 32, text2, 16)) ok = 0;
  if (!is_equal (all_result + 48, text1, 16)) ok = 0;
  assert_equal (all_result, text4, 16);
  assert_equal (all_result + 16, text3, 16);
  assert_equal (all_result + 32, text2, 16);
  assert_equal (all_result + 48, text1, 16);

  fprintf (stderr, "CFB enc/dec (2): %s\n", ok ? "ok" : "err");
}

void
test_ofb ()
{
  const char *iv1 = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
  const char *text1 = "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a";
  const char *cipher1 = "\x3b\x3f\xd9\x2e\xb7\x2d\xad\x20\x33\x34\x49\xf8\xe8\x3c\xfb\x4a";

  const char *iv2 = "\x50\xFE\x67\xCC\x99\x6D\x32\xB6\xDA\x09\x37\xE9\x9B\xAF\xEC\x60";
  const char *text2 = "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51";
  const char *cipher2 = "\x77\x89\x50\x8d\x16\x91\x8f\x03\xf5\x3c\x52\xda\xc5\x4e\xd8\x25";

  const char *iv3 = "\xD9\xA4\xDA\xDA\x08\x92\x23\x9F\x6B\x8B\x3D\x76\x80\xE1\x56\x74";
  const char *text3 = "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef";
  const char *cipher3 = "\x97\x40\x05\x1e\x9c\x5f\xec\xf6\x43\x44\xf7\xa8\x22\x60\xed\xcc";

  const char *iv4 = "\xA7\x88\x19\x58\x3F\x03\x08\xE7\xA6\xBF\x36\xB1\x38\x6A\xBF\x23";
  const char *text4 = "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10";
  const char *cipher4 = "\x30\x4c\x65\x28\xf6\x59\xc7\x78\x66\xa5\x10\xd9\xc1\xd6\xae\x5e";

  const char *key = "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";

  char *all_text, *all_cipher, *all_result, *key_iv;

  int ok;

  all_text = malloc (16 * 4);
  all_cipher = malloc (16 * 4);
  all_result = malloc (16 * 4);
  key_iv = malloc (16 * 2);

  memcpy (key_iv, key, 16);
  ok = 1;

  /*** Test 1 ***/
  memcpy (key_iv + 16, iv1, 16);
  set_mode (AESDEV_IOCTL_SET_OFB, key_iv);
  do_write (fd, text1, 16);
  do_read (fd, all_result, 16);
  if (!is_equal (all_result, cipher1, 16)) ok = 0;
  assert_equal (all_result, cipher1, 16);

  do_write (fd, text2, 16);
  do_read (fd, all_result, 16);
  if (!is_equal (all_result, cipher2, 16)) ok = 0;
  assert_equal (all_result, cipher2, 16);

  do_write (fd, text3, 16);
  do_read (fd, all_result, 16);
  if (!is_equal (all_result, cipher3, 16)) ok = 0;
  assert_equal (all_result, cipher3, 16);

  do_write (fd, text4, 16);
  do_read (fd, all_result, 16);
  if (!is_equal (all_result, cipher4, 16)) ok = 0;
  assert_equal (all_result, cipher4, 16);

  fprintf (stderr, "OFB encrypt (1): %s\n", ok ? "ok" : "err");

  /*** Test 2 ***/
  do_write (fd, text3, 16);
  do_write (fd, text2, 16);
  do_write (fd, text1, 16);
  do_read (fd, all_result + 16, 48);
  memcpy (key_iv + 16, iv4, 16);
  set_mode (AESDEV_IOCTL_SET_OFB, key_iv);
  do_write (fd, all_result, 64);
  do_read (fd, all_result, 64);
  ok = 1;
  if (!is_equal (all_result, text4, 16)) ok = 0;
  if (!is_equal (all_result + 16, text3, 16)) ok = 0;
  if (!is_equal (all_result + 32, text2, 16)) ok = 0;
  if (!is_equal (all_result + 48, text1, 16)) ok = 0;
  assert_equal (all_result, text4, 16);
  assert_equal (all_result + 16, text3, 16);
  assert_equal (all_result + 32, text2, 16);
  assert_equal (all_result + 48, text1, 16);

  fprintf (stderr, "OFB enc/dec (2): %s\n", ok ? "ok" : "err");
}

void
test_ctr ()
{
  const char *iv = "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff";
  const char *text1 = "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a";
  const char *cipher1 = "\x87\x4d\x61\x91\xb6\x20\xe3\x26\x1b\xef\x68\x64\x99\x0d\xb6\xce";

  const char *text2 = "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51";
  const char *cipher2 = "\x98\x06\xf6\x6b\x79\x70\xfd\xff\x86\x17\x18\x7b\xb9\xff\xfd\xff";

  const char *text3 = "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef";
  const char *cipher3 = "\x5a\xe4\xdf\x3e\xdb\xd5\xd3\x5e\x5b\x4f\x09\x02\x0d\xb0\x3e\xab";

  const char *text4 = "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10";
  const char *cipher4 = "\x1e\x03\x1d\xda\x2f\xbe\x03\xd1\x79\x21\x70\xa0\xf3\x00\x9c\xee";

  const char *key = "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";

  char *all_text, *all_cipher, *all_result, *key_iv;
  char *iv2;

  int ok;

  all_text = malloc (16 * 4);
  all_cipher = malloc (16 * 4);
  all_result = malloc (16 * 4);
  key_iv = malloc (16 * 2);
  iv2 = malloc (16);

  memcpy (key_iv, key, 16);
  ok = 1;

  /*** Test 1 ***/
  memcpy (key_iv + 16, iv, 16);
  set_mode (AESDEV_IOCTL_SET_CTR, key_iv);
  do_write (fd, text1, 16);
  do_read (fd, all_result, 16);
  if (!is_equal (all_result, cipher1, 16)) ok = 0;
  assert_equal (all_result, cipher1, 16);

  do_write (fd, text2, 16);
  do_read (fd, all_result, 16);
  if (!is_equal (all_result, cipher2, 16)) ok = 0;
  assert_equal (all_result, cipher2, 16);

  do_write (fd, text3, 16);
  do_read (fd, all_result, 16);
  if (!is_equal (all_result, cipher3, 16)) ok = 0;
  assert_equal (all_result, cipher3, 16);
  
  set_mode (AESDEV_IOCTL_GET_STATE, key_iv + 16);

  do_write (fd, text4, 16);
  do_read (fd, all_result, 16);
  if (!is_equal (all_result, cipher4, 16)) ok = 0;
  assert_equal (all_result, cipher4, 16);

  fprintf (stderr, "CTR encrypt (1): %s\n", ok ? "ok" : "err");

  /*** Test 2 ***/
  do_write (fd, text3, 16);
  do_write (fd, text2, 16);
  do_write (fd, text1, 16);
  do_read (fd, all_result + 16, 48);
  set_mode (AESDEV_IOCTL_SET_CTR, key_iv);
  do_write (fd, all_result, 64);
  do_read (fd, all_result, 64);
  ok = 1;
  if (!is_equal (all_result, text4, 16)) ok = 0;
  if (!is_equal (all_result + 16, text3, 16)) ok = 0;
  if (!is_equal (all_result + 32, text2, 16)) ok = 0;
  if (!is_equal (all_result + 48, text1, 16)) ok = 0;
  assert_equal (all_result, text4, 16);
  assert_equal (all_result + 16, text3, 16);
  assert_equal (all_result + 32, text2, 16);
  assert_equal (all_result + 48, text1, 16);

  fprintf (stderr, "CTR enc/dec (2): %s\n", ok ? "ok" : "err");
}

/*****************************************************************************/

int
main ()
{
  open_file ();

  test_ecb ();
//  test_cbc ();
//  test_cfb ();
//  test_ofb ();
//  test_ctr ();

  close (fd);

  return (EXIT_SUCCESS);
}
