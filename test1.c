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
#include "aesdev_ioctl.h"

int fd;
const char *test_block = "1111111122222222"; // 31 31 31 31 31 31 31 31 32 32 32 32 32 32 32 32
const char *test_key = "2222222244444444"; // 32 32 32 32 32 32 32 32 34 34 34 34 34 34 34 34
const char *test_iv = "3333333355555555"; // 
const char *test_key_iv = "22222222444444443333333355555555"; // 32 32 32 32 32 32 32 32 34 34 34 34 34 34 34 34
const char *test_enc_block = "\x7d\xe9\x85\x6a\xa1\xc4\x33\xcc\x87\x70\x5e\xab\x7d\x83\x88\xab";
// 7de9856aa1c433cc87705eab7d8388ab

void
set_mode (int mode)
{
  int ret;
  ret = ioctl (fd, mode, test_key_iv);
  if (ret == -1)
    {
      perror ("ioctl");
      exit (1);
    }
}

void
write_block (const char *block)
{
  int ret;
  ret = write (fd, block, 16);
  if (ret == -1)
    {
      perror ("write");
      exit (1);
    }
  if (ret != 16)
    {
      fprintf (stderr, "write != 16\n");
      exit (1);
    }
}

void
read_block (char *block)
{
  int ret;
  ret = read (fd, block, 16);
  if (ret == -1)
    {
      perror ("read");
      exit (1);
    }
  if (ret != 16)
    {
      fprintf (stderr, "read != 16\n");
      exit (1);
    }
}

void
open_file ()
{
  fd = open ("/dev/aesdev0", O_RDWR);
  if (fd == -1)
    {
      perror ("open");
      exit (1);
    }
}

/*** TESTS *******************************************************************/
void
test_ecb ()
{
  char ok;
  int i;
  char test_result[17];

  set_mode (AESDEV_IOCTL_SET_ECB_ENCRYPT);

  write_block (test_block);
  usleep (100000);
  read_block (test_result);

  for (i = 0; i < 16; ++i)
    if (test_result[i] != test_enc_block[i])
      ok = 0;

  //  for (i = 0; i < 16; ++i) fprintf (stderr, "%02x", test_result[i] & 0xFF);
  //  fprintf (stderr, "\n");
  //  for (i = 0; i < 16; ++i) fprintf (stderr, "%02x", test_enc_block[i] & 0xFF);
  //  fprintf (stderr, "\n");

  fprintf (stderr, "ECB encrypt %s\n", (ok ? "ok" : "err"));

  set_mode (AESDEV_IOCTL_SET_ECB_DECRYPT);

  write_block (test_enc_block);
  usleep (100000);
  read_block (test_result);
  ok = 1;
  for (i = 0; i < 16; ++i)
    if (test_result[i] != test_block[i])
      ok = 0;
  //  for (i = 0; i < 16; ++i) fprintf (stderr, "%02x", test_result[i] & 0xFF);
  //  fprintf (stderr, "\n");
  fprintf (stderr, "ECB decrypt %s\n", (ok ? "ok" : "err"));
}

void
test_cbc ()
{
  char ok;
  int i;
  char test_result[17];
  char test_manual[17];

  set_mode (AESDEV_IOCTL_SET_CBC_ENCRYPT);

  write_block (test_block);
  usleep (100000);
  read_block (test_result);

  set_mode (AESDEV_IOCTL_SET_ECB_ENCRYPT);
  for (i = 0; i < 16; ++i)
    test_manual[i] = test_iv[i] ^ test_block[i];
  write_block (test_manual);
  usleep (100000);
  read_block (test_manual);

  ok = 1;
  for (i = 0; i < 16; ++i)
    if (test_result[i] != test_manual[i])
      ok = 0;

  //  for (i = 0; i < 16; ++i) fprintf (stderr, "%02x", test_result[i] & 0xFF);
  //  fprintf (stderr, "\n");
  //  for (i = 0; i < 16; ++i) fprintf (stderr, "%02x", test_manual[i] & 0xFF);
  //  fprintf (stderr, "\n");

  fprintf (stderr, "CBC encrypt %s\n", (ok ? "ok" : "err"));

  set_mode (AESDEV_IOCTL_SET_CBC_DECRYPT);
  write_block (test_result);
  usleep (100000);
  read_block (test_result);

  ok = 1;
  for (i = 0; i < 16; ++i)
    if (test_result[i] != test_block[i])
      ok = 0;
  fprintf (stderr, "CBC decrypt %s\n", (ok ? "ok" : "err"));
}

void
test_cfb ()
{
  char ok;
  int i;
  char test_result[17];
  char test_manual[17];

  set_mode (AESDEV_IOCTL_SET_CFB_ENCRYPT);

  write_block (test_block);
  usleep (100000);
  read_block (test_result);

  set_mode (AESDEV_IOCTL_SET_ECB_ENCRYPT);
  write_block (test_iv);
  usleep (100000);
  read_block (test_manual);
  for (i = 0; i < 16; ++i)
    test_manual[i] = test_manual[i] ^ test_block[i];

  ok = 1;
  for (i = 0; i < 16; ++i)
    if (test_result[i] != test_manual[i])
      ok = 0;

  if (!ok)
    {
      for (i = 0; i < 16; ++i) fprintf (stderr, "%02x", test_result[i] & 0xFF);
      fprintf (stderr, "\n");
      for (i = 0; i < 16; ++i) fprintf (stderr, "%02x", test_manual[i] & 0xFF);
      fprintf (stderr, "\n");
    }

  fprintf (stderr, "CFB encrypt %s\n", (ok ? "ok" : "err"));

  set_mode (AESDEV_IOCTL_SET_CFB_DECRYPT);
  write_block (test_result);
  usleep (100000);
  read_block (test_result);

  ok = 1;
  for (i = 0; i < 16; ++i)
    if (test_result[i] != test_block[i])
      ok = 0;
  fprintf (stderr, "CFB decrypt %s\n", (ok ? "ok" : "err"));
}

void
test_ofb ()
{
  char ok;
  int i;
  char test_result[17];
  char test_manual[17];

  set_mode (AESDEV_IOCTL_SET_OFB);

  write_block (test_block);
  usleep (100000);
  read_block (test_result);

  set_mode (AESDEV_IOCTL_SET_ECB_ENCRYPT);
  write_block (test_iv);
  usleep (100000);
  read_block (test_manual);
  for (i = 0; i < 16; ++i)
    test_manual[i] = test_manual[i] ^ test_block[i];

  ok = 1;
  for (i = 0; i < 16; ++i)
    if (test_result[i] != test_manual[i])
      ok = 0;

  //  for (i = 0; i < 16; ++i) fprintf (stderr, "%02x", test_result[i] & 0xFF);
  //  fprintf (stderr, "\n");
  //  for (i = 0; i < 16; ++i) fprintf (stderr, "%02x", test_manual[i] & 0xFF);
  //  fprintf (stderr, "\n");

  fprintf (stderr, "OFB encrypt %s\n", (ok ? "ok" : "err"));

  set_mode (AESDEV_IOCTL_SET_OFB);
  write_block (test_result);
  usleep (100000);
  read_block (test_result);

  ok = 1;
  for (i = 0; i < 16; ++i)
    if (test_result[i] != test_block[i])
      ok = 0;
  fprintf (stderr, "OFB decrypt %s\n", (ok ? "ok" : "err"));
}

void
test_ctr ()
{
  char ok;
  int i;
  char test_result[17];
  char test_manual[17];

  set_mode (AESDEV_IOCTL_SET_CTR);

  write_block (test_block);
  usleep (100000);
  read_block (test_result);

  set_mode (AESDEV_IOCTL_SET_ECB_ENCRYPT);
  write_block (test_iv);
  usleep (100000);
  read_block (test_manual);
  for (i = 0; i < 16; ++i)
    test_manual[i] = test_manual[i] ^ test_block[i];

  ok = 1;
  for (i = 0; i < 16; ++i)
    if (test_result[i] != test_manual[i])
      ok = 0;

  //  for (i = 0; i < 16; ++i) fprintf (stderr, "%02x", test_result[i] & 0xFF);
  //  fprintf (stderr, "\n");
  //  for (i = 0; i < 16; ++i) fprintf (stderr, "%02x", test_manual[i] & 0xFF);
  //  fprintf (stderr, "\n");

  fprintf (stderr, "CTR encrypt %s\n", (ok ? "ok" : "err"));

  set_mode (AESDEV_IOCTL_SET_CTR);
  write_block (test_result);
  usleep (100000);
  read_block (test_result);

  ok = 1;
  for (i = 0; i < 16; ++i)
    if (test_result[i] != test_block[i])
      ok = 0;
  fprintf (stderr, "CTR decrypt %s\n", (ok ? "ok" : "err"));
}

/*****************************************************************************/

int
main ()
{
  int i;

  open_file ();

  for (i = 0; i < 0x1000; ++i)
    {
      printf ("0x%04x/0x%04x\n", i, 0x1000);
      test_ecb ();
      test_cbc ();
      test_cfb ();
      test_ofb ();
      test_ctr ();
    }

  close (fd);

  return (EXIT_SUCCESS);
}

