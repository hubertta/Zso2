KDIR ?= /lib/modules/`uname -r`/build
KDIR = /home/hubert/mim/zso/linux-3.13.3
CFLAGS += -Wall -m32
LDFLAGS += -Wall -m32

default: test1 test2
	$(MAKE) -C $(KDIR) M=$$PWD
	cp aesdev.ko ../../hshare/
	cp test1 test2 ../../hshare/

install:
	$(MAKE) -C $(KDIR) M=$$PWD modules_install

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean
