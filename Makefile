KDIR ?= /lib/modules/`uname -r`/build
KDIR = /home/hubert/mim/zso/linux-3.13.3
CFLAGS += -Wall -m32
LDFLAGS += -Wall -m32

default:
	$(MAKE) -C $(KDIR) M=$$PWD
	cp aesdev.ko ../../hshare/

install:
	$(MAKE) -C $(KDIR) M=$$PWD modules_install

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean
