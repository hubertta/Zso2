KDIR ?= /lib/modules/`uname -r`/build
CFLAGS += -Wall -m32 -g
LDFLAGS += -Wall -m32 -g

default:
	$(MAKE) -C $(KDIR) M=$$PWD

install:
	$(MAKE) -C $(KDIR) M=$$PWD modules_install

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean
