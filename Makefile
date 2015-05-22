KDIR ?= /lib/modules/`uname -r`/build
KDIR = /home/hubert/mim/zso/linux-3.13.3
CFLAGS += -Wall -m32
LDFLAGS += -Wall -m32

default: test1 test2 test3 test4 test5 test6
	$(MAKE) -C $(KDIR) M=$$PWD
	cp aesdev.ko ../../hshare/
	cp test1 test2 test3 test4 test5 test6 ../../hshare/
	cp test1.c test2.c test3.c test4.c test5.c test6.c ../../hshare
	
test4: test4.o
	$(CC) $(LDFLAGS) $< -pthread -o $@
	
test5: test5.o
	$(CC) $(LDFLAGS) $< -pthread -o $@

install:
	$(MAKE) -C $(KDIR) M=$$PWD modules_install

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean
