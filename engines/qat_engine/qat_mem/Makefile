# set your module name here
# provide the following files
#
# MODULENAME.c	the driver
# MODULENAME.h  the include file
# MODULENAME_test.c	the driver test program
# MODULENAME_test.sh	the driver test script
#
MODULENAME 	:= qat_mem
### should not need to change stuff below ######################


KDIR		:= /lib/modules/$(shell uname -r)/build
#KDIR		:= /exports/linux-2.6.12.2/
PWD		:= $(shell pwd)

ifeq ($(shell uname -r|grep -c grsec-WR), 1)
AUTO_CONF=/lib/modules/$(shell uname -r)/build/include/generated/autoconf.h
else
AUTO_CONF=/usr/src/kernels/$(shell uname -r)/include/linux/autoconf.h
endif

ifdef KERNEL_SOURCE_ROOT
AUTO_CONF=$(KERNEL_SOURCE_ROOT)/include/linux/autoconf.h
KDIR=$(KERNEL_SOURCE_ROOT)
endif

CC		:= gcc -Wall -imacros $(AUTO_CONF)

ifeq ($(KERNELRELEASE),)
all:	$(MODULENAME)_test
all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
else
  obj-m	:= $(MODULENAME).o
endif

$(MODULENAME)_test: $(MODULENAME)_test.c
	$(CC) -g -o $(MODULENAME)_test $(MODULENAME)_test.c


load:
	insmod ./$(MODULENAME).ko

unload:
	rmmod $(MODULENAME)

test: all
	./$(MODULENAME)_test.sh

clean:
	rm -f *.o *.ko Modules.symvers *.mod.c .*.cmd $(MODULENAME)_test

