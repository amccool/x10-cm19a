# Copyright (C) 2005 Michael LeMay
# All rights reserved

VERSION = 0.01
ADD_CPPFLAGS = -DMVERSION="\"$(VERSION)\""

.PHONY: all

ifneq ($(KERNELRELEASE),)   # Invoked by kbuild, symbols defined
EXTRA_CFLAGS = $(ADD_CPPFLAGS)
obj-m += x10-cm19a.o
x10-cm19a-objs := drivers/usb/comm/x10-cm19a.o

else   # Direct make invocation

KERNEL_VERSION = `uname -r`
KERNELDIR := /lib/modules/$(KERNEL_VERSION)/build
PWD  := $(shell pwd)
MODULE_INSTALLDIR = /lib/modules/$(KERNEL_VERSION)/kernel/drivers/usb/comm/

# Kernel v.2.4.x not supported
ifeq ($(shell uname -r | cut -d. -f1,2), 2.4)

all:
	@echo "Sorry, kernel v.2.4.x not supported."
	@exit 1

else

all:
	@echo 'Building X10-CM19A for 2.5/2.6 kernel...'
	@echo '   (make sure you have write access to your kernel source tree)'
	$(MAKE) -C $(KERNELDIR) SUBDIRS=$(PWD) modules

endif

install:
	mkdir -p $(MODULE_INSTALLDIR)
	install -c -m 0644 x10-cm19a.ko $(MODULE_INSTALLDIR)
	/sbin/depmod -ae

uninstall:
	rm -f $(MODULE_INSTALLDIR)/x10-cm19a.ko
	/sbin/depmod -aq

endif

##############################################################################
# OTHER TARGETS
##############################################################################
clean:
	rm -r -f drivers/usb/comm/*.o drivers/usb/comm/.x10-cm19a.o.cmd  *.o *.ko *.mod.* core *.i .x10* .tmp* Module.symvers modules.order

##############################################################################
