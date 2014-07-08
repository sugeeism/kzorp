KVERSION ?= $(shell uname -r)
KERNELRELEASE ?= $(KVERSION)
EXTRA_CFLAGS       = -I$(src)/../../include

kzorp-objs := kzorp_core.o kzorp_lookup.o kzorp_sockopt.o kzorp_netlink.o kzorp_ext.o
obj-m := kzorp.o
obj-m += xt_KZORP.o
obj-m += xt_service.o
obj-m += xt_zone.o

all: xt_KZORP.ko

xt_KZORP.ko:
	$(MAKE) -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

clean:
ifeq ($(wildcard /lib/modules/$(KVERSION)/build),) 
	rm -f .kzorp* Module.symvers *.ko *.mod.* modules.order *.o ../kzorp-dkms_0.1.0_all.deb && $(MAKE) KVERSION=$(KVERSION) -C tests theclean
else
	$(MAKE) -C /lib/modules/$(KVERSION)/build M=$(PWD) clean && $(MAKE) KVERSION=$(KVERSION) -C tests theclean
endif

distclean: clean

install:
