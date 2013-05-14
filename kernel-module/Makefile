KVERSION ?= $(shell uname -r)
KERNELRELEASE ?= $(KVERSION)

kzorp-objs := kzorp_core.o kzorp_lookup.o kzorp_sockopt.o kzorp_netlink.o kzorp_ext.o
obj-m := kzorp.o
obj-m += xt_KZORP.o
obj-m += xt_service.o
obj-m += xt_zone.o

all: tests/kzorp_ext.o xt_KZORP.ko
	echo "done"

notest: xt_KZORP.ko

xt_KZORP.ko:
	$(MAKE) -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(KVERSION)/build M=$(PWD) clean && $(MAKE) KVERSION=$(KVERSION) -C tests theclean

testing: tests/kzorp_ext.o

tests/kzorp_ext.o:
	$(MAKE) -C tests KVERSION=$(KVERSION) 

imgtest: tests/kzorp_ext.o xt_KZORP.ko
	$(MAKE) -C tests KVERSION=$(KVERSION) img_test

imgrun: tests/kzorp_ext.o xt_KZORP.ko
	$(MAKE) -C tests KVERSION=$(KVERSION) img_run
