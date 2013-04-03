kzorp-objs := kzorp_core.o kzorp_lookup.o kzorp_sockopt.o kzorp_netlink.o kzorp_ext.o
obj-m := kzorp.o
obj-m += xt_KZORP.o
obj-m += xt_service.o
obj-m += xt_zone.o

all: testing notest
	echo "done"

notest:
	$(MAKE) -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(KVERSION)/build M=$(PWD) clean && $(MAKE) -C tests theclean

testing:
	$(MAKE) -C tests KVERSION=$(KVERSION) 

imgtest: testing notest
	$(MAKE) -C tests KVERSION=$(KVERSION) img_test
