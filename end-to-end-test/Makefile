KVERSION ?= $(shell uname -r)

test: testimgs/$(KVERSION)/initrd.img
	./imgtest $(KVERSION)

run: testimgs/$(KVERSION)/initrd.img
	./imgrun $(KVERSION)

image: testimgs/$(KVERSION)/initrd.img

testimgs/$(KVERSION)/initrd.img: ../kernel-module/xt_KZORP.ko ../iptables/src/.libs/libxt_KZORP.so /boot/System.map-$(KVERSION)
	./imgsetup $(KVERSION)

../iptables/src/.libs/libxt_KZORP.so:
	(cd .. && [ ! -f Makefile ] || $(MAKE) iptables-module-make)

../kernel-module/xt_KZORP.ko:
	(cd ../kernel-module  && [ ! -f Makefile ] || $(MAKE) KVERSION=$(KVERSION))

clean: 
	echo $(KVERSION) ; rm -rf testimgs/*

