KVERSION ?= $(shell uname -r)

test: testimgs/$(KVERSION)/initrd.img
	./imgtest $(KVERSION)

run: testimgs/$(KVERSION)/initrd.img
	./imgrun $(KVERSION)

image: testimgs/$(KVERSION)/initrd.img

testimgs/$(KVERSION)/initrd.img: 
	./imgsetup $(KVERSION)

clean: 
	echo $(KVERSION) ; rm -rf testimgs/*

