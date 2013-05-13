srctree = /lib/modules/$(KVERSION)/build
KBUILD_SRC = $(srctree)

kzorp_tests: test_check perf
	echo done


test_check: test_ext test_ndim_eval test_ipv6_radix 
	@for i in $^ ; do gtester --keep-going --verbose $$i ; done

perf: test_kzorp_lookup
	@echo "Running test (use '--dump' to output test data)..."
	@./$^ && echo "################\n$^: PASSED\n################"

theclean: test_clean realclean
	echo cleaned

img_test: testimgs/$(KVERSION)/initrd.img
	./imgtest $(KVERSION)

img_run: testimgs/$(KVERSION)/initrd.img
	./imgrun $(KVERSION)

testimgs/$(KVERSION)/initrd.img: 
	./imgsetup $(KVERSION)

#kvm -m 2G -nographic -initrd /tmp/TESTROOT/initrd.img -kernel /boot/vmlinuz-3.2.35 -append console=ttyS0,115200 \
#	-net nic,vlan=0 -net user,vlan=0,net=11.22.33.0/24,guestfwd=tcp:11.22.33.1:1234-tcp:127.0.0.1:9999,hostfwd=tcp:127.0.0.1:10000-11.22.33.10:8888\
#	-net nic,vlan=1 -net user,vlan=1,net=44.55.66.0/24,guestfwd=tcp:44.55.66.253:8888-tcp:127.0.0.1:10001



include $(srctree)/Makefile




realclean:
	rm -rf arch scripts include arch kernel

# Test kzorp module:
FLAGS = -DKZ_USERSPACE -Wno-declaration-after-statement
CFLAGS = $(FLAGS) -D__KERNEL__ -DKBUILD_MODNAME=\"\" -O2 -fno-strict-aliasing -pipe -g -Wno-pointer-sign
CFLAGS += -I ../include -I$(srctree)/include -I$(srctree)/arch/$(hdr-arch)/include -I$(srctree)/arch/$(hdr-arch)/include/generated -include $(srctree)/include/linux/kconfig.h -I include
KBUILD_CFLAGS += $(FLAGS)

perf_measure.o: CFLAGS = -O2 -pipe -g
perf_measure.o: perf_measure.c
	$(CC) -Wall $< -c $(CFLAGS)

test_kzorp_lookup: rand-lfsr258.o perf_measure.o

.config: oldconfig
	bash -c 'PD=$${PWD%/*/*}/kernel ; cp $${PD/\/work\//\/build\/}/$@ ./'

test_clean:
	rm -rf *.o test_ipv6_radix test_ndim_eval test_kzorp_lookup include/config/ source test_ext testimgs

test_ndim_eval: test_ndim_eval.c test.h test_mocks.c kzorp_lookup.o sort.o
	$(CC) -Wall $(filter %.c %.o, $^) -o $@ $(CFLAGS) $(shell pkg-config glib-2.0 --libs --cflags)

test_ipv6_radix: test_ipv6_radix.c test.h test_mocks.c kzorp_lookup.o sort.o
	$(CC) -Wall $(filter %.c %.o, $^) -o $@ $(CFLAGS) $(shell pkg-config glib-2.0 --libs --cflags)

test_ext: test_ext.c test.h test_mocks.c kzorp_ext.o sort.o
	$(CC) -Wall $(filter %.c %.o, $^) -o $@ $(CFLAGS) $(shell pkg-config glib-2.0 --libs --cflags)

test_kzorp_lookup: test_kzorp_lookup.c test.h test_mocks.c kzorp_lookup.o sort.o
	$(CC) -Wall $(filter %.c %.o, $^) -o $@ $(CFLAGS) $(shell pkg-config glib-2.0 --libs --cflags)

kzorp_lookup.o: ../kzorp_lookup.c
	$(CC) -Wall -c $(filter %.c %.o, $^) -o $@ $(CFLAGS) $(shell pkg-config glib-2.0 --libs --cflags)

kzorp_ext.o: ../kzorp_ext.c
	$(CC) -Wall -c $(filter %.c %.o, $^) -o $@ $(CFLAGS) $(shell pkg-config glib-2.0 --libs --cflags)

sort.o: sort.c
	$(CC) -Wall -c $(filter %.c %.o, $^) -o $@ $(CFLAGS) $(shell pkg-config glib-2.0 --libs --cflags)

rand-lfsr258.o: rand-lfsr258.c
	$(CC) -Wall -c $(filter %.c %.o, $^) -o $@ $(CFLAGS) $(shell pkg-config glib-2.0 --libs --cflags)

perf_measure.o: perf_measure.c
	$(CC) -Wall -c $(filter %.c %.o, $^) -o $@ $(CFLAGS) $(shell pkg-config glib-2.0 --libs --cflags)

