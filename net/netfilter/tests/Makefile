KVERSION ?= $(shell uname -r)
KERNELRELEASE ?= $(KVERSION)

srctree = /lib/modules/$(KVERSION)/build
commontree = /lib/modules/$(KVERSION)/source

kzorp_tests: test_check perf
	echo done

ext: test_ext
	$(TESTER) --verbose test_ext

test_check: test_ext test_ndim_eval test_ipv6_radix 
	set -e;for i in $^ ; do $(TESTER) --verbose $$i ; done

perf: test_kzorp_lookup
	@echo "Running test (use '--dump' to output test data)..."
	@$(TESTER) ./$^ && echo "################\n$^: PASSED\n################"

theclean: test_clean realclean
	echo cleaned

ifeq ($(wildcard $(commontree)),) 
ifeq ($(wildcard $(srctree)),) 
    $(warning "no kernel source, only 'make clean' makes sense")
else
    KBUILD_SRC = $(srctree)
    include $(srctree)/Makefile
endif
else
  KBUILD_SRC = $(commontree)
  include $(commontree)/Makefile
  srctree = /lib/modules/$(KVERSION)/build
  DEPENDENT_FLAGS = -I $(commontree)/include -I $(commontree)/arch/$(hdr-arch)/include
endif

realclean:
	rm -rf arch scripts include arch kernel

# Test kzorp module:
FLAGS = -DKZ_USERSPACE -Wno-declaration-after-statement
ifeq ($(wildcard $(srctree)/include/linux/version.h),) 
CC = echo
TESTER = echo
FLAGS += -include $(srctree)/include/generated/uapi/linux/version.h
else
TESTER = gtester
FLAGS += -include $(srctree)/include/linux/version.h
endif
FLAGS += -include test_mocks.h
CFLAGS = $(FLAGS) -D__KERNEL__ -DKBUILD_MODNAME=\"\" -O2 -fno-strict-aliasing -pipe -g -Wno-pointer-sign
CFLAGS += $(DEPENDENT_FLAGS)
CFLAGS += -I../../../include
ifeq ($(wildcard $(srctree)/include/linux/kconfig.h),) 
  CFLAGS += -include $(commontree)/include/linux/kconfig.h
else 
  CFLAGS += -include $(srctree)/include/linux/kconfig.h
endif
CFLAGS += -I ../include -I$(srctree)/include -I$(srctree)/arch/$(hdr-arch)/include -I$(srctree)/arch/$(hdr-arch)/include/generated
KBUILD_CFLAGS += $(FLAGS)

perf_measure.o: CFLAGS = -O2 -pipe -g
perf_measure.o: perf_measure.c
	$(CC) -Wall $< -c $(CFLAGS)

test_kzorp_lookup: perf_measure.o

.config: oldconfig
	bash -c 'PD=$${PWD%/*/*}/kernel ; cp $${PD/\/work\//\/build\/}/$@ ./'

test_clean:
	rm -rf *.o test_ipv6_radix test_ndim_eval test_kzorp_lookup include/config/ source test_ext testimgs pytests/KZorpBaseTestCaseBind.pyc pytests/KZorpBaseTestCaseDispatchers.pyc pytests/KZorpBaseTestCaseQuery.pyc pytests/KZorpBaseTestCaseZones.pyc pytests/KZorpComm.pyc pytests/KZorpTestCaseDispatchers.pyc pytests/KZorpTestCaseQueryNDim.pyc pytests/KZorpTestCaseServices.pyc pytests/KZorpTestCaseTransaction.pyc pytests/KZorpTestCaseZones.pyc pytests/testutil.pyc

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

perf_measure.o: perf_measure.c
	$(CC) -Wall -c $(filter %.c %.o, $^) -o $@ $(CFLAGS) $(shell pkg-config glib-2.0 --libs --cflags)

