SUBDIRS = iptables pylib

ksrcdir = $(prefix)/src/kzorp-$(PACKAGE_VERSION)

ksrctestdir = $(ksrcdir)/tests

ksrcpytestdir = $(ksrcdir)/tests/pytests

ksrcincdir = $(ksrcdir)/include

ksrc_DATA = kernel-module/dkms.conf\
            kernel-module/kzorp_core.c\
            kernel-module/kzorp_ext.c\
            kernel-module/kzorp_lookup.c\
            kernel-module/kzorp_netlink.c\
            kernel-module/kzorp_sockopt.c\
            kernel-module/Makefile\
            kernel-module/README\
            kernel-module/xt_KZORP.c\
            kernel-module/xt_service.c\
            kernel-module/xt_zone.c

ksrcinc_DATA = kernel-module/include/kzorp.h\
               kernel-module/include/kzorp_internal.h\
               kernel-module/include/kzorp_lookup_internal.h\
               kernel-module/include/kzorp_netlink.h\
               kernel-module/include/kzorp_sockopt.h\
               kernel-module/include/xt_KZORP.h\
               kernel-module/include/xt_service.h\
               kernel-module/include/xt_zone.h

ksrctest_DATA = kernel-module/tests/100000rules_policy.py\
                kernel-module/tests/get_kzorp_result.c\
                kernel-module/tests/kzorp_rule_generator.py\
                kernel-module/tests/Makefile\
                kernel-module/tests/perf_measure.c\
                kernel-module/tests/policy.py\
                kernel-module/tests/rand-lfsr258.c\
                kernel-module/tests/rand-lfsr258.h\
                kernel-module/tests/sort.c\
                kernel-module/tests/test_ext.c\
                kernel-module/tests/test.h\
                kernel-module/tests/test_ipv6_radix.c\
                kernel-module/tests/test_kzorp_dump.sh\
                kernel-module/tests/test_kzorp_lookup.c\
                kernel-module/tests/test_kzorp_sockopt.py\
                kernel-module/tests/test_mocks.c\
                kernel-module/tests/test_ndim_eval.c


ksrcpytest_DATA = kernel-module/tests/pytests/__init__.py\
                  kernel-module/tests/pytests/KZorpBaseTestCaseBind.py\
                  kernel-module/tests/pytests/KZorpBaseTestCaseDispatchers.py\
                  kernel-module/tests/pytests/KZorpBaseTestCaseQuery.py\
                  kernel-module/tests/pytests/KZorpBaseTestCaseZones.py\
                  kernel-module/tests/pytests/KZorpComm.py\
                  kernel-module/tests/pytests/KZorpTestCaseDispatchers.py\
                  kernel-module/tests/pytests/KZorpTestCaseQueryNDim.py\
                  kernel-module/tests/pytests/KZorpTestCaseServices.py\
                  kernel-module/tests/pytests/KZorpTestCaseTransaction.py\
                  kernel-module/tests/pytests/KZorpTestCaseZones.py\
                  kernel-module/tests/pytests/testall.py\
                  kernel-module/tests/pytests/testutil.py
