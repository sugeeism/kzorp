SUBDIRS = pylib scripts

kprefix = $(prefix)/src/kzorp-$(PACKAGE_VERSION)

ksrcdir = $(kprefix)/net/netfilter

ksrctestdir = $(ksrcdir)/tests

ksrcpytestdir = $(ksrcdir)/tests/pytests

ksrcincdir = $(kprefix)/

ksrc_DATA = net/netfilter/dkms.conf\
            net/netfilter/kzorp_core.c\
            net/netfilter/kzorp_ext.c\
            net/netfilter/kzorp_lookup.c\
            net/netfilter/kzorp_netlink.c\
            net/netfilter/kzorp_sockopt.c\
            net/netfilter/Makefile\
            net/netfilter/README\
            net/netfilter/xt_KZORP.c\
            net/netfilter/xt_service.c\
            net/netfilter/xt_zone.c

nobase_ksrcinc_DATA = include/linux/netfilter/kzorp.h\
            include/linux/netfilter/kzorp_netlink.h\
            include/linux/netfilter/xt_service.h\
            include/linux/netfilter/xt_zone.h\
            include/linux/netfilter/kzorp_sockopt.h\
            include/linux/netfilter/xt_KZORP.h\
            include/net/netfilter/kzorp_internal.h\
            include/net/netfilter/kzorp_lookup_internal.h\
            include/net/netfilter/kzorp_compat.h

ksrctest_DATA = net/netfilter/tests/100000rules_policy.py\
                net/netfilter/tests/get_kzorp_result.c\
                net/netfilter/tests/kzorp_rule_generator.py\
                net/netfilter/tests/Makefile\
                net/netfilter/tests/perf_measure.c\
                net/netfilter/tests/policy.py\
                net/netfilter/tests/sort.c\
                net/netfilter/tests/test_ext.c\
                net/netfilter/tests/test.h\
                net/netfilter/tests/test_ipv6_radix.c\
                net/netfilter/tests/test_kzorp_dump.sh\
                net/netfilter/tests/test_kzorp_lookup.c\
                net/netfilter/tests/test_kzorp_sockopt.py\
                net/netfilter/tests/test_mocks.c\
                net/netfilter/tests/test_mocks.h\
                net/netfilter/tests/test_ndim_eval.c


ksrcpytest_DATA = net/netfilter/tests/pytests/__init__.py\
                  net/netfilter/tests/pytests/KZorpBaseTestCaseBind.py\
                  net/netfilter/tests/pytests/KZorpBaseTestCaseDispatchers.py\
                  net/netfilter/tests/pytests/KZorpBaseTestCaseQuery.py\
                  net/netfilter/tests/pytests/KZorpBaseTestCaseZones.py\
                  net/netfilter/tests/pytests/KZorpComm.py\
                  net/netfilter/tests/pytests/KZorpTestCaseDispatchers.py\
                  net/netfilter/tests/pytests/KZorpTestCaseQueryNDim.py\
                  net/netfilter/tests/pytests/KZorpTestCaseServices.py\
                  net/netfilter/tests/pytests/KZorpTestCaseTransaction.py\
                  net/netfilter/tests/pytests/KZorpTestCaseZones.py\
                  net/netfilter/tests/pytests/testall.py\
                  net/netfilter/tests/pytests/testutil.py

clean-local:
	(cd net/netfilter && [ ! -f Makefile ] || $(MAKE) clean)
	(cd end-to-end-test  && [ ! -f Makefile ] || $(MAKE) clean)

distclean-local:
	-rm -rf Makefile.in aclocal.m4 build-aux/ config.h.in configure debian/files debian/kzorp-dkms.debhelper.log debian/kzorp-dkms.postinst.debhelper debian/kzorp-dkms.prerm.debhelper debian/kzorp-dkms.substvars debian/kzorp-dkms/ debian/kzorp.debhelper.log debian/kzorp.postinst.debhelper debian/kzorp.prerm.debhelper debian/kzorp.substvars debian/kzorp/ end-to-end-test/iptables.zones

imgtest:
	(cd end-to-end-test && [ ! -f Makefile ] || $(MAKE))

install-exec-local:
	mkdir -p $(DESTDIR)$(kprefix);cp net/netfilter/proxy-Makefile $(DESTDIR)$(kprefix)/Makefile
