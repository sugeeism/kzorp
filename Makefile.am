SUBDIRS = pylib daemon scripts tests
DIST_SUBDIRS = $(SUBDIRS) driver

DRIVER_SUBDIR = driver

all-driver:
	cd $(DRIVER_SUBDIR) && $(MAKE) $(AM_MAKEFLAGS) all
check-driver:
	cd $(DRIVER_SUBDIR) && $(MAKE) $(AM_MAKEFLAGS) test
clean-driver:
	cd $(DRIVER_SUBDIR) && $(MAKE) $(AM_MAKEFLAGS) clean
install-driver:
	cd $(DRIVER_SUBDIR) && $(MAKE) $(AM_MAKEFLAGS) install
uninstall-driver:
	cd $(DRIVER_SUBDIR) && $(MAKE) $(AM_MAKEFLAGS) uninstall
