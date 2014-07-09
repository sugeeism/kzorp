# By default, we try to compile the modules for the currently running
# kernel.  But it's the first approximation, as we will re-read the
# version from the kernel sources.
ifeq (,$(KERNELRELEASE))
KVERS_UNAME ?= $(shell uname -r)
else
KVERS_UNAME ?= $(KERNELRELEASE)
endif

# KBUILD is the path to the Linux kernel build tree.  It is usually the
# same as the kernel source tree, except when the kernel was compiled in
# a separate directory.
KBUILD ?= $(shell readlink -f /lib/modules/$(KVERS_UNAME)/build)

ifeq (,$(KBUILD))
$(error Kernel build tree not found - please set KBUILD to configured kernel)
endif

KCONFIG := $(KBUILD)/.config
ifeq (,$(wildcard $(KCONFIG)))
$(error No .config found in $(KBUILD), please set KBUILD to configured kernel)
endif

ifneq (,$(wildcard $(KBUILD)/include/linux/version.h))
ifneq (,$(wildcard $(KBUILD)/include/generated/uapi/linux/version.h))
$(error Multiple copies of version.h found, please clean your build tree)
endif
endif

# Kernel Makefile doesn't always know the exact kernel version, so we
# get it from the kernel headers instead and pass it to make.
VERSION_H := $(KBUILD)/include/generated/utsrelease.h
ifeq (,$(wildcard $(VERSION_H)))
VERSION_H := $(KBUILD)/include/linux/utsrelease.h
endif
ifeq (,$(wildcard $(VERSION_H)))
VERSION_H := $(KBUILD)/include/linux/version.h
endif
ifeq (,$(wildcard $(VERSION_H)))
$(error Please run 'make modules_prepare' in $(KBUILD))
endif

KVERS := $(shell sed -ne 's/"//g;s/^\#define UTS_RELEASE //p' $(VERSION_H))

ifeq (,$(KVERS))
$(error Cannot find UTS_RELEASE in $(VERSION_H), please report)
endif

INST_DIR = /lib/modules/$(KVERS)/kernel/net/netfilter

SRC_DIR=$(shell pwd)

include $(KCONFIG)

EXTRA_CFLAGS += -I$(src)/../../include

MODULE_NAMES = kzorp xt_KZORP xt_service xt_zone

obj-m := kzorp.o xt_KZORP.o xt_service.o xt_zone.o
kzorp-y := kzorp_core.o kzorp_lookup.o kzorp_sockopt.o kzorp_netlink.o kzorp_ext.o

all: modules

modules:
	$(MAKE) -C $(KBUILD) M=$(SRC_DIR)

clean:
	rm -f *.o *.ko .*.cmd *.mod.c *.symvers modules.order *~ .\#*
	rm -rf .tmp_versions

install: modules
	@for module in $(MODULE_NAMES); do \
		/sbin/modinfo $$module.ko | grep -q "^vermagic: *$(KVERS) " || \
			{ echo "$$module" is not for Linux $(KVERS); exit 1; }; \
	done
	mkdir -p -m 755 $(DESTDIR)$(INST_DIR)
	@for module in $(MODULE_NAMES); do \
		install -m 0644 $$module.ko $(DESTDIR)$(INST_DIR); \
	done
ifndef DESTDIR
	-/sbin/depmod -a $(KVERS)
endif

uninstall:
	@for module in $(MODULE_NAMES); do \
		rm -f $(DESTDIR)$(INST_DIR)/$$module.ko; \
	done
ifndef DESTDIR
	-/sbin/depmod -a $(KVERS)
endif

dist:
	@for file in $(DISTFILES); do \
		cp $$file $(distdir)/$$file || exit 1; \
	done

.PHONY: all modules clean install dist
