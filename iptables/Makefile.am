# -*- Makefile -*-

AM_CPPFLAGS	= ${regular_CPPFLAGS} -I$(top_srcdir)/iptables/src/include
AM_CFLAGS	= ${regular_CFLAGS} ${libxtables_CFLAGS}
AM_LDFLAGS	= -module -avoid-version

pkgdir			= ${xtlibdir}
pkg_LTLIBRARIES	= src/libxt_ifgroup.la \
		  src/libxt_KZORP.la \
		  src/libxt_service.la \
		  src/libxt_zone.la

EXTRA_DIST	= src/libxt_ifgroup.man \
		  src/libxt_KZORP.man \
		  src/libxt_service.man \
		  src/libxt_zone.man
