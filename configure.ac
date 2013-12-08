AC_INIT([kzorp], m4_esyscmd([tr -d '\n' <VERSION]))
AC_CONFIG_SRCDIR([kernel-module/kzorp_core.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])
AM_SILENT_RULES([yes])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])


AC_PROG_INSTALL
AC_PROG_CC
AM_PROG_CC_C_O
AM_PATH_PYTHON
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_CHECK_HEADERS([linux/netfilter/x_tables.h], [],
	[AC_MSG_ERROR([You need to have linux/netfilter/x_tables.h, see INSTALL file for details])])
PKG_CHECK_MODULES([libxtables], [xtables >= 1.4.5])

xtlibdir="$(pkg-config --variable=xtlibdir xtables)"

AC_ARG_WITH([xtlibdir],
	AS_HELP_STRING([--with-xtlibdir=PATH],
	[Path where to install Xtables extensions [[autodetect]]]),
	[xtlibdir="$withval"])
AC_MSG_CHECKING([Xtables module directory])
AC_MSG_RESULT([$xtlibdir])

regular_CPPFLAGS="$CPPFLAGS -D_LARGEFILE_SOURCE=1 -D_LARGE_FILES -D_FILE_OFFSET_BITS=64 \
	-D_REENTRANT"
regular_CFLAGS="$CFLAGS -Wall -Waggregate-return -Wmissing-declarations \
	-Wmissing-prototypes -Wredundant-decls -Wshadow -Wstrict-prototypes \
	-Winline -pipe";

AC_SUBST([regular_CPPFLAGS])
AC_SUBST([regular_CFLAGS])
AC_SUBST([xtlibdir])
AC_SUBST([PACKAGE_VERSION])
AC_SUBST([PYTHON])
AC_CONFIG_FILES([Makefile
                 pylib/Makefile
                 pylib/kzorp/Makefile
                 pylib/kzorp/kzorp/Makefile
                 kernel-module/dkms.conf])
AC_OUTPUT
