AC_INIT([kzorp], m4_esyscmd([tr -d '\n' <VERSION]))
AC_CONFIG_SRCDIR([net/netfilter/kzorp_core.c])
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

regular_CPPFLAGS="$CPPFLAGS -D_LARGEFILE_SOURCE=1 -D_LARGE_FILES -D_FILE_OFFSET_BITS=64 \
	-D_REENTRANT"
regular_CFLAGS="$CFLAGS -Wall -Waggregate-return -Wmissing-declarations \
	-Wmissing-prototypes -Wredundant-decls -Wshadow -Wstrict-prototypes \
	-Winline -pipe";

AC_SUBST([regular_CPPFLAGS])
AC_SUBST([regular_CFLAGS])
AC_SUBST([PACKAGE_VERSION])
AC_SUBST([PYTHON])
AC_CONFIG_FILES([Makefile
                 pylib/Makefile
                 pylib/kzorp/Makefile
                 pylib/kzorp/kzorp/Makefile
                 net/netfilter/dkms.conf])
AC_OUTPUT
