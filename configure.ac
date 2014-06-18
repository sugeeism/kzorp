AC_INIT([kzorp], m4_esyscmd([tr -d '\n' < VERSION]))
AC_CONFIG_SRCDIR([net/netfilter/kzorp_core.c])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])
AM_SILENT_RULES([yes])

AC_PROG_INSTALL
AC_PROG_CC
AM_PROG_CC_C_O
AM_PATH_PYTHON
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_SUBST([PYTHON])

AC_CONFIG_FILES([
Makefile
pylib/Makefile
pylib/kzorp/Makefile
pylib/kzorp/kzorp/Makefile
net/netfilter/dkms.conf
])
AC_OUTPUT
