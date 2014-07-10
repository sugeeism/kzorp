AC_INIT([kzorp], m4_esyscmd([tr -d '\n' < VERSION]))
AC_CONFIG_SRCDIR([driver/kzorp_core.c])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])
AM_SILENT_RULES([yes])

AC_PROG_INSTALL
AC_PROG_CC
AM_PROG_CC_C_O
AM_PATH_PYTHON
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

KZORP_PYTHON_DIR="${pythondir}/kzorp"
ZORP_PYTHON_DIR="${pythondir}/Zorp"

AC_SUBST([PYTHON])
AC_SUBST(KZORP_PYTHON_DIR)
AC_SUBST(ZORP_PYTHON_DIR)

AC_CONFIG_FILES([
Makefile
kzorp/Makefile
kzorp/include/Makefile
kzorp/include/linux/Makefile
kzorp/include/linux/netfilter/Makefile
kzorp/include/net/Makefile
kzorp/include/net/netfilter/Makefile
kzorp/net/Makefile
scripts/Makefile
pylib/Makefile
pylib/kzorp/Makefile
pylib/Zorp/Makefile
tests/Makefile
tests/communication/Makefile
tests/query/Makefile
driver/net/netfilter/dkms.conf
])
AC_OUTPUT
