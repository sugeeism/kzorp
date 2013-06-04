libtoolize -f --copy
aclocal
autoheader
automake --add-missing --force-missing --copy --foreign
autoconf
