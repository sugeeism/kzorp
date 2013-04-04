EXTRA_DIST = setup.py
SUBDIRS = kzorp

clean:
	$(PYTHON) $(top_srcdir)/pylib/kzorp/setup.py clean --all

distclean: clean

install-exec-local:
	$(PYTHON) $(top_srcdir)/pylib/kzorp/setup.py install --prefix $(DESTDIR)/$(prefix) --install-layout=deb

