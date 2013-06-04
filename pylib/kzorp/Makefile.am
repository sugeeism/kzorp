EXTRA_DIST = setup.py
SUBDIRS = kzorp

clean-local:
	python $(top_srcdir)/pylib/kzorp/setup.py clean --all
#	$(PYTHON) $(top_srcdir)/pylib/kzorp/setup.py clean --all

install-exec-local:
	python $(top_srcdir)/pylib/kzorp/setup.py install --prefix $(DESTDIR)/$(prefix) --install-layout=deb
#	$(PYTHON) $(top_srcdir)/pylib/kzorp/setup.py install --prefix $(DESTDIR)/$(prefix) --install-layout=deb
