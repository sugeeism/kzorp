EXTRA_DIST = setup.py
SUBDIRS = kzorp

bin_SCRIPTS = kzorp.py

install-exec-hook:
	cd $(DESTDIR)$(bindir) && \
	mv kzorp.py kzorp

clean-local:
	$(PYTHON) $(top_srcdir)/pylib/kzorp/setup.py clean --all

install-exec-local:
	$(PYTHON) $(top_srcdir)/pylib/kzorp/setup.py install --prefix $(DESTDIR)/$(prefix) --install-layout=deb
