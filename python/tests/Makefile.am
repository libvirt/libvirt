## Copyright (C) 2005-2011 Red Hat, Inc.
## See COPYING.LIB for the License of this software

EXAMPLE_DIR = $(datadir)/doc/libvirt-python-$(LIBVIRT_VERSION)/examples

PYTESTS=		\
	basic.py	\
	create.py	\
	uuid.py		\
	error.py	\
	node.py

EXTRA_DIST = $(PYTESTS)

if WITH_PYTHON
tests: $(PYTESTS)
	@echo "## running Python regression tests"
	-@(PYTHONPATH="..:../.libs:../src/.libs:$(srcdir)/../src:$$PYTHONPATH";\
	   export PYTHONPATH; \
	   LD_LIBRARY_PATH="$(top_builddir)/src/.libs:$$LD_LIBRARY_PATH" ; \
	   export LD_LIBRARY_PATH; \
	   for test in $(PYTESTS) ; \
	   do log=`$(PYTHON) $(srcdir)/$$test` ; \
	   if [ "`echo $$log | grep OK`" = "" ] ; then \
	   echo "-- $$test" ; echo "$$log" ; fi ; done)
else
tests:
endif

clean:
	rm -f *.pyc core

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(EXAMPLE_DIR)
	-(for test in $(PYTESTS); \
	  do $(INSTALL) -m 0644 $(srcdir)/$$test $(DESTDIR)$(EXAMPLE_DIR) ; done)

uninstall-local:
	for test in $(PYTESTS); do rm -f $(DESTDIR)$(EXAMPLE_DIR)/$$test; done
