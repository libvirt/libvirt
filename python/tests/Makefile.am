## Copyright (C) 2005-2011, 2013 Red Hat, Inc.
##
## This library is free software; you can redistribute it and/or
## modify it under the terms of the GNU Lesser General Public
## License as published by the Free Software Foundation; either
## version 2.1 of the License, or (at your option) any later version.
##
## This library is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## Lesser General Public License for more details.
##
## You should have received a copy of the GNU Lesser General Public
## License along with this library.  If not, see
## <http://www.gnu.org/licenses/>.

EXAMPLE_DIR = $(datadir)/doc/libvirt-python-$(VERSION)/examples

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
