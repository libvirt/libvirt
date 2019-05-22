## Process this file with automake to produce Makefile.in

## Copyright (C) 2005-2016 Red Hat, Inc.
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

FILTERS = $(wildcard $(srcdir)/xml/nwfilter/*.xml)

POLKIT_EXAMPLES = \
	$(wildcard $(srcdir)/polkit/*.rules) \
	$(NULL)

SH_EXAMPLES = \
	$(wildcard $(srcdir)/sh/*) \
	$(NULL)

STORAGE_XML_EXAMPLES = \
	$(wildcard $(srcdir)/xml/storage/*.xml) \
	$(NULL)

SYSTEMTAP_EXAMPLES = \
	$(wildcard $(srcdir)/systemtap/*.stp) \
	$(NULL)

TEST_XML_EXAMPLES = \
	$(wildcard $(srcdir)/xml/test/*.xml) \
	$(NULL)

EXTRA_DIST = \
	$(POLKIT_EXAMPLES) \
	$(SH_EXAMPLES) \
	$(STORAGE_XML_EXAMPLES) \
	$(SYSTEMTAP_EXAMPLES) \
	$(TEST_XML_EXAMPLES) \
	$(FILTERS) \
	$(NULL)

AM_CPPFLAGS = \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	$(WARN_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(STATIC_BINARIES) \
	$(NULL)

LDADD = \
	$(top_builddir)/src/libvirt.la \
	$(top_builddir)/src/libvirt-admin.la \
	$(NULL)

# List of example programs. We need to list them here instead of using
# $(noinst_PROGRAMS) directly because we want to have access to the
# unmodified list during (un)installation, but at the same time automake
# might tweak $(noinst_PROGRAMS) to eg. automatically add the .exe file
# extension when targeting Windows.
EXAMPLES = \
	admin/client_close \
	admin/client_info \
	admin/client_limits \
	admin/list_clients \
	admin/list_servers \
	admin/logging \
	admin/threadpool_params \
	domain/dommigrate \
	domain/domtop \
	domain/info1 \
	domain/rename \
	domain/suspend \
	misc/event-test \
	misc/hellolibvirt \
	misc/openauth \
	$(NULL)

noinst_PROGRAMS = \
	$(EXAMPLES) \
	$(NULL)

admin_client_close_SOURCES = admin/client_close.c
admin_client_info_SOURCES = admin/client_info.c
admin_client_limits_SOURCES = admin/client_limits.c
admin_list_clients_SOURCES = admin/list_clients.c
admin_list_servers_SOURCES = admin/list_servers.c
admin_logging_SOURCES = admin/logging.c
admin_threadpool_params_SOURCES = admin/threadpool_params.c
domain_dommigrate_SOURCES = domain/dommigrate.c
domain_domtop_SOURCES = domain/domtop.c
domain_info1_SOURCES = domain/info1.c
domain_rename_SOURCES = domain/rename.c
domain_suspend_SOURCES = domain/suspend.c
misc_event_test_SOURCES = misc/event-test.c
misc_hellolibvirt_SOURCES = misc/hellolibvirt.c
misc_openauth_SOURCES = misc/openauth.c

if WITH_NWFILTER

nwfilterdir = $(sysconfdir)/libvirt/nwfilter
nwfilter_DATA = $(FILTERS)

endif WITH_NWFILTER

examplesdir = $(docdir)/examples

polkitexamplesdir = $(examplesdir)/polkit
polkitexamples_DATA = $(POLKIT_EXAMPLES)

shexamplesdir = $(examplesdir)/sh
shexamples_DATA = $(SH_EXAMPLES)

storagexmlexamplesdir = $(examplesdir)/xml/storage
storagexmlexamples_DATA = $(STORAGE_XML_EXAMPLES)

systemtapexamplesdir = $(examplesdir)/systemtap
systemtapexamples_DATA = $(SYSTEMTAP_EXAMPLES)

testxmlexamplesdir = $(examplesdir)/xml/test
testxmlexamples_DATA = $(TEST_XML_EXAMPLES)

install-data-local:
	for p in $(EXAMPLES); do \
		d=$$(dirname $$p); \
		$(mkinstalldirs) $(DESTDIR)$(examplesdir)/$$d; \
		$(INSTALL_DATA) $(srcdir)/$${p}.c $(DESTDIR)$(examplesdir)/$$d/; \
	done

uninstall-local:
	for p in $(EXAMPLES); do \
		rm -f $(DESTDIR)$(examplesdir)/$${p}.c; \
	done
