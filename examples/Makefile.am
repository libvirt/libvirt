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

EXTRA_DIST = \
	lxcconvert/virt-lxc-convert \
	polkit/libvirt-acl.rules \
	$(wildcard $(srcdir)/systemtap/*.stp) \
	$(FILTERS) \
	$(wildcard $(srcdir)/xml/storage/*.xml) \
	$(wildcard $(srcdir)/xml/test/*.xml)

AM_CPPFLAGS = \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include \
	-I$(top_srcdir) \
	$(WARN_CFLAGS) \
	$(NULL)

LDADD = \
	$(STATIC_BINARIES) \
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
	dominfo/info1 \
	dommigrate/dommigrate \
	domsuspend/suspend \
	domtop/domtop \
	hellolibvirt/hellolibvirt \
	object-events/event-test \
	openauth/openauth \
	rename/rename \
	$(NULL)

noinst_PROGRAMS = \
	$(EXAMPLES) \
	$(NULL)

dominfo_info1_SOURCES = dominfo/info1.c
dommigrate_dommigrate_SOURCES = dommigrate/dommigrate.c
domsuspend_suspend_SOURCES = domsuspend/suspend.c
domtop_domtop_SOURCES = domtop/domtop.c
hellolibvirt_hellolibvirt_SOURCES = hellolibvirt/hellolibvirt.c

object_events_event_test_SOURCES = object-events/event-test.c

openauth_openauth_SOURCES = openauth/openauth.c
rename_rename_SOURCES = rename/rename.c

admin_list_servers_SOURCES = admin/list_servers.c
admin_list_clients_SOURCES = admin/list_clients.c
admin_threadpool_params_SOURCES = admin/threadpool_params.c
admin_client_limits_SOURCES = admin/client_limits.c
admin_client_info_SOURCES = admin/client_info.c
admin_client_close_SOURCES = admin/client_close.c
admin_logging_SOURCES = admin/logging.c

INSTALL_DATA_LOCAL =
UNINSTALL_LOCAL =

if WITH_NWFILTER
NWFILTER_DIR = "$(DESTDIR)$(sysconfdir)/libvirt/nwfilter"

install-nwfilter-local:
	$(MKDIR_P) "$(NWFILTER_DIR)"
	for f in $(FILTERS); do \
		$(INSTALL_DATA) $$f "$(NWFILTER_DIR)"; \
	done

uninstall-nwfilter-local::
	for f in $(FILTERS); do \
		rm -f "$(NWFILTER_DIR)/`basename $$f`"; \
	done
	-test -z "$(shell ls $(NWFILTER_DIR))" || rmdir $(NWFILTER_DIR)

INSTALL_DATA_LOCAL += install-nwfilter-local
UNINSTALL_LOCAL += uninstall-nwfilter-local
endif WITH_NWFILTER

examplesdir = $(docdir)/examples

install-data-local: $(INSTALL_DATA_LOCAL)
	$(mkinstalldirs) $(DESTDIR)$(examplesdir)
	for p in $(EXAMPLES); do \
		d=$$(dirname $$p); \
		$(mkinstalldirs) $(DESTDIR)$(examplesdir)/$$d; \
		$(INSTALL_DATA) $(srcdir)/$${p}.c $(DESTDIR)$(examplesdir)/$$d/; \
	done

uninstall-local: $(UNINSTALL_LOCAL)
	for p in $(EXAMPLES); do \
		rm -f $(DESTDIR)$(examplesdir)/$${p}.c; \
	done
