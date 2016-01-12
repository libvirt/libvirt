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
	apparmor/TEMPLATE.qemu \
	apparmor/TEMPLATE.lxc \
	apparmor/libvirt-qemu \
	apparmor/libvirt-lxc \
	apparmor/usr.lib.libvirt.virt-aa-helper \
	apparmor/usr.sbin.libvirtd \
	lxcconvert/virt-lxc-convert \
	polkit/libvirt-acl.rules \
	systemtap/events.stp \
	systemtap/rpc-monitor.stp \
	$(FILTERS) \
	$(wildcard $(srcdir)/xml/storage/*.xml) \
	$(wildcard $(srcdir)/xml/test/*.xml)


INCLUDES = -I$(top_builddir)/include -I$(top_srcdir)/include -I$(top_srcdir) \
	-I$(top_builddir)/gnulib/lib -I$(top_srcdir)/gnulib/lib
LDADD = $(STATIC_BINARIES) $(WARN_CFLAGS) $(COVERAGE_LDFLAGS) \
	$(top_builddir)/src/libvirt.la $(top_builddir)/gnulib/lib/libgnu.la

noinst_PROGRAMS=dominfo/info1 dommigrate/dommigrate domsuspend/suspend \
	domtop/domtop hellolibvirt/hellolibvirt object-events/event-test \
	openauth/openauth rename/rename

dominfo_info1_SOURCES = dominfo/info1.c
dommigrate_dommigrate_SOURCES = dommigrate/dommigrate.c
domsuspend_suspend_SOURCES = domsuspend/suspend.c
domtop_domtop_SOURCES = domtop/domtop.c
hellolibvirt_hellolibvirt_SOURCES = hellolibvirt/hellolibvirt.c
object_events_event_test_SOURCES = object-events/event-test.c
openauth_openauth_SOURCES = openauth/openauth.c
rename_rename_SOURCES = rename/rename.c

if WITH_APPARMOR_PROFILES
apparmordir = $(sysconfdir)/apparmor.d/
apparmor_DATA = \
	apparmor/usr.lib.libvirt.virt-aa-helper \
	apparmor/usr.sbin.libvirtd \
	$(NULL)

abstractionsdir = $(apparmordir)/abstractions
abstractions_DATA = \
	apparmor/libvirt-qemu \
	apparmor/libvirt-lxc \
	$(NULL)

templatesdir = $(apparmordir)/libvirt
templates_DATA = \
	apparmor/TEMPLATE.qemu \
	apparmor/TEMPLATE.lxc \
	$(NULL)
endif WITH_APPARMOR_PROFILES

if WITH_NWFILTER
NWFILTER_DIR = "$(DESTDIR)$(sysconfdir)/libvirt/nwfilter"

install-data-local:
	$(MKDIR_P) "$(NWFILTER_DIR)"
	for f in $(FILTERS); do \
		$(INSTALL_DATA) $$f "$(NWFILTER_DIR)"; \
	done

uninstall-local::
	for f in $(FILTERS); do \
		rm -f "$(NWFILTER_DIR)/`basename $$f`"; \
	done
	-test -z $(shell ls $(NWFILTER_DIR)) || rmdir $(NWFILTER_DIR)
endif WITH_NWFILTER
