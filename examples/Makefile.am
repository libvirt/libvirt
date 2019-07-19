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

ADMIN_EXAMPLES = \
	$(wildcard $(srcdir)/c/admin/*.c) \
	$(NULL)

DOMAIN_EXAMPLES = \
	$(wildcard $(srcdir)/c/domain/*.c) \
	$(NULL)

MISC_EXAMPLES = \
	$(wildcard $(srcdir)/c/misc/*.c) \
	$(NULL)

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

noinst_PROGRAMS = \
	c/admin/client_close \
	c/admin/client_info \
	c/admin/client_limits \
	c/admin/list_clients \
	c/admin/list_servers \
	c/admin/logging \
	c/admin/threadpool_params \
	c/domain/dommigrate \
	c/domain/domtop \
	c/domain/info1 \
	c/domain/rename \
	c/domain/suspend \
	c/misc/event-test \
	c/misc/hellolibvirt \
	c/misc/openauth \
	$(NULL)

c_admin_client_close_SOURCES = c/admin/client_close.c
c_admin_client_info_SOURCES = c/admin/client_info.c
c_admin_client_limits_SOURCES = c/admin/client_limits.c
c_admin_list_clients_SOURCES = c/admin/list_clients.c
c_admin_list_servers_SOURCES = c/admin/list_servers.c
c_admin_logging_SOURCES = c/admin/logging.c
c_admin_threadpool_params_SOURCES = c/admin/threadpool_params.c
c_domain_dommigrate_SOURCES = c/domain/dommigrate.c
c_domain_domtop_SOURCES = c/domain/domtop.c
c_domain_info1_SOURCES = c/domain/info1.c
c_domain_rename_SOURCES = c/domain/rename.c
c_domain_suspend_SOURCES = c/domain/suspend.c
c_misc_event_test_SOURCES = c/misc/event-test.c
c_misc_hellolibvirt_SOURCES = c/misc/hellolibvirt.c
c_misc_openauth_SOURCES = c/misc/openauth.c

examplesdir = $(docdir)/examples

adminexamplesdir = $(examplesdir)/c/admin
adminexamples_DATA = $(ADMIN_EXAMPLES)

domainexamplesdir = $(examplesdir)/c/domain
domainexamples_DATA = $(DOMAIN_EXAMPLES)

miscexamplesdir = $(examplesdir)/c/misc
miscexamples_DATA = $(MISC_EXAMPLES)

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
