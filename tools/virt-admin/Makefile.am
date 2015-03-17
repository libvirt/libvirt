## Copyright (C) 2015 Red Hat, Inc.
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

AM_CPPFLAGS = \
	-I$(top_builddir)/include -I$(top_srcdir)/include	\
	-I$(top_builddir)/gnulib/lib -I$(top_srcdir)/gnulib/lib	\
	-I$(top_builddir)/src -I$(top_srcdir)/src		\
	-I$(top_srcdir)/src/util				\
	-I$(top_srcdir)						\
	$(GETTEXT_CPPFLAGS)

AM_LDFLAGS = \
	$(RELRO_LDFLAGS)					\
	$(NO_INDIRECT_LDFLAGS)					\
	$(NULL)

POD2MAN = pod2man -c "Virtualization Support" -r "$(PACKAGE)-$(VERSION)"

EXTRA_DIST = virt-admin.pod

DISTCLEANFILES =

bin_PROGRAMS = virt-admin

dist_man1_MANS = virt-admin.1

virt_admin_SOURCES = virt-admin.c

virt_admin_LDFLAGS = \
		$(AM_LDFLAGS) 					\
		$(COVERAGE_LDFLAGS)				\
		$(NULL)

virt_admin_LDADD =						\
		$(STATIC_BINARIES)				\
		$(PIE_LDFLAGS)					\
		../../src/libvirt-admin.la			\
		$(top_srcdir)/gnulib/lib/libgnu.la		\
		$(VIRT_ADMIN_LIBS)				\
		$(NULL)

virt_admin_CFLAGS =						\
		$(WARN_CFLAGS)					\
		$(PIE_CFLAGS)					\
		$(COVERAGE_CFLAGS)				\
		$(LIBXML_CFLAGS)				\
		$(READLINE_CFLAGS)				\
		$(NULL)

virt-admin.1: virt-admin.pod $(top_srcdir)/configure.ac
	$(AM_V_GEN)$(POD2MAN) $< $(srcdir)/$@ \
	    && if grep 'POD ERROR' $(srcdir)/$@ ; then \
		rm $(srcdir)/$@; exit 1; fi

CLEANFILES = *.gcov .libs/*.gcda .libs/*.gcno *.gcno *.gcda
MAINTAINERCLEANFILES = $(dist_man1_MANS)
