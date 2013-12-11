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

INCLUDES = -I$(top_builddir)/include -I$(top_srcdir)/include \
	   -I$(top_builddir)/gnulib/lib -I$(top_srcdir)/gnulib/lib \
	   -I$(top_srcdir)
noinst_PROGRAMS = event-test
event_test_CFLAGS = $(WARN_CFLAGS)
event_test_SOURCES = event-test.c
event_test_LDADD = $(top_builddir)/src/libvirt.la \
		 $(top_builddir)/gnulib/lib/libgnu.la
