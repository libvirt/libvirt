## Copyright (C) 2005-2012 Red Hat, Inc.
## See COPYING.LIB for the License of this software

INCLUDES = -I$(top_builddir)/include -I$(top_srcdir)/include
LDADDS = $(STATIC_BINARIES) $(WARN_CFLAGS) $(top_builddir)/src/libvirt.la \
	$(COVERAGE_LDFLAGS)

noinst_PROGRAMS=suspend

suspend_SOURCES=suspend.c
suspend_LDFLAGS=
suspend_LDADD= $(LDADDS)
