## Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_builddir)/include -I@srcdir@/include
DEPS = libxen.la
LDADDS = libxen.la

EXTRA_DIST = libxen_sym.version

lib_LTLIBRARIES = libxen.la
libxen_la_LIBADD = 
libxen_la_LDFLAGS = -Wl,--version-script=$(srcdir)/libxen_sym.version \
                    -version-info @LIBXEN_VERSION_INFO@
libxen_la_SOURCES = libxen.c internal.h hash.c hash.h

noinst_PROGRAMS=xensh

xensh_SOURCES=xensh.c
xensh_LDFLAGS =
xensh_DEPENDENCIES = $(DEPS)
xensh_LDADD= $(LDADDS)

