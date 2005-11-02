## Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_builddir)/include -I@srcdir@/include

EXTRA_DIST = libxen_sym.version

lib_LTLIBRARIES = libxen.la
libxen_la_LIBADD = 
libxen_la_LDFLAGS = -Wl,--version-script=$(srcdir)/libxen_sym.version \
                    -version-info @LIBXEN_VERSION_INFO@
libxen_la_SOURCES = libxen.c internal.h
