## Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_builddir)/include -I@srcdir@/include
DEPS = libvir.la
LDADDS = @STATIC_BINARIES@ libvir.la

EXTRA_DIST = libvir_sym.version

lib_LTLIBRARIES = libvir.la
libvir_la_LIBADD = 
libvir_la_LDFLAGS = -Wl,--version-script=$(srcdir)/libvir_sym.version \
                    -version-info @LIBXEN_VERSION_INFO@
libvir_la_SOURCES = libvir.c internal.h hash.c hash.h

noinst_PROGRAMS=virsh

virsh_SOURCES=virsh.c
virsh_LDFLAGS =
virsh_DEPENDENCIES = $(DEPS)
virsh_LDADD= $(LDADDS)

