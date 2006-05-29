## Process this file with automake to produce Makefile.in

LIBVIRT = $(top_builddir)/src/.libs/libvirt.a

INCLUDES = \
	-I$(top_builddir)/include \
	-I$(top_builddir)/src \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/src \
	@LIBXML_CFLAGS@

LDADDS = \
	@STATIC_BINARIES@ \
	@LIBXML_LIBS@ \
	$(LIBVIRT)

EXTRA_DIST = xmlrpcserver.py

noinst_PROGRAMS = xmlrpctest

# Note: xmlrpc.[c|h] is not in libvirt yet
xmlrpctest_SOURCES = \
	xmlrpctest.c \
	testutils.c testutils.h \
	$(top_builddir)/src/xmlrpc.c \
	$(top_builddir)/src/xmlrpc.h

xmlrpctest_LDFLAGS =
xmlrpctest_LDADD = $(LDADDS)

$(LIBVIRT):
	-@(cd $(top_builddir)/src && $(MAKE) MAKEFLAGS+=--silent)
