## Process this file with automake to produce Makefile.in

SUBDIRS = virshdata

LIBVIRT = $(top_builddir)/src/.libs/libvirt.a

INCLUDES = \
	-I$(top_builddir)/include \
	-I$(top_builddir)/src \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/src \
	@LIBXML_CFLAGS@ \
        -D_XOPEN_SOURCE=600 -D_POSIX_C_SOURCE=199506L

LDADDS = \
	@STATIC_BINARIES@ \
	@LIBXML_LIBS@ \
	$(LIBVIRT)

EXTRA_DIST = xmlrpcserver.py

noinst_PROGRAMS = xmlrpctest xml2sexprtest sexpr2xmltest virshtest

TESTS = xml2sexprtest sexpr2xmltest virshtest

valgrind:
	$(MAKE) check TESTS_ENVIRONMENT="valgrind --quiet"

# Note: xmlrpc.[c|h] is not in libvirt yet
xmlrpctest_SOURCES = \
	xmlrpctest.c \
	testutils.c testutils.h \
	$(top_builddir)/src/xmlrpc.c \
	$(top_builddir)/src/xmlrpc.h

xmlrpctest_LDFLAGS =
xmlrpctest_LDADD = $(LDADDS)

xml2sexprtest_SOURCES = \
	xml2sexprtest.c \
	testutils.c testutils.h
xml2sexprtest_LDFLAGS =
xml2sexprtest_LDADD = $(LDADDS)

sexpr2xmltest_SOURCES = \
	sexpr2xmltest.c \
	testutils.c testutils.h
sexpr2xmltest_LDFLAGS =
sexpr2xmltest_LDADD = $(LDADDS)

virshtest_SOURCES = \
	virshtest.c \
	testutils.c testutils.h
virshtest_LDFLAGS =
virshtest_LDADD = $(LDADDS)

$(LIBVIRT):
	-@(cd $(top_builddir)/src && $(MAKE) MAKEFLAGS+=--silent)
