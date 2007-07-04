## Process this file with automake to produce Makefile.in

SUBDIRS = virshdata confdata sexpr2xmldata xml2sexprdata xmconfigdata xencapsdata

# Wierd libtool related juju...
#
# We explicitly want wildcard here instead of just linking
# to the libvirt.a file. This ensures that when coverage
# tests are run, all the output data ends up in the correct
# location. ie, src/ instead of src/.libs.
LIBVIRT = $(wildcard $(top_builddir)/src/.libs/libvirt_la-*.o)

INCLUDES = \
	-I$(top_builddir)/include \
	-I$(top_builddir)/src \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/src \
	@LIBXML_CFLAGS@ \
        -D_XOPEN_SOURCE=600 -D_POSIX_C_SOURCE=199506L \
        -DGETTEXT_PACKAGE=\"$(PACKAGE)\" \
         $(COVERAGE_CFLAGS) \
         $(WARN_CFLAGS)	\
	 $(LIBVIRT_FEATURES)

LDADDS = \
	@STATIC_BINARIES@ \
	@LIBXML_LIBS@ \
        $(WARN_CFLAGS) \
	$(LIBVIRT) \
        $(COVERAGE_LDFLAGS)

EXTRA_DIST = xmlrpcserver.py test_conf.sh

noinst_PROGRAMS = xmlrpctest xml2sexprtest sexpr2xmltest virshtest conftest \
	reconnect xmconfigtest xencapstest

TESTS = xml2sexprtest sexpr2xmltest virshtest test_conf.sh xmconfigtest xencapstest
if ENABLE_XEN_TESTS
  TESTS += reconnect
endif

valgrind:
	$(MAKE) check TESTS_ENVIRONMENT="valgrind --quiet --leak-check=full"

# Note: xmlrpc.[c|h] is not in libvirt yet
xmlrpctest_SOURCES = \
	xmlrpctest.c \
	testutils.c testutils.h \
	@top_srcdir@/src/xmlrpc.c \
	@top_srcdir@/src/xmlrpc.h

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

xmconfigtest_SOURCES = \
	xmconfigtest.c \
	testutils.c testutils.h
xmconfigtest_LDFLAGS =
xmconfigtest_LDADD = $(LDADDS)

virshtest_SOURCES = \
	virshtest.c \
	testutils.c testutils.h
virshtest_LDFLAGS =
virshtest_LDADD = $(LDADDS)

conftest_SOURCES = \
	conftest.c
conftest_LDFLAGS =
conftest_LDADD = $(LDADDS)

xencapstest_SOURCES = \
	xencapstest.c testutils.h testutils.c
xencapstest_LDFLAGS =
xencapstest_LDADD = $(LDADDS)

reconnect_SOURCES = \
	reconnect.c
reconnect_LDFLAGS =
reconnect_LDADD = $(LDADDS)

$(LIBVIRT):
	-@(cd $(top_builddir)/src && $(MAKE) MAKEFLAGS+=--silent)
