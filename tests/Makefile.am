## Process this file with automake to produce Makefile.in

SHELL = $(PREFERABLY_POSIX_SHELL)

SUBDIRS = virshdata confdata sexpr2xmldata \
  xml2sexprdata xmconfigdata xencapsdata

INCLUDES = \
	-I$(top_srcdir)/gnulib/lib -I../gnulib/lib \
	-I$(top_builddir)/include \
	-I$(top_builddir)/src \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/src \
	$(LIBXML_CFLAGS) \
	$(GNUTLS_CFLAGS) \
	$(SASL_CFLAGS) \
	$(SELINUX_CFLAGS) \
        -D_XOPEN_SOURCE=600 -D_POSIX_C_SOURCE=199506L \
        -DGETTEXT_PACKAGE=\"$(PACKAGE)\" \
         $(COVERAGE_CFLAGS) \
         $(WARN_CFLAGS)	\
	 $(LIBVIRT_FEATURES)

LDADDS = \
	@STATIC_BINARIES@ \
	$(LIBXML_LIBS) \
        $(GNUTLS_LIBS) \
        $(SASL_LIBS) \
        $(SELINUX_LIBS) \
        $(WARN_CFLAGS) \
	../src/libvirt_test.la \
	../gnulib/lib/libgnu.la \
        $(COVERAGE_LDFLAGS)

EXTRA_DIST =		\
        oomtrace.pl     \
	test-lib.sh	\
	xmlrpcserver.py	\
	test_conf.sh	\
	qemuxml2argvdata \
	nodeinfodata

noinst_PROGRAMS = xmlrpctest xml2sexprtest sexpr2xmltest virshtest conftest \
	reconnect xmconfigtest xencapstest qemuxml2argvtest qemuxml2xmltest \
        nodeinfotest statstest qparamtest

test_scripts = \
	daemon-conf \
	int-overflow \
	read-bufsiz \
	read-non-seekable \
	vcpupin

EXTRA_DIST += $(test_scripts)

TESTS = xml2sexprtest sexpr2xmltest virshtest test_conf.sh xmconfigtest \
        xencapstest qemuxml2argvtest qemuxml2xmltest nodeinfotest \
	statstest qparamtest $(test_scripts)
if ENABLE_XEN_TESTS
  TESTS += reconnect
endif

path_add = $$abs_top_builddir/src$(PATH_SEPARATOR)$$abs_top_builddir/qemud

# NB, automake < 1.10 does not provide the real
# abs_top_{src/build}dir variables, so don't rely
# on them here. Fake them with 'pwd'
TESTS_ENVIRONMENT =				\
  abs_top_builddir=`cd '$(top_builddir)'; pwd`	\
  abs_top_srcdir=`cd '$(top_srcdir)'; pwd`	\
  abs_builddir=`cd '$(builddir)'; pwd`		\
  abs_srcdir=`cd '$(srcdir)'; pwd`		\
  PATH="$(path_add)$(PATH_SEPARATOR)$$PATH"	\
  SHELL="$(SHELL)"				\
  $(VG)

valgrind:
	$(MAKE) check VG="valgrind --quiet --leak-check=full --suppressions=$(srcdir)/.valgrind.supp"

# Note: xmlrpc.[c|h] is not in libvirt yet
xmlrpctest_SOURCES = \
	xmlrpctest.c \
	testutils.c testutils.h \
	@top_srcdir@/src/xmlrpc.c \
	@top_srcdir@/src/xmlrpc.h

xmlrpctest_LDADD = $(LDADDS)

xml2sexprtest_SOURCES = \
	xml2sexprtest.c \
	testutils.c testutils.h
xml2sexprtest_LDADD = $(LDADDS)

sexpr2xmltest_SOURCES = \
	sexpr2xmltest.c \
	testutils.c testutils.h
sexpr2xmltest_LDADD = $(LDADDS)

xmconfigtest_SOURCES = \
	xmconfigtest.c \
	testutils.c testutils.h
xmconfigtest_LDADD = $(LDADDS)

qemuxml2argvtest_SOURCES = \
	qemuxml2argvtest.c testutilsqemu.c testutilsqemu.h \
	testutils.c testutils.h
qemuxml2argvtest_LDADD = $(LDADDS)

qemuxml2xmltest_SOURCES = \
	qemuxml2xmltest.c testutilsqemu.c testutilsqemu.h \
	testutils.c testutils.h
qemuxml2xmltest_LDADD = $(LDADDS)

virshtest_SOURCES = \
	virshtest.c \
	testutils.c testutils.h
virshtest_LDADD = $(LDADDS)

conftest_SOURCES = \
	conftest.c
conftest_LDADD = $(LDADDS)

xencapstest_SOURCES = \
	xencapstest.c testutils.h testutils.c
xencapstest_LDADD = $(LDADDS)

nodeinfotest_SOURCES = \
	nodeinfotest.c testutils.h testutils.c
nodeinfotest_LDADD = $(LDADDS)

statstest_SOURCES = \
	statstest.c testutils.h testutils.c
statstest_LDADD = $(LDADDS)

qparamtest_SOURCES = \
	qparamtest.c testutils.h testutils.c
qparamtest_LDADD = $(LDADDS)

reconnect_SOURCES = \
	reconnect.c
reconnect_LDADD = $(LDADDS)

CLEANFILES = *.cov *.gcov .libs/*.gcda .libs/*.gcno *.gcno *.gcda
