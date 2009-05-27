## Process this file with automake to produce Makefile.in

SHELL = $(PREFERABLY_POSIX_SHELL)

SUBDIRS = confdata sexpr2xmldata \
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
        -DGETTEXT_PACKAGE=\"$(PACKAGE)\" \
         $(COVERAGE_CFLAGS) \
         $(WARN_CFLAGS)

if WITH_DRIVER_MODULES
INCLUDES += \
	-DTEST_DRIVER_DIR=\"$(top_builddir)/src/.libs\"
endif

LDADDS = \
	@STATIC_BINARIES@ \
	$(LIBXML_LIBS) \
        $(GNUTLS_LIBS) \
        $(SASL_LIBS) \
        $(SELINUX_LIBS) \
        $(WARN_CFLAGS) \
	../src/libvirt_test.la \
	../gnulib/lib/libgnu.la \
	$(LIBSOCKET) \
        $(COVERAGE_LDFLAGS)

EXTRA_DIST =		\
        oomtrace.pl     \
	test-lib.sh	\
	qemuxml2argvdata \
	nodeinfodata     \
	capabilityschematest \
	capabilityschemadata \
	networkschematest \
	domainschematest \
	domainschemadata \
	storagepoolschematest \
	storagepoolschemadata \
	storagevolschematest \
	storagevolschemadata \
	nodedevschematest \
	nodedevschemadata

noinst_PROGRAMS = virshtest conftest \
        nodeinfotest statstest qparamtest

if WITH_XEN
noinst_PROGRAMS += xml2sexprtest sexpr2xmltest \
	reconnect xmconfigtest xencapstest
endif
if WITH_QEMU
noinst_PROGRAMS += qemuxml2argvtest qemuxml2xmltest qemuargv2xmltest
endif

if WITH_SECDRIVER_SELINUX
noinst_PROGRAMS += seclabeltest
endif

if WITH_CIL
noinst_PROGRAMS += object-locking
endif

noinst_PROGRAMS += nodedevxml2xmltest

test_scripts = \
	capabilityschematest \
	networkschematest \
	storagepoolschematest \
	storagevolschematest \
	domainschematest \
	nodedevschematest

if WITH_LIBVIRTD
test_scripts +=				\
	test_conf.sh			\
	cpuset				\
	daemon-conf			\
	define-dev-segfault		\
	int-overflow			\
	libvirtd-fail			\
	libvirtd-pool			\
	read-bufsiz			\
	read-non-seekable		\
	start				\
	undefine			\
	vcpupin				\
	virsh-all			\
	virsh-synopsis
endif

EXTRA_DIST += $(test_scripts)

TESTS = virshtest \
        nodeinfotest \
	statstest \
	qparamtest \
	$(test_scripts)

if WITH_XEN
TESTS += xml2sexprtest \
	sexpr2xmltest \
	xmconfigtest \
	xencapstest
if ENABLE_XEN_TESTS
TESTS += reconnect
endif
endif

if WITH_QEMU
TESTS += qemuxml2argvtest qemuxml2xmltest qemuargv2xmltest
endif

if WITH_SECDRIVER_SELINUX
TESTS += seclabeltest
endif

if WITH_LIBVIRTD
noinst_PROGRAMS += eventtest
TESTS += eventtest
endif

TESTS += nodedevxml2xmltest

path_add = $$abs_top_builddir/src$(PATH_SEPARATOR)$$abs_top_builddir/qemud

# NB, automake < 1.10 does not provide the real
# abs_top_{src/build}dir variables, so don't rely
# on them here. Fake them with 'pwd'
TESTS_ENVIRONMENT =				\
  abs_top_builddir=`cd '$(top_builddir)'; pwd`	\
  abs_top_srcdir=`cd '$(top_srcdir)'; pwd`	\
  abs_builddir=`cd '$(builddir)'; pwd`		\
  abs_srcdir=`cd '$(srcdir)'; pwd`		\
  CONFIG_HEADER="`cd '$(top_builddir)'; pwd`/config.h"	\
  PATH="$(path_add)$(PATH_SEPARATOR)$$PATH"	\
  SHELL="$(SHELL)"				\
  LIBVIRT_DRIVER_DIR="$(abs_top_builddir)/src/.libs" \
  LIBVIRT_DEBUG="error"				\
  LC_ALL=C					\
  $(VG)

valgrind:
	$(MAKE) check VG="valgrind --quiet --leak-check=full --suppressions=$(srcdir)/.valgrind.supp"

if WITH_XEN
xml2sexprtest_SOURCES = \
	xml2sexprtest.c testutilsxen.c testutilsxen.h \
	testutils.c testutils.h
xml2sexprtest_LDADD = ../src/libvirt_driver_xen.la $(LDADDS)

sexpr2xmltest_SOURCES = \
	sexpr2xmltest.c testutilsxen.c testutilsxen.h \
	testutils.c testutils.h
sexpr2xmltest_LDADD = ../src/libvirt_driver_xen.la $(LDADDS)

xmconfigtest_SOURCES = \
	xmconfigtest.c testutilsxen.c testutilsxen.h \
	testutils.c testutils.h
xmconfigtest_LDADD = ../src/libvirt_driver_xen.la $(LDADDS)

xencapstest_SOURCES = \
	xencapstest.c testutils.h testutils.c
xencapstest_LDADD = ../src/libvirt_driver_xen.la $(LDADDS)

reconnect_SOURCES = \
	reconnect.c
reconnect_LDADD = $(LDADDS)

else
EXTRA_DIST += xml2sexprtest.c sexpr2xmltest.c xmconfigtest.c \
	xencapstest.c reconnect.c \
	testutilsxen.c testutilsxen.h
endif

if WITH_QEMU
qemuxml2argvtest_SOURCES = \
	qemuxml2argvtest.c testutilsqemu.c testutilsqemu.h \
	testutils.c testutils.h
qemuxml2argvtest_LDADD = ../src/libvirt_driver_qemu.la $(LDADDS)

qemuxml2xmltest_SOURCES = \
	qemuxml2xmltest.c testutilsqemu.c testutilsqemu.h \
	testutils.c testutils.h
qemuxml2xmltest_LDADD = ../src/libvirt_driver_qemu.la $(LDADDS)

qemuargv2xmltest_SOURCES = \
	qemuargv2xmltest.c testutilsqemu.c testutilsqemu.h \
	testutils.c testutils.h
qemuargv2xmltest_LDADD = ../src/libvirt_driver_qemu.la $(LDADDS)
else
EXTRA_DIST += qemuxml2argvtest.c qemuxml2xmltest.c qemuargv2xmltest.c testutilsqemu.c testutilsqemu.h
endif

nodedevxml2xmltest_SOURCES = \
	nodedevxml2xmltest.c \
	testutils.c testutils.h
nodedevxml2xmltest_LDADD = $(LDADDS)

virshtest_SOURCES = \
	virshtest.c \
	testutils.c testutils.h
virshtest_LDADD = $(LDADDS)

conftest_SOURCES = \
	conftest.c
conftest_LDADD = $(LDADDS)

nodeinfotest_SOURCES = \
	nodeinfotest.c testutils.h testutils.c
nodeinfotest_LDADD = $(LDADDS)

statstest_SOURCES = \
	statstest.c testutils.h testutils.c
statstest_LDADD = $(LDADDS)

if WITH_SECDRIVER_SELINUX
seclabeltest_SOURCES = \
	seclabeltest.c
seclabeltest_LDADD = ../src/libvirt_driver_security.la $(LDADDS)
else
EXTRA_DIST += seclabeltest.c
endif

qparamtest_SOURCES = \
	qparamtest.c testutils.h testutils.c
qparamtest_LDADD = $(LDADDS)

if WITH_LIBVIRTD
eventtest_SOURCES = \
	eventtest.c testutils.h testutils.c ../qemud/event.c
eventtest_LDADD = -lrt $(LDADDS)
endif

if WITH_CIL
CILOPTFLAGS =
CILOPTINCS =
CILOPTPACKAGES = -package unix,str,cil
CILOPTLIBS = -linkpkg

object_locking_SOURCES = object-locking.ml

%.cmx: %.ml
	ocamlfind ocamlopt $(CILOPTFLAGS) $(CILOPTINCS) $(CILOPTPACKAGES) -c $<

object-locking: object-locking.cmx object-locking-files.txt
	ocamlfind ocamlopt $(CILOPTFLAGS) $(CILOPTINCS) $(CILOPTPACKAGES) $(CILOPTLIBS) $< -o $@

object-locking-files.txt:
	find $(top_builddir)/src/ -name '*.i' > $@

else
EXTRA_DIST += object-locking.ml
endif

CLEANFILES = *.cov *.gcov .libs/*.gcda .libs/*.gcno *.gcno *.gcda *.cmi *.cmx object-locking-files.txt
