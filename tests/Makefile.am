## Process this file with automake to produce Makefile.in

SHELL = $(PREFERABLY_POSIX_SHELL)

INCLUDES = \
	-I$(top_srcdir)/gnulib/lib -I../gnulib/lib \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/util \
	-I$(top_srcdir)/src/conf \
	$(LIBXML_CFLAGS) \
	$(GNUTLS_CFLAGS) \
	$(SASL_CFLAGS) \
	$(SELINUX_CFLAGS) \
	$(APPARMOR_CFLAGS) \
         $(COVERAGE_CFLAGS) \
         $(WARN_CFLAGS)

if WITH_DRIVER_MODULES
INCLUDES += \
	-DTEST_DRIVER_DIR=\"$(top_builddir)/src/.libs\"
endif

LDADDS = \
	$(STATIC_BINARIES) \
	$(LIBXML_LIBS) \
        $(GNUTLS_LIBS) \
        $(SASL_LIBS) \
        $(SELINUX_LIBS) \
        $(APPARMOR_LIBS) \
        $(WARN_CFLAGS) \
	../src/libvirt_test.la \
	../gnulib/lib/libgnu.la \
	$(LIBSOCKET) \
        $(COVERAGE_LDFLAGS)

EXTRA_DIST =		\
	capabilityschemadata \
	capabilityschematest \
	commanddata \
	confdata \
	cputestdata \
	domainschemadata \
	domainschematest \
	domainsnapshotschematest \
	domainsnapshotxml2xmlin \
	domainsnapshotxml2xmlout \
	interfaceschemadata \
	networkschematest \
	networkxml2xmlin \
	networkxml2xmlout \
	nodedevschemadata \
	nodedevschematest \
	nodeinfodata     \
	nwfilterschematest \
	nwfilterxml2xmlin \
	nwfilterxml2xmlout \
	oomtrace.pl \
	qemuhelpdata \
	qemuxml2argvdata \
	qemuxml2xmloutdata \
	schematestutils.sh \
	sexpr2xmldata \
	storagepoolschematest \
	storagepoolxml2xmlin \
	storagepoolxml2xmlout \
	storagevolschematest \
	storagevolxml2xmlin \
	storagevolxml2xmlout \
	test-lib.sh	\
	vmx2xmldata \
	xencapsdata \
	xmconfigdata \
	xml2sexprdata \
	xml2vmxdata

check_PROGRAMS = virshtest conftest sockettest \
	nodeinfotest qparamtest virbuftest \
	commandtest commandhelper seclabeltest

if WITH_XEN
check_PROGRAMS += xml2sexprtest sexpr2xmltest \
	xmconfigtest xencapstest
if ENABLE_XEN_TESTS
check_PROGRAMS += statstest reconnect
endif
endif
if WITH_QEMU
check_PROGRAMS += qemuxml2argvtest qemuxml2xmltest qemuargv2xmltest qemuhelptest
endif

if WITH_ESX
check_PROGRAMS += esxutilstest
endif

if WITH_VMX
check_PROGRAMS += vmx2xmltest xml2vmxtest
endif

if WITH_CIL
check_PROGRAMS += object-locking
endif

check_PROGRAMS += networkxml2xmltest

check_PROGRAMS += nwfilterxml2xmltest

check_PROGRAMS += storagevolxml2xmltest storagepoolxml2xmltest

check_PROGRAMS += nodedevxml2xmltest

check_PROGRAMS += interfacexml2xmltest

check_PROGRAMS += cputest

test_scripts = \
	capabilityschematest \
	interfaceschematest \
	networkschematest \
	storagepoolschematest \
	storagevolschematest \
	domainschematest \
	nodedevschematest \
	nwfilterschematest \
	domainsnapshotschematest

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
	virsh-schedinfo			\
	virsh-synopsis
endif

if WITH_SECDRIVER_APPARMOR
test_scripts += virt-aa-helper-test
else
EXTRA_DIST += virt-aa-helper-test
endif

EXTRA_DIST += $(test_scripts)

TESTS = virshtest \
        nodeinfotest \
	qparamtest \
	virbuftest \
	sockettest \
	commandtest \
	seclabeltest \
	$(test_scripts)

if WITH_XEN
TESTS += xml2sexprtest \
	sexpr2xmltest \
	xmconfigtest \
	xencapstest
if ENABLE_XEN_TESTS
TESTS += reconnect statstest
endif
endif

if WITH_QEMU
TESTS += qemuxml2argvtest qemuxml2xmltest qemuargv2xmltest qemuhelptest
TESTS += nwfilterxml2xmltest
endif

if WITH_ESX
TESTS += esxutilstest
endif

if WITH_VMX
TESTS += vmx2xmltest xml2vmxtest
endif

if WITH_LIBVIRTD
check_PROGRAMS += eventtest
TESTS += eventtest
endif

TESTS += networkxml2xmltest

TESTS += storagevolxml2xmltest storagepoolxml2xmltest

TESTS += nodedevxml2xmltest

TESTS += interfacexml2xmltest

TESTS += cputest

path_add = $$abs_top_builddir/daemon$(PATH_SEPARATOR)$$abs_top_builddir/tools

# NB, automake < 1.10 does not provide the real
# abs_top_{src/build}dir or builddir variables, so don't rely
# on them here. Fake them with 'pwd'
TESTS_ENVIRONMENT =				\
  abs_top_builddir=`cd '$(top_builddir)'; pwd`	\
  abs_top_srcdir=`cd '$(top_srcdir)'; pwd`	\
  abs_builddir=`pwd`				\
  abs_srcdir=`cd '$(srcdir)'; pwd`		\
  CONFIG_HEADER="`cd '$(top_builddir)'; pwd`/config.h"	\
  PATH="$(path_add)$(PATH_SEPARATOR)$$PATH"	\
  SHELL="$(SHELL)"				\
  LIBVIRT_DRIVER_DIR="$(abs_top_builddir)/src/.libs" \
  LC_ALL=C					\
  $(VG)

valgrind:
	$(MAKE) check VG="valgrind --quiet --leak-check=full --suppressions=$(srcdir)/.valgrind.supp"

sockettest_SOURCES = \
	sockettest.c \
	testutils.c testutils.h
sockettest_LDADD = ../src/libvirt_util.la $(LDADDS)

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

statstest_SOURCES = \
	statstest.c testutils.h testutils.c
statstest_LDADD = ../src/libvirt_driver_xen.la $(LDADDS)

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

qemuhelptest_SOURCES = qemuhelptest.c testutils.c testutils.h
qemuhelptest_LDADD = ../src/libvirt_driver_qemu.la $(LDADDS)
else
EXTRA_DIST += qemuxml2argvtest.c qemuxml2xmltest.c qemuargv2xmltest.c qemuhelptest.c testutilsqemu.c testutilsqemu.h
endif

if WITH_ESX
esxutilstest_SOURCES = \
	esxutilstest.c \
	testutils.c testutils.h
esxutilstest_LDADD = ../src/libvirt_driver_esx.la $(LDADDS)
else
EXTRA_DIST += esxutilstest.c
endif

if WITH_VMX
vmx2xmltest_SOURCES = \
	vmx2xmltest.c \
	testutils.c testutils.h
vmx2xmltest_LDADD = ../src/libvirt_vmx.la $(LDADDS)

xml2vmxtest_SOURCES = \
	xml2vmxtest.c \
	testutils.c testutils.h
xml2vmxtest_LDADD = ../src/libvirt_vmx.la $(LDADDS)
else
EXTRA_DIST += vmx2xmltest.c xml2vmxtest.c
endif

networkxml2xmltest_SOURCES = \
	networkxml2xmltest.c \
	testutils.c testutils.h
networkxml2xmltest_LDADD = $(LDADDS)

nwfilterxml2xmltest_SOURCES = \
	nwfilterxml2xmltest.c \
	testutils.c testutils.h
nwfilterxml2xmltest_LDADD = $(LDADDS)

storagevolxml2xmltest_SOURCES = \
	storagevolxml2xmltest.c \
	testutils.c testutils.h
storagevolxml2xmltest_LDADD = $(LDADDS)

storagepoolxml2xmltest_SOURCES = \
	storagepoolxml2xmltest.c \
	testutils.c testutils.h
storagepoolxml2xmltest_LDADD = $(LDADDS)

nodedevxml2xmltest_SOURCES = \
	nodedevxml2xmltest.c \
	testutils.c testutils.h
nodedevxml2xmltest_LDADD = $(LDADDS)

interfacexml2xmltest_SOURCES = \
	interfacexml2xmltest.c \
	testutils.c testutils.h
interfacexml2xmltest_LDADD = $(LDADDS)

cputest_SOURCES = \
	cputest.c \
	testutils.c testutils.h
cputest_LDADD = $(LDADDS)

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

commandtest_SOURCES = \
	commandtest.c testutils.h testutils.c
commandtest_CFLAGS = -Dabs_builddir="\"`pwd`\""
commandtest_LDADD = $(LDADDS)

commandhelper_SOURCES = \
	commandhelper.c
commandhelper_CFLAGS = -Dabs_builddir="\"`pwd`\""
commandhelper_LDADD = $(LDADDS)

seclabeltest_SOURCES = \
	seclabeltest.c
seclabeltest_LDADD = ../src/libvirt_driver_security.la $(LDADDS)

qparamtest_SOURCES = \
	qparamtest.c testutils.h testutils.c
qparamtest_LDADD = $(LDADDS)

virbuftest_SOURCES = \
	virbuftest.c testutils.h testutils.c
virbuftest_LDADD = $(LDADDS)

if WITH_LIBVIRTD
eventtest_SOURCES = \
	eventtest.c testutils.h testutils.c
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
