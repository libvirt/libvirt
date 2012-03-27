## Process this file with automake to produce Makefile.in

## Copyright (C) 2005-2012 Red Hat, Inc.
## See COPYING.LIB for the License of this software

SHELL = $(PREFERABLY_POSIX_SHELL)

INCLUDES = \
	-I$(top_builddir)/gnulib/lib -I$(top_srcdir)/gnulib/lib \
	-I$(top_builddir)/include -I$(top_srcdir)/include \
	-I$(top_builddir)/src -I$(top_srcdir)/src \
	-I$(top_srcdir)/src/util \
	-I$(top_srcdir)/src/conf \
	$(GETTEXT_CPPFLAGS)

AM_CFLAGS = \
	$(LIBXML_CFLAGS) \
	$(GNUTLS_CFLAGS) \
	$(SASL_CFLAGS) \
	$(SELINUX_CFLAGS) \
	$(APPARMOR_CFLAGS) \
	$(YAJL_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(WARN_CFLAGS)

if WITH_DRIVER_MODULES
INCLUDES += \
	-DTEST_DRIVER_DIR=\"$(top_builddir)/src/.libs\"
endif

PROBES_O =
if WITH_DTRACE_PROBES
PROBES_O += ../src/probes.o
endif

LDADDS = \
	$(STATIC_BINARIES) \
	$(LIBXML_LIBS) \
        $(GNUTLS_LIBS) \
        $(SASL_LIBS) \
        $(SELINUX_LIBS) \
        $(APPARMOR_LIBS) \
        $(YAJL_LIBS) \
        $(WARN_CFLAGS) \
	../src/libvirt_test.la \
	$(PROBES_O) \
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
	lxcxml2xmldata \
	networkschematest \
	networkxml2xmlin \
	networkxml2xmlout \
	networkxml2argvdata \
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
	qemuxmlnsdata \
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
	xml2vmxdata \
	.valgrind.supp

test_helpers = commandhelper ssh conftest
test_programs = virshtest sockettest \
	nodeinfotest virbuftest \
	commandtest seclabeltest \
	virhashtest virnetmessagetest virnetsockettest \
	utiltest virnettlscontexttest shunloadtest \
	virtimetest viruritest virkeyfiletest \
	virauthconfigtest

# This is a fake SSH we use from virnetsockettest
ssh_SOURCES = ssh.c
ssh_LDADD = $(COVERAGE_LDFLAGS)

if WITH_XEN
test_programs += xml2sexprtest sexpr2xmltest \
	xmconfigtest xencapstest statstest reconnect
endif
if WITH_QEMU
test_programs += qemuxml2argvtest qemuxml2xmltest qemuxmlnstest \
	qemuargv2xmltest qemuhelptest domainsnapshotxml2xmltest \
	qemumonitortest
endif

if WITH_LXC
test_programs += lxcxml2xmltest
endif

if WITH_OPENVZ
test_programs += openvzutilstest
endif

if WITH_ESX
test_programs += esxutilstest
endif

if WITH_VMX
test_programs += vmx2xmltest xml2vmxtest
endif

if WITH_CIL
test_programs += object-locking
endif

if HAVE_YAJL
test_programs += jsontest
endif

test_programs += networkxml2xmltest

if WITH_NETWORK
test_programs += networkxml2argvtest
endif

test_programs += nwfilterxml2xmltest

test_programs += storagevolxml2xmltest storagepoolxml2xmltest

test_programs += nodedevxml2xmltest

test_programs += interfacexml2xmltest

test_programs += cputest

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
	virsh-optparse			\
	virsh-schedinfo			\
	virsh-synopsis

test_programs += eventtest
else
EXTRA_DIST += 				\
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
	virsh-optparse			\
	virsh-schedinfo			\
	virsh-synopsis
endif

if WITH_SECDRIVER_APPARMOR
test_scripts += virt-aa-helper-test
else
EXTRA_DIST += virt-aa-helper-test
endif

EXTRA_DIST += $(test_scripts)

if WITH_TESTS
noinst_PROGRAMS = $(test_programs) $(test_helpers)
noinst_LTLIBRARIES = libshunload.la
else
check_PROGRAMS = $(test_programs) $(test_helpers)
check_LTLIBRARIES = libshunload.la
endif

TESTS = $(test_programs) \
	$(test_scripts)

# NB, automake < 1.10 does not provide the real
# abs_top_{src/build}dir or builddir variables, so don't rely
# on them here. Fake them with 'pwd'
# Also, BSD sh doesn't like 'a=b b=$$a', so we can't use an
# intermediate shell variable, but must do all the expansion in make

lv_abs_top_builddir=`cd '$(top_builddir)'; pwd`
path_add = $(lv_abs_top_builddir)/daemon$(PATH_SEPARATOR)$(lv_abs_top_builddir)/tools$(PATH_SEPARATOR)$(lv_abs_top_builddir)/tests

TESTS_ENVIRONMENT =				\
  abs_top_builddir=$(lv_abs_top_builddir)	\
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
	reconnect.c testutils.h testutils.c
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

qemu_LDADDS = ../src/libvirt_driver_qemu.la

if WITH_NETWORK
qemu_LDADDS += ../src/libvirt_driver_network.la
endif

qemuxml2argvtest_SOURCES = \
	qemuxml2argvtest.c testutilsqemu.c testutilsqemu.h \
	testutils.c testutils.h
qemuxml2argvtest_LDADD = $(qemu_LDADDS)  $(LDADDS)

qemuxml2xmltest_SOURCES = \
	qemuxml2xmltest.c testutilsqemu.c testutilsqemu.h \
	testutils.c testutils.h
qemuxml2xmltest_LDADD = $(qemu_LDADDS) $(LDADDS)

qemuxmlnstest_SOURCES = \
	qemuxmlnstest.c testutilsqemu.c testutilsqemu.h \
	testutils.c testutils.h
qemuxmlnstest_LDADD = $(qemu_LDADDS)  $(LDADDS)

qemuargv2xmltest_SOURCES = \
	qemuargv2xmltest.c testutilsqemu.c testutilsqemu.h \
	testutils.c testutils.h
qemuargv2xmltest_LDADD = $(qemu_LDADDS) $(LDADDS)

qemuhelptest_SOURCES = qemuhelptest.c testutils.c testutils.h
qemuhelptest_LDADD = $(qemu_LDADDS) $(LDADDS)

qemumonitortest_SOURCES = qemumonitortest.c testutils.c testutils.h
qemumonitortest_LDADD = $(qemu_LDADDS) $(LDADDS)

domainsnapshotxml2xmltest_SOURCES = \
	domainsnapshotxml2xmltest.c testutilsqemu.c testutilsqemu.h \
	testutils.c testutils.h
domainsnapshotxml2xmltest_LDADD = $(qemu_LDADDS) $(LDADDS)
else
EXTRA_DIST += qemuxml2argvtest.c qemuxml2xmltest.c qemuargv2xmltest.c \
	qemuxmlnstest.c qemuhelptest.c domainsnapshotxml2xmltest.c \
	qemumonitortest.c testutilsqemu.c testutilsqemu.h
endif

if WITH_LXC

lxc_LDADDS = ../src/libvirt_driver_lxc.la

lxcxml2xmltest_SOURCES = \
	lxcxml2xmltest.c testutilslxc.c testutilslxc.h \
	testutils.c testutils.h
lxcxml2xmltest_LDADD = $(lxc_LDADDS) $(LDADDS)
else
EXTRA_DIST += lxcxml2xmltest.c testutilslxc.c testutilslxc.h
endif

if WITH_OPENVZ
openvzutilstest_SOURCES = \
	openvzutilstest.c \
	testutils.c testutils.h
openvzutilstest_LDADD = ../src/libvirt_driver_openvz.la $(LDADDS)
else
EXTRA_DIST += openvzutilstest.c
endif
EXTRA_DIST += openvzutilstest.conf

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

if WITH_NETWORK
networkxml2argvtest_SOURCES = \
	networkxml2argvtest.c \
	testutils.c testutils.h
networkxml2argvtest_LDADD = ../src/libvirt_driver_network.la $(LDADDS)
else
EXTRA_DIST += networkxml2argvtest.c
endif

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
commandtest_CFLAGS = -Dabs_builddir="\"`pwd`\"" $(AM_CFLAGS)
commandtest_LDADD = $(LDADDS)

commandhelper_SOURCES = \
	commandhelper.c
commandhelper_CFLAGS = -Dabs_builddir="\"`pwd`\"" $(AM_CFLAGS)
commandhelper_LDADD = $(LDADDS)

virnetmessagetest_SOURCES = \
	virnetmessagetest.c testutils.h testutils.c
virnetmessagetest_CFLAGS = -Dabs_builddir="\"$(abs_builddir)\"" $(AM_CFLAGS)
virnetmessagetest_LDADD = ../src/libvirt-net-rpc.la $(LDADDS)

virnetsockettest_SOURCES = \
	virnetsockettest.c testutils.h testutils.c
virnetsockettest_CFLAGS = -Dabs_builddir="\"$(abs_builddir)\"" $(AM_CFLAGS)
virnetsockettest_LDADD = ../src/libvirt-net-rpc.la $(LDADDS)

virnettlscontexttest_SOURCES = \
	virnettlscontexttest.c testutils.h testutils.c
virnettlscontexttest_CFLAGS = -Dabs_builddir="\"$(abs_builddir)\"" $(AM_CFLAGS)
virnettlscontexttest_LDADD = ../src/libvirt-net-rpc.la $(LDADDS)
if HAVE_LIBTASN1
virnettlscontexttest_SOURCES += pkix_asn1_tab.c
virnettlscontexttest_LDADD += -ltasn1
else
EXTRA_DIST += pkix_asn1_tab.c
endif

virtimetest_SOURCES = \
	virtimetest.c testutils.h testutils.c
virtimetest_CFLAGS = -Dabs_builddir="\"$(abs_builddir)\"" $(AM_CFLAGS)
virtimetest_LDADD = ../src/libvirt-net-rpc.la $(LDADDS)

viruritest_SOURCES = \
	viruritest.c testutils.h testutils.c
viruritest_CFLAGS = -Dabs_builddir="\"$(abs_builddir)\"" $(AM_CFLAGS)
viruritest_LDADD = ../src/libvirt-net-rpc.la $(LDADDS)

virkeyfiletest_SOURCES = \
	virkeyfiletest.c testutils.h testutils.c
virkeyfiletest_CFLAGS = -Dabs_builddir="\"$(abs_builddir)\"" $(AM_CFLAGS)
virkeyfiletest_LDADD = ../src/libvirt-net-rpc.la $(LDADDS)

virauthconfigtest_SOURCES = \
	virauthconfigtest.c testutils.h testutils.c
virauthconfigtest_CFLAGS = -Dabs_builddir="\"$(abs_builddir)\"" $(AM_CFLAGS)
virauthconfigtest_LDADD = ../src/libvirt-net-rpc.la $(LDADDS)

seclabeltest_SOURCES = \
	seclabeltest.c
seclabeltest_LDADD = ../src/libvirt_driver_security.la $(LDADDS)

virbuftest_SOURCES = \
	virbuftest.c testutils.h testutils.c
virbuftest_LDADD = $(LDADDS)

virhashtest_SOURCES = \
	virhashtest.c virhashdata.h testutils.h testutils.c
virhashtest_LDADD = $(LDADDS)

jsontest_SOURCES = \
	jsontest.c testutils.h testutils.c
jsontest_LDADD = $(LDADDS)

utiltest_SOURCES = \
	utiltest.c testutils.h testutils.c
utiltest_LDADD = $(LDADDS)

if WITH_LIBVIRTD
eventtest_SOURCES = \
	eventtest.c testutils.h testutils.c
eventtest_LDADD = -lrt $(LDADDS)
endif

libshunload_la_SOURCES = shunloadhelper.c
libshunload_la_LIBADD = ../src/libvirt.la
libshunload_la_LDFLAGS = -module -avoid-version -rpath /evil/libtool/hack/to/force/shared/lib/creation

shunloadtest_SOURCES = \
	shunloadtest.c
shunloadtest_LDADD = -lpthread
shunloadtest_DEPENDENCIES = libshunload.la

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
