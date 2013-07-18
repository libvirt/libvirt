## Process this file with automake to produce Makefile.in

## Copyright (C) 2005-2013 Red Hat, Inc.
##
## This library is free software; you can redistribute it and/or
## modify it under the terms of the GNU Lesser General Public
## License as published by the Free Software Foundation; either
## version 2.1 of the License, or (at your option) any later version.
##
## This library is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## Lesser General Public License for more details.
##
## You should have received a copy of the GNU Lesser General Public
## License along with this library.  If not, see
## <http://www.gnu.org/licenses/>.

SHELL = $(PREFERABLY_POSIX_SHELL)

INCLUDES = \
	-I$(top_builddir) -I$(top_srcdir) \
	-I$(top_builddir)/gnulib/lib -I$(top_srcdir)/gnulib/lib \
	-I$(top_builddir)/include -I$(top_srcdir)/include \
	-I$(top_builddir)/src -I$(top_srcdir)/src \
	-I$(top_srcdir)/src/util \
	-I$(top_srcdir)/src/conf \
	$(GETTEXT_CPPFLAGS)

AM_CFLAGS = \
	-Dabs_builddir="\"`pwd`\"" \
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
PROBES_O += ../src/libvirt_probes.lo
endif

LDADDS = \
        $(WARN_CFLAGS) \
	$(PROBES_O) \
	../src/libvirt.la \
	../gnulib/lib/libgnu.la

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
	fchostdata \
	interfaceschemadata \
	lxcxml2xmldata \
	networkschematest \
	networkxml2xmlin \
	networkxml2xmlout \
	networkxml2confdata \
	nodedevschemadata \
	nodedevschematest \
	nodeinfodata     \
	nwfilterschematest \
	nwfilterxml2xmlin \
	nwfilterxml2xmlout \
	oomtrace.pl \
	qemuhelpdata \
	qemuhotplugtestdata \
	qemuxml2argvdata \
	qemuxml2xmloutdata \
	qemuxmlnsdata \
	securityselinuxlabeldata \
	schematestutils.sh \
	sexpr2xmldata \
	storagepoolschemadata \
	storagepoolschematest \
	storagepoolxml2xmlin \
	storagepoolxml2xmlout \
	storagevolxml2argvdata \
	storagevolschemadata \
	storagevolschematest \
	storagevolxml2xmlin \
	storagevolxml2xmlout \
	sysinfodata \
	test-lib.sh	\
	vmx2xmldata \
	xencapsdata \
	xmconfigdata \
	xml2sexprdata \
	xml2vmxdata \
	.valgrind.supp

test_helpers = commandhelper ssh test_conf
test_programs = virshtest sockettest \
	nodeinfotest virbuftest \
	commandtest seclabeltest \
	virhashtest virnetmessagetest virnetsockettest \
	viratomictest \
	utiltest shunloadtest \
	virtimetest viruritest virkeyfiletest \
	virauthconfigtest \
	virbitmaptest \
	vircgrouptest \
	virendiantest \
	viridentitytest \
	virkeycodetest \
	virlockspacetest \
	virstringtest \
        virportallocatortest \
	sysinfotest \
	virstoragetest \
        fdstreamtest \
        fchosttest \
	$(NULL)

if WITH_DBUS
test_programs += virdbustest \
                 virsystemdtest
endif

if WITH_GNUTLS
test_programs += virnettlscontexttest
endif

if WITH_SECDRIVER_SELINUX
test_programs += securityselinuxtest
if WITH_QEMU
if WITH_ATTR
test_programs += securityselinuxlabeltest
endif
endif
endif

if WITH_DRIVER_MODULES
test_programs += virdrivermoduletest
endif

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
	qemumonitortest qemumonitorjsontest qemuhotplugtest
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

if WITH_YAJL
test_programs += jsontest
endif

test_programs += networkxml2xmltest

if WITH_NETWORK
test_programs += networkxml2conftest
endif

if WITH_STORAGE_SHEEPDOG
test_programs += storagebackendsheepdogtest
endif

test_programs += nwfilterxml2xmltest

if WITH_STORAGE
test_programs += storagevolxml2argvtest
endif

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
	define-dev-segfault		\
	int-overflow			\
	libvirtd-fail			\
	libvirtd-pool			\
	read-bufsiz			\
	read-non-seekable		\
	start				\
	vcpupin				\
	virsh-all			\
	virsh-optparse			\
	virsh-schedinfo			\
	virsh-synopsis			\
	virsh-undefine			\
	$(NULL)

test_programs += 			\
	eventtest			\
	libvirtdconftest
else
EXTRA_DIST += 				\
	test_conf.sh			\
	cpuset				\
	define-dev-segfault		\
	int-overflow			\
	libvirtd-fail			\
	libvirtd-pool			\
	read-bufsiz			\
	read-non-seekable		\
	start				\
	vcpupin				\
	virsh-all			\
	virsh-optparse			\
	virsh-schedinfo			\
	virsh-synopsis			\
	virsh-undefine			\
	$(NULL)
endif

if WITH_SECDRIVER_APPARMOR
test_scripts += virt-aa-helper-test
else
EXTRA_DIST += virt-aa-helper-test
endif

EXTRA_DIST += $(test_scripts)

test_libraries = libshunload.la \
		libvirportallocatormock.la \
		vircgroupmock.la \
		$(NULL)
if WITH_QEMU
test_libraries += libqemumonitortestutils.la
endif

if WITH_DBUS
test_libraries += virsystemdmock.la
endif

if WITH_TESTS
noinst_PROGRAMS = $(test_programs) $(test_helpers)
noinst_LTLIBRARIES = $(test_libraries)
else
check_PROGRAMS = $(test_programs) $(test_helpers)
check_LTLIBRARIES = $(test_libraries)
endif

TESTS = $(test_programs) \
	$(test_scripts)

# NB, automake < 1.10 does not provide the real
# abs_top_{src/build}dir or builddir variables, so don't rely
# on them here. Fake them with 'pwd'
# Also, BSD sh doesn't like 'a=b b=$$a', so we can't use an
# intermediate shell variable, but must do all the expansion in make

lv_abs_top_builddir=`cd '$(top_builddir)'; pwd`
path_add = $(subst :,$(PATH_SEPARATOR),\
	$(subst !,$(lv_abs_top_builddir)/,!daemon:!tools:!tests))

TESTS_ENVIRONMENT =				\
  abs_top_builddir=$(lv_abs_top_builddir)	\
  abs_top_srcdir=`cd '$(top_srcdir)'; pwd`	\
  abs_builddir=`pwd`				\
  abs_srcdir=`cd '$(srcdir)'; pwd`		\
  CONFIG_HEADER="`cd '$(top_builddir)'; pwd`/config.h"	\
  PATH="$(path_add)$(PATH_SEPARATOR)$$PATH"	\
  SHELL="$(SHELL)"				\
  LIBVIRT_DRIVER_DIR="$(abs_top_builddir)/src/.libs" \
  LIBVIRT_AUTOSTART=0				\
  LC_ALL=C					\
  $(VG)


VALGRIND = valgrind --quiet --leak-check=full \
	--suppressions=$(srcdir)/.valgrind.supp
valgrind:
	$(MAKE) check VG="libtool --mode=execute $(VALGRIND)"

sockettest_SOURCES = \
	sockettest.c \
	testutils.c testutils.h
sockettest_LDADD = $(LDADDS)

if WITH_XEN
xen_LDADDS = ../src/libvirt_driver_xen_impl.la
xen_LDADDS += $(LDADDS)

xml2sexprtest_SOURCES = \
	xml2sexprtest.c testutilsxen.c testutilsxen.h \
	testutils.c testutils.h
xml2sexprtest_LDADD = $(xen_LDADDS)

sexpr2xmltest_SOURCES = \
	sexpr2xmltest.c testutilsxen.c testutilsxen.h \
	testutils.c testutils.h
sexpr2xmltest_LDADD = $(xen_LDADDS)

xmconfigtest_SOURCES = \
	xmconfigtest.c testutilsxen.c testutilsxen.h \
	testutils.c testutils.h
xmconfigtest_LDADD = $(xen_LDADDS)

xencapstest_SOURCES = \
	xencapstest.c testutils.h testutils.c
xencapstest_LDADD = $(xen_LDADDS)

reconnect_SOURCES = \
	reconnect.c testutils.h testutils.c
reconnect_LDADD = $(LDADDS)

statstest_SOURCES = \
	statstest.c testutils.h testutils.c
statstest_LDADD = $(xen_LDADDS)

else
EXTRA_DIST += xml2sexprtest.c sexpr2xmltest.c xmconfigtest.c \
	xencapstest.c reconnect.c \
	testutilsxen.c testutilsxen.h
endif

QEMUMONITORTESTUTILS_SOURCES = \
	qemumonitortestutils.c \
	qemumonitortestutils.h \
	$(NULL)

if WITH_QEMU

libqemumonitortestutils_la_SOURCES = $(QEMUMONITORTESTUTILS_SOURCES)

qemu_LDADDS = ../src/libvirt_driver_qemu_impl.la
if WITH_NETWORK
qemu_LDADDS += ../src/libvirt_driver_network_impl.la
endif
if WITH_DTRACE_PROBES
qemu_LDADDS += ../src/libvirt_qemu_probes.lo
endif
qemu_LDADDS += $(LDADDS)

qemuxml2argvtest_SOURCES = \
	qemuxml2argvtest.c testutilsqemu.c testutilsqemu.h \
	testutils.c testutils.h
qemuxml2argvtest_LDADD = $(qemu_LDADDS)

qemuxml2xmltest_SOURCES = \
	qemuxml2xmltest.c testutilsqemu.c testutilsqemu.h \
	testutils.c testutils.h
qemuxml2xmltest_LDADD = $(qemu_LDADDS)

qemuxmlnstest_SOURCES = \
	qemuxmlnstest.c testutilsqemu.c testutilsqemu.h \
	testutils.c testutils.h
qemuxmlnstest_LDADD = $(qemu_LDADDS)

qemuargv2xmltest_SOURCES = \
	qemuargv2xmltest.c testutilsqemu.c testutilsqemu.h \
	testutils.c testutils.h
qemuargv2xmltest_LDADD = $(qemu_LDADDS)

qemuhelptest_SOURCES = qemuhelptest.c testutils.c testutils.h
qemuhelptest_LDADD = $(qemu_LDADDS)

qemumonitortest_SOURCES = qemumonitortest.c testutils.c testutils.h
qemumonitortest_LDADD = $(qemu_LDADDS)

qemumonitorjsontest_SOURCES = \
	qemumonitorjsontest.c \
	testutils.c testutils.h \
	testutilsqemu.c testutilsqemu.h \
	$(NULL)
qemumonitorjsontest_LDADD = $(qemu_LDADDS) libqemumonitortestutils.la

qemuhotplugtest_SOURCES = \
	qemuhotplugtest.c \
	testutils.c testutils.h \
	testutilsqemu.c testutilsqemu.h \
	$(NULL)
qemuhotplugtest_LDADD = $(qemu_LDADDS) libqemumonitortestutils.la

domainsnapshotxml2xmltest_SOURCES = \
	domainsnapshotxml2xmltest.c testutilsqemu.c testutilsqemu.h \
	testutils.c testutils.h
domainsnapshotxml2xmltest_LDADD = $(qemu_LDADDS)
else
EXTRA_DIST += qemuxml2argvtest.c qemuxml2xmltest.c qemuargv2xmltest.c \
	qemuxmlnstest.c qemuhelptest.c domainsnapshotxml2xmltest.c \
	qemumonitortest.c testutilsqemu.c testutilsqemu.h \
	qemumonitorjsontest.c qemuhotplugtest.c \
	$(QEMUMONITORTESTUTILS_SOURCES)
endif

if WITH_LXC

lxc_LDADDS = ../src/libvirt_driver_lxc_impl.la
if WITH_NETWORK
lxc_LDADDS += ../src/libvirt_driver_network_impl.la
endif
lxc_LDADDS += $(LDADDS)

lxcxml2xmltest_SOURCES = \
	lxcxml2xmltest.c testutilslxc.c testutilslxc.h \
	testutils.c testutils.h
lxcxml2xmltest_LDADD = $(lxc_LDADDS)
else
EXTRA_DIST += lxcxml2xmltest.c testutilslxc.c testutilslxc.h
endif

if WITH_OPENVZ
openvzutilstest_SOURCES = \
	openvzutilstest.c \
	testutils.c testutils.h
openvzutilstest_LDADD = $(LDADDS)
else
EXTRA_DIST += openvzutilstest.c
endif
EXTRA_DIST += openvzutilstest.conf

if WITH_ESX
esxutilstest_SOURCES = \
	esxutilstest.c \
	testutils.c testutils.h
esxutilstest_LDADD = $(LDADDS)
else
EXTRA_DIST += esxutilstest.c
endif

if WITH_VMX
vmx2xmltest_SOURCES = \
	vmx2xmltest.c \
	testutils.c testutils.h
vmx2xmltest_LDADD = $(LDADDS)

xml2vmxtest_SOURCES = \
	xml2vmxtest.c \
	testutils.c testutils.h
xml2vmxtest_LDADD = $(LDADDS)
else
EXTRA_DIST += vmx2xmltest.c xml2vmxtest.c
endif

networkxml2xmltest_SOURCES = \
	networkxml2xmltest.c \
	testutils.c testutils.h
networkxml2xmltest_LDADD = $(LDADDS)

if WITH_NETWORK
networkxml2conftest_SOURCES = \
	networkxml2conftest.c \
	testutils.c testutils.h
networkxml2conftest_LDADD = ../src/libvirt_driver_network_impl.la $(LDADDS)
else
EXTRA_DIST += networkxml2conftest.c
endif

if WITH_STORAGE_SHEEPDOG
storagebackendsheepdogtest_SOURCES = \
	storagebackendsheepdogtest.c \
	testutils.c testutils.h
storagebackendsheepdogtest_LDADD = \
	../src/libvirt_driver_storage_impl.la $(LDADDS)
else
EXTRA_DIST += storagebackendsheepdogtest.c
endif

nwfilterxml2xmltest_SOURCES = \
	nwfilterxml2xmltest.c \
	testutils.c testutils.h
nwfilterxml2xmltest_LDADD = $(LDADDS)

if WITH_STORAGE
storagevolxml2argvtest_SOURCES = \
    storagevolxml2argvtest.c \
    testutils.c testutils.h
storagevolxml2argvtest_LDADD = \
	../src/libvirt_driver_storage_impl.la $(LDADDS)
else
EXTRA_DIST += storagevolxml2argvtest.c
endif

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

test_conf_SOURCES = \
	test_conf.c
test_conf_LDADD = $(LDADDS)

nodeinfotest_SOURCES = \
	nodeinfotest.c testutils.h testutils.c
nodeinfotest_LDADD = $(LDADDS)

commandtest_SOURCES = \
	commandtest.c testutils.h testutils.c
commandtest_LDADD = $(LDADDS)

commandhelper_SOURCES = \
	commandhelper.c
commandhelper_LDADD = $(LDADDS)
commandhelper_LDFLAGS = -static

if WITH_LIBVIRTD
libvirtdconftest_SOURCES = \
	libvirtdconftest.c testutils.h testutils.c \
	../daemon/libvirtd-config.c
libvirtdconftest_LDADD = $(LDADDS)
else
EXTRA_DIST += libvirtdconftest.c
endif

virnetmessagetest_SOURCES = \
	virnetmessagetest.c testutils.h testutils.c
virnetmessagetest_CFLAGS = $(XDR_CFLAGS) $(AM_CFLAGS)
virnetmessagetest_LDADD = $(LDADDS)

virnetsockettest_SOURCES = \
	virnetsockettest.c testutils.h testutils.c
virnetsockettest_LDADD = $(LDADDS)

if WITH_GNUTLS
virnettlscontexttest_SOURCES = \
	virnettlscontexttest.c testutils.h testutils.c
virnettlscontexttest_LDADD = $(LDADDS)
if HAVE_LIBTASN1
virnettlscontexttest_SOURCES += pkix_asn1_tab.c
virnettlscontexttest_LDADD += -ltasn1
else
EXTRA_DIST += pkix_asn1_tab.c
endif
else
EXTRA_DIST += \
	virnettlscontexttest.c testutils.h testutils.c pkix_asn1_tab.c
endif

virtimetest_SOURCES = \
	virtimetest.c testutils.h testutils.c
virtimetest_LDADD = $(LDADDS)

virstringtest_SOURCES = \
	virstringtest.c testutils.h testutils.c
virstringtest_LDADD = $(LDADDS)

virstoragetest_SOURCES = \
	virstoragetest.c testutils.h testutils.c
virstoragetest_LDADD = $(LDADDS)

viridentitytest_SOURCES = \
	viridentitytest.c testutils.h testutils.c
viridentitytest_LDADD = $(LDADDS)

virkeycodetest_SOURCES = \
	virkeycodetest.c testutils.h testutils.c
virkeycodetest_LDADD = $(LDADDS)

virlockspacetest_SOURCES = \
	virlockspacetest.c testutils.h testutils.c
virlockspacetest_LDADD = $(LDADDS)

virportallocatortest_SOURCES = \
	virportallocatortest.c testutils.h testutils.c
virportallocatortest_LDADD = $(LDADDS)

libvirportallocatormock_la_SOURCES = \
	virportallocatortest.c
libvirportallocatormock_la_CFLAGS = $(AM_CFLAGS) -DMOCK_HELPER=1
libvirportallocatormock_la_LDFLAGS = -module -avoid-version \
        -rpath /evil/libtool/hack/to/force/shared/lib/creation

vircgrouptest_SOURCES = \
	vircgrouptest.c testutils.h testutils.c
vircgrouptest_LDADD = $(LDADDS)

vircgroupmock_la_SOURCES = \
	vircgroupmock.c
vircgroupmock_la_CFLAGS = $(AM_CFLAGS)
vircgroupmock_la_LDFLAGS = -module -avoid-version \
        -rpath /evil/libtool/hack/to/force/shared/lib/creation

if WITH_DBUS
virdbustest_SOURCES = \
	virdbustest.c testutils.h testutils.c
virdbustest_CFLAGS = $(AM_CFLAGS) $(DBUS_CFLAGS)
virdbustest_LDADD = $(LDADDS)

virsystemdtest_SOURCES = \
	virsystemdtest.c testutils.h testutils.c
virsystemdtest_CFLAGS = $(AM_CFLAGS)
virsystemdtest_LDADD = $(LDADDS)

virsystemdmock_la_SOURCES = \
	virsystemdmock.c
virsystemdmock_la_CFLAGS = $(AM_CFLAGS) $(DBUS_CFLAGS)
virsystemdmock_la_LDFLAGS = -module -avoid-version \
        -rpath /evil/libtool/hack/to/force/shared/lib/creation

else
EXTRA_DIST += virdbustest.c virsystemdtest.c virsystemdmock.c
endif

viruritest_SOURCES = \
	viruritest.c testutils.h testutils.c
viruritest_LDADD = $(LDADDS)

virkeyfiletest_SOURCES = \
	virkeyfiletest.c testutils.h testutils.c
virkeyfiletest_LDADD = $(LDADDS)

virauthconfigtest_SOURCES = \
	virauthconfigtest.c testutils.h testutils.c
virauthconfigtest_LDADD = $(LDADDS)

seclabeltest_SOURCES = \
	seclabeltest.c
seclabeltest_LDADD = $(LDADDS)

if WITH_SECDRIVER_SELINUX
if WITH_TESTS
noinst_LTLIBRARIES += libsecurityselinuxhelper.la
else
check_LTLIBRARIES += libsecurityselinuxhelper.la
endif

libsecurityselinuxhelper_la_SOURCES = \
	securityselinuxhelper.c
libsecurityselinuxhelper_la_LDFLAGS = -module -avoid-version \
        -rpath /evil/libtool/hack/to/force/shared/lib/creation

securityselinuxtest_SOURCES = \
	securityselinuxtest.c testutils.h testutils.c
securityselinuxtest_LDADD = $(LDADDS)
securityselinuxtest_DEPENDENCIES = libsecurityselinuxhelper.la \
	../src/libvirt.la

if WITH_QEMU
if WITH_ATTR
securityselinuxlabeltest_SOURCES = \
	securityselinuxlabeltest.c testutils.h testutils.c \
        testutilsqemu.h testutilsqemu.c
securityselinuxlabeltest_LDADD = $(qemu_LDADDS)
securityselinuxlabeltest_DEPENDENCIES = libsecurityselinuxhelper.la \
	../src/libvirt.la
endif
endif
endif
EXTRA_DIST += securityselinuxtest.c securityselinuxlabeltest.c \
	securityselinuxhelper.c

virbuftest_SOURCES = \
	virbuftest.c testutils.h testutils.c
virbuftest_LDADD = $(LDADDS)

virhashtest_SOURCES = \
	virhashtest.c virhashdata.h testutils.h testutils.c
virhashtest_LDADD = $(LDADDS)

viratomictest_SOURCES = \
	viratomictest.c testutils.h testutils.c
viratomictest_LDADD = $(LDADDS)

virbitmaptest_SOURCES = \
	virbitmaptest.c testutils.h testutils.c
virbitmaptest_LDADD = $(LDADDS)

virendiantest_SOURCES = \
	virendiantest.c testutils.h testutils.c
virendiantest_LDADD = $(LDADDS)

jsontest_SOURCES = \
	jsontest.c testutils.h testutils.c
jsontest_LDADD = $(LDADDS)

utiltest_SOURCES = \
	utiltest.c testutils.h testutils.c
utiltest_LDADD = $(LDADDS)

if WITH_DRIVER_MODULES
virdrivermoduletest_SOURCES = \
	virdrivermoduletest.c testutils.h testutils.c
virdrivermoduletest_LDADD = $(LDADDS)
endif

if WITH_LIBVIRTD
eventtest_SOURCES = \
	eventtest.c testutils.h testutils.c
eventtest_LDADD = -lrt $(LDADDS)
endif

libshunload_la_SOURCES = shunloadhelper.c
libshunload_la_LIBADD = ../src/libvirt.la
libshunload_la_LDFLAGS = -module -avoid-version \
	-rpath /evil/libtool/hack/to/force/shared/lib/creation

shunloadtest_SOURCES = \
	shunloadtest.c
shunloadtest_LDADD = $(LIB_PTHREAD)
shunloadtest_DEPENDENCIES = libshunload.la

sysinfotest_SOURCES = \
	sysinfotest.c testutils.h testutils.c
sysinfotest_LDADD = $(LDADDS)

fdstreamtest_SOURCES = \
	fdstreamtest.c testutils.h testutils.c
fdstreamtest_LDADD = $(LDADDS)

fchosttest_SOURCES = \
       fchosttest.c testutils.h testutils.c
fchosttest_LDADD = $(LDADDS)

if WITH_CIL
CILOPTFLAGS =
CILOPTINCS =
CILOPTPACKAGES = -package unix,str,cil
CILOPTLIBS = -linkpkg

object_locking_SOURCES = object-locking.ml

%.cmx: %.ml
	ocamlfind ocamlopt $(CILOPTFLAGS) $(CILOPTINCS) $(CILOPTPACKAGES) -c $<

object-locking: object-locking.cmx object-locking-files.txt
	ocamlfind ocamlopt $(CILOPTFLAGS) $(CILOPTINCS) $(CILOPTPACKAGES) \
	  $(CILOPTLIBS) $< -o $@

object-locking-files.txt:
	find $(top_builddir)/src/ -name '*.i' > $@

else
EXTRA_DIST += object-locking.ml
endif

CLEANFILES = *.cov *.gcov .libs/*.gcda .libs/*.gcno *.gcno *.gcda *.cmi *.cmx \
	object-locking-files.txt
