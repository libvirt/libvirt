## Process this file with automake to produce Makefile.in

## Copyright (C) 2005-2019 Red Hat, Inc.
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

PROBES_O =
if WITH_DTRACE_PROBES
PROBES_O += ../src/libvirt_probes.lo
endif WITH_DTRACE_PROBES

LDADDS = \
	$(NO_INDIRECT_LDFLAGS) \
	$(PROBES_O) \
	../src/libvirt.la \
	$(GLIB_LIBS) \
	$(NULL)

test_programs = virshtest sockettest \
	virhostcputest virbuftest \
	commandtest seclabeltest \
	virhashtest virconftest \
	utiltest shunloadtest \
	virtimetest viruritest \
	viralloctest \
	virauthconfigtest \
	virbitmaptest \
	vircgrouptest \
	vircryptotest \
	virpcitest \
	virendiantest \
	virfiletest \
	virfilecachetest \
	virfirewalltest \
	viriscsitest \
	virkeycodetest \
	virlockspacetest \
	virlogtest \
	virrotatingfiletest \
	virschematest \
	virstringtest \
	virportallocatortest \
	sysinfotest \
	virkmodtest \
	vircapstest \
	domaincapstest \
	domainconftest \
	virhostdevtest \
	virnetdevtest \
	virtypedparamtest \
	vshtabletest \
	virerrortest \
	$(NULL)

if WITH_REMOTE
test_programs += \
	virnetmessagetest \
	virnetsockettest \
	virnetdaemontest \
	virnetserverclienttest \
	virnettlscontexttest \
	virnettlssessiontest \
	$(NULL)
endif WITH_REMOTE

if WITH_LINUX
test_programs += fchosttest
test_programs += scsihosttest
test_programs += vircaps2xmltest
test_programs += virresctrltest
endif WITH_LINUX

if WITH_LIBVIRTD
test_programs += fdstreamtest
endif WITH_LIBVIRTD

if WITH_DBUS
test_programs += virdbustest \
                 virsystemdtest \
                 $(NULL)
if WITH_POLKIT
test_programs += virpolkittest
endif WITH_POLKIT
endif WITH_DBUS

if WITH_SECDRIVER_SELINUX
if WITH_ATTR
test_programs += securityselinuxtest \
                 viridentitytest
if WITH_QEMU
test_programs += securityselinuxlabeltest
endif WITH_QEMU
endif WITH_ATTR
endif WITH_SECDRIVER_SELINUX

if WITH_LIBXL
test_programs += xlconfigtest \
	xmconfigtest libxlxml2domconfigtest
endif WITH_LIBXL

if WITH_QEMU
test_programs += qemuxml2argvtest qemuxml2xmltest \
	qemudomaincheckpointxml2xmltest qemudomainsnapshotxml2xmltest \
	qemumonitorjsontest qemuhotplugtest \
	qemuagenttest qemucapabilitiestest qemucaps2xmltest \
	qemumemlocktest \
	qemucommandutiltest \
	qemublocktest \
	qemumigparamstest \
	qemusecuritytest \
	qemufirmwaretest \
	qemuvhostusertest \
	$(NULL)
test_helpers += qemucapsprobe
endif WITH_QEMU

if WITH_LXC
test_programs += lxcxml2xmltest lxcconf2xmltest
endif WITH_LXC

if WITH_OPENVZ
test_programs += openvzutilstest
endif WITH_OPENVZ

if WITH_ESX
test_programs += esxutilstest
endif WITH_ESX

if WITH_VBOX
test_programs += vboxsnapshotxmltest
endif WITH_VBOX

if WITH_VMX
test_programs += vmx2xmltest xml2vmxtest
endif WITH_VMX

if WITH_VMWARE
test_programs += vmwarevertest
endif WITH_VMWARE

if WITH_BHYVE
test_programs += bhyvexml2argvtest bhyvexml2xmltest bhyveargv2xmltest
endif WITH_BHYVE

if WITH_YAJL
test_programs += virjsontest
endif WITH_YAJL

test_programs += \
		networkxml2xmlupdatetest \
		virnetworkportxml2xmltest \
		$(NULL)

if WITH_NETWORK
test_programs += \
		networkxml2xmltest \
		networkxml2conftest \
		networkxml2firewalltest \
		$(NULL)
endif WITH_NETWORK

if WITH_STORAGE_SHEEPDOG
test_programs += storagebackendsheepdogtest
endif WITH_STORAGE_SHEEPDOG

test_programs += nwfilterxml2xmltest
test_programs += virnwfilterbindingxml2xmltest

if WITH_NWFILTER
test_programs += nwfilterebiptablestest
test_programs += nwfilterxml2firewalltest
endif WITH_NWFILTER

if WITH_STORAGE
test_programs += storagevolxml2argvtest
test_programs += storagepoolxml2argvtest
test_programs += virstorageutiltest
test_programs += storagepoolxml2xmltest
test_programs += storagepoolcapstest
endif WITH_STORAGE

if WITH_STORAGE_FS
test_programs += virstoragetest
endif WITH_STORAGE_FS

if WITH_LINUX
test_programs += virscsitest
endif WITH_LINUX

if WITH_NSS
test_helpers += nsslinktest nssguestlinktest
test_programs += nsstest nssguesttest
endif WITH_NSS

test_programs += storagevolxml2xmltest

test_programs += nodedevxml2xmltest

if WITH_NODE_DEVICES
test_programs += nodedevmdevctltest
endif WITH_NODE_DEVICES

test_programs += interfacexml2xmltest

test_programs += cputest

test_programs += metadatatest

test_programs += secretxml2xmltest

test_programs += genericxml2xmltest

if WITH_LINUX
test_programs += virusbtest \
	virnetdevbandwidthtest \
	$(NULL)
endif WITH_LINUX

test_scripts =
libvirtd_test_scripts = \
	libvirtd-fail \
	libvirtd-pool \
	virsh-auth \
	virsh-cpuset \
	virsh-define-dev-segfault \
	virsh-int-overflow \
	virsh-optparse \
	virsh-read-bufsiz \
	virsh-read-non-seekable \
	virsh-schedinfo \
	virsh-self-test \
	virt-admin-self-test \
	virsh-checkpoint \
	virsh-snapshot \
	virsh-start \
	virsh-undefine \
	virsh-uriprecedence \
	virsh-vcpupin \
	$(NULL)

if WITH_LIBVIRTD
test_scripts += $(libvirtd_test_scripts)

test_programs += \
	eventtest \
	virdrivermoduletest \
	virdriverconnvalidatetest
endif WITH_LIBVIRTD

test_programs += objecteventtest

if WITH_SECDRIVER_APPARMOR
if WITH_LIBVIRTD
test_scripts += virt-aa-helper-test
endif WITH_LIBVIRTD
endif WITH_SECDRIVER_APPARMOR

if WITH_LINUX
check-access: file-access-clean
	VIR_TEST_FILE_ACCESS=1 $(MAKE) $(AM_MAKEFLAGS) check
	$(RUNUTF8) $(PYTHON) $(top_srcdir)/scripts/check-file-access.py \
		$(abs_builddir)/test_file_access.txt \
		$(abs_srcdir)/permitted_file_access.txt | sort -u

file-access-clean:
	> test_file_access.txt
endif WITH_LINUX

noinst_PROGRAMS = $(test_programs) $(test_helpers)

TESTS = $(test_programs) \
	$(test_scripts)

VALGRIND = valgrind --quiet --leak-check=full --trace-children=yes \
	--trace-children-skip="*/tools/virsh","*/tests/commandhelper","/usr/bin/*" \
	--suppressions=$(abs_srcdir)/.valgrind.supp
valgrind:
	$(MAKE) check VG="$(LIBTOOL) --mode=execute $(VALGRIND)"

sockettest_SOURCES = \
	sockettest.c \
	testutils.c testutils.h
sockettest_LDADD = $(LDADDS)

if WITH_LIBXL
libxl_LDADDS = \
	../src/libvirt_driver_libxl_impl.la \
	$(LDADDS) \
	$(NULL)

xlconfigtest_SOURCES = \
	xlconfigtest.c testutilsxen.c testutilsxen.h \
	testutils.c testutils.h
xlconfigtest_LDADD = libxltestdriver.la \
	$(libxl_LDADDS)

xmconfigtest_SOURCES = \
	xmconfigtest.c testutilsxen.c testutilsxen.h \
	testutils.c testutils.h
xmconfigtest_LDADD = libxltestdriver.la \
	$(libxl_LDADDS)

libxlxml2domconfigtest_SOURCES = \
	libxlxml2domconfigtest.c testutilsxen.c testutilsxen.h \
	testutils.c testutils.h
libxlxml2domconfigtest_LDADD = libxltestdriver.la \
	$(libxl_LDADDS) $(LIBXML_LIBS)
endif WITH_LIBXL

if WITH_QEMU

qemu_LDADDS = ../src/libvirt_driver_qemu_impl.la
if WITH_DTRACE_PROBES
qemu_LDADDS += ../src/libvirt_qemu_probes.lo
endif WITH_DTRACE_PROBES
qemu_LDADDS += $(LDADDS)

qemuxml2argvtest_SOURCES = \
	qemuxml2argvtest.c testutilsqemu.c testutilsqemu.h \
	testutils.c testutils.h \
	virfilewrapper.c virfilewrapper.h \
	$(NULL)
qemuxml2argvtest_LDADD = libqemutestdriver.la libqemumonitortestutils.la \
	$(LDADDS) $(LIBXML_LIBS)

qemuxml2xmltest_SOURCES = \
	qemuxml2xmltest.c testutilsqemu.c testutilsqemu.h \
	testutils.c testutils.h \
	virfilewrapper.c virfilewrapper.h
qemuxml2xmltest_LDADD = $(qemu_LDADDS)

qemumonitorjsontest_SOURCES = \
	qemumonitorjsontest.c \
	testutils.c testutils.h \
	testutilsqemu.c testutilsqemu.h \
	$(NULL)
qemumonitorjsontest_LDADD = libqemumonitortestutils.la \
	$(qemu_LDADDS)

qemucapabilitiestest_SOURCES = \
	qemucapabilitiestest.c \
	testutils.c testutils.h \
	testutilsqemu.c testutilsqemu.h \
	$(NULL)
qemucapabilitiestest_LDADD = libqemumonitortestutils.la \
	$(qemu_LDADDS)

qemucapsprobe_SOURCES = \
	qemucapsprobe.c
qemucapsprobe_LDADD = \
	libqemutestdriver.la $(LDADDS)

qemucommandutiltest_SOURCES = \
	qemucommandutiltest.c \
	testutils.c testutils.h \
	testutilsqemu.c testutilsqemu.h \
	$(NULL)
qemucommandutiltest_LDADD = libqemumonitortestutils.la \
	$(qemu_LDADDS)

qemucaps2xmltest_SOURCES = \
	qemucaps2xmltest.c \
	testutils.c testutils.h \
	testutilsqemu.c testutilsqemu.h \
	$(NULL)
qemucaps2xmltest_LDADD = $(qemu_LDADDS)

qemuagenttest_SOURCES = \
	qemuagenttest.c \
	testutils.c testutils.h \
	testutilsqemu.c testutilsqemu.h \
	$(NULL)
qemuagenttest_LDADD = libqemumonitortestutils.la $(qemu_LDADDS)

qemuhotplugtest_SOURCES = \
	qemuhotplugtest.c \
	testutils.c testutils.h \
	testutilsqemu.c testutilsqemu.h \
	$(NULL)
qemuhotplugtest_LDADD = \
	libqemutestdriver.la \
	libqemumonitortestutils.la \
	$(qemu_LDADDS) \
	$(NULL)

qemublocktest_SOURCES = \
	qemublocktest.c \
	testutils.h testutils.c \
	testutilsqemu.h testutilsqemu.c \
	$(NULL)
qemublocktest_LDADD = \
	libqemumonitortestutils.la \
	../src/libvirt.la \
	$(qemu_LDADDS) \
	$(NULL)

qemudomaincheckpointxml2xmltest_SOURCES = \
	qemudomaincheckpointxml2xmltest.c testutilsqemu.c testutilsqemu.h \
	testutils.c testutils.h
qemudomaincheckpointxml2xmltest_LDADD = $(qemu_LDADDS)

qemudomainsnapshotxml2xmltest_SOURCES = \
	qemudomainsnapshotxml2xmltest.c testutilsqemu.c testutilsqemu.h \
	testutils.c testutils.h
qemudomainsnapshotxml2xmltest_LDADD = $(qemu_LDADDS)

qemumemlocktest_SOURCES = \
	qemumemlocktest.c \
	testutilsqemu.c testutilsqemu.h \
	testutils.c testutils.h
qemumemlocktest_LDADD = $(qemu_LDADDS)

qemumigparamstest_SOURCES = \
	qemumigparamstest.c \
	testutils.c testutils.h \
	testutilsqemu.c testutilsqemu.h \
	$(NULL)
qemumigparamstest_LDADD = libqemumonitortestutils.la \
	$(qemu_LDADDS)

qemusecuritytest_SOURCES = \
	qemusecuritytest.c qemusecuritytest.h \
	qemusecuritymock.c \
	testutils.h testutils.c \
	testutilsqemu.h testutilsqemu.c
qemusecuritytest_LDADD = $(qemu_LDADDS)

qemufirmwaretest_SOURCES = \
	qemufirmwaretest.c \
	testutils.h testutils.c \
	virfilewrapper.c virfilewrapper.h \
	$(NULL)
qemufirmwaretest_LDADD = $(qemu_LDADDS)

qemuvhostusertest_SOURCES = \
	qemuvhostusertest.c \
	testutils.h testutils.c \
	virfilewrapper.c virfilewrapper.h \
	$(NULL)
qemuvhostusertest_LDADD = $(qemu_LDADDS)
endif WITH_QEMU

if WITH_LXC

lxc_LDADDS = \
	../src/libvirt_driver_lxc_impl.la \
	$(LDADDS) \
	$(NULL)

lxcxml2xmltest_SOURCES = \
	lxcxml2xmltest.c testutilslxc.c testutilslxc.h \
	testutils.c testutils.h
lxcxml2xmltest_LDADD = $(lxc_LDADDS)

lxcconf2xmltest_SOURCES = \
	lxcconf2xmltest.c testutilslxc.c testutilslxc.h \
	testutils.c testutils.h
lxcconf2xmltest_LDADD = $(lxc_LDADDS)
endif WITH_LXC

if WITH_OPENVZ
openvzutilstest_SOURCES = \
	openvzutilstest.c \
	testutils.c testutils.h
openvzutilstest_LDADD = $(LDADDS) \
	../src/libvirt_driver_openvz.la
endif WITH_OPENVZ

if WITH_ESX
esxutilstest_SOURCES = \
	esxutilstest.c \
	testutils.c testutils.h
esxutilstest_LDADD = $(LDADDS)
esxutilstest_CFLAGS = \
	-I$(top_builddir)/src/esx \
	$(AM_CFLAGS)
endif WITH_ESX

if WITH_VBOX
vboxsnapshotxmltest_SOURCES = \
	vboxsnapshotxmltest.c \
	testutils.c testutils.h
vbox_LDADDS = ../src/libvirt_driver_vbox_impl.la
vboxsnapshotxmltest_LDADD = $(LDADDS) $(vbox_LDADDS)
endif WITH_VBOX

if WITH_VMX
vmx2xmltest_SOURCES = \
	vmx2xmltest.c \
	testutils.c testutils.h
vmx2xmltest_LDADD = $(LDADDS)

xml2vmxtest_SOURCES = \
	xml2vmxtest.c \
	testutils.c testutils.h
xml2vmxtest_LDADD = $(LDADDS)
endif WITH_VMX

if WITH_VMWARE
vmwarevertest_SOURCES = \
    vmwarevertest.c \
    testutils.c testutils.h
vmwarevertest_LDADD = $(LDADDS)
endif WITH_VMWARE

if WITH_BHYVE
bhyve_LDADDS = \
	../src/libvirt_driver_bhyve_impl.la \
	$(LDADDS) \
	$(NULL)
bhyvexml2argvtest_SOURCES = \
	bhyvexml2argvtest.c \
	testutils.c testutils.h
bhyvexml2argvtest_LDADD = $(bhyve_LDADDS)

bhyvexml2xmltest_SOURCES = \
	bhyvexml2xmltest.c \
	testutils.c testutils.h
bhyvexml2xmltest_LDADD = $(bhyve_LDADDS)

bhyveargv2xmltest_SOURCES = \
	bhyveargv2xmltest.c \
	testutils.c testutils.h
bhyveargv2xmltest_LDADD = $(bhyve_LDADDS)
endif WITH_BHYVE

networkxml2xmlupdatetest_SOURCES = \
	networkxml2xmlupdatetest.c \
	testutils.c testutils.h
networkxml2xmlupdatetest_LDADD = $(LDADDS)

virnetworkportxml2xmltest_SOURCES = \
	virnetworkportxml2xmltest.c \
	testutils.c testutils.h
virnetworkportxml2xmltest_LDADD = $(LDADDS)

if WITH_NETWORK
networkxml2xmltest_SOURCES = \
	networkxml2xmltest.c \
	testutils.c testutils.h
networkxml2xmltest_LDADD = ../src/libvirt_driver_network_impl.la $(LDADDS)

networkxml2conftest_SOURCES = \
	networkxml2conftest.c \
	testutils.c testutils.h
networkxml2conftest_LDADD = ../src/libvirt_driver_network_impl.la $(LDADDS)

networkxml2firewalltest_SOURCES = \
	networkxml2firewalltest.c \
	testutils.c testutils.h
networkxml2firewalltest_LDADD = ../src/libvirt_driver_network_impl.la $(LDADDS)
endif WITH_NETWORK

if WITH_STORAGE_SHEEPDOG
storagebackendsheepdogtest_SOURCES = \
	storagebackendsheepdogtest.c \
	testutils.c testutils.h
storagebackendsheepdogtest_LDADD = \
	../src/libvirt_storage_backend_sheepdog_priv.la \
	../src/libvirt_driver_storage_impl.la \
	$(LDADDS)
endif WITH_STORAGE_SHEEPDOG

nwfilterxml2xmltest_SOURCES = \
	nwfilterxml2xmltest.c \
	testutils.c testutils.h
nwfilterxml2xmltest_LDADD = $(LDADDS)

virnwfilterbindingxml2xmltest_SOURCES = \
	virnwfilterbindingxml2xmltest.c \
	testutils.c testutils.h
virnwfilterbindingxml2xmltest_LDADD = $(LDADDS)

if WITH_NWFILTER
nwfilterebiptablestest_SOURCES = \
	nwfilterebiptablestest.c \
	testutils.c testutils.h
nwfilterebiptablestest_LDADD = ../src/libvirt_driver_nwfilter_impl.la $(LDADDS)

nwfilterxml2firewalltest_SOURCES = \
	nwfilterxml2firewalltest.c \
	testutils.c testutils.h
nwfilterxml2firewalltest_LDADD = \
	../src/libvirt_driver_nwfilter_impl.la $(LDADDS)
endif WITH_NWFILTER

secretxml2xmltest_SOURCES = \
	secretxml2xmltest.c \
	testutils.c testutils.h
secretxml2xmltest_LDADD = $(LDADDS)

genericxml2xmltest_SOURCES = \
	genericxml2xmltest.c \
	testutils.c testutils.h
genericxml2xmltest_LDADD = $(LDADDS)


if WITH_STORAGE
virstorageutiltest_SOURCES = \
	virstorageutiltest.c \
	testutils.c \
	testutils.h \
	$(NULL)
virstorageutiltest_LDADD = \
	../src/libvirt_driver_storage_impl.la \
	$(LDADDS) \
	$(NULL)

storagevolxml2argvtest_SOURCES = \
    storagevolxml2argvtest.c \
    testutils.c testutils.h
storagevolxml2argvtest_LDADD = \
	$(LIBXML_LIBS) \
	../src/libvirt_driver_storage_impl.la \
	../src/libvirt.la \
	$(LDADDS)

storagepoolxml2argvtest_SOURCES = \
    storagepoolxml2argvtest.c \
    testutils.c testutils.h
storagepoolxml2argvtest_LDADD = \
	$(LIBXML_LIBS) \
	../src/libvirt_driver_storage_impl.la \
	../src/libvirt.la \
	$(LDADDS)

storagepoolxml2xmltest_SOURCES = \
	storagepoolxml2xmltest.c \
	testutils.c testutils.h
storagepoolxml2xmltest_LDADD = $(LDADDS) \
	../src/libvirt_driver_storage_impl.la

storagepoolcapstest_SOURCES = \
        storagepoolcapstest.c testutils.h testutils.c
storagepoolcapstest_LDADD = $(LDADDS)
endif WITH_STORAGE

storagevolxml2xmltest_SOURCES = \
	storagevolxml2xmltest.c \
	testutils.c testutils.h
storagevolxml2xmltest_LDADD = $(LDADDS)

nodedevxml2xmltest_SOURCES = \
	nodedevxml2xmltest.c \
	testutils.c testutils.h
nodedevxml2xmltest_LDADD = $(LDADDS)

if WITH_NODE_DEVICES
nodedevmdevctltest_SOURCES = \
	nodedevmdevctltest.c \
	testutils.c testutils.h

nodedevmdevctltest_LDADD = \
	../src/libvirt_driver_nodedev_impl.la \
	$(LDADDS)
endif WITH_NODE_DEVICES

interfacexml2xmltest_SOURCES = \
	interfacexml2xmltest.c \
	testutils.c testutils.h
interfacexml2xmltest_LDADD = $(LDADDS)

cputest_SOURCES = \
	cputest.c \
	testutils.c testutils.h
cputest_LDADD = $(LIBXML_LIBS)
if WITH_QEMU
cputest_SOURCES += testutilsqemu.c testutilsqemu.h
cputest_LDADD += libqemumonitortestutils.la $(qemu_LDADDS)
else ! WITH_QEMU
cputest_LDADD += $(LDADDS)
endif ! WITH_QEMU

metadatatest_SOURCES = \
	metadatatest.c \
	testutils.c testutils.h
metadatatest_LDADD = $(LDADDS) $(LIBXML_LIBS)

virerrortest_SOURCES = \
	virerrortest.c \
	testutils.c testutils.h
virerrortest_LDADD = $(LDADDS)

vshtabletest_SOURCES = \
	vshtabletest.c \
	testutils.c testutils.h
vshtabletest_LDADD = \
	$(LDADDS) \
	../tools/libvirt_shell.la

virshtest_SOURCES = \
	virshtest.c \
	testutils.c testutils.h
virshtest_LDADD = $(LDADDS)

virconftest_SOURCES = \
	virconftest.c testutils.h testutils.c
virconftest_LDADD = $(LDADDS)

virhostcputest_SOURCES = \
	virhostcputest.c testutils.h testutils.c virfilewrapper.h virfilewrapper.c
virhostcputest_LDADD = $(LDADDS)

commandtest_SOURCES = \
	commandtest.c testutils.h testutils.c
commandtest_LDADD = $(LDADDS)

virkmodtest_SOURCES = \
	virkmodtest.c testutils.h testutils.c
virkmodtest_LDADD = $(LDADDS)

vircapstest_SOURCES = \
	vircapstest.c testutils.h testutils.c
if WITH_LXC
vircapstest_SOURCES += testutilslxc.c testutilslxc.h
endif WITH_LXC
if WITH_QEMU
vircapstest_SOURCES += testutilsqemu.c testutilsqemu.h
endif WITH_QEMU
vircapstest_LDADD =
if WITH_QEMU
vircapstest_LDADD += ../src/libvirt_driver_qemu_impl.la
if WITH_DTRACE_PROBES
vircapstest_LDADD += ../src/libvirt_qemu_probes.lo
endif WITH_DTRACE_PROBES
endif WITH_QEMU
if WITH_LXC
vircapstest_LDADD += ../src/libvirt_driver_lxc_impl.la
endif WITH_LXC
vircapstest_LDADD += $(LDADDS)

domaincapstest_SOURCES = \
	domaincapstest.c testutils.h testutils.c \
	virfilewrapper.c virfilewrapper.h \
	$(NULL)
domaincapstest_LDADD = $(LDADDS)

if WITH_QEMU
domaincapstest_SOURCES += testutilsqemu.c testutilsqemu.h
domaincapstest_LDADD += libqemutestdriver.la
endif WITH_QEMU

if WITH_LIBXL
domaincapstest_SOURCES += testutilsxen.c testutilsxen.h
domaincapstest_LDADD += libxltestdriver.la
endif WITH_LIBXL

if WITH_BHYVE
domaincapstest_LDADD += ../src/libvirt_driver_bhyve_impl.la
endif WITH_BHYVE

virnetmessagetest_SOURCES = \
	virnetmessagetest.c testutils.h testutils.c
virnetmessagetest_LDADD = $(LDADDS)

virnetsockettest_SOURCES = \
	virnetsockettest.c testutils.h testutils.c
virnetsockettest_LDADD = $(LDADDS)

virnetdaemontest_SOURCES = \
	virnetdaemontest.c \
	testutils.h testutils.c
virnetdaemontest_LDADD = $(LDADDS)

virnetserverclienttest_SOURCES = \
	virnetserverclienttest.c \
	testutils.h testutils.c
virnetserverclienttest_LDADD = $(LDADDS)

virnettlscontexttest_SOURCES = \
	virnettlscontexttest.c \
	virnettlshelpers.h virnettlshelpers.c \
	testutils.h testutils.c
virnettlscontexttest_LDADD = $(LDADDS) $(GNUTLS_LIBS)
virnettlssessiontest_SOURCES = \
	virnettlssessiontest.c \
	virnettlshelpers.h virnettlshelpers.c \
	testutils.h testutils.c
virnettlssessiontest_LDADD = $(LDADDS) $(GNUTLS_LIBS)
if HAVE_LIBTASN1
virnettlscontexttest_SOURCES += pkix_asn1_tab.c
virnettlscontexttest_LDADD += -ltasn1
virnettlssessiontest_SOURCES += pkix_asn1_tab.c
virnettlssessiontest_LDADD += -ltasn1
endif HAVE_LIBTASN1

virtimetest_SOURCES = \
	virtimetest.c testutils.h testutils.c
virtimetest_LDADD = $(LDADDS)

virschematest_SOURCES = \
	virschematest.c testutils.h testutils.c
virschematest_LDADD = $(LDADDS) $(LIBXML_LIBS)

virstringtest_SOURCES = \
	virstringtest.c testutils.h testutils.c
virstringtest_LDADD = $(LDADDS)

virstoragetest_SOURCES = \
	virstoragetest.c testutils.h testutils.c
virstoragetest_LDADD = $(LDADDS) \
	../src/libvirt.la \
	../src/libvirt_driver_storage_impl.la \
	$(NULL)

viridentitytest_SOURCES = \
	viridentitytest.c testutils.h testutils.c
viridentitytest_LDADD = $(LDADDS)
if WITH_SELINUX
viridentitytest_LDADD += $(SELINUX_LIBS)
viridentitytest_DEPENDENCIES = libsecurityselinuxhelper.la \
	../src/libvirt.la
endif WITH_SELINUX

viriscsitest_SOURCES = \
	viriscsitest.c testutils.h testutils.c
viriscsitest_LDADD = $(LDADDS)

virkeycodetest_SOURCES = \
	virkeycodetest.c testutils.h testutils.c
virkeycodetest_LDADD = $(LDADDS)

virlockspacetest_SOURCES = \
	virlockspacetest.c testutils.h testutils.c
virlockspacetest_LDADD = $(LDADDS)

virlogtest_SOURCES = \
	virlogtest.c testutils.h testutils.c
virlogtest_LDADD = $(LDADDS)

virportallocatortest_SOURCES = \
	virportallocatortest.c testutils.h testutils.c
virportallocatortest_LDADD = $(LDADDS)

vircgrouptest_SOURCES = \
	vircgrouptest.c testutils.h testutils.c
vircgrouptest_LDADD = $(LDADDS)

vircryptotest_SOURCES = \
	vircryptotest.c testutils.h testutils.c
vircryptotest_LDADD = $(LDADDS)

virhostdevtest_SOURCES = \
	virhostdevtest.c testutils.h testutils.c
virhostdevtest_LDADD = $(LDADDS)

virpcitest_SOURCES = \
	virpcitest.c testutils.h testutils.c
virpcitest_LDADD = $(LDADDS)

if WITH_LINUX
vircaps2xmltest_SOURCES = \
	vircaps2xmltest.c testutils.h testutils.c virfilewrapper.h virfilewrapper.c
vircaps2xmltest_LDADD = $(LDADDS)

virresctrltest_SOURCES = \
	virresctrltest.c testutils.h testutils.c virfilewrapper.h virfilewrapper.c
virresctrltest_LDADD = $(LDADDS)
endif WITH_LINUX

if WITH_NSS
nsstest_SOURCES = \
	nsstest.c testutils.h testutils.c
nsstest_CFLAGS = \
	$(AM_CFLAGS) \
	-I$(top_srcdir)/tools/nss
nsstest_LDADD = \
	$(LDADDS) \
	../tools/nss/libnss_libvirt_impl.la

nssguesttest_SOURCES = \
	nsstest.c testutils.h testutils.c
nssguesttest_CFLAGS = \
	-DLIBVIRT_NSS_GUEST \
	$(AM_CFLAGS) \
	-I$(top_srcdir)/tools/nss
nssguesttest_LDADD = \
	$(LDADDS) \
	../tools/nss/libnss_libvirt_guest_impl.la

## Intentionaly not linking with anything else.
## See the test source for more detailed explanation.
nsslinktest_SOURCES = nsslinktest.c
nsslinktest_CFLAGS = \
	$(AM_CFLAGS) \
	-I$(top_srcdir)/tools/nss
nsslinktest_LDADD = ../tools/nss/libnss_libvirt_impl.la
nsslinktest_LDFLAGS = $(NULL)

nssguestlinktest_SOURCES = nsslinktest.c
nssguestlinktest_CFLAGS = \
	-DLIBVIRT_NSS_GUEST \
	$(AM_CFLAGS) \
	-I$(top_srcdir)/tools/nss
nssguestlinktest_LDADD = ../tools/nss/libnss_libvirt_guest_impl.la
nssguestlinktest_LDFLAGS = $(NULL)
endif WITH_NSS

if WITH_YAJL
virmacmaptest_SOURCES = \
	virmacmaptest.c testutils.h testutils.c
virmacmaptest_LDADD = $(LDADDS)

virnetdevopenvswitchtest_SOURCES = \
	virnetdevopenvswitchtest.c testutils.h testutils.c
virnetdevopenvswitchtest_LDADD = $(LDADDS)

test_programs += \
	virmacmaptest \
	virnetdevopenvswitchtest
endif WITH_YAJL

virnetdevtest_SOURCES = \
	virnetdevtest.c testutils.h testutils.c
virnetdevtest_CFLAGS = $(AM_CFLAGS) $(LIBNL_CFLAGS)
virnetdevtest_LDADD = $(LDADDS)

virrotatingfiletest_SOURCES = \
	virrotatingfiletest.c testutils.h testutils.c
virrotatingfiletest_LDADD = $(LDADDS)

if WITH_LINUX
virusbtest_SOURCES = \
	virusbtest.c testutils.h testutils.c
virusbtest_LDADD = $(LDADDS)

virnetdevbandwidthtest_SOURCES = \
	virnetdevbandwidthtest.c testutils.h testutils.c
virnetdevbandwidthtest_LDADD = $(LDADDS) $(LIBXML_LIBS)
endif WITH_LINUX

if WITH_DBUS
virdbustest_SOURCES = \
	virdbustest.c testutils.h testutils.c
virdbustest_CFLAGS = $(AM_CFLAGS) $(DBUS_CFLAGS)
virdbustest_LDADD = $(LDADDS) $(DBUS_LIBS)

virpolkittest_SOURCES = \
	virpolkittest.c testutils.h testutils.c
virpolkittest_CFLAGS = $(AM_CFLAGS) $(DBUS_CFLAGS)
virpolkittest_LDADD = $(LDADDS) $(DBUS_LIBS)

virsystemdtest_SOURCES = \
	virsystemdtest.c testutils.h testutils.c
virsystemdtest_CFLAGS = $(AM_CFLAGS) $(DBUS_CFLAGS)
virsystemdtest_LDADD = $(LDADDS) $(DBUS_LIBS)
endif WITH_DBUS

viruritest_SOURCES = \
	viruritest.c testutils.h testutils.c
viruritest_LDADD = $(LDADDS)

viralloctest_SOURCES = \
	viralloctest.c testutils.h testutils.c
viralloctest_LDADD = $(LDADDS)

virauthconfigtest_SOURCES = \
	virauthconfigtest.c testutils.h testutils.c
virauthconfigtest_LDADD = $(LDADDS)

seclabeltest_SOURCES = \
	seclabeltest.c testutils.h testutils.c
seclabeltest_LDADD = $(LDADDS)

if WITH_SECDRIVER_SELINUX
if WITH_ATTR

securityselinuxtest_SOURCES = \
	securityselinuxtest.c testutils.h testutils.c
securityselinuxtest_LDADD = $(LDADDS) $(SELINUX_LIBS)
securityselinuxtest_DEPENDENCIES = libsecurityselinuxhelper.la \
	../src/libvirt.la

if WITH_QEMU
securityselinuxlabeltest_SOURCES = \
	securityselinuxlabeltest.c testutils.h testutils.c \
        testutilsqemu.h testutilsqemu.c
securityselinuxlabeltest_LDADD = $(qemu_LDADDS) $(SELINUX_LIBS)
securityselinuxlabeltest_DEPENDENCIES = libsecurityselinuxhelper.la \
	../src/libvirt.la
endif WITH_QEMU
endif WITH_ATTR
endif WITH_SECDRIVER_SELINUX

virbuftest_SOURCES = \
	virbuftest.c testutils.h testutils.c
virbuftest_LDADD = $(LDADDS)

virhashtest_SOURCES = \
	virhashtest.c virhashdata.h testutils.h testutils.c
virhashtest_LDADD = $(LDADDS)

virbitmaptest_SOURCES = \
	virbitmaptest.c testutils.h testutils.c
virbitmaptest_LDADD = $(LDADDS)

virendiantest_SOURCES = \
	virendiantest.c testutils.h testutils.c
virendiantest_LDADD = $(LDADDS)

virfiletest_SOURCES = \
	virfiletest.c testutils.h testutils.c
virfiletest_LDADD = $(LDADDS)

virfilecachetest_SOURCES = \
	virfilecachetest.c testutils.h testutils.c
virfilecachetest_LDADD = $(LDADDS)

virfirewalltest_SOURCES = \
	virfirewalltest.c testutils.h testutils.c
virfirewalltest_LDADD = $(LDADDS) $(DBUS_LIBS)
virfirewalltest_CFLAGS = $(AM_CFLAGS) $(DBUS_CFLAGS)

virjsontest_SOURCES = \
	virjsontest.c testutils.h testutils.c
virjsontest_LDADD = $(LDADDS)

utiltest_SOURCES = \
	utiltest.c testutils.h testutils.c
utiltest_LDADD = $(LDADDS)

if WITH_LIBVIRTD
virdrivermoduletest_SOURCES = \
	virdrivermoduletest.c testutils.h testutils.c
virdrivermoduletest_LDADD = $(LDADDS)

virdriverconnvalidatetest_SOURCES = \
	virdriverconnvalidatetest.c testutils.h testutils.c
virdriverconnvalidatetest_LDADD = $(LDADDS)
endif WITH_LIBVIRTD

if WITH_LIBVIRTD
eventtest_SOURCES = \
	eventtest.c testutils.h testutils.c
eventtest_LDADD = $(LDADDS)
endif WITH_LIBVIRTD

shunloadtest_SOURCES = \
	shunloadtest.c
shunloadtest_LDADD = $(THREAD_LIBS) $(DLOPEN_LIBS)
shunloadtest_DEPENDENCIES = libshunload.la

sysinfotest_SOURCES = \
	sysinfotest.c testutils.h testutils.c
sysinfotest_LDADD = $(LDADDS)

domainconftest_SOURCES = \
	domainconftest.c testutils.h testutils.c
domainconftest_LDADD = $(LDADDS)

fdstreamtest_SOURCES = \
	fdstreamtest.c testutils.h testutils.c
fdstreamtest_LDADD = $(LDADDS)

objecteventtest_SOURCES = \
	objecteventtest.c \
	testutils.c testutils.h
objecteventtest_LDADD = $(LDADDS)

virtypedparamtest_SOURCES = \
	virtypedparamtest.c testutils.h testutils.c
virtypedparamtest_LDADD = $(LDADDS)


if WITH_LINUX
fchosttest_SOURCES = \
       fchosttest.c testutils.h testutils.c
fchosttest_LDADD = $(LDADDS)

scsihosttest_SOURCES = \
       scsihosttest.c testutils.h testutils.c
scsihosttest_LDADD = $(LDADDS)
endif WITH_LINUX

if WITH_LINUX
virscsitest_SOURCES = \
       virscsitest.c testutils.h testutils.c
virscsitest_LDADD = $(LDADDS)
endif WITH_LINUX
