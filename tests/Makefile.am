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

if WITH_VBOX
test_programs += vboxsnapshotxmltest
endif WITH_VBOX

if WITH_VMX
test_programs += vmx2xmltest xml2vmxtest
endif WITH_VMX

if WITH_VMWARE
test_programs += vmwarevertest
endif WITH_VMWARE

if WITH_YAJL
test_programs += virjsontest
endif WITH_YAJL

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

if WITH_NSS
test_helpers += nsslinktest nssguestlinktest
test_programs += nsstest nssguesttest
endif WITH_NSS

if WITH_NODE_DEVICES
test_programs += nodedevmdevctltest
endif WITH_NODE_DEVICES

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
endif WITH_LIBVIRTD

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

if WITH_NODE_DEVICES
nodedevmdevctltest_SOURCES = \
	nodedevmdevctltest.c \
	testutils.c testutils.h

nodedevmdevctltest_LDADD = \
	../src/libvirt_driver_nodedev_impl.la \
	$(LDADDS)
endif WITH_NODE_DEVICES

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

virjsontest_SOURCES = \
	virjsontest.c testutils.h testutils.c
virjsontest_LDADD = $(LDADDS)
