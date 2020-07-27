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

if WITH_QEMU
test_helpers += qemucapsprobe
endif WITH_QEMU

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

if WITH_STORAGE_SHEEPDOG
test_programs += storagebackendsheepdogtest
endif WITH_STORAGE_SHEEPDOG

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
endif WITH_NSS

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

if WITH_QEMU
qemucapsprobe_SOURCES = \
	qemucapsprobe.c
qemucapsprobe_LDADD = \
	libqemutestdriver.la $(LDADDS)
endif WITH_QEMU

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

if WITH_STORAGE_SHEEPDOG
storagebackendsheepdogtest_SOURCES = \
	storagebackendsheepdogtest.c \
	testutils.c testutils.h
storagebackendsheepdogtest_LDADD = \
	../src/libvirt_storage_backend_sheepdog_priv.la \
	../src/libvirt_driver_storage_impl.la \
	$(LDADDS)
endif WITH_STORAGE_SHEEPDOG

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
