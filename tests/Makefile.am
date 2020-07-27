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

TESTS = $(test_scripts)

VALGRIND = valgrind --quiet --leak-check=full --trace-children=yes \
	--trace-children-skip="*/tools/virsh","*/tests/commandhelper","/usr/bin/*" \
	--suppressions=$(abs_srcdir)/.valgrind.supp
valgrind:
	$(MAKE) check VG="$(LIBTOOL) --mode=execute $(VALGRIND)"
