## Copyright (C) 2005-2011, 2013 Red Hat, Inc.
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

EXTRA_DIST=				\
	TEMPLATE			\
	libvirt-qemu			\
	libvirt-lxc 			\
	usr.lib.libvirt.virt-aa-helper	\
	usr.sbin.libvirtd

if WITH_APPARMOR_PROFILES
apparmordir = $(sysconfdir)/apparmor.d/
apparmor_DATA = \
	usr.lib.libvirt.virt-aa-helper \
	usr.sbin.libvirtd \
	$(NULL)

abstractionsdir = $(apparmordir)/abstractions
abstractions_DATA = \
	libvirt-qemu \
	libvirt-lxc \
	$(NULL)

templatesdir = $(apparmordir)/libvirt
templates_DATA = \
	TEMPLATE \
	$(NULL)
endif WITH_APPARMOR_PROFILES
