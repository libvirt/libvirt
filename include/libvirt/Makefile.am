## Process this file with automake to produce Makefile.in

## Copyright (C) 2005-2011, 2013-2015 Red Hat, Inc.
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

virincdir = $(includedir)/libvirt

virinc_HEADERS = libvirt.h		\
		 libvirt-domain.h \
		 libvirt-domain-snapshot.h \
		 libvirt-event.h \
		 libvirt-host.h \
		 libvirt-interface.h \
		 libvirt-network.h \
		 libvirt-nodedev.h \
		 libvirt-nwfilter.h \
		 libvirt-secret.h \
		 libvirt-storage.h \
		 libvirt-stream.h \
		 libvirt-lxc.h		\
		 libvirt-qemu.h		\
		 virterror.h

install-exec-hook:
	$(mkinstalldirs) $(DESTDIR)$(virincdir)

EXTRA_DIST = libvirt.h.in

# Temporarily disabled, but we need it for building
EXTRA_DIST += libvirt-admin.h
