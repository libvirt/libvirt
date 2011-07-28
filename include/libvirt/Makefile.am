## Process this file with automake to produce Makefile.in

## Copyright (C) 2005-2011 Red Hat, Inc.
## See COPYING.LIB for the License of this software

virincdir = $(includedir)/libvirt

virinc_HEADERS = libvirt.h		\
		 libvirt-qemu.h		\
		 virterror.h

install-exec-hook:
	$(mkinstalldirs) $(DESTDIR)$(virincdir)

EXTRA_DIST = libvirt.h.in
