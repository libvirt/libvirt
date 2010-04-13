## Process this file with automake to produce Makefile.in

virincdir = $(includedir)/libvirt

virinc_HEADERS = libvirt.h		\
		 libvirt-qemu.h		\
		 virterror.h

install-exec-hook:
	$(mkinstalldirs) $(DESTDIR)$(virincdir)

EXTRA_DIST = libvirt.h.in
