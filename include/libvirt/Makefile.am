## Process this file with automake to produce Makefile.in

virincdir = $(includedir)/libvirt

virinc_HEADERS = libvirt.h

install-exec-hook:
	$(mkinstalldirs) $(DESTDIR)$(virincdir)

EXTRA_DIST = libvirt.h.in
