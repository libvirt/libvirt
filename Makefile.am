## Process this file with automake to produce Makefile.in

SUBDIRS = src include docs @PYTHON_SUBDIR@

EXTRA_DIST = libvir.spec.in libvir.spec COPYING.LIB \
             libvir.pc.in libvir.pc TODO AUTHORS ChangeLog \
	     NEWS README 

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libvir.pc

rpm: clean
	@(unset CDPATH ; $(MAKE) dist && rpmbuild -ta $(distdir).tar.gz)
