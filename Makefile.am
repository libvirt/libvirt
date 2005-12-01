## Process this file with automake to produce Makefile.in

SUBDIRS = src include docs
EXTRA_DIST = libxen.spec.in libxen.spec COPYING.LIB \
             libxen.pc.in libxen.pc TODO AUTHORS ChangeLog \
	     NEWS README 

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libxen.pc

rpm: clean
	@(unset CDPATH ; $(MAKE) dist && rpmbuild -ta $(distdir).tar.gz)
