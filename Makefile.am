## Process this file with automake to produce Makefile.in

SUBDIRS = src include docs @PYTHON_SUBDIR@ tests proxy po

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = libvirt.spec.in libvirt.spec COPYING.LIB \
             libvirt.pc.in libvirt.pc TODO AUTHORS ChangeLog \
	     NEWS README $(man_MANS)

man_MANS = virsh.1

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libvirt.pc

rpm: clean
	@(unset CDPATH ; $(MAKE) dist && rpmbuild -ta $(distdir).tar.gz)

check-local: all tests

tests:
	@(cd docs/examples ; $(MAKE) MAKEFLAGS+=--silent tests)
	@(if [ "@PYTHON_SUBDIR@" != "" ] ; then cd python ; \
	  $(MAKE) MAKEFLAGS+=--silent tests ; fi)	
