## Process this file with automake to produce Makefile.in

LCOV = lcov
GENHTML = genhtml

SUBDIRS = gnulib/lib include src qemud proxy docs gnulib/tests \
  python tests po

ACLOCAL_AMFLAGS = -I m4 -I gnulib/m4

EXTRA_DIST = \
  libvirt.spec libvirt.spec.in \
  libvirt.pc libvirt.pc.in \
  $(man_MANS) autobuild.sh \
  .x-sc_avoid_if_before_free \
  .x-sc_prohibit_strcmp \
  .x-sc_require_config_h \
  autogen.sh

man_MANS = virsh.1

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libvirt.pc

rpm: clean
	@(unset CDPATH ; $(MAKE) dist && rpmbuild -ta $(distdir).tar.gz)

check-local: all tests

tests:
	@(cd docs/examples ; $(MAKE) MAKEFLAGS+=--silent tests)
	@(if [ "$(pythondir)" != "" ] ; then cd python ; \
	  $(MAKE) MAKEFLAGS+=--silent tests ; fi)

cov: clean-cov
	mkdir $(top_builddir)/coverage
	$(LCOV) -c -o $(top_builddir)/coverage/libvirt.info.tmp -d $(top_srcdir)/src  -d $(top_srcdir)/qemud -d $(top_srcdir)/tests
	$(LCOV) -r $(top_builddir)/coverage/libvirt.info.tmp -o $(top_builddir)/coverage/libvirt.info *usr*
	rm $(top_builddir)/coverage/libvirt.info.tmp
	$(GENHTML) -s -t "libvirt" -o $(top_builddir)/coverage --legend $(top_builddir)/coverage/libvirt.info

clean-cov:
	rm -rf $(top_builddir)/coverage

# disable this check
distuninstallcheck:
