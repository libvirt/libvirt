## Process this file with automake to produce Makefile.in

SUBDIRS = gnulib/lib include src qemud proxy docs gnulib/tests \
  python tests po scripts

ACLOCAL_AMFLAGS = -I m4 -I gnulib/m4

EXTRA_DIST = libvirt.spec.in libvirt.spec COPYING.LIB \
             libvirt.pc.in libvirt.pc TODO AUTHORS ChangeLog \
	     NEWS README $(man_MANS) autobuild.sh

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

cov: cov-recursive cov-am

clean-cov:
	rm -rf $(top_builddir)/coverage
	cd src && $(MAKE) $(AM_MAKEFLAGS) clean-cov

cov-recursive:
	cd src && $(MAKE) $(AM_MAKEFLAGS) cov

cov-am:
	rm -rf $(top_builddir)/coverage
	mkdir $(top_builddir)/coverage
	perl $(srcdir)/scripts/coverage-report.pl src/*.cov > $(top_builddir)/coverage/index.xml
	xsltproc $(srcdir)/scripts/coverage-report.xsl \
	  $(top_builddir)/coverage/index.xml \
	  > $(top_builddir)/coverage/index.html
	for i in $(top_builddir)/src/*.gcov ; do o=`echo $$i | sed -e 's,$(top_builddir)/src,coverage,'` ; \
	  perl $(srcdir)/scripts/coverage-report-entry.pl $$i > $$o.html ; done

# disable this check
distuninstallcheck:
