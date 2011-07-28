## Process this file with automake to produce Makefile.in

## Copyright (C) 2005-2011 Red Hat, Inc.
## See COPYING.LIB for the License of this software

LCOV = lcov
GENHTML = genhtml

SUBDIRS = gnulib/lib include src daemon tools docs gnulib/tests \
  python tests po examples/domain-events/events-c examples/hellolibvirt \
  examples/dominfo examples/domsuspend examples/python examples/apparmor \
  examples/xml/nwfilter examples/openauth examples/systemtap

ACLOCAL_AMFLAGS = -I m4 -I gnulib/m4

XML_EXAMPLES = \
  $(patsubst $(srcdir)/%,%,$(wildcard $(addprefix $(srcdir)/examples/xml/, \
					test/*.xml storage/*.xml)))

EXTRA_DIST = \
  ChangeLog-old \
  libvirt.spec libvirt.spec.in \
  mingw32-libvirt.spec.in \
  libvirt.pc.in \
  autobuild.sh \
  Makefile.nonreentrant \
  autogen.sh \
  cfg.mk \
  examples/domain-events/events-python \
  $(XML_EXAMPLES)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libvirt.pc

NEWS: $(top_srcdir)/docs/news.xsl $(top_srcdir)/docs/news.html.in
	-@(if [ -x $(XSLTPROC) ] ; then				\
	  $(XSLTPROC) --nonet $(top_srcdir)/docs/news.xsl	\
	     $(top_srcdir)/docs/news.html.in			\
	   | perl -0777 -pe 's/\n\n+$$/\n/'			\
	   | perl -pe 's/[ \t]+$$//'				\
	   > $@-t && mv $@-t $@ ; fi );

$(top_srcdir)/HACKING: $(top_srcdir)/docs/hacking1.xsl $(top_srcdir)/docs/hacking2.xsl \
                       $(top_srcdir)/docs/wrapstring.xsl $(top_srcdir)/docs/hacking.html.in
	-@(if [ -x $(XSLTPROC) ] ; then \
	   $(XSLTPROC) --nonet $(top_srcdir)/docs/hacking1.xsl $(top_srcdir)/docs/hacking.html.in | \
	   $(XSLTPROC) --nonet $(top_srcdir)/docs/hacking2.xsl - \
	   | perl -0777 -pe 's/\n\n+$$/\n/' \
	   > $@-t && mv $@-t $@ ; fi );

rpm: clean
	@(unset CDPATH ; $(MAKE) dist && rpmbuild -ta $(distdir).tar.gz)

check-local: all tests

tests:
	@(cd docs/examples ; $(MAKE) MAKEFLAGS+=--silent tests)
	@(if [ "$(pythondir)" != "" ] ; then cd python ; \
	  $(MAKE) MAKEFLAGS+=--silent tests ; fi)

cov: clean-cov
	mkdir $(top_builddir)/coverage
	$(LCOV) -c -o $(top_builddir)/coverage/libvirt.info.tmp \
	  -d $(top_builddir)/src  -d $(top_builddir)/daemon \
	  -d $(top_builddir)/tests
	$(LCOV) -r $(top_builddir)/coverage/libvirt.info.tmp \
	  -o $(top_builddir)/coverage/libvirt.info
	rm $(top_builddir)/coverage/libvirt.info.tmp
	$(GENHTML) --show-details -t "libvirt" -o $(top_builddir)/coverage \
	  --legend $(top_builddir)/coverage/libvirt.info

clean-cov:
	rm -rf $(top_builddir)/coverage

MAINTAINERCLEANFILES = .git-module-status

# disable this check
distuninstallcheck:

dist-hook: gen-ChangeLog

# Generate the ChangeLog file (with all entries since the switch to git)
# and insert it into the directory we're about to use to create a tarball.
gen_start_date = 2009-07-04
.PHONY: gen-ChangeLog
gen-ChangeLog:
	if test -d .git; then					\
	  $(top_srcdir)/build-aux/gitlog-to-changelog		\
	    --since=$(gen_start_date) > $(distdir)/cl-t;	\
	  rm -f $(distdir)/ChangeLog;				\
	  mv $(distdir)/cl-t $(distdir)/ChangeLog;		\
	fi
