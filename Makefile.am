## Process this file with automake to produce Makefile.in

LCOV = lcov
GENHTML = genhtml

SUBDIRS = gnulib/lib include src daemon tools proxy docs gnulib/tests \
  python tests po examples/domain-events/events-c examples/hellolibvirt \
  examples/dominfo examples/domsuspend examples/python examples/apparmor \
  examples/xml/nwfilter

ACLOCAL_AMFLAGS = -I m4 -I gnulib/m4

XML_EXAMPLES = \
  $(patsubst $(srcdir)/%,%,$(wildcard $(addprefix $(srcdir)/examples/xml/, \
					test/*.xml storage/*.xml)))

EXTRA_DIST = \
  ChangeLog-old \
  libvirt.spec libvirt.spec.in \
  mingw32-libvirt.spec.in \
  libvirt.pc libvirt.pc.in \
  autobuild.sh \
  .x-sc_avoid_ctype_macros \
  .x-sc_avoid_if_before_free \
  .x-sc_avoid_write \
  .x-sc_m4_quote_check \
  .x-sc_prohibit_asprintf \
  .x-sc_prohibit_gethostby \
  .x-sc_prohibit_gethostname \
  .x-sc_prohibit_have_config_h \
  .x-sc_prohibit_HAVE_MBRTOWC \
  .x-sc_prohibit_nonreentrant \
  .x-sc_prohibit_strcmp \
  .x-sc_prohibit_strcmp_and_strncmp \
  .x-sc_prohibit_strncpy \
  .x-sc_prohibit_VIR_ERR_NO_MEMORY \
  .x-sc_require_config_h \
  .x-sc_require_config_h_first \
  .x-sc_trailing_blank \
  Makefile.nonreentrant \
  autogen.sh \
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


rpm: clean
	@(unset CDPATH ; $(MAKE) dist && rpmbuild -ta $(distdir).tar.gz)

check-local: all tests

tests:
	@(cd docs/examples ; $(MAKE) MAKEFLAGS+=--silent tests)
	@(if [ "$(pythondir)" != "" ] ; then cd python ; \
	  $(MAKE) MAKEFLAGS+=--silent tests ; fi)

cov: clean-cov
	mkdir $(top_builddir)/coverage
	$(LCOV) -c -o $(top_builddir)/coverage/libvirt.info.tmp -d $(top_srcdir)/src  -d $(top_srcdir)/daemon -d $(top_srcdir)/tests
	$(LCOV) -r $(top_builddir)/coverage/libvirt.info.tmp -o $(top_builddir)/coverage/libvirt.info *usr*
	rm $(top_builddir)/coverage/libvirt.info.tmp
	$(GENHTML) -s -t "libvirt" -o $(top_builddir)/coverage --legend $(top_builddir)/coverage/libvirt.info

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
