## Process this file with automake to produce Makefile.in

## Copyright (C) 2005-2013 Red Hat, Inc.
##
## This library is free software; you can redistribute it and/or
## modify it under the terms of the GNU Lesser General Public
## License as published by the Free Software Foundation; either
## version 2.1 of the License, or (at your option) any later version.
##
## This library is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## Lesser General Public License for more details.
##
## You should have received a copy of the GNU Lesser General Public
## License along with this library.  If not, see
## <http://www.gnu.org/licenses/>.

LCOV = lcov
GENHTML = genhtml

SUBDIRS = . gnulib/lib include src daemon tools docs gnulib/tests \
  tests po examples/object-events examples/hellolibvirt \
  examples/dominfo examples/domsuspend examples/apparmor \
  examples/xml/nwfilter examples/openauth examples/systemtap \
  tools/wireshark

ACLOCAL_AMFLAGS = -I m4

XML_EXAMPLES = \
  $(patsubst $(srcdir)/%,%,$(wildcard $(addprefix $(srcdir)/examples/xml/, \
					test/*.xml storage/*.xml)))

EXTRA_DIST = \
  config-post.h \
  ChangeLog-old \
  libvirt.spec libvirt.spec.in \
  mingw-libvirt.spec.in \
  libvirt.pc.in \
  autobuild.sh \
  Makefile.nonreentrant \
  autogen.sh \
  cfg.mk \
  run.in \
  AUTHORS.in \
  $(XML_EXAMPLES)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libvirt.pc

NEWS: $(top_srcdir)/docs/news.xsl $(top_srcdir)/docs/news.html.in
	$(AM_V_GEN)if [ -x $(XSLTPROC) ] ; then			\
	  $(XSLTPROC) --nonet $(top_srcdir)/docs/news.xsl	\
	     $(top_srcdir)/docs/news.html.in			\
	   | perl -0777 -pe 's/\n\n+$$/\n/'			\
	   | perl -pe 's/[ \t]+$$//'				\
	   > $@-t && mv $@-t $@ ; fi

$(top_srcdir)/HACKING: $(top_srcdir)/docs/hacking1.xsl \
			$(top_srcdir)/docs/hacking2.xsl \
			$(top_srcdir)/docs/wrapstring.xsl \
			$(top_srcdir)/docs/hacking.html.in
	$(AM_V_GEN)if [ -x $(XSLTPROC) ] ; then \
	   $(XSLTPROC) --nonet $(top_srcdir)/docs/hacking1.xsl \
		$(top_srcdir)/docs/hacking.html.in | \
	   $(XSLTPROC) --nonet $(top_srcdir)/docs/hacking2.xsl - \
	   | perl -0777 -pe 's/\n\n+$$/\n/' \
	   > $@-t && mv $@-t $@ ; fi;

rpm: clean
	@(unset CDPATH ; $(MAKE) dist && rpmbuild -ta $(distdir).tar.gz)

check-local: all tests

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

dist-hook: gen-ChangeLog gen-AUTHORS

# Generate the ChangeLog file (with all entries since the switch to git)
# and insert it into the directory we're about to use to create a tarball.
gen_start_date = 2009-07-04
.PHONY: gen-ChangeLog
gen-ChangeLog:
	$(AM_V_GEN)if test -d .git; then			\
	  $(top_srcdir)/build-aux/gitlog-to-changelog		\
	    --since=$(gen_start_date) > $(distdir)/cl-t;	\
	  rm -f $(distdir)/ChangeLog;				\
	  mv $(distdir)/cl-t $(distdir)/ChangeLog;		\
	fi

.PHONY: gen-AUTHORS
gen-AUTHORS:
	$(AM_V_GEN)if test -d $(srcdir)/.git; then \
	    out="`cd $(srcdir) && git log --pretty=format:'%aN <%aE>' | sort -u`" && \
	    perl -p -e "s/#authorslist#// and print '$$out'" \
	      < $(srcdir)/AUTHORS.in > $(distdir)/AUTHORS-tmp && \
	    mv -f $(distdir)/AUTHORS-tmp $(distdir)/AUTHORS ; \
	fi
