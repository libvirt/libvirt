## Process this file with automake to produce Makefile.in

## Copyright (C) 2005-2016 Red Hat, Inc.
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

PERL = perl

# The directory containing the source code (if it contains documentation).
DOC_SOURCE_DIR=../src

DEVHELP_DIR=$(datadir)/gtk-doc/html/libvirt

apihtml =					\
  html/index.html				\
  $(apihtml_generated)

apihtml_generated = \
  html/libvirt-libvirt-domain.html		\
  html/libvirt-libvirt-domain-snapshot.html	\
  html/libvirt-libvirt-event.html		\
  html/libvirt-libvirt-host.html		\
  html/libvirt-libvirt-interface.html		\
  html/libvirt-libvirt-network.html		\
  html/libvirt-libvirt-nodedev.html		\
  html/libvirt-libvirt-nwfilter.html		\
  html/libvirt-libvirt-secret.html		\
  html/libvirt-libvirt-storage.html		\
  html/libvirt-libvirt-stream.html		\
  html/libvirt-virterror.html

apipng =	\
  html/left.png	\
  html/up.png	\
  html/home.png	\
  html/right.png

devhelphtml =			\
  devhelp/libvirt.devhelp	\
  devhelp/index.html		\
  devhelp/general.html		\
  devhelp/libvirt-virterror.html

css =         \
  generic.css \
  libvirt.css \
  main.css

devhelppng =		\
  devhelp/home.png	\
  devhelp/left.png	\
  devhelp/right.png	\
  devhelp/up.png

devhelpcss = devhelp/style.css

devhelpxsl = devhelp/devhelp.xsl devhelp/html.xsl

png = \
  32favicon.png \
  footer_corner.png \
  footer_pattern.png \
  libvirt-header-bg.png \
  libvirt-header-logo.png \
  libvirtLogo.png \
  libvirt-net-logical.png \
  libvirt-net-physical.png \
  libvirt-daemon-arch.png \
  libvirt-driver-arch.png \
  libvirt-object-model.png \
  madeWith.png \
  et.png \
  migration-managed-direct.png \
  migration-managed-p2p.png \
  migration-native.png \
  migration-tunnel.png \
  migration-unmanaged-direct.png

gif = \
  architecture.gif \
  node.gif


internals_html_in = \
  $(patsubst $(srcdir)/%,%,$(wildcard $(srcdir)/internals/*.html.in))
internals_html = $(internals_html_in:%.html.in=%.html)

# todo.html is special - it is shipped in the tarball, but we
# have a dedicated 'todo' target to rebuild it from a proper
# config file, all other users are able to build it locally.
# For all other files, since we ship pre-built html in the
# tarball, we must also ship the sources, even when those
# sources are themselves generated.
dot_html_in = $(notdir $(wildcard $(srcdir)/*.html.in)) \
  todo.html.in \
  hvsupport.html.in
dot_html = $(dot_html_in:%.html.in=%.html)

dot_php_in = $(notdir $(wildcard $(srcdir)/*.php.in))
dot_php_code_in = $(dot_php_in:%.php.in=%.php.code.in)
dot_php = $(dot_php_in:%.php.in=%.php)

patches = $(patsubst $(srcdir)/%,%,$(wildcard $(srcdir)/api_extension/*.patch))

xml = \
  libvirt-api.xml \
  libvirt-refs.xml

qemu_xml = \
  libvirt-qemu-api.xml \
  libvirt-qemu-refs.xml

lxc_xml = \
  libvirt-lxc-api.xml \
  libvirt-lxc-refs.xml

admin_xml = \
  libvirt-admin-api.xml \
  libvirt-admin-refs.xml

apidir = $(pkgdatadir)/api
api_DATA = \
       libvirt-api.xml \
       libvirt-qemu-api.xml \
       libvirt-lxc-api.xml

fig = \
  libvirt-net-logical.fig \
  libvirt-net-physical.fig \
  libvirt-daemon-arch.fig \
  libvirt-driver-arch.fig \
  libvirt-object-model.fig \
  migration-managed-direct.fig \
  migration-managed-p2p.fig \
  migration-native.fig \
  migration-tunnel.fig \
  migration-unmanaged-direct.fig

schemadir = $(pkgdatadir)/schemas
schema_DATA = $(wildcard $(srcdir)/schemas/*.rng)

EXTRA_DIST=					\
  apibuild.py genaclperms.pl \
  site.xsl newapi.xsl news.xsl page.xsl \
  hacking1.xsl hacking2.xsl wrapstring.xsl \
  $(dot_html) $(dot_html_in) $(gif) $(apihtml) $(apipng) \
  $(devhelphtml) $(devhelppng) $(devhelpcss) $(devhelpxsl) \
  $(xml) $(qemu_xml) $(lxc_xml) $(fig) $(png) $(css) \
  $(patches) $(dot_php_in) $(dot_php_code_in) $(dot_php)\
  $(internals_html_in) $(internals_html) \
  sitemap.html.in aclperms.htmlinc \
  todo.pl hvsupport.pl todo.cfg-example \
  $(schema_DATA)

acl_generated = aclperms.htmlinc

$(srcdir)/aclperms.htmlinc: $(top_srcdir)/src/access/viraccessperm.h \
        $(srcdir)/genaclperms.pl Makefile.am
	$(AM_V_GEN)$(PERL) $(srcdir)/genaclperms.pl $< > $@

MAINTAINERCLEANFILES = \
  $(addprefix $(srcdir)/,$(dot_html)) \
  $(addprefix $(srcdir)/,$(apihtml)) \
  $(addprefix $(srcdir)/,$(devhelphtml)) \
  $(addprefix $(srcdir)/,$(internals_html)) \
  $(addprefix $(srcdir)/,$(dot_php)) \
  $(srcdir)/hvsupport.html.in $(srcdir)/aclperms.htmlinc

all-am: web

api: $(srcdir)/libvirt-api.xml $(srcdir)/libvirt-refs.xml
qemu_api: $(srcdir)/libvirt-qemu-api.xml $(srcdir)/libvirt-qemu-refs.xml
lxc_api: $(srcdir)/libvirt-lxc-api.xml $(srcdir)/libvirt-lxc-refs.xml
admin_api: $(srcdir)/libvirt-admin-api.xml $(srcdir)/libvirt-admin-refs.xml

web: $(dot_html) $(internals_html) html/index.html devhelp/index.html \
  $(dot_php)

todo.html.in: todo.pl
	if [ -f  todo.cfg ]; then \
		echo "Generating $@"; \
		$(PERL) $< > $@ \
		|| { rm $@ && exit 1; }; \
	else \
		echo "Stubbing $@"; \
		printf "%s\n" \
		  "<html xmlns=\"http://www.w3.org/1999/xhtml\">" \
		  "<body>" \
		  "<h1>Todo list unavailable: no config file</h1>" \
		  "</body></html>" > $@ ; \
	fi

todo:
	rm -f todo.html.in
	$(MAKE) todo.html

hvsupport.html: $(srcdir)/hvsupport.html.in

$(srcdir)/hvsupport.html.in: $(srcdir)/hvsupport.pl $(api_DATA) \
		$(top_srcdir)/src/libvirt_public.syms \
	$(top_srcdir)/src/libvirt_qemu.syms $(top_srcdir)/src/libvirt_lxc.syms \
	$(top_srcdir)/src/driver.h
	$(AM_V_GEN)$(PERL) $(srcdir)/hvsupport.pl $(top_srcdir)/src > $@ \
		|| { rm $@ && exit 1; }

.PHONY: todo

%.png: %.fig
	convert -rotate 90 $< $@

internals/%.html.tmp: internals/%.html.in subsite.xsl page.xsl sitemap.html.in
	@if [ -x $(XSLTPROC) ] ; then \
	  echo "Generating $@"; \
	  $(MKDIR_P) internals; \
	  name=`echo $@ | sed -e 's/.tmp//'`; \
	  $(XSLTPROC) --stringparam pagename $$name --nonet \
	    $(top_srcdir)/docs/subsite.xsl $< > $@ \
	    || { rm $@ && exit 1; }; fi

%.html.tmp: %.html.in site.xsl page.xsl sitemap.html.in $(acl_generated)
	@if [ -x $(XSLTPROC) ] ; then \
	  echo "Generating $@"; \
	  name=`echo $@ | sed -e 's/.tmp//'`; \
	  $(XSLTPROC) --stringparam pagename $$name --nonet \
	    $(top_srcdir)/docs/site.xsl $< > $@ \
	    || { rm $@ && exit 1; }; fi

%.html: %.html.tmp
	@if test -x $(XMLLINT) && test -x $(XMLCATALOG) ; then \
	  if $(XMLCATALOG) '$(XML_CATALOG_FILE)' \
	    "-//W3C//DTD XHTML 1.0 Strict//EN" > /dev/null ; then \
	  echo "Validating $@" ; \
	  SGML_CATALOG_FILES='$(XML_CATALOG_FILE)' \
	  $(XMLLINT) --catalogs --nonet --format --valid $< > $(srcdir)/$@ \
	  || { rm $(srcdir)/$@ && exit 1; }; \
	  else echo "missing XHTML1 DTD"; cat $< > $(srcdir)/$@ ; fi ; fi

%.php.tmp: %.php.in site.xsl page.xsl sitemap.html.in
	@if [ -x $(XSLTPROC) ] ; then \
	  echo "Generating $@"; \
	  $(XSLTPROC) --stringparam pagename $(@:.tmp=) --nonet \
	    $(top_srcdir)/docs/site.xsl $< > $@ \
	    || { rm $@ && exit 1; }; fi

%.php: %.php.tmp %.php.code.in
	@if [ -x $(XSLTPROC) ] ; then \
	  echo "Scripting $@"; \
	    sed -e '/<span id="php_placeholder"><\/span>/r '"$(srcdir)/$@.code.in" \
	    -e /php_placeholder/d < $@.tmp > $(srcdir)/$@ \
	    || { rm $(srcdir)/$@ && exit 1; }; fi

$(apihtml_generated): html/index.html

html/index.html: libvirt-api.xml newapi.xsl page.xsl sitemap.html.in
	$(AM_V_GEN)if [ -x $(XSLTPROC) ] ; then \
	  $(XSLTPROC) --nonet -o $(srcdir)/ \
	  --stringparam builddir '$(abs_top_builddir)' \
	  $(srcdir)/newapi.xsl $(srcdir)/libvirt-api.xml ; fi && \
	if test -x $(XMLLINT) && test -x $(XMLCATALOG) ; then \
	  if $(XMLCATALOG) '$(XML_CATALOG_FILE)' "-//W3C//DTD XHTML 1.0 Strict//EN" \
	    > /dev/null ; then \
	  SGML_CATALOG_FILES='$(XML_CATALOG_FILE)' \
	  $(XMLLINT) --catalogs --nonet --valid --noout $(srcdir)/html/*.html ; \
	  else echo "missing XHTML1 DTD"; cat $< > $(srcdir)/$@ ; fi ; fi

$(addprefix $(srcdir)/,$(devhelphtml)): $(srcdir)/libvirt-api.xml $(devhelpxsl)
	$(AM_V_GEN)if [ -x $(XSLTPROC) ] ; then \
	  $(XSLTPROC) --nonet -o $(srcdir)/devhelp/ \
	  $(top_srcdir)/docs/devhelp/devhelp.xsl $(srcdir)/libvirt-api.xml ; fi


python_generated_files = \
		$(srcdir)/html/libvirt-libvirt-lxc.html \
		$(srcdir)/html/libvirt-libvirt-qemu.html \
		$(srcdir)/html/libvirt-libvirt-admin.html \
		$(srcdir)/html/libvirt-virterror.html \
		$(srcdir)/libvirt-api.xml \
		$(srcdir)/libvirt-refs.xml \
		$(srcdir)/libvirt-lxc-api.xml \
		$(srcdir)/libvirt-lxc-refs.xml \
		$(srcdir)/libvirt-qemu-api.xml \
		$(srcdir)/libvirt-qemu-refs.xml \
		$(srcdir)/libvirt-admin-api.xml \
		$(srcdir)/libvirt-admin-refs.xml \
		$(NULL)

APIBUILD=$(srcdir)/apibuild.py
APIBUILD_STAMP=$(APIBUILD).stamp
EXTRA_DIST += $(APIBUILD_STAMP)

$(python_generated_files): $(APIBUILD_STAMP)

$(APIBUILD_STAMP): $(srcdir)/apibuild.py \
		$(top_srcdir)/include/libvirt/libvirt.h \
		$(top_srcdir)/include/libvirt/libvirt-common.h.in \
		$(top_srcdir)/include/libvirt/libvirt-domain-snapshot.h \
		$(top_srcdir)/include/libvirt/libvirt-domain.h \
		$(top_srcdir)/include/libvirt/libvirt-event.h \
		$(top_srcdir)/include/libvirt/libvirt-host.h \
		$(top_srcdir)/include/libvirt/libvirt-interface.h \
		$(top_srcdir)/include/libvirt/libvirt-network.h \
		$(top_srcdir)/include/libvirt/libvirt-nodedev.h \
		$(top_srcdir)/include/libvirt/libvirt-nwfilter.h \
		$(top_srcdir)/include/libvirt/libvirt-secret.h \
		$(top_srcdir)/include/libvirt/libvirt-storage.h \
		$(top_srcdir)/include/libvirt/libvirt-stream.h \
		$(top_srcdir)/include/libvirt/libvirt-lxc.h \
		$(top_srcdir)/include/libvirt/libvirt-qemu.h \
		$(top_srcdir)/include/libvirt/libvirt-admin.h \
		$(top_srcdir)/include/libvirt/virterror.h \
		$(top_srcdir)/src/libvirt.c \
		$(top_srcdir)/src/libvirt-lxc.c \
		$(top_srcdir)/src/libvirt-qemu.c \
		$(top_srcdir)/src/libvirt-admin.c \
		$(top_srcdir)/src/util/virerror.c \
		$(top_srcdir)/src/util/virevent.c \
		$(top_srcdir)/src/util/virtypedparam.c
	$(AM_V_GEN)srcdir=$(srcdir) $(PYTHON) $(APIBUILD)
	touch $@


check-local: all
dist-local: all

clean-local:
	rm -f *~ *.bak *.hierarchy *.signals *-unused.txt *.html

maintainer-clean-local: clean-local
	rm -rf $(srcdir)/libvirt-api.xml $(srcdir)/libvirt-refs.xml \
		todo.html.in
	rm -rf $(srcdir)/libvirt-qemu-api.xml $(srcdir)/libvirt-qemu-refs.xml
	rm -rf $(srcdir)/libvirt-lxc-api.xml $(srcdir)/libvirt-lxc-refs.xml
	rm -rf $(srcdir)/libvirt-admin-api.xml $(srcdir)/libvirt-admin-refs.xml
	rm -rf $(APIBUILD_STAMP)

rebuild: api qemu_api lxc_api admin_api all

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(HTML_DIR)
	for f in $(css) $(dot_html) $(gif) $(png); do \
	  $(INSTALL) -m 0644 $(srcdir)/$$f $(DESTDIR)$(HTML_DIR); done
	$(mkinstalldirs) $(DESTDIR)$(HTML_DIR)/html
	for h in $(apihtml); do \
	  $(INSTALL) -m 0644 $(srcdir)/$$h $(DESTDIR)$(HTML_DIR)/html; done
	for p in $(apipng); do \
	  $(INSTALL) -m 0644 $(srcdir)/$$p $(DESTDIR)$(HTML_DIR)/html; done
	$(mkinstalldirs) $(DESTDIR)$(HTML_DIR)/internals
	for f in $(internals_html); do \
	  $(INSTALL) -m 0644 $(srcdir)/$$f $(DESTDIR)$(HTML_DIR)/internals; done
	$(mkinstalldirs) $(DESTDIR)$(DEVHELP_DIR)
	for file in $(devhelphtml) $(devhelppng) $(devhelpcss); do \
	    $(INSTALL) -m 0644 $(srcdir)/$${file} $(DESTDIR)$(DEVHELP_DIR) ; \
	done
	$(INSTALL_DATA) $(srcdir)/libvirtLogo.png $(DESTDIR)$(pkgdatadir)

uninstall-local:
	for h in $(apihtml); do rm $(DESTDIR)$(HTML_DIR)/$$h; done
	for p in $(apipng); do rm $(DESTDIR)$(HTML_DIR)/$$p; done
	for f in $(devhelphtml) $(devhelppng) $(devhelpcss); do \
	  rm $(DESTDIR)$(DEVHELP_DIR)/$$(basename $$f); \
	done
