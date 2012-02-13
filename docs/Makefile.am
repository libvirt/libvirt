## Process this file with automake to produce Makefile.in

## Copyright (C) 2005-2011 Red Hat, Inc.
## See COPYING.LIB for the License of this software

SUBDIRS= schemas

PERL = perl

# The directory containing the source code (if it contains documentation).
DOC_SOURCE_DIR=../src

DEVHELP_DIR=$(datadir)/gtk-doc/html/libvirt

BUILT_SOURCES=hvsupport.html.in

apihtml =			\
  html/index.html		\
  html/libvirt-libvirt.html	\
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
  devhelp/libvirt-libvirt.html	\
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

dot_html_in = $(notdir $(wildcard $(srcdir)/*.html.in)) todo.html.in hvsupport.html.in \
      $(patsubst $(srcdir)/%,%,$(wildcard $(srcdir)/internals/*.html.in))
dot_html = $(dot_html_in:%.html.in=%.html)

patches = $(patsubst $(srcdir)/%,%,$(wildcard $(srcdir)/api_extension/*.patch))

xml = \
  libvirt-api.xml \
  libvirt-refs.xml

qemu_xml = \
  libvirt-qemu-api.xml \
  libvirt-qemu-refs.xml

apidir = $(pkgdatadir)/api
api_DATA = libvirt-api.xml libvirt-qemu-api.xml

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

EXTRA_DIST=					\
  apibuild.py \
  site.xsl newapi.xsl news.xsl page.xsl \
  hacking1.xsl hacking2.xsl wrapstring.xsl \
  $(dot_html) $(dot_html_in) $(gif) $(apihtml) $(apipng) \
  $(devhelphtml) $(devhelppng) $(devhelpcss) $(devhelpxsl) \
  $(xml) $(qemu_xml) $(fig) $(png) $(css) \
  $(patches) \
  sitemap.html.in \
  todo.pl hvsupport.pl todo.cfg-example

MAINTAINERCLEANFILES = \
  $(addprefix $(srcdir)/,$(dot_html)) \
  $(addprefix $(srcdir)/,$(apihtml)) \
  $(addprefix $(srcdir)/,$(devhelphtml))

all: web

api: $(srcdir)/libvirt-api.xml $(srcdir)/libvirt-refs.xml
qemu_api: $(srcdir)/libvirt-qemu-api.xml $(srcdir)/libvirt-qemu-refs.xml

web: $(dot_html) html/index.html devhelp/index.html

todo.html.in: todo.pl
	if [ -f  todo.cfg ]; then \
		echo "Generating $@"; \
		$(PERL) $< > $@ \
		|| { rm $@ && exit 1; }; \
	else \
		echo "Stubbing $@"; \
		echo "<html><body><h1>Todo list</h1></body></html>" > $@ ; \
	fi

todo:
	rm -f todo.html.in
	$(MAKE) todo.html

hvsupport.html.in: $(srcdir)/hvsupport.pl $(srcdir)/../src/libvirt_public.syms \
	 $(srcdir)/../src/libvirt_qemu.syms $(srcdir)/../src/driver.h
	$(AM_V_GEN)$(PERL) $(srcdir)/hvsupport.pl $(srcdir)/../src > $@ || { rm $@ && exit 1; }

.PHONY: todo

%.png: %.fig
	convert -rotate 90 $< $@

internals/%.html.tmp: internals/%.html.in subsite.xsl page.xsl sitemap.html.in
	@if [ -x $(XSLTPROC) ] ; then \
	  echo "Generating $@"; \
	  $(MKDIR_P) internals; \
	  name=`echo $@ | sed -e 's/.tmp//'`; \
	  $(XSLTPROC) --stringparam pagename $$name --nonet --html \
	    $(top_srcdir)/docs/subsite.xsl $< > $@ \
	    || { rm $@ && exit 1; }; fi

%.html.tmp: %.html.in site.xsl page.xsl sitemap.html.in
	@if [ -x $(XSLTPROC) ] ; then \
	  echo "Generating $@"; \
	  name=`echo $@ | sed -e 's/.tmp//'`; \
	  $(XSLTPROC) --stringparam pagename $$name --nonet --html \
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
	  else echo "missing XHTML1 DTD" ; fi ; fi


html/index.html: libvirt-api.xml newapi.xsl page.xsl sitemap.html.in
	$(AM_V_GEN)if [ -x $(XSLTPROC) ] ; then \
	  $(XSLTPROC) --nonet -o $(srcdir)/ \
	  $(srcdir)/newapi.xsl $(srcdir)/libvirt-api.xml ; fi && \
	if test -x $(XMLLINT) && test -x $(XMLCATALOG) ; then \
	  if $(XMLCATALOG) '$(XML_CATALOG_FILE)' "-//W3C//DTD XHTML 1.0 Strict//EN" \
	    > /dev/null ; then \
	  SGML_CATALOG_FILES='$(XML_CATALOG_FILE)' \
	  $(XMLLINT) --catalogs --nonet --valid --noout $(srcdir)/html/*.html ; \
	  else echo "missing XHTML1 DTD" ; fi ; fi

$(addprefix $(srcdir)/,$(devhelphtml)): $(srcdir)/libvirt-api.xml $(devhelpxsl)
	$(AM_V_GEN)if [ -x $(XSLTPROC) ] ; then \
	  $(XSLTPROC) --nonet -o $(srcdir)/devhelp/ \
	  $(top_srcdir)/docs/devhelp/devhelp.xsl $(srcdir)/libvirt-api.xml ; fi


python_generated_files = \
		$(srcdir)/html/libvirt-libvirt.html \
		$(srcdir)/html/libvirt-libvirt-qemu.html \
		$(srcdir)/html/libvirt-virterror.html \
		$(srcdir)/libvirt-api.xml \
		$(srcdir)/libvirt-refs.xml \
		$(srcdir)/libvirt-qemu-api.xml \
		$(srcdir)/libvirt-qemu-refs.xml

$(python_generated_files): $(srcdir)/apibuild.py \
		$(srcdir)/../include/libvirt/*.h \
		$(srcdir)/../src/libvirt.c \
		$(srcdir)/../src/libvirt-qemu.c \
		$(srcdir)/../src/util/virterror.c
	$(AM_V_GEN)srcdir=$(srcdir) $(PYTHON) $(srcdir)/apibuild.py

check-local: all

clean-local:
	rm -f *~ *.bak *.hierarchy *.signals *-unused.txt *.html

maintainer-clean-local: clean-local
	rm -rf $(srcdir)/libvirt-api.xml $(srcdir)/libvirt-refs.xml todo.html.in hvsupport.html.in
	rm -rf $(srcdir)/libvirt-qemu-api.xml $(srcdir)/libvirt-qemu-refs.xml

rebuild: api qemu_api all

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(HTML_DIR)
	for f in $(css) $(dot_html) $(gif) $(png); do \
	  $(INSTALL) -m 0644 $(srcdir)/$$f $(DESTDIR)$(HTML_DIR); done
	$(mkinstalldirs) $(DESTDIR)$(HTML_DIR)/html
	for h in $(apihtml); do \
	  $(INSTALL) -m 0644 $(srcdir)/$$h $(DESTDIR)$(HTML_DIR)/html; done
	for p in $(apipng); do \
	  $(INSTALL) -m 0644 $(srcdir)/$$p $(DESTDIR)$(HTML_DIR)/html; done
	$(mkinstalldirs) $(DESTDIR)$(DEVHELP_DIR)
	for file in $(devhelphtml) $(devhelppng) $(devhelpcss); do \
	    $(INSTALL) -m 0644 $(srcdir)/$${file} $(DESTDIR)$(DEVHELP_DIR) ; \
	done

uninstall-local:
	for h in $(apihtml); do rm $(DESTDIR)$(HTML_DIR)/$$h; done
	for p in $(apipng); do rm $(DESTDIR)$(HTML_DIR)/$$p; done
	for f in $(devhelphtml) $(devhelppng) $(devhelpcss); do \
	  rm $(DESTDIR)$(DEVHELP_DIR)/$$(basename $$f); \
	done
