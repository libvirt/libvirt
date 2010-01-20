## Process this file with automake to produce Makefile.in
SUBDIRS= schemas

# The directory containing the source code (if it contains documentation).
DOC_SOURCE_DIR=../src

DEVHELP_DIR=$(datadir)/gtk-doc/html/libvirt

apihtml =			\
  html/index.html		\
  html/libvirt-libvirt.html	\
  html/libvirt-virterror.html

apipng =	\
  html/left.png	\
  html/up.png	\
  html/home.png	\
  html/right.png

devhelphtml = 			\
  devhelp/libvirt.devhelp	\
  devhelp/index.html		\
  devhelp/general.html		\
  devhelp/libvirt-libvirt.html	\
  devhelp/libvirt-virterror.html

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
  et.png

gif = \
  architecture.gif \
  node.gif

dot_html_in = $(wildcard *.html.in)
dot_html = $(dot_html_in:%.html.in=%.html)

patches = $(wildcard api_extension/*.patch)

xml = \
  libvirt-api.xml \
  libvirt-refs.xml

fig = \
  libvirt-net-logical.fig \
  libvirt-net-physical.fig \
  libvirt-daemon-arch.fig \
  libvirt-driver-arch.fig \
  libvirt-object-model.fig

EXTRA_DIST=					\
  libvirt-api.xml libvirt-refs.xml apibuild.py	\
  site.xsl newapi.xsl news.xsl page.xsl	ChangeLog.xsl	\
  $(dot_html) $(dot_html_in) $(gif) $(apihtml) $(apipng) \
  $(devhelphtml) $(devhelppng) $(devhelpcss) $(devhelpxsl) \
  $(xml) $(fig) $(png) \
  $(patches) \
  ChangeLog.awk

CLEANFILES = $(dot_html) $(apihtml) $(devhelphtml)

all: web

api: libvirt-api.xml libvirt-refs.xml

web: $(dot_html) html/index.html devhelp/index.html

ChangeLog.xml: ../ChangeLog ChangeLog.awk
	awk -f ChangeLog.awk < $< > $@

ChangeLog.html.in: ChangeLog.xml ChangeLog.xsl
	@(if [ -x $(XSLTPROC) ] ; then \
	  echo "Generating $@"; \
	  name=`echo $@ | sed -e 's/.tmp//'`; \
	  $(XSLTPROC) --nonet $(top_srcdir)/docs/ChangeLog.xsl $< > $@ || (rm $@ && exit 1) ; fi )

%.png: %.fig
	convert -rotate 90 $< $@

%.html.tmp: %.html.in site.xsl page.xsl sitemap.html.in
	@(if [ -x $(XSLTPROC) ] ; then \
	  echo "Generating $@"; \
	  name=`echo $@ | sed -e 's/.tmp//'`; \
	  $(XSLTPROC) --stringparam pagename $$name --nonet --html $(top_srcdir)/docs/site.xsl $< > $@ || (rm $@ && exit 1) ; fi )

%.html: %.html.tmp
	@(if [ -x $(XMLLINT) -a -x $(XMLCATALOG) ] ; then \
	  if $(XMLCATALOG) /etc/xml/catalog "-//W3C//DTD XHTML 1.0 Strict//EN" > /dev/null ; then \
	  echo "Validating $@" ; \
	  $(XMLLINT) --nonet --format --valid $< > $@ || (rm $@ && exit 1) ; \
	  else echo "missing XHTML1 DTD" ; fi ; fi );


html/index.html: libvirt-api.xml newapi.xsl page.xsl sitemap.html.in
	-@(if [ -x $(XSLTPROC) ] ; then \
	  echo "Rebuilding the HTML pages from the XML API" ; \
	  $(XSLTPROC) --nonet $(srcdir)/newapi.xsl libvirt-api.xml ; fi )
	-@(if [ -x $(XMLLINT) -a -x $(XMLCATALOG) ] ; then \
	  if $(XMLCATALOG) /etc/xml/catalog "-//W3C//DTD XHTML 1.0 Strict//EN" > /dev/null ; then \
	  echo "Validating the resulting XHTML pages" ; \
	  $(XMLLINT) --nonet --valid --noout html/*.html ; \
	  else echo "missing XHTML1 DTD" ; fi ; fi );

devhelp/index.html devhelp/libvirt.devhelp: libvirt-api.xml $(devhelpxsl)
	-@(echo Rebuilding devhelp files)
	-@(if [ -x $(XSLTPROC) ] ; then \
	  $(XSLTPROC) --nonet -o devhelp/libvirt.devhelp $(top_srcdir)/docs/devhelp/devhelp.xsl $(top_srcdir)/docs/libvirt-api.xml ; fi );


libvirt-api.xml libvirt-refs.xml: apibuild.py \
		$(srcdir)/../include/libvirt/*.h \
		$(srcdir)/../src/libvirt.c $(srcdir)/../src/util/virterror.c
	-(./apibuild.py)

clean-local:
	rm -f *~ *.bak *.hierarchy *.signals *-unused.txt

maintainer-clean-local: clean-local
	rm -rf libvirt-api.xml libvirt-refs.xml

rebuild: api all

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(HTML_DIR)
	-$(INSTALL) -m 0644 $(srcdir)/FAQ.html \
	    $(srcdir)/Libxml2-Logo-90x34.gif $(DESTDIR)$(HTML_DIR)
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
