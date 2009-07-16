## Process this file with automake to produce Makefile.in
SUBDIRS= schemas examples devhelp

# The directory containing the source code (if it contains documentation).
DOC_SOURCE_DIR=../src

man_MANS=

apihtml =			\
  html/index.html		\
  html/libvirt-libvirt.html	\
  html/libvirt-virterror.html

apipng =	\
  html/left.png	\
  html/up.png	\
  html/home.png	\
  html/right.png

png = \
  16favicon.png \
  32favicon.png \
  footer_corner.png \
  footer_pattern.png \
  libvirHeader.png \
  libvirLogo.png \
  libvirt-header-bg.png \
  libvirt-header-logo.png \
  libvirtLogo.png \
  libvirt-net-logical.png \
  libvirt-net-physical.png \
  libvirt-daemon-arch.png \
  libvirt-driver-arch.png \
  libvirt-object-model.png \
  madeWith.png \
  windows-cygwin-1.png \
  windows-cygwin-2.png \
  windows-cygwin-3.png \
  et.png

gif = \
  Libxml2-Logo-90x34.gif \
  architecture.gif \
  node.gif

dot_html_in = $(wildcard *.html.in)
dot_html = $(dot_html_in:%.html.in=%.html)

patches = $(wildcard api_extension/*.patch)

xml = \
  libvirt-api.xml \
  libvirt-refs.xml \
  testdomfc4.xml \
  testdomfv0.xml \
  testnetdef.xml \
  testnetpriv.xml \
  testnode.xml \
  testpool.xml \
  testvol.xml

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
  $(xml) $(fig) $(png) \
  $(patches) \
  virsh.pod ChangeLog.awk

all: web $(top_builddir)/NEWS $(man_MANS)

virsh.1: virsh.pod
	pod2man -c "Virtualization Support" -r "$(PACKAGE)-$(VERSION)" $(srcdir)/virsh.pod > $@-t
	mv $@-t $@
	cp $@ $(top_builddir)

api: libvirt-api.xml libvirt-refs.xml $(srcdir)/html/index.html

web: $(dot_html)

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
	  if $(XMLCATALOG) /etc/xml/catalog "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd" > /dev/null ; then \
	  echo "Validating $@" ; \
	  $(XMLLINT) --nonet --format --valid $< > $@ || : ; \
	  else echo "missing XHTML1 DTD" ; fi ; fi );


$(srcdir)/html/index.html: libvirt-api.xml newapi.xsl page.xsl sitemap.html.in
	-@(if [ -x $(XSLTPROC) ] ; then \
	  echo "Rebuilding the HTML pages from the XML API" ; \
	  $(XSLTPROC) --nonet $(srcdir)/newapi.xsl libvirt-api.xml ; fi )
	-@(if [ -x $(XMLLINT) -a -x $(XMLCATALOG) ] ; then \
	  if $(XMLCATALOG) /etc/xml/catalog "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd" > /dev/null ; then \
	  echo "Validating the resulting XHTML pages" ; \
	  $(XMLLINT) --nonet --valid --noout html/*.html ; \
	  else echo "missing XHTML1 DTD" ; fi ; fi );

libvirt-api.xml libvirt-refs.xml: apibuild.py \
		$(srcdir)/../include/libvirt/*.h \
		$(srcdir)/../src/*.h $(srcdir)/../src/*.c
	-(./apibuild.py)

$(top_builddir)/NEWS: $(top_srcdir)/docs/news.xsl $(top_srcdir)/docs/news.html.in
	-@(if [ -x $(XSLTPROC) ] ; then				\
	  $(XSLTPROC) --nonet $(top_srcdir)/docs/news.xsl	\
	     $(top_srcdir)/docs/news.html.in			\
	   | perl -0777 -pe 's/\n\n+$$/\n/'			\
	   > $@-t && mv $@-t $@ ; fi );

clean-local:
	rm -f *~ *.bak *.hierarchy *.signals *-unused.txt

maintainer-clean-local: clean-local
	rm -rf libvirt-api.xml libvirt-refs.xml

rebuild: api all

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(HTML_DIR)
	-@INSTALL@ -m 0644 $(srcdir)/FAQ.html \
	    $(srcdir)/Libxml2-Logo-90x34.gif $(DESTDIR)$(HTML_DIR)
	$(mkinstalldirs) $(DESTDIR)$(HTML_DIR)/html
	for h in $(apihtml); do \
	  $(INSTALL) -m 0644 $(srcdir)/$$h $(DESTDIR)$(HTML_DIR)/html; done
	for p in $(apipng); do \
	  $(INSTALL) -m 0644 $(srcdir)/$$p $(DESTDIR)$(HTML_DIR)/html; done

uninstall-local:
	for h in $(apihtml); do rm $(DESTDIR)$(HTML_DIR)/$$h; done
	for p in $(apipng); do rm $(DESTDIR)$(HTML_DIR)/$$p; done
