## Process this file with automake to produce Makefile.in
SUBDIRS= . examples devhelp

# The directory containing the source code (if it contains documentation).
DOC_SOURCE_DIR=../src

PAGES= index.html bugs.html FAQ.html
APIPAGES=APIconstructors.html APIfiles.html APIfunctions.html \
    APIsymbols.html APIchunk0.html
EXTRA_DIST=							\
	   libvirt-api.xml libvirt-refs.xml apibuild.py		\
	   *.xsl *.html *.gif html/*.html html/*.png \
	   test*.xml libvirt.rng


man_MANS=

all: web $(top_builddir)/NEWS $(man_MANS)

api: libvirt-api.xml libvirt-refs.xml $(APIPAGES) $(srcdir)/html/index.html

web: $(PAGES)

$(PAGES): libvir.html site.xsl
	-@(if [ -x $(XSLTPROC) ] ; then \
	  echo "Rebuilding the HTML Web pages from libvir.html" ; \
	  $(XSLTPROC) --nonet --html $(top_srcdir)/docs/site.xsl $(top_srcdir)/docs/libvir.html > index.html ; fi );
	-@(if [ -x $(XMLLINT) ] ; then \
	  echo "Validating the HTML Web pages" ; \
	  $(XMLLINT) --nonet --valid --noout $(PAGES) ; fi );


$(APIPAGES): libvirt-api.xml libvirt-refs.xml $(top_srcdir)/docs/site.xsl $(top_srcdir)/docs/api.xsl
	-@(if [ -x $(XSLTPROC) ] ; then \
	  echo "Rebuilding the HTML API pages from libvirt-refs.xml" ; \
	  $(XSLTPROC) --nonet --html $(top_srcdir)/docs/api.xsl \
	                     $(top_srcdir)/docs/libvir.html ; fi );
	-@(if [ -x $(XMLLINT) ] ; then \
	  echo "Validating the HTML API pages" ; \
	  $(XMLLINT) --nonet --valid --noout API*.html ; fi );

$(srcdir)/html/index.html: libvirt-api.xml $(srcdir)/newapi.xsl
	-@(if [ -x $(XSLTPROC) ] ; then \
	  echo "Rebuilding the HTML pages from the XML API" ; \
	  $(XSLTPROC) --nonet $(srcdir)/newapi.xsl libvirt-api.xml ; fi )
	-@(if [ -x $(XMLLINT) ] ; then \
	  echo "Validating the resulting XHTML pages" ; \
	  $(XMLLINT) --nonet --valid --noout html/*.html ; fi );

libvirt-api.xml libvirt-refs.xml: apibuild.py ../include/libvirt/*.h ../src/*.h ../src/*.c
	-(./apibuild.py)

$(top_builddir)/NEWS: $(top_srcdir)/docs/news.xsl $(top_srcdir)/docs/news.html
	-@(if [ -x $(XSLTPROC) ] ; then \
	  $(XSLTPROC) --nonet $(top_srcdir)/docs/news.xsl $(top_srcdir)/docs/news.html > $(top_builddir)/NEWS ; fi );

clean-local:
	rm -f *~ *.bak *.hierarchy *.signals *-unused.txt

maintainer-clean-local: clean-local
	rm -rf libvirt-api.xml libvirt-refs.xml

rebuild: api all

install-data-local: 
	$(mkinstalldirs) $(DESTDIR)$(HTML_DIR)
	-@INSTALL@ -m 0644 $(srcdir)/libvir.html $(srcdir)/FAQ.html $(srcdir)/redhat.gif $(srcdir)/Libxml2-Logo-90x34.gif $(DESTDIR)$(HTML_DIR)
	$(mkinstalldirs) $(DESTDIR)$(HTML_DIR)/html
	-@INSTALL@ -m 0644 $(srcdir)/html/*.html $(DESTDIR)$(HTML_DIR)/html
	-@INSTALL@ -m 0644 $(srcdir)/html/*.png $(DESTDIR)$(HTML_DIR)/html

