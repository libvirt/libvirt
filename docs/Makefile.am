## Process this file with automake to produce Makefile.in
SUBDIRS=

# The directory containing the source code (if it contains documentation).
DOC_SOURCE_DIR=../src

PAGES= index.html
APIPAGES=APIconstructors.html APIfiles.html APIfunctions.html \
    APIsymbols.html APIchunk0.html
EXTRA_DIST=							\
	   libvir-api.xml libxen-refs.xml apibuild.py


man_MANS=

all: web $(man_MANS)

api: libvir-api.xml libvir-refs.xml

web: $(PAGES)

$(PAGES): libvir.html site.xsl
	-@(if [ -x $(XSLTPROC) ] ; then \
	  echo "Rebuilding the HTML Web pages from libvir.html" ; \
	  $(XSLTPROC) --nonet --html $(top_srcdir)/docs/site.xsl $(top_srcdir)/docs/libvir.html > index.html ; fi );
	-@(if [ -x $(XMLLINT) ] ; then \
	  echo "Validating the HTML Web pages" ; \
	  $(XMLLINT) --nonet --valid --noout $(PAGES) ; fi );


#$(APIPAGES): libxml2-api.xml libxml2-refs.xml $(top_srcdir)/docs/site.xsl $(top_srcdir)/docs/api.xsl
#	-@(if [ -x $(XSLTPROC) ] ; then \
#	  echo "Rebuilding the HTML API pages from libxml2-refs.xml" ; \
#	  $(XSLTPROC) --nonet --html $(top_srcdir)/doc/api.xsl \
#	                     $(top_srcdir)/doc/xml.html ; fi );
#	-@(if [ -x $(XMLLINT) ] ; then \
#	  echo "Validating the HTML API pages" ; \
#	  $(XMLLINT) --nonet --valid --noout API*.html ; fi );
#
#$(srcdir)/html/index.html: libxml2-api.xml $(srcdir)/newapi.xsl
#	-@(if [ -x $(XSLTPROC) ] ; then \
#	  echo "Rebuilding the HTML pages from the XML API" ; \
#	  $(XSLTPROC) --nonet $(srcdir)/newapi.xsl libxml2-api.xml ; fi )
#	-@(if [ -x $(XMLLINT) ] ; then \
#	  echo "Validating the resulting XHTML pages" ; \
#	  $(XMLLINT) --nonet --valid --noout html/*.html ; fi );

libvir-api.xml libvir-refs.xml: apibuild.py ../include/*.h ../src/*.h ../src/*.c
	-(./apibuild.py)

clean-local:
	rm -f *~ *.bak *.hierarchy *.signals *-unused.txt

maintainer-clean-local: clean-local
	rm -rf libvir-api.xml libvir-refs.xml

rebuild: api all

#install-data-local: 
#	$(mkinstalldirs) $(DESTDIR)$(HTML_DIR)
#	-@INSTALL@ -m 0644 $(srcdir)/xml.html $(srcdir)/encoding.html $(srcdir)/FAQ.html $(srcdir)/structure.gif $(srcdir)/DOM.gif $(srcdir)/smallfootonly.gif $(srcdir)/redhat.gif $(srcdir)/libxml.gif $(srcdir)/w3c.png $(srcdir)/Libxml2-Logo-180x168.gif $(srcdir)/Libxml2-Logo-90x34.gif $(DESTDIR)$(HTML_DIR)
#	$(mkinstalldirs) $(DESTDIR)$(HTML_DIR)/html
#	-@INSTALL@ -m 0644 $(srcdir)/html/*.html $(DESTDIR)$(HTML_DIR)/html
#	-@INSTALL@ -m 0644 $(srcdir)/html/*.png $(DESTDIR)$(HTML_DIR)/html
#	$(mkinstalldirs) $(DESTDIR)$(HTML_DIR)/tutorial
#	-@INSTALL@ -m 0644 $(srcdir)/tutorial/*.* \
#		$(DESTDIR)$(HTML_DIR)/tutorial
#	$(mkinstalldirs) $(DESTDIR)$(HTML_DIR)/tutorial/images
#	-@INSTALL@ -m 0644 $(srcdir)/tutorial/images/*.* \
#		$(DESTDIR)$(HTML_DIR)/tutorial/images
#	$(mkinstalldirs) $(DESTDIR)$(HTML_DIR)/tutorial/images/callouts
#	-@INSTALL@ -m 0644 $(srcdir)/tutorial/images/callouts/*.* \
#		$(DESTDIR)$(HTML_DIR)/tutorial/images/callouts

