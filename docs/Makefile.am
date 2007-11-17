## Process this file with automake to produce Makefile.in
SUBDIRS= . examples devhelp

# The directory containing the source code (if it contains documentation).
DOC_SOURCE_DIR=../src

PAGES= index.html bugs.html FAQ.html remote.html
APIPAGES=APIconstructors.html APIfiles.html APIfunctions.html \
    APIsymbols.html APIchunk0.html

man_MANS=

html =			\
  book1.html		\
  index.html		\
  libvirt-conf.html	\
  libvirt-lib.html	\
  libvirt-libvirt.html	\
  libvirt-virterror.html

png =		\
  left.png	\
  up.png	\
  home.png	\
  right.png

gif = \
  Libxml2-Logo-90x34.gif \
  architecture.gif \
  node.gif \
  redhat.gif

dot_html = \
  APIchunk0.html \
  APIchunk1.html \
  APIchunk2.html \
  APIchunk3.html \
  APIchunk4.html \
  APIchunk5.html \
  APIchunk6.html \
  APIchunk7.html \
  APIconstructors.html \
  APIfiles.html \
  APIfunctions.html \
  APIsymbols.html \
  FAQ.html \
  architecture.html \
  bugs.html \
  downloads.html \
  errors.html \
  format.html \
  hvsupport.html \
  index.html \
  intro.html \
  libvir.html \
  news.html \
  python.html \
  remote.html \
  uri.html

xml = \
  libvirt-api.xml \
  libvirt-refs.xml \
  testdomfc4.xml \
  testdomfv0.xml \
  testnetdef.xml \
  testnetpriv.xml \
  testnode.xml

rng = \
  libvirt.rng \
  network.rng

EXTRA_DIST=					\
  libvirt-api.xml libvirt-refs.xml apibuild.py	\
  site.xsl newapi.xsl api.xsl news.xsl		\
  $(dot_html) $(gif) html			\
  $(xml) $(rng)

all: web $(top_builddir)/NEWS $(man_MANS)

virsh.1: virsh.pod
	pod2man -c "Virtualization Support" $(srcdir)/virsh.pod > $@-t
	mv $@-t $@
	cp $@ $(top_builddir)

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

libvirt-api.xml libvirt-refs.xml: apibuild.py \
		$(srcdir)/../include/libvirt/*.h \
		$(srcdir)/../src/*.h $(srcdir)/../src/*.c
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
	-@INSTALL@ -m 0644 $(srcdir)/libvir.html $(srcdir)/FAQ.html \
	    $(srcdir)/redhat.gif $(srcdir)/Libxml2-Logo-90x34.gif \
	  $(DESTDIR)$(HTML_DIR)
	$(mkinstalldirs) $(DESTDIR)$(HTML_DIR)/html
	for h in $(html); do \
	  $(INSTALL) -m 0644 $(srcdir)/html/$$h $(DESTDIR)$(HTML_DIR)/html; done
	for p in $(png); do \
	  $(INSTALL) -m 0644 $(srcdir)/html/$$p $(DESTDIR)$(HTML_DIR)/html; done

uninstall-local:
	for h in $(html); do rm $(DESTDIR)$(HTML_DIR)/html/$$h; done
	for p in $(png); do rm $(DESTDIR)$(HTML_DIR)/html/$$p; done
