DEVHELP_DIR=$(datadir)/gtk-doc/html/libvirt
HTML_FILES=index.html general.html $(HTML_MODULES)
HTML_MODULES=				\
	libvirt-libvirt.html		\
	libvirt-virterror.html

EXTRA_FORMAT=				\
	home.png			\
	left.png			\
	right.png			\
	up.png				\
	style.css

EXTRA_DIST=devhelp.xsl html.xsl libvirt.devhelp $(HTML_FILES) $(EXTRA_FORMAT)

all: libvirt.devhelp $(HTML_FILES)

libvirt.devhelp $(HTML_FILES): $(srcdir)/devhelp.xsl html.xsl $(top_srcdir)/docs/libvirt-api.xml
	-@(echo Rebuilding devhelp files)
	-@(if [ -x $(XSLTPROC) ] ; then \
	  $(XSLTPROC) --nonet -o libvirt.devhelp $(srcdir)/devhelp.xsl $(top_srcdir)/docs/libvirt-api.xml ; fi );

install-data-local: libvirt.devhelp $(HTML_FILES)
	$(mkinstalldirs) $(DESTDIR)$(DEVHELP_DIR)
	-@INSTALL@ -m 0644 libvirt.devhelp $(DESTDIR)$(DEVHELP_DIR)
	-@INSTALL@ -m 0644 $(HTML_FILES) $(DESTDIR)$(DEVHELP_DIR)
	-for file in $(EXTRA_FORMAT); do \
	    @INSTALL@ -m 0644 $(srcdir)/$${file} $(DESTDIR)$(DEVHELP_DIR) ; \
	done
