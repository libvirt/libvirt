
bin_SCRIPTS = \
	virt-xml-validate

virt-xml-validate: virt-xml-validate.in Makefile
	sed -e 's,@SCHEMADIR@,$(pkgdatadir)/schemas,' < $< > $@ || (rm $@ && exit 1)
	chmod +x $@

man1_MANS = virt-xml-validate.1

EXTRA_DIST = virt-xml-validate.in

CLEANFILES = $(bin_SCRIPTS) $(man1_MANS)

%.1: %
	pod2man -c "Virtualization Support" -r "$(PACKAGE)-$(VERSION)" $< $@
