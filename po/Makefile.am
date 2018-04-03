DOMAIN = $(PACKAGE_NAME)
COPYRIGHT_HOLDER = The Libvirt authors
MSGID_BUGS_ADDRESS = https://libvirt.org/bugs.html

LANGS := \
	af am anp ar as ast bal be bg bn_IN \
	bn bo br brx bs ca cs cy da de_CH \
	de el en_GB eo es et eu fa fi \
	fr gl gu he hi hr hu ia \
	id ilo is it ja ka kk km kn ko \
	kw_GB kw@kkcor kw kw@uccor ky lt lv mai mk ml \
	mn mr ms nb nds ne nl nn nso \
	or pa pl pt_BR pt ro ru si sk sl \
	sq sr@latin sr sv ta te tg th tr tw \
	uk ur vi wba yo zh_CN zh_HK zh_TW zu


POTFILE_DEPS := $(shell $(SED) 's,^,$(top_srcdir)/,' $(srcdir)/POTFILES)
POTFILE := $(DOMAIN).pot
POFILES := $(LANGS:%=%.po)
GMOFILES := $(LANGS:%=%.gmo)

EXTRA_DIST = \
	POTFILES \
	$(POTFILE) \
	$(POFILES) \
	$(GMOFILES)

if HAVE_GNU_GETTEXT_TOOLS

XGETTEXT_ARGS = \
	--default-domain=$(DOMAIN) \
	--from-code=utf-8 \
	--add-comments=TRANSLATORS: \
        --keyword=_ --keyword=N_ \
	--copyright-holder='$(COPYRIGHT_HOLDER)' \
	--package-name="$(PACKAGE_NAME)" \
	--package-version="$(PACKAGE_VERSION)" \
	--msgid-bugs-address="$(MSGID_BUGS_ADDRESS)" \
	--directory=$(top_srcdir) \
	$(NULL)

SED_PO_FIXUP_ARGS = \
       -e "s|text/plain; charset=CHARSET|text/plain; charset=UTF-8|g" \
       -e "s|SOME DESCRIPTIVE TITLE|Libvirt package strings|g" \
       -e "s|Copyright (C) YEAR|Copyright (C) $$(date +'%Y')|" \
       $(NULL)


# Although they're in EXTRA_DIST, we still need to
# copy these again, because update-gmo will change
# their content, and dist-hook runs after the
# things in EXTRA_DIST are copied.
dist-hook: $(GMOFILES)
	cp -f $(POTFILE:%=$(srcdir)/%) $(distdir)/
	cp -f $(POFILES:%=$(srcdir)/%) $(distdir)/
	cp -f $(GMOFILES:%=$(srcdir)/%) $(distdir)/

update-po: $(POFILES)

update-gmo: $(GMOFILES)

$(POTFILE): POTFILES $(POTFILE_DEPS)
	$(XGETTEXT) -o $(srcdir)/$@-t $(XGETTEXT_ARGS) \
	  --files-from=$(abs_srcdir)/POTFILES
	$(SED) $(SED_PO_FIXUP_ARGS) < $@-t > $@
	rm -f $@-t

%.po: $(POTFILE)
	cd $(srcdir) && \
	  $(MSGMERGE) --backup=off --no-fuzzy-matching --update $@ $(POTFILE)

%.gmo: %.po
	rm -f $(srcdir)/$@ $@-t
	$(MSGFMT) -c -o $@-t $(srcdir)/$<
	mv $@-t $(srcdir)/$@

.PRECIOUS: $(POTFILE) $(POFILES)

endif HAVE_GNU_GETTEXT_TOOLS

# Cannot use 'localedir' since this conflicts with autoconf.
langinstdir = $(datadir)/locale

install-data-hook: $(GMOFILES)
	mkdir -p $(DESTDIR)$(langinstdir)
	for lang in $(LANGS); do \
	  d=$(DESTDIR)$(langinstdir)/$$lang/LC_MESSAGES; \
	  mkdir -p $$d; \
	  install -m 0644 $(srcdir)/$$lang.gmo $$d/$(DOMAIN).mo; \
	done

uninstall-hook:
	for lang in $(LANGS); do \
	  d=$(DESTDIR)$(langinstdir)/$$lang/LC_MESSAGES; \
	  rm -f $$d/$(DOMAIN).mo; \
	done
