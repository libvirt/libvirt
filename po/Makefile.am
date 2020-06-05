DOMAIN = $(PACKAGE_NAME)
COPYRIGHT_HOLDER = The Libvirt authors
MSGID_BUGS_ADDRESS = https://libvirt.org/bugs.html

LANGS := $(shell cat $(srcdir)/LINGUAS)

POTFILES_IN = $(srcdir)/POTFILES.in
POTFILES: $(POTFILES_IN)
	$(AM_V_GEN) cat $(POTFILES_IN) | \
		$(SED) 's|[@]SRCDIR[@]|$(top_srcdir)|' | \
		$(SED) 's|[@]BUILDDIR[@]|$(top_builddir)|' > $@
POTFILE_DEPS = $(shell cat POTFILES)
POTFILE := $(DOMAIN).pot
POFILES := $(LANGS:%=%.po)
GMOFILES := $(LANGS:%=%.gmo)

CLEANFILES = $(GMOFILES) POTFILES

EXTRA_DIST = \
	LINGUAS \
	$(POTFILES_IN) \
	$(POFILES)

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
	--sort-output \
	$(NULL)

SED_PO_FIXUP_ARGS = \
	-e "s|text/plain; charset=CHARSET|text/plain; charset=UTF-8|g" \
	-e "s|SOME DESCRIPTIVE TITLE|Libvirt package strings|g" \
	-e "s|Copyright (C) YEAR|Copyright (C) $$(date +'%Y')|" \
	$(NULL)

update-gmo: $(GMOFILES)

# The results of this target should not be committed to Git. The Weblate
# service is responsible for updating .po files when the .pot is changed.
update-po: $(POTFILE)
	cd $(srcdir) && \
	for lang in $(LANGS); do \
	  echo "Minimizing $$lang content" && \
	  $(MSGMERGE) --no-location --no-fuzzy-matching --sort-output \
	    $$lang.po $(POTFILE) | \
	  $(SED) $(SED_PO_FIXUP_ARGS) > $$lang.po-t && \
	  mv $$lang.po-t $$lang.po ; \
	done

$(POTFILE): POTFILES
	$(XGETTEXT) -o $@-t $(XGETTEXT_ARGS) \
	  --files-from=$(abs_builddir)/POTFILES
	$(SED) $(SED_PO_FIXUP_ARGS) < $@-t > $(srcdir)/$@
	rm -f $@-t

%.gmo: %.po
	rm -f $@ $@-t
	$(MSGFMT) -c -o $@-t $<
	mv $@-t $@

.PHONY: $(POTFILE)

endif HAVE_GNU_GETTEXT_TOOLS

if ENABLE_NLS

# Cannot use 'localedir' since this conflicts with autoconf.
langinstdir = $(datadir)/locale

install-data-hook: $(GMOFILES)
	mkdir -p $(DESTDIR)$(langinstdir)
	for lang in $(LANGS); do \
	  d=$(DESTDIR)$(langinstdir)/$$lang/LC_MESSAGES; \
	  mkdir -p $$d; \
	  install -m 0644 $$lang.gmo $$d/$(DOMAIN).mo; \
	done

uninstall-hook:
	for lang in $(LANGS); do \
	  d=$(DESTDIR)$(langinstdir)/$$lang/LC_MESSAGES; \
	  rm -f $$d/$(DOMAIN).mo; \
	done

endif ENABLE_NLS
