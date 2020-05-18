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
POMINIFILES := $(LANGS:%=%.mini.po)
POFILES := $(LANGS:%=%.po)
GMOFILES := $(LANGS:%=%.gmo)

CLEANFILES = $(POTFILE) $(POFILES) $(GMOFILES) POTFILES

EXTRA_DIST = \
	LINGUAS \
	$(POTFILES_IN) \
	$(POMINIFILES)

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
	$(NULL)

POT_CREATION_DATE = $(shell \
	if test -n "$$SOURCE_DATE_EPOCH"; \
	then \
		date --date="@$$SOURCE_DATE_EPOCH" +"%F %R%z"; \
	else \
		date +'%F %R%z'; \
	fi)

SED_PO_FIXUP_ARGS = \
	-e "s|text/plain; charset=CHARSET|text/plain; charset=UTF-8|g" \
	-e "s|SOME DESCRIPTIVE TITLE|Libvirt package strings|g" \
	-e "s|Copyright (C) YEAR|Copyright (C) $$(date +'%Y')|" \
	-e "s|POT-Creation-Date:[^\]*|POT-Creation-Date: $(POT_CREATION_DATE)|" \
	$(NULL)

update-po: $(POFILES)

update-gmo: $(GMOFILES)

update-mini-po: $(POTFILE)
	for lang in $(LANGS); do \
	  echo "Minimizing $$lang content" && \
	  $(MSGMERGE) --no-location --no-fuzzy-matching --sort-output \
	    $$lang.po $(POTFILE) | \
	  $(SED) $(SED_PO_FIXUP_ARGS) | \
	  $(RUNUTF8) $(PYTHON) $(top_srcdir)/scripts/minimize-po.py > \
	    $(srcdir)/$$lang.mini.po ; \
	done

push-pot: $(POTFILE)
	zanata push \
		--project-config $(srcdir)/zanata.xml \
		--push-type=source \
		--transdir $(builddir) \
		--srcdir $(srcdir)

pull-po: $(POTFILE)
	zanata pull \
		--project-config $(srcdir)/zanata.xml \
		--create-skeletons \
		--transdir $(builddir) \
		--srcdir $(srcdir)
	$(MAKE) update-mini-po
	$(MAKE) update-gmo

$(POTFILE): POTFILES $(POTFILE_DEPS)
	$(XGETTEXT) -o $@-t $(XGETTEXT_ARGS) \
	  --files-from=$(abs_builddir)/POTFILES
	$(SED) $(SED_PO_FIXUP_ARGS) < $@-t > $@
	rm -f $@-t

%.po: %.mini.po $(POTFILE)
	$(MSGMERGE) --no-fuzzy-matching $< $(POTFILE) | \
	  $(SED) $(SED_PO_FIXUP_ARGS) > $@

%.gmo: %.po
	rm -f $@ $@-t
	$(MSGFMT) -c -o $@-t $<
	mv $@-t $@

.PRECIOUS: $(POTFILE) $(POFILES)

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
