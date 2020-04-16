## Process this file with automake to produce Makefile.in

## Copyright (C) 2005-2016 Red Hat, Inc.
##
## This library is free software; you can redistribute it and/or
## modify it under the terms of the GNU Lesser General Public
## License as published by the Free Software Foundation; either
## version 2.1 of the License, or (at your option) any later version.
##
## This library is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## Lesser General Public License for more details.
##
## You should have received a copy of the GNU Lesser General Public
## License along with this library.  If not, see
## <http://www.gnu.org/licenses/>.

HTML_DIR = $(docdir)/html

modules = \
	libvirt-common \
	libvirt-domain \
	libvirt-domain-checkpoint \
	libvirt-domain-snapshot \
	libvirt-event \
	libvirt-host \
	libvirt-interface \
	libvirt-network \
	libvirt-nodedev \
	libvirt-nwfilter \
	libvirt-secret \
	libvirt-storage \
	libvirt-stream \
	virterror \
	$(NULL)

modules_admin = libvirt-admin
modules_qemu = libvirt-qemu
modules_lxc = libvirt-lxc

all: vpathhack

# This hack enables us to view the web pages
# from within the uninstalled build tree
vpathhack:
	@for dir in fonts js logos; \
	do \
	  test -e $$dir || ln -s $(srcdir)/$$dir $$dir ; \
	done
	@for file in $(assets); \
	do \
	  test -e $$file || ln -s $(srcdir)/$$file $$file ; \
	done

clean-local:
	for dir in fonts js logos; \
	do \
	  rm -f $$dir ; \
	done
	for file in $(assets); \
	do \
	  rm -f $$file ; \
	done

apihtml = \
  html/index.html \
  $(apihtml_generated)

apihtml_generated = \
	$(addprefix html/libvirt-,$(addsuffix .html,$(modules))) \
	$(NULL)

apiadminhtml = \
  html/index-admin.html \
  $(apiadminhtml_generated)

apiadminhtml_generated = \
	$(addprefix html/libvirt-,$(addsuffix .html,$(modules_admin))) \
	$(NULL)

apiqemuhtml = \
  html/index-qemu.html \
  $(apiqemuhtml_generated)

apiqemuhtml_generated = \
	$(addprefix html/libvirt-,$(addsuffix .html,$(modules_qemu))) \
	$(NULL)

apilxchtml = \
  html/index-lxc.html \
  $(apilxchtml_generated)

apilxchtml_generated = \
	$(addprefix html/libvirt-,$(addsuffix .html,$(modules_lxc))) \
	$(NULL)

apipng = \
  html/left.png \
  html/up.png \
  html/home.png \
  html/right.png

apirefdir = $(HTML_DIR)/html
apiref_DATA = $(apihtml) $(apiadminhtml) $(apiqemuhtml) $(apilxchtml) $(apipng)

javascript = \
  js/main.js \
  $(NULL)

javascriptdir = $(HTML_DIR)/js
javascript_DATA = $(javascript)

fonts = \
  fonts/LICENSE.rst \
  fonts/stylesheet.css \
  fonts/overpass-bold-italic.woff \
  fonts/overpass-bold.woff \
  fonts/overpass-italic.woff \
  fonts/overpass-light-italic.woff \
  fonts/overpass-light.woff \
  fonts/overpass-mono-bold.woff \
  fonts/overpass-mono-light.woff \
  fonts/overpass-mono-regular.woff \
  fonts/overpass-mono-semibold.woff \
  fonts/overpass-regular.woff

fontsdir = $(HTML_DIR)/fonts
fonts_DATA = $(fonts)

logofiles = \
  logos/logo-base.svg \
  logos/logo-square.svg \
  logos/logo-square-powered.svg \
  logos/logo-banner-dark.svg \
  logos/logo-banner-light.svg \
  logos/logo-square-96.png \
  logos/logo-square-128.png \
  logos/logo-square-192.png \
  logos/logo-square-256.png \
  logos/logo-square-powered-96.png \
  logos/logo-square-powered-128.png \
  logos/logo-square-powered-192.png \
  logos/logo-square-powered-256.png \
  logos/logo-banner-dark-256.png \
  logos/logo-banner-dark-800.png \
  logos/logo-banner-light-256.png \
  logos/logo-banner-light-800.png

logofilesdir = $(HTML_DIR)/logos
logofiles_DATA = $(logofiles)

assets = \
  android-chrome-192x192.png \
  android-chrome-256x256.png \
  apple-touch-icon.png \
  architecture.gif \
  browserconfig.xml \
  favicon.ico \
  favicon-16x16.png \
  favicon-32x32.png \
  generic.css \
  libvirt.css \
  libvirt-daemon-arch.png \
  libvirt-driver-arch.png \
  libvirt-object-model.png \
  libvirt-virConnect-example.png \
  main.css \
  manifest.json \
  migration-managed-direct.png \
  migration-managed-p2p.png \
  migration-native.png \
  migration-tunnel.png \
  migration-unmanaged-direct.png \
  mobile.css \
  mstile-150x150.png \
  node.gif \
  $(NULL)

internals_html_in = \
  $(patsubst $(srcdir)/%,%,$(wildcard $(srcdir)/internals/*.html.in))
internals_rst = \
  $(patsubst $(srcdir)/%,%,$(wildcard $(srcdir)/internals/*.rst))
internals_rst_html_in = \
  $(internals_rst:%.rst=%.html.in)
internals_html = \
  $(internals_html_in:%.html.in=%.html) \
  $(internals_rst_html_in:%.html.in=%.html)

internalsdir = $(HTML_DIR)/internals
internals_DATA = $(internals_html)

kbase_html_in = \
  $(patsubst $(srcdir)/%,%,$(wildcard $(srcdir)/kbase/*.html.in))
kbase_rst = \
  $(patsubst $(srcdir)/%,%,$(wildcard $(srcdir)/kbase/*.rst))
kbase_rst_html_in = \
  $(kbase_rst:%.rst=%.html.in)
kbase_html = \
  $(kbase_html_in:%.html.in=%.html) \
  $(kbase_rst_html_in:%.html.in=%.html)

kbasedir = $(HTML_DIR)/kbase
kbase_DATA = $(kbase_html)

# Sync with src/util/
KEYCODES = linux osx atset1 atset2 atset3 xtkbd usb win32 qnum
KEYNAMES = linux osx win32

manpages_rst = \
  manpages/index.rst \
  $(NULL)
manpages1_rst = \
  manpages/virt-pki-validate.rst \
  manpages/virt-xml-validate.rst \
  manpages/virt-admin.rst \
  manpages/virsh.rst \
  $(NULL)
manpages7_rst = \
  $(KEYCODES:%=manpages/virkeycode-%.rst) \
  $(KEYNAMES:%=manpages/virkeyname-%.rst) \
  $(NULL)
manpages8_rst = $(NULL)
manpages_rst += \
  $(manpages1_rst) \
  $(manpages7_rst) \
  $(manpages8_rst) \
  $(NULL)
if WITH_LIBVIRTD
manpages8_rst += \
  manpages/libvirtd.rst \
  manpages/virtlockd.rst \
  manpages/virtlogd.rst \
  $(NULL)
else ! WITH_LIBVIRTD
manpages_rst += \
  manpages/libvirtd.rst \
  manpages/virtlockd.rst \
  manpages/virtlogd.rst \
  $(NULL)
endif ! WITH_LIBVIRTD
if WITH_HOST_VALIDATE
  manpages1_rst += manpages/virt-host-validate.rst
else ! WITH_HOST_VALIDATE
  manpages_rst += manpages/virt-host-validate.rst
endif ! WITH_HOST_VALIDATE
if WITH_LOGIN_SHELL
  manpages1_rst += manpages/virt-login-shell.rst
else ! WITH_LOGIN_SHELL
  manpages_rst += manpages/virt-login-shell.rst
endif ! WITH_LOGIN_SHELL
if WITH_SANLOCK
  manpages8_rst += manpages/virt-sanlock-cleanup.rst
else ! WITH_SANLOCK
  manpages_rst += manpages/virt-sanlock-cleanup.rst
endif ! WITH_SANLOCK
if WITH_QEMU
  manpages1_rst += manpages/virt-qemu-run.rst
else ! WITH_QEMU
  manpages_rst += manpages/virt-qemu-run.rst
endif ! WITH_QEMU
manpages_rst_html_in = \
  $(manpages_rst:%.rst=%.html.in)
manpages_html = \
  $(manpages_rst_html_in:%.html.in=%.html)

man1_MANS = $(manpages1_rst:%.rst=%.1)
man7_MANS = $(manpages7_rst:%.rst=%.7)
man8_MANS = $(manpages8_rst:%.rst=%.8)

%.1: %.rst
	$(AM_V_GEN)$(MKDIR_P) `dirname $@` && \
	   grep -v '^\.\. contents::' < $< | \
	   sed -e 's|SYSCONFDIR|$(sysconfdir)|g' \
	       -e 's|RUNSTATEDIR|$(runstatedir)|g' | \
	   $(RST2MAN) --strict > $@ || { rm $@ && exit 1; }

%.7: %.rst
	$(AM_V_GEN)$(MKDIR_P) `dirname $@` && \
	   grep -v '^\.\. contents::' < $< | \
	   sed -e 's|SYSCONFDIR|$(sysconfdir)|g' \
	       -e 's|RUNSTATEDIR|$(runstatedir)|g' | \
	   $(RST2MAN) --strict > $@ || { rm $@ && exit 1; }

%.8: %.rst
	$(AM_V_GEN)$(MKDIR_P) `dirname $@` && \
	   grep -v '^\.\. contents::' < $< | \
	   sed -e 's|SYSCONFDIR|$(sysconfdir)|g' \
	       -e 's|RUNSTATEDIR|$(runstatedir)|g' | \
	   $(RST2MAN) --strict > $@ || { rm $@ && exit 1; }

manpages/virkeycode-%.rst: $(top_srcdir)/src/keycodemapdb/data/keymaps.csv \
		$(top_srcdir)/src/keycodemapdb/tools/keymap-gen Makefile.am
	$(AM_V_GEN)export NAME=`echo $@ | \
		sed -e 's,manpages/virkeycode-,,' -e 's,\.rst,,'` && \
		$(MKDIR_P) manpages/ && \
		$(RUNUTF8) $(PYTHON) $(top_srcdir)/src/keycodemapdb/tools/keymap-gen \
		code-docs \
		--lang rst \
		--title "virkeycode-$$NAME" \
		--subtitle "Key code values for $$NAME" \
		$(top_srcdir)/src/keycodemapdb/data/keymaps.csv $$NAME > $@

manpages/virkeyname-%.rst: $(top_srcdir)/src/keycodemapdb/data/keymaps.csv \
		$(top_srcdir)/src/keycodemapdb/tools/keymap-gen Makefile.am
	$(AM_V_GEN)export NAME=`echo $@ | \
		sed -e 's,manpages/virkeyname-,,' -e 's,\.rst,,'` && \
		$(MKDIR_P) manpages/ && \
		$(RUNUTF8) $(PYTHON) $(top_srcdir)/src/keycodemapdb/tools/keymap-gen \
		name-docs \
		--lang rst \
		--title "virkeyname-$$NAME" \
		--subtitle "Key name values for $$NAME" \
		$(top_srcdir)/src/keycodemapdb/data/keymaps.csv $$NAME > $@

manpagesdir = $(HTML_DIR)/manpages
manpages_DATA = $(manpages_html)

# Generate hvsupport.html and news.html first, since they take one extra step.
dot_html_generated_in = \
  hvsupport.html.in \
  news.html.in
dot_html_in = \
  $(notdir $(wildcard $(srcdir)/*.html.in))
dot_rst = \
  $(notdir $(wildcard $(srcdir)/*.rst))
dot_rst_html_in = \
  $(dot_rst:%.rst=%.html)
dot_html = \
  $(dot_html_generated_in:%.html.in=%.html) \
  $(dot_html_in:%.html.in=%.html) \
  $(dot_rst_html_in:%.html.in=%.html)

htmldir = $(HTML_DIR)
html_DATA = $(assets) $(dot_html)

apidir = $(pkgdatadir)/api
api_DATA = \
       libvirt-api.xml \
       libvirt-qemu-api.xml \
       libvirt-lxc-api.xml \
       libvirt-admin-api.xml

fig = \
  libvirt-daemon-arch.fig \
  libvirt-driver-arch.fig \
  libvirt-object-model.fig \
  migration-managed-direct.fig \
  migration-managed-p2p.fig \
  migration-native.fig \
  migration-tunnel.fig \
  migration-unmanaged-direct.fig

schemadir = $(pkgdatadir)/schemas
schema_DATA = $(wildcard $(srcdir)/schemas/*.rng)

EXTRA_DIST= \
  site.xsl subsite.xsl newapi.xsl page.xsl \
  wrapstring.xsl \
  $(dot_html_in) $(dot_rst) $(apipng) \
  $(fig) $(assets) \
  $(javascript) $(logofiles) \
  $(internals_html_in) $(internals_rst) $(fonts) \
  $(kbase_html_in) $(kbase_rst) \
  $(manpages_rst) \
  aclperms.htmlinc \
  $(schema_DATA)

acl_generated = aclperms.htmlinc

aclperms.htmlinc: $(top_srcdir)/src/access/viraccessperm.h \
        $(top_srcdir)/scripts/genaclperms.py Makefile.am
	$(AM_V_GEN)$(RUNUTF8) $(PYTHON) $(top_srcdir)/scripts/genaclperms.py $< > $@

CLEANFILES = \
  $(dot_html) \
  $(apihtml) \
  $(apiadminhtml) \
  $(apiqemuhtml) \
  $(apilxchtml) \
  $(internals_html) \
  $(kbase_html) \
  $(manpages_html) \
  $(man1_MANS) \
  $(man7_MANS) \
  $(manpages7_rst) \
  $(man8_MANS) \
  $(api_DATA) \
  $(dot_html_generated_in) \
  aclperms.htmlinc

timestamp="$(shell if test -n "$$SOURCE_DATE_EPOCH"; \
		   then \
		     date -u --date="@$$SOURCE_DATE_EPOCH"; \
		   else \
		     date -u; \
		   fi)"

hvsupport.html: hvsupport.html.in

hvsupport.html.in: $(top_srcdir)/scripts/hvsupport.py $(api_DATA) \
		$(top_srcdir)/src/libvirt_public.syms \
	$(top_srcdir)/src/libvirt_qemu.syms $(top_srcdir)/src/libvirt_lxc.syms \
	$(top_srcdir)/src/driver.h
	$(AM_V_GEN)$(RUNUTF8) $(PYTHON) $(top_srcdir)/scripts/hvsupport.py \
		$(top_srcdir) $(top_builddir) > $@ || { rm $@ && exit 1; }

news.html.in: \
	  $(srcdir)/news.xml \
	  $(srcdir)/news-html.xsl
	$(AM_V_GEN)$(XSLTPROC) --nonet \
	    $(srcdir)/news-html.xsl \
	    $(srcdir)/news.xml \
	  >$@ \
	    || { rm -f $@; exit 1; };
EXTRA_DIST += \
	$(srcdir)/news.xml \
	$(srcdir)/news.rng \
	$(srcdir)/news-html.xsl

%.png: %.fig
	convert -rotate 90 $< $@

manpages/%.html.in: manpages/%.rst
	$(AM_V_GEN)$(MKDIR_P) `dirname $@` && \
	 grep -v '^:Manual ' < $< | \
	  sed -e 's|SYSCONFDIR|$(sysconfdir)|g' \
	     -e 's|RUNSTATEDIR|$(runstatedir)|g' | \
	  $(RST2HTML) --strict > $@ || { rm $@ && exit 1; }

%.html.in: %.rst
	$(AM_V_GEN)$(MKDIR_P) `dirname $@` && \
	  $(RST2HTML) --strict $< > $@ || { rm $@ && exit 1; }

%.html.tmp: %.html.in site.xsl subsite.xsl page.xsl \
		$(acl_generated)
	$(AM_V_GEN)name=`echo $@ | sed -e 's/.tmp//'`; \
	  genhtmlin=`echo $@ | sed -e 's/.tmp/.in/'`; \
	  rst=`echo $@ | sed -e 's/.html.tmp/.rst/'`; \
	  src="$$genhtmlin"; \
	  test -f "$$genhtmlin" && src="$$rst"; \
	  dir=`dirname $@` ; \
	  if test "$$dir" = "."; \
	  then \
	    style=site.xsl; \
	  else \
	    $(MKDIR_P) $$dir; \
	    style=subsite.xsl; \
	  fi; \
	  $(XSLTPROC) --stringparam pagename $$name \
	    --stringparam pagesrc $$src \
	    --stringparam builddir '$(abs_top_builddir)' \
	    --stringparam timestamp $(timestamp) --nonet \
	    $(top_srcdir)/docs/$$style $< > $@ \
	    || { rm $@ && exit 1; }

%.html: %.html.tmp
	$(AM_V_GEN)$(XMLLINT) --nonet --format $< > $@ \
	  || { rm $@ && exit 1; }

$(apihtml_generated): html/index.html
$(apiadminhtml_generated): html/index-admin.html
$(apiqemuhtml_generated): html/index-qemu.html
$(apilxchtml_generated): html/index-lxc.html

html/index.html: libvirt-api.xml newapi.xsl page.xsl $(APIBUILD_STAMP)
	$(AM_V_GEN)$(XSLTPROC) --nonet -o ./ \
	  --stringparam builddir '$(abs_top_builddir)' \
	  --stringparam timestamp $(timestamp) \
	  $(srcdir)/newapi.xsl libvirt-api.xml

html/index-%.html: libvirt-%-api.xml newapi.xsl page.xsl $(APIBUILD_STAMP)
	$(AM_V_GEN)$(XSLTPROC) --nonet -o ./ \
	  --stringparam builddir '$(abs_top_builddir)' \
	  --stringparam timestamp $(timestamp) \
	  --stringparam indexfile $(@:html/%=%) \
	  $(srcdir)/newapi.xsl $<

check-html:
	$(XMLLINT) --nonet --noout html/*.html

check-local: check-html

python_generated_files = \
		html/libvirt-libvirt-lxc.html \
		html/libvirt-libvirt-qemu.html \
		html/libvirt-libvirt-admin.html \
		html/libvirt-virterror.html \
		$(api_DATA) \
		$(NULL)

APIBUILD=$(top_srcdir)/scripts/apibuild.py
APIBUILD_STAMP=apibuild.py.stamp
CLEANFILES += $(APIBUILD_STAMP)

$(python_generated_files): $(APIBUILD_STAMP)

$(APIBUILD_STAMP): $(top_srcdir)/scripts/apibuild.py \
		$(top_srcdir)/include/libvirt/libvirt.h \
		$(top_srcdir)/include/libvirt/libvirt-common.h.in \
		$(top_srcdir)/include/libvirt/libvirt-domain-checkpoint.h \
		$(top_srcdir)/include/libvirt/libvirt-domain-snapshot.h \
		$(top_srcdir)/include/libvirt/libvirt-domain.h \
		$(top_srcdir)/include/libvirt/libvirt-event.h \
		$(top_srcdir)/include/libvirt/libvirt-host.h \
		$(top_srcdir)/include/libvirt/libvirt-interface.h \
		$(top_srcdir)/include/libvirt/libvirt-network.h \
		$(top_srcdir)/include/libvirt/libvirt-nodedev.h \
		$(top_srcdir)/include/libvirt/libvirt-nwfilter.h \
		$(top_srcdir)/include/libvirt/libvirt-secret.h \
		$(top_srcdir)/include/libvirt/libvirt-storage.h \
		$(top_srcdir)/include/libvirt/libvirt-stream.h \
		$(top_srcdir)/include/libvirt/libvirt-lxc.h \
		$(top_srcdir)/include/libvirt/libvirt-qemu.h \
		$(top_srcdir)/include/libvirt/libvirt-admin.h \
		$(top_srcdir)/include/libvirt/virterror.h \
		$(top_srcdir)/src/libvirt.c \
		$(top_srcdir)/src/libvirt-domain-checkpoint.c \
		$(top_srcdir)/src/libvirt-domain-snapshot.c \
		$(top_srcdir)/src/libvirt-domain.c \
		$(top_srcdir)/src/libvirt-host.c \
		$(top_srcdir)/src/libvirt-interface.c \
		$(top_srcdir)/src/libvirt-network.c \
		$(top_srcdir)/src/libvirt-nodedev.c \
		$(top_srcdir)/src/libvirt-nwfilter.c \
		$(top_srcdir)/src/libvirt-secret.c \
		$(top_srcdir)/src/libvirt-storage.c \
		$(top_srcdir)/src/libvirt-stream.c \
		$(top_srcdir)/src/libvirt-lxc.c \
		$(top_srcdir)/src/libvirt-qemu.c \
		$(top_srcdir)/src/admin/libvirt-admin.c \
		$(top_srcdir)/src/util/virerror.c \
		$(top_srcdir)/src/util/virevent.c \
		$(top_srcdir)/src/util/virtypedparam-public.c
	$(AM_V_GEN)srcdir=$(srcdir) builddir=$(builddir) \
		$(RUNUTF8) $(PYTHON) $(APIBUILD)
	touch $@
