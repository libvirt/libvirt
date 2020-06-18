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

all: vpathhack

# This hack enables us to view the web pages
# from within the uninstalled build tree
vpathhack:
	@for dir in logos; \
	do \
	  test -e $$dir || ln -s $(srcdir)/$$dir $$dir ; \
	done

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

schemadir = $(pkgdatadir)/schemas
schema_DATA = $(wildcard $(srcdir)/schemas/*.rng)

manpages/%.html.in: manpages/%.rst
	$(AM_V_GEN)$(MKDIR_P) `dirname $@` && \
	 grep -v '^:Manual ' < $< | \
	  sed -e 's|SYSCONFDIR|$(sysconfdir)|g' \
	     -e 's|RUNSTATEDIR|$(runstatedir)|g' | \
	  $(RST2HTML) --strict > $@ || { rm $@ && exit 1; }

check-html:
	$(XMLLINT) --nonet --noout html/*.html

check-local: check-html
