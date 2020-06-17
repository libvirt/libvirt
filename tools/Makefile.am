## Copyright (C) 2005-2016 Red Hat, Inc.
## Copyright (C) 2013 Yuto KAWAMURA(kawamuray) <kawamuray.dadada@gmail.com>
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

# We do not want to accidentally include stuff from src/
# dir or public API dir. Specific files can
# still be included via their path relative to the root if
# needed
STANDALONE_CPPFLAGS = -I$(top_srcdir)

confdir = $(sysconfdir)/libvirt
conf_DATA =

bin_SCRIPTS = virt-pki-validate
libexec_SCRIPTS = libvirt-guests.sh

if WITH_SANLOCK
sbin_SCRIPTS = virt-sanlock-cleanup
endif WITH_SANLOCK

if WITH_LOGIN_SHELL
conf_DATA += virt-login-shell.conf
endif WITH_LOGIN_SHELL

virt-pki-validate: virt-pki-validate.in Makefile
	$(AM_V_GEN)sed -e 's|[@]sysconfdir@|$(sysconfdir)|g' \
		       -e 's|[@]VERSION@|$(VERSION)|g' \
	  < $< > $@ || (rm $@ && exit 1) && chmod +x $@

virt-sanlock-cleanup: virt-sanlock-cleanup.in Makefile
	$(AM_V_GEN)sed -e 's|[@]sysconfdir@|$(sysconfdir)|' \
	    -e 's|[@]localstatedir@|$(localstatedir)|' < $< > $@ \
	    || (rm $@ && exit 1) && chmod +x $@

noinst_LTLIBRARIES =

BUILT_SOURCES =

install-data-local: install-systemd install-nss \
	install-bash-completion

uninstall-local: uninstall-systemd uninstall-nss \
	uninstall-bash-completion

install-sysconfig:
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/sysconfig
	$(INSTALL_DATA) $(srcdir)/libvirt-guests.sysconf \
	  $(DESTDIR)$(sysconfdir)/sysconfig/libvirt-guests

uninstall-sysconfig:
	rm -f $(DESTDIR)$(sysconfdir)/sysconfig/libvirt-guests
	rmdir $(DESTDIR)$(sysconfdir)/sysconfig ||:

libvirt-guests.sh: libvirt-guests.sh.in $(top_builddir)/config.status
	$(AM_V_GEN)sed \
	    -e 's|[@]PACKAGE[@]|$(PACKAGE)|g' \
	    -e 's|[@]bindir[@]|$(bindir)|g' \
	    -e 's|[@]localedir[@]|$(localedir)|g' \
	    -e 's|[@]localstatedir[@]|$(localstatedir)|g' \
	    -e 's|[@]sbindir[@]|$(sbindir)|g' \
	    -e 's|[@]sysconfdir[@]|$(sysconfdir)|g' \
	    < $< > $@-t && \
	    chmod a+x $@-t && \
	    mv $@-t $@
BUILT_SOURCES += libvirt-guests.sh

SYSTEMD_UNIT_DIR = $(prefix)/lib/systemd/system

if LIBVIRT_INIT_SCRIPT_SYSTEMD
install-systemd: libvirt-guests.service install-sysconfig libvirt-guests.sh
	$(MKDIR_P) $(DESTDIR)$(SYSTEMD_UNIT_DIR)
	$(INSTALL_DATA) libvirt-guests.service \
	  $(DESTDIR)$(SYSTEMD_UNIT_DIR)/libvirt-guests.service

uninstall-systemd: uninstall-sysconfig
	rm -f $(DESTDIR)$(SYSTEMD_UNIT_DIR)/libvirt-guests.service
	rmdir $(DESTDIR)$(SYSTEMD_UNIT_DIR) ||:

BUILT_SOURCES += libvirt-guests.service

else ! LIBVIRT_INIT_SCRIPT_SYSTEMD
install-systemd:
uninstall-systemd:
endif ! LIBVIRT_INIT_SCRIPT_SYSTEMD

libvirt-guests.service: libvirt-guests.service.in $(top_builddir)/config.status
	$(AM_V_GEN)sed \
	    -e 's|[@]PACKAGE[@]|$(PACKAGE)|g' \
	    -e 's|[@]bindir[@]|$(bindir)|g' \
	    -e 's|[@]localedir[@]|$(localedir)|g' \
	    -e 's|[@]localstatedir[@]|$(localstatedir)|g' \
	    -e 's|[@]sbindir[@]|$(sbindir)|g' \
	    -e 's|[@]sysconfdir[@]|$(sysconfdir)|g' \
	    -e 's|[@]libexecdir[@]|$(libexecdir)|g' \
	    < $< > $@-t && \
	    mv $@-t $@


if WITH_BASH_COMPLETION
install-bash-completion:
	$(MKDIR_P) "$(DESTDIR)$(BASH_COMPLETIONS_DIR)"
	$(INSTALL_DATA) $(srcdir)/bash-completion/vsh \
		"$(DESTDIR)$(BASH_COMPLETIONS_DIR)/vsh"
	( cd $(DESTDIR)$(BASH_COMPLETIONS_DIR) && \
		rm -f virsh virt-admin && \
		$(LN_S) vsh virsh && \
		$(LN_S) vsh virt-admin )

uninstall-bash-completion:
	rm -f $(DESTDIR)$(BASH_COMPLETIONS_DIR)/vsh \
		$(DESTDIR)$(BASH_COMPLETIONS_DIR)/virsh \
		$(DESTDIR)$(BASH_COMPLETIONS_DIR)/virt-admin
	rmdir $(DESTDIR)$(BASH_COMPLETIONS_DIR) ||:
else ! WITH_BASH_COMPLETION
install-bash-completion:
uninstall-bash-completion:
endif ! WITH_BASH_COMPLETION


if WITH_WIRESHARK_DISSECTOR

ws_plugin_LTLIBRARIES = wireshark/src/libvirt.la
wireshark_src_libvirt_la_CFLAGS = \
	-I wireshark/src $(WIRESHARK_DISSECTOR_CFLAGS) $(XDR_CFLAGS) $(AM_CFLAGS)
wireshark_src_libvirt_la_LDFLAGS = -avoid-version -module
wireshark_src_libvirt_la_SOURCES = \
	wireshark/src/packet-libvirt.h \
	wireshark/src/packet-libvirt.c \
	wireshark/src/plugin.c

wireshark/src/packet-libvirt.c: wireshark/src/packet-libvirt.h \
		wireshark/src/libvirt/protocol.h

WS_DISSECTOR_PROTO_FILES  = \
  $(abs_top_srcdir)/src/remote/remote_protocol.x \
  $(abs_top_srcdir)/src/remote/qemu_protocol.x \
  $(abs_top_srcdir)/src/remote/lxc_protocol.x \
  $(abs_top_srcdir)/src/rpc/virkeepaliveprotocol.x

wireshark/src/libvirt/protocol.h: wireshark/util/genxdrstub.pl \
		$(WS_DISSECTOR_PROTO_FILES)
	$(AM_V_GEN)$(MKDIR_P) wireshark/src/libvirt && \
	cd wireshark/src && \
	LIBVIRT_VERSION=$(LIBVIRT_VERSION) \
		  $(PERL) $(abs_top_srcdir)/tools/wireshark/util/genxdrstub.pl \
		  $(WS_DISSECTOR_PROTO_FILES)

endif WITH_WIRESHARK_DISSECTOR

if WITH_BSD_NSS
LIBVIRT_NSS_SYMBOL_FILE = \
	$(srcdir)/nss/libvirt_nss_bsd.syms
LIBVIRT_GUEST_NSS_SYMBOL_FILE = \
	$(LIBVIRT_NSS_SYMBOL_FILE)
NSS_SO_VER = 1

install-nss:
	( cd $(DESTDIR)$(libdir) && \
	  rm -f nss_libvirt.so.$(NSS_SO_VER) && \
	  $(LN_S) libnss_libvirt.so.$(NSS_SO_VER) nss_libvirt.so.$(NSS_SO_VER) && \
	  rm -f nss_libvirt_guest.so.$(NSS_SO_VER) && \
	  $(LN_S) libnss_libvirt_guest.so.$(NSS_SO_VER) \
	  nss_libvirt_guest.so.$(NSS_SO_VER))

uninstall-nss:
	-rm -f $(DESTDIR)$(libdir)/nss_libvirt.so.$(NSS_SO_VER)
	-rm -f $(DESTDIR)$(libdir)/nss_libvirt_guest.so.$(NSS_SO_VER)
else ! WITH_BSD_NSS
LIBVIRT_NSS_SYMBOL_FILE = \
	$(srcdir)/nss/libvirt_nss.syms
LIBVIRT_GUEST_NSS_SYMBOL_FILE = \
	$(srcdir)/nss/libvirt_guest_nss.syms
NSS_SO_VER = 2

install-nss:
uninstall-nss:
endif ! WITH_BSD_NSS

LIBVIRT_NSS_SOURCES = \
	nss/libvirt_nss.c \
	nss/libvirt_nss.h \
	nss/libvirt_nss_leases.c \
	nss/libvirt_nss_leases.h \
	$(NULL)

if WITH_NSS
noinst_LTLIBRARIES += nss/libnss_libvirt_impl.la
nss_libnss_libvirt_impl_la_SOURCES = \
	$(LIBVIRT_NSS_SOURCES)

nss_libnss_libvirt_impl_la_CPPFLAGS = $(STANDALONE_CPPFLAGS)
nss_libnss_libvirt_impl_la_CFLAGS = \
	-DLIBVIRT_NSS \
	$(YAJL_CFLAGS) \
	$(AM_CFLAGS) \
	$(NULL)

nss_libnss_libvirt_impl_la_LIBADD = \
	$(YAJL_LIBS) \
	$(NULL)

nss_libnss_libvirt_la_SOURCES =
nss_libnss_libvirt_la_LDFLAGS = \
	$(VERSION_SCRIPT_FLAGS)$(LIBVIRT_NSS_SYMBOL_FILE) \
	$(AM_LDFLAGS) \
	-module \
	-export-dynamic \
	-avoid-version \
	-shared \
	-shrext .so.$(NSS_SO_VER)

nss_libnss_libvirt_la_LIBADD = \
	nss/libnss_libvirt_impl.la

nss_libnss_libvirt_la_DEPENDENCIES = \
	$(nss_libnss_libvirt_la_LIBADD) \
	$(LIBVIRT_NSS_SYMBOL_FILE)

noinst_LTLIBRARIES += nss/libnss_libvirt_guest_impl.la
nss_libnss_libvirt_guest_impl_la_SOURCES = \
	$(LIBVIRT_NSS_SOURCES) \
	nss/libvirt_nss_macs.h \
	nss/libvirt_nss_macs.c \
	$(NULL)

nss_libnss_libvirt_guest_impl_la_CPPFLAGS = $(STANDALONE_CPPFLAGS)
nss_libnss_libvirt_guest_impl_la_CFLAGS = \
	-DLIBVIRT_NSS \
	-DLIBVIRT_NSS_GUEST \
	$(YAJL_CFLAGS) \
	$(AM_CFLAGS) \
	$(NULL)

nss_libnss_libvirt_guest_impl_la_LIBADD = \
	$(YAJL_LIBS) \
	$(NULL)

nss_libnss_libvirt_guest_la_SOURCES =
nss_libnss_libvirt_guest_la_LDFLAGS = \
	$(VERSION_SCRIPT_FLAGS)$(LIBVIRT_GUEST_NSS_SYMBOL_FILE) \
	$(AM_LDFLAGS) \
	-module \
	-export-dynamic \
	-avoid-version \
	-shared \
	-shrext .so.$(NSS_SO_VER)

nss_libnss_libvirt_guest_la_LIBADD = \
	nss/libnss_libvirt_guest_impl.la

nss_libnss_libvirt_guest_la_DEPENDENCIES = \
	$(nss_libnss_libvirt_guest_la_LIBADD) \
	$(LIBVIRT_GUEST_NSS_SYMBOL_FILE)

lib_LTLIBRARIES = \
	nss/libnss_libvirt.la \
	nss/libnss_libvirt_guest.la

endif WITH_NSS
