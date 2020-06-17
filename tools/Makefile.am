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

noinst_LTLIBRARIES =

install-data-local: install-nss

uninstall-local: uninstall-nss

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
