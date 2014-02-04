## Process this file with automake to produce Makefile.in

# Copyright (C) 2013 Yuto KAWAMURA(kawamuray) <kawamuray.dadada@gmail.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.  If not, see
# <http://www.gnu.org/licenses/>.
#
# Author: Yuto KAWAMURA(kawamuray)

INCLUDES = -I$(top_srcdir)

ws_plugin_LTLIBRARIES     = libvirt.la
libvirt_la_SOURCES        = packet-libvirt.h packet-libvirt.c plugin.c
libvirt_la_CPPFLAGS       = $(WS_DISSECTOR_CPPFLAGS)
libvirt_la_LDFLAGS        = -avoid-version -module

packet-libvirt.c: packet-libvirt.h libvirt/protocol.h

plugin.c: packet-libvirt.c
	$(srcdir)/../util/make-dissector-reg . plugin $<

WS_DISSECTOR_PROTO_FILES  = \
  $(top_srcdir)/src/remote/remote_protocol.x \
  $(top_srcdir)/src/remote/qemu_protocol.x \
  $(top_srcdir)/src/remote/lxc_protocol.x \
  $(top_srcdir)/src/rpc/virkeepaliveprotocol.x

libvirt/protocol.h: $(srcdir)/../util/genxdrstub.pl $(WS_DISSECTOR_PROTO_FILES)
	$(MKDIR_P) libvirt
	LIBVIRT_VERSION=$(LIBVIRT_VERSION) \
          $(PERL) $(srcdir)/../util/genxdrstub.pl $(WS_DISSECTOR_PROTO_FILES)

clean-local:
	-rm -rf libvirt plugin.c
