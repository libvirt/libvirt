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


endif WITH_WIRESHARK_DISSECTOR
