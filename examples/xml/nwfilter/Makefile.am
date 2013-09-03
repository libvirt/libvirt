## Copyright (C) 2005-2011, 2013 Red Hat, Inc.
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

FILTERS = \
	allow-arp.xml \
	allow-dhcp-server.xml \
	allow-dhcp.xml \
	allow-incoming-ipv4.xml \
	allow-ipv4.xml \
	clean-traffic.xml \
	no-arp-spoofing.xml \
	no-arp-ip-spoofing.xml \
	no-arp-mac-spoofing.xml \
	no-ip-multicast.xml \
	no-ip-spoofing.xml \
	no-mac-broadcast.xml \
	no-mac-spoofing.xml \
	no-other-l2-traffic.xml \
	no-other-rarp-traffic.xml \
	qemu-announce-self.xml \
	qemu-announce-self-rarp.xml

EXTRA_DIST=$(FILTERS)

confdir = $(sysconfdir)/libvirt

NWFILTER_DIR = "$(DESTDIR)$(sysconfdir)/libvirt/nwfilter"

if WITH_NWFILTER
install-data-local:
	$(MKDIR_P) "$(NWFILTER_DIR)"
	for f in $(FILTERS); do \
		$(INSTALL_DATA) $(srcdir)/$$f "$(NWFILTER_DIR)"; \
	done

uninstall-local::
	for f in $(FILTERS); do \
		rm -f "$(NWFILTER_DIR)/$$f"; \
	done
	-test -z $(shell ls $(NWFILTER_DIR)) || rmdir $(NWFILTER_DIR)
endif WITH_NWFILTER
