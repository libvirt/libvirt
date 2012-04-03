## Copyright (C) 2005-2011 Red Hat, Inc.
## See COPYING.LIB for the License of this software

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
