## Process this file with automake to produce Makefile.in

## Copyright (C) 2005-2018 Red Hat, Inc.
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

# No libraries with the exception of LIBXML should be listed
# here. List them against the individual XXX_la_CFLAGS targets
# that actually use them.

RPC_PROBE_FILES =

include admin/Makefile.inc.am


# Keep this list synced with RPC_PROBE_FILES
PROTOCOL_STRUCTS = \
	$(srcdir)/remote_protocol-structs \
	$(srcdir)/lxc_protocol-structs \
	$(srcdir)/qemu_protocol-structs \
	$(srcdir)/virnetprotocol-structs \
	$(srcdir)/virkeepaliveprotocol-structs \
	$(srcdir)/lxc_monitor_protocol-structs \
	$(srcdir)/lock_protocol-structs \
	$(srcdir)/admin_protocol-structs \
	$(NULL)

if WITH_REMOTE
check-protocol: $(PROTOCOL_STRUCTS) $(PROTOCOL_STRUCTS:structs=struct)

# Ensure that we don't change the struct or member names or member ordering
# in remote_protocol.x  The check-remote-protocol.py script post-processes
# output to extract the bits we want.

CHECK_REMOTE_PROTOCOL = $(top_srcdir)/scripts/check-remote-protocol.py

# The .o file that pdwtags parses is created as a side effect of running
# libtool; but from make's perspective we depend on the .lo file.
$(srcdir)/remote_protocol-struct \
	$(srcdir)/qemu_protocol-struct \
	$(srcdir)/lxc_protocol-struct: \
		$(srcdir)/%-struct: remote/libvirt_driver_remote_la-%.lo
	$(AM_V_GEN)$(RUNUTF8) $(PYTHON) $(CHECK_REMOTE_PROTOCOL) \
		"$(CC)" $< $(@)s
$(srcdir)/virnetprotocol-struct $(srcdir)/virkeepaliveprotocol-struct: \
		$(srcdir)/%-struct: rpc/libvirt_net_rpc_la-%.lo
	$(AM_V_GEN)$(RUNUTF8) $(PYTHON) $(CHECK_REMOTE_PROTOCOL) \
		"$(CC)" $< $(@)s
if WITH_LXC
$(srcdir)/lxc_monitor_protocol-struct: \
		$(srcdir)/%-struct: lxc/libvirt_driver_lxc_impl_la-%.lo
	$(AM_V_GEN)$(RUNUTF8) $(PYTHON) $(CHECK_REMOTE_PROTOCOL) \
		"$(CC)" $< $(@)s
endif WITH_LXC
$(srcdir)/lock_protocol-struct: \
		$(srcdir)/%-struct: locking/lockd_la-%.lo
	$(AM_V_GEN)$(RUNUTF8) $(PYTHON) $(CHECK_REMOTE_PROTOCOL) \
		"$(CC)" $< $(@)s
$(srcdir)/admin_protocol-struct: \
		$(srcdir)/%-struct: admin/libvirt_admin_la-%.lo
	$(AM_V_GEN)$(RUNUTF8) $(PYTHON) $(CHECK_REMOTE_PROTOCOL) \
		"$(CC)" $< $(@)s

else !WITH_REMOTE
# The $(PROTOCOL_STRUCTS) files must live in git, because they cannot be
# re-generated when configured --without-remote.
check-protocol:
endif !WITH_REMOTE

check-local: check-protocol \
	check-admin
.PHONY: check-protocol $(PROTOCOL_STRUCTS:structs=struct)
