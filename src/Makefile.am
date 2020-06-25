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

BUILT_SOURCES =
nodist_conf_DATA =
DRIVER_SOURCE_FILES =
STATEFUL_DRIVER_SOURCE_FILES =
INSTALL_DATA_DIRS =
INSTALL_DATA_LOCAL =
UNINSTALL_LOCAL =
SYM_FILES =
USED_SYM_FILES =
augeas_DATA =
augeastest_DATA =
conf_DATA =
if WITH_DTRACE_PROBES
tapset_DATA =
endif WITH_DTRACE_PROBES
libexec_PROGRAMS =
RPC_PROBE_FILES =
LOGROTATE_FILES_IN =
SYSTEMD_UNIT_FILES =
SYSTEMD_UNIT_FILES_IN =
OPENRC_INIT_FILES =
OPENRC_INIT_FILES_IN =
OPENRC_CONF_FILES =
SYSCONF_FILES =
sbin_PROGRAMS =
bin_PROGRAMS =

COMMON_UNIT_VARS = \
	-e 's|[@]runstatedir[@]|$(runstatedir)|g' \
	-e 's|[@]sbindir[@]|$(sbindir)|g' \
	-e 's|[@]sysconfdir[@]|$(sysconfdir)|g' \
	$(NULL)

include util/Makefile.inc.am
include security/Makefile.inc.am
include access/Makefile.inc.am
include logging/Makefile.inc.am
include locking/Makefile.inc.am
include admin/Makefile.inc.am
include vbox/Makefile.inc.am
include qemu/Makefile.inc.am
include bhyve/Makefile.inc.am
include libxl/Makefile.inc.am
include vz/Makefile.inc.am
include lxc/Makefile.inc.am
include interface/Makefile.inc.am
include network/Makefile.inc.am
include nwfilter/Makefile.inc.am
include node_device/Makefile.inc.am
include secret/Makefile.inc.am
include storage/Makefile.inc.am
include remote/Makefile.inc.am


confdir = $(sysconfdir)/libvirt
conf_DATA += libvirt.conf

BUILT_SOURCES += $(nodist_conf_DATA)

augeasdir = $(datadir)/augeas/lenses

augeastestdir = $(datadir)/augeas/lenses/tests

# .libs/libvirt.so is built by libtool as a side-effect of the Makefile
# rule for libvirt.la.  However, checking symbols relies on Linux ELF layout
if WITH_LINUX
check-symfile: libvirt.syms libvirt.la
	$(AM_V_GEN)$(RUNUTF8) $(PYTHON) $(top_srcdir)/scripts/check-symfile.py \
		libvirt.syms .libs/libvirt.so
else ! WITH_LINUX
check-symfile:
endif ! WITH_LINUX
check-symsorting:
	$(AM_V_GEN)$(RUNUTF8) $(PYTHON) $(top_srcdir)/scripts/check-symsorting.py \
		$(srcdir) $(SYM_FILES)

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

DRIVERS = \
	$(srcdir)/driver-hypervisor.h \
	$(srcdir)/driver-interface.h \
	$(srcdir)/driver-network.h \
	$(srcdir)/driver-nodedev.h \
	$(srcdir)/driver-nwfilter.h \
	$(srcdir)/driver-secret.h \
	$(srcdir)/driver-state.h \
	$(srcdir)/driver-storage.h \
	$(srcdir)/driver-stream.h \
	$(NULL)

check-drivername:
	$(AM_V_GEN)$(RUNUTF8) $(PYTHON) $(top_srcdir)/scripts/check-drivername.py \
		$(DRIVERS) \
		$(srcdir)/libvirt_public.syms \
		$(srcdir)/libvirt_qemu.syms \
		$(srcdir)/libvirt_lxc.syms

check-driverimpls:
	$(AM_V_GEN)$(RUNUTF8) $(PYTHON) $(top_srcdir)/scripts/check-driverimpls.py \
		$(DRIVER_SOURCE_FILES)

check-aclrules:
	$(AM_V_GEN)$(RUNUTF8) $(PYTHON) $(top_srcdir)/scripts/check-aclrules.py \
		$(REMOTE_PROTOCOL) \
		$(STATEFUL_DRIVER_SOURCE_FILES)

check-aclperms:
	$(AM_V_GEN)$(RUNUTF8) $(PYTHON) $(top_srcdir)/scripts/check-aclperms.py \
		$(srcdir)/access/viraccessperm.h \
		$(srcdir)/access/viraccessperm.c

check-local: check-protocol check-symfile check-symsorting \
	check-drivername check-driverimpls check-aclrules \
	check-aclperms check-admin
.PHONY: check-protocol $(PROTOCOL_STRUCTS:structs=struct)


# All .syms files should be placed in exactly one of these three lists,
# depending on whether they are stored in git and/or used in the build.
SYM_FILES += $(USED_SYM_FILES)


check-local: check-augeas

check-augeas: $(augeas_DATA) $(augeastest_DATA)
	$(AM_V_GEN) \
	if test -x "$(AUGPARSE)"; then \
	    for f in $(augeastest_DATA); do \
		DIR=$$(dirname "$$f"); \
		FILE=$$(basename "$$f"); \
		"$(AUGPARSE)" \
		    -I "$(srcdir)/$$DIR" -I "$(builddir)/$$DIR" \
		    "$$DIR/$$FILE" || exit 1; \
	    done; \
	fi
.PHONY: check-augeas

AUG_GENTEST_SCRIPT = $(top_srcdir)/scripts/augeas-gentest.py
AUG_GENTEST = $(RUNUTF8) $(PYTHON) $(AUG_GENTEST_SCRIPT)

if WITH_DTRACE_PROBES

BUILT_SOURCES += libvirt_functions.stp

tapset_DATA += libvirt_functions.stp

# Keep this list synced with PROTOCOL_STRUCTS
RPC_PROBE_FILES += $(srcdir)/rpc/virnetprotocol.x \
		  $(srcdir)/rpc/virkeepaliveprotocol.x \
		  $(srcdir)/remote/remote_protocol.x \
		  $(srcdir)/remote/lxc_protocol.x \
		  $(srcdir)/remote/qemu_protocol.x \
		  $(srcdir)/admin/admin_protocol.x

libvirt_functions.stp: $(RPC_PROBE_FILES) $(top_srcdir)/scripts/gensystemtap.py
	$(AM_V_GEN)$(RUNUTF8) $(PYTHON) $(top_srcdir)/scripts/gensystemtap.py \
	  $(RPC_PROBE_FILES) > $@

endif WITH_DTRACE_PROBES

install-sysconfig:
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/sysconfig
	for f in $(SYSCONF_FILES:%.sysconf=%) ; \
	do \
	  tgt=`basename $$f`; \
	  $(INSTALL_DATA) $(srcdir)/$$f.sysconf \
	      $(DESTDIR)$(sysconfdir)/sysconfig/$$tgt; \
	done

uninstall-sysconfig:
	for f in $(SYSCONF_FILES:%.sysconf=%) ; \
	do \
	  tgt=`basename $$f`; \
	  rm -f $(DESTDIR)$(sysconfdir)/sysconfig/$$tgt; \
	done
	rmdir $(DESTDIR)$(sysconfdir)/sysconfig || :

OPENRC_CONF_DIR = $(sysconfdir)/conf.d

install-openrc-conf:
	$(MKDIR_P) $(DESTDIR)$(OPENRC_CONF_DIR)
	for f in $(OPENRC_CONF_FILES:%.confd=%) ; \
	do \
		tgt=`basename $$f`; \
		$(INSTALL_DATA) $(srcdir)/$$f.confd \
			$(DESTDIR)$(OPENRC_CONF_DIR)/$$tgt; \
	done

uninstall-openrc-conf:
	for f in $(OPENRC_CONF_FILES:%.confd=%) ; \
	do \
		tgt=`basename $$f`; \
		rm -f $(DESTDIR)$(OPENRC_CONF_DIR)/$$tgt; \
	done
	rmdir $(DESTDIR)$(OPENRC_CONF_DIR) || :

LOGROTATE_FILES := $(LOGROTATE_FILES_IN:remote/%.in=%)

BUILT_SOURCES += $(LOGROTATE_FILES)

%.logrotate: remote/%.logrotate.in
	$(AM_V_GEN)sed \
	    -e 's|[@]localstatedir[@]|$(localstatedir)|g' \
	    < $< > $@-t && \
	mv $@-t $@

if WITH_LIBVIRTD
install-logrotate: $(LOGROTATE_FILES)
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/logrotate.d/
	for f in $(LOGROTATE_FILES) ; \
	do \
	  tgt=`echo $$f | sed -e 's/.logrotate//'`; \
	  $(INSTALL_DATA) $$f \
		$(DESTDIR)$(sysconfdir)/logrotate.d/$$tgt; \
	done

uninstall-logrotate:
	rm -f $(LOGROTATE_FILES:%.logrotate=$(DESTDIR)$(sysconfdir)/logrotate.d/%)
	rmdir $(DESTDIR)$(sysconfdir)/logrotate.d || :

INSTALL_DATA_LOCAL += install-logrotate
UNINSTALL_LOCAL += uninstall-logrotate
endif WITH_LIBVIRTD


if WITH_LIBVIRTD
if LIBVIRT_INIT_SCRIPT_SYSTEMD

SYSTEMD_UNIT_DIR = $(prefix)/lib/systemd/system

BUILT_SOURCES += $(SYSTEMD_UNIT_FILES)

install-systemd: $(SYSTEMD_UNIT_FILES) install-sysconfig
	$(MKDIR_P) $(DESTDIR)$(SYSTEMD_UNIT_DIR)
	for f in $(SYSTEMD_UNIT_FILES); \
	do \
	  $(INSTALL_DATA) $$f $(DESTDIR)$(SYSTEMD_UNIT_DIR)/ ; \
	done

uninstall-systemd: uninstall-sysconfig
	rm -f $(SYSTEMD_UNIT_FILES:%=$(DESTDIR)$(SYSTEMD_UNIT_DIR)/%)
	rmdir $(DESTDIR)$(SYSTEMD_UNIT_DIR) || :

INSTALL_DATA_LOCAL += install-systemd
UNINSTALL_LOCAL += uninstall-systemd
endif LIBVIRT_INIT_SCRIPT_SYSTEMD

if LIBVIRT_INIT_SCRIPT_OPENRC

OPENRC_INIT_DIR = $(sysconfdir)/init.d

BUILT_SOURCES += $(OPENRC_INIT_FILES)

install-openrc: $(OPENRC_INIT_FILES) install-openrc-conf
	$(MKDIR_P) $(DESTDIR)$(OPENRC_INIT_DIR)
	for f in $(OPENRC_INIT_FILES:%.init=%) ; \
	do \
		tgt=`basename $$f`; \
		$(INSTALL_SCRIPT) $$f.init \
		$(DESTDIR)$(OPENRC_INIT_DIR)/$$tgt ; \
	done

uninstall-openrc: uninstall-openrc-conf
	for f in $(OPENRC_INIT_FILES:%.init=%) ; \
	do \
		tgt=`basename $$f`; \
		rm -f $(DESTDIR)$(OPENRC_INIT_DIR)/$$tgt ; \
	done
	rmdir $(DESTDIR)$(OPENRC_INIT_DIR) || :

INSTALL_DATA_LOCAL += install-openrc
UNINSTALL_LOCAL += uninstall-openrc
endif LIBVIRT_INIT_SCRIPT_OPENRC

endif WITH_LIBVIRTD


if WITH_LIBVIRTD
libexec_PROGRAMS += libvirt_iohelper
libvirt_iohelper_SOURCES = $(UTIL_IO_HELPER_SOURCES)
libvirt_iohelper_LDFLAGS = \
		$(AM_LDFLAGS) \
		$(NULL)
libvirt_iohelper_LDADD = \
		libvirt.la \
		$(GLIB_LIBS) \
		$(NULL)
if WITH_DTRACE_PROBES
libvirt_iohelper_LDADD += libvirt_probes.lo
endif WITH_DTRACE_PROBES

libvirt_iohelper_CFLAGS = \
		$(AM_CFLAGS) \
		$(NULL)


endif WITH_LIBVIRTD


generated-sources: $(BUILT_SOURCES)


install-data-local: $(INSTALL_DATA_LOCAL) \
		$(INSTALL_DATA_DIRS:%=install-data-%)
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/cache/libvirt"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/libvirt/images"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/libvirt/filesystems"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/libvirt/boot"

uninstall-local: $(UNINSTALL_LOCAL) \
		$(INSTALL_DATA_DIRS:%=uninstall-data-%)
	rmdir "$(DESTDIR)$(localstatedir)/cache/libvirt" ||:
	rmdir "$(DESTDIR)$(localstatedir)/lib/libvirt/images" ||:
	rmdir "$(DESTDIR)$(localstatedir)/lib/libvirt/filesystems" ||:
	rmdir "$(DESTDIR)$(localstatedir)/lib/libvirt/boot" ||:
	rmdir "$(DESTDIR)$(localstatedir)/lib/libvirt" ||:
