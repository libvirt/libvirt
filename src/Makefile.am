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

# old automake does not provide abs_{src,build}dir variables
abs_builddir = $(shell pwd)
abs_topbuilddir = $(shell cd .. && pwd)
abs_srcdir = $(shell cd $(srcdir) && pwd)
abs_topsrcdir = $(shell cd $(top_srcdir) && pwd)

# No libraries with the exception of LIBXML should be listed
# here. List them against the individual XXX_la_CFLAGS targets
# that actually use them. Also keep GETTEXT_CPPFLAGS at the end.
INCLUDES =	-I../gnulib/lib \
		-I$(top_srcdir)/gnulib/lib \
		-I$(top_srcdir) \
		-I../include \
		-I$(top_srcdir)/include \
		-I$(srcdir)/util \
		-I./util \
		-DIN_LIBVIRT \
		-Dabs_topbuilddir="\"$(abs_topbuilddir)\"" \
		-Dabs_topsrcdir="\"$(abs_topsrcdir)\"" \
		$(GETTEXT_CPPFLAGS)

WARN_CFLAGS += $(STRICT_FRAME_LIMIT_CFLAGS)

AM_CFLAGS =	$(LIBXML_CFLAGS) \
		$(WARN_CFLAGS) \
		$(LOCK_CHECKING_CFLAGS) \
		$(WIN32_EXTRA_CFLAGS) \
		$(COVERAGE_CFLAGS)
AM_LDFLAGS =	$(DRIVER_MODULES_LDFLAGS) \
		$(COVERAGE_LDFLAGS) \
		$(RELRO_LDFLAGS) \
		$(NO_INDIRECT_LDFLAGS) \
		$(CYGWIN_EXTRA_LDFLAGS) \
		$(MINGW_EXTRA_LDFLAGS) \
		$(NULL)
AM_LDFLAGS_MOD = -module -avoid-version $(AM_LDFLAGS)
AM_LDFLAGS_MOD_NOUNDEF = $(AM_LDFLAGS_MOD) $(NO_UNDEFINED_LDFLAGS)

POD2MAN = pod2man -c "Virtualization Support" -r "$(PACKAGE)-$(VERSION)"

EXTRA_DIST = $(conf_DATA)

BUILT_SOURCES =
CLEANFILES =
DISTCLEANFILES =
MAINTAINERCLEANFILES =
nodist_conf_DATA =
DRIVER_SOURCE_FILES =
STATEFUL_DRIVER_SOURCE_FILES =
noinst_LTLIBRARIES =
mod_LTLIBRARIES =
INSTALL_DATA_DIRS =
libvirt_la_BUILT_LIBADD =
SYM_FILES =
USED_SYM_FILES =
GENERATED_SYM_FILES =
augeas_DATA =
augeastest_DATA =
conf_DATA =
AUGEAS_DIRS =
if WITH_DTRACE_PROBES
tapset_DATA =
endif WITH_DTRACE_PROBES
libexec_PROGRAMS =
RPC_PROBE_FILES =

include uml/Makefile.inc.am
include phyp/Makefile.inc.am
include test/Makefile.inc.am
include esx/Makefile.inc.am
include hyperv/Makefile.inc.am
include vmware/Makefile.inc.am
include vbox/Makefile.inc.am
include openvz/Makefile.inc.am
include qemu/Makefile.inc.am
include bhyve/Makefile.inc.am
include xenconfig/Makefile.inc.am
include libxl/Makefile.inc.am
include xen/Makefile.inc.am
include xenapi/Makefile.inc.am
include vz/Makefile.inc.am
include lxc/Makefile.inc.am


THREAD_LIBS = $(LIB_PTHREAD) $(LTLIBMULTITHREAD)

SECDRIVER_CFLAGS =
SECDRIVER_LIBS =
if WITH_SECDRIVER_SELINUX
SECDRIVER_CFLAGS += $(SELINUX_CFLAGS)
SECDRIVER_LIBS += $(SELINUX_LIBS)
endif WITH_SECDRIVER_SELINUX
if WITH_SECDRIVER_APPARMOR
SECDRIVER_CFLAGS += $(APPARMOR_CFLAGS)
SECDRIVER_LIBS += $(APPARMOR_LIBS)
endif WITH_SECDRIVER_APPARMOR

if WITH_NETWORK
UUID=$(shell uuidgen 2>/dev/null)
endif WITH_NETWORK

lib_LTLIBRARIES = libvirt.la libvirt-qemu.la libvirt-lxc.la

moddir = $(libdir)/libvirt/connection-driver
sbin_PROGRAMS =

confdir = $(sysconfdir)/libvirt
conf_DATA += libvirt.conf libvirt-admin.conf

augeasdir = $(datadir)/augeas/lenses

augeastestdir = $(datadir)/augeas/lenses/tests

# These files are not related to driver APIs. Simply generic
# helper APIs for various purposes
UTIL_SOURCES = \
		util/viralloc.c util/viralloc.h \
		util/virarch.h util/virarch.c \
		util/viratomic.h util/viratomic.c \
		util/viraudit.c util/viraudit.h \
		util/virauth.c util/virauth.h \
		util/virauthconfig.c util/virauthconfig.h \
		util/virbitmap.c util/virbitmap.h \
		util/virbuffer.c util/virbuffer.h \
		util/virperf.c util/virperf.h \
		util/vircgroup.c util/vircgroup.h util/vircgrouppriv.h \
		util/virclosecallbacks.c util/virclosecallbacks.h \
		util/vircommand.c util/vircommand.h util/vircommandpriv.h \
		util/virconf.c util/virconf.h \
		util/vircrypto.c util/vircrypto.h \
		util/virdbus.c util/virdbus.h util/virdbuspriv.h \
		util/virdnsmasq.c util/virdnsmasq.h \
		util/virebtables.c util/virebtables.h \
		util/virendian.h \
		util/virerror.c util/virerror.h \
		util/virevent.c util/virevent.h \
		util/vireventpoll.c util/vireventpoll.h \
		util/virfcp.c util/virfcp.h \
		util/virfdstream.c util/virfdstream.h \
		util/virfile.c util/virfile.h \
		util/virfirewall.c util/virfirewall.h \
		util/virfirewallpriv.h \
		util/virfirmware.c util/virfirmware.h \
		util/virgettext.c util/virgettext.h \
		util/virgic.c util/virgic.h \
		util/virhash.c util/virhash.h \
		util/virhashcode.c util/virhashcode.h \
		util/virhook.c util/virhook.h \
		util/virhostcpu.c util/virhostcpu.h util/virhostcpupriv.h \
		util/virhostdev.c util/virhostdev.h \
		util/virhostmem.c util/virhostmem.h \
		util/viridentity.c util/viridentity.h \
		util/virinitctl.c util/virinitctl.h \
		util/viriptables.c util/viriptables.h \
		util/viriscsi.c util/viriscsi.h \
		util/virjson.c util/virjson.h \
		util/virkeycode.c util/virkeycode.h \
		util/virkeyfile.c util/virkeyfile.h \
		util/virlease.c util/virlease.h \
		util/virlockspace.c util/virlockspace.h \
		util/virlog.c util/virlog.h \
		util/virmacaddr.h util/virmacaddr.c \
		util/virmacmap.h util/virmacmap.c \
		util/virnetdev.h util/virnetdev.c \
		util/virnetdevbandwidth.h util/virnetdevbandwidth.c \
		util/virnetdevbridge.h util/virnetdevbridge.c \
		util/virnetdevip.h util/virnetdevip.c \
		util/virnetdevmacvlan.c util/virnetdevmacvlan.h \
		util/virnetdevmidonet.h util/virnetdevmidonet.c \
		util/virnetdevopenvswitch.h util/virnetdevopenvswitch.c \
		util/virnetdevtap.h util/virnetdevtap.c \
		util/virnetdevveth.h util/virnetdevveth.c \
		util/virnetdevvlan.h util/virnetdevvlan.c \
		util/virnetdevvportprofile.h util/virnetdevvportprofile.c \
		util/virnetlink.c util/virnetlink.h \
		util/virnodesuspend.c util/virnodesuspend.h \
		util/virkmod.c util/virkmod.h \
		util/virnuma.c util/virnuma.h \
		util/virobject.c util/virobject.h \
		util/virpci.c util/virpci.h \
		util/virpidfile.c util/virpidfile.h \
		util/virpolkit.c util/virpolkit.h \
		util/virportallocator.c util/virportallocator.h \
		util/virprobe.h \
		util/virprocess.c util/virprocess.h \
		util/virqemu.c util/virqemu.h \
		util/virrandom.h util/virrandom.c \
		util/virresctrl.h util/virresctrl.c util/virresctrlpriv.h \
		util/virrotatingfile.h util/virrotatingfile.c \
		util/virscsi.c util/virscsi.h \
		util/virscsihost.c util/virscsihost.h \
		util/virscsivhost.c util/virscsivhost.h \
		util/virseclabel.c util/virseclabel.h \
		util/virsecret.c util/virsecret.h \
		util/virsexpr.c util/virsexpr.h \
		util/virsocketaddr.h util/virsocketaddr.c \
		util/virstorageencryption.c util/virstorageencryption.h \
		util/virstoragefile.c util/virstoragefile.h \
		util/virstoragefilebackend.c util/virstoragefilebackend.h \
		util/virstring.h util/virstring.c \
		util/virsysinfo.c util/virsysinfo.h util/virsysinfopriv.h \
		util/virsystemd.c util/virsystemd.h util/virsystemdpriv.h \
		util/virthread.c util/virthread.h \
		util/virthreadjob.c util/virthreadjob.h \
		util/virthreadpool.c util/virthreadpool.h \
		util/virtime.h util/virtime.c \
		util/virtpm.h util/virtpm.c \
		util/virtypedparam.c util/virtypedparam.h \
		util/virusb.c util/virusb.h \
		util/viruri.h util/viruri.c \
		util/virutil.c util/virutil.h \
		util/viruuid.c util/viruuid.h \
		util/virvhba.c util/virvhba.h \
		util/virxdrdefs.h \
		util/virxml.c util/virxml.h \
		util/virmdev.c util/virmdev.h \
		util/virfilecache.c util/virfilecache.h \
		$(NULL)

EXTRA_DIST += \
	$(srcdir)/keycodemapdb/data/keymaps.csv \
	$(srcdir)/keycodemapdb/tools/keymap-gen \
	$(NULL)

util/virkeycodetable_%.h: $(srcdir)/keycodemapdb/data/keymaps.csv \
			$(srcdir)/keycodemapdb/tools/keymap-gen Makefile.am
	$(AM_V_GEN)export NAME=`echo $@ | sed -e 's,util/virkeycodetable_,,' \
					      -e 's,\.h,,'` && \
		$(MKDIR_P) util/ && \
		$(PYTHON) $(srcdir)/keycodemapdb/tools/keymap-gen \
			--lang stdc --varname virKeyCodeTable_$$NAME code-table \
			$(srcdir)/keycodemapdb/data/keymaps.csv $$NAME > $@-tmp && \
		mv $@-tmp $@ || rm -f $@-tmp

util/virkeynametable_%.h: $(srcdir)/keycodemapdb/data/keymaps.csv \
			$(srcdir)/keycodemapdb/tools/keymap-gen Makefile.am
	$(AM_V_GEN)export NAME=`echo $@ | sed -e 's,util/virkeynametable_,,' \
					      -e 's,\.h,,'` && \
		$(MKDIR_P) util/ && \
		$(PYTHON) $(srcdir)/keycodemapdb/tools/keymap-gen \
			--lang stdc --varname virKeyNameTable_$$NAME name-table \
			$(srcdir)/keycodemapdb/data/keymaps.csv $$NAME > $@-tmp && \
		mv $@-tmp $@ || rm -f $@-tmp

util/virkeycode-%.pod: $(srcdir)/keycodemapdb/data/keymaps.csv \
			$(srcdir)/keycodemapdb/tools/keymap-gen Makefile.am
	$(AM_V_GEN)export NAME=`echo $@ | sed -e 's,util/virkeycode-,,' \
					      -e 's,\.pod,,'` && \
		$(MKDIR_P) util/ && \
		$(PYTHON) $(srcdir)/keycodemapdb/tools/keymap-gen \
		--lang pod --varname "Key code values for $$NAME" code-docs \
		$(srcdir)/keycodemapdb/data/keymaps.csv $$NAME > \
			$@-tmp && mv $@-tmp $@ || rm $@-tmp

util/virkeyname-%.pod: $(srcdir)/keycodemapdb/data/keymaps.csv \
			$(srcdir)/keycodemapdb/tools/keymap-gen Makefile.am
	$(AM_V_GEN)export NAME=`echo $@ | sed -e 's,util/virkeyname-,,' \
					      -e 's,\.pod,,'` && \
		$(MKDIR_P) util/ && \
		$(PYTHON) $(srcdir)/keycodemapdb/tools/keymap-gen \
		--lang pod --varname "Key name values for $$NAME" name-docs \
		$(srcdir)/keycodemapdb/data/keymaps.csv $$NAME > \
			$@-tmp && mv $@-tmp $@ || rm $@-tmp

util/virkey%.7: util/virkey%.pod
	$(AM_V_GEN)$(POD2MAN) --section=7 $< $@-t1 && \
	if grep 'POD ERROR' $@-t1; then rm $@-t1; exit 1; fi && \
	sed \
		-e 's|SYSCONFDIR|\@sysconfdir\@|g' \
		-e 's|LOCALSTATEDIR|\@localstatedir\@|g' \
		< $@-t1 > $@-t2 && \
	rm -f $@-t1 && \
	mv $@-t2 $@

KEYCODES = linux osx atset1 atset2 atset3 xtkbd usb win32 rfb
KEYNAMES = linux osx win32

KEYTABLES = \
	$(KEYCODES:%=util/virkeycodetable_%.h) \
	$(KEYNAMES:%=util/virkeynametable_%.h) \
	$(NULL)

KEYPODS = $(KEYCODES:%=util/virkeycode-%.pod) \
	  $(KEYNAMES:%=util/virkeyname-%.pod)
KEYMANS = $(KEYPODS:%.pod=%.7)

man7_MANS = $(KEYMANS)

UTIL_SOURCES += $(KEYTABLES)
BUILT_SOURCES += $(KEYTABLES)
MAINTAINERCLEANFILES += $(KEYTABLES)
CLEANFILES += $(KEYMANS) $(KEYPODS)

# Internal generic driver infrastructure
DATATYPES_SOURCES = datatypes.h datatypes.c
DRIVER_SOURCES = \
		driver.c driver.h \
		driver-hypervisor.h \
		driver-interface.h \
		driver-network.h \
		driver-nodedev.h \
		driver-nwfilter.h \
		driver-secret.h \
		driver-state.h \
		driver-storage.h \
		driver-stream.h \
		internal.h \
		$(DATATYPES_SOURCES) \
		libvirt.c libvirt_internal.h \
		libvirt-domain.c \
		libvirt-domain-snapshot.c \
		libvirt-host.c \
		libvirt-interface.c \
		libvirt-network.c \
		libvirt-nodedev.c \
		libvirt-nwfilter.c \
		libvirt-secret.c \
		libvirt-storage.c \
		libvirt-stream.c \
		locking/lock_manager.c locking/lock_manager.h \
		locking/lock_driver.h \
		locking/lock_driver_nop.h locking/lock_driver_nop.c \
		locking/domain_lock.h locking/domain_lock.c \
		logging/log_manager.c logging/log_manager.h \
		$(NULL)

LOCK_DRIVER_SANLOCK_SOURCES = \
		locking/lock_driver_sanlock.c

LOCK_DRIVER_SANLOCK_HELPER_SOURCES = \
		locking/sanlock_helper.c

LOCK_PROTOCOL_GENERATED = \
		locking/lock_protocol.h \
		locking/lock_protocol.c \
		$(NULL)

LOCK_PROTOCOL = $(srcdir)/locking/lock_protocol.x
EXTRA_DIST += $(LOCK_PROTOCOL) \
	$(LOCK_PROTOCOL_GENERATED)
BUILT_SOURCES += $(LOCK_PROTOCOL_GENERATED)
MAINTAINERCLEANFILES += $(LOCK_PROTOCOL_GENERATED)

LOCK_DAEMON_GENERATED = \
		locking/lock_daemon_dispatch_stubs.h
		$(NULL)

BUILT_SOURCES += $(LOCK_DAEMON_GENERATED)
EXTRA_DIST += $(LOCK_DAEMON_GENERATED)
MAINTAINERCLEANFILES += $(LOCK_DAEMON_GENERATED)

LOCK_DRIVER_LOCKD_SOURCES = \
		locking/lock_driver_lockd.c \
		locking/lock_driver_lockd.h \
		$(NULL)

LOCK_DAEMON_SOURCES = \
		locking/lock_daemon.h \
		locking/lock_daemon.c \
		locking/lock_daemon_config.h \
		locking/lock_daemon_config.c \
		locking/lock_daemon_dispatch.c \
		locking/lock_daemon_dispatch.h \
		$(NULL)

locking/lock_daemon_dispatch_stubs.h: $(LOCK_PROTOCOL) \
		$(srcdir)/rpc/gendispatch.pl Makefile.am
	$(AM_V_GEN)perl -w $(srcdir)/rpc/gendispatch.pl --mode=server \
	    virLockSpaceProtocol VIR_LOCK_SPACE_PROTOCOL \
	    $(LOCK_PROTOCOL) > $(srcdir)/locking/lock_daemon_dispatch_stubs.h


LOG_PROTOCOL_GENERATED = \
		logging/log_protocol.h \
		logging/log_protocol.c \
		$(NULL)

DRIVER_SOURCES += $(LOG_PROTOCOL_GENERATED)

LOG_PROTOCOL = $(srcdir)/logging/log_protocol.x
EXTRA_DIST += $(LOG_PROTOCOL) \
	$(LOG_PROTOCOL_GENERATED)
BUILT_SOURCES += $(LOG_PROTOCOL_GENERATED)
MAINTAINERCLEANFILES += $(LOG_PROTOCOL_GENERATED)

LOG_DAEMON_GENERATED = \
		logging/log_daemon_dispatch_stubs.h
		$(NULL)

BUILT_SOURCES += $(LOG_DAEMON_GENERATED)
EXTRA_DIST += $(LOG_DAEMON_GENERATED)
MAINTAINERCLEANFILES += $(LOG_DAEMON_GENERATED)

LOG_DAEMON_SOURCES = \
		logging/log_daemon.h \
		logging/log_daemon.c \
		logging/log_daemon_config.h \
		logging/log_daemon_config.c \
		logging/log_daemon_dispatch.c \
		logging/log_daemon_dispatch.h \
		logging/log_handler.c \
		logging/log_handler.h \
		$(NULL)

logging/log_daemon_dispatch_stubs.h: $(LOG_PROTOCOL) \
		$(srcdir)/rpc/gendispatch.pl Makefile.am
	$(AM_V_GEN)perl -w $(srcdir)/rpc/gendispatch.pl --mode=server \
	    virLogManagerProtocol VIR_LOG_MANAGER_PROTOCOL \
	    $(LOG_PROTOCOL) > $(srcdir)/logging/log_daemon_dispatch_stubs.h


NETDEV_CONF_SOURCES = \
		conf/netdev_bandwidth_conf.h conf/netdev_bandwidth_conf.c \
		conf/netdev_vport_profile_conf.h conf/netdev_vport_profile_conf.c \
		conf/netdev_vlan_conf.h conf/netdev_vlan_conf.c

# XML configuration format handling sources
# Domain driver generic impl APIs
DOMAIN_CONF_SOURCES = \
		conf/capabilities.c conf/capabilities.h \
		conf/domain_addr.c conf/domain_addr.h \
		conf/domain_capabilities.c conf/domain_capabilities.h \
		conf/domain_conf.c conf/domain_conf.h \
		conf/domain_audit.c conf/domain_audit.h \
		conf/domain_nwfilter.c conf/domain_nwfilter.h \
		conf/virsavecookie.c conf/virsavecookie.h \
		conf/snapshot_conf.c conf/snapshot_conf.h \
		conf/numa_conf.c conf/numa_conf.h \
		conf/virdomainobjlist.c conf/virdomainobjlist.h

OBJECT_EVENT_SOURCES = \
		conf/object_event.c conf/object_event.h \
		conf/object_event_private.h

DOMAIN_EVENT_SOURCES = \
		conf/domain_event.c conf/domain_event.h

NETWORK_EVENT_SOURCES = \
		conf/network_event.c conf/network_event.h

STORAGE_EVENT_SOURCES = \
                conf/storage_event.c conf/storage_event.h

NODE_DEVICE_EVENT_SOURCES = \
                conf/node_device_event.c conf/node_device_event.h

SECRET_EVENT_SOURCES = \
                conf/secret_event.c conf/secret_event.h

# Network driver generic impl APIs
NETWORK_CONF_SOURCES = \
		conf/network_conf.c conf/network_conf.h \
		conf/virnetworkobj.c conf/virnetworkobj.h \
		conf/networkcommon_conf.c conf/networkcommon_conf.h

# Network filter driver generic impl APIs
NWFILTER_PARAM_CONF_SOURCES = \
		conf/nwfilter_params.c conf/nwfilter_params.h \
		conf/nwfilter_ipaddrmap.c \
		conf/nwfilter_ipaddrmap.h \
		conf/nwfilter_conf.h \
		conf/virnwfilterobj.h

NWFILTER_CONF_SOURCES = \
		$(NWFILTER_PARAM_CONF_SOURCES) \
		conf/nwfilter_conf.c conf/nwfilter_conf.h \
		conf/virnwfilterobj.c conf/virnwfilterobj.h

# Storage driver generic impl APIs
STORAGE_CONF_SOURCES = \
		conf/storage_adapter_conf.h conf/storage_adapter_conf.c \
		conf/storage_conf.h conf/storage_conf.c \
		conf/virstorageobj.h conf/virstorageobj.c

# Interface driver generic impl APIs
INTERFACE_CONF_SOURCES = \
		conf/interface_conf.c conf/interface_conf.h \
		conf/virinterfaceobj.c conf/virinterfaceobj.h

# Secret driver generic impl APIs
SECRET_CONF_SOURCES = \
		conf/secret_conf.h conf/secret_conf.c \
		conf/virsecretobj.h conf/virsecretobj.c

# Network driver generic impl APIs
NODE_DEVICE_CONF_SOURCES = \
		conf/node_device_conf.c conf/node_device_conf.h \
		conf/virnodedeviceobj.c conf/virnodedeviceobj.h

CPU_CONF_SOURCES = \
		conf/cpu_conf.c conf/cpu_conf.h

# Safe character device handling helper APIs
CHRDEV_CONF_SOURCES = \
		conf/virchrdev.c conf/virchrdev.h

# Device Helper APIs
DEVICE_CONF_SOURCES = \
		conf/device_conf.c conf/device_conf.h

CONF_SOURCES = \
		$(NETDEV_CONF_SOURCES) \
		$(DOMAIN_CONF_SOURCES) \
		$(OBJECT_EVENT_SOURCES) \
		$(DOMAIN_EVENT_SOURCES) \
		$(NETWORK_EVENT_SOURCES) \
		$(STORAGE_EVENT_SOURCES) \
		$(NODE_DEVICE_EVENT_SOURCES) \
		$(SECRET_EVENT_SOURCES) \
		$(NETWORK_CONF_SOURCES) \
		$(NWFILTER_CONF_SOURCES) \
		$(NODE_DEVICE_CONF_SOURCES) \
		$(STORAGE_CONF_SOURCES) \
		$(INTERFACE_CONF_SOURCES) \
		$(SECRET_CONF_SOURCES) \
		$(CPU_CONF_SOURCES) \
		$(CHRDEV_CONF_SOURCES) \
		$(DEVICE_CONF_SOURCES)

# The remote RPC driver, covering domains, storage, networks, etc
REMOTE_DRIVER_GENERATED = \
		remote/remote_protocol.c \
		remote/remote_protocol.h \
		remote/remote_client_bodies.h \
		remote/lxc_protocol.c \
		remote/lxc_protocol.h \
		remote/lxc_client_bodies.h \
		remote/qemu_protocol.c \
		remote/qemu_protocol.h \
		remote/qemu_client_bodies.h \
		$(NULL)

REMOTE_PROTOCOL = $(srcdir)/remote/remote_protocol.x
LXC_PROTOCOL = $(srcdir)/remote/lxc_protocol.x
QEMU_PROTOCOL = $(srcdir)/remote/qemu_protocol.x
REMOTE_DRIVER_PROTOCOL = $(REMOTE_PROTOCOL) $(QEMU_PROTOCOL) $(LXC_PROTOCOL)

remote/remote_client_bodies.h: $(srcdir)/rpc/gendispatch.pl \
		$(REMOTE_PROTOCOL) Makefile.am
	$(AM_V_GEN)$(PERL) -w $(srcdir)/rpc/gendispatch.pl --mode=client \
	  remote REMOTE $(REMOTE_PROTOCOL) \
	  > $(srcdir)/remote/remote_client_bodies.h

remote/lxc_client_bodies.h: $(srcdir)/rpc/gendispatch.pl \
		$(LXC_PROTOCOL) Makefile.am
	$(AM_V_GEN)$(PERL) -w $(srcdir)/rpc/gendispatch.pl --mode=client \
	  lxc LXC $(LXC_PROTOCOL) \
	  > $(srcdir)/remote/lxc_client_bodies.h

remote/qemu_client_bodies.h: $(srcdir)/rpc/gendispatch.pl \
		$(QEMU_PROTOCOL) Makefile.am
	$(AM_V_GEN)$(PERL) -w $(srcdir)/rpc/gendispatch.pl --mode=client \
	  qemu QEMU $(QEMU_PROTOCOL) \
	  > $(srcdir)/remote/qemu_client_bodies.h

remote/remote_daemon_dispatch_stubs.h: $(srcdir)/rpc/gendispatch.pl \
		$(REMOTE_PROTOCOL) Makefile.am
	$(AM_V_GEN)$(PERL) -w $(top_srcdir)/src/rpc/gendispatch.pl \
	  --mode=server remote REMOTE $(REMOTE_PROTOCOL) \
	  > $(srcdir)/remote/remote_daemon_dispatch_stubs.h

remote/remote_daemon_dispatch_lxc_stubs.h: $(srcdir)/rpc/gendispatch.pl \
		$(LXC_PROTOCOL) Makefile.am
	$(AM_V_GEN)$(PERL) -w $(top_srcdir)/src/rpc/gendispatch.pl \
	  --mode=server lxc LXC $(LXC_PROTOCOL) \
	  > $(srcdir)/remote/remote_daemon_dispatch_lxc_stubs.h

remote/remote_daemon_dispatch_qemu_stubs.h: $(srcdir)/rpc/gendispatch.pl \
		$(QEMU_PROTOCOL) Makefile.am
	$(AM_V_GEN)$(PERL) -w $(top_srcdir)/src/rpc/gendispatch.pl \
	  --mode=server qemu QEMU $(QEMU_PROTOCOL) \
	  > $(srcdir)/remote/remote_daemon_dispatch_qemu_stubs.h

REMOTE_DRIVER_SOURCES = \
		remote/remote_driver.c remote/remote_driver.h \
		$(REMOTE_DRIVER_GENERATED)

LIBVIRTD_GENERATED = \
		remote/remote_daemon_dispatch_stubs.h \
		remote/remote_daemon_dispatch_lxc_stubs.h \
		remote/remote_daemon_dispatch_qemu_stubs.h \
		$(NULL)

LIBVIRTD_SOURCES = \
		remote/remote_daemon.c remote/remote_daemon.h \
		remote/remote_daemon_config.c remote/remote_daemon_config.h \
		remote/remote_daemon_dispatch.c remote/remote_daemon_dispatch.h \
		remote/remote_daemon_stream.c remote/remote_daemon_stream.h \
		$(LIBVIRTD_GENERATED)

EXTRA_DIST +=  $(REMOTE_DRIVER_PROTOCOL) \
		$(REMOTE_DRIVER_GENERATED) \
		$(LIBVIRTD_SOURCES) \
		$(NULL)

ADMIN_PROTOCOL = $(srcdir)/admin/admin_protocol.x

ADMIN_PROTOCOL_GENERATED = \
		admin/admin_protocol.c \
		admin/admin_protocol.h \
		admin/admin_client.h \
		admin/admin_server_dispatch_stubs.h \
		$(NULL)

admin/admin_client.h: $(srcdir)/rpc/gendispatch.pl \
		$(ADMIN_PROTOCOL) Makefile.am
	$(AM_V_GEN)$(PERL) -w $(srcdir)/rpc/gendispatch.pl --mode=client \
	  admin ADMIN $(ADMIN_PROTOCOL) \
	  > $(srcdir)/admin/admin_client.h

admin/admin_server_dispatch_stubs.h: $(srcdir)/rpc/gendispatch.pl \
		$(ADMIN_PROTOCOL) Makefile.am
	$(AM_V_GEN)$(PERL) -w $(srcdir)/rpc/gendispatch.pl --mode=server \
	  admin ADMIN $(ADMIN_PROTOCOL) \
	  > $(srcdir)/admin/admin_server_dispatch_stubs.h

EXTRA_DIST += $(ADMIN_PROTOCOL) $(ADMIN_PROTOCOL_GENERATED)
BUILT_SOURCES += $(ADMIN_PROTOCOL_GENERATED)
MAINTAINERCLEANFILES += $(ADMIN_PROTOCOL_GENERATED)

# Ensure that we don't change the struct or member names or member ordering
# in remote_protocol.x  The embedded perl below needs a few comments, and
# presumes you know what pdwtags output looks like:
# * use -0777 -n to slurp the entire file into $_.
# * the "split" splits on the /* DD */ comments, so that $p iterates
#     through the struct definitions.
# * process only "struct remote_..." entries
# * remove comments and preceding TAB throughout
# * remove empty lines throughout
# * remove white space at end of buffer

# With pdwtags 1.8, --verbose output includes separators like these:
# /* 93 */
# /* <0> (null):0 */
# with the second line omitted for intrinsic types.
# Whereas with pdwtags 1.3, they look like this:
# /* <2d2> /usr/include/libio.h:180 */
# The alternation of the following regexps matches both cases.
r1 = /\* \d+ \*/
r2 = /\* <[[:xdigit:]]+> \S+:\d+ \*/
libs_prefix = remote_|qemu_|lxc_|admin_
other_prefix = keepalive|vir(Net|LockSpace|LXCMonitor)
struct_prefix = ($(libs_prefix)|$(other_prefix))

# Depending on configure options, libtool creates one or both of
# remote/{,.libs/}libvirt_driver_remote_la-remote_protocol.o.  We want
# the newest of the two, in case configure options changed and a stale
# file is left around from an earlier build.
# The pdwtags output is completely different when building with clang
# which causes the comparison against expected output to fail, so skip
# if using clang as CC.
PDWTAGS = \
	$(AM_V_GEN)if $(CC) -v 2>&1 | grep -q clang; then \
	   echo 'WARNING: skipping pdwtags test with Clang' >&2; \
	   exit 0; \
	fi; \
	if (pdwtags --help) > /dev/null 2>&1; then \
	  o=`ls -t $(<:.lo=.$(OBJEXT)) \
	     $(subst /,/.libs/,$(<:.lo=.$(OBJEXT))) \
	    2>/dev/null | sed -n 1p`; \
	  test -f "$$o" || { echo ".o for $< not found" >&2; exit 1; }; \
	  pdwtags --verbose $$o > $(@F)-t1 2> $(@F)-t2; \
	  if test ! -s $(@F)-t1 && test -s $(@F)-t2; then \
	    rm -rf $(@F)-t?; \
	    echo 'WARNING: pdwtags appears broken; skipping the $@ test' >&2;\
	  else \
	    $(PERL) -0777 -n \
		-e 'foreach my $$p (split m!\n*(?:$(r1)|$(r2))\n!) {' \
		-e '  if ($$p =~ /^(struct|enum) $(struct_prefix)/ ||' \
		-e '      $$p =~ /^enum \{/) {' \
		-e '    $$p =~ s!\t*/\*.*?\*/!!sg;' \
		-e '    $$p =~ s!\s+\n!\n!sg;' \
		-e '    $$p =~ s!\s+$$!!;' \
		-e '    $$p =~ s!\t!        !g;' \
		-e '    print "$$p\n";' \
		-e '    $$n++;' \
		-e '  }' \
		-e '}' \
		-e 'BEGIN {' \
		-e '  print "/* -*- c -*- */\n";' \
		-e '}' \
		-e 'END {' \
		-e '  if ($$n < 1) {' \
		-e '    warn "WARNING: your pdwtags program is too old\n";' \
		-e '    warn "WARNING: skipping the $@ test\n";' \
		-e '    warn "WARNING: install dwarves-1.3 or newer\n";' \
		-e '    exit 8;' \
		-e '  }' \
		-e '}' \
		< $(@F)-t1 > $(@F)-t3; \
	    case $$? in 8) rm -f $(@F)-t?; exit 0;; 0) ;; *) exit 1;; esac;\
	    diff -u $(@)s $(@F)-t3; st=$$?; rm -f $(@F)-t?; exit $$st; \
	  fi; \
	else \
	  echo 'WARNING: you lack pdwtags; skipping the $@ test' >&2; \
	  echo 'WARNING: install the dwarves package to get pdwtags' >&2; \
	fi

# .libs/libvirt.so is built by libtool as a side-effect of the Makefile
# rule for libvirt.la.  However, checking symbols relies on Linux ELF layout
if WITH_LINUX
check-symfile: libvirt.syms libvirt.la
	$(AM_V_GEN)$(PERL) $(srcdir)/check-symfile.pl libvirt.syms \
	  .libs/libvirt.so
check-admin-symfile: libvirt_admin.syms libvirt-admin.la
	$(AM_V_GEN)$(PERL) $(srcdir)/check-symfile.pl libvirt_admin.syms \
	  .libs/libvirt-admin.so
else ! WITH_LINUX
check-symfile:
check-admin-symfile:
endif ! WITH_LINUX
check-symsorting:
	$(AM_V_GEN)$(PERL) $(srcdir)/check-symsorting.pl \
		$(srcdir) $(SYM_FILES)
check-admin-symsorting:
	$(AM_V_GEN)$(PERL) $(srcdir)/check-symsorting.pl \
		$(srcdir) $(ADMIN_SYM_FILES)
EXTRA_DIST += check-symfile.pl check-symsorting.pl

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

# The .o file that pdwtags parses is created as a side effect of running
# libtool; but from make's perspective we depend on the .lo file.
$(srcdir)/remote_protocol-struct \
	$(srcdir)/qemu_protocol-struct \
	$(srcdir)/lxc_protocol-struct: \
		$(srcdir)/%-struct: remote/libvirt_driver_remote_la-%.lo
	$(PDWTAGS)
$(srcdir)/virnetprotocol-struct $(srcdir)/virkeepaliveprotocol-struct: \
		$(srcdir)/%-struct: rpc/libvirt_net_rpc_la-%.lo
	$(PDWTAGS)
$(srcdir)/lxc_monitor_protocol-struct: \
		$(srcdir)/%-struct: lxc/libvirt_driver_lxc_impl_la-%.lo
	$(PDWTAGS)
$(srcdir)/lock_protocol-struct: \
		$(srcdir)/%-struct: locking/lockd_la-%.lo
	$(PDWTAGS)
$(srcdir)/admin_protocol-struct: \
		$(srcdir)/%-struct: admin/libvirt_admin_la-%.lo
	$(PDWTAGS)

else !WITH_REMOTE
# The $(PROTOCOL_STRUCTS) files must live in git, because they cannot be
# re-generated when configured --without-remote.
check-protocol:
endif !WITH_REMOTE
EXTRA_DIST += $(PROTOCOL_STRUCTS)

check-drivername:
	$(AM_V_GEN)$(PERL) $(srcdir)/check-drivername.pl \
		$(srcdir)/driver.h \
		$(srcdir)/libvirt_public.syms \
		$(srcdir)/libvirt_admin_public.syms \
		$(srcdir)/libvirt_qemu.syms \
		$(srcdir)/libvirt_lxc.syms

EXTRA_DIST += check-drivername.pl

DRIVER_SOURCE_FILES += \
	$(INTERFACE_DRIVER_SOURCES) \
	$(NETWORK_DRIVER_SOURCES) \
	$(NODE_DEVICE_DRIVER_SOURCES) \
	$(NODE_DEVICE_DRIVER_HAL_SOURCES) \
	$(NODE_DEVICE_DRIVER_UDEV_SOURCES) \
	$(NWFILTER_DRIVER_SOURCES) \
	$(REMOTE_DRIVER_SOURCES) \
	$(SECRET_DRIVER_SOURCES) \
	$(STORAGE_DRIVER_SOURCES) \
	$(NULL)

STATEFUL_DRIVER_SOURCE_FILES += \
	$(INTERFACE_DRIVER_SOURCES) \
	$(NETWORK_DRIVER_SOURCES) \
	$(NODE_DEVICE_DRIVER_SOURCES) \
	$(NWFILTER_DRIVER_SOURCES) \
	$(SECRET_DRIVER_SOURCES) \
	$(STORAGE_DRIVER_SOURCES) \
	$(NULL)


check-driverimpls:
	$(AM_V_GEN)$(PERL) $(srcdir)/check-driverimpls.pl \
		$(filter /%,$(DRIVER_SOURCE_FILES)) \
		$(filter $(srcdir)/%,$(DRIVER_SOURCE_FILES)) \
		$(addprefix $(srcdir)/,$(filter-out $(srcdir)/%, \
			$(filter-out /%,$(DRIVER_SOURCE_FILES))))

check-aclrules:
	$(AM_V_GEN)$(PERL) $(srcdir)/check-aclrules.pl \
		$(REMOTE_PROTOCOL) \
		$(addprefix $(srcdir)/,$(filter-out /%,$(STATEFUL_DRIVER_SOURCE_FILES)))

check-aclperms:
	$(AM_V_GEN)$(PERL) $(srcdir)/check-aclperms.pl \
		$(srcdir)/access/viraccessperm.h \
		$(srcdir)/access/viraccessperm.c

EXTRA_DIST += check-driverimpls.pl check-aclrules.pl check-aclperms.pl

check-local: check-protocol check-symfile check-symsorting \
	check-drivername check-driverimpls check-aclrules \
	check-aclperms check-admin-symfile check-admin-symsorting
.PHONY: check-protocol $(PROTOCOL_STRUCTS:structs=struct)


SECURITY_DRIVER_APPARMOR_HELPER_SOURCES = \
		$(DATATYPES_SOURCES) \
		security/virt-aa-helper.c

NETWORK_DRIVER_SOURCES = \
		network/bridge_driver.h network/bridge_driver.c \
		network/bridge_driver_platform.h \
		network/bridge_driver_platform.c \
		$(NULL)
EXTRA_DIST += network/bridge_driver_linux.c network/bridge_driver_nop.c

INTERFACE_DRIVER_SOURCES =

if WITH_INTERFACE
INTERFACE_DRIVER_SOURCES += \
		interface/interface_driver.h \
		interface/interface_driver.c

if WITH_NETCF
INTERFACE_DRIVER_SOURCES += \
		interface/interface_backend_netcf.c
endif WITH_NETCF
if WITH_UDEV
INTERFACE_DRIVER_SOURCES += \
		interface/interface_backend_udev.c
endif WITH_UDEV
endif WITH_INTERFACE

SECRET_UTIL_SOURCES = \
		secret/secret_util.h secret/secret_util.c

SECRET_DRIVER_SOURCES = \
		secret/secret_driver.h secret/secret_driver.c

# Storage backend specific impls
STORAGE_DRIVER_BACKEND_SOURCES = \
		storage/storage_backend.h storage/storage_backend.c

STORAGE_DRIVER_SOURCES = \
		storage/storage_driver.h storage/storage_driver.c \
		$(STORAGE_DRIVER_BACKEND_SOURCES) \
		storage/storage_util.h storage/storage_util.c

STORAGE_DRIVER_FS_SOURCES = \
		storage/storage_backend_fs.h storage/storage_backend_fs.c

STORAGE_DRIVER_LVM_SOURCES = \
		storage/storage_backend_logical.h \
		storage/storage_backend_logical.c

STORAGE_DRIVER_ISCSI_SOURCES = \
		storage/storage_backend_iscsi.h storage/storage_backend_iscsi.c

STORAGE_DRIVER_SCSI_SOURCES = \
		storage/storage_backend_scsi.h storage/storage_backend_scsi.c

STORAGE_DRIVER_MPATH_SOURCES = \
		storage/storage_backend_mpath.h storage/storage_backend_mpath.c

STORAGE_DRIVER_DISK_SOURCES = \
		storage/storage_backend_disk.h storage/storage_backend_disk.c

STORAGE_DRIVER_RBD_SOURCES = \
		storage/storage_backend_rbd.h storage/storage_backend_rbd.c

STORAGE_DRIVER_SHEEPDOG_SOURCES = \
		storage/storage_backend_sheepdog.h storage/storage_backend_sheepdog.c \
		storage/storage_backend_sheepdog_priv.h

STORAGE_DRIVER_GLUSTER_SOURCES = \
		storage/storage_backend_gluster.h storage/storage_backend_gluster.c

STORAGE_DRIVER_ZFS_SOURCES = \
                storage/storage_backend_zfs.h storage/storage_backend_zfs.c

STORAGE_DRIVER_VSTORAGE_SOURCES = \
                storage/storage_backend_vstorage.h \
                storage/storage_backend_vstorage.c

STORAGE_HELPER_DISK_SOURCES = \
		storage/parthelper.c

UTIL_IO_HELPER_SOURCES = \
		util/iohelper.c

NETWORK_LEASES_HELPER_SOURCES = \
               network/leaseshelper.c

# Network filters
NWFILTER_DRIVER_SOURCES = \
		nwfilter/nwfilter_driver.h nwfilter/nwfilter_driver.c \
		nwfilter/nwfilter_tech_driver.h \
		nwfilter/nwfilter_gentech_driver.c \
		nwfilter/nwfilter_gentech_driver.h \
		nwfilter/nwfilter_dhcpsnoop.c \
		nwfilter/nwfilter_dhcpsnoop.h \
		nwfilter/nwfilter_ebiptables_driver.c \
		nwfilter/nwfilter_ebiptables_driver.h \
		nwfilter/nwfilter_learnipaddr.c \
		nwfilter/nwfilter_learnipaddr.h


# Security framework and drivers for various models
SECURITY_DRIVER_SOURCES = \
		security/security_driver.h security/security_driver.c \
		security/security_nop.h security/security_nop.c \
		security/security_stack.h security/security_stack.c \
		security/security_dac.h security/security_dac.c \
		security/security_manager.h security/security_manager.c

SECURITY_DRIVER_SELINUX_SOURCES = \
		security/security_selinux.h security/security_selinux.c

SECURITY_DRIVER_APPARMOR_SOURCES = \
		security/security_apparmor.h security/security_apparmor.c

ACCESS_DRIVER_GENERATED = \
		access/viraccessapicheck.h \
		access/viraccessapicheck.c \
		access/viraccessapicheckqemu.h \
		access/viraccessapicheckqemu.c \
		access/viraccessapichecklxc.h \
		access/viraccessapichecklxc.c \
		$(NULL)

ACCESS_DRIVER_SYM_FILES = \
		libvirt_access.syms \
		libvirt_access_qemu.syms \
		libvirt_access_lxc.syms

ACCESS_DRIVER_API_FILES = \
		libvirt_access.xml \
		libvirt_access_qemu.xml \
		libvirt_access_lxc.xml

ACCESS_DRIVER_SOURCES = \
		access/viraccessperm.h access/viraccessperm.c \
		access/viraccessmanager.h access/viraccessmanager.c \
		access/viraccessdriver.h \
		access/viraccessdrivernop.h access/viraccessdrivernop.c \
		access/viraccessdriverstack.h access/viraccessdriverstack.c

ACCESS_DRIVER_POLKIT_SOURCES = \
		access/viraccessdriverpolkit.h access/viraccessdriverpolkit.c

ACCESS_DRIVER_POLKIT_POLICY = \
		$(srcdir)/access/org.libvirt.api.policy


NODE_DEVICE_DRIVER_SOURCES = \
		node_device/node_device_driver.c \
		node_device/node_device_driver.h

NODE_DEVICE_DRIVER_HAL_SOURCES = \
		node_device/node_device_hal.c \
		node_device/node_device_hal.h

NODE_DEVICE_DRIVER_UDEV_SOURCES = \
		node_device/node_device_udev.c \
		node_device/node_device_udev.h

CPU_SOURCES = \
		cpu/cpu.h cpu/cpu.c \
		cpu/cpu_x86.h cpu/cpu_x86.c cpu/cpu_x86_data.h \
		cpu/cpu_s390.h cpu/cpu_s390.c \
		cpu/cpu_arm.h cpu/cpu_arm.c \
		cpu/cpu_ppc64.h cpu/cpu_ppc64.c \
		cpu/cpu_ppc64_data.h \
		cpu/cpu_map.h cpu/cpu_map.c

VMX_SOURCES = \
		vmx/vmx.c vmx/vmx.h


pkgdata_DATA =	cpu/cpu_map.xml

EXTRA_DIST +=	$(pkgdata_DATA)

#########################
#
# Build up list of libvirt.la source files based on configure conditions
#
# First deal with sources usable in non-daemon context

noinst_LTLIBRARIES += libvirt_util.la
libvirt_la_LIBADD = $(libvirt_la_BUILT_LIBADD)
libvirt_la_BUILT_LIBADD += libvirt_util.la
libvirt_util_la_SOURCES = \
		$(UTIL_SOURCES)
libvirt_util_la_CFLAGS = $(CAPNG_CFLAGS) $(YAJL_CFLAGS) $(LIBNL_CFLAGS) \
		$(AM_CFLAGS) $(AUDIT_CFLAGS) $(DEVMAPPER_CFLAGS) \
		$(DBUS_CFLAGS) $(LDEXP_LIBM) $(NUMACTL_CFLAGS) \
		$(POLKIT_CFLAGS) $(GNUTLS_CFLAGS) $(ACL_CFLAGS)
libvirt_util_la_LIBADD = $(CAPNG_LIBS) $(YAJL_LIBS) $(LIBNL_LIBS) \
		$(THREAD_LIBS) $(AUDIT_LIBS) $(DEVMAPPER_LIBS) \
		$(LIB_CLOCK_GETTIME) $(DBUS_LIBS) $(WIN32_EXTRA_LIBS) $(LIBXML_LIBS) \
		$(SECDRIVER_LIBS) $(NUMACTL_LIBS) $(ACL_LIBS) \
		$(POLKIT_LIBS) $(GNUTLS_LIBS)


noinst_LTLIBRARIES += libvirt_conf.la
libvirt_la_BUILT_LIBADD += libvirt_conf.la
libvirt_conf_la_SOURCES = $(CONF_SOURCES)
libvirt_conf_la_CFLAGS = \
		-I$(srcdir)/conf $(AM_CFLAGS)
libvirt_conf_la_LDFLAGS = $(AM_LDFLAGS)
libvirt_conf_la_LIBADD = $(LIBXML_LIBS)

noinst_LTLIBRARIES += libvirt_cpu.la
libvirt_la_BUILT_LIBADD += libvirt_cpu.la
libvirt_cpu_la_CFLAGS = \
		-I$(srcdir)/conf $(AM_CFLAGS)
libvirt_cpu_la_SOURCES = $(CPU_SOURCES)

noinst_LTLIBRARIES += libvirt_secret.la
libvirt_la_BUILT_LIBADD += libvirt_secret.la
libvirt_secret_la_CFLAGS = $(AM_CFLAGS)
libvirt_secret_la_LDFLAGS = $(AM_LDFLAGS)
libvirt_secret_la_SOURCES = $(SECRET_UTIL_SOURCES)

if WITH_VMX
noinst_LTLIBRARIES += libvirt_vmx.la
libvirt_la_BUILT_LIBADD += libvirt_vmx.la
libvirt_vmx_la_CFLAGS = \
		-I$(srcdir)/conf $(AM_CFLAGS)
libvirt_vmx_la_SOURCES = $(VMX_SOURCES)
endif WITH_VMX


noinst_LTLIBRARIES += libvirt_driver.la
libvirt_la_BUILT_LIBADD += libvirt_driver.la
libvirt_driver_la_SOURCES = $(DRIVER_SOURCES)

libvirt_driver_la_CFLAGS = \
		$(GNUTLS_CFLAGS) $(CURL_CFLAGS) $(XDR_CFLAGS) \
		-I$(srcdir)/conf $(AM_CFLAGS)
libvirt_driver_la_LIBADD = \
		$(GNUTLS_LIBS) $(CURL_LIBS) $(DLOPEN_LIBS)

# All .syms files should be placed in exactly one of these three lists,
# depending on whether they are stored in git and/or used in the build.
SYM_FILES += $(USED_SYM_FILES)
USED_SYM_FILES += $(srcdir)/libvirt_private.syms
GENERATED_SYM_FILES += \
	$(ACCESS_DRIVER_SYM_FILES) \
	libvirt.syms libvirt.def libvirt_qemu.def libvirt_lxc.def \
	libvirt_admin.syms libvirt_admin.def \
	$(NULL)

if WITH_REMOTE
noinst_LTLIBRARIES += libvirt_driver_remote.la
libvirt_la_BUILT_LIBADD += libvirt_driver_remote.la
libvirt_driver_remote_la_CFLAGS = \
		$(XDR_CFLAGS) \
		-I$(srcdir)/conf \
		-I$(srcdir)/rpc \
		$(AM_CFLAGS)
libvirt_driver_remote_la_LDFLAGS = $(AM_LDFLAGS)
libvirt_driver_remote_la_SOURCES = $(REMOTE_DRIVER_SOURCES)

BUILT_SOURCES += $(REMOTE_DRIVER_GENERATED)

endif WITH_REMOTE


if WITH_LIBVIRTD

sbin_PROGRAMS += libvirtd

BUILT_SOURCES += $(LIBVIRTD_GENERATED)

augeas_DATA += remote/libvirtd.aug

augeastest_DATA += test_libvirtd.aug

conf_DATA += remote/libvirtd.conf

CLEANFILES += test_libvirtd.aug

if WITH_POLKIT
if WITH_POLKIT0
policydir = $(datadir)/PolicyKit/policy
policyauth = auth_admin_keep_session
else ! WITH_POLKIT0
policydir = $(datadir)/polkit-1/actions
policyauth = auth_admin_keep
endif ! WITH_POLKIT0
endif WITH_POLKIT

BUILT_SOURCES += libvirtd.policy
CLEANFILES += libvirtd.policy

libvirtd.policy: remote/libvirtd.policy.in $(top_builddir)/config.status
	$(AM_V_GEN) sed \
	    -e 's|[@]authaction[@]|$(policyauth)|g' \
	    < $< > $@-t && \
	mv $@-t $@

libvirtd_SOURCES = $(LIBVIRTD_SOURCES)

libvirtd_CFLAGS = \
	$(LIBXML_CFLAGS) $(GNUTLS_CFLAGS) $(SASL_CFLAGS) \
	$(XDR_CFLAGS) $(DBUS_CFLAGS) $(LIBNL_CFLAGS) \
	$(WARN_CFLAGS) $(PIE_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	-I$(srcdir)/access \
	-I$(srcdir)/conf \
	-I$(srcdir)/rpc \
	$(NULL)

libvirtd_LDFLAGS = \
	$(RELRO_LDFLAGS) \
	$(PIE_LDFLAGS) \
	$(COVERAGE_LDFLAGS) \
	$(NO_INDIRECT_LDFLAGS) \
	$(NO_UNDEFINED_LDFLAGS) \
	$(NULL)

libvirtd_LDADD = \
	$(LIBXML_LIBS) \
	$(GNUTLS_LIBS) \
	$(SASL_LIBS) \
	$(DBUS_LIBS) \
	$(LIBNL_LIBS) \
	$(NULL)

if WITH_DTRACE_PROBES
libvirtd_LDADD += ../src/libvirt_probes.lo
endif WITH_DTRACE_PROBES

libvirtd_LDADD += \
	libvirt_driver_admin.la \
	libvirt-lxc.la \
	libvirt-qemu.la \
	libvirt.la \
	../gnulib/lib/libgnu.la $(LIBSOCKET) \
	$(NULL)

endif WITH_LIBVIRTD
EXTRA_DIST += \
	remote/test_libvirtd.aug.in \
	remote/libvirtd.aug \
	remote/libvirtd.conf \
	remote/libvirtd.policy.in \
	remote/libvirtd.rules \
	remote/libvirtd.sasl \
	remote/libvirtd.sysctl \
	$(NULL)

%protocol.c: %protocol.x %protocol.h $(srcdir)/rpc/genprotocol.pl
	$(AM_V_GEN)$(PERL) -w $(srcdir)/rpc/genprotocol.pl $(RPCGEN) -c \
	       $< $(srcdir)/$(subst $(srcdir)/,,$@)

%protocol.h: %protocol.x $(srcdir)/rpc/genprotocol.pl
	$(AM_V_GEN)$(PERL) -w $(srcdir)/rpc/genprotocol.pl $(RPCGEN) -h \
	       $< $(srcdir)/$(subst $(srcdir)/,,$@)


if WITH_NETWORK
noinst_LTLIBRARIES += libvirt_driver_network_impl.la
libvirt_driver_network_la_SOURCES =
libvirt_driver_network_la_LIBADD = libvirt_driver_network_impl.la
mod_LTLIBRARIES += libvirt_driver_network.la
libvirt_driver_network_la_LIBADD += libvirt.la ../gnulib/lib/libgnu.la \
	$(LIBNL_LIBS) \
	$(DBUS_LIBS) \
	$(NULL)
libvirt_driver_network_la_LDFLAGS = $(AM_LDFLAGS_MOD_NOUNDEF)

libvirt_driver_network_impl_la_CFLAGS = \
		$(LIBNL_CFLAGS) \
		$(DBUS_CFLAGS) \
		-I$(srcdir)/access \
		-I$(srcdir)/conf \
		$(AM_CFLAGS)
libvirt_driver_network_impl_la_SOURCES = $(NETWORK_DRIVER_SOURCES)
libvirt_driver_network_impl_la_LIBADD  = $(DBUS_LIBS)
endif WITH_NETWORK
EXTRA_DIST += network/default.xml


if WITH_INTERFACE
mod_LTLIBRARIES += libvirt_driver_interface.la
libvirt_driver_interface_la_CFLAGS = \
		-I$(srcdir)/access \
		-I$(srcdir)/conf \
		$(AM_CFLAGS) $(LIBNL_CFLAGS)
libvirt_driver_interface_la_LDFLAGS = $(AM_LDFLAGS_MOD_NOUNDEF)
libvirt_driver_interface_la_LIBADD =
if WITH_NETCF
libvirt_driver_interface_la_CFLAGS += $(NETCF_CFLAGS)
libvirt_driver_interface_la_LIBADD += $(NETCF_LIBS)
endif WITH_NETCF
if WITH_UDEV
libvirt_driver_interface_la_CFLAGS += $(UDEV_CFLAGS)
libvirt_driver_interface_la_LIBADD += $(UDEV_LIBS)
endif WITH_UDEV
libvirt_driver_interface_la_LIBADD += libvirt.la ../gnulib/lib/libgnu.la
libvirt_driver_interface_la_SOURCES = $(INTERFACE_DRIVER_SOURCES)
endif WITH_INTERFACE

if WITH_SECRETS
mod_LTLIBRARIES += libvirt_driver_secret.la
libvirt_driver_secret_la_CFLAGS = \
		-I$(srcdir)/access \
		-I$(srcdir)/conf \
		$(AM_CFLAGS)
libvirt_driver_secret_la_LIBADD = libvirt.la ../gnulib/lib/libgnu.la
libvirt_driver_secret_la_LDFLAGS = $(AM_LDFLAGS_MOD_NOUNDEF)
libvirt_driver_secret_la_SOURCES = $(SECRET_DRIVER_SOURCES)
endif WITH_SECRETS

# Needed to keep automake quiet about conditionals
libvirt_driver_storage_impl_la_SOURCES =
libvirt_driver_storage_impl_la_CFLAGS = \
		-I$(srcdir)/access \
		-I$(srcdir)/conf \
		-I$(srcdir)/secret \
		$(AM_CFLAGS)
libvirt_driver_storage_impl_la_LDFLAGS = $(AM_LDFLAGS)
libvirt_driver_storage_impl_la_LIBADD =
libvirt_driver_storage_impl_la_LIBADD += $(SECDRIVER_LIBS) $(LIBXML_LIBS)
if WITH_BLKID
libvirt_driver_storage_impl_la_CFLAGS += $(BLKID_CFLAGS)
libvirt_driver_storage_impl_la_LIBADD += $(BLKID_LIBS)
endif WITH_BLKID

storagebackenddir = $(libdir)/libvirt/storage-backend
storagebackend_LTLIBRARIES =

if WITH_STORAGE
noinst_LTLIBRARIES += libvirt_driver_storage_impl.la
libvirt_driver_storage_la_SOURCES =
libvirt_driver_storage_la_LIBADD = libvirt_driver_storage_impl.la
mod_LTLIBRARIES += libvirt_driver_storage.la
libvirt_driver_storage_la_LIBADD += libvirt.la ../gnulib/lib/libgnu.la
libvirt_driver_storage_la_LDFLAGS = $(AM_LDFLAGS_MOD_NOUNDEF)
libvirt_driver_storage_impl_la_SOURCES += $(STORAGE_DRIVER_SOURCES)


libvirt_storage_backend_fs_la_SOURCES = $(STORAGE_DRIVER_FS_SOURCES)
libvirt_storage_backend_fs_la_CFLAGS = \
	-I$(srcdir)/conf \
	$(AM_CFLAGS)

storagebackend_LTLIBRARIES += libvirt_storage_backend_fs.la
libvirt_storage_backend_fs_la_LDFLAGS = $(AM_LDFLAGS_MOD)
libvirt_storage_backend_fs_la_LIBADD = libvirt.la ../gnulib/lib/libgnu.la
endif WITH_STORAGE

if WITH_STORAGE_LVM
libvirt_storage_backend_logical_la_SOURCES = \
	$(STORAGE_DRIVER_LVM_SOURCES)
libvirt_storage_backend_logical_la_CFLAGS = \
	-I$(srcdir)/conf \
	$(AM_CFLAGS)

storagebackend_LTLIBRARIES += libvirt_storage_backend_logical.la
libvirt_storage_backend_logical_la_LDFLAGS = $(AM_LDFLAGS_MOD)
libvirt_storage_backend_logical_la_LIBADD = libvirt.la ../gnulib/lib/libgnu.la
endif WITH_STORAGE_LVM

if WITH_STORAGE_ISCSI
libvirt_storage_backend_iscsi_la_SOURCES = \
	$(STORAGE_DRIVER_ISCSI_SOURCES)
libvirt_storage_backend_iscsi_la_CFLAGS = \
	-I$(srcdir)/conf \
	-I$(srcdir)/secret \
	$(AM_CFLAGS)

storagebackend_LTLIBRARIES += libvirt_storage_backend_iscsi.la
libvirt_storage_backend_iscsi_la_LDFLAGS = $(AM_LDFLAGS_MOD)
libvirt_storage_backend_iscsi_la_LIBADD = libvirt.la ../gnulib/lib/libgnu.la
endif WITH_STORAGE_ISCSI

if WITH_STORAGE_SCSI
libvirt_storage_backend_scsi_la_SOURCES = $(STORAGE_DRIVER_SCSI_SOURCES)
libvirt_storage_backend_scsi_la_CFLAGS = \
	-I$(srcdir)/conf \
	$(AM_CFLAGS)

storagebackend_LTLIBRARIES += libvirt_storage_backend_scsi.la
libvirt_storage_backend_scsi_la_LDFLAGS = $(AM_LDFLAGS_MOD)
libvirt_storage_backend_scsi_la_LIBADD = libvirt.la ../gnulib/lib/libgnu.la
endif WITH_STORAGE_SCSI

if WITH_STORAGE_MPATH
libvirt_storage_backend_mpath_la_SOURCES = \
	$(STORAGE_DRIVER_MPATH_SOURCES)
libvirt_storage_backend_mpath_la_LIBADD = $(DEVMAPPER_LIBS)
libvirt_storage_backend_mpath_la_CFLAGS = \
	-I$(srcdir)/conf \
	$(DEVMAPPER_CFLAGS) \
	$(AM_CFLAGS)

storagebackend_LTLIBRARIES += libvirt_storage_backend_mpath.la
libvirt_storage_backend_mpath_la_LDFLAGS = $(AM_LDFLAGS_MOD)
libvirt_storage_backend_mpath_la_LIBADD += libvirt.la ../gnulib/lib/libgnu.la
endif WITH_STORAGE_MPATH

if WITH_STORAGE_DISK
libvirt_storage_backend_disk_la_SOURCES = $(STORAGE_DRIVER_DISK_SOURCES)
libvirt_storage_backend_disk_la_CFLAGS = \
	-I$(srcdir)/conf \
	$(AM_CFLAGS)

storagebackend_LTLIBRARIES += libvirt_storage_backend_disk.la
libvirt_storage_backend_disk_la_LDFLAGS = $(AM_LDFLAGS_MOD)
libvirt_storage_backend_disk_la_LIBADD = libvirt.la ../gnulib/lib/libgnu.la
endif WITH_STORAGE_DISK

if WITH_STORAGE_RBD
libvirt_storage_backend_rbd_la_SOURCES = $(STORAGE_DRIVER_RBD_SOURCES)
libvirt_storage_backend_rbd_la_LIBADD = $(LIBRBD_LIBS)
libvirt_storage_backend_rbd_la_CFLAGS = \
	-I$(srcdir)/conf \
	-I$(srcdir)/secret \
	$(AM_CFLAGS)

storagebackend_LTLIBRARIES += libvirt_storage_backend_rbd.la
libvirt_storage_backend_rbd_la_LDFLAGS = $(AM_LDFLAGS_MOD)
libvirt_storage_backend_rbd_la_LIBADD += libvirt.la ../gnulib/lib/libgnu.la
endif WITH_STORAGE_RBD

if WITH_STORAGE_SHEEPDOG
libvirt_storage_backend_sheepdog_la_SOURCES = \
	$(STORAGE_DRIVER_SHEEPDOG_SOURCES)
libvirt_storage_backend_sheepdog_la_CFLAGS = \
	-I$(srcdir)/conf \
	$(AM_CFLAGS)

libvirt_storage_backend_sheepdog_priv_la_SOURCES = \
	$(STORAGE_DRIVER_SHEEPDOG_SOURCES)
libvirt_storage_backend_sheepdog_priv_la_CFLAGS = \
	-I$(srcdir)/conf \
	$(AM_CFLAGS)
noinst_LTLIBRARIES += libvirt_storage_backend_sheepdog_priv.la

storagebackend_LTLIBRARIES += libvirt_storage_backend_sheepdog.la
libvirt_storage_backend_sheepdog_la_LDFLAGS = $(AM_LDFLAGS_MOD)
libvirt_storage_backend_sheepdog_la_LIBADD = libvirt.la ../gnulib/lib/libgnu.la
endif WITH_STORAGE_SHEEPDOG

if WITH_STORAGE_GLUSTER
libvirt_storage_backend_gluster_la_SOURCES = \
	$(STORAGE_DRIVER_GLUSTER_SOURCES)
libvirt_storage_backend_gluster_la_LIBADD = $(GLUSTERFS_LIBS)
libvirt_storage_backend_gluster_la_CFLAGS = \
	-I$(srcdir)/conf \
	$(GLUSTERFS_CFLAGS) \
	$(AM_CFLAGS)

storagebackend_LTLIBRARIES += libvirt_storage_backend_gluster.la
libvirt_storage_backend_gluster_la_LDFLAGS = $(AM_LDFLAGS_MOD)
libvirt_storage_backend_gluster_la_LIBADD += libvirt.la ../gnulib/lib/libgnu.la
endif WITH_STORAGE_GLUSTER

if WITH_STORAGE_ZFS
libvirt_storage_backend_zfs_la_SOURCES = $(STORAGE_DRIVER_ZFS_SOURCES)
libvirt_storage_backend_zfs_la_CFLAGS = \
	-I$(srcdir)/conf \
	$(AM_CFLAGS)

storagebackend_LTLIBRARIES += libvirt_storage_backend_zfs.la
libvirt_storage_backend_zfs_la_LDFLAGS = $(AM_LDFLAGS_MOD)
libvirt_storage_backend_zfs_la_LIBADD = libvirt.la ../gnulib/lib/libgnu.la
endif WITH_STORAGE_ZFS

if WITH_STORAGE_VSTORAGE
libvirt_storage_backend_vstorage_la_SOURCES = \
	$(STORAGE_DRIVER_VSTORAGE_SOURCES)
libvirt_storage_backend_vstorage_la_CFLAGS = \
	-I$(srcdir)/conf \
	$(AM_CFLAGS)

storagebackend_LTLIBRARIES += libvirt_storage_backend_vstorage.la
libvirt_storage_backend_vstorage_la_LDFLAGS = $(AM_LDFLAGS_MOD)
libvirt_storage_backend_vstorage_la_LIBADD = libvirt.la ../gnulib/lib/libgnu.la
endif WITH_STORAGE_VSTORAGE

if WITH_NODE_DEVICES
# Needed to keep automake quiet about conditionals
mod_LTLIBRARIES += libvirt_driver_nodedev.la
libvirt_driver_nodedev_la_SOURCES = $(NODE_DEVICE_DRIVER_SOURCES)

libvirt_driver_nodedev_la_CFLAGS = \
		-I$(srcdir)/access \
		-I$(srcdir)/conf \
		$(AM_CFLAGS) $(LIBNL_CFLAGS)
libvirt_driver_nodedev_la_LDFLAGS = $(AM_LDFLAGS_MOD_NOUNDEF)
libvirt_driver_nodedev_la_LIBADD =

if WITH_HAL
libvirt_driver_nodedev_la_SOURCES += $(NODE_DEVICE_DRIVER_HAL_SOURCES)
libvirt_driver_nodedev_la_CFLAGS += $(HAL_CFLAGS)
libvirt_driver_nodedev_la_LIBADD += $(HAL_LIBS)
endif WITH_HAL
if WITH_UDEV
libvirt_driver_nodedev_la_SOURCES += $(NODE_DEVICE_DRIVER_UDEV_SOURCES)
libvirt_driver_nodedev_la_CFLAGS += $(UDEV_CFLAGS) $(PCIACCESS_CFLAGS)
libvirt_driver_nodedev_la_LIBADD += $(UDEV_LIBS) $(PCIACCESS_LIBS)
endif WITH_UDEV

libvirt_driver_nodedev_la_LIBADD += libvirt.la ../gnulib/lib/libgnu.la
endif WITH_NODE_DEVICES


if WITH_NWFILTER
noinst_LTLIBRARIES += libvirt_driver_nwfilter_impl.la
libvirt_driver_nwfilter_la_SOURCES =
libvirt_driver_nwfilter_la_LIBADD = libvirt_driver_nwfilter_impl.la
mod_LTLIBRARIES += libvirt_driver_nwfilter.la
libvirt_driver_nwfilter_la_LDFLAGS = $(AM_LDFLAGS_MOD_NOUNDEF)
libvirt_driver_nwfilter_impl_la_CFLAGS = \
		$(LIBPCAP_CFLAGS) \
		$(LIBNL_CFLAGS) \
		$(DBUS_CFLAGS) \
		-I$(srcdir)/access \
		-I$(srcdir)/conf \
		$(AM_CFLAGS)
libvirt_driver_nwfilter_impl_la_LDFLAGS = $(AM_LDFLAGS)
libvirt_driver_nwfilter_impl_la_LIBADD = \
		$(LIBPCAP_LIBS) \
		$(LIBNL_LIBS) \
		$(DBUS_LIBS)
libvirt_driver_nwfilter_impl_la_LIBADD += libvirt.la ../gnulib/lib/libgnu.la
libvirt_driver_nwfilter_impl_la_SOURCES = $(NWFILTER_DRIVER_SOURCES)
endif WITH_NWFILTER


libvirt_security_manager_la_SOURCES = $(SECURITY_DRIVER_SOURCES)
noinst_LTLIBRARIES += libvirt_security_manager.la
libvirt_la_BUILT_LIBADD += libvirt_security_manager.la
libvirt_security_manager_la_CFLAGS = \
		-I$(srcdir)/conf $(AM_CFLAGS)
libvirt_security_manager_la_LDFLAGS = $(AM_LDFLAGS)
libvirt_security_manager_la_LIBADD = $(SECDRIVER_LIBS)
if WITH_SECDRIVER_SELINUX
libvirt_security_manager_la_SOURCES += $(SECURITY_DRIVER_SELINUX_SOURCES)
libvirt_security_manager_la_CFLAGS += $(SELINUX_CFLAGS)
endif WITH_SECDRIVER_SELINUX
if WITH_SECDRIVER_APPARMOR
libvirt_security_manager_la_SOURCES += $(SECURITY_DRIVER_APPARMOR_SOURCES)
libvirt_security_manager_la_CFLAGS += $(APPARMOR_CFLAGS)
endif WITH_SECDRIVER_APPARMOR

libvirt_driver_access_la_SOURCES = \
	$(ACCESS_DRIVER_SOURCES) $(ACCESS_DRIVER_GENERATED)
noinst_LTLIBRARIES += libvirt_driver_access.la
libvirt_la_BUILT_LIBADD += libvirt_driver_access.la
libvirt_driver_access_la_CFLAGS = \
		-I$(srcdir)/conf $(AM_CFLAGS)
libvirt_driver_access_la_LDFLAGS = $(AM_LDFLAGS)
libvirt_driver_access_la_LIBADD =

EXTRA_DIST += access/genpolkit.pl

$(ACCESS_DRIVER_POLKIT_POLICY): $(srcdir)/access/viraccessperm.h \
    $(srcdir)/access/genpolkit.pl Makefile.am
	$(AM_V_GEN)$(PERL) $(srcdir)/access/genpolkit.pl < $< > $@ || rm -f $@

if WITH_POLKIT1
libvirt_driver_access_la_SOURCES += $(ACCESS_DRIVER_POLKIT_SOURCES)

polkitactiondir = $(datadir)/polkit-1/actions
if WITH_LIBVIRTD
polkitaction_DATA = $(ACCESS_DRIVER_POLKIT_POLICY)
endif WITH_LIBVIRTD

CLEANFILES += $(ACCESS_DRIVER_POLKIT_POLICY)
BUILT_SOURCES += $(ACCESS_DRIVER_POLKIT_POLICY)
else ! WITH_POLKIT1
EXTRA_DIST += $(ACCESS_DRIVER_POLKIT_SOURCES)
endif ! WITH_POLKIT1


BUILT_SOURCES += $(ACCESS_DRIVER_GENERATED) $(ACCESS_DRIVER_API_FILES)
CLEANFILES += $(ACCESS_DRIVER_GENERATED) $(ACCESS_DRIVER_API_FILES)

libvirt_access.syms: $(srcdir)/rpc/gendispatch.pl \
			$(REMOTE_PROTOCOL) Makefile.am
	$(AM_V_GEN)$(PERL) -w $(srcdir)/rpc/gendispatch.pl --mode=aclsym \
	  remote REMOTE $(REMOTE_PROTOCOL) > $@
libvirt_access_qemu.syms: $(srcdir)/rpc/gendispatch.pl \
			$(QEMU_PROTOCOL) Makefile.am
	$(AM_V_GEN)$(PERL) -w $(srcdir)/rpc/gendispatch.pl --mode=aclsym \
	  qemu QEMU $(QEMU_PROTOCOL) > $@
libvirt_access_lxc.syms: $(srcdir)/rpc/gendispatch.pl \
			$(LXC_PROTOCOL) Makefile.am
	$(AM_V_GEN)$(PERL) -w $(srcdir)/rpc/gendispatch.pl --mode=aclsym \
	  lxc LXC $(LXC_PROTOCOL) > $@

libvirt_access.xml: $(srcdir)/rpc/gendispatch.pl \
			$(REMOTE_PROTOCOL) Makefile.am
	$(AM_V_GEN)$(PERL) -w $(srcdir)/rpc/gendispatch.pl --mode=aclapi \
	  remote REMOTE $(REMOTE_PROTOCOL) > $@
libvirt_access_qemu.xml: $(srcdir)/rpc/gendispatch.pl \
			$(QEMU_PROTOCOL) Makefile.am
	$(AM_V_GEN)$(PERL) -w $(srcdir)/rpc/gendispatch.pl --mode=aclapi \
	  qemu QEMU $(QEMU_PROTOCOL) > $@
libvirt_access_lxc.xml: $(srcdir)/rpc/gendispatch.pl \
			$(LXC_PROTOCOL) Makefile.am
	$(AM_V_GEN)$(PERL) -w $(srcdir)/rpc/gendispatch.pl --mode=aclapi \
	  lxc LXC $(LXC_PROTOCOL) > $@

access/viraccessapicheck.h: $(srcdir)/rpc/gendispatch.pl \
			$(REMOTE_PROTOCOL) Makefile.am
	$(AM_V_GEN)$(PERL) -w $(srcdir)/rpc/gendispatch.pl --mode=aclheader \
	  remote REMOTE $(REMOTE_PROTOCOL) \
	  > $(srcdir)/access/viraccessapicheck.h
access/viraccessapicheck.c: $(srcdir)/rpc/gendispatch.pl \
			$(REMOTE_PROTOCOL) Makefile.am
	$(AM_V_GEN)$(PERL) -w $(srcdir)/rpc/gendispatch.pl --mode=aclbody \
	  remote REMOTE $(REMOTE_PROTOCOL) access/viraccessapicheck.h \
	  > $(srcdir)/access/viraccessapicheck.c

access/viraccessapicheckqemu.h: $(srcdir)/rpc/gendispatch.pl \
			$(QEMU_PROTOCOL) Makefile.am
	$(AM_V_GEN)$(PERL) -w $(srcdir)/rpc/gendispatch.pl --mode=aclheader \
	  qemu QEMU $(QEMU_PROTOCOL) \
	  > $(srcdir)/access/viraccessapicheckqemu.h
access/viraccessapicheckqemu.c: $(srcdir)/rpc/gendispatch.pl \
			$(QEMU_PROTOCOL) Makefile.am
	$(AM_V_GEN)$(PERL) -w $(srcdir)/rpc/gendispatch.pl --mode=aclbody \
	  qemu QEMU $(QEMU_PROTOCOL) access/viraccessapicheckqemu.h \
	  > $(srcdir)/access/viraccessapicheckqemu.c

access/viraccessapichecklxc.h: $(srcdir)/rpc/gendispatch.pl \
			$(LXC_PROTOCOL) Makefile.am
	$(AM_V_GEN)$(PERL) -w $(srcdir)/rpc/gendispatch.pl --mode=aclheader \
	  lxc LXC $(LXC_PROTOCOL) \
	  > $(srcdir)/access/viraccessapichecklxc.h
access/viraccessapichecklxc.c: $(srcdir)/rpc/gendispatch.pl \
			$(LXC_PROTOCOL) Makefile.am
	$(AM_V_GEN)$(PERL) -w $(srcdir)/rpc/gendispatch.pl --mode=aclbody \
	  lxc LXC $(LXC_PROTOCOL) access/viraccessapichecklxc.h \
	  > $(srcdir)/access/viraccessapichecklxc.c

# Add all conditional sources just in case...
EXTRA_DIST += \
		$(REMOTE_DRIVER_SOURCES) \
		$(NETWORK_DRIVER_SOURCES) \
		$(INTERFACE_DRIVER_SOURCES) \
		$(STORAGE_DRIVER_SOURCES) \
		$(STORAGE_DRIVER_FS_SOURCES) \
		$(STORAGE_DRIVER_LVM_SOURCES) \
		$(STORAGE_DRIVER_ISCSI_SOURCES) \
		$(STORAGE_DRIVER_SCSI_SOURCES) \
		$(STORAGE_DRIVER_MPATH_SOURCES) \
		$(STORAGE_DRIVER_DISK_SOURCES) \
		$(STORAGE_DRIVER_RBD_SOURCES) \
		$(STORAGE_DRIVER_SHEEPDOG_SOURCES) \
		$(STORAGE_DRIVER_GLUSTER_SOURCES) \
		$(STORAGE_DRIVER_ZFS_SOURCES) \
		$(STORAGE_DRIVER_VSTORAGE_SOURCES) \
		$(NODE_DEVICE_DRIVER_SOURCES) \
		$(NODE_DEVICE_DRIVER_HAL_SOURCES) \
		$(NODE_DEVICE_DRIVER_UDEV_SOURCES) \
		$(NWFILTER_DRIVER_SOURCES) \
		$(SECURITY_DRIVER_SELINUX_SOURCES) \
		$(SECURITY_DRIVER_APPARMOR_SOURCES) \
		$(SECRET_DRIVER_SOURCES) \
		$(SECRET_UTIL_SOURCES) \
		$(ACCESS_DRIVER_POLKIT_POLICY)

check-local: check-augeas

.PHONY: check-augeas \
	check-augeas-sanlock \
	check-augeas-lockd \
	check-augeas-libvirtd \
	$(NULL)

check-augeas: $(AUGEAS_DIRS:%=check-augeas-%) \
	check-augeas-sanlock \
	check-augeas-lockd check-augeas-virtlockd \
	check-augeas-virtlogd check-augeas-libvirtd

AUG_GENTEST = $(PERL) $(top_srcdir)/build-aux/augeas-gentest.pl
EXTRA_DIST += $(top_srcdir)/build-aux/augeas-gentest.pl


if WITH_SANLOCK
test_libvirt_sanlock.aug: locking/test_libvirt_sanlock.aug.in \
		locking/qemu-sanlock.conf $(AUG_GENTEST)
	$(AM_V_GEN)$(AUG_GENTEST) locking/qemu-sanlock.conf $< $@

check-augeas-sanlock: test_libvirt_sanlock.aug
	$(AM_V_GEN)if test -x '$(AUGPARSE)'; then \
	    '$(AUGPARSE)' -I $(srcdir)/locking test_libvirt_sanlock.aug; \
	fi
else ! WITH_SANLOCK
check-augeas-sanlock:
endif ! WITH_SANLOCK

if WITH_QEMU
test_libvirt_lockd.aug: locking/test_libvirt_lockd.aug.in \
		locking/qemu-lockd.conf $(AUG_GENTEST)
	$(AM_V_GEN)$(AUG_GENTEST) locking/qemu-lockd.conf $< $@
else ! WITH_QEMU
test_libvirt_lockd.aug:
endif ! WITH_QEMU

test_virtlockd.aug: locking/test_virtlockd.aug.in \
		locking/virtlockd.conf $(AUG_GENTEST)
	$(AM_V_GEN)$(AUG_GENTEST) $(srcdir)/locking/virtlockd.conf $< $@

if WITH_QEMU
check-augeas-lockd: test_libvirt_lockd.aug
	$(AM_V_GEN)if test -x '$(AUGPARSE)'; then \
	    '$(AUGPARSE)' -I $(srcdir)/locking test_libvirt_lockd.aug; \
	fi
else ! WITH_QEMU
check-augeas-lockd:
endif ! WITH_QEMU

check-augeas-virtlockd: test_virtlockd.aug
	$(AM_V_GEN)if test -x '$(AUGPARSE)'; then \
	    '$(AUGPARSE)' -I $(srcdir)/locking test_virtlockd.aug; \
	fi


test_virtlogd.aug: logging/test_virtlogd.aug.in \
		logging/virtlogd.conf $(AUG_GENTEST)
	$(AM_V_GEN)$(AUG_GENTEST) $(srcdir)/logging/virtlogd.conf $< $@

check-augeas-virtlogd: test_virtlogd.aug
	$(AM_V_GEN)if test -x '$(AUGPARSE)'; then \
	    '$(AUGPARSE)' -I $(srcdir)/logging test_virtlogd.aug; \
	fi

if WITH_LIBVIRTD
test_libvirtd.aug: remote/test_libvirtd.aug.in \
		remote/libvirtd.conf $(AUG_GENTEST)
	$(AM_V_GEN)$(AUG_GENTEST) $(srcdir)/remote/libvirtd.conf $< $@

check-augeas-libvirtd: test_libvirtd.aug
	$(AM_V_GEN)if test -x '$(AUGPARSE)'; then \
	    '$(AUGPARSE)' -I $(srcdir)/remote test_libvirtd.aug; \
	fi
else ! WITH_LIBVIRTD
check-augeas-libvirtd:
endif ! WITH_LIBVIRTD
#
# Build our version script.  This is composed of three parts:
#
# 1. libvirt_public.syms - public API.  These functions are always
# present in the library and should never change incompatibly.
#
# 2. libvirt_private.syms - private API.  These symbols are private and
# semantics may change on every release, hence the version number is
# spliced in at build time. This ensures that if libvirtd, virsh, or a
# driver module was built against one libvirt release, it will refuse to
# load with another where symbols may have same names but different
# semantics. Such symbols should never be visible in an (installed)
# public header file.
#
# 3. libvirt_*.syms - dynamic private API.  Like libvirt_private.syms,
# except that build options (such as --enable-debug) can mean these
# symbols aren't present at all.
#

USED_SYM_FILES += $(srcdir)/libvirt_driver_modules.syms

if WITH_LINUX
USED_SYM_FILES += $(srcdir)/libvirt_linux.syms
else ! WITH_LINUX
SYM_FILES += $(srcdir)/libvirt_linux.syms
endif ! WITH_LINUX

if WITH_REMOTE
USED_SYM_FILES += $(srcdir)/libvirt_remote.syms
else ! WITH_REMOTE
SYM_FILES += $(srcdir)/libvirt_remote.syms
endif ! WITH_REMOTE

if WITH_VMX
USED_SYM_FILES += $(srcdir)/libvirt_vmx.syms
else ! WITH_VMX
SYM_FILES += $(srcdir)/libvirt_vmx.syms
endif ! WITH_VMX

if WITH_SASL
USED_SYM_FILES += $(srcdir)/libvirt_sasl.syms
else ! WITH_SASL
SYM_FILES += $(srcdir)/libvirt_sasl.syms
endif ! WITH_SASL

if WITH_GNUTLS
USED_SYM_FILES += $(srcdir)/libvirt_gnutls.syms
else ! WITH_GNUTLS
SYM_FILES += $(srcdir)/libvirt_gnutls.syms
endif ! WITH_GNUTLS

if WITH_SSH2
USED_SYM_FILES += $(srcdir)/libvirt_libssh2.syms
else ! WITH_SSH2
SYM_FILES += $(srcdir)/libvirt_libssh2.syms
endif ! WITH_SSH2

if WITH_ATOMIC_OPS_PTHREAD
USED_SYM_FILES += $(srcdir)/libvirt_atomic.syms
else ! WITH_ATOMIC_OPS_PTHREAD
SYM_FILES += $(srcdir)/libvirt_atomic.syms
endif ! WITH_ATOMIC_OPS_PTHREAD

if WITH_LIBSSH
USED_SYM_FILES += $(srcdir)/libvirt_libssh.syms
else ! WITH_LIBSSH
SYM_FILES += $(srcdir)/libvirt_libssh.syms
endif ! WITH_LIBSSH

EXTRA_DIST += \
	libvirt_public.syms \
	libvirt_lxc.syms \
	libvirt_qemu.syms \
	libvirt_admin_public.syms \
	$(SYM_FILES) \
	$(ADMIN_SYM_FILES) \
	$(NULL)

BUILT_SOURCES += $(GENERATED_SYM_FILES)

libvirt.syms: libvirt_public.syms $(USED_SYM_FILES) \
		$(ACCESS_DRIVER_SYM_FILES) \
		$(top_builddir)/config.status
	$(AM_V_GEN)rm -f $@-tmp $@ ; \
	printf '# WARNING: generated from the following:\n# $^\n\n' >$@-tmp && \
	cat $(srcdir)/libvirt_public.syms >>$@-tmp && \
	printf '\n\n# Private symbols\n\n' >>$@-tmp && \
	printf 'LIBVIRT_PRIVATE_$(VERSION) {\n\n'  >>$@-tmp && \
	printf 'global:\n\n' >>$@-tmp && \
	cat $(USED_SYM_FILES) $(ACCESS_DRIVER_SYM_FILES) >>$@-tmp && \
	printf '\n\nlocal:\n*;\n\n};' >>$@-tmp && \
	chmod a-w $@-tmp && \
	mv $@-tmp libvirt.syms

%.def: %.syms
	$(AM_V_GEN)rm -f -- $@-tmp $@ ; \
	printf 'EXPORTS\n' > $@-tmp && \
	sed -e '/^$$/d; /#/d; /:/d; /}/d; /\*/d; /LIBVIRT_/d' \
	    -e 's/[	 ]*\(.*\)\;/    \1/g' $^ >> $@-tmp && \
	chmod a-w $@-tmp && \
	mv $@-tmp $@

libvirt_admin.syms: libvirt_admin_public.syms $(ADMIN_SYM_FILES) \
		$(top_builddir)/config.status
	$(AM_V_GEN)rm -f $@-tmp $@ ; \
	printf '# WARNING: generated from the following:\n# $^\n\n' >$@-tmp && \
	cat $(srcdir)/libvirt_admin_public.syms >>$@-tmp && \
	printf '\n\n# Private symbols\n\n' >>$@-tmp && \
	printf 'LIBVIRT_ADMIN_PRIVATE_$(VERSION) {\n\n'  >>$@-tmp && \
	printf 'global:\n\n' >>$@-tmp && \
	cat $(ADMIN_SYM_FILES) >>$@-tmp && \
	printf '\n\nlocal:\n*;\n\n};' >>$@-tmp && \
	chmod a-w $@-tmp && \
	mv $@-tmp libvirt_admin.syms


admin/admin_server_dispatch.c: admin/admin_server_dispatch_stubs.h

noinst_LTLIBRARIES += libvirt_driver_admin.la
libvirt_driver_admin_la_SOURCES = \
		admin/admin_protocol.c \
		admin/admin_protocol.h \
		admin/admin_server.c \
		admin/admin_server.h \
		admin/admin_server_dispatch.c \
		admin/admin_server_dispatch.h \
		admin/admin_server_dispatch_stubs.h \
		$(NULL)
libvirt_driver_admin_la_CFLAGS = \
		$(AM_CFLAGS) \
		$(XDR_CFLAGS) \
		-I$(top_srcdir)/src/util \
		-I$(top_srcdir)/src/admin \
		$(NULL)
libvirt_driver_admin_la_LIBADD = ../gnulib/lib/libgnu.la
libvirt_driver_admin_la_LDFLAGS = -module -avoid-version $(AM_LDFLAGS)

# admin/admin_remote.c is being included in libvirt-admin.c, so we
# need to include it in the dist
EXTRA_DIST += admin/admin_remote.c

lib_LTLIBRARIES += libvirt-admin.la
libvirt_admin_la_SOURCES = \
		libvirt-admin.c \
		$(ADMIN_PROTOCOL_GENERATED) \
		$(DATATYPES_SOURCES)

libvirt_admin_la_LDFLAGS = \
		$(VERSION_SCRIPT_FLAGS)$(LIBVIRT_ADMIN_SYMBOL_FILE) \
		-version-info $(LIBVIRT_VERSION_INFO) \
		$(AM_LDFLAGS)

libvirt_admin_la_LIBADD = \
		libvirt.la \
		$(CYGWIN_EXTRA_LIBADD)

libvirt_admin_la_CFLAGS = \
		$(AM_CFLAGS) \
		-I$(srcdir)/remote \
		-I$(srcdir)/rpc \
		-I$(srcdir)/admin

libvirt_admin_la_CFLAGS += \
		$(XDR_CFLAGS) \
		$(CAPNG_CFLAGS) \
		$(YAJL_CFLAGS) \
		$(SSH2_CFLAGS) \
		$(SASL_CFLAGS) \
		$(GNUTLS_CFLAGS) \
		$(LIBSSH_CFLAGS)

libvirt_admin_la_LIBADD += \
		$(CAPNG_LIBS) \
		$(YAJL_LIBS) \
		$(DEVMAPPER_LIBS) \
		$(LIBXML_LIBS) \
		$(SSH2_LIBS) \
		$(SASL_LIBS) \
		$(GNUTLS_LIBS) \
		$(LIBSSH_LIBS)

ADMIN_SYM_FILES = $(srcdir)/libvirt_admin_private.syms

if WITH_DTRACE_PROBES
libvirt_admin_la_LIBADD += libvirt_probes.lo
endif WITH_DTRACE_PROBES

# Empty source list - it merely links a bunch of convenience libs together
libvirt_la_SOURCES =
libvirt_la_LDFLAGS = \
		$(VERSION_SCRIPT_FLAGS)$(LIBVIRT_SYMBOL_FILE) \
		-version-info $(LIBVIRT_VERSION_INFO) \
		$(LIBVIRT_NODELETE) \
		$(NO_UNDEFINED_LDFLAGS) \
		$(AM_LDFLAGS) \
		$(NULL)
libvirt_la_BUILT_LIBADD += ../gnulib/lib/libgnu.la
libvirt_la_LIBADD += \
		    $(DRIVER_MODULES_LIBS) \
		    $(CYGWIN_EXTRA_LIBADD)
libvirt_la_CFLAGS = -DIN_LIBVIRT $(AM_CFLAGS)
# Because we specify libvirt_la_DEPENDENCIES for $(LIBVIRT_SYMBOL_FILE), we
# lose automake's automatic dependencies on an appropriate subset of
# $(libvirt_la_LIBADD).  But we were careful to create
# $(libvirt_la_BUILT_LIBADD) as the subset that automake would have
# picked out for us.
libvirt_la_DEPENDENCIES = $(libvirt_la_BUILT_LIBADD) $(LIBVIRT_SYMBOL_FILE)

if WITH_DTRACE_PROBES
libvirt_la_BUILT_LIBADD += libvirt_probes.lo
libvirt_la_DEPENDENCIES += libvirt_probes.lo libvirt_probes.o
nodist_libvirt_la_SOURCES = libvirt_probes.h
if WITH_REMOTE
nodist_libvirt_driver_remote_la_SOURCES = libvirt_probes.h
endif WITH_REMOTE
DTRACE2SYSTEMTAP_FLAGS = --with-modules

BUILT_SOURCES += libvirt_probes.h libvirt_probes.stp libvirt_functions.stp


tapsetdir = $(datadir)/systemtap/tapset
tapset_DATA += libvirt_probes.stp libvirt_functions.stp

%_probes.h: %_probes.d
	$(AM_V_GEN)$(DTRACE) -o $@ -h -s $<

.PRECIOUS: %_probes.o
%_probes.o: %_probes.d
	$(AM_V_GEN)$(DTRACE) -o $@ -G -s $<

%_probes.lo: %_probes.o
	$(AM_V_GEN)printf %s\\n \
	  '# $@ - a libtool object file' \
	  '# Generated by libtool (GNU libtool) 2.4' \
	  '# Actually generated by Makefile.am, in order to shut up libtool' \
	  "pic_object='$<'" \
	  "non_pic_object='$<'" \
	> $@

# Keep this list synced with PROTOCOL_STRUCTS
RPC_PROBE_FILES += $(srcdir)/rpc/virnetprotocol.x \
		  $(srcdir)/rpc/virkeepaliveprotocol.x \
		  $(srcdir)/remote/remote_protocol.x \
		  $(srcdir)/remote/lxc_protocol.x \
		  $(srcdir)/remote/qemu_protocol.x \
		  $(srcdir)/locking/lock_protocol.x \
		  $(srcdir)/admin/admin_protocol.x

libvirt_functions.stp: $(RPC_PROBE_FILES) $(srcdir)/rpc/gensystemtap.pl
	$(AM_V_GEN)$(PERL) -w $(srcdir)/rpc/gensystemtap.pl $(RPC_PROBE_FILES) > $@

%_probes.stp: %_probes.d $(srcdir)/dtrace2systemtap.pl \
		$(top_builddir)/config.status
	$(AM_V_GEN)$(PERL) -w $(srcdir)/dtrace2systemtap.pl \
	  $(DTRACE2SYSTEMTAP_FLAGS) $(bindir) $(sbindir) $(libdir) $< > $@

CLEANFILES += libvirt_probes.h libvirt_probes.o libvirt_probes.lo \
              libvirt_functions.stp libvirt_probes.stp
endif WITH_DTRACE_PROBES

EXTRA_DIST += libvirt_probes.d

libvirt_qemu_la_SOURCES = libvirt-qemu.c
libvirt_qemu_la_LDFLAGS = \
		$(VERSION_SCRIPT_FLAGS)$(LIBVIRT_QEMU_SYMBOL_FILE) \
		-version-info $(LIBVIRT_VERSION_INFO) \
		$(AM_LDFLAGS) \
		$(NULL)
libvirt_qemu_la_CFLAGS = $(AM_CFLAGS)
libvirt_qemu_la_LIBADD = libvirt.la $(CYGWIN_EXTRA_LIBADD)

libvirt_lxc_la_SOURCES = libvirt-lxc.c
libvirt_lxc_la_LDFLAGS = \
		$(VERSION_SCRIPT_FLAGS)$(LIBVIRT_LXC_SYMBOL_FILE) \
		-version-info $(LIBVIRT_VERSION_INFO) \
		$(AM_LDFLAGS) \
		$(NULL)
libvirt_lxc_la_CFLAGS = $(AM_CFLAGS)
libvirt_lxc_la_LIBADD = libvirt.la $(CYGWIN_EXTRA_LIBADD)

# Since virt-login-shell will be setuid, we must do everything
# we can to avoid linking to other libraries. Many of them do
# unsafe things in functions marked __atttribute__((constructor)).
# This library is built to include the bare minimum required to
# have a RPC client for local UNIX socket access only. We use
# the ../config-post.h header to disable all external deps that
# we don't want
if WITH_SETUID_RPC_CLIENT
noinst_LTLIBRARIES += libvirt-setuid-rpc-client.la

libvirt_setuid_rpc_client_la_SOURCES = \
		util/viralloc.c \
		util/virarch.c \
		util/viratomic.c \
		util/viratomic.h \
		util/virbitmap.c \
		util/virbuffer.c \
		util/vircgroup.c \
		util/vircommand.c \
		util/virconf.c \
		util/virdbus.c \
		util/virerror.c \
		util/virevent.c \
		util/vireventpoll.c \
		util/virfile.c \
		util/virgettext.c \
		util/virhash.c \
		util/virhashcode.c \
		util/virhostcpu.c \
		util/virjson.c \
		util/virlog.c \
		util/virobject.c \
		util/virpidfile.c \
		util/virprocess.c \
		util/virrandom.c \
		util/virsocketaddr.c \
		util/virstring.c \
		util/virsystemd.c \
		util/virtime.c \
		util/virthread.c \
		util/virthreadjob.c \
		util/virtypedparam.c \
		util/viruri.c \
		util/virutil.c \
		util/viruuid.c \
		conf/domain_event.c \
		conf/network_event.c \
		conf/object_event.c \
		conf/storage_event.c \
		conf/node_device_event.c \
		conf/secret_event.c \
		rpc/virnetsocket.c \
		rpc/virnetsocket.h \
		rpc/virnetmessage.h \
		rpc/virnetmessage.c \
		rpc/virkeepalive.c \
		rpc/virkeepalive.h \
		rpc/virnetclient.c \
		rpc/virnetclientprogram.c \
		rpc/virnetclientstream.c \
		rpc/virnetprotocol.c \
		remote/remote_driver.c \
		remote/remote_protocol.c \
		remote/qemu_protocol.c \
		remote/lxc_protocol.c \
		datatypes.c \
		libvirt.c \
		libvirt-domain.c \
		libvirt-domain-snapshot.c \
		libvirt-host.c \
		libvirt-interface.c \
		libvirt-network.c \
		libvirt-nodedev.c \
		libvirt-nwfilter.c \
		libvirt-secret.c \
		libvirt-storage.c \
		libvirt-stream.c \
		libvirt-lxc.c \
		$(NULL)

libvirt_setuid_rpc_client_la_LDFLAGS = \
		$(AM_LDFLAGS) \
		$(LIBXML_LIBS) \
		$(SECDRIVER_LIBS) \
		$(NULL)
libvirt_setuid_rpc_client_la_CFLAGS = \
		-DLIBVIRT_SETUID_RPC_CLIENT \
		-I$(srcdir)/conf \
		-I$(srcdir)/rpc \
		$(AM_CFLAGS) \
		$(SECDRIVER_CFLAGS) \
		$(XDR_CFLAGS) \
		$(NULL)
endif WITH_SETUID_RPC_CLIENT

lockdriverdir = $(libdir)/libvirt/lock-driver
lockdriver_LTLIBRARIES =

if WITH_LIBVIRTD
lockdriver_LTLIBRARIES += lockd.la
lockd_la_SOURCES = \
		$(LOCK_DRIVER_LOCKD_SOURCES) \
		$(LOCK_PROTOCOL_GENERATED) \
		$(NULL)
lockd_la_CFLAGS = -I$(srcdir)/conf \
		$(XDR_CFLAGS) \
		$(AM_CFLAGS)
lockd_la_LDFLAGS = $(AM_LDFLAGS_MOD_NOUNDEF)
lockd_la_LIBADD = libvirt.la ../gnulib/lib/libgnu.la
augeas_DATA += locking/libvirt_lockd.aug
if WITH_DTRACE_PROBES
lockd_la_LIBADD += libvirt_probes.lo
endif WITH_DTRACE_PROBES
if WITH_QEMU
augeastest_DATA += test_libvirt_lockd.aug
CLEANFILES += test_libvirt_lockd.aug
nodist_conf_DATA += locking/qemu-lockd.conf
BUILT_SOURCES += locking/qemu-lockd.conf
DISTCLEANFILES += locking/qemu-lockd.conf
endif WITH_QEMU

if WITH_LIBXL
nodist_conf_DATA += locking/libxl-lockd.conf
BUILT_SOURCES += locking/libxl-lockd.conf
DISTCLEANFILES += locking/libxl-lockd.conf
endif WITH_LIBXL

locking/%-lockd.conf: $(srcdir)/locking/lockd.conf
	$(AM_V_GEN)$(MKDIR_P) locking ; \
	cp $< $@


sbin_PROGRAMS += virtlockd virtlogd

virtlockd_SOURCES = \
		$(LOCK_DAEMON_SOURCES) \
		$(LOCK_PROTOCOL_GENERATED) \
		$(LOCK_DAEMON_GENERATED) \
		$(NULL)
virtlockd_CFLAGS = \
		$(AM_CFLAGS) \
		$(PIE_CFLAGS) \
		$(XDR_CFLAGS) \
		$(NULL)
virtlockd_LDFLAGS = \
		$(AM_LDFLAGS) \
		$(PIE_LDFLAGS) \
		$(NO_UNDEFINED_LDFLAGS) \
		$(NULL)
virtlockd_LDADD = \
		libvirt_driver_admin.la \
		libvirt-net-rpc-server.la \
		libvirt-net-rpc.la \
		libvirt_util.la \
		../gnulib/lib/libgnu.la \
		$(CYGWIN_EXTRA_LIBADD) \
		$(NULL)
if WITH_DTRACE_PROBES
virtlockd_LDADD += libvirt_probes.lo
endif WITH_DTRACE_PROBES


virtlogd_SOURCES = \
		$(LOG_DAEMON_SOURCES) \
		$(LOG_PROTOCOL_GENERATED) \
		$(LOG_DAEMON_GENERATED) \
		$(NULL)
virtlogd_CFLAGS = \
		$(AM_CFLAGS) \
		$(PIE_CFLAGS) \
		$(XDR_CFLAGS) \
		$(NULL)
virtlogd_LDFLAGS = \
		$(AM_LDFLAGS) \
		$(PIE_LDFLAGS) \
		$(NO_UNDEFINED_LDFLAGS) \
		$(NULL)
virtlogd_LDADD = \
		libvirt_driver_admin.la \
		libvirt-net-rpc-server.la \
		libvirt-net-rpc.la \
		libvirt_util.la \
		../gnulib/lib/libgnu.la \
		$(CYGWIN_EXTRA_LIBADD) \
		$(NULL)
if WITH_DTRACE_PROBES
virtlogd_LDADD += libvirt_probes.lo
endif WITH_DTRACE_PROBES

else ! WITH_LIBVIRTD
EXTRA_DIST += $(LOCK_DAEMON_SOURCES) \
              $(LOCK_DRIVER_LOCKD_SOURCES) \
	      $(LOG_DAEMON_SOURCES)
endif ! WITH_LIBVIRTD

SYSCONF_FILES = \
	locking/virtlockd.sysconf \
	logging/virtlogd.sysconf \
	remote/libvirtd.sysconf \
	$(NULL)

EXTRA_DIST += \
	locking/lockd.conf \
	locking/libvirt_lockd.aug \
	locking/test_libvirt_lockd.aug.in \
	$(SYSCONF_FILES) \
	$(NULL)

install-sysconfig:
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/sysconfig
	for f in $(SYSCONF_FILES:%.sysconf=%) ; \
	do \
	  tgt=`basename $$f`; \
	  $(INSTALL_SCRIPT) $(srcdir)/$$f.sysconf \
	      $(DESTDIR)$(sysconfdir)/sysconfig/$$tgt; \
	done

uninstall-sysconfig:
	for f in $(SYSCONF_FILES:%.sysconf=%) ; \
	do \
	  tgt=`basename $$f`; \
	  rm -f $(DESTDIR)$(sysconfdir)/sysconfig/$$tgt; \
	done
	rmdir $(DESTDIR)$(sysconfdir)/sysconfig || :

SYSVINIT_FILES_IN = \
	locking/virtlockd.init.in \
	logging/virtlogd.init.in \
	remote/libvirtd.init.in \
	$(NULL)

SYSVINIT_FILES = $(notdir $(SYSVINIT_FILES_IN:%.in=%))

EXTRA_DIST += $(SYSVINIT_FILES_IN)

LOGROTATE_FILES_IN = \
	remote/libvirtd.qemu.logrotate.in \
	remote/libvirtd.lxc.logrotate.in \
	remote/libvirtd.libxl.logrotate.in \
	remote/libvirtd.uml.logrotate.in \
	remote/libvirtd.logrotate.in \
	$(NULL)

EXTRA_DIST += $(LOGROTATE_FILES_IN)

if WITH_LIBVIRTD

LOGROTATE_FILES := $(LOGROTATE_FILES_IN:remote/%.in=%)

BUILT_SOURCES += $(LOGROTATE_FILES)
CLEANFILES += $(LOGROTATE_FILES)

%.logrotate: remote/%.logrotate.in
	$(AM_V_GEN)sed \
	    -e 's|[@]localstatedir[@]|$(localstatedir)|g' \
	    < $< > $@-t && \
	mv $@-t $@

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

if WITH_SYSCTL
# Use $(prefix)/lib rather than $(libdir), since man sysctl.d insists on
# /usr/lib/sysctl.d/ even when libdir is /usr/lib64
install-sysctl:
	$(MKDIR_P) $(DESTDIR)$(prefix)/lib/sysctl.d
	$(INSTALL_DATA) $(srcdir)/remote/libvirtd.sysctl \
	  $(DESTDIR)$(prefix)/lib/sysctl.d/60-libvirtd.conf

uninstall-sysctl:
	rm -f $(DESTDIR)$(prefix)/lib/sysctl.d/60-libvirtd.conf
	rmdir $(DESTDIR)$(prefix)/lib/sysctl.d || :
else ! WITH_SYSCTL
install-sysctl:
uninstall-sysctl:
endif ! WITH_SYSCTL

if WITH_POLKIT
install-polkit::
	$(MKDIR_P) $(DESTDIR)$(policydir)
	$(INSTALL_DATA) libvirtd.policy $(DESTDIR)$(policydir)/org.libvirt.unix.policy
if ! WITH_POLKIT0
	$(MKDIR_P) $(DESTDIR)$(datadir)/polkit-1/rules.d
	$(INSTALL_DATA) $(srcdir)/remote/libvirtd.rules \
		$(DESTDIR)$(datadir)/polkit-1/rules.d/50-libvirt.rules
endif ! WITH_POLKIT0

uninstall-polkit::
	rm -f $(DESTDIR)$(policydir)/org.libvirt.unix.policy
	rmdir $(DESTDIR)$(policydir) || :
if ! WITH_POLKIT0
	rm -f $(DESTDIR)$(datadir)/polkit-1/rules.d/50-libvirt.rules
	rmdir $(DESTDIR)$(datadir)/polkit-1/rules.d || :
endif ! WITH_POLKIT0

else ! WITH_POLKIT
install-polkit::
uninstall-polkit::
endif ! WITH_POLKIT

if LIBVIRT_INIT_SCRIPT_RED_HAT
install-init:: $(SYSVINIT_FILES) install-sysconfig
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/rc.d/init.d
	for f in $(SYSVINIT_FILES:%.init=%) ; \
	do \
	  $(INSTALL_SCRIPT) $$f.init $(DESTDIR)$(sysconfdir)/rc.d/init.d/$$f; \
	done

uninstall-init:: uninstall-sysconfig
	rm -f $(SYSVINIT_FILES:%.init=$(DESTDIR)$(sysconfdir)/rc.d/init.d/%)
	rmdir $(DESTDIR)$(sysconfdir)/rc.d/init.d || :

BUILT_SOURCES += $(SYSVINIT_FILES)
DISTCLEANFILES += $(SYSVINIT_FILES)
else ! LIBVIRT_INIT_SCRIPT_RED_HAT
install-init::
uninstall-init::
endif ! LIBVIRT_INIT_SCRIPT_RED_HAT
else ! WITH_LIBVIRTD
install-polkit::
uninstall-polkit::
install-sysctl::
uninstall-sysctl::
install-init::
uninstall-init::
install-logrotate::
uninstall-logrotate::
endif ! WITH_LIBVIRTD

# This is needed for clients too, so can't wrap in
# the WITH_LIBVIRTD conditional
if WITH_SASL
install-sasl:
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/sasl2/
	$(INSTALL_DATA) $(srcdir)/remote/libvirtd.sasl \
		$(DESTDIR)$(sysconfdir)/sasl2/libvirt.conf

uninstall-sasl:
	rm -f $(DESTDIR)$(sysconfdir)/sasl2/libvirt.conf
	rmdir $(DESTDIR)$(sysconfdir)/sasl2/ || :
else ! WITH_SASL
install-sasl:
uninstall-sasl:
endif ! WITH_SASL


libvirtd.init: remote/libvirtd.init.in $(top_builddir)/config.status
	$(AM_V_GEN)sed \
	    -e 's|[@]localstatedir[@]|$(localstatedir)|g' \
	    -e 's|[@]sbindir[@]|$(sbindir)|g' \
	    -e 's|[@]sysconfdir[@]|$(sysconfdir)|g' \
	    < $< > $@-t && \
	    chmod a+x $@-t && \
	    mv $@-t $@

virtlockd.init: locking/virtlockd.init.in $(top_builddir)/config.status
	$(AM_V_GEN)sed \
	    -e 's|[@]localstatedir[@]|$(localstatedir)|g' \
	    -e 's|[@]sbindir[@]|$(sbindir)|g' \
	    -e 's|[@]sysconfdir[@]|$(sysconfdir)|g' \
	    < $< > $@-t && \
	    chmod a+x $@-t && \
	    mv $@-t $@

virtlogd.init: logging/virtlogd.init.in $(top_builddir)/config.status
	$(AM_V_GEN)sed \
	    -e 's|[@]localstatedir[@]|$(localstatedir)|g' \
	    -e 's|[@]sbindir[@]|$(sbindir)|g' \
	    -e 's|[@]sysconfdir[@]|$(sysconfdir)|g' \
	    < $< > $@-t && \
	    chmod a+x $@-t && \
	    mv $@-t $@

virtlockd.8.in: locking/virtlockd.pod
	$(AM_V_GEN)$(POD2MAN) --section=8 $< $@-t1 && \
	if grep 'POD ERROR' $@-t1; then rm $@-t1; exit 1; fi && \
	sed \
		-e 's|SYSCONFDIR|\@sysconfdir\@|g' \
		-e 's|LOCALSTATEDIR|\@localstatedir\@|g' \
		< $@-t1 > $@-t2 && \
	rm -f $@-t1 && \
	mv $@-t2 $@

virtlogd.8.in: logging/virtlogd.pod
	$(AM_V_GEN)$(POD2MAN) --section=8 $< $@-t1 && \
	if grep 'POD ERROR' $@-t1; then rm $@-t1; exit 1; fi && \
	sed \
		-e 's|SYSCONFDIR|\@sysconfdir\@|g' \
		-e 's|LOCALSTATEDIR|\@localstatedir\@|g' \
		< $@-t1 > $@-t2 && \
	rm -f $@-t1 && \
	mv $@-t2 $@

libvirtd.8.in: remote/libvirtd.pod
	$(AM_V_GEN)$(POD2MAN) --section=8 $< $@-t1 && \
	if grep 'POD ERROR' $@-t1; then rm $@-t1; exit 1; fi && \
	sed \
		-e 's|SYSCONFDIR|\@sysconfdir\@|g' \
		-e 's|LOCALSTATEDIR|\@localstatedir\@|g' \
		< $@-t1 > $@-t2 && \
	rm -f $@-t1 && \
	mv $@-t2 $@

%.8: %.8.in $(top_srcdir)/configure.ac
	$(AM_V_GEN)sed \
		-e 's|[@]sysconfdir[@]|$(sysconfdir)|g' \
		-e 's|[@]localstatedir[@]|$(localstatedir)|g' \
		< $< > $@-t && \
	mv $@-t $@

if WITH_LIBVIRTD
man8_MANS = virtlockd.8 virtlogd.8 libvirtd.8

conf_DATA += locking/virtlockd.conf logging/virtlogd.conf

augeas_DATA += locking/virtlockd.aug logging/virtlogd.aug
augeastest_DATA += test_virtlockd.aug test_virtlogd.aug
endif WITH_LIBVIRTD

PODFILES = \
	locking/virtlockd.pod \
	logging/virtlogd.pod \
	remote/libvirtd.pod \
	$(NULL)

MANINFILES = \
	virtlockd.8.in \
	virtlogd.8.in \
	libvirtd.8.in \
	$(NULL)

CLEANFILES += test_virtlockd.aug test_virtlogd.aug $(man8_MANS)
MAINTAINERCLEANFILES += $(MANINFILES)

SYSTEMD_UNIT_FILES_IN = \
	locking/virtlockd.service.in \
	locking/virtlockd.socket.in \
	locking/virtlockd-admin.socket.in \
	logging/virtlogd.service.in \
	logging/virtlogd.socket.in \
	logging/virtlogd-admin.socket.in \
	remote/libvirtd.service.in \
	remote/virt-guest-shutdown.target.in \
	$(NULL)

EXTRA_DIST += \
        $(SYSTEMD_UNIT_FILES_IN) \
        locking/virtlockd.aug \
        locking/virtlockd.conf \
        locking/test_virtlockd.aug.in \
        logging/virtlogd.aug \
        logging/virtlogd.conf \
        logging/test_virtlogd.aug.in \
        $(PODFILES) \
        $(MANINFILES) \
        $(NULL)


if WITH_LIBVIRTD
if LIBVIRT_INIT_SCRIPT_SYSTEMD

SYSTEMD_UNIT_DIR = $(prefix)/lib/systemd/system
SYSTEMD_UNIT_FILES = $(notdir $(SYSTEMD_UNIT_FILES_IN:%.in=%))

BUILT_SOURCES += $(SYSTEMD_UNIT_FILES)
DISTCLEANFILES += $(SYSTEMD_UNIT_FILES)

install-systemd: $(SYSTEMD_UNIT_FILES) install-sysconfig
	$(MKDIR_P) $(DESTDIR)$(SYSTEMD_UNIT_DIR)
	for f in $(SYSTEMD_UNIT_FILES); \
	do \
	  $(INSTALL_DATA) $$f $(DESTDIR)$(SYSTEMD_UNIT_DIR)/ ; \
	done

uninstall-systemd: uninstall-sysconfig
	rm -f $(SYSTEMD_UNIT_FILES:%=$(DESTDIR)$(SYSTEMD_UNIT_DIR)/%)
	rmdir $(DESTDIR)$(SYSTEMD_UNIT_DIR) || :
else ! LIBVIRT_INIT_SCRIPT_SYSTEMD
install-systemd:
uninstall-systemd:
endif ! LIBVIRT_INIT_SCRIPT_SYSTEMD
else ! WITH_LIBVIRTD
install-systemd:
uninstall-systemd:
endif ! WITH_LIBVIRTD

libvirtd.service: remote/libvirtd.service.in $(top_builddir)/config.status
	$(AM_V_GEN)sed \
	    -e 's|[@]localstatedir[@]|$(localstatedir)|g' \
	    -e 's|[@]sbindir[@]|$(sbindir)|g' \
	    -e 's|[@]sysconfdir[@]|$(sysconfdir)|g' \
	    < $< > $@-t && \
	    mv $@-t $@

virt-guest-shutdown.target: remote/virt-guest-shutdown.target.in \
			$(top_builddir)/config.status
	$(AM_V_GEN)cp $< $@

virtlockd.service: locking/virtlockd.service.in $(top_builddir)/config.status
	$(AM_V_GEN)sed \
	    -e 's|[@]sbindir[@]|$(sbindir)|g' \
	    < $< > $@-t && \
	    mv $@-t $@

virtlockd.socket: locking/virtlockd.socket.in $(top_builddir)/config.status
	$(AM_V_GEN)sed \
	    -e 's|[@]localstatedir[@]|$(localstatedir)|g' \
	    < $< > $@-t && \
	    mv $@-t $@

virtlockd-admin.socket: locking/virtlockd-admin.socket.in \
                        $(top_builddir)/config.status
	$(AM_V_GEN)sed \
	    -e 's|[@]localstatedir[@]|$(localstatedir)|g' \
	    < $< > $@-t && \
	    mv $@-t $@

virtlogd.service: logging/virtlogd.service.in $(top_builddir)/config.status
	$(AM_V_GEN)sed \
	    -e 's|[@]sbindir[@]|$(sbindir)|g' \
	    < $< > $@-t && \
	    mv $@-t $@

virtlogd.socket: logging/virtlogd.socket.in $(top_builddir)/config.status
	$(AM_V_GEN)sed \
	    -e 's|[@]localstatedir[@]|$(localstatedir)|g' \
	    < $< > $@-t && \
	    mv $@-t $@

virtlogd-admin.socket: logging/virtlogd-admin.socket.in \
                       $(top_builddir)/config.status
	$(AM_V_GEN)sed \
	    -e 's|[@]localstatedir[@]|$(localstatedir)|g' \
	    < $< > $@-t && \
	    mv $@-t $@


UPSTART_FILES = \
	remote/libvirtd.upstart \
	$(NULL)

EXTRA_DIST += $(UPSTART_FILES)

if WITH_LIBVIRTD
if LIBVIRT_INIT_SCRIPT_UPSTART

install-upstart: install-sysconfig
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/event.d
	for f in $(UPSTART_FILES:%.upstart=%); \
	do \
	  tgt=`basename $$f` ; \
	  $(INSTALL_SCRIPT) $(srcdir)/$$f.upstart \
	      $(DESTDIR)$(sysconfdir)/event.d/$$tgt ; \
	done

uninstall-upstart: uninstall-sysconfig
	for f in $(UPSTART_FILES:%.upstart=%); \
	do \
	  tgt=`basename $$f` ; \
	  rm -f $(DESTDIR)$(sysconfdir)/event.d/$$tgt ; \
	done
	rmdir $(DESTDIR)$(sysconfdir)/event.d || :
else ! LIBVIRT_INIT_SCRIPT_UPSTART
install-upstart:
uninstall-upstart:
endif ! LIBVIRT_INIT_SCRIPT_UPSTART
else ! WITH_LIBVIRTD
install-upstart:
uninstall-upstart:
endif ! WITH_LIBVIRTD

if WITH_SANLOCK
lockdriver_LTLIBRARIES += sanlock.la
sanlock_la_SOURCES = $(LOCK_DRIVER_SANLOCK_SOURCES)
sanlock_la_CFLAGS = -I$(srcdir)/conf $(AM_CFLAGS)
sanlock_la_LDFLAGS = $(AM_LDFLAGS_MOD_NOUNDEF)
sanlock_la_LIBADD = -lsanlock_client libvirt.la ../gnulib/lib/libgnu.la

augeas_DATA += locking/libvirt_sanlock.aug
augeastest_DATA += test_libvirt_sanlock.aug
CLEANFILES += test_libvirt_sanlock.aug

locking/%-sanlock.conf: $(srcdir)/locking/sanlock.conf
	$(AM_V_GEN)$(MKDIR_P) locking ; \
	cp $< $@

if WITH_QEMU
nodist_conf_DATA += locking/qemu-sanlock.conf
BUILT_SOURCES += locking/qemu-sanlock.conf
DISTCLEANFILES += locking/qemu-sanlock.conf
endif WITH_QEMU

if WITH_LIBXL
nodist_conf_DATA += locking/libxl-sanlock.conf
BUILT_SOURCES += locking/libxl-sanlock.conf
DISTCLEANFILES += locking/libxl-sanlock.conf
endif WITH_LIBXL
else ! WITH_SANLOCK
EXTRA_DIST += $(LOCK_DRIVER_SANLOCK_SOURCES)
endif ! WITH_SANLOCK
EXTRA_DIST += locking/sanlock.conf \
	locking/libvirt_sanlock.aug \
	locking/test_libvirt_sanlock.aug.in

noinst_LTLIBRARIES += \
	libvirt-net-rpc.la \
	libvirt-net-rpc-server.la \
	libvirt-net-rpc-client.la

libvirt_la_BUILT_LIBADD += \
       libvirt-net-rpc.la \
       libvirt-net-rpc-server.la \
       libvirt-net-rpc-client.la

EXTRA_DIST += \
	dtrace2systemtap.pl \
	rpc/gendispatch.pl \
	rpc/genprotocol.pl \
	rpc/gensystemtap.pl \
	rpc/virnetprotocol.x \
	rpc/virkeepaliveprotocol.x

VIR_NET_RPC_GENERATED = \
	rpc/virnetprotocol.h \
	rpc/virnetprotocol.c \
	rpc/virkeepaliveprotocol.h \
	rpc/virkeepaliveprotocol.c

BUILT_SOURCES += $(VIR_NET_RPC_GENERATED)

libvirt_net_rpc_la_SOURCES = \
	rpc/virnetmessage.h rpc/virnetmessage.c \
	rpc/virnetsocket.h rpc/virnetsocket.c \
	rpc/virkeepalive.h rpc/virkeepalive.c \
	$(VIR_NET_RPC_GENERATED)
if WITH_SSH2
libvirt_net_rpc_la_SOURCES += \
	rpc/virnetsshsession.h rpc/virnetsshsession.c
else ! WITH_SSH2
EXTRA_DIST += \
	rpc/virnetsshsession.h rpc/virnetsshsession.c
endif ! WITH_SSH2
if WITH_GNUTLS
libvirt_net_rpc_la_SOURCES += \
	rpc/virnettlscontext.h rpc/virnettlscontext.c
else ! WITH_GNUTLS
EXTRA_DIST += \
	rpc/virnettlscontext.h rpc/virnettlscontext.c
endif ! WITH_GNUTLS
if WITH_SASL
libvirt_net_rpc_la_SOURCES += \
	rpc/virnetsaslcontext.h rpc/virnetsaslcontext.c
else ! WITH_SASL
EXTRA_DIST += \
	rpc/virnetsaslcontext.h rpc/virnetsaslcontext.c
endif ! WITH_SASL
if WITH_LIBSSH
libvirt_net_rpc_la_SOURCES += \
	rpc/virnetlibsshsession.h rpc/virnetlibsshsession.c
else ! WITH_LIBSSH
EXTRA_DIST += \
	rpc/virnetlibsshsession.h rpc/virnetlibsshsession.c
endif ! WITH_LIBSSH
libvirt_net_rpc_la_CFLAGS = \
			$(GNUTLS_CFLAGS) \
			$(SASL_CFLAGS) \
			$(SSH2_CFLAGS) \
			$(LIBSSH_CFLAGS) \
			$(XDR_CFLAGS) \
			$(AM_CFLAGS)
libvirt_net_rpc_la_LDFLAGS = \
			$(GNUTLS_LIBS) \
			$(SASL_LIBS) \
			$(SSH2_LIBS)\
			$(LIBSSH_LIBS) \
			$(SECDRIVER_LIBS) \
			$(AM_LDFLAGS) \
			$(NULL)
libvirt_net_rpc_la_LIBADD = \
			$(CYGWIN_EXTRA_LIBADD)

libvirt_net_rpc_server_la_SOURCES = \
	rpc/virnetserverprogram.h rpc/virnetserverprogram.c \
	rpc/virnetserverservice.h rpc/virnetserverservice.c \
	rpc/virnetserverclient.h rpc/virnetserverclient.c \
	rpc/virnetservermdns.h rpc/virnetservermdns.c \
	rpc/virnetdaemon.h rpc/virnetdaemon.c \
	rpc/virnetserver.h rpc/virnetserver.c
libvirt_net_rpc_server_la_CFLAGS = \
			$(AVAHI_CFLAGS) \
			$(DBUS_CFLAGS) \
			$(XDR_CFLAGS) \
			$(AM_CFLAGS)
libvirt_net_rpc_server_la_LDFLAGS = \
			$(AM_LDFLAGS) \
			$(AVAHI_LIBS) \
			$(DBUS_LIBS) \
			$(NULL)
libvirt_net_rpc_server_la_LIBADD = \
			$(CYGWIN_EXTRA_LIBADD)

libvirt_net_rpc_client_la_SOURCES = \
	rpc/virnetclientprogram.h rpc/virnetclientprogram.c \
	rpc/virnetclientstream.h rpc/virnetclientstream.c \
	rpc/virnetclient.h rpc/virnetclient.c
libvirt_net_rpc_client_la_CFLAGS = \
			$(AM_CFLAGS) \
			$(XDR_CFLAGS)
libvirt_net_rpc_client_la_LDFLAGS = $(AM_LDFLAGS)
libvirt_net_rpc_client_la_LIBADD = \
			$(CYGWIN_EXTRA_LIBADD)

if WITH_LIBVIRTD
libexec_PROGRAMS += libvirt_iohelper
libvirt_iohelper_SOURCES = $(UTIL_IO_HELPER_SOURCES)
libvirt_iohelper_LDFLAGS = \
		$(AM_LDFLAGS) \
		$(PIE_LDFLAGS) \
		$(NULL)
libvirt_iohelper_LDADD = \
		libvirt_util.la \
		../gnulib/lib/libgnu.la
if WITH_DTRACE_PROBES
libvirt_iohelper_LDADD += libvirt_probes.lo
endif WITH_DTRACE_PROBES

libvirt_iohelper_CFLAGS = \
		$(AM_CFLAGS) \
		$(PIE_CFLAGS) \
		$(NULL)

if WITH_NETWORK
libexec_PROGRAMS += libvirt_leaseshelper
libvirt_leaseshelper_SOURCES = $(NETWORK_LEASES_HELPER_SOURCES)
libvirt_leaseshelper_LDFLAGS = \
		$(AM_LDFLAGS) \
		$(PIE_LDFLAGS) \
		$(NULL)
libvirt_leaseshelper_LDADD = \
               libvirt_util.la \
               ../gnulib/lib/libgnu.la
if WITH_DTRACE_PROBES
libvirt_leaseshelper_LDADD += libvirt_probes.lo
endif WITH_DTRACE_PROBES

libvirt_leaseshelper_CFLAGS = \
	       $(AM_CFLAGS) \
               $(PIE_CFLAGS) \
               $(NULL)
else ! WITH_NETWORK
EXTRA_DIST += $(NETWORK_LEASES_HELPER_SOURCES)
endif ! WITH_NETWORK

endif WITH_LIBVIRTD

if WITH_STORAGE_DISK
if WITH_LIBVIRTD
libexec_PROGRAMS += libvirt_parthelper

libvirt_parthelper_SOURCES = $(STORAGE_HELPER_DISK_SOURCES)
libvirt_parthelper_LDFLAGS = \
		$(AM_LDFLAGS) \
		$(PIE_LDFLAGS) \
		$(NULL)
libvirt_parthelper_LDADD = \
		$(LIBPARTED_LIBS) \
		libvirt_util.la \
		../gnulib/lib/libgnu.la
if WITH_DTRACE_PROBES
libvirt_parthelper_LDADD += libvirt_probes.lo
endif WITH_DTRACE_PROBES

libvirt_parthelper_CFLAGS = \
		$(LIBPARTED_CFLAGS) \
		$(AM_CFLAGS) \
		$(PIE_CFLAGS) \
		$(NULL)
endif WITH_LIBVIRTD
endif WITH_STORAGE_DISK
EXTRA_DIST += $(STORAGE_HELPER_DISK_SOURCES)


if WITH_SANLOCK
libexec_PROGRAMS += libvirt_sanlock_helper

libvirt_sanlock_helper_SOURCES = $(LOCK_DRIVER_SANLOCK_HELPER_SOURCES)
libvirt_sanlock_helper_CFLAGS = \
		-I$(srcdir)/conf \
		$(AM_CFLAGS) \
		$(PIE_CFLAGS) \
		$(NULL)
libvirt_sanlock_helper_LDFLAGS = \
		$(AM_LDFLAGS) \
		$(PIE_LDFLAGS) \
		$(NULL)
libvirt_sanlock_helper_LDADD = libvirt.la
endif WITH_SANLOCK


if WITH_SECDRIVER_APPARMOR
if WITH_LIBVIRTD
libexec_PROGRAMS += virt-aa-helper

virt_aa_helper_SOURCES = $(SECURITY_DRIVER_APPARMOR_HELPER_SOURCES)

virt_aa_helper_LDFLAGS = \
		$(AM_LDFLAGS) \
		$(PIE_LDFLAGS) \
		$(NULL)
virt_aa_helper_LDADD = \
		libvirt.la \
		libvirt_conf.la \
		libvirt_util.la \
		libvirt_driver_storage_impl.la \
		../gnulib/lib/libgnu.la
if WITH_DTRACE_PROBES
virt_aa_helper_LDADD += libvirt_probes.lo
endif WITH_DTRACE_PROBES
virt_aa_helper_CFLAGS = \
		-I$(srcdir)/conf \
		-I$(srcdir)/security \
		$(AM_CFLAGS) \
		$(PIE_CFLAGS) \
		$(NULL)
endif WITH_LIBVIRTD
endif WITH_SECDRIVER_APPARMOR
EXTRA_DIST += $(SECURITY_DRIVER_APPARMOR_HELPER_SOURCES)

if WITH_NSS
noinst_LTLIBRARIES += libvirt-nss.la

libvirt_nss_la_SOURCES = \
		util/viralloc.c \
		util/viralloc.h \
		util/viratomic.c \
		util/viratomic.h \
		util/virbitmap.c \
		util/virbitmap.h \
		util/virbuffer.c \
		util/virbuffer.h \
		util/vircommand.c \
		util/vircommand.h \
		util/virerror.c \
		util/virerror.h \
		util/virfile.c \
		util/virfile.h \
		util/virhash.c \
		util/virhash.h \
		util/virhashcode.c \
		util/virhashcode.h \
		util/virjson.c \
		util/virjson.h \
		util/virkmod.c \
		util/virkmod.h \
		util/virlease.c \
		util/virlease.h \
		util/virlog.c \
		util/virlog.h \
		util/virmacmap.c \
		util/virmacmap.h \
		util/virobject.c \
		util/virobject.h \
		util/virpidfile.c \
		util/virpidfile.h \
		util/virprocess.c \
		util/virprocess.h \
		util/virrandom.c \
		util/virrandom.h \
		util/virsocketaddr.c \
		util/virsocketaddr.h \
		util/virstring.c \
		util/virstring.h \
		util/virthread.c \
		util/virthread.h \
		util/virthreadjob.c \
		util/virthreadjob.h \
		util/virtime.c \
		util/virtime.h \
		util/virutil.c \
		util/virutil.h \
		$(NULL)

libvirt_nss_la_CFLAGS = \
		-DLIBVIRT_NSS \
		$(AM_CFLAGS) \
		$(YAJL_CFLAGS) \
		$(NULL)
libvirt_nss_la_LDFLAGS = \
		$(AM_LDFLAGS) \
		$(NULL)

libvirt_nss_la_LIBADD = \
		$(YAJL_LIBS) \
		$(NULL)
endif WITH_NSS


install-data-local: install-init install-systemd install-upstart \
		install-sysctl install-polkit install-sasl \
		install-logrotate $(INSTALL_DATA_DIRS:%=install-data-%)
if WITH_LIBVIRTD
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/log/libvirt"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/libvirt/lockd"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/libvirt/lockd/files"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/run/libvirt/lockd"
endif WITH_LIBVIRTD
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/cache/libvirt"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/libvirt/images"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/libvirt/filesystems"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/libvirt/boot"
if WITH_SANLOCK
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/libvirt/sanlock"
endif WITH_SANLOCK
if WITH_NETWORK
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/libvirt/network"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/libvirt/dnsmasq"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/run/libvirt/network"
	$(MKDIR_P) "$(DESTDIR)$(confdir)/qemu/networks/autostart"
	$(INSTALL_DATA) $(srcdir)/network/default.xml \
	  $(DESTDIR)$(confdir)/qemu/networks/default.xml
	test -z "$(UUID)" || \
	  { sed -e "s,</name>,</name>;  <uuid>$(UUID)</uuid>," \
	      $(DESTDIR)$(confdir)/qemu/networks/default.xml | \
	      tr ";" "\n" > \
	      $(DESTDIR)$(confdir)/qemu/networks/default.xml.t && \
	    cp $(DESTDIR)$(confdir)/qemu/networks/default.xml.t \
	      $(DESTDIR)$(confdir)/qemu/networks/default.xml && \
	    rm $(DESTDIR)$(confdir)/qemu/networks/default.xml.t; }
	( cd $(DESTDIR)$(confdir)/qemu/networks/autostart && \
	  rm -f default.xml && \
	  $(LN_S) ../default.xml default.xml )
endif WITH_NETWORK

uninstall-local:: uninstall-init uninstall-systemd uninstall-upstart \
		uninstall-sysctl uninstall-polkit uninstall-sasl \
		uninstall-logrotate $(INSTALL_DATA_DIRS:%=uninstall-data-%)
if WITH_LIBVIRTD
	rmdir "$(DESTDIR)$(localstatedir)/log/libvirt" ||:
	rmdir "$(DESTDIR)$(localstatedir)/lib/libvirt/lockd/files" ||:
	rmdir "$(DESTDIR)$(localstatedir)/lib/libvirt/lockd" ||:
	rmdir "$(DESTDIR)$(localstatedir)/run/libvirt/lockd" ||:
endif WITH_LIBVIRTD
	rmdir "$(DESTDIR)$(localstatedir)/cache/libvirt" ||:
	rmdir "$(DESTDIR)$(localstatedir)/lib/libvirt/images" ||:
	rmdir "$(DESTDIR)$(localstatedir)/lib/libvirt/filesystems" ||:
	rmdir "$(DESTDIR)$(localstatedir)/lib/libvirt/boot" ||:
if WITH_SANLOCK
	rmdir "$(DESTDIR)$(localstatedir)/lib/libvirt/sanlock" ||:
endif WITH_SANLOCK
if WITH_NETWORK
	rm -f $(DESTDIR)$(confdir)/qemu/networks/autostart/default.xml
	rm -f $(DESTDIR)$(confdir)/qemu/networks/default.xml
	rmdir "$(DESTDIR)$(confdir)/qemu/networks/autostart" || :
	rmdir "$(DESTDIR)$(confdir)/qemu/networks" || :
	rmdir "$(DESTDIR)$(localstatedir)/lib/libvirt/network" ||:
	rmdir "$(DESTDIR)$(localstatedir)/run/libvirt/network" ||:
endif WITH_NETWORK
	rmdir "$(DESTDIR)$(localstatedir)/lib/libvirt" ||:

CLEANFILES += *.gcov .libs/*.gcda .libs/*.gcno *.gcno *.gcda *.i *.s
DISTCLEANFILES += $(GENERATED_SYM_FILES)
MAINTAINERCLEANFILES += \
	$(REMOTE_DRIVER_GENERATED) \
	$(LIBVIRTD_GENERATED) \
	$(VIR_NET_RPC_GENERATED) \
	$(NULL)
