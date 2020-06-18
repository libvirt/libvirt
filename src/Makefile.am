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
AM_CPPFLAGS =	-I$(top_srcdir) \
		-I../include \
		-I$(top_srcdir)/include \
		-I$(srcdir)/util \
		-I./util \
		-DIN_LIBVIRT \
		-Dabs_top_builddir="\"$(abs_top_builddir)\"" \
		-Dabs_top_srcdir="\"$(abs_top_srcdir)\"" \
		$(NULL)

AM_CFLAGS =	$(LIBXML_CFLAGS) \
		$(GLIB_CFLAGS) \
		$(WARN_CFLAGS) \
		$(WIN32_EXTRA_CFLAGS) \
		$(COVERAGE_CFLAGS) \
		$(NULL)
AM_LDFLAGS =	$(DRIVER_MODULES_LDFLAGS) \
		$(COVERAGE_LDFLAGS) \
		$(RELRO_LDFLAGS) \
		$(NO_INDIRECT_LDFLAGS) \
		$(MINGW_EXTRA_LDFLAGS) \
		$(NULL)
AM_LDFLAGS_MOD = \
	-module \
	-avoid-version \
	$(LIBVIRT_NODELETE) \
	$(AM_LDFLAGS)
AM_LDFLAGS_MOD_NOUNDEF = $(AM_LDFLAGS_MOD) $(NO_UNDEFINED_LDFLAGS)

EXTRA_DIST = $(conf_DATA)

BUILT_SOURCES =
CLEANFILES =
DISTCLEANFILES =
MAINTAINERCLEANFILES =
nodist_conf_DATA =
DRIVER_SOURCE_FILES =
STATEFUL_DRIVER_SOURCE_FILES =
lib_LTLIBRARIES =
noinst_LTLIBRARIES =
mod_LTLIBRARIES =
INSTALL_DATA_DIRS =
INSTALL_DATA_LOCAL =
UNINSTALL_LOCAL =
libvirt_la_BUILT_LIBADD =
SYM_FILES =
USED_SYM_FILES =
GENERATED_SYM_FILES =
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
DRIVER_SOURCES =

COMMON_UNIT_VARS = \
	-e 's|[@]runstatedir[@]|$(runstatedir)|g' \
	-e 's|[@]sbindir[@]|$(sbindir)|g' \
	-e 's|[@]sysconfdir[@]|$(sysconfdir)|g' \
	$(NULL)

# Set these variables before we include any of the subdirs as libvirt-admin.la
# has to be installed after libvirt.la.
lib_LTLIBRARIES += libvirt.la libvirt-qemu.la libvirt-lxc.la

include util/Makefile.inc.am
include conf/Makefile.inc.am
include cpu/Makefile.inc.am
include cpu_map/Makefile.inc.am
include security/Makefile.inc.am
include access/Makefile.inc.am
include logging/Makefile.inc.am
include locking/Makefile.inc.am
include admin/Makefile.inc.am
include rpc/Makefile.inc.am
include test/Makefile.inc.am
include hypervisor/Makefile.inc.am
include esx/Makefile.inc.am
include hyperv/Makefile.inc.am
include vmx/Makefile.inc.am
include vmware/Makefile.inc.am
include vbox/Makefile.inc.am
include openvz/Makefile.inc.am
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


moddir = $(libdir)/libvirt/connection-driver

confdir = $(sysconfdir)/libvirt
conf_DATA += libvirt.conf

CLEANFILES += $(nodist_conf_DATA)
BUILT_SOURCES += $(nodist_conf_DATA)

augeasdir = $(datadir)/augeas/lenses

augeastestdir = $(datadir)/augeas/lenses/tests

CLEANFILES += $(augeastest_DATA)

# Internal generic driver infrastructure
DATATYPES_SOURCES = datatypes.h datatypes.c
DRIVER_SOURCES += \
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
		libvirt-domain-checkpoint.c \
		libvirt-domain-snapshot.c \
		libvirt-host.c \
		libvirt-interface.c \
		libvirt-network.c \
		libvirt-nodedev.c \
		libvirt-nwfilter.c \
		libvirt-secret.c \
		libvirt-storage.c \
		libvirt-stream.c \
		$(NULL)




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
EXTRA_DIST += $(PROTOCOL_STRUCTS)

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


#########################
#
# Build up list of libvirt.la source files based on configure conditions
#
# First deal with sources usable in non-daemon context


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
	libvirt.syms libvirt.def libvirt_qemu.def libvirt_lxc.def \
	$(NULL)



%protocol.c: %protocol.x %protocol.h $(srcdir)/rpc/genprotocol.pl
	$(AM_V_GEN)$(PERL) -w $(srcdir)/rpc/genprotocol.pl $(RPCGEN) -c \
	       $< $(subst $(srcdir)/,,$@)

%protocol.h: %protocol.x $(srcdir)/rpc/genprotocol.pl
	$(AM_V_GEN)$(PERL) -w $(srcdir)/rpc/genprotocol.pl $(RPCGEN) -h \
	       $< $(subst $(srcdir)/,,$@)

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

if WITH_SASL
USED_SYM_FILES += $(srcdir)/libvirt_sasl.syms
else ! WITH_SASL
SYM_FILES += $(srcdir)/libvirt_sasl.syms
endif ! WITH_SASL

if WITH_SSH2
USED_SYM_FILES += $(srcdir)/libvirt_libssh2.syms
else ! WITH_SSH2
SYM_FILES += $(srcdir)/libvirt_libssh2.syms
endif ! WITH_SSH2

if WITH_LIBSSH
USED_SYM_FILES += $(srcdir)/libvirt_libssh.syms
else ! WITH_LIBSSH
SYM_FILES += $(srcdir)/libvirt_libssh.syms
endif ! WITH_LIBSSH

EXTRA_DIST += \
	libvirt_public.syms \
	libvirt_lxc.syms \
	libvirt_qemu.syms \
	$(SYM_FILES) \
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

# Empty source list - it merely links a bunch of convenience libs together
libvirt_la_SOURCES =
libvirt_la_LDFLAGS = \
		$(VERSION_SCRIPT_FLAGS)$(LIBVIRT_SYMBOL_FILE) \
		-version-info $(LIBVIRT_VERSION_INFO) \
		$(LIBVIRT_NODELETE) \
		$(NO_UNDEFINED_LDFLAGS) \
		$(FLAT_NAMESPACE_FLAGS) \
		$(AM_LDFLAGS) \
		$(NULL)
libvirt_la_LIBADD += \
		$(DLOPEN_LIBS) \
		$(XDR_LIBS) \
		$(NULL)
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
		  $(srcdir)/admin/admin_protocol.x

libvirt_functions.stp: $(RPC_PROBE_FILES) $(top_srcdir)/scripts/gensystemtap.py
	$(AM_V_GEN)$(RUNUTF8) $(PYTHON) $(top_srcdir)/scripts/gensystemtap.py \
	  $(RPC_PROBE_FILES) > $@

%_probes.stp: %_probes.d $(top_srcdir)/scripts/dtrace2systemtap.py \
		$(top_builddir)/config.status
	$(AM_V_GEN)$(RUNUTF8) $(PYTHON) $(top_srcdir)/scripts/dtrace2systemtap.py \
	  $(bindir) $(sbindir) $(libdir) $< > $@

CLEANFILES += libvirt_probes.h libvirt_probes.o libvirt_probes.lo \
              libvirt_functions.stp libvirt_probes.stp
endif WITH_DTRACE_PROBES

EXTRA_DIST += libvirt_probes.d

libvirt_qemu_la_SOURCES = libvirt-qemu.c
libvirt_qemu_la_LDFLAGS = \
		$(VERSION_SCRIPT_FLAGS)$(LIBVIRT_QEMU_SYMBOL_FILE) \
		-version-info $(LIBVIRT_VERSION_INFO) \
		$(LIBVIRT_NODELETE) \
		$(AM_LDFLAGS) \
		$(NULL)
libvirt_qemu_la_CFLAGS = $(AM_CFLAGS)
libvirt_qemu_la_LIBADD = libvirt.la

libvirt_lxc_la_SOURCES = libvirt-lxc.c
libvirt_lxc_la_LDFLAGS = \
		$(VERSION_SCRIPT_FLAGS)$(LIBVIRT_LXC_SYMBOL_FILE) \
		-version-info $(LIBVIRT_VERSION_INFO) \
		$(LIBVIRT_NODELETE) \
		$(AM_LDFLAGS) \
		$(NULL)
libvirt_lxc_la_CFLAGS = $(AM_CFLAGS)
libvirt_lxc_la_LIBADD = libvirt.la

EXTRA_DIST += \
	$(SYSCONF_FILES) \
	$(OPENRC_CONF_FILES)

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

EXTRA_DIST += $(LOGROTATE_FILES_IN)

BUILT_SOURCES += $(LOGROTATE_FILES)
CLEANFILES += $(LOGROTATE_FILES)

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


EXTRA_DIST += \
        $(SYSTEMD_UNIT_FILES_IN) \
        $(OPENRC_INIT_FILES_IN) \
        $(NULL)


if WITH_LIBVIRTD
if LIBVIRT_INIT_SCRIPT_SYSTEMD

SYSTEMD_UNIT_DIR = $(prefix)/lib/systemd/system

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

INSTALL_DATA_LOCAL += install-systemd
UNINSTALL_LOCAL += uninstall-systemd
endif LIBVIRT_INIT_SCRIPT_SYSTEMD

if LIBVIRT_INIT_SCRIPT_OPENRC

OPENRC_INIT_DIR = $(sysconfdir)/init.d

BUILT_SOURCES += $(OPENRC_INIT_FILES)
DISTCLEANFILES += $(OPENRC_INIT_FILES)

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
		$(PIE_LDFLAGS) \
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
		$(PIE_CFLAGS) \
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

CLEANFILES += *.gcov .libs/*.gcda .libs/*.gcno *.gcno *.gcda *.i *.s
DISTCLEANFILES += $(GENERATED_SYM_FILES)
