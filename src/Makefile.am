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
AM_CPPFLAGS =	-I../gnulib/lib \
		-I$(top_srcdir)/gnulib/lib \
		-I$(top_srcdir) \
		-I../include \
		-I$(top_srcdir)/include \
		-I$(srcdir)/util \
		-I./util \
		-DIN_LIBVIRT \
		-Dabs_top_builddir="\"$(abs_top_builddir)\"" \
		-Dabs_top_srcdir="\"$(abs_top_srcdir)\"" \
		$(NULL)

WARN_CFLAGS += $(STRICT_FRAME_LIMIT_CFLAGS)

AM_CFLAGS =	$(LIBXML_CFLAGS) \
		$(WARN_CFLAGS) \
		$(LOCK_CHECKING_CFLAGS) \
		$(WIN32_EXTRA_CFLAGS) \
		$(NULL)
AM_LDFLAGS =	$(DRIVER_MODULES_LDFLAGS) \
		$(RELRO_LDFLAGS) \
		$(NO_INDIRECT_LDFLAGS) \
		$(CYGWIN_EXTRA_LDFLAGS) \
		$(MINGW_EXTRA_LDFLAGS) \
		$(NULL)
AM_LDFLAGS_MOD = \
	-module \
	-avoid-version \
	$(LIBVIRT_NODELETE) \
	$(AM_LDFLAGS)
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
INSTALL_DATA_LOCAL =
UNINSTALL_LOCAL =
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
LOGROTATE_FILES_IN =
PODFILES =
MANINFILES =
SYSTEMD_UNIT_FILES_IN =
SYSCONF_FILES =
sbin_PROGRAMS =
man8_MANS =
DRIVER_SOURCES =
man7_MANS =

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
include phyp/Makefile.inc.am
include test/Makefile.inc.am
include esx/Makefile.inc.am
include hyperv/Makefile.inc.am
include vmx/Makefile.inc.am
include vmware/Makefile.inc.am
include vbox/Makefile.inc.am
include openvz/Makefile.inc.am
include qemu/Makefile.inc.am
include bhyve/Makefile.inc.am
include xenconfig/Makefile.inc.am
include libxl/Makefile.inc.am
include xenapi/Makefile.inc.am
include vz/Makefile.inc.am
include lxc/Makefile.inc.am
include interface/Makefile.inc.am
include network/Makefile.inc.am
include nwfilter/Makefile.inc.am
include node_device/Makefile.inc.am
include secret/Makefile.inc.am
include storage/Makefile.inc.am
include remote/Makefile.inc.am


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


lib_LTLIBRARIES = libvirt.la libvirt-qemu.la libvirt-lxc.la

moddir = $(libdir)/libvirt/connection-driver

confdir = $(sysconfdir)/libvirt
conf_DATA += libvirt.conf libvirt-admin.conf

augeasdir = $(datadir)/augeas/lenses

augeastestdir = $(datadir)/augeas/lenses/tests


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
	libvirt_admin.syms libvirt_admin.def \
	$(NULL)



%protocol.c: %protocol.x %protocol.h $(srcdir)/rpc/genprotocol.pl
	$(AM_V_GEN)$(PERL) -w $(srcdir)/rpc/genprotocol.pl $(RPCGEN) -c \
	       $< $(srcdir)/$(subst $(srcdir)/,,$@)

%protocol.h: %protocol.x $(srcdir)/rpc/genprotocol.pl
	$(AM_V_GEN)$(PERL) -w $(srcdir)/rpc/genprotocol.pl $(RPCGEN) -h \
	       $< $(srcdir)/$(subst $(srcdir)/,,$@)







check-local: check-augeas

check-augeas: $(AUGEAS_DIRS:%=check-augeas-%)

AUG_GENTEST = $(PERL) $(top_srcdir)/build-aux/augeas-gentest.pl


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


lib_LTLIBRARIES += libvirt-admin.la
libvirt_admin_la_SOURCES = \
		libvirt-admin.c \
		$(ADMIN_PROTOCOL_GENERATED) \
		$(DATATYPES_SOURCES)

libvirt_admin_la_LDFLAGS = \
		$(VERSION_SCRIPT_FLAGS)$(LIBVIRT_ADMIN_SYMBOL_FILE) \
		-version-info $(LIBVIRT_VERSION_INFO) \
		$(LIBVIRT_NODELETE) \
		$(AM_LDFLAGS) \
		$(NULL)

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
		$(LIBVIRT_NODELETE) \
		$(AM_LDFLAGS) \
		$(NULL)
libvirt_qemu_la_CFLAGS = $(AM_CFLAGS)
libvirt_qemu_la_LIBADD = libvirt.la $(CYGWIN_EXTRA_LIBADD)

libvirt_lxc_la_SOURCES = libvirt-lxc.c
libvirt_lxc_la_LDFLAGS = \
		$(VERSION_SCRIPT_FLAGS)$(LIBVIRT_LXC_SYMBOL_FILE) \
		-version-info $(LIBVIRT_VERSION_INFO) \
		$(LIBVIRT_NODELETE) \
		$(AM_LDFLAGS) \
		$(NULL)
libvirt_lxc_la_CFLAGS = $(AM_CFLAGS)
libvirt_lxc_la_LIBADD = libvirt.la $(CYGWIN_EXTRA_LIBADD)

# Since virt-login-shell will be setuid, we must do everything
# we can to avoid linking to other libraries. Many of them do
# unsafe things in functions marked __attribute__((constructor)).
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
		util/virautoclean.h \
		util/virbitmap.c \
		util/virbuffer.c \
		util/vircgroup.c \
		util/vircgroupbackend.c \
		util/vircgroupv1.c \
		util/vircgroupv2.c \
		util/vircommand.c \
		util/virconf.c \
		util/virdbus.c \
		util/virenum.c \
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

EXTRA_DIST += $(SYSCONF_FILES)

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


%.8: %.8.in $(top_srcdir)/configure.ac
	$(AM_V_GEN)sed \
		-e 's|[@]sysconfdir[@]|$(sysconfdir)|g' \
		-e 's|[@]localstatedir[@]|$(localstatedir)|g' \
		< $< > $@-t && \
	mv $@-t $@

CLEANFILES += $(man8_MANS)
MAINTAINERCLEANFILES += $(MANINFILES)

EXTRA_DIST += \
        $(SYSTEMD_UNIT_FILES_IN) \
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

INSTALL_DATA_LOCAL += install-systemd
UNINSTALL_LOCAL += uninstall-systemd
endif LIBVIRT_INIT_SCRIPT_SYSTEMD
endif WITH_LIBVIRTD


EXTRA_DIST += dtrace2systemtap.pl


if WITH_LIBVIRTD
libexec_PROGRAMS += libvirt_iohelper
libvirt_iohelper_SOURCES = $(UTIL_IO_HELPER_SOURCES)
libvirt_iohelper_LDFLAGS = \
		$(AM_LDFLAGS) \
		$(PIE_LDFLAGS) \
		$(NULL)
libvirt_iohelper_LDADD = \
		libvirt.la \
		../gnulib/lib/libgnu.la
if WITH_DTRACE_PROBES
libvirt_iohelper_LDADD += libvirt_probes.lo
endif WITH_DTRACE_PROBES

libvirt_iohelper_CFLAGS = \
		$(AM_CFLAGS) \
		$(PIE_CFLAGS) \
		$(NULL)


endif WITH_LIBVIRTD



if WITH_NSS
noinst_LTLIBRARIES += libvirt-nss.la

libvirt_nss_la_SOURCES = \
		util/viralloc.c \
		util/viralloc.h \
		util/viratomic.c \
		util/viratomic.h \
		util/virautoclean.h \
		util/virbitmap.c \
		util/virbitmap.h \
		util/virbuffer.c \
		util/virbuffer.h \
		util/vircommand.c \
		util/vircommand.h \
		util/virenum.c \
		util/virenum.h \
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
