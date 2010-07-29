## Process this file with automake to produce Makefile.in

# No libraries with the exception of LIBXML should be listed
# here. List them against the individual XXX_la_CFLAGS targets
# that actually use them
INCLUDES =							\
		-I$(top_srcdir)/gnulib/lib			\
		-I../gnulib/lib					\
		-I../include					\
		-I@top_srcdir@/src/util				\
		-I@top_srcdir@/include				\
		$(DRIVER_MODULE_CFLAGS)				\
		$(LIBXML_CFLAGS)				\
		-DLIBDIR=\""$(libdir)"\"			\
		-DBINDIR=\""$(libexecdir)"\"			\
		-DSBINDIR=\""$(sbindir)"\"			\
		-DSYSCONF_DIR="\"$(sysconfdir)\""		\
		-DLOCALEBASEDIR=\""$(datadir)/locale"\"		\
		-DPKGDATADIR=\""$(pkgdatadir)"\"		\
		-DLOCAL_STATE_DIR=\""$(localstatedir)"\"	\
		-DGETTEXT_PACKAGE=\"$(PACKAGE)\"		\
		$(WARN_CFLAGS)					\
		$(LOCK_CHECKING_CFLAGS)			\
		-DIN_LIBVIRT				\
		$(WIN32_EXTRA_CFLAGS)

AM_CFLAGS = $(COVERAGE_CFLAGS)
AM_LDFLAGS = $(COVERAGE_LDFLAGS)

EXTRA_DIST = $(conf_DATA)

BUILT_SOURCES =

if WITH_NETWORK
UUID=$(shell uuidgen 2>/dev/null)
endif

lib_LTLIBRARIES = libvirt.la libvirt-qemu.la

moddir = $(libdir)/libvirt/drivers
mod_LTLIBRARIES =

confdir = $(sysconfdir)/libvirt
conf_DATA =

augeasdir = $(datadir)/augeas/lenses
augeas_DATA =

augeastestdir = $(datadir)/augeas/lenses/tests
augeastest_DATA =

# These files are not related to driver APIs. Simply generic
# helper APIs for various purposes
UTIL_SOURCES =							\
		util/authhelper.c util/authhelper.h		\
		util/bitmap.c util/bitmap.h			\
		util/bridge.c util/bridge.h			\
		util/buf.c util/buf.h				\
		util/conf.c util/conf.h				\
		util/cgroup.c util/cgroup.h			\
		util/event.c util/event.h			\
		util/hash.c util/hash.h				\
		util/hooks.c util/hooks.h			\
		util/iptables.c util/iptables.h			\
		util/ebtables.c util/ebtables.h			\
		util/dnsmasq.c util/dnsmasq.h                   \
		util/json.c util/json.h				\
		util/logging.c util/logging.h			\
		util/macvtap.c util/macvtap.h			\
		util/memory.c util/memory.h			\
		util/pci.c util/pci.h				\
		util/processinfo.c util/processinfo.h		\
		util/hostusb.c util/hostusb.h			\
		util/network.c util/network.h			\
		util/interface.c util/interface.h		\
		util/qparams.c util/qparams.h			\
		util/stats_linux.c util/stats_linux.h		\
		util/storage_file.c util/storage_file.h		\
		util/threads.c util/threads.h			\
		util/threads-pthread.h				\
		util/threads-win32.h				\
		util/uuid.c util/uuid.h				\
		util/util.c util/util.h				\
		util/xml.c util/xml.h				\
		util/virterror.c util/virterror_internal.h

EXTRA_DIST += util/threads-pthread.c util/threads-win32.c

# Internal generic driver infrastructure
NODE_INFO_SOURCES = nodeinfo.h nodeinfo.c
DRIVER_SOURCES =						\
		driver.c driver.h				\
		internal.h					\
		datatypes.c datatypes.h				\
		$(NODE_INFO_SOURCES)				\
		libvirt.c libvirt_internal.h


# XML configuration format handling sources
# Domain driver generic impl APIs
DOMAIN_CONF_SOURCES =						\
		conf/capabilities.c conf/capabilities.h		\
		conf/domain_conf.c conf/domain_conf.h		\
		conf/domain_nwfilter.c conf/domain_nwfilter.h

DOMAIN_EVENT_SOURCES =						\
		conf/domain_event.c conf/domain_event.h

# Network driver generic impl APIs
NETWORK_CONF_SOURCES =						\
		conf/network_conf.c conf/network_conf.h

# Network filter driver generic impl APIs
NWFILTER_PARAM_CONF_SOURCES =					\
		conf/nwfilter_params.c conf/nwfilter_params.h	\
		conf/nwfilter_conf.h

NWFILTER_CONF_SOURCES =					\
		$(NWFILTER_PARAM_CONF_SOURCES)			\
		conf/nwfilter_conf.c conf/nwfilter_conf.h

# Storage driver generic impl APIs
STORAGE_CONF_SOURCES =                                         \
		conf/storage_conf.h conf/storage_conf.c

# Interface driver generic impl APIs
INTERFACE_CONF_SOURCES =                                       \
		conf/interface_conf.c conf/interface_conf.h

# Secret driver generic impl APIs
SECRET_CONF_SOURCES =                                          \
		conf/secret_conf.h conf/secret_conf.c

# Network driver generic impl APIs
NODE_DEVICE_CONF_SOURCES =                                     \
		conf/node_device_conf.c conf/node_device_conf.h

ENCRYPTION_CONF_SOURCES =					\
		conf/storage_encryption_conf.c conf/storage_encryption_conf.h

CPU_CONF_SOURCES =						\
		conf/cpu_conf.c conf/cpu_conf.h

CONF_SOURCES =							\
		$(DOMAIN_CONF_SOURCES)				\
		$(DOMAIN_EVENT_SOURCES)				\
		$(NETWORK_CONF_SOURCES)				\
		$(NWFILTER_CONF_SOURCES)			\
		$(NODE_DEVICE_CONF_SOURCES)			\
		$(STORAGE_CONF_SOURCES)				\
		$(ENCRYPTION_CONF_SOURCES)			\
		$(INTERFACE_CONF_SOURCES)			\
		$(SECRET_CONF_SOURCES)				\
		$(CPU_CONF_SOURCES)

# The remote RPC driver, covering domains, storage, networks, etc
REMOTE_DRIVER_SOURCES =						\
		gnutls_1_0_compat.h			\
		remote/remote_driver.c remote/remote_driver.h	\
		remote/remote_protocol.c			\
		remote/remote_protocol.h			\
		remote/qemu_protocol.c				\
		remote/qemu_protocol.h

EXTRA_DIST += remote/remote_protocol.x remote/qemu_protocol.x \
		remote/rpcgen_fix.pl

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
# whereas with pdwtags 1.3, they look like this:
# /* <2d2> /usr/include/libio.h:180 */
# The concatenation of the following regexps matches both cases.
r1 = (?:/\* \d+ \*/\n)?
r2 = /\* <[[:xdigit:]]+> \S+:\d+ \*/

.PHONY: remote_protocol-structs
remote_protocol-structs:
	$(AM_V_GEN)if (pdwtags --help) > /dev/null 2>&1; then		\
	  pdwtags --verbose libvirt_driver_remote_la-remote_protocol.$(OBJEXT) \
	    | perl -0777 -n						\
		-e 'foreach my $$p (split m!\n\n$(r1)$(r2)\n!) {'	\
		-e '  if ($$p =~ /^struct remote_/) {'			\
		-e '    $$p =~ s!\t*/\*.*?\*/!!sg;'			\
		-e '    $$p =~ s!\s+\n!\n!sg;'				\
		-e '    $$p =~ s!\s+$$!!;'				\
		-e '    print "$$p\n";'					\
		-e '    $$n++;'						\
		-e '  }'						\
		-e '}'							\
		-e 'END {'						\
		-e '  if ($$n < 300) {'					\
		-e '    warn "WARNING: your pdwtags program is too old\n";' \
		-e '    warn "WARNING: skipping the $@ test\n";'	\
		-e '    warn "WARNING: install dwarves-1.3 or newer\n";' \
		-e '    exit 8;'					\
		-e '  }'						\
		-e '}'							\
		> $@-t;							\
          case $$? in 8) exit 0;; 0) ;; *) exit 1;; esac;		\
	  diff -u $@-t $(srcdir)/$@; st=$$?; rm -f $@-t; exit $$st;	\
	else								\
	  echo 'WARNING: you lack pdwtags; skipping the $@ test' >&2;	\
	  echo 'WARNING: install the dwarves package to get pdwtags' >&2; \
	fi
EXTRA_DIST += remote_protocol-structs
check-local: remote_protocol-structs

# Mock driver, covering domains, storage, networks, etc
TEST_DRIVER_SOURCES =						\
		test/test_driver.c test/test_driver.h



# Now the Hypervisor specific drivers
XEN_DRIVER_SOURCES =						\
		xen/proxy_internal.c xen/proxy_internal.h	\
		xen/sexpr.c xen/sexpr.h				\
		xen/block_stats.c xen/block_stats.h		\
		xen/xen_hypervisor.c xen/xen_hypervisor.h	\
		xen/xen_driver.c xen/xen_driver.h		\
		xen/xend_internal.c xen/xend_internal.h		\
		xen/xm_internal.c xen/xm_internal.h		\
		xen/xs_internal.c xen/xs_internal.h
if WITH_XEN_INOTIFY
XEN_DRIVER_SOURCES += xen/xen_inotify.c xen/xen_inotify.h
endif

LXC_DRIVER_SOURCES =						\
		lxc/lxc_conf.c lxc/lxc_conf.h			\
		lxc/lxc_container.c lxc/lxc_container.h		\
		lxc/lxc_driver.c lxc/lxc_driver.h		\
		lxc/veth.c lxc/veth.h

LXC_CONTROLLER_SOURCES =					\
		lxc/lxc_conf.c lxc/lxc_conf.h			\
		lxc/lxc_container.c lxc/lxc_container.h		\
		lxc/lxc_controller.c				\
		lxc/veth.c lxc/veth.h

SECURITY_DRIVER_APPARMOR_HELPER_SOURCES =			\
		security/virt-aa-helper.c

PHYP_DRIVER_SOURCES =						\
		phyp/phyp_driver.c phyp/phyp_driver.h

OPENVZ_DRIVER_SOURCES =						\
		openvz/openvz_conf.c openvz/openvz_conf.h	\
		openvz/openvz_driver.c openvz/openvz_driver.h

VBOX_DRIVER_SOURCES =						\
        vbox/vbox_XPCOMCGlue.c vbox/vbox_XPCOMCGlue.h		\
        vbox/vbox_driver.c vbox/vbox_driver.h			\
        vbox/vbox_V2_2.c vbox/vbox_CAPI_v2_2.h			\
        vbox/vbox_V3_0.c vbox/vbox_CAPI_v3_0.h			\
        vbox/vbox_V3_1.c vbox/vbox_CAPI_v3_1.h			\
        vbox/vbox_V3_2.c vbox/vbox_CAPI_v3_2.h

VBOX_DRIVER_EXTRA_DIST = vbox/vbox_tmpl.c vbox/README

QEMU_DRIVER_SOURCES =						\
		qemu/qemu_conf.c qemu/qemu_conf.h		\
		qemu/qemu_monitor.c qemu/qemu_monitor.h		\
		qemu/qemu_monitor_text.c			\
		qemu/qemu_monitor_text.h			\
		qemu/qemu_monitor_json.c			\
		qemu/qemu_monitor_json.h			\
		qemu/qemu_driver.c qemu/qemu_driver.h		\
		qemu/qemu_bridge_filter.c			\
		qemu/qemu_bridge_filter.h			\
		qemu/qemu_security_stacked.h			\
		qemu/qemu_security_stacked.c			\
		qemu/qemu_security_dac.h			\
		qemu/qemu_security_dac.c

XENAPI_DRIVER_SOURCES =								\
		xenapi/xenapi_driver.c xenapi/xenapi_driver.h	\
		xenapi/xenapi_driver_private.h					\
		xenapi/xenapi_utils.c xenapi/xenapi_utils.h

UML_DRIVER_SOURCES =						\
		uml/uml_conf.c uml/uml_conf.h			\
		uml/uml_driver.c uml/uml_driver.h

ONE_DRIVER_SOURCES =						\
		./opennebula/one_conf.c				\
		./opennebula/one_conf.h				\
		./opennebula/one_driver.c			\
		./opennebula/one_driver.h			\
		./opennebula/one_client.c			\
		./opennebula/one_client.h

ESX_DRIVER_SOURCES =						\
		esx/esx_private.h						\
		esx/esx_driver.c esx/esx_driver.h		\
		esx/esx_interface_driver.c esx/esx_interface_driver.h		\
		esx/esx_network_driver.c esx/esx_network_driver.h		\
		esx/esx_storage_driver.c esx/esx_storage_driver.h		\
		esx/esx_device_monitor.c esx/esx_device_monitor.h		\
		esx/esx_secret_driver.c esx/esx_secret_driver.h		\
		esx/esx_nwfilter_driver.c esx/esx_nwfilter_driver.h		\
		esx/esx_util.c esx/esx_util.h			\
		esx/esx_vi.c esx/esx_vi.h			\
		esx/esx_vi_methods.c esx/esx_vi_methods.h	\
		esx/esx_vi_types.c esx/esx_vi_types.h		\
		esx/esx_vmx.c esx/esx_vmx.h

ESX_DRIVER_GENERATED =							\
		esx/esx_vi_methods.generated.c				\
		esx/esx_vi_methods.generated.h				\
		esx/esx_vi_types.generated.c				\
		esx/esx_vi_types.generated.h				\
		esx/esx_vi_types.generated.typedef			\
		esx/esx_vi_types.generated.typeenum			\
		esx/esx_vi_types.generated.typetostring			\
		esx/esx_vi_types.generated.typefromstring

ESX_DRIVER_EXTRA_DIST =						\
		esx/README						\
		esx/esx_vi_generator.input				\
		esx/esx_vi_generator.py					\
		$(ESX_DRIVER_GENERATED)

NETWORK_DRIVER_SOURCES =					\
		network/bridge_driver.h network/bridge_driver.c

INTERFACE_DRIVER_SOURCES =					\
		interface/netcf_driver.h interface/netcf_driver.c

SECRET_DRIVER_SOURCES =						\
		secret/secret_driver.h secret/secret_driver.c

# Storage backend specific impls
STORAGE_DRIVER_SOURCES =					\
		storage/storage_driver.h storage/storage_driver.c		\
		storage/storage_backend.h storage/storage_backend.c

STORAGE_DRIVER_FS_SOURCES =					\
		storage/storage_backend_fs.h storage/storage_backend_fs.c

STORAGE_DRIVER_LVM_SOURCES =					\
		storage/storage_backend_logical.h			\
		storage/storage_backend_logical.c

STORAGE_DRIVER_ISCSI_SOURCES =					\
		storage/storage_backend_iscsi.h storage/storage_backend_iscsi.c

STORAGE_DRIVER_SCSI_SOURCES =					\
		storage/storage_backend_scsi.h storage/storage_backend_scsi.c

STORAGE_DRIVER_MPATH_SOURCES =					\
		storage/storage_backend_mpath.h storage/storage_backend_mpath.c

STORAGE_DRIVER_DISK_SOURCES =					\
		storage/storage_backend_disk.h storage/storage_backend_disk.c

STORAGE_HELPER_DISK_SOURCES =					\
		storage/parthelper.c

# Network filters
NWFILTER_DRIVER_SOURCES =					\
		nwfilter/nwfilter_driver.h nwfilter/nwfilter_driver.c	\
		nwfilter/nwfilter_gentech_driver.c			\
		nwfilter/nwfilter_gentech_driver.h			\
		nwfilter/nwfilter_ebiptables_driver.c			\
		nwfilter/nwfilter_ebiptables_driver.h			\
		nwfilter/nwfilter_learnipaddr.c				\
		nwfilter/nwfilter_learnipaddr.h


# Security framework and drivers for various models
SECURITY_DRIVER_SOURCES =					\
		security/security_driver.h security/security_driver.c

SECURITY_DRIVER_SELINUX_SOURCES =				\
		security/security_selinux.h security/security_selinux.c

SECURITY_DRIVER_APPARMOR_SOURCES =				\
		security/security_apparmor.h security/security_apparmor.c


NODE_DEVICE_DRIVER_SOURCES =					\
		node_device/node_device_driver.c \
		node_device/node_device_driver.h \
		node_device/node_device_linux_sysfs.c

NODE_DEVICE_DRIVER_HAL_SOURCES =				\
		node_device/node_device_hal.c			\
		node_device/node_device_hal.h

NODE_DEVICE_DRIVER_UDEV_SOURCES =				\
		node_device/node_device_udev.c			\
		node_device/node_device_udev.h

CPU_SOURCES =							\
		cpu/cpu.h cpu/cpu.c				\
		cpu/cpu_generic.h cpu/cpu_generic.c		\
		cpu/cpu_x86.h cpu/cpu_x86.c cpu/cpu_x86_data.h	\
		cpu/cpu_map.h cpu/cpu_map.c

pkgdata_DATA =	cpu/cpu_map.xml

EXTRA_DIST +=	$(pkgdata_DATA)

#########################
#
# Build up list of libvirt.la source files based on configure conditions
#
# First deal with sources usable in non-daemon context

noinst_LTLIBRARIES = libvirt_util.la
libvirt_la_LIBADD = $(libvirt_la_BUILT_LIBADD)
libvirt_la_BUILT_LIBADD = libvirt_util.la
libvirt_util_la_SOURCES =					\
		$(UTIL_SOURCES)
libvirt_util_la_CFLAGS = $(CAPNG_CFLAGS) $(YAJL_CFLAGS) $(LIBNL_CFLAGS) \
		$(AM_CFLAGS)
libvirt_util_la_LIBADD = $(CAPNG_LIBS) $(YAJL_LIBS) $(LIBNL_LIBS) $(LIB_PTHREAD)


noinst_LTLIBRARIES += libvirt_conf.la
libvirt_la_BUILT_LIBADD += libvirt_conf.la
libvirt_conf_la_SOURCES = $(CONF_SOURCES)
libvirt_conf_la_CFLAGS = $(AM_CFLAGS)
libvirt_conf_la_LDFLAGS = $(AM_LDFLAGS)

noinst_LTLIBRARIES += libvirt_cpu.la
libvirt_la_BUILT_LIBADD += libvirt_cpu.la
libvirt_cpu_la_CFLAGS = \
		-I@top_srcdir@/src/conf $(AM_CFLAGS)
libvirt_cpu_la_SOURCES = $(CPU_SOURCES)


noinst_LTLIBRARIES += libvirt_driver.la
libvirt_la_BUILT_LIBADD += libvirt_driver.la
libvirt_driver_la_SOURCES = $(DRIVER_SOURCES)

libvirt_driver_la_CFLAGS = $(NUMACTL_CFLAGS) $(GNUTLS_CFLAGS) \
		-I@top_srcdir@/src/conf $(AM_CFLAGS)
libvirt_driver_la_LIBADD = $(NUMACTL_LIBS) $(GNUTLS_LIBS)

USED_SYM_FILES = libvirt_private.syms

if WITH_TEST
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_test.la
else
noinst_LTLIBRARIES += libvirt_driver_test.la
libvirt_la_BUILT_LIBADD += libvirt_driver_test.la
endif
libvirt_driver_test_la_CFLAGS = \
		-I@top_srcdir@/src/conf $(AM_CFLAGS)
if WITH_DRIVER_MODULES
libvirt_driver_test_la_LDFLAGS = -module -avoid-version $(AM_LDFLAGS)
endif
libvirt_driver_test_la_SOURCES = $(TEST_DRIVER_SOURCES)
endif

if WITH_REMOTE
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_remote.la
else
noinst_LTLIBRARIES += libvirt_driver_remote.la
libvirt_la_BUILT_LIBADD += libvirt_driver_remote.la
endif
libvirt_driver_remote_la_CFLAGS =				\
		$(GNUTLS_CFLAGS)				\
		$(SASL_CFLAGS)					\
		-I@top_srcdir@/src/conf				\
		$(AM_CFLAGS)
libvirt_driver_remote_la_LDFLAGS = $(AM_LDFLAGS)
libvirt_driver_remote_la_LIBADD = $(GNUTLS_LIBS) $(SASL_LIBS)
if WITH_DRIVER_MODULES
libvirt_driver_remote_la_LDFLAGS += -module -avoid-version
endif
libvirt_driver_remote_la_SOURCES = $(REMOTE_DRIVER_SOURCES)

if HAVE_RPCGEN
#
# Maintainer-only target for re-generating the derived .c/.h source
# files, which are actually derived from the .x file.
#
# For committing protocol changes to GIT, the GLIBC rpcgen *must*
# be used.
#
# Support for non-GLIB rpcgen is here as a convenience for
# non-Linux people needing to test changes during dev.
#
rpcgen-normal:
	rm -f rp.c-t rp.h-t rp.c-t1 rp.c-t2 rp.h-t1
	$(RPCGEN) -h -o rp.h-t $(srcdir)/remote/remote_protocol.x
	$(RPCGEN) -c -o rp.c-t $(srcdir)/remote/remote_protocol.x
if HAVE_GLIBC_RPCGEN
	perl -w $(srcdir)/remote/rpcgen_fix.pl rp.h-t > rp.h-t1
	perl -w $(srcdir)/remote/rpcgen_fix.pl rp.c-t > rp.c-t1
	(echo '#include <config.h>'; cat rp.c-t1) > rp.c-t2
	chmod 0444 rp.c-t2 rp.h-t1
	mv -f rp.h-t1 $(srcdir)/remote/remote_protocol.h
	mv -f rp.c-t2 $(srcdir)/remote/remote_protocol.c
	rm -f rp.c-t rp.h-t rp.c-t1
else
	chmod 0444 rp.c-t rp.h-t
	mv -f rp.h-t $(srcdir)/remote/remote_protocol.h
	mv -f rp.c-t $(srcdir)/remote/remote_protocol.c
endif

rpcgen-qemu:
	rm -f rp_qemu.c-t rp_qemu.h-t rp_qemu.c-t1 rp_qemu.c-t2 rp_qemu.h-t1
	$(RPCGEN) -h -o rp_qemu.h-t $(srcdir)/remote/qemu_protocol.x
	$(RPCGEN) -c -o rp_qemu.c-t $(srcdir)/remote/qemu_protocol.x
if HAVE_GLIBC_RPCGEN
	perl -w $(srcdir)/remote/rpcgen_fix.pl rp_qemu.h-t > rp_qemu.h-t1
	perl -w $(srcdir)/remote/rpcgen_fix.pl rp_qemu.c-t > rp_qemu.c-t1
	(echo '#include <config.h>'; cat rp_qemu.c-t1) > rp_qemu.c-t2
	chmod 0444 rp_qemu.c-t2 rp_qemu.h-t1
	mv -f rp_qemu.h-t1 $(srcdir)/remote/qemu_protocol.h
	mv -f rp_qemu.c-t2 $(srcdir)/remote/qemu_protocol.c
	rm -f rp_qemu.c-t rp_qemu.h-t rp_qemu.c-t1
else
	chmod 0444 rp_qemu.c-t rp_qemu.h-t
	mv -f rp_qemu.h-t $(srcdir)/remote/qemu_protocol.h
	mv -f rp_qemu.c-t $(srcdir)/remote/qemu_protocol.c
endif

#
# Maintainer-only target for re-generating the derived .c/.h source
# files, which are actually derived from the .x file.
#
# For committing protocol changes to GIT, the GLIBC rpcgen *must*
# be used.
#
# Support for non-GLIB rpcgen is here as a convenience for
# non-Linux people needing to test changes during dev.
#
rpcgen: rpcgen-normal rpcgen-qemu

endif

remote/remote_protocol.c: remote/remote_protocol.h
endif

if WITH_XEN
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_xen.la
else
noinst_LTLIBRARIES += libvirt_driver_xen.la
libvirt_la_BUILT_LIBADD += libvirt_driver_xen.la
endif
libvirt_driver_xen_la_CFLAGS =					\
		$(XEN_CFLAGS)					\
		-I@top_srcdir@/src/conf				\
		$(AM_CFLAGS)
libvirt_driver_xen_la_LDFLAGS = $(AM_LDFLAGS)
libvirt_driver_xen_la_LIBADD = $(XEN_LIBS)
if WITH_DRIVER_MODULES
libvirt_driver_xen_la_LDFLAGS += -module -avoid-version
endif
libvirt_driver_xen_la_SOURCES = $(XEN_DRIVER_SOURCES)
endif

if WITH_PHYP
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_phyp.la
else
noinst_LTLIBRARIES += libvirt_driver_phyp.la
libvirt_la_BUILT_LIBADD += libvirt_driver_phyp.la
endif
libvirt_driver_phyp_la_LIBADD = $(LIBSSH2_LIBS)
libvirt_driver_phyp_la_CFLAGS = $(LIBSSH2_CFLAGS) \
		-I@top_srcdir@/src/conf $(AM_CFLAGS)
libvirt_driver_phyp_la_SOURCES = $(PHYP_DRIVER_SOURCES)
endif

if WITH_OPENVZ
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_openvz.la
else
noinst_LTLIBRARIES += libvirt_driver_openvz.la
libvirt_la_BUILT_LIBADD += libvirt_driver_openvz.la
endif
libvirt_driver_openvz_la_CFLAGS = \
		-I@top_srcdir@/src/conf $(AM_CFLAGS)
if WITH_DRIVER_MODULES
libvirt_driver_openvz_la_LDFLAGS = -module -avoid-version $(AM_LDFLAGS)
endif
libvirt_driver_openvz_la_SOURCES = $(OPENVZ_DRIVER_SOURCES)
endif

if WITH_VBOX
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_vbox.la
else
noinst_LTLIBRARIES += libvirt_driver_vbox.la
libvirt_la_BUILT_LIBADD += libvirt_driver_vbox.la
endif
libvirt_driver_vbox_la_CFLAGS = \
		-I@top_srcdir@/src/conf $(AM_CFLAGS)
if WITH_DRIVER_MODULES
libvirt_driver_vbox_la_LDFLAGS = -module -avoid-version $(AM_LDFLAGS)
endif
libvirt_driver_vbox_la_LIBADD = $(DLOPEN_LIBS)
libvirt_driver_vbox_la_SOURCES = $(VBOX_DRIVER_SOURCES)
endif

if WITH_XENAPI
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_xenapi.la
else
noinst_LTLIBRARIES += libvirt_driver_xenapi.la
libvirt_la_BUILT_LIBADD += libvirt_driver_xenapi.la
endif
libvirt_driver_xenapi_la_CFLAGS = $(LIBXENSERVER_CFLAGS) $(LIBCURL_CFLAGS) \
		-I@top_srcdir@/src/conf $(AM_CFLAGS)
libvirt_driver_xenapi_la_LDFLAGS = $(AM_LDFLAGS)
libvirt_driver_xenapi_la_LIBADD = $(LIBXENSERVER_LIBS) $(LIBCURL_LIBS)
if WITH_DRIVER_MODULES
libvirt_driver_xenapi_la_LDFLAGS += -module -avoid-version
endif
libvirt_driver_xenapi_la_SOURCES = $(XENAPI_DRIVER_SOURCES)
endif

if WITH_QEMU
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_qemu.la
else
noinst_LTLIBRARIES += libvirt_driver_qemu.la
# Stateful, so linked to daemon instead
#libvirt_la_BUILT_LIBADD += libvirt_driver_qemu.la
endif
libvirt_driver_qemu_la_CFLAGS = $(NUMACTL_CFLAGS) \
		-I@top_srcdir@/src/conf $(AM_CFLAGS)
libvirt_driver_qemu_la_LDFLAGS = $(AM_LDFLAGS)
libvirt_driver_qemu_la_LIBADD = $(NUMACTL_LIBS)
if WITH_DRIVER_MODULES
libvirt_driver_qemu_la_LDFLAGS += -module -avoid-version
endif
libvirt_driver_qemu_la_SOURCES = $(QEMU_DRIVER_SOURCES)

conf_DATA += qemu/qemu.conf

augeas_DATA += qemu/libvirtd_qemu.aug
augeastest_DATA += qemu/test_libvirtd_qemu.aug

endif
EXTRA_DIST += qemu/qemu.conf qemu/libvirtd_qemu.aug \
		qemu/test_libvirtd_qemu.aug qemu/THREADS.txt


if WITH_LXC
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_lxc.la
else
noinst_LTLIBRARIES += libvirt_driver_lxc.la
# Stateful, so linked to daemon instead
#libvirt_la_BUILT_LIBADD += libvirt_driver_lxc.la
endif
libvirt_driver_lxc_la_CFLAGS = \
		-I@top_srcdir@/src/conf $(AM_CFLAGS)
if WITH_DRIVER_MODULES
libvirt_driver_lxc_la_LDFLAGS = -module -avoid-version $(AM_LDFLAGS)
endif
libvirt_driver_lxc_la_SOURCES = $(LXC_DRIVER_SOURCES)

conf_DATA += lxc/lxc.conf

augeas_DATA += lxc/libvirtd_lxc.aug
augeastest_DATA += lxc/test_libvirtd_lxc.aug

endif
EXTRA_DIST += lxc/lxc.conf lxc/libvirtd_lxc.aug lxc/test_libvirtd_lxc.aug

if WITH_UML
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_uml.la
else
noinst_LTLIBRARIES += libvirt_driver_uml.la
# Stateful, so linked to daemon instead
#libvirt_la_BUILT_LIBADD += libvirt_driver_uml.la
endif
libvirt_driver_uml_la_CFLAGS = $(NUMACTL_CFLAGS) \
		-I@top_srcdir@/src/conf $(AM_CFLAGS)
libvirt_driver_uml_la_LDFLAGS = $(AM_LDFLAGS)
libvirt_driver_uml_la_LIBADD = $(NUMACTL_LIBS)
if WITH_DRIVER_MODULES
libvirt_driver_uml_la_LDFLAGS += -module -avoid-version
endif
libvirt_driver_uml_la_SOURCES = $(UML_DRIVER_SOURCES)
endif

if WITH_ONE
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_one.la
else
noinst_LTLIBRARIES += libvirt_driver_one.la
# Stateful, so linked to daemon instead
#libvirt_la_BUILT_LIBADD  += libvirt_driver_one.la
endif
libvirt_driver_one_la_CFLAGS = $(XMLRPC_CFLAGS) \
		-I@top_srcdir@/src/conf $(AM_CFLAGS)
libvirt_driver_one_la_LDFLAGS = $(AM_LDFLAGS)
libvirt_driver_one_la_LIBADD = $(XMLRPC_LIBS)
#libvirt_driver_one_la_CFLAGS  = "-DWITH_ONE"
if WITH_DRIVER_MODULES
libvirt_driver_one_la_LDFLAGS += -module -avoid-version
endif
libvirt_driver_one_la_SOURCES = $(ONE_DRIVER_SOURCES)
endif


BUILT_SOURCES += $(ESX_DRIVER_GENERATED)

$(ESX_DRIVER_GENERATED): $(srcdir)/esx/esx_vi_generator.input $(srcdir)/esx/esx_vi_generator.py
	-srcdir=$(srcdir) $(srcdir)/esx/esx_vi_generator.py

if WITH_ESX
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_esx.la
else
noinst_LTLIBRARIES += libvirt_driver_esx.la
libvirt_la_BUILT_LIBADD += libvirt_driver_esx.la
endif
libvirt_driver_esx_la_CFLAGS = $(LIBCURL_CFLAGS) \
		-I@top_srcdir@/src/conf $(AM_CFLAGS)
libvirt_driver_esx_la_LDFLAGS = $(AM_LDFLAGS)
libvirt_driver_esx_la_LIBADD = $(LIBCURL_LIBS)
if WITH_DRIVER_MODULES
libvirt_driver_esx_la_LDFLAGS += -module -avoid-version
endif
libvirt_driver_esx_la_SOURCES = $(ESX_DRIVER_SOURCES)
libvirt_driver_esx_la_DEPENDENCIES = $(ESX_DRIVER_GENERATED)
endif

if WITH_NETWORK
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_network.la
else
noinst_LTLIBRARIES += libvirt_driver_network.la
# Stateful, so linked to daemon instead
#libvirt_la_BUILT_LIBADD += libvirt_driver_network.la
endif
libvirt_driver_network_la_CFLAGS = \
		-I@top_srcdir@/src/conf $(AM_CFLAGS)
if WITH_DRIVER_MODULES
libvirt_driver_network_la_LDFLAGS = -module -avoid-version $(AM_LDFLAGS)
endif
libvirt_driver_network_la_SOURCES = $(NETWORK_DRIVER_SOURCES)
endif
EXTRA_DIST += network/default.xml




if WITH_NETCF
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_interface.la
else
noinst_LTLIBRARIES += libvirt_driver_interface.la
libvirt_la_BUILT_LIBADD += libvirt_driver_interface.la
endif
libvirt_driver_interface_la_CFLAGS = $(NETCF_CFLAGS) \
		-I@top_srcdir@/src/conf $(AM_CFLAGS)
libvirt_driver_interface_la_LDFLAGS = $(AM_LDFLAGS)
libvirt_driver_interface_la_LIBADD = $(NETCF_LIBS)
if WITH_DRIVER_MODULES
libvirt_driver_interface_la_LDFLAGS += -module -avoid-version
endif
libvirt_driver_interface_la_SOURCES = $(INTERFACE_DRIVER_SOURCES)
endif

if WITH_SECRETS
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_secret.la
else
noinst_LTLIBRARIES += libvirt_driver_secret.la
# Stateful, so linked to daemon instead
#libvirt_la_BUILT_LIBADD += libvirt_driver_secret.la
endif
libvirt_driver_secret_la_CFLAGS = \
		-I@top_srcdir@/src/conf $(AM_CFLAGS)
if WITH_DRIVER_MODULES
libvirt_driver_secret_la_LDFLAGS = -module -avoid-version $(AM_LDFLAGS)
libvirt_driver_secret_la_LIBADD = ../gnulib/lib/libgnu.la
endif
libvirt_driver_secret_la_SOURCES = $(SECRET_DRIVER_SOURCES)
endif

# Needed to keep automake quiet about conditionals
libvirt_driver_storage_la_SOURCES =
libvirt_driver_storage_la_CFLAGS = \
		-I@top_srcdir@/src/conf $(AM_CFLAGS)
libvirt_driver_storage_la_LDFLAGS = $(AM_LDFLAGS)
libvirt_driver_storage_la_LIBADD =
if WITH_STORAGE_DIR
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_storage.la
else
noinst_LTLIBRARIES += libvirt_driver_storage.la
# Stateful, so linked to daemon instead
#libvirt_la_BUILT_LIBADD += libvirt_driver_storage.la
endif
if WITH_DRIVER_MODULES
libvirt_driver_storage_la_LDFLAGS += -module -avoid-version
endif
libvirt_driver_storage_la_SOURCES += $(STORAGE_DRIVER_SOURCES)
libvirt_driver_storage_la_SOURCES += $(STORAGE_DRIVER_FS_SOURCES)
endif

if WITH_STORAGE_LVM
libvirt_driver_storage_la_SOURCES += $(STORAGE_DRIVER_LVM_SOURCES)
endif

if WITH_STORAGE_ISCSI
libvirt_driver_storage_la_SOURCES += $(STORAGE_DRIVER_ISCSI_SOURCES)
endif

if WITH_STORAGE_SCSI
libvirt_driver_storage_la_SOURCES += $(STORAGE_DRIVER_SCSI_SOURCES)
endif

if WITH_STORAGE_MPATH
libvirt_driver_storage_la_SOURCES += $(STORAGE_DRIVER_MPATH_SOURCES)
libvirt_driver_storage_la_CFLAGS += $(DEVMAPPER_CFLAGS)
libvirt_driver_storage_la_LIBADD += $(DEVMAPPER_LIBS)
endif

if WITH_STORAGE_DISK
libvirt_driver_storage_la_SOURCES += $(STORAGE_DRIVER_DISK_SOURCES)
endif

if WITH_NODE_DEVICES
# Needed to keep automake quiet about conditionals
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_nodedev.la
else
noinst_LTLIBRARIES += libvirt_driver_nodedev.la
# Stateful, so linked to daemon instead
#libvirt_la_BUILT_LIBADD += libvirt_driver_nodedev.la
endif
libvirt_driver_nodedev_la_SOURCES = $(NODE_DEVICE_DRIVER_SOURCES)

libvirt_driver_nodedev_la_CFLAGS = \
		-I@top_srcdir@/src/conf $(AM_CFLAGS)
libvirt_driver_nodedev_la_LDFLAGS = $(AM_LDFLAGS)
libvirt_driver_nodedev_la_LIBADD =
if HAVE_HAL
libvirt_driver_nodedev_la_SOURCES += $(NODE_DEVICE_DRIVER_HAL_SOURCES)
libvirt_driver_nodedev_la_CFLAGS += $(HAL_CFLAGS)
libvirt_driver_nodedev_la_LIBADD += $(HAL_LIBS)
endif
if HAVE_UDEV
libvirt_driver_nodedev_la_SOURCES += $(NODE_DEVICE_DRIVER_UDEV_SOURCES)
libvirt_driver_nodedev_la_CFLAGS += $(UDEV_CFLAGS) $(PCIACCESS_CFLAGS)
libvirt_driver_nodedev_la_LIBADD += $(UDEV_LIBS) $(PCIACCESS_LIBS)
endif

if WITH_DRIVER_MODULES
libvirt_driver_nodedev_la_LDFLAGS += -module -avoid-version
endif
endif


if WITH_NWFILTER
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_nwfilter.la
else
libvirt_la_BUILT_LIBADD += libvirt_driver_nwfilter.la
noinst_LTLIBRARIES += libvirt_driver_nwfilter.la
endif
libvirt_driver_nwfilter_la_CFLAGS = $(LIBPCAP_CFLAGS) \
		-I@top_srcdir@/src/conf $(AM_CFLAGS)
libvirt_driver_nwfilter_la_LDFLAGS = $(LD_AMFLAGS)
libvirt_driver_nwfilter_la_LIBADD = $(LIBPCAP_LIBS)
if WITH_DRIVER_MODULES
libvirt_driver_nwfilter_la_LDFLAGS += -module -avoid-version
libvirt_driver_nwfilter_la_LIBADD += ../gnulib/lib/libgnu.la
endif
libvirt_driver_nwfilter_la_SOURCES = $(NWFILTER_DRIVER_SOURCES)
endif


libvirt_driver_security_la_SOURCES = $(SECURITY_DRIVER_SOURCES)
noinst_LTLIBRARIES += libvirt_driver_security.la
libvirt_la_BUILT_LIBADD += libvirt_driver_security.la
libvirt_driver_security_la_CFLAGS = \
		-I@top_srcdir@/src/conf $(AM_CFLAGS)
libvirt_driver_security_la_LDFLAGS = $(AM_LDFLAGS)
libvirt_driver_security_la_LIBADD =
if WITH_SECDRIVER_SELINUX
libvirt_driver_security_la_SOURCES += $(SECURITY_DRIVER_SELINUX_SOURCES)
libvirt_driver_security_la_CFLAGS += $(SELINUX_CFLAGS)
libvirt_driver_security_la_LIBADD += $(SELINUX_LIBS)
endif
if WITH_SECDRIVER_APPARMOR
libvirt_driver_security_la_SOURCES += $(SECURITY_DRIVER_APPARMOR_SOURCES)
libvirt_driver_security_la_CFLAGS += $(APPARMOR_CFLAGS)
libvirt_driver_security_la_LIBADD += $(APPARMOR_LIBS)
endif

# Add all conditional sources just in case...
EXTRA_DIST +=							\
		$(TEST_DRIVER_SOURCES)				\
		$(REMOTE_DRIVER_SOURCES)			\
		$(XEN_DRIVER_SOURCES)				\
		$(QEMU_DRIVER_SOURCES)				\
		$(LXC_DRIVER_SOURCES)				\
		$(UML_DRIVER_SOURCES)				\
		$(ONE_DRIVER_SOURCES)				\
		$(OPENVZ_DRIVER_SOURCES)			\
		$(PHYP_DRIVER_SOURCES)				\
		$(VBOX_DRIVER_SOURCES)				\
		$(XENAPI_DRIVER_SOURCES)			\
		$(ESX_DRIVER_SOURCES)				\
		$(ESX_DRIVER_EXTRA_DIST)			\
		$(NETWORK_DRIVER_SOURCES)			\
		$(INTERFACE_DRIVER_SOURCES)			\
		$(STORAGE_DRIVER_SOURCES)			\
		$(STORAGE_DRIVER_FS_SOURCES)			\
		$(STORAGE_DRIVER_LVM_SOURCES)			\
		$(STORAGE_DRIVER_ISCSI_SOURCES)			\
		$(STORAGE_DRIVER_SCSI_SOURCES)			\
		$(STORAGE_DRIVER_MPATH_SOURCES)			\
		$(STORAGE_DRIVER_DISK_SOURCES)			\
		$(NODE_DEVICE_DRIVER_SOURCES)			\
		$(NODE_DEVICE_DRIVER_HAL_SOURCES)		\
		$(NODE_DEVICE_DRIVER_UDEV_SOURCES)		\
		$(NWFILTER_DRIVER_SOURCES)			\
		$(SECURITY_DRIVER_SELINUX_SOURCES)		\
		$(SECURITY_DRIVER_APPARMOR_SOURCES)		\
		$(SECRET_DRIVER_SOURCES)			\
		$(VBOX_DRIVER_EXTRA_DIST)

check-local: augeas-check

.PHONY: augeas-check
augeas-check:
if WITH_QEMU
	$(AM_V_GEN)if test -x '$(AUGPARSE)'; then \
	    '$(AUGPARSE)' -I $(srcdir)/qemu \
	    $(srcdir)/qemu/test_libvirtd_qemu.aug; \
	fi
endif
if WITH_LXC
	$(AM_V_GEN)if test -x '$(AUGPARSE)'; then \
	    '$(AUGPARSE)' -I $(srcdir)/lxc \
	    $(srcdir)/lxc/test_libvirtd_lxc.aug; \
	fi
endif

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

if WITH_DRIVER_MODULES
USED_SYM_FILES += libvirt_driver_modules.syms
endif

if WITH_BRIDGE
USED_SYM_FILES += libvirt_bridge.syms
endif

if WITH_LINUX
USED_SYM_FILES += libvirt_linux.syms
endif

if WITH_MACVTAP
USED_SYM_FILES += libvirt_macvtap.syms
endif

if WITH_LIBVIRTD
USED_SYM_FILES += libvirt_daemon.syms
endif

if WITH_NWFILTER
USED_SYM_FILES += libvirt_nwfilter.syms
endif

EXTRA_DIST += \
  libvirt_public.syms		\
  libvirt_private.syms		\
  libvirt_driver_modules.syms	\
  libvirt_bridge.syms		\
  libvirt_linux.syms		\
  libvirt_macvtap.syms		\
  libvirt_daemon.syms		\
  libvirt_nwfilter.syms

BUILT_SOURCES += libvirt.syms libvirt.def

libvirt.syms: libvirt_public.syms $(USED_SYM_FILES)
	$(AM_V_GEN)rm -f $@-tmp $@ ; \
	printf '# WARNING: generated from the following:\n# $^\n\n' >$@-tmp && \
	cat $(srcdir)/libvirt_public.syms >>$@-tmp && \
	printf '\n\n# Private symbols\n\n' >>$@-tmp && \
	printf 'LIBVIRT_PRIVATE_$(VERSION) {\n\n'  >>$@-tmp && \
	printf 'global:\n\n' >>$@-tmp && \
	for file in $(USED_SYM_FILES); do \
	    cat $(srcdir)/$$file >>$@-tmp; \
	done && \
	printf '\n\nlocal:\n*;\n\n};' >>$@-tmp && \
	chmod a-w $@-tmp && \
	mv $@-tmp libvirt.syms

libvirt.def: libvirt.syms
	$(AM_V_GEN)rm -f -- $@-tmp $@ ; \
	printf 'EXPORTS\n' > $@-tmp && \
	sed -e '/^$$/d; /#/d; /:/d; /\}/d; /\*/d; /LIBVIRT_/d; s/[ \t]*\(.*\)\;/    \1/g' $^ >> $@-tmp && \
	chmod a-w $@-tmp && \
	mv $@-tmp libvirt.def

# Empty source list - it merely links a bunch of convenience libs together
libvirt_la_SOURCES =
libvirt_la_LDFLAGS = $(VERSION_SCRIPT_FLAGS)$(LIBVIRT_SYMBOL_FILE) \
                     -version-info $(LIBVIRT_VERSION_INFO) \
                    $(AM_LDFLAGS) \
		    $(CYGWIN_EXTRA_LDFLAGS) $(MINGW_EXTRA_LDFLAGS)
libvirt_la_BUILT_LIBADD += ../gnulib/lib/libgnu.la
libvirt_la_LIBADD += $(LIBXML_LIBS) \
		    $(DRIVER_MODULE_LIBS) \
		    $(CYGWIN_EXTRA_LIBADD)
libvirt_la_CFLAGS = -DIN_LIBVIRT $(AM_CFLAGS)
# Because we specify libvirt_la_DEPENDENCIES for $(LIBVIRT_SYMBOL_FILE), we
# lose automake's automatic dependencies on an appropriate subset of
# $(libvirt_la_LIBADD).  But we were careful to create
# $(libvirt_la_BUILT_LIBADD) as the subset that automake would have
# picked out for us.
libvirt_la_DEPENDENCIES = $(libvirt_la_BUILT_LIBADD) $(LIBVIRT_SYMBOL_FILE)

# Create an automake "convenience library" version of libvirt_la,
# just for testing, since the test harness requires access to internal
# bits and pieces that we don't want to make publicly accessible.
noinst_LTLIBRARIES += libvirt_test.la

# Remove version script from convenience library
test_LDFLAGS =						\
  $$(echo '$(libvirt_la_LDFLAGS)'			\
     |sed 's!$(VERSION_SCRIPT_FLAGS)$(LIBVIRT_SYMBOL_FILE)!!'	\
     |sed 's!-version-info $(LIBVIRT_VERSION_INFO)!!')

# Just like the above, but with a slightly different set of public symbols.
libvirt_test_la_SOURCES = $(libvirt_la_SOURCES)
libvirt_test_la_LIBADD = $(libvirt_la_LIBADD)
libvirt_test_la_LDFLAGS = $(test_LDFLAGS) $(AM_LDFLAGS)
libvirt_test_la_CFLAGS = $(AM_CFLAGS)

libvirt_qemu_la_SOURCES = libvirt-qemu.c
libvirt_qemu_la_LDFLAGS = $(VERSION_SCRIPT_FLAGS)$(LIBVIRT_QEMU_SYMBOL_FILE) \
                          -version-info $(LIBVIRT_VERSION_INFO) \
                          $(CYGWIN_EXTRA_LDFLAGS) $(MINGW_EXTRA_LDFLAGS) \
			  $(AM_LDFLAGS)
libvirt_qemu_la_CFLAGS = $(AM_CFLAGS)
libvirt_qemu_la_LIBADD = libvirt.la $(CYGWIN_EXTRA_LIBADD)
EXTRA_DIST += $(LIBVIRT_QEMU_SYMBOL_FILE)

libexec_PROGRAMS =

if WITH_STORAGE_DISK
if WITH_LIBVIRTD
libexec_PROGRAMS += libvirt_parthelper

libvirt_parthelper_SOURCES = $(STORAGE_HELPER_DISK_SOURCES)
libvirt_parthelper_LDFLAGS = $(WARN_LDFLAGS) $(AM_LDFLAGS)
libvirt_parthelper_LDADD =		\
		$(LIBPARTED_LIBS)	\
		$(DEVMAPPER_LIBS)	\
		libvirt_util.la		\
		../gnulib/lib/libgnu.la

libvirt_parthelper_CFLAGS = $(LIBPARTED_CFLAGS) $(AM_CFLAGS)
endif
endif
EXTRA_DIST += $(STORAGE_HELPER_DISK_SOURCES)


if WITH_LXC
if WITH_LIBVIRTD
libexec_PROGRAMS += libvirt_lxc

libvirt_lxc_SOURCES =						\
		$(LXC_CONTROLLER_SOURCES)			\
		$(UTIL_SOURCES)					\
		$(NODE_INFO_SOURCES)				\
		$(ENCRYPTION_CONF_SOURCES)			\
		$(DOMAIN_CONF_SOURCES)				\
		$(CPU_CONF_SOURCES)				\
		$(NWFILTER_PARAM_CONF_SOURCES)
libvirt_lxc_LDFLAGS = $(WARN_CFLAGS) $(AM_LDFLAGS)
libvirt_lxc_LDADD = $(CAPNG_LIBS) $(YAJL_LIBS) \
		$(LIBXML_LIBS) $(NUMACTL_LIBS) $(LIB_PTHREAD) \
		$(LIBNL_LIBS) ../gnulib/lib/libgnu.la
libvirt_lxc_CFLAGS =				\
		$(LIBPARTED_CFLAGS)		\
		$(NUMACTL_CFLAGS)		\
		$(CAPNG_CFLAGS)			\
		$(YAJL_CFLAGS)			\
		-I@top_srcdir@/src/conf		\
		$(AM_CFLAGS)
endif
endif
EXTRA_DIST += $(LXC_CONTROLLER_SOURCES)

if WITH_SECDRIVER_APPARMOR
if WITH_LIBVIRTD
libexec_PROGRAMS += virt-aa-helper

virt_aa_helper_SOURCES = $(SECURITY_DRIVER_APPARMOR_HELPER_SOURCES)

virt_aa_helper_LDFLAGS = $(WARN_LDFLAGS) $(AM_LDFLAGS)
virt_aa_helper_LDADD =						\
		$(LIBXML_LIBS)					\
		libvirt_conf.la					\
		libvirt_util.la					\
		../gnulib/lib/libgnu.la
virt_aa_helper_CFLAGS =						\
		-I@top_srcdir@/src/conf				\
		-I@top_srcdir@/src/security			\
		$(AM_CFLAGS)
endif
endif
EXTRA_DIST += $(SECURITY_DRIVER_APPARMOR_HELPER_SOURCES)

install-data-local:
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/cache/libvirt"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/libvirt/images"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/libvirt/boot"
if WITH_QEMU
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/libvirt/qemu"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/run/libvirt/qemu"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/cache/libvirt/qemu"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/log/libvirt/qemu"
endif
if WITH_LXC
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/libvirt/lxc"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/run/libvirt/lxc"
endif
if WITH_UML
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/libvirt/uml"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/run/libvirt/uml"
endif
if WITH_NETWORK
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/libvirt/network"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/libvirt/dnsmasq"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/run/libvirt/network"
	$(MKDIR_P) "$(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/autostart"
	$(INSTALL_DATA) $(srcdir)/network/default.xml \
	  $(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/default.xml
	test -z "$(UUID)" || \
	  sed -i -e "s,</name>,</name>\n  <uuid>$(UUID)</uuid>," \
	    $(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/default.xml
	test -e $(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/autostart/default.xml || \
           ln -s ../default.xml \
	    $(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/autostart/default.xml
endif

uninstall-local::
	rmdir "$(DESTDIR)$(localstatedir)/cache/libvirt" ||:
	rmdir "$(DESTDIR)$(localstatedir)/lib/libvirt/images" ||:
	rmdir "$(DESTDIR)$(localstatedir)/lib/libvirt/boot" ||:
if WITH_QEMU
	rmdir "$(DESTDIR)$(localstatedir)/lib/libvirt/qemu" ||:
	rmdir "$(DESTDIR)$(localstatedir)/run/libvirt/qemu" ||:
	rmdir "$(DESTDIR)$(localstatedir)/cache/libvirt/qemu" ||:
	rmdir "$(DESTDIR)$(localstatedir)/log/libvirt/qemu" ||:
endif
if WITH_LXC
	rmdir "$(DESTDIR)$(localstatedir)/lib/libvirt/lxc" ||:
	rmdir "$(DESTDIR)$(localstatedir)/run/libvirt/lxc" ||:
endif
if WITH_UML
	rmdir "$(DESTDIR)$(localstatedir)/lib/libvirt/uml" ||:
	rmdir "$(DESTDIR)$(localstatedir)/run/libvirt/uml" ||:
endif
if WITH_NETWORK
	rm -f $(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/autostart/default.xml
	rm -f $(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/default.xml
	rmdir "$(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/autostart" || :
	rmdir "$(DESTDIR)$(sysconfdir)/libvirt/qemu/networks" || :
	rmdir "$(DESTDIR)$(localstatedir)/lib/libvirt/network" ||:
	rmdir "$(DESTDIR)$(localstatedir)/run/libvirt/network" ||:
endif
	rmdir "$(DESTDIR)$(localstatedir)/lib/libvirt" ||:

CLEANFILES = *.gcov .libs/*.gcda .libs/*.gcno *.gcno *.gcda *.i *.s
DISTCLEANFILES = $(BUILT_SOURCES)
