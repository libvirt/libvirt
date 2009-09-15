## Process this file with automake to produce Makefile.in

INCLUDES = \
	   -I$(top_srcdir)/gnulib/lib -I../gnulib/lib \
	   -I../include \
	   -I@top_srcdir@/include \
	   -I@top_srcdir@/qemud \
	   $(LIBXML_CFLAGS) \
	   $(LIBSSH2_CFLAGS) \
	   $(XEN_CFLAGS) \
	   $(SELINUX_CFLAGS) \
	   $(DRIVER_MODULE_CFLAGS) \
	   -DLIBDIR=\""$(libdir)"\" \
	   -DBINDIR=\""$(libexecdir)"\" \
	   -DSBINDIR=\""$(sbindir)"\" \
	   -DSYSCONF_DIR="\"$(sysconfdir)\"" \
	   -DLOCALEBASEDIR=\""$(datadir)/locale"\" \
           -DLOCAL_STATE_DIR=\""$(localstatedir)"\" \
           -DGETTEXT_PACKAGE=\"$(PACKAGE)\" \
	   $(WARN_CFLAGS) \
	   $(LOCK_CHECKING_CFLAGS)

confdir = $(sysconfdir)/libvirt/
conf_DATA = qemu.conf

ICON_FILES = \
	libvirt_win_icon_16x16.ico \
	libvirt_win_icon_32x32.ico \
	libvirt_win_icon_48x48.ico \
	libvirt_win_icon_64x64.ico \
	virsh_win_icon.rc

EXTRA_DIST = $(conf_DATA) $(ICON_FILES)


lib_LTLIBRARIES = libvirt.la

moddir = $(libdir)/libvirt/drivers
mod_LTLIBRARIES =


# These files are not related to driver APIs. Simply generic
# helper APIs for various purposes
UTIL_SOURCES =							\
		bridge.c bridge.h				\
		buf.c buf.h					\
		conf.c conf.h					\
		event.c event.h					\
		hash.c hash.h					\
		iptables.c iptables.h				\
		logging.c logging.h				\
		memory.c memory.h				\
		pci.c pci.h					\
		hostusb.c hostusb.h				\
		qparams.c qparams.h				\
		storage_encryption_conf.h storage_encryption_conf.c	\
		threads.c threads.h				\
		threads-pthread.h				\
		threads-win32.h					\
		uuid.c uuid.h					\
		util.c util.h					\
		virterror.c virterror_internal.h		\
		xml.c xml.h

EXTRA_DIST += threads-pthread.c threads-win32.c

# Internal generic driver infrastructure
DRIVER_SOURCES =						\
		driver.c driver.h				\
		internal.h					\
		datatypes.c datatypes.h				\
		domain_event.c domain_event.h			\
		stats_linux.c stats_linux.h			\
		libvirt.c libvirt_internal.h


# Domain driver generic impl APIs
DOMAIN_CONF_SOURCES =						\
		capabilities.c capabilities.h			\
		domain_conf.c domain_conf.h			\
		nodeinfo.h nodeinfo.c

# Network driver generic impl APIs
NETWORK_CONF_SOURCES =						\
		network_conf.c network_conf.h

# Storage driver generic impl APIs
STORAGE_CONF_SOURCES =						\
		storage_conf.h storage_conf.c

# Interface driver generic impl APIs
INTERFACE_CONF_SOURCES =					\
		interface_conf.c interface_conf.h

# Secret driver generic impl APIs
SECRET_CONF_SOURCES =						\
		secret_conf.h secret_conf.c

# The remote RPC driver, covering domains, storage, networks, etc
REMOTE_DRIVER_SOURCES =						\
		gnutls_1_0_compat.h				\
		remote_internal.c remote_internal.h		\
		../qemud/remote_protocol.c			\
		../qemud/remote_protocol.h

# Mock driver, covering domains, storage, networks, etc
TEST_DRIVER_SOURCES =						\
		test.c test.h



# Now the Hypervisor specific drivers
XEN_DRIVER_SOURCES =						\
		proxy_internal.c proxy_internal.h		\
		sexpr.c sexpr.h					\
		xen_internal.c xen_internal.h			\
		xen_unified.c xen_unified.h			\
		xend_internal.c xend_internal.h			\
		xm_internal.c xm_internal.h			\
		xs_internal.c xs_internal.h
if WITH_XEN_INOTIFY
XEN_DRIVER_SOURCES += xen_inotify.c xen_inotify.h
endif

LXC_DRIVER_SOURCES =						\
		lxc_conf.c lxc_conf.h				\
		lxc_container.c lxc_container.h			\
		lxc_driver.c lxc_driver.h			\
		veth.c veth.h					\
		cgroup.c cgroup.h

LXC_CONTROLLER_SOURCES =					\
		lxc_conf.c lxc_conf.h				\
		lxc_container.c lxc_container.h			\
		lxc_controller.c				\
		veth.c veth.h                                   \
		cgroup.c cgroup.h

PHYP_DRIVER_SOURCES =						\
		phyp/phyp_driver.c phyp/phyp_driver.h

OPENVZ_DRIVER_SOURCES =						\
		openvz_conf.c openvz_conf.h			\
		openvz_driver.c openvz_driver.h

VBOX_DRIVER_SOURCES =						\
        vbox/vbox_XPCOMCGlue.c vbox/vbox_XPCOMCGlue.h		\
        vbox/vbox_driver.c vbox/vbox_driver.h			\
        vbox/vbox_V2_2.c vbox/vbox_CAPI_v2_2.h			\
        vbox/vbox_V3_0.c vbox/vbox_CAPI_v3_0.h

VBOX_DRIVER_EXTRA_DIST = vbox/vbox_tmpl.c vbox/README

QEMU_DRIVER_SOURCES =						\
		qemu_conf.c qemu_conf.h				\
		qemu_driver.c qemu_driver.h			\
		cgroup.c cgroup.h

UML_DRIVER_SOURCES =						\
		uml_conf.c uml_conf.h				\
		uml_driver.c uml_driver.h

ONE_DRIVER_SOURCES =						\
		./opennebula/one_conf.c				\
		./opennebula/one_conf.h				\
		./opennebula/one_driver.c			\
		./opennebula/one_driver.h			\
		./opennebula/one_client.c			\
		./opennebula/one_client.h

ESX_DRIVER_SOURCES =						\
		esx/esx_driver.c esx/esx_driver.h		\
		esx/esx_util.c esx/esx_util.h			\
		esx/esx_vi.c esx/esx_vi.h			\
		esx/esx_vi_methods.c esx/esx_vi_methods.h	\
		esx/esx_vi_types.c esx/esx_vi_types.h		\
		esx/esx_vmx.c esx/esx_vmx.h

NETWORK_DRIVER_SOURCES =					\
		network_driver.h network_driver.c

INTERFACE_DRIVER_SOURCES =					\
		interface_driver.h interface_driver.c

SECRET_DRIVER_SOURCES =						\
		secret_driver.h secret_driver.c

# Storage backend specific impls
STORAGE_DRIVER_SOURCES =					\
		storage_driver.h storage_driver.c		\
		storage_backend.h storage_backend.c

# Network driver generic impl APIs
NODE_DEVICE_CONF_SOURCES =					\
		node_device_conf.c node_device_conf.h

STORAGE_DRIVER_FS_SOURCES =					\
		storage_backend_fs.h storage_backend_fs.c

STORAGE_DRIVER_LVM_SOURCES =					\
		storage_backend_logical.h			\
		storage_backend_logical.c

STORAGE_DRIVER_ISCSI_SOURCES =					\
		storage_backend_iscsi.h storage_backend_iscsi.c

STORAGE_DRIVER_SCSI_SOURCES =					\
		storage_backend_scsi.h storage_backend_scsi.c

STORAGE_DRIVER_MPATH_SOURCES =					\
		storage_backend_mpath.h storage_backend_mpath.c

STORAGE_DRIVER_DISK_SOURCES =					\
		storage_backend_disk.h storage_backend_disk.c

STORAGE_HELPER_DISK_SOURCES =					\
		parthelper.c


# Security framework and drivers for various models
SECURITY_DRIVER_SOURCES =					\
		security.h security.c

SECURITY_DRIVER_SELINUX_SOURCES =				\
		security_selinux.h security_selinux.c


NODE_DEVICE_DRIVER_SOURCES =					\
		node_device.c node_device.h

NODE_DEVICE_DRIVER_HAL_SOURCES =				\
		node_device_hal.c				\
		node_device_hal.h				\
		node_device_hal_linux.c

NODE_DEVICE_DRIVER_DEVKIT_SOURCES =				\
		node_device_devkit.c


#########################
#
# Build up list of libvirt.la source files based on configure conditions
#
# First deal with sources usable in non-daemon context

noinst_LTLIBRARIES = libvirt_util.la
libvirt_la_LIBADD = libvirt_util.la
libvirt_util_la_SOURCES =					\
		$(UTIL_SOURCES)
libvirt_util_la_CFLAGS =  $(CAPNG_CFLAGS)
libvirt_util_la_LDFLAGS =  $(CAPNG_LIBS)

noinst_LTLIBRARIES += libvirt_driver.la
libvirt_la_LIBADD += libvirt_driver.la
libvirt_driver_la_SOURCES =					\
		$(DRIVER_SOURCES)				\
		$(DOMAIN_CONF_SOURCES)				\
		$(NETWORK_CONF_SOURCES)				\
		$(STORAGE_CONF_SOURCES)				\
		$(INTERFACE_CONF_SOURCES)			\
		$(NODE_DEVICE_CONF_SOURCES)			\
		$(SECRET_CONF_SOURCES)

libvirt_driver_la_CFLAGS = $(XEN_CFLAGS) $(NUMACTL_CFLAGS)
libvirt_driver_la_LDFLAGS = $(XEN_LIBS) $(NUMACTL_LIBS)

USED_SYM_FILES = libvirt_private.syms

if WITH_TEST
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_test.la
else
noinst_LTLIBRARIES += libvirt_driver_test.la
libvirt_la_LIBADD += libvirt_driver_test.la
endif
if WITH_DRIVER_MODULES
libvirt_driver_test_la_LDFLAGS = -module -avoid-version
endif
libvirt_driver_test_la_SOURCES = $(TEST_DRIVER_SOURCES)
endif

if WITH_REMOTE
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_remote.la
else
noinst_LTLIBRARIES += libvirt_driver_remote.la
libvirt_la_LIBADD += libvirt_driver_remote.la
endif
libvirt_driver_remote_la_CFLAGS =				\
		$(GNUTLS_CFLAGS)				\
		$(SASL_CFLAGS)
libvirt_driver_remote_la_LDFLAGS =				\
		$(GNUTLS_LIBS)					\
		$(SASL_LIBS)
if WITH_DRIVER_MODULES
libvirt_driver_remote_la_LDFLAGS += -module -avoid-version
endif
libvirt_driver_remote_la_SOURCES = $(REMOTE_DRIVER_SOURCES)
endif

if WITH_XEN
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_xen.la
else
noinst_LTLIBRARIES += libvirt_driver_xen.la
libvirt_la_LIBADD += libvirt_driver_xen.la
endif
libvirt_driver_xen_la_CFLAGS = $(XEN_CFLAGS)
libvirt_driver_xen_la_LDFLAGS = $(XEN_LIBS)
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
libvirt_la_LIBADD += libvirt_driver_phyp.la
endif
libvirt_driver_phyp_la_LDFLAGS = $(LIBSSH2_LIBS)
libvirt_driver_phyp_la_CFLAGS = $(LIBSSH2_CFLAGS)
libvirt_driver_phyp_la_SOURCES = $(PHYP_DRIVER_SOURCES)
endif

if WITH_OPENVZ
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_openvz.la
else
noinst_LTLIBRARIES += libvirt_driver_openvz.la
libvirt_la_LIBADD += libvirt_driver_openvz.la
endif
if WITH_DRIVER_MODULES
libvirt_driver_openvz_la_LDFLAGS = -module -avoid-version
endif
libvirt_driver_openvz_la_SOURCES = $(OPENVZ_DRIVER_SOURCES)
endif

if WITH_VBOX
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_vbox.la
else
noinst_LTLIBRARIES += libvirt_driver_vbox.la
libvirt_la_LIBADD += libvirt_driver_vbox.la
endif
if WITH_DRIVER_MODULES
libvirt_driver_vbox_la_LDFLAGS = -module -avoid-version
endif
libvirt_driver_vbox_la_SOURCES = $(VBOX_DRIVER_SOURCES)
endif

if WITH_QEMU
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_qemu.la
else
noinst_LTLIBRARIES += libvirt_driver_qemu.la
# Stateful, so linked to daemon instead
#libvirt_la_LIBADD += libvirt_driver_qemu.la
endif
libvirt_driver_qemu_la_CFLAGS = $(NUMACTL_CFLAGS)
libvirt_driver_qemu_la_LDFLAGS = $(NUMACTL_LIBS)
if WITH_DRIVER_MODULES
libvirt_driver_qemu_la_LDFLAGS += -module -avoid-version
endif
libvirt_driver_qemu_la_SOURCES = $(QEMU_DRIVER_SOURCES)
endif

if WITH_LXC
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_lxc.la
else
noinst_LTLIBRARIES += libvirt_driver_lxc.la
# Stateful, so linked to daemon instead
#libvirt_la_LIBADD += libvirt_driver_lxc.la
endif
if WITH_DRIVER_MODULES
libvirt_driver_lxc_la_LDFLAGS = -module -avoid-version
endif
libvirt_driver_lxc_la_SOURCES = $(LXC_DRIVER_SOURCES)
endif

if WITH_UML
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_uml.la
else
noinst_LTLIBRARIES += libvirt_driver_uml.la
# Stateful, so linked to daemon instead
#libvirt_la_LIBADD += libvirt_driver_uml.la
endif
libvirt_driver_uml_la_CFLAGS = $(NUMACTL_CFLAGS)
libvirt_driver_uml_la_LDFLAGS = $(NUMACTL_LIBS)
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
#libvirt_la_LIBADD  += libvirt_driver_one.la
endif
libvirt_driver_one_la_CFLAGS = $(XMLRPC_CFLAGS)
libvirt_driver_one_la_LDFLAGS = $(XMLRPC_LIBS)
#libvirt_driver_one_la_CFLAGS  = "-DWITH_ONE"
if WITH_DRIVER_MODULES
libvirt_driver_one_la_LDFLAGS += -module -avoid-version
endif
libvirt_driver_one_la_SOURCES = $(ONE_DRIVER_SOURCES)
endif




if WITH_ESX
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_esx.la
else
noinst_LTLIBRARIES += libvirt_driver_esx.la
libvirt_la_LIBADD += libvirt_driver_esx.la
endif
libvirt_driver_esx_la_CFLAGS = $(LIBCURL_CFLAGS)
libvirt_driver_esx_la_LDFLAGS = $(LIBCURL_LIBS)
if WITH_DRIVER_MODULES
libvirt_driver_esx_la_LDFLAGS += -module -avoid-version
endif
libvirt_driver_esx_la_SOURCES = $(ESX_DRIVER_SOURCES)
endif

if WITH_NETWORK
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_network.la
else
noinst_LTLIBRARIES += libvirt_driver_network.la
# Stateful, so linked to daemon instead
#libvirt_la_LIBADD += libvirt_driver_network.la
endif
if WITH_DRIVER_MODULES
libvirt_driver_network_la_LDFLAGS = -module -avoid-version
endif
libvirt_driver_network_la_SOURCES = $(NETWORK_DRIVER_SOURCES)
endif

if WITH_NETCF
libvirt_driver_interface_la_LDFLAGS = $(NETCF_LIBS)
libvirt_driver_interface_la_CFLAGS = $(NETCF_CFLAGS)
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_interface.la
else
noinst_LTLIBRARIES += libvirt_driver_interface.la
libvirt_la_LIBADD += libvirt_driver_interface.la
endif
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
libvirt_la_LIBADD += libvirt_driver_secret.la
endif
if WITH_DRIVER_MODULES
libvirt_driver_secret_la_LDFLAGS = -module -avoid-version ../gnulib/lib/libgnu.la
endif
libvirt_driver_secret_la_SOURCES = $(SECRET_DRIVER_SOURCES)
endif

# Needed to keep automake quiet about conditionals
libvirt_driver_storage_la_SOURCES =
libvirt_driver_storage_la_CFLAGS =
if WITH_STORAGE_DIR
if WITH_DRIVER_MODULES
mod_LTLIBRARIES += libvirt_driver_storage.la
else
noinst_LTLIBRARIES += libvirt_driver_storage.la
# Stateful, so linked to daemon instead
#libvirt_la_LIBADD += libvirt_driver_storage.la
endif
if WITH_DRIVER_MODULES
libvirt_driver_storage_la_LDFLAGS = -module -avoid-version
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
#libvirt_la_LIBADD += libvirt_driver_nodedev.la
endif
libvirt_driver_nodedev_la_SOURCES = $(NODE_DEVICE_DRIVER_SOURCES)

libvirt_driver_nodedev_la_CFLAGS =
libvirt_driver_nodedev_la_LDFLAGS =
if HAVE_HAL
libvirt_driver_nodedev_la_SOURCES += $(NODE_DEVICE_DRIVER_HAL_SOURCES)
libvirt_driver_nodedev_la_CFLAGS += $(HAL_CFLAGS)
libvirt_driver_nodedev_la_LDFLAGS += $(HAL_LIBS)
endif
if HAVE_DEVKIT
libvirt_driver_nodedev_la_SOURCES += $(NODE_DEVICE_DRIVER_DEVKIT_SOURCES)
libvirt_driver_nodedev_la_CFLAGS += $(DEVKIT_CFLAGS)
libvirt_driver_nodedev_la_LDFLAGS += $(DEVKIT_LIBS)
endif

if WITH_DRIVER_MODULES
libvirt_driver_nodedev_la_LDFLAGS += -module -avoid-version
endif
endif


libvirt_driver_security_la_SOURCES = $(SECURITY_DRIVER_SOURCES)
noinst_LTLIBRARIES += libvirt_driver_security.la
libvirt_la_LIBADD += libvirt_driver_security.la
if WITH_SECDRIVER_SELINUX
libvirt_driver_security_la_SOURCES += $(SECURITY_DRIVER_SELINUX_SOURCES)
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
		$(ESX_DRIVER_SOURCES)				\
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
		$(NODE_DEVICE_DRIVER_DEVKIT_SOURCES)		\
		$(SECURITY_DRIVER_SELINUX_SOURCES)		\
		$(SECRET_DRIVER_SOURCES)			\
		$(VBOX_DRIVER_EXTRA_DIST)

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

EXTRA_DIST += \
  libvirt_public.syms		\
  libvirt_private.syms		\
  libvirt_driver_modules.syms	\
  libvirt_bridge.syms		\
  libvirt_linux.syms

libvirt.syms: libvirt_public.syms $(USED_SYM_FILES)
	rm -f $@-tmp $@
	printf '# WARNING: generated from the following:\n# $^\n\n' >$@-tmp
	cat $(srcdir)/libvirt_public.syms >>$@-tmp
	printf '\n\n# Private symbols\n\n' >>$@-tmp
	printf 'LIBVIRT_PRIVATE_$(VERSION) {\n\n'  >>$@-tmp
	printf 'global:\n\n' >>$@-tmp
	for file in $(USED_SYM_FILES); do \
	    cat $(srcdir)/$$file >>$@-tmp; \
	done
	printf '\n\nlocal:\n*;\n\n};' >>$@-tmp
	chmod a-w $@-tmp
	mv $@-tmp libvirt.syms

# Empty source list - it merely links a bunch of convenience libs together
libvirt_la_SOURCES =
libvirt_la_LIBADD += \
		    @CYGWIN_EXTRA_LIBADD@ ../gnulib/lib/libgnu.la
libvirt_la_LDFLAGS = $(VERSION_SCRIPT_FLAGS)libvirt.syms \
                     -version-info @LIBVIRT_VERSION_INFO@ \
                    $(COVERAGE_CFLAGS:-f%=-Wc,-f%) \
                    $(LIBXML_LIBS) $(SELINUX_LIBS) \
		    $(XEN_LIBS) $(DRIVER_MODULE_LIBS) \
		    $(DEVMAPPER_LIBS) \
		    @CYGWIN_EXTRA_LDFLAGS@ @MINGW_EXTRA_LDFLAGS@
libvirt_la_CFLAGS = $(COVERAGE_CFLAGS) -DIN_LIBVIRT
libvirt_la_DEPENDENCIES = $(libvirt_la_LIBADD) libvirt.syms

# Create an automake "convenience library" version of libvirt_la,
# just for testing, since the test harness requires access to internal
# bits and pieces that we don't want to make publicly accessible.
noinst_LTLIBRARIES += libvirt_test.la

# Remove version script from convenience library
test_LDFLAGS =						\
  $$(echo '$(libvirt_la_LDFLAGS)'			\
     |sed 's!@VERSION_SCRIPT_FLAGS@libvirt.syms!!'	\
     |sed 's!-version-info @LIBVIRT_VERSION_INFO@!!')

# Just like the above, but with a slightly different set of public symbols.
libvirt_test_la_SOURCES = $(libvirt_la_SOURCES)
libvirt_test_la_LIBADD = $(libvirt_la_LIBADD)
libvirt_test_la_LDFLAGS = $(test_LDFLAGS)
libvirt_test_la_CFLAGS = $(COVERAGE_CFLAGS)

bin_PROGRAMS = virsh

virsh_SOURCES =							\
		console.c console.h				\
		virsh.c

virsh_LDFLAGS = $(WARN_CFLAGS) $(COVERAGE_LDFLAGS)
virsh_LDADD =							\
		$(STATIC_BINARIES)				\
		$(WARN_CFLAGS)					\
		$(NUMACTL_LIBS)					\
		libvirt.la					\
		../gnulib/lib/libgnu.la				\
		$(VIRSH_LIBS)
virsh_CFLAGS = $(COVERAGE_CFLAGS) $(READLINE_CFLAGS) $(NUMACTL_CFLAGS)
BUILT_SOURCES = virsh-net-edit.c virsh-pool-edit.c libvirt.syms

virsh-net-edit.c: virsh.c Makefile.am
	rm -f $@-tmp
	echo '/* Automatically generated from: $^ */' > $@-tmp
	echo 'static int' >> $@-tmp
	awk '/^cmdEdit/, /^}/' $< \
	  | sed -e 's/domain/network/g' \
	      -e 's/Domain/Network/g' \
	      -e 's/cmdEdit/cmdNetworkEdit/g' \
	      -e 's/dom/network/g' \
	      -e 's/int flags.*/int flags = 0;/g' \
	>> $@-tmp
	chmod a-w $@-tmp
	rm -f $@
	mv $@-tmp $@

virsh-pool-edit.c: virsh.c Makefile.am
	rm -f $@-tmp
	echo '/* Automatically generated from: $^ */' > $@-tmp
	echo 'static int' >> $@-tmp
	awk '/^cmdEdit/, /^}/' $< \
	  | sed -e 's/domain/pool/g' \
	      -e 's/vshCommandOptDomain/vshCommandOptPool/g' \
	      -e 's/Domain %s/Pool %s/g' \
	      -e 's/(ctl, cmd, NULL);/(ctl, cmd, "pool", NULL);/' \
	      -e 's/Domain/StoragePool/g' \
	      -e 's/cmdEdit/cmdPoolEdit/g' \
	      -e 's/\(virStoragePoolDefineXML.*\));/\1, 0);/' \
	      -e 's/dom/pool/g' \
	      -e 's/int flags.*/int flags = 0;/g' \
	>> $@-tmp
	chmod a-w $@-tmp
	rm -f $@
	mv $@-tmp $@

if WITH_WIN_ICON
virsh_LDADD += virsh_win_icon.$(OBJEXT)

# Before you edit virsh_win_icon.rc, please note the following
# limitations of the resource file format:
#
# (1) '..' is not permitted in the icon filename field.
# (2) '-' is not permitted in the icon filename field.
# (3) Comments are not permitted in the file.
#
# Windows appears to choose the first <= 32x32 icon it finds
# in the resource file.  Therefore you should list the available
# icons from largest to smallest, and make sure that the 32x32
# icon is the most legible.
#
# Windows .ICO is a special MS-only format.  GIMP and other
# tools can write it.  However there are several variations,
# and Windows seems to do its own colour quantization.  More
# information is needed in this area.

virsh_win_icon.$(OBJEXT): virsh_win_icon.rc
	$(WINDRES) \
	  --input-format rc --input $< \
	  --output-format coff --output $@
endif

libexec_PROGRAMS =

if WITH_STORAGE_DISK
if WITH_LIBVIRTD
libexec_PROGRAMS += libvirt_parthelper

libvirt_parthelper_SOURCES = $(STORAGE_HELPER_DISK_SOURCES)
libvirt_parthelper_LDFLAGS = $(WARN_CFLAGS) $(COVERAGE_LDCFLAGS)
libvirt_parthelper_LDADD = $(LIBPARTED_LIBS)
libvirt_parthelper_CFLAGS =  $(LIBPARTED_CFLAGS)
endif
endif
EXTRA_DIST += $(STORAGE_HELPER_DISK_SOURCES)


if WITH_LXC
if WITH_LIBVIRTD
libexec_PROGRAMS += libvirt_lxc

libvirt_lxc_SOURCES =						\
		$(LXC_CONTROLLER_SOURCES)			\
		$(UTIL_SOURCES)					\
		$(DOMAIN_CONF_SOURCES)
libvirt_lxc_LDFLAGS = $(WARN_CFLAGS) $(COVERAGE_LDCFLAGS) $(CAPNG_LIBS)
libvirt_lxc_LDADD = $(LIBXML_LIBS) $(NUMACTL_LIBS) ../gnulib/lib/libgnu.la
libvirt_lxc_CFLAGS =  $(LIBPARTED_CFLAGS) $(NUMACTL_CFLAGS) $(CAPNG_CFLAGS)
endif
endif
EXTRA_DIST += $(LXC_CONTROLLER_SOURCES)

install-exec-local:
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/cache/libvirt"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/libvirt/images"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/libvirt/boot"
if WITH_QEMU
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/libvirt/qemu"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/run/libvirt/qemu"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/cache/libvirt/qemu"
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
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/libvirt/iptables/filter"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/libvirt/iptables/nat"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/libvirt/network"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/run/libvirt/network"
endif


CLEANFILES = *.gcov .libs/*.gcda .libs/*.gcno *.gcno *.gcda *.i *.s
DISTCLEANFILES = $(BUILT_SOURCES)
