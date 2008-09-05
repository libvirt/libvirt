## Process this file with automake to produce Makefile.in

INCLUDES = \
	   -I$(top_srcdir)/gnulib/lib -I../gnulib/lib \
	   -I../include \
	   -I@top_srcdir@/include \
	   -I@top_srcdir@/qemud \
	   $(LIBXML_CFLAGS) \
	   $(GNUTLS_CFLAGS) \
	   $(SASL_CFLAGS) \
	   $(SELINUX_CFLAGS) \
	   $(NUMACTL_CFLAGS) \
	   -DBINDIR=\""$(libexecdir)"\" \
	   -DSBINDIR=\""$(sbindir)"\" \
	   -DSYSCONF_DIR="\"$(sysconfdir)\"" \
	   -DLOCALEBASEDIR=\""$(datadir)/locale"\" \
           -DLOCAL_STATE_DIR=\""$(localstatedir)"\" \
           -DGETTEXT_PACKAGE=\"$(PACKAGE)\" \
	   $(WARN_CFLAGS) \
	   $(LIBVIRT_FEATURES)
DEPS = libvirt.la
LDADDS = @STATIC_BINARIES@ $(WARN_CFLAGS) libvirt.la ../gnulib/lib/libgnu.la
VIRSH_LIBS = @VIRSH_LIBS@

confdir = $(sysconfdir)/libvirt/
conf_DATA = qemu.conf


EXTRA_DIST = libvirt_sym.version $(conf_DATA)

lib_LTLIBRARIES = libvirt.la

# These files are not related to driver APIs. Simply generic
# helper APIs for various purposes
GENERIC_LIB_SOURCES =						\
		bridge.c bridge.h				\
		buf.c buf.h					\
		conf.c conf.h					\
		event.c event.h					\
		iptables.c iptables.h				\
		memory.c memory.h				\
		qparams.c qparams.h				\
		stats_linux.c stats_linux.h			\
		uuid.c uuid.h					\
		util.c util.h					\
		virterror.c					\
		xml.c xml.h

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
		storage_conf.h storage_conf.c			\
		storage_backend.h storage_backend.c


# The remote RPC driver, covering domains, storage, networks, etc
REMOTE_DRIVER_SOURCES =						\
		gnutls_1_0_compat.h				\
		remote_internal.c remote_internal.h		\
		../qemud/remote_protocol.c			\
		../qemud/remote_protocol.h			\
		socketcompat.h

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

LXC_DRIVER_SOURCES =						\
		lxc_conf.c lxc_conf.h				\
		lxc_container.c lxc_container.h			\
		lxc_driver.c lxc_driver.h			\
		veth.c veth.h

LXC_CONTROLLER_SOURCES =					\
		lxc_conf.c lxc_conf.h				\
		lxc_container.c lxc_container.h			\
		lxc_controller.c				\
		veth.c veth.h

OPENVZ_DRIVER_SOURCES =						\
		openvz_conf.c openvz_conf.h			\
		openvz_driver.c openvz_driver.h

# XXX network driver should be split out of this
QEMU_DRIVER_SOURCES =						\
		qemu_conf.c qemu_conf.h				\
		qemu_driver.c qemu_driver.h


# And finally storage backend specific impls
STORAGE_DRIVER_SOURCES =					\
		storage_driver.h storage_driver.c

STORAGE_DRIVER_FS_SOURCES =					\
		storage_backend_fs.h storage_backend_fs.c

STORAGE_DRIVER_LVM_SOURCES =					\
		storage_backend_logical.h 			\
		storage_backend_logical.c

STORAGE_DRIVER_ISCSI_SOURCES =					\
		storage_backend_iscsi.h storage_backend_iscsi.c

STORAGE_DRIVER_DISK_SOURCES =					\
		storage_backend_disk.h storage_backend_disk.c

STORAGE_HELPER_DISK_SOURCES =					\
		parthelper.c



#########################
#
# Build up list of libvirt.la source files based on configure conditions
#
# First deal with sources usable in non-daemon context

libvirt_la_SOURCES =						\
		driver.h					\
		hash.c hash.h					\
		internal.h					\
		libvirt.c					\
		$(GENERIC_LIB_SOURCES)				\
		$(DOMAIN_CONF_SOURCES)				\
		$(NETWORK_CONF_SOURCES)				\
		$(STORAGE_CONF_SOURCES)

# Drivers usable outside daemon context
if WITH_TEST
libvirt_la_SOURCES += $(TEST_DRIVER_SOURCES)
endif

if WITH_REMOTE
libvirt_la_SOURCES += $(REMOTE_DRIVER_SOURCES)
endif

if WITH_XEN
libvirt_la_SOURCES += $(XEN_DRIVER_SOURCES)
endif

if WITH_OPENVZ
libvirt_la_SOURCES += $(OPENVZ_DRIVER_SOURCES)
endif


# Drivers usable inside daemon context
if WITH_LIBVIRTD
libvirt_la_SOURCES += $(STORAGE_DRIVER_SOURCES)
libvirt_la_SOURCES += $(STORAGE_DRIVER_FS_SOURCES)

if WITH_QEMU
libvirt_la_SOURCES += $(QEMU_DRIVER_SOURCES)
endif

if WITH_LXC
libvirt_la_SOURCES += $(LXC_DRIVER_SOURCES)
endif

if WITH_STORAGE_LVM
libvirt_la_SOURCES += $(STORAGE_DRIVER_LVM_SOURCES)
endif

if WITH_STORAGE_ISCSI
libvirt_la_SOURCES += $(STORAGE_DRIVER_ISCSI_SOURCES)
endif

if WITH_STORAGE_DISK
libvirt_la_SOURCES += $(STORAGE_DRIVER_DISK_SOURCES)
endif
endif

# Add all conditional sources just in case...
EXTRA_DIST +=							\
		$(TEST_DRIVER_SOURCES)				\
		$(REMOTE_DRIVER_SOURCES)			\
		$(XEN_DRIVER_SOURCES)				\
		$(QEMU_DRIVER_SOURCES)				\
		$(LXC_DRIVER_SOURCES)				\
		$(OPENVZ_DRIVER_SOURCES)			\
		$(STORAGE_DRIVER_SOURCES)			\
		$(STORAGE_DRIVER_FS_SOURCES)			\
		$(STORAGE_DRIVER_LVM_SOURCES)			\
		$(STORAGE_DRIVER_ISCSI_SOURCES)			\
		$(STORAGE_DRIVER_DISK_SOURCES)


libvirt_la_LIBADD = $(LIBXML_LIBS) $(GNUTLS_LIBS) $(SASL_LIBS) $(SELINUX_LIBS) \
                    $(NUMACTL_LIBS) \
		    @CYGWIN_EXTRA_LIBADD@ ../gnulib/lib/libgnu.la
libvirt_la_LDFLAGS = -Wl,--version-script=$(srcdir)/libvirt_sym.version \
                     -version-info @LIBVIRT_VERSION_INFO@ \
                    $(COVERAGE_CFLAGS:-f%=-Wc,-f%) \
		    @CYGWIN_EXTRA_LDFLAGS@ @MINGW_EXTRA_LDFLAGS@
libvirt_la_CFLAGS = $(COVERAGE_CFLAGS) -DIN_LIBVIRT

# Create an automake "convenience library" version of libvirt_la,
# just for testing, since the test harness requires access to internal
# bits and pieces that we don't want to make publicly accessible.
noinst_LTLIBRARIES = libvirt_test.la

# Convert libvirt_sym.version
#      to libvirt_test_sym.version, and
# remove -version-info X.Y.Z (not needed since this is a convenience library.
test_LDFLAGS =						\
  $$(echo '$(libvirt_la_LDFLAGS)'			\
     |sed 's!-Wl,--v.*_sym\.version!!'			\
     |sed 's!-version-info @LIBVIRT_VERSION_INFO@!!')

# Just like the above, but with a slightly different set of public symbols.
libvirt_test_la_SOURCES = $(libvirt_la_SOURCES)
libvirt_test_la_LIBADD = $(libvirt_la_LIBADD)
libvirt_test_la_LDFLAGS = $(test_LDFLAGS)
libvirt_test_la_CFLAGS = $(COVERAGE_CFLAGS)

bin_PROGRAMS = virsh

virsh_SOURCES =							\
		console.c console.h				\
		util-lib.c util-lib.h				\
		virsh.c

virsh_LDFLAGS = $(WARN_CFLAGS) $(COVERAGE_LDFLAGS)
virsh_DEPENDENCIES = $(DEPS)
virsh_LDADD = $(LDADDS) $(VIRSH_LIBS)
virsh_CFLAGS = $(COVERAGE_CFLAGS) $(READLINE_CFLAGS)
BUILT_SOURCES = virsh-net-edit.c virsh-pool-edit.c

virsh-net-edit.c: virsh.c Makefile.am
	rm -f $@-tmp
	echo '/* Automatically generated from: $^ */' > $@-tmp
	echo 'static int' >> $@-tmp
	awk '/^cmdEdit/, /^}/' $< \
	  | sed -e 's/domain/network/g' \
	      -e 's/Domain/Network/g' \
	      -e 's/cmdEdit/cmdNetworkEdit/g' \
	      -e 's/dom/network/g' \
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
	      -e 's/Domain/StoragePool/g' \
	      -e 's/cmdEdit/cmdPoolEdit/g' \
	      -e 's/\(virStoragePoolDefineXML.*\));/\1, 0);/' \
	      -e 's/dom/pool/g' \
	>> $@-tmp
	chmod a-w $@-tmp
	rm -f $@
	mv $@-tmp $@

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
		$(GENERIC_LIB_SOURCES) 				\
		$(DOMAIN_CONF_SOURCES)
libvirt_lxc_LDFLAGS = $(WARN_CFLAGS) $(COVERAGE_LDCFLAGS)
libvirt_lxc_LDADD = $(LIBXML_LIBS) ../gnulib/lib/libgnu.la
libvirt_lxc_CFLAGS =  $(LIBPARTED_CFLAGS)
endif
endif
EXTRA_DIST += $(LXC_CONTROLLER_SOURCES)

# Create the /var/cache/libvirt directory when installing.
install-exec-local:
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/cache/libvirt

CLEANFILES = *.gcov .libs/*.gcda .libs/*.gcno *.gcno *.gcda
DISTCLEANFILES = $(BUILT_SOURCES)
