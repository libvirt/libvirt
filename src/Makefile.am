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

CLIENT_SOURCES =						\
		libvirt.c internal.h				\
		gnutls_1_0_compat.h				\
		socketcompat.h					\
                memory.c memory.h				\
		hash.c hash.h					\
		test.c test.h                                   \
                buf.c buf.h					\
		qparams.c qparams.h				\
                capabilities.c capabilities.h			\
		xml.c xml.h					\
		event.c event.h					\
		xen_unified.c xen_unified.h			\
		xen_internal.c xen_internal.h			\
		xs_internal.c xs_internal.h			\
		xend_internal.c xend_internal.h			\
		stats_linux.c stats_linux.h			\
		sexpr.c sexpr.h					\
		virterror.c					\
		driver.h					\
		proxy_internal.c proxy_internal.h		\
		conf.c conf.h                                   \
		xm_internal.c xm_internal.h                     \
		remote_internal.c remote_internal.h		\
		bridge.c bridge.h				\
		iptables.c iptables.h				\
		uuid.c uuid.h					\
		qemu_driver.c qemu_driver.h			\
		qemu_conf.c qemu_conf.h				\
		openvz_conf.c openvz_conf.h			\
		openvz_driver.c openvz_driver.h			\
		lxc_driver.c lxc_driver.h			\
		lxc_conf.c lxc_conf.h				\
		lxc_container.c lxc_container.h			\
                nodeinfo.h nodeinfo.c                           \
		util.c util.h

SERVER_SOURCES =						\
		../qemud/remote_protocol.c ../qemud/remote_protocol.h

if WITH_LIBVIRTD

CLIENT_SOURCES += 						\
		storage_conf.h storage_conf.c			\
		storage_driver.h storage_driver.c		\
		storage_backend.h storage_backend.c		\
		storage_backend_fs.h storage_backend_fs.c

if WITH_STORAGE_LVM
CLIENT_SOURCES += storage_backend_logical.h storage_backend_logical.c
else
EXTRA_DIST += storage_backend_logical.h storage_backend_logical.c
endif

if WITH_STORAGE_ISCSI
CLIENT_SOURCES +=  storage_backend_iscsi.h storage_backend_iscsi.c
else
EXTRA_DIST +=  storage_backend_iscsi.h storage_backend_iscsi.c
endif

if WITH_STORAGE_DISK
CLIENT_SOURCES += storage_backend_disk.h storage_backend_disk.c
else
EXTRA_DIST += storage_backend_disk.h storage_backend_disk.c
endif

endif


libvirt_la_SOURCES = $(CLIENT_SOURCES) $(SERVER_SOURCES)
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

virsh_SOURCES = virsh.c console.c console.h util-lib.c util-lib.h
virsh_LDFLAGS = $(WARN_CFLAGS) $(COVERAGE_LDFLAGS)
virsh_DEPENDENCIES = $(DEPS)
virsh_LDADD = $(LDADDS) $(VIRSH_LIBS)
virsh_CFLAGS = $(COVERAGE_CFLAGS) $(READLINE_CFLAGS)

if WITH_STORAGE_DISK
if WITH_LIBVIRTD
libexec_PROGRAMS = libvirt_parthelper

libvirt_parthelper_SOURCES = parthelper.c
libvirt_parthelper_LDFLAGS = $(WARN_CFLAGS) $(COVERAGE_LDCFLAGS)
libvirt_parthelper_LDADD = $(LIBPARTED_LIBS)
libvirt_parthelper_CFLAGS =  $(LIBPARTED_CFLAGS)
endif
else
EXTRA_DIST += parthelper.c
endif

# Create the /var/cache/libvirt directory when installing.
install-exec-local:
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/cache/libvirt

CLEANFILES = *.gcov .libs/*.gcda .libs/*.gcno *.gcno *.gcda
