## Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_builddir)/include \
	   -I@top_srcdir@/include \
	   -I@top_srcdir@/qemud \
	   $(LIBXML_CFLAGS) \
	   $(GNUTLS_CFLAGS) \
	   -DBINDIR=\""$(libexecdir)"\" \
	   -DSBINDIR=\""$(sbindir)"\" \
	   -DSYSCONF_DIR="\"$(sysconfdir)\"" \
	   -DLOCALEBASEDIR=\""$(datadir)/locale"\" \
           -DLOCAL_STATE_DIR=\""$(localstatedir)"\" \
           -DGETTEXT_PACKAGE=\"$(PACKAGE)\" \
	   $(WARN_CFLAGS) \
	   $(LIBVIRT_FEATURES)
DEPS = libvirt.la
LDADDS = @STATIC_BINARIES@ $(WARN_CFLAGS) libvirt.la
VIRSH_LIBS = @VIRSH_LIBS@

EXTRA_DIST = libvirt_sym.version

lib_LTLIBRARIES = libvirt.la
libvirt_la_LIBADD = $(LIBXML_LIBS) $(GNUTLS_LIBS)
libvirt_la_LDFLAGS = -Wl,--version-script=$(srcdir)/libvirt_sym.version \
                    -version-info @LIBVIRT_VERSION_INFO@ \
                    $(COVERAGE_CFLAGS:-f%=-Wc,-f%)
libvirt_la_CFLAGS = $(COVERAGE_CFLAGS)

CLIENT_SOURCES =						\
		libvirt.c internal.h				\
		gnutls_1_0_compat.h				\
		hash.c hash.h					\
		test.c test.h                                   \
                buf.c buf.h					\
		xml.c xml.h					\
		event.c event.h					\
		xen_unified.c xen_unified.h			\
		xen_internal.c xen_internal.h			\
		xs_internal.c xs_internal.h			\
		xend_internal.c xend_internal.h			\
		sexpr.c sexpr.h					\
		virterror.c					\
		driver.h					\
		proxy_internal.c proxy_internal.h		\
		conf.c conf.h                                   \
		xm_internal.c xm_internal.h                     \
		remote_internal.c remote_internal.h		\
		bridge.c bridge.h 				\
		iptables.c iptables.h 				\
		uuid.c uuid.h 					\
		qemu_driver.c qemu_driver.h 			\
		qemu_conf.c qemu_conf.h					\
		openvz_conf.c openvz_conf.h				\
		openvz_driver.c openvz_driver.h 		\
                nodeinfo.h nodeinfo.c                           \
		util.c util.h

SERVER_SOURCES = 						\
		../qemud/protocol.h ../qemud/protocol.c		\
		../qemud/remote_protocol.c ../qemud/remote_protocol.h

libvirt_la_SOURCES = $(CLIENT_SOURCES) $(SERVER_SOURCES)

bin_PROGRAMS = virsh

virsh_SOURCES = virsh.c console.c console.h
virsh_LDFLAGS = $(WARN_CFLAGS) $(COVERAGE_LDFLAGS)
virsh_DEPENDENCIES = $(DEPS)
virsh_LDADD = $(LDADDS) $(VIRSH_LIBS)
virsh_CFLAGS = $(COVERAGE_CFLAGS)

#
# target to ease building test programs
#
tst: tst.c
	$(CC) $(CFLAGS) -I../include -o tst tst.c .libs/libvirt.a -lxml2 -lxenstore -lpthread

COVERAGE_FILES = $(CLIENT_SOURCES:%.c=libvirt_la-%.cov)

cov: clean-cov $(COVERAGE_FILES)

clean-cov:
	rm -f *.cov *.gcov

%.cov: .libs/%.o
	gcov -b -f -o .libs $< > $@

CLEANFILES = *.cov *.gcov .libs/*.gcda .libs/*.gcno *.gcno *.gcda
