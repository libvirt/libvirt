## Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_builddir)/include -I@top_srcdir@/include @LIBXML_CFLAGS@ -I@top_srcdir@/qemud \
	   -DBINDIR=\""$(libexecdir)"\" -DSBINDIR=\""$(sbindir)"\" -DLOCALEBASEDIR=\""$(datadir)/locale"\" \
           -DLOCAL_STATE_DIR=\""$(localstatedir)"\" \
           -DGETTEXT_PACKAGE=\"$(PACKAGE)\" $(WARN_CFLAGS) $(LIBVIRT_FEATURES)
DEPS = libvirt.la
LDADDS = @STATIC_BINARIES@ libvirt.la
VIRSH_LIBS = @VIRSH_LIBS@

EXTRA_DIST = libvirt_sym.version

lib_LTLIBRARIES = libvirt.la
libvirt_la_LIBADD = @LIBXML_LIBS@
libvirt_la_LDFLAGS = -Wl,--version-script=$(srcdir)/libvirt_sym.version \
                    -version-info @LIBVIRT_VERSION_INFO@ \
                    $(COVERAGE_CFLAGS:-f%=-Wc,-f%)
libvirt_la_CFLAGS = $(COVERAGE_CFLAGS)
libvirt_la_SOURCES =						\
		libvirt.c internal.h				\
		hash.c hash.h					\
		test.c test.h                                   \
		xml.c xml.h					\
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
		qemu_internal.c qemu_internal.h

bin_PROGRAMS = virsh

virsh_SOURCES = virsh.c console.c console.h
virsh_LDFLAGS = $(COVERAGE_LDFLAGS)
virsh_DEPENDENCIES = $(DEPS)
virsh_LDADD = $(LDADDS) $(VIRSH_LIBS)
virsh_CFLAGS = $(COVERAGE_CFLAGS)

#
# target to ease building test programs
#
tst: tst.c
	$(CC) $(CFLAGS) -I../include -o tst tst.c .libs/libvirt.a -lxml2 -lxenstore -lpthread

COVERAGE_FILES = $(libvirt_la_SOURCES:%.c=libvirt_la-%.cov)

cov: clean-cov $(COVERAGE_FILES)

clean-cov:
	rm -f *.cov *.gcov

%.cov: .libs/%.o
	gcov -b -f -o .libs $< > $@

CLEANFILES = *.cov *.gcov .libs/*.gcda .libs/*.gcno *.gcno *.gcda
