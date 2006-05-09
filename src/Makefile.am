## Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_builddir)/include -I@top_srcdir@/include @LIBXML_CFLAGS@
DEPS = libvirt.la
LDADDS = @STATIC_BINARIES@ libvirt.la
VIRSH_LIBS = @VIRSH_LIBS@

EXTRA_DIST = libvirt_sym.version

lib_LTLIBRARIES = libvirt.la
libvirt_la_LIBADD = @LIBXML_LIBS@

libvirt_la_LDFLAGS = -Wl,--version-script=$(srcdir)/libvirt_sym.version \
                    -version-info @LIBVIRT_VERSION_INFO@

libvirt_la_SOURCES =						\
		libvirt.c internal.h				\
		hash.c hash.h					\
		xml.c xml.h					\
		xen_internal.c xen_internal.h			\
		xs_internal.c xs_internal.h			\
		xend_internal.c xend_internal.h			\
		sexpr.c sexpr.h					\
		virterror.c					\
		driver.h

bin_PROGRAMS = virsh

virsh_SOURCES = virsh.c
virsh_LDFLAGS =
virsh_DEPENDENCIES = $(DEPS)
virsh_LDADD = $(LDADDS) $(VIRSH_LIBS)

