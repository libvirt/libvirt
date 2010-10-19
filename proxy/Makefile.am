## Process this file with automake to produce Makefile.in

if WITH_PROXY
INCLUDES = -I$(top_srcdir)/gnulib/lib -I../gnulib/lib \
           -I$(top_builddir)/include -I@top_srcdir@/include \
	   -I@top_srcdir@/proxy -I@top_srcdir@/src \
           -I@top_srcdir@/src/util \
           -I@top_srcdir@/src/conf \
           -I@top_srcdir@/src/xen \
           $(LIBXML_CFLAGS) \
	   -DPROXY  -DLOCALEBASEDIR=\""$(datadir)/locale"\" \
           -DGETTEXT_PACKAGE=\"$(PACKAGE)\" $(WARN_CFLAGS) $(XEN_CFLAGS)

libexec_PROGRAMS = libvirt_proxy

libvirt_proxy_SOURCES = libvirt_proxy.c \
            @top_srcdir@/src/util/buf.c \
            @top_srcdir@/src/util/files.c \
            @top_srcdir@/src/util/hash.c \
	    @top_srcdir@/src/util/logging.c \
            @top_srcdir@/src/util/memory.c \
            @top_srcdir@/src/util/network.c \
	    @top_srcdir@/src/util/threads.c  \
            @top_srcdir@/src/util/util.c \
	    @top_srcdir@/src/util/uuid.c \
            @top_srcdir@/src/util/virterror.c \
            @top_srcdir@/src/conf/capabilities.c \
            @top_srcdir@/src/conf/storage_encryption_conf.c \
            @top_srcdir@/src/conf/domain_conf.c \
            @top_srcdir@/src/conf/cpu_conf.c \
            @top_srcdir@/src/conf/nwfilter_params.c \
            @top_srcdir@/src/xen/xend_internal.c \
	    @top_srcdir@/src/xen/xen_hypervisor.c \
	    @top_srcdir@/src/xen/sexpr.c  \
            @top_srcdir@/src/xen/xs_internal.c
libvirt_proxy_LDFLAGS = $(WARN_LDFLAGS)
libvirt_proxy_DEPENDENCIES =
libvirt_proxy_LDADD = ../gnulib/lib/libgnu.la $(XEN_LIBS) $(LIB_PTHREAD)

install-exec-hook:
	chmod u+s $(DESTDIR)$(libexecdir)/libvirt_proxy
endif
