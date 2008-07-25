## Process this file with automake to produce Makefile.in

if WITH_PROXY
INCLUDES = -I$(top_srcdir)/gnulib/lib -I../gnulib/lib \
           -I$(top_builddir)/include -I@top_srcdir@/include \
	   -I@top_srcdir@/proxy -I@top_srcdir@/src @LIBXML_CFLAGS@ \
	   -DPROXY  -DLOCALEBASEDIR=\""$(datadir)/locale"\" \
           -DGETTEXT_PACKAGE=\"$(PACKAGE)\" $(WARN_CFLAGS) $(LIBVIRT_FEATURES)

libexec_PROGRAMS = libvirt_proxy

libvirt_proxy_SOURCES = libvirt_proxy.c @top_srcdir@/src/xend_internal.c \
	    @top_srcdir@/src/xen_internal.c @top_srcdir@/src/virterror.c \
	    @top_srcdir@/src/sexpr.c  \
            @top_srcdir@/src/xs_internal.c @top_srcdir@/src/buf.c \
            @top_srcdir@/src/capabilities.c \
            @top_srcdir@/src/memory.c \
            @top_srcdir@/src/domain_conf.c \
            @top_srcdir@/src/util.c \
	    @top_srcdir@/src/uuid.c
libvirt_proxy_LDFLAGS = $(WARN_CFLAGS)
libvirt_proxy_DEPENDENCIES =
libvirt_proxy_LDADD = ../gnulib/lib/libgnu.la

install-exec-hook:
	chmod u+s $(DESTDIR)$(libexecdir)/libvirt_proxy
endif
