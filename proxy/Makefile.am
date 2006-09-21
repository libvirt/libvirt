## Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_builddir)/include -I@top_srcdir@/include \
           -I@top_srcdir@/proxy -I@top_srcdir@/src @LIBXML_CFLAGS@ \
	   -DPROXY  -DLOCALEBASEDIR=\""$(datadir)/locale"\" \
           -DGETTEXT_PACKAGE=\"$(PACKAGE)\"

libexec_PROGRAMS = libvirt_proxy

libvirt_proxy_SOURCES = libvirt_proxy.c @top_srcdir@/src/xend_internal.c \
	    @top_srcdir@/src/xen_internal.c @top_srcdir@/src/virterror.c \
	    @top_srcdir@/src/sexpr.c @top_srcdir@/src/xml.c \
            @top_srcdir@/src/xs_internal.c
libvirt_proxy_LDFLAGS =
libvirt_proxy_DEPENDENCIES =
libvirt_proxy_LDADD =

install-exec-hook:
	chmod u+s $(DESTDIR)$(libexecdir)/libvirt_proxy
