## Process this file with automake to produce Makefile.in

INCLUDES = -I$(top_builddir)/include -I@top_srcdir@/include \
           -I@top_srcdir@/proxy -I@top_srcdir@/src @LIBXML_CFLAGS@ \
	   -DBINDIR=\""$(libexecdir)"\"	\
	   -DBUILDDIR=\""$(top_builddir)"\" \
	   -DXEN_RO


bin_PROGRAMS = libvirt_proxy
LIBS=

libvirt_proxy_SOURCES = libvirt_proxy.c @top_srcdir@/src/xend_internal.c \
	    @top_srcdir@/src/xen_internal.c @top_srcdir@/src/virterror.c \
	    @top_srcdir@/src/sexpr.c

libvirt_proxy_LDFLAGS =
libvirt_proxy_DEPENDENCIES =
libvirt_proxy_LDADD =

noinst_PROGRAMS= test_proxy
test_proxy_SOURCES = proxy_client.c
test_proxy_LDFLAGS = 
test_proxy_DEPENDENCIES =
test_proxy_LDADD =
