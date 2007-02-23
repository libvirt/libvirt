## Process this file with automake to produce Makefile.in

INCLUDES = @LIBXML_CFLAGS@

sbin_PROGRAMS = libvirt_qemud

libvirt_qemud_SOURCES = qemud.c internal.h protocol.h \
                driver.c driver.h \
                dispatch.c dispatch.h \
                conf.c conf.h \
                bridge.c bridge.h \
                iptables.c iptables.h
#-D_XOPEN_SOURCE=600 -D_XOPEN_SOURCE_EXTENDED=1 -D_POSIX_C_SOURCE=199506L
libvirt_qemud_CFLAGS = \
        -I$(top_srcdir)/include -I$(top_builddir)/include $(LIBXML_CFLAGS) \
        -Wall -Wextra -DLOCAL_STATE_DIR="\"$(localstatedir)\"" \
        -DSYSCONF_DIR="\"$(sysconfdir)\""
libvirt_qemud_LDFLAGS = $(LIBXML_LIBS) $(SYSFS_LIBS)
libvirt_qemud_DEPENDENCIES =
libvirt_qemud_LDADD =

EXTRA_DIST = libvirt_qemud.init.in

if LIBVIRT_INIT_SCRIPTS_RED_HAT
initdir = $(sysconfdir)/rc.d/init.d
init_SCRIPTS = libvirtd

libvirtd: libvirtd.in
	sed						\
	    -e s!\@localstatedir\@!@localstatedir@!	\
	    -e s!\@sbindir\@!@sbindir@!			\
	    -e s!\@sysconfdir\@!@sysconfdir@!		\
	    < $< > $@
	chmod a+x libvirtd

CLEANFILES = libvirtd
endif # DBUS_INIT_SCRIPTS_RED_HAT
