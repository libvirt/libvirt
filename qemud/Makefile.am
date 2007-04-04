## Process this file with automake to produce Makefile.in

INCLUDES = @LIBXML_CFLAGS@
UUID=$(shell uuidgen)

sbin_PROGRAMS = libvirt_qemud

libvirt_qemud_SOURCES = qemud.c internal.h protocol.h \
                driver.c driver.h \
                dispatch.c dispatch.h \
                conf.c conf.h \
                bridge.c bridge.h \
                iptables.c iptables.h \
                uuid.c uuid.h \
		buf.c buf.h
#-D_XOPEN_SOURCE=600 -D_XOPEN_SOURCE_EXTENDED=1 -D_POSIX_C_SOURCE=199506L
libvirt_qemud_CFLAGS = \
        -I$(top_srcdir)/include -I$(top_builddir)/include $(LIBXML_CFLAGS) \
        $(WARN_CFLAGS) -DLOCAL_STATE_DIR="\"$(localstatedir)\"" \
        -DSYSCONF_DIR="\"$(sysconfdir)\"" \
	-DQEMUD_PID_FILE="\"$(QEMUD_PID_FILE)\""
libvirt_qemud_LDFLAGS = $(LIBXML_LIBS) $(SYSFS_LIBS)
libvirt_qemud_DEPENDENCIES =
libvirt_qemud_LDADD =

install-data-local:
	mkdir -p $(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/autostart
	$(INSTALL_DATA) $(srcdir)/default-network.xml $(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/default.xml
	sed -i -e "s,</name>,</name>\n  <uuid>$(UUID)</uuid>," $(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/default.xml
	test -e $(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/autostart/default.xml || \
           ln -s ../default.xml $(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/autostart/default.xml
	mkdir -p $(DESTDIR)$(localstatedir)/run/libvirt
	mkdir -p $(DESTDIR)$(localstatedir)/lib/libvirt

uninstall-local:
	rm -f $(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/autostart/default.xml
	rm -f $(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/default.xml
	rmdir $(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/autostart || :
	rmdir $(DESTDIR)$(localstatedir)/run/libvirt || :
	rmdir $(DESTDIR)$(localstatedir)/lib/libvirt || :

EXTRA_DIST = libvirtd.in default-network.xml

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
