## Process this file with automake to produce Makefile.in

UUID=$(shell uuidgen)

sbin_PROGRAMS = libvirtd

# Distribute the generated files so that rpcgen isn't required on the
# target machine (although almost any Unix machine will have it).
EXTRA_DIST = libvirtd.init.in libvirtd.sysconf default-network.xml \
	protocol.x remote_protocol.x \
	protocol.c protocol.h \
	remote_protocol.c remote_protocol.h \
	remote_generate_stubs.pl rpcgen_fix.pl \
	remote_dispatch_prototypes.h \
	remote_dispatch_localvars.h \
	remote_dispatch_proc_switch.h \
	mdns.c mdns.h

libvirtd_SOURCES = \
		qemud.c internal.h \
		protocol.h protocol.c \
		remote_protocol.h remote_protocol.c \
		remote.c \
		event.c event.h

#-D_XOPEN_SOURCE=600 -D_XOPEN_SOURCE_EXTENDED=1 -D_POSIX_C_SOURCE=199506L
libvirtd_CFLAGS = \
        -I$(top_srcdir)/include -I$(top_builddir)/include \
        $(LIBXML_CFLAGS) $(GNUTLS_CFLAGS) \
        $(WARN_CFLAGS) -DLOCAL_STATE_DIR="\"$(localstatedir)\"" \
        -DSYSCONF_DIR="\"$(sysconfdir)\"" \
	-DQEMUD_PID_FILE="\"$(QEMUD_PID_FILE)\"" \
	-DREMOTE_PID_FILE="\"$(REMOTE_PID_FILE)\"" \
        -DGETTEXT_PACKAGE=\"$(PACKAGE)\"

libvirtd_LDFLAGS = $(WARN_CFLAGS) $(LIBXML_LIBS) $(GNUTLS_LIBS)
libvirtd_DEPENDENCIES = ../src/libvirt.la
libvirtd_LDADD = ../src/libvirt.la

if HAVE_AVAHI
libvirtd_SOURCES += mdns.c mdns.h
libvirtd_CFLAGS += $(AVAHI_CFLAGS)
libvirtd_LDADD += $(AVAHI_LIBS)
endif

install-data-local: install-init
	mkdir -p $(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/autostart
	$(INSTALL_DATA) $(srcdir)/default-network.xml $(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/default.xml
	sed -i -e "s,</name>,</name>\n  <uuid>$(UUID)</uuid>," $(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/default.xml
	test -e $(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/autostart/default.xml || \
           ln -s ../default.xml $(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/autostart/default.xml
	mkdir -p $(DESTDIR)$(localstatedir)/log/libvirt/qemu
	mkdir -p $(DESTDIR)$(localstatedir)/run/libvirt
	mkdir -p $(DESTDIR)$(localstatedir)/lib/libvirt

uninstall-local: uninstall-init
	rm -f $(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/autostart/default.xml
	rm -f $(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/default.xml
	rmdir $(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/autostart || :
	rmdir $(DESTDIR)$(localstatedir)/log/libvirt/qemu || :
	rmdir $(DESTDIR)$(localstatedir)/run/libvirt || :
	rmdir $(DESTDIR)$(localstatedir)/lib/libvirt || :


.x.c:
	rm -f $@
	rpcgen -c -o $@ $<
	mv $@ $@.bak
	perl -w rpcgen_fix.pl < $@.bak > $@

.x.h:
	rm -f $@
	rpcgen -h -o $@ $<

protocol.c: protocol.h
remote_protocol.c: remote_protocol.h

remote.c: remote_dispatch_prototypes.h \
	  remote_dispatch_localvars.h \
	  remote_dispatch_proc_switch.h

remote_dispatch_prototypes.h: remote_generate_stubs.pl remote_protocol.x
	perl -w remote_generate_stubs.pl -i remote_protocol.x > $@

remote_dispatch_localvars.h: remote_generate_stubs.pl remote_protocol.x
	perl -w remote_generate_stubs.pl -v remote_protocol.x > $@

remote_dispatch_proc_switch.h: remote_generate_stubs.pl remote_protocol.x
	perl -w remote_generate_stubs.pl -w remote_protocol.x > $@

if LIBVIRT_INIT_SCRIPTS_RED_HAT
install-init: libvirtd.init
	mkdir -p $(DESTDIR)$(sysconfdir)/rc.d/init.d
	$(INSTALL_SCRIPT) $(srcdir)/libvirtd.init $(DESTDIR)$(sysconfdir)/rc.d/init.d/libvirtd
	mkdir -p $(DESTDIR)$(sysconfdir)/sysconfig
	$(INSTALL_SCRIPT) $(srcdir)/libvirtd.sysconf $(DESTDIR)$(sysconfdir)/sysconfig/libvirtd

uninstall-init:
	rm -f $(DESTDIR)$(sysconfdir)/rc.d/init.d/libvirtd

libvirtd.init: libvirtd.init.in
	sed						\
	    -e s!\@localstatedir\@!@localstatedir@!g	\
	    -e s!\@sbindir\@!@sbindir@!g		\
	    -e s!\@sysconfdir\@!@sysconfdir@!g		\
	    < $< > $@
	chmod a+x libvirtd.init

CLEANFILES = libvirtd.init
else

install-init:
uninstall-init:

endif # DBUS_INIT_SCRIPTS_RED_HAT
