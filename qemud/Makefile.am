## Process this file with automake to produce Makefile.in

# Distribute the generated files so that rpcgen isn't required on the
# target machine (although almost any Unix machine will have it).
EXTRA_DIST = libvirtd.init.in libvirtd.sysconf default-network.xml \
	remote_protocol.x \
	remote_protocol.c remote_protocol.h \
	remote_generate_stubs.pl rpcgen_fix.pl \
	remote_dispatch_prototypes.h \
	remote_dispatch_localvars.h \
	remote_dispatch_proc_switch.h \
	mdns.c mdns.h \
        libvirtd.sasl \
        libvirtd.conf

if RPCGEN
.x.c:
	rm -f $@
	rpcgen -c -o $@ $<
if GLIBC_RPCGEN
	mv $@ $@.bak
	perl -w rpcgen_fix.pl < $@.bak > $@
endif

.x.h:
	rm -f $@
	rpcgen -h -o $@ $<
endif

remote_protocol.c: remote_protocol.h

if WITH_LIBVIRTD

UUID=$(shell uuidgen)

sbin_PROGRAMS = libvirtd

confdir = $(sysconfdir)/libvirt/
conf_DATA = libvirtd.conf

libvirtd_SOURCES = \
		qemud.c internal.h \
		remote_protocol.h remote_protocol.c \
		remote.c \
		event.c event.h

#-D_XOPEN_SOURCE=600 -D_XOPEN_SOURCE_EXTENDED=1 -D_POSIX_C_SOURCE=199506L
libvirtd_CFLAGS = \
        -I$(top_srcdir)/gnulib/lib -I../gnulib/lib \
        -I$(top_srcdir)/include -I$(top_builddir)/include \
        $(LIBXML_CFLAGS) $(GNUTLS_CFLAGS) $(SASL_CFLAGS) \
        $(POLKIT_CFLAGS) \
        $(WARN_CFLAGS) -DLOCAL_STATE_DIR="\"$(localstatedir)\"" \
        -DSYSCONF_DIR="\"$(sysconfdir)\"" \
	-DQEMUD_PID_FILE="\"$(QEMUD_PID_FILE)\"" \
	-DREMOTE_PID_FILE="\"$(REMOTE_PID_FILE)\"" \
        -DGETTEXT_PACKAGE=\"$(PACKAGE)\"

libvirtd_LDFLAGS = $(WARN_CFLAGS) $(LIBXML_LIBS) $(GNUTLS_LIBS) $(SASL_LIBS) \
                   $(POLKIT_LIBS)
libvirtd_DEPENDENCIES = ../src/libvirt.la
libvirtd_LDADD = ../src/libvirt.la ../gnulib/lib/libgnu.la

if HAVE_POLKIT
policydir = $(datadir)/PolicyKit/policy
policy_DATA = libvirtd.policy
endif
EXTRA_DIST += libvirtd.policy

if HAVE_AVAHI
libvirtd_SOURCES += mdns.c mdns.h
libvirtd_CFLAGS += $(AVAHI_CFLAGS)
libvirtd_LDADD += $(AVAHI_LIBS)
endif

default_xml_dest = libvirt/qemu/networks/default.xml
install-data-local: install-init install-data-sasl
	mkdir -p $(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/autostart
	$(INSTALL_DATA) $(srcdir)/default-network.xml \
	  $(DESTDIR)$(sysconfdir)/$(default_xml_dest)
	sed -i -e "s,</name>,</name>\n  <uuid>$(UUID)</uuid>," \
	  $(DESTDIR)$(sysconfdir)/$(default_xml_dest)
	test -e $(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/autostart/default.xml || \
           ln -s ../default.xml \
	    $(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/autostart/default.xml
	mkdir -p $(DESTDIR)$(localstatedir)/log/libvirt/qemu
	mkdir -p $(DESTDIR)$(localstatedir)/run/libvirt
	mkdir -p $(DESTDIR)$(localstatedir)/lib/libvirt

uninstall-local:: uninstall-init uninstall-data-sasl
	rm -f $(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/autostart/default.xml
	rm -f $(DESTDIR)$(sysconfdir)/$(default_xml_dest)
	rmdir $(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/autostart || :
	rmdir $(DESTDIR)$(localstatedir)/log/libvirt/qemu || :
	rmdir $(DESTDIR)$(localstatedir)/run/libvirt || :
	rmdir $(DESTDIR)$(localstatedir)/lib/libvirt || :

if HAVE_SASL
install-data-sasl:: install-init
	mkdir -p $(DESTDIR)$(sysconfdir)/sasl2/
	$(INSTALL_DATA) $(srcdir)/libvirtd.sasl $(DESTDIR)$(sysconfdir)/sasl2/libvirt.conf

uninstall-data-sasl:: install-init
	rm -f $(DESTDIR)$(sysconfdir)/sasl2/libvirt.conf
	rmdir $(DESTDIR)$(sysconfdir)/sasl2/
else
install-data-sasl:
uninstall-data-sasl:
endif

remote.c: remote_dispatch_prototypes.h \
	  remote_dispatch_localvars.h \
	  remote_dispatch_proc_switch.h

remote_dispatch_prototypes.h: $(srcdir)/remote_generate_stubs.pl remote_protocol.x
	perl -w $(srcdir)/remote_generate_stubs.pl -i $(srcdir)/remote_protocol.x > $@

remote_dispatch_localvars.h: $(srcdir)/remote_generate_stubs.pl remote_protocol.x
	perl -w $(srcdir)/remote_generate_stubs.pl -v $(srcdir)/remote_protocol.x > $@

remote_dispatch_proc_switch.h: $(srcdir)/remote_generate_stubs.pl remote_protocol.x
	perl -w $(srcdir)/remote_generate_stubs.pl -w $(srcdir)/remote_protocol.x > $@

if LIBVIRT_INIT_SCRIPTS_RED_HAT
install-init: libvirtd.init
	mkdir -p $(DESTDIR)$(sysconfdir)/rc.d/init.d
	$(INSTALL_SCRIPT) libvirtd.init \
	  $(DESTDIR)$(sysconfdir)/rc.d/init.d/libvirtd
	mkdir -p $(DESTDIR)$(sysconfdir)/sysconfig
	$(INSTALL_SCRIPT) $(srcdir)/libvirtd.sysconf \
	  $(DESTDIR)$(sysconfdir)/sysconfig/libvirtd

uninstall-init:
	rm -f $(DESTDIR)$(sysconfdir)/rc.d/init.d/libvirtd \
		$(DESTDIR)$(sysconfdir)/sysconfig/libvirtd

libvirtd.init: libvirtd.init.in
	sed						\
	    -e s!\@localstatedir\@!@localstatedir@!g	\
	    -e s!\@sbindir\@!@sbindir@!g		\
	    -e s!\@sysconfdir\@!@sysconfdir@!g		\
	    < $< > $@-t
	chmod a+x $@-t
	mv $@-t $@

CLEANFILES = libvirtd.init
else

install-init:
uninstall-init:

endif # DBUS_INIT_SCRIPTS_RED_HAT

endif # WITH_LIBVIRTD