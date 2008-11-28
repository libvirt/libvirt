## Process this file with automake to produce Makefile.in

DAEMON_SOURCES =					\
		event.c event.h				\
		qemud.c qemud.h				\
		remote.c				\
		remote_dispatch_prototypes.h		\
		remote_dispatch_localvars.h		\
		remote_dispatch_proc_switch.h		\
		remote_protocol.h remote_protocol.c

AVAHI_SOURCES =						\
		mdns.c mdns.h

EXTRA_DIST =						\
	default-network.xml				\
	remote_generate_stubs.pl rpcgen_fix.pl		\
	remote_protocol.x				\
	libvirtd.conf					\
	libvirtd.init.in				\
	libvirtd.policy					\
	libvirtd.sasl					\
	libvirtd.sysconf				\
	libvirtd.aug                                    \
	libvirtd_qemu.aug                               \
	test_libvirtd.aug                               \
	test_libvirtd_qemu.aug                          \
	$(AVAHI_SOURCES)				\
	$(DAEMON_SOURCES)

if RPCGEN
SUFFIXES = .x
.x.c:
	rm -f $@ $@-t $@-t2
	rpcgen -c -o $@-t $<
if GLIBC_RPCGEN
	perl -w rpcgen_fix.pl $@-t > $@-t2
	chmod 444 $@-t2
	mv $@-t2 $@
endif

.x.h:
	rm -f $@ $@-t
	rpcgen -h -o $@-t $<
if GLIBC_RPCGEN
	perl -pi -e 's/\t/        /g' $@-t
	chmod 444 $@-t
	mv $@-t $@
endif
endif

remote_protocol.c: remote_protocol.h

if WITH_LIBVIRTD

UUID=$(shell uuidgen)

sbin_PROGRAMS = libvirtd

confdir = $(sysconfdir)/libvirt/
conf_DATA = libvirtd.conf

augeasdir = $(datadir)/augeas/lenses
augeas_DATA = libvirtd.aug libvirtd_qemu.aug

augeastestsdir = $(datadir)/augeas/lenses/tests
augeastests_DATA = test_libvirtd.aug test_libvirtd_qemu.aug

libvirtd_SOURCES = $(DAEMON_SOURCES)

#-D_XOPEN_SOURCE=600 -D_XOPEN_SOURCE_EXTENDED=1 -D_POSIX_C_SOURCE=199506L
libvirtd_CFLAGS = \
	-I$(top_srcdir)/gnulib/lib -I../gnulib/lib \
	-I$(top_srcdir)/include -I$(top_builddir)/include \
	-I$(top_srcdir)/src \
	$(LIBXML_CFLAGS) $(GNUTLS_CFLAGS) $(SASL_CFLAGS) \
	$(POLKIT_CFLAGS) \
	$(WARN_CFLAGS) -DLOCAL_STATE_DIR="\"$(localstatedir)\"" \
	$(COVERAGE_CFLAGS) \
	-DSYSCONF_DIR="\"$(sysconfdir)\"" \
	-DQEMUD_PID_FILE="\"$(QEMUD_PID_FILE)\"" \
	-DREMOTE_PID_FILE="\"$(REMOTE_PID_FILE)\"" \
	-DGETTEXT_PACKAGE=\"$(PACKAGE)\"

libvirtd_LDFLAGS = \
	$(WARN_CFLAGS) $(LIBXML_LIBS) $(GNUTLS_LIBS) $(SASL_LIBS) \
	$(COVERAGE_LDFLAGS) \
	$(POLKIT_LIBS)

libvirtd_LDADD =					\
		../gnulib/lib/libgnu.la

if ! WITH_DRIVER_MODULES
if WITH_QEMU
libvirtd_LDADD += ../src/libvirt_driver_qemu.la
endif

if WITH_LXC
libvirtd_LDADD += ../src/libvirt_driver_lxc.la
endif

if WITH_UML
libvirtd_LDADD += ../src/libvirt_driver_uml.la
endif

if WITH_STORAGE_DIR
libvirtd_LDADD += ../src/libvirt_driver_storage.la
endif

if WITH_NETWORK
libvirtd_LDADD += ../src/libvirt_driver_network.la
endif

if WITH_NODE_DEVICES
libvirtd_LDADD += ../src/libvirt_driver_nodedev.la
endif
endif

libvirtd_LDADD += ../src/libvirt.la

if HAVE_POLKIT
policydir = $(datadir)/PolicyKit/policy
endif

if HAVE_AVAHI
libvirtd_SOURCES += $(AVAHI_SOURCES)
libvirtd_CFLAGS += $(AVAHI_CFLAGS)
libvirtd_LDADD += $(AVAHI_LIBS)
endif

libvirtd_DEPENDENCIES = $(libvirtd_LDADD)


default_xml_dest = libvirt/qemu/networks/default.xml
install-data-local: install-init install-data-sasl install-data-polkit
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

uninstall-local:: uninstall-init uninstall-data-sasl install-data-polkit
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

if HAVE_POLKIT
install-data-polkit:: install-init
	mkdir -p $(DESTDIR)$(policydir)
	$(INSTALL_DATA) $(srcdir)/libvirtd.policy $(DESTDIR)$(policydir)/org.libvirt.unix.policy
uninstall-data-polkit:: install-init
	rm -f $(DESTDIR)$(policydir)/org.libvirt.unix.policy
else
install-data-polkit::
uninstall-data-polkit::
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

check-local:
	if [ -x $(AUGPARSE) ]; then $(AUGPARSE) -I $(srcdir) test_libvirtd.aug ; fi

else

install-init:
uninstall-init:

endif # DBUS_INIT_SCRIPTS_RED_HAT

endif # WITH_LIBVIRTD

CLEANFILES = libvirtd.init
CLEANFILES += *.cov *.gcov .libs/*.gcda .libs/*.gcno *.gcno *.gcda
