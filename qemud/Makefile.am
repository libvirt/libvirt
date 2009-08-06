## Process this file with automake to produce Makefile.in

DAEMON_SOURCES =					\
		event.c event.h				\
		qemud.c qemud.h				\
		remote.c remote.h			\
		dispatch.c dispatch.h			\
		remote_dispatch_prototypes.h		\
		remote_dispatch_table.h			\
		remote_dispatch_args.h			\
		remote_dispatch_ret.h			\
		remote_protocol.h remote_protocol.c

AVAHI_SOURCES =						\
		mdns.c mdns.h

DISTCLEANFILES =
EXTRA_DIST =						\
	default-network.xml				\
	remote_generate_stubs.pl rpcgen_fix.pl		\
	remote_protocol.x				\
	libvirtd.conf					\
	libvirtd.init.in				\
	libvirtd.policy-0				\
	libvirtd.policy-1				\
	libvirtd.sasl					\
	libvirtd.sysconf				\
	libvirtd.aug                                    \
	libvirtd_qemu.aug                               \
	libvirtd.logrotate.in                           \
	test_libvirtd.aug                               \
	test_libvirtd_qemu.aug                          \
	$(AVAHI_SOURCES)				\
	$(DAEMON_SOURCES)

BUILT_SOURCES =

if HAVE_RPCGEN
#
# Maintainer-only target for re-generating the derived .c/.h source
# files, which are actually derived from the .x file.
#
# For committing protocol changes to CVS, the GLIBC rpcgen *must*
# be used.
#
# Support for non-GLIB rpcgen is here as a convenience for
# non-Linux people needing to test changes during dev.
#
rpcgen:
	rm -f rp.c-t rp.h-t rp.c-t1 rp.c-t2 rp.h-t1
	$(RPCGEN) -h -o rp.h-t $(srcdir)/remote_protocol.x
	$(RPCGEN) -c -o rp.c-t $(srcdir)/remote_protocol.x
if HAVE_GLIBC_RPCGEN
	perl -w $(srcdir)/rpcgen_fix.pl rp.h-t > rp.h-t1
	perl -w $(srcdir)/rpcgen_fix.pl rp.c-t > rp.c-t1
	(echo '#include <config.h>'; cat rp.c-t1) > rp.c-t2
	chmod 0444 rp.c-t2 rp.h-t1
	mv -f rp.h-t1 $(srcdir)/remote_protocol.h
	mv -f rp.c-t2 $(srcdir)/remote_protocol.c
	rm -f rp.c-t rp.h-t rp.c-t1
else
	chmod 0444 rp.c-t rp.h-t
	mv -f rp.h-t $(srcdir)/remote_protocol.h
	mv -f rp.c-t $(srcdir)/remote_protocol.c
endif
endif

remote_protocol.c: remote_protocol.h

if WITH_LIBVIRTD

UUID=$(shell uuidgen 2>/dev/null)

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

libvirtd_LDFLAGS = 					\
	$(WARN_CFLAGS) 					\
	$(COVERAGE_LDFLAGS)

libvirtd_LDADD =					\
	$(LIBXML_LIBS)					\
	$(GNUTLS_LIBS)					\
	$(SASL_LIBS)					\
	$(POLKIT_LIBS)

if WITH_DRIVER_MODULES
  libvirtd_LDADD += ../src/libvirt_driver.la
  libvirtd_LDADD += ../src/libvirt_util.la
else
if WITH_QEMU
    libvirtd_LDADD += ../src/libvirt_driver_qemu.la
endif

if WITH_LXC
    libvirtd_LDADD += ../src/libvirt_driver_lxc.la
endif

if WITH_UML
    libvirtd_LDADD += ../src/libvirt_driver_uml.la
endif

if WITH_ONE
    libvirtd_LDADD += ../src/libvirt_driver_one.la
endif

if WITH_STORAGE_DIR
    libvirtd_LDADD += ../src/libvirt_driver_storage.la
endif

if WITH_NETWORK
    libvirtd_LDADD += ../src/libvirt_driver_network.la
endif

if WITH_NETCF
    libvirtd_LDADD += ../src/libvirt_driver_interface.la
endif

if WITH_NODE_DEVICES
    libvirtd_LDADD += ../src/libvirt_driver_nodedev.la
endif
endif

libvirtd_LDADD += ../src/libvirt.la

if HAVE_POLKIT
if HAVE_POLKIT0
policydir = $(datadir)/PolicyKit/policy
policyfile = libvirtd.policy-0
else
policydir = $(datadir)/polkit-1/actions
policyfile = libvirtd.policy-1
endif
endif

if HAVE_AVAHI
libvirtd_SOURCES += $(AVAHI_SOURCES)
libvirtd_CFLAGS += $(AVAHI_CFLAGS)
libvirtd_LDADD += $(AVAHI_LIBS)
endif


default_xml_dest = libvirt/qemu/networks/default.xml
install-data-local: install-init install-data-sasl install-data-polkit \
                    install-logrotate
	mkdir -p $(DESTDIR)$(sysconfdir)/libvirt/qemu/networks/autostart
	$(INSTALL_DATA) $(srcdir)/default-network.xml \
	  $(DESTDIR)$(sysconfdir)/$(default_xml_dest)
	test -z "$(UUID)" || \
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
	$(INSTALL_DATA) $(srcdir)/$(policyfile) $(DESTDIR)$(policydir)/org.libvirt.unix.policy
uninstall-data-polkit:: install-init
	rm -f $(DESTDIR)$(policydir)/org.libvirt.unix.policy
else
install-data-polkit::
uninstall-data-polkit::
endif


remote.c: remote_dispatch_prototypes.h \
	  remote_dispatch_table.h \
	  remote_dispatch_args.h \
	  remote_dispatch_ret.h

remote_dispatch_prototypes.h: $(srcdir)/remote_generate_stubs.pl remote_protocol.x
	perl -w $(srcdir)/remote_generate_stubs.pl -p $(srcdir)/remote_protocol.x > $@

remote_dispatch_table.h: $(srcdir)/remote_generate_stubs.pl remote_protocol.x
	perl -w $(srcdir)/remote_generate_stubs.pl -t $(srcdir)/remote_protocol.x > $@

remote_dispatch_args.h: $(srcdir)/remote_generate_stubs.pl remote_protocol.x
	perl -w $(srcdir)/remote_generate_stubs.pl -a $(srcdir)/remote_protocol.x > $@

remote_dispatch_ret.h: $(srcdir)/remote_generate_stubs.pl remote_protocol.x
	perl -w $(srcdir)/remote_generate_stubs.pl -r $(srcdir)/remote_protocol.x > $@

BUILT_SOURCES += libvirtd.logrotate

libvirtd.logrotate: libvirtd.logrotate.in
	sed						\
	    -e s!\@localstatedir\@!@localstatedir@!g	\
	    < $< > $@-t
	mv $@-t $@

install-logrotate: libvirtd.logrotate
	mkdir -p $(DESTDIR)$(localstatedir)/log/libvirt/qemu/
	mkdir -p $(DESTDIR)$(sysconfdir)/logrotate.d/
	$(INSTALL_DATA) $< $(DESTDIR)$(sysconfdir)/logrotate.d/libvirtd

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

BUILT_SOURCES += libvirtd.init

libvirtd.init: libvirtd.init.in
	sed						\
	    -e s!\@localstatedir\@!@localstatedir@!g	\
	    -e s!\@sbindir\@!@sbindir@!g		\
	    -e s!\@sysconfdir\@!@sysconfdir@!g		\
	    < $< > $@-t
	chmod a+x $@-t
	mv $@-t $@

check-local:
	test -x '$(AUGPARSE)' \
	  && '$(AUGPARSE)' -I $(srcdir) $(srcdir)/test_libvirtd.aug || :
	test -x '$(AUGPARSE)' \
	  && '$(AUGPARSE)' -I $(srcdir) $(srcdir)/test_libvirtd_qemu.aug || :

else

install-init:
uninstall-init:
libvirtd.init:

endif # DBUS_INIT_SCRIPTS_RED_HAT

# This must be added last, since functions it provides/replaces
# are used by nearly every other library.
libvirtd_LDADD += ../gnulib/lib/libgnu.la $(LIBSOCKET)

endif # WITH_LIBVIRTD

CLEANFILES = $(BUILT_SOURCES)
CLEANFILES += *.cov *.gcov .libs/*.gcda .libs/*.gcno *.gcno *.gcda
