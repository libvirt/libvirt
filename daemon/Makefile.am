## Process this file with automake to produce Makefile.in

CLEANFILES =

DAEMON_SOURCES =					\
		event.c event.h				\
		libvirtd.c libvirtd.h			\
		remote.c remote.h			\
		dispatch.c dispatch.h			\
		stream.c stream.h			\
		remote_dispatch_prototypes.h		\
		remote_dispatch_table.h			\
		remote_dispatch_args.h			\
		remote_dispatch_ret.h			\
		qemu_dispatch_prototypes.h		\
		qemu_dispatch_table.h			\
		qemu_dispatch_args.h			\
		qemu_dispatch_ret.h			\
		../src/remote/remote_protocol.c		\
		../src/remote/qemu_protocol.c

AVAHI_SOURCES =						\
		mdns.c mdns.h

DISTCLEANFILES =
EXTRA_DIST =						\
	remote_generate_stubs.pl			\
	libvirtd.conf					\
	libvirtd.init.in				\
	libvirtd.policy-0				\
	libvirtd.policy-1				\
	libvirtd.sasl					\
	libvirtd.sysconf				\
	libvirtd.aug                                    \
	libvirtd.qemu.logrotate.in                      \
	libvirtd.lxc.logrotate.in                       \
	libvirtd.uml.logrotate.in                       \
	test_libvirtd.aug                               \
	THREADING.txt					\
	libvirtd.pod.in					\
	libvirtd.stp					\
	$(AVAHI_SOURCES)				\
	$(DAEMON_SOURCES)

BUILT_SOURCES =

if WITH_LIBVIRTD

man_MANS = libvirtd.8

sbin_PROGRAMS = libvirtd

confdir = $(sysconfdir)/libvirt/
conf_DATA = libvirtd.conf

augeasdir = $(datadir)/augeas/lenses
augeas_DATA = libvirtd.aug

augeastestsdir = $(datadir)/augeas/lenses/tests
augeastests_DATA = test_libvirtd.aug

POD2MAN = pod2man -c "Virtualization Support" \
			-r "$(PACKAGE)-$(VERSION)" -s 8

libvirtd.pod: libvirtd.pod.in
	sed \
	    -e 's![@]sysconfdir[@]!$(sysconfdir)!g' \
	    -e 's![@]localstatedir[@]!$(localstatedir)!g' \
	    -e 's![@]remote_pid_file[@]!$(REMOTE_PID_FILE)!g' \
	    < $< > $@-t
	mv $@-t $@

libvirtd.8: libvirtd.pod
	$(AM_V_GEN)$(POD2MAN) $< $@

libvirtd_SOURCES = $(DAEMON_SOURCES)

#-D_XOPEN_SOURCE=600 -D_XOPEN_SOURCE_EXTENDED=1 -D_POSIX_C_SOURCE=199506L
libvirtd_CFLAGS = \
	-I$(top_srcdir)/gnulib/lib -I../gnulib/lib \
	-I$(top_srcdir)/include -I$(top_builddir)/include \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/util \
	-I$(top_srcdir)/src/conf \
	-I$(top_srcdir)/src/remote \
	$(LIBXML_CFLAGS) $(GNUTLS_CFLAGS) $(SASL_CFLAGS) \
	$(POLKIT_CFLAGS) \
	$(WARN_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	-DQEMUD_PID_FILE="\"$(QEMUD_PID_FILE)\"" \
	-DREMOTE_PID_FILE="\"$(REMOTE_PID_FILE)\""

libvirtd_LDFLAGS =					\
	$(WARN_CFLAGS)					\
	$(COVERAGE_LDFLAGS)

libvirtd_LDADD =					\
	$(LIBXML_LIBS)					\
	$(GNUTLS_LIBS)					\
	$(SASL_LIBS)					\
	$(POLKIT_LIBS)

libvirtd_LDADD += ../src/libvirt-qemu.la

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

if WITH_SECRETS
    libvirtd_LDADD += ../src/libvirt_driver_secret.la
endif

if WITH_NWFILTER
    libvirtd_LDADD += ../src/libvirt_driver_nwfilter.la
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

EXTRA_DIST += probes.d libvirtd.stp

if WITH_DTRACE
libvirtd_LDADD += probes.o
nodist_libvirtd_SOURCES = probes.h

BUILT_SOURCES += probes.h

tapsetdir = $(datadir)/systemtap/tapsets
tapset_DATA = libvirtd.stp

probes.h: probes.d
	$(AM_V_GEN)$(DTRACE) -o $@ -h -s $<

probes.o: probes.d
	$(AM_V_GEN)$(DTRACE) -o $@ -G -s $<

CLEANFILES += probes.h probes.o
endif

install-data-local: install-init install-data-sasl install-data-polkit \
                    install-logrotate
	mkdir -p $(DESTDIR)$(localstatedir)/log/libvirt
	mkdir -p $(DESTDIR)$(localstatedir)/run/libvirt
	mkdir -p $(DESTDIR)$(localstatedir)/lib/libvirt

uninstall-local:: uninstall-init uninstall-data-sasl uninstall-data-polkit
	rmdir $(DESTDIR)$(localstatedir)/log/libvirt || :
	rmdir $(DESTDIR)$(localstatedir)/run/libvirt || :
	rmdir $(DESTDIR)$(localstatedir)/lib/libvirt || :

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


remote.c: \
	remote_dispatch_prototypes.h \
	remote_dispatch_table.h \
	qemu_dispatch_prototypes.h \
	qemu_dispatch_table.h

remote.h: \
	remote_dispatch_args.h \
	remote_dispatch_ret.h \
	qemu_dispatch_args.h \
	qemu_dispatch_ret.h

REMOTE_PROTOCOL = $(top_srcdir)/src/remote/remote_protocol.x
QEMU_PROTOCOL = $(top_srcdir)/src/remote/qemu_protocol.x

remote_dispatch_prototypes.h: $(srcdir)/remote_generate_stubs.pl $(REMOTE_PROTOCOL)
	$(AM_V_GEN)perl -w $(srcdir)/remote_generate_stubs.pl -c -p remote $(REMOTE_PROTOCOL) > $@

remote_dispatch_table.h: $(srcdir)/remote_generate_stubs.pl $(REMOTE_PROTOCOL)
	$(AM_V_GEN)perl -w $(srcdir)/remote_generate_stubs.pl -c -t remote $(REMOTE_PROTOCOL) > $@

remote_dispatch_args.h: $(srcdir)/remote_generate_stubs.pl $(REMOTE_PROTOCOL)
	$(AM_V_GEN)perl -w $(srcdir)/remote_generate_stubs.pl -c -a remote $(REMOTE_PROTOCOL) > $@

remote_dispatch_ret.h: $(srcdir)/remote_generate_stubs.pl $(REMOTE_PROTOCOL)
	$(AM_V_GEN)perl -w $(srcdir)/remote_generate_stubs.pl -c -r remote $(REMOTE_PROTOCOL) > $@

qemu_dispatch_prototypes.h: $(srcdir)/remote_generate_stubs.pl $(QEMU_PROTOCOL)
	$(AM_V_GEN)perl -w $(srcdir)/remote_generate_stubs.pl -p qemu $(QEMU_PROTOCOL) > $@

qemu_dispatch_table.h: $(srcdir)/remote_generate_stubs.pl $(QEMU_PROTOCOL)
	$(AM_V_GEN)perl -w $(srcdir)/remote_generate_stubs.pl -t qemu $(QEMU_PROTOCOL) > $@

qemu_dispatch_args.h: $(srcdir)/remote_generate_stubs.pl $(QEMU_PROTOCOL)
	$(AM_V_GEN)perl -w $(srcdir)/remote_generate_stubs.pl -a qemu $(QEMU_PROTOCOL) > $@

qemu_dispatch_ret.h: $(srcdir)/remote_generate_stubs.pl $(QEMU_PROTOCOL)
	$(AM_V_GEN)perl -w $(srcdir)/remote_generate_stubs.pl -r qemu $(QEMU_PROTOCOL) > $@

LOGROTATE_CONFS = libvirtd.qemu.logrotate libvirtd.lxc.logrotate \
                  libvirtd.uml.logrotate

BUILT_SOURCES += $(LOGROTATE_CONFS)

libvirtd.qemu.logrotate: libvirtd.qemu.logrotate.in
	sed							\
	    -e 's![@]localstatedir[@]!$(localstatedir)!g'	\
	    < $< > $@-t
	mv $@-t $@

libvirtd.lxc.logrotate: libvirtd.lxc.logrotate.in
	$(AM_V_GEN)sed						\
	    -e 's![@]localstatedir[@]!$(localstatedir)!g'	\
	    < $< > $@-t &&					\
	    mv $@-t $@

libvirtd.uml.logrotate: libvirtd.uml.logrotate.in
	$(AM_V_GEN)sed						\
	    -e 's![@]localstatedir[@]!$(localstatedir)!g'	\
	    < $< > $@-t &&					\
	    mv $@-t $@

install-logrotate: $(LOGROTATE_CONFS)
	mkdir -p $(DESTDIR)$(localstatedir)/log/libvirt/qemu/
	mkdir -p $(DESTDIR)$(localstatedir)/log/libvirt/lxc/
	mkdir -p $(DESTDIR)$(localstatedir)/log/libvirt/uml/
	mkdir -p $(DESTDIR)$(sysconfdir)/logrotate.d/
	$(INSTALL_DATA) libvirtd.qemu.logrotate $(DESTDIR)$(sysconfdir)/logrotate.d/libvirtd.qemu
	$(INSTALL_DATA) libvirtd.lxc.logrotate $(DESTDIR)$(sysconfdir)/logrotate.d/libvirtd.lxc
	$(INSTALL_DATA) libvirtd.uml.logrotate $(DESTDIR)$(sysconfdir)/logrotate.d/libvirtd.uml

if LIBVIRT_INIT_SCRIPT_RED_HAT
install-init: libvirtd.init
	mkdir -p $(DESTDIR)$(sysconfdir)/rc.d/init.d
	$(INSTALL_SCRIPT) libvirtd.init \
	  $(DESTDIR)$(sysconfdir)/rc.d/init.d/libvirtd
	mkdir -p $(DESTDIR)$(sysconfdir)/sysconfig
	$(INSTALL_DATA) $(srcdir)/libvirtd.sysconf \
	  $(DESTDIR)$(sysconfdir)/sysconfig/libvirtd

uninstall-init:
	rm -f $(DESTDIR)$(sysconfdir)/rc.d/init.d/libvirtd \
		$(DESTDIR)$(sysconfdir)/sysconfig/libvirtd

BUILT_SOURCES += libvirtd.init

libvirtd.init: libvirtd.init.in $(top_builddir)/config.status
	$(AM_V_GEN)sed					\
	    -e s!\@localstatedir\@!@localstatedir@!g	\
	    -e s!\@sbindir\@!@sbindir@!g		\
	    -e s!\@sysconfdir\@!@sysconfdir@!g		\
	    < $< > $@-t &&				\
	    chmod a+x $@-t &&				\
	    mv $@-t $@

check-local:
	test -x '$(AUGPARSE)' \
	  && '$(AUGPARSE)' -I $(srcdir) $(srcdir)/test_libvirtd.aug || :

else

install-init:
uninstall-init:
libvirtd.init:

endif # LIBVIRT_INIT_SCRIPT_RED_HAT

# This must be added last, since functions it provides/replaces
# are used by nearly every other library.
libvirtd_LDADD += ../gnulib/lib/libgnu.la $(LIBSOCKET)

else # WITH_LIBVIRTD
install-data-local: install-data-sasl
uninstall-local:: uninstall-data-sasl
endif # WITH_LIBVIRTD

# This is needed for clients too, so can't wrap in
# the WITH_LIBVIRTD conditional
if HAVE_SASL
install-data-sasl:
	mkdir -p $(DESTDIR)$(sysconfdir)/sasl2/
	$(INSTALL_DATA) $(srcdir)/libvirtd.sasl $(DESTDIR)$(sysconfdir)/sasl2/libvirt.conf

uninstall-data-sasl:
	rm -f $(DESTDIR)$(sysconfdir)/sasl2/libvirt.conf
	rmdir $(DESTDIR)$(sysconfdir)/sasl2/
else
install-data-sasl:
uninstall-data-sasl:
endif


CLEANFILES += $(BUILT_SOURCES) $(man_MANS) libvirtd.pod
CLEANFILES += *.cov *.gcov .libs/*.gcda .libs/*.gcno *.gcno *.gcda
