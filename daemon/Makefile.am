## Process this file with automake to produce Makefile.in

## Copyright (C) 2005-2014 Red Hat, Inc.
##
## This library is free software; you can redistribute it and/or
## modify it under the terms of the GNU Lesser General Public
## License as published by the Free Software Foundation; either
## version 2.1 of the License, or (at your option) any later version.
##
## This library is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## Lesser General Public License for more details.
##
## You should have received a copy of the GNU Lesser General Public
## License along with this library.  If not, see
## <http://www.gnu.org/licenses/>.

INCLUDES = \
	-I$(top_builddir)/gnulib/lib -I$(top_srcdir)/gnulib/lib \
	-I$(top_srcdir) \
	-I$(top_builddir)/include -I$(top_srcdir)/include \
	-I$(top_builddir)/src -I$(top_srcdir)/src \
	-I$(top_srcdir)/src/util \
	-I$(top_srcdir)/src/conf \
	-I$(top_srcdir)/src/rpc \
	-I$(top_srcdir)/src/remote \
	-I$(top_srcdir)/src/access \
	$(GETTEXT_CPPFLAGS)

CLEANFILES =

DAEMON_GENERATED =			\
		remote_dispatch.h	\
		lxc_dispatch.h		\
		qemu_dispatch.h		\
		$(NULL)

DAEMON_SOURCES =					\
		libvirtd.c libvirtd.h			\
		remote.c remote.h			\
		stream.c stream.h			\
		$(DAEMON_GENERATED)

LIBVIRTD_CONF_SOURCES = libvirtd-config.c libvirtd-config.h

DISTCLEANFILES =
EXTRA_DIST =						\
	remote_dispatch.h				\
	lxc_dispatch.h					\
	qemu_dispatch.h					\
	libvirtd.conf					\
	libvirtd.init.in				\
	libvirtd.upstart				\
	libvirtd.policy.in				\
	libvirtd.sasl					\
	libvirtd.service.in				\
	libvirtd.sysconf				\
	libvirtd.sysctl					\
	libvirtd.aug                                    \
	libvirtd.logrotate.in                           \
	libvirtd.qemu.logrotate.in                      \
	libvirtd.lxc.logrotate.in                       \
	libvirtd.uml.logrotate.in                       \
	test_libvirtd.aug.in                             \
	THREADS.txt					\
	libvirtd.pod.in					\
	libvirtd.8.in					\
	$(DAEMON_SOURCES)				\
	$(LIBVIRTD_CONF_SOURCES)			\
	$(NULL)

BUILT_SOURCES =

REMOTE_PROTOCOL = $(top_srcdir)/src/remote/remote_protocol.x
LXC_PROTOCOL = $(top_srcdir)/src/remote/lxc_protocol.x
QEMU_PROTOCOL = $(top_srcdir)/src/remote/qemu_protocol.x

remote_dispatch.h: $(srcdir)/../src/rpc/gendispatch.pl \
		$(REMOTE_PROTOCOL)
	$(AM_V_GEN)$(PERL) -w $(srcdir)/../src/rpc/gendispatch.pl \
	  --mode=server remote REMOTE $(REMOTE_PROTOCOL) \
	  > $(srcdir)/remote_dispatch.h

lxc_dispatch.h: $(srcdir)/../src/rpc/gendispatch.pl \
		$(LXC_PROTOCOL)
	$(AM_V_GEN)$(PERL) -w $(srcdir)/../src/rpc/gendispatch.pl \
	  --mode=server lxc LXC $(LXC_PROTOCOL) \
	  > $(srcdir)/lxc_dispatch.h

qemu_dispatch.h: $(srcdir)/../src/rpc/gendispatch.pl \
		$(QEMU_PROTOCOL)
	$(AM_V_GEN)$(PERL) -w $(srcdir)/../src/rpc/gendispatch.pl \
	  --mode=server qemu QEMU $(QEMU_PROTOCOL) \
	  > $(srcdir)/qemu_dispatch.h

if WITH_LIBVIRTD

# Build a convenience library, for reuse in tests/libvirtdconftest
noinst_LTLIBRARIES = libvirtd_conf.la
libvirtd_conf_la_SOURCES = $(LIBVIRTD_CONF_SOURCES)
libvirtd_conf_la_CFLAGS = \
	$(LIBXML_CFLAGS) \
	$(XDR_CFLAGS) \
	$(WARN_CFLAGS) $(PIE_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(NULL)
libvirtd_conf_la_LDFLAGS =				\
	$(RELRO_LDFLAGS)				\
	$(PIE_LDFLAGS)					\
	$(COVERAGE_LDFLAGS)				\
	$(NO_INDIRECT_LDFLAGS)				\
	$(NULL)
libvirtd_conf_la_LIBADD = $(LIBXML_LIBS)

man8_MANS = libvirtd.8

sbin_PROGRAMS = libvirtd

confdir = $(sysconfdir)/libvirt/
conf_DATA = libvirtd.conf

augeasdir = $(datadir)/augeas/lenses
augeas_DATA = libvirtd.aug

augeastestsdir = $(datadir)/augeas/lenses/tests
augeastests_DATA = test_libvirtd.aug

CLEANFILES += test_libvirtd.aug

libvirtd.8: $(srcdir)/libvirtd.8.in
	$(AM_V_GEN)sed \
	    -e 's|[@]sysconfdir[@]|$(sysconfdir)|g' \
	    -e 's|[@]localstatedir[@]|$(localstatedir)|g' \
	    < $< > $@-t && \
	mv $@-t $@

libvirtd_SOURCES = $(DAEMON_SOURCES)

#-D_XOPEN_SOURCE=600 -D_XOPEN_SOURCE_EXTENDED=1 -D_POSIX_C_SOURCE=199506L
libvirtd_CFLAGS = \
	$(LIBXML_CFLAGS) $(GNUTLS_CFLAGS) $(SASL_CFLAGS) \
	$(XDR_CFLAGS) $(POLKIT_CFLAGS) $(DBUS_CFLAGS) $(LIBNL_CFLAGS) \
	$(WARN_CFLAGS) $(PIE_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	-DQEMUD_PID_FILE="\"$(QEMUD_PID_FILE)\""

libvirtd_LDFLAGS =					\
	$(RELRO_LDFLAGS)				\
	$(PIE_LDFLAGS)					\
	$(COVERAGE_LDFLAGS)				\
	$(NO_INDIRECT_LDFLAGS)				\
	$(NULL)

libvirtd_LDADD =					\
	$(LIBXML_LIBS)					\
	$(GNUTLS_LIBS)					\
	$(SASL_LIBS)					\
	$(DBUS_LIBS)					\
	$(POLKIT_LIBS)					\
	$(LIBNL_LIBS)

if WITH_DTRACE_PROBES
libvirtd_LDADD += ../src/libvirt_probes.lo
endif WITH_DTRACE_PROBES

libvirtd_LDADD += \
	libvirtd_conf.la \
	../src/libvirt-lxc.la \
	../src/libvirt-qemu.la \
	../src/libvirt_driver_remote.la \
	$(NULL)

if ! WITH_DRIVER_MODULES
if WITH_QEMU
    libvirtd_LDADD += ../src/libvirt_driver_qemu.la
if WITH_DTRACE_PROBES
    libvirtd_LDADD += ../src/libvirt_qemu_probes.lo
endif WITH_DTRACE_PROBES
endif WITH_QEMU

if WITH_LXC
    libvirtd_LDADD += ../src/libvirt_driver_lxc.la
endif WITH_LXC

if WITH_XEN
    libvirtd_LDADD += ../src/libvirt_driver_xen.la
endif WITH_XEN

if WITH_LIBXL
    libvirtd_LDADD += ../src/libvirt_driver_libxl.la
endif WITH_LIBXL

if WITH_UML
    libvirtd_LDADD += ../src/libvirt_driver_uml.la
endif WITH_UML

if WITH_VBOX
    libvirtd_LDADD += ../src/libvirt_driver_vbox.la
endif WITH_VBOX

if WITH_STORAGE
    libvirtd_LDADD += ../src/libvirt_driver_storage.la
endif WITH_STORAGE

if WITH_NETWORK
    libvirtd_LDADD += ../src/libvirt_driver_network.la
endif WITH_NETWORK

if WITH_INTERFACE
    libvirtd_LDADD += ../src/libvirt_driver_interface.la
endif WITH_INTERFACE

if WITH_NODE_DEVICES
    libvirtd_LDADD += ../src/libvirt_driver_nodedev.la
endif WITH_NODE_DEVICES

if WITH_SECRETS
    libvirtd_LDADD += ../src/libvirt_driver_secret.la
endif WITH_SECRETS

if WITH_NWFILTER
    libvirtd_LDADD += ../src/libvirt_driver_nwfilter.la
endif WITH_NWFILTER
endif ! WITH_DRIVER_MODULES

libvirtd_LDADD += ../src/libvirt.la

if WITH_POLKIT
if WITH_POLKIT0
policydir = $(datadir)/PolicyKit/policy
policyauth = auth_admin_keep_session
else ! WITH_POLKIT0
policydir = $(datadir)/polkit-1/actions
policyauth = auth_admin_keep
endif ! WITH_POLKIT0
endif WITH_POLKIT

libvirtd.policy: libvirtd.policy.in $(top_builddir)/config.status
	$(AM_V_GEN) sed \
	    -e 's|[@]authaction[@]|$(policyauth)|g' \
	    < $< > $@-t && \
	mv $@-t $@
BUILT_SOURCES += libvirtd.policy

install-data-local: install-init-redhat install-init-systemd \
		install-init-upstart \
		install-data-sasl install-data-polkit \
		install-logrotate install-sysctl
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/log/libvirt \
		   $(DESTDIR)$(localstatedir)/run/libvirt \
		   $(DESTDIR)$(localstatedir)/lib/libvirt

uninstall-local:: uninstall-init-redhat uninstall-init-systemd \
		uninstall-init-upstart \
		uninstall-data-sasl uninstall-data-polkit \
		uninstall-logrotate uninstall-sysctl
	rmdir $(DESTDIR)$(localstatedir)/log/libvirt || :
	rmdir $(DESTDIR)$(localstatedir)/run/libvirt || :
	rmdir $(DESTDIR)$(localstatedir)/lib/libvirt || :

if WITH_POLKIT
install-data-polkit::
	$(MKDIR_P) $(DESTDIR)$(policydir)
	$(INSTALL_DATA) libvirtd.policy $(DESTDIR)$(policydir)/org.libvirt.unix.policy
uninstall-data-polkit::
	rm -f $(DESTDIR)$(policydir)/org.libvirt.unix.policy
	rmdir $(DESTDIR)$(policydir) || :
else ! WITH_POLKIT
install-data-polkit::
uninstall-data-polkit::
endif ! WITH_POLKIT

remote.c: $(DAEMON_GENERATED)
remote.h: $(DAEMON_GENERATED)

LOGROTATE_CONFS = libvirtd.qemu.logrotate libvirtd.lxc.logrotate \
		  libvirtd.uml.logrotate libvirtd.logrotate

BUILT_SOURCES += $(LOGROTATE_CONFS)

libvirtd.logrotate: libvirtd.logrotate.in
	$(AM_V_GEN)sed						\
	    -e 's|[@]localstatedir[@]|$(localstatedir)|g'	\
	    < $< > $@-t && \
	mv $@-t $@

libvirtd.qemu.logrotate: libvirtd.qemu.logrotate.in
	$(AM_V_GEN)sed						\
	    -e 's|[@]localstatedir[@]|$(localstatedir)|g'	\
	    < $< > $@-t && \
	mv $@-t $@

libvirtd.lxc.logrotate: libvirtd.lxc.logrotate.in
	$(AM_V_GEN)sed						\
	    -e 's|[@]localstatedir[@]|$(localstatedir)|g'	\
	    < $< > $@-t &&					\
	    mv $@-t $@

libvirtd.uml.logrotate: libvirtd.uml.logrotate.in
	$(AM_V_GEN)sed						\
	    -e 's|[@]localstatedir[@]|$(localstatedir)|g'	\
	    < $< > $@-t &&					\
	    mv $@-t $@

install-logrotate: $(LOGROTATE_CONFS)
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/log/libvirt/qemu/ \
		   $(DESTDIR)$(localstatedir)/log/libvirt/lxc/ \
		   $(DESTDIR)$(localstatedir)/log/libvirt/uml/ \
		   $(DESTDIR)$(sysconfdir)/logrotate.d/
	$(INSTALL_DATA) libvirtd.logrotate \
		$(DESTDIR)$(sysconfdir)/logrotate.d/libvirtd
	$(INSTALL_DATA) libvirtd.qemu.logrotate \
		$(DESTDIR)$(sysconfdir)/logrotate.d/libvirtd.qemu
	$(INSTALL_DATA) libvirtd.lxc.logrotate \
		$(DESTDIR)$(sysconfdir)/logrotate.d/libvirtd.lxc
	$(INSTALL_DATA) libvirtd.uml.logrotate \
		$(DESTDIR)$(sysconfdir)/logrotate.d/libvirtd.uml

uninstall-logrotate:
	rm -f $(DESTDIR)$(sysconfdir)/logrotate.d/libvirtd \
	      $(DESTDIR)$(sysconfdir)/logrotate.d/libvirtd.qemu \
	      $(DESTDIR)$(sysconfdir)/logrotate.d/libvirtd.lxc \
	      $(DESTDIR)$(sysconfdir)/logrotate.d/libvirtd.uml
	rmdir $(DESTDIR)$(localstatedir)/log/libvirt/qemu || :
	rmdir $(DESTDIR)$(localstatedir)/log/libvirt/lxc || :
	rmdir $(DESTDIR)$(localstatedir)/log/libvirt/uml || :
	rmdir $(DESTDIR)$(sysconfdir)/logrotate.d || :

install-sysconfig:
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/sysconfig
	$(INSTALL_DATA) $(srcdir)/libvirtd.sysconf \
	  $(DESTDIR)$(sysconfdir)/sysconfig/libvirtd
uninstall-sysconfig:
	rm -f $(DESTDIR)$(sysconfdir)/sysconfig/libvirtd
	rmdir $(DESTDIR)$(sysconfdir)/sysconfig || :

if WITH_SYSCTL
# Use $(prefix)/lib rather than $(libdir), since man sysctl.d insists on
# /usr/lib/sysctl.d/ even when libdir is /usr/lib64
install-sysctl:
	$(MKDIR_P) $(DESTDIR)$(prefix)/lib/sysctl.d
	$(INSTALL_DATA) $(srcdir)/libvirtd.sysctl \
	  $(DESTDIR)$(prefix)/lib/sysctl.d/libvirtd.conf

uninstall-sysctl:
	rm -f $(DESTDIR)$(prefix)/lib/sysctl.d/libvirtd.conf
	rmdir $(DESTDIR)$(prefix)/lib/sysctl.d || :
else ! WITH_SYSCTL
install-sysctl:
uninstall-sysctl:
endif ! WITH_SYSCTL

if LIBVIRT_INIT_SCRIPT_RED_HAT

BUILT_SOURCES += libvirtd.init

install-init-redhat: install-sysconfig libvirtd.init
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/rc.d/init.d
	$(INSTALL_SCRIPT) libvirtd.init \
	  $(DESTDIR)$(sysconfdir)/rc.d/init.d/libvirtd

uninstall-init-redhat: uninstall-sysconfig
	rm -f $(DESTDIR)$(sysconfdir)/rc.d/init.d/libvirtd
	rmdir $(DESTDIR)$(sysconfdir)/rc.d/init.d || :
else ! LIBVIRT_INIT_SCRIPT_RED_HAT
install-init-redhat:
uninstall-init-redhat:
endif ! LIBVIRT_INIT_SCRIPT_RED_HAT


if LIBVIRT_INIT_SCRIPT_UPSTART

install-init-upstart: install-sysconfig
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/event.d
	$(INSTALL_SCRIPT) libvirtd.upstart \
	  $(DESTDIR)$(sysconfdir)/event.d/libvirtd

uninstall-init-upstart: uninstall-sysconfig
	rm -f $(DESTDIR)$(sysconfdir)/event.d/libvirtd
	rmdir $(DESTDIR)$(sysconfdir)/event.d || :
else ! LIBVIRT_INIT_SCRIPT_UPSTART
install-init-upstart:
uninstall-init-upstart:
endif ! LIBVIRT_INIT_SCRIPT_UPSTART


if LIBVIRT_INIT_SCRIPT_SYSTEMD

SYSTEMD_UNIT_DIR = $(prefix)/lib/systemd/system
BUILT_SOURCES += libvirtd.service

install-init-systemd: install-sysconfig libvirtd.service
	$(MKDIR_P) $(DESTDIR)$(SYSTEMD_UNIT_DIR)
	$(INSTALL_DATA) libvirtd.service \
	  $(DESTDIR)$(SYSTEMD_UNIT_DIR)/libvirtd.service

uninstall-init-systemd: uninstall-sysconfig
	rm -f $(DESTDIR)$(SYSTEMD_UNIT_DIR)/libvirtd.service
	rmdir $(DESTDIR)$(SYSTEMD_UNIT_DIR) || :
else ! LIBVIRT_INIT_SCRIPT_SYSTEMD
install-init-systemd:
uninstall-init-systemd:
endif ! LIBVIRT_INIT_SCRIPT_SYSTEMD

libvirtd.init: libvirtd.init.in $(top_builddir)/config.status
	$(AM_V_GEN)sed						\
	    -e 's|[@]localstatedir[@]|$(localstatedir)|g'	\
	    -e 's|[@]sbindir[@]|$(sbindir)|g'			\
	    -e 's|[@]sysconfdir[@]|$(sysconfdir)|g'		\
	    < $< > $@-t &&					\
	    chmod a+x $@-t &&					\
	    mv $@-t $@

libvirtd.service: libvirtd.service.in $(top_builddir)/config.status
	$(AM_V_GEN)sed						\
	    -e 's|[@]localstatedir[@]|$(localstatedir)|g'	\
	    -e 's|[@]sbindir[@]|$(sbindir)|g'			\
	    -e 's|[@]sysconfdir[@]|$(sysconfdir)|g'		\
	    < $< > $@-t &&					\
	    mv $@-t $@


check-local: check-augeas

AUG_GENTEST = $(PERL) $(top_srcdir)/build-aux/augeas-gentest.pl

test_libvirtd.aug: test_libvirtd.aug.in $(srcdir)/libvirtd.conf
	$(AM_V_GEN)$(AUG_GENTEST) $(srcdir)/libvirtd.conf $< $@

check-augeas: test_libvirtd.aug
	$(AM_V_GEN)if test -x '$(AUGPARSE)'; then \
	  '$(AUGPARSE)' -I $(srcdir) test_libvirtd.aug; \
	fi


# This must be added last, since functions it provides/replaces
# are used by nearly every other library.
libvirtd_LDADD += ../gnulib/lib/libgnu.la $(LIBSOCKET)

else ! WITH_LIBVIRTD
install-data-local: install-data-sasl
uninstall-local:: uninstall-data-sasl
endif ! WITH_LIBVIRTD

POD2MAN = pod2man -c "Virtualization Support" \
			-r "$(PACKAGE)-$(VERSION)" -s 8

$(srcdir)/libvirtd.8.in: libvirtd.pod.in $(top_srcdir)/configure.ac
	$(AM_V_GEN)$(POD2MAN) --name LIBVIRTD $< $@ \
	    && if grep 'POD ERROR' $@ ; then rm $@; exit 1; fi

# This is needed for clients too, so can't wrap in
# the WITH_LIBVIRTD conditional
if WITH_SASL
install-data-sasl:
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/sasl2/
	$(INSTALL_DATA) $(srcdir)/libvirtd.sasl \
		$(DESTDIR)$(sysconfdir)/sasl2/libvirt.conf

uninstall-data-sasl:
	rm -f $(DESTDIR)$(sysconfdir)/sasl2/libvirt.conf
	rmdir $(DESTDIR)$(sysconfdir)/sasl2/ || :
else ! WITH_SASL
install-data-sasl:
uninstall-data-sasl:
endif ! WITH_SASL


CLEANFILES += $(BUILT_SOURCES) $(man8_MANS)
CLEANFILES += *.cov *.gcov .libs/*.gcda .libs/*.gcno *.gcno *.gcda
MAINTAINERCLEANFILES = $(srcdir)/libvirtd.8.in $(DAEMON_GENERATED)
