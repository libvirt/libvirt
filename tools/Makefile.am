## Copyright (C) 2005-2016 Red Hat, Inc.
## Copyright (C) 2013 Yuto KAWAMURA(kawamuray) <kawamuray.dadada@gmail.com>
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
	-I$(top_builddir)/include -I$(top_srcdir)/include	\
	-I$(top_builddir)/gnulib/lib -I$(top_srcdir)/gnulib/lib	\
	-I$(top_builddir)/src -I$(top_srcdir)/src		\
	-I$(top_srcdir)/src/util				\
	-I$(top_srcdir)						\
	$(GETTEXT_CPPFLAGS)

WARN_CFLAGS += $(STRICT_FRAME_LIMIT_CFLAGS)

AM_LDFLAGS = \
	$(RELRO_LDFLAGS)					\
	$(NO_INDIRECT_LDFLAGS)					\
	$(NULL)

ICON_FILES = \
	libvirt_win_icon_16x16.ico \
	libvirt_win_icon_32x32.ico \
	libvirt_win_icon_48x48.ico \
	libvirt_win_icon_64x64.ico \
	virsh_win_icon.rc

PODFILES = \
	virt-admin.pod \
	virt-host-validate.pod \
	virt-login-shell.pod \
	virt-pki-validate.pod \
	virt-sanlock-cleanup.pod \
	virt-xml-validate.pod \
	virsh.pod \
	$(NULL)

MANINFILES = \
	virt-admin.1.in \
	virt-host-validate.1.in \
	virt-login-shell.1.in \
	virt-pki-validate.1.in \
	virt-sanlock-cleanup.8.in \
	virt-xml-validate.1.in \
	virsh.1.in \
	$(NULL)

EXTRA_DIST = \
	$(ICON_FILES)					\
	$(conf_DATA)					\
	virt-xml-validate.in				\
	virt-pki-validate.in				\
	virt-sanlock-cleanup.in				\
	libvirt-guests.sysconf				\
	virt-login-shell.conf				\
	virsh-edit.c					\
	$(PODFILES)					\
	$(MANINFILES)					\
	$(NULL)


CLEANFILES =
DISTCLEANFILES =
MAINTAINERCLEANFILES =

confdir = $(sysconfdir)/libvirt
conf_DATA =

bin_SCRIPTS = virt-xml-validate virt-pki-validate
bin_PROGRAMS = virsh virt-admin
libexec_SCRIPTS = libvirt-guests.sh
man1_MANS = \
		virt-pki-validate.1 \
		virt-xml-validate.1 \
		virsh.1 \
		virt-admin.1

if WITH_SANLOCK
sbin_SCRIPTS = virt-sanlock-cleanup
man8_MANS = virt-sanlock-cleanup.8
DISTCLEANFILES += virt-sanlock-cleanup
endif WITH_SANLOCK

if WITH_LOGIN_SHELL
conf_DATA += virt-login-shell.conf
bin_PROGRAMS += virt-login-shell
man1_MANS += virt-login-shell.1
endif WITH_LOGIN_SHELL

if WITH_HOST_VALIDATE
bin_PROGRAMS += virt-host-validate
man1_MANS += virt-host-validate.1
endif WITH_HOST_VALIDATE

virt-xml-validate: virt-xml-validate.in Makefile
	$(AM_V_GEN)sed -e 's|[@]schemadir@|$(pkgdatadir)/schemas|g' \
		       -e 's|[@]VERSION@|$(VERSION)|g' \
	  < $< > $@ || (rm $@ && exit 1) && chmod +x $@

virt-pki-validate: virt-pki-validate.in Makefile
	$(AM_V_GEN)sed -e 's|[@]sysconfdir@|$(sysconfdir)|g' \
		       -e 's|[@]VERSION@|$(VERSION)|g' \
	  < $< > $@ || (rm $@ && exit 1) && chmod +x $@

virt-sanlock-cleanup: virt-sanlock-cleanup.in Makefile
	$(AM_V_GEN)sed -e 's|[@]sysconfdir@|$(sysconfdir)|' \
	    -e 's|[@]localstatedir@|$(localstatedir)|' < $< > $@ \
	    || (rm $@ && exit 1) && chmod +x $@

noinst_LTLIBRARIES = libvirt_shell.la
libvirt_shell_la_CFLAGS = \
		$(AM_CFLAGS)						\
		$(PIE_CFLAGS)						\
		$(READLINE_CFLAGS)					\
		$(LIBXML_CFLAGS)					\
		$(NULL)
libvirt_shell_la_LDFLAGS = \
		$(AM_LDFLAGS)						\
		$(PIE_LDFLAGS)						\
		$(COVERAGE_LDFLAGS)					\
		$(NULL)
libvirt_shell_la_LIBADD = \
		$(LIBXML_LIBS)						\
		$(READLINE_LIBS)					\
		../src/libvirt.la					\
		../gnulib/lib/libgnu.la				\
		$(NULL)
libvirt_shell_la_SOURCES = vsh.c vsh.h

virt_host_validate_SOURCES = \
		virt-host-validate.c \
		virt-host-validate-common.c virt-host-validate-common.h

VIRT_HOST_VALIDATE_QEMU = \
		virt-host-validate-qemu.c \
		virt-host-validate-qemu.h
VIRT_HOST_VALIDATE_LXC = \
		virt-host-validate-lxc.c \
		virt-host-validate-lxc.h
VIRT_HOST_VALIDATE_BHYVE = \
		virt-host-validate-bhyve.c \
		virt-host-validate-bhyve.h
if WITH_QEMU
virt_host_validate_SOURCES += $(VIRT_HOST_VALIDATE_QEMU)
else ! WITH_QEMU
EXTRA_DIST += $(VIRT_HOST_VALIDATE_QEMU)
endif ! WITH_QEMU

if WITH_LXC
virt_host_validate_SOURCES += $(VIRT_HOST_VALIDATE_LXC)
else ! WITH_LXC
EXTRA_DIST += $(VIRT_HOST_VALIDATE_LXC)
endif ! WITH_LXC

if WITH_BHYVE
virt_host_validate_SOURCES += $(VIRT_HOST_VALIDATE_BHYVE)
else ! WITH_BHYVE
EXTRA_DIST += $(VIRT_HOST_VALIDATE_BHYVE)
endif ! WITH_BHYVE

virt_host_validate_LDFLAGS = \
		$(AM_LDFLAGS) \
		$(PIE_LDFLAGS) \
		$(COVERAGE_LDFLAGS) \
		$(NULL)

virt_host_validate_LDADD = \
		../src/libvirt.la				\
		../gnulib/lib/libgnu.la				\
		$(NULL)

virt_host_validate_CFLAGS = \
		$(LIBXML_CFLAGS)				\
		$(WARN_CFLAGS)					\
		$(PIE_CFLAGS)					\
		$(COVERAGE_CFLAGS)				\
		$(NULL)

# Since virt-login-shell will be setuid, we must do everything
# we can to avoid linking to other libraries. Many of them do
# unsafe things in functions marked __atttribute__((constructor)).
# This we statically link to a library containing only the minimal
# libvirt client code, not libvirt.so itself.
virt_login_shell_SOURCES =					\
		virt-login-shell.c

virt_login_shell_LDFLAGS = \
		$(AM_LDFLAGS) 					\
		$(PIE_LDFLAGS)					\
		$(COVERAGE_LDFLAGS)				\
		$(NULL)
virt_login_shell_LDADD =					\
		$(STATIC_BINARIES)				\
		../src/libvirt-setuid-rpc-client.la		\
		../gnulib/lib/libgnu.la

virt_login_shell_CFLAGS =					\
		-DLIBVIRT_SETUID_RPC_CLIENT			\
		$(LIBXML_CFLAGS)				\
		$(WARN_CFLAGS)					\
		$(PIE_CFLAGS)					\
		$(COVERAGE_CFLAGS)

virsh_SOURCES =							\
		virsh.c virsh.h					\
		virsh-console.c virsh-console.h			\
		virsh-domain.c virsh-domain.h			\
		virsh-domain-monitor.c virsh-domain-monitor.h	\
		virsh-host.c virsh-host.h			\
		virsh-interface.c virsh-interface.h		\
		virsh-network.c virsh-network.h			\
		virsh-nodedev.c virsh-nodedev.h			\
		virsh-nwfilter.c virsh-nwfilter.h		\
		virsh-pool.c virsh-pool.h			\
		virsh-secret.c virsh-secret.h			\
		virsh-snapshot.c virsh-snapshot.h		\
		virsh-volume.c virsh-volume.h			\
		$(NULL)

virsh_LDFLAGS = \
		$(AM_LDFLAGS) 					\
		$(PIE_LDFLAGS)					\
		$(COVERAGE_LDFLAGS)				\
		$(NULL)
virsh_LDADD =							\
		$(STATIC_BINARIES)				\
		../src/libvirt-lxc.la				\
		../src/libvirt-qemu.la				\
		libvirt_shell.la
virsh_CFLAGS =							\
		$(WARN_CFLAGS)					\
		$(PIE_CFLAGS)					\
		$(COVERAGE_CFLAGS)				\
		$(LIBXML_CFLAGS)

virt_admin_SOURCES =						\
		virt-admin.c virt-admin.h			\
		$(NULL)

virt_admin_LDFLAGS =						\
		$(AM_LDFLAGS)					\
		$(COVERAGE_LDFLAGS)				\
		$(STATIC_BINARIES)				\
		$(PIE_LDFLAGS)					\
		$(NULL)
virt_admin_LDADD =						\
		../src/libvirt-admin.la				\
		libvirt_shell.la				\
		$(LIBXML_LIBS)					\
		$(NULL)
virt_admin_CFLAGS =						\
		$(WARN_CFLAGS)					\
		$(PIE_CFLAGS)					\
		$(COVERAGE_CFLAGS)				\
		$(LIBXML_CFLAGS)				\
		$(READLINE_CFLAGS)
BUILT_SOURCES =

if WITH_WIN_ICON
virsh_LDADD += virsh_win_icon.$(OBJEXT)

# Before you edit virsh_win_icon.rc, please note the following
# limitations of the resource file format:
#
# (1) '..' is not permitted in the icon filename field.
# (2) '-' is not permitted in the icon filename field.
# (3) Comments are not permitted in the file.
#
# Windows appears to choose the first <= 32x32 icon it finds
# in the resource file.  Therefore you should list the available
# icons from largest to smallest, and make sure that the 32x32
# icon is the most legible.
#
# Windows .ICO is a special MS-only format.  GIMP and other
# tools can write it.  However there are several variations,
# and Windows seems to do its own colour quantization.  More
# information is needed in this area.

virsh_win_icon.$(OBJEXT): virsh_win_icon.rc
	$(AM_V_GEN)$(WINDRES) \
	  --input-format rc --input $< \
	  --output-format coff --output $@
endif WITH_WIN_ICON

POD2MAN = pod2man -c "Virtualization Support" -r "$(PACKAGE)-$(VERSION)"

%.1.in: %.pod
	$(AM_V_GEN)$(POD2MAN) $< $@-t1 && \
	if grep 'POD ERROR' $@-t1; then rm $@-t1; exit 1; fi && \
	sed \
		-e 's|SYSCONFDIR|\@sysconfdir\@|g' \
		-e 's|LOCALSTATEDIR|\@localstatedir\@|g' \
	< $@-t1 > $@-t2 && \
	rm -f $@-t1 && \
	mv $@-t2 $@

%.8.in: %.pod
	$(AM_V_GEN)$(POD2MAN) --section=8 $< $@-t1 && \
	if grep 'POD ERROR' $@-t1; then rm $@-t1; exit 1; fi && \
	sed \
		-e 's|SYSCONFDIR|\@sysconfdir\@|g' \
		-e 's|LOCALSTATEDIR|\@localstatedir\@|g' \
		< $@-t1 > $@-t2 && \
	rm -f $@-t1 && \
	mv $@-t2 $@

%.1: %.1.in $(top_srcdir)/configure.ac
	$(AM_V_GEN)sed \
		-e 's|[@]sysconfdir[@]|$(sysconfdir)|g' \
		-e 's|[@]localstatedir[@]|$(localstatedir)|g' \
		< $< > $@-t && \
	mv $@-t $@

%.8: %.8.in $(top_srcdir)/configure.ac
	$(AM_V_GEN)sed \
		-e 's|[@]sysconfdir[@]|$(sysconfdir)|g' \
		-e 's|[@]localstatedir[@]|$(localstatedir)|g' \
		< $< > $@-t && \
	mv $@-t $@

install-data-local: install-init install-systemd install-nss

uninstall-local: uninstall-init uninstall-systemd uninstall-nss

install-sysconfig:
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/sysconfig
	$(INSTALL_DATA) $(srcdir)/libvirt-guests.sysconf \
	  $(DESTDIR)$(sysconfdir)/sysconfig/libvirt-guests

uninstall-sysconfig:
	rm -f $(DESTDIR)$(sysconfdir)/sysconfig/libvirt-guests
	rmdir $(DESTDIR)$(sysconfdir)/sysconfig ||:

EXTRA_DIST += libvirt-guests.sh.in libvirt-guests.init.in

install-initscript: libvirt-guests.init
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/rc.d/init.d
	$(INSTALL_SCRIPT) libvirt-guests.init \
	  $(DESTDIR)$(sysconfdir)/rc.d/init.d/libvirt-guests

uninstall-initscript:
	rm -f $(DESTDIR)$(sysconfdir)/rc.d/init.d/libvirt-guests
	rmdir $(DESTDIR)$(sysconfdir)/rc.d/init.d ||:


if LIBVIRT_INIT_SCRIPT_RED_HAT
BUILT_SOURCES += libvirt-guests.init
install-init: install-sysconfig install-initscript
uninstall-init: uninstall-sysconfig uninstall-initscript
else ! LIBVIRT_INIT_SCRIPT_RED_HAT
install-init:
uninstall-init:
endif ! LIBVIRT_INIT_SCRIPT_RED_HAT

libvirt-guests.sh: libvirt-guests.sh.in $(top_builddir)/config.status
	$(AM_V_GEN)sed						\
	    -e 's|[@]PACKAGE[@]|$(PACKAGE)|g'			\
	    -e 's|[@]bindir[@]|$(bindir)|g'			\
	    -e 's|[@]localedir[@]|$(localedir)|g'		\
	    -e 's|[@]localstatedir[@]|$(localstatedir)|g'	\
	    -e 's|[@]sbindir[@]|$(sbindir)|g'			\
	    -e 's|[@]sysconfdir[@]|$(sysconfdir)|g'		\
	    < $< > $@-t &&					\
	    chmod a+x $@-t &&					\
	    mv $@-t $@
BUILT_SOURCES += libvirt-guests.sh

libvirt-guests.init: libvirt-guests.init.in libvirt-guests.sh
	$(AM_V_GEN)sed \
		-e 's|[@]libexecdir[@]|$(libexecdir)|g' \
	< $< > $@-t && \
	chmod a+x $@-t && \
	mv $@-t $@


EXTRA_DIST += libvirt-guests.service.in
SYSTEMD_UNIT_DIR = $(prefix)/lib/systemd/system

if LIBVIRT_INIT_SCRIPT_SYSTEMD
install-systemd: libvirt-guests.service install-sysconfig libvirt-guests.sh
	$(MKDIR_P) $(DESTDIR)$(SYSTEMD_UNIT_DIR)
	$(INSTALL_DATA) libvirt-guests.service \
	  $(DESTDIR)$(SYSTEMD_UNIT_DIR)/libvirt-guests.service

uninstall-systemd: uninstall-sysconfig
	rm -f $(DESTDIR)$(SYSTEMD_UNIT_DIR)/libvirt-guests.service
	rmdir $(DESTDIR)$(SYSTEMD_UNIT_DIR) ||:

BUILT_SOURCES += libvirt-guests.service

else ! LIBVIRT_INIT_SCRIPT_SYSTEMD
install-systemd:
uninstall-systemd:
endif ! LIBVIRT_INIT_SCRIPT_SYSTEMD

libvirt-guests.service: libvirt-guests.service.in $(top_builddir)/config.status
	$(AM_V_GEN)sed						\
	    -e 's|[@]PACKAGE[@]|$(PACKAGE)|g'			\
	    -e 's|[@]bindir[@]|$(bindir)|g'			\
	    -e 's|[@]localedir[@]|$(localedir)|g'		\
	    -e 's|[@]localstatedir[@]|$(localstatedir)|g'	\
	    -e 's|[@]sbindir[@]|$(sbindir)|g'			\
	    -e 's|[@]sysconfdir[@]|$(sysconfdir)|g'		\
	    -e 's|[@]libexecdir[@]|$(libexecdir)|g'		\
	    < $< > $@-t &&					\
	    mv $@-t $@


EXTRA_DIST += \
	wireshark/util/genxdrstub.pl \
	wireshark/util/make-dissector-reg

if WITH_WIRESHARK_DISSECTOR

ws_plugin_LTLIBRARIES = wireshark/src/libvirt.la
wireshark_src_libvirt_la_CPPFLAGS = \
	-I wireshark/src $(WIRESHARK_DISSECTOR_CFLAGS)
wireshark_src_libvirt_la_LDFLAGS = -avoid-version -module
nodist_wireshark_src_libvirt_la_SOURCES = wireshark/src/plugin.c
wireshark_src_libvirt_la_SOURCES = \
	wireshark/src/packet-libvirt.h \
	wireshark/src/packet-libvirt.c

wireshark/src/packet-libvirt.c: wireshark/src/packet-libvirt.h \
		wireshark/src/libvirt/protocol.h

wireshark/src/plugin.c: wireshark/src/packet-libvirt.c
	cd wireshark/src && \
		$(abs_top_srcdir)/tools/wireshark/util/make-dissector-reg \
		. plugin packet-libvirt.c

WS_DISSECTOR_PROTO_FILES  = \
  $(abs_top_srcdir)/src/remote/remote_protocol.x \
  $(abs_top_srcdir)/src/remote/qemu_protocol.x \
  $(abs_top_srcdir)/src/remote/lxc_protocol.x \
  $(abs_top_srcdir)/src/rpc/virkeepaliveprotocol.x

wireshark/src/libvirt/protocol.h: wireshark/util/genxdrstub.pl \
		$(WS_DISSECTOR_PROTO_FILES)
	$(MKDIR_P) wireshark/src/libvirt
	cd wireshark/src && \
	LIBVIRT_VERSION=$(LIBVIRT_VERSION) \
		  $(PERL) $(abs_top_srcdir)/tools/wireshark/util/genxdrstub.pl \
		  $(WS_DISSECTOR_PROTO_FILES)

CLEANFILES += wireshark/src/plugin.c

endif WITH_WIRESHARK_DISSECTOR

if WITH_BSD_NSS
LIBVIRT_NSS_SYMBOL_FILE = \
	$(srcdir)/nss/libvirt_nss_bsd.syms
LIBVIRT_GUEST_NSS_SYMBOL_FILE = \
	$(LIBVIRT_NSS_SYMBOL_FILE)
NSS_SO_VER = 1

install-nss:
	( cd $(DESTDIR)$(libdir) && \
	  rm -f nss_libvirt.so.$(NSS_SO_VER) && \
	  $(LN_S) libnss_libvirt.so.$(NSS_SO_VER) nss_libvirt.so.$(NSS_SO_VER) && \
	  rm -f nss_libvirt_guest.so.$(NSS_SO_VER) && \
	  $(LN_S) libnss_libvirt_guest.so.$(NSS_SO_VER) \
	  nss_libvirt_guest.so.$(NSS_SO_VER))

uninstall-nss:
	-rm -f $(DESTDIR)$(libdir)/nss_libvirt.so.$(NSS_SO_VER)
	-rm -f $(DESTDIR)$(libdir)/nss_libvirt_guest.so.$(NSS_SO_VER)
else ! WITH_BSD_NSS
LIBVIRT_NSS_SYMBOL_FILE = \
	$(srcdir)/nss/libvirt_nss.syms
LIBVIRT_GUEST_NSS_SYMBOL_FILE = \
	$(srcdir)/nss/libvirt_guest_nss.syms
NSS_SO_VER = 2

install-nss:
uninstall-nss:
endif ! WITH_BSD_NSS

LIBVIRT_NSS_SOURCES = \
	nss/libvirt_nss.c	\
	nss/libvirt_nss.h

if WITH_NSS
noinst_LTLIBRARIES += nss/libnss_libvirt_impl.la
nss_libnss_libvirt_impl_la_SOURCES = \
	$(LIBVIRT_NSS_SOURCES)

nss_libnss_libvirt_impl_la_CFLAGS = \
	-DLIBVIRT_NSS		\
	$(AM_CFLAGS)		\
	$(WARN_CFLAGS)		\
	$(PIE_CFLAGS)		\
	$(COVERAGE_CFLAGS)	\
	$(LIBXML_CFLAGS)

nss_libnss_libvirt_impl_la_LIBADD = \
	../gnulib/lib/libgnu.la		\
	../src/libvirt-nss.la

nss_libnss_libvirt_la_SOURCES =
nss_libnss_libvirt_la_LDFLAGS = \
	$(VERSION_SCRIPT_FLAGS)$(LIBVIRT_NSS_SYMBOL_FILE)	\
	$(AM_LDFLAGS) \
	-module \
	-export-dynamic \
	-avoid-version \
	-shared \
	-shrext .so.$(NSS_SO_VER)

nss_libnss_libvirt_la_LIBADD =  \
	nss/libnss_libvirt_impl.la

noinst_LTLIBRARIES += nss/libnss_libvirt_guest_impl.la
nss_libnss_libvirt_guest_impl_la_SOURCES = \
	$(LIBVIRT_NSS_SOURCES)

nss_libnss_libvirt_guest_impl_la_CFLAGS = \
	-DLIBVIRT_NSS		\
	-DLIBVIRT_NSS_GUEST	\
	$(AM_CFLAGS)		\
	$(WARN_CFLAGS)		\
	$(PIE_CFLAGS)		\
	$(COVERAGE_CFLAGS)	\
	$(LIBXML_CFLAGS)

nss_libnss_libvirt_guest_impl_la_LIBADD = \
	../gnulib/lib/libgnu.la		\
	../src/libvirt-nss.la

nss_libnss_libvirt_guest_la_SOURCES =
nss_libnss_libvirt_guest_la_LDFLAGS = \
	$(VERSION_SCRIPT_FLAGS)$(LIBVIRT_GUEST_NSS_SYMBOL_FILE)	\
	$(AM_LDFLAGS) \
	-module \
	-export-dynamic \
	-avoid-version \
	-shared \
	-shrext .so.$(NSS_SO_VER)

nss_libnss_libvirt_guest_la_LIBADD =  \
	nss/libnss_libvirt_guest_impl.la

lib_LTLIBRARIES = \
	nss/libnss_libvirt.la \
	nss/libnss_libvirt_guest.la

endif WITH_NSS

EXTRA_DIST += $(LIBVIRT_NSS_SOURCES) \
	$(srcdir)/nss/libvirt_nss.syms \
	$(srcdir)/nss/libvirt_nss_bsd.syms	\
	$(srcdir)/nss/libvirt_guest_nss.syms

clean-local:
	-rm -rf wireshark/src/libvirt

CLEANFILES += $(bin_SCRIPTS)
CLEANFILES += *.gcov .libs/*.gcda .libs/*.gcno *.gcno *.gcda *.i *.s
CLEANFILES += $(man1_MANS) $(man8_MANS)

DISTCLEANFILES += $(BUILT_SOURCES)

MAINTAINERCLEANFILES += $(MANINFILES)
