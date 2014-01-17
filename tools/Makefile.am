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
	-I$(top_builddir)/include -I$(top_srcdir)/include	\
	-I$(top_builddir)/gnulib/lib -I$(top_srcdir)/gnulib/lib	\
	-I$(top_builddir)/src -I$(top_srcdir)/src		\
	-I$(top_srcdir)/src/util				\
	-I$(top_srcdir)						\
	$(GETTEXT_CPPFLAGS)

AM_LDFLAGS = \
	$(RELRO_LDFLAGS)					\
	$(NO_INDIRECT_LDFLAGS)					\
	$(NULL)

POD2MAN = pod2man -c "Virtualization Support" -r "$(PACKAGE)-$(VERSION)"

ICON_FILES = \
	libvirt_win_icon_16x16.ico \
	libvirt_win_icon_32x32.ico \
	libvirt_win_icon_48x48.ico \
	libvirt_win_icon_64x64.ico \
	virsh_win_icon.rc

EXTRA_DIST = \
	$(ICON_FILES)					\
	$(conf_DATA)					\
	virt-xml-validate.in				\
	virt-pki-validate.in				\
	virt-sanlock-cleanup.in				\
	virt-sanlock-cleanup.8				\
	virt-login-shell.pod				\
	virsh.pod					\
	libvirt-guests.sysconf				\
	virsh-edit.c					\
	virsh-domain.c					\
	virsh-domain-monitor.c				\
	virsh-host.c virsh-interface.c			\
	virsh-network.c virsh-nodedev.c			\
	virsh-nwfilter.c virsh-pool.c			\
	virsh-secret.c virsh-snapshot.c			\
	virsh-volume.c



DISTCLEANFILES =

confdir = $(sysconfdir)/libvirt
conf_DATA =

bin_SCRIPTS = virt-xml-validate virt-pki-validate
bin_PROGRAMS = virsh virt-host-validate
libexec_SCRIPTS = libvirt-guests.sh

if WITH_SANLOCK
sbin_SCRIPTS = virt-sanlock-cleanup
DISTCLEANFILES += virt-sanlock-cleanup
endif WITH_SANLOCK

if WITH_LXC
conf_DATA += virt-login-shell.conf
bin_PROGRAMS += virt-login-shell
else ! WITH_LXC
EXTRA_DIST += virt-login-shell.conf
endif ! WITH_LXC


dist_man1_MANS = \
		virt-host-validate.1 \
		virt-pki-validate.1 \
		virt-xml-validate.1 \
		virsh.1
if WITH_LXC
dist_man1_MANS += virt-login-shell.1
else ! WITH_LXC
EXTRA_DIST += virt-login-shell.1
endif ! WITH_LXC
if WITH_SANLOCK
dist_man8_MANS = virt-sanlock-cleanup.8
endif WITH_SANLOCK

virt-xml-validate: virt-xml-validate.in Makefile
	$(AM_V_GEN)sed -e 's|[@]schemadir@|$(pkgdatadir)/schemas|g' \
		       -e 's|[@]VERSION@|$(VERSION)|g' \
	  < $< > $@ || (rm $@ && exit 1) && chmod +x $@

virt-xml-validate.1: virt-xml-validate.in $(top_srcdir)/configure.ac
	$(AM_V_GEN)$(POD2MAN) --name VIRT-XML-VALIDATE $< $(srcdir)/$@ \
	    && if grep 'POD ERROR' $(srcdir)/$@ ; then \
		rm $(srcdir)/$@; exit 1; fi

virt-pki-validate: virt-pki-validate.in Makefile
	$(AM_V_GEN)sed -e 's|[@]sysconfdir@|$(sysconfdir)|g' \
		       -e 's|[@]VERSION@|$(VERSION)|g' \
	  < $< > $@ || (rm $@ && exit 1) && chmod +x $@

virt-pki-validate.1: virt-pki-validate.in $(top_srcdir)/configure.ac
	$(AM_V_GEN)$(POD2MAN) --name VIRT-PKI-VALIDATE $< $(srcdir)/$@ \
	    && if grep 'POD ERROR' $(srcdir)/$@ ; then \
		rm $(srcdir)/$@; exit 1; fi

virt-host-validate.1: virt-host-validate.c $(top_srcdir)/configure.ac
	$(AM_V_GEN)$(POD2MAN) --name VIRT-HOST-VALIDATE $< $(srcdir)/$@ \
	    && if grep 'POD ERROR' $(srcdir)/$@ ; then \
		rm $(srcdir)/$@; exit 1; fi

virt-sanlock-cleanup: virt-sanlock-cleanup.in Makefile
	$(AM_V_GEN)sed -e 's|[@]sysconfdir@|$(sysconfdir)|' \
	    -e 's|[@]localstatedir@|$(localstatedir)|' < $< > $@ \
	    || (rm $@ && exit 1) && chmod +x $@

virt-sanlock-cleanup.8: virt-sanlock-cleanup.in $(top_srcdir)/configure.ac
	$(AM_V_GEN)$(POD2MAN) --name VIRT-SANLOCK-CLEANUP --section=8 \
	    $< $(srcdir)/$@ \
	    && if grep 'POD ERROR' $(srcdir)/$@ ; then \
		rm $(srcdir)/$@; exit 1; fi

virt_host_validate_SOURCES = \
		virt-host-validate.c \
		virt-host-validate-common.c virt-host-validate-common.h \
		virt-host-validate-qemu.c virt-host-validate-qemu.h \
		virt-host-validate-lxc.c virt-host-validate-lxc.h \
		$(NULL)

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
		$(COVERAGE_LDFLAGS)				\
		$(NULL)
virt_login_shell_LDADD =					\
		$(STATIC_BINARIES)				\
		$(PIE_LDFLAGS)					\
		../src/libvirt-setuid-rpc-client.la		\
		../gnulib/lib/libgnu.la

virt_login_shell_CFLAGS =					\
		-DLIBVIRT_SETUID_RPC_CLIENT			\
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
		$(COVERAGE_LDFLAGS)				\
		$(NULL)
virsh_LDADD =							\
		$(STATIC_BINARIES)				\
		$(PIE_LDFLAGS)					\
		../src/libvirt.la				\
		../src/libvirt-lxc.la				\
		../src/libvirt-qemu.la				\
		../gnulib/lib/libgnu.la				\
		$(LIBXML_LIBS)					\
		$(VIRSH_LIBS)
virsh_CFLAGS =							\
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

virt-login-shell.1: virt-login-shell.pod $(top_srcdir)/configure.ac
	$(AM_V_GEN)$(POD2MAN) $< $(srcdir)/$@ \
	    && if grep 'POD ERROR' $(srcdir)/$@ ; then \
		rm $(srcdir)/$@; exit 1; fi

virsh.1: virsh.pod $(top_srcdir)/configure.ac
	$(AM_V_GEN)$(POD2MAN) $< $(srcdir)/$@ \
	    && if grep 'POD ERROR' $(srcdir)/$@ ; then \
		rm $(srcdir)/$@; exit 1; fi

install-data-local: install-init install-systemd

uninstall-local: uninstall-init uninstall-systemd

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


CLEANFILES = $(bin_SCRIPTS)
CLEANFILES += *.gcov .libs/*.gcda .libs/*.gcno *.gcno *.gcda *.i *.s
MAINTAINERCLEANFILES = $(dist_man1_MANS)

DISTCLEANFILES += $(BUILT_SOURCES)
