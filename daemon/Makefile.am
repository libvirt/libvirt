## Process this file with automake to produce Makefile.in

## Copyright (C) 2005-2015 Red Hat, Inc.
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

CLEANFILES =

DISTCLEANFILES =
EXTRA_DIST = \
	libvirtd.policy.in \
	libvirt.rules \
	libvirtd.sasl \
	libvirtd.sysctl \
	libvirtd.logrotate.in \
	libvirtd.qemu.logrotate.in \
	libvirtd.lxc.logrotate.in \
	libvirtd.libxl.logrotate.in \
	libvirtd.uml.logrotate.in \
	$(NULL)

BUILT_SOURCES =

if WITH_LIBVIRTD

if WITH_POLKIT
if WITH_POLKIT0
policydir = $(datadir)/PolicyKit/policy
policyauth = auth_admin_keep_session
else ! WITH_POLKIT0
policydir = $(datadir)/polkit-1/actions
policyauth = auth_admin_keep
rulesdir = $(datadir)/polkit-1/rules.d
rulesfile = libvirt.rules
endif ! WITH_POLKIT0
endif WITH_POLKIT

libvirtd.policy: libvirtd.policy.in $(top_builddir)/config.status
	$(AM_V_GEN) sed \
	    -e 's|[@]authaction[@]|$(policyauth)|g' \
	    < $< > $@-t && \
	mv $@-t $@
BUILT_SOURCES += libvirtd.policy

install-data-local: install-data-sasl install-data-polkit \
		install-logrotate install-sysctl
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/log/libvirt \
		   $(DESTDIR)$(localstatedir)/run/libvirt \
		   $(DESTDIR)$(localstatedir)/lib/libvirt

uninstall-local:: uninstall-data-sasl uninstall-data-polkit \
		uninstall-logrotate uninstall-sysctl
	rmdir $(DESTDIR)$(localstatedir)/log/libvirt || :
	rmdir $(DESTDIR)$(localstatedir)/run/libvirt || :
	rmdir $(DESTDIR)$(localstatedir)/lib/libvirt || :

if WITH_POLKIT
install-data-polkit::
	$(MKDIR_P) $(DESTDIR)$(policydir)
	$(INSTALL_DATA) libvirtd.policy $(DESTDIR)$(policydir)/org.libvirt.unix.policy
if ! WITH_POLKIT0
	$(MKDIR_P) $(DESTDIR)$(rulesdir)
	$(INSTALL_DATA) $(srcdir)/$(rulesfile) $(DESTDIR)$(rulesdir)/50-libvirt.rules
endif ! WITH_POLKIT0

uninstall-data-polkit::
	rm -f $(DESTDIR)$(policydir)/org.libvirt.unix.policy
	rmdir $(DESTDIR)$(policydir) || :
if ! WITH_POLKIT0
	rm -f $(DESTDIR)$(rulesdir)/50-libvirt.rules
	rmdir $(DESTDIR)$(rulesdir) || :
endif ! WITH_POLKIT0

else ! WITH_POLKIT
install-data-polkit::
uninstall-data-polkit::
endif ! WITH_POLKIT

LOGROTATE_CONFS = libvirtd.qemu.logrotate libvirtd.lxc.logrotate \
		  libvirtd.libxl.logrotate libvirtd.uml.logrotate \
		  libvirtd.logrotate

BUILT_SOURCES += $(LOGROTATE_CONFS)

libvirtd.logrotate: libvirtd.logrotate.in
	$(AM_V_GEN)sed \
	    -e 's|[@]localstatedir[@]|$(localstatedir)|g' \
	    < $< > $@-t && \
	mv $@-t $@

libvirtd.qemu.logrotate: libvirtd.qemu.logrotate.in
	$(AM_V_GEN)sed \
	    -e 's|[@]localstatedir[@]|$(localstatedir)|g' \
	    < $< > $@-t && \
	mv $@-t $@

libvirtd.lxc.logrotate: libvirtd.lxc.logrotate.in
	$(AM_V_GEN)sed \
	    -e 's|[@]localstatedir[@]|$(localstatedir)|g' \
	    < $< > $@-t && \
	    mv $@-t $@

libvirtd.libxl.logrotate: libvirtd.libxl.logrotate.in
	$(AM_V_GEN)sed \
	    -e 's|[@]localstatedir[@]|$(localstatedir)|g' \
	    < $< > $@-t && \
	    mv $@-t $@

libvirtd.uml.logrotate: libvirtd.uml.logrotate.in
	$(AM_V_GEN)sed \
	    -e 's|[@]localstatedir[@]|$(localstatedir)|g' \
	    < $< > $@-t && \
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
	$(INSTALL_DATA) libvirtd.libxl.logrotate \
		$(DESTDIR)$(sysconfdir)/logrotate.d/libvirtd.libxl
	$(INSTALL_DATA) libvirtd.uml.logrotate \
		$(DESTDIR)$(sysconfdir)/logrotate.d/libvirtd.uml

uninstall-logrotate:
	rm -f $(DESTDIR)$(sysconfdir)/logrotate.d/libvirtd \
	      $(DESTDIR)$(sysconfdir)/logrotate.d/libvirtd.qemu \
	      $(DESTDIR)$(sysconfdir)/logrotate.d/libvirtd.lxc \
	      $(DESTDIR)$(sysconfdir)/logrotate.d/libvirtd.libxl \
	      $(DESTDIR)$(sysconfdir)/logrotate.d/libvirtd.uml
	rmdir $(DESTDIR)$(localstatedir)/log/libvirt/qemu || :
	rmdir $(DESTDIR)$(localstatedir)/log/libvirt/lxc || :
	rmdir $(DESTDIR)$(localstatedir)/log/libvirt/uml || :
	rmdir $(DESTDIR)$(sysconfdir)/logrotate.d || :

if WITH_SYSCTL
# Use $(prefix)/lib rather than $(libdir), since man sysctl.d insists on
# /usr/lib/sysctl.d/ even when libdir is /usr/lib64
install-sysctl:
	$(MKDIR_P) $(DESTDIR)$(prefix)/lib/sysctl.d
	$(INSTALL_DATA) $(srcdir)/libvirtd.sysctl \
	  $(DESTDIR)$(prefix)/lib/sysctl.d/60-libvirtd.conf

uninstall-sysctl:
	rm -f $(DESTDIR)$(prefix)/lib/sysctl.d/60-libvirtd.conf
	rmdir $(DESTDIR)$(prefix)/lib/sysctl.d || :
else ! WITH_SYSCTL
install-sysctl:
uninstall-sysctl:
endif ! WITH_SYSCTL

else ! WITH_LIBVIRTD
install-data-local: install-data-sasl
uninstall-local:: uninstall-data-sasl
endif ! WITH_LIBVIRTD

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


CLEANFILES += $(BUILT_SOURCES)
CLEANFILES += *.cov *.gcov .libs/*.gcda .libs/*.gcno *.gcno *.gcda
