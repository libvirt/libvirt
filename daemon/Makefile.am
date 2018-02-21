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
	libvirtd.logrotate.in \
	libvirtd.qemu.logrotate.in \
	libvirtd.lxc.logrotate.in \
	libvirtd.libxl.logrotate.in \
	libvirtd.uml.logrotate.in \
	$(NULL)

BUILT_SOURCES =

if WITH_LIBVIRTD



install-data-local: install-logrotate
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/log/libvirt \
		   $(DESTDIR)$(localstatedir)/run/libvirt \
		   $(DESTDIR)$(localstatedir)/lib/libvirt

uninstall-local:: uninstall-logrotate
	rmdir $(DESTDIR)$(localstatedir)/log/libvirt || :
	rmdir $(DESTDIR)$(localstatedir)/run/libvirt || :
	rmdir $(DESTDIR)$(localstatedir)/lib/libvirt || :

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

else ! WITH_LIBVIRTD
install-data-local:
uninstall-local::
endif ! WITH_LIBVIRTD


CLEANFILES += $(BUILT_SOURCES)
CLEANFILES += *.cov *.gcov .libs/*.gcda .libs/*.gcno *.gcno *.gcda
