## Process this file with automake to produce Makefile.in

## Copyright (C) 2005-2013 Red Hat, Inc.
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

# when building from tarball -Werror isn't auto enabled
# so force it explicitly
DISTCHECK_CONFIGURE_FLAGS = --enable-werror

SUBDIRS = . include/libvirt src tools docs \
  tests po examples

XZ_OPT ?= -v -T0
export XZ_OPT

ACLOCAL_AMFLAGS = -I m4

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libvirt.pc libvirt-qemu.pc libvirt-lxc.pc libvirt-admin.pc

rpm: clean
	@(unset CDPATH ; $(MAKE) dist && rpmbuild -ta $(distdir).tar.xz)

srpm: clean
	@(unset CDPATH ; $(MAKE) dist && rpmbuild -ts $(distdir).tar.xz)

check-local: all tests

check-access: all
	@($(MAKE) $(AM_MAKEFLAGS) -C tests check-access)

dist-hook: gen-AUTHORS

.PHONY: gen-AUTHORS
gen-AUTHORS:
	$(AM_V_GEN)\
	if test -d $(srcdir)/.git; then \
	  ( \
	    cd $(srcdir) && \
	    git log --pretty=format:'%aN <%aE>' | sort -u \
	  ) > all.list && \
	  sort -u $(srcdir)/AUTHORS.in > maint.list && \
	  comm -23 all.list maint.list > contrib.list && \
	  contrib="`cat contrib.list`" && \
	  perl -p -e "s/#contributorslist#// and print '$$contrib'" \
	    < $(srcdir)/AUTHORS.in > $(distdir)/AUTHORS-tmp && \
	  mv -f $(distdir)/AUTHORS-tmp $(distdir)/AUTHORS && \
	  rm -f all.list maint.list contrib.list; \
	fi

ci-%:
	$(MAKE) -C $(srcdir)/ci/ $@
