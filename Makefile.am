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

LCOV = lcov
GENHTML = genhtml

# when building from tarball -Werror isn't auto enabled
# so force it explicitly
DISTCHECK_CONFIGURE_FLAGS = --enable-werror

SUBDIRS = . include/libvirt src tools docs \
  tests po examples

XZ_OPT ?= -v -T0
export XZ_OPT

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = \
  config-post.h \
  libvirt.spec libvirt.spec.in \
  mingw-libvirt.spec.in \
  libvirt.pc.in \
  libvirt-qemu.pc.in \
  libvirt-lxc.pc.in \
  libvirt-admin.pc.in \
  Makefile.nonreentrant \
  autogen.sh \
  GNUmakefile \
  run.in \
  README.rst \
  AUTHORS.in \
  CONTRIBUTING.rst \
  NEWS.rst \
  scripts/apibuild.py \
  scripts/augeas-gentest.py \
  build-aux/check-spacing.pl \
  scripts/check-aclperms.py \
  scripts/check-aclrules.py \
  scripts/check-drivername.py \
  scripts/check-driverimpls.py \
  scripts/check-file-access.py \
  scripts/check-remote-protocol.py \
  scripts/check-symfile.py \
  scripts/check-symsorting.py \
  scripts/dtrace2systemtap.py \
  scripts/esx_vi_generator.py \
  scripts/genaclperms.py \
  scripts/genpolkit.py \
  scripts/gensystemtap.py \
  scripts/group-qemu-caps.py \
  scripts/header-ifdef.py \
  scripts/hvsupport.py \
  scripts/hyperv_wmi_generator.py \
  scripts/mock-noinline.py \
  scripts/prohibit-duplicate-header.py \
  scripts/test-wrap-argv.py \
  build-aux/syntax-check.mk \
  build-aux/useless-if-before-free \
  build-aux/vc-list-files \
  ci/Makefile \
  ci/build.sh \
  ci/list-images.sh \
  ci/prepare.sh \
  $(NULL)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libvirt.pc libvirt-qemu.pc libvirt-lxc.pc libvirt-admin.pc

rpm: clean
	@(unset CDPATH ; $(MAKE) dist && rpmbuild -ta $(distdir).tar.xz)

srpm: clean
	@(unset CDPATH ; $(MAKE) dist && rpmbuild -ts $(distdir).tar.xz)

check-local: all tests

check-access: all
	@($(MAKE) $(AM_MAKEFLAGS) -C tests check-access)

cov: clean-cov
	$(MKDIR_P) $(top_builddir)/coverage
	$(LCOV) -c -o $(top_builddir)/coverage/libvirt.info.tmp \
	  -d $(top_builddir)/src \
	  -d $(top_builddir)/tests
	$(LCOV) -r $(top_builddir)/coverage/libvirt.info.tmp \
	  -o $(top_builddir)/coverage/libvirt.info
	rm $(top_builddir)/coverage/libvirt.info.tmp
	$(GENHTML) --show-details -t "libvirt" -o $(top_builddir)/coverage \
	  --legend $(top_builddir)/coverage/libvirt.info

clean-cov:
	rm -rf $(top_builddir)/coverage

MAINTAINERCLEANFILES = .git-module-status

BUILT_SOURCES = configmake.h
CLEANFILES = configmake.h

distclean-local: clean-GNUmakefile
clean-GNUmakefile:
	test '$(srcdir)' = . || rm -f $(top_builddir)/GNUmakefile

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

# Listed in the same order as the GNU makefile conventions, and
# provided by autoconf 2.59c+ or 2.70.
# The Automake-defined pkg* macros are appended, in the order
# listed in the Automake 1.10a+ documentation.
configmake.h: Makefile
	$(AM_V_GEN)rm -f $@-t && \
	{ echo '/* DO NOT EDIT! GENERATED AUTOMATICALLY! */'; \
	  echo '#if WIN32'; \
	  echo '# include <winsock2.h> /* avoid mingw pollution on DATADIR */'; \
	  echo '#endif'; \
	  echo '#define PREFIX "$(prefix)"'; \
	  echo '#define EXEC_PREFIX "$(exec_prefix)"'; \
	  echo '#define BINDIR "$(bindir)"'; \
	  echo '#define SBINDIR "$(sbindir)"'; \
	  echo '#define LIBEXECDIR "$(libexecdir)"'; \
	  echo '#define DATAROOTDIR "$(datarootdir)"'; \
	  echo '#define DATADIR "$(datadir)"'; \
	  echo '#define SYSCONFDIR "$(sysconfdir)"'; \
	  echo '#define SHAREDSTATEDIR "$(sharedstatedir)"'; \
	  echo '#define LOCALSTATEDIR "$(localstatedir)"'; \
	  echo '#define RUNSTATEDIR "$(runstatedir)"'; \
	  echo '#define INCLUDEDIR "$(includedir)"'; \
	  echo '#define OLDINCLUDEDIR "$(oldincludedir)"'; \
	  echo '#define DOCDIR "$(docdir)"'; \
	  echo '#define INFODIR "$(infodir)"'; \
	  echo '#define HTMLDIR "$(htmldir)"'; \
	  echo '#define DVIDIR "$(dvidir)"'; \
	  echo '#define PDFDIR "$(pdfdir)"'; \
	  echo '#define PSDIR "$(psdir)"'; \
	  echo '#define LIBDIR "$(libdir)"'; \
	  echo '#define LISPDIR "$(lispdir)"'; \
	  echo '#define LOCALEDIR "$(localedir)"'; \
	  echo '#define MANDIR "$(mandir)"'; \
	  echo '#define MANEXT "$(manext)"'; \
	  echo '#define PKGDATADIR "$(pkgdatadir)"'; \
	  echo '#define PKGINCLUDEDIR "$(pkgincludedir)"'; \
	  echo '#define PKGLIBDIR "$(pkglibdir)"'; \
	  echo '#define PKGLIBEXECDIR "$(pkglibexecdir)"'; \
	} | sed '/""/d' > $@-t && \
	mv -f $@-t $@
