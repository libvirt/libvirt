# Makefile for libvirt python library

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

SUBDIRS= . tests

INCLUDES = \
	$(PYTHON_INCLUDES) \
	-I$(top_builddir)/gnulib/lib \
	-I$(top_srcdir)/gnulib/lib \
	-I$(top_builddir)/src \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/util \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include \
	$(GETTEXT_CPPFLAGS)

AM_CFLAGS = $(WARN_CFLAGS)

CLASSES_EXTRA = \
	libvirt-override-virConnect.py \
	libvirt-override-virDomain.py \
	libvirt-override-virDomainSnapshot.py \
	libvirt-override-virStoragePool.py \
	libvirt-override-virStream.py

EXTRA_DIST =			\
	generator.py		\
	typewrappers.c		\
	typewrappers.h		\
	libvirt-override.c	\
	libvirt-override.py	\
	libvirt-override-api.xml \
	libvirt-lxc-override.c	\
	libvirt-lxc-override-api.xml \
	libvirt-qemu-override.c	\
	libvirt-qemu-override-api.xml \
	sanitytest.py \
	$(CLASSES_EXTRA) \
	$(DOCS)

if WITH_PYTHON
mylibs = \
	$(top_builddir)/src/libvirt.la \
	$(top_builddir)/gnulib/lib/libgnu.la
myqemulibs = \
	$(top_builddir)/src/libvirt-qemu.la \
	$(top_builddir)/gnulib/lib/libgnu.la
mylxclibs = \
	$(top_builddir)/src/libvirt-lxc.la \
	$(top_builddir)/gnulib/lib/libgnu.la

all-local: libvirt.py libvirt_qemu.py libvirt_lxc.py

pyexec_LTLIBRARIES = libvirtmod.la libvirtmod_qemu.la libvirtmod_lxc.la

libvirtmod_la_SOURCES = libvirt-override.c typewrappers.c
nodist_libvirtmod_la_SOURCES = libvirt.c libvirt.h
# Python <= 2.4 header files contain a redundant decl, hence we
# need extra flags here
libvirtmod_la_CFLAGS = $(WARN_CFLAGS) $(WARN_PYTHON_CFLAGS)

libvirtmod_la_LDFLAGS = -module -avoid-version -shared \
	-L$(top_builddir)/src/.libs \
	$(CYGWIN_EXTRA_LDFLAGS)
libvirtmod_la_LIBADD = $(mylibs) \
	$(CYGWIN_EXTRA_LIBADD) $(CYGWIN_EXTRA_PYTHON_LIBADD)

libvirtmod_qemu_la_SOURCES = libvirt-qemu-override.c typewrappers.c
nodist_libvirtmod_qemu_la_SOURCES = libvirt-qemu.c libvirt-qemu.h
# Python <= 2.4 header files contain a redundant decl, hence we
# need extra flags here
libvirtmod_qemu_la_CFLAGS = $(WARN_PYTHON_CFLAGS)

libvirtmod_qemu_la_LDFLAGS = -module -avoid-version -shared \
	-L$(top_builddir)/src/.libs \
	$(CYGWIN_EXTRA_LDFLAGS)
libvirtmod_qemu_la_LIBADD = $(myqemulibs) \
	$(CYGWIN_EXTRA_LIBADD) $(CYGWIN_EXTRA_PYTHON_LIBADD)

libvirtmod_lxc_la_SOURCES = libvirt-lxc-override.c typewrappers.c
nodist_libvirtmod_lxc_la_SOURCES = libvirt-lxc.c libvirt-lxc.h
# Python <= 2.4 header files contain a redundant decl, hence we
# need extra flags here
libvirtmod_lxc_la_CFLAGS = $(WARN_PYTHON_CFLAGS)

libvirtmod_lxc_la_LDFLAGS = -module -avoid-version -shared \
	-L$(top_builddir)/src/.libs \
	$(CYGWIN_EXTRA_LDFLAGS)
libvirtmod_lxc_la_LIBADD = $(mylxclibs) \
	$(CYGWIN_EXTRA_LIBADD) $(CYGWIN_EXTRA_PYTHON_LIBADD)

GENERATE = generator.py
API_DESC = $(top_srcdir)/docs/libvirt-api.xml \
	$(srcdir)/libvirt-override-api.xml
GENERATED= libvirt-export.c \
	   libvirt.c \
	   libvirt.h \
	   libvirt.py

QEMU_API_DESC = $(top_srcdir)/docs/libvirt-qemu-api.xml \
	$(srcdir)/libvirt-qemu-override-api.xml
QEMU_GENERATED= libvirt-qemu-export.c \
	   libvirt-qemu.c \
	   libvirt-qemu.h \
	   libvirt_qemu.py

LXC_API_DESC = $(top_srcdir)/docs/libvirt-lxc-api.xml \
	$(srcdir)/libvirt-lxc-override-api.xml
LXC_GENERATED= libvirt-lxc-export.c \
	   libvirt-lxc.c \
	   libvirt-lxc.h \
	   libvirt_lxc.py

$(GENERATE).stamp: $(srcdir)/$(GENERATE) \
                   $(API_DESC) \
                   $(QEMU_API_DESC) \
                   $(LXC_API_DESC) \
                   $(CLASSES_EXTRA)
	$(AM_V_GEN)$(PYTHON) $(srcdir)/$(GENERATE) $(PYTHON) && \
	touch $@

$(GENERATED) $(QEMU_GENERATED) $(LXC_GENERATED): $(GENERATE).stamp

$(libvirtmod_la_OBJECTS): $(GENERATED)
$(libvirtmod_qemu_la_OBJECTS): $(QEMU_GENERATED)
$(libvirtmod_lxc_la_OBJECTS): $(LXC_GENERATED)

check-local:
	$(AM_V_GEN)../run $(PYTHON) $(srcdir)/sanitytest.py

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(pyexecdir)
	$(INSTALL) -m 0644 libvirt.py $(DESTDIR)$(pyexecdir)
	$(INSTALL) -m 0644 libvirt_lxc.py $(DESTDIR)$(pyexecdir)
	$(INSTALL) -m 0644 libvirt_qemu.py $(DESTDIR)$(pyexecdir)

uninstall-local:
	rm -f $(DESTDIR)$(pyexecdir)/libvirt.py
	rm -f $(DESTDIR)$(pyexecdir)/libvirt_lxc.py
	rm -f $(DESTDIR)$(pyexecdir)/libvirt_qemu.py

CLEANFILES= $(GENERATED) $(QEMU_GENERATED) $(LXC_GENERATED) $(GENERATE).stamp \
	*.pyc

else
all:
endif

dummy:

tests test: all dummy
	-@(cd tests && $(MAKE) MAKEFLAGS+=--silent tests)
