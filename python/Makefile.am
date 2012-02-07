# Makefile for libvirt python library

## Copyright (C) 2005-2012 Red Hat, Inc.
## See COPYING.LIB for the License of this software

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

DOCS_DIR = $(datadir)/doc/libvirt-python-$(LIBVIRT_VERSION)

DOCS = ${srcdir}/TODO

CLASSES_EXTRA = \
	libvirt-override-virConnect.py \
	libvirt-override-virStream.py

EXTRA_DIST =			\
	generator.py		\
	typewrappers.c		\
	typewrappers.h		\
	libvirt-override.c	\
	libvirt-override.py	\
	libvirt-override-api.xml \
	libvirt-qemu-override.c	\
	libvirt-qemu-override-api.xml \
	$(CLASSES_EXTRA) \
	$(DOCS)

if WITH_PYTHON
mylibs = \
	$(top_builddir)/src/libvirt.la \
	$(top_builddir)/gnulib/lib/libgnu.la
myqemulibs = \
	$(top_builddir)/src/libvirt-qemu.la \
	$(top_builddir)/gnulib/lib/libgnu.la

all-local: libvirt.py libvirt_qemu.py

pyexec_LTLIBRARIES = libvirtmod.la libvirtmod_qemu.la

libvirtmod_la_SOURCES = libvirt-override.c typewrappers.c
nodist_libvirtmod_la_SOURCES = libvirt.c libvirt.h
# Python <= 2.4 header files contain a redundant decl, hence we
# need extra flags here
libvirtmod_la_CFLAGS = $(WARN_CFLAGS) $(WARN_PYTHON_CFLAGS)

libvirtmod_la_LDFLAGS = -module -avoid-version -shared -L$(top_builddir)/src/.libs \
	$(CYGWIN_EXTRA_LDFLAGS)
libvirtmod_la_LIBADD = $(mylibs) \
	$(CYGWIN_EXTRA_LIBADD) $(CYGWIN_EXTRA_PYTHON_LIBADD)

libvirtmod_qemu_la_SOURCES = libvirt-qemu-override.c typewrappers.c
nodist_libvirtmod_qemu_la_SOURCES = libvirt-qemu.c libvirt-qemu.h
# Python <= 2.4 header files contain a redundant decl, hence we
# need extra flags here
libvirtmod_qemu_la_CFLAGS = $(WARN_PYTHON_CFLAGS)

libvirtmod_qemu_la_LDFLAGS = -module -avoid-version -shared -L$(top_builddir)/src/.libs \
	$(CYGWIN_EXTRA_LDFLAGS)
libvirtmod_qemu_la_LIBADD = $(myqemulibs) \
	$(CYGWIN_EXTRA_LIBADD) $(CYGWIN_EXTRA_PYTHON_LIBADD)

GENERATE = generator.py
API_DESC = $(top_srcdir)/docs/libvirt-api.xml $(srcdir)/libvirt-override-api.xml
GENERATED= libvirt-export.c \
	   libvirt.c \
	   libvirt.h \
	   libvirt.py

QEMU_API_DESC = $(top_srcdir)/docs/libvirt-qemu-api.xml $(srcdir)/libvirt-qemu-override-api.xml
QEMU_GENERATED= libvirt-qemu-export.c \
	   libvirt-qemu.c \
	   libvirt-qemu.h \
	   libvirt_qemu.py

$(GENERATE).stamp: $(srcdir)/$(GENERATE) $(API_DESC) $(QEMU_API_DESC)
	$(AM_V_GEN)$(PYTHON) $(srcdir)/$(GENERATE) $(PYTHON) && \
	touch $@

$(GENERATED) $(QEMU_GENERATED): $(GENERATE).stamp

$(libvirtmod_la_OBJECTS): $(GENERATED)
$(libvirtmod_qemu_la_OBJECTS): $(QEMU_GENERATED)

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(pyexecdir)
	$(INSTALL) -m 0644 libvirt.py $(DESTDIR)$(pyexecdir)
	$(INSTALL) -m 0644 libvirt_qemu.py $(DESTDIR)$(pyexecdir)
	$(mkinstalldirs) $(DESTDIR)$(DOCS_DIR)
	@(for doc in $(DOCS) ; \
	   do $(INSTALL) -m 0644 $$doc $(DESTDIR)$(DOCS_DIR) ; done)

uninstall-local:
	rm -f $(DESTDIR)$(pyexecdir)/libvirt.py
	rm -f $(DESTDIR)$(pyexecdir)/libvirt_qemu.py

CLEANFILES= $(GENERATED) $(QEMU_GENERATED) $(GENERATE).stamp

else
all:
endif

dummy:

tests test: all dummy
	-@(cd tests && $(MAKE) MAKEFLAGS+=--silent tests)
