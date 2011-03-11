# Makefile for libvirt python library

SUBDIRS= . tests

INCLUDES = \
        $(WARN_CFLAGS) \
        $(PYTHON_INCLUDES) \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_builddir)/$(subdir)

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
	$(CLASSES_EXTRA) \
	$(DOCS)

if WITH_PYTHON
mylibs = $(top_builddir)/src/libvirt.la

all-local: libvirt.py

pyexec_LTLIBRARIES = libvirtmod.la

libvirtmod_la_SOURCES = libvirt-override.c typewrappers.c
nodist_libvirtmod_la_SOURCES = libvirt.c libvirt.h
# Python <= 2.4 header files contain a redundant decl, hence we
# need extra flags here
libvirtmod_la_CFLAGS = $(WARN_PYTHON_CFLAGS)

libvirtmod_la_LDFLAGS = -module -avoid-version -shared -L$(top_builddir)/src/.libs \
	$(CYGWIN_EXTRA_LDFLAGS)
libvirtmod_la_LIBADD = $(mylibs) \
	$(CYGWIN_EXTRA_LIBADD) $(CYGWIN_EXTRA_PYTHON_LIBADD)

GENERATE = generator.py
API_DESC = $(top_srcdir)/docs/libvirt-api.xml $(srcdir)/libvirt-override-api.xml
GENERATED= libvirt-export.c \
	   libvirt.c \
	   libvirt.h \
	   libvirt.py

generated.stamp: $(srcdir)/$(GENERATE) $(API_DESC)
	$(PYTHON) $(srcdir)/$(GENERATE) $(PYTHON)
	touch $@

$(GENERATED): generated.stamp

$(libvirtmod_la_OBJECTS): $(GENERATED)

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(pyexecdir)
	$(INSTALL) -m 0644 libvirt.py $(DESTDIR)$(pyexecdir)
	$(mkinstalldirs) $(DESTDIR)$(DOCS_DIR)
	@(for doc in $(DOCS) ; \
	   do $(INSTALL) -m 0644 $$doc $(DESTDIR)$(DOCS_DIR) ; done)

uninstall-local:
	rm -f $(DESTDIR)$(pyexecdir)/libvirt.py

CLEANFILES= $(GENERATED) generated.stamp

else
all:
endif

dummy:

tests test: all dummy
	-@(cd tests && $(MAKE) MAKEFLAGS+=--silent tests)
