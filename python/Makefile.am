# Makefile for libvirt python library

SUBDIRS= . tests

INCLUDES = \
        $(WARN_CFLAGS) \
        -I$(PYTHON_INCLUDES) \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_builddir)/$(subdir)

DOCS_DIR = $(datadir)/doc/libvirt-python-$(LIBVIRT_VERSION)

DOCS = ${srcdir}/TODO

CLASSES_EXTRA = virConnect.py

EXTRA_DIST =		\
	libvir.c	\
	types.c		\
	generator.py	\
	libvirt_wrap.h	\
	libvirt.py	\
	libvir.py	\
	libvirt-python-api.xml \
	$(CLASSES_EXTRA) \
	$(DOCS)

if WITH_PYTHON
mylibs = $(top_builddir)/src/libvirt.la

all-local: libvirt.py

python_LTLIBRARIES = libvirtmod.la

libvirtmod_la_SOURCES = libvir.c types.c libvirt-py.c libvirt-py.h
# Python header files contain a redundant decl, hence:
libvirtmod_la_CFLAGS = -Wno-redundant-decls

libvirtmod_la_LDFLAGS = -module -avoid-version -L$(top_builddir)/src/.libs \
	@CYGWIN_EXTRA_LDFLAGS@
libvirtmod_la_LIBADD = $(mylibs) \
	@CYGWIN_EXTRA_LIBADD@ @CYGWIN_EXTRA_PYTHON_LIBADD@

GENERATE = generator.py
API_DESC = $(top_srcdir)/docs/libvirt-api.xml $(srcdir)/libvirt-python-api.xml
GENERATED= libvirt-export.c \
           libvirtclass.txt \
	   libvirt-py.c \
	   libvirt-py.h \
	   libvirtclass.py

$(GENERATED): $(srcdir)/$(GENERATE) $(API_DESC)
	$(PYTHON) $(srcdir)/$(GENERATE) $(srcdir)

libvirt.py: $(srcdir)/libvir.py $(GENERATED) $(CLASSES_EXTRA)
	cat $(srcdir)/libvir.py libvirtclass.py > $@-t
	mv $@-t $@

$(libvirtmod_la_OBJECTS): $(GENERATED)

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(pythondir)
	@INSTALL@ -m 0644 libvirt.py $(DESTDIR)$(pythondir)
	$(mkinstalldirs) $(DESTDIR)$(DOCS_DIR)
	@(for doc in $(DOCS) ; \
	   do @INSTALL@ -m 0644 $$doc $(DESTDIR)$(DOCS_DIR) ; done)

uninstall-local:
	rm -f $(DESTDIR)$(pythondir)/libvirt.py

CLEANFILES= $(GENERATED) libvirt.py

else
all:
endif

dummy:

tests test: all dummy
	-@(cd tests && $(MAKE) MAKEFLAGS+=--silent tests)
