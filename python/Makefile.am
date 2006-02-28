# Makefile for libvirt python library

SUBDIRS= . tests

INCLUDES = \
        -I$(PYTHON_INCLUDES) \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_builddir)/$(subdir)

DOCS_DIR = $(datadir)/doc/libvirt-python-$(LIBVIRT_VERSION)

DOCS = ${srcdir}/TODO

EXTRA_DIST =		\
	libvir.c	\
	types.c		\
	generator.py	\
	libvirt_wrap.h	\
	libvirt.py	\
	libvir.py	\
	libvirt-python-api.xml \
	$(DOCS)

libvirtmod_la_LDFLAGS = -module -avoid-version -L$(top_builddir)/src/.libs

if WITH_PYTHON
mylibs = $(top_builddir)/src/libvirt.la

all-local: libvirt.py

python_LTLIBRARIES = libvirtmod.la

libvirtmod_la_SOURCES = libvir.c types.c libvirt-py.c libvirt-py.h
libvirtmod_la_LIBADD = $(mylibs) 

libvirt.py: $(srcdir)/libvir.py libvirtclass.py
	cat $(srcdir)/libvir.py libvirtclass.py > libvirt.py

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(pythondir)
	@INSTALL@ -m 0644 libvirt.py $(DESTDIR)$(pythondir)
	$(mkinstalldirs) $(DESTDIR)$(DOCS_DIR)
	@(for doc in $(DOCS) ; \
	   do @INSTALL@ -m 0644 $$doc $(DESTDIR)$(DOCS_DIR) ; done)

GENERATE = generator.py
API_DESC = $(top_srcdir)/docs/libvirt-api.xml $(srcdir)/libvirt-python-api.xml
GENERATED= libvirt.py \
           libvirt-export.c \
           libvirtclass.txt \
	   libvirt-py.c \
	   libvirt-py.h \
	   libvirtclass.py

CLEANFILES= $(GENERATED) gen_prog libvirt.py

$(GENERATED): gen_prog

gen_prog: $(srcdir)/$(GENERATE) $(API_DESC)
	$(PYTHON) $(srcdir)/$(GENERATE) $(srcdir)
	touch gen_prog

$(libvirtmod_la_OBJECTS): $(GENERATED)

else
all: 
endif

dummy:

tests test: all dummy
	-@(cd tests && $(MAKE) MAKEFLAGS+=--silent tests)
