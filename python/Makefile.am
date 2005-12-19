# Makefile for libvir python library

INCLUDES = \
        -I$(PYTHON_INCLUDES) \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_builddir)/$(subdir)

DOCS_DIR = $(datadir)/doc/libvir-python-$(LIBVIR_VERSION)

DOCS = ${srcdir}/TODO

EXTRA_DIST =		\
	libvir.c	\
	types.c		\
	generator.py	\
	libvir_wrap.h	\
	libvir.py	\
	libvir-python-api.xml \
	$(DOCS)

libvirmod_la_LDFLAGS = -module -avoid-version -L$(top_builddir)/src/.libs

if WITH_PYTHON
mylibs = $(top_builddir)/src/libvir.la

all-local: libvir.py

python_LTLIBRARIES = libvirmod.la

libvirmod_la_SOURCES = libvir.c types.c libvir-py.c
libvirmod_la_LIBADD = $(mylibs) 


install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(pythondir)
	@INSTALL@ -m 0644 libvir.py $(DESTDIR)$(pythondir)
	$(mkinstalldirs) $(DESTDIR)$(DOCS_DIR)
	@(for doc in $(DOCS) ; \
	   do @INSTALL@ -m 0644 $$doc $(DESTDIR)$(DOCS_DIR) ; done)

GENERATE = generator.py
API_DESC = $(top_srcdir)/docs/libvir-api.xml $(srcdir)/libvir-python-api.xml
GENERATED= libvir.py \
           libvir-export.c \
           libvirclass.txt \
	   libvir-py.c \
	   libvir-py.h

CLEANFILES= $(GENERATED) gen_prog libvir.py

$(GENERATED): gen_prog

gen_prog: $(srcdir)/$(GENERATE) $(API_DESC)
	$(PYTHON) $(srcdir)/$(GENERATE) $(srcdir)
	touch gen_prog

$(libvirmod_la_OBJECTS): $(GENERATED)

else
all: 
endif
