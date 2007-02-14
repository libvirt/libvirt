## Process this file with automake to produce Makefile.in

INCLUDES = @LIBXML_CFLAGS@

libexec_PROGRAMS = libvirt_qemud

libvirt_qemud_SOURCES = qemud.c internal.h protocol.h \
                driver.c driver.h \
                dispatch.c dispatch.h \
                config.c config.h
#-D_XOPEN_SOURCE=600 -D_XOPEN_SOURCE_EXTENDED=1 -D_POSIX_C_SOURCE=199506L
libvirt_qemud_CFLAGS = \
        -I$(top_srcdir)/include -I$(top_builddir)/include $(LIBXML_CFLAGS) \
        -Werror -Wall -Wextra -DLOCAL_STATE_DIR="\"$(localstatedir)\"" \
        -DSYSCONF_DIR="\"$(sysconfdir)\""
libvirt_qemud_LDFLAGS = $(LIBXML_LIBS)
libvirt_qemud_DEPENDENCIES =
libvirt_qemud_LDADD =

