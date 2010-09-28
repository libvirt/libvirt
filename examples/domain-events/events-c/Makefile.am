INCLUDES = -I$(top_builddir)/include -I$(top_srcdir)/include \
	   -I$(top_builddir)/gnulib/lib -I$(top_srcdir)/gnulib/lib
noinst_PROGRAMS = event-test
event_test_CFLAGS = $(WARN_CFLAGS)
event_test_SOURCES = event-test.c
event_test_LDADD = $(top_builddir)/src/libvirt.la \
		 $(top_builddir)/gnulib/lib/libgnu.la
