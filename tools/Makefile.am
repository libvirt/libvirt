
POD2MAN = pod2man -c "Virtualization Support" -r "$(PACKAGE)-$(VERSION)"

ICON_FILES = \
	libvirt_win_icon_16x16.ico \
	libvirt_win_icon_32x32.ico \
	libvirt_win_icon_48x48.ico \
	libvirt_win_icon_64x64.ico \
	virsh_win_icon.rc

EXTRA_DIST = $(ICON_FILES) virt-xml-validate.in virt-pki-validate.in virsh.pod

bin_SCRIPTS = virt-xml-validate virt-pki-validate
bin_PROGRAMS = virsh

man1_MANS = virt-xml-validate.1 virt-pki-validate.1 virsh.1


virt-xml-validate: virt-xml-validate.in Makefile
	$(AM_V_GEN)sed -e 's,@SCHEMADIR@,$(pkgdatadir)/schemas,' < $< > $@ \
	    || (rm $@ && exit 1) && chmod +x $@

virt-xml-validate.1: virt-xml-validate
	$(AM_V_GEN)$(POD2MAN) $< $@

virt-pki-validate: virt-pki-validate.in Makefile
	$(AM_V_GEN)sed -e 's,@SYSCONFDIR@,$(sysconfdir),' < $< > $@ \
	    || (rm $@ && exit 1) && chmod +x $@

virt-pki-validate.1: virt-pki-validate
	$(AM_V_GEN)$(POD2MAN) $< $@

virsh_SOURCES =							\
		console.c console.h				\
		virsh.c

virsh_LDFLAGS = $(WARN_LDFLAGS) $(COVERAGE_LDFLAGS)
virsh_LDADD =							\
		$(STATIC_BINARIES)				\
		$(WARN_CFLAGS)					\
		../src/libvirt.la				\
		../gnulib/lib/libgnu.la				\
		$(VIRSH_LIBS)
virsh_CFLAGS =							\
		-I$(top_srcdir)/gnulib/lib -I../gnulib/lib	\
		-I../include -I$(top_srcdir)/include		\
		-I$(top_srcdir)/src				\
		-I$(top_srcdir)/src/util			\
		-DGETTEXT_PACKAGE=\"$(PACKAGE)\"		\
		-DLOCALEBASEDIR=\""$(datadir)/locale"\"		\
		$(WARN_CFLAGS)					\
		$(COVERAGE_CFLAGS)				\
		$(LIBXML_CFLAGS)				\
		$(READLINE_CFLAGS)
BUILT_SOURCES = virsh-net-edit.c virsh-pool-edit.c

virsh-net-edit.c: virsh.c Makefile.am
	$(AM_V_GEN)rm -f $@-tmp && \
	echo '/* Automatically generated from: $^ */' > $@-tmp && \
	echo 'static int' >> $@-tmp && \
	awk '/^cmdEdit/, /^}/' $< \
	  | sed -e 's/domain/network/g' \
	      -e 's/Domain/Network/g' \
	      -e 's/cmdEdit/cmdNetworkEdit/g' \
	      -e 's/dom/network/g' \
	      -e 's/int flags.*/int flags = 0;/g' \
	>> $@-tmp && \
	chmod a-w $@-tmp && \
	rm -f $@ && \
	mv $@-tmp $@

virsh-pool-edit.c: virsh.c Makefile.am
	$(AM_V_GEN)rm -f $@-tmp && \
	echo '/* Automatically generated from: $^ */' > $@-tmp && \
	echo 'static int' >> $@-tmp && \
	awk '/^cmdEdit/, /^}/' $< \
	  | sed -e 's/domain/pool/g' \
	      -e 's/vshCommandOptDomain/vshCommandOptPool/g' \
	      -e 's/Domain %s/Pool %s/g' \
	      -e 's/(ctl, cmd, NULL);/(ctl, cmd, "pool", NULL);/' \
	      -e 's/Domain/StoragePool/g' \
	      -e 's/cmdEdit/cmdPoolEdit/g' \
	      -e 's/\(virStoragePoolDefineXML.*\));/\1, 0);/' \
	      -e 's/dom/pool/g' \
	      -e 's/int flags.*/int flags = 0;/g' \
	>> $@-tmp && \
	chmod a-w $@-tmp && \
	rm -f $@ && \
	mv $@-tmp $@


if WITH_WIN_ICON
virsh_LDADD += virsh_win_icon.$(OBJEXT)

# Before you edit virsh_win_icon.rc, please note the following
# limitations of the resource file format:
#
# (1) '..' is not permitted in the icon filename field.
# (2) '-' is not permitted in the icon filename field.
# (3) Comments are not permitted in the file.
#
# Windows appears to choose the first <= 32x32 icon it finds
# in the resource file.  Therefore you should list the available
# icons from largest to smallest, and make sure that the 32x32
# icon is the most legible.
#
# Windows .ICO is a special MS-only format.  GIMP and other
# tools can write it.  However there are several variations,
# and Windows seems to do its own colour quantization.  More
# information is needed in this area.

virsh_win_icon.$(OBJEXT): virsh_win_icon.rc
	$(AM_V_GEN)$(WINDRES) \
	  --input-format rc --input $< \
	  --output-format coff --output $@
endif

virsh.1: virsh.pod
	$(AM_V_GEN)$(POD2MAN) $< $@


CLEANFILES = $(bin_SCRIPTS) $(man1_MANS)

DISTCLEANFILES = $(BUILT_SOURCES)
