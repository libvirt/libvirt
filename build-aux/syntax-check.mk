#
# Rules for running syntax-check, derived from gnulib's
# maint.mk
#
# Copyright (C) 2008-2019 Red Hat, Inc.
# Copyright (C) 2003-2019 Free Software Foundation, Inc.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see
# <http://www.gnu.org/licenses/>.

# This is reported not to work with make-3.79.1
# ME := $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST))
ME := $(_build-aux)/syntax-check.mk

# These variables ought to be defined through the configure.ac section
# of the module description. But some packages import this file directly,
# ignoring the module description.
AWK ?= awk
GREP ?= grep
SED ?= sed

# Helper variables.
_empty =
_sp = $(_empty) $(_empty)

# _equal,S1,S2
# ------------
# If S1 == S2, return S1, otherwise the empty string.
_equal = $(and $(findstring $(1),$(2)),$(findstring $(2),$(1)))

GIT = git
VC = $(GIT)

VC_LIST = $(srcdir)/$(_build-aux)/vc-list-files -C $(srcdir)

# You can override this variable in syntax-check.mk if your gnulib submodule lives
# in a different location.
gnulib_dir ?= $(srcdir)/gnulib

# You can override this variable in syntax-check.mk to set your own regexp
# matching files to ignore.
VC_LIST_ALWAYS_EXCLUDE_REGEX ?= ^$$

# This is to preprocess robustly the output of $(VC_LIST), so that even
# when $(srcdir) is a pathological name like "....", the leading sed command
# removes only the intended prefix.
_dot_escaped_srcdir = $(subst .,\.,$(srcdir))

# Post-process $(VC_LIST) output, prepending $(srcdir)/, but only
# when $(srcdir) is not ".".
ifeq ($(srcdir),.)
  _prepend_srcdir_prefix =
else
  _prepend_srcdir_prefix = | $(SED) 's|^|$(srcdir)/|'
endif

# In order to be able to consistently filter "."-relative names,
# (i.e., with no $(srcdir) prefix), this definition is careful to
# remove any $(srcdir) prefix, and to restore what it removes.
_sc_excl = \
  $(or $(exclude_file_name_regexp--$@),^$$)
VC_LIST_EXCEPT = \
  $(VC_LIST) | $(SED) 's|^$(_dot_escaped_srcdir)/||' \
	| if test -f $(srcdir)/.x-$@; then $(GREP) -vEf $(srcdir)/.x-$@; \
	  else $(GREP) -Ev -e "$${VC_LIST_EXCEPT_DEFAULT-ChangeLog}"; fi \
	| $(GREP) -Ev -e '($(VC_LIST_ALWAYS_EXCLUDE_REGEX)|$(_sc_excl))' \
	$(_prepend_srcdir_prefix)

# Override this in syntax-check.mk if you are using a different format in your
# NEWS file.
today = $(shell date +%Y-%m-%d)

# Prevent programs like 'sort' from considering distinct strings to be equal.
# Doing it here saves us from having to set LC_ALL elsewhere in this file.
export LC_ALL = C

## --------------- ##
## Sanity checks.  ##
## --------------- ##

_cfg_mk := $(wildcard $(srcdir)/$(_build-aux)/syntax-check.mk)

# Collect the names of rules starting with 'sc_'.
syntax-check-rules := $(sort $(shell $(SED) -n \
   's/^\(sc_[a-zA-Z0-9_-]*\):.*/\1/p' $(srcdir)/$(ME) $(_cfg_mk)))
.PHONY: $(syntax-check-rules)

ifeq ($(shell $(VC_LIST) >/dev/null 2>&1; echo $$?),0)
  local-checks-available += $(syntax-check-rules)
else
  local-checks-available += no-vc-detected
no-vc-detected:
	@echo "No version control files detected; skipping syntax check"
endif
.PHONY: $(local-checks-available)

# Arrange to print the name of each syntax-checking rule just before running it.
$(syntax-check-rules): %: %.m
sc_m_rules_ = $(patsubst %, %.m, $(syntax-check-rules))
.PHONY: $(sc_m_rules_)
$(sc_m_rules_):
	@echo $(patsubst sc_%.m, %, $@)
	@date +%s.%N > .sc-start-$(basename $@)

# Compute and print the elapsed time for each syntax-check rule.
sc_z_rules_ = $(patsubst %, %.z, $(syntax-check-rules))
.PHONY: $(sc_z_rules_)
$(sc_z_rules_): %.z: %
	@end=$$(date +%s.%N);						\
	start=$$(cat .sc-start-$*);					\
	rm -f .sc-start-$*;						\
	$(AWK) -v s=$$start -v e=$$end					\
	  'END {printf "%.2f $(patsubst sc_%,%,$*)\n", e - s}' < /dev/null

# The patsubst here is to replace each sc_% rule with its sc_%.z wrapper
# that computes and prints elapsed time.
local-check :=								\
  $(patsubst sc_%, sc_%.z,						\
    $(filter-out $(local-checks-to-skip), $(local-checks-available)))

syntax-check: $(local-check)

# We use .gnulib, not gnulib.
gnulib_dir = $(srcdir)/.gnulib

# List of additional files that we want to pick up in our POTFILES.in
# This is all gnulib files, as well as generated files for RPC code.
generated_files = \
  $(srcdir)/src/*/{remote_daemon,admin_server,log_daemon,lock_daemon}_dispatch_*stubs.h \
  $(srcdir)/src/lxc/{lxc_monitor,lxc_controller}_dispatch.h \
  $(srcdir)/src/remote/*_client_bodies.h \
  $(srcdir)/src/*/*_protocol.[ch] \
  $(srcdir)/gnulib/lib/*.[ch]

# We haven't converted all scripts to using gnulib's init.sh yet.
_test_script_regex = \<\(init\|test-lib\)\.sh\>

# Most developers don't run 'make distcheck'.  We want the official
# dist to be secure, but don't want to penalize other developers
# using a distro that has not yet picked up the automake fix.
# FIXME remove this ifeq (making the syntax check unconditional)
# once fixed automake (1.11.6 or 1.12.2+) is more common.
ifeq ($(filter dist%, $(MAKECMDGOALS)), )
local-checks-to-skip +=	sc_vulnerable_makefile_CVE-2012-3386
else
distdir: sc_vulnerable_makefile_CVE-2012-3386.z
endif

# Files that should never cause syntax check failures.
VC_LIST_ALWAYS_EXCLUDE_REGEX = \
  (^(docs/(news(-[0-9]*)?\.html\.in|.*\.patch))|\.(po|fig|gif|ico|png))$$

# Functions like free() that are no-ops on NULL arguments.
useless_free_options = \
  --name=VBOX_UTF16_FREE \
  --name=VBOX_UTF8_FREE \
  --name=VBOX_COM_UNALLOC_MEM \
  --name=VIR_FREE \
  --name=qemuCapsFree \
  --name=qemuMigrationCookieFree \
  --name=qemuMigrationCookieGraphicsFree \
  --name=sexpr_free \
  --name=usbFreeDevice \
  --name=virBandwidthDefFree \
  --name=virBitmapFree \
  --name=virCPUDefFree \
  --name=virCapabilitiesFree \
  --name=virCapabilitiesFreeGuest \
  --name=virCapabilitiesFreeGuestDomain \
  --name=virCapabilitiesFreeGuestFeature \
  --name=virCapabilitiesFreeGuestMachine \
  --name=virCapabilitiesFreeHostNUMACell \
  --name=virCapabilitiesFreeMachines \
  --name=virCgroupFree \
  --name=virCommandFree \
  --name=virConfFreeList \
  --name=virConfFreeValue \
  --name=virDomainActualNetDefFree \
  --name=virDomainChrDefFree \
  --name=virDomainControllerDefFree \
  --name=virDomainDefFree \
  --name=virDomainDeviceDefFree \
  --name=virDomainDiskDefFree \
  --name=virDomainEventCallbackListFree \
  --name=virObjectEventQueueFree \
  --name=virDomainFSDefFree \
  --name=virDomainGraphicsDefFree \
  --name=virDomainHostdevDefFree \
  --name=virDomainInputDefFree \
  --name=virDomainNetDefFree \
  --name=virDomainObjFree \
  --name=virDomainSmartcardDefFree \
  --name=virDomainSnapshotObjFree \
  --name=virDomainSoundDefFree \
  --name=virDomainVideoDefFree \
  --name=virDomainWatchdogDefFree \
  --name=virFileDirectFdFree \
  --name=virHashFree \
  --name=virInterfaceDefFree \
  --name=virInterfaceIpDefFree \
  --name=virInterfaceObjFree \
  --name=virInterfaceProtocolDefFree \
  --name=virJSONValueFree \
  --name=virLastErrFreeData \
  --name=virNetMessageFree \
  --name=virNWFilterDefFree \
  --name=virNWFilterEntryFree \
  --name=virNWFilterHashTableFree \
  --name=virNWFilterIPAddrLearnReqFree \
  --name=virNWFilterIncludeDefFree \
  --name=virNWFilterObjFree \
  --name=virNWFilterRuleDefFree \
  --name=virNWFilterRuleInstFree \
  --name=virNetworkDefFree \
  --name=virNodeDeviceDefFree \
  --name=virNodeDeviceObjFree \
  --name=virObjectUnref \
  --name=virObjectFreeCallback \
  --name=virPCIDeviceFree \
  --name=virSecretDefFree \
  --name=virStorageEncryptionFree \
  --name=virStorageEncryptionSecretFree \
  --name=virStorageFileFreeMetadata \
  --name=virStoragePoolDefFree \
  --name=virStoragePoolObjFree \
  --name=virStoragePoolSourceFree \
  --name=virStorageVolDefFree \
  --name=virThreadPoolFree \
  --name=xmlBufferFree \
  --name=xmlFree \
  --name=xmlFreeDoc \
  --name=xmlFreeNode \
  --name=xmlXPathFreeContext \
  --name=xmlXPathFreeObject

# The following template was generated by this command:
# make ID && aid free|grep '^vi'|sed 's/ .*//;s/^/#   /'
# N virBufferFreeAndReset
# y virCPUDefFree
# y virCapabilitiesFree
# y virCapabilitiesFreeGuest
# y virCapabilitiesFreeGuestDomain
# y virCapabilitiesFreeGuestFeature
# y virCapabilitiesFreeGuestMachine
# y virCapabilitiesFreeHostNUMACell
# y virCapabilitiesFreeMachines
# N virCapabilitiesFreeNUMAInfo FIXME
# y virCgroupFree
# N virConfFree               (diagnoses the "error")
# y virConfFreeList
# y virConfFreeValue
# y virDomainChrDefFree
# y virDomainControllerDefFree
# y virDomainDefFree
# y virDomainDeviceDefFree
# y virDomainDiskDefFree
# y virDomainEventCallbackListFree
# y virDomainEventQueueFree
# y virDomainFSDefFree
# n virDomainFree
# n virDomainFreeName (can't fix -- returns int)
# y virDomainGraphicsDefFree
# y virDomainHostdevDefFree
# y virDomainInputDefFree
# y virDomainNetDefFree
# y virDomainObjFree
# n virDomainSnapshotFree (returns int)
# n virDomainSnapshotFreeName (returns int)
# y virDomainSnapshotObjFree
# y virDomainSoundDefFree
# y virDomainVideoDefFree
# y virDomainWatchdogDefFree
# n virDrvNodeGetCellsFreeMemory (returns int)
# n virDrvNodeGetFreeMemory (returns long long)
# n virFree - dereferences param
# n virFreeError
# n virHashFree (takes 2 args)
# y virInterfaceDefFree
# n virInterfaceFree (returns int)
# n virInterfaceFreeName
# y virInterfaceIpDefFree
# y virInterfaceObjFree
# n virInterfaceObjListFree
# y virInterfaceProtocolDefFree
# y virJSONValueFree
# y virLastErrFreeData
# y virNWFilterDefFree
# y virNWFilterEntryFree
# n virNWFilterFree (returns int)
# y virNWFilterHashTableFree
# y virNWFilterIPAddrLearnReqFree
# y virNWFilterIncludeDefFree
# n virNWFilterFreeName (returns int)
# y virNWFilterObjFree
# n virNWFilterObjListFree FIXME
# y virNWFilterRuleDefFree
# n virNWFilterRuleFreeInstanceData (typedef)
# y virNWFilterRuleInstFree
# y virNetworkDefFree
# n virNetworkFree (returns int)
# n virNetworkFreeName (returns int)
# n virNodeDevCapsDefFree FIXME
# y virNodeDeviceDefFree
# n virNodeDeviceFree (returns int)
# y virNodeDeviceObjFree
# n virNodeDeviceObjListFree FIXME
# n virNodeGetCellsFreeMemory (returns int)
# n virNodeGetFreeMemory (returns non-void)
# y virSecretDefFree
# n virSecretFree (returns non-void)
# n virSecretFreeName (2 args)
# n virSecurityLabelDefFree FIXME
# n virStorageBackendDiskMakeFreeExtent (returns non-void)
# y virStorageEncryptionFree
# y virStorageEncryptionSecretFree
# n virStorageFreeType (enum)
# y virStoragePoolDefFree
# n virStoragePoolFree (returns non-void)
# n virStoragePoolFreeName (returns non-void)
# y virStoragePoolObjFree
# n virStoragePoolObjListFree FIXME
# y virStoragePoolSourceFree
# y virStorageVolDefFree
# n virStorageVolFree (returns non-void)
# n virStorageVolFreeName (returns non-void)
# n virStreamFree

# Avoid uses of write(2).  Either switch to streams (fwrite), or use
# the safewrite wrapper.
sc_avoid_write:
	@prohibit='\<write *\(' \
	in_vc_files='\.c$$' \
	halt='consider using safewrite instead of write' \
	  $(_sc_search_regexp)

# In debug statements, print flags as bitmask and mode_t as octal.
sc_flags_debug:
	@prohibit='\<mode=%[0-9.]*[diuxo]' \
	halt='use \"0%o\" to debug mode_t values' \
	  $(_sc_search_regexp)
	@prohibit='[Ff]lags=%[0-9.]*l*[dioux]' \
	halt='use \"0x%x\" to debug flag values' \
	  $(_sc_search_regexp)

# Prefer 'unsigned int flags', along with checks for unknown flags.
# For historical reasons, we are stuck with 'unsigned long flags' in
# migration, so check for those known 4 instances and no more in public
# API.  Also check that no flags are marked unused, and 'unsigned' should
# appear before any declaration of a flags variable (achieved by
# prohibiting the word prior to the type from ending in anything other
# than d).  The existence of long long, and of documentation about
# flags, makes the regex in the third test slightly harder.
sc_flags_usage:
	@test "$$(cat $(srcdir)/include/libvirt/libvirt-domain.h \
	    $(srcdir)/include/libvirt/virterror.h \
	    $(srcdir)/include/libvirt/libvirt-qemu.h \
	    $(srcdir)/include/libvirt/libvirt-lxc.h \
	    $(srcdir)/include/libvirt/libvirt-admin.h \
	  | $(GREP) -c '\(long\|unsigned\) flags')" != 4 && \
	  { echo '$(ME): new API should use "unsigned int flags"' 1>&2; \
	    exit 1; } || :
	@prohibit=' flags ATTRIBUTE_UNUSED' \
	exclude='virSecurityDomainImageLabelFlags' \
	halt='flags should be checked with virCheckFlags' \
	  $(_sc_search_regexp)
	@prohibit='^[^@]*([^d] (int|long long)|[^dg] long) flags[;,)]' \
	halt='flags should be unsigned' \
	  $(_sc_search_regexp)

# Avoid functions that should only be called via macro counterparts.
sc_prohibit_internal_functions:
	@prohibit='vir(Free|AllocN?|ReallocN|(Insert|Delete)ElementsN|File(Close|Fclose|Fdopen)) *\(' \
	halt='use VIR_ macros instead of internal functions' \
	  $(_sc_search_regexp)

sc_prohibit_raw_virclassnew:
	@prohibit='virClassNew *\(' \
	halt='use VIR_CLASS_NEW instead of virClassNew' \
	  $(_sc_search_regexp)

# Avoid raw malloc and free, except in documentation comments.
sc_prohibit_raw_allocation:
	@prohibit='^.[^*].*\<((m|c|re)alloc|free) *\([^)]' \
	halt='use VIR_ macros from viralloc.h instead of malloc/free' \
	  $(_sc_search_regexp)

# Avoid functions that can lead to double-close bugs.
sc_prohibit_close:
	@prohibit='([^>.]|^)\<[fp]?close *\(' \
	halt='use VIR_{FORCE_}[F]CLOSE instead of [f]close' \
	  $(_sc_search_regexp)
	@prohibit='\<fdopen *\(' \
	halt='use VIR_FDOPEN instead of fdopen' \
	  $(_sc_search_regexp)

# Prefer virCommand for all child processes.
sc_prohibit_fork_wrappers:
	@prohibit='= *\<(fork|popen|system) *\(' \
	halt='use virCommand for child processes' \
	  $(_sc_search_regexp)

# Prefer mkostemp with O_CLOEXEC.
sc_prohibit_mkstemp:
	@prohibit='[^"]\<mkstemps? *\(' \
	halt='use mkostemp with O_CLOEXEC instead of mkstemp' \
	  $(_sc_search_regexp)

# access with X_OK accepts directories, but we can't exec() those.
# access with F_OK or R_OK is okay, though.
sc_prohibit_access_xok:
	@prohibit='access(at)? *\(.*X_OK' \
	halt='use virFileIsExecutable instead of access(,X_OK)' \
	  $(_sc_search_regexp)

# Similar to the gnulib syntax-check.mk rule for sc_prohibit_strcmp
# Use STREQLEN or STRPREFIX rather than comparing strncmp == 0, or != 0.
snp_ = strncmp *\(.+\)
sc_prohibit_strncmp:
	@prohibit='! *strncmp *\(|\<$(snp_) *[!=]=|[!=]= *$(snp_)' \
	exclude=':# *define STR(N?EQLEN|PREFIX)\(' \
	halt='use STREQLEN or STRPREFIX instead of strncmp' \
	  $(_sc_search_regexp)

# strtol and friends are too easy to misuse
sc_prohibit_strtol:
	@prohibit='\bstrto(u?ll?|[ui]max) *\(' \
	exclude='exempt from syntax-check' \
	halt='use virStrToLong_*, not strtol variants' \
	  $(_sc_search_regexp)
	@prohibit='\bstrto[df] *\(' \
	exclude='exempt from syntax-check' \
	halt='use virStrToDouble, not strtod variants' \
	  $(_sc_search_regexp)

# Use virAsprintf rather than as'printf since *strp is undefined on error.
# But for plain %s, virAsprintf is overkill compared to strdup.
sc_prohibit_asprintf:
	@prohibit='\<v?a[s]printf\>' \
	halt='use virAsprintf, not asprintf' \
	  $(_sc_search_regexp)
	@prohibit='virAsprintf.*, *"%s",' \
	halt='use VIR_STRDUP instead of virAsprintf with "%s"' \
	  $(_sc_search_regexp)

sc_prohibit_strdup:
	@prohibit='\<strn?dup\> *\(' \
	halt='use VIR_STRDUP, not strdup' \
	  $(_sc_search_regexp)

# Prefer virSetUIDGID.
sc_prohibit_setuid:
	@prohibit='\<set(re)?[ug]id\> *\(' \
	halt='use virSetUIDGID, not raw set*id' \
	  $(_sc_search_regexp)

# Don't compare *id_t against raw -1.
sc_prohibit_risky_id_promotion:
	@prohibit='\b(user|group|[ug]id) *[=!]= *-' \
	halt='cast -1 to ([ug]id_t) before comparing against id' \
	  $(_sc_search_regexp)

# Use snprintf rather than s'printf, even if buffer is provably large enough,
# since gnulib has more guarantees for snprintf portability
sc_prohibit_sprintf:
	@prohibit='\<[s]printf\>' \
	halt='use snprintf, not sprintf' \
	  $(_sc_search_regexp)

sc_prohibit_readlink:
	@prohibit='\<readlink *\(' \
	halt='use virFileResolveLink, not readlink' \
	  $(_sc_search_regexp)

sc_prohibit_gethostname:
	@prohibit='gethostname *\(' \
	halt='use virGetHostname, not gethostname' \
	  $(_sc_search_regexp)

sc_prohibit_readdir:
	@prohibit='\b(read|close|open)dir *\(' \
	exclude='exempt from syntax-check' \
	halt='use virDirOpen, virDirRead and VIR_DIR_CLOSE' \
	  $(_sc_search_regexp)

sc_prohibit_gettext_noop:
	@prohibit='gettext_noop *\(' \
	halt='use N_, not gettext_noop' \
	  $(_sc_search_regexp)

sc_prohibit_VIR_ERR_NO_MEMORY:
	@prohibit='\<VIR_ERR_NO_MEMORY\>' \
	halt='use virReportOOMError, not VIR_ERR_NO_MEMORY' \
	  $(_sc_search_regexp)

sc_prohibit_PATH_MAX:
	@prohibit='\<PATH_MAX\>' \
	halt='dynamically allocate paths, do not use PATH_MAX' \
	  $(_sc_search_regexp)

include $(srcdir)/Makefile.nonreentrant
sc_prohibit_nonreentrant:
	@prohibit="\\<(${NON_REENTRANT_RE}) *\\(" \
	halt="use re-entrant functions (usually ending with _r)" \
	  $(_sc_search_regexp)

sc_prohibit_select:
	@prohibit='\<select *\(' \
	halt='use poll(), not select()' \
	  $(_sc_search_regexp)

# Prohibit the inclusion of <ctype.h>.
sc_prohibit_ctype_h:
	@prohibit='^# *include  *<ctype\.h>' \
	halt='use c-ctype.h instead of ctype.h' \
	  $(_sc_search_regexp)

# We have our own wrapper for mocking purposes
sc_prohibit_canonicalize_file_name:
	@prohibit='\<canonicalize_file_name\(' \
	exclude='exempt from syntax-check' \
	halt='use virFileCanonicalizePath() instead of canonicalize_file_name()' \
	  $(_sc_search_regexp)

# Insist on correct types for [pug]id.
sc_correct_id_types:
	@prohibit='\<(int|long) *[pug]id\>' \
	exclude='exempt from syntax-check' \
	halt='use pid_t for pid, uid_t for uid, gid_t for gid' \
	  $(_sc_search_regexp)

# "const fooPtr a" is the same as "foo * const a", even though it is
# usually desired to have "foo const *a".  It's easier to just prevent
# the confusing mix of typedef vs. const placement.
# Also requires that all 'fooPtr' typedefs are actually pointers.
sc_forbid_const_pointer_typedef:
	@prohibit='(^|[^"])const \w*Ptr' \
	halt='"const fooPtr var" does not declare what you meant' \
	  $(_sc_search_regexp)
	@prohibit='typedef [^(]+ [^*]\w*Ptr\b' \
	halt='use correct style and type for Ptr typedefs' \
	  $(_sc_search_regexp)

# Forbid sizeof foo or sizeof (foo), require sizeof(foo)
sc_size_of_brackets:
	@prohibit='sizeof\s' \
	halt='use sizeof(foo), not sizeof (foo) or sizeof foo' \
	  $(_sc_search_regexp)

# Ensure that no C source file, docs, or rng schema uses TABs for
# indentation.  Also match *.h.in files, to get libvirt.h.in.  Exclude
# files in gnulib, since they're imported.
space_indent_files=(\.(aug(\.in)?|rng|s?[ch](\.in)?|html.in|py|pl|syms)|(daemon|tools)/.*\.in)
sc_TAB_in_indentation:
	@prohibit='^ *	' \
	in_vc_files='$(space_indent_files)$$' \
	halt='indent with space, not TAB, in C, sh, html, py, syms and RNG schemas' \
	  $(_sc_search_regexp)

ctype_re = isalnum|isalpha|isascii|isblank|iscntrl|isdigit|isgraph|islower\
|isprint|ispunct|isspace|isupper|isxdigit|tolower|toupper

sc_avoid_ctype_macros:
	@prohibit='\b($(ctype_re)) *\(' \
	in_vc_files='\.[ch]$$' \
	halt='use c-ctype.h instead of ctype macros' \
	  $(_sc_search_regexp)

sc_avoid_strcase:
	@prohibit='\bstrn?case(cmp|str) *\(' \
	halt='use c-strcase.h instead of raw strcase functions' \
	  $(_sc_search_regexp)

sc_prohibit_virBufferAdd_with_string_literal:
	@prohibit='\<virBufferAdd *\([^,]+, *"[^"]' \
	halt='use virBufferAddLit, not virBufferAdd, with a string literal' \
	  $(_sc_search_regexp)

sc_prohibit_virBufferAsprintf_with_string_literal:
	@prohibit='\<virBufferAsprintf *\([^,]+, *"([^%"\]|\\.|%%)*"\)' \
	halt='use virBufferAddLit, not virBufferAsprintf, with a string literal' \
	  $(_sc_search_regexp)

sc_forbid_manual_xml_indent:
	@prohibit='virBuffer.*" +<' \
	halt='use virBufferAdjustIndent instead of spaces when indenting xml' \
	  $(_sc_search_regexp)

# dirname and basename from <libgen.h> are not required to be thread-safe
sc_prohibit_libgen:
	@prohibit='( (base|dir)name *\(|include .libgen\.h)' \
	halt='use functions from gnulib "dirname.h", not <libgen.h>' \
	  $(_sc_search_regexp)

# raw xmlGetProp requires some nasty casts
sc_prohibit_xmlGetProp:
	@prohibit='\<xmlGetProp *\(' \
	halt='use virXMLPropString, not xmlGetProp' \
	  $(_sc_search_regexp)

# xml(ParseURI|SaveUri) doesn't handle IPv6 URIs well
sc_prohibit_xmlURI:
	@prohibit='\<xml(ParseURI|SaveUri) *\(' \
	halt='use virURI(Parse|Format), not xml(ParseURI|SaveUri)' \
	  $(_sc_search_regexp)

# we don't want old old-style return with parentheses around argument
sc_prohibit_return_as_function:
	@prohibit='\<return *\(([^()]*(\([^()]*\)[^()]*)*)\) *;' \
	halt='avoid extra () with return statements' \
	  $(_sc_search_regexp)

# ATTRIBUTE_UNUSED should only be applied in implementations, not
# header declarations
sc_avoid_attribute_unused_in_header:
	@prohibit='^[^#]*ATTRIBUTE_UNUSED([^:]|$$)' \
	in_vc_files='\.h$$' \
	halt='use ATTRIBUTE_UNUSED in .c rather than .h files' \
	  $(_sc_search_regexp)

sc_prohibit_int_index:
	@prohibit='\<(int|unsigned)\s*\*?index\>(\s|,|;)' \
	halt='use different name than 'index' for declaration' \
	  $(_sc_search_regexp)

sc_prohibit_int_ijk:
	@prohibit='\<(int|unsigned) ([^(=]* )*(i|j|k)\>(\s|,|;)' \
	exclude='exempt from syntax-check' \
	halt='use size_t, not int/unsigned int for loop vars i, j, k' \
	  $(_sc_search_regexp)

sc_prohibit_loop_iijjkk:
	@prohibit='\<(int|unsigned) ([^=]+ )*(ii|jj|kk)\>(\s|,|;)' \
	halt='use i, j, k for loop iterators, not ii, jj, kk' \
	  $(_sc_search_regexp)

# RHEL 5 gcc can't grok "for (int i..."
sc_prohibit_loop_var_decl:
	@prohibit='\<for *\(\w+[ *]+\w+' \
	in_vc_files='\.[ch]$$' \
	halt='declare loop iterators outside the for statement' \
	  $(_sc_search_regexp)

# Use 'bool', not 'int', when assigning true or false
sc_prohibit_int_assign_bool:
	@prohibit='\<int\>.*= *(true|false)' \
	halt='use bool type for boolean values' \
	  $(_sc_search_regexp)

sc_prohibit_unsigned_pid:
	@prohibit='\<unsigned\> [^,=;(]+pid' \
	halt='use signed type for pid values' \
	  $(_sc_search_regexp)

# Many of the function names below came from this filter:
# git grep -B2 '\<_('|grep -E '\.c- *[[:alpha:]_][[:alnum:]_]* ?\(.*[,;]$' \
# |sed 's/.*\.c-  *//'|perl -pe 's/ ?\(.*//'|sort -u \
# |grep -vE '^(qsort|if|close|assert|fputc|free|N_|vir.*GetName|.*Unlock|virNodeListDevices|virHashRemoveEntry|freeaddrinfo|.*[fF]ree|xdrmem_create|xmlXPathFreeObject|virUUIDFormat|openvzSetProgramSentinal|polkit_action_unref)$'

msg_gen_function =
msg_gen_function += VIR_ERROR
msg_gen_function += lxcError
msg_gen_function += regerror
msg_gen_function += vah_error
msg_gen_function += vah_warning
msg_gen_function += virGenericReportError
msg_gen_function += virRaiseError
msg_gen_function += virReportError
msg_gen_function += virReportErrorHelper
msg_gen_function += virReportSystemError
msg_gen_function += virLastErrorPrefixMessage

# Uncomment the following and run "make syntax-check" to see diagnostics
# that are not yet marked for translation, but that need to be rewritten
# so that they are translatable.
# msg_gen_function += fprintf
# msg_gen_function += testError
# msg_gen_function += vshPrint
# msg_gen_function += vshError

space =
space +=
func_re= ($(subst $(space),|,$(msg_gen_function)))

# Look for diagnostics that aren't marked for translation.
# This won't find any for which error's format string is on a separate line.
# The sed filters eliminate false-positives like these:
#    _("...: "
#    "%s", _("no storage vol w..."
sc_libvirt_unmarked_diagnostics:
	@prohibit='\<$(func_re) *\([^"]*"[^"]*[a-z]{3}' \
	exclude='_\(' \
	halt='found unmarked diagnostic(s)' \
	  $(_sc_search_regexp)
	@{ $(VC_LIST_EXCEPT) | xargs \
		$(GREP)     -nE '\<$(func_re) *\(.*;$$' /dev/null; \
	   $(VC_LIST_EXCEPT) | xargs \
		$(GREP) -A1 -nE '\<$(func_re) *\(.*,$$' /dev/null; } \
	   | $(SED) -E 's/_\("([^\"]|\\.)+"//;s/"%s"//' \
	   | $(GREP) '"' && \
	  { echo '$(ME): found unmarked diagnostic(s)' 1>&2; \
	    exit 1; } || :

# Like the above, but prohibit a newline at the end of a diagnostic.
# This is subject to false positives partly because it naively looks for
# `\n"', which may not be the end of the string, and also because it takes
# two lines of context (the -A2) after the line with the function name.
# FIXME: this rule might benefit from a separate function list, in case
# there are functions to which this one applies but that do not get marked
# diagnostics.
sc_prohibit_newline_at_end_of_diagnostic:
	@$(VC_LIST_EXCEPT) | xargs $(GREP) -A2 -nE \
	    '\<$(func_re) *\(' /dev/null \
	    | $(GREP) '\\n"' \
	  && { echo '$(ME): newline at end of message(s)' 1>&2; \
	    exit 1; } || :

# Look for diagnostics that lack a % in the format string, except that we
# allow VIR_ERROR to do this, and ignore functions that take a single
# string rather than a format argument.
sc_prohibit_diagnostic_without_format:
	@{ $(VC_LIST_EXCEPT) | xargs \
		$(GREP)     -nE '\<$(func_re) *\(.*;$$' /dev/null; \
	   $(VC_LIST_EXCEPT) | xargs \
		$(GREP) -A2 -nE '\<$(func_re) *\(.*,$$' /dev/null; } \
	   | $(SED) -rn -e ':l; /[,"]$$/ {N;b l;}' \
		-e '/(vah_(error|warning))/d' \
		-e '/\<$(func_re) *\([^"]*"([^%"]|"\n[^"]*")*"[,)]/p' \
           | $(GREP) -vE 'VIR_ERROR' && \
	  { echo '$(ME): found diagnostic without %' 1>&2; \
	    exit 1; } || :

# The strings "" and "%s" should never be marked for translation.
# Files under tests/ and examples/ should not be translated.
sc_prohibit_useless_translation:
	@prohibit='_\("(%s)?"\)' \
	halt='found useless translation' \
	  $(_sc_search_regexp)
	@prohibit='\<N?_ *\(' \
	in_vc_files='(tests|examples)/' \
	halt='no translations in tests or examples' \
	  $(_sc_search_regexp)

# When splitting a diagnostic across lines, ensure that there is a space
# or \n on one side of the split.
sc_require_whitespace_in_translation:
	@$(VC_LIST_EXCEPT) | xargs $(GREP) -n -A1 '"$$' /dev/null \
	   | $(SED) -ne ':l; /"$$/ {N;b l;}; s/"\n[^"]*"/""/g; s/\\n/ /g' \
		-e '/_(.*[^\ ]""[^\ ]/p' | $(GREP) . && \
	  { echo '$(ME): missing whitespace at line split' 1>&2; \
	    exit 1; } || :

# Enforce recommended preprocessor indentation style.
sc_preprocessor_indentation:
	@if cppi --version >/dev/null 2>&1; then \
	  $(VC_LIST_EXCEPT) | $(GREP) -E '\.[ch](\.in)?$$' | xargs cppi -a -c \
	    || { echo '$(ME): incorrect preprocessor indentation' 1>&2; \
		exit 1; }; \
	else \
	  echo '$(ME): skipping test $@: cppi not installed' 1>&2; \
	fi

# Enforce similar spec file indentation style, by running cppi on a
# (comment-only) C file that mirrors the same layout as the spec file.
sc_spec_indentation:
	@if cppi --version >/dev/null 2>&1; then \
	  for f in $$($(VC_LIST_EXCEPT) | $(GREP) '\.spec\.in$$'); do \
	    $(SED) -e 's|#|// #|; s|%ifn*\(arch\)* |#if a // |' \
		-e 's/%\(else\|endif\|define\)/#\1/' \
		-e 's/^\( *\)\1\1\1#/#\1/' \
		-e 's|^\( *[^#/ ]\)|// \1|; s|^\( */[^/]\)|// \1|' $$f \
	    | cppi -a -c 2>&1 | $(SED) "s|standard input|$$f|"; \
	  done | { if $(GREP) . >&2; then false; else :; fi; } \
	    || { echo '$(ME): incorrect preprocessor indentation' 1>&2; \
		exit 1; }; \
	else \
	  echo '$(ME): skipping test $@: cppi not installed' 1>&2; \
	fi

# Nested conditionals are easier to understand if we enforce that endifs
# can be paired back to the if
sc_makefile_conditionals:
	@prohibit='(else|endif)($$| *#)' \
	in_vc_files='Makefile\.am' \
	halt='match "if FOO" with "endif FOO" in Makefiles' \
	  $(_sc_search_regexp)

# Long lines can be harder to diff; too long, and git send-email chokes.
# For now, only enforce line length on files where we have intentionally
# fixed things and don't want to regress.
sc_prohibit_long_lines:
	@prohibit='.{90}' \
	in_vc_files='\.arg[sv]' \
	halt='Wrap long lines in expected output files' \
	  $(_sc_search_regexp)
	@prohibit='.{80}' \
	in_vc_files='Makefile(\.inc)?\.am' \
	halt='Wrap long lines in Makefiles' \
	  $(_sc_search_regexp)

sc_copyright_format:
	@require='Copyright .*Red 'Hat', Inc\.' \
	containing='Copyright .*Red 'Hat \
	halt='Red Hat copyright is missing Inc.' \
	  $(_sc_search_regexp)
	@prohibit='Copyright [^(].*Red 'Hat \
	halt='consistently use (C) in Red Hat copyright' \
	  $(_sc_search_regexp)
	@prohibit='\<RedHat\>' \
	halt='spell Red Hat as two words' \
	  $(_sc_search_regexp)

# Prefer the new URL listing over the old street address listing when
# calling out where to get a copy of the [L]GPL.  Also, while we have
# to ship COPYING (GPL) alongside COPYING.LESSER (LGPL), we want any
# source file that calls out a top-level file to call out the LGPL
# version.  Note that our typical copyright boilerplate refers to the
# license by name, not by reference to a top-level file.
sc_copyright_usage:
	@prohibit=Boston,' MA' \
	halt='Point to <http://www.gnu.org/licenses/>, not an address' \
	  $(_sc_search_regexp)
	@require='COPYING\.LESSER' \
	containing='COPYING' \
	halt='Refer to COPYING.LESSER for LGPL' \
	  $(_sc_search_regexp)
	@prohibit='COPYING\.LIB' \
	halt='Refer to COPYING.LESSER for LGPL' \
	  $(_sc_search_regexp)

# Some functions/macros produce messages intended solely for developers
# and maintainers.  Do not mark them for translation.
sc_prohibit_gettext_markup:
	@prohibit='\<VIR_(WARN|INFO|DEBUG) *\(_\(' \
	halt='do not mark these strings for translation' \
	  $(_sc_search_regexp)

# Our code is divided into modular subdirectories for a reason, and
# lower-level code must not include higher-level headers.
cross_dirs=$(patsubst $(srcdir)/src/%.,%,$(wildcard $(srcdir)/src/*/.))
cross_dirs_re=($(subst / ,/|,$(cross_dirs)))
mid_dirs=access|admin|conf|cpu|locking|logging|rpc|security
sc_prohibit_cross_inclusion:
	@for dir in $(cross_dirs); do \
	  case $$dir in \
	    util/) safe="util";; \
	    access/ | conf/) safe="($$dir|conf|util)";; \
	    cpu/| network/| node_device/| rpc/| security/| storage/) \
	      safe="($$dir|util|conf|storage)";; \
	    *) safe="($$dir|$(mid_dirs)|util)";; \
	  esac; \
	  in_vc_files="^src/$$dir" \
	  prohibit='^# *include .$(cross_dirs_re)' \
	  exclude="# *include .$$safe" \
	  halt='unsafe cross-directory include' \
	    $(_sc_search_regexp) \
	done

# When converting an enum to a string, make sure that we track any new
# elements added to the enum by using a _LAST marker.
sc_require_enum_last_marker:
	@$(VC_LIST_EXCEPT) | xargs \
		$(GREP) -A1 -nE '^[^#]*VIR_ENUM_IMPL *\(' /dev/null \
	   | $(SED) -ne '/VIR_ENUM_IMPL.*,$$/N' \
	     -e '/VIR_ENUM_IMPL[^,]*,[^,]*,[^,]*[^_,][^L,][^A,][^S,][^T,],/p' \
	     -e '/VIR_ENUM_IMPL[^,]*,[^,]\{0,4\},/p' \
	   | $(GREP) . && \
	  { echo '$(ME): enum impl needs _LAST marker on second line' 1>&2; \
	    exit 1; } || :

# In Python files we don't want to end lines with a semicolon like in C
sc_flake8:
	@if [ -n "$(FLAKE8)" ]; then \
		$(VC_LIST_EXCEPT) | $(GREP) '\.py$$' | xargs \
			$(FLAKE8) --select E703 --show-source; \
	else \
		echo '$(ME): skipping test $@: flake8 not installed' 1>&2; \
	fi

# mymain() in test files should use return, not exit, for nicer output
sc_prohibit_exit_in_tests:
	@prohibit='\<exit *\(' \
	in_vc_files='tests/.*\.c$$' \
	halt='use return, not exit(), in tests' \
	  $(_sc_search_regexp)

# Don't include "libvirt/*.h" in "" form.
sc_prohibit_include_public_headers_quote:
	@prohibit='# *include *"libvirt/.*\.h"' \
	in_vc_files='\.[ch]$$' \
	halt='Do not include libvirt/*.h in internal source' \
	  $(_sc_search_regexp)

# Don't include "libvirt/*.h" in <> form. Except for external tools,
# e.g. Python binding, examples and tools subdirectories.
sc_prohibit_include_public_headers_brackets:
	@prohibit='# *include *<libvirt/.*\.h>' \
	in_vc_files='\.[ch]$$' \
	halt='Do not include libvirt/*.h in internal source' \
	  $(_sc_search_regexp)

# <config.h> is only needed in .c files; .h files do not need it since
# .c files must include config.h before any other .h.
sc_prohibit_config_h_in_headers:
	@prohibit='^# *include\>.*config\.h' \
	in_vc_files='\.h$$' \
	halt='headers should not include <config.h>' \
	  $(_sc_search_regexp)

sc_prohibit_unbounded_arrays_in_rpc:
	@prohibit='<>' \
	in_vc_files='\.x$$' \
	halt='Arrays in XDR must have a upper limit set for <NNN>' \
	  $(_sc_search_regexp)

sc_prohibit_atoi:
	@prohibit='\bato(i|f|l|ll|q) *\(' \
	halt='Use virStrToLong* instead of atoi, atol, atof, atoq, atoll' \
	  $(_sc_search_regexp)

sc_prohibit_wrong_filename_in_comment:
	@$(VC_LIST_EXCEPT) | $(GREP) '\.[ch]$$'	| xargs awk 'BEGIN { \
	  fail=0; \
	} FNR < 3 { \
	  n=match($$0, /[[:space:]][^[:space:]]*[.][ch][[:space:]:]/); \
	  if (n > 0) { \
	    A=substr($$0, RSTART+1, RLENGTH-2); \
	    n=split(FILENAME, arr, "/"); \
	    if (A != arr[n]) { \
	      print "in " FILENAME ": " A " mentioned in comments "; \
	      fail=1; \
	    } \
	  } \
	} END { \
	  if (fail == 1) { \
	    exit 1; \
	  } \
	}' || { echo '$(ME): The file name in comments must match the' \
	    'actual file name' 1>&2; exit 1; }

sc_prohibit_virConnectOpen_in_virsh:
	@prohibit='\bvirConnectOpen[a-zA-Z]* *\(' \
	in_vc_files='tools/virsh-.*\.[ch]$$' \
	halt='Use vshConnect() in virsh instead of virConnectOpen*' \
	  $(_sc_search_regexp)

sc_require_space_before_label:
	@prohibit='^(   ?)?[_a-zA-Z0-9]+:$$' \
	in_vc_files='\.[ch]$$' \
	halt='Top-level labels should be indented by one space' \
	  $(_sc_search_regexp)

# Allow for up to three spaces before the label: this is to avoid running
# into situations where neither this rule nor require_space_before_label
# would apply, eg. a line matching ^[a-zA-Z0-9]+ :$
sc_prohibit_space_in_label:
	@prohibit='^ {0,3}[_a-zA-Z0-9]+ +:$$' \
	in_vc_files='\.[ch]$$' \
	halt='There should be no space between label name and colon' \
	  $(_sc_search_regexp)

# Doesn't catch all cases of mismatched braces across if-else, but it helps
sc_require_if_else_matching_braces:
	@prohibit='(  else( if .*\))? {|} else( if .*\))?$$)' \
	in_vc_files='\.[chx]$$' \
	halt='if one side of if-else uses {}, both sides must use it' \
	  $(_sc_search_regexp)

sc_curly_braces_style:
	@if $(VC_LIST_EXCEPT) | $(GREP) '\.[ch]$$' | xargs $(GREP) -nHP \
'^\s*(?!([a-zA-Z_]*for_?each[a-zA-Z_]*) ?\()([_a-zA-Z0-9]+( [_a-zA-Z0-9]+)* ?\()?(\*?[_a-zA-Z0-9]+(,? \*?[_a-zA-Z0-9\[\]]+)+|void)\) ?\{' \
	/dev/null; then \
	  echo '$(ME): Non-K&R style used for curly braces around' \
	    'function body' 1>&2; exit 1; \
	fi; \
	if $(VC_LIST_EXCEPT) | $(GREP) '\.[ch]$$' | xargs \
	    $(GREP) -A1 -En ' ((if|for|while|switch) \(|(else|do)\b)[^{]*$$' \
	    /dev/null | $(GREP) '^[^ ]*- *{'; then \
	  echo '$(ME): Use hanging braces for compound statements' 1>&2; exit 1; \
	fi

sc_prohibit_windows_special_chars_in_filename:
	@$(VC_LIST_EXCEPT) | $(GREP) '[:*?"<>|]' && \
	{ echo '$(ME): Windows special chars in filename not allowed' 1>&2; echo exit 1; } || :

sc_prohibit_mixed_case_abbreviations:
	@prohibit='Pci|Usb|Scsi' \
	in_vc_files='\.[ch]$$' \
	halt='Use PCI, USB, SCSI, not Pci, Usb, Scsi' \
	  $(_sc_search_regexp)

# Require #include <locale.h> in all files that call setlocale()
sc_require_locale_h:
	@require='include.*locale\.h' \
	containing='setlocale *(' \
	halt='setlocale() requires <locale.h>' \
	  $(_sc_search_regexp)

sc_prohibit_empty_first_line:
	@$(VC_LIST_EXCEPT) | xargs awk 'BEGIN { fail=0; } \
	FNR == 1 { if ($$0 == "") { print FILENAME ":1:"; fail=1; } } \
	END { if (fail == 1) { \
	  print "$(ME): Prohibited empty first line" > "/dev/stderr"; \
	} exit fail; }'

sc_prohibit_paren_brace:
	@prohibit='\)\{$$' \
	in_vc_files='\.[chx]$$' \
	halt='Put space between closing parenthesis and opening brace' \
	  $(_sc_search_regexp)

# C guarantees that static variables are zero initialized, and some compilers
# waste space by sticking explicit initializers in .data instead of .bss
sc_prohibit_static_zero_init:
	@prohibit='\bstatic\b.*= *(0[^xX0-9]|NULL|false)' \
	in_vc_files='\.[chx](\.in)?$$' \
	halt='static variables do not need explicit zero initialization'\
	  $(_sc_search_regexp)

# FreeBSD exports the "devname" symbol which produces a warning.
sc_prohibit_devname:
	@prohibit='\bdevname\b' \
	exclude='sc_prohibit_devname' \
	halt='avoid using devname as FreeBSD exports the symbol' \
	  $(_sc_search_regexp)

sc_prohibit_system_error_with_vir_err:
	@prohibit='\bvirReportSystemError *\(VIR_ERR_' \
	halt='do not use virReportSystemError with VIR_ERR_* error codes' \
	  $(_sc_search_regexp)

# Rule to prohibit usage of virXXXFree within library, daemon, remote, etc.
# functions. There's a corresponding exclude to allow usage within tests,
# docs, examples, tools, src/libvirt-*.c, and include/libvirt/libvirt-*.h
sc_prohibit_virXXXFree:
	@prohibit='\bvir(Domain|Network|NodeDevice|StorageVol|StoragePool|Stream|Secret|NWFilter|Interface|DomainSnapshot)Free\b' \
	exclude='sc_prohibit_virXXXFree' \
	halt='avoid using virXXXFree, use virObjectUnref instead' \
	  $(_sc_search_regexp)

sc_prohibit_sysconf_pagesize:
	@prohibit='sysconf\(_SC_PAGESIZE' \
	halt='use virGetSystemPageSize[KB] instead of sysconf(_SC_PAGESIZE)' \
	  $(_sc_search_regexp)

sc_prohibit_virSecurity:
	@$(VC_LIST_EXCEPT) | $(GREP) 'src/qemu/' | \
		$(GREP) -v 'src/qemu/qemu_security' | \
		xargs $(GREP) -Pn 'virSecurityManager(?!Ptr)' /dev/null && \
		{ echo '$(ME): prefer qemuSecurity wrappers' 1>&2; exit 1; } || :

sc_prohibit_pthread_create:
	@prohibit='\bpthread_create\b' \
	exclude='sc_prohibit_pthread_create' \
	halt='avoid using pthread_create, use virThreadCreate instead' \
	  $(_sc_search_regexp)

sc_prohibit_not_streq:
	@prohibit='! *STRN?EQ *\(.*\)' \
	halt='Use STRNEQ instead of !STREQ and STREQ instead of !STRNEQ' \
	  $(_sc_search_regexp)

sc_prohibit_verbose_strcat:
	@prohibit='strncat\([^,]*,\s+([^,]*),\s+strlen\(\1\)\)' \
	in_vc_files='\.[ch]$$' \
	halt='Use strcat(a, b) instead of strncat(a, b, strlen(b))' \
	  $(_sc_search_regexp)

# Ensure that each .c file containing a "main" function also
# calls virGettextInitialize
sc_gettext_init:
	@require='virGettextInitialize *\(' \
	in_vc_files='\.c$$' \
	containing='\<main *(' \
	halt='the above files do not call virGettextInitialize' \
	  $(_sc_search_regexp)

sc_prohibit_obj_free_apis_in_virsh:
	@prohibit='\bvir(Domain|DomainSnapshot)Free\b' \
	in_vc_files='virsh.*\.[ch]$$' \
	exclude='sc_prohibit_obj_free_apis_in_virsh' \
	halt='avoid using virDomain(Snapshot)Free in virsh, use virsh-prefixed wrappers instead' \
	  $(_sc_search_regexp)

https_sites = www.libvirt.org
https_sites += libvirt.org
https_sites += security.libvirt.org
https_sites += qemu.org
https_sites += www.qemu.org
https_sites += wiki.qemu.org
https_sites += linux-kvm.org
https_sites += www.linux-kvm.org

https_re= ($(subst $(space),|,$(https_sites)))

sc_prohibit_http_urls:
	@prohibit='http://$(https_re)' \
	exclude="/schemas/" \
	halt='Links must use https:// protocol' \
	  $(_sc_search_regexp)

sc_prohibit_author:
	@prohibit="(\*|#)\s*(A|a)uthors?:" \
	halt="Author: statements are prohibited in source comments" \
	  $(_sc_search_regexp)

# Alignment is usually achieved through spaces (at least two of them)
# or tabs (at least one of them) right before the trailing backslash
sc_prohibit_backslash_alignment:
	@prohibit='(  |	)\\$$' \
	in_vc_files='*\.([chx]|am|mk)$$' \
	halt='Do not attempt to right-align backslashes' \
	  $(_sc_search_regexp)

# Some syntax rules pertaining to the usage of cleanup macros
# implementing GNU C's cleanup attribute

# Rule to ensure that variables declared using a cleanup macro are
# always initialized.
sc_require_attribute_cleanup_initialization:
	@prohibit='((g_auto(ptr|free)?)|(VIR_AUTO((FREE|PTR|UNREF|CLEAN)\(.+\)|CLOSE|STRINGLIST))) *[^=]+;' \
	in_vc_files='\.[chx]$$' \
	halt='variable declared with a cleanup macro must be initialized' \
	  $(_sc_search_regexp)

# "class" in headers is not good because by default Vim treats it as a keyword
# Let's prohibit it in source files as well.
sc_prohibit_class:
	@prohibit=' +_?class *;' \
	in_vc_files='\.[chx]$$' \
	halt='use klass instead of class or _class' \
	  $(_sc_search_regexp)

# The dirent "d_type" field is non-portable and even when it
# exists some filesystems will only ever return DT_UNKNOWN.
# This field should only be used by code which is exclusively
# run platforms supporting "d_type" and must expect DT_UNKNOWN.
# We blacklist it to discourage accidental usage which has
# happened many times. Add an exclude rule if it is genuinely
# needed and the above restrictions are acceptable.
sc_prohibit_dirent_d_type:
	@prohibit='(->|\.)d_type' \
	in_vc_files='\.[chx]$$' \
	halt='do not use the d_type field in "struct dirent"' \
	  $(_sc_search_regexp)


# _sc_search_regexp
#
# This macro searches for a given construct in the selected files and
# then takes some action.
#
# Parameters (shell variables):
#
#  prohibit | require
#
#     Regular expression (ERE) denoting either a forbidden construct
#     or a required construct.  Those arguments are exclusive.
#
#  exclude
#
#     Regular expression (ERE) denoting lines to ignore that matched
#     a prohibit construct.  For example, this can be used to exclude
#     comments that mention why the nearby code uses an alternative
#     construct instead of the simpler prohibited construct.
#
#  in_vc_files | in_files
#
#     grep-E-style regexp selecting the files to check.  For in_vc_files,
#     the regexp is used to select matching files from the list of all
#     version-controlled files; for in_files, it's from the names printed
#     by "find $(srcdir)".  When neither is specified, use all files that
#     are under version control.
#
#  containing | non_containing
#
#     Select the files (non) containing strings matching this regexp.
#     If both arguments are specified then CONTAINING takes
#     precedence.
#
#  with_grep_options
#
#     Extra options for grep.
#
#  ignore_case
#
#     Ignore case.
#
#  halt
#
#     Message to display before to halting execution.
#
# Finally, you may exempt files based on an ERE matching file names.
# For example, to exempt from the sc_space_tab check all files with the
# .diff suffix, set this Make variable:
#
# exclude_file_name_regexp--sc_space_tab = \.diff$
#
# Note that while this functionality is mostly inherited via VC_LIST_EXCEPT,
# when filtering by name via in_files, we explicitly filter out matching
# names here as well.

# Initialize each, so that envvar settings cannot interfere.
export require =
export prohibit =
export exclude =
export in_vc_files =
export in_files =
export containing =
export non_containing =
export halt =
export with_grep_options =

# By default, _sc_search_regexp does not ignore case.
export ignore_case =
_ignore_case = $$(test -n "$$ignore_case" && printf %s -i || :)

define _sc_say_and_exit
   dummy=; : so we do not need a semicolon before each use;		\
   { printf '%s\n' "$(ME): $$msg" 1>&2; exit 1; };
endef

define _sc_search_regexp
   dummy=; : so we do not need a semicolon before each use;		\
									\
   : Check arguments;							\
   test -n "$$prohibit" && test -n "$$require"				\
     && { msg='Cannot specify both prohibit and require'		\
          $(_sc_say_and_exit) } || :;					\
   test -z "$$prohibit" && test -z "$$require"				\
     && { msg='Should specify either prohibit or require'		\
          $(_sc_say_and_exit) } || :;					\
   test -z "$$prohibit" && test -n "$$exclude"				\
     && { msg='Use of exclude requires a prohibit pattern'		\
          $(_sc_say_and_exit) } || :;					\
   test -n "$$in_vc_files" && test -n "$$in_files"			\
     && { msg='Cannot specify both in_vc_files and in_files'		\
          $(_sc_say_and_exit) } || :;					\
   test "x$$halt" != x							\
     || { msg='halt not defined' $(_sc_say_and_exit) };			\
									\
   : Filter by file name;						\
   if test -n "$$in_files"; then					\
     files=$$(find $(srcdir) | $(GREP) -E "$$in_files"			\
              | $(GREP) -Ev '$(_sc_excl)');				\
   else									\
     files=$$($(VC_LIST_EXCEPT));					\
     if test -n "$$in_vc_files"; then					\
       files=$$(echo "$$files" | $(GREP) -E "$$in_vc_files");		\
     fi;								\
   fi;									\
									\
   : Filter by content;							\
   test -n "$$files"							\
     && test -n "$$containing"						\
     && { files=$$(echo "$$files" | xargs $(GREP) -l "$$containing"); }	\
     || :;								\
   test -n "$$files"							\
     && test -n "$$non_containing"					\
     && { files=$$(echo "$$files" | xargs $(GREP) -vl "$$non_containing"); } \
     || :;								\
									\
   : Check for the construct;						\
   if test -n "$$files"; then						\
     if test -n "$$prohibit"; then					\
       echo "$$files"							\
         | xargs $(GREP) $$with_grep_options $(_ignore_case) -nE	\
		"$$prohibit" /dev/null					\
         | $(GREP) -vE "$${exclude:-^$$}"				\
         && { msg="$$halt" $(_sc_say_and_exit) }			\
         || :;								\
     else								\
       echo "$$files"							\
         | xargs							\
             $(GREP) $$with_grep_options $(_ignore_case) -LE "$$require" \
         | $(GREP) .							\
         && { msg="$$halt" $(_sc_say_and_exit) }			\
         || :;								\
     fi									\
   else :;								\
   fi || :;
endef

sc_avoid_if_before_free:
	@$(VC_LIST_EXCEPT)						\
	  | $(GREP) -v useless-if-before-free				\
	  | xargs							\
	      $(srcdir)/$(_build-aux)/useless-if-before-free		\
	      $(useless_free_options)					\
	  && { printf '$(ME): found useless "if"'			\
		      ' before "free" above\n' 1>&2;			\
	       exit 1; }						\
	  || :

sc_cast_of_argument_to_free:
	@prohibit='\<free *\( *\(' halt="don't cast free argument"	\
	  $(_sc_search_regexp)

sc_cast_of_x_alloc_return_value:
	@prohibit='\*\) *x(m|c|re)alloc\>'				\
	halt="don't cast x*alloc return value"				\
	  $(_sc_search_regexp)

# Use STREQ rather than comparing strcmp == 0, or != 0.
sp_ = strcmp *\(.+\)
sc_prohibit_strcmp:
	@prohibit='! *strcmp *\(|\<$(sp_) *[!=]=|[!=]= *$(sp_)'		\
	exclude='# *define STRN?EQ\('					\
	halt='replace strcmp calls above with STREQ/STRNEQ'		\
	  $(_sc_search_regexp)

# Really.  You don't want to use this function.
# It may fail to NUL-terminate the destination,
# and always NUL-pads out to the specified length.
sc_prohibit_strncpy:
	@prohibit='\<strncpy *\('					\
	halt='do not use strncpy, period'				\
	  $(_sc_search_regexp)

# Pass EXIT_*, not number, to usage, exit, and error (when exiting)
# Convert all uses automatically, via these two commands:
# git grep -l '\<exit *(1)' \
#  | grep -vEf .x-sc_prohibit_magic_number_exit \
#  | xargs --no-run-if-empty \
#      perl -pi -e 's/(^|[^.])\b(exit ?)\(1\)/$1$2(EXIT_FAILURE)/'
# git grep -l '\<exit *(0)' \
#  | grep -vEf .x-sc_prohibit_magic_number_exit \
#  | xargs --no-run-if-empty \
#      perl -pi -e 's/(^|[^.])\b(exit ?)\(0\)/$1$2(EXIT_SUCCESS)/'
sc_prohibit_magic_number_exit:
	@prohibit='(^|[^.])\<(usage|exit|error) ?\(-?[0-9]+[,)]'	\
	exclude='exit \(77\)|error ?\(((0|77),|[^,]*)'			\
	halt='use EXIT_* values rather than magic number'		\
	  $(_sc_search_regexp)

# "FATAL:" should be fully upper-cased in error messages
# "WARNING:" should be fully upper-cased, or fully lower-cased
sc_error_message_warn_fatal:
	@$(VC_LIST_EXCEPT)						\
	  | xargs $(GREP) -nEA2 '[^rp]error *\(' /dev/null		\
	  | $(GREP) -E '"Warning|"Fatal|"fatal'				\
	  && { echo '$(ME): use FATAL, WARNING or warning' 1>&2;	\
	       exit 1; }						\
	  || :

# Error messages should not end with a period
sc_error_message_period:
	@$(VC_LIST_EXCEPT)						\
	  | xargs $(GREP) -nEA2 '[^rp]error *\(' /dev/null		\
	  | $(GREP) -E '[^."]\."'					\
	  && { echo '$(ME): found error message ending in period' 1>&2;	\
	       exit 1; }						\
	  || :

# Don't use cpp tests of this symbol.  All code assumes config.h is included.
sc_prohibit_have_config_h:
	@prohibit='^# *if.*HAVE''_CONFIG_H'				\
	halt='found use of HAVE''_CONFIG_H; remove'			\
	  $(_sc_search_regexp)

# Nearly all .c files must include <config.h>.  However, we also permit this
# via inclusion of a package-specific header, if syntax-check.mk specified one.
# config_h_header must be suitable for grep -E.
config_h_header ?= <config\.h>
sc_require_config_h:
	@require='^# *include $(config_h_header)'			\
	in_vc_files='\.c$$'						\
	halt='the above files do not include <config.h>'		\
	  $(_sc_search_regexp)

# Print each file name for which the first #include does not match
# $(config_h_header).  Like grep -m 1, this only looks at the first match.
perl_config_h_first_ =							\
  -e 'BEGIN {$$ret = 0}'						\
  -e 'if (/^\# *include\b/) {'						\
  -e '  if (not m{^\# *include $(config_h_header)}) {'			\
  -e '    print "$$ARGV\n";'						\
  -e '    $$ret = 1;'							\
  -e '  }'								\
  -e '  \# Move on to next file after first include'			\
  -e '  close ARGV;'							\
  -e '}'								\
  -e 'END {exit $$ret}'

# You must include <config.h> before including any other header file.
# This can possibly be via a package-specific header, if given by syntax-check.mk.
sc_require_config_h_first:
	@if $(VC_LIST_EXCEPT) | $(GREP) '\.c$$' > /dev/null; then	\
	  files=$$($(VC_LIST_EXCEPT) | $(GREP) '\.c$$') &&		\
	  perl -n $(perl_config_h_first_) $$files ||			\
	    { echo '$(ME): the above files include some other header'	\
		'before <config.h>' 1>&2; exit 1; } || :;		\
	else :;								\
	fi

sc_prohibit_HAVE_MBRTOWC:
	@prohibit='\bHAVE_MBRTOWC\b'					\
	halt="do not use $$prohibit; it is always defined"		\
	  $(_sc_search_regexp)

# To use this "command" macro, you must first define two shell variables:
# h: the header name, with no enclosing <> or ""
# re: a regular expression that matches IFF something provided by $h is used.
define _sc_header_without_use
  dummy=; : so we do not need a semicolon before each use;		\
  h_esc=`echo '[<"]'"$$h"'[">]'|$(SED) 's/\./\\\\./g'`;			\
  if $(VC_LIST_EXCEPT) | $(GREP) '\.c$$' > /dev/null; then		\
    files=$$($(GREP) -l '^# *include '"$$h_esc"				\
	     $$($(VC_LIST_EXCEPT) | $(GREP) '\.c$$')) &&		\
    $(GREP) -LE "$$re" $$files | $(GREP) . &&				\
      { echo "$(ME): the above files include $$h but don't use it"	\
	1>&2; exit 1; } || :;						\
  else :;								\
  fi
endef

# Prohibit the inclusion of assert.h without an actual use of assert.
sc_prohibit_assert_without_use:
	@h='assert.h' re='\<assert *\(' $(_sc_header_without_use)

# Prohibit the inclusion of close-stream.h without an actual use.
sc_prohibit_close_stream_without_use:
	@h='close-stream.h' re='\<close_stream *\(' $(_sc_header_without_use)

# Prohibit the inclusion of getopt.h without an actual use.
sc_prohibit_getopt_without_use:
	@h='getopt.h' re='\<getopt(_long)? *\(' $(_sc_header_without_use)

# Don't include this header unless you use one of its functions.
sc_prohibit_long_options_without_use:
	@h='long-options.h' re='\<parse_(long_options|gnu_standard_options_only) *\(' \
	  $(_sc_header_without_use)

# Don't include this header unless you use one of its functions.
sc_prohibit_inttostr_without_use:
	@h='inttostr.h' re='\<(off|[iu]max|uint)tostr *\(' \
	  $(_sc_header_without_use)

# Don't include this header unless you use one of its functions.
sc_prohibit_ignore_value_without_use:
	@h='ignore-value.h' re='\<ignore_(value|ptr) *\(' \
	  $(_sc_header_without_use)

# Don't include this header unless you use one of its functions.
sc_prohibit_error_without_use:
	@h='error.h' \
	re='\<error(_at_line|_print_progname|_one_per_line|_message_count)? *\('\
	  $(_sc_header_without_use)

# Don't include xalloc.h unless you use one of its functions.
# Consider these symbols:
# perl -lne '/^# *define (\w+)\(/ and print $1' lib/xalloc.h|grep -v '^__';
# perl -lne '/^(?:extern )?(?:void|char) \*?(\w+) *\(/ and print $1' lib/xalloc.h
# Divide into two sets on case, and filter each through this:
# | sort | perl -MRegexp::Assemble -le \
#  'print Regexp::Assemble->new(file => "/dev/stdin")->as_string'|sed 's/\?://g'
# Note this was produced by the above:
# _xa1 = \
#x(((2n?)?re|c(har)?|n(re|m)|z)alloc|alloc_(oversized|die)|m(alloc|emdup)|strdup)
# But we can do better, in at least two ways:
# 1) take advantage of two "dup"-suffixed strings:
# x(((2n?)?re|c(har)?|n(re|m)|[mz])alloc|alloc_(oversized|die)|(mem|str)dup)
# 2) notice that "c(har)?|[mz]" is equivalent to the shorter and more readable
# "char|[cmz]"
# x(((2n?)?re|char|n(re|m)|[cmz])alloc|alloc_(oversized|die)|(mem|str)dup)
_xa1 = x(((2n?)?re|char|n(re|m)|[cmz])alloc|alloc_(oversized|die)|(mem|str)dup)
_xa2 = X([CZ]|N?M)ALLOC
sc_prohibit_xalloc_without_use:
	@h='xalloc.h' \
	re='\<($(_xa1)|$(_xa2)) *\('\
	  $(_sc_header_without_use)

sc_prohibit_cloexec_without_use:
	@h='cloexec.h' re='\<(set_cloexec_flag|dup_cloexec) *\(' \
	  $(_sc_header_without_use)

sc_prohibit_posixver_without_use:
	@h='posixver.h' re='\<posix2_version *\(' $(_sc_header_without_use)

sc_prohibit_same_without_use:
	@h='same.h' re='\<same_name(at)? *\(' $(_sc_header_without_use)

sc_prohibit_hash_pjw_without_use:
	@h='hash-pjw.h' \
	re='\<hash_pjw\>' \
	  $(_sc_header_without_use)

sc_prohibit_safe_read_without_use:
	@h='safe-read.h' re='(\<SAFE_READ_ERROR\>|\<safe_read *\()' \
	  $(_sc_header_without_use)

sc_prohibit_argmatch_without_use:
	@h='argmatch.h' \
	re='(\<(ARRAY_CARDINALITY|X?ARGMATCH(|_TO_ARGUMENT|_VERIFY))\>|\<(invalid_arg|argmatch(_exit_fn|_(in)?valid)?) *\()' \
	  $(_sc_header_without_use)

sc_prohibit_canonicalize_without_use:
	@h='canonicalize.h' \
	re='CAN_(EXISTING|ALL_BUT_LAST|MISSING)|canonicalize_(mode_t|filename_mode|file_name)' \
	  $(_sc_header_without_use)

sc_prohibit_root_dev_ino_without_use:
	@h='root-dev-ino.h' \
	re='(\<ROOT_DEV_INO_(CHECK|WARN)\>|\<get_root_dev_ino *\()' \
	  $(_sc_header_without_use)

sc_prohibit_openat_without_use:
	@h='openat.h' \
	re='\<(openat_(permissive|needs_fchdir|(save|restore)_fail)|l?(stat|ch(own|mod))at|(euid)?accessat|(FCHMOD|FCHOWN|STAT)AT_INLINE)\>' \
	  $(_sc_header_without_use)

# Prohibit the inclusion of c-ctype.h without an actual use.
ctype_re = isalnum|isalpha|isascii|isblank|iscntrl|isdigit|isgraph|islower\
|isprint|ispunct|isspace|isupper|isxdigit|tolower|toupper
sc_prohibit_c_ctype_without_use:
	@h='c-ctype.h' re='\<c_($(ctype_re)) *\(' \
	  $(_sc_header_without_use)

# The following list was generated by running:
# man signal.h|col -b|perl -ne '/bsd_signal.*;/.../sigwaitinfo.*;/ and print' \
#   | perl -lne '/^\s+(?:int|void).*?(\w+).*/ and print $1' | fmt
_sig_functions = \
  bsd_signal kill killpg pthread_kill pthread_sigmask raise sigaction \
  sigaddset sigaltstack sigdelset sigemptyset sigfillset sighold sigignore \
  siginterrupt sigismember signal sigpause sigpending sigprocmask sigqueue \
  sigrelse sigset sigsuspend sigtimedwait sigwait sigwaitinfo
_sig_function_re = $(subst $(_sp),|,$(strip $(_sig_functions)))
# The following were extracted from "man signal.h" manually.
_sig_types_and_consts =							\
  MINSIGSTKSZ SA_NOCLDSTOP SA_NOCLDWAIT SA_NODEFER SA_ONSTACK		\
  SA_RESETHAND SA_RESTART SA_SIGINFO SIGEV_NONE SIGEV_SIGNAL		\
  SIGEV_THREAD SIGSTKSZ SIG_BLOCK SIG_SETMASK SIG_UNBLOCK SS_DISABLE	\
  SS_ONSTACK mcontext_t pid_t sig_atomic_t sigevent siginfo_t sigset_t	\
  sigstack sigval stack_t ucontext_t
# generated via this:
# perl -lne '/^#ifdef (SIG\w+)/ and print $1' lib/sig2str.c|sort -u|fmt -70
_sig_names =								\
  SIGABRT SIGALRM SIGALRM1 SIGBUS SIGCANCEL SIGCHLD SIGCLD SIGCONT	\
  SIGDANGER SIGDIL SIGEMT SIGFPE SIGFREEZE SIGGRANT SIGHUP SIGILL	\
  SIGINFO SIGINT SIGIO SIGIOT SIGKAP SIGKILL SIGKILLTHR SIGLOST SIGLWP	\
  SIGMIGRATE SIGMSG SIGPHONE SIGPIPE SIGPOLL SIGPRE SIGPROF SIGPWR	\
  SIGQUIT SIGRETRACT SIGSAK SIGSEGV SIGSOUND SIGSTKFLT SIGSTOP SIGSYS	\
  SIGTERM SIGTHAW SIGTRAP SIGTSTP SIGTTIN SIGTTOU SIGURG SIGUSR1	\
  SIGUSR2 SIGVIRT SIGVTALRM SIGWAITING SIGWINCH SIGWIND SIGWINDOW	\
  SIGXCPU SIGXFSZ
_sig_syms_re = $(subst $(_sp),|,$(strip $(_sig_names) $(_sig_types_and_consts)))

# Prohibit the inclusion of signal.h without an actual use.
sc_prohibit_signal_without_use:
	@h='signal.h'							\
	re='\<($(_sig_function_re)) *\(|\<($(_sig_syms_re))\>'		\
	  $(_sc_header_without_use)

# Don't include stdio--.h unless you use one of its functions.
sc_prohibit_stdio--_without_use:
	@h='stdio--.h' re='\<((f(re)?|p)open|tmpfile) *\('		\
	  $(_sc_header_without_use)

# Don't include stdio-safer.h unless you use one of its functions.
sc_prohibit_stdio-safer_without_use:
	@h='stdio-safer.h' re='\<((f(re)?|p)open|tmpfile)_safer *\('	\
	  $(_sc_header_without_use)

# Prohibit the inclusion of strings.h without a sensible use.
# Using the likes of bcmp, bcopy, bzero, index or rindex is not sensible.
sc_prohibit_strings_without_use:
	@h='strings.h'							\
	re='\<(strn?casecmp|ffs(ll)?)\>'				\
	  $(_sc_header_without_use)

# Extract the raw list of symbol names with this:
gl_extract_define_simple = \
  /^\# *define ([A-Z]\w+)\(/ and print $$1
# Filter out duplicates and convert to a space-separated list:
_intprops_names = \
  $(shell f=$(gnulib_dir)/lib/intprops.h;				\
    perl -lne '$(gl_extract_define_simple)' $$f | sort -u | tr '\n' ' ')
# Remove trailing space and convert to a regular expression:
_intprops_syms_re = $(subst $(_sp),|,$(strip $(_intprops_names)))
# Prohibit the inclusion of intprops.h without an actual use.
sc_prohibit_intprops_without_use:
	@h='intprops.h'							\
	re='\<($(_intprops_syms_re)) *\('				\
	  $(_sc_header_without_use)

_stddef_syms_re = NULL|offsetof|ptrdiff_t|size_t|wchar_t
# Prohibit the inclusion of stddef.h without an actual use.
sc_prohibit_stddef_without_use:
	@h='stddef.h'							\
	re='\<($(_stddef_syms_re))\>'					\
	  $(_sc_header_without_use)

_de1 = dirfd|(close|(fd)?open|read|rewind|seek|tell)dir(64)?(_r)?
_de2 = (versionsort|struct dirent|getdirentries|alphasort|scandir(at)?)(64)?
_de3 = MAXNAMLEN|DIR|ino_t|d_ino|d_fileno|d_namlen
_dirent_syms_re = $(_de1)|$(_de2)|$(_de3)
# Prohibit the inclusion of dirent.h without an actual use.
sc_prohibit_dirent_without_use:
	@h='dirent.h'							\
	re='\<($(_dirent_syms_re))\>'					\
	  $(_sc_header_without_use)

# Prohibit the inclusion of verify.h without an actual use.
sc_prohibit_verify_without_use:
	@h='verify.h'							\
	re='\<(verify(true|expr)?|assume|static_assert) *\('		\
	  $(_sc_header_without_use)

# Don't include xfreopen.h unless you use one of its functions.
sc_prohibit_xfreopen_without_use:
	@h='xfreopen.h' re='\<xfreopen *\(' $(_sc_header_without_use)

# Each nonempty ChangeLog line must start with a year number, or a TAB.
sc_changelog:
	@prohibit='^[^12	]'					\
	in_vc_files='^ChangeLog$$'					\
	halt='found unexpected prefix in a ChangeLog'			\
	  $(_sc_search_regexp)

# Ensure that each .c file containing a "main" function also
# calls bindtextdomain.
sc_bindtextdomain:
	@require='bindtextdomain *\('					\
	in_vc_files='\.c$$'						\
	containing='\<main *('						\
	halt='the above files do not call bindtextdomain'		\
	  $(_sc_search_regexp)

sc_trailing_blank:
	@prohibit='[	 ]$$'						\
	halt='found trailing blank(s)'					\
	exclude='^Binary file .* matches$$'				\
	  $(_sc_search_regexp)


# A regexp matching function names like "error" that may be used
# to emit translatable messages.
_gl_translatable_diag_func_re ?= error

# Look for diagnostics that aren't marked for translation.
# This won't find any for which error's format string is on a separate line.
sc_unmarked_diagnostics:
	@prohibit='\<$(_gl_translatable_diag_func_re) *\([^"]*"[^"]*[a-z]{3}' \
	exclude='(_|ngettext ?)\('					\
	halt='found unmarked diagnostic(s)'				\
	  $(_sc_search_regexp)

# List headers for which HAVE_HEADER_H is always true, assuming you are
# using the appropriate gnulib module.  CAUTION: for each "unnecessary"
# #if HAVE_HEADER_H that you remove, be sure that your project explicitly
# requires the gnulib module that guarantees the usability of that header.
gl_assured_headers_ = \
  cd $(gnulib_dir)/lib && echo *.in.h|$(SED) 's/\.in\.h//g'

# Convert the list of names to upper case, and replace each space with "|".
az_ = abcdefghijklmnopqrstuvwxyz
AZ_ = ABCDEFGHIJKLMNOPQRSTUVWXYZ
gl_header_upper_case_or_ =						\
  $$($(gl_assured_headers_)						\
    | tr $(az_)/.- $(AZ_)___						\
    | tr -s ' ' '|'							\
    )
sc_prohibit_always_true_header_tests:
	@or=$(gl_header_upper_case_or_);				\
	re="HAVE_($$or)_H";						\
	prohibit='\<'"$$re"'\>'						\
	halt=$$(printf '%s\n'						\
	'do not test the above HAVE_<header>_H symbol(s);'		\
	'  with the corresponding gnulib module, they are always true')	\
	  $(_sc_search_regexp)

sc_prohibit_defined_have_decl_tests:
	@prohibit='(#[	 ]*ifn?def|\<defined)\>[	 (]+HAVE_DECL_'	\
	halt='HAVE_DECL macros are always defined'			\
	  $(_sc_search_regexp)

# ==================================================================
gl_other_headers_ ?= \
  intprops.h	\
  openat.h	\
  stat-macros.h

# Perl -lne code to extract "significant" cpp-defined symbols from a
# gnulib header file, eliminating a few common false-positives.
# The exempted names below are defined only conditionally in gnulib,
# and hence sometimes must/may be defined in application code.
gl_extract_significant_defines_ = \
  /^\# *define ([^_ (][^ (]*)(\s*\(|\s+\w+)/\
    && $$2 !~ /(?:rpl_|_used_without_)/\
    && $$1 !~ /^(?:NSIG|ENODATA)$$/\
    && $$1 !~ /^(?:SA_RESETHAND|SA_RESTART)$$/\
    and print $$1

# Create a list of regular expressions matching the names
# of macros that are guaranteed to be defined by parts of gnulib.
define def_sym_regex
	gen_h=$(gl_generated_headers_);					\
	(cd $(gnulib_dir)/lib;						\
	  for f in *.in.h $(gl_other_headers_); do			\
	    test -f $$f							\
	      && perl -lne '$(gl_extract_significant_defines_)' $$f;	\
	  done;								\
	) | sort -u							\
	  | $(SED) 's/^/^ *# *(define|undef)  */;s/$$/\\>/'
endef

# Don't define macros that we already get from gnulib header files.
sc_prohibit_always-defined_macros:
	@if test -d $(gnulib_dir); then					\
	  case $$(echo all: | $(GREP) -l -f - $(abs_top_builddir)/Makefile) in $(abs_top_builddir)/Makefile);; *) \
	    echo '$(ME): skipping $@: you lack GNU grep' 1>&2; exit 0;;	\
	  esac;								\
	  regex=$$($(def_sym_regex)); export regex;			\
	  $(VC_LIST_EXCEPT)						\
	    | xargs sh -c 'echo $$regex | $(GREP) -E -f - "$$@"'	\
		dummy /dev/null						\
	    && { printf '$(ME): define the above'			\
			' via some gnulib .h file\n' 1>&2;		\
	         exit 1; }						\
	    || :;							\
	fi
# ==================================================================

# Prohibit checked in backup files.
sc_prohibit_backup_files:
	@$(VC_LIST) | $(GREP) '~$$' &&					\
	  { echo '$(ME): found version controlled backup file' 1>&2;	\
	    exit 1; } || :

# Require the latest GFDL.  Two regexp, since some .texi files end up
# line wrapping between 'Free Documentation License,' and 'Version'.
_GFDL_regexp = (Free ''Documentation.*Version 1\.[^3]|Version 1\.[^3] or any)
sc_GFDL_version:
	@prohibit='$(_GFDL_regexp)'					\
	halt='GFDL vN, N!=3'						\
	  $(_sc_search_regexp)

cvs_keywords = \
  Author|Date|Header|Id|Name|Locker|Log|RCSfile|Revision|Source|State

sc_prohibit_cvs_keyword:
	@prohibit='\$$($(cvs_keywords))\$$'				\
	halt='do not use CVS keyword expansion'				\
	  $(_sc_search_regexp)

# This Perl code is slightly obfuscated.  Not only is each "$" doubled
# because it's in a Makefile, but the $$c's are comments;  we cannot
# use "#" due to the way the script ends up concatenated onto one line.
# It would be much more concise, and would produce better output (including
# counts) if written as:
#   perl -ln -0777 -e '/\n(\n+)$/ and print "$ARGV: ".length $1' ...
# but that would be far less efficient, reading the entire contents
# of each file, rather than just the last two bytes of each.
# In addition, while the code below detects both blank lines and a missing
# newline at EOF, the above detects only the former.
#
# This is a perl script that is expected to be the single-quoted argument
# to a command-line "-le".  The remaining arguments are file names.
# Print the name of each file that does not end in exactly one newline byte.
# I.e., warn if there are blank lines (2 or more newlines), or if the
# last byte is not a newline.  However, currently we don't complain
# about any file that contains exactly one byte.
# Exit nonzero if at least one such file is found, otherwise, exit 0.
# Warn about, but otherwise ignore open failure.  Ignore seek/read failure.
#
# Use this if you want to remove trailing empty lines from selected files:
#   perl -pi -0777 -e 's/\n\n+$/\n/' files...
#
require_exactly_one_NL_at_EOF_ =					\
  foreach my $$f (@ARGV)						\
    {									\
      open F, "<", $$f or (warn "failed to open $$f: $$!\n"), next;	\
      my $$p = sysseek (F, -2, 2);					\
      my $$c = "seek failure probably means file has < 2 bytes; ignore"; \
      my $$last_two_bytes;						\
      defined $$p and $$p = sysread F, $$last_two_bytes, 2;		\
      close F;								\
      $$c = "ignore read failure";					\
      $$p && ($$last_two_bytes eq "\n\n"				\
              || substr ($$last_two_bytes,1) ne "\n")			\
          and (print $$f), $$fail=1;					\
    }									\
  END { exit defined $$fail }
sc_prohibit_empty_lines_at_EOF:
	@$(VC_LIST_EXCEPT)						\
	  | xargs perl -le '$(require_exactly_one_NL_at_EOF_)'		\
	  || { echo '$(ME): empty line(s) or no newline at EOF' 1>&2;	\
	       exit 1; }						\
	  || :


# Perl block to convert a match to FILE_NAME:LINENO:TEST,
# that is shared by two definitions below.
perl_filename_lineno_text_ =						\
    -e '  {'								\
    -e '    $$n = ($$` =~ tr/\n/\n/ + 1);'				\
    -e '    ($$v = $$&) =~ s/\n/\\n/g;'					\
    -e '    print "$$ARGV:$$n:$$v\n";'					\
    -e '  }'

prohibit_doubled_words_ = \
    the then in an on if is it but for or at and do to
# expand the regex before running the check to avoid using expensive captures
prohibit_doubled_word_expanded_ = \
    $(join $(prohibit_doubled_words_),$(addprefix \s+,$(prohibit_doubled_words_)))
prohibit_doubled_word_RE_ ?= \
    /\b(?:$(subst $(_sp),|,$(prohibit_doubled_word_expanded_)))\b/gims
prohibit_doubled_word_ =						\
    -e 'while ($(prohibit_doubled_word_RE_))'				\
    $(perl_filename_lineno_text_)

# Define this to a regular expression that matches
# any filename:dd:match lines you want to ignore.
# The default is to ignore no matches.
ignore_doubled_word_match_RE_ ?= ^$$

sc_prohibit_doubled_word:
	@$(VC_LIST_EXCEPT)						\
	  | xargs perl -n -0777 $(prohibit_doubled_word_)		\
	  | $(GREP) -vE '$(ignore_doubled_word_match_RE_)'		\
	  | $(GREP) .							\
	  && { echo '$(ME): doubled words' 1>&2; exit 1; }		\
	  || :

# Except for shell files and for loops, double semicolon is probably a mistake
sc_prohibit_double_semicolon:
	@prohibit='; *;[	{} \]*(/[/*]|$$)'			\
	in_vc_files='\.[chly]$$'					\
	exclude='\bfor *\(.*\)'						\
	halt="Double semicolon detected"				\
	  $(_sc_search_regexp)

_ptm1 = use "test C1 && test C2", not "test C1 -''a C2"
_ptm2 = use "test C1 || test C2", not "test C1 -''o C2"
# Using test's -a and -o operators is not portable.
# We prefer test over [, since the latter is spelled [[ in configure.ac.
sc_prohibit_test_minus_ao:
	@prohibit='(\<test| \[+) .+ -[ao] '				\
	halt='$(_ptm1); $(_ptm2)'					\
	  $(_sc_search_regexp)

# Avoid a test bashism.
sc_prohibit_test_double_equal:
	@prohibit='(\<test| \[+) .+ == '				\
	containing='#! */bin/[a-z]*sh'					\
	halt='use "test x = x", not "test x =''= x"'			\
	  $(_sc_search_regexp)

# Each program that uses proper_name_utf8 must link with one of the
# ICONV libraries.  Otherwise, some ICONV library must appear in LDADD.
# The perl -0777 invocation below extracts the possibly-multi-line
# definition of LDADD from the appropriate Makefile.am and exits 0
# when it contains "ICONV".
sc_proper_name_utf8_requires_ICONV:
	@progs=$$($(VC_LIST_EXCEPT)					\
		    | xargs $(GREP) -l 'proper_name_utf8 ''("');	\
	if test "x$$progs" != x; then					\
	  fail=0;							\
	  for p in $$progs; do						\
	    dir=$$(dirname "$$p");					\
	    perl -0777							\
	      -ne 'exit !(/^LDADD =(.+?[^\\]\n)/ms && $$1 =~ /ICONV/)'	\
	      $$dir/Makefile.am && continue;				\
	    base=$$(basename "$$p" .c);					\
	    $(GREP) "$${base}_LDADD.*ICONV)" $$dir/Makefile.am > /dev/null	\
	      || { fail=1; echo 1>&2 "$(ME): $$p uses proper_name_utf8"; }; \
	  done;								\
	  test $$fail = 1 &&						\
	    { echo 1>&2 '$(ME): the above do not link with any ICONV library'; \
	      exit 1; } || :;						\
	fi

# Warn about "c0nst struct Foo const foo[]",
# but not about "char const *const foo" or "#define const const".
sc_redundant_const:
	@prohibit='\bconst\b[[:space:][:alnum:]]{2,}\bconst\b'		\
	halt='redundant "const" in declarations'			\
	  $(_sc_search_regexp)

sc_const_long_option:
	@prohibit='^ *static.*struct option '				\
	exclude='const struct option|struct option const'		\
	halt='add "const" to the above declarations'			\
	  $(_sc_search_regexp)

NEWS_hash =								\
  $$($(SED) -n '/^\*.* $(PREV_VERSION_REGEXP) ([0-9-]*)/,$$p'		\
       $(srcdir)/NEWS							\
     | perl -0777 -pe							\
	's/^Copyright.+?Free\sSoftware\sFoundation,\sInc\.\n//ms'	\
     | md5sum -								\
     | $(SED) 's/ .*//')

# Update the hash stored above.  Do this after each release and
# for any corrections to old entries.
update-NEWS-hash: NEWS
	perl -pi -e 's/^(old_NEWS_hash[ \t]+:?=[ \t]+).*/$${1}'"$(NEWS_hash)/" \
	  $(srcdir)/syntax-check.mk

# Ensure that we use only the standard $(VAR) notation,
# not @...@ in Makefile.am, now that we can rely on automake
# to emit a definition for each substituted variable.
# However, there is still one case in which @VAR@ use is not just
# legitimate, but actually required: when augmenting an automake-defined
# variable with a prefix.  For example, gettext uses this:
# MAKEINFO = env LANG= LC_MESSAGES= LC_ALL= LANGUAGE= @MAKEINFO@
# otherwise, makeinfo would put German or French (current locale)
# navigation hints in the otherwise-English documentation.
#
# Allow the package to add exceptions via a hook in syntax-check.mk;
# for example, @PRAGMA_SYSTEM_HEADER@ can be permitted by
# setting this to ' && !/PRAGMA_SYSTEM_HEADER/'.
_makefile_at_at_check_exceptions ?=
sc_makefile_at_at_check:
	@perl -ne '/\@\w+\@/'						\
          -e ' && !/(\w+)\s+=.*\@\1\@$$/'				\
          -e ''$(_makefile_at_at_check_exceptions)			\
	  -e 'and (print "$$ARGV:$$.: $$_"), $$m=1; END {exit !$$m}'	\
	    $$($(VC_LIST_EXCEPT) | $(GREP) -E '(^|/)(Makefile\.am|[^/]+\.mk)$$') \
	  && { echo '$(ME): use $$(...), not @...@' 1>&2; exit 1; } || :

sc_makefile_TAB_only_indentation:
	@prohibit='^	[ ]{8}'						\
	in_vc_files='akefile|\.mk$$'					\
	halt='found TAB-8-space indentation'				\
	  $(_sc_search_regexp)

sc_m4_quote_check:
	@prohibit='(AC_DEFINE(_UNQUOTED)?|AC_DEFUN)\([^[]'		\
	in_vc_files='(^configure\.ac|\.m4)$$'				\
	halt='quote the first arg to AC_DEF*'				\
	  $(_sc_search_regexp)

fix_po_file_diag = \
'you have changed the set of files with translatable diagnostics;\n\
apply the above patch\n'

# Generate a list of files in which to search for translatable strings.
perl_translatable_files_list_ =						\
  -e 'foreach $$file (@ARGV) {'						\
  -e '	\# Consider only file extensions with one or two letters'	\
  -e '	$$file =~ /\...?$$/ or next;'					\
  -e '	\# Ignore m4 and mk files'					\
  -e '	$$file =~ /\.m[4k]$$/ and next;'				\
  -e '	\# Ignore a .c or .h file with a corresponding .l or .y file'	\
  -e '	$$file =~ /(.+)\.[ch]$$/ && (-e "$${1}.l" || -e "$${1}.y")'	\
  -e '	  and next;'							\
  -e '	\# Skip unreadable files'					\
  -e '	-r $$file or next;'						\
  -e '	print "$$file ";'						\
  -e '}'

# Verify that all source files using _() (more specifically, files that
# match $(_gl_translatable_string_re)) are listed in po/POTFILES.in.
po_file ?= $(srcdir)/po/POTFILES.in
generated_files ?= $(srcdir)/lib/*.[ch]
_gl_translatable_string_re ?= \b(N?_|gettext *)\([^)"]*("|$$)
sc_po_check:
	@if test -f $(po_file); then					\
	  $(GREP) -E -v '^(#|$$)' $(po_file)				\
	    | $(GREP) -v '^src/false\.c$$' | sort > $@-1;		\
	  { $(VC_LIST_EXCEPT); echo $(generated_files); }		\
	    | xargs perl $(perl_translatable_files_list_)		\
	    | xargs $(GREP) -E -l '$(_gl_translatable_string_re)'	\
	    | $(SED) 's|^$(_dot_escaped_srcdir)/||'			\
	    | sort -u > $@-2;						\
	  diff -u -L $(po_file) -L $(po_file) $@-1 $@-2			\
	    || { printf '$(ME): '$(fix_po_file_diag) 1>&2; exit 1; };	\
	  rm -f $@-1 $@-2;						\
	fi

# Check that 'make alpha' will not fail at the end of the process,
# i.e., when pkg-M.N.tar.xz already exists (either in "." or in ../release)
# and is read-only.
writable-files:
	$(AM_V_GEN)if test -d $(release_archive_dir); then		\
	  for file in $(DIST_ARCHIVES); do				\
	    for p in ./ $(release_archive_dir)/; do			\
	      test -e $$p$$file || continue;				\
	      test -w $$p$$file						\
		|| { echo ERROR: $$p$$file is not writable; fail=1; };	\
	    done;							\
	  done;								\
	  test "$$fail" && exit 1 || : ;				\
	else :;								\
	fi

v_etc_file = $(gnulib_dir)/lib/version-etc.c
sample-test = tests/sample-test
texi = doc/$(PACKAGE).texi
# Make sure that the copyright date in $(v_etc_file) is up to date.
# Do the same for the $(sample-test) and the main doc/.texi file.
sc_copyright_check:
	@require='enum { COPYRIGHT_YEAR = '$$(date +%Y)' };'		\
	in_files=$(v_etc_file)						\
	halt='out of date copyright in $(v_etc_file); update it'	\
	  $(_sc_search_regexp)
	@require='# Copyright \(C\) '$$(date +%Y)' Free'		\
	in_vc_files=$(sample-test)					\
	halt='out of date copyright in $(sample-test); update it'	\
	  $(_sc_search_regexp)
	@require='Copyright @copyright\{\} .*'$$(date +%Y)		\
	in_vc_files=$(texi)						\
	halt='out of date copyright in $(texi); update it'		\
	  $(_sc_search_regexp)


# BRE regex of file contents to identify a test script.
_test_script_regex ?= \<init\.sh\>

# In tests, use "compare expected actual", not the reverse.
sc_prohibit_reversed_compare_failure:
	@prohibit='\<compare [^ ]+ ([^ ]*exp|/dev/null)'		\
	containing='$(_test_script_regex)'				\
	halt='reversed compare arguments'				\
	  $(_sc_search_regexp)

# #if HAVE_... will evaluate to false for any non numeric string.
# That would be flagged by using -Wundef, however gnulib currently
# tests many undefined macros, and so we can't enable that option.
# So at least preclude common boolean strings as macro values.
sc_Wundef_boolean:
	@prohibit='^#define.*(yes|no|true|false)$$'			\
	in_files='$(CONFIG_INCLUDE)'					\
	halt='Use 0 or 1 for macro values'				\
	  $(_sc_search_regexp)

# Even if you use pathmax.h to guarantee that PATH_MAX is defined, it might
# not be constant, or might overflow a stack.  In general, use PATH_MAX as
# a limit, not an array or alloca size.
sc_prohibit_path_max_allocation:
	@prohibit='(\balloca *\([^)]*|\[[^]]*)\bPATH_MAX'		\
	halt='Avoid stack allocations of size PATH_MAX'			\
	  $(_sc_search_regexp)

sc_vulnerable_makefile_CVE-2009-4029:
	@prohibit='perm -777 -exec chmod a\+rwx|chmod 777 \$$\(distdir\)' \
	in_files='(^|/)Makefile\.in$$'					\
	halt=$$(printf '%s\n'						\
	  'the above files are vulnerable; beware of running'		\
	  '  "make dist*" rules, and upgrade to fixed automake'		\
	  '  see https://bugzilla.redhat.com/show_bug.cgi?id=542609 for details') \
	  $(_sc_search_regexp)

sc_vulnerable_makefile_CVE-2012-3386:
	@prohibit='chmod a\+w \$$\(distdir\)'				\
	in_files='(^|/)Makefile\.in$$'					\
	halt=$$(printf '%s\n'						\
	  'the above files are vulnerable; beware of running'		\
	  '  "make distcheck", and upgrade to fixed automake'		\
	  '  see https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2012-3386 for details') \
	  $(_sc_search_regexp)

# We don't use this feature of syntax-check.mk.
prev_version_file = /dev/null

ifneq ($(_gl-Makefile),)
ifeq (0,$(MAKELEVEL))
  _dry_run_result := $(shell \
      cd '$(srcdir)'; \
      test -d .git || test -f .git || { echo 0; exit; }; \
      $(srcdir)/autogen.sh --dry-run >/dev/null 2>&1; \
      echo $$?; \
  )
  _clean_requested = $(filter %clean,$(MAKECMDGOALS))

  # A return value of 0 means no action is required

  # A return value of 1 means a genuine error has occurred while
  # performing the dry run, and it should be reported so it can
  # be investigated
  ifeq (1,$(_dry_run_result))
    $(info INFO: autogen.sh error, running again to show details)
syntax-check.mk Makefile: _autogen_error
  endif

  # A return value of 2 means that autogen.sh needs to be executed
  # in earnest before building, probably because of gnulib updates.
  # We don't run autogen.sh if the clean target has been invoked,
  # though, as it would be quite pointless
  ifeq (2,$(_dry_run_result)$(_clean_requested))
    $(info INFO: running autogen.sh is required, running it now...)
    $(shell touch $(srcdir)/AUTHORS)
syntax-check.mk Makefile: _autogen
  endif
endif
endif

# It is necessary to call autogen any time gnulib changes.  Autogen
# reruns configure, then we regenerate all Makefiles at once.
.PHONY: _autogen
_autogen:
	$(srcdir)/autogen.sh
	./config.status

.PHONY: _autogen_error
_autogen_error:
	$(srcdir)/autogen.sh --dry-run

ifneq ($(_gl-Makefile),)
syntax-check: spacing-check test-wrap-argv \
	prohibit-duplicate-header mock-noinline group-qemu-caps \
        header-ifdef
	@if ! cppi --version >/dev/null 2>&1; then \
		echo "*****************************************************" >&2; \
		echo "* cppi not installed, some checks have been skipped *" >&2; \
		echo "*****************************************************" >&2; \
	fi; \
	if [ -z "$(FLAKE8)" ]; then \
		echo "*****************************************************" >&2; \
		echo "* flake8 not installed, sc_flake8 has been skipped  *" >&2; \
		echo "*****************************************************" >&2; \
	fi
endif

# Don't include duplicate header in the source (either *.c or *.h)
prohibit-duplicate-header:
	$(AM_V_GEN)$(VC_LIST_EXCEPT) | $(GREP) '\.[chx]$$' | xargs \
	$(PERL) -W $(top_srcdir)/build-aux/prohibit-duplicate-header.pl

spacing-check:
	$(AM_V_GEN)$(VC_LIST) | $(GREP) '\.c$$' | xargs \
	$(PERL) $(top_srcdir)/build-aux/check-spacing.pl || \
	  { echo '$(ME): incorrect formatting' 1>&2; exit 1; }

mock-noinline:
	$(AM_V_GEN)$(VC_LIST) | $(GREP) '\.[ch]$$' | xargs \
	$(PERL) $(top_srcdir)/build-aux/mock-noinline.pl

header-ifdef:
	$(AM_V_GEN)$(VC_LIST) | $(GREP) '\.[h]$$' | xargs \
	$(PERL) $(top_srcdir)/build-aux/header-ifdef.pl

test-wrap-argv:
	$(AM_V_GEN)$(VC_LIST) | $(GREP) -E '\.(ldargs|args)' | xargs \
	$(PERL) $(top_srcdir)/tests/test-wrap-argv.pl --check

group-qemu-caps:
	$(AM_V_GEN)$(PERL) $(top_srcdir)/tests/group-qemu-caps.pl --check $(top_srcdir)/

# sc_po_check can fail if generated files are not built first
sc_po_check: \
		$(srcdir)/src/remote/remote_daemon_dispatch_stubs.h \
		$(srcdir)/src/remote/remote_daemon_dispatch_qemu_stubs.h \
		$(srcdir)/src/remote/remote_client_bodies.h \
		$(srcdir)/src/admin/admin_server_dispatch_stubs.h \
		$(srcdir)/src/admin/admin_client.h
$(srcdir)/src/remote/remote_daemon_dispatch_stubs.h: $(srcdir)/src/remote/remote_protocol.x
	$(MAKE) -C src remote/remote_daemon_dispatch_stubs.h
$(srcdir)/src/remote/remote_daemon_dispatch_qemu_stubs.h: $(srcdir)/src/remote/qemu_protocol.x
	$(MAKE) -C src remote/remote_daemon_dispatch_qemu_stubs.h
$(srcdir)/src/remote/remote_client_bodies.h: $(srcdir)/src/remote/remote_protocol.x
	$(MAKE) -C src remote/remote_client_bodies.h
$(srcdir)/src/admin/admin_server_dispatch_stubs.h: $(srcdir)/src/admin/admin_protocol.x
	$(MAKE) -C src admin/admin_server_dispatch_stubs.h
$(srcdir)/src/admin/admin_client.h: $(srcdir)/src/admin/admin_protocol.x
	$(MAKE) -C src admin/admin_client.h

# List all syntax-check exemptions:
exclude_file_name_regexp--sc_avoid_strcase = ^tools/vsh\.h$$

_src1=libvirt-stream|qemu/qemu_monitor|util/vir(command|file|fdstream)|xen/xend_internal|rpc/virnetsocket|lxc/lxc_controller|locking/lock_daemon|logging/log_daemon
_test1=shunloadtest|virnettlscontexttest|virnettlssessiontest|vircgroupmock|commandhelper
exclude_file_name_regexp--sc_avoid_write = \
  ^(src/($(_src1))|tools/virsh-console|tests/($(_test1)))\.c$$

exclude_file_name_regexp--sc_bindtextdomain = .*

exclude_file_name_regexp--sc_gettext_init = ^((tests|examples)/|tools/virt-login-shell.c)

exclude_file_name_regexp--sc_copyright_format = \
	^build-aux/syntax-check\.mk$$

exclude_file_name_regexp--sc_copyright_usage = \
  ^COPYING(|\.LESSER)|build-aux/syntax-check.mk$$

exclude_file_name_regexp--sc_flags_usage = \
  ^(build-aux/syntax-check\.mk|docs/|src/util/virnetdevtap\.c$$|tests/((vir(cgroup|pci|test|usb)|nss|qemuxml2argv|qemusecurity)mock|virfilewrapper)\.c$$)

exclude_file_name_regexp--sc_libvirt_unmarked_diagnostics = \
  ^(src/rpc/gendispatch\.pl$$|tests/)

exclude_file_name_regexp--sc_po_check = ^(docs/|src/rpc/gendispatch\.pl$$)

exclude_file_name_regexp--sc_prohibit_VIR_ERR_NO_MEMORY = \
  ^(build-aux/syntax-check\.mk|include/libvirt/virterror\.h|src/remote/remote_daemon_dispatch\.c|src/util/virerror\.c|docs/internals/oomtesting\.html\.in)$$

exclude_file_name_regexp--sc_makefile_TAB_only_indentation = \
  ^build-aux/syntax-check\.mk$$

exclude_file_name_regexp--sc_makefile_at_at_check = \
  ^build-aux/syntax-check\.mk$$

exclude_file_name_regexp--sc_prohibit_PATH_MAX = \
	^build-aux/syntax-check\.mk$$

exclude_file_name_regexp--sc_prohibit_access_xok = \
	^(build-aux/syntax-check\.mk|src/util/virutil\.c)$$

exclude_file_name_regexp--sc_prohibit_asprintf = \
  ^(build-aux/syntax-check\.mk|bootstrap.conf$$|examples/|src/util/virstring\.[ch]$$|tests/vircgroupmock\.c|tools/virt-login-shell\.c|tools/nss/libvirt_nss\.c$$)

exclude_file_name_regexp--sc_prohibit_strdup = \
  ^(docs/|examples/|src/util/virstring\.c|tests/vir(netserverclient|cgroup)mock.c|tests/commandhelper\.c|tools/nss/libvirt_nss_(leases|macs)\.c$$)

exclude_file_name_regexp--sc_prohibit_close = \
  (\.p[yl]$$|\.spec\.in$$|^docs/|^(src/util/virfile\.c|src/libvirt-stream\.c|tests/(vir.+mock\.c|commandhelper\.c|qemusecuritymock\.c)|tools/nss/libvirt_nss_(leases|macs)\.c)$$)

exclude_file_name_regexp--sc_prohibit_empty_lines_at_EOF = \
  (^tests/(virhostcpu|virpcitest)data/|docs/js/.*\.js|docs/fonts/.*\.woff|\.diff|tests/virconfdata/no-newline\.conf$$)

_src2=src/(util/vircommand|libvirt|lxc/lxc_controller|locking/lock_daemon|logging/log_daemon|remote/remote_daemon)
exclude_file_name_regexp--sc_prohibit_fork_wrappers = \
  (^($(_src2)|tests/testutils)\.c$$)

exclude_file_name_regexp--sc_prohibit_gethostname = ^src/util/vir(util|log)\.c$$

exclude_file_name_regexp--sc_prohibit_internal_functions = \
  ^src/(util/(viralloc|virutil|virfile)\.[hc]|esx/esx_vi\.c)$$

exclude_file_name_regexp--sc_prohibit_raw_virclassnew = \
  ^src/util/virobject\.[hc]$$

exclude_file_name_regexp--sc_prohibit_newline_at_end_of_diagnostic = \
  ^src/rpc/gendispatch\.pl$$

exclude_file_name_regexp--sc_prohibit_nonreentrant = \
  ^((po|tests|examples)/|docs/.*(py|js|html\.in)|run.in$$|tools/wireshark/util/genxdrstub\.pl|tools/virt-login-shell\.c$$)

exclude_file_name_regexp--sc_prohibit_select = \
	^build-aux/syntax-check\.mk$$

exclude_file_name_regexp--sc_prohibit_canonicalize_file_name = \
  ^(build-aux/syntax-check\.mk|tests/virfilemock\.c)$$

exclude_file_name_regexp--sc_prohibit_raw_allocation = \
  ^(docs/hacking\.html\.in|src/util/viralloc\.[ch]|examples/.*|tests/(securityselinuxhelper|(vircgroup|nss)mock|commandhelper)\.c|tools/wireshark/src/packet-libvirt\.c|tools/nss/libvirt_nss(_leases|_macs)?\.c|build-aux/useless-if-before-free)$$

exclude_file_name_regexp--sc_prohibit_readlink = \
  ^src/(util/virutil|lxc/lxc_container)\.c$$

exclude_file_name_regexp--sc_prohibit_setuid = ^src/util/virutil\.c|tools/virt-login-shell\.c$$

exclude_file_name_regexp--sc_prohibit_sprintf = \
  ^(build-aux/syntax-check\.mk|docs/hacking\.html\.in|.*\.stp|.*\.pl)$$

exclude_file_name_regexp--sc_prohibit_strncpy = ^src/util/virstring\.c$$

exclude_file_name_regexp--sc_prohibit_strtol = ^examples/.*$$

exclude_file_name_regexp--sc_prohibit_xmlGetProp = ^src/util/virxml\.c$$

exclude_file_name_regexp--sc_prohibit_xmlURI = ^src/util/viruri\.c$$

exclude_file_name_regexp--sc_prohibit_return_as_function = \.py|build-aux/useless-if-before-free$$

exclude_file_name_regexp--sc_require_config_h = \
	^(examples/|tools/virsh-edit\.c$$|tests/virmockstathelpers.c)

exclude_file_name_regexp--sc_require_config_h_first = \
	^(examples/|tools/virsh-edit\.c$$|tests/virmockstathelpers.c)

exclude_file_name_regexp--sc_trailing_blank = \
  /sysinfodata/.*\.data|/virhostcpudata/.*\.cpuinfo|^gnulib/local/.*/.*diff$$

exclude_file_name_regexp--sc_unmarked_diagnostics = \
  ^(docs/apibuild.py|tests/virt-aa-helper-test|docs/js/.*\.js)$$

exclude_file_name_regexp--sc_size_of_brackets = build-aux/syntax-check\.mk

exclude_file_name_regexp--sc_correct_id_types = \
  (^src/locking/lock_protocol.x$$)

exclude_file_name_regexp--sc_m4_quote_check = m4/virt-lib.m4

exclude_file_name_regexp--sc_prohibit_include_public_headers_quote = \
  ^(src/internal\.h$$|tools/wireshark/src/packet-libvirt.c$$)

exclude_file_name_regexp--sc_prohibit_include_public_headers_brackets = \
  ^(tools/|examples/|include/libvirt/(virterror|libvirt(-(admin|qemu|lxc))?)\.h$$)

exclude_file_name_regexp--sc_prohibit_int_ijk = \
  ^(src/remote_protocol-structs|src/remote/remote_protocol\.x|build-aux/syntax-check\.mk|include/libvirt/libvirt.+|src/admin_protocol-structs|src/admin/admin_protocol\.x)$$

exclude_file_name_regexp--sc_prohibit_unsigned_pid = \
  ^(include/libvirt/.*\.h|src/(qemu/qemu_driver\.c|driver-hypervisor\.h|libvirt(-[a-z]*)?\.c|.*\.x|util/vir(polkit|systemd)\.c)|tests/virpolkittest\.c|tools/virsh-domain\.c)$$

exclude_file_name_regexp--sc_avoid_attribute_unused_in_header = \
  ^(src/util/virlog\.h|src/network/bridge_driver\.h)$$

exclude_file_name_regexp--sc_prohibit_mixed_case_abbreviations = \
  ^src/(vbox/vbox_CAPI.*.h|esx/esx_vi.(c|h)|esx/esx_storage_backend_iscsi.c)$$

exclude_file_name_regexp--sc_prohibit_empty_first_line = \
  ^(README|src/esx/README|tests/(vmwarever|virhostcpu)data/.*)$$

exclude_file_name_regexp--sc_prohibit_useless_translation = \
  ^tests/virpolkittest.c

exclude_file_name_regexp--sc_prohibit_devname = \
  ^(tools/virsh.pod|build-aux/syntax-check\.mk|docs/.*)$$

exclude_file_name_regexp--sc_prohibit_virXXXFree = \
  ^(docs/|tests/|examples/|tools/|build-aux/syntax-check\.mk|src/test/test_driver.c|src/libvirt_public.syms|include/libvirt/libvirt-(domain|network|nodedev|storage|stream|secret|nwfilter|interface|domain-snapshot).h|src/libvirt-(domain|qemu|network|nodedev|storage|stream|secret|nwfilter|interface|domain-snapshot).c$$)

exclude_file_name_regexp--sc_prohibit_sysconf_pagesize = \
  ^(build-aux/syntax-check\.mk|src/util/virutil\.c)$$

exclude_file_name_regexp--sc_prohibit_pthread_create = \
  ^(build-aux/syntax-check\.mk|src/util/virthread\.c|tests/.*)$$

exclude_file_name_regexp--sc_prohibit_always-defined_macros = \
  ^tests/virtestmock.c$$

exclude_file_name_regexp--sc_prohibit_readdir = \
  ^(tests/(.*mock|virfilewrapper)\.c|tools/nss/libvirt_nss\.c)$$

exclude_file_name_regexp--sc_prohibit_cross_inclusion = \
  ^(src/util/virclosecallbacks\.h|src/util/virhostdev\.h)$$

exclude_file_name_regexp--sc_prohibit_dirent_d_type = \
  ^(src/util/vircgroup.c)$

exclude_file_name_regexp--sc_prohibit_strcmp = \
  ^(tools/nss/libvirt_nss.*\.c|tools/virt-login-shell\.c)

exclude_file_name_regexp--sc_prohibit_backslash_alignment = \
  ^build-aux/syntax-check\.mk$$
