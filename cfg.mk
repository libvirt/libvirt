# Customize Makefile.maint.                           -*- makefile -*-
# Copyright (C) 2008-2015 Red Hat, Inc.
# Copyright (C) 2003-2008 Free Software Foundation, Inc.

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

# Use alpha.gnu.org for alpha and beta releases.
# Use ftp.gnu.org for major releases.
gnu_ftp_host-alpha = alpha.gnu.org
gnu_ftp_host-beta = alpha.gnu.org
gnu_ftp_host-major = ftp.gnu.org
gnu_rel_host = $(gnu_ftp_host-$(RELEASE_TYPE))

url_dir_list = \
  ftp://$(gnu_rel_host)/gnu/coreutils

# We use .gnulib, not gnulib.
gnulib_dir = $(srcdir)/.gnulib

# List of additional files that we want to pick up in our POTFILES.in
# This is all gnulib files, as well as generated files for RPC code.
generated_files = \
  $(srcdir)/daemon/*_dispatch.h \
  $(srcdir)/src/*/*_dispatch.h \
  $(srcdir)/src/remote/*_client_bodies.h \
  $(srcdir)/src/*/*_protocol.[ch] \
  $(srcdir)/gnulib/lib/*.[ch]

# We haven't converted all scripts to using gnulib's init.sh yet.
_test_script_regex = \<\(init\|test-lib\)\.sh\>

# Tests not to run as part of "make distcheck".
local-checks-to-skip =			\
  changelog-check			\
  makefile-check			\
  makefile_path_separator_check		\
  patch-check				\
  sc_GPL_version			\
  sc_always_defined_macros		\
  sc_cast_of_alloca_return_value	\
  sc_cross_check_PATH_usage_in_tests	\
  sc_dd_max_sym_length			\
  sc_error_exit_success			\
  sc_file_system			\
  sc_immutable_NEWS			\
  sc_makefile_path_separator_check	\
  sc_obsolete_symbols			\
  sc_prohibit_S_IS_definition		\
  sc_prohibit_atoi_atof			\
  sc_prohibit_hash_without_use		\
  sc_prohibit_jm_in_m4			\
  sc_prohibit_quote_without_use		\
  sc_prohibit_quotearg_without_use	\
  sc_prohibit_stat_st_blocks		\
  sc_prohibit_undesirable_word_seq	\
  sc_root_tests				\
  sc_space_tab				\
  sc_sun_os_names			\
  sc_system_h_headers			\
  sc_texinfo_acronym			\
  sc_tight_scope			\
  sc_two_space_separator_in_usage	\
  sc_error_message_uppercase		\
  sc_program_name			\
  sc_require_test_exit_idiom		\
  sc_makefile_check			\
  sc_useless_cpp_parens

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
  (^(HACKING|docs/(news(-[0-9]*)?\.html\.in|.*\.patch))|\.(po|fig|gif|ico|png))$$

# Functions like free() that are no-ops on NULL arguments.
useless_free_options =				\
  --name=VBOX_UTF16_FREE			\
  --name=VBOX_UTF8_FREE				\
  --name=VBOX_COM_UNALLOC_MEM			\
  --name=VIR_FREE				\
  --name=qemuCapsFree				\
  --name=qemuMigrationCookieFree                \
  --name=qemuMigrationCookieGraphicsFree        \
  --name=sexpr_free				\
  --name=usbFreeDevice                          \
  --name=virBandwidthDefFree			\
  --name=virBitmapFree                          \
  --name=virCPUDefFree				\
  --name=virCapabilitiesFree			\
  --name=virCapabilitiesFreeGuest		\
  --name=virCapabilitiesFreeGuestDomain		\
  --name=virCapabilitiesFreeGuestFeature	\
  --name=virCapabilitiesFreeGuestMachine	\
  --name=virCapabilitiesFreeHostNUMACell	\
  --name=virCapabilitiesFreeMachines		\
  --name=virCgroupFree				\
  --name=virCommandFree				\
  --name=virConfFreeList			\
  --name=virConfFreeValue			\
  --name=virDomainActualNetDefFree		\
  --name=virDomainChrDefFree			\
  --name=virDomainChrSourceDefFree		\
  --name=virDomainControllerDefFree		\
  --name=virDomainDefFree			\
  --name=virDomainDeviceDefFree			\
  --name=virDomainDiskDefFree			\
  --name=virDomainEventCallbackListFree		\
  --name=virObjectEventQueueFree		\
  --name=virDomainFSDefFree			\
  --name=virDomainGraphicsDefFree		\
  --name=virDomainHostdevDefFree		\
  --name=virDomainInputDefFree			\
  --name=virDomainNetDefFree			\
  --name=virDomainObjFree			\
  --name=virDomainSmartcardDefFree		\
  --name=virDomainSnapshotDefFree		\
  --name=virDomainSnapshotObjFree		\
  --name=virDomainSoundDefFree			\
  --name=virDomainVideoDefFree			\
  --name=virDomainWatchdogDefFree		\
  --name=virFileDirectFdFree			\
  --name=virHashFree				\
  --name=virInterfaceDefFree			\
  --name=virInterfaceIpDefFree			\
  --name=virInterfaceObjFree			\
  --name=virInterfaceProtocolDefFree		\
  --name=virJSONValueFree			\
  --name=virLastErrFreeData			\
  --name=virNetMessageFree                      \
  --name=virNetServerMDNSFree                   \
  --name=virNetServerMDNSEntryFree              \
  --name=virNetServerMDNSGroupFree              \
  --name=virNWFilterDefFree			\
  --name=virNWFilterEntryFree			\
  --name=virNWFilterHashTableFree		\
  --name=virNWFilterIPAddrLearnReqFree		\
  --name=virNWFilterIncludeDefFree		\
  --name=virNWFilterObjFree			\
  --name=virNWFilterRuleDefFree			\
  --name=virNWFilterRuleInstFree		\
  --name=virNetworkDefFree			\
  --name=virNodeDeviceDefFree			\
  --name=virNodeDeviceObjFree			\
  --name=virObjectUnref                         \
  --name=virObjectFreeCallback                  \
  --name=virPCIDeviceFree                       \
  --name=virSecretDefFree			\
  --name=virStorageEncryptionFree		\
  --name=virStorageEncryptionSecretFree		\
  --name=virStorageFileFreeMetadata		\
  --name=virStoragePoolDefFree			\
  --name=virStoragePoolObjFree			\
  --name=virStoragePoolSourceFree		\
  --name=virStorageVolDefFree			\
  --name=virThreadPoolFree			\
  --name=xmlBufferFree				\
  --name=xmlFree				\
  --name=xmlFreeDoc				\
  --name=xmlFreeNode				\
  --name=xmlXPathFreeContext			\
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
# y virDomainSnapshotDefFree
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
	@prohibit='\<write *\('						\
	in_vc_files='\.c$$'						\
	halt='consider using safewrite instead of write'		\
	  $(_sc_search_regexp)

# In debug statements, print flags as bitmask and mode_t as octal.
sc_flags_debug:
	@prohibit='\<mode=%[0-9.]*[diux]'				\
	halt='use %o to debug mode_t values'				\
	  $(_sc_search_regexp)
	@prohibit='[Ff]lags=%[0-9.]*l*[diou]'				\
	halt='use %x to debug flag values'				\
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
	@test "$$(cat $(srcdir)/include/libvirt/libvirt-domain.h	\
	    $(srcdir)/include/libvirt/virterror.h			\
	    $(srcdir)/include/libvirt/libvirt-qemu.h			\
	    $(srcdir)/include/libvirt/libvirt-lxc.h			\
	    $(srcdir)/include/libvirt/libvirt-admin.h			\
	  | grep -c '\(long\|unsigned\) flags')" != 4 &&		\
	  { echo '$(ME): new API should use "unsigned int flags"' 1>&2;	\
	    exit 1; } || :
	@prohibit=' flags ATTRIBUTE_UNUSED'				\
	halt='flags should be checked with virCheckFlags'		\
	  $(_sc_search_regexp)
	@prohibit='^[^@]*([^d] (int|long long)|[^dg] long) flags[;,)]'	\
	halt='flags should be unsigned'					\
	  $(_sc_search_regexp)

# Avoid functions that should only be called via macro counterparts.
sc_prohibit_internal_functions:
	@prohibit='vir(Free|AllocN?|ReallocN|(Insert|Delete)ElementsN|File(Close|Fclose|Fdopen)) *\(' \
	halt='use VIR_ macros instead of internal functions'		\
	  $(_sc_search_regexp)

# Avoid raw malloc and free, except in documentation comments.
sc_prohibit_raw_allocation:
	@prohibit='^.[^*].*\<((m|c|re)alloc|free) *\([^)]'		\
	halt='use VIR_ macros from viralloc.h instead of malloc/free'	\
	  $(_sc_search_regexp)

# Avoid functions that can lead to double-close bugs.
sc_prohibit_close:
	@prohibit='([^>.]|^)\<[fp]?close *\('				\
	halt='use VIR_{FORCE_}[F]CLOSE instead of [f]close'		\
	  $(_sc_search_regexp)
	@prohibit='\<fdopen *\('					\
	halt='use VIR_FDOPEN instead of fdopen'				\
	  $(_sc_search_regexp)

# Prefer virCommand for all child processes.
sc_prohibit_fork_wrappers:
	@prohibit='= *\<(fork|popen|system) *\('			\
	halt='use virCommand for child processes'			\
	  $(_sc_search_regexp)

# Prefer mkostemp with O_CLOEXEC.
sc_prohibit_mkstemp:
	@prohibit='[^"]\<mkstemps? *\('					\
	halt='use mkostemp with O_CLOEXEC instead of mkstemp'		\
	  $(_sc_search_regexp)

# access with X_OK accepts directories, but we can't exec() those.
# access with F_OK or R_OK is okay, though.
sc_prohibit_access_xok:
	@prohibit='access(at)? *\(.*X_OK'				\
	halt='use virFileIsExecutable instead of access(,X_OK)'		\
	  $(_sc_search_regexp)

# Similar to the gnulib maint.mk rule for sc_prohibit_strcmp
# Use STREQLEN or STRPREFIX rather than comparing strncmp == 0, or != 0.
snp_ = strncmp *\(.+\)
sc_prohibit_strncmp:
	@prohibit='! *strncmp *\(|\<$(snp_) *[!=]=|[!=]= *$(snp_)'	\
	exclude=':# *define STR(N?EQLEN|PREFIX)\('			\
	halt='use STREQLEN or STRPREFIX instead of strncmp'		\
	  $(_sc_search_regexp)

# strtol and friends are too easy to misuse
sc_prohibit_strtol:
	@prohibit='\bstrto(u?ll?|[ui]max) *\('				\
	exclude='exempt from syntax-check'				\
	halt='use virStrToLong_*, not strtol variants'			\
	  $(_sc_search_regexp)
	@prohibit='\bstrto[df] *\('					\
	exclude='exempt from syntax-check'				\
	halt='use virStrToDouble, not strtod variants'			\
	  $(_sc_search_regexp)

# Use virAsprintf rather than as'printf since *strp is undefined on error.
# But for plain %s, virAsprintf is overkill compared to strdup.
sc_prohibit_asprintf:
	@prohibit='\<v?a[s]printf\>'					\
	halt='use virAsprintf, not asprintf'				\
	  $(_sc_search_regexp)
	@prohibit='virAsprintf.*, *"%s",'				\
	halt='use VIR_STRDUP instead of virAsprintf with "%s"'		\
	  $(_sc_search_regexp)

sc_prohibit_strdup:
	@prohibit='\<strn?dup\> *\('					\
	halt='use VIR_STRDUP, not strdup'				\
	  $(_sc_search_regexp)

# Prefer virSetUIDGID.
sc_prohibit_setuid:
	@prohibit='\<set(re)?[ug]id\> *\('				\
	halt='use virSetUIDGID, not raw set*id'				\
	  $(_sc_search_regexp)

# Don't compare *id_t against raw -1.
sc_prohibit_risky_id_promotion:
	@prohibit='\b(user|group|[ug]id) *[=!]= *-'			\
	halt='cast -1 to ([ug]id_t) before comparing against id'	\
	  $(_sc_search_regexp)

# Use snprintf rather than s'printf, even if buffer is provably large enough,
# since gnulib has more guarantees for snprintf portability
sc_prohibit_sprintf:
	@prohibit='\<[s]printf\>'					\
	halt='use snprintf, not sprintf'				\
	  $(_sc_search_regexp)

sc_prohibit_readlink:
	@prohibit='\<readlink *\('					\
	halt='use virFileResolveLink, not readlink'			\
	  $(_sc_search_regexp)

sc_prohibit_gethostname:
	@prohibit='gethostname *\('					\
	halt='use virGetHostname, not gethostname'			\
	  $(_sc_search_regexp)

sc_prohibit_readdir:
	@prohibit='\b(read|close|open)dir *\('				\
	exclude='exempt from syntax-check'				\
	halt='use virDirOpen, virDirRead and VIR_DIR_CLOSE'		\
	  $(_sc_search_regexp)

sc_prohibit_gettext_noop:
	@prohibit='gettext_noop *\('					\
	halt='use N_, not gettext_noop'					\
	  $(_sc_search_regexp)

sc_prohibit_VIR_ERR_NO_MEMORY:
	@prohibit='\<VIR_ERR_NO_MEMORY\>'				\
	halt='use virReportOOMError, not VIR_ERR_NO_MEMORY'		\
	  $(_sc_search_regexp)

sc_prohibit_PATH_MAX:
	@prohibit='\<PATH_MAX\>'				\
	halt='dynamically allocate paths, do not use PATH_MAX'	\
	  $(_sc_search_regexp)

include $(srcdir)/Makefile.nonreentrant
sc_prohibit_nonreentrant:
	@prohibit="\\<(${NON_REENTRANT_RE}) *\\("			\
	halt="use re-entrant functions (usually ending with _r)"	\
	  $(_sc_search_regexp)

sc_prohibit_select:
	@prohibit='\<select *\('					\
	halt='use poll(), not select()'					\
	  $(_sc_search_regexp)

# Prohibit the inclusion of <ctype.h>.
sc_prohibit_ctype_h:
	@prohibit='^# *include  *<ctype\.h>'				\
	halt='use c-ctype.h instead of ctype.h'				\
	  $(_sc_search_regexp)

# Insist on correct types for [pug]id.
sc_correct_id_types:
	@prohibit='\<(int|long) *[pug]id\>'				\
	halt='use pid_t for pid, uid_t for uid, gid_t for gid'		\
	  $(_sc_search_regexp)

# "const fooPtr a" is the same as "foo * const a", even though it is
# usually desired to have "foo const *a".  It's easier to just prevent
# the confusing mix of typedef vs. const placement.
# Also requires that all 'fooPtr' typedefs are actually pointers.
sc_forbid_const_pointer_typedef:
	@prohibit='(^|[^"])const \w*Ptr'				\
	halt='"const fooPtr var" does not declare what you meant'	\
	  $(_sc_search_regexp)
	@prohibit='typedef [^(]+ [^*]\w*Ptr\b'				\
	halt='use correct style and type for Ptr typedefs'		\
	  $(_sc_search_regexp)

# Forbid sizeof foo or sizeof (foo), require sizeof(foo)
sc_size_of_brackets:
	@prohibit='sizeof\s'						\
	halt='use sizeof(foo), not sizeof (foo) or sizeof foo'		\
	  $(_sc_search_regexp)

# Ensure that no C source file, docs, or rng schema uses TABs for
# indentation.  Also match *.h.in files, to get libvirt.h.in.  Exclude
# files in gnulib, since they're imported.
space_indent_files=(\.(rng|s?[ch](\.in)?|html.in|py|pl|syms)|(daemon|tools)/.*\.in)
sc_TAB_in_indentation:
	@prohibit='^ *	'						\
	in_vc_files='$(space_indent_files)$$'				\
	halt='indent with space, not TAB, in C, sh, html, py, syms and RNG schemas' \
	  $(_sc_search_regexp)

ctype_re = isalnum|isalpha|isascii|isblank|iscntrl|isdigit|isgraph|islower\
|isprint|ispunct|isspace|isupper|isxdigit|tolower|toupper

sc_avoid_ctype_macros:
	@prohibit='\b($(ctype_re)) *\('					\
	halt='use c-ctype.h instead of ctype macros'			\
	  $(_sc_search_regexp)

sc_avoid_strcase:
	@prohibit='\bstrn?case(cmp|str) *\('				\
	halt='use c-strcase.h instead of raw strcase functions'		\
	  $(_sc_search_regexp)

sc_prohibit_virBufferAdd_with_string_literal:
	@prohibit='\<virBufferAdd *\([^,]+, *"[^"]'			\
	halt='use virBufferAddLit, not virBufferAdd, with a string literal' \
	  $(_sc_search_regexp)

sc_prohibit_virBufferAsprintf_with_string_literal:
	@prohibit='\<virBufferAsprintf *\([^,]+, *"([^%"\]|\\.|%%)*"\)'		\
	halt='use virBufferAddLit, not virBufferAsprintf, with a string literal' \
	  $(_sc_search_regexp)

sc_forbid_manual_xml_indent:
	@prohibit='virBuffer.*" +<'					      \
	halt='use virBufferAdjustIndent instead of spaces when indenting xml' \
	  $(_sc_search_regexp)

# dirname and basename from <libgen.h> are not required to be thread-safe
sc_prohibit_libgen:
	@prohibit='( (base|dir)name *\(|include .libgen\.h)'		\
	halt='use functions from gnulib "dirname.h", not <libgen.h>'	\
	  $(_sc_search_regexp)

# raw xmlGetProp requires some nasty casts
sc_prohibit_xmlGetProp:
	@prohibit='\<xmlGetProp *\('					\
	halt='use virXMLPropString, not xmlGetProp'			\
	  $(_sc_search_regexp)

# xml(ParseURI|SaveUri) doesn't handle IPv6 URIs well
sc_prohibit_xmlURI:
	@prohibit='\<xml(ParseURI|SaveUri) *\('				\
	halt='use virURI(Parse|Format), not xml(ParseURI|SaveUri)'	\
	  $(_sc_search_regexp)

# we don't want old old-style return with parentheses around argument
sc_prohibit_return_as_function:
	@prohibit='\<return *\(([^()]*(\([^()]*\)[^()]*)*)\) *;'    \
	halt='avoid extra () with return statements'                \
	  $(_sc_search_regexp)

# ATTRIBUTE_UNUSED should only be applied in implementations, not
# header declarations
sc_avoid_attribute_unused_in_header:
	@prohibit='^[^#]*ATTRIBUTE_UNUSED([^:]|$$)'			\
	in_vc_files='\.h$$'						\
	halt='use ATTRIBUTE_UNUSED in .c rather than .h files'		\
	  $(_sc_search_regexp)

sc_prohibit_int_index:
	@prohibit='\<(int|unsigned)\s*\*?index\>(\s|,|;)'	\
	halt='use different name than 'index' for declaration'	        \
	  $(_sc_search_regexp)

sc_prohibit_int_ijk:
	@prohibit='\<(int|unsigned) ([^(=]* )*(i|j|k)\>(\s|,|;)'	\
	exclude='exempt from syntax-check'				\
	halt='use size_t, not int/unsigned int for loop vars i, j, k'	\
	  $(_sc_search_regexp)

sc_prohibit_loop_iijjkk:
	@prohibit='\<(int|unsigned) ([^=]+ )*(ii|jj|kk)\>(\s|,|;)'	\
	halt='use i, j, k for loop iterators, not ii, jj, kk'		\
	  $(_sc_search_regexp)

# RHEL 5 gcc can't grok "for (int i..."
sc_prohibit_loop_var_decl:
	@prohibit='\<for *\(\w+[ *]+\w+'				\
	in_vc_files='\.[ch]$$'						\
	halt='declare loop iterators outside the for statement'		\
	  $(_sc_search_regexp)

# Use 'bool', not 'int', when assigning true or false
sc_prohibit_int_assign_bool:
	@prohibit='\<int\>.*= *(true|false)'				\
	halt='use bool type for boolean values'				\
	  $(_sc_search_regexp)

sc_prohibit_unsigned_pid:
	@prohibit='\<unsigned\> [^,=;(]+pid'				\
	halt='use signed type for pid values'				\
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
msg_gen_function += xenapiSessionErrorHandler

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
	@prohibit='\<$(func_re) *\([^"]*"[^"]*[a-z]{3}'			\
	exclude='_\('							\
	halt='found unmarked diagnostic(s)'				\
	  $(_sc_search_regexp)
	@{ grep     -nE '\<$(func_re) *\(.*;$$' $$($(VC_LIST_EXCEPT));   \
	   grep -A1 -nE '\<$(func_re) *\(.*,$$' $$($(VC_LIST_EXCEPT)); } \
	   | $(SED) 's/_("\([^\"]\|\\.\)\+"//;s/[	 ]"%s"//'		\
	   | grep '[	 ]"' &&						\
	  { echo '$(ME): found unmarked diagnostic(s)' 1>&2;		\
	    exit 1; } || :

# Like the above, but prohibit a newline at the end of a diagnostic.
# This is subject to false positives partly because it naively looks for
# `\n"', which may not be the end of the string, and also because it takes
# two lines of context (the -A2) after the line with the function name.
# FIXME: this rule might benefit from a separate function list, in case
# there are functions to which this one applies but that do not get marked
# diagnostics.
sc_prohibit_newline_at_end_of_diagnostic:
	@grep -A2 -nE							\
	    '\<$(func_re) *\(' $$($(VC_LIST_EXCEPT))			\
	    | grep '\\n"'						\
	  && { echo '$(ME): newline at end of message(s)' 1>&2;		\
	    exit 1; } || :

# Look for diagnostics that lack a % in the format string, except that we
# allow VIR_ERROR to do this, and ignore functions that take a single
# string rather than a format argument.
sc_prohibit_diagnostic_without_format:
	@{ grep     -nE '\<$(func_re) *\(.*;$$' $$($(VC_LIST_EXCEPT));   \
	   grep -A2 -nE '\<$(func_re) *\(.*,$$' $$($(VC_LIST_EXCEPT)); } \
	   | $(SED) -rn -e ':l; /[,"]$$/ {N;b l;}'				 \
		-e '/(xenapiSessionErrorHandler|vah_(error|warning))/d'	 \
		-e '/\<$(func_re) *\([^"]*"([^%"]|"\n[^"]*")*"[,)]/p'	 \
           | grep -vE 'VIR_ERROR' &&					 \
	  { echo '$(ME): found diagnostic without %' 1>&2;		 \
	    exit 1; } || :

# The strings "" and "%s" should never be marked for translation.
# Files under tests/ and examples/ should not be translated.
sc_prohibit_useless_translation:
	@prohibit='_\("(%s)?"\)'					\
	halt='found useless translation'				\
	  $(_sc_search_regexp)
	@prohibit='\<N?_ *\('						\
	in_vc_files='^(tests|examples)/'				\
	halt='no translations in tests or examples'			\
	  $(_sc_search_regexp)

# When splitting a diagnostic across lines, ensure that there is a space
# or \n on one side of the split.
sc_require_whitespace_in_translation:
	@grep -n -A1 '"$$' $$($(VC_LIST_EXCEPT))   			\
	   | $(SED) -ne ':l; /"$$/ {N;b l;}; s/"\n[^"]*"/""/g; s/\\n/ /g'	\
		-e '/_(.*[^\ ]""[^\ ]/p' | grep . &&			\
	  { echo '$(ME): missing whitespace at line split' 1>&2;	\
	    exit 1; } || :

# Enforce recommended preprocessor indentation style.
sc_preprocessor_indentation:
	@if cppi --version >/dev/null 2>&1; then			\
	  $(VC_LIST_EXCEPT) | grep -E '\.[ch](\.in)?$$' | xargs cppi -a -c	\
	    || { echo '$(ME): incorrect preprocessor indentation' 1>&2;	\
		exit 1; };						\
	else								\
	  echo '$(ME): skipping test $@: cppi not installed' 1>&2;	\
	fi

# Enforce similar spec file indentation style, by running cppi on a
# (comment-only) C file that mirrors the same layout as the spec file.
sc_spec_indentation:
	@if cppi --version >/dev/null 2>&1; then			\
	  for f in $$($(VC_LIST_EXCEPT) | grep '\.spec\.in$$'); do	\
	    $(SED) -e 's|#|// #|; s|%ifn*\(arch\)* |#if a // |'		\
		-e 's/%\(else\|endif\|define\)/#\1/'			\
		-e 's/^\( *\)\1\1\1#/#\1/'				\
		-e 's|^\( *[^#/ ]\)|// \1|; s|^\( */[^/]\)|// \1|' $$f	\
	    | cppi -a -c 2>&1 | $(SED) "s|standard input|$$f|";		\
	  done | { if grep . >&2; then false; else :; fi; }		\
	    || { echo '$(ME): incorrect preprocessor indentation' 1>&2;	\
		exit 1; };						\
	else								\
	  echo '$(ME): skipping test $@: cppi not installed' 1>&2;	\
	fi

# Nested conditionals are easier to understand if we enforce that endifs
# can be paired back to the if
sc_makefile_conditionals:
	@prohibit='(else|endif)($$| *#)'				\
	in_vc_files='Makefile\.am'					\
	halt='match "if FOO" with "endif FOO" in Makefiles'		\
	  $(_sc_search_regexp)

# Long lines can be harder to diff; too long, and git send-email chokes.
# For now, only enforce line length on files where we have intentionally
# fixed things and don't want to regress.
sc_prohibit_long_lines:
	@prohibit='.{90}'						\
	in_vc_files='\.arg[sv]'						\
	halt='Wrap long lines in expected output files'			\
	  $(_sc_search_regexp)
	@prohibit='.{80}'						\
	in_vc_files='Makefile\.am'					\
	halt='Wrap long lines in Makefiles'				\
	  $(_sc_search_regexp)

sc_copyright_format:
	@require='Copyright .*Red 'Hat', Inc\.'				\
	containing='Copyright .*Red 'Hat				\
	halt='Red Hat copyright is missing Inc.'			\
	  $(_sc_search_regexp)
	@prohibit='Copyright [^(].*Red 'Hat				\
	halt='consistently use (C) in Red Hat copyright'		\
	  $(_sc_search_regexp)
	@prohibit='\<RedHat\>'						\
	halt='spell Red Hat as two words'				\
	  $(_sc_search_regexp)

# Prefer the new URL listing over the old street address listing when
# calling out where to get a copy of the [L]GPL.  Also, while we have
# to ship COPYING (GPL) alongside COPYING.LESSER (LGPL), we want any
# source file that calls out a top-level file to call out the LGPL
# version.  Note that our typical copyright boilerplate refers to the
# license by name, not by reference to a top-level file.
sc_copyright_usage:
	@prohibit=Boston,' MA'						\
	halt='Point to <http://www.gnu.org/licenses/>, not an address'	\
	  $(_sc_search_regexp)
	@require='COPYING\.LESSER'					\
	containing='COPYING'						\
	halt='Refer to COPYING.LESSER for LGPL'				\
	  $(_sc_search_regexp)
	@prohibit='COPYING\.LIB'					\
	halt='Refer to COPYING.LESSER for LGPL'				\
	  $(_sc_search_regexp)

# Some functions/macros produce messages intended solely for developers
# and maintainers.  Do not mark them for translation.
sc_prohibit_gettext_markup:
	@prohibit='\<VIR_(WARN|INFO|DEBUG) *\(_\('			\
	halt='do not mark these strings for translation'		\
	  $(_sc_search_regexp)

# Our code is divided into modular subdirectories for a reason, and
# lower-level code must not include higher-level headers.
cross_dirs=$(patsubst $(srcdir)/src/%.,%,$(wildcard $(srcdir)/src/*/.))
cross_dirs_re=($(subst / ,/|,$(cross_dirs)))
mid_dirs=access|conf|cpu|locking|logging|network|node_device|rpc|security|storage
sc_prohibit_cross_inclusion:
	@for dir in $(cross_dirs); do					\
	  case $$dir in							\
	    util/) safe="util";;					\
	    access/ | conf/) safe="($$dir|conf|util)";;			\
	    locking/) safe="($$dir|util|conf|rpc)";;			\
	    cpu/| network/| node_device/| rpc/| security/| storage/)	\
	      safe="($$dir|util|conf|storage)";;			\
	    xenapi/ | xenconfig/ ) safe="($$dir|util|conf|xen)";;	\
	    *) safe="($$dir|$(mid_dirs)|util)";;			\
	  esac;								\
	  in_vc_files="^src/$$dir"					\
	  prohibit='^# *include .$(cross_dirs_re)'			\
	  exclude="# *include .$$safe"					\
	  halt='unsafe cross-directory include'				\
	    $(_sc_search_regexp)					\
	done

# When converting an enum to a string, make sure that we track any new
# elements added to the enum by using a _LAST marker.
sc_require_enum_last_marker:
	@grep -A1 -nE '^[^#]*VIR_ENUM_IMPL *\(' $$($(VC_LIST_EXCEPT))	\
	   | $(SED) -ne '/VIR_ENUM_IMPL[^,]*,$$/N'				\
	     -e '/VIR_ENUM_IMPL[^,]*,[^,]*[^_,][^L,][^A,][^S,][^T,],/p'	\
	     -e '/VIR_ENUM_IMPL[^,]*,[^,]\{0,4\},/p'			\
	   | grep . &&							\
	  { echo '$(ME): enum impl needs to use _LAST marker' 1>&2;	\
	    exit 1; } || :

# In Python files we don't want to end lines with a semicolon like in C
sc_prohibit_semicolon_at_eol_in_python:
	@prohibit='^[^#].*\;$$'			                        \
	in_vc_files='\.py$$'						\
	halt='python does not require to end lines with a semicolon'	\
	  $(_sc_search_regexp)

# mymain() in test files should use return, not exit, for nicer output
sc_prohibit_exit_in_tests:
	@prohibit='\<exit *\('						\
	in_vc_files='^tests/'						\
	halt='use return, not exit(), in tests'				\
	  $(_sc_search_regexp)

# Don't include "libvirt/*.h" in "" form.
sc_prohibit_include_public_headers_quote:
	@prohibit='# *include *"libvirt/.*\.h"'				\
	in_vc_files='\.[ch]$$'						\
	halt='Do not include libvirt/*.h in internal source'		\
	  $(_sc_search_regexp)

# Don't include "libvirt/*.h" in <> form. Except for external tools,
# e.g. Python binding, examples and tools subdirectories.
sc_prohibit_include_public_headers_brackets:
	@prohibit='# *include *<libvirt/.*\.h>'				\
	in_vc_files='\.[ch]$$'						\
	halt='Do not include libvirt/*.h in internal source'		\
	  $(_sc_search_regexp)

# <config.h> is only needed in .c files; .h files do not need it since
# .c files must include config.h before any other .h.
sc_prohibit_config_h_in_headers:
	@prohibit='^# *include\>.*config\.h'				\
	in_vc_files='\.h$$'						\
	halt='headers should not include <config.h>'			\
	  $(_sc_search_regexp)

sc_prohibit_unbounded_arrays_in_rpc:
	@prohibit='<>'							\
	in_vc_files='\.x$$'						\
	halt='Arrays in XDR must have a upper limit set for <NNN>'	\
	  $(_sc_search_regexp)

sc_prohibit_getenv:
	@prohibit='\b(secure_)?getenv *\('				\
	exclude='exempt from syntax-check'				\
	halt='Use virGetEnv{Allow,Block}SUID instead of getenv'		\
	  $(_sc_search_regexp)

sc_prohibit_atoi:
	@prohibit='\bato(i|f|l|ll|q) *\('	\
	halt='Use virStrToLong* instead of atoi, atol, atof, atoq, atoll' \
	  $(_sc_search_regexp)

sc_prohibit_wrong_filename_in_comment:
	@fail=0;                                                       \
	awk 'BEGIN {                                                   \
	  fail=0;                                                      \
	} FNR < 3 {                                                    \
	  n=match($$0, /[[:space:]][^[:space:]]*[.][ch][[:space:]:]/); \
	  if (n > 0) {                                                 \
	    A=substr($$0, RSTART+1, RLENGTH-2);                        \
	    n=split(FILENAME, arr, "/");                               \
	    if (A != arr[n]) {                                         \
	      print "in " FILENAME ": " A " mentioned in comments ";   \
	      fail=1;                                                  \
	    }                                                          \
	  }                                                            \
	} END {                                                        \
	  if (fail == 1) {                                             \
	    exit 1;                                                    \
	  }                                                            \
	}' $$($(VC_LIST_EXCEPT) | grep '\.[ch]$$') || fail=1;          \
	if test $$fail -eq 1; then                                     \
	  { echo '$(ME): The file name in comments must match the'     \
	    'actual file name' 1>&2; exit 1; }	                       \
	fi;

sc_prohibit_virConnectOpen_in_virsh:
	@prohibit='\bvirConnectOpen[a-zA-Z]* *\('                      \
	in_vc_files='^tools/virsh-.*\.[ch]$$'                          \
	halt='Use vshConnect() in virsh instead of virConnectOpen*'    \
	  $(_sc_search_regexp)

sc_require_space_before_label:
	@prohibit='^(   ?)?[_a-zA-Z0-9]+:$$'                           \
	in_vc_files='\.[ch]$$'                                         \
	halt='Top-level labels should be indented by one space'        \
	  $(_sc_search_regexp)

# Allow for up to three spaces before the label: this is to avoid running
# into situations where neither this rule nor require_space_before_label
# would apply, eg. a line matching ^[a-zA-Z0-9]+ :$
sc_prohibit_space_in_label:
	@prohibit='^ {0,3}[_a-zA-Z0-9]+ +:$$'                          \
	in_vc_files='\.[ch]$$'                                         \
	halt='There should be no space between label name and colon'   \
	  $(_sc_search_regexp)

# Doesn't catch all cases of mismatched braces across if-else, but it helps
sc_require_if_else_matching_braces:
	@prohibit='(  else( if .*\))? {|} else( if .*\))?$$)'		\
	in_vc_files='\.[chx]$$'						\
	halt='if one side of if-else uses {}, both sides must use it'	\
	  $(_sc_search_regexp)

sc_curly_braces_style:
	@files=$$($(VC_LIST_EXCEPT) | grep '\.[ch]$$');			\
	if $(GREP) -nHP							\
'^\s*(?!([a-zA-Z_]*for_?each[a-zA-Z_]*) ?\()([_a-zA-Z0-9]+( [_a-zA-Z0-9]+)* ?\()?(\*?[_a-zA-Z0-9]+(,? \*?[_a-zA-Z0-9\[\]]+)+|void)\) ?\{'		\
	$$files; then							\
	  echo '$(ME): Non-K&R style used for curly braces around'	\
		'function body, see HACKING' 1>&2; exit 1;		\
	fi;								\
	if $(GREP) -A1 -En ' ((if|for|while|switch) \(|(else|do)\b)[^{]*$$'\
	  $$files | $(GREP) '^[^ ]*- *{'; then				\
	  echo '$(ME): Use hanging braces for compound statements,'	\
		'see HACKING' 1>&2; exit 1;				\
	fi

sc_prohibit_windows_special_chars_in_filename:
	@files=$$($(VC_LIST_EXCEPT) | grep '[:*?"<>|]');               \
	test -n "$$files" && { echo '$(ME): Windows special chars'     \
	  'in filename not allowed:' 1>&2; echo $$files 1>&2; exit 1; } || :

sc_prohibit_mixed_case_abbreviations:
	@prohibit='Pci|Usb|Scsi'			\
	in_vc_files='\.[ch]$$'				\
	halt='Use PCI, USB, SCSI, not Pci, Usb, Scsi'	\
	  $(_sc_search_regexp)

# Require #include <locale.h> in all files that call setlocale()
sc_require_locale_h:
	@require='include.*locale\.h'					\
	containing='setlocale *('					\
	halt='setlocale() requires <locale.h>'				\
	  $(_sc_search_regexp)

sc_prohibit_empty_first_line:
	@awk 'BEGIN { fail=0; }						\
	FNR == 1 { if ($$0 == "") { print FILENAME ":1:"; fail=1; } }	\
	END { if (fail == 1) {						\
	  print "$(ME): Prohibited empty first line" > "/dev/stderr";	\
	} exit fail; }' $$($(VC_LIST_EXCEPT));

sc_prohibit_paren_brace:
	@prohibit='\)\{$$'						\
	in_vc_files='\.[chx]$$'						\
	halt='Put space between closing parenthesis and opening brace'	\
	  $(_sc_search_regexp)

# C guarantees that static variables are zero initialized, and some compilers
# waste space by sticking explicit initializers in .data instead of .bss
sc_prohibit_static_zero_init:
	@prohibit='\bstatic\b.*= *(0[^xX0-9]|NULL|false)'		\
	in_vc_files='\.[chx](\.in)?$$'					\
	halt='static variables do not need explicit zero initialization'\
	  $(_sc_search_regexp)

# FreeBSD exports the "devname" symbol which produces a warning.
sc_prohibit_devname:
	@prohibit='\bdevname\b'	\
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
	@prohibit='\bvir(Domain|Network|NodeDevice|StorageVol|StoragePool|Stream|Secret|NWFilter|Interface|DomainSnapshot)Free\b'	\
	exclude='sc_prohibit_virXXXFree' \
	halt='avoid using virXXXFree, use virObjectUnref instead' \
	  $(_sc_search_regexp)

sc_prohibit_sysconf_pagesize:
	@prohibit='sysconf\(_SC_PAGESIZE' \
	halt='use virGetSystemPageSize[KB] instead of sysconf(_SC_PAGESIZE)' \
	  $(_sc_search_regexp)

sc_prohibit_virSecurity:
	@grep -Pn 'virSecurityManager(?!Ptr)' $$($(VC_LIST_EXCEPT) | grep '^src/qemu/' | \
		grep -v '^src/qemu/qemu_security') && \
		{ echo '$(ME): prefer qemuSecurity wrappers' 1>&2; exit 1; } || :

sc_prohibit_pthread_create:
	@prohibit='\bpthread_create\b' \
	exclude='sc_prohibit_pthread_create' \
	halt='avoid using pthread_create, use virThreadCreate instead' \
	  $(_sc_search_regexp)

sc_prohibit_not_streq:
	@prohibit='! *STRN?EQ *\(.*\)'		\
	halt='Use STRNEQ instead of !STREQ and STREQ instead of !STRNEQ'	\
	  $(_sc_search_regexp)

sc_prohibit_verbose_strcat:
	@prohibit='strncat\([^,]*,\s+([^,]*),\s+strlen\(\1\)\)'     \
	in_vc_files='\.[ch]$$'                                      \
	halt='Use strcat(a, b) instead of strncat(a, b, strlen(b))' \
	  $(_sc_search_regexp)

# Ensure that each .c file containing a "main" function also
# calls virGettextInitialize
sc_gettext_init:
	@require='virGettextInitialize *\('					\
	in_vc_files='\.c$$'						\
	containing='\<main *('						\
	halt='the above files do not call virGettextInitialize'		\
	  $(_sc_search_regexp)

# We don't use this feature of maint.mk.
prev_version_file = /dev/null

ifneq ($(_gl-Makefile),)
ifeq (0,$(MAKELEVEL))
  _curr_status = .git-module-status
  # The sed filter accommodates those who check out on a commit from which
  # no tag is reachable.  In that case, git submodule status prints a "-"
  # in column 1 and does not print a "git describe"-style string after the
  # submodule name.  Contrast these:
  # -b653eda3ac4864de205419d9f41eec267cb89eeb .gnulib
  #  b653eda3ac4864de205419d9f41eec267cb89eeb .gnulib (v0.0-2286-gb653eda)
  # $ cat .git-module-status
  # b653eda3ac4864de205419d9f41eec267cb89eeb
  #
  # Keep this logic in sync with autogen.sh.
  _submodule_hash = $(SED) 's/^[ +-]//;s/ .*//'
  _update_required := $(shell						\
      cd '$(srcdir)';							\
      test -d .git || { echo 0; exit; };				\
      test -f po/Makevars || { echo 1; exit; };				\
      test -f AUTHORS || { echo 1; exit; };				\
      test "no-git" = "$$(cat $(_curr_status))" && { echo 0; exit; };	\
      actual=$$(git submodule status | $(_submodule_hash);		\
		git hash-object bootstrap.conf;				\
		git ls-tree -d HEAD gnulib/local | awk '{print $$3}';	\
		git diff .gnulib);					\
      stamp="$$($(_submodule_hash) $(_curr_status) 2>/dev/null)";	\
      test "$$stamp" = "$$actual"; echo $$?)
  _clean_requested = $(filter %clean,$(MAKECMDGOALS))
  ifeq (1,$(_update_required)$(_clean_requested))
    $(info INFO: gnulib update required; running ./autogen.sh first)
    $(shell touch $(srcdir)/AUTHORS $(srcdir)/ChangeLog)
maint.mk Makefile: _autogen
  endif
endif
endif

# It is necessary to call autogen any time gnulib changes.  Autogen
# reruns configure, then we regenerate all Makefiles at once.
.PHONY: _autogen
_autogen:
	$(srcdir)/autogen.sh
	./config.status

# regenerate HACKING as part of the syntax-check
ifneq ($(_gl-Makefile),)
syntax-check: $(top_srcdir)/HACKING spacing-check test-wrap-argv \
	prohibit-duplicate-header
endif

# Don't include duplicate header in the source (either *.c or *.h)
prohibit-duplicate-header:
	$(AM_V_GEN)files=$$($(VC_LIST_EXCEPT) | grep '\.[chx]$$'); \
	$(PERL) -W $(top_srcdir)/build-aux/prohibit-duplicate-header.pl $$files

spacing-check:
	$(AM_V_GEN)files=`$(VC_LIST) | grep '\.c$$'`; \
	$(PERL) $(top_srcdir)/build-aux/check-spacing.pl $$files || \
	  { echo '$(ME): incorrect formatting, see HACKING for rules' 1>&2; \
	    exit 1; }

test-wrap-argv:
	$(AM_V_GEN)files=`$(VC_LIST) | grep -E '\.(ldargs|args)'`; \
	$(PERL) $(top_srcdir)/tests/test-wrap-argv.pl --check $$files

# sc_po_check can fail if generated files are not built first
sc_po_check: \
		$(srcdir)/daemon/remote_dispatch.h \
		$(srcdir)/daemon/qemu_dispatch.h \
		$(srcdir)/src/remote/remote_client_bodies.h \
		$(srcdir)/daemon/admin_dispatch.h \
		$(srcdir)/src/admin/admin_client.h
$(srcdir)/daemon/remote_dispatch.h: $(srcdir)/src/remote/remote_protocol.x
	$(MAKE) -C daemon remote_dispatch.h
$(srcdir)/daemon/qemu_dispatch.h: $(srcdir)/src/remote/qemu_protocol.x
	$(MAKE) -C daemon qemu_dispatch.h
$(srcdir)/src/remote/remote_client_bodies.h: $(srcdir)/src/remote/remote_protocol.x
	$(MAKE) -C src remote/remote_client_bodies.h
$(srcdir)/daemon/admin_dispatch.h: $(srcdir)/src/admin/admin_protocol.x
	$(MAKE) -C daemon admin_dispatch.h
$(srcdir)/src/admin/admin_client.h: $(srcdir)/src/admin/admin_protocol.x
	$(MAKE) -C src admin/admin_client.h

# List all syntax-check exemptions:
exclude_file_name_regexp--sc_avoid_strcase = ^tools/vsh\.h$$

_src1=libvirt-stream|qemu/qemu_monitor|util/vir(command|file|fdstream)|xen/xend_internal|rpc/virnetsocket|lxc/lxc_controller|locking/lock_daemon|logging/log_daemon
_test1=shunloadtest|virnettlscontexttest|virnettlssessiontest|vircgroupmock
exclude_file_name_regexp--sc_avoid_write = \
  ^(src/($(_src1))|daemon/libvirtd|tools/virsh-console|tests/($(_test1)))\.c$$

exclude_file_name_regexp--sc_bindtextdomain = .*

exclude_file_name_regexp--sc_gettext_init = ^(tests|examples)/

exclude_file_name_regexp--sc_copyright_format = \
	^cfg\.mk$$

exclude_file_name_regexp--sc_copyright_usage = \
  ^COPYING(|\.LESSER)$$

exclude_file_name_regexp--sc_flags_usage = \
  ^(cfg\.mk|docs/|src/util/virnetdevtap\.c$$|tests/(vir(cgroup|pci|test|usb)|nss|qemuxml2argv)mock\.c$$)

exclude_file_name_regexp--sc_libvirt_unmarked_diagnostics = \
  ^(src/rpc/gendispatch\.pl$$|tests/)

exclude_file_name_regexp--sc_po_check = ^(docs/|src/rpc/gendispatch\.pl$$)

exclude_file_name_regexp--sc_prohibit_VIR_ERR_NO_MEMORY = \
  ^(cfg\.mk|include/libvirt/virterror\.h|daemon/dispatch\.c|src/util/virerror\.c|docs/internals/oomtesting\.html\.in)$$

exclude_file_name_regexp--sc_prohibit_PATH_MAX = \
	^cfg\.mk$$

exclude_file_name_regexp--sc_prohibit_access_xok = \
	^(cfg\.mk|src/util/virutil\.c)$$

exclude_file_name_regexp--sc_prohibit_asprintf = \
  ^(cfg\.mk|bootstrap.conf$$|examples/|src/util/virstring\.[ch]$$|tests/vircgroupmock\.c$$)

exclude_file_name_regexp--sc_prohibit_strdup = \
  ^(docs/|examples/|src/util/virstring\.c|tests/vir(netserverclient|cgroup)mock.c$$)

exclude_file_name_regexp--sc_prohibit_close = \
  (\.p[yl]$$|\.spec\.in$$|^docs/|^(src/util/virfile\.c|src/libvirt-stream\.c|tests/vir.+mock\.c)$$)

exclude_file_name_regexp--sc_prohibit_empty_lines_at_EOF = \
  (^tests/(qemuhelp|virhostcpu|virpcitest)data/|docs/js/.*\.js|docs/fonts/.*\.woff|\.diff|tests/virconfdata/no-newline\.conf$$)

_src2=src/(util/vircommand|libvirt|lxc/lxc_controller|locking/lock_daemon|logging/log_daemon)
exclude_file_name_regexp--sc_prohibit_fork_wrappers = \
  (^($(_src2)|tests/testutils|daemon/libvirtd)\.c$$)

exclude_file_name_regexp--sc_prohibit_gethostname = ^src/util/virutil\.c$$

exclude_file_name_regexp--sc_prohibit_internal_functions = \
  ^src/(util/(viralloc|virutil|virfile)\.[hc]|esx/esx_vi\.c)$$

exclude_file_name_regexp--sc_prohibit_newline_at_end_of_diagnostic = \
  ^src/rpc/gendispatch\.pl$$

exclude_file_name_regexp--sc_prohibit_nonreentrant = \
  ^((po|tests)/|docs/.*(py|js|html\.in)|run.in$$|tools/wireshark/util/genxdrstub\.pl$$)

exclude_file_name_regexp--sc_prohibit_select = \
	^cfg\.mk$$

exclude_file_name_regexp--sc_prohibit_raw_allocation = \
  ^(docs/hacking\.html\.in|src/util/viralloc\.[ch]|examples/.*|tests/(securityselinuxhelper|(vircgroup|nss)mock)\.c|tools/wireshark/src/packet-libvirt\.c)$$

exclude_file_name_regexp--sc_prohibit_readlink = \
  ^src/(util/virutil|lxc/lxc_container)\.c$$

exclude_file_name_regexp--sc_prohibit_setuid = ^src/util/virutil\.c$$

exclude_file_name_regexp--sc_prohibit_sprintf = \
  ^(cfg\.mk|docs/hacking\.html\.in|.*\.stp|.*\.pl)$$

exclude_file_name_regexp--sc_prohibit_strncpy = ^src/util/virstring\.c$$

exclude_file_name_regexp--sc_prohibit_strtol = ^examples/.*$$

exclude_file_name_regexp--sc_prohibit_xmlGetProp = ^src/util/virxml\.c$$

exclude_file_name_regexp--sc_prohibit_xmlURI = ^src/util/viruri\.c$$

exclude_file_name_regexp--sc_prohibit_return_as_function = \.py$$

exclude_file_name_regexp--sc_require_config_h = \
	^(examples/|tools/virsh-edit\.c$$)

exclude_file_name_regexp--sc_require_config_h_first = \
	^(examples/|tools/virsh-edit\.c$$)

exclude_file_name_regexp--sc_trailing_blank = \
  /qemuhelpdata/|/sysinfodata/.*\.data|/virhostcpudata/.*\.cpuinfo$$

exclude_file_name_regexp--sc_unmarked_diagnostics = \
  ^(docs/apibuild.py|tests/virt-aa-helper-test|docs/js/.*\.js)$$

exclude_file_name_regexp--sc_size_of_brackets = cfg.mk

exclude_file_name_regexp--sc_correct_id_types = \
  (^src/locking/lock_protocol.x$$)

exclude_file_name_regexp--sc_m4_quote_check = m4/virt-lib.m4

exclude_file_name_regexp--sc_prohibit_include_public_headers_quote = \
  ^(src/internal\.h$$|tools/wireshark/src/packet-libvirt.h$$)

exclude_file_name_regexp--sc_prohibit_include_public_headers_brackets = \
  ^(tools/|examples/|include/libvirt/(virterror|libvirt(-(admin|qemu|lxc))?)\.h$$)

exclude_file_name_regexp--sc_prohibit_int_ijk = \
  ^(src/remote_protocol-structs|src/remote/remote_protocol\.x|cfg\.mk|include/libvirt/libvirt.+|src/admin_protocol-structs|src/admin/admin_protocol\.x)$$

exclude_file_name_regexp--sc_prohibit_unsigned_pid = \
  ^(include/libvirt/.*\.h|src/(qemu/qemu_driver\.c|driver-hypervisor\.h|libvirt(-[a-z]*)?\.c|.*\.x|util/vir(polkit|systemd)\.c)|tests/virpolkittest\.c|tools/virsh-domain\.c)$$

exclude_file_name_regexp--sc_prohibit_getenv = \
  ^tests/.*\.[ch]$$

exclude_file_name_regexp--sc_avoid_attribute_unused_in_header = \
  ^(src/util/virlog\.h|src/network/bridge_driver\.h)$$

exclude_file_name_regexp--sc_prohibit_mixed_case_abbreviations = \
  ^src/(vbox/vbox_CAPI.*.h|esx/esx_vi.(c|h)|esx/esx_storage_backend_iscsi.c)$$

exclude_file_name_regexp--sc_prohibit_empty_first_line = \
  ^(README|daemon/THREADS\.txt|src/esx/README|tests/(vmwarever|virhostcpu)data/.*)$$

exclude_file_name_regexp--sc_prohibit_useless_translation = \
  ^tests/virpolkittest.c

exclude_file_name_regexp--sc_prohibit_devname = \
  ^(tools/virsh.pod|cfg.mk|docs/.*)$$

exclude_file_name_regexp--sc_prohibit_virXXXFree = \
  ^(docs/|tests/|examples/|tools/|cfg.mk|src/test/test_driver.c|src/libvirt_public.syms|include/libvirt/libvirt-(domain|network|nodedev|storage|stream|secret|nwfilter|interface|domain-snapshot).h|src/libvirt-(domain|qemu|network|nodedev|storage|stream|secret|nwfilter|interface|domain-snapshot).c$$)

exclude_file_name_regexp--sc_prohibit_sysconf_pagesize = \
  ^(cfg\.mk|src/util/virutil\.c)$$

exclude_file_name_regexp--sc_prohibit_pthread_create = \
  ^(cfg\.mk|src/util/virthread\.c|tests/.*)$$

exclude_file_name_regexp--sc_prohibit_always-defined_macros = \
  ^tests/virtestmock.c$$

exclude_file_name_regexp--sc_prohibit_readdir = \
  ^tests/.*mock\.c$$

exclude_file_name_regexp--sc_prohibit_cross_inclusion = \
  ^(src/util/virclosecallbacks\.h|src/util/virhostdev\.h)$$
