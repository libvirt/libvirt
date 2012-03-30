# Customize Makefile.maint.                           -*- makefile -*-
# Copyright (C) 2008-2012 Red Hat, Inc.
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
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

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
  $(srcdir)/src/remote/*_client_bodies.h \
  $(srcdir)/src/remote/*_protocol.[ch] \
  $(srcdir)/gnulib/lib/*.[ch]

# We haven't converted all scripts to using gnulib's init.sh yet.
_test_script_regex = \<\(init\|test-lib\)\.sh\>

# Tests not to run as part of "make distcheck".
local-checks-to-skip =			\
  changelog-check			\
  check-AUTHORS				\
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

# Files that should never cause syntax check failures.
VC_LIST_ALWAYS_EXCLUDE_REGEX = \
  (^(HACKING|docs/(news\.html\.in|.*\.patch))|\.po)$$

# Functions like free() that are no-ops on NULL arguments.
useless_free_options =				\
  --name=VIR_FREE				\
  --name=qemuCapsFree				\
  --name=qemuMigrationCookieFree                \
  --name=qemuMigrationCookieGraphicsFree        \
  --name=sexpr_free				\
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
  --name=virDomainEventFree			\
  --name=virDomainEventQueueFree		\
  --name=virDomainEventStateFree		\
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
  --name=virNetClientFree                       \
  --name=virNetClientProgramFree                \
  --name=virNetClientStreamFree                 \
  --name=virNetServerFree                       \
  --name=virNetServerClientFree                 \
  --name=virNetServerMDNSFree                   \
  --name=virNetServerMDNSEntryFree              \
  --name=virNetServerMDNSGroupFree              \
  --name=virNetServerProgramFree                \
  --name=virNetServerServiceFree                \
  --name=virNetSocketFree                       \
  --name=virNetSASLContextFree                  \
  --name=virNetSASLSessionFree                  \
  --name=virNetTLSSessionFree                   \
  --name=virNWFilterDefFree			\
  --name=virNWFilterEntryFree			\
  --name=virNWFilterHashTableFree		\
  --name=virNWFilterIPAddrLearnReqFree		\
  --name=virNWFilterIncludeDefFree		\
  --name=virNWFilterObjFree			\
  --name=virNWFilterRuleDefFree			\
  --name=virNWFilterRuleInstFree		\
  --name=virNetworkDefFree			\
  --name=virNetworkObjFree			\
  --name=virNodeDeviceDefFree			\
  --name=virNodeDeviceObjFree			\
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
# y virDomainEventFree
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
# y virNetworkObjFree
# n virNetworkObjListFree FIXME
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
	@test "$$(cat $(srcdir)/include/libvirt/libvirt.h.in		\
	    $(srcdir)/include/libvirt/virterror.h			\
	    $(srcdir)/include/libvirt/libvirt-qemu.h			\
	  | grep -c '\(long\|unsigned\) flags')" != 4 &&		\
	  { echo '$(ME): new API should use "unsigned int flags"' 1>&2;	\
	    exit 1; } || :
	@prohibit=' flags ''ATTRIBUTE_UNUSED'				\
	halt='flags should be checked with virCheckFlags'		\
	  $(_sc_search_regexp)
	@prohibit='^[^@]*([^d] (int|long long)|[^dg] long) flags[;,)]'	\
	halt='flags should be unsigned'					\
	  $(_sc_search_regexp)

# Avoid functions that should only be called via macro counterparts.
sc_prohibit_internal_functions:
	@prohibit='vir(Free|AllocN?|ReallocN|File(Close|Fclose|Fdopen)) *\(' \
	halt='use VIR_ macros instead of internal functions'		\
	  $(_sc_search_regexp)

# Avoid raw malloc and free, except in documentation comments.
sc_prohibit_raw_allocation:
	@prohibit='^.[^*].*\<((m|c|re)alloc|free) *\([^)]'		\
	halt='use VIR_ macros from memory.h instead of malloc/free'	\
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

# access with X_OK accepts directories, but we can't exec() those.
# access with F_OK or R_OK is okay, though.
sc_prohibit_access_xok:
	@prohibit='access''(at)? *\(.*X_OK'				\
	halt='use virFileIsExecutable instead of access''(,X_OK)'	\
	  $(_sc_search_regexp)

# Similar to the gnulib maint.mk rule for sc_prohibit_strcmp
# Use STREQLEN or STRPREFIX rather than comparing strncmp == 0, or != 0.
snp_ = strncmp *\(.+\)
sc_prohibit_strncmp:
	@prohibit='! *strncmp *\(|\<$(snp_) *[!=]=|[!=]= *$(snp_)'	\
	exclude=':# *define STR(N?EQLEN|PREFIX)\('			\
	halt='$(ME): use STREQLEN or STRPREFIX instead of str''ncmp'	\
	  $(_sc_search_regexp)

# Use virAsprintf rather than as'printf since *strp is undefined on error.
sc_prohibit_asprintf:
	@prohibit='\<v?a[s]printf\>'					\
	halt='use virAsprintf, not as'printf				\
	  $(_sc_search_regexp)

# Prefer virSetUIDGID.
sc_prohibit_setuid:
	@prohibit='\<set(re)?[ug]id\> *\('				\
	halt='use virSetUIDGID, not raw set*id'				\
	  $(_sc_search_regexp)

# Use snprintf rather than s'printf, even if buffer is provably large enough,
# since gnulib has more guarantees for snprintf portability
sc_prohibit_sprintf:
	@prohibit='\<[s]printf\>'					\
	halt='use snprintf, not s'printf				\
	  $(_sc_search_regexp)

sc_prohibit_strncpy:
	@prohibit='strncpy *\('						\
	halt='use virStrncpy, not strncpy'				\
	  $(_sc_search_regexp)

sc_prohibit_readlink:
	@prohibit='readlink *\('					\
	halt='use virFileResolveLink, not readlink'			\
	  $(_sc_search_regexp)

sc_prohibit_gethostname:
	@prohibit='gethostname *\('					\
	halt='use virGetHostname, not gethostname'			\
	  $(_sc_search_regexp)

sc_prohibit_gettext_noop:
	@prohibit='gettext_noop *\('					\
	halt='use N_, not gettext_noop'					\
	  $(_sc_search_regexp)

sc_prohibit_VIR_ERR_NO_MEMORY:
	@prohibit='\<V''IR_ERR_NO_MEMORY\>'				\
	halt='use virReportOOMError, not V'IR_ERR_NO_MEMORY		\
	  $(_sc_search_regexp)

# Use a subshell for each function, to give the optimal warning message.
include $(srcdir)/Makefile.nonreentrant
sc_prohibit_nonreentrant:
	@fail=0 ; \
	for i in $(NON_REENTRANT) ; \
	do \
	    (prohibit="\\<$$i *\\("					\
	     halt="use $${i}_r, not $$i"				\
	     $(_sc_search_regexp)					\
	    ) || fail=1;						\
	done ; \
	exit $$fail

# Prohibit the inclusion of <ctype.h>.
sc_prohibit_ctype_h:
	@prohibit='^# *include  *<ctype\.h>'				\
	halt="don't use ctype.h; instead, use c-ctype.h"		\
	  $(_sc_search_regexp)

# Insist on correct types for [pug]id.
sc_correct_id_types:
	@prohibit='\<(int|long) *[pug]id\>'				\
	halt="use pid_t for pid, uid_t for uid, gid_t for gid"		\
	  $(_sc_search_regexp)

# Forbid sizeof foo or sizeof (foo), require sizeof(foo)
sc_size_of_brackets:
	@prohibit='sizeof\s'						\
	halt='use sizeof(foo), not sizeof (foo) or sizeof foo'		\
	  $(_sc_search_regexp)

# Ensure that no C source file, docs, or rng schema uses TABs for
# indentation.  Also match *.h.in files, to get libvirt.h.in.  Exclude
# files in gnulib, since they're imported.
space_indent_files=(\.(rng|s?[ch](\.in)?|html.in|py|syms)|(daemon|tools)/.*\.in)
sc_TAB_in_indentation:
	@prohibit='^ *	'						\
	in_vc_files='$(space_indent_files)$$'				\
	halt='indent with space, not TAB, in C, sh, html, py, syms and RNG schemas' \
	  $(_sc_search_regexp)

ctype_re = isalnum|isalpha|isascii|isblank|iscntrl|isdigit|isgraph|islower\
|isprint|ispunct|isspace|isupper|isxdigit|tolower|toupper

sc_avoid_ctype_macros:
	@prohibit='\b($(ctype_re)) *\('					\
	halt="don't use ctype macros (use c-ctype.h)"			\
	  $(_sc_search_regexp)

sc_avoid_strcase:
	@prohibit='\bstrn?case(cmp|str) *\('				\
	halt="don't use raw strcase functions (use c-strcase instead)"	\
	  $(_sc_search_regexp)

sc_prohibit_virBufferAdd_with_string_literal:
	@prohibit='\<virBufferAdd *\([^,]+, *"[^"]'			\
	halt='use virBufferAddLit, not virBufferAdd, with a string literal' \
	  $(_sc_search_regexp)

# Not only do they fail to deal well with ipv6, but the gethostby*
# functions are also not thread-safe.
sc_prohibit_gethostby:
	@prohibit='\<gethostby(addr|name2?) *\('			\
	halt='use getaddrinfo, not gethostby*'				\
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

# Many of the function names below came from this filter:
# git grep -B2 '\<_('|grep -E '\.c- *[[:alpha:]_][[:alnum:]_]* ?\(.*[,;]$' \
# |sed 's/.*\.c-  *//'|perl -pe 's/ ?\(.*//'|sort -u \
# |grep -vE '^(qsort|if|close|assert|fputc|free|N_|vir.*GetName|.*Unlock|virNodeListDevices|virHashRemoveEntry|freeaddrinfo|.*[fF]ree|xdrmem_create|xmlXPathFreeObject|virUUIDFormat|openvzSetProgramSentinal|polkit_action_unref)$'

msg_gen_function =
msg_gen_function += ESX_ERROR
msg_gen_function += ESX_VI_ERROR
msg_gen_function += HYPERV_ERROR
msg_gen_function += PHYP_ERROR
msg_gen_function += VIR_ERROR
msg_gen_function += VMX_ERROR
msg_gen_function += XENXS_ERROR
msg_gen_function += eventReportError
msg_gen_function += ifaceError
msg_gen_function += interfaceReportError
msg_gen_function += iptablesError
msg_gen_function += lxcError
msg_gen_function += libxlError
msg_gen_function += macvtapError
msg_gen_function += networkReportError
msg_gen_function += nodeReportError
msg_gen_function += openvzError
msg_gen_function += pciReportError
msg_gen_function += qemuReportError
msg_gen_function += qemudDispatchClientFailure
msg_gen_function += regerror
msg_gen_function += remoteError
msg_gen_function += remoteDispatchFormatError
msg_gen_function += statsError
msg_gen_function += streamsReportError
msg_gen_function += usbReportError
msg_gen_function += umlReportError
msg_gen_function += vah_error
msg_gen_function += vah_warning
msg_gen_function += vboxError
msg_gen_function += virCommandError
msg_gen_function += virConfError
msg_gen_function += virCPUReportError
msg_gen_function += virEventError
msg_gen_function += virDomainReportError
msg_gen_function += virGenericReportError
msg_gen_function += virHashError
msg_gen_function += virHookReportError
msg_gen_function += virInterfaceReportError
msg_gen_function += virJSONError
msg_gen_function += virLibConnError
msg_gen_function += virLibDomainError
msg_gen_function += virLibDomainSnapshotError
msg_gen_function += virLibInterfaceError
msg_gen_function += virLibNetworkError
msg_gen_function += virLibNodeDeviceError
msg_gen_function += virLibNWFilterError
msg_gen_function += virLibSecretError
msg_gen_function += virLibStoragePoolError
msg_gen_function += virLibStorageVolError
msg_gen_function += virNetworkReportError
msg_gen_function += virNodeDeviceReportError
msg_gen_function += virNWFilterReportError
msg_gen_function += virRaiseError
msg_gen_function += virReportErrorHelper
msg_gen_function += virReportSystemError
msg_gen_function += virSecretReportError
msg_gen_function += virSecurityReportError
msg_gen_function += virSexprError
msg_gen_function += virSmbiosReportError
msg_gen_function += virSocketError
msg_gen_function += virStatsError
msg_gen_function += virStorageReportError
msg_gen_function += virUtilError
msg_gen_function += virXMLError
msg_gen_function += virXenInotifyError
msg_gen_function += virXenStoreError
msg_gen_function += virXendError
msg_gen_function += vmwareError
msg_gen_function += xenapiSessionErrorHandler
msg_gen_function += xenUnifiedError
msg_gen_function += xenXMError

# Uncomment the following and run "make syntax-check" to see diagnostics
# that are not yet marked for translation, but that need to be rewritten
# so that they are translatable.
# msg_gen_function += fprintf
# msg_gen_function += testError
# msg_gen_function += virXenError
# msg_gen_function += vshPrint
# msg_gen_function += vshError

func_or := $(shell printf '$(msg_gen_function)'|tr -s '[[:space:]]' '|')
func_re := ($(func_or))

# Look for diagnostics that aren't marked for translation.
# This won't find any for which error's format string is on a separate line.
# The sed filters eliminate false-positives like these:
#    _("...: "
#    "%s", _("no storage vol w..."
sc_libvirt_unmarked_diagnostics:
	@prohibit='\<$(func_re) *\([^"]*"[^"]*[a-z]{3}'			\
	exclude='_\('							\
	halt='$(ME): found unmarked diagnostic(s)'			\
	  $(_sc_search_regexp)
	@{ grep     -nE '\<$(func_re) *\(.*;$$' $$($(VC_LIST_EXCEPT));   \
	   grep -A1 -nE '\<$(func_re) *\(.*,$$' $$($(VC_LIST_EXCEPT)); } \
	   | sed 's/_("[^"][^"]*"//;s/[	 ]"%s"//'			\
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

# Enforce recommended preprocessor indentation style.
sc_preprocessor_indentation:
	@if cppi --version >/dev/null 2>&1; then			\
	  $(VC_LIST_EXCEPT) | grep '\.[ch]$$' | xargs cppi -a -c	\
	    || { echo '$(ME): incorrect preprocessor indentation' 1>&2;	\
		exit 1; };						\
	else								\
	  echo '$(ME): skipping test $@: cppi not installed' 1>&2;	\
	fi

sc_copyright_format:
	@require='Copyright .*Red 'Hat', Inc\.'				\
	containing='Copyright .*Red 'Hat				\
	halt='Red Hat copyright is missing Inc.'			\
	  $(_sc_search_regexp)
	@prohibit='Copyright [^(].*Red 'Hat				\
	halt='consistently use (C) in Red Hat copyright'		\
	  $(_sc_search_regexp)
	@prohibit='\<Red''Hat\>'					\
	halt='spell Red Hat as two words'				\
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
sc_prohibit_cross_inclusion:
	@for dir in $(cross_dirs); do					\
	  case $$dir in							\
	    util/) safe="util";;					\
	    cpu/ | locking/ | network/ | rpc/ | security/)		\
	      safe="($$dir|util|conf)";;				\
	    xenapi/ | xenxs/ ) safe="($$dir|util|conf|xen)";;		\
	    *) safe="($$dir|util|conf|cpu|network|locking|rpc|security)";; \
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
	   | sed -ne '/VIR_ENUM_IMPL[^,]*,$$/N'				\
	     -e '/VIR_ENUM_IMPL[^,]*,[^,]*[^_,][^L,][^A,][^S,][^T,],/p'	\
	     -e '/VIR_ENUM_IMPL[^,]*,[^,]\{0,4\},/p'			\
	   | grep . &&							\
	  { echo '$(ME): enum impl needs to use _LAST marker' 1>&2;	\
	    exit 1; } || :

# We don't use this feature of maint.mk.
prev_version_file = /dev/null

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
  _submodule_hash = sed 's/^[ +-]//;s/ .*//'
  _update_required := $(shell						\
      cd '$(srcdir)';							\
      test -d .git || { echo 0; exit; };				\
      test -f po/Makevars || { echo 1; exit; };				\
      actual=$$(git submodule status | $(_submodule_hash);		\
		git hash-object bootstrap.conf;				\
		git ls-tree -d HEAD gnulib/local | awk '{print $$3}';	\
		git diff .gnulib);					\
      stamp="$$($(_submodule_hash) $(_curr_status) 2>/dev/null)";	\
      test "$$stamp" = "$$actual"; echo $$?)
  _clean_requested = $(filter %clean,$(MAKECMDGOALS))
  ifeq (1,$(_update_required)$(_clean_requested))
    $(info INFO: gnulib update required; running ./autogen.sh first)
Makefile: _autogen
  endif
endif

# Give credit where due:
# Ensure that each commit author email address (possibly mapped via
# git log's .mailmap) appears in our AUTHORS file.
sc_check_author_list:
	@fail=0;							\
	for i in $$(git log --pretty=format:%aE%n|sort -u|grep -v '^$$'); do \
	  sanitized=$$(echo "$$i"|LC_ALL=C sed 's/\([^a-zA-Z0-9_@-]\)/\\\1/g'); \
	  grep -iq "<$$sanitized>" $(srcdir)/AUTHORS			\
	    || { printf '%s\n' "$$i" >&2; fail=1; };			\
	done;								\
	test $$fail = 1							\
	  && echo '$(ME): committer(s) not listed in AUTHORS' >&2;	\
	test $$fail = 0

# It is necessary to call autogen any time gnulib changes.  Autogen
# reruns configure, then we regenerate all Makefiles at once.
.PHONY: _autogen
_autogen:
	$(srcdir)/autogen.sh
	./config.status

# regenerate HACKING as part of the syntax-check
syntax-check: $(top_srcdir)/HACKING

# sc_po_check can fail if generated files are not built first
sc_po_check: \
		$(srcdir)/daemon/remote_dispatch.h \
		$(srcdir)/daemon/qemu_dispatch.h \
		$(srcdir)/src/remote/remote_client_bodies.h
$(srcdir)/daemon/remote_dispatch.h: $(srcdir)/src/remote/remote_protocol.x
	$(MAKE) -C daemon remote_dispatch.h
$(srcdir)/daemon/qemu_dispatch.h: $(srcdir)/src/remote/qemu_protocol.x
	$(MAKE) -C daemon qemu_dispatch.h
$(srcdir)/src/remote/remote_client_bodies.h: $(srcdir)/src/remote/remote_protocol.x
	$(MAKE) -C src remote/remote_client_bodies.h

# List all syntax-check exemptions:
exclude_file_name_regexp--sc_avoid_strcase = ^tools/virsh\.c$$

_src1=libvirt|fdstream|qemu/qemu_monitor|util/(command|util)|xen/xend_internal|rpc/virnetsocket|lxc/lxc_controller
exclude_file_name_regexp--sc_avoid_write = \
  ^(src/($(_src1))|daemon/libvirtd|tools/console|tests/(shunload|virnettlscontext)test)\.c$$

exclude_file_name_regexp--sc_bindtextdomain = ^(tests|examples)/

exclude_file_name_regexp--sc_flags_usage = ^(docs/|src/util/virnetdevtap\.c$$)

exclude_file_name_regexp--sc_libvirt_unmarked_diagnostics = \
  ^src/rpc/gendispatch\.pl$$

exclude_file_name_regexp--sc_po_check = ^(docs/|src/rpc/gendispatch\.pl$$)

exclude_file_name_regexp--sc_prohibit_VIR_ERR_NO_MEMORY = \
  ^(include/libvirt/virterror\.h|daemon/dispatch\.c|src/util/virterror\.c)$$

exclude_file_name_regexp--sc_prohibit_access_xok = ^src/util/util\.c$$

exclude_file_name_regexp--sc_prohibit_always_true_header_tests = \
  ^python/(libvirt-(qemu-)?override|typewrappers)\.c$$

exclude_file_name_regexp--sc_prohibit_asprintf = \
  ^(bootstrap.conf$$|src/util/util\.c$$|examples/domain-events/events-c/event-test\.c$$)

exclude_file_name_regexp--sc_prohibit_close = \
  (\.p[yl]$$|^docs/|^(src/util/virfile\.c|src/libvirt\.c)$$)

exclude_file_name_regexp--sc_prohibit_empty_lines_at_EOF = \
  (^tests/qemuhelpdata/|\.(gif|ico|png|diff)$$)

_src2=src/(util/command|libvirt|lxc/lxc_controller)
exclude_file_name_regexp--sc_prohibit_fork_wrappers = \
  (^($(_src2)|tests/testutils|daemon/libvirtd)\.c$$)

exclude_file_name_regexp--sc_prohibit_gethostname = ^src/util/util\.c$$

exclude_file_name_regexp--sc_prohibit_internal_functions = \
  ^src/(util/(memory|util|virfile)\.[hc]|esx/esx_vi\.c)$$

exclude_file_name_regexp--sc_prohibit_newline_at_end_of_diagnostic = \
  ^src/rpc/gendispatch\.pl$$

exclude_file_name_regexp--sc_prohibit_nonreentrant = \
  ^((po|tests)/|docs/.*py$$|tools/(virsh|console)\.c$$)

exclude_file_name_regexp--sc_prohibit_raw_allocation = \
  ^(src/util/memory\.[ch]|examples/.*)$$

exclude_file_name_regexp--sc_prohibit_readlink = ^src/util/util\.c$$

exclude_file_name_regexp--sc_prohibit_setuid = ^src/util/util\.c$$

exclude_file_name_regexp--sc_prohibit_sprintf = \
  ^(docs/hacking\.html\.in)|(examples/systemtap/.*stp)|(src/dtrace2systemtap\.pl)|(src/rpc/gensystemtap\.pl)$$

exclude_file_name_regexp--sc_prohibit_strncpy = \
  ^(src/util/util|tools/virsh)\.c$$

exclude_file_name_regexp--sc_prohibit_xmlGetProp = ^src/util/xml\.c$$

exclude_file_name_regexp--sc_prohibit_xmlURI = ^src/util/viruri\.c$$

exclude_file_name_regexp--sc_prohibit_return_as_function = \.py$$

exclude_file_name_regexp--sc_require_config_h = ^examples/

exclude_file_name_regexp--sc_require_config_h_first = ^examples/

exclude_file_name_regexp--sc_trailing_blank = \.(fig|gif|ico|png)$$

exclude_file_name_regexp--sc_unmarked_diagnostics = \
  ^(docs/apibuild.py|tests/virt-aa-helper-test)$$

exclude_file_name_regexp--sc_size_of_brackets = cfg.mk
