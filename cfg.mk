# Customize Makefile.maint.                           -*- makefile -*-
# Copyright (C) 2003-2010 Free Software Foundation, Inc.

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

useless_free_options =		\
  --name=sexpr_free		\
  --name=VIR_FREE		\
  --name=xmlFree		\
  --name=xmlXPathFreeContext	\
  --name=virDomainDefFree	\
  --name=xmlXPathFreeObject

# Avoid uses of write(2).  Either switch to streams (fwrite), or use
# the safewrite wrapper.
sc_avoid_write:
	@prohibit='\<write *\('						\
	in_vc_files='\.c$$'						\
	halt='consider using safewrite instead of write'		\
	 $(_sc_search_regexp)

# Use STREQ rather than comparing strcmp == 0, or != 0.
# Similarly, use STREQLEN or STRPREFIX rather than strncmp.
sc_prohibit_strcmp_and_strncmp:
	@prohibit='strn?cmp *\('					\
	halt='use STREQ() in place of the above uses of str[n]cmp'	\
	  $(_sc_search_regexp)

# Use virAsprintf rather than a'sprintf since *strp is undefined on error.
sc_prohibit_asprintf:
	@prohibit='\<[a]sprintf\>'					\
	halt='use virAsprintf, not a'sprintf				\
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

# Ensure that no C source file or rng schema uses TABs for
# indentation.  Also match *.h.in files, to get libvirt.h.in.  Exclude
# files in gnulib, since they're imported.
sc_TAB_in_indentation:
	@prohibit='^ *	'						\
	in_vc_files='\.(rng|[ch](\.in)?)$$'				\
	halt='use spaces, not TAB, for indentation in C sources and RNG schemas' \
	 $(_sc_search_regexp)

ctype_re = isalnum|isalpha|isascii|isblank|iscntrl|isdigit|isgraph|islower\
|isprint|ispunct|isspace|isupper|isxdigit|tolower|toupper

sc_avoid_ctype_macros:
	@prohibit='\b($(ctype_re)) *\('					\
	halt="don't use ctype macros (use c-ctype.h)"			\
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

# Many of the function names below came from this filter:
# git grep -B2 '\<_('|grep -E '\.c- *[[:alpha:]_][[:alnum:]_]* ?\(.*[,;]$' \
# |sed 's/.*\.c-  *//'|perl -pe 's/ ?\(.*//'|sort -u \
# |grep -vE '^(qsort|if|close|assert|fputc|free|N_|vir.*GetName|.*Unlock|virNodeListDevices|virHashRemoveEntry|freeaddrinfo|.*[fF]ree|xdrmem_create|xmlXPathFreeObject|virUUIDFormat|openvzSetProgramSentinal|polkit_action_unref)$'

msg_gen_function =
msg_gen_function += DEBUG0
msg_gen_function += DISABLE_fprintf
msg_gen_function += ERROR
msg_gen_function += ERROR0
msg_gen_function += REMOTE_DEBUG
msg_gen_function += ReportError
msg_gen_function += VIR_FREE
msg_gen_function += VIR_INFO
msg_gen_function += VIR_USE_CPU
msg_gen_function += errorf
msg_gen_function += lxcError
msg_gen_function += networkLog
msg_gen_function += networkReportError
msg_gen_function += oneError
msg_gen_function += openvzError
msg_gen_function += openvzLog
msg_gen_function += qemudDispatchClientFailure
msg_gen_function += qemudLog
msg_gen_function += qemudReportError
msg_gen_function += regerror
msg_gen_function += remoteDispatchFormatError
msg_gen_function += umlLog
msg_gen_function += umlReportError
msg_gen_function += vboxError
msg_gen_function += virConfError
msg_gen_function += virDomainReportError
msg_gen_function += virSecurityReportError
msg_gen_function += virHashError
msg_gen_function += virLibConnError
msg_gen_function += virLibDomainError
msg_gen_function += virLog
msg_gen_function += virNetworkReportError
msg_gen_function += virNodeDeviceReportError
msg_gen_function += virProxyError
msg_gen_function += virRaiseError
msg_gen_function += virReportErrorHelper
msg_gen_function += virReportSystemError
msg_gen_function += virSexprError
msg_gen_function += virStorageLog
msg_gen_function += virStorageReportError
msg_gen_function += virXMLError
msg_gen_function += virXenInotifyError
msg_gen_function += virXenStoreError
msg_gen_function += virXendError
msg_gen_function += vshCloseLogFile
msg_gen_function += xenapiSessionErrorHandler
msg_gen_function += xenUnifiedError
msg_gen_function += xenXMError

# Uncomment the following and run "make syntax-check" to see diagnostics
# that are not yet marked for translation, but that need to be rewritten
# so that they are translatable.
# msg_gen_function += error
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
	@grep -nE							\
	    '\<$(func_re) \([^"]*"[^"]*[a-z]{3}' $$($(VC_LIST_EXCEPT))	\
	  | grep -v '_''(' &&						\
	  { echo '$(ME): found unmarked diagnostic(s)' 1>&2;		\
	    exit 1; } || :
	@{ grep     -nE '\<$(func_re) *\(.*;$$' $$($(VC_LIST_EXCEPT));   \
	   grep -A1 -nE '\<$(func_re) *\(.*,$$' $$($(VC_LIST_EXCEPT)); } \
	   | sed 's/_("[^"][^"]*"//;s/[	 ]"%s"//'			\
	   | grep '[	 ]"' &&						\
	  { echo '$(ME): found unmarked diagnostic(s)' 1>&2;		\
	    exit 1; } || :

# Disallow trailing blank lines.
sc_prohibit_trailing_blank_lines:
	@$(VC_LIST_EXCEPT) | xargs perl -ln -0777 -e			\
	  '/\n\n+$$/ and print $$ARGV' > $@-t
	@found=0; test -s $@-t && { found=1; cat $@-t 1>&2;		\
	  echo '$(ME): found trailing blank line(s)' 1>&2; };		\
	rm -f $@-t;							\
	test $$found = 0

# Regex for grep -E that exempts generated files from style rules.
preprocessor_exempt = (remote_(driver|protocol)\.h)$$
# Enforce recommended preprocessor indentation style.
sc_preprocessor_indentation:
	@if (cppi --version >/dev/null 2>&1); then			\
	  $(VC_LIST_EXCEPT) | grep '\.[ch]$$'				\
	    | grep -vE '$(preprocessor_exempt)' | xargs cppi -a -c	\
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
      actual=$$(git submodule status | $(_submodule_hash);		\
		git hash-object bootstrap.conf;				\
		git diff .gnulib);					\
      stamp="$$($(_submodule_hash) $(_curr_status) 2>/dev/null)";	\
      test "$$stamp" = "$$actual"; echo $$?)
  ifeq (1,$(_update_required))
    $(info INFO: gnulib update required; running ./autogen.sh first)
Makefile: _autogen
  endif
endif

# It is necessary to call autogen any time gnulib changes.  Autogen
# reruns configure, then we regenerate all Makefiles at once.
.PHONY: _autogen
_autogen:
	$(srcdir)/autogen.sh
	./config.status

# Exempt @...@ uses of these symbols.
_makefile_at_at_check_exceptions = ' && !/(SCHEMA|SYSCONF)DIR/'
