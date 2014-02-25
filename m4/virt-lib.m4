dnl
dnl virt-lib.m4: Helper macros for checking for libraries
dnl
dnl Copyright (C) 2012-2014 Red Hat, Inc.
dnl
dnl This library is free software; you can redistribute it and/or
dnl modify it under the terms of the GNU Lesser General Public
dnl License as published by the Free Software Foundation; either
dnl version 2.1 of the License, or (at your option) any later version.
dnl
dnl This library is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
dnl Lesser General Public License for more details.
dnl
dnl You should have received a copy of the GNU Lesser General Public
dnl License along with this library.  If not, see
dnl <http://www.gnu.org/licenses/>.
dnl


dnl Probe for existence of libXXXX and set WITH_XXX
dnl config header var, WITH_XXXX make conditional and
dnl with_XXX configure shell var.
dnl
dnl  LIBVIRT_CHECK_LIB([CHECK_NAME], [LIBRARY_NAME],
dnl                    [FUNCTION_NAME], [HEADER_NAME])
dnl
dnl  CHECK_NAME: Suffix/prefix used for variables / flags, in uppercase.
dnl              Used to set
dnl                 config.h: WITH_XXX macro
dnl                 Makefile: WITH_XXX conditional
dnl                 Makefile: XXX_CFLAGS, XXX_LIBS variables
dnl                configure: --with-xxx argument
dnl                configure: with_xxx variable
dnl
dnl   LIBRARY_NAME: base name of library to check for eg libXXX.so
dnl  FUNCTION_NAME: function to check for in libXXX.so
dnl    HEADER_NAME: header file to check for
dnl
dnl e.g.
dnl
dnl  LIBVIRT_CHECK_LIB([SELINUX], [selinux],
dnl                    [getfilecon], [selinux/selinux.h])
dnl  LIBVIRT_CHECK_LIB([SANLOCK], [sanlock_client],
dnl                    [sanlock_init], [sanlock.h])
dnl  LIBVIRT_CHECK_LIB([LIBATTR], [attr],
dnl                    [getxattr], [attr/attr.h])
dnl
AC_DEFUN([LIBVIRT_CHECK_LIB],[
  m4_pushdef([check_name], [$1])
  m4_pushdef([library_name], [$2])
  m4_pushdef([function_name], [$3])
  m4_pushdef([header_name], [$4])

  m4_pushdef([check_name_lc], m4_tolower(check_name))
  m4_pushdef([check_name_dash], m4_translit(check_name_lc, [_], [-]))

  m4_pushdef([config_var], [WITH_]check_name)
  m4_pushdef([make_var], [WITH_]check_name)
  m4_pushdef([cflags_var], check_name[_CFLAGS])
  m4_pushdef([libs_var], check_name[_LIBS])
  m4_pushdef([arg_var], [with-]check_name_dash)
  m4_pushdef([with_var], [with_]check_name_lc)

  m4_divert_text([DEFAULTS], [with_var][=check])
  AC_ARG_WITH(check_name_dash,
    [AS_HELP_STRING([--arg_var],
                    [with lib]]m4_dquote(library_name)[[ support @<:@default=check@:>@])])

  old_LIBS=$LIBS
  old_CFLAGS=$CFLAGS
  cflags_var=
  libs_var=

  fail=0
  if test "x$with_var" != "xno" ; then
    if test "x$with_var" != "xyes" && test "x$with_var" != "xcheck" ; then
      cflags_var="-I$with_var/include"
      libs_var="-L$with_var/lib"
    fi
    CFLAGS="$CFLAGS $cflags_var"
    LIBS="$LIBS $libs_var"
    AC_CHECK_LIB(library_name, function_name, [],[
      if test "x$with_var" != "xcheck"; then
        fail=1
      fi
      with_var=no
    ])
    if test "$fail" = "0" && test "x$with_var" != "xno" ; then
      AC_CHECK_HEADER([header_name], [
        with_var=yes
      ],[
        if test "x$with_var" != "xcheck"; then
          fail=1
        fi
        with_var=no
      ])
    fi
  fi

  LIBS=$old_LIBS
  CFLAGS=$old_CFLAGS

  if test $fail = 1; then
    AC_MSG_ERROR([You must install the lib]library_name[ library & headers to compile libvirt])
  else
    if test "x$with_var" = "xyes" ; then
      if test "x$libs_var" = 'x' ; then
        libs_var="-l[]library_name"
      else
        libs_var="$libs_var -l[]library_name"
      fi
      AC_DEFINE_UNQUOTED(config_var, 1, [whether lib]library_name[ is available])
    fi

    AM_CONDITIONAL(make_var, [test "x$with_var" = "xyes"])

    AC_SUBST(cflags_var)
    AC_SUBST(libs_var)
  fi

  m4_popdef([with_var])
  m4_popdef([arg_var])
  m4_popdef([libs_var])
  m4_popdef([cflags_var])
  m4_popdef([make_var])
  m4_popdef([config_var])

  m4_popdef([check_name_dash])
  m4_popdef([check_name_lc])

  m4_popdef([header_name])
  m4_popdef([function_name])
  m4_popdef([library_name])
  m4_popdef([check_name])
])

dnl Probe for existence of libXXXX and set WITH_XXX
dnl config header var, WITH_XXXX make conditional and
dnl with_XXX configure shell var.
dnl
dnl  LIBVIRT_CHECK_LIB_ALT([CHECK_NAME], [LIBRARY_NAME],
dnl                        [FUNCTION_NAME], [HEADER_NAME],
dnl                        [CHECK_NAME_ALT, [LIBRARY_NAME_ALT],
dnl                        [FUNCTION_NAME_ALT], [HEADER_NAME_ALT])
dnl
dnl  CHECK_NAME: Suffix/prefix used for variables / flags, in uppercase.
dnl              Used to set
dnl                 config.h: WITH_XXX macro
dnl                 Makefile: WITH_XXX conditional
dnl                 Makefile: XXX_CFLAGS, XXX_LIBS variables
dnl                configure: --with-xxx argument
dnl                configure: with_xxx variable
dnl
dnl   LIBRARY_NAME: base name of library to check for eg libXXX.so
dnl  FUNCTION_NAME: function to check for in libXXX.so
dnl    HEADER_NAME: header file to check for
dnl
dnl     CHECK_NAME_ALT: Suffix/prefix used to set additional
dnl                     variables if alternative check succeeds
dnl                      config.h: WITH_XXX macro
dnl                      Makefile: WITH_XXX conditional
dnl                    NB all vars for CHECK_NAME are also set
dnl   LIBRARY_NAME_ALT: alternative library name to check for
dnl  FUNCTION_NAME_ALT: alternative function name to check for
dnl    HEADER_NAME_ALT: alternative header file to check for
dnl
dnl e.g.
dnl
dnl  LIBVIRT_CHECK_LIB([YAJL], [yajl],
dnl                    [yajl_parse_complete], [yajl/yajl_common.h],
dnl                    [YAJL2], [yajl],
dnl                    [yajl_tree_parse], [yajl/yajl_common.h])
dnl
AC_DEFUN([LIBVIRT_CHECK_LIB_ALT],[
  m4_pushdef([check_name], [$1])
  m4_pushdef([library_name], [$2])
  m4_pushdef([function_name], [$3])
  m4_pushdef([header_name], [$4])
  m4_pushdef([check_name_alt], [$5])
  m4_pushdef([library_name_alt], [$6])
  m4_pushdef([function_name_alt], [$7])
  m4_pushdef([header_name_alt], [$8])

  m4_pushdef([check_name_lc], m4_tolower(check_name))
  m4_pushdef([check_name_dash], m4_translit(check_name_lc, [_], [-]))

  m4_pushdef([config_var], [WITH_]check_name)
  m4_pushdef([make_var], [WITH_]check_name)
  m4_pushdef([cflags_var], check_name[_CFLAGS])
  m4_pushdef([libs_var], check_name[_LIBS])
  m4_pushdef([arg_var], [with-]check_name_dash)
  m4_pushdef([with_var], [with_]check_name_lc)
  m4_pushdef([config_var_alt], [WITH_]check_name_alt)
  m4_pushdef([make_var_alt], [WITH_]check_name_alt)

  m4_divert_text([DEFAULTS], [with_var][=check])
  AC_ARG_WITH(check_name_dash,
    [AS_HELP_STRING([--arg_var],
                    [with lib]]m4_dquote(library_name)[[ support @<:@default=check@:>@])])

  old_LIBS=$LIBS
  old_CFLAGS=$CFLAGS
  cflags_var=
  libs_var=

  fail=0
  alt=0
  if test "x$with_var" != "xno" ; then
    if test "x$with_var" != "xyes" && test "x$with_var" != "xcheck" ; then
      cflags_var="-I$with_var/include"
      libs_var="-L$with_var/lib"
    fi
    CFLAGS="$CFLAGS $cflags_var"
    LIBS="$LIBS $libs_var"
    AC_CHECK_LIB(library_name, function_name, [],[
      AC_CHECK_LIB(library_name_alt, function_name_alt, [
        alt=1
      ],[
        if test "x$with_var" != "xcheck"; then
          fail=1
        fi
        with_var=no
      ])
    ])
    if test "$fail" = "0" && test "x$with_var" != "xno" ; then
      AC_CHECK_HEADER([header_name], [
        with_var=yes
      ],[
        AC_CHECK_HEADER([header_name_alt], [
          with_var=yes
        ],[
          if test "x$with_var" != "xcheck"; then
            fail=1
          fi
          with_var=no
        ])
      ])
    fi
  fi

  LIBS=$old_LIBS
  CFLAGS=$old_CFLAGS

  if test $fail = 1; then
    AC_MSG_ERROR([You must install the lib]library_name[ library & headers to compile libvirt])
  else
    if test "x$with_var" = "xyes" ; then
      if test "x$libs_var" = 'x' ; then
        libs_var="-l[]library_name"
      else
        libs_var="$libs_var -l[]library_name"
      fi

      AC_DEFINE_UNQUOTED(config_var, 1, [whether lib]library_name[ is available])
      if test "$alt" = "1" ; then
        AC_DEFINE_UNQUOTED(config_var_alt, 1, [whether lib]library_name[ is available])
      fi
    fi

    AM_CONDITIONAL(make_var, [test "x$with_var" = "xyes"])
    AM_CONDITIONAL(make_var_alt, [test "x$with_var" = "xyes" && test "$alt" = "1"])

    AC_SUBST(cflags_var)
    AC_SUBST(libs_var)
  fi

  m4_popdef([make_var_alt])
  m4_popdef([config_var_alt])
  m4_popdef([with_var])
  m4_popdef([arg_var])
  m4_popdef([libs_var])
  m4_popdef([cflags_var])
  m4_popdef([make_var])
  m4_popdef([config_var])

  m4_popdef([check_name_lc])
  m4_popdef([check_name_dash])

  m4_popdef([header_name_alt])
  m4_popdef([function_name_alt])
  m4_popdef([library_name_alt])
  m4_popdef([header_name])
  m4_popdef([function_name])
  m4_popdef([library_name])
  m4_popdef([check_name])
])

dnl
dnl Probe for existence of libXXXX and set WITH_XXX
dnl config header var, WITH_XXXX make conditional and
dnl with_XXX configure shell var.
dnl
dnl  LIBVIRT_CHECK_PKG([CHECK_NAME], [PC_NAME], [PC_VERSION])
dnl
dnl  CHECK_NAME: Suffix/prefix used for variables / flags, in uppercase.
dnl              Used to set
dnl                 config.h: WITH_XXX macro
dnl                 Makefile: WITH_XXX conditional
dnl                 Makefile: XXX_CFLAGS, XXX_LIBS variables
dnl                configure: --with-xxx argument
dnl                configure: with_xxx variable
dnl    PC_NAME: Name of the pkg-config module
dnl    PC_VERSION: Version of the pkg-config module
dnl
dnl eg
dnl
dnl  LIBVIRT_CHECK_PKG([NETCF], [netcf], [0.1.4])
dnl
AC_DEFUN([LIBVIRT_CHECK_PKG],[
  m4_pushdef([check_name], [$1])
  m4_pushdef([pc_name], [$2])
  m4_pushdef([pc_version], [$3])

  m4_pushdef([check_name_lc], m4_tolower(check_name))
  m4_pushdef([check_name_dash], m4_translit(check_name_lc, [_], [-]))

  m4_pushdef([config_var], [WITH_]check_name)
  m4_pushdef([make_var], [WITH_]check_name)
  m4_pushdef([cflags_var], check_name[_CFLAGS])
  m4_pushdef([libs_var], check_name[_LIBS])
  m4_pushdef([arg_var], [with-]check_name_dash)
  m4_pushdef([with_var], [with_]check_name_lc)

  m4_divert_text([DEFAULTS], [with_var][=check])
  AC_ARG_WITH(check_name_dash,
    [AS_HELP_STRING([--arg_var],
                   [with ]]m4_dquote(pc_name)[[ (>= ]]m4_dquote(pc_version)[[) support @<:@default=check@:>@])])

  fail=0
  if test "x$with_var" != "xno" ; then
    PKG_CHECK_MODULES(check_name, pc_name[ >= ]pc_version, [
      with_var=yes
    ],[
      if test "x$with_var" != "xcheck"; then
        fail=1
      fi
      with_var=no
    ])
  fi

  if test $fail = 1; then
    AC_MSG_ERROR([You must install the ]pc_name[ >= ]pc_version[ pkg-config module to compile libvirt])
  fi

  if test "x$with_var" = "xyes" ; then
    AC_DEFINE_UNQUOTED(config_var, 1, [whether ]pc_name[ >= ]pc_version[ is available])
  fi

  AM_CONDITIONAL(make_var, [test "x$with_var" = "xyes"])

  m4_popdef([with_var])
  m4_popdef([arg_var])
  m4_popdef([libs_var])
  m4_popdef([cflags_var])
  m4_popdef([make_var])
  m4_popdef([config_var])

  m4_popdef([check_name_lc])
  m4_popdef([check_name_dash])

  m4_popdef([pc_version])
  m4_popdef([pc_name])
  m4_popdef([check_name])
])

dnl
dnl To be used after a call to LIBVIRT_CHECK_LIB,
dnl LIBVIRT_CHECK_LIB_ALT or LIBVIRT_CHECK_PKG
dnl to print the result status
dnl
dnl  LIBVIRT_RESULT_LIB([CHECK_NAME])
dnl
dnl  CHECK_NAME: Suffix/prefix used for variables / flags, in uppercase.
dnl
dnl  LIBVIRT_RESULT_LIB([SELINUX])
dnl
AC_DEFUN([LIBVIRT_RESULT_LIB],[
  m4_pushdef([check_name], [$1])

  m4_pushdef([check_name_lc], m4_tolower(check_name))

  m4_pushdef([cflags_var], check_name[_CFLAGS])
  m4_pushdef([libs_var], check_name[_LIBS])
  m4_pushdef([with_var], [with_]check_name_lc)

  LIBVIRT_RESULT(check_name_lc, [$with_var], [CFLAGS='$cflags_var' LIBS='$libs_var'])

  m4_popdef([with_var])
  m4_popdef([libs_var])
  m4_popdef([cflags_var])

  m4_popdef([check_name_lc])

  m4_popdef([check_name])
])
