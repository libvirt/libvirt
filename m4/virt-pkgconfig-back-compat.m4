dnl
dnl To support the old pkg-config from RHEL4 vintage, we need
dnl to define the PKG_PROG_PKG_CONFIG macro if its not already
dnl present
m4_ifndef([PKG_PROG_PKG_CONFIG],
  [AC_DEFUN([PKG_PROG_PKG_CONFIG],
[m4_pattern_forbid([^_?PKG_[A-Z_]+$])
m4_pattern_allow([^PKG_CONFIG(_PATH)?$])
AC_ARG_VAR([PKG_CONFIG], [path to pkg-config utility])dnl
if test "x$ac_cv_env_PKG_CONFIG_set" != "xset"; then
        AC_PATH_TOOL([PKG_CONFIG], [pkg-config])
fi
if test -n "$PKG_CONFIG"; then
        _pkg_min_version=m4_default([$1], [0.9.0])
        AC_MSG_CHECKING([pkg-config is at least version $_pkg_min_version])
        if $PKG_CONFIG --atleast-pkgconfig-version $_pkg_min_version; then
                AC_MSG_RESULT([yes])
        else
                AC_MSG_RESULT([no])
                PKG_CONFIG=""
        fi
fi[]dnl
])])
