dnl
dnl Taken from gnome-common/macros2/gnome-compiler-flags.m4
dnl
dnl We've added:
dnl   -Wextra -Wshadow -Wcast-align -Wwrite-strings -Waggregate-return -Wstrict-prototypes -Winline -Wredundant-decls
dnl We've removed
dnl   CFLAGS="$realsave_CFLAGS"
dnl   to avoid clobbering user-specified CFLAGS
dnl
AC_DEFUN([LIBVIRT_COMPILE_WARNINGS],[
    dnl ******************************
    dnl More compiler warnings
    dnl ******************************

    AC_ARG_ENABLE(compile-warnings,
                  [AC_HELP_STRING([--enable-compile-warnings=@<:@no/minimum/yes/maximum/error@:>@],
                                 [Turn on compiler warnings])],,
                  [enable_compile_warnings="m4_default([$1],[maximum])"])

    warnCFLAGS=

    common_flags=
    common_flags="$common_flags -Wp,-D_FORTIFY_SOURCE=2"
    common_flags="$common_flags -fexceptions"
    common_flags="$common_flags -fasynchronous-unwind-tables"
    common_flags="$common_flags -fdiagnostics-show-option"

    case "$enable_compile_warnings" in
    no)
        try_compiler_flags=""
	;;
    minimum)
	try_compiler_flags="-Wall -Wformat -Wformat-security $common_flags"
	;;
    yes)
	try_compiler_flags="-Wall -Wformat -Wformat-security -Wmissing-prototypes $common_flags"
	;;
    maximum|error)
	try_compiler_flags="-Wall -Wformat -Wformat-security"
	try_compiler_flags="$try_compiler_flags -Wmissing-prototypes"
	try_compiler_flags="$try_compiler_flags -Wnested-externs "
	try_compiler_flags="$try_compiler_flags -Wpointer-arith"
	try_compiler_flags="$try_compiler_flags -Wextra -Wshadow"
	try_compiler_flags="$try_compiler_flags -Wcast-align"
	try_compiler_flags="$try_compiler_flags -Wwrite-strings"
	try_compiler_flags="$try_compiler_flags -Waggregate-return"
	try_compiler_flags="$try_compiler_flags -Wstrict-prototypes"
	try_compiler_flags="$try_compiler_flags -Winline"
	try_compiler_flags="$try_compiler_flags -Wredundant-decls"
	try_compiler_flags="$try_compiler_flags -Wno-sign-compare"
	try_compiler_flags="$try_compiler_flags -Wlogical-op"
	try_compiler_flags="$try_compiler_flags $common_flags"
	if test "$enable_compile_warnings" = "error" ; then
	    try_compiler_flags="$try_compiler_flags -Werror"
	fi
	;;
    *)
	AC_MSG_ERROR(Unknown argument '$enable_compile_warnings' to --enable-compile-warnings)
	;;
    esac

    COMPILER_FLAGS=
    for option in $try_compiler_flags; do
        gl_COMPILER_FLAGS($option)
    done
    unset option
    unset try_compiler_flags

    AC_ARG_ENABLE(iso-c,
                  AC_HELP_STRING([--enable-iso-c],
                                 [Try to warn if code is not ISO C ]),,
                  [enable_iso_c=no])

    AC_MSG_CHECKING(what language compliance flags to pass to the C compiler)
    complCFLAGS=
    if test "x$enable_iso_c" != "xno"; then
	if test "x$GCC" = "xyes"; then
	case " $CFLAGS " in
	    *[\ \	]-ansi[\ \	]*) ;;
	    *) complCFLAGS="$complCFLAGS -ansi" ;;
	esac
	case " $CFLAGS " in
	    *[\ \	]-pedantic[\ \	]*) ;;
	    *) complCFLAGS="$complCFLAGS -pedantic" ;;
	esac
	fi
    fi
    AC_MSG_RESULT($complCFLAGS)

    WARN_CFLAGS="$COMPILER_FLAGS $complCFLAGS"
    WARN_LDFLAGS=$WARN_CFLAGS
    AC_SUBST([WARN_CFLAGS])
    AC_SUBST([WARN_LDFLAGS])

    dnl Needed to keep compile quiet on python 2.4
    COMPILER_FLAGS=
    gl_COMPILER_FLAGS(-Wno-redundant-decls)
    WARN_PYTHON_CFLAGS=$COMPILER_FLAGS
    AC_SUBST(WARN_PYTHON_CFLAGS)
])


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
