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
                  AC_HELP_STRING([--enable-compile-warnings=@<:@no/minimum/yes/maximum/error@:>@],
                                 [Turn on compiler warnings]),,
                  [enable_compile_warnings="m4_default([$1],[maximum])"])

    warnCFLAGS=

    common_flags="-Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fasynchronous-unwind-tables"

    case "$enable_compile_warnings" in
    no)
        try_compiler_flags=""
	;;
    minimum)
	try_compiler_flags="-Wall $common_flags"
	;;
    yes)
	try_compiler_flags="-Wall -Wmissing-prototypes $common_flags"
	;;
    maximum|error)
	try_compiler_flags="-Wall -Wmissing-prototypes -Wnested-externs -Wpointer-arith"
	try_compiler_flags="$try_compiler_flags -Wextra -Wshadow -Wcast-align -Wwrite-strings -Waggregate-return"
	try_compiler_flags="$try_compiler_flags -Wstrict-prototypes -Winline -Wredundant-decls -Wno-sign-compare"
	try_compiler_flags="$try_compiler_flags $common_flags"
	if test "$enable_compile_warnings" = "error" ; then
	    try_compiler_flags="$try_compiler_flags -Werror"
	fi
	;;
    *)
	AC_MSG_ERROR(Unknown argument '$enable_compile_warnings' to --enable-compile-warnings)
	;;
    esac

    compiler_flags=
    for option in $try_compiler_flags; do
	SAVE_CFLAGS="$CFLAGS"
	CFLAGS="$CFLAGS $option"
	AC_MSG_CHECKING([whether gcc understands $option])
	AC_TRY_LINK([], [],
		has_option=yes,
		has_option=no,)
	CFLAGS="$SAVE_CFLAGS"
	AC_MSG_RESULT($has_option)
	if test $has_option = yes; then
	  compiler_flags="$compiler_flags $option"
	fi
	unset has_option
	unset SAVE_CFLAGS
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

    WARN_CFLAGS="$compiler_flags $complCFLAGS"
    AC_SUBST(WARN_CFLAGS)
])
