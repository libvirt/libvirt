dnl
dnl Enable all known GCC compiler warnings, except for those
dnl we can't yet cope with
dnl
AC_DEFUN([LIBVIRT_COMPILE_WARNINGS],[
    dnl ******************************
    dnl More compiler warnings
    dnl ******************************

    AC_ARG_ENABLE(compile-warnings,
                  [AC_HELP_STRING([--enable-compile-warnings=@<:@no/yes/error@:>@],
                                 [Turn on compiler warnings])],,
                  [enable_compile_warnings="m4_default([$1],[yes])"])

    case "$enable_compile_warnings" in
    no)
        try_compiler_flags=""
	;;
    yes|minimum|maximum|error)

        # List of warnings that are not relevant / wanted

        # Don't care about C++ compiler compat
        dontwarn="$dontwarn -Wc++-compat"
        # Don't care about ancient C standard compat
        dontwarn="$dontwarn -Wtraditional"
        # Don't care about ancient C standard compat
        dontwarn="$dontwarn -Wtraditional-conversion"
        # Ignore warnings in /usr/include
        dontwarn="$dontwarn -Wsystem-headers"
        # Happy for compiler to add struct padding
        dontwarn="$dontwarn -Wpadded"
        # GCC very confused with -O2
        dontwarn="$dontwarn -Wunreachable-code"
        # Too many to deal with
        dontwarn="$dontwarn -Wconversion"
        # Too many to deal with
        dontwarn="$dontwarn -Wsign-conversion"
        # GNULIB gettext.h violates
        dontwarn="$dontwarn -Wvla"
        # Many GNULIB header violations
        dontwarn="$dontwarn -Wundef"
        # Need to allow bad cast for execve()
        dontwarn="$dontwarn -Wcast-qual"
        # We need to use long long in many places
        dontwarn="$dontwarn -Wlong-long"
        # We allow manual list of all enum cases without default:
        dontwarn="$dontwarn -Wswitch-default"
        # We allow optional default: instead of listing all enum values
        dontwarn="$dontwarn -Wswitch-enum"
        # Not a problem since we don't use -fstrict-overflow
        dontwarn="$dontwarn -Wstrict-overflow"
        # Not a problem since we don't use -funsafe-loop-optimizations
        dontwarn="$dontwarn -Wunsafe-loop-optimizations"
        # Things like virAsprintf mean we can't use this
        dontwarn="$dontwarn -Wformat-nonliteral"

        # We might fundamentally need some of these disabled forever, but ideally
        # we'd turn many of them on
        dontwarn="$dontwarn -Wfloat-equal"
        dontwarn="$dontwarn -Wdeclaration-after-statement"
        dontwarn="$dontwarn -Wcast-qual"
        dontwarn="$dontwarn -Wconversion"
        dontwarn="$dontwarn -Wsign-conversion"
        dontwarn="$dontwarn -Wold-style-definition"
        dontwarn="$dontwarn -Wmissing-noreturn"
        dontwarn="$dontwarn -Wpacked"
        dontwarn="$dontwarn -Wunused-macros"
        dontwarn="$dontwarn -Woverlength-strings"
        dontwarn="$dontwarn -Wstack-protector"

        # Get all possible GCC warnings
        gl_MANYWARN_ALL_GCC([maybewarn])

        # Remove the ones we don't want, blacklisted earlier
        gl_MANYWARN_COMPLEMENT([wantwarn], [$maybewarn], [$dontwarn])

        # Check for $CC support of each warning
        for w in $wantwarn; do
          gl_WARN_ADD([$w])
        done

        # GNULIB uses '-W' (aka -Wextra) which includes a bunch of stuff.
        # Unfortunately, this means you can't simply use '-Wsign-compare'
        # with gl_MANYWARN_COMPLEMENT
        # So we have -W enabled, and then have to explicitly turn off...
        gl_WARN_ADD([-Wno-sign-compare])

        # GNULIB expects this to be part of -Wc++-compat, but we turn
        # that one off, so we need to manually enable this again
        gl_WARN_ADD([-Wjump-misses-init])

        # This should be < 256 really, but with PATH_MAX everywhere
        # we have doom, even with 4096. In fact we have some functions
        # with several PATH_MAX sized variables :-( We should kill off
        # all PATH_MAX usage and then lower this limit
        gl_WARN_ADD([-Wframe-larger-than=65700])
        dnl gl_WARN_ADD([-Wframe-larger-than=4096])
        dnl gl_WARN_ADD([-Wframe-larger-than=256])

        # Extra special flags
        gl_WARN_ADD([-Wp,-D_FORTIFY_SOURCE=2])
        dnl Fedora only uses -fstack-protector, but doesn't seem to
        dnl be great overhead in adding -fstack-protector-all instead
        dnl gl_WARN_ADD([-fstack-protector])
        gl_WARN_ADD([-fstack-protector-all])
        gl_WARN_ADD([--param=ssp-buffer-size=4])
        gl_WARN_ADD([-fexceptions])
        gl_WARN_ADD([-fasynchronous-unwind-tables])
        gl_WARN_ADD([-fdiagnostics-show-option])

        if test "$enable_compile_warnings" = "error"
        then
          gl_WARN_ADD([-Werror])
        fi
	;;
    *)
	AC_MSG_ERROR(Unknown argument '$enable_compile_warnings' to --enable-compile-warnings)
	;;
    esac

    WARN_LDFLAGS=$WARN_CFLAGS
    AC_SUBST([WARN_CFLAGS])
    AC_SUBST([WARN_LDFLAGS])

    dnl Needed to keep compile quiet on python 2.4
    save_WARN_CFLAGS=$WARN_CFLAGS
    WARN_CFLAGS=
    gl_WARN_ADD([-Wno-redundant-decls])
    WARN_PYTHON_CFLAGS=$WARN_CFLAGS
    AC_SUBST(WARN_PYTHON_CFLAGS)
    WARN_CFLAGS=$save_WARN_CFLAGS
])
