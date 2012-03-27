dnl
dnl Enable all known GCC compiler warnings, except for those
dnl we can't yet cope with
dnl
AC_DEFUN([LIBVIRT_COMPILE_WARNINGS],[
    dnl ******************************
    dnl More compiler warnings
    dnl ******************************

    AC_ARG_ENABLE([werror],
                  AS_HELP_STRING([--enable-werror], [Use -Werror (if supported)]),
                  [set_werror="$enableval"],
                  [if test -d $srcdir/.git; then
                     is_git_version=true
                     set_werror=yes
                   else
                     set_werror=no
                   fi])

    # List of warnings that are not relevant / wanted

    # Don't care about C++ compiler compat
    dontwarn="$dontwarn -Wc++-compat"
    dontwarn="$dontwarn -Wabi"
    dontwarn="$dontwarn -Wdeprecated"
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

    # We might fundamentally need some of these disabled forever, but
    # ideally we'd turn many of them on
    dontwarn="$dontwarn -Wfloat-equal"
    dontwarn="$dontwarn -Wdeclaration-after-statement"
    dontwarn="$dontwarn -Wcast-qual"
    dontwarn="$dontwarn -Wconversion"
    dontwarn="$dontwarn -Wsign-conversion"
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

    # GNULIB turns on -Wformat=2 which implies -Wformat-nonliteral,
    # so we need to manually re-exclude it.
    gl_WARN_ADD([-Wno-format-nonliteral])

    # This should be < 256 really. Currently we're down to 4096,
    # but using 1024 bytes sized buffers (mostly for virStrerror)
    # stops us from going down further
    gl_WARN_ADD([-Wframe-larger-than=4096])
    dnl gl_WARN_ADD([-Wframe-larger-than=256])

    # Silence certain warnings in gnulib, and use improved glibc headers
    AC_DEFINE([lint], [1],
      [Define to 1 if the compiler is checking for lint.])
    AC_DEFINE([_FORTIFY_SOURCE], [2],
      [enable compile-time and run-time bounds-checking, and some warnings])

    # Extra special flags
    dnl -fstack-protector stuff passes gl_WARN_ADD with gcc
    dnl on Mingw32, but fails when actually used
    case $host in
       *-*-linux*)
       dnl Fedora only uses -fstack-protector, but doesn't seem to
       dnl be great overhead in adding -fstack-protector-all instead
       dnl gl_WARN_ADD([-fstack-protector])
       gl_WARN_ADD([-fstack-protector-all])
       gl_WARN_ADD([--param=ssp-buffer-size=4])
       ;;
    esac
    gl_WARN_ADD([-fexceptions])
    gl_WARN_ADD([-fasynchronous-unwind-tables])
    gl_WARN_ADD([-fdiagnostics-show-option])
    gl_WARN_ADD([-funit-at-a-time])

    # Need -fipa-pure-const in order to make -Wsuggest-attribute=pure
    # fire even without -O.
    gl_WARN_ADD([-fipa-pure-const])
    # We should eventually enable this, but right now there are at
    # least 75 functions triggering warnings.
    gl_WARN_ADD([-Wno-suggest-attribute=pure])
    gl_WARN_ADD([-Wno-suggest-attribute=const])

    if test "$set_werror" = "yes"
    then
      gl_WARN_ADD([-Werror])
    fi

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
