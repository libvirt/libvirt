dnl The QEMU driver
dnl
dnl Copyright (C) 2016 Red Hat, Inc.
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

AC_DEFUN([LIBVIRT_DRIVER_ARG_QEMU], [
  LIBVIRT_ARG_WITH_FEATURE([QEMU], [QEMU/KVM], [check])
  LIBVIRT_ARG_WITH([QEMU_USER], [username to run QEMU system instance as],
                   ['platform dependent'])
  LIBVIRT_ARG_WITH([QEMU_GROUP], [groupname to run QEMU system instance as],
                   ['platform dependent'])
])

AC_DEFUN([LIBVIRT_DRIVER_CHECK_QEMU], [
  dnl There is no way qemu driver will work without JSON support
  AC_REQUIRE([LIBVIRT_CHECK_YAJL])
  if test "$with_qemu:$with_yajl" = "yes:no"; then
    AC_MSG_ERROR([YAJL 2 is required to build QEMU driver])
  fi
  if test "$with_qemu" = "check"; then
    with_qemu=$with_yajl
  fi

  if test "$with_qemu" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_QEMU], 1, [whether QEMU driver is enabled])
  fi
  AM_CONDITIONAL([WITH_QEMU], [test "$with_qemu" = "yes"])

  if test $with_freebsd = yes || test $with_macos = yes; then
    default_qemu_user=root
    default_qemu_group=wheel
  else
    # Try to integrate gracefully with downstream packages by running QEMU
    # processes using the same user and group they would
    case $(grep ^ID= /etc/os-release 2>/dev/null) in
      *arch*)
        default_qemu_user=nobody
        default_qemu_group=nobody
        ;;
      *centos*|*fedora*|*gentoo*|*rhel*|*suse*)
        default_qemu_user=qemu
        default_qemu_group=qemu
        ;;
      *debian*)
        default_qemu_user=libvirt-qemu
        default_qemu_group=libvirt-qemu
        ;;
      *ubuntu*)
        default_qemu_user=libvirt-qemu
        default_qemu_group=kvm
        ;;
      *)
        default_qemu_user=root
        default_qemu_group=root
        ;;
    esac
    # If the expected user and group don't exist, or we haven't hit any
    # of the cases above because we're running on an unknown OS, the only
    # sensible fallback is root:root
    AC_MSG_CHECKING([for QEMU credentials ($default_qemu_user:$default_qemu_group)])
    if getent passwd "$default_qemu_user" >/dev/null 2>&1 && \
       getent group "$default_qemu_group" >/dev/null 2>&1; then
      AC_MSG_RESULT([ok])
    else
      AC_MSG_RESULT([not found, using root:root instead])
      default_qemu_user=root
      default_qemu_group=root
    fi
  fi

  if test "x$with_qemu_user" = "xplatform dependent" ; then
    QEMU_USER="$default_qemu_user"
  else
    QEMU_USER="$with_qemu_user"
  fi
  if test "x$with_qemu_group" = "xplatform dependent" ; then
    QEMU_GROUP="$default_qemu_group"
  else
    QEMU_GROUP="$with_qemu_group"
  fi
  AC_DEFINE_UNQUOTED([QEMU_USER], ["$QEMU_USER"], [QEMU user account])
  AC_DEFINE_UNQUOTED([QEMU_GROUP], ["$QEMU_GROUP"], [QEMU group account])

  AC_PATH_PROG([QEMU_BRIDGE_HELPER], [qemu-bridge-helper],
               [/usr/libexec/qemu-bridge-helper],
               [/usr/libexec:/usr/lib/qemu:/usr/lib])
  AC_DEFINE_UNQUOTED([QEMU_BRIDGE_HELPER], ["$QEMU_BRIDGE_HELPER"],
                     [QEMU bridge helper])
  AC_PATH_PROG([QEMU_PR_HELPER], [qemu-pr-helper],
               [/usr/bin/qemu-pr-helper],
               [/usr/bin:/usr/libexec])
  AC_DEFINE_UNQUOTED([QEMU_PR_HELPER], ["$QEMU_PR_HELPER"],
                     [QEMU PR helper])
  AC_PATH_PROG([QEMU_SLIRP_HELPER], [slirp-helper],
               [/usr/bin/slirp-helper],
               [/usr/bin:/usr/libexec])
  AC_DEFINE_UNQUOTED([QEMU_SLIRP_HELPER], ["$QEMU_SLIRP_HELPER"],
                     [QEMU slirp helper])
])

AC_DEFUN([LIBVIRT_DRIVER_RESULT_QEMU], [
  LIBVIRT_RESULT([QEMU], [$with_qemu])
])

AC_DEFUN([LIBVIRT_RESULT_QEMU_PRIVILEGES], [
  if test "$QEMU_USER" = "root"; then
    LIBVIRT_RESULT([QEMU], [$QEMU_USER:$QEMU_GROUP],
                   [!!! running QEMU as root is strongly discouraged !!!])
  else
    LIBVIRT_RESULT([QEMU], [$QEMU_USER:$QEMU_GROUP])
  fi
])
