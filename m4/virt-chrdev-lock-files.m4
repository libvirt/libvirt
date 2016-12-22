dnl The locaton of UUCP style lock files
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

AC_DEFUN([LIBVIRT_ARG_CHRDEV_LOCK_FILES], [
  LIBVIRT_ARG_WITH([CHRDEV_LOCK_FILES],
                   [location for UUCP style lock files for character devices ]
                     [(use auto for default paths on some platforms)],
                   [auto])
])

AC_DEFUN([LIBVIRT_CHECK_CHRDEV_LOCK_FILES], [
  if test "$with_chrdev_lock_files" != "no"; then
    case $with_chrdev_lock_files in
      yes | auto)
        dnl Default locations for platforms, or disable if unknown
        if test "$with_linux" = "yes"; then
          with_chrdev_lock_files=/var/lock
        elif test "$with_chrdev_lock_files" = "auto"; then
          with_chrdev_lock_files=no
        fi
        ;;
    esac
    if test "$with_chrdev_lock_files" = "yes"; then
      AC_MSG_ERROR([You must specify path for the lock files on this platform])
    fi
    if test "$with_chrdev_lock_files" != "no"; then
      AC_DEFINE_UNQUOTED([VIR_CHRDEV_LOCK_FILE_PATH], "$with_chrdev_lock_files",
                         [path to directory containing UUCP device lock files])
    fi
  fi
  AM_CONDITIONAL([VIR_CHRDEV_LOCK_FILE_PATH], [test "$with_chrdev_lock_files" != "no"])
])

AC_DEFUN([LIBVIRT_RESULT_CHRDEV_LOCK_FILES], [
  AC_MSG_NOTICE([ Char device locks: $with_chrdev_lock_files])
])
