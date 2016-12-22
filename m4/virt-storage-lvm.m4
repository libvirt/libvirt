dnl The storage LVM check
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

AC_DEFUN([LIBVIRT_STORAGE_ARG_LVM], [
  LIBVIRT_ARG_WITH_FEATURE([STORAGE_LVM], [LVM backend for storage driver], [check])
])

AC_DEFUN([LIBVIRT_STORAGE_CHECK_LVM], [
  if test "$with_storage_lvm" = "yes" || test "$with_storage_lvm" = "check"; then
    AC_PATH_PROG([PVCREATE], [pvcreate], [], [$LIBVIRT_SBIN_PATH])
    AC_PATH_PROG([VGCREATE], [vgcreate], [], [$LIBVIRT_SBIN_PATH])
    AC_PATH_PROG([LVCREATE], [lvcreate], [], [$LIBVIRT_SBIN_PATH])
    AC_PATH_PROG([PVREMOVE], [pvremove], [], [$LIBVIRT_SBIN_PATH])
    AC_PATH_PROG([VGREMOVE], [vgremove], [], [$LIBVIRT_SBIN_PATH])
    AC_PATH_PROG([LVREMOVE], [lvremove], [], [$LIBVIRT_SBIN_PATH])
    AC_PATH_PROG([LVCHANGE], [lvchange], [], [$LIBVIRT_SBIN_PATH])
    AC_PATH_PROG([VGCHANGE], [vgchange], [], [$LIBVIRT_SBIN_PATH])
    AC_PATH_PROG([VGSCAN], [vgscan], [], [$LIBVIRT_SBIN_PATH])
    AC_PATH_PROG([PVS], [pvs], [], [$LIBVIRT_SBIN_PATH])
    AC_PATH_PROG([VGS], [vgs], [], [$LIBVIRT_SBIN_PATH])
    AC_PATH_PROG([LVS], [lvs], [], [$LIBVIRT_SBIN_PATH])

    if test "$with_storage_lvm" = "yes" ; then
      if test -z "$PVCREATE" ; then AC_MSG_ERROR([We need pvcreate for LVM storage driver]) ; fi
      if test -z "$VGCREATE" ; then AC_MSG_ERROR([We need vgcreate for LVM storage driver]) ; fi
      if test -z "$LVCREATE" ; then AC_MSG_ERROR([We need lvcreate for LVM storage driver]) ; fi
      if test -z "$PVREMOVE" ; then AC_MSG_ERROR([We need pvremove for LVM storage driver]) ; fi
      if test -z "$VGREMOVE" ; then AC_MSG_ERROR([We need vgremove for LVM storage driver]) ; fi
      if test -z "$LVREMOVE" ; then AC_MSG_ERROR([We need lvremove for LVM storage driver]) ; fi
      if test -z "$LVCHANGE" ; then AC_MSG_ERROR([We need lvchange for LVM storage driver]) ; fi
      if test -z "$VGCHANGE" ; then AC_MSG_ERROR([We need vgchange for LVM storage driver]) ; fi
      if test -z "$VGSCAN" ; then AC_MSG_ERROR([We need vgscan for LVM storage driver]) ; fi
      if test -z "$PVS" ; then AC_MSG_ERROR([We need pvs for LVM storage driver]) ; fi
      if test -z "$VGS" ; then AC_MSG_ERROR([We need vgs for LVM storage driver]) ; fi
      if test -z "$LVS" ; then AC_MSG_ERROR([We need lvs for LVM storage driver]) ; fi
    else
      if test -z "$PVCREATE" ; then with_storage_lvm=no ; fi
      if test -z "$VGCREATE" ; then with_storage_lvm=no ; fi
      if test -z "$LVCREATE" ; then with_storage_lvm=no ; fi
      if test -z "$PVREMOVE" ; then with_storage_lvm=no ; fi
      if test -z "$VGREMOVE" ; then with_storage_lvm=no ; fi
      if test -z "$LVREMOVE" ; then with_storage_lvm=no ; fi
      if test -z "$LVCHANGE" ; then with_storage_lvm=no ; fi
      if test -z "$VGCHANGE" ; then with_storage_lvm=no ; fi
      if test -z "$VGSCAN" ; then with_storage_lvm=no ; fi
      if test -z "$PVS" ; then with_storage_lvm=no ; fi
      if test -z "$VGS" ; then with_storage_lvm=no ; fi
      if test -z "$LVS" ; then with_storage_lvm=no ; fi

      if test "$with_storage_lvm" = "check" ; then with_storage_lvm=yes ; fi
    fi

    if test "$with_storage_lvm" = "yes" ; then
      AC_DEFINE_UNQUOTED([WITH_STORAGE_LVM], 1, [whether LVM backend for storage driver is enabled])
      AC_DEFINE_UNQUOTED([PVCREATE],["$PVCREATE"],[Location of pvcreate program])
      AC_DEFINE_UNQUOTED([VGCREATE],["$VGCREATE"],[Location of vgcreate program])
      AC_DEFINE_UNQUOTED([LVCREATE],["$LVCREATE"],[Location of lvcreate program])
      AC_DEFINE_UNQUOTED([PVREMOVE],["$PVREMOVE"],[Location of pvremove program])
      AC_DEFINE_UNQUOTED([VGREMOVE],["$VGREMOVE"],[Location of vgremove program])
      AC_DEFINE_UNQUOTED([LVREMOVE],["$LVREMOVE"],[Location of lvremove program])
      AC_DEFINE_UNQUOTED([LVCHANGE],["$LVCHANGE"],[Location of lvchange program])
      AC_DEFINE_UNQUOTED([VGCHANGE],["$VGCHANGE"],[Location of vgchange program])
      AC_DEFINE_UNQUOTED([VGSCAN],["$VGSCAN"],[Location of vgscan program])
      AC_DEFINE_UNQUOTED([PVS],["$PVS"],[Location of pvs program])
      AC_DEFINE_UNQUOTED([VGS],["$VGS"],[Location of vgs program])
      AC_DEFINE_UNQUOTED([LVS],["$LVS"],[Location of lvs program])
    fi
  fi
  AM_CONDITIONAL([WITH_STORAGE_LVM], [test "$with_storage_lvm" = "yes"])
])

AC_DEFUN([LIBVIRT_STORAGE_RESULT_LVM], [
  LIBVIRT_RESULT([LVM], [$with_storage_lvm])
])
