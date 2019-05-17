dnl The External programs check
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

AC_DEFUN([LIBVIRT_CHECK_EXTERNAL_PROGRAMS], [
  dnl Do we have rpcgen?
  AC_PATH_PROGS([RPCGEN], [rpcgen portable-rpcgen], [no])
  AM_CONDITIONAL([HAVE_RPCGEN], [test "x$ac_cv_path_RPCGEN" != "xno"])

  dnl Miscellaneous external programs.
  AC_PATH_PROG([XMLLINT], [xmllint], [])
  if test -z "$XMLLINT"
  then
    AC_MSG_ERROR("xmllint is required to build libvirt")
  fi
  AC_PATH_PROG([XSLTPROC], [xsltproc], [])
  if test -z "$XSLTPROC"
  then
    AC_MSG_ERROR("xsltproc is required to build libvirt")
  fi
  AC_PATH_PROG([AUGPARSE], [augparse], [/usr/bin/augparse])
  AC_PROG_MKDIR_P
  AC_PROG_LN_S

  dnl External programs that we can use if they are available.
  dnl We will hard-code paths to these programs unless we cannot
  dnl detect them, in which case we'll search for the program
  dnl along the $PATH at runtime and fail if it's not there.
  AC_PATH_PROG([DMIDECODE], [dmidecode], [dmidecode], [$LIBVIRT_SBIN_PATH])
  AC_PATH_PROG([DNSMASQ], [dnsmasq], [dnsmasq], [$LIBVIRT_SBIN_PATH])
  AC_PATH_PROG([RADVD], [radvd], [radvd], [$LIBVIRT_SBIN_PATH])
  AC_PATH_PROG([TC], [tc], [tc], [$LIBVIRT_SBIN_PATH])
  AC_PATH_PROG([UDEVADM], [udevadm], [udevadm], [$LIBVIRT_SBIN_PATH])
  AC_PATH_PROG([MODPROBE], [modprobe], [modprobe], [$LIBVIRT_SBIN_PATH])
  AC_PATH_PROG([RMMOD], [rmmod], [rmmod], [$LIBVIRT_SBIN_PATH])
  AC_PATH_PROG([MMCTL], [mm-ctl], [mm-ctl], [$LIBVIRT_SBIN_PATH])
  AC_PATH_PROG([OVSVSCTL], [ovs-vsctl], [ovs-vsctl], [$LIBVIRT_SBIN_PATH])
  AC_PATH_PROG([SCRUB], [scrub], [scrub], [$LIBVIRT_SBIN_PATH])
  AC_PATH_PROG([ADDR2LINE], [addr2line], [addr2line], [$LIBVIRT_SBIN_PATH])

  AC_DEFINE_UNQUOTED([DMIDECODE], ["$DMIDECODE"],
                     [Location or name of the dmidecode program])
  AC_DEFINE_UNQUOTED([DNSMASQ], ["$DNSMASQ"],
                     [Location or name of the dnsmasq program])
  AC_DEFINE_UNQUOTED([RADVD], ["$RADVD"],
                     [Location or name of the radvd program])
  AC_DEFINE_UNQUOTED([TC], ["$TC"],
                     [Location or name of the tc program (see iproute2)])
  AC_DEFINE_UNQUOTED([MMCTL], ["$MMCTL"],
                     [Location or name of the mm-ctl program])
  AC_DEFINE_UNQUOTED([OVSVSCTL], ["$OVSVSCTL"],
                     [Location or name of the ovs-vsctl program])
  AC_DEFINE_UNQUOTED([UDEVADM], ["$UDEVADM"],
                     [Location or name of the udevadm program])
  AC_DEFINE_UNQUOTED([MODPROBE], ["$MODPROBE"],
                     [Location or name of the modprobe program])
  AC_DEFINE_UNQUOTED([RMMOD], ["$RMMOD"],
                     [Location or name of the rmmod program])
  AC_DEFINE_UNQUOTED([SCRUB], ["$SCRUB"],
                     [Location or name of the scrub program (for wiping algorithms)])
  AC_DEFINE_UNQUOTED([ADDR2LINE], ["$ADDR2LINE"],
                     [Location of addr2line program])

  AC_PATH_PROG([IP_PATH], [ip], [/sbin/ip], [$LIBVIRT_SBIN_PATH])
  AC_DEFINE_UNQUOTED([IP_PATH], ["$IP_PATH"], [path to ip binary])

  AC_PATH_PROG([IPTABLES_PATH], [iptables], /sbin/iptables, [$LIBVIRT_SBIN_PATH])
  AC_DEFINE_UNQUOTED([IPTABLES_PATH], ["$IPTABLES_PATH"], [path to iptables binary])

  AC_PATH_PROG([IP6TABLES_PATH], [ip6tables], [/sbin/ip6tables], [$LIBVIRT_SBIN_PATH])
  AC_DEFINE_UNQUOTED([IP6TABLES_PATH], ["$IP6TABLES_PATH"], [path to ip6tables binary])

  AC_PATH_PROG([EBTABLES_PATH], [ebtables], [/sbin/ebtables], [$LIBVIRT_SBIN_PATH])
  AC_DEFINE_UNQUOTED([EBTABLES_PATH], ["$EBTABLES_PATH"], [path to ebtables binary])
])
