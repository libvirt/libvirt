dnl The jansson library
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

AC_DEFUN([LIBVIRT_ARG_JANSSON],[
  LIBVIRT_ARG_WITH_FEATURE([JANSSON], [jansson], [check])
])

AC_DEFUN([LIBVIRT_CHECK_JANSSON],[
  dnl Jansson http://www.digip.org/jansson/
  LIBVIRT_CHECK_PKG([JANSSON], [jansson], [2.5])
  dnl Older versions of Jansson did not preserve the order of object keys
  dnl use this check to guard the tests that are sensitive to this
  LIBVIRT_CHECK_PKG([STABLE_ORDERING_JANSSON], [jansson], [2.8], [true])
])

AC_DEFUN([LIBVIRT_RESULT_JANSSON],[
  LIBVIRT_RESULT_LIB([JANSSON])
])
