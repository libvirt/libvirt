dnl The XML catalog file check
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

AC_DEFUN([LIBVIRT_ARG_XML_CATALOG], [
  LIBVIRT_ARG_WITH([XML_CATALOG_FILE],
                   [path to XML catalog file for validating generated html],
                   ['/etc/xml/catalog'])
])

AC_DEFUN([LIBVIRT_CHECK_XML_CATALOG], [
  dnl Specific XML catalog file for validation of generated html
  AC_SUBST([XML_CATALOG_FILE], [$with_xml_catalog_file])
])

AC_DEFUN([LIBVIRT_RESULT_XML_CATALOG], [
  AC_MSG_NOTICE([       XML Catalog: $with_xml_catalog_file])
])
