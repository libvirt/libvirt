/*
 * virdbuspriv.h: internal APIs for testing DBus code
 *
 * Copyright (C) 2012-2014 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#ifndef LIBVIRT_VIRDBUSPRIV_H_ALLOW
# error "virdbuspriv.h may only be included by virdbus.c or test suites"
#endif /* LIBVIRT_VIRDBUSPRIV_H_ALLOW */

#pragma once

#include "virdbus.h"

#if defined(WITH_DBUS) && !HAVE_DBUSBASICVALUE
/* Copied (and simplified) from dbus 1.6.12, for use with older dbus headers */
typedef union
{
  dbus_int16_t  i16;   /**< as int16 */
  dbus_uint16_t u16;   /**< as int16 */
  dbus_int32_t  i32;   /**< as int32 */
  dbus_uint32_t u32;   /**< as int32 */
  dbus_bool_t   bool_val; /**< as boolean */
  dbus_int64_t  i64;   /**< as int64 */
  dbus_uint64_t u64;   /**< as int64 */
  double dbl;          /**< as double */
  unsigned char byt;   /**< as byte */
} DBusBasicValue;
#endif

int virDBusMessageEncodeArgs(DBusMessage* msg,
                             const char *types,
                             va_list args);

int virDBusMessageDecodeArgs(DBusMessage* msg,
                             const char *types,
                             va_list args);

int virDBusMessageEncode(DBusMessage* msg,
                         const char *types,
                         ...);
