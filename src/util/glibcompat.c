/*
 * Copyright (C) 2019 Red Hat, Inc.
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
 */

#include <config.h>

#include <stdlib.h>
#include <unistd.h>

#include "glibcompat.h"

#undef g_strdup_printf
#undef g_strdup_vprintf
#undef g_fsync

/* Due to a bug in glib, g_strdup_printf() nor g_strdup_vprintf()
 * abort on OOM.  It's fixed in glib's upstream. Provide our own
 * implementation until the fix gets distributed. */
char *
vir_g_strdup_printf(const char *msg, ...)
{
  va_list args;
  char *ret;
  va_start(args, msg);
  ret = g_strdup_vprintf(msg, args);
  if (!ret)
    abort();
  va_end(args);
  return ret;
}


char *
vir_g_strdup_vprintf(const char *msg, va_list args)
{
  char *ret;
  ret = g_strdup_vprintf(msg, args);
  if (!ret)
    abort();
  return ret;
}


/* Drop when min glib >= 2.63.0 */
gint
vir_g_fsync(gint fd)
{
#ifdef G_OS_WIN32
  return _commit(fd);
#else
  return fsync(fd);
#endif
}
