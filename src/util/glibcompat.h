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

#pragma once

#include <glib.h>
#include <glib/gstdio.h>

char *vir_g_strdup_printf(const char *msg, ...)
    G_GNUC_PRINTF(1, 2);
char *vir_g_strdup_vprintf(const char *msg, va_list args)
    G_GNUC_PRINTF(1, 0);
gint vir_g_fsync(gint fd);

#if !GLIB_CHECK_VERSION(2, 64, 0)
# define g_strdup_printf vir_g_strdup_printf
# define g_strdup_vprintf vir_g_strdup_vprintf
#endif

#if !GLIB_CHECK_VERSION(2, 63, 0)
# define g_fsync vir_g_fsync
#endif
