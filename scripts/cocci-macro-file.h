/*
 * cocci-macro-file.h: simplified macro definitions for Coccinelle
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
 * To be used with:
 *   $ spatch --macro-file scripts/cocci-macro-file.h
 */

#pragma once

#define ATTRIBUTE_NONNULL(x)
#define ATTRIBUTE_PACKED

#define G_GNUC_WARN_UNUSED_RESULT
#define G_GNUC_UNUSED
#define G_GNUC_NULL_TERMINATED
#define G_GNUC_NORETURN
#define G_NO_INLINE
#define G_GNUC_FALLTHROUGH
#define G_GNUC_PRINTF(a, b)

#define g_autoptr(x) x##_autoptr
#define g_autofree
#define g_auto(x) x

#define BAD_CAST
