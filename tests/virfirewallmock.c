/*
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

#include "internal.h"
#include "virfile.h"

char *
virFindFileInPath(const char *file)
{
    if (file &&
        (g_strrstr(file, "ebtables") ||
         g_strrstr(file, "iptables") ||
         g_strrstr(file, "ip6tables"))) {
        return g_strdup(file);
    }

    /* We should not need any other binaries so return NULL. */
    return NULL;
}
