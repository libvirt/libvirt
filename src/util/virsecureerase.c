/*
 * virsecureerase.c: Secure clearing of memory
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

#include <config.h>

#include <string.h>

#include "virsecureerase.h"

/**
 * virSecureErase:
 * @ptr: pointer to memory to clear
 * @size: size of memory to clear
 *
 * Clear @size bytes of memory at @ptr.
 *
 * Note that for now this is implemented using memset which is not secure as
 * it can be optimized out.
 *
 * Also note that there are possible leftover direct uses of memset.
 */
void
virSecureErase(void *ptr,
               size_t size)
{
    if (!ptr || size == 0)
        return;

#ifdef WITH_EXPLICIT_BZERO
    explicit_bzero(ptr, size);
#else
    memset(ptr, 0, size);
#endif
}

/**
 * virSecureEraseString:
 * @str: String to securely erase
 */
void
virSecureEraseString(char *str)
{
    if (!str)
        return;

    virSecureErase(str, strlen(str));
}
