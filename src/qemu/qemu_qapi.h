/*
 * qemu_qapi.h: helper functions for QEMU QAPI schema
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

#ifndef LIBVIRT_QEMU_QAPI_H
# define LIBVIRT_QEMU_QAPI_H

# include "internal.h"

# include "virhash.h"
# include "virjson.h"

int
virQEMUQAPISchemaPathGet(const char *query,
                         virHashTablePtr schema,
                         virJSONValuePtr *entry);

bool
virQEMUQAPISchemaPathExists(const char *query,
                            virHashTablePtr schema);

virHashTablePtr
virQEMUQAPISchemaConvert(virJSONValuePtr schemareply);


#endif /* LIBVIRT_QEMU_QAPI_H */
