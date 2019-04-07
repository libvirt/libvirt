/*
 * testutilsqemuschema.h: helper functions for QEMU QAPI schema testing
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

#ifndef LIBVIRT_TESTUTILSQEMUSCHEMA_H
# define LIBVIRT_TESTUTILSQEMUSCHEMA_H

# include "virhash.h"
# include "virjson.h"
# include "virbuffer.h"

int
testQEMUSchemaValidate(virJSONValuePtr obj,
                       virJSONValuePtr root,
                       virHashTablePtr schema,
                       virBufferPtr debug);

virJSONValuePtr
testQEMUSchemaGetLatest(void);

virHashTablePtr
testQEMUSchemaLoad(void);

#endif /* LIBVIRT_TESTUTILSQEMUSCHEMA_H */
