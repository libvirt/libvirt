/*
 * storage_capabilities.h: storage pool capabilities XML processing
 *
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

#ifndef LIBVIRT_STORAGE_CAPABILITIES_H
# define LIBVIRT_STORAGE_CAPABILITIES_H

# include "internal.h"

typedef struct _virStoragePoolCaps virStoragePoolCaps;
typedef virStoragePoolCaps *virStoragePoolCapsPtr;
struct _virStoragePoolCaps {
    virObjectLockable parent;

    virCapsPtr driverCaps;
};

virStoragePoolCapsPtr
virStoragePoolCapsNew(virCapsPtr driverCaps);

char *
virStoragePoolCapsFormat(virStoragePoolCapsPtr const caps);


#endif /* LIBVIRT_STORAGE_CAPABILITIES_H */
