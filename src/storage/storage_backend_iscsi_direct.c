/*
 * storage_backend_iscsi_direct.c: storage backend for iSCSI using libiscsi
 *
 * Copyright (C) 2018 Clementine Hayat.
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
 * Author: Clementine Hayat <clem@lse.epita.fr>
 */

#include <config.h>

#include "storage_backend_iscsi_direct.h"
#include "storage_util.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_backend_iscsi_direct");


static int
virStorageBackendISCSIDirectCheckPool(virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                      bool *isActive ATTRIBUTE_UNUSED)
{
    return 0;
}

static int
virStorageBackendISCSIDirectRefreshPool(virStoragePoolObjPtr pool ATTRIBUTE_UNUSED)
{
    return 0;
}

virStorageBackend virStorageBackendISCSIDirect = {
    .type = VIR_STORAGE_POOL_ISCSI_DIRECT,

    .checkPool = virStorageBackendISCSIDirectCheckPool,
    .refreshPool = virStorageBackendISCSIDirectRefreshPool,
};

int
virStorageBackendISCSIDirectRegister(void)
{
    return virStorageBackendRegister(&virStorageBackendISCSIDirect);
}
