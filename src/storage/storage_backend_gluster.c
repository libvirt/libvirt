/*
 * storage_backend_gluster.c: storage backend for Gluster handling
 *
 * Copyright (C) 2013 Red Hat, Inc.
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

#include <glusterfs/api/glfs.h>

#include "virerror.h"
#include "storage_backend_gluster.h"
#include "storage_conf.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE


static int
virStorageBackendGlusterRefreshPool(virConnectPtr conn ATTRIBUTE_UNUSED,
                                    virStoragePoolObjPtr pool ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("gluster pool type not fully supported yet"));
    return -1;
}

virStorageBackend virStorageBackendGluster = {
    .type = VIR_STORAGE_POOL_GLUSTER,

    .refreshPool = virStorageBackendGlusterRefreshPool,
};
