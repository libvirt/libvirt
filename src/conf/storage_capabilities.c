/*
 * storage_capabilities.c: storage pool capabilities XML processing
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

#include <config.h>

#include "virerror.h"
#include "capabilities.h"
#include "storage_capabilities.h"
#include "storage_conf.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_CAPABILITIES

VIR_LOG_INIT("conf.storage_capabilities");

static virClass *virStoragePoolCapsClass;


static void
virStoragePoolCapsDispose(void *obj)
{
    virStoragePoolCaps *caps = obj;
    VIR_DEBUG("obj=%p", caps);

    virObjectUnref(caps->driverCaps);
}


static int
virStoragePoolCapsOnceInit(void)
{
    if (!VIR_CLASS_NEW(virStoragePoolCaps, virClassForObjectLockable()))
        return -1;
    return 0;
}

VIR_ONCE_GLOBAL_INIT(virStoragePoolCaps);


virStoragePoolCaps *
virStoragePoolCapsNew(virCaps *driverCaps)
{
    virStoragePoolCaps *caps = NULL;

    if (virStoragePoolCapsInitialize() < 0)
        return NULL;

    if (!(caps = virObjectLockableNew(virStoragePoolCapsClass)))
        return NULL;

    caps->driverCaps = virObjectRef(driverCaps);

    return caps;
}


static bool
virStoragePoolCapsIsLoaded(virCaps *driverCaps,
                           int poolType)
{
    size_t i;

    if (!driverCaps)
        return false;

    for (i = 0; i < driverCaps->npools; i++) {
        if (driverCaps->pools[i]->type == poolType)
            return true;
    }

    return false;
}


static int
virStoragePoolCapsFormatPool(virBuffer *buf,
                             int poolType,
                             const virStoragePoolCaps *caps)
{
    bool isLoaded = virStoragePoolCapsIsLoaded(caps->driverCaps, poolType);

    virBufferAsprintf(buf, "<pool type='%s' supported='%s'>\n",
                      virStoragePoolTypeToString(poolType),
                      isLoaded ? "yes" : "no");
    virBufferAdjustIndent(buf, 2);

    if (virStoragePoolOptionsFormatPool(buf, poolType) < 0)
        return -1;

    if (virStoragePoolOptionsFormatVolume(buf, poolType) < 0)
        return -1;

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</pool>\n");
    return 0;
}


char *
virStoragePoolCapsFormat(const virStoragePoolCaps *caps)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    size_t i;

    virBufferAddLit(&buf, "<storagepoolCapabilities>\n");
    virBufferAdjustIndent(&buf, 2);
    for (i = 0; i < VIR_STORAGE_POOL_LAST; i++) {
        if (virStoragePoolCapsFormatPool(&buf, i, caps) < 0)
            return NULL;
    }
    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</storagepoolCapabilities>\n");

    return virBufferContentAndReset(&buf);
}
