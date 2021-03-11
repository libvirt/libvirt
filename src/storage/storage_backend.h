/*
 * storage_backend.h: internal storage driver backend contract
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

#include <sys/stat.h>

#include "internal.h"
#include "virstorageobj.h"
#include "storage_driver.h"

typedef char * (*virStorageBackendFindPoolSources)(const char *srcSpec,
                                                   unsigned int flags);
typedef int (*virStorageBackendCheckPool)(virStoragePoolObj *pool,
                                          bool *active);
typedef int (*virStorageBackendStartPool)(virStoragePoolObj *pool);
typedef int (*virStorageBackendBuildPool)(virStoragePoolObj *pool,
                                          unsigned int flags);
typedef int (*virStorageBackendRefreshPool)(virStoragePoolObj *pool);
typedef int (*virStorageBackendStopPool)(virStoragePoolObj *pool);
typedef int (*virStorageBackendDeletePool)(virStoragePoolObj *pool,
                                           unsigned int flags);

/* A 'buildVol' backend must remove any volume created on error since
 * the storage driver does not distinguish whether the failure is due
 * to failure to create the volume, to reserve any space necessary for
 * the volume, to get data about the volume, to change it's accessibility,
 * etc. This avoids issues arising from a creation failure due to some
 * external action which created a volume of the same name that libvirt
 * was not aware of between checking the pool and the create attempt. It
 * also avoids extra round trips to just delete a file.
 */
typedef int (*virStorageBackendBuildVol)(virStoragePoolObj *pool,
                                         virStorageVolDef *vol,
                                         unsigned int flags);
typedef int (*virStorageBackendCreateVol)(virStoragePoolObj *pool,
                                          virStorageVolDef *vol);
typedef int (*virStorageBackendRefreshVol)(virStoragePoolObj *pool,
                                           virStorageVolDef *vol);
typedef int (*virStorageBackendDeleteVol)(virStoragePoolObj *pool,
                                          virStorageVolDef *vol,
                                          unsigned int flags);
typedef int (*virStorageBackendBuildVolFrom)(virStoragePoolObj *pool,
                                             virStorageVolDef *origvol,
                                             virStorageVolDef *newvol,
                                             unsigned int flags);
typedef int (*virStorageBackendVolumeResize)(virStoragePoolObj *pool,
                                             virStorageVolDef *vol,
                                             unsigned long long capacity,
                                             unsigned int flags);

/* Upon entering this callback passed @obj is unlocked. However,
 * the pool's asyncjobs counter has been incremented and volume's
 * in_use has been adjusted to ensure singular usage. */
typedef int (*virStorageBackendVolumeDownload)(virStoragePoolObj *obj,
                                               virStorageVolDef *vol,
                                               virStreamPtr stream,
                                               unsigned long long offset,
                                               unsigned long long length,
                                               unsigned int flags);

/* Upon entering this callback passed @obj is unlocked. However,
 * the pool's asyncjobs counter has been incremented and volume's
 * in_use has been adjusted to ensure singular usage. */
typedef int (*virStorageBackendVolumeUpload)(virStoragePoolObj *obj,
                                             virStorageVolDef *vol,
                                             virStreamPtr stream,
                                             unsigned long long offset,
                                             unsigned long long len,
                                             unsigned int flags);

/* Upon entering this callback passed @obj is unlocked. However,
 * the pool's asyncjobs counter has been incremented and volume's
 * in_use has been adjusted to ensure singular usage. */
typedef int (*virStorageBackendVolumeWipe)(virStoragePoolObj *pool,
                                           virStorageVolDef *vol,
                                           unsigned int algorithm,
                                           unsigned int flags);

typedef struct _virStorageBackend virStorageBackend;

/* Callbacks are optional unless documented otherwise; but adding more
 * callbacks provides better pool support.  */
struct _virStorageBackend {
    int type;

    virStorageBackendFindPoolSources findPoolSources;
    virStorageBackendCheckPool checkPool;
    virStorageBackendStartPool startPool;
    virStorageBackendBuildPool buildPool;
    virStorageBackendRefreshPool refreshPool; /* Must be non-NULL */
    virStorageBackendStopPool stopPool;
    virStorageBackendDeletePool deletePool;

    virStorageBackendBuildVol buildVol;
    virStorageBackendBuildVolFrom buildVolFrom;
    virStorageBackendCreateVol createVol;
    virStorageBackendRefreshVol refreshVol;
    virStorageBackendDeleteVol deleteVol;
    virStorageBackendVolumeResize resizeVol;
    virStorageBackendVolumeUpload uploadVol;
    virStorageBackendVolumeDownload downloadVol;
    virStorageBackendVolumeWipe wipeVol;
};

virStorageBackend *virStorageBackendForType(int type);

int virStorageBackendDriversRegister(bool allmodules);

int virStorageBackendRegister(virStorageBackend *backend);

virCaps *
virStorageBackendGetCapabilities(void);
