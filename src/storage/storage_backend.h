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
typedef int (*virStorageBackendCheckPool)(virStoragePoolObjPtr pool,
                                          bool *active);
typedef int (*virStorageBackendStartPool)(virStoragePoolObjPtr pool);
typedef int (*virStorageBackendBuildPool)(virStoragePoolObjPtr pool,
                                          unsigned int flags);
typedef int (*virStorageBackendRefreshPool)(virStoragePoolObjPtr pool);
typedef int (*virStorageBackendStopPool)(virStoragePoolObjPtr pool);
typedef int (*virStorageBackendDeletePool)(virStoragePoolObjPtr pool,
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
typedef int (*virStorageBackendBuildVol)(virStoragePoolObjPtr pool,
                                         virStorageVolDefPtr vol,
                                         unsigned int flags);
typedef int (*virStorageBackendCreateVol)(virStoragePoolObjPtr pool,
                                          virStorageVolDefPtr vol);
typedef int (*virStorageBackendRefreshVol)(virStoragePoolObjPtr pool,
                                           virStorageVolDefPtr vol);
typedef int (*virStorageBackendDeleteVol)(virStoragePoolObjPtr pool,
                                          virStorageVolDefPtr vol,
                                          unsigned int flags);
typedef int (*virStorageBackendBuildVolFrom)(virStoragePoolObjPtr pool,
                                             virStorageVolDefPtr origvol,
                                             virStorageVolDefPtr newvol,
                                             unsigned int flags);
typedef int (*virStorageBackendVolumeResize)(virStoragePoolObjPtr pool,
                                             virStorageVolDefPtr vol,
                                             unsigned long long capacity,
                                             unsigned int flags);

/* Upon entering this callback passed @obj is unlocked. However,
 * the pool's asyncjobs counter has been incremented and volume's
 * in_use has been adjusted to ensure singular usage. */
typedef int (*virStorageBackendVolumeDownload)(virStoragePoolObjPtr obj,
                                               virStorageVolDefPtr vol,
                                               virStreamPtr stream,
                                               unsigned long long offset,
                                               unsigned long long length,
                                               unsigned int flags);

/* Upon entering this callback passed @obj is unlocked. However,
 * the pool's asyncjobs counter has been incremented and volume's
 * in_use has been adjusted to ensure singular usage. */
typedef int (*virStorageBackendVolumeUpload)(virStoragePoolObjPtr obj,
                                             virStorageVolDefPtr vol,
                                             virStreamPtr stream,
                                             unsigned long long offset,
                                             unsigned long long len,
                                             unsigned int flags);

/* Upon entering this callback passed @obj is unlocked. However,
 * the pool's asyncjobs counter has been incremented and volume's
 * in_use has been adjusted to ensure singular usage. */
typedef int (*virStorageBackendVolumeWipe)(virStoragePoolObjPtr pool,
                                           virStorageVolDefPtr vol,
                                           unsigned int algorithm,
                                           unsigned int flags);

typedef struct _virStorageBackend virStorageBackend;
typedef virStorageBackend *virStorageBackendPtr;

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

virStorageBackendPtr virStorageBackendForType(int type);

int virStorageBackendDriversRegister(bool allmodules);

int virStorageBackendRegister(virStorageBackendPtr backend);

virCapsPtr
virStorageBackendGetCapabilities(void);
