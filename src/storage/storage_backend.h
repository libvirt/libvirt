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

#ifndef __VIR_STORAGE_BACKEND_H__
# define __VIR_STORAGE_BACKEND_H__

# include <sys/stat.h>

# include "internal.h"
# include "virstorageobj.h"
# include "storage_driver.h"

typedef char * (*virStorageBackendFindPoolSources)(virConnectPtr conn,
                                                   const char *srcSpec,
                                                   unsigned int flags);
typedef int (*virStorageBackendCheckPool)(virStoragePoolObjPtr pool,
                                          bool *active);
typedef int (*virStorageBackendStartPool)(virConnectPtr conn,
                                          virStoragePoolObjPtr pool);
typedef int (*virStorageBackendBuildPool)(virConnectPtr conn,
                                          virStoragePoolObjPtr pool,
                                          unsigned int flags);
typedef int (*virStorageBackendRefreshPool)(virConnectPtr conn,
                                            virStoragePoolObjPtr pool);
typedef int (*virStorageBackendStopPool)(virConnectPtr conn,
                                         virStoragePoolObjPtr pool);
typedef int (*virStorageBackendDeletePool)(virConnectPtr conn,
                                           virStoragePoolObjPtr pool,
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
typedef int (*virStorageBackendBuildVol)(virConnectPtr conn,
                                         virStoragePoolObjPtr pool,
                                         virStorageVolDefPtr vol,
                                         unsigned int flags);
typedef int (*virStorageBackendCreateVol)(virConnectPtr conn,
                                          virStoragePoolObjPtr pool,
                                          virStorageVolDefPtr vol);
typedef int (*virStorageBackendRefreshVol)(virConnectPtr conn,
                                           virStoragePoolObjPtr pool,
                                           virStorageVolDefPtr vol);
typedef int (*virStorageBackendDeleteVol)(virConnectPtr conn,
                                          virStoragePoolObjPtr pool,
                                          virStorageVolDefPtr vol,
                                          unsigned int flags);
typedef int (*virStorageBackendBuildVolFrom)(virConnectPtr conn,
                                             virStoragePoolObjPtr pool,
                                             virStorageVolDefPtr origvol,
                                             virStorageVolDefPtr newvol,
                                             unsigned int flags);
typedef int (*virStorageBackendVolumeResize)(virConnectPtr conn,
                                             virStoragePoolObjPtr pool,
                                             virStorageVolDefPtr vol,
                                             unsigned long long capacity,
                                             unsigned int flags);
typedef int (*virStorageBackendVolumeDownload)(virConnectPtr conn,
                                               virStoragePoolObjPtr obj,
                                               virStorageVolDefPtr vol,
                                               virStreamPtr stream,
                                               unsigned long long offset,
                                               unsigned long long length,
                                               unsigned int flags);
typedef int (*virStorageBackendVolumeUpload)(virConnectPtr conn,
                                             virStoragePoolObjPtr obj,
                                             virStorageVolDefPtr vol,
                                             virStreamPtr stream,
                                             unsigned long long offset,
                                             unsigned long long len,
                                             unsigned int flags);
typedef int (*virStorageBackendVolumeWipe)(virConnectPtr conn,
                                           virStoragePoolObjPtr pool,
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

/* ------- virStorageFile backends ------------ */
typedef struct _virStorageFileBackend virStorageFileBackend;
typedef virStorageFileBackend *virStorageFileBackendPtr;

struct _virStorageDriverData {
    virStorageFileBackendPtr backend;
    void *priv;

    uid_t uid;
    gid_t gid;
};

typedef int
(*virStorageFileBackendInit)(virStorageSourcePtr src);

typedef void
(*virStorageFileBackendDeinit)(virStorageSourcePtr src);

typedef int
(*virStorageFileBackendCreate)(virStorageSourcePtr src);

typedef int
(*virStorageFileBackendUnlink)(virStorageSourcePtr src);

typedef int
(*virStorageFileBackendStat)(virStorageSourcePtr src,
                             struct stat *st);

typedef ssize_t
(*virStorageFileBackendRead)(virStorageSourcePtr src,
                             size_t offset,
                             size_t len,
                             char **buf);

typedef const char *
(*virStorageFileBackendGetUniqueIdentifier)(virStorageSourcePtr src);

typedef int
(*virStorageFileBackendAccess)(virStorageSourcePtr src,
                               int mode);

typedef int
(*virStorageFileBackendChown)(const virStorageSource *src,
                              uid_t uid,
                              gid_t gid);

virStorageFileBackendPtr virStorageFileBackendForType(int type, int protocol);
virStorageFileBackendPtr virStorageFileBackendForTypeInternal(int type,
                                                              int protocol,
                                                              bool report);


struct _virStorageFileBackend {
    int type;
    int protocol;

    /* All storage file callbacks may be omitted if not implemented */

    /* The following group of callbacks is expected to set a libvirt
     * error on failure. */
    virStorageFileBackendInit backendInit;
    virStorageFileBackendDeinit backendDeinit;
    virStorageFileBackendRead storageFileRead;
    virStorageFileBackendGetUniqueIdentifier storageFileGetUniqueIdentifier;

    /* The following group of callbacks is expected to set errno
     * and return -1 on error. No libvirt error shall be reported */
    virStorageFileBackendCreate storageFileCreate;
    virStorageFileBackendUnlink storageFileUnlink;
    virStorageFileBackendStat   storageFileStat;
    virStorageFileBackendAccess storageFileAccess;
    virStorageFileBackendChown  storageFileChown;
};

int virStorageBackendDriversRegister(bool allmodules);

int virStorageBackendRegister(virStorageBackendPtr backend);
int virStorageBackendFileRegister(virStorageFileBackendPtr backend);

#endif /* __VIR_STORAGE_BACKEND_H__ */
