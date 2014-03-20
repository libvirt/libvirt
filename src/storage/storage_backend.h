/*
 * storage_backend.h: internal storage driver backend contract
 *
 * Copyright (C) 2007-2010, 2012-2014 Red Hat, Inc.
 * Copyright (C) 2007-2008 Daniel P. Berrange
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_STORAGE_BACKEND_H__
# define __VIR_STORAGE_BACKEND_H__

# include <sys/stat.h>

# include "internal.h"
# include "storage_conf.h"
# include "vircommand.h"
# include "storage_driver.h"

typedef char * (*virStorageBackendFindPoolSources)(virConnectPtr conn,
                                                   const char *srcSpec,
                                                   unsigned int flags);
typedef int (*virStorageBackendCheckPool)(virConnectPtr conn,
                                          virStoragePoolObjPtr pool,
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

/* File creation/cloning functions used for cloning between backends */
int virStorageBackendCreateRaw(virConnectPtr conn,
                               virStoragePoolObjPtr pool,
                               virStorageVolDefPtr vol,
                               virStorageVolDefPtr inputvol,
                               unsigned int flags);
virStorageBackendBuildVolFrom
virStorageBackendGetBuildVolFromFunction(virStorageVolDefPtr vol,
                                         virStorageVolDefPtr inputvol);
int virStorageBackendFindFSImageTool(char **tool);
virStorageBackendBuildVolFrom
virStorageBackendFSImageToolTypeToFunc(int tool_type);


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
};

virStorageBackendPtr virStorageBackendForType(int type);

int virStorageBackendVolOpen(const char *path)
ATTRIBUTE_RETURN_CHECK
ATTRIBUTE_NONNULL(1);

/* VolOpenCheckMode flags */
enum {
    VIR_STORAGE_VOL_OPEN_ERROR  = 1 << 0, /* warn if unexpected type
                                           * encountered */
    VIR_STORAGE_VOL_OPEN_REG    = 1 << 1, /* regular files okay */
    VIR_STORAGE_VOL_OPEN_BLOCK  = 1 << 2, /* block files okay */
    VIR_STORAGE_VOL_OPEN_CHAR   = 1 << 3, /* char files okay */
    VIR_STORAGE_VOL_OPEN_DIR    = 1 << 4, /* directories okay */
};

# define VIR_STORAGE_VOL_OPEN_DEFAULT (VIR_STORAGE_VOL_OPEN_ERROR    |\
                                       VIR_STORAGE_VOL_OPEN_REG      |\
                                       VIR_STORAGE_VOL_OPEN_BLOCK)

int virStorageBackendVolOpenCheckMode(const char *path, struct stat *sb,
                                      unsigned int flags)
    ATTRIBUTE_RETURN_CHECK
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int virStorageBackendUpdateVolInfo(virStorageVolDefPtr vol,
                                   int withCapacity);
int virStorageBackendUpdateVolInfoFlags(virStorageVolDefPtr vol,
                                        int withCapacity,
                                        unsigned int openflags);
int virStorageBackendUpdateVolTargetInfo(virStorageVolTargetPtr target,
                                         unsigned long long *allocation,
                                         unsigned long long *capacity,
                                         unsigned int openflags);
int virStorageBackendUpdateVolTargetInfoFD(virStorageVolTargetPtr target,
                                           int fd,
                                           struct stat *sb,
                                           unsigned long long *allocation,
                                           unsigned long long *capacity);
int virStorageBackendDetectBlockVolFormatFD(virStorageVolTargetPtr target,
                                            int fd);

char *virStorageBackendStablePath(virStoragePoolObjPtr pool,
                                  const char *devpath,
                                  bool loop);

virCommandPtr
virStorageBackendCreateQemuImgCmd(virConnectPtr conn,
                                  virStoragePoolObjPtr pool,
                                  virStorageVolDefPtr vol,
                                  virStorageVolDefPtr inputvol,
                                  unsigned int flags,
                                  const char *create_tool,
                                  int imgformat);

/* ------- virStorageFile backends ------------ */
typedef int
(*virStorageFileBackendInit)(virStorageFilePtr file);

typedef void
(*virStorageFileBackendDeinit)(virStorageFilePtr file);

typedef int
(*virStorageFileBackendCreate)(virStorageFilePtr file);

typedef int
(*virStorageFileBackendUnlink)(virStorageFilePtr file);

typedef int
(*virStorageFileBackendStat)(virStorageFilePtr file,
                             struct stat *st);

virStorageFileBackendPtr virStorageFileBackendForType(int type, int protocol);

struct _virStorageFileBackend {
    int type;
    int protocol;

    /* All storage file callbacks may be omitted if not implemented */

    /* The following group of callbacks is expected to set a libvirt
     * error on failure. */
    virStorageFileBackendInit backendInit;
    virStorageFileBackendDeinit backendDeinit;

    /* The following group of callbacks is expected to set errno
     * and return -1 on error. No libvirt error shall be reported */
    virStorageFileBackendCreate storageFileCreate;
    virStorageFileBackendUnlink storageFileUnlink;
    virStorageFileBackendStat   storageFileStat;
};

#endif /* __VIR_STORAGE_BACKEND_H__ */
