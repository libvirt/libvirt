/*
 * storage_backend.c: internal storage driver backend contract
 *
 * Copyright (C) 2007-2016 Red Hat, Inc.
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

#include <config.h>

#include <string.h>
#include <sys/stat.h>

#include "datatypes.h"
#include "virerror.h"
#include "viralloc.h"
#include "internal.h"
#include "virstoragefile.h"
#include "storage_backend.h"
#include "virlog.h"

#if WITH_STORAGE_LVM
# include "storage_backend_logical.h"
#endif
#if WITH_STORAGE_ISCSI
# include "storage_backend_iscsi.h"
#endif
#if WITH_STORAGE_SCSI
# include "storage_backend_scsi.h"
#endif
#if WITH_STORAGE_MPATH
# include "storage_backend_mpath.h"
#endif
#if WITH_STORAGE_DISK
# include "storage_backend_disk.h"
#endif
#if WITH_STORAGE_DIR
# include "storage_backend_fs.h"
#endif
#if WITH_STORAGE_RBD
# include "storage_backend_rbd.h"
#endif
#if WITH_STORAGE_SHEEPDOG
# include "storage_backend_sheepdog.h"
#endif
#if WITH_STORAGE_GLUSTER
# include "storage_backend_gluster.h"
#endif
#if WITH_STORAGE_ZFS
# include "storage_backend_zfs.h"
#endif
#if WITH_STORAGE_VSTORAGE
# include "storage_backend_vstorage.h"
#endif

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_backend");

static virStorageBackendPtr backends[] = {
#if WITH_STORAGE_DIR
    &virStorageBackendDirectory,
#endif
#if WITH_STORAGE_FS
    &virStorageBackendFileSystem,
    &virStorageBackendNetFileSystem,
#endif
#if WITH_STORAGE_LVM
    &virStorageBackendLogical,
#endif
#if WITH_STORAGE_ISCSI
    &virStorageBackendISCSI,
#endif
#if WITH_STORAGE_SCSI
    &virStorageBackendSCSI,
#endif
#if WITH_STORAGE_MPATH
    &virStorageBackendMpath,
#endif
#if WITH_STORAGE_DISK
    &virStorageBackendDisk,
#endif
#if WITH_STORAGE_RBD
    &virStorageBackendRBD,
#endif
#if WITH_STORAGE_SHEEPDOG
    &virStorageBackendSheepdog,
#endif
#if WITH_STORAGE_GLUSTER
    &virStorageBackendGluster,
#endif
#if WITH_STORAGE_ZFS
    &virStorageBackendZFS,
#endif
#if WITH_STORAGE_VSTORAGE
    &virStorageBackendVstorage,
#endif
    NULL
};


static virStorageFileBackendPtr fileBackends[] = {
#if WITH_STORAGE_FS
    &virStorageFileBackendFile,
    &virStorageFileBackendBlock,
#endif
#if WITH_STORAGE_GLUSTER
    &virStorageFileBackendGluster,
#endif
    NULL
};


virStorageBackendPtr
virStorageBackendForType(int type)
{
    size_t i;
    for (i = 0; backends[i]; i++)
        if (backends[i]->type == type)
            return backends[i];

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("missing backend for pool type %d (%s)"),
                   type, NULLSTR(virStoragePoolTypeToString(type)));
    return NULL;
}


virStorageFileBackendPtr
virStorageFileBackendForTypeInternal(int type,
                                     int protocol,
                                     bool report)
{
    size_t i;

    for (i = 0; fileBackends[i]; i++) {
        if (fileBackends[i]->type == type) {
            if (type == VIR_STORAGE_TYPE_NETWORK &&
                fileBackends[i]->protocol != protocol)
                continue;

            return fileBackends[i];
        }
    }

    if (!report)
        return NULL;

    if (type == VIR_STORAGE_TYPE_NETWORK) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing storage backend for network files "
                         "using %s protocol"),
                       virStorageNetProtocolTypeToString(protocol));
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing storage backend for '%s' storage"),
                       virStorageTypeToString(type));
    }

    return NULL;
}


virStorageFileBackendPtr
virStorageFileBackendForType(int type,
                             int protocol)
{
    return virStorageFileBackendForTypeInternal(type, protocol, true);
}
