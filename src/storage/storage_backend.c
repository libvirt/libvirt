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
#include "virfile.h"
#include "configmake.h"

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

#define VIR_STORAGE_BACKENDS_MAX 20

static virStorageBackendPtr virStorageBackends[VIR_STORAGE_BACKENDS_MAX];
static size_t virStorageBackendsCount;
static virStorageFileBackendPtr virStorageFileBackends[VIR_STORAGE_BACKENDS_MAX];
static size_t virStorageFileBackendsCount;

#if WITH_DRIVER_MODULES

# define STORAGE_BACKEND_MODULE_DIR LIBDIR "/libvirt/storage-backend"

static int
virStorageDriverLoadBackendModule(const char *name,
                                  const char *regfunc)
{
    char *modfile = NULL;
    int ret;

    if (!(modfile = virFileFindResourceFull(name,
                                            "libvirt_storage_backend_",
                                            ".so",
                                            abs_topbuilddir "/src/.libs",
                                            STORAGE_BACKEND_MODULE_DIR,
                                            "LIBVIRT_STORAGE_BACKEND_DIR")))
        return 1;

    ret = virDriverLoadModuleFull(modfile, regfunc, NULL);

    VIR_FREE(modfile);

    return ret;
}


# define VIR_STORAGE_BACKEND_REGISTER(func, module)                            \
    if (virStorageDriverLoadBackendModule(module, #func) < 0)                  \
        return -1
#else
# define VIR_STORAGE_BACKEND_REGISTER(func, module)                            \
    if (func() < 0)                                                            \
        return -1
#endif

int
virStorageBackendDriversRegister(void)
{
#if WITH_STORAGE_DIR || WITH_STORAGE_FS
    VIR_STORAGE_BACKEND_REGISTER(virStorageBackendFsRegister, "fs");
#endif
#if WITH_STORAGE_LVM
    VIR_STORAGE_BACKEND_REGISTER(virStorageBackendLogicalRegister, "logical");
#endif
#if WITH_STORAGE_ISCSI
    VIR_STORAGE_BACKEND_REGISTER(virStorageBackendISCSIRegister, "iscsi");
#endif
#if WITH_STORAGE_SCSI
    VIR_STORAGE_BACKEND_REGISTER(virStorageBackendSCSIRegister, "scsi");
#endif
#if WITH_STORAGE_MPATH
    VIR_STORAGE_BACKEND_REGISTER(virStorageBackendMpathRegister, "mpath");
#endif
#if WITH_STORAGE_DISK
    VIR_STORAGE_BACKEND_REGISTER(virStorageBackendDiskRegister, "disk");
#endif
#if WITH_STORAGE_RBD
    VIR_STORAGE_BACKEND_REGISTER(virStorageBackendRBDRegister, "rbd");
#endif
#if WITH_STORAGE_SHEEPDOG
    VIR_STORAGE_BACKEND_REGISTER(virStorageBackendSheepdogRegister, "sheepdog");
#endif
#if WITH_STORAGE_GLUSTER
    VIR_STORAGE_BACKEND_REGISTER(virStorageBackendGlusterRegister, "gluster");
#endif
#if WITH_STORAGE_ZFS
    VIR_STORAGE_BACKEND_REGISTER(virStorageBackendZFSRegister, "zfs");
#endif
#if WITH_STORAGE_VSTORAGE
    VIR_STORAGE_BACKEND_REGISTER(virStorageBackendVstorageRegister, "vstorage");
#endif

    return 0;
}
#undef VIR_STORAGE_BACKEND_REGISTER


int
virStorageBackendRegister(virStorageBackendPtr backend)
{
    VIR_DEBUG("Registering storage backend '%s'",
              virStorageTypeToString(backend->type));

    if (virStorageBackendsCount >= VIR_STORAGE_BACKENDS_MAX) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Too many drivers, cannot register storage backend '%s'"),
                       virStorageTypeToString(backend->type));
        return -1;
    }

    virStorageBackends[virStorageBackendsCount] = backend;
    virStorageBackendsCount++;
    return 0;
}


int
virStorageBackendFileRegister(virStorageFileBackendPtr backend)
{
    VIR_DEBUG("Registering storage file backend '%s' protocol '%s'",
              virStorageTypeToString(backend->type),
              virStorageNetProtocolTypeToString(backend->protocol));

    if (virStorageFileBackendsCount >= VIR_STORAGE_BACKENDS_MAX) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Too many drivers, cannot register storage file "
                         "backend '%s'"),
                       virStorageTypeToString(backend->type));
        return -1;
    }

    virStorageFileBackends[virStorageFileBackendsCount] = backend;
    virStorageFileBackendsCount++;
    return 0;
}


virStorageBackendPtr
virStorageBackendForType(int type)
{
    size_t i;
    for (i = 0; i < virStorageBackendsCount; i++)
        if (virStorageBackends[i]->type == type)
            return virStorageBackends[i];

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

    for (i = 0; i < virStorageFileBackendsCount; i++) {
        if (virStorageFileBackends[i]->type == type) {
            if (type == VIR_STORAGE_TYPE_NETWORK &&
                virStorageFileBackends[i]->protocol != protocol)
                continue;

            return virStorageFileBackends[i];
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
