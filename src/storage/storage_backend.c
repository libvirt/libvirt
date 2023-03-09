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
 */

#include <config.h>

#include <sys/stat.h>

#include "virerror.h"
#include "internal.h"
#include "storage_backend.h"
#include "virlog.h"
#include "virmodule.h"
#include "virfile.h"
#include "configmake.h"

#if WITH_STORAGE_LVM
# include "storage_backend_logical.h"
#endif
#if WITH_STORAGE_ISCSI
# include "storage_backend_iscsi.h"
#endif
#if WITH_STORAGE_ISCSI_DIRECT
# include "storage_backend_iscsi_direct.h"
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

static virStorageBackend *virStorageBackends[VIR_STORAGE_BACKENDS_MAX];
static size_t virStorageBackendsCount;

#define STORAGE_BACKEND_MODULE_DIR LIBDIR "/libvirt/storage-backend"

static int
virStorageDriverLoadBackendModule(const char *name,
                                  const char *regfunc,
                                  bool forceload)
{
    g_autofree char *modfile = NULL;

    if (!(modfile = virFileFindResourceFull(name,
                                            "libvirt_storage_backend_",
                                            VIR_FILE_MODULE_EXT,
                                            abs_top_builddir "/src",
                                            STORAGE_BACKEND_MODULE_DIR,
                                            "LIBVIRT_STORAGE_BACKEND_DIR")))
        return -1;

    return virModuleLoad(modfile, regfunc, forceload);
}


#define VIR_STORAGE_BACKEND_REGISTER(func, module) \
    if (virStorageDriverLoadBackendModule(module, #func, allbackends) < 0) \
        return -1

int
virStorageBackendDriversRegister(bool allbackends G_GNUC_UNUSED)
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
#if WITH_STORAGE_ISCSI_DIRECT
    VIR_STORAGE_BACKEND_REGISTER(virStorageBackendISCSIDirectRegister, "iscsi-direct");
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
virStorageBackendRegister(virStorageBackend *backend)
{
    VIR_DEBUG("Registering storage backend '%s'",
              virStoragePoolTypeToString(backend->type));

    if (virStorageBackendsCount >= VIR_STORAGE_BACKENDS_MAX) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Too many drivers, cannot register storage backend '%1$s'"),
                       virStoragePoolTypeToString(backend->type));
        return -1;
    }

    virStorageBackends[virStorageBackendsCount] = backend;
    virStorageBackendsCount++;
    return 0;
}


virStorageBackend *
virStorageBackendForType(int type)
{
    size_t i;
    for (i = 0; i < virStorageBackendsCount; i++)
        if (virStorageBackends[i]->type == type)
            return virStorageBackends[i];

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("missing backend for pool type %1$d (%2$s)"),
                   type, NULLSTR(virStoragePoolTypeToString(type)));
    return NULL;
}


virCaps *
virStorageBackendGetCapabilities(void)
{
    virCaps *caps;
    size_t i;

    if (!(caps = virCapabilitiesNew(VIR_ARCH_NONE, false, false)))
        return NULL;

    for (i = 0; i < virStorageBackendsCount; i++)
        virCapabilitiesAddStoragePool(caps, virStorageBackends[i]->type);

    return caps;
}
