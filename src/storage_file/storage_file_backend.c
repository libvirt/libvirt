/*
 * storage_file_backend.c: internal storage source backend contract
 *
 * Copyright (C) 2007-2018 Red Hat, Inc.
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
#include "storage_file_backend.h"
#include "virlog.h"
#include "virmodule.h"
#include "virfile.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_source_backend");

#define VIR_STORAGE_BACKENDS_MAX 20

static virStorageFileBackend *virStorageFileBackends[VIR_STORAGE_BACKENDS_MAX];
static size_t virStorageFileBackendsCount;

#if WITH_STORAGE_DIR || WITH_STORAGE_FS || WITH_STORAGE_GLUSTER

# define STORAGE_FILE_MODULE_DIR LIBDIR "/libvirt/storage-file"

static int
virStorageFileLoadBackendModule(const char *name,
                                const char *regfunc,
                                bool forceload)
{
    g_autofree char *modfile = NULL;
    int ret;

    if (!(modfile = virFileFindResourceFull(name,
                                            "libvirt_storage_file_",
                                            VIR_FILE_MODULE_EXT,
                                            abs_top_builddir "/src",
                                            STORAGE_FILE_MODULE_DIR,
                                            "LIBVIRT_STORAGE_FILE_DIR")))
        return -1;

    ret = virModuleLoad(modfile, regfunc, forceload);

    return ret;
}
#endif /* WITH_STORAGE_DIR || WITH_STORAGE_FS || WITH_STORAGE_GLUSTER */

static int virStorageFileBackendOnceInit(void)
{
#if WITH_STORAGE_DIR || WITH_STORAGE_FS
    if (virStorageFileLoadBackendModule("fs", "virStorageFileFsRegister", false) < 0)
        return -1;
#endif /* WITH_STORAGE_DIR || WITH_STORAGE_FS */
#if WITH_STORAGE_GLUSTER
    if (virStorageFileLoadBackendModule("gluster", "virStorageFileGlusterRegister", false) < 0)
        return -1;
#endif /* WITH_STORAGE_GLUSTER */
    return 0;
}

VIR_ONCE_GLOBAL_INIT(virStorageFileBackend);

int
virStorageFileBackendRegister(virStorageFileBackend *backend)
{
    VIR_DEBUG("Registering storage file backend '%s' protocol '%s'",
              virStorageTypeToString(backend->type),
              virStorageNetProtocolTypeToString(backend->protocol));

    if (virStorageFileBackendsCount >= VIR_STORAGE_BACKENDS_MAX) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Too many drivers, cannot register storage file backend '%1$s'"),
                       virStorageTypeToString(backend->type));
        return -1;
    }

    virStorageFileBackends[virStorageFileBackendsCount] = backend;
    virStorageFileBackendsCount++;
    return 0;
}

int
virStorageFileBackendForType(int type,
                             int protocol,
                             bool required,
                             virStorageFileBackend **backend)
{
    size_t i;

    *backend = NULL;

    if (virStorageFileBackendInitialize() < 0)
        return -1;

    for (i = 0; i < virStorageFileBackendsCount; i++) {
        if (virStorageFileBackends[i]->type == type) {
            if (type == VIR_STORAGE_TYPE_NETWORK &&
                virStorageFileBackends[i]->protocol != protocol)
                continue;

            *backend = virStorageFileBackends[i];
            return 0;
        }
    }

    if (!required)
        return 0;

    if (type == VIR_STORAGE_TYPE_NETWORK) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing storage backend for network files using %1$s protocol"),
                       virStorageNetProtocolTypeToString(protocol));
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing storage backend for '%1$s' storage"),
                       virStorageTypeToString(type));
    }

    return -1;
}
