/*
 * virstoragefilebackend.c: internal storage source backend contract
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
#include "virstoragefilebackend.h"
#include "virlog.h"
#include "virfile.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_source_backend");

#define VIR_STORAGE_BACKENDS_MAX 20

static virStorageFileBackendPtr virStorageFileBackends[VIR_STORAGE_BACKENDS_MAX];
static size_t virStorageFileBackendsCount;


int
virStorageFileBackendRegister(virStorageFileBackendPtr backend)
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
