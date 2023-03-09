/*
 * vircgroupbackend.c: methods for cgroups backend
 *
 * Copyright (C) 2018 Red Hat, Inc.
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

#include "vircgroupbackend.h"
#define LIBVIRT_VIRCGROUPPRIV_H_ALLOW
#include "vircgrouppriv.h"
#include "vircgroupv1.h"
#include "vircgroupv2.h"
#include "virerror.h"
#include "virthread.h"

#define VIR_FROM_THIS VIR_FROM_CGROUP

VIR_ENUM_IMPL(virCgroupBackend,
              VIR_CGROUP_BACKEND_TYPE_LAST,
              "cgroup V2",
              "cgroup V1",
);

static virOnceControl virCgroupBackendOnce = VIR_ONCE_CONTROL_INITIALIZER;
static virCgroupBackend *virCgroupBackends[VIR_CGROUP_BACKEND_TYPE_LAST] = { 0 };

void
virCgroupBackendRegister(virCgroupBackend *backend)
{
    if (virCgroupBackends[backend->type]) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cgroup backend '%1$s' already registered."),
                       virCgroupBackendTypeToString(backend->type));
        return;
    }

    virCgroupBackends[backend->type] = backend;
}


static void
virCgroupBackendOnceInit(void)
{
    virCgroupV2Register();
    virCgroupV1Register();
}


virCgroupBackend **
virCgroupBackendGetAll(void)
{
    if (virOnce(&virCgroupBackendOnce, virCgroupBackendOnceInit) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to initialize cgroup backend."));
        return NULL;
    }
    return virCgroupBackends;
}


virCgroupBackend *
virCgroupBackendForController(virCgroup *group,
                              unsigned int controller)
{
    size_t i;

    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        if (group->backends[i] &&
            group->backends[i]->hasController(group, controller)) {
            return group->backends[i];
        }
    }

    return NULL;
}
