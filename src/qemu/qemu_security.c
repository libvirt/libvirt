/*
 * qemu_security.c: QEMU security management
 *
 * Copyright (C) 2016 Red Hat, Inc.
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
 * Authors:
 *     Michal Privoznik <mprivozn@redhat.com>
 */

#include <config.h>

#include "qemu_domain.h"
#include "qemu_security.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_process");

struct qemuSecuritySetRestoreAllLabelData {
    bool set;
    virQEMUDriverPtr driver;
    virDomainObjPtr vm;
    const char *stdin_path;
    bool migrated;
};


static int
qemuSecuritySetRestoreAllLabelHelper(pid_t pid,
                                     void *opaque)
{
    struct qemuSecuritySetRestoreAllLabelData *data = opaque;

    virSecurityManagerPostFork(data->driver->securityManager);

    if (data->set) {
        VIR_DEBUG("Setting up security labels inside namespace pid=%lld",
                  (long long) pid);
        if (virSecurityManagerSetAllLabel(data->driver->securityManager,
                                          data->vm->def,
                                          data->stdin_path) < 0)
            return -1;
    } else {
        VIR_DEBUG("Restoring security labels inside namespace pid=%lld",
                  (long long) pid);
        if (virSecurityManagerRestoreAllLabel(data->driver->securityManager,
                                              data->vm->def,
                                              data->migrated) < 0)
            return -1;
    }

    return 0;
}


int
qemuSecuritySetAllLabel(virQEMUDriverPtr driver,
                        virDomainObjPtr vm,
                        const char *stdin_path)
{
    struct qemuSecuritySetRestoreAllLabelData data;

    memset(&data, 0, sizeof(data));

    data.set = true;
    data.driver = driver;
    data.vm = vm;
    data.stdin_path = stdin_path;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT)) {
        if (virSecurityManagerPreFork(driver->securityManager) < 0)
            return -1;
        if (virProcessRunInMountNamespace(vm->pid,
                                          qemuSecuritySetRestoreAllLabelHelper,
                                          &data) < 0) {
            virSecurityManagerPostFork(driver->securityManager);
            return -1;
        }
        virSecurityManagerPostFork(driver->securityManager);

    } else {
        if (virSecurityManagerSetAllLabel(driver->securityManager,
                                          vm->def,
                                          stdin_path) < 0)
            return -1;
    }
    return 0;
}


void
qemuSecurityRestoreAllLabel(virQEMUDriverPtr driver,
                            virDomainObjPtr vm,
                            bool migrated)
{
    struct qemuSecuritySetRestoreAllLabelData data;

    memset(&data, 0, sizeof(data));

    data.driver = driver;
    data.vm = vm;
    data.migrated = migrated;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT)) {
        if (virSecurityManagerPreFork(driver->securityManager) < 0)
            return;

        virProcessRunInMountNamespace(vm->pid,
                                      qemuSecuritySetRestoreAllLabelHelper,
                                      &data);
        virSecurityManagerPostFork(driver->securityManager);
    } else {
        virSecurityManagerRestoreAllLabel(driver->securityManager,
                                          vm->def,
                                          migrated);
    }
}


int
qemuSecuritySetDiskLabel(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         virDomainDiskDefPtr disk)
{
    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT)) {
        /* Already handled by namespace code. */
        return 0;
    }

    return virSecurityManagerSetDiskLabel(driver->securityManager,
                                          vm->def,
                                          disk);
}


int
qemuSecurityRestoreDiskLabel(virQEMUDriverPtr driver,
                             virDomainObjPtr vm,
                             virDomainDiskDefPtr disk)
{
    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT)) {
        /* Already handled by namespace code. */
        return 0;
    }

    return virSecurityManagerRestoreDiskLabel(driver->securityManager,
                                              vm->def,
                                              disk);
}
