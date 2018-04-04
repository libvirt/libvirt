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


int
qemuSecuritySetAllLabel(virQEMUDriverPtr driver,
                        virDomainObjPtr vm,
                        const char *stdin_path)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT) &&
        virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerSetAllLabel(driver->securityManager,
                                      vm->def,
                                      stdin_path,
                                      priv->chardevStdioLogd) < 0)
        goto cleanup;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT) &&
        virSecurityManagerTransactionCommit(driver->securityManager,
                                            vm->pid) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


void
qemuSecurityRestoreAllLabel(virQEMUDriverPtr driver,
                            virDomainObjPtr vm,
                            bool migrated)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    /* In contrast to qemuSecuritySetAllLabel, do not use
     * secdriver transactions here. This function is called from
     * qemuProcessStop() which is meant to do cleanup after qemu
     * process died. If it did do, the namespace is gone as qemu
     * was the only process running there. We would not succeed
     * in entering the namespace then. */
    virSecurityManagerRestoreAllLabel(driver->securityManager,
                                      vm->def,
                                      migrated,
                                      priv->chardevStdioLogd);
}


int
qemuSecuritySetDiskLabel(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         virDomainDiskDefPtr disk)
{
    int ret = -1;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT) &&
        virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerSetDiskLabel(driver->securityManager,
                                       vm->def,
                                       disk) < 0)
        goto cleanup;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT) &&
        virSecurityManagerTransactionCommit(driver->securityManager,
                                            vm->pid) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


int
qemuSecurityRestoreDiskLabel(virQEMUDriverPtr driver,
                             virDomainObjPtr vm,
                             virDomainDiskDefPtr disk)
{
    int ret = -1;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT) &&
        virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerRestoreDiskLabel(driver->securityManager,
                                           vm->def,
                                           disk) < 0)
        goto cleanup;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT) &&
        virSecurityManagerTransactionCommit(driver->securityManager,
                                            vm->pid) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


int
qemuSecuritySetImageLabel(virQEMUDriverPtr driver,
                          virDomainObjPtr vm,
                          virStorageSourcePtr src)
{
    int ret = -1;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT) &&
        virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerSetImageLabel(driver->securityManager,
                                        vm->def,
                                        src) < 0)
        goto cleanup;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT) &&
        virSecurityManagerTransactionCommit(driver->securityManager,
                                            vm->pid) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


int
qemuSecurityRestoreImageLabel(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              virStorageSourcePtr src)
{
    int ret = -1;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT) &&
        virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerRestoreImageLabel(driver->securityManager,
                                            vm->def,
                                            src) < 0)
        goto cleanup;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT) &&
        virSecurityManagerTransactionCommit(driver->securityManager,
                                            vm->pid) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


int
qemuSecuritySetHostdevLabel(virQEMUDriverPtr driver,
                            virDomainObjPtr vm,
                            virDomainHostdevDefPtr hostdev)
{
    int ret = -1;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT) &&
        virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerSetHostdevLabel(driver->securityManager,
                                          vm->def,
                                          hostdev,
                                          NULL) < 0)
        goto cleanup;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT) &&
        virSecurityManagerTransactionCommit(driver->securityManager,
                                            vm->pid) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


int
qemuSecurityRestoreHostdevLabel(virQEMUDriverPtr driver,
                                virDomainObjPtr vm,
                                virDomainHostdevDefPtr hostdev)
{
    int ret = -1;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT) &&
        virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerRestoreHostdevLabel(driver->securityManager,
                                              vm->def,
                                              hostdev,
                                              NULL) < 0)
        goto cleanup;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT) &&
        virSecurityManagerTransactionCommit(driver->securityManager,
                                            vm->pid) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


int
qemuSecuritySetMemoryLabel(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           virDomainMemoryDefPtr mem)
{
    int ret = -1;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT) &&
        virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerSetMemoryLabel(driver->securityManager,
                                         vm->def,
                                         mem) < 0)
        goto cleanup;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT) &&
        virSecurityManagerTransactionCommit(driver->securityManager,
                                            vm->pid) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


int
qemuSecurityRestoreMemoryLabel(virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               virDomainMemoryDefPtr mem)
{
    int ret = -1;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT) &&
        virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerRestoreMemoryLabel(driver->securityManager,
                                             vm->def,
                                             mem) < 0)
        goto cleanup;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT) &&
        virSecurityManagerTransactionCommit(driver->securityManager,
                                            vm->pid) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


int
qemuSecuritySetInputLabel(virDomainObjPtr vm,
                          virDomainInputDefPtr input)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverPtr driver = priv->driver;
    int ret = -1;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT) &&
        virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerSetInputLabel(driver->securityManager,
                                        vm->def,
                                        input) < 0)
        goto cleanup;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT) &&
        virSecurityManagerTransactionCommit(driver->securityManager,
                                            vm->pid) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


int
qemuSecurityRestoreInputLabel(virDomainObjPtr vm,
                              virDomainInputDefPtr input)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverPtr driver = priv->driver;
    int ret = -1;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT) &&
        virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerRestoreInputLabel(driver->securityManager,
                                            vm->def,
                                            input) < 0)
        goto cleanup;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT) &&
        virSecurityManagerTransactionCommit(driver->securityManager,
                                            vm->pid) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


int
qemuSecuritySetChardevLabel(virQEMUDriverPtr driver,
                            virDomainObjPtr vm,
                            virDomainChrDefPtr chr)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT) &&
        virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerSetChardevLabel(driver->securityManager,
                                          vm->def,
                                          chr->source,
                                          priv->chardevStdioLogd) < 0)
        goto cleanup;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT) &&
        virSecurityManagerTransactionCommit(driver->securityManager,
                                            vm->pid) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


int
qemuSecurityRestoreChardevLabel(virQEMUDriverPtr driver,
                                virDomainObjPtr vm,
                                virDomainChrDefPtr chr)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT) &&
        virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerRestoreChardevLabel(driver->securityManager,
                                              vm->def,
                                              chr->source,
                                              priv->chardevStdioLogd) < 0)
        goto cleanup;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT) &&
        virSecurityManagerTransactionCommit(driver->securityManager,
                                            vm->pid) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


/*
 * qemuSecurityStartTPMEmulator:
 *
 * @driver: the QEMU driver
 * @def: the domain definition
 * @cmd: the command to run
 * @uid: the uid to run the emulator
 * @gid: the gid to run the emulator
 * @existstatus: pointer to int returning exit status of process
 * @cmdret: pointer to int returning result of virCommandRun
 *
 * Start the TPM emulator with approriate labels. Apply security
 * labels to files first.
 * This function returns -1 on security setup error, 0 if all the
 * setup was done properly. In case the virCommand failed to run
 * 0 is returned but cmdret is set appropriately with the process
 * exitstatus also set.
 */
int
qemuSecurityStartTPMEmulator(virQEMUDriverPtr driver,
                             virDomainDefPtr def,
                             virCommandPtr cmd,
                             uid_t uid,
                             gid_t gid,
                             int *exitstatus,
                             int *cmdret)
{
    int ret = -1;

    if (virSecurityManagerSetTPMLabels(driver->securityManager,
                                       def) < 0)
        goto cleanup;

    if (virSecurityManagerSetChildProcessLabel(driver->securityManager,
                                               def, cmd) < 0)
        goto cleanup;

    if (virSecurityManagerPreFork(driver->securityManager) < 0)
        goto cleanup;

    ret = 0;
    /* make sure we run this with the appropriate user */
    virCommandSetUID(cmd, uid);
    virCommandSetGID(cmd, gid);

    *cmdret = virCommandRun(cmd, exitstatus);

    virSecurityManagerPostFork(driver->securityManager);

    if (*cmdret < 0)
        goto cleanup;

    return 0;

 cleanup:
    virSecurityManagerRestoreTPMLabels(driver->securityManager, def);

    return ret;
}


void
qemuSecurityCleanupTPMEmulator(virQEMUDriverPtr driver,
                               virDomainDefPtr def)
{
    virSecurityManagerRestoreTPMLabels(driver->securityManager, def);
}
