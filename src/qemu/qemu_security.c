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
 */

#include <config.h>

#include "qemu_domain.h"
#include "qemu_namespace.h"
#include "qemu_security.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_security");


int
qemuSecuritySetAllLabel(virQEMUDriver *driver,
                        virDomainObj *vm,
                        const char *incomingPath,
                        bool migrated)
{
    int ret = -1;
    qemuDomainObjPrivate *priv = vm->privateData;
    pid_t pid = -1;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        pid = vm->pid;

    if (virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerSetAllLabel(driver->securityManager,
                                      vm->def,
                                      incomingPath,
                                      priv->chardevStdioLogd,
                                      migrated) < 0)
        goto cleanup;

    if (virSecurityManagerTransactionCommit(driver->securityManager,
                                            pid, priv->rememberOwner) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


void
qemuSecurityRestoreAllLabel(virQEMUDriver *driver,
                            virDomainObj *vm,
                            bool migrated)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    bool transactionStarted = false;

    /* In contrast to qemuSecuritySetAllLabel, do not use vm->pid
     * here. This function is called from qemuProcessStop() which
     * is meant to do cleanup after qemu process died. The
     * domain's namespace is gone as qemu was the only process
     * running there. We would not succeed in entering the
     * namespace then. */
    if (virSecurityManagerTransactionStart(driver->securityManager) >= 0)
        transactionStarted = true;

    virSecurityManagerRestoreAllLabel(driver->securityManager,
                                      vm->def,
                                      migrated,
                                      priv->chardevStdioLogd);

    if (transactionStarted &&
        virSecurityManagerTransactionCommit(driver->securityManager,
                                            -1, priv->rememberOwner) < 0)
        VIR_WARN("Unable to run security manager transaction");

    virSecurityManagerTransactionAbort(driver->securityManager);
}


int
qemuSecuritySetImageLabel(virQEMUDriver *driver,
                          virDomainObj *vm,
                          virStorageSource *src,
                          bool backingChain,
                          bool chainTop)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    pid_t pid = -1;
    int ret = -1;
    virSecurityDomainImageLabelFlags labelFlags = 0;

    if (backingChain)
        labelFlags |= VIR_SECURITY_DOMAIN_IMAGE_LABEL_BACKING_CHAIN;

    if (chainTop)
        labelFlags |= VIR_SECURITY_DOMAIN_IMAGE_PARENT_CHAIN_TOP;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        pid = vm->pid;

    if (virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerSetImageLabel(driver->securityManager,
                                        vm->def, src, labelFlags) < 0)
        goto cleanup;

    if (virSecurityManagerTransactionCommit(driver->securityManager,
                                            pid, priv->rememberOwner) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


int
qemuSecurityRestoreImageLabel(virQEMUDriver *driver,
                              virDomainObj *vm,
                              virStorageSource *src,
                              bool backingChain)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    pid_t pid = -1;
    int ret = -1;
    virSecurityDomainImageLabelFlags labelFlags = 0;

    if (backingChain)
        labelFlags |= VIR_SECURITY_DOMAIN_IMAGE_LABEL_BACKING_CHAIN;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        pid = vm->pid;

    if (virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerRestoreImageLabel(driver->securityManager,
                                            vm->def, src, labelFlags) < 0)
        goto cleanup;

    if (virSecurityManagerTransactionCommit(driver->securityManager,
                                            pid, priv->rememberOwner) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


int
qemuSecurityMoveImageMetadata(virQEMUDriver *driver,
                              virDomainObj *vm,
                              virStorageSource *src,
                              virStorageSource *dst)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    pid_t pid = -1;

    if (!priv->rememberOwner)
        return 0;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        pid = vm->pid;

    return virSecurityManagerMoveImageMetadata(driver->securityManager, pid, src, dst);
}


int
qemuSecuritySetHostdevLabel(virQEMUDriver *driver,
                            virDomainObj *vm,
                            virDomainHostdevDef *hostdev)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    pid_t pid = -1;
    int ret = -1;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        pid = vm->pid;

    if (virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerSetHostdevLabel(driver->securityManager,
                                          vm->def,
                                          hostdev,
                                          NULL) < 0)
        goto cleanup;

    if (virSecurityManagerTransactionCommit(driver->securityManager,
                                            pid, priv->rememberOwner) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


int
qemuSecurityRestoreHostdevLabel(virQEMUDriver *driver,
                                virDomainObj *vm,
                                virDomainHostdevDef *hostdev)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    pid_t pid = -1;
    int ret = -1;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        pid = vm->pid;

    if (virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerRestoreHostdevLabel(driver->securityManager,
                                              vm->def,
                                              hostdev,
                                              NULL) < 0)
        goto cleanup;

    if (virSecurityManagerTransactionCommit(driver->securityManager,
                                            pid, priv->rememberOwner) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


int
qemuSecuritySetMemoryLabel(virQEMUDriver *driver,
                           virDomainObj *vm,
                           virDomainMemoryDef *mem)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    pid_t pid = -1;
    int ret = -1;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        pid = vm->pid;

    if (virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerSetMemoryLabel(driver->securityManager,
                                         vm->def,
                                         mem) < 0)
        goto cleanup;

    if (virSecurityManagerTransactionCommit(driver->securityManager,
                                            pid, priv->rememberOwner) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


int
qemuSecurityRestoreMemoryLabel(virQEMUDriver *driver,
                               virDomainObj *vm,
                               virDomainMemoryDef *mem)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    pid_t pid = -1;
    int ret = -1;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        pid = vm->pid;

    if (virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerRestoreMemoryLabel(driver->securityManager,
                                             vm->def,
                                             mem) < 0)
        goto cleanup;

    if (virSecurityManagerTransactionCommit(driver->securityManager,
                                            pid, priv->rememberOwner) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


int
qemuSecuritySetInputLabel(virDomainObj *vm,
                          virDomainInputDef *input)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    pid_t pid = -1;
    int ret = -1;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        pid = vm->pid;

    if (virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerSetInputLabel(driver->securityManager,
                                        vm->def,
                                        input) < 0)
        goto cleanup;

    if (virSecurityManagerTransactionCommit(driver->securityManager,
                                            pid, priv->rememberOwner) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


int
qemuSecurityRestoreInputLabel(virDomainObj *vm,
                              virDomainInputDef *input)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    pid_t pid = -1;
    int ret = -1;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        pid = vm->pid;

    if (virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerRestoreInputLabel(driver->securityManager,
                                            vm->def,
                                            input) < 0)
        goto cleanup;

    if (virSecurityManagerTransactionCommit(driver->securityManager,
                                            pid, priv->rememberOwner) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


int
qemuSecuritySetChardevLabel(virQEMUDriver *driver,
                            virDomainObj *vm,
                            virDomainChrDef *chr)
{
    int ret = -1;
    qemuDomainObjPrivate *priv = vm->privateData;
    pid_t pid = -1;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        pid = vm->pid;

    if (virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerSetChardevLabel(driver->securityManager,
                                          vm->def,
                                          chr->source,
                                          priv->chardevStdioLogd) < 0)
        goto cleanup;

    if (virSecurityManagerTransactionCommit(driver->securityManager,
                                            pid, priv->rememberOwner) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


int
qemuSecurityRestoreChardevLabel(virQEMUDriver *driver,
                                virDomainObj *vm,
                                virDomainChrDef *chr)
{
    int ret = -1;
    qemuDomainObjPrivate *priv = vm->privateData;
    pid_t pid = -1;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        pid = vm->pid;

    if (virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerRestoreChardevLabel(driver->securityManager,
                                              vm->def,
                                              chr->source,
                                              priv->chardevStdioLogd) < 0)
        goto cleanup;

    if (virSecurityManagerTransactionCommit(driver->securityManager,
                                            pid, priv->rememberOwner) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}

int
qemuSecuritySetNetdevLabel(virQEMUDriver *driver,
                           virDomainObj *vm,
                           virDomainNetDef *net)
{
    int ret = -1;
    qemuDomainObjPrivate *priv = vm->privateData;
    pid_t pid = -1;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        pid = vm->pid;

    if (virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerSetNetdevLabel(driver->securityManager,
                                         vm->def, net) < 0)
        goto cleanup;

    if (virSecurityManagerTransactionCommit(driver->securityManager,
                                            pid, priv->rememberOwner) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


int
qemuSecurityRestoreNetdevLabel(virQEMUDriver *driver,
                               virDomainObj *vm,
                               virDomainNetDef *net)
{
    int ret = -1;
    qemuDomainObjPrivate *priv = vm->privateData;
    pid_t pid = -1;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        pid = vm->pid;

    if (virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerRestoreNetdevLabel(driver->securityManager,
                                             vm->def, net) < 0)
        goto cleanup;

    if (virSecurityManagerTransactionCommit(driver->securityManager,
                                            pid, priv->rememberOwner) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


int
qemuSecuritySetTPMLabels(virQEMUDriver *driver,
                         virDomainObj *vm,
                         bool setTPMStateLabel)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    int ret = -1;

    if (virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerSetTPMLabels(driver->securityManager,
                                       vm->def, setTPMStateLabel) < 0)
        goto cleanup;

    if (virSecurityManagerTransactionCommit(driver->securityManager,
                                            -1, priv->rememberOwner) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


int
qemuSecurityRestoreTPMLabels(virQEMUDriver *driver,
                             virDomainObj *vm,
                             bool restoreTPMStateLabel)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    int ret = -1;

    if (virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerRestoreTPMLabels(driver->securityManager,
                                           vm->def, restoreTPMStateLabel) < 0)
        goto cleanup;

    if (virSecurityManagerTransactionCommit(driver->securityManager,
                                            -1, priv->rememberOwner) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


int
qemuSecurityDomainSetPathLabel(virQEMUDriver *driver,
                               virDomainObj *vm,
                               const char *path,
                               bool allowSubtree)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    pid_t pid = -1;
    int ret = -1;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        pid = vm->pid;

    if (virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerDomainSetPathLabel(driver->securityManager,
                                             vm->def,
                                             path,
                                             allowSubtree) < 0)
        goto cleanup;

    if (virSecurityManagerTransactionCommit(driver->securityManager,
                                            pid, priv->rememberOwner) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


int
qemuSecurityDomainRestorePathLabel(virQEMUDriver *driver,
                                   virDomainObj *vm,
                                   const char *path)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    pid_t pid = -1;
    int ret = -1;

    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        pid = vm->pid;

    if (virSecurityManagerTransactionStart(driver->securityManager) < 0)
        goto cleanup;

    if (virSecurityManagerDomainRestorePathLabel(driver->securityManager,
                                                 vm->def,
                                                 path) < 0)
        goto cleanup;

    if (virSecurityManagerTransactionCommit(driver->securityManager,
                                            pid, priv->rememberOwner) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecurityManagerTransactionAbort(driver->securityManager);
    return ret;
}


/**
 * qemuSecurityCommandRun:
 * @driver: the QEMU driver
 * @vm: the domain object
 * @cmd: the command to run
 * @uid: the uid to force
 * @gid: the gid to force
 * @existstatus: optional pointer to int returning exit status of process
 *
 * Run @cmd with seclabels set on it. If @uid and/or @gid are not
 * -1 then their value is enforced.
 *
 * Returns: 0 on success,
 *         -1 otherwise (with error reported).
 */
int
qemuSecurityCommandRun(virQEMUDriver *driver,
                       virDomainObj *vm,
                       virCommand *cmd,
                       uid_t uid,
                       gid_t gid,
                       bool useBinarySpecificLabel,
                       int *exitstatus)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    qemuDomainObjPrivate *priv = vm->privateData;
    int ret = -1;

    if (virSecurityManagerSetChildProcessLabel(driver->securityManager,
                                               vm->def, useBinarySpecificLabel,
                                               cmd) < 0) {
        return -1;
    }

    if (uid != (uid_t) -1)
        virCommandSetUID(cmd, uid);
    if (gid != (gid_t) -1)
        virCommandSetGID(cmd, gid);
    if (cfg->schedCore == QEMU_SCHED_CORE_FULL) {
        pid_t pid = vm->pid;

        if (pid <= 0)
            pid = priv->schedCoreChildPID;

        virCommandSetRunAmong(cmd, pid);
    }

    if (virSecurityManagerPreFork(driver->securityManager) < 0)
        return -1;

    ret = virCommandRun(cmd, exitstatus);

    virSecurityManagerPostFork(driver->securityManager);

    return ret;
}
