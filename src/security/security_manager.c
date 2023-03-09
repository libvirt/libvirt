/*
 * security_manager.c: Internal security manager API
 *
 * Copyright (C) 2010-2014 Red Hat, Inc.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "security_driver.h"
#include "security_stack.h"
#include "security_dac.h"
#include "virerror.h"
#include "viralloc.h"
#include "virobject.h"
#include "virlog.h"
#include "virfile.h"

#define VIR_FROM_THIS VIR_FROM_SECURITY

VIR_LOG_INIT("security.security_manager");

struct _virSecurityManager {
    virObjectLockable parent;

    virSecurityDriver *drv;
    unsigned int flags;
    const char *virtDriver;
    void *privateData;
};

static virClass *virSecurityManagerClass;


static
void virSecurityManagerDispose(void *obj)
{
    virSecurityManager *mgr = obj;

    if (mgr->drv->close)
        mgr->drv->close(mgr);
    g_free(mgr->privateData);
}


static int
virSecurityManagerOnceInit(void)
{
    if (!VIR_CLASS_NEW(virSecurityManager, virClassForObjectLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virSecurityManager);


static virSecurityManager *
virSecurityManagerNewDriver(virSecurityDriver *drv,
                            const char *virtDriver,
                            unsigned int flags)
{
    virSecurityManager *mgr = NULL;
    char *privateData = NULL;

    if (virSecurityManagerInitialize() < 0)
        return NULL;

    VIR_DEBUG("drv=%p (%s) virtDriver=%s flags=0x%x",
              drv, drv->name, virtDriver, flags);

    virCheckFlags(VIR_SECURITY_MANAGER_NEW_MASK, NULL);

    privateData = g_new0(char, drv->privateDataLen);

    if (!(mgr = virObjectLockableNew(virSecurityManagerClass)))
        goto error;

    mgr->drv = drv;
    mgr->flags = flags;
    mgr->virtDriver = virtDriver;
    mgr->privateData = g_steal_pointer(&privateData);

    if (drv->open(mgr) < 0)
        goto error;

    return mgr;
 error:
    VIR_FREE(privateData);
    virObjectUnref(mgr);
    return NULL;
}


virSecurityManager *
virSecurityManagerNewStack(virSecurityManager *primary)
{
    virSecurityManager *mgr =
        virSecurityManagerNewDriver(&virSecurityDriverStack,
                                    virSecurityManagerGetVirtDriver(primary),
                                    primary->flags);

    if (!mgr)
        return NULL;

    if (virSecurityStackAddNested(mgr, primary) < 0)
        goto error;

    return mgr;
 error:
    virObjectUnref(mgr);
    return NULL;
}


int
virSecurityManagerStackAddNested(virSecurityManager *stack,
                                 virSecurityManager *nested)
{
    if (STRNEQ("stack", stack->drv->name))
        return -1;
    return virSecurityStackAddNested(stack, nested);
}


virSecurityManager *
virSecurityManagerNewDAC(const char *virtDriver,
                         uid_t user,
                         gid_t group,
                         unsigned int flags,
                         virSecurityManagerDACChownCallback chownCallback)
{
    virSecurityManager *mgr;

    virCheckFlags(VIR_SECURITY_MANAGER_NEW_MASK |
                  VIR_SECURITY_MANAGER_DYNAMIC_OWNERSHIP |
                  VIR_SECURITY_MANAGER_MOUNT_NAMESPACE, NULL);

    mgr = virSecurityManagerNewDriver(&virSecurityDriverDAC,
                                      virtDriver,
                                      flags & VIR_SECURITY_MANAGER_NEW_MASK);

    if (!mgr)
        return NULL;

    if (virSecurityDACSetUserAndGroup(mgr, user, group) < 0) {
        virSecurityManagerDispose(mgr);
        return NULL;
    }

    virSecurityDACSetDynamicOwnership(mgr, flags & VIR_SECURITY_MANAGER_DYNAMIC_OWNERSHIP);
    virSecurityDACSetMountNamespace(mgr, flags & VIR_SECURITY_MANAGER_MOUNT_NAMESPACE);
    virSecurityDACSetChownCallback(mgr, chownCallback);

    return mgr;
}


virSecurityManager *
virSecurityManagerNew(const char *name,
                      const char *virtDriver,
                      unsigned int flags)
{
    virSecurityDriver *drv = virSecurityDriverLookup(name, virtDriver);
    if (!drv)
        return NULL;

    /* driver "none" needs some special handling of *Confined bools */
    if (STREQ(drv->name, "none")) {
        if (flags & VIR_SECURITY_MANAGER_REQUIRE_CONFINED) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Security driver \"none\" cannot create confined guests"));
            return NULL;
        }

        if (flags & VIR_SECURITY_MANAGER_DEFAULT_CONFINED) {
            if (name != NULL) {
                VIR_WARN("Configured security driver \"none\" disables default"
                         " policy to create confined guests");
            } else {
                VIR_DEBUG("Auto-probed security driver is \"none\";"
                          " confined guests will not be created");
            }
            flags &= ~VIR_SECURITY_MANAGER_DEFAULT_CONFINED;
        }
    }

    return virSecurityManagerNewDriver(drv,
                                       virtDriver,
                                       flags);
}


/*
 * Must be called before fork()'ing to ensure mutex state
 * is sane for the child to use. A negative return means the
 * child must not be forked; a successful return must be
 * followed by a call to virSecurityManagerPostFork() in both
 * parent and child.
 */
int
virSecurityManagerPreFork(virSecurityManager *mgr)
{
    int ret = 0;

    virObjectLock(mgr);
    if (mgr->drv->preFork) {
        ret = mgr->drv->preFork(mgr);
        if (ret < 0)
            virObjectUnlock(mgr);
    }

    return ret;
}


/*
 * Must be called after fork()'ing in both parent and child
 * to ensure mutex state is sane for the child to use
 */
void
virSecurityManagerPostFork(virSecurityManager *mgr)
{
    virObjectUnlock(mgr);
}


/**
 * virSecurityManagerTransactionStart:
 * @mgr: security manager
 *
 * Starts a new transaction. In transaction nothing is changed security
 * label until virSecurityManagerTransactionCommit() is called.
 *
 * Returns 0 on success,
 *        -1 otherwise.
 */
int
virSecurityManagerTransactionStart(virSecurityManager *mgr)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->transactionStart)
        return 0;

    return mgr->drv->transactionStart(mgr);
}


/**
 * virSecurityManagerTransactionCommit:
 * @mgr: security manager
 * @pid: domain's PID
 * @lock: lock and unlock paths that are relabeled
 *
 * If @pid is not -1 then enter the @pid namespace (usually @pid refers
 * to a domain) and perform all the operations on the transaction list.
 * If @pid is -1 then the transaction is performed in the namespace of
 * the caller.
 *
 * If @lock is true then all the paths that transaction would
 * touch are locked before and unlocked after it is done so.
 *
 * Note that the transaction is also freed, therefore new one has to be
 * started after successful return from this function. Also it is
 * considered as error if there's no transaction set and this function
 * is called.
 *
 * Returns: 0 on success,
 *         -1 otherwise.
 */
int
virSecurityManagerTransactionCommit(virSecurityManager *mgr,
                                    pid_t pid,
                                    bool lock)
{
    VIR_LOCK_GUARD lockguard = virObjectLockGuard(mgr);

    if (!mgr->drv->transactionCommit)
        return 0;

    return mgr->drv->transactionCommit(mgr, pid, lock);
}


/**
 * virSecurityManagerTransactionAbort:
 * @mgr: security manager
 *
 * Cancels and frees any out standing transaction.
 */
void
virSecurityManagerTransactionAbort(virSecurityManager *mgr)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (mgr->drv->transactionAbort)
        mgr->drv->transactionAbort(mgr);
}


void *
virSecurityManagerGetPrivateData(virSecurityManager *mgr)
{
    return mgr->privateData;
}


const char *
virSecurityManagerGetVirtDriver(virSecurityManager *mgr)
{
    return mgr->virtDriver;
}


const char *
virSecurityManagerGetDriver(virSecurityManager *mgr)
{
    return mgr->drv->name;
}


const char *
virSecurityManagerGetDOI(virSecurityManager *mgr)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->getDOI) {
        virReportUnsupportedError();
        return NULL;
    }

    return mgr->drv->getDOI(mgr);
}


const char *
virSecurityManagerGetModel(virSecurityManager *mgr)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->getModel) {
        virReportUnsupportedError();
        return NULL;
    }

    return mgr->drv->getModel(mgr);
}


/* return NULL if a base label is not present */
const char *
virSecurityManagerGetBaseLabel(virSecurityManager *mgr,
                               int virtType)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->getBaseLabel)
        return NULL;

    return mgr->drv->getBaseLabel(mgr, virtType);
}


bool
virSecurityManagerGetDefaultConfined(virSecurityManager *mgr)
{
    return mgr->flags & VIR_SECURITY_MANAGER_DEFAULT_CONFINED;
}


bool
virSecurityManagerGetRequireConfined(virSecurityManager *mgr)
{
    return mgr->flags & VIR_SECURITY_MANAGER_REQUIRE_CONFINED;
}


bool
virSecurityManagerGetPrivileged(virSecurityManager *mgr)
{
    return mgr->flags & VIR_SECURITY_MANAGER_PRIVILEGED;
}


/**
 * virSecurityManagerRestoreImageLabel:
 * @mgr: security manager object
 * @vm: domain definition object
 * @src: disk source definition to operate on
 * @flags: bitwise or of 'virSecurityDomainImageLabelFlags'
 *
 * Removes security label from @src according to @flags.
 *
 * Returns: 0 on success, -1 on error.
 */
int
virSecurityManagerRestoreImageLabel(virSecurityManager *mgr,
                                   virDomainDef *vm,
                                   virStorageSource *src,
                                   virSecurityDomainImageLabelFlags flags)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainRestoreSecurityImageLabel) {
        virReportUnsupportedError();
        return -1;
    }

    return mgr->drv->domainRestoreSecurityImageLabel(mgr, vm, src, flags);
}


/**
 * virSecurityManagerMoveImageMetadata:
 * @mgr: security manager
 * @pid: domain's PID
 * @src: source of metadata
 * @dst: destination to move metadata to
 *
 * For given source @src, metadata is moved to destination @dst.
 *
 * If @dst is NULL then metadata is removed from @src and not
 * stored anywhere.
 *
 * If @pid is not -1 enter the @pid mount namespace (usually
 * @pid refers to a domain) and perform the move from there. If
 * @pid is -1 then the move is performed from the caller's
 * namespace.
 *
 * Returns: 0 on success,
 *         -1 otherwise.
 */
int
virSecurityManagerMoveImageMetadata(virSecurityManager *mgr,
                                    pid_t pid,
                                    virStorageSource *src,
                                    virStorageSource *dst)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainMoveImageMetadata)
        return 0;

    return mgr->drv->domainMoveImageMetadata(mgr, pid, src, dst);
}


int
virSecurityManagerSetDaemonSocketLabel(virSecurityManager *mgr,
                                       virDomainDef *vm)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainSetSecurityDaemonSocketLabel) {
        virReportUnsupportedError();
        return -1;
    }

    return mgr->drv->domainSetSecurityDaemonSocketLabel(mgr, vm);
}


int
virSecurityManagerSetSocketLabel(virSecurityManager *mgr,
                                 virDomainDef *vm)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainSetSecuritySocketLabel) {
        virReportUnsupportedError();
        return -1;
    }

    return mgr->drv->domainSetSecuritySocketLabel(mgr, vm);
}


int
virSecurityManagerClearSocketLabel(virSecurityManager *mgr,
                                   virDomainDef *vm)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainClearSecuritySocketLabel) {
        virReportUnsupportedError();
        return -1;
    }

    return mgr->drv->domainClearSecuritySocketLabel(mgr, vm);
}


/**
 * virSecurityManagerSetImageLabel:
 * @mgr: security manager object
 * @vm: domain definition object
 * @src: disk source definition to operate on
 * @flags: bitwise or of 'virSecurityDomainImageLabelFlags'
 *
 * Labels a storage image with the configured security label according to @flags.
 *
 * Returns: 0 on success, -1 on error.
 */
int
virSecurityManagerSetImageLabel(virSecurityManager *mgr,
                                virDomainDef *vm,
                                virStorageSource *src,
                                virSecurityDomainImageLabelFlags flags)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainSetSecurityImageLabel) {
        virReportUnsupportedError();
        return -1;
    }

    return mgr->drv->domainSetSecurityImageLabel(mgr, vm, src, flags);
}


int
virSecurityManagerRestoreHostdevLabel(virSecurityManager *mgr,
                                      virDomainDef *vm,
                                      virDomainHostdevDef *dev,
                                      const char *vroot)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainRestoreSecurityHostdevLabel) {
        virReportUnsupportedError();
        return -1;
    }

    return mgr->drv->domainRestoreSecurityHostdevLabel(mgr, vm, dev, vroot);
}


int
virSecurityManagerSetHostdevLabel(virSecurityManager *mgr,
                                  virDomainDef *vm,
                                  virDomainHostdevDef *dev,
                                  const char *vroot)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainSetSecurityHostdevLabel) {
        virReportUnsupportedError();
        return -1;
    }

    return mgr->drv->domainSetSecurityHostdevLabel(mgr, vm, dev, vroot);
}


int
virSecurityManagerSetSavedStateLabel(virSecurityManager *mgr,
                                     virDomainDef *vm,
                                     const char *savefile)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainSetSavedStateLabel)
        return 0;

    return mgr->drv->domainSetSavedStateLabel(mgr, vm, savefile);
}


int
virSecurityManagerRestoreSavedStateLabel(virSecurityManager *mgr,
                                         virDomainDef *vm,
                                         const char *savefile)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainRestoreSavedStateLabel)
        return 0;

    return mgr->drv->domainRestoreSavedStateLabel(mgr, vm, savefile);
}


int
virSecurityManagerGenLabel(virSecurityManager *mgr,
                           virDomainDef *vm)
{
    int ret = -1;
    size_t i;
    virSecurityManager ** sec_managers = NULL;
    virSecurityLabelDef *seclabel;
    bool generated = false;

    if ((sec_managers = virSecurityManagerGetNested(mgr)) == NULL)
        return ret;

    virObjectLock(mgr);

    for (i = 0; sec_managers[i]; i++) {
        generated = false;
        seclabel = virDomainDefGetSecurityLabelDef(vm, sec_managers[i]->drv->name);
        if (seclabel == NULL) {
            /* Only generate seclabel if confinement is enabled */
            if (!virSecurityManagerGetDefaultConfined(sec_managers[i])) {
                VIR_DEBUG("Skipping auto generated seclabel");
                continue;
            } else {
                if (!(seclabel = virSecurityLabelDefNew(sec_managers[i]->drv->name)))
                    goto cleanup;
                generated = seclabel->implicit = true;
                seclabel->type = VIR_DOMAIN_SECLABEL_DYNAMIC;
            }
        } else {
            if (seclabel->type == VIR_DOMAIN_SECLABEL_DEFAULT) {
                if (virSecurityManagerGetDefaultConfined(sec_managers[i])) {
                    seclabel->type = VIR_DOMAIN_SECLABEL_DYNAMIC;
                } else {
                    seclabel->type = VIR_DOMAIN_SECLABEL_NONE;
                    seclabel->relabel = false;
                }
            }

            if (seclabel->type == VIR_DOMAIN_SECLABEL_NONE) {
                if (virSecurityManagerGetRequireConfined(sec_managers[i])) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("Unconfined guests are not allowed on this host"));
                    goto cleanup;
                }
            }
        }

        if (!sec_managers[i]->drv->domainGenSecurityLabel) {
            virReportUnsupportedError();
            g_clear_pointer(&seclabel, virSecurityLabelDefFree);
        } else {
            /* The seclabel must be added to @vm prior calling domainGenSecurityLabel
             * which may require seclabel to be presented already */
            if (generated)
                VIR_APPEND_ELEMENT(vm->seclabels, vm->nseclabels, seclabel);

            if (sec_managers[i]->drv->domainGenSecurityLabel(sec_managers[i], vm) < 0) {
                if (VIR_DELETE_ELEMENT(vm->seclabels,
                                       vm->nseclabels -1, vm->nseclabels) < 0)
                    vm->nseclabels--;
                goto cleanup;
            }

            seclabel = NULL;
        }
    }

    ret = 0;

 cleanup:
    virObjectUnlock(mgr);
    if (generated)
        virSecurityLabelDefFree(seclabel);
    VIR_FREE(sec_managers);
    return ret;
}


int
virSecurityManagerReserveLabel(virSecurityManager *mgr,
                               virDomainDef *vm,
                               pid_t pid)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainReserveSecurityLabel) {
        virReportUnsupportedError();
        return -1;
    }

    return mgr->drv->domainReserveSecurityLabel(mgr, vm, pid);
}


int
virSecurityManagerReleaseLabel(virSecurityManager *mgr,
                               virDomainDef *vm)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainReleaseSecurityLabel) {
        virReportUnsupportedError();
        return -1;
    }

    return mgr->drv->domainReleaseSecurityLabel(mgr, vm);
}


static int virSecurityManagerCheckModel(virSecurityManager *mgr,
                                        char *secmodel)
{
    int ret = -1;
    size_t i;
    virSecurityManager **sec_managers = NULL;

    if (STREQ_NULLABLE(secmodel, "none"))
        return 0;

    if ((sec_managers = virSecurityManagerGetNested(mgr)) == NULL)
        return -1;

    for (i = 0; sec_managers[i]; i++) {
        if (STREQ_NULLABLE(secmodel, sec_managers[i]->drv->name)) {
            ret = 0;
            goto cleanup;
        }
    }

    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                   _("Security driver model '%1$s' is not available"),
                   secmodel);
 cleanup:
    VIR_FREE(sec_managers);
    return ret;
}


static int
virSecurityManagerCheckDomainLabel(virSecurityManager *mgr,
                                   virDomainDef *def)
{
    size_t i;

    for (i = 0; i < def->nseclabels; i++) {
        if (virSecurityManagerCheckModel(mgr, def->seclabels[i]->model) < 0)
            return -1;
    }

    return 0;
}


static int
virSecurityManagerCheckDiskLabel(virSecurityManager *mgr,
                                 virDomainDiskDef *disk)
{
    size_t i;

    for (i = 0; i < disk->src->nseclabels; i++) {
        if (virSecurityManagerCheckModel(mgr, disk->src->seclabels[i]->model) < 0)
            return -1;
    }

    return 0;
}


static int
virSecurityManagerCheckChardevLabel(virSecurityManager *mgr,
                                    virDomainChrDef *dev)
{
    size_t i;

    for (i = 0; i < dev->source->nseclabels; i++) {
        if (virSecurityManagerCheckModel(mgr, dev->source->seclabels[i]->model) < 0)
            return -1;
    }

    return 0;
}


static int
virSecurityManagerCheckChardevCallback(virDomainDef *def G_GNUC_UNUSED,
                                       virDomainChrDef *dev,
                                       void *opaque)
{
    virSecurityManager *mgr = opaque;
    return virSecurityManagerCheckChardevLabel(mgr, dev);
}


int virSecurityManagerCheckAllLabel(virSecurityManager *mgr,
                                    virDomainDef *vm)
{
    size_t i;

    if (virSecurityManagerCheckDomainLabel(mgr, vm) < 0)
        return -1;

    for (i = 0; i < vm->ndisks; i++) {
        if (virSecurityManagerCheckDiskLabel(mgr, vm->disks[i]) < 0)
            return -1;
    }

    if (virDomainChrDefForeach(vm,
                               true,
                               virSecurityManagerCheckChardevCallback,
                               mgr) < 0)
        return -1;

    return 0;
}


int
virSecurityManagerSetAllLabel(virSecurityManager *mgr,
                              virDomainDef *vm,
                              const char *incomingPath,
                              bool chardevStdioLogd,
                              bool migrated)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainSetSecurityAllLabel) {
        virReportUnsupportedError();
        return -1;
    }

    return mgr->drv->domainSetSecurityAllLabel(mgr, vm, incomingPath,
                                               chardevStdioLogd, migrated);
}


int
virSecurityManagerRestoreAllLabel(virSecurityManager *mgr,
                                  virDomainDef *vm,
                                  bool migrated,
                                  bool chardevStdioLogd)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainRestoreSecurityAllLabel) {
        virReportUnsupportedError();
        return -1;
    }

    return mgr->drv->domainRestoreSecurityAllLabel(mgr, vm, migrated,
                                                   chardevStdioLogd);
}

int
virSecurityManagerGetProcessLabel(virSecurityManager *mgr,
                                  virDomainDef *vm,
                                  pid_t pid,
                                  virSecurityLabelPtr sec)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainGetSecurityProcessLabel) {
        virReportUnsupportedError();
        return -1;
    }

    return mgr->drv->domainGetSecurityProcessLabel(mgr, vm, pid, sec);
}


int
virSecurityManagerSetProcessLabel(virSecurityManager *mgr,
                                  virDomainDef *vm)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainSetSecurityProcessLabel) {
        virReportUnsupportedError();
        return -1;
    }

    return mgr->drv->domainSetSecurityProcessLabel(mgr, vm);
}


int
virSecurityManagerSetChildProcessLabel(virSecurityManager *mgr,
                                       virDomainDef *vm,
                                       bool useBinarySpecificLabel,
                                       virCommand *cmd)
{
    if (mgr->drv->domainSetSecurityChildProcessLabel) {
       return mgr->drv->domainSetSecurityChildProcessLabel(mgr, vm,
                                                           useBinarySpecificLabel,
                                                           cmd);
    }

    virReportUnsupportedError();
    return -1;
}


int
virSecurityManagerVerify(virSecurityManager *mgr,
                         virDomainDef *def)
{
    virSecurityLabelDef *secdef;

    if (mgr == NULL || mgr->drv == NULL)
        return 0;

    /* NULL model == dynamic labelling, with whatever driver
     * is active, so we can short circuit verify check to
     * avoid drivers de-referencing NULLs by accident
     */
    secdef = virDomainDefGetSecurityLabelDef(def, mgr->drv->name);
    if (secdef == NULL || secdef->model == NULL)
        return 0;

    VIR_WITH_OBJECT_LOCK_GUARD(mgr) {
        if (mgr->drv->domainSecurityVerify) {
            return mgr->drv->domainSecurityVerify(mgr, def);
        }
    }

    virReportUnsupportedError();
    return -1;
}


int
virSecurityManagerSetImageFDLabel(virSecurityManager *mgr,
                                  virDomainDef *vm,
                                  int fd)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainSetSecurityImageFDLabel) {
        virReportUnsupportedError();
        return -1;
    }

    return mgr->drv->domainSetSecurityImageFDLabel(mgr, vm, fd);
}


int
virSecurityManagerSetTapFDLabel(virSecurityManager *mgr,
                                virDomainDef *vm,
                                int fd)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainSetSecurityTapFDLabel) {
        virReportUnsupportedError();
        return -1;
    }

    return mgr->drv->domainSetSecurityTapFDLabel(mgr, vm, fd);
}


char *
virSecurityManagerGetMountOptions(virSecurityManager *mgr,
                                  virDomainDef *vm)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainGetSecurityMountOptions) {
        virReportUnsupportedError();
        return NULL;
    }

    return mgr->drv->domainGetSecurityMountOptions(mgr, vm);
}


virSecurityManager **
virSecurityManagerGetNested(virSecurityManager *mgr)
{
    virSecurityManager ** list = NULL;

    if (STREQ("stack", mgr->drv->name))
        return virSecurityStackGetNested(mgr);

    list = g_new0(virSecurityManager *, 2);

    list[0] = mgr;
    list[1] = NULL;
    return list;
}


/**
 * virSecurityManagerDomainSetPathLabel:
 * @mgr: security manager object
 * @vm: domain definition object
 * @path: path to label
 * @allowSubtree: whether to allow just @path or its subtree too
 *
 * This function relabels given @path so that @vm can access it.
 * If @allowSubtree is set to true the manager will grant access
 * to @path and its subdirectories at any level (currently
 * implemented only by AppArmor).
 *
 * Returns: 0 on success, -1 on error.
 */
int
virSecurityManagerDomainSetPathLabel(virSecurityManager *mgr,
                                     virDomainDef *vm,
                                     const char *path,
                                     bool allowSubtree)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainSetPathLabel)
        return 0;

    return mgr->drv->domainSetPathLabel(mgr, vm, path, allowSubtree);
}


/**
 * virSecurityManagerDomainSetPathLabelRO:
 * @mgr: security manager object
 * @vm: domain definition object
 * @path: path to label
 *
 * This function relabels given @path for read only access, which
 * is in contrast with virSecurityManagerDomainSetPathLabel() which
 * gives read write access.
 *
 * Returns: 0 on success, -1 on error.
 */
int
virSecurityManagerDomainSetPathLabelRO(virSecurityManager *mgr,
                                       virDomainDef *vm,
                                       const char *path)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainSetPathLabelRO)
        return 0;

    return mgr->drv->domainSetPathLabelRO(mgr, vm, path);
}

/**
 * virSecurityManagerDomainRestorePathLabel:
 * @mgr: security manager object
 * @vm: domain definition object
 * @path: path to restore labels one
 *
 * This function is a counterpart to virSecurityManagerDomainSetPathLabel() and
 * virSecurityManagerDomainSetPathLabelRO() as it restores any labels set by them.
 *
 * Returns: 0 on success, -1 on error.
 */
int
virSecurityManagerDomainRestorePathLabel(virSecurityManager *mgr,
                                         virDomainDef *vm,
                                         const char *path)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainRestorePathLabel)
        return 0;

    return mgr->drv->domainRestorePathLabel(mgr, vm, path);
}



/**
 * virSecurityManagerSetMemoryLabel:
 * @mgr: security manager object
 * @vm: domain definition object
 * @mem: memory module to operate on
 *
 * Labels the host part of a memory module.
 *
 * Returns: 0 on success, -1 on error.
 */
int
virSecurityManagerSetMemoryLabel(virSecurityManager *mgr,
                                     virDomainDef *vm,
                                     virDomainMemoryDef *mem)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainSetSecurityMemoryLabel) {
        virReportUnsupportedError();
        return -1;
    }

    return mgr->drv->domainSetSecurityMemoryLabel(mgr, vm, mem);
}


/**
 * virSecurityManagerRestoreMemoryLabel:
 * @mgr: security manager object
 * @vm: domain definition object
 * @mem: memory module to operate on
 *
 * Removes security label from the host part of a memory module.
 *
 * Returns: 0 on success, -1 on error.
 */
int
virSecurityManagerRestoreMemoryLabel(virSecurityManager *mgr,
                                        virDomainDef *vm,
                                        virDomainMemoryDef *mem)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainRestoreSecurityMemoryLabel) {
        virReportUnsupportedError();
        return -1;
    }

    return mgr->drv->domainRestoreSecurityMemoryLabel(mgr, vm, mem);
}


int
virSecurityManagerSetInputLabel(virSecurityManager *mgr,
                                virDomainDef *vm,
                                virDomainInputDef *input)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainSetSecurityInputLabel) {
        virReportUnsupportedError();
        return -1;
    }

    return mgr->drv->domainSetSecurityInputLabel(mgr, vm, input);
}


int
virSecurityManagerRestoreInputLabel(virSecurityManager *mgr,
                                    virDomainDef *vm,
                                    virDomainInputDef *input)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainRestoreSecurityInputLabel) {
        virReportUnsupportedError();
        return -1;
    }

    return mgr->drv->domainRestoreSecurityInputLabel(mgr, vm, input);
}


int
virSecurityManagerSetChardevLabel(virSecurityManager *mgr,
                                  virDomainDef *def,
                                  virDomainChrSourceDef *dev_source,
                                  bool chardevStdioLogd)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainSetSecurityChardevLabel) {
        virReportUnsupportedError();
        return -1;
    }

    return mgr->drv->domainSetSecurityChardevLabel(mgr, def, dev_source,
                                                   chardevStdioLogd);
}


int
virSecurityManagerRestoreChardevLabel(virSecurityManager *mgr,
                                      virDomainDef *def,
                                      virDomainChrSourceDef *dev_source,
                                      bool chardevStdioLogd)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainRestoreSecurityChardevLabel) {
        virReportUnsupportedError();
        return -1;
    }

    return mgr->drv->domainRestoreSecurityChardevLabel(mgr, def, dev_source,
                                                       chardevStdioLogd);
}


int
virSecurityManagerSetTPMLabels(virSecurityManager *mgr,
                               virDomainDef *vm,
                               bool setTPMStateLabel)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainSetSecurityTPMLabels)
        return 0;

    return mgr->drv->domainSetSecurityTPMLabels(mgr, vm, setTPMStateLabel);
}


int
virSecurityManagerRestoreTPMLabels(virSecurityManager *mgr,
                                   virDomainDef *vm,
                                   bool restoreTPMStateLabel)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainRestoreSecurityTPMLabels)
        return 0;

    return mgr->drv->domainRestoreSecurityTPMLabels(mgr, vm, restoreTPMStateLabel);
}


int
virSecurityManagerSetNetdevLabel(virSecurityManager *mgr,
                                 virDomainDef *vm,
                                 virDomainNetDef *net)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainSetSecurityNetdevLabel)
        return 0;

    return mgr->drv->domainSetSecurityNetdevLabel(mgr, vm, net);
}


int
virSecurityManagerRestoreNetdevLabel(virSecurityManager *mgr,
                                     virDomainDef *vm,
                                     virDomainNetDef *net)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mgr);

    if (!mgr->drv->domainRestoreSecurityNetdevLabel)
        return 0;

    return mgr->drv->domainRestoreSecurityNetdevLabel(mgr, vm, net);
}


static int
cmpstringp(const void *p1, const void *p2)
{
    const char *s1 = *(char * const *) p1;
    const char *s2 = *(char * const *) p2;

    if (!s1 && !s2)
        return 0;

    if (!s1 || !s2)
        return s2 ? -1 : 1;

    /* from man 3 qsort */
    return strcmp(s1, s2);
}

#define METADATA_OFFSET 1
#define METADATA_LEN 1

/**
 * virSecurityManagerMetadataLock:
 * @mgr: security manager object
 * @paths: paths to lock
 * @npaths: number of items in @paths array
 *
 * Lock passed @paths for metadata change. The returned state
 * should be passed to virSecurityManagerMetadataUnlock.
 * Passed @paths must not be freed until the corresponding unlock call.
 *
 * NOTE: this function is not thread safe (because of usage of
 * POSIX locks).
 *
 * Returns: state on success,
 *          NULL on failure.
 */
virSecurityManagerMetadataLockState *
virSecurityManagerMetadataLock(virSecurityManager *mgr G_GNUC_UNUSED,
                               const char **paths,
                               size_t npaths)
{
    size_t i = 0;
    size_t nfds = 0;
    int *fds = NULL;
    const char **locked_paths = NULL;
    virSecurityManagerMetadataLockState *ret = NULL;

    fds = g_new0(int, npaths);
    locked_paths = g_new0(const char *, npaths);

    /* Sort paths to lock in order to avoid deadlocks with other
     * processes. For instance, if one process wants to lock
     * paths A B and there's another that is trying to lock them
     * in reversed order a deadlock might occur.  But if we sort
     * the paths alphabetically then both processes will try lock
     * paths in the same order and thus no deadlock can occur.
     * Lastly, it makes searching for duplicate paths below
     * simpler. */
    if (paths)
        qsort(paths, npaths, sizeof(*paths), cmpstringp);

    for (i = 0; i < npaths; i++) {
        const char *p = paths[i];
        struct stat sb;
        size_t j;
        int retries = 10 * 1000;
        int fd;

        if (!p)
            continue;

        /* If there's a duplicate path on the list, skip it over.
         * Not only we would fail open()-ing it the second time,
         * we would deadlock with ourselves trying to lock it the
         * second time. After all, we've locked it when iterating
         * over it the first time. */
        for (j = 0; j < i; j++) {
            if (STREQ_NULLABLE(p, paths[j]))
                break;
        }

        if (i != j)
            continue;

        if (stat(p, &sb) < 0)
            continue;

        if (S_ISDIR(sb.st_mode)) {
            /* We need to open the path for writing because we need exclusive
             * (write) lock. But directories can't be opened for writing. */
            continue;
        }

        if ((fd = open(p, O_RDWR)) < 0) {
            if (errno == EROFS) {
                /* There is nothing we can do for RO filesystem. */
                continue;
            }

#ifndef WIN32
            if (S_ISSOCK(sb.st_mode)) {
                /* Sockets can be opened only if there exists the
                 * other side that listens. */
                continue;
            }
#endif /* !WIN32 */

            if (virFileIsSharedFS(p)) {
                /* Probably a root squashed NFS. */
                continue;
            }

            virReportSystemError(errno,
                                 _("unable to open %1$s"),
                                 p);
            goto cleanup;
        }

        do {
            if (virFileLock(fd, false,
                            METADATA_OFFSET, METADATA_LEN, false) < 0) {
                if (retries && (errno == EACCES || errno == EAGAIN)) {
                    /* File is locked. Try again. */
                    retries--;
                    g_usleep(1000);
                    continue;
                } else {
                    virReportSystemError(errno,
                                         _("unable to lock %1$s for metadata change"),
                                         p);
                    VIR_FORCE_CLOSE(fd);
                    goto cleanup;
                }
            }

            break;
        } while (1);

        locked_paths[nfds] = p;
        VIR_APPEND_ELEMENT_COPY_INPLACE(fds, nfds, fd);
    }

    ret = g_new0(virSecurityManagerMetadataLockState, 1);

    ret->paths = g_steal_pointer(&locked_paths);
    ret->fds = g_steal_pointer(&fds);
    ret->nfds = nfds;
    nfds = 0;

 cleanup:
    for (i = nfds; i > 0; i--)
        VIR_FORCE_CLOSE(fds[i - 1]);
    VIR_FREE(fds);
    VIR_FREE(locked_paths);
    return ret;
}


void
virSecurityManagerMetadataUnlock(virSecurityManager *mgr G_GNUC_UNUSED,
                                 virSecurityManagerMetadataLockState **state)
{
    size_t i;

    if (!state)
        return;

    for (i = 0; i < (*state)->nfds; i++) {
        const char *path = (*state)->paths[i];
        int fd = (*state)->fds[i];

        /* Technically, unlock is not needed because it will
         * happen on VIR_CLOSE() anyway. But let's play it nice. */
        if (virFileUnlock(fd, METADATA_OFFSET, METADATA_LEN) < 0) {
            VIR_WARN("Unable to unlock fd %d path %s: %s",
                     fd, path, g_strerror(errno));
        }

        if (VIR_CLOSE(fd) < 0) {
            VIR_WARN("Unable to close fd %d path %s: %s",
                     fd, path, g_strerror(errno));
        }
    }

    VIR_FREE((*state)->fds);
    VIR_FREE((*state)->paths);
    VIR_FREE(*state);
}
