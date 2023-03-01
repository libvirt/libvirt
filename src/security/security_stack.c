/*
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
 *
 * Stacked security driver
 */

#include <config.h>

#include "security_stack.h"

#include "viralloc.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_SECURITY
VIR_LOG_INIT("security.security_stack");

typedef struct _virSecurityStackData virSecurityStackData;
typedef struct _virSecurityStackItem virSecurityStackItem;

struct _virSecurityStackItem {
    virSecurityManager *securityManager;
    virSecurityStackItem *next;
    virSecurityStackItem *prev;
};

struct _virSecurityStackData {
    virSecurityStackItem *itemsHead;
};

int
virSecurityStackAddNested(virSecurityManager *mgr,
                          virSecurityManager *nested)
{
    virSecurityStackItem *item = NULL;
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *tmp;

    tmp = priv->itemsHead;
    while (tmp && tmp->next)
        tmp = tmp->next;

    item = g_new0(virSecurityStackItem, 1);
    item->securityManager = nested;
    item->prev = tmp;
    if (tmp)
        tmp->next = item;
    else
        priv->itemsHead = item;

    return 0;
}

virSecurityManager *
virSecurityStackGetPrimary(virSecurityManager *mgr)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    return priv->itemsHead->securityManager;
}

static virSecurityDriverStatus
virSecurityStackProbe(const char *virtDriver G_GNUC_UNUSED)
{
    return SECURITY_DRIVER_ENABLE;
}

static int
virSecurityStackOpen(virSecurityManager *mgr G_GNUC_UNUSED)
{
    return 0;
}

static int
virSecurityStackClose(virSecurityManager *mgr)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;
    virSecurityStackItem *next;

    while (item) {
        next = item->next;
        virObjectUnref(item->securityManager);
        VIR_FREE(item);
        item = next;
    }

    return 0;
}

static const char *
virSecurityStackGetModel(virSecurityManager *mgr)
{
    return virSecurityManagerGetModel(virSecurityStackGetPrimary(mgr));
}

static const char *
virSecurityStackGetDOI(virSecurityManager *mgr)
{
    return virSecurityManagerGetDOI(virSecurityStackGetPrimary(mgr));
}

static int
virSecurityStackPreFork(virSecurityManager *mgr)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;
    int rc = 0;

    /* XXX For now, we rely on no driver having any state that requires
     * rollback if a later driver in the stack fails; if this changes,
     * we'd need to split this into transaction semantics by dividing
     * the work into prepare/commit/abort.  */
    for (; item; item = item->next) {
        if (virSecurityManagerPreFork(item->securityManager) < 0) {
            rc = -1;
            break;
        }
        /* Undo the unbalanced locking left behind after recursion; if
         * PostFork ever delegates to driver callbacks, we'd instead
         * need to recurse to an internal method that does not regrab
         * a lock. */
        virSecurityManagerPostFork(item->securityManager);
    }

    return rc;
}


static int
virSecurityStackTransactionStart(virSecurityManager *mgr)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;

    for (; item; item = item->next) {
        if (virSecurityManagerTransactionStart(item->securityManager) < 0)
            goto rollback;
    }

    return 0;

 rollback:
    for (item = item->prev; item; item = item->prev)
        virSecurityManagerTransactionAbort(item->securityManager);
    return -1;
}


static int
virSecurityStackTransactionCommit(virSecurityManager *mgr,
                                  pid_t pid,
                                  bool lock)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;

    for (; item; item = item->next) {
        if (virSecurityManagerTransactionCommit(item->securityManager, pid, lock) < 0)
            goto rollback;
    }

    return 0;

 rollback:
    for (item = item->prev; item; item = item->prev)
        virSecurityManagerTransactionAbort(item->securityManager);
    return -1;
}


static void
virSecurityStackTransactionAbort(virSecurityManager *mgr)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;

    for (; item; item = item->next)
        virSecurityManagerTransactionAbort(item->securityManager);
}


static int
virSecurityStackVerify(virSecurityManager *mgr,
                       virDomainDef *def)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerVerify(item->securityManager, def) < 0) {
            rc = -1;
            break;
        }
    }

    return rc;
}


static int
virSecurityStackGenLabel(virSecurityManager *mgr,
                         virDomainDef *vm)
{
    int rc = 0;

    if (virSecurityManagerGenLabel(virSecurityStackGetPrimary(mgr), vm) < 0)
        rc = -1;

/* TODO */
#if 0
    /* We don't allow secondary drivers to generate labels.
     * This may have to change in the future, but requires
     * changes elsewhere in domain_conf.c and capabilities.c
     * XML formats first, to allow recording of multiple
     * labels
     */
    if (virSecurityManagerGenLabel(priv->secondary, vm) < 0)
        rc = -1;
#endif

    return rc;
}


static int
virSecurityStackReleaseLabel(virSecurityManager *mgr,
                             virDomainDef *vm)
{
    int rc = 0;

    if (virSecurityManagerReleaseLabel(virSecurityStackGetPrimary(mgr), vm) < 0)
        rc = -1;

/* TODO */
#if 0
    /* XXX See note in GenLabel */
    if (virSecurityManagerReleaseLabel(priv->secondary, vm) < 0)
        rc = -1;
#endif

    return rc;
}


static int
virSecurityStackReserveLabel(virSecurityManager *mgr,
                             virDomainDef *vm,
                             pid_t pid)
{
    int rc = 0;

    if (virSecurityManagerReserveLabel(virSecurityStackGetPrimary(mgr), vm, pid) < 0)
        rc = -1;
/* TODO */
#if 0
    /* XXX See note in GenLabel */
    if (virSecurityManagerReserveLabel(priv->secondary, vm, pid) < 0)
        rc = -1;
#endif

    return rc;
}


static int
virSecurityStackSetHostdevLabel(virSecurityManager *mgr,
                                virDomainDef *vm,
                                virDomainHostdevDef *dev,
                                const char *vroot)

{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;

    for (; item; item = item->next) {
        if (virSecurityManagerSetHostdevLabel(item->securityManager,
                                              vm,
                                              dev,
                                              vroot) < 0)
            goto rollback;
    }

    return 0;

 rollback:
    for (item = item->prev; item; item = item->prev) {
        if (virSecurityManagerRestoreHostdevLabel(item->securityManager,
                                                  vm,
                                                  dev,
                                                  vroot) < 0) {
            VIR_WARN("Unable to restore hostdev label after failed set label "
                     "call virDriver=%s driver=%s domain=%s hostdev=%p",
                     virSecurityManagerGetVirtDriver(mgr),
                     virSecurityManagerGetDriver(item->securityManager),
                     vm->name, dev);
        }
    }
    return -1;
}


static int
virSecurityStackRestoreHostdevLabel(virSecurityManager *mgr,
                                    virDomainDef *vm,
                                    virDomainHostdevDef *dev,
                                    const char *vroot)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerRestoreHostdevLabel(item->securityManager,
                                                  vm,
                                                  dev,
                                                  vroot) < 0)
            rc = -1;
    }

    return rc;
}


static int
virSecurityStackSetAllLabel(virSecurityManager *mgr,
                            virDomainDef *vm,
                            const char *incomingPath,
                            bool chardevStdioLogd,
                            bool migrated)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;

    for (; item; item = item->next) {
        if (virSecurityManagerSetAllLabel(item->securityManager, vm,
                                          incomingPath, chardevStdioLogd,
                                          migrated) < 0)
            goto rollback;
    }

    return 0;

 rollback:
    for (item = item->prev; item; item = item->prev) {
        if (virSecurityManagerRestoreAllLabel(item->securityManager,
                                              vm,
                                              migrated,
                                              chardevStdioLogd) < 0) {
            VIR_WARN("Unable to restore all labels after failed set label call "
                     "virDriver=%s driver=%s domain=%s migrated=%d",
                     virSecurityManagerGetVirtDriver(mgr),
                     virSecurityManagerGetDriver(item->securityManager),
                     vm->name, migrated);
        }
    }
    return -1;
}


static int
virSecurityStackRestoreAllLabel(virSecurityManager *mgr,
                                virDomainDef *vm,
                                bool migrated,
                                bool chardevStdioLogd)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerRestoreAllLabel(item->securityManager, vm,
                                              migrated, chardevStdioLogd) < 0)
            rc = -1;
    }

    return rc;
}


static int
virSecurityStackSetSavedStateLabel(virSecurityManager *mgr,
                                   virDomainDef *vm,
                                   const char *savefile)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;

    for (; item; item = item->next) {
        if (virSecurityManagerSetSavedStateLabel(item->securityManager, vm, savefile) < 0)
            goto rollback;
    }

    return 0;

 rollback:
    for (item = item->prev; item; item = item->prev) {
        if (virSecurityManagerRestoreSavedStateLabel(item->securityManager,
                                                     vm,
                                                     savefile) < 0) {
            VIR_WARN("Unable to restore saved state label after failed set "
                     "label call virDriver=%s driver=%s savefile=%s",
                     virSecurityManagerGetVirtDriver(mgr),
                     virSecurityManagerGetDriver(item->securityManager),
                     savefile);
        }
    }
    return -1;
}


static int
virSecurityStackRestoreSavedStateLabel(virSecurityManager *mgr,
                                       virDomainDef *vm,
                                       const char *savefile)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerRestoreSavedStateLabel(item->securityManager, vm, savefile) < 0)
            rc = -1;
    }

    return rc;
}

static int
virSecurityStackSetProcessLabel(virSecurityManager *mgr,
                                virDomainDef *vm)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerSetProcessLabel(item->securityManager, vm) < 0)
            rc = -1;
    }

    return rc;
}

static int
virSecurityStackSetChildProcessLabel(virSecurityManager *mgr,
                                     virDomainDef *vm,
                                     bool useBinarySpecificLabel,
                                     virCommand *cmd)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerSetChildProcessLabel(item->securityManager, vm,
                                                   useBinarySpecificLabel, cmd) < 0) {
            rc = -1;
        }
    }

    return rc;
}

static int
virSecurityStackGetProcessLabel(virSecurityManager *mgr,
                                virDomainDef *vm,
                                pid_t pid,
                                virSecurityLabelPtr seclabel)
{
    int rc = 0;

/* TODO */
#if 0
    if (virSecurityManagerGetProcessLabel(priv->secondary, vm, pid, seclabel) < 0)
        rc = -1;
#endif
    if (virSecurityManagerGetProcessLabel(virSecurityStackGetPrimary(mgr), vm, pid, seclabel) < 0)
        rc = -1;

    return rc;
}


static int
virSecurityStackSetDaemonSocketLabel(virSecurityManager *mgr,
                                     virDomainDef *vm)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;

    for (; item; item = item->next) {
        if (virSecurityManagerSetDaemonSocketLabel(item->securityManager, vm) < 0)
            goto rollback;
    }

    return 0;
 rollback:
    for (item = item->prev; item; item = item->prev) {
        if (virSecurityManagerClearSocketLabel(item->securityManager,
                                               vm) < 0) {
            VIR_WARN("Unable to clear new daemon socket label after failed "
                     "set label call virDriver=%s driver=%s domain=%s",
                     virSecurityManagerGetVirtDriver(mgr),
                     virSecurityManagerGetDriver(item->securityManager),
                     vm->name);
        }
    }
    return -1;
}


static int
virSecurityStackSetSocketLabel(virSecurityManager *mgr,
                               virDomainDef *vm)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;

    for (; item; item = item->next) {
        if (virSecurityManagerSetSocketLabel(item->securityManager, vm) < 0)
            goto rollback;
    }

    return 0;
 rollback:
    for (item = item->prev; item; item = item->prev) {
        if (virSecurityManagerClearSocketLabel(item->securityManager,
                                               vm) < 0) {
            VIR_WARN("Unable to clear new socket label after failed "
                     "set label call virDriver=%s driver=%s domain=%s",
                     virSecurityManagerGetVirtDriver(mgr),
                     virSecurityManagerGetDriver(item->securityManager),
                     vm->name);
        }
    }
    return -1;
}


static int
virSecurityStackClearSocketLabel(virSecurityManager *mgr,
                                 virDomainDef *vm)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerClearSocketLabel(item->securityManager, vm) < 0)
            rc = -1;
    }

    return rc;
}

static int
virSecurityStackSetImageFDLabel(virSecurityManager *mgr,
                                virDomainDef *vm,
                                int fd)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerSetImageFDLabel(item->securityManager, vm, fd) < 0)
            rc = -1;
    }

    return rc;
}

static int
virSecurityStackSetTapFDLabel(virSecurityManager *mgr,
                              virDomainDef *vm,
                              int fd)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerSetTapFDLabel(item->securityManager, vm, fd) < 0)
            rc = -1;
    }

    return rc;
}

static char *
virSecurityStackGetMountOptions(virSecurityManager *mgr G_GNUC_UNUSED,
                                virDomainDef *vm G_GNUC_UNUSED)
{
    return NULL;
}

virSecurityManager **
virSecurityStackGetNested(virSecurityManager *mgr)
{
    virSecurityManager **list = NULL;
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item;
    int len = 0;
    size_t i;

    for (item = priv->itemsHead; item; item = item->next)
        len++;

    list = g_new0(virSecurityManager *, len + 1);

    for (i = 0, item = priv->itemsHead; item; item = item->next, i++)
        list[i] = item->securityManager;
    list[len] = NULL;

    return list;
}

static const char *
virSecurityStackGetBaseLabel(virSecurityManager *mgr, int virtType)
{
    return virSecurityManagerGetBaseLabel(virSecurityStackGetPrimary(mgr),
                                          virtType);
}

static int
virSecurityStackSetImageLabel(virSecurityManager *mgr,
                              virDomainDef *vm,
                              virStorageSource *src,
                              virSecurityDomainImageLabelFlags flags)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;

    for (; item; item = item->next) {
        if (virSecurityManagerSetImageLabel(item->securityManager, vm, src,
                                            flags) < 0)
            goto rollback;
    }

    return 0;

 rollback:
    for (item = item->prev; item; item = item->prev) {
        if (virSecurityManagerRestoreImageLabel(item->securityManager,
                                                vm,
                                                src,
                                                flags) < 0) {
            VIR_WARN("Unable to restore image label after failed set label "
                     "call virDriver=%s driver=%s domain=%s src=%p (path=%s) "
                     "flags=0x%x",
                     virSecurityManagerGetVirtDriver(mgr),
                     virSecurityManagerGetDriver(item->securityManager),
                     vm->name, src, NULLSTR(src->path), flags);
        }
    }
    return -1;
}

static int
virSecurityStackRestoreImageLabel(virSecurityManager *mgr,
                                  virDomainDef *vm,
                                  virStorageSource *src,
                                  virSecurityDomainImageLabelFlags flags)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerRestoreImageLabel(item->securityManager,
                                                vm, src, flags) < 0)
            rc = -1;
    }

    return rc;
}

static int
virSecurityStackMoveImageMetadata(virSecurityManager *mgr,
                                  pid_t pid,
                                  virStorageSource *src,
                                  virStorageSource *dst)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerMoveImageMetadata(item->securityManager,
                                                pid, src, dst) < 0)
            rc = -1;
    }

    return rc;
}

static int
virSecurityStackSetMemoryLabel(virSecurityManager *mgr,
                               virDomainDef *vm,
                               virDomainMemoryDef *mem)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;

    for (; item; item = item->next) {
        if (virSecurityManagerSetMemoryLabel(item->securityManager, vm, mem) < 0)
            goto rollback;
    }

    return 0;

 rollback:
    for (item = item->prev; item; item = item->prev) {
        if (virSecurityManagerRestoreMemoryLabel(item->securityManager,
                                                 vm,
                                                 mem) < 0) {
            VIR_WARN("Unable to restore memory label after failed set label "
                     "call virDriver=%s driver=%s domain=%s mem=%p",
                     virSecurityManagerGetVirtDriver(mgr),
                     virSecurityManagerGetDriver(item->securityManager),
                     vm->name, mem);
        }
    }
    return -1;
}

static int
virSecurityStackRestoreMemoryLabel(virSecurityManager *mgr,
                                   virDomainDef *vm,
                                   virDomainMemoryDef *mem)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerRestoreMemoryLabel(item->securityManager,
                                                 vm, mem) < 0)
            rc = -1;
    }

    return rc;
}

static int
virSecurityStackSetInputLabel(virSecurityManager *mgr,
                              virDomainDef *vm,
                              virDomainInputDef *input)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;

    for (; item; item = item->next) {
        if (virSecurityManagerSetInputLabel(item->securityManager, vm, input) < 0)
            goto rollback;
    }

    return 0;

 rollback:
    for (item = item->prev; item; item = item->prev) {
        if (virSecurityManagerRestoreInputLabel(item->securityManager,
                                                vm,
                                                input) < 0) {
            VIR_WARN("Unable to restore input label after failed set label "
                     "call virDriver=%s driver=%s domain=%s input=%p",
                     virSecurityManagerGetVirtDriver(mgr),
                     virSecurityManagerGetDriver(item->securityManager),
                     vm->name, input);
        }
    }
    return -1;
}

static int
virSecurityStackRestoreInputLabel(virSecurityManager *mgr,
                                  virDomainDef *vm,
                                  virDomainInputDef *input)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerRestoreInputLabel(item->securityManager,
                                                vm, input) < 0)
            rc = -1;
    }

    return rc;
}

static int
virSecurityStackDomainSetPathLabel(virSecurityManager *mgr,
                                   virDomainDef *vm,
                                   const char *path,
                                   bool allowSubtree)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerDomainSetPathLabel(item->securityManager,
                                                 vm, path, allowSubtree) < 0)
            rc = -1;
    }

    return rc;
}


static int
virSecurityStackDomainSetPathLabelRO(virSecurityManager *mgr,
                                     virDomainDef *vm,
                                     const char *path)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerDomainSetPathLabelRO(item->securityManager,
                                                   vm, path) < 0)
            rc = -1;
    }

    return rc;
}


static int
virSecurityStackDomainRestorePathLabel(virSecurityManager *mgr,
                                       virDomainDef *vm,
                                       const char *path)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerDomainRestorePathLabel(item->securityManager,
                                                     vm, path) < 0)
            rc = -1;
    }

    return rc;
}


static int
virSecurityStackDomainSetChardevLabel(virSecurityManager *mgr,
                                      virDomainDef *def,
                                      virDomainChrSourceDef *dev_source,
                                      bool chardevStdioLogd)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;

    for (; item; item = item->next) {
        if (virSecurityManagerSetChardevLabel(item->securityManager,
                                              def, dev_source,
                                              chardevStdioLogd) < 0)
            goto rollback;
    }

    return 0;

 rollback:
    for (item = item->prev; item; item = item->prev) {
        if (virSecurityManagerRestoreChardevLabel(item->securityManager,
                                                  def,
                                                  dev_source,
                                                  chardevStdioLogd) < 0) {
            VIR_WARN("Unable to restore chardev label after failed set label "
                     "call virDriver=%s driver=%s domain=%s dev_source=%p",
                     virSecurityManagerGetVirtDriver(mgr),
                     virSecurityManagerGetDriver(item->securityManager),
                     def->name, dev_source);
        }
    }
    return -1;
}

static int
virSecurityStackDomainRestoreChardevLabel(virSecurityManager *mgr,
                                          virDomainDef *def,
                                          virDomainChrSourceDef *dev_source,
                                          bool chardevStdioLogd)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerRestoreChardevLabel(item->securityManager,
                                                  def, dev_source,
                                                  chardevStdioLogd) < 0)
            rc = -1;
    }

    return rc;
}


static int
virSecurityStackSetTPMLabels(virSecurityManager *mgr,
                             virDomainDef *vm,
                             bool setTPMStateLabel)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;

    for (; item; item = item->next) {
        if (virSecurityManagerSetTPMLabels(item->securityManager,
                                           vm, setTPMStateLabel) < 0)
            goto rollback;
    }

    return 0;

 rollback:
    for (item = item->prev; item; item = item->prev) {
        if (virSecurityManagerRestoreTPMLabels(item->securityManager,
                                               vm, setTPMStateLabel) < 0) {
            VIR_WARN("Unable to restore TPM label after failed set label "
                     "call virDriver=%s driver=%s domain=%s",
                     virSecurityManagerGetVirtDriver(mgr),
                     virSecurityManagerGetDriver(item->securityManager),
                     vm->name);
        }
    }
    return -1;
}


static int
virSecurityStackRestoreTPMLabels(virSecurityManager *mgr,
                                 virDomainDef *vm,
                                 bool restoreTPMStateLabel)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerRestoreTPMLabels(item->securityManager,
                                               vm, restoreTPMStateLabel) < 0)
            rc = -1;
    }

    return rc;
}


static int
virSecurityStackDomainSetNetdevLabel(virSecurityManager *mgr,
                                     virDomainDef *def,
                                     virDomainNetDef *net)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;

    for (; item; item = item->next) {
        if (virSecurityManagerSetNetdevLabel(item->securityManager, def, net) < 0)
            goto rollback;
    }

    return 0;

 rollback:
    for (item = item->prev; item; item = item->prev) {
        if (virSecurityManagerRestoreNetdevLabel(item->securityManager,
                                                 def, net) < 0) {
            VIR_WARN("Unable to restore netdev label after failed set label "
                     "call virDriver=%s driver=%s domain=%s",
                     virSecurityManagerGetVirtDriver(mgr),
                     virSecurityManagerGetDriver(item->securityManager),
                     def->name);
        }
    }
    return -1;
}


static int
virSecurityStackDomainRestoreNetdevLabel(virSecurityManager *mgr,
                                         virDomainDef *def,
                                         virDomainNetDef *net)
{
    virSecurityStackData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItem *item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerRestoreNetdevLabel(item->securityManager,
                                                 def, net) < 0)
            rc = -1;
    }

    return rc;
}


virSecurityDriver virSecurityDriverStack = {
    .privateDataLen                     = sizeof(virSecurityStackData),
    .name                               = "stack",
    .probe                              = virSecurityStackProbe,
    .open                               = virSecurityStackOpen,
    .close                              = virSecurityStackClose,

    .getModel                           = virSecurityStackGetModel,
    .getDOI                             = virSecurityStackGetDOI,

    .preFork                            = virSecurityStackPreFork,

    .transactionStart                   = virSecurityStackTransactionStart,
    .transactionCommit                  = virSecurityStackTransactionCommit,
    .transactionAbort                   = virSecurityStackTransactionAbort,

    .domainSecurityVerify               = virSecurityStackVerify,

    .domainSetSecurityImageLabel        = virSecurityStackSetImageLabel,
    .domainRestoreSecurityImageLabel    = virSecurityStackRestoreImageLabel,
    .domainMoveImageMetadata            = virSecurityStackMoveImageMetadata,

    .domainSetSecurityMemoryLabel       = virSecurityStackSetMemoryLabel,
    .domainRestoreSecurityMemoryLabel   = virSecurityStackRestoreMemoryLabel,

    .domainSetSecurityInputLabel        = virSecurityStackSetInputLabel,
    .domainRestoreSecurityInputLabel    = virSecurityStackRestoreInputLabel,

    .domainSetSecurityDaemonSocketLabel = virSecurityStackSetDaemonSocketLabel,
    .domainSetSecuritySocketLabel       = virSecurityStackSetSocketLabel,
    .domainClearSecuritySocketLabel     = virSecurityStackClearSocketLabel,

    .domainGenSecurityLabel             = virSecurityStackGenLabel,
    .domainReserveSecurityLabel         = virSecurityStackReserveLabel,
    .domainReleaseSecurityLabel         = virSecurityStackReleaseLabel,

    .domainGetSecurityProcessLabel      = virSecurityStackGetProcessLabel,
    .domainSetSecurityProcessLabel      = virSecurityStackSetProcessLabel,
    .domainSetSecurityChildProcessLabel = virSecurityStackSetChildProcessLabel,

    .domainSetSecurityAllLabel          = virSecurityStackSetAllLabel,
    .domainRestoreSecurityAllLabel      = virSecurityStackRestoreAllLabel,

    .domainSetSecurityHostdevLabel      = virSecurityStackSetHostdevLabel,
    .domainRestoreSecurityHostdevLabel  = virSecurityStackRestoreHostdevLabel,

    .domainSetSavedStateLabel           = virSecurityStackSetSavedStateLabel,
    .domainRestoreSavedStateLabel       = virSecurityStackRestoreSavedStateLabel,

    .domainSetSecurityImageFDLabel      = virSecurityStackSetImageFDLabel,
    .domainSetSecurityTapFDLabel        = virSecurityStackSetTapFDLabel,

    .domainGetSecurityMountOptions      = virSecurityStackGetMountOptions,

    .getBaseLabel                       = virSecurityStackGetBaseLabel,

    .domainSetPathLabel                 = virSecurityStackDomainSetPathLabel,
    .domainSetPathLabelRO               = virSecurityStackDomainSetPathLabelRO,
    .domainRestorePathLabel             = virSecurityStackDomainRestorePathLabel,

    .domainSetSecurityChardevLabel      = virSecurityStackDomainSetChardevLabel,
    .domainRestoreSecurityChardevLabel  = virSecurityStackDomainRestoreChardevLabel,

    .domainSetSecurityTPMLabels         = virSecurityStackSetTPMLabels,
    .domainRestoreSecurityTPMLabels     = virSecurityStackRestoreTPMLabels,

    .domainSetSecurityNetdevLabel      = virSecurityStackDomainSetNetdevLabel,
    .domainRestoreSecurityNetdevLabel  = virSecurityStackDomainRestoreNetdevLabel,
};
