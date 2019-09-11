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

#include "virerror.h"
#include "viralloc.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_SECURITY
VIR_LOG_INIT("security.security_stack");

typedef struct _virSecurityStackData virSecurityStackData;
typedef virSecurityStackData *virSecurityStackDataPtr;
typedef struct _virSecurityStackItem virSecurityStackItem;
typedef virSecurityStackItem *virSecurityStackItemPtr;

struct _virSecurityStackItem {
    virSecurityManagerPtr securityManager;
    virSecurityStackItemPtr next;
    virSecurityStackItemPtr prev;
};

struct _virSecurityStackData {
    virSecurityStackItemPtr itemsHead;
};

int
virSecurityStackAddNested(virSecurityManagerPtr mgr,
                          virSecurityManagerPtr nested)
{
    virSecurityStackItemPtr item = NULL;
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr tmp;

    tmp = priv->itemsHead;
    while (tmp && tmp->next)
        tmp = tmp->next;

    if (VIR_ALLOC(item) < 0)
        return -1;
    item->securityManager = nested;
    item->prev = tmp;
    if (tmp)
        tmp->next = item;
    else
        priv->itemsHead = item;

    return 0;
}

virSecurityManagerPtr
virSecurityStackGetPrimary(virSecurityManagerPtr mgr)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    return priv->itemsHead->securityManager;
}

static virSecurityDriverStatus
virSecurityStackProbe(const char *virtDriver ATTRIBUTE_UNUSED)
{
    return SECURITY_DRIVER_ENABLE;
}

static int
virSecurityStackOpen(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED)
{
    return 0;
}

static int
virSecurityStackClose(virSecurityManagerPtr mgr)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr next, item = priv->itemsHead;

    while (item) {
        next = item->next;
        virObjectUnref(item->securityManager);
        VIR_FREE(item);
        item = next;
    }

    return 0;
}

static const char *
virSecurityStackGetModel(virSecurityManagerPtr mgr)
{
    return virSecurityManagerGetModel(virSecurityStackGetPrimary(mgr));
}

static const char *
virSecurityStackGetDOI(virSecurityManagerPtr mgr)
{
    return virSecurityManagerGetDOI(virSecurityStackGetPrimary(mgr));
}

static int
virSecurityStackPreFork(virSecurityManagerPtr mgr)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;
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
virSecurityStackTransactionStart(virSecurityManagerPtr mgr)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;

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
virSecurityStackTransactionCommit(virSecurityManagerPtr mgr,
                                  pid_t pid,
                                  bool lock)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;

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
virSecurityStackTransactionAbort(virSecurityManagerPtr mgr)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;

    for (; item; item = item->next)
        virSecurityManagerTransactionAbort(item->securityManager);
}


static int
virSecurityStackVerify(virSecurityManagerPtr mgr,
                       virDomainDefPtr def)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;
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
virSecurityStackGenLabel(virSecurityManagerPtr mgr,
                         virDomainDefPtr vm)
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
virSecurityStackReleaseLabel(virSecurityManagerPtr mgr,
                             virDomainDefPtr vm)
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
virSecurityStackReserveLabel(virSecurityManagerPtr mgr,
                             virDomainDefPtr vm,
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
virSecurityStackSetHostdevLabel(virSecurityManagerPtr mgr,
                                virDomainDefPtr vm,
                                virDomainHostdevDefPtr dev,
                                const char *vroot)

{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;

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
virSecurityStackRestoreHostdevLabel(virSecurityManagerPtr mgr,
                                    virDomainDefPtr vm,
                                    virDomainHostdevDefPtr dev,
                                    const char *vroot)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;
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
virSecurityStackSetAllLabel(virSecurityManagerPtr mgr,
                            virDomainDefPtr vm,
                            const char *stdin_path,
                            bool chardevStdioLogd,
                            bool migrated)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;

    for (; item; item = item->next) {
        if (virSecurityManagerSetAllLabel(item->securityManager, vm,
                                          stdin_path, chardevStdioLogd,
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
virSecurityStackRestoreAllLabel(virSecurityManagerPtr mgr,
                                virDomainDefPtr vm,
                                bool migrated,
                                bool chardevStdioLogd)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerRestoreAllLabel(item->securityManager, vm,
                                              migrated, chardevStdioLogd) < 0)
            rc = -1;
    }

    return rc;
}


static int
virSecurityStackSetSavedStateLabel(virSecurityManagerPtr mgr,
                                   virDomainDefPtr vm,
                                   const char *savefile)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;

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
virSecurityStackRestoreSavedStateLabel(virSecurityManagerPtr mgr,
                                       virDomainDefPtr vm,
                                       const char *savefile)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerRestoreSavedStateLabel(item->securityManager, vm, savefile) < 0)
            rc = -1;
    }

    return rc;
}


static int
virSecurityStackSetProcessLabel(virSecurityManagerPtr mgr,
                                virDomainDefPtr vm)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerSetProcessLabel(item->securityManager, vm) < 0)
            rc = -1;
    }

    return rc;
}

static int
virSecurityStackSetChildProcessLabel(virSecurityManagerPtr mgr,
                                     virDomainDefPtr vm,
                                     virCommandPtr cmd)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerSetChildProcessLabel(item->securityManager, vm, cmd) < 0)
            rc = -1;
    }

    return rc;
}

static int
virSecurityStackGetProcessLabel(virSecurityManagerPtr mgr,
                                virDomainDefPtr vm,
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
virSecurityStackSetDaemonSocketLabel(virSecurityManagerPtr mgr,
                                     virDomainDefPtr vm)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;

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
virSecurityStackSetSocketLabel(virSecurityManagerPtr mgr,
                               virDomainDefPtr vm)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;

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
virSecurityStackClearSocketLabel(virSecurityManagerPtr mgr,
                                 virDomainDefPtr vm)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerClearSocketLabel(item->securityManager, vm) < 0)
            rc = -1;
    }

    return rc;
}

static int
virSecurityStackSetImageFDLabel(virSecurityManagerPtr mgr,
                                virDomainDefPtr vm,
                                int fd)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerSetImageFDLabel(item->securityManager, vm, fd) < 0)
            rc = -1;
    }

    return rc;
}

static int
virSecurityStackSetTapFDLabel(virSecurityManagerPtr mgr,
                              virDomainDefPtr vm,
                              int fd)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerSetTapFDLabel(item->securityManager, vm, fd) < 0)
            rc = -1;
    }

    return rc;
}

static char *
virSecurityStackGetMountOptions(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                virDomainDefPtr vm ATTRIBUTE_UNUSED)
{
    return NULL;
}

virSecurityManagerPtr*
virSecurityStackGetNested(virSecurityManagerPtr mgr)
{
    virSecurityManagerPtr *list = NULL;
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item;
    int len = 0;
    size_t i;

    for (item = priv->itemsHead; item; item = item->next)
        len++;

    if (VIR_ALLOC_N(list, len + 1) < 0)
        return NULL;

    for (i = 0, item = priv->itemsHead; item; item = item->next, i++)
        list[i] = item->securityManager;
    list[len] = NULL;

    return list;
}

static const char *
virSecurityStackGetBaseLabel(virSecurityManagerPtr mgr, int virtType)
{
    return virSecurityManagerGetBaseLabel(virSecurityStackGetPrimary(mgr),
                                          virtType);
}

static int
virSecurityStackSetImageLabel(virSecurityManagerPtr mgr,
                              virDomainDefPtr vm,
                              virStorageSourcePtr src,
                              virSecurityDomainImageLabelFlags flags)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;

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
virSecurityStackRestoreImageLabel(virSecurityManagerPtr mgr,
                                  virDomainDefPtr vm,
                                  virStorageSourcePtr src,
                                  virSecurityDomainImageLabelFlags flags)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerRestoreImageLabel(item->securityManager,
                                                vm, src, flags) < 0)
            rc = -1;
    }

    return rc;
}

static int
virSecurityStackMoveImageMetadata(virSecurityManagerPtr mgr,
                                  pid_t pid,
                                  virStorageSourcePtr src,
                                  virStorageSourcePtr dst)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerMoveImageMetadata(item->securityManager,
                                                pid, src, dst) < 0)
            rc = -1;
    }

    return rc;
}

static int
virSecurityStackSetMemoryLabel(virSecurityManagerPtr mgr,
                               virDomainDefPtr vm,
                               virDomainMemoryDefPtr mem)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;

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
virSecurityStackRestoreMemoryLabel(virSecurityManagerPtr mgr,
                                   virDomainDefPtr vm,
                                   virDomainMemoryDefPtr mem)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerRestoreMemoryLabel(item->securityManager,
                                                 vm, mem) < 0)
            rc = -1;
    }

    return rc;
}

static int
virSecurityStackSetInputLabel(virSecurityManagerPtr mgr,
                              virDomainDefPtr vm,
                              virDomainInputDefPtr input)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;

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
virSecurityStackRestoreInputLabel(virSecurityManagerPtr mgr,
                                  virDomainDefPtr vm,
                                  virDomainInputDefPtr input)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerRestoreInputLabel(item->securityManager,
                                                vm, input) < 0)
            rc = -1;
    }

    return rc;
}

static int
virSecurityStackDomainSetPathLabel(virSecurityManagerPtr mgr,
                                   virDomainDefPtr vm,
                                   const char *path,
                                   bool allowSubtree)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerDomainSetPathLabel(item->securityManager,
                                                 vm, path, allowSubtree) < 0)
            rc = -1;
    }

    return rc;
}

static int
virSecurityStackDomainSetChardevLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr def,
                                      virDomainChrSourceDefPtr dev_source,
                                      bool chardevStdioLogd)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;

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
virSecurityStackDomainRestoreChardevLabel(virSecurityManagerPtr mgr,
                                          virDomainDefPtr def,
                                          virDomainChrSourceDefPtr dev_source,
                                          bool chardevStdioLogd)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;
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
virSecurityStackSetTPMLabels(virSecurityManagerPtr mgr,
                             virDomainDefPtr vm)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;

    for (; item; item = item->next) {
        if (virSecurityManagerSetTPMLabels(item->securityManager,
                                           vm) < 0)
            goto rollback;
    }

    return 0;

 rollback:
    for (item = item->prev; item; item = item->prev) {
        if (virSecurityManagerRestoreTPMLabels(item->securityManager,
                                               vm) < 0) {
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
virSecurityStackRestoreTPMLabels(virSecurityManagerPtr mgr,
                                 virDomainDefPtr vm)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityStackItemPtr item = priv->itemsHead;
    int rc = 0;

    for (; item; item = item->next) {
        if (virSecurityManagerRestoreTPMLabels(item->securityManager,
                                               vm) < 0)
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

    .domainSetSecurityChardevLabel      = virSecurityStackDomainSetChardevLabel,
    .domainRestoreSecurityChardevLabel  = virSecurityStackDomainRestoreChardevLabel,

    .domainSetSecurityTPMLabels         = virSecurityStackSetTPMLabels,
    .domainRestoreSecurityTPMLabels     = virSecurityStackRestoreTPMLabels,
};
