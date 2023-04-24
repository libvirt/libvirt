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
 * POSIX DAC security driver
 */

#include <config.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef  __FreeBSD__
# include <sys/sysctl.h>
# include <sys/user.h>
#endif

#include "security_dac.h"
#include "security_util.h"
#include "virerror.h"
#include "virfile.h"
#include "viralloc.h"
#include "virlog.h"
#include "virmdev.h"
#include "virpci.h"
#include "virusb.h"
#include "virscsi.h"
#include "virscsivhost.h"
#include "virstring.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_SECURITY

VIR_LOG_INIT("security.security_dac");

#define SECURITY_DAC_NAME "dac"

typedef struct _virSecurityDACData virSecurityDACData;
struct _virSecurityDACData {
    uid_t user;
    gid_t group;
    gid_t *groups;
    int ngroups;
    bool dynamicOwnership;
    bool mountNamespace;
    char *baselabel;
    virSecurityManagerDACChownCallback chownCallback;
};

typedef struct _virSecurityDACCallbackData virSecurityDACCallbackData;
struct _virSecurityDACCallbackData {
    virSecurityManager *manager;
    virSecurityLabelDef *secdef;
};

typedef struct _virSecurityDACChownItem virSecurityDACChownItem;
struct _virSecurityDACChownItem {
    char *path;
    const virStorageSource *src;
    uid_t uid;
    gid_t gid;
    bool remember; /* Whether owner remembering should be done for @path/@src */
    bool restore; /* Whether current operation is 'set' or 'restore' */
};

typedef struct _virSecurityDACChownList virSecurityDACChownList;
struct _virSecurityDACChownList {
    virSecurityManager *manager;
    virSecurityDACChownItem **items;
    size_t nItems;
    bool lock;
};


virThreadLocal chownList;

static void
virSecurityDACChownItemFree(virSecurityDACChownItem *item)
{
    if (!item)
        return;

    g_free(item->path);
    g_free(item);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virSecurityDACChownItem, virSecurityDACChownItemFree);

static int
virSecurityDACChownListAppend(virSecurityDACChownList *list,
                              const char *path,
                              const virStorageSource *src,
                              uid_t uid,
                              gid_t gid,
                              bool remember,
                              bool restore)
{
    g_autoptr(virSecurityDACChownItem) item = NULL;

    item = g_new0(virSecurityDACChownItem, 1);

    item->path = g_strdup(path);
    item->src = src;
    item->uid = uid;
    item->gid = gid;
    item->remember = remember;
    item->restore = restore;

    VIR_APPEND_ELEMENT(list->items, list->nItems, item);

    return 0;
}

static void
virSecurityDACChownListFree(void *opaque)
{
    virSecurityDACChownList *list = opaque;
    size_t i;

    if (!list)
        return;

    for (i = 0; i < list->nItems; i++)
        virSecurityDACChownItemFree(list->items[i]);
    g_free(list->items);
    virObjectUnref(list->manager);
    g_free(list);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virSecurityDACChownList, virSecurityDACChownListFree);


/**
 * virSecurityDACTransactionAppend:
 * @path: Path to chown
 * @src: disk source to chown
 * @uid: user ID
 * @gid: group ID
 * @remember: if the original owner should be recorded/recalled
 * @restore: if current operation is set or restore
 *
 * Appends an entry onto transaction list.
 * The @remember should be true if caller wishes to record/recall
 * the original owner of @path/@src.
 * The @restore should be true if the operation is restoring
 * seclabel and false otherwise.
 *
 * Returns: 1 in case of successful append
 *          0 if there is no transaction enabled
 *         -1 otherwise.
 */
static int
virSecurityDACTransactionAppend(const char *path,
                                const virStorageSource *src,
                                uid_t uid,
                                gid_t gid,
                                bool remember,
                                bool restore)
{
    virSecurityDACChownList *list = virThreadLocalGet(&chownList);
    if (!list)
        return 0;

    if (virSecurityDACChownListAppend(list, path, src,
                                      uid, gid, remember, restore) < 0)
        return -1;

    return 1;
}


static int virSecurityDACSetOwnership(virSecurityManager *mgr,
                                      const virStorageSource *src,
                                      const char *path,
                                      uid_t uid,
                                      gid_t gid,
                                      bool remember);

static int virSecurityDACRestoreFileLabelInternal(virSecurityManager *mgr,
                                                  const virStorageSource *src,
                                                  const char *path,
                                                  bool recall);
/**
 * virSecurityDACTransactionRun:
 * @pid: process pid
 * @opaque: opaque data
 *
 * This is the callback that runs in the same namespace as the domain we are
 * relabelling. For given transaction (@opaque) it relabels all the paths on
 * the list. Depending on security manager configuration it might lock paths
 * we will relabel.
 *
 * Returns: 0 on success
 *         -1 otherwise.
 */
static int
virSecurityDACTransactionRun(pid_t pid G_GNUC_UNUSED,
                             void *opaque)
{
    virSecurityDACChownList *list = opaque;
    virSecurityManagerMetadataLockState *state;
    g_autofree const char **paths = NULL;
    size_t npaths = 0;
    size_t i;
    int rv = 0;

    if (list->lock) {
        paths = g_new0(const char *, list->nItems);

        for (i = 0; i < list->nItems; i++) {
            virSecurityDACChownItem *item = list->items[i];
            const char *p = item->path;

            if (item->remember)
                VIR_APPEND_ELEMENT_COPY_INPLACE(paths, npaths, p);
        }

        if (!(state = virSecurityManagerMetadataLock(list->manager, paths, npaths)))
            return -1;

        for (i = 0; i < list->nItems; i++) {
            virSecurityDACChownItem *item = list->items[i];
            size_t j;

            for (j = 0; j < state->nfds; j++) {
                if (STREQ_NULLABLE(item->path, state->paths[j]))
                    break;
            }

            /* If path wasn't locked, don't try to remember its label. */
            if (j == state->nfds)
                item->remember = false;
        }
    }

    for (i = 0; i < list->nItems; i++) {
        virSecurityDACChownItem *item = list->items[i];
        const bool remember = item->remember && list->lock;

        if (!item->restore) {
            rv = virSecurityDACSetOwnership(list->manager,
                                            item->src,
                                            item->path,
                                            item->uid,
                                            item->gid,
                                            remember);
        } else {
            rv = virSecurityDACRestoreFileLabelInternal(list->manager,
                                                        item->src,
                                                        item->path,
                                                        remember);
        }

        if (rv < 0)
            break;
    }

    for (; rv < 0 && i > 0; i--) {
        virSecurityDACChownItem *item = list->items[i - 1];
        const bool remember = item->remember && list->lock;

        if (!item->restore) {
            virSecurityDACRestoreFileLabelInternal(list->manager,
                                                   item->src,
                                                   item->path,
                                                   remember);
        } else {
            VIR_WARN("Ignoring failed restore attempt on %s",
                     NULLSTR(item->src ? item->src->path : item->path));
        }
    }

    if (list->lock)
        virSecurityManagerMetadataUnlock(list->manager, &state);

    if (rv < 0)
        return -1;

    return 0;
}


/* returns -1 on error, 0 on success */
int
virSecurityDACSetUserAndGroup(virSecurityManager *mgr,
                              uid_t user,
                              gid_t group)
{
    virSecurityDACData *priv = virSecurityManagerGetPrivateData(mgr);
    priv->user = user;
    priv->group = group;

    priv->baselabel = g_strdup_printf("+%u:+%u", (unsigned int)user,
                                      (unsigned int)group);

    return 0;
}

void
virSecurityDACSetDynamicOwnership(virSecurityManager *mgr,
                                  bool dynamicOwnership)
{
    virSecurityDACData *priv = virSecurityManagerGetPrivateData(mgr);
    priv->dynamicOwnership = dynamicOwnership;
}

void
virSecurityDACSetMountNamespace(virSecurityManager *mgr,
                                bool mountNamespace)
{
    virSecurityDACData *priv = virSecurityManagerGetPrivateData(mgr);
    priv->mountNamespace = mountNamespace;
}


void
virSecurityDACSetChownCallback(virSecurityManager *mgr,
                               virSecurityManagerDACChownCallback chownCallback)
{
    virSecurityDACData *priv = virSecurityManagerGetPrivateData(mgr);
    priv->chownCallback = chownCallback;
}

/* returns 1 if label isn't found, 0 on success, -1 on error */
static int
ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
virSecurityDACParseIds(virSecurityLabelDef *seclabel,
                       uid_t *uidPtr, gid_t *gidPtr)
{
    if (!seclabel || !seclabel->label)
        return 1;

    if (virParseOwnershipIds(seclabel->label, uidPtr, gidPtr) < 0)
        return -1;

    return 0;
}

static int
ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4)
virSecurityDACGetIds(virSecurityLabelDef *seclabel,
                     virSecurityDACData *priv,
                     uid_t *uidPtr, gid_t *gidPtr,
                     gid_t **groups, int *ngroups)
{
    int ret;

    if (groups)
        *groups = priv ? priv->groups : NULL;
    if (ngroups)
        *ngroups = priv ? priv->ngroups : 0;

    if ((ret = virSecurityDACParseIds(seclabel, uidPtr, gidPtr)) <= 0)
        return ret;

    if (!priv) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("DAC seclabel couldn't be determined"));
        return -1;
    }

    *uidPtr = priv->user;
    *gidPtr = priv->group;

    return 0;
}


/* returns 1 if label isn't found, 0 on success, -1 on error */
static int
ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
virSecurityDACParseImageIds(virSecurityLabelDef *seclabel,
                            uid_t *uidPtr, gid_t *gidPtr)
{
    if (!seclabel || !seclabel->imagelabel)
        return 1;

    if (virParseOwnershipIds(seclabel->imagelabel, uidPtr, gidPtr) < 0)
        return -1;

    return 0;
}

static int
ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4)
virSecurityDACGetImageIds(virSecurityLabelDef *seclabel,
                          virSecurityDACData *priv,
                          uid_t *uidPtr, gid_t *gidPtr)
{
    int ret;

    if ((ret = virSecurityDACParseImageIds(seclabel, uidPtr, gidPtr)) <= 0)
        return ret;

    if (!priv) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("DAC imagelabel couldn't be determined"));
        return -1;
    }

    *uidPtr = priv->user;
    *gidPtr = priv->group;

    return 0;
}

/**
 * virSecurityDACRememberLabel:
 * @priv: driver's private data
 * @path: path to the file
 * @uid: user owning the @path
 * @gid: group owning the @path
 *
 * Remember the owner of @path (represented by @uid:@gid).
 *
 * Returns: the @path refcount, or
 *          -1 on failure
 */
static int
virSecurityDACRememberLabel(virSecurityDACData *priv G_GNUC_UNUSED,
                            const char *path,
                            uid_t uid,
                            gid_t gid)
{
    g_autofree char *label = NULL;

    label = g_strdup_printf("+%u:+%u", (unsigned int)uid, (unsigned int)gid);

    return virSecuritySetRememberedLabel(SECURITY_DAC_NAME, path, label);
}

/**
 * virSecurityDACRecallLabel:
 * @priv: driver's private data
 * @path: path to the file
 * @uid: user owning the @path
 * @gid: group owning the @path
 *
 * Recall the previously recorded owner for the @path. However, it may happen
 * that @path is still in use (e.g. by another domain). In that case, 1 is
 * returned and caller should not relabel the @path.
 *
 * Returns: 1 if @path is still in use (@uid and @gid not touched)
 *          0 if @path should be restored (@uid and @gid set)
 *         -1 on failure (@uid and @gid not touched)
 */
static int
virSecurityDACRecallLabel(virSecurityDACData *priv G_GNUC_UNUSED,
                          const char *path,
                          uid_t *uid,
                          gid_t *gid)
{
    g_autofree char *label = NULL;
    int rv;

    rv = virSecurityGetRememberedLabel(SECURITY_DAC_NAME, path, &label);
    if (rv < 0)
        return rv;

    if (!label)
        return 1;

    if (virParseOwnershipIds(label, uid, gid) < 0)
        return -1;

    return 0;
}

static virSecurityDriverStatus
virSecurityDACProbe(const char *virtDriver G_GNUC_UNUSED)
{
    return SECURITY_DRIVER_ENABLE;
}

static int
virSecurityDACOpen(virSecurityManager *mgr G_GNUC_UNUSED)
{
    if (virThreadLocalInit(&chownList,
                           virSecurityDACChownListFree) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to initialize thread local variable"));
        return -1;
    }

    return 0;
}

static int
virSecurityDACClose(virSecurityManager *mgr)
{
    virSecurityDACData *priv = virSecurityManagerGetPrivateData(mgr);
    g_clear_pointer(&priv->groups, g_free);
    g_clear_pointer(&priv->baselabel, g_free);
    return 0;
}


static const char *
virSecurityDACGetModel(virSecurityManager *mgr G_GNUC_UNUSED)
{
    return SECURITY_DAC_NAME;
}

static const char *
virSecurityDACGetDOI(virSecurityManager *mgr G_GNUC_UNUSED)
{
    return "0";
}

static int
virSecurityDACPreFork(virSecurityManager *mgr)
{
    virSecurityDACData *priv = virSecurityManagerGetPrivateData(mgr);
    int ngroups;

    g_clear_pointer(&priv->groups, g_free);
    priv->ngroups = 0;
    if ((ngroups = virGetGroupList(priv->user, priv->group,
                                   &priv->groups)) < 0)
        return -1;
    priv->ngroups = ngroups;
    return 0;
}

/**
 * virSecurityDACTransactionStart:
 * @mgr: security manager
 *
 * Starts a new transaction. In transaction nothing is chown()-ed until
 * TransactionCommit() is called. This is implemented as a list that is
 * appended to whenever chown() would be called. Since secdriver APIs
 * can be called from multiple threads (to work over different domains)
 * the pointer to the list is stored in thread local variable.
 *
 * Returns 0 on success,
 *        -1 otherwise.
 */
static int
virSecurityDACTransactionStart(virSecurityManager *mgr)
{
    g_autoptr(virSecurityDACChownList) list = NULL;

    if (virThreadLocalGet(&chownList)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Another relabel transaction is already started"));
        return -1;
    }

    list = g_new0(virSecurityDACChownList, 1);

    list->manager = virObjectRef(mgr);

    if (virThreadLocalSet(&chownList, list) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to set thread local variable"));
        return -1;
    }
    list = NULL;

    return 0;
}

/**
 * virSecurityDACTransactionCommit:
 * @mgr: security manager
 * @pid: domain's PID
 * @lock: lock and unlock paths that are relabeled
 *
 * If @pid is not -1 then enter the @pid namespace (usually @pid refers
 * to a domain) and perform all the chown()-s on the list. If @pid is -1
 * then the transaction is performed in the namespace of the caller.
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
static int
virSecurityDACTransactionCommit(virSecurityManager *mgr G_GNUC_UNUSED,
                                pid_t pid,
                                bool lock)
{
    g_autoptr(virSecurityDACChownList) list = NULL;
    int rc;

    list = virThreadLocalGet(&chownList);
    if (!list) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("No transaction is set"));
        return -1;
    }

    if (virThreadLocalSet(&chownList, NULL) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to clear thread local variable"));
        return -1;
    }

    list->lock = lock;

    if (pid != -1) {
        rc = virProcessRunInMountNamespace(pid,
                                           virSecurityDACTransactionRun,
                                           list);
        if (rc < 0) {
            if (virGetLastErrorCode() == VIR_ERR_SYSTEM_ERROR)
                pid = -1;
            else
                return -1;
        }
    }

    if (pid == -1) {
        if (lock)
            rc = virProcessRunInFork(virSecurityDACTransactionRun, list);
        else
            rc = virSecurityDACTransactionRun(pid, list);
    }

    if (rc < 0)
        return -1;

    return 0;
}

/**
 * virSecurityDACTransactionAbort:
 * @mgr: security manager
 *
 * Cancels and frees any out standing transaction.
 */
static void
virSecurityDACTransactionAbort(virSecurityManager *mgr G_GNUC_UNUSED)
{
    g_autoptr(virSecurityDACChownList) list = NULL;

    list = virThreadLocalGet(&chownList);
    if (!list)
        return;

    if (virThreadLocalSet(&chownList, NULL) < 0)
        VIR_DEBUG("Unable to clear thread local variable");
}


static int
virSecurityDACSetOwnershipInternal(const virSecurityDACData *priv,
                                   const virStorageSource *src,
                                   const char *path,
                                   uid_t uid,
                                   gid_t gid)
{
    int rc = 0;

    /* Be aware that this function might run in a separate process.
     * Therefore, any driver state changes would be thrown away. */

    if (src && priv->chownCallback) {
        rc = priv->chownCallback(src, uid, gid);

        /* on -2 returned an error was already reported */
        if (rc == -2)
            return -1;
    }

    if (rc == 0 || rc == -3) {
        struct stat sb;

        if (!path)
            return 0;

        if (stat(path, &sb) < 0) {
            virReportSystemError(errno, _("unable to stat: %1$s"), path);
            return -1;
        }

        if (sb.st_uid == uid && sb.st_gid == gid) {
            /* nothing to chown */
            return 0;
        }

#ifdef WIN32
        rc = -1;
        errno = ENOSYS;
#else /* !WIN32 */
        rc = chown(path, uid, gid);
#endif /* !WIN32 */
    }

    if (rc < 0) {
        if (errno == EOPNOTSUPP || errno == EINVAL) {
            VIR_INFO("Setting user and group to '%ld:%ld' on '%s' not "
                     "supported by filesystem",
                     (long)uid, (long)gid, NULLSTR(path));
        } else if (errno == EPERM) {
            VIR_INFO("Setting user and group to '%ld:%ld' on '%s' not "
                     "permitted",
                     (long)uid, (long)gid, NULLSTR(path));
        } else if (errno == EROFS) {
            VIR_INFO("Setting user and group to '%ld:%ld' on '%s' not "
                     "possible on readonly filesystem",
                     (long)uid, (long)gid, NULLSTR(path));
        } else {
            virReportSystemError(errno,
                                 _("unable to set user and group to '%1$ld:%2$ld' on '%3$s'"),
                                 (long)uid, (long)gid, NULLSTR(path));
            return -1;
        }
    }
    return 0;
}


static int
virSecurityDACSetOwnership(virSecurityManager *mgr,
                           const virStorageSource *src,
                           const char *path,
                           uid_t uid,
                           gid_t gid,
                           bool remember)
{
    virSecurityDACData *priv = virSecurityManagerGetPrivateData(mgr);
    virErrorPtr origerr;
    struct stat sb;
    int refcount;
    int rc;

    if (!path && src && src->path &&
        virStorageSourceIsLocalStorage(src))
        path = src->path;

    /* Be aware that this function might run in a separate process.
     * Therefore, any driver state changes would be thrown away. */

    if ((rc = virSecurityDACTransactionAppend(path, src,
                                              uid, gid, remember, false)) < 0)
        return -1;
    else if (rc > 0)
        return 0;

    if (remember && path) {
        if (stat(path, &sb) < 0) {
            virReportSystemError(errno, _("unable to stat: %1$s"), path);
            return -1;
        }

        refcount = virSecurityDACRememberLabel(priv, path, sb.st_uid, sb.st_gid);
        if (refcount == -2) {
            /* Not supported. Don't error though. */
        } else if (refcount < 0) {
            return -1;
        } else if (refcount > 1) {
            /* Refcount is greater than 1 which means that there
             * is @refcount domains using the @path. Do not
             * change the label (as it would almost certainly
             * cause the other domains to lose access to the
             * @path). However, the refcounter was incremented in
             * XATTRs so decrease it. */
            if (sb.st_uid != uid || sb.st_gid != gid) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("Setting different DAC user or group on %1$s which is already in use"),
                               path);
                goto error;
            }
        }
    }

    VIR_INFO("Setting DAC user and group on '%s' to '%ld:%ld'",
             NULLSTR(src ? src->path : path), (long)uid, (long)gid);

    if (virSecurityDACSetOwnershipInternal(priv, src, path, uid, gid) < 0)
        goto error;

    return 0;

 error:
    virErrorPreserveLast(&origerr);
    /* Try to restore the label. This is done so that XATTRs
     * are left in the same state as when the control entered
     * this function. However, if our attempt fails, there's
     * not much we can do. XATTRs refcounting is fubar'ed and
     * the only option we have is warn users. */
    if (virSecurityDACRestoreFileLabelInternal(mgr, src, path, remember) < 0)
        VIR_WARN("Unable to restore label on '%s'. "
                 "XATTRs might have been left in inconsistent state.",
                 NULLSTR(src ? src->path : path));

    virErrorRestore(&origerr);

    return -1;
}


static int
virSecurityDACRestoreFileLabelInternal(virSecurityManager *mgr,
                                       const virStorageSource *src,
                                       const char *path,
                                       bool recall)
{
    virSecurityDACData *priv = virSecurityManagerGetPrivateData(mgr);
    int rv;
    uid_t uid = 0;  /* By default return to root:root */
    gid_t gid = 0;

    if (!path && src && src->path &&
        virStorageSourceIsLocalStorage(src))
        path = src->path;

    /* Be aware that this function might run in a separate process.
     * Therefore, any driver state changes would be thrown away. */

    if ((rv = virSecurityDACTransactionAppend(path, src, uid, gid, recall, true)) < 0)
        return -1;
    else if (rv > 0)
        return 0;

    if (recall && path) {
        rv = virSecurityDACRecallLabel(priv, path, &uid, &gid);
        if (rv == -2) {
            /* Not supported. Don't error though. */
        } else if (rv < 0) {
            return -1;
        } else if (rv > 0) {
            return 0;
        }
    }

    VIR_INFO("Restoring DAC user and group on '%s' to %ld:%ld",
             NULLSTR(src ? src->path : path), (long)uid, (long)gid);

    return virSecurityDACSetOwnershipInternal(priv, src, path, uid, gid);
}


static int
virSecurityDACRestoreFileLabel(virSecurityManager *mgr,
                               const char *path)
{
    return virSecurityDACRestoreFileLabelInternal(mgr, NULL, path, true);
}


static int
virSecurityDACSetImageLabelInternal(virSecurityManager *mgr,
                                    virDomainDef *def,
                                    virStorageSource *src,
                                    virStorageSource *parent,
                                    bool isChainTop)
{
    virSecurityLabelDef *secdef;
    virSecurityDeviceLabelDef *disk_seclabel;
    virSecurityDeviceLabelDef *parent_seclabel = NULL;
    virSecurityDACData *priv = virSecurityManagerGetPrivateData(mgr);
    bool remember;
    uid_t user;
    gid_t group;

    if (!priv->dynamicOwnership)
        return 0;

    /* Images passed via FD don't need DAC seclabel change */
    if (virStorageSourceIsFD(src))
        return 0;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_DAC_NAME);
    if (secdef && !secdef->relabel)
        return 0;

    disk_seclabel = virStorageSourceGetSecurityLabelDef(src, SECURITY_DAC_NAME);
    parent_seclabel = virStorageSourceGetSecurityLabelDef(parent,
                                                          SECURITY_DAC_NAME);

    if (disk_seclabel && (!disk_seclabel->relabel || disk_seclabel->label)) {
        if (!disk_seclabel->relabel)
            return 0;

        if (virParseOwnershipIds(disk_seclabel->label, &user, &group) < 0)
            return -1;
    } else if (parent_seclabel &&
               (!parent_seclabel->relabel || parent_seclabel->label)) {
        if (!parent_seclabel->relabel)
            return 0;

        if (virParseOwnershipIds(parent_seclabel->label, &user, &group) < 0)
            return -1;
    } else {
        if (virSecurityDACGetImageIds(secdef, priv, &user, &group))
            return -1;
    }

    /* This is not very clean. But so far we don't have NVMe
     * storage pool backend so that its chownCallback would be
     * called. And this place looks least offensive. */
    if (src->type == VIR_STORAGE_TYPE_NVME) {
        const virStorageSourceNVMeDef *nvme = src->nvme;
        g_autofree char *vfioGroupDev = NULL;

        if (!(vfioGroupDev = virPCIDeviceAddressGetIOMMUGroupDev(&nvme->pciAddr)))
            return -1;

        return virSecurityDACSetOwnership(mgr, NULL, vfioGroupDev, user, group, false);
    }

    /* We can't do restore on shared resources safely. Not even
     * with refcounting implemented in XATTRs because if there
     * was a domain running with the feature turned off the
     * refcounter in XATTRs would not reflect the actual number
     * of times the resource is in use and thus the last restore
     * on the resource (which actually restores the original
     * owner) might cut off access to the domain with the feature
     * disabled.
     * For disks, a shared resource is the whole backing chain
     * but the top layer, or read only image, or disk explicitly
     * marked as shared.
     */
    remember = isChainTop && !src->readonly && !src->shared;

    return virSecurityDACSetOwnership(mgr, src, NULL, user, group, remember);
}


static int
virSecurityDACSetImageLabelRelative(virSecurityManager *mgr,
                                    virDomainDef *def,
                                    virStorageSource *src,
                                    virStorageSource *parent,
                                    virSecurityDomainImageLabelFlags flags)
{
    virStorageSource *n;

    for (n = src; virStorageSourceIsBacking(n); n = n->backingStore) {
        const bool isChainTop = flags & VIR_SECURITY_DOMAIN_IMAGE_PARENT_CHAIN_TOP;

        if (virSecurityDACSetImageLabelInternal(mgr, def, n, parent, isChainTop) < 0)
            return -1;

        if (!(flags & VIR_SECURITY_DOMAIN_IMAGE_LABEL_BACKING_CHAIN))
            break;

        flags &= ~VIR_SECURITY_DOMAIN_IMAGE_PARENT_CHAIN_TOP;
    }

    return 0;
}

static int
virSecurityDACSetImageLabel(virSecurityManager *mgr,
                            virDomainDef *def,
                            virStorageSource *src,
                            virSecurityDomainImageLabelFlags flags)
{
    return virSecurityDACSetImageLabelRelative(mgr, def, src, src, flags);
}

static int
virSecurityDACRestoreImageLabelSingle(virSecurityManager *mgr,
                                      virDomainDef *def,
                                      virStorageSource *src,
                                      bool migrated)
{
    virSecurityDACData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityLabelDef *secdef;
    virSecurityDeviceLabelDef *disk_seclabel;

    if (!priv->dynamicOwnership)
        return 0;

    /* Don't restore labels on readoly/shared disks, because other VMs may
     * still be accessing these. Alternatively we could iterate over all
     * running domains and try to figure out if it is in use, but this would
     * not work for clustered filesystems, since we can't see running VMs using
     * the file on other nodes. Safest bet is thus to skip the restore step. */
    if (src->readonly || src->shared)
        return 0;

    /* Images passed via FD don't need DAC seclabel change */
    if (virStorageSourceIsFD(src))
        return 0;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_DAC_NAME);
    if (secdef && !secdef->relabel)
        return 0;

    disk_seclabel = virStorageSourceGetSecurityLabelDef(src,
                                                        SECURITY_DAC_NAME);
    if (disk_seclabel && !disk_seclabel->relabel)
        return 0;

    /* If we have a shared FS and are doing migration, we must not change
     * ownership, because that kills access on the destination host which is
     * sub-optimal for the guest VM's I/O attempts :-) */
    if (migrated) {
        int rc = 1;

        if (virStorageSourceIsLocalStorage(src)) {
            if (!src->path)
                return 0;

            if ((rc = virFileIsSharedFS(src->path)) < 0)
                return -1;
        }

        if (rc == 1) {
            VIR_DEBUG("Skipping image label restore on %s because FS is shared",
                      src->path);
            return 0;
        }
    }

    /* This is not very clean. But so far we don't have NVMe
     * storage pool backend so that its chownCallback would be
     * called. And this place looks least offensive. */
    if (src->type == VIR_STORAGE_TYPE_NVME) {
        const virStorageSourceNVMeDef *nvme = src->nvme;
        g_autofree char *vfioGroupDev = NULL;

        if (!(vfioGroupDev = virPCIDeviceAddressGetIOMMUGroupDev(&nvme->pciAddr)))
            return -1;

        /* Ideally, we would check if there is not another PCI
         * device within domain def that is in the same IOMMU
         * group. But we're not doing that for hostdevs yet. */

        return virSecurityDACRestoreFileLabelInternal(mgr, NULL, vfioGroupDev, false);
    }

    return virSecurityDACRestoreFileLabelInternal(mgr, src, NULL, true);
}


static int
virSecurityDACRestoreImageLabelInt(virSecurityManager *mgr,
                                   virDomainDef *def,
                                   virStorageSource *src,
                                   bool migrated)
{
    if (virSecurityDACRestoreImageLabelSingle(mgr, def, src, migrated) < 0)
        return -1;

    return 0;
}


static int
virSecurityDACRestoreImageLabel(virSecurityManager *mgr,
                                virDomainDef *def,
                                virStorageSource *src,
                                virSecurityDomainImageLabelFlags flags G_GNUC_UNUSED)
{
    return virSecurityDACRestoreImageLabelInt(mgr, def, src, false);
}


struct virSecurityDACMoveImageMetadataData {
    virSecurityManager *mgr;
    const char *src;
    const char *dst;
};


static int
virSecurityDACMoveImageMetadataHelper(pid_t pid G_GNUC_UNUSED,
                                      void *opaque)
{
    struct virSecurityDACMoveImageMetadataData *data = opaque;
    const char *paths[2] = { data->src, data->dst };
    virSecurityManagerMetadataLockState *state;
    int ret;

    if (!(state = virSecurityManagerMetadataLock(data->mgr, paths, G_N_ELEMENTS(paths))))
        return -1;

    ret = virSecurityMoveRememberedLabel(SECURITY_DAC_NAME, data->src, data->dst);
    virSecurityManagerMetadataUnlock(data->mgr, &state);

    if (ret == -2) {
        /* Libvirt built without XATTRS */
        ret = 0;
    }

    return ret;
}


static int
virSecurityDACMoveImageMetadata(virSecurityManager *mgr,
                                pid_t pid,
                                virStorageSource *src,
                                virStorageSource *dst)
{
    virSecurityDACData *priv = virSecurityManagerGetPrivateData(mgr);
    struct virSecurityDACMoveImageMetadataData data = { .mgr = mgr, 0 };
    int rc;

    /* If dynamicOwnership is turned off, or owner remembering is
     * not enabled there's nothing for us to do. */
    if (!priv->dynamicOwnership)
        return 0;

    if (src &&
        virStorageSourceIsLocalStorage(src) &&
        !virStorageSourceIsFD(src))
        data.src = src->path;

    if (dst &&
        virStorageSourceIsLocalStorage(dst) &&
        !virStorageSourceIsFD(dst))
        data.dst = dst->path;

    if (!data.src)
        return 0;

    if (pid == -1) {
        rc = virProcessRunInFork(virSecurityDACMoveImageMetadataHelper, &data);
    } else {
        rc = virProcessRunInMountNamespace(pid,
                                           virSecurityDACMoveImageMetadataHelper,
                                           &data);
    }

    return rc;
}


static int
virSecurityDACSetHostdevLabelHelper(const char *file,
                                    bool remember,
                                    void *opaque)
{
    virSecurityDACCallbackData *cbdata = opaque;
    virSecurityManager *mgr = cbdata->manager;
    virSecurityLabelDef *secdef = cbdata->secdef;
    virSecurityDACData *priv = virSecurityManagerGetPrivateData(mgr);
    uid_t user;
    gid_t group;

    if (virSecurityDACGetIds(secdef, priv, &user, &group, NULL, NULL) < 0)
        return -1;

    return virSecurityDACSetOwnership(mgr, NULL, file, user, group, remember);
}


static int
virSecurityDACSetPCILabel(virPCIDevice *dev G_GNUC_UNUSED,
                          const char *file,
                          void *opaque)
{
    return virSecurityDACSetHostdevLabelHelper(file, true, opaque);
}


static int
virSecurityDACSetUSBLabel(virUSBDevice *dev G_GNUC_UNUSED,
                          const char *file,
                          void *opaque)
{
    return virSecurityDACSetHostdevLabelHelper(file, true, opaque);
}


static int
virSecurityDACSetSCSILabel(virSCSIDevice *dev G_GNUC_UNUSED,
                           const char *file,
                           void *opaque)
{
    return virSecurityDACSetHostdevLabelHelper(file, true, opaque);
}


static int
virSecurityDACSetHostLabel(virSCSIVHostDevice *dev G_GNUC_UNUSED,
                           const char *file,
                           void *opaque)
{
    return virSecurityDACSetHostdevLabelHelper(file, true, opaque);
}


static int
virSecurityDACSetHostdevLabel(virSecurityManager *mgr,
                              virDomainDef *def,
                              virDomainHostdevDef *dev,
                              const char *vroot)
{
    virSecurityDACData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityDACCallbackData cbdata;
    virDomainHostdevSubsysUSB *usbsrc = &dev->source.subsys.u.usb;
    virDomainHostdevSubsysPCI *pcisrc = &dev->source.subsys.u.pci;
    virDomainHostdevSubsysSCSI *scsisrc = &dev->source.subsys.u.scsi;
    virDomainHostdevSubsysSCSIVHost *hostsrc = &dev->source.subsys.u.scsi_host;
    virDomainHostdevSubsysMediatedDev *mdevsrc = &dev->source.subsys.u.mdev;
    int ret = -1;

    if (!priv->dynamicOwnership)
        return 0;

    if (dev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
        return 0;

    /* Like virSecurityDACSetImageLabel() for a networked disk,
     * do nothing for an iSCSI hostdev
     */
    if (dev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI &&
        scsisrc->protocol == VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI)
        return 0;

    cbdata.manager = mgr;
    cbdata.secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_DAC_NAME);

    if (cbdata.secdef && !cbdata.secdef->relabel)
        return 0;

    switch (dev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB: {
        g_autoptr(virUSBDevice) usb = NULL;

        if (dev->missing)
            return 0;

        if (!(usb = virUSBDeviceNew(usbsrc->bus, usbsrc->device, vroot)))
            return -1;

        ret = virUSBDeviceFileIterate(usb,
                                      virSecurityDACSetUSBLabel,
                                      &cbdata);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI: {
        g_autoptr(virPCIDevice) pci = NULL;

        if (!virPCIDeviceExists(&pcisrc->addr))
            break;

        pci = virPCIDeviceNew(&pcisrc->addr);

        if (!pci)
            return -1;

        if (pcisrc->backend == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO) {
            g_autofree char *vfioGroupDev = virPCIDeviceGetIOMMUGroupDev(pci);

            if (!vfioGroupDev)
                return -1;

            ret = virSecurityDACSetHostdevLabelHelper(vfioGroupDev,
                                                      false,
                                                      &cbdata);
        } else {
            ret = virPCIDeviceFileIterate(pci,
                                          virSecurityDACSetPCILabel,
                                          &cbdata);
        }
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI: {
        virDomainHostdevSubsysSCSIHost *scsihostsrc = &scsisrc->u.host;
        g_autoptr(virSCSIDevice) scsi =
            virSCSIDeviceNew(NULL,
                             scsihostsrc->adapter, scsihostsrc->bus,
                             scsihostsrc->target, scsihostsrc->unit,
                             dev->readonly, dev->shareable);

        if (!scsi)
            return -1;

        ret = virSCSIDeviceFileIterate(scsi,
                                       virSecurityDACSetSCSILabel,
                                       &cbdata);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST: {
        g_autoptr(virSCSIVHostDevice) host = virSCSIVHostDeviceNew(hostsrc->wwpn);

        if (!host)
            return -1;

        ret = virSCSIVHostDeviceFileIterate(host,
                                            virSecurityDACSetHostLabel,
                                            &cbdata);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV: {
        g_autofree char *vfiodev = NULL;

        if (!(vfiodev = virMediatedDeviceGetIOMMUGroupDev(mdevsrc->uuidstr)))
            return -1;

        ret = virSecurityDACSetHostdevLabelHelper(vfiodev, false, &cbdata);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
        ret = 0;
        break;
    }

    return ret;
}


static int
virSecurityDACRestorePCILabel(virPCIDevice *dev G_GNUC_UNUSED,
                              const char *file,
                              void *opaque)
{
    virSecurityManager *mgr = opaque;
    return virSecurityDACRestoreFileLabel(mgr, file);
}


static int
virSecurityDACRestoreUSBLabel(virUSBDevice *dev G_GNUC_UNUSED,
                              const char *file,
                              void *opaque)
{
    virSecurityManager *mgr = opaque;
    return virSecurityDACRestoreFileLabel(mgr, file);
}


static int
virSecurityDACRestoreSCSILabel(virSCSIDevice *dev G_GNUC_UNUSED,
                               const char *file,
                               void *opaque)
{
    virSecurityManager *mgr = opaque;
    return virSecurityDACRestoreFileLabel(mgr, file);
}


static int
virSecurityDACRestoreHostLabel(virSCSIVHostDevice *dev G_GNUC_UNUSED,
                               const char *file,
                               void *opaque)
{
    virSecurityManager *mgr = opaque;
    return virSecurityDACRestoreFileLabel(mgr, file);
}


static int
virSecurityDACRestoreHostdevLabel(virSecurityManager *mgr,
                                  virDomainDef *def,
                                  virDomainHostdevDef *dev,
                                  const char *vroot)

{
    virSecurityDACData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityLabelDef *secdef;
    virDomainHostdevSubsysUSB *usbsrc = &dev->source.subsys.u.usb;
    virDomainHostdevSubsysPCI *pcisrc = &dev->source.subsys.u.pci;
    virDomainHostdevSubsysSCSI *scsisrc = &dev->source.subsys.u.scsi;
    virDomainHostdevSubsysSCSIVHost *hostsrc = &dev->source.subsys.u.scsi_host;
    virDomainHostdevSubsysMediatedDev *mdevsrc = &dev->source.subsys.u.mdev;
    int ret = -1;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_DAC_NAME);

    if (!priv->dynamicOwnership || (secdef && !secdef->relabel))
        return 0;

    if (dev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
        return 0;

    /* Like virSecurityDACRestoreImageLabelInt() for a networked disk,
     * do nothing for an iSCSI hostdev
     */
    if (dev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI &&
        scsisrc->protocol == VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI)
        return 0;

    switch (dev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB: {
        g_autoptr(virUSBDevice) usb = NULL;

        if (dev->missing)
            return 0;

        if (!(usb = virUSBDeviceNew(usbsrc->bus, usbsrc->device, vroot)))
            return -1;

        ret = virUSBDeviceFileIterate(usb, virSecurityDACRestoreUSBLabel, mgr);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI: {
        g_autoptr(virPCIDevice) pci = NULL;

        if (!virPCIDeviceExists(&pcisrc->addr))
            break;

        pci = virPCIDeviceNew(&pcisrc->addr);

        if (!pci)
            return -1;

        if (pcisrc->backend == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO) {
            g_autofree char *vfioGroupDev = virPCIDeviceGetIOMMUGroupDev(pci);

            if (!vfioGroupDev)
                return -1;

            ret = virSecurityDACRestoreFileLabelInternal(mgr, NULL,
                                                         vfioGroupDev, false);
        } else {
            ret = virPCIDeviceFileIterate(pci, virSecurityDACRestorePCILabel, mgr);
        }
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI: {
        virDomainHostdevSubsysSCSIHost *scsihostsrc = &scsisrc->u.host;
        g_autoptr(virSCSIDevice) scsi =
            virSCSIDeviceNew(NULL,
                             scsihostsrc->adapter, scsihostsrc->bus,
                             scsihostsrc->target, scsihostsrc->unit,
                             dev->readonly, dev->shareable);

        if (!scsi)
            return -1;

        ret = virSCSIDeviceFileIterate(scsi, virSecurityDACRestoreSCSILabel, mgr);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST: {
        g_autoptr(virSCSIVHostDevice) host = virSCSIVHostDeviceNew(hostsrc->wwpn);

        if (!host)
            return -1;

        ret = virSCSIVHostDeviceFileIterate(host,
                                            virSecurityDACRestoreHostLabel,
                                            mgr);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV: {
        g_autofree char *vfiodev = NULL;

        if (!(vfiodev = virMediatedDeviceGetIOMMUGroupDev(mdevsrc->uuidstr)))
            return -1;

        ret = virSecurityDACRestoreFileLabelInternal(mgr, NULL, vfiodev, false);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
        ret = 0;
        break;
    }

    return ret;
}


static int
virSecurityDACSetChardevLabelHelper(virSecurityManager *mgr,
                                    virDomainDef *def,
                                    virDomainChrSourceDef *dev_source,
                                    bool chardevStdioLogd,
                                    bool remember)

{
    virSecurityDACData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityLabelDef *seclabel;
    virSecurityDeviceLabelDef *chr_seclabel = NULL;
    g_autofree char *in = NULL;
    g_autofree char *out = NULL;
    uid_t user;
    gid_t group;

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_DAC_NAME);

    chr_seclabel = virDomainChrSourceDefGetSecurityLabelDef(dev_source,
                                                            SECURITY_DAC_NAME);

    if (chr_seclabel && !chr_seclabel->relabel)
        return 0;

    if (!chr_seclabel &&
        dev_source->type == VIR_DOMAIN_CHR_TYPE_FILE &&
        chardevStdioLogd)
        return 0;

    if (chr_seclabel && chr_seclabel->label) {
        if (virParseOwnershipIds(chr_seclabel->label, &user, &group) < 0)
            return -1;
    } else {
        if (virSecurityDACGetIds(seclabel, priv, &user, &group, NULL, NULL) < 0)
            return -1;
    }

    switch ((virDomainChrType)dev_source->type) {
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_FILE:
        if (virSecurityDACSetOwnership(mgr, NULL,
                                       dev_source->data.file.path,
                                       user, group, remember) < 0) {
            return -1;
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_PIPE:
        in = g_strdup_printf("%s.in", dev_source->data.file.path);
        out = g_strdup_printf("%s.out", dev_source->data.file.path);
        if (virFileExists(in) && virFileExists(out)) {
            if (virSecurityDACSetOwnership(mgr, NULL, in, user, group, remember) < 0 ||
                virSecurityDACSetOwnership(mgr, NULL, out, user, group, remember) < 0) {
                return -1;
            }
        } else if (virSecurityDACSetOwnership(mgr, NULL,
                                              dev_source->data.file.path,
                                              user, group, remember) < 0) {
            return -1;
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        if (!dev_source->data.nix.listen ||
            (dev_source->data.nix.path &&
             virFileExists(dev_source->data.nix.path))) {
            /* Also label mode='bind' sockets if they exist,
             * e.g. because they were created by libvirt
             * and passed via FD */
            if (virSecurityDACSetOwnership(mgr, NULL,
                                           dev_source->data.nix.path,
                                           user, group, remember) < 0) {
                return -1;
            }
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_SPICEPORT:
    case VIR_DOMAIN_CHR_TYPE_NULL:
    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_PTY:
    case VIR_DOMAIN_CHR_TYPE_STDIO:
    case VIR_DOMAIN_CHR_TYPE_UDP:
    case VIR_DOMAIN_CHR_TYPE_TCP:
    case VIR_DOMAIN_CHR_TYPE_SPICEVMC:
    case VIR_DOMAIN_CHR_TYPE_NMDM:
    case VIR_DOMAIN_CHR_TYPE_QEMU_VDAGENT:
    case VIR_DOMAIN_CHR_TYPE_DBUS:
    case VIR_DOMAIN_CHR_TYPE_LAST:
        break;
    }

    return 0;
}


static int
virSecurityDACSetChardevLabel(virSecurityManager *mgr,
                              virDomainDef *def,
                              virDomainChrSourceDef *dev_source,
                              bool chardevStdioLogd)
{
    return virSecurityDACSetChardevLabelHelper(mgr, def, dev_source,
                                               chardevStdioLogd, true);
}


static int
virSecurityDACRestoreChardevLabelHelper(virSecurityManager *mgr,
                                        virDomainDef *def G_GNUC_UNUSED,
                                        virDomainChrSourceDef *dev_source,
                                        bool chardevStdioLogd,
                                        bool recall)
{
    virSecurityDeviceLabelDef *chr_seclabel = NULL;
    g_autofree char *in = NULL;
    g_autofree char *out = NULL;

    chr_seclabel = virDomainChrSourceDefGetSecurityLabelDef(dev_source,
                                                            SECURITY_DAC_NAME);

    if (chr_seclabel && !chr_seclabel->relabel)
        return 0;

    if (!chr_seclabel &&
        dev_source->type == VIR_DOMAIN_CHR_TYPE_FILE &&
        chardevStdioLogd)
        return 0;

    switch ((virDomainChrType)dev_source->type) {
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_FILE:
        if (virSecurityDACRestoreFileLabelInternal(mgr, NULL,
                                                   dev_source->data.file.path,
                                                   recall) < 0) {
            return -1;
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_PIPE:
        out = g_strdup_printf("%s.out", dev_source->data.file.path);
        in = g_strdup_printf("%s.in", dev_source->data.file.path);
        if (virFileExists(in) && virFileExists(out)) {
            if (virSecurityDACRestoreFileLabelInternal(mgr, NULL, out, recall) < 0 ||
                virSecurityDACRestoreFileLabelInternal(mgr, NULL, in, recall) < 0) {
                return -1;
            }
        } else if (virSecurityDACRestoreFileLabelInternal(mgr, NULL,
                                                          dev_source->data.file.path,
                                                          recall) < 0) {
            return -1;
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        if (!dev_source->data.nix.listen &&
            virSecurityDACRestoreFileLabelInternal(mgr, NULL,
                                                   dev_source->data.nix.path,
                                                   recall) < 0) {
            return -1;
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_NULL:
    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_PTY:
    case VIR_DOMAIN_CHR_TYPE_STDIO:
    case VIR_DOMAIN_CHR_TYPE_UDP:
    case VIR_DOMAIN_CHR_TYPE_TCP:
    case VIR_DOMAIN_CHR_TYPE_SPICEVMC:
    case VIR_DOMAIN_CHR_TYPE_SPICEPORT:
    case VIR_DOMAIN_CHR_TYPE_NMDM:
    case VIR_DOMAIN_CHR_TYPE_QEMU_VDAGENT:
    case VIR_DOMAIN_CHR_TYPE_DBUS:
    case VIR_DOMAIN_CHR_TYPE_LAST:
        break;
    }

    return 0;
}


static int
virSecurityDACRestoreChardevLabel(virSecurityManager *mgr,
                                  virDomainDef *def,
                                  virDomainChrSourceDef *dev_source,
                                  bool chardevStdioLogd)
{
    return virSecurityDACRestoreChardevLabelHelper(mgr, def, dev_source,
                                                   chardevStdioLogd, true);
}


struct _virSecuritySELinuxChardevCallbackData {
    virSecurityManager *mgr;
    bool chardevStdioLogd;
};


static int
virSecurityDACRestoreChardevCallback(virDomainDef *def,
                                     virDomainChrDef *dev G_GNUC_UNUSED,
                                     void *opaque)
{
    struct _virSecuritySELinuxChardevCallbackData *data = opaque;

    return virSecurityDACRestoreChardevLabel(data->mgr, def, dev->source,
                                             data->chardevStdioLogd);
}


static int
virSecurityDACSetTPMFileLabel(virSecurityManager *mgr,
                              virDomainDef *def,
                              virDomainTPMDef *tpm)
{
    int ret = 0;

    switch (tpm->type) {
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
        ret = virSecurityDACSetChardevLabelHelper(mgr, def,
                                                  tpm->data.passthrough.source,
                                                  false, false);
        break;
    case VIR_DOMAIN_TPM_TYPE_EMULATOR:
        ret = virSecurityDACSetChardevLabelHelper(mgr, def,
                                                  tpm->data.emulator.source,
                                                  false, false);
        break;
    case VIR_DOMAIN_TPM_TYPE_EXTERNAL:
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }

    return ret;
}


static int
virSecurityDACRestoreTPMFileLabel(virSecurityManager *mgr,
                                  virDomainDef *def,
                                  virDomainTPMDef *tpm)
{
    int ret = 0;

    switch (tpm->type) {
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
        ret = virSecurityDACRestoreChardevLabelHelper(mgr, def,
                                                      tpm->data.passthrough.source,
                                                      false, false);
        break;
    case VIR_DOMAIN_TPM_TYPE_EMULATOR:
        /* swtpm will have removed the Unix socket upon termination */
    case VIR_DOMAIN_TPM_TYPE_EXTERNAL:
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }

    return ret;
}


static int
virSecurityDACSetGraphicsLabel(virSecurityManager *mgr,
                               virDomainDef *def,
                               virDomainGraphicsDef *gfx)

{
    const char *rendernode = virDomainGraphicsGetRenderNode(gfx);
    virSecurityDACData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityLabelDef *seclabel;
    uid_t user;
    gid_t group;

    /* There's nothing to relabel */
    if (!rendernode)
        return 0;

    /* Skip chowning the shared render file if namespaces are disabled */
    if (!priv->mountNamespace)
        return 0;

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_DAC_NAME);
    if (seclabel && !seclabel->relabel)
        return 0;

    if (virSecurityDACGetIds(seclabel, priv, &user, &group, NULL, NULL) < 0)
        return -1;

    if (virSecurityDACSetOwnership(mgr, NULL, rendernode, user, group, true) < 0)
        return -1;

    return 0;
}


static int
virSecurityDACRestoreGraphicsLabel(virSecurityManager *mgr G_GNUC_UNUSED,
                               virDomainDef *def G_GNUC_UNUSED,
                               virDomainGraphicsDef *gfx G_GNUC_UNUSED)

{
    /* The only graphics labelling we do is dependent on mountNamespaces,
       in which case 'restoring' the label doesn't actually accomplish
       anything, so there's nothing to do here */
    return 0;
}


static int
virSecurityDACSetInputLabel(virSecurityManager *mgr,
                            virDomainDef *def,
                            virDomainInputDef *input)

{
    virSecurityDACData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityLabelDef *seclabel;
    int ret = -1;
    uid_t user;
    gid_t group;

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_DAC_NAME);
    if (seclabel && !seclabel->relabel)
        return 0;

    switch ((virDomainInputType)input->type) {
    case VIR_DOMAIN_INPUT_TYPE_PASSTHROUGH:
    case VIR_DOMAIN_INPUT_TYPE_EVDEV:
        if (virSecurityDACGetIds(seclabel, priv, &user, &group, NULL, NULL) < 0)
            return -1;

        ret = virSecurityDACSetOwnership(mgr, NULL,
                                         input->source.evdev,
                                         user, group, true);
        break;

    case VIR_DOMAIN_INPUT_TYPE_MOUSE:
    case VIR_DOMAIN_INPUT_TYPE_TABLET:
    case VIR_DOMAIN_INPUT_TYPE_KBD:
    case VIR_DOMAIN_INPUT_TYPE_LAST:
        ret = 0;
        break;
    }

    return ret;
}

static int
virSecurityDACRestoreInputLabel(virSecurityManager *mgr,
                                virDomainDef *def G_GNUC_UNUSED,
                                virDomainInputDef *input)
{
    int ret = -1;

    switch ((virDomainInputType)input->type) {
    case VIR_DOMAIN_INPUT_TYPE_PASSTHROUGH:
    case VIR_DOMAIN_INPUT_TYPE_EVDEV:
        ret = virSecurityDACRestoreFileLabel(mgr, input->source.evdev);
        break;

    case VIR_DOMAIN_INPUT_TYPE_MOUSE:
    case VIR_DOMAIN_INPUT_TYPE_TABLET:
    case VIR_DOMAIN_INPUT_TYPE_KBD:
    case VIR_DOMAIN_INPUT_TYPE_LAST:
        ret = 0;
        break;
    }

    return ret;
}


static int
virSecurityDACRestoreMemoryLabel(virSecurityManager *mgr,
                                 virDomainDef *def G_GNUC_UNUSED,
                                 virDomainMemoryDef *mem)
{
    switch (mem->model) {
    case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
        return virSecurityDACRestoreFileLabel(mgr, mem->source.nvdimm.path);
    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM:
        return virSecurityDACRestoreFileLabel(mgr, mem->source.virtio_pmem.path);

    case VIR_DOMAIN_MEMORY_MODEL_SGX_EPC:
        /* We set label on SGX /dev nodes iff running with namespaces, so we
         * don't need to restore anything. */
        break;

    case VIR_DOMAIN_MEMORY_MODEL_DIMM:
    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM:
    case VIR_DOMAIN_MEMORY_MODEL_LAST:
    case VIR_DOMAIN_MEMORY_MODEL_NONE:
        break;
    }

    return 0;
}


static int
virSecurityDACRestoreSEVLabel(virSecurityManager *mgr G_GNUC_UNUSED,
                              virDomainDef *def G_GNUC_UNUSED)
{
    /* we only label /dev/sev when running with namespaces, so we don't need to
     * restore anything */
    return 0;
}


static int
virSecurityDACRestoreSysinfoLabel(virSecurityManager *mgr,
                                  virSysinfoDef *def)
{
    size_t i;

    for (i = 0; i < def->nfw_cfgs; i++) {
        virSysinfoFWCfgDef *f = &def->fw_cfgs[i];

        if (f->file &&
            virSecurityDACRestoreFileLabel(mgr, f->file) < 0)
            return -1;
    }

    return 0;
}


static int
virSecurityDACRestoreAllLabel(virSecurityManager *mgr,
                              virDomainDef *def,
                              bool migrated,
                              bool chardevStdioLogd)
{
    virSecurityDACData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityLabelDef *secdef;
    size_t i;
    int rc = 0;

    struct _virSecuritySELinuxChardevCallbackData chardevData = {
        .mgr = mgr,
        .chardevStdioLogd = chardevStdioLogd,
    };

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_DAC_NAME);

    if (!priv->dynamicOwnership || (secdef && !secdef->relabel))
        return 0;

    VIR_DEBUG("Restoring security label on %s migrated=%d",
              def->name, migrated);

    for (i = 0; i < def->ndisks; i++) {
        if (virSecurityDACRestoreImageLabelInt(mgr,
                                               def,
                                               def->disks[i]->src,
                                               migrated) < 0)
            rc = -1;
    }

    for (i = 0; i < def->ngraphics; i++) {
        if (virSecurityDACRestoreGraphicsLabel(mgr, def, def->graphics[i]) < 0)
            return -1;
    }

    for (i = 0; i < def->ninputs; i++) {
        if (virSecurityDACRestoreInputLabel(mgr, def, def->inputs[i]) < 0)
            rc = -1;
    }

    for (i = 0; i < def->nhostdevs; i++) {
        if (virSecurityDACRestoreHostdevLabel(mgr,
                                              def,
                                              def->hostdevs[i],
                                              NULL) < 0)
            rc = -1;
    }

    for (i = 0; i < def->nmems; i++) {
        if (virSecurityDACRestoreMemoryLabel(mgr,
                                             def,
                                             def->mems[i]) < 0)
            rc = -1;
    }

    if (virDomainChrDefForeach(def,
                               false,
                               virSecurityDACRestoreChardevCallback,
                               &chardevData) < 0)
        rc = -1;

    for (i = 0; i < def->ntpms; i++) {
        if (virSecurityDACRestoreTPMFileLabel(mgr,
                                              def,
                                              def->tpms[i]) < 0)
            rc = -1;
    }

    if (def->sec &&
        def->sec->sectype == VIR_DOMAIN_LAUNCH_SECURITY_SEV) {
        if (virSecurityDACRestoreSEVLabel(mgr, def) < 0)
            rc = -1;
    }

    for (i = 0; i < def->nsysinfo; i++) {
        if (virSecurityDACRestoreSysinfoLabel(mgr,
                                              def->sysinfo[i]) < 0)
            rc = -1;
    }

    if (def->os.loader && def->os.loader->nvram) {
        if (virSecurityDACRestoreImageLabelInt(mgr, def, def->os.loader->nvram,
                                               migrated) < 0)
            rc = -1;
    }

    if (def->os.kernel &&
        virSecurityDACRestoreFileLabel(mgr, def->os.kernel) < 0)
        rc = -1;

    if (def->os.initrd &&
        virSecurityDACRestoreFileLabel(mgr, def->os.initrd) < 0)
        rc = -1;

    if (def->os.dtb &&
        virSecurityDACRestoreFileLabel(mgr, def->os.dtb) < 0)
        rc = -1;

    if (def->os.slic_table &&
        virSecurityDACRestoreFileLabel(mgr, def->os.slic_table) < 0)
        rc = -1;

    return rc;
}


static int
virSecurityDACSetChardevCallback(virDomainDef *def,
                                 virDomainChrDef *dev G_GNUC_UNUSED,
                                 void *opaque)
{
    struct _virSecuritySELinuxChardevCallbackData *data = opaque;

    return virSecurityDACSetChardevLabel(data->mgr, def, dev->source,
                                         data->chardevStdioLogd);
}


static int
virSecurityDACSetMemoryLabel(virSecurityManager *mgr,
                             virDomainDef *def,
                             virDomainMemoryDef *mem)

{
    virSecurityDACData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityLabelDef *seclabel;
    uid_t user;
    gid_t group;

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_DAC_NAME);
    if (seclabel && !seclabel->relabel)
        return 0;

    if (virSecurityDACGetIds(seclabel, priv, &user, &group, NULL, NULL) < 0)
        return -1;

    switch (mem->model) {
    case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
        return virSecurityDACSetOwnership(mgr, NULL,
                                          mem->source.nvdimm.path,
                                          user, group, true);

    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM:
        return virSecurityDACSetOwnership(mgr, NULL,
                                          mem->source.virtio_pmem.path,
                                          user, group, true);

    case VIR_DOMAIN_MEMORY_MODEL_SGX_EPC:
        /* Skip chowning SGX if namespaces are disabled. */
        if (priv->mountNamespace &&
            (virSecurityDACSetOwnership(mgr, NULL,
                                        DEV_SGX_VEPC,
                                        user, group, true) < 0 ||
             virSecurityDACSetOwnership(mgr, NULL,
                                        DEV_SGX_PROVISION,
                                        user, group, true) < 0))
            return -1;
        break;

    case VIR_DOMAIN_MEMORY_MODEL_DIMM:
    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM:
    case VIR_DOMAIN_MEMORY_MODEL_LAST:
    case VIR_DOMAIN_MEMORY_MODEL_NONE:
        break;
    }

    return 0;
}


static int
virSecurityDACSetSEVLabel(virSecurityManager *mgr,
                          virDomainDef *def)
{
    virSecurityDACData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityLabelDef *seclabel;
    uid_t user;
    gid_t group;

    /* Skip chowning /dev/sev if namespaces are disabled as we'd significantly
     * increase the chance of a DOS attack on SEV
     */
    if (!priv->mountNamespace)
        return 0;

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_DAC_NAME);
    if (seclabel && !seclabel->relabel)
        return 0;

    if (virSecurityDACGetIds(seclabel, priv, &user, &group, NULL, NULL) < 0)
        return -1;

    if (virSecurityDACSetOwnership(mgr, NULL, DEV_SEV,
                                   user, group, true) < 0)
        return -1;

    return 0;
}


static int
virSecurityDACSetSysinfoLabel(virSecurityManager *mgr,
                              uid_t user,
                              gid_t group,
                              virSysinfoDef *def)
{
    size_t i;

    for (i = 0; i < def->nfw_cfgs; i++) {
        virSysinfoFWCfgDef *f = &def->fw_cfgs[i];

        if (f->file &&
            virSecurityDACSetOwnership(mgr, NULL, f->file,
                                       user, group, true) < 0)
            return -1;
    }

    return 0;
}


static int
virSecurityDACSetAllLabel(virSecurityManager *mgr,
                          virDomainDef *def,
                          const char *incomingPath G_GNUC_UNUSED,
                          bool chardevStdioLogd,
                          bool migrated G_GNUC_UNUSED)
{
    virSecurityDACData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityLabelDef *secdef;
    size_t i;
    uid_t user;
    gid_t group;

    struct _virSecuritySELinuxChardevCallbackData chardevData = {
        .mgr = mgr,
        .chardevStdioLogd = chardevStdioLogd,
    };

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_DAC_NAME);

    if (!priv->dynamicOwnership || (secdef && !secdef->relabel))
        return 0;

    for (i = 0; i < def->ndisks; i++) {
        /* XXX fixme - we need to recursively label the entire tree :-( */
        if (virDomainDiskGetType(def->disks[i]) == VIR_STORAGE_TYPE_DIR)
            continue;
        if (virSecurityDACSetImageLabel(mgr, def, def->disks[i]->src,
                                        VIR_SECURITY_DOMAIN_IMAGE_LABEL_BACKING_CHAIN |
                                        VIR_SECURITY_DOMAIN_IMAGE_PARENT_CHAIN_TOP) < 0)
            return -1;
    }

    for (i = 0; i < def->ngraphics; i++) {
        if (virSecurityDACSetGraphicsLabel(mgr, def, def->graphics[i]) < 0)
            return -1;
    }

    for (i = 0; i < def->ninputs; i++) {
        if (virSecurityDACSetInputLabel(mgr, def, def->inputs[i]) < 0)
            return -1;
    }

    for (i = 0; i < def->nhostdevs; i++) {
        if (virSecurityDACSetHostdevLabel(mgr,
                                          def,
                                          def->hostdevs[i],
                                          NULL) < 0)
            return -1;
    }

    for (i = 0; i < def->nmems; i++) {
        if (virSecurityDACSetMemoryLabel(mgr,
                                         def,
                                         def->mems[i]) < 0)
            return -1;
    }

    if (virDomainChrDefForeach(def,
                               true,
                               virSecurityDACSetChardevCallback,
                               &chardevData) < 0)
        return -1;

    for (i = 0; i < def->ntpms; i++) {
        if (virSecurityDACSetTPMFileLabel(mgr,
                                          def,
                                          def->tpms[i]) < 0)
            return -1;
    }

    if (def->sec &&
        def->sec->sectype == VIR_DOMAIN_LAUNCH_SECURITY_SEV) {
        if (virSecurityDACSetSEVLabel(mgr, def) < 0)
            return -1;
    }

    if (virSecurityDACGetImageIds(secdef, priv, &user, &group))
        return -1;

    for (i = 0; i < def->nsysinfo; i++) {
        if (virSecurityDACSetSysinfoLabel(mgr, user, group, def->sysinfo[i]) < 0)
            return -1;
    }

    if (def->os.loader && def->os.loader->nvram) {
        if (virSecurityDACSetImageLabel(mgr, def, def->os.loader->nvram,
                                        VIR_SECURITY_DOMAIN_IMAGE_LABEL_BACKING_CHAIN |
                                        VIR_SECURITY_DOMAIN_IMAGE_PARENT_CHAIN_TOP) < 0)
            return -1;
    }

    if (def->os.kernel &&
        virSecurityDACSetOwnership(mgr, NULL,
                                   def->os.kernel,
                                   user, group, true) < 0)
        return -1;

    if (def->os.initrd &&
        virSecurityDACSetOwnership(mgr, NULL,
                                   def->os.initrd,
                                   user, group, true) < 0)
        return -1;

    if (def->os.dtb &&
        virSecurityDACSetOwnership(mgr, NULL,
                                   def->os.dtb,
                                   user, group, true) < 0)
        return -1;

    if (def->os.slic_table &&
        virSecurityDACSetOwnership(mgr, NULL,
                                   def->os.slic_table,
                                   user, group, true) < 0)
        return -1;

    return 0;
}


static int
virSecurityDACSetProcessLabel(virSecurityManager *mgr,
                              virDomainDef *def)
{
    virSecurityDACData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityLabelDef *secdef;
    uid_t user;
    gid_t group;
    gid_t *groups;
    int ngroups;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_DAC_NAME);

    if (virSecurityDACGetIds(secdef, priv, &user, &group, &groups, &ngroups) < 0)
        return -1;

    VIR_DEBUG("Dropping privileges to %u:%u, %d supplemental groups",
              (unsigned int)user, (unsigned int)group, ngroups);

    if (virSetUIDGID(user, group, groups, ngroups) < 0)
        return -1;

    return 0;
}


static int
virSecurityDACSetChildProcessLabel(virSecurityManager *mgr,
                                   virDomainDef *def,
                                   bool useBinarySpecificLabel G_GNUC_UNUSED,
                                   virCommand *cmd)
{
    virSecurityDACData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityLabelDef *secdef;
    uid_t user;
    gid_t group;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_DAC_NAME);

    if (virSecurityDACGetIds(secdef, priv, &user, &group, NULL, NULL) < 0)
        return -1;

    VIR_DEBUG("Setting child to drop privileges to %u:%u",
              (unsigned int)user, (unsigned int)group);

    virCommandSetUID(cmd, user);
    virCommandSetGID(cmd, group);
    return 0;
}


static int
virSecurityDACVerify(virSecurityManager *mgr G_GNUC_UNUSED,
                     virDomainDef *def G_GNUC_UNUSED)
{
    return 0;
}

static int
virSecurityDACGenLabel(virSecurityManager *mgr,
                       virDomainDef *def)
{
    int rc = -1;
    virSecurityLabelDef *seclabel;
    virSecurityDACData *priv = virSecurityManagerGetPrivateData(mgr);

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_DAC_NAME);
    if (seclabel == NULL)
        return rc;

    if (seclabel->imagelabel) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("security image label already defined for VM"));
        return rc;
    }

    if (seclabel->model
        && STRNEQ(seclabel->model, SECURITY_DAC_NAME)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security label model %1$s is not supported with selinux"),
                       seclabel->model);
            return rc;
    }

    switch ((virDomainSeclabelType)seclabel->type) {
    case VIR_DOMAIN_SECLABEL_STATIC:
        if (seclabel->label == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("missing label for static security driver in domain %1$s"),
                           def->name);
            return rc;
        }
        break;
    case VIR_DOMAIN_SECLABEL_DYNAMIC:
        seclabel->label = g_strdup_printf("+%u:+%u", (unsigned int)priv->user,
                                          (unsigned int)priv->group);
        if (seclabel->label == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot generate dac user and group id for domain %1$s"),
                           def->name);
            return rc;
        }
        break;
    case VIR_DOMAIN_SECLABEL_NONE:
        /* no op */
        return 0;
    case VIR_DOMAIN_SECLABEL_DEFAULT:
    case VIR_DOMAIN_SECLABEL_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected security label type '%1$s'"),
                       virDomainSeclabelTypeToString(seclabel->type));
        return rc;
    }

    if (seclabel->relabel && !seclabel->imagelabel)
        seclabel->imagelabel = g_strdup(seclabel->label);

    return 0;
}

static int
virSecurityDACReleaseLabel(virSecurityManager *mgr G_GNUC_UNUSED,
                           virDomainDef *def G_GNUC_UNUSED)
{
    return 0;
}

static int
virSecurityDACReserveLabel(virSecurityManager *mgr G_GNUC_UNUSED,
                           virDomainDef *def G_GNUC_UNUSED,
                           pid_t pid G_GNUC_UNUSED)
{
    return 0;
}

#ifdef __linux__
static int
virSecurityDACGetProcessLabelInternal(pid_t pid,
                                      virSecurityLabelPtr seclabel)
{
    struct stat sb;
    g_autofree char *path = NULL;

    VIR_DEBUG("Getting DAC user and group on process '%d'", pid);

    path = g_strdup_printf("/proc/%d", (int)pid);

    if (g_lstat(path, &sb) < 0) {
        virReportSystemError(errno,
                             _("unable to get uid and gid for PID %1$d via procfs"),
                             pid);
        return -1;
    }

    g_snprintf(seclabel->label, VIR_SECURITY_LABEL_BUFLEN,
               "+%u:+%u", (unsigned int)sb.st_uid, (unsigned int)sb.st_gid);
    return 0;
}
#elif defined(__FreeBSD__)
static int
virSecurityDACGetProcessLabelInternal(pid_t pid,
                                      virSecurityLabelPtr seclabel)
{
    struct kinfo_proc p;
    int mib[4];
    size_t len = 4;

    sysctlnametomib("kern.proc.pid", mib, &len);

    len = sizeof(struct kinfo_proc);
    mib[3] = pid;

    if (sysctl(mib, 4, &p, &len, NULL, 0) < 0) {
        virReportSystemError(errno,
                             _("unable to get PID %1$d uid and gid via sysctl"),
                             pid);
        return -1;
    }

    g_snprintf(seclabel->label, VIR_SECURITY_LABEL_BUFLEN,
               "+%u:+%u", (unsigned int)p.ki_uid, (unsigned int)p.ki_groups[0]);

    return 0;
}
#else
static int
virSecurityDACGetProcessLabelInternal(pid_t pid G_GNUC_UNUSED,
                                      virSecurityLabelPtr seclabel G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Cannot get process uid and gid on this platform"));
    return -1;
}
#endif

static int
virSecurityDACGetProcessLabel(virSecurityManager *mgr G_GNUC_UNUSED,
                              virDomainDef *def,
                              pid_t pid,
                              virSecurityLabelPtr seclabel)
{
    virSecurityLabelDef *secdef =
        virDomainDefGetSecurityLabelDef(def, SECURITY_DAC_NAME);

    if (secdef == NULL) {
        VIR_DEBUG("missing label for DAC security "
                  "driver in domain %s", def->name);

        if (virSecurityDACGetProcessLabelInternal(pid, seclabel) < 0)
            return -1;
        return 0;
    }

    if (secdef->label)
        ignore_value(virStrcpy(seclabel->label, secdef->label,
                               VIR_SECURITY_LABEL_BUFLEN));

    return 0;
}

static int
virSecurityDACSetDaemonSocketLabel(virSecurityManager *mgr G_GNUC_UNUSED,
                                   virDomainDef *vm G_GNUC_UNUSED)
{
    return 0;
}


static int
virSecurityDACSetSocketLabel(virSecurityManager *mgr G_GNUC_UNUSED,
                             virDomainDef *def G_GNUC_UNUSED)
{
    return 0;
}


static int
virSecurityDACClearSocketLabel(virSecurityManager *mgr G_GNUC_UNUSED,
                               virDomainDef *def G_GNUC_UNUSED)
{
    return 0;
}

static int
virSecurityDACSetImageFDLabel(virSecurityManager *mgr G_GNUC_UNUSED,
                              virDomainDef *def G_GNUC_UNUSED,
                              int fd G_GNUC_UNUSED)
{
    return 0;
}

static int
virSecurityDACSetTapFDLabel(virSecurityManager *mgr G_GNUC_UNUSED,
                            virDomainDef *def G_GNUC_UNUSED,
                            int fd G_GNUC_UNUSED)
{
    return 0;
}

static char *
virSecurityDACGetMountOptions(virSecurityManager *mgr G_GNUC_UNUSED,
                              virDomainDef *vm G_GNUC_UNUSED)
{
    return NULL;
}

static const char *
virSecurityDACGetBaseLabel(virSecurityManager *mgr,
                           int virt G_GNUC_UNUSED)
{
    virSecurityDACData *priv = virSecurityManagerGetPrivateData(mgr);
    return priv->baselabel;
}

static int
virSecurityDACDomainSetPathLabel(virSecurityManager *mgr,
                                 virDomainDef *def,
                                 const char *path,
                                 bool allowSubtree G_GNUC_UNUSED)
{
    virSecurityDACData *priv = virSecurityManagerGetPrivateData(mgr);
    virSecurityLabelDef *seclabel;
    uid_t user;
    gid_t group;

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_DAC_NAME);

    if (virSecurityDACGetIds(seclabel, priv, &user, &group, NULL, NULL) < 0)
        return -1;

    return virSecurityDACSetOwnership(mgr, NULL, path, user, group, true);
}

static int
virSecurityDACDomainRestorePathLabel(virSecurityManager *mgr,
                                     virDomainDef *def G_GNUC_UNUSED,
                                     const char *path)
{
    return virSecurityDACRestoreFileLabel(mgr, path);
}


virSecurityDriver virSecurityDriverDAC = {
    .privateDataLen                     = sizeof(virSecurityDACData),
    .name                               = SECURITY_DAC_NAME,
    .probe                              = virSecurityDACProbe,
    .open                               = virSecurityDACOpen,
    .close                              = virSecurityDACClose,

    .getModel                           = virSecurityDACGetModel,
    .getDOI                             = virSecurityDACGetDOI,

    .preFork                            = virSecurityDACPreFork,

    .transactionStart                   = virSecurityDACTransactionStart,
    .transactionCommit                  = virSecurityDACTransactionCommit,
    .transactionAbort                   = virSecurityDACTransactionAbort,

    .domainSecurityVerify               = virSecurityDACVerify,

    .domainSetSecurityImageLabel        = virSecurityDACSetImageLabel,
    .domainRestoreSecurityImageLabel    = virSecurityDACRestoreImageLabel,
    .domainMoveImageMetadata            = virSecurityDACMoveImageMetadata,

    .domainSetSecurityMemoryLabel       = virSecurityDACSetMemoryLabel,
    .domainRestoreSecurityMemoryLabel   = virSecurityDACRestoreMemoryLabel,

    .domainSetSecurityInputLabel        = virSecurityDACSetInputLabel,
    .domainRestoreSecurityInputLabel    = virSecurityDACRestoreInputLabel,

    .domainSetSecurityDaemonSocketLabel = virSecurityDACSetDaemonSocketLabel,
    .domainSetSecuritySocketLabel       = virSecurityDACSetSocketLabel,
    .domainClearSecuritySocketLabel     = virSecurityDACClearSocketLabel,

    .domainGenSecurityLabel             = virSecurityDACGenLabel,
    .domainReserveSecurityLabel         = virSecurityDACReserveLabel,
    .domainReleaseSecurityLabel         = virSecurityDACReleaseLabel,

    .domainGetSecurityProcessLabel      = virSecurityDACGetProcessLabel,
    .domainSetSecurityProcessLabel      = virSecurityDACSetProcessLabel,
    .domainSetSecurityChildProcessLabel = virSecurityDACSetChildProcessLabel,

    .domainSetSecurityAllLabel          = virSecurityDACSetAllLabel,
    .domainRestoreSecurityAllLabel      = virSecurityDACRestoreAllLabel,

    .domainSetSecurityHostdevLabel      = virSecurityDACSetHostdevLabel,
    .domainRestoreSecurityHostdevLabel  = virSecurityDACRestoreHostdevLabel,

    .domainSetSecurityImageFDLabel      = virSecurityDACSetImageFDLabel,
    .domainSetSecurityTapFDLabel        = virSecurityDACSetTapFDLabel,

    .domainGetSecurityMountOptions      = virSecurityDACGetMountOptions,

    .getBaseLabel                       = virSecurityDACGetBaseLabel,

    .domainSetPathLabel                 = virSecurityDACDomainSetPathLabel,
    .domainRestorePathLabel             = virSecurityDACDomainRestorePathLabel,

    .domainSetSecurityChardevLabel      = virSecurityDACSetChardevLabel,
    .domainRestoreSecurityChardevLabel  = virSecurityDACRestoreChardevLabel,
};
