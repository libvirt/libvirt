/*
 * Copyright (C) 2008-2014 Red Hat, Inc.
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
 * SELinux security driver.
 */
#include <config.h>
#include <selinux/selinux.h>
#include <selinux/context.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <selinux/label.h>

#include "security_driver.h"
#include "security_selinux.h"
#include "security_util.h"
#include "virerror.h"
#include "viralloc.h"
#include "virlog.h"
#include "virmdev.h"
#include "virpci.h"
#include "virusb.h"
#include "virscsi.h"
#include "virscsivhost.h"
#include "virstoragefile.h"
#include "virfile.h"
#include "virhash.h"
#include "virrandom.h"
#include "virconf.h"
#include "virtpm.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_SECURITY

VIR_LOG_INIT("security.security_selinux");

#define MAX_CONTEXT 1024

typedef struct _virSecuritySELinuxData virSecuritySELinuxData;
typedef virSecuritySELinuxData *virSecuritySELinuxDataPtr;

struct _virSecuritySELinuxData {
    char *domain_context;
    char *alt_domain_context;
    char *file_context;
    char *content_context;
    virHashTablePtr mcs;
    bool skipAllLabel;
    struct selabel_handle *label_handle;
};

/* Data structure to pass to various callbacks so we have everything we need */
typedef struct _virSecuritySELinuxCallbackData virSecuritySELinuxCallbackData;
typedef virSecuritySELinuxCallbackData *virSecuritySELinuxCallbackDataPtr;

struct _virSecuritySELinuxCallbackData {
    virSecurityManagerPtr mgr;
    virDomainDefPtr def;
};

typedef struct _virSecuritySELinuxContextItem virSecuritySELinuxContextItem;
typedef virSecuritySELinuxContextItem *virSecuritySELinuxContextItemPtr;
struct _virSecuritySELinuxContextItem {
    char *path;
    char *tcon;
    bool remember; /* Whether owner remembering should be done for @path/@src */
    bool restore; /* Whether current operation is 'set' or 'restore' */
};

typedef struct _virSecuritySELinuxContextList virSecuritySELinuxContextList;
typedef virSecuritySELinuxContextList *virSecuritySELinuxContextListPtr;
struct _virSecuritySELinuxContextList {
    virSecurityManagerPtr manager;
    virSecuritySELinuxContextItemPtr *items;
    size_t nItems;
    bool lock;
};

#define SECURITY_SELINUX_VOID_DOI       "0"
#define SECURITY_SELINUX_NAME "selinux"

static int
virSecuritySELinuxRestoreTPMFileLabelInt(virSecurityManagerPtr mgr,
                                         virDomainDefPtr def,
                                         virDomainTPMDefPtr tpm);


virThreadLocal contextList;


static void
virSecuritySELinuxContextItemFree(virSecuritySELinuxContextItemPtr item)
{
    if (!item)
        return;

    VIR_FREE(item->path);
    VIR_FREE(item->tcon);
    VIR_FREE(item);
}

static int
virSecuritySELinuxContextListAppend(virSecuritySELinuxContextListPtr list,
                                    const char *path,
                                    const char *tcon,
                                    bool remember,
                                    bool restore)
{
    int ret = -1;
    virSecuritySELinuxContextItemPtr item = NULL;

    if (VIR_ALLOC(item) < 0)
        return -1;

    item->path = g_strdup(path);
    item->tcon = g_strdup(tcon);

    item->remember = remember;
    item->restore = restore;

    if (VIR_APPEND_ELEMENT(list->items, list->nItems, item) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecuritySELinuxContextItemFree(item);
    return ret;
}

static void
virSecuritySELinuxContextListFree(void *opaque)
{
    virSecuritySELinuxContextListPtr list = opaque;
    size_t i;

    if (!list)
        return;

    for (i = 0; i < list->nItems; i++)
        virSecuritySELinuxContextItemFree(list->items[i]);

    VIR_FREE(list->items);
    virObjectUnref(list->manager);
    VIR_FREE(list);
}


/**
 * virSecuritySELinuxTransactionAppend:
 * @path: Path to chown
 * @tcon: target context
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
virSecuritySELinuxTransactionAppend(const char *path,
                                    const char *tcon,
                                    bool remember,
                                    bool restore)
{
    virSecuritySELinuxContextListPtr list;

    list = virThreadLocalGet(&contextList);
    if (!list)
        return 0;

    if (virSecuritySELinuxContextListAppend(list, path, tcon,
                                            remember, restore) < 0)
        return -1;

    return 1;
}


static int
virSecuritySELinuxRememberLabel(const char *path,
                                const security_context_t con)
{
    return virSecuritySetRememberedLabel(SECURITY_SELINUX_NAME,
                                         path, con);
}


static int
virSecuritySELinuxRecallLabel(const char *path,
                              security_context_t *con)
{
    int rv;

    rv = virSecurityGetRememberedLabel(SECURITY_SELINUX_NAME, path, con);
    if (rv < 0)
        return rv;

    if (!*con)
        return 1;

    return 0;
}


static int virSecuritySELinuxSetFilecon(virSecurityManagerPtr mgr,
                                        const char *path,
                                        const char *tcon,
                                        bool remember);


static int virSecuritySELinuxRestoreFileLabel(virSecurityManagerPtr mgr,
                                              const char *path,
                                              bool recall);


/**
 * virSecuritySELinuxTransactionRun:
 * @pid: process pid
 * @opaque: opaque data
 *
 * This is the callback that runs in the same namespace as the domain we are
 * relabelling. For given transaction (@opaque) it relabels all the paths on
 * the list.
 *
 * Returns: 0 on success
 *         -1 otherwise.
 */
static int
virSecuritySELinuxTransactionRun(pid_t pid G_GNUC_UNUSED,
                                 void *opaque)
{
    virSecuritySELinuxContextListPtr list = opaque;
    virSecurityManagerMetadataLockStatePtr state;
    const char **paths = NULL;
    size_t npaths = 0;
    size_t i;
    int rv;
    int ret = -1;

    if (list->lock) {
        if (VIR_ALLOC_N(paths, list->nItems) < 0)
            return -1;

        for (i = 0; i < list->nItems; i++) {
            virSecuritySELinuxContextItemPtr item = list->items[i];
            const char *p = item->path;

            if (item->remember)
                VIR_APPEND_ELEMENT_COPY_INPLACE(paths, npaths, p);
        }

        if (!(state = virSecurityManagerMetadataLock(list->manager, paths, npaths)))
            goto cleanup;

        for (i = 0; i < list->nItems; i++) {
            virSecuritySELinuxContextItemPtr item = list->items[i];
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

    rv = 0;
    for (i = 0; i < list->nItems; i++) {
        virSecuritySELinuxContextItemPtr item = list->items[i];
        const bool remember = item->remember && list->lock;

        if (!item->restore) {
            rv = virSecuritySELinuxSetFilecon(list->manager,
                                              item->path,
                                              item->tcon,
                                              remember);
        } else {
            rv = virSecuritySELinuxRestoreFileLabel(list->manager,
                                                    item->path,
                                                    remember);
        }

        if (rv < 0)
            break;
    }

    for (; rv < 0 && i > 0; i--) {
        virSecuritySELinuxContextItemPtr item = list->items[i - 1];
        const bool remember = item->remember && list->lock;

        if (!item->restore) {
            virSecuritySELinuxRestoreFileLabel(list->manager,
                                               item->path,
                                               remember);
        } else {
            VIR_WARN("Ignoring failed restore attempt on %s", item->path);
        }
    }

    if (list->lock)
        virSecurityManagerMetadataUnlock(list->manager, &state);

    if (rv < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(paths);
    return ret;
}


/*
 * Returns 0 on success, 1 if already reserved, or -1 on fatal error
 */
static int
virSecuritySELinuxMCSAdd(virSecurityManagerPtr mgr,
                         const char *mcs)
{
    virSecuritySELinuxDataPtr data = virSecurityManagerGetPrivateData(mgr);

    if (virHashLookup(data->mcs, mcs))
        return 1;

    if (virHashAddEntry(data->mcs, mcs, (void*)0x1) < 0)
        return -1;

    return 0;
}

static void
virSecuritySELinuxMCSRemove(virSecurityManagerPtr mgr,
                            const char *mcs)
{
    virSecuritySELinuxDataPtr data = virSecurityManagerGetPrivateData(mgr);

    virHashRemoveEntry(data->mcs, mcs);
}


static char *
virSecuritySELinuxMCSFind(virSecurityManagerPtr mgr,
                          const char *sens,
                          int catMin,
                          int catMax)
{
    virSecuritySELinuxDataPtr data = virSecurityManagerGetPrivateData(mgr);
    int catRange;
    char *mcs = NULL;

    /* +1 since virRandomInt range is exclusive of the upper bound */
    catRange = (catMax - catMin) + 1;

    if (catRange < 8) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Category range c%d-c%d too small"),
                       catMin, catMax);
        return NULL;
    }

    VIR_DEBUG("Using sensitivity level '%s' cat min %d max %d range %d",
              sens, catMin, catMax, catRange);

    for (;;) {
        int c1 = virRandomInt(catRange);
        int c2 = virRandomInt(catRange);

        VIR_DEBUG("Try cat %s:c%d,c%d", sens, c1 + catMin, c2 + catMin);

        if (c1 == c2) {
            mcs = g_strdup_printf("%s:c%d", sens, catMin + c1);
        } else {
            if (c1 > c2) {
                int t = c1;
                c1 = c2;
                c2 = t;
            }
            mcs = g_strdup_printf("%s:c%d,c%d", sens, catMin + c1, catMin + c2);
        }

        if (virHashLookup(data->mcs, mcs) == NULL)
            break;

        VIR_FREE(mcs);
    }

    return mcs;
}


/*
 * This needs to cope with several styles of range
 *
 * system_u:system_r:virtd_t
 * system_u:system_r:virtd_t:s0
 * system_u:system_r:virtd_t:s0-s0
 * system_u:system_r:virtd_t:s0-s0:c0.c1023
 *
 * In the first case we'll assume s0:c0.c1023 and
 * in the next two cases, we'll assume c0.c1023 for
 * the category part, since that's what we're really
 * interested in. This won't work in Enforcing mode,
 * but will prevent libvirtd breaking in Permissive
 * mode when run with a weird process label.
 */
static int
virSecuritySELinuxMCSGetProcessRange(char **sens,
                                     int *catMin,
                                     int *catMax)
{
    security_context_t ourSecContext = NULL;
    context_t ourContext = NULL;
    char *cat = NULL;
    char *tmp;
    const char *contextRange;
    int ret = -1;

    if (getcon_raw(&ourSecContext) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to get current process SELinux context"));
        goto cleanup;
    }
    if (!(ourContext = context_new(ourSecContext))) {
        virReportSystemError(errno,
                             _("Unable to parse current SELinux context '%s'"),
                             ourSecContext);
        goto cleanup;
    }
    if (!(contextRange = context_range_get(ourContext)))
        contextRange = "s0";

    *sens = g_strdup(contextRange);

    /* Find and blank out the category part (if any) */
    tmp = strchr(*sens, ':');
    if (tmp) {
        *tmp = '\0';
        cat = tmp + 1;
    }
    /* Find and blank out the sensitivity upper bound */
    if ((tmp = strchr(*sens, '-')))
        *tmp = '\0';
    /* sens now just contains the sensitivity lower bound */

    /* If there was no category part, just assume c0.c1023 */
    if (!cat) {
        *catMin = 0;
        *catMax = 1023;
        ret = 0;
        goto cleanup;
    }

    /* Find & extract category min */
    tmp = cat;
    if (tmp[0] != 'c') {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot parse category in %s"),
                       cat);
        goto cleanup;
    }
    tmp++;
    if (virStrToLong_i(tmp, &tmp, 10, catMin) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot parse category in %s"),
                       cat);
        goto cleanup;
    }

    /* We *must* have a pair of categories otherwise
     * there's no range to allocate VM categories from */
    if (!tmp[0]) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("No category range available"));
        goto cleanup;
    }

    /* Find & extract category max (if any) */
    if (tmp[0] != '.') {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot parse category in %s"),
                       cat);
        goto cleanup;
    }
    tmp++;
    if (tmp[0] != 'c') {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot parse category in %s"),
                       cat);
        goto cleanup;
    }
    tmp++;
    if (virStrToLong_i(tmp, &tmp, 10, catMax) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot parse category in %s"),
                       cat);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    if (ret < 0)
        VIR_FREE(*sens);
    freecon(ourSecContext);
    context_free(ourContext);
    return ret;
}

static char *
virSecuritySELinuxContextAddRange(security_context_t src,
                                  security_context_t dst)
{
    char *str = NULL;
    char *ret = NULL;
    context_t srccon = NULL;
    context_t dstcon = NULL;

    if (!src || !dst)
        return ret;

    if (!(srccon = context_new(src)) || !(dstcon = context_new(dst))) {
        virReportSystemError(errno, "%s",
                             _("unable to allocate security context"));
        goto cleanup;
    }

    if (context_range_set(dstcon, context_range_get(srccon)) == -1) {
        virReportSystemError(errno,
                             _("unable to set security context range '%s'"), dst);
        goto cleanup;
    }

    if (!(str = context_str(dstcon))) {
        virReportSystemError(errno, "%s",
                             _("Unable to format SELinux context"));
        goto cleanup;
    }

    ret = g_strdup(str);

 cleanup:
    if (srccon) context_free(srccon);
    if (dstcon) context_free(dstcon);
    return ret;
}

static char *
virSecuritySELinuxGenNewContext(const char *basecontext,
                                const char *mcs,
                                bool isObjectContext)
{
    context_t context = NULL;
    char *ret = NULL;
    char *str;
    security_context_t ourSecContext = NULL;
    context_t ourContext = NULL;

    VIR_DEBUG("basecontext=%s mcs=%s isObjectContext=%d",
              basecontext, mcs, isObjectContext);

    if (getcon_raw(&ourSecContext) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to get current process SELinux context"));
        goto cleanup;
    }
    if (!(ourContext = context_new(ourSecContext))) {
        virReportSystemError(errno,
                             _("Unable to parse current SELinux context '%s'"),
                             ourSecContext);
        goto cleanup;
    }
    VIR_DEBUG("process=%s", ourSecContext);

    if (!(context = context_new(basecontext))) {
        virReportSystemError(errno,
                             _("Unable to parse base SELinux context '%s'"),
                             basecontext);
        goto cleanup;
    }

    if (context_user_set(context,
                         context_user_get(ourContext)) != 0) {
        virReportSystemError(errno,
                             _("Unable to set SELinux context user '%s'"),
                             context_user_get(ourContext));
        goto cleanup;
    }

    if (!isObjectContext &&
        context_role_set(context,
                         context_role_get(ourContext)) != 0) {
        virReportSystemError(errno,
                             _("Unable to set SELinux context role '%s'"),
                             context_role_get(ourContext));
        goto cleanup;
    }

    if (context_range_set(context, mcs) != 0) {
        virReportSystemError(errno,
                             _("Unable to set SELinux context MCS '%s'"),
                             mcs);
        goto cleanup;
    }
    if (!(str = context_str(context))) {
        virReportSystemError(errno, "%s",
                             _("Unable to format SELinux context"));
        goto cleanup;
    }
    ret = g_strdup(str);
    VIR_DEBUG("Generated context '%s'",  ret);
 cleanup:
    freecon(ourSecContext);
    context_free(ourContext);
    context_free(context);
    return ret;
}


#ifdef HAVE_SELINUX_LXC_CONTEXTS_PATH
static int
virSecuritySELinuxLXCInitialize(virSecurityManagerPtr mgr)
{
    g_autoptr(virConf) selinux_conf = NULL;
    virSecuritySELinuxDataPtr data = virSecurityManagerGetPrivateData(mgr);

    data->skipAllLabel = true;

    data->label_handle = selabel_open(SELABEL_CTX_FILE, NULL, 0);
    if (!data->label_handle) {
        virReportSystemError(errno, "%s",
                             _("cannot open SELinux label_handle"));
        return -1;
    }

    if (!(selinux_conf = virConfReadFile(selinux_lxc_contexts_path(), 0)))
        goto error;

    if (virConfGetValueString(selinux_conf, "process", &data->domain_context) < 0)
        goto error;

    if (!data->domain_context) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing 'process' value in selinux lxc contexts file '%s'"),
                       selinux_lxc_contexts_path());
        goto error;
    }

    if (virConfGetValueString(selinux_conf, "file", &data->file_context) < 0)
        goto error;

    if (!data->file_context) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing 'file' value in selinux lxc contexts file '%s'"),
                       selinux_lxc_contexts_path());
        goto error;
    }

    if (virConfGetValueString(selinux_conf, "content", &data->content_context) < 0)
        goto error;

    if (!data->content_context) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing 'content' value in selinux lxc contexts file '%s'"),
                       selinux_lxc_contexts_path());
        goto error;
    }

    if (!(data->mcs = virHashCreate(10, NULL)))
        goto error;

    return 0;

 error:
    selabel_close(data->label_handle);
    data->label_handle = NULL;
    VIR_FREE(data->domain_context);
    VIR_FREE(data->file_context);
    VIR_FREE(data->content_context);
    virHashFree(data->mcs);
    return -1;
}
#else
static int
virSecuritySELinuxLXCInitialize(virSecurityManagerPtr mgr G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("libselinux does not support LXC contexts path"));
    return -1;
}
#endif


static int
virSecuritySELinuxQEMUInitialize(virSecurityManagerPtr mgr)
{
    char *ptr;
    virSecuritySELinuxDataPtr data = virSecurityManagerGetPrivateData(mgr);

    data->skipAllLabel = false;

    data->label_handle = selabel_open(SELABEL_CTX_FILE, NULL, 0);
    if (!data->label_handle) {
        virReportSystemError(errno, "%s",
                             _("cannot open SELinux label_handle"));
        return -1;
    }

    if (virFileReadAll(selinux_virtual_domain_context_path(), MAX_CONTEXT, &(data->domain_context)) < 0) {
        virReportSystemError(errno,
                             _("cannot read SELinux virtual domain context file '%s'"),
                             selinux_virtual_domain_context_path());
        goto error;
    }

    ptr = strchr(data->domain_context, '\n');
    if (ptr) {
        *ptr = '\0';
        ptr++;
        if (*ptr != '\0') {
            data->alt_domain_context = g_strdup(ptr);
            ptr = strchr(data->alt_domain_context, '\n');
            if (ptr)
                *ptr = '\0';
        }
    }
    VIR_DEBUG("Loaded domain context '%s', alt domain context '%s'",
              data->domain_context, NULLSTR(data->alt_domain_context));


    if (virFileReadAll(selinux_virtual_image_context_path(), 2*MAX_CONTEXT, &(data->file_context)) < 0) {
        virReportSystemError(errno,
                             _("cannot read SELinux virtual image context file %s"),
                             selinux_virtual_image_context_path());
        goto error;
    }

    ptr = strchr(data->file_context, '\n');
    if (ptr) {
        *ptr = '\0';
        data->content_context = g_strdup(ptr + 1);
        ptr = strchr(data->content_context, '\n');
        if (ptr)
            *ptr = '\0';
    }

    VIR_DEBUG("Loaded file context '%s', content context '%s'",
              data->file_context, data->content_context);

    if (!(data->mcs = virHashCreate(10, NULL)))
        goto error;

    return 0;

 error:
    selabel_close(data->label_handle);
    data->label_handle = NULL;
    VIR_FREE(data->domain_context);
    VIR_FREE(data->alt_domain_context);
    VIR_FREE(data->file_context);
    VIR_FREE(data->content_context);
    virHashFree(data->mcs);
    return -1;
}


static int
virSecuritySELinuxInitialize(virSecurityManagerPtr mgr)
{
    VIR_DEBUG("SELinuxInitialize %s", virSecurityManagerGetVirtDriver(mgr));

    if (virThreadLocalInit(&contextList,
                           virSecuritySELinuxContextListFree) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to initialize thread local variable"));
        return -1;
    }

    if (STREQ(virSecurityManagerGetVirtDriver(mgr), "LXC")) {
        return virSecuritySELinuxLXCInitialize(mgr);
    } else {
        return virSecuritySELinuxQEMUInitialize(mgr);
    }
}


static int
virSecuritySELinuxGenLabel(virSecurityManagerPtr mgr,
                           virDomainDefPtr def)
{
    int rc = -1;
    char *mcs = NULL;
    char *scontext = NULL;
    context_t ctx = NULL;
    const char *range;
    virSecurityLabelDefPtr seclabel;
    virSecuritySELinuxDataPtr data;
    const char *baselabel;
    char *sens = NULL;
    int catMin, catMax;

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (seclabel == NULL)
        return 0;

    data = virSecurityManagerGetPrivateData(mgr);

    VIR_DEBUG("label=%s", virSecurityManagerGetVirtDriver(mgr));
    if (seclabel->type == VIR_DOMAIN_SECLABEL_DYNAMIC &&
        seclabel->label) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("security label already defined for VM"));
        return rc;
    }

    if (seclabel->imagelabel) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("security image label already defined for VM"));
        return rc;
    }

    if (seclabel->model &&
        STRNEQ(seclabel->model, SECURITY_SELINUX_NAME)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security label model %s is not supported with selinux"),
                       seclabel->model);
        return rc;
    }

    VIR_DEBUG("type=%d", seclabel->type);

    switch (seclabel->type) {
    case VIR_DOMAIN_SECLABEL_STATIC:
        if (!(ctx = context_new(seclabel->label))) {
            virReportSystemError(errno,
                                 _("unable to allocate socket security context '%s'"),
                                 seclabel->label);
            return rc;
        }

        if (!(range = context_range_get(ctx))) {
            virReportSystemError(errno, "%s", _("unable to get selinux context range"));
            goto cleanup;
        }
        mcs = g_strdup(range);
        break;

    case VIR_DOMAIN_SECLABEL_DYNAMIC:
        if (virSecuritySELinuxMCSGetProcessRange(&sens,
                                                 &catMin,
                                                 &catMax) < 0)
            goto cleanup;

        if (!(mcs = virSecuritySELinuxMCSFind(mgr,
                                              sens,
                                              catMin,
                                              catMax)))
            goto cleanup;

        if (virSecuritySELinuxMCSAdd(mgr, mcs) < 0)
            goto cleanup;

        baselabel = seclabel->baselabel;
        if (!baselabel) {
            if (def->virtType == VIR_DOMAIN_VIRT_QEMU) {
                if (data->alt_domain_context == NULL) {
                    static bool warned;
                    if (!warned) {
                        VIR_WARN("SELinux policy does not define a domain type for QEMU TCG. "
                                 "Guest startup may be denied due to missing 'execmem' privilege "
                                 "unless the 'virt_use_execmem' policy boolean is enabled");
                        warned = true;
                    }
                    baselabel = data->domain_context;
                } else {
                    baselabel = data->alt_domain_context;
                }
            } else {
                baselabel = data->domain_context;
            }
        }

        seclabel->label = virSecuritySELinuxGenNewContext(baselabel, mcs, false);
        if (!seclabel->label)
            goto cleanup;

        break;

    case VIR_DOMAIN_SECLABEL_NONE:
        if (virSecuritySELinuxMCSGetProcessRange(&sens,
                                                 &catMin,
                                                 &catMax) < 0)
            goto cleanup;

        mcs = g_strdup(sens);

        break;

    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected security label type '%s'"),
                       virDomainSeclabelTypeToString(seclabel->type));
        goto cleanup;
    }

    /* always generate a image label, needed to label new objects */
    seclabel->imagelabel = virSecuritySELinuxGenNewContext(data->file_context,
                                                           mcs,
                                                           true);
    if (!seclabel->imagelabel)
        goto cleanup;

    if (!seclabel->model)
        seclabel->model = g_strdup(SECURITY_SELINUX_NAME);

    rc = 0;

 cleanup:
    if (rc != 0) {
        if (seclabel->type == VIR_DOMAIN_SECLABEL_DYNAMIC)
            VIR_FREE(seclabel->label);
        VIR_FREE(seclabel->imagelabel);
        if (seclabel->type == VIR_DOMAIN_SECLABEL_DYNAMIC &&
            !seclabel->baselabel)
            VIR_FREE(seclabel->model);
    }

    if (ctx)
        context_free(ctx);
    VIR_FREE(scontext);
    VIR_FREE(mcs);
    VIR_FREE(sens);

    VIR_DEBUG("model=%s label=%s imagelabel=%s baselabel=%s",
              NULLSTR(seclabel->model),
              NULLSTR(seclabel->label),
              NULLSTR(seclabel->imagelabel),
              NULLSTR(seclabel->baselabel));

    return rc;
}

static int
virSecuritySELinuxReserveLabel(virSecurityManagerPtr mgr,
                               virDomainDefPtr def,
                               pid_t pid)
{
    security_context_t pctx;
    context_t ctx = NULL;
    const char *mcs;
    int rv;
    virSecurityLabelDefPtr seclabel;

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (!seclabel ||
        seclabel->type == VIR_DOMAIN_SECLABEL_NONE ||
        seclabel->type == VIR_DOMAIN_SECLABEL_STATIC)
        return 0;

    if (getpidcon_raw(pid, &pctx) == -1) {
        virReportSystemError(errno,
                             _("unable to get PID %d security context"), pid);
        return -1;
    }

    ctx = context_new(pctx);
    freecon(pctx);
    if (!ctx)
        goto error;

    mcs = context_range_get(ctx);
    if (!mcs)
        goto error;

    if ((rv = virSecuritySELinuxMCSAdd(mgr, mcs)) < 0)
        goto error;

    if (rv == 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("MCS level for existing domain label %s already reserved"),
                       (char*)pctx);
        goto error;
    }

    context_free(ctx);

    return 0;

 error:
    context_free(ctx);
    return -1;
}


static int
virSecuritySELinuxDriverProbe(const char *virtDriver)
{
    if (is_selinux_enabled() <= 0)
        return SECURITY_DRIVER_DISABLE;

    if (virtDriver && STREQ(virtDriver, "LXC")) {
#if HAVE_SELINUX_LXC_CONTEXTS_PATH
        if (!virFileExists(selinux_lxc_contexts_path()))
#endif
            return SECURITY_DRIVER_DISABLE;
    }

    return SECURITY_DRIVER_ENABLE;
}


static int
virSecuritySELinuxDriverOpen(virSecurityManagerPtr mgr)
{
    return virSecuritySELinuxInitialize(mgr);
}


static int
virSecuritySELinuxDriverClose(virSecurityManagerPtr mgr)
{
    virSecuritySELinuxDataPtr data = virSecurityManagerGetPrivateData(mgr);

    if (!data)
        return 0;

    if (data->label_handle)
        selabel_close(data->label_handle);

    virHashFree(data->mcs);

    VIR_FREE(data->domain_context);
    VIR_FREE(data->alt_domain_context);
    VIR_FREE(data->file_context);
    VIR_FREE(data->content_context);

    return 0;
}


static const char *
virSecuritySELinuxGetModel(virSecurityManagerPtr mgr G_GNUC_UNUSED)
{
    return SECURITY_SELINUX_NAME;
}

static const char *
virSecuritySELinuxGetDOI(virSecurityManagerPtr mgr G_GNUC_UNUSED)
{
    /*
     * Where will the DOI come from?  SELinux configuration, or qemu
     * configuration? For the moment, we'll just set it to "0".
     */
    return SECURITY_SELINUX_VOID_DOI;
}

/**
 * virSecuritySELinuxTransactionStart:
 * @mgr: security manager
 *
 * Starts a new transaction. In transaction nothing is changed context
 * until TransactionCommit() is called. This is implemented as a list
 * that is appended to whenever setfilecon() would be called. Since
 * secdriver APIs can be called from multiple threads (to work over
 * different domains) the pointer to the list is stored in thread local
 * variable.
 *
 * Returns 0 on success,
 *        -1 otherwise.
 */
static int
virSecuritySELinuxTransactionStart(virSecurityManagerPtr mgr)
{
    virSecuritySELinuxContextListPtr list;

    list = virThreadLocalGet(&contextList);
    if (list) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Another relabel transaction is already started"));
        return -1;
    }

    if (VIR_ALLOC(list) < 0)
        return -1;

    list->manager = virObjectRef(mgr);

    if (virThreadLocalSet(&contextList, list) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to set thread local variable"));
        virSecuritySELinuxContextListFree(list);
        return -1;
    }

    return 0;
}

/**
 * virSecuritySELinuxTransactionCommit:
 * @mgr: security manager
 * @pid: domain's PID
 * @lock: lock and unlock paths that are relabeled
 *
 * If @pis is not -1 then enter the @pid namespace (usually @pid refers
 * to a domain) and perform all the sefilecon()-s on the list. If @pid
 * is -1 then the transaction is performed in the namespace of the
 * caller.
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
virSecuritySELinuxTransactionCommit(virSecurityManagerPtr mgr G_GNUC_UNUSED,
                                    pid_t pid,
                                    bool lock)
{
    virSecuritySELinuxContextListPtr list;
    int rc;
    int ret = -1;

    list = virThreadLocalGet(&contextList);
    if (!list) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("No transaction is set"));
        return -1;
    }

    if (virThreadLocalSet(&contextList, NULL) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to clear thread local variable"));
        goto cleanup;
    }

    list->lock = lock;

    if (pid != -1) {
        rc = virProcessRunInMountNamespace(pid,
                                           virSecuritySELinuxTransactionRun,
                                           list);
        if (rc < 0) {
            if (virGetLastErrorCode() == VIR_ERR_SYSTEM_ERROR)
                pid = -1;
            else
                goto cleanup;
        }
    }

    if (pid == -1) {
        if (lock)
            rc = virProcessRunInFork(virSecuritySELinuxTransactionRun, list);
        else
            rc = virSecuritySELinuxTransactionRun(pid, list);
    }

    if (rc < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virSecuritySELinuxContextListFree(list);
    return ret;
}

/**
 * virSecuritySELinuxTransactionAbort:
 * @mgr: security manager
 *
 * Cancels and frees any out standing transaction.
 */
static void
virSecuritySELinuxTransactionAbort(virSecurityManagerPtr mgr G_GNUC_UNUSED)
{
    virSecuritySELinuxContextListPtr list;

    list = virThreadLocalGet(&contextList);
    if (!list)
        return;

    if (virThreadLocalSet(&contextList, NULL) < 0)
        VIR_DEBUG("Unable to clear thread local variable");
    virSecuritySELinuxContextListFree(list);
}

static int
virSecuritySELinuxGetProcessLabel(virSecurityManagerPtr mgr G_GNUC_UNUSED,
                                  virDomainDefPtr def G_GNUC_UNUSED,
                                  pid_t pid,
                                  virSecurityLabelPtr sec)
{
    security_context_t ctx;

    if (getpidcon_raw(pid, &ctx) == -1) {
        virReportSystemError(errno,
                             _("unable to get PID %d security context"),
                             pid);
        return -1;
    }

    if (strlen((char *)ctx) >= VIR_SECURITY_LABEL_BUFLEN) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security label exceeds "
                         "maximum length: %d"),
                       VIR_SECURITY_LABEL_BUFLEN - 1);
        freecon(ctx);
        return -1;
    }

    strcpy(sec->label, (char *)ctx);
    freecon(ctx);

    VIR_DEBUG("label=%s", sec->label);
    sec->enforcing = security_getenforce();
    if (sec->enforcing == -1) {
        virReportSystemError(errno, "%s",
                             _("error calling security_getenforce()"));
        return -1;
    }

    return 0;
}

/**
 * virSecuritySELinuxSetFileconImpl:
 * @path: path to the file to set context on
 * @tcon: target context to set
 * @privileged: whether running as privileged user
 *
 * Set @tcon SELinux context on @path. If unable to do so, check SELinux
 * configuration and produce sensible error message suggesting solution.
 * It may happen that setting context fails but hypervisor will be able to
 * open the @path successfully. This is because some file systems don't
 * support SELinux, are RO, or the @path had the correct context from the
 * start. If that is the case, a positive one is returned.
 *
 * Returns:  0 if context was set successfully
 *           1 if setting the context failed in a non-critical fashion
 *           -1 in case of error
 */
static int
virSecuritySELinuxSetFileconImpl(const char *path,
                                 const char *tcon,
                                 bool privileged)
{
    /* Be aware that this function might run in a separate process.
     * Therefore, any driver state changes would be thrown away. */

    VIR_INFO("Setting SELinux context on '%s' to '%s'", path, tcon);

    if (setfilecon_raw(path, (const char *)tcon) < 0) {
        int setfilecon_errno = errno;

        /* If the error complaint is related to an image hosted on a (possibly
         * read-only) NFS mount, or a usbfs/sysfs filesystem not supporting
         * labelling, then just ignore it & hope for the best.  The user
         * hopefully sets one of the necessary SELinux virt_use_{nfs,usb,pci}
         * boolean tunables to allow it ...
         */
        VIR_WARNINGS_NO_WLOGICALOP_EQUAL_EXPR
        if (setfilecon_errno != EOPNOTSUPP && setfilecon_errno != ENOTSUP &&
            setfilecon_errno != EROFS) {
        VIR_WARNINGS_RESET
            /* However, don't claim error if SELinux is in Enforcing mode and
             * we are running as unprivileged user and we really did see EPERM.
             * Otherwise we want to return error if SELinux is Enforcing. */
            if (security_getenforce() == 1 &&
                (setfilecon_errno != EPERM || privileged)) {
                virReportSystemError(setfilecon_errno,
                                     _("unable to set security context '%s' on '%s'"),
                                     tcon, path);
                return -1;
            }
            VIR_WARN("unable to set security context '%s' on '%s' (errno %d)",
                     tcon, path, setfilecon_errno);
        } else {
            const char *msg;
            if (virFileIsSharedFSType(path, VIR_FILE_SHFS_NFS) == 1 &&
                security_get_boolean_active("virt_use_nfs") != 1) {
                msg = _("Setting security context '%s' on '%s' not supported. "
                        "Consider setting virt_use_nfs");
                if (security_getenforce() == 1)
                    VIR_WARN(msg, tcon, path);
                else
                    VIR_INFO(msg, tcon, path);
            } else {
                VIR_INFO("Setting security context '%s' on '%s' not supported",
                         tcon, path);
            }
        }

        return 1;
    }
    return 0;
}


static int
virSecuritySELinuxSetFilecon(virSecurityManagerPtr mgr,
                             const char *path,
                             const char *tcon,
                             bool remember)
{
    bool privileged = virSecurityManagerGetPrivileged(mgr);
    security_context_t econ = NULL;
    int refcount;
    int rc;
    bool rollback = false;
    int ret = -1;

    if ((rc = virSecuritySELinuxTransactionAppend(path, tcon,
                                                  remember, false)) < 0)
        return -1;
    else if (rc > 0)
        return 0;

    if (remember) {
        if (getfilecon_raw(path, &econ) < 0 &&
            errno != ENOTSUP && errno != ENODATA) {
            virReportSystemError(errno,
                                 _("unable to get SELinux context of %s"),
                                 path);
            goto cleanup;
        }

        if (econ) {
            refcount = virSecuritySELinuxRememberLabel(path, econ);
            if (refcount > 0)
                rollback = true;
            if (refcount == -2) {
                /* Not supported. Don't error though. */
            } else if (refcount < 0) {
                goto cleanup;
            } else if (refcount > 1) {
                /* Refcount is greater than 1 which means that there
                 * is @refcount domains using the @path. Do not
                 * change the label (as it would almost certainly
                 * cause the other domains to lose access to the
                 * @path). However, the refcounter was
                 * incremented in XATTRs so decrease it. */
                if (STRNEQ(econ, tcon)) {
                    virReportError(VIR_ERR_OPERATION_INVALID,
                                   _("Setting different SELinux label on %s "
                                     "which is already in use"), path);
                    goto cleanup;
                }
            }
        }
    }

    rc = virSecuritySELinuxSetFileconImpl(path, tcon, privileged);
    if (rc < 0)
        goto cleanup;

    /* Do not try restoring the label if it was not changed
     * (setting it failed in a non-critical fashion) */
    if (rc == 0)
        rollback = false;

    ret = 0;
 cleanup:
    if (rollback) {
        virErrorPtr origerr;

        virErrorPreserveLast(&origerr);
        /* Try to restore the label. This is done so that XATTRs
         * are left in the same state as when the control entered
         * this function. However, if our attempt fails, there's
         * not much we can do. XATTRs refcounting is fubar'ed and
         * the only option we have is warn users. */
        if (virSecuritySELinuxRestoreFileLabel(mgr, path, remember) < 0)
            VIR_WARN("Unable to restore label on '%s'. "
                     "XATTRs might have been left in inconsistent state.",
                     path);

        virErrorRestore(&origerr);

    }
    freecon(econ);
    return ret;
}


static int
virSecuritySELinuxFSetFilecon(int fd, char *tcon)
{
    VIR_INFO("Setting SELinux context on fd %d to '%s'", fd, tcon);

    if (fsetfilecon_raw(fd, tcon) < 0) {
        int fsetfilecon_errno = errno;

        /* if the error complaint is related to an image hosted on
         * an nfs mount, or a usbfs/sysfs filesystem not supporting
         * labelling, then just ignore it & hope for the best.
         * The user hopefully set one of the necessary SELinux
         * virt_use_{nfs,usb,pci}  boolean tunables to allow it...
         */
        if (fsetfilecon_errno != EOPNOTSUPP) {
            virReportSystemError(fsetfilecon_errno,
                                 _("unable to set security context '%s' on fd %d"),
                                 tcon, fd);
            if (security_getenforce() == 1)
                return -1;
        } else {
            VIR_INFO("Setting security context '%s' on fd %d not supported",
                     tcon, fd);
        }
    }
    return 0;
}

/* Set fcon to the appropriate label for path and mode, or return -1.  */
static int
getContext(virSecurityManagerPtr mgr G_GNUC_UNUSED,
           const char *newpath, mode_t mode, security_context_t *fcon)
{
    virSecuritySELinuxDataPtr data = virSecurityManagerGetPrivateData(mgr);

    return selabel_lookup_raw(data->label_handle, fcon, newpath, mode);
}


/* This method shouldn't raise errors, since they'll overwrite
 * errors that the caller(s) are already dealing with */
static int
virSecuritySELinuxRestoreFileLabel(virSecurityManagerPtr mgr,
                                   const char *path,
                                   bool recall)
{
    bool privileged = virSecurityManagerGetPrivileged(mgr);
    struct stat buf;
    security_context_t fcon = NULL;
    char *newpath = NULL;
    int rc;
    int ret = -1;

    /* Some paths are auto-generated, so let's be safe here and do
     * nothing if nothing is needed.
     */
    if (!path)
        return 0;

    VIR_INFO("Restoring SELinux context on '%s'", path);

    if (virFileResolveLink(path, &newpath) < 0) {
        VIR_WARN("cannot resolve symlink %s: %s", path,
                 g_strerror(errno));
        goto cleanup;
    }

    if ((rc = virSecuritySELinuxTransactionAppend(path, NULL,
                                                  recall, true)) < 0) {
        goto cleanup;
    } else if (rc > 0) {
        ret = 0;
        goto cleanup;
    }

    if (recall) {
        rc = virSecuritySELinuxRecallLabel(newpath, &fcon);
        if (rc == -2) {
            /* Not supported. Lookup the default label below. */
        } else if (rc < 0) {
            goto cleanup;
        } else if (rc > 0) {
            ret = 0;
            goto cleanup;
        }
    }

    if (!recall || rc == -2) {
        if (stat(newpath, &buf) != 0) {
            VIR_WARN("cannot stat %s: %s", newpath,
                     g_strerror(errno));
            goto cleanup;
        }

        if (getContext(mgr, newpath, buf.st_mode, &fcon) < 0) {
            /* Any user created path likely does not have a default label,
             * which makes this an expected non error
             */
            VIR_WARN("cannot lookup default selinux label for %s", newpath);
            ret = 0;
            goto cleanup;
        }
    }

    if (virSecuritySELinuxSetFileconImpl(newpath, fcon, privileged) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    freecon(fcon);
    VIR_FREE(newpath);
    return ret;
}


static int
virSecuritySELinuxSetInputLabel(virSecurityManagerPtr mgr,
                                virDomainDefPtr def,
                                virDomainInputDefPtr input)
{
    virSecurityLabelDefPtr seclabel;

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (seclabel == NULL)
        return 0;

    switch ((virDomainInputType)input->type) {
    case VIR_DOMAIN_INPUT_TYPE_PASSTHROUGH:
        if (virSecuritySELinuxSetFilecon(mgr, input->source.evdev,
                                         seclabel->imagelabel, true) < 0)
            return -1;
        break;

    case VIR_DOMAIN_INPUT_TYPE_MOUSE:
    case VIR_DOMAIN_INPUT_TYPE_TABLET:
    case VIR_DOMAIN_INPUT_TYPE_KBD:
    case VIR_DOMAIN_INPUT_TYPE_LAST:
        break;
    }

    return 0;
}


static int
virSecuritySELinuxRestoreInputLabel(virSecurityManagerPtr mgr,
                                    virDomainDefPtr def,
                                    virDomainInputDefPtr input)
{
    int rc = 0;
    virSecurityLabelDefPtr seclabel;

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (seclabel == NULL)
        return 0;

    switch ((virDomainInputType)input->type) {
    case VIR_DOMAIN_INPUT_TYPE_PASSTHROUGH:
        rc = virSecuritySELinuxRestoreFileLabel(mgr, input->source.evdev, true);
        break;

    case VIR_DOMAIN_INPUT_TYPE_MOUSE:
    case VIR_DOMAIN_INPUT_TYPE_TABLET:
    case VIR_DOMAIN_INPUT_TYPE_KBD:
    case VIR_DOMAIN_INPUT_TYPE_LAST:
        break;
    }

    return rc;
}


static int
virSecuritySELinuxSetMemoryLabel(virSecurityManagerPtr mgr,
                                 virDomainDefPtr def,
                                 virDomainMemoryDefPtr mem)
{
    virSecurityLabelDefPtr seclabel;

    switch ((virDomainMemoryModel) mem->model) {
    case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
        seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
        if (!seclabel || !seclabel->relabel)
            return 0;

        if (virSecuritySELinuxSetFilecon(mgr, mem->nvdimmPath,
                                         seclabel->imagelabel, true) < 0)
            return -1;
        break;

    case VIR_DOMAIN_MEMORY_MODEL_NONE:
    case VIR_DOMAIN_MEMORY_MODEL_DIMM:
    case VIR_DOMAIN_MEMORY_MODEL_LAST:
        break;
    }

    return 0;
}


static int
virSecuritySELinuxRestoreMemoryLabel(virSecurityManagerPtr mgr,
                                     virDomainDefPtr def,
                                     virDomainMemoryDefPtr mem)
{
    int ret = -1;
    virSecurityLabelDefPtr seclabel;

    switch ((virDomainMemoryModel) mem->model) {
    case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
        seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
        if (!seclabel || !seclabel->relabel)
            return 0;

        ret = virSecuritySELinuxRestoreFileLabel(mgr, mem->nvdimmPath, true);
        break;

    case VIR_DOMAIN_MEMORY_MODEL_DIMM:
    case VIR_DOMAIN_MEMORY_MODEL_NONE:
    case VIR_DOMAIN_MEMORY_MODEL_LAST:
        ret = 0;
        break;
    }

    return ret;
}


static int
virSecuritySELinuxSetTPMFileLabel(virSecurityManagerPtr mgr,
                                  virDomainDefPtr def,
                                  virDomainTPMDefPtr tpm)
{
    int rc;
    virSecurityLabelDefPtr seclabel;
    char *cancel_path;
    const char *tpmdev;

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (seclabel == NULL)
        return 0;

    switch (tpm->type) {
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
        tpmdev = tpm->data.passthrough.source.data.file.path;
        rc = virSecuritySELinuxSetFilecon(mgr, tpmdev, seclabel->imagelabel, false);
        if (rc < 0)
            return -1;

        if ((cancel_path = virTPMCreateCancelPath(tpmdev)) != NULL) {
            rc = virSecuritySELinuxSetFilecon(mgr,
                                              cancel_path,
                                              seclabel->imagelabel, false);
            VIR_FREE(cancel_path);
            if (rc < 0) {
                virSecuritySELinuxRestoreTPMFileLabelInt(mgr, def, tpm);
                return -1;
            }
        } else {
            return -1;
        }
        break;
    case VIR_DOMAIN_TPM_TYPE_EMULATOR:
        tpmdev = tpm->data.emulator.source.data.nix.path;
        rc = virSecuritySELinuxSetFilecon(mgr, tpmdev, seclabel->imagelabel, false);
        if (rc < 0)
            return -1;
        break;
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }

    return 0;
}


static int
virSecuritySELinuxRestoreTPMFileLabelInt(virSecurityManagerPtr mgr,
                                         virDomainDefPtr def,
                                         virDomainTPMDefPtr tpm)
{
    int rc = 0;
    virSecurityLabelDefPtr seclabel;
    char *cancel_path;
    const char *tpmdev;

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (seclabel == NULL)
        return 0;

    switch (tpm->type) {
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
        tpmdev = tpm->data.passthrough.source.data.file.path;
        rc = virSecuritySELinuxRestoreFileLabel(mgr, tpmdev, false);

        if ((cancel_path = virTPMCreateCancelPath(tpmdev)) != NULL) {
            if (virSecuritySELinuxRestoreFileLabel(mgr, cancel_path, false) < 0)
                rc = -1;
            VIR_FREE(cancel_path);
        }
        break;
    case VIR_DOMAIN_TPM_TYPE_EMULATOR:
        /* swtpm will have removed the Unix socket upon termination */
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }

    return rc;
}


static int
virSecuritySELinuxRestoreImageLabelSingle(virSecurityManagerPtr mgr,
                                          virDomainDefPtr def,
                                          virStorageSourcePtr src,
                                          bool migrated)
{
    virSecurityLabelDefPtr seclabel;
    virSecurityDeviceLabelDefPtr disk_seclabel;
    g_autofree char *vfioGroupDev = NULL;
    const char *path = src->path;

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (seclabel == NULL)
        return 0;

    disk_seclabel = virStorageSourceGetSecurityLabelDef(src,
                                                        SECURITY_SELINUX_NAME);
    if (!seclabel->relabel || (disk_seclabel && !disk_seclabel->relabel))
        return 0;

    /* If labelskip is true and there are no backing files, then we
     * know it is safe to skip the restore.  FIXME - backing files should
     * be tracked in domain XML, at which point labelskip should be a
     * per-file attribute instead of a disk attribute. */
    if (disk_seclabel && disk_seclabel->labelskip &&
        !virStorageSourceHasBacking(src))
        return 0;

    /* Don't restore labels on readonly/shared disks, because other VMs may
     * still be accessing these. Alternatively we could iterate over all
     * running domains and try to figure out if it is in use, but this would
     * not work for clustered filesystems, since we can't see running VMs using
     * the file on other nodes. Safest bet is thus to skip the restore step. */
    if (src->readonly || src->shared)
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

        if (!(vfioGroupDev = virPCIDeviceAddressGetIOMMUGroupDev(&nvme->pciAddr)))
            return -1;

        /* Ideally, we would check if there is not another PCI
         * device within domain def that is in the same IOMMU
         * group. But we're not doing that for hostdevs yet. */
        path = vfioGroupDev;
    }

    return virSecuritySELinuxRestoreFileLabel(mgr, path, true);
}


static int
virSecuritySELinuxRestoreImageLabelInt(virSecurityManagerPtr mgr,
                                       virDomainDefPtr def,
                                       virStorageSourcePtr src,
                                       bool migrated)
{
    if (virSecuritySELinuxRestoreImageLabelSingle(mgr, def, src, migrated) < 0)
        return -1;

    if (src->externalDataStore &&
        virSecuritySELinuxRestoreImageLabelSingle(mgr,
                                                  def,
                                                  src->externalDataStore,
                                                  migrated) < 0)
        return -1;

    return 0;
}


static int
virSecuritySELinuxRestoreImageLabel(virSecurityManagerPtr mgr,
                                    virDomainDefPtr def,
                                    virStorageSourcePtr src,
                                    virSecurityDomainImageLabelFlags flags G_GNUC_UNUSED)
{
    return virSecuritySELinuxRestoreImageLabelInt(mgr, def, src, false);
}


static int
virSecuritySELinuxSetImageLabelInternal(virSecurityManagerPtr mgr,
                                        virDomainDefPtr def,
                                        virStorageSourcePtr src,
                                        virStorageSourcePtr parent,
                                        bool isChainTop)
{
    virSecuritySELinuxDataPtr data = virSecurityManagerGetPrivateData(mgr);
    virSecurityLabelDefPtr secdef;
    virSecurityDeviceLabelDefPtr disk_seclabel;
    virSecurityDeviceLabelDefPtr parent_seclabel = NULL;
    char *use_label = NULL;
    bool remember;
    g_autofree char *vfioGroupDev = NULL;
    const char *path = src->path;
    int ret;

    if (!src->path || !virStorageSourceIsLocalStorage(src))
        return 0;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (!secdef || !secdef->relabel)
        return 0;

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

    disk_seclabel = virStorageSourceGetSecurityLabelDef(src,
                                                        SECURITY_SELINUX_NAME);
    parent_seclabel = virStorageSourceGetSecurityLabelDef(parent,
                                                          SECURITY_SELINUX_NAME);

    if (disk_seclabel && (!disk_seclabel->relabel || disk_seclabel->label)) {
        if (!disk_seclabel->relabel)
            return 0;

        use_label = disk_seclabel->label;
    } else if (parent_seclabel && (!parent_seclabel->relabel || parent_seclabel->label)) {
        if (!parent_seclabel->relabel)
            return 0;

        use_label = parent_seclabel->label;
    } else if (parent == src || parent->externalDataStore == src) {
        if (src->shared) {
            use_label = data->file_context;
        } else if (src->readonly) {
            use_label = data->content_context;
        } else if (secdef->imagelabel) {
            use_label = secdef->imagelabel;
        } else {
            return 0;
        }
    } else {
        use_label = data->content_context;
    }

    /* This is not very clean. But so far we don't have NVMe
     * storage pool backend so that its chownCallback would be
     * called. And this place looks least offensive. */
    if (src->type == VIR_STORAGE_TYPE_NVME) {
        const virStorageSourceNVMeDef *nvme = src->nvme;

        if (!(vfioGroupDev = virPCIDeviceAddressGetIOMMUGroupDev(&nvme->pciAddr)))
            return -1;

        path = vfioGroupDev;
    }

    ret = virSecuritySELinuxSetFilecon(mgr, path, use_label, remember);

    if (ret == 1 && !disk_seclabel) {
        /* If we failed to set a label, but virt_use_nfs let us
         * proceed anyway, then we don't need to relabel later.  */
        disk_seclabel = virSecurityDeviceLabelDefNew(SECURITY_SELINUX_NAME);
        if (!disk_seclabel)
            return -1;
        disk_seclabel->labelskip = true;
        if (VIR_APPEND_ELEMENT(src->seclabels, src->nseclabels,
                               disk_seclabel) < 0) {
            virSecurityDeviceLabelDefFree(disk_seclabel);
            return -1;
        }
        ret = 0;
    }

    return ret;
}


static int
virSecuritySELinuxSetImageLabelRelative(virSecurityManagerPtr mgr,
                                        virDomainDefPtr def,
                                        virStorageSourcePtr src,
                                        virStorageSourcePtr parent,
                                        virSecurityDomainImageLabelFlags flags)
{
    virStorageSourcePtr n;

    for (n = src; virStorageSourceIsBacking(n); n = n->backingStore) {
        const bool isChainTop = flags & VIR_SECURITY_DOMAIN_IMAGE_PARENT_CHAIN_TOP;

        if (virSecuritySELinuxSetImageLabelInternal(mgr, def, n, parent, isChainTop) < 0)
            return -1;

        if (n->externalDataStore &&
            virSecuritySELinuxSetImageLabelRelative(mgr,
                                                    def,
                                                    n->externalDataStore,
                                                    parent,
                                                    flags) < 0)
            return -1;

        if (!(flags & VIR_SECURITY_DOMAIN_IMAGE_LABEL_BACKING_CHAIN))
            break;

        flags &= ~VIR_SECURITY_DOMAIN_IMAGE_PARENT_CHAIN_TOP;
    }

    return 0;
}


static int
virSecuritySELinuxSetImageLabel(virSecurityManagerPtr mgr,
                                virDomainDefPtr def,
                                virStorageSourcePtr src,
                                virSecurityDomainImageLabelFlags flags)
{
    return virSecuritySELinuxSetImageLabelRelative(mgr, def, src, src, flags);
}

struct virSecuritySELinuxMoveImageMetadataData {
    virSecurityManagerPtr mgr;
    const char *src;
    const char *dst;
};


static int
virSecuritySELinuxMoveImageMetadataHelper(pid_t pid G_GNUC_UNUSED,
                                          void *opaque)
{
    struct virSecuritySELinuxMoveImageMetadataData *data = opaque;
    const char *paths[2] = { data->src, data->dst };
    virSecurityManagerMetadataLockStatePtr state;
    int ret;

    if (!(state = virSecurityManagerMetadataLock(data->mgr, paths, G_N_ELEMENTS(paths))))
        return -1;

    ret = virSecurityMoveRememberedLabel(SECURITY_SELINUX_NAME, data->src, data->dst);
    virSecurityManagerMetadataUnlock(data->mgr, &state);
    return ret;
}


static int
virSecuritySELinuxMoveImageMetadata(virSecurityManagerPtr mgr,
                                    pid_t pid,
                                    virStorageSourcePtr src,
                                    virStorageSourcePtr dst)
{
    struct virSecuritySELinuxMoveImageMetadataData data = { .mgr = mgr, 0 };
    int rc;

    if (src && virStorageSourceIsLocalStorage(src))
        data.src = src->path;

    if (dst && virStorageSourceIsLocalStorage(dst))
        data.dst = dst->path;

    if (!data.src)
        return 0;

    if (pid == -1) {
        rc = virProcessRunInFork(virSecuritySELinuxMoveImageMetadataHelper,
                                 &data);
    } else {
        rc = virProcessRunInMountNamespace(pid,
                                           virSecuritySELinuxMoveImageMetadataHelper,
                                           &data);
    }

    return rc;
}


static int
virSecuritySELinuxSetHostdevLabelHelper(const char *file,
                                        bool remember,
                                        void *opaque)
{
    virSecurityLabelDefPtr secdef;
    virSecuritySELinuxCallbackDataPtr data = opaque;
    virSecurityManagerPtr mgr = data->mgr;
    virDomainDefPtr def = data->def;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (secdef == NULL)
        return 0;
    return virSecuritySELinuxSetFilecon(mgr, file, secdef->imagelabel, remember);
}

static int
virSecuritySELinuxSetPCILabel(virPCIDevicePtr dev G_GNUC_UNUSED,
                              const char *file, void *opaque)
{
    return virSecuritySELinuxSetHostdevLabelHelper(file, true, opaque);
}

static int
virSecuritySELinuxSetUSBLabel(virUSBDevicePtr dev G_GNUC_UNUSED,
                              const char *file, void *opaque)
{
    return virSecuritySELinuxSetHostdevLabelHelper(file, true, opaque);
}

static int
virSecuritySELinuxSetSCSILabel(virSCSIDevicePtr dev,
                               const char *file, void *opaque)
{
    virSecurityLabelDefPtr secdef;
    virSecuritySELinuxCallbackDataPtr ptr = opaque;
    virSecurityManagerPtr mgr = ptr->mgr;
    virSecuritySELinuxDataPtr data = virSecurityManagerGetPrivateData(mgr);

    secdef = virDomainDefGetSecurityLabelDef(ptr->def, SECURITY_SELINUX_NAME);
    if (secdef == NULL)
        return 0;

    if (virSCSIDeviceGetShareable(dev))
        return virSecuritySELinuxSetFilecon(mgr, file,
                                            data->file_context, true);
    else if (virSCSIDeviceGetReadonly(dev))
        return virSecuritySELinuxSetFilecon(mgr, file,
                                            data->content_context, true);
    else
        return virSecuritySELinuxSetFilecon(mgr, file,
                                            secdef->imagelabel, true);
}

static int
virSecuritySELinuxSetHostLabel(virSCSIVHostDevicePtr dev G_GNUC_UNUSED,
                               const char *file, void *opaque)
{
    return virSecuritySELinuxSetHostdevLabelHelper(file, true, opaque);
}


static int
virSecuritySELinuxSetHostdevSubsysLabel(virSecurityManagerPtr mgr,
                                        virDomainDefPtr def,
                                        virDomainHostdevDefPtr dev,
                                        const char *vroot)

{
    virDomainHostdevSubsysUSBPtr usbsrc = &dev->source.subsys.u.usb;
    virDomainHostdevSubsysPCIPtr pcisrc = &dev->source.subsys.u.pci;
    virDomainHostdevSubsysSCSIPtr scsisrc = &dev->source.subsys.u.scsi;
    virDomainHostdevSubsysSCSIVHostPtr hostsrc = &dev->source.subsys.u.scsi_host;
    virDomainHostdevSubsysMediatedDevPtr mdevsrc = &dev->source.subsys.u.mdev;
    virSecuritySELinuxCallbackData data = {.mgr = mgr, .def = def};

    int ret = -1;

    /* Like virSecuritySELinuxSetImageLabelInternal() for a networked
     * disk, do nothing for an iSCSI hostdev
     */
    if (dev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI &&
        scsisrc->protocol == VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI)
        return 0;

    switch ((virDomainHostdevSubsysType)dev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB: {
        virUSBDevicePtr usb;

        if (dev->missing)
            return 0;

        usb = virUSBDeviceNew(usbsrc->bus,
                              usbsrc->device,
                              vroot);
        if (!usb)
            return -1;

        ret = virUSBDeviceFileIterate(usb, virSecuritySELinuxSetUSBLabel, &data);
        virUSBDeviceFree(usb);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI: {
        virPCIDevicePtr pci =
            virPCIDeviceNew(pcisrc->addr.domain, pcisrc->addr.bus,
                            pcisrc->addr.slot, pcisrc->addr.function);

        if (!pci)
            return -1;

        if (pcisrc->backend == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO) {
            char *vfioGroupDev = virPCIDeviceGetIOMMUGroupDev(pci);

            if (!vfioGroupDev) {
                virPCIDeviceFree(pci);
                return -1;
            }
            ret = virSecuritySELinuxSetHostdevLabelHelper(vfioGroupDev,
                                                          false,
                                                          &data);
            VIR_FREE(vfioGroupDev);
        } else {
            ret = virPCIDeviceFileIterate(pci, virSecuritySELinuxSetPCILabel, &data);
        }
        virPCIDeviceFree(pci);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI: {
        virDomainHostdevSubsysSCSIHostPtr scsihostsrc = &scsisrc->u.host;

        virSCSIDevicePtr scsi =
            virSCSIDeviceNew(NULL,
                             scsihostsrc->adapter, scsihostsrc->bus,
                             scsihostsrc->target, scsihostsrc->unit,
                             dev->readonly, dev->shareable);

        if (!scsi)
            return -1;

        ret = virSCSIDeviceFileIterate(scsi,
                                       virSecuritySELinuxSetSCSILabel,
                                       &data);
        virSCSIDeviceFree(scsi);

        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST: {
        virSCSIVHostDevicePtr host = virSCSIVHostDeviceNew(hostsrc->wwpn);

        if (!host)
            return -1;

        ret = virSCSIVHostDeviceFileIterate(host,
                                            virSecuritySELinuxSetHostLabel,
                                            &data);
        virSCSIVHostDeviceFree(host);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV: {
        char *vfiodev = NULL;

        if (!(vfiodev = virMediatedDeviceGetIOMMUGroupDev(mdevsrc->uuidstr)))
            return ret;

        ret = virSecuritySELinuxSetHostdevLabelHelper(vfiodev, true, &data);

        VIR_FREE(vfiodev);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
        ret = 0;
        break;
    }

    return ret;
}


static int
virSecuritySELinuxSetHostdevCapsLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr def,
                                      virDomainHostdevDefPtr dev,
                                      const char *vroot)
{
    int ret = -1;
    virSecurityLabelDefPtr secdef;
    char *path;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (secdef == NULL)
        return 0;

    switch (dev->source.caps.type) {
    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_STORAGE: {
        if (vroot) {
            path = g_strdup_printf("%s/%s", vroot,
                                   dev->source.caps.u.storage.block);
        } else {
            path = g_strdup(dev->source.caps.u.storage.block);
        }
        ret = virSecuritySELinuxSetFilecon(mgr, path, secdef->imagelabel, true);
        VIR_FREE(path);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_MISC: {
        if (vroot) {
            path = g_strdup_printf("%s/%s", vroot,
                                   dev->source.caps.u.misc.chardev);
        } else {
            path = g_strdup(dev->source.caps.u.misc.chardev);
        }
        ret = virSecuritySELinuxSetFilecon(mgr, path, secdef->imagelabel, true);
        VIR_FREE(path);
        break;
    }

    default:
        ret = 0;
        break;
    }

    return ret;
}


static int
virSecuritySELinuxSetHostdevLabel(virSecurityManagerPtr mgr,
                                  virDomainDefPtr def,
                                  virDomainHostdevDefPtr dev,
                                  const char *vroot)

{
    virSecurityLabelDefPtr secdef;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (!secdef || !secdef->relabel)
        return 0;

    switch (dev->mode) {
    case VIR_DOMAIN_HOSTDEV_MODE_SUBSYS:
        return virSecuritySELinuxSetHostdevSubsysLabel(mgr, def, dev, vroot);

    case VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES:
        return virSecuritySELinuxSetHostdevCapsLabel(mgr, def, dev, vroot);

    default:
        return 0;
    }
}

static int
virSecuritySELinuxRestorePCILabel(virPCIDevicePtr dev G_GNUC_UNUSED,
                                  const char *file,
                                  void *opaque)
{
    virSecurityManagerPtr mgr = opaque;

    return virSecuritySELinuxRestoreFileLabel(mgr, file, true);
}

static int
virSecuritySELinuxRestoreUSBLabel(virUSBDevicePtr dev G_GNUC_UNUSED,
                                  const char *file,
                                  void *opaque)
{
    virSecurityManagerPtr mgr = opaque;

    return virSecuritySELinuxRestoreFileLabel(mgr, file, true);
}


static int
virSecuritySELinuxRestoreSCSILabel(virSCSIDevicePtr dev,
                                   const char *file,
                                   void *opaque)
{
    virSecurityManagerPtr mgr = opaque;

    /* Don't restore labels on a shareable or readonly hostdev, because
     * other VMs may still be accessing.
     */
    if (virSCSIDeviceGetShareable(dev) || virSCSIDeviceGetReadonly(dev))
        return 0;

    return virSecuritySELinuxRestoreFileLabel(mgr, file, true);
}

static int
virSecuritySELinuxRestoreHostLabel(virSCSIVHostDevicePtr dev G_GNUC_UNUSED,
                                   const char *file,
                                   void *opaque)
{
    virSecurityManagerPtr mgr = opaque;

    return virSecuritySELinuxRestoreFileLabel(mgr, file, true);
}


static int
virSecuritySELinuxRestoreHostdevSubsysLabel(virSecurityManagerPtr mgr,
                                            virDomainHostdevDefPtr dev,
                                            const char *vroot)

{
    virDomainHostdevSubsysUSBPtr usbsrc = &dev->source.subsys.u.usb;
    virDomainHostdevSubsysPCIPtr pcisrc = &dev->source.subsys.u.pci;
    virDomainHostdevSubsysSCSIPtr scsisrc = &dev->source.subsys.u.scsi;
    virDomainHostdevSubsysSCSIVHostPtr hostsrc = &dev->source.subsys.u.scsi_host;
    virDomainHostdevSubsysMediatedDevPtr mdevsrc = &dev->source.subsys.u.mdev;
    int ret = -1;

    /* Like virSecuritySELinuxRestoreImageLabelInt() for a networked
     * disk, do nothing for an iSCSI hostdev
     */
    if (dev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI &&
        scsisrc->protocol == VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI)
        return 0;

    switch ((virDomainHostdevSubsysType)dev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB: {
        virUSBDevicePtr usb;

        if (dev->missing)
            return 0;

        usb = virUSBDeviceNew(usbsrc->bus,
                              usbsrc->device,
                              vroot);
        if (!usb)
            return -1;

        ret = virUSBDeviceFileIterate(usb, virSecuritySELinuxRestoreUSBLabel, mgr);
        virUSBDeviceFree(usb);

        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI: {
        virPCIDevicePtr pci =
            virPCIDeviceNew(pcisrc->addr.domain, pcisrc->addr.bus,
                            pcisrc->addr.slot, pcisrc->addr.function);

        if (!pci)
            return -1;

        if (pcisrc->backend == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO) {
            char *vfioGroupDev = virPCIDeviceGetIOMMUGroupDev(pci);

            if (!vfioGroupDev) {
                virPCIDeviceFree(pci);
                return -1;
            }
            ret = virSecuritySELinuxRestoreFileLabel(mgr, vfioGroupDev, false);
            VIR_FREE(vfioGroupDev);
        } else {
            ret = virPCIDeviceFileIterate(pci, virSecuritySELinuxRestorePCILabel, mgr);
        }
        virPCIDeviceFree(pci);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI: {
        virDomainHostdevSubsysSCSIHostPtr scsihostsrc = &scsisrc->u.host;
        virSCSIDevicePtr scsi =
            virSCSIDeviceNew(NULL,
                             scsihostsrc->adapter, scsihostsrc->bus,
                             scsihostsrc->target, scsihostsrc->unit,
                             dev->readonly, dev->shareable);

        if (!scsi)
            return -1;

        ret = virSCSIDeviceFileIterate(scsi, virSecuritySELinuxRestoreSCSILabel, mgr);
        virSCSIDeviceFree(scsi);

        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST: {
        virSCSIVHostDevicePtr host = virSCSIVHostDeviceNew(hostsrc->wwpn);

        if (!host)
            return -1;

        ret = virSCSIVHostDeviceFileIterate(host,
                                            virSecuritySELinuxRestoreHostLabel,
                                            mgr);
        virSCSIVHostDeviceFree(host);

        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV: {
        char *vfiodev = NULL;

        if (!(vfiodev = virMediatedDeviceGetIOMMUGroupDev(mdevsrc->uuidstr)))
            return -1;

        ret = virSecuritySELinuxRestoreFileLabel(mgr, vfiodev, true);

        VIR_FREE(vfiodev);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
        ret = 0;
        break;
    }

    return ret;
}


static int
virSecuritySELinuxRestoreHostdevCapsLabel(virSecurityManagerPtr mgr,
                                          virDomainHostdevDefPtr dev,
                                          const char *vroot)
{
    int ret = -1;
    char *path;

    switch (dev->source.caps.type) {
    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_STORAGE: {
        if (vroot) {
            path = g_strdup_printf("%s/%s", vroot,
                                   dev->source.caps.u.storage.block);
        } else {
            path = g_strdup(dev->source.caps.u.storage.block);
        }
        ret = virSecuritySELinuxRestoreFileLabel(mgr, path, true);
        VIR_FREE(path);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_MISC: {
        if (vroot) {
            path = g_strdup_printf("%s/%s", vroot,
                                   dev->source.caps.u.misc.chardev);
        } else {
            path = g_strdup(dev->source.caps.u.misc.chardev);
        }
        ret = virSecuritySELinuxRestoreFileLabel(mgr, path, true);
        VIR_FREE(path);
        break;
    }

    default:
        ret = 0;
        break;
    }

    return ret;
}


static int
virSecuritySELinuxRestoreHostdevLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr def,
                                      virDomainHostdevDefPtr dev,
                                      const char *vroot)

{
    virSecurityLabelDefPtr secdef;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (!secdef || !secdef->relabel)
        return 0;

    switch (dev->mode) {
    case VIR_DOMAIN_HOSTDEV_MODE_SUBSYS:
        return virSecuritySELinuxRestoreHostdevSubsysLabel(mgr, dev, vroot);

    case VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES:
        return virSecuritySELinuxRestoreHostdevCapsLabel(mgr, dev, vroot);

    default:
        return 0;
    }
}


static int
virSecuritySELinuxSetChardevLabel(virSecurityManagerPtr mgr,
                                  virDomainDefPtr def,
                                  virDomainChrSourceDefPtr dev_source,
                                  bool chardevStdioLogd)

{
    virSecurityLabelDefPtr seclabel;
    virSecurityDeviceLabelDefPtr chr_seclabel = NULL;
    char *imagelabel = NULL;
    char *in = NULL, *out = NULL;
    int ret = -1;

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (!seclabel || !seclabel->relabel)
        return 0;

    chr_seclabel = virDomainChrSourceDefGetSecurityLabelDef(dev_source,
                                                            SECURITY_SELINUX_NAME);

    if (chr_seclabel && !chr_seclabel->relabel)
        return 0;

    if (!chr_seclabel &&
        dev_source->type == VIR_DOMAIN_CHR_TYPE_FILE &&
        chardevStdioLogd)
        return 0;

    if (chr_seclabel)
        imagelabel = chr_seclabel->label;
    if (!imagelabel)
        imagelabel = seclabel->imagelabel;

    switch (dev_source->type) {
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_FILE:
        ret = virSecuritySELinuxSetFilecon(mgr,
                                           dev_source->data.file.path,
                                           imagelabel,
                                           true);
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        if (!dev_source->data.nix.listen) {
            if (virSecuritySELinuxSetFilecon(mgr,
                                             dev_source->data.nix.path,
                                             imagelabel,
                                             true) < 0)
                goto done;
        }
        ret = 0;
        break;

    case VIR_DOMAIN_CHR_TYPE_PIPE:
        in = g_strdup_printf("%s.in", dev_source->data.file.path);
        out = g_strdup_printf("%s.out", dev_source->data.file.path);
        if (virFileExists(in) && virFileExists(out)) {
            if ((virSecuritySELinuxSetFilecon(mgr, in, imagelabel, true) < 0) ||
                (virSecuritySELinuxSetFilecon(mgr, out, imagelabel, true) < 0)) {
                goto done;
            }
        } else if (virSecuritySELinuxSetFilecon(mgr,
                                                dev_source->data.file.path,
                                                imagelabel,
                                                true) < 0) {
            goto done;
        }
        ret = 0;
        break;

    default:
        ret = 0;
        break;
    }

 done:
    VIR_FREE(in);
    VIR_FREE(out);
    return ret;
}

static int
virSecuritySELinuxRestoreChardevLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr def,
                                      virDomainChrSourceDefPtr dev_source,
                                      bool chardevStdioLogd)

{
    virSecurityLabelDefPtr seclabel;
    virSecurityDeviceLabelDefPtr chr_seclabel = NULL;
    char *in = NULL, *out = NULL;
    int ret = -1;

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (!seclabel || !seclabel->relabel)
        return 0;

    chr_seclabel = virDomainChrSourceDefGetSecurityLabelDef(dev_source,
                                                            SECURITY_SELINUX_NAME);
    if (chr_seclabel && !chr_seclabel->relabel)
        return 0;

    if (!chr_seclabel &&
        dev_source->type == VIR_DOMAIN_CHR_TYPE_FILE &&
        chardevStdioLogd)
        return 0;

    switch (dev_source->type) {
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_FILE:
        if (virSecuritySELinuxRestoreFileLabel(mgr,
                                               dev_source->data.file.path,
                                               true) < 0)
            goto done;
        ret = 0;
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        if (!dev_source->data.nix.listen) {
            if (virSecuritySELinuxRestoreFileLabel(mgr,
                                                   dev_source->data.file.path,
                                                   true) < 0)
                goto done;
        }
        ret = 0;
        break;

    case VIR_DOMAIN_CHR_TYPE_PIPE:
        out = g_strdup_printf("%s.out", dev_source->data.file.path);
        in = g_strdup_printf("%s.in", dev_source->data.file.path);
        if (virFileExists(in) && virFileExists(out)) {
            if ((virSecuritySELinuxRestoreFileLabel(mgr, out, true) < 0) ||
                (virSecuritySELinuxRestoreFileLabel(mgr, in, true) < 0)) {
                goto done;
            }
        } else if (virSecuritySELinuxRestoreFileLabel(mgr,
                                                      dev_source->data.file.path,
                                                      true) < 0) {
            goto done;
        }
        ret = 0;
        break;

    default:
        ret = 0;
        break;
    }

 done:
    VIR_FREE(in);
    VIR_FREE(out);
    return ret;
}


struct _virSecuritySELinuxChardevCallbackData {
    virSecurityManagerPtr mgr;
    bool chardevStdioLogd;
};


static int
virSecuritySELinuxRestoreSecurityChardevCallback(virDomainDefPtr def,
                                                 virDomainChrDefPtr dev G_GNUC_UNUSED,
                                                 void *opaque)
{
    struct _virSecuritySELinuxChardevCallbackData *data = opaque;

    return virSecuritySELinuxRestoreChardevLabel(data->mgr, def, dev->source,
                                                 data->chardevStdioLogd);
}


static int
virSecuritySELinuxRestoreSecuritySmartcardCallback(virDomainDefPtr def,
                                                   virDomainSmartcardDefPtr dev,
                                                   void *opaque)
{
    virSecurityManagerPtr mgr = opaque;
    const char *database;

    switch (dev->type) {
    case VIR_DOMAIN_SMARTCARD_TYPE_HOST:
        break;

    case VIR_DOMAIN_SMARTCARD_TYPE_HOST_CERTIFICATES:
        database = dev->data.cert.database;
        if (!database)
            database = VIR_DOMAIN_SMARTCARD_DEFAULT_DATABASE;
        return virSecuritySELinuxRestoreFileLabel(mgr, database, true);

    case VIR_DOMAIN_SMARTCARD_TYPE_PASSTHROUGH:
        return virSecuritySELinuxRestoreChardevLabel(mgr, def,
                                                     dev->data.passthru, false);

    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown smartcard type %d"),
                       dev->type);
        return -1;
    }

    return 0;
}


static const char *
virSecuritySELinuxGetBaseLabel(virSecurityManagerPtr mgr, int virtType)
{
    virSecuritySELinuxDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    if (virtType == VIR_DOMAIN_VIRT_QEMU && priv->alt_domain_context)
        return priv->alt_domain_context;
    else
        return priv->domain_context;
}


static int
virSecuritySELinuxRestoreAllLabel(virSecurityManagerPtr mgr,
                                  virDomainDefPtr def,
                                  bool migrated,
                                  bool chardevStdioLogd)
{
    virSecurityLabelDefPtr secdef;
    virSecuritySELinuxDataPtr data = virSecurityManagerGetPrivateData(mgr);
    size_t i;
    int rc = 0;

    VIR_DEBUG("Restoring security label on %s migrated=%d", def->name, migrated);

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);

    if (!secdef || !secdef->relabel || data->skipAllLabel)
        return 0;

    for (i = 0; i < def->ndisks; i++) {
        virDomainDiskDefPtr disk = def->disks[i];

        if (virSecuritySELinuxRestoreImageLabelInt(mgr, def, disk->src,
                                                   migrated) < 0)
            rc = -1;
    }

    for (i = 0; i < def->nhostdevs; i++) {
        if (virSecuritySELinuxRestoreHostdevLabel(mgr,
                                                  def,
                                                  def->hostdevs[i],
                                                  NULL) < 0)
            rc = -1;
    }

    for (i = 0; i < def->ninputs; i++) {
        if (virSecuritySELinuxRestoreInputLabel(mgr, def, def->inputs[i]) < 0)
            rc = -1;
    }

    for (i = 0; i < def->nmems; i++) {
        if (virSecuritySELinuxRestoreMemoryLabel(mgr, def, def->mems[i]) < 0)
            return -1;
    }

    if (def->tpm) {
        if (virSecuritySELinuxRestoreTPMFileLabelInt(mgr, def, def->tpm) < 0)
            rc = -1;
    }

    struct _virSecuritySELinuxChardevCallbackData chardevData = {
        .mgr = mgr,
        .chardevStdioLogd = chardevStdioLogd
    };

    if (virDomainChrDefForeach(def,
                               false,
                               virSecuritySELinuxRestoreSecurityChardevCallback,
                               &chardevData) < 0)
        rc = -1;

    if (virDomainSmartcardDefForeach(def,
                                     false,
                                     virSecuritySELinuxRestoreSecuritySmartcardCallback,
                                     mgr) < 0)
        rc = -1;

    if (def->os.loader && def->os.loader->nvram &&
        virSecuritySELinuxRestoreFileLabel(mgr, def->os.loader->nvram, true) < 0)
        rc = -1;

    if (def->os.kernel &&
        virSecuritySELinuxRestoreFileLabel(mgr, def->os.kernel, true) < 0)
        rc = -1;

    if (def->os.initrd &&
        virSecuritySELinuxRestoreFileLabel(mgr, def->os.initrd, true) < 0)
        rc = -1;

    if (def->os.dtb &&
        virSecuritySELinuxRestoreFileLabel(mgr, def->os.dtb, true) < 0)
        rc = -1;

    if (def->os.slic_table &&
        virSecuritySELinuxRestoreFileLabel(mgr, def->os.slic_table, true) < 0)
        rc = -1;

    return rc;
}

static int
virSecuritySELinuxReleaseLabel(virSecurityManagerPtr mgr,
                               virDomainDefPtr def)
{
    virSecurityLabelDefPtr secdef;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (secdef == NULL)
        return 0;

    if (secdef->type == VIR_DOMAIN_SECLABEL_DYNAMIC) {
        if (secdef->label != NULL) {
            context_t con = context_new(secdef->label);
            if (con) {
                virSecuritySELinuxMCSRemove(mgr, context_range_get(con));
                context_free(con);
            }
        }
        VIR_FREE(secdef->label);
        if (!secdef->baselabel)
            VIR_FREE(secdef->model);
    }
    VIR_FREE(secdef->imagelabel);

    return 0;
}


static int
virSecuritySELinuxSetSavedStateLabel(virSecurityManagerPtr mgr,
                                     virDomainDefPtr def,
                                     const char *savefile)
{
    virSecurityLabelDefPtr secdef;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (!secdef || !secdef->relabel)
        return 0;

    return virSecuritySELinuxSetFilecon(mgr, savefile, secdef->imagelabel, true);
}


static int
virSecuritySELinuxRestoreSavedStateLabel(virSecurityManagerPtr mgr,
                                         virDomainDefPtr def,
                                         const char *savefile)
{
    virSecurityLabelDefPtr secdef;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (!secdef || !secdef->relabel)
        return 0;

    return virSecuritySELinuxRestoreFileLabel(mgr, savefile, true);
}


static int
virSecuritySELinuxVerify(virSecurityManagerPtr mgr G_GNUC_UNUSED,
                         virDomainDefPtr def)
{
    virSecurityLabelDefPtr secdef;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (secdef == NULL)
        return 0;

    if (STRNEQ(SECURITY_SELINUX_NAME, secdef->model)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security label driver mismatch: "
                         "'%s' model configured for domain, but "
                         "hypervisor driver is '%s'."),
                       secdef->model, SECURITY_SELINUX_NAME);
        return -1;
    }

    if (secdef->type == VIR_DOMAIN_SECLABEL_STATIC) {
        if (security_check_context(secdef->label) != 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid security label %s"), secdef->label);
            return -1;
        }
    }
    return 0;
}

static int
virSecuritySELinuxSetProcessLabel(virSecurityManagerPtr mgr G_GNUC_UNUSED,
                                  virDomainDefPtr def)
{
    /* TODO: verify DOI */
    virSecurityLabelDefPtr secdef;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (!secdef || !secdef->label)
        return 0;

    VIR_DEBUG("label=%s", secdef->label);
    if (STRNEQ(SECURITY_SELINUX_NAME, secdef->model)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security label driver mismatch: "
                         "'%s' model configured for domain, but "
                         "hypervisor driver is '%s'."),
                       secdef->model, SECURITY_SELINUX_NAME);
        if (security_getenforce() == 1)
            return -1;
    }

    if (setexeccon_raw(secdef->label) == -1) {
        virReportSystemError(errno,
                             _("unable to set security context '%s'"),
                             secdef->label);
        if (security_getenforce() == 1)
            return -1;
    }

    return 0;
}

static int
virSecuritySELinuxSetChildProcessLabel(virSecurityManagerPtr mgr G_GNUC_UNUSED,
                                       virDomainDefPtr def,
                                       virCommandPtr cmd)
{
    /* TODO: verify DOI */
    virSecurityLabelDefPtr secdef;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (!secdef || !secdef->label)
        return 0;

    VIR_DEBUG("label=%s", secdef->label);
    if (STRNEQ(SECURITY_SELINUX_NAME, secdef->model)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security label driver mismatch: "
                         "'%s' model configured for domain, but "
                         "hypervisor driver is '%s'."),
                       secdef->model, SECURITY_SELINUX_NAME);
        if (security_getenforce() == 1)
            return -1;
    }

    /* save in cmd to be set after fork/before child process is exec'ed */
    virCommandSetSELinuxLabel(cmd, secdef->label);
    return 0;
}

static int
virSecuritySELinuxSetDaemonSocketLabel(virSecurityManagerPtr mgr G_GNUC_UNUSED,
                                       virDomainDefPtr def)
{
    /* TODO: verify DOI */
    virSecurityLabelDefPtr secdef;
    security_context_t scon = NULL;
    char *str = NULL;
    int rc = -1;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (!secdef || !secdef->label)
        return 0;

    if (STRNEQ(SECURITY_SELINUX_NAME, secdef->model)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security label driver mismatch: "
                         "'%s' model configured for domain, but "
                         "hypervisor driver is '%s'."),
                       secdef->model, SECURITY_SELINUX_NAME);
        goto done;
    }

    if (getcon_raw(&scon) == -1) {
        virReportSystemError(errno,
                             _("unable to get current process context '%s'"),
                             secdef->label);
        goto done;
    }

    if (!(str = virSecuritySELinuxContextAddRange(secdef->label, scon)))
        goto done;

    VIR_DEBUG("Setting VM %s socket context %s", def->name, str);
    if (setsockcreatecon_raw(str) == -1) {
        virReportSystemError(errno,
                             _("unable to set socket security context '%s'"), str);
        goto done;
    }

    rc = 0;
 done:

    if (security_getenforce() != 1)
        rc = 0;
    freecon(scon);
    VIR_FREE(str);
    return rc;
}

static int
virSecuritySELinuxSetSocketLabel(virSecurityManagerPtr mgr G_GNUC_UNUSED,
                                 virDomainDefPtr vm)
{
    virSecurityLabelDefPtr secdef;
    int rc = -1;

    secdef = virDomainDefGetSecurityLabelDef(vm, SECURITY_SELINUX_NAME);
    if (!secdef || !secdef->label)
        return 0;

    if (STRNEQ(SECURITY_SELINUX_NAME, secdef->model)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security label driver mismatch: "
                         "'%s' model configured for domain, but "
                         "hypervisor driver is '%s'."),
                       secdef->model, SECURITY_SELINUX_NAME);
        goto done;
    }

    VIR_DEBUG("Setting VM %s socket context %s",
              vm->name, secdef->label);
    if (setsockcreatecon_raw(secdef->label) == -1) {
        virReportSystemError(errno,
                             _("unable to set socket security context '%s'"),
                             secdef->label);
        goto done;
    }

    rc = 0;

 done:
    if (security_getenforce() != 1)
        rc = 0;

    return rc;
}

static int
virSecuritySELinuxClearSocketLabel(virSecurityManagerPtr mgr G_GNUC_UNUSED,
                                   virDomainDefPtr def)
{
    /* TODO: verify DOI */
    virSecurityLabelDefPtr secdef;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (!secdef || !secdef->label)
        return 0;

    if (STRNEQ(SECURITY_SELINUX_NAME, secdef->model)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security label driver mismatch: "
                         "'%s' model configured for domain, but "
                         "hypervisor driver is '%s'."),
                       secdef->model, SECURITY_SELINUX_NAME);
        if (security_getenforce() == 1)
            return -1;
    }

    if (setsockcreatecon_raw(NULL) == -1) {
        virReportSystemError(errno,
                             _("unable to clear socket security context '%s'"),
                             secdef->label);
        if (security_getenforce() == 1)
            return -1;
    }
    return 0;
}


static int
virSecuritySELinuxSetSecurityChardevCallback(virDomainDefPtr def,
                                             virDomainChrDefPtr dev G_GNUC_UNUSED,
                                             void *opaque)
{
    struct _virSecuritySELinuxChardevCallbackData *data = opaque;

    return virSecuritySELinuxSetChardevLabel(data->mgr, def, dev->source,
                                             data->chardevStdioLogd);
}


static int
virSecuritySELinuxSetSecuritySmartcardCallback(virDomainDefPtr def,
                                               virDomainSmartcardDefPtr dev,
                                               void *opaque)
{
    const char *database;
    virSecurityManagerPtr mgr = opaque;
    virSecuritySELinuxDataPtr data = virSecurityManagerGetPrivateData(mgr);

    switch (dev->type) {
    case VIR_DOMAIN_SMARTCARD_TYPE_HOST:
        break;

    case VIR_DOMAIN_SMARTCARD_TYPE_HOST_CERTIFICATES:
        database = dev->data.cert.database;
        if (!database)
            database = VIR_DOMAIN_SMARTCARD_DEFAULT_DATABASE;
        return virSecuritySELinuxSetFilecon(mgr, database, data->content_context, true);

    case VIR_DOMAIN_SMARTCARD_TYPE_PASSTHROUGH:
        return virSecuritySELinuxSetChardevLabel(mgr, def,
                                                 dev->data.passthru, false);

    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown smartcard type %d"),
                       dev->type);
        return -1;
    }

    return 0;
}


static int
virSecuritySELinuxSetAllLabel(virSecurityManagerPtr mgr,
                              virDomainDefPtr def,
                              const char *stdin_path,
                              bool chardevStdioLogd,
                              bool migrated G_GNUC_UNUSED)
{
    size_t i;
    virSecuritySELinuxDataPtr data = virSecurityManagerGetPrivateData(mgr);
    virSecurityLabelDefPtr secdef;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);

    if (!secdef || !secdef->relabel || data->skipAllLabel)
        return 0;

    for (i = 0; i < def->ndisks; i++) {
        /* XXX fixme - we need to recursively label the entire tree :-( */
        if (virDomainDiskGetType(def->disks[i]) == VIR_STORAGE_TYPE_DIR) {
            VIR_WARN("Unable to relabel directory tree %s for disk %s",
                     virDomainDiskGetSource(def->disks[i]),
                     def->disks[i]->dst);
            continue;
        }
        if (virSecuritySELinuxSetImageLabel(mgr, def, def->disks[i]->src,
                                            VIR_SECURITY_DOMAIN_IMAGE_LABEL_BACKING_CHAIN |
                                            VIR_SECURITY_DOMAIN_IMAGE_PARENT_CHAIN_TOP) < 0)
            return -1;
    }
    /* XXX fixme process  def->fss if relabel == true */

    for (i = 0; i < def->nhostdevs; i++) {
        if (virSecuritySELinuxSetHostdevLabel(mgr,
                                              def,
                                              def->hostdevs[i],
                                              NULL) < 0)
            return -1;
    }

    for (i = 0; i < def->ninputs; i++) {
        if (virSecuritySELinuxSetInputLabel(mgr, def, def->inputs[i]) < 0)
            return -1;
    }

    for (i = 0; i < def->nmems; i++) {
        if (virSecuritySELinuxSetMemoryLabel(mgr, def, def->mems[i]) < 0)
            return -1;
    }

    if (def->tpm) {
        if (virSecuritySELinuxSetTPMFileLabel(mgr, def, def->tpm) < 0)
            return -1;
    }

    struct _virSecuritySELinuxChardevCallbackData chardevData = {
        .mgr = mgr,
        .chardevStdioLogd = chardevStdioLogd
    };

    if (virDomainChrDefForeach(def,
                               true,
                               virSecuritySELinuxSetSecurityChardevCallback,
                               &chardevData) < 0)
        return -1;

    if (virDomainSmartcardDefForeach(def,
                                     true,
                                     virSecuritySELinuxSetSecuritySmartcardCallback,
                                     mgr) < 0)
        return -1;

    /* This is different than kernel or initrd. The nvram store
     * is really a disk, qemu can read and write to it. */
    if (def->os.loader && def->os.loader->nvram &&
        secdef && secdef->imagelabel &&
        virSecuritySELinuxSetFilecon(mgr, def->os.loader->nvram,
                                     secdef->imagelabel, true) < 0)
        return -1;

    if (def->os.kernel &&
        virSecuritySELinuxSetFilecon(mgr, def->os.kernel,
                                     data->content_context, true) < 0)
        return -1;

    if (def->os.initrd &&
        virSecuritySELinuxSetFilecon(mgr, def->os.initrd,
                                     data->content_context, true) < 0)
        return -1;

    if (def->os.dtb &&
        virSecuritySELinuxSetFilecon(mgr, def->os.dtb,
                                     data->content_context, true) < 0)
        return -1;

    if (def->os.slic_table &&
        virSecuritySELinuxSetFilecon(mgr, def->os.slic_table,
                                     data->content_context, true) < 0)
        return -1;

    if (stdin_path &&
        virSecuritySELinuxSetFilecon(mgr, stdin_path,
                                     data->content_context, true) < 0)
        return -1;

    return 0;
}

static int
virSecuritySELinuxSetImageFDLabel(virSecurityManagerPtr mgr G_GNUC_UNUSED,
                                  virDomainDefPtr def,
                                  int fd)
{
    virSecurityLabelDefPtr secdef;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (!secdef || !secdef->imagelabel)
        return 0;

    return virSecuritySELinuxFSetFilecon(fd, secdef->imagelabel);
}

static int
virSecuritySELinuxSetTapFDLabel(virSecurityManagerPtr mgr,
                                virDomainDefPtr def,
                                int fd)
{
    struct stat buf;
    security_context_t fcon = NULL;
    virSecurityLabelDefPtr secdef;
    char *str = NULL, *proc = NULL, *fd_path = NULL;
    int rc = -1;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (!secdef || !secdef->label)
        return 0;

    if (fstat(fd, &buf) < 0) {
        virReportSystemError(errno, _("cannot stat tap fd %d"), fd);
        goto cleanup;
    }

    if ((buf.st_mode & S_IFMT) != S_IFCHR) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("tap fd %d is not character device"), fd);
        goto cleanup;
    }

    /* Label /dev/tap([0-9]+)? devices only. Leave /dev/net/tun alone! */
    proc = g_strdup_printf("/proc/self/fd/%d", fd);

    if (virFileResolveLink(proc, &fd_path) < 0) {
        virReportSystemError(errno,
                             _("Unable to resolve link: %s"), proc);
        goto cleanup;
    }

    if (!STRPREFIX(fd_path, "/dev/tap")) {
        VIR_DEBUG("fd=%d points to %s not setting SELinux label",
                  fd, fd_path);
        rc = 0;
        goto cleanup;
    }

    if (getContext(mgr, fd_path, buf.st_mode, &fcon) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot lookup default selinux label for tap fd %d"), fd);
        goto cleanup;
    }

    if (!(str = virSecuritySELinuxContextAddRange(secdef->label, fcon))) {
        goto cleanup;
    } else {
        rc = virSecuritySELinuxFSetFilecon(fd, str);
    }

 cleanup:
    freecon(fcon);
    VIR_FREE(fd_path);
    VIR_FREE(proc);
    VIR_FREE(str);
    return rc;
}

static char *
virSecuritySELinuxGenImageLabel(virSecurityManagerPtr mgr,
                                virDomainDefPtr def)
{
    virSecurityLabelDefPtr secdef;
    virSecuritySELinuxDataPtr data = virSecurityManagerGetPrivateData(mgr);
    const char *range;
    context_t ctx = NULL;
    char *label = NULL;
    char *mcs = NULL;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (secdef == NULL)
        goto cleanup;

    if (secdef->label) {
        ctx = context_new(secdef->label);
        if (!ctx) {
            virReportSystemError(errno, _("unable to create selinux context for: %s"),
                                 secdef->label);
            goto cleanup;
        }
        range = context_range_get(ctx);
        if (range) {
            mcs = g_strdup(range);
            if (!(label = virSecuritySELinuxGenNewContext(data->file_context,
                                                          mcs, true)))
                goto cleanup;
        }
    }

 cleanup:
    context_free(ctx);
    VIR_FREE(mcs);
    return label;
}

static char *
virSecuritySELinuxGetSecurityMountOptions(virSecurityManagerPtr mgr,
                                          virDomainDefPtr def)
{
    char *opts = NULL;
    virSecurityLabelDefPtr secdef;

    if ((secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME))) {
        if (!secdef->imagelabel)
            secdef->imagelabel = virSecuritySELinuxGenImageLabel(mgr, def);

        if (secdef->imagelabel) {
            opts = g_strdup_printf(
                                   ",context=\"%s\"",
                                   (const char*) secdef->imagelabel);
        }
    }

    if (!opts)
        opts = g_strdup("");

    VIR_DEBUG("imageLabel=%s opts=%s",
              secdef ? secdef->imagelabel : "(null)", opts);
    return opts;
}

static int
virSecuritySELinuxDomainSetPathLabel(virSecurityManagerPtr mgr,
                                     virDomainDefPtr def,
                                     const char *path,
                                     bool allowSubtree G_GNUC_UNUSED)
{
    virSecurityLabelDefPtr seclabel;

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (!seclabel || !seclabel->relabel)
        return 0;

    return virSecuritySELinuxSetFilecon(mgr, path, seclabel->imagelabel, true);
}


/*
 * virSecuritySELinuxSetFileLabels:
 *
 * @mgr: the virSecurityManager
 * @path: path to a directory or a file
 * @seclabel: the security label
 *
 * Set the file labels on the given path; if the path is a directory
 * we label all files found there, including the directory itself,
 * otherwise we just label the file.
 */
static int
virSecuritySELinuxSetFileLabels(virSecurityManagerPtr mgr,
                                const char *path,
                                virSecurityLabelDefPtr seclabel)
{
    int ret = 0;
    struct dirent *ent;
    char *filename = NULL;
    DIR *dir;

    if ((ret = virSecuritySELinuxSetFilecon(mgr, path, seclabel->imagelabel, true)))
        return ret;

    if (!virFileIsDir(path))
        return 0;

    if (virDirOpen(&dir, path) < 0)
        return -1;

    while ((ret = virDirRead(dir, &ent, path)) > 0) {
        filename = g_strdup_printf("%s/%s", path, ent->d_name);
        ret = virSecuritySELinuxSetFilecon(mgr, filename,
                                           seclabel->imagelabel, true);
        VIR_FREE(filename);
        if (ret < 0)
            break;
    }
    if (ret < 0)
        virReportSystemError(errno, _("Unable to label files under %s"),
                             path);

    virDirClose(&dir);

    return ret;
}


/*
 * virSecuritySELinuxRestoreFileLabels:
 *
 * @mgr: the virSecurityManager
 * @path: path to a directory or a file
 *
 * Restore the file labels on the given path; if the path is a directory
 * we restore all file labels found there, including the label of the
 * directory itself, otherwise we just restore the label on the file.
 */
static int
virSecuritySELinuxRestoreFileLabels(virSecurityManagerPtr mgr,
                                    const char *path)
{
    int ret = 0;
    struct dirent *ent;
    char *filename = NULL;
    DIR *dir;

    if ((ret = virSecuritySELinuxRestoreFileLabel(mgr, path, true)))
        return ret;

    if (!virFileIsDir(path))
        return 0;

    if (virDirOpen(&dir, path) < 0)
        return -1;

    while ((ret = virDirRead(dir, &ent, path)) > 0) {
        filename = g_strdup_printf("%s/%s", path, ent->d_name);
        ret = virSecuritySELinuxRestoreFileLabel(mgr, filename, true);
        VIR_FREE(filename);
        if (ret < 0)
            break;
    }
    if (ret < 0)
        virReportSystemError(errno, _("Unable to restore file labels under %s"),
                             path);

    virDirClose(&dir);

    return ret;
}


static int
virSecuritySELinuxSetTPMLabels(virSecurityManagerPtr mgr,
                               virDomainDefPtr def)
{
    int ret = 0;
    virSecurityLabelDefPtr seclabel;

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (seclabel == NULL)
        return 0;

    switch (def->tpm->type) {
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
        break;
    case VIR_DOMAIN_TPM_TYPE_EMULATOR:
        ret = virSecuritySELinuxSetFileLabels(
            mgr, def->tpm->data.emulator.storagepath,
            seclabel);
        if (ret == 0 && def->tpm->data.emulator.logfile)
            ret = virSecuritySELinuxSetFileLabels(
                mgr, def->tpm->data.emulator.logfile,
                seclabel);
        break;
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }

    return ret;
}


static int
virSecuritySELinuxRestoreTPMLabels(virSecurityManagerPtr mgr,
                                   virDomainDefPtr def)
{
    int ret = 0;

    switch (def->tpm->type) {
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
        break;
    case VIR_DOMAIN_TPM_TYPE_EMULATOR:
        ret = virSecuritySELinuxRestoreFileLabels(
            mgr, def->tpm->data.emulator.storagepath);
        if (ret == 0 && def->tpm->data.emulator.logfile)
            ret = virSecuritySELinuxRestoreFileLabels(
                mgr, def->tpm->data.emulator.logfile);
        break;
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }

    return ret;
}


virSecurityDriver virSecurityDriverSELinux = {
    .privateDataLen                     = sizeof(virSecuritySELinuxData),
    .name                               = SECURITY_SELINUX_NAME,
    .probe                              = virSecuritySELinuxDriverProbe,
    .open                               = virSecuritySELinuxDriverOpen,
    .close                              = virSecuritySELinuxDriverClose,

    .getModel                           = virSecuritySELinuxGetModel,
    .getDOI                             = virSecuritySELinuxGetDOI,

    .transactionStart                   = virSecuritySELinuxTransactionStart,
    .transactionCommit                  = virSecuritySELinuxTransactionCommit,
    .transactionAbort                   = virSecuritySELinuxTransactionAbort,

    .domainSecurityVerify               = virSecuritySELinuxVerify,

    .domainSetSecurityImageLabel        = virSecuritySELinuxSetImageLabel,
    .domainRestoreSecurityImageLabel    = virSecuritySELinuxRestoreImageLabel,
    .domainMoveImageMetadata            = virSecuritySELinuxMoveImageMetadata,

    .domainSetSecurityMemoryLabel       = virSecuritySELinuxSetMemoryLabel,
    .domainRestoreSecurityMemoryLabel   = virSecuritySELinuxRestoreMemoryLabel,

    .domainSetSecurityInputLabel        = virSecuritySELinuxSetInputLabel,
    .domainRestoreSecurityInputLabel    = virSecuritySELinuxRestoreInputLabel,

    .domainSetSecurityDaemonSocketLabel = virSecuritySELinuxSetDaemonSocketLabel,
    .domainSetSecuritySocketLabel       = virSecuritySELinuxSetSocketLabel,
    .domainClearSecuritySocketLabel     = virSecuritySELinuxClearSocketLabel,

    .domainGenSecurityLabel             = virSecuritySELinuxGenLabel,
    .domainReserveSecurityLabel         = virSecuritySELinuxReserveLabel,
    .domainReleaseSecurityLabel         = virSecuritySELinuxReleaseLabel,

    .domainGetSecurityProcessLabel      = virSecuritySELinuxGetProcessLabel,
    .domainSetSecurityProcessLabel      = virSecuritySELinuxSetProcessLabel,
    .domainSetSecurityChildProcessLabel = virSecuritySELinuxSetChildProcessLabel,

    .domainSetSecurityAllLabel          = virSecuritySELinuxSetAllLabel,
    .domainRestoreSecurityAllLabel      = virSecuritySELinuxRestoreAllLabel,

    .domainSetSecurityHostdevLabel      = virSecuritySELinuxSetHostdevLabel,
    .domainRestoreSecurityHostdevLabel  = virSecuritySELinuxRestoreHostdevLabel,

    .domainSetSavedStateLabel           = virSecuritySELinuxSetSavedStateLabel,
    .domainRestoreSavedStateLabel       = virSecuritySELinuxRestoreSavedStateLabel,

    .domainSetSecurityImageFDLabel      = virSecuritySELinuxSetImageFDLabel,
    .domainSetSecurityTapFDLabel        = virSecuritySELinuxSetTapFDLabel,

    .domainGetSecurityMountOptions      = virSecuritySELinuxGetSecurityMountOptions,
    .getBaseLabel                       = virSecuritySELinuxGetBaseLabel,

    .domainSetPathLabel                 = virSecuritySELinuxDomainSetPathLabel,

    .domainSetSecurityChardevLabel      = virSecuritySELinuxSetChardevLabel,
    .domainRestoreSecurityChardevLabel  = virSecuritySELinuxRestoreChardevLabel,

    .domainSetSecurityTPMLabels         = virSecuritySELinuxSetTPMLabels,
    .domainRestoreSecurityTPMLabels     = virSecuritySELinuxRestoreTPMLabels,
};
