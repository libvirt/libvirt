/*
 * Copyright (C) 2008-2012 Red Hat, Inc.
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
 *     James Morris <jmorris@namei.org>
 *     Dan Walsh <dwalsh@redhat.com>
 *
 * SELinux security driver.
 */
#include <config.h>
#include <selinux/selinux.h>
#include <selinux/context.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#if HAVE_SELINUX_LABEL_H
# include <selinux/label.h>
#endif

#include "security_driver.h"
#include "security_selinux.h"
#include "virterror_internal.h"
#include "util.h"
#include "memory.h"
#include "logging.h"
#include "pci.h"
#include "hostusb.h"
#include "storage_file.h"
#include "virfile.h"
#include "virhash.h"
#include "virrandom.h"
#include "util.h"
#include "conf.h"

#define VIR_FROM_THIS VIR_FROM_SECURITY

#define MAX_CONTEXT 1024

typedef struct _virSecuritySELinuxData virSecuritySELinuxData;
typedef virSecuritySELinuxData *virSecuritySELinuxDataPtr;

typedef struct _virSecuritySELinuxCallbackData virSecuritySELinuxCallbackData;
typedef virSecuritySELinuxCallbackData *virSecuritySELinuxCallbackDataPtr;

struct _virSecuritySELinuxData {
    char *domain_context;
    char *file_context;
    char *content_context;
    virHashTablePtr mcs;
};

struct _virSecuritySELinuxCallbackData {
    virSecurityManagerPtr manager;
    virSecurityLabelDefPtr secdef;
};

#define SECURITY_SELINUX_VOID_DOI       "0"
#define SECURITY_SELINUX_NAME "selinux"

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
virSecuritySELinuxMCSFind(virSecurityManagerPtr mgr)
{
    virSecuritySELinuxDataPtr data = virSecurityManagerGetPrivateData(mgr);
    int c1 = 0;
    int c2 = 0;
    char *mcs = NULL;
    security_context_t ourSecContext = NULL;
    context_t ourContext = NULL;
    char *sens, *cat, *tmp;
    int catMin, catMax, catRange;

    if (getcon(&ourSecContext) < 0) {
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

    if (!(sens = strdup(context_range_get(ourContext)))) {
        virReportOOMError();
        goto cleanup;
    }

    /* Find and blank out the category part */
    if (!(tmp = strchr(sens, ':'))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot parse sensitivity level in %s"),
                       sens);
        goto cleanup;
    }
    *tmp = '\0';
    cat = tmp + 1;
    /* Find and blank out the sensitivity upper bound */
    if ((tmp = strchr(sens, '-')))
        *tmp = '\0';
    /* sens now just contains the sensitivity lower bound */

    /* Find & extract category min */
    tmp = cat;
    if (tmp[0] != 'c') {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot parse category in %s"),
                       cat);
        goto cleanup;
    }
    tmp++;
    if (virStrToLong_i(tmp, &tmp, 10, &catMin) < 0) {
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
    if (virStrToLong_i(tmp, &tmp, 10, &catMax) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot parse category in %s"),
                       cat);
        goto cleanup;
    }

    /* +1 since virRandomInt range is exclusive of the upper bound */
    catRange = (catMax - catMin) + 1;

    if (catRange < 8) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Category range c%d-c%d too small"),
                       catMin, catMax);
        goto cleanup;
    }

    VIR_DEBUG("Using sensitivity level '%s' cat min %d max %d range %d",
              sens, catMin, catMax, catRange);

    for (;;) {
        c1 = virRandomInt(catRange);
        c2 = virRandomInt(catRange);
        VIR_DEBUG("Try cat %s:c%d,c%d", sens, c1+catMin, c2+catMin);

        if (c1 == c2) {
            if (virAsprintf(&mcs, "%s:c%d", sens, catMin + c1) < 0) {
                virReportOOMError();
                return NULL;
            }
        } else {
            if (c1 > c2) {
                int t = c1;
                c1 = c2;
                c2 = t;
            }
            if (virAsprintf(&mcs, "%s:c%d,c%d", sens, catMin + c1, catMin + c2) < 0) {
                virReportOOMError();
                return NULL;
            }
        }

        if (virHashLookup(data->mcs, mcs) == NULL)
            goto cleanup;

        VIR_FREE(mcs);
    }

cleanup:
    VIR_DEBUG("Found context '%s'", NULLSTR(mcs));
    VIR_FREE(sens);
    freecon(ourSecContext);
    context_free(ourContext);
    return mcs;
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

    if (getcon(&ourSecContext) < 0) {
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
    if (!(ret = strdup(str))) {
        virReportOOMError();
        goto cleanup;
    }
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
    virConfValuePtr scon = NULL;
    virConfValuePtr tcon = NULL;
    virConfValuePtr dcon = NULL;
    virConfPtr selinux_conf;
    virSecuritySELinuxDataPtr data = virSecurityManagerGetPrivateData(mgr);

    selinux_conf = virConfReadFile(selinux_lxc_contexts_path(), 0);
    if (!selinux_conf) {
        virReportSystemError(errno,
                             _("cannot open SELinux lxc contexts file '%s'"),
                             selinux_lxc_contexts_path());
        return -1;
    }

    scon = virConfGetValue(selinux_conf, "process");
    if (! scon || scon->type != VIR_CONF_STRING || (! scon->str)) {
        virReportSystemError(errno,
                             _("cannot read 'process' value from selinux lxc contexts file '%s'"),
                             selinux_lxc_contexts_path());
        goto error;
    }

    tcon = virConfGetValue(selinux_conf, "file");
    if (! tcon || tcon->type != VIR_CONF_STRING || (! tcon->str)) {
        virReportSystemError(errno,
                             _("cannot read 'file' value from selinux lxc contexts file '%s'"),
                             selinux_lxc_contexts_path());
        goto error;
    }

    dcon = virConfGetValue(selinux_conf, "content");
    if (! dcon || dcon->type != VIR_CONF_STRING || (! dcon->str)) {
        virReportSystemError(errno,
                             _("cannot read 'file' value from selinux lxc contexts file '%s'"),
                             selinux_lxc_contexts_path());
        goto error;
    }

    data->domain_context = strdup(scon->str);
    data->file_context = strdup(tcon->str);
    data->content_context = strdup(dcon->str);
    if (!data->domain_context ||
        !data->file_context ||
        !data->content_context) {
        virReportSystemError(errno,
                             _("cannot allocate memory for LXC SELinux contexts '%s'"),
                             selinux_lxc_contexts_path());
        goto error;
    }

    if (!(data->mcs = virHashCreate(10, NULL)))
        goto error;

    virConfFree(selinux_conf);
    return 0;

error:
    virConfFree(selinux_conf);
    VIR_FREE(data->domain_context);
    VIR_FREE(data->file_context);
    VIR_FREE(data->content_context);
    virHashFree(data->mcs);
    return -1;
}
#else
static int
virSecuritySELinuxLXCInitialize(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED)
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

    if (virFileReadAll(selinux_virtual_domain_context_path(), MAX_CONTEXT, &(data->domain_context)) < 0) {
        virReportSystemError(errno,
                             _("cannot read SELinux virtual domain context file '%s'"),
                             selinux_virtual_domain_context_path());
        goto error;
    }

    ptr = strchrnul(data->domain_context, '\n');
    if (ptr)
        *ptr = '\0';

    if (virFileReadAll(selinux_virtual_image_context_path(), 2*MAX_CONTEXT, &(data->file_context)) < 0) {
        virReportSystemError(errno,
                             _("cannot read SELinux virtual image context file %s"),
                             selinux_virtual_image_context_path());
        goto error;
    }

    ptr = strchrnul(data->file_context, '\n');
    if (ptr && *ptr == '\n') {
        *ptr = '\0';
        data->content_context = strdup(ptr+1);
        if (!data->content_context) {
            virReportOOMError();
            goto error;
        }
        ptr = strchrnul(data->content_context, '\n');
        if (ptr && *ptr == '\n')
            *ptr = '\0';
    }

    if (!(data->mcs = virHashCreate(10, NULL)))
        goto error;

    return 0;

error:
    VIR_FREE(data->domain_context);
    VIR_FREE(data->file_context);
    VIR_FREE(data->content_context);
    virHashFree(data->mcs);
    return -1;
}


static int
virSecuritySELinuxInitialize(virSecurityManagerPtr mgr)
{
    VIR_DEBUG("SELinuxInitialize %s", virSecurityManagerGetDriver(mgr));
    if (STREQ(virSecurityManagerGetDriver(mgr),  "LXC")) {
        return virSecuritySELinuxLXCInitialize(mgr);
    } else {
        return virSecuritySELinuxQEMUInitialize(mgr);
    }
}


static int
virSecuritySELinuxGenSecurityLabel(virSecurityManagerPtr mgr,
                                   virDomainDefPtr def)
{
    int rc = -1;
    char *mcs = NULL;
    char *scontext = NULL;
    context_t ctx = NULL;
    const char *range;
    virSecurityLabelDefPtr seclabel;
    virSecuritySELinuxDataPtr data;

    if (mgr == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("invalid security driver"));
        return rc;
    }

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (seclabel == NULL) {
        return rc;
    }

    data = virSecurityManagerGetPrivateData(mgr);

    VIR_DEBUG("label=%s", virSecurityManagerGetDriver(mgr));
    if (seclabel->type == VIR_DOMAIN_SECLABEL_DYNAMIC &&
        seclabel->label) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("security label already defined for VM"));
        return rc;
    }

    if (seclabel->imagelabel) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("security image label already defined for VM"));
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
        if (!(ctx = context_new(seclabel->label)) ) {
            virReportSystemError(errno,
                                 _("unable to allocate socket security context '%s'"),
                                 seclabel->label);
            return rc;
        }

        range = context_range_get(ctx);
        if (!range ||
            !(mcs = strdup(range))) {
            virReportOOMError();
            goto cleanup;
        }
        break;

    case VIR_DOMAIN_SECLABEL_DYNAMIC:
        if (!(mcs = virSecuritySELinuxMCSFind(mgr)))
            goto cleanup;

        if (virSecuritySELinuxMCSAdd(mgr, mcs) < 0)
            goto cleanup;

        seclabel->label =
            virSecuritySELinuxGenNewContext(seclabel->baselabel ?
                                 seclabel->baselabel :
                                 data->domain_context, mcs, false);
        if (!seclabel->label)  {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot generate selinux context for %s"), mcs);
            goto cleanup;
        }
        break;

    case VIR_DOMAIN_SECLABEL_NONE:
        /* no op */
        break;

    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected security label type '%s'"),
                       virDomainSeclabelTypeToString(seclabel->type));
        goto cleanup;
    }

    if (!seclabel->norelabel) {
        seclabel->imagelabel = virSecuritySELinuxGenNewContext(data->file_context,
                                                               mcs,
                                                               true);
        if (!seclabel->imagelabel)  {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot generate selinux context for %s"), mcs);
            goto cleanup;
        }
    }

    if (!seclabel->model &&
        !(seclabel->model = strdup(SECURITY_SELINUX_NAME))) {
        virReportOOMError();
        goto cleanup;
    }

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

    VIR_DEBUG("model=%s label=%s imagelabel=%s baselabel=%s",
              NULLSTR(seclabel->model),
              NULLSTR(seclabel->label),
              NULLSTR(seclabel->imagelabel),
              NULLSTR(seclabel->baselabel));

    return rc;
}

static int
virSecuritySELinuxReserveSecurityLabel(virSecurityManagerPtr mgr,
                                       virDomainDefPtr def,
                                       pid_t pid)
{
    security_context_t pctx;
    context_t ctx = NULL;
    const char *mcs;
    int rv;
    virSecurityLabelDefPtr seclabel;

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (seclabel == NULL) {
        return -1;
    }

    if (seclabel->type == VIR_DOMAIN_SECLABEL_STATIC)
        return 0;

    if (getpidcon(pid, &pctx) == -1) {
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
virSecuritySELinuxSecurityDriverProbe(const char *virtDriver)
{
    if (!is_selinux_enabled())
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
virSecuritySELinuxSecurityDriverOpen(virSecurityManagerPtr mgr)
{
    return virSecuritySELinuxInitialize(mgr);
}


static int
virSecuritySELinuxSecurityDriverClose(virSecurityManagerPtr mgr)
{
    virSecuritySELinuxDataPtr data = virSecurityManagerGetPrivateData(mgr);

    if (!data)
        return 0;

    virHashFree(data->mcs);

    VIR_FREE(data->domain_context);
    VIR_FREE(data->file_context);
    VIR_FREE(data->content_context);

    return 0;
}


static const char *
virSecuritySELinuxSecurityGetModel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED)
{
    return SECURITY_SELINUX_NAME;
}

static const char *
virSecuritySELinuxSecurityGetDOI(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED)
{
    /*
     * Where will the DOI come from?  SELinux configuration, or qemu
     * configuration? For the moment, we'll just set it to "0".
     */
    return SECURITY_SELINUX_VOID_DOI;
}

static int
virSecuritySELinuxGetSecurityProcessLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                          virDomainDefPtr def ATTRIBUTE_UNUSED,
                                          pid_t pid,
                                          virSecurityLabelPtr sec)
{
    security_context_t ctx;

    if (getpidcon(pid, &ctx) == -1) {
        virReportSystemError(errno,
                             _("unable to get PID %d security context"),
                             pid);
        return -1;
    }

    if (strlen((char *) ctx) >= VIR_SECURITY_LABEL_BUFLEN) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security label exceeds "
                         "maximum length: %d"),
                       VIR_SECURITY_LABEL_BUFLEN - 1);
        freecon(ctx);
        return -1;
    }

    strcpy(sec->label, (char *) ctx);
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

/* Attempt to change the label of PATH to TCON.  If OPTIONAL is true,
 * return 1 if labelling was not possible.  Otherwise, require a label
 * change, and return 0 for success, -1 for failure.  */
static int
virSecuritySELinuxSetFileconHelper(const char *path, char *tcon, bool optional)
{
    security_context_t econ;

    VIR_INFO("Setting SELinux context on '%s' to '%s'", path, tcon);

    if (setfilecon(path, tcon) < 0) {
        int setfilecon_errno = errno;

        if (getfilecon(path, &econ) >= 0) {
            if (STREQ(tcon, econ)) {
                freecon(econ);
                /* It's alright, there's nothing to change anyway. */
                return optional ? 1 : 0;
            }
            freecon(econ);
        }

        /* if the error complaint is related to an image hosted on
         * an nfs mount, or a usbfs/sysfs filesystem not supporting
         * labelling, then just ignore it & hope for the best.
         * The user hopefully set one of the necessary SELinux
         * virt_use_{nfs,usb,pci}  boolean tunables to allow it...
         */
        if (setfilecon_errno != EOPNOTSUPP && setfilecon_errno != ENOTSUP) {
            virReportSystemError(setfilecon_errno,
                                 _("unable to set security context '%s' on '%s'"),
                                 tcon, path);
            if (security_getenforce() == 1)
                return -1;
        } else {
            const char *msg;
            if ((virStorageFileIsSharedFSType(path,
                                              VIR_STORAGE_FILE_SHFS_NFS) == 1) &&
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
            if (optional)
                return 1;
        }
    }
    return 0;
}

static int
virSecuritySELinuxSetFileconOptional(const char *path, char *tcon)
{
    return virSecuritySELinuxSetFileconHelper(path, tcon, true);
}

static int
virSecuritySELinuxSetFilecon(const char *path, char *tcon)
{
    return virSecuritySELinuxSetFileconHelper(path, tcon, false);
}

static int
virSecuritySELinuxFSetFilecon(int fd, char *tcon)
{
    security_context_t econ;

    VIR_INFO("Setting SELinux context on fd %d to '%s'", fd, tcon);

    if (fsetfilecon(fd, tcon) < 0) {
        int fsetfilecon_errno = errno;

        if (fgetfilecon(fd, &econ) >= 0) {
            if (STREQ(tcon, econ)) {
                freecon(econ);
                /* It's alright, there's nothing to change anyway. */
                return 0;
            }
            freecon(econ);
        }

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
getContext(const char *newpath, mode_t mode, security_context_t *fcon)
{
#if HAVE_SELINUX_LABEL_H
    struct selabel_handle *handle = selabel_open(SELABEL_CTX_FILE, NULL, 0);
    int ret;

    if (handle == NULL)
        return -1;

    ret = selabel_lookup(handle, fcon, newpath, mode);
    selabel_close(handle);
    return ret;
#else
    return matchpathcon(newpath, mode, fcon);
#endif
}


/* This method shouldn't raise errors, since they'll overwrite
 * errors that the caller(s) are already dealing with */
static int
virSecuritySELinuxRestoreSecurityFileLabel(const char *path)
{
    struct stat buf;
    security_context_t fcon = NULL;
    int rc = -1;
    char *newpath = NULL;
    char ebuf[1024];

    VIR_INFO("Restoring SELinux context on '%s'", path);

    if (virFileResolveLink(path, &newpath) < 0) {
        VIR_WARN("cannot resolve symlink %s: %s", path,
                 virStrerror(errno, ebuf, sizeof(ebuf)));
        goto err;
    }

    if (stat(newpath, &buf) != 0) {
        VIR_WARN("cannot stat %s: %s", newpath,
                 virStrerror(errno, ebuf, sizeof(ebuf)));
        goto err;
    }

    if (getContext(newpath, buf.st_mode, &fcon) < 0) {
        VIR_WARN("cannot lookup default selinux label for %s", newpath);
    } else {
        rc = virSecuritySELinuxSetFilecon(newpath, fcon);
    }

err:
    freecon(fcon);
    VIR_FREE(newpath);
    return rc;
}

static int
virSecuritySELinuxRestoreSecurityImageLabelInt(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                               virDomainDefPtr def,
                                               virDomainDiskDefPtr disk,
                                               int migrated)
{
    virSecurityLabelDefPtr seclabel;
    virSecurityDeviceLabelDefPtr disk_seclabel;

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (seclabel == NULL)
        return -1;

    disk_seclabel = virDomainDiskDefGetSecurityLabelDef(disk,
                                                        SECURITY_SELINUX_NAME);
    if (seclabel->norelabel || (disk_seclabel && disk_seclabel->norelabel))
        return 0;

    /* Don't restore labels on readoly/shared disks, because
     * other VMs may still be accessing these
     * Alternatively we could iterate over all running
     * domains and try to figure out if it is in use, but
     * this would not work for clustered filesystems, since
     * we can't see running VMs using the file on other nodes
     * Safest bet is thus to skip the restore step.
     */
    if (disk->readonly || disk->shared)
        return 0;

    if (!disk->src || disk->type == VIR_DOMAIN_DISK_TYPE_NETWORK)
        return 0;

    /* If we have a shared FS & doing migrated, we must not
     * change ownership, because that kills access on the
     * destination host which is sub-optimal for the guest
     * VM's I/O attempts :-)
     */
    if (migrated) {
        int rc = virStorageFileIsSharedFS(disk->src);
        if (rc < 0)
            return -1;
        if (rc == 1) {
            VIR_DEBUG("Skipping image label restore on %s because FS is shared",
                      disk->src);
            return 0;
        }
    }

    return virSecuritySELinuxRestoreSecurityFileLabel(disk->src);
}


static int
virSecuritySELinuxRestoreSecurityImageLabel(virSecurityManagerPtr mgr,
                                            virDomainDefPtr def,
                                            virDomainDiskDefPtr disk)
{
    return virSecuritySELinuxRestoreSecurityImageLabelInt(mgr, def, disk, 0);
}


static int
virSecuritySELinuxSetSecurityFileLabel(virDomainDiskDefPtr disk,
                                       const char *path,
                                       size_t depth,
                                       void *opaque)
{
    int ret;
    virSecurityDeviceLabelDefPtr disk_seclabel;
    virSecuritySELinuxCallbackDataPtr cbdata = opaque;
    const virSecurityLabelDefPtr secdef = cbdata->secdef;
    virSecuritySELinuxDataPtr data = virSecurityManagerGetPrivateData(cbdata->manager);

    disk_seclabel = virDomainDiskDefGetSecurityLabelDef(disk,
                                                        SECURITY_SELINUX_NAME);

    if (disk_seclabel && disk_seclabel->norelabel)
        return 0;

    if (disk_seclabel && !disk_seclabel->norelabel &&
        disk_seclabel->label) {
        ret = virSecuritySELinuxSetFilecon(path, disk_seclabel->label);
    } else if (depth == 0) {

        if (disk->shared) {
            ret = virSecuritySELinuxSetFileconOptional(path, data->file_context);
        } else if (disk->readonly) {
            ret = virSecuritySELinuxSetFileconOptional(path, data->content_context);
        } else if (secdef->imagelabel) {
            ret = virSecuritySELinuxSetFileconOptional(path, secdef->imagelabel);
        } else {
            ret = 0;
        }
    } else {
        ret = virSecuritySELinuxSetFileconOptional(path, data->content_context);
    }
    if (ret == 1 && !disk_seclabel) {
        /* If we failed to set a label, but virt_use_nfs let us
         * proceed anyway, then we don't need to relabel later.  */
        if (VIR_ALLOC(disk_seclabel) < 0) {
            virReportOOMError();
            return -1;
        }
        disk_seclabel->norelabel = true;
        ret = 0;
    }
    return ret;
}

static int
virSecuritySELinuxSetSecurityImageLabel(virSecurityManagerPtr mgr,
                                        virDomainDefPtr def,
                                        virDomainDiskDefPtr disk)

{
    bool allowDiskFormatProbing;
    virSecuritySELinuxCallbackData cbdata;
    cbdata.manager = mgr;
    cbdata.secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);

    allowDiskFormatProbing = virSecurityManagerGetAllowDiskFormatProbing(mgr);

    if (cbdata.secdef == NULL)
        return -1;

    if (cbdata.secdef->norelabel)
        return 0;

    if (disk->type == VIR_DOMAIN_DISK_TYPE_NETWORK)
        return 0;

    /* XXX On one hand, it would be nice to have the driver's uid:gid
     * here so we could retry opens with it. On the other hand, it
     * probably doesn't matter because in practice that's only useful
     * for files on root-squashed NFS shares, and NFS doesn't properly
     * support selinux anyway.
     */
    return virDomainDiskDefForeachPath(disk,
                                       allowDiskFormatProbing,
                                       true,
                                       -1, -1, /* current process uid:gid */
                                       virSecuritySELinuxSetSecurityFileLabel,
                                       &cbdata);
}


static int
virSecuritySELinuxSetSecurityPCILabel(pciDevice *dev ATTRIBUTE_UNUSED,
                                      const char *file, void *opaque)
{
    virSecurityLabelDefPtr secdef;
    virDomainDefPtr def = opaque;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (secdef == NULL)
        return -1;
    return virSecuritySELinuxSetFilecon(file, secdef->imagelabel);
}

static int
virSecuritySELinuxSetSecurityUSBLabel(usbDevice *dev ATTRIBUTE_UNUSED,
                                      const char *file, void *opaque)
{
    virSecurityLabelDefPtr secdef;
    virDomainDefPtr def = opaque;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (secdef == NULL)
        return -1;

    return virSecuritySELinuxSetFilecon(file, secdef->imagelabel);
}

static int
virSecuritySELinuxSetSecurityHostdevLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                          virDomainDefPtr def,
                                          virDomainHostdevDefPtr dev)

{
    virSecurityLabelDefPtr secdef;
    int ret = -1;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (secdef == NULL)
        return -1;

    if (secdef->norelabel)
        return 0;

    if (dev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
        return 0;

    switch (dev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB: {
        usbDevice *usb = usbGetDevice(dev->source.subsys.u.usb.bus,
                                      dev->source.subsys.u.usb.device);

        if (!usb)
            goto done;

        ret = usbDeviceFileIterate(usb, virSecuritySELinuxSetSecurityUSBLabel, def);
        usbFreeDevice(usb);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI: {
        pciDevice *pci = pciGetDevice(dev->source.subsys.u.pci.domain,
                                      dev->source.subsys.u.pci.bus,
                                      dev->source.subsys.u.pci.slot,
                                      dev->source.subsys.u.pci.function);

        if (!pci)
            goto done;

        ret = pciDeviceFileIterate(pci, virSecuritySELinuxSetSecurityPCILabel, def);
        pciFreeDevice(pci);

        break;
    }

    default:
        ret = 0;
        break;
    }

done:
    return ret;
}


static int
virSecuritySELinuxRestoreSecurityPCILabel(pciDevice *dev ATTRIBUTE_UNUSED,
                                          const char *file,
                                          void *opaque ATTRIBUTE_UNUSED)
{
    return virSecuritySELinuxRestoreSecurityFileLabel(file);
}

static int
virSecuritySELinuxRestoreSecurityUSBLabel(usbDevice *dev ATTRIBUTE_UNUSED,
                                          const char *file,
                                          void *opaque ATTRIBUTE_UNUSED)
{
    return virSecuritySELinuxRestoreSecurityFileLabel(file);
}

static int
virSecuritySELinuxRestoreSecurityHostdevLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                              virDomainDefPtr def,
                                              virDomainHostdevDefPtr dev)

{
    virSecurityLabelDefPtr secdef;
    int ret = -1;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (secdef == NULL)
        return -1;

    if (secdef->norelabel)
        return 0;

    if (dev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
        return 0;

    switch (dev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB: {
        usbDevice *usb = usbGetDevice(dev->source.subsys.u.usb.bus,
                                      dev->source.subsys.u.usb.device);

        if (!usb)
            goto done;

        ret = usbDeviceFileIterate(usb, virSecuritySELinuxRestoreSecurityUSBLabel, NULL);
        usbFreeDevice(usb);

        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI: {
        pciDevice *pci = pciGetDevice(dev->source.subsys.u.pci.domain,
                                      dev->source.subsys.u.pci.bus,
                                      dev->source.subsys.u.pci.slot,
                                      dev->source.subsys.u.pci.function);

        if (!pci)
            goto done;

        ret = pciDeviceFileIterate(pci, virSecuritySELinuxRestoreSecurityPCILabel, NULL);
        pciFreeDevice(pci);

        break;
    }

    default:
        ret = 0;
        break;
    }

done:
    return ret;
}


static int
virSecuritySELinuxSetSecurityChardevLabel(virDomainDefPtr def,
                                          virDomainChrDefPtr dev,
                                          virDomainChrSourceDefPtr dev_source)

{
    virSecurityLabelDefPtr seclabel;
    virSecurityDeviceLabelDefPtr chr_seclabel = NULL;
    char *imagelabel = NULL;
    char *in = NULL, *out = NULL;
    int ret = -1;

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (seclabel == NULL)
        return -1;

    if (dev)
        chr_seclabel = virDomainChrDefGetSecurityLabelDef(dev,
                                                          SECURITY_SELINUX_NAME);

    if (seclabel->norelabel || (chr_seclabel && chr_seclabel->norelabel))
        return 0;

    if (chr_seclabel)
        imagelabel = chr_seclabel->label;
    if (!imagelabel)
        imagelabel = seclabel->imagelabel;

    switch (dev_source->type) {
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_FILE:
        ret = virSecuritySELinuxSetFilecon(dev_source->data.file.path,
                                           imagelabel);
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        if (!dev_source->data.nix.listen) {
            if (virSecuritySELinuxSetFilecon(dev_source->data.file.path,
                                             imagelabel) < 0)
                goto done;
        }
        ret = 0;
        break;

    case VIR_DOMAIN_CHR_TYPE_PIPE:
        if ((virAsprintf(&in, "%s.in", dev_source->data.file.path) < 0) ||
            (virAsprintf(&out, "%s.out", dev_source->data.file.path) < 0)) {
            virReportOOMError();
            goto done;
        }
        if (virFileExists(in) && virFileExists(out)) {
            if ((virSecuritySELinuxSetFilecon(in, imagelabel) < 0) ||
                (virSecuritySELinuxSetFilecon(out, imagelabel) < 0)) {
                goto done;
            }
        } else if (virSecuritySELinuxSetFilecon(dev_source->data.file.path,
                                                imagelabel) < 0) {
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
virSecuritySELinuxRestoreSecurityChardevLabel(virDomainDefPtr def,
                                              virDomainChrDefPtr dev,
                                              virDomainChrSourceDefPtr dev_source)

{
    virSecurityLabelDefPtr seclabel;
    virSecurityDeviceLabelDefPtr chr_seclabel = NULL;
    char *in = NULL, *out = NULL;
    int ret = -1;

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (seclabel == NULL)
        return -1;

    if (dev)
        chr_seclabel = virDomainChrDefGetSecurityLabelDef(dev,
                                                          SECURITY_SELINUX_NAME);
    if (seclabel->norelabel || (chr_seclabel && chr_seclabel->norelabel))
        return 0;

    switch (dev_source->type) {
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_FILE:
        if (virSecuritySELinuxRestoreSecurityFileLabel(dev_source->data.file.path) < 0)
            goto done;
        ret = 0;
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        if (!dev_source->data.nix.listen) {
            if (virSecuritySELinuxRestoreSecurityFileLabel(dev_source->data.file.path) < 0)
                goto done;
        }
        ret = 0;
        break;

    case VIR_DOMAIN_CHR_TYPE_PIPE:
        if ((virAsprintf(&out, "%s.out", dev_source->data.file.path) < 0) ||
            (virAsprintf(&in, "%s.in", dev_source->data.file.path) < 0)) {
            virReportOOMError();
            goto done;
        }
        if (virFileExists(in) && virFileExists(out)) {
            if ((virSecuritySELinuxRestoreSecurityFileLabel(out) < 0) ||
                (virSecuritySELinuxRestoreSecurityFileLabel(in) < 0)) {
                goto done;
            }
        } else if (virSecuritySELinuxRestoreSecurityFileLabel(dev_source->data.file.path) < 0) {
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
virSecuritySELinuxRestoreSecurityChardevCallback(virDomainDefPtr def,
                                                 virDomainChrDefPtr dev,
                                                 void *opaque ATTRIBUTE_UNUSED)
{
    /* This is taken care of by processing of def->serials */
    if (dev->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
        dev->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL)
        return 0;

    return virSecuritySELinuxRestoreSecurityChardevLabel(def, dev,
                                                         &dev->source);
}


static int
virSecuritySELinuxRestoreSecuritySmartcardCallback(virDomainDefPtr def,
                                                   virDomainSmartcardDefPtr dev,
                                                   void *opaque ATTRIBUTE_UNUSED)
{
    const char *database;

    switch (dev->type) {
    case VIR_DOMAIN_SMARTCARD_TYPE_HOST:
        break;

    case VIR_DOMAIN_SMARTCARD_TYPE_HOST_CERTIFICATES:
        database = dev->data.cert.database;
        if (!database)
            database = VIR_DOMAIN_SMARTCARD_DEFAULT_DATABASE;
        return virSecuritySELinuxRestoreSecurityFileLabel(database);

    case VIR_DOMAIN_SMARTCARD_TYPE_PASSTHROUGH:
        return virSecuritySELinuxRestoreSecurityChardevLabel(def, NULL, &dev->data.passthru);

    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown smartcard type %d"),
                       dev->type);
        return -1;
    }

    return 0;
}


static int
virSecuritySELinuxRestoreSecurityAllLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                          virDomainDefPtr def,
                                          int migrated ATTRIBUTE_UNUSED)
{
    virSecurityLabelDefPtr secdef;
    int i;
    int rc = 0;

    VIR_DEBUG("Restoring security label on %s", def->name);

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (secdef == NULL)
        return -1;

    if (secdef->norelabel)
        return 0;

    for (i = 0 ; i < def->nhostdevs ; i++) {
        if (virSecuritySELinuxRestoreSecurityHostdevLabel(mgr,
                                                          def,
                                                          def->hostdevs[i]) < 0)
            rc = -1;
    }
    for (i = 0 ; i < def->ndisks ; i++) {
        if (virSecuritySELinuxRestoreSecurityImageLabelInt(mgr,
                                                           def,
                                                           def->disks[i],
                                                           migrated) < 0)
            rc = -1;
    }

    if (virDomainChrDefForeach(def,
                               false,
                               virSecuritySELinuxRestoreSecurityChardevCallback,
                               NULL) < 0)
        rc = -1;

    if (virDomainSmartcardDefForeach(def,
                                     false,
                                     virSecuritySELinuxRestoreSecuritySmartcardCallback,
                                     NULL) < 0)
        rc = -1;

    if (def->os.kernel &&
        virSecuritySELinuxRestoreSecurityFileLabel(def->os.kernel) < 0)
        rc = -1;

    if (def->os.initrd &&
        virSecuritySELinuxRestoreSecurityFileLabel(def->os.initrd) < 0)
        rc = -1;

    return rc;
}

static int
virSecuritySELinuxReleaseSecurityLabel(virSecurityManagerPtr mgr,
                                       virDomainDefPtr def)
{
    virSecurityLabelDefPtr secdef;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (secdef == NULL)
        return -1;

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
virSecuritySELinuxSetSavedStateLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                     virDomainDefPtr def,
                                     const char *savefile)
{
    virSecurityLabelDefPtr secdef;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (secdef == NULL)
        return -1;

    if (secdef->norelabel)
        return 0;

    return virSecuritySELinuxSetFilecon(savefile, secdef->imagelabel);
}


static int
virSecuritySELinuxRestoreSavedStateLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                         virDomainDefPtr def,
                                         const char *savefile)
{
    virSecurityLabelDefPtr secdef;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (secdef == NULL)
        return -1;

    if (secdef->norelabel)
        return 0;

    return virSecuritySELinuxRestoreSecurityFileLabel(savefile);
}


static int
virSecuritySELinuxSecurityVerify(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                 virDomainDefPtr def)
{
    virSecurityLabelDefPtr secdef;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (secdef == NULL)
        return -1;

    if (!STREQ(virSecurityManagerGetModel(mgr), secdef->model)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security label driver mismatch: "
                         "'%s' model configured for domain, but "
                         "hypervisor driver is '%s'."),
                       secdef->model, virSecurityManagerGetModel(mgr));
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
virSecuritySELinuxSetSecurityProcessLabel(virSecurityManagerPtr mgr,
                                          virDomainDefPtr def)
{
    /* TODO: verify DOI */
    virSecurityLabelDefPtr secdef;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (secdef == NULL)
        return -1;

    if (secdef->label == NULL)
        return 0;

    VIR_DEBUG("label=%s", secdef->label);
    if (!STREQ(virSecurityManagerGetModel(mgr), secdef->model)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security label driver mismatch: "
                         "'%s' model configured for domain, but "
                         "hypervisor driver is '%s'."),
                       secdef->model, virSecurityManagerGetModel(mgr));
        if (security_getenforce() == 1)
            return -1;
    }

    if (setexeccon(secdef->label) == -1) {
        virReportSystemError(errno,
                             _("unable to set security context '%s'"),
                             secdef->label);
        if (security_getenforce() == 1)
            return -1;
    }

    return 0;
}

static int
virSecuritySELinuxSetSecurityDaemonSocketLabel(virSecurityManagerPtr mgr,
                                               virDomainDefPtr def)
{
    /* TODO: verify DOI */
    virSecurityLabelDefPtr secdef;
    context_t execcon = NULL;
    context_t proccon = NULL;
    security_context_t scon = NULL;
    int rc = -1;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (secdef == NULL)
        return -1;

    if (secdef->label == NULL)
        return 0;

    if (!STREQ(virSecurityManagerGetModel(mgr), secdef->model)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security label driver mismatch: "
                         "'%s' model configured for domain, but "
                         "hypervisor driver is '%s'."),
                       secdef->model, virSecurityManagerGetModel(mgr));
        goto done;
    }

    if ( !(execcon = context_new(secdef->label)) ) {
        virReportSystemError(errno,
                             _("unable to allocate socket security context '%s'"),
                             secdef->label);
        goto done;
    }

    if (getcon(&scon) == -1) {
        virReportSystemError(errno,
                             _("unable to get current process context '%s'"),
                             secdef->label);
        goto done;
    }

    if ( !(proccon = context_new(scon)) ) {
        virReportSystemError(errno,
                             _("unable to set socket security context '%s'"),
                             secdef->label);
        goto done;
    }

    if (context_range_set(proccon, context_range_get(execcon)) == -1) {
        virReportSystemError(errno,
                             _("unable to set socket security context range '%s'"),
                             secdef->label);
        goto done;
    }

    VIR_DEBUG("Setting VM %s socket context %s",
              def->name, context_str(proccon));
    if (setsockcreatecon(context_str(proccon)) == -1) {
        virReportSystemError(errno,
                             _("unable to set socket security context '%s'"),
                             context_str(proccon));
        goto done;
    }

    rc = 0;
done:

    if (security_getenforce() != 1)
        rc = 0;
    if (execcon) context_free(execcon);
    if (proccon) context_free(proccon);
    freecon(scon);
    return rc;
}

static int
virSecuritySELinuxSetSecuritySocketLabel(virSecurityManagerPtr mgr,
                                         virDomainDefPtr vm)
{
    virSecurityLabelDefPtr secdef;
    int rc = -1;

    secdef = virDomainDefGetSecurityLabelDef(vm, SECURITY_SELINUX_NAME);
    if (secdef == NULL)
        return -1;

    if (secdef->label == NULL)
        return 0;

    if (!STREQ(virSecurityManagerGetModel(mgr), secdef->model)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security label driver mismatch: "
                         "'%s' model configured for domain, but "
                         "hypervisor driver is '%s'."),
                       secdef->model, virSecurityManagerGetModel(mgr));
        goto done;
    }

    VIR_DEBUG("Setting VM %s socket context %s",
              vm->name, secdef->label);
    if (setsockcreatecon(secdef->label) == -1) {
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
virSecuritySELinuxClearSecuritySocketLabel(virSecurityManagerPtr mgr,
                                           virDomainDefPtr def)
{
    /* TODO: verify DOI */
    virSecurityLabelDefPtr secdef;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (secdef == NULL)
        return -1;

    if (secdef->label == NULL)
        return 0;

    if (!STREQ(virSecurityManagerGetModel(mgr), secdef->model)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security label driver mismatch: "
                         "'%s' model configured for domain, but "
                         "hypervisor driver is '%s'."),
                       secdef->model, virSecurityManagerGetModel(mgr));
        if (security_getenforce() == 1)
            return -1;
    }

    if (setsockcreatecon(NULL) == -1) {
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
                                             virDomainChrDefPtr dev,
                                             void *opaque ATTRIBUTE_UNUSED)
{
    /* This is taken care of by processing of def->serials */
    if (dev->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
        dev->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL)
        return 0;

    return virSecuritySELinuxSetSecurityChardevLabel(def, dev, &dev->source);
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
        return virSecuritySELinuxSetFilecon(database, data->content_context);

    case VIR_DOMAIN_SMARTCARD_TYPE_PASSTHROUGH:
        return virSecuritySELinuxSetSecurityChardevLabel(def, NULL, &dev->data.passthru);

    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown smartcard type %d"),
                       dev->type);
        return -1;
    }

    return 0;
}


static int
virSecuritySELinuxSetSecurityAllLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr def,
                                      const char *stdin_path)
{
    int i;
    virSecuritySELinuxDataPtr data = virSecurityManagerGetPrivateData(mgr);
    virSecurityLabelDefPtr secdef;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (secdef == NULL)
        return -1;

    if (secdef->norelabel)
        return 0;

    for (i = 0 ; i < def->ndisks ; i++) {
        /* XXX fixme - we need to recursively label the entire tree :-( */
        if (def->disks[i]->type == VIR_DOMAIN_DISK_TYPE_DIR) {
            VIR_WARN("Unable to relabel directory tree %s for disk %s",
                     def->disks[i]->src, def->disks[i]->dst);
            continue;
        }
        if (virSecuritySELinuxSetSecurityImageLabel(mgr,
                                         def, def->disks[i]) < 0)
            return -1;
    }
    /* XXX fixme process  def->fss if relabel == true */

    for (i = 0 ; i < def->nhostdevs ; i++) {
        if (virSecuritySELinuxSetSecurityHostdevLabel(mgr,
                                           def,
                                           def->hostdevs[i]) < 0)
            return -1;
    }

    if (virDomainChrDefForeach(def,
                               true,
                               virSecuritySELinuxSetSecurityChardevCallback,
                               NULL) < 0)
        return -1;

    if (virDomainSmartcardDefForeach(def,
                                     true,
                                     virSecuritySELinuxSetSecuritySmartcardCallback,
                                     mgr) < 0)
        return -1;

    if (def->os.kernel &&
        virSecuritySELinuxSetFilecon(def->os.kernel, data->content_context) < 0)
        return -1;

    if (def->os.initrd &&
        virSecuritySELinuxSetFilecon(def->os.initrd, data->content_context) < 0)
        return -1;

    if (stdin_path) {
        if (virSecuritySELinuxSetFilecon(stdin_path, data->content_context) < 0 &&
            virStorageFileIsSharedFSType(stdin_path,
                                         VIR_STORAGE_FILE_SHFS_NFS) != 1)
            return -1;
    }

    return 0;
}

static int
virSecuritySELinuxSetImageFDLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                  virDomainDefPtr def,
                                  int fd)
{
    virSecurityLabelDefPtr secdef;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (secdef == NULL)
        return -1;

    if (secdef->imagelabel == NULL)
        return 0;

    return virSecuritySELinuxFSetFilecon(fd, secdef->imagelabel);
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
    const char *mcs = NULL;

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (secdef == NULL)
        goto cleanup;

    if (secdef->label) {
        ctx = context_new(secdef->label);
        if (!ctx) {
            virReportOOMError();
            goto cleanup;
        }
        range = context_range_get(ctx);
        if (range) {
            mcs = strdup(range);
            if (!mcs) {
                virReportOOMError();
                goto cleanup;
            }
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

    secdef = virDomainDefGetSecurityLabelDef(def, SECURITY_SELINUX_NAME);
    if (secdef == NULL)
        return NULL;

    if (! secdef->imagelabel)
        secdef->imagelabel = virSecuritySELinuxGenImageLabel(mgr,def);

    if (secdef->imagelabel) {
        virAsprintf(&opts,
                    ",context=\"%s\"",
                    (const char*) secdef->imagelabel);
    }

    VIR_DEBUG("imageLabel=%s", secdef->imagelabel);
    return opts;
}

virSecurityDriver virSecurityDriverSELinux = {
    .privateDataLen                     = sizeof(virSecuritySELinuxData),
    .name                               = SECURITY_SELINUX_NAME,
    .probe                              = virSecuritySELinuxSecurityDriverProbe,
    .open                               = virSecuritySELinuxSecurityDriverOpen,
    .close                              = virSecuritySELinuxSecurityDriverClose,

    .getModel                           = virSecuritySELinuxSecurityGetModel,
    .getDOI                             = virSecuritySELinuxSecurityGetDOI,

    .domainSecurityVerify               = virSecuritySELinuxSecurityVerify,

    .domainSetSecurityImageLabel        = virSecuritySELinuxSetSecurityImageLabel,
    .domainRestoreSecurityImageLabel    = virSecuritySELinuxRestoreSecurityImageLabel,

    .domainSetSecurityDaemonSocketLabel = virSecuritySELinuxSetSecurityDaemonSocketLabel,
    .domainSetSecuritySocketLabel       = virSecuritySELinuxSetSecuritySocketLabel,
    .domainClearSecuritySocketLabel     = virSecuritySELinuxClearSecuritySocketLabel,

    .domainGenSecurityLabel             = virSecuritySELinuxGenSecurityLabel,
    .domainReserveSecurityLabel         = virSecuritySELinuxReserveSecurityLabel,
    .domainReleaseSecurityLabel         = virSecuritySELinuxReleaseSecurityLabel,

    .domainGetSecurityProcessLabel      = virSecuritySELinuxGetSecurityProcessLabel,
    .domainSetSecurityProcessLabel      = virSecuritySELinuxSetSecurityProcessLabel,

    .domainSetSecurityAllLabel          = virSecuritySELinuxSetSecurityAllLabel,
    .domainRestoreSecurityAllLabel      = virSecuritySELinuxRestoreSecurityAllLabel,

    .domainSetSecurityHostdevLabel      = virSecuritySELinuxSetSecurityHostdevLabel,
    .domainRestoreSecurityHostdevLabel  = virSecuritySELinuxRestoreSecurityHostdevLabel,

    .domainSetSavedStateLabel           = virSecuritySELinuxSetSavedStateLabel,
    .domainRestoreSavedStateLabel       = virSecuritySELinuxRestoreSavedStateLabel,

    .domainSetSecurityImageFDLabel      = virSecuritySELinuxSetImageFDLabel,

    .domainGetSecurityMountOptions      = virSecuritySELinuxGetSecurityMountOptions,
};
