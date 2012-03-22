/*
 * Copyright (C) 2008-2011 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
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
#include "virrandom.h"

#define VIR_FROM_THIS VIR_FROM_SECURITY

static char default_domain_context[1024];
static char default_content_context[1024];
static char default_image_context[1024];
#define SECURITY_SELINUX_VOID_DOI       "0"
#define SECURITY_SELINUX_NAME "selinux"

/* TODO
   The data struct of used mcs should be replaced with a better data structure in the future
*/

struct MCS {
    char *mcs;
    struct MCS *next;
};
static struct MCS *mcsList = NULL;

static int
mcsAdd(const char *mcs)
{
    struct MCS *ptr;

    for (ptr = mcsList; ptr; ptr = ptr->next) {
        if (STREQ(ptr->mcs, mcs))
            return -1;
    }
    if (VIR_ALLOC(ptr) < 0)
        return -1;
    ptr->mcs = strdup(mcs);
    ptr->next = mcsList;
    mcsList = ptr;
    return 0;
}

static int
mcsRemove(const char *mcs)
{
    struct MCS *prevptr = NULL;
    struct MCS *ptr = NULL;

    for (ptr = mcsList; ptr; ptr = ptr->next) {
        if (STREQ(ptr->mcs, mcs)) {
            if (prevptr)
                prevptr->next = ptr->next;
            else {
                mcsList = ptr->next;
            }
            VIR_FREE(ptr->mcs);
            VIR_FREE(ptr);
            return 0;
        }
        prevptr = ptr;
    }
    return -1;
}

static char *
SELinuxGenNewContext(const char *oldcontext, const char *mcs)
{
    char *newcontext = NULL;
    char *scontext = strdup(oldcontext);
    context_t con;
    if (!scontext) goto err;
    con = context_new(scontext);
    if (!con) goto err;
    context_range_set(con, mcs);
    newcontext = strdup(context_str(con));
    context_free(con);
err:
    freecon(scontext);
    return newcontext;
}

static int
SELinuxInitialize(void)
{
    char *ptr = NULL;
    int fd = 0;

    fd = open(selinux_virtual_domain_context_path(), O_RDONLY);
    if (fd < 0) {
        virReportSystemError(errno,
                             _("cannot open SELinux virtual domain context file '%s'"),
                             selinux_virtual_domain_context_path());
        return -1;
    }

    if (saferead(fd, default_domain_context, sizeof(default_domain_context)) < 0) {
        virReportSystemError(errno,
                             _("cannot read SELinux virtual domain context file %s"),
                             selinux_virtual_domain_context_path());
        VIR_FORCE_CLOSE(fd);
        return -1;
    }
    VIR_FORCE_CLOSE(fd);

    ptr = strchrnul(default_domain_context, '\n');
    *ptr = '\0';

    if ((fd = open(selinux_virtual_image_context_path(), O_RDONLY)) < 0) {
        virReportSystemError(errno,
                             _("cannot open SELinux virtual image context file %s"),
                             selinux_virtual_image_context_path());
        return -1;
    }

    if (saferead(fd, default_image_context, sizeof(default_image_context)) < 0) {
        virReportSystemError(errno,
                             _("cannot read SELinux virtual image context file %s"),
                             selinux_virtual_image_context_path());
        VIR_FORCE_CLOSE(fd);
        return -1;
    }
    VIR_FORCE_CLOSE(fd);

    ptr = strchrnul(default_image_context, '\n');
    if (*ptr == '\n') {
        *ptr = '\0';
        strcpy(default_content_context, ptr+1);
        ptr = strchrnul(default_content_context, '\n');
        if (*ptr == '\n')
            *ptr = '\0';
    }
    return 0;
}

static int
SELinuxGenSecurityLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                        virDomainDefPtr def)
{
    int rc = -1;
    char *mcs = NULL;
    char *scontext = NULL;
    int c1 = 0;
    int c2 = 0;
    context_t ctx = NULL;
    const char *range;

    if ((def->seclabel.type == VIR_DOMAIN_SECLABEL_DYNAMIC) &&
        !def->seclabel.baselabel &&
        def->seclabel.model) {
        virSecurityReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("security model already defined for VM"));
        return rc;
    }

    if (def->seclabel.type == VIR_DOMAIN_SECLABEL_DYNAMIC &&
        def->seclabel.label) {
        virSecurityReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("security label already defined for VM"));
        return rc;
    }

    if (def->seclabel.imagelabel) {
        virSecurityReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("security image label already defined for VM"));
        return rc;
    }

    if (def->seclabel.model &&
        STRNEQ(def->seclabel.model, SECURITY_SELINUX_NAME)) {
        virSecurityReportError(VIR_ERR_INTERNAL_ERROR,
                               _("security label model %s is not supported with selinux"),
                               def->seclabel.model);
        return rc;
    }

    switch (def->seclabel.type) {
    case VIR_DOMAIN_SECLABEL_STATIC:
        if (!(ctx = context_new(def->seclabel.label)) ) {
            virReportSystemError(errno,
                                 _("unable to allocate socket security context '%s'"),
                                 def->seclabel.label);
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
        do {
            c1 = virRandomBits(10);
            c2 = virRandomBits(10);

            if ( c1 == c2 ) {
                if (virAsprintf(&mcs, "s0:c%d", c1) < 0) {
                    virReportOOMError();
                    goto cleanup;
                }
            } else {
                if (c1 > c2) {
                    c1 ^= c2;
                    c2 ^= c1;
                    c1 ^= c2;
                }
                if (virAsprintf(&mcs, "s0:c%d,c%d", c1, c2) < 0) {
                    virReportOOMError();
                    goto cleanup;
                }
            }
        } while (mcsAdd(mcs) == -1);

        def->seclabel.label =
            SELinuxGenNewContext(def->seclabel.baselabel ?
                                 def->seclabel.baselabel :
                                 default_domain_context, mcs);
        if (! def->seclabel.label)  {
            virSecurityReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("cannot generate selinux context for %s"), mcs);
            goto cleanup;
        }
        break;

    case VIR_DOMAIN_SECLABEL_NONE:
        /* no op */
        break;

    default:
        virSecurityReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unexpected security label type '%s'"),
                               virDomainSeclabelTypeToString(def->seclabel.type));
        goto cleanup;
    }

    if (!def->seclabel.norelabel) {
        def->seclabel.imagelabel = SELinuxGenNewContext(default_image_context, mcs);
        if (!def->seclabel.imagelabel)  {
            virSecurityReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("cannot generate selinux context for %s"), mcs);
            goto cleanup;
        }
    }

    if (!def->seclabel.model &&
        !(def->seclabel.model = strdup(SECURITY_SELINUX_NAME))) {
        virReportOOMError();
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (rc != 0) {
        if (def->seclabel.type == VIR_DOMAIN_SECLABEL_DYNAMIC)
            VIR_FREE(def->seclabel.label);
        VIR_FREE(def->seclabel.imagelabel);
        if (def->seclabel.type == VIR_DOMAIN_SECLABEL_DYNAMIC &&
            !def->seclabel.baselabel)
            VIR_FREE(def->seclabel.model);
    }

    if (ctx)
        context_free(ctx);
    VIR_FREE(scontext);
    VIR_FREE(mcs);

    VIR_DEBUG("model=%s label=%s imagelabel=%s baselabel=%s",
              NULLSTR(def->seclabel.model),
              NULLSTR(def->seclabel.label),
              NULLSTR(def->seclabel.imagelabel),
              NULLSTR(def->seclabel.baselabel));

    return rc;
}

static int
SELinuxReserveSecurityLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                            virDomainDefPtr def,
                            pid_t pid)
{
    security_context_t pctx;
    context_t ctx = NULL;
    const char *mcs;

    if (def->seclabel.type == VIR_DOMAIN_SECLABEL_STATIC)
        return 0;

    if (getpidcon(pid, &pctx) == -1) {
        virReportSystemError(errno,
                             _("unable to get PID %d security context"), pid);
        return -1;
    }

    ctx = context_new(pctx);
    freecon(pctx);
    if (!ctx)
        goto err;

    mcs = context_range_get(ctx);
    if (!mcs)
        goto err;

    mcsAdd(mcs);

    context_free(ctx);

    return 0;

err:
    context_free(ctx);
    return -1;
}



static int
SELinuxSecurityDriverProbe(void)
{
    return is_selinux_enabled() ? SECURITY_DRIVER_ENABLE : SECURITY_DRIVER_DISABLE;
}

static int
SELinuxSecurityDriverOpen(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED)
{
    return SELinuxInitialize();
}

static int
SELinuxSecurityDriverClose(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED)
{
    return 0;
}


static const char *SELinuxSecurityGetModel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED)
{
    return SECURITY_SELINUX_NAME;
}

static const char *SELinuxSecurityGetDOI(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED)
{
    /*
     * Where will the DOI come from?  SELinux configuration, or qemu
     * configuration? For the moment, we'll just set it to "0".
     */
    return SECURITY_SELINUX_VOID_DOI;
}

static int
SELinuxGetSecurityProcessLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
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
        virSecurityReportError(VIR_ERR_INTERNAL_ERROR,
                               _("security label exceeds "
                                 "maximum length: %d"),
                               VIR_SECURITY_LABEL_BUFLEN - 1);
        freecon(ctx);
        return -1;
    }

    strcpy(sec->label, (char *) ctx);
    freecon(ctx);

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
SELinuxSetFileconHelper(const char *path, char *tcon, bool optional)
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
SELinuxSetFileconOptional(const char *path, char *tcon)
{
    return SELinuxSetFileconHelper(path, tcon, true);
}

static int
SELinuxSetFilecon(const char *path, char *tcon)
{
    return SELinuxSetFileconHelper(path, tcon, false);
}

static int
SELinuxFSetFilecon(int fd, char *tcon)
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
SELinuxRestoreSecurityFileLabel(const char *path)
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
        rc = SELinuxSetFilecon(newpath, fcon);
    }

err:
    freecon(fcon);
    VIR_FREE(newpath);
    return rc;
}

static int
SELinuxRestoreSecurityImageLabelInt(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                    virDomainDefPtr def,
                                    virDomainDiskDefPtr disk,
                                    int migrated)
{
    const virSecurityLabelDefPtr secdef = &def->seclabel;

    if (secdef->norelabel || (disk->seclabel && disk->seclabel->norelabel))
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

    return SELinuxRestoreSecurityFileLabel(disk->src);
}


static int
SELinuxRestoreSecurityImageLabel(virSecurityManagerPtr mgr,
                                 virDomainDefPtr def,
                                 virDomainDiskDefPtr disk)
{
    return SELinuxRestoreSecurityImageLabelInt(mgr, def, disk, 0);
}


static int
SELinuxSetSecurityFileLabel(virDomainDiskDefPtr disk,
                            const char *path,
                            size_t depth,
                            void *opaque)
{
    const virSecurityLabelDefPtr secdef = opaque;
    int ret;

    if (disk->seclabel && disk->seclabel->norelabel)
        return 0;

    if (disk->seclabel && !disk->seclabel->norelabel &&
        disk->seclabel->label) {
        ret = SELinuxSetFilecon(path, disk->seclabel->label);
    } else if (depth == 0) {
        if (disk->shared) {
            ret = SELinuxSetFileconOptional(path, default_image_context);
        } else if (disk->readonly) {
            ret = SELinuxSetFileconOptional(path, default_content_context);
        } else if (secdef->imagelabel) {
            ret = SELinuxSetFileconOptional(path, secdef->imagelabel);
        } else {
            ret = 0;
        }
    } else {
        ret = SELinuxSetFileconOptional(path, default_content_context);
    }
    if (ret == 1 && !disk->seclabel) {
        /* If we failed to set a label, but virt_use_nfs let us
         * proceed anyway, then we don't need to relabel later.  */
        if (VIR_ALLOC(disk->seclabel) < 0) {
            virReportOOMError();
            return -1;
        }
        disk->seclabel->norelabel = true;
        ret = 0;
    }
    return ret;
}

static int
SELinuxSetSecurityImageLabel(virSecurityManagerPtr mgr,
                             virDomainDefPtr def,
                             virDomainDiskDefPtr disk)

{
    const virSecurityLabelDefPtr secdef = &def->seclabel;
    bool allowDiskFormatProbing = virSecurityManagerGetAllowDiskFormatProbing(mgr);

    if (secdef->norelabel)
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
                                       SELinuxSetSecurityFileLabel,
                                       secdef);
}


static int
SELinuxSetSecurityPCILabel(pciDevice *dev ATTRIBUTE_UNUSED,
                           const char *file, void *opaque)
{
    virDomainDefPtr def = opaque;
    const virSecurityLabelDefPtr secdef = &def->seclabel;

    return SELinuxSetFilecon(file, secdef->imagelabel);
}

static int
SELinuxSetSecurityUSBLabel(usbDevice *dev ATTRIBUTE_UNUSED,
                           const char *file, void *opaque)
{
    virDomainDefPtr def = opaque;
    const virSecurityLabelDefPtr secdef = &def->seclabel;

    return SELinuxSetFilecon(file, secdef->imagelabel);
}

static int
SELinuxSetSecurityHostdevLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                               virDomainDefPtr def,
                               virDomainHostdevDefPtr dev)

{
    const virSecurityLabelDefPtr secdef = &def->seclabel;
    int ret = -1;

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

        ret = usbDeviceFileIterate(usb, SELinuxSetSecurityUSBLabel, def);
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

        ret = pciDeviceFileIterate(pci, SELinuxSetSecurityPCILabel, def);
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
SELinuxRestoreSecurityPCILabel(pciDevice *dev ATTRIBUTE_UNUSED,
                               const char *file,
                               void *opaque ATTRIBUTE_UNUSED)
{
    return SELinuxRestoreSecurityFileLabel(file);
}

static int
SELinuxRestoreSecurityUSBLabel(usbDevice *dev ATTRIBUTE_UNUSED,
                               const char *file,
                               void *opaque ATTRIBUTE_UNUSED)
{
    return SELinuxRestoreSecurityFileLabel(file);
}

static int
SELinuxRestoreSecurityHostdevLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                   virDomainDefPtr def,
                                   virDomainHostdevDefPtr dev)

{
    const virSecurityLabelDefPtr secdef = &def->seclabel;
    int ret = -1;

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

        ret = usbDeviceFileIterate(usb, SELinuxRestoreSecurityUSBLabel, NULL);
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

        ret = pciDeviceFileIterate(pci, SELinuxRestoreSecurityPCILabel, NULL);
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
SELinuxSetSecurityChardevLabel(virDomainDefPtr def,
                               virDomainChrSourceDefPtr dev)

{
    const virSecurityLabelDefPtr secdef = &def->seclabel;
    char *in = NULL, *out = NULL;
    int ret = -1;

    if (secdef->norelabel)
        return 0;

    switch (dev->type) {
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_FILE:
        ret = SELinuxSetFilecon(dev->data.file.path, secdef->imagelabel);
        break;

    case VIR_DOMAIN_CHR_TYPE_PIPE:
        if ((virAsprintf(&in, "%s.in", dev->data.file.path) < 0) ||
            (virAsprintf(&out, "%s.out", dev->data.file.path) < 0)) {
            virReportOOMError();
            goto done;
        }
        if (virFileExists(in) && virFileExists(out)) {
            if ((SELinuxSetFilecon(in, secdef->imagelabel) < 0) ||
                (SELinuxSetFilecon(out, secdef->imagelabel) < 0)) {
                goto done;
            }
        } else if (SELinuxSetFilecon(dev->data.file.path, secdef->imagelabel) < 0) {
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
SELinuxRestoreSecurityChardevLabel(virDomainDefPtr def,
                                   virDomainChrSourceDefPtr dev)

{
    const virSecurityLabelDefPtr secdef = &def->seclabel;
    char *in = NULL, *out = NULL;
    int ret = -1;

    if (secdef->norelabel)
        return 0;

    switch (dev->type) {
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_FILE:
        if (SELinuxRestoreSecurityFileLabel(dev->data.file.path) < 0)
            goto done;
        ret = 0;
        break;
    case VIR_DOMAIN_CHR_TYPE_PIPE:
        if ((virAsprintf(&out, "%s.out", dev->data.file.path) < 0) ||
            (virAsprintf(&in, "%s.in", dev->data.file.path) < 0)) {
            virReportOOMError();
            goto done;
        }
        if (virFileExists(in) && virFileExists(out)) {
            if ((SELinuxRestoreSecurityFileLabel(out) < 0) ||
                (SELinuxRestoreSecurityFileLabel(in) < 0)) {
                goto done;
            }
        } else if (SELinuxRestoreSecurityFileLabel(dev->data.file.path) < 0) {
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
SELinuxRestoreSecurityChardevCallback(virDomainDefPtr def,
                                      virDomainChrDefPtr dev,
                                      void *opaque ATTRIBUTE_UNUSED)
{
    /* This is taken care of by processing of def->serials */
    if (dev->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
        dev->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL)
        return 0;

    return SELinuxRestoreSecurityChardevLabel(def, &dev->source);
}


static int
SELinuxRestoreSecuritySmartcardCallback(virDomainDefPtr def,
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
        return SELinuxRestoreSecurityFileLabel(database);

    case VIR_DOMAIN_SMARTCARD_TYPE_PASSTHROUGH:
        return SELinuxRestoreSecurityChardevLabel(def, &dev->data.passthru);

    default:
        virSecurityReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unknown smartcard type %d"),
                               dev->type);
        return -1;
    }

    return 0;
}


static int
SELinuxRestoreSecurityAllLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                               virDomainDefPtr def,
                               int migrated ATTRIBUTE_UNUSED)
{
    const virSecurityLabelDefPtr secdef = &def->seclabel;
    int i;
    int rc = 0;

    VIR_DEBUG("Restoring security label on %s", def->name);

    if (secdef->norelabel)
        return 0;

    for (i = 0 ; i < def->nhostdevs ; i++) {
        if (SELinuxRestoreSecurityHostdevLabel(mgr,
                                               def,
                                               def->hostdevs[i]) < 0)
            rc = -1;
    }
    for (i = 0 ; i < def->ndisks ; i++) {
        if (SELinuxRestoreSecurityImageLabelInt(mgr,
                                                def,
                                                def->disks[i],
                                                migrated) < 0)
            rc = -1;
    }

    if (virDomainChrDefForeach(def,
                               false,
                               SELinuxRestoreSecurityChardevCallback,
                               NULL) < 0)
        rc = -1;

    if (virDomainSmartcardDefForeach(def,
                                     false,
                                     SELinuxRestoreSecuritySmartcardCallback,
                                     NULL) < 0)
        rc = -1;

    if (def->os.kernel &&
        SELinuxRestoreSecurityFileLabel(def->os.kernel) < 0)
        rc = -1;

    if (def->os.initrd &&
        SELinuxRestoreSecurityFileLabel(def->os.initrd) < 0)
        rc = -1;

    return rc;
}

static int
SELinuxReleaseSecurityLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                            virDomainDefPtr def)
{
    const virSecurityLabelDefPtr secdef = &def->seclabel;

    if (secdef->type == VIR_DOMAIN_SECLABEL_DYNAMIC) {
        if (secdef->label != NULL) {
            context_t con = context_new(secdef->label);
            if (con) {
                mcsRemove(context_range_get(con));
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
SELinuxSetSavedStateLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                          virDomainDefPtr def,
                          const char *savefile)
{
    const virSecurityLabelDefPtr secdef = &def->seclabel;

    if (secdef->norelabel)
        return 0;

    return SELinuxSetFilecon(savefile, secdef->imagelabel);
}


static int
SELinuxRestoreSavedStateLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                              virDomainDefPtr def,
                              const char *savefile)
{
    const virSecurityLabelDefPtr secdef = &def->seclabel;

    if (secdef->norelabel)
        return 0;

    return SELinuxRestoreSecurityFileLabel(savefile);
}


static int
SELinuxSecurityVerify(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                      virDomainDefPtr def)
{
    const virSecurityLabelDefPtr secdef = &def->seclabel;
    if (!STREQ(virSecurityManagerGetModel(mgr), secdef->model)) {
        virSecurityReportError(VIR_ERR_INTERNAL_ERROR,
                               _("security label driver mismatch: "
                                 "'%s' model configured for domain, but "
                                 "hypervisor driver is '%s'."),
                               secdef->model, virSecurityManagerGetModel(mgr));
        return -1;
    }

    if (secdef->type == VIR_DOMAIN_SECLABEL_STATIC) {
        if (security_check_context(secdef->label) != 0) {
            virSecurityReportError(VIR_ERR_XML_ERROR,
                                   _("Invalid security label %s"), secdef->label);
            return -1;
        }
    }
    return 0;
}

static int
SELinuxSetSecurityProcessLabel(virSecurityManagerPtr mgr,
                               virDomainDefPtr def)
{
    /* TODO: verify DOI */
    const virSecurityLabelDefPtr secdef = &def->seclabel;

    if (def->seclabel.label == NULL)
        return 0;

    if (!STREQ(virSecurityManagerGetModel(mgr), secdef->model)) {
        virSecurityReportError(VIR_ERR_INTERNAL_ERROR,
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
SELinuxSetSecurityDaemonSocketLabel(virSecurityManagerPtr mgr,
                                    virDomainDefPtr def)
{
    /* TODO: verify DOI */
    const virSecurityLabelDefPtr secdef = &def->seclabel;
    context_t execcon = NULL;
    context_t proccon = NULL;
    security_context_t scon = NULL;
    int rc = -1;

    if (def->seclabel.label == NULL)
        return 0;

    if (!STREQ(virSecurityManagerGetModel(mgr), secdef->model)) {
        virSecurityReportError(VIR_ERR_INTERNAL_ERROR,
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
SELinuxSetSecuritySocketLabel(virSecurityManagerPtr mgr,
                              virDomainDefPtr vm)
{
    const virSecurityLabelDefPtr secdef = &vm->seclabel;
    int rc = -1;

    if (secdef->label == NULL)
        return 0;

    if (!STREQ(virSecurityManagerGetModel(mgr), secdef->model)) {
        virSecurityReportError(VIR_ERR_INTERNAL_ERROR,
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
SELinuxClearSecuritySocketLabel(virSecurityManagerPtr mgr,
                                virDomainDefPtr def)
{
    /* TODO: verify DOI */
    const virSecurityLabelDefPtr secdef = &def->seclabel;

    if (def->seclabel.label == NULL)
        return 0;

    if (!STREQ(virSecurityManagerGetModel(mgr), secdef->model)) {
        virSecurityReportError(VIR_ERR_INTERNAL_ERROR,
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
SELinuxSetSecurityChardevCallback(virDomainDefPtr def,
                                  virDomainChrDefPtr dev,
                                  void *opaque ATTRIBUTE_UNUSED)
{
    /* This is taken care of by processing of def->serials */
    if (dev->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
        dev->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL)
        return 0;

    return SELinuxSetSecurityChardevLabel(def, &dev->source);
}


static int
SELinuxSetSecuritySmartcardCallback(virDomainDefPtr def,
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
        return SELinuxSetFilecon(database, default_content_context);

    case VIR_DOMAIN_SMARTCARD_TYPE_PASSTHROUGH:
        return SELinuxSetSecurityChardevLabel(def, &dev->data.passthru);

    default:
        virSecurityReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unknown smartcard type %d"),
                               dev->type);
        return -1;
    }

    return 0;
}


static int
SELinuxSetSecurityAllLabel(virSecurityManagerPtr mgr,
                           virDomainDefPtr def,
                           const char *stdin_path)
{
    const virSecurityLabelDefPtr secdef = &def->seclabel;
    int i;

    if (secdef->norelabel)
        return 0;

    for (i = 0 ; i < def->ndisks ; i++) {
        /* XXX fixme - we need to recursively label the entire tree :-( */
        if (def->disks[i]->type == VIR_DOMAIN_DISK_TYPE_DIR) {
            VIR_WARN("Unable to relabel directory tree %s for disk %s",
                     def->disks[i]->src, def->disks[i]->dst);
            continue;
        }
        if (SELinuxSetSecurityImageLabel(mgr,
                                         def, def->disks[i]) < 0)
            return -1;
    }
    /* XXX fixme process  def->fss if relabel == true */

    for (i = 0 ; i < def->nhostdevs ; i++) {
        if (SELinuxSetSecurityHostdevLabel(mgr,
                                           def,
                                           def->hostdevs[i]) < 0)
            return -1;
    }

    if (virDomainChrDefForeach(def,
                               true,
                               SELinuxSetSecurityChardevCallback,
                               NULL) < 0)
        return -1;

    if (virDomainSmartcardDefForeach(def,
                                     true,
                                     SELinuxSetSecuritySmartcardCallback,
                                     NULL) < 0)
        return -1;

    if (def->os.kernel &&
        SELinuxSetFilecon(def->os.kernel, default_content_context) < 0)
        return -1;

    if (def->os.initrd &&
        SELinuxSetFilecon(def->os.initrd, default_content_context) < 0)
        return -1;

    if (stdin_path) {
        if (SELinuxSetFilecon(stdin_path, default_content_context) < 0 &&
            virStorageFileIsSharedFSType(stdin_path,
                                         VIR_STORAGE_FILE_SHFS_NFS) != 1)
            return -1;
    }

    return 0;
}

static int
SELinuxSetImageFDLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                       virDomainDefPtr def,
                       int fd)
{
    const virSecurityLabelDefPtr secdef = &def->seclabel;

    if (secdef->imagelabel == NULL)
        return 0;

    return SELinuxFSetFilecon(fd, secdef->imagelabel);
}

virSecurityDriver virSecurityDriverSELinux = {
    0,
    SECURITY_SELINUX_NAME,
    SELinuxSecurityDriverProbe,
    SELinuxSecurityDriverOpen,
    SELinuxSecurityDriverClose,

    SELinuxSecurityGetModel,
    SELinuxSecurityGetDOI,

    SELinuxSecurityVerify,

    SELinuxSetSecurityImageLabel,
    SELinuxRestoreSecurityImageLabel,

    SELinuxSetSecurityDaemonSocketLabel,
    SELinuxSetSecuritySocketLabel,
    SELinuxClearSecuritySocketLabel,

    SELinuxGenSecurityLabel,
    SELinuxReserveSecurityLabel,
    SELinuxReleaseSecurityLabel,

    SELinuxGetSecurityProcessLabel,
    SELinuxSetSecurityProcessLabel,

    SELinuxSetSecurityAllLabel,
    SELinuxRestoreSecurityAllLabel,

    SELinuxSetSecurityHostdevLabel,
    SELinuxRestoreSecurityHostdevLabel,

    SELinuxSetSavedStateLabel,
    SELinuxRestoreSavedStateLabel,

    SELinuxSetImageFDLabel,
};
