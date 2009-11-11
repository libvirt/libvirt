/*
 * Copyright (C) 2008,2009 Red Hat, Inc.
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

#include "security_driver.h"
#include "security_selinux.h"
#include "virterror_internal.h"
#include "util.h"
#include "memory.h"
#include "logging.h"
#include "pci.h"
#include "hostusb.h"
#include "storage_file.h"

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
            free(ptr->mcs);
            free(ptr);
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
    if (!scontext) goto err;
    context_t con = context_new(scontext);
    if (!con) goto err;
    context_range_set(con, mcs);
    newcontext = strdup(context_str(con));
    context_free(con);
err:
    freecon(scontext);
    return (newcontext);
}

static int
SELinuxInitialize(virConnectPtr conn)
{
    char *ptr = NULL;
    int fd = 0;

    fd = open(selinux_virtual_domain_context_path(), O_RDONLY);
    if (fd < 0) {
        virReportSystemError(conn, errno,
                             _("cannot open SELinux virtual domain context file '%s'"),
                             selinux_virtual_domain_context_path());
        return -1;
    }

    if (saferead(fd, default_domain_context, sizeof(default_domain_context)) < 0) {
        virReportSystemError(conn, errno,
                             _("cannot read SELinux virtual domain context file %s"),
                             selinux_virtual_domain_context_path());
        close(fd);
        return -1;
    }
    close(fd);

    ptr = strchrnul(default_domain_context, '\n');
    *ptr = '\0';

    if ((fd = open(selinux_virtual_image_context_path(), O_RDONLY)) < 0) {
        virReportSystemError(conn, errno,
                             _("cannot open SELinux virtual image context file %s"),
                             selinux_virtual_image_context_path());
        return -1;
    }

    if (saferead(fd, default_image_context, sizeof(default_image_context)) < 0) {
        virReportSystemError(conn, errno,
                             _("cannot read SELinux virtual image context file %s"),
                             selinux_virtual_image_context_path());
        close(fd);
        return -1;
    }
    close(fd);

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
SELinuxGenSecurityLabel(virConnectPtr conn,
                        virDomainObjPtr vm)
{
    int rc = -1;
    char mcs[1024];
    char *scontext = NULL;
    int c1 = 0;
    int c2 = 0;

    if (vm->def->seclabel.label ||
        vm->def->seclabel.model ||
        vm->def->seclabel.imagelabel) {
        virSecurityReportError(conn, VIR_ERR_INTERNAL_ERROR,
                               "%s", _("security label already defined for VM"));
        return rc;
    }

    do {
        c1 = virRandom(1024);
        c2 = virRandom(1024);

        if ( c1 == c2 ) {
            sprintf(mcs, "s0:c%d", c1);
        } else {
            if ( c1 < c2 )
                sprintf(mcs, "s0:c%d,c%d", c1, c2);
            else
                sprintf(mcs, "s0:c%d,c%d", c2, c1);
        }
    } while(mcsAdd(mcs) == -1);

    vm->def->seclabel.label = SELinuxGenNewContext(default_domain_context, mcs);
    if (! vm->def->seclabel.label)  {
        virSecurityReportError(conn, VIR_ERR_INTERNAL_ERROR,
                               _("cannot generate selinux context for %s"), mcs);
        goto err;
    }
    vm->def->seclabel.imagelabel = SELinuxGenNewContext(default_image_context, mcs);
    if (! vm->def->seclabel.imagelabel)  {
        virSecurityReportError(conn, VIR_ERR_INTERNAL_ERROR,
                               _("cannot generate selinux context for %s"), mcs);
        goto err;
    }
    vm->def->seclabel.model = strdup(SECURITY_SELINUX_NAME);
    if (!vm->def->seclabel.model) {
        virReportOOMError(conn);
        goto err;
    }


    rc = 0;
    goto done;
err:
    VIR_FREE(vm->def->seclabel.label);
    VIR_FREE(vm->def->seclabel.imagelabel);
    VIR_FREE(vm->def->seclabel.model);
done:
    VIR_FREE(scontext);
    return rc;
}

static int
SELinuxReserveSecurityLabel(virConnectPtr conn,
                            virDomainObjPtr vm)
{
    security_context_t pctx;
    context_t ctx = NULL;
    const char *mcs;

    if (getpidcon(vm->pid, &pctx) == -1) {
        virReportSystemError(conn, errno,
                             _("unable to get PID %d security context"), vm->pid);
        return -1;
    }

    ctx = context_new(pctx);
    VIR_FREE(pctx);
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
SELinuxSecurityDriverOpen(virConnectPtr conn, virSecurityDriverPtr drv)
{
    /*
     * Where will the DOI come from?  SELinux configuration, or qemu
     * configuration? For the moment, we'll just set it to "0".
     */
    virSecurityDriverSetDOI(conn, drv, SECURITY_SELINUX_VOID_DOI);
    return SELinuxInitialize(conn);
}

static int
SELinuxGetSecurityLabel(virConnectPtr conn,
                        virDomainObjPtr vm,
                        virSecurityLabelPtr sec)
{
    security_context_t ctx;

    if (getpidcon(vm->pid, &ctx) == -1) {
        virReportSystemError(conn, errno,
                             _("unable to get PID %d security context"),
                             vm->pid);
        return -1;
    }

    if (strlen((char *) ctx) >= VIR_SECURITY_LABEL_BUFLEN) {
        virSecurityReportError(conn, VIR_ERR_INTERNAL_ERROR,
                               _("security label exceeds "
                                 "maximum length: %d"),
                               VIR_SECURITY_LABEL_BUFLEN - 1);
        return -1;
    }

    strcpy(sec->label, (char *) ctx);
    free(ctx);

    sec->enforcing = security_getenforce();
    if (sec->enforcing == -1) {
        virReportSystemError(conn, errno, "%s",
                             _("error calling security_getenforce()"));
        return -1;
    }

    return 0;
}

static int
SELinuxSetFilecon(virConnectPtr conn, const char *path, char *tcon)
{
    security_context_t econ;

    VIR_INFO("Setting SELinux context on '%s' to '%s'", path, tcon);

    if (setfilecon(path, tcon) < 0) {
        int setfilecon_errno = errno;

        if (getfilecon(path, &econ) >= 0) {
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
        if (setfilecon_errno != EOPNOTSUPP) {
            virReportSystemError(conn, setfilecon_errno,
                                 _("unable to set security context '%s' on '%s'"),
                                 tcon, path);
            if (security_getenforce() == 1)
                return -1;
        } else {
            VIR_INFO("Setting security context '%s' on '%s' not supported",
                     tcon, path);
        }
    }
    return 0;
}

static int
SELinuxRestoreSecurityFileLabel(virConnectPtr conn,
                                const char *path)
{
    struct stat buf;
    security_context_t fcon = NULL;
    int rc = -1;
    int err;
    char *newpath = NULL;

    VIR_INFO("Restoring SELinux context on '%s'", path);

    if ((err = virFileResolveLink(path, &newpath)) < 0) {
        virReportSystemError(conn, err,
                             _("cannot resolve symlink %s"), path);
        goto err;
    }

    if (stat(newpath, &buf) != 0)
        goto err;

    if (matchpathcon(newpath, buf.st_mode, &fcon) == 0)  {
        rc = SELinuxSetFilecon(conn, newpath, fcon);
    }
err:
    VIR_FREE(fcon);
    VIR_FREE(newpath);
    return rc;
}

static int
SELinuxRestoreSecurityImageLabel(virConnectPtr conn,
                                 virDomainObjPtr vm ATTRIBUTE_UNUSED,
                                 virDomainDiskDefPtr disk)
{
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

    if (!disk->src)
        return 0;

    return SELinuxRestoreSecurityFileLabel(conn, disk->src);
}

static int
SELinuxSetSecurityImageLabel(virConnectPtr conn,
                             virDomainObjPtr vm,
                             virDomainDiskDefPtr disk)

{
    const virSecurityLabelDefPtr secdef = &vm->def->seclabel;
    const char *path;

    if (!disk->src)
        return 0;

    path = disk->src;
    do {
        virStorageFileMetadata meta;
        int ret;

        memset(&meta, 0, sizeof(meta));

        ret = virStorageFileGetMetadata(conn, path, &meta);

        if (path != disk->src)
            VIR_FREE(path);
        path = NULL;

        if (ret < 0)
            return -1;

        if (meta.backingStore != NULL &&
            SELinuxSetFilecon(conn, meta.backingStore,
                              default_content_context) < 0) {
            VIR_FREE(meta.backingStore);
            return -1;
        }

        path = meta.backingStore;
    } while (path != NULL);

    if (disk->shared) {
        return SELinuxSetFilecon(conn, disk->src, default_image_context);
    } else if (disk->readonly) {
        return SELinuxSetFilecon(conn, disk->src, default_content_context);
    } else if (secdef->imagelabel) {
        return SELinuxSetFilecon(conn, disk->src, secdef->imagelabel);
    }

    return 0;
}


static int
SELinuxSetSecurityPCILabel(virConnectPtr conn,
                           pciDevice *dev ATTRIBUTE_UNUSED,
                           const char *file, void *opaque)
{
    virDomainObjPtr vm = opaque;
    const virSecurityLabelDefPtr secdef = &vm->def->seclabel;

    return SELinuxSetFilecon(conn, file, secdef->imagelabel);
}

static int
SELinuxSetSecurityUSBLabel(virConnectPtr conn,
                           usbDevice *dev ATTRIBUTE_UNUSED,
                           const char *file, void *opaque)
{
    virDomainObjPtr vm = opaque;
    const virSecurityLabelDefPtr secdef = &vm->def->seclabel;

    return SELinuxSetFilecon(conn, file, secdef->imagelabel);
}

static int
SELinuxSetSecurityHostdevLabel(virConnectPtr conn,
                               virDomainObjPtr vm,
                               virDomainHostdevDefPtr dev)

{
    int ret = -1;

    if (dev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
        return 0;

    switch (dev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB: {
        if (dev->source.subsys.u.usb.bus && dev->source.subsys.u.usb.device) {
            usbDevice *usb = usbGetDevice(conn,
                                          dev->source.subsys.u.usb.bus,
                                          dev->source.subsys.u.usb.device);

            if (!usb)
                goto done;

            ret = usbDeviceFileIterate(conn, usb, SELinuxSetSecurityUSBLabel, vm);
            usbFreeDevice(conn, usb);
        } else {
            /* XXX deal with product/vendor better */
            ret = 0;
        }
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI: {
        pciDevice *pci = pciGetDevice(conn,
                                      dev->source.subsys.u.pci.domain,
                                      dev->source.subsys.u.pci.bus,
                                      dev->source.subsys.u.pci.slot,
                                      dev->source.subsys.u.pci.function);

        if (!pci)
            goto done;

        ret = pciDeviceFileIterate(conn, pci, SELinuxSetSecurityPCILabel, vm);
        pciFreeDevice(conn, pci);

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
SELinuxRestoreSecurityPCILabel(virConnectPtr conn,
                               pciDevice *dev ATTRIBUTE_UNUSED,
                               const char *file,
                               void *opaque ATTRIBUTE_UNUSED)
{
    return SELinuxRestoreSecurityFileLabel(conn, file);
}

static int
SELinuxRestoreSecurityUSBLabel(virConnectPtr conn,
                               usbDevice *dev ATTRIBUTE_UNUSED,
                               const char *file,
                               void *opaque ATTRIBUTE_UNUSED)
{
    return SELinuxRestoreSecurityFileLabel(conn, file);
}

static int
SELinuxRestoreSecurityHostdevLabel(virConnectPtr conn,
                                   virDomainHostdevDefPtr dev)

{
    int ret = -1;

    if (dev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
        return 0;

    switch (dev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB: {
        usbDevice *usb = usbGetDevice(conn,
                                      dev->source.subsys.u.usb.bus,
                                      dev->source.subsys.u.usb.device);

        if (!usb)
            goto done;

        ret = usbDeviceFileIterate(conn, usb, SELinuxRestoreSecurityUSBLabel, NULL);
        usbFreeDevice(conn, usb);

        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI: {
        pciDevice *pci = pciGetDevice(conn,
                                      dev->source.subsys.u.pci.domain,
                                      dev->source.subsys.u.pci.bus,
                                      dev->source.subsys.u.pci.slot,
                                      dev->source.subsys.u.pci.function);

        if (!pci)
            goto done;

        ret = pciDeviceFileIterate(conn, pci, SELinuxRestoreSecurityPCILabel, NULL);
        pciFreeDevice(conn, pci);

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
SELinuxRestoreSecurityLabel(virConnectPtr conn,
                            virDomainObjPtr vm)
{
    const virSecurityLabelDefPtr secdef = &vm->def->seclabel;
    int i;
    int rc = 0;

    VIR_DEBUG("Restoring security label on %s", vm->def->name);

    if (secdef->imagelabel) {
        for (i = 0 ; i < vm->def->nhostdevs ; i++) {
            if (SELinuxRestoreSecurityHostdevLabel(conn, vm->def->hostdevs[i]) < 0)
                rc = -1;
        }
        for (i = 0 ; i < vm->def->ndisks ; i++) {
            if (SELinuxRestoreSecurityImageLabel(conn, vm,
                                                 vm->def->disks[i]) < 0)
                rc = -1;
        }
        VIR_FREE(secdef->model);
        VIR_FREE(secdef->label);
        context_t con = context_new(secdef->imagelabel);
        if (con) {
            mcsRemove(context_range_get(con));
            context_free(con);
        }
        VIR_FREE(secdef->imagelabel);
    }
    return rc;
}


static int
SELinuxSetSavedStateLabel(virConnectPtr conn,
                          virDomainObjPtr vm,
                          const char *savefile)
{
    const virSecurityLabelDefPtr secdef = &vm->def->seclabel;

    return SELinuxSetFilecon(conn, savefile, secdef->imagelabel);
}


static int
SELinuxRestoreSavedStateLabel(virConnectPtr conn,
                              const char *savefile)
{
    return SELinuxRestoreSecurityFileLabel(conn, savefile);
}


static int
SELinuxSecurityVerify(virConnectPtr conn, virDomainDefPtr def)
{
    const virSecurityLabelDefPtr secdef = &def->seclabel;
    if (secdef->type == VIR_DOMAIN_SECLABEL_STATIC) {
        if (security_check_context(secdef->label) != 0) {
            virSecurityReportError(conn, VIR_ERR_XML_ERROR,
                                   _("Invalid security label %s"), secdef->label);
            return -1;
        }
    }
    return 0;
}

static int
SELinuxSetSecurityLabel(virConnectPtr conn,
                        virSecurityDriverPtr drv,
                        virDomainObjPtr vm)
{
    /* TODO: verify DOI */
    const virSecurityLabelDefPtr secdef = &vm->def->seclabel;
    int i;

    if (!STREQ(drv->name, secdef->model)) {
        virSecurityReportError(conn, VIR_ERR_INTERNAL_ERROR,
                               _("security label driver mismatch: "
                                 "'%s' model configured for domain, but "
                                 "hypervisor driver is '%s'."),
                               secdef->model, drv->name);
        if (security_getenforce() == 1)
            return -1;
    }

    if (setexeccon(secdef->label) == -1) {
        virReportSystemError(conn, errno,
                             _("unable to set security context '%s'"),
                             secdef->label);
        if (security_getenforce() == 1)
            return -1;
    }

    if (secdef->imagelabel) {
        for (i = 0 ; i < vm->def->ndisks ; i++) {
            if (SELinuxSetSecurityImageLabel(conn, vm, vm->def->disks[i]) < 0)
                return -1;
        }
        for (i = 0 ; i < vm->def->nhostdevs ; i++) {
            if (SELinuxSetSecurityHostdevLabel(conn, vm, vm->def->hostdevs[i]) < 0)
                return -1;
        }
    }

    return 0;
}

virSecurityDriver virSELinuxSecurityDriver = {
    .name                       = SECURITY_SELINUX_NAME,
    .probe                      = SELinuxSecurityDriverProbe,
    .open                       = SELinuxSecurityDriverOpen,
    .domainSecurityVerify       = SELinuxSecurityVerify,
    .domainSetSecurityImageLabel = SELinuxSetSecurityImageLabel,
    .domainRestoreSecurityImageLabel = SELinuxRestoreSecurityImageLabel,
    .domainGenSecurityLabel     = SELinuxGenSecurityLabel,
    .domainReserveSecurityLabel     = SELinuxReserveSecurityLabel,
    .domainGetSecurityLabel     = SELinuxGetSecurityLabel,
    .domainRestoreSecurityLabel = SELinuxRestoreSecurityLabel,
    .domainSetSecurityLabel     = SELinuxSetSecurityLabel,
    .domainSetSecurityHostdevLabel = SELinuxSetSecurityHostdevLabel,
    .domainRestoreSecurityHostdevLabel = SELinuxRestoreSecurityHostdevLabel,
    .domainSetSavedStateLabel = SELinuxSetSavedStateLabel,
    .domainRestoreSavedStateLabel = SELinuxRestoreSavedStateLabel,
};
