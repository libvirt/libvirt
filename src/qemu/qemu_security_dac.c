/*
 * Copyright (C) 2010 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * QEMU POSIX DAC security driver
 */
#include <config.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "qemu_security_dac.h"
#include "qemu_conf.h"
#include "datatypes.h"
#include "virterror_internal.h"
#include "util.h"
#include "memory.h"
#include "logging.h"
#include "pci.h"
#include "hostusb.h"
#include "storage_file.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

static struct qemud_driver *driver;

void qemuSecurityDACSetDriver(struct qemud_driver *newdriver)
{
    driver = newdriver;
}


static int
qemuSecurityDACSetOwnership(virConnectPtr conn, const char *path, int uid, int gid)
{
    VIR_INFO("Setting DAC context on '%s' to '%d:%d'", path, uid, gid);

    if (chown(path, uid, gid) < 0) {
        struct stat sb;
        int chown_errno = errno;

        if (stat(path, &sb) >= 0) {
            if (sb.st_uid == uid &&
                sb.st_gid == gid) {
                /* It's alright, there's nothing to change anyway. */
                return 0;
            }
        }

        /* if the error complaint is related to an image hosted on
         * an nfs mount, or a usbfs/sysfs filesystem not supporting
         * labelling, then just ignore it & hope for the best.
         * The user hopefully set one of the necessary qemuSecurityDAC
         * virt_use_{nfs,usb,pci}  boolean tunables to allow it...
         */
        if (chown_errno == EOPNOTSUPP) {
            VIR_INFO("Setting security context '%d:%d' on '%s' not supported by filesystem",
                     uid, gid, path);
        } else if (chown_errno == EPERM) {
            VIR_INFO("Setting security context '%d:%d' on '%s' not permitted",
                     uid, gid, path);
        } else if (chown_errno == EROFS) {
            VIR_INFO("Setting security context '%d:%d' on '%s' not possible on readonly filesystem",
                     uid, gid, path);
        } else {
            virReportSystemError(conn, chown_errno,
                                 _("unable to set security context '%d:%d' on '%s'"),
                                 uid, gid, path);
            return -1;
        }
    }
    return 0;
}

static int
qemuSecurityDACRestoreSecurityFileLabel(virConnectPtr conn,
                                        const char *path)
{
    struct stat buf;
    int rc = -1;
    int err;
    char *newpath = NULL;

    VIR_INFO("Restoring DAC context on '%s'", path);

    if ((err = virFileResolveLink(path, &newpath)) < 0) {
        virReportSystemError(conn, err,
                             _("cannot resolve symlink %s"), path);
        goto err;
    }

    if (stat(newpath, &buf) != 0)
        goto err;

    /* XXX record previous ownership */
    rc = qemuSecurityDACSetOwnership(conn, newpath, 0, 0);

err:
    VIR_FREE(newpath);
    return rc;
}


static int
qemuSecurityDACSetSecurityImageLabel(virConnectPtr conn,
                                     virDomainObjPtr vm ATTRIBUTE_UNUSED,
                                     virDomainDiskDefPtr disk)

{
    const char *path;

    if (!driver->privileged || !driver->dynamicOwnership)
        return 0;

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
            qemuSecurityDACSetOwnership(conn, meta.backingStore,
                                      driver->user, driver->group) < 0) {
            VIR_FREE(meta.backingStore);
            return -1;
        }

        path = meta.backingStore;
    } while (path != NULL);

    return qemuSecurityDACSetOwnership(conn, disk->src, driver->user, driver->group);
}


static int
qemuSecurityDACRestoreSecurityImageLabel(virConnectPtr conn,
                                         virDomainObjPtr vm ATTRIBUTE_UNUSED,
                                         virDomainDiskDefPtr disk)
{
    if (!driver->privileged || !driver->dynamicOwnership)
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

    if (!disk->src)
        return 0;

    return qemuSecurityDACRestoreSecurityFileLabel(conn, disk->src);
}


static int
qemuSecurityDACSetSecurityPCILabel(virConnectPtr conn,
                                   pciDevice *dev ATTRIBUTE_UNUSED,
                                   const char *file,
                                   void *opaque ATTRIBUTE_UNUSED)
{
    return qemuSecurityDACSetOwnership(conn, file, driver->user, driver->group);
}


static int
qemuSecurityDACSetSecurityUSBLabel(virConnectPtr conn,
                                   usbDevice *dev ATTRIBUTE_UNUSED,
                                   const char *file,
                                   void *opaque ATTRIBUTE_UNUSED)
{
    return qemuSecurityDACSetOwnership(conn, file, driver->user, driver->group);
}


static int
qemuSecurityDACSetSecurityHostdevLabel(virConnectPtr conn,
                                       virDomainObjPtr vm,
                                       virDomainHostdevDefPtr dev)

{
    int ret = -1;

    if (!driver->privileged || !driver->dynamicOwnership)
        return 0;

    if (dev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
        return 0;

    switch (dev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB: {
        usbDevice *usb = usbGetDevice(conn,
                                      dev->source.subsys.u.usb.bus,
                                      dev->source.subsys.u.usb.device,
                                      dev->source.subsys.u.usb.vendor,
                                      dev->source.subsys.u.usb.product);

        if (!usb)
            goto done;

        ret = usbDeviceFileIterate(conn, usb, qemuSecurityDACSetSecurityUSBLabel, vm);
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

        ret = pciDeviceFileIterate(conn, pci, qemuSecurityDACSetSecurityPCILabel, vm);
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
qemuSecurityDACRestoreSecurityPCILabel(virConnectPtr conn,
                                       pciDevice *dev ATTRIBUTE_UNUSED,
                                       const char *file,
                                       void *opaque ATTRIBUTE_UNUSED)
{
    return qemuSecurityDACRestoreSecurityFileLabel(conn, file);
}


static int
qemuSecurityDACRestoreSecurityUSBLabel(virConnectPtr conn,
                                       usbDevice *dev ATTRIBUTE_UNUSED,
                                       const char *file,
                                       void *opaque ATTRIBUTE_UNUSED)
{
    return qemuSecurityDACRestoreSecurityFileLabel(conn, file);
}


static int
qemuSecurityDACRestoreSecurityHostdevLabel(virConnectPtr conn,
                                           virDomainObjPtr vm ATTRIBUTE_UNUSED,
                                           virDomainHostdevDefPtr dev)

{
    int ret = -1;

    if (!driver->privileged || !driver->dynamicOwnership)
        return 0;

    if (dev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
        return 0;

    switch (dev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB: {
        usbDevice *usb = usbGetDevice(conn,
                                      dev->source.subsys.u.usb.bus,
                                      dev->source.subsys.u.usb.device,
                                      dev->source.subsys.u.usb.vendor,
                                      dev->source.subsys.u.usb.product);

        if (!usb)
            goto done;

        ret = usbDeviceFileIterate(conn, usb, qemuSecurityDACRestoreSecurityUSBLabel, NULL);
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

        ret = pciDeviceFileIterate(conn, pci, qemuSecurityDACRestoreSecurityPCILabel, NULL);
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
qemuSecurityDACRestoreSecurityAllLabel(virConnectPtr conn,
                                       virDomainObjPtr vm)
{
    int i;
    int rc = 0;

    if (!driver->privileged || !driver->dynamicOwnership)
        return 0;

    VIR_DEBUG("Restoring security label on %s", vm->def->name);

    for (i = 0 ; i < vm->def->nhostdevs ; i++) {
        if (qemuSecurityDACRestoreSecurityHostdevLabel(conn, vm,
                                                       vm->def->hostdevs[i]) < 0)
            rc = -1;
    }
    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (qemuSecurityDACRestoreSecurityImageLabel(conn, vm,
                                                     vm->def->disks[i]) < 0)
            rc = -1;
    }
    return rc;
}


static int
qemuSecurityDACSetSecurityAllLabel(virConnectPtr conn,
                                   virDomainObjPtr vm)
{
    int i;

    if (!driver->privileged || !driver->dynamicOwnership)
        return 0;

    for (i = 0 ; i < vm->def->ndisks ; i++) {
        /* XXX fixme - we need to recursively label the entriy tree :-( */
        if (vm->def->disks[i]->type == VIR_DOMAIN_DISK_TYPE_DIR)
            continue;
        if (qemuSecurityDACSetSecurityImageLabel(conn, vm, vm->def->disks[i]) < 0)
            return -1;
    }
    for (i = 0 ; i < vm->def->nhostdevs ; i++) {
        if (qemuSecurityDACSetSecurityHostdevLabel(conn, vm, vm->def->hostdevs[i]) < 0)
            return -1;
    }

    return 0;
}


static int
qemuSecurityDACSetSavedStateLabel(virConnectPtr conn,
                                  virDomainObjPtr vm ATTRIBUTE_UNUSED,
                                  const char *savefile)
{
    if (!driver->privileged || !driver->dynamicOwnership)
        return 0;

    return qemuSecurityDACSetOwnership(conn, savefile, driver->user, driver->group);
}


static int
qemuSecurityDACRestoreSavedStateLabel(virConnectPtr conn,
                                      virDomainObjPtr vm ATTRIBUTE_UNUSED,
                                      const char *savefile)
{
    if (!driver->privileged || !driver->dynamicOwnership)
        return 0;

    return qemuSecurityDACRestoreSecurityFileLabel(conn, savefile);
}


static int
qemuSecurityDACSetProcessLabel(virConnectPtr conn ATTRIBUTE_UNUSED,
                               virSecurityDriverPtr drv ATTRIBUTE_UNUSED,
                               virDomainObjPtr vm ATTRIBUTE_UNUSED)
{
    DEBUG("Dropping privileges of VM to %d:%d", driver->user, driver->group);

    if (!driver->privileged)
        return 0;

    if (driver->group) {
        if (setregid(driver->group, driver->group) < 0) {
            virReportSystemError(NULL, errno,
                                 _("cannot change to '%d' group"),
                                 driver->group);
            return -1;
        }
    }
    if (driver->user) {
        if (setreuid(driver->user, driver->user) < 0) {
            virReportSystemError(NULL, errno,
                                 _("cannot change to '%d' user"),
                                 driver->user);
            return -1;
        }
    }

    return 0;
}



virSecurityDriver qemuDACSecurityDriver = {
    .name                       = "qemuDAC",

    .domainSetSecurityProcessLabel = qemuSecurityDACSetProcessLabel,

    .domainSetSecurityImageLabel = qemuSecurityDACSetSecurityImageLabel,
    .domainRestoreSecurityImageLabel = qemuSecurityDACRestoreSecurityImageLabel,

    .domainSetSecurityAllLabel     = qemuSecurityDACSetSecurityAllLabel,
    .domainRestoreSecurityAllLabel = qemuSecurityDACRestoreSecurityAllLabel,

    .domainSetSecurityHostdevLabel = qemuSecurityDACSetSecurityHostdevLabel,
    .domainRestoreSecurityHostdevLabel = qemuSecurityDACRestoreSecurityHostdevLabel,

    .domainSetSavedStateLabel = qemuSecurityDACSetSavedStateLabel,
    .domainRestoreSavedStateLabel = qemuSecurityDACRestoreSavedStateLabel,
};
