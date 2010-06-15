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
qemuSecurityDACSetOwnership(const char *path, int uid, int gid)
{
    VIR_INFO("Setting DAC user and group on '%s' to '%d:%d'", path, uid, gid);

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

        if (chown_errno == EOPNOTSUPP) {
            VIR_INFO("Setting user and group to '%d:%d' on '%s' not supported by filesystem",
                     uid, gid, path);
        } else if (chown_errno == EPERM) {
            VIR_INFO("Setting user and group to '%d:%d' on '%s' not permitted",
                     uid, gid, path);
        } else if (chown_errno == EROFS) {
            VIR_INFO("Setting user and group to '%d:%d' on '%s' not possible on readonly filesystem",
                     uid, gid, path);
        } else {
            virReportSystemError(chown_errno,
                                 _("unable to set user and group to '%d:%d' on '%s'"),
                                 uid, gid, path);
            return -1;
        }
    }
    return 0;
}

static int
qemuSecurityDACRestoreSecurityFileLabel(const char *path)
{
    struct stat buf;
    int rc = -1;
    char *newpath = NULL;

    VIR_INFO("Restoring DAC user and group on '%s'", path);

    if (virFileResolveLink(path, &newpath) < 0) {
        virReportSystemError(errno,
                             _("cannot resolve symlink %s"), path);
        goto err;
    }

    if (stat(newpath, &buf) != 0)
        goto err;

    /* XXX record previous ownership */
    rc = qemuSecurityDACSetOwnership(newpath, 0, 0);

err:
    VIR_FREE(newpath);
    return rc;
}


static int
qemuSecurityDACSetSecurityFileLabel(virDomainDiskDefPtr disk ATTRIBUTE_UNUSED,
                                    const char *path,
                                    size_t depth ATTRIBUTE_UNUSED,
                                    void *opaque ATTRIBUTE_UNUSED)
{
    return qemuSecurityDACSetOwnership(path, driver->user, driver->group);
}


static int
qemuSecurityDACSetSecurityImageLabel(virSecurityDriverPtr drv ATTRIBUTE_UNUSED,
                                     virDomainObjPtr vm ATTRIBUTE_UNUSED,
                                     virDomainDiskDefPtr disk)

{
    if (!driver->privileged || !driver->dynamicOwnership)
        return 0;

    return virDomainDiskDefForeachPath(disk,
                                       driver->allowDiskFormatProbing,
                                       false,
                                       qemuSecurityDACSetSecurityFileLabel,
                                       NULL);
}


static int
qemuSecurityDACRestoreSecurityImageLabelInt(virSecurityDriverPtr drv ATTRIBUTE_UNUSED,
                                            virDomainObjPtr vm ATTRIBUTE_UNUSED,
                                            virDomainDiskDefPtr disk,
                                            int migrated)
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

    return qemuSecurityDACRestoreSecurityFileLabel(disk->src);
}


static int
qemuSecurityDACRestoreSecurityImageLabel(virSecurityDriverPtr drv,
                                         virDomainObjPtr vm,
                                         virDomainDiskDefPtr disk)
{
    return qemuSecurityDACRestoreSecurityImageLabelInt(drv, vm, disk, 0);
}


static int
qemuSecurityDACSetSecurityPCILabel(pciDevice *dev ATTRIBUTE_UNUSED,
                                   const char *file,
                                   void *opaque ATTRIBUTE_UNUSED)
{
    return qemuSecurityDACSetOwnership(file, driver->user, driver->group);
}


static int
qemuSecurityDACSetSecurityUSBLabel(usbDevice *dev ATTRIBUTE_UNUSED,
                                   const char *file,
                                   void *opaque ATTRIBUTE_UNUSED)
{
    return qemuSecurityDACSetOwnership(file, driver->user, driver->group);
}


static int
qemuSecurityDACSetSecurityHostdevLabel(virSecurityDriverPtr drv ATTRIBUTE_UNUSED,
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
        usbDevice *usb = usbGetDevice(dev->source.subsys.u.usb.bus,
                                      dev->source.subsys.u.usb.device);

        if (!usb)
            goto done;

        ret = usbDeviceFileIterate(usb, qemuSecurityDACSetSecurityUSBLabel, vm);
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

        ret = pciDeviceFileIterate(pci, qemuSecurityDACSetSecurityPCILabel, vm);
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
qemuSecurityDACRestoreSecurityPCILabel(pciDevice *dev ATTRIBUTE_UNUSED,
                                       const char *file,
                                       void *opaque ATTRIBUTE_UNUSED)
{
    return qemuSecurityDACRestoreSecurityFileLabel(file);
}


static int
qemuSecurityDACRestoreSecurityUSBLabel(usbDevice *dev ATTRIBUTE_UNUSED,
                                       const char *file,
                                       void *opaque ATTRIBUTE_UNUSED)
{
    return qemuSecurityDACRestoreSecurityFileLabel(file);
}


static int
qemuSecurityDACRestoreSecurityHostdevLabel(virSecurityDriverPtr drv ATTRIBUTE_UNUSED,
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
        usbDevice *usb = usbGetDevice(dev->source.subsys.u.usb.bus,
                                      dev->source.subsys.u.usb.device);

        if (!usb)
            goto done;

        ret = usbDeviceFileIterate(usb, qemuSecurityDACRestoreSecurityUSBLabel, NULL);
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

        ret = pciDeviceFileIterate(pci, qemuSecurityDACRestoreSecurityPCILabel, NULL);
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
qemuSecurityDACSetChardevLabel(virDomainObjPtr vm,
                               virDomainChrDefPtr dev)

{
    const virSecurityLabelDefPtr secdef = &vm->def->seclabel;
    char *in = NULL, *out = NULL;
    int ret = -1;

    if (secdef->type == VIR_DOMAIN_SECLABEL_STATIC)
        return 0;

    switch (dev->type) {
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_FILE:
        ret = qemuSecurityDACSetOwnership(dev->data.file.path, driver->user, driver->group);
        break;

    case VIR_DOMAIN_CHR_TYPE_PIPE:
        if ((virAsprintf(&in, "%s.in", dev->data.file.path) < 0) ||
            (virAsprintf(&out, "%s.out", dev->data.file.path) < 0)) {
            virReportOOMError();
            goto done;
        }
        if ((qemuSecurityDACSetOwnership(in, driver->user, driver->group) < 0) ||
            (qemuSecurityDACSetOwnership(out, driver->user, driver->group) < 0))
            goto done;
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
qemuSecurityDACRestoreChardevLabel(virDomainObjPtr vm,
                                   virDomainChrDefPtr dev)

{
    const virSecurityLabelDefPtr secdef = &vm->def->seclabel;
    char *in = NULL, *out = NULL;
    int ret = -1;

    if (secdef->type == VIR_DOMAIN_SECLABEL_STATIC)
        return 0;

    switch (dev->type) {
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_FILE:
        ret = qemuSecurityDACRestoreSecurityFileLabel(dev->data.file.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_PIPE:
        if ((virAsprintf(&out, "%s.out", dev->data.file.path) < 0) ||
            (virAsprintf(&in, "%s.in", dev->data.file.path) < 0)) {
            virReportOOMError();
            goto done;
        }
        if ((qemuSecurityDACRestoreSecurityFileLabel(out) < 0) ||
            (qemuSecurityDACRestoreSecurityFileLabel(in) < 0))
            goto done;
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
qemuSecurityDACRestoreChardevCallback(virDomainDefPtr def ATTRIBUTE_UNUSED,
                                      virDomainChrDefPtr dev,
                                      void *opaque)
{
    virDomainObjPtr vm = opaque;

    return qemuSecurityDACRestoreChardevLabel(vm, dev);
}


static int
qemuSecurityDACRestoreSecurityAllLabel(virSecurityDriverPtr drv,
                                       virDomainObjPtr vm,
                                       int migrated)
{
    int i;
    int rc = 0;

    if (!driver->privileged || !driver->dynamicOwnership)
        return 0;

    VIR_DEBUG("Restoring security label on %s migrated=%d",
              vm->def->name, migrated);

    for (i = 0 ; i < vm->def->nhostdevs ; i++) {
        if (qemuSecurityDACRestoreSecurityHostdevLabel(drv,
                                                       vm,
                                                       vm->def->hostdevs[i]) < 0)
            rc = -1;
    }
    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (qemuSecurityDACRestoreSecurityImageLabelInt(drv,
                                                        vm,
                                                        vm->def->disks[i],
                                                        migrated) < 0)
            rc = -1;
    }

    if (virDomainChrDefForeach(vm->def,
                               false,
                               qemuSecurityDACRestoreChardevCallback,
                               vm) < 0)
        rc = -1;

    if (vm->def->os.kernel &&
        qemuSecurityDACRestoreSecurityFileLabel(vm->def->os.kernel) < 0)
        rc = -1;

    if (vm->def->os.initrd &&
        qemuSecurityDACRestoreSecurityFileLabel(vm->def->os.initrd) < 0)
        rc = -1;

    return rc;
}


static int
qemuSecurityDACSetChardevCallback(virDomainDefPtr def ATTRIBUTE_UNUSED,
                                      virDomainChrDefPtr dev,
                                      void *opaque)
{
    virDomainObjPtr vm = opaque;

    return qemuSecurityDACSetChardevLabel(vm, dev);
}


static int
qemuSecurityDACSetSecurityAllLabel(virSecurityDriverPtr drv,
                                   virDomainObjPtr vm,
                                   const char *stdin_path ATTRIBUTE_UNUSED)
{
    int i;

    if (!driver->privileged || !driver->dynamicOwnership)
        return 0;

    for (i = 0 ; i < vm->def->ndisks ; i++) {
        /* XXX fixme - we need to recursively label the entriy tree :-( */
        if (vm->def->disks[i]->type == VIR_DOMAIN_DISK_TYPE_DIR)
            continue;
        if (qemuSecurityDACSetSecurityImageLabel(drv,
                                                 vm,
                                                 vm->def->disks[i]) < 0)
            return -1;
    }
    for (i = 0 ; i < vm->def->nhostdevs ; i++) {
        if (qemuSecurityDACSetSecurityHostdevLabel(drv,
                                                   vm,
                                                   vm->def->hostdevs[i]) < 0)
            return -1;
    }

    if (virDomainChrDefForeach(vm->def,
                               true,
                               qemuSecurityDACSetChardevCallback,
                               vm) < 0)
        return -1;

    if (vm->def->os.kernel &&
        qemuSecurityDACSetOwnership(vm->def->os.kernel,
                                    driver->user,
                                    driver->group) < 0)
        return -1;

    if (vm->def->os.initrd &&
        qemuSecurityDACSetOwnership(vm->def->os.initrd,
                                    driver->user,
                                    driver->group) < 0)
        return -1;

    return 0;
}


static int
qemuSecurityDACSetSavedStateLabel(virSecurityDriverPtr drv ATTRIBUTE_UNUSED,
                                  virDomainObjPtr vm ATTRIBUTE_UNUSED,
                                  const char *savefile)
{
    if (!driver->privileged)
        return 0;

    return qemuSecurityDACSetOwnership(savefile, driver->user, driver->group);
}


static int
qemuSecurityDACRestoreSavedStateLabel(virSecurityDriverPtr drv ATTRIBUTE_UNUSED,
                                      virDomainObjPtr vm ATTRIBUTE_UNUSED,
                                      const char *savefile)
{
    if (!driver->privileged)
        return 0;

    return qemuSecurityDACRestoreSecurityFileLabel(savefile);
}


static int
qemuSecurityDACSetProcessLabel(virSecurityDriverPtr drv ATTRIBUTE_UNUSED,
                               virDomainObjPtr vm ATTRIBUTE_UNUSED)
{
    DEBUG("Dropping privileges of VM to %d:%d", driver->user, driver->group);

    if (!driver->privileged)
        return 0;

    if (driver->group) {
        if (setregid(driver->group, driver->group) < 0) {
            virReportSystemError(errno,
                                 _("cannot change to '%d' group"),
                                 driver->group);
            return -1;
        }
    }
    if (driver->user) {
        if (setreuid(driver->user, driver->user) < 0) {
            virReportSystemError(errno,
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
