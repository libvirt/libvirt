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

#include "security_dac.h"
#include "virerror.h"
#include "virfile.h"
#include "viralloc.h"
#include "virlog.h"
#include "virpci.h"
#include "virusb.h"
#include "virscsi.h"
#include "virstoragefile.h"
#include "virstring.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_SECURITY

VIR_LOG_INIT("security.security_dac");

#define SECURITY_DAC_NAME "dac"

typedef struct _virSecurityDACData virSecurityDACData;
typedef virSecurityDACData *virSecurityDACDataPtr;

struct _virSecurityDACData {
    uid_t user;
    gid_t group;
    gid_t *groups;
    int ngroups;
    bool dynamicOwnership;
    char *baselabel;
};

/* returns -1 on error, 0 on success */
int
virSecurityDACSetUserAndGroup(virSecurityManagerPtr mgr,
                              uid_t user,
                              gid_t group)
{
    virSecurityDACDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    priv->user = user;
    priv->group = group;

    if (virAsprintf(&priv->baselabel, "+%u:+%u",
                    (unsigned int) user,
                    (unsigned int) group) < 0)
        return -1;

    return 0;
}

void
virSecurityDACSetDynamicOwnership(virSecurityManagerPtr mgr,
                                  bool dynamicOwnership)
{
    virSecurityDACDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    priv->dynamicOwnership = dynamicOwnership;
}

/* returns 1 if label isn't found, 0 on success, -1 on error */
static int
virSecurityDACParseIds(virDomainDefPtr def, uid_t *uidPtr, gid_t *gidPtr)
{
    uid_t uid;
    gid_t gid;
    virSecurityLabelDefPtr seclabel;

    if (def == NULL)
        return 1;

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_DAC_NAME);
    if (seclabel == NULL || seclabel->label == NULL) {
        VIR_DEBUG("DAC seclabel for domain '%s' wasn't found", def->name);
        return 1;
    }

    if (virParseOwnershipIds(seclabel->label, &uid, &gid) < 0)
        return -1;

    if (uidPtr)
        *uidPtr = uid;
    if (gidPtr)
        *gidPtr = gid;

    return 0;
}

static int
virSecurityDACGetIds(virDomainDefPtr def, virSecurityDACDataPtr priv,
                     uid_t *uidPtr, gid_t *gidPtr,
                     gid_t **groups, int *ngroups)
{
    int ret;

    if (!def && !priv) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to determine default DAC seclabel "
                         "for an unknown object"));
        return -1;
    }

    if (groups)
        *groups = priv ? priv->groups : NULL;
    if (ngroups)
        *ngroups = priv ? priv->ngroups : 0;

    if ((ret = virSecurityDACParseIds(def, uidPtr, gidPtr)) <= 0)
        return ret;

    if (!priv) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("DAC seclabel couldn't be determined "
                         "for domain '%s'"), def->name);
        return -1;
    }

    if (uidPtr)
        *uidPtr = priv->user;
    if (gidPtr)
        *gidPtr = priv->group;

    return 0;
}


/* returns 1 if label isn't found, 0 on success, -1 on error */
static int
virSecurityDACParseImageIds(virDomainDefPtr def,
                            uid_t *uidPtr, gid_t *gidPtr)
{
    uid_t uid;
    gid_t gid;
    virSecurityLabelDefPtr seclabel;

    if (def == NULL)
        return 1;

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_DAC_NAME);
    if (seclabel == NULL || seclabel->imagelabel == NULL) {
        VIR_DEBUG("DAC imagelabel for domain '%s' wasn't found", def->name);
        return 1;
    }

    if (virParseOwnershipIds(seclabel->imagelabel, &uid, &gid) < 0)
        return -1;

    if (uidPtr)
        *uidPtr = uid;
    if (gidPtr)
        *gidPtr = gid;

    return 0;
}

static int
virSecurityDACGetImageIds(virDomainDefPtr def, virSecurityDACDataPtr priv,
                          uid_t *uidPtr, gid_t *gidPtr)
{
    int ret;

    if (!def && !priv) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to determine default DAC imagelabel "
                         "for an unknown object"));
        return -1;
    }

    if ((ret = virSecurityDACParseImageIds(def, uidPtr, gidPtr)) <= 0)
        return ret;

    if (!priv) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("DAC imagelabel couldn't be determined "
                         "for domain '%s'"), def->name);
        return -1;
    }

    if (uidPtr)
        *uidPtr = priv->user;
    if (gidPtr)
        *gidPtr = priv->group;

    return 0;
}


static virSecurityDriverStatus
virSecurityDACProbe(const char *virtDriver ATTRIBUTE_UNUSED)
{
    return SECURITY_DRIVER_ENABLE;
}

static int
virSecurityDACOpen(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED)
{
    return 0;
}

static int
virSecurityDACClose(virSecurityManagerPtr mgr)
{
    virSecurityDACDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    VIR_FREE(priv->groups);
    VIR_FREE(priv->baselabel);
    return 0;
}


static const char *
virSecurityDACGetModel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED)
{
    return SECURITY_DAC_NAME;
}

static const char *
virSecurityDACGetDOI(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED)
{
    return "0";
}

static int
virSecurityDACPreFork(virSecurityManagerPtr mgr)
{
    virSecurityDACDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    int ngroups;

    VIR_FREE(priv->groups);
    priv->ngroups = 0;
    if ((ngroups = virGetGroupList(priv->user, priv->group,
                                   &priv->groups)) < 0)
        return -1;
    priv->ngroups = ngroups;
    return 0;
}

static int
virSecurityDACSetOwnership(const char *path, uid_t uid, gid_t gid)
{
    VIR_INFO("Setting DAC user and group on '%s' to '%ld:%ld'",
             path, (long) uid, (long) gid);

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

        if (chown_errno == EOPNOTSUPP || chown_errno == EINVAL) {
            VIR_INFO("Setting user and group to '%ld:%ld' on '%s' not "
                     "supported by filesystem",
                     (long) uid, (long) gid, path);
        } else if (chown_errno == EPERM) {
            VIR_INFO("Setting user and group to '%ld:%ld' on '%s' not "
                     "permitted",
                     (long) uid, (long) gid, path);
        } else if (chown_errno == EROFS) {
            VIR_INFO("Setting user and group to '%ld:%ld' on '%s' not "
                     "possible on readonly filesystem",
                     (long) uid, (long) gid, path);
        } else {
            virReportSystemError(chown_errno,
                                 _("unable to set user and group to '%ld:%ld' "
                                   "on '%s'"),
                                 (long) uid, (long) gid, path);
            return -1;
        }
    }
    return 0;
}

static int
virSecurityDACRestoreSecurityFileLabel(const char *path)
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
    rc = virSecurityDACSetOwnership(newpath, 0, 0);

 err:
    VIR_FREE(newpath);
    return rc;
}


static int
virSecurityDACSetSecurityFileLabel(virDomainDiskDefPtr disk ATTRIBUTE_UNUSED,
                                   const char *path,
                                   size_t depth ATTRIBUTE_UNUSED,
                                   void *opaque)
{
    void **params = opaque;
    virSecurityManagerPtr mgr = params[0];
    virDomainDefPtr def = params[1];
    virSecurityDACDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    uid_t user;
    gid_t group;

    if (virSecurityDACGetImageIds(def, priv, &user, &group))
        return -1;

    return virSecurityDACSetOwnership(path, user, group);
}


static int
virSecurityDACSetSecurityImageLabel(virSecurityManagerPtr mgr,
                                    virDomainDefPtr def,
                                    virDomainDiskDefPtr disk)

{
    void *params[2];
    virSecurityDACDataPtr priv = virSecurityManagerGetPrivateData(mgr);

    if (!priv->dynamicOwnership)
        return 0;

    if (virDomainDiskGetType(disk) == VIR_DOMAIN_DISK_TYPE_NETWORK)
        return 0;

    params[0] = mgr;
    params[1] = def;
    return virDomainDiskDefForeachPath(disk,
                                       false,
                                       virSecurityDACSetSecurityFileLabel,
                                       params);
}


static int
virSecurityDACRestoreSecurityImageLabelInt(virSecurityManagerPtr mgr,
                                           virDomainDefPtr def ATTRIBUTE_UNUSED,
                                           virDomainDiskDefPtr disk,
                                           int migrated)
{
    virSecurityDACDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    const char *src = virDomainDiskGetSource(disk);

    if (!priv->dynamicOwnership)
        return 0;

    if (virDomainDiskGetType(disk) == VIR_DOMAIN_DISK_TYPE_NETWORK)
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

    if (!src)
        return 0;

    /* If we have a shared FS & doing migrated, we must not
     * change ownership, because that kills access on the
     * destination host which is sub-optimal for the guest
     * VM's I/O attempts :-)
     */
    if (migrated) {
        int rc = virStorageFileIsSharedFS(src);
        if (rc < 0)
            return -1;
        if (rc == 1) {
            VIR_DEBUG("Skipping image label restore on %s because FS is shared",
                      src);
            return 0;
        }
    }

    return virSecurityDACRestoreSecurityFileLabel(src);
}


static int
virSecurityDACRestoreSecurityImageLabel(virSecurityManagerPtr mgr,
                                        virDomainDefPtr def,
                                        virDomainDiskDefPtr disk)
{
    return virSecurityDACRestoreSecurityImageLabelInt(mgr, def, disk, 0);
}


static int
virSecurityDACSetSecurityHostdevLabelHelper(const char *file,
                                            void *opaque)
{
    void **params = opaque;
    virSecurityManagerPtr mgr = params[0];
    virDomainDefPtr def = params[1];
    virSecurityDACDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    uid_t user;
    gid_t group;

    if (virSecurityDACGetIds(def, priv, &user, &group, NULL, NULL))
        return -1;

    return virSecurityDACSetOwnership(file, user, group);
}


static int
virSecurityDACSetSecurityPCILabel(virPCIDevicePtr dev ATTRIBUTE_UNUSED,
                                  const char *file,
                                  void *opaque)
{
    return virSecurityDACSetSecurityHostdevLabelHelper(file, opaque);
}


static int
virSecurityDACSetSecurityUSBLabel(virUSBDevicePtr dev ATTRIBUTE_UNUSED,
                                  const char *file,
                                  void *opaque)
{
    return virSecurityDACSetSecurityHostdevLabelHelper(file, opaque);
}


static int
virSecurityDACSetSecuritySCSILabel(virSCSIDevicePtr dev ATTRIBUTE_UNUSED,
                                   const char *file,
                                   void *opaque)
{
    return virSecurityDACSetSecurityHostdevLabelHelper(file, opaque);
}


static int
virSecurityDACSetSecurityHostdevLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr def,
                                      virDomainHostdevDefPtr dev,
                                      const char *vroot)
{
    void *params[] = {mgr, def};
    virSecurityDACDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    int ret = -1;

    if (!priv->dynamicOwnership)
        return 0;

    if (dev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
        return 0;

    switch (dev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB: {
        virUSBDevicePtr usb;

        if (dev->missing)
            return 0;

        usb = virUSBDeviceNew(dev->source.subsys.u.usb.bus,
                              dev->source.subsys.u.usb.device,
                              vroot);
        if (!usb)
            goto done;

        ret = virUSBDeviceFileIterate(usb, virSecurityDACSetSecurityUSBLabel,
                                      params);
        virUSBDeviceFree(usb);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI: {
        virPCIDevicePtr pci =
            virPCIDeviceNew(dev->source.subsys.u.pci.addr.domain,
                            dev->source.subsys.u.pci.addr.bus,
                            dev->source.subsys.u.pci.addr.slot,
                            dev->source.subsys.u.pci.addr.function);

        if (!pci)
            goto done;

        if (dev->source.subsys.u.pci.backend
            == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO) {
            char *vfioGroupDev = virPCIDeviceGetIOMMUGroupDev(pci);

            if (!vfioGroupDev) {
                virPCIDeviceFree(pci);
                goto done;
            }
            ret = virSecurityDACSetSecurityPCILabel(pci, vfioGroupDev, params);
            VIR_FREE(vfioGroupDev);
        } else {
            ret = virPCIDeviceFileIterate(pci, virSecurityDACSetSecurityPCILabel,
                                          params);
        }

        virPCIDeviceFree(pci);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI: {
        virSCSIDevicePtr scsi =
            virSCSIDeviceNew(NULL,
                             dev->source.subsys.u.scsi.adapter,
                             dev->source.subsys.u.scsi.bus,
                             dev->source.subsys.u.scsi.target,
                             dev->source.subsys.u.scsi.unit,
                             dev->readonly,
                             dev->shareable);

        if (!scsi)
            goto done;

        ret = virSCSIDeviceFileIterate(scsi, virSecurityDACSetSecuritySCSILabel,
                                       params);
        virSCSIDeviceFree(scsi);

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
virSecurityDACRestoreSecurityPCILabel(virPCIDevicePtr dev ATTRIBUTE_UNUSED,
                                      const char *file,
                                      void *opaque ATTRIBUTE_UNUSED)
{
    return virSecurityDACRestoreSecurityFileLabel(file);
}


static int
virSecurityDACRestoreSecurityUSBLabel(virUSBDevicePtr dev ATTRIBUTE_UNUSED,
                                      const char *file,
                                      void *opaque ATTRIBUTE_UNUSED)
{
    return virSecurityDACRestoreSecurityFileLabel(file);
}


static int
virSecurityDACRestoreSecuritySCSILabel(virSCSIDevicePtr dev ATTRIBUTE_UNUSED,
                                       const char *file,
                                       void *opaque ATTRIBUTE_UNUSED)
{
    return virSecurityDACRestoreSecurityFileLabel(file);
}


static int
virSecurityDACRestoreSecurityHostdevLabel(virSecurityManagerPtr mgr,
                                          virDomainDefPtr def ATTRIBUTE_UNUSED,
                                          virDomainHostdevDefPtr dev,
                                          const char *vroot)

{
    virSecurityDACDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    int ret = -1;

    if (!priv->dynamicOwnership)
        return 0;

    if (dev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
        return 0;

    switch (dev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB: {
        virUSBDevicePtr usb;

        if (dev->missing)
            return 0;

        usb = virUSBDeviceNew(dev->source.subsys.u.usb.bus,
                              dev->source.subsys.u.usb.device,
                              vroot);
        if (!usb)
            goto done;

        ret = virUSBDeviceFileIterate(usb, virSecurityDACRestoreSecurityUSBLabel, mgr);
        virUSBDeviceFree(usb);

        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI: {
        virPCIDevicePtr pci =
            virPCIDeviceNew(dev->source.subsys.u.pci.addr.domain,
                            dev->source.subsys.u.pci.addr.bus,
                            dev->source.subsys.u.pci.addr.slot,
                            dev->source.subsys.u.pci.addr.function);

        if (!pci)
            goto done;

        if (dev->source.subsys.u.pci.backend
            == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO) {
            char *vfioGroupDev = virPCIDeviceGetIOMMUGroupDev(pci);

            if (!vfioGroupDev) {
                virPCIDeviceFree(pci);
                goto done;
            }
            ret = virSecurityDACRestoreSecurityPCILabel(pci, vfioGroupDev, mgr);
            VIR_FREE(vfioGroupDev);
        } else {
            ret = virPCIDeviceFileIterate(pci, virSecurityDACRestoreSecurityPCILabel, mgr);
        }
        virPCIDeviceFree(pci);
        break;
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI: {
        virSCSIDevicePtr scsi =
            virSCSIDeviceNew(NULL,
                             dev->source.subsys.u.scsi.adapter,
                             dev->source.subsys.u.scsi.bus,
                             dev->source.subsys.u.scsi.target,
                             dev->source.subsys.u.scsi.unit,
                             dev->readonly,
                             dev->shareable);

        if (!scsi)
            goto done;

        ret = virSCSIDeviceFileIterate(scsi, virSecurityDACRestoreSecuritySCSILabel, mgr);
        virSCSIDeviceFree(scsi);

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
virSecurityDACSetChardevLabel(virSecurityManagerPtr mgr,
                              virDomainDefPtr def,
                              virDomainChrSourceDefPtr dev)

{
    virSecurityDACDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    char *in = NULL, *out = NULL;
    int ret = -1;
    uid_t user;
    gid_t group;

    if (virSecurityDACGetIds(def, priv, &user, &group, NULL, NULL))
        return -1;

    switch (dev->type) {
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_FILE:
        ret = virSecurityDACSetOwnership(dev->data.file.path, user, group);
        break;

    case VIR_DOMAIN_CHR_TYPE_PIPE:
        if ((virAsprintf(&in, "%s.in", dev->data.file.path) < 0) ||
            (virAsprintf(&out, "%s.out", dev->data.file.path) < 0))
            goto done;
        if (virFileExists(in) && virFileExists(out)) {
            if ((virSecurityDACSetOwnership(in, user, group) < 0) ||
                (virSecurityDACSetOwnership(out, user, group) < 0)) {
                goto done;
            }
        } else if (virSecurityDACSetOwnership(dev->data.file.path,
                                              user, group) < 0) {
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
virSecurityDACRestoreChardevLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                  virDomainChrSourceDefPtr dev)
{
    char *in = NULL, *out = NULL;
    int ret = -1;

    switch (dev->type) {
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_FILE:
        ret = virSecurityDACRestoreSecurityFileLabel(dev->data.file.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_PIPE:
        if ((virAsprintf(&out, "%s.out", dev->data.file.path) < 0) ||
            (virAsprintf(&in, "%s.in", dev->data.file.path) < 0))
            goto done;
        if (virFileExists(in) && virFileExists(out)) {
            if ((virSecurityDACRestoreSecurityFileLabel(out) < 0) ||
                (virSecurityDACRestoreSecurityFileLabel(in) < 0)) {
            goto done;
            }
        } else if (virSecurityDACRestoreSecurityFileLabel(dev->data.file.path) < 0) {
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
virSecurityDACRestoreChardevCallback(virDomainDefPtr def ATTRIBUTE_UNUSED,
                                     virDomainChrDefPtr dev,
                                     void *opaque)
{
    virSecurityManagerPtr mgr = opaque;

    return virSecurityDACRestoreChardevLabel(mgr, &dev->source);
}


static int
virSecurityDACSetSecurityTPMFileLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr def,
                                      virDomainTPMDefPtr tpm)
{
    int ret = 0;

    switch (tpm->type) {
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
        ret = virSecurityDACSetChardevLabel(mgr, def,
                                            &tpm->data.passthrough.source);
        break;
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }

    return ret;
}


static int
virSecurityDACRestoreSecurityTPMFileLabel(virSecurityManagerPtr mgr,
                                          virDomainTPMDefPtr tpm)
{
    int ret = 0;

    switch (tpm->type) {
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
        ret = virSecurityDACRestoreChardevLabel(mgr,
                                          &tpm->data.passthrough.source);
        break;
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }

    return ret;
}


static int
virSecurityDACRestoreSecurityAllLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr def,
                                      int migrated)
{
    virSecurityDACDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    size_t i;
    int rc = 0;

    if (!priv->dynamicOwnership)
        return 0;


    VIR_DEBUG("Restoring security label on %s migrated=%d",
              def->name, migrated);

    for (i = 0; i < def->nhostdevs; i++) {
        if (virSecurityDACRestoreSecurityHostdevLabel(mgr,
                                                      def,
                                                      def->hostdevs[i],
                                                      NULL) < 0)
            rc = -1;
    }
    for (i = 0; i < def->ndisks; i++) {
        if (virSecurityDACRestoreSecurityImageLabelInt(mgr,
                                                       def,
                                                       def->disks[i],
                                                       migrated) < 0)
            rc = -1;
    }

    if (virDomainChrDefForeach(def,
                               false,
                               virSecurityDACRestoreChardevCallback,
                               mgr) < 0)
        rc = -1;

    if (def->tpm) {
        if (virSecurityDACRestoreSecurityTPMFileLabel(mgr,
                                                      def->tpm) < 0)
            rc = -1;
    }

    if (def->os.kernel &&
        virSecurityDACRestoreSecurityFileLabel(def->os.kernel) < 0)
        rc = -1;

    if (def->os.initrd &&
        virSecurityDACRestoreSecurityFileLabel(def->os.initrd) < 0)
        rc = -1;

    if (def->os.dtb &&
        virSecurityDACRestoreSecurityFileLabel(def->os.dtb) < 0)
        rc = -1;

    return rc;
}


static int
virSecurityDACSetChardevCallback(virDomainDefPtr def ATTRIBUTE_UNUSED,
                                 virDomainChrDefPtr dev,
                                 void *opaque)
{
    virSecurityManagerPtr mgr = opaque;

    return virSecurityDACSetChardevLabel(mgr, def, &dev->source);
}


static int
virSecurityDACSetSecurityAllLabel(virSecurityManagerPtr mgr,
                                  virDomainDefPtr def,
                                  const char *stdin_path ATTRIBUTE_UNUSED)
{
    virSecurityDACDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    size_t i;
    uid_t user;
    gid_t group;

    if (!priv->dynamicOwnership)
        return 0;

    for (i = 0; i < def->ndisks; i++) {
        /* XXX fixme - we need to recursively label the entire tree :-( */
        if (virDomainDiskGetType(def->disks[i]) == VIR_DOMAIN_DISK_TYPE_DIR)
            continue;
        if (virSecurityDACSetSecurityImageLabel(mgr,
                                                def,
                                                def->disks[i]) < 0)
            return -1;
    }
    for (i = 0; i < def->nhostdevs; i++) {
        if (virSecurityDACSetSecurityHostdevLabel(mgr,
                                                  def,
                                                  def->hostdevs[i],
                                                  NULL) < 0)
            return -1;
    }

    if (virDomainChrDefForeach(def,
                               true,
                               virSecurityDACSetChardevCallback,
                               mgr) < 0)
        return -1;

    if (def->tpm) {
        if (virSecurityDACSetSecurityTPMFileLabel(mgr,
                                                  def,
                                                  def->tpm) < 0)
            return -1;
    }

    if (virSecurityDACGetImageIds(def, priv, &user, &group))
        return -1;

    if (def->os.kernel &&
        virSecurityDACSetOwnership(def->os.kernel, user, group) < 0)
        return -1;

    if (def->os.initrd &&
        virSecurityDACSetOwnership(def->os.initrd, user, group) < 0)
        return -1;

    if (def->os.dtb &&
        virSecurityDACSetOwnership(def->os.dtb, user, group) < 0)
        return -1;

    return 0;
}


static int
virSecurityDACSetSavedStateLabel(virSecurityManagerPtr mgr,
                                 virDomainDefPtr def,
                                 const char *savefile)
{
    uid_t user;
    gid_t group;
    virSecurityDACDataPtr priv = virSecurityManagerGetPrivateData(mgr);

    if (virSecurityDACGetImageIds(def, priv, &user, &group))
        return -1;

    return virSecurityDACSetOwnership(savefile, user, group);
}


static int
virSecurityDACRestoreSavedStateLabel(virSecurityManagerPtr mgr,
                                     virDomainDefPtr def ATTRIBUTE_UNUSED,
                                     const char *savefile)
{
    virSecurityDACDataPtr priv = virSecurityManagerGetPrivateData(mgr);

    if (!priv->dynamicOwnership)
        return 0;

    return virSecurityDACRestoreSecurityFileLabel(savefile);
}


static int
virSecurityDACSetProcessLabel(virSecurityManagerPtr mgr,
                              virDomainDefPtr def ATTRIBUTE_UNUSED)
{
    uid_t user;
    gid_t group;
    gid_t *groups;
    int ngroups;
    virSecurityDACDataPtr priv = virSecurityManagerGetPrivateData(mgr);

    if (virSecurityDACGetIds(def, priv, &user, &group, &groups, &ngroups))
        return -1;

    VIR_DEBUG("Dropping privileges of DEF to %u:%u, %d supplemental groups",
              (unsigned int) user, (unsigned int) group, ngroups);

    if (virSetUIDGID(user, group, groups, ngroups) < 0)
        return -1;

    return 0;
}


static int
virSecurityDACSetChildProcessLabel(virSecurityManagerPtr mgr,
                                   virDomainDefPtr def ATTRIBUTE_UNUSED,
                                   virCommandPtr cmd)
{
    uid_t user;
    gid_t group;
    virSecurityDACDataPtr priv = virSecurityManagerGetPrivateData(mgr);

    if (virSecurityDACGetIds(def, priv, &user, &group, NULL, NULL))
        return -1;

    VIR_DEBUG("Setting child to drop privileges of DEF to %u:%u",
              (unsigned int) user, (unsigned int) group);

    virCommandSetUID(cmd, user);
    virCommandSetGID(cmd, group);
    return 0;
}


static int
virSecurityDACVerify(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                     virDomainDefPtr def ATTRIBUTE_UNUSED)
{
    return 0;
}

static int
virSecurityDACGenLabel(virSecurityManagerPtr mgr,
                       virDomainDefPtr def)
{
    int rc = -1;
    virSecurityLabelDefPtr seclabel;
    virSecurityDACDataPtr priv = virSecurityManagerGetPrivateData(mgr);

    seclabel = virDomainDefGetSecurityLabelDef(def, SECURITY_DAC_NAME);
    if (seclabel == NULL) {
        return rc;
    }

    if (seclabel->imagelabel) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("security image label already "
                         "defined for VM"));
        return rc;
    }

    if (seclabel->model
        && STRNEQ(seclabel->model, SECURITY_DAC_NAME)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security label model %s is not supported "
                         "with selinux"),
                       seclabel->model);
            return rc;
    }

    switch (seclabel->type) {
    case VIR_DOMAIN_SECLABEL_STATIC:
        if (seclabel->label == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("missing label for static security "
                             "driver in domain %s"), def->name);
            return rc;
        }
        break;
    case VIR_DOMAIN_SECLABEL_DYNAMIC:
        if (virAsprintf(&seclabel->label, "+%u:+%u",
                        (unsigned int) priv->user,
                        (unsigned int) priv->group) < 0)
            return rc;
        if (seclabel->label == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot generate dac user and group id "
                             "for domain %s"), def->name);
            return rc;
        }
        break;
    case VIR_DOMAIN_SECLABEL_NONE:
        /* no op */
        return 0;
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected security label type '%s'"),
                       virDomainSeclabelTypeToString(seclabel->type));
        return rc;
    }

    if (!seclabel->norelabel && !seclabel->imagelabel &&
        VIR_STRDUP(seclabel->imagelabel, seclabel->label) < 0) {
        VIR_FREE(seclabel->label);
        return rc;
    }

    return 0;
}

static int
virSecurityDACReleaseLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                           virDomainDefPtr def ATTRIBUTE_UNUSED)
{
    return 0;
}

static int
virSecurityDACReserveLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                           virDomainDefPtr def ATTRIBUTE_UNUSED,
                           pid_t pid ATTRIBUTE_UNUSED)
{
    return 0;
}

static int
virSecurityDACGetProcessLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                              virDomainDefPtr def ATTRIBUTE_UNUSED,
                              pid_t pid ATTRIBUTE_UNUSED,
                              virSecurityLabelPtr seclabel ATTRIBUTE_UNUSED)
{
    virSecurityLabelDefPtr secdef =
        virDomainDefGetSecurityLabelDef(def, SECURITY_DAC_NAME);

    if (!secdef || !seclabel)
        return -1;

    if (secdef->label)
        ignore_value(virStrcpy(seclabel->label, secdef->label,
                               VIR_SECURITY_LABEL_BUFLEN));

    return 0;
}

static int
virSecurityDACSetDaemonSocketLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                                   virDomainDefPtr vm ATTRIBUTE_UNUSED)
{
    return 0;
}


static int
virSecurityDACSetSocketLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                             virDomainDefPtr def ATTRIBUTE_UNUSED)
{
    return 0;
}


static int
virSecurityDACClearSocketLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                               virDomainDefPtr def ATTRIBUTE_UNUSED)
{
    return 0;
}

static int
virSecurityDACSetImageFDLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                              virDomainDefPtr def ATTRIBUTE_UNUSED,
                              int fd ATTRIBUTE_UNUSED)
{
    return 0;
}

static int
virSecurityDACSetTapFDLabel(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                            virDomainDefPtr def ATTRIBUTE_UNUSED,
                            int fd ATTRIBUTE_UNUSED)
{
    return 0;
}

static char *
virSecurityDACGetMountOptions(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED,
                              virDomainDefPtr vm ATTRIBUTE_UNUSED)
{
    return NULL;
}

static const char *
virSecurityDACGetBaseLabel(virSecurityManagerPtr mgr,
                           int virt ATTRIBUTE_UNUSED)
{
    virSecurityDACDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    return priv->baselabel;
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

    .domainSecurityVerify               = virSecurityDACVerify,

    .domainSetSecurityImageLabel        = virSecurityDACSetSecurityImageLabel,
    .domainRestoreSecurityImageLabel    = virSecurityDACRestoreSecurityImageLabel,

    .domainSetSecurityDaemonSocketLabel = virSecurityDACSetDaemonSocketLabel,
    .domainSetSecuritySocketLabel       = virSecurityDACSetSocketLabel,
    .domainClearSecuritySocketLabel     = virSecurityDACClearSocketLabel,

    .domainGenSecurityLabel             = virSecurityDACGenLabel,
    .domainReserveSecurityLabel         = virSecurityDACReserveLabel,
    .domainReleaseSecurityLabel         = virSecurityDACReleaseLabel,

    .domainGetSecurityProcessLabel      = virSecurityDACGetProcessLabel,
    .domainSetSecurityProcessLabel      = virSecurityDACSetProcessLabel,
    .domainSetSecurityChildProcessLabel = virSecurityDACSetChildProcessLabel,

    .domainSetSecurityAllLabel          = virSecurityDACSetSecurityAllLabel,
    .domainRestoreSecurityAllLabel      = virSecurityDACRestoreSecurityAllLabel,

    .domainSetSecurityHostdevLabel      = virSecurityDACSetSecurityHostdevLabel,
    .domainRestoreSecurityHostdevLabel  = virSecurityDACRestoreSecurityHostdevLabel,

    .domainSetSavedStateLabel           = virSecurityDACSetSavedStateLabel,
    .domainRestoreSavedStateLabel       = virSecurityDACRestoreSavedStateLabel,

    .domainSetSecurityImageFDLabel      = virSecurityDACSetImageFDLabel,
    .domainSetSecurityTapFDLabel        = virSecurityDACSetTapFDLabel,

    .domainGetSecurityMountOptions      = virSecurityDACGetMountOptions,

    .getBaseLabel                       = virSecurityDACGetBaseLabel,
};
