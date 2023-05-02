/*
 * domain_audit.c: Domain audit management
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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
 */

#include <config.h>

#include <sys/stat.h>

#ifdef __linux__
# include <sys/sysmacros.h>
#endif

#include <sys/types.h>

#include "domain_audit.h"
#include "viraudit.h"
#include "viruuid.h"
#include "virlog.h"
#include "viralloc.h"

VIR_LOG_INIT("conf.domain_audit");

/* Return nn:mm in hex for block and character devices, and NULL
 * for other file types, stat failure, or allocation failure.  */
#if defined major && defined minor
static char *
virDomainAuditGetRdev(const char *path)
{
    char *ret = NULL;
    struct stat sb;

    if (stat(path, &sb) == 0 &&
        (S_ISCHR(sb.st_mode) || S_ISBLK(sb.st_mode))) {
        int maj = major(sb.st_rdev);
        int min = minor(sb.st_rdev);
        ret = g_strdup_printf("%02X:%02X", maj, min);
    }
    return ret;
}
#else
static char *
virDomainAuditGetRdev(const char *path G_GNUC_UNUSED)
{
    return NULL;
}
#endif


static const char *
virDomainAuditGetVirtType(virDomainDef *def)
{
    const char *virt;

    if (!(virt = virDomainVirtTypeToString(def->virtType))) {
        VIR_WARN("Unexpected virt type %d while encoding audit message",
                 def->virtType);
        virt = "?";
    }

    return virt;
}


static void
virDomainAuditGenericDev(virDomainObj *vm,
                         const char *type,
                         const char *oldsrcpath,
                         const char *newsrcpath,
                         const char *reason,
                         bool success)
{
    g_autofree char *newdev = NULL;
    g_autofree char *olddev = NULL;
    g_autofree char *vmname = NULL;
    g_autofree char *oldsrc = NULL;
    g_autofree char *newsrc = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    const char *virt = virDomainAuditGetVirtType(vm->def);

    /* if both new and old source aren't provided don't log anything */
    if (!newsrcpath && !oldsrcpath)
        return;

    newdev = g_strdup_printf("new-%s", type);
    olddev = g_strdup_printf("old-%s", type);

    virUUIDFormat(vm->def->uuid, uuidstr);

    if (!(vmname = virAuditEncode("vm", vm->def->name)))
        return;

    if (!(newsrc = virAuditEncode(newdev, VIR_AUDIT_STR(newsrcpath))))
        return;

    if (!(oldsrc = virAuditEncode(olddev, VIR_AUDIT_STR(oldsrcpath))))
        return;

    VIR_AUDIT(VIR_AUDIT_RECORD_RESOURCE, success,
              "virt=%s resrc=%s reason=%s %s uuid=%s %s %s",
              virt, type, reason, vmname, uuidstr, oldsrc, newsrc);
}


void
virDomainAuditChardev(virDomainObj *vm,
                      virDomainChrDef *oldDef,
                      virDomainChrDef *newDef,
                      const char *reason,
                      bool success)
{
    virDomainChrSourceDef *oldsrc = NULL;
    virDomainChrSourceDef *newsrc = NULL;

    if (oldDef)
        oldsrc = oldDef->source;

    if (newDef)
        newsrc = newDef->source;

    virDomainAuditGenericDev(vm, "chardev",
                             virDomainChrSourceDefGetPath(oldsrc),
                             virDomainChrSourceDefGetPath(newsrc),
                             reason, success);
}


static void
virDomainAuditSmartcard(virDomainObj *vm,
                        virDomainSmartcardDef *def,
                        const char *reason,
                        bool success)
{
    const char *database = VIR_DOMAIN_SMARTCARD_DEFAULT_DATABASE;
    size_t i;

    if (def) {
        switch ((virDomainSmartcardType) def->type) {
        case VIR_DOMAIN_SMARTCARD_TYPE_HOST:
            virDomainAuditGenericDev(vm, "smartcard",
                                     NULL, "nss-smartcard-device",
                                     reason, success);
            break;

        case VIR_DOMAIN_SMARTCARD_TYPE_HOST_CERTIFICATES:
            for (i = 0; i < VIR_DOMAIN_SMARTCARD_NUM_CERTIFICATES; i++) {
                virDomainAuditGenericDev(vm, "smartcard", NULL,
                                         def->data.cert.file[i],
                                         reason, success);
            }

            if (def->data.cert.database)
                database = def->data.cert.database;

            virDomainAuditGenericDev(vm, "smartcard",
                                     NULL, database,
                                     reason, success);
            break;

        case VIR_DOMAIN_SMARTCARD_TYPE_PASSTHROUGH:
            virDomainAuditGenericDev(vm, "smartcard", NULL,
                                     virDomainChrSourceDefGetPath(def->data.passthru),
                                     reason, success);
            break;

        case VIR_DOMAIN_SMARTCARD_TYPE_LAST:
            break;
        }
    }
}


void
virDomainAuditDisk(virDomainObj *vm,
                   virStorageSource *oldDef,
                   virStorageSource *newDef,
                   const char *reason,
                   bool success)
{
    const char *oldsrc = NULL;
    const char *newsrc = NULL;

    if (oldDef && virStorageSourceIsLocalStorage(oldDef))
        oldsrc = oldDef->path;

    if (newDef && virStorageSourceIsLocalStorage(newDef))
        newsrc = newDef->path;

    virDomainAuditGenericDev(vm, "disk", oldsrc, newsrc, reason, success);
}


void
virDomainAuditRNG(virDomainObj *vm,
                  virDomainRNGDef *oldDef, virDomainRNGDef *newDef,
                  const char *reason, bool success)
{
    const char *newsrcpath = NULL;
    const char *oldsrcpath = NULL;

    if (newDef) {
        switch (newDef->backend) {
        case VIR_DOMAIN_RNG_BACKEND_RANDOM:
            newsrcpath = newDef->source.file;
            break;

        case VIR_DOMAIN_RNG_BACKEND_EGD:
            newsrcpath = virDomainChrSourceDefGetPath(newDef->source.chardev);
            break;

        case VIR_DOMAIN_RNG_BACKEND_BUILTIN:
        case VIR_DOMAIN_RNG_BACKEND_LAST:
            break;
        }
    }

    if (oldDef) {
        switch (oldDef->backend) {
        case VIR_DOMAIN_RNG_BACKEND_RANDOM:
            oldsrcpath = oldDef->source.file;
            break;

        case VIR_DOMAIN_RNG_BACKEND_EGD:
            oldsrcpath = virDomainChrSourceDefGetPath(oldDef->source.chardev);
            break;

        case VIR_DOMAIN_RNG_BACKEND_BUILTIN:
        case VIR_DOMAIN_RNG_BACKEND_LAST:
            break;
        }
    }

    virDomainAuditGenericDev(vm, "rng", oldsrcpath, newsrcpath, reason, success);
}


void
virDomainAuditFS(virDomainObj *vm,
                 virDomainFSDef *oldDef, virDomainFSDef *newDef,
                 const char *reason, bool success)
{
    virDomainAuditGenericDev(vm, "fs",
                             oldDef ? oldDef->src->path : NULL,
                             newDef ? newDef->src->path : NULL,
                             reason, success);
}


void
virDomainAuditNet(virDomainObj *vm,
                  virDomainNetDef *oldDef, virDomainNetDef *newDef,
                  const char *reason, bool success)
{
    char newMacstr[VIR_MAC_STRING_BUFLEN];
    char oldMacstr[VIR_MAC_STRING_BUFLEN];

    if (oldDef)
        virMacAddrFormat(&oldDef->mac, oldMacstr);

    if (newDef)
        virMacAddrFormat(&newDef->mac, newMacstr);

    virDomainAuditGenericDev(vm, "net",
                             oldDef ? oldMacstr : NULL,
                             newDef ? newMacstr : NULL,
                             reason, success);
}

/**
 * virDomainAuditNetDevice:
 * @vmDef: the definition of the VM
 * @netDef: details of network device that fd will be tied to
 * @device: device being opened (such as /dev/vhost-net,
 * /dev/net/tun, /dev/tanN). Note that merely opening a device
 * does not mean that virDomain owns it; a followup virDomainAuditNet
 * shows whether the fd was passed on.
 * @success: true if the device was opened
 *
 * Log an audit message about an attempted network device open.
 */
void
virDomainAuditNetDevice(virDomainDef *vmDef, virDomainNetDef *netDef,
                        const char *device, bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char macstr[VIR_MAC_STRING_BUFLEN];
    g_autofree char *vmname = NULL;
    g_autofree char *dev_name = NULL;
    g_autofree char *rdev = NULL;
    const char *virt = virDomainAuditGetVirtType(vmDef);

    virUUIDFormat(vmDef->uuid, uuidstr);
    virMacAddrFormat(&netDef->mac, macstr);
    rdev = virDomainAuditGetRdev(device);

    if (!(vmname = virAuditEncode("vm", vmDef->name)) ||
        !(dev_name = virAuditEncode("path", device))) {
        VIR_WARN("OOM while encoding audit message");
        return;
    }

    VIR_AUDIT(VIR_AUDIT_RECORD_RESOURCE, success,
              "virt=%s resrc=net reason=open %s uuid=%s net=%s %s rdev=%s",
              virt, vmname, uuidstr, macstr, dev_name, VIR_AUDIT_STR(rdev));
}

/**
 * virDomainAuditHostdev:
 * @vm: domain making a change in pass-through host device
 * @hostdev: device being attached or removed
 * @reason: one of "start", "attach", or "detach"
 * @success: true if the device passthrough operation succeeded
 *
 * Log an audit message about an attempted device passthrough change.
 */
void
virDomainAuditHostdev(virDomainObj *vm, virDomainHostdevDef *hostdev,
                      const char *reason, bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    g_autofree char *vmname = NULL;
    g_autofree char *address = NULL;
    g_autofree char *device = NULL;
    const char *virt = virDomainAuditGetVirtType(vm->def);

    virDomainHostdevSubsysUSB *usbsrc = &hostdev->source.subsys.u.usb;
    virDomainHostdevSubsysPCI *pcisrc = &hostdev->source.subsys.u.pci;
    virDomainHostdevSubsysSCSI *scsisrc = &hostdev->source.subsys.u.scsi;
    virDomainHostdevSubsysSCSIVHost *hostsrc = &hostdev->source.subsys.u.scsi_host;
    virDomainHostdevSubsysMediatedDev *mdevsrc = &hostdev->source.subsys.u.mdev;

    virUUIDFormat(vm->def->uuid, uuidstr);
    if (!(vmname = virAuditEncode("vm", vm->def->name))) {
        VIR_WARN("OOM while encoding audit message");
        return;
    }

    switch (hostdev->mode) {
    case VIR_DOMAIN_HOSTDEV_MODE_SUBSYS:
        switch (hostdev->source.subsys.type) {
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
            address = virPCIDeviceAddressAsString(&pcisrc->addr);
            break;
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
            address = g_strdup_printf("%.3d.%.3d", usbsrc->bus, usbsrc->device);
            break;
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI: {
            if (scsisrc->protocol ==
                VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI) {
                /* Follow virDomainAuditDisk && virDomainAuditGenericDev
                 * and don't audit the networked device.
                 */
                return;
            } else {
                virDomainHostdevSubsysSCSIHost *scsihostsrc = &scsisrc->u.host;

                address = g_strdup_printf("%s:%u:%u:%llu",
                                          scsihostsrc->adapter, scsihostsrc->bus,
                                          scsihostsrc->target,
                                          scsihostsrc->unit);
            }
            break;
        }
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
            address = g_strdup(hostsrc->wwpn);
            break;
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV:
            address = g_strdup(mdevsrc->uuidstr);
            break;
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
        default:
            VIR_WARN("Unexpected hostdev type while encoding audit message: %d",
                     hostdev->source.subsys.type);
            return;
        }

        if (!(device = virAuditEncode("device", VIR_AUDIT_STR(address)))) {
            VIR_WARN("OOM while encoding audit message");
            return;
        }

        VIR_AUDIT(VIR_AUDIT_RECORD_RESOURCE, success,
                  "virt=%s resrc=dev reason=%s %s uuid=%s bus=%s %s",
                  virt, reason, vmname, uuidstr,
                  virDomainHostdevSubsysTypeToString(hostdev->source.subsys.type),
                  device);
        break;

    case VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES:
        switch (hostdev->source.caps.type) {
        case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_STORAGE:
            if (!(device = virAuditEncode("disk",
                                          VIR_AUDIT_STR(hostdev->source.caps.u.storage.block)))) {
                VIR_WARN("OOM while encoding audit message");
                return;
            }

            VIR_AUDIT(VIR_AUDIT_RECORD_RESOURCE, success,
                      "virt=%s resrc=hostdev reason=%s %s uuid=%s %s",
                      virt, reason, vmname, uuidstr, device);
            break;

        case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_MISC:
            if (!(device = virAuditEncode("chardev",
                                          VIR_AUDIT_STR(hostdev->source.caps.u.misc.chardev)))) {
                VIR_WARN("OOM while encoding audit message");
                return;
            }

            VIR_AUDIT(VIR_AUDIT_RECORD_RESOURCE, success,
                      "virt=%s resrc=hostdev reason=%s %s uuid=%s %s",
                      virt, reason, vmname, uuidstr, device);
            break;

        case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_NET:
        case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_LAST:
        default:
            VIR_WARN("Unexpected hostdev type while encoding audit message: %d",
                     hostdev->source.caps.type);
            return;
        }
        break;

    case VIR_DOMAIN_HOSTDEV_MODE_LAST:
    default:
        VIR_WARN("Unexpected hostdev mode while encoding audit message: %d",
                 hostdev->mode);
        return;
    }
}


/**
 * virDomainAuditRedirdev:
 * @vm: domain making a change in pass-through host device
 * @redirdev: device being attached or removed
 * @reason: one of "start", "attach", or "detach"
 * @success: true if the device passthrough operation succeeded
 *
 * Log an audit message about an attempted device passthrough change.
 */
void
virDomainAuditRedirdev(virDomainObj *vm, virDomainRedirdevDef *redirdev,
                      const char *reason, bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    g_autofree char *vmname = NULL;
    g_autofree char *address = NULL;
    g_autofree char *device = NULL;
    const char *virt = virDomainAuditGetVirtType(vm->def);

    virUUIDFormat(vm->def->uuid, uuidstr);
    if (!(vmname = virAuditEncode("vm", vm->def->name))) {
        VIR_WARN("OOM while encoding audit message");
        return;
    }

    switch (redirdev->bus) {
    case VIR_DOMAIN_REDIRDEV_BUS_USB:
        address = g_strdup("USB redirdev");
        break;
    default:
        VIR_WARN("Unexpected redirdev bus while encoding audit message: %d",
                 redirdev->bus);
        return;
    }

    if (!(device = virAuditEncode("device", VIR_AUDIT_STR(address)))) {
        VIR_WARN("OOM while encoding audit message");
        return;
    }

    VIR_AUDIT(VIR_AUDIT_RECORD_RESOURCE, success,
              "virt=%s resrc=dev reason=%s %s uuid=%s bus=%s %s",
              virt, reason, vmname, uuidstr,
              virDomainRedirdevBusTypeToString(redirdev->bus),
              device);
}


/**
 * virDomainAuditTPM:
 * @vm: domain making a change in pass-through host device or emulator
 * @tpm: TPM device being attached or removed
 * @reason: one of "start", "attach", or "detach"
 * @success: true if the device operation succeeded
 *
 * Log an audit message about an attempted device passthrough or emulator
 * change.
 */
static void
virDomainAuditTPM(virDomainObj *vm, virDomainTPMDef *tpm,
                  const char *reason, bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    g_autofree char *vmname = NULL;
    char *path = NULL;
    g_autofree char *device = NULL;
    const char *virt = virDomainAuditGetVirtType(vm->def);

    virUUIDFormat(vm->def->uuid, uuidstr);
    if (!(vmname = virAuditEncode("vm", vm->def->name))) {
        VIR_WARN("OOM while encoding audit message");
        return;
    }

    switch (tpm->type) {
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
        path = tpm->data.passthrough.source->data.file.path;
        if (!(device = virAuditEncode("device", VIR_AUDIT_STR(path)))) {
            VIR_WARN("OOM while encoding audit message");
            return;
        }

        VIR_AUDIT(VIR_AUDIT_RECORD_RESOURCE, success,
                  "virt=%s resrc=tpm reason=%s %s uuid=%s %s",
                  virt, reason, vmname, uuidstr, device);
        break;
    case VIR_DOMAIN_TPM_TYPE_EMULATOR:
        path = tpm->data.emulator.source->data.nix.path;
        if (!(device = virAuditEncode("device", VIR_AUDIT_STR(path)))) {
            VIR_WARN("OOM while encoding audit message");
            return;
        }

        VIR_AUDIT(VIR_AUDIT_RECORD_RESOURCE, success,
                  "virt=%s resrc=tpm-emulator reason=%s %s uuid=%s %s",
                  virt, reason, vmname, uuidstr, device);
        break;
    case VIR_DOMAIN_TPM_TYPE_EXTERNAL:
        path = tpm->data.external.source->data.nix.path;
        if (!(device = virAuditEncode("device", VIR_AUDIT_STR(path)))) {
            VIR_WARN("OOM while encoding audit message");
            return;
        }

        VIR_AUDIT(VIR_AUDIT_RECORD_RESOURCE, success,
                  "virt=%s resrc=tpm-external reason=%s %s uuid=%s %s",
                  virt, reason, vmname, uuidstr, device);
        break;
    case VIR_DOMAIN_TPM_TYPE_LAST:
    default:
        break;
    }
}


/**
 * virDomainAuditCgroup:
 * @vm: domain making the cgroups ACL change
 * @cgroup: cgroup that manages the devices
 * @reason: either "allow" or "deny"
 * @extra: additional details, in the form "all",
 * "major category=xyz maj=nn", or "path path=xyz dev=nn:mm" (the
 * latter two are generated by virDomainAuditCgroupMajor and
 * virDomainAuditCgroupPath).
 * @success: true if the cgroup operation succeeded
 *
 * Log an audit message about an attempted cgroup device ACL change.
 */
void
virDomainAuditCgroup(virDomainObj *vm, virCgroup *cgroup,
                     const char *reason, const char *extra, bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    g_autofree char *vmname = NULL;
    g_autofree char *controller = NULL;
    g_autofree char *detail = NULL;
    const char *virt = virDomainAuditGetVirtType(vm->def);

    virUUIDFormat(vm->def->uuid, uuidstr);
    if (!(vmname = virAuditEncode("vm", vm->def->name))) {
        VIR_WARN("OOM while encoding audit message");
        return;
    }

    ignore_value(virCgroupPathOfController(cgroup,
                                           VIR_CGROUP_CONTROLLER_DEVICES,
                                           NULL, &controller));
    detail = virAuditEncode("cgroup", VIR_AUDIT_STR(controller));

    VIR_AUDIT(VIR_AUDIT_RECORD_RESOURCE, success,
              "virt=%s resrc=cgroup reason=%s %s uuid=%s %s class=%s",
              virt, reason, vmname, uuidstr,
              detail ? detail : "cgroup=?", extra);
}

/**
 * virDomainAuditCgroupMajor:
 * @vm: domain making the cgroups ACL change
 * @cgroup: cgroup that manages the devices
 * @reason: either "allow" or "deny"
 * @maj: the major number of the device category
 * @name: a textual name for that device category, alphabetic only
 * @perms: string containing "r", "w", and/or "m" as appropriate
 * @success: true if the cgroup operation succeeded
 *
 * Log an audit message about an attempted cgroup device ACL change.
 */
void
virDomainAuditCgroupMajor(virDomainObj *vm, virCgroup *cgroup,
                          const char *reason, int maj, const char *name,
                          const char *perms, bool success)
{
    g_autofree char *extra = NULL;

    extra = g_strdup_printf("major category=%s maj=%02X acl=%s",
                            name, maj, perms);

    virDomainAuditCgroup(vm, cgroup, reason, extra, success);
}

/**
 * virDomainAuditCgroupPath:
 * @vm: domain making the cgroups ACL change
 * @cgroup: cgroup that manages the devices
 * @reason: either "allow" or "deny"
 * @path: the device being adjusted
 * @perms: string containing "r", "w", and/or "m" as appropriate
 * @rc: > 0 if not a device, 0 if success, < 0 if failure
 *
 * Log an audit message about an attempted cgroup device ACL change to
 * a specific device.
 */
void
virDomainAuditCgroupPath(virDomainObj *vm, virCgroup *cgroup,
                         const char *reason, const char *path, const char *perms,
                         int rc)
{
    g_autofree char *detail = NULL;
    g_autofree char *rdev = NULL;
    g_autofree char *extra = NULL;

    /* Nothing to audit for regular files.  */
    if (rc > 0)
        return;

    rdev = virDomainAuditGetRdev(path);

    if (!(detail = virAuditEncode("path", path))) {
        VIR_WARN("OOM while encoding audit message");
        return;
    }

    extra = g_strdup_printf("path %s rdev=%s acl=%s",
                            detail, VIR_AUDIT_STR(rdev), perms);

    virDomainAuditCgroup(vm, cgroup, reason, extra, rc == 0);
}

/**
 * virDomainAuditResource:
 * @vm: domain making an integer resource change
 * @resource: name of the resource: "mem" or "vcpu"
 * @oldval: the old value of the resource
 * @newval: the new value of the resource
 * @reason: either "start" or "update"
 * @success: true if the resource change succeeded
 *
 * Log an audit message about an attempted resource change.
 */
static void
virDomainAuditResource(virDomainObj *vm, const char *resource,
                       unsigned long long oldval, unsigned long long newval,
                       const char *reason, bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    g_autofree char *vmname = NULL;
    const char *virt = virDomainAuditGetVirtType(vm->def);

    virUUIDFormat(vm->def->uuid, uuidstr);
    if (!(vmname = virAuditEncode("vm", vm->def->name))) {
        VIR_WARN("OOM while encoding audit message");
        return;
    }

    VIR_AUDIT(VIR_AUDIT_RECORD_RESOURCE, success,
              "virt=%s resrc=%s reason=%s %s uuid=%s old-%s=%lld new-%s=%lld",
              virt, resource, reason, vmname, uuidstr,
              resource, oldval, resource, newval);
}

void
virDomainAuditMemory(virDomainObj *vm,
                     unsigned long long oldmem, unsigned long long newmem,
                     const char *reason, bool success)
{
    return virDomainAuditResource(vm, "mem", oldmem, newmem, reason, success);
}

void
virDomainAuditVcpu(virDomainObj *vm,
                   unsigned int oldvcpu, unsigned int newvcpu,
                   const char *reason, bool success)
{
    return virDomainAuditResource(vm, "vcpu", oldvcpu, newvcpu, reason, success);
}

void
virDomainAuditIOThread(virDomainObj *vm,
                       unsigned int oldiothread, unsigned int newiothread,
                       const char *reason, bool success)
{
    return virDomainAuditResource(vm, "iothread", oldiothread, newiothread,
                                  reason, success);
}

static void
virDomainAuditLifecycle(virDomainObj *vm, const char *op,
                        const char *reason, bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    g_autofree char *vmname = NULL;
    const char *virt = virDomainAuditGetVirtType(vm->def);

    virUUIDFormat(vm->def->uuid, uuidstr);

    if (!(vmname = virAuditEncode("vm", vm->def->name))) {
        VIR_WARN("OOM while encoding audit message");
        return;
    }

    VIR_AUDIT(VIR_AUDIT_RECORD_MACHINE_CONTROL, success,
              "virt=%s op=%s reason=%s %s uuid=%s vm-pid=%lld",
              virt, op, reason, vmname, uuidstr, (long long)vm->pid);
}


void
virDomainAuditStart(virDomainObj *vm, const char *reason, bool success)
{
    size_t i;

    for (i = 0; i < vm->def->ndisks; i++)
        virDomainAuditDisk(vm, NULL, vm->def->disks[i]->src, "start", true);

    for (i = 0; i < vm->def->nfss; i++) {
        virDomainFSDef *fs = vm->def->fss[i];
        virDomainAuditFS(vm, NULL, fs, "start", true);
    }

    for (i = 0; i < vm->def->nnets; i++) {
        virDomainNetDef *net = vm->def->nets[i];
        virDomainAuditNet(vm, NULL, net, "start", true);
    }

    for (i = 0; i < vm->def->nhostdevs; i++) {
        virDomainHostdevDef *hostdev = vm->def->hostdevs[i];
        virDomainAuditHostdev(vm, hostdev, "start", true);
    }

    for (i = 0; i < vm->def->nredirdevs; i++) {
        virDomainRedirdevDef *redirdev = vm->def->redirdevs[i];
        virDomainAuditRedirdev(vm, redirdev, "start", true);
    }

    for (i = 0; i < vm->def->nserials; i++)
        virDomainAuditChardev(vm, NULL, vm->def->serials[i], "start", true);

    for (i = 0; i < vm->def->nparallels; i++)
        virDomainAuditChardev(vm, NULL, vm->def->parallels[i], "start", true);

    for (i = 0; i < vm->def->nchannels; i++)
        virDomainAuditChardev(vm, NULL, vm->def->channels[i], "start", true);

    for (i = 0; i < vm->def->nconsoles; i++) {
        if (i == 0 &&
            (vm->def->consoles[i]->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL ||
             vm->def->consoles[i]->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_NONE) &&
             vm->def->os.type == VIR_DOMAIN_OSTYPE_HVM)
            continue;

        virDomainAuditChardev(vm, NULL, vm->def->consoles[i], "start", true);
    }

    for (i = 0; i < vm->def->nsmartcards; i++)
        virDomainAuditSmartcard(vm, vm->def->smartcards[i], "start", true);

    for (i = 0; i < vm->def->nrngs; i++)
        virDomainAuditRNG(vm, NULL, vm->def->rngs[i], "start", true);

    for (i = 0; i < vm->def->ntpms; i++)
        virDomainAuditTPM(vm, vm->def->tpms[i], "start", true);

    for (i = 0; i < vm->def->nshmems; i++)
        virDomainAuditShmem(vm, vm->def->shmems[i], "start", true);

    for (i = 0; i < vm->def->ninputs; i++)
        virDomainAuditInput(vm, vm->def->inputs[i], "start", true);

    virDomainAuditMemory(vm, 0, virDomainDefGetMemoryTotal(vm->def),
                         "start", true);
    virDomainAuditVcpu(vm, 0, virDomainDefGetVcpus(vm->def), "start", true);
    if (vm->def->niothreadids)
        virDomainAuditIOThread(vm, 0, vm->def->niothreadids, "start", true);

    virDomainAuditLifecycle(vm, "start", reason, success);
}

void
virDomainAuditInit(virDomainObj *vm,
                   pid_t initpid,
                   ino_t pidns)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    g_autofree char *vmname = NULL;
    const char *virt = virDomainAuditGetVirtType(vm->def);

    virUUIDFormat(vm->def->uuid, uuidstr);

    if (!(vmname = virAuditEncode("vm", vm->def->name))) {
        VIR_WARN("OOM while encoding audit message");
        return;
    }

    VIR_AUDIT(VIR_AUDIT_RECORD_MACHINE_CONTROL, true,
              "virt=%s op=init %s uuid=%s vm-pid=%lld init-pid=%lld pid-ns=%lld",
              virt, vmname, uuidstr, (long long)vm->pid, (long long)initpid,
              (long long)pidns);
}

void
virDomainAuditStop(virDomainObj *vm, const char *reason)
{
    virDomainAuditLifecycle(vm, "stop", reason, true);
}

void
virDomainAuditSecurityLabel(virDomainObj *vm, bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    g_autofree char *vmname = NULL;
    size_t i;
    const char *virt = virDomainAuditGetVirtType(vm->def);

    virUUIDFormat(vm->def->uuid, uuidstr);
    if (!(vmname = virAuditEncode("vm", vm->def->name))) {
        VIR_WARN("OOM while encoding audit message");
        return;
    }

    for (i = 0; i < vm->def->nseclabels; i++) {
        VIR_AUDIT(VIR_AUDIT_RECORD_MACHINE_ID, success,
                  "virt=%s %s uuid=%s vm-ctx=%s img-ctx=%s model=%s",
                  virt, vmname, uuidstr,
                  VIR_AUDIT_STR(vm->def->seclabels[i]->label),
                  VIR_AUDIT_STR(vm->def->seclabels[i]->imagelabel),
                  VIR_AUDIT_STR(vm->def->seclabels[i]->model));
    }
}

void
virDomainAuditShmem(virDomainObj *vm,
                    virDomainShmemDef *def,
                    const char *reason, bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    g_autofree char *vmname = virAuditEncode("vm", vm->def->name);
    const char *srcpath = virDomainChrSourceDefGetPath(def->server.chr);
    const char *virt = virDomainAuditGetVirtType(vm->def);
    g_autofree char *shmpath = NULL;

    virUUIDFormat(vm->def->uuid, uuidstr);

    if (!vmname) {
        VIR_WARN("OOM while encoding audit message");
        return;
    }

    shmpath = g_strdup_printf("/dev/shm/%s", def->name);

    if (!virt) {
        VIR_WARN("Unexpected virt type %d while encoding audit message",
                 vm->def->virtType);
        virt = "?";
    }

    if (def->server.enabled) {
        VIR_AUDIT(VIR_AUDIT_RECORD_RESOURCE, success,
                  "virt=%s resrc=ivshmem-socket reason=%s %s uuid=%s path=%s",
                  virt, reason, vmname, uuidstr, VIR_AUDIT_STR(srcpath));
    } else {
        VIR_AUDIT(VIR_AUDIT_RECORD_RESOURCE, success,
                  "virt=%s resrc=shmem reason=%s %s uuid=%s size=%llu path=%s",
                  virt, reason, vmname, uuidstr, def->size, VIR_AUDIT_STR(shmpath));
   }
}


void
virDomainAuditInput(virDomainObj *vm,
                    virDomainInputDef *input,
                    const char *reason,
                    bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    g_autofree char *vmname = NULL;
    const char *virt = virDomainAuditGetVirtType(vm->def);

    virUUIDFormat(vm->def->uuid, uuidstr);

    if (!(vmname = virAuditEncode("vm", vm->def->name)))
        return;

    switch ((virDomainInputType) input->type) {
    case VIR_DOMAIN_INPUT_TYPE_MOUSE:
    case VIR_DOMAIN_INPUT_TYPE_TABLET:
    case VIR_DOMAIN_INPUT_TYPE_KBD:
        break;

    case VIR_DOMAIN_INPUT_TYPE_PASSTHROUGH:
    case VIR_DOMAIN_INPUT_TYPE_EVDEV:
        VIR_AUDIT(VIR_AUDIT_RECORD_RESOURCE, success,
                  "virt=%s resrc=evdev reason=%s %s uuid=%s path=%s",
                  virt, reason, vmname, uuidstr, VIR_AUDIT_STR(input->source.evdev));
        break;

    case VIR_DOMAIN_INPUT_TYPE_LAST:
        break;
    }
}
