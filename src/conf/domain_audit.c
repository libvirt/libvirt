/*
 * domain_audit.c: Domain audit management
 *
 * Copyright (C) 2006-2012 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "domain_audit.h"
#include "viraudit.h"
#include "uuid.h"
#include "logging.h"
#include "memory.h"
#include "ignore-value.h"

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
        ignore_value(virAsprintf(&ret, "%02X:%02X", maj, min));
    }
    return ret;
}
#else
static char *
virDomainAuditGetRdev(const char *path ATTRIBUTE_UNUSED)
{
    return NULL;
}
#endif

void
virDomainAuditDisk(virDomainObjPtr vm,
                   const char *oldDef, const char *newDef,
                   const char *reason, bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *vmname;
    char *oldsrc = NULL;
    char *newsrc = NULL;
    const char *virt;

    virUUIDFormat(vm->def->uuid, uuidstr);
    if (!(vmname = virAuditEncode("vm", vm->def->name))) {
        VIR_WARN("OOM while encoding audit message");
        return;
    }

    if (!(virt = virDomainVirtTypeToString(vm->def->virtType))) {
        VIR_WARN("Unexpected virt type %d while encoding audit message", vm->def->virtType);
        virt = "?";
    }

    if (!(oldsrc = virAuditEncode("old-disk", VIR_AUDIT_STR(oldDef)))) {
        VIR_WARN("OOM while encoding audit message");
        goto cleanup;
    }
    if (!(newsrc = virAuditEncode("new-disk", VIR_AUDIT_STR(newDef)))) {
        VIR_WARN("OOM while encoding audit message");
        goto cleanup;
    }

    VIR_AUDIT(VIR_AUDIT_RECORD_RESOURCE, success,
              "virt=%s resrc=disk reason=%s %s uuid=%s %s %s",
              virt, reason, vmname, uuidstr,
              oldsrc, newsrc);

cleanup:
    VIR_FREE(vmname);
    VIR_FREE(oldsrc);
    VIR_FREE(newsrc);
}


void
virDomainAuditFS(virDomainObjPtr vm,
                 virDomainFSDefPtr oldDef, virDomainFSDefPtr newDef,
                 const char *reason, bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *vmname;
    char *oldsrc = NULL;
    char *newsrc = NULL;
    const char *virt;

    virUUIDFormat(vm->def->uuid, uuidstr);
    if (!(vmname = virAuditEncode("vm", vm->def->name))) {
        VIR_WARN("OOM while encoding audit message");
        return;
    }

    if (!(virt = virDomainVirtTypeToString(vm->def->virtType))) {
        VIR_WARN("Unexpected virt type %d while encoding audit message", vm->def->virtType);
        virt = "?";
    }

    if (!(oldsrc = virAuditEncode("old-fs",
                                  oldDef && oldDef->src ?
                                  oldDef->src : "?"))) {
        VIR_WARN("OOM while encoding audit message");
        goto cleanup;
    }
    if (!(newsrc = virAuditEncode("new-fs",
                                  newDef && newDef->src ?
                                  newDef->src : "?"))) {
        VIR_WARN("OOM while encoding audit message");
        goto cleanup;
    }

    VIR_AUDIT(VIR_AUDIT_RECORD_RESOURCE, success,
              "virt=%s resrc=fs reason=%s %s uuid=%s %s %s",
              virt, reason, vmname, uuidstr,
              oldsrc, newsrc);

cleanup:
    VIR_FREE(vmname);
    VIR_FREE(oldsrc);
    VIR_FREE(newsrc);
}


void
virDomainAuditNet(virDomainObjPtr vm,
                  virDomainNetDefPtr oldDef, virDomainNetDefPtr newDef,
                  const char *reason, bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char newMacstr[VIR_MAC_STRING_BUFLEN];
    char oldMacstr[VIR_MAC_STRING_BUFLEN];
    char *vmname;
    const char *virt;

    virUUIDFormat(vm->def->uuid, uuidstr);
    if (oldDef)
        virMacAddrFormat(oldDef->mac, oldMacstr);
    if (newDef)
        virMacAddrFormat(newDef->mac, newMacstr);
    if (!(vmname = virAuditEncode("vm", vm->def->name))) {
        VIR_WARN("OOM while encoding audit message");
        return;
    }

    if (!(virt = virDomainVirtTypeToString(vm->def->virtType))) {
        VIR_WARN("Unexpected virt type %d while encoding audit message", vm->def->virtType);
        virt = "?";
    }

    VIR_AUDIT(VIR_AUDIT_RECORD_RESOURCE, success,
              "virt=%s resrc=net reason=%s %s uuid=%s old-net=%s new-net=%s",
              virt, reason, vmname, uuidstr,
              oldDef ? oldMacstr : "?",
              newDef ? newMacstr : "?");

    VIR_FREE(vmname);
}

/**
 * virDomainAuditNetDevice:
 * @vm: domain opening a network-related device
 * @def: details of network device that fd will be tied to
 * @device: device being opened (such as /dev/vhost-net,
 * /dev/net/tun, /dev/tanN). Note that merely opening a device
 * does not mean that virDomain owns it; a followup virDomainAuditNet
 * shows whether the fd was passed on.
 * @success: true if the device was opened
 *
 * Log an audit message about an attempted network device open.
 */
void
virDomainAuditNetDevice(virDomainDefPtr vmDef, virDomainNetDefPtr netDef,
                        const char *device, bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char macstr[VIR_MAC_STRING_BUFLEN];
    char *vmname;
    char *dev_name;
    char *rdev;
    const char *virt;

    virUUIDFormat(vmDef->uuid, uuidstr);
    virMacAddrFormat(netDef->mac, macstr);
    rdev = virDomainAuditGetRdev(device);

    if (!(vmname = virAuditEncode("vm", vmDef->name)) ||
        !(dev_name = virAuditEncode("path", device))) {
        VIR_WARN("OOM while encoding audit message");
        goto cleanup;
    }

    if (!(virt = virDomainVirtTypeToString(vmDef->virtType))) {
        VIR_WARN("Unexpected virt type %d while encoding audit message", vmDef->virtType);
        virt = "?";
    }

    VIR_AUDIT(VIR_AUDIT_RECORD_RESOURCE, success,
              "virt=%s resrc=net reason=open %s uuid=%s net=%s %s rdev=%s",
              virt, vmname, uuidstr, macstr, dev_name, VIR_AUDIT_STR(rdev));

cleanup:
    VIR_FREE(vmname);
    VIR_FREE(dev_name);
    VIR_FREE(rdev);
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
virDomainAuditHostdev(virDomainObjPtr vm, virDomainHostdevDefPtr hostdev,
                      const char *reason, bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *vmname;
    char *address = NULL;
    char *device = NULL;
    const char *virt;

    virUUIDFormat(vm->def->uuid, uuidstr);
    if (!(vmname = virAuditEncode("vm", vm->def->name))) {
        VIR_WARN("OOM while encoding audit message");
        return;
    }

    if (!(virt = virDomainVirtTypeToString(vm->def->virtType))) {
        VIR_WARN("Unexpected virt type %d while encoding audit message", vm->def->virtType);
        virt = "?";
    }

    switch (hostdev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
        if (virAsprintf(&address, "%.4x:%.2x:%.2x.%.1x",
                        hostdev->source.subsys.u.pci.domain,
                        hostdev->source.subsys.u.pci.bus,
                        hostdev->source.subsys.u.pci.slot,
                        hostdev->source.subsys.u.pci.function) < 0) {
            VIR_WARN("OOM while encoding audit message");
            goto cleanup;
        }
        break;
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        if (virAsprintf(&address, "%.3d.%.3d",
                        hostdev->source.subsys.u.usb.bus,
                        hostdev->source.subsys.u.usb.device) < 0) {
            VIR_WARN("OOM while encoding audit message");
            goto cleanup;
        }
        break;
    default:
        VIR_WARN("Unexpected hostdev type while encoding audit message: %d",
                 hostdev->source.subsys.type);
        goto cleanup;
    }

    if (!(device = virAuditEncode("device", VIR_AUDIT_STR(address)))) {
        VIR_WARN("OOM while encoding audit message");
        goto cleanup;
    }

    VIR_AUDIT(VIR_AUDIT_RECORD_RESOURCE, success,
              "virt=%s resrc=dev reason=%s %s uuid=%s bus=%s %s",
              virt, reason, vmname, uuidstr,
              virDomainHostdevSubsysTypeToString(hostdev->source.subsys.type),
              device);

cleanup:
    VIR_FREE(vmname);
    VIR_FREE(device);
    VIR_FREE(address);
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
virDomainAuditRedirdev(virDomainObjPtr vm, virDomainRedirdevDefPtr redirdev,
                      const char *reason, bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *vmname;
    char *address = NULL;
    char *device = NULL;
    const char *virt;

    virUUIDFormat(vm->def->uuid, uuidstr);
    if (!(vmname = virAuditEncode("vm", vm->def->name))) {
        VIR_WARN("OOM while encoding audit message");
        return;
    }

    if (!(virt = virDomainVirtTypeToString(vm->def->virtType))) {
        VIR_WARN("Unexpected virt type %d while encoding audit message", vm->def->virtType);
        virt = "?";
    }

    switch (redirdev->bus) {
    case VIR_DOMAIN_REDIRDEV_BUS_USB:
        if (virAsprintf(&address, "USB redirdev") < 0) {
            VIR_WARN("OOM while encoding audit message");
            goto cleanup;
        }
        break;
    default:
        VIR_WARN("Unexpected redirdev bus while encoding audit message: %d",
                 redirdev->bus);
        goto cleanup;
    }

    if (!(device = virAuditEncode("device", VIR_AUDIT_STR(address)))) {
        VIR_WARN("OOM while encoding audit message");
        goto cleanup;
    }

    VIR_AUDIT(VIR_AUDIT_RECORD_RESOURCE, success,
              "virt=%s resrc=dev reason=%s %s uuid=%s bus=%s %s",
              virt, reason, vmname, uuidstr,
              virDomainRedirdevBusTypeToString(redirdev->bus),
              device);

cleanup:
    VIR_FREE(vmname);
    VIR_FREE(device);
    VIR_FREE(address);
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
virDomainAuditCgroup(virDomainObjPtr vm, virCgroupPtr cgroup,
                     const char *reason, const char *extra, bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *vmname;
    char *controller = NULL;
    char *detail;
    const char *virt;

    virUUIDFormat(vm->def->uuid, uuidstr);
    if (!(vmname = virAuditEncode("vm", vm->def->name))) {
        VIR_WARN("OOM while encoding audit message");
        return;
    }

    if (!(virt = virDomainVirtTypeToString(vm->def->virtType))) {
        VIR_WARN("Unexpected virt type %d while encoding audit message", vm->def->virtType);
        virt = "?";
    }

    ignore_value(virCgroupPathOfController(cgroup,
                                           VIR_CGROUP_CONTROLLER_DEVICES,
                                           NULL, &controller));
    detail = virAuditEncode("cgroup", VIR_AUDIT_STR(controller));

    VIR_AUDIT(VIR_AUDIT_RECORD_RESOURCE, success,
              "virt=%s resrc=cgroup reason=%s %s uuid=%s %s class=%s",
              virt, reason, vmname, uuidstr,
              detail ? detail : "cgroup=?", extra);

    VIR_FREE(vmname);
    VIR_FREE(controller);
    VIR_FREE(detail);
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
virDomainAuditCgroupMajor(virDomainObjPtr vm, virCgroupPtr cgroup,
                          const char *reason, int maj, const char *name,
                          const char *perms, bool success)
{
    char *extra;

    if (virAsprintf(&extra, "major category=%s maj=%02X acl=%s",
                    name, maj, perms) < 0) {
        VIR_WARN("OOM while encoding audit message");
        return;
    }

    virDomainAuditCgroup(vm, cgroup, reason, extra, success);

    VIR_FREE(extra);
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
virDomainAuditCgroupPath(virDomainObjPtr vm, virCgroupPtr cgroup,
                         const char *reason, const char *path, const char *perms,
                         int rc)
{
    char *detail;
    char *rdev;
    char *extra;

    /* Nothing to audit for regular files.  */
    if (rc > 0)
        return;

    rdev = virDomainAuditGetRdev(path);

    if (!(detail = virAuditEncode("path", path)) ||
        virAsprintf(&extra, "path path=%s rdev=%s acl=%s",
                    path, VIR_AUDIT_STR(rdev), perms) < 0) {
        VIR_WARN("OOM while encoding audit message");
        goto cleanup;
    }

    virDomainAuditCgroup(vm, cgroup, reason, extra, rc == 0);

cleanup:
    VIR_FREE(extra);
    VIR_FREE(detail);
    VIR_FREE(rdev);
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
virDomainAuditResource(virDomainObjPtr vm, const char *resource,
                       unsigned long long oldval, unsigned long long newval,
                       const char *reason, bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *vmname;
    const char *virt;

    virUUIDFormat(vm->def->uuid, uuidstr);
    if (!(vmname = virAuditEncode("vm", vm->def->name))) {
        VIR_WARN("OOM while encoding audit message");
        return;
    }

    if (!(virt = virDomainVirtTypeToString(vm->def->virtType))) {
        VIR_WARN("Unexpected virt type %d while encoding audit message", vm->def->virtType);
        virt = "?";
    }

    VIR_AUDIT(VIR_AUDIT_RECORD_RESOURCE, success,
              "virt=%s resrc=%s reason=%s %s uuid=%s old-%s=%lld new-%s=%lld",
              virt, resource, reason, vmname, uuidstr,
              resource, oldval, resource, newval);

    VIR_FREE(vmname);
}

void
virDomainAuditMemory(virDomainObjPtr vm,
                     unsigned long long oldmem, unsigned long long newmem,
                     const char *reason, bool success)
{
    return virDomainAuditResource(vm, "mem", oldmem, newmem, reason, success);
}

void
virDomainAuditVcpu(virDomainObjPtr vm,
                   unsigned int oldvcpu, unsigned int newvcpu,
                   const char *reason, bool success)
{
    return virDomainAuditResource(vm, "vcpu", oldvcpu, newvcpu, reason, success);
}

static void
virDomainAuditLifecycle(virDomainObjPtr vm, const char *op,
                        const char *reason, bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *vmname;
    const char *virt;

    virUUIDFormat(vm->def->uuid, uuidstr);

    if (!(vmname = virAuditEncode("vm", vm->def->name))) {
        VIR_WARN("OOM while encoding audit message");
        return;
    }

    if (!(virt = virDomainVirtTypeToString(vm->def->virtType))) {
        VIR_WARN("Unexpected virt type %d while encoding audit message", vm->def->virtType);
        virt = "?";
    }

    VIR_AUDIT(VIR_AUDIT_RECORD_MACHINE_CONTROL, success,
              "virt=%s op=%s reason=%s %s uuid=%s vm-pid=%d",
              virt, op, reason, vmname, uuidstr, vm->pid);

    VIR_FREE(vmname);
}


void
virDomainAuditStart(virDomainObjPtr vm, const char *reason, bool success)
{
    int i;

    for (i = 0 ; i < vm->def->ndisks ; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];
        if (disk->src) /* Skips CDROM without media initially inserted */
            virDomainAuditDisk(vm, NULL, disk->src, "start", true);
    }

    for (i = 0 ; i < vm->def->nfss ; i++) {
        virDomainFSDefPtr fs = vm->def->fss[i];
        virDomainAuditFS(vm, NULL, fs, "start", true);
    }

    for (i = 0 ; i < vm->def->nnets ; i++) {
        virDomainNetDefPtr net = vm->def->nets[i];
        virDomainAuditNet(vm, NULL, net, "start", true);
    }

    for (i = 0 ; i < vm->def->nhostdevs ; i++) {
        virDomainHostdevDefPtr hostdev = vm->def->hostdevs[i];
        virDomainAuditHostdev(vm, hostdev, "start", true);
    }

    for (i = 0 ; i < vm->def->nredirdevs ; i++) {
        virDomainRedirdevDefPtr redirdev = vm->def->redirdevs[i];
        virDomainAuditRedirdev(vm, redirdev, "start", true);
    }

    virDomainAuditMemory(vm, 0, vm->def->mem.cur_balloon, "start", true);
    virDomainAuditVcpu(vm, 0, vm->def->vcpus, "start", true);

    virDomainAuditLifecycle(vm, "start", reason, success);
}


void
virDomainAuditStop(virDomainObjPtr vm, const char *reason)
{
    virDomainAuditLifecycle(vm, "stop", reason, true);
}

void
virDomainAuditSecurityLabel(virDomainObjPtr vm, bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *vmname;
    const char *virt;

    virUUIDFormat(vm->def->uuid, uuidstr);
    if (!(vmname = virAuditEncode("vm", vm->def->name))) {
        VIR_WARN("OOM while encoding audit message");
        return;
    }

    if (!(virt = virDomainVirtTypeToString(vm->def->virtType))) {
        VIR_WARN("Unexpected virt type %d while encoding audit message", vm->def->virtType);
        virt = "?";
    }

    VIR_AUDIT(VIR_AUDIT_RECORD_MACHINE_ID, success,
              "virt=%s %s uuid=%s vm-ctx=%s img-ctx=%s",
              virt, vmname, uuidstr,
              VIR_AUDIT_STR(vm->def->seclabel.label),
              VIR_AUDIT_STR(vm->def->seclabel.imagelabel));

    VIR_FREE(vmname);
}
