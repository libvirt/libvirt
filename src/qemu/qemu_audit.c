/*
 * qemu_audit.c: QEMU audit management
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
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

#include "qemu_audit.h"
#include "virtaudit.h"
#include "uuid.h"
#include "logging.h"
#include "memory.h"
#include "ignore-value.h"

/* Return nn:mm in hex for block and character devices, and NULL
 * for other file types, stat failure, or allocation failure.  */
#if defined major && defined minor
static char *
qemuAuditGetRdev(const char *path)
{
    char *ret = NULL;
    struct stat sb;

    if (stat(path, &sb) == 0 &&
        (S_ISCHR(sb.st_mode) || S_ISBLK(sb.st_mode))) {
        int maj = major(sb.st_rdev);
        int min = minor(sb.st_rdev);
        virAsprintf(&ret, "%02X:%02X", maj, min);
    }
    return ret;
}
#else
static char *
qemuAuditGetRdev(const char *path ATTRIBUTE_UNUSED)
{
    return NULL;
}
#endif

void
qemuAuditDisk(virDomainObjPtr vm,
              virDomainDiskDefPtr oldDef, virDomainDiskDefPtr newDef,
              const char *reason, bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *vmname;
    char *oldsrc = NULL;
    char *newsrc = NULL;

    virUUIDFormat(vm->def->uuid, uuidstr);
    if (!(vmname = virAuditEncode("vm", vm->def->name))) {
        VIR_WARN("OOM while encoding audit message");
        return;
    }

    if (!(oldsrc = virAuditEncode("old-disk",
                                  oldDef && oldDef->src ?
                                  oldDef->src : "?"))) {
        VIR_WARN("OOM while encoding audit message");
        goto cleanup;
    }
    if (!(newsrc = virAuditEncode("new-disk",
                                  newDef && newDef->src ?
                                  newDef->src : "?"))) {
        VIR_WARN("OOM while encoding audit message");
        goto cleanup;
    }

    VIR_AUDIT(VIR_AUDIT_RECORD_RESOURCE, success,
              "resrc=disk reason=%s %s uuid=%s %s %s",
              reason, vmname, uuidstr,
              oldsrc, newsrc);

cleanup:
    VIR_FREE(vmname);
    VIR_FREE(oldsrc);
    VIR_FREE(newsrc);
}


void
qemuAuditNet(virDomainObjPtr vm,
             virDomainNetDefPtr oldDef, virDomainNetDefPtr newDef,
             const char *reason, bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char newMacstr[VIR_MAC_STRING_BUFLEN];
    char oldMacstr[VIR_MAC_STRING_BUFLEN];
    char *vmname;

    virUUIDFormat(vm->def->uuid, uuidstr);
    if (oldDef)
        virFormatMacAddr(oldDef->mac, oldMacstr);
    if (newDef)
        virFormatMacAddr(newDef->mac, newMacstr);
    if (!(vmname = virAuditEncode("vm", vm->def->name))) {
        VIR_WARN("OOM while encoding audit message");
        return;
    }

    VIR_AUDIT(VIR_AUDIT_RECORD_RESOURCE, success,
              "resrc=net reason=%s %s uuid=%s old-net='%s' new-net='%s'",
              reason, vmname, uuidstr,
              oldDef ? oldMacstr : "?",
              newDef ? newMacstr : "?");

    VIR_FREE(vmname);
}

/**
 * qemuAuditNetDevice:
 * @vm: domain opening a network-related device
 * @def: details of network device that fd will be tied to
 * @device: device being opened (such as /dev/vhost-net,
 * /dev/net/tun, /dev/tanN). Note that merely opening a device
 * does not mean that qemu owns it; a followup qemuAuditNet
 * shows whether the fd was passed on.
 * @success: true if the device was opened
 *
 * Log an audit message about an attempted network device open.
 */
void
qemuAuditNetDevice(virDomainDefPtr vmDef, virDomainNetDefPtr netDef,
                   const char *device, bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char macstr[VIR_MAC_STRING_BUFLEN];
    char *vmname;
    char *devname;
    char *rdev;

    virUUIDFormat(vmDef->uuid, uuidstr);
    virFormatMacAddr(netDef->mac, macstr);
    rdev = qemuAuditGetRdev(device);

    if (!(vmname = virAuditEncode("vm", vmDef->name)) ||
        !(devname = virAuditEncode("path", device))) {
        VIR_WARN("OOM while encoding audit message");
        goto cleanup;
    }

    VIR_AUDIT(VIR_AUDIT_RECORD_RESOURCE, success,
              "resrc=net reason=open %s uuid=%s net='%s' %s rdev=%s",
              vmname, uuidstr, macstr, devname, VIR_AUDIT_STR(rdev));

cleanup:
    VIR_FREE(vmname);
    VIR_FREE(devname);
    VIR_FREE(rdev);
}

/**
 * qemuAuditHostdev:
 * @vm: domain making a change in pass-through host device
 * @hostdev: device being attached or removed
 * @reason: one of "start", "attach", or "detach"
 * @success: true if the device passthrough operation succeeded
 *
 * Log an audit message about an attempted device passthrough change.
 */
void
qemuAuditHostdev(virDomainObjPtr vm, virDomainHostdevDefPtr hostdev,
                 const char *reason, bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *vmname;
    char *address;
    char *device;

    virUUIDFormat(vm->def->uuid, uuidstr);
    if (!(vmname = virAuditEncode("vm", vm->def->name))) {
        VIR_WARN("OOM while encoding audit message");
        return;
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
              "resrc=dev reason=%s %s uuid=%s bus=%s %s",
              reason, vmname, uuidstr,
              virDomainHostdevSubsysTypeToString(hostdev->source.subsys.type),
              device);

cleanup:
    VIR_FREE(vmname);
    VIR_FREE(device);
    VIR_FREE(address);
}


/**
 * qemuAuditCgroup:
 * @vm: domain making the cgroups ACL change
 * @cgroup: cgroup that manages the devices
 * @reason: either "allow" or "deny"
 * @extra: additional details, in the form "all",
 * "major category=xyz maj=nn", or "path path=xyz dev=nn:mm" (the
 * latter two are generated by qemuAuditCgroupMajor and
 * qemuAuditCgroupPath).
 * @success: true if the cgroup operation succeeded
 *
 * Log an audit message about an attempted cgroup device ACL change.
 */
void
qemuAuditCgroup(virDomainObjPtr vm, virCgroupPtr cgroup,
                const char *reason, const char *extra, bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *vmname;
    char *controller = NULL;
    char *detail;

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
              "resrc=cgroup reason=%s %s uuid=%s %s class=%s",
              reason, vmname, uuidstr,
              detail ? detail : "cgroup=?", extra);

    VIR_FREE(vmname);
    VIR_FREE(controller);
    VIR_FREE(detail);
}

/**
 * qemuAuditCgroupMajor:
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
qemuAuditCgroupMajor(virDomainObjPtr vm, virCgroupPtr cgroup,
                     const char *reason, int maj, const char *name,
                     const char *perms, bool success)
{
    char *extra;

    if (virAsprintf(&extra, "major category=%s maj=%02X acl=%s",
                    name, maj, perms) < 0) {
        VIR_WARN("OOM while encoding audit message");
        return;
    }

    qemuAuditCgroup(vm, cgroup, reason, extra, success);

    VIR_FREE(extra);
}

/**
 * qemuAuditCgroupPath:
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
qemuAuditCgroupPath(virDomainObjPtr vm, virCgroupPtr cgroup,
                    const char *reason, const char *path, const char *perms,
                    int rc)
{
    char *detail;
    char *rdev;
    char *extra;

    /* Nothing to audit for regular files.  */
    if (rc > 0)
        return;

    rdev = qemuAuditGetRdev(path);

    if (!(detail = virAuditEncode("path", path)) ||
        virAsprintf(&extra, "path path=%s rdev=%s acl=%s",
                    path, VIR_AUDIT_STR(rdev), perms) < 0) {
        VIR_WARN("OOM while encoding audit message");
        goto cleanup;
    }

    qemuAuditCgroup(vm, cgroup, reason, extra, rc == 0);

cleanup:
    VIR_FREE(extra);
    VIR_FREE(detail);
    VIR_FREE(rdev);
}

/**
 * qemuAuditResource:
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
qemuAuditResource(virDomainObjPtr vm, const char *resource,
                  unsigned long long oldval, unsigned long long newval,
                  const char *reason, bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *vmname;

    virUUIDFormat(vm->def->uuid, uuidstr);
    if (!(vmname = virAuditEncode("vm", vm->def->name))) {
        VIR_WARN("OOM while encoding audit message");
        return;
    }

    VIR_AUDIT(VIR_AUDIT_RECORD_RESOURCE, success,
              "resrc=%s reason=%s %s uuid=%s old-%s=%lld new-%s=%lld",
              resource, reason, vmname, uuidstr,
              resource, oldval, resource, newval);

    VIR_FREE(vmname);
}

void
qemuAuditMemory(virDomainObjPtr vm,
                unsigned long long oldmem, unsigned long long newmem,
                const char *reason, bool success)
{
    return qemuAuditResource(vm, "mem", oldmem, newmem, reason, success);
}

void
qemuAuditVcpu(virDomainObjPtr vm,
              unsigned int oldvcpu, unsigned int newvcpu,
              const char *reason, bool success)
{
    return qemuAuditResource(vm, "vcpu", oldvcpu, newvcpu, reason, success);
}

static void
qemuAuditLifecycle(virDomainObjPtr vm, const char *op,
                   const char *reason, bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *vmname;

    virUUIDFormat(vm->def->uuid, uuidstr);

    if (!(vmname = virAuditEncode("vm", vm->def->name))) {
        VIR_WARN("OOM while encoding audit message");
        return;
    }

    VIR_AUDIT(VIR_AUDIT_RECORD_MACHINE_CONTROL, success,
              "op=%s reason=%s %s uuid=%s", op, reason, vmname, uuidstr);

    VIR_FREE(vmname);
}


void
qemuAuditDomainStart(virDomainObjPtr vm, const char *reason, bool success)
{
    int i;

    for (i = 0 ; i < vm->def->ndisks ; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];
        if (disk->src) /* Skips CDROM without media initially inserted */
            qemuAuditDisk(vm, NULL, disk, "start", true);
    }

    for (i = 0 ; i < vm->def->nnets ; i++) {
        virDomainNetDefPtr net = vm->def->nets[i];
        qemuAuditNet(vm, NULL, net, "start", true);
    }

    for (i = 0 ; i < vm->def->nhostdevs ; i++) {
        virDomainHostdevDefPtr hostdev = vm->def->hostdevs[i];
        qemuAuditHostdev(vm, hostdev, "start", true);
    }

    qemuAuditMemory(vm, 0, vm->def->mem.cur_balloon, "start", true);
    qemuAuditVcpu(vm, 0, vm->def->vcpus, "start", true);

    qemuAuditLifecycle(vm, "start", reason, success);
}


void
qemuAuditDomainStop(virDomainObjPtr vm, const char *reason)
{
    qemuAuditLifecycle(vm, "stop", reason, true);
}

void
qemuAuditSecurityLabel(virDomainObjPtr vm, bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *vmname;

    virUUIDFormat(vm->def->uuid, uuidstr);
    if (!(vmname = virAuditEncode("vm", vm->def->name))) {
        VIR_WARN("OOM while encoding audit message");
        return;
    }

    VIR_AUDIT(VIR_AUDIT_RECORD_MACHINE_ID, success,
              "%s uuid=%s vm-ctx=%s img-ctx=%s",
              vmname, uuidstr,
              VIR_AUDIT_STR(vm->def->seclabel.label),
              VIR_AUDIT_STR(vm->def->seclabel.imagelabel));

    VIR_FREE(vmname);
}
