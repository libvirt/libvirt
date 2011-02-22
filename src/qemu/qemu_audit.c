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

#include "qemu_audit.h"
#include "virtaudit.h"
#include "uuid.h"
#include "logging.h"
#include "memory.h"

void qemuDomainDiskAudit(virDomainObjPtr vm,
                         virDomainDiskDefPtr oldDef,
                         virDomainDiskDefPtr newDef,
                         const char *reason,
                         bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *vmname;
    char *oldsrc = NULL;
    char *newsrc = NULL;

    virUUIDFormat(vm->def->uuid, uuidstr);
    if (!(vmname = virAuditEncode("vm", vm->def->name))) {
        VIR_WARN0("OOM while encoding audit message");
        return;
    }

    if (!(oldsrc = virAuditEncode("old-disk",
                                  oldDef && oldDef->src ?
                                  oldDef->src : "?"))) {
        VIR_WARN0("OOM while encoding audit message");
        goto cleanup;
    }
    if (!(newsrc = virAuditEncode("new-disk",
                                  newDef && newDef->src ?
                                  newDef->src : "?"))) {
        VIR_WARN0("OOM while encoding audit message");
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


void qemuDomainNetAudit(virDomainObjPtr vm,
                        virDomainNetDefPtr oldDef,
                        virDomainNetDefPtr newDef,
                        const char *reason,
                        bool success)
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
        VIR_WARN0("OOM while encoding audit message");
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
 * qemuDomainCgroupAudit:
 * @vm: domain making the cgroups ACL change
 * @cgroup: cgroup that manages the devices
 * @reason: either "allow" or "deny"
 * @item: one of "all", "path", or "major"
 * @name: NULL for @item of "all", device path for @item of "path", and
 * string describing major device type for @item of "major"
 * @success: true if the cgroup operation succeeded
 *
 * Log an audit message about an attempted cgroup device ACL change.
 */
void qemuDomainCgroupAudit(virDomainObjPtr vm,
                           virCgroupPtr cgroup ATTRIBUTE_UNUSED,
                           const char *reason,
                           const char *item,
                           const char *name,
                           bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *vmname;
    char *detail = NULL;

    virUUIDFormat(vm->def->uuid, uuidstr);
    if (!(vmname = virAuditEncode("vm", vm->def->name))) {
        VIR_WARN0("OOM while encoding audit message");
        return;
    }
    if (name &&
        !(detail = virAuditEncode(STREQ(item, "path") ? "path" : "type",
                                  name))) {
        VIR_WARN0("OOM while encoding audit message");
        goto cleanup;
    }

    VIR_AUDIT(VIR_AUDIT_RECORD_RESOURCE, success,
              "resrc=cgroup reason=%s %s uuid=%s item=%s%s%s",
              reason, vmname, uuidstr,
              item, detail ? " " : "", detail ? detail : "");

cleanup:
    VIR_FREE(vmname);
    VIR_FREE(detail);
}


/**
 * qemuDomainResourceAudit:
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
qemuDomainResourceAudit(virDomainObjPtr vm,
                        const char *resource,
                        unsigned long long oldval,
                        unsigned long long newval,
                        const char *reason,
                        bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *vmname;

    virUUIDFormat(vm->def->uuid, uuidstr);
    if (!(vmname = virAuditEncode("vm", vm->def->name))) {
        VIR_WARN0("OOM while encoding audit message");
        return;
    }

    VIR_AUDIT(VIR_AUDIT_RECORD_RESOURCE, success,
              "resrc=%s reason=%s %s uuid=%s old-%s=%lld new-%s=%lld",
              resource, reason, vmname, uuidstr,
              resource, oldval, resource, newval);

    VIR_FREE(vmname);
}

void
qemuDomainMemoryAudit(virDomainObjPtr vm,
                      unsigned long long oldmem, unsigned long long newmem,
                      const char *reason, bool success)
{
    return qemuDomainResourceAudit(vm, "mem", oldmem, newmem, reason, success);
}

void
qemuDomainVcpuAudit(virDomainObjPtr vm,
                    unsigned int oldvcpu, unsigned int newvcpu,
                    const char *reason, bool success)
{
    return qemuDomainResourceAudit(vm, "vcpu", oldvcpu, newvcpu, reason,
                                   success);
}

static void qemuDomainLifecycleAudit(virDomainObjPtr vm,
                                     const char *op,
                                     const char *reason,
                                     bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *vmname;

    virUUIDFormat(vm->def->uuid, uuidstr);

    if (!(vmname = virAuditEncode("vm", vm->def->name))) {
        VIR_WARN0("OOM while encoding audit message");
        return;
    }

    VIR_AUDIT(VIR_AUDIT_RECORD_MACHINE_CONTROL, success,
              "op=%s reason=%s %s uuid=%s", op, reason, vmname, uuidstr);

    VIR_FREE(vmname);
}


void qemuDomainStartAudit(virDomainObjPtr vm, const char *reason, bool success)
{
    int i;

    for (i = 0 ; i < vm->def->ndisks ; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];
        if (disk->src) /* Skips CDROM without media initially inserted */
            qemuDomainDiskAudit(vm, NULL, disk, "start", true);
    }

    for (i = 0 ; i < vm->def->nnets ; i++) {
        virDomainNetDefPtr net = vm->def->nets[i];
        qemuDomainNetAudit(vm, NULL, net, "start", true);
    }

    qemuDomainMemoryAudit(vm, 0, vm->def->mem.cur_balloon, "start", true);
    qemuDomainVcpuAudit(vm, 0, vm->def->vcpus, "start", true);

    qemuDomainLifecycleAudit(vm, "start", reason, success);
}


void qemuDomainStopAudit(virDomainObjPtr vm, const char *reason)
{
    qemuDomainLifecycleAudit(vm, "stop", reason, true);
}

void qemuDomainSecurityLabelAudit(virDomainObjPtr vm, bool success)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *vmname;

    virUUIDFormat(vm->def->uuid, uuidstr);
    if (!(vmname = virAuditEncode("vm", vm->def->name))) {
        VIR_WARN0("OOM while encoding audit message");
        return;
    }

    VIR_AUDIT(VIR_AUDIT_RECORD_MACHINE_ID, success,
              "%s uuid=%s vm-ctx=%s img-ctx=%s",
              vmname, uuidstr,
              VIR_AUDIT_STR(vm->def->seclabel.label),
              VIR_AUDIT_STR(vm->def->seclabel.imagelabel));

    VIR_FREE(vmname);
}
