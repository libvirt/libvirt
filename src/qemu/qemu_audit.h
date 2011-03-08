/*
 * qemu_audit.h: QEMU audit management
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

#ifndef __QEMU_AUDIT_H__
# define __QEMU_AUDIT_H__

# include "domain_conf.h"
# include "cgroup.h"

void qemuAuditDomainStart(virDomainObjPtr vm,
                          const char *reason,
                          bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
void qemuAuditDomainStop(virDomainObjPtr vm,
                         const char *reason)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
void qemuAuditDisk(virDomainObjPtr vm,
                   virDomainDiskDefPtr oldDef,
                   virDomainDiskDefPtr newDef,
                   const char *reason,
                   bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4);
void qemuAuditNet(virDomainObjPtr vm,
                  virDomainNetDefPtr oldDef,
                  virDomainNetDefPtr newDef,
                  const char *reason,
                  bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4);
void qemuAuditNetDevice(virDomainDefPtr vmDef,
                        virDomainNetDefPtr netDef,
                        const char *device,
                        bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);
void qemuAuditHostdev(virDomainObjPtr vm,
                      virDomainHostdevDefPtr def,
                      const char *reason,
                      bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);
void qemuAuditCgroup(virDomainObjPtr vm,
                     virCgroupPtr group,
                     const char *reason,
                     const char *extra,
                     bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4);
void qemuAuditCgroupMajor(virDomainObjPtr vm,
                          virCgroupPtr group,
                          const char *reason,
                          int maj,
                          const char *name,
                          const char *perms,
                          bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(5) ATTRIBUTE_NONNULL(6);
void qemuAuditCgroupPath(virDomainObjPtr vm,
                         virCgroupPtr group,
                         const char *reason,
                         const char *path,
                         const char *perms,
                         int rc)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4) ATTRIBUTE_NONNULL(5);
void qemuAuditMemory(virDomainObjPtr vm,
                     unsigned long long oldmem,
                     unsigned long long newmem,
                     const char *reason,
                     bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4);
void qemuAuditVcpu(virDomainObjPtr vm,
                   unsigned int oldvcpu,
                   unsigned int newvcpu,
                   const char *reason,
                   bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4);
void qemuAuditSecurityLabel(virDomainObjPtr vm,
                            bool success)
    ATTRIBUTE_NONNULL(1);

#endif /* __QEMU_AUDIT_H__ */
