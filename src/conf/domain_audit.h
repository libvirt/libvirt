/*
 * domain_audit.h: Domain audit management
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_DOMAIN_AUDIT_H__
# define __VIR_DOMAIN_AUDIT_H__

# include "domain_conf.h"
# include "vircgroup.h"

void virDomainAuditStart(virDomainObjPtr vm,
                         const char *reason,
                         bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
void virDomainAuditInit(virDomainObjPtr vm,
                        pid_t pid,
                        ino_t pidns)
    ATTRIBUTE_NONNULL(1);
void virDomainAuditStop(virDomainObjPtr vm,
                        const char *reason)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
void virDomainAuditDisk(virDomainObjPtr vm,
                        const char *oldDef,
                        const char *newDef,
                        const char *reason,
                        bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4);
void virDomainAuditFS(virDomainObjPtr vm,
                      virDomainFSDefPtr oldDef,
                      virDomainFSDefPtr newDef,
                      const char *reason,
                      bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4);
void virDomainAuditNet(virDomainObjPtr vm,
                       virDomainNetDefPtr oldDef,
                       virDomainNetDefPtr newDef,
                       const char *reason,
                       bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4);
void virDomainAuditNetDevice(virDomainDefPtr vmDef,
                             virDomainNetDefPtr netDef,
                             const char *device,
                             bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);
void virDomainAuditHostdev(virDomainObjPtr vm,
                           virDomainHostdevDefPtr def,
                           const char *reason,
                           bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);
void virDomainAuditCgroup(virDomainObjPtr vm,
                          virCgroupPtr group,
                          const char *reason,
                          const char *extra,
                          bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4);
void virDomainAuditCgroupMajor(virDomainObjPtr vm,
                               virCgroupPtr group,
                               const char *reason,
                               int maj,
                               const char *name,
                               const char *perms,
                               bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(5) ATTRIBUTE_NONNULL(6);
void virDomainAuditCgroupPath(virDomainObjPtr vm,
                              virCgroupPtr group,
                              const char *reason,
                              const char *path,
                              const char *perms,
                              int rc)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4) ATTRIBUTE_NONNULL(5);
void virDomainAuditMemory(virDomainObjPtr vm,
                          unsigned long long oldmem,
                          unsigned long long newmem,
                          const char *reason,
                          bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4);
void virDomainAuditVcpu(virDomainObjPtr vm,
                        unsigned int oldvcpu,
                        unsigned int newvcpu,
                        const char *reason,
                        bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4);
void virDomainAuditSecurityLabel(virDomainObjPtr vm,
                                 bool success)
    ATTRIBUTE_NONNULL(1);
void virDomainAuditRedirdev(virDomainObjPtr vm,
                            virDomainRedirdevDefPtr def,
                            const char *reason,
                            bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

#endif /* __VIR_DOMAIN_AUDIT_H__ */
