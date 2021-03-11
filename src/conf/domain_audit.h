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
 */

#pragma once

#include "domain_conf.h"
#include "vircgroup.h"

void virDomainAuditStart(virDomainObj *vm,
                         const char *reason,
                         bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
void virDomainAuditInit(virDomainObj *vm,
                        pid_t pid,
                        ino_t pidns)
    ATTRIBUTE_NONNULL(1);
void virDomainAuditStop(virDomainObj *vm,
                        const char *reason)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
void virDomainAuditDisk(virDomainObj *vm,
                        virStorageSource *oldDef,
                        virStorageSource *newDef,
                        const char *reason,
                        bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4);
void virDomainAuditFS(virDomainObj *vm,
                      virDomainFSDef *oldDef,
                      virDomainFSDef *newDef,
                      const char *reason,
                      bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4);
void virDomainAuditNet(virDomainObj *vm,
                       virDomainNetDef *oldDef,
                       virDomainNetDef *newDef,
                       const char *reason,
                       bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4);
void virDomainAuditNetDevice(virDomainDef *vmDef,
                             virDomainNetDef *netDef,
                             const char *device,
                             bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);
void virDomainAuditHostdev(virDomainObj *vm,
                           virDomainHostdevDef *def,
                           const char *reason,
                           bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);
void virDomainAuditCgroup(virDomainObj *vm,
                          virCgroup *group,
                          const char *reason,
                          const char *extra,
                          bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4);
void virDomainAuditCgroupMajor(virDomainObj *vm,
                               virCgroup *group,
                               const char *reason,
                               int maj,
                               const char *name,
                               const char *perms,
                               bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(5) ATTRIBUTE_NONNULL(6);
void virDomainAuditCgroupPath(virDomainObj *vm,
                              virCgroup *group,
                              const char *reason,
                              const char *path,
                              const char *perms,
                              int rc)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4) ATTRIBUTE_NONNULL(5);
void virDomainAuditMemory(virDomainObj *vm,
                          unsigned long long oldmem,
                          unsigned long long newmem,
                          const char *reason,
                          bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4);
void virDomainAuditVcpu(virDomainObj *vm,
                        unsigned int oldvcpu,
                        unsigned int newvcpu,
                        const char *reason,
                        bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4);
void virDomainAuditIOThread(virDomainObj *vm,
                            unsigned int oldiothread,
                            unsigned int newiothread,
                            const char *reason,
                            bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4);
void virDomainAuditSecurityLabel(virDomainObj *vm,
                                 bool success)
    ATTRIBUTE_NONNULL(1);
void virDomainAuditRedirdev(virDomainObj *vm,
                            virDomainRedirdevDef *def,
                            const char *reason,
                            bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

void virDomainAuditChardev(virDomainObj *vm,
                           virDomainChrDef *oldDef,
                           virDomainChrDef *newDef,
                           const char *reason,
                           bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4);
void virDomainAuditRNG(virDomainObj *vm,
                       virDomainRNGDef *oldDef,
                       virDomainRNGDef *newDef,
                       const char *reason,
                       bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4);
void virDomainAuditShmem(virDomainObj *vm,
                         virDomainShmemDef *def,
                         const char *reason, bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);
void virDomainAuditInput(virDomainObj *vm,
                         virDomainInputDef *input,
                         const char *reason,
                         bool success)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);
