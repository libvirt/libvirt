/*
 * qemu_security.h: QEMU security management
 *
 * Copyright (C) 2016 Red Hat, Inc.
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

#include "qemu_conf.h"
#include "domain_conf.h"
#include "security/security_manager.h"

int qemuSecuritySetAllLabel(virQEMUDriverPtr driver,
                            virDomainObjPtr vm,
                            const char *stdin_path);

void qemuSecurityRestoreAllLabel(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm,
                                 bool migrated);

int qemuSecuritySetImageLabel(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              virStorageSourcePtr src,
                              bool backingChain);

int qemuSecurityRestoreImageLabel(virQEMUDriverPtr driver,
                                  virDomainObjPtr vm,
                                  virStorageSourcePtr src,
                                  bool backingChain);

int qemuSecurityMoveImageMetadata(virQEMUDriverPtr driver,
                                  virDomainObjPtr vm,
                                  virStorageSourcePtr src,
                                  virStorageSourcePtr dst);

int qemuSecuritySetHostdevLabel(virQEMUDriverPtr driver,
                                virDomainObjPtr vm,
                                virDomainHostdevDefPtr hostdev);

int qemuSecurityRestoreHostdevLabel(virQEMUDriverPtr driver,
                                    virDomainObjPtr vm,
                                    virDomainHostdevDefPtr hostdev);

int qemuSecuritySetMemoryLabel(virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               virDomainMemoryDefPtr mem);

int qemuSecurityRestoreMemoryLabel(virQEMUDriverPtr driver,
                                   virDomainObjPtr vm,
                                   virDomainMemoryDefPtr mem);

int qemuSecuritySetInputLabel(virDomainObjPtr vm,
                              virDomainInputDefPtr input);

int qemuSecurityRestoreInputLabel(virDomainObjPtr vm,
                                  virDomainInputDefPtr input);

int qemuSecuritySetChardevLabel(virQEMUDriverPtr driver,
                                virDomainObjPtr vm,
                                virDomainChrDefPtr chr);

int qemuSecurityRestoreChardevLabel(virQEMUDriverPtr driver,
                                    virDomainObjPtr vm,
                                    virDomainChrDefPtr chr);

int qemuSecurityStartVhostUserGPU(virQEMUDriverPtr driver,
                                  virDomainObjPtr vm,
                                  virCommandPtr cmd,
                                  int *exitstatus,
                                  int *cmdret);

int qemuSecurityStartTPMEmulator(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm,
                                 virCommandPtr cmd,
                                 uid_t uid,
                                 gid_t gid,
                                 int *exitstatus,
                                 int *cmdret);

void qemuSecurityCleanupTPMEmulator(virQEMUDriverPtr driver,
                                    virDomainObjPtr vm);

int qemuSecurityDomainSetPathLabel(virQEMUDriverPtr driver,
                                   virDomainObjPtr vm,
                                   const char *path,
                                   bool allowSubtree);

int qemuSecuritySetSavedStateLabel(virQEMUDriverPtr driver,
                                   virDomainObjPtr vm,
                                   const char *savefile);

int qemuSecurityRestoreSavedStateLabel(virQEMUDriverPtr driver,
                                       virDomainObjPtr vm,
                                       const char *savefile);

int qemuSecurityCommandRun(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           virCommandPtr cmd,
                           uid_t uid,
                           gid_t gid,
                           int *exitstatus,
                           int *cmdret);

/* Please note that for these APIs there is no wrapper yet. Do NOT blindly add
 * new APIs here. If an API can touch a file add a proper wrapper instead.
 */
#define qemuSecurityCheckAllLabel virSecurityManagerCheckAllLabel
#define qemuSecurityClearSocketLabel virSecurityManagerClearSocketLabel
#define qemuSecurityGenLabel virSecurityManagerGenLabel
#define qemuSecurityGetBaseLabel virSecurityManagerGetBaseLabel
#define qemuSecurityGetDOI virSecurityManagerGetDOI
#define qemuSecurityGetModel virSecurityManagerGetModel
#define qemuSecurityGetMountOptions virSecurityManagerGetMountOptions
#define qemuSecurityGetNested virSecurityManagerGetNested
#define qemuSecurityGetProcessLabel virSecurityManagerGetProcessLabel
#define qemuSecurityNew virSecurityManagerNew
#define qemuSecurityNewDAC virSecurityManagerNewDAC
#define qemuSecurityNewStack virSecurityManagerNewStack
#define qemuSecurityPostFork virSecurityManagerPostFork
#define qemuSecurityPreFork virSecurityManagerPreFork
#define qemuSecurityReleaseLabel virSecurityManagerReleaseLabel
#define qemuSecurityReserveLabel virSecurityManagerReserveLabel
#define qemuSecuritySetChildProcessLabel virSecurityManagerSetChildProcessLabel
#define qemuSecuritySetDaemonSocketLabel virSecurityManagerSetDaemonSocketLabel
#define qemuSecuritySetImageFDLabel virSecurityManagerSetImageFDLabel
#define qemuSecuritySetSocketLabel virSecurityManagerSetSocketLabel
#define qemuSecuritySetTapFDLabel virSecurityManagerSetTapFDLabel
#define qemuSecurityStackAddNested virSecurityManagerStackAddNested
#define qemuSecurityVerify virSecurityManagerVerify
