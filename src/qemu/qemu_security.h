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

int qemuSecuritySetAllLabel(virQEMUDriver *driver,
                            virDomainObj *vm,
                            const char *incomingPath,
                            bool migrated);

void qemuSecurityRestoreAllLabel(virQEMUDriver *driver,
                                 virDomainObj *vm,
                                 bool migrated);

int qemuSecuritySetImageLabel(virQEMUDriver *driver,
                              virDomainObj *vm,
                              virStorageSource *src,
                              bool backingChain,
                              bool chainTop);

int qemuSecurityRestoreImageLabel(virQEMUDriver *driver,
                                  virDomainObj *vm,
                                  virStorageSource *src,
                                  bool backingChain);

int qemuSecurityMoveImageMetadata(virQEMUDriver *driver,
                                  virDomainObj *vm,
                                  virStorageSource *src,
                                  virStorageSource *dst);

int qemuSecuritySetHostdevLabel(virQEMUDriver *driver,
                                virDomainObj *vm,
                                virDomainHostdevDef *hostdev);

int qemuSecurityRestoreHostdevLabel(virQEMUDriver *driver,
                                    virDomainObj *vm,
                                    virDomainHostdevDef *hostdev);

int qemuSecuritySetMemoryLabel(virQEMUDriver *driver,
                               virDomainObj *vm,
                               virDomainMemoryDef *mem);

int qemuSecurityRestoreMemoryLabel(virQEMUDriver *driver,
                                   virDomainObj *vm,
                                   virDomainMemoryDef *mem);

int qemuSecuritySetInputLabel(virDomainObj *vm,
                              virDomainInputDef *input);

int qemuSecurityRestoreInputLabel(virDomainObj *vm,
                                  virDomainInputDef *input);

int qemuSecuritySetChardevLabel(virQEMUDriver *driver,
                                virDomainObj *vm,
                                virDomainChrDef *chr);

int qemuSecurityRestoreChardevLabel(virQEMUDriver *driver,
                                    virDomainObj *vm,
                                    virDomainChrDef *chr);

int qemuSecuritySetNetdevLabel(virQEMUDriver *driver,
                               virDomainObj *vm,
                               virDomainNetDef *net);

int qemuSecurityRestoreNetdevLabel(virQEMUDriver *driver,
                                   virDomainObj *vm,
                                   virDomainNetDef *net);

int qemuSecuritySetTPMLabels(virQEMUDriver *driver,
                             virDomainObj *vm,
                             bool setTPMStateLabel);

int qemuSecurityRestoreTPMLabels(virQEMUDriver *driver,
                                 virDomainObj *vm,
                                 bool restoreTPMStateLabel);

int qemuSecuritySetSavedStateLabel(virQEMUDriver *driver,
                                   virDomainObj *vm,
                                   const char *savefile);

int qemuSecurityRestoreSavedStateLabel(virQEMUDriver *driver,
                                       virDomainObj *vm,
                                       const char *savefile);

int qemuSecurityDomainSetPathLabel(virQEMUDriver *driver,
                                   virDomainObj *vm,
                                   const char *path,
                                   bool allowSubtree);

int qemuSecurityDomainRestorePathLabel(virQEMUDriver *driver,
                                       virDomainObj *vm,
                                       const char *path);

int qemuSecurityCommandRun(virQEMUDriver *driver,
                           virDomainObj *vm,
                           virCommand *cmd,
                           uid_t uid,
                           gid_t gid,
                           bool useBinarySpecificLabel,
                           int *exitstatus);

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
#define qemuSecurityRestoreSavedStateLabel virSecurityManagerRestoreSavedStateLabel
#define qemuSecuritySetChildProcessLabel virSecurityManagerSetChildProcessLabel
#define qemuSecuritySetDaemonSocketLabel virSecurityManagerSetDaemonSocketLabel
#define qemuSecuritySetImageFDLabel virSecurityManagerSetImageFDLabel
#define qemuSecuritySetSavedStateLabel virSecurityManagerSetSavedStateLabel
#define qemuSecuritySetSocketLabel virSecurityManagerSetSocketLabel
#define qemuSecuritySetTapFDLabel virSecurityManagerSetTapFDLabel
#define qemuSecurityStackAddNested virSecurityManagerStackAddNested
#define qemuSecurityVerify virSecurityManagerVerify
