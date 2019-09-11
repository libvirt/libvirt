/*
 * security_manager.h: Internal security manager API
 *
 * Copyright (C) 2010-2013 Red Hat, Inc.
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
#include "vircommand.h"
#include "virstoragefile.h"

typedef struct _virSecurityManager virSecurityManager;
typedef virSecurityManager *virSecurityManagerPtr;

typedef enum {
    VIR_SECURITY_MANAGER_DEFAULT_CONFINED   = 1 << 1,
    VIR_SECURITY_MANAGER_REQUIRE_CONFINED   = 1 << 2,
    VIR_SECURITY_MANAGER_PRIVILEGED         = 1 << 3,
    VIR_SECURITY_MANAGER_DYNAMIC_OWNERSHIP  = 1 << 4,
    VIR_SECURITY_MANAGER_MOUNT_NAMESPACE    = 1 << 5,
} virSecurityManagerNewFlags;

#define VIR_SECURITY_MANAGER_NEW_MASK \
    (VIR_SECURITY_MANAGER_DEFAULT_CONFINED  | \
     VIR_SECURITY_MANAGER_REQUIRE_CONFINED  | \
     VIR_SECURITY_MANAGER_PRIVILEGED)

virSecurityManagerPtr virSecurityManagerNew(const char *name,
                                            const char *virtDriver,
                                            unsigned int flags);

virSecurityManagerPtr virSecurityManagerNewStack(virSecurityManagerPtr primary);
int virSecurityManagerStackAddNested(virSecurityManagerPtr stack,
                                     virSecurityManagerPtr nested);

/**
 * virSecurityManagerDACChownCallback:
 * @src: Storage file to chown
 * @uid: target uid
 * @gid: target gid
 *
 * A function callback to chown image files described by the disk source struct
 * @src. The callback shall return 0 on success, -1 on error and errno set (no
 * libvirt error reported) OR -2 and a libvirt error reported. */
typedef int
(*virSecurityManagerDACChownCallback)(const virStorageSource *src,
                                      uid_t uid,
                                      gid_t gid);


virSecurityManagerPtr virSecurityManagerNewDAC(const char *virtDriver,
                                               uid_t user,
                                               gid_t group,
                                               unsigned int flags,
                                               virSecurityManagerDACChownCallback chownCallback);

int virSecurityManagerPreFork(virSecurityManagerPtr mgr);
void virSecurityManagerPostFork(virSecurityManagerPtr mgr);

int virSecurityManagerTransactionStart(virSecurityManagerPtr mgr);
int virSecurityManagerTransactionCommit(virSecurityManagerPtr mgr,
                                        pid_t pid,
                                        bool lock);
void virSecurityManagerTransactionAbort(virSecurityManagerPtr mgr);

void *virSecurityManagerGetPrivateData(virSecurityManagerPtr mgr);

const char *virSecurityManagerGetDriver(virSecurityManagerPtr mgr);
const char *virSecurityManagerGetDOI(virSecurityManagerPtr mgr);
const char *virSecurityManagerGetModel(virSecurityManagerPtr mgr);
const char *virSecurityManagerGetBaseLabel(virSecurityManagerPtr mgr, int virtType);

bool virSecurityManagerGetDefaultConfined(virSecurityManagerPtr mgr);
bool virSecurityManagerGetRequireConfined(virSecurityManagerPtr mgr);
bool virSecurityManagerGetPrivileged(virSecurityManagerPtr mgr);

int virSecurityManagerSetDaemonSocketLabel(virSecurityManagerPtr mgr,
                                           virDomainDefPtr vm);
int virSecurityManagerSetSocketLabel(virSecurityManagerPtr mgr,
                                     virDomainDefPtr def);
int virSecurityManagerClearSocketLabel(virSecurityManagerPtr mgr,
                                       virDomainDefPtr def);
int virSecurityManagerRestoreHostdevLabel(virSecurityManagerPtr mgr,
                                          virDomainDefPtr def,
                                          virDomainHostdevDefPtr dev,
                                          const char *vroot);
int virSecurityManagerSetHostdevLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr def,
                                      virDomainHostdevDefPtr dev,
                                      const char *vroot);
int virSecurityManagerSetSavedStateLabel(virSecurityManagerPtr mgr,
                                         virDomainDefPtr def,
                                         const char *savefile);
int virSecurityManagerRestoreSavedStateLabel(virSecurityManagerPtr mgr,
                                             virDomainDefPtr def,
                                             const char *savefile);
int virSecurityManagerGenLabel(virSecurityManagerPtr mgr,
                               virDomainDefPtr sec);
int virSecurityManagerReserveLabel(virSecurityManagerPtr mgr,
                                   virDomainDefPtr sec,
                                   pid_t pid);
int virSecurityManagerReleaseLabel(virSecurityManagerPtr mgr,
                                   virDomainDefPtr sec);
int virSecurityManagerCheckAllLabel(virSecurityManagerPtr mgr,
                                    virDomainDefPtr sec);
int virSecurityManagerSetAllLabel(virSecurityManagerPtr mgr,
                                  virDomainDefPtr sec,
                                  const char *stdin_path,
                                  bool chardevStdioLogd,
                                  bool migrated);
int virSecurityManagerRestoreAllLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr def,
                                      bool migrated,
                                      bool chardevStdioLogd);
int virSecurityManagerGetProcessLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr def,
                                      pid_t pid,
                                      virSecurityLabelPtr sec);
int virSecurityManagerSetProcessLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr def);
int virSecurityManagerSetChildProcessLabel(virSecurityManagerPtr mgr,
                                           virDomainDefPtr def,
                                           virCommandPtr cmd);
int virSecurityManagerVerify(virSecurityManagerPtr mgr,
                             virDomainDefPtr def);
int virSecurityManagerSetImageFDLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr def,
                                      int fd);
int virSecurityManagerSetTapFDLabel(virSecurityManagerPtr mgr,
                                    virDomainDefPtr vm,
                                    int fd);
char *virSecurityManagerGetMountOptions(virSecurityManagerPtr mgr,
                                        virDomainDefPtr vm);
virSecurityManagerPtr* virSecurityManagerGetNested(virSecurityManagerPtr mgr);

typedef enum {
    VIR_SECURITY_DOMAIN_IMAGE_LABEL_BACKING_CHAIN = 1 << 0,
} virSecurityDomainImageLabelFlags;

int virSecurityManagerSetImageLabel(virSecurityManagerPtr mgr,
                                    virDomainDefPtr vm,
                                    virStorageSourcePtr src,
                                    virSecurityDomainImageLabelFlags flags);
int virSecurityManagerRestoreImageLabel(virSecurityManagerPtr mgr,
                                        virDomainDefPtr vm,
                                        virStorageSourcePtr src,
                                        virSecurityDomainImageLabelFlags flags);
int virSecurityManagerMoveImageMetadata(virSecurityManagerPtr mgr,
                                        pid_t pid,
                                        virStorageSourcePtr src,
                                        virStorageSourcePtr dst);

int virSecurityManagerSetMemoryLabel(virSecurityManagerPtr mgr,
                                     virDomainDefPtr vm,
                                     virDomainMemoryDefPtr mem);
int virSecurityManagerRestoreMemoryLabel(virSecurityManagerPtr mgr,
                                        virDomainDefPtr vm,
                                        virDomainMemoryDefPtr mem);

int virSecurityManagerSetInputLabel(virSecurityManagerPtr mgr,
                                    virDomainDefPtr vm,
                                    virDomainInputDefPtr input);
int virSecurityManagerRestoreInputLabel(virSecurityManagerPtr mgr,
                                        virDomainDefPtr vm,
                                        virDomainInputDefPtr input);

int virSecurityManagerDomainSetPathLabel(virSecurityManagerPtr mgr,
                                         virDomainDefPtr vm,
                                         const char *path,
                                         bool allowSubtree);

int virSecurityManagerSetChardevLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr def,
                                      virDomainChrSourceDefPtr dev_source,
                                      bool chardevStdioLogd);

int virSecurityManagerRestoreChardevLabel(virSecurityManagerPtr mgr,
                                          virDomainDefPtr def,
                                          virDomainChrSourceDefPtr dev_source,
                                          bool chardevStdioLogd);

int virSecurityManagerSetTPMLabels(virSecurityManagerPtr mgr,
                                   virDomainDefPtr vm);

int virSecurityManagerRestoreTPMLabels(virSecurityManagerPtr mgr,
                                       virDomainDefPtr vm);

typedef struct _virSecurityManagerMetadataLockState virSecurityManagerMetadataLockState;
typedef virSecurityManagerMetadataLockState *virSecurityManagerMetadataLockStatePtr;

virSecurityManagerMetadataLockStatePtr
virSecurityManagerMetadataLock(virSecurityManagerPtr mgr,
                               const char **paths,
                               size_t npaths);

void
virSecurityManagerMetadataUnlock(virSecurityManagerPtr mgr,
                                 virSecurityManagerMetadataLockStatePtr *state);
