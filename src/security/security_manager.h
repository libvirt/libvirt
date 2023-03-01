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

#define DEV_SEV "/dev/sev"
#define DEV_SGX_VEPC "/dev/sgx_vepc"
#define DEV_SGX_PROVISION "/dev/sgx_provision"

typedef struct _virSecurityManager virSecurityManager;

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

virSecurityManager *virSecurityManagerNew(const char *name,
                                            const char *virtDriver,
                                            unsigned int flags);

virSecurityManager *virSecurityManagerNewStack(virSecurityManager *primary);
int virSecurityManagerStackAddNested(virSecurityManager *stack,
                                     virSecurityManager *nested);

/**
 * virSecurityManagerDACChownCallback:
 * @src: Storage file to chown
 * @uid: target uid
 * @gid: target gid
 *
 * A function callback to chown image files described by the disk
 * source struct @src. The callback can decide to skip given @src
 * and thus let DAC driver chown the file instead (signalled by
 * returning -3).
 *
 * Returns: 0 on success,
 *         -1 on error and errno set (no libvirt error reported),
 *         -2 and a libvirt error reported.
 *         -3 if callback did not handle chown
 */
typedef int
(*virSecurityManagerDACChownCallback)(const virStorageSource *src,
                                      uid_t uid,
                                      gid_t gid);


virSecurityManager *virSecurityManagerNewDAC(const char *virtDriver,
                                               uid_t user,
                                               gid_t group,
                                               unsigned int flags,
                                               virSecurityManagerDACChownCallback chownCallback);

int virSecurityManagerPreFork(virSecurityManager *mgr);
void virSecurityManagerPostFork(virSecurityManager *mgr);

int virSecurityManagerTransactionStart(virSecurityManager *mgr);
int virSecurityManagerTransactionCommit(virSecurityManager *mgr,
                                        pid_t pid,
                                        bool lock);
void virSecurityManagerTransactionAbort(virSecurityManager *mgr);

void *virSecurityManagerGetPrivateData(virSecurityManager *mgr);

const char *virSecurityManagerGetDriver(virSecurityManager *mgr);
const char *virSecurityManagerGetVirtDriver(virSecurityManager *mgr);
const char *virSecurityManagerGetDOI(virSecurityManager *mgr);
const char *virSecurityManagerGetModel(virSecurityManager *mgr);
const char *virSecurityManagerGetBaseLabel(virSecurityManager *mgr, int virtType);

bool virSecurityManagerGetDefaultConfined(virSecurityManager *mgr);
bool virSecurityManagerGetRequireConfined(virSecurityManager *mgr);
bool virSecurityManagerGetPrivileged(virSecurityManager *mgr);

int virSecurityManagerSetDaemonSocketLabel(virSecurityManager *mgr,
                                           virDomainDef *vm);
int virSecurityManagerSetSocketLabel(virSecurityManager *mgr,
                                     virDomainDef *def);
int virSecurityManagerClearSocketLabel(virSecurityManager *mgr,
                                       virDomainDef *def);
int virSecurityManagerRestoreHostdevLabel(virSecurityManager *mgr,
                                          virDomainDef *def,
                                          virDomainHostdevDef *dev,
                                          const char *vroot);
int virSecurityManagerSetHostdevLabel(virSecurityManager *mgr,
                                      virDomainDef *def,
                                      virDomainHostdevDef *dev,
                                      const char *vroot);
int virSecurityManagerSetSavedStateLabel(virSecurityManager *mgr,
                                         virDomainDef *def,
                                         const char *savefile);
int virSecurityManagerRestoreSavedStateLabel(virSecurityManager *mgr,
                                             virDomainDef *def,
                                             const char *savefile);
int virSecurityManagerGenLabel(virSecurityManager *mgr,
                               virDomainDef *sec);
int virSecurityManagerReserveLabel(virSecurityManager *mgr,
                                   virDomainDef *sec,
                                   pid_t pid);
int virSecurityManagerReleaseLabel(virSecurityManager *mgr,
                                   virDomainDef *sec);
int virSecurityManagerCheckAllLabel(virSecurityManager *mgr,
                                    virDomainDef *sec);
int virSecurityManagerSetAllLabel(virSecurityManager *mgr,
                                  virDomainDef *sec,
                                  const char *incomingPath,
                                  bool chardevStdioLogd,
                                  bool migrated);
int virSecurityManagerRestoreAllLabel(virSecurityManager *mgr,
                                      virDomainDef *def,
                                      bool migrated,
                                      bool chardevStdioLogd);
int virSecurityManagerGetProcessLabel(virSecurityManager *mgr,
                                      virDomainDef *def,
                                      pid_t pid,
                                      virSecurityLabelPtr sec);
int virSecurityManagerSetProcessLabel(virSecurityManager *mgr,
                                      virDomainDef *def);
int virSecurityManagerSetChildProcessLabel(virSecurityManager *mgr,
                                           virDomainDef *def,
                                           bool useBinarySpecificLabel,
                                           virCommand *cmd);
int virSecurityManagerVerify(virSecurityManager *mgr,
                             virDomainDef *def);
int virSecurityManagerSetImageFDLabel(virSecurityManager *mgr,
                                      virDomainDef *def,
                                      int fd);
int virSecurityManagerSetTapFDLabel(virSecurityManager *mgr,
                                    virDomainDef *vm,
                                    int fd);
char *virSecurityManagerGetMountOptions(virSecurityManager *mgr,
                                        virDomainDef *vm);
virSecurityManager ** virSecurityManagerGetNested(virSecurityManager *mgr);

typedef enum {
    VIR_SECURITY_DOMAIN_IMAGE_LABEL_BACKING_CHAIN = 1 << 0,
    /* The VIR_SECURITY_DOMAIN_IMAGE_PARENT_CHAIN_TOP should be set if the
     * image passed to virSecurityManagerSetImageLabel() is the top parent of
     * the whole backing chain. */
    VIR_SECURITY_DOMAIN_IMAGE_PARENT_CHAIN_TOP = 1 << 1,
} virSecurityDomainImageLabelFlags;

int virSecurityManagerSetImageLabel(virSecurityManager *mgr,
                                    virDomainDef *vm,
                                    virStorageSource *src,
                                    virSecurityDomainImageLabelFlags flags);
int virSecurityManagerRestoreImageLabel(virSecurityManager *mgr,
                                        virDomainDef *vm,
                                        virStorageSource *src,
                                        virSecurityDomainImageLabelFlags flags);
int virSecurityManagerMoveImageMetadata(virSecurityManager *mgr,
                                        pid_t pid,
                                        virStorageSource *src,
                                        virStorageSource *dst);

int virSecurityManagerSetMemoryLabel(virSecurityManager *mgr,
                                     virDomainDef *vm,
                                     virDomainMemoryDef *mem);
int virSecurityManagerRestoreMemoryLabel(virSecurityManager *mgr,
                                        virDomainDef *vm,
                                        virDomainMemoryDef *mem);

int virSecurityManagerSetInputLabel(virSecurityManager *mgr,
                                    virDomainDef *vm,
                                    virDomainInputDef *input);
int virSecurityManagerRestoreInputLabel(virSecurityManager *mgr,
                                        virDomainDef *vm,
                                        virDomainInputDef *input);

int virSecurityManagerDomainSetPathLabel(virSecurityManager *mgr,
                                         virDomainDef *vm,
                                         const char *path,
                                         bool allowSubtree);

int virSecurityManagerDomainSetPathLabelRO(virSecurityManager *mgr,
                                           virDomainDef *vm,
                                           const char *path);

int virSecurityManagerDomainRestorePathLabel(virSecurityManager *mgr,
                                             virDomainDef *def,
                                             const char *path);


int virSecurityManagerSetChardevLabel(virSecurityManager *mgr,
                                      virDomainDef *def,
                                      virDomainChrSourceDef *dev_source,
                                      bool chardevStdioLogd);

int virSecurityManagerRestoreChardevLabel(virSecurityManager *mgr,
                                          virDomainDef *def,
                                          virDomainChrSourceDef *dev_source,
                                          bool chardevStdioLogd);

int virSecurityManagerSetTPMLabels(virSecurityManager *mgr,
                                   virDomainDef *vm,
                                   bool setTPMStateLabel);

int virSecurityManagerRestoreTPMLabels(virSecurityManager *mgr,
                                       virDomainDef *vm,
                                       bool restoreTPMStateLabel);

int virSecurityManagerSetNetdevLabel(virSecurityManager *mgr,
                                     virDomainDef *vm,
                                     virDomainNetDef *net);

int virSecurityManagerRestoreNetdevLabel(virSecurityManager *mgr,
                                         virDomainDef *vm,
                                         virDomainNetDef *net);

typedef struct _virSecurityManagerMetadataLockState virSecurityManagerMetadataLockState;
struct _virSecurityManagerMetadataLockState {
    size_t nfds; /* Captures size of both @fds and @paths */
    int *fds;
    const char **paths;
};


virSecurityManagerMetadataLockState *
virSecurityManagerMetadataLock(virSecurityManager *mgr,
                               const char **paths,
                               size_t npaths);

void
virSecurityManagerMetadataUnlock(virSecurityManager *mgr,
                                 virSecurityManagerMetadataLockState **state);
