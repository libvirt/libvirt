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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef VIR_SECURITY_MANAGER_H__
# define VIR_SECURITY_MANAGER_H__

# include "domain_conf.h"
# include "vircommand.h"
# include "virstoragefile.h"

typedef struct _virSecurityManager virSecurityManager;
typedef virSecurityManager *virSecurityManagerPtr;

typedef enum {
    VIR_SECURITY_MANAGER_ALLOW_DISK_PROBE   = 1 << 0,
    VIR_SECURITY_MANAGER_DEFAULT_CONFINED   = 1 << 1,
    VIR_SECURITY_MANAGER_REQUIRE_CONFINED   = 1 << 2,
    VIR_SECURITY_MANAGER_PRIVILEGED         = 1 << 3,
    VIR_SECURITY_MANAGER_DYNAMIC_OWNERSHIP  = 1 << 4,
} virSecurityManagerNewFlags;

# define VIR_SECURITY_MANAGER_NEW_MASK  \
    (VIR_SECURITY_MANAGER_ALLOW_DISK_PROBE  | \
     VIR_SECURITY_MANAGER_DEFAULT_CONFINED  | \
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
                                        pid_t pid);
void virSecurityManagerTransactionAbort(virSecurityManagerPtr mgr);

void *virSecurityManagerGetPrivateData(virSecurityManagerPtr mgr);

const char *virSecurityManagerGetDriver(virSecurityManagerPtr mgr);
const char *virSecurityManagerGetDOI(virSecurityManagerPtr mgr);
const char *virSecurityManagerGetModel(virSecurityManagerPtr mgr);
const char *virSecurityManagerGetBaseLabel(virSecurityManagerPtr mgr, int virtType);

bool virSecurityManagerGetAllowDiskFormatProbing(virSecurityManagerPtr mgr);
bool virSecurityManagerGetDefaultConfined(virSecurityManagerPtr mgr);
bool virSecurityManagerGetRequireConfined(virSecurityManagerPtr mgr);
bool virSecurityManagerGetPrivileged(virSecurityManagerPtr mgr);

int virSecurityManagerRestoreDiskLabel(virSecurityManagerPtr mgr,
                                       virDomainDefPtr def,
                                       virDomainDiskDefPtr disk);
int virSecurityManagerSetDaemonSocketLabel(virSecurityManagerPtr mgr,
                                           virDomainDefPtr vm);
int virSecurityManagerSetSocketLabel(virSecurityManagerPtr mgr,
                                     virDomainDefPtr def);
int virSecurityManagerClearSocketLabel(virSecurityManagerPtr mgr,
                                       virDomainDefPtr def);
int virSecurityManagerSetDiskLabel(virSecurityManagerPtr mgr,
                                   virDomainDefPtr def,
                                   virDomainDiskDefPtr disk);
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
                                  const char *stdin_path);
int virSecurityManagerRestoreAllLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr def,
                                      bool migrated);
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

int virSecurityManagerSetImageLabel(virSecurityManagerPtr mgr,
                                    virDomainDefPtr vm,
                                    virStorageSourcePtr src);
int virSecurityManagerRestoreImageLabel(virSecurityManagerPtr mgr,
                                        virDomainDefPtr vm,
                                        virStorageSourcePtr src);

int virSecurityManagerDomainSetPathLabel(virSecurityManagerPtr mgr,
                                         virDomainDefPtr vm,
                                         const char *path);

#endif /* VIR_SECURITY_MANAGER_H__ */
