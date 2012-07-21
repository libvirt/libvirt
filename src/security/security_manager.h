/*
 * security_manager.h: Internal security manager API
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef VIR_SECURITY_MANAGER_H__
# define VIR_SECURITY_MANAGER_H__

typedef struct _virSecurityManager virSecurityManager;
typedef virSecurityManager *virSecurityManagerPtr;

virSecurityManagerPtr virSecurityManagerNew(const char *name,
                                            const char *virtDriver,
                                            bool allowDiskFormatProbing,
                                            bool defaultConfined,
                                            bool requireConfined);

virSecurityManagerPtr virSecurityManagerNewStack(virSecurityManagerPtr primary,
                                                 virSecurityManagerPtr secondary);

virSecurityManagerPtr virSecurityManagerNewDAC(const char *virtDriver,
                                               uid_t user,
                                               gid_t group,
                                               bool allowDiskFormatProbing,
                                               bool defaultConfined,
                                               bool requireConfined,
                                               bool dynamicOwnership);

void *virSecurityManagerGetPrivateData(virSecurityManagerPtr mgr);

void virSecurityManagerFree(virSecurityManagerPtr mgr);

const char *virSecurityManagerGetDriver(virSecurityManagerPtr mgr);
const char *virSecurityManagerGetDOI(virSecurityManagerPtr mgr);
const char *virSecurityManagerGetModel(virSecurityManagerPtr mgr);
bool virSecurityManagerGetAllowDiskFormatProbing(virSecurityManagerPtr mgr);
bool virSecurityManagerGetDefaultConfined(virSecurityManagerPtr mgr);
bool virSecurityManagerGetRequireConfined(virSecurityManagerPtr mgr);

int virSecurityManagerRestoreImageLabel(virSecurityManagerPtr mgr,
                                        virDomainDefPtr def,
                                        virDomainDiskDefPtr disk);
int virSecurityManagerSetDaemonSocketLabel(virSecurityManagerPtr mgr,
                                           virDomainDefPtr vm);
int virSecurityManagerSetSocketLabel(virSecurityManagerPtr mgr,
                                     virDomainDefPtr def);
int virSecurityManagerClearSocketLabel(virSecurityManagerPtr mgr,
                                       virDomainDefPtr def);
int virSecurityManagerSetImageLabel(virSecurityManagerPtr mgr,
                                    virDomainDefPtr def,
                                    virDomainDiskDefPtr disk);
int virSecurityManagerRestoreHostdevLabel(virSecurityManagerPtr mgr,
                                          virDomainDefPtr def,
                                          virDomainHostdevDefPtr dev);
int virSecurityManagerSetHostdevLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr def,
                                      virDomainHostdevDefPtr dev);
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
int virSecurityManagerSetAllLabel(virSecurityManagerPtr mgr,
                                  virDomainDefPtr sec,
                                  const char *stdin_path);
int virSecurityManagerRestoreAllLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr def,
                                      int migrated);
int virSecurityManagerGetProcessLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr def,
                                      pid_t pid,
                                      virSecurityLabelPtr sec);
int virSecurityManagerSetProcessLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr def);
int virSecurityManagerVerify(virSecurityManagerPtr mgr,
                             virDomainDefPtr def);
int virSecurityManagerSetImageFDLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr def,
                                      int fd);
char *virSecurityManagerGetMountOptions(virSecurityManagerPtr mgr,
                                              virDomainDefPtr vm);
#endif /* VIR_SECURITY_MANAGER_H__ */
