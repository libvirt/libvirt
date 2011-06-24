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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef VIR_SECURITY_MANAGER_H__
# define VIR_SECURITY_MANAGER_H__

# define virSecurityReportError(code, ...)                          \
    virReportErrorHelper(VIR_FROM_SECURITY, code, __FILE__,         \
                         __FUNCTION__, __LINE__, __VA_ARGS__)


typedef struct _virSecurityManager virSecurityManager;
typedef virSecurityManager *virSecurityManagerPtr;

virSecurityManagerPtr virSecurityManagerNew(const char *name,
                                            bool allowDiskFormatProbing);

virSecurityManagerPtr virSecurityManagerNewStack(virSecurityManagerPtr primary,
                                                 virSecurityManagerPtr secondary);

virSecurityManagerPtr virSecurityManagerNewDAC(uid_t user,
                                               gid_t group,
                                               bool allowDiskFormatProbing,
                                               bool dynamicOwnership);

void *virSecurityManagerGetPrivateData(virSecurityManagerPtr mgr);

void virSecurityManagerFree(virSecurityManagerPtr mgr);

const char *virSecurityManagerGetDOI(virSecurityManagerPtr mgr);
const char *virSecurityManagerGetModel(virSecurityManagerPtr mgr);
bool virSecurityManagerGetAllowDiskFormatProbing(virSecurityManagerPtr mgr);

int virSecurityManagerRestoreImageLabel(virSecurityManagerPtr mgr,
                                        virDomainObjPtr vm,
                                        virDomainDiskDefPtr disk);
int virSecurityManagerSetSocketLabel(virSecurityManagerPtr mgr,
                                     virDomainObjPtr vm);
int virSecurityManagerClearSocketLabel(virSecurityManagerPtr mgr,
                                       virDomainObjPtr vm);
int virSecurityManagerSetImageLabel(virSecurityManagerPtr mgr,
                                    virDomainObjPtr vm,
                                    virDomainDiskDefPtr disk);
int virSecurityManagerRestoreHostdevLabel(virSecurityManagerPtr mgr,
                                          virDomainObjPtr vm,
                                          virDomainHostdevDefPtr dev);
int virSecurityManagerSetHostdevLabel(virSecurityManagerPtr mgr,
                                      virDomainObjPtr vm,
                                      virDomainHostdevDefPtr dev);
int virSecurityManagerSetSavedStateLabel(virSecurityManagerPtr mgr,
                                         virDomainObjPtr vm,
                                         const char *savefile);
int virSecurityManagerRestoreSavedStateLabel(virSecurityManagerPtr mgr,
                                             virDomainObjPtr vm,
                                             const char *savefile);
int virSecurityManagerGenLabel(virSecurityManagerPtr mgr,
                               virDomainObjPtr sec);
int virSecurityManagerReserveLabel(virSecurityManagerPtr mgr,
                                   virDomainObjPtr sec);
int virSecurityManagerReleaseLabel(virSecurityManagerPtr mgr,
                                   virDomainObjPtr sec);
int virSecurityManagerSetAllLabel(virSecurityManagerPtr mgr,
                                  virDomainObjPtr sec,
                                  const char *stdin_path);
int virSecurityManagerRestoreAllLabel(virSecurityManagerPtr mgr,
                                      virDomainObjPtr vm,
                                      int migrated);
int virSecurityManagerGetProcessLabel(virSecurityManagerPtr mgr,
                                      virDomainObjPtr vm,
                                      virSecurityLabelPtr sec);
int virSecurityManagerSetProcessLabel(virSecurityManagerPtr mgr,
                                      virDomainObjPtr vm);
int virSecurityManagerVerify(virSecurityManagerPtr mgr,
                             virDomainDefPtr def);
int virSecurityManagerSetImageFDLabel(virSecurityManagerPtr mgr,
                                      virDomainObjPtr vm,
                                      int fd);
int virSecurityManagerSetProcessFDLabel(virSecurityManagerPtr mgr,
                                        virDomainObjPtr vm,
                                        int fd);

#endif /* VIR_SECURITY_MANAGER_H__ */
