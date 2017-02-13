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
 *
 * Authors:
 *     Michal Privoznik <mprivozn@redhat.com>
 */

#ifndef __QEMU_SECURITY_H__
# define __QEMU_SECURITY_H__

# include <stdbool.h>

# include "qemu_conf.h"
# include "domain_conf.h"
# include "security/security_manager.h"

int qemuSecuritySetAllLabel(virQEMUDriverPtr driver,
                            virDomainObjPtr vm,
                            const char *stdin_path);

void qemuSecurityRestoreAllLabel(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm,
                                 bool migrated);

int qemuSecuritySetDiskLabel(virQEMUDriverPtr driver,
                             virDomainObjPtr vm,
                             virDomainDiskDefPtr disk);

int qemuSecurityRestoreDiskLabel(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm,
                                 virDomainDiskDefPtr disk);

int qemuSecuritySetImageLabel(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              virStorageSourcePtr src);

int qemuSecurityRestoreImageLabel(virQEMUDriverPtr driver,
                                  virDomainObjPtr vm,
                                  virStorageSourcePtr src);

int qemuSecuritySetHostdevLabel(virQEMUDriverPtr driver,
                                virDomainObjPtr vm,
                                virDomainHostdevDefPtr hostdev);

int qemuSecurityRestoreHostdevLabel(virQEMUDriverPtr driver,
                                    virDomainObjPtr vm,
                                    virDomainHostdevDefPtr hostdev);

/* Please note that for these APIs there is no wrapper yet. Do NOT blindly add
 * new APIs here. If an API can touch a /dev file add a proper wrapper instead.
 */
# define qemuSecurityCheckAllLabel virSecurityManagerCheckAllLabel
# define qemuSecurityClearSocketLabel virSecurityManagerClearSocketLabel
# define qemuSecurityDomainSetPathLabel virSecurityManagerDomainSetPathLabel
# define qemuSecurityGenLabel virSecurityManagerGenLabel
# define qemuSecurityGetBaseLabel virSecurityManagerGetBaseLabel
# define qemuSecurityGetDOI virSecurityManagerGetDOI
# define qemuSecurityGetModel virSecurityManagerGetModel
# define qemuSecurityGetMountOptions virSecurityManagerGetMountOptions
# define qemuSecurityGetNested virSecurityManagerGetNested
# define qemuSecurityGetProcessLabel virSecurityManagerGetProcessLabel
# define qemuSecurityNew virSecurityManagerNew
# define qemuSecurityNewDAC virSecurityManagerNewDAC
# define qemuSecurityNewStack virSecurityManagerNewStack
# define qemuSecurityPostFork virSecurityManagerPostFork
# define qemuSecurityPreFork virSecurityManagerPreFork
# define qemuSecurityReleaseLabel virSecurityManagerReleaseLabel
# define qemuSecurityReserveLabel virSecurityManagerReserveLabel
# define qemuSecurityRestoreSavedStateLabel virSecurityManagerRestoreSavedStateLabel
# define qemuSecuritySetChildProcessLabel virSecurityManagerSetChildProcessLabel
# define qemuSecuritySetDaemonSocketLabel virSecurityManagerSetDaemonSocketLabel
# define qemuSecuritySetImageFDLabel virSecurityManagerSetImageFDLabel
# define qemuSecuritySetSavedStateLabel virSecurityManagerSetSavedStateLabel
# define qemuSecuritySetSocketLabel virSecurityManagerSetSocketLabel
# define qemuSecuritySetTapFDLabel virSecurityManagerSetTapFDLabel
# define qemuSecurityStackAddNested virSecurityManagerStackAddNested
# define qemuSecurityVerify virSecurityManagerVerify

#endif /* __QEMU_SECURITY_H__ */
