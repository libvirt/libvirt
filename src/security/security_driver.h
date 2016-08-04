/*
 * Copyright (C) 2008, 2010-2013 Red Hat, Inc.
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
 *     James Morris <jmorris@namei.org>
 *
 */
#ifndef __VIR_SECURITY_H__
# define __VIR_SECURITY_H__

# include "internal.h"
# include "domain_conf.h"

# include "security_manager.h"

/*
 * Return values for security driver probing: the driver will determine
 * whether it should be enabled or disabled.
 */
typedef enum {
    SECURITY_DRIVER_ENABLE      = 0,
    SECURITY_DRIVER_ERROR       = -1,
    SECURITY_DRIVER_DISABLE     = -2,
} virSecurityDriverStatus;

typedef struct _virSecurityDriver virSecurityDriver;
typedef virSecurityDriver *virSecurityDriverPtr;

typedef virSecurityDriverStatus (*virSecurityDriverProbe) (const char *virtDriver);
typedef int (*virSecurityDriverOpen) (virSecurityManagerPtr mgr);
typedef int (*virSecurityDriverClose) (virSecurityManagerPtr mgr);

typedef const char *(*virSecurityDriverGetModel) (virSecurityManagerPtr mgr);
typedef const char *(*virSecurityDriverGetDOI) (virSecurityManagerPtr mgr);
typedef const char *(*virSecurityDriverGetBaseLabel) (virSecurityManagerPtr mgr,
                                                      int virtType);

typedef int (*virSecurityDriverPreFork) (virSecurityManagerPtr mgr);

typedef int (*virSecurityDriverTransactionStart) (virSecurityManagerPtr mgr);
typedef int (*virSecurityDriverTransactionCommit) (virSecurityManagerPtr mgr,
                                                   pid_t pid);
typedef void (*virSecurityDriverTransactionAbort) (virSecurityManagerPtr mgr);

typedef int (*virSecurityDomainRestoreDiskLabel) (virSecurityManagerPtr mgr,
                                                  virDomainDefPtr def,
                                                  virDomainDiskDefPtr disk);
typedef int (*virSecurityDomainSetDaemonSocketLabel)(virSecurityManagerPtr mgr,
                                                     virDomainDefPtr vm);
typedef int (*virSecurityDomainSetSocketLabel) (virSecurityManagerPtr mgr,
                                                virDomainDefPtr def);
typedef int (*virSecurityDomainClearSocketLabel)(virSecurityManagerPtr mgr,
                                                virDomainDefPtr def);
typedef int (*virSecurityDomainSetDiskLabel) (virSecurityManagerPtr mgr,
                                              virDomainDefPtr def,
                                              virDomainDiskDefPtr disk);
typedef int (*virSecurityDomainRestoreHostdevLabel) (virSecurityManagerPtr mgr,
                                                     virDomainDefPtr def,
                                                     virDomainHostdevDefPtr dev,
                                                     const char *vroot);
typedef int (*virSecurityDomainSetHostdevLabel) (virSecurityManagerPtr mgr,
                                                 virDomainDefPtr def,
                                                 virDomainHostdevDefPtr dev,
                                                 const char *vroot);
typedef int (*virSecurityDomainSetSavedStateLabel) (virSecurityManagerPtr mgr,
                                                    virDomainDefPtr def,
                                                    const char *savefile);
typedef int (*virSecurityDomainRestoreSavedStateLabel) (virSecurityManagerPtr mgr,
                                                        virDomainDefPtr def,
                                                        const char *savefile);
typedef int (*virSecurityDomainGenLabel) (virSecurityManagerPtr mgr,
                                          virDomainDefPtr sec);
typedef int (*virSecurityDomainReserveLabel) (virSecurityManagerPtr mgr,
                                              virDomainDefPtr sec,
                                              pid_t pid);
typedef int (*virSecurityDomainReleaseLabel) (virSecurityManagerPtr mgr,
                                              virDomainDefPtr sec);
typedef int (*virSecurityDomainSetAllLabel) (virSecurityManagerPtr mgr,
                                             virDomainDefPtr sec,
                                             const char *stdin_path);
typedef int (*virSecurityDomainRestoreAllLabel) (virSecurityManagerPtr mgr,
                                                 virDomainDefPtr def,
                                                 bool migrated);
typedef int (*virSecurityDomainGetProcessLabel) (virSecurityManagerPtr mgr,
                                                 virDomainDefPtr def,
                                                 pid_t pid,
                                                 virSecurityLabelPtr sec);
typedef int (*virSecurityDomainSetProcessLabel) (virSecurityManagerPtr mgr,
                                                 virDomainDefPtr def);
typedef int (*virSecurityDomainSetChildProcessLabel) (virSecurityManagerPtr mgr,
                                                      virDomainDefPtr def,
                                                      virCommandPtr cmd);
typedef int (*virSecurityDomainSecurityVerify) (virSecurityManagerPtr mgr,
                                                virDomainDefPtr def);
typedef int (*virSecurityDomainSetImageFDLabel) (virSecurityManagerPtr mgr,
                                                 virDomainDefPtr def,
                                                 int fd);
typedef int (*virSecurityDomainSetTapFDLabel) (virSecurityManagerPtr mgr,
                                               virDomainDefPtr def,
                                               int fd);
typedef char *(*virSecurityDomainGetMountOptions) (virSecurityManagerPtr mgr,
                                                   virDomainDefPtr def);
typedef int (*virSecurityDomainSetHugepages) (virSecurityManagerPtr mgr,
                                              virDomainDefPtr def,
                                              const char *path);
typedef int (*virSecurityDomainSetImageLabel) (virSecurityManagerPtr mgr,
                                               virDomainDefPtr def,
                                               virStorageSourcePtr src);
typedef int (*virSecurityDomainRestoreImageLabel) (virSecurityManagerPtr mgr,
                                                   virDomainDefPtr def,
                                                   virStorageSourcePtr src);
typedef int (*virSecurityDomainSetMemoryLabel) (virSecurityManagerPtr mgr,
                                                virDomainDefPtr def,
                                                virDomainMemoryDefPtr mem);
typedef int (*virSecurityDomainRestoreMemoryLabel) (virSecurityManagerPtr mgr,
                                                    virDomainDefPtr def,
                                                    virDomainMemoryDefPtr mem);
typedef int (*virSecurityDomainSetPathLabel) (virSecurityManagerPtr mgr,
                                              virDomainDefPtr def,
                                              const char *path);


struct _virSecurityDriver {
    size_t privateDataLen;
    const char *name;
    virSecurityDriverProbe probe;
    virSecurityDriverOpen open;
    virSecurityDriverClose close;

    virSecurityDriverGetModel getModel;
    virSecurityDriverGetDOI getDOI;

    virSecurityDriverPreFork preFork;

    virSecurityDriverTransactionStart transactionStart;
    virSecurityDriverTransactionCommit transactionCommit;
    virSecurityDriverTransactionAbort transactionAbort;

    virSecurityDomainSecurityVerify domainSecurityVerify;

    virSecurityDomainSetDiskLabel domainSetSecurityDiskLabel;
    virSecurityDomainRestoreDiskLabel domainRestoreSecurityDiskLabel;

    virSecurityDomainSetImageLabel domainSetSecurityImageLabel;
    virSecurityDomainRestoreImageLabel domainRestoreSecurityImageLabel;

    virSecurityDomainSetMemoryLabel domainSetSecurityMemoryLabel;
    virSecurityDomainRestoreMemoryLabel domainRestoreSecurityMemoryLabel;

    virSecurityDomainSetDaemonSocketLabel domainSetSecurityDaemonSocketLabel;
    virSecurityDomainSetSocketLabel domainSetSecuritySocketLabel;
    virSecurityDomainClearSocketLabel domainClearSecuritySocketLabel;

    virSecurityDomainGenLabel domainGenSecurityLabel;
    virSecurityDomainReserveLabel domainReserveSecurityLabel;
    virSecurityDomainReleaseLabel domainReleaseSecurityLabel;

    virSecurityDomainGetProcessLabel domainGetSecurityProcessLabel;
    virSecurityDomainSetProcessLabel domainSetSecurityProcessLabel;
    virSecurityDomainSetChildProcessLabel domainSetSecurityChildProcessLabel;

    virSecurityDomainSetAllLabel domainSetSecurityAllLabel;
    virSecurityDomainRestoreAllLabel domainRestoreSecurityAllLabel;

    virSecurityDomainSetHostdevLabel domainSetSecurityHostdevLabel;
    virSecurityDomainRestoreHostdevLabel domainRestoreSecurityHostdevLabel;

    virSecurityDomainSetSavedStateLabel domainSetSavedStateLabel;
    virSecurityDomainRestoreSavedStateLabel domainRestoreSavedStateLabel;

    virSecurityDomainSetImageFDLabel domainSetSecurityImageFDLabel;
    virSecurityDomainSetTapFDLabel domainSetSecurityTapFDLabel;

    virSecurityDomainGetMountOptions domainGetSecurityMountOptions;

    virSecurityDriverGetBaseLabel getBaseLabel;

    virSecurityDomainSetPathLabel domainSetPathLabel;
};

virSecurityDriverPtr virSecurityDriverLookup(const char *name,
                                             const char *virtDriver);

#endif /* __VIR_SECURITY_H__ */
