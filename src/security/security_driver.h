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
 */

#pragma once

#include "internal.h"
#include "domain_conf.h"

#include "security_manager.h"

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

typedef virSecurityDriverStatus (*virSecurityDriverProbe) (const char *virtDriver);
typedef int (*virSecurityDriverOpen) (virSecurityManager *mgr);
typedef int (*virSecurityDriverClose) (virSecurityManager *mgr);

typedef const char *(*virSecurityDriverGetModel) (virSecurityManager *mgr);
typedef const char *(*virSecurityDriverGetDOI) (virSecurityManager *mgr);
typedef const char *(*virSecurityDriverGetBaseLabel) (virSecurityManager *mgr,
                                                      int virtType);

typedef int (*virSecurityDriverPreFork) (virSecurityManager *mgr);

typedef int (*virSecurityDriverTransactionStart) (virSecurityManager *mgr);
typedef int (*virSecurityDriverTransactionCommit) (virSecurityManager *mgr,
                                                   pid_t pid,
                                                   bool lock);
typedef void (*virSecurityDriverTransactionAbort) (virSecurityManager *mgr);

typedef int (*virSecurityDomainSetDaemonSocketLabel)(virSecurityManager *mgr,
                                                     virDomainDef *vm);
typedef int (*virSecurityDomainSetSocketLabel) (virSecurityManager *mgr,
                                                virDomainDef *def);
typedef int (*virSecurityDomainClearSocketLabel)(virSecurityManager *mgr,
                                                virDomainDef *def);
typedef int (*virSecurityDomainRestoreHostdevLabel) (virSecurityManager *mgr,
                                                     virDomainDef *def,
                                                     virDomainHostdevDef *dev,
                                                     const char *vroot);
typedef int (*virSecurityDomainSetHostdevLabel) (virSecurityManager *mgr,
                                                 virDomainDef *def,
                                                 virDomainHostdevDef *dev,
                                                 const char *vroot);
typedef int (*virSecurityDomainSetSavedStateLabel) (virSecurityManager *mgr,
                                                    virDomainDef *def,
                                                    const char *savefile);
typedef int (*virSecurityDomainRestoreSavedStateLabel) (virSecurityManager *mgr,
                                                        virDomainDef *def,
                                                        const char *savefile);
typedef int (*virSecurityDomainGenLabel) (virSecurityManager *mgr,
                                          virDomainDef *sec);
typedef int (*virSecurityDomainReserveLabel) (virSecurityManager *mgr,
                                              virDomainDef *sec,
                                              pid_t pid);
typedef int (*virSecurityDomainReleaseLabel) (virSecurityManager *mgr,
                                              virDomainDef *sec);
typedef int (*virSecurityDomainSetAllLabel) (virSecurityManager *mgr,
                                             virDomainDef *sec,
                                             const char *incomingPath,
                                             bool chardevStdioLogd,
                                             bool migrated);
typedef int (*virSecurityDomainRestoreAllLabel) (virSecurityManager *mgr,
                                                 virDomainDef *def,
                                                 bool migrated,
                                                 bool chardevStdioLogd);
typedef int (*virSecurityDomainGetProcessLabel) (virSecurityManager *mgr,
                                                 virDomainDef *def,
                                                 pid_t pid,
                                                 virSecurityLabelPtr sec);
typedef int (*virSecurityDomainSetProcessLabel) (virSecurityManager *mgr,
                                                 virDomainDef *def);
typedef int (*virSecurityDomainSetChildProcessLabel) (virSecurityManager *mgr,
                                                      virDomainDef *def,
                                                      bool useBinarySpecificLabel,
                                                      virCommand *cmd);
typedef int (*virSecurityDomainSecurityVerify) (virSecurityManager *mgr,
                                                virDomainDef *def);
typedef int (*virSecurityDomainSetImageFDLabel) (virSecurityManager *mgr,
                                                 virDomainDef *def,
                                                 int fd);
typedef int (*virSecurityDomainSetTapFDLabel) (virSecurityManager *mgr,
                                               virDomainDef *def,
                                               int fd);
typedef char *(*virSecurityDomainGetMountOptions) (virSecurityManager *mgr,
                                                   virDomainDef *def);
typedef int (*virSecurityDomainSetHugepages) (virSecurityManager *mgr,
                                              virDomainDef *def,
                                              const char *path);

typedef int (*virSecurityDomainSetImageLabel) (virSecurityManager *mgr,
                                               virDomainDef *def,
                                               virStorageSource *src,
                                               virSecurityDomainImageLabelFlags flags);
typedef int (*virSecurityDomainRestoreImageLabel) (virSecurityManager *mgr,
                                                   virDomainDef *def,
                                                   virStorageSource *src,
                                                   virSecurityDomainImageLabelFlags flags);
typedef int (*virSecurityDomainMoveImageMetadata) (virSecurityManager *mgr,
                                                   pid_t pid,
                                                   virStorageSource *src,
                                                   virStorageSource *dst);
typedef int (*virSecurityDomainSetMemoryLabel) (virSecurityManager *mgr,
                                                virDomainDef *def,
                                                virDomainMemoryDef *mem);
typedef int (*virSecurityDomainRestoreMemoryLabel) (virSecurityManager *mgr,
                                                    virDomainDef *def,
                                                    virDomainMemoryDef *mem);
typedef int (*virSecurityDomainSetInputLabel) (virSecurityManager *mgr,
                                               virDomainDef *def,
                                               virDomainInputDef *input);
typedef int (*virSecurityDomainRestoreInputLabel) (virSecurityManager *mgr,
                                                   virDomainDef *def,
                                                   virDomainInputDef *input);
typedef int (*virSecurityDomainSetPathLabel) (virSecurityManager *mgr,
                                              virDomainDef *def,
                                              const char *path,
                                              bool allowSubtree);
typedef int (*virSecurityDomainSetPathLabelRO) (virSecurityManager *mgr,
                                                virDomainDef *def,
                                                const char *path);
typedef int (*virSecurityDomainRestorePathLabel) (virSecurityManager *mgr,
                                                  virDomainDef *def,
                                                  const char *path);
typedef int (*virSecurityDomainSetChardevLabel) (virSecurityManager *mgr,
                                                 virDomainDef *def,
                                                 virDomainChrSourceDef *dev_source,
                                                 bool chardevStdioLogd);
typedef int (*virSecurityDomainRestoreChardevLabel) (virSecurityManager *mgr,
                                                     virDomainDef *def,
                                                     virDomainChrSourceDef *dev_source,
                                                     bool chardevStdioLogd);
typedef int (*virSecurityDomainSetTPMLabels) (virSecurityManager *mgr,
                                              virDomainDef *def,
                                              bool setTPMStateLabel);
typedef int (*virSecurityDomainRestoreTPMLabels) (virSecurityManager *mgr,
                                                  virDomainDef *def,
                                                  bool restoreTPMStateLabel);
typedef int (*virSecurityDomainSetNetdevLabel) (virSecurityManager *mgr,
                                                virDomainDef *def,
                                                virDomainNetDef *net);
typedef int (*virSecurityDomainRestoreNetdevLabel) (virSecurityManager *mgr,
                                                    virDomainDef *def,
                                                    virDomainNetDef *net);


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

    virSecurityDomainSetImageLabel domainSetSecurityImageLabel;
    virSecurityDomainRestoreImageLabel domainRestoreSecurityImageLabel;
    virSecurityDomainMoveImageMetadata domainMoveImageMetadata;

    virSecurityDomainSetMemoryLabel domainSetSecurityMemoryLabel;
    virSecurityDomainRestoreMemoryLabel domainRestoreSecurityMemoryLabel;

    virSecurityDomainSetInputLabel domainSetSecurityInputLabel;
    virSecurityDomainRestoreInputLabel domainRestoreSecurityInputLabel;

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
    virSecurityDomainSetPathLabelRO domainSetPathLabelRO;
    virSecurityDomainRestorePathLabel domainRestorePathLabel;

    virSecurityDomainSetChardevLabel domainSetSecurityChardevLabel;
    virSecurityDomainRestoreChardevLabel domainRestoreSecurityChardevLabel;

    virSecurityDomainSetTPMLabels domainSetSecurityTPMLabels;
    virSecurityDomainRestoreTPMLabels domainRestoreSecurityTPMLabels;

    virSecurityDomainSetNetdevLabel domainSetSecurityNetdevLabel;
    virSecurityDomainRestoreNetdevLabel domainRestoreSecurityNetdevLabel;
};

virSecurityDriver *virSecurityDriverLookup(const char *name,
                                             const char *virtDriver);
