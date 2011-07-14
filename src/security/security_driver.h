/*
 * Copyright (C) 2008, 2010 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
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

typedef virSecurityDriverStatus (*virSecurityDriverProbe) (void);
typedef int (*virSecurityDriverOpen) (virSecurityManagerPtr mgr);
typedef int (*virSecurityDriverClose) (virSecurityManagerPtr mgr);

typedef const char *(*virSecurityDriverGetModel) (virSecurityManagerPtr mgr);
typedef const char *(*virSecurityDriverGetDOI) (virSecurityManagerPtr mgr);

typedef int (*virSecurityDomainRestoreImageLabel) (virSecurityManagerPtr mgr,
                                                   virDomainDefPtr def,
                                                   virDomainDiskDefPtr disk);
typedef int (*virSecurityDomainSetDaemonSocketLabel)(virSecurityManagerPtr mgr,
                                                     virDomainDefPtr vm);
typedef int (*virSecurityDomainSetSocketLabel) (virSecurityManagerPtr mgr,
                                                virDomainDefPtr def);
typedef int (*virSecurityDomainClearSocketLabel)(virSecurityManagerPtr mgr,
                                                virDomainDefPtr def);
typedef int (*virSecurityDomainSetImageLabel) (virSecurityManagerPtr mgr,
                                               virDomainDefPtr def,
                                               virDomainDiskDefPtr disk);
typedef int (*virSecurityDomainRestoreHostdevLabel) (virSecurityManagerPtr mgr,
                                                     virDomainDefPtr def,
                                                     virDomainHostdevDefPtr dev);
typedef int (*virSecurityDomainSetHostdevLabel) (virSecurityManagerPtr mgr,
                                                 virDomainDefPtr def,
                                                 virDomainHostdevDefPtr dev);
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
                                                 int migrated);
typedef int (*virSecurityDomainGetProcessLabel) (virSecurityManagerPtr mgr,
                                                 virDomainDefPtr def,
                                                 pid_t pid,
                                                 virSecurityLabelPtr sec);
typedef int (*virSecurityDomainSetProcessLabel) (virSecurityManagerPtr mgr,
                                                 virDomainDefPtr def);
typedef int (*virSecurityDomainSecurityVerify) (virSecurityManagerPtr mgr,
                                                virDomainDefPtr def);
typedef int (*virSecurityDomainSetImageFDLabel) (virSecurityManagerPtr mgr,
                                                 virDomainDefPtr def,
                                                 int fd);

struct _virSecurityDriver {
    size_t privateDataLen;
    const char *name;
    virSecurityDriverProbe probe;
    virSecurityDriverOpen open;
    virSecurityDriverClose close;

    virSecurityDriverGetModel getModel;
    virSecurityDriverGetDOI getDOI;

    virSecurityDomainSecurityVerify domainSecurityVerify;

    virSecurityDomainSetImageLabel domainSetSecurityImageLabel;
    virSecurityDomainRestoreImageLabel domainRestoreSecurityImageLabel;

    virSecurityDomainSetDaemonSocketLabel domainSetSecurityDaemonSocketLabel;
    virSecurityDomainSetSocketLabel domainSetSecuritySocketLabel;
    virSecurityDomainClearSocketLabel domainClearSecuritySocketLabel;

    virSecurityDomainGenLabel domainGenSecurityLabel;
    virSecurityDomainReserveLabel domainReserveSecurityLabel;
    virSecurityDomainReleaseLabel domainReleaseSecurityLabel;

    virSecurityDomainGetProcessLabel domainGetSecurityProcessLabel;
    virSecurityDomainSetProcessLabel domainSetSecurityProcessLabel;

    virSecurityDomainSetAllLabel domainSetSecurityAllLabel;
    virSecurityDomainRestoreAllLabel domainRestoreSecurityAllLabel;

    virSecurityDomainSetHostdevLabel domainSetSecurityHostdevLabel;
    virSecurityDomainRestoreHostdevLabel domainRestoreSecurityHostdevLabel;

    virSecurityDomainSetSavedStateLabel domainSetSavedStateLabel;
    virSecurityDomainRestoreSavedStateLabel domainRestoreSavedStateLabel;

    virSecurityDomainSetImageFDLabel domainSetSecurityImageFDLabel;
};

virSecurityDriverPtr virSecurityDriverLookup(const char *name);

#endif /* __VIR_SECURITY_H__ */
