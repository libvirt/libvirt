/*
 * Copyright (C) 2008 Red Hat, Inc.
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
#define __VIR_SECURITY_H__

#include "internal.h"
#include "domain_conf.h"

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
typedef int (*virSecurityDriverOpen) (virSecurityDriverPtr drv);
typedef int (*virSecurityDomainRestoreImageLabel) (virDomainObjPtr vm,
                                                   virDomainDiskDefPtr disk);
typedef int (*virSecurityDomainSetImageLabel) (virDomainObjPtr vm,
                                               virDomainDiskDefPtr disk);
typedef int (*virSecurityDomainRestoreHostdevLabel) (virDomainObjPtr vm,
                                                     virDomainHostdevDefPtr dev);
typedef int (*virSecurityDomainSetHostdevLabel) (virDomainObjPtr vm,
                                                 virDomainHostdevDefPtr dev);
typedef int (*virSecurityDomainSetSavedStateLabel) (virDomainObjPtr vm,
                                                    const char *savefile);
typedef int (*virSecurityDomainRestoreSavedStateLabel) (virDomainObjPtr vm,
                                                        const char *savefile);
typedef int (*virSecurityDomainGenLabel) (virDomainObjPtr sec);
typedef int (*virSecurityDomainReserveLabel) (virDomainObjPtr sec);
typedef int (*virSecurityDomainReleaseLabel) (virDomainObjPtr sec);
typedef int (*virSecurityDomainSetAllLabel) (virDomainObjPtr sec);
typedef int (*virSecurityDomainRestoreAllLabel) (virDomainObjPtr vm);
typedef int (*virSecurityDomainGetProcessLabel) (virDomainObjPtr vm,
                                                 virSecurityLabelPtr sec);
typedef int (*virSecurityDomainSetProcessLabel) (virSecurityDriverPtr drv,
                                                 virDomainObjPtr vm);
typedef int (*virSecurityDomainSecurityVerify) (virDomainDefPtr def);

struct _virSecurityDriver {
    const char *name;
    virSecurityDriverProbe probe;
    virSecurityDriverOpen open;
    virSecurityDomainSecurityVerify domainSecurityVerify;
    virSecurityDomainRestoreImageLabel domainRestoreSecurityImageLabel;
    virSecurityDomainSetImageLabel domainSetSecurityImageLabel;
    virSecurityDomainGenLabel domainGenSecurityLabel;
    virSecurityDomainReserveLabel domainReserveSecurityLabel;
    virSecurityDomainReleaseLabel domainReleaseSecurityLabel;
    virSecurityDomainGetProcessLabel domainGetSecurityProcessLabel;
    virSecurityDomainSetProcessLabel domainSetSecurityProcessLabel;
    virSecurityDomainSetAllLabel domainSetSecurityAllLabel;
    virSecurityDomainRestoreAllLabel domainRestoreSecurityAllLabel;
    virSecurityDomainRestoreHostdevLabel domainRestoreSecurityHostdevLabel;
    virSecurityDomainSetHostdevLabel domainSetSecurityHostdevLabel;
    virSecurityDomainSetSavedStateLabel domainSetSavedStateLabel;
    virSecurityDomainRestoreSavedStateLabel domainRestoreSavedStateLabel;

    /*
     * This is internally managed driver state and should only be accessed
     * via helpers below.
     */
    struct {
        char doi[VIR_SECURITY_DOI_BUFLEN];
    } _private;
};

/* Global methods */
int virSecurityDriverStartup(virSecurityDriverPtr *drv,
                             const char *name);

int
virSecurityDriverVerify(virDomainDefPtr def);

#define virSecurityReportError(code, fmt...)                        \
    virReportErrorHelper(NULL, VIR_FROM_SECURITY, code, __FILE__,   \
                         __FUNCTION__, __LINE__, fmt)

/* Helpers */
void virSecurityDriverInit(virSecurityDriverPtr drv);
int virSecurityDriverSetDOI(virSecurityDriverPtr drv,
                            const char *doi);
const char *virSecurityDriverGetDOI(virSecurityDriverPtr drv);
const char *virSecurityDriverGetModel(virSecurityDriverPtr drv);

#endif /* __VIR_SECURITY_H__ */
