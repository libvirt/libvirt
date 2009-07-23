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
typedef int (*virSecurityDriverOpen) (virConnectPtr conn,
                                      virSecurityDriverPtr drv);
typedef int (*virSecurityDomainRestoreImageLabel) (virConnectPtr conn,
                                                   virDomainDiskDefPtr disk);
typedef int (*virSecurityDomainSetImageLabel) (virConnectPtr conn,
                                               virDomainObjPtr vm,
                                               virDomainDiskDefPtr disk);
typedef int (*virSecurityDomainGenLabel) (virConnectPtr conn,
                                          virDomainObjPtr sec);
typedef int (*virSecurityDomainReserveLabel) (virConnectPtr conn,
                                           virDomainObjPtr sec);
typedef int (*virSecurityDomainGetLabel) (virConnectPtr conn,
                                          virDomainObjPtr vm,
                                          virSecurityLabelPtr sec);
typedef int (*virSecurityDomainRestoreLabel) (virConnectPtr conn,
                                              virDomainObjPtr vm);
typedef int (*virSecurityDomainSetLabel) (virConnectPtr conn,
                                          virSecurityDriverPtr drv,
                                          virDomainObjPtr vm);
typedef int (*virSecurityDomainSecurityVerify) (virConnectPtr conn,
                                                virDomainDefPtr def);

struct _virSecurityDriver {
    const char *name;
    virSecurityDriverProbe probe;
    virSecurityDriverOpen open;
    virSecurityDomainSecurityVerify domainSecurityVerify;
    virSecurityDomainRestoreImageLabel domainRestoreSecurityImageLabel;
    virSecurityDomainSetImageLabel domainSetSecurityImageLabel;
    virSecurityDomainGenLabel domainGenSecurityLabel;
    virSecurityDomainReserveLabel domainReserveSecurityLabel;
    virSecurityDomainGetLabel domainGetSecurityLabel;
    virSecurityDomainSetLabel domainSetSecurityLabel;
    virSecurityDomainRestoreLabel domainRestoreSecurityLabel;

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
virSecurityDriverVerify(virConnectPtr conn, virDomainDefPtr def);

void
virSecurityReportError(virConnectPtr conn, int code, const char *fmt, ...)
    ATTRIBUTE_FMT_PRINTF(3, 4);

/* Helpers */
void virSecurityDriverInit(virSecurityDriverPtr drv);
int virSecurityDriverSetDOI(virConnectPtr conn,
                            virSecurityDriverPtr drv,
                            const char *doi);
const char *virSecurityDriverGetDOI(virSecurityDriverPtr drv);
const char *virSecurityDriverGetModel(virSecurityDriverPtr drv);

#endif /* __VIR_SECURITY_H__ */
