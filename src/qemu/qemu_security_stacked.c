/*
 * Copyright (C) 2010 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * QEMU stacked security driver
 */

#include <config.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "qemu_security_stacked.h"

#include "qemu_conf.h"
#include "datatypes.h"
#include "virterror_internal.h"
#include "util.h"
#include "memory.h"
#include "logging.h"
#include "pci.h"
#include "hostusb.h"
#include "storage_file.h"

#define VIR_FROM_THIS VIR_FROM_QEMU


static struct qemud_driver *driver;

void qemuSecurityStackedSetDriver(struct qemud_driver *newdriver)
{
    driver = newdriver;
}


static int
qemuSecurityStackedVerify(virConnectPtr conn,
                          virDomainDefPtr def)
{
    int rc = 0;

    if (driver->securitySecondaryDriver &&
        driver->securitySecondaryDriver->domainSecurityVerify &&
        driver->securitySecondaryDriver->domainSecurityVerify(conn, def) < 0)
        rc = -1;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainSecurityVerify &&
        driver->securityPrimaryDriver->domainSecurityVerify(conn, def) < 0)
        rc = -1;

    return rc;
}


static int
qemuSecurityStackedGenLabel(virConnectPtr conn,
                            virDomainObjPtr vm)
{
    int rc = 0;

    if (driver->securitySecondaryDriver &&
        driver->securitySecondaryDriver->domainGenSecurityLabel &&
        driver->securitySecondaryDriver->domainGenSecurityLabel(conn, vm) < 0)
        rc = -1;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainGenSecurityLabel &&
        driver->securityPrimaryDriver->domainGenSecurityLabel(conn, vm) < 0)
        rc = -1;

    return rc;
}


static int
qemuSecurityStackedReleaseLabel(virConnectPtr conn,
                                virDomainObjPtr vm)
{
    int rc = 0;

    if (driver->securitySecondaryDriver &&
        driver->securitySecondaryDriver->domainReleaseSecurityLabel &&
        driver->securitySecondaryDriver->domainReleaseSecurityLabel(conn, vm) < 0)
        rc = -1;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainReleaseSecurityLabel &&
        driver->securityPrimaryDriver->domainReleaseSecurityLabel(conn, vm) < 0)
        rc = -1;

    return rc;
}


static int
qemuSecurityStackedReserveLabel(virConnectPtr conn,
                                virDomainObjPtr vm)
{
    int rc = 0;

    if (driver->securitySecondaryDriver &&
        driver->securitySecondaryDriver->domainReserveSecurityLabel &&
        driver->securitySecondaryDriver->domainReserveSecurityLabel(conn, vm) < 0)
        rc = -1;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainReserveSecurityLabel &&
        driver->securityPrimaryDriver->domainReserveSecurityLabel(conn, vm) < 0)
        rc = -1;

    return rc;
}


static int
qemuSecurityStackedSetSecurityImageLabel(virConnectPtr conn,
                                         virDomainObjPtr vm,
                                         virDomainDiskDefPtr disk)
{
    int rc = 0;

    if (driver->securitySecondaryDriver &&
        driver->securitySecondaryDriver->domainSetSecurityImageLabel &&
        driver->securitySecondaryDriver->domainSetSecurityImageLabel(conn, vm, disk) < 0)
        rc = -1;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainSetSecurityImageLabel &&
        driver->securityPrimaryDriver->domainSetSecurityImageLabel(conn, vm, disk) < 0)
        rc = -1;

    return rc;
}


static int
qemuSecurityStackedRestoreSecurityImageLabel(virConnectPtr conn,
                                             virDomainObjPtr vm,
                                             virDomainDiskDefPtr disk)
{
    int rc = 0;

    if (driver->securitySecondaryDriver &&
        driver->securitySecondaryDriver->domainRestoreSecurityImageLabel &&
        driver->securitySecondaryDriver->domainRestoreSecurityImageLabel(conn, vm, disk) < 0)
        rc = -1;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainRestoreSecurityImageLabel &&
        driver->securityPrimaryDriver->domainRestoreSecurityImageLabel(conn, vm, disk) < 0)
        rc = -1;

    return rc;
}


static int
qemuSecurityStackedSetSecurityHostdevLabel(virConnectPtr conn,
                                           virDomainObjPtr vm,
                                           virDomainHostdevDefPtr dev)

{
    int rc = 0;

    if (driver->securitySecondaryDriver &&
        driver->securitySecondaryDriver->domainSetSecurityHostdevLabel &&
        driver->securitySecondaryDriver->domainSetSecurityHostdevLabel(conn, vm, dev) < 0)
        rc = -1;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainSetSecurityHostdevLabel &&
        driver->securityPrimaryDriver->domainSetSecurityHostdevLabel(conn, vm, dev) < 0)
        rc = -1;

    return rc;
}


static int
qemuSecurityStackedRestoreSecurityHostdevLabel(virConnectPtr conn,
                                               virDomainObjPtr vm,
                                               virDomainHostdevDefPtr dev)

{
    int rc = 0;

    if (driver->securitySecondaryDriver &&
        driver->securitySecondaryDriver->domainRestoreSecurityHostdevLabel &&
        driver->securitySecondaryDriver->domainRestoreSecurityHostdevLabel(conn, vm, dev) < 0)
        rc = -1;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainRestoreSecurityHostdevLabel &&
        driver->securityPrimaryDriver->domainRestoreSecurityHostdevLabel(conn, vm, dev) < 0)
        rc = -1;

    return rc;
}


static int
qemuSecurityStackedSetSecurityAllLabel(virConnectPtr conn,
                                       virDomainObjPtr vm)
{
    int rc = 0;

    if (driver->securitySecondaryDriver &&
        driver->securitySecondaryDriver->domainSetSecurityAllLabel &&
        driver->securitySecondaryDriver->domainSetSecurityAllLabel(conn, vm) < 0)
        rc = -1;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainSetSecurityAllLabel &&
        driver->securityPrimaryDriver->domainSetSecurityAllLabel(conn, vm) < 0)
        rc = -1;

    return rc;
}


static int
qemuSecurityStackedRestoreSecurityAllLabel(virConnectPtr conn,
                                           virDomainObjPtr vm)
{
    int rc = 0;

    if (driver->securitySecondaryDriver &&
        driver->securitySecondaryDriver->domainRestoreSecurityAllLabel &&
        driver->securitySecondaryDriver->domainRestoreSecurityAllLabel(conn, vm) < 0)
        rc = -1;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainRestoreSecurityAllLabel &&
        driver->securityPrimaryDriver->domainRestoreSecurityAllLabel(conn, vm) < 0)
        rc = -1;

    return rc;
}


static int
qemuSecurityStackedSetSavedStateLabel(virConnectPtr conn,
                                      virDomainObjPtr vm,
                                      const char *savefile)
{
    int rc = 0;

    if (driver->securitySecondaryDriver &&
        driver->securitySecondaryDriver->domainSetSavedStateLabel &&
        driver->securitySecondaryDriver->domainSetSavedStateLabel(conn, vm, savefile) < 0)
        rc = -1;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainSetSavedStateLabel &&
        driver->securityPrimaryDriver->domainSetSavedStateLabel(conn, vm, savefile) < 0)
        rc = -1;

    return rc;
}


static int
qemuSecurityStackedRestoreSavedStateLabel(virConnectPtr conn,
                                          virDomainObjPtr vm,
                                          const char *savefile)
{
    int rc = 0;

    if (driver->securitySecondaryDriver &&
        driver->securitySecondaryDriver->domainRestoreSavedStateLabel &&
        driver->securitySecondaryDriver->domainRestoreSavedStateLabel(conn, vm, savefile) < 0)
        rc = -1;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainRestoreSavedStateLabel &&
        driver->securityPrimaryDriver->domainRestoreSavedStateLabel(conn, vm, savefile) < 0)
        rc = -1;

    return rc;
}


static int
qemuSecurityStackedSetProcessLabel(virConnectPtr conn,
                                   virSecurityDriverPtr drv ATTRIBUTE_UNUSED,
                                   virDomainObjPtr vm)
{
    int rc = 0;

    if (driver->securitySecondaryDriver &&
        driver->securitySecondaryDriver->domainSetSecurityProcessLabel &&
        driver->securitySecondaryDriver->domainSetSecurityProcessLabel(conn,
                                                                       driver->securitySecondaryDriver,
                                                                       vm) < 0)
        rc = -1;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainSetSecurityProcessLabel &&
        driver->securityPrimaryDriver->domainSetSecurityProcessLabel(conn,
                                                                     driver->securityPrimaryDriver,
                                                                     vm) < 0)
        rc = -1;

    return rc;
}

static int
qemuSecurityStackedGetProcessLabel(virConnectPtr conn,
                                   virDomainObjPtr vm,
                                   virSecurityLabelPtr seclabel)
{
    int rc = 0;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainGetSecurityProcessLabel &&
        driver->securityPrimaryDriver->domainGetSecurityProcessLabel(conn,
                                                                     vm,
                                                                     seclabel) < 0)
        rc = -1;

    return rc;
}

virSecurityDriver qemuStackedSecurityDriver = {
    .name                       = "qemuStacked",
    .domainSecurityVerify = qemuSecurityStackedVerify,

    .domainGenSecurityLabel = qemuSecurityStackedGenLabel,
    .domainReleaseSecurityLabel = qemuSecurityStackedReleaseLabel,
    .domainReserveSecurityLabel = qemuSecurityStackedReserveLabel,

    .domainGetSecurityProcessLabel = qemuSecurityStackedGetProcessLabel,
    .domainSetSecurityProcessLabel = qemuSecurityStackedSetProcessLabel,

    .domainSetSecurityImageLabel = qemuSecurityStackedSetSecurityImageLabel,
    .domainRestoreSecurityImageLabel = qemuSecurityStackedRestoreSecurityImageLabel,

    .domainSetSecurityAllLabel     = qemuSecurityStackedSetSecurityAllLabel,
    .domainRestoreSecurityAllLabel = qemuSecurityStackedRestoreSecurityAllLabel,

    .domainSetSecurityHostdevLabel = qemuSecurityStackedSetSecurityHostdevLabel,
    .domainRestoreSecurityHostdevLabel = qemuSecurityStackedRestoreSecurityHostdevLabel,

    .domainSetSavedStateLabel = qemuSecurityStackedSetSavedStateLabel,
    .domainRestoreSavedStateLabel = qemuSecurityStackedRestoreSavedStateLabel,
};
