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
qemuSecurityStackedVerify(virDomainDefPtr def)
{
    int rc = 0;

    if (driver->securitySecondaryDriver &&
        driver->securitySecondaryDriver->domainSecurityVerify &&
        driver->securitySecondaryDriver->domainSecurityVerify(def) < 0)
        rc = -1;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainSecurityVerify &&
        driver->securityPrimaryDriver->domainSecurityVerify(def) < 0)
        rc = -1;

    return rc;
}


static int
qemuSecurityStackedGenLabel(virDomainObjPtr vm)
{
    int rc = 0;

    if (driver->securitySecondaryDriver &&
        driver->securitySecondaryDriver->domainGenSecurityLabel &&
        driver->securitySecondaryDriver->domainGenSecurityLabel(vm) < 0)
        rc = -1;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainGenSecurityLabel &&
        driver->securityPrimaryDriver->domainGenSecurityLabel(vm) < 0)
        rc = -1;

    return rc;
}


static int
qemuSecurityStackedReleaseLabel(virDomainObjPtr vm)
{
    int rc = 0;

    if (driver->securitySecondaryDriver &&
        driver->securitySecondaryDriver->domainReleaseSecurityLabel &&
        driver->securitySecondaryDriver->domainReleaseSecurityLabel(vm) < 0)
        rc = -1;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainReleaseSecurityLabel &&
        driver->securityPrimaryDriver->domainReleaseSecurityLabel(vm) < 0)
        rc = -1;

    return rc;
}


static int
qemuSecurityStackedReserveLabel(virDomainObjPtr vm)
{
    int rc = 0;

    if (driver->securitySecondaryDriver &&
        driver->securitySecondaryDriver->domainReserveSecurityLabel &&
        driver->securitySecondaryDriver->domainReserveSecurityLabel(vm) < 0)
        rc = -1;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainReserveSecurityLabel &&
        driver->securityPrimaryDriver->domainReserveSecurityLabel(vm) < 0)
        rc = -1;

    return rc;
}


static int
qemuSecurityStackedSetSecurityImageLabel(virDomainObjPtr vm,
                                         virDomainDiskDefPtr disk)
{
    int rc = 0;

    if (driver->securitySecondaryDriver &&
        driver->securitySecondaryDriver->domainSetSecurityImageLabel &&
        driver->securitySecondaryDriver->domainSetSecurityImageLabel(vm, disk) < 0)
        rc = -1;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainSetSecurityImageLabel &&
        driver->securityPrimaryDriver->domainSetSecurityImageLabel(vm, disk) < 0)
        rc = -1;

    return rc;
}


static int
qemuSecurityStackedRestoreSecurityImageLabel(virDomainObjPtr vm,
                                             virDomainDiskDefPtr disk)
{
    int rc = 0;

    if (driver->securitySecondaryDriver &&
        driver->securitySecondaryDriver->domainRestoreSecurityImageLabel &&
        driver->securitySecondaryDriver->domainRestoreSecurityImageLabel(vm, disk) < 0)
        rc = -1;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainRestoreSecurityImageLabel &&
        driver->securityPrimaryDriver->domainRestoreSecurityImageLabel(vm, disk) < 0)
        rc = -1;

    return rc;
}


static int
qemuSecurityStackedSetSecurityHostdevLabel(virDomainObjPtr vm,
                                           virDomainHostdevDefPtr dev)

{
    int rc = 0;

    if (driver->securitySecondaryDriver &&
        driver->securitySecondaryDriver->domainSetSecurityHostdevLabel &&
        driver->securitySecondaryDriver->domainSetSecurityHostdevLabel(vm, dev) < 0)
        rc = -1;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainSetSecurityHostdevLabel &&
        driver->securityPrimaryDriver->domainSetSecurityHostdevLabel(vm, dev) < 0)
        rc = -1;

    return rc;
}


static int
qemuSecurityStackedRestoreSecurityHostdevLabel(virDomainObjPtr vm,
                                               virDomainHostdevDefPtr dev)

{
    int rc = 0;

    if (driver->securitySecondaryDriver &&
        driver->securitySecondaryDriver->domainRestoreSecurityHostdevLabel &&
        driver->securitySecondaryDriver->domainRestoreSecurityHostdevLabel(vm, dev) < 0)
        rc = -1;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainRestoreSecurityHostdevLabel &&
        driver->securityPrimaryDriver->domainRestoreSecurityHostdevLabel(vm, dev) < 0)
        rc = -1;

    return rc;
}


static int
qemuSecurityStackedSetSecurityAllLabel(virDomainObjPtr vm, const char *stdin_path)
{
    int rc = 0;

    if (driver->securitySecondaryDriver &&
        driver->securitySecondaryDriver->domainSetSecurityAllLabel &&
        driver->securitySecondaryDriver->domainSetSecurityAllLabel(vm, stdin_path) < 0)
        rc = -1;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainSetSecurityAllLabel &&
        driver->securityPrimaryDriver->domainSetSecurityAllLabel(vm, stdin_path) < 0)
        rc = -1;

    return rc;
}


static int
qemuSecurityStackedRestoreSecurityAllLabel(virDomainObjPtr vm,
                                           int migrated)
{
    int rc = 0;

    if (driver->securitySecondaryDriver &&
        driver->securitySecondaryDriver->domainRestoreSecurityAllLabel &&
        driver->securitySecondaryDriver->domainRestoreSecurityAllLabel(vm, migrated) < 0)
        rc = -1;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainRestoreSecurityAllLabel &&
        driver->securityPrimaryDriver->domainRestoreSecurityAllLabel(vm, migrated) < 0)
        rc = -1;

    return rc;
}


static int
qemuSecurityStackedSetSavedStateLabel(virDomainObjPtr vm,
                                      const char *savefile)
{
    int rc = 0;

    if (driver->securitySecondaryDriver &&
        driver->securitySecondaryDriver->domainSetSavedStateLabel &&
        driver->securitySecondaryDriver->domainSetSavedStateLabel(vm, savefile) < 0)
        rc = -1;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainSetSavedStateLabel &&
        driver->securityPrimaryDriver->domainSetSavedStateLabel(vm, savefile) < 0)
        rc = -1;

    return rc;
}


static int
qemuSecurityStackedRestoreSavedStateLabel(virDomainObjPtr vm,
                                          const char *savefile)
{
    int rc = 0;

    if (driver->securitySecondaryDriver &&
        driver->securitySecondaryDriver->domainRestoreSavedStateLabel &&
        driver->securitySecondaryDriver->domainRestoreSavedStateLabel(vm, savefile) < 0)
        rc = -1;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainRestoreSavedStateLabel &&
        driver->securityPrimaryDriver->domainRestoreSavedStateLabel(vm, savefile) < 0)
        rc = -1;

    return rc;
}


static int
qemuSecurityStackedSetProcessLabel(virSecurityDriverPtr drv ATTRIBUTE_UNUSED,
                                   virDomainObjPtr vm)
{
    int rc = 0;

    if (driver->securitySecondaryDriver &&
        driver->securitySecondaryDriver->domainSetSecurityProcessLabel &&
        driver->securitySecondaryDriver->domainSetSecurityProcessLabel(driver->securitySecondaryDriver,
                                                                       vm) < 0)
        rc = -1;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainSetSecurityProcessLabel &&
        driver->securityPrimaryDriver->domainSetSecurityProcessLabel(driver->securityPrimaryDriver,
                                                                     vm) < 0)
        rc = -1;

    return rc;
}

static int
qemuSecurityStackedGetProcessLabel(virDomainObjPtr vm,
                                   virSecurityLabelPtr seclabel)
{
    int rc = 0;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainGetSecurityProcessLabel &&
        driver->securityPrimaryDriver->domainGetSecurityProcessLabel(vm,
                                                                     seclabel) < 0)
        rc = -1;

    return rc;
}


static int
qemuSecurityStackedSetSocketLabel(virSecurityDriverPtr drv ATTRIBUTE_UNUSED,
                                  virDomainObjPtr vm)
{
    int rc = 0;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainSetSecuritySocketLabel &&
        driver->securityPrimaryDriver->domainSetSecuritySocketLabel(driver->securityPrimaryDriver,
                                                                    vm) < 0)
        rc = -1;

    if (driver->securitySecondaryDriver &&
        driver->securitySecondaryDriver->domainSetSecuritySocketLabel &&
        driver->securitySecondaryDriver->domainSetSecuritySocketLabel(driver->securitySecondaryDriver,
                                                                      vm) < 0)
        rc = -1;

    return rc;
}


static int
qemuSecurityStackedClearSocketLabel(virSecurityDriverPtr drv ATTRIBUTE_UNUSED,
                                    virDomainObjPtr vm)
{
    int rc = 0;

    if (driver->securitySecondaryDriver &&
        driver->securitySecondaryDriver->domainClearSecuritySocketLabel &&
        driver->securitySecondaryDriver->domainClearSecuritySocketLabel(driver->securitySecondaryDriver,
                                                                        vm) < 0)
        rc = -1;

    if (driver->securityPrimaryDriver &&
        driver->securityPrimaryDriver->domainClearSecuritySocketLabel &&
        driver->securityPrimaryDriver->domainClearSecuritySocketLabel(driver->securityPrimaryDriver,
                                                                      vm) < 0)
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

    .domainClearSecuritySocketLabel = qemuSecurityStackedClearSocketLabel,
    .domainSetSecuritySocketLabel = qemuSecurityStackedSetSocketLabel,
};
