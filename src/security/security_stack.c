/*
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
 * Stacked security driver
 */

#include <config.h>

#include "security_stack.h"

#include "virterror_internal.h"

#define VIR_FROM_THIS VIR_FROM_SECURITY

typedef struct _virSecurityStackData virSecurityStackData;
typedef virSecurityStackData *virSecurityStackDataPtr;

struct _virSecurityStackData {
    virSecurityManagerPtr primary;
    virSecurityManagerPtr secondary;
};

void virSecurityStackSetPrimary(virSecurityManagerPtr mgr,
                                virSecurityManagerPtr primary)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    priv->primary = primary;
}

void virSecurityStackSetSecondary(virSecurityManagerPtr mgr,
                                  virSecurityManagerPtr secondary)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    priv->secondary = secondary;
}

static virSecurityDriverStatus
virSecurityStackProbe(void)
{
    return SECURITY_DRIVER_ENABLE;
}

static int
virSecurityStackOpen(virSecurityManagerPtr mgr ATTRIBUTE_UNUSED)
{
    return 0;
}

static int
virSecurityStackClose(virSecurityManagerPtr mgr)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);

    virSecurityManagerFree(priv->primary);
    virSecurityManagerFree(priv->secondary);

    return 0;
}

static const char *
virSecurityStackGetModel(virSecurityManagerPtr mgr)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);

    return virSecurityManagerGetModel(priv->primary);
}

static const char *
virSecurityStackGetDOI(virSecurityManagerPtr mgr)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);

    return virSecurityManagerGetDOI(priv->primary);
}

static int
virSecurityStackVerify(virSecurityManagerPtr mgr,
                       virDomainDefPtr def)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    int rc = 0;

    if (virSecurityManagerVerify(priv->primary, def) < 0)
        rc = -1;

    if (virSecurityManagerVerify(priv->secondary, def) < 0)
        rc = -1;

    return rc;
}


static int
virSecurityStackGenLabel(virSecurityManagerPtr mgr,
                         virDomainDefPtr vm)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    int rc = 0;

    if (virSecurityManagerGenLabel(priv->primary, vm) < 0)
        rc = -1;

#if 0
    /* We don't allow secondary drivers to generate labels.
     * This may have to change in the future, but requires
     * changes elsewhere in domain_conf.c and capabilities.c
     * XML formats first, to allow recording of multiple
     * labels
     */
    if (virSecurityManagerGenLabel(priv->secondary, vm) < 0)
        rc = -1;
#endif

    return rc;
}


static int
virSecurityStackReleaseLabel(virSecurityManagerPtr mgr,
                             virDomainDefPtr vm)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    int rc = 0;

    if (virSecurityManagerReleaseLabel(priv->primary, vm) < 0)
        rc = -1;
#if 0
    /* XXX See note in GenLabel */
    if (virSecurityManagerReleaseLabel(priv->secondary, vm) < 0)
        rc = -1;
#endif

    return rc;
}


static int
virSecurityStackReserveLabel(virSecurityManagerPtr mgr,
                             virDomainDefPtr vm,
                             pid_t pid)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    int rc = 0;

    if (virSecurityManagerReserveLabel(priv->primary, vm, pid) < 0)
        rc = -1;
#if 0
    /* XXX See note in GenLabel */
    if (virSecurityManagerReserveLabel(priv->secondary, vm, pid) < 0)
        rc = -1;
#endif

    return rc;
}


static int
virSecurityStackSetSecurityImageLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr vm,
                                      virDomainDiskDefPtr disk)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    int rc = 0;

    if (virSecurityManagerSetImageLabel(priv->secondary, vm, disk) < 0)
        rc = -1;
    if (virSecurityManagerSetImageLabel(priv->primary, vm, disk) < 0)
        rc = -1;

    return rc;
}


static int
virSecurityStackRestoreSecurityImageLabel(virSecurityManagerPtr mgr,
                                          virDomainDefPtr vm,
                                          virDomainDiskDefPtr disk)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    int rc = 0;

    if (virSecurityManagerRestoreImageLabel(priv->secondary, vm, disk) < 0)
        rc = -1;
    if (virSecurityManagerRestoreImageLabel(priv->primary, vm, disk) < 0)
        rc = -1;

    return rc;
}


static int
virSecurityStackSetSecurityHostdevLabel(virSecurityManagerPtr mgr,
                                        virDomainDefPtr vm,
                                        virDomainHostdevDefPtr dev)

{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    int rc = 0;

    if (virSecurityManagerSetHostdevLabel(priv->secondary, vm, dev) < 0)
        rc = -1;
    if (virSecurityManagerSetHostdevLabel(priv->primary, vm, dev) < 0)
        rc = -1;

    return rc;
}


static int
virSecurityStackRestoreSecurityHostdevLabel(virSecurityManagerPtr mgr,
                                            virDomainDefPtr vm,
                                            virDomainHostdevDefPtr dev)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    int rc = 0;

    if (virSecurityManagerRestoreHostdevLabel(priv->secondary, vm, dev) < 0)
        rc = -1;
    if (virSecurityManagerRestoreHostdevLabel(priv->primary, vm, dev) < 0)
        rc = -1;

    return rc;
}


static int
virSecurityStackSetSecurityAllLabel(virSecurityManagerPtr mgr,
                                    virDomainDefPtr vm,
                                    const char *stdin_path)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    int rc = 0;

    if (virSecurityManagerSetAllLabel(priv->secondary, vm, stdin_path) < 0)
        rc = -1;
    if (virSecurityManagerSetAllLabel(priv->primary, vm, stdin_path) < 0)
        rc = -1;

    return rc;
}


static int
virSecurityStackRestoreSecurityAllLabel(virSecurityManagerPtr mgr,
                                        virDomainDefPtr vm,
                                        int migrated)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    int rc = 0;

    if (virSecurityManagerRestoreAllLabel(priv->secondary, vm, migrated) < 0)
        rc = -1;
    if (virSecurityManagerRestoreAllLabel(priv->primary, vm, migrated) < 0)
        rc = -1;

    return rc;
}


static int
virSecurityStackSetSavedStateLabel(virSecurityManagerPtr mgr,
                                   virDomainDefPtr vm,
                                   const char *savefile)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    int rc = 0;

    if (virSecurityManagerSetSavedStateLabel(priv->secondary, vm, savefile) < 0)
        rc = -1;
    if (virSecurityManagerSetSavedStateLabel(priv->primary, vm, savefile) < 0)
        rc = -1;

    return rc;
}


static int
virSecurityStackRestoreSavedStateLabel(virSecurityManagerPtr mgr,
                                       virDomainDefPtr vm,
                                       const char *savefile)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    int rc = 0;

    if (virSecurityManagerRestoreSavedStateLabel(priv->secondary, vm, savefile) < 0)
        rc = -1;
    if (virSecurityManagerRestoreSavedStateLabel(priv->primary, vm, savefile) < 0)
        rc = -1;

    return rc;
}


static int
virSecurityStackSetProcessLabel(virSecurityManagerPtr mgr,
                                virDomainDefPtr vm)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    int rc = 0;

    if (virSecurityManagerSetProcessLabel(priv->secondary, vm) < 0)
        rc = -1;
    if (virSecurityManagerSetProcessLabel(priv->primary, vm) < 0)
        rc = -1;

    return rc;
}

static int
virSecurityStackGetProcessLabel(virSecurityManagerPtr mgr,
                                virDomainDefPtr vm,
                                pid_t pid,
                                virSecurityLabelPtr seclabel)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    int rc = 0;

#if 0
    if (virSecurityManagerGetProcessLabel(priv->secondary, vm, pid, seclabel) < 0)
        rc = -1;
#endif
    if (virSecurityManagerGetProcessLabel(priv->primary, vm, pid, seclabel) < 0)
        rc = -1;

    return rc;
}


static int
virSecurityStackSetDaemonSocketLabel(virSecurityManagerPtr mgr,
                                     virDomainDefPtr vm)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    int rc = 0;

    if (virSecurityManagerSetDaemonSocketLabel(priv->secondary, vm) < 0)
        rc = -1;
    if (virSecurityManagerSetDaemonSocketLabel(priv->primary, vm) < 0)
        rc = -1;

    return rc;
}


static int
virSecurityStackSetSocketLabel(virSecurityManagerPtr mgr,
                               virDomainDefPtr vm)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    int rc = 0;

    if (virSecurityManagerSetSocketLabel(priv->secondary, vm) < 0)
        rc = -1;
    if (virSecurityManagerSetSocketLabel(priv->primary, vm) < 0)
        rc = -1;

    return rc;
}


static int
virSecurityStackClearSocketLabel(virSecurityManagerPtr mgr,
                                 virDomainDefPtr vm)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    int rc = 0;

    if (virSecurityManagerClearSocketLabel(priv->secondary, vm) < 0)
        rc = -1;
    if (virSecurityManagerClearSocketLabel(priv->primary, vm) < 0)
        rc = -1;

    return rc;
}

static int
virSecurityStackSetImageFDLabel(virSecurityManagerPtr mgr,
                                virDomainDefPtr vm,
                                int fd)
{
    virSecurityStackDataPtr priv = virSecurityManagerGetPrivateData(mgr);
    int rc = 0;

    if (virSecurityManagerSetImageFDLabel(priv->secondary, vm, fd) < 0)
        rc = -1;
    if (virSecurityManagerSetImageFDLabel(priv->primary, vm, fd) < 0)
        rc = -1;

    return rc;
}


virSecurityDriver virSecurityDriverStack = {
    sizeof(virSecurityStackData),
    "stack",
    virSecurityStackProbe,
    virSecurityStackOpen,
    virSecurityStackClose,

    virSecurityStackGetModel,
    virSecurityStackGetDOI,

    virSecurityStackVerify,

    virSecurityStackSetSecurityImageLabel,
    virSecurityStackRestoreSecurityImageLabel,

    virSecurityStackSetDaemonSocketLabel,
    virSecurityStackSetSocketLabel,
    virSecurityStackClearSocketLabel,

    virSecurityStackGenLabel,
    virSecurityStackReserveLabel,
    virSecurityStackReleaseLabel,

    virSecurityStackGetProcessLabel,
    virSecurityStackSetProcessLabel,

    virSecurityStackSetSecurityAllLabel,
    virSecurityStackRestoreSecurityAllLabel,

    virSecurityStackSetSecurityHostdevLabel,
    virSecurityStackRestoreSecurityHostdevLabel,

    virSecurityStackSetSavedStateLabel,
    virSecurityStackRestoreSavedStateLabel,

    virSecurityStackSetImageFDLabel,
};
