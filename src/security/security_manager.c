/*
 * security_manager.c: Internal security manager API
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

#include <config.h>


#include "security_driver.h"
#include "security_stack.h"
#include "security_dac.h"
#include "virterror_internal.h"
#include "memory.h"
#include "logging.h"

#define VIR_FROM_THIS VIR_FROM_SECURITY


struct _virSecurityManager {
    virSecurityDriverPtr drv;
    bool allowDiskFormatProbing;
    bool defaultConfined;
    bool requireConfined;
};

static virSecurityManagerPtr virSecurityManagerNewDriver(virSecurityDriverPtr drv,
                                                         bool allowDiskFormatProbing,
                                                         bool defaultConfined,
                                                         bool requireConfined)
{
    virSecurityManagerPtr mgr;

    if (VIR_ALLOC_VAR(mgr, char, drv->privateDataLen) < 0) {
        virReportOOMError();
        return NULL;
    }

    mgr->drv = drv;
    mgr->allowDiskFormatProbing = allowDiskFormatProbing;
    mgr->defaultConfined = defaultConfined;
    mgr->requireConfined = requireConfined;

    if (drv->open(mgr) < 0) {
        virSecurityManagerFree(mgr);
        return NULL;
    }

    return mgr;
}

virSecurityManagerPtr virSecurityManagerNewStack(virSecurityManagerPtr primary,
                                                 virSecurityManagerPtr secondary)
{
    virSecurityManagerPtr mgr =
        virSecurityManagerNewDriver(&virSecurityDriverStack,
                                    virSecurityManagerGetAllowDiskFormatProbing(primary),
                                    virSecurityManagerGetDefaultConfined(primary),
                                    virSecurityManagerGetRequireConfined(primary));

    if (!mgr)
        return NULL;

    virSecurityStackSetPrimary(mgr, primary);
    virSecurityStackSetSecondary(mgr, secondary);

    return mgr;
}

virSecurityManagerPtr virSecurityManagerNewDAC(uid_t user,
                                               gid_t group,
                                               bool allowDiskFormatProbing,
                                               bool defaultConfined,
                                               bool requireConfined,
                                               bool dynamicOwnership)
{
    virSecurityManagerPtr mgr =
        virSecurityManagerNewDriver(&virSecurityDriverDAC,
                                    allowDiskFormatProbing,
                                    defaultConfined,
                                    requireConfined);

    if (!mgr)
        return NULL;

    virSecurityDACSetUser(mgr, user);
    virSecurityDACSetGroup(mgr, group);
    virSecurityDACSetDynamicOwnership(mgr, dynamicOwnership);

    return mgr;
}

virSecurityManagerPtr virSecurityManagerNew(const char *name,
                                            bool allowDiskFormatProbing,
                                            bool defaultConfined,
                                            bool requireConfined)
{
    virSecurityDriverPtr drv = virSecurityDriverLookup(name);
    if (!drv)
        return NULL;

    /* driver "none" needs some special handling of *Confined bools */
    if (STREQ(drv->name, "none")) {
        if (requireConfined) {
            virSecurityReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                    _("Security driver \"none\" cannot create confined guests"));
            return NULL;
        }

        if (defaultConfined) {
            if (name != NULL) {
                VIR_WARN("Configured security driver \"none\" disables default"
                         " policy to create confined guests");
            } else {
                VIR_DEBUG("Auto-probed security driver is \"none\";"
                          " confined guests will not be created");
            }
            defaultConfined = false;
        }
    }

    return virSecurityManagerNewDriver(drv,
                                       allowDiskFormatProbing,
                                       defaultConfined,
                                       requireConfined);
}


void *virSecurityManagerGetPrivateData(virSecurityManagerPtr mgr)
{
    /* This accesses the memory just beyond mgr, which was allocated
     * via VIR_ALLOC_VAR earlier.  */
    return mgr + 1;
}


void virSecurityManagerFree(virSecurityManagerPtr mgr)
{
    if (!mgr)
        return;

    if (mgr->drv->close)
        mgr->drv->close(mgr);

    VIR_FREE(mgr);
}

const char *
virSecurityManagerGetDOI(virSecurityManagerPtr mgr)
{
    if (mgr->drv->getDOI)
        return mgr->drv->getDOI(mgr);

    virSecurityReportError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return NULL;
}

const char *
virSecurityManagerGetModel(virSecurityManagerPtr mgr)
{
    if (mgr->drv->getModel)
        return mgr->drv->getModel(mgr);

    virSecurityReportError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return NULL;
}

bool virSecurityManagerGetAllowDiskFormatProbing(virSecurityManagerPtr mgr)
{
    return mgr->allowDiskFormatProbing;
}

bool virSecurityManagerGetDefaultConfined(virSecurityManagerPtr mgr)
{
    return mgr->defaultConfined;
}

bool virSecurityManagerGetRequireConfined(virSecurityManagerPtr mgr)
{
    return mgr->requireConfined;
}

int virSecurityManagerRestoreImageLabel(virSecurityManagerPtr mgr,
                                        virDomainDefPtr vm,
                                        virDomainDiskDefPtr disk)
{
    if (mgr->drv->domainRestoreSecurityImageLabel)
        return mgr->drv->domainRestoreSecurityImageLabel(mgr, vm, disk);

    virSecurityReportError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

int virSecurityManagerSetDaemonSocketLabel(virSecurityManagerPtr mgr,
                                           virDomainDefPtr vm)
{
    if (mgr->drv->domainSetSecurityDaemonSocketLabel)
        return mgr->drv->domainSetSecurityDaemonSocketLabel(mgr, vm);

    virSecurityReportError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

int virSecurityManagerSetSocketLabel(virSecurityManagerPtr mgr,
                                     virDomainDefPtr vm)
{
    if (mgr->drv->domainSetSecuritySocketLabel)
        return mgr->drv->domainSetSecuritySocketLabel(mgr, vm);

    virSecurityReportError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

int virSecurityManagerClearSocketLabel(virSecurityManagerPtr mgr,
                                       virDomainDefPtr vm)
{
    if (mgr->drv->domainClearSecuritySocketLabel)
        return mgr->drv->domainClearSecuritySocketLabel(mgr, vm);

    virSecurityReportError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

int virSecurityManagerSetImageLabel(virSecurityManagerPtr mgr,
                                    virDomainDefPtr vm,
                                    virDomainDiskDefPtr disk)
{
    if (mgr->drv->domainSetSecurityImageLabel)
        return mgr->drv->domainSetSecurityImageLabel(mgr, vm, disk);

    virSecurityReportError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

int virSecurityManagerRestoreHostdevLabel(virSecurityManagerPtr mgr,
                                          virDomainDefPtr vm,
                                          virDomainHostdevDefPtr dev)
{
    if (mgr->drv->domainRestoreSecurityHostdevLabel)
        return mgr->drv->domainRestoreSecurityHostdevLabel(mgr, vm, dev);

    virSecurityReportError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

int virSecurityManagerSetHostdevLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr vm,
                                      virDomainHostdevDefPtr dev)
{
    if (mgr->drv->domainSetSecurityHostdevLabel)
        return mgr->drv->domainSetSecurityHostdevLabel(mgr, vm, dev);

    virSecurityReportError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

int virSecurityManagerSetSavedStateLabel(virSecurityManagerPtr mgr,
                                         virDomainDefPtr vm,
                                         const char *savefile)
{
    if (mgr->drv->domainSetSavedStateLabel)
        return mgr->drv->domainSetSavedStateLabel(mgr, vm, savefile);

    virSecurityReportError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

int virSecurityManagerRestoreSavedStateLabel(virSecurityManagerPtr mgr,
                                             virDomainDefPtr vm,
                                             const char *savefile)
{
    if (mgr->drv->domainRestoreSavedStateLabel)
        return mgr->drv->domainRestoreSavedStateLabel(mgr, vm, savefile);

    virSecurityReportError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

int virSecurityManagerGenLabel(virSecurityManagerPtr mgr,
                               virDomainDefPtr vm)
{
    if (vm->seclabel.type == VIR_DOMAIN_SECLABEL_DEFAULT) {
        if (mgr->defaultConfined)
            vm->seclabel.type = VIR_DOMAIN_SECLABEL_DYNAMIC;
        else
            vm->seclabel.type = VIR_DOMAIN_SECLABEL_NONE;
    }

    if ((vm->seclabel.type == VIR_DOMAIN_SECLABEL_NONE) &&
        mgr->requireConfined) {
        virSecurityReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Unconfined guests are not allowed on this host"));
        return -1;
    }

    if (mgr->drv->domainGenSecurityLabel)
        return mgr->drv->domainGenSecurityLabel(mgr, vm);

    virSecurityReportError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

int virSecurityManagerReserveLabel(virSecurityManagerPtr mgr,
                                   virDomainDefPtr vm,
                                   pid_t pid)
{
    if (mgr->drv->domainReserveSecurityLabel)
        return mgr->drv->domainReserveSecurityLabel(mgr, vm, pid);

    virSecurityReportError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

int virSecurityManagerReleaseLabel(virSecurityManagerPtr mgr,
                                   virDomainDefPtr vm)
{
    if (mgr->drv->domainReleaseSecurityLabel)
        return mgr->drv->domainReleaseSecurityLabel(mgr, vm);

    virSecurityReportError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

int virSecurityManagerSetAllLabel(virSecurityManagerPtr mgr,
                                  virDomainDefPtr vm,
                                  const char *stdin_path)
{
    if (mgr->drv->domainSetSecurityAllLabel)
        return mgr->drv->domainSetSecurityAllLabel(mgr, vm, stdin_path);

    virSecurityReportError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

int virSecurityManagerRestoreAllLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr vm,
                                      int migrated)
{
    if (mgr->drv->domainRestoreSecurityAllLabel)
        return mgr->drv->domainRestoreSecurityAllLabel(mgr, vm, migrated);

    virSecurityReportError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

int virSecurityManagerGetProcessLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr vm,
                                      pid_t pid,
                                      virSecurityLabelPtr sec)
{
    if (mgr->drv->domainGetSecurityProcessLabel)
        return mgr->drv->domainGetSecurityProcessLabel(mgr, vm, pid, sec);

    virSecurityReportError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

int virSecurityManagerSetProcessLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr vm)
{
    if (mgr->drv->domainSetSecurityProcessLabel)
        return mgr->drv->domainSetSecurityProcessLabel(mgr, vm);

    virSecurityReportError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

int virSecurityManagerVerify(virSecurityManagerPtr mgr,
                             virDomainDefPtr def)
{
    const virSecurityLabelDefPtr secdef = &def->seclabel;
    /* NULL model == dynamic labelling, with whatever driver
     * is active, so we can short circuit verify check to
     * avoid drivers de-referencing NULLs by accident
     */
    if (!secdef->model)
        return 0;

    if (mgr->drv->domainSecurityVerify)
        return mgr->drv->domainSecurityVerify(mgr, def);

    virSecurityReportError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

int virSecurityManagerSetImageFDLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr vm,
                                      int fd)
{
    if (mgr->drv->domainSetSecurityImageFDLabel)
        return mgr->drv->domainSetSecurityImageFDLabel(mgr, vm, fd);

    virSecurityReportError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}
