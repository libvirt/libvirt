/*
 * security_manager.c: Internal security manager API
 *
 * Copyright (C) 2010-2014 Red Hat, Inc.
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>


#include "security_driver.h"
#include "security_stack.h"
#include "security_dac.h"
#include "virerror.h"
#include "viralloc.h"
#include "virobject.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_SECURITY

VIR_LOG_INIT("security.security_manager");

struct _virSecurityManager {
    virObjectLockable parent;

    virSecurityDriverPtr drv;
    bool allowDiskFormatProbing;
    bool defaultConfined;
    bool requireConfined;
    const char *virtDriver;
    void *privateData;
};

static virClassPtr virSecurityManagerClass;

static void virSecurityManagerDispose(void *obj);

static int virSecurityManagerOnceInit(void)
{
    if (!(virSecurityManagerClass = virClassNew(virClassForObjectLockable(),
                                                "virSecurityManagerClass",
                                                sizeof(virSecurityManager),
                                                virSecurityManagerDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virSecurityManager);

static virSecurityManagerPtr virSecurityManagerNewDriver(virSecurityDriverPtr drv,
                                                         const char *virtDriver,
                                                         bool allowDiskFormatProbing,
                                                         bool defaultConfined,
                                                         bool requireConfined)
{
    virSecurityManagerPtr mgr;
    char *privateData;

    if (virSecurityManagerInitialize() < 0)
        return NULL;

    VIR_DEBUG("drv=%p (%s) virtDriver=%s allowDiskFormatProbing=%d "
              "defaultConfined=%d requireConfined=%d",
              drv, drv->name, virtDriver,
              allowDiskFormatProbing, defaultConfined,
              requireConfined);

    if (VIR_ALLOC_N(privateData, drv->privateDataLen) < 0)
        return NULL;

    if (!(mgr = virObjectLockableNew(virSecurityManagerClass))) {
        VIR_FREE(privateData);
        return NULL;
    }

    mgr->drv = drv;
    mgr->allowDiskFormatProbing = allowDiskFormatProbing;
    mgr->defaultConfined = defaultConfined;
    mgr->requireConfined = requireConfined;
    mgr->virtDriver = virtDriver;
    mgr->privateData = privateData;

    if (drv->open(mgr) < 0) {
        virObjectUnref(mgr);
        return NULL;
    }

    return mgr;
}

virSecurityManagerPtr virSecurityManagerNewStack(virSecurityManagerPtr primary)
{
    virSecurityManagerPtr mgr =
        virSecurityManagerNewDriver(&virSecurityDriverStack,
                                    virSecurityManagerGetDriver(primary),
                                    virSecurityManagerGetAllowDiskFormatProbing(primary),
                                    virSecurityManagerGetDefaultConfined(primary),
                                    virSecurityManagerGetRequireConfined(primary));

    if (!mgr)
        return NULL;

    virSecurityStackAddNested(mgr, primary);

    return mgr;
}

int virSecurityManagerStackAddNested(virSecurityManagerPtr stack,
                                     virSecurityManagerPtr nested)
{
    if (!STREQ("stack", stack->drv->name))
        return -1;
    return virSecurityStackAddNested(stack, nested);
}

virSecurityManagerPtr virSecurityManagerNewDAC(const char *virtDriver,
                                               uid_t user,
                                               gid_t group,
                                               bool allowDiskFormatProbing,
                                               bool defaultConfined,
                                               bool requireConfined,
                                               bool dynamicOwnership)
{
    virSecurityManagerPtr mgr =
        virSecurityManagerNewDriver(&virSecurityDriverDAC,
                                    virtDriver,
                                    allowDiskFormatProbing,
                                    defaultConfined,
                                    requireConfined);

    if (!mgr)
        return NULL;

    if (virSecurityDACSetUserAndGroup(mgr, user, group) < 0) {
        virSecurityManagerDispose(mgr);
        return NULL;
    }
    virSecurityDACSetDynamicOwnership(mgr, dynamicOwnership);

    return mgr;
}

virSecurityManagerPtr virSecurityManagerNew(const char *name,
                                            const char *virtDriver,
                                            bool allowDiskFormatProbing,
                                            bool defaultConfined,
                                            bool requireConfined)
{
    virSecurityDriverPtr drv = virSecurityDriverLookup(name, virtDriver);
    if (!drv)
        return NULL;

    /* driver "none" needs some special handling of *Confined bools */
    if (STREQ(drv->name, "none")) {
        if (requireConfined) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
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
                                       virtDriver,
                                       allowDiskFormatProbing,
                                       defaultConfined,
                                       requireConfined);
}


/*
 * Must be called before fork()'ing to ensure mutex state
 * is sane for the child to use. A negative return means the
 * child must not be forked; a successful return must be
 * followed by a call to virSecurityManagerPostFork() in both
 * parent and child.
 */
int virSecurityManagerPreFork(virSecurityManagerPtr mgr)
{
    int ret = 0;

    virObjectLock(mgr);
    if (mgr->drv->preFork) {
        ret = mgr->drv->preFork(mgr);
        if (ret < 0)
            virObjectUnlock(mgr);
    }

    return ret;
}


/*
 * Must be called after fork()'ing in both parent and child
 * to ensure mutex state is sane for the child to use
 */
void virSecurityManagerPostFork(virSecurityManagerPtr mgr)
{
    virObjectUnlock(mgr);
}

void *virSecurityManagerGetPrivateData(virSecurityManagerPtr mgr)
{
    return mgr->privateData;
}


static void virSecurityManagerDispose(void *obj)
{
    virSecurityManagerPtr mgr = obj;

    if (mgr->drv->close)
        mgr->drv->close(mgr);
    VIR_FREE(mgr->privateData);
}

const char *
virSecurityManagerGetDriver(virSecurityManagerPtr mgr)
{
    return mgr->virtDriver;
}

const char *
virSecurityManagerGetDOI(virSecurityManagerPtr mgr)
{
    if (mgr->drv->getDOI) {
        const char *ret;
        virObjectLock(mgr);
        ret = mgr->drv->getDOI(mgr);
        virObjectUnlock(mgr);
        return ret;
    }

    virReportUnsupportedError();
    return NULL;
}

const char *
virSecurityManagerGetModel(virSecurityManagerPtr mgr)
{
    if (mgr->drv->getModel) {
        const char *ret;
        virObjectLock(mgr);
        ret = mgr->drv->getModel(mgr);
        virObjectUnlock(mgr);
        return ret;
    }

    virReportUnsupportedError();
    return NULL;
}

/* return NULL if a base label is not present */
const char *
virSecurityManagerGetBaseLabel(virSecurityManagerPtr mgr, int virtType)
{
    if (mgr->drv->getBaseLabel) {
        const char *ret;
        virObjectLock(mgr);
        ret = mgr->drv->getBaseLabel(mgr, virtType);
        virObjectUnlock(mgr);
        return ret;
    }

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
    if (mgr->drv->domainRestoreSecurityImageLabel) {
        int ret;
        virObjectLock(mgr);
        ret = mgr->drv->domainRestoreSecurityImageLabel(mgr, vm, disk);
        virObjectUnlock(mgr);
        return ret;
    }

    virReportUnsupportedError();
    return -1;
}

int virSecurityManagerSetDaemonSocketLabel(virSecurityManagerPtr mgr,
                                           virDomainDefPtr vm)
{
    if (mgr->drv->domainSetSecurityDaemonSocketLabel) {
        int ret;
        virObjectLock(mgr);
        ret = mgr->drv->domainSetSecurityDaemonSocketLabel(mgr, vm);
        virObjectUnlock(mgr);
        return ret;
    }

    virReportUnsupportedError();
    return -1;
}

int virSecurityManagerSetSocketLabel(virSecurityManagerPtr mgr,
                                     virDomainDefPtr vm)
{
    if (mgr->drv->domainSetSecuritySocketLabel) {
        int ret;
        virObjectLock(mgr);
        ret = mgr->drv->domainSetSecuritySocketLabel(mgr, vm);
        virObjectUnlock(mgr);
        return ret;
    }

    virReportUnsupportedError();
    return -1;
}

int virSecurityManagerClearSocketLabel(virSecurityManagerPtr mgr,
                                       virDomainDefPtr vm)
{
    if (mgr->drv->domainClearSecuritySocketLabel) {
        int ret;
        virObjectLock(mgr);
        ret = mgr->drv->domainClearSecuritySocketLabel(mgr, vm);
        virObjectUnlock(mgr);
        return ret;
    }

    virReportUnsupportedError();
    return -1;
}

int virSecurityManagerSetImageLabel(virSecurityManagerPtr mgr,
                                    virDomainDefPtr vm,
                                    virDomainDiskDefPtr disk)
{
    if (mgr->drv->domainSetSecurityImageLabel) {
        int ret;
        virObjectLock(mgr);
        ret = mgr->drv->domainSetSecurityImageLabel(mgr, vm, disk);
        virObjectUnlock(mgr);
        return ret;
    }

    virReportUnsupportedError();
    return -1;
}

int virSecurityManagerRestoreHostdevLabel(virSecurityManagerPtr mgr,
                                          virDomainDefPtr vm,
                                          virDomainHostdevDefPtr dev,
                                          const char *vroot)
{
    if (mgr->drv->domainRestoreSecurityHostdevLabel) {
        int ret;
        virObjectLock(mgr);
        ret = mgr->drv->domainRestoreSecurityHostdevLabel(mgr, vm, dev, vroot);
        virObjectUnlock(mgr);
        return ret;
    }

    virReportUnsupportedError();
    return -1;
}

int virSecurityManagerSetHostdevLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr vm,
                                      virDomainHostdevDefPtr dev,
                                      const char *vroot)
{
    if (mgr->drv->domainSetSecurityHostdevLabel) {
        int ret;
        virObjectLock(mgr);
        ret = mgr->drv->domainSetSecurityHostdevLabel(mgr, vm, dev, vroot);
        virObjectUnlock(mgr);
        return ret;
    }

    virReportUnsupportedError();
    return -1;
}

int virSecurityManagerSetSavedStateLabel(virSecurityManagerPtr mgr,
                                         virDomainDefPtr vm,
                                         const char *savefile)
{
    if (mgr->drv->domainSetSavedStateLabel) {
        int ret;
        virObjectLock(mgr);
        ret = mgr->drv->domainSetSavedStateLabel(mgr, vm, savefile);
        virObjectUnlock(mgr);
        return ret;
    }

    virReportUnsupportedError();
    return -1;
}

int virSecurityManagerRestoreSavedStateLabel(virSecurityManagerPtr mgr,
                                             virDomainDefPtr vm,
                                             const char *savefile)
{
    if (mgr->drv->domainRestoreSavedStateLabel) {
        int ret;
        virObjectLock(mgr);
        ret = mgr->drv->domainRestoreSavedStateLabel(mgr, vm, savefile);
        virObjectUnlock(mgr);
        return ret;
    }

    virReportUnsupportedError();
    return -1;
}

int virSecurityManagerGenLabel(virSecurityManagerPtr mgr,
                               virDomainDefPtr vm)
{
    int ret = -1;
    size_t i, j;
    virSecurityManagerPtr* sec_managers = NULL;
    virSecurityLabelDefPtr seclabel;
    bool generated = false;

    if (mgr == NULL || mgr->drv == NULL)
        return ret;

    if ((sec_managers = virSecurityManagerGetNested(mgr)) == NULL)
        return ret;

    virObjectLock(mgr);
    for (i = 0; i < vm->nseclabels; i++) {
        if (!vm->seclabels[i]->model)
            continue;

        for (j = 0; sec_managers[j]; j++)
            if (STREQ(vm->seclabels[i]->model, sec_managers[j]->drv->name))
                break;

        if (!sec_managers[j]) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unable to find security driver for label %s"),
                           vm->seclabels[i]->model);
            goto cleanup;
        }
    }

    for (i = 0; sec_managers[i]; i++) {
        generated = false;
        seclabel = virDomainDefGetSecurityLabelDef(vm, sec_managers[i]->drv->name);
        if (!seclabel) {
            if (!(seclabel = virDomainDefGenSecurityLabelDef(sec_managers[i]->drv->name)))
                goto cleanup;
            generated = seclabel->implicit = true;
        }

        if (seclabel->type == VIR_DOMAIN_SECLABEL_DEFAULT) {
            if (sec_managers[i]->defaultConfined) {
                seclabel->type = VIR_DOMAIN_SECLABEL_DYNAMIC;
            } else {
                seclabel->type = VIR_DOMAIN_SECLABEL_NONE;
                seclabel->norelabel = true;
            }
        }

        if (seclabel->type == VIR_DOMAIN_SECLABEL_NONE) {
            if (sec_managers[i]->requireConfined) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Unconfined guests are not allowed on this host"));
                goto cleanup;
            } else if (vm->nseclabels && generated) {
                VIR_DEBUG("Skipping auto generated seclabel of type none");
                virSecurityLabelDefFree(seclabel);
                seclabel = NULL;
                continue;
            }
        }

        if (!sec_managers[i]->drv->domainGenSecurityLabel) {
            virReportUnsupportedError();
        } else {
            /* The seclabel must be added to @vm prior calling domainGenSecurityLabel
             * which may require seclabel to be presented already */
            if (generated &&
                VIR_APPEND_ELEMENT(vm->seclabels, vm->nseclabels, seclabel) < 0)
                goto cleanup;

            if (sec_managers[i]->drv->domainGenSecurityLabel(sec_managers[i], vm) < 0) {
                if (VIR_DELETE_ELEMENT(vm->seclabels,
                                       vm->nseclabels -1, vm->nseclabels) < 0)
                    vm->nseclabels--;
                goto cleanup;
            }

            seclabel = NULL;
        }
    }

    ret = 0;

 cleanup:
    virObjectUnlock(mgr);
    if (generated)
        virSecurityLabelDefFree(seclabel);
    VIR_FREE(sec_managers);
    return ret;
}

int virSecurityManagerReserveLabel(virSecurityManagerPtr mgr,
                                   virDomainDefPtr vm,
                                   pid_t pid)
{
    if (mgr->drv->domainReserveSecurityLabel) {
        int ret;
        virObjectLock(mgr);
        ret = mgr->drv->domainReserveSecurityLabel(mgr, vm, pid);
        virObjectUnlock(mgr);
        return ret;
    }

    virReportUnsupportedError();
    return -1;
}

int virSecurityManagerReleaseLabel(virSecurityManagerPtr mgr,
                                   virDomainDefPtr vm)
{
    if (mgr->drv->domainReleaseSecurityLabel) {
        int ret;
        virObjectLock(mgr);
        ret = mgr->drv->domainReleaseSecurityLabel(mgr, vm);
        virObjectUnlock(mgr);
        return ret;
    }

    virReportUnsupportedError();
    return -1;
}

int virSecurityManagerSetAllLabel(virSecurityManagerPtr mgr,
                                  virDomainDefPtr vm,
                                  const char *stdin_path)
{
    if (mgr->drv->domainSetSecurityAllLabel) {
        int ret;
        virObjectLock(mgr);
        ret = mgr->drv->domainSetSecurityAllLabel(mgr, vm, stdin_path);
        virObjectUnlock(mgr);
        return ret;
    }

    virReportUnsupportedError();
    return -1;
}

int virSecurityManagerRestoreAllLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr vm,
                                      int migrated)
{
    if (mgr->drv->domainRestoreSecurityAllLabel) {
        int ret;
        virObjectLock(mgr);
        ret = mgr->drv->domainRestoreSecurityAllLabel(mgr, vm, migrated);
        virObjectUnlock(mgr);
        return ret;
    }

    virReportUnsupportedError();
    return -1;
}

int virSecurityManagerGetProcessLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr vm,
                                      pid_t pid,
                                      virSecurityLabelPtr sec)
{
    if (mgr->drv->domainGetSecurityProcessLabel) {
        int ret;
        virObjectLock(mgr);
        ret = mgr->drv->domainGetSecurityProcessLabel(mgr, vm, pid, sec);
        virObjectUnlock(mgr);
        return ret;
    }

    virReportUnsupportedError();
    return -1;
}

int virSecurityManagerSetProcessLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr vm)
{
    if (mgr->drv->domainSetSecurityProcessLabel) {
        int ret;
        virObjectLock(mgr);
        ret = mgr->drv->domainSetSecurityProcessLabel(mgr, vm);
        virObjectUnlock(mgr);
        return ret;
    }

    virReportUnsupportedError();
    return -1;
}

int virSecurityManagerSetChildProcessLabel(virSecurityManagerPtr mgr,
                                           virDomainDefPtr vm,
                                           virCommandPtr cmd)
{
    if (mgr->drv->domainSetSecurityChildProcessLabel)
       return mgr->drv->domainSetSecurityChildProcessLabel(mgr, vm, cmd);

    virReportUnsupportedError();
    return -1;
}

int virSecurityManagerVerify(virSecurityManagerPtr mgr,
                             virDomainDefPtr def)
{
    virSecurityLabelDefPtr secdef;

    if (mgr == NULL || mgr->drv == NULL)
        return 0;

    /* NULL model == dynamic labelling, with whatever driver
     * is active, so we can short circuit verify check to
     * avoid drivers de-referencing NULLs by accident
     */
    secdef = virDomainDefGetSecurityLabelDef(def, mgr->drv->name);
    if (secdef == NULL || secdef->model == NULL)
        return 0;

    if (mgr->drv->domainSecurityVerify) {
        int ret;
        virObjectLock(mgr);
        ret = mgr->drv->domainSecurityVerify(mgr, def);
        virObjectUnlock(mgr);
        return ret;
    }

    virReportUnsupportedError();
    return -1;
}

int virSecurityManagerSetImageFDLabel(virSecurityManagerPtr mgr,
                                      virDomainDefPtr vm,
                                      int fd)
{
    if (mgr->drv->domainSetSecurityImageFDLabel) {
        int ret;
        virObjectLock(mgr);
        ret = mgr->drv->domainSetSecurityImageFDLabel(mgr, vm, fd);
        virObjectUnlock(mgr);
        return ret;
    }

    virReportUnsupportedError();
    return -1;
}

int virSecurityManagerSetTapFDLabel(virSecurityManagerPtr mgr,
                                    virDomainDefPtr vm,
                                    int fd)
{
    if (mgr->drv->domainSetSecurityTapFDLabel) {
        int ret;
        virObjectLock(mgr);
        ret = mgr->drv->domainSetSecurityTapFDLabel(mgr, vm, fd);
        virObjectUnlock(mgr);
        return ret;
    }

    virReportUnsupportedError();
    return -1;
}

char *virSecurityManagerGetMountOptions(virSecurityManagerPtr mgr,
                                        virDomainDefPtr vm)
{
    if (mgr->drv->domainGetSecurityMountOptions) {
        char *ret;
        virObjectLock(mgr);
        ret = mgr->drv->domainGetSecurityMountOptions(mgr, vm);
        virObjectUnlock(mgr);
        return ret;
    }

    virReportUnsupportedError();
    return NULL;
}

virSecurityManagerPtr*
virSecurityManagerGetNested(virSecurityManagerPtr mgr)
{
    virSecurityManagerPtr* list = NULL;

    if (STREQ("stack", mgr->drv->name)) {
        return virSecurityStackGetNested(mgr);
    }

    if (VIR_ALLOC_N(list, 2) < 0)
        return NULL;

    list[0] = mgr;
    list[1] = NULL;
    return list;
}

int virSecurityManagerSetHugepages(virSecurityManagerPtr mgr,
                                    virDomainDefPtr vm,
                                    const char *path)
{
    if (mgr->drv->domainSetSecurityHugepages) {
        int ret;
        virObjectLock(mgr);
        ret = mgr->drv->domainSetSecurityHugepages(mgr, vm, path);
        virObjectUnlock(mgr);
        return ret;
    }

    return 0;
}
