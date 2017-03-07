/*
 * Copyright (C) 2010, 2014 Red Hat, Inc.
 * Copyright IBM Corp. 2008
 *
 * lxc_conf.c: config functions for managing linux containers
 *
 * Authors:
 *  David L. Leskovec <dlesko at linux.vnet.ibm.com>
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
 */

/* includes */
#include <config.h>

#include "lxc_conf.h"
#include "lxc_domain.h"
#include "virerror.h"
#include "virconf.h"
#include "viralloc.h"
#include "virlog.h"
#include "viruuid.h"
#include "configmake.h"
#include "lxc_container.h"
#include "virnodesuspend.h"
#include "virstring.h"
#include "virfile.h"

#define VIR_FROM_THIS VIR_FROM_LXC

VIR_LOG_INIT("lxc.lxc_conf");

static virClassPtr virLXCDriverConfigClass;
static void virLXCDriverConfigDispose(void *obj);

static int virLXCConfigOnceInit(void)
{
    if (!(virLXCDriverConfigClass = virClassNew(virClassForObject(),
                                                 "virLXCDriverConfig",
                                                 sizeof(virLXCDriverConfig),
                                                 virLXCDriverConfigDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virLXCConfig)


/* Functions */
virCapsPtr virLXCDriverCapsInit(virLXCDriverPtr driver)
{
    virCapsPtr caps;
    virCapsGuestPtr guest;
    virArch altArch;
    char *lxc_path = NULL;

    if ((caps = virCapabilitiesNew(virArchFromHost(),
                                   false, false)) == NULL)
        goto error;

    /* Some machines have problematic NUMA toplogy causing
     * unexpected failures. We don't want to break the lxc
     * driver in this scenario, so log errors & carry on
     */
    if (virCapabilitiesInitNUMA(caps) < 0) {
        virCapabilitiesFreeNUMAInfo(caps);
        VIR_WARN("Failed to query host NUMA topology, disabling NUMA capabilities");
    }

    /* Only probe for power management capabilities in the driver,
     * not in the emulator */
    if (driver && virNodeSuspendGetTargetMask(&caps->host.powerMgmt) < 0)
        VIR_WARN("Failed to get host power management capabilities");

    if (virGetHostUUID(caps->host.host_uuid)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot get the host uuid"));
        goto error;
    }

    if (!(lxc_path = virFileFindResource("libvirt_lxc",
                                         abs_topbuilddir "/src",
                                         LIBEXECDIR)))
        goto error;

    if ((guest = virCapabilitiesAddGuest(caps,
                                         VIR_DOMAIN_OSTYPE_EXE,
                                         caps->host.arch,
                                         lxc_path,
                                         NULL,
                                         0,
                                         NULL)) == NULL)
        goto error;

    if (virCapabilitiesAddGuestDomain(guest,
                                      VIR_DOMAIN_VIRT_LXC,
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto error;

    /* On 64-bit hosts, we can use personality() to request a 32bit process */
    if ((altArch = lxcContainerGetAlt32bitArch(caps->host.arch)) != VIR_ARCH_NONE) {
        if ((guest = virCapabilitiesAddGuest(caps,
                                             VIR_DOMAIN_OSTYPE_EXE,
                                             altArch,
                                             lxc_path,
                                             NULL,
                                             0,
                                             NULL)) == NULL)
            goto error;

        if (virCapabilitiesAddGuestDomain(guest,
                                          VIR_DOMAIN_VIRT_LXC,
                                          NULL,
                                          NULL,
                                          0,
                                          NULL) == NULL)
            goto error;
    }

    VIR_FREE(lxc_path);

    if (driver) {
        /* Security driver data */
        const char *doi, *model, *label, *type;

        doi = virSecurityManagerGetDOI(driver->securityManager);
        model = virSecurityManagerGetModel(driver->securityManager);
        label = virSecurityManagerGetBaseLabel(driver->securityManager,
                                               VIR_DOMAIN_VIRT_LXC);
        type = virDomainVirtTypeToString(VIR_DOMAIN_VIRT_LXC);
        /* Allocate the primary security driver for LXC. */
        if (VIR_ALLOC(caps->host.secModels) < 0)
            goto error;
        caps->host.nsecModels = 1;
        if (VIR_STRDUP(caps->host.secModels[0].model, model) < 0)
            goto error;
        if (VIR_STRDUP(caps->host.secModels[0].doi, doi) < 0)
            goto error;
        if (label &&
            virCapabilitiesHostSecModelAddBaseLabel(&caps->host.secModels[0],
                                                    type,
                                                    label) < 0)
            goto error;

        VIR_DEBUG("Initialized caps for security driver \"%s\" with "
                  "DOI \"%s\"", model, doi);
    } else {
        VIR_INFO("No driver, not initializing security driver");
    }

    return caps;

 error:
    VIR_FREE(lxc_path);
    virObjectUnref(caps);
    return NULL;
}


/**
 * virLXCDriverGetCapabilities:
 *
 * Get a reference to the virCapsPtr instance for the
 * driver. If @refresh is true, the capabilities will be
 * rebuilt first
 *
 * The caller must release the reference with virObjetUnref
 *
 * Returns: a reference to a virCapsPtr instance or NULL
 */
virCapsPtr virLXCDriverGetCapabilities(virLXCDriverPtr driver,
                                       bool refresh)
{
    virCapsPtr ret;
    if (refresh) {
        virCapsPtr caps = NULL;
        if ((caps = virLXCDriverCapsInit(driver)) == NULL)
            return NULL;

        lxcDriverLock(driver);
        virObjectUnref(driver->caps);
        driver->caps = caps;
    } else {
        lxcDriverLock(driver);
    }

    ret = virObjectRef(driver->caps);
    lxcDriverUnlock(driver);
    return ret;
}


virDomainXMLOptionPtr
lxcDomainXMLConfInit(void)
{
    return virDomainXMLOptionNew(&virLXCDriverDomainDefParserConfig,
                                 &virLXCDriverPrivateDataCallbacks,
                                 &virLXCDriverDomainXMLNamespace);
}


virLXCDriverConfigPtr
virLXCDriverConfigNew(void)
{
    virLXCDriverConfigPtr cfg;

    if (virLXCConfigInitialize() < 0)
        return NULL;

    if (!(cfg = virObjectNew(virLXCDriverConfigClass)))
        return NULL;

    cfg->securityDefaultConfined = false;
    cfg->securityRequireConfined = false;

    /* Set the container configuration directory */
    if (VIR_STRDUP(cfg->configDir, LXC_CONFIG_DIR) < 0)
        goto error;
    if (VIR_STRDUP(cfg->stateDir, LXC_STATE_DIR) < 0)
        goto error;
    if (VIR_STRDUP(cfg->logDir, LXC_LOG_DIR) < 0)
        goto error;
    if (VIR_STRDUP(cfg->autostartDir, LXC_AUTOSTART_DIR) < 0)
        goto error;

    return cfg;
 error:
    virObjectUnref(cfg);
    return NULL;
}

int
virLXCLoadDriverConfig(virLXCDriverConfigPtr cfg,
                       const char *filename)
{
    virConfPtr conf;
    int ret = -1;

    /* Avoid error from non-existent or unreadable file. */
    if (access(filename, R_OK) == -1)
        return 0;

    conf = virConfReadFile(filename, 0);
    if (!conf)
        return -1;

    if (virConfGetValueBool(conf, "log_with_libvirtd", &cfg->log_libvirtd) < 0)
        goto cleanup;

    if (virConfGetValueString(conf, "security_driver", &cfg->securityDriverName) < 0)
        goto cleanup;

    if (virConfGetValueBool(conf, "security_default_confined", &cfg->securityDefaultConfined) < 0)
        goto cleanup;

    if (virConfGetValueBool(conf, "security_require_confined", &cfg->securityRequireConfined) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virConfFree(conf);
    return ret;
}

virLXCDriverConfigPtr virLXCDriverGetConfig(virLXCDriverPtr driver)
{
    virLXCDriverConfigPtr cfg;
    lxcDriverLock(driver);
    cfg = virObjectRef(driver->config);
    lxcDriverUnlock(driver);
    return cfg;
}

static void
virLXCDriverConfigDispose(void *obj)
{
    virLXCDriverConfigPtr cfg = obj;

    VIR_FREE(cfg->configDir);
    VIR_FREE(cfg->autostartDir);
    VIR_FREE(cfg->stateDir);
    VIR_FREE(cfg->logDir);
    VIR_FREE(cfg->securityDriverName);
}
