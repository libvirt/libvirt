/*
 * Copyright (C) 2010, 2014 Red Hat, Inc.
 * Copyright IBM Corp. 2008
 *
 * lxc_conf.c: config functions for managing linux containers
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

#include <unistd.h>

#include "lxc_conf.h"
#include "lxc_domain.h"
#include "virerror.h"
#include "virconf.h"
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
    if (!VIR_CLASS_NEW(virLXCDriverConfig, virClassForObject()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virLXCConfig);


/* Functions */
virCapsPtr virLXCDriverCapsInit(virLXCDriverPtr driver)
{
    virCapsPtr caps;
    virCapsGuestPtr guest;
    virArch altArch;
    g_autofree char *lxc_path = NULL;

    if ((caps = virCapabilitiesNew(virArchFromHost(),
                                   false, false)) == NULL)
        goto error;

    /* Some machines have problematic NUMA topology causing
     * unexpected failures. We don't want to break the lxc
     * driver in this scenario, so log errors & carry on
     */
    if (!(caps->host.numa = virCapabilitiesHostNUMANewHost()))
        goto error;

    if (virCapabilitiesInitCaches(caps) < 0)
        VIR_WARN("Failed to get host CPU cache info");

    /* Only probe for power management capabilities in the driver,
     * not in the emulator */
    if (driver && virNodeSuspendGetTargetMask(&caps->host.powerMgmt) < 0)
        VIR_WARN("Failed to get host power management capabilities");

    /* Add huge pages info */
    if (virCapabilitiesInitPages(caps) < 0)
        VIR_WARN("Failed to get pages info");

    if (virGetHostUUID(caps->host.host_uuid)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot get the host uuid"));
        goto error;
    }

    if (!(lxc_path = virFileFindResource("libvirt_lxc",
                                         abs_top_builddir "/src",
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

    if (driver) {
        /* Security driver data */
        const char *doi, *model, *label, *type;

        doi = virSecurityManagerGetDOI(driver->securityManager);
        model = virSecurityManagerGetModel(driver->securityManager);
        label = virSecurityManagerGetBaseLabel(driver->securityManager,
                                               VIR_DOMAIN_VIRT_LXC);
        type = virDomainVirtTypeToString(VIR_DOMAIN_VIRT_LXC);
        /* Allocate the primary security driver for LXC. */
        caps->host.secModels = g_new0(virCapsHostSecModel, 1);
        caps->host.nsecModels = 1;
        caps->host.secModels[0].model = g_strdup(model);
        caps->host.secModels[0].doi = g_strdup(doi);
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

        if (driver->caps == NULL) {
            VIR_DEBUG("Capabilities didn't detect any guests. Forcing a "
                      "refresh.");
            lxcDriverUnlock(driver);
            return virLXCDriverGetCapabilities(driver, true);
        }
    }

    ret = virObjectRef(driver->caps);
    lxcDriverUnlock(driver);
    return ret;
}


virDomainXMLOptionPtr
lxcDomainXMLConfInit(virLXCDriverPtr driver)
{
    virLXCDriverDomainDefParserConfig.priv = driver;
    return virDomainXMLOptionNew(&virLXCDriverDomainDefParserConfig,
                                 &virLXCDriverPrivateDataCallbacks,
                                 &virLXCDriverDomainXMLNamespace,
                                 NULL, NULL);
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
    cfg->configDir = g_strdup(LXC_CONFIG_DIR);
    cfg->stateDir = g_strdup(LXC_STATE_DIR);
    cfg->logDir = g_strdup(LXC_LOG_DIR);
    cfg->autostartDir = g_strdup(LXC_AUTOSTART_DIR);

    return cfg;
}

int
virLXCLoadDriverConfig(virLXCDriverConfigPtr cfg,
                       const char *filename)
{
    g_autoptr(virConf) conf = NULL;

    /* Avoid error from non-existent or unreadable file. */
    if (access(filename, R_OK) == -1)
        return 0;

    conf = virConfReadFile(filename, 0);
    if (!conf)
        return -1;

    if (virConfGetValueBool(conf, "log_with_libvirtd", &cfg->log_libvirtd) < 0)
        return -1;

    if (virConfGetValueString(conf, "security_driver", &cfg->securityDriverName) < 0)
        return -1;

    if (virConfGetValueBool(conf, "security_default_confined", &cfg->securityDefaultConfined) < 0)
        return -1;

    if (virConfGetValueBool(conf, "security_require_confined", &cfg->securityRequireConfined) < 0)
        return -1;

    return 0;
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

    g_free(cfg->configDir);
    g_free(cfg->autostartDir);
    g_free(cfg->stateDir);
    g_free(cfg->logDir);
    g_free(cfg->securityDriverName);
}
