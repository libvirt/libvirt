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
#include "virfile.h"

#define VIR_FROM_THIS VIR_FROM_LXC

VIR_LOG_INIT("lxc.lxc_conf");

static virClass *virLXCDriverConfigClass;
static void virLXCDriverConfigDispose(void *obj);

static int virLXCConfigOnceInit(void)
{
    if (!VIR_CLASS_NEW(virLXCDriverConfig, virClassForObject()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virLXCConfig);


/* Functions */
virCaps *virLXCDriverCapsInit(virLXCDriver *driver)
{
    g_autoptr(virCaps) caps = NULL;
    virCapsGuest *guest;
    virArch altArch;
    g_autofree char *lxc_path = NULL;

    if ((caps = virCapabilitiesNew(virArchFromHost(),
                                   false, false)) == NULL)
        return NULL;

    /* Some machines have problematic NUMA topology causing
     * unexpected failures. We don't want to break the lxc
     * driver in this scenario, so log errors & carry on
     */
    if (!(caps->host.numa = virCapabilitiesHostNUMANewHost()))
        return NULL;

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
        return NULL;
    }

    if (!(lxc_path = virFileFindResource("libvirt_lxc",
                                         abs_top_builddir "/src",
                                         LIBEXECDIR)))
        return NULL;

    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_EXE,
                                    caps->host.arch, lxc_path, NULL, 0, NULL);

    virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_LXC,
                                  NULL, NULL, 0, NULL);

    /* On 64-bit hosts, we can use personality() to request a 32bit process */
    if ((altArch = lxcContainerGetAlt32bitArch(caps->host.arch)) != VIR_ARCH_NONE) {
        guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_EXE,
                                        altArch, lxc_path, NULL, 0, NULL);

        virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_LXC,
                                      NULL, NULL, 0, NULL);
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
            return NULL;

        VIR_DEBUG("Initialized caps for security driver \"%s\" with "
                  "DOI \"%s\"", model, doi);
    } else {
        VIR_INFO("No driver, not initializing security driver");
    }

    return g_steal_pointer(&caps);
}


/**
 * virLXCDriverGetCapabilities:
 *
 * Get a reference to the virCaps *instance for the
 * driver. If @refresh is true, the capabilities will be
 * rebuilt first
 *
 * The caller must release the reference with virObjetUnref
 *
 * Returns: a reference to a virCaps *instance or NULL
 */
virCaps *virLXCDriverGetCapabilities(virLXCDriver *driver,
                                       bool refresh)
{
    virCaps *ret = NULL;
    virCaps *caps = NULL;

    VIR_WITH_MUTEX_LOCK_GUARD(&driver->lock) {
        if (!refresh && !driver->caps) {
            VIR_DEBUG("Capabilities didn't detect any guests. Forcing a refresh.");
            refresh = true;
        }
    }

    if (refresh && !(caps = virLXCDriverCapsInit(driver)))
        return NULL;

    VIR_WITH_MUTEX_LOCK_GUARD(&driver->lock) {
        if (refresh) {
            virObjectUnref(driver->caps);
            driver->caps = caps;
        }

        ret = virObjectRef(driver->caps);
    }

    return ret;
}


virDomainXMLOption *
lxcDomainXMLConfInit(virLXCDriver *driver, const char *defsecmodel)
{
    virDomainXMLOption *ret = NULL;

    virLXCDriverDomainDefParserConfig.priv = driver;
    virLXCDriverDomainDefParserConfig.defSecModel = defsecmodel;

    ret = virDomainXMLOptionNew(&virLXCDriverDomainDefParserConfig,
                                &virLXCDriverPrivateDataCallbacks,
                                &virLXCDriverDomainXMLNamespace,
                                NULL, NULL, NULL);

    virDomainXMLOptionSetCloseCallbackAlloc(ret, virCloseCallbacksDomainAlloc);

    return ret;
}


virLXCDriverConfig *
virLXCDriverConfigNew(void)
{
    virLXCDriverConfig *cfg;

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
virLXCLoadDriverConfig(virLXCDriverConfig *cfg,
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

virLXCDriverConfig *virLXCDriverGetConfig(virLXCDriver *driver)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);
    return virObjectRef(driver->config);
}

static void
virLXCDriverConfigDispose(void *obj)
{
    virLXCDriverConfig *cfg = obj;

    g_free(cfg->configDir);
    g_free(cfg->autostartDir);
    g_free(cfg->stateDir);
    g_free(cfg->logDir);
    g_free(cfg->securityDriverName);
}
