/*
 * Copyright Intel Corp. 2020-2021
 *
 * ch_conf.c: functions for Cloud-Hypervisor configuration
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
 */

#include <config.h>

#include "configmake.h"
#include "viralloc.h"
#include "vircommand.h"
#include "virlog.h"
#include "virobject.h"
#include "virstring.h"
#include "virutil.h"

#include "ch_conf.h"
#include "ch_domain.h"

#define VIR_FROM_THIS VIR_FROM_CH

VIR_LOG_INIT("ch.ch_conf");

static virClass *virCHDriverConfigClass;
static void virCHDriverConfigDispose(void *obj);

static int virCHConfigOnceInit(void)
{
    if (!VIR_CLASS_NEW(virCHDriverConfig, virClassForObject()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virCHConfig);


/* Functions */
virCaps *virCHDriverCapsInit(void)
{
    virCaps *caps;
    virCapsGuest *guest;

    if ((caps = virCapabilitiesNew(virArchFromHost(),
                                   false, false)) == NULL)
        goto cleanup;

    if (!(caps->host.numa = virCapabilitiesHostNUMANewHost()))
        goto cleanup;

    if (virCapabilitiesInitCaches(caps) < 0)
        goto cleanup;

    if ((guest = virCapabilitiesAddGuest(caps,
                                         VIR_DOMAIN_OSTYPE_HVM,
                                         caps->host.arch,
                                         NULL,
                                         NULL,
                                         0,
                                         NULL)) == NULL)
        goto cleanup;

    if (virCapabilitiesAddGuestDomain(guest,
                                      VIR_DOMAIN_VIRT_KVM,
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto cleanup;

    return caps;

 cleanup:
    virObjectUnref(caps);
    return NULL;
}

/**
 * virCHDriverGetCapabilities:
 *
 * Get a reference to the virCaps instance for the
 * driver. If @refresh is true, the capabilities will be
 * rebuilt first
 *
 * The caller must release the reference with virObjetUnref
 *
 * Returns: a reference to a virCaps instance or NULL
 */
virCaps *virCHDriverGetCapabilities(virCHDriver *driver,
                                      bool refresh)
{
    virCaps *ret;
    if (refresh) {
        virCaps *caps = NULL;
        if ((caps = virCHDriverCapsInit()) == NULL)
            return NULL;

        chDriverLock(driver);
        virObjectUnref(driver->caps);
        driver->caps = caps;
    } else {
        chDriverLock(driver);
    }

    ret = virObjectRef(driver->caps);
    chDriverUnlock(driver);
    return ret;
}

virDomainXMLOption *
chDomainXMLConfInit(virCHDriver *driver)
{
    virCHDriverDomainDefParserConfig.priv = driver;
    return virDomainXMLOptionNew(&virCHDriverDomainDefParserConfig,
                                 &virCHDriverPrivateDataCallbacks,
                                 NULL, NULL, NULL);
}

virCHDriverConfig *
virCHDriverConfigNew(bool privileged)
{
    virCHDriverConfig *cfg;

    if (virCHConfigInitialize() < 0)
        return NULL;

    if (!(cfg = virObjectNew(virCHDriverConfigClass)))
        return NULL;

    cfg->uri = g_strdup(privileged ? "ch:///system" : "ch:///session");
    if (privileged) {
        if (virGetUserID(CH_USER, &cfg->user) < 0)
            return NULL;
        if (virGetGroupID(CH_GROUP, &cfg->group) < 0)
            return NULL;
    } else {
        cfg->user = (uid_t)-1;
        cfg->group = (gid_t)-1;
    }

    if (privileged) {
        cfg->logDir = g_strdup_printf("%s/log/libvirt/ch", LOCALSTATEDIR);
        cfg->stateDir = g_strdup_printf("%s/libvirt/ch", RUNSTATEDIR);

    } else {
        g_autofree char *rundir = NULL;
        g_autofree char *cachedir = NULL;

        cachedir = virGetUserCacheDirectory();

        cfg->logDir = g_strdup_printf("%s/ch/log", cachedir);

        rundir = virGetUserRuntimeDirectory();
        cfg->stateDir = g_strdup_printf("%s/ch/run", rundir);
    }

    return cfg;
}

virCHDriverConfig *virCHDriverGetConfig(virCHDriver *driver)
{
    virCHDriverConfig *cfg;
    chDriverLock(driver);
    cfg = virObjectRef(driver->config);
    chDriverUnlock(driver);
    return cfg;
}

static void
virCHDriverConfigDispose(void *obj)
{
    virCHDriverConfig *cfg = obj;

    g_free(cfg->stateDir);
    g_free(cfg->logDir);
}

#define MIN_VERSION ((15 * 1000000) + (0 * 1000) + (0))

static int
chExtractVersionInfo(int *retversion)
{
    int ret = -1;
    unsigned long version;
    char *help = NULL;
    char *tmp = NULL;
    g_autofree char *ch_cmd = g_find_program_in_path(CH_CMD);
    virCommand *cmd = virCommandNewArgList(ch_cmd, "--version", NULL);

    if (retversion)
        *retversion = 0;

    virCommandAddEnvString(cmd, "LC_ALL=C");
    virCommandSetOutputBuffer(cmd, &help);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    tmp = help;

    /* expected format: cloud-hypervisor v<major>.<minor>.<micro> */
    if ((tmp = STRSKIP(tmp, "cloud-hypervisor v")) == NULL)
        goto cleanup;

    if (virParseVersionString(tmp, &version, true) < 0)
        goto cleanup;

    if (version < MIN_VERSION) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cloud-Hypervisor version is too old (v15.0 is the minimum supported version)"));
        goto cleanup;
    }

    if (retversion)
        *retversion = version;

    ret = 0;

 cleanup:
    virCommandFree(cmd);

    return ret;
}

int chExtractVersion(virCHDriver *driver)
{
    if (driver->version > 0)
        return 0;

    if (chExtractVersionInfo(&driver->version) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not extract Cloud-Hypervisor version"));
        return -1;
    }

    return 0;
}
