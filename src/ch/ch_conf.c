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
#include "vircommand.h"
#include "virconf.h"
#include "virfile.h"
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
    g_autoptr(virCaps) caps = NULL;
    virCapsGuest *guest;

    if ((caps = virCapabilitiesNew(virArchFromHost(),
                                   false, false)) == NULL)
        return NULL;

    if (!(caps->host.numa = virCapabilitiesHostNUMANewHost()))
        return NULL;

    if (virCapabilitiesInitCaches(caps) < 0)
        return NULL;

    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM,
                                    caps->host.arch, NULL, NULL, 0, NULL);

    if (virFileExists("/dev/kvm")) {
        virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_KVM,
                                      NULL, NULL, 0, NULL);
    }

    if (virFileExists("/dev/mshv")) {
        virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_HYPERV,
                                      NULL, NULL, 0, NULL);
    }

    return g_steal_pointer(&caps);
}

int virCHDriverConfigLoadFile(virCHDriverConfig *cfg,
                              const char *filename)
{
    g_autoptr(virConf) conf = NULL;

    /* Just check the file is readable before opening it, otherwise
     * libvirt emits an error.
     */
    if (access(filename, R_OK) == -1) {
        VIR_INFO("Could not read ch config file %s", filename);
        return 0;
    }

    if (!(conf = virConfReadFile(filename, 0)))
        return -1;

    if (virConfGetValueUInt(conf, "log_level", &cfg->logLevel) < 0)
        return -1;

    if (!(cfg->logLevel < VIR_CH_LOGLEVEL_LAST)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Invalid log_level %1$u"),
                       cfg->logLevel);
        return -1;
    }

    return 0;
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
    virCaps *ret = NULL;
    virCaps *caps = NULL;

    if (refresh && !(caps = virCHDriverCapsInit()))
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
chDomainXMLConfInit(virCHDriver *driver)
{
    virCHDriverDomainDefParserConfig.priv = driver;
    return virDomainXMLOptionNew(&virCHDriverDomainDefParserConfig,
                                 &virCHDriverPrivateDataCallbacks,
                                 NULL, NULL, NULL, NULL);
}

virCHDriverConfig *
virCHDriverConfigNew(bool privileged)
{
    virCHDriverConfig *cfg;

    if (virCHConfigInitialize() < 0)
        return NULL;

    if (!(cfg = virObjectNew(virCHDriverConfigClass)))
        return NULL;

    cfg->cgroupControllers = -1; /* Auto detect */

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
        cfg->saveDir = g_strdup_printf("%s/lib/libvirt/ch/save", LOCALSTATEDIR);
        cfg->configDir = g_strdup(SYSCONFDIR "/libvirt");
    } else {
        g_autofree char *rundir = NULL;
        g_autofree char *cachedir = NULL;
        g_autofree char *configbasedir = NULL;

        cachedir = virGetUserCacheDirectory();

        cfg->logDir = g_strdup_printf("%s/ch/log", cachedir);

        rundir = virGetUserRuntimeDirectory();
        cfg->stateDir = g_strdup_printf("%s/ch/run", rundir);

        configbasedir = virGetUserConfigDirectory();
        cfg->saveDir = g_strdup_printf("%s/ch/save", configbasedir);
        cfg->configDir = g_strdup_printf("%s/ch", configbasedir);
    }

    return cfg;
}

virCHDriverConfig *virCHDriverGetConfig(virCHDriver *driver)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);
    return virObjectRef(driver->config);
}

static void
virCHDriverConfigDispose(void *obj)
{
    virCHDriverConfig *cfg = obj;

    g_free(cfg->stateDir);
    g_free(cfg->configDir);
    g_free(cfg->logDir);
    g_free(cfg->saveDir);
}

#define MIN_VERSION ((15 * 1000000) + (0 * 1000) + (0))

/**
 * chPreProcessVersionString:
 *
 * Returns: a pointer to numerical version without branch/commit info
 */
static char *
chPreProcessVersionString(char *version)
{
    char *tmp = strrchr(version, '/');

    if (tmp)
        version = tmp + 1;

    if (version[0] == 'v')
        version++;

    tmp = strchr(version, '-');
    if (tmp)
        *tmp = '\0';

    return version;
}

int
chExtractVersion(virCHDriver *driver)
{
    unsigned long long version;
    g_autofree char *help = NULL;
    char *tmp = NULL;
    g_autofree char *ch_cmd = g_find_program_in_path(CH_CMD);
    g_autoptr(virCommand) cmd = NULL;

    if (!ch_cmd)
        return -2;

    cmd = virCommandNewArgList(ch_cmd, "--version", NULL);
    virCommandAddEnvString(cmd, "LC_ALL=C");
    virCommandSetOutputBuffer(cmd, &help);

    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    tmp = help;

    /* Below are example version formats and expected outputs:
     *  cloud-hypervisor v32.0.0 (expected: 32.0.0)
     *  cloud-hypervisor v33.0-104-ge0e3779e-dirty (expected: 33.0)
     *  cloud-hypervisor testing/v32.0.131-1-ga5d6db5c-dirty (expected: 32.0.131)
     */
    if ((tmp = STRSKIP(tmp, "cloud-hypervisor ")) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unexpected output of cloud-hypervisor binary"));
        return -1;
    }

    tmp = chPreProcessVersionString(tmp);
    VIR_DEBUG("Cloud-Hypervisor version detected: %s", tmp);

    if (virStringParseVersion(&version, tmp, true) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse cloud-hypervisor version: %1$s"), tmp);
        return -1;
    }

    if (version < MIN_VERSION) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cloud-Hypervisor version is too old (v15.0 is the minimum supported version)"));
        return -1;
    }

    driver->version = version;
    return 0;
}
