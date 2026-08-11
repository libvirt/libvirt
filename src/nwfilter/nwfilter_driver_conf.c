/*
 * Copyright (C) 2022 Red Hat, Inc.
 *
 * nwfilter_driver_conf.c: nwfilter.conf config file inspection
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

#include <config.h>
#include "configmake.h"
#include "datatypes.h"
#include "virlog.h"
#include "virerror.h"
#include "virfile.h"
#include "virutil.h"
#include "virfirewall.h" /* for binary names */
#include "nwfilter_driver_conf.h"


#define VIR_FROM_THIS VIR_FROM_NWFILTER

VIR_LOG_INIT("nwfilter.nwfilter_driver");

static virClass *virNWFilterDriverConfigClass;
static void virNWFilterDriverConfigDispose(void *obj);

static int
virNWFilterConfigOnceInit(void)
{
    if (!VIR_CLASS_NEW(virNWFilterDriverConfig, virClassForObject()))
        return -1;

    return 0;
}


VIR_ONCE_GLOBAL_INIT(virNWFilterConfig);


static int
virNWFilterLoadDriverConfig(virNWFilterDriverConfig *cfg,
                            const char *filename)
{
    g_autoptr(virConf) conf = NULL;
    g_autofree char *fwBackendStr = NULL;
    bool fwBackendSelected = false;
    size_t i;
    int fwBackends[] = {
        FIREWALL_BACKENDS
    };
    G_STATIC_ASSERT(G_N_ELEMENTS(fwBackends) > 0 &&
                    G_N_ELEMENTS(fwBackends) <= VIR_FIREWALL_BACKEND_LAST);
    int nFwBackends = G_N_ELEMENTS(fwBackends);

    if (access(filename, R_OK) == 0) {

        conf = virConfReadFile(filename, 0);
        if (!conf)
            return -1;

        /* use virConfGetValue*(conf, ...) functions to read any settings into cfg */

        if (virConfGetValueString(conf, "firewall_backend", &fwBackendStr) < 0)
            return -1;
        if (virConfGetValueBool(conf, "enable_trace", &cfg->firewallTracing) < 0)
            return -1;
        if (virConfGetValueBool(conf, "enable_counters", &cfg->ruleCounters) < 0)
            return -1;

        if (fwBackendStr) {
            fwBackends[0] = virFirewallBackendTypeFromString(fwBackendStr);
            nFwBackends = 1;

            if (fwBackends[0] < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unrecognized nwfilter_driver = '%1$s' set in nwfilter driver config file %2$s"),
                               fwBackendStr, filename);
                return -1;
            }
            VIR_DEBUG("nwfilter_driver setting requested from config file %s: '%s'",
                      filename, virFirewallBackendTypeToString(fwBackends[0]));
        }
    }

    for (i = 0; i < nFwBackends && !fwBackendSelected; i++) {
        switch ((virFirewallBackend)fwBackends[i]) {
        case VIR_FIREWALL_BACKEND_NONE:
            fwBackendSelected = true;
            break;

        case VIR_FIREWALL_BACKEND_IPTABLES: {
            g_autofree char *iptablesInPath = virFindFileInPath(IPTABLES);

            if (iptablesInPath)
                fwBackendSelected = true;
            break;
        }

        case VIR_FIREWALL_BACKEND_NFTABLES: {
            g_autofree char *nftablesInPath = virFindFileInPath(NFT);

            if (nftablesInPath)
                fwBackendSelected = true;
            break;
        }

        case VIR_FIREWALL_BACKEND_PF: {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("unsupported nwfilter driver PF"));
            return -1;
        }

        case VIR_FIREWALL_BACKEND_LAST:
            virReportEnumRangeError(virFirewallBackend, fwBackends[i]);
            return -1;
        }

        if (fwBackendSelected)
            cfg->firewallBackend = fwBackends[i];
    }

    if (fwBackendSelected) {
        VIR_INFO("using nwfilter_driver: '%s'",
                 virFirewallBackendTypeToString(cfg->firewallBackend));
        return 0;
    } else if (fwBackendStr) {
        /* the explicitly requested driver wasn't found - this is a failure */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("requested nwfilter_driver '%1$s' is not available"),
                       fwBackendStr);
        return -1;
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not find a usable nwfilter driver"));
        return -1;
    }
}


virNWFilterDriverConfig *
virNWFilterDriverConfigNew(bool privileged)
{
    g_autoptr(virNWFilterDriverConfig) cfg = NULL;
    g_autofree char *configdir = NULL;
    g_autofree char *configfile = NULL;

    if (virNWFilterConfigInitialize() < 0)
        return NULL;

    if (!(cfg = virObjectNew(virNWFilterDriverConfigClass)))
        return NULL;

    if (!privileged)
        return g_steal_pointer(&cfg);

    cfg->stateDir = g_strdup(RUNSTATEDIR "/libvirt/nwfilter");
    cfg->configDir = g_strdup(SYSCONFDIR "/libvirt/nwfilter");
    cfg->bindingDir = g_strdup(RUNSTATEDIR "/libvirt/nwfilter-binding");
    configfile = g_strdup(SYSCONFDIR "/libvirt/nwfilter.conf");

    if (virNWFilterLoadDriverConfig(cfg, configfile) < 0)
        return NULL;

    if (g_mkdir_with_parents(cfg->stateDir, S_IRWXU) < 0) {
        virReportSystemError(errno, _("cannot create state directory '%1$s'"),
                             cfg->stateDir);
        return NULL;
    }

    if (g_mkdir_with_parents(cfg->configDir, S_IRWXU) < 0) {
        virReportSystemError(errno, _("cannot create config directory '%1$s'"),
                             cfg->configDir);
        return NULL;
    }

    if (g_mkdir_with_parents(cfg->bindingDir, S_IRWXU) < 0) {
        virReportSystemError(errno, _("cannot create config directory '%1$s'"),
                             cfg->bindingDir);
        return NULL;
    }

    return g_steal_pointer(&cfg);
}


virNWFilterDriverConfig *
virNWFilterDriverGetConfig(virNWFilterDriverState *driver)
{
    return virObjectRef(driver->config);
}


static void
virNWFilterDriverConfigDispose(void *obj)
{
    virNWFilterDriverConfig *cfg = obj;

    g_free(cfg->stateDir);
    g_free(cfg->configDir);
    g_free(cfg->bindingDir);
}
