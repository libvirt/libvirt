/*
 * lxc_native.c: LXC native configuration import
 *
 * Copyright (c) 2013 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 * Author: Cedric Bosdonnat <cbosdonnat@suse.com>
 */

#include <config.h>

#include "internal.h"
#include "lxc_native.h"
#include "util/viralloc.h"
#include "util/virlog.h"
#include "util/virstring.h"
#include "util/virconf.h"

#define VIR_FROM_THIS VIR_FROM_LXC


static virDomainFSDefPtr
lxcCreateFSDef(int type,
               const char *src,
               const char* dst)
{
    virDomainFSDefPtr def;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    def->type = type;
    def->accessmode = VIR_DOMAIN_FS_ACCESSMODE_PASSTHROUGH;
    if (src && VIR_STRDUP(def->src, src) < 0)
        goto error;
    if (VIR_STRDUP(def->dst, dst) < 0)
        goto error;

    return def;

 error:
    virDomainFSDefFree(def);
    return NULL;
}

static int
lxcAddFSDef(virDomainDefPtr def,
            int type,
            const char *src,
            const char *dst)
{
    virDomainFSDefPtr fsDef = NULL;

    if (!(fsDef = lxcCreateFSDef(type, src, dst)))
        goto error;

    if (VIR_EXPAND_N(def->fss, def->nfss, 1) < 0)
        goto error;
    def->fss[def->nfss - 1] = fsDef;

    return 0;

error:
    virDomainFSDefFree(fsDef);
    return -1;
}

static int
lxcSetRootfs(virDomainDefPtr def,
             virConfPtr properties)
{
    int type = VIR_DOMAIN_FS_TYPE_MOUNT;
    virConfValuePtr value;

    if (!(value = virConfGetValue(properties, "lxc.rootfs")) ||
        !value->str) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Missing lxc.rootfs configuration"));
        return -1;
    }

    if (STRPREFIX(value->str, "/dev/"))
        type = VIR_DOMAIN_FS_TYPE_BLOCK;

    if (lxcAddFSDef(def, type, value->str, "/") < 0)
        return -1;

    return 0;
}

virDomainDefPtr
lxcParseConfigString(const char *config)
{
    virDomainDefPtr vmdef = NULL;
    virConfPtr properties = NULL;
    virConfValuePtr value;

    if (!(properties = virConfReadMem(config, 0, VIR_CONF_FLAG_LXC_FORMAT)))
        return NULL;

    if (VIR_ALLOC(vmdef) < 0)
        goto error;

    if (virUUIDGenerate(vmdef->uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to generate uuid"));
        goto error;
    }
    vmdef->id = -1;
    vmdef->mem.max_balloon = 64 * 1024;

    vmdef->onReboot = VIR_DOMAIN_LIFECYCLE_RESTART;
    vmdef->onCrash = VIR_DOMAIN_LIFECYCLE_DESTROY;
    vmdef->onPoweroff = VIR_DOMAIN_LIFECYCLE_DESTROY;
    vmdef->virtType = VIR_DOMAIN_VIRT_LXC;

    /* Value not handled by the LXC driver, setting to
     * minimum required to make XML parsing pass */
    vmdef->maxvcpus = 1;

    if (VIR_STRDUP(vmdef->os.type, "exe") < 0)
        goto error;

    if (VIR_STRDUP(vmdef->os.init, "/sbin/init") < 0)
        goto error;

    if (!(value = virConfGetValue(properties, "lxc.utsname")) ||
            !value->str || (VIR_STRDUP(vmdef->name, value->str) < 0))
        goto error;
    if (!vmdef->name && (VIR_STRDUP(vmdef->name, "unnamed") < 0))
        goto error;

    if (lxcSetRootfs(vmdef, properties) < 0)
        goto error;

    goto cleanup;

error:
    virDomainDefFree(vmdef);
    vmdef = NULL;

cleanup:
    virConfFree(properties);

    return vmdef;
}
