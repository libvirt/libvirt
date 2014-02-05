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

    goto cleanup;

error:
    virDomainDefFree(vmdef);
    vmdef = NULL;

cleanup:
    virConfFree(properties);

    return vmdef;
}
