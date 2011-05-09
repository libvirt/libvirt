/*
 * Copyright (C) 2010 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

/* includes */
#include <config.h>

#include <sys/utsname.h>

#include "lxc_conf.h"
#include "nodeinfo.h"
#include "virterror_internal.h"
#include "conf.h"
#include "memory.h"
#include "logging.h"
#include "uuid.h"
#include "configmake.h"
#include "lxc_container.h"

#define VIR_FROM_THIS VIR_FROM_LXC

/* Functions */
virCapsPtr lxcCapsInit(void)
{
    struct utsname utsname;
    virCapsPtr caps;
    virCapsGuestPtr guest;
    const char *altArch;

    uname(&utsname);

    if ((caps = virCapabilitiesNew(utsname.machine,
                                   0, 0)) == NULL)
        goto error;

    /* Some machines have problematic NUMA toplogy causing
     * unexpected failures. We don't want to break the QEMU
     * driver in this scenario, so log errors & carry on
     */
    if (nodeCapsInitNUMA(caps) < 0) {
        virCapabilitiesFreeNUMAInfo(caps);
        VIR_WARN("Failed to query host NUMA topology, disabling NUMA capabilities");
    }

    if (virGetHostUUID(caps->host.host_uuid)) {
        lxcError(VIR_ERR_INTERNAL_ERROR,
                 "%s", _("cannot get the host uuid"));
        goto error;
    }

    /* XXX shouldn't 'borrow' KVM's prefix */
    virCapabilitiesSetMacPrefix(caps, (unsigned char []){ 0x52, 0x54, 0x00 });

    if ((guest = virCapabilitiesAddGuest(caps,
                                         "exe",
                                         utsname.machine,
                                         sizeof(void*) == 4 ? 32 : 64,
                                         LIBEXECDIR "/libvirt_lxc",
                                         NULL,
                                         0,
                                         NULL)) == NULL)
        goto error;

    if (virCapabilitiesAddGuestDomain(guest,
                                      "lxc",
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto error;

    /* On 64-bit hosts, we can use personality() to request a 32bit process */
    if ((altArch = lxcContainerGetAlt32bitArch(utsname.machine)) != NULL) {
        if ((guest = virCapabilitiesAddGuest(caps,
                                             "exe",
                                             altArch,
                                             32,
                                             LIBEXECDIR "/libvirt_lxc",
                                             NULL,
                                             0,
                                             NULL)) == NULL)
            goto error;

        if (virCapabilitiesAddGuestDomain(guest,
                                          "lxc",
                                          NULL,
                                          NULL,
                                          0,
                                          NULL) == NULL)
            goto error;
    }

    /* LXC Requires an emulator in the XML */
    virCapabilitiesSetEmulatorRequired(caps);

    return caps;

error:
    virCapabilitiesFree(caps);
    return NULL;
}

int lxcLoadDriverConfig(lxc_driver_t *driver)
{
    char *filename;
    virConfPtr conf;
    virConfValuePtr p;

    /* Set the container configuration directory */
    if ((driver->configDir = strdup(LXC_CONFIG_DIR)) == NULL)
        goto no_memory;
    if ((driver->stateDir = strdup(LXC_STATE_DIR)) == NULL)
        goto no_memory;
    if ((driver->logDir = strdup(LXC_LOG_DIR)) == NULL)
        goto no_memory;
    if ((driver->autostartDir = strdup(LXC_AUTOSTART_DIR)) == NULL)
        goto no_memory;


    if ((filename = strdup(SYSCONFDIR "/libvirt/lxc.conf")) == NULL)
        goto no_memory;

    /* Avoid error from non-existant or unreadable file. */
    if (access (filename, R_OK) == -1)
        goto done;
    conf = virConfReadFile(filename, 0);
    if (!conf)
        goto done;

    p = virConfGetValue(conf, "log_with_libvirtd");
    if (p) {
        if (p->type != VIR_CONF_LONG)
            VIR_WARN("lxcLoadDriverConfig: invalid setting: log_with_libvirtd");
        else
            driver->log_libvirtd = p->l;
    }

    virConfFree(conf);

done:
    VIR_FREE(filename);
    return 0;

no_memory:
    virReportOOMError();
    return -1;
}
