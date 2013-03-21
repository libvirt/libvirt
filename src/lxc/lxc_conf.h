/*
 * Copyright (C) 2010 Red Hat, Inc.
 * Copyright IBM Corp. 2008
 *
 * lxc_conf.h: header file for linux container config functions
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
 */

#ifndef LXC_CONF_H
# define LXC_CONF_H

# include <config.h>

# include "internal.h"
# include "domain_conf.h"
# include "domain_event.h"
# include "capabilities.h"
# include "virthread.h"
# include "security/security_manager.h"
# include "configmake.h"
# include "vircgroup.h"
# include "virsysinfo.h"
# include "virusb.h"

# define LXC_DRIVER_NAME "LXC"

# define LXC_CONFIG_DIR SYSCONFDIR "/libvirt/lxc"
# define LXC_STATE_DIR LOCALSTATEDIR "/run/libvirt/lxc"
# define LXC_LOG_DIR LOCALSTATEDIR "/log/libvirt/lxc"
# define LXC_AUTOSTART_DIR LXC_CONFIG_DIR "/autostart"

typedef struct _virLXCDriver virLXCDriver;
typedef virLXCDriver *virLXCDriverPtr;

struct _virLXCDriver {
    virMutex lock;

    virCapsPtr caps;
    virDomainXMLOptionPtr xmlopt;

    virCgroupPtr cgroup;

    virSysinfoDefPtr hostsysinfo;

    size_t nactive;
    virStateInhibitCallback inhibitCallback;
    void *inhibitOpaque;

    virDomainObjListPtr domains;
    char *configDir;
    char *autostartDir;
    char *stateDir;
    char *logDir;
    int log_libvirtd;
    int have_netns;

    virUSBDeviceListPtr activeUsbHostdevs;

    virDomainEventStatePtr domainEventState;

    char *securityDriverName;
    bool securityDefaultConfined;
    bool securityRequireConfined;
    virSecurityManagerPtr securityManager;

    /* Mapping of 'char *uuidstr' -> virConnectPtr
     * of guests which will be automatically killed
     * when the virConnectPtr is closed*/
    virHashTablePtr autodestroy;
};

int lxcLoadDriverConfig(virLXCDriverPtr driver);
virCapsPtr lxcCapsInit(virLXCDriverPtr driver);
virDomainXMLOptionPtr lxcDomainXMLConfInit(void);

static inline void lxcDriverLock(virLXCDriverPtr driver)
{
    virMutexLock(&driver->lock);
}
static inline void lxcDriverUnlock(virLXCDriverPtr driver)
{
    virMutexUnlock(&driver->lock);
}

#endif /* LXC_CONF_H */
