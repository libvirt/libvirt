/*
 * Copyright (C) 2010, 2013 Red Hat, Inc.
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

# include "internal.h"
# include "libvirt_internal.h"
# include "domain_conf.h"
# include "domain_event.h"
# include "capabilities.h"
# include "virthread.h"
# include "security/security_manager.h"
# include "configmake.h"
# include "vircgroup.h"
# include "virsysinfo.h"
# include "virusb.h"
# include "virclosecallbacks.h"
# include "virhostdev.h"

# define LXC_DRIVER_NAME "LXC"

# define LXC_CONFIG_DIR SYSCONFDIR "/libvirt/lxc"
# define LXC_STATE_DIR LOCALSTATEDIR "/run/libvirt/lxc"
# define LXC_LOG_DIR LOCALSTATEDIR "/log/libvirt/lxc"
# define LXC_AUTOSTART_DIR LXC_CONFIG_DIR "/autostart"

typedef struct _virLXCDriver virLXCDriver;
typedef virLXCDriver *virLXCDriverPtr;

typedef struct _virLXCDriverConfig virLXCDriverConfig;
typedef virLXCDriverConfig *virLXCDriverConfigPtr;

struct _virLXCDriverConfig {
    virObject parent;

    char *configDir;
    char *autostartDir;
    char *stateDir;
    char *logDir;
    int log_libvirtd;
    int have_netns;

    char *securityDriverName;
    bool securityDefaultConfined;
    bool securityRequireConfined;
};

struct _virLXCDriver {
    virMutex lock;

    /* Require lock to get reference on 'config',
     * then lockless thereafter */
    virLXCDriverConfigPtr config;

    /* Require lock to get a reference on the object,
     * lockless access thereafter */
    virCapsPtr caps;

    /* Immutable pointer, Immutable object */
    virDomainXMLOptionPtr xmlopt;

    /* Immutable pointer, lockless APIs*/
    virSysinfoDefPtr hostsysinfo;

    /* Atomic inc/dec only */
    unsigned int nactive;

    /* Immutable pointers. Caller must provide locking */
    virStateInhibitCallback inhibitCallback;
    void *inhibitOpaque;

    /* Immutable pointer, self-locking APIs */
    virDomainObjListPtr domains;

    virHostdevManagerPtr hostdevMgr;

    /* Immutable pointer, self-locking APIs */
    virObjectEventStatePtr domainEventState;

    /* Immutable pointer. self-locking APIs */
    virSecurityManagerPtr securityManager;

    /* Immutable pointer, self-locking APIs */
    virCloseCallbacksPtr closeCallbacks;
};

virLXCDriverConfigPtr virLXCDriverConfigNew(void);
virLXCDriverConfigPtr virLXCDriverGetConfig(virLXCDriverPtr driver);
int virLXCLoadDriverConfig(virLXCDriverConfigPtr cfg,
                           const char *filename);
virCapsPtr virLXCDriverCapsInit(virLXCDriverPtr driver);
virCapsPtr virLXCDriverGetCapabilities(virLXCDriverPtr driver,
                                       bool refresh);
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
