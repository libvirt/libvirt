/*
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifndef LXC_CONF_H
#define LXC_CONF_H

#include <config.h>

#include "internal.h"
#include "domain_conf.h"
#include "domain_event.h"
#include "capabilities.h"
#include "threads.h"
#include "cgroup.h"

#define LXC_CONFIG_DIR SYSCONF_DIR "/libvirt/lxc"
#define LXC_STATE_DIR LOCAL_STATE_DIR "/run/libvirt/lxc"
#define LXC_LOG_DIR LOCAL_STATE_DIR "/log/libvirt/lxc"
#define LXC_AUTOSTART_DIR LXC_CONFIG_DIR "/autostart"

typedef struct __lxc_driver lxc_driver_t;
struct __lxc_driver {
    virMutex lock;

    virCapsPtr caps;

    virCgroupPtr cgroup;
    virDomainObjList domains;
    char *configDir;
    char *autostartDir;
    char *stateDir;
    char *logDir;
    int log_libvirtd;
    int have_netns;

    /* An array of callbacks */
    virDomainEventCallbackListPtr domainEventCallbacks;
    virDomainEventQueuePtr domainEventQueue;
    int domainEventTimer;
    int domainEventDispatching;
};

int lxcLoadDriverConfig(lxc_driver_t *driver);
virCapsPtr lxcCapsInit(void);

#define lxcError(conn, dom, code, fmt...)                                    \
        virReportErrorHelper(conn, VIR_FROM_LXC, code, __FILE__,           \
                               __FUNCTION__, __LINE__, fmt)

#endif /* LXC_CONF_H */
