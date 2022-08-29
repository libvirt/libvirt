/*
 * Copyright (C) 2010, 2013 Red Hat, Inc.
 * Copyright IBM Corp. 2008
 *
 * lxc_conf.h: header file for linux container config functions
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

#pragma once

#include "internal.h"
#include "libvirt_internal.h"
#include "domain_event.h"
#include "virthread.h"
#include "security/security_manager.h"
#include "configmake.h"
#include "virsysinfo.h"
#include "virclosecallbacks.h"
#include "virhostdev.h"

#define LXC_DRIVER_NAME "LXC"

#define LXC_CONFIG_DIR SYSCONFDIR "/libvirt/lxc"
#define LXC_STATE_DIR RUNSTATEDIR "/libvirt/lxc"
#define LXC_LOG_DIR LOCALSTATEDIR "/log/libvirt/lxc"
#define LXC_AUTOSTART_DIR LXC_CONFIG_DIR "/autostart"

typedef struct _virLXCDriver virLXCDriver;

typedef struct _virLXCDriverConfig virLXCDriverConfig;
struct _virLXCDriverConfig {
    virObject parent;

    char *configDir;
    char *autostartDir;
    char *stateDir;
    char *logDir;
    bool log_libvirtd;
    int have_netns;

    char *securityDriverName;
    bool securityDefaultConfined;
    bool securityRequireConfined;
};

struct _virLXCDriver {
    virMutex lock;

    /* Require lock to get reference on 'config',
     * then lockless thereafter */
    virLXCDriverConfig *config;

    /* pid file FD, ensures two copies of the driver can't use the same root */
    int lockFD;

    /* Require lock to get a reference on the object,
     * lockless access thereafter */
    virCaps *caps;

    /* Immutable pointer, Immutable object */
    virDomainXMLOption *xmlopt;

    /* Immutable pointer, lockless APIs */
    virSysinfoDef *hostsysinfo;

    /* Atomic inc/dec only */
    unsigned int nactive;

    /* Immutable pointers. Caller must provide locking */
    virStateInhibitCallback inhibitCallback;
    void *inhibitOpaque;

    /* Immutable pointer, self-locking APIs */
    virDomainObjList *domains;

    virHostdevManager *hostdevMgr;

    /* Immutable pointer, self-locking APIs */
    virObjectEventState *domainEventState;

    /* Immutable pointer. self-locking APIs */
    virSecurityManager *securityManager;
};

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virLXCDriverConfig, virObjectUnref);

virLXCDriverConfig *virLXCDriverConfigNew(void);
virLXCDriverConfig *virLXCDriverGetConfig(virLXCDriver *driver);
int virLXCLoadDriverConfig(virLXCDriverConfig *cfg,
                           const char *filename);
virCaps *virLXCDriverCapsInit(virLXCDriver *driver);
virCaps *virLXCDriverGetCapabilities(virLXCDriver *driver,
                                       bool refresh);
virDomainXMLOption *lxcDomainXMLConfInit(virLXCDriver *driver,
                                           const char *defsecmodel);
