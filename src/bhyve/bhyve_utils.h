/*
 * bhyve_utils.h: bhyve utils
 *
 * Copyright (C) 2014 Roman Bogorodskiy
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

#pragma once

#include "driver.h"
#include "domain_event.h"
#include "configmake.h"
#include "virdomainobjlist.h"
#include "virthread.h"
#include "hypervisor/virclosecallbacks.h"
#include "virportallocator.h"

#define BHYVE_AUTOSTART_DIR    SYSCONFDIR "/libvirt/bhyve/autostart"
#define BHYVE_CONFIG_DIR       SYSCONFDIR "/libvirt/bhyve"
#define BHYVE_STATE_DIR        RUNSTATEDIR "/libvirt/bhyve"
#define BHYVE_LOG_DIR          LOCALSTATEDIR "/log/libvirt/bhyve"

typedef struct _virBhyveDriverConfig virBhyveDriverConfig;
struct _virBhyveDriverConfig {
    virObject parent;

    char *firmwareDir;
};

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virBhyveDriverConfig, virObjectUnref);

struct _bhyveConn {
    virMutex lock;

    struct _virBhyveDriverConfig *config;

    /* pid file FD, ensures two copies of the driver can't use the same root */
    int lockFD;

    virDomainObjList *domains;
    virCaps *caps;
    virDomainXMLOption *xmlopt;
    char *pidfile;
    virSysinfoDef *hostsysinfo;

    virObjectEventState *domainEventState;

    virPortAllocatorRange *remotePorts;

    unsigned bhyvecaps;
    unsigned grubcaps;
};

typedef struct _bhyveConn bhyveConn;

struct bhyveAutostartData {
    struct _bhyveConn *driver;
    virConnectPtr conn;
};
