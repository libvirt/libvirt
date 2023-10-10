/*
 * Copyright Intel Corp. 2020-2021
 *
 * ch_conf.h: header file for Cloud-Hypervisor configuration
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

#include "virdomainobjlist.h"
#include "virthread.h"
#include "ch_capabilities.h"

#define CH_DRIVER_NAME "CH"
#define CH_CMD "cloud-hypervisor"

typedef struct _virCHDriver virCHDriver;

typedef struct _virCHDriverConfig virCHDriverConfig;

struct _virCHDriverConfig {
    GObject parent;

    char *stateDir;
    char *logDir;

    int cgroupControllers;

    uid_t user;
    gid_t group;
};

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virCHDriverConfig, virObjectUnref);

struct _virCHDriver
{
    virMutex lock;

    bool privileged;

    /* Require lock to get a reference on the object,
     * lockless access thereafter */
    virCaps *caps;

    /* Immutable pointer, Immutable object
     * Initialized once and reused as needed
     */
    virBitmap *chCaps;

    /* Immutable pointer, Immutable object */
    virDomainXMLOption *xmlopt;

    /* Immutable pointer, self-locking APIs */
    virDomainObjList *domains;

    /* Cloud-Hypervisor version */
    int version;

    /* Require lock to get reference on 'config',
     * then lockless thereafter */
    virCHDriverConfig *config;

    /* pid file FD, ensures two copies of the driver can't use the same root */
    int lockFD;
};

virCaps *virCHDriverCapsInit(void);
virCaps *virCHDriverGetCapabilities(virCHDriver *driver,
                                      bool refresh);
virDomainXMLOption *chDomainXMLConfInit(virCHDriver *driver);
virCHDriverConfig *virCHDriverConfigNew(bool privileged);
virCHDriverConfig *virCHDriverGetConfig(virCHDriver *driver);
int chExtractVersion(virCHDriver *driver);
