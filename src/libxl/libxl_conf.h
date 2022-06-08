/*
 * libxl_conf.h: libxl configuration management
 *
 * Copyright (C) 2011-2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
 * Copyright (C) 2011 Univention GmbH.
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

#include <libxl.h>

#include "internal.h"
#include "libvirt_internal.h"
#include "virdomainobjlist.h"
#include "domain_event.h"
#include "configmake.h"
#include "virportallocator.h"
#include "virobject.h"
#include "virhostdev.h"
#include "locking/lock_manager.h"
#include "virfirmware.h"
#include "libxl_capabilities.h"
#include "libxl_logger.h"

#define LIBXL_DRIVER_EXTERNAL_NAME "Xen"
/*
 * We are stuck with the 'xenlight' name since it is used by the hostdev
 * manager. Changing it would break management of any host devices previously
 * managed under the name 'xenlight'.
 */
#define LIBXL_DRIVER_INTERNAL_NAME "xenlight"
#define LIBXL_VNC_PORT_MIN  5900
#define LIBXL_VNC_PORT_MAX  65535

#define LIBXL_MIGRATION_PORT_MIN  49152
#define LIBXL_MIGRATION_PORT_MAX  49216

#define LIBXL_CONFIG_BASE_DIR SYSCONFDIR "/libvirt"
#define LIBXL_CONFIG_DIR SYSCONFDIR "/libvirt/libxl"
#define LIBXL_AUTOSTART_DIR LIBXL_CONFIG_DIR "/autostart"
#define LIBXL_STATE_DIR RUNSTATEDIR "/libvirt/libxl"
#define LIBXL_LOG_DIR LOCALSTATEDIR "/log/libvirt/libxl"
#define LIBXL_LIB_DIR LOCALSTATEDIR "/lib/libvirt/libxl"
#define LIBXL_SAVE_DIR LIBXL_LIB_DIR "/save"
#define LIBXL_DUMP_DIR LIBXL_LIB_DIR "/dump"
#define LIBXL_CHANNEL_DIR LIBXL_LIB_DIR "/channel/target"
#define LIBXL_BOOTLOADER_PATH "pygrub"


typedef struct _libxlDriverPrivate libxlDriverPrivate;

typedef struct _libxlDriverConfig libxlDriverConfig;
struct _libxlDriverConfig {
    virObject parent;

    const libxl_version_info *verInfo;
    unsigned int version;

    /* log stream for driver-wide libxl ctx */
    libxlLogger *logger;
    /* libxl ctx for driver wide ops; getVersion, getNodeInfo, ... */
    libxl_ctx *ctx;

    /* Controls automatic ballooning of domain0. If true, attempt to get
     * memory for new domains from domain0. */
    bool autoballoon;

    char *lockManagerName;

    int keepAliveInterval;
    unsigned int keepAliveCount;

    bool nested_hvm;

    /* Once created, caps are immutable */
    virCaps *caps;

    char *configBaseDir;
    char *configDir;
    char *autostartDir;
    char *logDir;
    char *stateDir;
    char *libDir;
    char *saveDir;
    char *autoDumpDir;
    char *channelDir;

    virFirmware **firmwares;
    size_t nfirmwares;
};

G_DEFINE_AUTOPTR_CLEANUP_FUNC(libxlDriverConfig, virObjectUnref);


struct _libxlDriverPrivate {
    virMutex lock;

    virHostdevManager *hostdevMgr;
    /* Require lock to get reference on 'config',
     * then lockless thereafter */
    libxlDriverConfig *config;

    /* pid file FD, ensures two copies of the driver can't use the same root */
    int lockFD;

    /* Atomic inc/dec only */
    unsigned int nactive;

    /* Immutable pointers. Caller must provide locking */
    virStateInhibitCallback inhibitCallback;
    void *inhibitOpaque;

    /* Immutable pointer, self-locking APIs */
    virDomainObjList *domains;

    /* Immutable pointer, immutable object */
    virDomainXMLOption *xmlopt;

    /* Immutable pointer, self-locking APIs */
    virObjectEventState *domainEventState;

    /* Immutable pointer, immutable object */
    virPortAllocatorRange *reservedGraphicsPorts;

    /* Immutable pointer, immutable object */
    virPortAllocatorRange *migrationPorts;

    /* Immutable pointer, lockless APIs */
    virSysinfoDef *hostsysinfo;

    /* Immutable pointer. lockless access */
    virLockManagerPlugin *lockManager;
};

#define LIBXL_SAVE_MAGIC "libvirt-xml\n \0 \r"
#define LIBXL_SAVE_VERSION 2

typedef struct _libxlSavefileHeader libxlSavefileHeader;
struct _libxlSavefileHeader {
    char magic[sizeof(LIBXL_SAVE_MAGIC)-1];
    uint32_t version;
    uint32_t xmlLen;
    /* 24 bytes used, pad up to 64 bytes */
    uint32_t unused[10];
};


typedef struct _libxlDomainXmlNsDef libxlDomainXmlNsDef;
struct _libxlDomainXmlNsDef {
    size_t num_args;
    char **args;
};

libxlDriverConfig *
libxlDriverConfigNew(void);
int
libxlDriverConfigInit(libxlDriverConfig *cfg);

libxlDriverConfig *
libxlDriverConfigGet(libxlDriverPrivate *driver);

int
libxlDriverNodeGetInfo(libxlDriverPrivate *driver,
                       virNodeInfoPtr info);

int libxlDriverConfigLoadFile(libxlDriverConfig *cfg,
                              const char *filename);

int
libxlDriverGetDom0MaxmemConf(libxlDriverConfig *cfg,
                             unsigned long long *maxmem);

int
libxlMakeDisk(virDomainDiskDef *l_dev, libxl_device_disk *x_dev);

void
libxlUpdateDiskDef(virDomainDiskDef *l_dev, libxl_device_disk *x_dev);

int
libxlMakeNic(virDomainDef *def,
             virDomainNetDef *l_nic,
             libxl_device_nic *x_nic,
             bool attach);
int
libxlMakeVfb(virPortAllocatorRange *graphicsports,
             virDomainGraphicsDef *l_vfb, libxl_device_vfb *x_vfb);

int
libxlMakePCI(virDomainHostdevDef *hostdev, libxl_device_pci *pcidev);

int
libxlMakeUSBController(virDomainControllerDef *controller,
                       libxl_device_usbctrl *usbctrl);

int
libxlMakeUSB(virDomainHostdevDef *hostdev, libxl_device_usbdev *usbdev);

virDomainXMLOption *
libxlCreateXMLConf(libxlDriverPrivate *driver);

int
libxlBuildDomainConfig(virPortAllocatorRange *graphicsports,
                       virDomainDef *def,
                       libxlDriverConfig *cfg,
                       libxl_domain_config *d_config);
