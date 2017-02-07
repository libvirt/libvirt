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
 *
 * Authors:
 *     Jim Fehlig <jfehlig@novell.com>
 *     Markus Groß <gross@univention.de>
 */

#ifndef LIBXL_CONF_H
# define LIBXL_CONF_H

# include <libxl.h>

# include "internal.h"
# include "libvirt_internal.h"
# include "virdomainobjlist.h"
# include "domain_event.h"
# include "capabilities.h"
# include "configmake.h"
# include "virportallocator.h"
# include "virobject.h"
# include "virchrdev.h"
# include "virhostdev.h"
# include "locking/lock_manager.h"
# include "virfirmware.h"
# include "libxl_capabilities.h"
# include "libxl_logger.h"

# define LIBXL_DRIVER_NAME "xenlight"
# define LIBXL_VNC_PORT_MIN  5900
# define LIBXL_VNC_PORT_MAX  65535

# define LIBXL_MIGRATION_PORT_MIN  49152
# define LIBXL_MIGRATION_PORT_MAX  49216

# define LIBXL_CONFIG_BASE_DIR SYSCONFDIR "/libvirt"
# define LIBXL_CONFIG_DIR SYSCONFDIR "/libvirt/libxl"
# define LIBXL_AUTOSTART_DIR LIBXL_CONFIG_DIR "/autostart"
# define LIBXL_STATE_DIR LOCALSTATEDIR "/run/libvirt/libxl"
# define LIBXL_LOG_DIR LOCALSTATEDIR "/log/libvirt/libxl"
# define LIBXL_LIB_DIR LOCALSTATEDIR "/lib/libvirt/libxl"
# define LIBXL_SAVE_DIR LIBXL_LIB_DIR "/save"
# define LIBXL_DUMP_DIR LIBXL_LIB_DIR "/dump"
# define LIBXL_CHANNEL_DIR LIBXL_LIB_DIR "/channel/target"
# define LIBXL_BOOTLOADER_PATH "pygrub"


typedef struct _libxlDriverPrivate libxlDriverPrivate;
typedef libxlDriverPrivate *libxlDriverPrivatePtr;

typedef struct _libxlDriverConfig libxlDriverConfig;
typedef libxlDriverConfig *libxlDriverConfigPtr;

struct _libxlDriverConfig {
    virObject parent;

    const libxl_version_info *verInfo;
    unsigned int version;

    /* log stream for driver-wide libxl ctx */
    libxlLoggerPtr logger;
    /* libxl ctx for driver wide ops; getVersion, getNodeInfo, ... */
    libxl_ctx *ctx;

    /* Controls automatic ballooning of domain0. If true, attempt to get
     * memory for new domains from domain0. */
    bool autoballoon;

    char *lockManagerName;

    int keepAliveInterval;
    unsigned int keepAliveCount;

    /* Once created, caps are immutable */
    virCapsPtr caps;

    char *configBaseDir;
    char *configDir;
    char *autostartDir;
    char *logDir;
    char *stateDir;
    char *libDir;
    char *saveDir;
    char *autoDumpDir;
    char *channelDir;

    virFirmwarePtr *firmwares;
    size_t nfirmwares;
};


struct _libxlDriverPrivate {
    virMutex lock;

    virHostdevManagerPtr hostdevMgr;
    /* Require lock to get reference on 'config',
     * then lockless thereafter */
    libxlDriverConfigPtr config;

    /* Atomic inc/dec only */
    unsigned int nactive;

    /* Immutable pointers. Caller must provide locking */
    virStateInhibitCallback inhibitCallback;
    void *inhibitOpaque;

    /* Immutable pointer, self-locking APIs */
    virDomainObjListPtr domains;

    /* Immutable pointer, immutable object */
    virDomainXMLOptionPtr xmlopt;

    /* Immutable pointer, self-locking APIs */
    virObjectEventStatePtr domainEventState;

    /* Immutable pointer, self-locking APIs */
    virPortAllocatorPtr reservedGraphicsPorts;

    /* Immutable pointer, self-locking APIs */
    virPortAllocatorPtr migrationPorts;

    /* Immutable pointer, lockless APIs*/
    virSysinfoDefPtr hostsysinfo;

    /* Immutable pointer. lockless access */
    virLockManagerPluginPtr lockManager;
};

# define LIBXL_SAVE_MAGIC "libvirt-xml\n \0 \r"
# ifdef LIBXL_HAVE_SRM_V2
#  define LIBXL_SAVE_VERSION 2
# else
#  define LIBXL_SAVE_VERSION 1
# endif

typedef struct _libxlSavefileHeader libxlSavefileHeader;
typedef libxlSavefileHeader *libxlSavefileHeaderPtr;
struct _libxlSavefileHeader {
    char magic[sizeof(LIBXL_SAVE_MAGIC)-1];
    uint32_t version;
    uint32_t xmlLen;
    /* 24 bytes used, pad up to 64 bytes */
    uint32_t unused[10];
};

libxlDriverConfigPtr
libxlDriverConfigNew(void);

libxlDriverConfigPtr
libxlDriverConfigGet(libxlDriverPrivatePtr driver);

int
libxlDriverNodeGetInfo(libxlDriverPrivatePtr driver,
                       virNodeInfoPtr info);

int libxlDriverConfigLoadFile(libxlDriverConfigPtr cfg,
                              const char *filename);

int
libxlMakeDisk(virDomainDiskDefPtr l_dev, libxl_device_disk *x_dev);

void
libxlUpdateDiskDef(virDomainDiskDefPtr l_dev, libxl_device_disk *x_dev);

int
libxlMakeNic(virDomainDefPtr def,
             virDomainNetDefPtr l_nic,
             libxl_device_nic *x_nic,
             bool attach);
int
libxlMakeVfb(virPortAllocatorPtr graphicsports,
             virDomainGraphicsDefPtr l_vfb, libxl_device_vfb *x_vfb);

int
libxlMakePCI(virDomainHostdevDefPtr hostdev, libxl_device_pci *pcidev);

# ifdef LIBXL_HAVE_PVUSB
int
libxlMakeUSBController(virDomainControllerDefPtr controller,
                       libxl_device_usbctrl *usbctrl);

int
libxlMakeUSB(virDomainHostdevDefPtr hostdev, libxl_device_usbdev *usbdev);
# endif

virDomainXMLOptionPtr
libxlCreateXMLConf(void);

# ifdef LIBXL_HAVE_DEVICE_CHANNEL
#  define LIBXL_ATTR_UNUSED
# else
#  define LIBXL_ATTR_UNUSED ATTRIBUTE_UNUSED
# endif
int
libxlBuildDomainConfig(virPortAllocatorPtr graphicsports,
                       virDomainDefPtr def,
                       const char *channelDir LIBXL_ATTR_UNUSED,
                       libxl_ctx *ctx,
                       libxl_domain_config *d_config);

static inline void
libxlDriverLock(libxlDriverPrivatePtr driver)
{
    virMutexLock(&driver->lock);
}

static inline void
libxlDriverUnlock(libxlDriverPrivatePtr driver)
{
    virMutexUnlock(&driver->lock);
}

#endif /* LIBXL_CONF_H */
