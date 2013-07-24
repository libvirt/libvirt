/*---------------------------------------------------------------------------*/
/*  Copyright (C) 2011-2013 SUSE LINUX Products GmbH, Nuernberg, Germany.
 *  Copyright (C) 2011 Univention GmbH.
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
/*---------------------------------------------------------------------------*/

#ifndef LIBXL_CONF_H
# define LIBXL_CONF_H

# include <libxl.h>

# include "internal.h"
# include "domain_conf.h"
# include "domain_event.h"
# include "capabilities.h"
# include "configmake.h"
# include "virportallocator.h"
# include "virobject.h"


# define LIBXL_VNC_PORT_MIN  5900
# define LIBXL_VNC_PORT_MAX  65535

# define LIBXL_CONFIG_DIR SYSCONFDIR "/libvirt/libxl"
# define LIBXL_AUTOSTART_DIR LIBXL_CONFIG_DIR "/autostart"
# define LIBXL_STATE_DIR LOCALSTATEDIR "/run/libvirt/libxl"
# define LIBXL_LOG_DIR LOCALSTATEDIR "/log/libvirt/libxl"
# define LIBXL_LIB_DIR LOCALSTATEDIR "/lib/libvirt/libxl"
# define LIBXL_SAVE_DIR LIBXL_LIB_DIR "/save"
# define LIBXL_BOOTLOADER_PATH BINDIR "/pygrub"


typedef struct _libxlDriverPrivate libxlDriverPrivate;
typedef libxlDriverPrivate *libxlDriverPrivatePtr;
struct _libxlDriverPrivate {
    virMutex lock;
    virCapsPtr caps;
    virDomainXMLOptionPtr xmlopt;
    unsigned int version;

    FILE *logger_file;
    xentoollog_logger *logger;
    /* libxl ctx for driver wide ops; getVersion, getNodeInfo, ... */
    libxl_ctx *ctx;

    virPortAllocatorPtr reservedVNCPorts;

    /* Controls automatic ballooning of domain0. If true, attempt to get
     * memory for new domains from domain0. */
    bool autoballoon;

    size_t nactive;
    virStateInhibitCallback inhibitCallback;
    void *inhibitOpaque;

    virDomainObjListPtr domains;

    virDomainEventStatePtr domainEventState;
    virSysinfoDefPtr hostsysinfo;

    char *configDir;
    char *autostartDir;
    char *logDir;
    char *stateDir;
    char *libDir;
    char *saveDir;
};

typedef struct _libxlEventHookInfo libxlEventHookInfo;
typedef libxlEventHookInfo *libxlEventHookInfoPtr;

typedef struct _libxlDomainObjPrivate libxlDomainObjPrivate;
typedef libxlDomainObjPrivate *libxlDomainObjPrivatePtr;
struct _libxlDomainObjPrivate {
    virObjectLockable parent;

    /* per domain libxl ctx */
    libxl_ctx *ctx;
    libxl_evgen_domain_death *deathW;

    /* list of libxl timeout registrations */
    libxlEventHookInfoPtr timerRegistrations;
};

# define LIBXL_SAVE_MAGIC "libvirt-xml\n \0 \r"
# define LIBXL_SAVE_VERSION 1

typedef struct _libxlSavefileHeader libxlSavefileHeader;
typedef libxlSavefileHeader *libxlSavefileHeaderPtr;
struct _libxlSavefileHeader {
    char magic[sizeof(LIBXL_SAVE_MAGIC)-1];
    uint32_t version;
    uint32_t xmlLen;
    /* 24 bytes used, pad up to 64 bytes */
    uint32_t unused[10];
};

virCapsPtr
libxlMakeCapabilities(libxl_ctx *ctx);

int
libxlMakeDisk(virDomainDiskDefPtr l_dev, libxl_device_disk *x_dev);
int
libxlMakeNic(virDomainNetDefPtr l_nic, libxl_device_nic *x_nic);
int
libxlMakeVfb(libxlDriverPrivatePtr driver,
             virDomainGraphicsDefPtr l_vfb, libxl_device_vfb *x_vfb);

int
libxlBuildDomainConfig(libxlDriverPrivatePtr driver,
                       virDomainObjPtr vm, libxl_domain_config *d_config);

#endif /* LIBXL_CONF_H */
