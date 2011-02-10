/*---------------------------------------------------------------------------*/
/*  Copyright (c) 2011 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 */
/*---------------------------------------------------------------------------*/

#ifndef LIBXL_CONF_H
# define LIBXL_CONF_H

# include <config.h>

# include <libxl.h>

# include "internal.h"
# include "domain_conf.h"
# include "capabilities.h"
# include "configmake.h"
# include "bitmap.h"


# define LIBXL_VNC_PORT_MIN  5900
# define LIBXL_VNC_PORT_MAX  65535

# define LIBXL_CONFIG_DIR SYSCONFDIR "/libvirt/libxl"
# define LIBXL_AUTOSTART_DIR LIBXL_CONFIG_DIR "/autostart"
# define LIBXL_STATE_DIR LOCALSTATEDIR "/run/libvirt/libxl"
# define LIBXL_LOG_DIR LOCALSTATEDIR "/log/libvirt/libxl"
# define LIBXL_LIB_DIR LOCALSTATEDIR "/lib/libvirt/libxl"
# define LIBXL_SAVE_DIR LIBXL_LIB_DIR "/save"


typedef struct _libxlDriverPrivate libxlDriverPrivate;
typedef libxlDriverPrivate *libxlDriverPrivatePtr;
struct _libxlDriverPrivate {
    virMutex lock;
    virCapsPtr caps;
    unsigned int version;

    FILE *logger_file;
    xentoollog_logger *logger;
    /* libxl ctx for driver wide ops; getVersion, getNodeInfo, ... */
    libxl_ctx ctx;

    virBitmapPtr reservedVNCPorts;
    virDomainObjList domains;

    char *configDir;
    char *autostartDir;
    char *logDir;
    char *stateDir;
    char *libDir;
    char *saveDir;
};

typedef struct _libxlDomainObjPrivate libxlDomainObjPrivate;
typedef libxlDomainObjPrivate *libxlDomainObjPrivatePtr;
struct _libxlDomainObjPrivate {
    /* per domain libxl ctx */
    libxl_ctx ctx;
    libxl_waiter *dWaiter;
    int waiterFD;
    int eventHdl;
};


# define libxlError(code, ...)                                     \
    virReportErrorHelper(NULL, VIR_FROM_LIBXL, code, __FILE__,     \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

virCapsPtr
libxlMakeCapabilities(libxl_ctx *ctx);

int
libxlBuildDomainConfig(libxlDriverPrivatePtr driver,
                       virDomainDefPtr def, libxl_domain_config *d_config);


#endif /* LIBXL_CONF_H */
