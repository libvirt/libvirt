/*
 * virsh.h: a shell to exercise the libvirt API
 *
 * Copyright (C) 2005, 2007-2016 Red Hat, Inc.
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
 * Daniel Veillard <veillard@redhat.com>
 * Karel Zak <kzak@redhat.com>
 * Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef VIRSH_H
# define VIRSH_H

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <stdarg.h>
# include <unistd.h>
# include <sys/stat.h>
# include <termios.h>

# include "internal.h"
# include "virerror.h"
# include "virthread.h"
# include "virpolkit.h"
# include "vsh.h"

# define VIRSH_PROMPT_RW    "virsh # "
# define VIRSH_PROMPT_RO    "virsh > "

# define VIR_FROM_THIS VIR_FROM_NONE

/*
 * Command group types
 */
# define VIRSH_CMD_GRP_DOM_MANAGEMENT   "Domain Management"
# define VIRSH_CMD_GRP_DOM_MONITORING   "Domain Monitoring"
# define VIRSH_CMD_GRP_STORAGE_POOL     "Storage Pool"
# define VIRSH_CMD_GRP_STORAGE_VOL      "Storage Volume"
# define VIRSH_CMD_GRP_NETWORK          "Networking"
# define VIRSH_CMD_GRP_NODEDEV          "Node Device"
# define VIRSH_CMD_GRP_IFACE            "Interface"
# define VIRSH_CMD_GRP_NWFILTER         "Network Filter"
# define VIRSH_CMD_GRP_SECRET           "Secret"
# define VIRSH_CMD_GRP_SNAPSHOT         "Snapshot"
# define VIRSH_CMD_GRP_HOST_AND_HV      "Host and Hypervisor"
# define VIRSH_CMD_GRP_VIRSH            "Virsh itself"

/*
 * Common command options
 */
# define VIRSH_COMMON_OPT_POOL(_helpstr)                          \
    {.name = "pool",                                              \
     .type = VSH_OT_DATA,                                         \
     .flags = VSH_OFLAG_REQ,                                      \
     .help = _helpstr                                             \
    }                                                             \

# define VIRSH_COMMON_OPT_DOMAIN(_helpstr)                        \
    {.name = "domain",                                            \
     .type = VSH_OT_DATA,                                         \
     .flags = VSH_OFLAG_REQ,                                      \
     .help = _helpstr                                             \
    }                                                             \

# define VIRSH_COMMON_OPT_CONFIG(_helpstr)                        \
    {.name = "config",                                            \
     .type = VSH_OT_BOOL,                                         \
     .help = _helpstr                                             \
    }                                                             \

# define VIRSH_COMMON_OPT_LIVE(_helpstr)                          \
    {.name = "live",                                              \
     .type = VSH_OT_BOOL,                                         \
     .help = _helpstr                                             \
    }                                                             \

# define VIRSH_COMMON_OPT_CURRENT(_helpstr)                       \
    {.name = "current",                                           \
     .type = VSH_OT_BOOL,                                         \
     .help = _helpstr                                             \
    }                                                             \

# define VIRSH_COMMON_OPT_FILE(_helpstr)                          \
    {.name = "file",                                              \
     .type = VSH_OT_DATA,                                         \
     .flags = VSH_OFLAG_REQ,                                      \
     .help = _helpstr                                             \
    }                                                             \

typedef struct _virshControl virshControl;
typedef virshControl *virshControlPtr;

typedef struct _virshCtrlData virshCtrlData;

/*
 * vshControl
 */
struct _virshControl {
    virConnectPtr conn;         /* connection to hypervisor (MAY BE NULL) */
    bool readonly;              /* connect readonly (first time only, not
                                 * during explicit connect command)
                                 */
    bool useGetInfo;            /* must use virDomainGetInfo, since
                                   virDomainGetState is not supported */
    bool useSnapshotOld;        /* cannot use virDomainSnapshotGetParent or
                                   virDomainSnapshotNumChildren */
    bool blockJobNoBytes;       /* true if _BANDWIDTH_BYTE blockjob flags
                                   are missing */
    const char *escapeChar;     /* String representation of
                                   console escape character */
};

/* Typedefs, function prototypes for job progress reporting.
 * There are used by some long lingering commands like
 * migrate, dump, save, managedsave.
 */
struct _virshCtrlData {
    vshControl *ctl;
    const vshCmd *cmd;
    int writefd;
    virConnectPtr dconn;
};

/* Filter flags for various vshCommandOpt*By() functions */
typedef enum {
    VIRSH_BYID   = (1 << 1),
    VIRSH_BYUUID = (1 << 2),
    VIRSH_BYNAME = (1 << 3),
    VIRSH_BYMAC  = (1 << 4),
} virshLookupByFlags;

virConnectPtr virshConnect(vshControl *ctl, const char *uri, bool readonly);

#endif /* VIRSH_H */
