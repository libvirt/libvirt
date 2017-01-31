/*
 * vz_utils.h: core driver functions for managing
 * Parallels Cloud Server hosts
 *
 * Copyright (C) 2012 Parallels, Inc.
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
 * License along with this library; If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#ifndef PARALLELS_UTILS_H
# define PARALLELS_UTILS_H

# include <Parallels.h>

# include "driver.h"
# include "conf/domain_conf.h"
# include "conf/snapshot_conf.h"
# include "conf/virdomainobjlist.h"
# include "conf/domain_event.h"
# include "virthread.h"
# include "datatypes.h"

# define vzParseError()                                                 \
    virReportErrorHelper(VIR_FROM_TEST, VIR_ERR_OPERATION_FAILED, __FILE__,    \
                         __FUNCTION__, __LINE__, _("Can't parse prlctl output"))

# define IS_CT(def)  (def->os.type == VIR_DOMAIN_OSTYPE_EXE)

# define vzDomNotFoundError(domain)                               \
    do {                                                                 \
        char uuidstr[VIR_UUID_STRING_BUFLEN];                            \
        virUUIDFormat(domain->uuid, uuidstr);                            \
        virReportError(VIR_ERR_NO_DOMAIN,                                \
                       _("no domain with matching uuid '%s'"), uuidstr); \
    } while (0)

# define PARALLELS_DOMAIN_ROUTED_NETWORK_NAME   "host-routed"
# define VIRTUOZZO_VER_7 ((unsigned long) 7000000)

struct _vzCapabilities {
    virStorageFileFormat vmDiskFormat;
    virStorageFileFormat ctDiskFormat;
    virDomainDiskBus *diskBuses;
    virDomainControllerType *controllerTypes;
    virDomainControllerModelSCSI scsiControllerModel;
};
typedef struct _vzCapabilities vzCapabilities;
typedef struct _vzCapabilities *vzCapabilitiesPtr;

/* +2 to keep enclosing { and } */
# define VIR_UUID_STRING_BRACED_BUFLEN (VIR_UUID_STRING_BUFLEN + 2)

struct _vzDriver {
    virObjectLockable parent;

    /* Immutable pointer, self-locking APIs */
    virDomainObjListPtr domains;
    unsigned char session_uuid[VIR_UUID_BUFLEN];
    PRL_HANDLE server;
    virCapsPtr caps;
    virDomainXMLOptionPtr xmlopt;
    virObjectEventStatePtr domainEventState;
    virSysinfoDefPtr hostsysinfo;
    unsigned long vzVersion;
    vzCapabilities vzCaps;
};

typedef struct _vzDriver vzDriver;
typedef struct _vzDriver *vzDriverPtr;

struct _vzConn {
    struct _vzConn* next;

    vzDriverPtr driver;
    /* Immutable pointer, self-locking APIs */
    virConnectCloseCallbackDataPtr closeCallback;
};

typedef struct _vzConn vzConn;
typedef struct _vzConn *vzConnPtr;

struct _vzDomainJobObj {
    virCond cond;
    bool active;
    /* when the job started, zeroed on time discontinuities */
    unsigned long long started;
    unsigned long long elapsed;
    bool hasProgress;
    int progress; /* percents */
    PRL_HANDLE sdkJob;
    bool cancelled;
};

typedef struct _vzDomainJobObj vzDomainJobObj;
typedef struct _vzDomainJobObj *vzDomainJobObjPtr;

struct vzDomObj {
    int id;
    PRL_HANDLE sdkdom;
    PRL_HANDLE stats;
    vzDomainJobObj job;
};

typedef struct vzDomObj *vzDomObjPtr;

void* vzDomObjAlloc(void);
void vzDomObjFree(void *p);

virDomainObjPtr vzDomObjFromDomain(virDomainPtr domain);
virDomainObjPtr vzDomObjFromDomainRef(virDomainPtr domain);

char * vzGetOutput(const char *binary, ...)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_SENTINEL;

vzDriverPtr
vzGetDriverConnection(void);

void
vzDestroyDriverConnection(void);

int
vzInitVersion(vzDriverPtr driver);
int
vzCheckUnsupportedDisk(const virDomainDef *def,
                       virDomainDiskDefPtr disk,
                       vzCapabilitiesPtr vzCaps);
int
vzCheckUnsupportedControllers(const virDomainDef *def,
                              vzCapabilitiesPtr vzCaps);
int
vzGetDefaultSCSIModel(vzDriverPtr driver,
                      PRL_CLUSTERED_DEVICE_SUBTYPE *scsiModel);

int vzCheckUnsupportedGraphics(virDomainGraphicsDefPtr gr);

# define PARALLELS_BLOCK_STATS_FOREACH(OP)                              \
    OP(rd_req, VIR_DOMAIN_BLOCK_STATS_READ_REQ, "read_requests")        \
    OP(rd_bytes, VIR_DOMAIN_BLOCK_STATS_READ_BYTES, "read_total")       \
    OP(wr_req, VIR_DOMAIN_BLOCK_STATS_WRITE_REQ, "write_requests")      \
    OP(wr_bytes, VIR_DOMAIN_BLOCK_STATS_WRITE_BYTES, "write_total")

#endif

int
vzDomainObjBeginJob(virDomainObjPtr dom);
void
vzDomainObjEndJob(virDomainObjPtr dom);
int
vzDomainJobUpdateTime(vzDomainJobObjPtr job);
