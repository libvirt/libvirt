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
# include "conf/virdomainobjlist.h"
# include "conf/domain_event.h"
# include "virthread.h"

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

# define PARALLELS_DOMAIN_ROUTED_NETWORK_NAME   "Routed"
# define PARALLELS_DOMAIN_BRIDGED_NETWORK_NAME  "Bridged"

struct _vzConn {
    virMutex lock;

    /* Immutable pointer, self-locking APIs */
    virDomainObjListPtr domains;

    PRL_HANDLE server;
    virCapsPtr caps;
    virDomainXMLOptionPtr xmlopt;
    virObjectEventStatePtr domainEventState;
    const char *drivername;
};

typedef struct _vzConn vzConn;
typedef struct _vzConn *vzConnPtr;

struct _vzCountersCache {
    PRL_HANDLE stats;
    virCond cond;
    /* = -1 - unsubscribed
       > -1 - subscribed */
    int count;
};

typedef struct _vzCountersCache vzCountersCache;

struct vzDomObj {
    int id;
    char *home;
    PRL_HANDLE sdkdom;
    vzCountersCache cache;
};

typedef struct vzDomObj *vzDomObjPtr;

virDomainObjPtr vzDomObjFromDomain(virDomainPtr domain);
virDomainObjPtr vzDomObjFromDomainRef(virDomainPtr domain);

char * vzGetOutput(const char *binary, ...)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_SENTINEL;
void vzDriverLock(vzConnPtr driver);
void vzDriverUnlock(vzConnPtr driver);
virDomainObjPtr
vzNewDomain(vzConnPtr privconn,
            char *name,
            const unsigned char *uuid);

# define PARALLELS_BLOCK_STATS_FOREACH(OP)                              \
    OP(rd_req, VIR_DOMAIN_BLOCK_STATS_READ_REQ, "read_requests")        \
    OP(rd_bytes, VIR_DOMAIN_BLOCK_STATS_READ_BYTES, "read_total")       \
    OP(wr_req, VIR_DOMAIN_BLOCK_STATS_WRITE_REQ, "write_requests")      \
    OP(wr_bytes, VIR_DOMAIN_BLOCK_STATS_WRITE_BYTES, "write_total")

#endif
