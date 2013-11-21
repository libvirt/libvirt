/*
 * parallels_utils.h: core driver functions for managing
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

# include "driver.h"
# include "conf/domain_conf.h"
# include "conf/storage_conf.h"
# include "conf/domain_event.h"
# include "conf/network_conf.h"
# include "virthread.h"
# include "virjson.h"

# define parallelsParseError()                                                 \
    virReportErrorHelper(VIR_FROM_TEST, VIR_ERR_OPERATION_FAILED, __FILE__,    \
                     __FUNCTION__, __LINE__, _("Can't parse prlctl output"))

# define PARALLELS_ROUTED_NETWORK_NAME   "Routed"

struct _parallelsConn {
    virMutex lock;
    virDomainObjListPtr domains;
    virStoragePoolObjList pools;
    virNetworkObjList networks;
    virCapsPtr caps;
    virDomainXMLOptionPtr xmlopt;
    virObjectEventStatePtr domainEventState;
};

typedef struct _parallelsConn parallelsConn;
typedef struct _parallelsConn *parallelsConnPtr;

struct parallelsDomObj {
    int id;
    char *uuid;
    char *home;
};

typedef struct parallelsDomObj *parallelsDomObjPtr;

int parallelsStorageRegister(void);
int parallelsNetworkRegister(void);

virJSONValuePtr parallelsParseOutput(const char *binary, ...)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_SENTINEL;
char * parallelsGetOutput(const char *binary, ...)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_SENTINEL;
int parallelsCmdRun(const char *binary, ...)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_SENTINEL;
char * parallelsAddFileExt(const char *path, const char *ext);
void parallelsDriverLock(parallelsConnPtr driver);
void parallelsDriverUnlock(parallelsConnPtr driver);
virStorageVolPtr parallelsStorageVolLookupByPathLocked(virConnectPtr conn,
                                                       const char *path);
int parallelsStorageVolDefRemove(virStoragePoolObjPtr privpool,
                                 virStorageVolDefPtr privvol);

#endif
