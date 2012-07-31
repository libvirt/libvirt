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
# include "util/threads.h"
# include "conf/domain_conf.h"
# include "conf/storage_conf.h"
# include "conf/domain_event.h"
# include "json.h"

struct _parallelsConn {
    virMutex lock;
    virDomainObjList domains;
    virStoragePoolObjList pools;
    virCapsPtr caps;
    virDomainEventStatePtr domainEventState;
};

typedef struct _parallelsConn parallelsConn;
typedef struct _parallelsConn *parallelsConnPtr;

struct parallelsDomObj {
    int id;
    char *uuid;
    char *os;
};

typedef struct parallelsDomObj *parallelsDomObjPtr;

int parallelsStorageRegister(void);

virJSONValuePtr parallelsParseOutput(const char *binary, ...)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_SENTINEL;
char * parallelsGetOutput(const char *binary, ...)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_SENTINEL;
int parallelsCmdRun(const char *binary, ...)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_SENTINEL;
char * parallelsAddFileExt(const char *path, const char *ext);
void parallelsDriverLock(parallelsConnPtr driver);
void parallelsDriverUnlock(parallelsConnPtr driver);
virStorageVolPtr parallelsStorageVolumeLookupByPathLocked(virConnectPtr conn,
                                                          const char *path);

#endif
