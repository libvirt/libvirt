/*
 * virsecretobj.h: internal <secret> objects handling
 *
 * Copyright (C) 2009-2010, 2013-2014, 2016 Red Hat, Inc.
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

#include "internal.h"

#include "secret_conf.h"

typedef struct _virSecretObj virSecretObj;

void
virSecretObjEndAPI(virSecretObj **obj);

typedef struct _virSecretObjList virSecretObjList;

virSecretObjList *
virSecretObjListNew(void);

virSecretObj *
virSecretObjListFindByUUID(virSecretObjList *secrets,
                           const char *uuidstr);

virSecretObj *
virSecretObjListFindByUsage(virSecretObjList *secrets,
                            int usageType,
                            const char *usageID);

void
virSecretObjListRemove(virSecretObjList *secrets,
                       virSecretObj *obj);

virSecretObj *
virSecretObjListAdd(virSecretObjList *secrets,
                    virSecretDef **newdef,
                    const char *configDir,
                    virSecretDef **oldDef);

typedef bool
(*virSecretObjListACLFilter)(virConnectPtr conn,
                             virSecretDef *def);

int
virSecretObjListNumOfSecrets(virSecretObjList *secrets,
                             virSecretObjListACLFilter filter,
                             virConnectPtr conn);

int
virSecretObjListExport(virConnectPtr conn,
                       virSecretObjList *secretobjs,
                       virSecretPtr **secrets,
                       virSecretObjListACLFilter filter,
                       unsigned int flags);

int
virSecretObjListGetUUIDs(virSecretObjList *secrets,
                         char **uuids,
                         int maxuuids,
                         virSecretObjListACLFilter filter,
                         virConnectPtr conn);

int
virSecretObjDeleteConfig(virSecretObj *obj);

void
virSecretObjDeleteData(virSecretObj *obj);

int
virSecretObjSaveConfig(virSecretObj *obj);

int
virSecretObjSaveData(virSecretObj *obj);

virSecretDef *
virSecretObjGetDef(virSecretObj *obj);

void
virSecretObjSetDef(virSecretObj *obj,
                   virSecretDef *def);

unsigned char *
virSecretObjGetValue(virSecretObj *obj);

int
virSecretObjSetValue(virSecretObj *obj,
                     const unsigned char *value,
                     size_t value_size);

size_t
virSecretObjGetValueSize(virSecretObj *obj);

void
virSecretObjSetValueSize(virSecretObj *obj,
                         size_t value_size);

int
virSecretLoadAllConfigs(virSecretObjList *secrets,
                        const char *configDir);
