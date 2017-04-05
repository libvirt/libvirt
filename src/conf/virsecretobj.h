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

#ifndef __VIRSECRETOBJ_H__
# define __VIRSECRETOBJ_H__

# include "internal.h"

# include "secret_conf.h"
# include "virobject.h"

typedef struct _virSecretObj virSecretObj;
typedef virSecretObj *virSecretObjPtr;

void
virSecretObjEndAPI(virSecretObjPtr *secret);

typedef struct _virSecretObjList virSecretObjList;
typedef virSecretObjList *virSecretObjListPtr;

virSecretObjListPtr
virSecretObjListNew(void);

virSecretObjPtr
virSecretObjListFindByUUID(virSecretObjListPtr secrets,
                           const unsigned char *uuid);

virSecretObjPtr
virSecretObjListFindByUsage(virSecretObjListPtr secrets,
                            int usageType,
                            const char *usageID);

void
virSecretObjListRemove(virSecretObjListPtr secrets,
                       virSecretObjPtr secret);

virSecretObjPtr
virSecretObjListAdd(virSecretObjListPtr secrets,
                    virSecretDefPtr def,
                    const char *configDir,
                    virSecretDefPtr *oldDef);

typedef bool
(*virSecretObjListACLFilter)(virConnectPtr conn,
                             virSecretDefPtr def);

int
virSecretObjListNumOfSecrets(virSecretObjListPtr secrets,
                             virSecretObjListACLFilter filter,
                             virConnectPtr conn);

int
virSecretObjListExport(virConnectPtr conn,
                       virSecretObjListPtr secretobjs,
                       virSecretPtr **secrets,
                       virSecretObjListACLFilter filter,
                       unsigned int flags);

int
virSecretObjListGetUUIDs(virSecretObjListPtr secrets,
                         char **uuids,
                         int nuuids,
                         virSecretObjListACLFilter filter,
                         virConnectPtr conn);

int
virSecretObjDeleteConfig(virSecretObjPtr secret);

void
virSecretObjDeleteData(virSecretObjPtr secret);

int
virSecretObjSaveConfig(virSecretObjPtr secret);

int
virSecretObjSaveData(virSecretObjPtr secret);

virSecretDefPtr
virSecretObjGetDef(virSecretObjPtr secret);

void
virSecretObjSetDef(virSecretObjPtr secret,
                   virSecretDefPtr def);

unsigned char *
virSecretObjGetValue(virSecretObjPtr secret);

int
virSecretObjSetValue(virSecretObjPtr secret,
                     const unsigned char *value,
                     size_t value_size);

size_t
virSecretObjGetValueSize(virSecretObjPtr secret);

void
virSecretObjSetValueSize(virSecretObjPtr secret,
                         size_t value_size);

int
virSecretLoadAllConfigs(virSecretObjListPtr secrets,
                        const char *configDir);

#endif /* __VIRSECRETOBJ_H__ */
