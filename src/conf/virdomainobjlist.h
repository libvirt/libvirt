/*
 * virdomainobjlist.h: domain objects list utilities
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
 * Copyright (C) 2006-2008 Daniel P. Berrange
 * Copyright (c) 2015 SUSE LINUX Products GmbH, Nuernberg, Germany.
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

#include "domain_conf.h"

typedef struct _virDomainObjList virDomainObjList;

virDomainObjList *
virDomainObjListNew(void);

virDomainObj *
virDomainObjListFindByID(virDomainObjList *doms,
                         int id);
virDomainObj *
virDomainObjListFindByUUID(virDomainObjList *doms,
                           const unsigned char *uuid);
virDomainObj *
virDomainObjListFindByName(virDomainObjList *doms,
                           const char *name);

enum {
    VIR_DOMAIN_OBJ_LIST_ADD_LIVE = (1 << 0),
    VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE = (1 << 1),
};
virDomainObj *
virDomainObjListAdd(virDomainObjList *doms,
                    virDomainDef **def,
                    virDomainXMLOption *xmlopt,
                    unsigned int flags,
                    virDomainDef **oldDef);

typedef int (*virDomainObjListRenameCallback)(virDomainObj *dom,
                                              const char *new_name,
                                              unsigned int flags,
                                              void *opaque);
int
virDomainObjListRename(virDomainObjList *doms,
                       virDomainObj *dom,
                       const char *new_name,
                       unsigned int flags,
                       virDomainObjListRenameCallback callback,
                       void *opaque);

void
virDomainObjListRemove(virDomainObjList *doms,
                       virDomainObj *dom);
void
virDomainObjListRemoveLocked(virDomainObjList *doms,
                             virDomainObj *dom);

int
virDomainObjListLoadAllConfigs(virDomainObjList *doms,
                               const char *configDir,
                               const char *autostartDir,
                               bool liveStatus,
                               virDomainXMLOption *xmlopt,
                               virDomainLoadConfigNotify notify,
                               void *opaque);

int
virDomainObjListNumOfDomains(virDomainObjList *doms,
                             bool active,
                             virDomainObjListACLFilter filter,
                             virConnectPtr conn);

int
virDomainObjListGetActiveIDs(virDomainObjList *doms,
                             int *ids,
                             int maxids,
                             virDomainObjListACLFilter filter,
                             virConnectPtr conn);
int
virDomainObjListGetInactiveNames(virDomainObjList *doms,
                                 char **const names,
                                 int maxnames,
                                 virDomainObjListACLFilter filter,
                                 virConnectPtr conn);

typedef int (*virDomainObjListIterator)(virDomainObj *dom,
                                        void *opaque);

int
virDomainObjListForEach(virDomainObjList *doms,
                        bool modify,
                        virDomainObjListIterator callback,
                        void *opaque);

#define VIR_CONNECT_LIST_DOMAINS_FILTERS_ACTIVE \
                (VIR_CONNECT_LIST_DOMAINS_ACTIVE | \
                 VIR_CONNECT_LIST_DOMAINS_INACTIVE)

#define VIR_CONNECT_LIST_DOMAINS_FILTERS_PERSISTENT \
                (VIR_CONNECT_LIST_DOMAINS_PERSISTENT | \
                 VIR_CONNECT_LIST_DOMAINS_TRANSIENT)

#define VIR_CONNECT_LIST_DOMAINS_FILTERS_STATE \
                (VIR_CONNECT_LIST_DOMAINS_RUNNING | \
                 VIR_CONNECT_LIST_DOMAINS_PAUSED  | \
                 VIR_CONNECT_LIST_DOMAINS_SHUTOFF | \
                 VIR_CONNECT_LIST_DOMAINS_OTHER)

#define VIR_CONNECT_LIST_DOMAINS_FILTERS_MANAGEDSAVE \
                (VIR_CONNECT_LIST_DOMAINS_MANAGEDSAVE | \
                 VIR_CONNECT_LIST_DOMAINS_NO_MANAGEDSAVE)

#define VIR_CONNECT_LIST_DOMAINS_FILTERS_AUTOSTART \
                (VIR_CONNECT_LIST_DOMAINS_AUTOSTART | \
                 VIR_CONNECT_LIST_DOMAINS_NO_AUTOSTART)

#define VIR_CONNECT_LIST_DOMAINS_FILTERS_SNAPSHOT \
                (VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT | \
                 VIR_CONNECT_LIST_DOMAINS_NO_SNAPSHOT)

#define VIR_CONNECT_LIST_DOMAINS_FILTERS_CHECKPOINT \
                (VIR_CONNECT_LIST_DOMAINS_HAS_CHECKPOINT | \
                 VIR_CONNECT_LIST_DOMAINS_NO_CHECKPOINT)

#define VIR_CONNECT_LIST_DOMAINS_FILTERS_ALL \
                (VIR_CONNECT_LIST_DOMAINS_FILTERS_ACTIVE      | \
                 VIR_CONNECT_LIST_DOMAINS_FILTERS_PERSISTENT  | \
                 VIR_CONNECT_LIST_DOMAINS_FILTERS_STATE       | \
                 VIR_CONNECT_LIST_DOMAINS_FILTERS_MANAGEDSAVE | \
                 VIR_CONNECT_LIST_DOMAINS_FILTERS_AUTOSTART   | \
                 VIR_CONNECT_LIST_DOMAINS_FILTERS_SNAPSHOT    | \
                 VIR_CONNECT_LIST_DOMAINS_FILTERS_CHECKPOINT)

void
virDomainObjListCollectAll(virDomainObjList *domlist,
                           virDomainObj ***vms,
                           size_t *nvms);
void
virDomainObjListCollect(virDomainObjList *doms,
                        virConnectPtr conn,
                        virDomainObj ***vms,
                        size_t *nvms,
                        virDomainObjListACLFilter filter,
                        unsigned int flags);
int
virDomainObjListExport(virDomainObjList *doms,
                       virConnectPtr conn,
                       virDomainPtr **domains,
                       virDomainObjListACLFilter filter,
                       unsigned int flags);
int
virDomainObjListConvert(virDomainObjList *domlist,
                        virConnectPtr conn,
                        virDomainPtr *doms,
                        size_t ndoms,
                        virDomainObj ***vms,
                        size_t *nvms,
                        virDomainObjListACLFilter filter,
                        unsigned int flags,
                        bool skip_missing);
