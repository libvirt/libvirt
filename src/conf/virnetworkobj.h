/*
 * virnetworkobj.h: handle network objects
 *                  (derived from network_conf.h)
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

#ifndef __VIRNETWORKOBJ_H__
# define __VIRNETWORKOBJ_H__

# include "internal.h"

# include "network_conf.h"

typedef struct _virNetworkObj virNetworkObj;
typedef virNetworkObj *virNetworkObjPtr;
struct _virNetworkObj {
    virObjectLockable parent;

    pid_t dnsmasqPid;
    pid_t radvdPid;
    unsigned int active : 1;
    unsigned int autostart : 1;
    unsigned int persistent : 1;

    virNetworkDefPtr def; /* The current definition */
    virNetworkDefPtr newDef; /* New definition to activate at shutdown */

    virBitmapPtr class_id; /* bitmap of class IDs for QoS */
    unsigned long long floor_sum; /* sum of all 'floor'-s of attached NICs */

    unsigned int taint;

    /* Immutable pointer, self locking APIs */
    virMacMapPtr macmap;
};

virNetworkObjPtr
virNetworkObjNew(void);

void
virNetworkObjEndAPI(virNetworkObjPtr *net);

typedef struct _virNetworkObjList virNetworkObjList;
typedef virNetworkObjList *virNetworkObjListPtr;

static inline int
virNetworkObjIsActive(const virNetworkObj *net)
{
    return net->active;
}

virNetworkObjListPtr
virNetworkObjListNew(void);

virNetworkObjPtr
virNetworkObjFindByUUID(virNetworkObjListPtr nets,
                        const unsigned char *uuid);

virNetworkObjPtr
virNetworkObjFindByName(virNetworkObjListPtr nets,
                        const char *name);

bool
virNetworkObjTaint(virNetworkObjPtr obj,
                   virNetworkTaintFlags taint);

typedef bool
(*virNetworkObjListFilter)(virConnectPtr conn,
                           virNetworkDefPtr def);

virNetworkObjPtr
virNetworkObjAssignDef(virNetworkObjListPtr nets,
                       virNetworkDefPtr def,
                       unsigned int flags);

void
virNetworkObjUpdateAssignDef(virNetworkObjPtr network,
                             virNetworkDefPtr def,
                             bool live);

int
virNetworkObjSetDefTransient(virNetworkObjPtr network,
                             bool live);

void
virNetworkObjUnsetDefTransient(virNetworkObjPtr network);

virNetworkDefPtr
virNetworkObjGetPersistentDef(virNetworkObjPtr network);

int
virNetworkObjReplacePersistentDef(virNetworkObjPtr network,
                                  virNetworkDefPtr def);

void
virNetworkObjRemoveInactive(virNetworkObjListPtr nets,
                            virNetworkObjPtr net);

int
virNetworkObjSaveStatus(const char *statusDir,
                        virNetworkObjPtr net) ATTRIBUTE_RETURN_CHECK;

int
virNetworkObjLoadAllConfigs(virNetworkObjListPtr nets,
                            const char *configDir,
                            const char *autostartDir);

int
virNetworkObjLoadAllState(virNetworkObjListPtr nets,
                          const char *stateDir);

int
virNetworkObjDeleteConfig(const char *configDir,
                          const char *autostartDir,
                          virNetworkObjPtr net);

int
virNetworkObjBridgeInUse(virNetworkObjListPtr nets,
                         const char *bridge,
                         const char *skipname);

int
virNetworkObjUpdate(virNetworkObjPtr obj,
                    unsigned int command, /* virNetworkUpdateCommand */
                    unsigned int section, /* virNetworkUpdateSection */
                    int parentIndex,
                    const char *xml,
                    unsigned int flags);  /* virNetworkUpdateFlags */

int
virNetworkObjListExport(virConnectPtr conn,
                        virNetworkObjListPtr netobjs,
                        virNetworkPtr **nets,
                        virNetworkObjListFilter filter,
                        unsigned int flags);

typedef int
(*virNetworkObjListIterator)(virNetworkObjPtr net,
                             void *opaque);

int
virNetworkObjListForEach(virNetworkObjListPtr nets,
                         virNetworkObjListIterator callback,
                         void *opaque);

int
virNetworkObjListGetNames(virNetworkObjListPtr nets,
                          bool active,
                          char **names,
                          int nnames,
                          virNetworkObjListFilter filter,
                          virConnectPtr conn);

int
virNetworkObjListNumOfNetworks(virNetworkObjListPtr nets,
                               bool active,
                               virNetworkObjListFilter filter,
                               virConnectPtr conn);

void
virNetworkObjListPrune(virNetworkObjListPtr nets,
                       unsigned int flags);

#endif /* __VIRNETWORKOBJ_H__ */
