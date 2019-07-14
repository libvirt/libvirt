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

#pragma once

#include "internal.h"

#include "network_conf.h"
#include "virnetworkportdef.h"

typedef struct _virNetworkObj virNetworkObj;
typedef virNetworkObj *virNetworkObjPtr;

virNetworkObjPtr
virNetworkObjNew(void);

virNetworkDefPtr
virNetworkObjGetDef(virNetworkObjPtr obj);

void
virNetworkObjSetDef(virNetworkObjPtr obj,
                    virNetworkDefPtr def);

virNetworkDefPtr
virNetworkObjGetNewDef(virNetworkObjPtr obj);

bool
virNetworkObjIsActive(virNetworkObjPtr obj);

void
virNetworkObjSetActive(virNetworkObjPtr obj,
                       bool active);

bool
virNetworkObjIsPersistent(virNetworkObjPtr obj);

bool
virNetworkObjIsAutostart(virNetworkObjPtr obj);

void
virNetworkObjSetAutostart(virNetworkObjPtr obj,
                          bool autostart);

virMacMapPtr
virNetworkObjGetMacMap(virNetworkObjPtr obj);

pid_t
virNetworkObjGetDnsmasqPid(virNetworkObjPtr obj);

void
virNetworkObjSetDnsmasqPid(virNetworkObjPtr obj,
                           pid_t dnsmasqPid);

pid_t
virNetworkObjGetRadvdPid(virNetworkObjPtr obj);

void
virNetworkObjSetRadvdPid(virNetworkObjPtr obj,
                         pid_t radvdPid);

virBitmapPtr
virNetworkObjGetClassIdMap(virNetworkObjPtr obj);

unsigned long long
virNetworkObjGetFloorSum(virNetworkObjPtr obj);

void
virNetworkObjSetFloorSum(virNetworkObjPtr obj,
                         unsigned long long floor_sum);

void
virNetworkObjSetMacMap(virNetworkObjPtr obj,
                       virMacMapPtr macmap);

void
virNetworkObjUnrefMacMap(virNetworkObjPtr obj);

int
virNetworkObjMacMgrAdd(virNetworkObjPtr obj,
                       const char *dnsmasqStateDir,
                       const char *domain,
                       const virMacAddr *mac);

int
virNetworkObjMacMgrDel(virNetworkObjPtr obj,
                       const char *dnsmasqStateDir,
                       const char *domain,
                       const virMacAddr *mac);

void
virNetworkObjEndAPI(virNetworkObjPtr *net);

typedef struct _virNetworkObjList virNetworkObjList;
typedef virNetworkObjList *virNetworkObjListPtr;

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
                             bool live,
                             virNetworkXMLOptionPtr xmlopt);

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
virNetworkObjAddPort(virNetworkObjPtr net,
                     virNetworkPortDefPtr portdef,
                     const char *stateDir);

char *
virNetworkObjGetPortStatusDir(virNetworkObjPtr net,
                              const char *stateDir);

virNetworkPortDefPtr
virNetworkObjLookupPort(virNetworkObjPtr net,
                        const unsigned char *uuid);

int
virNetworkObjDeletePort(virNetworkObjPtr net,
                        const unsigned char *uuid,
                        const char *stateDir);

int
virNetworkObjDeleteAllPorts(virNetworkObjPtr net,
                            const char *stateDir);

typedef bool
(*virNetworkPortListFilter)(virConnectPtr conn,
                            virNetworkDefPtr def,
                            virNetworkPortDefPtr portdef);

int
virNetworkObjPortListExport(virNetworkPtr net,
                            virNetworkObjPtr obj,
                            virNetworkPortPtr **ports,
                            virNetworkPortListFilter filter);

int
virNetworkObjSaveStatus(const char *statusDir,
                        virNetworkObjPtr net,
                        virNetworkXMLOptionPtr xmlopt) ATTRIBUTE_RETURN_CHECK;

int
virNetworkObjLoadAllConfigs(virNetworkObjListPtr nets,
                            const char *configDir,
                            const char *autostartDir,
                            virNetworkXMLOptionPtr xmlopt);

int
virNetworkObjLoadAllState(virNetworkObjListPtr nets,
                          const char *stateDir,
                          virNetworkXMLOptionPtr xmlopt);

int
virNetworkObjDeleteConfig(const char *configDir,
                          const char *autostartDir,
                          virNetworkObjPtr net);

bool
virNetworkObjBridgeInUse(virNetworkObjListPtr nets,
                         const char *bridge,
                         const char *skipname);

int
virNetworkObjUpdate(virNetworkObjPtr obj,
                    unsigned int command, /* virNetworkUpdateCommand */
                    unsigned int section, /* virNetworkUpdateSection */
                    int parentIndex,
                    const char *xml,
                    virNetworkXMLOptionPtr xmlopt,
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
                          int maxnames,
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
