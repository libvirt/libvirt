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

virNetworkObj *
virNetworkObjNew(void);

virNetworkDef *
virNetworkObjGetDef(virNetworkObj *obj);

void
virNetworkObjSetDef(virNetworkObj *obj,
                    virNetworkDef *def);

virNetworkDef *
virNetworkObjGetNewDef(virNetworkObj *obj);

bool
virNetworkObjIsActive(virNetworkObj *obj);

void
virNetworkObjSetActive(virNetworkObj *obj,
                       bool active);

bool
virNetworkObjIsPersistent(virNetworkObj *obj);

bool
virNetworkObjIsAutostart(virNetworkObj *obj);

void
virNetworkObjSetAutostart(virNetworkObj *obj,
                          bool autostart);

virMacMap *
virNetworkObjGetMacMap(virNetworkObj *obj);

pid_t
virNetworkObjGetDnsmasqPid(virNetworkObj *obj);

void
virNetworkObjSetDnsmasqPid(virNetworkObj *obj,
                           pid_t dnsmasqPid);

virBitmap *
virNetworkObjGetClassIdMap(virNetworkObj *obj);

unsigned long long
virNetworkObjGetFloorSum(virNetworkObj *obj);

void
virNetworkObjSetFloorSum(virNetworkObj *obj,
                         unsigned long long floor_sum);

void
virNetworkObjSetMacMap(virNetworkObj *obj,
                       virMacMap **macmap);

void
virNetworkObjUnrefMacMap(virNetworkObj *obj);

int
virNetworkObjMacMgrAdd(virNetworkObj *obj,
                       const char *dnsmasqStateDir,
                       const char *domain,
                       const virMacAddr *mac);

int
virNetworkObjMacMgrDel(virNetworkObj *obj,
                       const char *dnsmasqStateDir,
                       const char *domain,
                       const virMacAddr *mac);

void
virNetworkObjEndAPI(virNetworkObj **net);

typedef struct _virNetworkObjList virNetworkObjList;

virNetworkObjList *
virNetworkObjListNew(void);

virNetworkObj *
virNetworkObjFindByUUID(virNetworkObjList *nets,
                        const unsigned char *uuid);

virNetworkObj *
virNetworkObjFindByName(virNetworkObjList *nets,
                        const char *name);

bool
virNetworkObjTaint(virNetworkObj *obj,
                   virNetworkTaintFlags taint);

typedef bool
(*virNetworkObjListFilter)(virConnectPtr conn,
                           virNetworkDef *def);

virNetworkObj *
virNetworkObjAssignDef(virNetworkObjList *nets,
                       virNetworkDef *def,
                       unsigned int flags);

void
virNetworkObjUpdateAssignDef(virNetworkObj *network,
                             virNetworkDef *def,
                             bool live);

int
virNetworkObjSetDefTransient(virNetworkObj *network,
                             bool live,
                             virNetworkXMLOption *xmlopt);

void
virNetworkObjUnsetDefTransient(virNetworkObj *network);

virNetworkDef *
virNetworkObjGetPersistentDef(virNetworkObj *network);

int
virNetworkObjReplacePersistentDef(virNetworkObj *network,
                                  virNetworkDef *def);

void
virNetworkObjRemoveInactive(virNetworkObjList *nets,
                            virNetworkObj *net);

int
virNetworkObjAddPort(virNetworkObj *net,
                     virNetworkPortDef *portdef,
                     const char *stateDir);

char *
virNetworkObjGetPortStatusDir(virNetworkObj *net,
                              const char *stateDir);

virNetworkPortDef *
virNetworkObjLookupPort(virNetworkObj *net,
                        const unsigned char *uuid);

int
virNetworkObjDeletePort(virNetworkObj *net,
                        const unsigned char *uuid,
                        const char *stateDir);

int
virNetworkObjDeleteAllPorts(virNetworkObj *net,
                            const char *stateDir);

typedef bool
(*virNetworkPortListFilter)(virConnectPtr conn,
                            virNetworkDef *def,
                            virNetworkPortDef *portdef);

int
virNetworkObjPortListExport(virNetworkPtr net,
                            virNetworkObj *obj,
                            virNetworkPortPtr **ports,
                            virNetworkPortListFilter filter);

typedef bool
(*virNetworkPortListIter)(virNetworkPortDef *portdef,
                          void *opaque);

int
virNetworkObjPortForEach(virNetworkObj *obj,
                         virNetworkPortListIter iter,
                         void *opaque);

int
virNetworkObjSaveStatus(const char *statusDir,
                        virNetworkObj *net,
                        virNetworkXMLOption *xmlopt) G_GNUC_WARN_UNUSED_RESULT;

int
virNetworkObjLoadAllConfigs(virNetworkObjList *nets,
                            const char *configDir,
                            const char *autostartDir,
                            virNetworkXMLOption *xmlopt);

int
virNetworkObjLoadAllState(virNetworkObjList *nets,
                          const char *stateDir,
                          virNetworkXMLOption *xmlopt);

int
virNetworkObjDeleteConfig(const char *configDir,
                          const char *autostartDir,
                          virNetworkObj *net);

bool
virNetworkObjBridgeInUse(virNetworkObjList *nets,
                         const char *bridge,
                         const char *skipname);

int
virNetworkObjUpdate(virNetworkObj *obj,
                    unsigned int command, /* virNetworkUpdateCommand */
                    unsigned int section, /* virNetworkUpdateSection */
                    int parentIndex,
                    const char *xml,
                    virNetworkXMLOption *xmlopt,
                    unsigned int flags);  /* virNetworkUpdateFlags */

int
virNetworkObjListExport(virConnectPtr conn,
                        virNetworkObjList *netobjs,
                        virNetworkPtr **nets,
                        virNetworkObjListFilter filter,
                        unsigned int flags);

typedef int
(*virNetworkObjListIterator)(virNetworkObj *net,
                             void *opaque);

int
virNetworkObjListForEach(virNetworkObjList *nets,
                         virNetworkObjListIterator callback,
                         void *opaque);

int
virNetworkObjListGetNames(virNetworkObjList *nets,
                          bool active,
                          char **names,
                          int maxnames,
                          virNetworkObjListFilter filter,
                          virConnectPtr conn);

int
virNetworkObjListNumOfNetworks(virNetworkObjList *nets,
                               bool active,
                               virNetworkObjListFilter filter,
                               virConnectPtr conn);

void
virNetworkObjListPrune(virNetworkObjList *nets,
                       unsigned int flags);

int
virNetworkObjUpdateModificationImpact(virNetworkObj *obj,
                                      unsigned int *flags);

char *
virNetworkObjGetMetadata(virNetworkObj *network,
                         int type,
                         const char *uri,
                         unsigned int flags);

int
virNetworkObjSetMetadata(virNetworkObj *network,
                         int type,
                         const char *metadata,
                         const char *key,
                         const char *uri,
                         virNetworkXMLOption *xmlopt,
                         const char *stateDir,
                         const char *configDir,
                         unsigned int flags);
