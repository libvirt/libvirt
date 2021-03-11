/*
 * driver-storage.h: entry points for storage drivers
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
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

#ifndef __VIR_DRIVER_H_INCLUDES___
# error "Don't include this file directly, only use driver.h"
#endif

typedef int
(*virDrvConnectNumOfStoragePools)(virConnectPtr conn);

typedef int
(*virDrvConnectListStoragePools)(virConnectPtr conn,
                                 char **const names,
                                 int maxnames);

typedef int
(*virDrvConnectNumOfDefinedStoragePools)(virConnectPtr conn);

typedef int
(*virDrvConnectListDefinedStoragePools)(virConnectPtr conn,
                                        char **const names,
                                        int maxnames);

typedef int
(*virDrvConnectListAllStoragePools)(virConnectPtr conn,
                                    virStoragePoolPtr **pools,
                                    unsigned int flags);

typedef char *
(*virDrvConnectFindStoragePoolSources)(virConnectPtr conn,
                                       const char *type,
                                       const char *srcSpec,
                                       unsigned int flags);

typedef char *
(*virDrvConnectGetStoragePoolCapabilities)(virConnectPtr conn,
                                           unsigned int flags);

typedef virStoragePoolPtr
(*virDrvStoragePoolLookupByName)(virConnectPtr conn,
                                 const char *name);

typedef virStoragePoolPtr
(*virDrvStoragePoolLookupByUUID)(virConnectPtr conn,
                                 const unsigned char *uuid);

typedef virStoragePoolPtr
(*virDrvStoragePoolLookupByVolume)(virStorageVolPtr vol);

typedef virStoragePoolPtr
(*virDrvStoragePoolLookupByTargetPath)(virConnectPtr conn,
                                       const char *path);

typedef virStoragePoolPtr
(*virDrvStoragePoolCreateXML)(virConnectPtr conn,
                              const char *xmlDesc,
                              unsigned int flags);

typedef virStoragePoolPtr
(*virDrvStoragePoolDefineXML)(virConnectPtr conn,
                              const char *xmlDesc,
                              unsigned int flags);

typedef int
(*virDrvStoragePoolUndefine)(virStoragePoolPtr pool);

typedef int
(*virDrvStoragePoolBuild)(virStoragePoolPtr pool,
                          unsigned int flags);

typedef int
(*virDrvStoragePoolCreate)(virStoragePoolPtr pool,
                           unsigned int flags);

typedef int
(*virDrvStoragePoolDestroy)(virStoragePoolPtr pool);

typedef int
(*virDrvStoragePoolDelete)(virStoragePoolPtr pool,
                           unsigned int flags);

typedef int
(*virDrvStoragePoolRefresh)(virStoragePoolPtr pool,
                            unsigned int flags);

typedef int
(*virDrvStoragePoolGetInfo)(virStoragePoolPtr vol,
                            virStoragePoolInfoPtr info);

typedef char *
(*virDrvStoragePoolGetXMLDesc)(virStoragePoolPtr pool,
                               unsigned int flags);

typedef int
(*virDrvStoragePoolGetAutostart)(virStoragePoolPtr pool,
                                 int *autostart);

typedef int
(*virDrvStoragePoolSetAutostart)(virStoragePoolPtr pool,
                                 int autostart);

typedef int
(*virDrvStoragePoolNumOfVolumes)(virStoragePoolPtr pool);

typedef int
(*virDrvStoragePoolListVolumes)(virStoragePoolPtr pool,
                                char **const names,
                                int maxnames);

typedef int
(*virDrvStoragePoolListAllVolumes)(virStoragePoolPtr pool,
                                   virStorageVolPtr **vols,
                                   unsigned int flags);

typedef virStorageVolPtr
(*virDrvStorageVolLookupByName)(virStoragePoolPtr pool,
                                const char *name);

typedef virStorageVolPtr
(*virDrvStorageVolLookupByKey)(virConnectPtr pool,
                               const char *key);

typedef virStorageVolPtr
(*virDrvStorageVolLookupByPath)(virConnectPtr pool,
                                const char *path);

typedef virStorageVolPtr
(*virDrvStorageVolCreateXML)(virStoragePoolPtr pool,
                             const char *xmldesc,
                             unsigned int flags);

typedef int
(*virDrvStorageVolDelete)(virStorageVolPtr vol,
                          unsigned int flags);

typedef int
(*virDrvStorageVolWipe)(virStorageVolPtr vol,
                        unsigned int flags);

typedef int
(*virDrvStorageVolWipePattern)(virStorageVolPtr vol,
                               unsigned int algorithm,
                               unsigned int flags);

typedef int
(*virDrvStorageVolGetInfo)(virStorageVolPtr vol,
                           virStorageVolInfoPtr info);

typedef int
(*virDrvStorageVolGetInfoFlags)(virStorageVolPtr vol,
                                virStorageVolInfoPtr info,
                                unsigned int flags);

typedef char *
(*virDrvStorageVolGetXMLDesc)(virStorageVolPtr pool,
                              unsigned int flags);

typedef char *
(*virDrvStorageVolGetPath)(virStorageVolPtr vol);

typedef virStorageVolPtr
(*virDrvStorageVolCreateXMLFrom)(virStoragePoolPtr pool,
                                 const char *xmldesc,
                                 virStorageVolPtr clonevol,
                                 unsigned int flags);

typedef int
(*virDrvStorageVolDownload)(virStorageVolPtr vol,
                            virStreamPtr stream,
                            unsigned long long offset,
                            unsigned long long length,
                            unsigned int flags);

typedef int
(*virDrvStorageVolUpload)(virStorageVolPtr vol,
                          virStreamPtr stream,
                          unsigned long long offset,
                          unsigned long long length,
                          unsigned int flags);

typedef int
(*virDrvStorageVolResize)(virStorageVolPtr vol,
                          unsigned long long capacity,
                          unsigned int flags);

typedef int
(*virDrvStoragePoolIsActive)(virStoragePoolPtr pool);

typedef int
(*virDrvStoragePoolIsPersistent)(virStoragePoolPtr pool);

typedef int
(*virDrvConnectStoragePoolEventRegisterAny)(virConnectPtr conn,
                                            virStoragePoolPtr pool,
                                            int eventID,
                                            virConnectStoragePoolEventGenericCallback cb,
                                            void *opaque,
                                            virFreeCallback freecb);

typedef int
(*virDrvConnectStoragePoolEventDeregisterAny)(virConnectPtr conn,
                                              int callbackID);


typedef struct _virStorageDriver virStorageDriver;

/**
 * _virStorageDriver:
 *
 * Structure associated to a storage driver, defining the various
 * entry points for it.
 */
struct _virStorageDriver {
    const char *name; /* the name of the driver */
    virDrvConnectNumOfStoragePools connectNumOfStoragePools;
    virDrvConnectListStoragePools connectListStoragePools;
    virDrvConnectNumOfDefinedStoragePools connectNumOfDefinedStoragePools;
    virDrvConnectListDefinedStoragePools connectListDefinedStoragePools;
    virDrvConnectListAllStoragePools connectListAllStoragePools;
    virDrvConnectFindStoragePoolSources connectFindStoragePoolSources;
    virDrvConnectStoragePoolEventRegisterAny connectStoragePoolEventRegisterAny;
    virDrvConnectStoragePoolEventDeregisterAny connectStoragePoolEventDeregisterAny;
    virDrvConnectGetStoragePoolCapabilities connectGetStoragePoolCapabilities;
    virDrvStoragePoolLookupByName storagePoolLookupByName;
    virDrvStoragePoolLookupByUUID storagePoolLookupByUUID;
    virDrvStoragePoolLookupByVolume storagePoolLookupByVolume;
    virDrvStoragePoolLookupByTargetPath storagePoolLookupByTargetPath;
    virDrvStoragePoolCreateXML storagePoolCreateXML;
    virDrvStoragePoolDefineXML storagePoolDefineXML;
    virDrvStoragePoolBuild storagePoolBuild;
    virDrvStoragePoolUndefine storagePoolUndefine;
    virDrvStoragePoolCreate storagePoolCreate;
    virDrvStoragePoolDestroy storagePoolDestroy;
    virDrvStoragePoolDelete storagePoolDelete;
    virDrvStoragePoolRefresh storagePoolRefresh;
    virDrvStoragePoolGetInfo storagePoolGetInfo;
    virDrvStoragePoolGetXMLDesc storagePoolGetXMLDesc;
    virDrvStoragePoolGetAutostart storagePoolGetAutostart;
    virDrvStoragePoolSetAutostart storagePoolSetAutostart;
    virDrvStoragePoolNumOfVolumes storagePoolNumOfVolumes;
    virDrvStoragePoolListVolumes storagePoolListVolumes;
    virDrvStoragePoolListAllVolumes storagePoolListAllVolumes;
    virDrvStorageVolLookupByName storageVolLookupByName;
    virDrvStorageVolLookupByKey storageVolLookupByKey;
    virDrvStorageVolLookupByPath storageVolLookupByPath;
    virDrvStorageVolCreateXML storageVolCreateXML;
    virDrvStorageVolCreateXMLFrom storageVolCreateXMLFrom;
    virDrvStorageVolDownload storageVolDownload;
    virDrvStorageVolUpload storageVolUpload;
    virDrvStorageVolDelete storageVolDelete;
    virDrvStorageVolWipe storageVolWipe;
    virDrvStorageVolWipePattern storageVolWipePattern;
    virDrvStorageVolGetInfo storageVolGetInfo;
    virDrvStorageVolGetInfoFlags storageVolGetInfoFlags;
    virDrvStorageVolGetXMLDesc storageVolGetXMLDesc;
    virDrvStorageVolGetPath storageVolGetPath;
    virDrvStorageVolResize storageVolResize;
    virDrvStoragePoolIsActive storagePoolIsActive;
    virDrvStoragePoolIsPersistent storagePoolIsPersistent;
};
