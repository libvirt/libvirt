/*
 * qemu_block.h: helper functions for QEMU block subsystem
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

#include "qemu_conf.h"
#include "qemu_domain.h"

#include "virhash.h"
#include "virjson.h"
#include "viruri.h"

typedef struct qemuBlockNodeNameBackingChainData qemuBlockNodeNameBackingChainData;
typedef qemuBlockNodeNameBackingChainData *qemuBlockNodeNameBackingChainDataPtr;
struct qemuBlockNodeNameBackingChainData {
    char *qemufilename; /* name of the image from qemu */
    char *nodeformat;   /* node name of the format layer */
    char *nodestorage;  /* node name of the storage backing the format node */

    qemuBlockNodeNameBackingChainDataPtr backing;

    /* for testing purposes */
    char *drvformat;
    char *drvstorage;
};

virHashTablePtr
qemuBlockNodeNameGetBackingChain(virJSONValuePtr namednodesdata,
                                 virJSONValuePtr blockstats);

int
qemuBlockNodeNamesDetect(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         qemuDomainAsyncJob asyncJob);

virHashTablePtr
qemuBlockGetNodeData(virJSONValuePtr data);

bool
qemuBlockStorageSourceSupportsConcurrentAccess(virStorageSourcePtr src);

virJSONValuePtr
qemuBlockStorageSourceGetBackendProps(virStorageSourcePtr src,
                                      bool legacy,
                                      bool onlytarget,
                                      bool autoreadonly);

virURIPtr
qemuBlockStorageSourceGetURI(virStorageSourcePtr src);

virJSONValuePtr
qemuBlockStorageSourceGetBlockdevProps(virStorageSourcePtr src);

virJSONValuePtr
qemuBlockStorageGetCopyOnReadProps(virDomainDiskDefPtr disk);

typedef struct qemuBlockStorageSourceAttachData qemuBlockStorageSourceAttachData;
typedef qemuBlockStorageSourceAttachData *qemuBlockStorageSourceAttachDataPtr;
struct qemuBlockStorageSourceAttachData {
    virJSONValuePtr prmgrProps;
    char *prmgrAlias;

    virJSONValuePtr storageProps;
    const char *storageNodeName;
    bool storageAttached;

    virJSONValuePtr formatProps;
    const char *formatNodeName;
    bool formatAttached;

    char *driveCmd;
    char *driveAlias;
    bool driveAdded;

    virJSONValuePtr authsecretProps;
    char *authsecretAlias;

    virJSONValuePtr encryptsecretProps;
    char *encryptsecretAlias;

    virJSONValuePtr tlsProps;
    char *tlsAlias;
};


void
qemuBlockStorageSourceAttachDataFree(qemuBlockStorageSourceAttachDataPtr data);

VIR_DEFINE_AUTOPTR_FUNC(qemuBlockStorageSourceAttachData,
                        qemuBlockStorageSourceAttachDataFree);

qemuBlockStorageSourceAttachDataPtr
qemuBlockStorageSourceAttachPrepareBlockdev(virStorageSourcePtr src,
                                            bool autoreadonly);

qemuBlockStorageSourceAttachDataPtr
qemuBlockStorageSourceDetachPrepare(virStorageSourcePtr src,
                                    char *driveAlias);

int
qemuBlockStorageSourceAttachApply(qemuMonitorPtr mon,
                                  qemuBlockStorageSourceAttachDataPtr data);

void
qemuBlockStorageSourceAttachRollback(qemuMonitorPtr mon,
                                     qemuBlockStorageSourceAttachDataPtr data);

int
qemuBlockStorageSourceDetachOneBlockdev(virQEMUDriverPtr driver,
                                        virDomainObjPtr vm,
                                        qemuDomainAsyncJob asyncJob,
                                        virStorageSourcePtr src);

struct _qemuBlockStorageSourceChainData {
    qemuBlockStorageSourceAttachDataPtr *srcdata;
    size_t nsrcdata;
};

typedef struct _qemuBlockStorageSourceChainData qemuBlockStorageSourceChainData;
typedef qemuBlockStorageSourceChainData *qemuBlockStorageSourceChainDataPtr;

void
qemuBlockStorageSourceChainDataFree(qemuBlockStorageSourceChainDataPtr data);

qemuBlockStorageSourceChainDataPtr
qemuBlockStorageSourceChainDetachPrepareBlockdev(virStorageSourcePtr src);
qemuBlockStorageSourceChainDataPtr
qemuBlockStorageSourceChainDetachPrepareDrive(virStorageSourcePtr src,
                                              char *driveAlias);

int
qemuBlockStorageSourceChainAttach(qemuMonitorPtr mon,
                                  qemuBlockStorageSourceChainDataPtr data);

void
qemuBlockStorageSourceChainDetach(qemuMonitorPtr mon,
                                  qemuBlockStorageSourceChainDataPtr data);


VIR_DEFINE_AUTOPTR_FUNC(qemuBlockStorageSourceChainData,
                        qemuBlockStorageSourceChainDataFree);

int
qemuBlockSnapshotAddLegacy(virJSONValuePtr actions,
                           virDomainDiskDefPtr disk,
                           virStorageSourcePtr newsrc,
                           bool reuse);

int
qemuBlockStorageSourceCreateGetFormatProps(virStorageSourcePtr src,
                                           virStorageSourcePtr backing,
                                           virJSONValuePtr *props)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3) ATTRIBUTE_RETURN_CHECK;

int
qemuBlockStorageSourceCreateGetStorageProps(virStorageSourcePtr src,
                                            virJSONValuePtr *props)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
