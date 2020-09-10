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

typedef enum {
    QEMU_BLOCK_STORAGE_SOURCE_BACKEND_PROPS_LEGACY = 1 << 0,
    QEMU_BLOCK_STORAGE_SOURCE_BACKEND_PROPS_TARGET_ONLY = 1 << 1,
    QEMU_BLOCK_STORAGE_SOURCE_BACKEND_PROPS_AUTO_READONLY = 1 << 2,
    QEMU_BLOCK_STORAGE_SOURCE_BACKEND_PROPS_SKIP_UNMAP = 1 << 3,
} qemuBlockStorageSourceBackendPropsFlags;

virJSONValuePtr
qemuBlockStorageSourceGetBackendProps(virStorageSourcePtr src,
                                      unsigned int flags);

virURIPtr
qemuBlockStorageSourceGetURI(virStorageSourcePtr src);

virJSONValuePtr
qemuBlockStorageSourceGetBlockdevProps(virStorageSourcePtr src,
                                       virStorageSourcePtr backingStore);

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

    virJSONValuePtr storageSliceProps;
    const char *storageSliceNodeName;
    bool storageSliceAttached;

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

    virJSONValuePtr httpcookiesecretProps;
    char *httpcookiesecretAlias;

    virJSONValuePtr tlsProps;
    char *tlsAlias;
    virJSONValuePtr tlsKeySecretProps;
    char *tlsKeySecretAlias;
};


void
qemuBlockStorageSourceAttachDataFree(qemuBlockStorageSourceAttachDataPtr data);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuBlockStorageSourceAttachData,
                        qemuBlockStorageSourceAttachDataFree);

qemuBlockStorageSourceAttachDataPtr
qemuBlockStorageSourceAttachPrepareBlockdev(virStorageSourcePtr src,
                                            virStorageSourcePtr backingStore,
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


G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuBlockStorageSourceChainData,
                        qemuBlockStorageSourceChainDataFree);

int
qemuBlockSnapshotAddLegacy(virJSONValuePtr actions,
                           virDomainDiskDefPtr disk,
                           virStorageSourcePtr newsrc,
                           bool reuse);

int
qemuBlockSnapshotAddBlockdev(virJSONValuePtr actions,
                             virDomainDiskDefPtr disk,
                             virStorageSourcePtr newsrc);

char *
qemuBlockGetBackingStoreString(virStorageSourcePtr src,
                               bool pretty)
    ATTRIBUTE_NONNULL(1);

int
qemuBlockStorageSourceCreateGetFormatProps(virStorageSourcePtr src,
                                           virStorageSourcePtr backing,
                                           virJSONValuePtr *props)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3) G_GNUC_WARN_UNUSED_RESULT;

int
qemuBlockStorageSourceCreateGetStorageProps(virStorageSourcePtr src,
                                            virJSONValuePtr *props)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;

int
qemuBlockStorageSourceCreate(virDomainObjPtr vm,
                             virStorageSourcePtr src,
                             virStorageSourcePtr backingStore,
                             virStorageSourcePtr chain,
                             qemuBlockStorageSourceAttachDataPtr data,
                             qemuDomainAsyncJob asyncJob);

int
qemuBlockStorageSourceCreateDetectSize(virHashTablePtr blockNamedNodeData,
                                       virStorageSourcePtr src,
                                       virStorageSourcePtr templ);

int
qemuBlockRemoveImageMetadata(virQEMUDriverPtr driver,
                             virDomainObjPtr vm,
                             const char *diskTarget,
                             virStorageSourcePtr src);

qemuBlockNamedNodeDataBitmapPtr
qemuBlockNamedNodeDataGetBitmapByName(virHashTablePtr blockNamedNodeData,
                                      virStorageSourcePtr src,
                                      const char *bitmap);

virHashTablePtr
qemuBlockGetNamedNodeData(virDomainObjPtr vm,
                          qemuDomainAsyncJob asyncJob);

int
qemuBlockGetBitmapMergeActions(virStorageSourcePtr topsrc,
                               virStorageSourcePtr basesrc,
                               virStorageSourcePtr target,
                               const char *bitmapname,
                               const char *dstbitmapname,
                               virStorageSourcePtr writebitmapsrc,
                               virJSONValuePtr *actions,
                               virHashTablePtr blockNamedNodeData);

bool
qemuBlockBitmapChainIsValid(virStorageSourcePtr src,
                            const char *bitmapname,
                            virHashTablePtr blockNamedNodeData);

int
qemuBlockBitmapsHandleBlockcopy(virStorageSourcePtr src,
                                virStorageSourcePtr mirror,
                                virHashTablePtr blockNamedNodeData,
                                bool shallow,
                                virJSONValuePtr *actions);

int
qemuBlockBitmapsHandleCommitFinish(virStorageSourcePtr topsrc,
                                   virStorageSourcePtr basesrc,
                                   bool active,
                                   virHashTablePtr blockNamedNodeData,
                                   virJSONValuePtr *actions);

int
qemuBlockReopenReadWrite(virDomainObjPtr vm,
                         virStorageSourcePtr src,
                         qemuDomainAsyncJob asyncJob);
int
qemuBlockReopenReadOnly(virDomainObjPtr vm,
                        virStorageSourcePtr src,
                        qemuDomainAsyncJob asyncJob);

bool
qemuBlockStorageSourceNeedsStorageSliceLayer(const virStorageSource *src);

char *
qemuBlockStorageSourceGetCookieString(virStorageSourcePtr src);

int
qemuBlockUpdateRelativeBacking(virDomainObjPtr vm,
                               virStorageSourcePtr src,
                               virStorageSourcePtr topsrc);
