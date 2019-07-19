/*
 * virconftypes.h: struct typedefs to avoid circular inclusion
 *
 * Copyright (C) 2006-2019 Red Hat, Inc.
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

/* forward declarations of various types required in src/conf */

typedef struct _virBlkioDevice virBlkioDevice;
typedef virBlkioDevice *virBlkioDevicePtr;

typedef struct _virCaps virCaps;
typedef virCaps *virCapsPtr;

typedef struct _virCapsDomainData virCapsDomainData;
typedef virCapsDomainData *virCapsDomainDataPtr;

typedef struct _virCapsGuest virCapsGuest;
typedef virCapsGuest *virCapsGuestPtr;

typedef struct _virCapsGuestArch virCapsGuestArch;
typedef virCapsGuestArch *virCapsGuestArchptr;

typedef struct _virCapsGuestDomain virCapsGuestDomain;
typedef virCapsGuestDomain *virCapsGuestDomainPtr;

typedef struct _virCapsGuestDomainInfo virCapsGuestDomainInfo;
typedef virCapsGuestDomainInfo *virCapsGuestDomainInfoPtr;

typedef struct _virCapsGuestFeature virCapsGuestFeature;
typedef virCapsGuestFeature *virCapsGuestFeaturePtr;

typedef struct _virCapsGuestMachine virCapsGuestMachine;
typedef virCapsGuestMachine *virCapsGuestMachinePtr;

typedef struct _virCapsHost virCapsHost;
typedef virCapsHost *virCapsHostPtr;

typedef struct _virCapsHostCache virCapsHostCache;
typedef virCapsHostCache *virCapsHostCachePtr;

typedef struct _virCapsHostCacheBank virCapsHostCacheBank;
typedef virCapsHostCacheBank *virCapsHostCacheBankPtr;

typedef struct _virCapsHostMemBW virCapsHostMemBW;
typedef virCapsHostMemBW *virCapsHostMemBWPtr;

typedef struct _virCapsHostMemBWNode virCapsHostMemBWNode;
typedef virCapsHostMemBWNode *virCapsHostMemBWNodePtr;

typedef struct _virCapsHostNUMACell virCapsHostNUMACell;
typedef virCapsHostNUMACell *virCapsHostNUMACellPtr;

typedef struct _virCapsHostNUMACellCPU virCapsHostNUMACellCPU;
typedef virCapsHostNUMACellCPU *virCapsHostNUMACellCPUPtr;

typedef struct _virCapsHostNUMACellPageInfo virCapsHostNUMACellPageInfo;
typedef virCapsHostNUMACellPageInfo *virCapsHostNUMACellPageInfoPtr;

typedef struct _virCapsHostNUMACellSiblingInfo virCapsHostNUMACellSiblingInfo;
typedef virCapsHostNUMACellSiblingInfo *virCapsHostNUMACellSiblingInfoPtr;

typedef struct _virCapsHostSecModel virCapsHostSecModel;
typedef virCapsHostSecModel *virCapsHostSecModelPtr;

typedef struct _virCapsHostSecModelLabel virCapsHostSecModelLabel;
typedef virCapsHostSecModelLabel *virCapsHostSecModelLabelPtr;

typedef struct _virCapsStoragePool virCapsStoragePool;
typedef virCapsStoragePool *virCapsStoragePoolPtr;

typedef struct _virDomainABIStability virDomainABIStability;
typedef virDomainABIStability *virDomainABIStabilityPtr;

typedef struct _virDomainActualNetDef virDomainActualNetDef;
typedef virDomainActualNetDef *virDomainActualNetDefPtr;

typedef struct _virDomainBIOSDef virDomainBIOSDef;
typedef virDomainBIOSDef *virDomainBIOSDefPtr;

typedef struct _virDomainBlkiotune virDomainBlkiotune;
typedef virDomainBlkiotune *virDomainBlkiotunePtr;

typedef struct _virDomainBlockIoTuneInfo virDomainBlockIoTuneInfo;
typedef virDomainBlockIoTuneInfo *virDomainBlockIoTuneInfoPtr;

typedef struct _virDomainCheckpointDef virDomainCheckpointDef;
typedef virDomainCheckpointDef *virDomainCheckpointDefPtr;

typedef struct _virDomainCheckpointObj virDomainCheckpointObj;
typedef virDomainCheckpointObj *virDomainCheckpointObjPtr;

typedef struct _virDomainCheckpointObjList virDomainCheckpointObjList;
typedef virDomainCheckpointObjList *virDomainCheckpointObjListPtr;

typedef struct _virDomainChrDef virDomainChrDef;
typedef virDomainChrDef *virDomainChrDefPtr;

typedef struct _virDomainChrSourceDef virDomainChrSourceDef;
typedef virDomainChrSourceDef *virDomainChrSourceDefPtr;

typedef struct _virDomainChrSourceReconnectDef virDomainChrSourceReconnectDef;
typedef virDomainChrSourceReconnectDef *virDomainChrSourceReconnectDefPtr;

typedef struct _virDomainClockDef virDomainClockDef;
typedef virDomainClockDef *virDomainClockDefPtr;

typedef struct _virDomainControllerDef virDomainControllerDef;
typedef virDomainControllerDef *virDomainControllerDefPtr;

typedef struct _virDomainCputune virDomainCputune;
typedef virDomainCputune *virDomainCputunePtr;

typedef struct _virDomainDef virDomainDef;
typedef virDomainDef *virDomainDefPtr;

typedef struct _virDomainDefParserConfig virDomainDefParserConfig;
typedef virDomainDefParserConfig *virDomainDefParserConfigPtr;

typedef struct _virDomainDeviceDef virDomainDeviceDef;
typedef virDomainDeviceDef *virDomainDeviceDefPtr;

typedef struct _virDomainDiskDef virDomainDiskDef;
typedef virDomainDiskDef *virDomainDiskDefPtr;

typedef struct _virDomainFSDef virDomainFSDef;
typedef virDomainFSDef *virDomainFSDefPtr;

typedef struct _virDomainGraphicsAuthDef virDomainGraphicsAuthDef;
typedef virDomainGraphicsAuthDef *virDomainGraphicsAuthDefPtr;

typedef struct _virDomainGraphicsDef virDomainGraphicsDef;
typedef virDomainGraphicsDef *virDomainGraphicsDefPtr;

typedef struct _virDomainGraphicsListenDef virDomainGraphicsListenDef;
typedef virDomainGraphicsListenDef *virDomainGraphicsListenDefPtr;

typedef struct _virDomainHostdevCaps virDomainHostdevCaps;
typedef virDomainHostdevCaps *virDomainHostdevCapsPtr;

typedef struct _virDomainHostdevDef virDomainHostdevDef;
typedef virDomainHostdevDef *virDomainHostdevDefPtr;

typedef struct _virDomainHostdevOrigStates virDomainHostdevOrigStates;
typedef virDomainHostdevOrigStates *virDomainHostdevOrigStatesPtr;

typedef struct _virDomainHostdevSubsys virDomainHostdevSubsys;
typedef virDomainHostdevSubsys *virDomainHostdevSubsysPtr;

typedef struct _virDomainHostdevSubsysMediatedDev virDomainHostdevSubsysMediatedDev;
typedef virDomainHostdevSubsysMediatedDev *virDomainHostdevSubsysMediatedDevPtr;

typedef struct _virDomainHostdevSubsysPCI virDomainHostdevSubsysPCI;
typedef virDomainHostdevSubsysPCI *virDomainHostdevSubsysPCIPtr;

typedef struct _virDomainHostdevSubsysSCSI virDomainHostdevSubsysSCSI;
typedef virDomainHostdevSubsysSCSI *virDomainHostdevSubsysSCSIPtr;

typedef struct _virDomainHostdevSubsysSCSIHost virDomainHostdevSubsysSCSIHost;
typedef virDomainHostdevSubsysSCSIHost *virDomainHostdevSubsysSCSIHostPtr;

typedef struct _virDomainHostdevSubsysSCSIVHost virDomainHostdevSubsysSCSIVHost;
typedef virDomainHostdevSubsysSCSIVHost *virDomainHostdevSubsysSCSIVHostPtr;

typedef struct _virDomainHostdevSubsysSCSIiSCSI virDomainHostdevSubsysSCSIiSCSI;
typedef virDomainHostdevSubsysSCSIiSCSI *virDomainHostdevSubsysSCSIiSCSIPtr;

typedef struct _virDomainHostdevSubsysUSB virDomainHostdevSubsysUSB;
typedef virDomainHostdevSubsysUSB *virDomainHostdevSubsysUSBPtr;

typedef struct _virDomainHubDef virDomainHubDef;
typedef virDomainHubDef *virDomainHubDefPtr;

typedef struct _virDomainHugePage virDomainHugePage;
typedef virDomainHugePage *virDomainHugePagePtr;

typedef struct _virDomainIOMMUDef virDomainIOMMUDef;
typedef virDomainIOMMUDef *virDomainIOMMUDefPtr;

typedef struct _virDomainIOThreadIDDef virDomainIOThreadIDDef;
typedef virDomainIOThreadIDDef *virDomainIOThreadIDDefPtr;

typedef struct _virDomainIdMapDef virDomainIdMapDef;
typedef virDomainIdMapDef *virDomainIdMapDefPtr;

typedef struct _virDomainIdMapEntry virDomainIdMapEntry;
typedef virDomainIdMapEntry *virDomainIdMapEntryPtr;

typedef struct _virDomainInputDef virDomainInputDef;
typedef virDomainInputDef *virDomainInputDefPtr;

typedef struct _virDomainKeyWrapDef virDomainKeyWrapDef;
typedef virDomainKeyWrapDef *virDomainKeyWrapDefPtr;

typedef struct _virDomainLeaseDef virDomainLeaseDef;
typedef virDomainLeaseDef *virDomainLeaseDefPtr;

typedef struct _virDomainLoaderDef virDomainLoaderDef;
typedef virDomainLoaderDef *virDomainLoaderDefPtr;

typedef struct _virDomainMemballoonDef virDomainMemballoonDef;
typedef virDomainMemballoonDef *virDomainMemballoonDefPtr;

typedef struct _virDomainMemoryDef virDomainMemoryDef;
typedef virDomainMemoryDef *virDomainMemoryDefPtr;

typedef struct _virDomainMemtune virDomainMemtune;
typedef virDomainMemtune *virDomainMemtunePtr;

typedef struct _virDomainMomentDef virDomainMomentDef;
typedef virDomainMomentDef *virDomainMomentDefPtr;

typedef struct _virDomainMomentObj virDomainMomentObj;
typedef virDomainMomentObj *virDomainMomentObjPtr;

typedef struct _virDomainMomentObjList virDomainMomentObjList;
typedef virDomainMomentObjList *virDomainMomentObjListPtr;

typedef struct _virDomainNVRAMDef virDomainNVRAMDef;
typedef virDomainNVRAMDef *virDomainNVRAMDefPtr;

typedef struct _virDomainNetDef virDomainNetDef;
typedef virDomainNetDef *virDomainNetDefPtr;

typedef struct _virDomainOSDef virDomainOSDef;
typedef virDomainOSDef *virDomainOSDefPtr;

typedef struct _virDomainOSEnv virDomainOSEnv;
typedef virDomainOSEnv *virDomainOSEnvPtr;

typedef struct _virDomainObj virDomainObj;
typedef virDomainObj *virDomainObjPtr;

typedef struct _virDomainPCIControllerOpts virDomainPCIControllerOpts;
typedef virDomainPCIControllerOpts *virDomainPCIControllerOptsPtr;

typedef struct _virDomainPanicDef virDomainPanicDef;
typedef virDomainPanicDef *virDomainPanicDefPtr;

typedef struct _virDomainPerfDef virDomainPerfDef;
typedef virDomainPerfDef *virDomainPerfDefPtr;

typedef struct _virDomainPowerManagement virDomainPowerManagement;
typedef virDomainPowerManagement *virDomainPowerManagementPtr;

typedef struct _virDomainRNGDef virDomainRNGDef;
typedef virDomainRNGDef *virDomainRNGDefPtr;

typedef struct _virDomainRedirFilterDef virDomainRedirFilterDef;
typedef virDomainRedirFilterDef *virDomainRedirFilterDefPtr;

typedef struct _virDomainRedirFilterUSBDevDef virDomainRedirFilterUSBDevDef;
typedef virDomainRedirFilterUSBDevDef *virDomainRedirFilterUSBDevDefPtr;

typedef struct _virDomainRedirdevDef virDomainRedirdevDef;
typedef virDomainRedirdevDef *virDomainRedirdevDefPtr;

typedef struct _virDomainResctrlDef virDomainResctrlDef;
typedef virDomainResctrlDef *virDomainResctrlDefPtr;

typedef struct _virDomainResctrlMonDef virDomainResctrlMonDef;
typedef virDomainResctrlMonDef *virDomainResctrlMonDefPtr;

typedef struct _virDomainResourceDef virDomainResourceDef;
typedef virDomainResourceDef *virDomainResourceDefPtr;

typedef struct _virDomainSEVDef virDomainSEVDef;
typedef virDomainSEVDef *virDomainSEVDefPtr;

typedef struct _virDomainShmemDef virDomainShmemDef;
typedef virDomainShmemDef *virDomainShmemDefPtr;

typedef struct _virDomainSmartcardDef virDomainSmartcardDef;
typedef virDomainSmartcardDef *virDomainSmartcardDefPtr;

typedef struct _virDomainSnapshotDef virDomainSnapshotDef;
typedef virDomainSnapshotDef *virDomainSnapshotDefPtr;

typedef struct _virDomainSnapshotObjList virDomainSnapshotObjList;
typedef virDomainSnapshotObjList *virDomainSnapshotObjListPtr;

typedef struct _virDomainSoundCodecDef virDomainSoundCodecDef;
typedef virDomainSoundCodecDef *virDomainSoundCodecDefPtr;

typedef struct _virDomainSoundDef virDomainSoundDef;
typedef virDomainSoundDef *virDomainSoundDefPtr;

typedef struct _virDomainTPMDef virDomainTPMDef;
typedef virDomainTPMDef *virDomainTPMDefPtr;

typedef struct _virDomainThreadSchedParam virDomainThreadSchedParam;
typedef virDomainThreadSchedParam *virDomainThreadSchedParamPtr;

typedef struct _virDomainTimerCatchupDef virDomainTimerCatchupDef;
typedef virDomainTimerCatchupDef *virDomainTimerCatchupDefPtr;

typedef struct _virDomainTimerDef virDomainTimerDef;
typedef virDomainTimerDef *virDomainTimerDefPtr;

typedef struct _virDomainUSBControllerOpts virDomainUSBControllerOpts;
typedef virDomainUSBControllerOpts *virDomainUSBControllerOptsPtr;

typedef struct _virDomainVcpuDef virDomainVcpuDef;
typedef virDomainVcpuDef *virDomainVcpuDefPtr;

typedef struct _virDomainVideoAccelDef virDomainVideoAccelDef;
typedef virDomainVideoAccelDef *virDomainVideoAccelDefPtr;

typedef struct _virDomainVideoDef virDomainVideoDef;
typedef virDomainVideoDef *virDomainVideoDefPtr;

typedef struct _virDomainVideoDriverDef virDomainVideoDriverDef;
typedef virDomainVideoDriverDef *virDomainVideoDriverDefPtr;

typedef struct _virDomainVirtioOptions virDomainVirtioOptions;
typedef virDomainVirtioOptions *virDomainVirtioOptionsPtr;

typedef struct _virDomainVirtioSerialOpts virDomainVirtioSerialOpts;
typedef virDomainVirtioSerialOpts *virDomainVirtioSerialOptsPtr;

typedef struct _virDomainVsockDef virDomainVsockDef;
typedef virDomainVsockDef *virDomainVsockDefPtr;

typedef struct _virDomainWatchdogDef virDomainWatchdogDef;
typedef virDomainWatchdogDef *virDomainWatchdogDefPtr;

typedef struct _virDomainXMLNamespace virDomainXMLNamespace;
typedef virDomainXMLNamespace *virDomainXMLNamespacePtr;

typedef struct _virDomainXMLOption virDomainXMLOption;
typedef virDomainXMLOption *virDomainXMLOptionPtr;

typedef struct _virDomainXMLPrivateDataCallbacks virDomainXMLPrivateDataCallbacks;
typedef virDomainXMLPrivateDataCallbacks *virDomainXMLPrivateDataCallbacksPtr;

typedef struct _virDomainXenbusControllerOpts virDomainXenbusControllerOpts;
typedef virDomainXenbusControllerOpts *virDomainXenbusControllerOptsPtr;
