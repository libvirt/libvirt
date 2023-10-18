/*
 * virconftypes.h: struct and enum type definitions to avoid circular inclusion
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

typedef struct _virCaps virCaps;

typedef struct _virCapsDomainData virCapsDomainData;

typedef struct _virCapsGuest virCapsGuest;

typedef struct _virCapsGuestArch virCapsGuestArch;

typedef struct _virCapsGuestDomain virCapsGuestDomain;

typedef struct _virCapsGuestDomainInfo virCapsGuestDomainInfo;

typedef struct _virCapsGuestFeature virCapsGuestFeature;

typedef struct _virCapsGuestMachine virCapsGuestMachine;

typedef struct _virCapsHost virCapsHost;

typedef struct _virCapsHostCache virCapsHostCache;

typedef struct _virCapsHostCacheBank virCapsHostCacheBank;

typedef struct _virCapsHostMemBW virCapsHostMemBW;

typedef struct _virCapsHostMemBWNode virCapsHostMemBWNode;

typedef struct _virCapsHostNUMA virCapsHostNUMA;

typedef struct _virCapsHostNUMACell virCapsHostNUMACell;

typedef struct _virCapsHostNUMACellCPU virCapsHostNUMACellCPU;

typedef struct _virCapsHostNUMACellPageInfo virCapsHostNUMACellPageInfo;

typedef struct _virCapsHostSecModel virCapsHostSecModel;

typedef struct _virCapsHostSecModelLabel virCapsHostSecModelLabel;

typedef struct _virCapsStoragePool virCapsStoragePool;

typedef struct _virDomainABIStability virDomainABIStability;

typedef struct _virDomainActualNetDef virDomainActualNetDef;

typedef struct _virDomainBackupDef virDomainBackupDef;

typedef struct _virDomainBIOSDef virDomainBIOSDef;

typedef struct _virDomainBlkiotune virDomainBlkiotune;

typedef struct _virDomainBlockIoTuneInfo virDomainBlockIoTuneInfo;

typedef struct _virDomainCheckpointDef virDomainCheckpointDef;

typedef struct _virDomainCheckpointObj virDomainCheckpointObj;

typedef struct _virDomainCheckpointObjList virDomainCheckpointObjList;

typedef struct _virDomainChrDef virDomainChrDef;

typedef struct _virDomainChrSourceDef virDomainChrSourceDef;

typedef struct _virDomainChrSourceReconnectDef virDomainChrSourceReconnectDef;

typedef struct _virDomainClockDef virDomainClockDef;

typedef struct _virDomainControllerDef virDomainControllerDef;

typedef struct _virDomainCputune virDomainCputune;

typedef struct _virDomainDef virDomainDef;

typedef struct _virDomainDefParserConfig virDomainDefParserConfig;

typedef struct _virDomainDeviceDef virDomainDeviceDef;

typedef struct _virDomainDiskDef virDomainDiskDef;

typedef struct _virDomainFSDef virDomainFSDef;

typedef struct _virDomainGraphicsAuthDef virDomainGraphicsAuthDef;

typedef struct _virDomainGraphicsDef virDomainGraphicsDef;

typedef struct _virDomainGraphicsListenDef virDomainGraphicsListenDef;

typedef struct _virDomainHostdevCaps virDomainHostdevCaps;

typedef struct _virDomainHostdevDef virDomainHostdevDef;

typedef struct _virDomainHostdevSubsys virDomainHostdevSubsys;

typedef struct _virDomainHostdevSubsysMediatedDev virDomainHostdevSubsysMediatedDev;

typedef struct _virDomainHostdevSubsysPCI virDomainHostdevSubsysPCI;

typedef struct _virDomainHostdevSubsysSCSI virDomainHostdevSubsysSCSI;

typedef struct _virDomainHostdevSubsysSCSIHost virDomainHostdevSubsysSCSIHost;

typedef struct _virDomainHostdevSubsysSCSIVHost virDomainHostdevSubsysSCSIVHost;

typedef struct _virDomainHostdevSubsysSCSIiSCSI virDomainHostdevSubsysSCSIiSCSI;

typedef struct _virDomainHostdevSubsysUSB virDomainHostdevSubsysUSB;

typedef struct _virDomainHubDef virDomainHubDef;

typedef struct _virDomainHugePage virDomainHugePage;

typedef struct _virDomainIOMMUDef virDomainIOMMUDef;

typedef struct _virDomainIOThreadIDDef virDomainIOThreadIDDef;

typedef struct _virDomainDefaultIOThreadDef virDomainDefaultIOThreadDef;

typedef struct _virDomainIdMapDef virDomainIdMapDef;

typedef struct _virDomainIdMapEntry virDomainIdMapEntry;

typedef struct _virDomainInputDef virDomainInputDef;

typedef struct _virDomainJobObjConfig virDomainJobObjConfig;

typedef struct _virDomainKeyWrapDef virDomainKeyWrapDef;

typedef struct _virDomainLeaseDef virDomainLeaseDef;

typedef struct _virDomainLoaderDef virDomainLoaderDef;

typedef struct _virDomainMemballoonDef virDomainMemballoonDef;

typedef struct _virDomainMemoryDef virDomainMemoryDef;

typedef struct _virDomainMemtune virDomainMemtune;

typedef struct _virDomainMomentDef virDomainMomentDef;

typedef struct _virDomainMomentObj virDomainMomentObj;

typedef struct _virDomainMomentObjList virDomainMomentObjList;

typedef struct _virDomainNVRAMDef virDomainNVRAMDef;

typedef struct _virDomainNetBackend virDomainNetBackend;

typedef struct _virDomainNetPortForwardRange virDomainNetPortForwardRange;

typedef struct _virDomainNetPortForward virDomainNetPortForward;

typedef struct _virDomainNetDef virDomainNetDef;

typedef struct _virDomainNetTeamingInfo virDomainNetTeamingInfo;

typedef struct _virDomainOSDef virDomainOSDef;

typedef struct _virDomainOSEnv virDomainOSEnv;

typedef struct _virDomainObj virDomainObj;

typedef struct _virDomainPCIControllerOpts virDomainPCIControllerOpts;

typedef struct _virDomainPanicDef virDomainPanicDef;

typedef struct _virDomainPerfDef virDomainPerfDef;

typedef struct _virDomainPowerManagement virDomainPowerManagement;

typedef struct _virDomainRNGDef virDomainRNGDef;

typedef struct _virDomainRedirFilterDef virDomainRedirFilterDef;

typedef struct _virDomainRedirFilterUSBDevDef virDomainRedirFilterUSBDevDef;

typedef struct _virDomainRedirdevDef virDomainRedirdevDef;

typedef struct _virDomainResctrlDef virDomainResctrlDef;

typedef struct _virDomainResctrlMonDef virDomainResctrlMonDef;

typedef struct _virDomainResourceDef virDomainResourceDef;

typedef struct _virDomainSEVDef virDomainSEVDef;

typedef struct _virDomainSecDef virDomainSecDef;

typedef struct _virDomainShmemDef virDomainShmemDef;

typedef struct _virDomainSmartcardDef virDomainSmartcardDef;

typedef struct _virDomainSnapshotDef virDomainSnapshotDef;

typedef struct _virDomainSnapshotObjList virDomainSnapshotObjList;

typedef struct _virDomainSoundCodecDef virDomainSoundCodecDef;

typedef struct _virDomainSoundDef virDomainSoundDef;

typedef struct _virDomainAudioDef virDomainAudioDef;

typedef struct _virDomainTPMDef virDomainTPMDef;

typedef struct _virDomainThreadSchedParam virDomainThreadSchedParam;

typedef struct _virDomainTimerCatchupDef virDomainTimerCatchupDef;

typedef struct _virDomainTimerDef virDomainTimerDef;

typedef struct _virDomainUSBControllerOpts virDomainUSBControllerOpts;

typedef struct _virDomainVcpuDef virDomainVcpuDef;

typedef struct _virDomainVideoAccelDef virDomainVideoAccelDef;

typedef struct _virDomainVideoResolutionDef virDomainVideoResolutionDef;

typedef struct _virDomainVideoDef virDomainVideoDef;

typedef struct _virDomainVideoDriverDef virDomainVideoDriverDef;

typedef struct _virDomainVirtioOptions virDomainVirtioOptions;

typedef struct _virDomainVirtioSerialOpts virDomainVirtioSerialOpts;

typedef struct _virDomainVsockDef virDomainVsockDef;

typedef struct _virDomainCryptoDef virDomainCryptoDef;

typedef struct _virDomainWatchdogDef virDomainWatchdogDef;

typedef struct _virDomainXMLOption virDomainXMLOption;

typedef struct _virDomainXMLPrivateDataCallbacks virDomainXMLPrivateDataCallbacks;

typedef struct _virDomainXenbusControllerOpts virDomainXenbusControllerOpts;

typedef enum {
    VIR_DOMAIN_DISK_IO_DEFAULT = 0,
    VIR_DOMAIN_DISK_IO_NATIVE,
    VIR_DOMAIN_DISK_IO_THREADS,
    VIR_DOMAIN_DISK_IO_URING,

    VIR_DOMAIN_DISK_IO_LAST
} virDomainDiskIo;

typedef enum {
    VIR_DOMAIN_DISK_CACHE_DEFAULT = 0,
    VIR_DOMAIN_DISK_CACHE_DISABLE,
    VIR_DOMAIN_DISK_CACHE_WRITETHRU,
    VIR_DOMAIN_DISK_CACHE_WRITEBACK,
    VIR_DOMAIN_DISK_CACHE_DIRECTSYNC,
    VIR_DOMAIN_DISK_CACHE_UNSAFE,

    VIR_DOMAIN_DISK_CACHE_LAST
} virDomainDiskCache;

typedef enum {
    VIR_DOMAIN_DISK_DISCARD_DEFAULT = 0,
    VIR_DOMAIN_DISK_DISCARD_UNMAP,
    VIR_DOMAIN_DISK_DISCARD_IGNORE,

    VIR_DOMAIN_DISK_DISCARD_LAST
} virDomainDiskDiscard;

typedef enum {
    VIR_DOMAIN_DISK_DETECT_ZEROES_DEFAULT = 0,
    VIR_DOMAIN_DISK_DETECT_ZEROES_OFF,
    VIR_DOMAIN_DISK_DETECT_ZEROES_ON,
    VIR_DOMAIN_DISK_DETECT_ZEROES_UNMAP,

    VIR_DOMAIN_DISK_DETECT_ZEROES_LAST
} virDomainDiskDetectZeroes;
