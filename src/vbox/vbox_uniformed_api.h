/*
 * Copyright (C) 2014, Taowei Luo (uaedante@gmail.com)
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

/* This file may be used in three place. That is vbox_tmpl.c,
 * vbox_common.c and vbox_driver.c. The vboxUniformedAPI and some
 * types used for vboxUniformedAPI is defined here.
 *
 * The vbox_tmpl.c is the only place where the driver knows the inside
 * architecture of those vbox structs(vboxObj, vboxSession,
 * pFuncs, and vboxCallback). The file should be included
 * after the correct vbox_CAPI_v*.h, then we can use the vbox structs
 * in vboxGlobalData. The vbox_tmpl.c should implement functions
 * defined in vboxUniformedAPI.
 *
 * In vbox_driver.c, it is used to define the struct vboxUniformedAPI.
 * The vbox_driver.c collects vboxUniformedAPI for all versions.
 * Then vboxRegister calls the vboxRegisterUniformedAPI to register.
 * Note: In vbox_driver.c, the vbox structs in vboxGlobalData is
 * defined by vbox_CAPI_v4_0.h.
 *
 * The vbox_common.c, it is used to generate common codes for all vbox
 * versions. Because the same member variable's offset in a vbox struct
 * may change between different vbox versions. The vbox_common.c
 * shouldn't directly use struct's member variables defined in
 * vbox_CAPI_v*.h. To make things safety, we include the
 * vbox_common.h in vbox_common.c. In this case, we treat structs
 * defined by vbox as a void*. The common codes don't concern about
 * the inside of this structs(actually, we can't, in the common level).
 * With the help of vboxUniformed API, we call VirtualBox's API and
 * implement the vbox driver in a high level.
 *
 * In conclusion:
 *  * In vbox_tmpl.c, this file is included after vbox_CAPI_v*.h
 *  * In vbox_driver.c, this file is included after vbox_XPCOMCGlue.h
 *  * In vbox_common.c, this file is included after vbox_common.h
 *
 */

/* Extracted define from vbox_tmpl.c */

struct _vboxIID {
    /* IID is represented by a UTF-16 encoded UUID in string form. */
    PRUnichar *value;

    /* owner indicates if we own the value and need to free it. */
    bool owner;
};

typedef struct _vboxIID vboxIID;

typedef union {
    nsresult uResultCode;
    PRInt32 resultCode;
} resultCodeUnion;


struct _vboxDriver {
    virObjectLockable parent;

    virCaps *caps;
    virDomainXMLOption *xmlopt;
    virObjectEventState *domainEventState;

    /* vbox API initialization members */
    PCVBOXXPCOM pFuncs;
    IVirtualBox *vboxObj;
    ISession *vboxSession;
#ifdef VBOX_API_VERSION
    IVirtualBoxClient *vboxClient;
#endif

    unsigned long version;

    /* reference counting of vbox connections */
    int volatile connectionCount;
};

typedef struct _vboxDriver vboxDriver;

/* vboxUniformedAPI gives vbox_common.c a uniformed layer to see
 * vbox API.
 */

/* Functions for pFuncs */
typedef struct {
    int (*Initialize)(struct _vboxDriver *driver);
    void (*Uninitialize)(struct _vboxDriver *driver);
    void (*ComUnallocMem)(PCVBOXXPCOM pFuncs, void *pv);
    void (*Utf16Free)(PCVBOXXPCOM pFuncs, PRUnichar *pwszString);
    void (*Utf8Free)(PCVBOXXPCOM pFuncs, char *pszString);
    int (*Utf16ToUtf8)(PCVBOXXPCOM pFuncs, const PRUnichar *pwszString, char **ppszString);
    int (*Utf8ToUtf16)(PCVBOXXPCOM pFuncs, const char *pszString, PRUnichar **ppwszString);
    HRESULT (*GetException)(PCVBOXXPCOM pFuncs, nsIException **ppException);
    HRESULT (*ClearException)(PCVBOXXPCOM pFuncs);
} vboxUniformedPFN;

/* Functions for vboxIID */
typedef struct {
    void (*vboxIIDInitialize)(vboxIID *iid);
    void (*vboxIIDUnalloc)(struct _vboxDriver *driver, vboxIID *iid);
    void (*vboxIIDToUUID)(struct _vboxDriver *driver, vboxIID *iid, unsigned char *uuid);
    void (*vboxIIDFromUUID)(struct _vboxDriver *driver, vboxIID *iid, const unsigned char *uuid);
    bool (*vboxIIDIsEqual)(struct _vboxDriver *driver, vboxIID *iid1, vboxIID *iid2);
    void (*vboxIIDFromArrayItem)(struct _vboxDriver *driver, vboxIID *iid, vboxArray *array, int idx);
    void (*vboxIIDToUtf8)(struct _vboxDriver *driver, vboxIID *iid, char **utf8);
    void (*DEBUGIID)(struct _vboxDriver *driver, const char *msg, vboxIID *iid);
} vboxUniformedIID;

/* Functions for vboxArray */
typedef struct {
    nsresult (*vboxArrayGet)(vboxArray *array, void *self, void *getter);
    nsresult (*vboxArrayGetWithIIDArg)(vboxArray *array, void *self, void *getter, vboxIID *iid);
    void (*vboxArrayRelease)(vboxArray *array);
    void (*vboxArrayUnalloc)(vboxArray *array);
    /* Generate function pointers for vboxArrayGet */
    void* (*handleGetMachines)(IVirtualBox *vboxObj);
    void* (*handleGetHardDisks)(IVirtualBox *vboxObj);
    void* (*handleUSBGetDeviceFilters)(IUSBCommon *USBCommon);
    void* (*handleMachineGetStorageControllers)(IMachine *machine);
    void* (*handleMachineGetMediumAttachments)(IMachine *machine);
    void* (*handleMachineGetSharedFolders)(IMachine *machine);
    void* (*handleSnapshotGetChildren)(ISnapshot *snapshot);
    void* (*handleMediumGetChildren)(IMedium *medium);
    void* (*handleMediumGetSnapshotIds)(IMedium *medium);
    void* (*handleMediumGetMachineIds)(IMedium *medium);
    void* (*handleHostGetNetworkInterfaces)(IHost *host);
} vboxUniformedArray;

/* Functions for nsISupports */
typedef struct {
    nsresult (*QueryInterface)(nsISupports *nsi, const nsID *iid, void **resultp);
    nsresult (*Release)(nsISupports *nsi);
    nsresult (*AddRef)(nsISupports *nsi);
} vboxUniformednsISupports;

/* Functions for IVirtualBox */
typedef struct {
    nsresult (*GetVersion)(IVirtualBox *vboxObj, PRUnichar **versionUtf16);
    nsresult (*GetMachine)(IVirtualBox *vboxObj, vboxIID *iid, IMachine **machine);
    nsresult (*OpenMachine)(IVirtualBox *vboxObj, PRUnichar *settingsFile, IMachine **machine);
    nsresult (*GetSystemProperties)(IVirtualBox *vboxObj, ISystemProperties **systemProperties);
    nsresult (*GetHost)(IVirtualBox *vboxObj, IHost **host);
    nsresult (*CreateMachine)(struct _vboxDriver *driver, virDomainDef *def, IMachine **machine, char *uuidstr);
    nsresult (*CreateHardDisk)(IVirtualBox *vboxObj, PRUnichar *format, PRUnichar *location, IMedium **medium);
    nsresult (*RegisterMachine)(IVirtualBox *vboxObj, IMachine *machine);
    nsresult (*FindHardDisk)(IVirtualBox *vboxObj, PRUnichar *location, PRUint32 deviceType,
                             PRUint32 accessMode, IMedium **medium);
    nsresult (*OpenMedium)(IVirtualBox *vboxObj, PRUnichar *location, PRUint32 deviceType, PRUint32 accessMode, IMedium **medium);
    nsresult (*GetHardDiskByIID)(IVirtualBox *vboxObj, vboxIID *iid, IMedium **medium);
    nsresult (*FindDHCPServerByNetworkName)(IVirtualBox *vboxObj, PRUnichar *name, IDHCPServer **server);
    nsresult (*CreateDHCPServer)(IVirtualBox *vboxObj, PRUnichar *name, IDHCPServer **server);
    nsresult (*RemoveDHCPServer)(IVirtualBox *vboxObj, IDHCPServer *server);
} vboxUniformedIVirtualBox;

/* Functions for IMachine */
typedef struct {
    nsresult (*AddStorageController)(IMachine *machine, PRUnichar *name,
        PRUint32 connectionType, IStorageController **controller);
    nsresult (*GetStorageControllerByName)(IMachine *machine, PRUnichar *name,
                                           IStorageController **storageController);
    nsresult (*AttachDevice)(IMachine *machine, PRUnichar *name,
                             PRInt32 controllerPort, PRInt32 device,
                             PRUint32 type, IMedium *medium);
    nsresult (*CreateSharedFolder)(IMachine *machine, PRUnichar *name,
                                   PRUnichar *hostPath, PRBool writable,
                                   PRBool automount);
    nsresult (*RemoveSharedFolder)(IMachine *machine, PRUnichar *name);
    nsresult (*LaunchVMProcess)(struct _vboxDriver *driver, IMachine *machine,
                                PRUnichar *sessionType, PRUnichar *env,
                                IProgress **progress);
    nsresult (*Unregister)(IMachine *machine, PRUint32 cleanupMode,
                           PRUint32 *aMediaSize, IMedium ***aMedia);
    nsresult (*FindSnapshot)(IMachine *machine, vboxIID *iid, ISnapshot **snapshot);
    nsresult (*DetachDevice)(IMachine *machine, PRUnichar *name,
                             PRInt32 controllerPort, PRInt32 device);
    nsresult (*GetAccessible)(IMachine *machine, PRBool *isAccessible);
    nsresult (*GetState)(IMachine *machine, PRUint32 *state);
    nsresult (*GetName)(IMachine *machine, PRUnichar **name);
    nsresult (*GetId)(IMachine *machine, vboxIID *iid);
    nsresult (*GetBIOSSettings)(IMachine *machine, IBIOSSettings **bios);
    nsresult (*GetAudioAdapter)(IMachine *machine, IAudioAdapter **audioAdapter);
    nsresult (*GetNetworkAdapter)(IMachine *machine, PRUint32 slot, INetworkAdapter **adapter);
    nsresult (*GetChipsetType)(IMachine *machine, PRUint32 *chipsetType);
    nsresult (*GetSerialPort)(IMachine *machine, PRUint32 slot, ISerialPort **port);
    nsresult (*GetParallelPort)(IMachine *machine, PRUint32 slot, IParallelPort **port);
    nsresult (*GetVRDEServer)(IMachine *machine, IVRDEServer **VRDEServer);
    nsresult (*GetUSBCommon)(IMachine *machine, IUSBCommon **USBCommon);
    nsresult (*GetCurrentSnapshot)(IMachine *machine, ISnapshot **currentSnapshot);
    nsresult (*GetSettingsFilePath)(IMachine *machine, PRUnichar **settingsFilePath);
    nsresult (*GetCPUCount)(IMachine *machine, PRUint32 *CPUCount);
    nsresult (*SetCPUCount)(IMachine *machine, PRUint32 CPUCount);
    nsresult (*GetMemorySize)(IMachine *machine, PRUint32 *memorySize);
    nsresult (*SetMemorySize)(IMachine *machine, PRUint32 memorySize);
    nsresult (*GetCPUProperty)(IMachine *machine, PRUint32 property, PRBool *value);
    nsresult (*SetCPUProperty)(IMachine *machine, PRUint32 property, PRBool value);
    nsresult (*GetBootOrder)(IMachine *machine, PRUint32 position, PRUint32 *device);
    nsresult (*SetBootOrder)(IMachine *machine, PRUint32 position, PRUint32 device);
    nsresult (*GetVRAMSize)(IMachine *machine, PRUint32 *VRAMSize);
    nsresult (*SetVRAMSize)(IMachine *machine, PRUint32 VRAMSize);
    nsresult (*GetMonitorCount)(IMachine *machine, PRUint32 *monitorCount);
    nsresult (*SetMonitorCount)(IMachine *machine, PRUint32 monitorCount);
    nsresult (*GetAccelerate3DEnabled)(IMachine *machine, PRBool *accelerate3DEnabled);
    nsresult (*SetAccelerate3DEnabled)(IMachine *machine, PRBool accelerate3DEnabled);
    nsresult (*GetAccelerate2DVideoEnabled)(IMachine *machine, PRBool *accelerate2DVideoEnabled);
    nsresult (*SetAccelerate2DVideoEnabled)(IMachine *machine, PRBool accelerate2DVideoEnabled);
    nsresult (*GetExtraData)(IMachine *machine, PRUnichar *key, PRUnichar **value);
    nsresult (*SetExtraData)(IMachine *machine, PRUnichar *key, PRUnichar *value);
    nsresult (*GetSnapshotCount)(IMachine *machine, PRUint32 *snapshotCount);
    nsresult (*SaveSettings)(IMachine *machine);
} vboxUniformedIMachine;

/* Functions for ISession */
typedef struct {
    nsresult (*Open)(struct _vboxDriver *driver, IMachine *machine);
    nsresult (*OpenExisting)(struct _vboxDriver *driver, IMachine *machine);
    nsresult (*GetConsole)(ISession *session, IConsole **console);
    nsresult (*GetMachine)(ISession *session, IMachine **machine);
    nsresult (*Close)(ISession *session);
} vboxUniformedISession;

/* Functions for IConsole */
typedef struct {
    nsresult (*SaveState)(IConsole *console, IProgress **progress);
    nsresult (*Pause)(IConsole *console);
    nsresult (*Resume)(IConsole *console);
    nsresult (*PowerButton)(IConsole *console);
    nsresult (*PowerDown)(IConsole *console);
    nsresult (*Reset)(IConsole *console);
    nsresult (*TakeSnapshot)(IConsole *console, PRUnichar *name,
                             PRUnichar *description, IProgress **progress);
    nsresult (*DeleteSnapshot)(IConsole *console, vboxIID *iid, IProgress **progress);
    nsresult (*GetDisplay)(IConsole *console, IDisplay **display);
    nsresult (*GetKeyboard)(IConsole *console, IKeyboard **keyboard);
} vboxUniformedIConsole;

/* Functions for IProgress */
typedef struct {
    nsresult (*WaitForCompletion)(IProgress *progress, PRInt32 timeout);
    nsresult (*GetResultCode)(IProgress *progress, resultCodeUnion *resultCode);
    nsresult (*GetCompleted)(IProgress *progress, PRBool *completed);
} vboxUniformedIProgress;

/* Functions for ISystemProperties */
typedef struct {
    nsresult (*GetMaxGuestCPUCount)(ISystemProperties *systemProperties, PRUint32 *maxCPUCount);
    nsresult (*GetMaxBootPosition)(ISystemProperties *systemProperties, PRUint32 *maxBootPosition);
    nsresult (*GetMaxNetworkAdapters)(ISystemProperties *systemProperties, PRUint32 chipset,
                                      PRUint32 *maxNetworkAdapters);
    nsresult (*GetSerialPortCount)(ISystemProperties *systemProperties, PRUint32 *SerialPortCount);
    nsresult (*GetParallelPortCount)(ISystemProperties *systemProperties, PRUint32 *ParallelPortCount);
    nsresult (*GetMaxPortCountForStorageBus)(ISystemProperties *systemProperties, PRUint32 bus,
                                             PRUint32 *maxPortCount);
    nsresult (*GetMaxDevicesPerPortForStorageBus)(ISystemProperties *systemProperties,
                                                  PRUint32 bus, PRUint32 *maxDevicesPerPort);
    nsresult (*GetMaxGuestRAM)(ISystemProperties *systemProperties, PRUint32 *maxGuestRAM);
} vboxUniformedISystemProperties;

/* Functions for IBIOSSettings */
typedef struct {
    nsresult (*GetACPIEnabled)(IBIOSSettings *bios, PRBool *ACPIEnabled);
    nsresult (*SetACPIEnabled)(IBIOSSettings *bios, PRBool ACPIEnabled);
    nsresult (*GetIOAPICEnabled)(IBIOSSettings *bios, PRBool *IOAPICEnabled);
    nsresult (*SetIOAPICEnabled)(IBIOSSettings *bios, PRBool IOAPICEnabled);
} vboxUniformedIBIOSSettings;

/* Functions for IAudioAdapter */
typedef struct {
    nsresult (*GetEnabled)(IAudioAdapter *audioAdapter, PRBool *enabled);
    nsresult (*SetEnabled)(IAudioAdapter *audioAdapter, PRBool enabled);
    nsresult (*GetAudioController)(IAudioAdapter *audioAdapter, PRUint32 *audioController);
    nsresult (*SetAudioController)(IAudioAdapter *audioAdapter, PRUint32 audioController);
} vboxUniformedIAudioAdapter;

/* Functions for INetworkAdapter */
typedef struct {
    nsresult (*GetAttachmentType)(INetworkAdapter *adapter, PRUint32 *attachmentType);
    nsresult (*GetEnabled)(INetworkAdapter *adapter, PRBool *enabled);
    nsresult (*SetEnabled)(INetworkAdapter *adapter, PRBool enabled);
    nsresult (*GetAdapterType)(INetworkAdapter *adapter, PRUint32 *adapterType);
    nsresult (*SetAdapterType)(INetworkAdapter *adapter, PRUint32 adapterType);
    nsresult (*GetBridgedInterface)(INetworkAdapter *adapter, PRUnichar **bridgedInterface);
    nsresult (*SetBridgedInterface)(INetworkAdapter *adapter, PRUnichar *bridgedInterface);
    nsresult (*GetInternalNetwork)(INetworkAdapter *adapter, PRUnichar **internalNetwork);
    nsresult (*SetInternalNetwork)(INetworkAdapter *adapter, PRUnichar *internalNetwork);
    nsresult (*GetHostOnlyInterface)(INetworkAdapter *adapter, PRUnichar **hostOnlyInterface);
    nsresult (*SetHostOnlyInterface)(INetworkAdapter *adapter, PRUnichar *hostOnlyInterface);
    nsresult (*GetMACAddress)(INetworkAdapter *adapter, PRUnichar **MACAddress);
    nsresult (*SetMACAddress)(INetworkAdapter *adapter, PRUnichar *MACAddress);
    nsresult (*AttachToBridgedInterface)(INetworkAdapter *adapter);
    nsresult (*AttachToInternalNetwork)(INetworkAdapter *adapter);
    nsresult (*AttachToHostOnlyInterface)(INetworkAdapter *adapter);
    nsresult (*AttachToNAT)(INetworkAdapter *adapter);
} vboxUniformedINetworkAdapter;

/* Functions for ISerialPort */
typedef struct {
    nsresult (*GetEnabled)(ISerialPort *port, PRBool *enabled);
    nsresult (*SetEnabled)(ISerialPort *port, PRBool enabled);
    nsresult (*GetPath)(ISerialPort *port, PRUnichar **path);
    nsresult (*SetPath)(ISerialPort *port, PRUnichar *path);
    nsresult (*GetIRQ)(ISerialPort *port, PRUint32 *IRQ);
    nsresult (*SetIRQ)(ISerialPort *port, PRUint32 IRQ);
    nsresult (*GetIOBase)(ISerialPort *port, PRUint32 *IOBase);
    nsresult (*SetIOBase)(ISerialPort *port, PRUint32 IOBase);
    nsresult (*GetHostMode)(ISerialPort *port, PRUint32 *hostMode);
    nsresult (*SetHostMode)(ISerialPort *port, PRUint32 hostMode);
} vboxUniformedISerialPort;

/* Functions for IParallelPort */
typedef struct {
    nsresult (*GetEnabled)(IParallelPort *port, PRBool *enabled);
    nsresult (*SetEnabled)(IParallelPort *port, PRBool enabled);
    nsresult (*GetPath)(IParallelPort *port, PRUnichar **path);
    nsresult (*SetPath)(IParallelPort *port, PRUnichar *path);
    nsresult (*GetIRQ)(IParallelPort *port, PRUint32 *IRQ);
    nsresult (*SetIRQ)(IParallelPort *port, PRUint32 IRQ);
    nsresult (*GetIOBase)(IParallelPort *port, PRUint32 *IOBase);
    nsresult (*SetIOBase)(IParallelPort *port, PRUint32 IOBase);
} vboxUniformedIParallelPort;

/* Functions for IVRDEServer */
typedef struct {
    nsresult (*GetEnabled)(IVRDEServer *VRDEServer, PRBool *enabled);
    nsresult (*SetEnabled)(IVRDEServer *VRDEServer, PRBool enabled);
    nsresult (*GetPorts)(struct _vboxDriver *driver, IVRDEServer *VRDEServer,
                         IMachine *machine, virDomainGraphicsDef *graphics);
    nsresult (*SetPorts)(struct _vboxDriver *driver, IVRDEServer *VRDEServer,
                         virDomainGraphicsDef *graphics);
    nsresult (*GetReuseSingleConnection)(IVRDEServer *VRDEServer, PRBool *enabled);
    nsresult (*SetReuseSingleConnection)(IVRDEServer *VRDEServer, PRBool enabled);
    nsresult (*GetAllowMultiConnection)(IVRDEServer *VRDEServer, PRBool *enabled);
    nsresult (*SetAllowMultiConnection)(IVRDEServer *VRDEServer, PRBool enabled);
    nsresult (*GetNetAddress)(struct _vboxDriver *driver, IVRDEServer *VRDEServer,
                              PRUnichar **netAddress);
    nsresult (*SetNetAddress)(struct _vboxDriver *driver, IVRDEServer *VRDEServer,
                              PRUnichar *netAddress);
} vboxUniformedIVRDEServer;

/* Common Functions for IUSBController and IUSBDeviceFilters */
typedef struct {
    nsresult (*CreateDeviceFilter)(IUSBCommon *USBCommon, PRUnichar *name,
                                   IUSBDeviceFilter **filter);
    nsresult (*InsertDeviceFilter)(IUSBCommon *USBCommon, PRUint32 position,
                                   IUSBDeviceFilter *filter);
} vboxUniformedIUSBCommon;

typedef struct {
    nsresult (*GetProductId)(IUSBDeviceFilter *USBDeviceFilter, PRUnichar **productId);
    nsresult (*SetProductId)(IUSBDeviceFilter *USBDeviceFilter, PRUnichar *productId);
    nsresult (*GetActive)(IUSBDeviceFilter *USBDeviceFilter, PRBool *active);
    nsresult (*SetActive)(IUSBDeviceFilter *USBDeviceFilter, PRBool active);
    nsresult (*GetVendorId)(IUSBDeviceFilter *USBDeviceFilter, PRUnichar **vendorId);
    nsresult (*SetVendorId)(IUSBDeviceFilter *USBDeviceFilter, PRUnichar *vendorId);
} vboxUniformedIUSBDeviceFilter;

/* Functions for IMedium */
typedef struct {
    nsresult (*GetId)(IMedium *medium, vboxIID *iid);
    nsresult (*GetLocation)(IMedium *medium, PRUnichar **location);
    nsresult (*GetState)(IMedium *medium, PRUint32 *state);
    nsresult (*GetName)(IMedium *medium, PRUnichar **name);
    nsresult (*GetSize)(IMedium *medium, PRUint64 *uSize);
    nsresult (*GetReadOnly)(IMedium *medium, PRBool *readOnly);
    nsresult (*GetParent)(IMedium *medium, IMedium **parent);
    nsresult (*GetChildren)(IMedium *medium, PRUint32 *childrenSize,
                            IMedium ***children);
    nsresult (*GetFormat)(IMedium *medium, PRUnichar **format);
    nsresult (*DeleteStorage)(IMedium *medium, IProgress **progress);
    nsresult (*Release)(IMedium *medium);
    nsresult (*Close)(IMedium *medium);
    nsresult (*SetType)(IMedium *medium, PRUint32 type);
    nsresult (*CreateDiffStorage)(IMedium *medium, IMedium *target,
                                  PRUint32 variantSize, PRUint32 *variant,
                                  IProgress **progress);
    nsresult (*CreateBaseStorage)(IMedium *medium, PRUint64 logicalSize,
                                  PRUint32 variant, IProgress **progress);
    nsresult (*GetLogicalSize)(IMedium *medium, PRUint64 *uLogicalSize);
} vboxUniformedIMedium;

/* Functions for IMediumAttachment */
typedef struct {
    nsresult (*GetMedium)(IMediumAttachment *mediumAttachment, IMedium **medium);
    nsresult (*GetController)(IMediumAttachment *mediumAttachment, PRUnichar **controller);
    nsresult (*GetType)(IMediumAttachment *mediumAttachment, PRUint32 *type);
    nsresult (*GetPort)(IMediumAttachment *mediumAttachment, PRInt32 *port);
    nsresult (*GetDevice)(IMediumAttachment *mediumAttachment, PRInt32 *device);
} vboxUniformedIMediumAttachment;


/* Functions for IStorageController */
typedef struct {
    nsresult (*GetBus)(IStorageController *storageController, PRUint32 *bus);
    nsresult (*SetControllerType)(IStorageController *storageController, PRUint32 controllerType);
    nsresult (*GetControllerType)(IStorageController *storageController, PRUint32 *controllerType);
} vboxUniformedIStorageController;

/* Functions for ISharedFolder */
typedef struct {
    nsresult (*GetHostPath)(ISharedFolder *sharedFolder, PRUnichar **hostPath);
    nsresult (*GetName)(ISharedFolder *sharedFolder, PRUnichar **name);
    nsresult (*GetWritable)(ISharedFolder *sharedFolder, PRBool *writable);
} vboxUniformedISharedFolder;

/* Functions for ISnapshot */
typedef struct {
    nsresult (*GetName)(ISnapshot *snapshot, PRUnichar **name);
    nsresult (*GetId)(ISnapshot *snapshot, vboxIID *iid);
    nsresult (*GetMachine)(ISnapshot *snapshot, IMachine **machine);
    nsresult (*GetDescription)(ISnapshot *snapshot, PRUnichar **description);
    nsresult (*GetTimeStamp)(ISnapshot *snapshot, PRInt64 *timeStamp);
    nsresult (*GetParent)(ISnapshot *snapshot, ISnapshot **parent);
    nsresult (*GetOnline)(ISnapshot *snapshot, PRBool *online);
} vboxUniformedISnapshot;

/* Functions for IDisplay */
typedef struct {
    nsresult (*GetScreenResolution)(IDisplay *display,
                                    PRUint32 screenId,
                                    PRUint32 *width,
                                    PRUint32 *height,
                                    PRUint32 *bitsPerPixel,
                                    PRInt32 *xOrigin,
                                    PRInt32 *yOrigin);
    nsresult (*TakeScreenShotPNGToArray)(IDisplay *display,
                                         PRUint32 screenId,
                                         PRUint32 width,
                                         PRUint32 height,
                                         PRUint32 *screenDataSize,
                                         PRUint8** screenData);
} vboxUniformedIDisplay;

/* Functions for IHost */
typedef struct {
    nsresult (*FindHostNetworkInterfaceById)(IHost *host, vboxIID *iid,
                                             IHostNetworkInterface **networkInterface);
    nsresult (*FindHostNetworkInterfaceByName)(IHost *host, PRUnichar *name,
                                               IHostNetworkInterface **networkInterface);
    nsresult (*CreateHostOnlyNetworkInterface)(IHost *host,
                                               IHostNetworkInterface **networkInterface);
    nsresult (*RemoveHostOnlyNetworkInterface)(IHost *host, vboxIID *iid,
                                               IProgress **progress);
} vboxUniformedIHost;

/* Functions for IHostNetworkInterface */
typedef struct {
    nsresult (*GetInterfaceType)(IHostNetworkInterface *hni, PRUint32 *interfaceType);
    nsresult (*GetStatus)(IHostNetworkInterface *hni, PRUint32 *status);
    nsresult (*GetName)(IHostNetworkInterface *hni, PRUnichar **name);
    nsresult (*GetId)(IHostNetworkInterface *hni, vboxIID *iid);
    nsresult (*GetHardwareAddress)(IHostNetworkInterface *hni, PRUnichar **hardwareAddress);
    nsresult (*GetIPAddress)(IHostNetworkInterface *hni, PRUnichar **IPAddress);
    nsresult (*GetNetworkMask)(IHostNetworkInterface *hni, PRUnichar **networkMask);
    nsresult (*EnableStaticIPConfig)(IHostNetworkInterface *hni, PRUnichar *IPAddress,
                                     PRUnichar *networkMask);
    nsresult (*EnableDynamicIPConfig)(IHostNetworkInterface *hni);
    nsresult (*DHCPRediscover)(IHostNetworkInterface *hni);
} vboxUniformedIHNInterface;

/* Functions for IDHCPServer */
typedef struct {
    nsresult (*GetIPAddress)(IDHCPServer *dhcpServer, PRUnichar **IPAddress);
    nsresult (*GetNetworkMask)(IDHCPServer *dhcpServer, PRUnichar **networkMask);
    nsresult (*GetLowerIP)(IDHCPServer *dhcpServer, PRUnichar **lowerIP);
    nsresult (*GetUpperIP)(IDHCPServer *dhcpServer, PRUnichar **upperIP);
    nsresult (*SetEnabled)(IDHCPServer *dhcpServer, PRBool enabled);
    nsresult (*SetConfiguration)(IDHCPServer *dhcpServer, PRUnichar *IPAddress,
                                 PRUnichar *networkMask, PRUnichar *FromIPAddress,
                                 PRUnichar *ToIPAddress);
    nsresult (*Start)(IDHCPServer *dhcpServer,
                      PRUnichar *trunkName, PRUnichar *trunkType);
    nsresult (*Stop)(IDHCPServer *dhcpServer);
} vboxUniformedIDHCPServer;

typedef struct {
    nsresult (*PutScancode)(IKeyboard *keyboard, PRInt32 scancode);
    nsresult (*PutScancodes)(IKeyboard *keyboard, PRUint32 scancodesSize,
                             PRInt32 *scanCodes, PRUint32 *codesStored);
} vboxUniformedIKeyboard;

typedef struct {
    const nsID * (*GetIID)(void);
    nsresult (*GetComponent)(IVirtualBoxErrorInfo *errInfo, PRUnichar **component);
    nsresult (*GetNext)(IVirtualBoxErrorInfo *errInfo, IVirtualBoxErrorInfo **next);
    nsresult (*GetText)(IVirtualBoxErrorInfo *errInfo, PRUnichar **text);
} vboxUniformedIVirtualBoxErrorInfo;

typedef struct {
    bool (*Online)(PRUint32 state);
    bool (*Inactive)(PRUint32 state);
    bool (*NotStart)(PRUint32 state);
    bool (*Running)(PRUint32 state);
    bool (*Paused)(PRUint32 state);
    bool (*PoweredOff)(PRUint32 state);
} uniformedMachineStateChecker;

typedef struct {
    /* vbox API version */
    uint32_t APIVersion;
    uint32_t XPCOMCVersion;
    /* vbox APIs */
    nsresult (*unregisterMachine)(struct _vboxDriver *driver, vboxIID *iid, IMachine **machine);
    void (*deleteConfig)(IMachine *machine);
    void (*vboxAttachDrivesOld)(virDomainDef *def, struct _vboxDriver *driver, IMachine *machine);
    virDomainState (*vboxConvertState)(PRUint32 state);
    int (*snapshotRestore)(virDomainPtr dom, IMachine *machine, ISnapshot *snapshot);
    vboxUniformedPFN UPFN;
    vboxUniformedIID UIID;
    vboxUniformedArray UArray;
    vboxUniformednsISupports nsUISupports;
    vboxUniformedIVirtualBox UIVirtualBox;
    vboxUniformedIMachine UIMachine;
    vboxUniformedISession UISession;
    vboxUniformedIConsole UIConsole;
    vboxUniformedIProgress UIProgress;
    vboxUniformedISystemProperties UISystemProperties;
    vboxUniformedIBIOSSettings UIBIOSSettings;
    vboxUniformedIAudioAdapter UIAudioAdapter;
    vboxUniformedINetworkAdapter UINetworkAdapter;
    vboxUniformedISerialPort UISerialPort;
    vboxUniformedIParallelPort UIParallelPort;
    vboxUniformedIVRDEServer UIVRDEServer;
    vboxUniformedIUSBCommon UIUSBCommon;
    vboxUniformedIUSBDeviceFilter UIUSBDeviceFilter;
    vboxUniformedIMedium UIMedium;
    vboxUniformedIMediumAttachment UIMediumAttachment;
    vboxUniformedIStorageController UIStorageController;
    vboxUniformedISharedFolder UISharedFolder;
    vboxUniformedISnapshot UISnapshot;
    vboxUniformedIDisplay UIDisplay;
    vboxUniformedIHost UIHost;
    vboxUniformedIHNInterface UIHNInterface;
    vboxUniformedIDHCPServer UIDHCPServer;
    vboxUniformedIKeyboard UIKeyboard;
    vboxUniformedIVirtualBoxErrorInfo UIVirtualBoxErrorInfo;
    uniformedMachineStateChecker machineStateChecker;
    /* vbox API features */
    bool chipsetType;
    bool vboxSnapshotRedefine;
} vboxUniformedAPI;

virDomainPtr vboxDomainLookupByUUID(virConnectPtr conn,
                                    const unsigned char *uuid);

/* Version specified functions for installing uniformed API */
void vbox61InstallUniformedAPI(vboxUniformedAPI *pVBoxAPI);
void vbox70InstallUniformedAPI(vboxUniformedAPI *pVBoxAPI);
