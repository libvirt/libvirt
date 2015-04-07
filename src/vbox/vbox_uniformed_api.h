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

#ifndef VBOX_UNIFORMED_API_H
# define VBOX_UNIFORMED_API_H

# include "internal.h"

/* This file may be used in three place. That is vbox_tmpl.c,
 * vbox_common.c and vbox_driver.c. The vboxUniformedAPI and some
 * types used for vboxUniformedAPI is defined here.
 *
 * The vbox_tmpl.c is the only place where the driver knows the inside
 * architecture of those vbox structs(vboxObj, vboxSession,
 * pFuncs, vboxCallback and vboxQueue). The file should be included
 * after the currect vbox_CAPI_v*.h, then we can use the vbox structs
 * in vboxGlobalData. The vbox_tmpl.c should implement functions
 * defined in vboxUniformedAPI.
 *
 * In vbox_driver.c, it is used to define the struct vboxUniformedAPI.
 * The vbox_driver.c collects vboxUniformedAPI for all versions.
 * Then vboxRegister calls the vboxRegisterUniformedAPI to register.
 * Note: In vbox_driver.c, the vbox structs in vboxGlobalData is
 * defined by vbox_CAPI_v2.2.h.
 *
 * The vbox_common.c, it is used to generate common codes for all vbox
 * versions. Bacause the same member varible's offset in a vbox struct
 * may change between different vbox versions. The vbox_common.c
 * shouldn't directly use struct's member varibles defined in
 * vbox_CAPI_v*.h. To make things safety, we include the
 * vbox_common.h in vbox_common.c. In this case, we treat structs
 * defined by vbox as a void*. The common codes don't concern about
 * the inside of this structs(actually, we can't, in the common level).
 * With the help of vboxUniformed API, we call VirtualBox's API and
 * implement the vbox driver in a high level.
 *
 * In conclusion:
 *  * In vbox_tmpl.c, this file is included after vbox_CAPI_v*.h
 *  * In vbox_driver.c, this file is included after vbox_glue.h
 *  * In vbox_common.c, this file is included after vbox_common.h
 *
 */

/* Extracted define from vbox_tmpl.c */

# ifdef WIN32
struct _vboxIID_v2_x_WIN32 {
    /* IID is represented by a GUID value. */
    GUID value;
};
# endif /* !WIN32 */

struct _vboxIID_v2_x {
    /* IID is represented by a pointer to a nsID. */
    nsID *value;

    /* backing is used in cases where we need to create or copy an IID.
     * We cannot allocate memory that can be freed by ComUnallocMem.
     * Therefore, we use this stack allocated nsID instead. */
    nsID backing;
};

struct _vboxIID_v3_x {
    /* IID is represented by a UTF-16 encoded UUID in string form. */
    PRUnichar *value;

    /* owner indicates if we own the value and need to free it. */
    bool owner;
};

typedef union {
# ifdef WIN32
    struct _vboxIID_v2_x_WIN32 vboxIID_v2_x_WIN32;
# endif /* !WIN32 */
    struct _vboxIID_v2_x vboxIID_v2_x;
    struct _vboxIID_v3_x vboxIID_v3_x;
} vboxIIDUnion;

typedef union {
    nsresult uResultCode;
    PRInt32 resultCode;
} resultCodeUnion;

typedef struct {
    virMutex lock;
    unsigned long version;

    virCapsPtr caps;
    virDomainXMLOptionPtr xmlopt;

    IVirtualBox *vboxObj;
    ISession *vboxSession;

    /** Our version specific API table pointer. */
    PCVBOXXPCOM pFuncs;

    /* The next is used for domainEvent */
# if defined(VBOX_API_VERSION) && VBOX_API_VERSION > 2002000 && VBOX_API_VERSION < 4000000

    /* Async event handling */
    virObjectEventStatePtr domainEvents;
    int fdWatch;
    IVirtualBoxCallback *vboxCallback;
    nsIEventQueue  *vboxQueue;

    int volatile vboxCallBackRefCount;

    /* pointer back to the connection */
    virConnectPtr conn;

# else /* VBOX_API_VERSION <= 2002000 || VBOX_API_VERSION >= 4000000 || VBOX_API_VERSION undefined */

    virObjectEventStatePtr domainEvents;
    int fdWatch;
    void *vboxCallback;
    void *vboxQueue;
    int volatile vboxCallBackRefCount;
    virConnectPtr conn;

# endif /* VBOX_API_VERSION <= 2002000 || VBOX_API_VERSION >= 4000000 || VBOX_API_VERSION undefined */

} vboxGlobalData;

/* vboxUniformedAPI gives vbox_common.c a uniformed layer to see
 * vbox API.
 */

/* Functions for pFuncs */
typedef struct {
    int (*Initialize)(vboxGlobalData *data);
    void (*Uninitialize)(vboxGlobalData *data);
    void (*ComUnallocMem)(PCVBOXXPCOM pFuncs, void *pv);
    void (*Utf16Free)(PCVBOXXPCOM pFuncs, PRUnichar *pwszString);
    void (*Utf8Free)(PCVBOXXPCOM pFuncs, char *pszString);
    int (*Utf16ToUtf8)(PCVBOXXPCOM pFuncs, const PRUnichar *pwszString, char **ppszString);
    int (*Utf8ToUtf16)(PCVBOXXPCOM pFuncs, const char *pszString, PRUnichar **ppwszString);
} vboxUniformedPFN;

/* Functions for vboxIID */
typedef struct {
    void (*vboxIIDInitialize)(vboxIIDUnion *iidu);
    void (*vboxIIDUnalloc)(vboxGlobalData *data, vboxIIDUnion *iidu);
    void (*vboxIIDToUUID)(vboxGlobalData *data, vboxIIDUnion *iidu, unsigned char *uuid);
    void (*vboxIIDFromUUID)(vboxGlobalData *data, vboxIIDUnion *iidu, const unsigned char *uuid);
    bool (*vboxIIDIsEqual)(vboxGlobalData *data, vboxIIDUnion *iidu1, vboxIIDUnion *iidu2);
    void (*vboxIIDFromArrayItem)(vboxGlobalData *data, vboxIIDUnion *iidu, vboxArray *array, int idx);
    void (*vboxIIDToUtf8)(vboxGlobalData *data, vboxIIDUnion *iidu, char **utf8);
    void (*DEBUGIID)(const char *msg, vboxIIDUnion *iidu);
} vboxUniformedIID;

/* Functions for vboxArray */
typedef struct {
    nsresult (*vboxArrayGet)(vboxArray *array, void *self, void *getter);
    nsresult (*vboxArrayGetWithIIDArg)(vboxArray *array, void *self, void *getter, vboxIIDUnion *iidu);
    void (*vboxArrayRelease)(vboxArray *array);
    void (*vboxArrayUnalloc)(vboxArray *array);
    /* Generate function pointers for vboxArrayGet */
    void* (*handleGetMachines)(IVirtualBox *vboxObj);
    void* (*handleGetHardDisks)(IVirtualBox *vboxObj);
    void* (*handleUSBGetDeviceFilters)(IUSBCommon *USBCommon);
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
    nsresult (*Release)(nsISupports *nsi);
    nsresult (*AddRef)(nsISupports *nsi);
} vboxUniformednsISupports;

/* Functions for IVirtualBox */
typedef struct {
    nsresult (*GetVersion)(IVirtualBox *vboxObj, PRUnichar **versionUtf16);
    nsresult (*GetMachine)(IVirtualBox *vboxObj, vboxIIDUnion *iidu, IMachine **machine);
    nsresult (*OpenMachine)(IVirtualBox *vboxObj, PRUnichar *settingsFile, IMachine **machine);
    nsresult (*GetSystemProperties)(IVirtualBox *vboxObj, ISystemProperties **systemProperties);
    nsresult (*GetHost)(IVirtualBox *vboxObj, IHost **host);
    nsresult (*CreateMachine)(vboxGlobalData *data, virDomainDefPtr def, IMachine **machine, char *uuidstr);
    nsresult (*CreateHardDisk)(IVirtualBox *vboxObj, PRUnichar *format, PRUnichar *location, IHardDisk **hardDisk);
    nsresult (*RegisterMachine)(IVirtualBox *vboxObj, IMachine *machine);
    nsresult (*FindHardDisk)(IVirtualBox *vboxObj, PRUnichar *location, PRUint32 deviceType,
                             PRUint32 accessMode, IHardDisk **hardDisk);
    nsresult (*OpenMedium)(IVirtualBox *vboxObj, PRUnichar *location, PRUint32 deviceType, PRUint32 accessMode, IMedium **medium);
    nsresult (*GetHardDiskByIID)(IVirtualBox *vboxObj, vboxIIDUnion *iidu, IHardDisk **hardDisk);
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
    nsresult (*LaunchVMProcess)(vboxGlobalData *data, IMachine *machine,
                                vboxIIDUnion *iidu,
                                PRUnichar *sessionType, PRUnichar *env,
                                IProgress **progress);
    nsresult (*Unregister)(IMachine *machine, PRUint32 cleanupMode,
                           PRUint32 *aMediaSize, IMedium ***aMedia);
    nsresult (*FindSnapshot)(IMachine *machine, vboxIIDUnion *iidu, ISnapshot **snapshot);
    nsresult (*DetachDevice)(IMachine *machine, PRUnichar *name,
                             PRInt32 controllerPort, PRInt32 device);
    nsresult (*GetAccessible)(IMachine *machine, PRBool *isAccessible);
    nsresult (*GetState)(IMachine *machine, PRUint32 *state);
    nsresult (*GetName)(IMachine *machine, PRUnichar **name);
    nsresult (*GetId)(IMachine *machine, vboxIIDUnion *iidu);
    nsresult (*GetBIOSSettings)(IMachine *machine, IBIOSSettings **bios);
    nsresult (*GetAudioAdapter)(IMachine *machine, IAudioAdapter **audioAdapter);
    nsresult (*GetNetworkAdapter)(IMachine *machine, PRUint32 slot, INetworkAdapter **adapter);
    nsresult (*GetChipsetType)(IMachine *machine, PRUint32 *chipsetType);
    nsresult (*GetSerialPort)(IMachine *machine, PRUint32 slot, ISerialPort **port);
    nsresult (*GetParallelPort)(IMachine *machine, PRUint32 slot, IParallelPort **port);
    nsresult (*GetVRDxServer)(IMachine *machine, IVRDxServer **VRDxServer);
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
    nsresult (*Open)(vboxGlobalData *data, vboxIIDUnion *iidu, IMachine *machine);
    nsresult (*OpenExisting)(vboxGlobalData *data, vboxIIDUnion *iidu, IMachine *machine);
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
    nsresult (*DeleteSnapshot)(IConsole *console, vboxIIDUnion *iidu, IProgress **progress);
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

/* Functions for IVRDPServer and IVRDEServer */
typedef struct {
    nsresult (*GetEnabled)(IVRDxServer *VRDxServer, PRBool *enabled);
    nsresult (*SetEnabled)(IVRDxServer *VRDxServer, PRBool enabled);
    nsresult (*GetPorts)(vboxGlobalData *data, IVRDxServer *VRDxServer,
                         virDomainGraphicsDefPtr graphics);
    nsresult (*SetPorts)(vboxGlobalData *data, IVRDxServer *VRDxServer,
                         virDomainGraphicsDefPtr graphics);
    nsresult (*GetReuseSingleConnection)(IVRDxServer *VRDxServer, PRBool *enabled);
    nsresult (*SetReuseSingleConnection)(IVRDxServer *VRDxServer, PRBool enabled);
    nsresult (*GetAllowMultiConnection)(IVRDxServer *VRDxServer, PRBool *enabled);
    nsresult (*SetAllowMultiConnection)(IVRDxServer *VRDxServer, PRBool enabled);
    nsresult (*GetNetAddress)(vboxGlobalData *data, IVRDxServer *VRDxServer,
                              PRUnichar **netAddress);
    nsresult (*SetNetAddress)(vboxGlobalData *data, IVRDxServer *VRDxServer,
                              PRUnichar *netAddress);
} vboxUniformedIVRDxServer;

/* Common Functions for IUSBController and IUSBDeviceFilters */
typedef struct {
    nsresult (*Enable)(IUSBCommon *USBCommon);
    nsresult (*GetEnabled)(IUSBCommon *USBCommon, PRBool *enabled);
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
    nsresult (*GetId)(IMedium *medium, vboxIIDUnion *iidu);
    nsresult (*GetLocation)(IMedium *medium, PRUnichar **location);
    nsresult (*GetState)(IMedium *medium, PRUint32 *state);
    nsresult (*GetName)(IMedium *medium, PRUnichar **name);
    nsresult (*GetSize)(IMedium *medium, PRUint64 *uSize);
    nsresult (*GetReadOnly)(IMedium *medium, PRBool *readOnly);
    nsresult (*GetParent)(IMedium *medium, IMedium **parent);
    nsresult (*GetChildren)(IMedium *medium, PRUint32 *childrenSize, IMedium ***children);
    nsresult (*GetFormat)(IMedium *medium, PRUnichar **format);
    nsresult (*DeleteStorage)(IMedium *medium, IProgress **progress);
    nsresult (*Release)(IMedium *medium);
    nsresult (*Close)(IMedium *medium);
    nsresult (*SetType)(IMedium *medium, PRUint32 type);
    nsresult (*CreateDiffStorage)(IMedium *medium, IMedium *target, PRUint32 variantSize,
                                  PRUint32 *variant, IProgress **progress);
} vboxUniformedIMedium;

/* Functions for IMediumAttachment */
typedef struct {
    nsresult (*GetMedium)(IMediumAttachment *mediumAttachment, IHardDisk **hardDisk);
    nsresult (*GetController)(IMediumAttachment *mediumAttachment, PRUnichar **controller);
    nsresult (*GetType)(IMediumAttachment *mediumAttachment, PRUint32 *type);
    nsresult (*GetPort)(IMediumAttachment *mediumAttachment, PRInt32 *port);
    nsresult (*GetDevice)(IMediumAttachment *mediumAttachment, PRInt32 *device);
} vboxUniformedIMediumAttachment;


/* Functions for IStorageController */
typedef struct {
    nsresult (*GetBus)(IStorageController *storageController, PRUint32 *bus);
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
    nsresult (*GetId)(ISnapshot *snapshot, vboxIIDUnion *iidu);
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
    nsresult (*FindHostNetworkInterfaceById)(IHost *host, vboxIIDUnion *iidu,
                                             IHostNetworkInterface **networkInterface);
    nsresult (*FindHostNetworkInterfaceByName)(IHost *host, PRUnichar *name,
                                               IHostNetworkInterface **networkInterface);
    nsresult (*CreateHostOnlyNetworkInterface)(vboxGlobalData *data,
                                               IHost *host, char *name,
                                               IHostNetworkInterface **networkInterface);
    nsresult (*RemoveHostOnlyNetworkInterface)(IHost *host, vboxIIDUnion *iidu,
                                               IProgress **progress);
} vboxUniformedIHost;

/* Functions for IHostNetworkInterface */
typedef struct {
    nsresult (*GetInterfaceType)(IHostNetworkInterface *hni, PRUint32 *interfaceType);
    nsresult (*GetStatus)(IHostNetworkInterface *hni, PRUint32 *status);
    nsresult (*GetName)(IHostNetworkInterface *hni, PRUnichar **name);
    nsresult (*GetId)(IHostNetworkInterface *hni, vboxIIDUnion *iidu);
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
    nsresult (*Start)(IDHCPServer *dhcpServer, PRUnichar *networkName,
                      PRUnichar *trunkName, PRUnichar *trunkType);
    nsresult (*Stop)(IDHCPServer *dhcpServer);
} vboxUniformedIDHCPServer;

/* Functions for IHardDisk, in vbox3.1 and later, it will call the
 * corresponding functions in IMedium as IHardDisk does't exist in
 * these versions. */
typedef struct {
    nsresult (*CreateBaseStorage)(IHardDisk *hardDisk, PRUint64 logicalSize,
                                  PRUint32 variant, IProgress **progress);
    nsresult (*DeleteStorage)(IHardDisk *hardDisk, IProgress **progress);
    nsresult (*GetLogicalSizeInByte)(IHardDisk *hardDisk, PRUint64 *uLogicalSize);
    nsresult (*GetFormat)(IHardDisk *hardDisk, PRUnichar **format);
} vboxUniformedIHardDisk;

typedef struct {
    nsresult (*PutScancode)(IKeyboard *keyboard, PRInt32 scancode);
    nsresult (*PutScancodes)(IKeyboard *keyboard, PRUint32 scancodesSize,
                             PRInt32 *scanCodes, PRUint32 *codesStored);
} vboxUniformedIKeyboard;

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
    int (*initializeDomainEvent)(vboxGlobalData *data);
    void (*registerGlobalData)(vboxGlobalData *data);
    void (*detachDevices)(vboxGlobalData *data, IMachine *machine, PRUnichar *hddcnameUtf16);
    nsresult (*unregisterMachine)(vboxGlobalData *data, vboxIIDUnion *iidu, IMachine **machine);
    void (*deleteConfig)(IMachine *machine);
    void (*vboxAttachDrivesOld)(virDomainDefPtr def, vboxGlobalData *data, IMachine *machine);
    virDomainState (*vboxConvertState)(PRUint32 state);
    void (*dumpIDEHDDsOld)(virDomainDefPtr def, vboxGlobalData *data, IMachine *machine);
    void (*dumpDVD)(virDomainDefPtr def, vboxGlobalData *data, IMachine *machine);
    int (*attachDVD)(vboxGlobalData *data, IMachine *machine, const char *src);
    int (*detachDVD)(IMachine *machine);
    void (*dumpFloppy)(virDomainDefPtr def, vboxGlobalData *data, IMachine *machine);
    int (*attachFloppy)(vboxGlobalData *data, IMachine *machine, const char *src);
    int (*detachFloppy)(IMachine *machine);
    int (*snapshotRestore)(virDomainPtr dom, IMachine *machine, ISnapshot *snapshot);
    void (*registerDomainEvent)(virHypervisorDriverPtr driver);
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
    vboxUniformedIVRDxServer UIVRDxServer;
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
    vboxUniformedIHardDisk UIHardDisk;
    vboxUniformedIKeyboard UIKeyboard;
    uniformedMachineStateChecker machineStateChecker;
    /* vbox API features */
    bool domainEventCallbacks;
    bool hasStaticGlobalData;
    bool getMachineForSession;
    bool detachDevicesExplicitly;
    bool chipsetType;
    bool accelerate2DVideo;
    bool vboxAttachDrivesUseOld;
    bool oldMediumInterface;
    bool vboxSnapshotRedefine;
    bool supportScreenshot;
    bool networkRemoveInterface;
} vboxUniformedAPI;

virDomainPtr vboxDomainLookupByUUID(virConnectPtr conn,
                                    const unsigned char *uuid);

/* Version specified functions for installing uniformed API */
void vbox22InstallUniformedAPI(vboxUniformedAPI *pVBoxAPI);
void vbox30InstallUniformedAPI(vboxUniformedAPI *pVBoxAPI);
void vbox31InstallUniformedAPI(vboxUniformedAPI *pVBoxAPI);
void vbox32InstallUniformedAPI(vboxUniformedAPI *pVBoxAPI);
void vbox40InstallUniformedAPI(vboxUniformedAPI *pVBoxAPI);
void vbox41InstallUniformedAPI(vboxUniformedAPI *pVBoxAPI);
void vbox42InstallUniformedAPI(vboxUniformedAPI *pVBoxAPI);
void vbox42_20InstallUniformedAPI(vboxUniformedAPI *pVBoxAPI);
void vbox43InstallUniformedAPI(vboxUniformedAPI *pVBoxAPI);
void vbox43_4InstallUniformedAPI(vboxUniformedAPI *pVBoxAPI);

#endif /* VBOX_UNIFORMED_API_H */
