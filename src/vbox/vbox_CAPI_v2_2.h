
/*
 *  DO NOT EDIT! This is a generated file.
 *
 *  XPCOM IDL (XPIDL) definition for VirtualBox Main API (COM interfaces)
 *  generated from XIDL (XML interface definition).
 *
 *  Source    : src/VBox/Main/idl/VirtualBox.xidl
 *  Generator : src/VBox/Main/idl/xpcidl.xsl
 *
 *  This file contains portions from the following Mozilla XPCOM files:
 *      xpcom/include/xpcom/nsID.h
 *      xpcom/include/nsIException.h
 *      xpcom/include/nsprpub/prtypes.h
 *      xpcom/include/xpcom/nsISupportsBase.h
 *
 * These files were originally triple-licensed (MPL/GPL2/LGPL2.1). Sun
 * elects to distribute this derived work under the LGPL2.1 only.
 */

/*
 * Copyright (C) 2008-2009 Sun Microsystems, Inc.
 *
 * This file is part of a free software library; you can redistribute
 * it and/or modify it under the terms of the GNU Lesser General
 * Public License version 2.1 as published by the Free Software
 * Foundation and shipped in the "COPYING" file with this library.
 * The library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY of any kind.
 *
 * Sun LGPL Disclaimer: For the avoidance of doubt, except that if
 * any license choice other than GPL or LGPL is available it will
 * apply instead, Sun elects to use only the Lesser General Public
 * License version 2.1 (LGPLv2) at this time for any software where
 * a choice of LGPL license versions is made available with the
 * language indicating that LGPLv2 or any later version may be used,
 * or where a choice of which version of the LGPL is applied is
 * otherwise unspecified.
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa
 * Clara, CA 95054 USA or visit http://www.sun.com if you need
 * additional information or have any questions.
 */

#ifndef ___VirtualBox_CXPCOM_h
#define ___VirtualBox_CXPCOM_h

#ifdef __cplusplus
# include "VirtualBox_XPCOM.h"
#else /* !__cplusplus */

#include <stddef.h>
#include "wchar.h"

#if defined(WIN32)

#define PR_EXPORT(__type) extern __declspec(dllexport) __type
#define PR_EXPORT_DATA(__type) extern __declspec(dllexport) __type
#define PR_IMPORT(__type) __declspec(dllimport) __type
#define PR_IMPORT_DATA(__type) __declspec(dllimport) __type

#define PR_EXTERN(__type) extern __declspec(dllexport) __type
#define PR_IMPLEMENT(__type) __declspec(dllexport) __type
#define PR_EXTERN_DATA(__type) extern __declspec(dllexport) __type
#define PR_IMPLEMENT_DATA(__type) __declspec(dllexport) __type

#define PR_CALLBACK
#define PR_CALLBACK_DECL
#define PR_STATIC_CALLBACK(__x) static __x

#elif defined(XP_BEOS)

#define PR_EXPORT(__type) extern __declspec(dllexport) __type
#define PR_EXPORT_DATA(__type) extern __declspec(dllexport) __type
#define PR_IMPORT(__type) extern __declspec(dllexport) __type
#define PR_IMPORT_DATA(__type) extern __declspec(dllexport) __type

#define PR_EXTERN(__type) extern __declspec(dllexport) __type
#define PR_IMPLEMENT(__type) __declspec(dllexport) __type
#define PR_EXTERN_DATA(__type) extern __declspec(dllexport) __type
#define PR_IMPLEMENT_DATA(__type) __declspec(dllexport) __type

#define PR_CALLBACK
#define PR_CALLBACK_DECL
#define PR_STATIC_CALLBACK(__x) static __x

#elif defined(WIN16)

#define PR_CALLBACK_DECL        __cdecl

#if defined(_WINDLL)
#define PR_EXPORT(__type) extern __type _cdecl _export _loadds
#define PR_IMPORT(__type) extern __type _cdecl _export _loadds
#define PR_EXPORT_DATA(__type) extern __type _export
#define PR_IMPORT_DATA(__type) extern __type _export

#define PR_EXTERN(__type) extern __type _cdecl _export _loadds
#define PR_IMPLEMENT(__type) __type _cdecl _export _loadds
#define PR_EXTERN_DATA(__type) extern __type _export
#define PR_IMPLEMENT_DATA(__type) __type _export

#define PR_CALLBACK             __cdecl __loadds
#define PR_STATIC_CALLBACK(__x) static __x PR_CALLBACK

#else /* this must be .EXE */
#define PR_EXPORT(__type) extern __type _cdecl _export
#define PR_IMPORT(__type) extern __type _cdecl _export
#define PR_EXPORT_DATA(__type) extern __type _export
#define PR_IMPORT_DATA(__type) extern __type _export

#define PR_EXTERN(__type) extern __type _cdecl _export
#define PR_IMPLEMENT(__type) __type _cdecl _export
#define PR_EXTERN_DATA(__type) extern __type _export
#define PR_IMPLEMENT_DATA(__type) __type _export

#define PR_CALLBACK             __cdecl __loadds
#define PR_STATIC_CALLBACK(__x) __x PR_CALLBACK
#endif /* _WINDLL */

#elif defined(XP_MAC)

#define PR_EXPORT(__type) extern __declspec(export) __type
#define PR_EXPORT_DATA(__type) extern __declspec(export) __type
#define PR_IMPORT(__type) extern __declspec(export) __type
#define PR_IMPORT_DATA(__type) extern __declspec(export) __type

#define PR_EXTERN(__type) extern __declspec(export) __type
#define PR_IMPLEMENT(__type) __declspec(export) __type
#define PR_EXTERN_DATA(__type) extern __declspec(export) __type
#define PR_IMPLEMENT_DATA(__type) __declspec(export) __type

#define PR_CALLBACK
#define PR_CALLBACK_DECL
#define PR_STATIC_CALLBACK(__x) static __x

#elif defined(XP_OS2) && defined(__declspec)

#define PR_EXPORT(__type) extern __declspec(dllexport) __type
#define PR_EXPORT_DATA(__type) extern __declspec(dllexport) __type
#define PR_IMPORT(__type) __declspec(dllimport) __type
#define PR_IMPORT_DATA(__type) __declspec(dllimport) __type

#define PR_EXTERN(__type) extern __declspec(dllexport) __type
#define PR_IMPLEMENT(__type) __declspec(dllexport) __type
#define PR_EXTERN_DATA(__type) extern __declspec(dllexport) __type
#define PR_IMPLEMENT_DATA(__type) __declspec(dllexport) __type

#define PR_CALLBACK
#define PR_CALLBACK_DECL
#define PR_STATIC_CALLBACK(__x) static __x

#elif defined(XP_OS2_VACPP)

#define PR_EXPORT(__type) extern __type
#define PR_EXPORT_DATA(__type) extern __type
#define PR_IMPORT(__type) extern __type
#define PR_IMPORT_DATA(__type) extern __type

#define PR_EXTERN(__type) extern __type
#define PR_IMPLEMENT(__type) __type
#define PR_EXTERN_DATA(__type) extern __type
#define PR_IMPLEMENT_DATA(__type) __type
#define PR_CALLBACK _Optlink
#define PR_CALLBACK_DECL
#define PR_STATIC_CALLBACK(__x) static __x PR_CALLBACK

#else /* Unix */

# ifdef VBOX_HAVE_VISIBILITY_HIDDEN
#  define PR_EXPORT(__type) __attribute__((visibility("default"))) extern __type
#  define PR_EXPORT_DATA(__type) __attribute__((visibility("default"))) extern __type
#  define PR_IMPORT(__type) extern __type
#  define PR_IMPORT_DATA(__type) extern __type
#  define PR_EXTERN(__type) __attribute__((visibility("default"))) extern __type
#  define PR_IMPLEMENT(__type) __attribute__((visibility("default"))) __type
#  define PR_EXTERN_DATA(__type) __attribute__((visibility("default"))) extern __type
#  define PR_IMPLEMENT_DATA(__type) __attribute__((visibility("default"))) __type
#  define PR_CALLBACK
#  define PR_CALLBACK_DECL
#  define PR_STATIC_CALLBACK(__x) static __x
# else
#  define PR_EXPORT(__type) extern __type
#  define PR_EXPORT_DATA(__type) extern __type
#  define PR_IMPORT(__type) extern __type
#  define PR_IMPORT_DATA(__type) extern __type
#  define PR_EXTERN(__type) extern __type
#  define PR_IMPLEMENT(__type) __type
#  define PR_EXTERN_DATA(__type) extern __type
#  define PR_IMPLEMENT_DATA(__type) __type
#  define PR_CALLBACK
#  define PR_CALLBACK_DECL
#  define PR_STATIC_CALLBACK(__x) static __x
# endif
#endif

#if defined(_NSPR_BUILD_)
#define NSPR_API(__type) PR_EXPORT(__type)
#define NSPR_DATA_API(__type) PR_EXPORT_DATA(__type)
#else
#define NSPR_API(__type) PR_IMPORT(__type)
#define NSPR_DATA_API(__type) PR_IMPORT_DATA(__type)
#endif

typedef unsigned char PRUint8;
#if (defined(HPUX) && defined(__cplusplus) \
        && !defined(__GNUC__) && __cplusplus < 199707L) \
    || (defined(SCO) && defined(__cplusplus) \
        && !defined(__GNUC__) && __cplusplus == 1L)
typedef char PRInt8;
#else
typedef signed char PRInt8;
#endif

#define PR_INT8_MAX 127
#define PR_INT8_MIN (-128)
#define PR_UINT8_MAX 255U

typedef unsigned short PRUint16;
typedef short PRInt16;

#define PR_INT16_MAX 32767
#define PR_INT16_MIN (-32768)
#define PR_UINT16_MAX 65535U

typedef unsigned int PRUint32;
typedef int PRInt32;
#define PR_INT32(x)  x
#define PR_UINT32(x) x ## U

#define PR_INT32_MAX PR_INT32(2147483647)
#define PR_INT32_MIN (-PR_INT32_MAX - 1)
#define PR_UINT32_MAX PR_UINT32(4294967295)

typedef long PRInt64;
typedef unsigned long PRUint64;
typedef int PRIntn;
typedef unsigned int PRUintn;

typedef double          PRFloat64;
typedef size_t PRSize;

typedef ptrdiff_t PRPtrdiff;

typedef unsigned long PRUptrdiff;

typedef PRIntn PRBool;

#define PR_TRUE 1
#define PR_FALSE 0

typedef PRUint8 PRPackedBool;

/*
** Status code used by some routines that have a single point of failure or
** special status return.
*/
typedef enum { PR_FAILURE = -1, PR_SUCCESS = 0 } PRStatus;

#ifndef __PRUNICHAR__
#define __PRUNICHAR__
#if defined(WIN32) || defined(XP_MAC)
typedef wchar_t PRUnichar;
#else
typedef PRUint16 PRUnichar;
#endif
#endif

typedef long PRWord;
typedef unsigned long PRUword;

#define nsnull 0
typedef PRUint32 nsresult;

#if defined(__GNUC__) && (__GNUC__ > 2)
#define NS_LIKELY(x)    (__builtin_expect((x), 1))
#define NS_UNLIKELY(x)  (__builtin_expect((x), 0))
#else
#define NS_LIKELY(x)    (x)
#define NS_UNLIKELY(x)  (x)
#endif

#define NS_FAILED(_nsresult) (NS_UNLIKELY((_nsresult) & 0x80000000))
#define NS_SUCCEEDED(_nsresult) (NS_LIKELY(!((_nsresult) & 0x80000000)))

/**
 * An "interface id" which can be used to uniquely identify a given
 * interface.
 * A "unique identifier". This is modeled after OSF DCE UUIDs.
 */

struct nsID {
  PRUint32 m0;
  PRUint16 m1;
  PRUint16 m2;
  PRUint8 m3[8];
};

typedef struct nsID nsID;
typedef nsID nsIID;

struct nsISupports;   /* forward declaration */
struct nsIStackFrame; /* forward declaration */
struct nsIException;  /* forward declaration */
typedef struct nsISupports nsISupports;     /* forward declaration */
typedef struct nsIStackFrame nsIStackFrame; /* forward declaration */
typedef struct nsIException nsIException;   /* forward declaration */

/**
 * IID for the nsISupports interface
 * {00000000-0000-0000-c000-000000000046}
 *
 * To maintain binary compatibility with COM's IUnknown, we define the IID
 * of nsISupports to be the same as that of COM's IUnknown.
 */
#define NS_ISUPPORTS_IID                                                      \
  { 0x00000000, 0x0000, 0x0000,                                               \
    {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46} }

/**
 * Reference count values
 *
 * This is the return type for AddRef() and Release() in nsISupports.
 * IUnknown of COM returns an unsigned long from equivalent functions.
 * The following ifdef exists to maintain binary compatibility with
 * IUnknown.
 */

/**
 * Basic component object model interface. Objects which implement
 * this interface support runtime interface discovery (QueryInterface)
 * and a reference counted memory model (AddRef/Release). This is
 * modelled after the win32 IUnknown API.
 */
struct nsISupports_vtbl {

  /**
   * @name Methods
   */

  /**
   * A run time mechanism for interface discovery.
   * @param aIID         [in]  A requested interface IID
   * @param aInstancePtr [out] A pointer to an interface pointer to
   *                           receive the result.
   * @return            NS_OK if the interface is supported by the associated
   *                          instance, NS_NOINTERFACE if it is not.
   * NS_ERROR_INVALID_POINTER if aInstancePtr is NULL.
   */
  nsresult (*QueryInterface)(nsISupports *pThis, const nsID *iid, void **resultp);
  /**
   * Increases the reference count for this interface.
   * The associated instance will not be deleted unless
   * the reference count is returned to zero.
   *
   * @return The resulting reference count.
   */
  nsresult (*AddRef)(nsISupports *pThis);

  /**
   * Decreases the reference count for this interface.
   * Generally, if the reference count returns to zero,
   * the associated instance is deleted.
   *
   * @return The resulting reference count.
   */
  nsresult (*Release)(nsISupports *pThis);

};

struct nsISupports {
    struct nsISupports_vtbl *vtbl;
};

/* starting interface:    nsIException */
#define NS_IEXCEPTION_IID_STR "f3a8d3b4-c424-4edc-8bf6-8974c983ba78"

#define NS_IEXCEPTION_IID \
  {0xf3a8d3b4, 0xc424, 0x4edc, \
    { 0x8b, 0xf6, 0x89, 0x74, 0xc9, 0x83, 0xba, 0x78 }}

struct nsIException_vtbl {

  /* Methods from the Class nsISupports */
  struct nsISupports_vtbl nsisupports;

  /* readonly attribute string message; */
  nsresult (*GetMessage)(nsIException *pThis, PRUnichar * *aMessage);

  /* readonly attribute nsresult (*result; */
  nsresult (*GetResult)(nsIException *pThis, nsresult *aResult);

  /* readonly attribute string name; */
  nsresult (*GetName)(nsIException *pThis, PRUnichar * *aName);

  /* readonly attribute string filename; */
  nsresult (*GetFilename)(nsIException *pThis, PRUnichar * *aFilename);

  /* readonly attribute PRUint32 lineNumber; */
  nsresult (*GetLineNumber)(nsIException *pThis, PRUint32 *aLineNumber);

  /* readonly attribute PRUint32 columnNumber; */
  nsresult (*GetColumnNumber)(nsIException *pThis, PRUint32 *aColumnNumber);

  /* readonly attribute nsIStackFrame location; */
  nsresult (*GetLocation)(nsIException *pThis, nsIStackFrame * *aLocation);

  /* readonly attribute nsIException inner; */
  nsresult (*GetInner)(nsIException *pThis, nsIException * *aInner);

  /* readonly attribute nsISupports data; */
  nsresult (*GetData)(nsIException *pThis, nsISupports * *aData);

  /* string toString (); */
  nsresult (*ToString)(nsIException *pThis, PRUnichar **_retval);
};

struct nsIException {
    struct nsIException_vtbl *vtbl;
};

/* starting interface:    nsIStackFrame */
#define NS_ISTACKFRAME_IID_STR "91d82105-7c62-4f8b-9779-154277c0ee90"

#define NS_ISTACKFRAME_IID \
  {0x91d82105, 0x7c62, 0x4f8b, \
    { 0x97, 0x79, 0x15, 0x42, 0x77, 0xc0, 0xee, 0x90 }}

struct nsIStackFrame_vtbl {

  /* Methods from the Class nsISupports */
  struct nsISupports_vtbl nsisupports;

  /* readonly attribute PRUint32 language; */
  nsresult (*GetLanguage)(nsIStackFrame *pThis, PRUint32 *aLanguage);

  /* readonly attribute string languageName; */
  nsresult (*GetLanguageName)(nsIStackFrame *pThis, PRUnichar * *aLanguageName);

  /* readonly attribute string filename; */
  nsresult (*GetFilename)(nsIStackFrame *pThis, PRUnichar * *aFilename);

  /* readonly attribute string name; */
  nsresult (*GetName)(nsIStackFrame *pThis, PRUnichar * *aName);

  /* readonly attribute PRInt32 lineNumber; */
  nsresult (*GetLineNumber)(nsIStackFrame *pThis, PRInt32 *aLineNumber);

  /* readonly attribute string sourceLine; */
  nsresult (*GetSourceLine)(nsIStackFrame *pThis, PRUnichar * *aSourceLine);

  /* readonly attribute nsIStackFrame caller; */
  nsresult (*GetCaller)(nsIStackFrame *pThis, nsIStackFrame * *aCaller);

  /* string toString (); */
  nsresult (*ToString)(nsIStackFrame *pThis, PRUnichar **_retval);
};

struct nsIStackFrame {
    struct nsIStackFrame_vtbl *vtbl;
};


#define VBOX_E_OBJECT_NOT_FOUND 0x80BB0001
#define VBOX_E_INVALID_VM_STATE 0x80BB0002
#define VBOX_E_VM_ERROR 0x80BB0003
#define VBOX_E_FILE_ERROR 0x80BB0004
#define VBOX_E_IPRT_ERROR 0x80BB0005
#define VBOX_E_PDM_ERROR 0x80BB0006
#define VBOX_E_INVALID_OBJECT_STATE 0x80BB0007
#define VBOX_E_HOST_ERROR 0x80BB0008
#define VBOX_E_NOT_SUPPORTED 0x80BB0009
#define VBOX_E_XML_ERROR 0x80BB000A
#define VBOX_E_INVALID_SESSION_STATE 0x80BB000B
#define VBOX_E_OBJECT_IN_USE 0x80BB000C


struct IVirtualBoxErrorInfo;
struct IVirtualBoxCallback;
struct IDHCPServer;
struct IVirtualBox;
struct IAppliance;
struct IVirtualSystemDescription;
struct IInternalMachineControl;
struct IBIOSSettings;
struct IMachine;
struct IConsoleCallback;
struct IRemoteDisplayInfo;
struct IConsole;
struct IHostDVDDrive;
struct IHostFloppyDrive;
struct IHostNetworkInterface;
struct IHost;
struct ISystemProperties;
struct IGuestOSType;
struct IGuest;
struct IProgress;
struct ISnapshot;
struct IMedium;
struct IHardDiskAttachment;
struct IHardDisk;
struct IHardDiskFormat;
struct IFloppyImage;
struct IDVDImage;
struct IDVDDrive;
struct IFloppyDrive;
struct IKeyboard;
struct IMouse;
struct IFramebuffer;
struct IFramebufferOverlay;
struct IDisplay;
struct INetworkAdapter;
struct ISerialPort;
struct IParallelPort;
struct IMachineDebugger;
struct IUSBController;
struct IUSBDevice;
struct IUSBDeviceFilter;
struct IHostUSBDevice;
struct IHostUSBDeviceFilter;
struct IAudioAdapter;
struct IVRDPServer;
struct ISharedFolder;
struct IInternalSessionControl;
struct ISession;
struct IStorageController;
struct IManagedObjectRef;
struct IWebsessionManager;
struct IPerformanceMetric;
struct IPerformanceCollector;

typedef struct IVirtualBoxErrorInfo IVirtualBoxErrorInfo;
typedef struct IVirtualBoxCallback IVirtualBoxCallback;
typedef struct IDHCPServer IDHCPServer;
typedef struct IVirtualBox IVirtualBox;
typedef struct IAppliance IAppliance;
typedef struct IVirtualSystemDescription IVirtualSystemDescription;
typedef struct IInternalMachineControl IInternalMachineControl;
typedef struct IBIOSSettings IBIOSSettings;
typedef struct IMachine IMachine;
typedef struct IConsoleCallback IConsoleCallback;
typedef struct IRemoteDisplayInfo IRemoteDisplayInfo;
typedef struct IConsole IConsole;
typedef struct IHostDVDDrive IHostDVDDrive;
typedef struct IHostFloppyDrive IHostFloppyDrive;
typedef struct IHostNetworkInterface IHostNetworkInterface;
typedef struct IHost IHost;
typedef struct ISystemProperties ISystemProperties;
typedef struct IGuestOSType IGuestOSType;
typedef struct IGuest IGuest;
typedef struct IProgress IProgress;
typedef struct ISnapshot ISnapshot;
typedef struct IMedium IMedium;
typedef struct IHardDiskAttachment IHardDiskAttachment;
typedef struct IHardDisk IHardDisk;
typedef struct IHardDiskFormat IHardDiskFormat;
typedef struct IFloppyImage IFloppyImage;
typedef struct IDVDImage IDVDImage;
typedef struct IDVDDrive IDVDDrive;
typedef struct IFloppyDrive IFloppyDrive;
typedef struct IKeyboard IKeyboard;
typedef struct IMouse IMouse;
typedef struct IFramebuffer IFramebuffer;
typedef struct IFramebufferOverlay IFramebufferOverlay;
typedef struct IDisplay IDisplay;
typedef struct INetworkAdapter INetworkAdapter;
typedef struct ISerialPort ISerialPort;
typedef struct IParallelPort IParallelPort;
typedef struct IMachineDebugger IMachineDebugger;
typedef struct IUSBController IUSBController;
typedef struct IUSBDevice IUSBDevice;
typedef struct IUSBDeviceFilter IUSBDeviceFilter;
typedef struct IHostUSBDevice IHostUSBDevice;
typedef struct IHostUSBDeviceFilter IHostUSBDeviceFilter;
typedef struct IAudioAdapter IAudioAdapter;
typedef struct IVRDPServer IVRDPServer;
typedef struct ISharedFolder ISharedFolder;
typedef struct IInternalSessionControl IInternalSessionControl;
typedef struct ISession ISession;
typedef struct IStorageController IStorageController;
typedef struct IManagedObjectRef IManagedObjectRef;
typedef struct IWebsessionManager IWebsessionManager;
typedef struct IPerformanceMetric IPerformanceMetric;
typedef struct IPerformanceCollector IPerformanceCollector;

/* Start of enum TSBool Declaration */
#define TSBOOL_IID_STR "523ff64d-842a-4b1a-80e7-c311b028cb3a"
#define TSBOOL_IID { \
    0x523ff64d, 0x842a, 0x4b1a, \
    { 0x80, 0xe7, 0xc3, 0x11, 0xb0, 0x28, 0xcb, 0x3a } \
}
enum TSBool
{
    TSBool_False = 0,
    TSBool_True = 1,
    TSBool_Default = 2
};
/* End of enum TSBool Declaration */


/* Start of enum AccessMode Declaration */
#define ACCESSMODE_IID_STR "1da0007c-ddf7-4be8-bcac-d84a1558785f"
#define ACCESSMODE_IID { \
    0x1da0007c, 0xddf7, 0x4be8, \
    { 0xbc, 0xac, 0xd8, 0x4a, 0x15, 0x58, 0x78, 0x5f } \
}
enum AccessMode
{
    AccessMode_ReadOnly = 1,
    AccessMode_ReadWrite = 2
};
/* End of enum AccessMode Declaration */


/* Start of enum MachineState Declaration */
#define MACHINESTATE_IID_STR "73bf04d0-7c4f-4684-9abf-d65a9ad74343"
#define MACHINESTATE_IID { \
    0x73bf04d0, 0x7c4f, 0x4684, \
    { 0x9a, 0xbf, 0xd6, 0x5a, 0x9a, 0xd7, 0x43, 0x43 } \
}
enum MachineState
{
    MachineState_Null = 0,
    MachineState_PoweredOff = 1,
    MachineState_Saved = 2,
    MachineState_Aborted = 3,
    MachineState_Running = 4,
    MachineState_Paused = 5,
    MachineState_Stuck = 6,
    MachineState_Starting = 7,
    MachineState_Stopping = 8,
    MachineState_Saving = 9,
    MachineState_Restoring = 10,
    MachineState_Discarding = 11,
    MachineState_SettingUp = 12,
    MachineState_FirstOnline = 4,
    MachineState_LastOnline = 10,
    MachineState_FirstTransient = 7,
    MachineState_LastTransient = 12
};
/* End of enum MachineState Declaration */


/* Start of enum SessionState Declaration */
#define SESSIONSTATE_IID_STR "CF2700C0-EA4B-47ae-9725-7810114B94D8"
#define SESSIONSTATE_IID { \
    0xCF2700C0, 0xEA4B, 0x47ae, \
    { 0x97, 0x25, 0x78, 0x10, 0x11, 0x4B, 0x94, 0xD8 } \
}
enum SessionState
{
    SessionState_Null = 0,
    SessionState_Closed = 1,
    SessionState_Open = 2,
    SessionState_Spawning = 3,
    SessionState_Closing = 4
};
/* End of enum SessionState Declaration */


/* Start of enum SessionType Declaration */
#define SESSIONTYPE_IID_STR "A13C02CB-0C2C-421E-8317-AC0E8AAA153A"
#define SESSIONTYPE_IID { \
    0xA13C02CB, 0x0C2C, 0x421E, \
    { 0x83, 0x17, 0xAC, 0x0E, 0x8A, 0xAA, 0x15, 0x3A } \
}
enum SessionType
{
    SessionType_Null = 0,
    SessionType_Direct = 1,
    SessionType_Remote = 2,
    SessionType_Existing = 3
};
/* End of enum SessionType Declaration */


/* Start of enum DeviceType Declaration */
#define DEVICETYPE_IID_STR "6d9420f7-0b56-4636-99f9-7346f1b01e57"
#define DEVICETYPE_IID { \
    0x6d9420f7, 0x0b56, 0x4636, \
    { 0x99, 0xf9, 0x73, 0x46, 0xf1, 0xb0, 0x1e, 0x57 } \
}
enum DeviceType
{
    DeviceType_Null = 0,
    DeviceType_Floppy = 1,
    DeviceType_DVD = 2,
    DeviceType_HardDisk = 3,
    DeviceType_Network = 4,
    DeviceType_USB = 5,
    DeviceType_SharedFolder = 6
};
/* End of enum DeviceType Declaration */


/* Start of enum DeviceActivity Declaration */
#define DEVICEACTIVITY_IID_STR "6FC8AEAA-130A-4eb5-8954-3F921422D707"
#define DEVICEACTIVITY_IID { \
    0x6FC8AEAA, 0x130A, 0x4eb5, \
    { 0x89, 0x54, 0x3F, 0x92, 0x14, 0x22, 0xD7, 0x07 } \
}
enum DeviceActivity
{
    DeviceActivity_Null = 0,
    DeviceActivity_Idle = 1,
    DeviceActivity_Reading = 2,
    DeviceActivity_Writing = 3
};
/* End of enum DeviceActivity Declaration */


/* Start of enum ClipboardMode Declaration */
#define CLIPBOARDMODE_IID_STR "33364716-4008-4701-8f14-be0fa3d62950"
#define CLIPBOARDMODE_IID { \
    0x33364716, 0x4008, 0x4701, \
    { 0x8f, 0x14, 0xbe, 0x0f, 0xa3, 0xd6, 0x29, 0x50 } \
}
enum ClipboardMode
{
    ClipboardMode_Disabled = 0,
    ClipboardMode_HostToGuest = 1,
    ClipboardMode_GuestToHost = 2,
    ClipboardMode_Bidirectional = 3
};
/* End of enum ClipboardMode Declaration */


/* Start of enum Scope Declaration */
#define SCOPE_IID_STR "7c91096e-499e-4eca-9f9b-9001438d7855"
#define SCOPE_IID { \
    0x7c91096e, 0x499e, 0x4eca, \
    { 0x9f, 0x9b, 0x90, 0x01, 0x43, 0x8d, 0x78, 0x55 } \
}
enum Scope
{
    Scope_Global = 0,
    Scope_Machine = 1,
    Scope_Session = 2
};
/* End of enum Scope Declaration */


/* Start of enum GuestStatisticType Declaration */
#define GUESTSTATISTICTYPE_IID_STR "aa7c1d71-aafe-47a8-9608-27d2d337cf55"
#define GUESTSTATISTICTYPE_IID { \
    0xaa7c1d71, 0xaafe, 0x47a8, \
    { 0x96, 0x08, 0x27, 0xd2, 0xd3, 0x37, 0xcf, 0x55 } \
}
enum GuestStatisticType
{
    GuestStatisticType_CPULoad_Idle = 0,
    GuestStatisticType_CPULoad_Kernel = 1,
    GuestStatisticType_CPULoad_User = 2,
    GuestStatisticType_Threads = 3,
    GuestStatisticType_Processes = 4,
    GuestStatisticType_Handles = 5,
    GuestStatisticType_MemoryLoad = 6,
    GuestStatisticType_PhysMemTotal = 7,
    GuestStatisticType_PhysMemAvailable = 8,
    GuestStatisticType_PhysMemBalloon = 9,
    GuestStatisticType_MemCommitTotal = 10,
    GuestStatisticType_MemKernelTotal = 11,
    GuestStatisticType_MemKernelPaged = 12,
    GuestStatisticType_MemKernelNonpaged = 13,
    GuestStatisticType_MemSystemCache = 14,
    GuestStatisticType_PageFileSize = 15,
    GuestStatisticType_SampleNumber = 16,
    GuestStatisticType_MaxVal = 17
};
/* End of enum GuestStatisticType Declaration */


/* Start of enum BIOSBootMenuMode Declaration */
#define BIOSBOOTMENUMODE_IID_STR "ae4fb9f7-29d2-45b4-b2c7-d579603135d5"
#define BIOSBOOTMENUMODE_IID { \
    0xae4fb9f7, 0x29d2, 0x45b4, \
    { 0xb2, 0xc7, 0xd5, 0x79, 0x60, 0x31, 0x35, 0xd5 } \
}
enum BIOSBootMenuMode
{
    BIOSBootMenuMode_Disabled = 0,
    BIOSBootMenuMode_MenuOnly = 1,
    BIOSBootMenuMode_MessageAndMenu = 2
};
/* End of enum BIOSBootMenuMode Declaration */


/* Start of enum DriveState Declaration */
#define DRIVESTATE_IID_STR "cb7233b7-c519-42a5-8310-1830953cacbc"
#define DRIVESTATE_IID { \
    0xcb7233b7, 0xc519, 0x42a5, \
    { 0x83, 0x10, 0x18, 0x30, 0x95, 0x3c, 0xac, 0xbc } \
}
enum DriveState
{
    DriveState_Null = 0,
    DriveState_NotMounted = 1,
    DriveState_ImageMounted = 2,
    DriveState_HostDriveCaptured = 3
};
/* End of enum DriveState Declaration */


/* Start of enum ProcessorFeature Declaration */
#define PROCESSORFEATURE_IID_STR "b8353b35-705d-4796-9967-ebfb7ba54af4"
#define PROCESSORFEATURE_IID { \
    0xb8353b35, 0x705d, 0x4796, \
    { 0x99, 0x67, 0xeb, 0xfb, 0x7b, 0xa5, 0x4a, 0xf4 } \
}
enum ProcessorFeature
{
    ProcessorFeature_HWVirtEx = 0,
    ProcessorFeature_PAE = 1,
    ProcessorFeature_LongMode = 2
};
/* End of enum ProcessorFeature Declaration */


/* Start of enum CIMOSType Declaration */
#define CIMOSTYPE_IID_STR "86ef5f8c-18b2-4db8-a314-33721b59f89b"
#define CIMOSTYPE_IID { \
    0x86ef5f8c, 0x18b2, 0x4db8, \
    { 0xa3, 0x14, 0x33, 0x72, 0x1b, 0x59, 0xf8, 0x9b } \
}
enum CIMOSType
{
    CIMOSType_CIMOS_Unknown = 0,
    CIMOSType_CIMOS_Other = 1,
    CIMOSType_CIMOS_MACOS = 2,
    CIMOSType_CIMOS_ATTUNIX = 3,
    CIMOSType_CIMOS_DGUX = 4,
    CIMOSType_CIMOS_DECNT = 5,
    CIMOSType_CIMOS_Tru64UNIX = 6,
    CIMOSType_CIMOS_OpenVMS = 7,
    CIMOSType_CIMOS_HPUX = 8,
    CIMOSType_CIMOS_AIX = 9,
    CIMOSType_CIMOS_MVS = 10,
    CIMOSType_CIMOS_OS400 = 11,
    CIMOSType_CIMOS_OS2 = 12,
    CIMOSType_CIMOS_JavaVM = 13,
    CIMOSType_CIMOS_MSDOS = 14,
    CIMOSType_CIMOS_WIN3x = 15,
    CIMOSType_CIMOS_WIN95 = 16,
    CIMOSType_CIMOS_WIN98 = 17,
    CIMOSType_CIMOS_WINNT = 18,
    CIMOSType_CIMOS_WINCE = 19,
    CIMOSType_CIMOS_NCR3000 = 20,
    CIMOSType_CIMOS_NetWare = 21,
    CIMOSType_CIMOS_OSF = 22,
    CIMOSType_CIMOS_DCOS = 23,
    CIMOSType_CIMOS_ReliantUNIX = 24,
    CIMOSType_CIMOS_SCOUnixWare = 25,
    CIMOSType_CIMOS_SCOOpenServer = 26,
    CIMOSType_CIMOS_Sequent = 27,
    CIMOSType_CIMOS_IRIX = 28,
    CIMOSType_CIMOS_Solaris = 29,
    CIMOSType_CIMOS_SunOS = 30,
    CIMOSType_CIMOS_U6000 = 31,
    CIMOSType_CIMOS_ASERIES = 32,
    CIMOSType_CIMOS_HPNonStopOS = 33,
    CIMOSType_CIMOS_HPNonStopOSS = 34,
    CIMOSType_CIMOS_BS2000 = 35,
    CIMOSType_CIMOS_LINUX = 36,
    CIMOSType_CIMOS_Lynx = 37,
    CIMOSType_CIMOS_XENIX = 38,
    CIMOSType_CIMOS_VM = 39,
    CIMOSType_CIMOS_InteractiveUNIX = 40,
    CIMOSType_CIMOS_BSDUNIX = 41,
    CIMOSType_CIMOS_FreeBSD = 42,
    CIMOSType_CIMOS_NetBSD = 43,
    CIMOSType_CIMOS_GNUHurd = 44,
    CIMOSType_CIMOS_OS9 = 45,
    CIMOSType_CIMOS_MACHKernel = 46,
    CIMOSType_CIMOS_Inferno = 47,
    CIMOSType_CIMOS_QNX = 48,
    CIMOSType_CIMOS_EPOC = 49,
    CIMOSType_CIMOS_IxWorks = 50,
    CIMOSType_CIMOS_VxWorks = 51,
    CIMOSType_CIMOS_MiNT = 52,
    CIMOSType_CIMOS_BeOS = 53,
    CIMOSType_CIMOS_HPMPE = 54,
    CIMOSType_CIMOS_NextStep = 55,
    CIMOSType_CIMOS_PalmPilot = 56,
    CIMOSType_CIMOS_Rhapsody = 57,
    CIMOSType_CIMOS_Windows2000 = 58,
    CIMOSType_CIMOS_Dedicated = 59,
    CIMOSType_CIMOS_OS390 = 60,
    CIMOSType_CIMOS_VSE = 61,
    CIMOSType_CIMOS_TPF = 62,
    CIMOSType_CIMOS_WindowsMe = 63,
    CIMOSType_CIMOS_CalderaOpenUNIX = 64,
    CIMOSType_CIMOS_OpenBSD = 65,
    CIMOSType_CIMOS_NotApplicable = 66,
    CIMOSType_CIMOS_WindowsXP = 67,
    CIMOSType_CIMOS_zOS = 68,
    CIMOSType_CIMOS_MicrosoftWindowsServer2003 = 69,
    CIMOSType_CIMOS_MicrosoftWindowsServer2003_64 = 70,
    CIMOSType_CIMOS_WindowsXP_64 = 71,
    CIMOSType_CIMOS_WindowsXPEmbedded = 72,
    CIMOSType_CIMOS_WindowsVista = 73,
    CIMOSType_CIMOS_WindowsVista_64 = 74,
    CIMOSType_CIMOS_WindowsEmbeddedforPointofService = 75,
    CIMOSType_CIMOS_MicrosoftWindowsServer2008 = 76,
    CIMOSType_CIMOS_MicrosoftWindowsServer2008_64 = 77,
    CIMOSType_CIMOS_FreeBSD_64 = 78,
    CIMOSType_CIMOS_RedHatEnterpriseLinux = 79,
    CIMOSType_CIMOS_RedHatEnterpriseLinux_64 = 80,
    CIMOSType_CIMOS_Solaris_64 = 81,
    CIMOSType_CIMOS_SUSE = 82,
    CIMOSType_CIMOS_SUSE_64 = 83,
    CIMOSType_CIMOS_SLES = 84,
    CIMOSType_CIMOS_SLES_64 = 85,
    CIMOSType_CIMOS_NovellOES = 86,
    CIMOSType_CIMOS_NovellLinuxDesktop = 87,
    CIMOSType_CIMOS_SunJavaDesktopSystem = 88,
    CIMOSType_CIMOS_Mandriva = 89,
    CIMOSType_CIMOS_Mandriva_64 = 90,
    CIMOSType_CIMOS_TurboLinux = 91,
    CIMOSType_CIMOS_TurboLinux_64 = 92,
    CIMOSType_CIMOS_Ubuntu = 93,
    CIMOSType_CIMOS_Ubuntu_64 = 94,
    CIMOSType_CIMOS_Debian = 95,
    CIMOSType_CIMOS_Debian_64 = 96,
    CIMOSType_CIMOS_Linux_2_4_x = 97,
    CIMOSType_CIMOS_Linux_2_4_x_64 = 98,
    CIMOSType_CIMOS_Linux_2_6_x = 99,
    CIMOSType_CIMOS_Linux_2_6_x_64 = 100,
    CIMOSType_CIMOS_Linux_64 = 101,
    CIMOSType_CIMOS_Other_64 = 102
};
/* End of enum CIMOSType Declaration */


/* Start of enum OVFResourceType Declaration */
#define OVFRESOURCETYPE_IID_STR "646a78d7-6f04-49f4-82c4-75c28a75a4cd"
#define OVFRESOURCETYPE_IID { \
    0x646a78d7, 0x6f04, 0x49f4, \
    { 0x82, 0xc4, 0x75, 0xc2, 0x8a, 0x75, 0xa4, 0xcd } \
}
enum OVFResourceType
{
    OVFResourceType_Other = 1,
    OVFResourceType_ComputerSystem = 2,
    OVFResourceType_Processor = 3,
    OVFResourceType_Memory = 4,
    OVFResourceType_IDEController = 5,
    OVFResourceType_ParallelSCSIHBA = 6,
    OVFResourceType_FCHBA = 7,
    OVFResourceType_iSCSIHBA = 8,
    OVFResourceType_IBHCA = 9,
    OVFResourceType_EthernetAdapter = 10,
    OVFResourceType_OtherNetworkAdapter = 11,
    OVFResourceType_IOSlot = 12,
    OVFResourceType_IODevice = 13,
    OVFResourceType_FloppyDrive = 14,
    OVFResourceType_CDDrive = 15,
    OVFResourceType_DVDDrive = 16,
    OVFResourceType_HardDisk = 17,
    OVFResourceType_OtherStorageDevice = 20,
    OVFResourceType_USBController = 23,
    OVFResourceType_SoundCard = 35
};
/* End of enum OVFResourceType Declaration */


/* Start of enum VirtualSystemDescriptionType Declaration */
#define VIRTUALSYSTEMDESCRIPTIONTYPE_IID_STR "aacc58de-5b45-4f82-ae2e-dd9a824fc3b5"
#define VIRTUALSYSTEMDESCRIPTIONTYPE_IID { \
    0xaacc58de, 0x5b45, 0x4f82, \
    { 0xae, 0x2e, 0xdd, 0x9a, 0x82, 0x4f, 0xc3, 0xb5 } \
}
enum VirtualSystemDescriptionType
{
    VirtualSystemDescriptionType_Ignore = 1,
    VirtualSystemDescriptionType_OS = 2,
    VirtualSystemDescriptionType_Name = 3,
    VirtualSystemDescriptionType_Product = 4,
    VirtualSystemDescriptionType_Vendor = 5,
    VirtualSystemDescriptionType_Version = 6,
    VirtualSystemDescriptionType_ProductUrl = 7,
    VirtualSystemDescriptionType_VendorUrl = 8,
    VirtualSystemDescriptionType_Description = 9,
    VirtualSystemDescriptionType_License = 10,
    VirtualSystemDescriptionType_Miscellaneous = 11,
    VirtualSystemDescriptionType_CPU = 12,
    VirtualSystemDescriptionType_Memory = 13,
    VirtualSystemDescriptionType_HardDiskControllerIDE = 14,
    VirtualSystemDescriptionType_HardDiskControllerSATA = 15,
    VirtualSystemDescriptionType_HardDiskControllerSCSI = 16,
    VirtualSystemDescriptionType_HardDiskImage = 17,
    VirtualSystemDescriptionType_Floppy = 18,
    VirtualSystemDescriptionType_CDROM = 19,
    VirtualSystemDescriptionType_NetworkAdapter = 20,
    VirtualSystemDescriptionType_USBController = 21,
    VirtualSystemDescriptionType_SoundCard = 22
};
/* End of enum VirtualSystemDescriptionType Declaration */


/* Start of enum VirtualSystemDescriptionValueType Declaration */
#define VIRTUALSYSTEMDESCRIPTIONVALUETYPE_IID_STR "56d9403f-3425-4118-9919-36f2a9b8c77c"
#define VIRTUALSYSTEMDESCRIPTIONVALUETYPE_IID { \
    0x56d9403f, 0x3425, 0x4118, \
    { 0x99, 0x19, 0x36, 0xf2, 0xa9, 0xb8, 0xc7, 0x7c } \
}
enum VirtualSystemDescriptionValueType
{
    VirtualSystemDescriptionValueType_Reference = 1,
    VirtualSystemDescriptionValueType_Original = 2,
    VirtualSystemDescriptionValueType_Auto = 3,
    VirtualSystemDescriptionValueType_ExtraConfig = 4
};
/* End of enum VirtualSystemDescriptionValueType Declaration */


/* Start of enum HostNetworkInterfaceMediumType Declaration */
#define HOSTNETWORKINTERFACEMEDIUMTYPE_IID_STR "1aa54aaf-2497-45a2-bfb1-8eb225e93d5b"
#define HOSTNETWORKINTERFACEMEDIUMTYPE_IID { \
    0x1aa54aaf, 0x2497, 0x45a2, \
    { 0xbf, 0xb1, 0x8e, 0xb2, 0x25, 0xe9, 0x3d, 0x5b } \
}
enum HostNetworkInterfaceMediumType
{
    HostNetworkInterfaceMediumType_Unknown = 0,
    HostNetworkInterfaceMediumType_Ethernet = 1,
    HostNetworkInterfaceMediumType_PPP = 2,
    HostNetworkInterfaceMediumType_SLIP = 3
};
/* End of enum HostNetworkInterfaceMediumType Declaration */


/* Start of enum HostNetworkInterfaceStatus Declaration */
#define HOSTNETWORKINTERFACESTATUS_IID_STR "CC474A69-2710-434B-8D99-C38E5D5A6F41"
#define HOSTNETWORKINTERFACESTATUS_IID { \
    0xCC474A69, 0x2710, 0x434B, \
    { 0x8D, 0x99, 0xC3, 0x8E, 0x5D, 0x5A, 0x6F, 0x41 } \
}
enum HostNetworkInterfaceStatus
{
    HostNetworkInterfaceStatus_Unknown = 0,
    HostNetworkInterfaceStatus_Up = 1,
    HostNetworkInterfaceStatus_Down = 2
};
/* End of enum HostNetworkInterfaceStatus Declaration */


/* Start of enum HostNetworkInterfaceType Declaration */
#define HOSTNETWORKINTERFACETYPE_IID_STR "67431b00-9946-48a2-bc02-b25c5919f4f3"
#define HOSTNETWORKINTERFACETYPE_IID { \
    0x67431b00, 0x9946, 0x48a2, \
    { 0xbc, 0x02, 0xb2, 0x5c, 0x59, 0x19, 0xf4, 0xf3 } \
}
enum HostNetworkInterfaceType
{
    HostNetworkInterfaceType_Bridged = 1,
    HostNetworkInterfaceType_HostOnly = 2
};
/* End of enum HostNetworkInterfaceType Declaration */


/* Start of enum MediaState Declaration */
#define MEDIASTATE_IID_STR "8b86e03c-2f1c-412a-8fbd-326f62701200"
#define MEDIASTATE_IID { \
    0x8b86e03c, 0x2f1c, 0x412a, \
    { 0x8f, 0xbd, 0x32, 0x6f, 0x62, 0x70, 0x12, 0x00 } \
}
enum MediaState
{
    MediaState_NotCreated = 0,
    MediaState_Created = 1,
    MediaState_LockedRead = 2,
    MediaState_LockedWrite = 3,
    MediaState_Inaccessible = 4,
    MediaState_Creating = 5,
    MediaState_Deleting = 6
};
/* End of enum MediaState Declaration */


/* Start of enum HardDiskType Declaration */
#define HARDDISKTYPE_IID_STR "a348fafd-a64e-4643-ba65-eb3896bd7e0a"
#define HARDDISKTYPE_IID { \
    0xa348fafd, 0xa64e, 0x4643, \
    { 0xba, 0x65, 0xeb, 0x38, 0x96, 0xbd, 0x7e, 0x0a } \
}
enum HardDiskType
{
    HardDiskType_Normal = 0,
    HardDiskType_Immutable = 1,
    HardDiskType_Writethrough = 2
};
/* End of enum HardDiskType Declaration */


/* Start of enum HardDiskVariant Declaration */
#define HARDDISKVARIANT_IID_STR "eb7fc6b3-ae23-4c5d-a1f6-e3522dd1efb0"
#define HARDDISKVARIANT_IID { \
    0xeb7fc6b3, 0xae23, 0x4c5d, \
    { 0xa1, 0xf6, 0xe3, 0x52, 0x2d, 0xd1, 0xef, 0xb0 } \
}
enum HardDiskVariant
{
    HardDiskVariant_Standard = 0,
    HardDiskVariant_VmdkSplit2G = 0x01,
    HardDiskVariant_VmdkStreamOptimized = 0x04,
    HardDiskVariant_VmdkESX = 0x08,
    HardDiskVariant_Fixed = 0x10000,
    HardDiskVariant_Diff = 0x20000
};
/* End of enum HardDiskVariant Declaration */


/* Start of enum DataType Declaration */
#define DATATYPE_IID_STR "d90ea51e-a3f1-4a01-beb1-c1723c0d3ba7"
#define DATATYPE_IID { \
    0xd90ea51e, 0xa3f1, 0x4a01, \
    { 0xbe, 0xb1, 0xc1, 0x72, 0x3c, 0x0d, 0x3b, 0xa7 } \
}
enum DataType
{
    DataType_Int32 = 0,
    DataType_Int8 = 1,
    DataType_String = 2
};
/* End of enum DataType Declaration */


/* Start of enum DataFlags Declaration */
#define DATAFLAGS_IID_STR "86884dcf-1d6b-4f1b-b4bf-f5aa44959d60"
#define DATAFLAGS_IID { \
    0x86884dcf, 0x1d6b, 0x4f1b, \
    { 0xb4, 0xbf, 0xf5, 0xaa, 0x44, 0x95, 0x9d, 0x60 } \
}
enum DataFlags
{
    DataFlags_None = 0x00,
    DataFlags_Mandatory = 0x01,
    DataFlags_Expert = 0x02,
    DataFlags_Array = 0x04,
    DataFlags_FlagMask = 0x07
};
/* End of enum DataFlags Declaration */


/* Start of enum HardDiskFormatCapabilities Declaration */
#define HARDDISKFORMATCAPABILITIES_IID_STR "1df1e4aa-d25a-4ba6-b2a2-02f60eb5903b"
#define HARDDISKFORMATCAPABILITIES_IID { \
    0x1df1e4aa, 0xd25a, 0x4ba6, \
    { 0xb2, 0xa2, 0x02, 0xf6, 0x0e, 0xb5, 0x90, 0x3b } \
}
enum HardDiskFormatCapabilities
{
    HardDiskFormatCapabilities_Uuid = 0x01,
    HardDiskFormatCapabilities_CreateFixed = 0x02,
    HardDiskFormatCapabilities_CreateDynamic = 0x04,
    HardDiskFormatCapabilities_CreateSplit2G = 0x08,
    HardDiskFormatCapabilities_Differencing = 0x10,
    HardDiskFormatCapabilities_Asynchronous = 0x20,
    HardDiskFormatCapabilities_File = 0x40,
    HardDiskFormatCapabilities_Properties = 0x80,
    HardDiskFormatCapabilities_CapabilityMask = 0xFF
};
/* End of enum HardDiskFormatCapabilities Declaration */


/* Start of enum MouseButtonState Declaration */
#define MOUSEBUTTONSTATE_IID_STR "03131722-2EC5-4173-9794-0DACA46673EF"
#define MOUSEBUTTONSTATE_IID { \
    0x03131722, 0x2EC5, 0x4173, \
    { 0x97, 0x94, 0x0D, 0xAC, 0xA4, 0x66, 0x73, 0xEF } \
}
enum MouseButtonState
{
    MouseButtonState_LeftButton = 0x01,
    MouseButtonState_RightButton = 0x02,
    MouseButtonState_MiddleButton = 0x04,
    MouseButtonState_WheelUp = 0x08,
    MouseButtonState_WheelDown = 0x10,
    MouseButtonState_MouseStateMask = 0x1F
};
/* End of enum MouseButtonState Declaration */


/* Start of enum FramebufferAccelerationOperation Declaration */
#define FRAMEBUFFERACCELERATIONOPERATION_IID_STR "f0e5ebbe-dc8e-4e2d-916e-53baa3844df8"
#define FRAMEBUFFERACCELERATIONOPERATION_IID { \
    0xf0e5ebbe, 0xdc8e, 0x4e2d, \
    { 0x91, 0x6e, 0x53, 0xba, 0xa3, 0x84, 0x4d, 0xf8 } \
}
enum FramebufferAccelerationOperation
{
    FramebufferAccelerationOperation_SolidFillAcceleration = 1,
    FramebufferAccelerationOperation_ScreenCopyAcceleration = 2
};
/* End of enum FramebufferAccelerationOperation Declaration */


/* Start of enum FramebufferPixelFormat Declaration */
#define FRAMEBUFFERPIXELFORMAT_IID_STR "7acfd5ed-29e3-45e3-8136-73c9224f3d2d"
#define FRAMEBUFFERPIXELFORMAT_IID { \
    0x7acfd5ed, 0x29e3, 0x45e3, \
    { 0x81, 0x36, 0x73, 0xc9, 0x22, 0x4f, 0x3d, 0x2d } \
}
enum FramebufferPixelFormat
{
    FramebufferPixelFormat_Opaque = 0,
    FramebufferPixelFormat_FOURCC_RGB = 0x32424752
};
/* End of enum FramebufferPixelFormat Declaration */


/* Start of enum NetworkAttachmentType Declaration */
#define NETWORKATTACHMENTTYPE_IID_STR "44bce1ee-99f7-4e8e-89fc-80597fd9eeaf"
#define NETWORKATTACHMENTTYPE_IID { \
    0x44bce1ee, 0x99f7, 0x4e8e, \
    { 0x89, 0xfc, 0x80, 0x59, 0x7f, 0xd9, 0xee, 0xaf } \
}
enum NetworkAttachmentType
{
    NetworkAttachmentType_Null = 0,
    NetworkAttachmentType_NAT = 1,
    NetworkAttachmentType_Bridged = 2,
    NetworkAttachmentType_Internal = 3,
    NetworkAttachmentType_HostOnly = 4
};
/* End of enum NetworkAttachmentType Declaration */


/* Start of enum NetworkAdapterType Declaration */
#define NETWORKADAPTERTYPE_IID_STR "50c3dfd8-07ac-4a31-baac-519c828fbf97"
#define NETWORKADAPTERTYPE_IID { \
    0x50c3dfd8, 0x07ac, 0x4a31, \
    { 0xba, 0xac, 0x51, 0x9c, 0x82, 0x8f, 0xbf, 0x97 } \
}
enum NetworkAdapterType
{
    NetworkAdapterType_Null = 0,
    NetworkAdapterType_Am79C970A = 1,
    NetworkAdapterType_Am79C973 = 2,
    NetworkAdapterType_I82540EM = 3,
    NetworkAdapterType_I82543GC = 4,
    NetworkAdapterType_I82545EM = 5
};
/* End of enum NetworkAdapterType Declaration */


/* Start of enum PortMode Declaration */
#define PORTMODE_IID_STR "b266f43c-2e93-46b3-812b-c20e600e867b"
#define PORTMODE_IID { \
    0xb266f43c, 0x2e93, 0x46b3, \
    { 0x81, 0x2b, 0xc2, 0x0e, 0x60, 0x0e, 0x86, 0x7b } \
}
enum PortMode
{
    PortMode_Disconnected = 0,
    PortMode_HostPipe = 1,
    PortMode_HostDevice = 2
};
/* End of enum PortMode Declaration */


/* Start of enum USBDeviceState Declaration */
#define USBDEVICESTATE_IID_STR "b99a2e65-67fb-4882-82fd-f3e5e8193ab4"
#define USBDEVICESTATE_IID { \
    0xb99a2e65, 0x67fb, 0x4882, \
    { 0x82, 0xfd, 0xf3, 0xe5, 0xe8, 0x19, 0x3a, 0xb4 } \
}
enum USBDeviceState
{
    USBDeviceState_NotSupported = 0,
    USBDeviceState_Unavailable = 1,
    USBDeviceState_Busy = 2,
    USBDeviceState_Available = 3,
    USBDeviceState_Held = 4,
    USBDeviceState_Captured = 5
};
/* End of enum USBDeviceState Declaration */


/* Start of enum USBDeviceFilterAction Declaration */
#define USBDEVICEFILTERACTION_IID_STR "cbc30a49-2f4e-43b5-9da6-121320475933"
#define USBDEVICEFILTERACTION_IID { \
    0xcbc30a49, 0x2f4e, 0x43b5, \
    { 0x9d, 0xa6, 0x12, 0x13, 0x20, 0x47, 0x59, 0x33 } \
}
enum USBDeviceFilterAction
{
    USBDeviceFilterAction_Null = 0,
    USBDeviceFilterAction_Ignore = 1,
    USBDeviceFilterAction_Hold = 2
};
/* End of enum USBDeviceFilterAction Declaration */


/* Start of enum AudioDriverType Declaration */
#define AUDIODRIVERTYPE_IID_STR "4bcc3d73-c2fe-40db-b72f-0c2ca9d68496"
#define AUDIODRIVERTYPE_IID { \
    0x4bcc3d73, 0xc2fe, 0x40db, \
    { 0xb7, 0x2f, 0x0c, 0x2c, 0xa9, 0xd6, 0x84, 0x96 } \
}
enum AudioDriverType
{
    AudioDriverType_Null = 0,
    AudioDriverType_WinMM = 1,
    AudioDriverType_OSS = 2,
    AudioDriverType_ALSA = 3,
    AudioDriverType_DirectSound = 4,
    AudioDriverType_CoreAudio = 5,
    AudioDriverType_MMPM = 6,
    AudioDriverType_Pulse = 7,
    AudioDriverType_SolAudio = 8
};
/* End of enum AudioDriverType Declaration */


/* Start of enum AudioControllerType Declaration */
#define AUDIOCONTROLLERTYPE_IID_STR "7afd395c-42c3-444e-8788-3ce80292f36c"
#define AUDIOCONTROLLERTYPE_IID { \
    0x7afd395c, 0x42c3, 0x444e, \
    { 0x87, 0x88, 0x3c, 0xe8, 0x02, 0x92, 0xf3, 0x6c } \
}
enum AudioControllerType
{
    AudioControllerType_AC97 = 0,
    AudioControllerType_SB16 = 1
};
/* End of enum AudioControllerType Declaration */


/* Start of enum VRDPAuthType Declaration */
#define VRDPAUTHTYPE_IID_STR "3d91887a-b67f-4b33-85bf-2da7ab1ea83a"
#define VRDPAUTHTYPE_IID { \
    0x3d91887a, 0xb67f, 0x4b33, \
    { 0x85, 0xbf, 0x2d, 0xa7, 0xab, 0x1e, 0xa8, 0x3a } \
}
enum VRDPAuthType
{
    VRDPAuthType_Null = 0,
    VRDPAuthType_External = 1,
    VRDPAuthType_Guest = 2
};
/* End of enum VRDPAuthType Declaration */


/* Start of enum StorageBus Declaration */
#define STORAGEBUS_IID_STR "f381fdca-5953-41d0-b2bd-0542b012698d"
#define STORAGEBUS_IID { \
    0xf381fdca, 0x5953, 0x41d0, \
    { 0xb2, 0xbd, 0x05, 0x42, 0xb0, 0x12, 0x69, 0x8d } \
}
enum StorageBus
{
    StorageBus_Null = 0,
    StorageBus_IDE = 1,
    StorageBus_SATA = 2,
    StorageBus_SCSI = 3
};
/* End of enum StorageBus Declaration */


/* Start of enum StorageControllerType Declaration */
#define STORAGECONTROLLERTYPE_IID_STR "685387db-a837-4320-a258-08f46a22f62a"
#define STORAGECONTROLLERTYPE_IID { \
    0x685387db, 0xa837, 0x4320, \
    { 0xa2, 0x58, 0x08, 0xf4, 0x6a, 0x22, 0xf6, 0x2a } \
}
enum StorageControllerType
{
    StorageControllerType_Null = 0,
    StorageControllerType_LsiLogic = 1,
    StorageControllerType_BusLogic = 2,
    StorageControllerType_IntelAhci = 3,
    StorageControllerType_PIIX3 = 4,
    StorageControllerType_PIIX4 = 5,
    StorageControllerType_ICH6 = 6
};
/* End of enum StorageControllerType Declaration */


/* Start of struct IVirtualBoxErrorInfo Declaration */
#define IVIRTUALBOXERRORINFO_IID_STR "e98b5376-8eb4-4eea-812a-3964bf3bb26f"
#define IVIRTUALBOXERRORINFO_IID { \
    0xe98b5376, 0x8eb4, 0x4eea, \
    { 0x81, 0x2a, 0x39, 0x64, 0xbf, 0x3b, 0xb2, 0x6f } \
}
struct IVirtualBoxErrorInfo_vtbl
{
    struct nsIException_vtbl nsiexception;

    nsresult (*GetResultCode)(IVirtualBoxErrorInfo *pThis, nsresult *resultCode);

    nsresult (*GetInterfaceID)(IVirtualBoxErrorInfo *pThis, nsID * *interfaceID);

    nsresult (*GetComponent)(IVirtualBoxErrorInfo *pThis, PRUnichar * *component);

    nsresult (*GetText)(IVirtualBoxErrorInfo *pThis, PRUnichar * *text);

    nsresult (*GetNext)(IVirtualBoxErrorInfo *pThis, IVirtualBoxErrorInfo * *next);

};

struct IVirtualBoxErrorInfo
{
    struct IVirtualBoxErrorInfo_vtbl *vtbl;
};
/* End of struct IVirtualBoxErrorInfo Declaration */


/* Start of struct IVirtualBoxCallback Declaration */
#define IVIRTUALBOXCALLBACK_IID_STR "5516cc08-fb81-47a6-b184-031e7bbd2997"
#define IVIRTUALBOXCALLBACK_IID { \
    0x5516cc08, 0xfb81, 0x47a6, \
    { 0xb1, 0x84, 0x03, 0x1e, 0x7b, 0xbd, 0x29, 0x97 } \
}
struct IVirtualBoxCallback_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*OnMachineStateChange)(
        IVirtualBoxCallback *pThis,
        const nsID * machineId,
        PRUint32 state
    );

    nsresult (*OnMachineDataChange)(
        IVirtualBoxCallback *pThis,
        const nsID * machineId
    );

    nsresult (*OnExtraDataCanChange)(
        IVirtualBoxCallback *pThis,
        const nsID * machineId,
        PRUnichar * key,
        PRUnichar * value,
        PRUnichar * * error,
        PRBool * allowChange
    );

    nsresult (*OnExtraDataChange)(
        IVirtualBoxCallback *pThis,
        const nsID * machineId,
        PRUnichar * key,
        PRUnichar * value
    );

    nsresult (*OnMediaRegistered)(
        IVirtualBoxCallback *pThis,
        const nsID * mediaId,
        PRUint32 mediaType,
        PRBool registered
    );

    nsresult (*OnMachineRegistered)(
        IVirtualBoxCallback *pThis,
        const nsID * machineId,
        PRBool registered
    );

    nsresult (*OnSessionStateChange)(
        IVirtualBoxCallback *pThis,
        const nsID * machineId,
        PRUint32 state
    );

    nsresult (*OnSnapshotTaken)(
        IVirtualBoxCallback *pThis,
        const nsID * machineId,
        const nsID * snapshotId
    );

    nsresult (*OnSnapshotDiscarded)(
        IVirtualBoxCallback *pThis,
        const nsID * machineId,
        const nsID * snapshotId
    );

    nsresult (*OnSnapshotChange)(
        IVirtualBoxCallback *pThis,
        const nsID * machineId,
        const nsID * snapshotId
    );

    nsresult (*OnGuestPropertyChange)(
        IVirtualBoxCallback *pThis,
        const nsID * machineId,
        PRUnichar * name,
        PRUnichar * value,
        PRUnichar * flags
    );

};

struct IVirtualBoxCallback
{
    struct IVirtualBoxCallback_vtbl *vtbl;
};
/* End of struct IVirtualBoxCallback Declaration */


/* Start of struct IDHCPServer Declaration */
#define IDHCPSERVER_IID_STR "6cfe387c-74fb-4ca7-bff6-973bec8af7a3"
#define IDHCPSERVER_IID { \
    0x6cfe387c, 0x74fb, 0x4ca7, \
    { 0xbf, 0xf6, 0x97, 0x3b, 0xec, 0x8a, 0xf7, 0xa3 } \
}
struct IDHCPServer_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetEnabled)(IDHCPServer *pThis, PRBool *enabled);
    nsresult (*SetEnabled)(IDHCPServer *pThis, PRBool enabled);

    nsresult (*GetIPAddress)(IDHCPServer *pThis, PRUnichar * *IPAddress);

    nsresult (*GetNetworkMask)(IDHCPServer *pThis, PRUnichar * *networkMask);

    nsresult (*GetNetworkName)(IDHCPServer *pThis, PRUnichar * *networkName);

    nsresult (*GetLowerIP)(IDHCPServer *pThis, PRUnichar * *lowerIP);

    nsresult (*GetUpperIP)(IDHCPServer *pThis, PRUnichar * *upperIP);

    nsresult (*SetConfiguration)(
        IDHCPServer *pThis,
        PRUnichar * IPAddress,
        PRUnichar * networkMask,
        PRUnichar * FromIPAddress,
        PRUnichar * ToIPAddress
    );

    nsresult (*Start)(
        IDHCPServer *pThis,
        PRUnichar * networkName,
        PRUnichar * trunkName,
        PRUnichar * trunkType
    );

    nsresult (*Stop)(IDHCPServer *pThis );

};

struct IDHCPServer
{
    struct IDHCPServer_vtbl *vtbl;
};
/* End of struct IDHCPServer Declaration */


/* Start of struct IVirtualBox Declaration */
#define IVIRTUALBOX_IID_STR "779264f4-65ed-48ed-be39-518ca549e296"
#define IVIRTUALBOX_IID { \
    0x779264f4, 0x65ed, 0x48ed, \
    { 0xbe, 0x39, 0x51, 0x8c, 0xa5, 0x49, 0xe2, 0x96 } \
}
struct IVirtualBox_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetVersion)(IVirtualBox *pThis, PRUnichar * *version);

    nsresult (*GetRevision)(IVirtualBox *pThis, PRUint32 *revision);

    nsresult (*GetPackageType)(IVirtualBox *pThis, PRUnichar * *packageType);

    nsresult (*GetHomeFolder)(IVirtualBox *pThis, PRUnichar * *homeFolder);

    nsresult (*GetSettingsFilePath)(IVirtualBox *pThis, PRUnichar * *settingsFilePath);

    nsresult (*GetSettingsFileVersion)(IVirtualBox *pThis, PRUnichar * *settingsFileVersion);

    nsresult (*GetSettingsFormatVersion)(IVirtualBox *pThis, PRUnichar * *settingsFormatVersion);

    nsresult (*GetHost)(IVirtualBox *pThis, IHost * *host);

    nsresult (*GetSystemProperties)(IVirtualBox *pThis, ISystemProperties * *systemProperties);

    nsresult (*GetMachines)(IVirtualBox *pThis, PRUint32 *machinesSize, IMachine * **machines);

    nsresult (*GetHardDisks)(IVirtualBox *pThis, PRUint32 *hardDisksSize, IHardDisk * **hardDisks);

    nsresult (*GetDVDImages)(IVirtualBox *pThis, PRUint32 *DVDImagesSize, IDVDImage * **DVDImages);

    nsresult (*GetFloppyImages)(IVirtualBox *pThis, PRUint32 *floppyImagesSize, IFloppyImage * **floppyImages);

    nsresult (*GetProgressOperations)(IVirtualBox *pThis, PRUint32 *progressOperationsSize, IProgress * **progressOperations);

    nsresult (*GetGuestOSTypes)(IVirtualBox *pThis, PRUint32 *guestOSTypesSize, IGuestOSType * **guestOSTypes);

    nsresult (*GetSharedFolders)(IVirtualBox *pThis, PRUint32 *sharedFoldersSize, ISharedFolder * **sharedFolders);

    nsresult (*GetPerformanceCollector)(IVirtualBox *pThis, IPerformanceCollector * *performanceCollector);

    nsresult (*GetDHCPServers)(IVirtualBox *pThis, PRUint32 *DHCPServersSize, IDHCPServer * **DHCPServers);

    nsresult (*CreateMachine)(
        IVirtualBox *pThis,
        PRUnichar * name,
        PRUnichar * osTypeId,
        PRUnichar * baseFolder,
        const nsID * id,
        IMachine * * machine
    );

    nsresult (*CreateLegacyMachine)(
        IVirtualBox *pThis,
        PRUnichar * name,
        PRUnichar * osTypeId,
        PRUnichar * settingsFile,
        const nsID * id,
        IMachine * * machine
    );

    nsresult (*OpenMachine)(
        IVirtualBox *pThis,
        PRUnichar * settingsFile,
        IMachine * * machine
    );

    nsresult (*RegisterMachine)(
        IVirtualBox *pThis,
        IMachine * machine
    );

    nsresult (*GetMachine)(
        IVirtualBox *pThis,
        const nsID * id,
        IMachine * * machine
    );

    nsresult (*FindMachine)(
        IVirtualBox *pThis,
        PRUnichar * name,
        IMachine * * machine
    );

    nsresult (*UnregisterMachine)(
        IVirtualBox *pThis,
        const nsID * id,
        IMachine * * machine
    );

    nsresult (*CreateAppliance)(
        IVirtualBox *pThis,
        IAppliance * * appliance
    );

    nsresult (*CreateHardDisk)(
        IVirtualBox *pThis,
        PRUnichar * format,
        PRUnichar * location,
        IHardDisk * * hardDisk
    );

    nsresult (*OpenHardDisk)(
        IVirtualBox *pThis,
        PRUnichar * location,
        PRUint32 accessMode,
        IHardDisk * * hardDisk
    );

    nsresult (*GetHardDisk)(
        IVirtualBox *pThis,
        const nsID * id,
        IHardDisk * * hardDisk
    );

    nsresult (*FindHardDisk)(
        IVirtualBox *pThis,
        PRUnichar * location,
        IHardDisk * * hardDisk
    );

    nsresult (*OpenDVDImage)(
        IVirtualBox *pThis,
        PRUnichar * location,
        const nsID * id,
        IDVDImage * * image
    );

    nsresult (*GetDVDImage)(
        IVirtualBox *pThis,
        const nsID * id,
        IDVDImage * * image
    );

    nsresult (*FindDVDImage)(
        IVirtualBox *pThis,
        PRUnichar * location,
        IDVDImage * * image
    );

    nsresult (*OpenFloppyImage)(
        IVirtualBox *pThis,
        PRUnichar * location,
        const nsID * id,
        IFloppyImage * * image
    );

    nsresult (*GetFloppyImage)(
        IVirtualBox *pThis,
        const nsID * id,
        IFloppyImage * * image
    );

    nsresult (*FindFloppyImage)(
        IVirtualBox *pThis,
        PRUnichar * location,
        IFloppyImage * * image
    );

    nsresult (*GetGuestOSType)(
        IVirtualBox *pThis,
        PRUnichar * id,
        IGuestOSType * * type
    );

    nsresult (*CreateSharedFolder)(
        IVirtualBox *pThis,
        PRUnichar * name,
        PRUnichar * hostPath,
        PRBool writable
    );

    nsresult (*RemoveSharedFolder)(
        IVirtualBox *pThis,
        PRUnichar * name
    );

    nsresult (*GetNextExtraDataKey)(
        IVirtualBox *pThis,
        PRUnichar * key,
        PRUnichar * * nextKey,
        PRUnichar * * nextValue
    );

    nsresult (*GetExtraData)(
        IVirtualBox *pThis,
        PRUnichar * key,
        PRUnichar * * value
    );

    nsresult (*SetExtraData)(
        IVirtualBox *pThis,
        PRUnichar * key,
        PRUnichar * value
    );

    nsresult (*OpenSession)(
        IVirtualBox *pThis,
        ISession * session,
        const nsID * machineId
    );

    nsresult (*OpenRemoteSession)(
        IVirtualBox *pThis,
        ISession * session,
        const nsID * machineId,
        PRUnichar * type,
        PRUnichar * environment,
        IProgress * * progress
    );

    nsresult (*OpenExistingSession)(
        IVirtualBox *pThis,
        ISession * session,
        const nsID * machineId
    );

    nsresult (*RegisterCallback)(
        IVirtualBox *pThis,
        IVirtualBoxCallback * callback
    );

    nsresult (*UnregisterCallback)(
        IVirtualBox *pThis,
        IVirtualBoxCallback * callback
    );

    nsresult (*WaitForPropertyChange)(
        IVirtualBox *pThis,
        PRUnichar * what,
        PRUint32 timeout,
        PRUnichar * * changed,
        PRUnichar * * values
    );

    nsresult (*SaveSettings)(IVirtualBox *pThis );

    nsresult (*SaveSettingsWithBackup)(
        IVirtualBox *pThis,
        PRUnichar * * bakFileName
    );

    nsresult (*CreateDHCPServer)(
        IVirtualBox *pThis,
        PRUnichar * name,
        IDHCPServer * * server
    );

    nsresult (*FindDHCPServerByNetworkName)(
        IVirtualBox *pThis,
        PRUnichar * name,
        IDHCPServer * * server
    );

    nsresult (*RemoveDHCPServer)(
        IVirtualBox *pThis,
        IDHCPServer * server
    );

};

struct IVirtualBox
{
    struct IVirtualBox_vtbl *vtbl;
};
/* End of struct IVirtualBox Declaration */


/* Start of struct IAppliance Declaration */
#define IAPPLIANCE_IID_STR "30bfa6b8-9eda-4b0a-b218-a86813248ccd"
#define IAPPLIANCE_IID { \
    0x30bfa6b8, 0x9eda, 0x4b0a, \
    { 0xb2, 0x18, 0xa8, 0x68, 0x13, 0x24, 0x8c, 0xcd } \
}
struct IAppliance_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetPath)(IAppliance *pThis, PRUnichar * *path);

    nsresult (*GetDisks)(IAppliance *pThis, PRUint32 *disksSize, PRUnichar * **disks);

    nsresult (*GetVirtualSystemDescriptions)(IAppliance *pThis, PRUint32 *virtualSystemDescriptionsSize, IVirtualSystemDescription * **virtualSystemDescriptions);

    nsresult (*Read)(
        IAppliance *pThis,
        PRUnichar * file
    );

    nsresult (*Interpret)(IAppliance *pThis );

    nsresult (*ImportMachines)(
        IAppliance *pThis,
        IProgress * * aProgress
    );

    nsresult (*Write)(
        IAppliance *pThis,
        PRUnichar * format,
        PRUnichar * path,
        IProgress * * aProgress
    );

    nsresult (*GetWarnings)(
        IAppliance *pThis,
        PRUint32 *aWarningsSize,
        PRUnichar *** aWarnings
    );

};

struct IAppliance
{
    struct IAppliance_vtbl *vtbl;
};
/* End of struct IAppliance Declaration */


/* Start of struct IVirtualSystemDescription Declaration */
#define IVIRTUALSYSTEMDESCRIPTION_IID_STR "d7525e6c-531a-4c51-8e04-41235083a3d8"
#define IVIRTUALSYSTEMDESCRIPTION_IID { \
    0xd7525e6c, 0x531a, 0x4c51, \
    { 0x8e, 0x04, 0x41, 0x23, 0x50, 0x83, 0xa3, 0xd8 } \
}
struct IVirtualSystemDescription_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetCount)(IVirtualSystemDescription *pThis, PRUint32 *count);

    nsresult (*GetDescription)(
        IVirtualSystemDescription *pThis,
        PRUint32 *aTypesSize,
        PRUint32* aTypes,
        PRUint32 *aRefsSize,
        PRUnichar *** aRefs,
        PRUint32 *aOvfValuesSize,
        PRUnichar *** aOvfValues,
        PRUint32 *aVboxValuesSize,
        PRUnichar *** aVboxValues,
        PRUint32 *aExtraConfigValuesSize,
        PRUnichar *** aExtraConfigValues
    );

    nsresult (*GetDescriptionByType)(
        IVirtualSystemDescription *pThis,
        PRUint32 aType,
        PRUint32 *aTypesSize,
        PRUint32* aTypes,
        PRUint32 *aRefsSize,
        PRUnichar *** aRefs,
        PRUint32 *aOvfValuesSize,
        PRUnichar *** aOvfValues,
        PRUint32 *aVboxValuesSize,
        PRUnichar *** aVboxValues,
        PRUint32 *aExtraConfigValuesSize,
        PRUnichar *** aExtraConfigValues
    );

    nsresult (*GetValuesByType)(
        IVirtualSystemDescription *pThis,
        PRUint32 aType,
        PRUint32 aWhich,
        PRUint32 *aValuesSize,
        PRUnichar *** aValues
    );

    nsresult (*SetFinalValues)(
        IVirtualSystemDescription *pThis,
        PRUint32 aEnabledSize,
        PRBool* aEnabled,
        PRUint32 aVboxValuesSize,
        PRUnichar ** aVboxValues,
        PRUint32 aExtraConfigValuesSize,
        PRUnichar ** aExtraConfigValues
    );

    nsresult (*AddDescription)(
        IVirtualSystemDescription *pThis,
        PRUint32 aType,
        PRUnichar * aVboxValue,
        PRUnichar * aExtraConfigValue
    );

};

struct IVirtualSystemDescription
{
    struct IVirtualSystemDescription_vtbl *vtbl;
};
/* End of struct IVirtualSystemDescription Declaration */


/* Start of struct IInternalMachineControl Declaration */
#define IINTERNALMACHINECONTROL_IID_STR "2c88b969-7a74-4ef3-b95f-8a209a1535f3"
#define IINTERNALMACHINECONTROL_IID { \
    0x2c88b969, 0x7a74, 0x4ef3, \
    { 0xb9, 0x5f, 0x8a, 0x20, 0x9a, 0x15, 0x35, 0xf3 } \
}
struct IInternalMachineControl_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*UpdateState)(
        IInternalMachineControl *pThis,
        PRUint32 state
    );

    nsresult (*GetIPCId)(
        IInternalMachineControl *pThis,
        PRUnichar * * id
    );

    nsresult (*RunUSBDeviceFilters)(
        IInternalMachineControl *pThis,
        IUSBDevice * device,
        PRBool * matched,
        PRUint32 * maskedInterfaces
    );

    nsresult (*CaptureUSBDevice)(
        IInternalMachineControl *pThis,
        const nsID * id
    );

    nsresult (*DetachUSBDevice)(
        IInternalMachineControl *pThis,
        const nsID * id,
        PRBool done
    );

    nsresult (*AutoCaptureUSBDevices)(IInternalMachineControl *pThis );

    nsresult (*DetachAllUSBDevices)(
        IInternalMachineControl *pThis,
        PRBool done
    );

    nsresult (*OnSessionEnd)(
        IInternalMachineControl *pThis,
        ISession * session,
        IProgress * * progress
    );

    nsresult (*BeginSavingState)(
        IInternalMachineControl *pThis,
        IProgress * progress,
        PRUnichar * * stateFilePath
    );

    nsresult (*EndSavingState)(
        IInternalMachineControl *pThis,
        PRBool success
    );

    nsresult (*AdoptSavedState)(
        IInternalMachineControl *pThis,
        PRUnichar * savedStateFile
    );

    nsresult (*BeginTakingSnapshot)(
        IInternalMachineControl *pThis,
        IConsole * initiator,
        PRUnichar * name,
        PRUnichar * description,
        IProgress * progress,
        PRUnichar * * stateFilePath,
        IProgress * * serverProgress
    );

    nsresult (*EndTakingSnapshot)(
        IInternalMachineControl *pThis,
        PRBool success
    );

    nsresult (*DiscardSnapshot)(
        IInternalMachineControl *pThis,
        IConsole * initiator,
        const nsID * id,
        PRUint32 * machineState,
        IProgress * * progress
    );

    nsresult (*DiscardCurrentState)(
        IInternalMachineControl *pThis,
        IConsole * initiator,
        PRUint32 * machineState,
        IProgress * * progress
    );

    nsresult (*DiscardCurrentSnapshotAndState)(
        IInternalMachineControl *pThis,
        IConsole * initiator,
        PRUint32 * machineState,
        IProgress * * progress
    );

    nsresult (*PullGuestProperties)(
        IInternalMachineControl *pThis,
        PRUint32 *nameSize,
        PRUnichar *** name,
        PRUint32 *valueSize,
        PRUnichar *** value,
        PRUint32 *timestampSize,
        PRUint64* timestamp,
        PRUint32 *flagsSize,
        PRUnichar *** flags
    );

    nsresult (*PushGuestProperties)(
        IInternalMachineControl *pThis,
        PRUint32 nameSize,
        PRUnichar ** name,
        PRUint32 valueSize,
        PRUnichar ** value,
        PRUint32 timestampSize,
        PRUint64* timestamp,
        PRUint32 flagsSize,
        PRUnichar ** flags
    );

    nsresult (*PushGuestProperty)(
        IInternalMachineControl *pThis,
        PRUnichar * name,
        PRUnichar * value,
        PRUint64 timestamp,
        PRUnichar * flags
    );

    nsresult (*LockMedia)(IInternalMachineControl *pThis );

};

struct IInternalMachineControl
{
    struct IInternalMachineControl_vtbl *vtbl;
};
/* End of struct IInternalMachineControl Declaration */


/* Start of struct IBIOSSettings Declaration */
#define IBIOSSETTINGS_IID_STR "38b54279-dc35-4f5e-a431-835b867c6b5e"
#define IBIOSSETTINGS_IID { \
    0x38b54279, 0xdc35, 0x4f5e, \
    { 0xa4, 0x31, 0x83, 0x5b, 0x86, 0x7c, 0x6b, 0x5e } \
}
struct IBIOSSettings_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetLogoFadeIn)(IBIOSSettings *pThis, PRBool *logoFadeIn);
    nsresult (*SetLogoFadeIn)(IBIOSSettings *pThis, PRBool logoFadeIn);

    nsresult (*GetLogoFadeOut)(IBIOSSettings *pThis, PRBool *logoFadeOut);
    nsresult (*SetLogoFadeOut)(IBIOSSettings *pThis, PRBool logoFadeOut);

    nsresult (*GetLogoDisplayTime)(IBIOSSettings *pThis, PRUint32 *logoDisplayTime);
    nsresult (*SetLogoDisplayTime)(IBIOSSettings *pThis, PRUint32 logoDisplayTime);

    nsresult (*GetLogoImagePath)(IBIOSSettings *pThis, PRUnichar * *logoImagePath);
    nsresult (*SetLogoImagePath)(IBIOSSettings *pThis, PRUnichar * logoImagePath);

    nsresult (*GetBootMenuMode)(IBIOSSettings *pThis, PRUint32 *bootMenuMode);
    nsresult (*SetBootMenuMode)(IBIOSSettings *pThis, PRUint32 bootMenuMode);

    nsresult (*GetACPIEnabled)(IBIOSSettings *pThis, PRBool *ACPIEnabled);
    nsresult (*SetACPIEnabled)(IBIOSSettings *pThis, PRBool ACPIEnabled);

    nsresult (*GetIOAPICEnabled)(IBIOSSettings *pThis, PRBool *IOAPICEnabled);
    nsresult (*SetIOAPICEnabled)(IBIOSSettings *pThis, PRBool IOAPICEnabled);

    nsresult (*GetTimeOffset)(IBIOSSettings *pThis, PRInt64 *timeOffset);
    nsresult (*SetTimeOffset)(IBIOSSettings *pThis, PRInt64 timeOffset);

    nsresult (*GetPXEDebugEnabled)(IBIOSSettings *pThis, PRBool *PXEDebugEnabled);
    nsresult (*SetPXEDebugEnabled)(IBIOSSettings *pThis, PRBool PXEDebugEnabled);

};

struct IBIOSSettings
{
    struct IBIOSSettings_vtbl *vtbl;
};
/* End of struct IBIOSSettings Declaration */


/* Start of struct IMachine Declaration */
#define IMACHINE_IID_STR "13420cbb-175a-4456-85d0-301126dfdec7"
#define IMACHINE_IID { \
    0x13420cbb, 0x175a, 0x4456, \
    { 0x85, 0xd0, 0x30, 0x11, 0x26, 0xdf, 0xde, 0xc7 } \
}
struct IMachine_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetParent)(IMachine *pThis, IVirtualBox * *parent);

    nsresult (*GetAccessible)(IMachine *pThis, PRBool *accessible);

    nsresult (*GetAccessError)(IMachine *pThis, IVirtualBoxErrorInfo * *accessError);

    nsresult (*GetName)(IMachine *pThis, PRUnichar * *name);
    nsresult (*SetName)(IMachine *pThis, PRUnichar * name);

    nsresult (*GetDescription)(IMachine *pThis, PRUnichar * *description);
    nsresult (*SetDescription)(IMachine *pThis, PRUnichar * description);

    nsresult (*GetId)(IMachine *pThis, nsID * *id);

    nsresult (*GetOSTypeId)(IMachine *pThis, PRUnichar * *OSTypeId);
    nsresult (*SetOSTypeId)(IMachine *pThis, PRUnichar * OSTypeId);

    nsresult (*GetHardwareVersion)(IMachine *pThis, PRUnichar * *HardwareVersion);
    nsresult (*SetHardwareVersion)(IMachine *pThis, PRUnichar * HardwareVersion);

    nsresult (*GetCPUCount)(IMachine *pThis, PRUint32 *CPUCount);
    nsresult (*SetCPUCount)(IMachine *pThis, PRUint32 CPUCount);

    nsresult (*GetMemorySize)(IMachine *pThis, PRUint32 *memorySize);
    nsresult (*SetMemorySize)(IMachine *pThis, PRUint32 memorySize);

    nsresult (*GetMemoryBalloonSize)(IMachine *pThis, PRUint32 *memoryBalloonSize);
    nsresult (*SetMemoryBalloonSize)(IMachine *pThis, PRUint32 memoryBalloonSize);

    nsresult (*GetStatisticsUpdateInterval)(IMachine *pThis, PRUint32 *statisticsUpdateInterval);
    nsresult (*SetStatisticsUpdateInterval)(IMachine *pThis, PRUint32 statisticsUpdateInterval);

    nsresult (*GetVRAMSize)(IMachine *pThis, PRUint32 *VRAMSize);
    nsresult (*SetVRAMSize)(IMachine *pThis, PRUint32 VRAMSize);

    nsresult (*GetAccelerate3DEnabled)(IMachine *pThis, PRBool *accelerate3DEnabled);
    nsresult (*SetAccelerate3DEnabled)(IMachine *pThis, PRBool accelerate3DEnabled);

    nsresult (*GetMonitorCount)(IMachine *pThis, PRUint32 *monitorCount);
    nsresult (*SetMonitorCount)(IMachine *pThis, PRUint32 monitorCount);

    nsresult (*GetBIOSSettings)(IMachine *pThis, IBIOSSettings * *BIOSSettings);

    nsresult (*GetHWVirtExEnabled)(IMachine *pThis, PRUint32 *HWVirtExEnabled);
    nsresult (*SetHWVirtExEnabled)(IMachine *pThis, PRUint32 HWVirtExEnabled);

    nsresult (*GetHWVirtExNestedPagingEnabled)(IMachine *pThis, PRBool *HWVirtExNestedPagingEnabled);
    nsresult (*SetHWVirtExNestedPagingEnabled)(IMachine *pThis, PRBool HWVirtExNestedPagingEnabled);

    nsresult (*GetHWVirtExVPIDEnabled)(IMachine *pThis, PRBool *HWVirtExVPIDEnabled);
    nsresult (*SetHWVirtExVPIDEnabled)(IMachine *pThis, PRBool HWVirtExVPIDEnabled);

    nsresult (*GetPAEEnabled)(IMachine *pThis, PRBool *PAEEnabled);
    nsresult (*SetPAEEnabled)(IMachine *pThis, PRBool PAEEnabled);

    nsresult (*GetSnapshotFolder)(IMachine *pThis, PRUnichar * *snapshotFolder);
    nsresult (*SetSnapshotFolder)(IMachine *pThis, PRUnichar * snapshotFolder);

    nsresult (*GetVRDPServer)(IMachine *pThis, IVRDPServer * *VRDPServer);

    nsresult (*GetHardDiskAttachments)(IMachine *pThis, PRUint32 *hardDiskAttachmentsSize, IHardDiskAttachment * **hardDiskAttachments);

    nsresult (*GetDVDDrive)(IMachine *pThis, IDVDDrive * *DVDDrive);

    nsresult (*GetFloppyDrive)(IMachine *pThis, IFloppyDrive * *floppyDrive);

    nsresult (*GetUSBController)(IMachine *pThis, IUSBController * *USBController);

    nsresult (*GetAudioAdapter)(IMachine *pThis, IAudioAdapter * *audioAdapter);

    nsresult (*GetStorageControllers)(IMachine *pThis, PRUint32 *storageControllersSize, IStorageController * **storageControllers);

    nsresult (*GetSettingsFilePath)(IMachine *pThis, PRUnichar * *settingsFilePath);

    nsresult (*GetSettingsFileVersion)(IMachine *pThis, PRUnichar * *settingsFileVersion);

    nsresult (*GetSettingsModified)(IMachine *pThis, PRBool *settingsModified);

    nsresult (*GetSessionState)(IMachine *pThis, PRUint32 *sessionState);

    nsresult (*GetSessionType)(IMachine *pThis, PRUnichar * *sessionType);

    nsresult (*GetSessionPid)(IMachine *pThis, PRUint32 *sessionPid);

    nsresult (*GetState)(IMachine *pThis, PRUint32 *state);

    nsresult (*GetLastStateChange)(IMachine *pThis, PRInt64 *lastStateChange);

    nsresult (*GetStateFilePath)(IMachine *pThis, PRUnichar * *stateFilePath);

    nsresult (*GetLogFolder)(IMachine *pThis, PRUnichar * *logFolder);

    nsresult (*GetCurrentSnapshot)(IMachine *pThis, ISnapshot * *currentSnapshot);

    nsresult (*GetSnapshotCount)(IMachine *pThis, PRUint32 *snapshotCount);

    nsresult (*GetCurrentStateModified)(IMachine *pThis, PRBool *currentStateModified);

    nsresult (*GetSharedFolders)(IMachine *pThis, PRUint32 *sharedFoldersSize, ISharedFolder * **sharedFolders);

    nsresult (*GetClipboardMode)(IMachine *pThis, PRUint32 *clipboardMode);
    nsresult (*SetClipboardMode)(IMachine *pThis, PRUint32 clipboardMode);

    nsresult (*GetGuestPropertyNotificationPatterns)(IMachine *pThis, PRUnichar * *guestPropertyNotificationPatterns);
    nsresult (*SetGuestPropertyNotificationPatterns)(IMachine *pThis, PRUnichar * guestPropertyNotificationPatterns);

    nsresult (*SetBootOrder)(
        IMachine *pThis,
        PRUint32 position,
        PRUint32 device
    );

    nsresult (*GetBootOrder)(
        IMachine *pThis,
        PRUint32 position,
        PRUint32 * device
    );

    nsresult (*AttachHardDisk)(
        IMachine *pThis,
        const nsID * id,
        PRUnichar * name,
        PRInt32 controllerPort,
        PRInt32 device
    );

    nsresult (*GetHardDisk)(
        IMachine *pThis,
        PRUnichar * name,
        PRInt32 controllerPort,
        PRInt32 device,
        IHardDisk * * hardDisk
    );

    nsresult (*DetachHardDisk)(
        IMachine *pThis,
        PRUnichar * name,
        PRInt32 controllerPort,
        PRInt32 device
    );

    nsresult (*GetHardDiskAttachmentsOfController)(
        IMachine *pThis,
        PRUnichar * name,
        PRUint32 *hardDiskAttachmentsSize,
        IHardDiskAttachment *** hardDiskAttachments
    );

    nsresult (*GetNetworkAdapter)(
        IMachine *pThis,
        PRUint32 slot,
        INetworkAdapter * * adapter
    );

    nsresult (*AddStorageController)(
        IMachine *pThis,
        PRUnichar * name,
        PRUint32 connectionType,
        IStorageController * * controller
    );

    nsresult (*GetStorageControllerByName)(
        IMachine *pThis,
        PRUnichar * name,
        IStorageController * * storageController
    );

    nsresult (*RemoveStorageController)(
        IMachine *pThis,
        PRUnichar * name
    );

    nsresult (*GetSerialPort)(
        IMachine *pThis,
        PRUint32 slot,
        ISerialPort * * port
    );

    nsresult (*GetParallelPort)(
        IMachine *pThis,
        PRUint32 slot,
        IParallelPort * * port
    );

    nsresult (*GetNextExtraDataKey)(
        IMachine *pThis,
        PRUnichar * key,
        PRUnichar * * nextKey,
        PRUnichar * * nextValue
    );

    nsresult (*GetExtraData)(
        IMachine *pThis,
        PRUnichar * key,
        PRUnichar * * value
    );

    nsresult (*SetExtraData)(
        IMachine *pThis,
        PRUnichar * key,
        PRUnichar * value
    );

    nsresult (*SaveSettings)(IMachine *pThis );

    nsresult (*SaveSettingsWithBackup)(
        IMachine *pThis,
        PRUnichar * * bakFileName
    );

    nsresult (*DiscardSettings)(IMachine *pThis );

    nsresult (*DeleteSettings)(IMachine *pThis );

    nsresult (*Export)(
        IMachine *pThis,
        IAppliance * aAppliance,
        IVirtualSystemDescription * * aDescription
    );

    nsresult (*GetSnapshot)(
        IMachine *pThis,
        const nsID * id,
        ISnapshot * * snapshot
    );

    nsresult (*FindSnapshot)(
        IMachine *pThis,
        PRUnichar * name,
        ISnapshot * * snapshot
    );

    nsresult (*SetCurrentSnapshot)(
        IMachine *pThis,
        const nsID * id
    );

    nsresult (*CreateSharedFolder)(
        IMachine *pThis,
        PRUnichar * name,
        PRUnichar * hostPath,
        PRBool writable
    );

    nsresult (*RemoveSharedFolder)(
        IMachine *pThis,
        PRUnichar * name
    );

    nsresult (*CanShowConsoleWindow)(
        IMachine *pThis,
        PRBool * canShow
    );

    nsresult (*ShowConsoleWindow)(
        IMachine *pThis,
        PRUint64 * winId
    );

    nsresult (*GetGuestProperty)(
        IMachine *pThis,
        PRUnichar * name,
        PRUnichar * * value,
        PRUint64 * timestamp,
        PRUnichar * * flags
    );

    nsresult (*GetGuestPropertyValue)(
        IMachine *pThis,
        PRUnichar * property,
        PRUnichar * * value
    );

    nsresult (*GetGuestPropertyTimestamp)(
        IMachine *pThis,
        PRUnichar * property,
        PRUint64 * value
    );

    nsresult (*SetGuestProperty)(
        IMachine *pThis,
        PRUnichar * property,
        PRUnichar * value,
        PRUnichar * flags
    );

    nsresult (*SetGuestPropertyValue)(
        IMachine *pThis,
        PRUnichar * property,
        PRUnichar * value
    );

    nsresult (*EnumerateGuestProperties)(
        IMachine *pThis,
        PRUnichar * patterns,
        PRUint32 *nameSize,
        PRUnichar *** name,
        PRUint32 *valueSize,
        PRUnichar *** value,
        PRUint32 *timestampSize,
        PRUint64* timestamp,
        PRUint32 *flagsSize,
        PRUnichar *** flags
    );

};

struct IMachine
{
    struct IMachine_vtbl *vtbl;
};
/* End of struct IMachine Declaration */


/* Start of struct IConsoleCallback Declaration */
#define ICONSOLECALLBACK_IID_STR "13dfbef3-b74d-487d-bada-2304529aefa6"
#define ICONSOLECALLBACK_IID { \
    0x13dfbef3, 0xb74d, 0x487d, \
    { 0xba, 0xda, 0x23, 0x04, 0x52, 0x9a, 0xef, 0xa6 } \
}
struct IConsoleCallback_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*OnMousePointerShapeChange)(
        IConsoleCallback *pThis,
        PRBool visible,
        PRBool alpha,
        PRUint32 xHot,
        PRUint32 yHot,
        PRUint32 width,
        PRUint32 height,
        PRUint8 * shape
    );

    nsresult (*OnMouseCapabilityChange)(
        IConsoleCallback *pThis,
        PRBool supportsAbsolute,
        PRBool needsHostCursor
    );

    nsresult (*OnKeyboardLedsChange)(
        IConsoleCallback *pThis,
        PRBool numLock,
        PRBool capsLock,
        PRBool scrollLock
    );

    nsresult (*OnStateChange)(
        IConsoleCallback *pThis,
        PRUint32 state
    );

    nsresult (*OnAdditionsStateChange)(IConsoleCallback *pThis );

    nsresult (*OnDVDDriveChange)(IConsoleCallback *pThis );

    nsresult (*OnFloppyDriveChange)(IConsoleCallback *pThis );

    nsresult (*OnNetworkAdapterChange)(
        IConsoleCallback *pThis,
        INetworkAdapter * networkAdapter
    );

    nsresult (*OnSerialPortChange)(
        IConsoleCallback *pThis,
        ISerialPort * serialPort
    );

    nsresult (*OnParallelPortChange)(
        IConsoleCallback *pThis,
        IParallelPort * parallelPort
    );

    nsresult (*OnStorageControllerChange)(IConsoleCallback *pThis );

    nsresult (*OnVRDPServerChange)(IConsoleCallback *pThis );

    nsresult (*OnUSBControllerChange)(IConsoleCallback *pThis );

    nsresult (*OnUSBDeviceStateChange)(
        IConsoleCallback *pThis,
        IUSBDevice * device,
        PRBool attached,
        IVirtualBoxErrorInfo * error
    );

    nsresult (*OnSharedFolderChange)(
        IConsoleCallback *pThis,
        PRUint32 scope
    );

    nsresult (*OnRuntimeError)(
        IConsoleCallback *pThis,
        PRBool fatal,
        PRUnichar * id,
        PRUnichar * message
    );

    nsresult (*OnCanShowWindow)(
        IConsoleCallback *pThis,
        PRBool * canShow
    );

    nsresult (*OnShowWindow)(
        IConsoleCallback *pThis,
        PRUint64 * winId
    );

};

struct IConsoleCallback
{
    struct IConsoleCallback_vtbl *vtbl;
};
/* End of struct IConsoleCallback Declaration */


/* Start of struct IRemoteDisplayInfo Declaration */
#define IREMOTEDISPLAYINFO_IID_STR "550104cd-2dfd-4a6c-857d-f6f8e088e62c"
#define IREMOTEDISPLAYINFO_IID { \
    0x550104cd, 0x2dfd, 0x4a6c, \
    { 0x85, 0x7d, 0xf6, 0xf8, 0xe0, 0x88, 0xe6, 0x2c } \
}
struct IRemoteDisplayInfo_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetActive)(IRemoteDisplayInfo *pThis, PRBool *active);

    nsresult (*GetNumberOfClients)(IRemoteDisplayInfo *pThis, PRUint32 *numberOfClients);

    nsresult (*GetBeginTime)(IRemoteDisplayInfo *pThis, PRInt64 *beginTime);

    nsresult (*GetEndTime)(IRemoteDisplayInfo *pThis, PRInt64 *endTime);

    nsresult (*GetBytesSent)(IRemoteDisplayInfo *pThis, PRUint64 *bytesSent);

    nsresult (*GetBytesSentTotal)(IRemoteDisplayInfo *pThis, PRUint64 *bytesSentTotal);

    nsresult (*GetBytesReceived)(IRemoteDisplayInfo *pThis, PRUint64 *bytesReceived);

    nsresult (*GetBytesReceivedTotal)(IRemoteDisplayInfo *pThis, PRUint64 *bytesReceivedTotal);

    nsresult (*GetUser)(IRemoteDisplayInfo *pThis, PRUnichar * *user);

    nsresult (*GetDomain)(IRemoteDisplayInfo *pThis, PRUnichar * *domain);

    nsresult (*GetClientName)(IRemoteDisplayInfo *pThis, PRUnichar * *clientName);

    nsresult (*GetClientIP)(IRemoteDisplayInfo *pThis, PRUnichar * *clientIP);

    nsresult (*GetClientVersion)(IRemoteDisplayInfo *pThis, PRUint32 *clientVersion);

    nsresult (*GetEncryptionStyle)(IRemoteDisplayInfo *pThis, PRUint32 *encryptionStyle);

};

struct IRemoteDisplayInfo
{
    struct IRemoteDisplayInfo_vtbl *vtbl;
};
/* End of struct IRemoteDisplayInfo Declaration */


/* Start of struct IConsole Declaration */
#define ICONSOLE_IID_STR "9511bc54-15ee-4ddf-808e-472aba03809c"
#define ICONSOLE_IID { \
    0x9511bc54, 0x15ee, 0x4ddf, \
    { 0x80, 0x8e, 0x47, 0x2a, 0xba, 0x03, 0x80, 0x9c } \
}
struct IConsole_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetMachine)(IConsole *pThis, IMachine * *machine);

    nsresult (*GetState)(IConsole *pThis, PRUint32 *state);

    nsresult (*GetGuest)(IConsole *pThis, IGuest * *guest);

    nsresult (*GetKeyboard)(IConsole *pThis, IKeyboard * *keyboard);

    nsresult (*GetMouse)(IConsole *pThis, IMouse * *mouse);

    nsresult (*GetDisplay)(IConsole *pThis, IDisplay * *display);

    nsresult (*GetDebugger)(IConsole *pThis, IMachineDebugger * *debugger);

    nsresult (*GetUSBDevices)(IConsole *pThis, PRUint32 *USBDevicesSize, IUSBDevice * **USBDevices);

    nsresult (*GetRemoteUSBDevices)(IConsole *pThis, PRUint32 *remoteUSBDevicesSize, IHostUSBDevice * **remoteUSBDevices);

    nsresult (*GetSharedFolders)(IConsole *pThis, PRUint32 *sharedFoldersSize, ISharedFolder * **sharedFolders);

    nsresult (*GetRemoteDisplayInfo)(IConsole *pThis, IRemoteDisplayInfo * *remoteDisplayInfo);

    nsresult (*PowerUp)(
        IConsole *pThis,
        IProgress * * progress
    );

    nsresult (*PowerUpPaused)(
        IConsole *pThis,
        IProgress * * progress
    );

    nsresult (*PowerDown)(IConsole *pThis );

    nsresult (*PowerDownAsync)(
        IConsole *pThis,
        IProgress * * progress
    );

    nsresult (*Reset)(IConsole *pThis );

    nsresult (*Pause)(IConsole *pThis );

    nsresult (*Resume)(IConsole *pThis );

    nsresult (*PowerButton)(IConsole *pThis );

    nsresult (*SleepButton)(IConsole *pThis );

    nsresult (*GetPowerButtonHandled)(
        IConsole *pThis,
        PRBool * handled
    );

    nsresult (*GetGuestEnteredACPIMode)(
        IConsole *pThis,
        PRBool * entered
    );

    nsresult (*SaveState)(
        IConsole *pThis,
        IProgress * * progress
    );

    nsresult (*AdoptSavedState)(
        IConsole *pThis,
        PRUnichar * savedStateFile
    );

    nsresult (*DiscardSavedState)(IConsole *pThis );

    nsresult (*GetDeviceActivity)(
        IConsole *pThis,
        PRUint32 type,
        PRUint32 * activity
    );

    nsresult (*AttachUSBDevice)(
        IConsole *pThis,
        const nsID * id
    );

    nsresult (*DetachUSBDevice)(
        IConsole *pThis,
        const nsID * id,
        IUSBDevice * * device
    );

    nsresult (*FindUSBDeviceByAddress)(
        IConsole *pThis,
        PRUnichar * name,
        IUSBDevice * * device
    );

    nsresult (*FindUSBDeviceById)(
        IConsole *pThis,
        const nsID * id,
        IUSBDevice * * device
    );

    nsresult (*CreateSharedFolder)(
        IConsole *pThis,
        PRUnichar * name,
        PRUnichar * hostPath,
        PRBool writable
    );

    nsresult (*RemoveSharedFolder)(
        IConsole *pThis,
        PRUnichar * name
    );

    nsresult (*TakeSnapshot)(
        IConsole *pThis,
        PRUnichar * name,
        PRUnichar * description,
        IProgress * * progress
    );

    nsresult (*DiscardSnapshot)(
        IConsole *pThis,
        const nsID * id,
        IProgress * * progress
    );

    nsresult (*DiscardCurrentState)(
        IConsole *pThis,
        IProgress * * progress
    );

    nsresult (*DiscardCurrentSnapshotAndState)(
        IConsole *pThis,
        IProgress * * progress
    );

    nsresult (*RegisterCallback)(
        IConsole *pThis,
        IConsoleCallback * callback
    );

    nsresult (*UnregisterCallback)(
        IConsole *pThis,
        IConsoleCallback * callback
    );

};

struct IConsole
{
    struct IConsole_vtbl *vtbl;
};
/* End of struct IConsole Declaration */


/* Start of struct IHostDVDDrive Declaration */
#define IHOSTDVDDRIVE_IID_STR "21f86694-202d-4ce4-8b05-a63ff82dbf4c"
#define IHOSTDVDDRIVE_IID { \
    0x21f86694, 0x202d, 0x4ce4, \
    { 0x8b, 0x05, 0xa6, 0x3f, 0xf8, 0x2d, 0xbf, 0x4c } \
}
struct IHostDVDDrive_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetName)(IHostDVDDrive *pThis, PRUnichar * *name);

    nsresult (*GetDescription)(IHostDVDDrive *pThis, PRUnichar * *description);

    nsresult (*GetUdi)(IHostDVDDrive *pThis, PRUnichar * *udi);

};

struct IHostDVDDrive
{
    struct IHostDVDDrive_vtbl *vtbl;
};
/* End of struct IHostDVDDrive Declaration */


/* Start of struct IHostFloppyDrive Declaration */
#define IHOSTFLOPPYDRIVE_IID_STR "3f02d604-e908-4919-9fd1-8a4afd68fc63"
#define IHOSTFLOPPYDRIVE_IID { \
    0x3f02d604, 0xe908, 0x4919, \
    { 0x9f, 0xd1, 0x8a, 0x4a, 0xfd, 0x68, 0xfc, 0x63 } \
}
struct IHostFloppyDrive_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetName)(IHostFloppyDrive *pThis, PRUnichar * *name);

    nsresult (*GetDescription)(IHostFloppyDrive *pThis, PRUnichar * *description);

    nsresult (*GetUdi)(IHostFloppyDrive *pThis, PRUnichar * *udi);

};

struct IHostFloppyDrive
{
    struct IHostFloppyDrive_vtbl *vtbl;
};
/* End of struct IHostFloppyDrive Declaration */


/* Start of struct IHostNetworkInterface Declaration */
#define IHOSTNETWORKINTERFACE_IID_STR "88adaf3f-166b-4542-9457-0f1323507fae"
#define IHOSTNETWORKINTERFACE_IID { \
    0x88adaf3f, 0x166b, 0x4542, \
    { 0x94, 0x57, 0x0f, 0x13, 0x23, 0x50, 0x7f, 0xae } \
}
struct IHostNetworkInterface_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetName)(IHostNetworkInterface *pThis, PRUnichar * *name);

    nsresult (*GetId)(IHostNetworkInterface *pThis, nsID * *id);

    nsresult (*GetNetworkName)(IHostNetworkInterface *pThis, PRUnichar * *networkName);

    nsresult (*GetDhcpEnabled)(IHostNetworkInterface *pThis, PRBool *dhcpEnabled);

    nsresult (*GetIPAddress)(IHostNetworkInterface *pThis, PRUnichar * *IPAddress);

    nsresult (*GetNetworkMask)(IHostNetworkInterface *pThis, PRUnichar * *networkMask);

    nsresult (*GetIPV6Supported)(IHostNetworkInterface *pThis, PRBool *IPV6Supported);

    nsresult (*GetIPV6Address)(IHostNetworkInterface *pThis, PRUnichar * *IPV6Address);

    nsresult (*GetIPV6NetworkMaskPrefixLength)(IHostNetworkInterface *pThis, PRUint32 *IPV6NetworkMaskPrefixLength);

    nsresult (*GetHardwareAddress)(IHostNetworkInterface *pThis, PRUnichar * *hardwareAddress);

    nsresult (*GetMediumType)(IHostNetworkInterface *pThis, PRUint32 *mediumType);

    nsresult (*GetStatus)(IHostNetworkInterface *pThis, PRUint32 *status);

    nsresult (*GetInterfaceType)(IHostNetworkInterface *pThis, PRUint32 *interfaceType);

    nsresult (*EnableStaticIpConfig)(
        IHostNetworkInterface *pThis,
        PRUnichar * IPAddress,
        PRUnichar * networkMask
    );

    nsresult (*EnableStaticIpConfigV6)(
        IHostNetworkInterface *pThis,
        PRUnichar * IPV6Address,
        PRUint32 IPV6NetworkMaskPrefixLength
    );

    nsresult (*EnableDynamicIpConfig)(IHostNetworkInterface *pThis );

    nsresult (*DhcpRediscover)(IHostNetworkInterface *pThis );

};

struct IHostNetworkInterface
{
    struct IHostNetworkInterface_vtbl *vtbl;
};
/* End of struct IHostNetworkInterface Declaration */


/* Start of struct IHost Declaration */
#define IHOST_IID_STR "926469ca-9091-42ef-928e-582d78b66c70"
#define IHOST_IID { \
    0x926469ca, 0x9091, 0x42ef, \
    { 0x92, 0x8e, 0x58, 0x2d, 0x78, 0xb6, 0x6c, 0x70 } \
}
struct IHost_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetDVDDrives)(IHost *pThis, PRUint32 *DVDDrivesSize, IHostDVDDrive * **DVDDrives);

    nsresult (*GetFloppyDrives)(IHost *pThis, PRUint32 *floppyDrivesSize, IHostFloppyDrive * **floppyDrives);

    nsresult (*GetUSBDevices)(IHost *pThis, PRUint32 *USBDevicesSize, IHostUSBDevice * **USBDevices);

    nsresult (*GetUSBDeviceFilters)(IHost *pThis, PRUint32 *USBDeviceFiltersSize, IHostUSBDeviceFilter * **USBDeviceFilters);

    nsresult (*GetNetworkInterfaces)(IHost *pThis, PRUint32 *networkInterfacesSize, IHostNetworkInterface * **networkInterfaces);

    nsresult (*GetProcessorCount)(IHost *pThis, PRUint32 *processorCount);

    nsresult (*GetProcessorOnlineCount)(IHost *pThis, PRUint32 *processorOnlineCount);

    nsresult (*GetMemorySize)(IHost *pThis, PRUint32 *memorySize);

    nsresult (*GetMemoryAvailable)(IHost *pThis, PRUint32 *memoryAvailable);

    nsresult (*GetOperatingSystem)(IHost *pThis, PRUnichar * *operatingSystem);

    nsresult (*GetOSVersion)(IHost *pThis, PRUnichar * *OSVersion);

    nsresult (*GetUTCTime)(IHost *pThis, PRInt64 *UTCTime);

    nsresult (*GetProcessorSpeed)(
        IHost *pThis,
        PRUint32 cpuId,
        PRUint32 * speed
    );

    nsresult (*GetProcessorFeature)(
        IHost *pThis,
        PRUint32 feature,
        PRBool * supported
    );

    nsresult (*GetProcessorDescription)(
        IHost *pThis,
        PRUint32 cpuId,
        PRUnichar * * description
    );

    nsresult (*CreateUSBDeviceFilter)(
        IHost *pThis,
        PRUnichar * name,
        IHostUSBDeviceFilter * * filter
    );

    nsresult (*InsertUSBDeviceFilter)(
        IHost *pThis,
        PRUint32 position,
        IHostUSBDeviceFilter * filter
    );

    nsresult (*RemoveUSBDeviceFilter)(
        IHost *pThis,
        PRUint32 position,
        IHostUSBDeviceFilter * * filter
    );

    nsresult (*FindHostDVDDrive)(
        IHost *pThis,
        PRUnichar * name,
        IHostDVDDrive * * drive
    );

    nsresult (*FindHostFloppyDrive)(
        IHost *pThis,
        PRUnichar * name,
        IHostFloppyDrive * * drive
    );

    nsresult (*FindHostNetworkInterfaceByName)(
        IHost *pThis,
        PRUnichar * name,
        IHostNetworkInterface * * networkInterface
    );

    nsresult (*FindHostNetworkInterfaceById)(
        IHost *pThis,
        const nsID * id,
        IHostNetworkInterface * * networkInterface
    );

    nsresult (*FindHostNetworkInterfacesOfType)(
        IHost *pThis,
        PRUint32 type,
        PRUint32 *networkInterfacesSize,
        IHostNetworkInterface *** networkInterfaces
    );

    nsresult (*FindUSBDeviceById)(
        IHost *pThis,
        const nsID * id,
        IHostUSBDevice * * device
    );

    nsresult (*FindUSBDeviceByAddress)(
        IHost *pThis,
        PRUnichar * name,
        IHostUSBDevice * * device
    );

};

struct IHost
{
    struct IHost_vtbl *vtbl;
};
/* End of struct IHost Declaration */


/* Start of struct ISystemProperties Declaration */
#define ISYSTEMPROPERTIES_IID_STR "0760e03f-06d0-481e-9f81-be43fef092ba"
#define ISYSTEMPROPERTIES_IID { \
    0x0760e03f, 0x06d0, 0x481e, \
    { 0x9f, 0x81, 0xbe, 0x43, 0xfe, 0xf0, 0x92, 0xba } \
}
struct ISystemProperties_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetMinGuestRAM)(ISystemProperties *pThis, PRUint32 *minGuestRAM);

    nsresult (*GetMaxGuestRAM)(ISystemProperties *pThis, PRUint32 *maxGuestRAM);

    nsresult (*GetMinGuestVRAM)(ISystemProperties *pThis, PRUint32 *minGuestVRAM);

    nsresult (*GetMaxGuestVRAM)(ISystemProperties *pThis, PRUint32 *maxGuestVRAM);

    nsresult (*GetMinGuestCPUCount)(ISystemProperties *pThis, PRUint32 *minGuestCPUCount);

    nsresult (*GetMaxGuestCPUCount)(ISystemProperties *pThis, PRUint32 *maxGuestCPUCount);

    nsresult (*GetMaxVDISize)(ISystemProperties *pThis, PRUint64 *maxVDISize);

    nsresult (*GetNetworkAdapterCount)(ISystemProperties *pThis, PRUint32 *networkAdapterCount);

    nsresult (*GetSerialPortCount)(ISystemProperties *pThis, PRUint32 *serialPortCount);

    nsresult (*GetParallelPortCount)(ISystemProperties *pThis, PRUint32 *parallelPortCount);

    nsresult (*GetMaxBootPosition)(ISystemProperties *pThis, PRUint32 *maxBootPosition);

    nsresult (*GetDefaultMachineFolder)(ISystemProperties *pThis, PRUnichar * *defaultMachineFolder);
    nsresult (*SetDefaultMachineFolder)(ISystemProperties *pThis, PRUnichar * defaultMachineFolder);

    nsresult (*GetDefaultHardDiskFolder)(ISystemProperties *pThis, PRUnichar * *defaultHardDiskFolder);
    nsresult (*SetDefaultHardDiskFolder)(ISystemProperties *pThis, PRUnichar * defaultHardDiskFolder);

    nsresult (*GetHardDiskFormats)(ISystemProperties *pThis, PRUint32 *hardDiskFormatsSize, IHardDiskFormat * **hardDiskFormats);

    nsresult (*GetDefaultHardDiskFormat)(ISystemProperties *pThis, PRUnichar * *defaultHardDiskFormat);
    nsresult (*SetDefaultHardDiskFormat)(ISystemProperties *pThis, PRUnichar * defaultHardDiskFormat);

    nsresult (*GetRemoteDisplayAuthLibrary)(ISystemProperties *pThis, PRUnichar * *remoteDisplayAuthLibrary);
    nsresult (*SetRemoteDisplayAuthLibrary)(ISystemProperties *pThis, PRUnichar * remoteDisplayAuthLibrary);

    nsresult (*GetWebServiceAuthLibrary)(ISystemProperties *pThis, PRUnichar * *webServiceAuthLibrary);
    nsresult (*SetWebServiceAuthLibrary)(ISystemProperties *pThis, PRUnichar * webServiceAuthLibrary);

    nsresult (*GetHWVirtExEnabled)(ISystemProperties *pThis, PRBool *HWVirtExEnabled);
    nsresult (*SetHWVirtExEnabled)(ISystemProperties *pThis, PRBool HWVirtExEnabled);

    nsresult (*GetLogHistoryCount)(ISystemProperties *pThis, PRUint32 *LogHistoryCount);
    nsresult (*SetLogHistoryCount)(ISystemProperties *pThis, PRUint32 LogHistoryCount);

};

struct ISystemProperties
{
    struct ISystemProperties_vtbl *vtbl;
};
/* End of struct ISystemProperties Declaration */


/* Start of struct IGuestOSType Declaration */
#define IGUESTOSTYPE_IID_STR "cfe9e64c-4430-435b-9e7c-e3d8e417bd58"
#define IGUESTOSTYPE_IID { \
    0xcfe9e64c, 0x4430, 0x435b, \
    { 0x9e, 0x7c, 0xe3, 0xd8, 0xe4, 0x17, 0xbd, 0x58 } \
}
struct IGuestOSType_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetFamilyId)(IGuestOSType *pThis, PRUnichar * *familyId);

    nsresult (*GetFamilyDescription)(IGuestOSType *pThis, PRUnichar * *familyDescription);

    nsresult (*GetId)(IGuestOSType *pThis, PRUnichar * *id);

    nsresult (*GetDescription)(IGuestOSType *pThis, PRUnichar * *description);

    nsresult (*GetIs64Bit)(IGuestOSType *pThis, PRBool *is64Bit);

    nsresult (*GetRecommendedIOAPIC)(IGuestOSType *pThis, PRBool *recommendedIOAPIC);

    nsresult (*GetRecommendedVirtEx)(IGuestOSType *pThis, PRBool *recommendedVirtEx);

    nsresult (*GetRecommendedRAM)(IGuestOSType *pThis, PRUint32 *recommendedRAM);

    nsresult (*GetRecommendedVRAM)(IGuestOSType *pThis, PRUint32 *recommendedVRAM);

    nsresult (*GetRecommendedHDD)(IGuestOSType *pThis, PRUint32 *recommendedHDD);

    nsresult (*GetAdapterType)(IGuestOSType *pThis, PRUint32 *adapterType);

};

struct IGuestOSType
{
    struct IGuestOSType_vtbl *vtbl;
};
/* End of struct IGuestOSType Declaration */


/* Start of struct IGuest Declaration */
#define IGUEST_IID_STR "d8556fca-81bc-12af-fca3-365528fa38ca"
#define IGUEST_IID { \
    0xd8556fca, 0x81bc, 0x12af, \
    { 0xfc, 0xa3, 0x36, 0x55, 0x28, 0xfa, 0x38, 0xca } \
}
struct IGuest_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetOSTypeId)(IGuest *pThis, PRUnichar * *OSTypeId);

    nsresult (*GetAdditionsActive)(IGuest *pThis, PRBool *additionsActive);

    nsresult (*GetAdditionsVersion)(IGuest *pThis, PRUnichar * *additionsVersion);

    nsresult (*GetSupportsSeamless)(IGuest *pThis, PRBool *supportsSeamless);

    nsresult (*GetSupportsGraphics)(IGuest *pThis, PRBool *supportsGraphics);

    nsresult (*GetMemoryBalloonSize)(IGuest *pThis, PRUint32 *memoryBalloonSize);
    nsresult (*SetMemoryBalloonSize)(IGuest *pThis, PRUint32 memoryBalloonSize);

    nsresult (*GetStatisticsUpdateInterval)(IGuest *pThis, PRUint32 *statisticsUpdateInterval);
    nsresult (*SetStatisticsUpdateInterval)(IGuest *pThis, PRUint32 statisticsUpdateInterval);

    nsresult (*SetCredentials)(
        IGuest *pThis,
        PRUnichar * userName,
        PRUnichar * password,
        PRUnichar * domain,
        PRBool allowInteractiveLogon
    );

    nsresult (*GetStatistic)(
        IGuest *pThis,
        PRUint32 cpuId,
        PRUint32 statistic,
        PRUint32 * statVal
    );

};

struct IGuest
{
    struct IGuest_vtbl *vtbl;
};
/* End of struct IGuest Declaration */


/* Start of struct IProgress Declaration */
#define IPROGRESS_IID_STR "c4f94e6b-2273-446b-9539-4c05bb416fe7"
#define IPROGRESS_IID { \
    0xc4f94e6b, 0x2273, 0x446b, \
    { 0x95, 0x39, 0x4c, 0x05, 0xbb, 0x41, 0x6f, 0xe7 } \
}
struct IProgress_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetId)(IProgress *pThis, nsID * *id);

    nsresult (*GetDescription)(IProgress *pThis, PRUnichar * *description);

    nsresult (*GetInitiator)(IProgress *pThis, nsISupports * *initiator);

    nsresult (*GetCancelable)(IProgress *pThis, PRBool *cancelable);

    nsresult (*GetPercent)(IProgress *pThis, PRUint32 *percent);

    nsresult (*GetTimeRemaining)(IProgress *pThis, PRInt32 *timeRemaining);

    nsresult (*GetCompleted)(IProgress *pThis, PRBool *completed);

    nsresult (*GetCanceled)(IProgress *pThis, PRBool *canceled);

    nsresult (*GetResultCode)(IProgress *pThis, nsresult *resultCode);

    nsresult (*GetErrorInfo)(IProgress *pThis, IVirtualBoxErrorInfo * *errorInfo);

    nsresult (*GetOperationCount)(IProgress *pThis, PRUint32 *operationCount);

    nsresult (*GetOperation)(IProgress *pThis, PRUint32 *operation);

    nsresult (*GetOperationDescription)(IProgress *pThis, PRUnichar * *operationDescription);

    nsresult (*GetOperationPercent)(IProgress *pThis, PRUint32 *operationPercent);

    nsresult (*WaitForCompletion)(
        IProgress *pThis,
        PRInt32 timeout
    );

    nsresult (*WaitForOperationCompletion)(
        IProgress *pThis,
        PRUint32 operation,
        PRInt32 timeout
    );

    nsresult (*Cancel)(IProgress *pThis );

};

struct IProgress
{
    struct IProgress_vtbl *vtbl;
};
/* End of struct IProgress Declaration */


/* Start of struct ISnapshot Declaration */
#define ISNAPSHOT_IID_STR "5db6b1d9-c76b-4424-a6f4-8257f642d6ea"
#define ISNAPSHOT_IID { \
    0x5db6b1d9, 0xc76b, 0x4424, \
    { 0xa6, 0xf4, 0x82, 0x57, 0xf6, 0x42, 0xd6, 0xea } \
}
struct ISnapshot_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetId)(ISnapshot *pThis, nsID * *id);

    nsresult (*GetName)(ISnapshot *pThis, PRUnichar * *name);
    nsresult (*SetName)(ISnapshot *pThis, PRUnichar * name);

    nsresult (*GetDescription)(ISnapshot *pThis, PRUnichar * *description);
    nsresult (*SetDescription)(ISnapshot *pThis, PRUnichar * description);

    nsresult (*GetTimeStamp)(ISnapshot *pThis, PRInt64 *timeStamp);

    nsresult (*GetOnline)(ISnapshot *pThis, PRBool *online);

    nsresult (*GetMachine)(ISnapshot *pThis, IMachine * *machine);

    nsresult (*GetParent)(ISnapshot *pThis, ISnapshot * *parent);

    nsresult (*GetChildren)(ISnapshot *pThis, PRUint32 *childrenSize, ISnapshot * **children);

};

struct ISnapshot
{
    struct ISnapshot_vtbl *vtbl;
};
/* End of struct ISnapshot Declaration */


/* Start of struct IMedium Declaration */
#define IMEDIUM_IID_STR "a7fb3bfb-c180-4274-bae4-7fbc89046e13"
#define IMEDIUM_IID { \
    0xa7fb3bfb, 0xc180, 0x4274, \
    { 0xba, 0xe4, 0x7f, 0xbc, 0x89, 0x04, 0x6e, 0x13 } \
}
struct IMedium_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetId)(IMedium *pThis, nsID * *id);

    nsresult (*GetDescription)(IMedium *pThis, PRUnichar * *description);
    nsresult (*SetDescription)(IMedium *pThis, PRUnichar * description);

    nsresult (*GetState)(IMedium *pThis, PRUint32 *state);

    nsresult (*GetLocation)(IMedium *pThis, PRUnichar * *location);
    nsresult (*SetLocation)(IMedium *pThis, PRUnichar * location);

    nsresult (*GetName)(IMedium *pThis, PRUnichar * *name);

    nsresult (*GetSize)(IMedium *pThis, PRUint64 *size);

    nsresult (*GetLastAccessError)(IMedium *pThis, PRUnichar * *lastAccessError);

    nsresult (*GetMachineIds)(IMedium *pThis, PRUint32 *machineIdsSize, nsID * **machineIds);

    nsresult (*GetSnapshotIds)(
        IMedium *pThis,
        const nsID * machineId,
        PRUint32 *snapshotIdsSize,
        nsID *** snapshotIds
    );

    nsresult (*LockRead)(
        IMedium *pThis,
        PRUint32 * state
    );

    nsresult (*UnlockRead)(
        IMedium *pThis,
        PRUint32 * state
    );

    nsresult (*LockWrite)(
        IMedium *pThis,
        PRUint32 * state
    );

    nsresult (*UnlockWrite)(
        IMedium *pThis,
        PRUint32 * state
    );

    nsresult (*Close)(IMedium *pThis );

};

struct IMedium
{
    struct IMedium_vtbl *vtbl;
};
/* End of struct IMedium Declaration */


/* Start of struct IHardDiskAttachment Declaration */
#define IHARDDISKATTACHMENT_IID_STR "b1dd04bb-93c0-4ad3-a9cf-82316e595836"
#define IHARDDISKATTACHMENT_IID { \
    0xb1dd04bb, 0x93c0, 0x4ad3, \
    { 0xa9, 0xcf, 0x82, 0x31, 0x6e, 0x59, 0x58, 0x36 } \
}
struct IHardDiskAttachment_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetHardDisk)(IHardDiskAttachment *pThis, IHardDisk * *hardDisk);

    nsresult (*GetController)(IHardDiskAttachment *pThis, PRUnichar * *controller);

    nsresult (*GetPort)(IHardDiskAttachment *pThis, PRInt32 *port);

    nsresult (*GetDevice)(IHardDiskAttachment *pThis, PRInt32 *device);

};

struct IHardDiskAttachment
{
    struct IHardDiskAttachment_vtbl *vtbl;
};
/* End of struct IHardDiskAttachment Declaration */


/* Start of struct IHardDisk Declaration */
#define IHARDDISK_IID_STR "91648dc6-bb19-46bf-9e1c-4bf5b960c8e2"
#define IHARDDISK_IID { \
    0x91648dc6, 0xbb19, 0x46bf, \
    { 0x9e, 0x1c, 0x4b, 0xf5, 0xb9, 0x60, 0xc8, 0xe2 } \
}
struct IHardDisk_vtbl
{
    struct IMedium_vtbl imedium;

    nsresult (*GetFormat)(IHardDisk *pThis, PRUnichar * *format);

    nsresult (*GetType)(IHardDisk *pThis, PRUint32 *type);
    nsresult (*SetType)(IHardDisk *pThis, PRUint32 type);

    nsresult (*GetParent)(IHardDisk *pThis, IHardDisk * *parent);

    nsresult (*GetChildren)(IHardDisk *pThis, PRUint32 *childrenSize, IHardDisk * **children);

    nsresult (*GetRoot)(IHardDisk *pThis, IHardDisk * *root);

    nsresult (*GetReadOnly)(IHardDisk *pThis, PRBool *readOnly);

    nsresult (*GetLogicalSize)(IHardDisk *pThis, PRUint64 *logicalSize);

    nsresult (*GetAutoReset)(IHardDisk *pThis, PRBool *autoReset);
    nsresult (*SetAutoReset)(IHardDisk *pThis, PRBool autoReset);

    nsresult (*GetProperty)(
        IHardDisk *pThis,
        PRUnichar * name,
        PRUnichar * * value
    );

    nsresult (*SetProperty)(
        IHardDisk *pThis,
        PRUnichar * name,
        PRUnichar * value
    );

    nsresult (*GetProperties)(
        IHardDisk *pThis,
        PRUnichar * names,
        PRUint32 *returnNamesSize,
        PRUnichar *** returnNames,
        PRUint32 *returnValuesSize,
        PRUnichar *** returnValues
    );

    nsresult (*SetProperties)(
        IHardDisk *pThis,
        PRUint32 namesSize,
        PRUnichar ** names,
        PRUint32 valuesSize,
        PRUnichar ** values
    );

    nsresult (*CreateBaseStorage)(
        IHardDisk *pThis,
        PRUint64 logicalSize,
        PRUint32 variant,
        IProgress * * progress
    );

    nsresult (*DeleteStorage)(
        IHardDisk *pThis,
        IProgress * * progress
    );

    nsresult (*CreateDiffStorage)(
        IHardDisk *pThis,
        IHardDisk * target,
        PRUint32 variant,
        IProgress * * progress
    );

    nsresult (*MergeTo)(
        IHardDisk *pThis,
        const nsID * targetId,
        IProgress * * progress
    );

    nsresult (*CloneTo)(
        IHardDisk *pThis,
        IHardDisk * target,
        PRUint32 variant,
        IHardDisk * parent,
        IProgress * * progress
    );

    nsresult (*Compact)(
        IHardDisk *pThis,
        IProgress * * progress
    );

    nsresult (*Reset)(
        IHardDisk *pThis,
        IProgress * * progress
    );

};

struct IHardDisk
{
    struct IHardDisk_vtbl *vtbl;
};
/* End of struct IHardDisk Declaration */


/* Start of struct IHardDiskFormat Declaration */
#define IHARDDISKFORMAT_IID_STR "7f3ba790-3a0b-4a8a-bac2-bb50150123c5"
#define IHARDDISKFORMAT_IID { \
    0x7f3ba790, 0x3a0b, 0x4a8a, \
    { 0xba, 0xc2, 0xbb, 0x50, 0x15, 0x01, 0x23, 0xc5 } \
}
struct IHardDiskFormat_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetId)(IHardDiskFormat *pThis, PRUnichar * *id);

    nsresult (*GetName)(IHardDiskFormat *pThis, PRUnichar * *name);

    nsresult (*GetFileExtensions)(IHardDiskFormat *pThis, PRUint32 *fileExtensionsSize, PRUnichar * **fileExtensions);

    nsresult (*GetCapabilities)(IHardDiskFormat *pThis, PRUint32 *capabilities);

    nsresult (*DescribeProperties)(
        IHardDiskFormat *pThis,
        PRUint32 *namesSize,
        PRUnichar *** names,
        PRUint32 *descriptionSize,
        PRUnichar *** description,
        PRUint32 *typesSize,
        PRUint32* types,
        PRUint32 *flagsSize,
        PRUint32* flags,
        PRUint32 *defaultsSize,
        PRUnichar *** defaults
    );

};

struct IHardDiskFormat
{
    struct IHardDiskFormat_vtbl *vtbl;
};
/* End of struct IHardDiskFormat Declaration */


/* Start of struct IFloppyImage Declaration */
#define IFLOPPYIMAGE_IID_STR "faa6101f-078c-4b3a-ab75-75670c8170b3"
#define IFLOPPYIMAGE_IID { \
    0xfaa6101f, 0x078c, 0x4b3a, \
    { 0xab, 0x75, 0x75, 0x67, 0x0c, 0x81, 0x70, 0xb3 } \
}
struct IFloppyImage_vtbl
{
    struct IMedium_vtbl imedium;

};

struct IFloppyImage
{
    struct IFloppyImage_vtbl *vtbl;
};
/* End of struct IFloppyImage Declaration */


/* Start of struct IDVDImage Declaration */
#define IDVDIMAGE_IID_STR "b1f90bbb-e8a9-4484-9af1-3638e943f763"
#define IDVDIMAGE_IID { \
    0xb1f90bbb, 0xe8a9, 0x4484, \
    { 0x9a, 0xf1, 0x36, 0x38, 0xe9, 0x43, 0xf7, 0x63 } \
}
struct IDVDImage_vtbl
{
    struct IMedium_vtbl imedium;

};

struct IDVDImage
{
    struct IDVDImage_vtbl *vtbl;
};
/* End of struct IDVDImage Declaration */


/* Start of struct IDVDDrive Declaration */
#define IDVDDRIVE_IID_STR "d650ef30-be9b-4dae-b463-11d5824681a5"
#define IDVDDRIVE_IID { \
    0xd650ef30, 0xbe9b, 0x4dae, \
    { 0xb4, 0x63, 0x11, 0xd5, 0x82, 0x46, 0x81, 0xa5 } \
}
struct IDVDDrive_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetState)(IDVDDrive *pThis, PRUint32 *state);

    nsresult (*GetPassthrough)(IDVDDrive *pThis, PRBool *passthrough);
    nsresult (*SetPassthrough)(IDVDDrive *pThis, PRBool passthrough);

    nsresult (*MountImage)(
        IDVDDrive *pThis,
        const nsID * imageId
    );

    nsresult (*CaptureHostDrive)(
        IDVDDrive *pThis,
        IHostDVDDrive * drive
    );

    nsresult (*Unmount)(IDVDDrive *pThis );

    nsresult (*GetImage)(
        IDVDDrive *pThis,
        IDVDImage * * image
    );

    nsresult (*GetHostDrive)(
        IDVDDrive *pThis,
        IHostDVDDrive * * drive
    );

};

struct IDVDDrive
{
    struct IDVDDrive_vtbl *vtbl;
};
/* End of struct IDVDDrive Declaration */


/* Start of struct IFloppyDrive Declaration */
#define IFLOPPYDRIVE_IID_STR "159412cd-bab8-452e-8097-218a020825a6"
#define IFLOPPYDRIVE_IID { \
    0x159412cd, 0xbab8, 0x452e, \
    { 0x80, 0x97, 0x21, 0x8a, 0x02, 0x08, 0x25, 0xa6 } \
}
struct IFloppyDrive_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetEnabled)(IFloppyDrive *pThis, PRBool *enabled);
    nsresult (*SetEnabled)(IFloppyDrive *pThis, PRBool enabled);

    nsresult (*GetState)(IFloppyDrive *pThis, PRUint32 *state);

    nsresult (*MountImage)(
        IFloppyDrive *pThis,
        const nsID * imageId
    );

    nsresult (*CaptureHostDrive)(
        IFloppyDrive *pThis,
        IHostFloppyDrive * drive
    );

    nsresult (*Unmount)(IFloppyDrive *pThis );

    nsresult (*GetImage)(
        IFloppyDrive *pThis,
        IFloppyImage * * image
    );

    nsresult (*GetHostDrive)(
        IFloppyDrive *pThis,
        IHostFloppyDrive * * drive
    );

};

struct IFloppyDrive
{
    struct IFloppyDrive_vtbl *vtbl;
};
/* End of struct IFloppyDrive Declaration */


/* Start of struct IKeyboard Declaration */
#define IKEYBOARD_IID_STR "2d1a531b-4c6e-49cc-8af6-5c857b78b5d7"
#define IKEYBOARD_IID { \
    0x2d1a531b, 0x4c6e, 0x49cc, \
    { 0x8a, 0xf6, 0x5c, 0x85, 0x7b, 0x78, 0xb5, 0xd7 } \
}
struct IKeyboard_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*PutScancode)(
        IKeyboard *pThis,
        PRInt32 scancode
    );

    nsresult (*PutScancodes)(
        IKeyboard *pThis,
        PRUint32 scancodesSize,
        PRInt32* scancodes,
        PRUint32 * codesStored
    );

    nsresult (*PutCAD)(IKeyboard *pThis );

};

struct IKeyboard
{
    struct IKeyboard_vtbl *vtbl;
};
/* End of struct IKeyboard Declaration */


/* Start of struct IMouse Declaration */
#define IMOUSE_IID_STR "FD443EC1-0006-4F5B-9282-D72760A66916"
#define IMOUSE_IID { \
    0xFD443EC1, 0x0006, 0x4F5B, \
    { 0x92, 0x82, 0xD7, 0x27, 0x60, 0xA6, 0x69, 0x16 } \
}
struct IMouse_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetAbsoluteSupported)(IMouse *pThis, PRBool *absoluteSupported);

    nsresult (*PutMouseEvent)(
        IMouse *pThis,
        PRInt32 dx,
        PRInt32 dy,
        PRInt32 dz,
        PRInt32 buttonState
    );

    nsresult (*PutMouseEventAbsolute)(
        IMouse *pThis,
        PRInt32 x,
        PRInt32 y,
        PRInt32 dz,
        PRInt32 buttonState
    );

};

struct IMouse
{
    struct IMouse_vtbl *vtbl;
};
/* End of struct IMouse Declaration */


/* Start of struct IFramebuffer Declaration */
#define IFRAMEBUFFER_IID_STR "af431304-5b09-40e2-94da-3c3cb03822c1"
#define IFRAMEBUFFER_IID { \
    0xaf431304, 0x5b09, 0x40e2, \
    { 0x94, 0xda, 0x3c, 0x3c, 0xb0, 0x38, 0x22, 0xc1 } \
}
struct IFramebuffer_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetAddress)(IFramebuffer *pThis, PRUint8 * *address);

    nsresult (*GetWidth)(IFramebuffer *pThis, PRUint32 *width);

    nsresult (*GetHeight)(IFramebuffer *pThis, PRUint32 *height);

    nsresult (*GetBitsPerPixel)(IFramebuffer *pThis, PRUint32 *bitsPerPixel);

    nsresult (*GetBytesPerLine)(IFramebuffer *pThis, PRUint32 *bytesPerLine);

    nsresult (*GetPixelFormat)(IFramebuffer *pThis, PRUint32 *pixelFormat);

    nsresult (*GetUsesGuestVRAM)(IFramebuffer *pThis, PRBool *usesGuestVRAM);

    nsresult (*GetHeightReduction)(IFramebuffer *pThis, PRUint32 *heightReduction);

    nsresult (*GetOverlay)(IFramebuffer *pThis, IFramebufferOverlay * *overlay);

    nsresult (*GetWinId)(IFramebuffer *pThis, PRUint64 *winId);

    nsresult (*Lock)(IFramebuffer *pThis );

    nsresult (*Unlock)(IFramebuffer *pThis );

    nsresult (*NotifyUpdate)(
        IFramebuffer *pThis,
        PRUint32 x,
        PRUint32 y,
        PRUint32 width,
        PRUint32 height,
        PRBool * finished
    );

    nsresult (*RequestResize)(
        IFramebuffer *pThis,
        PRUint32 screenId,
        PRUint32 pixelFormat,
        PRUint8 * VRAM,
        PRUint32 bitsPerPixel,
        PRUint32 bytesPerLine,
        PRUint32 width,
        PRUint32 height,
        PRBool * finished
    );

    nsresult (*OperationSupported)(
        IFramebuffer *pThis,
        PRUint32 operation,
        PRBool * supported
    );

    nsresult (*VideoModeSupported)(
        IFramebuffer *pThis,
        PRUint32 width,
        PRUint32 height,
        PRUint32 bpp,
        PRBool * supported
    );

    nsresult (*SolidFill)(
        IFramebuffer *pThis,
        PRUint32 x,
        PRUint32 y,
        PRUint32 width,
        PRUint32 height,
        PRUint32 color,
        PRBool * handled
    );

    nsresult (*CopyScreenBits)(
        IFramebuffer *pThis,
        PRUint32 xDst,
        PRUint32 yDst,
        PRUint32 xSrc,
        PRUint32 ySrc,
        PRUint32 width,
        PRUint32 height,
        PRBool * handled
    );

    nsresult (*GetVisibleRegion)(
        IFramebuffer *pThis,
        PRUint8 * rectangles,
        PRUint32 count,
        PRUint32 * countCopied
    );

    nsresult (*SetVisibleRegion)(
        IFramebuffer *pThis,
        PRUint8 * rectangles,
        PRUint32 count
    );

};

struct IFramebuffer
{
    struct IFramebuffer_vtbl *vtbl;
};
/* End of struct IFramebuffer Declaration */


/* Start of struct IFramebufferOverlay Declaration */
#define IFRAMEBUFFEROVERLAY_IID_STR "0bcc1c7e-e415-47d2-bfdb-e4c705fb0f47"
#define IFRAMEBUFFEROVERLAY_IID { \
    0x0bcc1c7e, 0xe415, 0x47d2, \
    { 0xbf, 0xdb, 0xe4, 0xc7, 0x05, 0xfb, 0x0f, 0x47 } \
}
struct IFramebufferOverlay_vtbl
{
    struct IFramebuffer_vtbl iframebuffer;

    nsresult (*GetX)(IFramebufferOverlay *pThis, PRUint32 *x);

    nsresult (*GetY)(IFramebufferOverlay *pThis, PRUint32 *y);

    nsresult (*GetVisible)(IFramebufferOverlay *pThis, PRBool *visible);
    nsresult (*SetVisible)(IFramebufferOverlay *pThis, PRBool visible);

    nsresult (*GetAlpha)(IFramebufferOverlay *pThis, PRUint32 *alpha);
    nsresult (*SetAlpha)(IFramebufferOverlay *pThis, PRUint32 alpha);

    nsresult (*Move)(
        IFramebufferOverlay *pThis,
        PRUint32 x,
        PRUint32 y
    );

};

struct IFramebufferOverlay
{
    struct IFramebufferOverlay_vtbl *vtbl;
};
/* End of struct IFramebufferOverlay Declaration */


/* Start of struct IDisplay Declaration */
#define IDISPLAY_IID_STR "09789f63-4525-48e5-a5e4-1080453b0eab"
#define IDISPLAY_IID { \
    0x09789f63, 0x4525, 0x48e5, \
    { 0xa5, 0xe4, 0x10, 0x80, 0x45, 0x3b, 0x0e, 0xab } \
}
struct IDisplay_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetWidth)(IDisplay *pThis, PRUint32 *width);

    nsresult (*GetHeight)(IDisplay *pThis, PRUint32 *height);

    nsresult (*GetBitsPerPixel)(IDisplay *pThis, PRUint32 *bitsPerPixel);

    nsresult (*SetupInternalFramebuffer)(
        IDisplay *pThis,
        PRUint32 depth
    );

    nsresult (*LockFramebuffer)(
        IDisplay *pThis,
        PRUint8 * * address
    );

    nsresult (*UnlockFramebuffer)(IDisplay *pThis );

    nsresult (*RegisterExternalFramebuffer)(
        IDisplay *pThis,
        IFramebuffer * framebuffer
    );

    nsresult (*SetFramebuffer)(
        IDisplay *pThis,
        PRUint32 screenId,
        IFramebuffer * framebuffer
    );

    nsresult (*GetFramebuffer)(
        IDisplay *pThis,
        PRUint32 screenId,
        IFramebuffer * * framebuffer,
        PRInt32 * xOrigin,
        PRInt32 * yOrigin
    );

    nsresult (*SetVideoModeHint)(
        IDisplay *pThis,
        PRUint32 width,
        PRUint32 height,
        PRUint32 bitsPerPixel,
        PRUint32 display
    );

    nsresult (*SetSeamlessMode)(
        IDisplay *pThis,
        PRBool enabled
    );

    nsresult (*TakeScreenShot)(
        IDisplay *pThis,
        PRUint8 * address,
        PRUint32 width,
        PRUint32 height
    );

    nsresult (*DrawToScreen)(
        IDisplay *pThis,
        PRUint8 * address,
        PRUint32 x,
        PRUint32 y,
        PRUint32 width,
        PRUint32 height
    );

    nsresult (*InvalidateAndUpdate)(IDisplay *pThis );

    nsresult (*ResizeCompleted)(
        IDisplay *pThis,
        PRUint32 screenId
    );

    nsresult (*UpdateCompleted)(IDisplay *pThis );

};

struct IDisplay
{
    struct IDisplay_vtbl *vtbl;
};
/* End of struct IDisplay Declaration */


/* Start of struct INetworkAdapter Declaration */
#define INETWORKADAPTER_IID_STR "65607a27-2b73-4d43-b4cc-0ba2c817fbde"
#define INETWORKADAPTER_IID { \
    0x65607a27, 0x2b73, 0x4d43, \
    { 0xb4, 0xcc, 0x0b, 0xa2, 0xc8, 0x17, 0xfb, 0xde } \
}
struct INetworkAdapter_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetAdapterType)(INetworkAdapter *pThis, PRUint32 *adapterType);
    nsresult (*SetAdapterType)(INetworkAdapter *pThis, PRUint32 adapterType);

    nsresult (*GetSlot)(INetworkAdapter *pThis, PRUint32 *slot);

    nsresult (*GetEnabled)(INetworkAdapter *pThis, PRBool *enabled);
    nsresult (*SetEnabled)(INetworkAdapter *pThis, PRBool enabled);

    nsresult (*GetMACAddress)(INetworkAdapter *pThis, PRUnichar * *MACAddress);
    nsresult (*SetMACAddress)(INetworkAdapter *pThis, PRUnichar * MACAddress);

    nsresult (*GetAttachmentType)(INetworkAdapter *pThis, PRUint32 *attachmentType);

    nsresult (*GetHostInterface)(INetworkAdapter *pThis, PRUnichar * *hostInterface);
    nsresult (*SetHostInterface)(INetworkAdapter *pThis, PRUnichar * hostInterface);

    nsresult (*GetInternalNetwork)(INetworkAdapter *pThis, PRUnichar * *internalNetwork);
    nsresult (*SetInternalNetwork)(INetworkAdapter *pThis, PRUnichar * internalNetwork);

    nsresult (*GetNATNetwork)(INetworkAdapter *pThis, PRUnichar * *NATNetwork);
    nsresult (*SetNATNetwork)(INetworkAdapter *pThis, PRUnichar * NATNetwork);

    nsresult (*GetCableConnected)(INetworkAdapter *pThis, PRBool *cableConnected);
    nsresult (*SetCableConnected)(INetworkAdapter *pThis, PRBool cableConnected);

    nsresult (*GetLineSpeed)(INetworkAdapter *pThis, PRUint32 *lineSpeed);
    nsresult (*SetLineSpeed)(INetworkAdapter *pThis, PRUint32 lineSpeed);

    nsresult (*GetTraceEnabled)(INetworkAdapter *pThis, PRBool *traceEnabled);
    nsresult (*SetTraceEnabled)(INetworkAdapter *pThis, PRBool traceEnabled);

    nsresult (*GetTraceFile)(INetworkAdapter *pThis, PRUnichar * *traceFile);
    nsresult (*SetTraceFile)(INetworkAdapter *pThis, PRUnichar * traceFile);

    nsresult (*AttachToNAT)(INetworkAdapter *pThis );

    nsresult (*AttachToBridgedInterface)(INetworkAdapter *pThis );

    nsresult (*AttachToInternalNetwork)(INetworkAdapter *pThis );

    nsresult (*AttachToHostOnlyInterface)(INetworkAdapter *pThis );

    nsresult (*Detach)(INetworkAdapter *pThis );

};

struct INetworkAdapter
{
    struct INetworkAdapter_vtbl *vtbl;
};
/* End of struct INetworkAdapter Declaration */


/* Start of struct ISerialPort Declaration */
#define ISERIALPORT_IID_STR "937f6970-5103-4745-b78e-d28dcf1479a8"
#define ISERIALPORT_IID { \
    0x937f6970, 0x5103, 0x4745, \
    { 0xb7, 0x8e, 0xd2, 0x8d, 0xcf, 0x14, 0x79, 0xa8 } \
}
struct ISerialPort_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetSlot)(ISerialPort *pThis, PRUint32 *slot);

    nsresult (*GetEnabled)(ISerialPort *pThis, PRBool *enabled);
    nsresult (*SetEnabled)(ISerialPort *pThis, PRBool enabled);

    nsresult (*GetIOBase)(ISerialPort *pThis, PRUint32 *IOBase);
    nsresult (*SetIOBase)(ISerialPort *pThis, PRUint32 IOBase);

    nsresult (*GetIRQ)(ISerialPort *pThis, PRUint32 *IRQ);
    nsresult (*SetIRQ)(ISerialPort *pThis, PRUint32 IRQ);

    nsresult (*GetHostMode)(ISerialPort *pThis, PRUint32 *hostMode);
    nsresult (*SetHostMode)(ISerialPort *pThis, PRUint32 hostMode);

    nsresult (*GetServer)(ISerialPort *pThis, PRBool *server);
    nsresult (*SetServer)(ISerialPort *pThis, PRBool server);

    nsresult (*GetPath)(ISerialPort *pThis, PRUnichar * *path);
    nsresult (*SetPath)(ISerialPort *pThis, PRUnichar * path);

};

struct ISerialPort
{
    struct ISerialPort_vtbl *vtbl;
};
/* End of struct ISerialPort Declaration */


/* Start of struct IParallelPort Declaration */
#define IPARALLELPORT_IID_STR "0c925f06-dd10-4b77-8de8-294d738c3214"
#define IPARALLELPORT_IID { \
    0x0c925f06, 0xdd10, 0x4b77, \
    { 0x8d, 0xe8, 0x29, 0x4d, 0x73, 0x8c, 0x32, 0x14 } \
}
struct IParallelPort_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetSlot)(IParallelPort *pThis, PRUint32 *slot);

    nsresult (*GetEnabled)(IParallelPort *pThis, PRBool *enabled);
    nsresult (*SetEnabled)(IParallelPort *pThis, PRBool enabled);

    nsresult (*GetIOBase)(IParallelPort *pThis, PRUint32 *IOBase);
    nsresult (*SetIOBase)(IParallelPort *pThis, PRUint32 IOBase);

    nsresult (*GetIRQ)(IParallelPort *pThis, PRUint32 *IRQ);
    nsresult (*SetIRQ)(IParallelPort *pThis, PRUint32 IRQ);

    nsresult (*GetPath)(IParallelPort *pThis, PRUnichar * *path);
    nsresult (*SetPath)(IParallelPort *pThis, PRUnichar * path);

};

struct IParallelPort
{
    struct IParallelPort_vtbl *vtbl;
};
/* End of struct IParallelPort Declaration */


/* Start of struct IMachineDebugger Declaration */
#define IMACHINEDEBUGGER_IID_STR "b0b2a2dd-0627-4502-91c2-ddc5e77609e0"
#define IMACHINEDEBUGGER_IID { \
    0xb0b2a2dd, 0x0627, 0x4502, \
    { 0x91, 0xc2, 0xdd, 0xc5, 0xe7, 0x76, 0x09, 0xe0 } \
}
struct IMachineDebugger_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetSinglestep)(IMachineDebugger *pThis, PRBool *singlestep);
    nsresult (*SetSinglestep)(IMachineDebugger *pThis, PRBool singlestep);

    nsresult (*GetRecompileUser)(IMachineDebugger *pThis, PRBool *recompileUser);
    nsresult (*SetRecompileUser)(IMachineDebugger *pThis, PRBool recompileUser);

    nsresult (*GetRecompileSupervisor)(IMachineDebugger *pThis, PRBool *recompileSupervisor);
    nsresult (*SetRecompileSupervisor)(IMachineDebugger *pThis, PRBool recompileSupervisor);

    nsresult (*GetPATMEnabled)(IMachineDebugger *pThis, PRBool *PATMEnabled);
    nsresult (*SetPATMEnabled)(IMachineDebugger *pThis, PRBool PATMEnabled);

    nsresult (*GetCSAMEnabled)(IMachineDebugger *pThis, PRBool *CSAMEnabled);
    nsresult (*SetCSAMEnabled)(IMachineDebugger *pThis, PRBool CSAMEnabled);

    nsresult (*GetLogEnabled)(IMachineDebugger *pThis, PRBool *logEnabled);
    nsresult (*SetLogEnabled)(IMachineDebugger *pThis, PRBool logEnabled);

    nsresult (*GetHWVirtExEnabled)(IMachineDebugger *pThis, PRBool *HWVirtExEnabled);

    nsresult (*GetHWVirtExNestedPagingEnabled)(IMachineDebugger *pThis, PRBool *HWVirtExNestedPagingEnabled);

    nsresult (*GetHWVirtExVPIDEnabled)(IMachineDebugger *pThis, PRBool *HWVirtExVPIDEnabled);

    nsresult (*GetPAEEnabled)(IMachineDebugger *pThis, PRBool *PAEEnabled);

    nsresult (*GetVirtualTimeRate)(IMachineDebugger *pThis, PRUint32 *virtualTimeRate);
    nsresult (*SetVirtualTimeRate)(IMachineDebugger *pThis, PRUint32 virtualTimeRate);

    nsresult (*GetVM)(IMachineDebugger *pThis, PRUint64 *VM);

    nsresult (*ResetStats)(
        IMachineDebugger *pThis,
        PRUnichar * pattern
    );

    nsresult (*DumpStats)(
        IMachineDebugger *pThis,
        PRUnichar * pattern
    );

    nsresult (*GetStats)(
        IMachineDebugger *pThis,
        PRUnichar * pattern,
        PRBool withDescriptions,
        PRUnichar * * stats
    );

    nsresult (*InjectNMI)(IMachineDebugger *pThis );

};

struct IMachineDebugger
{
    struct IMachineDebugger_vtbl *vtbl;
};
/* End of struct IMachineDebugger Declaration */


/* Start of struct IUSBController Declaration */
#define IUSBCONTROLLER_IID_STR "238540fa-4b73-435a-a38e-4e1d9eab5c17"
#define IUSBCONTROLLER_IID { \
    0x238540fa, 0x4b73, 0x435a, \
    { 0xa3, 0x8e, 0x4e, 0x1d, 0x9e, 0xab, 0x5c, 0x17 } \
}
struct IUSBController_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetEnabled)(IUSBController *pThis, PRBool *enabled);
    nsresult (*SetEnabled)(IUSBController *pThis, PRBool enabled);

    nsresult (*GetEnabledEhci)(IUSBController *pThis, PRBool *enabledEhci);
    nsresult (*SetEnabledEhci)(IUSBController *pThis, PRBool enabledEhci);

    nsresult (*GetUSBStandard)(IUSBController *pThis, PRUint16 *USBStandard);

    nsresult (*GetDeviceFilters)(IUSBController *pThis, PRUint32 *deviceFiltersSize, IUSBDeviceFilter * **deviceFilters);

    nsresult (*CreateDeviceFilter)(
        IUSBController *pThis,
        PRUnichar * name,
        IUSBDeviceFilter * * filter
    );

    nsresult (*InsertDeviceFilter)(
        IUSBController *pThis,
        PRUint32 position,
        IUSBDeviceFilter * filter
    );

    nsresult (*RemoveDeviceFilter)(
        IUSBController *pThis,
        PRUint32 position,
        IUSBDeviceFilter * * filter
    );

};

struct IUSBController
{
    struct IUSBController_vtbl *vtbl;
};
/* End of struct IUSBController Declaration */


/* Start of struct IUSBDevice Declaration */
#define IUSBDEVICE_IID_STR "850af07b-9ee8-48c2-b6b0-f6d0acbf63c3"
#define IUSBDEVICE_IID { \
    0x850af07b, 0x9ee8, 0x48c2, \
    { 0xb6, 0xb0, 0xf6, 0xd0, 0xac, 0xbf, 0x63, 0xc3 } \
}
struct IUSBDevice_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetId)(IUSBDevice *pThis, nsID * *id);

    nsresult (*GetVendorId)(IUSBDevice *pThis, PRUint16 *vendorId);

    nsresult (*GetProductId)(IUSBDevice *pThis, PRUint16 *productId);

    nsresult (*GetRevision)(IUSBDevice *pThis, PRUint16 *revision);

    nsresult (*GetManufacturer)(IUSBDevice *pThis, PRUnichar * *manufacturer);

    nsresult (*GetProduct)(IUSBDevice *pThis, PRUnichar * *product);

    nsresult (*GetSerialNumber)(IUSBDevice *pThis, PRUnichar * *serialNumber);

    nsresult (*GetAddress)(IUSBDevice *pThis, PRUnichar * *address);

    nsresult (*GetPort)(IUSBDevice *pThis, PRUint16 *port);

    nsresult (*GetVersion)(IUSBDevice *pThis, PRUint16 *version);

    nsresult (*GetPortVersion)(IUSBDevice *pThis, PRUint16 *portVersion);

    nsresult (*GetRemote)(IUSBDevice *pThis, PRBool *remote);

};

struct IUSBDevice
{
    struct IUSBDevice_vtbl *vtbl;
};
/* End of struct IUSBDevice Declaration */


/* Start of struct IUSBDeviceFilter Declaration */
#define IUSBDEVICEFILTER_IID_STR "d6831fb4-1a94-4c2c-96ef-8d0d6192066d"
#define IUSBDEVICEFILTER_IID { \
    0xd6831fb4, 0x1a94, 0x4c2c, \
    { 0x96, 0xef, 0x8d, 0x0d, 0x61, 0x92, 0x06, 0x6d } \
}
struct IUSBDeviceFilter_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetName)(IUSBDeviceFilter *pThis, PRUnichar * *name);
    nsresult (*SetName)(IUSBDeviceFilter *pThis, PRUnichar * name);

    nsresult (*GetActive)(IUSBDeviceFilter *pThis, PRBool *active);
    nsresult (*SetActive)(IUSBDeviceFilter *pThis, PRBool active);

    nsresult (*GetVendorId)(IUSBDeviceFilter *pThis, PRUnichar * *vendorId);
    nsresult (*SetVendorId)(IUSBDeviceFilter *pThis, PRUnichar * vendorId);

    nsresult (*GetProductId)(IUSBDeviceFilter *pThis, PRUnichar * *productId);
    nsresult (*SetProductId)(IUSBDeviceFilter *pThis, PRUnichar * productId);

    nsresult (*GetRevision)(IUSBDeviceFilter *pThis, PRUnichar * *revision);
    nsresult (*SetRevision)(IUSBDeviceFilter *pThis, PRUnichar * revision);

    nsresult (*GetManufacturer)(IUSBDeviceFilter *pThis, PRUnichar * *manufacturer);
    nsresult (*SetManufacturer)(IUSBDeviceFilter *pThis, PRUnichar * manufacturer);

    nsresult (*GetProduct)(IUSBDeviceFilter *pThis, PRUnichar * *product);
    nsresult (*SetProduct)(IUSBDeviceFilter *pThis, PRUnichar * product);

    nsresult (*GetSerialNumber)(IUSBDeviceFilter *pThis, PRUnichar * *serialNumber);
    nsresult (*SetSerialNumber)(IUSBDeviceFilter *pThis, PRUnichar * serialNumber);

    nsresult (*GetPort)(IUSBDeviceFilter *pThis, PRUnichar * *port);
    nsresult (*SetPort)(IUSBDeviceFilter *pThis, PRUnichar * port);

    nsresult (*GetRemote)(IUSBDeviceFilter *pThis, PRUnichar * *remote);
    nsresult (*SetRemote)(IUSBDeviceFilter *pThis, PRUnichar * remote);

    nsresult (*GetMaskedInterfaces)(IUSBDeviceFilter *pThis, PRUint32 *maskedInterfaces);
    nsresult (*SetMaskedInterfaces)(IUSBDeviceFilter *pThis, PRUint32 maskedInterfaces);

};

struct IUSBDeviceFilter
{
    struct IUSBDeviceFilter_vtbl *vtbl;
};
/* End of struct IUSBDeviceFilter Declaration */


/* Start of struct IHostUSBDevice Declaration */
#define IHOSTUSBDEVICE_IID_STR "173b4b44-d268-4334-a00d-b6521c9a740a"
#define IHOSTUSBDEVICE_IID { \
    0x173b4b44, 0xd268, 0x4334, \
    { 0xa0, 0x0d, 0xb6, 0x52, 0x1c, 0x9a, 0x74, 0x0a } \
}
struct IHostUSBDevice_vtbl
{
    struct IUSBDevice_vtbl iusbdevice;

    nsresult (*GetState)(IHostUSBDevice *pThis, PRUint32 *state);

};

struct IHostUSBDevice
{
    struct IHostUSBDevice_vtbl *vtbl;
};
/* End of struct IHostUSBDevice Declaration */


/* Start of struct IHostUSBDeviceFilter Declaration */
#define IHOSTUSBDEVICEFILTER_IID_STR "4cc70246-d74a-400f-8222-3900489c0374"
#define IHOSTUSBDEVICEFILTER_IID { \
    0x4cc70246, 0xd74a, 0x400f, \
    { 0x82, 0x22, 0x39, 0x00, 0x48, 0x9c, 0x03, 0x74 } \
}
struct IHostUSBDeviceFilter_vtbl
{
    struct IUSBDeviceFilter_vtbl iusbdevicefilter;

    nsresult (*GetAction)(IHostUSBDeviceFilter *pThis, PRUint32 *action);
    nsresult (*SetAction)(IHostUSBDeviceFilter *pThis, PRUint32 action);

};

struct IHostUSBDeviceFilter
{
    struct IHostUSBDeviceFilter_vtbl *vtbl;
};
/* End of struct IHostUSBDeviceFilter Declaration */


/* Start of struct IAudioAdapter Declaration */
#define IAUDIOADAPTER_IID_STR "921873db-5f3f-4b69-91f9-7be9e535a2cb"
#define IAUDIOADAPTER_IID { \
    0x921873db, 0x5f3f, 0x4b69, \
    { 0x91, 0xf9, 0x7b, 0xe9, 0xe5, 0x35, 0xa2, 0xcb } \
}
struct IAudioAdapter_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetEnabled)(IAudioAdapter *pThis, PRBool *enabled);
    nsresult (*SetEnabled)(IAudioAdapter *pThis, PRBool enabled);

    nsresult (*GetAudioController)(IAudioAdapter *pThis, PRUint32 *audioController);
    nsresult (*SetAudioController)(IAudioAdapter *pThis, PRUint32 audioController);

    nsresult (*GetAudioDriver)(IAudioAdapter *pThis, PRUint32 *audioDriver);
    nsresult (*SetAudioDriver)(IAudioAdapter *pThis, PRUint32 audioDriver);

};

struct IAudioAdapter
{
    struct IAudioAdapter_vtbl *vtbl;
};
/* End of struct IAudioAdapter Declaration */


/* Start of struct IVRDPServer Declaration */
#define IVRDPSERVER_IID_STR "f4584ae7-6bce-474b-83d6-17d235e6aa89"
#define IVRDPSERVER_IID { \
    0xf4584ae7, 0x6bce, 0x474b, \
    { 0x83, 0xd6, 0x17, 0xd2, 0x35, 0xe6, 0xaa, 0x89 } \
}
struct IVRDPServer_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetEnabled)(IVRDPServer *pThis, PRBool *enabled);
    nsresult (*SetEnabled)(IVRDPServer *pThis, PRBool enabled);

    nsresult (*GetPort)(IVRDPServer *pThis, PRUint32 *port);
    nsresult (*SetPort)(IVRDPServer *pThis, PRUint32 port);

    nsresult (*GetNetAddress)(IVRDPServer *pThis, PRUnichar * *netAddress);
    nsresult (*SetNetAddress)(IVRDPServer *pThis, PRUnichar * netAddress);

    nsresult (*GetAuthType)(IVRDPServer *pThis, PRUint32 *authType);
    nsresult (*SetAuthType)(IVRDPServer *pThis, PRUint32 authType);

    nsresult (*GetAuthTimeout)(IVRDPServer *pThis, PRUint32 *authTimeout);
    nsresult (*SetAuthTimeout)(IVRDPServer *pThis, PRUint32 authTimeout);

    nsresult (*GetAllowMultiConnection)(IVRDPServer *pThis, PRBool *allowMultiConnection);
    nsresult (*SetAllowMultiConnection)(IVRDPServer *pThis, PRBool allowMultiConnection);

    nsresult (*GetReuseSingleConnection)(IVRDPServer *pThis, PRBool *reuseSingleConnection);
    nsresult (*SetReuseSingleConnection)(IVRDPServer *pThis, PRBool reuseSingleConnection);

};

struct IVRDPServer
{
    struct IVRDPServer_vtbl *vtbl;
};
/* End of struct IVRDPServer Declaration */


/* Start of struct ISharedFolder Declaration */
#define ISHAREDFOLDER_IID_STR "64637bb2-9e17-471c-b8f3-f8968dd9884e"
#define ISHAREDFOLDER_IID { \
    0x64637bb2, 0x9e17, 0x471c, \
    { 0xb8, 0xf3, 0xf8, 0x96, 0x8d, 0xd9, 0x88, 0x4e } \
}
struct ISharedFolder_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetName)(ISharedFolder *pThis, PRUnichar * *name);

    nsresult (*GetHostPath)(ISharedFolder *pThis, PRUnichar * *hostPath);

    nsresult (*GetAccessible)(ISharedFolder *pThis, PRBool *accessible);

    nsresult (*GetWritable)(ISharedFolder *pThis, PRBool *writable);

    nsresult (*GetLastAccessError)(ISharedFolder *pThis, PRUnichar * *lastAccessError);

};

struct ISharedFolder
{
    struct ISharedFolder_vtbl *vtbl;
};
/* End of struct ISharedFolder Declaration */


/* Start of struct IInternalSessionControl Declaration */
#define IINTERNALSESSIONCONTROL_IID_STR "2581845a-5a9d-45fb-bc3b-2476552dd970"
#define IINTERNALSESSIONCONTROL_IID { \
    0x2581845a, 0x5a9d, 0x45fb, \
    { 0xbc, 0x3b, 0x24, 0x76, 0x55, 0x2d, 0xd9, 0x70 } \
}
struct IInternalSessionControl_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetPID)(
        IInternalSessionControl *pThis,
        PRUint32 * pid
    );

    nsresult (*GetRemoteConsole)(
        IInternalSessionControl *pThis,
        IConsole * * console
    );

    nsresult (*AssignMachine)(
        IInternalSessionControl *pThis,
        IMachine * machine
    );

    nsresult (*AssignRemoteMachine)(
        IInternalSessionControl *pThis,
        IMachine * machine,
        IConsole * console
    );

    nsresult (*UpdateMachineState)(
        IInternalSessionControl *pThis,
        PRUint32 aMachineState
    );

    nsresult (*Uninitialize)(IInternalSessionControl *pThis );

    nsresult (*OnDVDDriveChange)(IInternalSessionControl *pThis );

    nsresult (*OnFloppyDriveChange)(IInternalSessionControl *pThis );

    nsresult (*OnNetworkAdapterChange)(
        IInternalSessionControl *pThis,
        INetworkAdapter * networkAdapter
    );

    nsresult (*OnSerialPortChange)(
        IInternalSessionControl *pThis,
        ISerialPort * serialPort
    );

    nsresult (*OnParallelPortChange)(
        IInternalSessionControl *pThis,
        IParallelPort * parallelPort
    );

    nsresult (*OnStorageControllerChange)(IInternalSessionControl *pThis );

    nsresult (*OnVRDPServerChange)(IInternalSessionControl *pThis );

    nsresult (*OnUSBControllerChange)(IInternalSessionControl *pThis );

    nsresult (*OnSharedFolderChange)(
        IInternalSessionControl *pThis,
        PRBool global
    );

    nsresult (*OnUSBDeviceAttach)(
        IInternalSessionControl *pThis,
        IUSBDevice * device,
        IVirtualBoxErrorInfo * error,
        PRUint32 maskedInterfaces
    );

    nsresult (*OnUSBDeviceDetach)(
        IInternalSessionControl *pThis,
        const nsID * id,
        IVirtualBoxErrorInfo * error
    );

    nsresult (*OnShowWindow)(
        IInternalSessionControl *pThis,
        PRBool check,
        PRBool * canShow,
        PRUint64 * winId
    );

    nsresult (*AccessGuestProperty)(
        IInternalSessionControl *pThis,
        PRUnichar * name,
        PRUnichar * value,
        PRUnichar * flags,
        PRBool isSetter,
        PRUnichar * * retValue,
        PRUint64 * retTimestamp,
        PRUnichar * * retFlags
    );

    nsresult (*EnumerateGuestProperties)(
        IInternalSessionControl *pThis,
        PRUnichar * patterns,
        PRUint32 *keySize,
        PRUnichar *** key,
        PRUint32 *valueSize,
        PRUnichar *** value,
        PRUint32 *timestampSize,
        PRUint64* timestamp,
        PRUint32 *flagsSize,
        PRUnichar *** flags
    );

};

struct IInternalSessionControl
{
    struct IInternalSessionControl_vtbl *vtbl;
};
/* End of struct IInternalSessionControl Declaration */


/* Start of struct ISession Declaration */
#define ISESSION_IID_STR "12F4DCDB-12B2-4ec1-B7CD-DDD9F6C5BF4D"
#define ISESSION_IID { \
    0x12F4DCDB, 0x12B2, 0x4ec1, \
    { 0xB7, 0xCD, 0xDD, 0xD9, 0xF6, 0xC5, 0xBF, 0x4D } \
}
struct ISession_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetState)(ISession *pThis, PRUint32 *state);

    nsresult (*GetType)(ISession *pThis, PRUint32 *type);

    nsresult (*GetMachine)(ISession *pThis, IMachine * *machine);

    nsresult (*GetConsole)(ISession *pThis, IConsole * *console);

    nsresult (*Close)(ISession *pThis );

};

struct ISession
{
    struct ISession_vtbl *vtbl;
};
/* End of struct ISession Declaration */


/* Start of struct IStorageController Declaration */
#define ISTORAGECONTROLLER_IID_STR "6bf8335b-d14a-44a5-9b45-ddc49ce7d5b2"
#define ISTORAGECONTROLLER_IID { \
    0x6bf8335b, 0xd14a, 0x44a5, \
    { 0x9b, 0x45, 0xdd, 0xc4, 0x9c, 0xe7, 0xd5, 0xb2 } \
}
struct IStorageController_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetName)(IStorageController *pThis, PRUnichar * *name);

    nsresult (*GetMaxDevicesPerPortCount)(IStorageController *pThis, PRUint32 *maxDevicesPerPortCount);

    nsresult (*GetMinPortCount)(IStorageController *pThis, PRUint32 *minPortCount);

    nsresult (*GetMaxPortCount)(IStorageController *pThis, PRUint32 *maxPortCount);

    nsresult (*GetInstance)(IStorageController *pThis, PRUint32 *instance);
    nsresult (*SetInstance)(IStorageController *pThis, PRUint32 instance);

    nsresult (*GetPortCount)(IStorageController *pThis, PRUint32 *portCount);
    nsresult (*SetPortCount)(IStorageController *pThis, PRUint32 portCount);

    nsresult (*GetBus)(IStorageController *pThis, PRUint32 *bus);

    nsresult (*GetControllerType)(IStorageController *pThis, PRUint32 *controllerType);
    nsresult (*SetControllerType)(IStorageController *pThis, PRUint32 controllerType);

    nsresult (*GetIDEEmulationPort)(
        IStorageController *pThis,
        PRInt32 devicePosition,
        PRInt32 * portNumber
    );

    nsresult (*SetIDEEmulationPort)(
        IStorageController *pThis,
        PRInt32 devicePosition,
        PRInt32 portNumber
    );

};

struct IStorageController
{
    struct IStorageController_vtbl *vtbl;
};
/* End of struct IStorageController Declaration */


/* Start of struct IPerformanceMetric Declaration */
#define IPERFORMANCEMETRIC_IID_STR "2a1a60ae-9345-4019-ad53-d34ba41cbfe9"
#define IPERFORMANCEMETRIC_IID { \
    0x2a1a60ae, 0x9345, 0x4019, \
    { 0xad, 0x53, 0xd3, 0x4b, 0xa4, 0x1c, 0xbf, 0xe9 } \
}
struct IPerformanceMetric_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetMetricName)(IPerformanceMetric *pThis, PRUnichar * *metricName);

    nsresult (*GetObject)(IPerformanceMetric *pThis, nsISupports * *object);

    nsresult (*GetDescription)(IPerformanceMetric *pThis, PRUnichar * *description);

    nsresult (*GetPeriod)(IPerformanceMetric *pThis, PRUint32 *period);

    nsresult (*GetCount)(IPerformanceMetric *pThis, PRUint32 *count);

    nsresult (*GetUnit)(IPerformanceMetric *pThis, PRUnichar * *unit);

    nsresult (*GetMinimumValue)(IPerformanceMetric *pThis, PRInt32 *minimumValue);

    nsresult (*GetMaximumValue)(IPerformanceMetric *pThis, PRInt32 *maximumValue);

};

struct IPerformanceMetric
{
    struct IPerformanceMetric_vtbl *vtbl;
};
/* End of struct IPerformanceMetric Declaration */


/* Start of struct IPerformanceCollector Declaration */
#define IPERFORMANCECOLLECTOR_IID_STR "e22e1acb-ac4a-43bb-a31c-17321659b0c6"
#define IPERFORMANCECOLLECTOR_IID { \
    0xe22e1acb, 0xac4a, 0x43bb, \
    { 0xa3, 0x1c, 0x17, 0x32, 0x16, 0x59, 0xb0, 0xc6 } \
}
struct IPerformanceCollector_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult (*GetMetricNames)(IPerformanceCollector *pThis, PRUint32 *metricNamesSize, PRUnichar * **metricNames);

    nsresult (*GetMetrics)(
        IPerformanceCollector *pThis,
        PRUint32 metricNamesSize,
        PRUnichar ** metricNames,
        PRUint32 objectsSize,
        nsISupports ** objects,
        PRUint32 *metricsSize,
        IPerformanceMetric *** metrics
    );

    nsresult (*SetupMetrics)(
        IPerformanceCollector *pThis,
        PRUint32 metricNamesSize,
        PRUnichar ** metricNames,
        PRUint32 objectsSize,
        nsISupports ** objects,
        PRUint32 period,
        PRUint32 count,
        PRUint32 *affectedMetricsSize,
        IPerformanceMetric *** affectedMetrics
    );

    nsresult (*EnableMetrics)(
        IPerformanceCollector *pThis,
        PRUint32 metricNamesSize,
        PRUnichar ** metricNames,
        PRUint32 objectsSize,
        nsISupports ** objects,
        PRUint32 *affectedMetricsSize,
        IPerformanceMetric *** affectedMetrics
    );

    nsresult (*DisableMetrics)(
        IPerformanceCollector *pThis,
        PRUint32 metricNamesSize,
        PRUnichar ** metricNames,
        PRUint32 objectsSize,
        nsISupports ** objects,
        PRUint32 *affectedMetricsSize,
        IPerformanceMetric *** affectedMetrics
    );

    nsresult (*QueryMetricsData)(
        IPerformanceCollector *pThis,
        PRUint32 metricNamesSize,
        PRUnichar ** metricNames,
        PRUint32 objectsSize,
        nsISupports ** objects,
        PRUint32 *returnMetricNamesSize,
        PRUnichar *** returnMetricNames,
        PRUint32 *returnObjectsSize,
        nsISupports ** returnObjects,
        PRUint32 *returnUnitsSize,
        PRUnichar *** returnUnits,
        PRUint32 *returnScalesSize,
        PRUint32* returnScales,
        PRUint32 *returnSequenceNumbersSize,
        PRUint32* returnSequenceNumbers,
        PRUint32 *returnDataIndicesSize,
        PRUint32* returnDataIndices,
        PRUint32 *returnDataLengthsSize,
        PRUint32* returnDataLengths,
        PRUint32 *returnDataSize,
        PRInt32** returnData
    );

};

struct IPerformanceCollector
{
    struct IPerformanceCollector_vtbl *vtbl;
};
/* End of struct IPerformanceCollector Declaration */



#define NS_VIRTUALBOX_CID { \
    0xB1A7A4F2, 0x47B9, 0x4A1E, \
    { 0x82, 0xB2, 0x07, 0xCC, 0xD5, 0x32, 0x3C, 0x3F } \
}
#define NS_VIRTUALBOX_CONTRACTID "@virtualbox.org/VirtualBox;1"
/* for compatibility with Win32 */
#define CLSID_VirtualBox (nsCID) NS_VIRTUALBOX_CID



#define NS_SESSION_CID { \
    0x3C02F46D, 0xC9D2, 0x4f11, \
    { 0xA3, 0x84, 0x53, 0xF0, 0xCF, 0x91, 0x72, 0x14 } \
}
#define NS_SESSION_CONTRACTID "@virtualbox.org/Session;1"
/* for compatibility with Win32 */
#define CLSID_Session (nsCID) NS_SESSION_CID



#endif /* !__cplusplus */

#ifdef IN_VBOXXPCOMC
# define VBOXXPCOMC_DECL(type)  PR_EXPORT(type)
#else
# define VBOXXPCOMC_DECL(type)  PR_IMPORT(type)
#endif

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Function table for dynamic linking.
 * Use VBoxGetFunctions() to obtain the pointer to it.
 */
typedef struct VBOXXPCOMC
{
    /** The size of the structure. */
    unsigned cb;
    /** The structure version. */
    unsigned uVersion;

    unsigned int (*pfnGetVersion)(void);

    void  (*pfnComInitialize)(IVirtualBox **virtualBox, ISession **session);
    void  (*pfnComUninitialize)(void);

    void  (*pfnComUnallocMem)(void *pv);
    void  (*pfnUtf16Free)(PRUnichar *pwszString);
    void  (*pfnUtf8Free)(char *pszString);

    int   (*pfnUtf16ToUtf8)(const PRUnichar *pwszString, char **ppszString);
    int   (*pfnUtf8ToUtf16)(const char *pszString, PRUnichar **ppwszString);

    /** Tail version, same as uVersion. */
    unsigned uEndVersion;
} VBOXXPCOMC;
/** Pointer to a const VBoxXPCOMC function table. */
typedef VBOXXPCOMC const *PCVBOXXPCOM;

/** The current interface version.
 * For use with VBoxGetXPCOMCFunctions and to be found in
 * VBOXXPCOMC::uVersion. */
#define VBOX_XPCOMC_VERSION     0x00010000U

VBOXXPCOMC_DECL(PCVBOXXPCOM) VBoxGetXPCOMCFunctions(unsigned uVersion);
/** Typedef for VBoxGetXPCOMCFunctions. */
typedef PCVBOXXPCOM (*PFNVBOXGETXPCOMCFUNCTIONS)(unsigned uVersion);

/** The symbol name of VBoxGetXPCOMCFunctions. */
#if defined(__OS2__)
# define VBOX_GET_XPCOMC_FUNCTIONS_SYMBOL_NAME   "_VBoxGetXPCOMCFunctions"
#else
# define VBOX_GET_XPCOMC_FUNCTIONS_SYMBOL_NAME   "VBoxGetXPCOMCFunctions"
#endif


#ifdef __cplusplus
}
#endif

#endif /* !___VirtualBox_CXPCOM_h */
