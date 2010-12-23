/*
 * Libvirt notice: this file is derived from the VirtualBox SDK, with
 * libvirt edits; do not regenerate in the context of libvirt.
 */
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
# define ___VirtualBox_CXPCOM_h

# ifdef __cplusplus
#  include "VirtualBox_XPCOM.h"
# else /* !__cplusplus */

#  include <stddef.h>
#  include "wchar.h"

#  ifdef WIN32
#   define PR_COM_METHOD __stdcall
#   define PR_IID_IN_TYPE GUID
#   define PR_IID_OUT_TYPE GUID *
#  else
#   define PR_COM_METHOD
#   define PR_IID_IN_TYPE const nsID *
#   define PR_IID_OUT_TYPE nsID **
#  endif

#  if defined(WIN32)

#   define PR_EXPORT(__type) extern __declspec(dllexport) __type
#   define PR_EXPORT_DATA(__type) extern __declspec(dllexport) __type
#   define PR_IMPORT(__type) __declspec(dllimport) __type
#   define PR_IMPORT_DATA(__type) __declspec(dllimport) __type

#   define PR_EXTERN(__type) extern __declspec(dllexport) __type
#   define PR_IMPLEMENT(__type) __declspec(dllexport) __type
#   define PR_EXTERN_DATA(__type) extern __declspec(dllexport) __type
#   define PR_IMPLEMENT_DATA(__type) __declspec(dllexport) __type

#   define PR_CALLBACK
#   define PR_CALLBACK_DECL
#   define PR_STATIC_CALLBACK(__x) static __x

#  elif defined(XP_BEOS)

#   define PR_EXPORT(__type) extern __declspec(dllexport) __type
#   define PR_EXPORT_DATA(__type) extern __declspec(dllexport) __type
#   define PR_IMPORT(__type) extern __declspec(dllexport) __type
#   define PR_IMPORT_DATA(__type) extern __declspec(dllexport) __type

#   define PR_EXTERN(__type) extern __declspec(dllexport) __type
#   define PR_IMPLEMENT(__type) __declspec(dllexport) __type
#   define PR_EXTERN_DATA(__type) extern __declspec(dllexport) __type
#   define PR_IMPLEMENT_DATA(__type) __declspec(dllexport) __type

#   define PR_CALLBACK
#   define PR_CALLBACK_DECL
#   define PR_STATIC_CALLBACK(__x) static __x

#  elif defined(WIN16)

#   define PR_CALLBACK_DECL        __cdecl

#   if defined(_WINDLL)
#    define PR_EXPORT(__type) extern __type _cdecl _export _loadds
#    define PR_IMPORT(__type) extern __type _cdecl _export _loadds
#    define PR_EXPORT_DATA(__type) extern __type _export
#    define PR_IMPORT_DATA(__type) extern __type _export

#    define PR_EXTERN(__type) extern __type _cdecl _export _loadds
#    define PR_IMPLEMENT(__type) __type _cdecl _export _loadds
#    define PR_EXTERN_DATA(__type) extern __type _export
#    define PR_IMPLEMENT_DATA(__type) __type _export

#    define PR_CALLBACK             __cdecl __loadds
#    define PR_STATIC_CALLBACK(__x) static __x PR_CALLBACK

#   else /* this must be .EXE */
#    define PR_EXPORT(__type) extern __type _cdecl _export
#    define PR_IMPORT(__type) extern __type _cdecl _export
#    define PR_EXPORT_DATA(__type) extern __type _export
#    define PR_IMPORT_DATA(__type) extern __type _export

#    define PR_EXTERN(__type) extern __type _cdecl _export
#    define PR_IMPLEMENT(__type) __type _cdecl _export
#    define PR_EXTERN_DATA(__type) extern __type _export
#    define PR_IMPLEMENT_DATA(__type) __type _export

#    define PR_CALLBACK             __cdecl __loadds
#    define PR_STATIC_CALLBACK(__x) __x PR_CALLBACK
#   endif /* _WINDLL */

#  elif defined(XP_MAC)

#   define PR_EXPORT(__type) extern __declspec(export) __type
#   define PR_EXPORT_DATA(__type) extern __declspec(export) __type
#   define PR_IMPORT(__type) extern __declspec(export) __type
#   define PR_IMPORT_DATA(__type) extern __declspec(export) __type

#   define PR_EXTERN(__type) extern __declspec(export) __type
#   define PR_IMPLEMENT(__type) __declspec(export) __type
#   define PR_EXTERN_DATA(__type) extern __declspec(export) __type
#   define PR_IMPLEMENT_DATA(__type) __declspec(export) __type

#   define PR_CALLBACK
#   define PR_CALLBACK_DECL
#   define PR_STATIC_CALLBACK(__x) static __x

#  elif defined(XP_OS2) && defined(__declspec)

#   define PR_EXPORT(__type) extern __declspec(dllexport) __type
#   define PR_EXPORT_DATA(__type) extern __declspec(dllexport) __type
#   define PR_IMPORT(__type) __declspec(dllimport) __type
#   define PR_IMPORT_DATA(__type) __declspec(dllimport) __type

#   define PR_EXTERN(__type) extern __declspec(dllexport) __type
#   define PR_IMPLEMENT(__type) __declspec(dllexport) __type
#   define PR_EXTERN_DATA(__type) extern __declspec(dllexport) __type
#   define PR_IMPLEMENT_DATA(__type) __declspec(dllexport) __type

#   define PR_CALLBACK
#   define PR_CALLBACK_DECL
#   define PR_STATIC_CALLBACK(__x) static __x

#  elif defined(XP_OS2_VACPP)

#   define PR_EXPORT(__type) extern __type
#   define PR_EXPORT_DATA(__type) extern __type
#   define PR_IMPORT(__type) extern __type
#   define PR_IMPORT_DATA(__type) extern __type

#   define PR_EXTERN(__type) extern __type
#   define PR_IMPLEMENT(__type) __type
#   define PR_EXTERN_DATA(__type) extern __type
#   define PR_IMPLEMENT_DATA(__type) __type
#   define PR_CALLBACK _Optlink
#   define PR_CALLBACK_DECL
#   define PR_STATIC_CALLBACK(__x) static __x PR_CALLBACK

#  else /* Unix */

#   ifdef VBOX_HAVE_VISIBILITY_HIDDEN
#    define PR_EXPORT(__type) __attribute__((visibility("default"))) extern __type
#    define PR_EXPORT_DATA(__type) __attribute__((visibility("default"))) extern __type
#    define PR_IMPORT(__type) extern __type
#    define PR_IMPORT_DATA(__type) extern __type
#    define PR_EXTERN(__type) __attribute__((visibility("default"))) extern __type
#    define PR_IMPLEMENT(__type) __attribute__((visibility("default"))) __type
#    define PR_EXTERN_DATA(__type) __attribute__((visibility("default"))) extern __type
#    define PR_IMPLEMENT_DATA(__type) __attribute__((visibility("default"))) __type
#    define PR_CALLBACK
#    define PR_CALLBACK_DECL
#    define PR_STATIC_CALLBACK(__x) static __x
#   else
#    define PR_EXPORT(__type) extern __type
#    define PR_EXPORT_DATA(__type) extern __type
#    define PR_IMPORT(__type) extern __type
#    define PR_IMPORT_DATA(__type) extern __type
#    define PR_EXTERN(__type) extern __type
#    define PR_IMPLEMENT(__type) __type
#    define PR_EXTERN_DATA(__type) extern __type
#    define PR_IMPLEMENT_DATA(__type) __type
#    define PR_CALLBACK
#    define PR_CALLBACK_DECL
#    define PR_STATIC_CALLBACK(__x) static __x
#   endif
#  endif

#  if defined(_NSPR_BUILD_)
#   define NSPR_API(__type) PR_EXPORT(__type)
#   define NSPR_DATA_API(__type) PR_EXPORT_DATA(__type)
#  else
#   define NSPR_API(__type) PR_IMPORT(__type)
#   define NSPR_DATA_API(__type) PR_IMPORT_DATA(__type)
#  endif

typedef unsigned char PRUint8;
#  if (defined(HPUX) && defined(__cplusplus) \
        && !defined(__GNUC__) && __cplusplus < 199707L) \
    || (defined(SCO) && defined(__cplusplus) \
        && !defined(__GNUC__) && __cplusplus == 1L)
typedef char PRInt8;
#  else
typedef signed char PRInt8;
#  endif

#  define PR_INT8_MAX 127
#  define PR_INT8_MIN (-128)
#  define PR_UINT8_MAX 255U

typedef unsigned short PRUint16;
typedef short PRInt16;

#  define PR_INT16_MAX 32767
#  define PR_INT16_MIN (-32768)
#  define PR_UINT16_MAX 65535U

typedef unsigned int PRUint32;
typedef int PRInt32;
#  define PR_INT32(x)  x
#  define PR_UINT32(x) x ## U

#  define PR_INT32_MAX PR_INT32(2147483647)
#  define PR_INT32_MIN (-PR_INT32_MAX - 1)
#  define PR_UINT32_MAX PR_UINT32(4294967295)

typedef long PRInt64;
typedef unsigned long PRUint64;
typedef int PRIntn;
typedef unsigned int PRUintn;

typedef double          PRFloat64;
typedef size_t PRSize;

typedef ptrdiff_t PRPtrdiff;

typedef unsigned long PRUptrdiff;

typedef PRIntn PRBool;

#  define PR_TRUE 1
#  define PR_FALSE 0

typedef PRUint8 PRPackedBool;

/*
** Status code used by some routines that have a single point of failure or
** special status return.
*/
typedef enum { PR_FAILURE = -1, PR_SUCCESS = 0 } PRStatus;

#  ifndef __PRUNICHAR__
#   define __PRUNICHAR__
#   if defined(WIN32) || defined(XP_MAC)
typedef wchar_t PRUnichar;
#   else
typedef PRUint16 PRUnichar;
#   endif
#  endif

typedef long PRWord;
typedef unsigned long PRUword;

#  define nsnull 0
typedef PRUint32 nsresult;

#  if defined(__GNUC__) && (__GNUC__ > 2)
#   define NS_LIKELY(x)    (__builtin_expect((x), 1))
#   define NS_UNLIKELY(x)  (__builtin_expect((x), 0))
#  else
#   define NS_LIKELY(x)    (x)
#   define NS_UNLIKELY(x)  (x)
#  endif

#  define NS_FAILED(_nsresult) (NS_UNLIKELY((_nsresult) & 0x80000000))
#  define NS_SUCCEEDED(_nsresult) (NS_LIKELY(!((_nsresult) & 0x80000000)))

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
#  define NS_ISUPPORTS_IID                                                      \
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
  nsresult PR_COM_METHOD (*QueryInterface)(nsISupports *pThis, PR_IID_IN_TYPE iid, void **resultp);
  /**
   * Increases the reference count for this interface.
   * The associated instance will not be deleted unless
   * the reference count is returned to zero.
   *
   * @return The resulting reference count.
   */
  nsresult PR_COM_METHOD (*AddRef)(nsISupports *pThis);

  /**
   * Decreases the reference count for this interface.
   * Generally, if the reference count returns to zero,
   * the associated instance is deleted.
   *
   * @return The resulting reference count.
   */
  nsresult PR_COM_METHOD (*Release)(nsISupports *pThis);
};

struct nsISupports {
    struct nsISupports_vtbl *vtbl;
};

/* starting interface:    nsIException */
#  define NS_IEXCEPTION_IID_STR "f3a8d3b4-c424-4edc-8bf6-8974c983ba78"

#  define NS_IEXCEPTION_IID \
  {0xf3a8d3b4, 0xc424, 0x4edc, \
    { 0x8b, 0xf6, 0x89, 0x74, 0xc9, 0x83, 0xba, 0x78 }}

struct nsIException_vtbl {

  /* Methods from the Class nsISupports */
  struct nsISupports_vtbl nsisupports;

  /* readonly attribute string message; */
  nsresult PR_COM_METHOD (*GetMessage)(nsIException *pThis, PRUnichar * *aMessage);

  /* readonly attribute nsresult PR_COM_METHOD (*result; */
  nsresult PR_COM_METHOD (*GetResult)(nsIException *pThis, nsresult *aResult);

  /* readonly attribute string name; */
  nsresult PR_COM_METHOD (*GetName)(nsIException *pThis, PRUnichar * *aName);

  /* readonly attribute string filename; */
  nsresult PR_COM_METHOD (*GetFilename)(nsIException *pThis, PRUnichar * *aFilename);

  /* readonly attribute PRUint32 lineNumber; */
  nsresult PR_COM_METHOD (*GetLineNumber)(nsIException *pThis, PRUint32 *aLineNumber);

  /* readonly attribute PRUint32 columnNumber; */
  nsresult PR_COM_METHOD (*GetColumnNumber)(nsIException *pThis, PRUint32 *aColumnNumber);

  /* readonly attribute nsIStackFrame location; */
  nsresult PR_COM_METHOD (*GetLocation)(nsIException *pThis, nsIStackFrame * *aLocation);

  /* readonly attribute nsIException inner; */
  nsresult PR_COM_METHOD (*GetInner)(nsIException *pThis, nsIException * *aInner);

  /* readonly attribute nsISupports data; */
  nsresult PR_COM_METHOD (*GetData)(nsIException *pThis, nsISupports * *aData);

  /* string toString (); */
  nsresult PR_COM_METHOD (*ToString)(nsIException *pThis, PRUnichar **_retval);
};

struct nsIException {
    struct nsIException_vtbl *vtbl;
};

/* starting interface:    nsIStackFrame */
#  define NS_ISTACKFRAME_IID_STR "91d82105-7c62-4f8b-9779-154277c0ee90"

#  define NS_ISTACKFRAME_IID \
  {0x91d82105, 0x7c62, 0x4f8b, \
    { 0x97, 0x79, 0x15, 0x42, 0x77, 0xc0, 0xee, 0x90 }}

struct nsIStackFrame_vtbl {

  /* Methods from the Class nsISupports */
  struct nsISupports_vtbl nsisupports;

  /* readonly attribute PRUint32 language; */
  nsresult PR_COM_METHOD (*GetLanguage)(nsIStackFrame *pThis, PRUint32 *aLanguage);

  /* readonly attribute string languageName; */
  nsresult PR_COM_METHOD (*GetLanguageName)(nsIStackFrame *pThis, PRUnichar * *aLanguageName);

  /* readonly attribute string filename; */
  nsresult PR_COM_METHOD (*GetFilename)(nsIStackFrame *pThis, PRUnichar * *aFilename);

  /* readonly attribute string name; */
  nsresult PR_COM_METHOD (*GetName)(nsIStackFrame *pThis, PRUnichar * *aName);

  /* readonly attribute PRInt32 lineNumber; */
  nsresult PR_COM_METHOD (*GetLineNumber)(nsIStackFrame *pThis, PRInt32 *aLineNumber);

  /* readonly attribute string sourceLine; */
  nsresult PR_COM_METHOD (*GetSourceLine)(nsIStackFrame *pThis, PRUnichar * *aSourceLine);

  /* readonly attribute nsIStackFrame caller; */
  nsresult PR_COM_METHOD (*GetCaller)(nsIStackFrame *pThis, nsIStackFrame * *aCaller);

  /* string toString (); */
  nsresult PR_COM_METHOD (*ToString)(nsIStackFrame *pThis, PRUnichar **_retval);
};

struct nsIStackFrame {
    struct nsIStackFrame_vtbl *vtbl;
};


#  define VBOX_E_OBJECT_NOT_FOUND 0x80BB0001
#  define VBOX_E_INVALID_VM_STATE 0x80BB0002
#  define VBOX_E_VM_ERROR 0x80BB0003
#  define VBOX_E_FILE_ERROR 0x80BB0004
#  define VBOX_E_IPRT_ERROR 0x80BB0005
#  define VBOX_E_PDM_ERROR 0x80BB0006
#  define VBOX_E_INVALID_OBJECT_STATE 0x80BB0007
#  define VBOX_E_HOST_ERROR 0x80BB0008
#  define VBOX_E_NOT_SUPPORTED 0x80BB0009
#  define VBOX_E_XML_ERROR 0x80BB000A
#  define VBOX_E_INVALID_SESSION_STATE 0x80BB000B
#  define VBOX_E_OBJECT_IN_USE 0x80BB000C


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
#  define TSBOOL_IID_STR "523ff64d-842a-4b1a-80e7-c311b028cb3a"
#  define TSBOOL_IID { \
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
#  define ACCESSMODE_IID_STR "1da0007c-ddf7-4be8-bcac-d84a1558785f"
#  define ACCESSMODE_IID { \
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
#  define MACHINESTATE_IID_STR "73bf04d0-7c4f-4684-9abf-d65a9ad74343"
#  define MACHINESTATE_IID { \
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
#  define SESSIONSTATE_IID_STR "CF2700C0-EA4B-47ae-9725-7810114B94D8"
#  define SESSIONSTATE_IID { \
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
#  define SESSIONTYPE_IID_STR "A13C02CB-0C2C-421E-8317-AC0E8AAA153A"
#  define SESSIONTYPE_IID { \
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
#  define DEVICETYPE_IID_STR "6d9420f7-0b56-4636-99f9-7346f1b01e57"
#  define DEVICETYPE_IID { \
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
#  define DEVICEACTIVITY_IID_STR "6FC8AEAA-130A-4eb5-8954-3F921422D707"
#  define DEVICEACTIVITY_IID { \
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
#  define CLIPBOARDMODE_IID_STR "33364716-4008-4701-8f14-be0fa3d62950"
#  define CLIPBOARDMODE_IID { \
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
#  define SCOPE_IID_STR "7c91096e-499e-4eca-9f9b-9001438d7855"
#  define SCOPE_IID { \
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
#  define GUESTSTATISTICTYPE_IID_STR "aa7c1d71-aafe-47a8-9608-27d2d337cf55"
#  define GUESTSTATISTICTYPE_IID { \
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
#  define BIOSBOOTMENUMODE_IID_STR "ae4fb9f7-29d2-45b4-b2c7-d579603135d5"
#  define BIOSBOOTMENUMODE_IID { \
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
#  define DRIVESTATE_IID_STR "cb7233b7-c519-42a5-8310-1830953cacbc"
#  define DRIVESTATE_IID { \
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
#  define PROCESSORFEATURE_IID_STR "b8353b35-705d-4796-9967-ebfb7ba54af4"
#  define PROCESSORFEATURE_IID { \
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
#  define CIMOSTYPE_IID_STR "86ef5f8c-18b2-4db8-a314-33721b59f89b"
#  define CIMOSTYPE_IID { \
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
#  define OVFRESOURCETYPE_IID_STR "646a78d7-6f04-49f4-82c4-75c28a75a4cd"
#  define OVFRESOURCETYPE_IID { \
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
#  define VIRTUALSYSTEMDESCRIPTIONTYPE_IID_STR "aacc58de-5b45-4f82-ae2e-dd9a824fc3b5"
#  define VIRTUALSYSTEMDESCRIPTIONTYPE_IID { \
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
#  define VIRTUALSYSTEMDESCRIPTIONVALUETYPE_IID_STR "56d9403f-3425-4118-9919-36f2a9b8c77c"
#  define VIRTUALSYSTEMDESCRIPTIONVALUETYPE_IID { \
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
#  define HOSTNETWORKINTERFACEMEDIUMTYPE_IID_STR "1aa54aaf-2497-45a2-bfb1-8eb225e93d5b"
#  define HOSTNETWORKINTERFACEMEDIUMTYPE_IID { \
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
#  define HOSTNETWORKINTERFACESTATUS_IID_STR "CC474A69-2710-434B-8D99-C38E5D5A6F41"
#  define HOSTNETWORKINTERFACESTATUS_IID { \
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
#  define HOSTNETWORKINTERFACETYPE_IID_STR "67431b00-9946-48a2-bc02-b25c5919f4f3"
#  define HOSTNETWORKINTERFACETYPE_IID { \
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
#  define MEDIASTATE_IID_STR "8b86e03c-2f1c-412a-8fbd-326f62701200"
#  define MEDIASTATE_IID { \
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
#  define HARDDISKTYPE_IID_STR "a348fafd-a64e-4643-ba65-eb3896bd7e0a"
#  define HARDDISKTYPE_IID { \
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
#  define HARDDISKVARIANT_IID_STR "eb7fc6b3-ae23-4c5d-a1f6-e3522dd1efb0"
#  define HARDDISKVARIANT_IID { \
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
#  define DATATYPE_IID_STR "d90ea51e-a3f1-4a01-beb1-c1723c0d3ba7"
#  define DATATYPE_IID { \
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
#  define DATAFLAGS_IID_STR "86884dcf-1d6b-4f1b-b4bf-f5aa44959d60"
#  define DATAFLAGS_IID { \
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
#  define HARDDISKFORMATCAPABILITIES_IID_STR "1df1e4aa-d25a-4ba6-b2a2-02f60eb5903b"
#  define HARDDISKFORMATCAPABILITIES_IID { \
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
#  define MOUSEBUTTONSTATE_IID_STR "03131722-2EC5-4173-9794-0DACA46673EF"
#  define MOUSEBUTTONSTATE_IID { \
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
#  define FRAMEBUFFERACCELERATIONOPERATION_IID_STR "f0e5ebbe-dc8e-4e2d-916e-53baa3844df8"
#  define FRAMEBUFFERACCELERATIONOPERATION_IID { \
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
#  define FRAMEBUFFERPIXELFORMAT_IID_STR "7acfd5ed-29e3-45e3-8136-73c9224f3d2d"
#  define FRAMEBUFFERPIXELFORMAT_IID { \
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
#  define NETWORKATTACHMENTTYPE_IID_STR "44bce1ee-99f7-4e8e-89fc-80597fd9eeaf"
#  define NETWORKATTACHMENTTYPE_IID { \
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
#  define NETWORKADAPTERTYPE_IID_STR "50c3dfd8-07ac-4a31-baac-519c828fbf97"
#  define NETWORKADAPTERTYPE_IID { \
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
#  define PORTMODE_IID_STR "b266f43c-2e93-46b3-812b-c20e600e867b"
#  define PORTMODE_IID { \
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
#  define USBDEVICESTATE_IID_STR "b99a2e65-67fb-4882-82fd-f3e5e8193ab4"
#  define USBDEVICESTATE_IID { \
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
#  define USBDEVICEFILTERACTION_IID_STR "cbc30a49-2f4e-43b5-9da6-121320475933"
#  define USBDEVICEFILTERACTION_IID { \
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
#  define AUDIODRIVERTYPE_IID_STR "4bcc3d73-c2fe-40db-b72f-0c2ca9d68496"
#  define AUDIODRIVERTYPE_IID { \
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
#  define AUDIOCONTROLLERTYPE_IID_STR "7afd395c-42c3-444e-8788-3ce80292f36c"
#  define AUDIOCONTROLLERTYPE_IID { \
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
#  define VRDPAUTHTYPE_IID_STR "3d91887a-b67f-4b33-85bf-2da7ab1ea83a"
#  define VRDPAUTHTYPE_IID { \
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
#  define STORAGEBUS_IID_STR "f381fdca-5953-41d0-b2bd-0542b012698d"
#  define STORAGEBUS_IID { \
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
#  define STORAGECONTROLLERTYPE_IID_STR "685387db-a837-4320-a258-08f46a22f62a"
#  define STORAGECONTROLLERTYPE_IID { \
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
#  define IVIRTUALBOXERRORINFO_IID_STR "e98b5376-8eb4-4eea-812a-3964bf3bb26f"
#  define IVIRTUALBOXERRORINFO_IID { \
    0xe98b5376, 0x8eb4, 0x4eea, \
    { 0x81, 0x2a, 0x39, 0x64, 0xbf, 0x3b, 0xb2, 0x6f } \
}
struct IVirtualBoxErrorInfo_vtbl
{
    struct nsIException_vtbl nsiexception;

    nsresult PR_COM_METHOD (*GetResultCode)(IVirtualBoxErrorInfo *pThis, nsresult *resultCode);

    nsresult PR_COM_METHOD (*GetInterfaceID)(IVirtualBoxErrorInfo *pThis, PR_IID_OUT_TYPE interfaceID);

    nsresult PR_COM_METHOD (*GetComponent)(IVirtualBoxErrorInfo *pThis, PRUnichar * *component);

    nsresult PR_COM_METHOD (*GetText)(IVirtualBoxErrorInfo *pThis, PRUnichar * *text);

    nsresult PR_COM_METHOD (*GetNext)(IVirtualBoxErrorInfo *pThis, IVirtualBoxErrorInfo * *next);

};

struct IVirtualBoxErrorInfo
{
    struct IVirtualBoxErrorInfo_vtbl *vtbl;
};
/* End of struct IVirtualBoxErrorInfo Declaration */


/* Start of struct IVirtualBoxCallback Declaration */
#  define IVIRTUALBOXCALLBACK_IID_STR "5516cc08-fb81-47a6-b184-031e7bbd2997"
#  define IVIRTUALBOXCALLBACK_IID { \
    0x5516cc08, 0xfb81, 0x47a6, \
    { 0xb1, 0x84, 0x03, 0x1e, 0x7b, 0xbd, 0x29, 0x97 } \
}
struct IVirtualBoxCallback_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*OnMachineStateChange)(
        IVirtualBoxCallback *pThis,
        PR_IID_IN_TYPE machineId,
        PRUint32 state
    );

    nsresult PR_COM_METHOD (*OnMachineDataChange)(
        IVirtualBoxCallback *pThis,
        PR_IID_IN_TYPE machineId
    );

    nsresult PR_COM_METHOD (*OnExtraDataCanChange)(
        IVirtualBoxCallback *pThis,
        PR_IID_IN_TYPE machineId,
        PRUnichar * key,
        PRUnichar * value,
        PRUnichar * * error,
        PRBool * allowChange
    );

    nsresult PR_COM_METHOD (*OnExtraDataChange)(
        IVirtualBoxCallback *pThis,
        PR_IID_IN_TYPE machineId,
        PRUnichar * key,
        PRUnichar * value
    );

    nsresult PR_COM_METHOD (*OnMediaRegistered)(
        IVirtualBoxCallback *pThis,
        PR_IID_IN_TYPE mediaId,
        PRUint32 mediaType,
        PRBool registered
    );

    nsresult PR_COM_METHOD (*OnMachineRegistered)(
        IVirtualBoxCallback *pThis,
        PR_IID_IN_TYPE machineId,
        PRBool registered
    );

    nsresult PR_COM_METHOD (*OnSessionStateChange)(
        IVirtualBoxCallback *pThis,
        PR_IID_IN_TYPE machineId,
        PRUint32 state
    );

    nsresult PR_COM_METHOD (*OnSnapshotTaken)(
        IVirtualBoxCallback *pThis,
        PR_IID_IN_TYPE machineId,
        PR_IID_IN_TYPE snapshotId
    );

    nsresult PR_COM_METHOD (*OnSnapshotDiscarded)(
        IVirtualBoxCallback *pThis,
        PR_IID_IN_TYPE machineId,
        PR_IID_IN_TYPE snapshotId
    );

    nsresult PR_COM_METHOD (*OnSnapshotChange)(
        IVirtualBoxCallback *pThis,
        PR_IID_IN_TYPE machineId,
        PR_IID_IN_TYPE snapshotId
    );

    nsresult PR_COM_METHOD (*OnGuestPropertyChange)(
        IVirtualBoxCallback *pThis,
        PR_IID_IN_TYPE machineId,
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
#  define IDHCPSERVER_IID_STR "6cfe387c-74fb-4ca7-bff6-973bec8af7a3"
#  define IDHCPSERVER_IID { \
    0x6cfe387c, 0x74fb, 0x4ca7, \
    { 0xbf, 0xf6, 0x97, 0x3b, 0xec, 0x8a, 0xf7, 0xa3 } \
}
struct IDHCPServer_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetEnabled)(IDHCPServer *pThis, PRBool *enabled);
    nsresult PR_COM_METHOD (*SetEnabled)(IDHCPServer *pThis, PRBool enabled);

    nsresult PR_COM_METHOD (*GetIPAddress)(IDHCPServer *pThis, PRUnichar * *IPAddress);

    nsresult PR_COM_METHOD (*GetNetworkMask)(IDHCPServer *pThis, PRUnichar * *networkMask);

    nsresult PR_COM_METHOD (*GetNetworkName)(IDHCPServer *pThis, PRUnichar * *networkName);

    nsresult PR_COM_METHOD (*GetLowerIP)(IDHCPServer *pThis, PRUnichar * *lowerIP);

    nsresult PR_COM_METHOD (*GetUpperIP)(IDHCPServer *pThis, PRUnichar * *upperIP);

    nsresult PR_COM_METHOD (*SetConfiguration)(
        IDHCPServer *pThis,
        PRUnichar * IPAddress,
        PRUnichar * networkMask,
        PRUnichar * FromIPAddress,
        PRUnichar * ToIPAddress
    );

    nsresult PR_COM_METHOD (*Start)(
        IDHCPServer *pThis,
        PRUnichar * networkName,
        PRUnichar * trunkName,
        PRUnichar * trunkType
    );

    nsresult PR_COM_METHOD (*Stop)(IDHCPServer *pThis );

};

struct IDHCPServer
{
    struct IDHCPServer_vtbl *vtbl;
};
/* End of struct IDHCPServer Declaration */


/* Start of struct IVirtualBox Declaration */
#  define IVIRTUALBOX_IID_STR "779264f4-65ed-48ed-be39-518ca549e296"
#  define IVIRTUALBOX_IID { \
    0x779264f4, 0x65ed, 0x48ed, \
    { 0xbe, 0x39, 0x51, 0x8c, 0xa5, 0x49, 0xe2, 0x96 } \
}
struct IVirtualBox_vtbl
{
    struct nsISupports_vtbl nsisupports;

#  ifdef WIN32
    /* The MSCOM implementation has some additional methods here.
     * So add them here to get correct binary layout of the object.
     * In API version 2.2 this affects IVirtualBox and ISession only. */
    nsresult PR_COM_METHOD (*GetTypeInfoCount)(IVirtualBox *pThis);
    nsresult PR_COM_METHOD (*GetTypeInfo)(IVirtualBox *pThis);
    nsresult PR_COM_METHOD (*GetIDsOfNames)(IVirtualBox *pThis);
    nsresult PR_COM_METHOD (*Invoke)(IVirtualBox *pThis);
#  endif

    nsresult PR_COM_METHOD (*GetVersion)(IVirtualBox *pThis, PRUnichar * *version);

    nsresult PR_COM_METHOD (*GetRevision)(IVirtualBox *pThis, PRUint32 *revision);

    nsresult PR_COM_METHOD (*GetPackageType)(IVirtualBox *pThis, PRUnichar * *packageType);

    nsresult PR_COM_METHOD (*GetHomeFolder)(IVirtualBox *pThis, PRUnichar * *homeFolder);

    nsresult PR_COM_METHOD (*GetSettingsFilePath)(IVirtualBox *pThis, PRUnichar * *settingsFilePath);

    nsresult PR_COM_METHOD (*GetSettingsFileVersion)(IVirtualBox *pThis, PRUnichar * *settingsFileVersion);

    nsresult PR_COM_METHOD (*GetSettingsFormatVersion)(IVirtualBox *pThis, PRUnichar * *settingsFormatVersion);

    nsresult PR_COM_METHOD (*GetHost)(IVirtualBox *pThis, IHost * *host);

    nsresult PR_COM_METHOD (*GetSystemProperties)(IVirtualBox *pThis, ISystemProperties * *systemProperties);

    nsresult PR_COM_METHOD (*GetMachines)(IVirtualBox *pThis, PRUint32 *machinesSize, IMachine * **machines);

    nsresult PR_COM_METHOD (*GetHardDisks)(IVirtualBox *pThis, PRUint32 *hardDisksSize, IHardDisk * **hardDisks);

    nsresult PR_COM_METHOD (*GetDVDImages)(IVirtualBox *pThis, PRUint32 *DVDImagesSize, IDVDImage * **DVDImages);

    nsresult PR_COM_METHOD (*GetFloppyImages)(IVirtualBox *pThis, PRUint32 *floppyImagesSize, IFloppyImage * **floppyImages);

    nsresult PR_COM_METHOD (*GetProgressOperations)(IVirtualBox *pThis, PRUint32 *progressOperationsSize, IProgress * **progressOperations);

    nsresult PR_COM_METHOD (*GetGuestOSTypes)(IVirtualBox *pThis, PRUint32 *guestOSTypesSize, IGuestOSType * **guestOSTypes);

    nsresult PR_COM_METHOD (*GetSharedFolders)(IVirtualBox *pThis, PRUint32 *sharedFoldersSize, ISharedFolder * **sharedFolders);

    nsresult PR_COM_METHOD (*GetPerformanceCollector)(IVirtualBox *pThis, IPerformanceCollector * *performanceCollector);

    nsresult PR_COM_METHOD (*GetDHCPServers)(IVirtualBox *pThis, PRUint32 *DHCPServersSize, IDHCPServer * **DHCPServers);

    nsresult PR_COM_METHOD (*CreateMachine)(
        IVirtualBox *pThis,
        PRUnichar * name,
        PRUnichar * osTypeId,
        PRUnichar * baseFolder,
        PR_IID_IN_TYPE id,
        IMachine * * machine
    );

    nsresult PR_COM_METHOD (*CreateLegacyMachine)(
        IVirtualBox *pThis,
        PRUnichar * name,
        PRUnichar * osTypeId,
        PRUnichar * settingsFile,
        PR_IID_IN_TYPE id,
        IMachine * * machine
    );

    nsresult PR_COM_METHOD (*OpenMachine)(
        IVirtualBox *pThis,
        PRUnichar * settingsFile,
        IMachine * * machine
    );

    nsresult PR_COM_METHOD (*RegisterMachine)(
        IVirtualBox *pThis,
        IMachine * machine
    );

    nsresult PR_COM_METHOD (*GetMachine)(
        IVirtualBox *pThis,
        PR_IID_IN_TYPE id,
        IMachine * * machine
    );

    nsresult PR_COM_METHOD (*FindMachine)(
        IVirtualBox *pThis,
        PRUnichar * name,
        IMachine * * machine
    );

    nsresult PR_COM_METHOD (*UnregisterMachine)(
        IVirtualBox *pThis,
        PR_IID_IN_TYPE id,
        IMachine * * machine
    );

    nsresult PR_COM_METHOD (*CreateAppliance)(
        IVirtualBox *pThis,
        IAppliance * * appliance
    );

    nsresult PR_COM_METHOD (*CreateHardDisk)(
        IVirtualBox *pThis,
        PRUnichar * format,
        PRUnichar * location,
        IHardDisk * * hardDisk
    );

    nsresult PR_COM_METHOD (*OpenHardDisk)(
        IVirtualBox *pThis,
        PRUnichar * location,
        PRUint32 accessMode,
        IHardDisk * * hardDisk
    );

    nsresult PR_COM_METHOD (*GetHardDisk)(
        IVirtualBox *pThis,
        PR_IID_IN_TYPE id,
        IHardDisk * * hardDisk
    );

    nsresult PR_COM_METHOD (*FindHardDisk)(
        IVirtualBox *pThis,
        PRUnichar * location,
        IHardDisk * * hardDisk
    );

    nsresult PR_COM_METHOD (*OpenDVDImage)(
        IVirtualBox *pThis,
        PRUnichar * location,
        PR_IID_IN_TYPE id,
        IDVDImage * * image
    );

    nsresult PR_COM_METHOD (*GetDVDImage)(
        IVirtualBox *pThis,
        PR_IID_IN_TYPE id,
        IDVDImage * * image
    );

    nsresult PR_COM_METHOD (*FindDVDImage)(
        IVirtualBox *pThis,
        PRUnichar * location,
        IDVDImage * * image
    );

    nsresult PR_COM_METHOD (*OpenFloppyImage)(
        IVirtualBox *pThis,
        PRUnichar * location,
        PR_IID_IN_TYPE id,
        IFloppyImage * * image
    );

    nsresult PR_COM_METHOD (*GetFloppyImage)(
        IVirtualBox *pThis,
        PR_IID_IN_TYPE id,
        IFloppyImage * * image
    );

    nsresult PR_COM_METHOD (*FindFloppyImage)(
        IVirtualBox *pThis,
        PRUnichar * location,
        IFloppyImage * * image
    );

    nsresult PR_COM_METHOD (*GetGuestOSType)(
        IVirtualBox *pThis,
        PRUnichar * id,
        IGuestOSType * * type
    );

    nsresult PR_COM_METHOD (*CreateSharedFolder)(
        IVirtualBox *pThis,
        PRUnichar * name,
        PRUnichar * hostPath,
        PRBool writable
    );

    nsresult PR_COM_METHOD (*RemoveSharedFolder)(
        IVirtualBox *pThis,
        PRUnichar * name
    );

    nsresult PR_COM_METHOD (*GetNextExtraDataKey)(
        IVirtualBox *pThis,
        PRUnichar * key,
        PRUnichar * * nextKey,
        PRUnichar * * nextValue
    );

    nsresult PR_COM_METHOD (*GetExtraData)(
        IVirtualBox *pThis,
        PRUnichar * key,
        PRUnichar * * value
    );

    nsresult PR_COM_METHOD (*SetExtraData)(
        IVirtualBox *pThis,
        PRUnichar * key,
        PRUnichar * value
    );

    nsresult PR_COM_METHOD (*OpenSession)(
        IVirtualBox *pThis,
        ISession * session,
        PR_IID_IN_TYPE machineId
    );

    nsresult PR_COM_METHOD (*OpenRemoteSession)(
        IVirtualBox *pThis,
        ISession * session,
        PR_IID_IN_TYPE machineId,
        PRUnichar * type,
        PRUnichar * environment,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*OpenExistingSession)(
        IVirtualBox *pThis,
        ISession * session,
        PR_IID_IN_TYPE machineId
    );

    nsresult PR_COM_METHOD (*RegisterCallback)(
        IVirtualBox *pThis,
        IVirtualBoxCallback * callback
    );

    nsresult PR_COM_METHOD (*UnregisterCallback)(
        IVirtualBox *pThis,
        IVirtualBoxCallback * callback
    );

    nsresult PR_COM_METHOD (*WaitForPropertyChange)(
        IVirtualBox *pThis,
        PRUnichar * what,
        PRUint32 timeout,
        PRUnichar * * changed,
        PRUnichar * * values
    );

    nsresult PR_COM_METHOD (*SaveSettings)(IVirtualBox *pThis );

    nsresult PR_COM_METHOD (*SaveSettingsWithBackup)(
        IVirtualBox *pThis,
        PRUnichar * * bakFileName
    );

    nsresult PR_COM_METHOD (*CreateDHCPServer)(
        IVirtualBox *pThis,
        PRUnichar * name,
        IDHCPServer * * server
    );

    nsresult PR_COM_METHOD (*FindDHCPServerByNetworkName)(
        IVirtualBox *pThis,
        PRUnichar * name,
        IDHCPServer * * server
    );

    nsresult PR_COM_METHOD (*RemoveDHCPServer)(
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
#  define IAPPLIANCE_IID_STR "30bfa6b8-9eda-4b0a-b218-a86813248ccd"
#  define IAPPLIANCE_IID { \
    0x30bfa6b8, 0x9eda, 0x4b0a, \
    { 0xb2, 0x18, 0xa8, 0x68, 0x13, 0x24, 0x8c, 0xcd } \
}
struct IAppliance_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetPath)(IAppliance *pThis, PRUnichar * *path);

    nsresult PR_COM_METHOD (*GetDisks)(IAppliance *pThis, PRUint32 *disksSize, PRUnichar * **disks);

    nsresult PR_COM_METHOD (*GetVirtualSystemDescriptions)(IAppliance *pThis, PRUint32 *virtualSystemDescriptionsSize, IVirtualSystemDescription * **virtualSystemDescriptions);

    nsresult PR_COM_METHOD (*Read)(
        IAppliance *pThis,
        PRUnichar * file
    );

    nsresult PR_COM_METHOD (*Interpret)(IAppliance *pThis );

    nsresult PR_COM_METHOD (*ImportMachines)(
        IAppliance *pThis,
        IProgress * * aProgress
    );

    nsresult PR_COM_METHOD (*Write)(
        IAppliance *pThis,
        PRUnichar * format,
        PRUnichar * path,
        IProgress * * aProgress
    );

    nsresult PR_COM_METHOD (*GetWarnings)(
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
#  define IVIRTUALSYSTEMDESCRIPTION_IID_STR "d7525e6c-531a-4c51-8e04-41235083a3d8"
#  define IVIRTUALSYSTEMDESCRIPTION_IID { \
    0xd7525e6c, 0x531a, 0x4c51, \
    { 0x8e, 0x04, 0x41, 0x23, 0x50, 0x83, 0xa3, 0xd8 } \
}
struct IVirtualSystemDescription_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetCount)(IVirtualSystemDescription *pThis, PRUint32 *count);

    nsresult PR_COM_METHOD (*GetDescription)(
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

    nsresult PR_COM_METHOD (*GetDescriptionByType)(
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

    nsresult PR_COM_METHOD (*GetValuesByType)(
        IVirtualSystemDescription *pThis,
        PRUint32 aType,
        PRUint32 aWhich,
        PRUint32 *aValuesSize,
        PRUnichar *** aValues
    );

    nsresult PR_COM_METHOD (*SetFinalValues)(
        IVirtualSystemDescription *pThis,
        PRUint32 aEnabledSize,
        PRBool* aEnabled,
        PRUint32 aVboxValuesSize,
        PRUnichar ** aVboxValues,
        PRUint32 aExtraConfigValuesSize,
        PRUnichar ** aExtraConfigValues
    );

    nsresult PR_COM_METHOD (*AddDescription)(
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
#  define IINTERNALMACHINECONTROL_IID_STR "2c88b969-7a74-4ef3-b95f-8a209a1535f3"
#  define IINTERNALMACHINECONTROL_IID { \
    0x2c88b969, 0x7a74, 0x4ef3, \
    { 0xb9, 0x5f, 0x8a, 0x20, 0x9a, 0x15, 0x35, 0xf3 } \
}
struct IInternalMachineControl_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*UpdateState)(
        IInternalMachineControl *pThis,
        PRUint32 state
    );

    nsresult PR_COM_METHOD (*GetIPCId)(
        IInternalMachineControl *pThis,
        PRUnichar * * id
    );

    nsresult PR_COM_METHOD (*RunUSBDeviceFilters)(
        IInternalMachineControl *pThis,
        IUSBDevice * device,
        PRBool * matched,
        PRUint32 * maskedInterfaces
    );

    nsresult PR_COM_METHOD (*CaptureUSBDevice)(
        IInternalMachineControl *pThis,
        PR_IID_IN_TYPE id
    );

    nsresult PR_COM_METHOD (*DetachUSBDevice)(
        IInternalMachineControl *pThis,
        PR_IID_IN_TYPE id,
        PRBool done
    );

    nsresult PR_COM_METHOD (*AutoCaptureUSBDevices)(IInternalMachineControl *pThis );

    nsresult PR_COM_METHOD (*DetachAllUSBDevices)(
        IInternalMachineControl *pThis,
        PRBool done
    );

    nsresult PR_COM_METHOD (*OnSessionEnd)(
        IInternalMachineControl *pThis,
        ISession * session,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*BeginSavingState)(
        IInternalMachineControl *pThis,
        IProgress * progress,
        PRUnichar * * stateFilePath
    );

    nsresult PR_COM_METHOD (*EndSavingState)(
        IInternalMachineControl *pThis,
        PRBool success
    );

    nsresult PR_COM_METHOD (*AdoptSavedState)(
        IInternalMachineControl *pThis,
        PRUnichar * savedStateFile
    );

    nsresult PR_COM_METHOD (*BeginTakingSnapshot)(
        IInternalMachineControl *pThis,
        IConsole * initiator,
        PRUnichar * name,
        PRUnichar * description,
        IProgress * progress,
        PRUnichar * * stateFilePath,
        IProgress * * serverProgress
    );

    nsresult PR_COM_METHOD (*EndTakingSnapshot)(
        IInternalMachineControl *pThis,
        PRBool success
    );

    nsresult PR_COM_METHOD (*DiscardSnapshot)(
        IInternalMachineControl *pThis,
        IConsole * initiator,
        PR_IID_IN_TYPE id,
        PRUint32 * machineState,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*DiscardCurrentState)(
        IInternalMachineControl *pThis,
        IConsole * initiator,
        PRUint32 * machineState,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*DiscardCurrentSnapshotAndState)(
        IInternalMachineControl *pThis,
        IConsole * initiator,
        PRUint32 * machineState,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*PullGuestProperties)(
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

    nsresult PR_COM_METHOD (*PushGuestProperties)(
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

    nsresult PR_COM_METHOD (*PushGuestProperty)(
        IInternalMachineControl *pThis,
        PRUnichar * name,
        PRUnichar * value,
        PRUint64 timestamp,
        PRUnichar * flags
    );

    nsresult PR_COM_METHOD (*LockMedia)(IInternalMachineControl *pThis );

};

struct IInternalMachineControl
{
    struct IInternalMachineControl_vtbl *vtbl;
};
/* End of struct IInternalMachineControl Declaration */


/* Start of struct IBIOSSettings Declaration */
#  define IBIOSSETTINGS_IID_STR "38b54279-dc35-4f5e-a431-835b867c6b5e"
#  define IBIOSSETTINGS_IID { \
    0x38b54279, 0xdc35, 0x4f5e, \
    { 0xa4, 0x31, 0x83, 0x5b, 0x86, 0x7c, 0x6b, 0x5e } \
}
struct IBIOSSettings_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetLogoFadeIn)(IBIOSSettings *pThis, PRBool *logoFadeIn);
    nsresult PR_COM_METHOD (*SetLogoFadeIn)(IBIOSSettings *pThis, PRBool logoFadeIn);

    nsresult PR_COM_METHOD (*GetLogoFadeOut)(IBIOSSettings *pThis, PRBool *logoFadeOut);
    nsresult PR_COM_METHOD (*SetLogoFadeOut)(IBIOSSettings *pThis, PRBool logoFadeOut);

    nsresult PR_COM_METHOD (*GetLogoDisplayTime)(IBIOSSettings *pThis, PRUint32 *logoDisplayTime);
    nsresult PR_COM_METHOD (*SetLogoDisplayTime)(IBIOSSettings *pThis, PRUint32 logoDisplayTime);

    nsresult PR_COM_METHOD (*GetLogoImagePath)(IBIOSSettings *pThis, PRUnichar * *logoImagePath);
    nsresult PR_COM_METHOD (*SetLogoImagePath)(IBIOSSettings *pThis, PRUnichar * logoImagePath);

    nsresult PR_COM_METHOD (*GetBootMenuMode)(IBIOSSettings *pThis, PRUint32 *bootMenuMode);
    nsresult PR_COM_METHOD (*SetBootMenuMode)(IBIOSSettings *pThis, PRUint32 bootMenuMode);

    nsresult PR_COM_METHOD (*GetACPIEnabled)(IBIOSSettings *pThis, PRBool *ACPIEnabled);
    nsresult PR_COM_METHOD (*SetACPIEnabled)(IBIOSSettings *pThis, PRBool ACPIEnabled);

    nsresult PR_COM_METHOD (*GetIOAPICEnabled)(IBIOSSettings *pThis, PRBool *IOAPICEnabled);
    nsresult PR_COM_METHOD (*SetIOAPICEnabled)(IBIOSSettings *pThis, PRBool IOAPICEnabled);

    nsresult PR_COM_METHOD (*GetTimeOffset)(IBIOSSettings *pThis, PRInt64 *timeOffset);
    nsresult PR_COM_METHOD (*SetTimeOffset)(IBIOSSettings *pThis, PRInt64 timeOffset);

    nsresult PR_COM_METHOD (*GetPXEDebugEnabled)(IBIOSSettings *pThis, PRBool *PXEDebugEnabled);
    nsresult PR_COM_METHOD (*SetPXEDebugEnabled)(IBIOSSettings *pThis, PRBool PXEDebugEnabled);

};

struct IBIOSSettings
{
    struct IBIOSSettings_vtbl *vtbl;
};
/* End of struct IBIOSSettings Declaration */


/* Start of struct IMachine Declaration */
#  define IMACHINE_IID_STR "13420cbb-175a-4456-85d0-301126dfdec7"
#  define IMACHINE_IID { \
    0x13420cbb, 0x175a, 0x4456, \
    { 0x85, 0xd0, 0x30, 0x11, 0x26, 0xdf, 0xde, 0xc7 } \
}
struct IMachine_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetParent)(IMachine *pThis, IVirtualBox * *parent);

    nsresult PR_COM_METHOD (*GetAccessible)(IMachine *pThis, PRBool *accessible);

    nsresult PR_COM_METHOD (*GetAccessError)(IMachine *pThis, IVirtualBoxErrorInfo * *accessError);

    nsresult PR_COM_METHOD (*GetName)(IMachine *pThis, PRUnichar * *name);
    nsresult PR_COM_METHOD (*SetName)(IMachine *pThis, PRUnichar * name);

    nsresult PR_COM_METHOD (*GetDescription)(IMachine *pThis, PRUnichar * *description);
    nsresult PR_COM_METHOD (*SetDescription)(IMachine *pThis, PRUnichar * description);

    nsresult PR_COM_METHOD (*GetId)(IMachine *pThis, PR_IID_OUT_TYPE id);

    nsresult PR_COM_METHOD (*GetOSTypeId)(IMachine *pThis, PRUnichar * *OSTypeId);
    nsresult PR_COM_METHOD (*SetOSTypeId)(IMachine *pThis, PRUnichar * OSTypeId);

    nsresult PR_COM_METHOD (*GetHardwareVersion)(IMachine *pThis, PRUnichar * *HardwareVersion);
    nsresult PR_COM_METHOD (*SetHardwareVersion)(IMachine *pThis, PRUnichar * HardwareVersion);

    nsresult PR_COM_METHOD (*GetCPUCount)(IMachine *pThis, PRUint32 *CPUCount);
    nsresult PR_COM_METHOD (*SetCPUCount)(IMachine *pThis, PRUint32 CPUCount);

    nsresult PR_COM_METHOD (*GetMemorySize)(IMachine *pThis, PRUint32 *memorySize);
    nsresult PR_COM_METHOD (*SetMemorySize)(IMachine *pThis, PRUint32 memorySize);

    nsresult PR_COM_METHOD (*GetMemoryBalloonSize)(IMachine *pThis, PRUint32 *memoryBalloonSize);
    nsresult PR_COM_METHOD (*SetMemoryBalloonSize)(IMachine *pThis, PRUint32 memoryBalloonSize);

    nsresult PR_COM_METHOD (*GetStatisticsUpdateInterval)(IMachine *pThis, PRUint32 *statisticsUpdateInterval);
    nsresult PR_COM_METHOD (*SetStatisticsUpdateInterval)(IMachine *pThis, PRUint32 statisticsUpdateInterval);

    nsresult PR_COM_METHOD (*GetVRAMSize)(IMachine *pThis, PRUint32 *VRAMSize);
    nsresult PR_COM_METHOD (*SetVRAMSize)(IMachine *pThis, PRUint32 VRAMSize);

    nsresult PR_COM_METHOD (*GetAccelerate3DEnabled)(IMachine *pThis, PRBool *accelerate3DEnabled);
    nsresult PR_COM_METHOD (*SetAccelerate3DEnabled)(IMachine *pThis, PRBool accelerate3DEnabled);

    nsresult PR_COM_METHOD (*GetMonitorCount)(IMachine *pThis, PRUint32 *monitorCount);
    nsresult PR_COM_METHOD (*SetMonitorCount)(IMachine *pThis, PRUint32 monitorCount);

    nsresult PR_COM_METHOD (*GetBIOSSettings)(IMachine *pThis, IBIOSSettings * *BIOSSettings);

    nsresult PR_COM_METHOD (*GetHWVirtExEnabled)(IMachine *pThis, PRUint32 *HWVirtExEnabled);
    nsresult PR_COM_METHOD (*SetHWVirtExEnabled)(IMachine *pThis, PRUint32 HWVirtExEnabled);

    nsresult PR_COM_METHOD (*GetHWVirtExNestedPagingEnabled)(IMachine *pThis, PRBool *HWVirtExNestedPagingEnabled);
    nsresult PR_COM_METHOD (*SetHWVirtExNestedPagingEnabled)(IMachine *pThis, PRBool HWVirtExNestedPagingEnabled);

    nsresult PR_COM_METHOD (*GetHWVirtExVPIDEnabled)(IMachine *pThis, PRBool *HWVirtExVPIDEnabled);
    nsresult PR_COM_METHOD (*SetHWVirtExVPIDEnabled)(IMachine *pThis, PRBool HWVirtExVPIDEnabled);

    nsresult PR_COM_METHOD (*GetPAEEnabled)(IMachine *pThis, PRBool *PAEEnabled);
    nsresult PR_COM_METHOD (*SetPAEEnabled)(IMachine *pThis, PRBool PAEEnabled);

    nsresult PR_COM_METHOD (*GetSnapshotFolder)(IMachine *pThis, PRUnichar * *snapshotFolder);
    nsresult PR_COM_METHOD (*SetSnapshotFolder)(IMachine *pThis, PRUnichar * snapshotFolder);

    nsresult PR_COM_METHOD (*GetVRDPServer)(IMachine *pThis, IVRDPServer * *VRDPServer);

    nsresult PR_COM_METHOD (*GetHardDiskAttachments)(IMachine *pThis, PRUint32 *hardDiskAttachmentsSize, IHardDiskAttachment * **hardDiskAttachments);

    nsresult PR_COM_METHOD (*GetDVDDrive)(IMachine *pThis, IDVDDrive * *DVDDrive);

    nsresult PR_COM_METHOD (*GetFloppyDrive)(IMachine *pThis, IFloppyDrive * *floppyDrive);

    nsresult PR_COM_METHOD (*GetUSBController)(IMachine *pThis, IUSBController * *USBController);

    nsresult PR_COM_METHOD (*GetAudioAdapter)(IMachine *pThis, IAudioAdapter * *audioAdapter);

    nsresult PR_COM_METHOD (*GetStorageControllers)(IMachine *pThis, PRUint32 *storageControllersSize, IStorageController * **storageControllers);

    nsresult PR_COM_METHOD (*GetSettingsFilePath)(IMachine *pThis, PRUnichar * *settingsFilePath);

    nsresult PR_COM_METHOD (*GetSettingsFileVersion)(IMachine *pThis, PRUnichar * *settingsFileVersion);

    nsresult PR_COM_METHOD (*GetSettingsModified)(IMachine *pThis, PRBool *settingsModified);

    nsresult PR_COM_METHOD (*GetSessionState)(IMachine *pThis, PRUint32 *sessionState);

    nsresult PR_COM_METHOD (*GetSessionType)(IMachine *pThis, PRUnichar * *sessionType);

    nsresult PR_COM_METHOD (*GetSessionPid)(IMachine *pThis, PRUint32 *sessionPid);

    nsresult PR_COM_METHOD (*GetState)(IMachine *pThis, PRUint32 *state);

    nsresult PR_COM_METHOD (*GetLastStateChange)(IMachine *pThis, PRInt64 *lastStateChange);

    nsresult PR_COM_METHOD (*GetStateFilePath)(IMachine *pThis, PRUnichar * *stateFilePath);

    nsresult PR_COM_METHOD (*GetLogFolder)(IMachine *pThis, PRUnichar * *logFolder);

    nsresult PR_COM_METHOD (*GetCurrentSnapshot)(IMachine *pThis, ISnapshot * *currentSnapshot);

    nsresult PR_COM_METHOD (*GetSnapshotCount)(IMachine *pThis, PRUint32 *snapshotCount);

    nsresult PR_COM_METHOD (*GetCurrentStateModified)(IMachine *pThis, PRBool *currentStateModified);

    nsresult PR_COM_METHOD (*GetSharedFolders)(IMachine *pThis, PRUint32 *sharedFoldersSize, ISharedFolder * **sharedFolders);

    nsresult PR_COM_METHOD (*GetClipboardMode)(IMachine *pThis, PRUint32 *clipboardMode);
    nsresult PR_COM_METHOD (*SetClipboardMode)(IMachine *pThis, PRUint32 clipboardMode);

    nsresult PR_COM_METHOD (*GetGuestPropertyNotificationPatterns)(IMachine *pThis, PRUnichar * *guestPropertyNotificationPatterns);
    nsresult PR_COM_METHOD (*SetGuestPropertyNotificationPatterns)(IMachine *pThis, PRUnichar * guestPropertyNotificationPatterns);

    nsresult PR_COM_METHOD (*SetBootOrder)(
        IMachine *pThis,
        PRUint32 position,
        PRUint32 device
    );

    nsresult PR_COM_METHOD (*GetBootOrder)(
        IMachine *pThis,
        PRUint32 position,
        PRUint32 * device
    );

    nsresult PR_COM_METHOD (*AttachHardDisk)(
        IMachine *pThis,
        PR_IID_IN_TYPE id,
        PRUnichar * name,
        PRInt32 controllerPort,
        PRInt32 device
    );

    nsresult PR_COM_METHOD (*GetHardDisk)(
        IMachine *pThis,
        PRUnichar * name,
        PRInt32 controllerPort,
        PRInt32 device,
        IHardDisk * * hardDisk
    );

    nsresult PR_COM_METHOD (*DetachHardDisk)(
        IMachine *pThis,
        PRUnichar * name,
        PRInt32 controllerPort,
        PRInt32 device
    );

    nsresult PR_COM_METHOD (*GetHardDiskAttachmentsOfController)(
        IMachine *pThis,
        PRUnichar * name,
        PRUint32 *hardDiskAttachmentsSize,
        IHardDiskAttachment *** hardDiskAttachments
    );

    nsresult PR_COM_METHOD (*GetNetworkAdapter)(
        IMachine *pThis,
        PRUint32 slot,
        INetworkAdapter * * adapter
    );

    nsresult PR_COM_METHOD (*AddStorageController)(
        IMachine *pThis,
        PRUnichar * name,
        PRUint32 connectionType,
        IStorageController * * controller
    );

    nsresult PR_COM_METHOD (*GetStorageControllerByName)(
        IMachine *pThis,
        PRUnichar * name,
        IStorageController * * storageController
    );

    nsresult PR_COM_METHOD (*RemoveStorageController)(
        IMachine *pThis,
        PRUnichar * name
    );

    nsresult PR_COM_METHOD (*GetSerialPort)(
        IMachine *pThis,
        PRUint32 slot,
        ISerialPort * * port
    );

    nsresult PR_COM_METHOD (*GetParallelPort)(
        IMachine *pThis,
        PRUint32 slot,
        IParallelPort * * port
    );

    nsresult PR_COM_METHOD (*GetNextExtraDataKey)(
        IMachine *pThis,
        PRUnichar * key,
        PRUnichar * * nextKey,
        PRUnichar * * nextValue
    );

    nsresult PR_COM_METHOD (*GetExtraData)(
        IMachine *pThis,
        PRUnichar * key,
        PRUnichar * * value
    );

    nsresult PR_COM_METHOD (*SetExtraData)(
        IMachine *pThis,
        PRUnichar * key,
        PRUnichar * value
    );

    nsresult PR_COM_METHOD (*SaveSettings)(IMachine *pThis );

    nsresult PR_COM_METHOD (*SaveSettingsWithBackup)(
        IMachine *pThis,
        PRUnichar * * bakFileName
    );

    nsresult PR_COM_METHOD (*DiscardSettings)(IMachine *pThis );

    nsresult PR_COM_METHOD (*DeleteSettings)(IMachine *pThis );

    nsresult PR_COM_METHOD (*Export)(
        IMachine *pThis,
        IAppliance * aAppliance,
        IVirtualSystemDescription * * aDescription
    );

    nsresult PR_COM_METHOD (*GetSnapshot)(
        IMachine *pThis,
        PR_IID_IN_TYPE id,
        ISnapshot * * snapshot
    );

    nsresult PR_COM_METHOD (*FindSnapshot)(
        IMachine *pThis,
        PRUnichar * name,
        ISnapshot * * snapshot
    );

    nsresult PR_COM_METHOD (*SetCurrentSnapshot)(
        IMachine *pThis,
        PR_IID_IN_TYPE id
    );

    nsresult PR_COM_METHOD (*CreateSharedFolder)(
        IMachine *pThis,
        PRUnichar * name,
        PRUnichar * hostPath,
        PRBool writable
    );

    nsresult PR_COM_METHOD (*RemoveSharedFolder)(
        IMachine *pThis,
        PRUnichar * name
    );

    nsresult PR_COM_METHOD (*CanShowConsoleWindow)(
        IMachine *pThis,
        PRBool * canShow
    );

    nsresult PR_COM_METHOD (*ShowConsoleWindow)(
        IMachine *pThis,
        PRUint64 * winId
    );

    nsresult PR_COM_METHOD (*GetGuestProperty)(
        IMachine *pThis,
        PRUnichar * name,
        PRUnichar * * value,
        PRUint64 * timestamp,
        PRUnichar * * flags
    );

    nsresult PR_COM_METHOD (*GetGuestPropertyValue)(
        IMachine *pThis,
        PRUnichar * property,
        PRUnichar * * value
    );

    nsresult PR_COM_METHOD (*GetGuestPropertyTimestamp)(
        IMachine *pThis,
        PRUnichar * property,
        PRUint64 * value
    );

    nsresult PR_COM_METHOD (*SetGuestProperty)(
        IMachine *pThis,
        PRUnichar * property,
        PRUnichar * value,
        PRUnichar * flags
    );

    nsresult PR_COM_METHOD (*SetGuestPropertyValue)(
        IMachine *pThis,
        PRUnichar * property,
        PRUnichar * value
    );

    nsresult PR_COM_METHOD (*EnumerateGuestProperties)(
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
#  define ICONSOLECALLBACK_IID_STR "13dfbef3-b74d-487d-bada-2304529aefa6"
#  define ICONSOLECALLBACK_IID { \
    0x13dfbef3, 0xb74d, 0x487d, \
    { 0xba, 0xda, 0x23, 0x04, 0x52, 0x9a, 0xef, 0xa6 } \
}
struct IConsoleCallback_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*OnMousePointerShapeChange)(
        IConsoleCallback *pThis,
        PRBool visible,
        PRBool alpha,
        PRUint32 xHot,
        PRUint32 yHot,
        PRUint32 width,
        PRUint32 height,
        PRUint8 * shape
    );

    nsresult PR_COM_METHOD (*OnMouseCapabilityChange)(
        IConsoleCallback *pThis,
        PRBool supportsAbsolute,
        PRBool needsHostCursor
    );

    nsresult PR_COM_METHOD (*OnKeyboardLedsChange)(
        IConsoleCallback *pThis,
        PRBool numLock,
        PRBool capsLock,
        PRBool scrollLock
    );

    nsresult PR_COM_METHOD (*OnStateChange)(
        IConsoleCallback *pThis,
        PRUint32 state
    );

    nsresult PR_COM_METHOD (*OnAdditionsStateChange)(IConsoleCallback *pThis );

    nsresult PR_COM_METHOD (*OnDVDDriveChange)(IConsoleCallback *pThis );

    nsresult PR_COM_METHOD (*OnFloppyDriveChange)(IConsoleCallback *pThis );

    nsresult PR_COM_METHOD (*OnNetworkAdapterChange)(
        IConsoleCallback *pThis,
        INetworkAdapter * networkAdapter
    );

    nsresult PR_COM_METHOD (*OnSerialPortChange)(
        IConsoleCallback *pThis,
        ISerialPort * serialPort
    );

    nsresult PR_COM_METHOD (*OnParallelPortChange)(
        IConsoleCallback *pThis,
        IParallelPort * parallelPort
    );

    nsresult PR_COM_METHOD (*OnStorageControllerChange)(IConsoleCallback *pThis );

    nsresult PR_COM_METHOD (*OnVRDPServerChange)(IConsoleCallback *pThis );

    nsresult PR_COM_METHOD (*OnUSBControllerChange)(IConsoleCallback *pThis );

    nsresult PR_COM_METHOD (*OnUSBDeviceStateChange)(
        IConsoleCallback *pThis,
        IUSBDevice * device,
        PRBool attached,
        IVirtualBoxErrorInfo * error
    );

    nsresult PR_COM_METHOD (*OnSharedFolderChange)(
        IConsoleCallback *pThis,
        PRUint32 scope
    );

    nsresult PR_COM_METHOD (*OnRuntimeError)(
        IConsoleCallback *pThis,
        PRBool fatal,
        PRUnichar * id,
        PRUnichar * message
    );

    nsresult PR_COM_METHOD (*OnCanShowWindow)(
        IConsoleCallback *pThis,
        PRBool * canShow
    );

    nsresult PR_COM_METHOD (*OnShowWindow)(
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
#  define IREMOTEDISPLAYINFO_IID_STR "550104cd-2dfd-4a6c-857d-f6f8e088e62c"
#  define IREMOTEDISPLAYINFO_IID { \
    0x550104cd, 0x2dfd, 0x4a6c, \
    { 0x85, 0x7d, 0xf6, 0xf8, 0xe0, 0x88, 0xe6, 0x2c } \
}
struct IRemoteDisplayInfo_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetActive)(IRemoteDisplayInfo *pThis, PRBool *active);

    nsresult PR_COM_METHOD (*GetNumberOfClients)(IRemoteDisplayInfo *pThis, PRUint32 *numberOfClients);

    nsresult PR_COM_METHOD (*GetBeginTime)(IRemoteDisplayInfo *pThis, PRInt64 *beginTime);

    nsresult PR_COM_METHOD (*GetEndTime)(IRemoteDisplayInfo *pThis, PRInt64 *endTime);

    nsresult PR_COM_METHOD (*GetBytesSent)(IRemoteDisplayInfo *pThis, PRUint64 *bytesSent);

    nsresult PR_COM_METHOD (*GetBytesSentTotal)(IRemoteDisplayInfo *pThis, PRUint64 *bytesSentTotal);

    nsresult PR_COM_METHOD (*GetBytesReceived)(IRemoteDisplayInfo *pThis, PRUint64 *bytesReceived);

    nsresult PR_COM_METHOD (*GetBytesReceivedTotal)(IRemoteDisplayInfo *pThis, PRUint64 *bytesReceivedTotal);

    nsresult PR_COM_METHOD (*GetUser)(IRemoteDisplayInfo *pThis, PRUnichar * *user);

    nsresult PR_COM_METHOD (*GetDomain)(IRemoteDisplayInfo *pThis, PRUnichar * *domain);

    nsresult PR_COM_METHOD (*GetClientName)(IRemoteDisplayInfo *pThis, PRUnichar * *clientName);

    nsresult PR_COM_METHOD (*GetClientIP)(IRemoteDisplayInfo *pThis, PRUnichar * *clientIP);

    nsresult PR_COM_METHOD (*GetClientVersion)(IRemoteDisplayInfo *pThis, PRUint32 *clientVersion);

    nsresult PR_COM_METHOD (*GetEncryptionStyle)(IRemoteDisplayInfo *pThis, PRUint32 *encryptionStyle);

};

struct IRemoteDisplayInfo
{
    struct IRemoteDisplayInfo_vtbl *vtbl;
};
/* End of struct IRemoteDisplayInfo Declaration */


/* Start of struct IConsole Declaration */
#  define ICONSOLE_IID_STR "9511bc54-15ee-4ddf-808e-472aba03809c"
#  define ICONSOLE_IID { \
    0x9511bc54, 0x15ee, 0x4ddf, \
    { 0x80, 0x8e, 0x47, 0x2a, 0xba, 0x03, 0x80, 0x9c } \
}
struct IConsole_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetMachine)(IConsole *pThis, IMachine * *machine);

    nsresult PR_COM_METHOD (*GetState)(IConsole *pThis, PRUint32 *state);

    nsresult PR_COM_METHOD (*GetGuest)(IConsole *pThis, IGuest * *guest);

    nsresult PR_COM_METHOD (*GetKeyboard)(IConsole *pThis, IKeyboard * *keyboard);

    nsresult PR_COM_METHOD (*GetMouse)(IConsole *pThis, IMouse * *mouse);

    nsresult PR_COM_METHOD (*GetDisplay)(IConsole *pThis, IDisplay * *display);

    nsresult PR_COM_METHOD (*GetDebugger)(IConsole *pThis, IMachineDebugger * *debugger);

    nsresult PR_COM_METHOD (*GetUSBDevices)(IConsole *pThis, PRUint32 *USBDevicesSize, IUSBDevice * **USBDevices);

    nsresult PR_COM_METHOD (*GetRemoteUSBDevices)(IConsole *pThis, PRUint32 *remoteUSBDevicesSize, IHostUSBDevice * **remoteUSBDevices);

    nsresult PR_COM_METHOD (*GetSharedFolders)(IConsole *pThis, PRUint32 *sharedFoldersSize, ISharedFolder * **sharedFolders);

    nsresult PR_COM_METHOD (*GetRemoteDisplayInfo)(IConsole *pThis, IRemoteDisplayInfo * *remoteDisplayInfo);

    nsresult PR_COM_METHOD (*PowerUp)(
        IConsole *pThis,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*PowerUpPaused)(
        IConsole *pThis,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*PowerDown)(IConsole *pThis );

    nsresult PR_COM_METHOD (*PowerDownAsync)(
        IConsole *pThis,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*Reset)(IConsole *pThis );

    nsresult PR_COM_METHOD (*Pause)(IConsole *pThis );

    nsresult PR_COM_METHOD (*Resume)(IConsole *pThis );

    nsresult PR_COM_METHOD (*PowerButton)(IConsole *pThis );

    nsresult PR_COM_METHOD (*SleepButton)(IConsole *pThis );

    nsresult PR_COM_METHOD (*GetPowerButtonHandled)(
        IConsole *pThis,
        PRBool * handled
    );

    nsresult PR_COM_METHOD (*GetGuestEnteredACPIMode)(
        IConsole *pThis,
        PRBool * entered
    );

    nsresult PR_COM_METHOD (*SaveState)(
        IConsole *pThis,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*AdoptSavedState)(
        IConsole *pThis,
        PRUnichar * savedStateFile
    );

    nsresult PR_COM_METHOD (*DiscardSavedState)(IConsole *pThis );

    nsresult PR_COM_METHOD (*GetDeviceActivity)(
        IConsole *pThis,
        PRUint32 type,
        PRUint32 * activity
    );

    nsresult PR_COM_METHOD (*AttachUSBDevice)(
        IConsole *pThis,
        PR_IID_IN_TYPE id
    );

    nsresult PR_COM_METHOD (*DetachUSBDevice)(
        IConsole *pThis,
        PR_IID_IN_TYPE id,
        IUSBDevice * * device
    );

    nsresult PR_COM_METHOD (*FindUSBDeviceByAddress)(
        IConsole *pThis,
        PRUnichar * name,
        IUSBDevice * * device
    );

    nsresult PR_COM_METHOD (*FindUSBDeviceById)(
        IConsole *pThis,
        PR_IID_IN_TYPE id,
        IUSBDevice * * device
    );

    nsresult PR_COM_METHOD (*CreateSharedFolder)(
        IConsole *pThis,
        PRUnichar * name,
        PRUnichar * hostPath,
        PRBool writable
    );

    nsresult PR_COM_METHOD (*RemoveSharedFolder)(
        IConsole *pThis,
        PRUnichar * name
    );

    nsresult PR_COM_METHOD (*TakeSnapshot)(
        IConsole *pThis,
        PRUnichar * name,
        PRUnichar * description,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*DiscardSnapshot)(
        IConsole *pThis,
        PR_IID_IN_TYPE id,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*DiscardCurrentState)(
        IConsole *pThis,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*DiscardCurrentSnapshotAndState)(
        IConsole *pThis,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*RegisterCallback)(
        IConsole *pThis,
        IConsoleCallback * callback
    );

    nsresult PR_COM_METHOD (*UnregisterCallback)(
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
#  define IHOSTDVDDRIVE_IID_STR "21f86694-202d-4ce4-8b05-a63ff82dbf4c"
#  define IHOSTDVDDRIVE_IID { \
    0x21f86694, 0x202d, 0x4ce4, \
    { 0x8b, 0x05, 0xa6, 0x3f, 0xf8, 0x2d, 0xbf, 0x4c } \
}
struct IHostDVDDrive_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetName)(IHostDVDDrive *pThis, PRUnichar * *name);

    nsresult PR_COM_METHOD (*GetDescription)(IHostDVDDrive *pThis, PRUnichar * *description);

    nsresult PR_COM_METHOD (*GetUdi)(IHostDVDDrive *pThis, PRUnichar * *udi);

};

struct IHostDVDDrive
{
    struct IHostDVDDrive_vtbl *vtbl;
};
/* End of struct IHostDVDDrive Declaration */


/* Start of struct IHostFloppyDrive Declaration */
#  define IHOSTFLOPPYDRIVE_IID_STR "3f02d604-e908-4919-9fd1-8a4afd68fc63"
#  define IHOSTFLOPPYDRIVE_IID { \
    0x3f02d604, 0xe908, 0x4919, \
    { 0x9f, 0xd1, 0x8a, 0x4a, 0xfd, 0x68, 0xfc, 0x63 } \
}
struct IHostFloppyDrive_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetName)(IHostFloppyDrive *pThis, PRUnichar * *name);

    nsresult PR_COM_METHOD (*GetDescription)(IHostFloppyDrive *pThis, PRUnichar * *description);

    nsresult PR_COM_METHOD (*GetUdi)(IHostFloppyDrive *pThis, PRUnichar * *udi);

};

struct IHostFloppyDrive
{
    struct IHostFloppyDrive_vtbl *vtbl;
};
/* End of struct IHostFloppyDrive Declaration */


/* Start of struct IHostNetworkInterface Declaration */
#  define IHOSTNETWORKINTERFACE_IID_STR "88adaf3f-166b-4542-9457-0f1323507fae"
#  define IHOSTNETWORKINTERFACE_IID { \
    0x88adaf3f, 0x166b, 0x4542, \
    { 0x94, 0x57, 0x0f, 0x13, 0x23, 0x50, 0x7f, 0xae } \
}
struct IHostNetworkInterface_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetName)(IHostNetworkInterface *pThis, PRUnichar * *name);

    nsresult PR_COM_METHOD (*GetId)(IHostNetworkInterface *pThis, PR_IID_OUT_TYPE id);

    nsresult PR_COM_METHOD (*GetNetworkName)(IHostNetworkInterface *pThis, PRUnichar * *networkName);

    nsresult PR_COM_METHOD (*GetDhcpEnabled)(IHostNetworkInterface *pThis, PRBool *dhcpEnabled);

    nsresult PR_COM_METHOD (*GetIPAddress)(IHostNetworkInterface *pThis, PRUnichar * *IPAddress);

    nsresult PR_COM_METHOD (*GetNetworkMask)(IHostNetworkInterface *pThis, PRUnichar * *networkMask);

    nsresult PR_COM_METHOD (*GetIPV6Supported)(IHostNetworkInterface *pThis, PRBool *IPV6Supported);

    nsresult PR_COM_METHOD (*GetIPV6Address)(IHostNetworkInterface *pThis, PRUnichar * *IPV6Address);

    nsresult PR_COM_METHOD (*GetIPV6NetworkMaskPrefixLength)(IHostNetworkInterface *pThis, PRUint32 *IPV6NetworkMaskPrefixLength);

    nsresult PR_COM_METHOD (*GetHardwareAddress)(IHostNetworkInterface *pThis, PRUnichar * *hardwareAddress);

    nsresult PR_COM_METHOD (*GetMediumType)(IHostNetworkInterface *pThis, PRUint32 *mediumType);

    nsresult PR_COM_METHOD (*GetStatus)(IHostNetworkInterface *pThis, PRUint32 *status);

    nsresult PR_COM_METHOD (*GetInterfaceType)(IHostNetworkInterface *pThis, PRUint32 *interfaceType);

    nsresult PR_COM_METHOD (*EnableStaticIpConfig)(
        IHostNetworkInterface *pThis,
        PRUnichar * IPAddress,
        PRUnichar * networkMask
    );

    nsresult PR_COM_METHOD (*EnableStaticIpConfigV6)(
        IHostNetworkInterface *pThis,
        PRUnichar * IPV6Address,
        PRUint32 IPV6NetworkMaskPrefixLength
    );

    nsresult PR_COM_METHOD (*EnableDynamicIpConfig)(IHostNetworkInterface *pThis );

    nsresult PR_COM_METHOD (*DhcpRediscover)(IHostNetworkInterface *pThis );

};

struct IHostNetworkInterface
{
    struct IHostNetworkInterface_vtbl *vtbl;
};
/* End of struct IHostNetworkInterface Declaration */


/* Start of struct IHost Declaration */
#  define IHOST_IID_STR "926469ca-9091-42ef-928e-582d78b66c70"
#  define IHOST_IID { \
    0x926469ca, 0x9091, 0x42ef, \
    { 0x92, 0x8e, 0x58, 0x2d, 0x78, 0xb6, 0x6c, 0x70 } \
}
struct IHost_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetDVDDrives)(IHost *pThis, PRUint32 *DVDDrivesSize, IHostDVDDrive * **DVDDrives);

    nsresult PR_COM_METHOD (*GetFloppyDrives)(IHost *pThis, PRUint32 *floppyDrivesSize, IHostFloppyDrive * **floppyDrives);

    nsresult PR_COM_METHOD (*GetUSBDevices)(IHost *pThis, PRUint32 *USBDevicesSize, IHostUSBDevice * **USBDevices);

    nsresult PR_COM_METHOD (*GetUSBDeviceFilters)(IHost *pThis, PRUint32 *USBDeviceFiltersSize, IHostUSBDeviceFilter * **USBDeviceFilters);

    nsresult PR_COM_METHOD (*GetNetworkInterfaces)(IHost *pThis, PRUint32 *networkInterfacesSize, IHostNetworkInterface * **networkInterfaces);

    nsresult PR_COM_METHOD (*GetProcessorCount)(IHost *pThis, PRUint32 *processorCount);

    nsresult PR_COM_METHOD (*GetProcessorOnlineCount)(IHost *pThis, PRUint32 *processorOnlineCount);

    nsresult PR_COM_METHOD (*GetMemorySize)(IHost *pThis, PRUint32 *memorySize);

    nsresult PR_COM_METHOD (*GetMemoryAvailable)(IHost *pThis, PRUint32 *memoryAvailable);

    nsresult PR_COM_METHOD (*GetOperatingSystem)(IHost *pThis, PRUnichar * *operatingSystem);

    nsresult PR_COM_METHOD (*GetOSVersion)(IHost *pThis, PRUnichar * *OSVersion);

    nsresult PR_COM_METHOD (*GetUTCTime)(IHost *pThis, PRInt64 *UTCTime);

    nsresult PR_COM_METHOD (*GetProcessorSpeed)(
        IHost *pThis,
        PRUint32 cpuId,
        PRUint32 * speed
    );

    nsresult PR_COM_METHOD (*GetProcessorFeature)(
        IHost *pThis,
        PRUint32 feature,
        PRBool * supported
    );

    nsresult PR_COM_METHOD (*GetProcessorDescription)(
        IHost *pThis,
        PRUint32 cpuId,
        PRUnichar * * description
    );

    nsresult PR_COM_METHOD (*CreateUSBDeviceFilter)(
        IHost *pThis,
        PRUnichar * name,
        IHostUSBDeviceFilter * * filter
    );

    nsresult PR_COM_METHOD (*InsertUSBDeviceFilter)(
        IHost *pThis,
        PRUint32 position,
        IHostUSBDeviceFilter * filter
    );

    nsresult PR_COM_METHOD (*RemoveUSBDeviceFilter)(
        IHost *pThis,
        PRUint32 position,
        IHostUSBDeviceFilter * * filter
    );

    nsresult PR_COM_METHOD (*FindHostDVDDrive)(
        IHost *pThis,
        PRUnichar * name,
        IHostDVDDrive * * drive
    );

    nsresult PR_COM_METHOD (*FindHostFloppyDrive)(
        IHost *pThis,
        PRUnichar * name,
        IHostFloppyDrive * * drive
    );

    nsresult PR_COM_METHOD (*FindHostNetworkInterfaceByName)(
        IHost *pThis,
        PRUnichar * name,
        IHostNetworkInterface * * networkInterface
    );

    nsresult PR_COM_METHOD (*FindHostNetworkInterfaceById)(
        IHost *pThis,
        PR_IID_IN_TYPE id,
        IHostNetworkInterface * * networkInterface
    );

    nsresult PR_COM_METHOD (*FindHostNetworkInterfacesOfType)(
        IHost *pThis,
        PRUint32 type,
        PRUint32 *networkInterfacesSize,
        IHostNetworkInterface *** networkInterfaces
    );

    nsresult PR_COM_METHOD (*FindUSBDeviceById)(
        IHost *pThis,
        PR_IID_IN_TYPE id,
        IHostUSBDevice * * device
    );

    nsresult PR_COM_METHOD (*FindUSBDeviceByAddress)(
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
#  define ISYSTEMPROPERTIES_IID_STR "0760e03f-06d0-481e-9f81-be43fef092ba"
#  define ISYSTEMPROPERTIES_IID { \
    0x0760e03f, 0x06d0, 0x481e, \
    { 0x9f, 0x81, 0xbe, 0x43, 0xfe, 0xf0, 0x92, 0xba } \
}
struct ISystemProperties_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetMinGuestRAM)(ISystemProperties *pThis, PRUint32 *minGuestRAM);

    nsresult PR_COM_METHOD (*GetMaxGuestRAM)(ISystemProperties *pThis, PRUint32 *maxGuestRAM);

    nsresult PR_COM_METHOD (*GetMinGuestVRAM)(ISystemProperties *pThis, PRUint32 *minGuestVRAM);

    nsresult PR_COM_METHOD (*GetMaxGuestVRAM)(ISystemProperties *pThis, PRUint32 *maxGuestVRAM);

    nsresult PR_COM_METHOD (*GetMinGuestCPUCount)(ISystemProperties *pThis, PRUint32 *minGuestCPUCount);

    nsresult PR_COM_METHOD (*GetMaxGuestCPUCount)(ISystemProperties *pThis, PRUint32 *maxGuestCPUCount);

    nsresult PR_COM_METHOD (*GetMaxVDISize)(ISystemProperties *pThis, PRUint64 *maxVDISize);

    nsresult PR_COM_METHOD (*GetNetworkAdapterCount)(ISystemProperties *pThis, PRUint32 *networkAdapterCount);

    nsresult PR_COM_METHOD (*GetSerialPortCount)(ISystemProperties *pThis, PRUint32 *serialPortCount);

    nsresult PR_COM_METHOD (*GetParallelPortCount)(ISystemProperties *pThis, PRUint32 *parallelPortCount);

    nsresult PR_COM_METHOD (*GetMaxBootPosition)(ISystemProperties *pThis, PRUint32 *maxBootPosition);

    nsresult PR_COM_METHOD (*GetDefaultMachineFolder)(ISystemProperties *pThis, PRUnichar * *defaultMachineFolder);
    nsresult PR_COM_METHOD (*SetDefaultMachineFolder)(ISystemProperties *pThis, PRUnichar * defaultMachineFolder);

    nsresult PR_COM_METHOD (*GetDefaultHardDiskFolder)(ISystemProperties *pThis, PRUnichar * *defaultHardDiskFolder);
    nsresult PR_COM_METHOD (*SetDefaultHardDiskFolder)(ISystemProperties *pThis, PRUnichar * defaultHardDiskFolder);

    nsresult PR_COM_METHOD (*GetHardDiskFormats)(ISystemProperties *pThis, PRUint32 *hardDiskFormatsSize, IHardDiskFormat * **hardDiskFormats);

    nsresult PR_COM_METHOD (*GetDefaultHardDiskFormat)(ISystemProperties *pThis, PRUnichar * *defaultHardDiskFormat);
    nsresult PR_COM_METHOD (*SetDefaultHardDiskFormat)(ISystemProperties *pThis, PRUnichar * defaultHardDiskFormat);

    nsresult PR_COM_METHOD (*GetRemoteDisplayAuthLibrary)(ISystemProperties *pThis, PRUnichar * *remoteDisplayAuthLibrary);
    nsresult PR_COM_METHOD (*SetRemoteDisplayAuthLibrary)(ISystemProperties *pThis, PRUnichar * remoteDisplayAuthLibrary);

    nsresult PR_COM_METHOD (*GetWebServiceAuthLibrary)(ISystemProperties *pThis, PRUnichar * *webServiceAuthLibrary);
    nsresult PR_COM_METHOD (*SetWebServiceAuthLibrary)(ISystemProperties *pThis, PRUnichar * webServiceAuthLibrary);

    nsresult PR_COM_METHOD (*GetHWVirtExEnabled)(ISystemProperties *pThis, PRBool *HWVirtExEnabled);
    nsresult PR_COM_METHOD (*SetHWVirtExEnabled)(ISystemProperties *pThis, PRBool HWVirtExEnabled);

    nsresult PR_COM_METHOD (*GetLogHistoryCount)(ISystemProperties *pThis, PRUint32 *LogHistoryCount);
    nsresult PR_COM_METHOD (*SetLogHistoryCount)(ISystemProperties *pThis, PRUint32 LogHistoryCount);

};

struct ISystemProperties
{
    struct ISystemProperties_vtbl *vtbl;
};
/* End of struct ISystemProperties Declaration */


/* Start of struct IGuestOSType Declaration */
#  define IGUESTOSTYPE_IID_STR "cfe9e64c-4430-435b-9e7c-e3d8e417bd58"
#  define IGUESTOSTYPE_IID { \
    0xcfe9e64c, 0x4430, 0x435b, \
    { 0x9e, 0x7c, 0xe3, 0xd8, 0xe4, 0x17, 0xbd, 0x58 } \
}
struct IGuestOSType_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetFamilyId)(IGuestOSType *pThis, PRUnichar * *familyId);

    nsresult PR_COM_METHOD (*GetFamilyDescription)(IGuestOSType *pThis, PRUnichar * *familyDescription);

    nsresult PR_COM_METHOD (*GetId)(IGuestOSType *pThis, PRUnichar * *id);

    nsresult PR_COM_METHOD (*GetDescription)(IGuestOSType *pThis, PRUnichar * *description);

    nsresult PR_COM_METHOD (*GetIs64Bit)(IGuestOSType *pThis, PRBool *is64Bit);

    nsresult PR_COM_METHOD (*GetRecommendedIOAPIC)(IGuestOSType *pThis, PRBool *recommendedIOAPIC);

    nsresult PR_COM_METHOD (*GetRecommendedVirtEx)(IGuestOSType *pThis, PRBool *recommendedVirtEx);

    nsresult PR_COM_METHOD (*GetRecommendedRAM)(IGuestOSType *pThis, PRUint32 *recommendedRAM);

    nsresult PR_COM_METHOD (*GetRecommendedVRAM)(IGuestOSType *pThis, PRUint32 *recommendedVRAM);

    nsresult PR_COM_METHOD (*GetRecommendedHDD)(IGuestOSType *pThis, PRUint32 *recommendedHDD);

    nsresult PR_COM_METHOD (*GetAdapterType)(IGuestOSType *pThis, PRUint32 *adapterType);

};

struct IGuestOSType
{
    struct IGuestOSType_vtbl *vtbl;
};
/* End of struct IGuestOSType Declaration */


/* Start of struct IGuest Declaration */
#  define IGUEST_IID_STR "d8556fca-81bc-12af-fca3-365528fa38ca"
#  define IGUEST_IID { \
    0xd8556fca, 0x81bc, 0x12af, \
    { 0xfc, 0xa3, 0x36, 0x55, 0x28, 0xfa, 0x38, 0xca } \
}
struct IGuest_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetOSTypeId)(IGuest *pThis, PRUnichar * *OSTypeId);

    nsresult PR_COM_METHOD (*GetAdditionsActive)(IGuest *pThis, PRBool *additionsActive);

    nsresult PR_COM_METHOD (*GetAdditionsVersion)(IGuest *pThis, PRUnichar * *additionsVersion);

    nsresult PR_COM_METHOD (*GetSupportsSeamless)(IGuest *pThis, PRBool *supportsSeamless);

    nsresult PR_COM_METHOD (*GetSupportsGraphics)(IGuest *pThis, PRBool *supportsGraphics);

    nsresult PR_COM_METHOD (*GetMemoryBalloonSize)(IGuest *pThis, PRUint32 *memoryBalloonSize);
    nsresult PR_COM_METHOD (*SetMemoryBalloonSize)(IGuest *pThis, PRUint32 memoryBalloonSize);

    nsresult PR_COM_METHOD (*GetStatisticsUpdateInterval)(IGuest *pThis, PRUint32 *statisticsUpdateInterval);
    nsresult PR_COM_METHOD (*SetStatisticsUpdateInterval)(IGuest *pThis, PRUint32 statisticsUpdateInterval);

    nsresult PR_COM_METHOD (*SetCredentials)(
        IGuest *pThis,
        PRUnichar * userName,
        PRUnichar * password,
        PRUnichar * domain,
        PRBool allowInteractiveLogon
    );

    nsresult PR_COM_METHOD (*GetStatistic)(
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
#  define IPROGRESS_IID_STR "c4f94e6b-2273-446b-9539-4c05bb416fe7"
#  define IPROGRESS_IID { \
    0xc4f94e6b, 0x2273, 0x446b, \
    { 0x95, 0x39, 0x4c, 0x05, 0xbb, 0x41, 0x6f, 0xe7 } \
}
struct IProgress_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetId)(IProgress *pThis, PR_IID_OUT_TYPE id);

    nsresult PR_COM_METHOD (*GetDescription)(IProgress *pThis, PRUnichar * *description);

    nsresult PR_COM_METHOD (*GetInitiator)(IProgress *pThis, nsISupports * *initiator);

    nsresult PR_COM_METHOD (*GetCancelable)(IProgress *pThis, PRBool *cancelable);

    nsresult PR_COM_METHOD (*GetPercent)(IProgress *pThis, PRUint32 *percent);

    nsresult PR_COM_METHOD (*GetTimeRemaining)(IProgress *pThis, PRInt32 *timeRemaining);

    nsresult PR_COM_METHOD (*GetCompleted)(IProgress *pThis, PRBool *completed);

    nsresult PR_COM_METHOD (*GetCanceled)(IProgress *pThis, PRBool *canceled);

    nsresult PR_COM_METHOD (*GetResultCode)(IProgress *pThis, nsresult *resultCode);

    nsresult PR_COM_METHOD (*GetErrorInfo)(IProgress *pThis, IVirtualBoxErrorInfo * *errorInfo);

    nsresult PR_COM_METHOD (*GetOperationCount)(IProgress *pThis, PRUint32 *operationCount);

    nsresult PR_COM_METHOD (*GetOperation)(IProgress *pThis, PRUint32 *operation);

    nsresult PR_COM_METHOD (*GetOperationDescription)(IProgress *pThis, PRUnichar * *operationDescription);

    nsresult PR_COM_METHOD (*GetOperationPercent)(IProgress *pThis, PRUint32 *operationPercent);

    nsresult PR_COM_METHOD (*WaitForCompletion)(
        IProgress *pThis,
        PRInt32 timeout
    );

    nsresult PR_COM_METHOD (*WaitForOperationCompletion)(
        IProgress *pThis,
        PRUint32 operation,
        PRInt32 timeout
    );

    nsresult PR_COM_METHOD (*Cancel)(IProgress *pThis );

};

struct IProgress
{
    struct IProgress_vtbl *vtbl;
};
/* End of struct IProgress Declaration */


/* Start of struct ISnapshot Declaration */
#  define ISNAPSHOT_IID_STR "5db6b1d9-c76b-4424-a6f4-8257f642d6ea"
#  define ISNAPSHOT_IID { \
    0x5db6b1d9, 0xc76b, 0x4424, \
    { 0xa6, 0xf4, 0x82, 0x57, 0xf6, 0x42, 0xd6, 0xea } \
}
struct ISnapshot_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetId)(ISnapshot *pThis, PR_IID_OUT_TYPE id);

    nsresult PR_COM_METHOD (*GetName)(ISnapshot *pThis, PRUnichar * *name);
    nsresult PR_COM_METHOD (*SetName)(ISnapshot *pThis, PRUnichar * name);

    nsresult PR_COM_METHOD (*GetDescription)(ISnapshot *pThis, PRUnichar * *description);
    nsresult PR_COM_METHOD (*SetDescription)(ISnapshot *pThis, PRUnichar * description);

    nsresult PR_COM_METHOD (*GetTimeStamp)(ISnapshot *pThis, PRInt64 *timeStamp);

    nsresult PR_COM_METHOD (*GetOnline)(ISnapshot *pThis, PRBool *online);

    nsresult PR_COM_METHOD (*GetMachine)(ISnapshot *pThis, IMachine * *machine);

    nsresult PR_COM_METHOD (*GetParent)(ISnapshot *pThis, ISnapshot * *parent);

    nsresult PR_COM_METHOD (*GetChildren)(ISnapshot *pThis, PRUint32 *childrenSize, ISnapshot * **children);

};

struct ISnapshot
{
    struct ISnapshot_vtbl *vtbl;
};
/* End of struct ISnapshot Declaration */


/* Start of struct IMedium Declaration */
#  define IMEDIUM_IID_STR "a7fb3bfb-c180-4274-bae4-7fbc89046e13"
#  define IMEDIUM_IID { \
    0xa7fb3bfb, 0xc180, 0x4274, \
    { 0xba, 0xe4, 0x7f, 0xbc, 0x89, 0x04, 0x6e, 0x13 } \
}
struct IMedium_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetId)(IMedium *pThis, PR_IID_OUT_TYPE id);

    nsresult PR_COM_METHOD (*GetDescription)(IMedium *pThis, PRUnichar * *description);
    nsresult PR_COM_METHOD (*SetDescription)(IMedium *pThis, PRUnichar * description);

    nsresult PR_COM_METHOD (*GetState)(IMedium *pThis, PRUint32 *state);

    nsresult PR_COM_METHOD (*GetLocation)(IMedium *pThis, PRUnichar * *location);
    nsresult PR_COM_METHOD (*SetLocation)(IMedium *pThis, PRUnichar * location);

    nsresult PR_COM_METHOD (*GetName)(IMedium *pThis, PRUnichar * *name);

    nsresult PR_COM_METHOD (*GetSize)(IMedium *pThis, PRUint64 *size);

    nsresult PR_COM_METHOD (*GetLastAccessError)(IMedium *pThis, PRUnichar * *lastAccessError);

    nsresult PR_COM_METHOD (*GetMachineIds)(IMedium *pThis, PRUint32 *machineIdsSize, PR_IID_OUT_TYPE *machineIds);

    nsresult PR_COM_METHOD (*GetSnapshotIds)(
        IMedium *pThis,
        PR_IID_IN_TYPE machineId,
        PRUint32 *snapshotIdsSize,
        nsID *** snapshotIds
    );

    nsresult PR_COM_METHOD (*LockRead)(
        IMedium *pThis,
        PRUint32 * state
    );

    nsresult PR_COM_METHOD (*UnlockRead)(
        IMedium *pThis,
        PRUint32 * state
    );

    nsresult PR_COM_METHOD (*LockWrite)(
        IMedium *pThis,
        PRUint32 * state
    );

    nsresult PR_COM_METHOD (*UnlockWrite)(
        IMedium *pThis,
        PRUint32 * state
    );

    nsresult PR_COM_METHOD (*Close)(IMedium *pThis );

};

struct IMedium
{
    struct IMedium_vtbl *vtbl;
};
/* End of struct IMedium Declaration */


/* Start of struct IHardDiskAttachment Declaration */
#  define IHARDDISKATTACHMENT_IID_STR "b1dd04bb-93c0-4ad3-a9cf-82316e595836"
#  define IHARDDISKATTACHMENT_IID { \
    0xb1dd04bb, 0x93c0, 0x4ad3, \
    { 0xa9, 0xcf, 0x82, 0x31, 0x6e, 0x59, 0x58, 0x36 } \
}
struct IHardDiskAttachment_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetHardDisk)(IHardDiskAttachment *pThis, IHardDisk * *hardDisk);

    nsresult PR_COM_METHOD (*GetController)(IHardDiskAttachment *pThis, PRUnichar * *controller);

    nsresult PR_COM_METHOD (*GetPort)(IHardDiskAttachment *pThis, PRInt32 *port);

    nsresult PR_COM_METHOD (*GetDevice)(IHardDiskAttachment *pThis, PRInt32 *device);

};

struct IHardDiskAttachment
{
    struct IHardDiskAttachment_vtbl *vtbl;
};
/* End of struct IHardDiskAttachment Declaration */


/* Start of struct IHardDisk Declaration */
#  define IHARDDISK_IID_STR "91648dc6-bb19-46bf-9e1c-4bf5b960c8e2"
#  define IHARDDISK_IID { \
    0x91648dc6, 0xbb19, 0x46bf, \
    { 0x9e, 0x1c, 0x4b, 0xf5, 0xb9, 0x60, 0xc8, 0xe2 } \
}
struct IHardDisk_vtbl
{
    struct IMedium_vtbl imedium;

    nsresult PR_COM_METHOD (*GetFormat)(IHardDisk *pThis, PRUnichar * *format);

    nsresult PR_COM_METHOD (*GetType)(IHardDisk *pThis, PRUint32 *type);
    nsresult PR_COM_METHOD (*SetType)(IHardDisk *pThis, PRUint32 type);

    nsresult PR_COM_METHOD (*GetParent)(IHardDisk *pThis, IHardDisk * *parent);

    nsresult PR_COM_METHOD (*GetChildren)(IHardDisk *pThis, PRUint32 *childrenSize, IHardDisk * **children);

    nsresult PR_COM_METHOD (*GetRoot)(IHardDisk *pThis, IHardDisk * *root);

    nsresult PR_COM_METHOD (*GetReadOnly)(IHardDisk *pThis, PRBool *readOnly);

    nsresult PR_COM_METHOD (*GetLogicalSize)(IHardDisk *pThis, PRUint64 *logicalSize);

    nsresult PR_COM_METHOD (*GetAutoReset)(IHardDisk *pThis, PRBool *autoReset);
    nsresult PR_COM_METHOD (*SetAutoReset)(IHardDisk *pThis, PRBool autoReset);

    nsresult PR_COM_METHOD (*GetProperty)(
        IHardDisk *pThis,
        PRUnichar * name,
        PRUnichar * * value
    );

    nsresult PR_COM_METHOD (*SetProperty)(
        IHardDisk *pThis,
        PRUnichar * name,
        PRUnichar * value
    );

    nsresult PR_COM_METHOD (*GetProperties)(
        IHardDisk *pThis,
        PRUnichar * names,
        PRUint32 *returnNamesSize,
        PRUnichar *** returnNames,
        PRUint32 *returnValuesSize,
        PRUnichar *** returnValues
    );

    nsresult PR_COM_METHOD (*SetProperties)(
        IHardDisk *pThis,
        PRUint32 namesSize,
        PRUnichar ** names,
        PRUint32 valuesSize,
        PRUnichar ** values
    );

    nsresult PR_COM_METHOD (*CreateBaseStorage)(
        IHardDisk *pThis,
        PRUint64 logicalSize,
        PRUint32 variant,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*DeleteStorage)(
        IHardDisk *pThis,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*CreateDiffStorage)(
        IHardDisk *pThis,
        IHardDisk * target,
        PRUint32 variant,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*MergeTo)(
        IHardDisk *pThis,
        PR_IID_IN_TYPE targetId,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*CloneTo)(
        IHardDisk *pThis,
        IHardDisk * target,
        PRUint32 variant,
        IHardDisk * parent,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*Compact)(
        IHardDisk *pThis,
        IProgress * * progress
    );

    nsresult PR_COM_METHOD (*Reset)(
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
#  define IHARDDISKFORMAT_IID_STR "7f3ba790-3a0b-4a8a-bac2-bb50150123c5"
#  define IHARDDISKFORMAT_IID { \
    0x7f3ba790, 0x3a0b, 0x4a8a, \
    { 0xba, 0xc2, 0xbb, 0x50, 0x15, 0x01, 0x23, 0xc5 } \
}
struct IHardDiskFormat_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetId)(IHardDiskFormat *pThis, PRUnichar * *id);

    nsresult PR_COM_METHOD (*GetName)(IHardDiskFormat *pThis, PRUnichar * *name);

    nsresult PR_COM_METHOD (*GetFileExtensions)(IHardDiskFormat *pThis, PRUint32 *fileExtensionsSize, PRUnichar * **fileExtensions);

    nsresult PR_COM_METHOD (*GetCapabilities)(IHardDiskFormat *pThis, PRUint32 *capabilities);

    nsresult PR_COM_METHOD (*DescribeProperties)(
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
#  define IFLOPPYIMAGE_IID_STR "faa6101f-078c-4b3a-ab75-75670c8170b3"
#  define IFLOPPYIMAGE_IID { \
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
#  define IDVDIMAGE_IID_STR "b1f90bbb-e8a9-4484-9af1-3638e943f763"
#  define IDVDIMAGE_IID { \
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
#  define IDVDDRIVE_IID_STR "d650ef30-be9b-4dae-b463-11d5824681a5"
#  define IDVDDRIVE_IID { \
    0xd650ef30, 0xbe9b, 0x4dae, \
    { 0xb4, 0x63, 0x11, 0xd5, 0x82, 0x46, 0x81, 0xa5 } \
}
struct IDVDDrive_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetState)(IDVDDrive *pThis, PRUint32 *state);

    nsresult PR_COM_METHOD (*GetPassthrough)(IDVDDrive *pThis, PRBool *passthrough);
    nsresult PR_COM_METHOD (*SetPassthrough)(IDVDDrive *pThis, PRBool passthrough);

    nsresult PR_COM_METHOD (*MountImage)(
        IDVDDrive *pThis,
        PR_IID_IN_TYPE imageId
    );

    nsresult PR_COM_METHOD (*CaptureHostDrive)(
        IDVDDrive *pThis,
        IHostDVDDrive * drive
    );

    nsresult PR_COM_METHOD (*Unmount)(IDVDDrive *pThis );

    nsresult PR_COM_METHOD (*GetImage)(
        IDVDDrive *pThis,
        IDVDImage * * image
    );

    nsresult PR_COM_METHOD (*GetHostDrive)(
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
#  define IFLOPPYDRIVE_IID_STR "159412cd-bab8-452e-8097-218a020825a6"
#  define IFLOPPYDRIVE_IID { \
    0x159412cd, 0xbab8, 0x452e, \
    { 0x80, 0x97, 0x21, 0x8a, 0x02, 0x08, 0x25, 0xa6 } \
}
struct IFloppyDrive_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetEnabled)(IFloppyDrive *pThis, PRBool *enabled);
    nsresult PR_COM_METHOD (*SetEnabled)(IFloppyDrive *pThis, PRBool enabled);

    nsresult PR_COM_METHOD (*GetState)(IFloppyDrive *pThis, PRUint32 *state);

    nsresult PR_COM_METHOD (*MountImage)(
        IFloppyDrive *pThis,
        PR_IID_IN_TYPE imageId
    );

    nsresult PR_COM_METHOD (*CaptureHostDrive)(
        IFloppyDrive *pThis,
        IHostFloppyDrive * drive
    );

    nsresult PR_COM_METHOD (*Unmount)(IFloppyDrive *pThis );

    nsresult PR_COM_METHOD (*GetImage)(
        IFloppyDrive *pThis,
        IFloppyImage * * image
    );

    nsresult PR_COM_METHOD (*GetHostDrive)(
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
#  define IKEYBOARD_IID_STR "2d1a531b-4c6e-49cc-8af6-5c857b78b5d7"
#  define IKEYBOARD_IID { \
    0x2d1a531b, 0x4c6e, 0x49cc, \
    { 0x8a, 0xf6, 0x5c, 0x85, 0x7b, 0x78, 0xb5, 0xd7 } \
}
struct IKeyboard_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*PutScancode)(
        IKeyboard *pThis,
        PRInt32 scancode
    );

    nsresult PR_COM_METHOD (*PutScancodes)(
        IKeyboard *pThis,
        PRUint32 scancodesSize,
        PRInt32* scancodes,
        PRUint32 * codesStored
    );

    nsresult PR_COM_METHOD (*PutCAD)(IKeyboard *pThis );

};

struct IKeyboard
{
    struct IKeyboard_vtbl *vtbl;
};
/* End of struct IKeyboard Declaration */


/* Start of struct IMouse Declaration */
#  define IMOUSE_IID_STR "FD443EC1-0006-4F5B-9282-D72760A66916"
#  define IMOUSE_IID { \
    0xFD443EC1, 0x0006, 0x4F5B, \
    { 0x92, 0x82, 0xD7, 0x27, 0x60, 0xA6, 0x69, 0x16 } \
}
struct IMouse_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetAbsoluteSupported)(IMouse *pThis, PRBool *absoluteSupported);

    nsresult PR_COM_METHOD (*PutMouseEvent)(
        IMouse *pThis,
        PRInt32 dx,
        PRInt32 dy,
        PRInt32 dz,
        PRInt32 buttonState
    );

    nsresult PR_COM_METHOD (*PutMouseEventAbsolute)(
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
#  define IFRAMEBUFFER_IID_STR "af431304-5b09-40e2-94da-3c3cb03822c1"
#  define IFRAMEBUFFER_IID { \
    0xaf431304, 0x5b09, 0x40e2, \
    { 0x94, 0xda, 0x3c, 0x3c, 0xb0, 0x38, 0x22, 0xc1 } \
}
struct IFramebuffer_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetAddress)(IFramebuffer *pThis, PRUint8 * *address);

    nsresult PR_COM_METHOD (*GetWidth)(IFramebuffer *pThis, PRUint32 *width);

    nsresult PR_COM_METHOD (*GetHeight)(IFramebuffer *pThis, PRUint32 *height);

    nsresult PR_COM_METHOD (*GetBitsPerPixel)(IFramebuffer *pThis, PRUint32 *bitsPerPixel);

    nsresult PR_COM_METHOD (*GetBytesPerLine)(IFramebuffer *pThis, PRUint32 *bytesPerLine);

    nsresult PR_COM_METHOD (*GetPixelFormat)(IFramebuffer *pThis, PRUint32 *pixelFormat);

    nsresult PR_COM_METHOD (*GetUsesGuestVRAM)(IFramebuffer *pThis, PRBool *usesGuestVRAM);

    nsresult PR_COM_METHOD (*GetHeightReduction)(IFramebuffer *pThis, PRUint32 *heightReduction);

    nsresult PR_COM_METHOD (*GetOverlay)(IFramebuffer *pThis, IFramebufferOverlay * *overlay);

    nsresult PR_COM_METHOD (*GetWinId)(IFramebuffer *pThis, PRUint64 *winId);

    nsresult PR_COM_METHOD (*Lock)(IFramebuffer *pThis );

    nsresult PR_COM_METHOD (*Unlock)(IFramebuffer *pThis );

    nsresult PR_COM_METHOD (*NotifyUpdate)(
        IFramebuffer *pThis,
        PRUint32 x,
        PRUint32 y,
        PRUint32 width,
        PRUint32 height,
        PRBool * finished
    );

    nsresult PR_COM_METHOD (*RequestResize)(
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

    nsresult PR_COM_METHOD (*OperationSupported)(
        IFramebuffer *pThis,
        PRUint32 operation,
        PRBool * supported
    );

    nsresult PR_COM_METHOD (*VideoModeSupported)(
        IFramebuffer *pThis,
        PRUint32 width,
        PRUint32 height,
        PRUint32 bpp,
        PRBool * supported
    );

    nsresult PR_COM_METHOD (*SolidFill)(
        IFramebuffer *pThis,
        PRUint32 x,
        PRUint32 y,
        PRUint32 width,
        PRUint32 height,
        PRUint32 color,
        PRBool * handled
    );

    nsresult PR_COM_METHOD (*CopyScreenBits)(
        IFramebuffer *pThis,
        PRUint32 xDst,
        PRUint32 yDst,
        PRUint32 xSrc,
        PRUint32 ySrc,
        PRUint32 width,
        PRUint32 height,
        PRBool * handled
    );

    nsresult PR_COM_METHOD (*GetVisibleRegion)(
        IFramebuffer *pThis,
        PRUint8 * rectangles,
        PRUint32 count,
        PRUint32 * countCopied
    );

    nsresult PR_COM_METHOD (*SetVisibleRegion)(
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
#  define IFRAMEBUFFEROVERLAY_IID_STR "0bcc1c7e-e415-47d2-bfdb-e4c705fb0f47"
#  define IFRAMEBUFFEROVERLAY_IID { \
    0x0bcc1c7e, 0xe415, 0x47d2, \
    { 0xbf, 0xdb, 0xe4, 0xc7, 0x05, 0xfb, 0x0f, 0x47 } \
}
struct IFramebufferOverlay_vtbl
{
    struct IFramebuffer_vtbl iframebuffer;

    nsresult PR_COM_METHOD (*GetX)(IFramebufferOverlay *pThis, PRUint32 *x);

    nsresult PR_COM_METHOD (*GetY)(IFramebufferOverlay *pThis, PRUint32 *y);

    nsresult PR_COM_METHOD (*GetVisible)(IFramebufferOverlay *pThis, PRBool *visible);
    nsresult PR_COM_METHOD (*SetVisible)(IFramebufferOverlay *pThis, PRBool visible);

    nsresult PR_COM_METHOD (*GetAlpha)(IFramebufferOverlay *pThis, PRUint32 *alpha);
    nsresult PR_COM_METHOD (*SetAlpha)(IFramebufferOverlay *pThis, PRUint32 alpha);

    nsresult PR_COM_METHOD (*Move)(
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
#  define IDISPLAY_IID_STR "09789f63-4525-48e5-a5e4-1080453b0eab"
#  define IDISPLAY_IID { \
    0x09789f63, 0x4525, 0x48e5, \
    { 0xa5, 0xe4, 0x10, 0x80, 0x45, 0x3b, 0x0e, 0xab } \
}
struct IDisplay_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetWidth)(IDisplay *pThis, PRUint32 *width);

    nsresult PR_COM_METHOD (*GetHeight)(IDisplay *pThis, PRUint32 *height);

    nsresult PR_COM_METHOD (*GetBitsPerPixel)(IDisplay *pThis, PRUint32 *bitsPerPixel);

    nsresult PR_COM_METHOD (*SetupInternalFramebuffer)(
        IDisplay *pThis,
        PRUint32 depth
    );

    nsresult PR_COM_METHOD (*LockFramebuffer)(
        IDisplay *pThis,
        PRUint8 * * address
    );

    nsresult PR_COM_METHOD (*UnlockFramebuffer)(IDisplay *pThis );

    nsresult PR_COM_METHOD (*RegisterExternalFramebuffer)(
        IDisplay *pThis,
        IFramebuffer * framebuffer
    );

    nsresult PR_COM_METHOD (*SetFramebuffer)(
        IDisplay *pThis,
        PRUint32 screenId,
        IFramebuffer * framebuffer
    );

    nsresult PR_COM_METHOD (*GetFramebuffer)(
        IDisplay *pThis,
        PRUint32 screenId,
        IFramebuffer * * framebuffer,
        PRInt32 * xOrigin,
        PRInt32 * yOrigin
    );

    nsresult PR_COM_METHOD (*SetVideoModeHint)(
        IDisplay *pThis,
        PRUint32 width,
        PRUint32 height,
        PRUint32 bitsPerPixel,
        PRUint32 display
    );

    nsresult PR_COM_METHOD (*SetSeamlessMode)(
        IDisplay *pThis,
        PRBool enabled
    );

    nsresult PR_COM_METHOD (*TakeScreenShot)(
        IDisplay *pThis,
        PRUint8 * address,
        PRUint32 width,
        PRUint32 height
    );

    nsresult PR_COM_METHOD (*DrawToScreen)(
        IDisplay *pThis,
        PRUint8 * address,
        PRUint32 x,
        PRUint32 y,
        PRUint32 width,
        PRUint32 height
    );

    nsresult PR_COM_METHOD (*InvalidateAndUpdate)(IDisplay *pThis );

    nsresult PR_COM_METHOD (*ResizeCompleted)(
        IDisplay *pThis,
        PRUint32 screenId
    );

    nsresult PR_COM_METHOD (*UpdateCompleted)(IDisplay *pThis );

};

struct IDisplay
{
    struct IDisplay_vtbl *vtbl;
};
/* End of struct IDisplay Declaration */


/* Start of struct INetworkAdapter Declaration */
#  define INETWORKADAPTER_IID_STR "65607a27-2b73-4d43-b4cc-0ba2c817fbde"
#  define INETWORKADAPTER_IID { \
    0x65607a27, 0x2b73, 0x4d43, \
    { 0xb4, 0xcc, 0x0b, 0xa2, 0xc8, 0x17, 0xfb, 0xde } \
}
struct INetworkAdapter_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetAdapterType)(INetworkAdapter *pThis, PRUint32 *adapterType);
    nsresult PR_COM_METHOD (*SetAdapterType)(INetworkAdapter *pThis, PRUint32 adapterType);

    nsresult PR_COM_METHOD (*GetSlot)(INetworkAdapter *pThis, PRUint32 *slot);

    nsresult PR_COM_METHOD (*GetEnabled)(INetworkAdapter *pThis, PRBool *enabled);
    nsresult PR_COM_METHOD (*SetEnabled)(INetworkAdapter *pThis, PRBool enabled);

    nsresult PR_COM_METHOD (*GetMACAddress)(INetworkAdapter *pThis, PRUnichar * *MACAddress);
    nsresult PR_COM_METHOD (*SetMACAddress)(INetworkAdapter *pThis, PRUnichar * MACAddress);

    nsresult PR_COM_METHOD (*GetAttachmentType)(INetworkAdapter *pThis, PRUint32 *attachmentType);

    nsresult PR_COM_METHOD (*GetHostInterface)(INetworkAdapter *pThis, PRUnichar * *hostInterface);
    nsresult PR_COM_METHOD (*SetHostInterface)(INetworkAdapter *pThis, PRUnichar * hostInterface);

    nsresult PR_COM_METHOD (*GetInternalNetwork)(INetworkAdapter *pThis, PRUnichar * *internalNetwork);
    nsresult PR_COM_METHOD (*SetInternalNetwork)(INetworkAdapter *pThis, PRUnichar * internalNetwork);

    nsresult PR_COM_METHOD (*GetNATNetwork)(INetworkAdapter *pThis, PRUnichar * *NATNetwork);
    nsresult PR_COM_METHOD (*SetNATNetwork)(INetworkAdapter *pThis, PRUnichar * NATNetwork);

    nsresult PR_COM_METHOD (*GetCableConnected)(INetworkAdapter *pThis, PRBool *cableConnected);
    nsresult PR_COM_METHOD (*SetCableConnected)(INetworkAdapter *pThis, PRBool cableConnected);

    nsresult PR_COM_METHOD (*GetLineSpeed)(INetworkAdapter *pThis, PRUint32 *lineSpeed);
    nsresult PR_COM_METHOD (*SetLineSpeed)(INetworkAdapter *pThis, PRUint32 lineSpeed);

    nsresult PR_COM_METHOD (*GetTraceEnabled)(INetworkAdapter *pThis, PRBool *traceEnabled);
    nsresult PR_COM_METHOD (*SetTraceEnabled)(INetworkAdapter *pThis, PRBool traceEnabled);

    nsresult PR_COM_METHOD (*GetTraceFile)(INetworkAdapter *pThis, PRUnichar * *traceFile);
    nsresult PR_COM_METHOD (*SetTraceFile)(INetworkAdapter *pThis, PRUnichar * traceFile);

    nsresult PR_COM_METHOD (*AttachToNAT)(INetworkAdapter *pThis );

    nsresult PR_COM_METHOD (*AttachToBridgedInterface)(INetworkAdapter *pThis );

    nsresult PR_COM_METHOD (*AttachToInternalNetwork)(INetworkAdapter *pThis );

    nsresult PR_COM_METHOD (*AttachToHostOnlyInterface)(INetworkAdapter *pThis );

    nsresult PR_COM_METHOD (*Detach)(INetworkAdapter *pThis );

};

struct INetworkAdapter
{
    struct INetworkAdapter_vtbl *vtbl;
};
/* End of struct INetworkAdapter Declaration */


/* Start of struct ISerialPort Declaration */
#  define ISERIALPORT_IID_STR "937f6970-5103-4745-b78e-d28dcf1479a8"
#  define ISERIALPORT_IID { \
    0x937f6970, 0x5103, 0x4745, \
    { 0xb7, 0x8e, 0xd2, 0x8d, 0xcf, 0x14, 0x79, 0xa8 } \
}
struct ISerialPort_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetSlot)(ISerialPort *pThis, PRUint32 *slot);

    nsresult PR_COM_METHOD (*GetEnabled)(ISerialPort *pThis, PRBool *enabled);
    nsresult PR_COM_METHOD (*SetEnabled)(ISerialPort *pThis, PRBool enabled);

    nsresult PR_COM_METHOD (*GetIOBase)(ISerialPort *pThis, PRUint32 *IOBase);
    nsresult PR_COM_METHOD (*SetIOBase)(ISerialPort *pThis, PRUint32 IOBase);

    nsresult PR_COM_METHOD (*GetIRQ)(ISerialPort *pThis, PRUint32 *IRQ);
    nsresult PR_COM_METHOD (*SetIRQ)(ISerialPort *pThis, PRUint32 IRQ);

    nsresult PR_COM_METHOD (*GetHostMode)(ISerialPort *pThis, PRUint32 *hostMode);
    nsresult PR_COM_METHOD (*SetHostMode)(ISerialPort *pThis, PRUint32 hostMode);

    nsresult PR_COM_METHOD (*GetServer)(ISerialPort *pThis, PRBool *server);
    nsresult PR_COM_METHOD (*SetServer)(ISerialPort *pThis, PRBool server);

    nsresult PR_COM_METHOD (*GetPath)(ISerialPort *pThis, PRUnichar * *path);
    nsresult PR_COM_METHOD (*SetPath)(ISerialPort *pThis, PRUnichar * path);

};

struct ISerialPort
{
    struct ISerialPort_vtbl *vtbl;
};
/* End of struct ISerialPort Declaration */


/* Start of struct IParallelPort Declaration */
#  define IPARALLELPORT_IID_STR "0c925f06-dd10-4b77-8de8-294d738c3214"
#  define IPARALLELPORT_IID { \
    0x0c925f06, 0xdd10, 0x4b77, \
    { 0x8d, 0xe8, 0x29, 0x4d, 0x73, 0x8c, 0x32, 0x14 } \
}
struct IParallelPort_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetSlot)(IParallelPort *pThis, PRUint32 *slot);

    nsresult PR_COM_METHOD (*GetEnabled)(IParallelPort *pThis, PRBool *enabled);
    nsresult PR_COM_METHOD (*SetEnabled)(IParallelPort *pThis, PRBool enabled);

    nsresult PR_COM_METHOD (*GetIOBase)(IParallelPort *pThis, PRUint32 *IOBase);
    nsresult PR_COM_METHOD (*SetIOBase)(IParallelPort *pThis, PRUint32 IOBase);

    nsresult PR_COM_METHOD (*GetIRQ)(IParallelPort *pThis, PRUint32 *IRQ);
    nsresult PR_COM_METHOD (*SetIRQ)(IParallelPort *pThis, PRUint32 IRQ);

    nsresult PR_COM_METHOD (*GetPath)(IParallelPort *pThis, PRUnichar * *path);
    nsresult PR_COM_METHOD (*SetPath)(IParallelPort *pThis, PRUnichar * path);

};

struct IParallelPort
{
    struct IParallelPort_vtbl *vtbl;
};
/* End of struct IParallelPort Declaration */


/* Start of struct IMachineDebugger Declaration */
#  define IMACHINEDEBUGGER_IID_STR "b0b2a2dd-0627-4502-91c2-ddc5e77609e0"
#  define IMACHINEDEBUGGER_IID { \
    0xb0b2a2dd, 0x0627, 0x4502, \
    { 0x91, 0xc2, 0xdd, 0xc5, 0xe7, 0x76, 0x09, 0xe0 } \
}
struct IMachineDebugger_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetSinglestep)(IMachineDebugger *pThis, PRBool *singlestep);
    nsresult PR_COM_METHOD (*SetSinglestep)(IMachineDebugger *pThis, PRBool singlestep);

    nsresult PR_COM_METHOD (*GetRecompileUser)(IMachineDebugger *pThis, PRBool *recompileUser);
    nsresult PR_COM_METHOD (*SetRecompileUser)(IMachineDebugger *pThis, PRBool recompileUser);

    nsresult PR_COM_METHOD (*GetRecompileSupervisor)(IMachineDebugger *pThis, PRBool *recompileSupervisor);
    nsresult PR_COM_METHOD (*SetRecompileSupervisor)(IMachineDebugger *pThis, PRBool recompileSupervisor);

    nsresult PR_COM_METHOD (*GetPATMEnabled)(IMachineDebugger *pThis, PRBool *PATMEnabled);
    nsresult PR_COM_METHOD (*SetPATMEnabled)(IMachineDebugger *pThis, PRBool PATMEnabled);

    nsresult PR_COM_METHOD (*GetCSAMEnabled)(IMachineDebugger *pThis, PRBool *CSAMEnabled);
    nsresult PR_COM_METHOD (*SetCSAMEnabled)(IMachineDebugger *pThis, PRBool CSAMEnabled);

    nsresult PR_COM_METHOD (*GetLogEnabled)(IMachineDebugger *pThis, PRBool *logEnabled);
    nsresult PR_COM_METHOD (*SetLogEnabled)(IMachineDebugger *pThis, PRBool logEnabled);

    nsresult PR_COM_METHOD (*GetHWVirtExEnabled)(IMachineDebugger *pThis, PRBool *HWVirtExEnabled);

    nsresult PR_COM_METHOD (*GetHWVirtExNestedPagingEnabled)(IMachineDebugger *pThis, PRBool *HWVirtExNestedPagingEnabled);

    nsresult PR_COM_METHOD (*GetHWVirtExVPIDEnabled)(IMachineDebugger *pThis, PRBool *HWVirtExVPIDEnabled);

    nsresult PR_COM_METHOD (*GetPAEEnabled)(IMachineDebugger *pThis, PRBool *PAEEnabled);

    nsresult PR_COM_METHOD (*GetVirtualTimeRate)(IMachineDebugger *pThis, PRUint32 *virtualTimeRate);
    nsresult PR_COM_METHOD (*SetVirtualTimeRate)(IMachineDebugger *pThis, PRUint32 virtualTimeRate);

    nsresult PR_COM_METHOD (*GetVM)(IMachineDebugger *pThis, PRUint64 *VM);

    nsresult PR_COM_METHOD (*ResetStats)(
        IMachineDebugger *pThis,
        PRUnichar * pattern
    );

    nsresult PR_COM_METHOD (*DumpStats)(
        IMachineDebugger *pThis,
        PRUnichar * pattern
    );

    nsresult PR_COM_METHOD (*GetStats)(
        IMachineDebugger *pThis,
        PRUnichar * pattern,
        PRBool withDescriptions,
        PRUnichar * * stats
    );

    nsresult PR_COM_METHOD (*InjectNMI)(IMachineDebugger *pThis );

};

struct IMachineDebugger
{
    struct IMachineDebugger_vtbl *vtbl;
};
/* End of struct IMachineDebugger Declaration */


/* Start of struct IUSBController Declaration */
#  define IUSBCONTROLLER_IID_STR "238540fa-4b73-435a-a38e-4e1d9eab5c17"
#  define IUSBCONTROLLER_IID { \
    0x238540fa, 0x4b73, 0x435a, \
    { 0xa3, 0x8e, 0x4e, 0x1d, 0x9e, 0xab, 0x5c, 0x17 } \
}
struct IUSBController_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetEnabled)(IUSBController *pThis, PRBool *enabled);
    nsresult PR_COM_METHOD (*SetEnabled)(IUSBController *pThis, PRBool enabled);

    nsresult PR_COM_METHOD (*GetEnabledEhci)(IUSBController *pThis, PRBool *enabledEhci);
    nsresult PR_COM_METHOD (*SetEnabledEhci)(IUSBController *pThis, PRBool enabledEhci);

    nsresult PR_COM_METHOD (*GetUSBStandard)(IUSBController *pThis, PRUint16 *USBStandard);

    nsresult PR_COM_METHOD (*GetDeviceFilters)(IUSBController *pThis, PRUint32 *deviceFiltersSize, IUSBDeviceFilter * **deviceFilters);

    nsresult PR_COM_METHOD (*CreateDeviceFilter)(
        IUSBController *pThis,
        PRUnichar * name,
        IUSBDeviceFilter * * filter
    );

    nsresult PR_COM_METHOD (*InsertDeviceFilter)(
        IUSBController *pThis,
        PRUint32 position,
        IUSBDeviceFilter * filter
    );

    nsresult PR_COM_METHOD (*RemoveDeviceFilter)(
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
#  define IUSBDEVICE_IID_STR "850af07b-9ee8-48c2-b6b0-f6d0acbf63c3"
#  define IUSBDEVICE_IID { \
    0x850af07b, 0x9ee8, 0x48c2, \
    { 0xb6, 0xb0, 0xf6, 0xd0, 0xac, 0xbf, 0x63, 0xc3 } \
}
struct IUSBDevice_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetId)(IUSBDevice *pThis, PR_IID_OUT_TYPE id);

    nsresult PR_COM_METHOD (*GetVendorId)(IUSBDevice *pThis, PRUint16 *vendorId);

    nsresult PR_COM_METHOD (*GetProductId)(IUSBDevice *pThis, PRUint16 *productId);

    nsresult PR_COM_METHOD (*GetRevision)(IUSBDevice *pThis, PRUint16 *revision);

    nsresult PR_COM_METHOD (*GetManufacturer)(IUSBDevice *pThis, PRUnichar * *manufacturer);

    nsresult PR_COM_METHOD (*GetProduct)(IUSBDevice *pThis, PRUnichar * *product);

    nsresult PR_COM_METHOD (*GetSerialNumber)(IUSBDevice *pThis, PRUnichar * *serialNumber);

    nsresult PR_COM_METHOD (*GetAddress)(IUSBDevice *pThis, PRUnichar * *address);

    nsresult PR_COM_METHOD (*GetPort)(IUSBDevice *pThis, PRUint16 *port);

    nsresult PR_COM_METHOD (*GetVersion)(IUSBDevice *pThis, PRUint16 *version);

    nsresult PR_COM_METHOD (*GetPortVersion)(IUSBDevice *pThis, PRUint16 *portVersion);

    nsresult PR_COM_METHOD (*GetRemote)(IUSBDevice *pThis, PRBool *remote);

};

struct IUSBDevice
{
    struct IUSBDevice_vtbl *vtbl;
};
/* End of struct IUSBDevice Declaration */


/* Start of struct IUSBDeviceFilter Declaration */
#  define IUSBDEVICEFILTER_IID_STR "d6831fb4-1a94-4c2c-96ef-8d0d6192066d"
#  define IUSBDEVICEFILTER_IID { \
    0xd6831fb4, 0x1a94, 0x4c2c, \
    { 0x96, 0xef, 0x8d, 0x0d, 0x61, 0x92, 0x06, 0x6d } \
}
struct IUSBDeviceFilter_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetName)(IUSBDeviceFilter *pThis, PRUnichar * *name);
    nsresult PR_COM_METHOD (*SetName)(IUSBDeviceFilter *pThis, PRUnichar * name);

    nsresult PR_COM_METHOD (*GetActive)(IUSBDeviceFilter *pThis, PRBool *active);
    nsresult PR_COM_METHOD (*SetActive)(IUSBDeviceFilter *pThis, PRBool active);

    nsresult PR_COM_METHOD (*GetVendorId)(IUSBDeviceFilter *pThis, PRUnichar * *vendorId);
    nsresult PR_COM_METHOD (*SetVendorId)(IUSBDeviceFilter *pThis, PRUnichar * vendorId);

    nsresult PR_COM_METHOD (*GetProductId)(IUSBDeviceFilter *pThis, PRUnichar * *productId);
    nsresult PR_COM_METHOD (*SetProductId)(IUSBDeviceFilter *pThis, PRUnichar * productId);

    nsresult PR_COM_METHOD (*GetRevision)(IUSBDeviceFilter *pThis, PRUnichar * *revision);
    nsresult PR_COM_METHOD (*SetRevision)(IUSBDeviceFilter *pThis, PRUnichar * revision);

    nsresult PR_COM_METHOD (*GetManufacturer)(IUSBDeviceFilter *pThis, PRUnichar * *manufacturer);
    nsresult PR_COM_METHOD (*SetManufacturer)(IUSBDeviceFilter *pThis, PRUnichar * manufacturer);

    nsresult PR_COM_METHOD (*GetProduct)(IUSBDeviceFilter *pThis, PRUnichar * *product);
    nsresult PR_COM_METHOD (*SetProduct)(IUSBDeviceFilter *pThis, PRUnichar * product);

    nsresult PR_COM_METHOD (*GetSerialNumber)(IUSBDeviceFilter *pThis, PRUnichar * *serialNumber);
    nsresult PR_COM_METHOD (*SetSerialNumber)(IUSBDeviceFilter *pThis, PRUnichar * serialNumber);

    nsresult PR_COM_METHOD (*GetPort)(IUSBDeviceFilter *pThis, PRUnichar * *port);
    nsresult PR_COM_METHOD (*SetPort)(IUSBDeviceFilter *pThis, PRUnichar * port);

    nsresult PR_COM_METHOD (*GetRemote)(IUSBDeviceFilter *pThis, PRUnichar * *remote);
    nsresult PR_COM_METHOD (*SetRemote)(IUSBDeviceFilter *pThis, PRUnichar * remote);

    nsresult PR_COM_METHOD (*GetMaskedInterfaces)(IUSBDeviceFilter *pThis, PRUint32 *maskedInterfaces);
    nsresult PR_COM_METHOD (*SetMaskedInterfaces)(IUSBDeviceFilter *pThis, PRUint32 maskedInterfaces);

};

struct IUSBDeviceFilter
{
    struct IUSBDeviceFilter_vtbl *vtbl;
};
/* End of struct IUSBDeviceFilter Declaration */


/* Start of struct IHostUSBDevice Declaration */
#  define IHOSTUSBDEVICE_IID_STR "173b4b44-d268-4334-a00d-b6521c9a740a"
#  define IHOSTUSBDEVICE_IID { \
    0x173b4b44, 0xd268, 0x4334, \
    { 0xa0, 0x0d, 0xb6, 0x52, 0x1c, 0x9a, 0x74, 0x0a } \
}
struct IHostUSBDevice_vtbl
{
    struct IUSBDevice_vtbl iusbdevice;

    nsresult PR_COM_METHOD (*GetState)(IHostUSBDevice *pThis, PRUint32 *state);

};

struct IHostUSBDevice
{
    struct IHostUSBDevice_vtbl *vtbl;
};
/* End of struct IHostUSBDevice Declaration */


/* Start of struct IHostUSBDeviceFilter Declaration */
#  define IHOSTUSBDEVICEFILTER_IID_STR "4cc70246-d74a-400f-8222-3900489c0374"
#  define IHOSTUSBDEVICEFILTER_IID { \
    0x4cc70246, 0xd74a, 0x400f, \
    { 0x82, 0x22, 0x39, 0x00, 0x48, 0x9c, 0x03, 0x74 } \
}
struct IHostUSBDeviceFilter_vtbl
{
    struct IUSBDeviceFilter_vtbl iusbdevicefilter;

    nsresult PR_COM_METHOD (*GetAction)(IHostUSBDeviceFilter *pThis, PRUint32 *action);
    nsresult PR_COM_METHOD (*SetAction)(IHostUSBDeviceFilter *pThis, PRUint32 action);

};

struct IHostUSBDeviceFilter
{
    struct IHostUSBDeviceFilter_vtbl *vtbl;
};
/* End of struct IHostUSBDeviceFilter Declaration */


/* Start of struct IAudioAdapter Declaration */
#  define IAUDIOADAPTER_IID_STR "921873db-5f3f-4b69-91f9-7be9e535a2cb"
#  define IAUDIOADAPTER_IID { \
    0x921873db, 0x5f3f, 0x4b69, \
    { 0x91, 0xf9, 0x7b, 0xe9, 0xe5, 0x35, 0xa2, 0xcb } \
}
struct IAudioAdapter_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetEnabled)(IAudioAdapter *pThis, PRBool *enabled);
    nsresult PR_COM_METHOD (*SetEnabled)(IAudioAdapter *pThis, PRBool enabled);

    nsresult PR_COM_METHOD (*GetAudioController)(IAudioAdapter *pThis, PRUint32 *audioController);
    nsresult PR_COM_METHOD (*SetAudioController)(IAudioAdapter *pThis, PRUint32 audioController);

    nsresult PR_COM_METHOD (*GetAudioDriver)(IAudioAdapter *pThis, PRUint32 *audioDriver);
    nsresult PR_COM_METHOD (*SetAudioDriver)(IAudioAdapter *pThis, PRUint32 audioDriver);

};

struct IAudioAdapter
{
    struct IAudioAdapter_vtbl *vtbl;
};
/* End of struct IAudioAdapter Declaration */


/* Start of struct IVRDPServer Declaration */
#  define IVRDPSERVER_IID_STR "f4584ae7-6bce-474b-83d6-17d235e6aa89"
#  define IVRDPSERVER_IID { \
    0xf4584ae7, 0x6bce, 0x474b, \
    { 0x83, 0xd6, 0x17, 0xd2, 0x35, 0xe6, 0xaa, 0x89 } \
}
struct IVRDPServer_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetEnabled)(IVRDPServer *pThis, PRBool *enabled);
    nsresult PR_COM_METHOD (*SetEnabled)(IVRDPServer *pThis, PRBool enabled);

    nsresult PR_COM_METHOD (*GetPort)(IVRDPServer *pThis, PRUint32 *port);
    nsresult PR_COM_METHOD (*SetPort)(IVRDPServer *pThis, PRUint32 port);

    nsresult PR_COM_METHOD (*GetNetAddress)(IVRDPServer *pThis, PRUnichar * *netAddress);
    nsresult PR_COM_METHOD (*SetNetAddress)(IVRDPServer *pThis, PRUnichar * netAddress);

    nsresult PR_COM_METHOD (*GetAuthType)(IVRDPServer *pThis, PRUint32 *authType);
    nsresult PR_COM_METHOD (*SetAuthType)(IVRDPServer *pThis, PRUint32 authType);

    nsresult PR_COM_METHOD (*GetAuthTimeout)(IVRDPServer *pThis, PRUint32 *authTimeout);
    nsresult PR_COM_METHOD (*SetAuthTimeout)(IVRDPServer *pThis, PRUint32 authTimeout);

    nsresult PR_COM_METHOD (*GetAllowMultiConnection)(IVRDPServer *pThis, PRBool *allowMultiConnection);
    nsresult PR_COM_METHOD (*SetAllowMultiConnection)(IVRDPServer *pThis, PRBool allowMultiConnection);

    nsresult PR_COM_METHOD (*GetReuseSingleConnection)(IVRDPServer *pThis, PRBool *reuseSingleConnection);
    nsresult PR_COM_METHOD (*SetReuseSingleConnection)(IVRDPServer *pThis, PRBool reuseSingleConnection);

};

struct IVRDPServer
{
    struct IVRDPServer_vtbl *vtbl;
};
/* End of struct IVRDPServer Declaration */


/* Start of struct ISharedFolder Declaration */
#  define ISHAREDFOLDER_IID_STR "64637bb2-9e17-471c-b8f3-f8968dd9884e"
#  define ISHAREDFOLDER_IID { \
    0x64637bb2, 0x9e17, 0x471c, \
    { 0xb8, 0xf3, 0xf8, 0x96, 0x8d, 0xd9, 0x88, 0x4e } \
}
struct ISharedFolder_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetName)(ISharedFolder *pThis, PRUnichar * *name);

    nsresult PR_COM_METHOD (*GetHostPath)(ISharedFolder *pThis, PRUnichar * *hostPath);

    nsresult PR_COM_METHOD (*GetAccessible)(ISharedFolder *pThis, PRBool *accessible);

    nsresult PR_COM_METHOD (*GetWritable)(ISharedFolder *pThis, PRBool *writable);

    nsresult PR_COM_METHOD (*GetLastAccessError)(ISharedFolder *pThis, PRUnichar * *lastAccessError);

};

struct ISharedFolder
{
    struct ISharedFolder_vtbl *vtbl;
};
/* End of struct ISharedFolder Declaration */


/* Start of struct IInternalSessionControl Declaration */
#  define IINTERNALSESSIONCONTROL_IID_STR "2581845a-5a9d-45fb-bc3b-2476552dd970"
#  define IINTERNALSESSIONCONTROL_IID { \
    0x2581845a, 0x5a9d, 0x45fb, \
    { 0xbc, 0x3b, 0x24, 0x76, 0x55, 0x2d, 0xd9, 0x70 } \
}
struct IInternalSessionControl_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetPID)(
        IInternalSessionControl *pThis,
        PRUint32 * pid
    );

    nsresult PR_COM_METHOD (*GetRemoteConsole)(
        IInternalSessionControl *pThis,
        IConsole * * console
    );

    nsresult PR_COM_METHOD (*AssignMachine)(
        IInternalSessionControl *pThis,
        IMachine * machine
    );

    nsresult PR_COM_METHOD (*AssignRemoteMachine)(
        IInternalSessionControl *pThis,
        IMachine * machine,
        IConsole * console
    );

    nsresult PR_COM_METHOD (*UpdateMachineState)(
        IInternalSessionControl *pThis,
        PRUint32 aMachineState
    );

    nsresult PR_COM_METHOD (*Uninitialize)(IInternalSessionControl *pThis );

    nsresult PR_COM_METHOD (*OnDVDDriveChange)(IInternalSessionControl *pThis );

    nsresult PR_COM_METHOD (*OnFloppyDriveChange)(IInternalSessionControl *pThis );

    nsresult PR_COM_METHOD (*OnNetworkAdapterChange)(
        IInternalSessionControl *pThis,
        INetworkAdapter * networkAdapter
    );

    nsresult PR_COM_METHOD (*OnSerialPortChange)(
        IInternalSessionControl *pThis,
        ISerialPort * serialPort
    );

    nsresult PR_COM_METHOD (*OnParallelPortChange)(
        IInternalSessionControl *pThis,
        IParallelPort * parallelPort
    );

    nsresult PR_COM_METHOD (*OnStorageControllerChange)(IInternalSessionControl *pThis );

    nsresult PR_COM_METHOD (*OnVRDPServerChange)(IInternalSessionControl *pThis );

    nsresult PR_COM_METHOD (*OnUSBControllerChange)(IInternalSessionControl *pThis );

    nsresult PR_COM_METHOD (*OnSharedFolderChange)(
        IInternalSessionControl *pThis,
        PRBool global
    );

    nsresult PR_COM_METHOD (*OnUSBDeviceAttach)(
        IInternalSessionControl *pThis,
        IUSBDevice * device,
        IVirtualBoxErrorInfo * error,
        PRUint32 maskedInterfaces
    );

    nsresult PR_COM_METHOD (*OnUSBDeviceDetach)(
        IInternalSessionControl *pThis,
        PR_IID_IN_TYPE id,
        IVirtualBoxErrorInfo * error
    );

    nsresult PR_COM_METHOD (*OnShowWindow)(
        IInternalSessionControl *pThis,
        PRBool check,
        PRBool * canShow,
        PRUint64 * winId
    );

    nsresult PR_COM_METHOD (*AccessGuestProperty)(
        IInternalSessionControl *pThis,
        PRUnichar * name,
        PRUnichar * value,
        PRUnichar * flags,
        PRBool isSetter,
        PRUnichar * * retValue,
        PRUint64 * retTimestamp,
        PRUnichar * * retFlags
    );

    nsresult PR_COM_METHOD (*EnumerateGuestProperties)(
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
#  define ISESSION_IID_STR "12F4DCDB-12B2-4ec1-B7CD-DDD9F6C5BF4D"
#  define ISESSION_IID { \
    0x12F4DCDB, 0x12B2, 0x4ec1, \
    { 0xB7, 0xCD, 0xDD, 0xD9, 0xF6, 0xC5, 0xBF, 0x4D } \
}
struct ISession_vtbl
{
    struct nsISupports_vtbl nsisupports;

#  ifdef WIN32
    /* The MSCOM implementation has some additional methods here.
     * So add them here to get correct binary layout of the object.
     * In API version 2.2 this affects IVirtualBox and ISession only. */
    nsresult PR_COM_METHOD (*GetTypeInfoCount)(ISession *pThis);
    nsresult PR_COM_METHOD (*GetTypeInfo)(ISession *pThis);
    nsresult PR_COM_METHOD (*GetIDsOfNames)(ISession *pThis);
    nsresult PR_COM_METHOD (*Invoke)(ISession *pThis);
#  endif

    nsresult PR_COM_METHOD (*GetState)(ISession *pThis, PRUint32 *state);

    nsresult PR_COM_METHOD (*GetType)(ISession *pThis, PRUint32 *type);

    nsresult PR_COM_METHOD (*GetMachine)(ISession *pThis, IMachine * *machine);

    nsresult PR_COM_METHOD (*GetConsole)(ISession *pThis, IConsole * *console);

    nsresult PR_COM_METHOD (*Close)(ISession *pThis );

};

struct ISession
{
    struct ISession_vtbl *vtbl;
};
/* End of struct ISession Declaration */


/* Start of struct IStorageController Declaration */
#  define ISTORAGECONTROLLER_IID_STR "6bf8335b-d14a-44a5-9b45-ddc49ce7d5b2"
#  define ISTORAGECONTROLLER_IID { \
    0x6bf8335b, 0xd14a, 0x44a5, \
    { 0x9b, 0x45, 0xdd, 0xc4, 0x9c, 0xe7, 0xd5, 0xb2 } \
}
struct IStorageController_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetName)(IStorageController *pThis, PRUnichar * *name);

    nsresult PR_COM_METHOD (*GetMaxDevicesPerPortCount)(IStorageController *pThis, PRUint32 *maxDevicesPerPortCount);

    nsresult PR_COM_METHOD (*GetMinPortCount)(IStorageController *pThis, PRUint32 *minPortCount);

    nsresult PR_COM_METHOD (*GetMaxPortCount)(IStorageController *pThis, PRUint32 *maxPortCount);

    nsresult PR_COM_METHOD (*GetInstance)(IStorageController *pThis, PRUint32 *instance);
    nsresult PR_COM_METHOD (*SetInstance)(IStorageController *pThis, PRUint32 instance);

    nsresult PR_COM_METHOD (*GetPortCount)(IStorageController *pThis, PRUint32 *portCount);
    nsresult PR_COM_METHOD (*SetPortCount)(IStorageController *pThis, PRUint32 portCount);

    nsresult PR_COM_METHOD (*GetBus)(IStorageController *pThis, PRUint32 *bus);

    nsresult PR_COM_METHOD (*GetControllerType)(IStorageController *pThis, PRUint32 *controllerType);
    nsresult PR_COM_METHOD (*SetControllerType)(IStorageController *pThis, PRUint32 controllerType);

    nsresult PR_COM_METHOD (*GetIDEEmulationPort)(
        IStorageController *pThis,
        PRInt32 devicePosition,
        PRInt32 * portNumber
    );

    nsresult PR_COM_METHOD (*SetIDEEmulationPort)(
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
#  define IPERFORMANCEMETRIC_IID_STR "2a1a60ae-9345-4019-ad53-d34ba41cbfe9"
#  define IPERFORMANCEMETRIC_IID { \
    0x2a1a60ae, 0x9345, 0x4019, \
    { 0xad, 0x53, 0xd3, 0x4b, 0xa4, 0x1c, 0xbf, 0xe9 } \
}
struct IPerformanceMetric_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetMetricName)(IPerformanceMetric *pThis, PRUnichar * *metricName);

    nsresult PR_COM_METHOD (*GetObject)(IPerformanceMetric *pThis, nsISupports * *object);

    nsresult PR_COM_METHOD (*GetDescription)(IPerformanceMetric *pThis, PRUnichar * *description);

    nsresult PR_COM_METHOD (*GetPeriod)(IPerformanceMetric *pThis, PRUint32 *period);

    nsresult PR_COM_METHOD (*GetCount)(IPerformanceMetric *pThis, PRUint32 *count);

    nsresult PR_COM_METHOD (*GetUnit)(IPerformanceMetric *pThis, PRUnichar * *unit);

    nsresult PR_COM_METHOD (*GetMinimumValue)(IPerformanceMetric *pThis, PRInt32 *minimumValue);

    nsresult PR_COM_METHOD (*GetMaximumValue)(IPerformanceMetric *pThis, PRInt32 *maximumValue);

};

struct IPerformanceMetric
{
    struct IPerformanceMetric_vtbl *vtbl;
};
/* End of struct IPerformanceMetric Declaration */


/* Start of struct IPerformanceCollector Declaration */
#  define IPERFORMANCECOLLECTOR_IID_STR "e22e1acb-ac4a-43bb-a31c-17321659b0c6"
#  define IPERFORMANCECOLLECTOR_IID { \
    0xe22e1acb, 0xac4a, 0x43bb, \
    { 0xa3, 0x1c, 0x17, 0x32, 0x16, 0x59, 0xb0, 0xc6 } \
}
struct IPerformanceCollector_vtbl
{
    struct nsISupports_vtbl nsisupports;

    nsresult PR_COM_METHOD (*GetMetricNames)(IPerformanceCollector *pThis, PRUint32 *metricNamesSize, PRUnichar * **metricNames);

    nsresult PR_COM_METHOD (*GetMetrics)(
        IPerformanceCollector *pThis,
        PRUint32 metricNamesSize,
        PRUnichar ** metricNames,
        PRUint32 objectsSize,
        nsISupports ** objects,
        PRUint32 *metricsSize,
        IPerformanceMetric *** metrics
    );

    nsresult PR_COM_METHOD (*SetupMetrics)(
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

    nsresult PR_COM_METHOD (*EnableMetrics)(
        IPerformanceCollector *pThis,
        PRUint32 metricNamesSize,
        PRUnichar ** metricNames,
        PRUint32 objectsSize,
        nsISupports ** objects,
        PRUint32 *affectedMetricsSize,
        IPerformanceMetric *** affectedMetrics
    );

    nsresult PR_COM_METHOD (*DisableMetrics)(
        IPerformanceCollector *pThis,
        PRUint32 metricNamesSize,
        PRUnichar ** metricNames,
        PRUint32 objectsSize,
        nsISupports ** objects,
        PRUint32 *affectedMetricsSize,
        IPerformanceMetric *** affectedMetrics
    );

    nsresult PR_COM_METHOD (*QueryMetricsData)(
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



#  define NS_VIRTUALBOX_CID { \
    0xB1A7A4F2, 0x47B9, 0x4A1E, \
    { 0x82, 0xB2, 0x07, 0xCC, 0xD5, 0x32, 0x3C, 0x3F } \
}
#  define NS_VIRTUALBOX_CONTRACTID "@virtualbox.org/VirtualBox;1"
/* for compatibility with Win32 */
#  define CLSID_VirtualBox (nsCID) NS_VIRTUALBOX_CID



#  define NS_SESSION_CID { \
    0x3C02F46D, 0xC9D2, 0x4f11, \
    { 0xA3, 0x84, 0x53, 0xF0, 0xCF, 0x91, 0x72, 0x14 } \
}
#  define NS_SESSION_CONTRACTID "@virtualbox.org/Session;1"
/* for compatibility with Win32 */
#  define CLSID_Session (nsCID) NS_SESSION_CID



# endif /* !__cplusplus */

# ifdef IN_VBOXXPCOMC
#  define VBOXXPCOMC_DECL(type)  PR_EXPORT(type)
# else
#  define VBOXXPCOMC_DECL(type)  PR_IMPORT(type)
# endif

# ifdef __cplusplus
extern "C" {
# endif


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
# define VBOX_XPCOMC_VERSION     0x00010000U

VBOXXPCOMC_DECL(PCVBOXXPCOM) VBoxGetXPCOMCFunctions(unsigned uVersion);
/** Typedef for VBoxGetXPCOMCFunctions. */
typedef PCVBOXXPCOM (*PFNVBOXGETXPCOMCFUNCTIONS)(unsigned uVersion);

/** The symbol name of VBoxGetXPCOMCFunctions. */
# if defined(__OS2__)
#  define VBOX_GET_XPCOMC_FUNCTIONS_SYMBOL_NAME   "_VBoxGetXPCOMCFunctions"
# else
#  define VBOX_GET_XPCOMC_FUNCTIONS_SYMBOL_NAME   "VBoxGetXPCOMCFunctions"
# endif


# ifdef __cplusplus
}
# endif

#endif /* !___VirtualBox_CXPCOM_h */
