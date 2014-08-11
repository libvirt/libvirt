/*
 * Copyright 2014, Taowei Luo (uaedante@gmail.com)
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

#ifndef VBOX_COMMON_H
# define VBOX_COMMON_H

# ifdef ___VirtualBox_CXPCOM_h
#  error this file should not be included after vbox_CAPI_v*.h
# endif

# include "internal.h"
# include <stddef.h>
# include "wchar.h"

/* This file extracts some symbols defined in
 * vbox_CAPI_v*.h. It tells the vbox_common.c
 * how to treat with this symbols. This file
 * can't be included with files such as
 * vbox_CAPI_v*.h, or it would casue multiple
 * definitions.
 *
 * You can see the more informations in vbox_api.h
 */

/* Copied definitions from vbox_CAPI_*.h.
 * We must MAKE SURE these codes are compatible. */

typedef unsigned char PRUint8;
# if (defined(HPUX) && defined(__cplusplus) \
     && !defined(__GNUC__) && __cplusplus < 199707L) \
    || (defined(SCO) && defined(__cplusplus) \
        && !defined(__GNUC__) && __cplusplus == 1L)
typedef char PRInt8;
# else
typedef signed char PRInt8;
# endif

# define PR_INT8_MAX 127
# define PR_INT8_MIN (-128)
# define PR_UINT8_MAX 255U

typedef unsigned short PRUint16;
typedef short PRInt16;

# define PR_INT16_MAX 32767
# define PR_INT16_MIN (-32768)
# define PR_UINT16_MAX 65535U

typedef unsigned int PRUint32;
typedef int PRInt32;
# define PR_INT32(x)  x
# define PR_UINT32(x) x ## U

# define PR_INT32_MAX PR_INT32(2147483647)
# define PR_INT32_MIN (-PR_INT32_MAX - 1)
# define PR_UINT32_MAX PR_UINT32(4294967295)

typedef long PRInt64;
typedef unsigned long PRUint64;
typedef int PRIntn;
typedef unsigned int PRUintn;

typedef double          PRFloat64;
typedef size_t PRSize;

typedef ptrdiff_t PRPtrdiff;

typedef unsigned long PRUptrdiff;

typedef PRIntn PRBool;

# define PR_TRUE 1
# define PR_FALSE 0

typedef PRUint8 PRPackedBool;

/*
** Status code used by some routines that have a single point of failure or
** special status return.
*/
typedef enum { PR_FAILURE = -1, PR_SUCCESS = 0 } PRStatus;

# ifndef __PRUNICHAR__
#  define __PRUNICHAR__
#  if defined(WIN32) || defined(XP_MAC)
typedef wchar_t PRUnichar;
#  else
typedef PRUint16 PRUnichar;
#  endif
# endif

typedef long PRWord;
typedef unsigned long PRUword;

# define nsnull 0
typedef PRUint32 nsresult;

# if defined(__GNUC__) && (__GNUC__ > 2)
#  define NS_LIKELY(x)    (__builtin_expect((x), 1))
#  define NS_UNLIKELY(x)  (__builtin_expect((x), 0))
# else
#  define NS_LIKELY(x)    (x)
#  define NS_UNLIKELY(x)  (x)
# endif

# define NS_FAILED(_nsresult) (NS_UNLIKELY((_nsresult) & 0x80000000))
# define NS_SUCCEEDED(_nsresult) (NS_LIKELY(!((_nsresult) & 0x80000000)))

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

typedef struct _vboxArray vboxArray;

# ifdef WIN32

struct _vboxArray {
    void **items;
    size_t count;
    void *handle;
};
#  define VBOX_ARRAY_INITIALIZER { NULL, 0, NULL }

# else /* !WIN32 */

struct _vboxArray {
    void **items;
    size_t count;
};
#  define VBOX_ARRAY_INITIALIZER { NULL, 0 }

# endif /* !WIN32 */

/* We make the assumption that these enum flags
 * are compatible in all vbox API version.
 *
 * Yes it is, as it has been checked from vbox 2.2 to
 * vbox 4.3.3. And this rule MAY NOT stands for new
 * vbox versions.
 * */
enum CPUPropertyType
{
    CPUPropertyType_Null = 0,
    CPUPropertyType_PAE = 1,
    CPUPropertyType_Synthetic = 2,
};

enum AudioControllerType
{
    AudioControllerType_AC97 = 0,
    AudioControllerType_SB16 = 1
};

enum ChipsetType
{
    ChipsetType_Null = 0,
    ChipsetType_PIIX3 = 1,
    ChipsetType_ICH9 = 2
};

enum NetworkAdapterType
{
    NetworkAdapterType_Null = 0,
    NetworkAdapterType_Am79C970A = 1,
    NetworkAdapterType_Am79C973 = 2,
    NetworkAdapterType_I82540EM = 3,
    NetworkAdapterType_I82543GC = 4,
    NetworkAdapterType_I82545EM = 5,
    NetworkAdapterType_Virtio = 6
};

enum NetworkAttachmentType
{
    NetworkAttachmentType_Null = 0,
    NetworkAttachmentType_NAT = 1,
    NetworkAttachmentType_Bridged = 2,
    NetworkAttachmentType_Internal = 3,
    NetworkAttachmentType_HostOnly = 4
};

enum PortMode
{
    PortMode_Disconnected = 0,
    PortMode_HostPipe = 1,
    PortMode_HostDevice = 2,
    PortMode_RawFile = 3
};

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

enum StorageBus
{
    StorageBus_Null = 0,
    StorageBus_IDE = 1,
    StorageBus_SATA = 2,
    StorageBus_SCSI = 3,
    StorageBus_Floppy = 4,
    StorageBus_SAS = 5
};

enum AccessMode
{
    AccessMode_ReadOnly = 1,
    AccessMode_ReadWrite = 2
};

enum MediumType
{
    MediumType_Normal = 0,
    MediumType_Immutable = 1,
    MediumType_Writethrough = 2,
};

enum CleanupMode
{
    CleanupMode_UnregisterOnly = 1,
    CleanupMode_DetachAllReturnNone = 2,
    CleanupMode_DetachAllReturnHardDisksOnly = 3,
    CleanupMode_Full = 4
};

enum MediumVariant
{
    MediumVariant_Standard = 0,
    MediumVariant_VmdkSplit2G = 0x01,
    MediumVariant_VmdkStreamOptimized = 0x04,
    MediumVariant_VmdkESX = 0x08,
    MediumVariant_Fixed = 0x10000,
    MediumVariant_Diff = 0x20000
};

# define VBOX_E_OBJECT_NOT_FOUND 0x80BB0001
# define VBOX_E_INVALID_VM_STATE 0x80BB0002
# define VBOX_E_VM_ERROR 0x80BB0003
# define VBOX_E_FILE_ERROR 0x80BB0004
# define VBOX_E_IPRT_ERROR 0x80BB0005
# define VBOX_E_PDM_ERROR 0x80BB0006
# define VBOX_E_INVALID_OBJECT_STATE 0x80BB0007
# define VBOX_E_HOST_ERROR 0x80BB0008
# define VBOX_E_NOT_SUPPORTED 0x80BB0009
# define VBOX_E_XML_ERROR 0x80BB000A
# define VBOX_E_INVALID_SESSION_STATE 0x80BB000B
# define VBOX_E_OBJECT_IN_USE 0x80BB000C

/* Simplied definitions in vbox_CAPI_*.h */

typedef void const *PCVBOXXPCOM;
typedef struct nsISupports nsISupports;
typedef nsISupports IVirtualBox;
typedef nsISupports ISession;
typedef nsISupports IConsole;
typedef nsISupports IProgress;
typedef nsISupports IMachine;
typedef nsISupports ISystemProperties;
typedef nsISupports IBIOSSettings;
typedef nsISupports IAudioAdapter;
typedef nsISupports INetworkAdapter;
typedef nsISupports ISerialPort;
typedef nsISupports IParallelPort;
typedef nsISupports IVRDxServer;
typedef nsISupports IUSBCommon;
typedef nsISupports IUSBDeviceFilter;
typedef nsISupports IMedium;
typedef nsISupports IMediumAttachment;
typedef nsISupports IStorageController;
typedef nsISupports ISharedFolder;
typedef nsISupports ISnapshot;
typedef nsISupports IDisplay;

#endif /* VBOX_COMMON_H */
