/** @file vbox_tmpl.c
 * Template File to support multiple versions of VirtualBox
 * at runtime :).
 *
 * IMPORTANT:
 * Please dont include this file in the src/Makefile.am, it
 * is automatically include by other files.
 */

/*
 * Copyright (C) 2010-2014 Red Hat, Inc.
 * Copyright (C) 2008-2009 Sun Microsystems, Inc.
 *
 * This file is part of a free software library; you can redistribute
 * it and/or modify it under the terms of the GNU Lesser General
 * Public License version 2.1 as published by the Free Software
 * Foundation and shipped in the "COPYING.LESSER" file with this library.
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

#include <config.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "internal.h"
#include "datatypes.h"
#include "domain_conf.h"
#include "domain_event.h"
#include "viralloc.h"
#include "virlog.h"
#include "virstring.h"
#include "virutil.h"

/* This one changes from version to version. */
#if VBOX_API_VERSION == 2002000
# include "vbox_CAPI_v2_2.h"
#elif VBOX_API_VERSION == 3000000
# include "vbox_CAPI_v3_0.h"
#elif VBOX_API_VERSION == 3001000
# include "vbox_CAPI_v3_1.h"
#elif VBOX_API_VERSION == 3002000
# include "vbox_CAPI_v3_2.h"
#elif VBOX_API_VERSION == 4000000
# include "vbox_CAPI_v4_0.h"
#elif VBOX_API_VERSION == 4001000
# include "vbox_CAPI_v4_1.h"
#elif VBOX_API_VERSION == 4002000
# include "vbox_CAPI_v4_2.h"
#elif VBOX_API_VERSION == 4002020
# include "vbox_CAPI_v4_2_20.h"
#elif VBOX_API_VERSION == 4003000
# include "vbox_CAPI_v4_3.h"
#elif VBOX_API_VERSION == 4003004
# include "vbox_CAPI_v4_3_4.h"
#else
# error "Unsupport VBOX_API_VERSION"
#endif

/* Include this *last* or we'll get the wrong vbox_CAPI_*.h. */
#include "vbox_glue.h"

#if VBOX_API_VERSION < 4000000
typedef IVRDPServer IVRDxServer;
#else /* VBOX_API_VERSION >= 4000000 */
typedef IVRDEServer IVRDxServer;
#endif /* VBOX_API_VERSION >= 4000000 */

#if VBOX_API_VERSION < 4003000
typedef IUSBController IUSBCommon;
#else /* VBOX_API_VERSION >= 4003000 */
typedef IUSBDeviceFilters IUSBCommon;
#endif /* VBOX_API_VERSION >= 4003000 */

#if VBOX_API_VERSION < 3001000
typedef IHardDiskAttachment IMediumAttachment;
#else  /* VBOX_API_VERSION >= 3001000 */
typedef IMedium IHardDisk;
#endif /* VBOX_API_VERSION >= 3001000 */

#include "vbox_uniformed_api.h"

#define VIR_FROM_THIS                   VIR_FROM_VBOX

VIR_LOG_INIT("vbox.vbox_tmpl");

#define vboxUnsupported() \
    VIR_WARN("No %s in current vbox version %d.", __FUNCTION__, VBOX_API_VERSION);

#define VBOX_UTF16_FREE(arg)                                            \
    do {                                                                \
        if (arg) {                                                      \
            data->pFuncs->pfnUtf16Free(arg);                            \
            (arg) = NULL;                                               \
        }                                                               \
    } while (0)

#define VBOX_UTF8_FREE(arg)                                             \
    do {                                                                \
        if (arg) {                                                      \
            data->pFuncs->pfnUtf8Free(arg);                             \
            (arg) = NULL;                                               \
        }                                                               \
    } while (0)

#define VBOX_UTF16_TO_UTF8(arg1, arg2)  data->pFuncs->pfnUtf16ToUtf8(arg1, arg2)
#define VBOX_UTF8_TO_UTF16(arg1, arg2)  data->pFuncs->pfnUtf8ToUtf16(arg1, arg2)

#define VBOX_RELEASE(arg)                                                     \
    do {                                                                      \
        if (arg) {                                                            \
            (arg)->vtbl->nsisupports.Release((nsISupports *)(arg));           \
            (arg) = NULL;                                                     \
        }                                                                     \
    } while (0)

#if VBOX_API_VERSION < 3001000
# define VBOX_MEDIUM_RELEASE(arg) \
if (arg)\
    (arg)->vtbl->imedium.nsisupports.Release((nsISupports *)(arg))
#else  /* VBOX_API_VERSION >= 3001000 */
# define VBOX_MEDIUM_RELEASE(arg) VBOX_RELEASE(arg)
#endif /* VBOX_API_VERSION >= 3001000 */

#define DEBUGPRUnichar(msg, strUtf16) \
if (strUtf16) {\
    char *strUtf8 = NULL;\
\
    g_pVBoxGlobalData->pFuncs->pfnUtf16ToUtf8(strUtf16, &strUtf8);\
    if (strUtf8) {\
        VIR_DEBUG("%s: %s", msg, strUtf8);\
        g_pVBoxGlobalData->pFuncs->pfnUtf8Free(strUtf8);\
    }\
}

#define DEBUGUUID(msg, iid) \
{\
    VIR_DEBUG("%s: {%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}", msg,\
          (unsigned)(iid)->m0,\
          (unsigned)(iid)->m1,\
          (unsigned)(iid)->m2,\
          (unsigned)(iid)->m3[0],\
          (unsigned)(iid)->m3[1],\
          (unsigned)(iid)->m3[2],\
          (unsigned)(iid)->m3[3],\
          (unsigned)(iid)->m3[4],\
          (unsigned)(iid)->m3[5],\
          (unsigned)(iid)->m3[6],\
          (unsigned)(iid)->m3[7]);\
}\

#if VBOX_API_VERSION > 2002000

/* g_pVBoxGlobalData has to be global variable,
 * there is no other way to make the callbacks
 * work other then having g_pVBoxGlobalData as
 * global, because the functions namely AddRef,
 * Release, etc consider it as global and you
 * can't change the function definition as it
 * is XPCOM nsISupport::* function and it expects
 * them that way
 */

static vboxGlobalData *g_pVBoxGlobalData;

#endif /* !(VBOX_API_VERSION == 2002000) */

#if VBOX_API_VERSION < 4000000

# define VBOX_SESSION_OPEN(/* in */ iid_value, /* unused */ machine) \
    data->vboxObj->vtbl->OpenSession(data->vboxObj, data->vboxSession, iid_value)

# define VBOX_SESSION_CLOSE() \
    data->vboxSession->vtbl->Close(data->vboxSession)

#else /* VBOX_API_VERSION >= 4000000 */

# define VBOX_SESSION_OPEN(/* unused */ iid_value, /* in */ machine) \
    machine->vtbl->LockMachine(machine, data->vboxSession, LockType_Write)

# define VBOX_SESSION_CLOSE() \
    data->vboxSession->vtbl->UnlockMachine(data->vboxSession)

#endif /* VBOX_API_VERSION >= 4000000 */

#if VBOX_API_VERSION > 2002000 && VBOX_API_VERSION < 4000000
/* Since vboxConnectGetCapabilities has been rewritten,
 * vboxDriverLock and vboxDriverUnlock only be used in code for
 * 3.x release. */

static void vboxDriverLock(vboxGlobalData *data)
{
    virMutexLock(&data->lock);
}

static void vboxDriverUnlock(vboxGlobalData *data)
{
    virMutexUnlock(&data->lock);
}

#endif

#if VBOX_API_VERSION == 2002000

static void nsIDtoChar(unsigned char *uuid, const nsID *iid)
{
    char uuidstrsrc[VIR_UUID_STRING_BUFLEN];
    char uuidstrdst[VIR_UUID_STRING_BUFLEN];
    unsigned char uuidinterim[VIR_UUID_BUFLEN];
    size_t i;

    memcpy(uuidinterim, iid, VIR_UUID_BUFLEN);
    virUUIDFormat(uuidinterim, uuidstrsrc);

    uuidstrdst[0] = uuidstrsrc[6];
    uuidstrdst[1] = uuidstrsrc[7];
    uuidstrdst[2] = uuidstrsrc[4];
    uuidstrdst[3] = uuidstrsrc[5];
    uuidstrdst[4] = uuidstrsrc[2];
    uuidstrdst[5] = uuidstrsrc[3];
    uuidstrdst[6] = uuidstrsrc[0];
    uuidstrdst[7] = uuidstrsrc[1];

    uuidstrdst[8] = uuidstrsrc[8];

    uuidstrdst[9] = uuidstrsrc[11];
    uuidstrdst[10] = uuidstrsrc[12];
    uuidstrdst[11] = uuidstrsrc[9];
    uuidstrdst[12] = uuidstrsrc[10];

    uuidstrdst[13] = uuidstrsrc[13];

    uuidstrdst[14] = uuidstrsrc[16];
    uuidstrdst[15] = uuidstrsrc[17];
    uuidstrdst[16] = uuidstrsrc[14];
    uuidstrdst[17] = uuidstrsrc[15];

    for (i = 18; i < VIR_UUID_STRING_BUFLEN; i++)
        uuidstrdst[i] = uuidstrsrc[i];

    uuidstrdst[VIR_UUID_STRING_BUFLEN-1] = '\0';
    ignore_value(virUUIDParse(uuidstrdst, uuid));
}

static void nsIDFromChar(nsID *iid, const unsigned char *uuid)
{
    char uuidstrsrc[VIR_UUID_STRING_BUFLEN];
    char uuidstrdst[VIR_UUID_STRING_BUFLEN];
    unsigned char uuidinterim[VIR_UUID_BUFLEN];
    size_t i;

    virUUIDFormat(uuid, uuidstrsrc);

    uuidstrdst[0] = uuidstrsrc[6];
    uuidstrdst[1] = uuidstrsrc[7];
    uuidstrdst[2] = uuidstrsrc[4];
    uuidstrdst[3] = uuidstrsrc[5];
    uuidstrdst[4] = uuidstrsrc[2];
    uuidstrdst[5] = uuidstrsrc[3];
    uuidstrdst[6] = uuidstrsrc[0];
    uuidstrdst[7] = uuidstrsrc[1];

    uuidstrdst[8] = uuidstrsrc[8];

    uuidstrdst[9] = uuidstrsrc[11];
    uuidstrdst[10] = uuidstrsrc[12];
    uuidstrdst[11] = uuidstrsrc[9];
    uuidstrdst[12] = uuidstrsrc[10];

    uuidstrdst[13] = uuidstrsrc[13];

    uuidstrdst[14] = uuidstrsrc[16];
    uuidstrdst[15] = uuidstrsrc[17];
    uuidstrdst[16] = uuidstrsrc[14];
    uuidstrdst[17] = uuidstrsrc[15];

    for (i = 18; i < VIR_UUID_STRING_BUFLEN; i++)
        uuidstrdst[i] = uuidstrsrc[i];

    uuidstrdst[VIR_UUID_STRING_BUFLEN-1] = '\0';
    ignore_value(virUUIDParse(uuidstrdst, uuidinterim));
    memcpy(iid, uuidinterim, VIR_UUID_BUFLEN);
}

# ifdef WIN32

typedef struct _vboxIID_v2_x_WIN32 vboxIID;
typedef struct _vboxIID_v2_x_WIN32 vboxIID_v2_x_WIN32;

#  define VBOX_IID_INITIALIZER { { 0, 0, 0, { 0, 0, 0, 0, 0, 0, 0, 0 } } }
#  define IID_MEMBER(name) (iidu->vboxIID_v2_x_WIN32.name)

static void
vboxIIDUnalloc_v2_x_WIN32(vboxGlobalData *data ATTRIBUTE_UNUSED,
                          vboxIID_v2_x_WIN32 *iid ATTRIBUTE_UNUSED)
{
    /* Nothing to free */
}

static void
_vboxIIDUnalloc(vboxGlobalData *data ATTRIBUTE_UNUSED,
                vboxIIDUnion *iid ATTRIBUTE_UNUSED)
{
    /* Nothing to free */
}

static void
vboxIIDToUUID_v2_x_WIN32(vboxIID_v2_x_WIN32 *iid, unsigned char *uuid)
{
    nsIDtoChar(uuid, (nsID *)&iid->value);
}

static void
_vboxIIDToUUID(vboxGlobalData *data ATTRIBUTE_UNUSED, vboxIIDUnion *iidu, unsigned char *uuid)
{
    vboxIIDToUUID_v2_x_WIN32(&iidu->vboxIID_v2_x_WIN32, uuid);
}

static void
vboxIIDFromUUID_v2_x_WIN32(vboxGlobalData *data, vboxIID_v2_x_WIN32 *iid,
                           const unsigned char *uuid)
{
    vboxIIDUnalloc_v2_x_WIN32(data, iid);

    nsIDFromChar((nsID *)&iid->value, uuid);
}

static void
_vboxIIDFromUUID(vboxGlobalData *data, vboxIIDUnion *iidu,
                 const unsigned char *uuid)
{
    vboxIIDFromUUID_v2_x_WIN32(data, &iidu->vboxIID_v2_x_WIN32, uuid);
}

static bool
vboxIIDIsEqual_v2_x_WIN32(vboxIID_v2_x_WIN32 *iid1, vboxIID_v2_x_WIN32 *iid2)
{
    return memcmp(&iid1->value, &iid2->value, sizeof(GUID)) == 0;
}

static bool
_vboxIIDIsEqual(vboxGlobalData *data ATTRIBUTE_UNUSED, vboxIIDUnion *iidu1, vboxIIDUnion *iidu2)
{
    return vboxIIDIsEqual_v2_x_WIN32(&iidu1->vboxIID_v2_x_WIN32, &iidu2->vboxIID_v2_x_WIN32);
}

static void
vboxIIDFromArrayItem_v2_x_WIN32(vboxGlobalData *data, vboxIID_v2_x_WIN32 *iid,
                                vboxArray *array, int idx)
{
    GUID *items = (GUID *)array->items;

    vboxIIDUnalloc_v2_x_WIN32(data, iid);

    memcpy(&iid->value, &items[idx], sizeof(GUID));
}

static void
_vboxIIDFromArrayItem(vboxGlobalData *data, vboxIIDUnion *iidu,
                      vboxArray *array, int idx)
{
    vboxIIDFromArrayItem_v2_x_WIN32(data, &iidu->vboxIID_v2_x_WIN32, array, idx);
}

#  define vboxIIDUnalloc(iid) vboxIIDUnalloc_v2_x_WIN32(data, iid)
#  define vboxIIDToUUID(iid, uuid) vboxIIDToUUID_v2_x_WIN32(iid, uuid)
#  define vboxIIDFromUUID(iid, uuid) vboxIIDFromUUID_v2_x_WIN32(data, iid, uuid)
#  define vboxIIDIsEqual(iid1, iid2) vboxIIDIsEqual_v2_x_WIN32(iid1, iid2)
#  define vboxIIDFromArrayItem(iid, array, idx) \
    vboxIIDFromArrayItem_v2_x_WIN32(data, iid, array, idx)
#  define DEBUGIID(msg, iid) DEBUGUUID(msg, (nsID *)&(iid))

# else /* !WIN32 */

typedef struct _vboxIID_v2_x vboxIID;
typedef struct _vboxIID_v2_x vboxIID_v2_x;

#  define VBOX_IID_INITIALIZER { NULL, { 0, 0, 0, { 0, 0, 0, 0, 0, 0, 0, 0 } } }
#  define IID_MEMBER(name) (iidu->vboxIID_v2_x.name)

static void
vboxIIDUnalloc_v2_x(vboxGlobalData *data, vboxIID_v2_x *iid)
{
    if (iid->value == NULL)
        return;

    if (iid->value != &iid->backing)
        data->pFuncs->pfnComUnallocMem(iid->value);

    iid->value = NULL;
}

static void
_vboxIIDUnalloc(vboxGlobalData *data, vboxIIDUnion *iidu)
{
    vboxIIDUnalloc_v2_x(data, &iidu->vboxIID_v2_x);
}

static void
vboxIIDToUUID_v2_x(vboxIID_v2_x *iid, unsigned char *uuid)
{
    nsIDtoChar(uuid, iid->value);
}

static void
_vboxIIDToUUID(vboxGlobalData *data ATTRIBUTE_UNUSED,
               vboxIIDUnion *iidu, unsigned char *uuid)
{
    vboxIIDToUUID_v2_x(&iidu->vboxIID_v2_x, uuid);
}

static void
vboxIIDFromUUID_v2_x(vboxGlobalData *data, vboxIID_v2_x *iid,
                     const unsigned char *uuid)
{
    vboxIIDUnalloc_v2_x(data, iid);

    iid->value = &iid->backing;

    sa_assert(iid->value);
    nsIDFromChar(iid->value, uuid);
}

static void
_vboxIIDFromUUID(vboxGlobalData *data, vboxIIDUnion *iidu,
                 const unsigned char *uuid)
{
    vboxIIDFromUUID_v2_x(data, &iidu->vboxIID_v2_x, uuid);
}

static bool
vboxIIDIsEqual_v2_x(vboxIID_v2_x *iid1, vboxIID_v2_x *iid2)
{
    return memcmp(iid1->value, iid2->value, sizeof(nsID)) == 0;
}

static bool
_vboxIIDIsEqual(vboxGlobalData *data ATTRIBUTE_UNUSED,
                vboxIIDUnion *iidu1, vboxIIDUnion *iidu2)
{
    return vboxIIDIsEqual_v2_x(&iidu1->vboxIID_v2_x, &iidu2->vboxIID_v2_x);
}

static void
vboxIIDFromArrayItem_v2_x(vboxGlobalData *data, vboxIID_v2_x *iid,
                          vboxArray *array, int idx)
{
    vboxIIDUnalloc_v2_x(data, iid);

    iid->value = &iid->backing;

    memcpy(iid->value, array->items[idx], sizeof(nsID));
}

static void
_vboxIIDFromArrayItem(vboxGlobalData *data, vboxIIDUnion *iidu,
                      vboxArray *array, int idx)
{
    vboxIIDFromArrayItem_v2_x(data, &iidu->vboxIID_v2_x, array, idx);
}

#  define vboxIIDUnalloc(iid) vboxIIDUnalloc_v2_x(data, iid)
#  define vboxIIDToUUID(iid, uuid) vboxIIDToUUID_v2_x(iid, uuid)
#  define vboxIIDFromUUID(iid, uuid) vboxIIDFromUUID_v2_x(data, iid, uuid)
#  define vboxIIDIsEqual(iid1, iid2) vboxIIDIsEqual_v2_x(iid1, iid2)
#  define vboxIIDFromArrayItem(iid, array, idx) \
    vboxIIDFromArrayItem_v2_x(data, iid, array, idx)
#  define DEBUGIID(msg, iid) DEBUGUUID(msg, iid)

# endif /* !WIN32 */

#else /* VBOX_API_VERSION != 2002000 */

typedef struct _vboxIID_v3_x vboxIID;
typedef struct _vboxIID_v3_x vboxIID_v3_x;

# define VBOX_IID_INITIALIZER { NULL, true }
# define IID_MEMBER(name) (iidu->vboxIID_v3_x.name)

static void
vboxIIDUnalloc_v3_x(vboxGlobalData *data, vboxIID_v3_x *iid)
{
    if (iid->value != NULL && iid->owner)
        data->pFuncs->pfnUtf16Free(iid->value);

    iid->value = NULL;
    iid->owner = true;
}

static void
_vboxIIDUnalloc(vboxGlobalData *data, vboxIIDUnion *iidu)
{
    vboxIIDUnalloc_v3_x(data, &iidu->vboxIID_v3_x);
}

static void
vboxIIDToUUID_v3_x(vboxGlobalData *data, vboxIID_v3_x *iid,
                   unsigned char *uuid)
{
    char *utf8 = NULL;

    data->pFuncs->pfnUtf16ToUtf8(iid->value, &utf8);

    ignore_value(virUUIDParse(utf8, uuid));

    data->pFuncs->pfnUtf8Free(utf8);
}

static void
_vboxIIDToUUID(vboxGlobalData *data, vboxIIDUnion *iidu,
               unsigned char *uuid)
{
    vboxIIDToUUID_v3_x(data, &iidu->vboxIID_v3_x, uuid);
}

static void
vboxIIDFromUUID_v3_x(vboxGlobalData *data, vboxIID_v3_x *iid,
                     const unsigned char *uuid)
{
    char utf8[VIR_UUID_STRING_BUFLEN];

    vboxIIDUnalloc_v3_x(data, iid);

    virUUIDFormat(uuid, utf8);

    data->pFuncs->pfnUtf8ToUtf16(utf8, &iid->value);
}

static void
_vboxIIDFromUUID(vboxGlobalData *data, vboxIIDUnion *iidu,
                 const unsigned char *uuid)
{
    vboxIIDFromUUID_v3_x(data, &iidu->vboxIID_v3_x, uuid);
}

static bool
vboxIIDIsEqual_v3_x(vboxGlobalData *data, vboxIID_v3_x *iid1,
                    vboxIID_v3_x *iid2)
{
    unsigned char uuid1[VIR_UUID_BUFLEN];
    unsigned char uuid2[VIR_UUID_BUFLEN];

    /* Note: we can't directly compare the utf8 strings here
     * cause the two UUID's may have separators as space or '-'
     * or mixture of both and we don't want to fail here by
     * using direct string comparison. Here virUUIDParse() takes
     * care of these cases. */
    vboxIIDToUUID_v3_x(data, iid1, uuid1);
    vboxIIDToUUID_v3_x(data, iid2, uuid2);

    return memcmp(uuid1, uuid2, VIR_UUID_BUFLEN) == 0;
}

static bool
_vboxIIDIsEqual(vboxGlobalData *data, vboxIIDUnion *iidu1,
                vboxIIDUnion *iidu2)
{
    return vboxIIDIsEqual_v3_x(data, &iidu1->vboxIID_v3_x, &iidu2->vboxIID_v3_x);
}

static void
vboxIIDFromArrayItem_v3_x(vboxGlobalData *data, vboxIID_v3_x *iid,
                          vboxArray *array, int idx)
{
    vboxIIDUnalloc_v3_x(data, iid);

    iid->value = array->items[idx];
    iid->owner = false;
}

static void
_vboxIIDFromArrayItem(vboxGlobalData *data, vboxIIDUnion *iidu,
                      vboxArray *array, int idx)
{
    vboxIIDFromArrayItem_v3_x(data, &iidu->vboxIID_v3_x, array, idx);
}

# define vboxIIDUnalloc(iid) vboxIIDUnalloc_v3_x(data, iid)
# define vboxIIDToUUID(iid, uuid) vboxIIDToUUID_v3_x(data, iid, uuid)
# define vboxIIDFromUUID(iid, uuid) vboxIIDFromUUID_v3_x(data, iid, uuid)
# define vboxIIDIsEqual(iid1, iid2) vboxIIDIsEqual_v3_x(data, iid1, iid2)
# define vboxIIDFromArrayItem(iid, array, idx) \
    vboxIIDFromArrayItem_v3_x(data, iid, array, idx)
# define DEBUGIID(msg, strUtf16) DEBUGPRUnichar(msg, strUtf16)

#endif /* !(VBOX_API_VERSION == 2002000) */

/**
 * function to get the StorageBus, Port number
 * and Device number for the given devicename
 * e.g: hda has StorageBus = IDE, port = 0,
 *      device = 0
 *
 * @returns     true on Success, false on failure.
 * @param       deviceName      Input device name
 * @param       aMaxPortPerInst Input array of max port per device instance
 * @param       aMaxSlotPerPort Input array of max slot per device port
 * @param       storageBus      Input storage bus type
 * @param       deviceInst      Output device instance number
 * @param       devicePort      Output port number
 * @param       deviceSlot      Output slot number
 *
 */
#if VBOX_API_VERSION >= 3001000
# if VBOX_API_VERSION < 4000000
/* Only 3.x will use this function. */
static bool vboxGetDeviceDetails(const char *deviceName,
                                 PRUint32 *aMaxPortPerInst,
                                 PRUint32 *aMaxSlotPerPort,
                                 PRUint32 storageBus,
                                 PRInt32 *deviceInst,
                                 PRInt32 *devicePort,
                                 PRInt32 *deviceSlot)
{
    int total = 0;
    PRUint32 maxPortPerInst = 0;
    PRUint32 maxSlotPerPort = 0;

    if (!deviceName ||
        !deviceInst ||
        !devicePort ||
        !deviceSlot ||
        !aMaxPortPerInst ||
        !aMaxSlotPerPort)
        return false;

    if ((storageBus < StorageBus_IDE) ||
        (storageBus > StorageBus_Floppy))
        return false;

    total = virDiskNameToIndex(deviceName);

    maxPortPerInst = aMaxPortPerInst[storageBus];
    maxSlotPerPort = aMaxSlotPerPort[storageBus];

    if (!maxPortPerInst ||
        !maxSlotPerPort ||
        (total < 0))
        return false;

    *deviceInst = total / (maxPortPerInst * maxSlotPerPort);
    *devicePort = (total % (maxPortPerInst * maxSlotPerPort)) / maxSlotPerPort;
    *deviceSlot = (total % (maxPortPerInst * maxSlotPerPort)) % maxSlotPerPort;

    VIR_DEBUG("name=%s, total=%d, storageBus=%u, deviceInst=%d, "
          "devicePort=%d deviceSlot=%d, maxPortPerInst=%u maxSlotPerPort=%u",
          deviceName, total, storageBus, *deviceInst, *devicePort,
          *deviceSlot, maxPortPerInst, maxSlotPerPort);

    return true;
}

/**
 * function to get the values for max port per
 * instance and max slots per port for the devices
 *
 * @returns     true on Success, false on failure.
 * @param       vbox            Input IVirtualBox pointer
 * @param       maxPortPerInst  Output array of max port per instance
 * @param       maxSlotPerPort  Output array of max slot per port
 *
 */

/* This function would not be used in 4.1 and later since
 * vboxDomainSnapshotGetXMLDesc is written*/
static bool vboxGetMaxPortSlotValues(IVirtualBox *vbox,
                                     PRUint32 *maxPortPerInst,
                                     PRUint32 *maxSlotPerPort)
{
    ISystemProperties *sysProps = NULL;

    if (!vbox)
        return false;

    vbox->vtbl->GetSystemProperties(vbox, &sysProps);

    if (!sysProps)
        return false;

    sysProps->vtbl->GetMaxPortCountForStorageBus(sysProps,
                                                 StorageBus_IDE,
                                                 &maxPortPerInst[StorageBus_IDE]);
    sysProps->vtbl->GetMaxPortCountForStorageBus(sysProps,
                                                 StorageBus_SATA,
                                                 &maxPortPerInst[StorageBus_SATA]);
    sysProps->vtbl->GetMaxPortCountForStorageBus(sysProps,
                                                 StorageBus_SCSI,
                                                 &maxPortPerInst[StorageBus_SCSI]);
    sysProps->vtbl->GetMaxPortCountForStorageBus(sysProps,
                                                 StorageBus_Floppy,
                                                 &maxPortPerInst[StorageBus_Floppy]);

    sysProps->vtbl->GetMaxDevicesPerPortForStorageBus(sysProps,
                                                      StorageBus_IDE,
                                                      &maxSlotPerPort[StorageBus_IDE]);
    sysProps->vtbl->GetMaxDevicesPerPortForStorageBus(sysProps,
                                                      StorageBus_SATA,
                                                      &maxSlotPerPort[StorageBus_SATA]);
    sysProps->vtbl->GetMaxDevicesPerPortForStorageBus(sysProps,
                                                      StorageBus_SCSI,
                                                      &maxSlotPerPort[StorageBus_SCSI]);
    sysProps->vtbl->GetMaxDevicesPerPortForStorageBus(sysProps,
                                                      StorageBus_Floppy,
                                                      &maxSlotPerPort[StorageBus_Floppy]);

    VBOX_RELEASE(sysProps);

    return true;
}
# endif /* VBOX_API_VERSION < 4000000 */

/**
 * Converts Utf-16 string to int
 */
static int PRUnicharToInt(PRUnichar *strUtf16)
{
    char *strUtf8 = NULL;
    int ret = 0;

    if (!strUtf16)
        return -1;

    g_pVBoxGlobalData->pFuncs->pfnUtf16ToUtf8(strUtf16, &strUtf8);
    if (!strUtf8)
        return -1;

    if (virStrToLong_i(strUtf8, NULL, 10, &ret) < 0)
        ret = -1;

    g_pVBoxGlobalData->pFuncs->pfnUtf8Free(strUtf8);

    return ret;
}

/**
 * Converts int to Utf-16 string
 */
static PRUnichar *PRUnicharFromInt(int n) {
    PRUnichar *strUtf16 = NULL;
    char s[24];

    snprintf(s, sizeof(s), "%d", n);

    g_pVBoxGlobalData->pFuncs->pfnUtf8ToUtf16(s, &strUtf16);

    return strUtf16;
}

#endif /* VBOX_API_VERSION >= 3001000 */

static virDomainState _vboxConvertState(PRUint32 state)
{
    switch (state) {
        case MachineState_Running:
            return VIR_DOMAIN_RUNNING;
        case MachineState_Stuck:
            return VIR_DOMAIN_BLOCKED;
        case MachineState_Paused:
            return VIR_DOMAIN_PAUSED;
        case MachineState_Stopping:
            return VIR_DOMAIN_SHUTDOWN;
        case MachineState_PoweredOff:
        case MachineState_Saved:
            return VIR_DOMAIN_SHUTOFF;
        case MachineState_Aborted:
            return VIR_DOMAIN_CRASHED;
        case MachineState_Null:
        default:
            return VIR_DOMAIN_NOSTATE;
    }
}

#if VBOX_API_VERSION < 3001000

static void
_vboxAttachDrivesOld(virDomainDefPtr def, vboxGlobalData *data, IMachine *machine)
{
    size_t i;
    nsresult rc;

    if (def->ndisks == 0)
        return;

    for (i = 0; i < def->ndisks; i++) {
        const char *src = virDomainDiskGetSource(def->disks[i]);
        int type = virDomainDiskGetType(def->disks[i]);
        int format = virDomainDiskGetFormat(def->disks[i]);

        VIR_DEBUG("disk(%zu) type:       %d", i, type);
        VIR_DEBUG("disk(%zu) device:     %d", i, def->disks[i]->device);
        VIR_DEBUG("disk(%zu) bus:        %d", i, def->disks[i]->bus);
        VIR_DEBUG("disk(%zu) src:        %s", i, src);
        VIR_DEBUG("disk(%zu) dst:        %s", i, def->disks[i]->dst);
        VIR_DEBUG("disk(%zu) driverName: %s", i,
                  virDomainDiskGetDriver(def->disks[i]));
        VIR_DEBUG("disk(%zu) driverType: %s", i,
                  virStorageFileFormatTypeToString(format));
        VIR_DEBUG("disk(%zu) cachemode:  %d", i, def->disks[i]->cachemode);
        VIR_DEBUG("disk(%zu) readonly:   %s", i, (def->disks[i]->src->readonly
                                             ? "True" : "False"));
        VIR_DEBUG("disk(%zu) shared:     %s", i, (def->disks[i]->src->shared
                                             ? "True" : "False"));

        if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
            if (type == VIR_STORAGE_TYPE_FILE && src) {
                IDVDDrive *dvdDrive = NULL;
                /* Currently CDROM/DVD Drive is always IDE
                 * Secondary Master so neglecting the following
                 * parameters:
                 *      def->disks[i]->bus
                 *      def->disks[i]->dst
                 */

                machine->vtbl->GetDVDDrive(machine, &dvdDrive);
                if (dvdDrive) {
                    IDVDImage *dvdImage = NULL;
                    PRUnichar *dvdfileUtf16 = NULL;
                    vboxIID dvduuid = VBOX_IID_INITIALIZER;
                    vboxIID dvdemptyuuid = VBOX_IID_INITIALIZER;

                    VBOX_UTF8_TO_UTF16(src, &dvdfileUtf16);

                    data->vboxObj->vtbl->FindDVDImage(data->vboxObj,
                                                      dvdfileUtf16, &dvdImage);
                    if (!dvdImage) {
                        data->vboxObj->vtbl->OpenDVDImage(data->vboxObj,
                                                          dvdfileUtf16,
                                                          dvdemptyuuid.value,
                                                          &dvdImage);
                    }
                    if (dvdImage) {
                        rc = dvdImage->vtbl->imedium.GetId((IMedium *)dvdImage,
                                                           &dvduuid.value);
                        if (NS_FAILED(rc)) {
                            virReportError(VIR_ERR_INTERNAL_ERROR,
                                           _("can't get the uuid of the file to "
                                             "be attached to cdrom: %s, rc=%08x"),
                                           src, (unsigned)rc);
                        } else {
                            rc = dvdDrive->vtbl->MountImage(dvdDrive, dvduuid.value);
                            if (NS_FAILED(rc)) {
                                virReportError(VIR_ERR_INTERNAL_ERROR,
                                               _("could not attach the file to cdrom: %s, rc=%08x"),
                                               src, (unsigned)rc);
                            } else {
                                DEBUGIID("CD/DVDImage UUID:", dvduuid.value);
                            }
                        }

                        VBOX_MEDIUM_RELEASE(dvdImage);
                    }
                    vboxIIDUnalloc(&dvduuid);
                    VBOX_UTF16_FREE(dvdfileUtf16);
                    VBOX_RELEASE(dvdDrive);
                }
            } else if (type == VIR_STORAGE_TYPE_BLOCK) {
            }
        } else if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
            if (type == VIR_STORAGE_TYPE_FILE && src) {
                IHardDisk *hardDisk = NULL;
                PRUnichar *hddfileUtf16 = NULL;
                vboxIID hdduuid = VBOX_IID_INITIALIZER;
                PRUnichar *hddEmpty = NULL;
                /* Current Limitation: Harddisk can't be connected to
                 * Secondary Master as Secondary Master is always used
                 * for CD/DVD Drive, so don't connect the harddisk if it
                 * is requested to be connected to Secondary master
                 */

                VBOX_UTF8_TO_UTF16(src, &hddfileUtf16);
                VBOX_UTF8_TO_UTF16("", &hddEmpty);

                data->vboxObj->vtbl->FindHardDisk(data->vboxObj, hddfileUtf16,
                                                  &hardDisk);

                if (!hardDisk) {
# if VBOX_API_VERSION == 2002000
                    data->vboxObj->vtbl->OpenHardDisk(data->vboxObj,
                                                      hddfileUtf16,
                                                      AccessMode_ReadWrite,
                                                      &hardDisk);
# else
                    data->vboxObj->vtbl->OpenHardDisk(data->vboxObj,
                                                      hddfileUtf16,
                                                      AccessMode_ReadWrite,
                                                      0,
                                                      hddEmpty,
                                                      0,
                                                      hddEmpty,
                                                      &hardDisk);
# endif
                }

                if (hardDisk) {
                    rc = hardDisk->vtbl->imedium.GetId((IMedium *)hardDisk,
                                                       &hdduuid.value);
                    if (NS_FAILED(rc)) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("can't get the uuid of the file to be "
                                         "attached as harddisk: %s, rc=%08x"),
                                       src, (unsigned)rc);
                    } else {
                        if (def->disks[i]->src->readonly) {
                            hardDisk->vtbl->SetType(hardDisk,
                                                    HardDiskType_Immutable);
                            VIR_DEBUG("setting harddisk to readonly");
                        } else if (!def->disks[i]->src->readonly) {
                            hardDisk->vtbl->SetType(hardDisk,
                                                    HardDiskType_Normal);
                            VIR_DEBUG("setting harddisk type to normal");
                        }
                        if (def->disks[i]->bus == VIR_DOMAIN_DISK_BUS_IDE) {
                            if (STREQ(def->disks[i]->dst, "hdc")) {
                                VIR_DEBUG("Not connecting harddisk to hdc as hdc"
                                       " is taken by CD/DVD Drive");
                            } else {
                                PRInt32 channel = 0;
                                PRInt32 device = 0;
                                PRUnichar *hddcnameUtf16 = NULL;

                                char *hddcname;
                                ignore_value(VIR_STRDUP(hddcname, "IDE"));
                                VBOX_UTF8_TO_UTF16(hddcname, &hddcnameUtf16);
                                VIR_FREE(hddcname);

                                if (STREQ(def->disks[i]->dst, "hda")) {
                                    channel = 0;
                                    device = 0;
                                } else if (STREQ(def->disks[i]->dst, "hdb")) {
                                    channel = 0;
                                    device = 1;
                                } else if (STREQ(def->disks[i]->dst, "hdd")) {
                                    channel = 1;
                                    device = 1;
                                }

                                rc = machine->vtbl->AttachHardDisk(machine,
                                                                   hdduuid.value,
                                                                   hddcnameUtf16,
                                                                   channel,
                                                                   device);
                                VBOX_UTF16_FREE(hddcnameUtf16);

                                if (NS_FAILED(rc)) {
                                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                                   _("could not attach the file as "
                                                     "harddisk: %s, rc=%08x"),
                                                   src, (unsigned)rc);
                                } else {
                                    DEBUGIID("Attached HDD with UUID", hdduuid.value);
                                }
                            }
                        }
                    }
                    VBOX_MEDIUM_RELEASE(hardDisk);
                }
                vboxIIDUnalloc(&hdduuid);
                VBOX_UTF16_FREE(hddEmpty);
                VBOX_UTF16_FREE(hddfileUtf16);
            } else if (type == VIR_STORAGE_TYPE_BLOCK) {
            }
        } else if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
            if (type == VIR_STORAGE_TYPE_FILE && src) {
                IFloppyDrive *floppyDrive;
                machine->vtbl->GetFloppyDrive(machine, &floppyDrive);
                if (floppyDrive) {
                    rc = floppyDrive->vtbl->SetEnabled(floppyDrive, 1);
                    if (NS_SUCCEEDED(rc)) {
                        IFloppyImage *floppyImage = NULL;
                        PRUnichar *fdfileUtf16 = NULL;
                        vboxIID fduuid = VBOX_IID_INITIALIZER;
                        vboxIID fdemptyuuid = VBOX_IID_INITIALIZER;

                        VBOX_UTF8_TO_UTF16(src, &fdfileUtf16);
                        rc = data->vboxObj->vtbl->FindFloppyImage(data->vboxObj,
                                                                  fdfileUtf16,
                                                                  &floppyImage);

                        if (!floppyImage) {
                            data->vboxObj->vtbl->OpenFloppyImage(data->vboxObj,
                                                                 fdfileUtf16,
                                                                 fdemptyuuid.value,
                                                                 &floppyImage);
                        }

                        if (floppyImage) {
                            rc = floppyImage->vtbl->imedium.GetId((IMedium *)floppyImage,
                                                                  &fduuid.value);
                            if (NS_FAILED(rc)) {
                                virReportError(VIR_ERR_INTERNAL_ERROR,
                                               _("can't get the uuid of the file to "
                                                 "be attached to floppy drive: %s, rc=%08x"),
                                               src, (unsigned)rc);
                            } else {
                                rc = floppyDrive->vtbl->MountImage(floppyDrive,
                                                                   fduuid.value);
                                if (NS_FAILED(rc)) {
                                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                                   _("could not attach the file to "
                                                     "floppy drive: %s, rc=%08x"),
                                                   src, (unsigned)rc);
                                } else {
                                    DEBUGIID("floppyImage UUID", fduuid.value);
                                }
                            }
                            VBOX_MEDIUM_RELEASE(floppyImage);
                        }
                        vboxIIDUnalloc(&fduuid);
                        VBOX_UTF16_FREE(fdfileUtf16);
                    }
                    VBOX_RELEASE(floppyDrive);
                }
            } else if (type == VIR_STORAGE_TYPE_BLOCK) {
            }
        }
    }
}

#elif VBOX_API_VERSION < 4000000

static void
_vboxAttachDrivesOld(virDomainDefPtr def, vboxGlobalData *data, IMachine *machine)
{
    size_t i;
    nsresult rc;

    PRUint32 maxPortPerInst[StorageBus_Floppy + 1] = {};
    PRUint32 maxSlotPerPort[StorageBus_Floppy + 1] = {};
    PRUnichar *storageCtlName = NULL;
    bool error = false;

    /* get the max port/slots/etc for the given storage bus */
    error = !vboxGetMaxPortSlotValues(data->vboxObj, maxPortPerInst,
                                      maxSlotPerPort);

    /* add a storage controller for the mediums to be attached */
    /* this needs to change when multiple controller are supported for
     * ver > 3.1 */
    {
        IStorageController *storageCtl = NULL;
        PRUnichar *sName = NULL;

        VBOX_UTF8_TO_UTF16("IDE Controller", &sName);
        machine->vtbl->AddStorageController(machine,
                                            sName,
                                            StorageBus_IDE,
                                            &storageCtl);
        VBOX_UTF16_FREE(sName);
        VBOX_RELEASE(storageCtl);

        VBOX_UTF8_TO_UTF16("SATA Controller", &sName);
        machine->vtbl->AddStorageController(machine,
                                            sName,
                                            StorageBus_SATA,
                                            &storageCtl);
        VBOX_UTF16_FREE(sName);
        VBOX_RELEASE(storageCtl);

        VBOX_UTF8_TO_UTF16("SCSI Controller", &sName);
        machine->vtbl->AddStorageController(machine,
                                            sName,
                                            StorageBus_SCSI,
                                            &storageCtl);
        VBOX_UTF16_FREE(sName);
        VBOX_RELEASE(storageCtl);

        VBOX_UTF8_TO_UTF16("Floppy Controller", &sName);
        machine->vtbl->AddStorageController(machine,
                                            sName,
                                            StorageBus_Floppy,
                                            &storageCtl);
        VBOX_UTF16_FREE(sName);
        VBOX_RELEASE(storageCtl);
    }

    for (i = 0; i < def->ndisks && !error; i++) {
        const char *src = virDomainDiskGetSource(def->disks[i]);
        int type = virDomainDiskGetType(def->disks[i]);
        int format = virDomainDiskGetFormat(def->disks[i]);

        VIR_DEBUG("disk(%zu) type:       %d", i, type);
        VIR_DEBUG("disk(%zu) device:     %d", i, def->disks[i]->device);
        VIR_DEBUG("disk(%zu) bus:        %d", i, def->disks[i]->bus);
        VIR_DEBUG("disk(%zu) src:        %s", i, src);
        VIR_DEBUG("disk(%zu) dst:        %s", i, def->disks[i]->dst);
        VIR_DEBUG("disk(%zu) driverName: %s", i,
                  virDomainDiskGetDriver(def->disks[i]));
        VIR_DEBUG("disk(%zu) driverType: %s", i,
                  virStorageFileFormatTypeToString(format));
        VIR_DEBUG("disk(%zu) cachemode:  %d", i, def->disks[i]->cachemode);
        VIR_DEBUG("disk(%zu) readonly:   %s", i, (def->disks[i]->src->readonly
                                             ? "True" : "False"));
        VIR_DEBUG("disk(%zu) shared:     %s", i, (def->disks[i]->src->shared
                                             ? "True" : "False"));

        if (type == VIR_STORAGE_TYPE_FILE && src) {
            IMedium *medium = NULL;
            PRUnichar *mediumUUID = NULL;
            PRUnichar *mediumFileUtf16 = NULL;
            PRUint32 storageBus = StorageBus_Null;
            PRUint32 deviceType = DeviceType_Null;
            PRInt32 deviceInst = 0;
            PRInt32 devicePort = 0;
            PRInt32 deviceSlot = 0;

            VBOX_UTF8_TO_UTF16(src, &mediumFileUtf16);

            if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
                deviceType = DeviceType_HardDisk;
                data->vboxObj->vtbl->FindHardDisk(data->vboxObj,
                                                  mediumFileUtf16, &medium);
            } else if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
                deviceType = DeviceType_DVD;
                data->vboxObj->vtbl->FindDVDImage(data->vboxObj,
                                                  mediumFileUtf16, &medium);
            } else if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
                deviceType = DeviceType_Floppy;
                data->vboxObj->vtbl->FindFloppyImage(data->vboxObj,
                                                     mediumFileUtf16, &medium);
            } else {
                VBOX_UTF16_FREE(mediumFileUtf16);
                continue;
            }

            if (!medium) {
                PRUnichar *mediumEmpty = NULL;

                VBOX_UTF8_TO_UTF16("", &mediumEmpty);

                if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
                    rc = data->vboxObj->vtbl->OpenHardDisk(data->vboxObj,
                                                           mediumFileUtf16,
                                                           AccessMode_ReadWrite,
                                                           false,
                                                           mediumEmpty,
                                                           false,
                                                           mediumEmpty,
                                                           &medium);
                } else if (def->disks[i]->device ==
                           VIR_DOMAIN_DISK_DEVICE_CDROM) {
                    rc = data->vboxObj->vtbl->OpenDVDImage(data->vboxObj,
                                                           mediumFileUtf16,
                                                           mediumEmpty,
                                                           &medium);
                } else if (def->disks[i]->device ==
                           VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
                    rc = data->vboxObj->vtbl->OpenFloppyImage(data->vboxObj,
                                                              mediumFileUtf16,
                                                              mediumEmpty,
                                                              &medium);
                } else {
                    rc = 0;
                }
                VBOX_UTF16_FREE(mediumEmpty);
            }

            if (!medium) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Failed to attach the following disk/dvd/floppy "
                                 "to the machine: %s, rc=%08x"),
                               src, (unsigned)rc);
                VBOX_UTF16_FREE(mediumFileUtf16);
                continue;
            }

            rc = medium->vtbl->GetId(medium, &mediumUUID);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("can't get the uuid of the file to be attached "
                                 "as harddisk/dvd/floppy: %s, rc=%08x"),
                               src, (unsigned)rc);
                VBOX_RELEASE(medium);
                VBOX_UTF16_FREE(mediumFileUtf16);
                continue;
            }

            if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
                if (def->disks[i]->src->readonly) {
                    medium->vtbl->SetType(medium, MediumType_Immutable);
                    VIR_DEBUG("setting harddisk to immutable");
                } else if (!def->disks[i]->src->readonly) {
                    medium->vtbl->SetType(medium, MediumType_Normal);
                    VIR_DEBUG("setting harddisk type to normal");
                }
            }

            if (def->disks[i]->bus == VIR_DOMAIN_DISK_BUS_IDE) {
                VBOX_UTF8_TO_UTF16("IDE Controller", &storageCtlName);
                storageBus = StorageBus_IDE;
            } else if (def->disks[i]->bus == VIR_DOMAIN_DISK_BUS_SATA) {
                VBOX_UTF8_TO_UTF16("SATA Controller", &storageCtlName);
                storageBus = StorageBus_SATA;
            } else if (def->disks[i]->bus == VIR_DOMAIN_DISK_BUS_SCSI) {
                VBOX_UTF8_TO_UTF16("SCSI Controller", &storageCtlName);
                storageBus = StorageBus_SCSI;
            } else if (def->disks[i]->bus == VIR_DOMAIN_DISK_BUS_FDC) {
                VBOX_UTF8_TO_UTF16("Floppy Controller", &storageCtlName);
                storageBus = StorageBus_Floppy;
            }

            /* get the device details i.e instance, port and slot */
            if (!vboxGetDeviceDetails(def->disks[i]->dst,
                                      maxPortPerInst,
                                      maxSlotPerPort,
                                      storageBus,
                                      &deviceInst,
                                      &devicePort,
                                      &deviceSlot)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("can't get the port/slot number of "
                                 "harddisk/dvd/floppy to be attached: "
                                 "%s, rc=%08x"),
                               src, (unsigned)rc);
                VBOX_RELEASE(medium);
                VBOX_UTF16_FREE(mediumUUID);
                VBOX_UTF16_FREE(mediumFileUtf16);
                continue;
            }

            /* attach the harddisk/dvd/Floppy to the storage controller */
            rc = machine->vtbl->AttachDevice(machine,
                                             storageCtlName,
                                             devicePort,
                                             deviceSlot,
                                             deviceType,
                                             mediumUUID);

            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("could not attach the file as "
                                 "harddisk/dvd/floppy: %s, rc=%08x"),
                               src, (unsigned)rc);
            } else {
                DEBUGIID("Attached HDD/DVD/Floppy with UUID", mediumUUID);
            }

            VBOX_RELEASE(medium);
            VBOX_UTF16_FREE(mediumUUID);
            VBOX_UTF16_FREE(mediumFileUtf16);
            VBOX_UTF16_FREE(storageCtlName);
        }
    }
}

#else /* VBOX_API_VERSION >= 4000000 */

static void
_vboxAttachDrivesOld(virDomainDefPtr def ATTRIBUTE_UNUSED,
                     vboxGlobalData *data ATTRIBUTE_UNUSED,
                     IMachine *machine ATTRIBUTE_UNUSED)
{
    vboxUnsupported();
}

#endif /* VBOX_API_VERSION >= 4000000 */

#if VBOX_API_VERSION < 3001000
static int
_vboxDomainSnapshotRestore(virDomainPtr dom,
                          IMachine *machine,
                          ISnapshot *snapshot)
{
    vboxGlobalData *data = dom->conn->privateData;
    vboxIID iid = VBOX_IID_INITIALIZER;
    nsresult rc;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    rc = snapshot->vtbl->GetId(snapshot, &iid.value);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not get snapshot UUID"));
        goto cleanup;
    }

    rc = machine->vtbl->SetCurrentSnapshot(machine, iid.value);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not restore snapshot for domain %s"), dom->name);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    vboxIIDUnalloc(&iid);
    return ret;
}
#else
static int
_vboxDomainSnapshotRestore(virDomainPtr dom,
                          IMachine *machine,
                          ISnapshot *snapshot)
{
    vboxGlobalData *data = dom->conn->privateData;
    IConsole *console = NULL;
    IProgress *progress = NULL;
    PRUint32 state;
    nsresult rc;
    PRInt32 result;
    vboxIID domiid = VBOX_IID_INITIALIZER;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    rc = machine->vtbl->GetId(machine, &domiid.value);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not get domain UUID"));
        goto cleanup;
    }

    rc = machine->vtbl->GetState(machine, &state);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not get domain state"));
        goto cleanup;
    }

    if (state >= MachineState_FirstOnline
        && state <= MachineState_LastOnline) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("domain %s is already running"), dom->name);
        goto cleanup;
    }

    rc = VBOX_SESSION_OPEN(domiid.value, machine);
    if (NS_SUCCEEDED(rc))
        rc = data->vboxSession->vtbl->GetConsole(data->vboxSession, &console);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not open VirtualBox session with domain %s"),
                       dom->name);
        goto cleanup;
    }

    rc = console->vtbl->RestoreSnapshot(console, snapshot, &progress);
    if (NS_FAILED(rc) || !progress) {
        if (rc == VBOX_E_INVALID_VM_STATE) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("cannot restore domain snapshot for running domain"));
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("could not restore snapshot for domain %s"),
                           dom->name);
        }
        goto cleanup;
    }

    progress->vtbl->WaitForCompletion(progress, -1);
    progress->vtbl->GetResultCode(progress, &result);
    if (NS_FAILED(result)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not restore snapshot for domain %s"), dom->name);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VBOX_RELEASE(progress);
    VBOX_RELEASE(console);
    VBOX_SESSION_CLOSE();
    vboxIIDUnalloc(&domiid);
    return ret;
}
#endif

#if VBOX_API_VERSION <= 2002000 || VBOX_API_VERSION >= 4000000
    /* No Callback support for VirtualBox 2.2.* series */
    /* No Callback support for VirtualBox 4.* series */

static void
_registerDomainEvent(virHypervisorDriverPtr driver)
{
    driver->connectDomainEventRegister = NULL;
    driver->connectDomainEventDeregister = NULL;
    driver->connectDomainEventRegisterAny = NULL;
    driver->connectDomainEventDeregisterAny = NULL;
}

#else /* !(VBOX_API_VERSION == 2002000 || VBOX_API_VERSION >= 4000000) */

/* Functions needed for Callbacks */
static nsresult PR_COM_METHOD
vboxCallbackOnMachineStateChange(IVirtualBoxCallback *pThis ATTRIBUTE_UNUSED,
                                 PRUnichar *machineId, PRUint32 state)
{
    virDomainPtr dom = NULL;
    int event = 0;
    int detail = 0;

    vboxDriverLock(g_pVBoxGlobalData);

    VIR_DEBUG("IVirtualBoxCallback: %p, State: %d", pThis, state);
    DEBUGPRUnichar("machineId", machineId);

    if (machineId) {
        char *machineIdUtf8 = NULL;
        unsigned char uuid[VIR_UUID_BUFLEN];

        g_pVBoxGlobalData->pFuncs->pfnUtf16ToUtf8(machineId, &machineIdUtf8);
        ignore_value(virUUIDParse(machineIdUtf8, uuid));

        dom = vboxDomainLookupByUUID(g_pVBoxGlobalData->conn, uuid);
        if (dom) {
            virObjectEventPtr ev;

            if (state == MachineState_Starting) {
                event = VIR_DOMAIN_EVENT_STARTED;
                detail = VIR_DOMAIN_EVENT_STARTED_BOOTED;
            } else if (state == MachineState_Restoring) {
                event = VIR_DOMAIN_EVENT_STARTED;
                detail = VIR_DOMAIN_EVENT_STARTED_RESTORED;
            } else if (state == MachineState_Paused) {
                event = VIR_DOMAIN_EVENT_SUSPENDED;
                detail = VIR_DOMAIN_EVENT_SUSPENDED_PAUSED;
            } else if (state == MachineState_Running) {
                event = VIR_DOMAIN_EVENT_RESUMED;
                detail = VIR_DOMAIN_EVENT_RESUMED_UNPAUSED;
            } else if (state == MachineState_PoweredOff) {
                event = VIR_DOMAIN_EVENT_STOPPED;
                detail = VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN;
            } else if (state == MachineState_Stopping) {
                event = VIR_DOMAIN_EVENT_STOPPED;
                detail = VIR_DOMAIN_EVENT_STOPPED_DESTROYED;
            } else if (state == MachineState_Aborted) {
                event = VIR_DOMAIN_EVENT_STOPPED;
                detail = VIR_DOMAIN_EVENT_STOPPED_CRASHED;
            } else if (state == MachineState_Saving) {
                event = VIR_DOMAIN_EVENT_STOPPED;
                detail = VIR_DOMAIN_EVENT_STOPPED_SAVED;
            } else {
                event = VIR_DOMAIN_EVENT_STOPPED;
                detail = VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN;
            }

            ev = virDomainEventLifecycleNewFromDom(dom, event, detail);

            if (ev)
                virObjectEventStateQueue(g_pVBoxGlobalData->domainEvents, ev);
        }
    }

    vboxDriverUnlock(g_pVBoxGlobalData);

    return NS_OK;
}

static nsresult PR_COM_METHOD
vboxCallbackOnMachineDataChange(IVirtualBoxCallback *pThis ATTRIBUTE_UNUSED,
                                PRUnichar *machineId)
{
    VIR_DEBUG("IVirtualBoxCallback: %p", pThis);
    DEBUGPRUnichar("machineId", machineId);

    return NS_OK;
}

static nsresult PR_COM_METHOD
vboxCallbackOnExtraDataCanChange(IVirtualBoxCallback *pThis ATTRIBUTE_UNUSED,
                                 PRUnichar *machineId, PRUnichar *key,
                                 PRUnichar *value,
                                 PRUnichar **error ATTRIBUTE_UNUSED,
                                 PRBool *allowChange ATTRIBUTE_UNUSED)
{
    VIR_DEBUG("IVirtualBoxCallback: %p, allowChange: %s", pThis, *allowChange ? "true" : "false");
    DEBUGPRUnichar("machineId", machineId);
    DEBUGPRUnichar("key", key);
    DEBUGPRUnichar("value", value);

    return NS_OK;
}

static nsresult PR_COM_METHOD
vboxCallbackOnExtraDataChange(IVirtualBoxCallback *pThis ATTRIBUTE_UNUSED,
                              PRUnichar *machineId,
                              PRUnichar *key, PRUnichar *value)
{
    VIR_DEBUG("IVirtualBoxCallback: %p", pThis);
    DEBUGPRUnichar("machineId", machineId);
    DEBUGPRUnichar("key", key);
    DEBUGPRUnichar("value", value);

    return NS_OK;
}

# if VBOX_API_VERSION < 3001000
static nsresult PR_COM_METHOD
vboxCallbackOnMediaRegistered(IVirtualBoxCallback *pThis ATTRIBUTE_UNUSED,
                              PRUnichar *mediaId,
                              PRUint32 mediaType ATTRIBUTE_UNUSED,
                              PRBool registered ATTRIBUTE_UNUSED)
{
    VIR_DEBUG("IVirtualBoxCallback: %p, registered: %s", pThis, registered ? "true" : "false");
    VIR_DEBUG("mediaType: %d", mediaType);
    DEBUGPRUnichar("mediaId", mediaId);

    return NS_OK;
}
# else  /* VBOX_API_VERSION >= 3001000 */
# endif /* VBOX_API_VERSION >= 3001000 */

static nsresult PR_COM_METHOD
vboxCallbackOnMachineRegistered(IVirtualBoxCallback *pThis ATTRIBUTE_UNUSED,
                                PRUnichar *machineId, PRBool registered)
{
    virDomainPtr dom = NULL;
    int event = 0;
    int detail = 0;

    vboxDriverLock(g_pVBoxGlobalData);

    VIR_DEBUG("IVirtualBoxCallback: %p, registered: %s", pThis, registered ? "true" : "false");
    DEBUGPRUnichar("machineId", machineId);

    if (machineId) {
        char *machineIdUtf8 = NULL;
        unsigned char uuid[VIR_UUID_BUFLEN];

        g_pVBoxGlobalData->pFuncs->pfnUtf16ToUtf8(machineId, &machineIdUtf8);
        ignore_value(virUUIDParse(machineIdUtf8, uuid));

        dom = vboxDomainLookupByUUID(g_pVBoxGlobalData->conn, uuid);
        if (dom) {
            virObjectEventPtr ev;

            /* CURRENT LIMITATION: we never get the VIR_DOMAIN_EVENT_UNDEFINED
             * event because the when the machine is de-registered the call
             * to vboxDomainLookupByUUID fails and thus we don't get any
             * dom pointer which is necessary (null dom pointer doesn't work)
             * to show the VIR_DOMAIN_EVENT_UNDEFINED event
             */
            if (registered) {
                event = VIR_DOMAIN_EVENT_DEFINED;
                detail = VIR_DOMAIN_EVENT_DEFINED_ADDED;
            } else {
                event = VIR_DOMAIN_EVENT_UNDEFINED;
                detail = VIR_DOMAIN_EVENT_UNDEFINED_REMOVED;
            }

            ev = virDomainEventLifecycleNewFromDom(dom, event, detail);

            if (ev)
                virObjectEventStateQueue(g_pVBoxGlobalData->domainEvents, ev);
        }
    }

    vboxDriverUnlock(g_pVBoxGlobalData);

    return NS_OK;
}

static nsresult PR_COM_METHOD
vboxCallbackOnSessionStateChange(IVirtualBoxCallback *pThis ATTRIBUTE_UNUSED,
                                 PRUnichar *machineId,
                                 PRUint32 state ATTRIBUTE_UNUSED)
{
    VIR_DEBUG("IVirtualBoxCallback: %p, state: %d", pThis, state);
    DEBUGPRUnichar("machineId", machineId);

    return NS_OK;
}

static nsresult PR_COM_METHOD
vboxCallbackOnSnapshotTaken(IVirtualBoxCallback *pThis ATTRIBUTE_UNUSED,
                            PRUnichar *machineId,
                            PRUnichar *snapshotId)
{
    VIR_DEBUG("IVirtualBoxCallback: %p", pThis);
    DEBUGPRUnichar("machineId", machineId);
    DEBUGPRUnichar("snapshotId", snapshotId);

    return NS_OK;
}

static nsresult PR_COM_METHOD
vboxCallbackOnSnapshotDiscarded(IVirtualBoxCallback *pThis ATTRIBUTE_UNUSED,
                                PRUnichar *machineId,
                                PRUnichar *snapshotId)
{
    VIR_DEBUG("IVirtualBoxCallback: %p", pThis);
    DEBUGPRUnichar("machineId", machineId);
    DEBUGPRUnichar("snapshotId", snapshotId);

    return NS_OK;
}

static nsresult PR_COM_METHOD
vboxCallbackOnSnapshotChange(IVirtualBoxCallback *pThis ATTRIBUTE_UNUSED,
                             PRUnichar *machineId,
                             PRUnichar *snapshotId)
{
    VIR_DEBUG("IVirtualBoxCallback: %p", pThis);
    DEBUGPRUnichar("machineId", machineId);
    DEBUGPRUnichar("snapshotId", snapshotId);

    return NS_OK;
}

static nsresult PR_COM_METHOD
vboxCallbackOnGuestPropertyChange(IVirtualBoxCallback *pThis ATTRIBUTE_UNUSED,
                                  PRUnichar *machineId, PRUnichar *name,
                                  PRUnichar *value, PRUnichar *flags)
{
    VIR_DEBUG("IVirtualBoxCallback: %p", pThis);
    DEBUGPRUnichar("machineId", machineId);
    DEBUGPRUnichar("name", name);
    DEBUGPRUnichar("value", value);
    DEBUGPRUnichar("flags", flags);

    return NS_OK;
}

static nsresult PR_COM_METHOD
vboxCallbackAddRef(nsISupports *pThis ATTRIBUTE_UNUSED)
{
    nsresult c;

    c = ++g_pVBoxGlobalData->vboxCallBackRefCount;

    VIR_DEBUG("pThis: %p, vboxCallback AddRef: %d", pThis, c);

    return c;
}

static nsresult PR_COM_METHOD
vboxCallbackRelease(nsISupports *pThis)
{
    nsresult c;

    c = --g_pVBoxGlobalData->vboxCallBackRefCount;
    if (c == 0) {
        /* delete object */
        VIR_FREE(pThis->vtbl);
        VIR_FREE(pThis);
    }

    VIR_DEBUG("pThis: %p, vboxCallback Release: %d", pThis, c);

    return c;
}

static nsresult PR_COM_METHOD
vboxCallbackQueryInterface(nsISupports *pThis, const nsID *iid, void **resultp)
{
    IVirtualBoxCallback *that = (IVirtualBoxCallback *)pThis;
    static const nsID ivirtualboxCallbackUUID = IVIRTUALBOXCALLBACK_IID;
    static const nsID isupportIID = NS_ISUPPORTS_IID;

    /* Match UUID for IVirtualBoxCallback class */
    if (memcmp(iid, &ivirtualboxCallbackUUID, sizeof(nsID)) == 0 ||
        memcmp(iid, &isupportIID, sizeof(nsID)) == 0) {
        g_pVBoxGlobalData->vboxCallBackRefCount++;
        *resultp = that;

        VIR_DEBUG("pThis: %p, vboxCallback QueryInterface: %d", pThis, g_pVBoxGlobalData->vboxCallBackRefCount);

        return NS_OK;
    }


    VIR_DEBUG("pThis: %p, vboxCallback QueryInterface didn't find a matching interface", pThis);
    DEBUGUUID("The UUID Callback Interface expects", iid);
    DEBUGUUID("The UUID Callback Interface got", &ivirtualboxCallbackUUID);
    return NS_NOINTERFACE;
}


static IVirtualBoxCallback *vboxAllocCallbackObj(void) {
    IVirtualBoxCallback *vboxCallback = NULL;

    /* Allocate, Initialize and return a valid
     * IVirtualBoxCallback object here
     */
    if ((VIR_ALLOC(vboxCallback) < 0) || (VIR_ALLOC(vboxCallback->vtbl) < 0)) {
        VIR_FREE(vboxCallback);
        return NULL;
    }

    {
        vboxCallback->vtbl->nsisupports.AddRef          = &vboxCallbackAddRef;
        vboxCallback->vtbl->nsisupports.Release         = &vboxCallbackRelease;
        vboxCallback->vtbl->nsisupports.QueryInterface  = &vboxCallbackQueryInterface;
        vboxCallback->vtbl->OnMachineStateChange        = &vboxCallbackOnMachineStateChange;
        vboxCallback->vtbl->OnMachineDataChange         = &vboxCallbackOnMachineDataChange;
        vboxCallback->vtbl->OnExtraDataCanChange        = &vboxCallbackOnExtraDataCanChange;
        vboxCallback->vtbl->OnExtraDataChange           = &vboxCallbackOnExtraDataChange;
# if VBOX_API_VERSION < 3001000
        vboxCallback->vtbl->OnMediaRegistered           = &vboxCallbackOnMediaRegistered;
# else  /* VBOX_API_VERSION >= 3001000 */
# endif /* VBOX_API_VERSION >= 3001000 */
        vboxCallback->vtbl->OnMachineRegistered         = &vboxCallbackOnMachineRegistered;
        vboxCallback->vtbl->OnSessionStateChange        = &vboxCallbackOnSessionStateChange;
        vboxCallback->vtbl->OnSnapshotTaken             = &vboxCallbackOnSnapshotTaken;
# if VBOX_API_VERSION < 3002000
        vboxCallback->vtbl->OnSnapshotDiscarded         = &vboxCallbackOnSnapshotDiscarded;
# else /* VBOX_API_VERSION >= 3002000 */
        vboxCallback->vtbl->OnSnapshotDeleted           = &vboxCallbackOnSnapshotDiscarded;
# endif /* VBOX_API_VERSION >= 3002000 */
        vboxCallback->vtbl->OnSnapshotChange            = &vboxCallbackOnSnapshotChange;
        vboxCallback->vtbl->OnGuestPropertyChange       = &vboxCallbackOnGuestPropertyChange;
        g_pVBoxGlobalData->vboxCallBackRefCount = 1;

    }

    return vboxCallback;
}

static void vboxReadCallback(int watch ATTRIBUTE_UNUSED,
                             int fd,
                             int events ATTRIBUTE_UNUSED,
                             void *opaque ATTRIBUTE_UNUSED)
{
    if (fd >= 0) {
        g_pVBoxGlobalData->vboxQueue->vtbl->ProcessPendingEvents(g_pVBoxGlobalData->vboxQueue);
    } else {
        nsresult rc;
        PLEvent *pEvent = NULL;

        rc = g_pVBoxGlobalData->vboxQueue->vtbl->WaitForEvent(g_pVBoxGlobalData->vboxQueue, &pEvent);
        if (NS_SUCCEEDED(rc))
            g_pVBoxGlobalData->vboxQueue->vtbl->HandleEvent(g_pVBoxGlobalData->vboxQueue, pEvent);
    }
}

static int
vboxConnectDomainEventRegister(virConnectPtr conn,
                               virConnectDomainEventCallback callback,
                               void *opaque,
                               virFreeCallback freecb)
{
    vboxGlobalData *data = conn->privateData;
    int vboxRet = -1;
    nsresult rc;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    /* Locking has to be there as callbacks are not
     * really fully thread safe
     */
    vboxDriverLock(data);

    if (data->vboxCallback == NULL) {
        data->vboxCallback = vboxAllocCallbackObj();
        if (data->vboxCallback != NULL) {
            rc = data->vboxObj->vtbl->RegisterCallback(data->vboxObj, data->vboxCallback);
            if (NS_SUCCEEDED(rc))
                vboxRet = 0;
        }
    } else {
        vboxRet = 0;
    }

    /* Get the vbox file handle and add a event handle to it
     * so that the events can be passed down to the user
     */
    if (vboxRet == 0) {
        if (data->fdWatch < 0) {
            PRInt32 vboxFileHandle;
            vboxFileHandle = data->vboxQueue->vtbl->GetEventQueueSelectFD(data->vboxQueue);

            data->fdWatch = virEventAddHandle(vboxFileHandle, VIR_EVENT_HANDLE_READABLE, vboxReadCallback, NULL, NULL);
        }

        if (data->fdWatch >= 0) {
            /* Once a callback is registered with virtualbox, use a list
             * to store the callbacks registered with libvirt so that
             * later you can iterate over them
             */

            ret = virDomainEventStateRegister(conn, data->domainEvents,
                                              callback, opaque, freecb);
            VIR_DEBUG("virObjectEventStateRegister (ret = %d) (conn: %p, "
                      "callback: %p, opaque: %p, "
                      "freecb: %p)", ret, conn, callback,
                      opaque, freecb);
        }
    }

    vboxDriverUnlock(data);

    if (ret >= 0) {
        return 0;
    } else {
        if (data->vboxObj && data->vboxCallback)
            data->vboxObj->vtbl->UnregisterCallback(data->vboxObj, data->vboxCallback);
        return -1;
    }
}

static int
vboxConnectDomainEventDeregister(virConnectPtr conn,
                                 virConnectDomainEventCallback callback)
{
    vboxGlobalData *data = conn->privateData;
    int cnt;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    /* Locking has to be there as callbacks are not
     * really fully thread safe
     */
    vboxDriverLock(data);

    cnt = virDomainEventStateDeregister(conn, data->domainEvents,
                                        callback);

    if (data->vboxCallback && cnt == 0) {
        data->vboxObj->vtbl->UnregisterCallback(data->vboxObj, data->vboxCallback);
        VBOX_RELEASE(data->vboxCallback);

        /* Remove the Event file handle on which we are listening as well */
        virEventRemoveHandle(data->fdWatch);
        data->fdWatch = -1;
    }

    vboxDriverUnlock(data);

    if (cnt >= 0)
        ret = 0;

    return ret;
}

static int vboxConnectDomainEventRegisterAny(virConnectPtr conn,
                                             virDomainPtr dom,
                                             int eventID,
                                             virConnectDomainEventGenericCallback callback,
                                             void *opaque,
                                             virFreeCallback freecb)
{
    vboxGlobalData *data = conn->privateData;
    int vboxRet = -1;
    nsresult rc;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    /* Locking has to be there as callbacks are not
     * really fully thread safe
     */
    vboxDriverLock(data);

    if (data->vboxCallback == NULL) {
        data->vboxCallback = vboxAllocCallbackObj();
        if (data->vboxCallback != NULL) {
            rc = data->vboxObj->vtbl->RegisterCallback(data->vboxObj, data->vboxCallback);
            if (NS_SUCCEEDED(rc))
                vboxRet = 0;
        }
    } else {
        vboxRet = 0;
    }

    /* Get the vbox file handle and add a event handle to it
     * so that the events can be passed down to the user
     */
    if (vboxRet == 0) {
        if (data->fdWatch < 0) {
            PRInt32 vboxFileHandle;
            vboxFileHandle = data->vboxQueue->vtbl->GetEventQueueSelectFD(data->vboxQueue);

            data->fdWatch = virEventAddHandle(vboxFileHandle, VIR_EVENT_HANDLE_READABLE, vboxReadCallback, NULL, NULL);
        }

        if (data->fdWatch >= 0) {
            /* Once a callback is registered with virtualbox, use a list
             * to store the callbacks registered with libvirt so that
             * later you can iterate over them
             */

            if (virDomainEventStateRegisterID(conn, data->domainEvents,
                                              dom, eventID,
                                              callback, opaque, freecb, &ret) < 0)
                ret = -1;
            VIR_DEBUG("virDomainEventStateRegisterID (ret = %d) (conn: %p, "
                      "callback: %p, opaque: %p, "
                      "freecb: %p)", ret, conn, callback,
                      opaque, freecb);
        }
    }

    vboxDriverUnlock(data);

    if (ret >= 0) {
        return ret;
    } else {
        if (data->vboxObj && data->vboxCallback)
            data->vboxObj->vtbl->UnregisterCallback(data->vboxObj, data->vboxCallback);
        return -1;
    }
}

static int
vboxConnectDomainEventDeregisterAny(virConnectPtr conn,
                                    int callbackID)
{
    vboxGlobalData *data = conn->privateData;
    int cnt;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    /* Locking has to be there as callbacks are not
     * really fully thread safe
     */
    vboxDriverLock(data);

    cnt = virObjectEventStateDeregisterID(conn, data->domainEvents,
                                          callbackID);

    if (data->vboxCallback && cnt == 0) {
        data->vboxObj->vtbl->UnregisterCallback(data->vboxObj, data->vboxCallback);
        VBOX_RELEASE(data->vboxCallback);

        /* Remove the Event file handle on which we are listening as well */
        virEventRemoveHandle(data->fdWatch);
        data->fdWatch = -1;
    }

    vboxDriverUnlock(data);

    if (cnt >= 0)
        ret = 0;

    return ret;
}

static void
_registerDomainEvent(virHypervisorDriverPtr driver)
{
    driver->connectDomainEventRegister = vboxConnectDomainEventRegister; /* 0.7.0 */
    driver->connectDomainEventDeregister = vboxConnectDomainEventDeregister; /* 0.7.0 */
    driver->connectDomainEventRegisterAny = vboxConnectDomainEventRegisterAny; /* 0.8.0 */
    driver->connectDomainEventDeregisterAny = vboxConnectDomainEventDeregisterAny; /* 0.8.0 */
}

#endif /* !(VBOX_API_VERSION == 2002000 || VBOX_API_VERSION >= 4000000) */

static int _pfnInitialize(vboxGlobalData *data)
{
    data->pFuncs = g_pfnGetFunctions(VBOX_XPCOMC_VERSION);
    if (data->pFuncs == NULL)
        return -1;
#if VBOX_XPCOMC_VERSION == 0x00010000U
    data->pFuncs->pfnComInitialize(&data->vboxObj, &data->vboxSession);
#else  /* !(VBOX_XPCOMC_VERSION == 0x00010000U) */
    data->pFuncs->pfnComInitialize(IVIRTUALBOX_IID_STR, &data->vboxObj, ISESSION_IID_STR, &data->vboxSession);
#endif /* !(VBOX_XPCOMC_VERSION == 0x00010000U) */
    return 0;
}

static int
_initializeDomainEvent(vboxGlobalData *data ATTRIBUTE_UNUSED)
{
#if VBOX_API_VERSION <= 2002000 || VBOX_API_VERSION >= 4000000
    /* No event queue functionality in 2.2.* and 4.* as of now */
    vboxUnsupported();
#else /* VBOX_API_VERSION > 2002000 || VBOX_API_VERSION < 4000000 */
    /* Initialize the fWatch needed for Event Callbacks */
    data->fdWatch = -1;
    data->pFuncs->pfnGetEventQueue(&data->vboxQueue);
    if (data->vboxQueue == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("nsIEventQueue object is null"));
        return -1;
    }
#endif /* VBOX_API_VERSION > 2002000 || VBOX_API_VERSION < 4000000 */
    return 0;
}

static
void _registerGlobalData(vboxGlobalData *data ATTRIBUTE_UNUSED)
{
#if VBOX_API_VERSION == 2002000
    vboxUnsupported();
#else /* VBOX_API_VERSION != 2002000 */
    g_pVBoxGlobalData = data;
#endif /* VBOX_API_VERSION != 2002000 */
}

#if VBOX_API_VERSION < 4000000

# if VBOX_API_VERSION < 3001000
static void
_detachDevices(vboxGlobalData *data ATTRIBUTE_UNUSED,
               IMachine *machine, PRUnichar *hddcnameUtf16)
{
    /* Disconnect all the drives if present */
    machine->vtbl->DetachHardDisk(machine, hddcnameUtf16, 0, 0);
    machine->vtbl->DetachHardDisk(machine, hddcnameUtf16, 0, 1);
    machine->vtbl->DetachHardDisk(machine, hddcnameUtf16, 1, 1);
}
# else  /* VBOX_API_VERSION >= 3001000 */
static void
_detachDevices(vboxGlobalData *data, IMachine *machine,
               PRUnichar *hddcnameUtf16 ATTRIBUTE_UNUSED)
{
    /* get all the controller first, then the attachments and
    * remove them all so that the machine can be undefined
    */
   vboxArray storageControllers = VBOX_ARRAY_INITIALIZER;
   size_t i = 0, j = 0;

   vboxArrayGet(&storageControllers, machine,
                machine->vtbl->GetStorageControllers);

   for (i = 0; i < storageControllers.count; i++) {
       IStorageController *strCtl = storageControllers.items[i];
       PRUnichar *strCtlName = NULL;
       vboxArray mediumAttachments = VBOX_ARRAY_INITIALIZER;

       if (!strCtl)
           continue;

       strCtl->vtbl->GetName(strCtl, &strCtlName);
       vboxArrayGetWithPtrArg(&mediumAttachments, machine,
                              machine->vtbl->GetMediumAttachmentsOfController,
                              strCtlName);

       for (j = 0; j < mediumAttachments.count; j++) {
           IMediumAttachment *medAtt = mediumAttachments.items[j];
           PRInt32 port = ~0U;
           PRInt32 device = ~0U;

           if (!medAtt)
               continue;

           medAtt->vtbl->GetPort(medAtt, &port);
           medAtt->vtbl->GetDevice(medAtt, &device);

           if ((port != ~0U) && (device != ~0U)) {
               machine->vtbl->DetachDevice(machine,
                                           strCtlName,
                                           port,
                                           device);
           }
       }
       vboxArrayRelease(&storageControllers);
       machine->vtbl->RemoveStorageController(machine, strCtlName);
       VBOX_UTF16_FREE(strCtlName);
   }
   vboxArrayRelease(&storageControllers);
}
# endif /* VBOX_API_VERSION >= 3001000 */

static nsresult
_unregisterMachine(vboxGlobalData *data, vboxIIDUnion *iidu, IMachine **machine)
{
    return data->vboxObj->vtbl->UnregisterMachine(data->vboxObj, IID_MEMBER(value), machine);
}

static void
_deleteConfig(IMachine *machine)
{
    machine->vtbl->DeleteSettings(machine);
}

#else /* VBOX_API_VERSION >= 4000000 */

static void
_detachDevices(vboxGlobalData *data ATTRIBUTE_UNUSED,
               IMachine *machine ATTRIBUTE_UNUSED,
               PRUnichar *hddcnameUtf16 ATTRIBUTE_UNUSED)
{
    vboxUnsupported();
}

static nsresult
_unregisterMachine(vboxGlobalData *data, vboxIIDUnion *iidu, IMachine **machine)
{
    nsresult rc;
    vboxArray media = VBOX_ARRAY_INITIALIZER;
    rc = data->vboxObj->vtbl->FindMachine(data->vboxObj, IID_MEMBER(value), machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        return rc;
    }

    /* We're not interested in the array returned by the Unregister method,
     * but in the side effect of unregistering the virtual machine. In order
     * to call the Unregister method correctly we need to use the vboxArray
     * wrapper here. */
    rc = vboxArrayGetWithUintArg(&media, *machine, (*machine)->vtbl->Unregister,
                                 CleanupMode_DetachAllReturnNone);
    vboxArrayUnalloc(&media);
    return rc;
}

static void
_deleteConfig(IMachine *machine)
{
    IProgress *progress = NULL;

    /* The IMachine Delete method takes an array of IMedium items to be
     * deleted along with the virtual machine. We just want to pass an
     * empty array. But instead of adding a full vboxArraySetWithReturn to
     * the glue layer (in order to handle the required signature of the
     * Delete method) we use a local solution here. */
# ifdef WIN32
    SAFEARRAY *safeArray = NULL;
    typedef HRESULT __stdcall (*IMachine_Delete)(IMachine *self,
                                                 SAFEARRAY **media,
                                                 IProgress **progress);

#  if VBOX_API_VERSION < 4003000
    ((IMachine_Delete)machine->vtbl->Delete)(machine, &safeArray, &progress);
#  else
    ((IMachine_Delete)machine->vtbl->DeleteConfig)(machine, &safeArray, &progress);
#  endif
# else
    /* XPCOM doesn't like NULL as an array, even when the array size is 0.
     * Instead pass it a dummy array to avoid passing NULL. */
    IMedium *array[] = { NULL };
#  if VBOX_API_VERSION < 4003000
    machine->vtbl->Delete(machine, 0, array, &progress);
#  else
    machine->vtbl->DeleteConfig(machine, 0, array, &progress);
#  endif
# endif
    if (progress != NULL) {
        progress->vtbl->WaitForCompletion(progress, -1);
        VBOX_RELEASE(progress);
    }
}

#endif /* VBOX_API_VERSION >= 4000000 */

#if VBOX_API_VERSION < 3001000

static void
_dumpIDEHDDsOld(virDomainDefPtr def,
                vboxGlobalData *data,
                IMachine *machine)
{
    PRInt32 hddNum = 0;
    IHardDisk *hardDiskPM = NULL;
    IHardDisk *hardDiskPS = NULL;
    IHardDisk *hardDiskSS = NULL;
    const char *hddBus = "IDE";
    PRUnichar *hddBusUtf16 = NULL;

    /* dump IDE hdds if present */
    VBOX_UTF8_TO_UTF16(hddBus, &hddBusUtf16);

    def->ndisks = 0;
    machine->vtbl->GetHardDisk(machine, hddBusUtf16, 0, 0, &hardDiskPM);
    if (hardDiskPM)
        def->ndisks++;

    machine->vtbl->GetHardDisk(machine, hddBusUtf16, 0, 1, &hardDiskPS);
    if (hardDiskPS)
        def->ndisks++;

    machine->vtbl->GetHardDisk(machine, hddBusUtf16, 1, 1, &hardDiskSS);
    if (hardDiskSS)
        def->ndisks++;

    VBOX_UTF16_FREE(hddBusUtf16);

    if ((def->ndisks > 0) && (VIR_ALLOC_N(def->disks, def->ndisks) >= 0)) {
        size_t i;
        for (i = 0; i < def->ndisks; i++) {
            if ((def->disks[i] = virDomainDiskDefNew(NULL))) {
                def->disks[i]->device = VIR_DOMAIN_DISK_DEVICE_DISK;
                def->disks[i]->bus = VIR_DOMAIN_DISK_BUS_IDE;
                virDomainDiskSetType(def->disks[i],
                                     VIR_STORAGE_TYPE_FILE);
            }
        }
    }

    if (hardDiskPM) {
        PRUnichar *hddlocationUtf16 = NULL;
        char *hddlocation = NULL;
        PRUint32 hddType = HardDiskType_Normal;

        hardDiskPM->vtbl->imedium.GetLocation((IMedium *)hardDiskPM, &hddlocationUtf16);
        VBOX_UTF16_TO_UTF8(hddlocationUtf16, &hddlocation);

        hardDiskPM->vtbl->GetType(hardDiskPM, &hddType);

        if (hddType == HardDiskType_Immutable)
            def->disks[hddNum]->src->readonly = true;
        ignore_value(virDomainDiskSetSource(def->disks[hddNum],
                                            hddlocation));
        ignore_value(VIR_STRDUP(def->disks[hddNum]->dst, "hda"));
        hddNum++;

        VBOX_UTF8_FREE(hddlocation);
        VBOX_UTF16_FREE(hddlocationUtf16);
        VBOX_MEDIUM_RELEASE(hardDiskPM);
    }

    if (hardDiskPS) {
        PRUnichar *hddlocationUtf16 = NULL;
        char *hddlocation = NULL;
        PRUint32 hddType = HardDiskType_Normal;

        hardDiskPS->vtbl->imedium.GetLocation((IMedium *)hardDiskPS, &hddlocationUtf16);
        VBOX_UTF16_TO_UTF8(hddlocationUtf16, &hddlocation);

        hardDiskPS->vtbl->GetType(hardDiskPS, &hddType);

        if (hddType == HardDiskType_Immutable)
            def->disks[hddNum]->src->readonly = true;
        ignore_value(virDomainDiskSetSource(def->disks[hddNum],
                                            hddlocation));
        ignore_value(VIR_STRDUP(def->disks[hddNum]->dst, "hdb"));
        hddNum++;

        VBOX_UTF8_FREE(hddlocation);
        VBOX_UTF16_FREE(hddlocationUtf16);
        VBOX_MEDIUM_RELEASE(hardDiskPS);
    }

    if (hardDiskSS) {
        PRUnichar *hddlocationUtf16 = NULL;
        char *hddlocation = NULL;
        PRUint32 hddType = HardDiskType_Normal;

        hardDiskSS->vtbl->imedium.GetLocation((IMedium *)hardDiskSS, &hddlocationUtf16);
        VBOX_UTF16_TO_UTF8(hddlocationUtf16, &hddlocation);

        hardDiskSS->vtbl->GetType(hardDiskSS, &hddType);

        if (hddType == HardDiskType_Immutable)
            def->disks[hddNum]->src->readonly = true;
        ignore_value(virDomainDiskSetSource(def->disks[hddNum],
                                            hddlocation));
        ignore_value(VIR_STRDUP(def->disks[hddNum]->dst, "hdd"));
        hddNum++;

        VBOX_UTF8_FREE(hddlocation);
        VBOX_UTF16_FREE(hddlocationUtf16);
        VBOX_MEDIUM_RELEASE(hardDiskSS);
    }
}

static void
_dumpDVD(virDomainDefPtr def,
         vboxGlobalData *data,
         IMachine *machine)
{
    IDVDDrive *dvdDrive = NULL;
    IDVDImage *dvdImage = NULL;
    PRUnichar *locationUtf16 = NULL;
    char *location = NULL;


    /* dump CDROM/DVD if the drive is attached and has DVD/CD in it */
    machine->vtbl->GetDVDDrive(machine, &dvdDrive);
    if (!dvdDrive)
        return;

    PRUint32 state = DriveState_Null;

    dvdDrive->vtbl->GetState(dvdDrive, &state);
    if (state != DriveState_ImageMounted)
        goto cleanupDVDDrive;


    dvdDrive->vtbl->GetImage(dvdDrive, &dvdImage);
    if (!dvdImage)
        goto cleanupDVDDrive;

    dvdImage->vtbl->imedium.GetLocation((IMedium *)dvdImage, &locationUtf16);
    VBOX_UTF16_TO_UTF8(locationUtf16, &location);

    def->ndisks++;
    if (VIR_REALLOC_N(def->disks, def->ndisks) >= 0) {
        if ((def->disks[def->ndisks - 1] = virDomainDiskDefNew(NULL))) {
            def->disks[def->ndisks - 1]->device = VIR_DOMAIN_DISK_DEVICE_CDROM;
            def->disks[def->ndisks - 1]->bus = VIR_DOMAIN_DISK_BUS_IDE;
            virDomainDiskSetType(def->disks[def->ndisks - 1],
                                 VIR_STORAGE_TYPE_FILE);
            def->disks[def->ndisks - 1]->src->readonly = true;
            ignore_value(virDomainDiskSetSource(def->disks[def->ndisks - 1], location));
            ignore_value(VIR_STRDUP(def->disks[def->ndisks - 1]->dst, "hdc"));
            def->ndisks--;
        } else {
            def->ndisks--;
        }
    } else {
        def->ndisks--;
    }

    VBOX_UTF8_FREE(location);
    VBOX_UTF16_FREE(locationUtf16);
    VBOX_MEDIUM_RELEASE(dvdImage);

 cleanupDVDDrive:
    VBOX_RELEASE(dvdDrive);
}

static int
_attachDVD(vboxGlobalData *data, IMachine *machine, const char *src)
{
    IDVDDrive *dvdDrive = NULL;
    IDVDImage *dvdImage = NULL;
    PRUnichar *dvdfileUtf16 = NULL;
    vboxIID dvduuid = VBOX_IID_INITIALIZER;
    vboxIID dvdemptyuuid = VBOX_IID_INITIALIZER;
    nsresult rc;
    int ret = -1;

    /* Currently CDROM/DVD Drive is always IDE
     * Secondary Master so neglecting the following
     * parameter dev->data.disk->bus
     */
    machine->vtbl->GetDVDDrive(machine, &dvdDrive);
    if (!dvdDrive)
        return ret;

    VBOX_UTF8_TO_UTF16(src, &dvdfileUtf16);

    data->vboxObj->vtbl->FindDVDImage(data->vboxObj, dvdfileUtf16, &dvdImage);
    if (!dvdImage)
        data->vboxObj->vtbl->OpenDVDImage(data->vboxObj, dvdfileUtf16, dvdemptyuuid.value, &dvdImage);

    if (!dvdImage)
        goto cleanup;

    rc = dvdImage->vtbl->imedium.GetId((IMedium *)dvdImage, &dvduuid.value);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("can't get the uuid of the file to "
                         "be attached to cdrom: %s, rc=%08x"),
                       src, (unsigned)rc);
    } else {
        /* unmount the previous mounted image */
        dvdDrive->vtbl->Unmount(dvdDrive);
        rc = dvdDrive->vtbl->MountImage(dvdDrive, dvduuid.value);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("could not attach the file to cdrom: %s, rc=%08x"),
                           src, (unsigned)rc);
        } else {
            ret = 0;
            DEBUGIID("CD/DVD Image UUID:", dvduuid.value);
        }
    }

    VBOX_MEDIUM_RELEASE(dvdImage);
 cleanup:
    vboxIIDUnalloc(&dvduuid);
    VBOX_UTF16_FREE(dvdfileUtf16);
    VBOX_RELEASE(dvdDrive);
    return ret;
}

static int
_detachDVD(IMachine *machine)
{
    IDVDDrive *dvdDrive = NULL;
    int ret = -1;
    nsresult rc;
    /* Currently CDROM/DVD Drive is always IDE
     * Secondary Master so neglecting the following
     * parameter dev->data.disk->bus
     */
    machine->vtbl->GetDVDDrive(machine, &dvdDrive);
    if (!dvdDrive)
        return ret;

    rc = dvdDrive->vtbl->Unmount(dvdDrive);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not de-attach the mounted ISO, rc=%08x"),
                       (unsigned)rc);
    } else {
        ret = 0;
    }
    VBOX_RELEASE(dvdDrive);

    return ret;
}

static void
_dumpFloppy(virDomainDefPtr def,
            vboxGlobalData *data,
            IMachine *machine)
{
    IFloppyDrive *floppyDrive = NULL;
    IFloppyImage *floppyImage = NULL;
    PRUnichar *locationUtf16 = NULL;
    char *location = NULL;
    PRBool enabled = PR_FALSE;
    PRUint32 state = DriveState_Null;

    /* dump Floppy if the drive is attached and has floppy in it */
    machine->vtbl->GetFloppyDrive(machine, &floppyDrive);
    if (!floppyDrive)
        return;

    floppyDrive->vtbl->GetEnabled(floppyDrive, &enabled);
    if (!enabled)
        goto cleanupFloppyDrive;


    floppyDrive->vtbl->GetState(floppyDrive, &state);
    if (state != DriveState_ImageMounted)
        goto cleanupFloppyDrive;

    floppyDrive->vtbl->GetImage(floppyDrive, &floppyImage);
    if (!floppyImage)
        goto cleanupFloppyDrive;

    floppyImage->vtbl->imedium.GetLocation((IMedium *)floppyImage, &locationUtf16);
    VBOX_UTF16_TO_UTF8(locationUtf16, &location);

    def->ndisks++;
    if (VIR_REALLOC_N(def->disks, def->ndisks) >= 0) {
        if ((def->disks[def->ndisks - 1] = virDomainDiskDefNew(NULL))) {
            def->disks[def->ndisks - 1]->device = VIR_DOMAIN_DISK_DEVICE_FLOPPY;
            def->disks[def->ndisks - 1]->bus = VIR_DOMAIN_DISK_BUS_FDC;
            virDomainDiskSetType(def->disks[def->ndisks - 1],
                                 VIR_STORAGE_TYPE_FILE);
            def->disks[def->ndisks - 1]->src->readonly = false;
            ignore_value(virDomainDiskSetSource(def->disks[def->ndisks - 1], location));
            ignore_value(VIR_STRDUP(def->disks[def->ndisks - 1]->dst, "fda"));
            def->ndisks--;
        } else {
            def->ndisks--;
        }
    } else {
        def->ndisks--;
    }

    VBOX_UTF8_FREE(location);
    VBOX_UTF16_FREE(locationUtf16);
    VBOX_MEDIUM_RELEASE(floppyImage);

 cleanupFloppyDrive:
    VBOX_RELEASE(floppyDrive);
}

static int
_attachFloppy(vboxGlobalData *data, IMachine *machine, const char *src)
{
    IFloppyDrive *floppyDrive;
    IFloppyImage *floppyImage = NULL;
    PRUnichar *fdfileUtf16 = NULL;
    vboxIID fduuid = VBOX_IID_INITIALIZER;
    vboxIID fdemptyuuid = VBOX_IID_INITIALIZER;
    nsresult rc;
    int ret = -1;

    machine->vtbl->GetFloppyDrive(machine, &floppyDrive);
    if (!floppyDrive)
        return ret;

    rc = floppyDrive->vtbl->SetEnabled(floppyDrive, 1);
    if (NS_FAILED(rc))
        goto cleanup;

    VBOX_UTF8_TO_UTF16(src, &fdfileUtf16);
    rc = data->vboxObj->vtbl->FindFloppyImage(data->vboxObj,
                                              fdfileUtf16,
                                              &floppyImage);

    if (!floppyImage) {
        data->vboxObj->vtbl->OpenFloppyImage(data->vboxObj,
                                             fdfileUtf16,
                                             fdemptyuuid.value,
                                             &floppyImage);
    }

    if (floppyImage) {
        rc = floppyImage->vtbl->imedium.GetId((IMedium *)floppyImage, &fduuid.value);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("can't get the uuid of the file to be "
                             "attached to floppy drive: %s, rc=%08x"),
                           src, (unsigned)rc);
        } else {
            rc = floppyDrive->vtbl->MountImage(floppyDrive, fduuid.value);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("could not attach the file to floppy drive: %s, rc=%08x"),
                               src, (unsigned)rc);
            } else {
                ret = 0;
                DEBUGIID("attached floppy, UUID:", fduuid.value);
            }
        }
        VBOX_MEDIUM_RELEASE(floppyImage);
    }
    vboxIIDUnalloc(&fduuid);
    VBOX_UTF16_FREE(fdfileUtf16);

 cleanup:
    VBOX_RELEASE(floppyDrive);
    return ret;
}

static int
_detachFloppy(IMachine *machine)
{
    IFloppyDrive *floppyDrive;
    int ret = -1;
    nsresult rc;

    machine->vtbl->GetFloppyDrive(machine, &floppyDrive);
    if (!floppyDrive)
        return ret;

    PRBool enabled = PR_FALSE;

    floppyDrive->vtbl->GetEnabled(floppyDrive, &enabled);
    if (enabled) {
        rc = floppyDrive->vtbl->Unmount(floppyDrive);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("could not attach the file "
                             "to floppy drive, rc=%08x"),
                           (unsigned)rc);
        } else {
            ret = 0;
        }
    } else {
        /* If you are here means floppy drive is already unmounted
         * so don't flag error, just say everything is fine and quit
         */
        ret = 0;
    }
    VBOX_RELEASE(floppyDrive);

    return ret;
}

#else  /* VBOX_API_VERSION >= 3001000 */

static void
_dumpIDEHDDsOld(virDomainDefPtr def ATTRIBUTE_UNUSED,
                vboxGlobalData *data ATTRIBUTE_UNUSED,
                IMachine *machine ATTRIBUTE_UNUSED)
{
    vboxUnsupported();
}

static void
_dumpDVD(virDomainDefPtr def ATTRIBUTE_UNUSED,
         vboxGlobalData *data ATTRIBUTE_UNUSED,
         IMachine *machine ATTRIBUTE_UNUSED)
{
    vboxUnsupported();
}

static int
_attachDVD(vboxGlobalData *data ATTRIBUTE_UNUSED,
           IMachine *machine ATTRIBUTE_UNUSED,
           const char *src ATTRIBUTE_UNUSED)
{
    vboxUnsupported();
    return 0;
}

static int
_detachDVD(IMachine *machine ATTRIBUTE_UNUSED)
{
    vboxUnsupported();
    return 0;
}

static void
_dumpFloppy(virDomainDefPtr def ATTRIBUTE_UNUSED,
            vboxGlobalData *data ATTRIBUTE_UNUSED,
            IMachine *machine ATTRIBUTE_UNUSED)
{
    vboxUnsupported();
}

static int
_attachFloppy(vboxGlobalData *data ATTRIBUTE_UNUSED,
              IMachine *machine ATTRIBUTE_UNUSED,
              const char *src ATTRIBUTE_UNUSED)
{
    vboxUnsupported();
    return 0;
}

static int
_detachFloppy(IMachine *machine ATTRIBUTE_UNUSED)
{
    vboxUnsupported();
    return 0;
}

#endif  /* VBOX_API_VERSION >= 3001000 */

static void _pfnUninitialize(vboxGlobalData *data)
{
    if (data->pFuncs)
        data->pFuncs->pfnComUninitialize();
}

static void _pfnComUnallocMem(PCVBOXXPCOM pFuncs, void *pv)
{
    pFuncs->pfnComUnallocMem(pv);
}

static void _pfnUtf16Free(PCVBOXXPCOM pFuncs, PRUnichar *pwszString)
{
    pFuncs->pfnUtf16Free(pwszString);
}

static void _pfnUtf8Free(PCVBOXXPCOM pFuncs, char *pszString)
{
    pFuncs->pfnUtf8Free(pszString);
}

static int _pfnUtf16ToUtf8(PCVBOXXPCOM pFuncs, const PRUnichar *pwszString, char **ppszString)
{
    return pFuncs->pfnUtf16ToUtf8(pwszString, ppszString);
}

static int _pfnUtf8ToUtf16(PCVBOXXPCOM pFuncs, const char *pszString, PRUnichar **ppwszString)
{
    return pFuncs->pfnUtf8ToUtf16(pszString, ppwszString);
}

#if VBOX_API_VERSION == 2002000

static void _vboxIIDInitialize(vboxIIDUnion *iidu)
{
    memset(iidu, 0, sizeof(vboxIIDUnion));
}

static void _DEBUGIID(const char *msg, vboxIIDUnion *iidu)
{
# ifdef WIN32
    DEBUGUUID(msg, (nsID *)&IID_MEMBER(value));
# else /* !WIN32 */
    DEBUGUUID(msg, IID_MEMBER(value));
# endif /* !WIN32 */
}

#else /* VBOX_API_VERSION != 2002000 */

static void _vboxIIDInitialize(vboxIIDUnion *iidu)
{
    memset(iidu, 0, sizeof(vboxIIDUnion));
    IID_MEMBER(owner) = true;
}

static void _DEBUGIID(const char *msg, vboxIIDUnion *iidu)
{
    DEBUGPRUnichar(msg, IID_MEMBER(value));
}

#endif /* VBOX_API_VERSION != 2002000 */

static void
_vboxIIDToUtf8(vboxGlobalData *data ATTRIBUTE_UNUSED,
               vboxIIDUnion *iidu ATTRIBUTE_UNUSED,
               char **utf8 ATTRIBUTE_UNUSED)
{
#if VBOX_API_VERSION == 2002000
    vboxUnsupported();
#else /* !(VBOX_API_VERSION == 2002000) */
    data->pFuncs->pfnUtf16ToUtf8(IID_MEMBER(value), utf8);
#endif /* !(VBOX_API_VERSION == 2002000) */
}

static nsresult
_vboxArrayGetWithIIDArg(vboxArray *array, void *self, void *getter, vboxIIDUnion *iidu)
{
    return vboxArrayGetWithPtrArg(array, self, getter, IID_MEMBER(value));
}

static void* _handleGetMachines(IVirtualBox *vboxObj)
{
    return vboxObj->vtbl->GetMachines;
}

static void* _handleGetHardDisks(IVirtualBox *vboxObj)
{
    return vboxObj->vtbl->GetHardDisks;
}

static void* _handleUSBGetDeviceFilters(IUSBCommon *USBCommon)
{
    return USBCommon->vtbl->GetDeviceFilters;
}

static void* _handleMachineGetMediumAttachments(IMachine *machine)
{
#if VBOX_API_VERSION < 3001000
    return machine->vtbl->GetHardDiskAttachments;
#else /* VBOX_API_VERSION >= 3001000 */
    return machine->vtbl->GetMediumAttachments;
#endif /* VBOX_API_VERSION >= 3001000 */
}

static void* _handleMachineGetSharedFolders(IMachine *machine)
{
    return machine->vtbl->GetSharedFolders;
}

static void* _handleSnapshotGetChildren(ISnapshot *snapshot)
{
    return snapshot->vtbl->GetChildren;
}

static void* _handleMediumGetChildren(IMedium *medium ATTRIBUTE_UNUSED)
{
#if VBOX_API_VERSION < 3001000
    vboxUnsupported();
    return 0;
#else /* VBOX_API_VERSION >= 3001000 */
    return medium->vtbl->GetChildren;
#endif /* VBOX_API_VERSION >= 3001000 */
}

static void* _handleMediumGetSnapshotIds(IMedium *medium)
{
    return medium->vtbl->GetSnapshotIds;
}

static void* _handleMediumGetMachineIds(IMedium *medium)
{
    return medium->vtbl->GetMachineIds;
}

static void* _handleHostGetNetworkInterfaces(IHost *host)
{
    return host->vtbl->GetNetworkInterfaces;
}

static nsresult _nsisupportsRelease(nsISupports *nsi)
{
    return nsi->vtbl->Release(nsi);
}

static nsresult _nsisupportsAddRef(nsISupports *nsi)
{
    return nsi->vtbl->AddRef(nsi);
}

static nsresult
_virtualboxGetVersion(IVirtualBox *vboxObj, PRUnichar **versionUtf16)
{
    return vboxObj->vtbl->GetVersion(vboxObj, versionUtf16);
}

#if VBOX_API_VERSION < 4000000

static nsresult
_virtualboxGetMachine(IVirtualBox *vboxObj, vboxIIDUnion *iidu, IMachine **machine)
{
    return vboxObj->vtbl->GetMachine(vboxObj, IID_MEMBER(value), machine);
}

#else /* VBOX_API_VERSION >= 4000000 */

static nsresult
_virtualboxGetMachine(IVirtualBox *vboxObj, vboxIIDUnion *iidu, IMachine **machine)
{
    return vboxObj->vtbl->FindMachine(vboxObj, IID_MEMBER(value), machine);
}

#endif /* VBOX_API_VERSION >= 4000000 */

static nsresult
_virtualboxOpenMachine(IVirtualBox *vboxObj, PRUnichar *settingsFile, IMachine **machine)
{
    return vboxObj->vtbl->OpenMachine(vboxObj, settingsFile, machine);
}

static nsresult
_virtualboxGetSystemProperties(IVirtualBox *vboxObj, ISystemProperties **systemProperties)
{
    return vboxObj->vtbl->GetSystemProperties(vboxObj, systemProperties);
}

static nsresult
_virtualboxGetHost(IVirtualBox *vboxObj, IHost **host)
{
    return vboxObj->vtbl->GetHost(vboxObj, host);
}

static nsresult
_virtualboxCreateMachine(vboxGlobalData *data, virDomainDefPtr def, IMachine **machine, char *uuidstr ATTRIBUTE_UNUSED)
{
    vboxIID iid = VBOX_IID_INITIALIZER;
    PRUnichar *machineNameUtf16 = NULL;
    nsresult rc;

    VBOX_UTF8_TO_UTF16(def->name, &machineNameUtf16);
    vboxIIDFromUUID(&iid, def->uuid);
    {
#if VBOX_API_VERSION < 3002000
        rc = data->vboxObj->vtbl->CreateMachine(data->vboxObj,
                                                    machineNameUtf16,
                                                    NULL,
                                                    NULL,
                                                    iid.value,
                                                    machine);
#elif VBOX_API_VERSION < 4000000 /* 3002000 <= VBOX_API_VERSION < 4000000 */
        PRBool override = PR_FALSE;
        rc = data->vboxObj->vtbl->CreateMachine(data->vboxObj,
                                                machineNameUtf16,
                                                NULL,
                                                NULL,
                                                iid.value,
                                                override,
                                                machine);
#elif VBOX_API_VERSION >= 4000000 && VBOX_API_VERSION < 4002000
        PRBool override = PR_FALSE;
        rc = data->vboxObj->vtbl->CreateMachine(data->vboxObj,
                                                NULL,
                                                machineNameUtf16,
                                                NULL,
                                                iid.value,
                                                override,
                                                machine);
#else /* VBOX_API_VERSION >= 4002000 */
        const char *flagsUUIDPrefix = "UUID=";
        const char *flagsForceOverwrite = "forceOverwrite=0";
        const char *flagsSeparator = ",";
        char createFlags[strlen(flagsUUIDPrefix) + VIR_UUID_STRING_BUFLEN + strlen(flagsSeparator) + strlen(flagsForceOverwrite) + 1];
        PRUnichar *createFlagsUtf16 = NULL;

        snprintf(createFlags, sizeof(createFlags), "%s%s%s%s",
                 flagsUUIDPrefix,
                 uuidstr,
                 flagsSeparator,
                 flagsForceOverwrite
                );
        VBOX_UTF8_TO_UTF16(createFlags, &createFlagsUtf16);
        rc = data->vboxObj->vtbl->CreateMachine(data->vboxObj,
                                                NULL,
                                                machineNameUtf16,
                                                0,
                                                nsnull,
                                                nsnull,
                                                createFlagsUtf16,
                                                machine);
#endif /* VBOX_API_VERSION >= 4002000 */
    }
    VBOX_UTF16_FREE(machineNameUtf16);
    vboxIIDUnalloc(&iid);
    return rc;
}

static nsresult
_virtualboxCreateHardDisk(IVirtualBox *vboxObj, PRUnichar *format,
                          PRUnichar *location, IHardDisk **hardDisk)
{
    /* In vbox 2.2 and 3.0, this function will create a IHardDisk object.
     * In vbox 3.1 and later, this function will create a IMedium object.
     */
    return vboxObj->vtbl->CreateHardDisk(vboxObj, format, location, hardDisk);
}

static nsresult
_virtualboxRegisterMachine(IVirtualBox *vboxObj, IMachine *machine)
{
    return vboxObj->vtbl->RegisterMachine(vboxObj, machine);
}

static nsresult
_virtualboxFindHardDisk(IVirtualBox *vboxObj, PRUnichar *location,
                        PRUint32 deviceType ATTRIBUTE_UNUSED,
                        PRUint32 accessMode ATTRIBUTE_UNUSED,
                        IHardDisk **hardDisk)
{
    /* In vbox 2.2 and 3.0, this function will create a IHardDisk object.
     * In vbox 3.1 and later, this function will create a IMedium object.
     */
#if VBOX_API_VERSION < 4000000
    return vboxObj->vtbl->FindHardDisk(vboxObj, location, hardDisk);
#elif VBOX_API_VERSION < 4002000
    return vboxObj->vtbl->FindMedium(vboxObj, location,
                                     deviceType, hardDisk);
#else /* VBOX_API_VERSION >= 4002000 */
    return vboxObj->vtbl->OpenMedium(vboxObj, location,
                                     deviceType, accessMode, PR_FALSE, hardDisk);
#endif /* VBOX_API_VERSION >= 4002000 */
}

static nsresult
_virtualboxOpenMedium(IVirtualBox *vboxObj ATTRIBUTE_UNUSED,
                      PRUnichar *location ATTRIBUTE_UNUSED,
                      PRUint32 deviceType ATTRIBUTE_UNUSED,
                      PRUint32 accessMode ATTRIBUTE_UNUSED,
                      IMedium **medium ATTRIBUTE_UNUSED)
{
#if VBOX_API_VERSION == 4000000
    return vboxObj->vtbl->OpenMedium(vboxObj,
                                     location,
                                     deviceType, accessMode,
                                     medium);
#elif VBOX_API_VERSION >= 4001000
    return vboxObj->vtbl->OpenMedium(vboxObj,
                                     location,
                                     deviceType, accessMode,
                                     false,
                                     medium);
#else
    vboxUnsupported();
    return 0;
#endif
}

static nsresult
_virtualboxGetHardDiskByIID(IVirtualBox *vboxObj, vboxIIDUnion *iidu, IHardDisk **hardDisk)
{
#if VBOX_API_VERSION < 4000000
    return vboxObj->vtbl->GetHardDisk(vboxObj, IID_MEMBER(value), hardDisk);
#elif VBOX_API_VERSION >= 4000000 && VBOX_API_VERSION < 4002000
    return vboxObj->vtbl->FindMedium(vboxObj, IID_MEMBER(value), DeviceType_HardDisk,
                                     hardDisk);
#else /* VBOX_API_VERSION >= 4002000 */
    return vboxObj->vtbl->OpenMedium(vboxObj, IID_MEMBER(value), DeviceType_HardDisk,
                                     AccessMode_ReadWrite, PR_FALSE, hardDisk);
#endif /* VBOX_API_VERSION >= 4002000 */
}

static nsresult
_virtualboxFindDHCPServerByNetworkName(IVirtualBox *vboxObj, PRUnichar *name, IDHCPServer **server)
{
    return vboxObj->vtbl->FindDHCPServerByNetworkName(vboxObj, name, server);
}

static nsresult
_virtualboxCreateDHCPServer(IVirtualBox *vboxObj, PRUnichar *name, IDHCPServer **server)
{
    return vboxObj->vtbl->CreateDHCPServer(vboxObj, name, server);
}

static nsresult
_virtualboxRemoveDHCPServer(IVirtualBox *vboxObj, IDHCPServer *server)
{
    return vboxObj->vtbl->RemoveDHCPServer(vboxObj, server);
}

static nsresult
_machineAddStorageController(IMachine *machine, PRUnichar *name,
                             PRUint32 connectionType,
                             IStorageController **controller)
{
    return machine->vtbl->AddStorageController(machine, name, connectionType,
                                               controller);
}

static nsresult
_machineGetStorageControllerByName(IMachine *machine, PRUnichar *name,
                                   IStorageController **storageController)
{
    return machine->vtbl->GetStorageControllerByName(machine, name,
                                                     storageController);
}

static nsresult
_machineAttachDevice(IMachine *machine ATTRIBUTE_UNUSED,
                     PRUnichar *name ATTRIBUTE_UNUSED,
                     PRInt32 controllerPort ATTRIBUTE_UNUSED,
                     PRInt32 device ATTRIBUTE_UNUSED,
                     PRUint32 type ATTRIBUTE_UNUSED,
                     IMedium * medium ATTRIBUTE_UNUSED)
{
#if VBOX_API_VERSION >= 4000000
    return machine->vtbl->AttachDevice(machine, name, controllerPort,
                                       device, type, medium);
#else /* VBOX_API_VERSION < 4000000 */
    vboxUnsupported();
    return 0;
#endif /* VBOX_API_VERSION < 4000000 */
}

static nsresult
_machineCreateSharedFolder(IMachine *machine, PRUnichar *name,
                           PRUnichar *hostPath, PRBool writable,
                           PRBool automount ATTRIBUTE_UNUSED)
{
#if VBOX_API_VERSION < 4000000
    return machine->vtbl->CreateSharedFolder(machine, name, hostPath,
                                             writable);
#else /* VBOX_API_VERSION >= 4000000 */
    return machine->vtbl->CreateSharedFolder(machine, name, hostPath,
                                             writable, automount);
#endif /* VBOX_API_VERSION >= 4000000 */
}

static nsresult
_machineRemoveSharedFolder(IMachine *machine, PRUnichar *name)
{
    return machine->vtbl->RemoveSharedFolder(machine, name);
}

static nsresult
_machineLaunchVMProcess(vboxGlobalData *data,
                        IMachine *machine ATTRIBUTE_UNUSED,
                        vboxIIDUnion *iidu ATTRIBUTE_UNUSED,
                        PRUnichar *sessionType, PRUnichar *env,
                        IProgress **progress)
{
#if VBOX_API_VERSION < 4000000
    return data->vboxObj->vtbl->OpenRemoteSession(data->vboxObj,
                                                  data->vboxSession,
                                                  IID_MEMBER(value),
                                                  sessionType,
                                                  env,
                                                  progress);
#else /* VBOX_API_VERSION >= 4000000 */
    return machine->vtbl->LaunchVMProcess(machine, data->vboxSession,
                                          sessionType, env, progress);
#endif /* VBOX_API_VERSION >= 4000000 */
}

static nsresult
_machineUnregister(IMachine *machine ATTRIBUTE_UNUSED,
                   PRUint32 cleanupMode ATTRIBUTE_UNUSED,
                   PRUint32 *aMediaSize ATTRIBUTE_UNUSED,
                   IMedium ***aMedia ATTRIBUTE_UNUSED)
{
#if VBOX_API_VERSION < 4000000
    vboxUnsupported();
    return 0;
#else /* VBOX_API_VERSION >= 4000000 */
    return machine->vtbl->Unregister(machine, cleanupMode, aMediaSize, aMedia);
#endif /* VBOX_API_VERSION >= 4000000 */
}

static nsresult
_machineFindSnapshot(IMachine *machine, vboxIIDUnion *iidu, ISnapshot **snapshot)
{
#if VBOX_API_VERSION < 4000000
    return machine->vtbl->GetSnapshot(machine, IID_MEMBER(value), snapshot);
#else /* VBOX_API_VERSION >= 4000000 */
    return machine->vtbl->FindSnapshot(machine, IID_MEMBER(value), snapshot);
#endif /* VBOX_API_VERSION >= 4000000 */
}

static nsresult
_machineDetachDevice(IMachine *machine, PRUnichar *name,
                     PRInt32 controllerPort, PRInt32 device)
{
#if VBOX_API_VERSION < 3001000
    return machine->vtbl->DetachHardDisk(machine, name, controllerPort, device);
#else  /* VBOX_API_VERSION >= 3001000 */
    return machine->vtbl->DetachDevice(machine, name, controllerPort, device);
#endif /* VBOX_API_VERSION >= 3001000 */
}

static nsresult
_machineGetAccessible(IMachine *machine, PRBool *isAccessible)
{
    return machine->vtbl->GetAccessible(machine, isAccessible);
}

static nsresult
_machineGetState(IMachine *machine, PRUint32 *state)
{
    return machine->vtbl->GetState(machine, state);
}

static nsresult
_machineGetName(IMachine *machine, PRUnichar **name)
{
    return machine->vtbl->GetName(machine, name);
}

static nsresult
_machineGetId(IMachine *machine, vboxIIDUnion *iidu)
{
    return machine->vtbl->GetId(machine, &IID_MEMBER(value));
}

static nsresult
_machineGetBIOSSettings(IMachine *machine, IBIOSSettings **bios)
{
    return machine->vtbl->GetBIOSSettings(machine, bios);
}

static nsresult
_machineGetAudioAdapter(IMachine *machine, IAudioAdapter **audioadapter)
{
    return machine->vtbl->GetAudioAdapter(machine, audioadapter);
}

static nsresult
_machineGetNetworkAdapter(IMachine *machine, PRUint32 slot, INetworkAdapter **adapter)
{
    return machine->vtbl->GetNetworkAdapter(machine, slot, adapter);
}

static nsresult
_machineGetChipsetType(IMachine *machine ATTRIBUTE_UNUSED, PRUint32 *chipsetType ATTRIBUTE_UNUSED)
{
#if VBOX_API_VERSION >= 4001000
    return machine->vtbl->GetChipsetType(machine, chipsetType);
#else /* VBOX_API_VERSION < 4001000 */
    vboxUnsupported();
    return 0;
#endif /* VBOX_API_VERSION < 4001000 */
}

static nsresult
_machineGetSerialPort(IMachine *machine, PRUint32 slot, ISerialPort **port)
{
    return machine->vtbl->GetSerialPort(machine, slot, port);
}

static nsresult
_machineGetParallelPort(IMachine *machine, PRUint32 slot, IParallelPort **port)
{
    return machine->vtbl->GetParallelPort(machine, slot, port);
}

static nsresult
_machineGetVRDxServer(IMachine *machine, IVRDxServer **VRDxServer)
{
#if VBOX_API_VERSION < 4000000
    return machine->vtbl->GetVRDPServer(machine, VRDxServer);
#else /* VBOX_API_VERSION >= 4000000 */
    return machine->vtbl->GetVRDEServer(machine, VRDxServer);
#endif /* VBOX_API_VERSION >= 4000000 */
}

static nsresult
_machineGetUSBCommon(IMachine *machine, IUSBCommon **USBCommon)
{
#if VBOX_API_VERSION < 4003000
    return machine->vtbl->GetUSBController(machine, USBCommon);
#else
    return machine->vtbl->GetUSBDeviceFilters(machine, USBCommon);
#endif
}

static nsresult
_machineGetCurrentSnapshot(IMachine *machine, ISnapshot **currentSnapshot)
{
    return machine->vtbl->GetCurrentSnapshot(machine, currentSnapshot);
}

static nsresult
_machineGetSettingsFilePath(IMachine *machine, PRUnichar **settingsFilePath)
{
    return machine->vtbl->GetSettingsFilePath(machine, settingsFilePath);
}

static nsresult
_machineGetCPUCount(IMachine *machine, PRUint32 *CPUCount)
{
    return machine->vtbl->GetCPUCount(machine, CPUCount);
}

static nsresult
_machineSetCPUCount(IMachine *machine, PRUint32 CPUCount)
{
    return machine->vtbl->SetCPUCount(machine, CPUCount);
}

static nsresult
_machineGetMemorySize(IMachine *machine, PRUint32 *memorySize)
{
    return machine->vtbl->GetMemorySize(machine, memorySize);
}

static nsresult
_machineSetMemorySize(IMachine *machine, PRUint32 memorySize)
{
    return machine->vtbl->SetMemorySize(machine, memorySize);
}

static nsresult
_machineGetCPUProperty(IMachine *machine, PRUint32 property ATTRIBUTE_UNUSED, PRBool *value)
{
#if VBOX_API_VERSION < 3001000
    return machine->vtbl->GetPAEEnabled(machine, value);
#elif VBOX_API_VERSION == 3001000
    return machine->vtbl->GetCpuProperty(machine, property, value);
#elif VBOX_API_VERSION >= 3002000
    return machine->vtbl->GetCPUProperty(machine, property, value);
#endif
}

static nsresult
_machineSetCPUProperty(IMachine *machine, PRUint32 property ATTRIBUTE_UNUSED, PRBool value)
{
#if VBOX_API_VERSION < 3001000
    return machine->vtbl->SetPAEEnabled(machine, value);
#elif VBOX_API_VERSION == 3001000
    return machine->vtbl->SetCpuProperty(machine, property, value);
#elif VBOX_API_VERSION >= 3002000
    return machine->vtbl->SetCPUProperty(machine, property, value);
#endif
}

static nsresult
_machineGetBootOrder(IMachine *machine, PRUint32 position, PRUint32 *device)
{
    return machine->vtbl->GetBootOrder(machine, position, device);
}

static nsresult
_machineSetBootOrder(IMachine *machine, PRUint32 position, PRUint32 device)
{
    return machine->vtbl->SetBootOrder(machine, position, device);
}

static nsresult
_machineGetVRAMSize(IMachine *machine, PRUint32 *VRAMSize)
{
    return machine->vtbl->GetVRAMSize(machine, VRAMSize);
}

static nsresult
_machineSetVRAMSize(IMachine *machine, PRUint32 VRAMSize)
{
    return machine->vtbl->SetVRAMSize(machine, VRAMSize);
}

static nsresult
_machineGetMonitorCount(IMachine *machine, PRUint32 *monitorCount)
{
    return machine->vtbl->GetMonitorCount(machine, monitorCount);
}

static nsresult
_machineSetMonitorCount(IMachine *machine, PRUint32 monitorCount)
{
    return machine->vtbl->SetMonitorCount(machine, monitorCount);
}

static nsresult
_machineGetAccelerate3DEnabled(IMachine *machine, PRBool *accelerate3DEnabled)
{
    return machine->vtbl->GetAccelerate3DEnabled(machine, accelerate3DEnabled);
}

static nsresult
_machineSetAccelerate3DEnabled(IMachine *machine, PRBool accelerate3DEnabled)
{
    return machine->vtbl->SetAccelerate3DEnabled(machine, accelerate3DEnabled);
}

static nsresult
_machineGetAccelerate2DVideoEnabled(IMachine *machine ATTRIBUTE_UNUSED,
                                    PRBool *accelerate2DVideoEnabled ATTRIBUTE_UNUSED)
{
#if VBOX_API_VERSION >= 3001000
    return machine->vtbl->GetAccelerate2DVideoEnabled(machine, accelerate2DVideoEnabled);
#else /* VBOX_API_VERSION < 3001000 */
    vboxUnsupported();
    return 0;
#endif /* VBOX_API_VERSION < 3001000 */
}

static nsresult
_machineSetAccelerate2DVideoEnabled(IMachine *machine ATTRIBUTE_UNUSED,
                                    PRBool accelerate2DVideoEnabled ATTRIBUTE_UNUSED)
{
#if VBOX_API_VERSION >= 3001000
    return machine->vtbl->SetAccelerate2DVideoEnabled(machine, accelerate2DVideoEnabled);
#else /* VBOX_API_VERSION < 3001000 */
    vboxUnsupported();
    return 0;
#endif /* VBOX_API_VERSION < 3001000 */
}

static nsresult
_machineGetExtraData(IMachine *machine, PRUnichar *key, PRUnichar **value)
{
    return machine->vtbl->GetExtraData(machine, key, value);
}

static nsresult
_machineSetExtraData(IMachine *machine, PRUnichar *key, PRUnichar *value)
{
    return machine->vtbl->SetExtraData(machine, key, value);
}

static nsresult
_machineGetSnapshotCount(IMachine *machine, PRUint32 *snapshotCount)
{
    return machine->vtbl->GetSnapshotCount(machine, snapshotCount);
}

static nsresult
_machineSaveSettings(IMachine *machine)
{
    return machine->vtbl->SaveSettings(machine);
}

#if VBOX_API_VERSION < 4000000

static nsresult
_sessionOpen(vboxGlobalData *data, vboxIIDUnion *iidu, IMachine *machine ATTRIBUTE_UNUSED)
{
    return data->vboxObj->vtbl->OpenSession(data->vboxObj, data->vboxSession, IID_MEMBER(value));
}

static nsresult
_sessionOpenExisting(vboxGlobalData *data, vboxIIDUnion *iidu, IMachine *machine ATTRIBUTE_UNUSED)
{
    return data->vboxObj->vtbl->OpenExistingSession(data->vboxObj, data->vboxSession, IID_MEMBER(value));
}

static nsresult
_sessionClose(ISession *session)
{
    return session->vtbl->Close(session);
}

#else /* VBOX_API_VERSION >= 4000000 */

static nsresult
_sessionOpen(vboxGlobalData *data, vboxIIDUnion *iidu ATTRIBUTE_UNUSED, IMachine *machine)
{
    return machine->vtbl->LockMachine(machine, data->vboxSession, LockType_Write);
}

static nsresult
_sessionOpenExisting(vboxGlobalData *data, vboxIIDUnion *iidu ATTRIBUTE_UNUSED, IMachine *machine)
{
    return machine->vtbl->LockMachine(machine, data->vboxSession, LockType_Shared);
}

static nsresult
_sessionClose(ISession *session)
{
    return session->vtbl->UnlockMachine(session);
}

#endif /* VBOX_API_VERSION >= 4000000 */

static nsresult
_sessionGetConsole(ISession *session, IConsole **console)
{
    return session->vtbl->GetConsole(session, console);
}

static nsresult
_sessionGetMachine(ISession *session, IMachine **machine)
{
    return session->vtbl->GetMachine(session, machine);
}

static nsresult
_consoleSaveState(IConsole *console, IProgress **progress)
{
    return console->vtbl->SaveState(console, progress);
}

static nsresult
_consolePause(IConsole *console)
{
    return console->vtbl->Pause(console);
}

static nsresult
_consoleResume(IConsole *console)
{
    return console->vtbl->Resume(console);
}

static nsresult
_consolePowerButton(IConsole *console)
{
    return console->vtbl->PowerButton(console);
}

static nsresult
_consolePowerDown(IConsole *console)
{
    nsresult rc;
#if VBOX_API_VERSION == 2002000
    rc = console->vtbl->PowerDown(console);
#else
    IProgress *progress = NULL;
    rc = console->vtbl->PowerDown(console, &progress);
    if (progress) {
        rc = progress->vtbl->WaitForCompletion(progress, -1);
        VBOX_RELEASE(progress);
    }
#endif
    return rc;
}

static nsresult
_consoleReset(IConsole *console)
{
    return console->vtbl->Reset(console);
}

static nsresult
_consoleTakeSnapshot(IConsole *console, PRUnichar *name,
                     PRUnichar *description, IProgress **progress)
{
    return console->vtbl->TakeSnapshot(console, name, description, progress);
}

static nsresult
_consoleDeleteSnapshot(IConsole *console, vboxIIDUnion *iidu, IProgress **progress)
{
#if VBOX_API_VERSION < 3001000
    return console->vtbl->DiscardSnapshot(console, IID_MEMBER(value), progress);
#else /* VBOX_API_VERSION >= 3001000 */
    return console->vtbl->DeleteSnapshot(console, IID_MEMBER(value), progress);
#endif /* VBOX_API_VERSION >= 3001000 */
}

static nsresult
_consoleGetDisplay(IConsole *console, IDisplay **display)
{
    return console->vtbl->GetDisplay(console, display);
}

static nsresult
_consoleGetKeyboard(IConsole *console, IKeyboard **keyboard)
{
    return console->vtbl->GetKeyboard(console, keyboard);
}

static nsresult
_progressWaitForCompletion(IProgress *progress, PRInt32 timeout)
{
    return progress->vtbl->WaitForCompletion(progress, timeout);
}

static nsresult
_progressGetResultCode(IProgress *progress, resultCodeUnion *resultCode)
{
#if VBOX_API_VERSION == 2002000
    return progress->vtbl->GetResultCode(progress, &resultCode->uResultCode);
#else /* VBOX_API_VERSION != 2002000 */
    return progress->vtbl->GetResultCode(progress, &resultCode->resultCode);
#endif /* VBOX_API_VERSION != 2002000 */
}

static nsresult
_progressGetCompleted(IProgress *progress, PRBool *completed)
{
    return progress->vtbl->GetCompleted(progress, completed);
}

static nsresult
_systemPropertiesGetMaxGuestCPUCount(ISystemProperties *systemProperties, PRUint32 *maxCPUCount)
{
    return systemProperties->vtbl->GetMaxGuestCPUCount(systemProperties, maxCPUCount);
}

static nsresult
_systemPropertiesGetMaxBootPosition(ISystemProperties *systemProperties, PRUint32 *maxBootPosition)
{
    return systemProperties->vtbl->GetMaxBootPosition(systemProperties, maxBootPosition);
}

static nsresult
_systemPropertiesGetMaxNetworkAdapters(ISystemProperties *systemProperties, PRUint32 chipset ATTRIBUTE_UNUSED,
                                       PRUint32 *maxNetworkAdapters)
{
#if VBOX_API_VERSION < 4001000
        return systemProperties->vtbl->GetNetworkAdapterCount(systemProperties,
                                                              maxNetworkAdapters);
#else  /* VBOX_API_VERSION >= 4000000 */
        return systemProperties->vtbl->GetMaxNetworkAdapters(systemProperties, chipset,
                                                             maxNetworkAdapters);
#endif /* VBOX_API_VERSION >= 4000000 */
}

static nsresult
_systemPropertiesGetSerialPortCount(ISystemProperties *systemProperties, PRUint32 *SerialPortCount)
{
    return systemProperties->vtbl->GetSerialPortCount(systemProperties, SerialPortCount);
}

static nsresult
_systemPropertiesGetParallelPortCount(ISystemProperties *systemProperties, PRUint32 *ParallelPortCount)
{
    return systemProperties->vtbl->GetParallelPortCount(systemProperties, ParallelPortCount);
}

#if VBOX_API_VERSION >= 3001000
static nsresult
_systemPropertiesGetMaxPortCountForStorageBus(ISystemProperties *systemProperties, PRUint32 bus,
                                              PRUint32 *maxPortCount)
{
    return systemProperties->vtbl->GetMaxPortCountForStorageBus(systemProperties, bus, maxPortCount);
}

static nsresult
_systemPropertiesGetMaxDevicesPerPortForStorageBus(ISystemProperties *systemProperties,
                                                   PRUint32 bus, PRUint32 *maxDevicesPerPort)
{
    return systemProperties->vtbl->GetMaxDevicesPerPortForStorageBus(systemProperties,
                                                                     bus, maxDevicesPerPort);
}
#else /* VBOX_API_VERSION < 3001000 */
static nsresult
_systemPropertiesGetMaxPortCountForStorageBus(ISystemProperties *systemProperties ATTRIBUTE_UNUSED,
                                              PRUint32 bus ATTRIBUTE_UNUSED,
                                              PRUint32 *maxPortCount ATTRIBUTE_UNUSED)
{
    vboxUnsupported();
    return 0;
}

static nsresult
_systemPropertiesGetMaxDevicesPerPortForStorageBus(ISystemProperties *systemProperties ATTRIBUTE_UNUSED,
                                                   PRUint32 bus ATTRIBUTE_UNUSED,
                                                   PRUint32 *maxDevicesPerPort ATTRIBUTE_UNUSED)
{
    vboxUnsupported();
    return 0;
}
#endif

static nsresult
_systemPropertiesGetMaxGuestRAM(ISystemProperties *systemProperties, PRUint32 *maxGuestRAM)
{
    return systemProperties->vtbl->GetMaxGuestRAM(systemProperties, maxGuestRAM);
}

static nsresult
_biosSettingsGetACPIEnabled(IBIOSSettings *bios, PRBool *ACPIEnabled)
{
    return bios->vtbl->GetACPIEnabled(bios, ACPIEnabled);
}

static nsresult
_biosSettingsSetACPIEnabled(IBIOSSettings *bios, PRBool ACPIEnabled)
{
    return bios->vtbl->SetACPIEnabled(bios, ACPIEnabled);
}

static nsresult
_biosSettingsGetIOAPICEnabled(IBIOSSettings *bios, PRBool *IOAPICEnabled)
{
    return bios->vtbl->GetIOAPICEnabled(bios, IOAPICEnabled);
}

static nsresult
_biosSettingsSetIOAPICEnabled(IBIOSSettings *bios, PRBool IOAPICEnabled)
{
    return bios->vtbl->SetIOAPICEnabled(bios, IOAPICEnabled);
}

static nsresult
_audioAdapterGetEnabled(IAudioAdapter *audioAdapter, PRBool *enabled)
{
    return audioAdapter->vtbl->GetEnabled(audioAdapter, enabled);
}

static nsresult
_audioAdapterSetEnabled(IAudioAdapter *audioAdapter, PRBool enabled)
{
    return audioAdapter->vtbl->SetEnabled(audioAdapter, enabled);
}

static nsresult
_audioAdapterGetAudioController(IAudioAdapter *audioAdapter, PRUint32 *audioController)
{
    return audioAdapter->vtbl->GetAudioController(audioAdapter, audioController);
}

static nsresult
_audioAdapterSetAudioController(IAudioAdapter *audioAdapter, PRUint32 audioController)
{
    return audioAdapter->vtbl->SetAudioController(audioAdapter, audioController);
}

static nsresult
_networkAdapterGetAttachmentType(INetworkAdapter *adapter, PRUint32 *attachmentType)
{
    return adapter->vtbl->GetAttachmentType(adapter, attachmentType);
}

static nsresult
_networkAdapterGetEnabled(INetworkAdapter *adapter, PRBool *enabled)
{
    return adapter->vtbl->GetEnabled(adapter, enabled);
}

static nsresult
_networkAdapterSetEnabled(INetworkAdapter *adapter, PRBool enabled)
{
    return adapter->vtbl->SetEnabled(adapter, enabled);
}

static nsresult
_networkAdapterGetAdapterType(INetworkAdapter *adapter, PRUint32 *adapterType)
{
    return adapter->vtbl->GetAdapterType(adapter, adapterType);
}

static nsresult
_networkAdapterSetAdapterType(INetworkAdapter *adapter, PRUint32 adapterType)
{
    return adapter->vtbl->SetAdapterType(adapter, adapterType);
}

static nsresult
_networkAdapterGetInternalNetwork(INetworkAdapter *adapter, PRUnichar **internalNetwork)
{
    return adapter->vtbl->GetInternalNetwork(adapter, internalNetwork);
}

static nsresult
_networkAdapterSetInternalNetwork(INetworkAdapter *adapter, PRUnichar *internalNetwork)
{
    return adapter->vtbl->SetInternalNetwork(adapter, internalNetwork);
}

static nsresult
_networkAdapterGetMACAddress(INetworkAdapter *adapter, PRUnichar **MACAddress)
{
    return adapter->vtbl->GetMACAddress(adapter, MACAddress);
}

static nsresult
_networkAdapterSetMACAddress(INetworkAdapter *adapter, PRUnichar *MACAddress)
{
    return adapter->vtbl->SetMACAddress(adapter, MACAddress);
}

#if VBOX_API_VERSION < 4001000

static nsresult
_networkAdapterGetBridgedInterface(INetworkAdapter *adapter, PRUnichar **hostInterface)
{
    return adapter->vtbl->GetHostInterface(adapter, hostInterface);
}

static nsresult
_networkAdapterSetBridgedInterface(INetworkAdapter *adapter, PRUnichar *hostInterface)
{
    return adapter->vtbl->SetHostInterface(adapter, hostInterface);
}

static nsresult
_networkAdapterGetHostOnlyInterface(INetworkAdapter *adapter, PRUnichar **hostOnlyInterface)
{
    return adapter->vtbl->GetHostInterface(adapter, hostOnlyInterface);
}

static nsresult
_networkAdapterSetHostOnlyInterface(INetworkAdapter *adapter, PRUnichar *hostOnlyInterface)
{
    return adapter->vtbl->SetHostInterface(adapter, hostOnlyInterface);
}

static nsresult
_networkAdapterAttachToBridgedInterface(INetworkAdapter *adapter)
{
    return adapter->vtbl->AttachToBridgedInterface(adapter);
}

static nsresult
_networkAdapterAttachToInternalNetwork(INetworkAdapter *adapter)
{
    return adapter->vtbl->AttachToInternalNetwork(adapter);
}

static nsresult
_networkAdapterAttachToHostOnlyInterface(INetworkAdapter *adapter)
{
    return adapter->vtbl->AttachToHostOnlyInterface(adapter);
}

static nsresult
_networkAdapterAttachToNAT(INetworkAdapter *adapter)
{
    return adapter->vtbl->AttachToNAT(adapter);
}

#else /* VBOX_API_VERSION >= 4001000 */

static nsresult
_networkAdapterGetBridgedInterface(INetworkAdapter *adapter, PRUnichar **bridgedInterface)
{
    return adapter->vtbl->GetBridgedInterface(adapter, bridgedInterface);
}

static nsresult
_networkAdapterSetBridgedInterface(INetworkAdapter *adapter, PRUnichar *bridgedInterface)
{
    return adapter->vtbl->SetBridgedInterface(adapter, bridgedInterface);
}

static nsresult
_networkAdapterGetHostOnlyInterface(INetworkAdapter *adapter, PRUnichar **hostOnlyInterface)
{
    return adapter->vtbl->GetHostOnlyInterface(adapter, hostOnlyInterface);
}

static nsresult
_networkAdapterSetHostOnlyInterface(INetworkAdapter *adapter, PRUnichar *hostOnlyInterface)
{
    return adapter->vtbl->SetHostOnlyInterface(adapter, hostOnlyInterface);
}

static nsresult
_networkAdapterAttachToBridgedInterface(INetworkAdapter *adapter)
{
    return adapter->vtbl->SetAttachmentType(adapter, NetworkAttachmentType_Bridged);
}

static nsresult
_networkAdapterAttachToInternalNetwork(INetworkAdapter *adapter)
{
    return adapter->vtbl->SetAttachmentType(adapter, NetworkAttachmentType_Internal);
}

static nsresult
_networkAdapterAttachToHostOnlyInterface(INetworkAdapter *adapter)
{
    return adapter->vtbl->SetAttachmentType(adapter, NetworkAttachmentType_HostOnly);
}

static nsresult
_networkAdapterAttachToNAT(INetworkAdapter *adapter)
{
    return adapter->vtbl->SetAttachmentType(adapter, NetworkAttachmentType_NAT);
}

#endif /* VBOX_API_VERSION >= 4001000 */

static nsresult
_serialPortGetEnabled(ISerialPort *port, PRBool *enabled)
{
    return port->vtbl->GetEnabled(port, enabled);
}

static nsresult
_serialPortSetEnabled(ISerialPort *port, PRBool enabled)
{
    return port->vtbl->SetEnabled(port, enabled);
}

static nsresult
_serialPortGetPath(ISerialPort *port, PRUnichar **path)
{
    return port->vtbl->GetPath(port, path);
}

static nsresult
_serialPortSetPath(ISerialPort *port, PRUnichar *path)
{
    return port->vtbl->SetPath(port, path);
}

static nsresult
_serialPortGetIRQ(ISerialPort *port, PRUint32 *IRQ)
{
    return port->vtbl->GetIRQ(port, IRQ);
}

static nsresult
_serialPortSetIRQ(ISerialPort *port, PRUint32 IRQ)
{
    return port->vtbl->SetIRQ(port, IRQ);
}

static nsresult
_serialPortGetIOBase(ISerialPort *port, PRUint32 *IOBase)
{
    return port->vtbl->GetIOBase(port, IOBase);
}

static nsresult
_serialPortSetIOBase(ISerialPort *port, PRUint32 IOBase)
{
    return port->vtbl->SetIOBase(port, IOBase);
}

static nsresult
_serialPortGetHostMode(ISerialPort *port, PRUint32 *hostMode)
{
    return port->vtbl->GetHostMode(port, hostMode);
}

static nsresult
_serialPortSetHostMode(ISerialPort *port, PRUint32 hostMode)
{
    return port->vtbl->SetHostMode(port, hostMode);
}

static nsresult
_parallelPortGetEnabled(IParallelPort *port, PRBool *enabled)
{
    return port->vtbl->GetEnabled(port, enabled);
}

static nsresult
_parallelPortSetEnabled(IParallelPort *port, PRBool enabled)
{
    return port->vtbl->SetEnabled(port, enabled);
}

static nsresult
_parallelPortGetPath(IParallelPort *port, PRUnichar **path)
{
    return port->vtbl->GetPath(port, path);
}

static nsresult
_parallelPortSetPath(IParallelPort *port, PRUnichar *path)
{
    return port->vtbl->SetPath(port, path);
}

static nsresult
_parallelPortGetIRQ(IParallelPort *port, PRUint32 *IRQ)
{
    return port->vtbl->GetIRQ(port, IRQ);
}

static nsresult
_parallelPortSetIRQ(IParallelPort *port, PRUint32 IRQ)
{
    return port->vtbl->SetIRQ(port, IRQ);
}

static nsresult
_parallelPortGetIOBase(IParallelPort *port, PRUint32 *IOBase)
{
    return port->vtbl->GetIOBase(port, IOBase);
}

static nsresult
_parallelPortSetIOBase(IParallelPort *port, PRUint32 IOBase)
{
    return port->vtbl->SetIOBase(port, IOBase);
}

static nsresult
_vrdxServerGetEnabled(IVRDxServer *VRDxServer, PRBool *enabled)
{
    return VRDxServer->vtbl->GetEnabled(VRDxServer, enabled);
}

static nsresult
_vrdxServerSetEnabled(IVRDxServer *VRDxServer, PRBool enabled)
{
    return VRDxServer->vtbl->SetEnabled(VRDxServer, enabled);
}

static nsresult
_vrdxServerGetPorts(vboxGlobalData *data ATTRIBUTE_UNUSED,
                    IVRDxServer *VRDxServer, virDomainGraphicsDefPtr graphics)
{
    nsresult rc;
#if VBOX_API_VERSION < 3001000
    PRUint32 VRDPport = 0;
    rc = VRDxServer->vtbl->GetPort(VRDxServer, &VRDPport);
    if (VRDPport) {
        graphics->data.rdp.port = VRDPport;
    } else {
        graphics->data.rdp.autoport = true;
    }
#elif VBOX_API_VERSION < 4000000 /* 3001000 <= VBOX_API_VERSION < 4000000 */
    PRUnichar *VRDPport = NULL;
    rc = VRDxServer->vtbl->GetPorts(VRDxServer, &VRDPport);
    if (VRDPport) {
        /* even if vbox supports mutilpe ports, single port for now here */
        graphics->data.rdp.port = PRUnicharToInt(VRDPport);
        VBOX_UTF16_FREE(VRDPport);
    } else {
        graphics->data.rdp.autoport = true;
    }
#else /* VBOX_API_VERSION >= 4000000 */
    PRUnichar *VRDEPortsKey = NULL;
    PRUnichar *VRDEPortsValue = NULL;
    VBOX_UTF8_TO_UTF16("TCP/Ports", &VRDEPortsKey);
    rc = VRDxServer->vtbl->GetVRDEProperty(VRDxServer, VRDEPortsKey, &VRDEPortsValue);
    VBOX_UTF16_FREE(VRDEPortsKey);
    if (VRDEPortsValue) {
        /* even if vbox supports mutilpe ports, single port for now here */
        graphics->data.rdp.port = PRUnicharToInt(VRDEPortsValue);
        VBOX_UTF16_FREE(VRDEPortsValue);
    } else {
        graphics->data.rdp.autoport = true;
    }
#endif /* VBOX_API_VERSION >= 4000000 */
    return rc;
}

static nsresult
_vrdxServerSetPorts(vboxGlobalData *data ATTRIBUTE_UNUSED,
                    IVRDxServer *VRDxServer, virDomainGraphicsDefPtr graphics)
{
    nsresult rc = 0;
#if VBOX_API_VERSION < 3001000
    if (graphics->data.rdp.port) {
        rc = VRDxServer->vtbl->SetPort(VRDxServer,
                                       graphics->data.rdp.port);
        VIR_DEBUG("VRDP Port changed to: %d",
                  graphics->data.rdp.port);
    } else if (graphics->data.rdp.autoport) {
        /* Setting the port to 0 will reset its value to
         * the default one which is 3389 currently
         */
        rc = VRDxServer->vtbl->SetPort(VRDxServer, 0);
        VIR_DEBUG("VRDP Port changed to default, which is 3389 currently");
    }
#elif VBOX_API_VERSION < 4000000 /* 3001000 <= VBOX_API_VERSION < 4000000 */
    PRUnichar *portUtf16 = NULL;
    portUtf16 = PRUnicharFromInt(graphics->data.rdp.port);
    rc = VRDxServer->vtbl->SetPorts(VRDxServer, portUtf16);
    VBOX_UTF16_FREE(portUtf16);
#else /* VBOX_API_VERSION >= 4000000 */
    PRUnichar *VRDEPortsKey = NULL;
    PRUnichar *VRDEPortsValue = NULL;
    VBOX_UTF8_TO_UTF16("TCP/Ports", &VRDEPortsKey);
    VRDEPortsValue = PRUnicharFromInt(graphics->data.rdp.port);
    rc = VRDxServer->vtbl->SetVRDEProperty(VRDxServer, VRDEPortsKey,
                                           VRDEPortsValue);
    VBOX_UTF16_FREE(VRDEPortsKey);
    VBOX_UTF16_FREE(VRDEPortsValue);
#endif /* VBOX_API_VERSION >= 4000000 */
    return rc;
}

static nsresult
_vrdxServerGetReuseSingleConnection(IVRDxServer *VRDxServer, PRBool *enabled)
{
    return VRDxServer->vtbl->GetReuseSingleConnection(VRDxServer, enabled);
}

static nsresult
_vrdxServerSetReuseSingleConnection(IVRDxServer *VRDxServer, PRBool enabled)
{
    return VRDxServer->vtbl->SetReuseSingleConnection(VRDxServer, enabled);
}

static nsresult
_vrdxServerGetAllowMultiConnection(IVRDxServer *VRDxServer, PRBool *enabled)
{
    return VRDxServer->vtbl->GetAllowMultiConnection(VRDxServer, enabled);
}

static nsresult
_vrdxServerSetAllowMultiConnection(IVRDxServer *VRDxServer, PRBool enabled)
{
    return VRDxServer->vtbl->SetAllowMultiConnection(VRDxServer, enabled);
}

static nsresult
_vrdxServerGetNetAddress(vboxGlobalData *data ATTRIBUTE_UNUSED,
                         IVRDxServer *VRDxServer, PRUnichar **netAddress)
{
#if VBOX_API_VERSION >= 4000000
    PRUnichar *VRDENetAddressKey = NULL;
    nsresult rc;
    VBOX_UTF8_TO_UTF16("TCP/Address", &VRDENetAddressKey);
    rc = VRDxServer->vtbl->GetVRDEProperty(VRDxServer, VRDENetAddressKey, netAddress);
    VBOX_UTF16_FREE(VRDENetAddressKey);
    return rc;
#else /* VBOX_API_VERSION < 4000000 */
    return VRDxServer->vtbl->GetNetAddress(VRDxServer, netAddress);
#endif /* VBOX_API_VERSION < 4000000 */
}

static nsresult
_vrdxServerSetNetAddress(vboxGlobalData *data ATTRIBUTE_UNUSED,
                         IVRDxServer *VRDxServer, PRUnichar *netAddress)
{
#if VBOX_API_VERSION < 4000000
    return VRDxServer->vtbl->SetNetAddress(VRDxServer,
                                           netAddress);
#else /* VBOX_API_VERSION >= 4000000 */
    PRUnichar *netAddressKey = NULL;
    nsresult rc;
    VBOX_UTF8_TO_UTF16("TCP/Address", &netAddressKey);
    rc = VRDxServer->vtbl->SetVRDEProperty(VRDxServer, netAddressKey,
                                           netAddress);
    VBOX_UTF16_FREE(netAddressKey);
    return rc;
#endif /* VBOX_API_VERSION >= 4000000 */
}

static nsresult
_usbCommonEnable(IUSBCommon *USBCommon ATTRIBUTE_UNUSED)
{
    nsresult rc = 0;
#if VBOX_API_VERSION < 4003000
    USBCommon->vtbl->SetEnabled(USBCommon, 1);
# if VBOX_API_VERSION < 4002000
    rc = USBCommon->vtbl->SetEnabledEhci(USBCommon, 1);
# else /* VBOX_API_VERSION >= 4002000 */
    rc = USBCommon->vtbl->SetEnabledEHCI(USBCommon, 1);
# endif /* VBOX_API_VERSION >= 4002000 */
#endif /* VBOX_API_VERSION >= 4003000 */
    /* We don't need to set usb enabled for vbox 4.3 and later */
    return rc;
}

static nsresult
_usbCommonGetEnabled(IUSBCommon *USBCommon ATTRIBUTE_UNUSED, PRBool *enabled)
{
#if VBOX_API_VERSION < 4003000
    return USBCommon->vtbl->GetEnabled(USBCommon, enabled);
#else /* VBOX_API_VERSION >= 4003000 */
    *enabled = true;
    return 0;
#endif /* VBOX_API_VERSION >= 4003000 */
}

static nsresult
_usbCommonCreateDeviceFilter(IUSBCommon *USBCommon, PRUnichar *name,
                             IUSBDeviceFilter **filter)
{
    return USBCommon->vtbl->CreateDeviceFilter(USBCommon, name, filter);
}

static nsresult
_usbCommonInsertDeviceFilter(IUSBCommon *USBCommon, PRUint32 position,
                             IUSBDeviceFilter *filter)
{
    return USBCommon->vtbl->InsertDeviceFilter(USBCommon, position, filter);
}

static nsresult
_usbDeviceFilterGetProductId(IUSBDeviceFilter *USBDeviceFilter, PRUnichar **productId)
{
    return USBDeviceFilter->vtbl->GetProductId(USBDeviceFilter, productId);
}

static nsresult
_usbDeviceFilterSetProductId(IUSBDeviceFilter *USBDeviceFilter, PRUnichar *productId)
{
    return USBDeviceFilter->vtbl->SetProductId(USBDeviceFilter, productId);
}

static nsresult
_usbDeviceFilterGetActive(IUSBDeviceFilter *USBDeviceFilter, PRBool *active)
{
    return USBDeviceFilter->vtbl->GetActive(USBDeviceFilter, active);
}

static nsresult
_usbDeviceFilterSetActive(IUSBDeviceFilter *USBDeviceFilter, PRBool active)
{
    return USBDeviceFilter->vtbl->SetActive(USBDeviceFilter, active);
}

static nsresult
_usbDeviceFilterGetVendorId(IUSBDeviceFilter *USBDeviceFilter, PRUnichar **vendorId)
{
    return USBDeviceFilter->vtbl->GetVendorId(USBDeviceFilter, vendorId);
}

static nsresult
_usbDeviceFilterSetVendorId(IUSBDeviceFilter *USBDeviceFilter, PRUnichar *vendorId)
{
    return USBDeviceFilter->vtbl->SetVendorId(USBDeviceFilter, vendorId);
}

static nsresult _mediumGetId(IMedium *medium, vboxIIDUnion *iidu)
{
    return medium->vtbl->GetId(medium, &IID_MEMBER(value));
}

static nsresult _mediumGetLocation(IMedium *medium, PRUnichar **location)
{
    return medium->vtbl->GetLocation(medium, location);
}

static nsresult _mediumGetState(IMedium *medium, PRUint32 *state)
{
    return medium->vtbl->GetState(medium, state);
}

static nsresult _mediumGetName(IMedium *medium, PRUnichar **name)
{
    return medium->vtbl->GetName(medium, name);
}

static nsresult _mediumGetSize(IMedium *medium, PRUint64 *uSize)
{
#if VBOX_API_VERSION < 4000000
    return medium->vtbl->GetSize(medium, uSize);
#else /* VBOX_API_VERSION >= 4000000 */
    nsresult rc;
    PRInt64 Size;
    rc = medium->vtbl->GetSize(medium, &Size);
    *uSize = Size;
    return rc;
#endif /* VBOX_API_VERSION >= 4000000 */
}

static nsresult _mediumGetReadOnly(IMedium *medium ATTRIBUTE_UNUSED,
                                   PRBool *readOnly ATTRIBUTE_UNUSED)
{
#if VBOX_API_VERSION < 3001000
    vboxUnsupported();
    return 0;
#else /* VBOX_API_VERSION >= 3001000 */
    return medium->vtbl->GetReadOnly(medium, readOnly);
#endif /* VBOX_API_VERSION >= 3001000 */
}

#if VBOX_API_VERSION < 3001000

static nsresult _mediumGetParent(IMedium *medium ATTRIBUTE_UNUSED,
                                 IMedium **parent ATTRIBUTE_UNUSED)
{
    vboxUnsupported();
    return 0;
}

static nsresult _mediumGetChildren(IMedium *medium ATTRIBUTE_UNUSED,
                                   PRUint32 *childrenSize ATTRIBUTE_UNUSED,
                                   IMedium ***children ATTRIBUTE_UNUSED)
{
    vboxUnsupported();
    return 0;
}

static nsresult _mediumGetFormat(IMedium *medium ATTRIBUTE_UNUSED,
                                 PRUnichar **format ATTRIBUTE_UNUSED)
{
    vboxUnsupported();
    return 0;
}

static nsresult _mediumDeleteStorage(IMedium *medium ATTRIBUTE_UNUSED,
                                     IProgress **progress ATTRIBUTE_UNUSED)
{
    vboxUnsupported();
    return 0;
}

#else /* VBOX_API_VERSION >= 3001000 */

static nsresult _mediumGetParent(IMedium *medium,
                                 IMedium **parent)
{
    return medium->vtbl->GetParent(medium, parent);
}

static nsresult _mediumGetChildren(IMedium *medium,
                                   PRUint32 *childrenSize,
                                   IMedium ***children)
{
    return medium->vtbl->GetChildren(medium, childrenSize, children);
}

static nsresult _mediumGetFormat(IMedium *medium,
                                 PRUnichar **format)
{
    return medium->vtbl->GetFormat(medium, format);
}

static nsresult _mediumDeleteStorage(IMedium *medium,
                                     IProgress **progress)
{
    return medium->vtbl->DeleteStorage(medium, progress);
}

#endif /* VBOX_API_VERSION >= 3001000 */

static nsresult _mediumRelease(IMedium *medium)
{
    return medium->vtbl->nsisupports.Release((nsISupports *)medium);
}
static nsresult _mediumClose(IMedium *medium)
{
    return medium->vtbl->Close(medium);
}

static nsresult _mediumSetType(IMedium *medium ATTRIBUTE_UNUSED,
                               PRUint32 type ATTRIBUTE_UNUSED)
{
#if VBOX_API_VERSION > 3000000
    return medium->vtbl->SetType(medium, type);
#else
    vboxUnsupported();
    return 0;
#endif
}

static nsresult
_mediumCreateDiffStorage(IMedium *medium ATTRIBUTE_UNUSED,
                         IMedium *target ATTRIBUTE_UNUSED,
                         PRUint32 variantSize ATTRIBUTE_UNUSED,
                         PRUint32 *variant ATTRIBUTE_UNUSED,
                         IProgress **progress ATTRIBUTE_UNUSED)
{
#if VBOX_API_VERSION < 3001000
    vboxUnsupported();
    return 0;
#elif VBOX_API_VERSION < 4003000
    if (variantSize == 0)
        return 0;
    if (variantSize > 1)
        VIR_WARN("Only one variant is avaible in current version");
    return medium->vtbl->CreateDiffStorage(medium, target, variant[0], progress);
#else /* VBOX_API_VERSION >= 4003000 */
    return medium->vtbl->CreateDiffStorage(medium, target, variantSize, variant, progress);
#endif /* VBOX_API_VERSION >= 4003000 */
}

static nsresult
_mediumAttachmentGetMedium(IMediumAttachment *mediumAttachment,
                           IHardDisk **hardDisk)
{
#if VBOX_API_VERSION < 3001000
    return mediumAttachment->vtbl->GetHardDisk(mediumAttachment, hardDisk);
#else /* VBOX_API_VERSION >= 3001000 */
    return mediumAttachment->vtbl->GetMedium(mediumAttachment, hardDisk);
#endif /* VBOX_API_VERSION >= 3001000 */
}

static nsresult
_mediumAttachmentGetController(IMediumAttachment *mediumAttachment,
                               PRUnichar **controller)
{
    return mediumAttachment->vtbl->GetController(mediumAttachment, controller);
}

static nsresult
_mediumAttachmentGetType(IMediumAttachment *mediumAttachment ATTRIBUTE_UNUSED,
                         PRUint32 *type ATTRIBUTE_UNUSED)
{
#if VBOX_API_VERSION < 3001000
    vboxUnsupported();
    return 0;
#else /* VBOX_API_VERSION >= 3001000 */
    return mediumAttachment->vtbl->GetType(mediumAttachment, type);
#endif /* VBOX_API_VERSION >= 3001000 */
}

static nsresult
_mediumAttachmentGetPort(IMediumAttachment *mediumAttachment, PRInt32 *port)
{
    return mediumAttachment->vtbl->GetPort(mediumAttachment, port);
}

static nsresult
_mediumAttachmentGetDevice(IMediumAttachment *mediumAttachment, PRInt32 *device)
{
    return mediumAttachment->vtbl->GetDevice(mediumAttachment, device);
}

static nsresult
_storageControllerGetBus(IStorageController *storageController, PRUint32 *bus)
{
    return storageController->vtbl->GetBus(storageController, bus);
}

static nsresult
_sharedFolderGetHostPath(ISharedFolder *sharedFolder, PRUnichar **hostPath)
{
    return sharedFolder->vtbl->GetHostPath(sharedFolder, hostPath);
}

static nsresult
_sharedFolderGetName(ISharedFolder *sharedFolder, PRUnichar **name)
{
    return sharedFolder->vtbl->GetName(sharedFolder, name);
}

static nsresult
_sharedFolderGetWritable(ISharedFolder *sharedFolder, PRBool *writable)
{
    return sharedFolder->vtbl->GetWritable(sharedFolder, writable);
}

static nsresult
_snapshotGetName(ISnapshot *snapshot, PRUnichar **name)
{
    return snapshot->vtbl->GetName(snapshot, name);
}

static nsresult
_snapshotGetId(ISnapshot *snapshot, vboxIIDUnion *iidu)
{
    return snapshot->vtbl->GetId(snapshot, &IID_MEMBER(value));
}

static nsresult
_snapshotGetMachine(ISnapshot *snapshot, IMachine **machine)
{
    return snapshot->vtbl->GetMachine(snapshot, machine);
}

static nsresult
_snapshotGetDescription(ISnapshot *snapshot, PRUnichar **description)
{
    return snapshot->vtbl->GetDescription(snapshot, description);
}

static nsresult
_snapshotGetTimeStamp(ISnapshot *snapshot, PRInt64 *timeStamp)
{
    return snapshot->vtbl->GetTimeStamp(snapshot, timeStamp);
}

static nsresult
_snapshotGetParent(ISnapshot *snapshot, ISnapshot **parent)
{
    return snapshot->vtbl->GetParent(snapshot, parent);
}

static nsresult
_snapshotGetOnline(ISnapshot *snapshot, PRBool *online)
{
    return snapshot->vtbl->GetOnline(snapshot, online);
}

static nsresult
_displayGetScreenResolution(IDisplay *display ATTRIBUTE_UNUSED,
                            PRUint32 screenId ATTRIBUTE_UNUSED,
                            PRUint32 *width ATTRIBUTE_UNUSED,
                            PRUint32 *height ATTRIBUTE_UNUSED,
                            PRUint32 *bitsPerPixel ATTRIBUTE_UNUSED,
                            PRInt32 *xOrigin ATTRIBUTE_UNUSED,
                            PRInt32 *yOrigin ATTRIBUTE_UNUSED)
{
#if VBOX_API_VERSION < 3002000
    vboxUnsupported();
    return 0;
#elif VBOX_API_VERSION < 4003000
    return display->vtbl->GetScreenResolution(display, screenId, width,
                                              height, bitsPerPixel);
#else /* VBOX_API_VERSION >= 4003000 */
    return display->vtbl->GetScreenResolution(display, screenId, width,
                                              height, bitsPerPixel,
                                              xOrigin, yOrigin);
#endif /* VBOX_API_VERSION >= 4003000 */
}

static nsresult
_displayTakeScreenShotPNGToArray(IDisplay *display ATTRIBUTE_UNUSED,
                                 PRUint32 screenId ATTRIBUTE_UNUSED,
                                 PRUint32 width ATTRIBUTE_UNUSED,
                                 PRUint32 height ATTRIBUTE_UNUSED,
                                 PRUint32 *screenDataSize ATTRIBUTE_UNUSED,
                                 PRUint8** screenData ATTRIBUTE_UNUSED)
{
#if VBOX_API_VERSION < 4000000
    vboxUnsupported();
    return 0;
#else /* VBOX_API_VERSION >= 4000000 */
    return display->vtbl->TakeScreenShotPNGToArray(display, screenId, width,
                                                   height, screenDataSize,
                                                   screenData);
#endif /* VBOX_API_VERSION >= 4000000 */
}

static nsresult
_hostFindHostNetworkInterfaceById(IHost *host, vboxIIDUnion *iidu,
                                  IHostNetworkInterface **networkInterface)
{
    return host->vtbl->FindHostNetworkInterfaceById(host, IID_MEMBER(value),
                                                    networkInterface);
}

static nsresult
_hostFindHostNetworkInterfaceByName(IHost *host, PRUnichar *name,
                                    IHostNetworkInterface **networkInterface)
{
    return host->vtbl->FindHostNetworkInterfaceByName(host, name,
                                                      networkInterface);
}

static nsresult
_hostCreateHostOnlyNetworkInterface(vboxGlobalData *data ATTRIBUTE_UNUSED,
                                    IHost *host, char *name ATTRIBUTE_UNUSED,
                                    IHostNetworkInterface **networkInterface)
{
    nsresult rc = -1;
#if VBOX_API_VERSION == 2002000
    if (STREQ(name, "vboxnet0")) {
        PRUint32 interfaceType = 0;
        PRUnichar *networkInterfaceNameUtf16 = NULL;

        VBOX_UTF8_TO_UTF16(name, &networkInterfaceNameUtf16);
        host->vtbl->FindHostNetworkInterfaceByName(host, networkInterfaceNameUtf16, networkInterface);

        (*networkInterface)->vtbl->GetInterfaceType(*networkInterface, &interfaceType);
        if (interfaceType != HostNetworkInterfaceType_HostOnly) {
            VBOX_RELEASE(*networkInterface);
            *networkInterface = NULL;
        } else {
            rc = 0;
        }
    }
#else /* VBOX_API_VERSION != 2002000 */
    IProgress *progress = NULL;
    host->vtbl->CreateHostOnlyNetworkInterface(host, networkInterface,
                                               &progress);

    if (progress) {
        rc = progress->vtbl->WaitForCompletion(progress, -1);
        VBOX_RELEASE(progress);
    }
#endif /* VBOX_API_VERSION != 2002000 */
    return rc;
}

static nsresult
_hostRemoveHostOnlyNetworkInterface(IHost *host ATTRIBUTE_UNUSED,
                                    vboxIIDUnion *iidu ATTRIBUTE_UNUSED,
                                    IProgress **progress ATTRIBUTE_UNUSED)
{
#if VBOX_API_VERSION == 2002000
    vboxUnsupported();
    return 0;
#elif VBOX_API_VERSION == 3000000
    nsresult rc;
    IHostNetworkInterface *netInt = NULL;
    rc = host->vtbl->RemoveHostOnlyNetworkInterface(host, IID_MEMBER(value), &netInt, progress);
    VBOX_RELEASE(netInt);
    return rc;
#else  /* VBOX_API_VERSION > 3000000 */
    return host->vtbl->RemoveHostOnlyNetworkInterface(host, IID_MEMBER(value), progress);
#endif /* VBOX_API_VERSION > 3000000 */
}

static nsresult
_hnInterfaceGetInterfaceType(IHostNetworkInterface *hni, PRUint32 *interfaceType)
{
    return hni->vtbl->GetInterfaceType(hni, interfaceType);
}

static nsresult
_hnInterfaceGetStatus(IHostNetworkInterface *hni, PRUint32 *status)
{
    return hni->vtbl->GetStatus(hni, status);
}

static nsresult
_hnInterfaceGetName(IHostNetworkInterface *hni, PRUnichar **name)
{
    return hni->vtbl->GetName(hni, name);
}

static nsresult
_hnInterfaceGetId(IHostNetworkInterface *hni, vboxIIDUnion *iidu)
{
    return hni->vtbl->GetId(hni, &IID_MEMBER(value));
}

static nsresult
_hnInterfaceGetHardwareAddress(IHostNetworkInterface *hni, PRUnichar **hardwareAddress)
{
    return hni->vtbl->GetHardwareAddress(hni, hardwareAddress);
}

static nsresult
_hnInterfaceGetIPAddress(IHostNetworkInterface *hni, PRUnichar **IPAddress)
{
    return hni->vtbl->GetIPAddress(hni, IPAddress);
}

static nsresult
_hnInterfaceGetNetworkMask(IHostNetworkInterface *hni, PRUnichar **networkMask)
{
    return hni->vtbl->GetNetworkMask(hni, networkMask);
}

static nsresult
_hnInterfaceEnableStaticIPConfig(IHostNetworkInterface *hni, PRUnichar *IPAddress,
                                 PRUnichar *networkMask)
{
#if VBOX_API_VERSION < 4002000
    return hni->vtbl->EnableStaticIpConfig(hni, IPAddress, networkMask);
#else
    return hni->vtbl->EnableStaticIPConfig(hni, IPAddress, networkMask);
#endif
}

static nsresult
_hnInterfaceEnableDynamicIPConfig(IHostNetworkInterface *hni)
{
#if VBOX_API_VERSION < 4002000
    return hni->vtbl->EnableDynamicIpConfig(hni);
#else
    return hni->vtbl->EnableDynamicIPConfig(hni);
#endif
}

static nsresult
_hnInterfaceDHCPRediscover(IHostNetworkInterface *hni)
{
#if VBOX_API_VERSION < 4002000
    return hni->vtbl->DhcpRediscover(hni);
#else
    return hni->vtbl->DHCPRediscover(hni);
#endif
}

static nsresult
_dhcpServerGetIPAddress(IDHCPServer *dhcpServer, PRUnichar **IPAddress)
{
    return dhcpServer->vtbl->GetIPAddress(dhcpServer, IPAddress);
}

static nsresult
_dhcpServerGetNetworkMask(IDHCPServer *dhcpServer, PRUnichar **networkMask)
{
    return dhcpServer->vtbl->GetNetworkMask(dhcpServer, networkMask);
}

static nsresult
_dhcpServerGetLowerIP(IDHCPServer *dhcpServer, PRUnichar **lowerIP)
{
    return dhcpServer->vtbl->GetLowerIP(dhcpServer, lowerIP);
}

static nsresult
_dhcpServerGetUpperIP(IDHCPServer *dhcpServer, PRUnichar **upperIP)
{
    return dhcpServer->vtbl->GetUpperIP(dhcpServer, upperIP);
}

static nsresult
_dhcpServerSetEnabled(IDHCPServer *dhcpServer, PRBool enabled)
{
    return dhcpServer->vtbl->SetEnabled(dhcpServer, enabled);
}

static nsresult
_dhcpServerSetConfiguration(IDHCPServer *dhcpServer, PRUnichar *IPAddress,
                            PRUnichar *networkMask, PRUnichar *FromIPAddress,
                            PRUnichar *ToIPAddress)
{
    return dhcpServer->vtbl->SetConfiguration(dhcpServer, IPAddress,
                                              networkMask, FromIPAddress,
                                              ToIPAddress);
}

static nsresult
_dhcpServerStart(IDHCPServer *dhcpServer, PRUnichar *networkName,
                 PRUnichar *trunkName, PRUnichar *trunkType)
{
    return dhcpServer->vtbl->Start(dhcpServer, networkName,
                                   trunkName, trunkType);
}

static nsresult
_dhcpServerStop(IDHCPServer *dhcpServer)
{
    return dhcpServer->vtbl->Stop(dhcpServer);
}

static nsresult
_hardDiskCreateBaseStorage(IHardDisk *hardDisk, PRUint64 logicalSize,
                           PRUint32 variant, IProgress **progress)
{
#if VBOX_API_VERSION < 4003000
    return hardDisk->vtbl->CreateBaseStorage(hardDisk, logicalSize, variant, progress);
#else
    return hardDisk->vtbl->CreateBaseStorage(hardDisk, logicalSize, 1, &variant, progress);
#endif
}

static nsresult
_hardDiskDeleteStorage(IHardDisk *hardDisk, IProgress **progress)
{
    return hardDisk->vtbl->DeleteStorage(hardDisk, progress);
}

static nsresult
_hardDiskGetLogicalSizeInByte(IHardDisk *hardDisk, PRUint64 *uLogicalSize)
{
    nsresult rc;
#if VBOX_API_VERSION < 4000000
    rc = hardDisk->vtbl->GetLogicalSize(hardDisk, uLogicalSize);
    *uLogicalSize *= 1024 * 1024; /* MB => Bytes */
#else /* VBOX_API_VERSION >= 4000000 */
    PRInt64 logicalSize;
    rc = hardDisk->vtbl->GetLogicalSize(hardDisk, &logicalSize);
    *uLogicalSize = logicalSize;
#endif /* VBOX_API_VERSION >= 4000000 */
    return rc;
}

static nsresult
_hardDiskGetFormat(IHardDisk *hardDisk, PRUnichar **format)
{
    return hardDisk->vtbl->GetFormat(hardDisk, format);
}

static nsresult
_keyboardPutScancode(IKeyboard *keyboard, PRInt32 scancode)
{
    return keyboard->vtbl->PutScancode(keyboard, scancode);
}

static nsresult
_keyboardPutScancodes(IKeyboard *keyboard, PRUint32 scancodesSize,
                      PRInt32 *scanCodes, PRUint32 *codesStored)
{
    return keyboard->vtbl->PutScancodes(keyboard, scancodesSize, scanCodes,
                                        codesStored);
}

static bool _machineStateOnline(PRUint32 state)
{
    return ((state >= MachineState_FirstOnline) &&
            (state <= MachineState_LastOnline));
}

static bool _machineStateInactive(PRUint32 state)
{
    return ((state < MachineState_FirstOnline) ||
            (state > MachineState_LastOnline));
}

static bool _machineStateNotStart(PRUint32 state)
{
    return ((state == MachineState_PoweredOff) ||
            (state == MachineState_Saved) ||
            (state == MachineState_Aborted));
}

static bool _machineStateRunning(PRUint32 state)
{
    return state == MachineState_Running;
}

static bool _machineStatePaused(PRUint32 state)
{
    return state == MachineState_Paused;
}

static bool _machineStatePoweredOff(PRUint32 state)
{
    return state == MachineState_PoweredOff;
}

static vboxUniformedPFN _UPFN = {
    .Initialize = _pfnInitialize,
    .Uninitialize = _pfnUninitialize,
    .ComUnallocMem = _pfnComUnallocMem,
    .Utf16Free = _pfnUtf16Free,
    .Utf8Free = _pfnUtf8Free,
    .Utf16ToUtf8 = _pfnUtf16ToUtf8,
    .Utf8ToUtf16 = _pfnUtf8ToUtf16,
};

static vboxUniformedIID _UIID = {
    .vboxIIDInitialize = _vboxIIDInitialize,
    .vboxIIDUnalloc = _vboxIIDUnalloc,
    .vboxIIDToUUID = _vboxIIDToUUID,
    .vboxIIDFromUUID = _vboxIIDFromUUID,
    .vboxIIDIsEqual = _vboxIIDIsEqual,
    .vboxIIDFromArrayItem = _vboxIIDFromArrayItem,
    .vboxIIDToUtf8 = _vboxIIDToUtf8,
    .DEBUGIID = _DEBUGIID,
};

static vboxUniformedArray _UArray = {
    .vboxArrayGet = vboxArrayGet,
    .vboxArrayGetWithIIDArg = _vboxArrayGetWithIIDArg,
    .vboxArrayRelease = vboxArrayRelease,
    .vboxArrayUnalloc = vboxArrayUnalloc,
    .handleGetMachines = _handleGetMachines,
    .handleGetHardDisks = _handleGetHardDisks,
    .handleUSBGetDeviceFilters = _handleUSBGetDeviceFilters,
    .handleMachineGetMediumAttachments = _handleMachineGetMediumAttachments,
    .handleMachineGetSharedFolders = _handleMachineGetSharedFolders,
    .handleSnapshotGetChildren = _handleSnapshotGetChildren,
    .handleMediumGetChildren = _handleMediumGetChildren,
    .handleMediumGetSnapshotIds = _handleMediumGetSnapshotIds,
    .handleMediumGetMachineIds = _handleMediumGetMachineIds,
    .handleHostGetNetworkInterfaces = _handleHostGetNetworkInterfaces,
};

static vboxUniformednsISupports _nsUISupports = {
    .Release = _nsisupportsRelease,
    .AddRef = _nsisupportsAddRef,
};

static vboxUniformedIVirtualBox _UIVirtualBox = {
    .GetVersion = _virtualboxGetVersion,
    .GetMachine = _virtualboxGetMachine,
    .OpenMachine = _virtualboxOpenMachine,
    .GetSystemProperties = _virtualboxGetSystemProperties,
    .GetHost = _virtualboxGetHost,
    .CreateMachine = _virtualboxCreateMachine,
    .CreateHardDisk = _virtualboxCreateHardDisk,
    .RegisterMachine = _virtualboxRegisterMachine,
    .FindHardDisk = _virtualboxFindHardDisk,
    .OpenMedium = _virtualboxOpenMedium,
    .GetHardDiskByIID = _virtualboxGetHardDiskByIID,
    .FindDHCPServerByNetworkName = _virtualboxFindDHCPServerByNetworkName,
    .CreateDHCPServer = _virtualboxCreateDHCPServer,
    .RemoveDHCPServer = _virtualboxRemoveDHCPServer,
};

static vboxUniformedIMachine _UIMachine = {
    .AddStorageController = _machineAddStorageController,
    .GetStorageControllerByName = _machineGetStorageControllerByName,
    .AttachDevice = _machineAttachDevice,
    .CreateSharedFolder = _machineCreateSharedFolder,
    .RemoveSharedFolder = _machineRemoveSharedFolder,
    .LaunchVMProcess = _machineLaunchVMProcess,
    .Unregister = _machineUnregister,
    .FindSnapshot = _machineFindSnapshot,
    .DetachDevice = _machineDetachDevice,
    .GetAccessible = _machineGetAccessible,
    .GetState = _machineGetState,
    .GetName = _machineGetName,
    .GetId = _machineGetId,
    .GetBIOSSettings = _machineGetBIOSSettings,
    .GetAudioAdapter = _machineGetAudioAdapter,
    .GetNetworkAdapter = _machineGetNetworkAdapter,
    .GetChipsetType = _machineGetChipsetType,
    .GetSerialPort = _machineGetSerialPort,
    .GetParallelPort = _machineGetParallelPort,
    .GetVRDxServer = _machineGetVRDxServer,
    .GetUSBCommon = _machineGetUSBCommon,
    .GetCurrentSnapshot = _machineGetCurrentSnapshot,
    .GetSettingsFilePath = _machineGetSettingsFilePath,
    .GetCPUCount = _machineGetCPUCount,
    .SetCPUCount = _machineSetCPUCount,
    .GetMemorySize = _machineGetMemorySize,
    .SetMemorySize = _machineSetMemorySize,
    .GetCPUProperty = _machineGetCPUProperty,
    .SetCPUProperty = _machineSetCPUProperty,
    .GetBootOrder = _machineGetBootOrder,
    .SetBootOrder = _machineSetBootOrder,
    .GetVRAMSize = _machineGetVRAMSize,
    .SetVRAMSize = _machineSetVRAMSize,
    .GetMonitorCount = _machineGetMonitorCount,
    .SetMonitorCount = _machineSetMonitorCount,
    .GetAccelerate3DEnabled = _machineGetAccelerate3DEnabled,
    .SetAccelerate3DEnabled = _machineSetAccelerate3DEnabled,
    .GetAccelerate2DVideoEnabled = _machineGetAccelerate2DVideoEnabled,
    .SetAccelerate2DVideoEnabled = _machineSetAccelerate2DVideoEnabled,
    .GetExtraData = _machineGetExtraData,
    .SetExtraData = _machineSetExtraData,
    .GetSnapshotCount = _machineGetSnapshotCount,
    .SaveSettings = _machineSaveSettings,
};

static vboxUniformedISession _UISession = {
    .Open = _sessionOpen,
    .OpenExisting = _sessionOpenExisting,
    .GetConsole = _sessionGetConsole,
    .GetMachine = _sessionGetMachine,
    .Close = _sessionClose,
};

static vboxUniformedIConsole _UIConsole = {
    .SaveState = _consoleSaveState,
    .Pause = _consolePause,
    .Resume = _consoleResume,
    .PowerButton = _consolePowerButton,
    .PowerDown = _consolePowerDown,
    .Reset = _consoleReset,
    .TakeSnapshot = _consoleTakeSnapshot,
    .DeleteSnapshot = _consoleDeleteSnapshot,
    .GetDisplay = _consoleGetDisplay,
    .GetKeyboard = _consoleGetKeyboard,
};

static vboxUniformedIProgress _UIProgress = {
    .WaitForCompletion = _progressWaitForCompletion,
    .GetResultCode = _progressGetResultCode,
    .GetCompleted = _progressGetCompleted,
};

static vboxUniformedISystemProperties _UISystemProperties = {
    .GetMaxGuestCPUCount = _systemPropertiesGetMaxGuestCPUCount,
    .GetMaxBootPosition = _systemPropertiesGetMaxBootPosition,
    .GetMaxNetworkAdapters = _systemPropertiesGetMaxNetworkAdapters,
    .GetSerialPortCount = _systemPropertiesGetSerialPortCount,
    .GetParallelPortCount = _systemPropertiesGetParallelPortCount,
    .GetMaxPortCountForStorageBus = _systemPropertiesGetMaxPortCountForStorageBus,
    .GetMaxDevicesPerPortForStorageBus = _systemPropertiesGetMaxDevicesPerPortForStorageBus,
    .GetMaxGuestRAM = _systemPropertiesGetMaxGuestRAM,
};

static vboxUniformedIBIOSSettings _UIBIOSSettings = {
    .GetACPIEnabled = _biosSettingsGetACPIEnabled,
    .SetACPIEnabled = _biosSettingsSetACPIEnabled,
    .GetIOAPICEnabled = _biosSettingsGetIOAPICEnabled,
    .SetIOAPICEnabled = _biosSettingsSetIOAPICEnabled,
};

static vboxUniformedIAudioAdapter _UIAudioAdapter = {
    .GetEnabled = _audioAdapterGetEnabled,
    .SetEnabled = _audioAdapterSetEnabled,
    .GetAudioController = _audioAdapterGetAudioController,
    .SetAudioController = _audioAdapterSetAudioController,
};

static vboxUniformedINetworkAdapter _UINetworkAdapter = {
    .GetAttachmentType = _networkAdapterGetAttachmentType,
    .GetEnabled = _networkAdapterGetEnabled,
    .SetEnabled = _networkAdapterSetEnabled,
    .GetAdapterType = _networkAdapterGetAdapterType,
    .SetAdapterType = _networkAdapterSetAdapterType,
    .GetBridgedInterface = _networkAdapterGetBridgedInterface,
    .SetBridgedInterface = _networkAdapterSetBridgedInterface,
    .GetInternalNetwork = _networkAdapterGetInternalNetwork,
    .SetInternalNetwork = _networkAdapterSetInternalNetwork,
    .GetHostOnlyInterface = _networkAdapterGetHostOnlyInterface,
    .SetHostOnlyInterface = _networkAdapterSetHostOnlyInterface,
    .GetMACAddress = _networkAdapterGetMACAddress,
    .SetMACAddress = _networkAdapterSetMACAddress,
    .AttachToBridgedInterface = _networkAdapterAttachToBridgedInterface,
    .AttachToInternalNetwork = _networkAdapterAttachToInternalNetwork,
    .AttachToHostOnlyInterface = _networkAdapterAttachToHostOnlyInterface,
    .AttachToNAT = _networkAdapterAttachToNAT,
};

static vboxUniformedISerialPort _UISerialPort = {
    .GetEnabled = _serialPortGetEnabled,
    .SetEnabled = _serialPortSetEnabled,
    .GetPath = _serialPortGetPath,
    .SetPath = _serialPortSetPath,
    .GetIRQ = _serialPortGetIRQ,
    .SetIRQ = _serialPortSetIRQ,
    .GetIOBase = _serialPortGetIOBase,
    .SetIOBase = _serialPortSetIOBase,
    .GetHostMode = _serialPortGetHostMode,
    .SetHostMode = _serialPortSetHostMode,
};

static vboxUniformedIParallelPort _UIParallelPort = {
    .GetEnabled = _parallelPortGetEnabled,
    .SetEnabled = _parallelPortSetEnabled,
    .GetPath = _parallelPortGetPath,
    .SetPath = _parallelPortSetPath,
    .GetIRQ = _parallelPortGetIRQ,
    .SetIRQ = _parallelPortSetIRQ,
    .GetIOBase = _parallelPortGetIOBase,
    .SetIOBase = _parallelPortSetIOBase,
};

static vboxUniformedIVRDxServer _UIVRDxServer = {
    .GetEnabled = _vrdxServerGetEnabled,
    .SetEnabled = _vrdxServerSetEnabled,
    .GetPorts = _vrdxServerGetPorts,
    .SetPorts = _vrdxServerSetPorts,
    .GetReuseSingleConnection = _vrdxServerGetReuseSingleConnection,
    .SetReuseSingleConnection = _vrdxServerSetReuseSingleConnection,
    .GetAllowMultiConnection = _vrdxServerGetAllowMultiConnection,
    .SetAllowMultiConnection = _vrdxServerSetAllowMultiConnection,
    .GetNetAddress = _vrdxServerGetNetAddress,
    .SetNetAddress = _vrdxServerSetNetAddress,
};

static vboxUniformedIUSBCommon _UIUSBCommon = {
    .Enable = _usbCommonEnable,
    .GetEnabled = _usbCommonGetEnabled,
    .CreateDeviceFilter = _usbCommonCreateDeviceFilter,
    .InsertDeviceFilter = _usbCommonInsertDeviceFilter,
};

static vboxUniformedIUSBDeviceFilter _UIUSBDeviceFilter = {
    .GetProductId = _usbDeviceFilterGetProductId,
    .SetProductId = _usbDeviceFilterSetProductId,
    .GetActive = _usbDeviceFilterGetActive,
    .SetActive = _usbDeviceFilterSetActive,
    .GetVendorId = _usbDeviceFilterGetVendorId,
    .SetVendorId = _usbDeviceFilterSetVendorId,
};

static vboxUniformedIMedium _UIMedium = {
    .GetId = _mediumGetId,
    .GetLocation = _mediumGetLocation,
    .GetState = _mediumGetState,
    .GetName = _mediumGetName,
    .GetSize = _mediumGetSize,
    .GetReadOnly = _mediumGetReadOnly,
    .GetParent = _mediumGetParent,
    .GetChildren = _mediumGetChildren,
    .GetFormat = _mediumGetFormat,
    .DeleteStorage = _mediumDeleteStorage,
    .Release = _mediumRelease,
    .Close = _mediumClose,
    .SetType = _mediumSetType,
    .CreateDiffStorage = _mediumCreateDiffStorage,
};

static vboxUniformedIMediumAttachment _UIMediumAttachment = {
    .GetMedium = _mediumAttachmentGetMedium,
    .GetController = _mediumAttachmentGetController,
    .GetType = _mediumAttachmentGetType,
    .GetPort = _mediumAttachmentGetPort,
    .GetDevice = _mediumAttachmentGetDevice,
};

static vboxUniformedIStorageController _UIStorageController = {
    .GetBus = _storageControllerGetBus,
};

static vboxUniformedISharedFolder _UISharedFolder = {
    .GetHostPath = _sharedFolderGetHostPath,
    .GetName = _sharedFolderGetName,
    .GetWritable = _sharedFolderGetWritable,
};

static vboxUniformedISnapshot _UISnapshot = {
    .GetName = _snapshotGetName,
    .GetId = _snapshotGetId,
    .GetMachine = _snapshotGetMachine,
    .GetDescription = _snapshotGetDescription,
    .GetTimeStamp = _snapshotGetTimeStamp,
    .GetParent = _snapshotGetParent,
    .GetOnline = _snapshotGetOnline,
};

static vboxUniformedIDisplay _UIDisplay = {
    .GetScreenResolution = _displayGetScreenResolution,
    .TakeScreenShotPNGToArray = _displayTakeScreenShotPNGToArray,
};

static vboxUniformedIHost _UIHost = {
    .FindHostNetworkInterfaceById = _hostFindHostNetworkInterfaceById,
    .FindHostNetworkInterfaceByName = _hostFindHostNetworkInterfaceByName,
    .CreateHostOnlyNetworkInterface = _hostCreateHostOnlyNetworkInterface,
    .RemoveHostOnlyNetworkInterface = _hostRemoveHostOnlyNetworkInterface,
};

static vboxUniformedIHNInterface _UIHNInterface = {
    .GetInterfaceType = _hnInterfaceGetInterfaceType,
    .GetStatus = _hnInterfaceGetStatus,
    .GetName = _hnInterfaceGetName,
    .GetId = _hnInterfaceGetId,
    .GetHardwareAddress = _hnInterfaceGetHardwareAddress,
    .GetIPAddress = _hnInterfaceGetIPAddress,
    .GetNetworkMask = _hnInterfaceGetNetworkMask,
    .EnableStaticIPConfig = _hnInterfaceEnableStaticIPConfig,
    .EnableDynamicIPConfig = _hnInterfaceEnableDynamicIPConfig,
    .DHCPRediscover = _hnInterfaceDHCPRediscover,
};

static vboxUniformedIDHCPServer _UIDHCPServer = {
    .GetIPAddress = _dhcpServerGetIPAddress,
    .GetNetworkMask = _dhcpServerGetNetworkMask,
    .GetLowerIP = _dhcpServerGetLowerIP,
    .GetUpperIP = _dhcpServerGetUpperIP,
    .SetEnabled = _dhcpServerSetEnabled,
    .SetConfiguration = _dhcpServerSetConfiguration,
    .Start = _dhcpServerStart,
    .Stop = _dhcpServerStop,
};

static vboxUniformedIHardDisk _UIHardDisk = {
    .CreateBaseStorage = _hardDiskCreateBaseStorage,
    .DeleteStorage = _hardDiskDeleteStorage,
    .GetLogicalSizeInByte = _hardDiskGetLogicalSizeInByte,
    .GetFormat = _hardDiskGetFormat,
};

static vboxUniformedIKeyboard _UIKeyboard = {
    .PutScancode = _keyboardPutScancode,
    .PutScancodes = _keyboardPutScancodes,
};

static uniformedMachineStateChecker _machineStateChecker = {
    .Online = _machineStateOnline,
    .Inactive = _machineStateInactive,
    .NotStart = _machineStateNotStart,
    .Running = _machineStateRunning,
    .Paused = _machineStatePaused,
    .PoweredOff = _machineStatePoweredOff,
};

void NAME(InstallUniformedAPI)(vboxUniformedAPI *pVBoxAPI)
{
    pVBoxAPI->APIVersion = VBOX_API_VERSION;
    pVBoxAPI->XPCOMCVersion = VBOX_XPCOMC_VERSION;
    pVBoxAPI->initializeDomainEvent = _initializeDomainEvent;
    pVBoxAPI->registerGlobalData = _registerGlobalData;
    pVBoxAPI->detachDevices = _detachDevices;
    pVBoxAPI->unregisterMachine = _unregisterMachine;
    pVBoxAPI->deleteConfig = _deleteConfig;
    pVBoxAPI->vboxAttachDrivesOld = _vboxAttachDrivesOld;
    pVBoxAPI->vboxConvertState = _vboxConvertState;
    pVBoxAPI->dumpIDEHDDsOld = _dumpIDEHDDsOld;
    pVBoxAPI->dumpDVD = _dumpDVD;
    pVBoxAPI->attachDVD = _attachDVD;
    pVBoxAPI->detachDVD = _detachDVD;
    pVBoxAPI->dumpFloppy = _dumpFloppy;
    pVBoxAPI->attachFloppy = _attachFloppy;
    pVBoxAPI->detachFloppy = _detachFloppy;
    pVBoxAPI->snapshotRestore = _vboxDomainSnapshotRestore;
    pVBoxAPI->registerDomainEvent = _registerDomainEvent;
    pVBoxAPI->UPFN = _UPFN;
    pVBoxAPI->UIID = _UIID;
    pVBoxAPI->UArray = _UArray;
    pVBoxAPI->nsUISupports = _nsUISupports;
    pVBoxAPI->UIVirtualBox = _UIVirtualBox;
    pVBoxAPI->UIMachine = _UIMachine;
    pVBoxAPI->UISession = _UISession;
    pVBoxAPI->UIConsole = _UIConsole;
    pVBoxAPI->UIProgress = _UIProgress;
    pVBoxAPI->UISystemProperties = _UISystemProperties;
    pVBoxAPI->UIBIOSSettings = _UIBIOSSettings;
    pVBoxAPI->UIAudioAdapter = _UIAudioAdapter;
    pVBoxAPI->UINetworkAdapter = _UINetworkAdapter;
    pVBoxAPI->UISerialPort = _UISerialPort;
    pVBoxAPI->UIParallelPort = _UIParallelPort;
    pVBoxAPI->UIVRDxServer = _UIVRDxServer;
    pVBoxAPI->UIUSBCommon = _UIUSBCommon;
    pVBoxAPI->UIUSBDeviceFilter = _UIUSBDeviceFilter;
    pVBoxAPI->UIMedium = _UIMedium;
    pVBoxAPI->UIMediumAttachment = _UIMediumAttachment;
    pVBoxAPI->UIStorageController = _UIStorageController;
    pVBoxAPI->UISharedFolder = _UISharedFolder;
    pVBoxAPI->UISnapshot = _UISnapshot;
    pVBoxAPI->UIDisplay = _UIDisplay;
    pVBoxAPI->UIHost = _UIHost;
    pVBoxAPI->UIHNInterface = _UIHNInterface;
    pVBoxAPI->UIDHCPServer = _UIDHCPServer;
    pVBoxAPI->UIHardDisk = _UIHardDisk;
    pVBoxAPI->UIKeyboard = _UIKeyboard;
    pVBoxAPI->machineStateChecker = _machineStateChecker;

#if VBOX_API_VERSION <= 2002000 || VBOX_API_VERSION >= 4000000
    pVBoxAPI->domainEventCallbacks = 0;
#else /* VBOX_API_VERSION > 2002000 || VBOX_API_VERSION < 4000000 */
    pVBoxAPI->domainEventCallbacks = 1;
#endif /* VBOX_API_VERSION > 2002000 || VBOX_API_VERSION < 4000000 */

#if VBOX_API_VERSION == 2002000
    pVBoxAPI->hasStaticGlobalData = 0;
#else /* VBOX_API_VERSION > 2002000 */
    pVBoxAPI->hasStaticGlobalData = 1;
#endif /* VBOX_API_VERSION > 2002000 */

#if VBOX_API_VERSION >= 4000000
    /* Get machine for the call to VBOX_SESSION_OPEN_EXISTING */
    pVBoxAPI->getMachineForSession = 1;
    pVBoxAPI->detachDevicesExplicitly = 0;
    pVBoxAPI->vboxAttachDrivesUseOld = 0;
    pVBoxAPI->supportScreenshot = 1;
#else /* VBOX_API_VERSION < 4000000 */
    pVBoxAPI->getMachineForSession = 0;
    pVBoxAPI->detachDevicesExplicitly = 1;
    pVBoxAPI->vboxAttachDrivesUseOld = 1;
    pVBoxAPI->supportScreenshot = 0;
#endif /* VBOX_API_VERSION < 4000000 */

#if VBOX_API_VERSION >= 4001000
    pVBoxAPI->chipsetType = 1;
#else /* VBOX_API_VERSION < 4001000 */
    pVBoxAPI->chipsetType = 0;
#endif /* VBOX_API_VERSION < 4001000 */

#if VBOX_API_VERSION >= 3001000
    pVBoxAPI->accelerate2DVideo = 1;
    pVBoxAPI->oldMediumInterface = 0;
#else /* VBOX_API_VERSION < 3001000 */
    pVBoxAPI->accelerate2DVideo = 0;
    pVBoxAPI->oldMediumInterface = 1;
#endif /* VBOX_API_VERSION < 3001000 */

#if VBOX_API_VERSION >= 4002000
    pVBoxAPI->vboxSnapshotRedefine = 1;
#else /* VBOX_API_VERSION < 4002000 */
    pVBoxAPI->vboxSnapshotRedefine = 0;
#endif /* VBOX_API_VERSION < 4002000 */

#if VBOX_API_VERSION == 2002000
    pVBoxAPI->networkRemoveInterface = 0;
#else /* VBOX_API_VERSION > 2002000 */
    pVBoxAPI->networkRemoveInterface = 1;
#endif /* VBOX_API_VERSION > 2002000 */
}
