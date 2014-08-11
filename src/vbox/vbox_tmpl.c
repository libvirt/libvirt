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
#include "snapshot_conf.h"
#include "vbox_snapshot_conf.h"
#include "network_conf.h"
#include "virerror.h"
#include "domain_event.h"
#include "storage_conf.h"
#include "virstoragefile.h"
#include "viruuid.h"
#include "viralloc.h"
#include "nodeinfo.h"
#include "virlog.h"
#include "vbox_driver.h"
#include "configmake.h"
#include "virfile.h"
#include "fdstream.h"
#include "viruri.h"
#include "virstring.h"
#include "virtime.h"
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
#endif /* VBOX_API_VERSION < 3001000 */

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

#define VBOX_COM_UNALLOC_MEM(arg)                                       \
    do {                                                                \
        if (arg) {                                                      \
            data->pFuncs->pfnComUnallocMem(arg);                        \
            (arg) = NULL;                                               \
        }                                                               \
    } while (0)

#define VBOX_UTF16_TO_UTF8(arg1, arg2)  data->pFuncs->pfnUtf16ToUtf8(arg1, arg2)
#define VBOX_UTF8_TO_UTF16(arg1, arg2)  data->pFuncs->pfnUtf8ToUtf16(arg1, arg2)

#define VBOX_ADDREF(arg) (arg)->vtbl->nsisupports.AddRef((nsISupports *)(arg))

#define VBOX_RELEASE(arg)                                                     \
    do {                                                                      \
        if (arg) {                                                            \
            (arg)->vtbl->nsisupports.Release((nsISupports *)(arg));           \
            (arg) = NULL;                                                     \
        }                                                                     \
    } while (0)

#define VBOX_OBJECT_CHECK(conn, type, value) \
vboxGlobalData *data = conn->privateData;\
type ret = value;\
if (!data->vboxObj) {\
    return ret;\
}

#define VBOX_OBJECT_HOST_CHECK(conn, type, value) \
vboxGlobalData *data = conn->privateData;\
type ret = value;\
IHost *host = NULL;\
if (!data->vboxObj) {\
    return ret;\
}\
data->vboxObj->vtbl->GetHost(data->vboxObj, &host);\
if (!host) {\
    return ret;\
}

#if VBOX_API_VERSION < 3001000

# define VBOX_MEDIUM_RELEASE(arg) \
if (arg)\
    (arg)->vtbl->imedium.nsisupports.Release((nsISupports *)(arg))
# define VBOX_MEDIUM_FUNC_ARG1(object, func, arg1) \
    (object)->vtbl->imedium.func((IMedium *)(object), arg1)
# define VBOX_MEDIUM_FUNC_ARG2(object, func, arg1, arg2) \
    (object)->vtbl->imedium.func((IMedium *)(object), arg1, arg2)

#else  /* VBOX_API_VERSION >= 3001000 */

typedef IMedium IHardDisk;
typedef IMediumAttachment IHardDiskAttachment;
# define MediaState_Inaccessible     MediumState_Inaccessible
# define HardDiskVariant_Standard    MediumVariant_Standard
# define HardDiskVariant_Fixed       MediumVariant_Fixed
# define VBOX_MEDIUM_RELEASE(arg) VBOX_RELEASE(arg)
# define VBOX_MEDIUM_FUNC_ARG1(object, func, arg1) \
    (object)->vtbl->func(object, arg1)
# define VBOX_MEDIUM_FUNC_ARG2(object, func, arg1, arg2) \
    (object)->vtbl->func(object, arg1, arg2)

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

static vboxGlobalData *g_pVBoxGlobalData = NULL;

#endif /* !(VBOX_API_VERSION == 2002000) */

#if VBOX_API_VERSION < 4000000

# define VBOX_OBJECT_GET_MACHINE(/* in */ iid_value, /* out */ machine) \
    data->vboxObj->vtbl->GetMachine(data->vboxObj, iid_value, machine)

# define VBOX_SESSION_OPEN(/* in */ iid_value, /* unused */ machine) \
    data->vboxObj->vtbl->OpenSession(data->vboxObj, data->vboxSession, iid_value)

# define VBOX_SESSION_OPEN_EXISTING(/* in */ iid_value, /* unused */ machine) \
    data->vboxObj->vtbl->OpenExistingSession(data->vboxObj, data->vboxSession, iid_value)

# define VBOX_SESSION_CLOSE() \
    data->vboxSession->vtbl->Close(data->vboxSession)

#else /* VBOX_API_VERSION >= 4000000 */

# define VBOX_OBJECT_GET_MACHINE(/* in */ iid_value, /* out */ machine) \
    data->vboxObj->vtbl->FindMachine(data->vboxObj, iid_value, machine)

# define VBOX_SESSION_OPEN(/* unused */ iid_value, /* in */ machine) \
    machine->vtbl->LockMachine(machine, data->vboxSession, LockType_Write)

# define VBOX_SESSION_OPEN_EXISTING(/* unused */ iid_value, /* in */ machine) \
    machine->vtbl->LockMachine(machine, data->vboxSession, LockType_Shared)

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

    uuidstrdst[0]  = uuidstrsrc[6];
    uuidstrdst[1]  = uuidstrsrc[7];
    uuidstrdst[2]  = uuidstrsrc[4];
    uuidstrdst[3]  = uuidstrsrc[5];
    uuidstrdst[4]  = uuidstrsrc[2];
    uuidstrdst[5]  = uuidstrsrc[3];
    uuidstrdst[6]  = uuidstrsrc[0];
    uuidstrdst[7]  = uuidstrsrc[1];

    uuidstrdst[8]  = uuidstrsrc[8];

    uuidstrdst[9]  = uuidstrsrc[11];
    uuidstrdst[10] = uuidstrsrc[12];
    uuidstrdst[11] = uuidstrsrc[9];
    uuidstrdst[12] = uuidstrsrc[10];

    uuidstrdst[13] = uuidstrsrc[13];

    uuidstrdst[14] = uuidstrsrc[16];
    uuidstrdst[15] = uuidstrsrc[17];
    uuidstrdst[16] = uuidstrsrc[14];
    uuidstrdst[17] = uuidstrsrc[15];

    for (i = 18; i < VIR_UUID_STRING_BUFLEN; i++) {
        uuidstrdst[i] = uuidstrsrc[i];
    }

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

    uuidstrdst[0]  = uuidstrsrc[6];
    uuidstrdst[1]  = uuidstrsrc[7];
    uuidstrdst[2]  = uuidstrsrc[4];
    uuidstrdst[3]  = uuidstrsrc[5];
    uuidstrdst[4]  = uuidstrsrc[2];
    uuidstrdst[5]  = uuidstrsrc[3];
    uuidstrdst[6]  = uuidstrsrc[0];
    uuidstrdst[7]  = uuidstrsrc[1];

    uuidstrdst[8]  = uuidstrsrc[8];

    uuidstrdst[9]  = uuidstrsrc[11];
    uuidstrdst[10] = uuidstrsrc[12];
    uuidstrdst[11] = uuidstrsrc[9];
    uuidstrdst[12] = uuidstrsrc[10];

    uuidstrdst[13] = uuidstrsrc[13];

    uuidstrdst[14] = uuidstrsrc[16];
    uuidstrdst[15] = uuidstrsrc[17];
    uuidstrdst[16] = uuidstrsrc[14];
    uuidstrdst[17] = uuidstrsrc[15];

    for (i = 18; i < VIR_UUID_STRING_BUFLEN; i++) {
        uuidstrdst[i] = uuidstrsrc[i];
    }

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
    if (iid->value == NULL) {
        return;
    }

    if (iid->value != &iid->backing) {
        data->pFuncs->pfnComUnallocMem(iid->value);
    }

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
    if (iid->value != NULL && iid->owner) {
        data->pFuncs->pfnUtf16Free(iid->value);
    }

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
 * function to generate the name for medium,
 * for e.g: hda, sda, etc
 *
 * @returns     null terminated string with device name or NULL
 *              for failures
 * @param       conn            Input Connection Pointer
 * @param       storageBus      Input storage bus type
 * @param       deviceInst      Input device instance number
 * @param       devicePort      Input port number
 * @param       deviceSlot      Input slot number
 * @param       aMaxPortPerInst Input array of max port per device instance
 * @param       aMaxSlotPerPort Input array of max slot per device port
 *
 */
/* This functions is used for 4.2 and later only since vboxDomainGetXMLDesc
 * is rewritten. */
#if VBOX_API_VERSION >= 4002000
static char *vboxGenerateMediumName(PRUint32  storageBus,
                                    PRInt32   deviceInst,
                                    PRInt32   devicePort,
                                    PRInt32   deviceSlot,
                                    PRUint32 *aMaxPortPerInst,
                                    PRUint32 *aMaxSlotPerPort)
{
    const char *prefix = NULL;
    char *name  = NULL;
    int   total = 0;
    PRUint32 maxPortPerInst = 0;
    PRUint32 maxSlotPerPort = 0;

    if (!aMaxPortPerInst ||
        !aMaxSlotPerPort)
        return NULL;

    if ((storageBus < StorageBus_IDE) ||
        (storageBus > StorageBus_Floppy))
        return NULL;

    maxPortPerInst = aMaxPortPerInst[storageBus];
    maxSlotPerPort = aMaxSlotPerPort[storageBus];
    total =   (deviceInst * maxPortPerInst * maxSlotPerPort)
            + (devicePort * maxSlotPerPort)
            + deviceSlot;

    if (storageBus == StorageBus_IDE) {
        prefix = "hd";
    } else if ((storageBus == StorageBus_SATA) ||
               (storageBus == StorageBus_SCSI)) {
        prefix = "sd";
    } else if (storageBus == StorageBus_Floppy) {
        prefix = "fd";
    }

    name = virIndexToDiskName(total, prefix);

    VIR_DEBUG("name=%s, total=%d, storageBus=%u, deviceInst=%d, "
          "devicePort=%d deviceSlot=%d, maxPortPerInst=%u maxSlotPerPort=%u",
          NULLSTR(name), total, storageBus, deviceInst, devicePort,
          deviceSlot, maxPortPerInst, maxSlotPerPort);
    return name;
}
#endif /* VBOX_API_VERSION >= 4002000 */

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
                                 PRUint32   *aMaxPortPerInst,
                                 PRUint32   *aMaxSlotPerPort,
                                 PRUint32    storageBus,
                                 PRInt32    *deviceInst,
                                 PRInt32    *devicePort,
                                 PRInt32    *deviceSlot) {
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
# endif /* VBOX_API_VERSION < 4000000 */

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

/* This function would not be used in 4.0 and 4.1 since
 * vboxDomainGetXMLDesc is written*/
# if VBOX_API_VERSION >= 4002000 || VBOX_API_VERSION < 4000000
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
# endif /* VBOX_API_VERSION >= 4002000 || VBOX_API_VERSION < 4000000 */

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

static PRUnichar *
vboxSocketFormatAddrUtf16(vboxGlobalData *data, virSocketAddrPtr addr)
{
    char *utf8 = NULL;
    PRUnichar *utf16 = NULL;

    utf8 = virSocketAddrFormat(addr);

    if (utf8 == NULL) {
        return NULL;
    }

    VBOX_UTF8_TO_UTF16(utf8, &utf16);
    VIR_FREE(utf8);

    return utf16;
}

static int
vboxSocketParseAddrUtf16(vboxGlobalData *data, const PRUnichar *utf16,
                         virSocketAddrPtr addr)
{
    int result = -1;
    char *utf8 = NULL;

    VBOX_UTF16_TO_UTF8(utf16, &utf8);

    if (virSocketAddrParse(addr, utf8, AF_UNSPEC) < 0) {
        goto cleanup;
    }

    result = 0;

 cleanup:
    VBOX_UTF8_FREE(utf8);

    return result;
}

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
                    IDVDImage *dvdImage          = NULL;
                    PRUnichar *dvdfileUtf16      = NULL;
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
                IHardDisk *hardDisk     = NULL;
                PRUnichar *hddfileUtf16 = NULL;
                vboxIID hdduuid = VBOX_IID_INITIALIZER;
                PRUnichar *hddEmpty     = NULL;
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
                                PRInt32 channel          = 0;
                                PRInt32 device           = 0;
                                PRUnichar *hddcnameUtf16 = NULL;

                                char *hddcname;
                                ignore_value(VIR_STRDUP(hddcname, "IDE"));
                                VBOX_UTF8_TO_UTF16(hddcname, &hddcnameUtf16);
                                VIR_FREE(hddcname);

                                if (STREQ(def->disks[i]->dst, "hda")) {
                                    channel = 0;
                                    device  = 0;
                                } else if (STREQ(def->disks[i]->dst, "hdb")) {
                                    channel = 0;
                                    device  = 1;
                                } else if (STREQ(def->disks[i]->dst, "hdd")) {
                                    channel = 1;
                                    device  = 1;
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
                        IFloppyImage *floppyImage   = NULL;
                        PRUnichar *fdfileUtf16      = NULL;
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
            IMedium   *medium          = NULL;
            PRUnichar *mediumUUID      = NULL;
            PRUnichar *mediumFileUtf16 = NULL;
            PRUint32   storageBus      = StorageBus_Null;
            PRUint32   deviceType      = DeviceType_Null;
            PRInt32    deviceInst      = 0;
            PRInt32    devicePort      = 0;
            PRInt32    deviceSlot      = 0;

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

static int vboxDomainAttachDeviceImpl(virDomainPtr dom,
                                      const char *xml,
                                      int mediaChangeOnly ATTRIBUTE_UNUSED)
{
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    IMachine *machine    = NULL;
    vboxIID iid = VBOX_IID_INITIALIZER;
    PRUint32 state       = MachineState_Null;
    virDomainDefPtr def  = NULL;
    virDomainDeviceDefPtr dev  = NULL;
    nsresult rc;

    if (VIR_ALLOC(def) < 0)
        return ret;

    if (VIR_STRDUP(def->os.type, "hvm") < 0)
        goto cleanup;

    dev = virDomainDeviceDefParse(xml, def, data->caps, data->xmlopt,
                                  VIR_DOMAIN_XML_INACTIVE);
    if (dev == NULL)
        goto cleanup;

    vboxIIDFromUUID(&iid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(iid.value, &machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    if (machine) {
        machine->vtbl->GetState(machine, &state);

        if ((state == MachineState_Running) ||
            (state == MachineState_Paused)) {
            rc = VBOX_SESSION_OPEN_EXISTING(iid.value, machine);
        } else {
            rc = VBOX_SESSION_OPEN(iid.value, machine);
        }
        if (NS_SUCCEEDED(rc)) {
            rc = data->vboxSession->vtbl->GetMachine(data->vboxSession, &machine);
            if (NS_SUCCEEDED(rc) && machine) {
                if (dev->type == VIR_DOMAIN_DEVICE_DISK) {
#if VBOX_API_VERSION < 3001000
                    const char *src = virDomainDiskGetSource(dev->data.disk);
                    int type = virDomainDiskGetType(dev->data.disk);

                    if (dev->data.disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
                        if (type == VIR_STORAGE_TYPE_FILE && src) {
                            IDVDDrive *dvdDrive = NULL;
                            /* Currently CDROM/DVD Drive is always IDE
                             * Secondary Master so neglecting the following
                             * parameter dev->data.disk->bus
                             */
                            machine->vtbl->GetDVDDrive(machine, &dvdDrive);
                            if (dvdDrive) {
                                IDVDImage *dvdImage          = NULL;
                                PRUnichar *dvdfileUtf16      = NULL;
                                vboxIID dvduuid = VBOX_IID_INITIALIZER;
                                vboxIID dvdemptyuuid = VBOX_IID_INITIALIZER;

                                VBOX_UTF8_TO_UTF16(src, &dvdfileUtf16);

                                data->vboxObj->vtbl->FindDVDImage(data->vboxObj, dvdfileUtf16, &dvdImage);
                                if (!dvdImage) {
                                    data->vboxObj->vtbl->OpenDVDImage(data->vboxObj, dvdfileUtf16, dvdemptyuuid.value, &dvdImage);
                                }
                                if (dvdImage) {
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
                                }
                                vboxIIDUnalloc(&dvduuid);
                                VBOX_UTF16_FREE(dvdfileUtf16);
                                VBOX_RELEASE(dvdDrive);
                            }
                        } else if (type == VIR_STORAGE_TYPE_BLOCK) {
                        }
                    } else if (dev->data.disk->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
                        if (type == VIR_STORAGE_TYPE_FILE && src) {
                            IFloppyDrive *floppyDrive;
                            machine->vtbl->GetFloppyDrive(machine, &floppyDrive);
                            if (floppyDrive) {
                                rc = floppyDrive->vtbl->SetEnabled(floppyDrive, 1);
                                if (NS_SUCCEEDED(rc)) {
                                    IFloppyImage *floppyImage   = NULL;
                                    PRUnichar *fdfileUtf16      = NULL;
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
                                }
                                VBOX_RELEASE(floppyDrive);
                            }
                        } else if (type == VIR_STORAGE_TYPE_BLOCK) {
                        }
                    }
#else  /* VBOX_API_VERSION >= 3001000 */
#endif /* VBOX_API_VERSION >= 3001000 */
                } else if (dev->type == VIR_DOMAIN_DEVICE_NET) {
                } else if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV) {
                    if (dev->data.hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {
                        if (dev->data.hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB) {
                        }
                    }
                } else if (dev->type == VIR_DOMAIN_DEVICE_FS &&
                           dev->data.fs->type == VIR_DOMAIN_FS_TYPE_MOUNT) {
                    PRUnichar *nameUtf16;
                    PRUnichar *hostPathUtf16;
                    PRBool writable;

                    VBOX_UTF8_TO_UTF16(dev->data.fs->dst, &nameUtf16);
                    VBOX_UTF8_TO_UTF16(dev->data.fs->src, &hostPathUtf16);
                    writable = !dev->data.fs->readonly;

#if VBOX_API_VERSION < 4000000
                    rc = machine->vtbl->CreateSharedFolder(machine, nameUtf16, hostPathUtf16,
                                                           writable);
#else /* VBOX_API_VERSION >= 4000000 */
                    rc = machine->vtbl->CreateSharedFolder(machine, nameUtf16, hostPathUtf16,
                                                           writable, PR_FALSE);
#endif /* VBOX_API_VERSION >= 4000000 */

                    if (NS_FAILED(rc)) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("could not attach shared folder '%s', rc=%08x"),
                                       dev->data.fs->dst, (unsigned)rc);
                    } else {
                        ret = 0;
                    }

                    VBOX_UTF16_FREE(nameUtf16);
                    VBOX_UTF16_FREE(hostPathUtf16);
                }
                machine->vtbl->SaveSettings(machine);
                VBOX_RELEASE(machine);
            }
            VBOX_SESSION_CLOSE();
        }
    }

 cleanup:
    vboxIIDUnalloc(&iid);
    virDomainDefFree(def);
    virDomainDeviceDefFree(dev);
    return ret;
}

static int vboxDomainUpdateDeviceFlags(virDomainPtr dom, const char *xml,
                                       unsigned int flags)
{
    virCheckFlags(VIR_DOMAIN_AFFECT_CURRENT |
                  VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot modify the persistent configuration of a domain"));
        return -1;
    }

    return vboxDomainAttachDeviceImpl(dom, xml, 1);
}

static int vboxDomainDetachDevice(virDomainPtr dom, const char *xml)
{
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    IMachine *machine    = NULL;
    vboxIID iid = VBOX_IID_INITIALIZER;
    PRUint32 state       = MachineState_Null;
    virDomainDefPtr def  = NULL;
    virDomainDeviceDefPtr dev  = NULL;
    nsresult rc;

    if (VIR_ALLOC(def) < 0)
        return ret;

    if (VIR_STRDUP(def->os.type, "hvm") < 0)
        goto cleanup;

    dev = virDomainDeviceDefParse(xml, def, data->caps, data->xmlopt,
                                  VIR_DOMAIN_XML_INACTIVE);
    if (dev == NULL)
        goto cleanup;

    vboxIIDFromUUID(&iid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(iid.value, &machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        goto cleanup;
    }

    if (machine) {
        machine->vtbl->GetState(machine, &state);

        if ((state == MachineState_Running) ||
            (state == MachineState_Paused)) {
            rc = VBOX_SESSION_OPEN_EXISTING(iid.value, machine);
        } else {
            rc = VBOX_SESSION_OPEN(iid.value, machine);
        }

        if (NS_SUCCEEDED(rc)) {
            rc = data->vboxSession->vtbl->GetMachine(data->vboxSession, &machine);
            if (NS_SUCCEEDED(rc) && machine) {
                if (dev->type == VIR_DOMAIN_DEVICE_DISK) {
#if VBOX_API_VERSION < 3001000
                    int type = virDomainDiskGetType(dev->data.disk);

                    if (dev->data.disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
                        if (type == VIR_STORAGE_TYPE_FILE) {
                            IDVDDrive *dvdDrive = NULL;
                            /* Currently CDROM/DVD Drive is always IDE
                             * Secondary Master so neglecting the following
                             * parameter dev->data.disk->bus
                             */
                            machine->vtbl->GetDVDDrive(machine, &dvdDrive);
                            if (dvdDrive) {
                                rc = dvdDrive->vtbl->Unmount(dvdDrive);
                                if (NS_FAILED(rc)) {
                                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                                   _("could not de-attach the mounted ISO, rc=%08x"),
                                                   (unsigned)rc);
                                } else {
                                    ret = 0;
                                }
                                VBOX_RELEASE(dvdDrive);
                            }
                        } else if (type == VIR_STORAGE_TYPE_BLOCK) {
                        }
                    } else if (dev->data.disk->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
                        if (type == VIR_STORAGE_TYPE_FILE) {
                            IFloppyDrive *floppyDrive;
                            machine->vtbl->GetFloppyDrive(machine, &floppyDrive);
                            if (floppyDrive) {
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
                            }
                        } else if (type == VIR_STORAGE_TYPE_BLOCK) {
                        }
                    }
#else  /* VBOX_API_VERSION >= 3001000 */
#endif /* VBOX_API_VERSION >= 3001000 */
                } else if (dev->type == VIR_DOMAIN_DEVICE_NET) {
                } else if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV) {
                    if (dev->data.hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {
                        if (dev->data.hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB) {
                        }
                    }
                } else if (dev->type == VIR_DOMAIN_DEVICE_FS &&
                           dev->data.fs->type == VIR_DOMAIN_FS_TYPE_MOUNT) {
                    PRUnichar *nameUtf16;

                    VBOX_UTF8_TO_UTF16(dev->data.fs->dst, &nameUtf16);

                    rc = machine->vtbl->RemoveSharedFolder(machine, nameUtf16);

                    if (NS_FAILED(rc)) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("could not detach shared folder '%s', rc=%08x"),
                                       dev->data.fs->dst, (unsigned)rc);
                    } else {
                        ret = 0;
                    }

                    VBOX_UTF16_FREE(nameUtf16);
                }
                machine->vtbl->SaveSettings(machine);
                VBOX_RELEASE(machine);
            }
            VBOX_SESSION_CLOSE();
        }
    }

 cleanup:
    vboxIIDUnalloc(&iid);
    virDomainDefFree(def);
    virDomainDeviceDefFree(dev);
    return ret;
}

static int
vboxDomainDetachDeviceFlags(virDomainPtr dom, const char *xml,
                            unsigned int flags)
{
    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot modify the persistent configuration of a domain"));
        return -1;
    }

    return vboxDomainDetachDevice(dom, xml);
}

static int
vboxDomainSnapshotGetAll(virDomainPtr dom,
                         IMachine *machine,
                         ISnapshot ***snapshots)
{
    vboxIID empty = VBOX_IID_INITIALIZER;
    ISnapshot **list = NULL;
    PRUint32 count;
    nsresult rc;
    unsigned int next;
    unsigned int top;

    rc = machine->vtbl->GetSnapshotCount(machine, &count);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not get snapshot count for domain %s"),
                       dom->name);
        goto error;
    }

    if (count == 0)
        goto out;

    if (VIR_ALLOC_N(list, count) < 0)
        goto error;

#if VBOX_API_VERSION < 4000000
    rc = machine->vtbl->GetSnapshot(machine, empty.value, list);
#else /* VBOX_API_VERSION >= 4000000 */
    rc = machine->vtbl->FindSnapshot(machine, empty.value, list);
#endif /* VBOX_API_VERSION >= 4000000 */
    if (NS_FAILED(rc) || !list[0]) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not get root snapshot for domain %s"),
                       dom->name);
        goto error;
    }

    /* BFS walk through snapshot tree */
    top = 1;
    for (next = 0; next < count; next++) {
        vboxArray children = VBOX_ARRAY_INITIALIZER;
        size_t i;

        if (!list[next]) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected number of snapshots < %u"), count);
            goto error;
        }

        rc = vboxArrayGet(&children, list[next],
                               list[next]->vtbl->GetChildren);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("could not get children snapshots"));
            goto error;
        }
        for (i = 0; i < children.count; i++) {
            ISnapshot *child = children.items[i];
            if (!child)
                continue;
            if (top == count) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unexpected number of snapshots > %u"), count);
                vboxArrayRelease(&children);
                goto error;
            }
            VBOX_ADDREF(child);
            list[top++] = child;
        }
        vboxArrayRelease(&children);
    }

 out:
    *snapshots = list;
    return count;

 error:
    if (list) {
        for (next = 0; next < count; next++)
            VBOX_RELEASE(list[next]);
    }
    VIR_FREE(list);

    return -1;
}

static ISnapshot *
vboxDomainSnapshotGet(vboxGlobalData *data,
                      virDomainPtr dom,
                      IMachine *machine,
                      const char *name)
{
    ISnapshot **snapshots = NULL;
    ISnapshot *snapshot = NULL;
    nsresult rc;
    int count = 0;
    size_t i;

    if ((count = vboxDomainSnapshotGetAll(dom, machine, &snapshots)) < 0)
        goto cleanup;

    for (i = 0; i < count; i++) {
        PRUnichar *nameUtf16;
        char *nameUtf8;

        rc = snapshots[i]->vtbl->GetName(snapshots[i], &nameUtf16);
        if (NS_FAILED(rc) || !nameUtf16) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("could not get snapshot name"));
            goto cleanup;
        }
        VBOX_UTF16_TO_UTF8(nameUtf16, &nameUtf8);
        VBOX_UTF16_FREE(nameUtf16);
        if (STREQ(name, nameUtf8))
            snapshot = snapshots[i];
        VBOX_UTF8_FREE(nameUtf8);

        if (snapshot)
            break;
    }

    if (!snapshot) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("domain %s has no snapshots with name %s"),
                       dom->name, name);
        goto cleanup;
    }

 cleanup:
    if (count > 0) {
        for (i = 0; i < count; i++) {
            if (snapshots[i] != snapshot)
                VBOX_RELEASE(snapshots[i]);
        }
    }
    VIR_FREE(snapshots);
    return snapshot;
}

#if VBOX_API_VERSION >= 4002000
static int vboxCloseDisksRecursively(virDomainPtr dom, char *location)
{
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    nsresult rc;
    size_t i = 0;
    PRUnichar *locationUtf = NULL;
    IMedium *medium = NULL;
    IMedium **children = NULL;
    PRUint32 childrenSize = 0;
    VBOX_UTF8_TO_UTF16(location, &locationUtf);
    rc = data->vboxObj->vtbl->OpenMedium(data->vboxObj,
                                         locationUtf,
                                         DeviceType_HardDisk,
                                         AccessMode_ReadWrite,
                                         false,
                                         &medium);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to open HardDisk, rc=%08x"),
                       (unsigned)rc);
        goto cleanup;
    }
    rc = medium->vtbl->GetChildren(medium, &childrenSize, &children);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s"
                       , _("Unable to get disk children"));
        goto cleanup;
    }
    for (i = 0; i < childrenSize; i++) {
        IMedium *childMedium = children[i];
        if (childMedium) {
            PRUnichar *childLocationUtf = NULL;
            char *childLocation = NULL;
            rc = childMedium->vtbl->GetLocation(childMedium, &childLocationUtf);
            VBOX_UTF16_TO_UTF8(childLocationUtf, &childLocation);
            VBOX_UTF16_FREE(childLocationUtf);
            if (vboxCloseDisksRecursively(dom, childLocation) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s"
                               , _("Unable to close disk children"));
                goto cleanup;
            }
            VIR_FREE(childLocation);
        }
    }
    rc = medium->vtbl->Close(medium);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to close HardDisk, rc=%08x"),
                       (unsigned)rc);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VBOX_UTF16_FREE(locationUtf);
    return ret;
}

static int
vboxSnapshotRedefine(virDomainPtr dom,
                     virDomainSnapshotDefPtr def,
                     bool isCurrent)
{
    /*
     * If your snapshot has a parent,
     * it will only be redefined if you have already
     * redefined the parent.
     *
     * The general algorithm of this function is below :
     * First of all, we are going to create our vboxSnapshotXmlMachinePtr struct from
     * the machine settings path.
     * Then, if the machine current snapshot xml file is saved in the machine location,
     * it means that this snapshot was previously modified by us and has fake disks.
     * Fake disks are added when the flag VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT was not set
     * yet, in order to not corrupt read-only disks. The first thing to do is to remove those
     * disks and restore the read-write disks, if any, in the vboxSnapshotXmlMachinePtr struct.
     * We also delete the current snapshot xml file.
     *
     * After that, we are going to register the snapshot read-only disks that we want to redefine,
     * if they are not in the media registry struct.
     *
     * The next step is to unregister the machine and close all disks.
     *
     * Then, we check if the flag VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE has already been set.
     * If this flag was set, we just add read-write disks to the media registry
     * struct. Otherwise, we save the snapshot xml file into the machine location in order
     * to recover the read-write disks during the next redefine and we create differential disks
     * from the snapshot read-only disks and add them to the media registry struct.
     *
     * Finally, we register the machine with the new virtualbox description file.
     */
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    vboxIID domiid = VBOX_IID_INITIALIZER;
    IMachine *machine = NULL;
    nsresult rc;
    PRUnichar *settingsFilePath = NULL;
    char *settingsFilePath_Utf8 = NULL;
    virVBoxSnapshotConfMachinePtr snapshotMachineDesc = NULL;
    char *currentSnapshotXmlFilePath = NULL;
    PRUnichar *machineNameUtf16 = NULL;
    char *machineName = NULL;
    char **realReadWriteDisksPath = NULL;
    int realReadWriteDisksPathSize = 0;
    char **realReadOnlyDisksPath = NULL;
    int realReadOnlyDisksPathSize = 0;
    virVBoxSnapshotConfSnapshotPtr newSnapshotPtr = NULL;
    unsigned char snapshotUuid[VIR_UUID_BUFLEN];
    int it = 0;
    int jt = 0;
    PRUint32 aMediaSize = 0;
    IMedium **aMedia = NULL;
    char *machineLocationPath = NULL;
    char *nameTmpUse = NULL;
    bool snapshotFileExists = false;
    bool needToChangeStorageController = false;

    vboxIIDFromUUID(&domiid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(domiid.value, &machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching UUID"));
        goto cleanup;
    }

    rc = machine->vtbl->SaveSettings(machine);
    /*It may failed when the machine is not mutable.*/
    rc = machine->vtbl->GetSettingsFilePath(machine, &settingsFilePath);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot get settings file path"));
        goto cleanup;
    }
    VBOX_UTF16_TO_UTF8(settingsFilePath, &settingsFilePath_Utf8);

    /*Getting the machine name to retrieve the machine location path.*/
    rc = machine->vtbl->GetName(machine, &machineNameUtf16);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot get machine name"));
        goto cleanup;
    }
    VBOX_UTF16_TO_UTF8(machineNameUtf16, &machineName);

    if (virAsprintf(&nameTmpUse, "%s.vbox", machineName) < 0)
        goto cleanup;
    machineLocationPath = virStringReplace(settingsFilePath_Utf8, nameTmpUse, "");
    if (machineLocationPath == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to get the machine location path"));
        goto cleanup;
    }

    /*We create the xml struct with the settings file path.*/
    snapshotMachineDesc = virVBoxSnapshotConfLoadVboxFile(settingsFilePath_Utf8, machineLocationPath);
    if (snapshotMachineDesc == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot create a vboxSnapshotXmlPtr"));
        goto cleanup;
    }
    if (snapshotMachineDesc->currentSnapshot != NULL) {
        if (virAsprintf(&currentSnapshotXmlFilePath, "%s%s.xml", machineLocationPath,
                       snapshotMachineDesc->currentSnapshot) < 0)
            goto cleanup;
        snapshotFileExists = virFileExists(currentSnapshotXmlFilePath);
    }

    if (snapshotFileExists) {
        /*
         * We have created fake disks, so we have to remove them and replace them with
         * the read-write disks if there are any. The fake disks will be closed during
         * the machine unregistration.
         */
        if (virVBoxSnapshotConfRemoveFakeDisks(snapshotMachineDesc) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to remove Fake Disks"));
            goto cleanup;
        }
        realReadWriteDisksPathSize = virVBoxSnapshotConfGetRWDisksPathsFromLibvirtXML(currentSnapshotXmlFilePath,
                                                             &realReadWriteDisksPath);
        realReadOnlyDisksPathSize = virVBoxSnapshotConfGetRODisksPathsFromLibvirtXML(currentSnapshotXmlFilePath,
                                                                         &realReadOnlyDisksPath);
        /*The read-only disk number is necessarily greater or equal to the
         *read-write disk number*/
        if (realReadOnlyDisksPathSize < realReadWriteDisksPathSize) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("The read only disk number must be greater or equal to the "
                           " read write disk number"));
            goto cleanup;
        }
        for (it = 0; it < realReadWriteDisksPathSize; it++) {
            virVBoxSnapshotConfHardDiskPtr readWriteDisk = NULL;
            PRUnichar *locationUtf = NULL;
            IMedium *readWriteMedium = NULL;
            PRUnichar *uuidUtf = NULL;
            char *uuid = NULL;
            PRUnichar *formatUtf = NULL;
            char *format = NULL;
            const char *parentUuid = NULL;

            VBOX_UTF8_TO_UTF16(realReadWriteDisksPath[it], &locationUtf);
            rc = data->vboxObj->vtbl->OpenMedium(data->vboxObj,
                                                 locationUtf,
                                                 DeviceType_HardDisk,
                                                 AccessMode_ReadWrite,
                                                 false,
                                                 &readWriteMedium);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to open HardDisk, rc=%08x"),
                               (unsigned)rc);
                VBOX_UTF16_FREE(locationUtf);
                goto cleanup;
            }
            VBOX_UTF16_FREE(locationUtf);

            rc = readWriteMedium->vtbl->GetId(readWriteMedium, &uuidUtf);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unable to get the read write medium id"));
                goto cleanup;
            }
            VBOX_UTF16_TO_UTF8(uuidUtf, &uuid);
            VBOX_UTF16_FREE(uuidUtf);

            rc = readWriteMedium->vtbl->GetFormat(readWriteMedium, &formatUtf);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unable to get the read write medium format"));
                VIR_FREE(uuid);
                goto cleanup;
            }
            VBOX_UTF16_TO_UTF8(formatUtf, &format);
            VBOX_UTF16_FREE(formatUtf);

            if (VIR_ALLOC(readWriteDisk) < 0) {
                VIR_FREE(uuid);
                VIR_FREE(formatUtf);
                goto cleanup;
            }

            readWriteDisk->format = format;
            readWriteDisk->uuid = uuid;
            readWriteDisk->location = realReadWriteDisksPath[it];
            /*
             * We get the current snapshot's read-only disk uuid in order to add the
             * read-write disk to the media registry as it's child. The read-only disk
             * is already in the media registry because it is the fake disk's parent.
             */
            parentUuid = virVBoxSnapshotConfHardDiskUuidByLocation(snapshotMachineDesc,
                                                      realReadOnlyDisksPath[it]);
            if (parentUuid == NULL) {
                VIR_FREE(readWriteDisk);
                goto cleanup;
            }

            if (virVBoxSnapshotConfAddHardDiskToMediaRegistry(readWriteDisk,
                                           snapshotMachineDesc->mediaRegistry,
                                           parentUuid) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unable to add hard disk to media Registry"));
                VIR_FREE(readWriteDisk);
                goto cleanup;
            }
            rc = readWriteMedium->vtbl->Close(readWriteMedium);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to close HardDisk, rc=%08x"),
                               (unsigned)rc);
                goto cleanup;
            }
        }
        /*
         * Now we have done this swap, we remove the snapshot xml file from the
         * current machine location.
         */
        if (unlink(currentSnapshotXmlFilePath) < 0) {
            virReportSystemError(errno,
                                 _("Unable to delete file %s"), currentSnapshotXmlFilePath);
            goto cleanup;
        }
    }
    /*
     * Before unregistering the machine, while all disks are still open, ensure that all
     * read-only disks are in the redefined snapshot's media registry (the disks need to
     * be open to query their uuid).
     */
    for (it = 0; it < def->dom->ndisks; it++) {
        int diskInMediaRegistry = 0;
        IMedium *readOnlyMedium = NULL;
        PRUnichar *locationUtf = NULL;
        PRUnichar *uuidUtf = NULL;
        char *uuid = NULL;
        PRUnichar *formatUtf = NULL;
        char *format = NULL;
        PRUnichar *parentUuidUtf = NULL;
        char *parentUuid = NULL;
        virVBoxSnapshotConfHardDiskPtr readOnlyDisk = NULL;

        diskInMediaRegistry = virVBoxSnapshotConfDiskIsInMediaRegistry(snapshotMachineDesc,
                                                        def->dom->disks[it]->src->path);
        if (diskInMediaRegistry == -1) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to know if disk is in media registry"));
            goto cleanup;
        }
        if (diskInMediaRegistry == 1) /*Nothing to do.*/
            continue;
        /*The read only disk is not in the media registry*/

        VBOX_UTF8_TO_UTF16(def->dom->disks[it]->src->path, &locationUtf);
        rc = data->vboxObj->vtbl->OpenMedium(data->vboxObj,
                                             locationUtf,
                                             DeviceType_HardDisk,
                                             AccessMode_ReadWrite,
                                             false,
                                             &readOnlyMedium);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to open HardDisk, rc=%08x"),
                           (unsigned)rc);
            VBOX_UTF16_FREE(locationUtf);
            goto cleanup;
        }
        VBOX_UTF16_FREE(locationUtf);

        rc = readOnlyMedium->vtbl->GetId(readOnlyMedium, &uuidUtf);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to get hard disk id"));
            goto cleanup;
        }
        VBOX_UTF16_TO_UTF8(uuidUtf, &uuid);
        VBOX_UTF16_FREE(uuidUtf);

        rc = readOnlyMedium->vtbl->GetFormat(readOnlyMedium, &formatUtf);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to get hard disk format"));
            VIR_FREE(uuid);
            goto cleanup;
        }
        VBOX_UTF16_TO_UTF8(formatUtf, &format);
        VBOX_UTF16_FREE(formatUtf);

        /*This disk is already in the media registry*/
        IMedium *parentReadOnlyMedium = NULL;
        rc = readOnlyMedium->vtbl->GetParent(readOnlyMedium, &parentReadOnlyMedium);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to get parent hard disk"));
            VIR_FREE(uuid);
            goto cleanup;
        }

        rc = parentReadOnlyMedium->vtbl->GetId(parentReadOnlyMedium, &parentUuidUtf);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to get hard disk id, rc=%08x"),
                           (unsigned)rc);
            VIR_FREE(uuid);
            goto cleanup;
        }
        VBOX_UTF16_TO_UTF8(parentUuidUtf, &parentUuid);
        VBOX_UTF16_FREE(parentUuidUtf);

        rc = readOnlyMedium->vtbl->Close(readOnlyMedium);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to close HardDisk, rc=%08x"),
                           (unsigned)rc);
            VIR_FREE(uuid);
            VIR_FREE(parentUuid);
            goto cleanup;
        }

        if (VIR_ALLOC(readOnlyDisk) < 0) {
            VIR_FREE(uuid);
            VIR_FREE(parentUuid);
            goto cleanup;
        }

        readOnlyDisk->format = format;
        readOnlyDisk->uuid = uuid;
        if (VIR_STRDUP(readOnlyDisk->location, def->dom->disks[it]->src->path) < 0) {
            VIR_FREE(readOnlyDisk);
            goto cleanup;
        }

        if (virVBoxSnapshotConfAddHardDiskToMediaRegistry(readOnlyDisk, snapshotMachineDesc->mediaRegistry,
                                       parentUuid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to add hard disk to media registry"));
            VIR_FREE(readOnlyDisk);
            goto cleanup;
        }
    }

    /*Now, we can unregister the machine*/
    rc = machine->vtbl->Unregister(machine,
                              CleanupMode_DetachAllReturnHardDisksOnly,
                              &aMediaSize,
                              &aMedia);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to unregister machine, rc=%08x"),
                       (unsigned)rc);
        goto cleanup;
    }
    VBOX_RELEASE(machine);

    /*
     * Unregister the machine, and then close all disks returned by the unregister method.
     * Some close operations will fail because some disks that need to be closed will not
     * be returned by virtualbox. We will close them just after. We have to use this
     * solution because it is the only way to delete fake disks.
     */
    for (it = 0; it < aMediaSize; it++) {
        IMedium *medium = aMedia[it];
        if (medium) {
            PRUnichar *locationUtf16 = NULL;
            char *locationUtf8 = NULL;
            rc = medium->vtbl->GetLocation(medium, &locationUtf16);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unable to get medium location"));
                goto cleanup;
            }
            VBOX_UTF16_TO_UTF8(locationUtf16, &locationUtf8);
            VBOX_UTF16_FREE(locationUtf16);
            if (strstr(locationUtf8, "fake") != NULL) {
                /*we delete the fake disk because we don't need it anymore*/
                IProgress *progress = NULL;
                PRInt32 resultCode = -1;
                rc = medium->vtbl->DeleteStorage(medium, &progress);
                if (NS_FAILED(rc)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Unable to delete medium, rc=%08x"),
                                   (unsigned)rc);
                    VIR_FREE(locationUtf8);
                    goto cleanup;
                }
                progress->vtbl->WaitForCompletion(progress, -1);
                progress->vtbl->GetResultCode(progress, &resultCode);
                if (NS_FAILED(resultCode)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Error while closing medium, rc=%08x"),
                                   (unsigned)resultCode);
                    VIR_FREE(locationUtf8);
                    goto cleanup;
                }
                VBOX_RELEASE(progress);
            } else {
                /*
                 * This a comment from vboxmanage code in the handleUnregisterVM
                 * function in VBoxManageMisc.cpp :
                 * Note that the IMachine::Unregister method will return the medium
                 * reference in a sane order, which means that closing will normally
                 * succeed, unless there is still another machine which uses the
                 * medium. No harm done if we ignore the error.
                 */
                rc = medium->vtbl->Close(medium);
            }
            VBOX_UTF8_FREE(locationUtf8);
        }
    }
    /*Close all disks that failed to close normally.*/
    for (it = 0; it < snapshotMachineDesc->mediaRegistry->ndisks; it++) {
        if (vboxCloseDisksRecursively(dom, snapshotMachineDesc->mediaRegistry->disks[it]->location) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to close recursively all disks"));
            goto cleanup;
        }
    }
    /*Here, all disks are closed or deleted*/

    /*We are now going to create and fill the Snapshot xml struct*/
    if (VIR_ALLOC(newSnapshotPtr) < 0)
        goto cleanup;

    if (virUUIDGenerate(snapshotUuid) < 0)
        goto cleanup;

    char uuidtmp[VIR_UUID_STRING_BUFLEN];
    virUUIDFormat(snapshotUuid, uuidtmp);
    if (VIR_STRDUP(newSnapshotPtr->uuid, uuidtmp) < 0)
        goto cleanup;

    VIR_DEBUG("New snapshot UUID: %s", newSnapshotPtr->uuid);
    if (VIR_STRDUP(newSnapshotPtr->name, def->name) < 0)
        goto cleanup;

    newSnapshotPtr->timeStamp = virTimeStringThen(def->creationTime * 1000);

    if (VIR_STRDUP(newSnapshotPtr->description, def->description) < 0)
        goto cleanup;

    if (VIR_STRDUP(newSnapshotPtr->hardware, snapshotMachineDesc->hardware) < 0)
        goto cleanup;

    if (VIR_STRDUP(newSnapshotPtr->storageController, snapshotMachineDesc->storageController) < 0)
        goto cleanup;

    /*We get the parent disk uuid from the parent disk location to correctly fill the storage controller.*/
    for (it = 0; it < def->dom->ndisks; it++) {
        char *location = NULL;
        const char *uuidReplacing = NULL;
        char **searchResultTab = NULL;
        ssize_t resultSize = 0;
        char *tmp = NULL;

        location = def->dom->disks[it]->src->path;
        if (!location)
            goto cleanup;
        /*Replacing the uuid*/
        uuidReplacing = virVBoxSnapshotConfHardDiskUuidByLocation(snapshotMachineDesc, location);
        if (uuidReplacing == NULL)
            goto cleanup;

        resultSize = virStringSearch(newSnapshotPtr->storageController,
                                     VBOX_UUID_REGEX,
                                     it + 1,
                                     &searchResultTab);
        if (resultSize != it + 1)
            goto cleanup;

        tmp = virStringReplace(newSnapshotPtr->storageController,
                               searchResultTab[it],
                               uuidReplacing);
        virStringFreeList(searchResultTab);
        VIR_FREE(newSnapshotPtr->storageController);
        if (!tmp)
            goto cleanup;
        if (VIR_STRDUP(newSnapshotPtr->storageController, tmp) < 0)
            goto cleanup;

        VIR_FREE(tmp);
    }
    if (virVBoxSnapshotConfAddSnapshotToXmlMachine(newSnapshotPtr, snapshotMachineDesc, def->parent) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to add the snapshot to the machine description"));
        goto cleanup;
    }
    /*
     * We change the current snapshot only if there is no current snapshot or if the
     * snapshotFile exists, otherwise, it means that the correct current snapshot is
     * already set.
     */

    if (snapshotMachineDesc->currentSnapshot == NULL || snapshotFileExists) {
        snapshotMachineDesc->currentSnapshot = newSnapshotPtr->uuid;
        needToChangeStorageController = true;
    }

    /*
     * Open the snapshot's read-write disk's full ancestry to allow opening the
     * read-write disk itself.
     */
    for (it = 0; it < def->dom->ndisks; it++) {
        char *location = NULL;
        virVBoxSnapshotConfHardDiskPtr *hardDiskToOpen = NULL;
        size_t hardDiskToOpenSize = 0;

        location = def->dom->disks[it]->src->path;
        if (!location)
            goto cleanup;

        hardDiskToOpenSize = virVBoxSnapshotConfDiskListToOpen(snapshotMachineDesc,
                                                   &hardDiskToOpen, location);
        for (jt = hardDiskToOpenSize -1; jt >= 0; jt--) {
            IMedium *medium = NULL;
            PRUnichar *locationUtf16 = NULL;
            VBOX_UTF8_TO_UTF16(hardDiskToOpen[jt]->location, &locationUtf16);

            rc = data->vboxObj->vtbl->OpenMedium(data->vboxObj,
                                                 locationUtf16,
                                                 DeviceType_HardDisk,
                                                 AccessMode_ReadWrite,
                                                 false,
                                                 &medium);
            VBOX_UTF16_FREE(locationUtf16);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to open HardDisk, rc=%08x"),
                               (unsigned)rc);
                goto cleanup;
            }
        }
    }
    if (isCurrent || !needToChangeStorageController) {
        /* We don't create a differential hard disk because either the current snapshot
         * has already been defined or the snapshot to redefine is the current snapshot.
         * If the snapshot to redefine is the current snapshot, we add read-write disks in
         * the machine storage controllers.
         */
        for (it = 0; it < def->ndisks; it++) {
            IMedium *medium = NULL;
            PRUnichar *locationUtf16 = NULL;
            virVBoxSnapshotConfHardDiskPtr disk = NULL;
            PRUnichar *formatUtf16 = NULL;
            char *format = NULL;
            PRUnichar *uuidUtf16 = NULL;
            char *uuid = NULL;
            IMedium *parentDisk = NULL;
            PRUnichar *parentUuidUtf16 = NULL;
            char *parentUuid = NULL;

            VBOX_UTF8_TO_UTF16(def->disks[it].src->path, &locationUtf16);
            rc = data->vboxObj->vtbl->OpenMedium(data->vboxObj,
                                                 locationUtf16,
                                                 DeviceType_HardDisk,
                                                 AccessMode_ReadWrite,
                                                 false,
                                                 &medium);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to open HardDisk, rc=%08x"),
                               (unsigned)rc);
                goto cleanup;
            }
            VBOX_UTF16_FREE(locationUtf16);

            if (VIR_ALLOC(disk) < 0)
                goto cleanup;

            rc = medium->vtbl->GetFormat(medium, &formatUtf16);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unable to get disk format"));
                VIR_FREE(disk);
                goto cleanup;
            }

            VBOX_UTF16_TO_UTF8(formatUtf16, &format);
            disk->format = format;
            VBOX_UTF16_FREE(formatUtf16);

            if (VIR_STRDUP(disk->location, def->disks[it].src->path) < 0) {
                VIR_FREE(disk);
                goto cleanup;
            }

            rc = medium->vtbl->GetId(medium, &uuidUtf16);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unable to get disk uuid"));
                VIR_FREE(disk);
                goto cleanup;
            }
            VBOX_UTF16_TO_UTF8(uuidUtf16, &uuid);
            disk->uuid  = uuid;
            VBOX_UTF16_FREE(uuidUtf16);

            rc = medium->vtbl->GetParent(medium, &parentDisk);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unable to get disk parent"));
                VIR_FREE(disk);
                goto cleanup;
            }

            parentDisk->vtbl->GetId(parentDisk, &parentUuidUtf16);
            VBOX_UTF16_TO_UTF8(parentUuidUtf16, &parentUuid);
            VBOX_UTF16_FREE(parentUuidUtf16);
            if (virVBoxSnapshotConfAddHardDiskToMediaRegistry(disk,
                                           snapshotMachineDesc->mediaRegistry,
                                           parentUuid) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unable to add hard disk to the media registry"));
                VIR_FREE(disk);
                goto cleanup;
            }

            if (needToChangeStorageController) {
                /*We need to append this disk in the storage controller*/
                char **searchResultTab = NULL;
                ssize_t resultSize = 0;
                char *tmp = NULL;
                resultSize = virStringSearch(snapshotMachineDesc->storageController,
                                             VBOX_UUID_REGEX,
                                             it + 1,
                                             &searchResultTab);
                if (resultSize != it + 1) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Unable to find UUID %s"), searchResultTab[it]);
                    goto cleanup;
                }

                tmp = virStringReplace(snapshotMachineDesc->storageController,
                                       searchResultTab[it],
                                       disk->uuid);
                virStringFreeList(searchResultTab);
                VIR_FREE(snapshotMachineDesc->storageController);
                if (!tmp)
                    goto cleanup;
                if (VIR_STRDUP(snapshotMachineDesc->storageController, tmp) < 0)
                    goto cleanup;

                VIR_FREE(tmp);
            }
            /*Close disk*/
            rc = medium->vtbl->Close(medium);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to close HardDisk, rc=%08x"),
                               (unsigned)rc);
                goto cleanup;
            }
        }
    } else {
        /*Create a "fake" disk to avoid corrupting children snapshot disks.*/
        for (it = 0; it < def->dom->ndisks; it++) {
            IMedium *medium = NULL;
            PRUnichar *locationUtf16 = NULL;
            PRUnichar *parentUuidUtf16 = NULL;
            char *parentUuid = NULL;
            IMedium *newMedium = NULL;
            PRUnichar *formatUtf16 = NULL;
            PRUnichar *newLocation = NULL;
            char *newLocationUtf8 = NULL;
            PRInt32 resultCode = -1;
            virVBoxSnapshotConfHardDiskPtr disk = NULL;
            PRUnichar *uuidUtf16 = NULL;
            char *uuid = NULL;
            char *format = NULL;
            char **searchResultTab = NULL;
            ssize_t resultSize = 0;
            char *tmp = NULL;

            VBOX_UTF8_TO_UTF16(def->dom->disks[it]->src->path, &locationUtf16);
            rc = data->vboxObj->vtbl->OpenMedium(data->vboxObj,
                                                 locationUtf16,
                                                 DeviceType_HardDisk,
                                                 AccessMode_ReadWrite,
                                                 false,
                                                 &medium);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to open HardDisk, rc=%08x"),
                               (unsigned)rc);
                VBOX_UTF16_FREE(locationUtf16);
                goto cleanup;
            }
            VBOX_UTF16_FREE(locationUtf16);

            rc = medium->vtbl->GetId(medium, &parentUuidUtf16);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to get hardDisk Id, rc=%08x"),
                               (unsigned)rc);
                goto cleanup;
            }
            VBOX_UTF16_TO_UTF8(parentUuidUtf16, &parentUuid);
            VBOX_UTF16_FREE(parentUuidUtf16);
            VBOX_UTF8_TO_UTF16("VDI", &formatUtf16);

            if (virAsprintf(&newLocationUtf8, "%sfakedisk-%d.vdi", machineLocationPath, it) < 0)
                goto cleanup;
            VBOX_UTF8_TO_UTF16(newLocationUtf8, &newLocation);
            rc = data->vboxObj->vtbl->CreateHardDisk(data->vboxObj,
                                                formatUtf16,
                                                newLocation,
                                                &newMedium);
            VBOX_UTF16_FREE(newLocation);
            VBOX_UTF16_FREE(formatUtf16);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to create HardDisk, rc=%08x"),
                               (unsigned)rc);
                goto cleanup;
            }

            IProgress *progress = NULL;
# if VBOX_API_VERSION < 4003000
            medium->vtbl->CreateDiffStorage(medium, newMedium, MediumVariant_Diff, &progress);
# else
            PRUint32 tab[1];
            tab[0] =  MediumVariant_Diff;
            medium->vtbl->CreateDiffStorage(medium, newMedium, 1, tab, &progress);
# endif

            progress->vtbl->WaitForCompletion(progress, -1);
            progress->vtbl->GetResultCode(progress, &resultCode);
            if (NS_FAILED(resultCode)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Error while creating diff storage, rc=%08x"),
                               (unsigned)resultCode);
                goto cleanup;
            }
            VBOX_RELEASE(progress);
            /*
             * The differential disk is created, we add it to the media registry and the
             * machine storage controllers.
             */

            if (VIR_ALLOC(disk) < 0)
                goto cleanup;

            rc = newMedium->vtbl->GetId(newMedium, &uuidUtf16);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to get medium uuid, rc=%08x"),
                               (unsigned)rc);
                goto cleanup;
            }
            VBOX_UTF16_TO_UTF8(uuidUtf16, &uuid);
            disk->uuid = uuid;
            VBOX_UTF16_FREE(uuidUtf16);

            if (VIR_STRDUP(disk->location, newLocationUtf8) < 0)
                goto cleanup;

            rc = newMedium->vtbl->GetFormat(newMedium, &formatUtf16);
            VBOX_UTF16_TO_UTF8(formatUtf16, &format);
            disk->format = format;
            VBOX_UTF16_FREE(formatUtf16);

            if (virVBoxSnapshotConfAddHardDiskToMediaRegistry(disk,
                                           snapshotMachineDesc->mediaRegistry,
                                           parentUuid) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unable to add hard disk to the media registry"));
                goto cleanup;
            }
            /*Adding the fake disk to the machine storage controllers*/

            resultSize = virStringSearch(snapshotMachineDesc->storageController,
                                         VBOX_UUID_REGEX,
                                         it + 1,
                                         &searchResultTab);
            if (resultSize != it + 1) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to find UUID %s"), searchResultTab[it]);
                goto cleanup;
            }

            tmp = virStringReplace(snapshotMachineDesc->storageController,
                                   searchResultTab[it],
                                   disk->uuid);
            virStringFreeList(searchResultTab);
            VIR_FREE(snapshotMachineDesc->storageController);
            if (!tmp)
                goto cleanup;
            if (VIR_STRDUP(snapshotMachineDesc->storageController, tmp) < 0)
                goto cleanup;

            VIR_FREE(tmp);
            /*Closing the "fake" disk*/
            rc = newMedium->vtbl->Close(newMedium);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to close the new medium, rc=%08x"),
                               (unsigned)rc);
                goto cleanup;
            }
        }
        /*
         * We save the snapshot xml file to retrieve the real read-write disk during the
         * next define. This file is saved as "'machineLocation'/snapshot-'uuid'.xml"
         */
        VIR_FREE(currentSnapshotXmlFilePath);
        if (virAsprintf(&currentSnapshotXmlFilePath, "%s%s.xml", machineLocationPath, snapshotMachineDesc->currentSnapshot) < 0)
            goto cleanup;
        char *snapshotContent = virDomainSnapshotDefFormat(NULL, def, VIR_DOMAIN_XML_SECURE, 0);
        if (snapshotContent == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to get snapshot content"));
            goto cleanup;
        }
        if (virFileWriteStr(currentSnapshotXmlFilePath, snapshotContent, 0644) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Unable to save new snapshot xml file"));
            goto cleanup;
        }
        VIR_FREE(snapshotContent);
    }
    /*
     * All the snapshot structure manipulation is done, we close the disks we have
     * previously opened.
     */
    for (it = 0; it < def->dom->ndisks; it++) {
        char *location = def->dom->disks[it]->src->path;
        if (!location)
            goto cleanup;

        virVBoxSnapshotConfHardDiskPtr *hardDiskToOpen = NULL;
        size_t hardDiskToOpenSize = virVBoxSnapshotConfDiskListToOpen(snapshotMachineDesc,
                                                   &hardDiskToOpen, location);
        for (jt = 0; jt < hardDiskToOpenSize; jt++) {
            IMedium *medium = NULL;
            PRUnichar *locationUtf16 = NULL;
            VBOX_UTF8_TO_UTF16(hardDiskToOpen[jt]->location, &locationUtf16);
            rc = data->vboxObj->vtbl->OpenMedium(data->vboxObj,
                                                 locationUtf16,
                                                 DeviceType_HardDisk,
                                                 AccessMode_ReadWrite,
                                                 false,
                                                 &medium);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to open HardDisk, rc=%08x"),
                               (unsigned)rc);
                goto cleanup;
            }
            rc = medium->vtbl->Close(medium);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to close HardDisk, rc=%08x"),
                               (unsigned)rc);
                goto cleanup;
            }
            VBOX_UTF16_FREE(locationUtf16);
        }
    }

    /*Now, we rewrite the 'machineName'.vbox file to redefine the machine.*/
    if (virVBoxSnapshotConfSaveVboxFile(snapshotMachineDesc, settingsFilePath_Utf8) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to serialize the machine description"));
        goto cleanup;
    }
    rc = data->vboxObj->vtbl->OpenMachine(data->vboxObj,
                                     settingsFilePath,
                                     &machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to open Machine, rc=%08x"),
                       (unsigned)rc);
        goto cleanup;
    }

    rc = data->vboxObj->vtbl->RegisterMachine(data->vboxObj, machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to register Machine, rc=%08x"),
                       (unsigned)rc);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VBOX_RELEASE(machine);
    VBOX_UTF16_FREE(settingsFilePath);
    VBOX_UTF8_FREE(settingsFilePath_Utf8);
    VIR_FREE(snapshotMachineDesc);
    VIR_FREE(currentSnapshotXmlFilePath);
    VBOX_UTF16_FREE(machineNameUtf16);
    VBOX_UTF8_FREE(machineName);
    virStringFreeList(realReadOnlyDisksPath);
    virStringFreeList(realReadWriteDisksPath);
    VIR_FREE(newSnapshotPtr);
    VIR_FREE(machineLocationPath);
    VIR_FREE(nameTmpUse);
    return ret;
}
#endif

static virDomainSnapshotPtr
vboxDomainSnapshotCreateXML(virDomainPtr dom,
                            const char *xmlDesc,
                            unsigned int flags)
{
    VBOX_OBJECT_CHECK(dom->conn, virDomainSnapshotPtr, NULL);
    virDomainSnapshotDefPtr def = NULL;
    vboxIID domiid = VBOX_IID_INITIALIZER;
    IMachine *machine = NULL;
    IConsole *console = NULL;
    IProgress *progress = NULL;
    ISnapshot *snapshot = NULL;
    PRUnichar *name = NULL;
    PRUnichar *description = NULL;
    PRUint32 state;
    nsresult rc;
#if VBOX_API_VERSION == 2002000
    nsresult result;
#else
    PRInt32 result;
#endif
#if VBOX_API_VERSION >= 4002000
    bool isCurrent = false;
#endif


    /* VBox has no snapshot metadata, so this flag is trivial.  */
    virCheckFlags(VIR_DOMAIN_SNAPSHOT_CREATE_NO_METADATA |
                  VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE |
                  VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT, NULL);

    if (!(def = virDomainSnapshotDefParseString(xmlDesc, data->caps,
                                                data->xmlopt, -1,
                                                VIR_DOMAIN_SNAPSHOT_PARSE_DISKS |
                                                VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE)))
        goto cleanup;


    vboxIIDFromUUID(&domiid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(domiid.value, &machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching UUID"));
        goto cleanup;
    }

#if VBOX_API_VERSION >= 4002000
    isCurrent = flags & VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT;
    if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE) {
        if (vboxSnapshotRedefine(dom, def, isCurrent) < 0)
            goto cleanup;
        ret = virGetDomainSnapshot(dom, def->name);
        goto cleanup;
    }
#endif

    rc = machine->vtbl->GetState(machine, &state);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not get domain state"));
        goto cleanup;
    }

    if ((state >= MachineState_FirstOnline)
        && (state <= MachineState_LastOnline)) {
        rc = VBOX_SESSION_OPEN_EXISTING(domiid.value, machine);
    } else {
        rc = VBOX_SESSION_OPEN(domiid.value, machine);
    }

    if (NS_SUCCEEDED(rc))
        rc = data->vboxSession->vtbl->GetConsole(data->vboxSession, &console);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not open VirtualBox session with domain %s"),
                       dom->name);
        goto cleanup;
    }

    VBOX_UTF8_TO_UTF16(def->name, &name);
    if (!name) {
        virReportOOMError();
        goto cleanup;
    }

    if (def->description) {
        VBOX_UTF8_TO_UTF16(def->description, &description);
        if (!description) {
            virReportOOMError();
            goto cleanup;
        }
    }

    rc = console->vtbl->TakeSnapshot(console, name, description, &progress);
    if (NS_FAILED(rc) || !progress) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not take snapshot of domain %s"), dom->name);
        goto cleanup;
    }

    progress->vtbl->WaitForCompletion(progress, -1);
    progress->vtbl->GetResultCode(progress, &result);
    if (NS_FAILED(result)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not take snapshot of domain %s"), dom->name);
        goto cleanup;
    }

    rc = machine->vtbl->GetCurrentSnapshot(machine, &snapshot);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not get current snapshot of domain %s"),
                  dom->name);
        goto cleanup;
    }

    ret = virGetDomainSnapshot(dom, def->name);

 cleanup:
    VBOX_RELEASE(progress);
    VBOX_UTF16_FREE(description);
    VBOX_UTF16_FREE(name);
    VBOX_RELEASE(console);
    VBOX_SESSION_CLOSE();
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&domiid);
    virDomainSnapshotDefFree(def);
    return ret;
}

#if VBOX_API_VERSION >=4002000
static
int vboxSnapshotGetReadWriteDisks(virDomainSnapshotDefPtr def,
                                    virDomainSnapshotPtr snapshot)
{
    virDomainPtr dom = snapshot->domain;
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    vboxIID domiid = VBOX_IID_INITIALIZER;
    IMachine *machine = NULL;
    ISnapshot *snap = NULL;
    IMachine *snapMachine = NULL;
    vboxArray mediumAttachments         = VBOX_ARRAY_INITIALIZER;
    PRUint32   maxPortPerInst[StorageBus_Floppy + 1] = {};
    PRUint32   maxSlotPerPort[StorageBus_Floppy + 1] = {};
    int diskCount = 0;
    nsresult rc;
    vboxIID snapIid = VBOX_IID_INITIALIZER;
    char *snapshotUuidStr = NULL;
    size_t i = 0;

    vboxIIDFromUUID(&domiid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(domiid.value, &machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("no domain with matching UUID"));
        goto cleanup;
    }
    if (!(snap = vboxDomainSnapshotGet(data, dom, machine, snapshot->name)))
        goto cleanup;

    rc = snap->vtbl->GetId(snap, &snapIid.value);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not get snapshot id"));
        goto cleanup;
    }

    VBOX_UTF16_TO_UTF8(snapIid.value, &snapshotUuidStr);
    rc = snap->vtbl->GetMachine(snap, &snapMachine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not get machine"));
        goto cleanup;
    }
    def->ndisks = 0;
    rc = vboxArrayGet(&mediumAttachments, snapMachine, snapMachine->vtbl->GetMediumAttachments);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("no medium attachments"));
        goto cleanup;
    }
    /* get the number of attachments */
    for (i = 0; i < mediumAttachments.count; i++) {
        IMediumAttachment *imediumattach = mediumAttachments.items[i];
        if (imediumattach) {
            IMedium *medium = NULL;

            rc = imediumattach->vtbl->GetMedium(imediumattach, &medium);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("cannot get medium"));
                goto cleanup;
            }
            if (medium) {
                def->ndisks++;
                VBOX_RELEASE(medium);
            }
        }
    }
    /* Allocate mem, if fails return error */
    if (VIR_ALLOC_N(def->disks, def->ndisks) < 0)
        goto cleanup;
    for (i = 0; i < def->ndisks; i++) {
        if (VIR_ALLOC(def->disks[i].src) < 0)
            goto cleanup;
    }

    if (!vboxGetMaxPortSlotValues(data->vboxObj, maxPortPerInst, maxSlotPerPort))
        goto cleanup;

    /* get the attachment details here */
    for (i = 0; i < mediumAttachments.count && diskCount < def->ndisks; i++) {
        IStorageController *storageController = NULL;
        PRUnichar *storageControllerName = NULL;
        PRUint32   deviceType     = DeviceType_Null;
        PRUint32   storageBus     = StorageBus_Null;
        IMedium   *disk         = NULL;
        PRUnichar *childLocUtf16 = NULL;
        char      *childLocUtf8  = NULL;
        PRUint32   deviceInst     = 0;
        PRInt32    devicePort     = 0;
        PRInt32    deviceSlot     = 0;
        vboxArray children = VBOX_ARRAY_INITIALIZER;
        vboxArray snapshotIids = VBOX_ARRAY_INITIALIZER;
        IMediumAttachment *imediumattach = mediumAttachments.items[i];
        size_t j = 0;
        size_t k = 0;
        if (!imediumattach)
            continue;
        rc = imediumattach->vtbl->GetMedium(imediumattach, &disk);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot get medium"));
            goto cleanup;
        }
        if (!disk)
            continue;
        rc = imediumattach->vtbl->GetController(imediumattach, &storageControllerName);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot get controller"));
            goto cleanup;
        }
        if (!storageControllerName) {
            VBOX_RELEASE(disk);
            continue;
        }
        rc = vboxArrayGet(&children, disk, disk->vtbl->GetChildren);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot get children disk"));
            goto cleanup;
        }
        rc = vboxArrayGetWithPtrArg(&snapshotIids, disk, disk->vtbl->GetSnapshotIds, domiid.value);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot get snapshot ids"));
            goto cleanup;
        }
        for (j = 0; j < children.count; ++j) {
            IMedium *child = children.items[j];
            for (k = 0; k < snapshotIids.count; ++k) {
                PRUnichar *diskSnapId = snapshotIids.items[k];
                char *diskSnapIdStr = NULL;
                VBOX_UTF16_TO_UTF8(diskSnapId, &diskSnapIdStr);
                if (STREQ(diskSnapIdStr, snapshotUuidStr)) {
                    rc = machine->vtbl->GetStorageControllerByName(machine,
                                                              storageControllerName,
                                                              &storageController);
                    VBOX_UTF16_FREE(storageControllerName);
                    if (!storageController) {
                        VBOX_RELEASE(child);
                        break;
                    }
                    rc = child->vtbl->GetLocation(child, &childLocUtf16);
                    if (NS_FAILED(rc)) {
                        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                       _("cannot get disk location"));
                        goto cleanup;
                    }
                    VBOX_UTF16_TO_UTF8(childLocUtf16, &childLocUtf8);
                    VBOX_UTF16_FREE(childLocUtf16);
                    if (VIR_STRDUP(def->disks[diskCount].src->path, childLocUtf8) < 0) {
                        VBOX_RELEASE(child);
                        VBOX_RELEASE(storageController);
                        goto cleanup;
                    }
                    VBOX_UTF8_FREE(childLocUtf8);

                    rc = storageController->vtbl->GetBus(storageController, &storageBus);
                    if (NS_FAILED(rc)) {
                        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                       _("cannot get storage controller bus"));
                        goto cleanup;
                    }
                    rc = imediumattach->vtbl->GetType(imediumattach, &deviceType);
                    if (NS_FAILED(rc)) {
                        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                       _("cannot get medium attachment type"));
                        goto cleanup;
                    }
                    rc = imediumattach->vtbl->GetPort(imediumattach, &devicePort);
                    if (NS_FAILED(rc)) {
                        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                       _("cannot get medium attachment type"));
                        goto cleanup;
                    }
                    rc = imediumattach->vtbl->GetDevice(imediumattach, &deviceSlot);
                    if (NS_FAILED(rc)) {
                        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                       _("cannot get medium attachment device"));
                        goto cleanup;
                    }
                    def->disks[diskCount].src->type = VIR_STORAGE_TYPE_FILE;
                    def->disks[diskCount].name = vboxGenerateMediumName(storageBus,
                                                                        deviceInst,
                                                                        devicePort,
                                                                        deviceSlot,
                                                                        maxPortPerInst,
                                                                        maxSlotPerPort);
                }
                VBOX_UTF8_FREE(diskSnapIdStr);
            }
        }
        VBOX_RELEASE(storageController);
        VBOX_RELEASE(disk);
        diskCount++;
    }
    vboxArrayRelease(&mediumAttachments);

    ret = 0;
 cleanup:
    if (ret < 0) {
        for (i = 0; i < def->ndisks; i++) {
            VIR_FREE(def->disks[i].src);
        }
        VIR_FREE(def->disks);
        def->ndisks = 0;
    }
    VBOX_RELEASE(snap);
    return ret;
}

static
int vboxSnapshotGetReadOnlyDisks(virDomainSnapshotPtr snapshot,
                                    virDomainSnapshotDefPtr def)
{
    virDomainPtr dom = snapshot->domain;
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    vboxIID domiid = VBOX_IID_INITIALIZER;
    ISnapshot *snap = NULL;
    IMachine *machine = NULL;
    IMachine *snapMachine = NULL;
    IStorageController *storageController = NULL;
    IMedium   *disk         = NULL;
    nsresult rc;
    vboxIIDFromUUID(&domiid, dom->uuid);
    vboxArray mediumAttachments         = VBOX_ARRAY_INITIALIZER;
    size_t i = 0;
    PRUint32   maxPortPerInst[StorageBus_Floppy + 1] = {};
    PRUint32   maxSlotPerPort[StorageBus_Floppy + 1] = {};
    int diskCount = 0;

    rc = VBOX_OBJECT_GET_MACHINE(domiid.value, &machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching UUID"));
        goto cleanup;
    }

    if (!(snap = vboxDomainSnapshotGet(data, dom, machine, snapshot->name)))
        goto cleanup;

    rc = snap->vtbl->GetMachine(snap, &snapMachine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot get machine"));
        goto cleanup;
    }
    /*
     * Get READ ONLY disks
     * In the snapshot metadata, these are the disks written inside the <domain> node
    */
    rc = vboxArrayGet(&mediumAttachments, snapMachine, snapMachine->vtbl->GetMediumAttachments);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot get medium attachments"));
        goto cleanup;
    }
    /* get the number of attachments */
    for (i = 0; i < mediumAttachments.count; i++) {
        IMediumAttachment *imediumattach = mediumAttachments.items[i];
        if (imediumattach) {
            IMedium *medium = NULL;

            rc = imediumattach->vtbl->GetMedium(imediumattach, &medium);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("cannot get medium"));
                goto cleanup;
            }
            if (medium) {
                def->dom->ndisks++;
                VBOX_RELEASE(medium);
            }
        }
    }

    /* Allocate mem, if fails return error */
    if (VIR_ALLOC_N(def->dom->disks, def->dom->ndisks) >= 0) {
        for (i = 0; i < def->dom->ndisks; i++) {
            virDomainDiskDefPtr diskDef = virDomainDiskDefNew();
            if (!diskDef)
                goto cleanup;
            def->dom->disks[i] = diskDef;
        }
    } else {
        goto cleanup;
    }

    if (!vboxGetMaxPortSlotValues(data->vboxObj, maxPortPerInst, maxSlotPerPort))
        goto cleanup;

    /* get the attachment details here */
    for (i = 0; i < mediumAttachments.count && diskCount < def->dom->ndisks; i++) {
        PRUnichar *storageControllerName = NULL;
        PRUint32   deviceType     = DeviceType_Null;
        PRUint32   storageBus     = StorageBus_Null;
        PRBool     readOnly       = PR_FALSE;
        PRUnichar *mediumLocUtf16 = NULL;
        char      *mediumLocUtf8  = NULL;
        PRUint32   deviceInst     = 0;
        PRInt32    devicePort     = 0;
        PRInt32    deviceSlot     = 0;
        IMediumAttachment *imediumattach = mediumAttachments.items[i];
        if (!imediumattach)
            continue;
        rc = imediumattach->vtbl->GetMedium(imediumattach, &disk);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot get medium"));
            goto cleanup;
        }
        if (!disk)
            continue;
        rc = imediumattach->vtbl->GetController(imediumattach, &storageControllerName);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot get storage controller name"));
            goto cleanup;
        }
        if (!storageControllerName)
            continue;
        rc = machine->vtbl->GetStorageControllerByName(machine,
                                                  storageControllerName,
                                                  &storageController);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot get storage controller"));
            goto cleanup;
        }
        VBOX_UTF16_FREE(storageControllerName);
        if (!storageController)
            continue;
        rc = disk->vtbl->GetLocation(disk, &mediumLocUtf16);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot get disk location"));
            goto cleanup;
        }
        VBOX_UTF16_TO_UTF8(mediumLocUtf16, &mediumLocUtf8);
        VBOX_UTF16_FREE(mediumLocUtf16);
        if (VIR_STRDUP(def->dom->disks[diskCount]->src->path, mediumLocUtf8) < 0)
            goto cleanup;

        VBOX_UTF8_FREE(mediumLocUtf8);

        rc = storageController->vtbl->GetBus(storageController, &storageBus);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot get storage controller bus"));
            goto cleanup;
        }
        if (storageBus == StorageBus_IDE) {
            def->dom->disks[diskCount]->bus = VIR_DOMAIN_DISK_BUS_IDE;
        } else if (storageBus == StorageBus_SATA) {
            def->dom->disks[diskCount]->bus = VIR_DOMAIN_DISK_BUS_SATA;
        } else if (storageBus == StorageBus_SCSI) {
            def->dom->disks[diskCount]->bus = VIR_DOMAIN_DISK_BUS_SCSI;
        } else if (storageBus == StorageBus_Floppy) {
            def->dom->disks[diskCount]->bus = VIR_DOMAIN_DISK_BUS_FDC;
        }

        rc = imediumattach->vtbl->GetType(imediumattach, &deviceType);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot get medium attachment type"));
            goto cleanup;
        }
        if (deviceType == DeviceType_HardDisk)
            def->dom->disks[diskCount]->device = VIR_DOMAIN_DISK_DEVICE_DISK;
        else if (deviceType == DeviceType_Floppy)
            def->dom->disks[diskCount]->device = VIR_DOMAIN_DISK_DEVICE_FLOPPY;
        else if (deviceType == DeviceType_DVD)
            def->dom->disks[diskCount]->device = VIR_DOMAIN_DISK_DEVICE_CDROM;

        rc = imediumattach->vtbl->GetPort(imediumattach, &devicePort);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot get medium attachment port"));
            goto cleanup;
        }
        rc = imediumattach->vtbl->GetDevice(imediumattach, &deviceSlot);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot get device"));
            goto cleanup;
        }
        rc = disk->vtbl->GetReadOnly(disk, &readOnly);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot get read only attribute"));
            goto cleanup;
        }
        if (readOnly == PR_TRUE)
            def->dom->disks[diskCount]->src->readonly = true;
        def->dom->disks[diskCount]->src->type = VIR_STORAGE_TYPE_FILE;
        def->dom->disks[diskCount]->dst = vboxGenerateMediumName(storageBus,
                                                                 deviceInst,
                                                                 devicePort,
                                                                 deviceSlot,
                                                                 maxPortPerInst,
                                                                 maxSlotPerPort);
        if (!def->dom->disks[diskCount]->dst) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not generate medium name for the disk "
                             "at: controller instance:%u, port:%d, slot:%d"),
                           deviceInst, devicePort, deviceSlot);
            ret = -1;
            goto cleanup;
        }
        diskCount ++;
    }
    /* cleanup on error */

    ret = 0;
 cleanup:
    if (ret < 0) {
        for (i = 0; i < def->dom->ndisks; i++)
            virDomainDiskDefFree(def->dom->disks[i]);
        VIR_FREE(def->dom->disks);
        def->dom->ndisks = 0;
    }
    VBOX_RELEASE(disk);
    VBOX_RELEASE(storageController);
    vboxArrayRelease(&mediumAttachments);
    VBOX_RELEASE(snap);
    return ret;
}
#endif

static char *
vboxDomainSnapshotGetXMLDesc(virDomainSnapshotPtr snapshot,
                             unsigned int flags)
{
    virDomainPtr dom = snapshot->domain;
    VBOX_OBJECT_CHECK(dom->conn, char *, NULL);
    vboxIID domiid = VBOX_IID_INITIALIZER;
    IMachine *machine = NULL;
    ISnapshot *snap = NULL;
    ISnapshot *parent = NULL;
    nsresult rc;
    virDomainSnapshotDefPtr def = NULL;
    PRUnichar *str16;
    char *str8;
    PRInt64 timestamp;
    PRBool online = PR_FALSE;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
#if VBOX_API_VERSION >=4002000
    PRUint32 memorySize                 = 0;
    PRUint32 CPUCount                 = 0;
#endif

    virCheckFlags(0, NULL);

    vboxIIDFromUUID(&domiid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(domiid.value, &machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching UUID"));
        goto cleanup;
    }

    if (!(snap = vboxDomainSnapshotGet(data, dom, machine, snapshot->name)))
        goto cleanup;

    if (VIR_ALLOC(def) < 0 || VIR_ALLOC(def->dom) < 0)
        goto cleanup;
    if (VIR_STRDUP(def->name, snapshot->name) < 0)
        goto cleanup;

#if VBOX_API_VERSION >=4002000
    /* Register def->dom properties for them to be saved inside the snapshot XMl
     * Otherwise, there is a problem while parsing the xml
     */
    def->dom->virtType = VIR_DOMAIN_VIRT_VBOX;
    def->dom->id = dom->id;
    memcpy(def->dom->uuid, dom->uuid, VIR_UUID_BUFLEN);
    if (VIR_STRDUP(def->dom->name, dom->name) < 0)
        goto cleanup;
    machine->vtbl->GetMemorySize(machine, &memorySize);
    def->dom->mem.cur_balloon = memorySize * 1024;
    /* Currently setting memory and maxMemory as same, cause
     * the notation here seems to be inconsistent while
     * reading and while dumping xml
     */
    def->dom->mem.max_balloon = memorySize * 1024;
    if (VIR_STRDUP(def->dom->os.type, "hvm") < 0)
        goto cleanup;
    def->dom->os.arch = virArchFromHost();
    machine->vtbl->GetCPUCount(machine, &CPUCount);
    def->dom->maxvcpus = def->dom->vcpus = CPUCount;
    if (vboxSnapshotGetReadWriteDisks(def, snapshot) < 0) {
        VIR_DEBUG("Could not get read write disks for snapshot");
    }

    if (vboxSnapshotGetReadOnlyDisks(snapshot, def) < 0) {
        VIR_DEBUG("Could not get Readonly disks for snapshot");
    }
#endif /* VBOX_API_VERSION >= 4002000 */

    rc = snap->vtbl->GetDescription(snap, &str16);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not get description of snapshot %s"),
                       snapshot->name);
        goto cleanup;
    }
    if (str16) {
        VBOX_UTF16_TO_UTF8(str16, &str8);
        VBOX_UTF16_FREE(str16);
        if (VIR_STRDUP(def->description, str8) < 0) {
            VBOX_UTF8_FREE(str8);
            goto cleanup;
        }
        VBOX_UTF8_FREE(str8);
    }

    rc = snap->vtbl->GetTimeStamp(snap, &timestamp);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not get creation time of snapshot %s"),
                       snapshot->name);
        goto cleanup;
    }
    /* timestamp is in milliseconds while creationTime in seconds */
    def->creationTime = timestamp / 1000;

    rc = snap->vtbl->GetParent(snap, &parent);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not get parent of snapshot %s"),
                       snapshot->name);
        goto cleanup;
    }
    if (parent) {
        rc = parent->vtbl->GetName(parent, &str16);
        if (NS_FAILED(rc) || !str16) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("could not get name of parent of snapshot %s"),
                           snapshot->name);
            goto cleanup;
        }
        VBOX_UTF16_TO_UTF8(str16, &str8);
        VBOX_UTF16_FREE(str16);
        if (VIR_STRDUP(def->parent, str8) < 0) {
            VBOX_UTF8_FREE(str8);
            goto cleanup;
        }
        VBOX_UTF8_FREE(str8);
    }

    rc = snap->vtbl->GetOnline(snap, &online);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not get online state of snapshot %s"),
                       snapshot->name);
        goto cleanup;
    }
    if (online)
        def->state = VIR_DOMAIN_RUNNING;
    else
        def->state = VIR_DOMAIN_SHUTOFF;

    virUUIDFormat(dom->uuid, uuidstr);
    memcpy(def->dom->uuid, dom->uuid, VIR_UUID_BUFLEN);
    ret = virDomainSnapshotDefFormat(uuidstr, def, flags, 0);

 cleanup:
    virDomainSnapshotDefFree(def);
    VBOX_RELEASE(parent);
    VBOX_RELEASE(snap);
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&domiid);
    return ret;
}

static int
vboxDomainSnapshotNum(virDomainPtr dom,
                      unsigned int flags)
{
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    vboxIID iid = VBOX_IID_INITIALIZER;
    IMachine *machine = NULL;
    nsresult rc;
    PRUint32 snapshotCount;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_LIST_ROOTS |
                  VIR_DOMAIN_SNAPSHOT_LIST_METADATA, -1);

    vboxIIDFromUUID(&iid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(iid.value, &machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching UUID"));
        goto cleanup;
    }

    /* VBox snapshots do not require libvirt to maintain any metadata.  */
    if (flags & VIR_DOMAIN_SNAPSHOT_LIST_METADATA) {
        ret = 0;
        goto cleanup;
    }

    rc = machine->vtbl->GetSnapshotCount(machine, &snapshotCount);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not get snapshot count for domain %s"),
                       dom->name);
        goto cleanup;
    }

    /* VBox has at most one root snapshot.  */
    if (snapshotCount && (flags & VIR_DOMAIN_SNAPSHOT_LIST_ROOTS))
        ret = 1;
    else
        ret = snapshotCount;

 cleanup:
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    return ret;
}

static int
vboxDomainSnapshotListNames(virDomainPtr dom,
                            char **names,
                            int nameslen,
                            unsigned int flags)
{
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    vboxIID iid = VBOX_IID_INITIALIZER;
    IMachine *machine = NULL;
    nsresult rc;
    ISnapshot **snapshots = NULL;
    int count = 0;
    size_t i;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_LIST_ROOTS |
                  VIR_DOMAIN_SNAPSHOT_LIST_METADATA, -1);

    vboxIIDFromUUID(&iid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(iid.value, &machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching UUID"));
        goto cleanup;
    }

    if (flags & VIR_DOMAIN_SNAPSHOT_LIST_METADATA) {
        ret = 0;
        goto cleanup;
    }

    if (flags & VIR_DOMAIN_SNAPSHOT_LIST_ROOTS) {
        vboxIID empty = VBOX_IID_INITIALIZER;

        if (VIR_ALLOC_N(snapshots, 1) < 0)
            goto cleanup;
#if VBOX_API_VERSION < 4000000
        rc = machine->vtbl->GetSnapshot(machine, empty.value, snapshots);
#else /* VBOX_API_VERSION >= 4000000 */
        rc = machine->vtbl->FindSnapshot(machine, empty.value, snapshots);
#endif /* VBOX_API_VERSION >= 4000000 */
        if (NS_FAILED(rc) || !snapshots[0]) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("could not get root snapshot for domain %s"),
                           dom->name);
            goto cleanup;
        }
        count = 1;
    } else {
        if ((count = vboxDomainSnapshotGetAll(dom, machine, &snapshots)) < 0)
            goto cleanup;
    }

    for (i = 0; i < nameslen; i++) {
        PRUnichar *nameUtf16;
        char *name;

        if (i >= count)
            break;

        rc = snapshots[i]->vtbl->GetName(snapshots[i], &nameUtf16);
        if (NS_FAILED(rc) || !nameUtf16) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("could not get snapshot name"));
            goto cleanup;
        }
        VBOX_UTF16_TO_UTF8(nameUtf16, &name);
        VBOX_UTF16_FREE(nameUtf16);
        if (VIR_STRDUP(names[i], name) < 0) {
            VBOX_UTF8_FREE(name);
            goto cleanup;
        }
        VBOX_UTF8_FREE(name);
    }

    if (count <= nameslen)
        ret = count;
    else
        ret = nameslen;

 cleanup:
    if (count > 0) {
        for (i = 0; i < count; i++)
            VBOX_RELEASE(snapshots[i]);
    }
    VIR_FREE(snapshots);
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    return ret;
}

static virDomainSnapshotPtr
vboxDomainSnapshotLookupByName(virDomainPtr dom,
                               const char *name,
                               unsigned int flags)
{
    VBOX_OBJECT_CHECK(dom->conn, virDomainSnapshotPtr, NULL);
    vboxIID iid = VBOX_IID_INITIALIZER;
    IMachine *machine = NULL;
    ISnapshot *snapshot = NULL;
    nsresult rc;

    virCheckFlags(0, NULL);

    vboxIIDFromUUID(&iid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(iid.value, &machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching UUID"));
        goto cleanup;
    }

    if (!(snapshot = vboxDomainSnapshotGet(data, dom, machine, name)))
        goto cleanup;

    ret = virGetDomainSnapshot(dom, name);

 cleanup:
    VBOX_RELEASE(snapshot);
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    return ret;
}

static int
vboxDomainHasCurrentSnapshot(virDomainPtr dom,
                             unsigned int flags)
{
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    vboxIID iid = VBOX_IID_INITIALIZER;
    IMachine *machine = NULL;
    ISnapshot *snapshot = NULL;
    nsresult rc;

    virCheckFlags(0, -1);

    vboxIIDFromUUID(&iid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(iid.value, &machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching UUID"));
        goto cleanup;
    }

    rc = machine->vtbl->GetCurrentSnapshot(machine, &snapshot);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not get current snapshot"));
        goto cleanup;
    }

    if (snapshot)
        ret = 1;
    else
        ret = 0;

 cleanup:
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    return ret;
}

static virDomainSnapshotPtr
vboxDomainSnapshotGetParent(virDomainSnapshotPtr snapshot,
                            unsigned int flags)
{
    virDomainPtr dom = snapshot->domain;
    VBOX_OBJECT_CHECK(dom->conn, virDomainSnapshotPtr, NULL);
    vboxIID iid = VBOX_IID_INITIALIZER;
    IMachine *machine = NULL;
    ISnapshot *snap = NULL;
    ISnapshot *parent = NULL;
    PRUnichar *nameUtf16 = NULL;
    char *name = NULL;
    nsresult rc;

    virCheckFlags(0, NULL);

    vboxIIDFromUUID(&iid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(iid.value, &machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching UUID"));
        goto cleanup;
    }

    if (!(snap = vboxDomainSnapshotGet(data, dom, machine, snapshot->name)))
        goto cleanup;

    rc = snap->vtbl->GetParent(snap, &parent);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not get parent of snapshot %s"),
                       snapshot->name);
        goto cleanup;
    }
    if (!parent) {
        virReportError(VIR_ERR_NO_DOMAIN_SNAPSHOT,
                       _("snapshot '%s' does not have a parent"),
                       snapshot->name);
        goto cleanup;
    }

    rc = parent->vtbl->GetName(parent, &nameUtf16);
    if (NS_FAILED(rc) || !nameUtf16) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not get name of parent of snapshot %s"),
                       snapshot->name);
        goto cleanup;
    }
    VBOX_UTF16_TO_UTF8(nameUtf16, &name);
    if (!name) {
        virReportOOMError();
        goto cleanup;
    }

    ret = virGetDomainSnapshot(dom, name);

 cleanup:
    VBOX_UTF8_FREE(name);
    VBOX_UTF16_FREE(nameUtf16);
    VBOX_RELEASE(snap);
    VBOX_RELEASE(parent);
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    return ret;
}

static virDomainSnapshotPtr
vboxDomainSnapshotCurrent(virDomainPtr dom,
                          unsigned int flags)
{
    VBOX_OBJECT_CHECK(dom->conn, virDomainSnapshotPtr, NULL);
    vboxIID iid = VBOX_IID_INITIALIZER;
    IMachine *machine = NULL;
    ISnapshot *snapshot = NULL;
    PRUnichar *nameUtf16 = NULL;
    char *name = NULL;
    nsresult rc;

    virCheckFlags(0, NULL);

    vboxIIDFromUUID(&iid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(iid.value, &machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching UUID"));
        goto cleanup;
    }

    rc = machine->vtbl->GetCurrentSnapshot(machine, &snapshot);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not get current snapshot"));
        goto cleanup;
    }

    if (!snapshot) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain has no snapshots"));
        goto cleanup;
    }

    rc = snapshot->vtbl->GetName(snapshot, &nameUtf16);
    if (NS_FAILED(rc) || !nameUtf16) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not get current snapshot name"));
        goto cleanup;
    }

    VBOX_UTF16_TO_UTF8(nameUtf16, &name);
    if (!name) {
        virReportOOMError();
        goto cleanup;
    }

    ret = virGetDomainSnapshot(dom, name);

 cleanup:
    VBOX_UTF8_FREE(name);
    VBOX_UTF16_FREE(nameUtf16);
    VBOX_RELEASE(snapshot);
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    return ret;
}

static int
vboxDomainSnapshotIsCurrent(virDomainSnapshotPtr snapshot,
                            unsigned int flags)
{
    virDomainPtr dom = snapshot->domain;
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    vboxIID iid = VBOX_IID_INITIALIZER;
    IMachine *machine = NULL;
    ISnapshot *snap = NULL;
    ISnapshot *current = NULL;
    PRUnichar *nameUtf16 = NULL;
    char *name = NULL;
    nsresult rc;

    virCheckFlags(0, -1);

    vboxIIDFromUUID(&iid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(iid.value, &machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching UUID"));
        goto cleanup;
    }

    if (!(snap = vboxDomainSnapshotGet(data, dom, machine, snapshot->name)))
        goto cleanup;

    rc = machine->vtbl->GetCurrentSnapshot(machine, &current);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not get current snapshot"));
        goto cleanup;
    }
    if (!current) {
        ret = 0;
        goto cleanup;
    }

    rc = current->vtbl->GetName(current, &nameUtf16);
    if (NS_FAILED(rc) || !nameUtf16) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not get current snapshot name"));
        goto cleanup;
    }

    VBOX_UTF16_TO_UTF8(nameUtf16, &name);
    if (!name) {
        virReportOOMError();
        goto cleanup;
    }

    ret = STREQ(snapshot->name, name);

 cleanup:
    VBOX_UTF8_FREE(name);
    VBOX_UTF16_FREE(nameUtf16);
    VBOX_RELEASE(snap);
    VBOX_RELEASE(current);
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    return ret;
}

static int
vboxDomainSnapshotHasMetadata(virDomainSnapshotPtr snapshot,
                              unsigned int flags)
{
    virDomainPtr dom = snapshot->domain;
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    vboxIID iid = VBOX_IID_INITIALIZER;
    IMachine *machine = NULL;
    ISnapshot *snap = NULL;
    nsresult rc;

    virCheckFlags(0, -1);

    vboxIIDFromUUID(&iid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(iid.value, &machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching UUID"));
        goto cleanup;
    }

    /* Check that snapshot exists.  If so, there is no metadata.  */
    if (!(snap = vboxDomainSnapshotGet(data, dom, machine, snapshot->name)))
        goto cleanup;

    ret = 0;

 cleanup:
    VBOX_RELEASE(snap);
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    return ret;
}

#if VBOX_API_VERSION < 3001000
static int
vboxDomainSnapshotRestore(virDomainPtr dom,
                          IMachine *machine,
                          ISnapshot *snapshot)
{
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    vboxIID iid = VBOX_IID_INITIALIZER;
    nsresult rc;

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
vboxDomainSnapshotRestore(virDomainPtr dom,
                          IMachine *machine,
                          ISnapshot *snapshot)
{
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    IConsole *console = NULL;
    IProgress *progress = NULL;
    PRUint32 state;
    nsresult rc;
    PRInt32 result;
    vboxIID domiid = VBOX_IID_INITIALIZER;

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

static int
vboxDomainRevertToSnapshot(virDomainSnapshotPtr snapshot,
                           unsigned int flags)
{
    virDomainPtr dom = snapshot->domain;
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    vboxIID domiid = VBOX_IID_INITIALIZER;
    IMachine *machine = NULL;
    ISnapshot *newSnapshot = NULL;
    ISnapshot *prevSnapshot = NULL;
    PRBool online = PR_FALSE;
    PRUint32 state;
    nsresult rc;

    virCheckFlags(0, -1);

    vboxIIDFromUUID(&domiid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(domiid.value, &machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching UUID"));
        goto cleanup;
    }

    newSnapshot = vboxDomainSnapshotGet(data, dom, machine, snapshot->name);
    if (!newSnapshot)
        goto cleanup;

    rc = newSnapshot->vtbl->GetOnline(newSnapshot, &online);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not get online state of snapshot %s"),
                       snapshot->name);
        goto cleanup;
    }

    rc = machine->vtbl->GetCurrentSnapshot(machine, &prevSnapshot);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not get current snapshot of domain %s"),
                       dom->name);
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
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot revert snapshot of running domain"));
        goto cleanup;
    }

    if (vboxDomainSnapshotRestore(dom, machine, newSnapshot))
        goto cleanup;

    if (online) {
        ret = vboxDomainCreate(dom);
        if (!ret)
            vboxDomainSnapshotRestore(dom, machine, prevSnapshot);
    } else
        ret = 0;

 cleanup:
    VBOX_RELEASE(prevSnapshot);
    VBOX_RELEASE(newSnapshot);
    vboxIIDUnalloc(&domiid);
    return ret;
}

static int
vboxDomainSnapshotDeleteSingle(vboxGlobalData *data,
                               IConsole *console,
                               ISnapshot *snapshot)
{
    IProgress *progress = NULL;
    vboxIID iid = VBOX_IID_INITIALIZER;
    int ret = -1;
    nsresult rc;
#if VBOX_API_VERSION == 2002000
    nsresult result;
#else
    PRInt32 result;
#endif

    rc = snapshot->vtbl->GetId(snapshot, &iid.value);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not get snapshot UUID"));
        goto cleanup;
    }

#if VBOX_API_VERSION < 3001000
    rc = console->vtbl->DiscardSnapshot(console, iid.value, &progress);
#else
    rc = console->vtbl->DeleteSnapshot(console, iid.value, &progress);
#endif
    if (NS_FAILED(rc) || !progress) {
        if (rc == VBOX_E_INVALID_VM_STATE) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("cannot delete domain snapshot for running domain"));
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("could not delete snapshot"));
        }
        goto cleanup;
    }

    progress->vtbl->WaitForCompletion(progress, -1);
    progress->vtbl->GetResultCode(progress, &result);
    if (NS_FAILED(result)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not delete snapshot"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VBOX_RELEASE(progress);
    vboxIIDUnalloc(&iid);
    return ret;
}

static int
vboxDomainSnapshotDeleteTree(vboxGlobalData *data,
                             IConsole *console,
                             ISnapshot *snapshot)
{
    vboxArray children = VBOX_ARRAY_INITIALIZER;
    int ret = -1;
    nsresult rc;
    size_t i;

    rc = vboxArrayGet(&children, snapshot, snapshot->vtbl->GetChildren);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not get children snapshots"));
        goto cleanup;
    }

    for (i = 0; i < children.count; i++) {
        if (vboxDomainSnapshotDeleteTree(data, console, children.items[i]))
            goto cleanup;
    }

    ret = vboxDomainSnapshotDeleteSingle(data, console, snapshot);

 cleanup:
    vboxArrayRelease(&children);
    return ret;
}

#if VBOX_API_VERSION >= 4002000
static int
vboxDomainSnapshotDeleteMetadataOnly(virDomainSnapshotPtr snapshot)
{
    /*
     * This function will remove the node in the vbox xml corresponding to the snapshot.
     * It is usually called by vboxDomainSnapshotDelete() with the flag
     * VIR_DOMAIN_SNAPSHOT_DELETE_METADATA_ONLY.
     * If you want to use it anywhere else, be careful, if the snapshot you want to delete
     * has children, the result is not granted, they will probably will be deleted in the
     * xml, but you may have a problem with hard drives.
     *
     * If the snapshot which is being deleted is the current one, we will set the current
     * snapshot of the machine to the parent of this snapshot. Before writing the modified
     * xml file, we undefine the machine from vbox. After writing the file, we redefine
     * the machine with the new file.
     */

    virDomainPtr dom = snapshot->domain;
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    virDomainSnapshotDefPtr def = NULL;
    char *defXml = NULL;
    vboxIID domiid = VBOX_IID_INITIALIZER;
    nsresult rc;
    IMachine *machine = NULL;
    PRUnichar *settingsFilePathUtf16 = NULL;
    char *settingsFilepath = NULL;
    virVBoxSnapshotConfMachinePtr snapshotMachineDesc = NULL;
    int isCurrent = -1;
    int it = 0;
    PRUnichar *machineNameUtf16 = NULL;
    char *machineName = NULL;
    char *nameTmpUse = NULL;
    char *machineLocationPath = NULL;
    PRUint32 aMediaSize = 0;
    IMedium **aMedia = NULL;

    defXml = vboxDomainSnapshotGetXMLDesc(snapshot, 0);
    if (!defXml) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to get XML Desc of snapshot"));
        goto cleanup;
    }
    def = virDomainSnapshotDefParseString(defXml,
                                          data->caps,
                                          data->xmlopt,
                                          -1,
                                          VIR_DOMAIN_SNAPSHOT_PARSE_DISKS |
                                          VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE);
    if (!def) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to get a virDomainSnapshotDefPtr"));
        goto cleanup;
    }

    vboxIIDFromUUID(&domiid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(domiid.value, &machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching UUID"));
        goto cleanup;
    }
    rc = machine->vtbl->GetSettingsFilePath(machine, &settingsFilePathUtf16);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot get settings file path"));
        goto cleanup;
    }
    VBOX_UTF16_TO_UTF8(settingsFilePathUtf16, &settingsFilepath);

    /*Getting the machine name to retrieve the machine location path.*/
    rc = machine->vtbl->GetName(machine, &machineNameUtf16);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot get machine name"));
        goto cleanup;
    }
    VBOX_UTF16_TO_UTF8(machineNameUtf16, &machineName);
    if (virAsprintf(&nameTmpUse, "%s.vbox", machineName) < 0)
        goto cleanup;
    machineLocationPath = virStringReplace(settingsFilepath, nameTmpUse, "");
    if (machineLocationPath == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to get the machine location path"));
        goto cleanup;
    }
    snapshotMachineDesc = virVBoxSnapshotConfLoadVboxFile(settingsFilepath, machineLocationPath);
    if (!snapshotMachineDesc) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot create a vboxSnapshotXmlPtr"));
        goto cleanup;
    }

    isCurrent = virVBoxSnapshotConfIsCurrentSnapshot(snapshotMachineDesc, def->name);
    if (isCurrent < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to know if the snapshot is the current snapshot"));
        goto cleanup;
    }
    if (isCurrent) {
        /*
         * If the snapshot is the current snapshot, it means that the machine has read-write
         * disks. The first thing to do is to manipulate VirtualBox API to create
         * differential read-write disks if the parent snapshot is not null.
         */
        if (def->parent != NULL) {
            for (it = 0; it < def->dom->ndisks; it++) {
                virVBoxSnapshotConfHardDiskPtr readOnly = NULL;
                IMedium *medium = NULL;
                PRUnichar *locationUtf16 = NULL;
                PRUnichar *parentUuidUtf16 = NULL;
                char *parentUuid = NULL;
                IMedium *newMedium = NULL;
                PRUnichar *formatUtf16 = NULL;
                PRUnichar *newLocation = NULL;
                char *newLocationUtf8 = NULL;
                IProgress *progress = NULL;
                PRInt32 resultCode = -1;
                virVBoxSnapshotConfHardDiskPtr disk = NULL;
                PRUnichar *uuidUtf16 = NULL;
                char *uuid = NULL;
                char *format = NULL;
                char **searchResultTab = NULL;
                ssize_t resultSize = 0;
                char *tmp = NULL;

                readOnly = virVBoxSnapshotConfHardDiskPtrByLocation(snapshotMachineDesc,
                                                 def->dom->disks[it]->src->path);
                if (!readOnly) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("Cannot get hard disk by location"));
                    goto cleanup;
                }
                if (readOnly->parent == NULL) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("The read only disk has no parent"));
                    goto cleanup;
                }

                VBOX_UTF8_TO_UTF16(readOnly->parent->location, &locationUtf16);
                rc = data->vboxObj->vtbl->OpenMedium(data->vboxObj,
                                                     locationUtf16,
                                                     DeviceType_HardDisk,
                                                     AccessMode_ReadWrite,
                                                     false,
                                                     &medium);
                if (NS_FAILED(rc)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Unable to open HardDisk, rc=%08x"),
                                   (unsigned)rc);
                    goto cleanup;
                }

                rc = medium->vtbl->GetId(medium, &parentUuidUtf16);
                if (NS_FAILED(rc)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Unable to get hardDisk Id, rc=%08x"),
                                   (unsigned)rc);
                    goto cleanup;
                }
                VBOX_UTF16_TO_UTF8(parentUuidUtf16, &parentUuid);
                VBOX_UTF16_FREE(parentUuidUtf16);
                VBOX_UTF16_FREE(locationUtf16);
                VBOX_UTF8_TO_UTF16("VDI", &formatUtf16);

                if (virAsprintf(&newLocationUtf8, "%sfakedisk-%s-%d.vdi",
                                machineLocationPath, def->parent, it) < 0)
                    goto cleanup;
                VBOX_UTF8_TO_UTF16(newLocationUtf8, &newLocation);
                rc = data->vboxObj->vtbl->CreateHardDisk(data->vboxObj,
                                                         formatUtf16,
                                                         newLocation,
                                                         &newMedium);
                if (NS_FAILED(rc)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Unable to create HardDisk, rc=%08x"),
                                   (unsigned)rc);
                    goto cleanup;
                }
                VBOX_UTF16_FREE(formatUtf16);
                VBOX_UTF16_FREE(newLocation);

# if VBOX_API_VERSION < 4003000
                medium->vtbl->CreateDiffStorage(medium, newMedium, MediumVariant_Diff, &progress);
# else
                PRUint32 tab[1];
                tab[0] =  MediumVariant_Diff;
                medium->vtbl->CreateDiffStorage(medium, newMedium, 1, tab, &progress);
# endif

                progress->vtbl->WaitForCompletion(progress, -1);
                progress->vtbl->GetResultCode(progress, &resultCode);
                if (NS_FAILED(resultCode)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Error while creating diff storage, rc=%08x"),
                                   (unsigned)resultCode);
                    goto cleanup;
                }
                VBOX_RELEASE(progress);
                /*
                 * The differential disk is created, we add it to the media registry and
                 * the machine storage controller.
                 */

                if (VIR_ALLOC(disk) < 0)
                    goto cleanup;

                rc = newMedium->vtbl->GetId(newMedium, &uuidUtf16);
                if (NS_FAILED(rc)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Unable to get medium uuid, rc=%08x"),
                                   (unsigned)rc);
                    VIR_FREE(disk);
                    goto cleanup;
                }
                VBOX_UTF16_TO_UTF8(uuidUtf16, &uuid);
                disk->uuid = uuid;
                VBOX_UTF16_FREE(uuidUtf16);

                if (VIR_STRDUP(disk->location, newLocationUtf8) < 0) {
                    VIR_FREE(disk);
                    goto cleanup;
                }

                rc = newMedium->vtbl->GetFormat(newMedium, &formatUtf16);
                VBOX_UTF16_TO_UTF8(formatUtf16, &format);
                disk->format = format;
                VBOX_UTF16_FREE(formatUtf16);

                if (virVBoxSnapshotConfAddHardDiskToMediaRegistry(disk,
                                               snapshotMachineDesc->mediaRegistry,
                                               parentUuid) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("Unable to add hard disk to the media registry"));
                    goto cleanup;
                }
                /*Adding fake disks to the machine storage controllers*/

                resultSize = virStringSearch(snapshotMachineDesc->storageController,
                                             VBOX_UUID_REGEX,
                                             it + 1,
                                             &searchResultTab);
                if (resultSize != it + 1) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Unable to find UUID %s"), searchResultTab[it]);
                    goto cleanup;
                }

                tmp = virStringReplace(snapshotMachineDesc->storageController,
                                       searchResultTab[it],
                                       disk->uuid);
                virStringFreeList(searchResultTab);
                VIR_FREE(snapshotMachineDesc->storageController);
                if (!tmp)
                    goto cleanup;
                if (VIR_STRDUP(snapshotMachineDesc->storageController, tmp) < 0)
                    goto cleanup;

                VIR_FREE(tmp);
                /*Closing the "fake" disk*/
                rc = newMedium->vtbl->Close(newMedium);
                if (NS_FAILED(rc)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Unable to close the new medium, rc=%08x"),
                                   (unsigned)rc);
                    goto cleanup;
                }
            }
        } else {
            for (it = 0; it < def->dom->ndisks; it++) {
                const char *uuidRO = NULL;
                char **searchResultTab = NULL;
                ssize_t resultSize = 0;
                char *tmp = NULL;
                uuidRO = virVBoxSnapshotConfHardDiskUuidByLocation(snapshotMachineDesc,
                                                      def->dom->disks[it]->src->path);
                if (!uuidRO) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("No such disk in media registry %s"),
                                   def->dom->disks[it]->src->path);
                    goto cleanup;
                }

                resultSize = virStringSearch(snapshotMachineDesc->storageController,
                                             VBOX_UUID_REGEX,
                                             it + 1,
                                             &searchResultTab);
                if (resultSize != it + 1) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Unable to find UUID %s"),
                                   searchResultTab[it]);
                    goto cleanup;
                }

                tmp = virStringReplace(snapshotMachineDesc->storageController,
                                       searchResultTab[it],
                                       uuidRO);
                virStringFreeList(searchResultTab);
                VIR_FREE(snapshotMachineDesc->storageController);
                if (!tmp)
                    goto cleanup;
                if (VIR_STRDUP(snapshotMachineDesc->storageController, tmp) < 0)
                    goto cleanup;

                VIR_FREE(tmp);
            }
        }
    }
    /*We remove the read write disks from the media registry*/
    for (it = 0; it < def->ndisks; it++) {
        const char *uuidRW =
            virVBoxSnapshotConfHardDiskUuidByLocation(snapshotMachineDesc,
                                                      def->disks[it].src->path);
        if (!uuidRW) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to find UUID for location %s"), def->disks[it].src->path);
            goto cleanup;
        }
        if (virVBoxSnapshotConfRemoveHardDisk(snapshotMachineDesc->mediaRegistry, uuidRW) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to remove disk from media registry. uuid = %s"), uuidRW);
            goto cleanup;
        }
    }
    /*If the parent snapshot is not NULL, we remove the-read only disks from the media registry*/
    if (def->parent != NULL) {
        for (it = 0; it < def->dom->ndisks; it++) {
            const char *uuidRO =
                virVBoxSnapshotConfHardDiskUuidByLocation(snapshotMachineDesc,
                                                          def->dom->disks[it]->src->path);
            if (!uuidRO) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to find UUID for location %s"), def->dom->disks[it]->src->path);
                goto cleanup;
            }
            if (virVBoxSnapshotConfRemoveHardDisk(snapshotMachineDesc->mediaRegistry, uuidRO) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to remove disk from media registry. uuid = %s"), uuidRO);
                goto cleanup;
            }
        }
    }
    rc = machine->vtbl->Unregister(machine,
                              CleanupMode_DetachAllReturnHardDisksOnly,
                              &aMediaSize,
                              &aMedia);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to unregister machine, rc=%08x"),
                       (unsigned)rc);
        goto cleanup;
    }
    VBOX_RELEASE(machine);
    for (it = 0; it < aMediaSize; it++) {
        IMedium *medium = aMedia[it];
        if (medium) {
            PRUnichar *locationUtf16 = NULL;
            char *locationUtf8 = NULL;
            rc = medium->vtbl->GetLocation(medium, &locationUtf16);
            VBOX_UTF16_TO_UTF8(locationUtf16, &locationUtf8);
            if (isCurrent && strstr(locationUtf8, "fake") != NULL) {
                /*we delete the fake disk because we don't need it anymore*/
                IProgress *progress = NULL;
                PRInt32 resultCode = -1;
                rc = medium->vtbl->DeleteStorage(medium, &progress);
                if (NS_FAILED(rc)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Unable to delete medium, rc=%08x"),
                                   (unsigned)rc);
                    goto cleanup;
                }
                progress->vtbl->WaitForCompletion(progress, -1);
                progress->vtbl->GetResultCode(progress, &resultCode);
                if (NS_FAILED(resultCode)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Error while closing medium, rc=%08x"),
                                   (unsigned)resultCode);
                    goto cleanup;
                }
                VBOX_RELEASE(progress);
            } else {
                /* This a comment from vboxmanage code in the handleUnregisterVM
                 * function in VBoxManageMisc.cpp :
                 * Note that the IMachine::Unregister method will return the medium
                 * reference in a sane order, which means that closing will normally
                 * succeed, unless there is still another machine which uses the
                 * medium. No harm done if we ignore the error. */
                rc = medium->vtbl->Close(medium);
            }
            VBOX_UTF16_FREE(locationUtf16);
            VBOX_UTF8_FREE(locationUtf8);
        }
    }

    /*removing the snapshot*/
    if (virVBoxSnapshotConfRemoveSnapshot(snapshotMachineDesc, def->name) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to remove snapshot %s"), def->name);
        goto cleanup;
    }

    if (isCurrent) {
        VIR_FREE(snapshotMachineDesc->currentSnapshot);
        if (def->parent != NULL) {
            virVBoxSnapshotConfSnapshotPtr snap = virVBoxSnapshotConfSnapshotByName(snapshotMachineDesc->snapshot, def->parent);
            if (!snap) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unable to get the snapshot to remove"));
                goto cleanup;
            }
            if (VIR_STRDUP(snapshotMachineDesc->currentSnapshot, snap->uuid) < 0)
                goto cleanup;
        }
    }

    /*Registering the machine*/
    if (virVBoxSnapshotConfSaveVboxFile(snapshotMachineDesc, settingsFilepath) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to serialize the machine description"));
        goto cleanup;
    }
    rc = data->vboxObj->vtbl->OpenMachine(data->vboxObj,
                                     settingsFilePathUtf16,
                                     &machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to open Machine, rc=%08x"),
                       (unsigned)rc);
        goto cleanup;
    }

    rc = data->vboxObj->vtbl->RegisterMachine(data->vboxObj, machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to register Machine, rc=%08x"),
                       (unsigned)rc);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(def);
    VIR_FREE(defXml);
    VBOX_RELEASE(machine);
    VBOX_UTF16_FREE(settingsFilePathUtf16);
    VBOX_UTF8_FREE(settingsFilepath);
    VIR_FREE(snapshotMachineDesc);
    VBOX_UTF16_FREE(machineNameUtf16);
    VBOX_UTF8_FREE(machineName);
    VIR_FREE(machineLocationPath);
    VIR_FREE(nameTmpUse);

    return ret;
}
#endif

static int
vboxDomainSnapshotDelete(virDomainSnapshotPtr snapshot,
                         unsigned int flags)
{
    virDomainPtr dom = snapshot->domain;
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    vboxIID domiid = VBOX_IID_INITIALIZER;
    IMachine *machine = NULL;
    ISnapshot *snap = NULL;
    IConsole *console = NULL;
    PRUint32 state;
    nsresult rc;
    vboxArray snapChildren = VBOX_ARRAY_INITIALIZER;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN |
                  VIR_DOMAIN_SNAPSHOT_DELETE_METADATA_ONLY, -1);

    vboxIIDFromUUID(&domiid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(domiid.value, &machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching UUID"));
        goto cleanup;
    }

    snap = vboxDomainSnapshotGet(data, dom, machine, snapshot->name);
    if (!snap)
        goto cleanup;

    rc = machine->vtbl->GetState(machine, &state);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not get domain state"));
        goto cleanup;
    }

    /* In case we just want to delete the metadata, we will edit the vbox file in order
     *to remove the node concerning the snapshot
    */
    if (flags & VIR_DOMAIN_SNAPSHOT_DELETE_METADATA_ONLY) {
        rc = vboxArrayGet(&snapChildren, snap, snap->vtbl->GetChildren);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("could not get snapshot children"));
            goto cleanup;
        }
        if (snapChildren.count != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot delete metadata of a snapshot with children"));
            goto cleanup;
        } else {
#if VBOX_API_VERSION >= 4002000
            ret = vboxDomainSnapshotDeleteMetadataOnly(snapshot);
#endif
        }
        goto cleanup;
    }

    if (state >= MachineState_FirstOnline
        && state <= MachineState_LastOnline) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot delete snapshots of running domain"));
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

    if (flags & VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN)
        ret = vboxDomainSnapshotDeleteTree(data, console, snap);
    else
        ret = vboxDomainSnapshotDeleteSingle(data, console, snap);

 cleanup:
    VBOX_RELEASE(console);
    VBOX_RELEASE(snap);
    vboxIIDUnalloc(&domiid);
    VBOX_SESSION_CLOSE();
    return ret;
}

#if VBOX_API_VERSION <= 2002000 || VBOX_API_VERSION >= 4000000
    /* No Callback support for VirtualBox 2.2.* series */
    /* No Callback support for VirtualBox 4.* series */
#else /* !(VBOX_API_VERSION == 2002000 || VBOX_API_VERSION >= 4000000) */

/* Functions needed for Callbacks */
static nsresult PR_COM_METHOD
vboxCallbackOnMachineStateChange(IVirtualBoxCallback *pThis ATTRIBUTE_UNUSED,
                                 PRUnichar *machineId, PRUint32 state)
{
    virDomainPtr dom = NULL;
    int event        = 0;
    int detail       = 0;

    vboxDriverLock(g_pVBoxGlobalData);

    VIR_DEBUG("IVirtualBoxCallback: %p, State: %d", pThis, state);
    DEBUGPRUnichar("machineId", machineId);

    if (machineId) {
        char *machineIdUtf8       = NULL;
        unsigned char uuid[VIR_UUID_BUFLEN];

        g_pVBoxGlobalData->pFuncs->pfnUtf16ToUtf8(machineId, &machineIdUtf8);
        ignore_value(virUUIDParse(machineIdUtf8, uuid));

        dom = vboxDomainLookupByUUID(g_pVBoxGlobalData->conn, uuid);
        if (dom) {
            virObjectEventPtr ev;

            if (state == MachineState_Starting) {
                event  = VIR_DOMAIN_EVENT_STARTED;
                detail = VIR_DOMAIN_EVENT_STARTED_BOOTED;
            } else if (state == MachineState_Restoring) {
                event  = VIR_DOMAIN_EVENT_STARTED;
                detail = VIR_DOMAIN_EVENT_STARTED_RESTORED;
            } else if (state == MachineState_Paused) {
                event  = VIR_DOMAIN_EVENT_SUSPENDED;
                detail = VIR_DOMAIN_EVENT_SUSPENDED_PAUSED;
            } else if (state == MachineState_Running) {
                event  = VIR_DOMAIN_EVENT_RESUMED;
                detail = VIR_DOMAIN_EVENT_RESUMED_UNPAUSED;
            } else if (state == MachineState_PoweredOff) {
                event  = VIR_DOMAIN_EVENT_STOPPED;
                detail = VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN;
            } else if (state == MachineState_Stopping) {
                event  = VIR_DOMAIN_EVENT_STOPPED;
                detail = VIR_DOMAIN_EVENT_STOPPED_DESTROYED;
            } else if (state == MachineState_Aborted) {
                event  = VIR_DOMAIN_EVENT_STOPPED;
                detail = VIR_DOMAIN_EVENT_STOPPED_CRASHED;
            } else if (state == MachineState_Saving) {
                event  = VIR_DOMAIN_EVENT_STOPPED;
                detail = VIR_DOMAIN_EVENT_STOPPED_SAVED;
            } else {
                event  = VIR_DOMAIN_EVENT_STOPPED;
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
    int event        = 0;
    int detail       = 0;

    vboxDriverLock(g_pVBoxGlobalData);

    VIR_DEBUG("IVirtualBoxCallback: %p, registered: %s", pThis, registered ? "true" : "false");
    DEBUGPRUnichar("machineId", machineId);

    if (machineId) {
        char *machineIdUtf8       = NULL;
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
                event  = VIR_DOMAIN_EVENT_DEFINED;
                detail = VIR_DOMAIN_EVENT_DEFINED_ADDED;
            } else {
                event  = VIR_DOMAIN_EVENT_UNDEFINED;
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
    VBOX_OBJECT_CHECK(conn, int, -1);
    int vboxRet          = -1;
    nsresult rc;

    /* Locking has to be there as callbacks are not
     * really fully thread safe
     */
    vboxDriverLock(data);

    if (data->vboxCallback == NULL) {
        data->vboxCallback = vboxAllocCallbackObj();
        if (data->vboxCallback != NULL) {
            rc = data->vboxObj->vtbl->RegisterCallback(data->vboxObj, data->vboxCallback);
            if (NS_SUCCEEDED(rc)) {
                vboxRet = 0;
            }
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
        if (data->vboxObj && data->vboxCallback) {
            data->vboxObj->vtbl->UnregisterCallback(data->vboxObj, data->vboxCallback);
        }
        return -1;
    }
}

static int
vboxConnectDomainEventDeregister(virConnectPtr conn,
                                 virConnectDomainEventCallback callback)
{
    VBOX_OBJECT_CHECK(conn, int, -1);
    int cnt;

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
    VBOX_OBJECT_CHECK(conn, int, -1);
    int vboxRet          = -1;
    nsresult rc;

    /* Locking has to be there as callbacks are not
     * really fully thread safe
     */
    vboxDriverLock(data);

    if (data->vboxCallback == NULL) {
        data->vboxCallback = vboxAllocCallbackObj();
        if (data->vboxCallback != NULL) {
            rc = data->vboxObj->vtbl->RegisterCallback(data->vboxObj, data->vboxCallback);
            if (NS_SUCCEEDED(rc)) {
                vboxRet = 0;
            }
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
        if (data->vboxObj && data->vboxCallback) {
            data->vboxObj->vtbl->UnregisterCallback(data->vboxObj, data->vboxCallback);
        }
        return -1;
    }
}

static int
vboxConnectDomainEventDeregisterAny(virConnectPtr conn,
                                    int callbackID)
{
    VBOX_OBJECT_CHECK(conn, int, -1);
    int cnt;

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

#endif /* !(VBOX_API_VERSION == 2002000 || VBOX_API_VERSION >= 4000000) */

/**
 * The Network Functions here on
 */
static virDrvOpenStatus vboxNetworkOpen(virConnectPtr conn,
                                        virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                        unsigned int flags)
{
    vboxGlobalData *data = conn->privateData;

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (STRNEQ(conn->driver->name, "VBOX"))
        goto cleanup;

    if ((data->pFuncs      == NULL) ||
        (data->vboxObj     == NULL) ||
        (data->vboxSession == NULL))
        goto cleanup;

    VIR_DEBUG("network initialized");
    /* conn->networkPrivateData = some network specific data */
    return VIR_DRV_OPEN_SUCCESS;

 cleanup:
    return VIR_DRV_OPEN_DECLINED;
}

static int vboxNetworkClose(virConnectPtr conn)
{
    VIR_DEBUG("network uninitialized");
    conn->networkPrivateData = NULL;
    return 0;
}

static int vboxConnectNumOfNetworks(virConnectPtr conn)
{
    VBOX_OBJECT_HOST_CHECK(conn, int, 0);
    vboxArray networkInterfaces = VBOX_ARRAY_INITIALIZER;
    size_t i = 0;

    vboxArrayGet(&networkInterfaces, host, host->vtbl->GetNetworkInterfaces);

    for (i = 0; i < networkInterfaces.count; i++) {
        IHostNetworkInterface *networkInterface = networkInterfaces.items[i];

        if (networkInterface) {
            PRUint32 interfaceType = 0;

            networkInterface->vtbl->GetInterfaceType(networkInterface, &interfaceType);
            if (interfaceType == HostNetworkInterfaceType_HostOnly) {
                PRUint32 status = HostNetworkInterfaceStatus_Unknown;

                networkInterface->vtbl->GetStatus(networkInterface, &status);

                if (status == HostNetworkInterfaceStatus_Up)
                    ret++;
            }
        }
    }

    vboxArrayRelease(&networkInterfaces);

    VBOX_RELEASE(host);

    VIR_DEBUG("numActive: %d", ret);
    return ret;
}

static int vboxConnectListNetworks(virConnectPtr conn, char **const names, int nnames) {
    VBOX_OBJECT_HOST_CHECK(conn, int, 0);
    vboxArray networkInterfaces = VBOX_ARRAY_INITIALIZER;
    size_t i = 0;

    vboxArrayGet(&networkInterfaces, host, host->vtbl->GetNetworkInterfaces);

    for (i = 0; (ret < nnames) && (i < networkInterfaces.count); i++) {
        IHostNetworkInterface *networkInterface = networkInterfaces.items[i];

        if (networkInterface) {
            PRUint32 interfaceType = 0;

            networkInterface->vtbl->GetInterfaceType(networkInterface, &interfaceType);

            if (interfaceType == HostNetworkInterfaceType_HostOnly) {
                PRUint32 status = HostNetworkInterfaceStatus_Unknown;

                networkInterface->vtbl->GetStatus(networkInterface, &status);

                if (status == HostNetworkInterfaceStatus_Up) {
                    char *nameUtf8       = NULL;
                    PRUnichar *nameUtf16 = NULL;

                    networkInterface->vtbl->GetName(networkInterface, &nameUtf16);
                    VBOX_UTF16_TO_UTF8(nameUtf16, &nameUtf8);

                    VIR_DEBUG("nnames[%d]: %s", ret, nameUtf8);
                    if (VIR_STRDUP(names[ret], nameUtf8) >= 0)
                        ret++;

                    VBOX_UTF8_FREE(nameUtf8);
                    VBOX_UTF16_FREE(nameUtf16);
                }
            }
        }
    }

    vboxArrayRelease(&networkInterfaces);

    VBOX_RELEASE(host);

    return ret;
}

static int vboxConnectNumOfDefinedNetworks(virConnectPtr conn)
{
    VBOX_OBJECT_HOST_CHECK(conn, int, 0);
    vboxArray networkInterfaces = VBOX_ARRAY_INITIALIZER;
    size_t i = 0;

    vboxArrayGet(&networkInterfaces, host, host->vtbl->GetNetworkInterfaces);

    for (i = 0; i < networkInterfaces.count; i++) {
        IHostNetworkInterface *networkInterface = networkInterfaces.items[i];

        if (networkInterface) {
            PRUint32 interfaceType = 0;

            networkInterface->vtbl->GetInterfaceType(networkInterface, &interfaceType);
            if (interfaceType == HostNetworkInterfaceType_HostOnly) {
                PRUint32 status = HostNetworkInterfaceStatus_Unknown;

                networkInterface->vtbl->GetStatus(networkInterface, &status);

                if (status == HostNetworkInterfaceStatus_Down)
                    ret++;
            }
        }
    }

    vboxArrayRelease(&networkInterfaces);

    VBOX_RELEASE(host);

    VIR_DEBUG("numActive: %d", ret);
    return ret;
}

static int vboxConnectListDefinedNetworks(virConnectPtr conn, char **const names, int nnames) {
    VBOX_OBJECT_HOST_CHECK(conn, int, 0);
    vboxArray networkInterfaces = VBOX_ARRAY_INITIALIZER;
    size_t i = 0;

    vboxArrayGet(&networkInterfaces, host, host->vtbl->GetNetworkInterfaces);

    for (i = 0; (ret < nnames) && (i < networkInterfaces.count); i++) {
        IHostNetworkInterface *networkInterface = networkInterfaces.items[i];

        if (networkInterface) {
            PRUint32 interfaceType = 0;

            networkInterface->vtbl->GetInterfaceType(networkInterface, &interfaceType);

            if (interfaceType == HostNetworkInterfaceType_HostOnly) {
                PRUint32 status = HostNetworkInterfaceStatus_Unknown;

                networkInterface->vtbl->GetStatus(networkInterface, &status);

                if (status == HostNetworkInterfaceStatus_Down) {
                    char *nameUtf8       = NULL;
                    PRUnichar *nameUtf16 = NULL;

                    networkInterface->vtbl->GetName(networkInterface, &nameUtf16);
                    VBOX_UTF16_TO_UTF8(nameUtf16, &nameUtf8);

                    VIR_DEBUG("nnames[%d]: %s", ret, nameUtf8);
                    if (VIR_STRDUP(names[ret], nameUtf8) >= 0)
                        ret++;

                    VBOX_UTF8_FREE(nameUtf8);
                    VBOX_UTF16_FREE(nameUtf16);
                }
            }
        }
    }

    vboxArrayRelease(&networkInterfaces);

    VBOX_RELEASE(host);

    return ret;
}

static virNetworkPtr
vboxNetworkLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    VBOX_OBJECT_HOST_CHECK(conn, virNetworkPtr, NULL);
    vboxIID iid = VBOX_IID_INITIALIZER;

    vboxIIDFromUUID(&iid, uuid);

    /* TODO: "internal" networks are just strings and
     * thus can't do much with them
     */
    IHostNetworkInterface *networkInterface = NULL;

    host->vtbl->FindHostNetworkInterfaceById(host, iid.value, &networkInterface);
    if (networkInterface) {
        PRUint32 interfaceType = 0;

        networkInterface->vtbl->GetInterfaceType(networkInterface, &interfaceType);

        if (interfaceType == HostNetworkInterfaceType_HostOnly) {
            char *nameUtf8       = NULL;
            PRUnichar *nameUtf16 = NULL;

            networkInterface->vtbl->GetName(networkInterface, &nameUtf16);
            VBOX_UTF16_TO_UTF8(nameUtf16, &nameUtf8);

            ret = virGetNetwork(conn, nameUtf8, uuid);

            VIR_DEBUG("Network Name: %s", nameUtf8);
            DEBUGIID("Network UUID", iid.value);

            VBOX_UTF8_FREE(nameUtf8);
            VBOX_UTF16_FREE(nameUtf16);
        }

        VBOX_RELEASE(networkInterface);
    }

    VBOX_RELEASE(host);

    vboxIIDUnalloc(&iid);
    return ret;
}

static virNetworkPtr
vboxNetworkLookupByName(virConnectPtr conn, const char *name)
{
    VBOX_OBJECT_HOST_CHECK(conn, virNetworkPtr, NULL);
    PRUnichar *nameUtf16                    = NULL;
    IHostNetworkInterface *networkInterface = NULL;

    VBOX_UTF8_TO_UTF16(name, &nameUtf16);

    host->vtbl->FindHostNetworkInterfaceByName(host, nameUtf16, &networkInterface);

    if (networkInterface) {
        PRUint32 interfaceType = 0;

        networkInterface->vtbl->GetInterfaceType(networkInterface, &interfaceType);

        if (interfaceType == HostNetworkInterfaceType_HostOnly) {
            unsigned char uuid[VIR_UUID_BUFLEN];
            vboxIID iid = VBOX_IID_INITIALIZER;

            networkInterface->vtbl->GetId(networkInterface, &iid.value);
            vboxIIDToUUID(&iid, uuid);
            ret = virGetNetwork(conn, name, uuid);
            VIR_DEBUG("Network Name: %s", name);

            DEBUGIID("Network UUID", iid.value);
            vboxIIDUnalloc(&iid);
        }

        VBOX_RELEASE(networkInterface);
    }

    VBOX_UTF16_FREE(nameUtf16);
    VBOX_RELEASE(host);

    return ret;
}

static virNetworkPtr
vboxNetworkDefineCreateXML(virConnectPtr conn, const char *xml, bool start)
{
    VBOX_OBJECT_HOST_CHECK(conn, virNetworkPtr, NULL);
    PRUnichar *networkInterfaceNameUtf16    = NULL;
    char      *networkInterfaceNameUtf8     = NULL;
    IHostNetworkInterface *networkInterface = NULL;
    nsresult rc;

    virNetworkDefPtr def = virNetworkDefParseString(xml);
    virNetworkIpDefPtr ipdef;
    virSocketAddr netmask;

    if ((!def) ||
        (def->forward.type != VIR_NETWORK_FORWARD_NONE) ||
        (def->nips == 0 || !def->ips))
        goto cleanup;

    /* Look for the first IPv4 IP address definition and use that.
     * If there weren't any IPv4 addresses, ignore the network (since it's
     * required below to have an IPv4 address)
    */
    ipdef = virNetworkDefGetIpByIndex(def, AF_INET, 0);
    if (!ipdef)
        goto cleanup;

    if (virNetworkIpDefNetmask(ipdef, &netmask) < 0)
        goto cleanup;

    /* the current limitation of hostonly network is that you can't
     * assign a name to it and it defaults to vboxnet*, for e.g:
     * vboxnet0, vboxnet1, etc. Also the UUID is assigned to it
     * automatically depending on the mac address and thus both
     * these paramters are ignored here for now.
     */

#if VBOX_API_VERSION == 2002000
    if (STREQ(def->name, "vboxnet0")) {
        PRUint32 interfaceType = 0;

        VBOX_UTF8_TO_UTF16(def->name, &networkInterfaceNameUtf16);
        host->vtbl->FindHostNetworkInterfaceByName(host, networkInterfaceNameUtf16, &networkInterface);

        networkInterface->vtbl->GetInterfaceType(networkInterface, &interfaceType);
        if (interfaceType != HostNetworkInterfaceType_HostOnly) {
            VBOX_RELEASE(networkInterface);
            networkInterface = NULL;
        }
    }
#else /* VBOX_API_VERSION != 2002000 */
    {
        IProgress *progress = NULL;
        host->vtbl->CreateHostOnlyNetworkInterface(host, &networkInterface,
                                                   &progress);

        if (progress) {
            progress->vtbl->WaitForCompletion(progress, -1);
            VBOX_RELEASE(progress);
        }
    }
#endif /* VBOX_API_VERSION != 2002000 */

    if (networkInterface) {
        unsigned char uuid[VIR_UUID_BUFLEN];
        char      *networkNameUtf8  = NULL;
        PRUnichar *networkNameUtf16 = NULL;
        vboxIID vboxnetiid = VBOX_IID_INITIALIZER;

        networkInterface->vtbl->GetName(networkInterface, &networkInterfaceNameUtf16);
        if (networkInterfaceNameUtf16) {
            VBOX_UTF16_TO_UTF8(networkInterfaceNameUtf16, &networkInterfaceNameUtf8);

            if (virAsprintf(&networkNameUtf8, "HostInterfaceNetworking-%s", networkInterfaceNameUtf8) < 0) {
                VBOX_RELEASE(host);
                VBOX_RELEASE(networkInterface);
                goto cleanup;
            }
        }

        VBOX_UTF8_TO_UTF16(networkNameUtf8, &networkNameUtf16);

        /* Currently support only one dhcp server per network
         * with contigious address space from start to end
         */
        if ((ipdef->nranges >= 1) &&
            VIR_SOCKET_ADDR_VALID(&ipdef->ranges[0].start) &&
            VIR_SOCKET_ADDR_VALID(&ipdef->ranges[0].end)) {
            IDHCPServer *dhcpServer = NULL;

            data->vboxObj->vtbl->FindDHCPServerByNetworkName(data->vboxObj,
                                                             networkNameUtf16,
                                                             &dhcpServer);
            if (!dhcpServer) {
                /* create a dhcp server */
                data->vboxObj->vtbl->CreateDHCPServer(data->vboxObj,
                                                      networkNameUtf16,
                                                      &dhcpServer);
                VIR_DEBUG("couldn't find dhcp server so creating one");
            }
            if (dhcpServer) {
                PRUnichar *ipAddressUtf16     = NULL;
                PRUnichar *networkMaskUtf16   = NULL;
                PRUnichar *fromIPAddressUtf16 = NULL;
                PRUnichar *toIPAddressUtf16   = NULL;
                PRUnichar *trunkTypeUtf16     = NULL;

                ipAddressUtf16 = vboxSocketFormatAddrUtf16(data, &ipdef->address);
                networkMaskUtf16 = vboxSocketFormatAddrUtf16(data, &netmask);
                fromIPAddressUtf16 = vboxSocketFormatAddrUtf16(data, &ipdef->ranges[0].start);
                toIPAddressUtf16 = vboxSocketFormatAddrUtf16(data, &ipdef->ranges[0].end);

                if (ipAddressUtf16 == NULL || networkMaskUtf16 == NULL ||
                    fromIPAddressUtf16 == NULL || toIPAddressUtf16 == NULL) {
                    VBOX_UTF16_FREE(ipAddressUtf16);
                    VBOX_UTF16_FREE(networkMaskUtf16);
                    VBOX_UTF16_FREE(fromIPAddressUtf16);
                    VBOX_UTF16_FREE(toIPAddressUtf16);
                    VBOX_RELEASE(dhcpServer);
                    goto cleanup;
                }

                VBOX_UTF8_TO_UTF16("netflt", &trunkTypeUtf16);

                dhcpServer->vtbl->SetEnabled(dhcpServer, PR_TRUE);

                dhcpServer->vtbl->SetConfiguration(dhcpServer,
                                                   ipAddressUtf16,
                                                   networkMaskUtf16,
                                                   fromIPAddressUtf16,
                                                   toIPAddressUtf16);

                if (start)
                    dhcpServer->vtbl->Start(dhcpServer,
                                            networkNameUtf16,
                                            networkInterfaceNameUtf16,
                                            trunkTypeUtf16);

                VBOX_UTF16_FREE(ipAddressUtf16);
                VBOX_UTF16_FREE(networkMaskUtf16);
                VBOX_UTF16_FREE(fromIPAddressUtf16);
                VBOX_UTF16_FREE(toIPAddressUtf16);
                VBOX_UTF16_FREE(trunkTypeUtf16);
                VBOX_RELEASE(dhcpServer);
            }
        }

        if ((ipdef->nhosts >= 1) &&
            VIR_SOCKET_ADDR_VALID(&ipdef->hosts[0].ip)) {
            PRUnichar *ipAddressUtf16   = NULL;
            PRUnichar *networkMaskUtf16 = NULL;

            ipAddressUtf16 = vboxSocketFormatAddrUtf16(data, &ipdef->hosts[0].ip);
            networkMaskUtf16 = vboxSocketFormatAddrUtf16(data, &netmask);

            if (ipAddressUtf16 == NULL || networkMaskUtf16 == NULL) {
                VBOX_UTF16_FREE(ipAddressUtf16);
                VBOX_UTF16_FREE(networkMaskUtf16);
                goto cleanup;
            }

            /* Current drawback is that since EnableStaticIpConfig() sets
             * IP and enables the interface so even if the dhcpserver is not
             * started the interface is still up and running
             */
#if VBOX_API_VERSION < 4002000
            networkInterface->vtbl->EnableStaticIpConfig(networkInterface,
                                                         ipAddressUtf16,
                                                         networkMaskUtf16);
#else
            networkInterface->vtbl->EnableStaticIPConfig(networkInterface,
                                                         ipAddressUtf16,
                                                         networkMaskUtf16);
#endif

            VBOX_UTF16_FREE(ipAddressUtf16);
            VBOX_UTF16_FREE(networkMaskUtf16);
        } else {
#if VBOX_API_VERSION < 4002000
            networkInterface->vtbl->EnableDynamicIpConfig(networkInterface);
            networkInterface->vtbl->DhcpRediscover(networkInterface);
#else
            networkInterface->vtbl->EnableDynamicIPConfig(networkInterface);
            networkInterface->vtbl->DHCPRediscover(networkInterface);
#endif
        }

        rc = networkInterface->vtbl->GetId(networkInterface, &vboxnetiid.value);
        if (NS_SUCCEEDED(rc)) {
            vboxIIDToUUID(&vboxnetiid, uuid);
            DEBUGIID("Real Network UUID", vboxnetiid.value);
            vboxIIDUnalloc(&vboxnetiid);
            ret = virGetNetwork(conn, networkInterfaceNameUtf8, uuid);
        }

        VIR_FREE(networkNameUtf8);
        VBOX_UTF16_FREE(networkNameUtf16);
        VBOX_RELEASE(networkInterface);
    }

    VBOX_UTF8_FREE(networkInterfaceNameUtf8);
    VBOX_UTF16_FREE(networkInterfaceNameUtf16);
    VBOX_RELEASE(host);

 cleanup:
    virNetworkDefFree(def);
    return ret;
}

static virNetworkPtr vboxNetworkCreateXML(virConnectPtr conn, const char *xml)
{
    return vboxNetworkDefineCreateXML(conn, xml, true);
}

static virNetworkPtr vboxNetworkDefineXML(virConnectPtr conn, const char *xml)
{
    return vboxNetworkDefineCreateXML(conn, xml, false);
}

static int
vboxNetworkUndefineDestroy(virNetworkPtr network, bool removeinterface)
{
    VBOX_OBJECT_HOST_CHECK(network->conn, int, -1);
    char *networkNameUtf8 = NULL;
    PRUnichar *networkInterfaceNameUtf16    = NULL;
    IHostNetworkInterface *networkInterface = NULL;

    /* Current limitation of the function for VirtualBox 2.2.* is
     * that you can't delete the default hostonly adaptor namely:
     * vboxnet0 and thus all this functions does is remove the
     * dhcp server configuration, but the network can still be used
     * by giving the machine static IP and also it will still
     * show up in the net-list in virsh
     */

    if (virAsprintf(&networkNameUtf8, "HostInterfaceNetworking-%s", network->name) < 0)
        goto cleanup;

    VBOX_UTF8_TO_UTF16(network->name, &networkInterfaceNameUtf16);

    host->vtbl->FindHostNetworkInterfaceByName(host, networkInterfaceNameUtf16, &networkInterface);

    if (networkInterface) {
        PRUint32 interfaceType = 0;

        networkInterface->vtbl->GetInterfaceType(networkInterface, &interfaceType);

        if (interfaceType == HostNetworkInterfaceType_HostOnly) {
            PRUnichar *networkNameUtf16 = NULL;
            IDHCPServer *dhcpServer     = NULL;

#if VBOX_API_VERSION != 2002000
            if (removeinterface) {
                PRUnichar *iidUtf16 = NULL;
                IProgress *progress = NULL;

                networkInterface->vtbl->GetId(networkInterface, &iidUtf16);

                if (iidUtf16) {
# if VBOX_API_VERSION == 3000000
                    IHostNetworkInterface *netInt = NULL;
                    host->vtbl->RemoveHostOnlyNetworkInterface(host, iidUtf16, &netInt, &progress);
                    VBOX_RELEASE(netInt);
# else  /* VBOX_API_VERSION > 3000000 */
                    host->vtbl->RemoveHostOnlyNetworkInterface(host, iidUtf16, &progress);
# endif /* VBOX_API_VERSION > 3000000 */
                    VBOX_UTF16_FREE(iidUtf16);
                }

                if (progress) {
                    progress->vtbl->WaitForCompletion(progress, -1);
                    VBOX_RELEASE(progress);
                }
            }
#endif /* VBOX_API_VERSION != 2002000 */

            VBOX_UTF8_TO_UTF16(networkNameUtf8, &networkNameUtf16);

            data->vboxObj->vtbl->FindDHCPServerByNetworkName(data->vboxObj,
                                                             networkNameUtf16,
                                                             &dhcpServer);
            if (dhcpServer) {
                dhcpServer->vtbl->SetEnabled(dhcpServer, PR_FALSE);
                dhcpServer->vtbl->Stop(dhcpServer);
                if (removeinterface)
                    data->vboxObj->vtbl->RemoveDHCPServer(data->vboxObj, dhcpServer);
                VBOX_RELEASE(dhcpServer);
            }

            VBOX_UTF16_FREE(networkNameUtf16);

        }
        VBOX_RELEASE(networkInterface);
    }

    VBOX_UTF16_FREE(networkInterfaceNameUtf16);
    VBOX_RELEASE(host);

    ret = 0;

 cleanup:
    VIR_FREE(networkNameUtf8);
    return ret;
}

static int vboxNetworkUndefine(virNetworkPtr network)
{
    return vboxNetworkUndefineDestroy(network, true);
}

static int vboxNetworkCreate(virNetworkPtr network)
{
    VBOX_OBJECT_HOST_CHECK(network->conn, int, -1);
    char *networkNameUtf8 = NULL;
    PRUnichar *networkInterfaceNameUtf16    = NULL;
    IHostNetworkInterface *networkInterface = NULL;

    /* Current limitation of the function for VirtualBox 2.2.* is
     * that the default hostonly network "vboxnet0" is always active
     * and thus all this functions does is start the dhcp server,
     * but the network can still be used without starting the dhcp
     * server by giving the machine static IP
     */

    if (virAsprintf(&networkNameUtf8, "HostInterfaceNetworking-%s", network->name) < 0)
        goto cleanup;

    VBOX_UTF8_TO_UTF16(network->name, &networkInterfaceNameUtf16);

    host->vtbl->FindHostNetworkInterfaceByName(host, networkInterfaceNameUtf16, &networkInterface);

    if (networkInterface) {
        PRUint32 interfaceType = 0;

        networkInterface->vtbl->GetInterfaceType(networkInterface, &interfaceType);

        if (interfaceType == HostNetworkInterfaceType_HostOnly) {
            PRUnichar *networkNameUtf16 = NULL;
            IDHCPServer *dhcpServer     = NULL;


            VBOX_UTF8_TO_UTF16(networkNameUtf8, &networkNameUtf16);

            data->vboxObj->vtbl->FindDHCPServerByNetworkName(data->vboxObj,
                                                             networkNameUtf16,
                                                             &dhcpServer);
            if (dhcpServer) {
                PRUnichar *trunkTypeUtf16 = NULL;

                dhcpServer->vtbl->SetEnabled(dhcpServer, PR_TRUE);

                VBOX_UTF8_TO_UTF16("netflt", &trunkTypeUtf16);

                dhcpServer->vtbl->Start(dhcpServer,
                                        networkNameUtf16,
                                        networkInterfaceNameUtf16,
                                        trunkTypeUtf16);

                VBOX_UTF16_FREE(trunkTypeUtf16);
                VBOX_RELEASE(dhcpServer);
            }

            VBOX_UTF16_FREE(networkNameUtf16);
        }

        VBOX_RELEASE(networkInterface);
    }

    VBOX_UTF16_FREE(networkInterfaceNameUtf16);
    VBOX_RELEASE(host);

    ret = 0;

 cleanup:
    VIR_FREE(networkNameUtf8);
    return ret;
}

static int vboxNetworkDestroy(virNetworkPtr network)
{
    return vboxNetworkUndefineDestroy(network, false);
}

static char *vboxNetworkGetXMLDesc(virNetworkPtr network,
                                   unsigned int flags)
{
    VBOX_OBJECT_HOST_CHECK(network->conn, char *, NULL);
    virNetworkDefPtr def  = NULL;
    virNetworkIpDefPtr ipdef = NULL;
    char *networkNameUtf8 = NULL;
    PRUnichar *networkInterfaceNameUtf16    = NULL;
    IHostNetworkInterface *networkInterface = NULL;

    virCheckFlags(0, NULL);

    if (VIR_ALLOC(def) < 0)
        goto cleanup;
    if (VIR_ALLOC(ipdef) < 0)
        goto cleanup;
    def->ips = ipdef;
    def->nips = 1;

    if (virAsprintf(&networkNameUtf8, "HostInterfaceNetworking-%s", network->name) < 0)
        goto cleanup;

    VBOX_UTF8_TO_UTF16(network->name, &networkInterfaceNameUtf16);

    host->vtbl->FindHostNetworkInterfaceByName(host, networkInterfaceNameUtf16, &networkInterface);

    if (networkInterface) {
        PRUint32 interfaceType = 0;

        networkInterface->vtbl->GetInterfaceType(networkInterface, &interfaceType);

        if (interfaceType == HostNetworkInterfaceType_HostOnly) {
            if (VIR_STRDUP(def->name, network->name) >= 0) {
                PRUnichar *networkNameUtf16 = NULL;
                IDHCPServer *dhcpServer     = NULL;
                vboxIID vboxnet0IID = VBOX_IID_INITIALIZER;

                networkInterface->vtbl->GetId(networkInterface, &vboxnet0IID.value);
                vboxIIDToUUID(&vboxnet0IID, def->uuid);

                VBOX_UTF8_TO_UTF16(networkNameUtf8, &networkNameUtf16);

                def->forward.type = VIR_NETWORK_FORWARD_NONE;

                data->vboxObj->vtbl->FindDHCPServerByNetworkName(data->vboxObj,
                                                                 networkNameUtf16,
                                                                 &dhcpServer);
                if (dhcpServer) {
                    ipdef->nranges = 1;
                    if (VIR_ALLOC_N(ipdef->ranges, ipdef->nranges) >= 0) {
                        PRUnichar *ipAddressUtf16     = NULL;
                        PRUnichar *networkMaskUtf16   = NULL;
                        PRUnichar *fromIPAddressUtf16 = NULL;
                        PRUnichar *toIPAddressUtf16   = NULL;
                        bool errorOccurred = false;

                        dhcpServer->vtbl->GetIPAddress(dhcpServer, &ipAddressUtf16);
                        dhcpServer->vtbl->GetNetworkMask(dhcpServer, &networkMaskUtf16);
                        dhcpServer->vtbl->GetLowerIP(dhcpServer, &fromIPAddressUtf16);
                        dhcpServer->vtbl->GetUpperIP(dhcpServer, &toIPAddressUtf16);
                        /* Currently virtualbox supports only one dhcp server per network
                         * with contigious address space from start to end
                         */
                        if (vboxSocketParseAddrUtf16(data, ipAddressUtf16,
                                                     &ipdef->address) < 0 ||
                            vboxSocketParseAddrUtf16(data, networkMaskUtf16,
                                                     &ipdef->netmask) < 0 ||
                            vboxSocketParseAddrUtf16(data, fromIPAddressUtf16,
                                                     &ipdef->ranges[0].start) < 0 ||
                            vboxSocketParseAddrUtf16(data, toIPAddressUtf16,
                                                     &ipdef->ranges[0].end) < 0) {
                            errorOccurred = true;
                        }

                        VBOX_UTF16_FREE(ipAddressUtf16);
                        VBOX_UTF16_FREE(networkMaskUtf16);
                        VBOX_UTF16_FREE(fromIPAddressUtf16);
                        VBOX_UTF16_FREE(toIPAddressUtf16);

                        if (errorOccurred) {
                            goto cleanup;
                        }
                    } else {
                        ipdef->nranges = 0;
                    }

                    ipdef->nhosts = 1;
                    if (VIR_ALLOC_N(ipdef->hosts, ipdef->nhosts) >= 0) {
                        if (VIR_STRDUP(ipdef->hosts[0].name, network->name) < 0) {
                            VIR_FREE(ipdef->hosts);
                            ipdef->nhosts = 0;
                        } else {
                            PRUnichar *macAddressUtf16 = NULL;
                            PRUnichar *ipAddressUtf16  = NULL;
                            bool errorOccurred = false;

                            networkInterface->vtbl->GetHardwareAddress(networkInterface, &macAddressUtf16);
                            networkInterface->vtbl->GetIPAddress(networkInterface, &ipAddressUtf16);

                            VBOX_UTF16_TO_UTF8(macAddressUtf16, &ipdef->hosts[0].mac);

                            if (vboxSocketParseAddrUtf16(data, ipAddressUtf16,
                                                         &ipdef->hosts[0].ip) < 0) {
                                errorOccurred = true;
                            }

                            VBOX_UTF16_FREE(macAddressUtf16);
                            VBOX_UTF16_FREE(ipAddressUtf16);

                            if (errorOccurred) {
                                goto cleanup;
                            }
                        }
                    } else {
                        ipdef->nhosts = 0;
                    }

                    VBOX_RELEASE(dhcpServer);
                } else {
                    PRUnichar *networkMaskUtf16 = NULL;
                    PRUnichar *ipAddressUtf16   = NULL;
                    bool errorOccurred = false;

                    networkInterface->vtbl->GetNetworkMask(networkInterface, &networkMaskUtf16);
                    networkInterface->vtbl->GetIPAddress(networkInterface, &ipAddressUtf16);

                    if (vboxSocketParseAddrUtf16(data, networkMaskUtf16,
                                                 &ipdef->netmask) < 0 ||
                        vboxSocketParseAddrUtf16(data, ipAddressUtf16,
                                                 &ipdef->address) < 0) {
                        errorOccurred = true;
                    }

                    VBOX_UTF16_FREE(networkMaskUtf16);
                    VBOX_UTF16_FREE(ipAddressUtf16);

                    if (errorOccurred) {
                        goto cleanup;
                    }
                }

                DEBUGIID("Network UUID", vboxnet0IID.value);
                vboxIIDUnalloc(&vboxnet0IID);
                VBOX_UTF16_FREE(networkNameUtf16);
            }
        }

        VBOX_RELEASE(networkInterface);
    }

    VBOX_UTF16_FREE(networkInterfaceNameUtf16);
    VBOX_RELEASE(host);

    ret = virNetworkDefFormat(def, 0);

 cleanup:
    virNetworkDefFree(def);
    VIR_FREE(networkNameUtf8);
    return ret;
}

/**
 * The Storage Functions here on
 */

static virDrvOpenStatus vboxStorageOpen(virConnectPtr conn,
                                        virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                        unsigned int flags)
{
    vboxGlobalData *data = conn->privateData;

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (STRNEQ(conn->driver->name, "VBOX"))
        return VIR_DRV_OPEN_DECLINED;

    if ((data->pFuncs      == NULL) ||
        (data->vboxObj     == NULL) ||
        (data->vboxSession == NULL))
        return VIR_DRV_OPEN_ERROR;

    VIR_DEBUG("vbox storage initialized");
    /* conn->storagePrivateData = some storage specific data */
    return VIR_DRV_OPEN_SUCCESS;
}

static int vboxStorageClose(virConnectPtr conn)
{
    VIR_DEBUG("vbox storage uninitialized");
    conn->storagePrivateData = NULL;
    return 0;
}

static int vboxConnectNumOfStoragePools(virConnectPtr conn ATTRIBUTE_UNUSED)
{

    /** Currently only one pool supported, the default one
     * given by ISystemProperties::defaultHardDiskFolder()
     */

    return 1;
}

static int vboxConnectListStoragePools(virConnectPtr conn ATTRIBUTE_UNUSED,
                                       char **const names, int nnames) {
    int numActive = 0;

    if (nnames == 1 &&
        VIR_STRDUP(names[numActive], "default-pool") > 0)
        numActive++;
    return numActive;
}

static virStoragePoolPtr
vboxStoragePoolLookupByName(virConnectPtr conn, const char *name)
{
    virStoragePoolPtr ret = NULL;

    /** Current limitation of the function: since
     * the default pool doesn't have UUID just assign
     * one till vbox can handle pools
     */
    if (STREQ("default-pool", name)) {
        unsigned char uuid[VIR_UUID_BUFLEN];
        const char *uuidstr = "1deff1ff-1481-464f-967f-a50fe8936cc4";

        ignore_value(virUUIDParse(uuidstr, uuid));

        ret = virGetStoragePool(conn, name, uuid, NULL, NULL);
    }

    return ret;
}

static int vboxStoragePoolNumOfVolumes(virStoragePoolPtr pool)
{
    VBOX_OBJECT_CHECK(pool->conn, int, -1);
    vboxArray hardDisks = VBOX_ARRAY_INITIALIZER;
    PRUint32 hardDiskAccessible = 0;
    nsresult rc;
    size_t i;

    rc = vboxArrayGet(&hardDisks, data->vboxObj, data->vboxObj->vtbl->GetHardDisks);
    if (NS_SUCCEEDED(rc)) {
        for (i = 0; i < hardDisks.count; ++i) {
            IHardDisk *hardDisk = hardDisks.items[i];
            if (hardDisk) {
                PRUint32 hddstate;

                VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetState, &hddstate);
                if (hddstate != MediaState_Inaccessible)
                    hardDiskAccessible++;
            }
        }

        vboxArrayRelease(&hardDisks);

        ret = hardDiskAccessible;
    } else {
        ret = -1;
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not get number of volumes in the pool: %s, rc=%08x"),
                       pool->name, (unsigned)rc);
    }

    return ret;
}

static int vboxStoragePoolListVolumes(virStoragePoolPtr pool, char **const names, int nnames) {
    VBOX_OBJECT_CHECK(pool->conn, int, -1);
    vboxArray hardDisks = VBOX_ARRAY_INITIALIZER;
    PRUint32 numActive     = 0;
    nsresult rc;
    size_t i;

    rc = vboxArrayGet(&hardDisks, data->vboxObj, data->vboxObj->vtbl->GetHardDisks);
    if (NS_SUCCEEDED(rc)) {
        for (i = 0; i < hardDisks.count && numActive < nnames; ++i) {
            IHardDisk *hardDisk = hardDisks.items[i];

            if (hardDisk) {
                PRUint32 hddstate;
                char      *nameUtf8  = NULL;
                PRUnichar *nameUtf16 = NULL;

                VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetState, &hddstate);
                if (hddstate != MediaState_Inaccessible) {
                    VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetName, &nameUtf16);

                    VBOX_UTF16_TO_UTF8(nameUtf16, &nameUtf8);
                    VBOX_UTF16_FREE(nameUtf16);

                    if (nameUtf8) {
                        VIR_DEBUG("nnames[%d]: %s", numActive, nameUtf8);
                        if (VIR_STRDUP(names[numActive], nameUtf8) > 0)
                            numActive++;

                        VBOX_UTF8_FREE(nameUtf8);
                    }
                }
            }
        }

        vboxArrayRelease(&hardDisks);

        ret = numActive;
    } else {
        ret = -1;
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not get the volume list in the pool: %s, rc=%08x"),
                       pool->name, (unsigned)rc);
    }

    return ret;
}

static virStorageVolPtr
vboxStorageVolLookupByName(virStoragePoolPtr pool, const char *name)
{
    VBOX_OBJECT_CHECK(pool->conn, virStorageVolPtr, NULL);
    vboxArray hardDisks = VBOX_ARRAY_INITIALIZER;
    nsresult rc;
    size_t i;

    if (!name)
        return ret;

    rc = vboxArrayGet(&hardDisks, data->vboxObj, data->vboxObj->vtbl->GetHardDisks);
    if (NS_SUCCEEDED(rc)) {
        for (i = 0; i < hardDisks.count; ++i) {
            IHardDisk *hardDisk = hardDisks.items[i];

            if (hardDisk) {
                PRUint32 hddstate;
                char      *nameUtf8  = NULL;
                PRUnichar *nameUtf16 = NULL;

                VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetState, &hddstate);
                if (hddstate != MediaState_Inaccessible) {
                    VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetName, &nameUtf16);

                    if (nameUtf16) {
                        VBOX_UTF16_TO_UTF8(nameUtf16, &nameUtf8);
                        VBOX_UTF16_FREE(nameUtf16);
                    }

                    if (nameUtf8 && STREQ(nameUtf8, name)) {
                        vboxIID hddIID = VBOX_IID_INITIALIZER;
                        unsigned char uuid[VIR_UUID_BUFLEN];
                        char key[VIR_UUID_STRING_BUFLEN] = "";

                        rc = VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetId, &hddIID.value);
                        if (NS_SUCCEEDED(rc)) {
                            vboxIIDToUUID(&hddIID, uuid);
                            virUUIDFormat(uuid, key);

                            ret = virGetStorageVol(pool->conn, pool->name, name, key,
                                                   NULL, NULL);

                            VIR_DEBUG("virStorageVolPtr: %p", ret);
                            VIR_DEBUG("Storage Volume Name: %s", name);
                            VIR_DEBUG("Storage Volume key : %s", key);
                            VIR_DEBUG("Storage Volume Pool: %s", pool->name);
                        }

                        vboxIIDUnalloc(&hddIID);
                        VBOX_UTF8_FREE(nameUtf8);
                        break;
                    }

                    VBOX_UTF8_FREE(nameUtf8);
                }
            }
        }

        vboxArrayRelease(&hardDisks);
    }

    return ret;
}

static virStorageVolPtr
vboxStorageVolLookupByKey(virConnectPtr conn, const char *key)
{
    VBOX_OBJECT_CHECK(conn, virStorageVolPtr, NULL);
    vboxIID hddIID = VBOX_IID_INITIALIZER;
    unsigned char uuid[VIR_UUID_BUFLEN];
    IHardDisk *hardDisk  = NULL;
    nsresult rc;

    if (!key)
        return ret;

    if (virUUIDParse(key, uuid) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Could not parse UUID from '%s'"), key);
        return NULL;
    }

    vboxIIDFromUUID(&hddIID, uuid);
#if VBOX_API_VERSION < 4000000
    rc = data->vboxObj->vtbl->GetHardDisk(data->vboxObj, hddIID.value, &hardDisk);
#elif VBOX_API_VERSION >= 4000000 && VBOX_API_VERSION < 4002000
    rc = data->vboxObj->vtbl->FindMedium(data->vboxObj, hddIID.value,
                                         DeviceType_HardDisk, &hardDisk);
#else
    rc = data->vboxObj->vtbl->OpenMedium(data->vboxObj, hddIID.value,
                                         DeviceType_HardDisk, AccessMode_ReadWrite,
                                         PR_FALSE, &hardDisk);
#endif /* VBOX_API_VERSION >= 4000000 */
    if (NS_SUCCEEDED(rc)) {
        PRUint32 hddstate;

        VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetState, &hddstate);
        if (hddstate != MediaState_Inaccessible) {
            PRUnichar *hddNameUtf16 = NULL;
            char      *hddNameUtf8  = NULL;

            VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetName, &hddNameUtf16);
            VBOX_UTF16_TO_UTF8(hddNameUtf16, &hddNameUtf8);

            if (hddNameUtf8) {
                if (vboxConnectNumOfStoragePools(conn) == 1) {
                    ret = virGetStorageVol(conn, "default-pool", hddNameUtf8, key,
                                           NULL, NULL);
                    VIR_DEBUG("Storage Volume Pool: %s", "default-pool");
                } else {
                    /* TODO: currently only one default pool and thus
                     * nothing here, change it when pools are supported
                     */
                }

                VIR_DEBUG("Storage Volume Name: %s", key);
                VIR_DEBUG("Storage Volume key : %s", hddNameUtf8);

                VBOX_UTF8_FREE(hddNameUtf8);
                VBOX_UTF16_FREE(hddNameUtf16);
            }
        }

        VBOX_MEDIUM_RELEASE(hardDisk);
    }

    vboxIIDUnalloc(&hddIID);
    return ret;
}

static virStorageVolPtr
vboxStorageVolLookupByPath(virConnectPtr conn, const char *path)
{
    VBOX_OBJECT_CHECK(conn, virStorageVolPtr, NULL);
    PRUnichar *hddPathUtf16 = NULL;
    IHardDisk *hardDisk     = NULL;
    nsresult rc;

    if (!path)
        return ret;

    VBOX_UTF8_TO_UTF16(path, &hddPathUtf16);

    if (!hddPathUtf16)
        return ret;

#if VBOX_API_VERSION < 4000000
    rc = data->vboxObj->vtbl->FindHardDisk(data->vboxObj, hddPathUtf16, &hardDisk);
#elif VBOX_API_VERSION >= 4000000 && VBOX_API_VERSION < 4002000
    rc = data->vboxObj->vtbl->FindMedium(data->vboxObj, hddPathUtf16,
                                         DeviceType_HardDisk, &hardDisk);
#else
    rc = data->vboxObj->vtbl->OpenMedium(data->vboxObj, hddPathUtf16,
                                         DeviceType_HardDisk, AccessMode_ReadWrite,
                                         PR_FALSE, &hardDisk);
#endif /* VBOX_API_VERSION >= 4000000 */
    if (NS_SUCCEEDED(rc)) {
        PRUint32 hddstate;

        VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetState, &hddstate);
        if (hddstate != MediaState_Inaccessible) {
            PRUnichar *hddNameUtf16 = NULL;
            char      *hddNameUtf8  = NULL;

            VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetName, &hddNameUtf16);

            if (hddNameUtf16) {
                VBOX_UTF16_TO_UTF8(hddNameUtf16, &hddNameUtf8);
                VBOX_UTF16_FREE(hddNameUtf16);
            }

            if (hddNameUtf8) {
                vboxIID hddIID = VBOX_IID_INITIALIZER;
                unsigned char uuid[VIR_UUID_BUFLEN];
                char key[VIR_UUID_STRING_BUFLEN] = "";

                rc = VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetId, &hddIID.value);
                if (NS_SUCCEEDED(rc)) {
                    vboxIIDToUUID(&hddIID, uuid);
                    virUUIDFormat(uuid, key);

                    /* TODO: currently only one default pool and thus
                     * the check below, change it when pools are supported
                     */
                    if (vboxConnectNumOfStoragePools(conn) == 1)
                        ret = virGetStorageVol(conn, "default-pool", hddNameUtf8, key,
                                               NULL, NULL);

                    VIR_DEBUG("Storage Volume Pool: %s", "default-pool");
                    VIR_DEBUG("Storage Volume Name: %s", hddNameUtf8);
                    VIR_DEBUG("Storage Volume key : %s", key);
                }

                vboxIIDUnalloc(&hddIID);
            }

            VBOX_UTF8_FREE(hddNameUtf8);
        }

        VBOX_MEDIUM_RELEASE(hardDisk);
    }

    VBOX_UTF16_FREE(hddPathUtf16);

    return ret;
}

static virStorageVolPtr vboxStorageVolCreateXML(virStoragePoolPtr pool,
                                                const char *xml,
                                                unsigned int flags)
{
    VBOX_OBJECT_CHECK(pool->conn, virStorageVolPtr, NULL);
    virStorageVolDefPtr  def  = NULL;
    PRUnichar *hddFormatUtf16 = NULL;
    PRUnichar *hddNameUtf16   = NULL;
    virStoragePoolDef poolDef;
    nsresult rc;

    virCheckFlags(0, NULL);

    /* since there is currently one default pool now
     * and virStorageVolDefFormat() just checks it type
     * so just assign it for now, change the behaviour
     * when vbox supports pools.
     */
    memset(&poolDef, 0, sizeof(poolDef));
    poolDef.type = VIR_STORAGE_POOL_DIR;

    if ((def = virStorageVolDefParseString(&poolDef, xml)) == NULL)
        goto cleanup;

    if (!def->name ||
        (def->type != VIR_STORAGE_VOL_FILE))
        goto cleanup;

    /* For now only the vmdk, vpc and vdi type harddisk
     * variants can be created.  For historical reason, we default to vdi */
    if (def->target.format == VIR_STORAGE_FILE_VMDK) {
        VBOX_UTF8_TO_UTF16("VMDK", &hddFormatUtf16);
    } else if (def->target.format == VIR_STORAGE_FILE_VPC) {
        VBOX_UTF8_TO_UTF16("VHD", &hddFormatUtf16);
    } else {
        VBOX_UTF8_TO_UTF16("VDI", &hddFormatUtf16);
    }

    VBOX_UTF8_TO_UTF16(def->name, &hddNameUtf16);

    if (hddFormatUtf16 && hddNameUtf16) {
        IHardDisk *hardDisk = NULL;

        rc = data->vboxObj->vtbl->CreateHardDisk(data->vboxObj, hddFormatUtf16, hddNameUtf16, &hardDisk);
        if (NS_SUCCEEDED(rc)) {
            IProgress *progress    = NULL;
            PRUint64   logicalSize = VIR_DIV_UP(def->target.capacity,
                                                1024 * 1024);
            PRUint32   variant     = HardDiskVariant_Standard;

            if (def->target.capacity == def->target.allocation)
                variant = HardDiskVariant_Fixed;

#if VBOX_API_VERSION < 4003000
            rc = hardDisk->vtbl->CreateBaseStorage(hardDisk, logicalSize, variant, &progress);
#else
            rc = hardDisk->vtbl->CreateBaseStorage(hardDisk, logicalSize, 1, &variant, &progress);
#endif
            if (NS_SUCCEEDED(rc) && progress) {
#if VBOX_API_VERSION == 2002000
                nsresult resultCode;
#else
                PRInt32  resultCode;
#endif

                progress->vtbl->WaitForCompletion(progress, -1);
                progress->vtbl->GetResultCode(progress, &resultCode);

                if (NS_SUCCEEDED(resultCode)) {
                    vboxIID hddIID = VBOX_IID_INITIALIZER;
                    unsigned char uuid[VIR_UUID_BUFLEN];
                    char key[VIR_UUID_STRING_BUFLEN] = "";

                    rc = VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetId, &hddIID.value);
                    if (NS_SUCCEEDED(rc)) {
                        vboxIIDToUUID(&hddIID, uuid);
                        virUUIDFormat(uuid, key);

                        ret = virGetStorageVol(pool->conn, pool->name, def->name, key,
                                               NULL, NULL);
                    }

                    vboxIIDUnalloc(&hddIID);
                }

                VBOX_RELEASE(progress);
            }
        }
    }

    VBOX_UTF16_FREE(hddFormatUtf16);
    VBOX_UTF16_FREE(hddNameUtf16);

 cleanup:
    virStorageVolDefFree(def);
    return ret;
}

static int vboxStorageVolDelete(virStorageVolPtr vol,
                                unsigned int flags)
{
    VBOX_OBJECT_CHECK(vol->conn, int, -1);
    vboxIID hddIID = VBOX_IID_INITIALIZER;
    unsigned char uuid[VIR_UUID_BUFLEN];
    IHardDisk *hardDisk  = NULL;
    int deregister = 0;
    nsresult rc;
    size_t i = 0;
    size_t j = 0;

    virCheckFlags(0, -1);

    if (virUUIDParse(vol->key, uuid) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Could not parse UUID from '%s'"), vol->key);
        return -1;
    }

    vboxIIDFromUUID(&hddIID, uuid);
#if VBOX_API_VERSION < 4000000
    rc = data->vboxObj->vtbl->GetHardDisk(data->vboxObj, hddIID.value, &hardDisk);
#elif VBOX_API_VERSION >= 4000000 && VBOX_API_VERSION < 4002000
    rc = data->vboxObj->vtbl->FindMedium(data->vboxObj, hddIID.value,
                                         DeviceType_HardDisk, &hardDisk);
#else
    rc = data->vboxObj->vtbl->OpenMedium(data->vboxObj, hddIID.value,
                                         DeviceType_HardDisk, AccessMode_ReadWrite,
                                         PR_FALSE, &hardDisk);
#endif /* VBOX_API_VERSION >= 4000000 */
    if (NS_SUCCEEDED(rc)) {
        PRUint32 hddstate;

        VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetState, &hddstate);
        if (hddstate != MediaState_Inaccessible) {
            PRUint32  machineIdsSize = 0;
            vboxArray machineIds = VBOX_ARRAY_INITIALIZER;

#if VBOX_API_VERSION < 3001000
            vboxArrayGet(&machineIds, hardDisk, hardDisk->vtbl->imedium.GetMachineIds);
#else  /* VBOX_API_VERSION >= 3001000 */
            vboxArrayGet(&machineIds, hardDisk, hardDisk->vtbl->GetMachineIds);
#endif /* VBOX_API_VERSION >= 3001000 */

#if VBOX_API_VERSION == 2002000 && defined WIN32
            /* VirtualBox 2.2 on Windows represents IIDs as GUIDs and the
             * machineIds array contains direct instances of the GUID struct
             * instead of pointers to the actual struct instances. But there
             * is no 128bit width simple item type for a SafeArray to fit a
             * GUID in. The largest simple type it 64bit width and VirtualBox
             * uses two of this 64bit items to represents one GUID. Therefore,
             * we divide the size of the SafeArray by two, to compensate for
             * this workaround in VirtualBox */
            machineIds.count /= 2;
#endif /* VBOX_API_VERSION >= 2002000 */

            machineIdsSize = machineIds.count;

            for (i = 0; i < machineIds.count; i++) {
                IMachine *machine = NULL;
                vboxIID machineId = VBOX_IID_INITIALIZER;

                vboxIIDFromArrayItem(&machineId, &machineIds, i);

#if VBOX_API_VERSION >= 4000000
                rc = VBOX_OBJECT_GET_MACHINE(machineId.value, &machine);
                if (NS_FAILED(rc)) {
                    virReportError(VIR_ERR_NO_DOMAIN, "%s",
                                   _("no domain with matching uuid"));
                    break;
                }
#endif

                rc = VBOX_SESSION_OPEN(machineId.value, machine);

                if (NS_SUCCEEDED(rc)) {

                    rc = data->vboxSession->vtbl->GetMachine(data->vboxSession, &machine);
                    if (NS_SUCCEEDED(rc)) {
                        vboxArray hddAttachments = VBOX_ARRAY_INITIALIZER;

#if VBOX_API_VERSION < 3001000
                        vboxArrayGet(&hddAttachments, machine,
                                     machine->vtbl->GetHardDiskAttachments);
#else  /* VBOX_API_VERSION >= 3001000 */
                        vboxArrayGet(&hddAttachments, machine,
                                     machine->vtbl->GetMediumAttachments);
#endif /* VBOX_API_VERSION >= 3001000 */
                        for (j = 0; j < hddAttachments.count; j++) {
                            IHardDiskAttachment *hddAttachment = hddAttachments.items[j];

                            if (hddAttachment) {
                                IHardDisk *hdd = NULL;

#if VBOX_API_VERSION < 3001000
                                rc = hddAttachment->vtbl->GetHardDisk(hddAttachment, &hdd);
#else  /* VBOX_API_VERSION >= 3001000 */
                                rc = hddAttachment->vtbl->GetMedium(hddAttachment, &hdd);
#endif /* VBOX_API_VERSION >= 3001000 */
                                if (NS_SUCCEEDED(rc) && hdd) {
                                    vboxIID iid = VBOX_IID_INITIALIZER;

                                    rc = VBOX_MEDIUM_FUNC_ARG1(hdd, GetId, &iid.value);
                                    if (NS_SUCCEEDED(rc)) {

                                            DEBUGIID("HardDisk (to delete) UUID", hddIID.value);
                                            DEBUGIID("HardDisk (currently processing) UUID", iid.value);

                                        if (vboxIIDIsEqual(&hddIID, &iid)) {
                                            PRUnichar *controller = NULL;
                                            PRInt32    port       = 0;
                                            PRInt32    device     = 0;

                                            DEBUGIID("Found HardDisk to delete, UUID", hddIID.value);

                                            hddAttachment->vtbl->GetController(hddAttachment, &controller);
                                            hddAttachment->vtbl->GetPort(hddAttachment, &port);
                                            hddAttachment->vtbl->GetDevice(hddAttachment, &device);

#if VBOX_API_VERSION < 3001000
                                            rc = machine->vtbl->DetachHardDisk(machine, controller, port, device);
#else  /* VBOX_API_VERSION >= 3001000 */
                                            rc = machine->vtbl->DetachDevice(machine, controller, port, device);
#endif /* VBOX_API_VERSION >= 3001000 */
                                            if (NS_SUCCEEDED(rc)) {
                                                rc = machine->vtbl->SaveSettings(machine);
                                                VIR_DEBUG("saving machine settings");
                                            }

                                            if (NS_SUCCEEDED(rc)) {
                                                deregister++;
                                                VIR_DEBUG("deregistering hdd:%d", deregister);
                                            }

                                            VBOX_UTF16_FREE(controller);
                                        }
                                        vboxIIDUnalloc(&iid);
                                    }
                                    VBOX_MEDIUM_RELEASE(hdd);
                                }
                            }
                        }
                        vboxArrayRelease(&hddAttachments);
                        VBOX_RELEASE(machine);
                    }
                    VBOX_SESSION_CLOSE();
                }

                vboxIIDUnalloc(&machineId);
            }

            vboxArrayUnalloc(&machineIds);

            if (machineIdsSize == 0 || machineIdsSize == deregister) {
                IProgress *progress = NULL;
                rc = hardDisk->vtbl->DeleteStorage(hardDisk, &progress);

                if (NS_SUCCEEDED(rc) && progress) {
                    progress->vtbl->WaitForCompletion(progress, -1);
                    VBOX_RELEASE(progress);
                    DEBUGIID("HardDisk deleted, UUID", hddIID.value);
                    ret = 0;
                }
            }
        }

        VBOX_MEDIUM_RELEASE(hardDisk);
    }

    vboxIIDUnalloc(&hddIID);

    return ret;
}

static int
vboxStorageVolGetInfo(virStorageVolPtr vol, virStorageVolInfoPtr info)
{
    VBOX_OBJECT_CHECK(vol->conn, int, -1);
    IHardDisk *hardDisk  = NULL;
    unsigned char uuid[VIR_UUID_BUFLEN];
    vboxIID hddIID = VBOX_IID_INITIALIZER;
    nsresult rc;

    if (!info)
        return ret;

    if (virUUIDParse(vol->key, uuid) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Could not parse UUID from '%s'"), vol->key);
        return ret;
    }

    vboxIIDFromUUID(&hddIID, uuid);
#if VBOX_API_VERSION < 4000000
    rc = data->vboxObj->vtbl->GetHardDisk(data->vboxObj, hddIID.value, &hardDisk);
#elif VBOX_API_VERSION >= 4000000 && VBOX_API_VERSION < 4002000
    rc = data->vboxObj->vtbl->FindMedium(data->vboxObj, hddIID.value,
                                         DeviceType_HardDisk, &hardDisk);
#else
    rc = data->vboxObj->vtbl->OpenMedium(data->vboxObj, hddIID.value,
                                         DeviceType_HardDisk, AccessMode_ReadWrite,
                                         PR_FALSE, &hardDisk);
#endif /* VBOX_API_VERSION >= 4000000 */
    if (NS_SUCCEEDED(rc)) {
        PRUint32 hddstate;

        VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetState, &hddstate);
        if (hddstate != MediaState_Inaccessible) {
#if VBOX_API_VERSION < 4000000
            PRUint64 hddLogicalSize;
            PRUint64 hddActualSize;
#else /* VBOX_API_VERSION >= 4000000 */
            PRInt64 hddLogicalSize;
            PRInt64 hddActualSize;
#endif /* VBOX_API_VERSION >= 4000000 */

            info->type = VIR_STORAGE_VOL_FILE;

            hardDisk->vtbl->GetLogicalSize(hardDisk, &hddLogicalSize);
#if VBOX_API_VERSION < 4000000
            info->capacity = hddLogicalSize * 1024 * 1024; /* MB => Bytes */
#else /* VBOX_API_VERSION >= 4000000 */
            info->capacity = hddLogicalSize;
#endif /* VBOX_API_VERSION >= 4000000 */

            VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetSize, &hddActualSize);
            info->allocation = hddActualSize;

            ret = 0;

            VIR_DEBUG("Storage Volume Name: %s", vol->name);
            VIR_DEBUG("Storage Volume Type: %s", info->type == VIR_STORAGE_VOL_BLOCK ? "Block" : "File");
            VIR_DEBUG("Storage Volume Capacity: %llu", info->capacity);
            VIR_DEBUG("Storage Volume Allocation: %llu", info->allocation);
        }

        VBOX_MEDIUM_RELEASE(hardDisk);
    }

    vboxIIDUnalloc(&hddIID);

    return ret;
}

static char *vboxStorageVolGetXMLDesc(virStorageVolPtr vol, unsigned int flags)
{
    VBOX_OBJECT_CHECK(vol->conn, char *, NULL);
    IHardDisk *hardDisk  = NULL;
    unsigned char uuid[VIR_UUID_BUFLEN];
    vboxIID hddIID = VBOX_IID_INITIALIZER;
    virStoragePoolDef pool;
    virStorageVolDef def;
    int defOk = 0;
    nsresult rc;

    virCheckFlags(0, NULL);

    memset(&pool, 0, sizeof(pool));
    memset(&def, 0, sizeof(def));

    if (virUUIDParse(vol->key, uuid) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Could not parse UUID from '%s'"), vol->key);
        return ret;
    }

    vboxIIDFromUUID(&hddIID, uuid);
#if VBOX_API_VERSION < 4000000
    rc = data->vboxObj->vtbl->GetHardDisk(data->vboxObj, hddIID.value, &hardDisk);
#elif VBOX_API_VERSION >= 4000000 && VBOX_API_VERSION < 4002000
    rc = data->vboxObj->vtbl->FindMedium(data->vboxObj, hddIID.value,
                                         DeviceType_HardDisk, &hardDisk);
#else
    rc = data->vboxObj->vtbl->OpenMedium(data->vboxObj, hddIID.value,
                                         DeviceType_HardDisk, AccessMode_ReadWrite,
                                         PR_FALSE, &hardDisk);
#endif /* VBOX_API_VERSION >= 4000000 */
    if (NS_SUCCEEDED(rc)) {
        PRUint32 hddstate;

        VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetState, &hddstate);
        if (NS_SUCCEEDED(rc) && hddstate != MediaState_Inaccessible) {
            PRUnichar *hddFormatUtf16 = NULL;
#if VBOX_API_VERSION < 4000000
            PRUint64 hddLogicalSize;
            PRUint64 hddActualSize;
#else /* VBOX_API_VERSION >= 4000000 */
            PRInt64 hddLogicalSize;
            PRInt64 hddActualSize;
#endif /* VBOX_API_VERSION >= 4000000 */

            /* since there is currently one default pool now
             * and virStorageVolDefFormat() just checks it type
             * so just assign it for now, change the behaviour
             * when vbox supports pools.
             */
            pool.type = VIR_STORAGE_POOL_DIR;
            def.type = VIR_STORAGE_VOL_FILE;
            defOk = 1;

            rc = hardDisk->vtbl->GetLogicalSize(hardDisk, &hddLogicalSize);
            if (NS_SUCCEEDED(rc) && defOk) {
#if VBOX_API_VERSION < 4000000
                def.target.capacity = hddLogicalSize * 1024 * 1024; /* MB => Bytes */
#else /* VBOX_API_VERSION >= 4000000 */
                def.target.capacity = hddLogicalSize;
#endif /* VBOX_API_VERSION >= 4000000 */
            } else
                defOk = 0;

            rc = VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetSize, &hddActualSize);
            if (NS_SUCCEEDED(rc) && defOk)
                def.target.allocation = hddActualSize;
            else
                defOk = 0;

            if (VIR_STRDUP(def.name, vol->name) < 0)
                defOk = 0;

            if (VIR_STRDUP(def.key, vol->key) < 0)
                defOk = 0;

            rc = hardDisk->vtbl->GetFormat(hardDisk, &hddFormatUtf16);
            if (NS_SUCCEEDED(rc) && defOk) {
                char *hddFormatUtf8 = NULL;

                VBOX_UTF16_TO_UTF8(hddFormatUtf16, &hddFormatUtf8);
                if (hddFormatUtf8) {

                    VIR_DEBUG("Storage Volume Format: %s", hddFormatUtf8);

                    if (STRCASEEQ("vmdk", hddFormatUtf8))
                        def.target.format = VIR_STORAGE_FILE_VMDK;
                    else if (STRCASEEQ("vhd", hddFormatUtf8))
                        def.target.format = VIR_STORAGE_FILE_VPC;
                    else if (STRCASEEQ("vdi", hddFormatUtf8))
                        def.target.format = VIR_STORAGE_FILE_VDI;
                    else
                        def.target.format = VIR_STORAGE_FILE_RAW;

                    VBOX_UTF8_FREE(hddFormatUtf8);
                }

                VBOX_UTF16_FREE(hddFormatUtf16);
            } else {
                defOk = 0;
            }
        }

        VBOX_MEDIUM_RELEASE(hardDisk);
    }

    vboxIIDUnalloc(&hddIID);

    if (defOk)
        ret = virStorageVolDefFormat(&pool, &def);

    return ret;
}

static char *vboxStorageVolGetPath(virStorageVolPtr vol) {
    VBOX_OBJECT_CHECK(vol->conn, char *, NULL);
    IHardDisk *hardDisk  = NULL;
    unsigned char uuid[VIR_UUID_BUFLEN];
    vboxIID hddIID = VBOX_IID_INITIALIZER;
    nsresult rc;

    if (virUUIDParse(vol->key, uuid) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Could not parse UUID from '%s'"), vol->key);
        return ret;
    }

    vboxIIDFromUUID(&hddIID, uuid);
#if VBOX_API_VERSION < 4000000
    rc = data->vboxObj->vtbl->GetHardDisk(data->vboxObj, hddIID.value, &hardDisk);
#elif VBOX_API_VERSION >= 4000000 && VBOX_API_VERSION < 4002000
    rc = data->vboxObj->vtbl->FindMedium(data->vboxObj, hddIID.value,
                                         DeviceType_HardDisk, &hardDisk);
#else
    rc = data->vboxObj->vtbl->OpenMedium(data->vboxObj, hddIID.value,
                                         DeviceType_HardDisk, AccessMode_ReadWrite,
                                         PR_FALSE, &hardDisk);
#endif /* VBOX_API_VERSION >= 4000000 */
    if (NS_SUCCEEDED(rc)) {
        PRUint32 hddstate;

        VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetState, &hddstate);
        if (hddstate != MediaState_Inaccessible) {
            PRUnichar *hddLocationUtf16 = NULL;
            char      *hddLocationUtf8  = NULL;

            VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetLocation, &hddLocationUtf16);

            VBOX_UTF16_TO_UTF8(hddLocationUtf16, &hddLocationUtf8);
            if (hddLocationUtf8) {

                ignore_value(VIR_STRDUP(ret, hddLocationUtf8));

                VIR_DEBUG("Storage Volume Name: %s", vol->name);
                VIR_DEBUG("Storage Volume Path: %s", hddLocationUtf8);
                VIR_DEBUG("Storage Volume Pool: %s", vol->pool);

                VBOX_UTF8_FREE(hddLocationUtf8);
            }

            VBOX_UTF16_FREE(hddLocationUtf16);
        }

        VBOX_MEDIUM_RELEASE(hardDisk);
    }

    vboxIIDUnalloc(&hddIID);

    return ret;
}

#if VBOX_API_VERSION >= 4000000
static char *
vboxDomainScreenshot(virDomainPtr dom,
                     virStreamPtr st,
                     unsigned int screen,
                     unsigned int flags)
{
    VBOX_OBJECT_CHECK(dom->conn, char *, NULL);
    IConsole *console = NULL;
    vboxIID iid = VBOX_IID_INITIALIZER;
    IMachine *machine = NULL;
    nsresult rc;
    char *tmp;
    int tmp_fd = -1;
    unsigned int max_screen;

    virCheckFlags(0, NULL);

    vboxIIDFromUUID(&iid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(iid.value, &machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        return NULL;
    }

    rc = machine->vtbl->GetMonitorCount(machine, &max_screen);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("unable to get monitor count"));
        VBOX_RELEASE(machine);
        return NULL;
    }

    if (screen >= max_screen) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("screen ID higher than monitor "
                         "count (%d)"), max_screen);
        VBOX_RELEASE(machine);
        return NULL;
    }

    if (virAsprintf(&tmp, "%s/cache/libvirt/vbox.screendump.XXXXXX", LOCALSTATEDIR) < 0) {
        VBOX_RELEASE(machine);
        return NULL;
    }

    if ((tmp_fd = mkostemp(tmp, O_CLOEXEC)) == -1) {
        virReportSystemError(errno, _("mkostemp(\"%s\") failed"), tmp);
        VIR_FREE(tmp);
        VBOX_RELEASE(machine);
        return NULL;
    }


    rc = VBOX_SESSION_OPEN_EXISTING(iid.value, machine);
    if (NS_SUCCEEDED(rc)) {
        rc = data->vboxSession->vtbl->GetConsole(data->vboxSession, &console);
        if (NS_SUCCEEDED(rc) && console) {
            IDisplay *display = NULL;

            console->vtbl->GetDisplay(console, &display);

            if (display) {
                PRUint32 width, height, bitsPerPixel;
                PRUint32 screenDataSize;
                PRUint8 *screenData;
# if VBOX_API_VERSION >= 4003000
                PRInt32 xOrigin, yOrigin;
# endif

                rc = display->vtbl->GetScreenResolution(display, screen,
                                                        &width, &height,
# if VBOX_API_VERSION < 4003000
                                                        &bitsPerPixel);
# else
                                                        &bitsPerPixel,
                                                        &xOrigin, &yOrigin);
# endif

                if (NS_FAILED(rc) || !width || !height) {
                    virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                                   _("unable to get screen resolution"));
                    goto endjob;
                }

                rc = display->vtbl->TakeScreenShotPNGToArray(display, screen,
                                                             width, height,
                                                             &screenDataSize,
                                                             &screenData);
                if (NS_FAILED(rc)) {
                    virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                                   _("failed to take screenshot"));
                    goto endjob;
                }

                if (safewrite(tmp_fd, (char *) screenData,
                              screenDataSize) < 0) {
                    virReportSystemError(errno, _("unable to write data "
                                                  "to '%s'"), tmp);
                    goto endjob;
                }

                if (VIR_CLOSE(tmp_fd) < 0) {
                    virReportSystemError(errno, _("unable to close %s"), tmp);
                    goto endjob;
                }

                if (VIR_STRDUP(ret, "image/png") < 0)
                    goto endjob;

                if (virFDStreamOpenFile(st, tmp, 0, 0, O_RDONLY) < 0) {
                    virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                                   _("unable to open stream"));
                    VIR_FREE(ret);
                }
 endjob:
                VIR_FREE(screenData);
                VBOX_RELEASE(display);
            }
            VBOX_RELEASE(console);
        }
        VBOX_SESSION_CLOSE();
    }

    VIR_FORCE_CLOSE(tmp_fd);
    unlink(tmp);
    VIR_FREE(tmp);
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    return ret;
}
#endif /* VBOX_API_VERSION >= 4000000 */


#define MATCH(FLAG) (flags & (FLAG))
static int
vboxConnectListAllDomains(virConnectPtr conn,
                          virDomainPtr **domains,
                          unsigned int flags)
{
    VBOX_OBJECT_CHECK(conn, int, -1);
    vboxArray machines = VBOX_ARRAY_INITIALIZER;
    char      *machineNameUtf8  = NULL;
    PRUnichar *machineNameUtf16 = NULL;
    unsigned char uuid[VIR_UUID_BUFLEN];
    vboxIID iid = VBOX_IID_INITIALIZER;
    PRUint32 state;
    nsresult rc;
    size_t i;
    virDomainPtr dom;
    virDomainPtr *doms = NULL;
    int count = 0;
    bool active;
    PRUint32 snapshotCount;

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_FILTERS_ALL, -1);

    /* filter out flag options that will produce 0 results in vbox driver:
     * - managed save: vbox guests don't have managed save images
     * - autostart: vbox doesn't support autostarting guests
     * - persistance: vbox doesn't support transient guests
     */
    if ((MATCH(VIR_CONNECT_LIST_DOMAINS_TRANSIENT) &&
         !MATCH(VIR_CONNECT_LIST_DOMAINS_PERSISTENT)) ||
        (MATCH(VIR_CONNECT_LIST_DOMAINS_AUTOSTART) &&
         !MATCH(VIR_CONNECT_LIST_DOMAINS_NO_AUTOSTART)) ||
        (MATCH(VIR_CONNECT_LIST_DOMAINS_MANAGEDSAVE) &&
         !MATCH(VIR_CONNECT_LIST_DOMAINS_NO_MANAGEDSAVE))) {
        if (domains &&
            VIR_ALLOC_N(*domains, 1) < 0)
            goto cleanup;

        ret = 0;
        goto cleanup;
    }

    rc = vboxArrayGet(&machines, data->vboxObj, data->vboxObj->vtbl->GetMachines);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get list of domains, rc=%08x"), (unsigned)rc);
        goto cleanup;
    }

    if (domains &&
        VIR_ALLOC_N(doms, machines.count + 1) < 0)
        goto cleanup;

    for (i = 0; i < machines.count; i++) {
        IMachine *machine = machines.items[i];

        if (machine) {
            PRBool isAccessible = PR_FALSE;
            machine->vtbl->GetAccessible(machine, &isAccessible);
            if (isAccessible) {
                machine->vtbl->GetState(machine, &state);

                if (state >= MachineState_FirstOnline &&
                    state <= MachineState_LastOnline)
                    active = true;
                else
                    active = false;

                /* filter by active state */
                if (MATCH(VIR_CONNECT_LIST_DOMAINS_FILTERS_ACTIVE) &&
                    !((MATCH(VIR_CONNECT_LIST_DOMAINS_ACTIVE) && active) ||
                      (MATCH(VIR_CONNECT_LIST_DOMAINS_INACTIVE) && !active)))
                    continue;

                /* filter by snapshot existence */
                if (MATCH(VIR_CONNECT_LIST_DOMAINS_FILTERS_SNAPSHOT)) {
                    rc = machine->vtbl->GetSnapshotCount(machine, &snapshotCount);
                    if (NS_FAILED(rc)) {
                        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                       _("could not get snapshot count for listed domains"));
                        goto cleanup;
                    }
                    if (!((MATCH(VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT) &&
                           snapshotCount > 0) ||
                          (MATCH(VIR_CONNECT_LIST_DOMAINS_NO_SNAPSHOT) &&
                           snapshotCount == 0)))
                        continue;
                }

                /* filter by machine state */
                if (MATCH(VIR_CONNECT_LIST_DOMAINS_FILTERS_STATE) &&
                    !((MATCH(VIR_CONNECT_LIST_DOMAINS_RUNNING) &&
                       state == MachineState_Running) ||
                      (MATCH(VIR_CONNECT_LIST_DOMAINS_PAUSED) &&
                       state == MachineState_Paused) ||
                      (MATCH(VIR_CONNECT_LIST_DOMAINS_SHUTOFF) &&
                       state == MachineState_PoweredOff) ||
                      (MATCH(VIR_CONNECT_LIST_DOMAINS_OTHER) &&
                       (state != MachineState_Running &&
                        state != MachineState_Paused &&
                        state != MachineState_PoweredOff))))
                    continue;

                /* just count the machines */
                if (!doms) {
                    count++;
                    continue;
                }

                machine->vtbl->GetName(machine, &machineNameUtf16);
                VBOX_UTF16_TO_UTF8(machineNameUtf16, &machineNameUtf8);
                machine->vtbl->GetId(machine, &iid.value);
                vboxIIDToUUID(&iid, uuid);
                vboxIIDUnalloc(&iid);

                dom = virGetDomain(conn, machineNameUtf8, uuid);

                VBOX_UTF8_FREE(machineNameUtf8);
                VBOX_UTF16_FREE(machineNameUtf16);

                if (!dom)
                    goto cleanup;

                if (active)
                    dom->id = i + 1;

                doms[count++] = dom;
            }
        }
    }

    if (doms) {
        /* safe to ignore, new size will be equal or less than
         * previous allocation*/
        ignore_value(VIR_REALLOC_N(doms, count + 1));
        *domains = doms;
        doms = NULL;
    }

    ret = count;

 cleanup:
    if (doms) {
        for (i = 0; i < count; i++) {
            if (doms[i])
                virDomainFree(doms[i]);
        }
    }
    VIR_FREE(doms);

    vboxArrayRelease(&machines);
    return ret;
}
#undef MATCH


static int
vboxNodeGetInfo(virConnectPtr conn ATTRIBUTE_UNUSED,
                virNodeInfoPtr nodeinfo)
{
    return nodeGetInfo(nodeinfo);
}


static int
vboxNodeGetCellsFreeMemory(virConnectPtr conn ATTRIBUTE_UNUSED,
                           unsigned long long *freeMems,
                           int startCell,
                           int maxCells)
{
    return nodeGetCellsFreeMemory(freeMems, startCell, maxCells);
}


static unsigned long long
vboxNodeGetFreeMemory(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    unsigned long long freeMem;
    if (nodeGetMemory(NULL, &freeMem) < 0)
        return 0;
    return freeMem;
}


static int
vboxNodeGetFreePages(virConnectPtr conn ATTRIBUTE_UNUSED,
                     unsigned int npages,
                     unsigned int *pages,
                     int startCell,
                     unsigned int cellCount,
                     unsigned long long *counts,
                     unsigned int flags)
{
    virCheckFlags(0, -1);

    return nodeGetFreePages(npages, pages, startCell, cellCount, counts);
}

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
    rc = VBOX_OBJECT_GET_MACHINE(IID_MEMBER(value), machine);
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
    PRInt32       hddNum                = 0;
    IHardDisk    *hardDiskPM            = NULL;
    IHardDisk    *hardDiskPS            = NULL;
    IHardDisk    *hardDiskSS            = NULL;
    const char   *hddBus                = "IDE";
    PRUnichar    *hddBusUtf16           = NULL;

    /* dump IDE hdds if present */
    VBOX_UTF8_TO_UTF16(hddBus, &hddBusUtf16);

    def->ndisks = 0;
    machine->vtbl->GetHardDisk(machine, hddBusUtf16, 0, 0,  &hardDiskPM);
    if (hardDiskPM)
        def->ndisks++;

    machine->vtbl->GetHardDisk(machine, hddBusUtf16, 0, 1,  &hardDiskPS);
    if (hardDiskPS)
        def->ndisks++;

    machine->vtbl->GetHardDisk(machine, hddBusUtf16, 1, 1,  &hardDiskSS);
    if (hardDiskSS)
        def->ndisks++;

    VBOX_UTF16_FREE(hddBusUtf16);

    if ((def->ndisks > 0) && (VIR_ALLOC_N(def->disks, def->ndisks) >= 0)) {
        size_t i;
        for (i = 0; i < def->ndisks; i++) {
            if ((def->disks[i] = virDomainDiskDefNew())) {
                def->disks[i]->device = VIR_DOMAIN_DISK_DEVICE_DISK;
                def->disks[i]->bus = VIR_DOMAIN_DISK_BUS_IDE;
                virDomainDiskSetType(def->disks[i],
                                     VIR_STORAGE_TYPE_FILE);
            }
        }
    }

    if (hardDiskPM) {
        PRUnichar *hddlocationUtf16 = NULL;
        char *hddlocation           = NULL;
        PRUint32 hddType            = HardDiskType_Normal;

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
        char *hddlocation           = NULL;
        PRUint32 hddType            = HardDiskType_Normal;

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
        char *hddlocation           = NULL;
        PRUint32 hddType            = HardDiskType_Normal;

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
    IDVDDrive *dvdDrive      = NULL;
    IDVDImage *dvdImage      = NULL;
    PRUnichar *locationUtf16 = NULL;
    char *location           = NULL;


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
        if ((def->disks[def->ndisks - 1] = virDomainDiskDefNew())) {
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
    IDVDDrive *dvdDrive     = NULL;
    IDVDImage *dvdImage     = NULL;
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
    if (!dvdImage) {
        data->vboxObj->vtbl->OpenDVDImage(data->vboxObj, dvdfileUtf16, dvdemptyuuid.value, &dvdImage);
    }

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

static void
_dumpFloppy(virDomainDefPtr def,
            vboxGlobalData *data,
            IMachine *machine)
{
    IFloppyDrive *floppyDrive = NULL;
    IFloppyImage *floppyImage = NULL;
    PRUnichar *locationUtf16  = NULL;
    char *location            = NULL;
    PRBool enabled            = PR_FALSE;
    PRUint32 state            = DriveState_Null;

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
        if ((def->disks[def->ndisks - 1] = virDomainDiskDefNew())) {
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
    IFloppyImage *floppyImage   = NULL;
    PRUnichar *fdfileUtf16      = NULL;
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

static void* _handleGetMachines(IVirtualBox *vboxObj)
{
    return vboxObj->vtbl->GetMachines;
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

static nsresult _nsisupportsRelease(nsISupports *nsi)
{
    return nsi->vtbl->Release(nsi);
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
_virtualboxGetSystemProperties(IVirtualBox *vboxObj, ISystemProperties **systemProperties)
{
    return vboxObj->vtbl->GetSystemProperties(vboxObj, systemProperties);
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
        PRBool override             = PR_FALSE;
        rc = data->vboxObj->vtbl->CreateMachine(data->vboxObj,
                                                machineNameUtf16,
                                                NULL,
                                                NULL,
                                                iid.value,
                                                override,
                                                machine);
#elif VBOX_API_VERSION >= 4000000 && VBOX_API_VERSION < 4002000
        PRBool override             = PR_FALSE;
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
_virtualboxRegisterMachine(IVirtualBox *vboxObj, IMachine *machine)
{
    return vboxObj->vtbl->RegisterMachine(vboxObj, machine);
}

static nsresult
_virtualboxFindMedium(IVirtualBox *vboxObj ATTRIBUTE_UNUSED,
                      PRUnichar *location ATTRIBUTE_UNUSED,
                      PRUint32 deviceType ATTRIBUTE_UNUSED,
                      PRUint32 accessMode ATTRIBUTE_UNUSED,
                      IMedium **medium ATTRIBUTE_UNUSED)
{
#if VBOX_API_VERSION >= 4000000 && VBOX_API_VERSION < 4002000
    return vboxObj->vtbl->FindMedium(vboxObj, location,
                                     deviceType, medium);
#elif VBOX_API_VERSION >= 4002000
    return vboxObj->vtbl->OpenMedium(vboxObj, location,
                                     deviceType, accessMode, PR_FALSE, medium);
#else
    vboxUnsupported();
    return 0;
#endif
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

static nsresult _mediumRelease(IMedium *medium)
{
    return medium->vtbl->nsisupports.Release((nsISupports *)medium);
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
_mediumAttachmentGetMedium(IMediumAttachment *mediumAttachment ATTRIBUTE_UNUSED,
                           IMedium **medium ATTRIBUTE_UNUSED)
{
#if VBOX_API_VERSION < 3001000
    vboxUnsupported();
    return 0;
#else /* VBOX_API_VERSION >= 3001000 */
    return mediumAttachment->vtbl->GetMedium(mediumAttachment, medium);
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

static bool _machineStateOnline(PRUint32 state)
{
    return ((state >= MachineState_FirstOnline) &&
            (state <= MachineState_LastOnline));
}

static bool _machineStateInactive(PRUint32 state)
{
    return ((state > MachineState_FirstOnline) &&
            (state < MachineState_LastOnline));
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
    .DEBUGIID = _DEBUGIID,
};

static vboxUniformedArray _UArray = {
    .vboxArrayGet = vboxArrayGet,
    .vboxArrayRelease = vboxArrayRelease,
    .handleGetMachines = _handleGetMachines,
    .handleUSBGetDeviceFilters = _handleUSBGetDeviceFilters,
    .handleMachineGetMediumAttachments = _handleMachineGetMediumAttachments,
    .handleMachineGetSharedFolders = _handleMachineGetSharedFolders,
};

static vboxUniformednsISupports _nsUISupports = {
    .Release = _nsisupportsRelease,
};

static vboxUniformedIVirtualBox _UIVirtualBox = {
    .GetVersion = _virtualboxGetVersion,
    .GetMachine = _virtualboxGetMachine,
    .GetSystemProperties = _virtualboxGetSystemProperties,
    .CreateMachine = _virtualboxCreateMachine,
    .RegisterMachine = _virtualboxRegisterMachine,
    .FindMedium = _virtualboxFindMedium,
    .OpenMedium = _virtualboxOpenMedium,
};

static vboxUniformedIMachine _UIMachine = {
    .AddStorageController = _machineAddStorageController,
    .GetStorageControllerByName = _machineGetStorageControllerByName,
    .AttachDevice = _machineAttachDevice,
    .CreateSharedFolder = _machineCreateSharedFolder,
    .LaunchVMProcess = _machineLaunchVMProcess,
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
    .GetReadOnly = _mediumGetReadOnly,
    .Release = _mediumRelease,
    .SetType = _mediumSetType,
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
    pVBoxAPI->dumpFloppy = _dumpFloppy;
    pVBoxAPI->attachFloppy = _attachFloppy;
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
#else /* VBOX_API_VERSION < 4000000 */
    pVBoxAPI->getMachineForSession = 0;
    pVBoxAPI->detachDevicesExplicitly = 1;
    pVBoxAPI->vboxAttachDrivesUseOld = 1;
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
}

/**
 * Function Tables
 */

virDriver NAME(Driver) = {
    .no = VIR_DRV_VBOX,
    .name = "VBOX",
    .connectOpen = vboxConnectOpen, /* 0.6.3 */
    .connectClose = vboxConnectClose, /* 0.6.3 */
    .connectGetVersion = vboxConnectGetVersion, /* 0.6.3 */
    .connectGetHostname = vboxConnectGetHostname, /* 0.6.3 */
    .connectGetMaxVcpus = vboxConnectGetMaxVcpus, /* 0.6.3 */
    .nodeGetInfo = vboxNodeGetInfo, /* 0.6.3 */
    .connectGetCapabilities = vboxConnectGetCapabilities, /* 0.6.3 */
    .connectListDomains = vboxConnectListDomains, /* 0.6.3 */
    .connectNumOfDomains = vboxConnectNumOfDomains, /* 0.6.3 */
    .connectListAllDomains = vboxConnectListAllDomains, /* 0.9.13 */
    .domainCreateXML = vboxDomainCreateXML, /* 0.6.3 */
    .domainLookupByID = vboxDomainLookupByID, /* 0.6.3 */
    .domainLookupByUUID = vboxDomainLookupByUUID, /* 0.6.3 */
    .domainLookupByName = vboxDomainLookupByName, /* 0.6.3 */
    .domainSuspend = vboxDomainSuspend, /* 0.6.3 */
    .domainResume = vboxDomainResume, /* 0.6.3 */
    .domainShutdown = vboxDomainShutdown, /* 0.6.3 */
    .domainShutdownFlags = vboxDomainShutdownFlags, /* 0.9.10 */
    .domainReboot = vboxDomainReboot, /* 0.6.3 */
    .domainDestroy = vboxDomainDestroy, /* 0.6.3 */
    .domainDestroyFlags = vboxDomainDestroyFlags, /* 0.9.4 */
    .domainGetOSType = vboxDomainGetOSType, /* 0.6.3 */
    .domainSetMemory = vboxDomainSetMemory, /* 0.6.3 */
    .domainGetInfo = vboxDomainGetInfo, /* 0.6.3 */
    .domainGetState = vboxDomainGetState, /* 0.9.2 */
    .domainSave = vboxDomainSave, /* 0.6.3 */
    .domainSetVcpus = vboxDomainSetVcpus, /* 0.7.1 */
    .domainSetVcpusFlags = vboxDomainSetVcpusFlags, /* 0.8.5 */
    .domainGetVcpusFlags = vboxDomainGetVcpusFlags, /* 0.8.5 */
    .domainGetMaxVcpus = vboxDomainGetMaxVcpus, /* 0.7.1 */
    .domainGetXMLDesc = vboxDomainGetXMLDesc, /* 0.6.3 */
    .connectListDefinedDomains = vboxConnectListDefinedDomains, /* 0.6.3 */
    .connectNumOfDefinedDomains = vboxConnectNumOfDefinedDomains, /* 0.6.3 */
    .domainCreate = vboxDomainCreate, /* 0.6.3 */
    .domainCreateWithFlags = vboxDomainCreateWithFlags, /* 0.8.2 */
    .domainDefineXML = vboxDomainDefineXML, /* 0.6.3 */
    .domainUndefine = vboxDomainUndefine, /* 0.6.3 */
    .domainUndefineFlags = vboxDomainUndefineFlags, /* 0.9.5 */
    .domainAttachDevice = vboxDomainAttachDevice, /* 0.6.3 */
    .domainAttachDeviceFlags = vboxDomainAttachDeviceFlags, /* 0.7.7 */
    .domainDetachDevice = vboxDomainDetachDevice, /* 0.6.3 */
    .domainDetachDeviceFlags = vboxDomainDetachDeviceFlags, /* 0.7.7 */
    .domainUpdateDeviceFlags = vboxDomainUpdateDeviceFlags, /* 0.8.0 */
    .nodeGetCellsFreeMemory = vboxNodeGetCellsFreeMemory, /* 0.6.5 */
    .nodeGetFreeMemory = vboxNodeGetFreeMemory, /* 0.6.5 */
#if VBOX_API_VERSION >= 4000000
    .domainScreenshot = vboxDomainScreenshot, /* 0.9.2 */
#endif
#if VBOX_API_VERSION > 2002000 && VBOX_API_VERSION < 4000000
    .connectDomainEventRegister = vboxConnectDomainEventRegister, /* 0.7.0 */
    .connectDomainEventDeregister = vboxConnectDomainEventDeregister, /* 0.7.0 */
#endif
    .connectIsEncrypted = vboxConnectIsEncrypted, /* 0.7.3 */
    .connectIsSecure = vboxConnectIsSecure, /* 0.7.3 */
    .domainIsActive = vboxDomainIsActive, /* 0.7.3 */
    .domainIsPersistent = vboxDomainIsPersistent, /* 0.7.3 */
    .domainIsUpdated = vboxDomainIsUpdated, /* 0.8.6 */
#if VBOX_API_VERSION > 2002000 && VBOX_API_VERSION < 4000000
    .connectDomainEventRegisterAny = vboxConnectDomainEventRegisterAny, /* 0.8.0 */
    .connectDomainEventDeregisterAny = vboxConnectDomainEventDeregisterAny, /* 0.8.0 */
#endif
    .domainSnapshotCreateXML = vboxDomainSnapshotCreateXML, /* 0.8.0 */
    .domainSnapshotGetXMLDesc = vboxDomainSnapshotGetXMLDesc, /* 0.8.0 */
    .domainSnapshotNum = vboxDomainSnapshotNum, /* 0.8.0 */
    .domainSnapshotListNames = vboxDomainSnapshotListNames, /* 0.8.0 */
    .domainSnapshotLookupByName = vboxDomainSnapshotLookupByName, /* 0.8.0 */
    .domainHasCurrentSnapshot = vboxDomainHasCurrentSnapshot, /* 0.8.0 */
    .domainSnapshotGetParent = vboxDomainSnapshotGetParent, /* 0.9.7 */
    .domainSnapshotCurrent = vboxDomainSnapshotCurrent, /* 0.8.0 */
    .domainSnapshotIsCurrent = vboxDomainSnapshotIsCurrent, /* 0.9.13 */
    .domainSnapshotHasMetadata = vboxDomainSnapshotHasMetadata, /* 0.9.13 */
    .domainRevertToSnapshot = vboxDomainRevertToSnapshot, /* 0.8.0 */
    .domainSnapshotDelete = vboxDomainSnapshotDelete, /* 0.8.0 */
    .connectIsAlive = vboxConnectIsAlive, /* 0.9.8 */
    .nodeGetFreePages = vboxNodeGetFreePages, /* 1.2.6 */
};

virNetworkDriver NAME(NetworkDriver) = {
    "VBOX",
    .networkOpen = vboxNetworkOpen, /* 0.6.4 */
    .networkClose = vboxNetworkClose, /* 0.6.4 */
    .connectNumOfNetworks = vboxConnectNumOfNetworks, /* 0.6.4 */
    .connectListNetworks = vboxConnectListNetworks, /* 0.6.4 */
    .connectNumOfDefinedNetworks = vboxConnectNumOfDefinedNetworks, /* 0.6.4 */
    .connectListDefinedNetworks = vboxConnectListDefinedNetworks, /* 0.6.4 */
    .networkLookupByUUID = vboxNetworkLookupByUUID, /* 0.6.4 */
    .networkLookupByName = vboxNetworkLookupByName, /* 0.6.4 */
    .networkCreateXML = vboxNetworkCreateXML, /* 0.6.4 */
    .networkDefineXML = vboxNetworkDefineXML, /* 0.6.4 */
    .networkUndefine = vboxNetworkUndefine, /* 0.6.4 */
    .networkCreate = vboxNetworkCreate, /* 0.6.4 */
    .networkDestroy = vboxNetworkDestroy, /* 0.6.4 */
    .networkGetXMLDesc = vboxNetworkGetXMLDesc, /* 0.6.4 */
};

virStorageDriver NAME(StorageDriver) = {
    .name               = "VBOX",
    .storageOpen = vboxStorageOpen, /* 0.7.1 */
    .storageClose = vboxStorageClose, /* 0.7.1 */
    .connectNumOfStoragePools = vboxConnectNumOfStoragePools, /* 0.7.1 */
    .connectListStoragePools = vboxConnectListStoragePools, /* 0.7.1 */
    .storagePoolLookupByName = vboxStoragePoolLookupByName, /* 0.7.1 */
    .storagePoolNumOfVolumes = vboxStoragePoolNumOfVolumes, /* 0.7.1 */
    .storagePoolListVolumes = vboxStoragePoolListVolumes, /* 0.7.1 */

    .storageVolLookupByName = vboxStorageVolLookupByName, /* 0.7.1 */
    .storageVolLookupByKey = vboxStorageVolLookupByKey, /* 0.7.1 */
    .storageVolLookupByPath = vboxStorageVolLookupByPath, /* 0.7.1 */
    .storageVolCreateXML = vboxStorageVolCreateXML, /* 0.7.1 */
    .storageVolDelete = vboxStorageVolDelete, /* 0.7.1 */
    .storageVolGetInfo = vboxStorageVolGetInfo, /* 0.7.1 */
    .storageVolGetXMLDesc = vboxStorageVolGetXMLDesc, /* 0.7.1 */
    .storageVolGetPath = vboxStorageVolGetPath /* 0.7.1 */
};
