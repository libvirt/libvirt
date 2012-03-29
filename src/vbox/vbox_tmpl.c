/** @file vbox_tmpl.c
 * Template File to support multiple versions of VirtualBox
 * at runtime :).
 *
 * IMPORTANT:
 * Please dont include this file in the src/Makefile.am, it
 * is automatically include by other files.
 */

/*
 * Copyright (C) 2010-2012 Red Hat, Inc.
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

#include <config.h>

#include <sys/utsname.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "internal.h"
#include "datatypes.h"
#include "domain_conf.h"
#include "network_conf.h"
#include "virterror_internal.h"
#include "domain_event.h"
#include "storage_conf.h"
#include "storage_file.h"
#include "uuid.h"
#include "memory.h"
#include "nodeinfo.h"
#include "logging.h"
#include "vbox_driver.h"
#include "configmake.h"
#include "virfile.h"
#include "fdstream.h"
#include "viruri.h"

/* This one changes from version to version. */
#if VBOX_API_VERSION == 2002
# include "vbox_CAPI_v2_2.h"
#elif VBOX_API_VERSION == 3000
# include "vbox_CAPI_v3_0.h"
#elif VBOX_API_VERSION == 3001
# include "vbox_CAPI_v3_1.h"
#elif VBOX_API_VERSION == 3002
# include "vbox_CAPI_v3_2.h"
#elif VBOX_API_VERSION == 4000
# include "vbox_CAPI_v4_0.h"
#elif VBOX_API_VERSION == 4001
# include "vbox_CAPI_v4_1.h"
#else
# error "Unsupport VBOX_API_VERSION"
#endif

/* Include this *last* or we'll get the wrong vbox_CAPI_*.h. */
#include "vbox_glue.h"


#define VIR_FROM_THIS                   VIR_FROM_VBOX
#define VBOX_UTF16_FREE(arg)            data->pFuncs->pfnUtf16Free(arg)
#define VBOX_UTF8_FREE(arg)             data->pFuncs->pfnUtf8Free(arg)
#define VBOX_COM_UNALLOC_MEM(arg)       data->pFuncs->pfnComUnallocMem(arg)
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
if(!data->vboxObj) {\
    return ret;\
}

#define VBOX_OBJECT_HOST_CHECK(conn, type, value) \
vboxGlobalData *data = conn->privateData;\
type ret = value;\
IHost *host = NULL;\
if(!data->vboxObj) {\
    return ret;\
}\
data->vboxObj->vtbl->GetHost(data->vboxObj, &host);\
if (!host) {\
    return ret;\
}

#if VBOX_API_VERSION < 3001

# define VBOX_MEDIUM_RELEASE(arg) \
if(arg)\
    (arg)->vtbl->imedium.nsisupports.Release((nsISupports *)(arg))
# define VBOX_MEDIUM_FUNC_ARG1(object, func, arg1) \
    (object)->vtbl->imedium.func((IMedium *)(object), arg1)
# define VBOX_MEDIUM_FUNC_ARG2(object, func, arg1, arg2) \
    (object)->vtbl->imedium.func((IMedium *)(object), arg1, arg2)

#else  /* VBOX_API_VERSION >= 3001 */

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

#endif /* VBOX_API_VERSION >= 3001 */

#define vboxError(code, ...) \
        virReportErrorHelper(VIR_FROM_VBOX, code, __FILE__, \
                             __FUNCTION__, __LINE__, __VA_ARGS__)

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
    VIR_DEBUG (msg ": {%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",\
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

typedef struct {
    virMutex lock;
    unsigned long version;

    virCapsPtr caps;

    IVirtualBox *vboxObj;
    ISession *vboxSession;

    /** Our version specific API table pointer. */
    PCVBOXXPCOM pFuncs;

#if VBOX_API_VERSION == 2002

} vboxGlobalData;

#else /* !(VBOX_API_VERSION == 2002) */

    /* Async event handling */
    virDomainEventStatePtr domainEvents;
    int fdWatch;

# if VBOX_API_VERSION <= 3002
    /* IVirtualBoxCallback is used in VirtualBox 3.x only */
    IVirtualBoxCallback *vboxCallback;
# endif /* VBOX_API_VERSION <= 3002 */

    nsIEventQueue  *vboxQueue;
    int volatile vboxCallBackRefCount;

    /* pointer back to the connection */
    virConnectPtr conn;

} vboxGlobalData;

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

#endif /* !(VBOX_API_VERSION == 2002) */

#if VBOX_API_VERSION < 4000

# define VBOX_OBJECT_GET_MACHINE(/* in */ iid_value, /* out */ machine) \
    data->vboxObj->vtbl->GetMachine(data->vboxObj, iid_value, machine)

# define VBOX_SESSION_OPEN(/* in */ iid_value, /* unused */ machine) \
    data->vboxObj->vtbl->OpenSession(data->vboxObj, data->vboxSession, iid_value)

# define VBOX_SESSION_OPEN_EXISTING(/* in */ iid_value, /* unused */ machine) \
    data->vboxObj->vtbl->OpenExistingSession(data->vboxObj, data->vboxSession, iid_value)

# define VBOX_SESSION_CLOSE() \
    data->vboxSession->vtbl->Close(data->vboxSession)

#else /* VBOX_API_VERSION >= 4000 */

# define VBOX_OBJECT_GET_MACHINE(/* in */ iid_value, /* out */ machine) \
    data->vboxObj->vtbl->FindMachine(data->vboxObj, iid_value, machine)

# define VBOX_SESSION_OPEN(/* unused */ iid_value, /* in */ machine) \
    machine->vtbl->LockMachine(machine, data->vboxSession, LockType_Write)

# define VBOX_SESSION_OPEN_EXISTING(/* unused */ iid_value, /* in */ machine) \
    machine->vtbl->LockMachine(machine, data->vboxSession, LockType_Shared)

# define VBOX_SESSION_CLOSE() \
    data->vboxSession->vtbl->UnlockMachine(data->vboxSession)

#endif /* VBOX_API_VERSION >= 4000 */

static virDomainPtr vboxDomainDefineXML(virConnectPtr conn, const char *xml);
static int vboxDomainCreate(virDomainPtr dom);
static int vboxDomainUndefineFlags(virDomainPtr dom, unsigned int flags);

static void vboxDriverLock(vboxGlobalData *data) {
    virMutexLock(&data->lock);
}

static void vboxDriverUnlock(vboxGlobalData *data) {
    virMutexUnlock(&data->lock);
}

#if VBOX_API_VERSION == 2002

static void nsIDtoChar(unsigned char *uuid, const nsID *iid) {
    char uuidstrsrc[VIR_UUID_STRING_BUFLEN];
    char uuidstrdst[VIR_UUID_STRING_BUFLEN];
    unsigned char uuidinterim[VIR_UUID_BUFLEN];
    int i;

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

    for(i = 18; i < VIR_UUID_STRING_BUFLEN; i++) {
        uuidstrdst[i] = uuidstrsrc[i];
    }

    uuidstrdst[VIR_UUID_STRING_BUFLEN-1] = '\0';
    ignore_value(virUUIDParse(uuidstrdst, uuid));
}

static void nsIDFromChar(nsID *iid, const unsigned char *uuid) {
    char uuidstrsrc[VIR_UUID_STRING_BUFLEN];
    char uuidstrdst[VIR_UUID_STRING_BUFLEN];
    unsigned char uuidinterim[VIR_UUID_BUFLEN];
    int i;

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

    for(i = 18; i < VIR_UUID_STRING_BUFLEN; i++) {
        uuidstrdst[i] = uuidstrsrc[i];
    }

    uuidstrdst[VIR_UUID_STRING_BUFLEN-1] = '\0';
    ignore_value(virUUIDParse(uuidstrdst, uuidinterim));
    memcpy(iid, uuidinterim, VIR_UUID_BUFLEN);
}

# ifdef WIN32

typedef struct _vboxIID_v2_x_WIN32 vboxIID;
typedef struct _vboxIID_v2_x_WIN32 vboxIID_v2_x_WIN32;

struct _vboxIID_v2_x_WIN32 {
    /* IID is represented by a GUID value. */
    GUID value;
};

#  define VBOX_IID_INITIALIZER { { 0, 0, 0, { 0, 0, 0, 0, 0, 0, 0, 0 } } }

static void
vboxIIDUnalloc_v2_x_WIN32(vboxGlobalData *data ATTRIBUTE_UNUSED,
                          vboxIID_v2_x_WIN32 *iid ATTRIBUTE_UNUSED)
{
    /* Nothing to free */
}

static void
vboxIIDToUUID_v2_x_WIN32(vboxIID_v2_x_WIN32 *iid, unsigned char *uuid)
{
    nsIDtoChar(uuid, (nsID *)&iid->value);
}

static void
vboxIIDFromUUID_v2_x_WIN32(vboxGlobalData *data, vboxIID_v2_x_WIN32 *iid,
                           const unsigned char *uuid)
{
    vboxIIDUnalloc_v2_x_WIN32(data, iid);

    nsIDFromChar((nsID *)&iid->value, uuid);
}

static bool
vboxIIDIsEqual_v2_x_WIN32(vboxIID_v2_x_WIN32 *iid1, vboxIID_v2_x_WIN32 *iid2)
{
    return memcmp(&iid1->value, &iid2->value, sizeof(GUID)) == 0;
}

static void
vboxIIDFromArrayItem_v2_x_WIN32(vboxGlobalData *data, vboxIID_v2_x_WIN32 *iid,
                                vboxArray *array, int idx)
{
    GUID *items = (GUID *)array->items;

    vboxIIDUnalloc_v2_x_WIN32(data, iid);

    memcpy(&iid->value, &items[idx], sizeof(GUID));
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

struct _vboxIID_v2_x {
    /* IID is represented by a pointer to a nsID. */
    nsID *value;

    /* backing is used in cases where we need to create or copy an IID.
     * We cannot allocate memory that can be freed by ComUnallocMem.
     * Therefore, we use this stack allocated nsID instead. */
    nsID backing;
};

#  define VBOX_IID_INITIALIZER { NULL, { 0, 0, 0, { 0, 0, 0, 0, 0, 0, 0, 0 } } }

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
vboxIIDToUUID_v2_x(vboxIID_v2_x *iid, unsigned char *uuid)
{
    nsIDtoChar(uuid, iid->value);
}

static void
vboxIIDFromUUID_v2_x(vboxGlobalData *data, vboxIID_v2_x *iid,
                     const unsigned char *uuid)
{
    vboxIIDUnalloc_v2_x(data, iid);

    iid->value = &iid->backing;

    nsIDFromChar(iid->value, uuid);
}

static bool
vboxIIDIsEqual_v2_x(vboxIID_v2_x *iid1, vboxIID_v2_x *iid2)
{
    return memcmp(iid1->value, iid2->value, sizeof(nsID)) == 0;
}

static void
vboxIIDFromArrayItem_v2_x(vboxGlobalData *data, vboxIID_v2_x *iid,
                          vboxArray *array, int idx)
{
    vboxIIDUnalloc_v2_x(data, iid);

    iid->value = &iid->backing;

    memcpy(iid->value, array->items[idx], sizeof(nsID));
}

#  define vboxIIDUnalloc(iid) vboxIIDUnalloc_v2_x(data, iid)
#  define vboxIIDToUUID(iid, uuid) vboxIIDToUUID_v2_x(iid, uuid)
#  define vboxIIDFromUUID(iid, uuid) vboxIIDFromUUID_v2_x(data, iid, uuid)
#  define vboxIIDIsEqual(iid1, iid2) vboxIIDIsEqual_v2_x(iid1, iid2)
#  define vboxIIDFromArrayItem(iid, array, idx) \
    vboxIIDFromArrayItem_v2_x(data, iid, array, idx)
#  define DEBUGIID(msg, iid) DEBUGUUID(msg, iid)

# endif /* !WIN32 */

#else /* VBOX_API_VERSION != 2002 */

typedef struct _vboxIID_v3_x vboxIID;
typedef struct _vboxIID_v3_x vboxIID_v3_x;

struct _vboxIID_v3_x {
    /* IID is represented by a UTF-16 encoded UUID in string form. */
    PRUnichar *value;

    /* owner indicates if we own the value and need to free it. */
    bool owner;
};

# define VBOX_IID_INITIALIZER { NULL, true }

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
vboxIIDToUUID_v3_x(vboxGlobalData *data, vboxIID_v3_x *iid,
                   unsigned char *uuid)
{
    char *utf8 = NULL;

    data->pFuncs->pfnUtf16ToUtf8(iid->value, &utf8);

    ignore_value(virUUIDParse(utf8, uuid));

    data->pFuncs->pfnUtf8Free(utf8);
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


static void
vboxIIDFromArrayItem_v3_x(vboxGlobalData *data, vboxIID_v3_x *iid,
                          vboxArray *array, int idx)
{
    vboxIIDUnalloc_v3_x(data, iid);

    iid->value = array->items[idx];
    iid->owner = false;
}


# define vboxIIDUnalloc(iid) vboxIIDUnalloc_v3_x(data, iid)
# define vboxIIDToUUID(iid, uuid) vboxIIDToUUID_v3_x(data, iid, uuid)
# define vboxIIDFromUUID(iid, uuid) vboxIIDFromUUID_v3_x(data, iid, uuid)
# define vboxIIDIsEqual(iid1, iid2) vboxIIDIsEqual_v3_x(data, iid1, iid2)
# define vboxIIDFromArrayItem(iid, array, idx) \
    vboxIIDFromArrayItem_v3_x(data, iid, array, idx)
# define DEBUGIID(msg, strUtf16) DEBUGPRUnichar(msg, strUtf16)

# if VBOX_API_VERSION >= 3001

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
static char *vboxGenerateMediumName(PRUint32  storageBus,
                                    PRInt32   deviceInst,
                                    PRInt32   devicePort,
                                    PRInt32   deviceSlot,
                                    PRUint32 *aMaxPortPerInst,
                                    PRUint32 *aMaxSlotPerPort) {
    const char *prefix = NULL;
    char *name  = NULL;
    int   total = 0;
    PRUint32 maxPortPerInst = 0;
    PRUint32 maxSlotPerPort = 0;

    if (   !aMaxPortPerInst
        || !aMaxSlotPerPort)
        return NULL;

    if (   (storageBus < StorageBus_IDE)
        || (storageBus > StorageBus_Floppy))
        return NULL;

    maxPortPerInst = aMaxPortPerInst[storageBus];
    maxSlotPerPort = aMaxSlotPerPort[storageBus];
    total =   (deviceInst * maxPortPerInst * maxSlotPerPort)
            + (devicePort * maxSlotPerPort)
            + deviceSlot;

    if (storageBus == StorageBus_IDE) {
        prefix = "hd";
    } else if (   (storageBus == StorageBus_SATA)
               || (storageBus == StorageBus_SCSI)) {
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

    if (   !deviceName
        || !deviceInst
        || !devicePort
        || !deviceSlot
        || !aMaxPortPerInst
        || !aMaxSlotPerPort)
        return false;

    if (   (storageBus < StorageBus_IDE)
        || (storageBus > StorageBus_Floppy))
        return false;

    total = virDiskNameToIndex(deviceName);

    maxPortPerInst = aMaxPortPerInst[storageBus];
    maxSlotPerPort = aMaxSlotPerPort[storageBus];

    if (   !maxPortPerInst
        || !maxSlotPerPort
        || (total < 0))
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

static bool vboxGetMaxPortSlotValues(IVirtualBox *vbox,
                                     PRUint32 *maxPortPerInst,
                                     PRUint32 *maxSlotPerPort) {
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

/**
 * Converts Utf-16 string to int
 */
static int PRUnicharToInt(PRUnichar *strUtf16) {
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

# endif /* VBOX_API_VERSION >= 3001 */

#endif /* !(VBOX_API_VERSION == 2002) */

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


static int vboxDefaultConsoleType(const char *ostype ATTRIBUTE_UNUSED)
{
    return VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL;
}


static virCapsPtr vboxCapsInit(void) {
    struct utsname utsname;
    virCapsPtr caps;
    virCapsGuestPtr guest;

    uname(&utsname);

    if ((caps = virCapabilitiesNew(utsname.machine,
                                   0, 0)) == NULL)
        goto no_memory;

    if (nodeCapsInitNUMA(caps) < 0)
        goto no_memory;

    virCapabilitiesSetMacPrefix(caps, (unsigned char[]){ 0x08, 0x00, 0x27 });

    if ((guest = virCapabilitiesAddGuest(caps,
                                         "hvm",
                                         utsname.machine,
                                         sizeof(void *) * CHAR_BIT,
                                         NULL,
                                         NULL,
                                         0,
                                         NULL)) == NULL)
        goto no_memory;

    if (virCapabilitiesAddGuestDomain(guest,
                                      "vbox",
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto no_memory;

    caps->defaultConsoleTargetType = vboxDefaultConsoleType;

    return caps;

no_memory:
    virCapabilitiesFree(caps);
    return NULL;
}

static int
vboxInitialize(vboxGlobalData *data)
{
    data->pFuncs = g_pfnGetFunctions(VBOX_XPCOMC_VERSION);

    if (data->pFuncs == NULL)
        goto cleanup;

#if VBOX_XPCOMC_VERSION == 0x00010000U
    data->pFuncs->pfnComInitialize(&data->vboxObj, &data->vboxSession);
#else  /* !(VBOX_XPCOMC_VERSION == 0x00010000U) */
    data->pFuncs->pfnComInitialize(IVIRTUALBOX_IID_STR, &data->vboxObj,
                               ISESSION_IID_STR, &data->vboxSession);

# if VBOX_API_VERSION == 2002

    /* No event queue functionality in 2.2.* as of now */

# else  /* !(VBOX_API_VERSION == 2002) */

    /* Initial the fWatch needed for Event Callbacks */
    data->fdWatch = -1;

    data->pFuncs->pfnGetEventQueue(&data->vboxQueue);

    if (data->vboxQueue == NULL) {
        vboxError(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("nsIEventQueue object is null"));
        goto cleanup;
    }

# endif /* !(VBOX_API_VERSION == 2002) */
#endif /* !(VBOX_XPCOMC_VERSION == 0x00010000U) */

    if (data->vboxObj == NULL) {
        vboxError(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("IVirtualBox object is null"));
        goto cleanup;
    }

    if (data->vboxSession == NULL) {
        vboxError(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("ISession object is null"));
        goto cleanup;
    }

    return 0;

cleanup:
    return -1;
}

static int vboxExtractVersion(vboxGlobalData *data) {
    int ret = -1;
    PRUnichar *versionUtf16 = NULL;
    nsresult rc;

    if (data->version > 0)
        return 0;

    rc = data->vboxObj->vtbl->GetVersion(data->vboxObj, &versionUtf16);
    if (NS_SUCCEEDED(rc)) {
        char *vboxVersion = NULL;

        VBOX_UTF16_TO_UTF8(versionUtf16, &vboxVersion);

        if (virParseVersionString(vboxVersion, &data->version, false) >= 0)
            ret = 0;

        VBOX_UTF8_FREE(vboxVersion);
        VBOX_COM_UNALLOC_MEM(versionUtf16);
    }

    if (ret != 0)
        vboxError(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("Could not extract VirtualBox version"));

    return ret;
}

static void vboxUninitialize(vboxGlobalData *data) {
    if (!data)
        return;

    if (data->pFuncs)
        data->pFuncs->pfnComUninitialize();

    virCapabilitiesFree(data->caps);
#if VBOX_API_VERSION == 2002
    /* No domainEventCallbacks in 2.2.* version */
#else  /* !(VBOX_API_VERSION == 2002) */
    virDomainEventStateFree(data->domainEvents);
#endif /* !(VBOX_API_VERSION == 2002) */
    VIR_FREE(data);
}


static virDrvOpenStatus vboxOpen(virConnectPtr conn,
                                 virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                 unsigned int flags)
{
    vboxGlobalData *data = NULL;
    uid_t uid = getuid();

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (conn->uri == NULL &&
        !(conn->uri = virURIParse(uid ? "vbox:///session" : "vbox:///system")))
        return VIR_DRV_OPEN_ERROR;

    if (conn->uri->scheme == NULL ||
        STRNEQ (conn->uri->scheme, "vbox"))
        return VIR_DRV_OPEN_DECLINED;

    /* Leave for remote driver */
    if (conn->uri->server != NULL)
        return VIR_DRV_OPEN_DECLINED;

    if (conn->uri->path == NULL || STREQ(conn->uri->path, "")) {
        vboxError(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("no VirtualBox driver path specified (try vbox:///session)"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (uid != 0) {
        if (STRNEQ (conn->uri->path, "/session")) {
            vboxError(VIR_ERR_INTERNAL_ERROR,
                      _("unknown driver path '%s' specified (try vbox:///session)"), conn->uri->path);
            return VIR_DRV_OPEN_ERROR;
        }
    } else { /* root */
        if (STRNEQ (conn->uri->path, "/system") &&
            STRNEQ (conn->uri->path, "/session")) {
            vboxError(VIR_ERR_INTERNAL_ERROR,
                      _("unknown driver path '%s' specified (try vbox:///system)"), conn->uri->path);
            return VIR_DRV_OPEN_ERROR;
        }
    }

    if (VIR_ALLOC(data) < 0) {
        virReportOOMError();
        return VIR_DRV_OPEN_ERROR;
    }

    if (!(data->caps = vboxCapsInit()) ||
        vboxInitialize(data) < 0 ||
        vboxExtractVersion(data) < 0) {
        vboxUninitialize(data);
        return VIR_DRV_OPEN_ERROR;
    }

#if VBOX_API_VERSION == 2002

    /* No domainEventCallbacks in 2.2.* version */

#else  /* !(VBOX_API_VERSION == 2002) */

    if (!(data->domainEvents = virDomainEventStateNew())) {
        vboxUninitialize(data);
        return VIR_DRV_OPEN_ERROR;
    }

    data->conn = conn;
    g_pVBoxGlobalData = data;

#endif /* !(VBOX_API_VERSION == 2002) */

    conn->privateData = data;
    VIR_DEBUG("in vboxOpen");

    return VIR_DRV_OPEN_SUCCESS;
}

static int vboxClose(virConnectPtr conn) {
    vboxGlobalData *data = conn->privateData;
    VIR_DEBUG("%s: in vboxClose",conn->driver->name);

    vboxUninitialize(data);
    conn->privateData = NULL;

    return 0;
}

static int vboxGetVersion(virConnectPtr conn, unsigned long *version) {
    vboxGlobalData *data = conn->privateData;
    VIR_DEBUG("%s: in vboxGetVersion",conn->driver->name);

    vboxDriverLock(data);
    *version = data->version;
    vboxDriverUnlock(data);

    return 0;
}

static int vboxIsSecure(virConnectPtr conn ATTRIBUTE_UNUSED) {
    /* Driver is using local, non-network based transport */
    return 1;
}

static int vboxIsEncrypted(virConnectPtr conn ATTRIBUTE_UNUSED) {
    /* No encryption is needed, or used on the local transport*/
    return 0;
}

static int vboxIsAlive(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 1;
}

static int vboxGetMaxVcpus(virConnectPtr conn, const char *type ATTRIBUTE_UNUSED) {
    VBOX_OBJECT_CHECK(conn, int, -1);
    PRUint32 maxCPUCount = 0;

    /* VirtualBox Supports only hvm and thus the type passed to it
     * has no meaning, setting it to ATTRIBUTE_UNUSED
     */
    ISystemProperties *systemProperties = NULL;

    data->vboxObj->vtbl->GetSystemProperties(data->vboxObj, &systemProperties);
    if (systemProperties) {
        systemProperties->vtbl->GetMaxGuestCPUCount(systemProperties, &maxCPUCount);
        VBOX_RELEASE(systemProperties);
    }

    if (maxCPUCount > 0)
        ret = maxCPUCount;

    return ret;
}


static char *vboxGetCapabilities(virConnectPtr conn) {
    VBOX_OBJECT_CHECK(conn, char *, NULL);

    vboxDriverLock(data);
    ret = virCapabilitiesFormatXML(data->caps);
    vboxDriverUnlock(data);

    return ret;
}

static int vboxListDomains(virConnectPtr conn, int *ids, int nids) {
    VBOX_OBJECT_CHECK(conn, int, -1);
    vboxArray machines = VBOX_ARRAY_INITIALIZER;
    PRUint32 state;
    nsresult rc;
    int i, j;

    rc = vboxArrayGet(&machines, data->vboxObj, data->vboxObj->vtbl->GetMachines);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("Could not get list of Domains, rc=%08x"),(unsigned)rc);
        goto cleanup;
    }

    ret = 0;
    for (i = 0, j = 0; (i < machines.count) && (j < nids); ++i) {
        IMachine *machine = machines.items[i];

        if (machine) {
            PRBool isAccessible = PR_FALSE;
            machine->vtbl->GetAccessible(machine, &isAccessible);
            if (isAccessible) {
                machine->vtbl->GetState(machine, &state);
                if (   (state >= MachineState_FirstOnline)
                    && (state <= MachineState_LastOnline) ) {
                    ret++;
                    ids[j++] = i + 1;
                }
            }
        }
    }

cleanup:
    vboxArrayRelease(&machines);
    return ret;
}

static int vboxNumOfDomains(virConnectPtr conn) {
    VBOX_OBJECT_CHECK(conn, int, -1);
    vboxArray machines = VBOX_ARRAY_INITIALIZER;
    PRUint32 state;
    nsresult rc;
    int i;

    rc = vboxArrayGet(&machines, data->vboxObj, data->vboxObj->vtbl->GetMachines);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("Could not get number of Domains, rc=%08x"), (unsigned)rc);
        goto cleanup;
    }

    ret = 0;
    for (i = 0; i < machines.count; ++i) {
        IMachine *machine = machines.items[i];

        if (machine) {
            PRBool isAccessible = PR_FALSE;
            machine->vtbl->GetAccessible(machine, &isAccessible);
            if (isAccessible) {
                machine->vtbl->GetState(machine, &state);
                if (   (state >= MachineState_FirstOnline)
                    && (state <= MachineState_LastOnline) )
                    ret++;
            }
        }
    }

cleanup:
    vboxArrayRelease(&machines);
    return ret;
}

static virDomainPtr vboxDomainCreateXML(virConnectPtr conn, const char *xml,
                                        unsigned int flags) {
    /* VirtualBox currently doesn't have support for running
     * virtual machines without actually defining them and thus
     * for time being just define new machine and start it.
     *
     * TODO: After the appropriate API's are added in VirtualBox
     * change this behaviour to the expected one.
     */

    virDomainPtr dom;

    virCheckFlags(0, NULL);

    dom = vboxDomainDefineXML(conn, xml);
    if (dom == NULL)
        return NULL;

    if (vboxDomainCreate(dom) < 0) {
        vboxDomainUndefineFlags(dom, 0);
        virUnrefDomain(dom);
        return NULL;
    }

    return dom;
}

static virDomainPtr vboxDomainLookupByID(virConnectPtr conn, int id) {
    VBOX_OBJECT_CHECK(conn, virDomainPtr, NULL);
    vboxArray machines = VBOX_ARRAY_INITIALIZER;
    vboxIID iid = VBOX_IID_INITIALIZER;
    unsigned char uuid[VIR_UUID_BUFLEN];
    PRUint32 state;
    nsresult rc;

    /* Internal vbox IDs start from 0, the public libvirt ID
     * starts from 1, so refuse id==0, and adjust the rest*/
    if (id == 0) {
        vboxError(VIR_ERR_NO_DOMAIN,
                  _("no domain with matching id %d"), id);
        return NULL;
    }
    id = id - 1;

    rc = vboxArrayGet(&machines, data->vboxObj, data->vboxObj->vtbl->GetMachines);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("Could not get list of machines, rc=%08x"), (unsigned)rc);
        return NULL;
    }

    if (id < machines.count) {
        IMachine *machine = machines.items[id];

        if (machine) {
            PRBool isAccessible = PR_FALSE;
            machine->vtbl->GetAccessible(machine, &isAccessible);
            if (isAccessible) {
                machine->vtbl->GetState(machine, &state);
                if (   (state >= MachineState_FirstOnline)
                    && (state <= MachineState_LastOnline) ) {
                    PRUnichar *machineNameUtf16 = NULL;
                    char      *machineNameUtf8  = NULL;

                    machine->vtbl->GetName(machine, &machineNameUtf16);
                    VBOX_UTF16_TO_UTF8(machineNameUtf16, &machineNameUtf8);

                    machine->vtbl->GetId(machine, &iid.value);
                    vboxIIDToUUID(&iid, uuid);
                    vboxIIDUnalloc(&iid);

                    /* get a new domain pointer from virGetDomain, if it fails
                     * then no need to assign the id, else assign the id, cause
                     * it is -1 by default. rest is taken care by virGetDomain
                     * itself, so need not worry.
                     */

                    ret = virGetDomain(conn, machineNameUtf8, uuid);
                    if (ret)
                        ret->id = id + 1;

                    /* Cleanup all the XPCOM allocated stuff here */
                    VBOX_UTF8_FREE(machineNameUtf8);
                    VBOX_UTF16_FREE(machineNameUtf16);
                }
            }
        }
    }

    vboxArrayRelease(&machines);

    return ret;
}

static virDomainPtr vboxDomainLookupByUUID(virConnectPtr conn, const unsigned char *uuid) {
    VBOX_OBJECT_CHECK(conn, virDomainPtr, NULL);
    vboxArray machines = VBOX_ARRAY_INITIALIZER;
    vboxIID iid = VBOX_IID_INITIALIZER;
    char      *machineNameUtf8  = NULL;
    PRUnichar *machineNameUtf16 = NULL;
    unsigned char iid_as_uuid[VIR_UUID_BUFLEN];
    int i, matched = 0;
    nsresult rc;

    rc = vboxArrayGet(&machines, data->vboxObj, data->vboxObj->vtbl->GetMachines);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("Could not get list of machines, rc=%08x"), (unsigned)rc);
        return NULL;
    }

    for (i = 0; i < machines.count; ++i) {
        IMachine *machine = machines.items[i];
        PRBool isAccessible = PR_FALSE;

        if (!machine)
            continue;

        machine->vtbl->GetAccessible(machine, &isAccessible);
        if (isAccessible) {

            rc = machine->vtbl->GetId(machine, &iid.value);
            if (NS_FAILED(rc))
                continue;
            vboxIIDToUUID(&iid, iid_as_uuid);
            vboxIIDUnalloc(&iid);

            if (memcmp(uuid, iid_as_uuid, VIR_UUID_BUFLEN) == 0) {

                PRUint32 state;

                matched = 1;

                machine->vtbl->GetName(machine, &machineNameUtf16);
                VBOX_UTF16_TO_UTF8(machineNameUtf16, &machineNameUtf8);

                machine->vtbl->GetState(machine, &state);

                /* get a new domain pointer from virGetDomain, if it fails
                 * then no need to assign the id, else assign the id, cause
                 * it is -1 by default. rest is taken care by virGetDomain
                 * itself, so need not worry.
                 */

                ret = virGetDomain(conn, machineNameUtf8, iid_as_uuid);
                if (   ret
                    && (state >= MachineState_FirstOnline)
                    && (state <= MachineState_LastOnline) )
                    ret->id = i + 1;
            }

            if (matched == 1)
                break;
        }
    }

    /* Do the cleanup and take care you dont leak any memory */
    VBOX_UTF8_FREE(machineNameUtf8);
    VBOX_COM_UNALLOC_MEM(machineNameUtf16);
    vboxArrayRelease(&machines);

    return ret;
}

static virDomainPtr vboxDomainLookupByName(virConnectPtr conn, const char *name) {
    VBOX_OBJECT_CHECK(conn, virDomainPtr, NULL);
    vboxArray machines = VBOX_ARRAY_INITIALIZER;
    vboxIID iid = VBOX_IID_INITIALIZER;
    char      *machineNameUtf8  = NULL;
    PRUnichar *machineNameUtf16 = NULL;
    unsigned char uuid[VIR_UUID_BUFLEN];
    int i, matched = 0;
    nsresult rc;

    rc = vboxArrayGet(&machines, data->vboxObj, data->vboxObj->vtbl->GetMachines);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("Could not get list of machines, rc=%08x"), (unsigned)rc);
        return NULL;
    }

    for (i = 0; i < machines.count; ++i) {
        IMachine *machine = machines.items[i];
        PRBool isAccessible = PR_FALSE;

        if (!machine)
            continue;

        machine->vtbl->GetAccessible(machine, &isAccessible);
        if (isAccessible) {

            machine->vtbl->GetName(machine, &machineNameUtf16);
            VBOX_UTF16_TO_UTF8(machineNameUtf16, &machineNameUtf8);

            if (STREQ(name, machineNameUtf8)) {

                PRUint32 state;

                matched = 1;

                machine->vtbl->GetId(machine, &iid.value);
                vboxIIDToUUID(&iid, uuid);
                vboxIIDUnalloc(&iid);

                machine->vtbl->GetState(machine, &state);

                /* get a new domain pointer from virGetDomain, if it fails
                 * then no need to assign the id, else assign the id, cause
                 * it is -1 by default. rest is taken care by virGetDomain
                 * itself, so need not worry.
                 */

                ret = virGetDomain(conn, machineNameUtf8, uuid);
                if (   ret
                    && (state >= MachineState_FirstOnline)
                    && (state <= MachineState_LastOnline) )
                    ret->id = i + 1;
            }

            if (machineNameUtf8) {
                VBOX_UTF8_FREE(machineNameUtf8);
                machineNameUtf8 = NULL;
            }
            if (machineNameUtf16) {
                VBOX_COM_UNALLOC_MEM(machineNameUtf16);
                machineNameUtf16 = NULL;
            }
            if (matched == 1)
                break;
        }
    }

    vboxArrayRelease(&machines);

    return ret;
}


static int vboxDomainIsActive(virDomainPtr dom) {
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    vboxArray machines = VBOX_ARRAY_INITIALIZER;
    vboxIID iid = VBOX_IID_INITIALIZER;
    char      *machineNameUtf8  = NULL;
    PRUnichar *machineNameUtf16 = NULL;
    unsigned char uuid[VIR_UUID_BUFLEN];
    int i, matched = 0;
    nsresult rc;

    rc = vboxArrayGet(&machines, data->vboxObj, data->vboxObj->vtbl->GetMachines);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("Could not get list of machines, rc=%08x"), (unsigned)rc);
        return ret;
    }

    for (i = 0; i < machines.count; ++i) {
        IMachine *machine = machines.items[i];
        PRBool isAccessible = PR_FALSE;

        if (!machine)
            continue;

        machine->vtbl->GetAccessible(machine, &isAccessible);
        if (isAccessible) {

            rc = machine->vtbl->GetId(machine, &iid.value);
            if (NS_FAILED(rc))
                continue;
            vboxIIDToUUID(&iid, uuid);
            vboxIIDUnalloc(&iid);

            if (memcmp(dom->uuid, uuid, VIR_UUID_BUFLEN) == 0) {

                PRUint32 state;

                matched = 1;

                machine->vtbl->GetName(machine, &machineNameUtf16);
                VBOX_UTF16_TO_UTF8(machineNameUtf16, &machineNameUtf8);

                machine->vtbl->GetState(machine, &state);

                if (   (state >= MachineState_FirstOnline)
                    && (state <= MachineState_LastOnline) )
                    ret = 1;
                else
                    ret = 0;
            }

            if (matched == 1)
                break;
        }
    }

    /* Do the cleanup and take care you dont leak any memory */
    VBOX_UTF8_FREE(machineNameUtf8);
    VBOX_COM_UNALLOC_MEM(machineNameUtf16);
    vboxArrayRelease(&machines);

    return ret;
}


static int vboxDomainIsPersistent(virDomainPtr dom ATTRIBUTE_UNUSED) {
    /* All domains are persistent. */
    return 1;
}


static int vboxDomainIsUpdated(virDomainPtr dom ATTRIBUTE_UNUSED) {
    return 0;
}

static int vboxDomainSuspend(virDomainPtr dom) {
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    IMachine *machine    = NULL;
    vboxIID iid = VBOX_IID_INITIALIZER;
    IConsole *console    = NULL;
    PRBool isAccessible  = PR_FALSE;
    PRUint32 state;
    nsresult rc;

    vboxIIDFromUUID(&iid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(iid.value, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_NO_DOMAIN,
                  _("no domain with matching id %d"), dom->id);
        goto cleanup;
    }

    if (!machine)
        goto cleanup;

    machine->vtbl->GetAccessible(machine, &isAccessible);
    if (isAccessible) {
        machine->vtbl->GetState(machine, &state);

        if (state == MachineState_Running) {
            /* set state pause */
            VBOX_SESSION_OPEN_EXISTING(iid.value, machine);
            data->vboxSession->vtbl->GetConsole(data->vboxSession, &console);
            if (console) {
                console->vtbl->Pause(console);
                VBOX_RELEASE(console);
                ret = 0;
            } else {
                vboxError(VIR_ERR_OPERATION_FAILED, "%s",
                          _("error while suspending the domain"));
                goto cleanup;
            }
            VBOX_SESSION_CLOSE();
        } else {
            vboxError(VIR_ERR_OPERATION_FAILED, "%s",
                      _("machine not in running state to suspend it"));
            goto cleanup;
        }
    }

cleanup:
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    return ret;
}

static int vboxDomainResume(virDomainPtr dom) {
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    IMachine *machine    = NULL;
    vboxIID iid = VBOX_IID_INITIALIZER;
    IConsole *console    = NULL;
    PRUint32 state       = MachineState_Null;
    nsresult rc;

    PRBool isAccessible = PR_FALSE;

    vboxIIDFromUUID(&iid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(iid.value, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_NO_DOMAIN,
                  _("no domain with matching id %d"), dom->id);
        goto cleanup;
    }

    if (!machine)
        goto cleanup;

    machine->vtbl->GetAccessible(machine, &isAccessible);
    if (isAccessible) {
        machine->vtbl->GetState(machine, &state);

        if (state == MachineState_Paused) {
            /* resume the machine here */
            VBOX_SESSION_OPEN_EXISTING(iid.value, machine);
            data->vboxSession->vtbl->GetConsole(data->vboxSession, &console);
            if (console) {
                console->vtbl->Resume(console);
                VBOX_RELEASE(console);
                ret = 0;
            } else {
                vboxError(VIR_ERR_OPERATION_FAILED, "%s",
                          _("error while resuming the domain"));
                goto cleanup;
            }
            VBOX_SESSION_CLOSE();
        } else {
            vboxError(VIR_ERR_OPERATION_FAILED, "%s",
                      _("machine not paused, so can't resume it"));
            goto cleanup;
        }
    }

cleanup:
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    return ret;
}

static int vboxDomainShutdownFlags(virDomainPtr dom,
                                   unsigned int flags) {
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    IMachine *machine    = NULL;
    vboxIID iid = VBOX_IID_INITIALIZER;
    IConsole *console    = NULL;
    PRUint32 state       = MachineState_Null;
    PRBool isAccessible  = PR_FALSE;
    nsresult rc;

    virCheckFlags(0, -1);

    vboxIIDFromUUID(&iid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(iid.value, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_NO_DOMAIN,
                  _("no domain with matching id %d"), dom->id);
        goto cleanup;
    }

    if (!machine)
        goto cleanup;

    machine->vtbl->GetAccessible(machine, &isAccessible);
    if (isAccessible) {
        machine->vtbl->GetState(machine, &state);

        if (state == MachineState_Paused) {
            vboxError(VIR_ERR_OPERATION_FAILED, "%s",
                      _("machine paused, so can't power it down"));
            goto cleanup;
        } else if (state == MachineState_PoweredOff) {
            vboxError(VIR_ERR_OPERATION_FAILED, "%s",
                      _("machine already powered down"));
            goto cleanup;
        }

        VBOX_SESSION_OPEN_EXISTING(iid.value, machine);
        data->vboxSession->vtbl->GetConsole(data->vboxSession, &console);
        if (console) {
            console->vtbl->PowerButton(console);
            VBOX_RELEASE(console);
            ret = 0;
        }
        VBOX_SESSION_CLOSE();
    }

cleanup:
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    return ret;
}

static int vboxDomainShutdown(virDomainPtr dom) {
    return vboxDomainShutdownFlags(dom, 0);
}


static int vboxDomainReboot(virDomainPtr dom, unsigned int flags)
{
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    IMachine *machine    = NULL;
    vboxIID iid = VBOX_IID_INITIALIZER;
    IConsole *console    = NULL;
    PRUint32 state       = MachineState_Null;
    PRBool isAccessible  = PR_FALSE;
    nsresult rc;

    virCheckFlags(0, -1);

    vboxIIDFromUUID(&iid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(iid.value, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_NO_DOMAIN,
                  _("no domain with matching id %d"), dom->id);
        goto cleanup;
    }

    if (!machine)
        goto cleanup;

    machine->vtbl->GetAccessible(machine, &isAccessible);
    if (isAccessible) {
        machine->vtbl->GetState(machine, &state);

        if (state == MachineState_Running) {
            VBOX_SESSION_OPEN_EXISTING(iid.value, machine);
            data->vboxSession->vtbl->GetConsole(data->vboxSession, &console);
            if (console) {
                console->vtbl->Reset(console);
                VBOX_RELEASE(console);
                ret = 0;
            }
            VBOX_SESSION_CLOSE();
        } else {
            vboxError(VIR_ERR_OPERATION_FAILED, "%s",
                      _("machine not running, so can't reboot it"));
            goto cleanup;
        }
    }

cleanup:
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    return ret;
}

static int
vboxDomainDestroyFlags(virDomainPtr dom,
                       unsigned int flags)
{
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    IMachine *machine    = NULL;
    vboxIID iid = VBOX_IID_INITIALIZER;
    IConsole *console    = NULL;
    PRUint32 state       = MachineState_Null;
    PRBool isAccessible  = PR_FALSE;
    nsresult rc;

    virCheckFlags(0, -1);

    vboxIIDFromUUID(&iid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(iid.value, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_NO_DOMAIN,
                  _("no domain with matching id %d"), dom->id);
        goto cleanup;
    }

    if (!machine)
        goto cleanup;

    machine->vtbl->GetAccessible(machine, &isAccessible);
    if (isAccessible) {
        machine->vtbl->GetState(machine, &state);

        if (state == MachineState_PoweredOff) {
            vboxError(VIR_ERR_OPERATION_FAILED, "%s",
                      _("machine already powered down"));
            goto cleanup;
        }

        VBOX_SESSION_OPEN_EXISTING(iid.value, machine);
        data->vboxSession->vtbl->GetConsole(data->vboxSession, &console);
        if (console) {

#if VBOX_API_VERSION == 2002
            console->vtbl->PowerDown(console);
#else
            IProgress *progress = NULL;
            console->vtbl->PowerDown(console, &progress);
            if (progress) {
                progress->vtbl->WaitForCompletion(progress, -1);
                VBOX_RELEASE(progress);
            }
#endif
            VBOX_RELEASE(console);
            dom->id = -1;
            ret = 0;
        }
        VBOX_SESSION_CLOSE();
    }

cleanup:
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    return ret;
}

static int
vboxDomainDestroy(virDomainPtr dom)
{
    return vboxDomainDestroyFlags(dom, 0);
}

static char *vboxDomainGetOSType(virDomainPtr dom ATTRIBUTE_UNUSED) {
    /* Returning "hvm" always as suggested on list, cause
     * this functions seems to be badly named and it
     * is supposed to pass the ABI name and not the domain
     * operating system driver as I had imagined ;)
     */
    char *osType = strdup("hvm");

    if (osType == NULL)
        virReportOOMError();

    return osType;
}

static int vboxDomainSetMemory(virDomainPtr dom, unsigned long memory) {
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    IMachine *machine    = NULL;
    vboxIID iid = VBOX_IID_INITIALIZER;
    PRUint32 state       = MachineState_Null;
    PRBool isAccessible  = PR_FALSE;
    nsresult rc;

    vboxIIDFromUUID(&iid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(iid.value, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_NO_DOMAIN,
                  _("no domain with matching id %d"), dom->id);
        goto cleanup;
    }

    if (!machine)
        goto cleanup;

    machine->vtbl->GetAccessible(machine, &isAccessible);
    if (isAccessible) {
        machine->vtbl->GetState(machine, &state);

        if (state != MachineState_PoweredOff) {
            vboxError(VIR_ERR_OPERATION_FAILED, "%s",
                      _("memory size can't be changed unless domain is powered down"));
            goto cleanup;
        }

        rc = VBOX_SESSION_OPEN(iid.value, machine);
        if (NS_SUCCEEDED(rc)) {
            rc = data->vboxSession->vtbl->GetMachine(data->vboxSession, &machine);
            if (NS_SUCCEEDED(rc) && machine) {

                rc = machine->vtbl->SetMemorySize(machine,
                                                  VIR_DIV_UP(memory, 1024));
                if (NS_SUCCEEDED(rc)) {
                    machine->vtbl->SaveSettings(machine);
                    ret = 0;
                } else {
                    vboxError(VIR_ERR_INTERNAL_ERROR,
                              _("could not set the memory size of the "
                                "domain to: %lu Kb, rc=%08x"),
                              memory, (unsigned)rc);
                }
            }
            VBOX_SESSION_CLOSE();
        }
    }

cleanup:
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    return ret;
}

static int vboxDomainGetInfo(virDomainPtr dom, virDomainInfoPtr info) {
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    vboxArray machines = VBOX_ARRAY_INITIALIZER;
    char *machineName    = NULL;
    PRUnichar *machineNameUtf16 = NULL;
    nsresult rc;
    int i = 0;

    rc = vboxArrayGet(&machines, data->vboxObj, data->vboxObj->vtbl->GetMachines);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("Could not get list of machines, rc=%08x"), (unsigned)rc);
        goto cleanup;
    }

    info->nrVirtCpu = 0;
    for (i = 0; i < machines.count; ++i) {
        IMachine *machine = machines.items[i];
        PRBool isAccessible = PR_FALSE;

        if (!machine)
            continue;

        machine->vtbl->GetAccessible(machine, &isAccessible);
        if (isAccessible) {

            machine->vtbl->GetName(machine, &machineNameUtf16);
            VBOX_UTF16_TO_UTF8(machineNameUtf16, &machineName);

            if (STREQ(dom->name, machineName)) {
                /* Get the Machine State (also match it with
                * virDomainState). Get the Machine memory and
                * for time being set max_balloon and cur_balloon to same
                * Also since there is no direct way of checking
                * the cputime required (one condition being the
                * VM is remote), return zero for cputime. Get the
                * number of CPU.
                */
                PRUint32 CPUCount   = 0;
                PRUint32 memorySize = 0;
                PRUint32 state      = MachineState_Null;
                PRUint32 maxMemorySize = 4 * 1024;
                ISystemProperties *systemProperties = NULL;

                data->vboxObj->vtbl->GetSystemProperties(data->vboxObj, &systemProperties);
                if (systemProperties) {
                    systemProperties->vtbl->GetMaxGuestRAM(systemProperties, &maxMemorySize);
                    VBOX_RELEASE(systemProperties);
                    systemProperties = NULL;
                }


                machine->vtbl->GetCPUCount(machine, &CPUCount);
                machine->vtbl->GetMemorySize(machine, &memorySize);
                machine->vtbl->GetState(machine, &state);

                info->cpuTime = 0;
                info->nrVirtCpu = CPUCount;
                info->memory = memorySize * 1024;
                info->maxMem = maxMemorySize * 1024;
                switch(state) {
                    case MachineState_Running:
                        info->state = VIR_DOMAIN_RUNNING;
                        break;
                    case MachineState_Stuck:
                        info->state = VIR_DOMAIN_BLOCKED;
                        break;
                    case MachineState_Paused:
                        info->state = VIR_DOMAIN_PAUSED;
                        break;
                    case MachineState_Stopping:
                        info->state = VIR_DOMAIN_SHUTDOWN;
                        break;
                    case MachineState_PoweredOff:
                        info->state = VIR_DOMAIN_SHUTOFF;
                        break;
                    case MachineState_Aborted:
                        info->state = VIR_DOMAIN_CRASHED;
                        break;
                    case MachineState_Null:
                    default:
                        info->state = VIR_DOMAIN_NOSTATE;
                        break;
                }

                ret = 0;
            }

            if (machineName)
                VBOX_UTF8_FREE(machineName);
            if (machineNameUtf16)
                VBOX_COM_UNALLOC_MEM(machineNameUtf16);
            if (info->nrVirtCpu)
                break;
        }

    }

    vboxArrayRelease(&machines);

cleanup:
    return ret;
}

static int
vboxDomainGetState(virDomainPtr dom,
                   int *state,
                   int *reason,
                   unsigned int flags)
{
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    vboxIID domiid = VBOX_IID_INITIALIZER;
    IMachine *machine = NULL;
    PRUint32 mstate = MachineState_Null;
    nsresult rc;

    virCheckFlags(0, -1);

    vboxIIDFromUUID(&domiid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(domiid.value, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_NO_DOMAIN, "%s",
                  _("no domain with matching UUID"));
        goto cleanup;
    }

    machine->vtbl->GetState(machine, &mstate);

    switch (mstate) {
    case MachineState_Running:
        *state = VIR_DOMAIN_RUNNING;
        break;
    case MachineState_Stuck:
        *state = VIR_DOMAIN_BLOCKED;
        break;
    case MachineState_Paused:
        *state = VIR_DOMAIN_PAUSED;
        break;
    case MachineState_Stopping:
        *state = VIR_DOMAIN_SHUTDOWN;
        break;
    case MachineState_PoweredOff:
        *state = VIR_DOMAIN_SHUTOFF;
        break;
    case MachineState_Aborted:
        *state = VIR_DOMAIN_CRASHED;
        break;
    case MachineState_Null:
    default:
        *state = VIR_DOMAIN_NOSTATE;
        break;
    }

    if (reason)
        *reason = 0;

    ret = 0;

cleanup:
    vboxIIDUnalloc(&domiid);
    return ret;
}

static int vboxDomainSave(virDomainPtr dom, const char *path ATTRIBUTE_UNUSED) {
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    IConsole *console    = NULL;
    vboxIID iid = VBOX_IID_INITIALIZER;
    IMachine *machine = NULL;
    nsresult rc;

    /* VirtualBox currently doesn't support saving to a file
     * at a location other then the machine folder and thus
     * setting path to ATTRIBUTE_UNUSED for now, will change
     * this behaviour once get the VirtualBox API in right
     * shape to do this
     */

    /* Open a Session for the machine */
    vboxIIDFromUUID(&iid, dom->uuid);
#if VBOX_API_VERSION >= 4000
    /* Get machine for the call to VBOX_SESSION_OPEN_EXISTING */
    rc = VBOX_OBJECT_GET_MACHINE(iid.value, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_NO_DOMAIN, "%s",
                  _("no domain with matching uuid"));
        return -1;
    }
#endif

    rc = VBOX_SESSION_OPEN_EXISTING(iid.value, machine);
    if (NS_SUCCEEDED(rc)) {
        rc = data->vboxSession->vtbl->GetConsole(data->vboxSession, &console);
        if (NS_SUCCEEDED(rc) && console) {
            IProgress *progress = NULL;

            console->vtbl->SaveState(console, &progress);

            if (progress) {
#if VBOX_API_VERSION == 2002
                nsresult resultCode;
#else
                PRInt32 resultCode;
#endif

                progress->vtbl->WaitForCompletion(progress, -1);
                progress->vtbl->GetResultCode(progress, &resultCode);
                if (NS_SUCCEEDED(resultCode)) {
                    ret = 0;
                }
                VBOX_RELEASE(progress);
            }
            VBOX_RELEASE(console);
        }
        VBOX_SESSION_CLOSE();
    }

    DEBUGIID("UUID of machine being saved:", iid.value);

    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    return ret;
}

static int
vboxDomainSetVcpusFlags(virDomainPtr dom, unsigned int nvcpus,
                        unsigned int flags)
{
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    IMachine *machine    = NULL;
    vboxIID iid = VBOX_IID_INITIALIZER;
    PRUint32  CPUCount   = nvcpus;
    nsresult rc;

    if (flags != VIR_DOMAIN_AFFECT_LIVE) {
        vboxError(VIR_ERR_INVALID_ARG, _("unsupported flags: (0x%x)"), flags);
        return -1;
    }

    vboxIIDFromUUID(&iid, dom->uuid);
#if VBOX_API_VERSION >= 4000
    /* Get machine for the call to VBOX_SESSION_OPEN */
    rc = VBOX_OBJECT_GET_MACHINE(iid.value, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_NO_DOMAIN, "%s",
                  _("no domain with matching uuid"));
        return -1;
    }
#endif

    rc = VBOX_SESSION_OPEN(iid.value, machine);
    if (NS_SUCCEEDED(rc)) {
        data->vboxSession->vtbl->GetMachine(data->vboxSession, &machine);
        if (machine) {
            rc = machine->vtbl->SetCPUCount(machine, CPUCount);
            if (NS_SUCCEEDED(rc)) {
                machine->vtbl->SaveSettings(machine);
                ret = 0;
            } else {
                vboxError(VIR_ERR_INTERNAL_ERROR,
                          _("could not set the number of cpus of the domain "
                            "to: %u, rc=%08x"),
                          CPUCount, (unsigned)rc);
            }
            VBOX_RELEASE(machine);
        } else {
            vboxError(VIR_ERR_NO_DOMAIN,
                      _("no domain with matching id %d"), dom->id);
        }
    } else {
        vboxError(VIR_ERR_NO_DOMAIN,
                  _("can't open session to the domain with id %d"), dom->id);
    }
    VBOX_SESSION_CLOSE();

    vboxIIDUnalloc(&iid);
    return ret;
}

static int
vboxDomainSetVcpus(virDomainPtr dom, unsigned int nvcpus)
{
    return vboxDomainSetVcpusFlags(dom, nvcpus, VIR_DOMAIN_AFFECT_LIVE);
}

static int
vboxDomainGetVcpusFlags(virDomainPtr dom, unsigned int flags)
{
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    ISystemProperties *systemProperties = NULL;
    PRUint32 maxCPUCount = 0;

    if (flags != (VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_VCPU_MAXIMUM)) {
        vboxError(VIR_ERR_INVALID_ARG, _("unsupported flags: (0x%x)"), flags);
        return -1;
    }

    /* Currently every domain supports the same number of max cpus
     * as that supported by vbox and thus take it directly from
     * the systemproperties.
     */

    data->vboxObj->vtbl->GetSystemProperties(data->vboxObj, &systemProperties);
    if (systemProperties) {
        systemProperties->vtbl->GetMaxGuestCPUCount(systemProperties, &maxCPUCount);
        VBOX_RELEASE(systemProperties);
    }

    if (maxCPUCount > 0)
        ret = maxCPUCount;

    return ret;
}

static int
vboxDomainGetMaxVcpus(virDomainPtr dom)
{
    return vboxDomainGetVcpusFlags(dom, (VIR_DOMAIN_AFFECT_LIVE |
                                         VIR_DOMAIN_VCPU_MAXIMUM));
}

static char *vboxDomainGetXMLDesc(virDomainPtr dom, unsigned int flags) {
    VBOX_OBJECT_CHECK(dom->conn, char *, NULL);
    virDomainDefPtr def  = NULL;
    IMachine *machine    = NULL;
    vboxIID iid = VBOX_IID_INITIALIZER;
    int gotAllABoutDef   = -1;
    nsresult rc;
    char *tmp;

    /* Flags checked by virDomainDefFormat */

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    vboxIIDFromUUID(&iid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(iid.value, &machine);
    if (NS_SUCCEEDED(rc)) {
        PRBool accessible = PR_FALSE;

        machine->vtbl->GetAccessible(machine, &accessible);
        if (accessible) {
            int i = 0;
            struct utsname utsname;
            PRBool PAEEnabled                   = PR_FALSE;
            PRBool ACPIEnabled                  = PR_FALSE;
            PRBool IOAPICEnabled                = PR_FALSE;
            PRBool VRDxEnabled                  = PR_FALSE;
            PRUint32 CPUCount                   = 0;
            PRUint32 memorySize                 = 0;
            PRUint32 netAdpCnt                  = 0;
            PRUint32 netAdpIncCnt               = 0;
            PRUint32 maxMemorySize              = 4 * 1024;
            PRUint32 USBFilterCount             = 0;
            PRUint32 maxBootPosition            = 0;
            PRUint32 serialPortCount            = 0;
            PRUint32 serialPortIncCount         = 0;
            PRUint32 parallelPortCount          = 0;
            PRUint32 parallelPortIncCount       = 0;
            IBIOSSettings *bios                 = NULL;
#if VBOX_API_VERSION < 3001
            PRInt32       hddNum                = 0;
            IDVDDrive    *dvdDrive              = NULL;
            IHardDisk    *hardDiskPM            = NULL;
            IHardDisk    *hardDiskPS            = NULL;
            IHardDisk    *hardDiskSS            = NULL;
            const char   *hddBus                = "IDE";
            PRUnichar    *hddBusUtf16           = NULL;
            IFloppyDrive *floppyDrive           = NULL;
#else  /* VBOX_API_VERSION >= 3001 */
            vboxArray mediumAttachments         = VBOX_ARRAY_INITIALIZER;
#endif /* VBOX_API_VERSION >= 3001 */
#if VBOX_API_VERSION < 4000
            IVRDPServer *VRDxServer             = NULL;
#else  /* VBOX_API_VERSION >= 4000 */
            IVRDEServer *VRDxServer             = NULL;
#endif /* VBOX_API_VERSION >= 4000 */
            IAudioAdapter *audioAdapter         = NULL;
            IUSBController *USBController       = NULL;
#if VBOX_API_VERSION >= 4001
            PRUint32 chipsetType                = ChipsetType_Null;
#endif /* VBOX_API_VERSION >= 4001 */
            ISystemProperties *systemProperties = NULL;


            def->virtType = VIR_DOMAIN_VIRT_VBOX;
            def->id = dom->id;
            memcpy(def->uuid, dom->uuid, VIR_UUID_BUFLEN);
            def->name = strdup(dom->name);

            machine->vtbl->GetMemorySize(machine, &memorySize);
            def->mem.cur_balloon = memorySize * 1024;

#if VBOX_API_VERSION >= 4001
            machine->vtbl->GetChipsetType(machine, &chipsetType);
#endif /* VBOX_API_VERSION >= 4001 */

            data->vboxObj->vtbl->GetSystemProperties(data->vboxObj, &systemProperties);
            if (systemProperties) {
                systemProperties->vtbl->GetMaxGuestRAM(systemProperties, &maxMemorySize);
                systemProperties->vtbl->GetMaxBootPosition(systemProperties, &maxBootPosition);
#if VBOX_API_VERSION < 4001
                systemProperties->vtbl->GetNetworkAdapterCount(systemProperties, &netAdpCnt);
#else  /* VBOX_API_VERSION >= 4000 */
                systemProperties->vtbl->GetMaxNetworkAdapters(systemProperties, chipsetType, &netAdpCnt);
#endif /* VBOX_API_VERSION >= 4000 */
                systemProperties->vtbl->GetSerialPortCount(systemProperties, &serialPortCount);
                systemProperties->vtbl->GetParallelPortCount(systemProperties, &parallelPortCount);
                VBOX_RELEASE(systemProperties);
                systemProperties = NULL;
            }
            /* Currently setting memory and maxMemory as same, cause
             * the notation here seems to be inconsistent while
             * reading and while dumping xml
             */
            /* def->mem.max_balloon = maxMemorySize * 1024; */
            def->mem.max_balloon = memorySize * 1024;

            machine->vtbl->GetCPUCount(machine, &CPUCount);
            def->maxvcpus = def->vcpus = CPUCount;

            /* Skip cpumasklen, cpumask, onReboot, onPoweroff, onCrash */

            def->os.type = strdup("hvm");

            uname(&utsname);
            def->os.arch = strdup(utsname.machine);

            def->os.nBootDevs = 0;
            for (i = 0; (i < VIR_DOMAIN_BOOT_LAST) && (i < maxBootPosition); i++) {
                PRUint32 device = DeviceType_Null;

                machine->vtbl->GetBootOrder(machine, i+1, &device);

                if (device == DeviceType_Floppy) {
                    def->os.bootDevs[i] = VIR_DOMAIN_BOOT_FLOPPY;
                    def->os.nBootDevs++;
                } else if (device == DeviceType_DVD) {
                    def->os.bootDevs[i] = VIR_DOMAIN_BOOT_CDROM;
                    def->os.nBootDevs++;
                } else if (device == DeviceType_HardDisk) {
                    def->os.bootDevs[i] = VIR_DOMAIN_BOOT_DISK;
                    def->os.nBootDevs++;
                } else if (device == DeviceType_Network) {
                    def->os.bootDevs[i] = VIR_DOMAIN_BOOT_NET;
                    def->os.nBootDevs++;
                } else if (device == DeviceType_USB) {
                    /* Not supported by libvirt yet */
                } else if (device == DeviceType_SharedFolder) {
                    /* Not supported by libvirt yet */
                    /* Can VirtualBox really boot from a shared folder? */
                }
            }

            def->features = 0;
#if VBOX_API_VERSION < 3001
            machine->vtbl->GetPAEEnabled(machine, &PAEEnabled);
#elif VBOX_API_VERSION == 3001
            machine->vtbl->GetCpuProperty(machine, CpuPropertyType_PAE, &PAEEnabled);
#elif VBOX_API_VERSION >= 3002
            machine->vtbl->GetCPUProperty(machine, CPUPropertyType_PAE, &PAEEnabled);
#endif
            if (PAEEnabled) {
                def->features = def->features | (1 << VIR_DOMAIN_FEATURE_PAE);
            }

            machine->vtbl->GetBIOSSettings(machine, &bios);
            if (bios) {
                bios->vtbl->GetACPIEnabled(bios, &ACPIEnabled);
                if (ACPIEnabled) {
                    def->features = def->features | (1 << VIR_DOMAIN_FEATURE_ACPI);
                }

                bios->vtbl->GetIOAPICEnabled(bios, &IOAPICEnabled);
                if (IOAPICEnabled) {
                    def->features = def->features | (1 << VIR_DOMAIN_FEATURE_APIC);
                }

                VBOX_RELEASE(bios);
            }

            /* Currently VirtualBox always uses locatime
             * so locatime is always true here */
            def->clock.offset = VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME;

            /* dump video options vram/2d/3d/directx/etc. */
            {
                /* Currently supports only one graphics card */
                def->nvideos = 1;
                if (VIR_ALLOC_N(def->videos, def->nvideos) >= 0) {
                    if (VIR_ALLOC(def->videos[0]) >= 0) {
                        /* the default is: vram is 8MB, One monitor, 3dAccel Off */
                        PRUint32 VRAMSize          = 8;
                        PRUint32 monitorCount      = 1;
                        PRBool accelerate3DEnabled = PR_FALSE;
                        PRBool accelerate2DEnabled = PR_FALSE;

                        machine->vtbl->GetVRAMSize(machine, &VRAMSize);
                        machine->vtbl->GetMonitorCount(machine, &monitorCount);
                        machine->vtbl->GetAccelerate3DEnabled(machine, &accelerate3DEnabled);
#if VBOX_API_VERSION >= 3001
                        machine->vtbl->GetAccelerate2DVideoEnabled(machine, &accelerate2DEnabled);
#endif /* VBOX_API_VERSION >= 3001 */

                        def->videos[0]->type            = VIR_DOMAIN_VIDEO_TYPE_VBOX;
                        def->videos[0]->vram            = VRAMSize * 1024;
                        def->videos[0]->heads           = monitorCount;
                        if (VIR_ALLOC(def->videos[0]->accel) >= 0) {
                            def->videos[0]->accel->support3d = accelerate3DEnabled;
                            def->videos[0]->accel->support2d = accelerate2DEnabled;
                        } else
                            virReportOOMError();
                    } else
                        virReportOOMError();
                } else
                    virReportOOMError();
            }

            /* dump display options vrdp/gui/sdl */
            {
                int vrdpPresent           = 0;
                int sdlPresent            = 0;
                int guiPresent            = 0;
                int totalPresent          = 0;
                char *guiDisplay          = NULL;
                char *sdlDisplay          = NULL;
                PRUnichar *keyTypeUtf16   = NULL;
                PRUnichar *valueTypeUtf16 = NULL;
                char      *valueTypeUtf8  = NULL;

                def->ngraphics = 0;

                VBOX_UTF8_TO_UTF16("FRONTEND/Type", &keyTypeUtf16);
                machine->vtbl->GetExtraData(machine, keyTypeUtf16, &valueTypeUtf16);
                VBOX_UTF16_FREE(keyTypeUtf16);

                if (valueTypeUtf16) {
                    VBOX_UTF16_TO_UTF8(valueTypeUtf16, &valueTypeUtf8);
                    VBOX_UTF16_FREE(valueTypeUtf16);

                    if ( STREQ(valueTypeUtf8, "sdl") || STREQ(valueTypeUtf8, "gui") ) {
                        PRUnichar *keyDislpayUtf16   = NULL;
                        PRUnichar *valueDisplayUtf16 = NULL;
                        char      *valueDisplayUtf8  = NULL;

                        VBOX_UTF8_TO_UTF16("FRONTEND/Display", &keyDislpayUtf16);
                        machine->vtbl->GetExtraData(machine, keyDislpayUtf16, &valueDisplayUtf16);
                        VBOX_UTF16_FREE(keyDislpayUtf16);

                        if (valueDisplayUtf16) {
                            VBOX_UTF16_TO_UTF8(valueDisplayUtf16, &valueDisplayUtf8);
                            VBOX_UTF16_FREE(valueDisplayUtf16);

                            if (strlen(valueDisplayUtf8) <= 0) {
                                VBOX_UTF8_FREE(valueDisplayUtf8);
                                valueDisplayUtf8 = NULL;
                            }
                        }

                        if (STREQ(valueTypeUtf8, "sdl")) {
                            sdlPresent = 1;
                            if (valueDisplayUtf8)
                                sdlDisplay = strdup(valueDisplayUtf8);
                            if (sdlDisplay == NULL) {
                                virReportOOMError();
                                /* just don't go to cleanup yet as it is ok to have
                                 * sdlDisplay as NULL and we check it below if it
                                 * exist and then only use it there
                                 */
                            }
                            totalPresent++;
                        }

                        if (STREQ(valueTypeUtf8, "gui")) {
                            guiPresent = 1;
                            if (valueDisplayUtf8)
                                guiDisplay = strdup(valueDisplayUtf8);
                            if (guiDisplay == NULL) {
                                virReportOOMError();
                                /* just don't go to cleanup yet as it is ok to have
                                 * guiDisplay as NULL and we check it below if it
                                 * exist and then only use it there
                                 */
                            }
                            totalPresent++;
                        }
                        if (valueDisplayUtf8)
                            VBOX_UTF8_FREE(valueDisplayUtf8);
                    }

                    if (STREQ(valueTypeUtf8, "vrdp"))
                        vrdpPresent = 1;

                    VBOX_UTF8_FREE(valueTypeUtf8);
                }

                if ((totalPresent > 0) && (VIR_ALLOC_N(def->graphics, totalPresent) >= 0)) {
                    if ((guiPresent) && (VIR_ALLOC(def->graphics[def->ngraphics]) >= 0)) {
                        def->graphics[def->ngraphics]->type = VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP;
                        if (guiDisplay)
                            def->graphics[def->ngraphics]->data.desktop.display = guiDisplay;
                        def->ngraphics++;
                    }

                    if ((sdlPresent) && (VIR_ALLOC(def->graphics[def->ngraphics]) >= 0)) {
                        def->graphics[def->ngraphics]->type = VIR_DOMAIN_GRAPHICS_TYPE_SDL;
                        if (sdlDisplay)
                            def->graphics[def->ngraphics]->data.sdl.display = sdlDisplay;
                        def->ngraphics++;
                    }
                } else if ((vrdpPresent != 1) && (totalPresent == 0) && (VIR_ALLOC_N(def->graphics, 1) >= 0)) {
                    if (VIR_ALLOC(def->graphics[def->ngraphics]) >= 0) {
                        def->graphics[def->ngraphics]->type = VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP;
                        tmp = getenv("DISPLAY");
                        if (tmp != NULL) {
                            def->graphics[def->ngraphics]->data.desktop.display = strdup(tmp);
                            if (def->graphics[def->ngraphics]->data.desktop.display == NULL) {
                                virReportOOMError();
                                /* just don't go to cleanup yet as it is ok to have
                                 * display as NULL
                                 */
                            }
                        }
                        totalPresent++;
                        def->ngraphics++;
                    }
                }

#if VBOX_API_VERSION < 4000
                machine->vtbl->GetVRDPServer(machine, &VRDxServer);
#else  /* VBOX_API_VERSION >= 4000 */
                machine->vtbl->GetVRDEServer(machine, &VRDxServer);
#endif /* VBOX_API_VERSION >= 4000 */
                if (VRDxServer) {
                    VRDxServer->vtbl->GetEnabled(VRDxServer, &VRDxEnabled);
                    if (VRDxEnabled) {

                        totalPresent++;

                        if ((VIR_REALLOC_N(def->graphics, totalPresent) >= 0) &&
                            (VIR_ALLOC(def->graphics[def->ngraphics]) >= 0)) {
                            PRUnichar *netAddressUtf16   = NULL;
                            char      *netAddressUtf8    = NULL;
                            PRBool allowMultiConnection  = PR_FALSE;
                            PRBool reuseSingleConnection = PR_FALSE;
#if VBOX_API_VERSION < 3001
                            PRUint32 VRDPport = 0;
                            VRDxServer->vtbl->GetPort(VRDxServer, &VRDPport);
                            if (VRDPport) {
                                def->graphics[def->ngraphics]->data.rdp.port = VRDPport;
#elif VBOX_API_VERSION < 4000 /* 3001 <= VBOX_API_VERSION < 4000 */
                            PRUnichar *VRDPport = NULL;
                            VRDxServer->vtbl->GetPorts(VRDxServer, &VRDPport);
                            if (VRDPport) {
                                /* even if vbox supports mutilpe ports, single port for now here */
                                def->graphics[def->ngraphics]->data.rdp.port = PRUnicharToInt(VRDPport);
                                VBOX_UTF16_FREE(VRDPport);
#else /* VBOX_API_VERSION >= 4000 */
                            PRUnichar *VRDEPortsKey = NULL;
                            PRUnichar *VRDEPortsValue = NULL;
                            VBOX_UTF8_TO_UTF16("TCP/Ports", &VRDEPortsKey);
                            VRDxServer->vtbl->GetVRDEProperty(VRDxServer, VRDEPortsKey, &VRDEPortsValue);
                            VBOX_UTF16_FREE(VRDEPortsKey);
                            if (VRDEPortsValue) {
                                /* even if vbox supports mutilpe ports, single port for now here */
                                def->graphics[def->ngraphics]->data.rdp.port = PRUnicharToInt(VRDEPortsValue);
                                VBOX_UTF16_FREE(VRDEPortsValue);
#endif /* VBOX_API_VERSION >= 4000 */
                            } else {
                                def->graphics[def->ngraphics]->data.rdp.autoport = 1;
                            }

                            def->graphics[def->ngraphics]->type = VIR_DOMAIN_GRAPHICS_TYPE_RDP;

#if VBOX_API_VERSION >= 4000
                            PRUnichar *VRDENetAddressKey = NULL;
                            VBOX_UTF8_TO_UTF16("TCP/Address", &VRDENetAddressKey);
                            VRDxServer->vtbl->GetVRDEProperty(VRDxServer, VRDENetAddressKey, &netAddressUtf16);
                            VBOX_UTF16_FREE(VRDENetAddressKey);
#else /* VBOX_API_VERSION < 4000 */
                            VRDxServer->vtbl->GetNetAddress(VRDxServer, &netAddressUtf16);
#endif /* VBOX_API_VERSION < 4000 */
                            if (netAddressUtf16) {
                                VBOX_UTF16_TO_UTF8(netAddressUtf16, &netAddressUtf8);
                                if (STRNEQ(netAddressUtf8, ""))
                                    virDomainGraphicsListenSetAddress(def->graphics[def->ngraphics], 0,
                                                                      netAddressUtf8, -1, true);
                                VBOX_UTF16_FREE(netAddressUtf16);
                                VBOX_UTF8_FREE(netAddressUtf8);
                            }

                            VRDxServer->vtbl->GetAllowMultiConnection(VRDxServer, &allowMultiConnection);
                            if (allowMultiConnection) {
                                def->graphics[def->ngraphics]->data.rdp.multiUser = 1;
                            }

                            VRDxServer->vtbl->GetReuseSingleConnection(VRDxServer, &reuseSingleConnection);
                            if (reuseSingleConnection) {
                                def->graphics[def->ngraphics]->data.rdp.replaceUser = 1;
                            }

                            def->ngraphics++;
                        } else
                            virReportOOMError();
                    }
                    VBOX_RELEASE(VRDxServer);
                }
            }

#if VBOX_API_VERSION < 3001
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
                for (i = 0; i < def->ndisks; i++) {
                    if (VIR_ALLOC(def->disks[i]) >= 0) {
                        def->disks[i]->device = VIR_DOMAIN_DISK_DEVICE_DISK;
                        def->disks[i]->bus = VIR_DOMAIN_DISK_BUS_IDE;
                        def->disks[i]->type = VIR_DOMAIN_DISK_TYPE_FILE;
                    } else
                        virReportOOMError();
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
                    def->disks[hddNum]->readonly = 1;
                def->disks[hddNum]->src = strdup(hddlocation);
                def->disks[hddNum]->dst = strdup("hda");
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
                    def->disks[hddNum]->readonly = 1;
                def->disks[hddNum]->src = strdup(hddlocation);
                def->disks[hddNum]->dst = strdup("hdb");
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
                    def->disks[hddNum]->readonly = 1;
                def->disks[hddNum]->src = strdup(hddlocation);
                def->disks[hddNum]->dst = strdup("hdd");
                hddNum++;

                VBOX_UTF8_FREE(hddlocation);
                VBOX_UTF16_FREE(hddlocationUtf16);
                VBOX_MEDIUM_RELEASE(hardDiskSS);
            }
#else  /* VBOX_API_VERSION >= 3001 */
            /* dump IDE hdds if present */

            bool error = false;
            int diskCount = 0;
            PRUint32   maxPortPerInst[StorageBus_Floppy + 1] = {};
            PRUint32   maxSlotPerPort[StorageBus_Floppy + 1] = {};
            def->ndisks = 0;
            vboxArrayGet(&mediumAttachments, machine, machine->vtbl->GetMediumAttachments);

            /* get the number of attachments */
            for (i = 0; i < mediumAttachments.count; i++) {
                IMediumAttachment *imediumattach = mediumAttachments.items[i];
                if (imediumattach) {
                    IMedium *medium = NULL;

                    imediumattach->vtbl->GetMedium(imediumattach, &medium);
                    if (medium) {
                        def->ndisks++;
                        VBOX_RELEASE(medium);
                    }
                }
            }

            /* Allocate mem, if fails return error */
            if (VIR_ALLOC_N(def->disks, def->ndisks) >= 0) {
                for (i = 0; i < def->ndisks; i++) {
                    if (VIR_ALLOC(def->disks[i]) < 0) {
                        virReportOOMError();
                        error = true;
                        break;
                    }
                }
            } else {
                virReportOOMError();
                error = true;
            }

            if (!error)
                error = !vboxGetMaxPortSlotValues(data->vboxObj, maxPortPerInst, maxSlotPerPort);

            /* get the attachment details here */
            for (i = 0; i < mediumAttachments.count && diskCount < def->ndisks && !error; i++) {
                IMediumAttachment *imediumattach = mediumAttachments.items[i];
                IStorageController *storageController = NULL;
                PRUnichar *storageControllerName = NULL;
                PRUint32   deviceType     = DeviceType_Null;
                PRUint32   storageBus     = StorageBus_Null;
                PRBool     readOnly       = PR_FALSE;
                IMedium   *medium         = NULL;
                PRUnichar *mediumLocUtf16 = NULL;
                char      *mediumLocUtf8  = NULL;
                PRUint32   deviceInst     = 0;
                PRInt32    devicePort     = 0;
                PRInt32    deviceSlot     = 0;

                if (!imediumattach)
                    continue;

                imediumattach->vtbl->GetMedium(imediumattach, &medium);
                if (!medium)
                    continue;

                imediumattach->vtbl->GetController(imediumattach, &storageControllerName);
                if (!storageControllerName) {
                    VBOX_RELEASE(medium);
                    continue;
                }

                machine->vtbl->GetStorageControllerByName(machine,
                                                          storageControllerName,
                                                          &storageController);
                VBOX_UTF16_FREE(storageControllerName);
                if (!storageController) {
                    VBOX_RELEASE(medium);
                    continue;
                }

                medium->vtbl->GetLocation(medium, &mediumLocUtf16);
                VBOX_UTF16_TO_UTF8(mediumLocUtf16, &mediumLocUtf8);
                VBOX_UTF16_FREE(mediumLocUtf16);
                def->disks[diskCount]->src = strdup(mediumLocUtf8);
                VBOX_UTF8_FREE(mediumLocUtf8);

                if (!(def->disks[diskCount]->src)) {
                    VBOX_RELEASE(medium);
                    VBOX_RELEASE(storageController);
                    virReportOOMError();
                    error = true;
                    break;
                }

                storageController->vtbl->GetBus(storageController, &storageBus);
                if (storageBus == StorageBus_IDE) {
                    def->disks[diskCount]->bus = VIR_DOMAIN_DISK_BUS_IDE;
                } else if (storageBus == StorageBus_SATA) {
                    def->disks[diskCount]->bus = VIR_DOMAIN_DISK_BUS_SATA;
                } else if (storageBus == StorageBus_SCSI) {
                    def->disks[diskCount]->bus = VIR_DOMAIN_DISK_BUS_SCSI;
                } else if (storageBus == StorageBus_Floppy) {
                    def->disks[diskCount]->bus = VIR_DOMAIN_DISK_BUS_FDC;
                }

                imediumattach->vtbl->GetType(imediumattach, &deviceType);
                if (deviceType == DeviceType_HardDisk)
                    def->disks[diskCount]->device = VIR_DOMAIN_DISK_DEVICE_DISK;
                else if (deviceType == DeviceType_Floppy)
                    def->disks[diskCount]->device = VIR_DOMAIN_DISK_DEVICE_FLOPPY;
                else if (deviceType == DeviceType_DVD)
                    def->disks[diskCount]->device = VIR_DOMAIN_DISK_DEVICE_CDROM;

                imediumattach->vtbl->GetPort(imediumattach, &devicePort);
                imediumattach->vtbl->GetDevice(imediumattach, &deviceSlot);
                def->disks[diskCount]->dst = vboxGenerateMediumName(storageBus,
                                                                    deviceInst,
                                                                    devicePort,
                                                                    deviceSlot,
                                                                    maxPortPerInst,
                                                                    maxSlotPerPort);
                if (!def->disks[diskCount]->dst) {
                    vboxError(VIR_ERR_INTERNAL_ERROR,
                              _("Could not generate medium name for the disk "
                                "at: controller instance:%u, port:%d, slot:%d"),
                              deviceInst, devicePort, deviceSlot);
                    VBOX_RELEASE(medium);
                    VBOX_RELEASE(storageController);
                    error = true;
                    break;
                }

                medium->vtbl->GetReadOnly(medium, &readOnly);
                if (readOnly == PR_TRUE)
                    def->disks[diskCount]->readonly = 1;

                def->disks[diskCount]->type = VIR_DOMAIN_DISK_TYPE_FILE;

                VBOX_RELEASE(medium);
                VBOX_RELEASE(storageController);
                diskCount++;
            }

            vboxArrayRelease(&mediumAttachments);

            /* cleanup on error */
            if (error) {
                for (i = 0; i < def->ndisks; i++) {
                    VIR_FREE(def->disks[i]);
                }
                VIR_FREE(def->disks);
                def->ndisks = 0;
            }

#endif /* VBOX_API_VERSION >= 3001 */

            /* shared folders */
            vboxArray sharedFolders = VBOX_ARRAY_INITIALIZER;

            def->nfss = 0;

            vboxArrayGet(&sharedFolders, machine,
                         machine->vtbl->GetSharedFolders);

            if (sharedFolders.count > 0) {
                if (VIR_ALLOC_N(def->fss, sharedFolders.count) < 0) {
                    virReportOOMError();
                    goto sharedFoldersCleanup;
                }

                for (i = 0; i < sharedFolders.count; i++) {
                    ISharedFolder *sharedFolder = sharedFolders.items[i];
                    PRUnichar *nameUtf16 = NULL;
                    char *name = NULL;
                    PRUnichar *hostPathUtf16 = NULL;
                    char *hostPath = NULL;
                    PRBool writable = PR_FALSE;

                    if (VIR_ALLOC(def->fss[i]) < 0) {
                        virReportOOMError();
                        goto sharedFoldersCleanup;
                    }

                    def->fss[i]->type = VIR_DOMAIN_FS_TYPE_MOUNT;

                    sharedFolder->vtbl->GetHostPath(sharedFolder, &hostPathUtf16);
                    VBOX_UTF16_TO_UTF8(hostPathUtf16, &hostPath);
                    def->fss[i]->src = strdup(hostPath);
                    VBOX_UTF8_FREE(hostPath);
                    VBOX_UTF16_FREE(hostPathUtf16);

                    if (def->fss[i]->src == NULL) {
                        virReportOOMError();
                        goto sharedFoldersCleanup;
                    }

                    sharedFolder->vtbl->GetName(sharedFolder, &nameUtf16);
                    VBOX_UTF16_TO_UTF8(nameUtf16, &name);
                    def->fss[i]->dst = strdup(name);
                    VBOX_UTF8_FREE(name);
                    VBOX_UTF16_FREE(nameUtf16);

                    if (def->fss[i]->dst == NULL) {
                        virReportOOMError();
                        goto sharedFoldersCleanup;
                    }

                    sharedFolder->vtbl->GetWritable(sharedFolder, &writable);
                    def->fss[i]->readonly = !writable;

                    ++def->nfss;
                }
            }

sharedFoldersCleanup:
            vboxArrayRelease(&sharedFolders);

            /* dump network cards if present */
            def->nnets = 0;
            /* Get which network cards are enabled */
            for (i = 0; i < netAdpCnt; i++) {
                INetworkAdapter *adapter = NULL;

                machine->vtbl->GetNetworkAdapter(machine, i, &adapter);
                if (adapter) {
                    PRBool enabled = PR_FALSE;

                    adapter->vtbl->GetEnabled(adapter, &enabled);
                    if (enabled) {
                        def->nnets++;
                    }

                    VBOX_RELEASE(adapter);
                }
            }

            /* Allocate memory for the networkcards which are enabled */
            if ((def->nnets > 0) && (VIR_ALLOC_N(def->nets, def->nnets) >= 0)) {
                for (i = 0; i < def->nnets; i++) {
                    if (VIR_ALLOC(def->nets[i]) >= 0) {
                    } else
                        virReportOOMError();
                }
            }

            /* Now get the details about the network cards here */
            for (i = 0;(netAdpIncCnt < def->nnets) && (i < netAdpCnt); i++) {
                INetworkAdapter *adapter = NULL;

                machine->vtbl->GetNetworkAdapter(machine, i, &adapter);
                if (adapter) {
                    PRBool enabled = PR_FALSE;

                    adapter->vtbl->GetEnabled(adapter, &enabled);
                    if (enabled) {
                        PRUint32 attachmentType    = NetworkAttachmentType_Null;
                        PRUint32 adapterType       = NetworkAdapterType_Null;
                        PRUnichar *MACAddressUtf16 = NULL;
                        char *MACAddress           = NULL;
                        char macaddr[VIR_MAC_STRING_BUFLEN] = {0};

                        adapter->vtbl->GetAttachmentType(adapter, &attachmentType);
                        if (attachmentType == NetworkAttachmentType_NAT) {

                            def->nets[netAdpIncCnt]->type = VIR_DOMAIN_NET_TYPE_USER;

                        } else if (attachmentType == NetworkAttachmentType_Bridged) {
                            PRUnichar *hostIntUtf16 = NULL;
                            char *hostInt           = NULL;

                            def->nets[netAdpIncCnt]->type = VIR_DOMAIN_NET_TYPE_BRIDGE;

#if VBOX_API_VERSION < 4001
                            adapter->vtbl->GetHostInterface(adapter, &hostIntUtf16);
#else /* VBOX_API_VERSION >= 4001 */
                            adapter->vtbl->GetBridgedInterface(adapter, &hostIntUtf16);
#endif /* VBOX_API_VERSION >= 4001 */

                            VBOX_UTF16_TO_UTF8(hostIntUtf16, &hostInt);
                            def->nets[netAdpIncCnt]->data.bridge.brname = strdup(hostInt);

                            VBOX_UTF8_FREE(hostInt);
                            VBOX_UTF16_FREE(hostIntUtf16);

                        } else if (attachmentType == NetworkAttachmentType_Internal) {
                            PRUnichar *intNetUtf16 = NULL;
                            char *intNet           = NULL;

                            def->nets[netAdpIncCnt]->type = VIR_DOMAIN_NET_TYPE_INTERNAL;

                            adapter->vtbl->GetInternalNetwork(adapter, &intNetUtf16);

                            VBOX_UTF16_TO_UTF8(intNetUtf16, &intNet);
                            def->nets[netAdpIncCnt]->data.internal.name = strdup(intNet);

                            VBOX_UTF8_FREE(intNet);
                            VBOX_UTF16_FREE(intNetUtf16);

                        } else if (attachmentType == NetworkAttachmentType_HostOnly) {
                            PRUnichar *hostIntUtf16 = NULL;
                            char *hostInt           = NULL;

                            def->nets[netAdpIncCnt]->type = VIR_DOMAIN_NET_TYPE_NETWORK;

#if VBOX_API_VERSION < 4001
                            adapter->vtbl->GetHostInterface(adapter, &hostIntUtf16);
#else /* VBOX_API_VERSION >= 4001 */
                            adapter->vtbl->GetHostOnlyInterface(adapter, &hostIntUtf16);
#endif /* VBOX_API_VERSION >= 4001 */

                            VBOX_UTF16_TO_UTF8(hostIntUtf16, &hostInt);
                            def->nets[netAdpIncCnt]->data.network.name = strdup(hostInt);

                            VBOX_UTF8_FREE(hostInt);
                            VBOX_UTF16_FREE(hostIntUtf16);

                        } else {
                            /* default to user type i.e. NAT in VirtualBox if this
                             * dump is ever used to create a machine.
                             */
                            def->nets[netAdpIncCnt]->type = VIR_DOMAIN_NET_TYPE_USER;
                        }

                        adapter->vtbl->GetAdapterType(adapter, &adapterType);
                        if (adapterType == NetworkAdapterType_Am79C970A) {
                            def->nets[netAdpIncCnt]->model = strdup("Am79C970A");
                        } else if (adapterType == NetworkAdapterType_Am79C973) {
                            def->nets[netAdpIncCnt]->model = strdup("Am79C973");
                        } else if (adapterType == NetworkAdapterType_I82540EM) {
                            def->nets[netAdpIncCnt]->model = strdup("82540EM");
                        } else if (adapterType == NetworkAdapterType_I82545EM) {
                            def->nets[netAdpIncCnt]->model = strdup("82545EM");
                        } else if (adapterType == NetworkAdapterType_I82543GC) {
                            def->nets[netAdpIncCnt]->model = strdup("82543GC");
#if VBOX_API_VERSION >= 3001
                        } else if (adapterType == NetworkAdapterType_Virtio) {
                            def->nets[netAdpIncCnt]->model = strdup("virtio");
#endif /* VBOX_API_VERSION >= 3001 */
                        }

                        adapter->vtbl->GetMACAddress(adapter, &MACAddressUtf16);
                        VBOX_UTF16_TO_UTF8(MACAddressUtf16, &MACAddress);
                        snprintf(macaddr, VIR_MAC_STRING_BUFLEN,
                                 "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",
                                 MACAddress[0], MACAddress[1], MACAddress[2], MACAddress[3],
                                 MACAddress[4], MACAddress[5], MACAddress[6], MACAddress[7],
                                 MACAddress[8], MACAddress[9], MACAddress[10], MACAddress[11]);

                        /* XXX some real error handling here some day ... */
                        if (virMacAddrParse(macaddr, def->nets[netAdpIncCnt]->mac) < 0)
                        {}

                        netAdpIncCnt++;

                        VBOX_UTF16_FREE(MACAddressUtf16);
                        VBOX_UTF8_FREE(MACAddress);
                    }

                    VBOX_RELEASE(adapter);
                }
            }

            /* dump sound card if active */

            /* Set def->nsounds to one as VirtualBox currently supports
             * only one sound card
             */

            machine->vtbl->GetAudioAdapter(machine, &audioAdapter);
            if (audioAdapter) {
                PRBool enabled = PR_FALSE;

                audioAdapter->vtbl->GetEnabled(audioAdapter, &enabled);
                if (enabled) {
                    PRUint32 audioController = AudioControllerType_AC97;

                    def->nsounds = 1;
                    if (VIR_ALLOC_N(def->sounds, def->nsounds) >= 0) {
                        if (VIR_ALLOC(def->sounds[0]) >= 0) {
                            audioAdapter->vtbl->GetAudioController(audioAdapter, &audioController);
                            if (audioController == AudioControllerType_SB16) {
                                def->sounds[0]->model = VIR_DOMAIN_SOUND_MODEL_SB16;
                            } else if (audioController == AudioControllerType_AC97) {
                                def->sounds[0]->model = VIR_DOMAIN_SOUND_MODEL_AC97;
                            }
                        } else {
                            VIR_FREE(def->sounds);
                            def->nsounds = 0;
                            virReportOOMError();
                        }
                    } else {
                        def->nsounds = 0;
                        virReportOOMError();
                    }
                }
                VBOX_RELEASE(audioAdapter);
            }

#if VBOX_API_VERSION < 3001
            /* dump CDROM/DVD if the drive is attached and has DVD/CD in it */
            machine->vtbl->GetDVDDrive(machine, &dvdDrive);
            if (dvdDrive) {
                PRUint32 state = DriveState_Null;

                dvdDrive->vtbl->GetState(dvdDrive, &state);
                if (state == DriveState_ImageMounted) {
                    IDVDImage *dvdImage = NULL;

                    dvdDrive->vtbl->GetImage(dvdDrive, &dvdImage);
                    if (dvdImage) {
                        PRUnichar *locationUtf16 = NULL;
                        char *location           = NULL;

                        dvdImage->vtbl->imedium.GetLocation((IMedium *)dvdImage, &locationUtf16);
                        VBOX_UTF16_TO_UTF8(locationUtf16, &location);

                        def->ndisks++;
                        if (VIR_REALLOC_N(def->disks, def->ndisks) >= 0) {
                            if (VIR_ALLOC(def->disks[def->ndisks - 1]) >= 0) {
                                def->disks[def->ndisks - 1]->device = VIR_DOMAIN_DISK_DEVICE_CDROM;
                                def->disks[def->ndisks - 1]->bus = VIR_DOMAIN_DISK_BUS_IDE;
                                def->disks[def->ndisks - 1]->type = VIR_DOMAIN_DISK_TYPE_FILE;
                                def->disks[def->ndisks - 1]->readonly = 1;
                                def->disks[def->ndisks - 1]->src = strdup(location);
                                def->disks[def->ndisks - 1]->dst = strdup("hdc");
                            } else {
                                def->ndisks--;
                                virReportOOMError();
                            }
                        } else {
                            def->ndisks--;
                            virReportOOMError();
                        }

                        VBOX_UTF8_FREE(location);
                        VBOX_UTF16_FREE(locationUtf16);
                        VBOX_MEDIUM_RELEASE(dvdImage);
                    }
                }
                VBOX_RELEASE(dvdDrive);
            }

            /* dump Floppy if the drive is attached and has floppy in it */
            machine->vtbl->GetFloppyDrive(machine, &floppyDrive);
            if (floppyDrive) {
                PRBool enabled = PR_FALSE;

                floppyDrive->vtbl->GetEnabled(floppyDrive, &enabled);
                if (enabled) {
                    PRUint32 state = DriveState_Null;

                    floppyDrive->vtbl->GetState(floppyDrive, &state);
                    if (state == DriveState_ImageMounted) {
                        IFloppyImage *floppyImage = NULL;

                        floppyDrive->vtbl->GetImage(floppyDrive, &floppyImage);
                        if (floppyImage) {
                            PRUnichar *locationUtf16 = NULL;
                            char *location           = NULL;

                            floppyImage->vtbl->imedium.GetLocation((IMedium *)floppyImage, &locationUtf16);
                            VBOX_UTF16_TO_UTF8(locationUtf16, &location);

                            def->ndisks++;
                            if (VIR_REALLOC_N(def->disks, def->ndisks) >= 0) {
                                if (VIR_ALLOC(def->disks[def->ndisks - 1]) >= 0) {
                                    def->disks[def->ndisks - 1]->device = VIR_DOMAIN_DISK_DEVICE_FLOPPY;
                                    def->disks[def->ndisks - 1]->bus = VIR_DOMAIN_DISK_BUS_FDC;
                                    def->disks[def->ndisks - 1]->type = VIR_DOMAIN_DISK_TYPE_FILE;
                                    def->disks[def->ndisks - 1]->readonly = 0;
                                    def->disks[def->ndisks - 1]->src = strdup(location);
                                    def->disks[def->ndisks - 1]->dst = strdup("fda");
                                } else {
                                    def->ndisks--;
                                    virReportOOMError();
                                }
                            } else {
                                def->ndisks--;
                                virReportOOMError();
                            }

                            VBOX_UTF8_FREE(location);
                            VBOX_UTF16_FREE(locationUtf16);
                            VBOX_MEDIUM_RELEASE(floppyImage);
                        }
                    }
                }

                VBOX_RELEASE(floppyDrive);
            }
#else  /* VBOX_API_VERSION >= 3001 */
#endif /* VBOX_API_VERSION >= 3001 */

            /* dump serial port if active */
            def->nserials = 0;
            /* Get which serial ports are enabled/active */
            for (i = 0; i < serialPortCount; i++) {
                ISerialPort *serialPort = NULL;

                machine->vtbl->GetSerialPort(machine, i, &serialPort);
                if (serialPort) {
                    PRBool enabled = PR_FALSE;

                    serialPort->vtbl->GetEnabled(serialPort, &enabled);
                    if (enabled) {
                        def->nserials++;
                    }

                    VBOX_RELEASE(serialPort);
                }
            }

            /* Allocate memory for the serial ports which are enabled */
            if ((def->nserials > 0) && (VIR_ALLOC_N(def->serials, def->nserials) >= 0)) {
                for (i = 0; i < def->nserials; i++) {
                    if (VIR_ALLOC(def->serials[i]) >= 0) {
                    } else
                        virReportOOMError();
                }
            }

            /* Now get the details about the serial ports here */
            for (i = 0;(serialPortIncCount < def->nserials) && (i < serialPortCount); i++) {
                ISerialPort *serialPort = NULL;

                machine->vtbl->GetSerialPort(machine, i, &serialPort);
                if (serialPort) {
                    PRBool enabled = PR_FALSE;

                    serialPort->vtbl->GetEnabled(serialPort, &enabled);
                    if (enabled) {
                        PRUint32 hostMode    = PortMode_Disconnected;
                        PRUint32 IOBase      = 0;
                        PRUint32 IRQ         = 0;
                        PRUnichar *pathUtf16 = NULL;
                        char *path           = NULL;

                        serialPort->vtbl->GetHostMode(serialPort, &hostMode);
                        if (hostMode == PortMode_HostPipe) {
                            def->serials[serialPortIncCount]->source.type = VIR_DOMAIN_CHR_TYPE_PIPE;
                        } else if (hostMode == PortMode_HostDevice) {
                            def->serials[serialPortIncCount]->source.type = VIR_DOMAIN_CHR_TYPE_DEV;
#if VBOX_API_VERSION >= 3000
                        } else if (hostMode == PortMode_RawFile) {
                            def->serials[serialPortIncCount]->source.type = VIR_DOMAIN_CHR_TYPE_FILE;
#endif /* VBOX_API_VERSION >= 3000 */
                        } else {
                            def->serials[serialPortIncCount]->source.type = VIR_DOMAIN_CHR_TYPE_NULL;
                        }

                        def->serials[serialPortIncCount]->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL;

                        serialPort->vtbl->GetIRQ(serialPort, &IRQ);
                        serialPort->vtbl->GetIOBase(serialPort, &IOBase);
                        if ((IRQ == 4) && (IOBase == 1016)) {
                            def->serials[serialPortIncCount]->target.port = 0;
                        } else if ((IRQ == 3) && (IOBase == 760)) {
                            def->serials[serialPortIncCount]->target.port = 1;
                        }

                        serialPort->vtbl->GetPath(serialPort, &pathUtf16);

                        if (pathUtf16) {
                            VBOX_UTF16_TO_UTF8(pathUtf16, &path);
                            def->serials[serialPortIncCount]->source.data.file.path = strdup(path);
                        }

                        serialPortIncCount++;

                        VBOX_UTF16_FREE(pathUtf16);
                        VBOX_UTF8_FREE(path);
                    }

                    VBOX_RELEASE(serialPort);
                }
            }

            /* dump parallel ports if active */
            def->nparallels = 0;
            /* Get which parallel ports are enabled/active */
            for (i = 0; i < parallelPortCount; i++) {
                IParallelPort *parallelPort = NULL;

                machine->vtbl->GetParallelPort(machine, i, &parallelPort);
                if (parallelPort) {
                    PRBool enabled = PR_FALSE;

                    parallelPort->vtbl->GetEnabled(parallelPort, &enabled);
                    if (enabled) {
                        def->nparallels++;
                    }

                    VBOX_RELEASE(parallelPort);
                }
            }

            /* Allocate memory for the parallel ports which are enabled */
            if ((def->nparallels > 0) && (VIR_ALLOC_N(def->parallels, def->nparallels) >= 0)) {
                for (i = 0; i < def->nparallels; i++) {
                    if (VIR_ALLOC(def->parallels[i]) >= 0) {
                    } else
                        virReportOOMError();
                }
            }

            /* Now get the details about the parallel ports here */
            for (i = 0;(parallelPortIncCount < def->nparallels) && (i < parallelPortCount); i++) {
                IParallelPort *parallelPort = NULL;

                machine->vtbl->GetParallelPort(machine, i, &parallelPort);
                if (parallelPort) {
                    PRBool enabled = PR_FALSE;

                    parallelPort->vtbl->GetEnabled(parallelPort, &enabled);
                    if (enabled) {
                        PRUint32 IOBase      = 0;
                        PRUint32 IRQ         = 0;
                        PRUnichar *pathUtf16 = NULL;
                        char *path           = NULL;

                        parallelPort->vtbl->GetIRQ(parallelPort, &IRQ);
                        parallelPort->vtbl->GetIOBase(parallelPort, &IOBase);
                        if ((IRQ == 7) && (IOBase == 888)) {
                            def->parallels[parallelPortIncCount]->target.port = 0;
                        } else if ((IRQ == 5) && (IOBase == 632)) {
                            def->parallels[parallelPortIncCount]->target.port = 1;
                        }

                        def->parallels[parallelPortIncCount]->source.type = VIR_DOMAIN_CHR_TYPE_FILE;
                        def->parallels[parallelPortIncCount]->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL;

                        parallelPort->vtbl->GetPath(parallelPort, &pathUtf16);

                        VBOX_UTF16_TO_UTF8(pathUtf16, &path);
                        def->parallels[parallelPortIncCount]->source.data.file.path = strdup(path);

                        parallelPortIncCount++;

                        VBOX_UTF16_FREE(pathUtf16);
                        VBOX_UTF8_FREE(path);
                    }

                    VBOX_RELEASE(parallelPort);
                }
            }

            /* dump USB devices/filters if active */
            def->nhostdevs = 0;
            machine->vtbl->GetUSBController(machine, &USBController);
            if (USBController) {
                PRBool enabled = PR_FALSE;

                USBController->vtbl->GetEnabled(USBController, &enabled);
                if (enabled) {
                    vboxArray deviceFilters = VBOX_ARRAY_INITIALIZER;

                    vboxArrayGet(&deviceFilters, USBController,
                                 USBController->vtbl->GetDeviceFilters);

                    if (deviceFilters.count > 0) {

                        /* check if the filters are active and then only
                         * alloc mem and set def->nhostdevs
                         */

                        for(i = 0; i < deviceFilters.count; i++) {
                            PRBool active = PR_FALSE;
                            IUSBDeviceFilter *deviceFilter = deviceFilters.items[i];

                            deviceFilter->vtbl->GetActive(deviceFilter, &active);
                            if (active) {
                                def->nhostdevs++;
                            }
                        }

                        if (def->nhostdevs > 0) {
                            /* Alloc mem needed for the filters now */
                            if (VIR_ALLOC_N(def->hostdevs, def->nhostdevs) >= 0) {

                                for(i = 0; (USBFilterCount < def->nhostdevs) || (i < deviceFilters.count); i++) {
                                    PRBool active = PR_FALSE;
                                    IUSBDeviceFilter *deviceFilter = deviceFilters.items[i];

                                    deviceFilter->vtbl->GetActive(deviceFilter, &active);
                                    if (active) {
                                        if (VIR_ALLOC(def->hostdevs[USBFilterCount]) >= 0) {
                                            PRUnichar *vendorIdUtf16  = NULL;
                                            char *vendorIdUtf8        = NULL;
                                            unsigned vendorId         = 0;
                                            PRUnichar *productIdUtf16 = NULL;
                                            char *productIdUtf8       = NULL;
                                            unsigned productId        = 0;
                                            char *endptr              = NULL;

                                            def->hostdevs[USBFilterCount]->mode =
                                                VIR_DOMAIN_HOSTDEV_MODE_SUBSYS;
                                            def->hostdevs[USBFilterCount]->source.subsys.type =
                                                VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB;

                                            deviceFilter->vtbl->GetVendorId(deviceFilter, &vendorIdUtf16);
                                            deviceFilter->vtbl->GetProductId(deviceFilter, &productIdUtf16);

                                            VBOX_UTF16_TO_UTF8(vendorIdUtf16, &vendorIdUtf8);
                                            VBOX_UTF16_TO_UTF8(productIdUtf16, &productIdUtf8);

                                            vendorId  = strtol(vendorIdUtf8, &endptr, 16);
                                            productId = strtol(productIdUtf8, &endptr, 16);

                                            def->hostdevs[USBFilterCount]->source.subsys.u.usb.vendor  = vendorId;
                                            def->hostdevs[USBFilterCount]->source.subsys.u.usb.product = productId;

                                            VBOX_UTF16_FREE(vendorIdUtf16);
                                            VBOX_UTF8_FREE(vendorIdUtf8);

                                            VBOX_UTF16_FREE(productIdUtf16);
                                            VBOX_UTF8_FREE(productIdUtf8);

                                            USBFilterCount++;
                                        } else
                                            virReportOOMError();
                                    }
                                }
                            } else
                                virReportOOMError();
                        }
                    }

                    /* Cleanup */
                    vboxArrayRelease(&deviceFilters);
                }
                VBOX_RELEASE(USBController);
            }

            /* all done so set gotAllABoutDef and pass def to virDomainDefFormat
             * to generate XML for it
             */
            gotAllABoutDef = 0;
        }
        VBOX_RELEASE(machine);
        machine = NULL;
    }

    if (gotAllABoutDef == 0)
        ret = virDomainDefFormat(def, flags);

cleanup:
    vboxIIDUnalloc(&iid);
    virDomainDefFree(def);
    return ret;
}

static int vboxListDefinedDomains(virConnectPtr conn, char ** const names, int maxnames) {
    VBOX_OBJECT_CHECK(conn, int, -1);
    vboxArray machines = VBOX_ARRAY_INITIALIZER;
    char *machineName    = NULL;
    PRUnichar *machineNameUtf16 = NULL;
    PRUint32 state;
    nsresult rc;
    int i, j;

    rc = vboxArrayGet(&machines, data->vboxObj, data->vboxObj->vtbl->GetMachines);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("Could not get list of Defined Domains, rc=%08x"),
                  (unsigned)rc);
        goto cleanup;
    }

    ret = 0;
    for (i = 0, j = 0; (i < machines.count) && (j < maxnames); i++) {
        IMachine *machine = machines.items[i];

        if (machine) {
            PRBool isAccessible = PR_FALSE;
            machine->vtbl->GetAccessible(machine, &isAccessible);
            if (isAccessible) {
                machine->vtbl->GetState(machine, &state);
                if (   (state < MachineState_FirstOnline)
                    || (state > MachineState_LastOnline) ) {
                    machine->vtbl->GetName(machine, &machineNameUtf16);
                    VBOX_UTF16_TO_UTF8(machineNameUtf16, &machineName);
                    names[j] = strdup(machineName);
                    VBOX_UTF16_FREE(machineNameUtf16);
                    VBOX_UTF8_FREE(machineName);
                    if (!names[j]) {
                        virReportOOMError();
                        for ( ; j >= 0 ; j--)
                            VIR_FREE(names[j]);
                        ret = -1;
                        goto cleanup;
                    }
                    j++;
                    ret++;
                }
            }
        }
    }

cleanup:
    vboxArrayRelease(&machines);
    return ret;
}

static int vboxNumOfDefinedDomains(virConnectPtr conn) {
    VBOX_OBJECT_CHECK(conn, int, -1);
    vboxArray machines = VBOX_ARRAY_INITIALIZER;
    PRUint32 state       = MachineState_Null;
    nsresult rc;
    int i;

    rc = vboxArrayGet(&machines, data->vboxObj, data->vboxObj->vtbl->GetMachines);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("Could not get number of Defined Domains, rc=%08x"),
                  (unsigned)rc);
        goto cleanup;
    }

    ret = 0;
    for (i = 0; i < machines.count; ++i) {
        IMachine *machine = machines.items[i];

        if (machine) {
            PRBool isAccessible = PR_FALSE;
            machine->vtbl->GetAccessible(machine, &isAccessible);
            if (isAccessible) {
                machine->vtbl->GetState(machine, &state);
                if (   (state < MachineState_FirstOnline)
                    || (state > MachineState_LastOnline) ) {
                    ret++;
                }
            }
        }
    }

cleanup:
    vboxArrayRelease(&machines);
    return ret;
}


static int
vboxStartMachine(virDomainPtr dom, int i, IMachine *machine,
                 vboxIID *iid ATTRIBUTE_UNUSED /* >= 4.0 */)
{
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    int vrdpPresent              = 0;
    int sdlPresent               = 0;
    int guiPresent               = 0;
    char *guiDisplay             = NULL;
    char *sdlDisplay             = NULL;
    PRUnichar *keyTypeUtf16      = NULL;
    PRUnichar *valueTypeUtf16    = NULL;
    char      *valueTypeUtf8     = NULL;
    PRUnichar *keyDislpayUtf16   = NULL;
    PRUnichar *valueDisplayUtf16 = NULL;
    char      *valueDisplayUtf8  = NULL;
    IProgress *progress          = NULL;
    PRUnichar *env               = NULL;
    PRUnichar *sessionType       = NULL;
    nsresult rc;

    VBOX_UTF8_TO_UTF16("FRONTEND/Type", &keyTypeUtf16);
    machine->vtbl->GetExtraData(machine, keyTypeUtf16, &valueTypeUtf16);
    VBOX_UTF16_FREE(keyTypeUtf16);

    if (valueTypeUtf16) {
        VBOX_UTF16_TO_UTF8(valueTypeUtf16, &valueTypeUtf8);
        VBOX_UTF16_FREE(valueTypeUtf16);

        if ( STREQ(valueTypeUtf8, "sdl") || STREQ(valueTypeUtf8, "gui") ) {

            VBOX_UTF8_TO_UTF16("FRONTEND/Display", &keyDislpayUtf16);
            machine->vtbl->GetExtraData(machine, keyDislpayUtf16,
                                        &valueDisplayUtf16);
            VBOX_UTF16_FREE(keyDislpayUtf16);

            if (valueDisplayUtf16) {
                VBOX_UTF16_TO_UTF8(valueDisplayUtf16, &valueDisplayUtf8);
                VBOX_UTF16_FREE(valueDisplayUtf16);

                if (strlen(valueDisplayUtf8) <= 0) {
                    VBOX_UTF8_FREE(valueDisplayUtf8);
                    valueDisplayUtf8 = NULL;
                }
            }

            if (STREQ(valueTypeUtf8, "sdl")) {
                sdlPresent = 1;
                if (valueDisplayUtf8) {
                    sdlDisplay = strdup(valueDisplayUtf8);
                    if (sdlDisplay == NULL) {
                        virReportOOMError();
                        /* just don't go to cleanup yet as it is ok to have
                         * sdlDisplay as NULL and we check it below if it
                         * exist and then only use it there
                         */
                    }
                }
            }

            if (STREQ(valueTypeUtf8, "gui")) {
                guiPresent = 1;
                if (valueDisplayUtf8) {
                    guiDisplay = strdup(valueDisplayUtf8);
                    if (guiDisplay == NULL) {
                        virReportOOMError();
                        /* just don't go to cleanup yet as it is ok to have
                         * guiDisplay as NULL and we check it below if it
                         * exist and then only use it there
                         */
                    }
                }
            }
        }

        if (STREQ(valueTypeUtf8, "vrdp")) {
            vrdpPresent = 1;
        }

        if (!vrdpPresent && !sdlPresent && !guiPresent) {
            /* if nothing is selected it means either the machine xml
             * file is really old or some values are missing so fallback
             */
            guiPresent = 1;
        }

        VBOX_UTF8_FREE(valueTypeUtf8);

    } else {
        guiPresent = 1;
    }
    if (valueDisplayUtf8)
        VBOX_UTF8_FREE(valueDisplayUtf8);

    if (guiPresent) {
        if (guiDisplay) {
            char *displayutf8;
            if (virAsprintf(&displayutf8, "DISPLAY=%s", guiDisplay) < 0)
                virReportOOMError();
            else {
                VBOX_UTF8_TO_UTF16(displayutf8, &env);
                VIR_FREE(displayutf8);
            }
            VIR_FREE(guiDisplay);
        }

        VBOX_UTF8_TO_UTF16("gui", &sessionType);
    }

    if (sdlPresent) {
        if (sdlDisplay) {
            char *displayutf8;
            if (virAsprintf(&displayutf8, "DISPLAY=%s", sdlDisplay) < 0)
                virReportOOMError();
            else {
                VBOX_UTF8_TO_UTF16(displayutf8, &env);
                VIR_FREE(displayutf8);
            }
            VIR_FREE(sdlDisplay);
        }

        VBOX_UTF8_TO_UTF16("sdl", &sessionType);
    }

    if (vrdpPresent) {
        VBOX_UTF8_TO_UTF16("vrdp", &sessionType);
    }

#if VBOX_API_VERSION < 4000
    rc = data->vboxObj->vtbl->OpenRemoteSession(data->vboxObj,
                                                data->vboxSession,
                                                iid->value,
                                                sessionType,
                                                env,
                                                &progress );
#else /* VBOX_API_VERSION >= 4000 */
    rc = machine->vtbl->LaunchVMProcess(machine, data->vboxSession,
                                        sessionType, env, &progress);
#endif /* VBOX_API_VERSION >= 4000 */

    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_OPERATION_FAILED, "%s",
                  _("OpenRemoteSession/LaunchVMProcess failed, domain can't be started"));
        ret = -1;
    } else {
        PRBool completed = 0;
#if VBOX_API_VERSION == 2002
        nsresult resultCode;
#else
        PRInt32  resultCode;
#endif
        progress->vtbl->WaitForCompletion(progress, -1);
        rc = progress->vtbl->GetCompleted(progress, &completed);
        if (NS_FAILED(rc)) {
            /* error */
            ret = -1;
        }
        progress->vtbl->GetResultCode(progress, &resultCode);
        if (NS_FAILED(resultCode)) {
            /* error */
            ret = -1;
        } else {
            /* all ok set the domid */
            dom->id = i + 1;
            ret = 0;
        }
    }

    VBOX_RELEASE(progress);

    VBOX_SESSION_CLOSE();

    VBOX_UTF16_FREE(env);
    VBOX_UTF16_FREE(sessionType);

    return ret;
}

static int vboxDomainCreateWithFlags(virDomainPtr dom, unsigned int flags) {
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    vboxArray machines = VBOX_ARRAY_INITIALIZER;
    unsigned char uuid[VIR_UUID_BUFLEN] = {0};
    nsresult rc;
    int i = 0;

    virCheckFlags(0, -1);

    if (!dom->name) {
        vboxError(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("Error while reading the domain name"));
        goto cleanup;
    }

    rc = vboxArrayGet(&machines, data->vboxObj, data->vboxObj->vtbl->GetMachines);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("Could not get list of machines, rc=%08x"), (unsigned)rc);
        goto cleanup;
    }

    for (i = 0; i < machines.count; ++i) {
        IMachine *machine = machines.items[i];
        PRBool isAccessible = PR_FALSE;

        if (!machine)
            continue;

        machine->vtbl->GetAccessible(machine, &isAccessible);
        if (isAccessible) {
            vboxIID iid = VBOX_IID_INITIALIZER;

            rc = machine->vtbl->GetId(machine, &iid.value);
            if (NS_FAILED(rc))
                continue;
            vboxIIDToUUID(&iid, uuid);

            if (memcmp(dom->uuid, uuid, VIR_UUID_BUFLEN) == 0) {
                PRUint32 state = MachineState_Null;
                machine->vtbl->GetState(machine, &state);

                if ( (state == MachineState_PoweredOff) ||
                     (state == MachineState_Saved) ||
                     (state == MachineState_Aborted) ) {
                    ret = vboxStartMachine(dom, i, machine, &iid);
                } else {
                    vboxError(VIR_ERR_OPERATION_FAILED, "%s",
                              _("machine is not in poweroff|saved|"
                                "aborted state, so couldn't start it"));
                    ret = -1;
                }
            }
            vboxIIDUnalloc(&iid);
            if (ret != -1)
                break;
        }
    }

    /* Do the cleanup and take care you dont leak any memory */
    vboxArrayRelease(&machines);

cleanup:
    return ret;
}

static int vboxDomainCreate(virDomainPtr dom) {
    return vboxDomainCreateWithFlags(dom, 0);
}

static void
vboxSetBootDeviceOrder(virDomainDefPtr def, vboxGlobalData *data,
                       IMachine *machine)
{
    ISystemProperties *systemProperties = NULL;
    PRUint32 maxBootPosition            = 0;
    int i = 0;

    VIR_DEBUG("def->os.type             %s", def->os.type);
    VIR_DEBUG("def->os.arch             %s", def->os.arch);
    VIR_DEBUG("def->os.machine          %s", def->os.machine);
    VIR_DEBUG("def->os.nBootDevs        %d", def->os.nBootDevs);
    VIR_DEBUG("def->os.bootDevs[0]      %d", def->os.bootDevs[0]);
    VIR_DEBUG("def->os.bootDevs[1]      %d", def->os.bootDevs[1]);
    VIR_DEBUG("def->os.bootDevs[2]      %d", def->os.bootDevs[2]);
    VIR_DEBUG("def->os.bootDevs[3]      %d", def->os.bootDevs[3]);
    VIR_DEBUG("def->os.init             %s", def->os.init);
    VIR_DEBUG("def->os.kernel           %s", def->os.kernel);
    VIR_DEBUG("def->os.initrd           %s", def->os.initrd);
    VIR_DEBUG("def->os.cmdline          %s", def->os.cmdline);
    VIR_DEBUG("def->os.root             %s", def->os.root);
    VIR_DEBUG("def->os.loader           %s", def->os.loader);
    VIR_DEBUG("def->os.bootloader       %s", def->os.bootloader);
    VIR_DEBUG("def->os.bootloaderArgs   %s", def->os.bootloaderArgs);

    data->vboxObj->vtbl->GetSystemProperties(data->vboxObj, &systemProperties);
    if (systemProperties) {
        systemProperties->vtbl->GetMaxBootPosition(systemProperties,
                                                   &maxBootPosition);
        VBOX_RELEASE(systemProperties);
        systemProperties = NULL;
    }

    /* Clear the defaults first */
    for (i = 0; i < maxBootPosition; i++) {
        machine->vtbl->SetBootOrder(machine, i+1, DeviceType_Null);
    }

    for (i = 0; (i < def->os.nBootDevs) && (i < maxBootPosition); i++) {
        PRUint32 device = DeviceType_Null;

        if (def->os.bootDevs[i] == VIR_DOMAIN_BOOT_FLOPPY) {
            device = DeviceType_Floppy;
        } else if (def->os.bootDevs[i] == VIR_DOMAIN_BOOT_CDROM) {
            device = DeviceType_DVD;
        } else if (def->os.bootDevs[i] == VIR_DOMAIN_BOOT_DISK) {
            device = DeviceType_HardDisk;
        } else if (def->os.bootDevs[i] == VIR_DOMAIN_BOOT_NET) {
            device = DeviceType_Network;
        }
        machine->vtbl->SetBootOrder(machine, i+1, device);
    }
}

static void
vboxAttachDrives(virDomainDefPtr def, vboxGlobalData *data, IMachine *machine)
{
    int i;
    nsresult rc;

#if VBOX_API_VERSION < 3001
    if (def->ndisks == 0)
        return;

    for (i = 0; i < def->ndisks; i++) {
        VIR_DEBUG("disk(%d) type:       %d", i, def->disks[i]->type);
        VIR_DEBUG("disk(%d) device:     %d", i, def->disks[i]->device);
        VIR_DEBUG("disk(%d) bus:        %d", i, def->disks[i]->bus);
        VIR_DEBUG("disk(%d) src:        %s", i, def->disks[i]->src);
        VIR_DEBUG("disk(%d) dst:        %s", i, def->disks[i]->dst);
        VIR_DEBUG("disk(%d) driverName: %s", i, def->disks[i]->driverName);
        VIR_DEBUG("disk(%d) driverType: %s", i, def->disks[i]->driverType);
        VIR_DEBUG("disk(%d) cachemode:  %d", i, def->disks[i]->cachemode);
        VIR_DEBUG("disk(%d) readonly:   %s", i, (def->disks[i]->readonly
                                             ? "True" : "False"));
        VIR_DEBUG("disk(%d) shared:     %s", i, (def->disks[i]->shared
                                             ? "True" : "False"));

        if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
            if (def->disks[i]->type == VIR_DOMAIN_DISK_TYPE_FILE &&
                def->disks[i]->src != NULL) {
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

                    VBOX_UTF8_TO_UTF16(def->disks[i]->src, &dvdfileUtf16);

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
                            vboxError(VIR_ERR_INTERNAL_ERROR,
                                      _("can't get the uuid of the file to "
                                        "be attached to cdrom: %s, rc=%08x"),
                                      def->disks[i]->src, (unsigned)rc);
                        } else {
                            rc = dvdDrive->vtbl->MountImage(dvdDrive, dvduuid.value);
                            if (NS_FAILED(rc)) {
                                vboxError(VIR_ERR_INTERNAL_ERROR,
                                          _("could not attach the file to cdrom: %s, rc=%08x"),
                                          def->disks[i]->src, (unsigned)rc);
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
            } else if (def->disks[i]->type == VIR_DOMAIN_DISK_TYPE_BLOCK) {
            }
        } else if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
            if (def->disks[i]->type == VIR_DOMAIN_DISK_TYPE_FILE &&
                def->disks[i]->src != NULL) {
                IHardDisk *hardDisk     = NULL;
                PRUnichar *hddfileUtf16 = NULL;
                vboxIID hdduuid = VBOX_IID_INITIALIZER;
                PRUnichar *hddEmpty     = NULL;
                /* Current Limitation: Harddisk can't be connected to
                 * Secondary Master as Secondary Master is always used
                 * for CD/DVD Drive, so don't connect the harddisk if it
                 * is requested to be connected to Secondary master
                 */

                VBOX_UTF8_TO_UTF16(def->disks[i]->src, &hddfileUtf16);
                VBOX_UTF8_TO_UTF16("", &hddEmpty);

                data->vboxObj->vtbl->FindHardDisk(data->vboxObj, hddfileUtf16,
                                                  &hardDisk);

                if (!hardDisk) {
# if VBOX_API_VERSION == 2002
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
                        vboxError(VIR_ERR_INTERNAL_ERROR,
                                  _("can't get the uuid of the file to be "
                                    "attached as harddisk: %s, rc=%08x"),
                                  def->disks[i]->src, (unsigned)rc);
                    } else {
                        if (def->disks[i]->readonly) {
                            hardDisk->vtbl->SetType(hardDisk,
                                                    HardDiskType_Immutable);
                            VIR_DEBUG("setting harddisk to readonly");
                        } else if (!def->disks[i]->readonly) {
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

                                char *hddcname = strdup("IDE");
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
                                    vboxError(VIR_ERR_INTERNAL_ERROR,
                                              _("could not attach the file as "
                                                "harddisk: %s, rc=%08x"),
                                              def->disks[i]->src, (unsigned)rc);
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
            } else if (def->disks[i]->type == VIR_DOMAIN_DISK_TYPE_BLOCK) {
            }
        } else if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
            if (def->disks[i]->type == VIR_DOMAIN_DISK_TYPE_FILE &&
                def->disks[i]->src != NULL) {
                IFloppyDrive *floppyDrive;
                machine->vtbl->GetFloppyDrive(machine, &floppyDrive);
                if (floppyDrive) {
                    rc = floppyDrive->vtbl->SetEnabled(floppyDrive, 1);
                    if (NS_SUCCEEDED(rc)) {
                        IFloppyImage *floppyImage   = NULL;
                        PRUnichar *fdfileUtf16      = NULL;
                        vboxIID fduuid = VBOX_IID_INITIALIZER;
                        vboxIID fdemptyuuid = VBOX_IID_INITIALIZER;

                        VBOX_UTF8_TO_UTF16(def->disks[i]->src, &fdfileUtf16);
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
                                vboxError(VIR_ERR_INTERNAL_ERROR,
                                          _("can't get the uuid of the file to "
                                            "be attached to floppy drive: %s, rc=%08x"),
                                          def->disks[i]->src, (unsigned)rc);
                            } else {
                                rc = floppyDrive->vtbl->MountImage(floppyDrive,
                                                                   fduuid.value);
                                if (NS_FAILED(rc)) {
                                    vboxError(VIR_ERR_INTERNAL_ERROR,
                                              _("could not attach the file to "
                                                "floppy drive: %s, rc=%08x"),
                                              def->disks[i]->src, (unsigned)rc);
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
            } else if (def->disks[i]->type == VIR_DOMAIN_DISK_TYPE_BLOCK) {
            }
        }
    }
#else  /* VBOX_API_VERSION >= 3001 */
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
        VIR_DEBUG("disk(%d) type:       %d", i, def->disks[i]->type);
        VIR_DEBUG("disk(%d) device:     %d", i, def->disks[i]->device);
        VIR_DEBUG("disk(%d) bus:        %d", i, def->disks[i]->bus);
        VIR_DEBUG("disk(%d) src:        %s", i, def->disks[i]->src);
        VIR_DEBUG("disk(%d) dst:        %s", i, def->disks[i]->dst);
        VIR_DEBUG("disk(%d) driverName: %s", i, def->disks[i]->driverName);
        VIR_DEBUG("disk(%d) driverType: %s", i, def->disks[i]->driverType);
        VIR_DEBUG("disk(%d) cachemode:  %d", i, def->disks[i]->cachemode);
        VIR_DEBUG("disk(%d) readonly:   %s", i, (def->disks[i]->readonly
                                             ? "True" : "False"));
        VIR_DEBUG("disk(%d) shared:     %s", i, (def->disks[i]->shared
                                             ? "True" : "False"));

        if (def->disks[i]->type == VIR_DOMAIN_DISK_TYPE_FILE &&
            def->disks[i]->src != NULL) {
            IMedium   *medium          = NULL;
            PRUnichar *mediumUUID      = NULL;
            PRUnichar *mediumFileUtf16 = NULL;
            PRUint32   storageBus      = StorageBus_Null;
            PRUint32   deviceType      = DeviceType_Null;
# if VBOX_API_VERSION >= 4000
            PRUint32   accessMode      = AccessMode_ReadOnly;
# endif
            PRInt32    deviceInst      = 0;
            PRInt32    devicePort      = 0;
            PRInt32    deviceSlot      = 0;

            VBOX_UTF8_TO_UTF16(def->disks[i]->src, &mediumFileUtf16);

            if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
                deviceType = DeviceType_HardDisk;
# if VBOX_API_VERSION < 4000
                data->vboxObj->vtbl->FindHardDisk(data->vboxObj,
                                                  mediumFileUtf16, &medium);
# else
                accessMode = AccessMode_ReadWrite;
# endif
            } else if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
                deviceType = DeviceType_DVD;
# if VBOX_API_VERSION < 4000
                data->vboxObj->vtbl->FindDVDImage(data->vboxObj,
                                                  mediumFileUtf16, &medium);
# else
                accessMode = AccessMode_ReadOnly;
# endif
            } else if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
                deviceType = DeviceType_Floppy;
# if VBOX_API_VERSION < 4000
                data->vboxObj->vtbl->FindFloppyImage(data->vboxObj,
                                                     mediumFileUtf16, &medium);
# else
                accessMode = AccessMode_ReadWrite;
# endif
            } else {
                VBOX_UTF16_FREE(mediumFileUtf16);
                continue;
            }

# if VBOX_API_VERSION >= 4000
            data->vboxObj->vtbl->FindMedium(data->vboxObj, mediumFileUtf16,
                                            deviceType, &medium);
# endif

            if (!medium) {
                PRUnichar *mediumEmpty = NULL;

                VBOX_UTF8_TO_UTF16("", &mediumEmpty);

# if VBOX_API_VERSION < 4000
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
# elif VBOX_API_VERSION == 4000
                rc = data->vboxObj->vtbl->OpenMedium(data->vboxObj,
                                                     mediumFileUtf16,
                                                     deviceType, accessMode,
                                                     &medium);
# elif VBOX_API_VERSION >= 4001
                rc = data->vboxObj->vtbl->OpenMedium(data->vboxObj,
                                                     mediumFileUtf16,
                                                     deviceType, accessMode,
                                                     false,
                                                     &medium);
# endif /* VBOX_API_VERSION >= 4001 */

                VBOX_UTF16_FREE(mediumEmpty);
            }

            if (!medium) {
                vboxError(VIR_ERR_INTERNAL_ERROR,
                          _("Failed to attach the following disk/dvd/floppy "
                            "to the machine: %s, rc=%08x"),
                          def->disks[i]->src, (unsigned)rc);
                VBOX_UTF16_FREE(mediumFileUtf16);
                continue;
            }

            rc = medium->vtbl->GetId(medium, &mediumUUID);
            if (NS_FAILED(rc)) {
                vboxError(VIR_ERR_INTERNAL_ERROR,
                          _("can't get the uuid of the file to be attached "
                            "as harddisk/dvd/floppy: %s, rc=%08x"),
                          def->disks[i]->src, (unsigned)rc);
                VBOX_RELEASE(medium);
                VBOX_UTF16_FREE(mediumFileUtf16);
                continue;
            }

            if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
                if (def->disks[i]->readonly) {
                    medium->vtbl->SetType(medium, MediumType_Immutable);
                    VIR_DEBUG("setting harddisk to immutable");
                } else if (!def->disks[i]->readonly) {
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
                vboxError(VIR_ERR_INTERNAL_ERROR,
                          _("can't get the port/slot number of harddisk/"
                            "dvd/floppy to be attached: %s, rc=%08x"),
                          def->disks[i]->src, (unsigned)rc);
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
# if VBOX_API_VERSION < 4000
                                             mediumUUID);
# else /* VBOX_API_VERSION >= 4000 */
                                             medium);
# endif /* VBOX_API_VERSION >= 4000 */

            if (NS_FAILED(rc)) {
                vboxError(VIR_ERR_INTERNAL_ERROR,
                          _("could not attach the file as harddisk/"
                            "dvd/floppy: %s, rc=%08x"),
                          def->disks[i]->src, (unsigned)rc);
            } else {
                DEBUGIID("Attached HDD/DVD/Floppy with UUID", mediumUUID);
            }

            VBOX_RELEASE(medium);
            VBOX_UTF16_FREE(mediumUUID);
            VBOX_UTF16_FREE(mediumFileUtf16);
            VBOX_UTF16_FREE(storageCtlName);
        }
    }
#endif /* VBOX_API_VERSION >= 3001 */
}

static void
vboxAttachSound(virDomainDefPtr def, IMachine *machine)
{
    nsresult rc;

    /* Check if def->nsounds is one as VirtualBox currently supports
     * only one sound card
     */
    if (def->nsounds == 1) {
        IAudioAdapter *audioAdapter = NULL;

        machine->vtbl->GetAudioAdapter(machine, &audioAdapter);
        if (audioAdapter) {
            rc = audioAdapter->vtbl->SetEnabled(audioAdapter, 1);
            if (NS_SUCCEEDED(rc)) {
                if (def->sounds[0]->model == VIR_DOMAIN_SOUND_MODEL_SB16) {
                    audioAdapter->vtbl->SetAudioController(audioAdapter,
                                                           AudioControllerType_SB16);
                } else if (def->sounds[0]->model == VIR_DOMAIN_SOUND_MODEL_AC97) {
                    audioAdapter->vtbl->SetAudioController(audioAdapter,
                                                           AudioControllerType_AC97);
                }
            }
            VBOX_RELEASE(audioAdapter);
        }
    }
}

static void
vboxAttachNetwork(virDomainDefPtr def, vboxGlobalData *data, IMachine *machine)
{
    ISystemProperties *systemProperties = NULL;
#if VBOX_API_VERSION >= 4001
    PRUint32 chipsetType                = ChipsetType_Null;
#endif /* VBOX_API_VERSION >= 4001 */
    PRUint32 networkAdapterCount        = 0;
    int i = 0;

#if VBOX_API_VERSION >= 4001
    machine->vtbl->GetChipsetType(machine, &chipsetType);
#endif /* VBOX_API_VERSION >= 4001 */

    data->vboxObj->vtbl->GetSystemProperties(data->vboxObj, &systemProperties);
    if (systemProperties) {
#if VBOX_API_VERSION < 4001
        systemProperties->vtbl->GetNetworkAdapterCount(systemProperties,
                                                       &networkAdapterCount);
#else  /* VBOX_API_VERSION >= 4000 */
        systemProperties->vtbl->GetMaxNetworkAdapters(systemProperties, chipsetType,
                                                      &networkAdapterCount);
#endif /* VBOX_API_VERSION >= 4000 */
        VBOX_RELEASE(systemProperties);
        systemProperties = NULL;
    }

    VIR_DEBUG("Number of Network Cards to be connected: %d", def->nnets);
    VIR_DEBUG("Number of Network Cards available: %d", networkAdapterCount);

    for (i = 0; (i < def->nnets) && (i < networkAdapterCount); i++) {
        INetworkAdapter *adapter = NULL;
        PRUint32 adapterType     = NetworkAdapterType_Null;
        char macaddr[VIR_MAC_STRING_BUFLEN] = {0};
        char macaddrvbox[VIR_MAC_STRING_BUFLEN - 5] = {0};

        virMacAddrFormat(def->nets[i]->mac, macaddr);
        snprintf(macaddrvbox, VIR_MAC_STRING_BUFLEN - 5,
                 "%02X%02X%02X%02X%02X%02X",
                 def->nets[i]->mac[0],
                 def->nets[i]->mac[1],
                 def->nets[i]->mac[2],
                 def->nets[i]->mac[3],
                 def->nets[i]->mac[4],
                 def->nets[i]->mac[5]);
        macaddrvbox[VIR_MAC_STRING_BUFLEN - 6] = '\0';

        VIR_DEBUG("NIC(%d): Type:   %d", i, def->nets[i]->type);
        VIR_DEBUG("NIC(%d): Model:  %s", i, def->nets[i]->model);
        VIR_DEBUG("NIC(%d): Mac:    %s", i, macaddr);
        VIR_DEBUG("NIC(%d): ifname: %s", i, def->nets[i]->ifname);
        if (def->nets[i]->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
            VIR_DEBUG("NIC(%d): name:    %s", i, def->nets[i]->data.network.name);
        } else if (def->nets[i]->type == VIR_DOMAIN_NET_TYPE_INTERNAL) {
            VIR_DEBUG("NIC(%d): name:   %s", i, def->nets[i]->data.internal.name);
        } else if (def->nets[i]->type == VIR_DOMAIN_NET_TYPE_USER) {
            VIR_DEBUG("NIC(%d): NAT.", i);
        } else if (def->nets[i]->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {
            VIR_DEBUG("NIC(%d): brname: %s", i, def->nets[i]->data.bridge.brname);
            VIR_DEBUG("NIC(%d): script: %s", i, def->nets[i]->script);
            VIR_DEBUG("NIC(%d): ipaddr: %s", i, def->nets[i]->data.bridge.ipaddr);
        }

        machine->vtbl->GetNetworkAdapter(machine, i, &adapter);
        if (adapter) {
            PRUnichar *MACAddress = NULL;

            adapter->vtbl->SetEnabled(adapter, 1);

            if (def->nets[i]->model) {
                if (STRCASEEQ(def->nets[i]->model , "Am79C970A")) {
                    adapterType = NetworkAdapterType_Am79C970A;
                } else if (STRCASEEQ(def->nets[i]->model , "Am79C973")) {
                    adapterType = NetworkAdapterType_Am79C973;
                } else if (STRCASEEQ(def->nets[i]->model , "82540EM")) {
                    adapterType = NetworkAdapterType_I82540EM;
                } else if (STRCASEEQ(def->nets[i]->model , "82545EM")) {
                    adapterType = NetworkAdapterType_I82545EM;
                } else if (STRCASEEQ(def->nets[i]->model , "82543GC")) {
                    adapterType = NetworkAdapterType_I82543GC;
#if VBOX_API_VERSION >= 3001
                } else if (STRCASEEQ(def->nets[i]->model , "virtio")) {
                    adapterType = NetworkAdapterType_Virtio;
#endif /* VBOX_API_VERSION >= 3001 */
                }
            } else {
                adapterType = NetworkAdapterType_Am79C973;
            }

            adapter->vtbl->SetAdapterType(adapter, adapterType);

            if (def->nets[i]->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {
                PRUnichar *hostInterface = NULL;
                /* Bridged Network */

#if VBOX_API_VERSION < 4001
                adapter->vtbl->AttachToBridgedInterface(adapter);
#else /* VBOX_API_VERSION >= 4001 */
                adapter->vtbl->SetAttachmentType(adapter, NetworkAttachmentType_Bridged);
#endif /* VBOX_API_VERSION >= 4001 */

                if (def->nets[i]->data.bridge.brname) {
                    VBOX_UTF8_TO_UTF16(def->nets[i]->data.bridge.brname,
                                       &hostInterface);
#if VBOX_API_VERSION < 4001
                    adapter->vtbl->SetHostInterface(adapter, hostInterface);
#else /* VBOX_API_VERSION >= 4001 */
                    adapter->vtbl->SetBridgedInterface(adapter, hostInterface);
#endif /* VBOX_API_VERSION >= 4001 */
                    VBOX_UTF16_FREE(hostInterface);
                }
            } else if (def->nets[i]->type == VIR_DOMAIN_NET_TYPE_INTERNAL) {
                PRUnichar *internalNetwork = NULL;
                /* Internal Network */

#if VBOX_API_VERSION < 4001
                adapter->vtbl->AttachToInternalNetwork(adapter);
#else /* VBOX_API_VERSION >= 4001 */
                adapter->vtbl->SetAttachmentType(adapter, NetworkAttachmentType_Internal);
#endif /* VBOX_API_VERSION >= 4001 */

                if (def->nets[i]->data.internal.name) {
                    VBOX_UTF8_TO_UTF16(def->nets[i]->data.internal.name,
                                       &internalNetwork);
                    adapter->vtbl->SetInternalNetwork(adapter, internalNetwork);
                    VBOX_UTF16_FREE(internalNetwork);
                }
            } else if (def->nets[i]->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
                PRUnichar *hostInterface = NULL;
                /* Host Only Networking (currently only vboxnet0 available
                 * on *nix and mac, on windows you can create and configure
                 * as many as you want)
                 */
#if VBOX_API_VERSION < 4001
                adapter->vtbl->AttachToHostOnlyInterface(adapter);
#else /* VBOX_API_VERSION >= 4001 */
                adapter->vtbl->SetAttachmentType(adapter, NetworkAttachmentType_HostOnly);
#endif /* VBOX_API_VERSION >= 4001 */

                if (def->nets[i]->data.network.name) {
                    VBOX_UTF8_TO_UTF16(def->nets[i]->data.network.name,
                                       &hostInterface);
#if VBOX_API_VERSION < 4001
                    adapter->vtbl->SetHostInterface(adapter, hostInterface);
#else /* VBOX_API_VERSION >= 4001 */
                    adapter->vtbl->SetHostOnlyInterface(adapter, hostInterface);
#endif /* VBOX_API_VERSION >= 4001 */
                    VBOX_UTF16_FREE(hostInterface);
                }
            } else if (def->nets[i]->type == VIR_DOMAIN_NET_TYPE_USER) {
                /* NAT */
#if VBOX_API_VERSION < 4001
                adapter->vtbl->AttachToNAT(adapter);
#else /* VBOX_API_VERSION >= 4001 */
                adapter->vtbl->SetAttachmentType(adapter, NetworkAttachmentType_NAT);
#endif /* VBOX_API_VERSION >= 4001 */
            } else {
                /* else always default to NAT if we don't understand
                 * what option is been passed to us
                 */
#if VBOX_API_VERSION < 4001
                adapter->vtbl->AttachToNAT(adapter);
#else /* VBOX_API_VERSION >= 4001 */
                adapter->vtbl->SetAttachmentType(adapter, NetworkAttachmentType_NAT);
#endif /* VBOX_API_VERSION >= 4001 */
            }

            VBOX_UTF8_TO_UTF16(macaddrvbox, &MACAddress);
            adapter->vtbl->SetMACAddress(adapter, MACAddress);
            VBOX_UTF16_FREE(MACAddress);
        }
    }
}

static void
vboxAttachSerial(virDomainDefPtr def, vboxGlobalData *data, IMachine *machine)
{
    ISystemProperties *systemProperties = NULL;
    PRUint32 serialPortCount            = 0;
    int i = 0;

    data->vboxObj->vtbl->GetSystemProperties(data->vboxObj, &systemProperties);
    if (systemProperties) {
        systemProperties->vtbl->GetSerialPortCount(systemProperties,
                                                   &serialPortCount);
        VBOX_RELEASE(systemProperties);
        systemProperties = NULL;
    }

    VIR_DEBUG("Number of Serial Ports to be connected: %d", def->nserials);
    VIR_DEBUG("Number of Serial Ports available: %d", serialPortCount);
    for (i = 0; (i < def->nserials) && (i < serialPortCount); i++) {
        ISerialPort *serialPort = NULL;

        VIR_DEBUG("SerialPort(%d): Type: %d", i, def->serials[i]->source.type);
        VIR_DEBUG("SerialPort(%d): target.port: %d", i,
              def->serials[i]->target.port);

        machine->vtbl->GetSerialPort(machine, i, &serialPort);
        if (serialPort) {
            PRUnichar *pathUtf16 = NULL;

            serialPort->vtbl->SetEnabled(serialPort, 1);

            if (def->serials[i]->source.data.file.path) {
                VBOX_UTF8_TO_UTF16(def->serials[i]->source.data.file.path,
                                   &pathUtf16);
                serialPort->vtbl->SetPath(serialPort, pathUtf16);
            }

            /* For now hard code the serial ports to COM1 and COM2,
             * COM1 (Base Addr: 0x3F8 (decimal: 1016), IRQ: 4)
             * COM2 (Base Addr: 0x2F8 (decimal:  760), IRQ: 3)
             * TODO: make this more flexible
             */
            /* TODO: to improve the libvirt XMl handling so
             * that def->serials[i]->target.port shows real port
             * and not always start at 0
             */
            if (def->serials[i]->target.port == 0) {
                serialPort->vtbl->SetIRQ(serialPort, 4);
                serialPort->vtbl->SetIOBase(serialPort, 1016);
                VIR_DEBUG(" serialPort-%d irq: %d, iobase 0x%x, path: %s",
                      i, 4, 1016, def->serials[i]->source.data.file.path);
            } else if (def->serials[i]->target.port == 1) {
                serialPort->vtbl->SetIRQ(serialPort, 3);
                serialPort->vtbl->SetIOBase(serialPort, 760);
                VIR_DEBUG(" serialPort-%d irq: %d, iobase 0x%x, path: %s",
                      i, 3, 760, def->serials[i]->source.data.file.path);
            }

            if (def->serials[i]->source.type == VIR_DOMAIN_CHR_TYPE_DEV) {
                serialPort->vtbl->SetHostMode(serialPort, PortMode_HostDevice);
            } else if (def->serials[i]->source.type == VIR_DOMAIN_CHR_TYPE_PIPE) {
                serialPort->vtbl->SetHostMode(serialPort, PortMode_HostPipe);
#if VBOX_API_VERSION >= 3000
            } else if (def->serials[i]->source.type == VIR_DOMAIN_CHR_TYPE_FILE) {
                serialPort->vtbl->SetHostMode(serialPort, PortMode_RawFile);
#endif /* VBOX_API_VERSION >= 3000 */
            } else {
                serialPort->vtbl->SetHostMode(serialPort,
                                              PortMode_Disconnected);
            }

            VBOX_RELEASE(serialPort);
            if (pathUtf16) {
                VBOX_UTF16_FREE(pathUtf16);
                pathUtf16 = NULL;
            }
        }
    }
}

static void
vboxAttachParallel(virDomainDefPtr def, vboxGlobalData *data, IMachine *machine)
{
    ISystemProperties *systemProperties = NULL;
    PRUint32 parallelPortCount          = 0;
    int i = 0;

    data->vboxObj->vtbl->GetSystemProperties(data->vboxObj, &systemProperties);
    if (systemProperties) {
        systemProperties->vtbl->GetParallelPortCount(systemProperties,
                                                     &parallelPortCount);
        VBOX_RELEASE(systemProperties);
        systemProperties = NULL;
    }

    VIR_DEBUG("Number of Parallel Ports to be connected: %d", def->nparallels);
    VIR_DEBUG("Number of Parallel Ports available: %d", parallelPortCount);
    for (i = 0; (i < def->nparallels) && (i < parallelPortCount); i++) {
        IParallelPort *parallelPort = NULL;

        VIR_DEBUG("ParallelPort(%d): Type: %d", i, def->parallels[i]->source.type);
        VIR_DEBUG("ParallelPort(%d): target.port: %d", i,
              def->parallels[i]->target.port);

        machine->vtbl->GetParallelPort(machine, i, &parallelPort);
        if (parallelPort) {
            PRUnichar *pathUtf16 = NULL;

            VBOX_UTF8_TO_UTF16(def->parallels[i]->source.data.file.path, &pathUtf16);

            /* For now hard code the parallel ports to
             * LPT1 (Base Addr: 0x378 (decimal: 888), IRQ: 7)
             * LPT2 (Base Addr: 0x278 (decimal: 632), IRQ: 5)
             * TODO: make this more flexible
             */
            if ((def->parallels[i]->source.type == VIR_DOMAIN_CHR_TYPE_DEV)  ||
                (def->parallels[i]->source.type == VIR_DOMAIN_CHR_TYPE_PTY)  ||
                (def->parallels[i]->source.type == VIR_DOMAIN_CHR_TYPE_FILE) ||
                (def->parallels[i]->source.type == VIR_DOMAIN_CHR_TYPE_PIPE)) {
                parallelPort->vtbl->SetPath(parallelPort, pathUtf16);
                if (i == 0) {
                    parallelPort->vtbl->SetIRQ(parallelPort, 7);
                    parallelPort->vtbl->SetIOBase(parallelPort, 888);
                    VIR_DEBUG(" parallePort-%d irq: %d, iobase 0x%x, path: %s",
                          i, 7, 888, def->parallels[i]->source.data.file.path);
                } else if (i == 1) {
                    parallelPort->vtbl->SetIRQ(parallelPort, 5);
                    parallelPort->vtbl->SetIOBase(parallelPort, 632);
                    VIR_DEBUG(" parallePort-%d irq: %d, iobase 0x%x, path: %s",
                          i, 5, 632, def->parallels[i]->source.data.file.path);
                }
            }

            /* like serial port, parallel port can't be enabled unless
             * correct IRQ and IOBase values are specified.
             */
            parallelPort->vtbl->SetEnabled(parallelPort, 1);

            VBOX_RELEASE(parallelPort);
            if (pathUtf16) {
                VBOX_UTF16_FREE(pathUtf16);
                pathUtf16 = NULL;
            }
        }
    }
}

static void
vboxAttachVideo(virDomainDefPtr def, IMachine *machine)
{
    if ((def->nvideos == 1) &&
        (def->videos[0]->type == VIR_DOMAIN_VIDEO_TYPE_VBOX)) {
        machine->vtbl->SetVRAMSize(machine,
                                   VIR_DIV_UP(def->videos[0]->vram, 1024));
        machine->vtbl->SetMonitorCount(machine, def->videos[0]->heads);
        if (def->videos[0]->accel) {
            machine->vtbl->SetAccelerate3DEnabled(machine,
                                                  def->videos[0]->accel->support3d);
#if VBOX_API_VERSION >= 3001
            machine->vtbl->SetAccelerate2DVideoEnabled(machine,
                                                       def->videos[0]->accel->support2d);
#endif /* VBOX_API_VERSION >= 3001 */
        } else {
            machine->vtbl->SetAccelerate3DEnabled(machine, 0);
#if VBOX_API_VERSION >= 3001
            machine->vtbl->SetAccelerate2DVideoEnabled(machine, 0);
#endif /* VBOX_API_VERSION >= 3001 */
        }
    }
}

static void
vboxAttachDisplay(virDomainDefPtr def, vboxGlobalData *data, IMachine *machine)
{
    int vrdpPresent  = 0;
    int sdlPresent   = 0;
    int guiPresent   = 0;
    char *guiDisplay = NULL;
    char *sdlDisplay = NULL;
    int i = 0;

    for (i = 0; i < def->ngraphics; i++) {
#if VBOX_API_VERSION < 4000
        IVRDPServer *VRDxServer = NULL;
#else /* VBOX_API_VERSION >= 4000 */
        IVRDEServer *VRDxServer = NULL;
#endif /* VBOX_API_VERSION >= 4000 */

        if ((def->graphics[i]->type == VIR_DOMAIN_GRAPHICS_TYPE_RDP) &&
            (vrdpPresent == 0)) {

            vrdpPresent = 1;
#if VBOX_API_VERSION < 4000
            machine->vtbl->GetVRDPServer(machine, &VRDxServer);
#else /* VBOX_API_VERSION >= 4000 */
            machine->vtbl->GetVRDEServer(machine, &VRDxServer);
#endif /* VBOX_API_VERSION >= 4000 */
            if (VRDxServer) {
                const char *listenAddr
                    = virDomainGraphicsListenGetAddress(def->graphics[i], 0);

                VRDxServer->vtbl->SetEnabled(VRDxServer, PR_TRUE);
                VIR_DEBUG("VRDP Support turned ON.");

#if VBOX_API_VERSION < 3001
                if (def->graphics[i]->data.rdp.port) {
                    VRDxServer->vtbl->SetPort(VRDxServer,
                                              def->graphics[i]->data.rdp.port);
                    VIR_DEBUG("VRDP Port changed to: %d",
                          def->graphics[i]->data.rdp.port);
                } else if (def->graphics[i]->data.rdp.autoport) {
                    /* Setting the port to 0 will reset its value to
                     * the default one which is 3389 currently
                     */
                    VRDxServer->vtbl->SetPort(VRDxServer, 0);
                    VIR_DEBUG("VRDP Port changed to default, which is 3389 currently");
                }
#elif VBOX_API_VERSION < 4000 /* 3001 <= VBOX_API_VERSION < 4000 */
                PRUnichar *portUtf16 = NULL;
                portUtf16 = PRUnicharFromInt(def->graphics[i]->data.rdp.port);
                VRDxServer->vtbl->SetPorts(VRDxServer, portUtf16);
                VBOX_UTF16_FREE(portUtf16);
#else /* VBOX_API_VERSION >= 4000 */
                PRUnichar *VRDEPortsKey = NULL;
                PRUnichar *VRDEPortsValue = NULL;
                VBOX_UTF8_TO_UTF16("TCP/Ports", &VRDEPortsKey);
                VRDEPortsValue = PRUnicharFromInt(def->graphics[i]->data.rdp.port);
                VRDxServer->vtbl->SetVRDEProperty(VRDxServer, VRDEPortsKey,
                                                  VRDEPortsValue);
                VBOX_UTF16_FREE(VRDEPortsKey);
                VBOX_UTF16_FREE(VRDEPortsValue);
#endif /* VBOX_API_VERSION >= 4000 */

                if (def->graphics[i]->data.rdp.replaceUser) {
                    VRDxServer->vtbl->SetReuseSingleConnection(VRDxServer,
                                                               PR_TRUE);
                    VIR_DEBUG("VRDP set to reuse single connection");
                }

                if (def->graphics[i]->data.rdp.multiUser) {
                    VRDxServer->vtbl->SetAllowMultiConnection(VRDxServer,
                                                              PR_TRUE);
                    VIR_DEBUG("VRDP set to allow multiple connection");
                }

                if (listenAddr) {
#if VBOX_API_VERSION >= 4000
                    PRUnichar *netAddressKey = NULL;
#endif
                    PRUnichar *netAddressUtf16 = NULL;

                    VBOX_UTF8_TO_UTF16(listenAddr, &netAddressUtf16);
#if VBOX_API_VERSION < 4000
                    VRDxServer->vtbl->SetNetAddress(VRDxServer,
                                                    netAddressUtf16);
#else /* VBOX_API_VERSION >= 4000 */
                    VBOX_UTF8_TO_UTF16("TCP/Address", &netAddressKey);
                    VRDxServer->vtbl->SetVRDEProperty(VRDxServer, netAddressKey,
                                                      netAddressUtf16);
                    VBOX_UTF16_FREE(netAddressKey);
#endif /* VBOX_API_VERSION >= 4000 */
                    VIR_DEBUG("VRDP listen address is set to: %s",
                              listenAddr);

                    VBOX_UTF16_FREE(netAddressUtf16);
                }

                VBOX_RELEASE(VRDxServer);
            }
        }

        if ((def->graphics[i]->type == VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP) &&
            (guiPresent == 0)) {
            guiPresent = 1;
            if (def->graphics[i]->data.desktop.display) {
                guiDisplay = strdup(def->graphics[i]->data.desktop.display);
                if (guiDisplay == NULL) {
                    virReportOOMError();
                    /* just don't go to cleanup yet as it is ok to have
                     * guiDisplay as NULL and we check it below if it
                     * exist and then only use it there
                     */
                }
            }
        }

        if ((def->graphics[i]->type == VIR_DOMAIN_GRAPHICS_TYPE_SDL) &&
            (sdlPresent == 0)) {
            sdlPresent = 1;
            if (def->graphics[i]->data.sdl.display) {
                sdlDisplay = strdup(def->graphics[i]->data.sdl.display);
                if (sdlDisplay == NULL) {
                    virReportOOMError();
                    /* just don't go to cleanup yet as it is ok to have
                     * sdlDisplay as NULL and we check it below if it
                     * exist and then only use it there
                     */
                }
            }
        }
    }

    if ((vrdpPresent == 1) && (guiPresent == 0) && (sdlPresent == 0)) {
        /* store extradata key that frontend is set to vrdp */
        PRUnichar *keyTypeUtf16   = NULL;
        PRUnichar *valueTypeUtf16 = NULL;

        VBOX_UTF8_TO_UTF16("FRONTEND/Type", &keyTypeUtf16);
        VBOX_UTF8_TO_UTF16("vrdp", &valueTypeUtf16);

        machine->vtbl->SetExtraData(machine, keyTypeUtf16, valueTypeUtf16);

        VBOX_UTF16_FREE(keyTypeUtf16);
        VBOX_UTF16_FREE(valueTypeUtf16);

    } else if ((guiPresent == 0) && (sdlPresent == 1)) {
        /* store extradata key that frontend is set to sdl */
        PRUnichar *keyTypeUtf16      = NULL;
        PRUnichar *valueTypeUtf16    = NULL;
        PRUnichar *keyDislpayUtf16   = NULL;
        PRUnichar *valueDisplayUtf16 = NULL;

        VBOX_UTF8_TO_UTF16("FRONTEND/Type", &keyTypeUtf16);
        VBOX_UTF8_TO_UTF16("sdl", &valueTypeUtf16);

        machine->vtbl->SetExtraData(machine, keyTypeUtf16, valueTypeUtf16);

        VBOX_UTF16_FREE(keyTypeUtf16);
        VBOX_UTF16_FREE(valueTypeUtf16);

        if (sdlDisplay) {
            VBOX_UTF8_TO_UTF16("FRONTEND/Display", &keyDislpayUtf16);
            VBOX_UTF8_TO_UTF16(sdlDisplay, &valueDisplayUtf16);

            machine->vtbl->SetExtraData(machine, keyDislpayUtf16,
                                        valueDisplayUtf16);

            VBOX_UTF16_FREE(keyDislpayUtf16);
            VBOX_UTF16_FREE(valueDisplayUtf16);
        }

    } else {
        /* if all are set then default is gui, with vrdp turned on */
        PRUnichar *keyTypeUtf16      = NULL;
        PRUnichar *valueTypeUtf16    = NULL;
        PRUnichar *keyDislpayUtf16   = NULL;
        PRUnichar *valueDisplayUtf16 = NULL;

        VBOX_UTF8_TO_UTF16("FRONTEND/Type", &keyTypeUtf16);
        VBOX_UTF8_TO_UTF16("gui", &valueTypeUtf16);

        machine->vtbl->SetExtraData(machine, keyTypeUtf16, valueTypeUtf16);

        VBOX_UTF16_FREE(keyTypeUtf16);
        VBOX_UTF16_FREE(valueTypeUtf16);

        if (guiDisplay) {
            VBOX_UTF8_TO_UTF16("FRONTEND/Display", &keyDislpayUtf16);
            VBOX_UTF8_TO_UTF16(guiDisplay, &valueDisplayUtf16);

            machine->vtbl->SetExtraData(machine, keyDislpayUtf16,
                                        valueDisplayUtf16);

            VBOX_UTF16_FREE(keyDislpayUtf16);
            VBOX_UTF16_FREE(valueDisplayUtf16);
        }
    }

    VIR_FREE(guiDisplay);
    VIR_FREE(sdlDisplay);
}

static void
vboxAttachUSB(virDomainDefPtr def, vboxGlobalData *data, IMachine *machine)
{
    IUSBController *USBController = NULL;
    int i = 0;
    bool isUSB = false;

    if (def->nhostdevs == 0)
        return;

    /* Loop through the devices first and see if you
     * have a USB Device, only if you have one then
     * start the USB controller else just proceed as
     * usual
     */
    for (i = 0; i < def->nhostdevs; i++) {
        if (def->hostdevs[i]->mode ==
            VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {
            if (def->hostdevs[i]->source.subsys.type ==
                VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB) {
                if (def->hostdevs[i]->source.subsys.u.usb.vendor ||
                    def->hostdevs[i]->source.subsys.u.usb.product) {
                    VIR_DEBUG("USB Device detected, VendorId:0x%x, ProductId:0x%x",
                          def->hostdevs[i]->source.subsys.u.usb.vendor,
                          def->hostdevs[i]->source.subsys.u.usb.product);
                    isUSB = true;
                    break;
                }
            }
        }
    }

    if (isUSB) {
        /* First Start the USB Controller and then loop
         * to attach USB Devices to it
         */
        machine->vtbl->GetUSBController(machine, &USBController);
        if (USBController) {
            USBController->vtbl->SetEnabled(USBController, 1);
            USBController->vtbl->SetEnabledEhci(USBController, 1);

            for (i = 0; i < def->nhostdevs; i++) {
                if (def->hostdevs[i]->mode ==
                    VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {
                    if (def->hostdevs[i]->source.subsys.type ==
                        VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB) {

                        char *filtername           = NULL;
                        PRUnichar *filternameUtf16 = NULL;
                        IUSBDeviceFilter *filter   = NULL;

                        /* Zero pad for nice alignment when fewer than 9999
                         * devices.
                         */
                        if (virAsprintf(&filtername, "filter%04d", i) < 0) {
                            virReportOOMError();
                        } else {
                            VBOX_UTF8_TO_UTF16(filtername, &filternameUtf16);
                            VIR_FREE(filtername);
                            USBController->vtbl->CreateDeviceFilter(USBController,
                                                                    filternameUtf16,
                                                                    &filter);
                        }
                        VBOX_UTF16_FREE(filternameUtf16);

                        if (filter &&
                            (def->hostdevs[i]->source.subsys.u.usb.vendor ||
                             def->hostdevs[i]->source.subsys.u.usb.product)) {

                            PRUnichar *vendorIdUtf16  = NULL;
                            char vendorId[40]         = {0};
                            PRUnichar *productIdUtf16 = NULL;
                            char productId[40]        = {0};

                            if (def->hostdevs[i]->source.subsys.u.usb.vendor) {
                                snprintf(vendorId, sizeof(vendorId), "%x",
                                         def->hostdevs[i]->source.subsys.u.usb.vendor);
                                VBOX_UTF8_TO_UTF16(vendorId, &vendorIdUtf16);
                                filter->vtbl->SetVendorId(filter, vendorIdUtf16);
                                VBOX_UTF16_FREE(vendorIdUtf16);
                            }
                            if (def->hostdevs[i]->source.subsys.u.usb.product) {
                                snprintf(productId, sizeof(productId), "%x",
                                         def->hostdevs[i]->source.subsys.u.usb.product);
                                VBOX_UTF8_TO_UTF16(productId, &productIdUtf16);
                                filter->vtbl->SetProductId(filter,
                                                           productIdUtf16);
                                VBOX_UTF16_FREE(productIdUtf16);
                            }
                            filter->vtbl->SetActive(filter, 1);
                            USBController->vtbl->InsertDeviceFilter(USBController,
                                                                    i,
                                                                    filter);
                            VBOX_RELEASE(filter);
                        }

                    }
                }
            }
            VBOX_RELEASE(USBController);
        }
    }
}

static void
vboxAttachSharedFolder(virDomainDefPtr def, vboxGlobalData *data, IMachine *machine)
{
    int i;
    PRUnichar *nameUtf16;
    PRUnichar *hostPathUtf16;
    PRBool writable;

    if (def->nfss == 0)
        return;

    for (i = 0; i < def->nfss; i++) {
        if (def->fss[i]->type != VIR_DOMAIN_FS_TYPE_MOUNT)
            continue;

        VBOX_UTF8_TO_UTF16(def->fss[i]->dst, &nameUtf16);
        VBOX_UTF8_TO_UTF16(def->fss[i]->src, &hostPathUtf16);
        writable = !def->fss[i]->readonly;

#if VBOX_API_VERSION < 4000
        machine->vtbl->CreateSharedFolder(machine, nameUtf16, hostPathUtf16,
                                          writable);
#else /* VBOX_API_VERSION >= 4000 */
        machine->vtbl->CreateSharedFolder(machine, nameUtf16, hostPathUtf16,
                                          writable, PR_FALSE);
#endif /* VBOX_API_VERSION >= 4000 */

        VBOX_UTF16_FREE(nameUtf16);
        VBOX_UTF16_FREE(hostPathUtf16);
    }
}

static virDomainPtr vboxDomainDefineXML(virConnectPtr conn, const char *xml) {
    VBOX_OBJECT_CHECK(conn, virDomainPtr, NULL);
    IMachine       *machine     = NULL;
    IBIOSSettings  *bios        = NULL;
    vboxIID iid = VBOX_IID_INITIALIZER;
    vboxIID mchiid = VBOX_IID_INITIALIZER;
    virDomainDefPtr def         = NULL;
    PRUnichar *machineNameUtf16 = NULL;
#if VBOX_API_VERSION >= 3002
    PRBool override             = PR_FALSE;
#endif
    nsresult rc;

    if (!(def = virDomainDefParseString(data->caps, xml,
                                        1 << VIR_DOMAIN_VIRT_VBOX,
                                        VIR_DOMAIN_XML_INACTIVE))) {
        goto cleanup;
    }

    VBOX_UTF8_TO_UTF16(def->name, &machineNameUtf16);
    vboxIIDFromUUID(&iid, def->uuid);
#if VBOX_API_VERSION < 3002
    rc = data->vboxObj->vtbl->CreateMachine(data->vboxObj,
                                            machineNameUtf16,
                                            NULL,
                                            NULL,
                                            iid.value,
                                            &machine);
#elif VBOX_API_VERSION < 4000 /* 3002 <= VBOX_API_VERSION < 4000 */
    rc = data->vboxObj->vtbl->CreateMachine(data->vboxObj,
                                            machineNameUtf16,
                                            NULL,
                                            NULL,
                                            iid.value,
                                            override,
                                            &machine);
#else /* VBOX_API_VERSION >= 4000 */
    rc = data->vboxObj->vtbl->CreateMachine(data->vboxObj,
                                            NULL,
                                            machineNameUtf16,
                                            NULL,
                                            iid.value,
                                            override,
                                            &machine);
#endif /* VBOX_API_VERSION >= 4000 */
    VBOX_UTF16_FREE(machineNameUtf16);

    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("could not define a domain, rc=%08x"), (unsigned)rc);
        goto cleanup;
    }

    rc = machine->vtbl->SetMemorySize(machine,
                                      VIR_DIV_UP(def->mem.cur_balloon, 1024));
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("could not set the memory size of the domain to: %llu Kb, "
                    "rc=%08x"),
                  def->mem.cur_balloon, (unsigned)rc);
    }

    if (def->vcpus != def->maxvcpus) {
        vboxError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                    _("current vcpu count must equal maximum"));
    }
    rc = machine->vtbl->SetCPUCount(machine, def->maxvcpus);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("could not set the number of virtual CPUs to: %u, rc=%08x"),
                  def->maxvcpus, (unsigned)rc);
    }

#if VBOX_API_VERSION < 3001
    rc = machine->vtbl->SetPAEEnabled(machine, (def->features) &
                                      (1 << VIR_DOMAIN_FEATURE_PAE));
#elif VBOX_API_VERSION == 3001
    rc = machine->vtbl->SetCpuProperty(machine, CpuPropertyType_PAE,
                                       (def->features) &
                                       (1 << VIR_DOMAIN_FEATURE_PAE));
#elif VBOX_API_VERSION >= 3002
    rc = machine->vtbl->SetCPUProperty(machine, CPUPropertyType_PAE,
                                       (def->features) &
                                       (1 << VIR_DOMAIN_FEATURE_PAE));
#endif
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("could not change PAE status to: %s, rc=%08x"),
                  ((def->features) & (1 << VIR_DOMAIN_FEATURE_PAE))
                  ? _("Enabled") : _("Disabled"), (unsigned)rc);
    }

    machine->vtbl->GetBIOSSettings(machine, &bios);
    if (bios) {
        rc = bios->vtbl->SetACPIEnabled(bios, (def->features) &
                                        (1 << VIR_DOMAIN_FEATURE_ACPI));
        if (NS_FAILED(rc)) {
            vboxError(VIR_ERR_INTERNAL_ERROR,
                      _("could not change ACPI status to: %s, rc=%08x"),
                      ((def->features) & (1 << VIR_DOMAIN_FEATURE_ACPI))
                      ? _("Enabled") : _("Disabled"), (unsigned)rc);
        }
        rc = bios->vtbl->SetIOAPICEnabled(bios, (def->features) &
                                          (1 << VIR_DOMAIN_FEATURE_APIC));
        if (NS_FAILED(rc)) {
            vboxError(VIR_ERR_INTERNAL_ERROR,
                      _("could not change APIC status to: %s, rc=%08x"),
                      ((def->features) & (1 << VIR_DOMAIN_FEATURE_APIC))
                      ? _("Enabled") : _("Disabled"), (unsigned)rc);
        }
        VBOX_RELEASE(bios);
    }

    /* Register the machine before attaching other devices to it */
    rc = data->vboxObj->vtbl->RegisterMachine(data->vboxObj, machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("could not define a domain, rc=%08x"), (unsigned)rc);
        goto cleanup;
    }

    /* Get the uuid of the machine, currently it is immutable
     * object so open a session to it and get it back, so that
     * you can make changes to the machine setting
     */
    machine->vtbl->GetId(machine, &mchiid.value);
    VBOX_SESSION_OPEN(mchiid.value, machine);
    data->vboxSession->vtbl->GetMachine(data->vboxSession, &machine);

    vboxSetBootDeviceOrder(def, data, machine);
    vboxAttachDrives(def, data, machine);
    vboxAttachSound(def, machine);
    vboxAttachNetwork(def, data, machine);
    vboxAttachSerial(def, data, machine);
    vboxAttachParallel(def, data, machine);
    vboxAttachVideo(def, machine);
    vboxAttachDisplay(def, data, machine);
    vboxAttachUSB(def, data, machine);
    vboxAttachSharedFolder(def, data, machine);

    /* Save the machine settings made till now and close the
     * session. also free up the mchiid variable used.
     */
    rc = machine->vtbl->SaveSettings(machine);
    VBOX_SESSION_CLOSE();
    vboxIIDUnalloc(&mchiid);

    ret = virGetDomain(conn, def->name, def->uuid);
    VBOX_RELEASE(machine);

    vboxIIDUnalloc(&iid);
    virDomainDefFree(def);

    return ret;

cleanup:
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    virDomainDefFree(def);
    return NULL;
}

static int
vboxDomainUndefineFlags(virDomainPtr dom, unsigned int flags)
{
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    IMachine *machine    = NULL;
    vboxIID iid = VBOX_IID_INITIALIZER;
    nsresult rc;
#if VBOX_API_VERSION >= 4000
    vboxArray media = VBOX_ARRAY_INITIALIZER;
#endif
    /* No managed save, so we explicitly reject
     * VIR_DOMAIN_UNDEFINE_MANAGED_SAVE.  No snapshot metadata for
     * VBox, so we can trivially ignore that flag.  */
    virCheckFlags(VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA, -1);

    vboxIIDFromUUID(&iid, dom->uuid);

#if VBOX_API_VERSION < 4000
    /* Block for checking if HDD's are attched to VM.
     * considering just IDE bus for now. Also skipped
     * chanel=1 and device=0 (Secondary Master) as currenlty
     * it is allocated to CD/DVD Drive by default.
     *
     * Only do this for VirtualBox 3.x and before. Since
     * VirtualBox 4.0 the Unregister method can do this for use.
     */
    {
        PRUnichar *hddcnameUtf16 = NULL;

        char *hddcname = strdup("IDE");
        VBOX_UTF8_TO_UTF16(hddcname, &hddcnameUtf16);
        VIR_FREE(hddcname);

        /* Open a Session for the machine */
        rc = VBOX_SESSION_OPEN(iid.value, machine);
        if (NS_SUCCEEDED(rc)) {
            rc = data->vboxSession->vtbl->GetMachine(data->vboxSession, &machine);
            if (NS_SUCCEEDED(rc) && machine) {

# if VBOX_API_VERSION < 3001
                /* Disconnect all the drives if present */
                machine->vtbl->DetachHardDisk(machine, hddcnameUtf16, 0, 0);
                machine->vtbl->DetachHardDisk(machine, hddcnameUtf16, 0, 1);
                machine->vtbl->DetachHardDisk(machine, hddcnameUtf16, 1, 1);
# else  /* VBOX_API_VERSION >= 3001 */
                /* get all the controller first, then the attachments and
                 * remove them all so that the machine can be undefined
                 */
                vboxArray storageControllers = VBOX_ARRAY_INITIALIZER;
                int i = 0, j = 0;

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
# endif /* VBOX_API_VERSION >= 3001 */

                machine->vtbl->SaveSettings(machine);
            }
            VBOX_SESSION_CLOSE();
        }
        VBOX_UTF16_FREE(hddcnameUtf16);
    }
#endif

#if VBOX_API_VERSION < 4000
    rc = data->vboxObj->vtbl->UnregisterMachine(data->vboxObj, iid.value, &machine);
#else /* VBOX_API_VERSION >= 4000 */
    rc = VBOX_OBJECT_GET_MACHINE(iid.value, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_NO_DOMAIN, "%s",
                  _("no domain with matching uuid"));
        return -1;
    }

    /* We're not interested in the array returned by the Unregister method,
     * but in the side effect of unregistering the virtual machine. In order
     * to call the Unregister method correctly we need to use the vboxArray
     * wrapper here. */
    rc = vboxArrayGetWithUintArg(&media, machine, machine->vtbl->Unregister,
                                 CleanupMode_DetachAllReturnNone);
#endif /* VBOX_API_VERSION >= 4000 */
    DEBUGIID("UUID of machine being undefined", iid.value);

    if (NS_SUCCEEDED(rc)) {
#if VBOX_API_VERSION < 4000
        machine->vtbl->DeleteSettings(machine);
#else /* VBOX_API_VERSION >= 4000 */
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

        ((IMachine_Delete)machine->vtbl->Delete)(machine, &safeArray, &progress);
# else
        machine->vtbl->Delete(machine, 0, NULL, &progress);
# endif
        if (progress != NULL) {
            progress->vtbl->WaitForCompletion(progress, -1);
            VBOX_RELEASE(progress);
        }
#endif /* VBOX_API_VERSION >= 4000 */
        ret = 0;
    } else {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("could not delete the domain, rc=%08x"), (unsigned)rc);
    }

#if VBOX_API_VERSION >= 4000
    vboxArrayUnalloc(&media);
#endif
    vboxIIDUnalloc(&iid);
    VBOX_RELEASE(machine);

    return ret;
}

static int
vboxDomainUndefine(virDomainPtr dom)
{
    return vboxDomainUndefineFlags(dom, 0);
}

static int vboxDomainAttachDeviceImpl(virDomainPtr dom,
                                      const char *xml,
                                      int mediaChangeOnly ATTRIBUTE_UNUSED) {
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    IMachine *machine    = NULL;
    vboxIID iid = VBOX_IID_INITIALIZER;
    PRUint32 state       = MachineState_Null;
    virDomainDefPtr def  = NULL;
    virDomainDeviceDefPtr dev  = NULL;
    nsresult rc;

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError();
        return ret;
    }

    def->os.type = strdup("hvm");

    if (def->os.type == NULL) {
        virReportOOMError();
        goto cleanup;
    }

    dev = virDomainDeviceDefParse(data->caps, def, xml,
                                  VIR_DOMAIN_XML_INACTIVE);
    if (dev == NULL) {
        virReportOOMError();
        goto cleanup;
    }

    vboxIIDFromUUID(&iid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(iid.value, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_NO_DOMAIN, "%s",
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
#if VBOX_API_VERSION < 3001
                    if (dev->data.disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
                        if (dev->data.disk->type == VIR_DOMAIN_DISK_TYPE_FILE &&
                            dev->data.disk->src != NULL) {
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

                                VBOX_UTF8_TO_UTF16(dev->data.disk->src, &dvdfileUtf16);

                                data->vboxObj->vtbl->FindDVDImage(data->vboxObj, dvdfileUtf16, &dvdImage);
                                if (!dvdImage) {
                                    data->vboxObj->vtbl->OpenDVDImage(data->vboxObj, dvdfileUtf16, dvdemptyuuid.value, &dvdImage);
                                }
                                if (dvdImage) {
                                    rc = dvdImage->vtbl->imedium.GetId((IMedium *)dvdImage, &dvduuid.value);
                                    if (NS_FAILED(rc)) {
                                        vboxError(VIR_ERR_INTERNAL_ERROR,
                                                  _("can't get the uuid of the file to "
                                                    "be attached to cdrom: %s, rc=%08x"),
                                                  dev->data.disk->src, (unsigned)rc);
                                    } else {
                                        /* unmount the previous mounted image */
                                        dvdDrive->vtbl->Unmount(dvdDrive);
                                        rc = dvdDrive->vtbl->MountImage(dvdDrive, dvduuid.value);
                                        if (NS_FAILED(rc)) {
                                            vboxError(VIR_ERR_INTERNAL_ERROR,
                                                      _("could not attach the file to cdrom: %s, rc=%08x"),
                                                      dev->data.disk->src, (unsigned)rc);
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
                        } else if (dev->data.disk->type == VIR_DOMAIN_DISK_TYPE_BLOCK) {
                        }
                    } else if (dev->data.disk->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
                        if (dev->data.disk->type == VIR_DOMAIN_DISK_TYPE_FILE &&
                            dev->data.disk->src != NULL) {
                            IFloppyDrive *floppyDrive;
                            machine->vtbl->GetFloppyDrive(machine, &floppyDrive);
                            if (floppyDrive) {
                                rc = floppyDrive->vtbl->SetEnabled(floppyDrive, 1);
                                if (NS_SUCCEEDED(rc)) {
                                    IFloppyImage *floppyImage   = NULL;
                                    PRUnichar *fdfileUtf16      = NULL;
                                    vboxIID fduuid = VBOX_IID_INITIALIZER;
                                    vboxIID fdemptyuuid = VBOX_IID_INITIALIZER;
                                    VBOX_UTF8_TO_UTF16(dev->data.disk->src, &fdfileUtf16);
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
                                            vboxError(VIR_ERR_INTERNAL_ERROR,
                                                      _("can't get the uuid of the file to be "
                                                        "attached to floppy drive: %s, rc=%08x"),
                                                      dev->data.disk->src, (unsigned)rc);
                                        } else {
                                            rc = floppyDrive->vtbl->MountImage(floppyDrive, fduuid.value);
                                            if (NS_FAILED(rc)) {
                                                vboxError(VIR_ERR_INTERNAL_ERROR,
                                                          _("could not attach the file to floppy drive: %s, rc=%08x"),
                                                          dev->data.disk->src, (unsigned)rc);
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
                        } else if (dev->data.disk->type == VIR_DOMAIN_DISK_TYPE_BLOCK) {
                        }
                    }
#else  /* VBOX_API_VERSION >= 3001 */
#endif /* VBOX_API_VERSION >= 3001 */
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

#if VBOX_API_VERSION < 4000
                    rc = machine->vtbl->CreateSharedFolder(machine, nameUtf16, hostPathUtf16,
                                                           writable);
#else /* VBOX_API_VERSION >= 4000 */
                    rc = machine->vtbl->CreateSharedFolder(machine, nameUtf16, hostPathUtf16,
                                                           writable, PR_FALSE);
#endif /* VBOX_API_VERSION >= 4000 */

                    if (NS_FAILED(rc)) {
                        vboxError(VIR_ERR_INTERNAL_ERROR,
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

static int vboxDomainAttachDevice(virDomainPtr dom, const char *xml) {
    return vboxDomainAttachDeviceImpl(dom, xml, 0);
}

static int
vboxDomainAttachDeviceFlags(virDomainPtr dom, const char *xml,
                            unsigned int flags)
{
    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        vboxError(VIR_ERR_OPERATION_INVALID, "%s",
                  _("cannot modify the persistent configuration of a domain"));
        return -1;
    }

    return vboxDomainAttachDeviceImpl(dom, xml, 0);
}

static int vboxDomainUpdateDeviceFlags(virDomainPtr dom, const char *xml,
                                       unsigned int flags) {
    virCheckFlags(VIR_DOMAIN_AFFECT_CURRENT |
                  VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        vboxError(VIR_ERR_OPERATION_INVALID, "%s",
                  _("cannot modify the persistent configuration of a domain"));
        return -1;
    }

    return vboxDomainAttachDeviceImpl(dom, xml, 1);
}

static int vboxDomainDetachDevice(virDomainPtr dom, const char *xml) {
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    IMachine *machine    = NULL;
    vboxIID iid = VBOX_IID_INITIALIZER;
    PRUint32 state       = MachineState_Null;
    virDomainDefPtr def  = NULL;
    virDomainDeviceDefPtr dev  = NULL;
    nsresult rc;

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError();
        return ret;
    }

    def->os.type = strdup("hvm");

    if (def->os.type == NULL) {
        virReportOOMError();
        goto cleanup;
    }

    dev = virDomainDeviceDefParse(data->caps, def, xml,
                                  VIR_DOMAIN_XML_INACTIVE);
    if (dev == NULL) {
        virReportOOMError();
        goto cleanup;
    }

    vboxIIDFromUUID(&iid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(iid.value, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_NO_DOMAIN, "%s",
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
#if VBOX_API_VERSION < 3001
                    if (dev->data.disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
                        if (dev->data.disk->type == VIR_DOMAIN_DISK_TYPE_FILE) {
                            IDVDDrive *dvdDrive = NULL;
                            /* Currently CDROM/DVD Drive is always IDE
                             * Secondary Master so neglecting the following
                             * parameter dev->data.disk->bus
                             */
                            machine->vtbl->GetDVDDrive(machine, &dvdDrive);
                            if (dvdDrive) {
                                rc = dvdDrive->vtbl->Unmount(dvdDrive);
                                if (NS_FAILED(rc)) {
                                    vboxError(VIR_ERR_INTERNAL_ERROR,
                                              _("could not de-attach the mounted ISO, rc=%08x"),
                                              (unsigned)rc);
                                } else {
                                    ret = 0;
                                }
                                VBOX_RELEASE(dvdDrive);
                            }
                        } else if (dev->data.disk->type == VIR_DOMAIN_DISK_TYPE_BLOCK) {
                        }
                    } else if (dev->data.disk->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
                        if (dev->data.disk->type == VIR_DOMAIN_DISK_TYPE_FILE) {
                            IFloppyDrive *floppyDrive;
                            machine->vtbl->GetFloppyDrive(machine, &floppyDrive);
                            if (floppyDrive) {
                                PRBool enabled = PR_FALSE;

                                floppyDrive->vtbl->GetEnabled(floppyDrive, &enabled);
                                if (enabled) {
                                    rc = floppyDrive->vtbl->Unmount(floppyDrive);
                                    if (NS_FAILED(rc)) {
                                        vboxError(VIR_ERR_INTERNAL_ERROR,
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
                        } else if (dev->data.disk->type == VIR_DOMAIN_DISK_TYPE_BLOCK) {
                        }
                    }
#else  /* VBOX_API_VERSION >= 3001 */
#endif /* VBOX_API_VERSION >= 3001 */
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
                        vboxError(VIR_ERR_INTERNAL_ERROR,
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
        vboxError(VIR_ERR_OPERATION_INVALID, "%s",
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
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("could not get snapshot count for domain %s"),
                  dom->name);
        goto error;
    }

    if (count == 0)
        goto out;

    if (VIR_ALLOC_N(list, count) < 0) {
        virReportOOMError();
        goto error;
    }

#if VBOX_API_VERSION < 4000
    rc = machine->vtbl->GetSnapshot(machine, empty.value, list);
#else /* VBOX_API_VERSION >= 4000 */
    rc = machine->vtbl->FindSnapshot(machine, empty.value, list);
#endif /* VBOX_API_VERSION >= 4000 */
    if (NS_FAILED(rc) || !list[0]) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("could not get root snapshot for domain %s"),
                  dom->name);
        goto error;
    }

    /* BFS walk through snapshot tree */
    top = 1;
    for (next = 0; next < count; next++) {
        vboxArray children = VBOX_ARRAY_INITIALIZER;
        unsigned int i;

        if (!list[next]) {
            vboxError(VIR_ERR_INTERNAL_ERROR,
                      _("unexpected number of snapshots < %u"), count);
            goto error;
        }

        rc = vboxArrayGet(&children, list[next],
                               list[next]->vtbl->GetChildren);
        if (NS_FAILED(rc)) {
            vboxError(VIR_ERR_INTERNAL_ERROR,
                      "%s", _("could not get children snapshots"));
            goto error;
        }
        for (i = 0; i < children.count; i++) {
            ISnapshot *child = children.items[i];
            if (!child)
                continue;
            if (top == count) {
                vboxError(VIR_ERR_INTERNAL_ERROR,
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
    int i;

    if ((count = vboxDomainSnapshotGetAll(dom, machine, &snapshots)) < 0)
        goto cleanup;

    for (i = 0; i < count; i++) {
        PRUnichar *nameUtf16;
        char *nameUtf8;

        rc = snapshots[i]->vtbl->GetName(snapshots[i], &nameUtf16);
        if (NS_FAILED(rc) || !nameUtf16) {
            vboxError(VIR_ERR_INTERNAL_ERROR,
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
        vboxError(VIR_ERR_OPERATION_INVALID,
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
#if VBOX_API_VERSION == 2002
    nsresult result;
#else
    PRInt32 result;
#endif

    /* VBox has no snapshot metadata, so this flag is trivial.  */
    virCheckFlags(VIR_DOMAIN_SNAPSHOT_CREATE_NO_METADATA, NULL);

    if (!(def = virDomainSnapshotDefParseString(xmlDesc, NULL, 0, 0)))
        goto cleanup;

    if (def->ndisks) {
        vboxError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                  _("disk snapshots not supported yet"));
        goto cleanup;
    }

    vboxIIDFromUUID(&domiid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(domiid.value, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_NO_DOMAIN, "%s",
                  _("no domain with matching UUID"));
        goto cleanup;
    }

    rc = machine->vtbl->GetState(machine, &state);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR, "%s",
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
        vboxError(VIR_ERR_INTERNAL_ERROR,
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
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("could not take snapshot of domain %s"), dom->name);
        goto cleanup;
    }

    progress->vtbl->WaitForCompletion(progress, -1);
    progress->vtbl->GetResultCode(progress, &result);
    if (NS_FAILED(result)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("could not take snapshot of domain %s"), dom->name);
        goto cleanup;
    }

    rc = machine->vtbl->GetCurrentSnapshot(machine, &snapshot);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
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

    virCheckFlags(0, NULL);

    vboxIIDFromUUID(&domiid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(domiid.value, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_NO_DOMAIN, "%s",
                  _("no domain with matching UUID"));
        goto cleanup;
    }

    if (!(snap = vboxDomainSnapshotGet(data, dom, machine, snapshot->name)))
        goto cleanup;

    if (VIR_ALLOC(def) < 0
        || !(def->name = strdup(snapshot->name)))
        goto no_memory;

    rc = snap->vtbl->GetDescription(snap, &str16);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("could not get description of snapshot %s"),
                  snapshot->name);
        goto cleanup;
    }
    if (str16) {
        VBOX_UTF16_TO_UTF8(str16, &str8);
        VBOX_UTF16_FREE(str16);
        def->description = strdup(str8);
        VBOX_UTF8_FREE(str8);
        if (!def->description)
            goto no_memory;
    }

    rc = snap->vtbl->GetTimeStamp(snap, &timestamp);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("could not get creation time of snapshot %s"),
                  snapshot->name);
        goto cleanup;
    }
    /* timestamp is in milliseconds while creationTime in seconds */
    def->creationTime = timestamp / 1000;

    rc = snap->vtbl->GetParent(snap, &parent);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("could not get parent of snapshot %s"),
                  snapshot->name);
        goto cleanup;
    }
    if (parent) {
        rc = parent->vtbl->GetName(parent, &str16);
        if (NS_FAILED(rc) || !str16) {
            vboxError(VIR_ERR_INTERNAL_ERROR,
                      _("could not get name of parent of snapshot %s"),
                      snapshot->name);
            goto cleanup;
        }
        VBOX_UTF16_TO_UTF8(str16, &str8);
        VBOX_UTF16_FREE(str16);
        def->parent = strdup(str8);
        VBOX_UTF8_FREE(str8);
        if (!def->parent)
            goto no_memory;
    }

    rc = snap->vtbl->GetOnline(snap, &online);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("could not get online state of snapshot %s"),
                  snapshot->name);
        goto cleanup;
    }
    if (online)
        def->state = VIR_DOMAIN_RUNNING;
    else
        def->state = VIR_DOMAIN_SHUTOFF;

    virUUIDFormat(dom->uuid, uuidstr);
    ret = virDomainSnapshotDefFormat(uuidstr, def, flags, 0);

cleanup:
    virDomainSnapshotDefFree(def);
    VBOX_RELEASE(parent);
    VBOX_RELEASE(snap);
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&domiid);
    return ret;

no_memory:
    virReportOOMError();
    goto cleanup;
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
        vboxError(VIR_ERR_NO_DOMAIN, "%s",
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
        vboxError(VIR_ERR_INTERNAL_ERROR,
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
    int i;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_LIST_ROOTS |
                  VIR_DOMAIN_SNAPSHOT_LIST_METADATA, -1);

    vboxIIDFromUUID(&iid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(iid.value, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_NO_DOMAIN, "%s",
                  _("no domain with matching UUID"));
        goto cleanup;
    }

    if (flags & VIR_DOMAIN_SNAPSHOT_LIST_METADATA) {
        ret = 0;
        goto cleanup;
    }

    if (flags & VIR_DOMAIN_SNAPSHOT_LIST_ROOTS) {
        vboxIID empty = VBOX_IID_INITIALIZER;

        if (VIR_ALLOC_N(snapshots, 1) < 0) {
            virReportOOMError();
            goto cleanup;
        }
#if VBOX_API_VERSION < 4000
        rc = machine->vtbl->GetSnapshot(machine, empty.value, snapshots);
#else /* VBOX_API_VERSION >= 4000 */
        rc = machine->vtbl->FindSnapshot(machine, empty.value, snapshots);
#endif /* VBOX_API_VERSION >= 4000 */
        if (NS_FAILED(rc) || !snapshots[0]) {
            vboxError(VIR_ERR_INTERNAL_ERROR,
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
            vboxError(VIR_ERR_INTERNAL_ERROR,
                      "%s", _("could not get snapshot name"));
            goto cleanup;
        }
        VBOX_UTF16_TO_UTF8(nameUtf16, &name);
        VBOX_UTF16_FREE(nameUtf16);
        names[i] = strdup(name);
        VBOX_UTF8_FREE(name);
        if (!names[i]) {
            virReportOOMError();
            goto cleanup;
        }
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
        vboxError(VIR_ERR_NO_DOMAIN, "%s",
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
        vboxError(VIR_ERR_NO_DOMAIN, "%s",
                  _("no domain with matching UUID"));
        goto cleanup;
    }

    rc = machine->vtbl->GetCurrentSnapshot(machine, &snapshot);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR, "%s",
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
        vboxError(VIR_ERR_NO_DOMAIN, "%s",
                  _("no domain with matching UUID"));
        goto cleanup;
    }

    if (!(snap = vboxDomainSnapshotGet(data, dom, machine, snapshot->name)))
        goto cleanup;

    rc = snap->vtbl->GetParent(snap, &parent);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("could not get parent of snapshot %s"),
                  snapshot->name);
        goto cleanup;
    }
    if (!parent) {
        vboxError(VIR_ERR_NO_DOMAIN_SNAPSHOT,
                  _("snapshot '%s' does not have a parent"),
                  snapshot->name);
        goto cleanup;
    }

    rc = parent->vtbl->GetName(parent, &nameUtf16);
    if (NS_FAILED(rc) || !nameUtf16) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
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
        vboxError(VIR_ERR_NO_DOMAIN, "%s",
                  _("no domain with matching UUID"));
        goto cleanup;
    }

    rc = machine->vtbl->GetCurrentSnapshot(machine, &snapshot);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("could not get current snapshot"));
        goto cleanup;
    }

    if (!snapshot) {
        vboxError(VIR_ERR_OPERATION_INVALID, "%s",
                  _("domain has no snapshots"));
        goto cleanup;
    }

    rc = snapshot->vtbl->GetName(snapshot, &nameUtf16);
    if (NS_FAILED(rc) || !nameUtf16) {
        vboxError(VIR_ERR_INTERNAL_ERROR, "%s",
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

#if VBOX_API_VERSION < 3001
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
        vboxError(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("could not get snapshot UUID"));
        goto cleanup;
    }

    rc = machine->vtbl->SetCurrentSnapshot(machine, iid.value);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
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
        vboxError(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("could not get domain UUID"));
        goto cleanup;
    }

    rc = machine->vtbl->GetState(machine, &state);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("could not get domain state"));
        goto cleanup;
    }

    if (state >= MachineState_FirstOnline
        && state <= MachineState_LastOnline) {
        vboxError(VIR_ERR_OPERATION_INVALID,
                  _("domain %s is already running"), dom->name);
        goto cleanup;
    }

    rc = VBOX_SESSION_OPEN(domiid.value, machine);
    if (NS_SUCCEEDED(rc))
        rc = data->vboxSession->vtbl->GetConsole(data->vboxSession, &console);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("could not open VirtualBox session with domain %s"),
                  dom->name);
        goto cleanup;
    }

    rc = console->vtbl->RestoreSnapshot(console, snapshot, &progress);
    if (NS_FAILED(rc) || !progress) {
        if (rc == VBOX_E_INVALID_VM_STATE) {
            vboxError(VIR_ERR_OPERATION_INVALID, "%s",
                      _("cannot restore domain snapshot for running domain"));
        } else {
            vboxError(VIR_ERR_INTERNAL_ERROR,
                      _("could not restore snapshot for domain %s"),
                      dom->name);
        }
        goto cleanup;
    }

    progress->vtbl->WaitForCompletion(progress, -1);
    progress->vtbl->GetResultCode(progress, &result);
    if (NS_FAILED(result)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
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
        vboxError(VIR_ERR_NO_DOMAIN, "%s",
                  _("no domain with matching UUID"));
        goto cleanup;
    }

    newSnapshot = vboxDomainSnapshotGet(data, dom, machine, snapshot->name);
    if (!newSnapshot)
        goto cleanup;

    rc = newSnapshot->vtbl->GetOnline(newSnapshot, &online);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("could not get online state of snapshot %s"),
                  snapshot->name);
        goto cleanup;
    }

    rc = machine->vtbl->GetCurrentSnapshot(machine, &prevSnapshot);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("could not get current snapshot of domain %s"),
                  dom->name);
        goto cleanup;
    }

    rc = machine->vtbl->GetState(machine, &state);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("could not get domain state"));
        goto cleanup;
    }

    if (state >= MachineState_FirstOnline
        && state <= MachineState_LastOnline) {
        vboxError(VIR_ERR_OPERATION_INVALID, "%s",
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
#if VBOX_API_VERSION == 2002
    nsresult result;
#else
    PRInt32 result;
#endif

    rc = snapshot->vtbl->GetId(snapshot, &iid.value);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("could not get snapshot UUID"));
        goto cleanup;
    }

#if VBOX_API_VERSION < 3001
    rc = console->vtbl->DiscardSnapshot(console, iid.value, &progress);
#else
    rc = console->vtbl->DeleteSnapshot(console, iid.value, &progress);
#endif
    if (NS_FAILED(rc) || !progress) {
        if (rc == VBOX_E_INVALID_VM_STATE) {
            vboxError(VIR_ERR_OPERATION_INVALID, "%s",
                      _("cannot delete domain snapshot for running domain"));
        } else {
            vboxError(VIR_ERR_INTERNAL_ERROR, "%s",
                      _("could not delete snapshot"));
        }
        goto cleanup;
    }

    progress->vtbl->WaitForCompletion(progress, -1);
    progress->vtbl->GetResultCode(progress, &result);
    if (NS_FAILED(result)) {
        vboxError(VIR_ERR_INTERNAL_ERROR, "%s",
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
    unsigned int i;

    rc = vboxArrayGet(&children, snapshot, snapshot->vtbl->GetChildren);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR, "%s",
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

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN |
                  VIR_DOMAIN_SNAPSHOT_DELETE_METADATA_ONLY, -1);

    vboxIIDFromUUID(&domiid, dom->uuid);
    rc = VBOX_OBJECT_GET_MACHINE(domiid.value, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_NO_DOMAIN, "%s",
                  _("no domain with matching UUID"));
        goto cleanup;
    }

    snap = vboxDomainSnapshotGet(data, dom, machine, snapshot->name);
    if (!snap)
        goto cleanup;

    rc = machine->vtbl->GetState(machine, &state);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("could not get domain state"));
        goto cleanup;
    }

    /* VBOX snapshots do not require any libvirt metadata, making this
     * flag trivial once we know we have a valid snapshot.  */
    if (flags & VIR_DOMAIN_SNAPSHOT_DELETE_METADATA_ONLY) {
        ret = 0;
        goto cleanup;
    }

    if (state >= MachineState_FirstOnline
        && state <= MachineState_LastOnline) {
        vboxError(VIR_ERR_OPERATION_INVALID, "%s",
                  _("cannot delete snapshots of running domain"));
        goto cleanup;
    }

    rc = VBOX_SESSION_OPEN(domiid.value, machine);
    if (NS_SUCCEEDED(rc))
        rc = data->vboxSession->vtbl->GetConsole(data->vboxSession, &console);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
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

#if VBOX_API_VERSION <= 2002 || VBOX_API_VERSION >= 4000
    /* No Callback support for VirtualBox 2.2.* series */
    /* No Callback support for VirtualBox 4.* series */
#else /* !(VBOX_API_VERSION == 2002 || VBOX_API_VERSION >= 4000) */

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
            virDomainEventPtr ev;

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

            ev = virDomainEventNewFromDom(dom, event, detail);

            if (ev)
                virDomainEventStateQueue(g_pVBoxGlobalData->domainEvents, ev);
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

# if VBOX_API_VERSION < 3001
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
# else  /* VBOX_API_VERSION >= 3001 */
# endif /* VBOX_API_VERSION >= 3001 */

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
            virDomainEventPtr ev;

            /* CURRENT LIMITATION: we never get the VIR_DOMAIN_EVENT_UNDEFINED
             * event becuase the when the machine is de-registered the call
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

            ev = virDomainEventNewFromDom(dom, event, detail);

            if (ev)
                virDomainEventStateQueue(g_pVBoxGlobalData->domainEvents, ev);
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
    if (    memcmp(iid, &ivirtualboxCallbackUUID, sizeof(nsID)) == 0
        ||  memcmp(iid, &isupportIID, sizeof(nsID)) == 0) {
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
        virReportOOMError();
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
# if VBOX_API_VERSION < 3001
        vboxCallback->vtbl->OnMediaRegistered           = &vboxCallbackOnMediaRegistered;
# else  /* VBOX_API_VERSION >= 3001 */
# endif /* VBOX_API_VERSION >= 3001 */
        vboxCallback->vtbl->OnMachineRegistered         = &vboxCallbackOnMachineRegistered;
        vboxCallback->vtbl->OnSessionStateChange        = &vboxCallbackOnSessionStateChange;
        vboxCallback->vtbl->OnSnapshotTaken             = &vboxCallbackOnSnapshotTaken;
# if VBOX_API_VERSION < 3002
        vboxCallback->vtbl->OnSnapshotDiscarded         = &vboxCallbackOnSnapshotDiscarded;
# else /* VBOX_API_VERSION >= 3002 */
        vboxCallback->vtbl->OnSnapshotDeleted           = &vboxCallbackOnSnapshotDiscarded;
# endif /* VBOX_API_VERSION >= 3002 */
        vboxCallback->vtbl->OnSnapshotChange            = &vboxCallbackOnSnapshotChange;
        vboxCallback->vtbl->OnGuestPropertyChange       = &vboxCallbackOnGuestPropertyChange;
        g_pVBoxGlobalData->vboxCallBackRefCount = 1;

    }

    return vboxCallback;
}

static void vboxReadCallback(int watch ATTRIBUTE_UNUSED,
                             int fd,
                             int events ATTRIBUTE_UNUSED,
                             void *opaque ATTRIBUTE_UNUSED) {
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

static int vboxDomainEventRegister (virConnectPtr conn,
                                    virConnectDomainEventCallback callback,
                                    void *opaque,
                                    virFreeCallback freecb) {
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
            VIR_DEBUG("virDomainEventStateRegister (ret = %d) ( conn: %p, "
                      "callback: %p, opaque: %p, "
                      "freecb: %p )", ret, conn, callback,
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

static int vboxDomainEventDeregister (virConnectPtr conn,
                                      virConnectDomainEventCallback callback) {
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

    return ret;
}

static int vboxDomainEventRegisterAny(virConnectPtr conn,
                                      virDomainPtr dom,
                                      int eventID,
                                      virConnectDomainEventGenericCallback callback,
                                      void *opaque,
                                      virFreeCallback freecb) {
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
            VIR_DEBUG("virDomainEventStateRegisterID (ret = %d) ( conn: %p, "
                      "callback: %p, opaque: %p, "
                      "freecb: %p )", ret, conn, callback,
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

static int vboxDomainEventDeregisterAny(virConnectPtr conn,
                                        int callbackID) {
    VBOX_OBJECT_CHECK(conn, int, -1);
    int cnt;

    /* Locking has to be there as callbacks are not
     * really fully thread safe
     */
    vboxDriverLock(data);

    cnt = virDomainEventStateDeregisterID(conn, data->domainEvents,
                                          callbackID);

    if (data->vboxCallback && cnt == 0) {
        data->vboxObj->vtbl->UnregisterCallback(data->vboxObj, data->vboxCallback);
        VBOX_RELEASE(data->vboxCallback);

        /* Remove the Event file handle on which we are listening as well */
        virEventRemoveHandle(data->fdWatch);
        data->fdWatch = -1;
    }

    vboxDriverUnlock(data);

    return ret;
}

#endif /* !(VBOX_API_VERSION == 2002 || VBOX_API_VERSION >= 4000) */

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

static int vboxNetworkClose(virConnectPtr conn) {
    VIR_DEBUG("network uninitialized");
    conn->networkPrivateData = NULL;
    return 0;
}

static int vboxNumOfNetworks(virConnectPtr conn) {
    VBOX_OBJECT_HOST_CHECK(conn, int, 0);
    vboxArray networkInterfaces = VBOX_ARRAY_INITIALIZER;
    int i = 0;

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

static int vboxListNetworks(virConnectPtr conn, char **const names, int nnames) {
    VBOX_OBJECT_HOST_CHECK(conn, int, 0);
    vboxArray networkInterfaces = VBOX_ARRAY_INITIALIZER;
    int i = 0;

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
                    names[ret] = strdup(nameUtf8);
                    if (names[ret] == NULL) {
                        virReportOOMError();
                    } else {
                        ret++;
                    }

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

static int vboxNumOfDefinedNetworks(virConnectPtr conn) {
    VBOX_OBJECT_HOST_CHECK(conn, int, 0);
    vboxArray networkInterfaces = VBOX_ARRAY_INITIALIZER;
    int i = 0;

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

static int vboxListDefinedNetworks(virConnectPtr conn, char **const names, int nnames) {
    VBOX_OBJECT_HOST_CHECK(conn, int, 0);
    vboxArray networkInterfaces = VBOX_ARRAY_INITIALIZER;
    int i = 0;

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
                    names[ret] = strdup(nameUtf8);
                    if (names[ret] == NULL) {
                        virReportOOMError();
                    } else {
                        ret++;
                    }

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

static virNetworkPtr vboxNetworkLookupByName(virConnectPtr conn, const char *name) {
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

static virNetworkPtr vboxNetworkDefineCreateXML(virConnectPtr conn, const char *xml, bool start) {
    VBOX_OBJECT_HOST_CHECK(conn, virNetworkPtr, NULL);
    PRUnichar *networkInterfaceNameUtf16    = NULL;
    char      *networkInterfaceNameUtf8     = NULL;
    IHostNetworkInterface *networkInterface = NULL;
    nsresult rc;

    virNetworkDefPtr def = virNetworkDefParseString(xml);
    virNetworkIpDefPtr ipdef;
    virSocketAddr netmask;

    if (   (!def)
        || (def->forwardType != VIR_NETWORK_FORWARD_NONE)
        || (def->nips == 0 || !def->ips))
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

#if VBOX_API_VERSION == 2002
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
#else /* VBOX_API_VERSION != 2002 */
    {
        IProgress *progress = NULL;
        host->vtbl->CreateHostOnlyNetworkInterface(host, &networkInterface,
                                                   &progress);

        if (progress) {
            progress->vtbl->WaitForCompletion(progress, -1);
            VBOX_RELEASE(progress);
        }
    }
#endif /* VBOX_API_VERSION != 2002 */

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
                virReportOOMError();
                goto cleanup;
            }
        }

        VBOX_UTF8_TO_UTF16(networkNameUtf8 , &networkNameUtf16);

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
            networkInterface->vtbl->EnableStaticIpConfig(networkInterface,
                                                         ipAddressUtf16,
                                                         networkMaskUtf16);

            VBOX_UTF16_FREE(ipAddressUtf16);
            VBOX_UTF16_FREE(networkMaskUtf16);
        } else {
            networkInterface->vtbl->EnableDynamicIpConfig(networkInterface);
            networkInterface->vtbl->DhcpRediscover(networkInterface);
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

static virNetworkPtr vboxNetworkCreateXML(virConnectPtr conn, const char *xml) {
    return vboxNetworkDefineCreateXML(conn, xml, true);
}

static virNetworkPtr vboxNetworkDefineXML(virConnectPtr conn, const char *xml) {
    return vboxNetworkDefineCreateXML(conn, xml, false);
}

static int vboxNetworkUndefineDestroy(virNetworkPtr network, bool removeinterface) {
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

    if (virAsprintf(&networkNameUtf8, "HostInterfaceNetworking-%s", network->name) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    VBOX_UTF8_TO_UTF16(network->name, &networkInterfaceNameUtf16);

    host->vtbl->FindHostNetworkInterfaceByName(host, networkInterfaceNameUtf16, &networkInterface);

    if (networkInterface) {
        PRUint32 interfaceType = 0;

        networkInterface->vtbl->GetInterfaceType(networkInterface, &interfaceType);

        if (interfaceType == HostNetworkInterfaceType_HostOnly) {
            PRUnichar *networkNameUtf16 = NULL;
            IDHCPServer *dhcpServer     = NULL;

#if VBOX_API_VERSION != 2002
            if (removeinterface) {
                PRUnichar *iidUtf16 = NULL;
                IProgress *progress = NULL;

                networkInterface->vtbl->GetId(networkInterface, &iidUtf16);

                if (iidUtf16) {
# if VBOX_API_VERSION == 3000
                    IHostNetworkInterface *netInt = NULL;
                    host->vtbl->RemoveHostOnlyNetworkInterface(host, iidUtf16, &netInt, &progress);
                    VBOX_RELEASE(netInt);
# else  /* VBOX_API_VERSION > 3000 */
                    host->vtbl->RemoveHostOnlyNetworkInterface(host, iidUtf16, &progress);
# endif /* VBOX_API_VERSION > 3000 */
                    VBOX_UTF16_FREE(iidUtf16);
                }

                if (progress) {
                    progress->vtbl->WaitForCompletion(progress, -1);
                    VBOX_RELEASE(progress);
                }
            }
#endif /* VBOX_API_VERSION != 2002 */

            VBOX_UTF8_TO_UTF16(networkNameUtf8 , &networkNameUtf16);

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

static int vboxNetworkUndefine(virNetworkPtr network) {
    return vboxNetworkUndefineDestroy(network, true);
}

static int vboxNetworkCreate(virNetworkPtr network) {
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

    if (virAsprintf(&networkNameUtf8, "HostInterfaceNetworking-%s", network->name) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    VBOX_UTF8_TO_UTF16(network->name, &networkInterfaceNameUtf16);

    host->vtbl->FindHostNetworkInterfaceByName(host, networkInterfaceNameUtf16, &networkInterface);

    if (networkInterface) {
        PRUint32 interfaceType = 0;

        networkInterface->vtbl->GetInterfaceType(networkInterface, &interfaceType);

        if (interfaceType == HostNetworkInterfaceType_HostOnly) {
            PRUnichar *networkNameUtf16 = NULL;
            IDHCPServer *dhcpServer     = NULL;


            VBOX_UTF8_TO_UTF16(networkNameUtf8 , &networkNameUtf16);

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

static int vboxNetworkDestroy(virNetworkPtr network) {
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

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError();
        goto cleanup;
    }
    if (VIR_ALLOC(ipdef) < 0) {
        virReportOOMError();
        goto cleanup;
    }
    def->ips = ipdef;
    def->nips = 1;

    if (virAsprintf(&networkNameUtf8, "HostInterfaceNetworking-%s", network->name) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    VBOX_UTF8_TO_UTF16(network->name, &networkInterfaceNameUtf16);

    host->vtbl->FindHostNetworkInterfaceByName(host, networkInterfaceNameUtf16, &networkInterface);

    if (networkInterface) {
        PRUint32 interfaceType = 0;

        networkInterface->vtbl->GetInterfaceType(networkInterface, &interfaceType);

        if (interfaceType == HostNetworkInterfaceType_HostOnly) {
            def->name = strdup(network->name);
            if (def->name != NULL) {
                PRUnichar *networkNameUtf16 = NULL;
                IDHCPServer *dhcpServer     = NULL;
                vboxIID vboxnet0IID = VBOX_IID_INITIALIZER;

                networkInterface->vtbl->GetId(networkInterface, &vboxnet0IID.value);
                vboxIIDToUUID(&vboxnet0IID, def->uuid);

                VBOX_UTF8_TO_UTF16(networkNameUtf8 , &networkNameUtf16);

                def->forwardType = VIR_NETWORK_FORWARD_NONE;

                data->vboxObj->vtbl->FindDHCPServerByNetworkName(data->vboxObj,
                                                                 networkNameUtf16,
                                                                 &dhcpServer);
                if (dhcpServer) {
                    ipdef->nranges = 1;
                    if (VIR_ALLOC_N(ipdef->ranges, ipdef->nranges) >=0 ) {
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
                        virReportOOMError();
                    }

                    ipdef->nhosts = 1;
                    if (VIR_ALLOC_N(ipdef->hosts, ipdef->nhosts) >=0 ) {
                        ipdef->hosts[0].name = strdup(network->name);
                        if (ipdef->hosts[0].name == NULL) {
                            VIR_FREE(ipdef->hosts);
                            ipdef->nhosts = 0;
                            virReportOOMError();
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
            } else {
                virReportOOMError();
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

static virDrvOpenStatus vboxStorageOpen (virConnectPtr conn,
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

static int vboxStorageClose (virConnectPtr conn) {
    VIR_DEBUG("vbox storage uninitialized");
    conn->storagePrivateData = NULL;
    return 0;
}

static int vboxStorageNumOfPools(virConnectPtr conn ATTRIBUTE_UNUSED) {

    /** Currently only one pool supported, the default one
     * given by ISystemProperties::defaultHardDiskFolder()
     */

    return 1;
}

static int vboxStorageListPools(virConnectPtr conn ATTRIBUTE_UNUSED,
                                char **const names, int nnames) {
    int numActive = 0;

    if (nnames == 1) {
        names[numActive] = strdup("default-pool");
        if (names[numActive] == NULL) {
            virReportOOMError();
        } else {
            numActive++;
        }
    }
    return numActive;
}

static virStoragePoolPtr vboxStoragePoolLookupByName(virConnectPtr conn, const char *name) {
    virStoragePoolPtr ret = NULL;

    /** Current limitation of the function: since
     * the default pool doesn't have UUID just assign
     * one till vbox can handle pools
     */
    if (STREQ("default-pool", name)) {
        unsigned char uuid[VIR_UUID_BUFLEN];
        const char *uuidstr = "1deff1ff-1481-464f-967f-a50fe8936cc4";

        ignore_value(virUUIDParse(uuidstr, uuid));

        ret = virGetStoragePool(conn, name, uuid);
    }

    return ret;
}

static int vboxStoragePoolNumOfVolumes(virStoragePoolPtr pool) {
    VBOX_OBJECT_CHECK(pool->conn, int, -1);
    vboxArray hardDisks = VBOX_ARRAY_INITIALIZER;
    PRUint32 hardDiskAccessible = 0;
    nsresult rc;
    int i;

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
        vboxError(VIR_ERR_INTERNAL_ERROR,
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
    int i;

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
                        names[numActive] = strdup(nameUtf8);
                        if (names[numActive] == NULL) {
                            virReportOOMError();
                        } else {
                            numActive++;
                        }

                        VBOX_UTF8_FREE(nameUtf8);
                    }
                }
            }
        }

        vboxArrayRelease(&hardDisks);

        ret = numActive;
    } else {
        ret = -1;
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("could not get the volume list in the pool: %s, rc=%08x"),
                  pool->name, (unsigned)rc);
    }

    return ret;
}

static virStorageVolPtr vboxStorageVolLookupByName(virStoragePoolPtr pool, const char *name) {
    VBOX_OBJECT_CHECK(pool->conn, virStorageVolPtr, NULL);
    vboxArray hardDisks = VBOX_ARRAY_INITIALIZER;
    nsresult rc;
    int i;

    if(!name)
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

                            ret = virGetStorageVol(pool->conn, pool->name, name, key);

                            VIR_DEBUG("virStorageVolPtr: %p", ret);
                            VIR_DEBUG("Storage Volume Name: %s", name);
                            VIR_DEBUG("Storage Volume key : %s", key);
                            VIR_DEBUG("Storage Volume Pool: %s", pool->name);
                        }

                        vboxIIDUnalloc(&hddIID);
                        VBOX_UTF8_FREE(nameUtf8);
                        break;
                    }

                    if (nameUtf8)
                        VBOX_UTF8_FREE(nameUtf8);
                }
            }
        }

        vboxArrayRelease(&hardDisks);
    }

    return ret;
}

static virStorageVolPtr vboxStorageVolLookupByKey(virConnectPtr conn, const char *key) {
    VBOX_OBJECT_CHECK(conn, virStorageVolPtr, NULL);
    vboxIID hddIID = VBOX_IID_INITIALIZER;
    unsigned char uuid[VIR_UUID_BUFLEN];
    IHardDisk *hardDisk  = NULL;
    nsresult rc;

    if (!key)
        return ret;

    if (virUUIDParse(key, uuid) < 0) {
        vboxError(VIR_ERR_INVALID_ARG,
                  _("Could not parse UUID from '%s'"), key);
        return NULL;
    }

    vboxIIDFromUUID(&hddIID, uuid);
#if VBOX_API_VERSION < 4000
    rc = data->vboxObj->vtbl->GetHardDisk(data->vboxObj, hddIID.value, &hardDisk);
#else /* VBOX_API_VERSION >= 4000 */
    rc = data->vboxObj->vtbl->FindMedium(data->vboxObj, hddIID.value,
                                         DeviceType_HardDisk, &hardDisk);
#endif /* VBOX_API_VERSION >= 4000 */
    if (NS_SUCCEEDED(rc)) {
        PRUint32 hddstate;

        VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetState, &hddstate);
        if (hddstate != MediaState_Inaccessible) {
            PRUnichar *hddNameUtf16 = NULL;
            char      *hddNameUtf8  = NULL;

            VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetName, &hddNameUtf16);
            VBOX_UTF16_TO_UTF8(hddNameUtf16, &hddNameUtf8);

            if (hddNameUtf8) {
                if (vboxStorageNumOfPools(conn) == 1) {
                    ret = virGetStorageVol(conn, "default-pool", hddNameUtf8, key);
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

static virStorageVolPtr vboxStorageVolLookupByPath(virConnectPtr conn, const char *path) {
    VBOX_OBJECT_CHECK(conn, virStorageVolPtr, NULL);
    PRUnichar *hddPathUtf16 = NULL;
    IHardDisk *hardDisk     = NULL;
    nsresult rc;

    if (!path)
        return ret;

    VBOX_UTF8_TO_UTF16(path, &hddPathUtf16);

    if (!hddPathUtf16)
        return ret;

#if VBOX_API_VERSION < 4000
    rc = data->vboxObj->vtbl->FindHardDisk(data->vboxObj, hddPathUtf16, &hardDisk);
#else /* VBOX_API_VERSION >= 4000 */
    rc = data->vboxObj->vtbl->FindMedium(data->vboxObj, hddPathUtf16,
                                         DeviceType_HardDisk, &hardDisk);
#endif /* VBOX_API_VERSION >= 4000 */
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
                    if (vboxStorageNumOfPools(conn) == 1)
                        ret = virGetStorageVol(conn, "default-pool", hddNameUtf8, key);

                    VIR_DEBUG("Storage Volume Pool: %s", "default-pool");
                    VIR_DEBUG("Storage Volume Name: %s", hddNameUtf8);
                    VIR_DEBUG("Storage Volume key : %s", key);
                }

                vboxIIDUnalloc(&hddIID);
            }

            if (hddNameUtf8)
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

    if (   !def->name
        || (def->type != VIR_STORAGE_VOL_FILE))
        goto cleanup;

    /* TODO: for now only the vmdk, vpc and vdi type harddisk
     * variants can be created, also since there is no vdi
     * type in enum virStorageFileFormat {} the default
     * will be to create vdi if nothing is specified in
     * def->target.format
     */

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
            PRUint64   logicalSize = VIR_DIV_UP(def->capacity, 1024 * 1024);
            PRUint32   variant     = HardDiskVariant_Standard;

            if (def->capacity == def->allocation)
                variant = HardDiskVariant_Fixed;

            rc = hardDisk->vtbl->CreateBaseStorage(hardDisk, logicalSize, variant, &progress);
            if (NS_SUCCEEDED(rc) && progress) {
#if VBOX_API_VERSION == 2002
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

                        ret = virGetStorageVol(pool->conn, pool->name, def->name, key);
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
    int i = 0;
    int j = 0;

    virCheckFlags(0, -1);

    if (virUUIDParse(vol->key, uuid) < 0) {
        vboxError(VIR_ERR_INVALID_ARG,
                  _("Could not parse UUID from '%s'"), vol->key);
        return -1;
    }

    vboxIIDFromUUID(&hddIID, uuid);
#if VBOX_API_VERSION < 4000
    rc = data->vboxObj->vtbl->GetHardDisk(data->vboxObj, hddIID.value, &hardDisk);
#else /* VBOX_API_VERSION >= 4000 */
    rc = data->vboxObj->vtbl->FindMedium(data->vboxObj, hddIID.value,
                                         DeviceType_HardDisk, &hardDisk);
#endif /* VBOX_API_VERSION >= 4000 */
    if (NS_SUCCEEDED(rc)) {
        PRUint32 hddstate;

        VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetState, &hddstate);
        if (hddstate != MediaState_Inaccessible) {
            PRUint32  machineIdsSize = 0;
            vboxArray machineIds = VBOX_ARRAY_INITIALIZER;

#if VBOX_API_VERSION < 3001
            vboxArrayGet(&machineIds, hardDisk, hardDisk->vtbl->imedium.GetMachineIds);
#else  /* VBOX_API_VERSION >= 3001 */
            vboxArrayGet(&machineIds, hardDisk, hardDisk->vtbl->GetMachineIds);
#endif /* VBOX_API_VERSION >= 3001 */

#if VBOX_API_VERSION == 2002 && defined WIN32
            /* VirtualBox 2.2 on Windows represents IIDs as GUIDs and the
             * machineIds array contains direct instances of the GUID struct
             * instead of pointers to the actual struct instances. But there
             * is no 128bit width simple item type for a SafeArray to fit a
             * GUID in. The largest simple type it 64bit width and VirtualBox
             * uses two of this 64bit items to represents one GUID. Therefore,
             * we devide the size of the SafeArray by two, to compensate for
             * this workaround in VirtualBox */
            machineIds.count /= 2;
#endif /* VBOX_API_VERSION >= 2002 */

            machineIdsSize = machineIds.count;

            for (i = 0; i < machineIds.count; i++) {
                IMachine *machine = NULL;
                vboxIID machineId = VBOX_IID_INITIALIZER;

                vboxIIDFromArrayItem(&machineId, &machineIds, i);

#if VBOX_API_VERSION >= 4000
                rc = VBOX_OBJECT_GET_MACHINE(machineId.value, &machine);
                if (NS_FAILED(rc)) {
                    vboxError(VIR_ERR_NO_DOMAIN, "%s",
                              _("no domain with matching uuid"));
                    break;
                }
#endif

                rc = VBOX_SESSION_OPEN(machineId.value, machine);

                if (NS_SUCCEEDED(rc)) {

                    rc = data->vboxSession->vtbl->GetMachine(data->vboxSession, &machine);
                    if (NS_SUCCEEDED(rc)) {
                        vboxArray hddAttachments = VBOX_ARRAY_INITIALIZER;

#if VBOX_API_VERSION < 3001
                        vboxArrayGet(&hddAttachments, machine,
                                     machine->vtbl->GetHardDiskAttachments);
#else  /* VBOX_API_VERSION >= 3001 */
                        vboxArrayGet(&hddAttachments, machine,
                                     machine->vtbl->GetMediumAttachments);
#endif /* VBOX_API_VERSION >= 3001 */
                        for (j = 0; j < hddAttachments.count; j++) {
                            IHardDiskAttachment *hddAttachment = hddAttachments.items[j];

                            if (hddAttachment) {
                                IHardDisk *hdd = NULL;

#if VBOX_API_VERSION < 3001
                                rc = hddAttachment->vtbl->GetHardDisk(hddAttachment, &hdd);
#else  /* VBOX_API_VERSION >= 3001 */
                                rc = hddAttachment->vtbl->GetMedium(hddAttachment, &hdd);
#endif /* VBOX_API_VERSION >= 3001 */
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

#if VBOX_API_VERSION < 3001
                                            rc = machine->vtbl->DetachHardDisk(machine, controller, port, device);
#else  /* VBOX_API_VERSION >= 3001 */
                                            rc = machine->vtbl->DetachDevice(machine, controller, port, device);
#endif /* VBOX_API_VERSION >= 3001 */
                                            if (NS_SUCCEEDED(rc)) {
                                                rc = machine->vtbl->SaveSettings(machine);
                                                VIR_DEBUG("saving machine settings");
                                            }

                                            if (NS_SUCCEEDED(rc)) {
                                                deregister++;
                                                VIR_DEBUG("deregistering hdd:%d", deregister);
                                            }

                                            if (controller)
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

static int vboxStorageVolGetInfo(virStorageVolPtr vol, virStorageVolInfoPtr info) {
    VBOX_OBJECT_CHECK(vol->conn, int, -1);
    IHardDisk *hardDisk  = NULL;
    unsigned char uuid[VIR_UUID_BUFLEN];
    vboxIID hddIID = VBOX_IID_INITIALIZER;
    nsresult rc;

    if (!info)
        return ret;

    if (virUUIDParse(vol->key, uuid) < 0) {
        vboxError(VIR_ERR_INVALID_ARG,
                  _("Could not parse UUID from '%s'"), vol->key);
        return ret;
    }

    vboxIIDFromUUID(&hddIID, uuid);
#if VBOX_API_VERSION < 4000
    rc = data->vboxObj->vtbl->GetHardDisk(data->vboxObj, hddIID.value, &hardDisk);
#else /* VBOX_API_VERSION >= 4000 */
    rc = data->vboxObj->vtbl->FindMedium(data->vboxObj, hddIID.value,
                                         DeviceType_HardDisk, &hardDisk);
#endif /* VBOX_API_VERSION >= 4000 */
    if (NS_SUCCEEDED(rc)) {
        PRUint32 hddstate;

        VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetState, &hddstate);
        if (hddstate != MediaState_Inaccessible) {
#if VBOX_API_VERSION < 4000
            PRUint64 hddLogicalSize;
            PRUint64 hddActualSize;
#else /* VBOX_API_VERSION >= 4000 */
            PRInt64 hddLogicalSize;
            PRInt64 hddActualSize;
#endif /* VBOX_API_VERSION >= 4000 */

            info->type = VIR_STORAGE_VOL_FILE;

            hardDisk->vtbl->GetLogicalSize(hardDisk, &hddLogicalSize);
#if VBOX_API_VERSION < 4000
            info->capacity = hddLogicalSize * 1024 * 1024; /* MB => Bytes */
#else /* VBOX_API_VERSION >= 4000 */
            info->capacity = hddLogicalSize;
#endif /* VBOX_API_VERSION >= 4000 */

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
        vboxError(VIR_ERR_INVALID_ARG,
                  _("Could not parse UUID from '%s'"), vol->key);
        return ret;
    }

    vboxIIDFromUUID(&hddIID, uuid);
#if VBOX_API_VERSION < 4000
    rc = data->vboxObj->vtbl->GetHardDisk(data->vboxObj, hddIID.value, &hardDisk);
#else /* VBOX_API_VERSION >= 4000 */
    rc = data->vboxObj->vtbl->FindMedium(data->vboxObj, hddIID.value,
                                         DeviceType_HardDisk, &hardDisk);
#endif /* VBOX_API_VERSION >= 4000 */
    if (NS_SUCCEEDED(rc)) {
        PRUint32 hddstate;

        VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetState, &hddstate);
        if (NS_SUCCEEDED(rc) && hddstate != MediaState_Inaccessible) {
            PRUnichar *hddFormatUtf16 = NULL;
#if VBOX_API_VERSION < 4000
            PRUint64 hddLogicalSize;
            PRUint64 hddActualSize;
#else /* VBOX_API_VERSION >= 4000 */
            PRInt64 hddLogicalSize;
            PRInt64 hddActualSize;
#endif /* VBOX_API_VERSION >= 4000 */

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
#if VBOX_API_VERSION < 4000
                def.capacity = hddLogicalSize * 1024 * 1024; /* MB => Bytes */
#else /* VBOX_API_VERSION >= 4000 */
                def.capacity = hddLogicalSize;
#endif /* VBOX_API_VERSION >= 4000 */
            } else
                defOk = 0;

            rc = VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetSize, &hddActualSize);
            if (NS_SUCCEEDED(rc) && defOk)
                def.allocation = hddActualSize;
            else
                defOk = 0;

            def.name = strdup(vol->name);
            if (!(def.name && defOk))
                defOk = 0;

            def.key = strdup(vol->key);
            if (!(def.key && defOk))
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
                    else
                        def.target.format = VIR_STORAGE_FILE_RAW;

                    /* TODO: need to add vdi to enum virStorageFileFormat {}
                     * and then add it here
                     */

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
        vboxError(VIR_ERR_INVALID_ARG,
                  _("Could not parse UUID from '%s'"), vol->key);
        return ret;
    }

    vboxIIDFromUUID(&hddIID, uuid);
#if VBOX_API_VERSION < 4000
    rc = data->vboxObj->vtbl->GetHardDisk(data->vboxObj, hddIID.value, &hardDisk);
#else /* VBOX_API_VERSION >= 4000 */
    rc = data->vboxObj->vtbl->FindMedium(data->vboxObj, hddIID.value,
                                         DeviceType_HardDisk, &hardDisk);
#endif /* VBOX_API_VERSION >= 4000 */
    if (NS_SUCCEEDED(rc)) {
        PRUint32 hddstate;

        VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetState, &hddstate);
        if (hddstate != MediaState_Inaccessible) {
            PRUnichar *hddLocationUtf16 = NULL;
            char      *hddLocationUtf8  = NULL;

            VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetLocation, &hddLocationUtf16);

            VBOX_UTF16_TO_UTF8(hddLocationUtf16, &hddLocationUtf8);
            if (hddLocationUtf8) {

                ret = strdup(hddLocationUtf8);
                if (!ret)
                    virReportOOMError();

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

#if VBOX_API_VERSION >= 4000
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
        vboxError(VIR_ERR_NO_DOMAIN, "%s",
                  _("no domain with matching uuid"));
        return NULL;
    }

    rc = machine->vtbl->GetMonitorCount(machine, &max_screen);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_OPERATION_FAILED, "%s",
                  _("unable to get monitor count"));
        VBOX_RELEASE(machine);
        return NULL;
    }

    if (screen >= max_screen) {
        vboxError(VIR_ERR_INVALID_ARG, _("screen ID higher than monitor "
                  "count (%d)"), max_screen);
        VBOX_RELEASE(machine);
        return NULL;
    }

    if (virAsprintf(&tmp, "%s/cache/libvirt/vbox.screendump.XXXXXX", LOCALSTATEDIR) < 0) {
        virReportOOMError();
        VBOX_RELEASE(machine);
        return NULL;
    }

    if ((tmp_fd = mkstemp(tmp)) == -1) {
        virReportSystemError(errno, _("mkstemp(\"%s\") failed"), tmp);
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

                rc = display->vtbl->GetScreenResolution(display, screen,
                                                        &width, &height,
                                                        &bitsPerPixel);

                if (NS_FAILED(rc) || !width || !height) {
                    vboxError(VIR_ERR_OPERATION_FAILED, "%s",
                              _("unable to get screen resolution"));
                    goto endjob;
                }

                rc = display->vtbl->TakeScreenShotPNGToArray(display, screen,
                                                             width, height,
                                                             &screenDataSize,
                                                             &screenData);
                if (NS_FAILED(rc)) {
                    vboxError(VIR_ERR_OPERATION_FAILED, "%s",
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

                if (virFDStreamOpenFile(st, tmp, 0, 0, O_RDONLY) < 0) {
                    vboxError(VIR_ERR_OPERATION_FAILED, "%s",
                              _("unable to open stream"));
                    goto endjob;
                }

                ret = strdup("image/png");

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
#endif /* VBOX_API_VERSION >= 4000 */

/**
 * Function Tables
 */

virDriver NAME(Driver) = {
    .no = VIR_DRV_VBOX,
    .name = "VBOX",
    .open = vboxOpen, /* 0.6.3 */
    .close = vboxClose, /* 0.6.3 */
    .version = vboxGetVersion, /* 0.6.3 */
    .getHostname = virGetHostname, /* 0.6.3 */
    .getMaxVcpus = vboxGetMaxVcpus, /* 0.6.3 */
    .nodeGetInfo = nodeGetInfo, /* 0.6.3 */
    .getCapabilities = vboxGetCapabilities, /* 0.6.3 */
    .listDomains = vboxListDomains, /* 0.6.3 */
    .numOfDomains = vboxNumOfDomains, /* 0.6.3 */
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
    .listDefinedDomains = vboxListDefinedDomains, /* 0.6.3 */
    .numOfDefinedDomains = vboxNumOfDefinedDomains, /* 0.6.3 */
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
    .nodeGetCellsFreeMemory = nodeGetCellsFreeMemory, /* 0.6.5 */
    .nodeGetFreeMemory = nodeGetFreeMemory, /* 0.6.5 */
#if VBOX_API_VERSION >= 4000
    .domainScreenshot = vboxDomainScreenshot, /* 0.9.2 */
#endif
#if VBOX_API_VERSION > 2002 && VBOX_API_VERSION < 4000
    .domainEventRegister = vboxDomainEventRegister, /* 0.7.0 */
    .domainEventDeregister = vboxDomainEventDeregister, /* 0.7.0 */
#endif
    .isEncrypted = vboxIsEncrypted, /* 0.7.3 */
    .isSecure = vboxIsSecure, /* 0.7.3 */
    .domainIsActive = vboxDomainIsActive, /* 0.7.3 */
    .domainIsPersistent = vboxDomainIsPersistent, /* 0.7.3 */
    .domainIsUpdated = vboxDomainIsUpdated, /* 0.8.6 */
#if VBOX_API_VERSION > 2002 && VBOX_API_VERSION < 4000
    .domainEventRegisterAny = vboxDomainEventRegisterAny, /* 0.8.0 */
    .domainEventDeregisterAny = vboxDomainEventDeregisterAny, /* 0.8.0 */
#endif
    .domainSnapshotCreateXML = vboxDomainSnapshotCreateXML, /* 0.8.0 */
    .domainSnapshotGetXMLDesc = vboxDomainSnapshotGetXMLDesc, /* 0.8.0 */
    .domainSnapshotNum = vboxDomainSnapshotNum, /* 0.8.0 */
    .domainSnapshotListNames = vboxDomainSnapshotListNames, /* 0.8.0 */
    .domainSnapshotLookupByName = vboxDomainSnapshotLookupByName, /* 0.8.0 */
    .domainHasCurrentSnapshot = vboxDomainHasCurrentSnapshot, /* 0.8.0 */
    .domainSnapshotGetParent = vboxDomainSnapshotGetParent, /* 0.9.7 */
    .domainSnapshotCurrent = vboxDomainSnapshotCurrent, /* 0.8.0 */
    .domainRevertToSnapshot = vboxDomainRevertToSnapshot, /* 0.8.0 */
    .domainSnapshotDelete = vboxDomainSnapshotDelete, /* 0.8.0 */
    .isAlive = vboxIsAlive, /* 0.9.8 */
};

virNetworkDriver NAME(NetworkDriver) = {
    "VBOX",
    .open                   = vboxNetworkOpen, /* 0.6.4 */
    .close                  = vboxNetworkClose, /* 0.6.4 */
    .numOfNetworks          = vboxNumOfNetworks, /* 0.6.4 */
    .listNetworks           = vboxListNetworks, /* 0.6.4 */
    .numOfDefinedNetworks   = vboxNumOfDefinedNetworks, /* 0.6.4 */
    .listDefinedNetworks    = vboxListDefinedNetworks, /* 0.6.4 */
    .networkLookupByUUID    = vboxNetworkLookupByUUID, /* 0.6.4 */
    .networkLookupByName    = vboxNetworkLookupByName, /* 0.6.4 */
    .networkCreateXML       = vboxNetworkCreateXML, /* 0.6.4 */
    .networkDefineXML       = vboxNetworkDefineXML, /* 0.6.4 */
    .networkUndefine        = vboxNetworkUndefine, /* 0.6.4 */
    .networkCreate          = vboxNetworkCreate, /* 0.6.4 */
    .networkDestroy         = vboxNetworkDestroy, /* 0.6.4 */
    .networkGetXMLDesc      = vboxNetworkGetXMLDesc, /* 0.6.4 */
};

virStorageDriver NAME(StorageDriver) = {
    .name               = "VBOX",
    .open               = vboxStorageOpen, /* 0.7.1 */
    .close              = vboxStorageClose, /* 0.7.1 */
    .numOfPools         = vboxStorageNumOfPools, /* 0.7.1 */
    .listPools          = vboxStorageListPools, /* 0.7.1 */
    .poolLookupByName   = vboxStoragePoolLookupByName, /* 0.7.1 */
    .poolNumOfVolumes   = vboxStoragePoolNumOfVolumes, /* 0.7.1 */
    .poolListVolumes    = vboxStoragePoolListVolumes, /* 0.7.1 */

    .volLookupByName    = vboxStorageVolLookupByName, /* 0.7.1 */
    .volLookupByKey     = vboxStorageVolLookupByKey, /* 0.7.1 */
    .volLookupByPath    = vboxStorageVolLookupByPath, /* 0.7.1 */
    .volCreateXML       = vboxStorageVolCreateXML, /* 0.7.1 */
    .volDelete          = vboxStorageVolDelete, /* 0.7.1 */
    .volGetInfo         = vboxStorageVolGetInfo, /* 0.7.1 */
    .volGetXMLDesc      = vboxStorageVolGetXMLDesc, /* 0.7.1 */
    .volGetPath         = vboxStorageVolGetPath /* 0.7.1 */
};
