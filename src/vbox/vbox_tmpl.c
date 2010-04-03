/** @file vbox_tmpl.c
 * Template File to support multiple versions of VirtualBox
 * at runtime :).
 *
 * IMPORTANT:
 * Please dont include this file in the src/Makefile.am, it
 * is automatically include by other files.
 */

/*
 * Copyright (C) 2010 Red Hat, Inc.
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

#include <dlfcn.h>
#include <sys/utsname.h>
#include <stdbool.h>

#include "internal.h"

#include "datatypes.h"
#include "domain_conf.h"
#include "network_conf.h"
#include "virterror_internal.h"
#include "domain_event.h"
#include "storage_conf.h"
#include "storage_file.h"
#include "uuid.h"
#include "event.h"
#include "memory.h"
#include "nodeinfo.h"
#include "logging.h"
#include "vbox_driver.h"

/* This one changes from version to version. */
#if VBOX_API_VERSION == 2002
# include "vbox_CAPI_v2_2.h"
#elif VBOX_API_VERSION == 3000
# include "vbox_CAPI_v3_0.h"
#elif VBOX_API_VERSION == 3001
# include "vbox_CAPI_v3_1.h"
#else
# error "Unsupport VBOX_API_VERSION"
#endif

/* Include this *last* or we'll get the wrong vbox_CAPI_*.h. */
#include "vbox_XPCOMCGlue.h"


#define VIR_FROM_THIS                   VIR_FROM_VBOX
#define VBOX_UTF16_FREE(arg)            data->pFuncs->pfnUtf16Free(arg)
#define VBOX_UTF8_FREE(arg)             data->pFuncs->pfnUtf8Free(arg)
#define VBOX_COM_UNALLOC_MEM(arg)       data->pFuncs->pfnComUnallocMem(arg)
#define VBOX_UTF16_TO_UTF8(arg1, arg2)  data->pFuncs->pfnUtf16ToUtf8(arg1, arg2)
#define VBOX_UTF8_TO_UTF16(arg1, arg2)  data->pFuncs->pfnUtf8ToUtf16(arg1, arg2)

#define VBOX_RELEASE(arg) \
if(arg)\
    (arg)->vtbl->nsisupports.Release((nsISupports *)(arg))

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
        virReportErrorHelper(NULL, VIR_FROM_VBOX, code, __FILE__, \
                             __FUNCTION__, __LINE__, __VA_ARGS__)

#define DEBUGPRUnichar(msg, strUtf16) \
if (strUtf16) {\
    char *strUtf8 = NULL;\
\
    g_pVBoxGlobalData->pFuncs->pfnUtf16ToUtf8(strUtf16, &strUtf8);\
    if (strUtf8) {\
        DEBUG("%s: %s", msg, strUtf8);\
        g_pVBoxGlobalData->pFuncs->pfnUtf8Free(strUtf8);\
    }\
}

#define DEBUGUUID(msg, iid) \
{\
    DEBUG (msg ": {%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",\
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

    /* An array of callbacks */
    virDomainEventCallbackListPtr domainEventCallbacks;

    int fdWatch;
    int domainEventDispatching;

    IVirtualBoxCallback *vboxCallback;

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

static virDomainPtr vboxDomainDefineXML(virConnectPtr conn, const char *xml);
static int vboxDomainCreate(virDomainPtr dom);
static int vboxDomainUndefine(virDomainPtr dom);

static void vboxDriverLock(vboxGlobalData *data) {
    virMutexLock(&data->lock);
}

static void vboxDriverUnlock(vboxGlobalData *data) {
    virMutexUnlock(&data->lock);
}

#if VBOX_API_VERSION == 2002

# define vboxIIDFromUUID(uuid, iid) nsIDFromChar((iid), (uuid))
# define vboxIIDToUUID(uuid, iid) nsIDtoChar((uuid), (iid))
# define vboxIIDUnalloc(iid) data->pFuncs->pfnComUnallocMem(iid)
# define vboxIIDFree(iid) VIR_FREE(iid)
# define vboxIIDUtf8Free(iid) VIR_FREE(iid)
# define vboxIIDUtf16Free(iid) VIR_FREE(iid)
# define DEBUGIID(msg, iid) DEBUGUUID(msg, iid)

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
    virUUIDParse(uuidstrdst, uuid);
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
    virUUIDParse(uuidstrdst, uuidinterim);
    memcpy(iid, uuidinterim, VIR_UUID_BUFLEN);
}

typedef nsID vboxIID;

static bool vboxIIDEqual(vboxIID *firstIID, vboxIID *secondIID) {
    if (memcmp(firstIID, secondIID, sizeof(firstIID)) == 0)
        return true;
    else
        return false;
}

static void vboxIIDtoUtf8(vboxIID *iid, char **uuidstr) {
    unsigned char hddUUID[VIR_UUID_BUFLEN];

    if (VIR_ALLOC_N(*uuidstr, VIR_UUID_STRING_BUFLEN) < 0) {
        virReportOOMError();
        return;
    }

    vboxIIDToUUID(hddUUID, iid);
    virUUIDFormat(hddUUID, *uuidstr);
}

static void vboxUtf8toIID(char *uuidstr, vboxIID **iid) {
    unsigned char hddUUID[VIR_UUID_BUFLEN];

    if (VIR_ALLOC(*iid) < 0) {
        virReportOOMError();
        return;
    }

    virUUIDParse(uuidstr, hddUUID);
    vboxIIDFromUUID(hddUUID, *iid);
}

#else /* VBOX_API_VERSION != 2002 */

# define vboxIIDFromUUID(uuid, iid)\
{\
    char vboxIIDUtf8[VIR_UUID_STRING_BUFLEN];\
\
    virUUIDFormat((uuid), vboxIIDUtf8);\
    data->pFuncs->pfnUtf8ToUtf16(vboxIIDUtf8, (&(iid)));\
}

# define vboxIIDToUUID(uuid, iid)\
{\
    char *vboxIIDUtf8  = NULL;\
    data->pFuncs->pfnUtf16ToUtf8((iid), &vboxIIDUtf8);\
    virUUIDParse(vboxIIDUtf8, (uuid));\
    data->pFuncs->pfnUtf8Free(vboxIIDUtf8);\
}

# define vboxIIDFree(iid) data->pFuncs->pfnUtf16Free(iid)
# define vboxIIDUtf8Free(iid) data->pFuncs->pfnUtf8Free(iid)
# define vboxIIDUtf16Free(iid) data->pFuncs->pfnUtf16Free(iid)
# define vboxIIDUnalloc(iid) data->pFuncs->pfnUtf16Free(iid)
# define DEBUGIID(msg, strUtf16) DEBUGPRUnichar(msg, strUtf16)

typedef PRUnichar vboxIID;

static bool vboxIIDEqual(vboxIID *firstIID, vboxIID *secondIID) {
    unsigned char firstUUID[VIR_UUID_BUFLEN];
    unsigned char secondUUID[VIR_UUID_BUFLEN];
    char *firstIIDUtf8  = NULL;
    char *secondIIDUtf8 = NULL;

    if (!g_pVBoxGlobalData)
        return false;

    g_pVBoxGlobalData->pFuncs->pfnUtf16ToUtf8(firstIID, &firstIIDUtf8);
    g_pVBoxGlobalData->pFuncs->pfnUtf16ToUtf8(secondIID, &secondIIDUtf8);

    /* Note: we can't directly compare the utf8 strings here
     * cause the two UUID's may have seperators as space or '-'
     * or mixture of both and we don't want to fail here by
     * using direct string comparison. Here virUUIDParse() takes
     * care of these cases.
     */

    virUUIDParse(firstIIDUtf8, firstUUID);
    virUUIDParse(secondIIDUtf8, secondUUID);

    g_pVBoxGlobalData->pFuncs->pfnUtf8Free(firstIIDUtf8);
    g_pVBoxGlobalData->pFuncs->pfnUtf8Free(secondIIDUtf8);

    if (memcmp(firstUUID, secondUUID, sizeof(firstIID)) == 0)
        return true;
    else
        return false;
}

static void vboxIIDtoUtf8(vboxIID *iid, char **uuidstr) {
    g_pVBoxGlobalData->pFuncs->pfnUtf16ToUtf8(iid, uuidstr);
    if (!(*uuidstr))
        virReportOOMError();
}

static void vboxUtf8toIID(char *uuidstr, vboxIID **iid) {
    g_pVBoxGlobalData->pFuncs->pfnUtf8ToUtf16(uuidstr, iid);
    if (!(*iid))
        virReportOOMError();
}

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

    DEBUG("name=%s, total=%d, storageBus=%u, deviceInst=%d, "
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

    DEBUG("name=%s, total=%d, storageBus=%u, deviceInst=%d, "
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
    return caps;

no_memory:
    virCapabilitiesFree(caps);
    return NULL;
}

static int vboxInitialize(vboxGlobalData *data) {

    /* Get the API table for out version, g_pVBoxFuncs is for the oldest
       version of the API that we support so we cannot use that. */
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

        if (virParseVersionString(vboxVersion, &data->version) >= 0)
            ret = 0;

        VBOX_UTF8_FREE(vboxVersion);
        VBOX_COM_UNALLOC_MEM(versionUtf16);
    }

    if (ret != 0)
        vboxError(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("Cound not extract VirtualBox version"));

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
    VIR_FREE(data->domainEventCallbacks);
#endif /* !(VBOX_API_VERSION == 2002) */
    VIR_FREE(data);
}

static virDrvOpenStatus vboxOpen(virConnectPtr conn,
                                 virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                 int flags ATTRIBUTE_UNUSED) {
    vboxGlobalData *data = NULL;
    uid_t uid = getuid();

    if (conn->uri == NULL) {
        conn->uri = xmlParseURI(uid ? "vbox:///session" : "vbox:///system");
        if (conn->uri == NULL) {
            virReportOOMError();
            return VIR_DRV_OPEN_ERROR;
        }
    }

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

    if (VIR_ALLOC(data->domainEventCallbacks) < 0) {
        virReportOOMError();
        return VIR_DRV_OPEN_ERROR;
    }

    data->conn = conn;
    g_pVBoxGlobalData = data;

#endif /* !(VBOX_API_VERSION == 2002) */

    conn->privateData = data;
    DEBUG0("in vboxOpen");

    return VIR_DRV_OPEN_SUCCESS;
}

static int vboxClose(virConnectPtr conn) {
    vboxGlobalData *data = conn->privateData;
    DEBUG("%s: in vboxClose",conn->driver->name);

    vboxUninitialize(data);
    conn->privateData = NULL;

    return 0;
}

static int vboxGetVersion(virConnectPtr conn, unsigned long *version) {
    vboxGlobalData *data = conn->privateData;
    DEBUG("%s: in vboxGetVersion",conn->driver->name);

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
    IMachine **machines  = NULL;
    PRUint32 machineCnt  = 0;
    PRUint32 state;
    nsresult rc;
    int i, j;

    rc = data->vboxObj->vtbl->GetMachines(data->vboxObj, &machineCnt, &machines);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("Could not get list of Domains, rc=%08x"),(unsigned)rc);
        goto cleanup;
    }

    if (machineCnt == 0) {
        ret = 0;
        goto cleanup;
    }

    for (i = 0,j = 0; (i < machineCnt) && (j < nids); ++i) {
        IMachine *machine = machines[i];

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
    ret++;

cleanup:
    for (i = 0; i < machineCnt; ++i)
        VBOX_RELEASE(machines[i]);
    return ret;
}

static int vboxNumOfDomains(virConnectPtr conn) {
    VBOX_OBJECT_CHECK(conn, int, -1);
    IMachine **machines  = NULL;
    PRUint32 machineCnt  = 0;
    PRUint32 state;
    nsresult rc;
    int i;

    rc = data->vboxObj->vtbl->GetMachines(data->vboxObj, &machineCnt, &machines);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("Could not get number of Domains, rc=%08x"), (unsigned)rc);
        goto cleanup;
    }

    if (machineCnt == 0) {
        ret = 0;
        goto cleanup;
    }

    /* Do the cleanup as required by GetMachines() */
    for (i = 0; i < machineCnt; ++i) {
        IMachine *machine = machines[i];

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
    ret++;

cleanup:
    for (i = 0; i < machineCnt; ++i)
        VBOX_RELEASE(machines[i]);
    return ret;
}

static virDomainPtr vboxDomainCreateXML(virConnectPtr conn, const char *xml,
                                        unsigned int flags ATTRIBUTE_UNUSED) {
    /* VirtualBox currently doesn't have support for running
     * virtual machines without actually defining them and thus
     * for time being just define new machine and start it.
     *
     * TODO: After the appropriate API's are added in VirtualBox
     * change this behaviour to the expected one.
     */

    virDomainPtr dom = vboxDomainDefineXML(conn, xml);
    if (dom == NULL)
        return NULL;

    if (vboxDomainCreate(dom) < 0) {
        vboxDomainUndefine(dom);
        virUnrefDomain(dom);
        return NULL;
    }

    return dom;
}

static virDomainPtr vboxDomainLookupByID(virConnectPtr conn, int id) {
    VBOX_OBJECT_CHECK(conn, virDomainPtr, NULL);
    IMachine **machines  = NULL;
    PRUint32 machineCnt  = 0;
    vboxIID *iid         = NULL;
    unsigned char iidl[VIR_UUID_BUFLEN];
    PRUint32 state;
    nsresult rc;
    int i;

    /* Internal vbox IDs start from 0, the public libvirt ID
     * starts from 1, so refuse id==0, and adjust the rest*/
    if (id == 0) {
        vboxError(VIR_ERR_NO_DOMAIN,
                  _("no domain with matching id %d"), id);
        return NULL;
    }
    id = id - 1;

    rc = data->vboxObj->vtbl->GetMachines(data->vboxObj, &machineCnt, &machines);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("Could not get list of machines, rc=%08x"), (unsigned)rc);
        return NULL;
    }

    if (id < machineCnt) {
        if (machines[id]) {
            PRBool isAccessible = PR_FALSE;
            machines[id]->vtbl->GetAccessible(machines[id], &isAccessible);
            if (isAccessible) {
                machines[id]->vtbl->GetState(machines[id], &state);
                if (   (state >= MachineState_FirstOnline)
                    && (state <= MachineState_LastOnline) ) {
                    PRUnichar *machineNameUtf16 = NULL;
                    char      *machineNameUtf8  = NULL;

                    machines[id]->vtbl->GetName(machines[id], &machineNameUtf16);
                    VBOX_UTF16_TO_UTF8(machineNameUtf16, &machineNameUtf8);

                    machines[id]->vtbl->GetId(machines[id], &iid);
                    vboxIIDToUUID(iidl, iid);
                    vboxIIDUnalloc(iid);

                    /* get a new domain pointer from virGetDomain, if it fails
                     * then no need to assign the id, else assign the id, cause
                     * it is -1 by default. rest is taken care by virGetDomain
                     * itself, so need not worry.
                     */

                    ret = virGetDomain(conn, machineNameUtf8, iidl);
                    if (ret)
                        ret->id = id + 1;

                    /* Cleanup all the XPCOM allocated stuff here */
                    VBOX_UTF8_FREE(machineNameUtf8);
                    VBOX_UTF16_FREE(machineNameUtf16);
                }
            }
        }
    }

    /* Do the cleanup as required by GetMachines() */
    for (i = 0; i < machineCnt; ++i)
        VBOX_RELEASE(machines[i]);

    return ret;
}

static virDomainPtr vboxDomainLookupByUUID(virConnectPtr conn, const unsigned char *uuid) {
    VBOX_OBJECT_CHECK(conn, virDomainPtr, NULL);
    IMachine **machines  = NULL;
    PRUint32 machineCnt  = 0;
    vboxIID *iid         = NULL;
    char      *machineNameUtf8  = NULL;
    PRUnichar *machineNameUtf16 = NULL;
    unsigned char iidl[VIR_UUID_BUFLEN];
    int i, matched = 0;
    nsresult rc;

    rc = data->vboxObj->vtbl->GetMachines(data->vboxObj, &machineCnt, &machines);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("Could not get list of machines, rc=%08x"), (unsigned)rc);
        return NULL;
    }

    for (i = 0; i < machineCnt; ++i) {
        IMachine *machine = machines[i];
        PRBool isAccessible = PR_FALSE;

        if (!machine)
            continue;

        machine->vtbl->GetAccessible(machine, &isAccessible);
        if (isAccessible) {

            machine->vtbl->GetId(machine, &iid);
            if (!iid)
                continue;
            vboxIIDToUUID(iidl, iid);
            vboxIIDUnalloc(iid);

            if (memcmp(uuid, iidl, VIR_UUID_BUFLEN) == 0) {

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

                ret = virGetDomain(conn, machineNameUtf8, iidl);
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
    for (i = 0; i < machineCnt; ++i)
        VBOX_RELEASE(machines[i]);

    return ret;
}

static virDomainPtr vboxDomainLookupByName(virConnectPtr conn, const char *name) {
    VBOX_OBJECT_CHECK(conn, virDomainPtr, NULL);
    IMachine **machines  = NULL;
    PRUint32 machineCnt  = 0;
    vboxIID *iid         = NULL;
    char      *machineNameUtf8  = NULL;
    PRUnichar *machineNameUtf16 = NULL;
    unsigned char iidl[VIR_UUID_BUFLEN];
    int i, matched = 0;
    nsresult rc;

    rc = data->vboxObj->vtbl->GetMachines(data->vboxObj, &machineCnt, &machines);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("Could not get list of machines, rc=%08x"), (unsigned)rc);
        return NULL;
    }

    for (i = 0; i < machineCnt; ++i) {
        IMachine *machine = machines[i];
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

                machine->vtbl->GetId(machine, &iid);
                vboxIIDToUUID(iidl, iid);
                vboxIIDUnalloc(iid);

                machine->vtbl->GetState(machine, &state);

                /* get a new domain pointer from virGetDomain, if it fails
                 * then no need to assign the id, else assign the id, cause
                 * it is -1 by default. rest is taken care by virGetDomain
                 * itself, so need not worry.
                 */

                ret = virGetDomain(conn, machineNameUtf8, iidl);
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

    /* Do the cleanup and take care you dont leak any memory */
    for (i = 0; i < machineCnt; ++i)
        VBOX_RELEASE(machines[i]);

    return ret;
}


static int vboxDomainIsActive(virDomainPtr dom) {
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    IMachine **machines  = NULL;
    PRUint32 machineCnt  = 0;
    vboxIID *iid         = NULL;
    char      *machineNameUtf8  = NULL;
    PRUnichar *machineNameUtf16 = NULL;
    unsigned char iidl[VIR_UUID_BUFLEN];
    int i, matched = 0;
    nsresult rc;

    rc = data->vboxObj->vtbl->GetMachines(data->vboxObj, &machineCnt, &machines);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("Could not get list of machines, rc=%08x"), (unsigned)rc);
        return ret;
    }

    for (i = 0; i < machineCnt; ++i) {
        IMachine *machine = machines[i];
        PRBool isAccessible = PR_FALSE;

        if (!machine)
            continue;

        machine->vtbl->GetAccessible(machine, &isAccessible);
        if (isAccessible) {

            machine->vtbl->GetId(machine, &iid);
            if (!iid)
                continue;
            vboxIIDToUUID(iidl, iid);
            vboxIIDUnalloc(iid);

            if (memcmp(dom->uuid, iidl, VIR_UUID_BUFLEN) == 0) {

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
    for (i = 0; i < machineCnt; ++i)
        VBOX_RELEASE(machines[i]);

    return ret;
}


static int vboxDomainIsPersistent(virDomainPtr dom ATTRIBUTE_UNUSED) {
    /* All domains are persistent. */
    return 1;
}


static int vboxDomainSuspend(virDomainPtr dom) {
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    IMachine *machine    = NULL;
    vboxIID  *iid        = NULL;
    IConsole *console    = NULL;
    PRBool isAccessible  = PR_FALSE;
    PRUint32 state;
    nsresult rc;

#if VBOX_API_VERSION == 2002
    if (VIR_ALLOC(iid) < 0) {
        virReportOOMError();
        goto cleanup;
    }
#endif

    vboxIIDFromUUID(dom->uuid, iid);
    rc = data->vboxObj->vtbl->GetMachine(data->vboxObj, iid, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INVALID_DOMAIN,
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
            data->vboxObj->vtbl->OpenExistingSession(data->vboxObj, data->vboxSession, iid);
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
            data->vboxSession->vtbl->Close(data->vboxSession);
        } else {
            vboxError(VIR_ERR_OPERATION_FAILED, "%s",
                      _("machine not in running state to suspend it"));
            goto cleanup;
        }
    }

cleanup:
    VBOX_RELEASE(machine);
    vboxIIDFree(iid);
    return ret;
}

static int vboxDomainResume(virDomainPtr dom) {
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    IMachine *machine    = NULL;
    vboxIID  *iid        = NULL;
    IConsole *console    = NULL;
    PRUint32 state       = MachineState_Null;
    nsresult rc;

#if VBOX_API_VERSION == 2002
    if (VIR_ALLOC(iid) < 0) {
        virReportOOMError();
        goto cleanup;
    }
#endif

    PRBool isAccessible = PR_FALSE;

    vboxIIDFromUUID(dom->uuid, iid);
    rc = data->vboxObj->vtbl->GetMachine(data->vboxObj, iid, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INVALID_DOMAIN,
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
            data->vboxObj->vtbl->OpenExistingSession(data->vboxObj, data->vboxSession, iid);
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
            data->vboxSession->vtbl->Close(data->vboxSession);
        } else {
            vboxError(VIR_ERR_OPERATION_FAILED, "%s",
                      _("machine not paused, so can't resume it"));
            goto cleanup;
        }
    }

cleanup:
    VBOX_RELEASE(machine);
    vboxIIDFree(iid);
    return ret;
}

static int vboxDomainShutdown(virDomainPtr dom) {
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    IMachine *machine    = NULL;
    vboxIID  *iid        = NULL;
    IConsole *console    = NULL;
    PRUint32 state       = MachineState_Null;
    PRBool isAccessible  = PR_FALSE;
    nsresult rc;

#if VBOX_API_VERSION == 2002
    if (VIR_ALLOC(iid) < 0) {
        virReportOOMError();
        goto cleanup;
    }
#endif

    vboxIIDFromUUID(dom->uuid, iid);
    rc = data->vboxObj->vtbl->GetMachine(data->vboxObj, iid, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INVALID_DOMAIN,
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

        data->vboxObj->vtbl->OpenExistingSession(data->vboxObj, data->vboxSession, iid);
        data->vboxSession->vtbl->GetConsole(data->vboxSession, &console);
        if (console) {
            console->vtbl->PowerButton(console);
            VBOX_RELEASE(console);
            ret = 0;
        }
        data->vboxSession->vtbl->Close(data->vboxSession);
    }

cleanup:
    VBOX_RELEASE(machine);
    vboxIIDFree(iid);
    return ret;
}

static int vboxDomainReboot(virDomainPtr dom, unsigned int flags ATTRIBUTE_UNUSED) {
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    IMachine *machine    = NULL;
    vboxIID  *iid        = NULL;
    IConsole *console    = NULL;
    PRUint32 state       = MachineState_Null;
    PRBool isAccessible  = PR_FALSE;
    nsresult rc;

#if VBOX_API_VERSION == 2002
    if (VIR_ALLOC(iid) < 0) {
        virReportOOMError();
        goto cleanup;
    }
#endif

    vboxIIDFromUUID(dom->uuid, iid);
    rc = data->vboxObj->vtbl->GetMachine(data->vboxObj, iid, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INVALID_DOMAIN,
                  _("no domain with matching id %d"), dom->id);
        goto cleanup;
    }

    if (!machine)
        goto cleanup;

    machine->vtbl->GetAccessible(machine, &isAccessible);
    if (isAccessible) {
        machine->vtbl->GetState(machine, &state);

        if (state == MachineState_Running) {
            data->vboxObj->vtbl->OpenExistingSession(data->vboxObj, data->vboxSession, iid);
            data->vboxSession->vtbl->GetConsole(data->vboxSession, &console);
            if (console) {
                console->vtbl->Reset(console);
                VBOX_RELEASE(console);
                ret = 0;
            }
            data->vboxSession->vtbl->Close(data->vboxSession);
        } else {
            vboxError(VIR_ERR_OPERATION_FAILED, "%s",
                      _("machine not running, so can't reboot it"));
            goto cleanup;
        }
    }

cleanup:
    VBOX_RELEASE(machine);
    vboxIIDFree(iid);
    return ret;
}

static int vboxDomainDestroy(virDomainPtr dom) {
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    IMachine *machine    = NULL;
    vboxIID  *iid        = NULL;
    IConsole *console    = NULL;
    PRUint32 state       = MachineState_Null;
    PRBool isAccessible  = PR_FALSE;
    nsresult rc;

#if VBOX_API_VERSION == 2002
    if (VIR_ALLOC(iid) < 0) {
        virReportOOMError();
        goto cleanup;
    }
#endif

    vboxIIDFromUUID(dom->uuid, iid);
    rc = data->vboxObj->vtbl->GetMachine(data->vboxObj, iid, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INVALID_DOMAIN,
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

        data->vboxObj->vtbl->OpenExistingSession(data->vboxObj, data->vboxSession, iid);
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
            ret = 0;
        }
        data->vboxSession->vtbl->Close(data->vboxSession);
    }

cleanup:
    VBOX_RELEASE(machine);
    vboxIIDFree(iid);
    return ret;
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
    vboxIID  *iid        = NULL;
    PRUint32 state       = MachineState_Null;
    PRBool isAccessible  = PR_FALSE;
    nsresult rc;

#if VBOX_API_VERSION == 2002
    if (VIR_ALLOC(iid) < 0) {
        virReportOOMError();
        goto cleanup;
    }
#endif

    vboxIIDFromUUID(dom->uuid, iid);
    rc = data->vboxObj->vtbl->GetMachine(data->vboxObj, iid, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INVALID_DOMAIN,
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

        rc = data->vboxObj->vtbl->OpenSession(data->vboxObj, data->vboxSession, iid);
        if (NS_SUCCEEDED(rc)) {
            rc = data->vboxSession->vtbl->GetMachine(data->vboxSession, &machine);
            if (NS_SUCCEEDED(rc) && machine) {

                rc = machine->vtbl->SetMemorySize(machine, memory / 1024);
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
            data->vboxSession->vtbl->Close(data->vboxSession);
        }
    }

cleanup:
    VBOX_RELEASE(machine);
    vboxIIDFree(iid);
    return ret;
}

static int vboxDomainGetInfo(virDomainPtr dom, virDomainInfoPtr info) {
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    IMachine **machines  = NULL;
    PRUint32 machineCnt  = 0;
    char *machineName    = NULL;
    PRUnichar *machineNameUtf16 = NULL;
    nsresult rc;
    int i = 0;

    rc = data->vboxObj->vtbl->GetMachines(data->vboxObj, &machineCnt, &machines);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("Could not get list of machines, rc=%08x"), (unsigned)rc);
        goto cleanup;
    }

    info->nrVirtCpu = 0;
    for (i = 0; i < machineCnt; ++i) {
        IMachine *machine = machines[i];
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
                * for time being set maxmem and memory to same
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

    /* Do the cleanup and take care you dont leak any memory */
    for (i = 0; i < machineCnt; ++i)
        VBOX_RELEASE(machines[i]);

cleanup:
    return ret;
}

static int vboxDomainSave(virDomainPtr dom, const char *path ATTRIBUTE_UNUSED) {
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    IConsole *console    = NULL;
    vboxIID  *iid        = NULL;
    nsresult rc;

    /* VirtualBox currently doesn't support saving to a file
     * at a location other then the machine folder and thus
     * setting path to ATTRIBUTE_UNUSED for now, will change
     * this behaviour once get the VirtualBox API in right
     * shape to do this
     */
#if VBOX_API_VERSION == 2002
    if (VIR_ALLOC(iid) < 0) {
        virReportOOMError();
        goto cleanup;
    }
#endif

    /* Open a Session for the machine */
    vboxIIDFromUUID(dom->uuid, iid);
    rc = data->vboxObj->vtbl->OpenExistingSession(data->vboxObj, data->vboxSession, iid);
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
        data->vboxSession->vtbl->Close(data->vboxSession);
    }

    DEBUGIID("UUID of machine being saved:", iid);

#if VBOX_API_VERSION == 2002
cleanup:
#endif
    vboxIIDFree(iid);
    return ret;
}

static int vboxDomainSetVcpus(virDomainPtr dom, unsigned int nvcpus) {
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    IMachine *machine    = NULL;
    vboxIID  *iid        = NULL;
    PRUint32  CPUCount   = nvcpus;
    nsresult rc;

#if VBOX_API_VERSION == 2002
    if (VIR_ALLOC(iid) < 0) {
        virReportOOMError();
        goto cleanup;
    }
#endif

    vboxIIDFromUUID(dom->uuid, iid);

    rc = data->vboxObj->vtbl->OpenSession(data->vboxObj, data->vboxSession, iid);
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
            vboxError(VIR_ERR_INVALID_DOMAIN,
                      _("no domain with matching id %d"), dom->id);
        }
    } else {
        vboxError(VIR_ERR_INVALID_DOMAIN,
                  _("can't open session to the domain with id %d"), dom->id);
    }
    data->vboxSession->vtbl->Close(data->vboxSession);

#if VBOX_API_VERSION == 2002
cleanup:
#endif
    vboxIIDFree(iid);
    return ret;
}

static int vboxDomainGetMaxVcpus(virDomainPtr dom) {
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    ISystemProperties *systemProperties = NULL;
    PRUint32 maxCPUCount = 0;

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

static char *vboxDomainDumpXML(virDomainPtr dom, int flags) {
    VBOX_OBJECT_CHECK(dom->conn, char *, NULL);
    virDomainDefPtr def  = NULL;
    IMachine *machine    = NULL;
    vboxIID  *iid        = NULL;
    int gotAllABoutDef   = -1;
    nsresult rc;

#if VBOX_API_VERSION == 2002
    if (VIR_ALLOC(iid) < 0) {
        virReportOOMError();
        goto cleanup;
    }
#endif

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    vboxIIDFromUUID(dom->uuid, iid);
    rc = data->vboxObj->vtbl->GetMachine(data->vboxObj, iid, &machine);
    if (NS_SUCCEEDED(rc) && machine) {
        PRBool accessible = PR_FALSE;

        machine->vtbl->GetAccessible(machine, &accessible);
        if (accessible) {
            int i = 0;
            struct utsname utsname;
            PRBool PAEEnabled                   = PR_FALSE;
            PRBool ACPIEnabled                  = PR_FALSE;
            PRBool IOAPICEnabled                = PR_FALSE;
            PRBool VRDPEnabled                  = PR_FALSE;
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
            PRUint32      mediumAttachSize      = 0;
            IMediumAttachment **mediumAttachments = NULL;
#endif /* VBOX_API_VERSION >= 3001 */
            IVRDPServer *VRDPServer             = NULL;
            IAudioAdapter *audioAdapter         = NULL;
            IUSBController *USBController       = NULL;
            ISystemProperties *systemProperties = NULL;


            def->virtType = VIR_DOMAIN_VIRT_VBOX;
            def->id = dom->id;
            memcpy(def->uuid, dom->uuid, VIR_UUID_BUFLEN);
            def->name = strdup(dom->name);

            machine->vtbl->GetMemorySize(machine, &memorySize);
            def->memory = memorySize * 1024;

            data->vboxObj->vtbl->GetSystemProperties(data->vboxObj, &systemProperties);
            if (systemProperties) {
                systemProperties->vtbl->GetMaxGuestRAM(systemProperties, &maxMemorySize);
                systemProperties->vtbl->GetMaxBootPosition(systemProperties, &maxBootPosition);
                systemProperties->vtbl->GetNetworkAdapterCount(systemProperties, &netAdpCnt);
                systemProperties->vtbl->GetSerialPortCount(systemProperties, &serialPortCount);
                systemProperties->vtbl->GetParallelPortCount(systemProperties, &parallelPortCount);
                VBOX_RELEASE(systemProperties);
                systemProperties = NULL;
            }
            /* Currently setting memory and maxMemory as same, cause
             * the notation here seems to be inconsistent while
             * reading and while dumping xml
             */
            /* def->maxmem = maxMemorySize * 1024; */
            def->maxmem = memorySize * 1024;

            machine->vtbl->GetCPUCount(machine, &CPUCount);
            def->vcpus = CPUCount;

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
                }
            }

            def->features = 0;
#if VBOX_API_VERSION < 3001
            machine->vtbl->GetPAEEnabled(machine, &PAEEnabled);
#else  /* VBOX_API_VERSION >= 3001 */
            machine->vtbl->GetCpuProperty(machine, CpuPropertyType_PAE, &PAEEnabled);
#endif /* VBOX_API_VERSION >= 3001 */
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
                        PRUint32 VRAMSize          = 8 * 1024;
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
                        def->videos[0]->vram            = VRAMSize;
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
                        def->graphics[def->ngraphics]->data.desktop.display = strdup(getenv("DISPLAY"));
                        if (def->graphics[def->ngraphics]->data.desktop.display == NULL) {
                            virReportOOMError();
                            /* just don't go to cleanup yet as it is ok to have
                             * display as NULL
                             */
                        }
                        totalPresent++;
                        def->ngraphics++;
                    }
                }

                machine->vtbl->GetVRDPServer(machine, &VRDPServer);
                if (VRDPServer) {
                    VRDPServer->vtbl->GetEnabled(VRDPServer, &VRDPEnabled);
                    if (VRDPEnabled) {

                        totalPresent++;

                        if ((VIR_REALLOC_N(def->graphics, totalPresent) >= 0) &&
                            (VIR_ALLOC(def->graphics[def->ngraphics]) >= 0)) {
                            PRUnichar *netAddressUtf16   = NULL;
                            char      *netAddressUtf8    = NULL;
                            PRBool allowMultiConnection  = PR_FALSE;
                            PRBool reuseSingleConnection = PR_FALSE;
#if VBOX_API_VERSION < 3001
                            PRUint32 VRDPport = 0;
                            VRDPServer->vtbl->GetPort(VRDPServer, &VRDPport);
                            if (VRDPport) {
                                def->graphics[def->ngraphics]->data.rdp.port = VRDPport;
#else  /* VBOX_API_VERSION >= 3001 */
                            PRUnichar *VRDPport = NULL;
                            VRDPServer->vtbl->GetPorts(VRDPServer, &VRDPport);
                            if (VRDPport) {
                                /* even if vbox supports mutilpe ports, single port for now here */
                                def->graphics[def->ngraphics]->data.rdp.port = PRUnicharToInt(VRDPport);
                                VBOX_UTF16_FREE(VRDPport);
#endif /* VBOX_API_VERSION >= 3001 */
                            } else {
                                def->graphics[def->ngraphics]->data.rdp.autoport = 1;
                            }

                            def->graphics[def->ngraphics]->type = VIR_DOMAIN_GRAPHICS_TYPE_RDP;

                            VRDPServer->vtbl->GetNetAddress(VRDPServer, &netAddressUtf16);
                            if (netAddressUtf16) {
                                VBOX_UTF16_TO_UTF8(netAddressUtf16, &netAddressUtf8);
                                if (STRNEQ(netAddressUtf8, ""))
                                        def->graphics[def->ngraphics]->data.rdp.listenAddr = strdup(netAddressUtf8);
                                VBOX_UTF16_FREE(netAddressUtf16);
                                VBOX_UTF8_FREE(netAddressUtf8);
                            }

                            VRDPServer->vtbl->GetAllowMultiConnection(VRDPServer, &allowMultiConnection);
                            if (allowMultiConnection) {
                                def->graphics[def->ngraphics]->data.rdp.multiUser = 1;
                            }

                            VRDPServer->vtbl->GetReuseSingleConnection(VRDPServer, &reuseSingleConnection);
                            if (reuseSingleConnection) {
                                def->graphics[def->ngraphics]->data.rdp.replaceUser = 1;
                            }

                            def->ngraphics++;
                        } else
                            virReportOOMError();
                    }
                    VBOX_RELEASE(VRDPServer);
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
            machine->vtbl->GetMediumAttachments(machine, &mediumAttachSize, &mediumAttachments);

            /* get the number of attachments */
            for (i = 0; i < mediumAttachSize; i++) {
                IMediumAttachment *imediumattach = mediumAttachments[i];
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
            for (i = 0; i < mediumAttachSize && diskCount < def->ndisks && !error; i++) {
                IMediumAttachment *imediumattach = mediumAttachments[i];
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

            /* free the memory */
            for (i = 0; i < mediumAttachSize; i++)
                VBOX_RELEASE(mediumAttachments[i]);

            /* cleanup on error */
            if (error) {
                for (i = 0; i < def->ndisks; i++) {
                    VIR_FREE(def->disks[i]);
                }
                VIR_FREE(def->disks);
                def->ndisks = 0;
            }

#endif /* VBOX_API_VERSION >= 3001 */

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

                            adapter->vtbl->GetHostInterface(adapter, &hostIntUtf16);

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

                            adapter->vtbl->GetHostInterface(adapter, &hostIntUtf16);

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
                        if (virParseMacAddr(macaddr, def->nets[netAdpIncCnt]->mac) < 0)
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
                            def->serials[serialPortIncCount]->type = VIR_DOMAIN_CHR_TYPE_PIPE;
                        } else if (hostMode == PortMode_HostDevice) {
                            def->serials[serialPortIncCount]->type = VIR_DOMAIN_CHR_TYPE_DEV;
#if VBOX_API_VERSION >= 3000
                        } else if (hostMode == PortMode_RawFile) {
                            def->serials[serialPortIncCount]->type = VIR_DOMAIN_CHR_TYPE_FILE;
#endif /* VBOX_API_VERSION >= 3000 */
                        } else {
                            def->serials[serialPortIncCount]->type = VIR_DOMAIN_CHR_TYPE_NULL;
                        }

                        def->serials[serialPortIncCount]->targetType = VIR_DOMAIN_CHR_TARGET_TYPE_SERIAL;

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
                            def->serials[serialPortIncCount]->data.file.path = strdup(path);
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

                        def->parallels[parallelPortIncCount]->type = VIR_DOMAIN_CHR_TYPE_FILE;
                        def->parallels[parallelPortIncCount]->targetType = VIR_DOMAIN_CHR_TARGET_TYPE_PARALLEL;

                        parallelPort->vtbl->GetPath(parallelPort, &pathUtf16);

                        VBOX_UTF16_TO_UTF8(pathUtf16, &path);
                        def->parallels[parallelPortIncCount]->data.file.path = strdup(path);

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
                    PRUint32 deviceFiltersNum        = 0;
                    IUSBDeviceFilter **deviceFilters = NULL;

                    USBController->vtbl->GetDeviceFilters(USBController,
                                                          &deviceFiltersNum,
                                                          &deviceFilters);

                    if (deviceFiltersNum > 0) {

                        /* check if the filters are active and then only
                         * alloc mem and set def->nhostdevs
                         */

                        for(i = 0; i < deviceFiltersNum; i++) {
                            PRBool active = PR_FALSE;

                            deviceFilters[i]->vtbl->GetActive(deviceFilters[i], &active);
                            if (active) {
                                def->nhostdevs++;
                            }
                        }

                        if (def->nhostdevs > 0) {
                            /* Alloc mem needed for the filters now */
                            if (VIR_ALLOC_N(def->hostdevs, def->nhostdevs) >= 0) {

                                for(i = 0; (USBFilterCount < def->nhostdevs) || (i < deviceFiltersNum); i++) {
                                    PRBool active = PR_FALSE;

                                    deviceFilters[i]->vtbl->GetActive(deviceFilters[i], &active);
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

                                            deviceFilters[i]->vtbl->GetVendorId(deviceFilters[i], &vendorIdUtf16);
                                            deviceFilters[i]->vtbl->GetProductId(deviceFilters[i], &productIdUtf16);

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
                    for(i = 0; i < deviceFiltersNum; i++)
                        VBOX_RELEASE(deviceFilters[i]);
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
    vboxIIDFree(iid);
    virDomainDefFree(def);
    return ret;
}

static int vboxListDefinedDomains(virConnectPtr conn, char ** const names, int maxnames) {
    VBOX_OBJECT_CHECK(conn, int, -1);
    IMachine **machines  = NULL;
    PRUint32 machineCnt  = 0;
    char *machineName    = NULL;
    PRUnichar *machineNameUtf16 = NULL;
    PRUint32 state;
    nsresult rc;
    int i, j;

    rc = data->vboxObj->vtbl->GetMachines(data->vboxObj, &machineCnt, &machines);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("Could not get list of Defined Domains, rc=%08x"),
                  (unsigned)rc);
        goto cleanup;
    }

    if (machineCnt == 0) {
        ret = 0;
        goto cleanup;
    }

    for (i = 0,j = 0; (i < machineCnt) && (j < maxnames); i++) {
        IMachine *machine = machines[i];

        if (machine) {
            PRBool isAccessible = PR_FALSE;
            machine->vtbl->GetAccessible(machine, &isAccessible);
            if (isAccessible) {
                machine->vtbl->GetState(machine, &state);
                if (   (state < MachineState_FirstOnline)
                    || (state > MachineState_LastOnline) ) {
                    machine->vtbl->GetName(machine, &machineNameUtf16);
                    VBOX_UTF16_TO_UTF8(machineNameUtf16, &machineName);
                    if (!(names[j++] = strdup(machineName))) {
                        virReportOOMError();
                        for ( ; j >= 0 ; j--)
                            VIR_FREE(names[j]);
                        ret = -1;
                        goto cleanup;
                    }
                    ret++;
                }
            }
        }
    }
    ret++;

cleanup:
    VBOX_UTF8_FREE(machineName);
    VBOX_UTF16_FREE(machineNameUtf16);
    for (i = 0; i < machineCnt; ++i)
        VBOX_RELEASE(machines[i]);
    return ret;
}

static int vboxNumOfDefinedDomains(virConnectPtr conn) {
    VBOX_OBJECT_CHECK(conn, int, -1);
    IMachine **machines  = NULL;
    PRUint32 machineCnt  = 0;
    PRUint32 state       = MachineState_Null;
    nsresult rc;
    int i;

    rc = data->vboxObj->vtbl->GetMachines(data->vboxObj, &machineCnt, &machines);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("Could not get number of Defined Domains, rc=%08x"),
                  (unsigned)rc);
        goto cleanup;
    }

    if (machineCnt == 0) {
        ret = 0;
        goto cleanup;
    }

    /* Do the cleanup as required by GetMachines() */
    for (i = 0; i < machineCnt; ++i) {
        IMachine *machine = machines[i];

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
    ret++;

cleanup:
    for (i = 0; i < machineCnt; ++i)
        VBOX_RELEASE(machines[i]);
    return ret;
}

static int vboxDomainCreate(virDomainPtr dom) {
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    IMachine **machines    = NULL;
    IProgress *progress    = NULL;
    PRUint32 machineCnt    = 0;
    PRUnichar *env         = NULL;
    PRUnichar *sessionType = NULL;
    char displayutf8[32]   = {0};
    unsigned char iidl[VIR_UUID_BUFLEN] = {0};
    nsresult rc;
    int i = 0;

    if (!dom->name) {
        vboxError(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("Error while reading the domain name"));
        goto cleanup;
    }

    rc = data->vboxObj->vtbl->GetMachines(data->vboxObj, &machineCnt, &machines);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("Could not get list of machines, rc=%08x"), (unsigned)rc);
        goto cleanup;
    }

    for (i = 0; i < machineCnt; ++i) {
        IMachine *machine = machines[i];
        PRBool isAccessible = PR_FALSE;

        if (!machine)
            continue;

        machine->vtbl->GetAccessible(machine, &isAccessible);
        if (isAccessible) {
            vboxIID *iid = NULL;

            machine->vtbl->GetId(machine, &iid);
            if (!iid)
                continue;
            vboxIIDToUUID(iidl, iid);

            if (memcmp(dom->uuid, iidl, VIR_UUID_BUFLEN) == 0) {
                PRUint32 state = MachineState_Null;
                machine->vtbl->GetState(machine, &state);

                if ( (state == MachineState_PoweredOff) ||
                     (state == MachineState_Saved) ||
                     (state == MachineState_Aborted) ) {
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

                    VBOX_UTF8_TO_UTF16("FRONTEND/Type", &keyTypeUtf16);
                    machine->vtbl->GetExtraData(machine, keyTypeUtf16, &valueTypeUtf16);
                    VBOX_UTF16_FREE(keyTypeUtf16);

                    if (valueTypeUtf16) {
                        VBOX_UTF16_TO_UTF8(valueTypeUtf16, &valueTypeUtf8);
                        VBOX_UTF16_FREE(valueTypeUtf16);

                        if ( STREQ(valueTypeUtf8, "sdl") || STREQ(valueTypeUtf8, "gui") ) {

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
                            sprintf(displayutf8, "DISPLAY=%.24s", guiDisplay);
                            VBOX_UTF8_TO_UTF16(displayutf8, &env);
                            VIR_FREE(guiDisplay);
                        }

                        VBOX_UTF8_TO_UTF16("gui", &sessionType);
                    }

                    if (sdlPresent) {
                        if (sdlDisplay) {
                            sprintf(displayutf8, "DISPLAY=%.24s", sdlDisplay);
                            VBOX_UTF8_TO_UTF16(displayutf8, &env);
                            VIR_FREE(sdlDisplay);
                        }

                        VBOX_UTF8_TO_UTF16("sdl", &sessionType);
                    }

                    if (vrdpPresent) {
                        VBOX_UTF8_TO_UTF16("vrdp", &sessionType);
                    }

                    rc = data->vboxObj->vtbl->OpenRemoteSession(data->vboxObj,
                                                                data->vboxSession,
                                                                iid,
                                                                sessionType,
                                                                env,
                                                                &progress );
                    if (NS_FAILED(rc)) {
                        vboxError(VIR_ERR_OPERATION_FAILED, "%s",
                                  _("openremotesession failed, domain can't be started"));
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

                    data->vboxSession->vtbl->Close(data->vboxSession);

                } else {
                    vboxError(VIR_ERR_OPERATION_FAILED, "%s",
                              _("machine is not in poweroff|saved|"
                                "aborted state, so couldn't start it"));
                    ret = -1;
                }
            }
            vboxIIDUnalloc(iid);
            if (ret != -1)
                break;
        }
    }

    /* Do the cleanup and take care you dont leak any memory */
    for (i = 0; i < machineCnt; ++i)
        VBOX_RELEASE(machines[i]);

    VBOX_UTF16_FREE(env);
    VBOX_UTF16_FREE(sessionType);

cleanup:
    return ret;
}

static virDomainPtr vboxDomainDefineXML(virConnectPtr conn, const char *xml) {
    VBOX_OBJECT_CHECK(conn, virDomainPtr, NULL);
    IMachine       *machine     = NULL;
    IBIOSSettings  *bios        = NULL;
    vboxIID        *iid         = NULL;
    vboxIID        *mchiid      = NULL;
    virDomainDefPtr def         = NULL;
    PRUnichar *machineNameUtf16 = NULL;
    nsresult rc;

    if (!(def = virDomainDefParseString(data->caps, xml,
                                        VIR_DOMAIN_XML_INACTIVE))) {
        goto cleanup;
    }

#if VBOX_API_VERSION == 2002
    if (VIR_ALLOC(iid) < 0) {
        virReportOOMError();
        goto cleanup;
    }
#endif

    VBOX_UTF8_TO_UTF16(def->name, &machineNameUtf16);
    vboxIIDFromUUID(def->uuid, iid);
    rc = data->vboxObj->vtbl->CreateMachine(data->vboxObj,
                                            machineNameUtf16,
                                            NULL,
                                            NULL,
                                            iid,
                                            &machine);
    VBOX_UTF16_FREE(machineNameUtf16);

    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("could not define a domain, rc=%08x"), (unsigned)rc);
        goto cleanup;
    }

    rc = machine->vtbl->SetMemorySize(machine, def->memory / 1024);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("could not set the memory size of the domain to: %lu Kb, "
                    "rc=%08x"),
                  def->memory, (unsigned)rc);
    }

    rc = machine->vtbl->SetCPUCount(machine, def->vcpus);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("could not set the number of virtual CPUs to: %lu, rc=%08x"),
                  def->vcpus, (unsigned)rc);
    }

#if VBOX_API_VERSION < 3001
    rc = machine->vtbl->SetPAEEnabled(machine, (def->features) &
                                      (1 << VIR_DOMAIN_FEATURE_PAE));
#else  /* VBOX_API_VERSION >= 3001 */
    rc = machine->vtbl->SetCpuProperty(machine, CpuPropertyType_PAE,
                                       (def->features) &
                                       (1 << VIR_DOMAIN_FEATURE_PAE));
#endif /* VBOX_API_VERSION >= 3001 */
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
    machine->vtbl->GetId(machine, &mchiid);
    data->vboxObj->vtbl->OpenSession(data->vboxObj, data->vboxSession, mchiid);
    data->vboxSession->vtbl->GetMachine(data->vboxSession, &machine);

    {   /* Started:Block to set the boot device order */
        ISystemProperties *systemProperties = NULL;
        PRUint32 maxBootPosition            = 0;
        int i = 0;

        DEBUG("def->os.type             %s", def->os.type);
        DEBUG("def->os.arch             %s", def->os.arch);
        DEBUG("def->os.machine          %s", def->os.machine);
        DEBUG("def->os.nBootDevs        %d", def->os.nBootDevs);
        DEBUG("def->os.bootDevs[0]      %d", def->os.bootDevs[0]);
        DEBUG("def->os.bootDevs[1]      %d", def->os.bootDevs[1]);
        DEBUG("def->os.bootDevs[2]      %d", def->os.bootDevs[2]);
        DEBUG("def->os.bootDevs[3]      %d", def->os.bootDevs[3]);
        DEBUG("def->os.init             %s", def->os.init);
        DEBUG("def->os.kernel           %s", def->os.kernel);
        DEBUG("def->os.initrd           %s", def->os.initrd);
        DEBUG("def->os.cmdline          %s", def->os.cmdline);
        DEBUG("def->os.root             %s", def->os.root);
        DEBUG("def->os.loader           %s", def->os.loader);
        DEBUG("def->os.bootloader       %s", def->os.bootloader);
        DEBUG("def->os.bootloaderArgs   %s", def->os.bootloaderArgs);

        data->vboxObj->vtbl->GetSystemProperties(data->vboxObj, &systemProperties);
        if (systemProperties) {
            systemProperties->vtbl->GetMaxBootPosition(systemProperties, &maxBootPosition);
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
    }   /* Finished:Block to set the boot device order */

#if VBOX_API_VERSION < 3001
    {   /* Started:Block to attach the CDROM/DVD Drive and HardDisks to the VM */

        if (def->ndisks > 0) {
            int i;

            for (i = 0; i < def->ndisks; i++) {
                DEBUG("disk(%d) type:       %d", i, def->disks[i]->type);
                DEBUG("disk(%d) device:     %d", i, def->disks[i]->device);
                DEBUG("disk(%d) bus:        %d", i, def->disks[i]->bus);
                DEBUG("disk(%d) src:        %s", i, def->disks[i]->src);
                DEBUG("disk(%d) dst:        %s", i, def->disks[i]->dst);
                DEBUG("disk(%d) driverName: %s", i, def->disks[i]->driverName);
                DEBUG("disk(%d) driverType: %s", i, def->disks[i]->driverType);
                DEBUG("disk(%d) cachemode:  %d", i, def->disks[i]->cachemode);
                DEBUG("disk(%d) readonly:   %s", i, def->disks[i]->readonly ? "True" : "False");
                DEBUG("disk(%d) shared:     %s", i, def->disks[i]->shared ? "True" : "False");

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
                            vboxIID *dvduuid             = NULL;
# if VBOX_API_VERSION == 2002
                            nsID dvdemptyuuid;

                            memset(&dvdemptyuuid, 0, sizeof(dvdemptyuuid));
# else
                            PRUnichar *dvdemptyuuidUtf16 = NULL;
# endif

                            VBOX_UTF8_TO_UTF16(def->disks[i]->src, &dvdfileUtf16);

                            data->vboxObj->vtbl->FindDVDImage(data->vboxObj, dvdfileUtf16, &dvdImage);
                            if (!dvdImage) {
# if VBOX_API_VERSION == 2002
                                data->vboxObj->vtbl->OpenDVDImage(data->vboxObj, dvdfileUtf16, &dvdemptyuuid, &dvdImage);
# else
                                data->vboxObj->vtbl->OpenDVDImage(data->vboxObj, dvdfileUtf16, dvdemptyuuidUtf16, &dvdImage);
# endif
                            }
                            if (dvdImage) {
                                rc = dvdImage->vtbl->imedium.GetId((IMedium *)dvdImage, &dvduuid);
                                if (NS_FAILED(rc)) {
                                    vboxError(VIR_ERR_INTERNAL_ERROR,
                                              _("can't get the uuid of the file to "
                                                "be attached to cdrom: %s, rc=%08x"),
                                              def->disks[i]->src, (unsigned)rc);
                                } else {
                                    rc = dvdDrive->vtbl->MountImage(dvdDrive, dvduuid);
                                    if (NS_FAILED(rc)) {
                                        vboxError(VIR_ERR_INTERNAL_ERROR,
                                                  _("could not attach the file to cdrom: %s, rc=%08x"),
                                                  def->disks[i]->src, (unsigned)rc);
                                    } else {
                                        DEBUGIID("CD/DVDImage UUID:", dvduuid);
                                    }
                                }

                                VBOX_MEDIUM_RELEASE(dvdImage);
                            }
                            vboxIIDUnalloc(dvduuid);
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
                        vboxIID   *hdduuid      = NULL;
                        PRUnichar *hddEmpty     = NULL;
                        /* Current Limitation: Harddisk can't be connected to
                         * Secondary Master as Secondary Master is always used
                         * for CD/DVD Drive, so don't connect the harddisk if it
                         * is requested to be connected to Secondary master
                         */

                        VBOX_UTF8_TO_UTF16(def->disks[i]->src, &hddfileUtf16);
                        VBOX_UTF8_TO_UTF16("", &hddEmpty);

                        data->vboxObj->vtbl->FindHardDisk(data->vboxObj, hddfileUtf16, &hardDisk);

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
                            rc = hardDisk->vtbl->imedium.GetId((IMedium *)hardDisk, &hdduuid);
                            if (NS_FAILED(rc)) {
                                vboxError(VIR_ERR_INTERNAL_ERROR,
                                          _("can't get the uuid of the file to be "
                                            "attached as harddisk: %s, rc=%08x"),
                                          def->disks[i]->src, (unsigned)rc);
                            } else {
                                if (def->disks[i]->readonly) {
                                    hardDisk->vtbl->SetType(hardDisk, HardDiskType_Immutable);
                                    DEBUG0("setting harddisk to readonly");
                                } else if (!def->disks[i]->readonly) {
                                    hardDisk->vtbl->SetType(hardDisk, HardDiskType_Normal);
                                    DEBUG0("setting harddisk type to normal");
                                }
                                if (def->disks[i]->bus == VIR_DOMAIN_DISK_BUS_IDE) {
                                    if (STREQ(def->disks[i]->dst, "hdc")) {
                                        DEBUG0("Not connecting harddisk to hdc as hdc"
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
                                                                           hdduuid,
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
                                            DEBUGIID("Attached HDD with UUID", hdduuid);
                                        }
                                    }
                                }
                            }
                            VBOX_MEDIUM_RELEASE(hardDisk);
                        }
                        vboxIIDUnalloc(hdduuid);
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
                                vboxIID *fduuid             = NULL;
# if VBOX_API_VERSION == 2002
                                nsID fdemptyuuid;

                                memset(&fdemptyuuid, 0, sizeof(fdemptyuuid));
# else
                                PRUnichar *fdemptyuuidUtf16 = NULL;
# endif

                                VBOX_UTF8_TO_UTF16(def->disks[i]->src, &fdfileUtf16);
                                rc = data->vboxObj->vtbl->FindFloppyImage(data->vboxObj,
                                                                          fdfileUtf16,
                                                                          &floppyImage);

                                if (!floppyImage) {
                                    data->vboxObj->vtbl->OpenFloppyImage(data->vboxObj,
                                                                         fdfileUtf16,
# if VBOX_API_VERSION == 2002
                                                                         &fdemptyuuid,
# else
                                                                         fdemptyuuidUtf16,
# endif
                                                                         &floppyImage);
                                }

                                if (floppyImage) {
                                    rc = floppyImage->vtbl->imedium.GetId((IMedium *)floppyImage, &fduuid);
                                    if (NS_FAILED(rc)) {
                                        vboxError(VIR_ERR_INTERNAL_ERROR,
                                                  _("can't get the uuid of the file to "
                                                    "be attached to floppy drive: %s, rc=%08x"),
                                                  def->disks[i]->src, (unsigned)rc);
                                    } else {
                                        rc = floppyDrive->vtbl->MountImage(floppyDrive, fduuid);
                                        if (NS_FAILED(rc)) {
                                            vboxError(VIR_ERR_INTERNAL_ERROR,
                                                      _("could not attach the file to "
                                                        "floppy drive: %s, rc=%08x"),
                                                      def->disks[i]->src, (unsigned)rc);
                                        } else {
                                            DEBUGIID("floppyImage UUID", fduuid);
                                        }
                                    }
                                    VBOX_MEDIUM_RELEASE(floppyImage);
                                }
                                vboxIIDUnalloc(fduuid);
                                VBOX_UTF16_FREE(fdfileUtf16);
                            }
                            VBOX_RELEASE(floppyDrive);
                        }
                    } else if (def->disks[i]->type == VIR_DOMAIN_DISK_TYPE_BLOCK) {
                    }
                }
            }
        }

    }   /* Finished:Block to attach the CDROM/DVD Drive and HardDisks to the VM */

#else  /* VBOX_API_VERSION >= 3001 */
    {
        PRUint32 maxPortPerInst[StorageBus_Floppy + 1] = {};
        PRUint32 maxSlotPerPort[StorageBus_Floppy + 1] = {};
        PRUnichar *storageCtlName = NULL;
        bool error = false;
        int i = 0;

        /* get the max port/slots/etc for the given storage bus */
        error = !vboxGetMaxPortSlotValues(data->vboxObj, maxPortPerInst, maxSlotPerPort);

        /* add a storage controller for the mediums to be attached */
        /* this needs to change when multiple controller are supported for ver > 3.1 */
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

        /* Started:Block to attach the CDROM/DVD Drive and HardDisks to the VM */
        for (i = 0; i < def->ndisks && !error; i++) {
            DEBUG("disk(%d) type:       %d", i, def->disks[i]->type);
            DEBUG("disk(%d) device:     %d", i, def->disks[i]->device);
            DEBUG("disk(%d) bus:        %d", i, def->disks[i]->bus);
            DEBUG("disk(%d) src:        %s", i, def->disks[i]->src);
            DEBUG("disk(%d) dst:        %s", i, def->disks[i]->dst);
            DEBUG("disk(%d) driverName: %s", i, def->disks[i]->driverName);
            DEBUG("disk(%d) driverType: %s", i, def->disks[i]->driverType);
            DEBUG("disk(%d) cachemode:  %d", i, def->disks[i]->cachemode);
            DEBUG("disk(%d) readonly:   %s", i, def->disks[i]->readonly ? "True" : "False");
            DEBUG("disk(%d) shared:     %s", i, def->disks[i]->shared ? "True" : "False");

            if (def->disks[i]->type == VIR_DOMAIN_DISK_TYPE_FILE &&
                def->disks[i]->src != NULL) {
                IMedium   *medium          = NULL;
                PRUnichar *mediumUUID      = NULL;
                PRUnichar *mediumFileUtf16 = NULL;
                PRUint32   storageBus      = StorageBus_Null;
                PRUint32   deviceType      = DeviceType_Null;
                PRInt32    deviceInst      = 0;
                PRInt32    devicePort      = 0;
                PRInt32    deviceSlot      = 0;

                VBOX_UTF8_TO_UTF16(def->disks[i]->src, &mediumFileUtf16);

                if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
                    deviceType = DeviceType_HardDisk;
                    data->vboxObj->vtbl->FindHardDisk(data->vboxObj, mediumFileUtf16, &medium);
                } else if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
                    deviceType = DeviceType_DVD;
                    data->vboxObj->vtbl->FindDVDImage(data->vboxObj, mediumFileUtf16, &medium);
                } else if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
                    deviceType = DeviceType_Floppy;
                    data->vboxObj->vtbl->FindFloppyImage(data->vboxObj, mediumFileUtf16, &medium);
                } else {
                    VBOX_UTF16_FREE(mediumFileUtf16);
                    continue;
                }

                if (!medium) {
                    PRUnichar *mediumEmpty = NULL;

                    VBOX_UTF8_TO_UTF16("", &mediumEmpty);

                    if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
                        data->vboxObj->vtbl->OpenHardDisk(data->vboxObj,
                                                          mediumFileUtf16,
                                                          AccessMode_ReadWrite,
                                                          false,
                                                          mediumEmpty,
                                                          false,
                                                          mediumEmpty,
                                                          &medium);
                    } else if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
                        data->vboxObj->vtbl->OpenDVDImage(data->vboxObj,
                                                          mediumFileUtf16,
                                                          mediumEmpty,
                                                          &medium);
                    } else if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
                        data->vboxObj->vtbl->OpenFloppyImage(data->vboxObj,
                                                             mediumFileUtf16,
                                                             mediumEmpty,
                                                             &medium);
                    }

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
                        DEBUG0("setting harddisk to immutable");
                    } else if (!def->disks[i]->readonly) {
                        medium->vtbl->SetType(medium, MediumType_Normal);
                        DEBUG0("setting harddisk type to normal");
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
                                                 mediumUUID);

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
    }
    /* Finished:Block to attach the CDROM/DVD Drive and HardDisks to the VM */
#endif /* VBOX_API_VERSION >= 3001 */

    {   /* Started:Block to attach the Sound Controller to the VM */
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
                        audioAdapter->vtbl->SetAudioController(audioAdapter, AudioControllerType_SB16);
                    } else if (def->sounds[0]->model == VIR_DOMAIN_SOUND_MODEL_AC97) {
                        audioAdapter->vtbl->SetAudioController(audioAdapter, AudioControllerType_AC97);
                    }
                }
                VBOX_RELEASE(audioAdapter);
            }
        }
    }   /* Finished:Block to attach the Sound Controller to the VM */

    {   /* Started:Block to attach the Network Card to the VM */
        ISystemProperties *systemProperties = NULL;
        PRUint32 networkAdapterCount        = 0;
        int i = 0;

        data->vboxObj->vtbl->GetSystemProperties(data->vboxObj, &systemProperties);
        if (systemProperties) {
            systemProperties->vtbl->GetNetworkAdapterCount(systemProperties, &networkAdapterCount);
            VBOX_RELEASE(systemProperties);
            systemProperties = NULL;
        }

        DEBUG("Number of Network Cards to be connected: %d", def->nnets);
        DEBUG("Number of Network Cards available: %d", networkAdapterCount);

        for (i = 0; (i < def->nnets) && (i < networkAdapterCount); i++) {
            INetworkAdapter *adapter = NULL;
            PRUint32 adapterType     = NetworkAdapterType_Null;
            char macaddr[VIR_MAC_STRING_BUFLEN] = {0};
            char macaddrvbox[VIR_MAC_STRING_BUFLEN - 5] = {0};

            virFormatMacAddr(def->nets[i]->mac, macaddr);
            snprintf(macaddrvbox, VIR_MAC_STRING_BUFLEN - 5,
                     "%02X%02X%02X%02X%02X%02X",
                     def->nets[i]->mac[0],
                     def->nets[i]->mac[1],
                     def->nets[i]->mac[2],
                     def->nets[i]->mac[3],
                     def->nets[i]->mac[4],
                     def->nets[i]->mac[5]);
            macaddrvbox[VIR_MAC_STRING_BUFLEN - 6] = '\0';

            DEBUG("NIC(%d): Type:   %d", i, def->nets[i]->type);
            DEBUG("NIC(%d): Model:  %s", i, def->nets[i]->model);
            DEBUG("NIC(%d): Mac:    %s", i, macaddr);
            DEBUG("NIC(%d): ifname: %s", i, def->nets[i]->ifname);
            if (def->nets[i]->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
                DEBUG("NIC(%d): name:    %s", i, def->nets[i]->data.network.name);
            } else if (def->nets[i]->type == VIR_DOMAIN_NET_TYPE_INTERNAL) {
                DEBUG("NIC(%d): name:   %s", i, def->nets[i]->data.internal.name);
            } else if (def->nets[i]->type == VIR_DOMAIN_NET_TYPE_USER) {
                DEBUG("NIC(%d): NAT.", i);
            } else if (def->nets[i]->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {
                DEBUG("NIC(%d): brname: %s", i, def->nets[i]->data.bridge.brname);
                DEBUG("NIC(%d): script: %s", i, def->nets[i]->data.bridge.script);
                DEBUG("NIC(%d): ipaddr: %s", i, def->nets[i]->data.bridge.ipaddr);
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

                    adapter->vtbl->AttachToBridgedInterface(adapter);

                    if (def->nets[i]->data.bridge.brname) {
                        VBOX_UTF8_TO_UTF16(def->nets[i]->data.bridge.brname, &hostInterface);
                        adapter->vtbl->SetHostInterface(adapter, hostInterface);
                        VBOX_UTF16_FREE(hostInterface);
                    }
                } else if (def->nets[i]->type == VIR_DOMAIN_NET_TYPE_INTERNAL) {
                    PRUnichar *internalNetwork = NULL;
                    /* Internal Network */

                    adapter->vtbl->AttachToInternalNetwork(adapter);

                    if (def->nets[i]->data.internal.name) {
                        VBOX_UTF8_TO_UTF16(def->nets[i]->data.internal.name, &internalNetwork);
                        adapter->vtbl->SetInternalNetwork(adapter, internalNetwork);
                        VBOX_UTF16_FREE(internalNetwork);
                    }
                } else if (def->nets[i]->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
                    PRUnichar *hostInterface = NULL;
                    /* Host Only Networking (currently only vboxnet0 available
                     * on *nix and mac, on windows you can create and configure
                     * as many as you want)
                     */
                    adapter->vtbl->AttachToHostOnlyInterface(adapter);

                    if (def->nets[i]->data.network.name) {
                        VBOX_UTF8_TO_UTF16(def->nets[i]->data.network.name, &hostInterface);
                        adapter->vtbl->SetHostInterface(adapter, hostInterface);
                        VBOX_UTF16_FREE(hostInterface);
                    }
                } else if (def->nets[i]->type == VIR_DOMAIN_NET_TYPE_USER) {
                    /* NAT */
                    adapter->vtbl->AttachToNAT(adapter);
                } else {
                    /* else always default to NAT if we don't understand
                     * what option is been passed to us
                     */
                    adapter->vtbl->AttachToNAT(adapter);
                }

                VBOX_UTF8_TO_UTF16(macaddrvbox, &MACAddress);
                adapter->vtbl->SetMACAddress(adapter, MACAddress);
                VBOX_UTF16_FREE(MACAddress);
            }
        }
    }   /* Finished:Block to attach the Network Card to the VM */

    {   /* Started:Block to attach the Serial Port to the VM */
        ISystemProperties *systemProperties = NULL;
        PRUint32 serialPortCount            = 0;
        int i = 0;

        data->vboxObj->vtbl->GetSystemProperties(data->vboxObj, &systemProperties);
        if (systemProperties) {
            systemProperties->vtbl->GetSerialPortCount(systemProperties, &serialPortCount);
            VBOX_RELEASE(systemProperties);
            systemProperties = NULL;
        }

        DEBUG("Number of Serial Ports to be connected: %d", def->nserials);
        DEBUG("Number of Serial Ports available: %d", serialPortCount);
        for (i = 0; (i < def->nserials) && (i < serialPortCount); i++) {
            ISerialPort *serialPort = NULL;

            DEBUG("SerialPort(%d): Type: %d", i, def->serials[i]->type);
            DEBUG("SerialPort(%d): target.port: %d", i, def->serials[i]->target.port);

            machine->vtbl->GetSerialPort(machine, i, &serialPort);
            if (serialPort) {
                PRUnichar *pathUtf16 = NULL;

                serialPort->vtbl->SetEnabled(serialPort, 1);

                if (def->serials[i]->data.file.path) {
                    VBOX_UTF8_TO_UTF16(def->serials[i]->data.file.path, &pathUtf16);
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
                    DEBUG(" serialPort-%d irq: %d, iobase 0x%x, path: %s",
                          i, 4, 1016, def->serials[i]->data.file.path);
                } else if (def->serials[i]->target.port == 1) {
                    serialPort->vtbl->SetIRQ(serialPort, 3);
                    serialPort->vtbl->SetIOBase(serialPort, 760);
                    DEBUG(" serialPort-%d irq: %d, iobase 0x%x, path: %s",
                          i, 3, 760, def->serials[i]->data.file.path);
                }

                if (def->serials[i]->type == VIR_DOMAIN_CHR_TYPE_DEV) {
                    serialPort->vtbl->SetHostMode(serialPort, PortMode_HostDevice);
                } else if (def->serials[i]->type == VIR_DOMAIN_CHR_TYPE_PIPE) {
                    serialPort->vtbl->SetHostMode(serialPort, PortMode_HostPipe);
#if VBOX_API_VERSION >= 3000
                } else if (def->serials[i]->type == VIR_DOMAIN_CHR_TYPE_FILE) {
                    serialPort->vtbl->SetHostMode(serialPort, PortMode_RawFile);
#endif /* VBOX_API_VERSION >= 3000 */
                } else {
                    serialPort->vtbl->SetHostMode(serialPort, PortMode_Disconnected);
                }

                VBOX_RELEASE(serialPort);
                if (pathUtf16) {
                    VBOX_UTF16_FREE(pathUtf16);
                    pathUtf16 = NULL;
                }
            }
        }
    }   /* Finished:Block to attach the Serial Port to the VM */

    {   /* Started:Block to attach the Parallel Port to the VM */
        ISystemProperties *systemProperties = NULL;
        PRUint32 parallelPortCount          = 0;
        int i = 0;

        data->vboxObj->vtbl->GetSystemProperties(data->vboxObj, &systemProperties);
        if (systemProperties) {
            systemProperties->vtbl->GetParallelPortCount(systemProperties, &parallelPortCount);
            VBOX_RELEASE(systemProperties);
            systemProperties = NULL;
        }

        DEBUG("Number of Parallel Ports to be connected: %d", def->nparallels);
        DEBUG("Number of Parallel Ports available: %d", parallelPortCount);
        for (i = 0; (i < def->nparallels) && (i < parallelPortCount); i++) {
            IParallelPort *parallelPort = NULL;

            DEBUG("ParallelPort(%d): Type: %d", i, def->parallels[i]->type);
            DEBUG("ParallelPort(%d): target.port: %d", i, def->parallels[i]->target.port);

            machine->vtbl->GetParallelPort(machine, i, &parallelPort);
            if (parallelPort) {
                PRUnichar *pathUtf16 = NULL;

                VBOX_UTF8_TO_UTF16(def->parallels[i]->data.file.path, &pathUtf16);

                /* For now hard code the parallel ports to
                 * LPT1 (Base Addr: 0x378 (decimal: 888), IRQ: 7)
                 * LPT2 (Base Addr: 0x278 (decimal: 632), IRQ: 5)
                 * TODO: make this more flexible
                 */
                if ((def->parallels[i]->type == VIR_DOMAIN_CHR_TYPE_DEV)  ||
                    (def->parallels[i]->type == VIR_DOMAIN_CHR_TYPE_PTY)  ||
                    (def->parallels[i]->type == VIR_DOMAIN_CHR_TYPE_FILE) ||
                    (def->parallels[i]->type == VIR_DOMAIN_CHR_TYPE_PIPE)) {
                    parallelPort->vtbl->SetPath(parallelPort, pathUtf16);
                    if (i == 0) {
                        parallelPort->vtbl->SetIRQ(parallelPort, 7);
                        parallelPort->vtbl->SetIOBase(parallelPort, 888);
                        DEBUG(" parallePort-%d irq: %d, iobase 0x%x, path: %s",
                              i, 7, 888, def->parallels[i]->data.file.path);
                    } else if (i == 1) {
                        parallelPort->vtbl->SetIRQ(parallelPort, 5);
                        parallelPort->vtbl->SetIOBase(parallelPort, 632);
                        DEBUG(" parallePort-%d irq: %d, iobase 0x%x, path: %s",
                              i, 5, 632, def->parallels[i]->data.file.path);
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
    }   /* Finished:Block to attach the Parallel Port to the VM */

    {   /* Started:Block to specify video card settings */
        if ((def->nvideos == 1) && (def->videos[0]->type == VIR_DOMAIN_VIDEO_TYPE_VBOX)) {
            machine->vtbl->SetVRAMSize(machine, def->videos[0]->vram);
            machine->vtbl->SetMonitorCount(machine, def->videos[0]->heads);
            if (def->videos[0]->accel) {
                machine->vtbl->SetAccelerate3DEnabled(machine, def->videos[0]->accel->support3d);
#if VBOX_API_VERSION >= 3001
                machine->vtbl->SetAccelerate2DVideoEnabled(machine, def->videos[0]->accel->support2d);
#endif /* VBOX_API_VERSION >= 3001 */
            } else {
                machine->vtbl->SetAccelerate3DEnabled(machine, 0);
#if VBOX_API_VERSION >= 3001
                machine->vtbl->SetAccelerate2DVideoEnabled(machine, 0);
#endif /* VBOX_API_VERSION >= 3001 */
            }
        }
    }   /* Finished:Block to specify video card settings */

    {   /* Started:Block to attach the Remote Display to VM */
        int vrdpPresent  = 0;
        int sdlPresent   = 0;
        int guiPresent   = 0;
        char *guiDisplay = NULL;
        char *sdlDisplay = NULL;
        int i = 0;

        for (i = 0; i < def->ngraphics; i++) {
            IVRDPServer *VRDPServer = NULL;

            if ((def->graphics[i]->type == VIR_DOMAIN_GRAPHICS_TYPE_RDP) && (vrdpPresent == 0)) {

                vrdpPresent = 1;
                machine->vtbl->GetVRDPServer(machine, &VRDPServer);
                if (VRDPServer) {
                    VRDPServer->vtbl->SetEnabled(VRDPServer, PR_TRUE);
                    DEBUG0("VRDP Support turned ON.");

#if VBOX_API_VERSION < 3001
                    if (def->graphics[i]->data.rdp.port) {
                        VRDPServer->vtbl->SetPort(VRDPServer, def->graphics[i]->data.rdp.port);
                        DEBUG("VRDP Port changed to: %d", def->graphics[i]->data.rdp.port);
                    } else if (def->graphics[i]->data.rdp.autoport) {
                        /* Setting the port to 0 will reset its value to
                         * the default one which is 3389 currently
                         */
                        VRDPServer->vtbl->SetPort(VRDPServer, 0);
                        DEBUG0("VRDP Port changed to default, which is 3389 currently");
                    }
#else  /* VBOX_API_VERSION >= 3001 */
                    PRUnichar *portUtf16 = NULL;
                    portUtf16 = PRUnicharFromInt(def->graphics[i]->data.rdp.port);
                    VRDPServer->vtbl->SetPorts(VRDPServer, portUtf16);
                    VBOX_UTF16_FREE(portUtf16);
#endif /* VBOX_API_VERSION >= 3001 */

                    if (def->graphics[i]->data.rdp.replaceUser) {
                        VRDPServer->vtbl->SetReuseSingleConnection(VRDPServer, PR_TRUE);
                        DEBUG0("VRDP set to reuse single connection");
                    }

                    if (def->graphics[i]->data.rdp.multiUser) {
                        VRDPServer->vtbl->SetAllowMultiConnection(VRDPServer, PR_TRUE);
                        DEBUG0("VRDP set to allow multiple connection");
                    }

                    if (def->graphics[i]->data.rdp.listenAddr) {
                        PRUnichar *netAddressUtf16 = NULL;

                        VBOX_UTF8_TO_UTF16(def->graphics[i]->data.rdp.listenAddr, &netAddressUtf16);
                        VRDPServer->vtbl->SetNetAddress(VRDPServer, netAddressUtf16);
                        DEBUG("VRDP listen address is set to: %s", def->graphics[i]->data.rdp.listenAddr);

                        VBOX_UTF16_FREE(netAddressUtf16);
                    }

                    VBOX_RELEASE(VRDPServer);
                }
            }

            if ((def->graphics[i]->type == VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP) && (guiPresent == 0)) {
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

            if ((def->graphics[i]->type == VIR_DOMAIN_GRAPHICS_TYPE_SDL) && (sdlPresent == 0)) {
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

                machine->vtbl->SetExtraData(machine, keyDislpayUtf16, valueDisplayUtf16);

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

                machine->vtbl->SetExtraData(machine, keyDislpayUtf16, valueDisplayUtf16);

                VBOX_UTF16_FREE(keyDislpayUtf16);
                VBOX_UTF16_FREE(valueDisplayUtf16);
            }
        }

        VIR_FREE(guiDisplay);
        VIR_FREE(sdlDisplay);

    }   /* Finished:Block to attach the Remote Display to VM */

    {   /* Started:Block to attach USB Devices to VM */
        if (def->nhostdevs > 0) {
            IUSBController *USBController = NULL;
            int i = 0, isUSB = 0;
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
                            DEBUG("USB Device detected, VendorId:0x%x, ProductId:0x%x",
                                  def->hostdevs[i]->source.subsys.u.usb.vendor,
                                  def->hostdevs[i]->source.subsys.u.usb.product);
                            isUSB++;
                        }
                    }
                }
            }

            if (isUSB > 0) {
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

                                char filtername[11]        = {0};
                                PRUnichar *filternameUtf16 = NULL;
                                IUSBDeviceFilter *filter   = NULL;

                                /* Assuming can't have more then 9999 devices so
                                 * restricting to %04d
                                 */
                                sprintf(filtername, "filter%04d", i);
                                VBOX_UTF8_TO_UTF16(filtername, &filternameUtf16);

                                USBController->vtbl->CreateDeviceFilter(USBController,
                                                                        filternameUtf16,
                                                                        &filter);
                                VBOX_UTF16_FREE(filternameUtf16);

                                if (filter &&
                                    (def->hostdevs[i]->source.subsys.u.usb.vendor ||
                                    def->hostdevs[i]->source.subsys.u.usb.product)) {

                                    PRUnichar *vendorIdUtf16  = NULL;
                                    char vendorId[40]         = {0};
                                    PRUnichar *productIdUtf16 = NULL;
                                    char productId[40]        = {0};

                                    if (def->hostdevs[i]->source.subsys.u.usb.vendor) {
                                        sprintf(vendorId, "%x", def->hostdevs[i]->source.subsys.u.usb.vendor);
                                        VBOX_UTF8_TO_UTF16(vendorId, &vendorIdUtf16);
                                        filter->vtbl->SetVendorId(filter, vendorIdUtf16);
                                        VBOX_UTF16_FREE(vendorIdUtf16);
                                    }
                                    if (def->hostdevs[i]->source.subsys.u.usb.product) {
                                        sprintf(productId, "%x", def->hostdevs[i]->source.subsys.u.usb.product);
                                        VBOX_UTF8_TO_UTF16(productId, &productIdUtf16);
                                        filter->vtbl->SetProductId(filter, productIdUtf16);
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
    }   /* Finished:Block to attach USB Devices to VM */

    /* Save the machine settings made till now and close the
     * session. also free up the mchiid variable used.
     */
    rc = machine->vtbl->SaveSettings(machine);
    data->vboxSession->vtbl->Close(data->vboxSession);
    vboxIIDUnalloc(mchiid);

    ret = virGetDomain(conn, def->name, def->uuid);
    VBOX_RELEASE(machine);
    machine = NULL;

    vboxIIDFree(iid);
    virDomainDefFree(def);

    return ret;

cleanup:
    VBOX_RELEASE(machine);
    vboxIIDFree(iid);
    virDomainDefFree(def);
    return NULL;
}

static int vboxDomainUndefine(virDomainPtr dom) {
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    IMachine *machine    = NULL;
    vboxIID  *iid        = NULL;
    nsresult rc;

#if VBOX_API_VERSION == 2002
    if (VIR_ALLOC(iid) < 0) {
        virReportOOMError();
        goto cleanup;
    }
#endif

    vboxIIDFromUUID(dom->uuid, iid);

    /* Block for checking if HDD's are attched to VM.
     * considering just IDE bus for now. Also skipped
     * chanel=1 and device=0 (Secondary Master) as currenlty
     * it is allocated to CD/DVD Drive bt default
     */
    {
        PRUnichar *hddcnameUtf16 = NULL;

        char *hddcname = strdup("IDE");
        VBOX_UTF8_TO_UTF16(hddcname, &hddcnameUtf16);
        VIR_FREE(hddcname);

        /* Open a Session for the machine */
        rc = data->vboxObj->vtbl->OpenSession(data->vboxObj, data->vboxSession, iid);
        if (NS_SUCCEEDED(rc)) {
            rc = data->vboxSession->vtbl->GetMachine(data->vboxSession, &machine);
            if (NS_SUCCEEDED(rc) && machine) {

#if VBOX_API_VERSION < 3001
                /* Disconnect all the drives if present */
                machine->vtbl->DetachHardDisk(machine, hddcnameUtf16, 0, 0);
                machine->vtbl->DetachHardDisk(machine, hddcnameUtf16, 0, 1);
                machine->vtbl->DetachHardDisk(machine, hddcnameUtf16, 1, 1);
#else  /* VBOX_API_VERSION >= 3001 */
                /* get all the controller first, then the attachments and
                 * remove them all so that the machine can be undefined
                 */
                PRUint32 strCtlSize = 0;
                IStorageController **aStrCtls = NULL;
                int i = 0, j = 0;

                machine->vtbl->GetStorageControllers(machine,
                                                     &strCtlSize,
                                                     &aStrCtls);

                for (i = 0; i < strCtlSize; i++) {
                    IStorageController *strCtl = aStrCtls[i];
                    PRUnichar *strCtlName = NULL;
                    PRUint32   medAttSize = 0;
                    IMediumAttachment **aMedAtts = NULL;

                    if (!strCtl)
                        continue;

                    strCtl->vtbl->GetName(strCtl, &strCtlName);
                    machine->vtbl->GetMediumAttachmentsOfController(machine,
                                                                    strCtlName,
                                                                    &medAttSize,
                                                                    &aMedAtts);

                    for (j = 0; j < medAttSize; j++) {
                        IMediumAttachment *medAtt = aMedAtts[j];
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

                        VBOX_RELEASE(medAtt);
                    }

                    VBOX_RELEASE(strCtl);
                    machine->vtbl->RemoveStorageController(machine, strCtlName);
                    VBOX_UTF16_FREE(strCtlName);
                }
#endif /* VBOX_API_VERSION >= 3001 */

                machine->vtbl->SaveSettings(machine);
            }
            data->vboxSession->vtbl->Close(data->vboxSession);
        }
        VBOX_UTF16_FREE(hddcnameUtf16);
    }

    rc = data->vboxObj->vtbl->UnregisterMachine(data->vboxObj, iid, &machine);
    DEBUGIID("UUID of machine being undefined", iid);

    if (NS_SUCCEEDED(rc) && machine){
        machine->vtbl->DeleteSettings(machine);
        ret = 0;
    } else {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("could not delete the domain, rc=%08x"), (unsigned)rc);
    }

#if VBOX_API_VERSION == 2002
cleanup:
#endif
    vboxIIDFree(iid);
    VBOX_RELEASE(machine);

    return ret;
}

static int vboxDomainAttachDeviceImpl(virDomainPtr dom,
                                      const char *xml,
                                      int mediaChangeOnly ATTRIBUTE_UNUSED) {
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    IMachine *machine    = NULL;
    vboxIID  *iid        = NULL;
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

#if VBOX_API_VERSION == 2002
    if (VIR_ALLOC(iid) < 0) {
        virReportOOMError();
        goto cleanup;
    }
#endif

    vboxIIDFromUUID(dom->uuid, iid);

    rc = data->vboxObj->vtbl->GetMachine(data->vboxObj, iid, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INVALID_DOMAIN, "%s",
                  _("no domain with matching uuid"));
        goto cleanup;
    }

    if (machine) {
        machine->vtbl->GetState(machine, &state);

        if ((state == MachineState_Running) ||
            (state == MachineState_Paused)) {
            rc = data->vboxObj->vtbl->OpenExistingSession(data->vboxObj, data->vboxSession, iid);
        } else {
            rc = data->vboxObj->vtbl->OpenSession(data->vboxObj, data->vboxSession, iid);
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
                                vboxIID   *dvduuid           = NULL;
# if VBOX_API_VERSION == 2002
                                nsID dvdemptyuuid;

                                memset(&dvdemptyuuid, 0, sizeof(dvdemptyuuid));
# else
                                PRUnichar *dvdemptyuuidUtf16 = NULL;
# endif

                                VBOX_UTF8_TO_UTF16(dev->data.disk->src, &dvdfileUtf16);

                                data->vboxObj->vtbl->FindDVDImage(data->vboxObj, dvdfileUtf16, &dvdImage);
                                if (!dvdImage) {
# if VBOX_API_VERSION == 2002
                                    data->vboxObj->vtbl->OpenDVDImage(data->vboxObj, dvdfileUtf16, &dvdemptyuuid, &dvdImage);
# else
                                    data->vboxObj->vtbl->OpenDVDImage(data->vboxObj, dvdfileUtf16, dvdemptyuuidUtf16, &dvdImage);
# endif
                                }
                                if (dvdImage) {
                                    rc = dvdImage->vtbl->imedium.GetId((IMedium *)dvdImage, &dvduuid);
                                    if (NS_FAILED(rc)) {
                                        vboxError(VIR_ERR_INTERNAL_ERROR,
                                                  _("can't get the uuid of the file to "
                                                    "be attached to cdrom: %s, rc=%08x"),
                                                  dev->data.disk->src, (unsigned)rc);
                                    } else {
                                        /* unmount the previous mounted image */
                                        dvdDrive->vtbl->Unmount(dvdDrive);
                                        rc = dvdDrive->vtbl->MountImage(dvdDrive, dvduuid);
                                        if (NS_FAILED(rc)) {
                                            vboxError(VIR_ERR_INTERNAL_ERROR,
                                                      _("could not attach the file to cdrom: %s, rc=%08x"),
                                                      dev->data.disk->src, (unsigned)rc);
                                        } else {
                                            ret = 0;
                                            DEBUGIID("CD/DVD Image UUID:", dvduuid);
                                        }
                                    }

                                    VBOX_MEDIUM_RELEASE(dvdImage);
                                }
                                vboxIIDUnalloc(dvduuid);
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
                                    vboxIID *fduuid             = NULL;
# if VBOX_API_VERSION == 2002
                                    nsID fdemptyuuid;

                                    memset(&fdemptyuuid, 0, sizeof(fdemptyuuid));
# else
                                    PRUnichar *fdemptyuuidUtf16 = NULL;
# endif
                                    VBOX_UTF8_TO_UTF16(dev->data.disk->src, &fdfileUtf16);
                                    rc = data->vboxObj->vtbl->FindFloppyImage(data->vboxObj,
                                                                              fdfileUtf16,
                                                                              &floppyImage);

                                    if (!floppyImage) {
                                        data->vboxObj->vtbl->OpenFloppyImage(data->vboxObj,
                                                                             fdfileUtf16,
# if VBOX_API_VERSION == 2002
                                                                             &fdemptyuuid,
# else
                                                                             fdemptyuuidUtf16,
# endif
                                                                             &floppyImage);
                                    }

                                    if (floppyImage) {
                                        rc = floppyImage->vtbl->imedium.GetId((IMedium *)floppyImage, &fduuid);
                                        if (NS_FAILED(rc)) {
                                            vboxError(VIR_ERR_INTERNAL_ERROR,
                                                      _("can't get the uuid of the file to be "
                                                        "attached to floppy drive: %s, rc=%08x"),
                                                      dev->data.disk->src, (unsigned)rc);
                                        } else {
                                            rc = floppyDrive->vtbl->MountImage(floppyDrive, fduuid);
                                            if (NS_FAILED(rc)) {
                                                vboxError(VIR_ERR_INTERNAL_ERROR,
                                                          _("could not attach the file to floppy drive: %s, rc=%08x"),
                                                          dev->data.disk->src, (unsigned)rc);
                                            } else {
                                                ret = 0;
                                                DEBUGIID("attached floppy, UUID:", fduuid);
                                            }
                                        }
                                        VBOX_MEDIUM_RELEASE(floppyImage);
                                    }
                                    vboxIIDUnalloc(fduuid);
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
                }
                machine->vtbl->SaveSettings(machine);
                VBOX_RELEASE(machine);
            }
            data->vboxSession->vtbl->Close(data->vboxSession);
        }
    }

cleanup:
    vboxIIDFree(iid);
    virDomainDefFree(def);
    virDomainDeviceDefFree(dev);
    return ret;
}

static int vboxDomainAttachDevice(virDomainPtr dom, const char *xml) {
    return vboxDomainAttachDeviceImpl(dom, xml, 0);
}

static int vboxDomainAttachDeviceFlags(virDomainPtr dom, const char *xml,
                                       unsigned int flags) {
    if (flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG) {
        vboxError(VIR_ERR_OPERATION_INVALID, "%s",
                  _("cannot modify the persistent configuration of a domain"));
        return -1;
    }

    return vboxDomainAttachDeviceImpl(dom, xml, 0);
}

static int vboxDomainUpdateDeviceFlags(virDomainPtr dom, const char *xml,
                                       unsigned int flags) {
    if (flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG) {
        vboxError(VIR_ERR_OPERATION_INVALID, "%s",
                  _("cannot modify the persistent configuration of a domain"));
        return -1;
    }

    return vboxDomainAttachDeviceImpl(dom, xml, 1);
}

static int vboxDomainDetachDevice(virDomainPtr dom, const char *xml) {
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    IMachine *machine    = NULL;
    vboxIID  *iid        = NULL;
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

#if VBOX_API_VERSION == 2002
    if (VIR_ALLOC(iid) < 0) {
        virReportOOMError();
        goto cleanup;
    }
#endif

    vboxIIDFromUUID(dom->uuid, iid);

    rc = data->vboxObj->vtbl->GetMachine(data->vboxObj, iid, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INVALID_DOMAIN, "%s",
                  _("no domain with matching uuid"));
        goto cleanup;
    }

    if (machine) {
        machine->vtbl->GetState(machine, &state);

        if ((state == MachineState_Running) ||
            (state == MachineState_Paused)) {
            rc = data->vboxObj->vtbl->OpenExistingSession(data->vboxObj, data->vboxSession, iid);
        } else {
            rc = data->vboxObj->vtbl->OpenSession(data->vboxObj, data->vboxSession, iid);
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
                }
                machine->vtbl->SaveSettings(machine);
                VBOX_RELEASE(machine);
            }
            data->vboxSession->vtbl->Close(data->vboxSession);
        }
    }

cleanup:
    vboxIIDFree(iid);
    virDomainDefFree(def);
    virDomainDeviceDefFree(dev);
    return ret;
}

static int vboxDomainDetachDeviceFlags(virDomainPtr dom, const char *xml,
                                       unsigned int flags) {
    if (flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG) {
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

    rc = machine->vtbl->GetSnapshot(machine, NULL, list);
    if (NS_FAILED(rc) || !list[0]) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("could not get root snapshot for domain %s"),
                  dom->name);
        goto error;
    }

    /* BFS walk through snapshot tree */
    top = 1;
    for (next = 0; next < count; next++) {
        PRUint32 childrenCount = 0;
        ISnapshot **children = NULL;
        unsigned int i;

        if (!list[next]) {
            vboxError(VIR_ERR_INTERNAL_ERROR,
                      _("unexpected number of snapshots < %u"), count);
            goto error;
        }

        rc = list[next]->vtbl->GetChildren(list[next], &childrenCount,
                                           &children);
        if (NS_FAILED(rc)) {
            vboxError(VIR_ERR_INTERNAL_ERROR,
                      "%s", _("could not get children snapshots"));
            goto error;
        }
        for (i = 0; i < childrenCount; i++) {
            if (!children[i])
                continue;
            if (top == count) {
                vboxError(VIR_ERR_INTERNAL_ERROR,
                          _("unexpected number of snapshots > %u"), count);
                goto error;
            }
            list[top++] = children[i];
        }
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
                            unsigned int flags ATTRIBUTE_UNUSED)
{
    VBOX_OBJECT_CHECK(dom->conn, virDomainSnapshotPtr, NULL);
    virDomainSnapshotDefPtr def = NULL;
    vboxIID *domiid = NULL;
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

    if (!(def = virDomainSnapshotDefParseString(xmlDesc, 1)))
        goto cleanup;

#if VBOX_API_VERSION == 2002
    if (VIR_ALLOC(domiid) < 0) {
        virReportOOMError();
        goto cleanup;
    }
#endif

    vboxIIDFromUUID(dom->uuid, domiid);
    rc = data->vboxObj->vtbl->GetMachine(data->vboxObj, domiid, &machine);
    if (NS_FAILED(rc) || !machine) {
        vboxError(VIR_ERR_INVALID_DOMAIN, "%s",
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
        rc = data->vboxObj->vtbl->OpenExistingSession(data->vboxObj,
                                                      data->vboxSession,
                                                      domiid);
    } else {
        rc = data->vboxObj->vtbl->OpenSession(data->vboxObj,
                                              data->vboxSession,
                                              domiid);
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
    data->vboxSession->vtbl->Close(data->vboxSession);
    VBOX_RELEASE(machine);
    vboxIIDFree(domiid);
    virDomainSnapshotDefFree(def);
    return ret;
}

static char *
vboxDomainSnapshotDumpXML(virDomainSnapshotPtr snapshot,
                          unsigned int flags ATTRIBUTE_UNUSED)
{
    virDomainPtr dom = snapshot->domain;
    VBOX_OBJECT_CHECK(dom->conn, char *, NULL);
    vboxIID *domiid = NULL;
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

#if VBOX_API_VERSION == 2002
    if (VIR_ALLOC(domiid) < 0) {
        virReportOOMError();
        goto cleanup;
    }
#endif

    vboxIIDFromUUID(dom->uuid, domiid);
    rc = data->vboxObj->vtbl->GetMachine(data->vboxObj, domiid, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INVALID_DOMAIN, "%s",
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
    ret = virDomainSnapshotDefFormat(uuidstr, def, 0);

cleanup:
    virDomainSnapshotDefFree(def);
    VBOX_RELEASE(parent);
    VBOX_RELEASE(snap);
    VBOX_RELEASE(machine);
    vboxIIDFree(domiid);
    return ret;

no_memory:
    virReportOOMError();
    goto cleanup;
}

static int
vboxDomainSnapshotNum(virDomainPtr dom,
                      unsigned int flags ATTRIBUTE_UNUSED)
{
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    vboxIID *iid = NULL;
    IMachine *machine = NULL;
    nsresult rc;
    PRUint32 snapshotCount;

#if VBOX_API_VERSION == 2002
    if (VIR_ALLOC(iid) < 0) {
        virReportOOMError();
        goto cleanup;
    }
#endif

    vboxIIDFromUUID(dom->uuid, iid);
    rc = data->vboxObj->vtbl->GetMachine(data->vboxObj, iid, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INVALID_DOMAIN, "%s",
                  _("no domain with matching UUID"));
        goto cleanup;
    }

    rc = machine->vtbl->GetSnapshotCount(machine, &snapshotCount);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("could not get snapshot count for domain %s"),
                  dom->name);
        goto cleanup;
    }

    ret = snapshotCount;

cleanup:
    VBOX_RELEASE(machine);
    vboxIIDFree(iid);
    return ret;
}

static int
vboxDomainSnapshotListNames(virDomainPtr dom,
                            char **names,
                            int nameslen,
                            unsigned int flags ATTRIBUTE_UNUSED)
{
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    vboxIID *iid = NULL;
    IMachine *machine = NULL;
    nsresult rc;
    ISnapshot **snapshots = NULL;
    int count = 0;
    int i;

#if VBOX_API_VERSION == 2002
    if (VIR_ALLOC(iid) < 0) {
        virReportOOMError();
        goto cleanup;
    }
#endif

    vboxIIDFromUUID(dom->uuid, iid);
    rc = data->vboxObj->vtbl->GetMachine(data->vboxObj, iid, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INVALID_DOMAIN, "%s",
                  _("no domain with matching UUID"));
        goto cleanup;
    }

    if ((count = vboxDomainSnapshotGetAll(dom, machine, &snapshots)) < 0)
        goto cleanup;

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
    vboxIIDFree(iid);
    return ret;
}

static virDomainSnapshotPtr
vboxDomainSnapshotLookupByName(virDomainPtr dom,
                               const char *name,
                               unsigned int flags ATTRIBUTE_UNUSED)
{
    VBOX_OBJECT_CHECK(dom->conn, virDomainSnapshotPtr, NULL);
    vboxIID *iid = NULL;
    IMachine *machine = NULL;
    ISnapshot *snapshot = NULL;
    nsresult rc;

#if VBOX_API_VERSION == 2002
    if (VIR_ALLOC(iid) < 0) {
        virReportOOMError();
        goto cleanup;
    }
#endif

    vboxIIDFromUUID(dom->uuid, iid);
    rc = data->vboxObj->vtbl->GetMachine(data->vboxObj, iid, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INVALID_DOMAIN, "%s",
                  _("no domain with matching UUID"));
        goto cleanup;
    }

    if (!(snapshot = vboxDomainSnapshotGet(data, dom, machine, name)))
        goto cleanup;

    ret = virGetDomainSnapshot(dom, name);

cleanup:
    VBOX_RELEASE(snapshot);
    VBOX_RELEASE(machine);
    vboxIIDFree(iid);
    return ret;
}

static int
vboxDomainHasCurrentSnapshot(virDomainPtr dom,
                             unsigned int flags ATTRIBUTE_UNUSED)
{
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    vboxIID *iid = NULL;
    IMachine *machine = NULL;
    ISnapshot *snapshot = NULL;
    nsresult rc;

#if VBOX_API_VERSION == 2002
    if (VIR_ALLOC(iid) < 0) {
        virReportOOMError();
        goto cleanup;
    }
#endif

    vboxIIDFromUUID(dom->uuid, iid);
    rc = data->vboxObj->vtbl->GetMachine(data->vboxObj, iid, &machine);
    if (NS_FAILED(rc) || !machine) {
        vboxError(VIR_ERR_INVALID_DOMAIN, "%s",
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
    vboxIIDFree(iid);
    return ret;
}

static virDomainSnapshotPtr
vboxDomainSnapshotCurrent(virDomainPtr dom,
                          unsigned int flags ATTRIBUTE_UNUSED)
{
    VBOX_OBJECT_CHECK(dom->conn, virDomainSnapshotPtr, NULL);
    vboxIID *iid = NULL;
    IMachine *machine = NULL;
    ISnapshot *snapshot = NULL;
    PRUnichar *nameUtf16 = NULL;
    char *name = NULL;
    nsresult rc;

#if VBOX_API_VERSION == 2002
    if (VIR_ALLOC(iid) < 0) {
        virReportOOMError();
        goto cleanup;
    }
#endif

    vboxIIDFromUUID(dom->uuid, iid);
    rc = data->vboxObj->vtbl->GetMachine(data->vboxObj, iid, &machine);
    if (NS_FAILED(rc) || !machine) {
        vboxError(VIR_ERR_INVALID_DOMAIN, "%s",
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
    vboxIIDFree(iid);
    return ret;
}

#if VBOX_API_VERSION < 3001
static int
vboxDomainSnapshotRestore(virDomainPtr dom,
                          IMachine *machine,
                          ISnapshot *snapshot)
{
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    vboxIID *iid = NULL;
    nsresult rc;

    rc = snapshot->vtbl->GetId(snapshot, &iid);
    if (NS_FAILED(rc) || !iid) {
        vboxError(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("could not get snapshot UUID"));
        goto cleanup;
    }

    rc = machine->vtbl->SetCurrentSnapshot(machine, iid);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("could not restore snapshot for domain %s"), dom->name);
        goto cleanup;
    }

    ret = 0;

cleanup:
    vboxIIDUnalloc(iid);
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
    vboxIID *domiid;

    rc = machine->vtbl->GetId(machine, &domiid);
    if (NS_FAILED(rc) || !domiid) {
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

    rc = data->vboxObj->vtbl->OpenSession(data->vboxObj, data->vboxSession,
                                          domiid);
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
    data->vboxSession->vtbl->Close(data->vboxSession);
    return ret;
}
#endif

static int
vboxDomainRevertToSnapshot(virDomainSnapshotPtr snapshot,
                           unsigned int flags ATTRIBUTE_UNUSED)
{
    virDomainPtr dom = snapshot->domain;
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    vboxIID *domiid = NULL;
    IMachine *machine = NULL;
    ISnapshot *newSnapshot = NULL;
    ISnapshot *prevSnapshot = NULL;
    PRBool online = PR_FALSE;
    PRUint32 state;
    nsresult rc;

#if VBOX_API_VERSION == 2002
    if (VIR_ALLOC(domiid) < 0) {
        virReportOOMError();
        goto cleanup;
    }
#endif

    vboxIIDFromUUID(dom->uuid, domiid);
    rc = data->vboxObj->vtbl->GetMachine(data->vboxObj, domiid, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INVALID_DOMAIN, "%s",
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
    vboxIIDUnalloc(domiid);
    return ret;
}

static int
vboxDomainSnapshotDeleteSingle(vboxGlobalData *data,
                               IConsole *console,
                               ISnapshot *snapshot)
{
    IProgress *progress = NULL;
    vboxIID *iid = NULL;
    int ret = -1;
    nsresult rc;
#if VBOX_API_VERSION == 2002
    nsresult result;
#else
    PRInt32 result;
#endif

    rc = snapshot->vtbl->GetId(snapshot, &iid);
    if (NS_FAILED(rc) || !iid) {
        vboxError(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("could not get snapshot UUID"));
        goto cleanup;
    }

#if VBOX_API_VERSION < 3001
    rc = console->vtbl->DiscardSnapshot(console, iid, &progress);
#else
    rc = console->vtbl->DeleteSnapshot(console, iid, &progress);
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
    vboxIIDUnalloc(iid);
    return ret;
}

static int
vboxDomainSnapshotDeleteTree(vboxGlobalData *data,
                             IConsole *console,
                             ISnapshot *snapshot)
{
    PRUint32 childrenCount = 0;
    ISnapshot **children = NULL;
    int ret = -1;
    nsresult rc;
    unsigned int i;

    rc = snapshot->vtbl->GetChildren(snapshot, &childrenCount, &children);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("could not get children snapshots"));
        goto cleanup;
    }

    if (childrenCount > 0) {
        for (i = 0; i < childrenCount; i++) {
            if (vboxDomainSnapshotDeleteTree(data, console, children[i]))
                goto cleanup;
        }
    }

    ret = vboxDomainSnapshotDeleteSingle(data, console, snapshot);

cleanup:
    for (i = 0; i < childrenCount; i++)
        VBOX_RELEASE(children[i]);
    return ret;
}

static int
vboxDomainSnapshotDelete(virDomainSnapshotPtr snapshot,
                         unsigned int flags)
{
    virDomainPtr dom = snapshot->domain;
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    vboxIID *domiid = NULL;
    IMachine *machine = NULL;
    ISnapshot *snap = NULL;
    IConsole *console = NULL;
    PRUint32 state;
    nsresult rc;

#if VBOX_API_VERSION == 2002
    if (VIR_ALLOC(domiid) < 0) {
        virReportOOMError();
        goto cleanup;
    }
#endif

    vboxIIDFromUUID(dom->uuid, domiid);

    rc = data->vboxObj->vtbl->GetMachine(data->vboxObj, domiid, &machine);
    if (NS_FAILED(rc)) {
        vboxError(VIR_ERR_INVALID_DOMAIN, "%s",
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

    if (state >= MachineState_FirstOnline
        && state <= MachineState_LastOnline) {
        vboxError(VIR_ERR_OPERATION_INVALID, "%s",
                  _("cannot delete snapshots of running domain"));
        goto cleanup;
    }

    rc = data->vboxObj->vtbl->OpenSession(data->vboxObj, data->vboxSession,
                                          domiid);
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
    vboxIIDUnalloc(domiid);
    data->vboxSession->vtbl->Close(data->vboxSession);
    return ret;
}

#if VBOX_API_VERSION == 2002
    /* No Callback support for VirtualBox 2.2.* series */
#else /* !(VBOX_API_VERSION == 2002) */

/* Functions needed for Callbacks */
static  nsresult vboxCallbackOnMachineStateChange (IVirtualBoxCallback *pThis,
                                                   PRUnichar * machineId,
                                                   PRUint32 state) {
    virDomainPtr dom = NULL;
    int event        = 0;
    int detail       = 0;

    g_pVBoxGlobalData->domainEventDispatching = 1;
    vboxDriverLock(g_pVBoxGlobalData);

    DEBUG("IVirtualBoxCallback: %p, State: %d", pThis, state);
    DEBUGPRUnichar("machineId", machineId);

    if (machineId) {
        char *machineIdUtf8       = NULL;
        unsigned char uuid[VIR_UUID_BUFLEN];

        g_pVBoxGlobalData->pFuncs->pfnUtf16ToUtf8(machineId, &machineIdUtf8);
        virUUIDParse(machineIdUtf8, uuid);

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

            if (ev) {
                virDomainEventDispatch(ev,
                                       g_pVBoxGlobalData->domainEventCallbacks,
                                       virDomainEventDispatchDefaultFunc,
                                       NULL);
                virDomainEventFree(ev);
            }
        }
    }

    virDomainEventCallbackListPurgeMarked(g_pVBoxGlobalData->domainEventCallbacks);

    vboxDriverUnlock(g_pVBoxGlobalData);
    g_pVBoxGlobalData->domainEventDispatching = 0;

    return NS_OK;
}

static nsresult vboxCallbackOnMachineDataChange (IVirtualBoxCallback *pThis,
                                                 PRUnichar * machineId) {
    DEBUG("IVirtualBoxCallback: %p", pThis);
    DEBUGPRUnichar("machineId", machineId);

    return NS_OK;
}

static nsresult vboxCallbackOnExtraDataCanChange (IVirtualBoxCallback *pThis,
                                                  PRUnichar * machineId,
                                                  PRUnichar * key,
                                                  PRUnichar * value,
                                                  PRUnichar * * error ATTRIBUTE_UNUSED,
                                                  PRBool * allowChange) {
    DEBUG("IVirtualBoxCallback: %p, allowChange: %s", pThis, *allowChange ? "true" : "false");
    DEBUGPRUnichar("machineId", machineId);
    DEBUGPRUnichar("key", key);
    DEBUGPRUnichar("value", value);

    return NS_OK;
}

static nsresult vboxCallbackOnExtraDataChange (IVirtualBoxCallback *pThis,
                                               PRUnichar * machineId,
                                               PRUnichar * key,
                                               PRUnichar * value) {
    DEBUG("IVirtualBoxCallback: %p", pThis);
    DEBUGPRUnichar("machineId", machineId);
    DEBUGPRUnichar("key", key);
    DEBUGPRUnichar("value", value);

    return NS_OK;
}

# if VBOX_API_VERSION < 3001
static nsresult vboxCallbackOnMediaRegistered (IVirtualBoxCallback *pThis,
                                               PRUnichar * mediaId,
                                               PRUint32 mediaType,
                                               PRBool registered) {
    DEBUG("IVirtualBoxCallback: %p, registered: %s", pThis, registered ? "true" : "false");
    DEBUG("mediaType: %d", mediaType);
    DEBUGPRUnichar("mediaId", mediaId);

    return NS_OK;
}
# else  /* VBOX_API_VERSION >= 3001 */
# endif /* VBOX_API_VERSION >= 3001 */

static nsresult vboxCallbackOnMachineRegistered (IVirtualBoxCallback *pThis,
                                                 PRUnichar * machineId,
                                                 PRBool registered) {
    virDomainPtr dom = NULL;
    int event        = 0;
    int detail       = 0;

    g_pVBoxGlobalData->domainEventDispatching = 1;
    vboxDriverLock(g_pVBoxGlobalData);

    DEBUG("IVirtualBoxCallback: %p, registered: %s", pThis, registered ? "true" : "false");
    DEBUGPRUnichar("machineId", machineId);

    if (machineId) {
        char *machineIdUtf8       = NULL;
        unsigned char uuid[VIR_UUID_BUFLEN];

        g_pVBoxGlobalData->pFuncs->pfnUtf16ToUtf8(machineId, &machineIdUtf8);
        virUUIDParse(machineIdUtf8, uuid);

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

            if (ev) {
                virDomainEventDispatch(ev,
                                       g_pVBoxGlobalData->domainEventCallbacks,
                                       virDomainEventDispatchDefaultFunc,
                                       NULL);
                virDomainEventFree(ev);
            }
        }
    }

    virDomainEventCallbackListPurgeMarked(g_pVBoxGlobalData->domainEventCallbacks);

    vboxDriverUnlock(g_pVBoxGlobalData);
    g_pVBoxGlobalData->domainEventDispatching = 0;

    return NS_OK;
}

static nsresult vboxCallbackOnSessionStateChange (IVirtualBoxCallback *pThis,
                                                  PRUnichar * machineId,
                                                  PRUint32 state) {
    DEBUG("IVirtualBoxCallback: %p, state: %d", pThis, state);
    DEBUGPRUnichar("machineId", machineId);

    return NS_OK;
}

static nsresult vboxCallbackOnSnapshotTaken (IVirtualBoxCallback *pThis,
                                             PRUnichar * machineId,
                                             PRUnichar * snapshotId) {
    DEBUG("IVirtualBoxCallback: %p", pThis);
    DEBUGPRUnichar("machineId", machineId);
    DEBUGPRUnichar("snapshotId", snapshotId);

    return NS_OK;
}

static nsresult vboxCallbackOnSnapshotDiscarded (IVirtualBoxCallback *pThis,
                                                 PRUnichar * machineId,
                                                 PRUnichar * snapshotId) {
    DEBUG("IVirtualBoxCallback: %p", pThis);
    DEBUGPRUnichar("machineId", machineId);
    DEBUGPRUnichar("snapshotId", snapshotId);

    return NS_OK;
}

static nsresult vboxCallbackOnSnapshotChange (IVirtualBoxCallback *pThis,
                                              PRUnichar * machineId,
                                              PRUnichar * snapshotId) {
    DEBUG("IVirtualBoxCallback: %p", pThis);
    DEBUGPRUnichar("machineId", machineId);
    DEBUGPRUnichar("snapshotId", snapshotId);

    return NS_OK;
}

static nsresult vboxCallbackOnGuestPropertyChange (IVirtualBoxCallback *pThis,
                                                   PRUnichar * machineId,
                                                   PRUnichar * name,
                                                   PRUnichar * value,
                                                   PRUnichar * flags) {
    DEBUG("IVirtualBoxCallback: %p", pThis);
    DEBUGPRUnichar("machineId", machineId);
    DEBUGPRUnichar("name", name);
    DEBUGPRUnichar("value", value);
    DEBUGPRUnichar("flags", flags);

    return NS_OK;
}

static nsresult vboxCallbackAddRef(nsISupports *pThis) {
    nsresult c;

    c = ++g_pVBoxGlobalData->vboxCallBackRefCount;

    DEBUG("pThis: %p, vboxCallback AddRef: %d", pThis, c);

    return c;
}

static nsresult vboxCallbackRelease(nsISupports *pThis) {
    nsresult c;

    c = --g_pVBoxGlobalData->vboxCallBackRefCount;
    if (c == 0) {
        /* delete object */
        VIR_FREE(pThis->vtbl);
        VIR_FREE(pThis);
    }

    DEBUG("pThis: %p, vboxCallback Release: %d", pThis, c);

    return c;
}

static nsresult vboxCallbackQueryInterface(nsISupports *pThis, const nsID *iid, void **resultp) {
    IVirtualBoxCallback *that = (IVirtualBoxCallback *)pThis;
    static const nsID ivirtualboxCallbackUUID = IVIRTUALBOXCALLBACK_IID;
    static const nsID isupportIID = NS_ISUPPORTS_IID;

    /* Match UUID for IVirtualBoxCallback class */
    if (    memcmp(iid, &ivirtualboxCallbackUUID, sizeof(nsID)) == 0
        ||  memcmp(iid, &isupportIID, sizeof(nsID)) == 0) {
        g_pVBoxGlobalData->vboxCallBackRefCount++;
        *resultp = that;

        DEBUG("pThis: %p, vboxCallback QueryInterface: %d", pThis, g_pVBoxGlobalData->vboxCallBackRefCount);

        return NS_OK;
    }


    DEBUG("pThis: %p, vboxCallback QueryInterface didn't find a matching interface", pThis);
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
        vboxCallback->vtbl->OnSnapshotDiscarded         = &vboxCallbackOnSnapshotDiscarded;
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

            ret = virDomainEventCallbackListAdd(conn, data->domainEventCallbacks,
                                                callback, opaque, freecb);
            DEBUG("virDomainEventCallbackListAdd (ret = %d) ( conn: %p, "
                  "data->domainEventCallbacks: %p, callback: %p, opaque: %p, "
                  "freecb: %p )", ret, conn, data->domainEventCallbacks, callback,
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

    /* Locking has to be there as callbacks are not
     * really fully thread safe
     */
    vboxDriverLock(data);

    if (data->domainEventDispatching)
        ret = virDomainEventCallbackListMarkDelete(conn, data->domainEventCallbacks,
                                                   callback);
    else
        ret = virDomainEventCallbackListRemove(conn, data->domainEventCallbacks,
                                               callback);

    if (data->vboxCallback) {
        /* check count here of how many times register was called
         * and only on the last de-register do the un-register call
         */
        if (data->domainEventCallbacks && virDomainEventCallbackListCount(data->domainEventCallbacks) == 0) {
            data->vboxObj->vtbl->UnregisterCallback(data->vboxObj, data->vboxCallback);
            VBOX_RELEASE(data->vboxCallback);

            /* Remove the Event file handle on which we are listening as well */
            virEventRemoveHandle(data->fdWatch);
            data->fdWatch = -1;
        }
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

            ret = virDomainEventCallbackListAddID(conn, data->domainEventCallbacks,
                                                  dom, eventID,
                                                  callback, opaque, freecb);
            DEBUG("virDomainEventCallbackListAddID (ret = %d) ( conn: %p, "
                  "data->domainEventCallbacks: %p, callback: %p, opaque: %p, "
                  "freecb: %p )", ret, conn, data->domainEventCallbacks, callback,
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

    /* Locking has to be there as callbacks are not
     * really fully thread safe
     */
    vboxDriverLock(data);

    if (data->domainEventDispatching)
        ret = virDomainEventCallbackListMarkDeleteID(conn, data->domainEventCallbacks,
                                                     callbackID);
    else
        ret = virDomainEventCallbackListRemoveID(conn, data->domainEventCallbacks,
                                                 callbackID);

    if (data->vboxCallback) {
        /* check count here of how many times register was called
         * and only on the last de-register do the un-register call
         */
        if (data->domainEventCallbacks && virDomainEventCallbackListCount(data->domainEventCallbacks) == 0) {
            data->vboxObj->vtbl->UnregisterCallback(data->vboxObj, data->vboxCallback);
            VBOX_RELEASE(data->vboxCallback);

            /* Remove the Event file handle on which we are listening as well */
            virEventRemoveHandle(data->fdWatch);
            data->fdWatch = -1;
        }
    }

    vboxDriverUnlock(data);

    return ret;
}

#endif /* !(VBOX_API_VERSION == 2002) */

/**
 * The Network Functions here on
 */
static virDrvOpenStatus vboxNetworkOpen(virConnectPtr conn,
                                        virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                        int flags ATTRIBUTE_UNUSED) {
    vboxGlobalData *data = conn->privateData;

    if (STRNEQ(conn->driver->name, "VBOX"))
        goto cleanup;

    if ((data->pFuncs      == NULL) ||
        (data->vboxObj     == NULL) ||
        (data->vboxSession == NULL))
        goto cleanup;

    DEBUG0("network initialized");
    /* conn->networkPrivateData = some network specific data */
    return VIR_DRV_OPEN_SUCCESS;

cleanup:
    return VIR_DRV_OPEN_DECLINED;
}

static int vboxNetworkClose(virConnectPtr conn) {
    DEBUG0("network uninitialized");
    conn->networkPrivateData = NULL;
    return 0;
}

static int vboxNumOfNetworks(virConnectPtr conn) {
    VBOX_OBJECT_HOST_CHECK(conn, int, 0);
    PRUint32 networkInterfacesSize = 0;
    IHostNetworkInterface **networkInterfaces = NULL;
    int i = 0;

    host->vtbl->GetNetworkInterfaces(host, &networkInterfacesSize, &networkInterfaces);

    for (i = 0; i < networkInterfacesSize; i++) {
        if (networkInterfaces[i]) {
            PRUint32 interfaceType = 0;

            networkInterfaces[i]->vtbl->GetInterfaceType(networkInterfaces[i], &interfaceType);
            if (interfaceType == HostNetworkInterfaceType_HostOnly) {
                PRUint32 status = HostNetworkInterfaceStatus_Unknown;

                networkInterfaces[i]->vtbl->GetStatus(networkInterfaces[i], &status);

                if (status == HostNetworkInterfaceStatus_Up)
                    ret++;
            }

            VBOX_RELEASE(networkInterfaces[i]);
        }
    }

    VBOX_RELEASE(host);

    DEBUG("numActive: %d", ret);
    return ret;
}

static int vboxListNetworks(virConnectPtr conn, char **const names, int nnames) {
    VBOX_OBJECT_HOST_CHECK(conn, int, 0);
    PRUint32 networkInterfacesSize = 0;
    IHostNetworkInterface **networkInterfaces = NULL;
    int i = 0;

    host->vtbl->GetNetworkInterfaces(host, &networkInterfacesSize, &networkInterfaces);

    for (i = 0; (ret < nnames) && (i < networkInterfacesSize); i++) {
        if (networkInterfaces[i]) {
            PRUint32 interfaceType = 0;

            networkInterfaces[i]->vtbl->GetInterfaceType(networkInterfaces[i], &interfaceType);

            if (interfaceType == HostNetworkInterfaceType_HostOnly) {
                PRUint32 status = HostNetworkInterfaceStatus_Unknown;

                networkInterfaces[i]->vtbl->GetStatus(networkInterfaces[i], &status);

                if (status == HostNetworkInterfaceStatus_Up) {
                    char *nameUtf8       = NULL;
                    PRUnichar *nameUtf16 = NULL;

                    networkInterfaces[i]->vtbl->GetName(networkInterfaces[i], &nameUtf16);
                    VBOX_UTF16_TO_UTF8(nameUtf16, &nameUtf8);

                    DEBUG("nnames[%d]: %s", ret, nameUtf8);
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

    for (i = 0; i < networkInterfacesSize; i++)
        VBOX_RELEASE(networkInterfaces[i]);

    VBOX_RELEASE(host);

    return ret;
}

static int vboxNumOfDefinedNetworks(virConnectPtr conn) {
    VBOX_OBJECT_HOST_CHECK(conn, int, 0);
    PRUint32 networkInterfacesSize = 0;
    IHostNetworkInterface **networkInterfaces = NULL;
    int i = 0;

    host->vtbl->GetNetworkInterfaces(host, &networkInterfacesSize, &networkInterfaces);

    for (i = 0; i < networkInterfacesSize; i++) {
        if (networkInterfaces[i]) {
            PRUint32 interfaceType = 0;

            networkInterfaces[i]->vtbl->GetInterfaceType(networkInterfaces[i], &interfaceType);
            if (interfaceType == HostNetworkInterfaceType_HostOnly) {
                PRUint32 status = HostNetworkInterfaceStatus_Unknown;

                networkInterfaces[i]->vtbl->GetStatus(networkInterfaces[i], &status);

                if (status == HostNetworkInterfaceStatus_Down)
                    ret++;
            }

            VBOX_RELEASE(networkInterfaces[i]);
        }
    }

    VBOX_RELEASE(host);

    DEBUG("numActive: %d", ret);
    return ret;
}

static int vboxListDefinedNetworks(virConnectPtr conn, char **const names, int nnames) {
    VBOX_OBJECT_HOST_CHECK(conn, int, 0);
    PRUint32 networkInterfacesSize = 0;
    IHostNetworkInterface **networkInterfaces = NULL;
    int i = 0;

    host->vtbl->GetNetworkInterfaces(host, &networkInterfacesSize, &networkInterfaces);

    for (i = 0; (ret < nnames) && (i < networkInterfacesSize); i++) {
        if (networkInterfaces[i]) {
            PRUint32 interfaceType = 0;

            networkInterfaces[i]->vtbl->GetInterfaceType(networkInterfaces[i], &interfaceType);

            if (interfaceType == HostNetworkInterfaceType_HostOnly) {
                PRUint32 status = HostNetworkInterfaceStatus_Unknown;

                networkInterfaces[i]->vtbl->GetStatus(networkInterfaces[i], &status);

                if (status == HostNetworkInterfaceStatus_Down) {
                    char *nameUtf8       = NULL;
                    PRUnichar *nameUtf16 = NULL;

                    networkInterfaces[i]->vtbl->GetName(networkInterfaces[i], &nameUtf16);
                    VBOX_UTF16_TO_UTF8(nameUtf16, &nameUtf8);

                    DEBUG("nnames[%d]: %s", ret, nameUtf8);
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

    for (i = 0; i < networkInterfacesSize; i++)
        VBOX_RELEASE(networkInterfaces[i]);

    VBOX_RELEASE(host);

    return ret;
}

static virNetworkPtr vboxNetworkLookupByUUID(virConnectPtr conn, const unsigned char *uuid) {
    VBOX_OBJECT_HOST_CHECK(conn, virNetworkPtr, NULL);
    vboxIID *iid         = NULL;

#if VBOX_API_VERSION == 2002
    if (VIR_ALLOC(iid) < 0) {
        virReportOOMError();
        goto cleanup;
    }
#endif

    vboxIIDFromUUID(uuid, iid);

    /* TODO: "internal" networks are just strings and
     * thus can't do much with them
     */
    IHostNetworkInterface *networkInterface = NULL;

    host->vtbl->FindHostNetworkInterfaceById(host, iid, &networkInterface);
    if (networkInterface) {
        PRUint32 interfaceType = 0;

        networkInterface->vtbl->GetInterfaceType(networkInterface, &interfaceType);

        if (interfaceType == HostNetworkInterfaceType_HostOnly) {
            char *nameUtf8       = NULL;
            PRUnichar *nameUtf16 = NULL;

            networkInterface->vtbl->GetName(networkInterface, &nameUtf16);
            VBOX_UTF16_TO_UTF8(nameUtf16, &nameUtf8);

            ret = virGetNetwork(conn, nameUtf8, uuid);

            DEBUG("Network Name: %s", nameUtf8);
            DEBUGIID("Network UUID", iid);

            VBOX_UTF8_FREE(nameUtf8);
            VBOX_UTF16_FREE(nameUtf16);
        }

        VBOX_RELEASE(networkInterface);
    }

    VBOX_RELEASE(host);

#if VBOX_API_VERSION == 2002
cleanup:
#endif
    vboxIIDFree(iid);
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
            vboxIID *iid = NULL;

            networkInterface->vtbl->GetId(networkInterface, &iid);
            vboxIIDToUUID(uuid, iid);
            ret = virGetNetwork(conn, name, uuid);
            DEBUG("Network Name: %s", name);

            DEBUGIID("Network UUID", iid);
            vboxIIDUnalloc(iid);
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

    virNetworkDefPtr def = virNetworkDefParseString(xml);

    if (   (!def)
        || (def->forwardType != VIR_NETWORK_FORWARD_NONE))
        goto cleanup;

    /* the current limitation of hostonly network is that you can't
     * assign a name to it and it defaults to vboxnet*, for e.g:
     * vboxnet0, vboxnet1, etc. Also the UUID is assigned to it
     * automatically depending on the mac address and thus both
     * these paramters are ignored here for now.
     */

#if VBOX_API_VERSION == 2002
    if STREQ(def->name, "vboxnet0") {
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
    IProgress *progress = NULL;
    host->vtbl->CreateHostOnlyNetworkInterface(host, &networkInterface, &progress);

    if (progress) {
        progress->vtbl->WaitForCompletion(progress, -1);
        VBOX_RELEASE(progress);
    }
#endif /* VBOX_API_VERSION != 2002 */

    if (networkInterface) {
        unsigned char uuid[VIR_UUID_BUFLEN];
        char      *networkNameUtf8  = NULL;
        PRUnichar *networkNameUtf16 = NULL;
        vboxIID   *vboxnetiid       = NULL;

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
        if ((def->nranges >= 1) &&
            (def->ranges[0].start) &&
            (def->ranges[0].end)) {
            IDHCPServer *dhcpServer = NULL;

            data->vboxObj->vtbl->FindDHCPServerByNetworkName(data->vboxObj,
                                                             networkNameUtf16,
                                                             &dhcpServer);
            if (!dhcpServer) {
                /* create a dhcp server */
                data->vboxObj->vtbl->CreateDHCPServer(data->vboxObj,
                                                      networkNameUtf16,
                                                      &dhcpServer);
                DEBUG0("couldn't find dhcp server so creating one");
            }
            if (dhcpServer) {
                PRUnichar *ipAddressUtf16     = NULL;
                PRUnichar *networkMaskUtf16   = NULL;
                PRUnichar *fromIPAddressUtf16 = NULL;
                PRUnichar *toIPAddressUtf16   = NULL;
                PRUnichar *trunkTypeUtf16     = NULL;


                VBOX_UTF8_TO_UTF16(def->ipAddress, &ipAddressUtf16);
                VBOX_UTF8_TO_UTF16(def->netmask, &networkMaskUtf16);
                VBOX_UTF8_TO_UTF16(def->ranges[0].start, &fromIPAddressUtf16);
                VBOX_UTF8_TO_UTF16(def->ranges[0].end, &toIPAddressUtf16);
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

        if ((def->nhosts >= 1) &&
            (def->hosts[0].ip)) {
            PRUnichar *ipAddressUtf16   = NULL;
            PRUnichar *networkMaskUtf16 = NULL;

            VBOX_UTF8_TO_UTF16(def->netmask, &networkMaskUtf16);
            VBOX_UTF8_TO_UTF16(def->hosts[0].ip, &ipAddressUtf16);

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

        networkInterface->vtbl->GetId(networkInterface, &vboxnetiid);
        if (vboxnetiid) {
            vboxIIDToUUID(uuid, vboxnetiid);
            DEBUGIID("Real Network UUID", vboxnetiid);
            vboxIIDUnalloc(vboxnetiid);
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

    PRUnichar *networkInterfaceNameUtf16    = NULL;
    IHostNetworkInterface *networkInterface = NULL;

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

    PRUnichar *networkInterfaceNameUtf16    = NULL;
    IHostNetworkInterface *networkInterface = NULL;

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

static char *vboxNetworkDumpXML(virNetworkPtr network, int flags ATTRIBUTE_UNUSED) {
    VBOX_OBJECT_HOST_CHECK(network->conn, char *, NULL);
    virNetworkDefPtr def  = NULL;
    char *networkNameUtf8 = NULL;

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virAsprintf(&networkNameUtf8, "HostInterfaceNetworking-%s", network->name) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    PRUnichar *networkInterfaceNameUtf16    = NULL;
    IHostNetworkInterface *networkInterface = NULL;

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
                vboxIID *vboxnet0IID        = NULL;

                networkInterface->vtbl->GetId(networkInterface, &vboxnet0IID);
                vboxIIDToUUID(def->uuid, vboxnet0IID);

                VBOX_UTF8_TO_UTF16(networkNameUtf8 , &networkNameUtf16);

                def->forwardType = VIR_NETWORK_FORWARD_NONE;

                data->vboxObj->vtbl->FindDHCPServerByNetworkName(data->vboxObj,
                                                                 networkNameUtf16,
                                                                 &dhcpServer);
                if (dhcpServer) {
                    def->nranges = 1;
                    if (VIR_ALLOC_N(def->ranges, def->nranges) >=0 ) {
                        PRUnichar *ipAddressUtf16     = NULL;
                        PRUnichar *networkMaskUtf16   = NULL;
                        PRUnichar *fromIPAddressUtf16 = NULL;
                        PRUnichar *toIPAddressUtf16   = NULL;

                        dhcpServer->vtbl->GetIPAddress(dhcpServer, &ipAddressUtf16);
                        dhcpServer->vtbl->GetNetworkMask(dhcpServer, &networkMaskUtf16);
                        dhcpServer->vtbl->GetLowerIP(dhcpServer, &fromIPAddressUtf16);
                        dhcpServer->vtbl->GetUpperIP(dhcpServer, &toIPAddressUtf16);
                        /* Currently virtualbox supports only one dhcp server per network
                         * with contigious address space from start to end
                         */
                        VBOX_UTF16_TO_UTF8(ipAddressUtf16, &def->ipAddress);
                        VBOX_UTF16_TO_UTF8(networkMaskUtf16, &def->netmask);
                        VBOX_UTF16_TO_UTF8(fromIPAddressUtf16, &def->ranges[0].start);
                        VBOX_UTF16_TO_UTF8(toIPAddressUtf16, &def->ranges[0].end);

                        VBOX_UTF16_FREE(ipAddressUtf16);
                        VBOX_UTF16_FREE(networkMaskUtf16);
                        VBOX_UTF16_FREE(fromIPAddressUtf16);
                        VBOX_UTF16_FREE(toIPAddressUtf16);
                    } else {
                        def->nranges = 0;
                        virReportOOMError();
                    }

                    def->nhosts = 1;
                    if (VIR_ALLOC_N(def->hosts, def->nhosts) >=0 ) {
                        def->hosts[0].name = strdup(network->name);
                        if (def->hosts[0].name == NULL) {
                            VIR_FREE(def->hosts);
                            def->nhosts = 0;
                            virReportOOMError();
                        } else {
                            PRUnichar *macAddressUtf16 = NULL;
                            PRUnichar *ipAddressUtf16  = NULL;

                            networkInterface->vtbl->GetHardwareAddress(networkInterface, &macAddressUtf16);
                            networkInterface->vtbl->GetIPAddress(networkInterface, &ipAddressUtf16);

                            VBOX_UTF16_TO_UTF8(macAddressUtf16, &def->hosts[0].mac);
                            VBOX_UTF16_TO_UTF8(ipAddressUtf16, &def->hosts[0].ip);

                            VBOX_UTF16_FREE(macAddressUtf16);
                            VBOX_UTF16_FREE(ipAddressUtf16);
                        }
                    } else {
                        def->nhosts = 0;
                    }

                    VBOX_RELEASE(dhcpServer);
                } else {
                    PRUnichar *networkMaskUtf16 = NULL;
                    PRUnichar *ipAddressUtf16   = NULL;

                    networkInterface->vtbl->GetNetworkMask(networkInterface, &networkMaskUtf16);
                    networkInterface->vtbl->GetIPAddress(networkInterface, &ipAddressUtf16);

                    VBOX_UTF16_TO_UTF8(networkMaskUtf16, &def->netmask);
                    VBOX_UTF16_TO_UTF8(ipAddressUtf16, &def->ipAddress);

                    VBOX_UTF16_FREE(networkMaskUtf16);
                    VBOX_UTF16_FREE(ipAddressUtf16);
                }

                DEBUGIID("Network UUID", vboxnet0IID);
                vboxIIDUnalloc(vboxnet0IID);
                VBOX_UTF16_FREE(networkNameUtf16);
            } else {
                virReportOOMError();
            }
        }

        VBOX_RELEASE(networkInterface);
    }

    VBOX_UTF16_FREE(networkInterfaceNameUtf16);
    VBOX_RELEASE(host);

    ret = virNetworkDefFormat(def);

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
                                         int flags ATTRIBUTE_UNUSED) {
    vboxGlobalData *data = conn->privateData;

    if (STRNEQ(conn->driver->name, "VBOX"))
        goto cleanup;

    if ((data->pFuncs      == NULL) ||
        (data->vboxObj     == NULL) ||
        (data->vboxSession == NULL))
        goto cleanup;

    DEBUG0("vbox storage initialized");
    /* conn->storagePrivateData = some storage specific data */
    return VIR_DRV_OPEN_SUCCESS;

cleanup:
    return VIR_DRV_OPEN_DECLINED;
}

static int vboxStorageClose (virConnectPtr conn) {
    DEBUG0("vbox storage uninitialized");
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

        virUUIDParse(uuidstr, uuid);

        ret = virGetStoragePool(conn, name, uuid);
    }

    return ret;
}

static int vboxStoragePoolNumOfVolumes(virStoragePoolPtr pool) {
    VBOX_OBJECT_CHECK(pool->conn, int, -1);
    IHardDisk **hardDisks       = NULL;
    PRUint32 hardDiskCount      = 0;
    PRUint32 hardDiskAccessible = 0;
    nsresult rc;
    int i;

    rc = data->vboxObj->vtbl->GetHardDisks(data->vboxObj, &hardDiskCount, &hardDisks);
    if (NS_SUCCEEDED(rc)) {
        for (i = 0; i < hardDiskCount; ++i) {
            IHardDisk *hardDisk = hardDisks[i];
            if (hardDisk) {
                PRUint32 hddstate;

                VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetState, &hddstate);
                if (hddstate != MediaState_Inaccessible)
                    hardDiskAccessible++;

                VBOX_MEDIUM_RELEASE(hardDisk);
            }
        }
        hardDiskCount = 0;
    } else {
        hardDiskCount = -1;
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("could not get number of volumes in the pool: %s, rc=%08x"),
                  pool->name, (unsigned)rc);
    }

    if (hardDiskAccessible)
        ret = hardDiskAccessible;
    else
        ret = hardDiskCount;

    return ret;
}

static int vboxStoragePoolListVolumes(virStoragePoolPtr pool, char **const names, int nnames) {
    VBOX_OBJECT_CHECK(pool->conn, int, -1);
    IHardDisk **hardDisks  = NULL;
    PRUint32 hardDiskCount = 0;
    PRUint32 numActive     = 0;
    nsresult rc;
    int i;

    rc = data->vboxObj->vtbl->GetHardDisks(data->vboxObj, &hardDiskCount, &hardDisks);
    if (NS_SUCCEEDED(rc)) {
        for (i = 0; i < hardDiskCount && numActive < nnames; ++i) {
            IHardDisk *hardDisk = hardDisks[i];

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
                        DEBUG("nnames[%d]: %s", numActive, nameUtf8);
                        names[numActive] = strdup(nameUtf8);
                        if (names[numActive] == NULL) {
                            virReportOOMError();
                        } else {
                            numActive++;
                        }

                        VBOX_UTF8_FREE(nameUtf8);
                    }
                }
                VBOX_MEDIUM_RELEASE(hardDisk);
            }
        }
        hardDiskCount = 0;
    } else {
        hardDiskCount = -1;
        vboxError(VIR_ERR_INTERNAL_ERROR,
                  _("could not get the volume list in the pool: %s, rc=%08x"),
                  pool->name, (unsigned)rc);
    }

    if (numActive)
        ret = numActive;
    else
        ret = hardDiskCount;

    return ret;
}

static virStorageVolPtr vboxStorageVolLookupByName(virStoragePoolPtr pool, const char *name) {
    VBOX_OBJECT_CHECK(pool->conn, virStorageVolPtr, NULL);
    IHardDisk **hardDisks        = NULL;
    PRUint32 hardDiskCount       = 0;
    nsresult rc;
    int i;

    if(!name)
        return ret;

    rc = data->vboxObj->vtbl->GetHardDisks(data->vboxObj, &hardDiskCount, &hardDisks);
    if (NS_SUCCEEDED(rc)) {
        for (i = 0; i < hardDiskCount; ++i) {
            IHardDisk *hardDisk = hardDisks[i];

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
                        vboxIID *hddIID     = NULL;
                        char    *hddIIDUtf8 = NULL;

                        VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetId, &hddIID);

                        if (hddIID) {
                            vboxIIDtoUtf8(hddIID, &hddIIDUtf8);
                            vboxIIDUnalloc(hddIID);
                        }

                        if (hddIIDUtf8) {

                            ret = virGetStorageVol(pool->conn, pool->name, name, hddIIDUtf8);

                            DEBUG("virStorageVolPtr: %p", ret);
                            DEBUG("Storage Volume Name: %s", name);
                            DEBUG("Storage Volume key : %s", hddIIDUtf8);
                            DEBUG("Storage Volume Pool: %s", pool->name);

                            vboxIIDUtf8Free(hddIIDUtf8);
                        }

                        VBOX_UTF8_FREE(nameUtf8);
                        break;
                    }

                    if (nameUtf8)
                        VBOX_UTF8_FREE(nameUtf8);
                }
            }
        }

        for (i = 0; i < hardDiskCount; ++i)
            VBOX_MEDIUM_RELEASE(hardDisks[i]);
    }

    return ret;
}

static virStorageVolPtr vboxStorageVolLookupByKey(virConnectPtr conn, const char *key) {
    VBOX_OBJECT_CHECK(conn, virStorageVolPtr, NULL);
    vboxIID   *hddIID    = NULL;
    IHardDisk *hardDisk  = NULL;
    nsresult rc;

    if (!key)
        return ret;

#if VBOX_API_VERSION == 2002

    if (VIR_ALLOC(hddIID) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    unsigned char hddUUID[VIR_UUID_BUFLEN];

    virUUIDParse(key, hddUUID);
    vboxIIDFromUUID(hddUUID, hddIID);

#else  /* VBOX_API_VERSION != 2002 */

    VBOX_UTF8_TO_UTF16(key, &hddIID);
    if (!hddIID)
        return ret;

#endif /* VBOX_API_VERSION != 2002 */

    rc = data->vboxObj->vtbl->GetHardDisk(data->vboxObj, hddIID, &hardDisk);
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
                    DEBUG("Storage Volume Pool: %s", "default-pool");
                } else {
                    /* TODO: currently only one default pool and thus
                     * nothing here, change it when pools are supported
                     */
                }

                DEBUG("Storage Volume Name: %s", key);
                DEBUG("Storage Volume key : %s", hddNameUtf8);

                VBOX_UTF8_FREE(hddNameUtf8);
                VBOX_UTF16_FREE(hddNameUtf16);
            }
        }

        VBOX_MEDIUM_RELEASE(hardDisk);
    }

#if VBOX_API_VERSION == 2002
cleanup:
#endif  /* VBOX_API_VERSION == 2002 */
    vboxIIDFree(hddIID);
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

    rc = data->vboxObj->vtbl->FindHardDisk(data->vboxObj, hddPathUtf16, &hardDisk);
    if (NS_SUCCEEDED(rc)) {
        PRUint32 hddstate;

        VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetState, &hddstate);
        if (hddstate != MediaState_Inaccessible) {
            PRUnichar *hddNameUtf16 = NULL;
            char      *hddNameUtf8  = NULL;
            vboxIID   *hddIID       = NULL;
            char      *hddIIDUtf8   = NULL;

            VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetName, &hddNameUtf16);
            VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetId, &hddIID);

            if (hddNameUtf16) {
                VBOX_UTF16_TO_UTF8(hddNameUtf16, &hddNameUtf8);
                VBOX_UTF16_FREE(hddNameUtf16);
            }

            if (hddIID) {
                vboxIIDtoUtf8(hddIID, &hddIIDUtf8);
                vboxIIDUnalloc(hddIID);
            }

            if (hddIIDUtf8 && hddNameUtf8) {

                /* TODO: currently only one default pool and thus
                 * the check below, change it when pools are supported
                 */
                if (vboxStorageNumOfPools(conn) == 1)
                    ret = virGetStorageVol(conn, "default-pool", hddNameUtf8, hddIIDUtf8);

                DEBUG("Storage Volume Pool: %s", "default-pool");
                DEBUG("Storage Volume Name: %s", hddNameUtf8);
                DEBUG("Storage Volume key : %s", hddIIDUtf8);

            }

            if (hddNameUtf8)
                VBOX_UTF8_FREE(hddNameUtf8);

            if (hddIIDUtf8)
                vboxIIDUtf8Free(hddIIDUtf8);
        }

        VBOX_MEDIUM_RELEASE(hardDisk);
    }

    VBOX_UTF16_FREE(hddPathUtf16);

    return ret;
}

static virStorageVolPtr vboxStorageVolCreateXML(virStoragePoolPtr pool,
                                                const char *xml,
                                                unsigned int flags ATTRIBUTE_UNUSED) {
    VBOX_OBJECT_CHECK(pool->conn, virStorageVolPtr, NULL);
    virStorageVolDefPtr  def  = NULL;
    PRUnichar *hddFormatUtf16 = NULL;
    PRUnichar *hddNameUtf16   = NULL;
    virStoragePoolDef poolDef;
    nsresult rc;

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
            PRUint64   logicalSize = def->capacity / 1024 / 1024;
            PRUint32   variant     = HardDiskVariant_Standard;

            if (def->capacity == def->allocation)
                variant = HardDiskVariant_Fixed;

            rc = hardDisk->vtbl->CreateBaseStorage(hardDisk, logicalSize, variant, &progress);
            if (NS_SUCCEEDED(rc) && progress) {
                vboxIID *hddIID = NULL;
#if VBOX_API_VERSION == 2002
                nsresult resultCode;
#else
                PRInt32  resultCode;
#endif

                progress->vtbl->WaitForCompletion(progress, -1);
                progress->vtbl->GetResultCode(progress, &resultCode);

                if (NS_SUCCEEDED(resultCode)) {

                    rc = VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetId, &hddIID);
                    if (NS_SUCCEEDED(rc)) {
                        char *hddKey = NULL;

                        vboxIIDtoUtf8(hddIID, &hddKey);

                        if (hddKey)
                            ret = virGetStorageVol(pool->conn, pool->name, def->name, hddKey);

                        vboxIIDUtf8Free(hddKey);
                        vboxIIDUnalloc(hddIID);
                    }
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
                                unsigned int flags ATTRIBUTE_UNUSED) {
    VBOX_OBJECT_CHECK(vol->conn, int, -1);
    vboxIID   *hddIID    = NULL;
    IHardDisk *hardDisk  = NULL;
    int deregister = 0;
    nsresult rc;
    int i = 0;
    int j = 0;

    vboxUtf8toIID(vol->key, &hddIID);
    if (!hddIID)
        return ret;

    rc = data->vboxObj->vtbl->GetHardDisk(data->vboxObj, hddIID, &hardDisk);
    if (NS_SUCCEEDED(rc)) {
        PRUint32 hddstate;

        VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetState, &hddstate);
        if (hddstate != MediaState_Inaccessible) {
            PRUint32  machineIdsSize = 0;
            vboxIID **machineIds     = NULL;

            VBOX_MEDIUM_FUNC_ARG2(hardDisk, GetMachineIds, &machineIdsSize, &machineIds);

            for (i = 0; i < machineIdsSize; i++) {
                IMachine *machine = NULL;

                rc = data->vboxObj->vtbl->OpenSession(data->vboxObj, data->vboxSession, machineIds[i]);
                if (NS_SUCCEEDED(rc)) {

                    rc = data->vboxSession->vtbl->GetMachine(data->vboxSession, &machine);
                    if (NS_SUCCEEDED(rc)) {
                        PRUint32 hddAttachSize = 0;
                        IHardDiskAttachment **hddAttachments = NULL;

#if VBOX_API_VERSION < 3001
                        machine->vtbl->GetHardDiskAttachments(machine, &hddAttachSize, &hddAttachments);
#else  /* VBOX_API_VERSION >= 3001 */
                        machine->vtbl->GetMediumAttachments(machine, &hddAttachSize, &hddAttachments);
#endif /* VBOX_API_VERSION >= 3001 */
                        for (j = 0; j < hddAttachSize; j++) {
                            IHardDiskAttachment *hddAttachment = hddAttachments[j];

                            if (hddAttachment) {
                                IHardDisk *hdd = NULL;

#if VBOX_API_VERSION < 3001
                                rc = hddAttachment->vtbl->GetHardDisk(hddAttachment, &hdd);
#else  /* VBOX_API_VERSION >= 3001 */
                                rc = hddAttachment->vtbl->GetMedium(hddAttachment, &hdd);
#endif /* VBOX_API_VERSION >= 3001 */
                                if (NS_SUCCEEDED(rc) && hdd) {
                                    vboxIID *iid = NULL;

                                    VBOX_MEDIUM_FUNC_ARG1(hdd, GetId, &iid);
                                    if (iid) {

                                            DEBUGIID("HardDisk (to delete) UUID", hddIID);
                                            DEBUGIID("HardDisk (currently processing) UUID", iid);

                                        if (vboxIIDEqual(hddIID, iid)) {
                                            PRUnichar *controller = NULL;
                                            PRInt32    port       = 0;
                                            PRInt32    device     = 0;

                                            DEBUGIID("Found HardDisk to delete, UUID", hddIID);

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
                                                DEBUG0("saving machine settings");
                                            }

                                            if (NS_SUCCEEDED(rc)) {
                                                deregister++;
                                                DEBUG("deregistering hdd:%d", deregister);
                                            }

                                            if (controller)
                                                VBOX_UTF16_FREE(controller);
                                        }
                                        vboxIIDUnalloc(iid);
                                    }
                                    VBOX_MEDIUM_RELEASE(hdd);
                                }
                                VBOX_RELEASE(hddAttachment);
                            }
                        }
                        VBOX_RELEASE(machine);
                    }
                    data->vboxSession->vtbl->Close(data->vboxSession);
                }
            }

            for (i = 0; i < machineIdsSize; i++)
                if (machineIds[i])
                    vboxIIDUnalloc(machineIds[i]);

            if (machineIdsSize == 0 || machineIdsSize == deregister) {
                IProgress *progress = NULL;

                rc = hardDisk->vtbl->DeleteStorage(hardDisk, &progress);

                if (NS_SUCCEEDED(rc) && progress) {
                    progress->vtbl->WaitForCompletion(progress, -1);
                    VBOX_RELEASE(progress);
                    DEBUGIID("HardDisk deleted, UUID", hddIID);
                    ret = 0;
                }
            }

        }

        VBOX_MEDIUM_RELEASE(hardDisk);
    }

    vboxIIDUtf16Free(hddIID);

    return ret;
}

static int vboxStorageVolGetInfo(virStorageVolPtr vol, virStorageVolInfoPtr info) {
    VBOX_OBJECT_CHECK(vol->conn, int, -1);
    IHardDisk *hardDisk  = NULL;
    vboxIID   *hddIID    = NULL;
    nsresult rc;

    if (!info)
        return ret;

    vboxUtf8toIID(vol->key, &hddIID);
    if (!hddIID)
        return ret;

    rc = data->vboxObj->vtbl->GetHardDisk(data->vboxObj, hddIID, &hardDisk);
    if (NS_SUCCEEDED(rc)) {
        PRUint32 hddstate;

        VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetState, &hddstate);
        if (hddstate != MediaState_Inaccessible) {
            PRUint64 hddLogicalSize;
            PRUint64 hddActualSize;

            info->type = VIR_STORAGE_VOL_FILE;

            hardDisk->vtbl->GetLogicalSize(hardDisk, &hddLogicalSize);
            info->capacity = hddLogicalSize * 1024 * 1024; /* MB => Bytes */

            VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetSize, &hddActualSize);
            info->allocation = hddActualSize;

            ret = 0;

            DEBUG("Storage Volume Name: %s", vol->name);
            DEBUG("Storage Volume Type: %s", info->type == VIR_STORAGE_VOL_BLOCK ? "Block" : "File");
            DEBUG("Storage Volume Capacity: %llu", info->capacity);
            DEBUG("Storage Volume Allocation: %llu", info->allocation);
        }

        VBOX_MEDIUM_RELEASE(hardDisk);
    }

    vboxIIDUtf16Free(hddIID);

    return ret;
}

static char *vboxStorageVolGetXMLDesc(virStorageVolPtr vol, unsigned int flags ATTRIBUTE_UNUSED) {
    VBOX_OBJECT_CHECK(vol->conn, char *, NULL);
    IHardDisk *hardDisk  = NULL;
    vboxIID   *hddIID    = NULL;
    virStoragePoolDef pool;
    virStorageVolDef def;
    int defOk = 0;
    nsresult rc;

    memset(&pool, 0, sizeof(pool));
    memset(&def, 0, sizeof(def));

    vboxUtf8toIID(vol->key, &hddIID);
    if (!hddIID)
        return ret;

    rc = data->vboxObj->vtbl->GetHardDisk(data->vboxObj, hddIID, &hardDisk);
    if (NS_SUCCEEDED(rc)) {
        PRUint32 hddstate;

        VBOX_MEDIUM_FUNC_ARG1(hardDisk, GetState, &hddstate);
        if (NS_SUCCEEDED(rc) && hddstate != MediaState_Inaccessible) {
            PRUnichar *hddFormatUtf16 = NULL;
            PRUint64 hddLogicalSize;
            PRUint64 hddActualSize;

            /* since there is currently one default pool now
             * and virStorageVolDefFormat() just checks it type
             * so just assign it for now, change the behaviour
             * when vbox supports pools.
             */
            pool.type = VIR_STORAGE_POOL_DIR;
            def.type = VIR_STORAGE_VOL_FILE;
            defOk = 1;

            rc = hardDisk->vtbl->GetLogicalSize(hardDisk, &hddLogicalSize);
            if (NS_SUCCEEDED(rc) && defOk)
                def.capacity = hddLogicalSize * 1024 * 1024; /* MB => Bytes */
            else
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

                    DEBUG("Storage Volume Format: %s", hddFormatUtf8);

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

    vboxIIDUtf16Free(hddIID);

    if (defOk)
        ret = virStorageVolDefFormat(&pool, &def);

    return ret;
}

static char *vboxStorageVolGetPath(virStorageVolPtr vol) {
    VBOX_OBJECT_CHECK(vol->conn, char *, NULL);
    IHardDisk *hardDisk  = NULL;
    vboxIID   *hddIID    = NULL;
    nsresult rc;

    vboxUtf8toIID(vol->key, &hddIID);
    if (!hddIID)
        return ret;

    rc = data->vboxObj->vtbl->GetHardDisk(data->vboxObj, hddIID, &hardDisk);
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

                DEBUG("Storage Volume Name: %s", vol->name);
                DEBUG("Storage Volume Path: %s", hddLocationUtf8);
                DEBUG("Storage Volume Pool: %s", vol->pool);

                VBOX_UTF8_FREE(hddLocationUtf8);
            }

            VBOX_UTF16_FREE(hddLocationUtf16);
        }

        VBOX_MEDIUM_RELEASE(hardDisk);
    }

    vboxIIDUtf16Free(hddIID);

    return ret;
}

/**
 * Function Tables
 */

virDriver NAME(Driver) = {
    VIR_DRV_VBOX,
    "VBOX",
    vboxOpen, /* open */
    vboxClose, /* close */
    NULL, /* supports_feature */
    NULL, /* type */
    vboxGetVersion, /* version */
    NULL, /* libvirtVersion (impl. in libvirt.c) */
    virGetHostname, /* getHostname */
    vboxGetMaxVcpus, /* getMaxVcpus */
    nodeGetInfo, /* nodeGetInfo */
    vboxGetCapabilities, /* getCapabilities */
    vboxListDomains, /* listDomains */
    vboxNumOfDomains, /* numOfDomains */
    vboxDomainCreateXML, /* domainCreateXML */
    vboxDomainLookupByID, /* domainLookupByID */
    vboxDomainLookupByUUID, /* domainLookupByUUID */
    vboxDomainLookupByName, /* domainLookupByName */
    vboxDomainSuspend, /* domainSuspend */
    vboxDomainResume, /* domainResume */
    vboxDomainShutdown, /* domainShutdown */
    vboxDomainReboot, /* domainReboot */
    vboxDomainDestroy, /* domainDestroy */
    vboxDomainGetOSType, /* domainGetOSType */
    NULL, /* domainGetMaxMemory */
    NULL, /* domainSetMaxMemory */
    vboxDomainSetMemory, /* domainSetMemory */
    vboxDomainGetInfo, /* domainGetInfo */
    vboxDomainSave, /* domainSave */
    NULL, /* domainRestore */
    NULL, /* domainCoreDump */
    vboxDomainSetVcpus, /* domainSetVcpus */
    NULL, /* domainPinVcpu */
    NULL, /* domainGetVcpus */
    vboxDomainGetMaxVcpus, /* domainGetMaxVcpus */
    NULL, /* domainGetSecurityLabel */
    NULL, /* nodeGetSecurityModel */
    vboxDomainDumpXML, /* domainDumpXML */
    NULL, /* domainXMLFromNative */
    NULL, /* domainXMLToNative */
    vboxListDefinedDomains, /* listDefinedDomains */
    vboxNumOfDefinedDomains, /* numOfDefinedDomains */
    vboxDomainCreate, /* domainCreate */
    vboxDomainDefineXML, /* domainDefineXML */
    vboxDomainUndefine, /* domainUndefine */
    vboxDomainAttachDevice, /* domainAttachDevice */
    vboxDomainAttachDeviceFlags, /* domainAttachDeviceFlags */
    vboxDomainDetachDevice, /* domainDetachDevice */
    vboxDomainDetachDeviceFlags, /* domainDetachDeviceFlags */
    vboxDomainUpdateDeviceFlags, /* domainUpdateDeviceFlags */
    NULL, /* domainGetAutostart */
    NULL, /* domainSetAutostart */
    NULL, /* domainGetSchedulerType */
    NULL, /* domainGetSchedulerParameters */
    NULL, /* domainSetSchedulerParameters */
    NULL, /* domainMigratePrepare */
    NULL, /* domainMigratePerform */
    NULL, /* domainMigrateFinish */
    NULL, /* domainBlockStats */
    NULL, /* domainInterfaceStats */
    NULL, /* domainMemoryStats */
    NULL, /* domainBlockPeek */
    NULL, /* domainMemoryPeek */
    nodeGetCellsFreeMemory, /* nodeGetCellsFreeMemory */
    nodeGetFreeMemory,  /* getFreeMemory */
#if VBOX_API_VERSION == 2002
    NULL, /* domainEventRegister */
    NULL, /* domainEventDeregister */
#else
    vboxDomainEventRegister, /* domainEventRegister */
    vboxDomainEventDeregister, /* domainEventDeregister */
#endif
    NULL, /* domainMigratePrepare2 */
    NULL, /* domainMigrateFinish2 */
    NULL, /* nodeDeviceDettach */
    NULL, /* nodeDeviceReAttach */
    NULL, /* nodeDeviceReset */
    NULL, /* domainMigratePrepareTunnel */
    vboxIsEncrypted, /* isEncrypted */
    vboxIsSecure, /* isSecure */
    vboxDomainIsActive, /* domainIsActive */
    vboxDomainIsPersistent, /* domainIsPersistent */
    NULL, /* cpuCompare */
    NULL, /* cpuBaseline */
    NULL, /* domainGetJobInfo */
    NULL, /* domainAbortJob */
    NULL, /* domainMigrateSetMaxDowntime */
#if VBOX_API_VERSION == 2002
    NULL, /* domainEventRegisterAny */
    NULL, /* domainEventDeregisterAny */
#else
    vboxDomainEventRegisterAny, /* domainEventRegisterAny */
    vboxDomainEventDeregisterAny, /* domainEventDeregisterAny */
#endif
    NULL, /* domainManagedSave */
    NULL, /* domainHasManagedSaveImage */
    NULL, /* domainManagedSaveRemove */
    vboxDomainSnapshotCreateXML, /* domainSnapshotCreateXML */
    vboxDomainSnapshotDumpXML, /* domainSnapshotDumpXML */
    vboxDomainSnapshotNum, /* domainSnapshotNum */
    vboxDomainSnapshotListNames, /* domainSnapshotListNames */
    vboxDomainSnapshotLookupByName, /* domainSnapshotLookupByName */
    vboxDomainHasCurrentSnapshot, /* domainHasCurrentSnapshot */
    vboxDomainSnapshotCurrent, /* domainSnapshotCurrent */
    vboxDomainRevertToSnapshot, /* domainRevertToSnapshot */
    vboxDomainSnapshotDelete, /* domainSnapshotDelete */
};

virNetworkDriver NAME(NetworkDriver) = {
    "VBOX",
    .open                   = vboxNetworkOpen,
    .close                  = vboxNetworkClose,
    .numOfNetworks          = vboxNumOfNetworks,
    .listNetworks           = vboxListNetworks,
    .numOfDefinedNetworks   = vboxNumOfDefinedNetworks,
    .listDefinedNetworks    = vboxListDefinedNetworks,
    .networkLookupByUUID    = vboxNetworkLookupByUUID,
    .networkLookupByName    = vboxNetworkLookupByName,
    .networkCreateXML       = vboxNetworkCreateXML,
    .networkDefineXML       = vboxNetworkDefineXML,
    .networkUndefine        = vboxNetworkUndefine,
    .networkCreate          = vboxNetworkCreate,
    .networkDestroy         = vboxNetworkDestroy,
    .networkDumpXML         = vboxNetworkDumpXML,
    .networkGetBridgeName   = NULL,
    .networkGetAutostart    = NULL,
    .networkSetAutostart    = NULL
};

virStorageDriver NAME(StorageDriver) = {
    .name               = "VBOX",
    .open               = vboxStorageOpen,
    .close              = vboxStorageClose,
    .numOfPools         = vboxStorageNumOfPools,
    .listPools          = vboxStorageListPools,
    .numOfDefinedPools  = NULL,
    .listDefinedPools   = NULL,
    .findPoolSources    = NULL,
    .poolLookupByName   = vboxStoragePoolLookupByName,
    .poolLookupByUUID   = NULL,
    .poolLookupByVolume = NULL,
    .poolCreateXML      = NULL,
    .poolDefineXML      = NULL,
    .poolBuild          = NULL,
    .poolUndefine       = NULL,
    .poolCreate         = NULL,
    .poolDestroy        = NULL,
    .poolDelete         = NULL,
    .poolRefresh        = NULL,
    .poolGetInfo        = NULL,
    .poolGetXMLDesc     = NULL,
    .poolGetAutostart   = NULL,
    .poolSetAutostart   = NULL,
    .poolNumOfVolumes   = vboxStoragePoolNumOfVolumes,
    .poolListVolumes    = vboxStoragePoolListVolumes,

    .volLookupByName    = vboxStorageVolLookupByName,
    .volLookupByKey     = vboxStorageVolLookupByKey,
    .volLookupByPath    = vboxStorageVolLookupByPath,
    .volCreateXML       = vboxStorageVolCreateXML,
    .volCreateXMLFrom   = NULL,
    .volDelete          = vboxStorageVolDelete,
    .volGetInfo         = vboxStorageVolGetInfo,
    .volGetXMLDesc      = vboxStorageVolGetXMLDesc,
    .volGetPath         = vboxStorageVolGetPath
};
