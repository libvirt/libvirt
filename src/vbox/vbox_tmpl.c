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
#if VBOX_API_VERSION == 4000000
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
#elif VBOX_API_VERSION == 5000000
# include "vbox_CAPI_v5_0.h"
#elif VBOX_API_VERSION == 5001000
# include "vbox_CAPI_v5_1.h"
#elif VBOX_API_VERSION == 5002000
# include "vbox_CAPI_v5_2.h"
#else
# error "Unsupport VBOX_API_VERSION"
#endif

/* Include this *last* or we'll get the wrong vbox_CAPI_*.h. */
#include "vbox_glue.h"

#if VBOX_API_VERSION < 4003000
typedef IUSBController IUSBCommon;
#else /* VBOX_API_VERSION >= 4003000 */
typedef IUSBDeviceFilters IUSBCommon;
#endif /* VBOX_API_VERSION >= 4003000 */


#include "vbox_uniformed_api.h"

#define VIR_FROM_THIS                   VIR_FROM_VBOX

VIR_LOG_INIT("vbox.vbox_tmpl");

#define vboxUnsupported() \
    VIR_WARN("No %s in current vbox version %d.", __FUNCTION__, VBOX_API_VERSION);

#define VBOX_UTF16_FREE(arg) \
    do { \
        if (arg) { \
            data->pFuncs->pfnUtf16Free(arg); \
            (arg) = NULL; \
        } \
    } while (0)

#define VBOX_UTF8_FREE(arg) \
    do { \
        if (arg) { \
            data->pFuncs->pfnUtf8Free(arg); \
            (arg) = NULL; \
        } \
    } while (0)

#define VBOX_UTF16_TO_UTF8(arg1, arg2)  data->pFuncs->pfnUtf16ToUtf8(arg1, arg2)
#define VBOX_UTF8_TO_UTF16(arg1, arg2)  data->pFuncs->pfnUtf8ToUtf16(arg1, arg2)

#define VBOX_RELEASE(arg) \
    do { \
        if (arg) { \
            (arg)->vtbl->nsisupports.Release((nsISupports *)(arg)); \
            (arg) = NULL; \
        } \
    } while (0)

#define VBOX_MEDIUM_RELEASE(arg) VBOX_RELEASE(arg)

#define DEBUGPRUnichar(msg, strUtf16) \
if (strUtf16) {\
    char *strUtf8 = NULL;\
\
    data->pFuncs->pfnUtf16ToUtf8(strUtf16, &strUtf8);\
    if (strUtf8) {\
        VIR_DEBUG("%s: %s", msg, strUtf8);\
        data->pFuncs->pfnUtf8Free(strUtf8);\
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

#define VBOX_IID_INITIALIZER { NULL, true }

/* default RDP port range to use for auto-port setting */
#define VBOX_RDP_AUTOPORT_RANGE "3389-3689"

static void
_vboxIIDUnalloc(vboxDriverPtr data, vboxIID *iid)
{
    if (iid->value != NULL && iid->owner)
        data->pFuncs->pfnUtf16Free(iid->value);

    iid->value = NULL;
    iid->owner = true;
}

static void
_vboxIIDToUUID(vboxDriverPtr data, vboxIID *iid,
               unsigned char *uuid)
{
    char *utf8 = NULL;

    data->pFuncs->pfnUtf16ToUtf8(iid->value, &utf8);

    ignore_value(virUUIDParse(utf8, uuid));

    data->pFuncs->pfnUtf8Free(utf8);
}

static void
_vboxIIDFromUUID(vboxDriverPtr data, vboxIID *iid,
                 const unsigned char *uuid)
{
    char utf8[VIR_UUID_STRING_BUFLEN];

    _vboxIIDUnalloc(data, iid);

    virUUIDFormat(uuid, utf8);

    data->pFuncs->pfnUtf8ToUtf16(utf8, &iid->value);
}

static bool
_vboxIIDIsEqual(vboxDriverPtr data, vboxIID *iid1,
                vboxIID *iid2)
{
    unsigned char uuid1[VIR_UUID_BUFLEN];
    unsigned char uuid2[VIR_UUID_BUFLEN];

    /* Note: we can't directly compare the utf8 strings here
     * cause the two UUID's may have separators as space or '-'
     * or mixture of both and we don't want to fail here by
     * using direct string comparison. Here virUUIDParse() takes
     * care of these cases. */
    _vboxIIDToUUID(data, iid1, uuid1);
    _vboxIIDToUUID(data, iid2, uuid2);

    return memcmp(uuid1, uuid2, VIR_UUID_BUFLEN) == 0;
}

static void
_vboxIIDFromArrayItem(vboxDriverPtr data, vboxIID *iid,
                      vboxArray *array, int idx)
{
    _vboxIIDUnalloc(data, iid);

    iid->value = array->items[idx];
    iid->owner = false;
}

#define vboxIIDUnalloc(iid) _vboxIIDUnalloc(data, iid)
#define vboxIIDToUUID(iid, uuid) _vboxIIDToUUID(data, iid, uuid)
#define vboxIIDFromUUID(iid, uuid) _vboxIIDFromUUID(data, iid, uuid)
#define vboxIIDIsEqual(iid1, iid2) _vboxIIDIsEqual(data, iid1, iid2)
#define vboxIIDFromArrayItem(iid, array, idx) \
    _vboxIIDFromArrayItem(data, iid, array, idx)
#define DEBUGIID(msg, strUtf16) DEBUGPRUnichar(msg, strUtf16)

/**
 * Converts int to Utf-16 string
 */
static PRUnichar *PRUnicharFromInt(PCVBOXXPCOM pFuncs, int n) {
    PRUnichar *strUtf16 = NULL;
    char s[24];

    snprintf(s, sizeof(s), "%d", n);

    pFuncs->pfnUtf8ToUtf16(s, &strUtf16);

    return strUtf16;
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


static int
vboxGetActiveVRDEServerPort(ISession *session, IMachine *machine)
{
    nsresult rc;
    PRInt32 port = -1;
    IVRDEServerInfo *vrdeInfo = NULL;
    IConsole *console = NULL;

    rc = machine->vtbl->LockMachine(machine, session, LockType_Shared);
    if (NS_FAILED(rc)) {
        VIR_WARN("Could not obtain shared lock on VBox VM, rc=%08x", rc);
        return -1;
    }

    rc = session->vtbl->GetConsole(session, &console);
    if (NS_FAILED(rc)) {
        VIR_WARN("Could not get VBox session console, rc=%08x", rc);
        goto cleanup;
    }

    /* it may be null if VM is not running */
    if (!console)
        goto cleanup;

    rc = console->vtbl->GetVRDEServerInfo(console, &vrdeInfo);

    if (NS_FAILED(rc) || !vrdeInfo) {
        VIR_WARN("Could not get VBox VM VRDEServerInfo, rc=%08x", rc);
        goto cleanup;
    }

    rc = vrdeInfo->vtbl->GetPort(vrdeInfo, &port);

    if (NS_FAILED(rc)) {
        VIR_WARN("Could not read port from VRDEServerInfo, rc=%08x", rc);
        goto cleanup;
    }

 cleanup:
    VBOX_RELEASE(console);
    VBOX_RELEASE(vrdeInfo);
    session->vtbl->UnlockMachine(session);

    return port;
}


static int
_vboxDomainSnapshotRestore(virDomainPtr dom,
                          IMachine *machine,
                          ISnapshot *snapshot)
{
    vboxDriverPtr data = dom->conn->privateData;
#if VBOX_API_VERSION < 5000000
    IConsole *console = NULL;
#endif /*VBOX_API_VERSION < 5000000*/
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

    rc = machine->vtbl->LockMachine(machine, data->vboxSession, LockType_Write);
#if VBOX_API_VERSION < 5000000
    if (NS_SUCCEEDED(rc))
        rc = data->vboxSession->vtbl->GetConsole(data->vboxSession, &console);
#endif /*VBOX_API_VERSION < 5000000*/
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not open VirtualBox session with domain %s"),
                       dom->name);
        goto cleanup;
    }

#if VBOX_API_VERSION < 5000000
    rc = console->vtbl->RestoreSnapshot(console, snapshot, &progress);
#elif VBOX_API_VERSION >= 5000000  /*VBOX_API_VERSION < 5000000*/
    rc = machine->vtbl->RestoreSnapshot(machine, snapshot, &progress);
#endif /*VBOX_API_VERSION >= 5000000*/

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
#if VBOX_API_VERSION < 5000000
    VBOX_RELEASE(console);
#endif /*VBOX_API_VERSION < 5000000*/
    data->vboxSession->vtbl->UnlockMachine(data->vboxSession);
    vboxIIDUnalloc(&domiid);
    return ret;
}

static nsresult
_unregisterMachine(vboxDriverPtr data, vboxIID *iid, IMachine **machine)
{
    nsresult rc;
    vboxArray media = VBOX_ARRAY_INITIALIZER;
    size_t i;

    rc = data->vboxObj->vtbl->FindMachine(data->vboxObj, iid->value, machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        return rc;
    }

    rc = vboxArrayGetWithUintArg(&media, *machine, (*machine)->vtbl->Unregister,
                                 CleanupMode_DetachAllReturnHardDisksOnly);

    if (NS_FAILED(rc))
        goto cleanup;

    /* close each medium attached to VM to remove from media registry */
    for (i = 0; i < media.count; i++) {
        IMedium *medium = media.items[i];

        if (!medium)
            continue;

        /* it's ok to ignore failure here - e.g. it may be used by another VM */
        ignore_value(medium->vtbl->Close(medium));
    }

 cleanup:
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
#ifdef WIN32
    SAFEARRAY *safeArray = NULL;
    typedef HRESULT __stdcall (*IMachine_Delete)(IMachine *self,
                                                 SAFEARRAY **media,
                                                 IProgress **progress);

# if VBOX_API_VERSION < 4003000
    ((IMachine_Delete)machine->vtbl->Delete)(machine, &safeArray, &progress);
# else
    ((IMachine_Delete)machine->vtbl->DeleteConfig)(machine, &safeArray, &progress);
# endif
#else
    /* XPCOM doesn't like NULL as an array, even when the array size is 0.
     * Instead pass it a dummy array to avoid passing NULL. */
    IMedium *array[] = { NULL };
# if VBOX_API_VERSION < 4003000
    machine->vtbl->Delete(machine, 0, array, &progress);
# else
    machine->vtbl->DeleteConfig(machine, 0, array, &progress);
# endif
#endif
    if (progress != NULL) {
        progress->vtbl->WaitForCompletion(progress, -1);
        VBOX_RELEASE(progress);
    }
}

static int _pfnInitialize(vboxDriverPtr driver)
{
    if (!(driver->pFuncs = g_pfnGetFunctions(VBOX_XPCOMC_VERSION)))
        return -1;
#if VBOX_API_VERSION == 4002020 || VBOX_API_VERSION >= 4004004
    nsresult rc;

    rc = driver->pFuncs->pfnClientInitialize(IVIRTUALBOXCLIENT_IID_STR,
                                             &driver->vboxClient);

    if (NS_FAILED(rc)) {
        return -1;
    } else {
        driver->vboxClient->vtbl->GetVirtualBox(driver->vboxClient, &driver->vboxObj);
        driver->vboxClient->vtbl->GetSession(driver->vboxClient, &driver->vboxSession);
    }
#else
    driver->pFuncs->pfnComInitialize(IVIRTUALBOX_IID_STR, &driver->vboxObj,
                                     ISESSION_IID_STR, &driver->vboxSession);
#endif

    return 0;
}

static void _pfnUninitialize(vboxDriverPtr data)
{
    if (data->pFuncs) {
#if VBOX_API_VERSION == 4002020 || VBOX_API_VERSION >= 4003004
        VBOX_RELEASE(data->vboxObj);
        VBOX_RELEASE(data->vboxSession);
        VBOX_RELEASE(data->vboxClient);

        data->pFuncs->pfnClientUninitialize();
#else
        data->pFuncs->pfnComUninitialize();
#endif
    }
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

static void _vboxIIDInitialize(vboxIID *iid)
{
    memset(iid, 0, sizeof(vboxIID));
    iid->owner = true;
}

static void _DEBUGIID(vboxDriverPtr data, const char *msg, vboxIID *iid)
{
    DEBUGPRUnichar(msg, iid->value);
}

static void
_vboxIIDToUtf8(vboxDriverPtr data ATTRIBUTE_UNUSED,
               vboxIID *iid ATTRIBUTE_UNUSED,
               char **utf8 ATTRIBUTE_UNUSED)
{
    data->pFuncs->pfnUtf16ToUtf8(iid->value, utf8);
}

static nsresult
_vboxArrayGetWithIIDArg(vboxArray *array, void *self, void *getter, vboxIID *iid)
{
    return vboxArrayGetWithPtrArg(array, self, getter, iid->value);
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

static void* _handleMachineGetStorageControllers(IMachine *machine)
{
    return machine->vtbl->GetStorageControllers;
}

static void* _handleMachineGetMediumAttachments(IMachine *machine)
{
    return machine->vtbl->GetMediumAttachments;
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
    return medium->vtbl->GetChildren;
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

static nsresult
_virtualboxGetMachine(IVirtualBox *vboxObj, vboxIID *iid, IMachine **machine)
{
    return vboxObj->vtbl->FindMachine(vboxObj, iid->value, machine);
}

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
_virtualboxCreateMachine(vboxDriverPtr data, virDomainDefPtr def, IMachine **machine, char *uuidstr ATTRIBUTE_UNUSED)
{
    vboxIID iid = VBOX_IID_INITIALIZER;
    PRUnichar *machineNameUtf16 = NULL;
    nsresult rc = -1;

    VBOX_UTF8_TO_UTF16(def->name, &machineNameUtf16);
    vboxIIDFromUUID(&iid, def->uuid);
    {
#if VBOX_API_VERSION >= 4000000 && VBOX_API_VERSION < 4002000
        PRBool override = PR_FALSE;
        rc = data->vboxObj->vtbl->CreateMachine(data->vboxObj,
                                                NULL,
                                                machineNameUtf16,
                                                NULL,
                                                iid.value,
                                                override,
                                                machine);
#else /* VBOX_API_VERSION >= 4002000 */
        char *createFlags = NULL;
        PRUnichar *createFlagsUtf16 = NULL;

        if (virAsprintf(&createFlags,
                        "UUID=%s,forceOverwrite=0", uuidstr) < 0)
            goto cleanup;
        VBOX_UTF8_TO_UTF16(createFlags, &createFlagsUtf16);
        rc = data->vboxObj->vtbl->CreateMachine(data->vboxObj,
                                                NULL,
                                                machineNameUtf16,
                                                0,
                                                nsnull,
                                                nsnull,
                                                createFlagsUtf16,
                                                machine);
 cleanup:
        VIR_FREE(createFlags);
#endif /* VBOX_API_VERSION >= 4002000 */
    }
    VBOX_UTF16_FREE(machineNameUtf16);
    vboxIIDUnalloc(&iid);
    return rc;
}

static nsresult
_virtualboxCreateHardDisk(IVirtualBox *vboxObj, PRUnichar *format,
                          PRUnichar *location, IMedium **medium)
{
    /* In vbox 2.2 and 3.0, this function will create a IHardDisk object.
     * In vbox 3.1 and later, this function will create a IMedium object.
     */
#if VBOX_API_VERSION < 5000000
    return vboxObj->vtbl->CreateHardDisk(vboxObj, format, location, medium);
#elif VBOX_API_VERSION >= 5000000 /*VBOX_API_VERSION >= 5000000*/
    return vboxObj->vtbl->CreateMedium(vboxObj, format, location,
                                       AccessMode_ReadWrite,
                                       DeviceType_HardDisk, medium);
#endif /*VBOX_API_VERSION >= 5000000*/
}

static nsresult
_virtualboxRegisterMachine(IVirtualBox *vboxObj, IMachine *machine)
{
    return vboxObj->vtbl->RegisterMachine(vboxObj, machine);
}

static nsresult
_virtualboxFindHardDisk(IVirtualBox *vboxObj,
                        PRUnichar *location,
                        PRUint32 deviceType,
                        PRUint32 accessMode ATTRIBUTE_UNUSED,
                        IMedium **medium)
{
#if VBOX_API_VERSION < 4002000
    return vboxObj->vtbl->FindMedium(vboxObj, location, deviceType, medium);
#else /* VBOX_API_VERSION >= 4002000 */
    return vboxObj->vtbl->OpenMedium(vboxObj, location, deviceType, accessMode,
                                     PR_FALSE, medium);
#endif /* VBOX_API_VERSION >= 4002000 */
}

static nsresult
_virtualboxOpenMedium(IVirtualBox *vboxObj,
                      PRUnichar *location,
                      PRUint32 deviceType,
                      PRUint32 accessMode,
                      IMedium **medium)
{
#if VBOX_API_VERSION == 4000000
    return vboxObj->vtbl->OpenMedium(vboxObj, location, deviceType, accessMode,
                                     medium);
#elif VBOX_API_VERSION >= 4001000
    return vboxObj->vtbl->OpenMedium(vboxObj, location, deviceType, accessMode,
                                     false, medium);
#endif
}

static nsresult
_virtualboxGetHardDiskByIID(IVirtualBox *vboxObj, vboxIID *iid, IMedium **medium)
{
#if VBOX_API_VERSION >= 4000000 && VBOX_API_VERSION < 4002000
    return vboxObj->vtbl->FindMedium(vboxObj, iid->value, DeviceType_HardDisk,
                                     medium);
#else /* VBOX_API_VERSION >= 4002000 */
    return vboxObj->vtbl->OpenMedium(vboxObj, iid->value, DeviceType_HardDisk,
                                     AccessMode_ReadWrite, PR_FALSE, medium);
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
_machineAttachDevice(IMachine *machine,
                     PRUnichar *name,
                     PRInt32 controllerPort,
                     PRInt32 device,
                     PRUint32 type,
                     IMedium * medium)
{
    return machine->vtbl->AttachDevice(machine, name, controllerPort,
                                       device, type, medium);
}

static nsresult
_machineCreateSharedFolder(IMachine *machine, PRUnichar *name,
                           PRUnichar *hostPath, PRBool writable,
                           PRBool automount ATTRIBUTE_UNUSED)
{
    return machine->vtbl->CreateSharedFolder(machine, name, hostPath,
                                             writable, automount);
}

static nsresult
_machineRemoveSharedFolder(IMachine *machine, PRUnichar *name)
{
    return machine->vtbl->RemoveSharedFolder(machine, name);
}

static nsresult
_machineLaunchVMProcess(vboxDriverPtr data,
                        IMachine *machine ATTRIBUTE_UNUSED,
                        vboxIID *iid ATTRIBUTE_UNUSED,
                        PRUnichar *sessionType, PRUnichar *env,
                        IProgress **progress)
{
    return machine->vtbl->LaunchVMProcess(machine, data->vboxSession,
                                          sessionType, env, progress);
}

static nsresult
_machineUnregister(IMachine *machine ATTRIBUTE_UNUSED,
                   PRUint32 cleanupMode ATTRIBUTE_UNUSED,
                   PRUint32 *aMediaSize ATTRIBUTE_UNUSED,
                   IMedium ***aMedia ATTRIBUTE_UNUSED)
{
    return machine->vtbl->Unregister(machine, cleanupMode, aMediaSize, aMedia);
}

static nsresult
_machineFindSnapshot(IMachine *machine, vboxIID *iid, ISnapshot **snapshot)
{
    return machine->vtbl->FindSnapshot(machine, iid->value, snapshot);
}

static nsresult
_machineDetachDevice(IMachine *machine, PRUnichar *name,
                     PRInt32 controllerPort, PRInt32 device)
{
    return machine->vtbl->DetachDevice(machine, name, controllerPort, device);
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
_machineGetId(IMachine *machine, vboxIID *iid)
{
    return machine->vtbl->GetId(machine, &iid->value);
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
    return machine->vtbl->GetChipsetType(machine, chipsetType);
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
_machineGetVRDEServer(IMachine *machine, IVRDEServer **VRDEServer)
{
    return machine->vtbl->GetVRDEServer(machine, VRDEServer);
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
    return machine->vtbl->GetCPUProperty(machine, property, value);
}

static nsresult
_machineSetCPUProperty(IMachine *machine, PRUint32 property ATTRIBUTE_UNUSED, PRBool value)
{
    return machine->vtbl->SetCPUProperty(machine, property, value);
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
_machineGetAccelerate2DVideoEnabled(IMachine *machine,
                                    PRBool *accelerate2DVideoEnabled)
{
    return machine->vtbl->GetAccelerate2DVideoEnabled(machine, accelerate2DVideoEnabled);
}

static nsresult
_machineSetAccelerate2DVideoEnabled(IMachine *machine,
                                    PRBool accelerate2DVideoEnabled)
{
    return machine->vtbl->SetAccelerate2DVideoEnabled(machine, accelerate2DVideoEnabled);
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

static nsresult
_sessionOpen(vboxDriverPtr data, vboxIID *iid ATTRIBUTE_UNUSED, IMachine *machine)
{
    return machine->vtbl->LockMachine(machine, data->vboxSession, LockType_Write);
}

static nsresult
_sessionOpenExisting(vboxDriverPtr data, vboxIID *iid ATTRIBUTE_UNUSED, IMachine *machine)
{
    return machine->vtbl->LockMachine(machine, data->vboxSession, LockType_Shared);
}

static nsresult
_sessionClose(ISession *session)
{
    return session->vtbl->UnlockMachine(session);
}

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
#if VBOX_API_VERSION < 5000000
    return console->vtbl->SaveState(console, progress);
#else /*VBOX_API_VERSION < 5000000*/
    IMachine *machine;
    nsresult rc;

    rc = console->vtbl->GetMachine(console, &machine);

    if (NS_SUCCEEDED(rc))
        rc = machine->vtbl->SaveState(machine, progress);
    else
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to get machine from console. (error %d)"), rc);

    return rc;

#endif /*VBOX_API_VERSION >= 5000000*/
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
    IProgress *progress = NULL;
    rc = console->vtbl->PowerDown(console, &progress);
    if (progress) {
        rc = progress->vtbl->WaitForCompletion(progress, -1);
        VBOX_RELEASE(progress);
    }

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
#if VBOX_API_VERSION < 5000000
    return console->vtbl->TakeSnapshot(console, name, description, progress);
#else
    IMachine *machine;
    nsresult rc;
    PRUnichar *id = NULL;
    bool bpause = true; /*NO live snapshot*/

    rc = console->vtbl->GetMachine(console, &machine);

    if (NS_SUCCEEDED(rc))
        rc = machine->vtbl->TakeSnapshot(machine, name, description, bpause, &id, progress);
    else
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to get machine from console. (error %d)"), rc);

    VBOX_RELEASE(machine);
    return rc;
#endif /* VBOX_API_VERSION >= 5000000 */
}

static nsresult
_consoleDeleteSnapshot(IConsole *console, vboxIID *iid, IProgress **progress)
{
#if VBOX_API_VERSION < 5000000 /* VBOX_API_VERSION < 5000000 */
    return console->vtbl->DeleteSnapshot(console, iid->value, progress);
#else /* VBOX_API_VERSION >= 5000000 */
    IMachine *machine;
    nsresult rc;

    rc = console->vtbl->GetMachine(console, &machine);

    if (NS_SUCCEEDED(rc))
        rc = machine->vtbl->DeleteSnapshot(machine, iid->value, progress);
    else
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to get machine from console. (error %d)"), rc);

    VBOX_RELEASE(machine);

    return rc;
#endif /* VBOX_API_VERSION >= 5000000 */
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
    return progress->vtbl->GetResultCode(progress, &resultCode->resultCode);
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
_vrdeServerGetEnabled(IVRDEServer *VRDEServer, PRBool *enabled)
{
    return VRDEServer->vtbl->GetEnabled(VRDEServer, enabled);
}

static nsresult
_vrdeServerSetEnabled(IVRDEServer *VRDEServer, PRBool enabled)
{
    return VRDEServer->vtbl->SetEnabled(VRDEServer, enabled);
}

static nsresult
_vrdeServerGetPorts(vboxDriverPtr data, IVRDEServer *VRDEServer,
                    IMachine *machine, virDomainGraphicsDefPtr graphics)
{
    nsresult rc;
    PRUnichar *VRDEPortsKey = NULL;
    PRUnichar *VRDEPortsValue = NULL;
    PRInt32 port = -1;
    ssize_t nmatches = 0;
    char **matches = NULL;
    char *portUtf8 = NULL;

    /* get active (effective) port - available only when VM is running and has
     * the VBOX extensions installed (without extenstions RDP server
     * functionality is disabled)
     */
    port = vboxGetActiveVRDEServerPort(data->vboxSession, machine);

    if (port > 0)
        graphics->data.rdp.port = port;

    /* get the port (or port range) set in VM properties, this info will
     * be used to determine whether to set autoport flag
     */
    VBOX_UTF8_TO_UTF16("TCP/Ports", &VRDEPortsKey);
    rc = VRDEServer->vtbl->GetVRDEProperty(VRDEServer, VRDEPortsKey,
                                           &VRDEPortsValue);

    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to read RDP port value, rc=%08x"),
                       (unsigned) rc);
       goto cleanup;
    }

    VBOX_UTF16_TO_UTF8(VRDEPortsValue, &portUtf8);

    if (portUtf8) {
        /* does the string contain digits only */
        nmatches = virStringSearch(portUtf8, "(^[[:digit:]]+$)", 1, &matches);

        /* the port property is not numeric, then it must be a port range or
         * port list or combination of the two, either way it's an autoport
         */
        if (nmatches != 1)
            graphics->data.rdp.autoport = true;

        /* no active port available, e.g. VM is powered off, try to get it from
         * the property string
         */
        if (port < 0) {
            if (nmatches == 1 && virStrToLong_i(portUtf8, NULL, 10, &port) == 0)
                graphics->data.rdp.port = port;
        }
    }

 cleanup:
    virStringListFree(matches);
    VBOX_UTF8_FREE(portUtf8);
    VBOX_UTF16_FREE(VRDEPortsValue);
    VBOX_UTF16_FREE(VRDEPortsKey);

    return rc;
}

static nsresult
_vrdeServerSetPorts(vboxDriverPtr data, IVRDEServer *VRDEServer,
                    virDomainGraphicsDefPtr graphics)
{
    nsresult rc = 0;
    PRUnichar *VRDEPortsKey = NULL;
    PRUnichar *VRDEPortsValue = NULL;

    VBOX_UTF8_TO_UTF16("TCP/Ports", &VRDEPortsKey);

    if (graphics->data.rdp.autoport)
        VBOX_UTF8_TO_UTF16(VBOX_RDP_AUTOPORT_RANGE, &VRDEPortsValue);
    else
        VRDEPortsValue = PRUnicharFromInt(data->pFuncs,
                                          graphics->data.rdp.port);

    rc = VRDEServer->vtbl->SetVRDEProperty(VRDEServer, VRDEPortsKey,
                                           VRDEPortsValue);
    VBOX_UTF16_FREE(VRDEPortsKey);
    VBOX_UTF16_FREE(VRDEPortsValue);

    return rc;
}

static nsresult
_vrdeServerGetReuseSingleConnection(IVRDEServer *VRDEServer, PRBool *enabled)
{
    return VRDEServer->vtbl->GetReuseSingleConnection(VRDEServer, enabled);
}

static nsresult
_vrdeServerSetReuseSingleConnection(IVRDEServer *VRDEServer, PRBool enabled)
{
    return VRDEServer->vtbl->SetReuseSingleConnection(VRDEServer, enabled);
}

static nsresult
_vrdeServerGetAllowMultiConnection(IVRDEServer *VRDEServer, PRBool *enabled)
{
    return VRDEServer->vtbl->GetAllowMultiConnection(VRDEServer, enabled);
}

static nsresult
_vrdeServerSetAllowMultiConnection(IVRDEServer *VRDEServer, PRBool enabled)
{
    return VRDEServer->vtbl->SetAllowMultiConnection(VRDEServer, enabled);
}

static nsresult
_vrdeServerGetNetAddress(vboxDriverPtr data ATTRIBUTE_UNUSED,
                         IVRDEServer *VRDEServer, PRUnichar **netAddress)
{
    PRUnichar *VRDENetAddressKey = NULL;
    nsresult rc;

    VBOX_UTF8_TO_UTF16("TCP/Address", &VRDENetAddressKey);
    rc = VRDEServer->vtbl->GetVRDEProperty(VRDEServer, VRDENetAddressKey, netAddress);
    VBOX_UTF16_FREE(VRDENetAddressKey);

    return rc;
}

static nsresult
_vrdeServerSetNetAddress(vboxDriverPtr data ATTRIBUTE_UNUSED,
                         IVRDEServer *VRDEServer, PRUnichar *netAddress)
{
    PRUnichar *netAddressKey = NULL;
    nsresult rc;

    VBOX_UTF8_TO_UTF16("TCP/Address", &netAddressKey);
    rc = VRDEServer->vtbl->SetVRDEProperty(VRDEServer, netAddressKey,
                                           netAddress);
    VBOX_UTF16_FREE(netAddressKey);

    return rc;
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

static nsresult _mediumGetId(IMedium *medium, vboxIID *iid)
{
    return medium->vtbl->GetId(medium, &iid->value);
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
    nsresult rc;
    PRInt64 Size;

    rc = medium->vtbl->GetSize(medium, &Size);
    *uSize = Size;

    return rc;
}

static nsresult _mediumGetReadOnly(IMedium *medium ATTRIBUTE_UNUSED,
                                   PRBool *readOnly ATTRIBUTE_UNUSED)
{
    return medium->vtbl->GetReadOnly(medium, readOnly);
}

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
    return medium->vtbl->SetType(medium, type);
}

static nsresult
_mediumCreateDiffStorage(IMedium *medium ATTRIBUTE_UNUSED,
                         IMedium *target ATTRIBUTE_UNUSED,
                         PRUint32 variantSize ATTRIBUTE_UNUSED,
                         PRUint32 *variant ATTRIBUTE_UNUSED,
                         IProgress **progress ATTRIBUTE_UNUSED)
{
#if VBOX_API_VERSION < 4003000
    if (variantSize == 0)
        return 0;
    if (variantSize > 1)
        VIR_WARN("Only one variant is available in current version");
    return medium->vtbl->CreateDiffStorage(medium, target, variant[0], progress);
#else /* VBOX_API_VERSION >= 4003000 */
    return medium->vtbl->CreateDiffStorage(medium, target, variantSize, variant, progress);
#endif /* VBOX_API_VERSION >= 4003000 */
}

static nsresult
_mediumCreateBaseStorage(IMedium *medium, PRUint64 logicalSize,
                           PRUint32 variant, IProgress **progress)
{
#if VBOX_API_VERSION < 4003000
    return medium->vtbl->CreateBaseStorage(medium, logicalSize, variant, progress);
#else
    return medium->vtbl->CreateBaseStorage(medium, logicalSize, 1, &variant, progress);
#endif
}

static nsresult
_mediumGetLogicalSize(IMedium *medium, PRUint64 *uLogicalSize)
{
    nsresult rc;
    PRInt64 logicalSize;

    rc = medium->vtbl->GetLogicalSize(medium, &logicalSize);
    *uLogicalSize = logicalSize;

    return rc;
}

static nsresult
_mediumAttachmentGetMedium(IMediumAttachment *mediumAttachment,
                           IMedium **medium)
{
    return mediumAttachment->vtbl->GetMedium(mediumAttachment, medium);
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
    return mediumAttachment->vtbl->GetType(mediumAttachment, type);
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
_storageControllerGetControllerType(IStorageController *storageController, PRUint32 *controllerType)
{
    return storageController->vtbl->GetControllerType(storageController, controllerType);
}

static nsresult
_storageControllerSetControllerType(IStorageController *storageController, PRUint32 controllerType)
{
    return storageController->vtbl->SetControllerType(storageController, controllerType);
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
_snapshotGetId(ISnapshot *snapshot, vboxIID *iid)
{
    return snapshot->vtbl->GetId(snapshot, &iid->value);
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
#if VBOX_API_VERSION < 4003000
    return display->vtbl->GetScreenResolution(display, screenId, width,
                                              height, bitsPerPixel);
#elif VBOX_API_VERSION < 5000000 /* VBOX_API_VERSION >= 4003000 */
    return display->vtbl->GetScreenResolution(display, screenId, width,
                                              height, bitsPerPixel,
                                              xOrigin, yOrigin);
#else /*VBOX_API_VERSION >= 5000000 */
    PRUint32 gms;

    return display->vtbl->GetScreenResolution(display, screenId, width,
                                              height, bitsPerPixel,
                                              xOrigin, yOrigin, &gms);
#endif /* VBOX_API_VERSION >= 5000000 */
}

static nsresult
_displayTakeScreenShotPNGToArray(IDisplay *display, PRUint32 screenId,
                                 PRUint32 width, PRUint32 height,
                                 PRUint32 *screenDataSize,
                                 PRUint8** screenData)
{
#if VBOX_API_VERSION >= 5000000
    return display->vtbl->TakeScreenShotToArray(display, screenId, width,
                                                height, BitmapFormat_PNG,
                                                screenDataSize, screenData);
#else /* VBOX_API_VERSION < 5000000 */
    return display->vtbl->TakeScreenShotPNGToArray(display, screenId, width,
                                                   height, screenDataSize,
                                                   screenData);
#endif /* VBOX_API_VERSION >= 5000000 */
}

static nsresult
_hostFindHostNetworkInterfaceById(IHost *host, vboxIID *iid,
                                  IHostNetworkInterface **networkInterface)
{
    return host->vtbl->FindHostNetworkInterfaceById(host, iid->value,
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
_hostCreateHostOnlyNetworkInterface(vboxDriverPtr data ATTRIBUTE_UNUSED,
                                    IHost *host, char *name ATTRIBUTE_UNUSED,
                                    IHostNetworkInterface **networkInterface)
{
    nsresult rc = -1;
    IProgress *progress = NULL;

    host->vtbl->CreateHostOnlyNetworkInterface(host, networkInterface,
                                               &progress);

    if (progress) {
        rc = progress->vtbl->WaitForCompletion(progress, -1);
        VBOX_RELEASE(progress);
    }

    return rc;
}

static nsresult
_hostRemoveHostOnlyNetworkInterface(IHost *host ATTRIBUTE_UNUSED,
                                    vboxIID *iid ATTRIBUTE_UNUSED,
                                    IProgress **progress ATTRIBUTE_UNUSED)
{
    return host->vtbl->RemoveHostOnlyNetworkInterface(host, iid->value, progress);
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
_hnInterfaceGetId(IHostNetworkInterface *hni, vboxIID *iid)
{
    return hni->vtbl->GetId(hni, &iid->value);
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
    .handleMachineGetStorageControllers = _handleMachineGetStorageControllers,
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
    .GetVRDEServer = _machineGetVRDEServer,
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

static vboxUniformedIVRDEServer _UIVRDEServer = {
    .GetEnabled = _vrdeServerGetEnabled,
    .SetEnabled = _vrdeServerSetEnabled,
    .GetPorts = _vrdeServerGetPorts,
    .SetPorts = _vrdeServerSetPorts,
    .GetReuseSingleConnection = _vrdeServerGetReuseSingleConnection,
    .SetReuseSingleConnection = _vrdeServerSetReuseSingleConnection,
    .GetAllowMultiConnection = _vrdeServerGetAllowMultiConnection,
    .SetAllowMultiConnection = _vrdeServerSetAllowMultiConnection,
    .GetNetAddress = _vrdeServerGetNetAddress,
    .SetNetAddress = _vrdeServerSetNetAddress,
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
    .CreateBaseStorage = _mediumCreateBaseStorage,
    .GetLogicalSize = _mediumGetLogicalSize,
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
    .GetControllerType = _storageControllerGetControllerType,
    .SetControllerType = _storageControllerSetControllerType,
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
    pVBoxAPI->unregisterMachine = _unregisterMachine;
    pVBoxAPI->deleteConfig = _deleteConfig;
    pVBoxAPI->vboxConvertState = _vboxConvertState;
    pVBoxAPI->snapshotRestore = _vboxDomainSnapshotRestore;
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
    pVBoxAPI->UIVRDEServer = _UIVRDEServer;
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
    pVBoxAPI->UIKeyboard = _UIKeyboard;
    pVBoxAPI->machineStateChecker = _machineStateChecker;

#if VBOX_API_VERSION >= 4001000
    pVBoxAPI->chipsetType = 1;
#else /* VBOX_API_VERSION < 4001000 */
    pVBoxAPI->chipsetType = 0;
#endif /* VBOX_API_VERSION < 4001000 */

#if VBOX_API_VERSION >= 4002000
    pVBoxAPI->vboxSnapshotRedefine = 1;
#else /* VBOX_API_VERSION < 4002000 */
    pVBoxAPI->vboxSnapshotRedefine = 0;
#endif /* VBOX_API_VERSION < 4002000 */
}
