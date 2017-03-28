/*
 * Copyright (C) 2014, Taowei Luo (uaedante@gmail.com)
 * Copyright (C) 2010-2016 Red Hat, Inc.
 * Copyright (C) 2008-2009 Sun Microsystems, Inc.
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

#include <config.h>

#include <unistd.h>
#include <fcntl.h>

#include "internal.h"
#include "datatypes.h"
#include "virdomainobjlist.h"
#include "domain_event.h"
#include "virlog.h"
#include "viralloc.h"
#include "virhostmem.h"
#include "virstring.h"
#include "virfile.h"
#include "virtime.h"
#include "virkeycode.h"
#include "snapshot_conf.h"
#include "vbox_snapshot_conf.h"
#include "virfdstream.h"
#include "configmake.h"

#include "vbox_common.h"
#include "vbox_uniformed_api.h"
#include "vbox_get_driver.h"

/* Common codes for vbox driver. With the definitions in vbox_common.h,
 * it treats vbox structs as a void*. Though vboxUniformedAPI
 * it call vbox functions. This file is a high level implement about
 * the vbox driver.
 */

#define VIR_FROM_THIS VIR_FROM_VBOX

VIR_LOG_INIT("vbox.vbox_common");

/* global vbox API, used for all common codes. */
static vboxUniformedAPI gVBoxAPI;

static virClassPtr vboxDriverClass;
static virMutex vbox_driver_lock = VIR_MUTEX_INITIALIZER;
static vboxDriverPtr vbox_driver;
static vboxDriverPtr vboxDriverObjNew(void);

static virDomainDefParserConfig vboxDomainDefParserConfig = {
    .macPrefix = { 0x08, 0x00, 0x27 },
    .features = VIR_DOMAIN_DEF_FEATURE_NAME_SLASH,
};

static virCapsPtr
vboxCapsInit(void)
{
    virCapsPtr caps;
    virCapsGuestPtr guest;

    if ((caps = virCapabilitiesNew(virArchFromHost(),
                                   false, false)) == NULL)
        goto no_memory;

    if (virCapabilitiesInitNUMA(caps) < 0)
        goto no_memory;

    if ((guest = virCapabilitiesAddGuest(caps,
                                         VIR_DOMAIN_OSTYPE_HVM,
                                         caps->host.arch,
                                         NULL,
                                         NULL,
                                         0,
                                         NULL)) == NULL)
        goto no_memory;

    if (virCapabilitiesAddGuestDomain(guest,
                                      VIR_DOMAIN_VIRT_VBOX,
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto no_memory;

    return caps;

 no_memory:
    virObjectUnref(caps);
    return NULL;
}

static void
vboxDriverDispose(void *obj)
{
    vboxDriverPtr driver = obj;

    virObjectUnref(driver->caps);
    virObjectUnref(driver->xmlopt);
}

static int
vboxDriverOnceInit(void)
{
    if (!(vboxDriverClass = virClassNew(virClassForObjectLockable(),
                                        "vboxDriver",
                                        sizeof(vboxDriver),
                                        vboxDriverDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(vboxDriver);

static vboxDriverPtr
vboxDriverObjNew(void)
{
    vboxDriverPtr driver;

    if (vboxDriverInitialize() < 0)
        return NULL;

    if (!(driver = virObjectLockableNew(vboxDriverClass)))
        return NULL;

    if (!(driver->caps = vboxCapsInit()) ||
        !(driver->xmlopt = virDomainXMLOptionNew(&vboxDomainDefParserConfig,
                                                 NULL, NULL)))
        goto cleanup;

    return driver;

 cleanup:
    virObjectUnref(driver);
    return NULL;
}

static int
vboxExtractVersion(void)
{
    int ret = -1;
    PRUnichar *versionUtf16 = NULL;
    char *vboxVersion = NULL;
    nsresult rc;

    if (vbox_driver->version > 0)
        return 0;

    rc = gVBoxAPI.UIVirtualBox.GetVersion(vbox_driver->vboxObj, &versionUtf16);
    if (NS_FAILED(rc))
        goto failed;

    gVBoxAPI.UPFN.Utf16ToUtf8(vbox_driver->pFuncs, versionUtf16, &vboxVersion);

    if (virParseVersionString(vboxVersion, &vbox_driver->version, false) >= 0)
        ret = 0;

    gVBoxAPI.UPFN.Utf8Free(vbox_driver->pFuncs, vboxVersion);
    gVBoxAPI.UPFN.ComUnallocMem(vbox_driver->pFuncs, versionUtf16);
    vboxVersion = NULL;
    versionUtf16 = NULL;

 failed:
    if (ret != 0)
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not extract VirtualBox version"));

    return ret;
}

static int
vboxSdkInitialize(void)
{
    /* vbox API was already initialized by first connection */
    if (vbox_driver->connectionCount > 0)
        return 0;

    if (gVBoxAPI.UPFN.Initialize(vbox_driver) != 0)
        return -1;

    if (vbox_driver->vboxObj == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("IVirtualBox object is null"));
        return -1;
    }

    if (vbox_driver->vboxSession == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("ISession object is null"));
        return -1;
    }

    return 0;
}

static void
vboxSdkUninitialize(void)
{
    /* do not uninitialize, when there are still connection using it */
    if (vbox_driver->connectionCount > 0)
        return;

    gVBoxAPI.UPFN.Uninitialize(vbox_driver);
}

static vboxDriverPtr
vboxGetDriverConnection(void)
{
    virMutexLock(&vbox_driver_lock);

    if (vbox_driver) {
        virObjectRef(vbox_driver);
    } else {
        vbox_driver = vboxDriverObjNew();

        if (!vbox_driver) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Failed to create vbox driver object."));
            return NULL;
        }
    }

    if (vboxSdkInitialize() < 0 || vboxExtractVersion() < 0) {
        gVBoxAPI.UPFN.Uninitialize(vbox_driver);
        /* make sure to clear the pointer when last reference was released */
        if (!virObjectUnref(vbox_driver))
            vbox_driver = NULL;

        virMutexUnlock(&vbox_driver_lock);

        return NULL;
    }

    vbox_driver->connectionCount++;

    virMutexUnlock(&vbox_driver_lock);

    return vbox_driver;
}

static void
vboxDestroyDriverConnection(void)
{
    virMutexLock(&vbox_driver_lock);

    if (!vbox_driver)
        goto cleanup;

    vbox_driver->connectionCount--;

    vboxSdkUninitialize();

    if (!virObjectUnref(vbox_driver))
        vbox_driver = NULL;

 cleanup:
    virMutexUnlock(&vbox_driver_lock);
}

static int openSessionForMachine(vboxDriverPtr data, const unsigned char *dom_uuid,
                                 vboxIID *iid, IMachine **machine)
{
    VBOX_IID_INITIALIZE(iid);
    vboxIIDFromUUID(iid, dom_uuid);

    /* Get machine for the call to VBOX_SESSION_OPEN_EXISTING */
    if (NS_FAILED(gVBoxAPI.UIVirtualBox.GetMachine(data->vboxObj, iid, machine))) {
        virReportError(VIR_ERR_NO_DOMAIN, "%s",
                       _("no domain with matching uuid"));
        return -1;
    }

    return 0;
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
                                     PRUint32 *maxSlotPerPort)
{
    ISystemProperties *sysProps = NULL;

    if (!vbox)
        return false;

    gVBoxAPI.UIVirtualBox.GetSystemProperties(vbox, &sysProps);

    if (!sysProps)
        return false;

    gVBoxAPI.UISystemProperties.GetMaxPortCountForStorageBus(sysProps,
                                                             StorageBus_IDE,
                                                             &maxPortPerInst[StorageBus_IDE]);
    gVBoxAPI.UISystemProperties.GetMaxPortCountForStorageBus(sysProps,
                                                             StorageBus_SATA,
                                                             &maxPortPerInst[StorageBus_SATA]);
    gVBoxAPI.UISystemProperties.GetMaxPortCountForStorageBus(sysProps,
                                                             StorageBus_SCSI,
                                                             &maxPortPerInst[StorageBus_SCSI]);
    gVBoxAPI.UISystemProperties.GetMaxPortCountForStorageBus(sysProps,
                                                             StorageBus_Floppy,
                                                             &maxPortPerInst[StorageBus_Floppy]);

    gVBoxAPI.UISystemProperties.GetMaxDevicesPerPortForStorageBus(sysProps,
                                                                  StorageBus_IDE,
                                                                  &maxSlotPerPort[StorageBus_IDE]);
    gVBoxAPI.UISystemProperties.GetMaxDevicesPerPortForStorageBus(sysProps,
                                                                  StorageBus_SATA,
                                                                  &maxSlotPerPort[StorageBus_SATA]);
    gVBoxAPI.UISystemProperties.GetMaxDevicesPerPortForStorageBus(sysProps,
                                                                  StorageBus_SCSI,
                                                                  &maxSlotPerPort[StorageBus_SCSI]);
    gVBoxAPI.UISystemProperties.GetMaxDevicesPerPortForStorageBus(sysProps,
                                                                  StorageBus_Floppy,
                                                                  &maxSlotPerPort[StorageBus_Floppy]);

    VBOX_RELEASE(sysProps);

    return true;
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
static char *vboxGenerateMediumName(PRUint32 storageBus,
                                    PRInt32 deviceInst,
                                    PRInt32 devicePort,
                                    PRInt32 deviceSlot,
                                    PRUint32 *aMaxPortPerInst,
                                    PRUint32 *aMaxSlotPerPort)
{
    const char *prefix = NULL;
    char *name = NULL;
    int total = 0;
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
    total = (deviceInst * maxPortPerInst * maxSlotPerPort)
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

static virDrvOpenStatus
vboxConnectOpen(virConnectPtr conn,
                virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                virConfPtr conf ATTRIBUTE_UNUSED,
                unsigned int flags)
{
    vboxDriverPtr driver = NULL;
    uid_t uid = geteuid();

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (conn->uri == NULL &&
        !(conn->uri = virURIParse(uid ? "vbox:///session" : "vbox:///system")))
        return VIR_DRV_OPEN_ERROR;

    if (conn->uri->scheme == NULL ||
        STRNEQ(conn->uri->scheme, "vbox"))
        return VIR_DRV_OPEN_DECLINED;

    /* Leave for remote driver */
    if (conn->uri->server != NULL)
        return VIR_DRV_OPEN_DECLINED;

    if (conn->uri->path == NULL || STREQ(conn->uri->path, "")) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("no VirtualBox driver path specified (try vbox:///session)"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (uid != 0) {
        if (STRNEQ(conn->uri->path, "/session")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unknown driver path '%s' specified (try vbox:///session)"), conn->uri->path);
            return VIR_DRV_OPEN_ERROR;
        }
    } else { /* root */
        if (STRNEQ(conn->uri->path, "/system") &&
            STRNEQ(conn->uri->path, "/session")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unknown driver path '%s' specified (try vbox:///system)"), conn->uri->path);
            return VIR_DRV_OPEN_ERROR;
        }
    }

    if (!(driver = vboxGetDriverConnection()))
        return VIR_DRV_OPEN_ERROR;

    conn->privateData = virObjectRef(driver);

    VIR_DEBUG("in vboxOpen");

    return VIR_DRV_OPEN_SUCCESS;
}

static int vboxConnectClose(virConnectPtr conn)
{
    VIR_DEBUG("%s: in vboxClose", conn->driver->name);

    virObjectUnref(conn->privateData);
    vboxDestroyDriverConnection();

    return 0;
}

static int
vboxDomainSave(virDomainPtr dom, const char *path ATTRIBUTE_UNUSED)
{
    vboxDriverPtr data = dom->conn->privateData;
    IConsole *console = NULL;
    vboxIID iid;
    IMachine *machine = NULL;
    IProgress *progress = NULL;
    resultCodeUnion resultCode;
    nsresult rc;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    /* VirtualBox currently doesn't support saving to a file
     * at a location other then the machine folder and thus
     * setting path to ATTRIBUTE_UNUSED for now, will change
     * this behaviour once get the VirtualBox API in right
     * shape to do this
     */

    /* Open a Session for the machine */
    if (openSessionForMachine(data, dom->uuid, &iid, &machine) < 0)
        goto cleanup;

    rc = gVBoxAPI.UISession.OpenExisting(data, &iid, machine);
    if (NS_FAILED(rc))
        goto cleanup;

    rc = gVBoxAPI.UISession.GetConsole(data->vboxSession, &console);
    if (NS_FAILED(rc) || !console)
        goto freeSession;

    rc = gVBoxAPI.UIConsole.SaveState(console, &progress);
    if (!progress)
        goto freeSession;

    gVBoxAPI.UIProgress.WaitForCompletion(progress, -1);
    gVBoxAPI.UIProgress.GetResultCode(progress, &resultCode);
    if (RC_SUCCEEDED(resultCode))
        ret = 0;

 freeSession:
    gVBoxAPI.UISession.Close(data->vboxSession);

 cleanup:
    DEBUGIID("UUID of machine being saved:", &iid);
    VBOX_RELEASE(machine);
    VBOX_RELEASE(console);
    VBOX_RELEASE(progress);
    vboxIIDUnalloc(&iid);
    return ret;
}

static int vboxConnectGetVersion(virConnectPtr conn, unsigned long *version)
{
    vboxDriverPtr data = conn->privateData;
    VIR_DEBUG("%s: in vboxGetVersion", conn->driver->name);

    virObjectLock(data);
    *version = data->version;
    virObjectUnlock(data);

    return 0;
}

static char *vboxConnectGetHostname(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return virGetHostname();
}

static int vboxConnectIsSecure(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* Driver is using local, non-network based transport */
    return 1;
}

static int vboxConnectIsEncrypted(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* No encryption is needed, or used on the local transport*/
    return 0;
}

static int vboxConnectIsAlive(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 1;
}

static int
vboxConnectGetMaxVcpus(virConnectPtr conn, const char *type ATTRIBUTE_UNUSED)
{
    vboxDriverPtr data = conn->privateData;
    PRUint32 maxCPUCount = 0;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    /* VirtualBox Supports only hvm and thus the type passed to it
     * has no meaning, setting it to ATTRIBUTE_UNUSED
     */
    ISystemProperties *systemProperties = NULL;

    gVBoxAPI.UIVirtualBox.GetSystemProperties(data->vboxObj, &systemProperties);
    if (!systemProperties)
        goto cleanup;
    gVBoxAPI.UISystemProperties.GetMaxGuestCPUCount(systemProperties, &maxCPUCount);

    if (maxCPUCount > 0)
        ret = maxCPUCount;

 cleanup:
    VBOX_RELEASE(systemProperties);
    return ret;
}

static char *vboxConnectGetCapabilities(virConnectPtr conn)
{
    vboxDriverPtr data = conn->privateData;
    char *ret = NULL;

    if (!data->vboxObj)
        return ret;

    virObjectLock(data);
    ret = virCapabilitiesFormatXML(data->caps);
    virObjectUnlock(data);

    return ret;
}

static int vboxConnectListDomains(virConnectPtr conn, int *ids, int nids)
{
    vboxDriverPtr data = conn->privateData;
    vboxArray machines = VBOX_ARRAY_INITIALIZER;
    PRUint32 state;
    nsresult rc;
    size_t i, j;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    rc = gVBoxAPI.UArray.vboxArrayGet(&machines, data->vboxObj, ARRAY_GET_MACHINES);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get list of Domains, rc=%08x"),
                       (unsigned)rc);
        goto cleanup;
    }

    ret = 0;
    for (i = 0, j = 0; (i < machines.count) && (j < nids); ++i) {
        IMachine *machine = machines.items[i];

        if (machine) {
            PRBool isAccessible = PR_FALSE;
            gVBoxAPI.UIMachine.GetAccessible(machine, &isAccessible);
            if (isAccessible) {
                gVBoxAPI.UIMachine.GetState(machine, &state);
                if (gVBoxAPI.machineStateChecker.Online(state)) {
                    ret++;
                    ids[j++] = i + 1;
                }
            }
        }
    }

 cleanup:
    gVBoxAPI.UArray.vboxArrayRelease(&machines);
    return ret;
}

static int vboxConnectNumOfDomains(virConnectPtr conn)
{
    vboxDriverPtr data = conn->privateData;
    vboxArray machines = VBOX_ARRAY_INITIALIZER;
    PRUint32 state;
    nsresult rc;
    size_t i;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    rc = gVBoxAPI.UArray.vboxArrayGet(&machines, data->vboxObj, ARRAY_GET_MACHINES);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get number of Domains, rc=%08x"), (unsigned)rc);
        goto cleanup;
    }

    ret = 0;
    for (i = 0; i < machines.count; ++i) {
        IMachine *machine = machines.items[i];

        if (machine) {
            PRBool isAccessible = PR_FALSE;
            gVBoxAPI.UIMachine.GetAccessible(machine, &isAccessible);
            if (isAccessible) {
                gVBoxAPI.UIMachine.GetState(machine, &state);
                if (gVBoxAPI.machineStateChecker.Online(state))
                    ret++;
            }
        }
    }

 cleanup:
    gVBoxAPI.UArray.vboxArrayRelease(&machines);
    return ret;
}

static virDomainPtr vboxDomainLookupByID(virConnectPtr conn, int id)
{
    vboxDriverPtr data = conn->privateData;
    vboxArray machines = VBOX_ARRAY_INITIALIZER;
    IMachine *machine;
    PRBool isAccessible = PR_FALSE;
    PRUnichar *machineNameUtf16 = NULL;
    char *machineNameUtf8 = NULL;
    vboxIID iid;
    unsigned char uuid[VIR_UUID_BUFLEN];
    PRUint32 state;
    nsresult rc;
    virDomainPtr ret = NULL;

    if (!data->vboxObj)
        return ret;

    VBOX_IID_INITIALIZE(&iid);
    /* Internal vbox IDs start from 0, the public libvirt ID
     * starts from 1, so refuse id == 0, and adjust the rest*/
    if (id == 0) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching id %d"), id);
        return NULL;
    }
    id = id - 1;

    rc = gVBoxAPI.UArray.vboxArrayGet(&machines, data->vboxObj, ARRAY_GET_MACHINES);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get list of machines, rc=%08x"), (unsigned)rc);
        return NULL;
    }

    if (id >= machines.count)
        goto cleanup;

    machine = machines.items[id];

    if (!machine)
        goto cleanup;

    isAccessible = PR_FALSE;
    gVBoxAPI.UIMachine.GetAccessible(machine, &isAccessible);
    if (!isAccessible)
        goto cleanup;

    gVBoxAPI.UIMachine.GetState(machine, &state);
    if (!gVBoxAPI.machineStateChecker.Online(state))
        goto cleanup;

    gVBoxAPI.UIMachine.GetName(machine, &machineNameUtf16);
    VBOX_UTF16_TO_UTF8(machineNameUtf16, &machineNameUtf8);

    gVBoxAPI.UIMachine.GetId(machine, &iid);
    vboxIIDToUUID(&iid, uuid);
    vboxIIDUnalloc(&iid);

    /* get a new domain pointer from virGetDomain, if it fails
     * then no need to assign the id, else assign the id, cause
     * it is -1 by default. rest is taken care by virGetDomain
     * itself, so need not worry.
     */

    ret = virGetDomain(conn, machineNameUtf8, uuid, id + 1);

    /* Cleanup all the XPCOM allocated stuff here */
    VBOX_UTF8_FREE(machineNameUtf8);
    VBOX_UTF16_FREE(machineNameUtf16);

 cleanup:
    gVBoxAPI.UArray.vboxArrayRelease(&machines);
    return ret;
}

virDomainPtr vboxDomainLookupByUUID(virConnectPtr conn,
                                    const unsigned char *uuid)
{
    vboxDriverPtr data = conn->privateData;
    vboxArray machines = VBOX_ARRAY_INITIALIZER;
    vboxIID iid;
    char *machineNameUtf8 = NULL;
    PRUnichar *machineNameUtf16 = NULL;
    unsigned char iid_as_uuid[VIR_UUID_BUFLEN];
    size_t i;
    bool matched = false;
    nsresult rc;
    virDomainPtr ret = NULL;

    if (!data->vboxObj)
        return ret;

    VBOX_IID_INITIALIZE(&iid);
    rc = gVBoxAPI.UArray.vboxArrayGet(&machines, data->vboxObj, ARRAY_GET_MACHINES);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get list of machines, rc=%08x"), (unsigned)rc);
        return NULL;
    }

    for (i = 0; i < machines.count; ++i) {
        IMachine *machine = machines.items[i];
        PRBool isAccessible = PR_FALSE;

        if (!machine)
            continue;

        gVBoxAPI.UIMachine.GetAccessible(machine, &isAccessible);
        if (!isAccessible)
            continue;

        rc = gVBoxAPI.UIMachine.GetId(machine, &iid);
        if (NS_FAILED(rc))
            continue;
        vboxIIDToUUID(&iid, iid_as_uuid);
        vboxIIDUnalloc(&iid);

        if (memcmp(uuid, iid_as_uuid, VIR_UUID_BUFLEN) == 0) {
            PRUint32 state;
            int id = -1;


            matched = true;

            gVBoxAPI.UIMachine.GetName(machine, &machineNameUtf16);
            VBOX_UTF16_TO_UTF8(machineNameUtf16, &machineNameUtf8);

            gVBoxAPI.UIMachine.GetState(machine, &state);

            if (gVBoxAPI.machineStateChecker.Online(state))
                id = i + 1;

            ret = virGetDomain(conn, machineNameUtf8, iid_as_uuid, id);
         }

         if (matched)
             break;
    }

    /* Do the cleanup and take care you dont leak any memory */
    VBOX_UTF8_FREE(machineNameUtf8);
    VBOX_COM_UNALLOC_MEM(machineNameUtf16);
    gVBoxAPI.UArray.vboxArrayRelease(&machines);

    return ret;
}

static virDomainPtr
vboxDomainLookupByName(virConnectPtr conn, const char *name)
{
    vboxDriverPtr data = conn->privateData;
    vboxArray machines = VBOX_ARRAY_INITIALIZER;
    vboxIID iid;
    char *machineNameUtf8 = NULL;
    PRUnichar *machineNameUtf16 = NULL;
    unsigned char uuid[VIR_UUID_BUFLEN];
    size_t i;
    bool matched = false;
    nsresult rc;
    virDomainPtr ret = NULL;

    if (!data->vboxObj)
        return ret;

    VBOX_IID_INITIALIZE(&iid);
    rc = gVBoxAPI.UArray.vboxArrayGet(&machines, data->vboxObj, ARRAY_GET_MACHINES);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get list of machines, rc=%08x"), (unsigned)rc);
        return NULL;
    }

    for (i = 0; i < machines.count; ++i) {
        IMachine *machine = machines.items[i];
        PRBool isAccessible = PR_FALSE;

        if (!machine)
            continue;

        gVBoxAPI.UIMachine.GetAccessible(machine, &isAccessible);
        if (!isAccessible)
            continue;

        gVBoxAPI.UIMachine.GetName(machine, &machineNameUtf16);
        VBOX_UTF16_TO_UTF8(machineNameUtf16, &machineNameUtf8);

        if (STREQ(name, machineNameUtf8)) {
            PRUint32 state;
            int id = -1;

            matched = true;

            gVBoxAPI.UIMachine.GetId(machine, &iid);
            vboxIIDToUUID(&iid, uuid);
            vboxIIDUnalloc(&iid);

            gVBoxAPI.UIMachine.GetState(machine, &state);

            if (gVBoxAPI.machineStateChecker.Online(state))
                id = i + 1;

            ret = virGetDomain(conn, machineNameUtf8, uuid, id);
        }

        VBOX_UTF8_FREE(machineNameUtf8);
        VBOX_COM_UNALLOC_MEM(machineNameUtf16);
        if (matched)
            break;
    }

    gVBoxAPI.UArray.vboxArrayRelease(&machines);

    return ret;
}

static void
vboxSetBootDeviceOrder(virDomainDefPtr def, vboxDriverPtr data,
                       IMachine *machine)
{
    ISystemProperties *systemProperties = NULL;
    PRUint32 maxBootPosition = 0;
    size_t i = 0;

    VIR_DEBUG("def->os.type             %s", virDomainOSTypeToString(def->os.type));
    VIR_DEBUG("def->os.arch             %s", virArchToString(def->os.arch));
    VIR_DEBUG("def->os.machine          %s", def->os.machine);
    VIR_DEBUG("def->os.nBootDevs        %zu", def->os.nBootDevs);
    VIR_DEBUG("def->os.bootDevs[0]      %d", def->os.bootDevs[0]);
    VIR_DEBUG("def->os.bootDevs[1]      %d", def->os.bootDevs[1]);
    VIR_DEBUG("def->os.bootDevs[2]      %d", def->os.bootDevs[2]);
    VIR_DEBUG("def->os.bootDevs[3]      %d", def->os.bootDevs[3]);
    VIR_DEBUG("def->os.init             %s", def->os.init);
    VIR_DEBUG("def->os.kernel           %s", def->os.kernel);
    VIR_DEBUG("def->os.initrd           %s", def->os.initrd);
    VIR_DEBUG("def->os.cmdline          %s", def->os.cmdline);
    VIR_DEBUG("def->os.root             %s", def->os.root);
    if (def->os.loader) {
        VIR_DEBUG("def->os.loader->path     %s", def->os.loader->path);
        VIR_DEBUG("def->os.loader->readonly %d", def->os.loader->readonly);
        VIR_DEBUG("def->os.loader->type     %d", def->os.loader->type);
        VIR_DEBUG("def->os.loader->nvram    %s", def->os.loader->nvram);
    }
    VIR_DEBUG("def->os.bootloader       %s", def->os.bootloader);
    VIR_DEBUG("def->os.bootloaderArgs   %s", def->os.bootloaderArgs);

    gVBoxAPI.UIVirtualBox.GetSystemProperties(data->vboxObj, &systemProperties);
    if (systemProperties) {
        gVBoxAPI.UISystemProperties.GetMaxBootPosition(systemProperties,
                                                       &maxBootPosition);
        VBOX_RELEASE(systemProperties);
    }

    /* Clear the defaults first */
    for (i = 0; i < maxBootPosition; i++)
        gVBoxAPI.UIMachine.SetBootOrder(machine, i+1, DeviceType_Null);

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
        gVBoxAPI.UIMachine.SetBootOrder(machine, i+1, device);
    }
}

static void
vboxAttachDrives(virDomainDefPtr def, vboxDriverPtr data, IMachine *machine)
{
    size_t i;
    nsresult rc = 0;
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
        gVBoxAPI.UIMachine.AddStorageController(machine,
                                                sName,
                                                StorageBus_IDE,
                                                &storageCtl);
        VBOX_UTF16_FREE(sName);
        VBOX_RELEASE(storageCtl);

        VBOX_UTF8_TO_UTF16("SATA Controller", &sName);
        gVBoxAPI.UIMachine.AddStorageController(machine,
                                                sName,
                                                StorageBus_SATA,
                                                &storageCtl);
        VBOX_UTF16_FREE(sName);
        VBOX_RELEASE(storageCtl);

        VBOX_UTF8_TO_UTF16("SCSI Controller", &sName);
        gVBoxAPI.UIMachine.AddStorageController(machine,
                                                sName,
                                                StorageBus_SCSI,
                                                &storageCtl);
        VBOX_UTF16_FREE(sName);
        VBOX_RELEASE(storageCtl);

        VBOX_UTF8_TO_UTF16("Floppy Controller", &sName);
        gVBoxAPI.UIMachine.AddStorageController(machine,
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
            vboxIID mediumUUID;
            PRUnichar *mediumFileUtf16 = NULL;
            PRUint32 storageBus = StorageBus_Null;
            PRUint32 deviceType = DeviceType_Null;
            PRUint32 accessMode = AccessMode_ReadOnly;
            PRInt32 deviceInst = 0;
            PRInt32 devicePort = 0;
            PRInt32 deviceSlot = 0;

            VBOX_IID_INITIALIZE(&mediumUUID);
            VBOX_UTF8_TO_UTF16(src, &mediumFileUtf16);

            if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
                deviceType = DeviceType_HardDisk;
                accessMode = AccessMode_ReadWrite;
            } else if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
                deviceType = DeviceType_DVD;
                accessMode = AccessMode_ReadOnly;
            } else if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
                deviceType = DeviceType_Floppy;
                accessMode = AccessMode_ReadWrite;
            } else {
                VBOX_UTF16_FREE(mediumFileUtf16);
                continue;
            }

            gVBoxAPI.UIVirtualBox.FindHardDisk(data->vboxObj, mediumFileUtf16,
                                               deviceType, accessMode, &medium);

            if (!medium) {
                PRUnichar *mediumEmpty = NULL;

                VBOX_UTF8_TO_UTF16("", &mediumEmpty);

                rc = gVBoxAPI.UIVirtualBox.OpenMedium(data->vboxObj,
                                                      mediumFileUtf16,
                                                      deviceType, accessMode,
                                                      &medium);
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

            rc = gVBoxAPI.UIMedium.GetId(medium, &mediumUUID);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("can't get the uuid of the file to be attached "
                                 "as harddisk/dvd/floppy: %s, rc=%08x"),
                               src, (unsigned)rc);
                VBOX_MEDIUM_RELEASE(medium);
                VBOX_UTF16_FREE(mediumFileUtf16);
                continue;
            }

            if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
                if (def->disks[i]->src->readonly) {
                    gVBoxAPI.UIMedium.SetType(medium, MediumType_Immutable);
                    VIR_DEBUG("setting harddisk to immutable");
                } else if (!def->disks[i]->src->readonly) {
                    gVBoxAPI.UIMedium.SetType(medium, MediumType_Normal);
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
                VBOX_MEDIUM_RELEASE(medium);
                vboxIIDUnalloc(&mediumUUID);
                VBOX_UTF16_FREE(mediumFileUtf16);
                continue;
            }

            /* attach the harddisk/dvd/Floppy to the storage controller */
            rc = gVBoxAPI.UIMachine.AttachDevice(machine,
                                                 storageCtlName,
                                                 devicePort,
                                                 deviceSlot,
                                                 deviceType,
                                                 medium);

            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("could not attach the file as "
                                 "harddisk/dvd/floppy: %s, rc=%08x"),
                               src, (unsigned)rc);
            } else {
                DEBUGIID("Attached HDD/DVD/Floppy with UUID", &mediumUUID);
            }

            VBOX_MEDIUM_RELEASE(medium);
            vboxIIDUnalloc(&mediumUUID);
            VBOX_UTF16_FREE(mediumFileUtf16);
            VBOX_UTF16_FREE(storageCtlName);
        }
    }
}

static void
vboxAttachSound(virDomainDefPtr def, IMachine *machine)
{
    nsresult rc;
    IAudioAdapter *audioAdapter = NULL;

    /* Check if def->nsounds is one as VirtualBox currently supports
     * only one sound card
     */
    if (def->nsounds != 1)
        return;

    gVBoxAPI.UIMachine.GetAudioAdapter(machine, &audioAdapter);
    if (!audioAdapter)
        return;

    rc = gVBoxAPI.UIAudioAdapter.SetEnabled(audioAdapter, 1);
    if (NS_FAILED(rc))
        goto cleanup;

    if (def->sounds[0]->model == VIR_DOMAIN_SOUND_MODEL_SB16) {
        gVBoxAPI.UIAudioAdapter.SetAudioController(audioAdapter,
                                                   AudioControllerType_SB16);
    } else if (def->sounds[0]->model == VIR_DOMAIN_SOUND_MODEL_AC97) {
        gVBoxAPI.UIAudioAdapter.SetAudioController(audioAdapter,
                                                   AudioControllerType_AC97);
    }

 cleanup:
    VBOX_RELEASE(audioAdapter);
}

static int
vboxAttachNetwork(virDomainDefPtr def, vboxDriverPtr data, IMachine *machine)
{
    ISystemProperties *systemProperties = NULL;
    PRUint32 chipsetType = ChipsetType_Null;
    PRUint32 networkAdapterCount = 0;
    size_t i = 0;

    if (gVBoxAPI.chipsetType)
        gVBoxAPI.UIMachine.GetChipsetType(machine, &chipsetType);

    gVBoxAPI.UIVirtualBox.GetSystemProperties(data->vboxObj, &systemProperties);
    if (systemProperties) {
        gVBoxAPI.UISystemProperties.GetMaxNetworkAdapters(systemProperties, chipsetType,
                                                          &networkAdapterCount);
        VBOX_RELEASE(systemProperties);
    }

    VIR_DEBUG("Number of Network Cards to be connected: %zu", def->nnets);
    VIR_DEBUG("Number of Network Cards available: %d", networkAdapterCount);

    for (i = 0; (i < def->nnets) && (i < networkAdapterCount); i++) {
        INetworkAdapter *adapter = NULL;
        PRUint32 adapterType = NetworkAdapterType_Null;
        char macaddr[VIR_MAC_STRING_BUFLEN] = {0};
        char macaddrvbox[VIR_MAC_STRING_BUFLEN - 5] = {0};
        PRUnichar *MACAddress = NULL;

        virMacAddrFormat(&def->nets[i]->mac, macaddr);
        snprintf(macaddrvbox, VIR_MAC_STRING_BUFLEN - 5,
                 "%02X%02X%02X%02X%02X%02X",
                 def->nets[i]->mac.addr[0],
                 def->nets[i]->mac.addr[1],
                 def->nets[i]->mac.addr[2],
                 def->nets[i]->mac.addr[3],
                 def->nets[i]->mac.addr[4],
                 def->nets[i]->mac.addr[5]);
        macaddrvbox[VIR_MAC_STRING_BUFLEN - 6] = '\0';

        VIR_DEBUG("NIC(%zu): Type:   %d", i, def->nets[i]->type);
        VIR_DEBUG("NIC(%zu): Model:  %s", i, def->nets[i]->model);
        VIR_DEBUG("NIC(%zu): Mac:    %s", i, macaddr);
        VIR_DEBUG("NIC(%zu): ifname: %s", i, def->nets[i]->ifname);
        if (def->nets[i]->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
            VIR_DEBUG("NIC(%zu): name:    %s", i, def->nets[i]->data.network.name);
        } else if (def->nets[i]->type == VIR_DOMAIN_NET_TYPE_INTERNAL) {
            VIR_DEBUG("NIC(%zu): name:   %s", i, def->nets[i]->data.internal.name);
        } else if (def->nets[i]->type == VIR_DOMAIN_NET_TYPE_USER) {
            VIR_DEBUG("NIC(%zu): NAT.", i);
        } else if (def->nets[i]->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {
            VIR_DEBUG("NIC(%zu): brname: %s", i, def->nets[i]->data.bridge.brname);
            VIR_DEBUG("NIC(%zu): script: %s", i, def->nets[i]->script);
            if (def->nets[i]->guestIP.nips == 1) {
                char *ipStr = virSocketAddrFormat(&def->nets[i]->guestIP.ips[0]->address);
                VIR_DEBUG("NIC(%zu): ipaddr: %s", i, ipStr);
                VIR_FREE(ipStr);
            } else if (def->nets[i]->guestIP.nips > 1) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Driver does not support setting multiple IP addresses"));
                return -1;
            }
        }

        gVBoxAPI.UIMachine.GetNetworkAdapter(machine, i, &adapter);
        if (!adapter)
            continue;

        gVBoxAPI.UINetworkAdapter.SetEnabled(adapter, 1);

        if (def->nets[i]->model) {
            if (STRCASEEQ(def->nets[i]->model, "Am79C970A")) {
                adapterType = NetworkAdapterType_Am79C970A;
            } else if (STRCASEEQ(def->nets[i]->model, "Am79C973")) {
                adapterType = NetworkAdapterType_Am79C973;
            } else if (STRCASEEQ(def->nets[i]->model, "82540EM")) {
                adapterType = NetworkAdapterType_I82540EM;
            } else if (STRCASEEQ(def->nets[i]->model, "82545EM")) {
                adapterType = NetworkAdapterType_I82545EM;
            } else if (STRCASEEQ(def->nets[i]->model, "82543GC")) {
                adapterType = NetworkAdapterType_I82543GC;
            } else if (gVBoxAPI.APIVersion >= 3000051 &&
                       STRCASEEQ(def->nets[i]->model, "virtio")) {
                /* Only vbox 3.1 and later support NetworkAdapterType_Virto */
                adapterType = NetworkAdapterType_Virtio;
            }
        } else {
            adapterType = NetworkAdapterType_Am79C973;
        }

        gVBoxAPI.UINetworkAdapter.SetAdapterType(adapter, adapterType);

        if (def->nets[i]->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {
            PRUnichar *hostInterface = NULL;
            /* Bridged Network */

            gVBoxAPI.UINetworkAdapter.AttachToBridgedInterface(adapter);

            if (def->nets[i]->data.bridge.brname) {
                VBOX_UTF8_TO_UTF16(def->nets[i]->data.bridge.brname,
                                   &hostInterface);
                gVBoxAPI.UINetworkAdapter.SetBridgedInterface(adapter, hostInterface);
                VBOX_UTF16_FREE(hostInterface);
            }
        } else if (def->nets[i]->type == VIR_DOMAIN_NET_TYPE_INTERNAL) {
            PRUnichar *internalNetwork = NULL;
            /* Internal Network */

            gVBoxAPI.UINetworkAdapter.AttachToInternalNetwork(adapter);

            if (def->nets[i]->data.internal.name) {
                VBOX_UTF8_TO_UTF16(def->nets[i]->data.internal.name,
                                   &internalNetwork);
                gVBoxAPI.UINetworkAdapter.SetInternalNetwork(adapter, internalNetwork);
                VBOX_UTF16_FREE(internalNetwork);
            }
        } else if (def->nets[i]->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
            PRUnichar *hostInterface = NULL;
            /* Host Only Networking (currently only vboxnet0 available
             * on *nix and mac, on windows you can create and configure
             * as many as you want)
             */
            gVBoxAPI.UINetworkAdapter.AttachToHostOnlyInterface(adapter);

            if (def->nets[i]->data.network.name) {
                VBOX_UTF8_TO_UTF16(def->nets[i]->data.network.name,
                                   &hostInterface);
                gVBoxAPI.UINetworkAdapter.SetHostOnlyInterface(adapter, hostInterface);
                VBOX_UTF16_FREE(hostInterface);
            }
        } else if (def->nets[i]->type == VIR_DOMAIN_NET_TYPE_USER) {
            /* NAT */
            gVBoxAPI.UINetworkAdapter.AttachToNAT(adapter);
        } else {
            /* else always default to NAT if we don't understand
             * what option is been passed to us
             */
            gVBoxAPI.UINetworkAdapter.AttachToNAT(adapter);
        }

        VBOX_UTF8_TO_UTF16(macaddrvbox, &MACAddress);
        gVBoxAPI.UINetworkAdapter.SetMACAddress(adapter, MACAddress);
        VBOX_UTF16_FREE(MACAddress);
    }
    return 0;
}

static void
vboxAttachSerial(virDomainDefPtr def, vboxDriverPtr data, IMachine *machine)
{
    ISystemProperties *systemProperties = NULL;
    PRUint32 serialPortCount = 0;
    size_t i = 0;

    gVBoxAPI.UIVirtualBox.GetSystemProperties(data->vboxObj, &systemProperties);
    if (systemProperties) {
        gVBoxAPI.UISystemProperties.GetSerialPortCount(systemProperties,
                                                       &serialPortCount);
        VBOX_RELEASE(systemProperties);
    }

    VIR_DEBUG("Number of Serial Ports to be connected: %zu", def->nserials);
    VIR_DEBUG("Number of Serial Ports available: %d", serialPortCount);

    for (i = 0; (i < def->nserials) && (i < serialPortCount); i++) {
        ISerialPort *serialPort = NULL;
        PRUnichar *pathUtf16 = NULL;

        VIR_DEBUG("SerialPort(%zu): Type: %d", i, def->serials[i]->source->type);
        VIR_DEBUG("SerialPort(%zu): target.port: %d", i,
              def->serials[i]->target.port);

        gVBoxAPI.UIMachine.GetSerialPort(machine, i, &serialPort);
        if (!serialPort)
            continue;

        gVBoxAPI.UISerialPort.SetEnabled(serialPort, 1);

        if (def->serials[i]->source->data.file.path) {
            VBOX_UTF8_TO_UTF16(def->serials[i]->source->data.file.path,
                               &pathUtf16);
            gVBoxAPI.UISerialPort.SetPath(serialPort, pathUtf16);
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
            gVBoxAPI.UISerialPort.SetIRQ(serialPort, 4);
            gVBoxAPI.UISerialPort.SetIOBase(serialPort, 1016);
            VIR_DEBUG(" serialPort-%zu irq: %d, iobase 0x%x, path: %s",
                  i, 4, 1016, def->serials[i]->source->data.file.path);
        } else if (def->serials[i]->target.port == 1) {
            gVBoxAPI.UISerialPort.SetIRQ(serialPort, 3);
            gVBoxAPI.UISerialPort.SetIOBase(serialPort, 760);
            VIR_DEBUG(" serialPort-%zu irq: %d, iobase 0x%x, path: %s",
                  i, 3, 760, def->serials[i]->source->data.file.path);
        }

        if (def->serials[i]->source->type == VIR_DOMAIN_CHR_TYPE_DEV) {
            gVBoxAPI.UISerialPort.SetHostMode(serialPort, PortMode_HostDevice);
        } else if (def->serials[i]->source->type == VIR_DOMAIN_CHR_TYPE_PIPE) {
            gVBoxAPI.UISerialPort.SetHostMode(serialPort, PortMode_HostPipe);
        } else if (gVBoxAPI.APIVersion >= 2002051 &&
                   def->serials[i]->source->type == VIR_DOMAIN_CHR_TYPE_FILE) {
            /* PortMode RawFile is used for vbox 3.0 or later */
            gVBoxAPI.UISerialPort.SetHostMode(serialPort, PortMode_RawFile);
        } else {
            gVBoxAPI.UISerialPort.SetHostMode(serialPort,
                                              PortMode_Disconnected);
        }

        VBOX_RELEASE(serialPort);
        VBOX_UTF16_FREE(pathUtf16);
    }
}

static void
vboxAttachParallel(virDomainDefPtr def, vboxDriverPtr data, IMachine *machine)
{
    ISystemProperties *systemProperties = NULL;
    PRUint32 parallelPortCount = 0;
    size_t i = 0;

    gVBoxAPI.UIVirtualBox.GetSystemProperties(data->vboxObj, &systemProperties);
    if (systemProperties) {
        gVBoxAPI.UISystemProperties.GetParallelPortCount(systemProperties,
                                                         &parallelPortCount);
        VBOX_RELEASE(systemProperties);
    }

    VIR_DEBUG("Number of Parallel Ports to be connected: %zu", def->nparallels);
    VIR_DEBUG("Number of Parallel Ports available: %d", parallelPortCount);
    for (i = 0; (i < def->nparallels) && (i < parallelPortCount); i++) {
        IParallelPort *parallelPort = NULL;
        PRUnichar *pathUtf16 = NULL;

        VIR_DEBUG("ParallelPort(%zu): Type: %d", i, def->parallels[i]->source->type);
        VIR_DEBUG("ParallelPort(%zu): target.port: %d", i,
              def->parallels[i]->target.port);

        gVBoxAPI.UIMachine.GetParallelPort(machine, i, &parallelPort);
        if (!parallelPort)
            continue;

        VBOX_UTF8_TO_UTF16(def->parallels[i]->source->data.file.path, &pathUtf16);

        /* For now hard code the parallel ports to
         * LPT1 (Base Addr: 0x378 (decimal: 888), IRQ: 7)
         * LPT2 (Base Addr: 0x278 (decimal: 632), IRQ: 5)
         * TODO: make this more flexible
         */
        if ((def->parallels[i]->source->type == VIR_DOMAIN_CHR_TYPE_DEV) ||
            (def->parallels[i]->source->type == VIR_DOMAIN_CHR_TYPE_PTY) ||
            (def->parallels[i]->source->type == VIR_DOMAIN_CHR_TYPE_FILE) ||
            (def->parallels[i]->source->type == VIR_DOMAIN_CHR_TYPE_PIPE)) {
            gVBoxAPI.UIParallelPort.SetPath(parallelPort, pathUtf16);
            if (i == 0) {
                gVBoxAPI.UIParallelPort.SetIRQ(parallelPort, 7);
                gVBoxAPI.UIParallelPort.SetIOBase(parallelPort, 888);
                VIR_DEBUG(" parallePort-%zu irq: %d, iobase 0x%x, path: %s",
                      i, 7, 888, def->parallels[i]->source->data.file.path);
            } else if (i == 1) {
                gVBoxAPI.UIParallelPort.SetIRQ(parallelPort, 5);
                gVBoxAPI.UIParallelPort.SetIOBase(parallelPort, 632);
                VIR_DEBUG(" parallePort-%zu irq: %d, iobase 0x%x, path: %s",
                      i, 5, 632, def->parallels[i]->source->data.file.path);
            }
        }

        /* like serial port, parallel port can't be enabled unless
         * correct IRQ and IOBase values are specified.
         */
        gVBoxAPI.UIParallelPort.SetEnabled(parallelPort, 1);

        VBOX_RELEASE(parallelPort);
        VBOX_UTF16_FREE(pathUtf16);
    }
}

static void
vboxAttachVideo(virDomainDefPtr def, IMachine *machine)
{
    if ((def->nvideos == 1) &&
        (def->videos[0]->type == VIR_DOMAIN_VIDEO_TYPE_VBOX)) {
        gVBoxAPI.UIMachine.SetVRAMSize(machine,
                                       VIR_DIV_UP(def->videos[0]->vram, 1024));
        gVBoxAPI.UIMachine.SetMonitorCount(machine, def->videos[0]->heads);
        if (def->videos[0]->accel) {
            if (def->videos[0]->accel->accel3d) {
                gVBoxAPI.UIMachine.SetAccelerate3DEnabled(machine,
                    def->videos[0]->accel->accel3d == VIR_TRISTATE_BOOL_YES);
            }
            if (def->videos[0]->accel->accel2d) {
                gVBoxAPI.UIMachine.SetAccelerate2DVideoEnabled(machine,
                    def->videos[0]->accel->accel2d == VIR_TRISTATE_BOOL_YES);
            }
        } else {
            gVBoxAPI.UIMachine.SetAccelerate3DEnabled(machine, 0);
            gVBoxAPI.UIMachine.SetAccelerate2DVideoEnabled(machine, 0);
        }
    }
}

static void
vboxAttachDisplay(virDomainDefPtr def, vboxDriverPtr data, IMachine *machine)
{
    int vrdpPresent = 0;
    int sdlPresent = 0;
    int guiPresent = 0;
    char *guiDisplay = NULL;
    char *sdlDisplay = NULL;
    size_t i = 0;
    virDomainGraphicsListenDefPtr glisten;

    for (i = 0; i < def->ngraphics; i++) {
        IVRDEServer *VRDEServer = NULL;

        if ((def->graphics[i]->type == VIR_DOMAIN_GRAPHICS_TYPE_RDP) &&
            (vrdpPresent == 0)) {

            vrdpPresent = 1;
            gVBoxAPI.UIMachine.GetVRDEServer(machine, &VRDEServer);
            if (VRDEServer) {
                gVBoxAPI.UIVRDEServer.SetEnabled(VRDEServer, PR_TRUE);
                VIR_DEBUG("VRDP Support turned ON.");

                gVBoxAPI.UIVRDEServer.SetPorts(data, VRDEServer, def->graphics[i]);

                if (def->graphics[i]->data.rdp.replaceUser) {
                    gVBoxAPI.UIVRDEServer.SetReuseSingleConnection(VRDEServer,
                                                                   PR_TRUE);
                    VIR_DEBUG("VRDP set to reuse single connection");
                }

                if (def->graphics[i]->data.rdp.multiUser) {
                    gVBoxAPI.UIVRDEServer.SetAllowMultiConnection(VRDEServer,
                                                                  PR_TRUE);
                    VIR_DEBUG("VRDP set to allow multiple connection");
                }

                if ((glisten = virDomainGraphicsGetListen(def->graphics[i], 0)) &&
                    glisten->address) {
                    PRUnichar *netAddressUtf16 = NULL;

                    VBOX_UTF8_TO_UTF16(glisten->address, &netAddressUtf16);
                    gVBoxAPI.UIVRDEServer.SetNetAddress(data, VRDEServer,
                                                        netAddressUtf16);
                    VIR_DEBUG("VRDP listen address is set to: %s",
                              glisten->address);

                    VBOX_UTF16_FREE(netAddressUtf16);
                }

                VBOX_RELEASE(VRDEServer);
            }
        }

        if ((def->graphics[i]->type == VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP) &&
            (guiPresent == 0)) {
            guiPresent = 1;
            if (VIR_STRDUP(guiDisplay, def->graphics[i]->data.desktop.display) < 0) {
                /* just don't go to cleanup yet as it is ok to have
                 * guiDisplay as NULL and we check it below if it
                 * exist and then only use it there
                 */
            }
        }

        if ((def->graphics[i]->type == VIR_DOMAIN_GRAPHICS_TYPE_SDL) &&
            (sdlPresent == 0)) {
            sdlPresent = 1;
            if (VIR_STRDUP(sdlDisplay, def->graphics[i]->data.sdl.display) < 0) {
                /* just don't go to cleanup yet as it is ok to have
                 * sdlDisplay as NULL and we check it below if it
                 * exist and then only use it there
                 */
            }
        }
    }

    if ((vrdpPresent == 1) && (guiPresent == 0) && (sdlPresent == 0)) {
        /* store extradata key that frontend is set to vrdp */
        PRUnichar *keyTypeUtf16 = NULL;
        PRUnichar *valueTypeUtf16 = NULL;

        VBOX_UTF8_TO_UTF16("FRONTEND/Type", &keyTypeUtf16);
        VBOX_UTF8_TO_UTF16("vrdp", &valueTypeUtf16);

        gVBoxAPI.UIMachine.SetExtraData(machine, keyTypeUtf16, valueTypeUtf16);

        VBOX_UTF16_FREE(keyTypeUtf16);
        VBOX_UTF16_FREE(valueTypeUtf16);

    } else if ((guiPresent == 0) && (sdlPresent == 1)) {
        /* store extradata key that frontend is set to sdl */
        PRUnichar *keyTypeUtf16 = NULL;
        PRUnichar *valueTypeUtf16 = NULL;
        PRUnichar *keyDislpayUtf16 = NULL;
        PRUnichar *valueDisplayUtf16 = NULL;

        VBOX_UTF8_TO_UTF16("FRONTEND/Type", &keyTypeUtf16);
        VBOX_UTF8_TO_UTF16("sdl", &valueTypeUtf16);

        gVBoxAPI.UIMachine.SetExtraData(machine, keyTypeUtf16, valueTypeUtf16);

        VBOX_UTF16_FREE(keyTypeUtf16);
        VBOX_UTF16_FREE(valueTypeUtf16);

        if (sdlDisplay) {
            VBOX_UTF8_TO_UTF16("FRONTEND/Display", &keyDislpayUtf16);
            VBOX_UTF8_TO_UTF16(sdlDisplay, &valueDisplayUtf16);

            gVBoxAPI.UIMachine.SetExtraData(machine, keyDislpayUtf16,
                                            valueDisplayUtf16);

            VBOX_UTF16_FREE(keyDislpayUtf16);
            VBOX_UTF16_FREE(valueDisplayUtf16);
        }

    } else {
        /* if all are set then default is gui, with vrdp turned on */
        PRUnichar *keyTypeUtf16 = NULL;
        PRUnichar *valueTypeUtf16 = NULL;
        PRUnichar *keyDislpayUtf16 = NULL;
        PRUnichar *valueDisplayUtf16 = NULL;

        VBOX_UTF8_TO_UTF16("FRONTEND/Type", &keyTypeUtf16);
        VBOX_UTF8_TO_UTF16("gui", &valueTypeUtf16);

        gVBoxAPI.UIMachine.SetExtraData(machine, keyTypeUtf16, valueTypeUtf16);

        VBOX_UTF16_FREE(keyTypeUtf16);
        VBOX_UTF16_FREE(valueTypeUtf16);

        if (guiDisplay) {
            VBOX_UTF8_TO_UTF16("FRONTEND/Display", &keyDislpayUtf16);
            VBOX_UTF8_TO_UTF16(guiDisplay, &valueDisplayUtf16);

            gVBoxAPI.UIMachine.SetExtraData(machine, keyDislpayUtf16,
                                            valueDisplayUtf16);

            VBOX_UTF16_FREE(keyDislpayUtf16);
            VBOX_UTF16_FREE(valueDisplayUtf16);
        }
    }

    VIR_FREE(guiDisplay);
    VIR_FREE(sdlDisplay);
}

static void
vboxAttachUSB(virDomainDefPtr def, vboxDriverPtr data, IMachine *machine)
{
    IUSBCommon *USBCommon = NULL;
    size_t i = 0;
    bool isUSB = false;
    nsresult rc;

    if (def->nhostdevs == 0)
        return;

    /* Loop through the devices first and see if you
     * have a USB Device, only if you have one then
     * start the USB controller else just proceed as
     * usual
     */
    for (i = 0; i < def->nhostdevs; i++) {
        if (def->hostdevs[i]->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;

        if (def->hostdevs[i]->source.subsys.type !=
            VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB)
            continue;

        if (!def->hostdevs[i]->source.subsys.u.usb.vendor &&
            !def->hostdevs[i]->source.subsys.u.usb.product)
            continue;

        VIR_DEBUG("USB Device detected, VendorId:0x%x, ProductId:0x%x",
                  def->hostdevs[i]->source.subsys.u.usb.vendor,
                  def->hostdevs[i]->source.subsys.u.usb.product);
        isUSB = true;
        break;
    }

    if (!isUSB)
        return;

    /* First Start the USB Controller and then loop
     * to attach USB Devices to it
     */
    rc = gVBoxAPI.UIMachine.GetUSBCommon(machine, &USBCommon);
    if (NS_FAILED(rc) || !USBCommon)
        return;
    gVBoxAPI.UIUSBCommon.Enable(USBCommon);

    for (i = 0; i < def->nhostdevs; i++) {
        char *filtername = NULL;
        PRUnichar *filternameUtf16 = NULL;
        IUSBDeviceFilter *filter = NULL;
        PRUnichar *vendorIdUtf16 = NULL;
        char vendorId[40] = {0};
        PRUnichar *productIdUtf16 = NULL;
        char productId[40] = {0};

        if (def->hostdevs[i]->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;

        if (def->hostdevs[i]->source.subsys.type !=
            VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB)
            continue;

        /* Zero pad for nice alignment when fewer than 9999
         * devices.
         */
        if (virAsprintf(&filtername, "filter%04zu", i) >= 0) {
            VBOX_UTF8_TO_UTF16(filtername, &filternameUtf16);
            VIR_FREE(filtername);
            gVBoxAPI.UIUSBCommon.CreateDeviceFilter(USBCommon,
                                                    filternameUtf16,
                                                    &filter);
        }
        VBOX_UTF16_FREE(filternameUtf16);

        if (!filter)
            continue;

        if (!def->hostdevs[i]->source.subsys.u.usb.vendor &&
            !def->hostdevs[i]->source.subsys.u.usb.product)
            continue;

        if (def->hostdevs[i]->source.subsys.u.usb.vendor) {
            snprintf(vendorId, sizeof(vendorId), "%x",
                     def->hostdevs[i]->source.subsys.u.usb.vendor);
            VBOX_UTF8_TO_UTF16(vendorId, &vendorIdUtf16);
            gVBoxAPI.UIUSBDeviceFilter.SetVendorId(filter, vendorIdUtf16);
            VBOX_UTF16_FREE(vendorIdUtf16);
        }
        if (def->hostdevs[i]->source.subsys.u.usb.product) {
            snprintf(productId, sizeof(productId), "%x",
                     def->hostdevs[i]->source.subsys.u.usb.product);
            VBOX_UTF8_TO_UTF16(productId, &productIdUtf16);
            gVBoxAPI.UIUSBDeviceFilter.SetProductId(filter,
                                                    productIdUtf16);
            VBOX_UTF16_FREE(productIdUtf16);
        }
        gVBoxAPI.UIUSBDeviceFilter.SetActive(filter, 1);
        gVBoxAPI.UIUSBCommon.InsertDeviceFilter(USBCommon, i, filter);
        VBOX_RELEASE(filter);
    }

    VBOX_RELEASE(USBCommon);
}

static void
vboxAttachSharedFolder(virDomainDefPtr def, vboxDriverPtr data, IMachine *machine)
{
    size_t i;
    PRUnichar *nameUtf16;
    PRUnichar *hostPathUtf16;
    PRBool writable;

    if (def->nfss == 0)
        return;

    for (i = 0; i < def->nfss; i++) {
        if (def->fss[i]->type != VIR_DOMAIN_FS_TYPE_MOUNT)
            continue;

        VBOX_UTF8_TO_UTF16(def->fss[i]->dst, &nameUtf16);
        VBOX_UTF8_TO_UTF16(def->fss[i]->src->path, &hostPathUtf16);
        writable = !def->fss[i]->readonly;

        gVBoxAPI.UIMachine.CreateSharedFolder(machine, nameUtf16, hostPathUtf16,
                                              writable, PR_FALSE);

        VBOX_UTF16_FREE(nameUtf16);
        VBOX_UTF16_FREE(hostPathUtf16);
    }
}

static virDomainPtr
vboxDomainDefineXMLFlags(virConnectPtr conn, const char *xml, unsigned int flags)
{
    vboxDriverPtr data = conn->privateData;
    IMachine *machine = NULL;
    IBIOSSettings *bios = NULL;
    vboxIID mchiid;
    virDomainDefPtr def = NULL;
    nsresult rc;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virDomainPtr ret = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    virCheckFlags(VIR_DOMAIN_DEFINE_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_DEFINE_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    if (!data->vboxObj)
        return ret;

    VBOX_IID_INITIALIZE(&mchiid);
    if (!(def = virDomainDefParseString(xml, data->caps, data->xmlopt,
                                        NULL, parse_flags))) {
        goto cleanup;
    }

    virUUIDFormat(def->uuid, uuidstr);

    rc = gVBoxAPI.UIVirtualBox.CreateMachine(data, def, &machine, uuidstr);

    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not define a domain, rc=%08x"), (unsigned)rc);
        goto cleanup;
    }

    rc = gVBoxAPI.UIMachine.SetMemorySize(machine,
                                          VIR_DIV_UP(def->mem.cur_balloon, 1024));
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not set the memory size of the domain to: %llu Kb, "
                         "rc=%08x"),
                       def->mem.cur_balloon, (unsigned)rc);
    }

    if (virDomainDefHasVcpusOffline(def)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("current vcpu count must equal maximum"));
    }
    rc = gVBoxAPI.UIMachine.SetCPUCount(machine, virDomainDefGetVcpusMax(def));
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not set the number of virtual CPUs to: %u, rc=%08x"),
                       virDomainDefGetVcpusMax(def), (unsigned)rc);
    }

    rc = gVBoxAPI.UIMachine.SetCPUProperty(machine, CPUPropertyType_PAE,
                                           def->features[VIR_DOMAIN_FEATURE_PAE] ==
                                           VIR_TRISTATE_SWITCH_ON);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not change PAE status to: %s, rc=%08x"),
                       (def->features[VIR_DOMAIN_FEATURE_PAE] == VIR_TRISTATE_SWITCH_ON)
                       ? _("Enabled") : _("Disabled"), (unsigned)rc);
    }

    gVBoxAPI.UIMachine.GetBIOSSettings(machine, &bios);
    if (bios) {
        rc = gVBoxAPI.UIBIOSSettings.SetACPIEnabled(bios,
                                                    def->features[VIR_DOMAIN_FEATURE_ACPI] ==
                                                    VIR_TRISTATE_SWITCH_ON);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("could not change ACPI status to: %s, rc=%08x"),
                           (def->features[VIR_DOMAIN_FEATURE_ACPI] == VIR_TRISTATE_SWITCH_ON)
                           ? _("Enabled") : _("Disabled"), (unsigned)rc);
        }
        rc = gVBoxAPI.UIBIOSSettings.SetIOAPICEnabled(bios,
                                                      def->features[VIR_DOMAIN_FEATURE_APIC] ==
                                                      VIR_TRISTATE_SWITCH_ON);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("could not change APIC status to: %s, rc=%08x"),
                           (def->features[VIR_DOMAIN_FEATURE_APIC] == VIR_TRISTATE_SWITCH_ON)
                           ? _("Enabled") : _("Disabled"), (unsigned)rc);
        }
        VBOX_RELEASE(bios);
    }

    /* Register the machine before attaching other devices to it */
    rc = gVBoxAPI.UIVirtualBox.RegisterMachine(data->vboxObj, machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not define a domain, rc=%08x"), (unsigned)rc);
        goto cleanup;
    }

    /* Get the uuid of the machine, currently it is immutable
     * object so open a session to it and get it back, so that
     * you can make changes to the machine setting
     */
    gVBoxAPI.UIMachine.GetId(machine, &mchiid);
    gVBoxAPI.UISession.Open(data, &mchiid, machine);
    gVBoxAPI.UISession.GetMachine(data->vboxSession, &machine);

    vboxSetBootDeviceOrder(def, data, machine);
    vboxAttachDrives(def, data, machine);
    vboxAttachSound(def, machine);
    if (vboxAttachNetwork(def, data, machine) < 0)
        goto cleanup;
    vboxAttachSerial(def, data, machine);
    vboxAttachParallel(def, data, machine);
    vboxAttachVideo(def, machine);
    vboxAttachDisplay(def, data, machine);
    vboxAttachUSB(def, data, machine);
    vboxAttachSharedFolder(def, data, machine);

    /* Save the machine settings made till now and close the
     * session. also free up the mchiid variable used.
     */
    rc = gVBoxAPI.UIMachine.SaveSettings(machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed no saving settings, rc=%08x"), (unsigned)rc);
        goto cleanup;
    }

    gVBoxAPI.UISession.Close(data->vboxSession);
    vboxIIDUnalloc(&mchiid);

    ret = virGetDomain(conn, def->name, def->uuid, -1);
    VBOX_RELEASE(machine);

    virDomainDefFree(def);

    return ret;

 cleanup:
    VBOX_RELEASE(machine);
    virDomainDefFree(def);
    return NULL;
}

static virDomainPtr
vboxDomainDefineXML(virConnectPtr conn, const char *xml)
{
    return vboxDomainDefineXMLFlags(conn, xml, 0);
}

static int vboxDomainUndefineFlags(virDomainPtr dom, unsigned int flags)
{
    vboxDriverPtr data = dom->conn->privateData;
    IMachine *machine = NULL;
    vboxIID iid;
    nsresult rc;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    gVBoxAPI.UIID.vboxIIDInitialize(&iid);
    /* No managed save, so we explicitly reject
     * VIR_DOMAIN_UNDEFINE_MANAGED_SAVE.  No snapshot metadata for
     * VBox, so we can trivially ignore that flag.  */
    virCheckFlags(VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA, -1);
    vboxIIDFromUUID(&iid, dom->uuid);
    rc = gVBoxAPI.unregisterMachine(data, &iid, &machine);

    DEBUGIID("UUID of machine being undefined", &iid);

    if (NS_SUCCEEDED(rc)) {
        gVBoxAPI.deleteConfig(machine);
        ret = 0;
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not delete the domain, rc=%08x"), (unsigned)rc);
    }

    vboxIIDUnalloc(&iid);
    VBOX_RELEASE(machine);

    return ret;
}

static int vboxDomainUndefine(virDomainPtr dom)
{
    return vboxDomainUndefineFlags(dom, 0);
}

static int
vboxStartMachine(virDomainPtr dom, int maxDomID, IMachine *machine, vboxIID *iid)
{
    vboxDriverPtr data = dom->conn->privateData;
    int vrdpPresent = 0;
    int sdlPresent = 0;
    int guiPresent = 0;
    char *guiDisplay = NULL;
    char *sdlDisplay = NULL;
    PRUnichar *keyTypeUtf16 = NULL;
    PRUnichar *valueTypeUtf16 = NULL;
    char *valueTypeUtf8 = NULL;
    PRUnichar *keyDislpayUtf16 = NULL;
    PRUnichar *valueDisplayUtf16 = NULL;
    char *valueDisplayUtf8 = NULL;
    IProgress *progress = NULL;
    PRUnichar *env = NULL;
    PRUnichar *sessionType = NULL;
    nsresult rc;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    VBOX_UTF8_TO_UTF16("FRONTEND/Type", &keyTypeUtf16);
    gVBoxAPI.UIMachine.GetExtraData(machine, keyTypeUtf16, &valueTypeUtf16);
    VBOX_UTF16_FREE(keyTypeUtf16);

    if (valueTypeUtf16) {
        VBOX_UTF16_TO_UTF8(valueTypeUtf16, &valueTypeUtf8);
        VBOX_UTF16_FREE(valueTypeUtf16);

        if (STREQ(valueTypeUtf8, "sdl") || STREQ(valueTypeUtf8, "gui")) {

            VBOX_UTF8_TO_UTF16("FRONTEND/Display", &keyDislpayUtf16);
            gVBoxAPI.UIMachine.GetExtraData(machine, keyDislpayUtf16,
                                            &valueDisplayUtf16);
            VBOX_UTF16_FREE(keyDislpayUtf16);

            if (valueDisplayUtf16) {
                VBOX_UTF16_TO_UTF8(valueDisplayUtf16, &valueDisplayUtf8);
                VBOX_UTF16_FREE(valueDisplayUtf16);

                if (strlen(valueDisplayUtf8) <= 0)
                    VBOX_UTF8_FREE(valueDisplayUtf8);
            }

            if (STREQ(valueTypeUtf8, "sdl")) {
                sdlPresent = 1;
                if (VIR_STRDUP(sdlDisplay, valueDisplayUtf8) < 0) {
                    /* just don't go to cleanup yet as it is ok to have
                     * sdlDisplay as NULL and we check it below if it
                     * exist and then only use it there
                     */
                }
            }

            if (STREQ(valueTypeUtf8, "gui")) {
                guiPresent = 1;
                if (VIR_STRDUP(guiDisplay, valueDisplayUtf8) < 0) {
                    /* just don't go to cleanup yet as it is ok to have
                     * guiDisplay as NULL and we check it below if it
                     * exist and then only use it there
                     */
                }
            }
        }

        if (STREQ(valueTypeUtf8, "vrdp"))
            vrdpPresent = 1;

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
    VBOX_UTF8_FREE(valueDisplayUtf8);

    if (guiPresent) {
        if (guiDisplay) {
            char *displayutf8;
            if (virAsprintf(&displayutf8, "DISPLAY=%s", guiDisplay) >= 0) {
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
            if (virAsprintf(&displayutf8, "DISPLAY=%s", sdlDisplay) >= 0) {
                VBOX_UTF8_TO_UTF16(displayutf8, &env);
                VIR_FREE(displayutf8);
            }
            VIR_FREE(sdlDisplay);
        }

        VBOX_UTF8_TO_UTF16("sdl", &sessionType);
    }

    if (vrdpPresent)
        VBOX_UTF8_TO_UTF16("vrdp", &sessionType);

    rc = gVBoxAPI.UIMachine.LaunchVMProcess(data, machine, iid,
                                            sessionType, env,
                                            &progress);

    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("OpenRemoteSession/LaunchVMProcess failed, domain can't be started"));
        ret = -1;
    } else {
        PRBool completed = 0;
        resultCodeUnion resultCode;

        gVBoxAPI.UIProgress.WaitForCompletion(progress, -1);
        rc = gVBoxAPI.UIProgress.GetCompleted(progress, &completed);
        if (NS_FAILED(rc)) {
            /* error */
            ret = -1;
        }
        gVBoxAPI.UIProgress.GetResultCode(progress, &resultCode);
        if (RC_FAILED(resultCode)) {
            /* error */
            ret = -1;
        } else {
            /* all ok set the domid */
            dom->id = maxDomID + 1;
            ret = 0;
        }
    }

    VBOX_RELEASE(progress);

    gVBoxAPI.UISession.Close(data->vboxSession);

    VBOX_UTF16_FREE(env);
    VBOX_UTF16_FREE(sessionType);

    return ret;
}

static int vboxDomainCreateWithFlags(virDomainPtr dom, unsigned int flags)
{
    vboxDriverPtr data = dom->conn->privateData;
    vboxArray machines = VBOX_ARRAY_INITIALIZER;
    unsigned char uuid[VIR_UUID_BUFLEN] = {0};
    nsresult rc;
    size_t i = 0;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    virCheckFlags(0, -1);

    if (!dom->name) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Error while reading the domain name"));
        goto cleanup;
    }

    rc = gVBoxAPI.UArray.vboxArrayGet(&machines, data->vboxObj, ARRAY_GET_MACHINES);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get list of machines, rc=%08x"), (unsigned)rc);
        goto cleanup;
    }

    for (i = 0; i < machines.count; ++i) {
        IMachine *machine = machines.items[i];
        PRBool isAccessible = PR_FALSE;

        if (!machine)
            continue;

        gVBoxAPI.UIMachine.GetAccessible(machine, &isAccessible);
        if (isAccessible) {
            vboxIID iid;

            VBOX_IID_INITIALIZE(&iid);

            rc = gVBoxAPI.UIMachine.GetId(machine, &iid);
            if (NS_FAILED(rc))
                continue;
            vboxIIDToUUID(&iid, uuid);

            if (memcmp(dom->uuid, uuid, VIR_UUID_BUFLEN) == 0) {
                PRUint32 state;
                gVBoxAPI.UIMachine.GetState(machine, &state);

                if (gVBoxAPI.machineStateChecker.NotStart(state)) {
                    ret = vboxStartMachine(dom, i, machine, &iid);
                } else {
                    virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                                   _("machine is not in "
                                     "poweroff|saved|aborted state, so "
                                     "couldn't start it"));
                    ret = -1;
                }
            }
            vboxIIDUnalloc(&iid);
            if (ret != -1)
                break;
        }
    }

    /* Do the cleanup and take care you dont leak any memory */
    gVBoxAPI.UArray.vboxArrayRelease(&machines);

 cleanup:
    return ret;
}

static int vboxDomainCreate(virDomainPtr dom)
{
    return vboxDomainCreateWithFlags(dom, 0);
}

static virDomainPtr vboxDomainCreateXML(virConnectPtr conn, const char *xml,
                                        unsigned int flags)
{
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
        virObjectUnref(dom);
        return NULL;
    }

    return dom;
}

static int vboxDomainIsActive(virDomainPtr dom)
{
    vboxDriverPtr data = dom->conn->privateData;
    vboxArray machines = VBOX_ARRAY_INITIALIZER;
    vboxIID iid;
    char *machineNameUtf8 = NULL;
    PRUnichar *machineNameUtf16 = NULL;
    unsigned char uuid[VIR_UUID_BUFLEN];
    size_t i;
    bool matched = false;
    nsresult rc;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    VBOX_IID_INITIALIZE(&iid);
    rc = gVBoxAPI.UArray.vboxArrayGet(&machines, data->vboxObj, ARRAY_GET_MACHINES);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get list of machines, rc=%08x"), (unsigned)rc);
        return ret;
    }

    for (i = 0; i < machines.count; ++i) {
        IMachine *machine = machines.items[i];
        PRBool isAccessible = PR_FALSE;

        if (!machine)
            continue;

        gVBoxAPI.UIMachine.GetAccessible(machine, &isAccessible);
        if (!isAccessible)
            continue;

        gVBoxAPI.UIMachine.GetId(machine, &iid);
        if (NS_FAILED(rc))
            continue;
        vboxIIDToUUID(&iid, uuid);
        vboxIIDUnalloc(&iid);

        if (memcmp(dom->uuid, uuid, VIR_UUID_BUFLEN) == 0) {

            PRUint32 state;

            matched = true;

            gVBoxAPI.UIMachine.GetName(machine, &machineNameUtf16);
            VBOX_UTF16_TO_UTF8(machineNameUtf16, &machineNameUtf8);

            gVBoxAPI.UIMachine.GetState(machine, &state);

            if (gVBoxAPI.machineStateChecker.Online(state))
                ret = 1;
            else
                ret = 0;
        }

        if (matched)
            break;
    }

    /* Do the cleanup and take care you dont leak any memory */
    VBOX_UTF8_FREE(machineNameUtf8);
    VBOX_COM_UNALLOC_MEM(machineNameUtf16);
    gVBoxAPI.UArray.vboxArrayRelease(&machines);

    return ret;
}

static int vboxDomainIsPersistent(virDomainPtr dom)
{
    /* All domains are persistent.  However, we do want to check for
     * existence. */
    vboxDriverPtr data = dom->conn->privateData;
    vboxIID iid;
    IMachine *machine = NULL;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    if (openSessionForMachine(data, dom->uuid, &iid, &machine) < 0)
        goto cleanup;

    ret = 1;

 cleanup:
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    return ret;
}

static int vboxDomainIsUpdated(virDomainPtr dom)
{
    /* VBox domains never have a persistent state that differs from
     * current state.  However, we do want to check for existence.  */
    vboxDriverPtr data = dom->conn->privateData;
    vboxIID iid;
    IMachine *machine = NULL;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    if (openSessionForMachine(data, dom->uuid, &iid, &machine) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    return ret;
}

static int vboxDomainSuspend(virDomainPtr dom)
{
    vboxDriverPtr data = dom->conn->privateData;
    IMachine *machine = NULL;
    vboxIID iid;
    IConsole *console = NULL;
    PRBool isAccessible = PR_FALSE;
    PRUint32 state;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    if (openSessionForMachine(data, dom->uuid, &iid, &machine) < 0)
        goto cleanup;

    if (!machine)
        goto cleanup;

    gVBoxAPI.UIMachine.GetAccessible(machine, &isAccessible);
    if (!isAccessible)
        goto cleanup;

    gVBoxAPI.UIMachine.GetState(machine, &state);

    if (gVBoxAPI.machineStateChecker.Running(state)) {
        /* set state pause */
        gVBoxAPI.UISession.OpenExisting(data, &iid, machine);
        gVBoxAPI.UISession.GetConsole(data->vboxSession, &console);
        if (console) {
            gVBoxAPI.UIConsole.Pause(console);
            VBOX_RELEASE(console);
            ret = 0;
        } else {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("error while suspending the domain"));
            goto cleanup;
        }
        gVBoxAPI.UISession.Close(data->vboxSession);
    } else {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("machine not in running state to suspend it"));
        goto cleanup;
    }

 cleanup:
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    return ret;
}

static int vboxDomainResume(virDomainPtr dom)
{
    vboxDriverPtr data = dom->conn->privateData;
    IMachine *machine = NULL;
    vboxIID iid;
    IConsole *console = NULL;
    PRUint32 state;
    PRBool isAccessible = PR_FALSE;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    if (openSessionForMachine(data, dom->uuid, &iid, &machine) < 0)
        goto cleanup;

    if (!machine)
        goto cleanup;

    gVBoxAPI.UIMachine.GetAccessible(machine, &isAccessible);
    if (!isAccessible)
        goto cleanup;

    gVBoxAPI.UIMachine.GetState(machine, &state);

    if (gVBoxAPI.machineStateChecker.Paused(state)) {
        /* resume the machine here */
        gVBoxAPI.UISession.OpenExisting(data, &iid, machine);
        gVBoxAPI.UISession.GetConsole(data->vboxSession, &console);
        if (console) {
            gVBoxAPI.UIConsole.Resume(console);
            VBOX_RELEASE(console);
            ret = 0;
        } else {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("error while resuming the domain"));
            goto cleanup;
        }
        gVBoxAPI.UISession.Close(data->vboxSession);
    } else {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("machine not paused, so can't resume it"));
        goto cleanup;
    }

 cleanup:
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    return ret;
}

static int vboxDomainShutdownFlags(virDomainPtr dom, unsigned int flags)
{
    vboxDriverPtr data = dom->conn->privateData;
    IMachine *machine = NULL;
    vboxIID iid;
    IConsole *console = NULL;
    PRUint32 state;
    PRBool isAccessible = PR_FALSE;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    virCheckFlags(0, -1);

    if (openSessionForMachine(data, dom->uuid, &iid, &machine) < 0)
        goto cleanup;

    if (!machine)
        goto cleanup;

    gVBoxAPI.UIMachine.GetAccessible(machine, &isAccessible);
    if (!isAccessible)
        goto cleanup;

    gVBoxAPI.UIMachine.GetState(machine, &state);

    if (gVBoxAPI.machineStateChecker.Paused(state)) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("machine paused, so can't power it down"));
        goto cleanup;
    } else if (gVBoxAPI.machineStateChecker.PoweredOff(state)) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("machine already powered down"));
        goto cleanup;
    }

    gVBoxAPI.UISession.OpenExisting(data, &iid, machine);
    gVBoxAPI.UISession.GetConsole(data->vboxSession, &console);
    if (console) {
        gVBoxAPI.UIConsole.PowerButton(console);
        VBOX_RELEASE(console);
        ret = 0;
    }
    gVBoxAPI.UISession.Close(data->vboxSession);

 cleanup:
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    return ret;
}

static int vboxDomainShutdown(virDomainPtr dom)
{
    return vboxDomainShutdownFlags(dom, 0);
}

static int vboxDomainReboot(virDomainPtr dom, unsigned int flags)
{
    vboxDriverPtr data = dom->conn->privateData;
    IMachine *machine = NULL;
    vboxIID iid;
    IConsole *console = NULL;
    PRUint32 state;
    PRBool isAccessible = PR_FALSE;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    virCheckFlags(0, -1);

    if (openSessionForMachine(data, dom->uuid, &iid, &machine) < 0)
        goto cleanup;

    if (!machine)
        goto cleanup;

    gVBoxAPI.UIMachine.GetAccessible(machine, &isAccessible);
    if (!isAccessible)
        goto cleanup;

    gVBoxAPI.UIMachine.GetState(machine, &state);

    if (gVBoxAPI.machineStateChecker.Running(state)) {
        gVBoxAPI.UISession.OpenExisting(data, &iid, machine);
        gVBoxAPI.UISession.GetConsole(data->vboxSession, &console);
        if (console) {
            gVBoxAPI.UIConsole.Reset(console);
            VBOX_RELEASE(console);
            ret = 0;
        }
        gVBoxAPI.UISession.Close(data->vboxSession);
    } else {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("machine not running, so can't reboot it"));
        goto cleanup;
    }

 cleanup:
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    return ret;
}

static int vboxDomainDestroyFlags(virDomainPtr dom, unsigned int flags)
{
    vboxDriverPtr data = dom->conn->privateData;
    IMachine *machine = NULL;
    vboxIID iid;
    IConsole *console = NULL;
    PRUint32 state;
    PRBool isAccessible = PR_FALSE;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    virCheckFlags(0, -1);

    if (openSessionForMachine(data, dom->uuid, &iid, &machine) < 0)
        goto cleanup;

    if (!machine)
        goto cleanup;

    gVBoxAPI.UIMachine.GetAccessible(machine, &isAccessible);
    if (!isAccessible)
        goto cleanup;

    gVBoxAPI.UIMachine.GetState(machine, &state);

    if (gVBoxAPI.machineStateChecker.PoweredOff(state)) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("machine already powered down"));
        goto cleanup;
    }

    gVBoxAPI.UISession.OpenExisting(data, &iid, machine);
    gVBoxAPI.UISession.GetConsole(data->vboxSession, &console);
    if (console) {
        gVBoxAPI.UIConsole.PowerDown(console);
        VBOX_RELEASE(console);
        dom->id = -1;
        ret = 0;
    }
    gVBoxAPI.UISession.Close(data->vboxSession);

 cleanup:
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    return ret;
}

static int vboxDomainDestroy(virDomainPtr dom)
{
    return vboxDomainDestroyFlags(dom, 0);
}

static char *vboxDomainGetOSType(virDomainPtr dom ATTRIBUTE_UNUSED) {
    /* Returning "hvm" always as suggested on list, cause
     * this functions seems to be badly named and it
     * is supposed to pass the ABI name and not the domain
     * operating system driver as I had imagined ;)
     */
    char *osType;

    ignore_value(VIR_STRDUP(osType, "hvm"));
    return osType;
}

static int vboxDomainSetMemory(virDomainPtr dom, unsigned long memory)
{
    vboxDriverPtr data = dom->conn->privateData;
    IMachine *machine = NULL;
    vboxIID iid;
    PRUint32 state;
    PRBool isAccessible = PR_FALSE;
    nsresult rc;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    if (openSessionForMachine(data, dom->uuid, &iid, &machine) < 0)
        goto cleanup;

    if (!machine)
        goto cleanup;

    gVBoxAPI.UIMachine.GetAccessible(machine, &isAccessible);
    if (!isAccessible)
        goto cleanup;

    gVBoxAPI.UIMachine.GetState(machine, &state);

    if (!gVBoxAPI.machineStateChecker.PoweredOff(state)) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("memory size can't be changed unless domain is powered down"));
        goto cleanup;
    }

    rc = gVBoxAPI.UISession.Open(data, &iid, machine);
    if (NS_FAILED(rc))
        goto cleanup;

    rc = gVBoxAPI.UISession.GetMachine(data->vboxSession, &machine);
    if (NS_SUCCEEDED(rc) && machine) {

        rc = gVBoxAPI.UIMachine.SetMemorySize(machine,
                                              VIR_DIV_UP(memory, 1024));
        if (NS_SUCCEEDED(rc)) {
            gVBoxAPI.UIMachine.SaveSettings(machine);
            ret = 0;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("could not set the memory size of the "
                             "domain to: %lu Kb, rc=%08x"),
                           memory, (unsigned)rc);
        }
    }
    gVBoxAPI.UISession.Close(data->vboxSession);

 cleanup:
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    return ret;
}

static int vboxDomainGetInfo(virDomainPtr dom, virDomainInfoPtr info)
{
    vboxDriverPtr data = dom->conn->privateData;
    vboxArray machines = VBOX_ARRAY_INITIALIZER;
    char *machineName = NULL;
    PRUnichar *machineNameUtf16 = NULL;
    nsresult rc;
    size_t i = 0;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    rc = gVBoxAPI.UArray.vboxArrayGet(&machines, data->vboxObj, ARRAY_GET_MACHINES);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get list of machines, rc=%08x"), (unsigned)rc);
        goto cleanup;
    }

    info->nrVirtCpu = 0;
    for (i = 0; i < machines.count; ++i) {
        IMachine *machine = machines.items[i];
        PRBool isAccessible = PR_FALSE;

        if (!machine)
            continue;

        gVBoxAPI.UIMachine.GetAccessible(machine, &isAccessible);
        if (!isAccessible)
            continue;

        gVBoxAPI.UIMachine.GetName(machine, &machineNameUtf16);
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
            PRUint32 CPUCount = 0;
            PRUint32 memorySize = 0;
            PRUint32 state;
            PRUint32 maxMemorySize = 4 * 1024;
            ISystemProperties *systemProperties = NULL;

            gVBoxAPI.UIVirtualBox.GetSystemProperties(data->vboxObj, &systemProperties);
            if (systemProperties) {
                gVBoxAPI.UISystemProperties.GetMaxGuestRAM(systemProperties, &maxMemorySize);
                VBOX_RELEASE(systemProperties);
                systemProperties = NULL;
            }

            gVBoxAPI.UIMachine.GetCPUCount(machine, &CPUCount);
            gVBoxAPI.UIMachine.GetMemorySize(machine, &memorySize);
            gVBoxAPI.UIMachine.GetState(machine, &state);

            info->cpuTime = 0;
            info->nrVirtCpu = CPUCount;
            info->memory = memorySize * 1024;
            info->maxMem = maxMemorySize * 1024;
            info->state = gVBoxAPI.vboxConvertState(state);

            ret = 0;
        }

        VBOX_UTF8_FREE(machineName);
        VBOX_COM_UNALLOC_MEM(machineNameUtf16);
        if (info->nrVirtCpu)
            break;

    }

    gVBoxAPI.UArray.vboxArrayRelease(&machines);

 cleanup:
    return ret;
}

static int vboxDomainGetState(virDomainPtr dom, int *state,
                              int *reason, unsigned int flags)
{
    vboxDriverPtr data = dom->conn->privateData;
    vboxIID domiid;
    IMachine *machine = NULL;
    PRUint32 mstate;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    virCheckFlags(0, -1);

    if (openSessionForMachine(data, dom->uuid, &domiid, &machine) < 0)
        goto cleanup;

    gVBoxAPI.UIMachine.GetState(machine, &mstate);

    *state = gVBoxAPI.vboxConvertState(mstate);

    if (reason)
        *reason = 0;

    ret = 0;

 cleanup:
    vboxIIDUnalloc(&domiid);
    return ret;
}

static int vboxDomainSetVcpusFlags(virDomainPtr dom, unsigned int nvcpus,
                                   unsigned int flags)
{
    vboxDriverPtr data = dom->conn->privateData;
    IMachine *machine = NULL;
    vboxIID iid;
    PRUint32 CPUCount = nvcpus;
    nsresult rc;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    if (flags != VIR_DOMAIN_AFFECT_LIVE) {
        virReportError(VIR_ERR_INVALID_ARG, _("unsupported flags: (0x%x)"), flags);
        return -1;
    }

    if (openSessionForMachine(data, dom->uuid, &iid, &machine) < 0)
        return -1;

    rc = gVBoxAPI.UISession.Open(data, &iid, machine);
    if (NS_SUCCEEDED(rc)) {
        gVBoxAPI.UISession.GetMachine(data->vboxSession, &machine);
        if (machine) {
            rc = gVBoxAPI.UIMachine.SetCPUCount(machine, CPUCount);
            if (NS_SUCCEEDED(rc)) {
                gVBoxAPI.UIMachine.SaveSettings(machine);
                ret = 0;
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("could not set the number of cpus of the domain "
                                 "to: %u, rc=%08x"),
                               CPUCount, (unsigned)rc);
            }
            VBOX_RELEASE(machine);
        } else {
            virReportError(VIR_ERR_NO_DOMAIN,
                           _("no domain with matching id %d"), dom->id);
        }
    } else {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("can't open session to the domain with id %d"), dom->id);
    }
    gVBoxAPI.UISession.Close(data->vboxSession);

    vboxIIDUnalloc(&iid);
    return ret;
}

static int vboxDomainSetVcpus(virDomainPtr dom, unsigned int nvcpus)
{
    return vboxDomainSetVcpusFlags(dom, nvcpus, VIR_DOMAIN_AFFECT_LIVE);
}

static int vboxDomainGetVcpusFlags(virDomainPtr dom, unsigned int flags)
{
    vboxDriverPtr data = dom->conn->privateData;
    ISystemProperties *systemProperties = NULL;
    PRUint32 maxCPUCount = 0;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    if (flags != (VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_VCPU_MAXIMUM)) {
        virReportError(VIR_ERR_INVALID_ARG, _("unsupported flags: (0x%x)"), flags);
        return -1;
    }

    /* Currently every domain supports the same number of max cpus
     * as that supported by vbox and thus take it directly from
     * the systemproperties.
     */

    gVBoxAPI.UIVirtualBox.GetSystemProperties(data->vboxObj, &systemProperties);
    if (systemProperties) {
        gVBoxAPI.UISystemProperties.GetMaxGuestCPUCount(systemProperties, &maxCPUCount);
        VBOX_RELEASE(systemProperties);
    }

    if (maxCPUCount > 0)
        ret = maxCPUCount;

    return ret;
}

static int vboxDomainGetMaxVcpus(virDomainPtr dom)
{
    return vboxDomainGetVcpusFlags(dom, (VIR_DOMAIN_AFFECT_LIVE |
                                         VIR_DOMAIN_VCPU_MAXIMUM));
}

static void
vboxHostDeviceGetXMLDesc(vboxDriverPtr data, virDomainDefPtr def, IMachine *machine)
{
    IUSBCommon *USBCommon = NULL;
    PRBool enabled = PR_FALSE;
    vboxArray deviceFilters = VBOX_ARRAY_INITIALIZER;
    size_t i;
    PRUint32 USBFilterCount = 0;

    def->nhostdevs = 0;

    gVBoxAPI.UIMachine.GetUSBCommon(machine, &USBCommon);
    if (!USBCommon)
        return;

    gVBoxAPI.UIUSBCommon.GetEnabled(USBCommon, &enabled);
    if (!enabled)
        goto release_controller;

    gVBoxAPI.UArray.vboxArrayGet(&deviceFilters, USBCommon,
                                 gVBoxAPI.UArray.handleUSBGetDeviceFilters(USBCommon));

    if (deviceFilters.count <= 0)
        goto release_filters;

    /* check if the filters are active and then only
     * alloc mem and set def->nhostdevs
     */

    for (i = 0; i < deviceFilters.count; i++) {
        PRBool active = PR_FALSE;
        IUSBDeviceFilter *deviceFilter = deviceFilters.items[i];

        gVBoxAPI.UIUSBDeviceFilter.GetActive(deviceFilter, &active);
        if (active)
            def->nhostdevs++;
    }

    if (def->nhostdevs == 0)
        goto release_filters;

    /* Alloc mem needed for the filters now */
    if (VIR_ALLOC_N(def->hostdevs, def->nhostdevs) < 0)
        goto release_filters;

    for (i = 0; i < def->nhostdevs; i++) {
        def->hostdevs[i] = virDomainHostdevDefAlloc(NULL);
        if (!def->hostdevs[i])
            goto release_hostdevs;
    }

    for (i = 0; i < deviceFilters.count; i++) {
        PRBool active = PR_FALSE;
        IUSBDeviceFilter *deviceFilter = deviceFilters.items[i];
        PRUnichar *vendorIdUtf16 = NULL;
        char *vendorIdUtf8 = NULL;
        unsigned vendorId = 0;
        PRUnichar *productIdUtf16 = NULL;
        char *productIdUtf8 = NULL;
        unsigned productId = 0;
        char *endptr = NULL;

        gVBoxAPI.UIUSBDeviceFilter.GetActive(deviceFilter, &active);
        if (!active)
            continue;

        def->hostdevs[USBFilterCount]->mode =
            VIR_DOMAIN_HOSTDEV_MODE_SUBSYS;
        def->hostdevs[USBFilterCount]->source.subsys.type =
            VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB;

        gVBoxAPI.UIUSBDeviceFilter.GetVendorId(deviceFilter, &vendorIdUtf16);
        gVBoxAPI.UIUSBDeviceFilter.GetProductId(deviceFilter, &productIdUtf16);

        VBOX_UTF16_TO_UTF8(vendorIdUtf16, &vendorIdUtf8);
        VBOX_UTF16_TO_UTF8(productIdUtf16, &productIdUtf8);

        ignore_value(virStrToLong_ui(vendorIdUtf8, &endptr, 16, &vendorId));
        ignore_value(virStrToLong_ui(productIdUtf8, &endptr, 16, &productId));

        def->hostdevs[USBFilterCount]->source.subsys.u.usb.vendor = vendorId;
        def->hostdevs[USBFilterCount]->source.subsys.u.usb.product = productId;

        VBOX_UTF16_FREE(vendorIdUtf16);
        VBOX_UTF8_FREE(vendorIdUtf8);

        VBOX_UTF16_FREE(productIdUtf16);
        VBOX_UTF8_FREE(productIdUtf8);

        USBFilterCount++;
    }

 release_filters:
    gVBoxAPI.UArray.vboxArrayRelease(&deviceFilters);
 release_controller:
    VBOX_RELEASE(USBCommon);
    return;

 release_hostdevs:
    for (i = 0; i < def->nhostdevs; i++)
        virDomainHostdevDefFree(def->hostdevs[i]);
    VIR_FREE(def->hostdevs);

    goto release_filters;
}

static void
vboxDumpIDEHDDs(virDomainDefPtr def, vboxDriverPtr data, IMachine *machine)
{
    /* dump IDE hdds if present */
    vboxArray mediumAttachments = VBOX_ARRAY_INITIALIZER;
    bool error = false;
    int diskCount = 0;
    size_t i;
    PRUint32 maxPortPerInst[StorageBus_Floppy + 1] = {};
    PRUint32 maxSlotPerPort[StorageBus_Floppy + 1] = {};

    def->ndisks = 0;
    gVBoxAPI.UArray.vboxArrayGet(&mediumAttachments, machine,
                                 gVBoxAPI.UArray.handleMachineGetMediumAttachments(machine));

    /* get the number of attachments */
    for (i = 0; i < mediumAttachments.count; i++) {
        IMediumAttachment *imediumattach = mediumAttachments.items[i];
        if (imediumattach) {
            IMedium *medium = NULL;

            gVBoxAPI.UIMediumAttachment.GetMedium(imediumattach, &medium);
            if (medium) {
                def->ndisks++;
                VBOX_RELEASE(medium);
            }
        }
    }

    /* Allocate mem, if fails return error */
    if (VIR_ALLOC_N(def->disks, def->ndisks) >= 0) {
        for (i = 0; i < def->ndisks; i++) {
            virDomainDiskDefPtr disk = virDomainDiskDefNew(NULL);
            if (!disk) {
                error = true;
                break;
            }
            def->disks[i] = disk;
        }
    } else {
        error = true;
    }

    if (!error)
        error = !vboxGetMaxPortSlotValues(data->vboxObj, maxPortPerInst, maxSlotPerPort);

    /* get the attachment details here */
    for (i = 0; i < mediumAttachments.count && diskCount < def->ndisks && !error; i++) {
        IMediumAttachment *imediumattach = mediumAttachments.items[i];
        IStorageController *storageController = NULL;
        PRUnichar *storageControllerName = NULL;
        PRUint32 deviceType = DeviceType_Null;
        PRUint32 storageBus = StorageBus_Null;
        PRBool readOnly = PR_FALSE;
        IMedium *medium = NULL;
        PRUnichar *mediumLocUtf16 = NULL;
        char *mediumLocUtf8 = NULL;
        PRUint32 deviceInst = 0;
        PRInt32 devicePort = 0;
        PRInt32 deviceSlot = 0;

        if (!imediumattach)
            continue;

        gVBoxAPI.UIMediumAttachment.GetMedium(imediumattach, &medium);
        if (!medium)
            continue;

        gVBoxAPI.UIMediumAttachment.GetController(imediumattach, &storageControllerName);
        if (!storageControllerName) {
            VBOX_RELEASE(medium);
            continue;
        }

        gVBoxAPI.UIMachine.GetStorageControllerByName(machine,
                                                      storageControllerName,
                                                      &storageController);
        VBOX_UTF16_FREE(storageControllerName);
        if (!storageController) {
            VBOX_RELEASE(medium);
            continue;
        }

        gVBoxAPI.UIMedium.GetLocation(medium, &mediumLocUtf16);
        VBOX_UTF16_TO_UTF8(mediumLocUtf16, &mediumLocUtf8);
        VBOX_UTF16_FREE(mediumLocUtf16);
        ignore_value(virDomainDiskSetSource(def->disks[diskCount],
                                            mediumLocUtf8));
        VBOX_UTF8_FREE(mediumLocUtf8);

        if (!virDomainDiskGetSource(def->disks[diskCount])) {
            VBOX_RELEASE(medium);
            VBOX_RELEASE(storageController);
            error = true;
            break;
        }

        gVBoxAPI.UIStorageController.GetBus(storageController, &storageBus);
        if (storageBus == StorageBus_IDE) {
            def->disks[diskCount]->bus = VIR_DOMAIN_DISK_BUS_IDE;
        } else if (storageBus == StorageBus_SATA) {
            def->disks[diskCount]->bus = VIR_DOMAIN_DISK_BUS_SATA;
        } else if (storageBus == StorageBus_SCSI) {
            def->disks[diskCount]->bus = VIR_DOMAIN_DISK_BUS_SCSI;
        } else if (storageBus == StorageBus_Floppy) {
            def->disks[diskCount]->bus = VIR_DOMAIN_DISK_BUS_FDC;
        }

        gVBoxAPI.UIMediumAttachment.GetType(imediumattach, &deviceType);
        if (deviceType == DeviceType_HardDisk)
            def->disks[diskCount]->device = VIR_DOMAIN_DISK_DEVICE_DISK;
        else if (deviceType == DeviceType_Floppy)
            def->disks[diskCount]->device = VIR_DOMAIN_DISK_DEVICE_FLOPPY;
        else if (deviceType == DeviceType_DVD)
            def->disks[diskCount]->device = VIR_DOMAIN_DISK_DEVICE_CDROM;

        gVBoxAPI.UIMediumAttachment.GetPort(imediumattach, &devicePort);
        gVBoxAPI.UIMediumAttachment.GetDevice(imediumattach, &deviceSlot);
        def->disks[diskCount]->dst = vboxGenerateMediumName(storageBus,
                                                            deviceInst,
                                                            devicePort,
                                                            deviceSlot,
                                                            maxPortPerInst,
                                                            maxSlotPerPort);
        if (!def->disks[diskCount]->dst) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not generate medium name for the disk "
                             "at: controller instance:%u, port:%d, slot:%d"),
                           deviceInst, devicePort, deviceSlot);
            VBOX_RELEASE(medium);
            VBOX_RELEASE(storageController);
            error = true;
            break;
        }

        gVBoxAPI.UIMedium.GetReadOnly(medium, &readOnly);
        if (readOnly == PR_TRUE)
            def->disks[diskCount]->src->readonly = true;

        virDomainDiskSetType(def->disks[diskCount],
                             VIR_STORAGE_TYPE_FILE);

        VBOX_RELEASE(medium);
        VBOX_RELEASE(storageController);
        diskCount++;
    }

    gVBoxAPI.UArray.vboxArrayRelease(&mediumAttachments);

    /* cleanup on error */
    if (error) {
        for (i = 0; i < def->ndisks; i++)
            VIR_FREE(def->disks[i]);
        VIR_FREE(def->disks);
        def->ndisks = 0;
    }
}

static int
vboxDumpVideo(virDomainDefPtr def, vboxDriverPtr data ATTRIBUTE_UNUSED,
              IMachine *machine)
{
    /* dump video options vram/2d/3d/directx/etc. */
    /* the default is: vram is 8MB, One monitor, 3dAccel Off */
    PRUint32 VRAMSize = 8;
    PRUint32 monitorCount = 1;
    PRBool accelerate3DEnabled = PR_FALSE;
    PRBool accelerate2DEnabled = PR_FALSE;

    /* Currently supports only one graphics card */
    if (VIR_ALLOC_N(def->videos, 1) < 0)
        return -1;
    def->nvideos = 1;

    if (VIR_ALLOC(def->videos[0]) < 0)
        return -1;

    gVBoxAPI.UIMachine.GetVRAMSize(machine, &VRAMSize);
    gVBoxAPI.UIMachine.GetMonitorCount(machine, &monitorCount);
    gVBoxAPI.UIMachine.GetAccelerate3DEnabled(machine, &accelerate3DEnabled);
    gVBoxAPI.UIMachine.GetAccelerate2DVideoEnabled(machine, &accelerate2DEnabled);

    def->videos[0]->type = VIR_DOMAIN_VIDEO_TYPE_VBOX;
    def->videos[0]->vram = VRAMSize * 1024;
    def->videos[0]->heads = monitorCount;
    if (VIR_ALLOC(def->videos[0]->accel) < 0)
        return -1;
    def->videos[0]->accel->accel3d = accelerate3DEnabled ?
        VIR_TRISTATE_BOOL_YES : VIR_TRISTATE_BOOL_NO;
    def->videos[0]->accel->accel2d = accelerate2DEnabled ?
        VIR_TRISTATE_BOOL_YES : VIR_TRISTATE_BOOL_NO;

    return 0;
}

static int
vboxDumpDisplay(virDomainDefPtr def, vboxDriverPtr data, IMachine *machine)
{
    /* dump display options vrdp/gui/sdl */
    PRUnichar *keyUtf16 = NULL;
    PRUnichar *valueTypeUtf16 = NULL;
    char *valueTypeUtf8 = NULL;
    char *netAddressUtf8 = NULL;
    IVRDEServer *VRDEServer = NULL;
    PRBool VRDxEnabled = PR_FALSE;
    virDomainGraphicsDefPtr graphics = NULL;
    int ret = -1;

    def->ngraphics = 0;

    VBOX_UTF8_TO_UTF16("FRONTEND/Type", &keyUtf16);
    gVBoxAPI.UIMachine.GetExtraData(machine, keyUtf16, &valueTypeUtf16);
    VBOX_UTF16_FREE(keyUtf16);

    if (valueTypeUtf16) {
        VBOX_UTF16_TO_UTF8(valueTypeUtf16, &valueTypeUtf8);
        VBOX_UTF16_FREE(valueTypeUtf16);
    }

    if (STREQ_NULLABLE(valueTypeUtf8, "sdl") ||
        STREQ_NULLABLE(valueTypeUtf8, "gui")) {
        PRUnichar *valueDisplayUtf16 = NULL;
        char *valueDisplayUtf8 = NULL;

        if (VIR_ALLOC(graphics) < 0)
            goto cleanup;

        VBOX_UTF8_TO_UTF16("FRONTEND/Display", &keyUtf16);
        gVBoxAPI.UIMachine.GetExtraData(machine, keyUtf16, &valueDisplayUtf16);
        VBOX_UTF16_FREE(keyUtf16);

        if (valueDisplayUtf16) {
            VBOX_UTF16_TO_UTF8(valueDisplayUtf16, &valueDisplayUtf8);
            VBOX_UTF16_FREE(valueDisplayUtf16);

            if (STREQ(valueDisplayUtf8, ""))
                VBOX_UTF8_FREE(valueDisplayUtf8);
        }

        if (STREQ(valueTypeUtf8, "sdl")) {
            graphics->type = VIR_DOMAIN_GRAPHICS_TYPE_SDL;
            graphics->data.sdl.display = valueDisplayUtf8;
            valueDisplayUtf8 = NULL;
        }

        if (STREQ(valueTypeUtf8, "gui")) {
            graphics->type = VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP;
            graphics->data.desktop.display = valueDisplayUtf8;
            valueDisplayUtf8 = NULL;
        }
        VBOX_UTF8_FREE(valueDisplayUtf8);
    } else if (STRNEQ_NULLABLE(valueTypeUtf8, "vrdp")) {
        if (VIR_ALLOC(graphics) < 0)
            goto cleanup;

        graphics->type = VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP;
        if (VIR_STRDUP(graphics->data.desktop.display,
                       virGetEnvBlockSUID("DISPLAY")) < 0)
            goto cleanup;
    }

    if (graphics &&
        VIR_APPEND_ELEMENT(def->graphics, def->ngraphics, graphics) < 0)
        goto cleanup;

    gVBoxAPI.UIMachine.GetVRDEServer(machine, &VRDEServer);
    if (VRDEServer)
        gVBoxAPI.UIVRDEServer.GetEnabled(VRDEServer, &VRDxEnabled);

    if (VRDxEnabled) {
        PRUnichar *netAddressUtf16 = NULL;
        PRBool allowMultiConnection = PR_FALSE;
        PRBool reuseSingleConnection = PR_FALSE;

        if (VIR_ALLOC(graphics) < 0)
            goto cleanup;

        gVBoxAPI.UIVRDEServer.GetPorts(data, VRDEServer, graphics);

        graphics->type = VIR_DOMAIN_GRAPHICS_TYPE_RDP;

        gVBoxAPI.UIVRDEServer.GetNetAddress(data, VRDEServer, &netAddressUtf16);
        if (netAddressUtf16) {
            VBOX_UTF16_TO_UTF8(netAddressUtf16, &netAddressUtf8);
            VBOX_UTF16_FREE(netAddressUtf16);
        }

        if (netAddressUtf8 && STREQ(netAddressUtf8, ""))
            VBOX_UTF8_FREE(netAddressUtf8);

        if (virDomainGraphicsListenAppendAddress(graphics, netAddressUtf8) < 0)
            goto cleanup;

        gVBoxAPI.UIVRDEServer.GetAllowMultiConnection(VRDEServer, &allowMultiConnection);
        if (allowMultiConnection)
            graphics->data.rdp.multiUser = true;

        gVBoxAPI.UIVRDEServer.GetReuseSingleConnection(VRDEServer, &reuseSingleConnection);
        if (reuseSingleConnection)
            graphics->data.rdp.replaceUser = true;

        if (VIR_APPEND_ELEMENT(def->graphics, def->ngraphics, graphics) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    VBOX_RELEASE(VRDEServer);
    VBOX_UTF8_FREE(valueTypeUtf8);
    VBOX_UTF8_FREE(netAddressUtf8);
    virDomainGraphicsDefFree(graphics);
    return ret;
}

static void
vboxDumpSharedFolders(virDomainDefPtr def, vboxDriverPtr data, IMachine *machine)
{
    /* shared folders */
    vboxArray sharedFolders = VBOX_ARRAY_INITIALIZER;
    size_t i = 0;

    def->nfss = 0;

    gVBoxAPI.UArray.vboxArrayGet(&sharedFolders, machine,
                                 gVBoxAPI.UArray.handleMachineGetSharedFolders(machine));

    if (sharedFolders.count <= 0)
        goto sharedFoldersCleanup;

    if (VIR_ALLOC_N(def->fss, sharedFolders.count) < 0)
        goto sharedFoldersCleanup;

    for (i = 0; i < sharedFolders.count; i++) {
        ISharedFolder *sharedFolder = sharedFolders.items[i];
        PRUnichar *nameUtf16 = NULL;
        char *name = NULL;
        PRUnichar *hostPathUtf16 = NULL;
        char *hostPath = NULL;
        PRBool writable = PR_FALSE;

        if (VIR_ALLOC(def->fss[i]) < 0)
            goto sharedFoldersCleanup;

        def->fss[i]->type = VIR_DOMAIN_FS_TYPE_MOUNT;

        gVBoxAPI.UISharedFolder.GetHostPath(sharedFolder, &hostPathUtf16);
        VBOX_UTF16_TO_UTF8(hostPathUtf16, &hostPath);
        if (VIR_STRDUP(def->fss[i]->src->path, hostPath) < 0) {
            VBOX_UTF8_FREE(hostPath);
            VBOX_UTF16_FREE(hostPathUtf16);
            goto sharedFoldersCleanup;
        }
        VBOX_UTF8_FREE(hostPath);
        VBOX_UTF16_FREE(hostPathUtf16);

        gVBoxAPI.UISharedFolder.GetName(sharedFolder, &nameUtf16);
        VBOX_UTF16_TO_UTF8(nameUtf16, &name);
        if (VIR_STRDUP(def->fss[i]->dst, name) < 0) {
            VBOX_UTF8_FREE(name);
            VBOX_UTF16_FREE(nameUtf16);
            goto sharedFoldersCleanup;
        }
        VBOX_UTF8_FREE(name);
        VBOX_UTF16_FREE(nameUtf16);

        gVBoxAPI.UISharedFolder.GetWritable(sharedFolder, &writable);
        def->fss[i]->readonly = !writable;

        ++def->nfss;
    }

 sharedFoldersCleanup:
    gVBoxAPI.UArray.vboxArrayRelease(&sharedFolders);
}

static void
vboxDumpNetwork(virDomainDefPtr def, vboxDriverPtr data, IMachine *machine, PRUint32 networkAdapterCount)
{
    PRUint32 netAdpIncCnt = 0;
    size_t i = 0;
    /* dump network cards if present */
    def->nnets = 0;
    /* Get which network cards are enabled */
    for (i = 0; i < networkAdapterCount; i++) {
        INetworkAdapter *adapter = NULL;

        gVBoxAPI.UIMachine.GetNetworkAdapter(machine, i, &adapter);
        if (adapter) {
            PRBool enabled = PR_FALSE;

            gVBoxAPI.UINetworkAdapter.GetEnabled(adapter, &enabled);
            if (enabled)
                def->nnets++;

            VBOX_RELEASE(adapter);
        }
    }

    /* Allocate memory for the networkcards which are enabled */
    if ((def->nnets > 0) && (VIR_ALLOC_N(def->nets, def->nnets) >= 0)) {
        for (i = 0; i < def->nnets; i++)
            ignore_value(VIR_ALLOC(def->nets[i]));
    }

    /* Now get the details about the network cards here */
    for (i = 0; netAdpIncCnt < def->nnets && i < networkAdapterCount; i++) {
        INetworkAdapter *adapter = NULL;

        gVBoxAPI.UIMachine.GetNetworkAdapter(machine, i, &adapter);
        if (adapter) {
            PRBool enabled = PR_FALSE;

            gVBoxAPI.UINetworkAdapter.GetEnabled(adapter, &enabled);
            if (enabled) {
                PRUint32 attachmentType = NetworkAttachmentType_Null;
                PRUint32 adapterType = NetworkAdapterType_Null;
                PRUnichar *MACAddressUtf16 = NULL;
                char *MACAddress = NULL;
                char macaddr[VIR_MAC_STRING_BUFLEN] = {0};

                gVBoxAPI.UINetworkAdapter.GetAttachmentType(adapter, &attachmentType);
                if (attachmentType == NetworkAttachmentType_NAT) {

                    def->nets[netAdpIncCnt]->type = VIR_DOMAIN_NET_TYPE_USER;

                } else if (attachmentType == NetworkAttachmentType_Bridged) {
                    PRUnichar *hostIntUtf16 = NULL;
                    char *hostInt = NULL;

                    def->nets[netAdpIncCnt]->type = VIR_DOMAIN_NET_TYPE_BRIDGE;

                    gVBoxAPI.UINetworkAdapter.GetBridgedInterface(adapter, &hostIntUtf16);

                    VBOX_UTF16_TO_UTF8(hostIntUtf16, &hostInt);
                    ignore_value(VIR_STRDUP(def->nets[netAdpIncCnt]->data.bridge.brname, hostInt));

                    VBOX_UTF8_FREE(hostInt);
                    VBOX_UTF16_FREE(hostIntUtf16);

                } else if (attachmentType == NetworkAttachmentType_Internal) {
                    PRUnichar *intNetUtf16 = NULL;
                    char *intNet = NULL;

                    def->nets[netAdpIncCnt]->type = VIR_DOMAIN_NET_TYPE_INTERNAL;

                    gVBoxAPI.UINetworkAdapter.GetInternalNetwork(adapter, &intNetUtf16);

                    VBOX_UTF16_TO_UTF8(intNetUtf16, &intNet);
                    ignore_value(VIR_STRDUP(def->nets[netAdpIncCnt]->data.internal.name, intNet));

                    VBOX_UTF8_FREE(intNet);
                    VBOX_UTF16_FREE(intNetUtf16);

                } else if (attachmentType == NetworkAttachmentType_HostOnly) {
                    PRUnichar *hostIntUtf16 = NULL;
                    char *hostInt = NULL;

                    def->nets[netAdpIncCnt]->type = VIR_DOMAIN_NET_TYPE_NETWORK;

                    gVBoxAPI.UINetworkAdapter.GetHostOnlyInterface(adapter, &hostIntUtf16);

                    VBOX_UTF16_TO_UTF8(hostIntUtf16, &hostInt);
                    ignore_value(VIR_STRDUP(def->nets[netAdpIncCnt]->data.network.name, hostInt));

                    VBOX_UTF8_FREE(hostInt);
                    VBOX_UTF16_FREE(hostIntUtf16);

                } else {
                    /* default to user type i.e. NAT in VirtualBox if this
                     * dump is ever used to create a machine.
                     */
                    def->nets[netAdpIncCnt]->type = VIR_DOMAIN_NET_TYPE_USER;
                }

                gVBoxAPI.UINetworkAdapter.GetAdapterType(adapter, &adapterType);
                if (adapterType == NetworkAdapterType_Am79C970A) {
                    ignore_value(VIR_STRDUP(def->nets[netAdpIncCnt]->model, "Am79C970A"));
                } else if (adapterType == NetworkAdapterType_Am79C973) {
                    ignore_value(VIR_STRDUP(def->nets[netAdpIncCnt]->model, "Am79C973"));
                } else if (adapterType == NetworkAdapterType_I82540EM) {
                    ignore_value(VIR_STRDUP(def->nets[netAdpIncCnt]->model, "82540EM"));
                } else if (adapterType == NetworkAdapterType_I82545EM) {
                    ignore_value(VIR_STRDUP(def->nets[netAdpIncCnt]->model, "82545EM"));
                } else if (adapterType == NetworkAdapterType_I82543GC) {
                    ignore_value(VIR_STRDUP(def->nets[netAdpIncCnt]->model, "82543GC"));
                } else if (gVBoxAPI.APIVersion >= 3000051 &&
                           adapterType == NetworkAdapterType_Virtio) {
                    /* Only vbox 3.1 and later support NetworkAdapterType_Virto */
                    ignore_value(VIR_STRDUP(def->nets[netAdpIncCnt]->model, "virtio"));
                }

                gVBoxAPI.UINetworkAdapter.GetMACAddress(adapter, &MACAddressUtf16);
                VBOX_UTF16_TO_UTF8(MACAddressUtf16, &MACAddress);
                snprintf(macaddr, VIR_MAC_STRING_BUFLEN,
                         "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",
                         MACAddress[0], MACAddress[1], MACAddress[2], MACAddress[3],
                         MACAddress[4], MACAddress[5], MACAddress[6], MACAddress[7],
                         MACAddress[8], MACAddress[9], MACAddress[10], MACAddress[11]);

                /* XXX some real error handling here some day ... */
                ignore_value(virMacAddrParse(macaddr,
                                             &def->nets[netAdpIncCnt]->mac));

                netAdpIncCnt++;

                VBOX_UTF16_FREE(MACAddressUtf16);
                VBOX_UTF8_FREE(MACAddress);
            }

            VBOX_RELEASE(adapter);
        }
    }
}

static void
vboxDumpAudio(virDomainDefPtr def, vboxDriverPtr data ATTRIBUTE_UNUSED,
              IMachine *machine)
{
    /* dump sound card if active */

    /* Set def->nsounds to one as VirtualBox currently supports
     * only one sound card
     */
    IAudioAdapter *audioAdapter = NULL;

    gVBoxAPI.UIMachine.GetAudioAdapter(machine, &audioAdapter);
    if (audioAdapter) {
        PRBool enabled = PR_FALSE;

        gVBoxAPI.UIAudioAdapter.GetEnabled(audioAdapter, &enabled);
        if (enabled) {
            PRUint32 audioController = AudioControllerType_AC97;

            def->nsounds = 1;
            if (VIR_ALLOC_N(def->sounds, def->nsounds) >= 0) {
                if (VIR_ALLOC(def->sounds[0]) >= 0) {
                    gVBoxAPI.UIAudioAdapter.GetAudioController(audioAdapter, &audioController);
                    if (audioController == AudioControllerType_SB16) {
                        def->sounds[0]->model = VIR_DOMAIN_SOUND_MODEL_SB16;
                    } else if (audioController == AudioControllerType_AC97) {
                        def->sounds[0]->model = VIR_DOMAIN_SOUND_MODEL_AC97;
                    }
                } else {
                    VIR_FREE(def->sounds);
                    def->nsounds = 0;
                }
            } else {
                def->nsounds = 0;
            }
        }
        VBOX_RELEASE(audioAdapter);
    }
}

static void
vboxDumpSerial(virDomainDefPtr def, vboxDriverPtr data, IMachine *machine, PRUint32 serialPortCount)
{
    PRUint32 serialPortIncCount = 0;
    size_t i = 0;
    /* dump serial port if active */
    def->nserials = 0;
    /* Get which serial ports are enabled/active */
    for (i = 0; i < serialPortCount; i++) {
        ISerialPort *serialPort = NULL;

        gVBoxAPI.UIMachine.GetSerialPort(machine, i, &serialPort);
        if (serialPort) {
            PRBool enabled = PR_FALSE;

            gVBoxAPI.UISerialPort.GetEnabled(serialPort, &enabled);
            if (enabled)
                def->nserials++;

            VBOX_RELEASE(serialPort);
        }
    }

    /* Allocate memory for the serial ports which are enabled */
    if ((def->nserials > 0) && (VIR_ALLOC_N(def->serials, def->nserials) >= 0)) {
        for (i = 0; i < def->nserials; i++)
            ignore_value(VIR_ALLOC(def->serials[i]));
    }

    /* Now get the details about the serial ports here */
    for (i = 0;
         serialPortIncCount < def->nserials && i < serialPortCount;
         i++) {
        ISerialPort *serialPort = NULL;

        gVBoxAPI.UIMachine.GetSerialPort(machine, i, &serialPort);
        if (serialPort) {
            PRBool enabled = PR_FALSE;

            gVBoxAPI.UISerialPort.GetEnabled(serialPort, &enabled);
            if (enabled) {
                PRUint32 hostMode = PortMode_Disconnected;
                PRUint32 IOBase = 0;
                PRUint32 IRQ = 0;
                PRUnichar *pathUtf16 = NULL;
                char *path = NULL;

                gVBoxAPI.UISerialPort.GetHostMode(serialPort, &hostMode);
                if (hostMode == PortMode_HostPipe) {
                    def->serials[serialPortIncCount]->source->type = VIR_DOMAIN_CHR_TYPE_PIPE;
                } else if (hostMode == PortMode_HostDevice) {
                    def->serials[serialPortIncCount]->source->type = VIR_DOMAIN_CHR_TYPE_DEV;
                } else if (gVBoxAPI.APIVersion >= 2002051 &&
                           hostMode == PortMode_RawFile) {
                    /* PortMode RawFile is used for vbox 3.0 or later */
                    def->serials[serialPortIncCount]->source->type = VIR_DOMAIN_CHR_TYPE_FILE;
                } else {
                    def->serials[serialPortIncCount]->source->type = VIR_DOMAIN_CHR_TYPE_NULL;
                }

                def->serials[serialPortIncCount]->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL;

                gVBoxAPI.UISerialPort.GetIRQ(serialPort, &IRQ);
                gVBoxAPI.UISerialPort.GetIOBase(serialPort, &IOBase);
                if ((IRQ == 4) && (IOBase == 1016)) {
                    def->serials[serialPortIncCount]->target.port = 0;
                } else if ((IRQ == 3) && (IOBase == 760)) {
                    def->serials[serialPortIncCount]->target.port = 1;
                }

                gVBoxAPI.UISerialPort.GetPath(serialPort, &pathUtf16);

                if (pathUtf16) {
                    VBOX_UTF16_TO_UTF8(pathUtf16, &path);
                    ignore_value(VIR_STRDUP(def->serials[serialPortIncCount]->source->data.file.path, path));
                }

                serialPortIncCount++;

                VBOX_UTF16_FREE(pathUtf16);
                VBOX_UTF8_FREE(path);
            }

            VBOX_RELEASE(serialPort);
        }
    }
}

static void
vboxDumpParallel(virDomainDefPtr def, vboxDriverPtr data, IMachine *machine, PRUint32 parallelPortCount)
{
    PRUint32 parallelPortIncCount = 0;
    size_t i = 0;
    /* dump parallel ports if active */
    def->nparallels = 0;
    /* Get which parallel ports are enabled/active */
    for (i = 0; i < parallelPortCount; i++) {
        IParallelPort *parallelPort = NULL;

        gVBoxAPI.UIMachine.GetParallelPort(machine, i, &parallelPort);
        if (parallelPort) {
            PRBool enabled = PR_FALSE;

            gVBoxAPI.UIParallelPort.GetEnabled(parallelPort, &enabled);
            if (enabled)
                def->nparallels++;

            VBOX_RELEASE(parallelPort);
        }
    }

    /* Allocate memory for the parallel ports which are enabled */
    if ((def->nparallels > 0) && (VIR_ALLOC_N(def->parallels, def->nparallels) >= 0)) {
        for (i = 0; i < def->nparallels; i++)
            ignore_value(VIR_ALLOC(def->parallels[i]));
    }

    /* Now get the details about the parallel ports here */
    for (i = 0;
         parallelPortIncCount < def->nparallels &&
             i < parallelPortCount;
         i++) {
        IParallelPort *parallelPort = NULL;

        gVBoxAPI.UIMachine.GetParallelPort(machine, i, &parallelPort);
        if (parallelPort) {
            PRBool enabled = PR_FALSE;

            gVBoxAPI.UIParallelPort.GetEnabled(parallelPort, &enabled);
            if (enabled) {
                PRUint32 IOBase = 0;
                PRUint32 IRQ = 0;
                PRUnichar *pathUtf16 = NULL;
                char *path = NULL;

                gVBoxAPI.UIParallelPort.GetIRQ(parallelPort, &IRQ);
                gVBoxAPI.UIParallelPort.GetIOBase(parallelPort, &IOBase);
                if ((IRQ == 7) && (IOBase == 888)) {
                    def->parallels[parallelPortIncCount]->target.port = 0;
                } else if ((IRQ == 5) && (IOBase == 632)) {
                    def->parallels[parallelPortIncCount]->target.port = 1;
                }

                def->parallels[parallelPortIncCount]->source->type = VIR_DOMAIN_CHR_TYPE_FILE;
                def->parallels[parallelPortIncCount]->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL;

                gVBoxAPI.UIParallelPort.GetPath(parallelPort, &pathUtf16);

                VBOX_UTF16_TO_UTF8(pathUtf16, &path);
                ignore_value(VIR_STRDUP(def->parallels[parallelPortIncCount]->source->data.file.path, path));

                parallelPortIncCount++;

                VBOX_UTF16_FREE(pathUtf16);
                VBOX_UTF8_FREE(path);
            }

            VBOX_RELEASE(parallelPort);
        }
    }
}

static char *vboxDomainGetXMLDesc(virDomainPtr dom, unsigned int flags)
{
    vboxDriverPtr data = dom->conn->privateData;
    virDomainDefPtr def = NULL;
    IMachine *machine = NULL;
    vboxIID iid;
    PRBool accessible = PR_FALSE;
    size_t i = 0;
    PRBool PAEEnabled = PR_FALSE;
    PRBool ACPIEnabled = PR_FALSE;
    PRBool IOAPICEnabled = PR_FALSE;
    PRUint32 CPUCount = 0;
    PRUint32 memorySize = 0;
    PRUint32 networkAdapterCount = 0;
    PRUint32 maxMemorySize = 4 * 1024;
    PRUint32 maxBootPosition = 0;
    PRUint32 serialPortCount = 0;
    PRUint32 parallelPortCount = 0;
    IBIOSSettings *bios = NULL;
    PRUint32 chipsetType = ChipsetType_Null;
    ISystemProperties *systemProperties = NULL;
    char *ret = NULL;

    if (!data->vboxObj)
        return ret;

    /* Flags checked by virDomainDefFormat */

    if (openSessionForMachine(data, dom->uuid, &iid, &machine) < 0)
        goto cleanup;

    if (!(def = virDomainDefNew()))
        goto cleanup;

    gVBoxAPI.UIMachine.GetAccessible(machine, &accessible);
    if (!accessible)
        goto cleanup;

    def->virtType = VIR_DOMAIN_VIRT_VBOX;
    def->id = dom->id;
    memcpy(def->uuid, dom->uuid, VIR_UUID_BUFLEN);
    if (VIR_STRDUP(def->name, dom->name) < 0)
        goto cleanup;

    gVBoxAPI.UIMachine.GetMemorySize(machine, &memorySize);
    def->mem.cur_balloon = memorySize * 1024;

    if (gVBoxAPI.chipsetType)
        gVBoxAPI.UIMachine.GetChipsetType(machine, &chipsetType);

    gVBoxAPI.UIVirtualBox.GetSystemProperties(data->vboxObj, &systemProperties);
    if (systemProperties) {
        gVBoxAPI.UISystemProperties.GetMaxGuestRAM(systemProperties, &maxMemorySize);
        gVBoxAPI.UISystemProperties.GetMaxBootPosition(systemProperties, &maxBootPosition);
        gVBoxAPI.UISystemProperties.GetMaxNetworkAdapters(systemProperties, chipsetType, &networkAdapterCount);
        gVBoxAPI.UISystemProperties.GetSerialPortCount(systemProperties, &serialPortCount);
        gVBoxAPI.UISystemProperties.GetParallelPortCount(systemProperties, &parallelPortCount);
        VBOX_RELEASE(systemProperties);
        systemProperties = NULL;
    }
    /* Currently setting memory and maxMemory as same, cause
     * the notation here seems to be inconsistent while
     * reading and while dumping xml
     */
    /* def->mem.max_balloon = maxMemorySize * 1024; */
    virDomainDefSetMemoryTotal(def, memorySize * 1024);

    gVBoxAPI.UIMachine.GetCPUCount(machine, &CPUCount);
    if (virDomainDefSetVcpusMax(def, CPUCount, data->xmlopt) < 0)
        goto cleanup;

    if (virDomainDefSetVcpus(def, CPUCount) < 0)
        goto cleanup;

    /* Skip cpumasklen, cpumask, onReboot, onPoweroff, onCrash */

    def->os.type = VIR_DOMAIN_OSTYPE_HVM;
    def->os.arch = virArchFromHost();

    def->os.nBootDevs = 0;
    for (i = 0; (i < VIR_DOMAIN_BOOT_LAST) && (i < maxBootPosition); i++) {
        PRUint32 device = DeviceType_Null;

        gVBoxAPI.UIMachine.GetBootOrder(machine, i+1, &device);

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

    gVBoxAPI.UIMachine.GetCPUProperty(machine, CPUPropertyType_PAE, &PAEEnabled);
    if (PAEEnabled)
        def->features[VIR_DOMAIN_FEATURE_PAE] = VIR_TRISTATE_SWITCH_ON;

    gVBoxAPI.UIMachine.GetBIOSSettings(machine, &bios);
    if (bios) {
        gVBoxAPI.UIBIOSSettings.GetACPIEnabled(bios, &ACPIEnabled);
        if (ACPIEnabled)
            def->features[VIR_DOMAIN_FEATURE_ACPI] = VIR_TRISTATE_SWITCH_ON;

        gVBoxAPI.UIBIOSSettings.GetIOAPICEnabled(bios, &IOAPICEnabled);
        if (IOAPICEnabled)
            def->features[VIR_DOMAIN_FEATURE_APIC] = VIR_TRISTATE_SWITCH_ON;

        VBOX_RELEASE(bios);
    }

    /* Currently VirtualBox always uses locatime
     * so locatime is always true here */
    def->clock.offset = VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME;

    if (vboxDumpVideo(def, data, machine) < 0)
        goto cleanup;
    if (vboxDumpDisplay(def, data, machine) < 0)
        goto cleanup;

    vboxDumpIDEHDDs(def, data, machine);

    vboxDumpSharedFolders(def, data, machine);
    vboxDumpNetwork(def, data, machine, networkAdapterCount);
    vboxDumpAudio(def, data, machine);
    vboxDumpSerial(def, data, machine, serialPortCount);
    vboxDumpParallel(def, data, machine, parallelPortCount);

    /* dump USB devices/filters if active */
    vboxHostDeviceGetXMLDesc(data, def, machine);

    ret = virDomainDefFormat(def, data->caps,
                             virDomainDefFormatConvertXMLFlags(flags));

 cleanup:
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    virDomainDefFree(def);
    return ret;
}

static int vboxConnectListDefinedDomains(virConnectPtr conn,
                                         char ** const names, int maxnames)
{
    vboxDriverPtr data = conn->privateData;
    vboxArray machines = VBOX_ARRAY_INITIALIZER;
    char *machineName = NULL;
    PRUnichar *machineNameUtf16 = NULL;
    PRUint32 state;
    nsresult rc;
    size_t i, j;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    rc = gVBoxAPI.UArray.vboxArrayGet(&machines, data->vboxObj,
                                      ARRAY_GET_MACHINES);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get list of Defined Domains, rc=%08x"),
                       (unsigned)rc);
        goto cleanup;
    }

    memset(names, 0, sizeof(names[i]) * maxnames);

    ret = 0;
    for (i = 0, j = 0; (i < machines.count) && (j < maxnames); i++) {
        PRBool isAccessible = PR_FALSE;
        IMachine *machine = machines.items[i];

        if (!machine)
            continue;

        gVBoxAPI.UIMachine.GetAccessible(machine, &isAccessible);
        if (!isAccessible)
            continue;

        gVBoxAPI.UIMachine.GetState(machine, &state);
        if (!gVBoxAPI.machineStateChecker.Inactive(state))
            continue;

        gVBoxAPI.UIMachine.GetName(machine, &machineNameUtf16);
        VBOX_UTF16_TO_UTF8(machineNameUtf16, &machineName);
        if (VIR_STRDUP(names[j], machineName) < 0) {
            VBOX_UTF16_FREE(machineNameUtf16);
            VBOX_UTF8_FREE(machineName);
            for (j = 0; j < maxnames; j++)
                VIR_FREE(names[j]);
            ret = -1;
            goto cleanup;
        }
        VBOX_UTF16_FREE(machineNameUtf16);
        VBOX_UTF8_FREE(machineName);
        j++;
        ret++;
    }

 cleanup:
    gVBoxAPI.UArray.vboxArrayRelease(&machines);
    return ret;
}

static int vboxConnectNumOfDefinedDomains(virConnectPtr conn)
{
    vboxDriverPtr data = conn->privateData;
    vboxArray machines = VBOX_ARRAY_INITIALIZER;
    PRUint32 state;
    nsresult rc;
    size_t i;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    rc = gVBoxAPI.UArray.vboxArrayGet(&machines, data->vboxObj,
                                      ARRAY_GET_MACHINES);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get number of Defined Domains, rc=%08x"),
                       (unsigned)rc);
        goto cleanup;
    }

    ret = 0;
    for (i = 0; i < machines.count; ++i) {
        PRBool isAccessible = PR_FALSE;
        IMachine *machine = machines.items[i];

        if (!machine)
            continue;

        gVBoxAPI.UIMachine.GetAccessible(machine, &isAccessible);
        if (!isAccessible)
            continue;

        gVBoxAPI.UIMachine.GetState(machine, &state);
        if (gVBoxAPI.machineStateChecker.Inactive(state))
            ret++;
    }

 cleanup:
    gVBoxAPI.UArray.vboxArrayRelease(&machines);
    return ret;
}

static int vboxDomainAttachDeviceImpl(virDomainPtr dom,
                                      const char *xml,
                                      int mediaChangeOnly ATTRIBUTE_UNUSED)
{
    vboxDriverPtr data = dom->conn->privateData;
    IMachine *machine = NULL;
    vboxIID iid;
    PRUint32 state;
    virDomainDefPtr def = NULL;
    virDomainDeviceDefPtr dev = NULL;
    nsresult rc;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    VBOX_IID_INITIALIZE(&iid);
    if (!(def = virDomainDefNew()))
        return ret;

    def->os.type = VIR_DOMAIN_OSTYPE_HVM;

    dev = virDomainDeviceDefParse(xml, def, data->caps, data->xmlopt,
                                  VIR_DOMAIN_DEF_PARSE_INACTIVE);
    if (dev == NULL)
        goto cleanup;

    if (openSessionForMachine(data, dom->uuid, &iid, &machine) < 0)
        goto cleanup;

    if (!machine)
        goto cleanup;

    gVBoxAPI.UIMachine.GetState(machine, &state);

    if (gVBoxAPI.machineStateChecker.Running(state) ||
        gVBoxAPI.machineStateChecker.Paused(state)) {
        rc = gVBoxAPI.UISession.OpenExisting(data, &iid, machine);
    } else {
        rc = gVBoxAPI.UISession.Open(data, &iid, machine);
    }

    if (NS_FAILED(rc))
        goto cleanup;

    rc = gVBoxAPI.UISession.GetMachine(data->vboxSession, &machine);

    if (NS_SUCCEEDED(rc) && machine) {
        /* ret = -VIR_ERR_ARGUMENT_UNSUPPORTED means the current device don't support hotplug. */
        ret = -VIR_ERR_ARGUMENT_UNSUPPORTED;
        if (dev->type == VIR_DOMAIN_DEVICE_FS &&
            dev->data.fs->type == VIR_DOMAIN_FS_TYPE_MOUNT) {
            PRUnichar *nameUtf16;
            PRUnichar *hostPathUtf16;
            PRBool writable;

            VBOX_UTF8_TO_UTF16(dev->data.fs->dst, &nameUtf16);
            VBOX_UTF8_TO_UTF16(dev->data.fs->src->path, &hostPathUtf16);
            writable = !dev->data.fs->readonly;

            rc = gVBoxAPI.UIMachine.CreateSharedFolder(machine, nameUtf16, hostPathUtf16,
                                                       writable, PR_FALSE);

            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("could not attach shared folder '%s', rc=%08x"),
                               dev->data.fs->dst, (unsigned)rc);
                ret = -1;
            } else {
                ret = 0;
            }

            VBOX_UTF16_FREE(nameUtf16);
            VBOX_UTF16_FREE(hostPathUtf16);
        }
        gVBoxAPI.UIMachine.SaveSettings(machine);
        VBOX_RELEASE(machine);

        if (ret == -VIR_ERR_ARGUMENT_UNSUPPORTED) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, _("Unsupported device type %d"), dev->type);
            ret = -1;
        }
    }
    gVBoxAPI.UISession.Close(data->vboxSession);

 cleanup:
    vboxIIDUnalloc(&iid);
    virDomainDefFree(def);
    virDomainDeviceDefFree(dev);
    return ret;
}

static int vboxDomainAttachDevice(virDomainPtr dom, const char *xml)
{
    return vboxDomainAttachDeviceImpl(dom, xml, 0);
}

static int vboxDomainAttachDeviceFlags(virDomainPtr dom, const char *xml,
                                       unsigned int flags)
{
    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE, -1);

    return vboxDomainAttachDeviceImpl(dom, xml, 0);
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
    vboxDriverPtr data = dom->conn->privateData;
    IMachine *machine = NULL;
    vboxIID iid;
    PRUint32 state;
    virDomainDefPtr def = NULL;
    virDomainDeviceDefPtr dev = NULL;
    nsresult rc;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    VBOX_IID_INITIALIZE(&iid);
    if (!(def = virDomainDefNew()))
        return ret;

    def->os.type = VIR_DOMAIN_OSTYPE_HVM;

    dev = virDomainDeviceDefParse(xml, def, data->caps, data->xmlopt,
                                  VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                  VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE);
    if (dev == NULL)
        goto cleanup;

    if (openSessionForMachine(data, dom->uuid, &iid, &machine) < 0)
        goto cleanup;

    if (!machine)
        goto cleanup;

    gVBoxAPI.UIMachine.GetState(machine, &state);

    if (gVBoxAPI.machineStateChecker.Running(state) ||
        gVBoxAPI.machineStateChecker.Paused(state)) {
        rc = gVBoxAPI.UISession.OpenExisting(data, &iid, machine);
    } else {
        rc = gVBoxAPI.UISession.Open(data, &iid, machine);
    }

    if (NS_FAILED(rc))
        goto cleanup;

    rc = gVBoxAPI.UISession.GetMachine(data->vboxSession, &machine);
    if (NS_SUCCEEDED(rc) && machine) {
        /* ret = -VIR_ERR_ARGUMENT_UNSUPPORTED means the current device don't support hotplug. */
        ret = -VIR_ERR_ARGUMENT_UNSUPPORTED;
        if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV) {
            if (dev->data.hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {
                if (dev->data.hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB) {
                }
            }
        } else if (dev->type == VIR_DOMAIN_DEVICE_FS &&
                   dev->data.fs->type == VIR_DOMAIN_FS_TYPE_MOUNT) {
            PRUnichar *nameUtf16;

            VBOX_UTF8_TO_UTF16(dev->data.fs->dst, &nameUtf16);

            rc = gVBoxAPI.UIMachine.RemoveSharedFolder(machine, nameUtf16);

            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("could not detach shared folder '%s', rc=%08x"),
                               dev->data.fs->dst, (unsigned)rc);
            } else {
                ret = 0;
            }

            VBOX_UTF16_FREE(nameUtf16);
        }
        gVBoxAPI.UIMachine.SaveSettings(machine);
        VBOX_RELEASE(machine);

        if (ret == -VIR_ERR_ARGUMENT_UNSUPPORTED) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, _("Unsupported device type %d"), dev->type);
            ret = -1;
        }
    }
    gVBoxAPI.UISession.Close(data->vboxSession);

 cleanup:
    vboxIIDUnalloc(&iid);
    virDomainDefFree(def);
    virDomainDeviceDefFree(dev);
    return ret;
}

static int vboxDomainDetachDeviceFlags(virDomainPtr dom, const char *xml,
                                       unsigned int flags)
{
    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE, -1);

    return vboxDomainDetachDevice(dom, xml);
}

static int vboxCloseDisksRecursively(virDomainPtr dom, char *location)
{
    vboxDriverPtr data = dom->conn->privateData;
    nsresult rc;
    size_t i = 0;
    PRUnichar *locationUtf = NULL;
    IMedium *medium = NULL;
    IMedium **children = NULL;
    PRUint32 childrenSize = 0;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    if (!gVBoxAPI.vboxSnapshotRedefine)
        VIR_WARN("This function may not work in current version");

    VBOX_UTF8_TO_UTF16(location, &locationUtf);
    rc = gVBoxAPI.UIVirtualBox.OpenMedium(data->vboxObj,
                                          locationUtf,
                                          DeviceType_HardDisk,
                                          AccessMode_ReadWrite,
                                          &medium);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to open HardDisk, rc=%08x"),
                       (unsigned)rc);
        goto cleanup;
    }
    rc = gVBoxAPI.UIMedium.GetChildren(medium, &childrenSize, &children);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to get disk children"));
        goto cleanup;
    }
    for (i = 0; i < childrenSize; i++) {
        IMedium *childMedium = children[i];
        if (childMedium) {
            PRUnichar *childLocationUtf = NULL;
            char *childLocation = NULL;
            rc = gVBoxAPI.UIMedium.GetLocation(childMedium, &childLocationUtf);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unable to get childMedium location"));
                goto cleanup;
            }
            VBOX_UTF16_TO_UTF8(childLocationUtf, &childLocation);
            VBOX_UTF16_FREE(childLocationUtf);
            if (vboxCloseDisksRecursively(dom, childLocation) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unable to close disk children"));
                goto cleanup;
            }
            VIR_FREE(childLocation);
        }
    }
    rc = gVBoxAPI.UIMedium.Close(medium);
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
    vboxDriverPtr data = dom->conn->privateData;
    vboxIID domiid;
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
    char **searchResultTab = NULL;
    ssize_t resultSize = 0;
    int it = 0;
    int jt = 0;
    PRUint32 aMediaSize = 0;
    IMedium **aMedia = NULL;
    char *machineLocationPath = NULL;
    char *nameTmpUse = NULL;
    bool snapshotFileExists = false;
    bool needToChangeStorageController = false;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    if (!gVBoxAPI.vboxSnapshotRedefine)
        VIR_WARN("This function may not work in current version");

    if (openSessionForMachine(data, dom->uuid, &domiid, &machine) < 0)
        goto cleanup;

    rc = gVBoxAPI.UIMachine.SaveSettings(machine);
    /*It may failed when the machine is not mutable.*/
    rc = gVBoxAPI.UIMachine.GetSettingsFilePath(machine, &settingsFilePath);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot get settings file path"));
        goto cleanup;
    }
    VBOX_UTF16_TO_UTF8(settingsFilePath, &settingsFilePath_Utf8);

    /*Getting the machine name to retrieve the machine location path.*/
    rc = gVBoxAPI.UIMachine.GetName(machine, &machineNameUtf16);
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
            char *uuid = NULL;
            PRUnichar *formatUtf = NULL;
            char *format = NULL;
            const char *parentUuid = NULL;
            vboxIID iid;

            VBOX_IID_INITIALIZE(&iid);
            VBOX_UTF8_TO_UTF16(realReadWriteDisksPath[it], &locationUtf);
            rc = gVBoxAPI.UIVirtualBox.OpenMedium(data->vboxObj,
                                                  locationUtf,
                                                  DeviceType_HardDisk,
                                                  AccessMode_ReadWrite,
                                                  &readWriteMedium);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to open HardDisk, rc=%08x"),
                               (unsigned)rc);
                VBOX_UTF16_FREE(locationUtf);
                goto cleanup;
            }
            VBOX_UTF16_FREE(locationUtf);

            rc = gVBoxAPI.UIMedium.GetId(readWriteMedium, &iid);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unable to get the read write medium id"));
                goto cleanup;
            }
            gVBoxAPI.UIID.vboxIIDToUtf8(data, &iid, &uuid);
            vboxIIDUnalloc(&iid);

            rc = gVBoxAPI.UIMedium.GetFormat(readWriteMedium, &formatUtf);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unable to get the read write medium format"));
                goto cleanup;
            }
            VBOX_UTF16_TO_UTF8(formatUtf, &format);
            VBOX_UTF16_FREE(formatUtf);

            if (VIR_ALLOC(readWriteDisk) < 0) {
                VIR_FREE(formatUtf);
                goto cleanup;
            }

            readWriteDisk->format = format;
            readWriteDisk->uuid = uuid;
            readWriteDisk->location = realReadWriteDisksPath[it];
            /*
             * We get the current snapshot's read-only disk uuid in order to add the
             * read-write disk to the media registry as its child. The read-only disk
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
            rc = gVBoxAPI.UIMedium.Close(readWriteMedium);
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
        char *uuid = NULL;
        PRUnichar *formatUtf = NULL;
        char *format = NULL;
        char *parentUuid = NULL;
        virVBoxSnapshotConfHardDiskPtr readOnlyDisk = NULL;
        vboxIID iid, parentiid;

        VBOX_IID_INITIALIZE(&iid);
        VBOX_IID_INITIALIZE(&parentiid);
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
        rc = gVBoxAPI.UIVirtualBox.OpenMedium(data->vboxObj,
                                              locationUtf,
                                              DeviceType_HardDisk,
                                              AccessMode_ReadWrite,
                                              &readOnlyMedium);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to open HardDisk, rc=%08x"),
                           (unsigned)rc);
            VBOX_UTF16_FREE(locationUtf);
            goto cleanup;
        }
        VBOX_UTF16_FREE(locationUtf);

        rc = gVBoxAPI.UIMedium.GetId(readOnlyMedium, &iid);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to get hard disk id"));
            goto cleanup;
        }
        gVBoxAPI.UIID.vboxIIDToUtf8(data, &iid, &uuid);
        vboxIIDUnalloc(&iid);

        rc = gVBoxAPI.UIMedium.GetFormat(readOnlyMedium, &formatUtf);
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
        rc = gVBoxAPI.UIMedium.GetParent(readOnlyMedium, &parentReadOnlyMedium);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to get parent hard disk"));
            VIR_FREE(uuid);
            goto cleanup;
        }

        rc = gVBoxAPI.UIMedium.GetId(parentReadOnlyMedium, &parentiid);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to get hard disk id, rc=%08x"),
                           (unsigned)rc);
            VIR_FREE(uuid);
            goto cleanup;
        }
        gVBoxAPI.UIID.vboxIIDToUtf8(data, &parentiid, &parentUuid);
        vboxIIDUnalloc(&parentiid);

        rc = gVBoxAPI.UIMedium.Close(readOnlyMedium);
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
    rc = gVBoxAPI.UIMachine.Unregister(machine,
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
            rc = gVBoxAPI.UIMedium.GetLocation(medium, &locationUtf16);
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
                resultCodeUnion resultCode;
                rc = gVBoxAPI.UIMedium.DeleteStorage(medium, &progress);
                if (NS_FAILED(rc)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Unable to delete medium, rc=%08x"),
                                   (unsigned)rc);
                    VIR_FREE(locationUtf8);
                    goto cleanup;
                }
                gVBoxAPI.UIProgress.WaitForCompletion(progress, -1);
                gVBoxAPI.UIProgress.GetResultCode(progress, &resultCode);
                if (RC_FAILED(resultCode)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Error while closing medium, rc=%08x"),
                                   resultCode.uResultCode);
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
                ignore_value(gVBoxAPI.UIMedium.Close(medium));
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
        virStringListFree(searchResultTab);
        searchResultTab = NULL;
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

            rc = gVBoxAPI.UIVirtualBox.OpenMedium(data->vboxObj,
                                                  locationUtf16,
                                                  DeviceType_HardDisk,
                                                  AccessMode_ReadWrite,
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
            char *uuid = NULL;
            IMedium *parentDisk = NULL;
            char *parentUuid = NULL;
            vboxIID iid, parentiid;

            VBOX_IID_INITIALIZE(&iid);
            VBOX_IID_INITIALIZE(&parentiid);
            VBOX_UTF8_TO_UTF16(def->disks[it].src->path, &locationUtf16);
            rc = gVBoxAPI.UIVirtualBox.OpenMedium(data->vboxObj,
                                                 locationUtf16,
                                                 DeviceType_HardDisk,
                                                 AccessMode_ReadWrite,
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

            rc = gVBoxAPI.UIMedium.GetFormat(medium, &formatUtf16);
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

            rc = gVBoxAPI.UIMedium.GetId(medium, &iid);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unable to get disk uuid"));
                VIR_FREE(disk);
                goto cleanup;
            }
            gVBoxAPI.UIID.vboxIIDToUtf8(data, &iid, &uuid);
            disk->uuid = uuid;
            vboxIIDUnalloc(&iid);

            rc = gVBoxAPI.UIMedium.GetParent(medium, &parentDisk);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unable to get disk parent"));
                VIR_FREE(disk);
                goto cleanup;
            }

            gVBoxAPI.UIMedium.GetId(parentDisk, &parentiid);
            gVBoxAPI.UIID.vboxIIDToUtf8(data, &parentiid, &parentUuid);
            vboxIIDUnalloc(&parentiid);
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
                VIR_FREE(snapshotMachineDesc->storageController);
                if (!tmp)
                    goto cleanup;
                if (VIR_STRDUP(snapshotMachineDesc->storageController, tmp) < 0)
                    goto cleanup;

                VIR_FREE(tmp);
            }
            /*Close disk*/
            rc = gVBoxAPI.UIMedium.Close(medium);
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
            char *parentUuid = NULL;
            IMedium *newMedium = NULL;
            PRUnichar *formatUtf16 = NULL;
            PRUnichar *newLocation = NULL;
            char *newLocationUtf8 = NULL;
            resultCodeUnion resultCode;
            virVBoxSnapshotConfHardDiskPtr disk = NULL;
            char *uuid = NULL;
            char *format = NULL;
            char *tmp = NULL;
            vboxIID iid, parentiid;

            VBOX_IID_INITIALIZE(&iid);
            VBOX_IID_INITIALIZE(&parentiid);
            VBOX_UTF8_TO_UTF16(def->dom->disks[it]->src->path, &locationUtf16);
            rc = gVBoxAPI.UIVirtualBox.OpenMedium(data->vboxObj,
                                                  locationUtf16,
                                                  DeviceType_HardDisk,
                                                  AccessMode_ReadWrite,
                                                  &medium);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to open HardDisk, rc=%08x"),
                               (unsigned)rc);
                VBOX_UTF16_FREE(locationUtf16);
                goto cleanup;
            }
            VBOX_UTF16_FREE(locationUtf16);

            rc = gVBoxAPI.UIMedium.GetId(medium, &parentiid);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to get hardDisk Id, rc=%08x"),
                               (unsigned)rc);
                goto cleanup;
            }
            gVBoxAPI.UIID.vboxIIDToUtf8(data, &parentiid, &parentUuid);
            vboxIIDUnalloc(&parentiid);
            VBOX_UTF8_TO_UTF16("VDI", &formatUtf16);

            if (virAsprintf(&newLocationUtf8, "%sfakedisk-%d.vdi", machineLocationPath, it) < 0)
                goto cleanup;
            VBOX_UTF8_TO_UTF16(newLocationUtf8, &newLocation);
            rc = gVBoxAPI.UIVirtualBox.CreateHardDisk(data->vboxObj,
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
            PRUint32 tab[1];
            tab[0] = MediumVariant_Diff;
            gVBoxAPI.UIMedium.CreateDiffStorage(medium, newMedium, 1, tab, &progress);

            gVBoxAPI.UIProgress.WaitForCompletion(progress, -1);
            gVBoxAPI.UIProgress.GetResultCode(progress, &resultCode);
            if (RC_FAILED(resultCode)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Error while creating diff storage, rc=%08x"),
                               resultCode.uResultCode);
                goto cleanup;
            }
            VBOX_RELEASE(progress);
            /*
             * The differential disk is created, we add it to the media registry and the
             * machine storage controllers.
             */

            if (VIR_ALLOC(disk) < 0)
                goto cleanup;

            rc = gVBoxAPI.UIMedium.GetId(newMedium, &iid);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to get medium uuid, rc=%08x"),
                               (unsigned)rc);
                goto cleanup;
            }
            gVBoxAPI.UIID.vboxIIDToUtf8(data, &iid, &uuid);
            disk->uuid = uuid;
            vboxIIDUnalloc(&iid);

            if (VIR_STRDUP(disk->location, newLocationUtf8) < 0)
                goto cleanup;

            rc = gVBoxAPI.UIMedium.GetFormat(newMedium, &formatUtf16);
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
            VIR_FREE(snapshotMachineDesc->storageController);
            if (!tmp)
                goto cleanup;
            if (VIR_STRDUP(snapshotMachineDesc->storageController, tmp) < 0)
                goto cleanup;

            VIR_FREE(tmp);
            /*Closing the "fake" disk*/
            rc = gVBoxAPI.UIMedium.Close(newMedium);
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
        char *snapshotContent = virDomainSnapshotDefFormat(NULL, def, data->caps, VIR_DOMAIN_DEF_FORMAT_SECURE, 0);
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
            rc = gVBoxAPI.UIVirtualBox.OpenMedium(data->vboxObj,
                                                  locationUtf16,
                                                  DeviceType_HardDisk,
                                                  AccessMode_ReadWrite,
                                                  &medium);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to open HardDisk, rc=%08x"),
                               (unsigned)rc);
                goto cleanup;
            }
            rc = gVBoxAPI.UIMedium.Close(medium);
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
    rc = gVBoxAPI.UIVirtualBox.OpenMachine(data->vboxObj,
                                           settingsFilePath,
                                           &machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to open Machine, rc=%08x"),
                       (unsigned)rc);
        goto cleanup;
    }

    rc = gVBoxAPI.UIVirtualBox.RegisterMachine(data->vboxObj, machine);
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
    virStringListFree(realReadOnlyDisksPath);
    virStringListFree(realReadWriteDisksPath);
    virStringListFree(searchResultTab);
    VIR_FREE(newSnapshotPtr);
    VIR_FREE(machineLocationPath);
    VIR_FREE(nameTmpUse);
    return ret;
}

static virDomainSnapshotPtr
vboxDomainSnapshotCreateXML(virDomainPtr dom,
                            const char *xmlDesc,
                            unsigned int flags)
{
    vboxDriverPtr data = dom->conn->privateData;
    virDomainSnapshotDefPtr def = NULL;
    vboxIID domiid;
    IMachine *machine = NULL;
    IConsole *console = NULL;
    IProgress *progress = NULL;
    ISnapshot *snapshot = NULL;
    PRUnichar *name = NULL;
    PRUnichar *description = NULL;
    PRUint32 state;
    nsresult rc;
    resultCodeUnion result;
    virDomainSnapshotPtr ret = NULL;

    if (!data->vboxObj)
        return ret;

    VBOX_IID_INITIALIZE(&domiid);
    /* VBox has no snapshot metadata, so this flag is trivial.  */
    virCheckFlags(VIR_DOMAIN_SNAPSHOT_CREATE_NO_METADATA |
                  VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE |
                  VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT, NULL);

    if (!(def = virDomainSnapshotDefParseString(xmlDesc, data->caps,
                                                data->xmlopt,
                                                VIR_DOMAIN_SNAPSHOT_PARSE_DISKS |
                                                VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE)))
        goto cleanup;


    if (openSessionForMachine(data, dom->uuid, &domiid, &machine) < 0)
        goto cleanup;

    if (gVBoxAPI.vboxSnapshotRedefine) {
        PRBool isCurrent = flags & VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT;
        if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE) {
            if (vboxSnapshotRedefine(dom, def, isCurrent) < 0)
                goto cleanup;
            ret = virGetDomainSnapshot(dom, def->name);
            goto cleanup;
        }
    }

    rc = gVBoxAPI.UIMachine.GetState(machine, &state);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not get domain state"));
        goto cleanup;
    }

    if (gVBoxAPI.machineStateChecker.Online(state)) {
        rc = gVBoxAPI.UISession.OpenExisting(data, &domiid, machine);
    } else {
        rc = gVBoxAPI.UISession.Open(data, &domiid, machine);
    }

    if (NS_SUCCEEDED(rc))
        rc = gVBoxAPI.UISession.GetConsole(data->vboxSession, &console);
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

    rc = gVBoxAPI.UIConsole.TakeSnapshot(console, name, description, &progress);
    if (NS_FAILED(rc) || !progress) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not take snapshot of domain %s"), dom->name);
        goto cleanup;
    }

    gVBoxAPI.UIProgress.WaitForCompletion(progress, -1);
    gVBoxAPI.UIProgress.GetResultCode(progress, &result);
    if (RC_FAILED(result)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not take snapshot of domain %s"), dom->name);
        goto cleanup;
    }

    rc = gVBoxAPI.UIMachine.GetCurrentSnapshot(machine, &snapshot);
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
    gVBoxAPI.UISession.Close(data->vboxSession);
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&domiid);
    virDomainSnapshotDefFree(def);
    return ret;
}

static int
vboxDomainSnapshotGetAll(virDomainPtr dom,
                         IMachine *machine,
                         ISnapshot ***snapshots)
{
    vboxIID empty;
    ISnapshot **list = NULL;
    PRUint32 count;
    nsresult rc;
    unsigned int next;
    unsigned int top;

    VBOX_IID_INITIALIZE(&empty);
    rc = gVBoxAPI.UIMachine.GetSnapshotCount(machine, &count);
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

    rc = gVBoxAPI.UIMachine.FindSnapshot(machine, &empty, list);
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

        rc = gVBoxAPI.UArray.vboxArrayGet(&children, list[next],
                                          gVBoxAPI.UArray.handleSnapshotGetChildren(list[next]));
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
                gVBoxAPI.UArray.vboxArrayRelease(&children);
                goto error;
            }
            VBOX_ADDREF(child);
            list[top++] = child;
        }
        gVBoxAPI.UArray.vboxArrayRelease(&children);
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
vboxDomainSnapshotGet(vboxDriverPtr data,
                      virDomainPtr dom,
                      IMachine *machine,
                      const char *name)
{
    ISnapshot **snapshots = NULL;
    ISnapshot *snapshot = NULL;
    nsresult rc;
    ssize_t i, count = 0;

    if ((count = vboxDomainSnapshotGetAll(dom, machine, &snapshots)) < 0)
        return NULL;

    for (i = 0; i < count; i++) {
        PRUnichar *nameUtf16;
        char *nameUtf8;

        rc = gVBoxAPI.UISnapshot.GetName(snapshots[i], &nameUtf16);
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
    for (i = 0; i < count; i++) {
        if (snapshots[i] != snapshot)
            VBOX_RELEASE(snapshots[i]);
    }
    VIR_FREE(snapshots);
    return snapshot;
}

static int vboxSnapshotGetReadWriteDisks(virDomainSnapshotDefPtr def,
                                         virDomainSnapshotPtr snapshot)
{
    virDomainPtr dom = snapshot->domain;
    vboxDriverPtr data = dom->conn->privateData;
    vboxIID domiid;
    IMachine *machine = NULL;
    ISnapshot *snap = NULL;
    IMachine *snapMachine = NULL;
    vboxArray mediumAttachments = VBOX_ARRAY_INITIALIZER;
    PRUint32 maxPortPerInst[StorageBus_Floppy + 1] = {};
    PRUint32 maxSlotPerPort[StorageBus_Floppy + 1] = {};
    int diskCount = 0;
    nsresult rc;
    vboxIID snapIid;
    char *snapshotUuidStr = NULL;
    size_t i = 0;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    if (!gVBoxAPI.vboxSnapshotRedefine)
        VIR_WARN("This function may not work in current version");

    VBOX_IID_INITIALIZE(&snapIid);
    if (openSessionForMachine(data, dom->uuid, &domiid, &machine) < 0)
        goto cleanup;

    if (!(snap = vboxDomainSnapshotGet(data, dom, machine, snapshot->name)))
        goto cleanup;

    rc = gVBoxAPI.UISnapshot.GetId(snap, &snapIid);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not get snapshot id"));
        goto cleanup;
    }

    gVBoxAPI.UIID.vboxIIDToUtf8(data, &snapIid, &snapshotUuidStr);
    vboxIIDUnalloc(&snapIid);
    rc = gVBoxAPI.UISnapshot.GetMachine(snap, &snapMachine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not get machine"));
        goto cleanup;
    }
    def->ndisks = 0;
    rc = gVBoxAPI.UArray.vboxArrayGet(&mediumAttachments, snapMachine,
                                      gVBoxAPI.UArray.handleMachineGetMediumAttachments(snapMachine));
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

            rc = gVBoxAPI.UIMediumAttachment.GetMedium(imediumattach, &medium);
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
        PRUint32 deviceType = DeviceType_Null;
        PRUint32 storageBus = StorageBus_Null;
        IMedium *disk = NULL;
        PRUnichar *childLocUtf16 = NULL;
        char *childLocUtf8 = NULL;
        PRUint32 deviceInst = 0;
        PRInt32 devicePort = 0;
        PRInt32 deviceSlot = 0;
        vboxArray children = VBOX_ARRAY_INITIALIZER;
        vboxArray snapshotIids = VBOX_ARRAY_INITIALIZER;
        IMediumAttachment *imediumattach = mediumAttachments.items[i];
        void *handle;
        size_t j = 0;
        size_t k = 0;
        if (!imediumattach)
            continue;
        rc = gVBoxAPI.UIMediumAttachment.GetMedium(imediumattach, &disk);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot get medium"));
            goto cleanup;
        }
        if (!disk)
            continue;
        rc = gVBoxAPI.UIMediumAttachment.GetController(imediumattach, &storageControllerName);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot get controller"));
            goto cleanup;
        }
        if (!storageControllerName) {
            VBOX_RELEASE(disk);
            continue;
        }
        handle = gVBoxAPI.UArray.handleMediumGetChildren(disk);
        rc = gVBoxAPI.UArray.vboxArrayGet(&children, disk, handle);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot get children disk"));
            goto cleanup;
        }
        handle = gVBoxAPI.UArray.handleMediumGetSnapshotIds(disk);
        rc = gVBoxAPI.UArray.vboxArrayGetWithIIDArg(&snapshotIids, disk,
                                                    handle, &domiid);
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
                    rc = gVBoxAPI.UIMachine.GetStorageControllerByName(machine,
                                                                       storageControllerName,
                                                                       &storageController);
                    VBOX_UTF16_FREE(storageControllerName);
                    if (!storageController) {
                        VBOX_RELEASE(child);
                        break;
                    }
                    rc = gVBoxAPI.UIMedium.GetLocation(child, &childLocUtf16);
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

                    rc = gVBoxAPI.UIStorageController.GetBus(storageController, &storageBus);
                    if (NS_FAILED(rc)) {
                        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                       _("cannot get storage controller bus"));
                        goto cleanup;
                    }
                    rc = gVBoxAPI.UIMediumAttachment.GetType(imediumattach, &deviceType);
                    if (NS_FAILED(rc)) {
                        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                       _("cannot get medium attachment type"));
                        goto cleanup;
                    }
                    rc = gVBoxAPI.UIMediumAttachment.GetPort(imediumattach, &devicePort);
                    if (NS_FAILED(rc)) {
                        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                       _("cannot get medium attachment type"));
                        goto cleanup;
                    }
                    rc = gVBoxAPI.UIMediumAttachment.GetDevice(imediumattach, &deviceSlot);
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
    gVBoxAPI.UArray.vboxArrayRelease(&mediumAttachments);

    ret = 0;
 cleanup:
    if (ret < 0) {
        for (i = 0; i < def->ndisks; i++)
            VIR_FREE(def->disks[i].src);
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
    vboxDriverPtr data = dom->conn->privateData;
    vboxIID domiid;
    ISnapshot *snap = NULL;
    IMachine *machine = NULL;
    IMachine *snapMachine = NULL;
    IStorageController *storageController = NULL;
    IMedium *disk = NULL;
    nsresult rc;
    vboxArray mediumAttachments = VBOX_ARRAY_INITIALIZER;
    size_t i = 0;
    PRUint32 maxPortPerInst[StorageBus_Floppy + 1] = {};
    PRUint32 maxSlotPerPort[StorageBus_Floppy + 1] = {};
    int diskCount = 0;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    if (!gVBoxAPI.vboxSnapshotRedefine)
        VIR_WARN("This function may not work in current version");

    if (openSessionForMachine(data, dom->uuid, &domiid, &machine) < 0)
        goto cleanup;

    if (!(snap = vboxDomainSnapshotGet(data, dom, machine, snapshot->name)))
        goto cleanup;

    rc = gVBoxAPI.UISnapshot.GetMachine(snap, &snapMachine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot get machine"));
        goto cleanup;
    }
    /*
     * Get READ ONLY disks
     * In the snapshot metadata, these are the disks written inside the <domain> node
    */
    rc = gVBoxAPI.UArray.vboxArrayGet(&mediumAttachments, snapMachine,
                                      gVBoxAPI.UArray.handleMachineGetMediumAttachments(snapMachine));
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

            rc = gVBoxAPI.UIMediumAttachment.GetMedium(imediumattach, &medium);
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
            virDomainDiskDefPtr diskDef = virDomainDiskDefNew(NULL);
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
        PRUint32 deviceType = DeviceType_Null;
        PRUint32 storageBus = StorageBus_Null;
        PRBool readOnly = PR_FALSE;
        PRUnichar *mediumLocUtf16 = NULL;
        char *mediumLocUtf8 = NULL;
        PRUint32 deviceInst = 0;
        PRInt32 devicePort = 0;
        PRInt32 deviceSlot = 0;
        IMediumAttachment *imediumattach = mediumAttachments.items[i];
        if (!imediumattach)
            continue;
        rc = gVBoxAPI.UIMediumAttachment.GetMedium(imediumattach, &disk);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot get medium"));
            goto cleanup;
        }
        if (!disk)
            continue;
        rc = gVBoxAPI.UIMediumAttachment.GetController(imediumattach, &storageControllerName);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot get storage controller name"));
            goto cleanup;
        }
        if (!storageControllerName)
            continue;
        rc = gVBoxAPI.UIMachine.GetStorageControllerByName(machine,
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
        rc = gVBoxAPI.UIMedium.GetLocation(disk, &mediumLocUtf16);
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

        rc = gVBoxAPI.UIStorageController.GetBus(storageController, &storageBus);
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

        rc = gVBoxAPI.UIMediumAttachment.GetType(imediumattach, &deviceType);
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

        rc = gVBoxAPI.UIMediumAttachment.GetPort(imediumattach, &devicePort);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot get medium attachment port"));
            goto cleanup;
        }
        rc = gVBoxAPI.UIMediumAttachment.GetDevice(imediumattach, &deviceSlot);
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot get device"));
            goto cleanup;
        }
        rc = gVBoxAPI.UIMedium.GetReadOnly(disk, &readOnly);
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
    gVBoxAPI.UArray.vboxArrayRelease(&mediumAttachments);
    VBOX_RELEASE(snap);
    return ret;
}

static char *vboxDomainSnapshotGetXMLDesc(virDomainSnapshotPtr snapshot,
                                          unsigned int flags)
{
    virDomainPtr dom = snapshot->domain;
    vboxDriverPtr data = dom->conn->privateData;
    vboxIID domiid;
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
    char *ret = NULL;

    if (!data->vboxObj)
        return ret;

    virCheckFlags(0, NULL);

    if (openSessionForMachine(data, dom->uuid, &domiid, &machine) < 0)
        goto cleanup;

    if (!(snap = vboxDomainSnapshotGet(data, dom, machine, snapshot->name)))
        goto cleanup;

    if (VIR_ALLOC(def) < 0 || !(def->dom = virDomainDefNew()))
        goto cleanup;
    if (VIR_STRDUP(def->name, snapshot->name) < 0)
        goto cleanup;

    if (gVBoxAPI.vboxSnapshotRedefine) {
        /* Register def->dom properties for them to be saved inside the snapshot XMl
         * Otherwise, there is a problem while parsing the xml
         */
        PRUint32 memorySize = 0;
        PRUint32 CPUCount = 0;

        def->dom->virtType = VIR_DOMAIN_VIRT_VBOX;
        def->dom->id = dom->id;
        memcpy(def->dom->uuid, dom->uuid, VIR_UUID_BUFLEN);
        if (VIR_STRDUP(def->dom->name, dom->name) < 0)
            goto cleanup;
        gVBoxAPI.UIMachine.GetMemorySize(machine, &memorySize);
        def->dom->mem.cur_balloon = memorySize * 1024;
        /* Currently setting memory and maxMemory as same, cause
         * the notation here seems to be inconsistent while
         * reading and while dumping xml
         */
        virDomainDefSetMemoryTotal(def->dom, memorySize * 1024);
        def->dom->os.type = VIR_DOMAIN_OSTYPE_HVM;
        def->dom->os.arch = virArchFromHost();
        gVBoxAPI.UIMachine.GetCPUCount(machine, &CPUCount);
        if (virDomainDefSetVcpusMax(def->dom, CPUCount, data->xmlopt) < 0)
            goto cleanup;

        if (virDomainDefSetVcpus(def->dom, CPUCount) < 0)
            goto cleanup;

        if (vboxSnapshotGetReadWriteDisks(def, snapshot) < 0)
            VIR_DEBUG("Could not get read write disks for snapshot");

        if (vboxSnapshotGetReadOnlyDisks(snapshot, def) < 0)
            VIR_DEBUG("Could not get Readonly disks for snapshot");
    }

    rc = gVBoxAPI.UISnapshot.GetDescription(snap, &str16);
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

    rc = gVBoxAPI.UISnapshot.GetTimeStamp(snap, &timestamp);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not get creation time of snapshot %s"),
                       snapshot->name);
        goto cleanup;
    }
    /* timestamp is in milliseconds while creationTime in seconds */
    def->creationTime = timestamp / 1000;

    rc = gVBoxAPI.UISnapshot.GetParent(snap, &parent);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not get parent of snapshot %s"),
                       snapshot->name);
        goto cleanup;
    }
    if (parent) {
        rc = gVBoxAPI.UISnapshot.GetName(parent, &str16);
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

    rc = gVBoxAPI.UISnapshot.GetOnline(snap, &online);
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
    ret = virDomainSnapshotDefFormat(uuidstr, def, data->caps,
                                      virDomainDefFormatConvertXMLFlags(flags),
                                      0);

 cleanup:
    virDomainSnapshotDefFree(def);
    VBOX_RELEASE(parent);
    VBOX_RELEASE(snap);
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&domiid);
    return ret;
}

static int vboxDomainSnapshotNum(virDomainPtr dom, unsigned int flags)
{
    vboxDriverPtr data = dom->conn->privateData;
    vboxIID iid;
    IMachine *machine = NULL;
    nsresult rc;
    PRUint32 snapshotCount;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_LIST_ROOTS |
                  VIR_DOMAIN_SNAPSHOT_LIST_METADATA, -1);

    if (openSessionForMachine(data, dom->uuid, &iid, &machine) < 0)
        goto cleanup;

    /* VBox snapshots do not require libvirt to maintain any metadata.  */
    if (flags & VIR_DOMAIN_SNAPSHOT_LIST_METADATA) {
        ret = 0;
        goto cleanup;
    }

    rc = gVBoxAPI.UIMachine.GetSnapshotCount(machine, &snapshotCount);
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

static int vboxDomainSnapshotListNames(virDomainPtr dom, char **names,
                                       int nameslen, unsigned int flags)
{
    vboxDriverPtr data = dom->conn->privateData;
    vboxIID iid;
    IMachine *machine = NULL;
    nsresult rc;
    ISnapshot **snapshots = NULL;
    ssize_t i, count = 0;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_LIST_ROOTS |
                  VIR_DOMAIN_SNAPSHOT_LIST_METADATA, -1);

    if (openSessionForMachine(data, dom->uuid, &iid, &machine) < 0)
        goto cleanup;

    if (flags & VIR_DOMAIN_SNAPSHOT_LIST_METADATA) {
        ret = 0;
        goto cleanup;
    }

    if (flags & VIR_DOMAIN_SNAPSHOT_LIST_ROOTS) {
        vboxIID empty;

        VBOX_IID_INITIALIZE(&empty);
        if (VIR_ALLOC_N(snapshots, 1) < 0)
            goto cleanup;
        rc = gVBoxAPI.UIMachine.FindSnapshot(machine, &empty, snapshots);
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

        rc = gVBoxAPI.UISnapshot.GetName(snapshots[i], &nameUtf16);
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
    for (i = 0; i < count; i++)
        VBOX_RELEASE(snapshots[i]);
    VIR_FREE(snapshots);
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    return ret;
}

static virDomainSnapshotPtr
vboxDomainSnapshotLookupByName(virDomainPtr dom, const char *name,
                               unsigned int flags)
{
    vboxDriverPtr data = dom->conn->privateData;
    vboxIID iid;
    IMachine *machine = NULL;
    ISnapshot *snapshot = NULL;
    virDomainSnapshotPtr ret = NULL;

    if (!data->vboxObj)
        return ret;

    virCheckFlags(0, NULL);

    if (openSessionForMachine(data, dom->uuid, &iid, &machine) < 0)
        goto cleanup;

    if (!(snapshot = vboxDomainSnapshotGet(data, dom, machine, name)))
        goto cleanup;

    ret = virGetDomainSnapshot(dom, name);

 cleanup:
    VBOX_RELEASE(snapshot);
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    return ret;
}

static int vboxDomainHasCurrentSnapshot(virDomainPtr dom,
                                        unsigned int flags)
{
    vboxDriverPtr data = dom->conn->privateData;
    vboxIID iid;
    IMachine *machine = NULL;
    ISnapshot *snapshot = NULL;
    nsresult rc;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    virCheckFlags(0, -1);

    if (openSessionForMachine(data, dom->uuid, &iid, &machine) < 0)
        goto cleanup;

    rc = gVBoxAPI.UIMachine.GetCurrentSnapshot(machine, &snapshot);
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
    vboxDriverPtr data = dom->conn->privateData;
    vboxIID iid;
    IMachine *machine = NULL;
    ISnapshot *snap = NULL;
    ISnapshot *parent = NULL;
    PRUnichar *nameUtf16 = NULL;
    char *name = NULL;
    nsresult rc;
    virDomainSnapshotPtr ret = NULL;

    if (!data->vboxObj)
        return ret;

    virCheckFlags(0, NULL);

    if (openSessionForMachine(data, dom->uuid, &iid, &machine) < 0)
        goto cleanup;

    if (!(snap = vboxDomainSnapshotGet(data, dom, machine, snapshot->name)))
        goto cleanup;

    rc = gVBoxAPI.UISnapshot.GetParent(snap, &parent);
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

    rc = gVBoxAPI.UISnapshot.GetName(parent, &nameUtf16);
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
vboxDomainSnapshotCurrent(virDomainPtr dom, unsigned int flags)
{
    vboxDriverPtr data = dom->conn->privateData;
    vboxIID iid;
    IMachine *machine = NULL;
    ISnapshot *snapshot = NULL;
    PRUnichar *nameUtf16 = NULL;
    char *name = NULL;
    nsresult rc;
    virDomainSnapshotPtr ret = NULL;

    if (!data->vboxObj)
        return ret;

    virCheckFlags(0, NULL);

    if (openSessionForMachine(data, dom->uuid, &iid, &machine) < 0)
        goto cleanup;

    rc = gVBoxAPI.UIMachine.GetCurrentSnapshot(machine, &snapshot);
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

    rc = gVBoxAPI.UISnapshot.GetName(snapshot, &nameUtf16);
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

static int vboxDomainSnapshotIsCurrent(virDomainSnapshotPtr snapshot,
                                       unsigned int flags)
{
    virDomainPtr dom = snapshot->domain;
    vboxDriverPtr data = dom->conn->privateData;
    vboxIID iid;
    IMachine *machine = NULL;
    ISnapshot *snap = NULL;
    ISnapshot *current = NULL;
    PRUnichar *nameUtf16 = NULL;
    char *name = NULL;
    nsresult rc;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    virCheckFlags(0, -1);

    if (openSessionForMachine(data, dom->uuid, &iid, &machine) < 0)
        goto cleanup;

    if (!(snap = vboxDomainSnapshotGet(data, dom, machine, snapshot->name)))
        goto cleanup;

    rc = gVBoxAPI.UIMachine.GetCurrentSnapshot(machine, &current);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not get current snapshot"));
        goto cleanup;
    }
    if (!current) {
        ret = 0;
        goto cleanup;
    }

    rc = gVBoxAPI.UISnapshot.GetName(current, &nameUtf16);
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

static int vboxDomainSnapshotHasMetadata(virDomainSnapshotPtr snapshot,
                                         unsigned int flags)
{
    virDomainPtr dom = snapshot->domain;
    vboxDriverPtr data = dom->conn->privateData;
    vboxIID iid;
    IMachine *machine = NULL;
    ISnapshot *snap = NULL;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    virCheckFlags(0, -1);

    if (openSessionForMachine(data, dom->uuid, &iid, &machine) < 0)
        goto cleanup;

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

static int vboxDomainRevertToSnapshot(virDomainSnapshotPtr snapshot,
                                      unsigned int flags)
{
    virDomainPtr dom = snapshot->domain;
    vboxDriverPtr data = dom->conn->privateData;
    vboxIID domiid;
    IMachine *machine = NULL;
    ISnapshot *newSnapshot = NULL;
    ISnapshot *prevSnapshot = NULL;
    PRBool online = PR_FALSE;
    PRUint32 state;
    nsresult rc;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    virCheckFlags(0, -1);

    if (openSessionForMachine(data, dom->uuid, &domiid, &machine) < 0)
        goto cleanup;

    newSnapshot = vboxDomainSnapshotGet(data, dom, machine, snapshot->name);
    if (!newSnapshot)
        goto cleanup;

    rc = gVBoxAPI.UISnapshot.GetOnline(newSnapshot, &online);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not get online state of snapshot %s"),
                       snapshot->name);
        goto cleanup;
    }

    rc = gVBoxAPI.UIMachine.GetCurrentSnapshot(machine, &prevSnapshot);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not get current snapshot of domain %s"),
                       dom->name);
        goto cleanup;
    }

    rc = gVBoxAPI.UIMachine.GetState(machine, &state);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not get domain state"));
        goto cleanup;
    }

    if (gVBoxAPI.machineStateChecker.Online(state)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot revert snapshot of running domain"));
        goto cleanup;
    }

    if (gVBoxAPI.snapshotRestore(dom, machine, newSnapshot))
        goto cleanup;

    if (online) {
        ret = vboxDomainCreate(dom);
        if (!ret)
            gVBoxAPI.snapshotRestore(dom, machine, prevSnapshot);
    } else {
        ret = 0;
    }

 cleanup:
    VBOX_RELEASE(prevSnapshot);
    VBOX_RELEASE(newSnapshot);
    vboxIIDUnalloc(&domiid);
    return ret;
}

static int
vboxDomainSnapshotDeleteSingle(vboxDriverPtr data,
                               IConsole *console,
                               ISnapshot *snapshot)
{
    IProgress *progress = NULL;
    vboxIID iid;
    int ret = -1;
    nsresult rc;
    resultCodeUnion result;

    VBOX_IID_INITIALIZE(&iid);
    rc = gVBoxAPI.UISnapshot.GetId(snapshot, &iid);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not get snapshot UUID"));
        goto cleanup;
    }

    rc = gVBoxAPI.UIConsole.DeleteSnapshot(console, &iid, &progress);
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

    gVBoxAPI.UIProgress.WaitForCompletion(progress, -1);
    gVBoxAPI.UIProgress.GetResultCode(progress, &result);
    if (RC_FAILED(result)) {
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
vboxDomainSnapshotDeleteTree(vboxDriverPtr data,
                             IConsole *console,
                             ISnapshot *snapshot)
{
    vboxArray children = VBOX_ARRAY_INITIALIZER;
    int ret = -1;
    nsresult rc;
    size_t i;

    rc = gVBoxAPI.UArray.vboxArrayGet(&children, snapshot,
                  gVBoxAPI.UArray.handleSnapshotGetChildren(snapshot));
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
    gVBoxAPI.UArray.vboxArrayRelease(&children);
    return ret;
}

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
    vboxDriverPtr data = dom->conn->privateData;
    virDomainSnapshotDefPtr def = NULL;
    char *defXml = NULL;
    vboxIID domiid;
    nsresult rc;
    IMachine *machine = NULL;
    PRUnichar *settingsFilePathUtf16 = NULL;
    char *settingsFilepath = NULL;
    virVBoxSnapshotConfMachinePtr snapshotMachineDesc = NULL;
    int isCurrent = -1;
    char **searchResultTab = NULL;
    ssize_t resultSize = 0;
    int it = 0;
    PRUnichar *machineNameUtf16 = NULL;
    char *machineName = NULL;
    char *nameTmpUse = NULL;
    char *machineLocationPath = NULL;
    PRUint32 aMediaSize = 0;
    IMedium **aMedia = NULL;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    VBOX_IID_INITIALIZE(&domiid);
    if (!gVBoxAPI.vboxSnapshotRedefine)
        VIR_WARN("This function may not work in current version");

    defXml = vboxDomainSnapshotGetXMLDesc(snapshot, 0);
    if (!defXml) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to get XML Desc of snapshot"));
        goto cleanup;
    }
    def = virDomainSnapshotDefParseString(defXml,
                                          data->caps,
                                          data->xmlopt,
                                          VIR_DOMAIN_SNAPSHOT_PARSE_DISKS |
                                          VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE);
    if (!def) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to get a virDomainSnapshotDefPtr"));
        goto cleanup;
    }

    if (openSessionForMachine(data, dom->uuid, &domiid, &machine) < 0)
        goto cleanup;
    rc = gVBoxAPI.UIMachine.GetSettingsFilePath(machine, &settingsFilePathUtf16);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot get settings file path"));
        goto cleanup;
    }
    VBOX_UTF16_TO_UTF8(settingsFilePathUtf16, &settingsFilepath);

    /*Getting the machine name to retrieve the machine location path.*/
    rc = gVBoxAPI.UIMachine.GetName(machine, &machineNameUtf16);
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
                char *parentUuid = NULL;
                IMedium *newMedium = NULL;
                PRUnichar *formatUtf16 = NULL;
                PRUnichar *newLocation = NULL;
                char *newLocationUtf8 = NULL;
                IProgress *progress = NULL;
                virVBoxSnapshotConfHardDiskPtr disk = NULL;
                char *uuid = NULL;
                char *format = NULL;
                char *tmp = NULL;
                vboxIID iid, parentiid;
                resultCodeUnion resultCode;

                VBOX_IID_INITIALIZE(&iid);
                VBOX_IID_INITIALIZE(&parentiid);
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
                rc = gVBoxAPI.UIVirtualBox.OpenMedium(data->vboxObj,
                                                      locationUtf16,
                                                      DeviceType_HardDisk,
                                                      AccessMode_ReadWrite,
                                                      &medium);
                if (NS_FAILED(rc)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Unable to open HardDisk, rc=%08x"),
                                   (unsigned)rc);
                    goto cleanup;
                }

                rc = gVBoxAPI.UIMedium.GetId(medium, &parentiid);
                if (NS_FAILED(rc)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Unable to get hardDisk Id, rc=%08x"),
                                   (unsigned)rc);
                    goto cleanup;
                }
                gVBoxAPI.UIID.vboxIIDToUtf8(data, &parentiid, &parentUuid);
                vboxIIDUnalloc(&parentiid);
                VBOX_UTF16_FREE(locationUtf16);
                VBOX_UTF8_TO_UTF16("VDI", &formatUtf16);

                if (virAsprintf(&newLocationUtf8, "%sfakedisk-%s-%d.vdi",
                                machineLocationPath, def->parent, it) < 0)
                    goto cleanup;
                VBOX_UTF8_TO_UTF16(newLocationUtf8, &newLocation);
                rc = gVBoxAPI.UIVirtualBox.CreateHardDisk(data->vboxObj,
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

                PRUint32 tab[1];
                tab[0] = MediumVariant_Diff;
                gVBoxAPI.UIMedium.CreateDiffStorage(medium, newMedium, 1, tab, &progress);

                gVBoxAPI.UIProgress.WaitForCompletion(progress, -1);
                gVBoxAPI.UIProgress.GetResultCode(progress, &resultCode);
                if (RC_FAILED(resultCode)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Error while creating diff storage, rc=%08x"),
                                   resultCode.uResultCode);
                    goto cleanup;
                }
                VBOX_RELEASE(progress);
                /*
                 * The differential disk is created, we add it to the media registry and
                 * the machine storage controller.
                 */

                if (VIR_ALLOC(disk) < 0)
                    goto cleanup;

                rc = gVBoxAPI.UIMedium.GetId(newMedium, &iid);
                if (NS_FAILED(rc)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Unable to get medium uuid, rc=%08x"),
                                   (unsigned)rc);
                    VIR_FREE(disk);
                    goto cleanup;
                }
                gVBoxAPI.UIID.vboxIIDToUtf8(data, &iid, &uuid);
                disk->uuid = uuid;
                vboxIIDUnalloc(&iid);

                if (VIR_STRDUP(disk->location, newLocationUtf8) < 0) {
                    VIR_FREE(disk);
                    goto cleanup;
                }

                rc = gVBoxAPI.UIMedium.GetFormat(newMedium, &formatUtf16);
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
                VIR_FREE(snapshotMachineDesc->storageController);
                if (!tmp)
                    goto cleanup;
                if (VIR_STRDUP(snapshotMachineDesc->storageController, tmp) < 0)
                    goto cleanup;

                VIR_FREE(tmp);
                /*Closing the "fake" disk*/
                rc = gVBoxAPI.UIMedium.Close(newMedium);
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
    rc = gVBoxAPI.UIMachine.Unregister(machine,
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
        PRUnichar *locationUtf16 = NULL;
        char *locationUtf8 = NULL;

        if (!medium)
            continue;

        rc = gVBoxAPI.UIMedium.GetLocation(medium, &locationUtf16);
        VBOX_UTF16_TO_UTF8(locationUtf16, &locationUtf8);
        if (isCurrent && strstr(locationUtf8, "fake") != NULL) {
            /*we delete the fake disk because we don't need it anymore*/
            IProgress *progress = NULL;
            resultCodeUnion resultCode;
            rc = gVBoxAPI.UIMedium.DeleteStorage(medium, &progress);
            if (NS_FAILED(rc)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to delete medium, rc=%08x"),
                               (unsigned)rc);
                goto cleanup;
            }
            gVBoxAPI.UIProgress.WaitForCompletion(progress, -1);
            gVBoxAPI.UIProgress.GetResultCode(progress, &resultCode);
            if (RC_FAILED(resultCode)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Error while closing medium, rc=%08x"),
                               resultCode.uResultCode);
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
            ignore_value(gVBoxAPI.UIMedium.Close(medium));
        }
        VBOX_UTF16_FREE(locationUtf16);
        VBOX_UTF8_FREE(locationUtf8);
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
    rc = gVBoxAPI.UIVirtualBox.OpenMachine(data->vboxObj,
                                           settingsFilePathUtf16,
                                           &machine);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to open Machine, rc=%08x"),
                       (unsigned)rc);
        goto cleanup;
    }

    rc = gVBoxAPI.UIVirtualBox.RegisterMachine(data->vboxObj, machine);
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
    virStringListFree(searchResultTab);
    VIR_FREE(snapshotMachineDesc);
    VBOX_UTF16_FREE(machineNameUtf16);
    VBOX_UTF8_FREE(machineName);
    VIR_FREE(machineLocationPath);
    VIR_FREE(nameTmpUse);

    return ret;
}

static int vboxDomainSnapshotDelete(virDomainSnapshotPtr snapshot,
                                    unsigned int flags)
{
    virDomainPtr dom = snapshot->domain;
    vboxDriverPtr data = dom->conn->privateData;
    vboxIID domiid;
    IMachine *machine = NULL;
    ISnapshot *snap = NULL;
    IConsole *console = NULL;
    PRUint32 state;
    nsresult rc;
    vboxArray snapChildren = VBOX_ARRAY_INITIALIZER;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN |
                  VIR_DOMAIN_SNAPSHOT_DELETE_METADATA_ONLY, -1);

    if (openSessionForMachine(data, dom->uuid, &domiid, &machine) < 0)
        goto cleanup;

    snap = vboxDomainSnapshotGet(data, dom, machine, snapshot->name);
    if (!snap)
        goto cleanup;

    rc = gVBoxAPI.UIMachine.GetState(machine, &state);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not get domain state"));
        goto cleanup;
    }

    /* In case we just want to delete the metadata, we will edit the vbox file in order
     *to remove the node concerning the snapshot
    */
    if (flags & VIR_DOMAIN_SNAPSHOT_DELETE_METADATA_ONLY) {
        rc = gVBoxAPI.UArray.vboxArrayGet(&snapChildren, snap,
                             gVBoxAPI.UArray.handleSnapshotGetChildren(snap));
        if (NS_FAILED(rc)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("could not get snapshot children"));
            goto cleanup;
        }
        if (snapChildren.count != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot delete metadata of a snapshot with children"));
            goto cleanup;
        } else if (gVBoxAPI.vboxSnapshotRedefine) {
            ret = vboxDomainSnapshotDeleteMetadataOnly(snapshot);
        }
        goto cleanup;
    }

    if (gVBoxAPI.machineStateChecker.Online(state)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot delete snapshots of running domain"));
        goto cleanup;
    }

    rc = gVBoxAPI.UISession.Open(data, &domiid, machine);
    if (NS_SUCCEEDED(rc))
        rc = gVBoxAPI.UISession.GetConsole(data->vboxSession, &console);
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
    gVBoxAPI.UISession.Close(data->vboxSession);
    return ret;
}

static char *
vboxDomainScreenshot(virDomainPtr dom,
                     virStreamPtr st,
                     unsigned int screen,
                     unsigned int flags)
{
    vboxDriverPtr data = dom->conn->privateData;
    IConsole *console = NULL;
    vboxIID iid;
    IMachine *machine = NULL;
    nsresult rc;
    char *tmp;
    char *cacheDir;
    int tmp_fd = -1;
    unsigned int max_screen;
    bool privileged = geteuid() == 0;
    char *ret = NULL;

    if (!data->vboxObj)
        return ret;

    virCheckFlags(0, NULL);

    if (openSessionForMachine(data, dom->uuid, &iid, &machine) < 0)
        return NULL;

    rc = gVBoxAPI.UIMachine.GetMonitorCount(machine, &max_screen);
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

    if ((privileged && virAsprintf(&cacheDir, "%s/cache/libvirt", LOCALSTATEDIR) < 0) ||
        (!privileged && !(cacheDir = virGetUserCacheDirectory()))) {
        VBOX_RELEASE(machine);
        return NULL;
    }

    if (virAsprintf(&tmp, "%s/vbox.screendump.XXXXXX", cacheDir) < 0) {
        VBOX_RELEASE(machine);
        VIR_FREE(cacheDir);
        return NULL;
    }

    if ((tmp_fd = mkostemp(tmp, O_CLOEXEC)) == -1) {
        virReportSystemError(errno, _("mkostemp(\"%s\") failed"), tmp);
        VIR_FREE(tmp);
        VBOX_RELEASE(machine);
        return NULL;
    }


    rc = gVBoxAPI.UISession.OpenExisting(data, &iid, machine);
    if (NS_SUCCEEDED(rc)) {
        rc = gVBoxAPI.UISession.GetConsole(data->vboxSession, &console);
        if (NS_SUCCEEDED(rc) && console) {
            IDisplay *display = NULL;

            gVBoxAPI.UIConsole.GetDisplay(console, &display);

            if (display) {
                PRUint32 width, height, bitsPerPixel;
                PRUint32 screenDataSize;
                PRUint8 *screenData;
                PRInt32 xOrigin, yOrigin;

                rc = gVBoxAPI.UIDisplay.GetScreenResolution(display, screen,
                                                            &width, &height,
                                                            &bitsPerPixel,
                                                            &xOrigin, &yOrigin);

                if (NS_FAILED(rc) || !width || !height) {
                    virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                                   _("unable to get screen resolution"));
                    goto endjob;
                }

                rc = gVBoxAPI.UIDisplay.TakeScreenShotPNGToArray(display, screen,
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
        gVBoxAPI.UISession.Close(data->vboxSession);
    }

    VIR_FORCE_CLOSE(tmp_fd);
    unlink(tmp);
    VIR_FREE(tmp);
    VIR_FREE(cacheDir);
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);
    return ret;
}

#define MATCH(FLAG) (flags & (FLAG))
static int
vboxConnectListAllDomains(virConnectPtr conn,
                          virDomainPtr **domains,
                          unsigned int flags)
{
    vboxDriverPtr data = conn->privateData;
    vboxArray machines = VBOX_ARRAY_INITIALIZER;
    char *machineNameUtf8 = NULL;
    PRUnichar *machineNameUtf16 = NULL;
    unsigned char uuid[VIR_UUID_BUFLEN];
    vboxIID iid;
    PRUint32 state;
    nsresult rc;
    size_t i;
    virDomainPtr dom;
    virDomainPtr *doms = NULL;
    int count = 0;
    bool active;
    PRUint32 snapshotCount;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_FILTERS_ALL, -1);

    /* filter out flag options that will produce 0 results in vbox driver:
     * - managed save: vbox guests don't have managed save images
     * - autostart: vbox doesn't support autostarting guests
     * - persistence: vbox doesn't support transient guests
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

    rc = gVBoxAPI.UArray.vboxArrayGet(&machines, data->vboxObj, ARRAY_GET_MACHINES);
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
        int id = -1;

        if (!machine)
            continue;

        PRBool isAccessible = PR_FALSE;
        gVBoxAPI.UIMachine.GetAccessible(machine, &isAccessible);

        if (!isAccessible)
            continue;

      gVBoxAPI.UIMachine.GetState(machine, &state);

      if (gVBoxAPI.machineStateChecker.Online(state))
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
          rc = gVBoxAPI.UIMachine.GetSnapshotCount(machine, &snapshotCount);
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
             gVBoxAPI.machineStateChecker.Running(state)) ||
            (MATCH(VIR_CONNECT_LIST_DOMAINS_PAUSED) &&
             gVBoxAPI.machineStateChecker.Paused(state)) ||
            (MATCH(VIR_CONNECT_LIST_DOMAINS_SHUTOFF) &&
             gVBoxAPI.machineStateChecker.PoweredOff(state)) ||
            (MATCH(VIR_CONNECT_LIST_DOMAINS_OTHER) &&
             (!gVBoxAPI.machineStateChecker.Running(state) &&
              !gVBoxAPI.machineStateChecker.Paused(state) &&
              !gVBoxAPI.machineStateChecker.PoweredOff(state)))))
          continue;

      /* just count the machines */
      if (!doms) {
          count++;
          continue;
      }

      gVBoxAPI.UIMachine.GetName(machine, &machineNameUtf16);
      VBOX_UTF16_TO_UTF8(machineNameUtf16, &machineNameUtf8);
      gVBoxAPI.UIMachine.GetId(machine, &iid);
      vboxIIDToUUID(&iid, uuid);
      vboxIIDUnalloc(&iid);

      if (active)
          id = i + 1;

      dom = virGetDomain(conn, machineNameUtf8, uuid, id);

      VBOX_UTF8_FREE(machineNameUtf8);
      VBOX_UTF16_FREE(machineNameUtf16);

      if (!dom)
          goto cleanup;

      doms[count++] = dom;
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
        for (i = 0; i < count; i++)
            virObjectUnref(doms[i]);
    }
    VIR_FREE(doms);

    gVBoxAPI.UArray.vboxArrayRelease(&machines);
    return ret;
}
#undef MATCH

static int
vboxNodeGetInfo(virConnectPtr conn ATTRIBUTE_UNUSED,
                virNodeInfoPtr nodeinfo)
{
    return virCapabilitiesGetNodeInfo(nodeinfo);
}

static int
vboxNodeGetCellsFreeMemory(virConnectPtr conn ATTRIBUTE_UNUSED,
                           unsigned long long *freeMems,
                           int startCell,
                           int maxCells)
{
    return virHostMemGetCellsFree(freeMems, startCell, maxCells);
}

static unsigned long long
vboxNodeGetFreeMemory(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    unsigned long long freeMem;
    if (virHostMemGetInfo(NULL, &freeMem) < 0)
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

    return virHostMemGetFreePages(npages, pages, startCell, cellCount, counts);
}

static int
vboxNodeAllocPages(virConnectPtr conn ATTRIBUTE_UNUSED,
                   unsigned int npages,
                   unsigned int *pageSizes,
                   unsigned long long *pageCounts,
                   int startCell,
                   unsigned int cellCount,
                   unsigned int flags)
{
    bool add = !(flags & VIR_NODE_ALLOC_PAGES_SET);

    virCheckFlags(VIR_NODE_ALLOC_PAGES_SET, -1);

    return virHostMemAllocPages(npages, pageSizes, pageCounts,
                                startCell, cellCount, add);
}

static int
vboxDomainHasManagedSaveImage(virDomainPtr dom, unsigned int flags)
{
    vboxDriverPtr data = dom->conn->privateData;
    vboxArray machines = VBOX_ARRAY_INITIALIZER;
    vboxIID iid;
    char *machineNameUtf8 = NULL;
    PRUnichar *machineNameUtf16 = NULL;
    unsigned char uuid[VIR_UUID_BUFLEN];
    size_t i;
    bool matched = false;
    nsresult rc;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!data->vboxObj)
        return ret;

    VBOX_IID_INITIALIZE(&iid);
    rc = gVBoxAPI.UArray.vboxArrayGet(&machines, data->vboxObj, ARRAY_GET_MACHINES);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get list of machines, rc=%08x"), (unsigned)rc);
        return ret;
    }

    for (i = 0; i < machines.count; ++i) {
        IMachine *machine = machines.items[i];
        PRBool isAccessible = PR_FALSE;

        if (!machine)
            continue;

        gVBoxAPI.UIMachine.GetAccessible(machine, &isAccessible);
        if (!isAccessible)
            continue;

        gVBoxAPI.UIMachine.GetId(machine, &iid);
        if (NS_FAILED(rc))
            continue;
        vboxIIDToUUID(&iid, uuid);
        vboxIIDUnalloc(&iid);

        if (memcmp(dom->uuid, uuid, VIR_UUID_BUFLEN) == 0) {

            PRUint32 state;

            matched = true;

            gVBoxAPI.UIMachine.GetName(machine, &machineNameUtf16);
            VBOX_UTF16_TO_UTF8(machineNameUtf16, &machineNameUtf8);

            gVBoxAPI.UIMachine.GetState(machine, &state);

            ret = 0;
        }

        if (matched)
            break;
    }

    /* Do the cleanup and take care you dont leak any memory */
    VBOX_UTF8_FREE(machineNameUtf8);
    VBOX_COM_UNALLOC_MEM(machineNameUtf16);
    gVBoxAPI.UArray.vboxArrayRelease(&machines);

    return ret;
}

static int
vboxDomainSendKey(virDomainPtr dom,
                  unsigned int codeset,
                  unsigned int holdtime,
                  unsigned int *keycodes,
                  int nkeycodes,
                  unsigned int flags)
{
    int ret = -1;
    vboxDriverPtr data = dom->conn->privateData;
    IConsole *console = NULL;
    vboxIID iid;
    IMachine *machine = NULL;
    IKeyboard *keyboard = NULL;
    PRInt32 *keyDownCodes = NULL;
    PRInt32 *keyUpCodes = NULL;
    PRUint32 codesStored = 0;
    nsresult rc;
    size_t i;
    int keycode;

    if (!data->vboxObj)
        return ret;

    virCheckFlags(0, -1);

    keyDownCodes = (PRInt32 *) keycodes;

    if (VIR_ALLOC_N(keyUpCodes, nkeycodes) < 0)
        return ret;

    /* translate keycodes to xt and generate keyup scancodes */
    for (i = 0; i < nkeycodes; i++) {
        if (codeset != VIR_KEYCODE_SET_XT) {
            keycode = virKeycodeValueTranslate(codeset, VIR_KEYCODE_SET_XT,
                                               keyDownCodes[i]);
            if (keycode < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot translate keycode %u of %s codeset to"
                                 " xt keycode"),
                                 keyDownCodes[i],
                                 virKeycodeSetTypeToString(codeset));
                goto cleanup;
            }
            keyDownCodes[i] = keycode;
        }

        keyUpCodes[i] = keyDownCodes[i] + 0x80;
    }

    if (openSessionForMachine(data, dom->uuid, &iid, &machine) < 0)
        goto cleanup;

    rc = gVBoxAPI.UISession.OpenExisting(data, &iid, machine);

    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Unable to open VirtualBox session with domain %s"),
                       dom->name);
        goto cleanup;
    }

    rc = gVBoxAPI.UISession.GetConsole(data->vboxSession, &console);

    if (NS_FAILED(rc) || !console) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Unable to get Console object for domain %s"),
                       dom->name);
        goto cleanup;
    }

    rc = gVBoxAPI.UIConsole.GetKeyboard(console, &keyboard);

    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Unable to get Keyboard object for domain %s"),
                       dom->name);
        goto cleanup;
    }

    rc = gVBoxAPI.UIKeyboard.PutScancodes(keyboard, nkeycodes, keyDownCodes,
                                          &codesStored);

    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Unable to send keyboard scancodes for domain %s"),
                       dom->name);
        goto cleanup;
    }

    /* since VBOX does not support holdtime, simulate it by sleeping and
       then sending the release key scancodes */
    if (holdtime > 0)
        usleep(holdtime * 1000);

    rc = gVBoxAPI.UIKeyboard.PutScancodes(keyboard, nkeycodes, keyUpCodes,
                                          &codesStored);

    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Unable to send keyboard scan codes to domain %s"),
                       dom->name);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(keyUpCodes);
    VBOX_RELEASE(keyboard);
    VBOX_RELEASE(console);
    gVBoxAPI.UISession.Close(data->vboxSession);
    VBOX_RELEASE(machine);
    vboxIIDUnalloc(&iid);

    return ret;
}


/**
 * Function Tables
 */

virHypervisorDriver vboxCommonDriver = {
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
    .domainDefineXMLFlags = vboxDomainDefineXMLFlags, /* 1.2.12 */
    .domainUndefine = vboxDomainUndefine, /* 0.6.3 */
    .domainUndefineFlags = vboxDomainUndefineFlags, /* 0.9.5 */
    .domainAttachDevice = vboxDomainAttachDevice, /* 0.6.3 */
    .domainAttachDeviceFlags = vboxDomainAttachDeviceFlags, /* 0.7.7 */
    .domainDetachDevice = vboxDomainDetachDevice, /* 0.6.3 */
    .domainDetachDeviceFlags = vboxDomainDetachDeviceFlags, /* 0.7.7 */
    .domainUpdateDeviceFlags = vboxDomainUpdateDeviceFlags, /* 0.8.0 */
    .nodeGetCellsFreeMemory = vboxNodeGetCellsFreeMemory, /* 0.6.5 */
    .nodeGetFreeMemory = vboxNodeGetFreeMemory, /* 0.6.5 */
    .connectIsEncrypted = vboxConnectIsEncrypted, /* 0.7.3 */
    .connectIsSecure = vboxConnectIsSecure, /* 0.7.3 */
    .domainIsActive = vboxDomainIsActive, /* 0.7.3 */
    .domainIsPersistent = vboxDomainIsPersistent, /* 0.7.3 */
    .domainIsUpdated = vboxDomainIsUpdated, /* 0.8.6 */
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
    .nodeAllocPages = vboxNodeAllocPages, /* 1.2.9 */
    .domainHasManagedSaveImage = vboxDomainHasManagedSaveImage, /* 1.2.13 */
    .domainSendKey = vboxDomainSendKey, /* 1.2.15 */
    .domainScreenshot = vboxDomainScreenshot, /* 0.9.2 */
};

virHypervisorDriverPtr vboxGetHypervisorDriver(uint32_t uVersion)
{
    /* Install gVBoxAPI according to the vbox API version. */
    int result = 0;
    installUniformedAPI(gVBoxAPI, result);
    if (result < 0) {
        VIR_WARN("Libvirt doesn't support VirtualBox API version %u",
                 uVersion);
        return NULL;
    }

    return &vboxCommonDriver;
}
