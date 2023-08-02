/*
 * Copyright (C) 2014 Taowei Luo (uaedante@gmail.com)
 * Copyright (C) 2010-2014 Red Hat, Inc.
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

#include "internal.h"
#include "datatypes.h"
#include "virlog.h"
#include "storage_conf.h"
#include "virutil.h"

#include "vbox_common.h"
#include "vbox_uniformed_api.h"
#include "vbox_get_driver.h"

#define VIR_FROM_THIS VIR_FROM_VBOX

VIR_LOG_INIT("vbox.vbox_storage");

static vboxUniformedAPI gVBoxAPI;

/**
 * The Storage Functions here on
 */

static int vboxConnectNumOfStoragePools(virConnectPtr conn G_GNUC_UNUSED)
{
    /** Currently only one pool supported, the default one
     * given by ISystemProperties::defaultHardDiskFolder()
     */

    return 1;
}

static int vboxConnectListStoragePools(virConnectPtr conn G_GNUC_UNUSED,
                                       char **const names, int nnames)
{
    int numActive = 0;

    if (nnames > 0) {
        names[numActive] = g_strdup("default-pool");
        numActive++;
    }
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
    struct _vboxDriver *data = pool->conn->privateData;
    vboxArray hardDisks = VBOX_ARRAY_INITIALIZER;
    PRUint32 hardDiskAccessible = 0;
    nsresult rc;
    size_t i;

    if (!data->vboxObj)
        return -1;

    rc = gVBoxAPI.UArray.vboxArrayGet(&hardDisks, data->vboxObj,
                                      gVBoxAPI.UArray.handleGetHardDisks(data->vboxObj));
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not get number of volumes in the pool: %1$s, rc=%2$08x"),
                       pool->name, (unsigned)rc);
        return -1;
    }

    for (i = 0; i < hardDisks.count; ++i) {
        IMedium *hardDisk = hardDisks.items[i];
        PRUint32 hddstate;

        if (!hardDisk)
            continue;

        gVBoxAPI.UIMedium.GetState(hardDisk, &hddstate);
        if (hddstate != MediaState_Inaccessible)
            hardDiskAccessible++;
    }

    gVBoxAPI.UArray.vboxArrayRelease(&hardDisks);

    return hardDiskAccessible;
}

static int
vboxStoragePoolListVolumes(virStoragePoolPtr pool, char **const names, int nnames)
{
    struct _vboxDriver *data = pool->conn->privateData;
    vboxArray hardDisks = VBOX_ARRAY_INITIALIZER;
    PRUint32 numActive = 0;
    nsresult rc;
    size_t i;

    if (!data->vboxObj)
        return -1;

    rc = gVBoxAPI.UArray.vboxArrayGet(&hardDisks, data->vboxObj,
                                      gVBoxAPI.UArray.handleGetHardDisks(data->vboxObj));
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not get the volume list in the pool: %1$s, rc=%2$08x"),
                       pool->name, (unsigned)rc);
        return -1;
    }

    for (i = 0; i < hardDisks.count && numActive < nnames; ++i) {
        IMedium *hardDisk = hardDisks.items[i];
        PRUint32 hddstate;
        char *nameUtf8 = NULL;
        PRUnichar *nameUtf16 = NULL;

        if (!hardDisk)
            continue;

        gVBoxAPI.UIMedium.GetState(hardDisk, &hddstate);
        if (hddstate == MediaState_Inaccessible)
            continue;

        gVBoxAPI.UIMedium.GetName(hardDisk, &nameUtf16);

        VBOX_UTF16_TO_UTF8(nameUtf16, &nameUtf8);
        VBOX_UTF16_FREE(nameUtf16);

        if (!nameUtf8)
            continue;

        VIR_DEBUG("nnames[%d]: %s", numActive, nameUtf8);
        names[numActive] = g_strdup(nameUtf8);
        numActive++;

        VBOX_UTF8_FREE(nameUtf8);
    }

    gVBoxAPI.UArray.vboxArrayRelease(&hardDisks);
    return numActive;
}

static virStorageVolPtr
vboxStorageVolLookupByName(virStoragePoolPtr pool, const char *name)
{
    struct _vboxDriver *data = pool->conn->privateData;
    vboxArray hardDisks = VBOX_ARRAY_INITIALIZER;
    nsresult rc;
    size_t i;
    virStorageVolPtr ret = NULL;

    if (!data->vboxObj)
        return ret;

    if (!name)
        return ret;

    rc = gVBoxAPI.UArray.vboxArrayGet(&hardDisks, data->vboxObj,
                                      gVBoxAPI.UArray.handleGetHardDisks(data->vboxObj));
    if (NS_FAILED(rc))
        return ret;

    for (i = 0; i < hardDisks.count; ++i) {
        IMedium *hardDisk = hardDisks.items[i];
        PRUint32 hddstate;
        char *nameUtf8 = NULL;
        PRUnichar *nameUtf16 = NULL;

        if (!hardDisk)
            continue;

        gVBoxAPI.UIMedium.GetState(hardDisk, &hddstate);
        if (hddstate == MediaState_Inaccessible)
            continue;

        gVBoxAPI.UIMedium.GetName(hardDisk, &nameUtf16);

        if (nameUtf16) {
            VBOX_UTF16_TO_UTF8(nameUtf16, &nameUtf8);
            VBOX_UTF16_FREE(nameUtf16);
        }

        if (nameUtf8 && STREQ(nameUtf8, name)) {
            vboxIID hddIID;
            unsigned char uuid[VIR_UUID_BUFLEN];
            char key[VIR_UUID_STRING_BUFLEN] = "";

            VBOX_IID_INITIALIZE(&hddIID);
            rc = gVBoxAPI.UIMedium.GetId(hardDisk, &hddIID);
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

    gVBoxAPI.UArray.vboxArrayRelease(&hardDisks);

    return ret;
}

static virStorageVolPtr
vboxStorageVolLookupByKey(virConnectPtr conn, const char *key)
{
    struct _vboxDriver *data = conn->privateData;
    vboxIID hddIID;
    unsigned char uuid[VIR_UUID_BUFLEN];
    IMedium *hardDisk = NULL;
    PRUnichar *hddNameUtf16 = NULL;
    char *hddNameUtf8 = NULL;
    PRUint32 hddstate;
    nsresult rc;
    virStorageVolPtr ret = NULL;

    if (!data->vboxObj)
        return ret;

    VBOX_IID_INITIALIZE(&hddIID);
    if (!key)
        return ret;

    if (virUUIDParse(key, uuid) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Could not parse UUID from '%1$s'"), key);
        return NULL;
    }

    vboxIIDFromUUID(&hddIID, uuid);
    rc = gVBoxAPI.UIVirtualBox.GetHardDiskByIID(data->vboxObj, &hddIID, &hardDisk);
    if (NS_FAILED(rc))
        goto cleanup;

    gVBoxAPI.UIMedium.GetState(hardDisk, &hddstate);
    if (hddstate == MediaState_Inaccessible)
        goto cleanup;

    gVBoxAPI.UIMedium.GetName(hardDisk, &hddNameUtf16);
    if (!hddNameUtf16)
        goto cleanup;

    VBOX_UTF16_TO_UTF8(hddNameUtf16, &hddNameUtf8);
    if (!hddNameUtf8) {
        VBOX_UTF16_FREE(hddNameUtf16);
        goto cleanup;
    }

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

 cleanup:
    VBOX_MEDIUM_RELEASE(hardDisk);
    vboxIIDUnalloc(&hddIID);
    return ret;
}

static virStorageVolPtr
vboxStorageVolLookupByPath(virConnectPtr conn, const char *path)
{
    struct _vboxDriver *data = conn->privateData;
    PRUnichar *hddPathUtf16 = NULL;
    IMedium *hardDisk = NULL;
    PRUnichar *hddNameUtf16 = NULL;
    char *hddNameUtf8 = NULL;
    unsigned char uuid[VIR_UUID_BUFLEN];
    char key[VIR_UUID_STRING_BUFLEN] = "";
    vboxIID hddIID;
    PRUint32 hddstate;
    nsresult rc;
    virStorageVolPtr ret = NULL;

    if (!data->vboxObj)
        return ret;

    VBOX_IID_INITIALIZE(&hddIID);

    if (!path)
        return ret;

    VBOX_UTF8_TO_UTF16(path, &hddPathUtf16);

    if (!hddPathUtf16)
        return ret;

    rc = gVBoxAPI.UIVirtualBox.FindHardDisk(data->vboxObj, hddPathUtf16,
                                            DeviceType_HardDisk, AccessMode_ReadWrite, &hardDisk);
    if (NS_FAILED(rc))
        goto cleanup;

    gVBoxAPI.UIMedium.GetState(hardDisk, &hddstate);
    if (hddstate == MediaState_Inaccessible)
        goto cleanup;

    gVBoxAPI.UIMedium.GetName(hardDisk, &hddNameUtf16);

    if (!hddNameUtf16)
        goto cleanup;

    VBOX_UTF16_TO_UTF8(hddNameUtf16, &hddNameUtf8);
    VBOX_UTF16_FREE(hddNameUtf16);

    if (!hddNameUtf8)
        goto cleanup;

    rc = gVBoxAPI.UIMedium.GetId(hardDisk, &hddIID);
    if (NS_FAILED(rc)) {
        VBOX_UTF8_FREE(hddNameUtf8);
        goto cleanup;
    }

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

    vboxIIDUnalloc(&hddIID);
    VBOX_UTF8_FREE(hddNameUtf8);

 cleanup:
    VBOX_MEDIUM_RELEASE(hardDisk);
    VBOX_UTF16_FREE(hddPathUtf16);
    return ret;
}

static virStorageVolPtr
vboxStorageVolCreateXML(virStoragePoolPtr pool,
                        const char *xml, unsigned int flags)
{
    struct _vboxDriver *data = pool->conn->privateData;
    PRUnichar *hddFormatUtf16 = NULL;
    PRUnichar *hddNameUtf16 = NULL;
    virStoragePoolDef poolDef = { 0 };
    nsresult rc;
    vboxIID hddIID;
    unsigned char uuid[VIR_UUID_BUFLEN];
    char key[VIR_UUID_STRING_BUFLEN] = "";
    IMedium *hardDisk = NULL;
    IProgress *progress = NULL;
    PRUint64 logicalSize = 0;
    PRUint32 variant = HardDiskVariant_Standard;
    resultCodeUnion resultCode;
    virStorageVolPtr ret = NULL;
    g_autoptr(virStorageVolDef) def = NULL;
    g_autofree char *homedir = NULL;
    unsigned int parseFlags = 0;

    if (!data->vboxObj)
        return ret;

    virCheckFlags(VIR_STORAGE_VOL_CREATE_VALIDATE, NULL);

    if (flags & VIR_STORAGE_VOL_CREATE_VALIDATE)
        parseFlags |= VIR_VOL_XML_PARSE_VALIDATE;

    /* since there is currently one default pool now
     * and virStorageVolDefFormat() just checks it type
     * so just assign it for now, change the behaviour
     * when vbox supports pools.
     */
    poolDef.type = VIR_STORAGE_POOL_DIR;

    if ((def = virStorageVolDefParse(&poolDef, xml, NULL, parseFlags)) == NULL)
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

    /* If target.path isn't given, use default path ~/.VirtualBox/image_name */
    if (!def->target.path) {
        homedir = virGetUserDirectory();
        def->target.path = g_strdup_printf("%s/.VirtualBox/%s", homedir, def->name);
    }
    VBOX_UTF8_TO_UTF16(def->target.path, &hddNameUtf16);

    if (!hddFormatUtf16 || !hddNameUtf16)
        goto cleanup;

    rc = gVBoxAPI.UIVirtualBox.CreateHardDisk(data->vboxObj, hddFormatUtf16, hddNameUtf16, &hardDisk);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not create harddisk, rc=%1$08x"),
                       (unsigned)rc);
        goto cleanup;
    }

    logicalSize = VIR_DIV_UP(def->target.capacity, 1024 * 1024);

    if (def->target.capacity == def->target.allocation)
        variant = HardDiskVariant_Fixed;

    rc = gVBoxAPI.UIMedium.CreateBaseStorage(hardDisk, logicalSize, variant, &progress);
    if (NS_FAILED(rc) || !progress) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not create base storage, rc=%1$08x"),
                       (unsigned)rc);
        goto cleanup;
    }

    gVBoxAPI.UIProgress.WaitForCompletion(progress, -1);
    gVBoxAPI.UIProgress.GetResultCode(progress, &resultCode);
    if (RC_FAILED(resultCode)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not create base storage, rc=%1$08x"),
                       (unsigned)resultCode.uResultCode);
        goto cleanup;
    }

    VBOX_IID_INITIALIZE(&hddIID);
    rc = gVBoxAPI.UIMedium.GetId(hardDisk, &hddIID);
    if (NS_FAILED(rc))
        goto cleanup;

    vboxIIDToUUID(&hddIID, uuid);
    virUUIDFormat(uuid, key);

    ret = virGetStorageVol(pool->conn, pool->name, def->name, key,
                           NULL, NULL);

 cleanup:
    vboxIIDUnalloc(&hddIID);
    VBOX_RELEASE(progress);
    VBOX_UTF16_FREE(hddFormatUtf16);
    VBOX_UTF16_FREE(hddNameUtf16);
    return ret;
}

static int vboxStorageVolDelete(virStorageVolPtr vol, unsigned int flags)
{
    struct _vboxDriver *data = vol->conn->privateData;
    unsigned char uuid[VIR_UUID_BUFLEN];
    IMedium *hardDisk = NULL;
    int deregister = 0;
    PRUint32 hddstate = 0;
    size_t i = 0;
    size_t j = 0;
    PRUint32 machineIdsSize = 0;
    vboxArray machineIds = VBOX_ARRAY_INITIALIZER;
    vboxIID hddIID;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    VBOX_IID_INITIALIZE(&hddIID);
    virCheckFlags(0, -1);

    if (virUUIDParse(vol->key, uuid) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Could not parse UUID from '%1$s'"), vol->key);
        return -1;
    }

    vboxIIDFromUUID(&hddIID, uuid);
    if (NS_FAILED(gVBoxAPI.UIVirtualBox.GetHardDiskByIID(data->vboxObj,
                                                         &hddIID,
                                                         &hardDisk)))
        goto cleanup;

    gVBoxAPI.UIMedium.GetState(hardDisk, &hddstate);
    if (hddstate == MediaState_Inaccessible)
        goto cleanup;

    gVBoxAPI.UArray.vboxArrayGet(&machineIds, hardDisk,
                                 gVBoxAPI.UArray.handleMediumGetMachineIds(hardDisk));

#if defined WIN32
    /* VirtualBox 2.2 on Windows represents IIDs as GUIDs and the
     * machineIds array contains direct instances of the GUID struct
     * instead of pointers to the actual struct instances. But there
     * is no 128bit width simple item type for a SafeArray to fit a
     * GUID in. The largest simple type it 64bit width and VirtualBox
     * uses two of this 64bit items to represents one GUID. Therefore,
     * we divide the size of the SafeArray by two, to compensate for
     * this workaround in VirtualBox */
    if (gVBoxAPI.uVersion >= 2001052 && gVBoxAPI.uVersion < 2002051)
        machineIds.count /= 2;
#endif /* !defined WIN32 */

    machineIdsSize = machineIds.count;

    for (i = 0; i < machineIds.count; i++) {
        IMachine *machine = NULL;
        vboxIID machineId;
        vboxArray hddAttachments = VBOX_ARRAY_INITIALIZER;

        VBOX_IID_INITIALIZE(&machineId);
        vboxIIDFromArrayItem(&machineId, &machineIds, i);

        if (NS_FAILED(gVBoxAPI.UIVirtualBox.GetMachine(data->vboxObj,
                                                       &machineId,
                                                       &machine))) {
            virReportError(VIR_ERR_NO_DOMAIN, "%s",
                           _("no domain with matching uuid"));
            break;
        }

        if (NS_FAILED(gVBoxAPI.UISession.Open(data, machine))) {
            vboxIIDUnalloc(&machineId);
            continue;
        }

        if (NS_FAILED(gVBoxAPI.UISession.GetMachine(data->vboxSession,
                                                    &machine)))
            goto cleanupLoop;

        gVBoxAPI.UArray.vboxArrayGet(&hddAttachments, machine,
                                     gVBoxAPI.UArray.handleMachineGetMediumAttachments(machine));

        for (j = 0; j < hddAttachments.count; j++) {
            IMediumAttachment *hddAttachment = hddAttachments.items[j];
            IMedium *hdd = NULL;
            vboxIID iid;

            if (!hddAttachment)
                continue;

            if (NS_FAILED(gVBoxAPI.UIMediumAttachment.GetMedium(hddAttachment,
                                                                &hdd)) || !hdd)
                continue;

            VBOX_IID_INITIALIZE(&iid);
            if (NS_FAILED(gVBoxAPI.UIMedium.GetId(hdd, &iid))) {
                VBOX_MEDIUM_RELEASE(hdd);
                continue;
            }

            DEBUGIID("HardDisk (to delete) UUID", &hddIID);
            DEBUGIID("HardDisk (currently processing) UUID", &iid);

            if (vboxIIDIsEqual(&hddIID, &iid)) {
                PRUnichar *controller = NULL;
                PRInt32 port = 0;
                PRInt32 device = 0;

                DEBUGIID("Found HardDisk to delete, UUID", &hddIID);

                gVBoxAPI.UIMediumAttachment.GetController(hddAttachment, &controller);
                gVBoxAPI.UIMediumAttachment.GetPort(hddAttachment, &port);
                gVBoxAPI.UIMediumAttachment.GetDevice(hddAttachment, &device);

                if (NS_SUCCEEDED(gVBoxAPI.UIMachine.DetachDevice(machine, controller, port, device))) {
                    ignore_value(gVBoxAPI.UIMachine.SaveSettings(machine));
                    VIR_DEBUG("saving machine settings");
                    deregister++;
                    VIR_DEBUG("deregistering hdd:%d", deregister);
                }

                VBOX_UTF16_FREE(controller);
            }
            vboxIIDUnalloc(&iid);
            VBOX_MEDIUM_RELEASE(hdd);
        }

 cleanupLoop:
        gVBoxAPI.UArray.vboxArrayRelease(&hddAttachments);
        VBOX_RELEASE(machine);
        gVBoxAPI.UISession.Close(data->vboxSession);
        vboxIIDUnalloc(&machineId);
    }

    gVBoxAPI.UArray.vboxArrayUnalloc(&machineIds);

    if (machineIdsSize == 0 || machineIdsSize == deregister) {
        IProgress *progress = NULL;
        if (NS_SUCCEEDED(gVBoxAPI.UIMedium.DeleteStorage(hardDisk, &progress)) &&
            progress) {
            gVBoxAPI.UIProgress.WaitForCompletion(progress, -1);
            VBOX_RELEASE(progress);
            DEBUGIID("HardDisk deleted, UUID", &hddIID);
            ret = 0;
        }
    }

 cleanup:
    VBOX_MEDIUM_RELEASE(hardDisk);
    vboxIIDUnalloc(&hddIID);
    return ret;
}

static int vboxStorageVolGetInfo(virStorageVolPtr vol, virStorageVolInfoPtr info)
{
    struct _vboxDriver *data = vol->conn->privateData;
    IMedium *hardDisk = NULL;
    unsigned char uuid[VIR_UUID_BUFLEN];
    PRUint32 hddstate;
    PRUint64 hddLogicalSize = 0;
    PRUint64 hddActualSize = 0;
    vboxIID hddIID;
    nsresult rc;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    if (!info)
        return ret;

    if (virUUIDParse(vol->key, uuid) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Could not parse UUID from '%1$s'"), vol->key);
        return ret;
    }

    VBOX_IID_INITIALIZE(&hddIID);
    vboxIIDFromUUID(&hddIID, uuid);
    rc = gVBoxAPI.UIVirtualBox.GetHardDiskByIID(data->vboxObj, &hddIID, &hardDisk);
    if (NS_FAILED(rc))
        goto cleanup;

    gVBoxAPI.UIMedium.GetState(hardDisk, &hddstate);
    if (hddstate == MediaState_Inaccessible)
        goto cleanup;

    info->type = VIR_STORAGE_VOL_FILE;

    gVBoxAPI.UIMedium.GetLogicalSize(hardDisk, &hddLogicalSize);
    info->capacity = hddLogicalSize;

    gVBoxAPI.UIMedium.GetSize(hardDisk, &hddActualSize);
    info->allocation = hddActualSize;

    ret = 0;

    VIR_DEBUG("Storage Volume Name: %s", vol->name);
    VIR_DEBUG("Storage Volume Type: %s", info->type == VIR_STORAGE_VOL_BLOCK ? "Block" : "File");
    VIR_DEBUG("Storage Volume Capacity: %llu", info->capacity);
    VIR_DEBUG("Storage Volume Allocation: %llu", info->allocation);

 cleanup:
    VBOX_MEDIUM_RELEASE(hardDisk);
    vboxIIDUnalloc(&hddIID);
    return ret;
}

static char *vboxStorageVolGetXMLDesc(virStorageVolPtr vol, unsigned int flags)
{
    struct _vboxDriver *data = vol->conn->privateData;
    IMedium *hardDisk = NULL;
    unsigned char uuid[VIR_UUID_BUFLEN];
    PRUnichar *hddFormatUtf16 = NULL;
    char *hddFormatUtf8 = NULL;
    PRUint64 hddLogicalSize = 0;
    PRUint64 hddActualSize = 0;
    virStoragePoolDef pool = { 0 };
    virStorageVolDef def = { 0 };
    vboxIID hddIID;
    PRUint32 hddstate;
    nsresult rc;
    char *ret = NULL;

    if (!data->vboxObj)
        return ret;

    virCheckFlags(0, NULL);

    if (virUUIDParse(vol->key, uuid) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Could not parse UUID from '%1$s'"), vol->key);
        return ret;
    }

    VBOX_IID_INITIALIZE(&hddIID);
    vboxIIDFromUUID(&hddIID, uuid);
    rc = gVBoxAPI.UIVirtualBox.GetHardDiskByIID(data->vboxObj, &hddIID, &hardDisk);
    if (NS_FAILED(rc))
        goto cleanup;

    gVBoxAPI.UIMedium.GetState(hardDisk, &hddstate);
    if (hddstate == MediaState_Inaccessible)
        goto cleanup;

    /* since there is currently one default pool now
     * and virStorageVolDefFormat() just checks it type
     * so just assign it for now, change the behaviour
     * when vbox supports pools.
     */
    pool.type = VIR_STORAGE_POOL_DIR;
    def.type = VIR_STORAGE_VOL_FILE;

    rc = gVBoxAPI.UIMedium.GetLogicalSize(hardDisk, &hddLogicalSize);
    if (NS_FAILED(rc))
        goto cleanup;

    def.target.capacity = hddLogicalSize;

    rc = gVBoxAPI.UIMedium.GetSize(hardDisk, &hddActualSize);
    if (NS_FAILED(rc))
        goto cleanup;

    def.name = g_strdup(vol->name);

    def.key = g_strdup(vol->key);

    rc = gVBoxAPI.UIMedium.GetFormat(hardDisk, &hddFormatUtf16);
    if (NS_FAILED(rc))
        goto cleanup;

    VBOX_UTF16_TO_UTF8(hddFormatUtf16, &hddFormatUtf8);
    if (!hddFormatUtf8)
        goto cleanup;

    VIR_DEBUG("Storage Volume Format: %s", hddFormatUtf8);

    if (STRCASEEQ("vmdk", hddFormatUtf8))
        def.target.format = VIR_STORAGE_FILE_VMDK;
    else if (STRCASEEQ("vhd", hddFormatUtf8))
        def.target.format = VIR_STORAGE_FILE_VPC;
    else if (STRCASEEQ("vdi", hddFormatUtf8))
        def.target.format = VIR_STORAGE_FILE_VDI;
    else
        def.target.format = VIR_STORAGE_FILE_RAW;
    ret = virStorageVolDefFormat(&pool, &def);

 cleanup:
    VBOX_UTF16_FREE(hddFormatUtf16);
    VBOX_UTF8_FREE(hddFormatUtf8);
    VBOX_MEDIUM_RELEASE(hardDisk);
    vboxIIDUnalloc(&hddIID);
    return ret;
}

static char *vboxStorageVolGetPath(virStorageVolPtr vol)
{
    struct _vboxDriver *data = vol->conn->privateData;
    IMedium *hardDisk = NULL;
    PRUnichar *hddLocationUtf16 = NULL;
    char *hddLocationUtf8 = NULL;
    unsigned char uuid[VIR_UUID_BUFLEN];
    vboxIID hddIID;
    PRUint32 hddstate;
    nsresult rc;
    char *ret = NULL;

    if (!data->vboxObj)
        return ret;

    if (virUUIDParse(vol->key, uuid) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Could not parse UUID from '%1$s'"), vol->key);
        return ret;
    }

    VBOX_IID_INITIALIZE(&hddIID);
    vboxIIDFromUUID(&hddIID, uuid);
    rc = gVBoxAPI.UIVirtualBox.GetHardDiskByIID(data->vboxObj, &hddIID, &hardDisk);
    if (NS_FAILED(rc))
        goto cleanup;

    gVBoxAPI.UIMedium.GetState(hardDisk, &hddstate);
    if (hddstate == MediaState_Inaccessible)
        goto cleanup;

    gVBoxAPI.UIMedium.GetLocation(hardDisk, &hddLocationUtf16);
    if (!hddLocationUtf16)
        goto cleanup;

    VBOX_UTF16_TO_UTF8(hddLocationUtf16, &hddLocationUtf8);
    if (!hddLocationUtf8)
        goto cleanup;

    ret = g_strdup(hddLocationUtf8);

    VIR_DEBUG("Storage Volume Name: %s", vol->name);
    VIR_DEBUG("Storage Volume Path: %s", hddLocationUtf8);
    VIR_DEBUG("Storage Volume Pool: %s", vol->pool);

    VBOX_UTF8_FREE(hddLocationUtf8);

 cleanup:
    VBOX_UTF16_FREE(hddLocationUtf16);
    VBOX_MEDIUM_RELEASE(hardDisk);
    vboxIIDUnalloc(&hddIID);
    return ret;
}

/**
 * Function Tables
 */

virStorageDriver vboxStorageDriver = {
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

virStorageDriver *vboxGetStorageDriver(uint32_t uVersion)
{
    /* Install gVBoxAPI according to the vbox API version.
     * Return -1 for unsupported version.
     */
    if (uVersion >= 6000051 && uVersion < 6001051) {
        vbox61InstallUniformedAPI(&gVBoxAPI);
    } else if (uVersion >= 7000000 && uVersion < 7000004) {
        vbox70InstallUniformedAPI(&gVBoxAPI);
    } else {
        return NULL;
    }
    return &vboxStorageDriver;
}
