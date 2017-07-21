/*
 * vz_utils.c: core driver functions for managing
 * Parallels Cloud Server hosts
 *
 * Copyright (C) 2012 Parallels, Inc.
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
 * License along with this library; If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#include <config.h>

#include <stdarg.h>

#include "vircommand.h"
#include "virerror.h"
#include "viralloc.h"
#include "virjson.h"
#include "vz_utils.h"
#include "vz_sdk.h"
#include "virstring.h"
#include "datatypes.h"
#include "virlog.h"
#include "virtime.h"

#define VIR_FROM_THIS VIR_FROM_PARALLELS
#define PRLSRVCTL "prlsrvctl"

VIR_LOG_INIT("parallels.utils");

static virDomainDiskBus vz6DiskBuses[] = {VIR_DOMAIN_DISK_BUS_IDE,
                                          VIR_DOMAIN_DISK_BUS_SCSI,
                                          VIR_DOMAIN_DISK_BUS_SATA,
                                          VIR_DOMAIN_DISK_BUS_LAST};

static virDomainDiskBus vz7DiskBuses[] = {VIR_DOMAIN_DISK_BUS_IDE,
                                          VIR_DOMAIN_DISK_BUS_SCSI,
                                          VIR_DOMAIN_DISK_BUS_LAST};

static virDomainControllerType vz6ControllerTypes[] = {VIR_DOMAIN_CONTROLLER_TYPE_SCSI,
                                                       VIR_DOMAIN_CONTROLLER_TYPE_IDE,
                                                       VIR_DOMAIN_CONTROLLER_TYPE_SATA,
                                                       VIR_DOMAIN_CONTROLLER_TYPE_LAST};

static virDomainControllerType vz7ControllerTypes[] = {VIR_DOMAIN_CONTROLLER_TYPE_SCSI,
                                                       VIR_DOMAIN_CONTROLLER_TYPE_IDE,
                                                       VIR_DOMAIN_CONTROLLER_TYPE_LAST};

/**
 * vzDomObjFromDomain:
 * @domain: Domain pointer that has to be looked up
 *
 * This function looks up @domain and returns the appropriate virDomainObjPtr
 * that has to be unlocked by virObjectUnlock().
 *
 * Returns the domain object without incremented reference counter which is locked
 * on success, NULL otherwise.
 */
virDomainObjPtr
vzDomObjFromDomain(virDomainPtr domain)
{
    virDomainObjPtr vm;
    vzConnPtr privconn = domain->conn->privateData;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    vzDriverPtr driver = privconn->driver;

    vm = virDomainObjListFindByUUID(driver->domains, domain->uuid);
    if (!vm) {
        virUUIDFormat(domain->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%s' (%s)"),
                       uuidstr, domain->name);
        return NULL;
    }

    return vm;
}

/**
 * vzDomObjFromDomainRef:
 * @domain: Domain pointer that has to be looked up
 *
 * This function looks up @domain and returns the appropriate virDomainObjPtr
 * that has to be released by calling virDomainObjEndAPI().
 *
 * Returns the domain object with incremented reference counter which is locked
 * on success, NULL otherwise.
 */
virDomainObjPtr
vzDomObjFromDomainRef(virDomainPtr domain)
{
    virDomainObjPtr vm;
    vzConnPtr privconn = domain->conn->privateData;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    vzDriverPtr driver = privconn->driver;

    vm = virDomainObjListFindByUUIDRef(driver->domains, domain->uuid);
    if (!vm) {
        virUUIDFormat(domain->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%s' (%s)"),
                       uuidstr, domain->name);
        return NULL;
    }

    return vm;
}

static int
vzDoCmdRun(char **outbuf, const char *binary, va_list list)
{
    virCommandPtr cmd = virCommandNewVAList(binary, list);
    int ret = -1;

    if (outbuf)
        virCommandSetOutputBuffer(cmd, outbuf);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virCommandFree(cmd);
    if (ret && outbuf)
        VIR_FREE(*outbuf);
    return ret;
}

/*
 * Run command and return its output, pointer to
 * buffer or NULL in case of error. Caller os responsible
 * for freeing the buffer.
 */
char *
vzGetOutput(const char *binary, ...)
{
    char *outbuf;
    va_list list;
    int ret;

    va_start(list, binary);
    ret = vzDoCmdRun(&outbuf, binary, list);
    va_end(list);
    if (ret)
        return NULL;

    return outbuf;
}

static void
vzInitCaps(unsigned long vzVersion, vzCapabilitiesPtr vzCaps)
{
    if (vzVersion < VIRTUOZZO_VER_7) {
        vzCaps->ctDiskFormat = VIR_STORAGE_FILE_PLOOP;
        vzCaps->vmDiskFormat = VIR_STORAGE_FILE_PLOOP;
        vzCaps->diskBuses = vz6DiskBuses;
        vzCaps->controllerTypes = vz6ControllerTypes;
        vzCaps->scsiControllerModel = VIR_DOMAIN_CONTROLLER_MODEL_SCSI_BUSLOGIC;
    } else {
        vzCaps->ctDiskFormat = VIR_STORAGE_FILE_PLOOP;
        vzCaps->vmDiskFormat = VIR_STORAGE_FILE_QCOW2;
        vzCaps->diskBuses = vz7DiskBuses;
        vzCaps->controllerTypes = vz7ControllerTypes;
        vzCaps->scsiControllerModel = VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_SCSI;
    }
}

int
vzInitVersion(vzDriverPtr driver)
{
    char *output, *sVer, *tmp;
    const char *searchStr = "prlsrvctl version ";
    int ret = -1;

    output = vzGetOutput(PRLSRVCTL, "--help", NULL);

    if (!output) {
        vzParseError();
        goto cleanup;
    }

    if (!(sVer = strstr(output, searchStr))) {
        vzParseError();
        goto cleanup;
    }

    sVer = sVer + strlen(searchStr);

    /* parallels server has versions number like 6.0.17977.782218 or 7.0.0,
     * In libvirt we handle only first two numbers. */
    if (!(tmp = strchr(sVer, '.'))) {
        vzParseError();
        goto cleanup;
    }

    if (!(tmp = strchr(tmp + 1, '.'))) {
        vzParseError();
        goto cleanup;
    }

    tmp[0] = '\0';
    if (virParseVersionString(sVer, &(driver->vzVersion), true) < 0) {
        vzParseError();
        goto cleanup;
    }

    vzInitCaps(driver->vzVersion, &driver->vzCaps);
    ret = 0;

 cleanup:
    VIR_FREE(output);
    return ret;
}

static int
vzCheckDiskAddressDriveUnsupportedParams(virDomainDiskDefPtr disk)
{
    virDomainDeviceDriveAddressPtr drive = &disk->info.addr.drive;
    int devIdx, busIdx;

    if (drive->controller > 0) {
        /* We have only one controller of each type */
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Invalid drive address of disk %s, vz driver "
                         "supports only one controller."), disk->dst);
        return -1;
    }

    if (drive->target > 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Invalid drive address of disk %s, vz driver "
                         "supports only target 0."), disk->dst);
        return -1;
    }

    switch (disk->bus) {
    case VIR_DOMAIN_DISK_BUS_IDE:
        if (drive->unit > 1) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Invalid drive address of disk %s, vz driver "
                             "supports only units 0-1 for IDE bus."),
                           disk->dst);
            return -1;
        }
        break;
    case VIR_DOMAIN_DISK_BUS_SCSI:
    case VIR_DOMAIN_DISK_BUS_SATA:
        if (drive->bus > 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Invalid drive address of disk %s, vz driver "
                             "supports only bus 0 for SATA and SCSI bus."),
                           disk->dst);
            return -1;
        }
        break;
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Specified disk bus is not supported by vz driver."));
        return -1;
    }

    if (virDiskNameToBusDeviceIndex(disk, &busIdx, &devIdx) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot convert disk '%s' to bus/device index"),
                       disk->dst);
        return -1;
    }

    if (busIdx != drive->bus || devIdx != drive->unit) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Invalid drive address of disk %s, vz driver "
                         "does not support non default name mappings."),
                       disk->dst);
        return -1;
    }

    return 0;
}

static int
vzCheckDiskUnsupportedParams(virDomainDiskDefPtr disk)
{
    if (disk->device != VIR_DOMAIN_DISK_DEVICE_DISK &&
        disk->device != VIR_DOMAIN_DISK_DEVICE_CDROM) {

        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Only hard disks and cdroms are supported "
                         "by vz driver."));
        return -1;
    }

    if (disk->blockio.logical_block_size ||
        disk->blockio.physical_block_size) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Setting disk block sizes is not "
                         "supported by vz driver."));
        return -1;
    }

    if (disk->blkdeviotune.total_bytes_sec ||
        disk->blkdeviotune.read_bytes_sec ||
        disk->blkdeviotune.write_bytes_sec ||
        disk->blkdeviotune.total_iops_sec ||
        disk->blkdeviotune.read_iops_sec ||
        disk->blkdeviotune.write_iops_sec) {

        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Setting disk io limits is not "
                         "supported by vz driver yet."));
        return -1;
    }

    if (disk->serial && disk->device != VIR_DOMAIN_DISK_DEVICE_DISK) {
        VIR_INFO("%s", _("Setting disk serial number is "
                         "supported only for disk devices."));
    }

    if (disk->wwn) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Setting disk wwn id is not "
                         "supported by vz driver."));
        return -1;
    }

    if (disk->vendor) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Setting disk vendor is not "
                         "supported by vz driver."));
        return -1;
    }

    if (disk->product) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Setting disk product id is not "
                         "supported by vz driver."));
        return -1;
    }

    if (disk->error_policy != VIR_DOMAIN_DISK_ERROR_POLICY_DEFAULT) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Setting disk error policy is not "
                         "supported by vz driver."));
        return -1;
    }

    if (disk->iomode != VIR_DOMAIN_DISK_IO_DEFAULT &&
        disk->iomode != VIR_DOMAIN_DISK_IO_NATIVE) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Only native iomode is "
                         "supported by vz driver."));
        return -1;
    }

    if (disk->copy_on_read) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Disk copy_on_read is not "
                         "supported by vz driver."));
        return -1;
    }

    if (disk->startupPolicy != VIR_DOMAIN_STARTUP_POLICY_DEFAULT) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Setting up disk startup policy is not "
                         "supported by vz driver."));
        return -1;
    }

    if (disk->transient) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Transient disks are not "
                         "supported by vz driver."));
        return -1;
    }

    if (disk->discard) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Setting up disk discard parameter is not "
                         "supported by vz driver."));
        return -1;
    }

    if (disk->iothread) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Setting up disk io thread # is not "
                         "supported by vz driver."));
        return -1;
    }

    if (disk->src->type != VIR_STORAGE_TYPE_FILE &&
        disk->src->type != VIR_STORAGE_TYPE_BLOCK) {

        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Only disk and block storage types are "
                         "supported by vz driver."));
        return -1;

    }

    if (vzCheckDiskAddressDriveUnsupportedParams(disk) < 0)
        return -1;

    return 0;
}

int
vzCheckUnsupportedDisk(const virDomainDef *def,
                       virDomainDiskDefPtr disk,
                       vzCapabilitiesPtr vzCaps)
{
    size_t i;
    virStorageFileFormat diskFormat;

    if (vzCheckDiskUnsupportedParams(disk) < 0)
        return -1;

    if (disk->src->type == VIR_STORAGE_TYPE_FILE) {
        if (disk->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
            if (IS_CT(def))
                diskFormat = vzCaps->ctDiskFormat;
            else
                diskFormat = vzCaps->vmDiskFormat;
        } else {
            diskFormat = VIR_STORAGE_FILE_RAW;
        }
    } else {
        diskFormat = VIR_STORAGE_FILE_RAW;
    }

    if (virDomainDiskGetFormat(disk) != VIR_STORAGE_FILE_NONE &&
        virDomainDiskGetFormat(disk) != diskFormat) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported format of disk %s"),
                       disk->src->path);
        return -1;
    }

    for (i = 0; vzCaps->diskBuses[i] != VIR_DOMAIN_DISK_BUS_LAST; i++) {
        if (disk->bus == vzCaps->diskBuses[i])
            break;
    }

    if (vzCaps->diskBuses[i] == VIR_DOMAIN_DISK_BUS_LAST) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported disk bus type %s"),
                       virDomainDiskBusTypeToString(disk->bus));
        return -1;
    }

    return 0;
}

int
vzCheckUnsupportedControllers(const virDomainDef *def, vzCapabilitiesPtr vzCaps)
{
    size_t i, j;
    virDomainControllerDefPtr controller;

    for (i = 0; i < def->ncontrollers; i++) {
        controller = def->controllers[i];

        for (j = 0; vzCaps->controllerTypes[j] != VIR_DOMAIN_CONTROLLER_TYPE_LAST; j++) {
            if (controller->type == vzCaps->controllerTypes[j])
                break;
        }

        if (vzCaps->controllerTypes[j] == VIR_DOMAIN_CONTROLLER_TYPE_LAST) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported controller type %s"),
                           virDomainControllerTypeToString(controller->type));
            return -1;
        }

        if (controller->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI &&
            controller->model != -1 &&
            controller->model != VIR_DOMAIN_CONTROLLER_MODEL_SCSI_AUTO &&
            controller->model != vzCaps->scsiControllerModel) {

                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Unsupported SCSI controller model %s"),
                               virDomainControllerModelSCSITypeToString(controller->model));
                return -1;
        }
    }
    return 0;
}

int vzGetDefaultSCSIModel(vzDriverPtr driver,
                          PRL_CLUSTERED_DEVICE_SUBTYPE *scsiModel)
{
    switch (driver->vzCaps.scsiControllerModel) {
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_SCSI:
        *scsiModel = PCD_VIRTIO_SCSI;
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_BUSLOGIC:
        *scsiModel = PCD_BUSLOGIC;
        break;
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown SCSI controller model %s"),
                       virDomainControllerModelSCSITypeToString(
                           driver->vzCaps.scsiControllerModel));
        return -1;
    }
    return 0;
}

int vzCheckUnsupportedGraphics(virDomainGraphicsDefPtr gr)
{
    if (gr->type != VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("vz driver supports only "
                         "VNC graphics."));
        return -1;
    }

    if (gr->data.vnc.websocket != 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("vz driver doesn't support "
                         "websockets for VNC graphics."));
        return -1;
    }

    if (gr->data.vnc.keymap != 0 &&
        STRNEQ(gr->data.vnc.keymap, "en-us")) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("vz driver supports only "
                         "\"en-us\" keymap for VNC graphics."));
        return -1;
    }

    if (gr->data.vnc.sharePolicy == VIR_DOMAIN_GRAPHICS_VNC_SHARE_ALLOW_EXCLUSIVE) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("vz driver doesn't support "
                         "exclusive share policy for VNC graphics."));
        return -1;
    }

    if (gr->data.vnc.auth.connected == VIR_DOMAIN_GRAPHICS_AUTH_CONNECTED_FAIL ||
        gr->data.vnc.auth.connected == VIR_DOMAIN_GRAPHICS_AUTH_CONNECTED_KEEP) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("vz driver doesn't support "
                         "given action in case of password change."));
        return -1;
    }

    if (gr->data.vnc.auth.expires) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("vz driver doesn't support "
                         "setting password expire time."));
        return -1;
    }

    if (gr->nListens > 1) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("vz driver doesn't support more than "
                         "one listening VNC server per domain"));
        return -1;
    }

    if (gr->nListens == 1 &&
        gr->listens[0].type != VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("vz driver supports only address-based VNC listening"));
        return -1;
    }

    return 0;
}

void*
vzDomObjAlloc(void *opaque ATTRIBUTE_UNUSED)
{
    vzDomObjPtr pdom = NULL;

    if (VIR_ALLOC(pdom) < 0)
        return NULL;

    if (virCondInit(&pdom->job.cond) < 0)
        goto error;

    pdom->stats = PRL_INVALID_HANDLE;

    return pdom;

 error:
    VIR_FREE(pdom);

    return NULL;
}

void
vzDomObjFree(void* p)
{
    vzDomObjPtr pdom = p;

    if (!pdom)
        return;

    PrlHandle_Free(pdom->sdkdom);
    PrlHandle_Free(pdom->stats);
    virCondDestroy(&pdom->job.cond);
    VIR_FREE(pdom);
};

#define VZ_JOB_WAIT_TIME (1000 * 30)

int
vzDomainObjBeginJob(virDomainObjPtr dom)
{
    vzDomObjPtr pdom = dom->privateData;
    unsigned long long now;
    unsigned long long then;

    if (virTimeMillisNow(&now) < 0)
        return -1;
    then = now + VZ_JOB_WAIT_TIME;

    while (pdom->job.active) {
        if (virCondWaitUntil(&pdom->job.cond, &dom->parent.lock, then) < 0)
            goto error;
    }

    if (virTimeMillisNow(&now) < 0)
        return -1;

    pdom->job.active = true;
    pdom->job.started = now;
    pdom->job.elapsed = 0;
    pdom->job.progress = 0;
    pdom->job.hasProgress = false;
    return 0;

 error:
    if (errno == ETIMEDOUT)
        virReportError(VIR_ERR_OPERATION_TIMEOUT,
                       "%s", _("cannot acquire state change lock"));
    else
        virReportSystemError(errno,
                             "%s", _("cannot acquire job mutex"));
    return -1;
}

void
vzDomainObjEndJob(virDomainObjPtr dom)
{
    vzDomObjPtr pdom = dom->privateData;

    pdom->job.active = false;
    pdom->job.cancelled = false;
    virCondSignal(&pdom->job.cond);
}

int
vzDomainJobUpdateTime(vzDomainJobObjPtr job)
{
    unsigned long long now;

    if (!job->started)
        return 0;

    if (virTimeMillisNow(&now) < 0)
        return -1;

    if (now < job->started) {
        VIR_WARN("Async job starts in the future");
        job->started = 0;
        return 0;
    }

    job->elapsed = now - job->started;
    return 0;
}
