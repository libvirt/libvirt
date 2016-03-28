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

virDomainObjPtr
vzNewDomain(vzDriverPtr driver, char *name, const unsigned char *uuid)
{
    virDomainDefPtr def = NULL;
    virDomainObjPtr dom = NULL;
    vzDomObjPtr pdom = NULL;

    if (!(def = virDomainDefNewFull(name, uuid, -1)))
        goto error;

    if (VIR_ALLOC(pdom) < 0)
        goto error;

    if (virCondInit(&pdom->cache.cond) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("cannot initialize condition"));
        goto error;
    }
    pdom->cache.stats = PRL_INVALID_HANDLE;
    pdom->cache.count = -1;

    def->virtType = VIR_DOMAIN_VIRT_VZ;

    if (!(dom = virDomainObjListAdd(driver->domains, def,
                                    driver->xmlopt,
                                    0, NULL)))
        goto error;

    dom->privateData = pdom;
    dom->privateDataFreeFunc = prlsdkDomObjFreePrivate;
    dom->persistent = 1;
    return dom;

 error:
    if (pdom && pdom->cache.count == -1)
        virCondDestroy(&pdom->cache.cond);
    virDomainDefFree(def);
    VIR_FREE(pdom);
    return NULL;
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

    if (disk->serial) {
        VIR_INFO("%s", _("Setting disk serial number is not "
                         "supported by vz driver."));
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

    return 0;
}

int
vzCheckUnsupportedDisks(virDomainDefPtr def, vzCapabilitiesPtr vzCaps)
{
    size_t i, j;
    virDomainDiskDefPtr disk;
    virStorageFileFormat diskFormat;
    bool supported;

    for (i = 0; i < def->ndisks; i++) {
        disk = def->disks[i];

        if (vzCheckDiskUnsupportedParams(disk) < 0)
            return -1;

        diskFormat = virDomainDiskGetFormat(disk);
        supported = true;
        if (disk->src->type == VIR_STORAGE_TYPE_FILE) {
            if (disk->device == VIR_DOMAIN_DISK_DEVICE_DISK &&
                diskFormat != VIR_STORAGE_FILE_NONE) {

                if (IS_CT(def))
                    supported = vzCaps->ctDiskFormat == diskFormat;
                else
                    supported = vzCaps->vmDiskFormat == diskFormat;
            }
        } else {
            if (disk->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
                supported = diskFormat == VIR_STORAGE_FILE_RAW ||
                            diskFormat == VIR_STORAGE_FILE_NONE ||
                            diskFormat == VIR_STORAGE_FILE_AUTO;
            }
        }

        if (!supported) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported format of disk %s"),
                           disk->src->path);
            return -1;
        }
        for (j = 0; vzCaps->diskBuses[j] != VIR_DOMAIN_DISK_BUS_LAST; j++) {
            if (disk->bus == vzCaps->diskBuses[j])
                break;
        }

        if (vzCaps->diskBuses[j] == VIR_DOMAIN_DISK_BUS_LAST) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported disk bus type %s"),
                           virDomainDiskBusTypeToString(disk->bus));
            return -1;
        }
    }
    return 0;
}

int
vzCheckUnsupportedControllers(virDomainDefPtr def, vzCapabilitiesPtr vzCaps)
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
