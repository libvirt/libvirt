
/*
 * esx_vmx.c: VMX related methods for the VMware ESX driver
 *
 * Copyright (C) 2009 Matthias Bolte <matthias.bolte@googlemail.com>
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <config.h>

#include "internal.h"
#include "virterror_internal.h"
#include "memory.h"
#include "logging.h"
#include "esx_util.h"
#include "esx_vmx.h"

/*

mapping:

domain-xml                        <=>   vmx


                                        config.version = "8"                    # essential
                                        virtualHW.version = "4"                 # essential for ESX 3.5
                                        virtualHW.version = "7"                 # essential for ESX 4.0


???                               <=>   guestOS = "<value>"                     # essential, FIXME: not representable
def->id = <value>                 <=>   ???                                     # not representable
def->uuid = <value>               <=>   uuid.bios = "<value>"
def->name = <value>               <=>   displayName = "<value>"
def->maxmem = <value kilobyte>    <=>   memsize = "<value megabyte>"            # must be a multiple of 4, defaults to 32
def->memory = <value kilobyte>    <=>   sched.mem.max = "<value megabyte>"      # defaults to "unlimited" -> def->memory = def->maxmem
def->vcpus = <value>              <=>   numvcpus = "<value>"                    # must be 1 or a multiple of 2, defaults to 1
def->cpumask = <uint list>        <=>   sched.cpu.affinity = "<uint list>"



################################################################################
## os ##########################################################################

def->os

->type = "hvm"
->arch = <arch>                   <=>   guestOS = "<value>"                     # if <value> ends with -64 than <arch> is x86_64, otherwise <arch> is i686
->machine
->nBootDevs
->bootDevs
->init
->kernel
->initrd
->cmdline
->root
->loader
->bootloader
->bootloaderArgs



################################################################################
## disks #######################################################################

                                        scsi[0..3]:[0..6,8..15] -> <controller>:<id>
                                        ide[0..1]:[0..1]        -> <controller>:<id>
                                        floppy[0..1]            -> <controller>

def->disks[0]...

## disks: scsi hard drive from .vmdk image #####################################

                                        scsi0.present = "true"                  # defaults to "false"
                                        scsi0:0.present = "true"                # defaults to "false"
                                        scsi0:0.startConnected = "true"         # defaults to "true"

???                               <=>   scsi0:0.mode = "persistent"             # defaults to "persistent"
                                        scsi0:0.mode = "undoable"
                                        scsi0:0.mode = "independent-persistent"
                                        scsi0:0.mode = "independent-nonpersistent"

...
->type = _DISK_TYPE_FILE          <=>   scsi0:0.deviceType = "scsi-hardDisk"    # defaults to ?
->device = _DISK_DEVICE_DISK      <=>   scsi0:0.deviceType = "scsi-hardDisk"    # defaults to ?
->bus = _DISK_BUS_SCSI
->src = <value>.vmdk              <=>   scsi0:0.fileName = "<value>.vmdk"
->dst = sd[<controller> * 15 + <id> mapped to [a-z]+]
->driverName = <driver>           <=>   scsi0.virtualDev = "<driver>"           # default depends on guestOS value
->driverType
->cachemode                       <=>   scsi0:0.writeThrough = "<value>"        # defaults to false, true -> _DISK_CACHE_WRITETHRU, false _DISK_CACHE_DEFAULT
->readonly
->shared
->slotnum


## disks: ide hard drive from .vmdk image ######################################

                                        ide0:0.present = "true"                 # defaults to "false"
                                        ide0:0.startConnected = "true"          # defaults to "true"

???                               <=>   ide0:0.mode = "persistent"              # defaults to "persistent"
                                        ide0:0.mode = "undoable"
                                        ide0:0.mode = "independent-persistent"
                                        ide0:0.mode = "independent-nonpersistent"

...
->type = _DISK_TYPE_FILE          <=>   ide0:0.deviceType = "ata-hardDisk"      # defaults to ?
->device = _DISK_DEVICE_DISK      <=>   ide0:0.deviceType = "ata-hardDisk"      # defaults to ?
->bus = _DISK_BUS_IDE
->src = <value>.vmdk              <=>   ide0:0.fileName = "<value>.vmdk"
->dst = hd[<controller> * 2 + <id> mapped to [a-z]+]
->driverName
->driverType
->cachemode                       <=>   ide0:0.writeThrough = "<value>"         # defaults to false, true -> _DISK_CACHE_WRITETHRU, false _DISK_CACHE_DEFAULT
->readonly
->shared
->slotnum


## disks: scsi cdrom from .iso image ###########################################

                                        scsi0.present = "true"                  # defaults to "false"
                                        scsi0:0.present = "true"                # defaults to "false"
                                        scsi0:0.startConnected = "true"         # defaults to "true"

...
->type = _DISK_TYPE_FILE          <=>   scsi0:0.deviceType = "cdrom-image"      # defaults to ?
->device = _DISK_DEVICE_CDROM     <=>   scsi0:0.deviceType = "cdrom-image"      # defaults to ?
->bus = _DISK_BUS_SCSI
->src = <value>.iso               <=>   scsi0:0.fileName = "<value>.iso"
->dst = sd[<controller> * 15 + <id> mapped to [a-z]+]
->driverName = <driver>           <=>   scsi0.virtualDev = "<driver>"           # default depends on guestOS value
->driverType
->cachemode
->readonly
->shared
->slotnum


## disks: ide cdrom from .iso image ############################################

                                        ide0:0.present = "true"                 # defaults to "false"
                                        ide0:0.startConnected = "true"          # defaults to "true"

...
->type = _DISK_TYPE_FILE          <=>   ide0:0.deviceType = "cdrom-image"       # defaults to ?
->device = _DISK_DEVICE_CDROM     <=>   ide0:0.deviceType = "cdrom-image"       # defaults to ?
->bus = _DISK_BUS_IDE
->src = <value>.iso               <=>   ide0:0.fileName = "<value>.iso"
->dst = hd[<controller> * 2 + <id> mapped to [a-z]+]
->driverName
->driverType
->cachemode
->readonly
->shared
->slotnum


## disks: scsi cdrom from host device ##########################################

                                        scsi0.present = "true"                  # defaults to "false"
                                        scsi0:0.present = "true"                # defaults to "false"
                                        scsi0:0.startConnected = "true"         # defaults to "true"

...
->type = _DISK_TYPE_BLOCK         <=>   scsi0:0.deviceType = "atapi-cdrom"      # defaults to ?
->device = _DISK_DEVICE_CDROM     <=>   scsi0:0.deviceType = "atapi-cdrom"      # defaults to ?
->bus = _DISK_BUS_SCSI
->src = <value>                   <=>   scsi0:0.fileName = "<value>"            # e.g. "/dev/scd0" ?
->dst = sd[<controller> * 16 + <id> mapped to [a-z]+]
->driverName = <driver>           <=>   scsi0.virtualDev = "<driver>"           # default depends on guestOS value
->driverType
->cachemode
->readonly
->shared
->slotnum


## disks: ide cdrom from host device ###########################################

                                        ide0:0.present = "true"                 # defaults to "false"
                                        ide0:0.startConnected = "true"          # defaults to "true"
                                        ide0:0.clientDevice = "false"           # defaults to "false"

...
->type = _DISK_TYPE_BLOCK         <=>   ide0:0.deviceType = "atapi-cdrom"       # defaults to ?
->device = _DISK_DEVICE_CDROM     <=>   ide0:0.deviceType = "atapi-cdrom"       # defaults to ?
->bus = _DISK_BUS_IDE
->src = <value>                   <=>   ide0:0.fileName = "<value>"             # e.g. "/dev/scd0"
->dst = hd[<controller> * 2 + <id> mapped to [a-z]+]
->driverName
->driverType
->cachemode
->readonly
->shared
->slotnum


## disks: floppy from .flp image ###############################################

                                        floppy0.present = "true"                # defaults to "false"
                                        floppy0.startConnected = "true"         # defaults to "true"
                                        floppy0.clientDevice = "false"          # defaults to "false"

...
->type = _DISK_TYPE_FILE          <=>   floppy0.fileType = "file"               # defaults to ?
->device = _DISK_DEVICE_FLOPPY
->bus = _DISK_BUS_FDC
->src = <value>.flp               <=>   floppy0.fileName = "<value>.flp"
->dst = fd[<controller> mapped to [a-z]+]
->driverName
->driverType
->cachemode
->readonly
->shared
->slotnum


## disks: floppy from host device ##############################################

                                        floppy0.present = "true"                # defaults to "false"
                                        floppy0.startConnected = "true"         # defaults to "true"
                                        floppy0.clientDevice = "false"          # defaults to "false"

...
->type = _DISK_TYPE_BLOCK         <=>   floppy0.fileType = "device"             # defaults to ?
->device = _DISK_DEVICE_FLOPPY
->bus = _DISK_BUS_FDC
->src = <value>                   <=>   floppy0.fileName = "<value>"            # e.g. "/dev/fd0"
->dst = fd[<controller> mapped to [a-z]+]
->driverName
->driverType
->cachemode
->readonly
->shared
->slotnum



################################################################################
## nets ########################################################################

                                        ethernet[0..3] -> <controller>

                                        ethernet0.present = "true"              # defaults to "false"
                                        ethernet0.startConnected = "true"       # defaults to "true"

                                        ethernet0.networkName = "VM Network"    # FIXME

def->nets[0]...
->model = <model>                 <=>   ethernet0.virtualDev = "<model>"        # default depends on guestOS value


                                        ethernet0.addressType = "generated"     # default to "generated"
->mac = <value>                   <=>   ethernet0.generatedAddress = "<value>"
                                        ethernet0.generatedAddressOffset = "0"  # ?


                                        ethernet0.addressType = "static"        # default to "generated"
->mac = <value>                   <=>   ethernet0.address = "<value>"


                                        ethernet0.addressType = "vpx"           # default to "generated"
->mac = <value>                   <=>   ethernet0.generatedAddress = "<value>"


                                        ethernet0.addressType = "static"        # default to "generated"
->mac = <value>                   <=>   ethernet0.address = "<value>"
                                        ethernet0.checkMACAddress = "false"     # mac address outside the VMware prefixes

                                                                                # 00:0c:29 prefix for autogenerated mac's -> ethernet0.addressType = "generated"
                                                                                # 00:50:56 prefix for manual configured mac's
                                                                                #          00:50:56:00:00:00 - 00:50:56:3f:ff:ff -> ethernet0.addressType = "static"
                                                                                #          00:50:56:80:00:00 - 00:50:56:bf:ff:ff -> ethernet0.addressType = "vpx"
                                                                                # 00:05:69 old prefix from esx 1.5


## nets: bridged ###############################################################

...
->type = _NET_TYPE_BRIDGE         <=>   ethernet0.connectionType = "bridged"    # defaults to "bridged"
->data.bridge.brname = <value>    <=>   ethernet0.networkName = "<value>"


## nets: hostonly ##############################################################

...                                                                             # FIXME: Investigate if ESX supports this
->type = _NET_TYPE_NETWORK        <=>   ethernet0.connectionType = "hostonly"   # defaults to "bridged"


## nets: nat ###################################################################

...                                                                             # FIXME: Investigate if ESX supports this
->type = _NET_TYPE_USER           <=>   ethernet0.connectionType = "nat"        # defaults to "bridged"


## nets: custom ################################################################

...
->type = _NET_TYPE_BRIDGE         <=>   ethernet0.connectionType = "custom"     # defaults to "bridged"
->data.bridge.brname = <value>    <=>   ethernet0.networkName = "<value>"
->ifname = <value>                <=>   ethernet0.vnet = "<value>"



################################################################################
## serials #####################################################################

                                        serial[0..3] -> <port>

                                        serial0.present = "true"                # defaults to "false"
                                        serial0.startConnected = "true"         # defaults to "true"

def->serials[0]...
->target.port = <port>


## serials: device #############################################################

->type = _CHR_TYPE_DEV            <=>   serial0.fileType = "device"
->data.file.path = <value>        <=>   serial0.fileName = "<value>"            # e.g. "/dev/ttyS0"
???                               <=>   serial0.tryNoRxLoss = "false"           # defaults to "false", FIXME: not representable
???                               <=>   serial0.yieldOnMsrRead = "true"         # defaults to "false", FIXME: not representable


## serials: file ###############################################################

->type = _CHR_TYPE_FILE           <=>   serial0.fileType = "file"
->data.file.path = <value>        <=>   serial0.fileName = "<value>"            # e.g. "serial0.file"
???                               <=>   serial0.tryNoRxLoss = "false"           # defaults to "false", FIXME: not representable
???                               <=>   serial0.yieldOnMsrRead = "true"         # defaults to "false", FIXME: not representable


## serials: pipe, far end -> app ###############################################

->type = _CHR_TYPE_PIPE           <=>   serial0.fileType = "pipe"
->data.file.path = <value>        <=>   serial0.fileName = "<value>"            # e.g. "serial0.pipe"
???                               <=>   serial0.pipe.endPoint = "client"        # defaults to ?, FIXME: not representable
???                               <=>   serial0.tryNoRxLoss = "true"            # defaults to "false", FIXME: not representable
???                               <=>   serial0.yieldOnMsrRead = "true"         # defaults to "false", FIXME: not representable

->type = _CHR_TYPE_PIPE           <=>   serial0.fileType = "pipe"
->data.file.path = <value>        <=>   serial0.fileName = "<value>"            # e.g. "serial0.pipe"
???                               <=>   serial0.pipe.endPoint = "server"        # defaults to ?, FIXME: not representable
???                               <=>   serial0.tryNoRxLoss = "true"            # defaults to "false", FIXME: not representable
???                               <=>   serial0.yieldOnMsrRead = "true"         # defaults to "false", FIXME: not representable


## serials: pipe, far end -> vm ################################################

->type = _CHR_TYPE_PIPE           <=>   serial0.fileType = "pipe"
->data.file.path = <value>        <=>   serial0.fileName = "<value>"            # e.g. "serial0.pipe"
???                               <=>   serial0.pipe.endPoint = "client"        # defaults to ?, FIXME: not representable
???                               <=>   serial0.tryNoRxLoss = "false"           # defaults to "false", FIXME: not representable
???                               <=>   serial0.yieldOnMsrRead = "true"         # defaults to "false", FIXME: not representable

->type = _CHR_TYPE_PIPE           <=>   serial0.fileType = "pipe"
->data.file.path = <value>        <=>   serial0.fileName = "<value>"            # e.g. "serial0.pipe"
???                               <=>   serial0.pipe.endPoint = "server"        # defaults to ?, FIXME: not representable
???                               <=>   serial0.tryNoRxLoss = "false"           # defaults to "false", FIXME: not representable
???                               <=>   serial0.yieldOnMsrRead = "true"         # defaults to "false", FIXME: not representable



################################################################################
## parallels ###################################################################

                                        parallel[0..2] -> <port>

                                        parallel0.present = "true"              # defaults to "false"
                                        parallel0.startConnected = "true"       # defaults to "true"

def->parallels[0]...
->target.port = <port>


## parallels: device #############################################################

->type = _CHR_TYPE_DEV            <=>   parallel0.fileType = "device"
->data.file.path = <value>        <=>   parallel0.fileName = "<value>"          # e.g. "/dev/parport0"
???                               <=>   parallel0.bidirectional = "<value>"     # defaults to ?, FIXME: not representable


## parallels: file #############################################################

->type = _CHR_TYPE_FILE           <=>   parallel0.fileType = "file"
->data.file.path = <value>        <=>   parallel0.fileName = "<value>"          # e.g. "parallel0.file"
???                               <=>   parallel0.bidirectional = "<value>"     # must be "false" for fileType = "file", FIXME: not representable



################################################################################
## sound #######################################################################

                                        sound.present = "true"                  # defaults to "false"
                                        sound.startConnected = "true"           # defaults to "true"
                                        sound.autodetect = "true"
                                        sound.fileName = "-1"

                                        FIXME: Investigate if ESX supports this,
                                               at least the VI Client GUI has no
                                               options to add a sound device, but
                                               the VI API contains a VirtualSoundCard

*/

#define VIR_FROM_THIS VIR_FROM_ESX

#define ESX_ERROR(code, fmt...)                                               \
    virReportErrorHelper(NULL, VIR_FROM_ESX, code, __FILE__, __FUNCTION__,    \
                         __LINE__, fmt)



#define ESX_BUILD_VMX_NAME(_suffix)                                           \
    snprintf(_suffix##_name, sizeof(_suffix##_name), "%s."#_suffix, prefix);



int
esxVMX_SCSIDiskNameToControllerAndID(const char *name, int *controller, int *id)
{
    int idx;

    if (! STRPREFIX(name, "sd")) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Expecting domain XML attribute 'dev' of entry "
                  "'devices/disk/target' to start with 'sd'");
        return -1;
    }

    idx = virDiskNameToIndex(name);

    if (idx < 0) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Could not parse valid disk index from '%s'", name);
        return -1;
    }

    /* Each of the 4 SCSI controllers offers 15 IDs for devices */
    if (idx >= (4 * 15)) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "SCSI disk index (parsed from '%s') is too large", name);
        return -1;
    }

    *controller = idx / 15;
    *id = idx % 15;

    /* Skip the controller ifself with ID 7 */
    if (*id >= 7) {
        ++(*id);
    }

    return 0;
}



int
esxVMX_IDEDiskNameToControllerAndID(const char *name, int *controller, int *id)
{
    int idx;

    if (! STRPREFIX(name, "hd")) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Expecting domain XML attribute 'dev' of entry "
                  "'devices/disk/target' to start with 'hd'");
        return -1;
    }

    idx = virDiskNameToIndex(name);

    if (idx < 0) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Could not parse valid disk index from '%s'", name);
        return -1;
    }

    /* Each of the 2 IDE controllers offers 2 IDs for devices */
    if (idx >= (2 * 2)) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "IDE disk index (parsed from '%s') is too large", name);
        return -1;
    }

    *controller = idx / 2;
    *id = idx % 2;

    return 0;
}



int
esxVMX_FloppyDiskNameToController(const char *name, int *controller)
{
    int idx;

    if (! STRPREFIX(name, "fd")) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Expecting domain XML attribute 'dev' of entry "
                  "'devices/disk/target' to start with 'fd'");
        return -1;
    }

    idx = virDiskNameToIndex(name);

    if (idx < 0) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Could not parse valid disk index from '%s'", name);
        return -1;
    }

    if (idx >= 2) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Floppy disk index (parsed from '%s') is too large", name);
        return -1;
    }

    *controller = idx;

    return 0;
}



int
esxVMX_GatherSCSIControllers(virDomainDefPtr def, char *virtualDev[4],
                             int present[4])
{
    virDomainDiskDefPtr disk;
    int i, controller, id;

    /* Check for continuous use of the same virtualDev per SCSI controller */
    for (i = 0; i < def->ndisks; ++i) {
        disk = def->disks[i];

        if (disk->bus != VIR_DOMAIN_DISK_BUS_SCSI) {
            continue;
        }

        if (disk->driverName != NULL &&
            STRCASENEQ(disk->driverName, "buslogic") &&
            STRCASENEQ(disk->driverName, "lsilogic")) {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      "Expecting domain XML entry 'devices/disk/target' to be "
                      "'buslogic' or 'lsilogic' but found '%s'",
                      disk->driverName);
            return -1;
        }

        if (esxVMX_SCSIDiskNameToControllerAndID(disk->dst, &controller,
                                                 &id) < 0) {
            return -1;
        }

        present[controller] = 1;

        if (virtualDev[controller] == NULL) {
            virtualDev[controller] = disk->driverName;
        } else if (STRCASENEQ(virtualDev[controller], disk->driverName)) {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      "Inconsistent driver usage ('%s' is not '%s') on SCSI "
                      "controller index %d", virtualDev[controller],
                      disk->driverName, controller);
            return -1;
        }
    }

    return 0;
}



char *
esxVMX_AbsolutePathToDatastoreRelatedPath(esxVI_Context *ctx,
                                          const char *absolutePath)
{
    char *datastoreRelatedPath = NULL;
    char *preliminaryDatastoreName = NULL;
    char *directoryAndFileName = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_ObjectContent *datastore = NULL;
    const char *datastoreName = NULL;

    if (sscanf(absolutePath, "/vmfs/volumes/%a[^/]/%a[^\n]",
               &preliminaryDatastoreName, &directoryAndFileName) != 2) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Absolute path '%s' doesn't have expected format "
                  "'/vmfs/volumes/<datastore>/<path>'", absolutePath);
        goto failure;
    }

    if (ctx != NULL) {
        if (esxVI_LookupDatastoreByName(ctx, preliminaryDatastoreName,
                                        NULL, &datastore,
                                        esxVI_Occurrence_OptionalItem) < 0) {
            goto failure;
        }

        if (datastore != NULL) {
            for (dynamicProperty = datastore->propSet; dynamicProperty != NULL;
                 dynamicProperty = dynamicProperty->_next) {
                if (STREQ(dynamicProperty->name, "summary.accessible")) {
                    /* Ignore it */
                } else if (STREQ(dynamicProperty->name, "summary.name")) {
                    if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                                 esxVI_Type_String) < 0) {
                        goto failure;
                    }

                    datastoreName = dynamicProperty->val->string;
                    break;
                } else if (STREQ(dynamicProperty->name, "summary.url")) {
                    /* Ignore it */
                } else {
                    VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
                }
            }
        }

        if (datastoreName == NULL) {
            VIR_WARN("Could not retrieve datastore name for absolute "
                     "path '%s', falling back to preliminary name '%s'",
                     absolutePath, preliminaryDatastoreName);

            datastoreName = preliminaryDatastoreName;
        }
    } else {
        datastoreName = preliminaryDatastoreName;
    }

    if (virAsprintf(&datastoreRelatedPath, "[%s] %s", datastoreName,
                    directoryAndFileName) < 0) {
        virReportOOMError(NULL);
        goto failure;
    }

    /* FIXME: Check if referenced path/file really exists */

  cleanup:
    VIR_FREE(preliminaryDatastoreName);
    VIR_FREE(directoryAndFileName);
    esxVI_ObjectContent_Free(&datastore);

    return datastoreRelatedPath;

  failure:
    VIR_FREE(datastoreRelatedPath);

    goto cleanup;
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VMX -> Domain XML
 */

char *
esxVMX_ParseFileName(esxVI_Context *ctx, const char *fileName,
                     const char *datastoreName, const char *directoryName)
{
    char *src = NULL;

    if (STRPREFIX(fileName, "/vmfs/volumes/")) {
        /* Found absolute path referencing a file inside a datastore */
        return esxVMX_AbsolutePathToDatastoreRelatedPath(ctx, fileName);
    } else if (STRPREFIX(fileName, "/")) {
        /* Found absolute path referencing a file outside a datastore */
        src = strdup(fileName);

        if (src == NULL) {
            virReportOOMError(NULL);
            return NULL;
        }

        /* FIXME: Check if referenced path/file really exists */

        return src;
    } else if (strchr(fileName, '/') != NULL) {
        /* Found relative path, this is not supported */
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Found relative path '%s' in VMX file, this is not "
                  "supported", fileName);
        return NULL;
    } else {
        /* Found single file name referencing a file inside a datastore */
        if (virAsprintf(&src, "[%s] %s/%s", datastoreName, directoryName,
                        fileName) < 0) {
            virReportOOMError(NULL);
            return NULL;
        }

        /* FIXME: Check if referenced path/file really exists */

        return src;
    }
}



virDomainDefPtr
esxVMX_ParseConfig(esxVI_Context *ctx, const char *vmx,
                   const char *datastoreName, const char *directoryName,
                   esxVI_APIVersion apiVersion)
{
    virConfPtr conf = NULL;
    virDomainDefPtr def = NULL;
    long long config_version = 0;
    long long virtualHW_version = 0;
    long long memsize = 0;
    long long memory = 0;
    long long numvcpus = 0;
    char *sched_cpu_affinity = NULL;
    char *guestOS = NULL;
    int controller;
    int port;
    int present; // boolean
    char *scsi_virtualDev = NULL;
    int id;

    conf = virConfReadMem(vmx, strlen(vmx), VIR_CONF_FLAG_VMX_FORMAT);

    if (conf == NULL) {
        return NULL;
    }

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError(NULL);
        goto failure;
    }

    def->virtType = VIR_DOMAIN_VIRT_VMWARE; /* FIXME: maybe add VIR_DOMAIN_VIRT_ESX ? */
    def->id = -1;

    /* vmx:config.version */
    if (esxUtil_GetConfigLong(conf, "config.version", &config_version, 0,
                              0) < 0) {
        goto failure;
    }

    if (config_version != 8) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Expecting VMX entry 'config.version' to be 8 but found "
                  "%lld", config_version);
        goto failure;
    }

    /* vmx:virtualHW.version */
    if (esxUtil_GetConfigLong(conf, "virtualHW.version", &virtualHW_version, 0,
                              0) < 0) {
        goto failure;
    }

    switch (apiVersion) {
      case esxVI_APIVersion_25:
        if (virtualHW_version != 4) {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      "Expecting VMX entry 'virtualHW.version' to be 4 for "
                      "VI API version 2.5 but found %lld", virtualHW_version);
            goto failure;
        }

        break;

      case esxVI_APIVersion_40:
        if (virtualHW_version != 4 && virtualHW_version != 7) {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      "Expecting VMX entry 'virtualHW.version' to be 4 or 7 for "
                      "VI API version 4.0 but found %lld", virtualHW_version);
            goto failure;
        }

        break;

      case esxVI_APIVersion_Unknown:
        if (virtualHW_version != 4 && virtualHW_version != 7) {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      "Expecting VMX entry 'virtualHW.version' to be 4 or 7 "
                      "but found %lld", virtualHW_version);
            goto failure;
        }

        break;

      default:
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Expecting VI API version 2.5 or 4.0");
        goto failure;
    }

    /* vmx:uuid.bios -> def:uuid */
    /* FIXME: Need to handle 'uuid.action = "create"' */
    if (esxUtil_GetConfigUUID(conf, "uuid.bios", def->uuid, 1) < 0) {
        goto failure;
    }

    /* vmx:displayName -> def:name */
    if (esxUtil_GetConfigString(conf, "displayName", &def->name, 1) < 0) {
        goto failure;
    }

    /* vmx:memsize -> def:maxmem */
    if (esxUtil_GetConfigLong(conf, "memsize", &memsize, 32, 1) < 0) {
        goto failure;
    }

    if (memsize <= 0 || memsize % 4 != 0) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Expecting VMX entry 'memsize' to be an unsigned "
                  "integer (multiple of 4) but found %lld", memsize);
        goto failure;
    }

    def->maxmem = memsize * 1024; /* Scale from megabytes to kilobytes */

    /* vmx:sched.mem.max -> def:memory */
    if (esxUtil_GetConfigLong(conf, "sched.mem.max", &memory, memsize, 1) < 0) {
        goto failure;
    }

    if (memory < 0) {
        memory = memsize;
    }

    def->memory = memory * 1024; /* Scale from megabytes to kilobytes */

    if (def->memory > def->maxmem) {
        def->memory = def->maxmem;
    }

    /* vmx:numvcpus -> def:vcpus */
    if (esxUtil_GetConfigLong(conf, "numvcpus", &numvcpus, 1, 1) < 0) {
        goto failure;
    }

    if (numvcpus <= 0 || (numvcpus % 2 != 0 && numvcpus != 1)) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Expecting VMX entry 'numvcpus' to be an unsigned "
                  "integer (1 or a multiple of 2) but found %lld", numvcpus);
        goto failure;
    }

    def->vcpus = numvcpus;

    /* vmx:sched.cpu.affinity -> def:cpumask */
    // VirtualMachine:config.cpuAffinity.affinitySet
    if (esxUtil_GetConfigString(conf, "sched.cpu.affinity", &sched_cpu_affinity,
                                1) < 0) {
        goto failure;
    }

    if (sched_cpu_affinity != NULL && STRNEQ(sched_cpu_affinity, "all")) {
        const char *current = sched_cpu_affinity;
        int number, count = 0;

        def->cpumasklen = 0;

        if (VIR_ALLOC_N(def->cpumask, VIR_DOMAIN_CPUMASK_LEN) < 0) {
            virReportOOMError(NULL);
            goto failure;
        }

        while (*current != '\0') {
            virSkipSpaces(&current);

            number = virParseNumber(&current);

            if (number < 0) {
                ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                          "Expecting VMX entry 'sched.cpu.affinity' to be "
                          "a comma separated list of unsigned integers but "
                          "found '%s'", sched_cpu_affinity);
                goto failure;
            }

            if (number >= VIR_DOMAIN_CPUMASK_LEN) {
                ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                          "VMX entry 'sched.cpu.affinity' contains a %d, this "
                          "value is too large", number);
                goto failure;
            }

            if (number + 1 > def->cpumasklen) {
                def->cpumasklen = number + 1;
            }

            def->cpumask[number] = 1;
            ++count;

            virSkipSpaces(&current);

            if (*current == ',') {
                ++current;
            } else if (*current == '\0') {
                break;
            } else {
                ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                          "Expecting VMX entry 'sched.cpu.affinity' to be "
                          "a comma separated list of unsigned integers but "
                          "found '%s'", sched_cpu_affinity);
                goto failure;
            }

            virSkipSpaces(&current);
        }

        if (count < numvcpus) {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      "Expecting VMX entry 'sched.cpu.affinity' to contain "
                      "at least as many values as 'numvcpus' (%lld) but "
                      "found only %d value(s)", numvcpus, count);
            goto failure;
        }
    }

    /* def:lifecycle */
    def->onReboot = VIR_DOMAIN_LIFECYCLE_RESTART;
    def->onPoweroff = VIR_DOMAIN_LIFECYCLE_DESTROY;
    def->onCrash = VIR_DOMAIN_LIFECYCLE_DESTROY;

    /* def:os */
    def->os.type = strdup("hvm");

    if (def->os.type == NULL) {
        virReportOOMError(NULL);
        goto failure;
    }

    /* vmx:guestOS -> def:os.arch */
    if (esxUtil_GetConfigString(conf, "guestOS", &guestOS, 1) < 0) {
        goto failure;
    }

    if (guestOS != NULL && virFileHasSuffix(guestOS, "-64")) {
        def->os.arch = strdup("x86_64");
    } else {
        def->os.arch = strdup("i686");
    }

    if (def->os.arch == NULL) {
        virReportOOMError(NULL);
        goto failure;
    }

/*
    def->emulator
    def->features*/

/*
    def->localtime*/

    /* def:graphics */
    if (VIR_ALLOC_N(def->graphics, 1) < 0) {
        virReportOOMError(NULL);
        goto failure;
    }

    def->ngraphics = 0;

    if (esxVMX_ParseVNC(conf, &def->graphics[def->ngraphics]) < 0) {
        goto failure;
    }

    if (def->graphics[def->ngraphics] != NULL) {
        ++def->ngraphics;
    }

    /* def:disks: 4 * 15 scsi + 2 * 2 ide + 2 floppy = 66 */
    if (VIR_ALLOC_N(def->disks, 66) < 0) {
        virReportOOMError(NULL);
        goto failure;
    }

    def->ndisks = 0;

    /* def:disks (scsi) */
    for (controller = 0; controller < 4; ++controller) {
        VIR_FREE(scsi_virtualDev);

        if (esxVMX_ParseSCSIController(conf, controller, &present,
                                       &scsi_virtualDev) < 0) {
            goto failure;
        }

        if (! present) {
            continue;
        }

        for (id = 0; id < 16; ++id) {
            if (id == 7) {
                /*
                 * SCSI ID 7 is assigned to the SCSI controller and cannot be
                 * used for disk devices.
                 */
                continue;
            }

            if (esxVMX_ParseDisk(ctx, conf, VIR_DOMAIN_DISK_DEVICE_DISK,
                                 VIR_DOMAIN_DISK_BUS_SCSI, controller, id,
                                 scsi_virtualDev, datastoreName, directoryName,
                                 &def->disks[def->ndisks]) < 0) {
                goto failure;
            }

            if (def->disks[def->ndisks] != NULL) {
                ++def->ndisks;
                continue;
            }

            if (esxVMX_ParseDisk(ctx, conf, VIR_DOMAIN_DISK_DEVICE_CDROM,
                                 VIR_DOMAIN_DISK_BUS_SCSI, controller, id,
                                 scsi_virtualDev, datastoreName, directoryName,
                                 &def->disks[def->ndisks]) < 0) {
                goto failure;
            }

            if (def->disks[def->ndisks] != NULL) {
                ++def->ndisks;
            }
        }
    }

    /* def:disks (ide) */
    for (controller = 0; controller < 2; ++controller) {
        for (id = 0; id < 2; ++id) {
            if (esxVMX_ParseDisk(ctx, conf, VIR_DOMAIN_DISK_DEVICE_DISK,
                                 VIR_DOMAIN_DISK_BUS_IDE, controller, id,
                                 NULL, datastoreName, directoryName,
                                 &def->disks[def->ndisks]) < 0) {
                goto failure;
            }

            if (def->disks[def->ndisks] != NULL) {
                ++def->ndisks;
                continue;
            }

            if (esxVMX_ParseDisk(ctx, conf, VIR_DOMAIN_DISK_DEVICE_CDROM,
                                 VIR_DOMAIN_DISK_BUS_IDE, controller, id,
                                 NULL, datastoreName, directoryName,
                                 &def->disks[def->ndisks]) < 0) {
                goto failure;
            }

            if (def->disks[def->ndisks] != NULL) {
                ++def->ndisks;
            }
        }
    }

    /* def:disks (floppy) */
    for (controller = 0; controller < 2; ++controller) {
        if (esxVMX_ParseDisk(ctx, conf, VIR_DOMAIN_DISK_DEVICE_FLOPPY,
                             VIR_DOMAIN_DISK_BUS_FDC, controller, -1, NULL,
                             datastoreName, directoryName,
                             &def->disks[def->ndisks]) < 0) {
            goto failure;
        }

        if (def->disks[def->ndisks] != NULL) {
            ++def->ndisks;
        }
    }

    /* def:fss */
    /* FIXME */

    /* def:nets */
    if (VIR_ALLOC_N(def->nets, 4) < 0) {
        virReportOOMError(NULL);
        goto failure;
    }

    def->nnets = 0;

    for (controller = 0; controller < 4; ++controller) {
        if (esxVMX_ParseEthernet(conf, controller,
                                 &def->nets[def->nnets]) < 0) {
            goto failure;
        }

        if (def->nets[def->nnets] != NULL) {
            ++def->nnets;
        }
    }

    /* def:inputs */
    /* FIXME */

    /* def:sounds */
    /* FIXME */

    /* def:hostdevs */
    /* FIXME */

    /* def:serials */
    if (VIR_ALLOC_N(def->serials, 4) < 0) {
        virReportOOMError(NULL);
        goto failure;
    }

    def->nserials = 0;

    for (port = 0; port < 4; ++port) {
        if (esxVMX_ParseSerial(ctx, conf, port, datastoreName,
                               directoryName,
                               &def->serials[def->nserials]) < 0) {
            goto failure;
        }

        if (def->serials[def->nserials] != NULL) {
            ++def->nserials;
        }
    }

    /* def:parallels */
    if (VIR_ALLOC_N(def->parallels, 3) < 0) {
        virReportOOMError(NULL);
        goto failure;
    }

    def->nparallels = 0;

    for (port = 0; port < 3; ++port) {
        if (esxVMX_ParseParallel(ctx, conf, port, datastoreName,
                                 directoryName,
                                 &def->parallels[def->nparallels]) < 0) {
            goto failure;
        }

        if (def->parallels[def->nparallels] != NULL) {
            ++def->nparallels;
        }
    }

  cleanup:
    virConfFree(conf);
    VIR_FREE(sched_cpu_affinity);
    VIR_FREE(guestOS);
    VIR_FREE(scsi_virtualDev);

    return def;

  failure:
    virDomainDefFree(def);
    def = NULL;

    goto cleanup;
}



int
esxVMX_ParseVNC(virConfPtr conf, virDomainGraphicsDefPtr *def)
{
    int enabled = 0; // boolean
    long long port = 0;

    if (def == NULL || *def != NULL) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (esxUtil_GetConfigBoolean(conf, "RemoteDisplay.vnc.enabled", &enabled,
                                 0, 1) < 0) {
        return -1;
    }

    if (! enabled) {
        return 0;
    }

    if (VIR_ALLOC(*def) < 0) {
        virReportOOMError(NULL);
        goto failure;
    }

    (*def)->type = VIR_DOMAIN_GRAPHICS_TYPE_VNC;

    if (esxUtil_GetConfigLong(conf, "RemoteDisplay.vnc.port", &port, -1,
                               1) < 0 ||
        esxUtil_GetConfigString(conf, "RemoteDisplay.vnc.ip",
                                &(*def)->data.vnc.listenAddr, 1) < 0 ||
        esxUtil_GetConfigString(conf, "RemoteDisplay.vnc.keymap",
                                &(*def)->data.vnc.keymap, 1) < 0 ||
        esxUtil_GetConfigString(conf, "RemoteDisplay.vnc.password",
                                &(*def)->data.vnc.passwd, 1) < 0) {
        goto failure;
    }

    if (port < 0) {
        VIR_WARN0("VNC is enabled but VMX entry 'RemoteDisplay.vnc.port' "
                  "is missing, the VNC port is unknown");

        (*def)->data.vnc.port = 0;
        (*def)->data.vnc.autoport = 1;
    } else {
        if (port < 5900 || port > 5964) {
            VIR_WARN("VNC port %lld it out of [5900..5964] range", port);
        }

        (*def)->data.vnc.port = port;
        (*def)->data.vnc.autoport = 0;
    }

    return 0;

  failure:
    virDomainGraphicsDefFree(*def);
    *def = NULL;

    return -1;
}



int
esxVMX_ParseSCSIController(virConfPtr conf, int controller, int *present,
                           char **virtualDev)
{
    char present_name[32];
    char virtualDev_name[32];

    if (virtualDev == NULL || *virtualDev != NULL) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (controller < 0 || controller > 3) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "SCSI controller index %d out of [0..3] range",
                  controller);
        return -1;
    }

    snprintf(present_name, sizeof(present_name), "scsi%d.present", controller);
    snprintf(virtualDev_name, sizeof(virtualDev_name), "scsi%d.virtualDev",
             controller);

    if (esxUtil_GetConfigBoolean(conf, present_name, present, 0, 1) < 0) {
        goto failure;
    }

    if (! *present) {
        return 0;
    }

    if (esxUtil_GetConfigString(conf, virtualDev_name, virtualDev, 1) < 0) {
        goto failure;
    }

    if (*virtualDev != NULL &&
        STRCASENEQ(*virtualDev, "buslogic") &&
        STRCASENEQ(*virtualDev, "lsilogic")) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Expecting VMX entry '%s' to be 'buslogic' or 'lsilogic' "
                  "but found '%s'", virtualDev_name, *virtualDev);
        goto failure;
    }

    return 0;

  failure:
    VIR_FREE(*virtualDev);

    return -1;
}



/*
struct _virDomainDiskDef {
    int type;               // partly done
    int device;             // done
    int bus;                // done
    char *src;              // done
    char *dst;              // done
    char *driverName;       // done
    char *driverType;
    int cachemode;          // done
    unsigned int readonly : 1;
    unsigned int shared : 1;
    int slotnum;
};*/

int
esxVMX_ParseDisk(esxVI_Context *ctx, virConfPtr conf, int device, int bus,
                 int controller, int id, const char *virtualDev,
                 const char *datastoreName, const char *directoryName,
                 virDomainDiskDefPtr *def)
{
    /*
     *     device = {VIR_DOMAIN_DISK_DEVICE_DISK, VIR_DOMAIN_DISK_DEVICE_CDROM}
     *        bus = VIR_DOMAIN_DISK_BUS_SCSI
     * controller = [0..3]
     *         id = [0..6,8..15]
     * virtualDev = {'buslogic', 'lsilogic'}
     *
     *     device = {VIR_DOMAIN_DISK_DEVICE_DISK, VIR_DOMAIN_DISK_DEVICE_CDROM}
     *        bus = VIR_DOMAIN_DISK_BUS_IDE
     * controller = [0..1]
     *         id = [0..1]
     * virtualDev = NULL
     *
     *     device = VIR_DOMAIN_DISK_DEVICE_FLOPPY
     *        bus = VIR_DOMAIN_DISK_BUS_FDC
     * controller = [0..1]
     *         id = -1
     * virtualDev = NULL
     */

    int result = 0;
    char *prefix = NULL;

    char present_name[32] = "";
    int present = 0;

    char startConnected_name[32] = "";
    int startConnected = 0;

    char deviceType_name[32] = "";
    char *deviceType = NULL;

    char clientDevice_name[32] = "";
    int clientDevice = 0;

    char fileType_name[32] = "";
    char *fileType = NULL;

    char fileName_name[32] = "";
    char *fileName = NULL;

    char writeThrough_name[32] = "";
    int writeThrough = 0;

    if (def == NULL || *def != NULL) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (VIR_ALLOC(*def) < 0) {
        virReportOOMError(NULL);
        goto failure;
    }

    (*def)->device = device;
    (*def)->bus = bus;

    /* def:dst, def:driverName */
    if (device == VIR_DOMAIN_DISK_DEVICE_DISK ||
        device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
        if (bus == VIR_DOMAIN_DISK_BUS_SCSI) {
            if (controller < 0 || controller > 3) {
                ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                          "SCSI controller index %d out of [0..3] range",
                          controller);
                goto failure;
            }

            if (id < 0 || id > 15 || id == 7) {
                ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                          "SCSI ID %d out of [0..6,8..15] range", id);
                goto failure;
            }

            if (virAsprintf(&prefix, "scsi%d:%d", controller, id) < 0) {
                virReportOOMError(NULL);
                goto failure;
            }

            (*def)->dst =
               virIndexToDiskName
                 (controller * 15 + (id < 7 ? id : id - 1), "sd");

            if ((*def)->dst == NULL) {
                goto failure;
            }

            if (virtualDev != NULL) {
                (*def)->driverName = strdup(virtualDev);

                if ((*def)->driverName == NULL) {
                    virReportOOMError(NULL);
                    goto failure;
                }
            }
        } else if (bus == VIR_DOMAIN_DISK_BUS_IDE) {
            if (controller < 0 || controller > 1) {
                ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                          "IDE controller index %d out of [0..1] range",
                          controller);
                goto failure;
            }

            if (id < 0 || id > 1) {
                ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                          "IDE ID %d out of [0..1] range", id);
                goto failure;
            }

            if (virAsprintf(&prefix, "ide%d:%d", controller, id) < 0) {
                virReportOOMError(NULL);
                goto failure;
            }

            (*def)->dst = virIndexToDiskName(controller * 2 + id, "hd");

            if ((*def)->dst == NULL) {
                goto failure;
            }
        } else {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      "Unsupported bus type '%s' for device type '%s'",
                      virDomainDiskBusTypeToString(bus),
                      virDomainDiskDeviceTypeToString(device));
            goto failure;
        }
    } else if (device == VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
        if (bus == VIR_DOMAIN_DISK_BUS_FDC) {
            if (controller < 0 || controller > 1) {
                ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                          "Floppy controller index %d out of [0..1] range",
                          controller);
                goto failure;
            }

            if (virAsprintf(&prefix, "floppy%d", controller) < 0) {
                virReportOOMError(NULL);
                goto failure;
            }

            (*def)->dst = virIndexToDiskName(controller, "fd");

            if ((*def)->dst == NULL) {
                goto failure;
            }
        } else {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      "Unsupported bus type '%s' for device type '%s'",
                      virDomainDiskBusTypeToString(bus),
                      virDomainDiskDeviceTypeToString(device));
            goto failure;
        }
    } else {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Unsupported device type '%s'",
                  virDomainDiskDeviceTypeToString(device));
        goto failure;
    }

    ESX_BUILD_VMX_NAME(present);
    ESX_BUILD_VMX_NAME(startConnected);
    ESX_BUILD_VMX_NAME(deviceType);
    ESX_BUILD_VMX_NAME(clientDevice);
    ESX_BUILD_VMX_NAME(fileType);
    ESX_BUILD_VMX_NAME(fileName);
    ESX_BUILD_VMX_NAME(writeThrough);

    /* vmx:present */
    if (esxUtil_GetConfigBoolean(conf, present_name, &present, 0, 1) < 0) {
        goto failure;
    }

    /* vmx:startConnected */
    if (esxUtil_GetConfigBoolean(conf, startConnected_name, &startConnected,
                                 1, 1) < 0) {
        goto failure;
    }

    /* FIXME: Need to distiguish between active and inactive domains here */
    if (! present/* && ! startConnected*/) {
        goto ignore;
    }

    /* vmx:deviceType -> def:type */
    if (esxUtil_GetConfigString(conf, deviceType_name, &deviceType, 1) < 0) {
        goto failure;
    }

    /* vmx:clientDevice */
    if (esxUtil_GetConfigBoolean(conf, clientDevice_name, &clientDevice, 0,
                                 1) < 0) {
        goto failure;
    }

    if (clientDevice) {
        /*
         * Just ignore devices in client mode, because I have no clue how to
         * handle them (e.g. assign an image) without the VI Client GUI.
         */
        goto ignore;
    }

    /* vmx:fileType -> def:type */
    if (esxUtil_GetConfigString(conf, fileType_name, &fileType, 1) < 0) {
        goto failure;
    }

    /* vmx:fileName -> def:src, def:type */
    if (esxUtil_GetConfigString(conf, fileName_name, &fileName, 0) < 0) {
        goto failure;
    }

    /* vmx:writeThrough -> def:cachemode */
    if (esxUtil_GetConfigBoolean(conf, writeThrough_name, &writeThrough, 0,
                                 1) < 0) {
        goto failure;
    }

    /* Setup virDomainDiskDef */
    if (device == VIR_DOMAIN_DISK_DEVICE_DISK) {
        if (virFileHasSuffix(fileName, ".vmdk")) {
            if (deviceType != NULL) {
                if (bus == VIR_DOMAIN_DISK_BUS_SCSI &&
                    STRCASENEQ(deviceType, "scsi-hardDisk")) {
                    ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                              "Expecting VMX entry '%s' to be 'scsi-hardDisk' "
                              "but found '%s'", deviceType_name, deviceType);
                    goto failure;
                } else if (bus == VIR_DOMAIN_DISK_BUS_IDE &&
                           STRCASENEQ(deviceType, "ata-hardDisk")) {
                    ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                              "Expecting VMX entry '%s' to be 'ata-hardDisk' "
                              "but found '%s'", deviceType_name, deviceType);
                    goto failure;
                }
            }

            if (writeThrough && virtualDev == NULL) {
                /*
                 * FIXME: If no virtualDev is explicit specified need to get
                 *        the default based on the guestOS. The mechanism to
                 *        obtain the default is currently missing
                 */
                VIR_WARN0("No explicit SCSI driver specified in VMX config, "
                          "cannot represent explicit specified cachemode");
            }

            (*def)->type = VIR_DOMAIN_DISK_TYPE_FILE;
            (*def)->src = esxVMX_ParseFileName(ctx, fileName, datastoreName,
                                               directoryName);
            (*def)->cachemode = writeThrough ? VIR_DOMAIN_DISK_CACHE_WRITETHRU
                                             : VIR_DOMAIN_DISK_CACHE_DEFAULT;

            if ((*def)->src == NULL) {
                goto failure;
            }
        } else if (virFileHasSuffix(fileName, ".iso") ||
                   STREQ(deviceType, "atapi-cdrom")) {
            /*
             * This function was called in order to parse a harddisk device,
             * but .iso files and 'atapi-cdrom' devices are for CDROM devices
             * only. Just ignore it, another call to this function to parse a
             * CDROM device may handle it.
             */
            goto ignore;
        } else {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      "Invalid or not yet handled value '%s' for VMX entry "
                      "'%s'", fileName, fileName_name);
            goto failure;
        }
    } else if (device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
        if (virFileHasSuffix(fileName, ".iso")) {
            if (deviceType != NULL) {
                if (STRCASENEQ(deviceType, "cdrom-image")) {
                    ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                              "Expecting VMX entry '%s' to be 'cdrom-image' "
                              "but found '%s'", deviceType_name, deviceType);
                    goto failure;
                }
            }

            (*def)->type = VIR_DOMAIN_DISK_TYPE_FILE;
            (*def)->src = esxVMX_ParseFileName(ctx, fileName, datastoreName,
                                               directoryName);

            if ((*def)->src == NULL) {
                goto failure;
            }
        } else if (virFileHasSuffix(fileName, ".vmdk")) {
            /*
             * This function was called in order to parse a CDROM device, but
             * .vmdk files are for harddisk devices only. Just ignore it,
             * another call to this function to parse a harddisk device may
             * handle it.
             */
            goto ignore;
        } else if (STREQ(deviceType, "atapi-cdrom")) {
            (*def)->type = VIR_DOMAIN_DISK_TYPE_BLOCK;
            (*def)->src = fileName;

            fileName = NULL;
        } else {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      "Invalid or not yet handled value '%s' for VMX entry "
                      "'%s'", fileName, fileName_name);
            goto failure;
        }
    } else if (device == VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
        if (virFileHasSuffix(fileName, ".flp")) {
            if (fileType != NULL) {
                if (STRCASENEQ(fileType, "file")) {
                    ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                              "Expecting VMX entry '%s' to be 'file' but "
                              "found '%s'", fileType_name, fileType);
                    goto failure;
                }
            }

            (*def)->type = VIR_DOMAIN_DISK_TYPE_FILE;
            (*def)->src = esxVMX_ParseFileName(ctx, fileName, datastoreName,
                                               directoryName);

            if ((*def)->src == NULL) {
                goto failure;
            }
        } else if (fileType != NULL && STREQ(fileType, "device")) {
            (*def)->type = VIR_DOMAIN_DISK_TYPE_BLOCK;
            (*def)->src = fileName;

            fileName = NULL;
        } else {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      "Invalid or not yet handled value '%s' for VMX entry "
                      "'%s'", fileName, fileName_name);
            goto failure;
        }
    } else {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "Unsupported device type '%s'",
                  virDomainDiskDeviceTypeToString(device));
        goto failure;
    }

  cleanup:
    VIR_FREE(prefix);
    VIR_FREE(deviceType);
    VIR_FREE(fileType);
    VIR_FREE(fileName);

    return result;

  failure:
    result = -1;

  ignore:
    virDomainDiskDefFree(*def);
    *def = NULL;

    goto cleanup;
}



int
esxVMX_ParseEthernet(virConfPtr conf, int controller, virDomainNetDefPtr *def)
{
    int result = 0;
    char prefix[48] = "";

    char present_name[48] = "";
    int present = 0;

    char startConnected_name[48] = "";
    int startConnected = 0;

    char connectionType_name[48] = "";
    char *connectionType = NULL;

    char addressType_name[48] = "";
    char *addressType = NULL;

    char generatedAddress_name[48] = "";
    char *generatedAddress = NULL;

    char address_name[48] = "";
    char *address = NULL;

    char virtualDev_name[48] = "";
    char *virtualDev = NULL;

    char vnet_name[48] = "";
    char *vnet = NULL;

    char networkName_name[48] = "";
    char *networkName = NULL;

    if (def == NULL || *def != NULL) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (controller < 0 || controller > 3) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Ethernet controller index %d out of [0..3] range",
                  controller);
        return -1;
    }

    if (VIR_ALLOC(*def) < 0) {
        virReportOOMError(NULL);
        goto failure;
    }

    snprintf(prefix, sizeof(prefix), "ethernet%d", controller);

    ESX_BUILD_VMX_NAME(present);
    ESX_BUILD_VMX_NAME(startConnected);
    ESX_BUILD_VMX_NAME(connectionType);
    ESX_BUILD_VMX_NAME(addressType);
    ESX_BUILD_VMX_NAME(generatedAddress);
    ESX_BUILD_VMX_NAME(address);
    ESX_BUILD_VMX_NAME(virtualDev);
    ESX_BUILD_VMX_NAME(networkName);
    ESX_BUILD_VMX_NAME(vnet);

    /* vmx:present */
    if (esxUtil_GetConfigBoolean(conf, present_name, &present, 0, 1) < 0) {
        goto failure;
    }

    /* vmx:startConnected */
    if (esxUtil_GetConfigBoolean(conf, startConnected_name, &startConnected, 1,
                                 1) < 0) {
        goto failure;
    }

    /* FIXME: Need to distiguish between active and inactive domains here */
    if (! present/* && ! startConnected*/) {
        goto ignore;
    }

    /* vmx:connectionType -> def:type */
    if (esxUtil_GetConfigString(conf, connectionType_name, &connectionType,
                                1) < 0) {
        goto failure;
    }

    /* vmx:addressType, vmx:generatedAddress, vmx:address -> def:mac */
    if (esxUtil_GetConfigString(conf, addressType_name, &addressType, 1) < 0 ||
        esxUtil_GetConfigString(conf, generatedAddress_name, &generatedAddress,
                                1) < 0 ||
        esxUtil_GetConfigString(conf, address_name, &address, 1) < 0) {
        goto failure;
    }

    if (addressType == NULL || STRCASEEQ(addressType, "generated") ||
        STRCASEEQ(addressType, "vpx")) {
        if (generatedAddress != NULL) {
            if (virParseMacAddr(generatedAddress, (*def)->mac) < 0) {
                ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                          "Expecting VMX entry '%s' to be MAC address but "
                          "found '%s'", generatedAddress_name,
                          generatedAddress);
                goto failure;
            }
        }
    } else if (STRCASEEQ(addressType, "static")) {
        if (address != NULL) {
            if (virParseMacAddr(address, (*def)->mac) < 0) {
                ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                          "Expecting VMX entry '%s' to be MAC address but "
                          "found '%s'", address_name, address);
                goto failure;
            }
        }
    } else {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Expecting VMX entry '%s' to be 'generated' or 'static' or "
                  "'vpx' but found '%s'", addressType_name, addressType);
        goto failure;
    }

    /* vmx:virtualDev -> def:model */
    if (esxUtil_GetConfigString(conf, virtualDev_name, &virtualDev, 1) < 0) {
        goto failure;
    }

    if (virtualDev != NULL &&
        STRCASENEQ(virtualDev, "vlance") &&
        STRCASENEQ(virtualDev, "vmxnet") &&
        STRCASENEQ(virtualDev, "vmxnet3") &&
        STRCASENEQ(virtualDev, "e1000")) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Expecting VMX entry '%s' to be 'vlance' or 'vmxnet' or "
                  "'vmxnet3' or 'e1000' but found '%s'", virtualDev_name,
                  virtualDev);
        goto failure;
    }

    /* vmx:networkName -> def:data.bridge.brname */
    if ((connectionType == NULL ||
         STRCASEEQ(connectionType, "bridged") ||
         STRCASEEQ(connectionType, "custom")) &&
        esxUtil_GetConfigString(conf, networkName_name, &networkName, 0) < 0) {
        goto failure;
    }

    /* vmx:vnet -> def:data.ifname */
    if (connectionType != NULL && STRCASEEQ(connectionType, "custom") &&
        esxUtil_GetConfigString(conf, vnet_name, &vnet, 0) < 0) {
        goto failure;
    }

    /* Setup virDomainNetDef */
    if (connectionType == NULL || STRCASEEQ(connectionType, "bridged")) {
        (*def)->type = VIR_DOMAIN_NET_TYPE_BRIDGE;
        (*def)->model = virtualDev;
        (*def)->data.bridge.brname = networkName;

        virtualDev = NULL;
        networkName = NULL;
    } else if (STRCASEEQ(connectionType, "hostonly")) {
        /* FIXME */
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "No yet handled value '%s' for VMX entry '%s'",
                  connectionType, connectionType_name);
        goto failure;
    } else if (STRCASEEQ(connectionType, "nat")) {
        /* FIXME */
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "No yet handled value '%s' for VMX entry '%s'",
                  connectionType, connectionType_name);
        goto failure;
    } else if (STRCASEEQ(connectionType, "custom")) {
        (*def)->type = VIR_DOMAIN_NET_TYPE_BRIDGE;
        (*def)->model = virtualDev;
        (*def)->data.bridge.brname = networkName;
        (*def)->ifname = vnet;

        virtualDev = NULL;
        networkName = NULL;
        vnet = NULL;
    } else {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Invalid value '%s' for VMX entry '%s'", connectionType,
                  connectionType_name);
        goto failure;
    }

  cleanup:
    VIR_FREE(connectionType);
    VIR_FREE(addressType);
    VIR_FREE(generatedAddress);
    VIR_FREE(address);
    VIR_FREE(virtualDev);
    VIR_FREE(vnet);

    return result;

  failure:
    result = -1;

  ignore:
    virDomainNetDefFree(*def);
    *def = NULL;

    goto cleanup;
}



int
esxVMX_ParseSerial(esxVI_Context *ctx, virConfPtr conf, int port,
                   const char *datastoreName, const char *directoryName,
                   virDomainChrDefPtr *def)
{
    int result = 0;
    char prefix[48] = "";

    char present_name[48] = "";
    int present = 0;

    char startConnected_name[48] = "";
    int startConnected = 0;

    char fileType_name[48] = "";
    char *fileType = NULL;

    char fileName_name[48] = "";
    char *fileName = NULL;

    if (def == NULL || *def != NULL) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (port < 0 || port > 3) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Serial port index %d out of [0..3] range", port);
        return -1;
    }

    if (VIR_ALLOC(*def) < 0) {
        virReportOOMError(NULL);
        goto failure;
    }

    (*def)->targetType = VIR_DOMAIN_CHR_TARGET_TYPE_SERIAL;

    snprintf(prefix, sizeof(prefix), "serial%d", port);

    ESX_BUILD_VMX_NAME(present);
    ESX_BUILD_VMX_NAME(startConnected);
    ESX_BUILD_VMX_NAME(fileType);
    ESX_BUILD_VMX_NAME(fileName);

    /* vmx:present */
    if (esxUtil_GetConfigBoolean(conf, present_name, &present, 0, 1) < 0) {
        goto failure;
    }

    /* vmx:startConnected */
    if (esxUtil_GetConfigBoolean(conf, startConnected_name, &startConnected, 1,
                                 1) < 0) {
        goto failure;
    }

    /* FIXME: Need to distiguish between active and inactive domains here */
    if (! present/* && ! startConnected*/) {
        goto ignore;
    }

    /* vmx:fileType -> def:type */
    if (esxUtil_GetConfigString(conf, fileType_name, &fileType, 0) < 0) {
        goto failure;
    }

    /* vmx:fileName -> def:data.file.path */
    if (esxUtil_GetConfigString(conf, fileName_name, &fileName, 0) < 0) {
        goto failure;
    }

    /* Setup virDomainChrDef */
    if (STRCASEEQ(fileType, "device")) {
        (*def)->target.port = port;
        (*def)->type = VIR_DOMAIN_CHR_TYPE_DEV;
        (*def)->data.file.path = fileName;

        fileName = NULL;
    } else if (STRCASEEQ(fileType, "file")) {
        (*def)->target.port = port;
        (*def)->type = VIR_DOMAIN_CHR_TYPE_FILE;
        (*def)->data.file.path = esxVMX_ParseFileName(ctx, fileName,
                                                      datastoreName,
                                                      directoryName);

        if ((*def)->data.file.path == NULL) {
            goto failure;
        }
    } else if (STRCASEEQ(fileType, "pipe")) {
        /*
         * FIXME: Differences between client/server and VM/application pipes
         *        not representable in domain XML form
         */
        (*def)->target.port = port;
        (*def)->type = VIR_DOMAIN_CHR_TYPE_PIPE;
        (*def)->data.file.path = fileName;

        fileName = NULL;
    } else {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Expecting VMX entry '%s' to be 'device', 'file' or 'pipe' "
                  "but found '%s'", fileType_name, fileType);
        goto failure;
    }

  cleanup:
    VIR_FREE(fileType);
    VIR_FREE(fileName);

    return result;

  failure:
    result = -1;

  ignore:
    virDomainChrDefFree(*def);
    *def = NULL;

    goto cleanup;
}



int
esxVMX_ParseParallel(esxVI_Context *ctx, virConfPtr conf, int port,
                     const char *datastoreName, const char *directoryName,
                     virDomainChrDefPtr *def)
{
    int result = 0;
    char prefix[48] = "";

    char present_name[48] = "";
    int present = 0;

    char startConnected_name[48] = "";
    int startConnected = 0;

    char fileType_name[48] = "";
    char *fileType = NULL;

    char fileName_name[48] = "";
    char *fileName = NULL;

    if (def == NULL || *def != NULL) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (port < 0 || port > 2) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Parallel port index %d out of [0..2] range", port);
        return -1;
    }

    if (VIR_ALLOC(*def) < 0) {
        virReportOOMError(NULL);
        goto failure;
    }

    (*def)->targetType = VIR_DOMAIN_CHR_TARGET_TYPE_PARALLEL;

    snprintf(prefix, sizeof(prefix), "parallel%d", port);

    ESX_BUILD_VMX_NAME(present);
    ESX_BUILD_VMX_NAME(startConnected);
    ESX_BUILD_VMX_NAME(fileType);
    ESX_BUILD_VMX_NAME(fileName);

    /* vmx:present */
    if (esxUtil_GetConfigBoolean(conf, present_name, &present, 0, 1) < 0) {
        goto failure;
    }

    /* vmx:startConnected */
    if (esxUtil_GetConfigBoolean(conf, startConnected_name, &startConnected, 1,
                                 1) < 0) {
        goto failure;
    }

    /* FIXME: Need to distiguish between active and inactive domains here */
    if (! present/* && ! startConnected*/) {
        goto ignore;
    }

    /* vmx:fileType -> def:type */
    if (esxUtil_GetConfigString(conf, fileType_name, &fileType, 0) < 0) {
        goto failure;
    }

    /* vmx:fileName -> def:data.file.path */
    if (esxUtil_GetConfigString(conf, fileName_name, &fileName, 0) < 0) {
        goto failure;
    }

    /* Setup virDomainChrDef */
    if (STRCASEEQ(fileType, "device")) {
        (*def)->target.port = port;
        (*def)->type = VIR_DOMAIN_CHR_TYPE_DEV;
        (*def)->data.file.path = fileName;

        fileName = NULL;
    } else if (STRCASEEQ(fileType, "file")) {
        (*def)->target.port = port;
        (*def)->type = VIR_DOMAIN_CHR_TYPE_FILE;
        (*def)->data.file.path = esxVMX_ParseFileName(ctx, fileName,
                                                      datastoreName,
                                                      directoryName);

        if ((*def)->data.file.path == NULL) {
            goto failure;
        }
    } else {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Expecting VMX entry '%s' to be 'device' or 'file' but "
                  "found '%s'", fileType_name, fileType);
        goto failure;
    }

  cleanup:
    VIR_FREE(fileType);
    VIR_FREE(fileName);

    return result;

  failure:
    result = -1;

  ignore:
    virDomainChrDefFree(*def);
    *def = NULL;

    goto cleanup;
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Domain XML -> VMX
 */

char *
esxVMX_FormatFileName(esxVI_Context *ctx ATTRIBUTE_UNUSED, const char *src)
{
    char *datastoreName = NULL;
    char *directoryName = NULL;
    char *fileName = NULL;
    char *absolutePath = NULL;

    if (STRPREFIX(src, "[")) {
        /* Found potential datastore related path */
        if (esxUtil_ParseDatastoreRelatedPath(src, &datastoreName,
                                              &directoryName, &fileName) < 0) {
            goto failure;
        }

        if (directoryName == NULL) {
            if (virAsprintf(&absolutePath, "/vmfs/volumes/%s/%s",
                            datastoreName, fileName) < 0) {
                virReportOOMError(NULL);
                goto failure;
            }
        } else {
            if (virAsprintf(&absolutePath, "/vmfs/volumes/%s/%s/%s",
                            datastoreName, directoryName, fileName) < 0) {
                virReportOOMError(NULL);
                goto failure;
            }
        }
    } else if (STRPREFIX(src, "/")) {
        /* Found absolute path */
        absolutePath = strdup(src);

        if (absolutePath == NULL) {
            virReportOOMError(NULL);
            goto failure;
        }
    } else {
        /* Found relative path, this is not supported */
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Found relative path '%s' in domain XML, this is not "
                  "supported", src);
        goto failure;
    }

    /* FIXME: Check if referenced path/file really exists */

  cleanup:
    VIR_FREE(datastoreName);
    VIR_FREE(directoryName);
    VIR_FREE(fileName);

    return absolutePath;

  failure:
    VIR_FREE(absolutePath);

    goto cleanup;
}



char *
esxVMX_FormatConfig(esxVI_Context *ctx, virDomainDefPtr def,
                    esxVI_APIVersion apiVersion)
{
    int i;
    int sched_cpu_affinity_length;
    unsigned char zero[VIR_UUID_BUFLEN];
    virBuffer buffer = VIR_BUFFER_INITIALIZER;

    memset(zero, 0, VIR_UUID_BUFLEN);

    if (def->virtType != VIR_DOMAIN_VIRT_VMWARE) { /* FIXME: maybe add VIR_DOMAIN_VIRT_ESX ? */
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Expecting virt type to be '%s' but found '%s'",
                  virDomainVirtTypeToString(VIR_DOMAIN_VIRT_VMWARE),
                  virDomainVirtTypeToString(def->virtType));
        return NULL;
    }

    /* vmx:config.version */
    virBufferAddLit(&buffer, "config.version = \"8\"\n");

    /* vmx:virtualHW.version */
    switch (apiVersion) {
      case esxVI_APIVersion_25:
        virBufferAddLit(&buffer, "virtualHW.version = \"4\"\n");
        break;

      case esxVI_APIVersion_40:
        virBufferAddLit(&buffer, "virtualHW.version = \"7\"\n");
        break;

      default:
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Expecting VI API version 2.5 or 4.0");
        goto failure;
    }

    /* def:arch -> vmx:guestOS */
    if (def->os.arch == NULL || STRCASEEQ(def->os.arch, "i686")) {
        virBufferAddLit(&buffer, "guestOS = \"other\"\n");
    } else if (STRCASEEQ(def->os.arch, "x86_64")) {
        virBufferAddLit(&buffer, "guestOS = \"other-64\"\n");
    } else {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Expecting domain XML attribute 'arch' of entry 'os/type' "
                  "to be 'i686' or 'x86_64' but found '%s'", def->os.arch);
        goto failure;
    }

    /* def:uuid -> vmx:uuid.action, vmx:uuid.bios */
    if (memcmp(def->uuid, zero, VIR_UUID_BUFLEN) == 0) {
        virBufferAddLit(&buffer, "uuid.action = \"create\"\n");
    } else {
        virBufferVSprintf(&buffer, "uuid.bios = \"%02x %02x %02x %02x %02x %02x "
                          "%02x %02x-%02x %02x %02x %02x %02x %02x %02x %02x\"\n",
                          def->uuid[0], def->uuid[1], def->uuid[2], def->uuid[3],
                          def->uuid[4], def->uuid[5], def->uuid[6], def->uuid[7],
                          def->uuid[8], def->uuid[9], def->uuid[10], def->uuid[11],
                          def->uuid[12], def->uuid[13], def->uuid[14],
                          def->uuid[15]);
    }

    /* def:name -> vmx:displayName */
    virBufferVSprintf(&buffer, "displayName = \"%s\"\n", def->name);

    /* def:maxmem -> vmx:memsize */
    if (def->maxmem <= 0 || def->maxmem % 4096 != 0) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Expecting domain XML entry 'memory' to be an unsigned "
                  "integer (multiple of 4096) but found %lld",
                  (unsigned long long)def->maxmem);
        goto failure;
    }

    /* Scale from kilobytes to megabytes */
    virBufferVSprintf(&buffer, "memsize = \"%d\"\n",
                      (int)(def->maxmem / 1024));

    /* def:memory -> vmx:sched.mem.max */
    if (def->memory < def->maxmem) {
        if (def->memory <= 0 || def->memory % 1024 != 0) {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      "Expecting domain XML entry 'currentMemory' to be an "
                      "unsigned integer (multiple of 1024) but found %lld",
                      (unsigned long long)def->memory);
            goto failure;
        }

        /* Scale from kilobytes to megabytes */
        virBufferVSprintf(&buffer, "sched.mem.max = \"%d\"\n",
                          (int)(def->memory / 1024));
    }

    /* def:vcpus -> vmx:numvcpus */
    if (def->vcpus <= 0 || (def->vcpus % 2 != 0 && def->vcpus != 1)) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Expecting domain XML entry 'vcpu' to be an unsigned "
                  "integer (1 or a multiple of 2) but found %d",
                  (int)def->vcpus);
        goto failure;
    }

    virBufferVSprintf(&buffer, "numvcpus = \"%d\"\n", (int)def->vcpus);

    /* def:cpumask -> vmx:sched.cpu.affinity */
    if (def->cpumasklen > 0) {
        virBufferAddLit(&buffer, "sched.cpu.affinity = \"");

        sched_cpu_affinity_length = 0;

        for (i = 0; i < def->cpumasklen; ++i) {
            if (def->cpumask[i]) {
                ++sched_cpu_affinity_length;
            }
        }

        if (sched_cpu_affinity_length < def->vcpus) {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      "Expecting domain XML attribute 'cpuset' of entry "
                      "'vcpu' to contains at least %d CPU(s)",
                      (int)def->vcpus);
            goto failure;
        }

        for (i = 0; i < def->cpumasklen; ++i) {
            if (def->cpumask[i]) {
                virBufferVSprintf(&buffer, "%d", i);

                if (sched_cpu_affinity_length > 1) {
                    virBufferAddChar(&buffer, ',');
                }

                --sched_cpu_affinity_length;
            }
        }

        virBufferAddLit(&buffer, "\"\n");
    }

    /* def:graphics */
    for (i = 0; i < def->ngraphics; ++i) {
        switch (def->graphics[i]->type) {
          case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
            if (esxVMX_FormatVNC(def->graphics[i], &buffer) < 0) {
                goto failure;
            }

            break;

          default:
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      "Unsupported graphics type '%s'",
                      virDomainGraphicsTypeToString(def->graphics[i]->type));
            goto failure;
        }
    }

    /* def:disks */
    int scsi_present[4] = { 0, 0, 0, 0 };
    char *scsi_virtualDev[4] = { NULL, NULL, NULL, NULL };

    if (esxVMX_GatherSCSIControllers(def, scsi_virtualDev, scsi_present) < 0) {
        goto failure;
    }

    for (i = 0; i < 4; ++i) {
        if (scsi_present[i]) {
            virBufferVSprintf(&buffer, "scsi%d.present = \"true\"\n", i);

            if (scsi_virtualDev[i] != NULL) {
                virBufferVSprintf(&buffer, "scsi%d.virtualDev = \"%s\"\n", i,
                                  scsi_virtualDev[i]);
            }
        }
    }

    for (i = 0; i < def->ndisks; ++i) {
        switch (def->disks[i]->device) {
          case VIR_DOMAIN_DISK_DEVICE_DISK:
            if (esxVMX_FormatHardDisk(ctx, def->disks[i], &buffer) < 0) {
                goto failure;
            }

            break;

          case VIR_DOMAIN_DISK_DEVICE_CDROM:
            if (esxVMX_FormatCDROM(ctx, def->disks[i], &buffer) < 0) {
                goto failure;
            }

            break;

          case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
            if (esxVMX_FormatFloppy(ctx, def->disks[i], &buffer) < 0) {
                goto failure;
            }

            break;

          default:
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      "Unsupported disk device type '%s'",
                      virDomainDiskDeviceTypeToString(def->disks[i]->device));
            goto failure;
        }
    }

    /* def:fss */
    /* FIXME */

    /* def:nets */
    for (i = 0; i < def->nnets; ++i) {
        if (esxVMX_FormatEthernet(def->nets[i], i, &buffer) < 0) {
            goto failure;
        }
    }

    /* def:inputs */
    /* FIXME */

    /* def:sounds */
    /* FIXME */

    /* def:hostdevs */
    /* FIXME */

    /* def:serials */
    for (i = 0; i < def->nserials; ++i) {
        if (esxVMX_FormatSerial(ctx, def->serials[i], &buffer) < 0) {
            goto failure;
        }
    }

    /* def:parallels */
    for (i = 0; i < def->nparallels; ++i) {
        if (esxVMX_FormatParallel(ctx, def->parallels[i], &buffer) < 0) {
            goto failure;
        }
    }

    /* Get final VMX output */
    if (virBufferError(&buffer)) {
        virReportOOMError(NULL);
        goto failure;
    }

    return virBufferContentAndReset(&buffer);

  failure:
    virBufferFreeAndReset(&buffer);

    return NULL;
}



int
esxVMX_FormatVNC(virDomainGraphicsDefPtr def, virBufferPtr buffer)
{
    if (def->type != VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    virBufferVSprintf(buffer, "RemoteDisplay.vnc.enabled = \"true\"\n");

    if (def->data.vnc.autoport) {
        VIR_WARN0("VNC autoport is enabled, but the automatically assigned "
                  "VNC port cannot be read back");
    } else {
        if (def->data.vnc.port < 5900 || def->data.vnc.port > 5964) {
            VIR_WARN("VNC port %d it out of [5900..5964] range",
                     def->data.vnc.port);
        }

        virBufferVSprintf(buffer, "RemoteDisplay.vnc.port = \"%d\"\n",
                          def->data.vnc.port);
    }

    if (def->data.vnc.listenAddr != NULL) {
        virBufferVSprintf(buffer, "RemoteDisplay.vnc.ip = \"%s\"\n",
                          def->data.vnc.listenAddr);
    }

    if (def->data.vnc.keymap != NULL) {
        virBufferVSprintf(buffer, "RemoteDisplay.vnc.keymap = \"%s\"\n",
                          def->data.vnc.keymap);
    }

    if (def->data.vnc.passwd != NULL) {
        virBufferVSprintf(buffer, "RemoteDisplay.vnc.password = \"%s\"\n",
                          def->data.vnc.passwd);
    }

    return 0;
}



int
esxVMX_FormatHardDisk(esxVI_Context *ctx, virDomainDiskDefPtr def,
                      virBufferPtr buffer)
{
    int controller, id;
    const char *busName = NULL;
    const char *entryPrefix = NULL;
    const char *deviceTypePrefix = NULL;
    char *fileName = NULL;

    if (def->device != VIR_DOMAIN_DISK_DEVICE_DISK) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (def->bus == VIR_DOMAIN_DISK_BUS_SCSI) {
        busName = "SCSI";
        entryPrefix = "scsi";
        deviceTypePrefix = "scsi";

        if (esxVMX_SCSIDiskNameToControllerAndID(def->dst, &controller,
                                                 &id) < 0) {
            return -1;
        }
    } else if (def->bus == VIR_DOMAIN_DISK_BUS_IDE) {
        busName = "IDE";
        entryPrefix = "ide";
        deviceTypePrefix = "ata";

        if (esxVMX_IDEDiskNameToControllerAndID(def->dst, &controller,
                                                &id) < 0) {
            return -1;
        }
    } else {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Unsupported bus type '%s' for harddisk",
                  virDomainDiskBusTypeToString(def->bus));
        return -1;
    }

    if (def->type != VIR_DOMAIN_DISK_TYPE_FILE) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "%s harddisk '%s' has unsupported type '%s', expecting '%s'",
                  busName, def->dst, virDomainDiskTypeToString(def->type),
                  virDomainDiskTypeToString(VIR_DOMAIN_DISK_TYPE_FILE));
        return -1;
    }

    virBufferVSprintf(buffer, "%s%d:%d.present = \"true\"\n",
                      entryPrefix, controller, id);
    virBufferVSprintf(buffer, "%s%d:%d.deviceType = \"%s-hardDisk\"\n",
                      entryPrefix, controller, id, deviceTypePrefix);

    if (def->src != NULL) {
        if (! virFileHasSuffix(def->src, ".vmdk")) {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      "Image file for %s harddisk '%s' has unsupported suffix, "
                      "expecting '.vmdk'", busName, def->dst);
            return -1;
        }

        fileName = esxVMX_FormatFileName(ctx, def->src);

        if (fileName == NULL) {
            return -1;
        }

        virBufferVSprintf(buffer, "%s%d:%d.fileName = \"%s\"\n",
                          entryPrefix, controller, id, fileName);

        VIR_FREE(fileName);
    }

    if (def->bus == VIR_DOMAIN_DISK_BUS_SCSI) {
        if (def->cachemode == VIR_DOMAIN_DISK_CACHE_WRITETHRU) {
            virBufferVSprintf(buffer, "%s%d:%d.writeThrough = \"true\"\n",
                              entryPrefix, controller, id);
        } else if (def->cachemode != VIR_DOMAIN_DISK_CACHE_DEFAULT) {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      "%s harddisk '%s' has unsupported cache mode '%s'",
                      busName, def->dst,
                      virDomainDiskCacheTypeToString(def->cachemode));
            return -1;
        }
    }

    return 0;
}



int
esxVMX_FormatCDROM(esxVI_Context *ctx, virDomainDiskDefPtr def,
                   virBufferPtr buffer)
{
    int controller, id;
    const char *busName = NULL;
    const char *entryPrefix = NULL;
    char *fileName = NULL;

    if (def->device != VIR_DOMAIN_DISK_DEVICE_CDROM) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (def->bus == VIR_DOMAIN_DISK_BUS_SCSI) {
        busName = "SCSI";
        entryPrefix = "scsi";

        if (esxVMX_SCSIDiskNameToControllerAndID(def->dst, &controller,
                                                 &id) < 0) {
            return -1;
        }
    } else if (def->bus == VIR_DOMAIN_DISK_BUS_IDE) {
        busName = "IDE";
        entryPrefix = "ide";

        if (esxVMX_IDEDiskNameToControllerAndID(def->dst, &controller,
                                                &id) < 0) {
            return -1;
        }
    } else {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "Unsupported bus type '%s' for cdrom",
                  virDomainDiskBusTypeToString(def->bus));
        return -1;
    }

    virBufferVSprintf(buffer, "%s%d:%d.present = \"true\"\n",
                      entryPrefix, controller, id);

    if (def->type == VIR_DOMAIN_DISK_TYPE_FILE) {
        virBufferVSprintf(buffer, "%s%d:%d.deviceType = \"cdrom-image\"\n",
                          entryPrefix, controller, id);

        if (def->src != NULL) {
            if (! virFileHasSuffix(def->src, ".iso")) {
                ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                          "Image file for %s cdrom '%s' has unsupported "
                          "suffix, expecting '.iso'", busName, def->dst);
                return -1;
            }

            fileName = esxVMX_FormatFileName(ctx, def->src);

            if (fileName == NULL) {
                return -1;
            }

            virBufferVSprintf(buffer, "%s%d:%d.fileName = \"%s\"\n",
                              entryPrefix, controller, id, fileName);

            VIR_FREE(fileName);
        }
    } else if (def->type == VIR_DOMAIN_DISK_TYPE_BLOCK) {
        virBufferVSprintf(buffer, "%s%d:%d.deviceType = \"atapi-cdrom\"\n",
                          entryPrefix, controller, id);

        if (def->src != NULL) {
            virBufferVSprintf(buffer, "%s%d:%d.fileName = \"%s\"\n",
                              entryPrefix, controller, id, def->src);
        }
    } else {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "%s cdrom '%s' has unsupported type '%s', expecting '%s' "
                  "or '%s'", busName, def->dst,
                  virDomainDiskTypeToString(def->type),
                  virDomainDiskTypeToString(VIR_DOMAIN_DISK_TYPE_FILE),
                  virDomainDiskTypeToString(VIR_DOMAIN_DISK_TYPE_BLOCK));
        return -1;
    }

    return 0;
}



int
esxVMX_FormatFloppy(esxVI_Context *ctx, virDomainDiskDefPtr def,
                    virBufferPtr buffer)
{
    int controller;
    char *fileName = NULL;

    if (def->device != VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (esxVMX_FloppyDiskNameToController(def->dst, &controller) < 0) {
        return -1;
    }

    virBufferVSprintf(buffer, "floppy%d.present = \"true\"\n", controller);

    if (def->type == VIR_DOMAIN_DISK_TYPE_FILE) {
        virBufferVSprintf(buffer, "floppy%d.fileType = \"file\"\n",
                          controller);

        if (def->src != NULL) {
            if (! virFileHasSuffix(def->src, ".flp")) {
                ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                          "Image file for floppy '%s' has unsupported suffix, "
                          "expecting '.flp'", def->dst);
                return -1;
            }

            fileName = esxVMX_FormatFileName(ctx, def->src);

            if (fileName == NULL) {
                return -1;
            }

            virBufferVSprintf(buffer, "floppy%d.fileName = \"%s\"\n",
                              controller, fileName);

            VIR_FREE(fileName);
        }
    } else if (def->type == VIR_DOMAIN_DISK_TYPE_BLOCK) {
        virBufferVSprintf(buffer, "floppy%d.fileType = \"device\"\n",
                          controller);

        if (def->src != NULL) {
            virBufferVSprintf(buffer, "floppy%d.fileName = \"%s\"\n",
                              controller, def->src);
        }
    } else {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Floppy '%s' has unsupported type '%s', expecting '%s' "
                  "or '%s'", def->dst,
                  virDomainDiskTypeToString(def->type),
                  virDomainDiskTypeToString(VIR_DOMAIN_DISK_TYPE_FILE),
                  virDomainDiskTypeToString(VIR_DOMAIN_DISK_TYPE_BLOCK));
        return -1;
    }

    return 0;
}



int
esxVMX_FormatEthernet(virDomainNetDefPtr def, int controller,
                      virBufferPtr buffer)
{
    char mac_string[VIR_MAC_STRING_BUFLEN];
    unsigned int prefix, suffix;

    if (controller < 0 || controller > 3) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Ethernet controller index %d out of [0..3] range",
                  controller);
        return -1;
    }

    virBufferVSprintf(buffer, "ethernet%d.present = \"true\"\n", controller);

    /* def:model -> vmx:virtualDev */
    if (def->model != NULL) {
        if (STRCASENEQ(def->model, "vlance") &&
            STRCASENEQ(def->model, "vmxnet") &&
            STRCASENEQ(def->model, "vmxnet3") &&
            STRCASENEQ(def->model, "e1000")) {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      "Expecting domain XML entry 'devices/interfase/model' "
                      "to be 'vlance' or 'vmxnet' or 'vmxnet3' or 'e1000' but "
                      "found '%s'", def->model);
            return -1;
        }

        virBufferVSprintf(buffer, "ethernet%d.virtualDev = \"%s\"\n",
                          controller, def->model);
    }

    /* def:type, def:ifname -> vmx:connectionType */
    switch (def->type) {
      case VIR_DOMAIN_NET_TYPE_BRIDGE:
        virBufferVSprintf(buffer, "ethernet%d.networkName = \"%s\"\n",
                          controller, def->data.bridge.brname);

        if (def->ifname != NULL) {
            virBufferVSprintf(buffer, "ethernet%d.connectionType = \"custom\"\n",
                              controller);
            virBufferVSprintf(buffer, "ethernet%d.vnet = \"%s\"\n",
                              controller, def->ifname);
        } else {
            virBufferVSprintf(buffer, "ethernet%d.connectionType = \"bridged\"\n",
                              controller);
        }

        break;

      default:
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "Unsupported net type '%s'",
                  virDomainNetTypeToString(def->type));
        return -1;
    }

    /* def:mac -> vmx:addressType, vmx:(generated)Address, vmx:checkMACAddress */
    virFormatMacAddr(def->mac, mac_string);

    prefix = (def->mac[0] << 16) | (def->mac[1] << 8) | def->mac[2];
    suffix = (def->mac[3] << 16) | (def->mac[4] << 8) | def->mac[5];

    if (prefix == 0x000c29) {
        virBufferVSprintf(buffer, "ethernet%d.addressType = \"generated\"\n",
                          controller);
        virBufferVSprintf(buffer, "ethernet%d.generatedAddress = \"%s\"\n",
                          controller, mac_string);
        virBufferVSprintf(buffer, "ethernet%d.generatedAddressOffset = \"0\"\n",
                          controller);
    } else if (prefix == 0x005056 && suffix <= 0x3fffff) {
        virBufferVSprintf(buffer, "ethernet%d.addressType = \"static\"\n",
                          controller);
        virBufferVSprintf(buffer, "ethernet%d.address = \"%s\"\n",
                          controller, mac_string);
    } else if (prefix == 0x005056 && suffix >= 0x800000 && suffix <= 0xbfffff) {
        virBufferVSprintf(buffer, "ethernet%d.addressType = \"vpx\"\n",
                          controller);
        virBufferVSprintf(buffer, "ethernet%d.generatedAddress = \"%s\"\n",
                          controller, mac_string);
    } else {
        virBufferVSprintf(buffer, "ethernet%d.addressType = \"static\"\n",
                          controller);
        virBufferVSprintf(buffer, "ethernet%d.address = \"%s\"\n",
                          controller, mac_string);
        virBufferVSprintf(buffer, "ethernet%d.checkMACAddress = \"false\"\n",
                          controller);
    }

    return 0;
}



int
esxVMX_FormatSerial(esxVI_Context *ctx, virDomainChrDefPtr def,
                    virBufferPtr buffer)
{
    char *fileName = NULL;

    if (def->target.port < 0 || def->target.port > 3) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Serial port index %d out of [0..3] range", def->target.port);
        return -1;
    }

    if (def->data.file.path == NULL) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Expecting domain XML attribute 'path' of entry "
                  "'devices/serial/source' to be present");
        return -1;
    }

    virBufferVSprintf(buffer, "serial%d.present = \"true\"\n", def->target.port);

    /* def:type -> vmx:fileType and def:data.file.path -> vmx:fileName */
    switch (def->type) {
      case VIR_DOMAIN_CHR_TYPE_DEV:
        virBufferVSprintf(buffer, "serial%d.fileType = \"device\"\n",
                          def->target.port);
        virBufferVSprintf(buffer, "serial%d.fileName = \"%s\"\n",
                          def->target.port, def->data.file.path);
        break;

      case VIR_DOMAIN_CHR_TYPE_FILE:
        virBufferVSprintf(buffer, "serial%d.fileType = \"file\"\n",
                          def->target.port);

        fileName = esxVMX_FormatFileName(ctx, def->data.file.path);

        if (fileName == NULL) {
            return -1;
        }

        virBufferVSprintf(buffer, "serial%d.fileName = \"%s\"\n",
                          def->target.port, fileName);

        VIR_FREE(fileName);
        break;

      case VIR_DOMAIN_CHR_TYPE_PIPE:
        virBufferVSprintf(buffer, "serial%d.fileType = \"pipe\"\n",
                          def->target.port);
        /* FIXME: Based on VI Client GUI default */
        virBufferVSprintf(buffer, "serial%d.pipe.endPoint = \"client\"\n",
                          def->target.port);
        /* FIXME: Based on VI Client GUI default */
        virBufferVSprintf(buffer, "serial%d.tryNoRxLoss = \"false\"\n",
                          def->target.port);
        virBufferVSprintf(buffer, "serial%d.fileName = \"%s\"\n",
                          def->target.port, def->data.file.path);
        break;

      default:
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Unsupported character device type '%s'",
                  virDomainChrTypeToString(def->type));
        return -1;
    }

    /* vmx:yieldOnMsrRead */
    /* FIXME: Based on VI Client GUI default */
    virBufferVSprintf(buffer, "serial%d.yieldOnMsrRead = \"true\"\n",
                      def->target.port);

    return 0;
}



int
esxVMX_FormatParallel(esxVI_Context *ctx, virDomainChrDefPtr def,
                      virBufferPtr buffer)
{
    char *fileName = NULL;

    if (def->target.port < 0 || def->target.port > 2) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Parallel port index %d out of [0..2] range",
                  def->target.port);
        return -1;
    }

    if (def->data.file.path == NULL) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Expecting domain XML attribute 'path' of entry "
                  "'devices/parallel/source' to be present");
        return -1;
    }

    virBufferVSprintf(buffer, "parallel%d.present = \"true\"\n",
                      def->target.port);

    /* def:type -> vmx:fileType and def:data.file.path -> vmx:fileName */
    switch (def->type) {
      case VIR_DOMAIN_CHR_TYPE_DEV:
        virBufferVSprintf(buffer, "parallel%d.fileType = \"device\"\n",
                          def->target.port);
        virBufferVSprintf(buffer, "parallel%d.fileName = \"%s\"\n",
                          def->target.port, def->data.file.path);
        break;

      case VIR_DOMAIN_CHR_TYPE_FILE:
        virBufferVSprintf(buffer, "parallel%d.fileType = \"file\"\n",
                          def->target.port);

        fileName = esxVMX_FormatFileName(ctx, def->data.file.path);

        if (fileName == NULL) {
            return -1;
        }

        virBufferVSprintf(buffer, "parallel%d.fileName = \"%s\"\n",
                          def->target.port, fileName);

        VIR_FREE(fileName);
        break;

      default:
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  "Unsupported character device type '%s'",
                  virDomainChrTypeToString(def->type));
        return -1;
    }

    return 0;
}
