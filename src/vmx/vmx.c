/*
 * vmx.c: VMware VMX parsing/formatting functions
 *
 * Copyright (C) 2010-2014 Red Hat, Inc.
 * Copyright (C) 2009-2010 Matthias Bolte <matthias.bolte@googlemail.com>
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
 *
 */

#include <config.h>

#include <c-ctype.h>

#include "internal.h"
#include "virerror.h"
#include "virfile.h"
#include "virconf.h"
#include "viralloc.h"
#include "virlog.h"
#include "viruuid.h"
#include "vmx.h"
#include "viruri.h"
#include "virstring.h"

VIR_LOG_INIT("vmx.vmx");

/*

 mapping:

domain-xml                        <=>   vmx


                                        config.version = "8"                    # essential
                                        virtualHW.version = "4"                 # essential for ESX 3.5
                                        virtualHW.version = "7"                 # essential for ESX 4.0
                                        virtualHW.version = "8"                 # essential for ESX 5.0
                                        virtualHW.version = "9"                 # essential for ESX 5.1


???                               <=>   guestOS = "<value>"                     # essential, FIXME: not representable
def->id = <value>                 <=>   ???                                     # not representable
def->uuid = <value>               <=>   uuid.bios = "<value>"
def->name = <value>               <=>   displayName = "<value>"
def->mem.max_balloon = <value kilobyte>    <=>   memsize = "<value megabyte>"            # must be a multiple of 4, defaults to 32
def->mem.cur_balloon = <value kilobyte>    <=>   sched.mem.max = "<value megabyte>"      # defaults to "unlimited" -> def->mem.cur_balloon = def->mem.max_balloon
def->mem.min_guarantee = <value kilobyte>  <=>   sched.mem.minsize = "<value megabyte>"  # defaults to 0
def->maxvcpus = <value>           <=>   numvcpus = "<value>"                    # must be 1 or a multiple of 2, defaults to 1
def->cpumask = <uint list>        <=>   sched.cpu.affinity = "<uint list>"
def->cputune.shares = <value>     <=>   sched.cpu.shares = "<value>"            # with handling for special values
                                                                                # "high", "normal", "low"



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
->smbios_mode                     <=>   smbios.reflecthost = "<value>"          # <value> == true means SMBIOS_HOST, otherwise it's SMBIOS_EMULATE, defaults to "false"



################################################################################
## disks #######################################################################

                                        scsi[0..3]:[0..6,8..15] -> <controller>:<unit> with 1 bus per controller
                                        ide[0..1]:[0..1]        -> <bus>:<unit> with 1 controller
                                        floppy[0..1]            -> <unit> with 1 controller and 1 bus per controller

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
->dst = sd[<controller> * 15 + <unit> mapped to [a-z]+]
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
->dst = hd[<bus> * 2 + <unit> mapped to [a-z]+]
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
->dst = sd[<controller> * 15 + <unit> mapped to [a-z]+]
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
->dst = hd[<bus> * 2 + <unit> mapped to [a-z]+]
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
->dst = sd[<controller> * 15 + <unit> mapped to [a-z]+]
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
->dst = hd[<bus> * 2 + <unit> mapped to [a-z]+]
->driverName
->driverType
->cachemode
->readonly
->shared
->slotnum


## disks: floppy from .flp image ###############################################

                                        floppy0.present = "true"                # defaults to "true"
                                        floppy0.startConnected = "true"         # defaults to "true"
                                        floppy0.clientDevice = "false"          # defaults to "false"

...
->type = _DISK_TYPE_FILE          <=>   floppy0.fileType = "file"               # defaults to ?
->device = _DISK_DEVICE_FLOPPY
->bus = _DISK_BUS_FDC
->src = <value>.flp               <=>   floppy0.fileName = "<value>.flp"
->dst = fd[<unit> mapped to [a-z]+]
->driverName
->driverType
->cachemode
->readonly
->shared
->slotnum


## disks: floppy from host device ##############################################

                                        floppy0.present = "true"                # defaults to "true"
                                        floppy0.startConnected = "true"         # defaults to "true"
                                        floppy0.clientDevice = "false"          # defaults to "false"

...
->type = _DISK_TYPE_BLOCK         <=>   floppy0.fileType = "device"             # defaults to ?
->device = _DISK_DEVICE_FLOPPY
->bus = _DISK_BUS_FDC
->src = <value>                   <=>   floppy0.fileName = "<value>"            # e.g. "/dev/fd0"
->dst = fd[<unit> mapped to [a-z]+]
->driverName
->driverType
->cachemode
->readonly
->shared
->slotnum



################################################################################
## filesystems #################################################################

                                        isolation.tools.hgfs.disable = "false"  # defaults to "true"

def->nfss = 1                     <=>   sharedFolder.maxNum = "1"               # must match the number of shared folders

                                        sharedFolder[0..n] -> <filesystem>

def->fss[0]...                    <=>   sharedFolder0.present = "true"          # defaults to "false"
                                        sharedFolder0.enabled = "true"          # defaults to "false"
                                        sharedFolder0.expiration = "never"      # defaults to "never"
                                        sharedFolder0.readAccess = "true"       # defaults to "false"
->type = _FS_TYPE_MOUNT
->fsdriver
->accessmode
->wrpolicy
->src = <value>                   <=>   sharedFolder0.hostPath = "<value>"      # defaults to ?
->dst = <value>                   <=>   sharedFolder0.guestName = "<value>"
->readonly = <readonly>           <=>   sharedFolder0.writeAccess = "<value>"   # "true" -> <readonly> = 0, "false" -> <readonly> = 1



################################################################################
## nets ########################################################################

                                        ethernet[0..3] -> <controller>

                                        ethernet0.present = "true"              # defaults to "false"
                                        ethernet0.startConnected = "true"       # defaults to "true"

                                        ethernet0.networkName = "VM Network"    # FIXME

def->nets[0]...
->model = <model>                 <=>   ethernet0.virtualDev = "<model>"        # default depends on guestOS value
                                        ethernet0.features = "15"               # if present and virtualDev is "vmxnet" => vmxnet2 (enhanced)


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
## video #######################################################################

def->videos[0]...
->type = _VIDEO_TYPE_VMVGA
->vram = <value kilobyte>         <=>   svga.vramSize = "<value byte>"
->heads = 1



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


## serials: network, server (since vSphere 4.1) ################################

->type = _CHR_TYPE_TCP            <=>   serial0.fileType = "network"

->data.tcp.host = <host>          <=>   serial0.fileName = "<protocol>://<host>:<service>"
->data.tcp.service = <service>                                                  # e.g. "telnet://0.0.0.0:42001"
->data.tcp.protocol = <protocol>

->data.tcp.listen = true          <=>   serial0.network.endPoint = "server"     # defaults to "server"

???                               <=>   serial0.vspc = "foobar"                 # defaults to <not present>, FIXME: not representable
???                               <=>   serial0.tryNoRxLoss = "false"           # defaults to "false", FIXME: not representable
???                               <=>   serial0.yieldOnMsrRead = "true"         # defaults to "false", FIXME: not representable


## serials: network, client (since vSphere 4.1) ################################

->type = _CHR_TYPE_TCP            <=>   serial0.fileType = "network"

->data.tcp.host = <host>          <=>   serial0.fileName = "<protocol>://<host>:<service>"
->data.tcp.service = <service>                                                  # e.g. "telnet://192.168.0.17:42001"
->data.tcp.protocol = <protocol>

->data.tcp.listen = false         <=>   serial0.network.endPoint = "client"     # defaults to "server"

???                               <=>   serial0.vspc = "foobar"                 # defaults to <not present>, FIXME: not representable
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

#define VIR_FROM_THIS VIR_FROM_NONE

#define VMX_BUILD_NAME_EXTRA(_suffix, _extra)                                 \
    snprintf(_suffix##_name, sizeof(_suffix##_name), "%s."_extra, prefix);

#define VMX_BUILD_NAME(_suffix)                                               \
    VMX_BUILD_NAME_EXTRA(_suffix, #_suffix)

/* directly map the virDomainControllerModel to virVMXSCSIControllerModel,
 * this is good enough for now because all virDomainControllerModel values
 * are actually SCSI controller models in the ESX case */
VIR_ENUM_DECL(virVMXControllerModelSCSI)
VIR_ENUM_IMPL(virVMXControllerModelSCSI, VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LAST,
              "auto", /* just to match virDomainControllerModel, will never be used */
              "buslogic",
              "lsilogic",
              "lsisas1068",
              "pvscsi",
              "UNUSED ibmvscsi",
              "UNUSED virtio-scsi",
              "UNUSED lsisas1078");


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Helpers
 */

virDomainDefParserConfig virVMXDomainDefParserConfig = {
    .hasWideScsiBus = true,
    .macPrefix = {0x00, 0x0c, 0x29},
};


virDomainXMLOptionPtr
virVMXDomainXMLConfInit(void)
{
    return virDomainXMLOptionNew(&virVMXDomainDefParserConfig,
                               NULL, NULL);
}

char *
virVMXEscapeHex(const char *string, char escape, const char *special)
{
    char *escaped = NULL;
    size_t length = 1; /* 1 byte for termination */
    const char *tmp1 = string;
    char *tmp2;

    /* Calculate length of escaped string */
    while (*tmp1 != '\0') {
        if (*tmp1 == escape || strspn(tmp1, special) > 0) {
            length += 2;
        }

        ++tmp1;
        ++length;
    }

    if (VIR_ALLOC_N(escaped, length) < 0)
        return NULL;

    tmp1 = string; /* reading from this one */
    tmp2 = escaped; /* writing to this one */

    /* Escape to 'cXX' where c is the escape char and X is a hex digit */
    while (*tmp1 != '\0') {
        if (*tmp1 == escape || strspn(tmp1, special) > 0) {
            *tmp2++ = escape;

            snprintf(tmp2, 3, "%02x", (unsigned int)*tmp1);

            tmp2 += 2;
        } else {
            *tmp2++ = *tmp1;
        }

        ++tmp1;
    }

    *tmp2 = '\0';

    return escaped;
}



int
virVMXUnescapeHex(char *string, char escape)
{
    char *tmp1 = string; /* reading from this one */
    char *tmp2 = string; /* writing to this one */

    /* Unescape from 'cXX' where c is the escape char and X is a hex digit */
    while (*tmp1 != '\0') {
        if (*tmp1 == escape) {
            if (!c_isxdigit(tmp1[1]) || !c_isxdigit(tmp1[2])) {
                return -1;
            }

            *tmp2++ = virHexToBin(tmp1[1]) * 16 + virHexToBin(tmp1[2]);
            tmp1 += 3;
        } else {
            *tmp2++ = *tmp1++;
        }
    }

    *tmp2 = '\0';

    return 0;
}



char *
virVMXConvertToUTF8(const char *encoding, const char *string)
{
    char *result = NULL;
    xmlCharEncodingHandlerPtr handler;
    xmlBufferPtr input;
    xmlBufferPtr utf8;

    handler = xmlFindCharEncodingHandler(encoding);

    if (handler == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("libxml2 doesn't handle %s encoding"), encoding);
        return NULL;
    }

    input = xmlBufferCreateStatic((char *)string, strlen(string));
    utf8 = xmlBufferCreate();

    if (xmlCharEncInFunc(handler, utf8, input) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not convert from %s to UTF-8 encoding"), encoding);
        goto cleanup;
    }

    result = (char *)utf8->content;
    utf8->content = NULL;

 cleanup:
    xmlCharEncCloseFunc(handler);
    xmlBufferFree(input);
    xmlBufferFree(utf8);

    return result;
}



static int
virVMXGetConfigString(virConfPtr conf, const char *name, char **string,
                      bool optional)
{
    virConfValuePtr value;

    *string = NULL;
    value = virConfGetValue(conf, name);

    if (value == NULL) {
        if (optional) {
            return 0;
        }

        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Missing essential config entry '%s'"), name);
        return -1;
    }

    if (value->type != VIR_CONF_STRING) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Config entry '%s' must be a string"), name);
        return -1;
    }

    if (value->str == NULL) {
        if (optional) {
            return 0;
        }

        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Missing essential config entry '%s'"), name);
        return -1;
    }

    return VIR_STRDUP(*string, value->str);
}



static int
virVMXGetConfigUUID(virConfPtr conf, const char *name, unsigned char *uuid,
                    bool optional)
{
    virConfValuePtr value;

    value = virConfGetValue(conf, name);

    if (value == NULL) {
        if (optional) {
            return 0;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Missing essential config entry '%s'"), name);
            return -1;
        }
    }

    if (value->type != VIR_CONF_STRING) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Config entry '%s' must be a string"), name);
        return -1;
    }

    if (value->str == NULL) {
        if (optional) {
            return 0;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Missing essential config entry '%s'"), name);
            return -1;
        }
    }

    if (virUUIDParse(value->str, uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not parse UUID from string '%s'"), value->str);
        return -1;
    }

    return 0;
}



static int
virVMXGetConfigLong(virConfPtr conf, const char *name, long long *number,
                    long long default_, bool optional)
{
    virConfValuePtr value;

    *number = default_;
    value = virConfGetValue(conf, name);

    if (value == NULL) {
        if (optional) {
            return 0;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Missing essential config entry '%s'"), name);
            return -1;
        }
    }

    if (value->type == VIR_CONF_STRING) {
        if (value->str == NULL) {
            if (optional) {
                return 0;
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Missing essential config entry '%s'"), name);
                return -1;
            }
        }

        if (STRCASEEQ(value->str, "unlimited")) {
            *number = -1;
        } else if (virStrToLong_ll(value->str, NULL, 10, number) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Config entry '%s' must represent an integer value"),
                           name);
            return -1;
        }
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Config entry '%s' must be a string"), name);
        return -1;
    }

    return 0;
}



static int
virVMXGetConfigBoolean(virConfPtr conf, const char *name, bool *boolean_,
                       bool default_, bool optional)
{
    virConfValuePtr value;

    *boolean_ = default_;
    value = virConfGetValue(conf, name);

    if (value == NULL) {
        if (optional) {
            return 0;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Missing essential config entry '%s'"), name);
            return -1;
        }
    }

    if (value->type == VIR_CONF_STRING) {
        if (value->str == NULL) {
            if (optional) {
                return 0;
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Missing essential config entry '%s'"), name);
                return -1;
            }
        }

        if (STRCASEEQ(value->str, "true")) {
            *boolean_ = 1;
        } else if (STRCASEEQ(value->str, "false")) {
            *boolean_ = 0;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Config entry '%s' must represent a boolean value "
                             "(true|false)"), name);
            return -1;
        }
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Config entry '%s' must be a string"), name);
        return -1;
    }

    return 0;
}



static int
virVMXSCSIDiskNameToControllerAndUnit(const char *name, int *controller, int *unit)
{
    int idx;

    if (! STRPREFIX(name, "sd")) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Expecting domain XML attribute 'dev' of entry "
                         "'devices/disk/target' to start with 'sd'"));
        return -1;
    }

    idx = virDiskNameToIndex(name);

    if (idx < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not parse valid disk index from '%s'"), name);
        return -1;
    }

    /* Each of the 4 SCSI controllers has 1 bus with 15 units each for devices */
    if (idx >= (4 * 15)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("SCSI disk index (parsed from '%s') is too large"), name);
        return -1;
    }

    *controller = idx / 15;
    *unit = idx % 15;

    /* Skip the controller ifself at unit 7 */
    if (*unit >= 7) {
        ++(*unit);
    }

    return 0;
}



static int
virVMXIDEDiskNameToBusAndUnit(const char *name, int *bus, int *unit)
{
    int idx;

    if (! STRPREFIX(name, "hd")) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Expecting domain XML attribute 'dev' of entry "
                         "'devices/disk/target' to start with 'hd'"));
        return -1;
    }

    idx = virDiskNameToIndex(name);

    if (idx < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not parse valid disk index from '%s'"), name);
        return -1;
    }

    /* The IDE controller has 2 buses with 2 units each for devices */
    if (idx >= (2 * 2)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("IDE disk index (parsed from '%s') is too large"), name);
        return -1;
    }

    *bus = idx / 2;
    *unit = idx % 2;

    return 0;
}



static int
virVMXFloppyDiskNameToUnit(const char *name, int *unit)
{
    int idx;

    if (! STRPREFIX(name, "fd")) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Expecting domain XML attribute 'dev' of entry "
                         "'devices/disk/target' to start with 'fd'"));
        return -1;
    }

    idx = virDiskNameToIndex(name);

    if (idx < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not parse valid disk index from '%s'"), name);
        return -1;
    }

    /* The FDC controller has 1 bus with 2 units for devices */
    if (idx >= 2) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Floppy disk index (parsed from '%s') is too large"), name);
        return -1;
    }

    *unit = idx;

    return 0;
}



static int
virVMXVerifyDiskAddress(virDomainXMLOptionPtr xmlopt, virDomainDiskDefPtr disk)
{
    virDomainDiskDef def;
    virDomainDeviceDriveAddressPtr drive;

    memset(&def, 0, sizeof(def));

    if (disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported disk address type '%s'"),
                       virDomainDeviceAddressTypeToString(disk->info.type));
        return -1;
    }

    drive = &disk->info.addr.drive;

    def.dst = disk->dst;
    def.bus = disk->bus;

    if (virDomainDiskDefAssignAddress(xmlopt, &def) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not verify disk address"));
        return -1;
    }

    if (def.info.addr.drive.controller != drive->controller ||
        def.info.addr.drive.bus != drive->bus ||
        def.info.addr.drive.unit != drive->unit) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Disk address %d:%d:%d doesn't match target device '%s'"),
                       drive->controller, drive->bus, drive->unit, disk->dst);
        return -1;
    }

    /* drive->{controller|bus|unit} is unsigned, no >= 0 checks are necessary */
    if (disk->bus == VIR_DOMAIN_DISK_BUS_SCSI) {
        if (drive->controller > 3) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("SCSI controller index %d out of [0..3] range"),
                           drive->controller);
            return -1;
        }

        if (drive->bus != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("SCSI bus index %d out of [0] range"),
                           drive->bus);
            return -1;
        }

        if (drive->unit > 15 || drive->unit == 7) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("SCSI unit index %d out of [0..6,8..15] range"),
                           drive->unit);
            return -1;
        }
    } else if (disk->bus == VIR_DOMAIN_DISK_BUS_IDE) {
        if (drive->controller != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("IDE controller index %d out of [0] range"),
                           drive->controller);
            return -1;
        }

        if (drive->bus > 1) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("IDE bus index %d out of [0..1] range"),
                           drive->bus);
            return -1;
        }

        if (drive->unit > 1) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("IDE unit index %d out of [0..1] range"),
                           drive->unit);
            return -1;
        }
    } else if (disk->bus == VIR_DOMAIN_DISK_BUS_FDC) {
        if (drive->controller != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("FDC controller index %d out of [0] range"),
                           drive->controller);
            return -1;
        }

        if (drive->bus != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("FDC bus index %d out of [0] range"),
                           drive->bus);
            return -1;
        }

        if (drive->unit > 1) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("FDC unit index %d out of [0..1] range"),
                           drive->unit);
            return -1;
        }
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported bus type '%s'"),
                       virDomainDiskBusTypeToString(disk->bus));
        return -1;
    }

    return 0;
}



static int
virVMXHandleLegacySCSIDiskDriverName(virDomainDefPtr def,
                                     virDomainDiskDefPtr disk)
{
    char *tmp;
    int model;
    size_t i;
    virDomainControllerDefPtr controller = NULL;
    const char *driver = virDomainDiskGetDriver(disk);
    char *copy;

    if (disk->bus != VIR_DOMAIN_DISK_BUS_SCSI || !driver) {
        return 0;
    }

    if (VIR_STRDUP(copy, driver) < 0)
        return -1;
    tmp = copy;

    for (; *tmp != '\0'; ++tmp) {
        *tmp = c_tolower(*tmp);
    }

    model = virDomainControllerModelSCSITypeFromString(copy);
    VIR_FREE(copy);

    if (model < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown driver name '%s'"), driver);
        return -1;
    }

    for (i = 0; i < def->ncontrollers; ++i) {
        if (def->controllers[i]->idx == disk->info.addr.drive.controller) {
            controller = def->controllers[i];
            break;
        }
    }

    if (controller == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Missing SCSI controller for index %d"),
                       disk->info.addr.drive.controller);
        return -1;
    }

    if (controller->model == -1) {
        controller->model = model;
    } else if (controller->model != model) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Inconsistent SCSI controller model ('%s' is not '%s') "
                         "for SCSI controller index %d"), driver,
                       virDomainControllerModelSCSITypeToString(controller->model),
                       controller->idx);
        return -1;
    }

    return 0;
}



static int
virVMXGatherSCSIControllers(virVMXContext *ctx, virDomainDefPtr def,
                            int virtualDev[4], bool present[4])
{
    int result = -1;
    size_t i, k;
    virDomainDiskDefPtr disk;
    virDomainControllerDefPtr controller;
    bool controllerHasDisksAttached;
    int count = 0;
    int *autodetectedModels;

    if (VIR_ALLOC_N(autodetectedModels, def->ndisks) < 0)
        return -1;

    for (i = 0; i < def->ncontrollers; ++i) {
        controller = def->controllers[i];

        if (controller->type != VIR_DOMAIN_CONTROLLER_TYPE_SCSI) {
            /* skip non-SCSI controllers */
            continue;
        }

        controllerHasDisksAttached = false;

        for (k = 0; k < def->ndisks; ++k) {
            disk = def->disks[k];

            if (disk->bus == VIR_DOMAIN_DISK_BUS_SCSI &&
                disk->info.addr.drive.controller == controller->idx) {
                controllerHasDisksAttached = true;
                break;
            }
        }

        if (! controllerHasDisksAttached) {
            /* skip SCSI controllers without attached disks */
            continue;
        }

        if (controller->model == VIR_DOMAIN_CONTROLLER_MODEL_SCSI_AUTO &&
            ctx->autodetectSCSIControllerModel != NULL) {
            count = 0;

            /* try to autodetect the SCSI controller model by collecting
             * SCSI controller model of all disks attached to this controller */
            for (k = 0; k < def->ndisks; ++k) {
                disk = def->disks[k];

                if (disk->bus == VIR_DOMAIN_DISK_BUS_SCSI &&
                    disk->info.addr.drive.controller == controller->idx) {
                    if (ctx->autodetectSCSIControllerModel
                               (disk, &autodetectedModels[count],
                                ctx->opaque) < 0) {
                        goto cleanup;
                    }

                    ++count;
                }
            }

            /* autodetection fails when the disks attached to one controller
             * have inconsistent SCSI controller models */
            for (k = 0; k < count; ++k) {
                if (autodetectedModels[k] != autodetectedModels[0]) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Disks on SCSI controller %d have inconsistent "
                                     "controller models, cannot autodetect model"),
                                   controller->idx);
                    goto cleanup;
                }
            }

            controller->model = autodetectedModels[0];
        }

        if (controller->model != -1 &&
            controller->model != VIR_DOMAIN_CONTROLLER_MODEL_SCSI_BUSLOGIC &&
            controller->model != VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC &&
            controller->model != VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSISAS1068 &&
            controller->model != VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VMPVSCSI) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Expecting domain XML attribute 'model' of entry "
                             "'controller' to be 'buslogic' or 'lsilogic' or "
                             "'lsisas1068' or 'vmpvscsi' but found '%s'"),
                           virDomainControllerModelSCSITypeToString(controller->model));
            goto cleanup;
        }

        present[controller->idx] = true;
        virtualDev[controller->idx] = controller->model;
    }

    result = 0;

 cleanup:
    VIR_FREE(autodetectedModels);

    return result;
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VMX -> Domain XML
 */

virDomainDefPtr
virVMXParseConfig(virVMXContext *ctx,
                  virDomainXMLOptionPtr xmlopt,
                  const char *vmx)
{
    bool success = false;
    virConfPtr conf = NULL;
    char *encoding = NULL;
    char *utf8;
    virDomainDefPtr def = NULL;
    long long config_version = 0;
    long long virtualHW_version = 0;
    long long memsize = 0;
    long long sched_mem_max = 0;
    long long sched_mem_minsize = 0;
    long long numvcpus = 0;
    char *sched_cpu_affinity = NULL;
    char *sched_cpu_shares = NULL;
    char *guestOS = NULL;
    bool smbios_reflecthost = false;
    int controller;
    int bus;
    int port;
    bool present;
    int scsi_virtualDev[4] = { -1, -1, -1, -1 };
    int unit;
    bool hgfs_disabled = true;
    long long sharedFolder_maxNum = 0;
    int cpumasklen;

    if (ctx->parseFileName == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("virVMXContext has no parseFileName function set"));
        return NULL;
    }

    conf = virConfReadMem(vmx, strlen(vmx), VIR_CONF_FLAG_VMX_FORMAT);

    if (conf == NULL) {
        return NULL;
    }

    /* vmx:.encoding */
    if (virVMXGetConfigString(conf, ".encoding", &encoding, true) < 0) {
        goto cleanup;
    }

    if (encoding == NULL || STRCASEEQ(encoding, "UTF-8")) {
        /* nothing */
    } else {
        virConfFree(conf);
        conf = NULL;

        utf8 = virVMXConvertToUTF8(encoding, vmx);

        if (utf8 == NULL) {
            goto cleanup;
        }

        conf = virConfReadMem(utf8, strlen(utf8), VIR_CONF_FLAG_VMX_FORMAT);

        VIR_FREE(utf8);

        if (conf == NULL) {
            goto cleanup;
        }
    }

    /* Allocate domain def */
    if (VIR_ALLOC(def) < 0)
        goto cleanup;

    def->virtType = VIR_DOMAIN_VIRT_VMWARE;
    def->id = -1;

    /* vmx:config.version */
    if (virVMXGetConfigLong(conf, "config.version", &config_version, 0,
                            false) < 0) {
        goto cleanup;
    }

    if (config_version != 8) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Expecting VMX entry 'config.version' to be 8 but found "
                         "%lld"), config_version);
        goto cleanup;
    }

    /* vmx:virtualHW.version */
    if (virVMXGetConfigLong(conf, "virtualHW.version", &virtualHW_version, 0,
                            false) < 0) {
        goto cleanup;
    }

    if (virtualHW_version != 4 && virtualHW_version != 7 &&
        virtualHW_version != 8 && virtualHW_version != 9) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Expecting VMX entry 'virtualHW.version' to be "
                         "4, 7, 8 or 9 but found %lld"),
                       virtualHW_version);
        goto cleanup;
    }

    /* vmx:uuid.bios -> def:uuid */
    /* FIXME: Need to handle 'uuid.action = "create"' */
    if (virVMXGetConfigUUID(conf, "uuid.bios", def->uuid, true) < 0) {
        goto cleanup;
    }

    /* vmx:displayName -> def:name */
    if (virVMXGetConfigString(conf, "displayName", &def->name, true) < 0) {
        goto cleanup;
    }

    if (def->name != NULL) {
        if (virVMXUnescapeHexPercent(def->name) < 0 ||
            virVMXUnescapeHexPipe(def->name) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("VMX entry 'name' contains invalid escape sequence"));
            goto cleanup;
        }
    }

    /* vmx:annotation -> def:description */
    if (virVMXGetConfigString(conf, "annotation", &def->description,
                              true) < 0) {
        goto cleanup;
    }

    if (def->description != NULL) {
        if (virVMXUnescapeHexPipe(def->description) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("VMX entry 'annotation' contains invalid escape "
                             "sequence"));
            goto cleanup;
        }
    }

    /* vmx:memsize -> def:mem.max_balloon */
    if (virVMXGetConfigLong(conf, "memsize", &memsize, 32, true) < 0) {
        goto cleanup;
    }

    if (memsize <= 0 || memsize % 4 != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Expecting VMX entry 'memsize' to be an unsigned "
                         "integer (multiple of 4) but found %lld"), memsize);
        goto cleanup;
    }

    def->mem.max_balloon = memsize * 1024; /* Scale from megabytes to kilobytes */

    /* vmx:sched.mem.max -> def:mem.cur_balloon */
    if (virVMXGetConfigLong(conf, "sched.mem.max", &sched_mem_max, memsize,
                            true) < 0) {
        goto cleanup;
    }

    if (sched_mem_max < 0) {
        sched_mem_max = memsize;
    }

    def->mem.cur_balloon = sched_mem_max * 1024; /* Scale from megabytes to kilobytes */

    if (def->mem.cur_balloon > def->mem.max_balloon) {
        def->mem.cur_balloon = def->mem.max_balloon;
    }

    /* vmx:sched.mem.minsize -> def:mem.min_guarantee */
    if (virVMXGetConfigLong(conf, "sched.mem.minsize", &sched_mem_minsize, 0,
                            true) < 0) {
        goto cleanup;
    }

    if (sched_mem_minsize < 0) {
        sched_mem_minsize = 0;
    }

    def->mem.min_guarantee = sched_mem_minsize * 1024; /* Scale from megabytes to kilobytes */

    if (def->mem.min_guarantee > def->mem.max_balloon) {
        def->mem.min_guarantee = def->mem.max_balloon;
    }

    /* vmx:numvcpus -> def:vcpus */
    if (virVMXGetConfigLong(conf, "numvcpus", &numvcpus, 1, true) < 0) {
        goto cleanup;
    }

    if (numvcpus <= 0 || (numvcpus % 2 != 0 && numvcpus != 1)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Expecting VMX entry 'numvcpus' to be an unsigned "
                         "integer (1 or a multiple of 2) but found %lld"), numvcpus);
        goto cleanup;
    }

    def->maxvcpus = def->vcpus = numvcpus;

    /* vmx:sched.cpu.affinity -> def:cpumask */
    /* NOTE: maps to VirtualMachine:config.cpuAffinity.affinitySet */
    if (virVMXGetConfigString(conf, "sched.cpu.affinity", &sched_cpu_affinity,
                              true) < 0) {
        goto cleanup;
    }

    if (sched_cpu_affinity != NULL && STRCASENEQ(sched_cpu_affinity, "all")) {
        const char *current = sched_cpu_affinity;
        int number, count = 0;

        cpumasklen = 0;

        def->cpumask = virBitmapNew(VIR_DOMAIN_CPUMASK_LEN);
        if (!def->cpumask)
            goto cleanup;

        while (*current != '\0') {
            virSkipSpaces(&current);

            number = virParseNumber(&current);

            if (number < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Expecting VMX entry 'sched.cpu.affinity' to be "
                                 "a comma separated list of unsigned integers but "
                                 "found '%s'"), sched_cpu_affinity);
                goto cleanup;
            }

            if (number >= VIR_DOMAIN_CPUMASK_LEN) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("VMX entry 'sched.cpu.affinity' contains a %d, "
                                 "this value is too large"), number);
                goto cleanup;
            }

            if (number + 1 > cpumasklen) {
                cpumasklen = number + 1;
            }

            ignore_value(virBitmapSetBit(def->cpumask, number));
            ++count;

            virSkipSpaces(&current);

            if (*current == ',') {
                ++current;
            } else if (*current == '\0') {
                break;
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Expecting VMX entry 'sched.cpu.affinity' to be "
                                 "a comma separated list of unsigned integers but "
                                 "found '%s'"), sched_cpu_affinity);
                goto cleanup;
            }

            virSkipSpaces(&current);
        }

        if (count < numvcpus) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Expecting VMX entry 'sched.cpu.affinity' to contain "
                             "at least as many values as 'numvcpus' (%lld) but "
                             "found only %d value(s)"), numvcpus, count);
            goto cleanup;
        }
    }

    /* vmx:sched.cpu.shares -> def:cputune.shares */
    if (virVMXGetConfigString(conf, "sched.cpu.shares", &sched_cpu_shares,
                              true) < 0) {
        goto cleanup;
    }

    if (sched_cpu_shares != NULL) {
        /* See http://www.vmware.com/support/developer/vc-sdk/visdk41pubs/ApiReference/vim.SharesInfo.Level.html */
        if (STRCASEEQ(sched_cpu_shares, "low")) {
            def->cputune.shares = def->vcpus * 500;
        } else if (STRCASEEQ(sched_cpu_shares, "normal")) {
            def->cputune.shares = def->vcpus * 1000;
        } else if (STRCASEEQ(sched_cpu_shares, "high")) {
            def->cputune.shares = def->vcpus * 2000;
        } else if (virStrToLong_ul(sched_cpu_shares, NULL, 10,
                                   &def->cputune.shares) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Expecting VMX entry 'sched.cpu.shares' to be an "
                             "unsigned integer or 'low', 'normal' or 'high' but "
                             "found '%s'"), sched_cpu_shares);
            goto cleanup;
        }
        def->cputune.sharesSpecified = true;
    }

    /* def:lifecycle */
    def->onReboot = VIR_DOMAIN_LIFECYCLE_RESTART;
    def->onPoweroff = VIR_DOMAIN_LIFECYCLE_DESTROY;
    def->onCrash = VIR_DOMAIN_LIFECYCLE_DESTROY;

    /* def:os */
    if (VIR_STRDUP(def->os.type, "hvm") < 0)
        goto cleanup;

    /* vmx:guestOS -> def:os.arch */
    if (virVMXGetConfigString(conf, "guestOS", &guestOS, true) < 0) {
        goto cleanup;
    }

    if (guestOS != NULL && virFileHasSuffix(guestOS, "-64")) {
        def->os.arch = VIR_ARCH_X86_64;
    } else {
        def->os.arch = VIR_ARCH_I686;
    }

    /* vmx:smbios.reflecthost -> def:os.smbios_mode */
    if (virVMXGetConfigBoolean(conf, "smbios.reflecthost",
                               &smbios_reflecthost, false, true) < 0) {
        goto cleanup;
    }

    if (smbios_reflecthost) {
        def->os.smbios_mode = VIR_DOMAIN_SMBIOS_HOST;
    }

    /* def:features */
    /* FIXME */

    /* def:clock */
    /* FIXME */

    /* def:graphics */
    if (VIR_ALLOC_N(def->graphics, 1) < 0)
        goto cleanup;

    def->ngraphics = 0;

    if (virVMXParseVNC(conf, &def->graphics[def->ngraphics]) < 0) {
        goto cleanup;
    }

    if (def->graphics[def->ngraphics] != NULL) {
        ++def->ngraphics;
    }

    /* def:disks: 4 * 15 scsi + 2 * 2 ide + 2 floppy = 66 */
    if (VIR_ALLOC_N(def->disks, 66) < 0)
        goto cleanup;

    def->ndisks = 0;

    /* def:disks (scsi) */
    for (controller = 0; controller < 4; ++controller) {
        if (virVMXParseSCSIController(conf, controller, &present,
                                      &scsi_virtualDev[controller]) < 0) {
            goto cleanup;
        }

        if (! present) {
            continue;
        }

        for (unit = 0; unit < 16; ++unit) {
            if (unit == 7) {
                /*
                 * SCSI unit 7 is assigned to the SCSI controller and cannot be
                 * used for disk devices.
                 */
                continue;
            }

            if (virVMXParseDisk(ctx, xmlopt, conf, VIR_DOMAIN_DISK_DEVICE_DISK,
                                VIR_DOMAIN_DISK_BUS_SCSI, controller, unit,
                                &def->disks[def->ndisks]) < 0) {
                goto cleanup;
            }

            if (def->disks[def->ndisks] != NULL) {
                ++def->ndisks;
                continue;
            }

            if (virVMXParseDisk(ctx, xmlopt, conf, VIR_DOMAIN_DISK_DEVICE_CDROM,
                                 VIR_DOMAIN_DISK_BUS_SCSI, controller, unit,
                                 &def->disks[def->ndisks]) < 0) {
                goto cleanup;
            }

            if (def->disks[def->ndisks] != NULL) {
                ++def->ndisks;
            }
        }
    }

    /* def:disks (ide) */
    for (bus = 0; bus < 2; ++bus) {
        for (unit = 0; unit < 2; ++unit) {
            if (virVMXParseDisk(ctx, xmlopt, conf, VIR_DOMAIN_DISK_DEVICE_DISK,
                                VIR_DOMAIN_DISK_BUS_IDE, bus, unit,
                                &def->disks[def->ndisks]) < 0) {
                goto cleanup;
            }

            if (def->disks[def->ndisks] != NULL) {
                ++def->ndisks;
                continue;
            }

            if (virVMXParseDisk(ctx, xmlopt, conf, VIR_DOMAIN_DISK_DEVICE_CDROM,
                                VIR_DOMAIN_DISK_BUS_IDE, bus, unit,
                                &def->disks[def->ndisks]) < 0) {
                goto cleanup;
            }

            if (def->disks[def->ndisks] != NULL) {
                ++def->ndisks;
            }
        }
    }

    /* def:disks (floppy) */
    for (unit = 0; unit < 2; ++unit) {
        if (virVMXParseDisk(ctx, xmlopt, conf, VIR_DOMAIN_DISK_DEVICE_FLOPPY,
                            VIR_DOMAIN_DISK_BUS_FDC, 0, unit,
                            &def->disks[def->ndisks]) < 0) {
            goto cleanup;
        }

        if (def->disks[def->ndisks] != NULL) {
            ++def->ndisks;
        }
    }

    /* def:controllers */
    if (virDomainDefAddImplicitControllers(def) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Could not add controllers"));
        goto cleanup;
    }

    for (controller = 0; controller < def->ncontrollers; ++controller) {
        if (def->controllers[controller]->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI) {
            if (def->controllers[controller]->idx > 3) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("SCSI controller index %d out of [0..3] range"),
                               def->controllers[controller]->idx);
                goto cleanup;
            }

            def->controllers[controller]->model =
              scsi_virtualDev[def->controllers[controller]->idx];
        }
    }

    /* def:fss */
    if (virVMXGetConfigBoolean(conf, "isolation.tools.hgfs.disable",
                               &hgfs_disabled, true, true) < 0) {
        goto cleanup;
    }

    if (!hgfs_disabled) {
        if (virVMXGetConfigLong(conf, "sharedFolder.maxNum", &sharedFolder_maxNum,
                                0, true) < 0) {
            goto cleanup;
        }

        if (sharedFolder_maxNum > 0) {
            int number;

            if (VIR_ALLOC_N(def->fss, sharedFolder_maxNum) < 0)
                goto cleanup;

            def->nfss = 0;

            for (number = 0; number < sharedFolder_maxNum; ++number) {
                if (virVMXParseFileSystem(conf, number,
                                          &def->fss[def->nfss]) < 0) {
                    goto cleanup;
                }

                if (def->fss[def->nfss] != NULL) {
                    ++def->nfss;
                }
            }
        }
    }

    /* def:nets */
    if (VIR_ALLOC_N(def->nets, 4) < 0)
        goto cleanup;

    def->nnets = 0;

    for (controller = 0; controller < 4; ++controller) {
        if (virVMXParseEthernet(conf, controller,
                                &def->nets[def->nnets]) < 0) {
            goto cleanup;
        }

        if (def->nets[def->nnets] != NULL) {
            ++def->nnets;
        }
    }

    /* def:inputs */
    /* FIXME */

    /* def:videos */
    if (VIR_ALLOC_N(def->videos, 1) < 0)
        goto cleanup;

    def->nvideos = 0;

    if (virVMXParseSVGA(conf, &def->videos[def->nvideos]) < 0) {
        goto cleanup;
    }

    def->nvideos = 1;

    /* def:sounds */
    /* FIXME */

    /* def:hostdevs */
    /* FIXME */

    /* def:serials */
    if (VIR_ALLOC_N(def->serials, 4) < 0)
        goto cleanup;

    def->nserials = 0;

    for (port = 0; port < 4; ++port) {
        if (virVMXParseSerial(ctx, conf, port,
                              &def->serials[def->nserials]) < 0) {
            goto cleanup;
        }

        if (def->serials[def->nserials] != NULL) {
            ++def->nserials;
        }
    }

    /* def:parallels */
    if (VIR_ALLOC_N(def->parallels, 3) < 0)
        goto cleanup;

    def->nparallels = 0;

    for (port = 0; port < 3; ++port) {
        if (virVMXParseParallel(ctx, conf, port,
                                &def->parallels[def->nparallels]) < 0) {
            goto cleanup;
        }

        if (def->parallels[def->nparallels] != NULL) {
            ++def->nparallels;
        }
    }

    success = true;

 cleanup:
    if (! success) {
        virDomainDefFree(def);
        def = NULL;
    }

    virConfFree(conf);
    VIR_FREE(encoding);
    VIR_FREE(sched_cpu_affinity);
    VIR_FREE(sched_cpu_shares);
    VIR_FREE(guestOS);

    return def;
}



int
virVMXParseVNC(virConfPtr conf, virDomainGraphicsDefPtr *def)
{
    bool enabled = false;
    long long port = 0;
    char *listenAddr = NULL;

    if (def == NULL || *def != NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (virVMXGetConfigBoolean(conf, "RemoteDisplay.vnc.enabled", &enabled,
                               false, true) < 0) {
        return -1;
    }

    if (! enabled) {
        return 0;
    }

    if (VIR_ALLOC(*def) < 0)
        goto failure;

    (*def)->type = VIR_DOMAIN_GRAPHICS_TYPE_VNC;

    if (virVMXGetConfigLong(conf, "RemoteDisplay.vnc.port", &port, -1,
                            true) < 0 ||
        virVMXGetConfigString(conf, "RemoteDisplay.vnc.ip",
                              &listenAddr, true) < 0 ||
        virVMXGetConfigString(conf, "RemoteDisplay.vnc.keymap",
                              &(*def)->data.vnc.keymap, true) < 0 ||
        virVMXGetConfigString(conf, "RemoteDisplay.vnc.password",
                              &(*def)->data.vnc.auth.passwd, true) < 0) {
        goto failure;
    }

    if (listenAddr) {
        if (virDomainGraphicsListenSetAddress(*def, 0, listenAddr, -1, true) < 0)
            goto failure;
        VIR_FREE(listenAddr);
    }

    if (port < 0) {
        VIR_WARN("VNC is enabled but VMX entry 'RemoteDisplay.vnc.port' "
                  "is missing, the VNC port is unknown");

        (*def)->data.vnc.port = 0;
        (*def)->data.vnc.autoport = true;
    } else {
        if (port < 5900 || port > 5964) {
            VIR_WARN("VNC port %lld it out of [5900..5964] range", port);
        }

        (*def)->data.vnc.port = port;
        (*def)->data.vnc.autoport = false;
    }

    return 0;

 failure:
    VIR_FREE(listenAddr);
    virDomainGraphicsDefFree(*def);
    *def = NULL;

    return -1;
}



int
virVMXParseSCSIController(virConfPtr conf, int controller, bool *present,
                          int *virtualDev)
{
    int result = -1;
    char present_name[32];
    char virtualDev_name[32];
    char *virtualDev_string = NULL;
    char *tmp;

    if (virtualDev == NULL || *virtualDev != -1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (controller < 0 || controller > 3) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("SCSI controller index %d out of [0..3] range"),
                       controller);
        return -1;
    }

    snprintf(present_name, sizeof(present_name), "scsi%d.present", controller);
    snprintf(virtualDev_name, sizeof(virtualDev_name), "scsi%d.virtualDev",
             controller);

    if (virVMXGetConfigBoolean(conf, present_name, present, false, true) < 0) {
        goto cleanup;
    }

    if (! *present) {
        result = 0;
        goto cleanup;
    }

    if (virVMXGetConfigString(conf, virtualDev_name, &virtualDev_string,
                              true) < 0) {
        goto cleanup;
    }

    if (virtualDev_string != NULL) {
        tmp = virtualDev_string;

        for (; *tmp != '\0'; ++tmp) {
            *tmp = c_tolower(*tmp);
        }

        *virtualDev = virVMXControllerModelSCSITypeFromString(virtualDev_string);

        if (*virtualDev == -1 ||
            (*virtualDev != VIR_DOMAIN_CONTROLLER_MODEL_SCSI_BUSLOGIC &&
             *virtualDev != VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC &&
             *virtualDev != VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSISAS1068 &&
             *virtualDev != VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VMPVSCSI)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Expecting VMX entry '%s' to be 'buslogic' or 'lsilogic' "
                             "or 'lsisas1068' or 'pvscsi' but found '%s'"),
                           virtualDev_name, virtualDev_string);
            goto cleanup;
        }
    }

    result = 0;

 cleanup:
    VIR_FREE(virtualDev_string);

    return result;
}



int
virVMXParseDisk(virVMXContext *ctx, virDomainXMLOptionPtr xmlopt, virConfPtr conf,
                int device, int busType, int controllerOrBus, int unit,
                virDomainDiskDefPtr *def)
{
    /*
     *          device = {VIR_DOMAIN_DISK_DEVICE_DISK,
     *                    VIR_DOMAIN_DISK_DEVICE_CDROM,
     *                    VIR_DOMAIN_DISK_DEVICE_LUN}
     *         busType = VIR_DOMAIN_DISK_BUS_SCSI
     * controllerOrBus = [0..3] -> controller
     *            unit = [0..6,8..15]
     *
     *          device = {VIR_DOMAIN_DISK_DEVICE_DISK,
     *                    VIR_DOMAIN_DISK_DEVICE_CDROM,
     *                    VIR_DOMAIN_DISK_DEVICE_LUN}
     *         busType = VIR_DOMAIN_DISK_BUS_IDE
     * controllerOrBus = [0..1] -> bus
     *            unit = [0..1]
     *
     *          device = VIR_DOMAIN_DISK_DEVICE_FLOPPY
     *         busType = VIR_DOMAIN_DISK_BUS_FDC
     * controllerOrBus = [0]
     *            unit = [0..1]
     */

    int result = -1;
    char *prefix = NULL;

    char present_name[32] = "";
    bool present = false;

    char startConnected_name[32] = "";
    bool startConnected = false;

    char deviceType_name[32] = "";
    char *deviceType = NULL;

    char clientDevice_name[32] = "";
    bool clientDevice = false;

    char fileType_name[32] = "";
    char *fileType = NULL;

    char fileName_name[32] = "";
    char *fileName = NULL;

    char writeThrough_name[32] = "";
    bool writeThrough = false;

    char mode_name[32] = "";
    char *mode = NULL;

    if (def == NULL || *def != NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (VIR_ALLOC(*def) < 0)
        return -1;

    (*def)->device = device;
    (*def)->bus = busType;

    /* def:dst, def:driverName */
    if (device == VIR_DOMAIN_DISK_DEVICE_DISK ||
        device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
        if (busType == VIR_DOMAIN_DISK_BUS_SCSI) {
            if (controllerOrBus < 0 || controllerOrBus > 3) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("SCSI controller index %d out of [0..3] range"),
                               controllerOrBus);
                goto cleanup;
            }

            if (unit < 0 || unit > 15 || unit == 7) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("SCSI unit index %d out of [0..6,8..15] range"),
                               unit);
                goto cleanup;
            }

            if (virAsprintf(&prefix, "scsi%d:%d", controllerOrBus, unit) < 0)
                goto cleanup;

            (*def)->dst =
               virIndexToDiskName
                 (controllerOrBus * 15 + (unit < 7 ? unit : unit - 1), "sd");

            if ((*def)->dst == NULL) {
                goto cleanup;
            }
        } else if (busType == VIR_DOMAIN_DISK_BUS_IDE) {
            if (controllerOrBus < 0 || controllerOrBus > 1) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("IDE bus index %d out of [0..1] range"),
                               controllerOrBus);
                goto cleanup;
            }

            if (unit < 0 || unit > 1) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("IDE unit index %d out of [0..1] range"), unit);
                goto cleanup;
            }

            if (virAsprintf(&prefix, "ide%d:%d", controllerOrBus, unit) < 0)
                goto cleanup;

            (*def)->dst = virIndexToDiskName(controllerOrBus * 2 + unit, "hd");

            if ((*def)->dst == NULL) {
                goto cleanup;
            }
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported bus type '%s' for device type '%s'"),
                           virDomainDiskBusTypeToString(busType),
                           virDomainDiskDeviceTypeToString(device));
            goto cleanup;
        }
    } else if (device == VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
        if (busType == VIR_DOMAIN_DISK_BUS_FDC) {
            if (controllerOrBus != 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("FDC controller index %d out of [0] range"),
                               controllerOrBus);
                goto cleanup;
            }

            if (unit < 0 || unit > 1) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("FDC unit index %d out of [0..1] range"),
                               unit);
                goto cleanup;
            }

            if (virAsprintf(&prefix, "floppy%d", unit) < 0)
                goto cleanup;

            (*def)->dst = virIndexToDiskName(unit, "fd");

            if ((*def)->dst == NULL) {
                goto cleanup;
            }
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported bus type '%s' for device type '%s'"),
                           virDomainDiskBusTypeToString(busType),
                           virDomainDiskDeviceTypeToString(device));
            goto cleanup;
        }
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported device type '%s'"),
                       virDomainDiskDeviceTypeToString(device));
        goto cleanup;
    }

    VMX_BUILD_NAME(present);
    VMX_BUILD_NAME(startConnected);
    VMX_BUILD_NAME(deviceType);
    VMX_BUILD_NAME(clientDevice);
    VMX_BUILD_NAME(fileType);
    VMX_BUILD_NAME(fileName);
    VMX_BUILD_NAME(writeThrough);
    VMX_BUILD_NAME(mode);

    /* vmx:present */
    if (virVMXGetConfigBoolean(conf, present_name, &present, false, true) < 0) {
        goto cleanup;
    }

    /* vmx:startConnected */
    if (virVMXGetConfigBoolean(conf, startConnected_name, &startConnected,
                               true, true) < 0) {
        goto cleanup;
    }

    /* FIXME: Need to distiguish between active and inactive domains here */
    if (! present/* && ! startConnected*/) {
        goto ignore;
    }

    /* vmx:deviceType -> def:type */
    if (virVMXGetConfigString(conf, deviceType_name, &deviceType, true) < 0) {
        goto cleanup;
    }

    /* vmx:clientDevice */
    if (virVMXGetConfigBoolean(conf, clientDevice_name, &clientDevice, false,
                               true) < 0) {
        goto cleanup;
    }

    /* vmx:mode -> def:transient */
    if (virVMXGetConfigString(conf, mode_name, &mode, true) < 0) {
        goto cleanup;
    }

    if (clientDevice) {
        /*
         * Just ignore devices in client mode, because I have no clue how to
         * handle them (e.g. assign an image) without the VI Client GUI.
         */
        goto ignore;
    }

    /* vmx:fileType -> def:type */
    if (virVMXGetConfigString(conf, fileType_name, &fileType, true) < 0) {
        goto cleanup;
    }

    /* vmx:fileName -> def:src, def:type */
    if (virVMXGetConfigString(conf, fileName_name, &fileName, false) < 0) {
        goto cleanup;
    }

    /* vmx:writeThrough -> def:cachemode */
    if (virVMXGetConfigBoolean(conf, writeThrough_name, &writeThrough, false,
                               true) < 0) {
        goto cleanup;
    }

    /* Setup virDomainDiskDef */
    if (device == VIR_DOMAIN_DISK_DEVICE_DISK) {
        if (virFileHasSuffix(fileName, ".vmdk")) {
            char *tmp;

            if (deviceType != NULL) {
                if (busType == VIR_DOMAIN_DISK_BUS_SCSI &&
                    STRCASENEQ(deviceType, "scsi-hardDisk") &&
                    STRCASENEQ(deviceType, "disk")) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Expecting VMX entry '%s' to be 'scsi-hardDisk' "
                                     "or 'disk' but found '%s'"), deviceType_name,
                                   deviceType);
                    goto cleanup;
                } else if (busType == VIR_DOMAIN_DISK_BUS_IDE &&
                           STRCASENEQ(deviceType, "ata-hardDisk") &&
                           STRCASENEQ(deviceType, "disk")) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Expecting VMX entry '%s' to be 'ata-hardDisk' "
                                     "or 'disk' but found '%s'"), deviceType_name,
                                   deviceType);
                    goto cleanup;
                }
            }

            virDomainDiskSetType(*def, VIR_DOMAIN_DISK_TYPE_FILE);
            if (!(tmp = ctx->parseFileName(fileName, ctx->opaque)))
                goto cleanup;
            if (virDomainDiskSetSource(*def, tmp) < 0) {
                VIR_FREE(tmp);
                goto cleanup;
            }
            VIR_FREE(tmp);
            (*def)->cachemode = writeThrough ? VIR_DOMAIN_DISK_CACHE_WRITETHRU
                                             : VIR_DOMAIN_DISK_CACHE_DEFAULT;
            if (mode)
                (*def)->transient = STRCASEEQ(mode,
                                              "independent-nonpersistent");
        } else if (virFileHasSuffix(fileName, ".iso") ||
                   STRCASEEQ(deviceType, "atapi-cdrom") ||
                   STRCASEEQ(deviceType, "cdrom-raw")) {
            /*
             * This function was called in order to parse a harddisk device,
             * but .iso files, 'atapi-cdrom', and 'cdrom-raw' devices are for
             * CDROM devices only. Just ignore it, another call to this
             * function to parse a CDROM device may handle it.
             */
            goto ignore;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid or not yet handled value '%s' "
                             "for VMX entry '%s' for device type '%s'"),
                             fileName, fileName_name,
                             deviceType ? deviceType : "unknown");
            goto cleanup;
        }
    } else if (device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
        if (virFileHasSuffix(fileName, ".iso")) {
            char *tmp;

            if (deviceType != NULL) {
                if (STRCASENEQ(deviceType, "cdrom-image")) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Expecting VMX entry '%s' to be 'cdrom-image' "
                                     "but found '%s'"), deviceType_name, deviceType);
                    goto cleanup;
                }
            }

            virDomainDiskSetType(*def, VIR_DOMAIN_DISK_TYPE_FILE);
            if (!(tmp = ctx->parseFileName(fileName, ctx->opaque)))
                goto cleanup;
            if (virDomainDiskSetSource(*def, tmp) < 0) {
                VIR_FREE(tmp);
                goto cleanup;
            }
            VIR_FREE(tmp);
        } else if (virFileHasSuffix(fileName, ".vmdk")) {
            /*
             * This function was called in order to parse a CDROM device, but
             * .vmdk files are for harddisk devices only. Just ignore it,
             * another call to this function to parse a harddisk device may
             * handle it.
             */
            goto ignore;
        } else if (STRCASEEQ(deviceType, "atapi-cdrom")) {
            virDomainDiskSetType(*def, VIR_DOMAIN_DISK_TYPE_BLOCK);

            if (STRCASEEQ(fileName, "auto detect")) {
                ignore_value(virDomainDiskSetSource(*def, NULL));
                (*def)->startupPolicy = VIR_DOMAIN_STARTUP_POLICY_OPTIONAL;
            } else if (virDomainDiskSetSource(*def, fileName) < 0) {
                goto cleanup;
            }
        } else if (STRCASEEQ(deviceType, "cdrom-raw")) {
            /* Raw access CD-ROMs actually are device='lun' */
            (*def)->device = VIR_DOMAIN_DISK_DEVICE_LUN;
            virDomainDiskSetType(*def, VIR_DOMAIN_DISK_TYPE_BLOCK);

            if (STRCASEEQ(fileName, "auto detect")) {
                ignore_value(virDomainDiskSetSource(*def, NULL));
                (*def)->startupPolicy = VIR_DOMAIN_STARTUP_POLICY_OPTIONAL;
            } else if (virDomainDiskSetSource(*def, fileName) < 0) {
                goto cleanup;
            }
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid or not yet handled value '%s' "
                             "for VMX entry '%s' for device type '%s'"),
                             fileName, fileName_name,
                             deviceType ? deviceType : "unknown");
            goto cleanup;
        }
    } else if (device == VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
        if (fileType != NULL && STRCASEEQ(fileType, "device")) {
            virDomainDiskSetType(*def, VIR_DOMAIN_DISK_TYPE_BLOCK);
            if (virDomainDiskSetSource(*def, fileName) < 0)
                goto cleanup;
        } else if (fileType != NULL && STRCASEEQ(fileType, "file")) {
            char *tmp;

            virDomainDiskSetType(*def, VIR_DOMAIN_DISK_TYPE_FILE);
            if (!(tmp = ctx->parseFileName(fileName, ctx->opaque)))
                goto cleanup;
            if (virDomainDiskSetSource(*def, tmp) < 0) {
                VIR_FREE(tmp);
                goto cleanup;
            }
            VIR_FREE(tmp);
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid or not yet handled value '%s' "
                             "for VMX entry '%s' for device type '%s'"),
                             fileName, fileName_name,
                             deviceType ? deviceType : "unknown");
            goto cleanup;
        }
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, _("Unsupported device type '%s'"),
                       virDomainDiskDeviceTypeToString(device));
        goto cleanup;
    }

    if (virDomainDiskDefAssignAddress(xmlopt, *def) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not assign address to disk '%s'"),
                       virDomainDiskGetSource(*def));
        goto cleanup;
    }

    result = 0;

 cleanup:
    if (result < 0) {
        virDomainDiskDefFree(*def);
        *def = NULL;
    }

    VIR_FREE(prefix);
    VIR_FREE(deviceType);
    VIR_FREE(fileType);
    VIR_FREE(fileName);
    VIR_FREE(mode);

    return result;

 ignore:
    virDomainDiskDefFree(*def);
    *def = NULL;

    result = 0;

    goto cleanup;
}



int virVMXParseFileSystem(virConfPtr conf, int number, virDomainFSDefPtr *def)
{
    int result = -1;
    char prefix[48] = "";

    char present_name[48] = "";
    bool present = false;

    char enabled_name[48] = "";
    bool enabled = false;

    char hostPath_name[48] = "";
    char *hostPath = NULL;

    char guestName_name[48] = "";
    char *guestName = NULL;

    char writeAccess_name[48] = "";
    bool writeAccess = false;

    if (def == NULL || *def != NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (VIR_ALLOC(*def) < 0)
        return -1;

    (*def)->type = VIR_DOMAIN_FS_TYPE_MOUNT;

    snprintf(prefix, sizeof(prefix), "sharedFolder%d", number);

    VMX_BUILD_NAME(present);
    VMX_BUILD_NAME(enabled);
    VMX_BUILD_NAME(hostPath);
    VMX_BUILD_NAME(guestName);
    VMX_BUILD_NAME(writeAccess);

    /* vmx:present */
    if (virVMXGetConfigBoolean(conf, present_name, &present, false, true) < 0) {
        goto cleanup;
    }

    /* vmx:enabled */
    if (virVMXGetConfigBoolean(conf, enabled_name, &enabled, false, true) < 0) {
        goto cleanup;
    }

    if (!(present && enabled)) {
        goto ignore;
    }

    /* vmx:hostPath */
    if (virVMXGetConfigString(conf, hostPath_name, &hostPath, false) < 0) {
        goto cleanup;
    }

    (*def)->src = hostPath;
    hostPath = NULL;

    /* vmx:guestName */
    if (virVMXGetConfigString(conf, guestName_name, &guestName, false) < 0) {
        goto cleanup;
    }

    (*def)->dst = guestName;
    guestName = NULL;

    /* vmx:writeAccess */
    if (virVMXGetConfigBoolean(conf, writeAccess_name, &writeAccess, false,
                               true) < 0) {
        goto cleanup;
    }

    (*def)->readonly = !writeAccess;

    result = 0;

 cleanup:
    if (result < 0) {
        virDomainFSDefFree(*def);
        *def = NULL;
    }

    VIR_FREE(hostPath);
    VIR_FREE(guestName);

    return result;

 ignore:
    virDomainFSDefFree(*def);
    *def = NULL;

    result = 0;

    goto cleanup;
}



int
virVMXParseEthernet(virConfPtr conf, int controller, virDomainNetDefPtr *def)
{
    int result = -1;
    char prefix[48] = "";

    char present_name[48] = "";
    bool present = false;

    char startConnected_name[48] = "";
    bool startConnected = false;

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

    char features_name[48] = "";
    long long features = 0;

    char vnet_name[48] = "";
    char *vnet = NULL;

    char networkName_name[48] = "";
    char *networkName = NULL;

    if (def == NULL || *def != NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (controller < 0 || controller > 3) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Ethernet controller index %d out of [0..3] range"),
                       controller);
        return -1;
    }

    if (VIR_ALLOC(*def) < 0)
        return -1;

    snprintf(prefix, sizeof(prefix), "ethernet%d", controller);

    VMX_BUILD_NAME(present);
    VMX_BUILD_NAME(startConnected);
    VMX_BUILD_NAME(connectionType);
    VMX_BUILD_NAME(addressType);
    VMX_BUILD_NAME(generatedAddress);
    VMX_BUILD_NAME(address);
    VMX_BUILD_NAME(virtualDev);
    VMX_BUILD_NAME(features);
    VMX_BUILD_NAME(networkName);
    VMX_BUILD_NAME(vnet);

    /* vmx:present */
    if (virVMXGetConfigBoolean(conf, present_name, &present, false, true) < 0) {
        goto cleanup;
    }

    /* vmx:startConnected */
    if (virVMXGetConfigBoolean(conf, startConnected_name, &startConnected,
                               true, true) < 0) {
        goto cleanup;
    }

    /* FIXME: Need to distiguish between active and inactive domains here */
    if (! present/* && ! startConnected*/) {
        goto ignore;
    }

    /* vmx:connectionType -> def:type */
    if (virVMXGetConfigString(conf, connectionType_name, &connectionType,
                              true) < 0) {
        goto cleanup;
    }

    /* vmx:addressType, vmx:generatedAddress, vmx:address -> def:mac */
    if (virVMXGetConfigString(conf, addressType_name, &addressType,
                              true) < 0 ||
        virVMXGetConfigString(conf, generatedAddress_name, &generatedAddress,
                              true) < 0 ||
        virVMXGetConfigString(conf, address_name, &address, true) < 0) {
        goto cleanup;
    }

    if (addressType == NULL || STRCASEEQ(addressType, "generated") ||
        STRCASEEQ(addressType, "vpx")) {
        if (generatedAddress != NULL) {
            if (virMacAddrParse(generatedAddress, &(*def)->mac) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Expecting VMX entry '%s' to be MAC address but "
                                 "found '%s'"), generatedAddress_name,
                               generatedAddress);
                goto cleanup;
            }
        }
    } else if (STRCASEEQ(addressType, "static")) {
        if (address != NULL) {
            if (virMacAddrParse(address, &(*def)->mac) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Expecting VMX entry '%s' to be MAC address but "
                                 "found '%s'"), address_name, address);
                goto cleanup;
            }
        }
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Expecting VMX entry '%s' to be 'generated' or 'static' or "
                         "'vpx' but found '%s'"), addressType_name, addressType);
        goto cleanup;
    }

    /* vmx:virtualDev, vmx:features -> def:model */
    if (virVMXGetConfigString(conf, virtualDev_name, &virtualDev, true) < 0 ||
        virVMXGetConfigLong(conf, features_name, &features, 0, true) < 0) {
        goto cleanup;
    }

    if (virtualDev != NULL) {
        if (STRCASENEQ(virtualDev, "vlance") &&
            STRCASENEQ(virtualDev, "vmxnet") &&
            STRCASENEQ(virtualDev, "vmxnet3") &&
            STRCASENEQ(virtualDev, "e1000")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Expecting VMX entry '%s' to be 'vlance' or 'vmxnet' or "
                             "'vmxnet3' or 'e1000' but found '%s'"), virtualDev_name,
                           virtualDev);
            goto cleanup;
        }

        if (STRCASEEQ(virtualDev, "vmxnet") && features == 15) {
            VIR_FREE(virtualDev);

            if (VIR_STRDUP(virtualDev, "vmxnet2") < 0)
                goto cleanup;
        }
    }

    /* vmx:networkName -> def:data.bridge.brname */
    if (connectionType == NULL ||
        STRCASEEQ(connectionType, "bridged") ||
        STRCASEEQ(connectionType, "custom")) {
        if (virVMXGetConfigString(conf, networkName_name, &networkName,
                                  true) < 0)
            goto cleanup;

        if (!networkName && VIR_STRDUP(networkName, "") < 0)
            goto cleanup;
    }

    /* vmx:vnet -> def:data.ifname */
    if (connectionType != NULL && STRCASEEQ(connectionType, "custom") &&
        virVMXGetConfigString(conf, vnet_name, &vnet, false) < 0) {
        goto cleanup;
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
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("No yet handled value '%s' for VMX entry '%s'"),
                       connectionType, connectionType_name);
        goto cleanup;
    } else if (STRCASEEQ(connectionType, "nat")) {
        (*def)->type = VIR_DOMAIN_NET_TYPE_USER;
        (*def)->model = virtualDev;

        virtualDev = NULL;
    } else if (STRCASEEQ(connectionType, "custom")) {
        (*def)->type = VIR_DOMAIN_NET_TYPE_BRIDGE;
        (*def)->model = virtualDev;
        (*def)->data.bridge.brname = networkName;
        (*def)->ifname = vnet;

        virtualDev = NULL;
        networkName = NULL;
        vnet = NULL;
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid value '%s' for VMX entry '%s'"), connectionType,
                       connectionType_name);
        goto cleanup;
    }

    result = 0;

 cleanup:
    if (result < 0) {
        virDomainNetDefFree(*def);
        *def = NULL;
    }

    VIR_FREE(networkName);
    VIR_FREE(connectionType);
    VIR_FREE(addressType);
    VIR_FREE(generatedAddress);
    VIR_FREE(address);
    VIR_FREE(virtualDev);
    VIR_FREE(vnet);

    return result;

 ignore:
    virDomainNetDefFree(*def);
    *def = NULL;

    result = 0;

    goto cleanup;
}



int
virVMXParseSerial(virVMXContext *ctx, virConfPtr conf, int port,
                  virDomainChrDefPtr *def)
{
    int result = -1;
    char prefix[48] = "";

    char present_name[48] = "";
    bool present = false;

    char startConnected_name[48] = "";
    bool startConnected = false;

    char fileType_name[48] = "";
    char *fileType = NULL;

    char fileName_name[48] = "";
    char *fileName = NULL;

    char network_endPoint_name[48] = "";
    char *network_endPoint = NULL;

    virURIPtr parsedUri = NULL;

    if (def == NULL || *def != NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (port < 0 || port > 3) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Serial port index %d out of [0..3] range"), port);
        return -1;
    }

    if (VIR_ALLOC(*def) < 0)
        return -1;

    (*def)->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL;

    snprintf(prefix, sizeof(prefix), "serial%d", port);

    VMX_BUILD_NAME(present);
    VMX_BUILD_NAME(startConnected);
    VMX_BUILD_NAME(fileType);
    VMX_BUILD_NAME(fileName);
    VMX_BUILD_NAME_EXTRA(network_endPoint, "network.endPoint");

    /* vmx:present */
    if (virVMXGetConfigBoolean(conf, present_name, &present, false, true) < 0) {
        goto cleanup;
    }

    /* vmx:startConnected */
    if (virVMXGetConfigBoolean(conf, startConnected_name, &startConnected,
                               true, true) < 0) {
        goto cleanup;
    }

    /* FIXME: Need to distiguish between active and inactive domains here */
    if (! present/* && ! startConnected*/) {
        goto ignore;
    }

    /* vmx:fileType -> def:type */
    if (virVMXGetConfigString(conf, fileType_name, &fileType, false) < 0) {
        goto cleanup;
    }

    /* vmx:fileName -> def:data.file.path */
    if (virVMXGetConfigString(conf, fileName_name, &fileName, true) < 0) {
        goto cleanup;
    }

    /* vmx:network.endPoint -> def:data.tcp.listen */
    if (virVMXGetConfigString(conf, network_endPoint_name, &network_endPoint,
                              true) < 0) {
        goto cleanup;
    }

    /* Setup virDomainChrDef */
    if (STRCASEEQ(fileType, "device")) {
        (*def)->target.port = port;
        (*def)->source.type = VIR_DOMAIN_CHR_TYPE_DEV;
        (*def)->source.data.file.path = fileName;

        fileName = NULL;
    } else if (STRCASEEQ(fileType, "file")) {
        (*def)->target.port = port;
        (*def)->source.type = VIR_DOMAIN_CHR_TYPE_FILE;
        (*def)->source.data.file.path = ctx->parseFileName(fileName,
                                                           ctx->opaque);

        if ((*def)->source.data.file.path == NULL) {
            goto cleanup;
        }
    } else if (STRCASEEQ(fileType, "pipe")) {
        /*
         * FIXME: Differences between client/server and VM/application pipes
         *        not representable in domain XML form
         */
        (*def)->target.port = port;
        (*def)->source.type = VIR_DOMAIN_CHR_TYPE_PIPE;
        (*def)->source.data.file.path = fileName;

        fileName = NULL;
    } else if (STRCASEEQ(fileType, "network")) {
        (*def)->target.port = port;
        (*def)->source.type = VIR_DOMAIN_CHR_TYPE_TCP;

        if (!(parsedUri = virURIParse(fileName)))
            goto cleanup;

        if (parsedUri->port == 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("VMX entry '%s' doesn't contain a port part"),
                           fileName_name);
            goto cleanup;
        }

        if (VIR_STRDUP((*def)->source.data.tcp.host, parsedUri->server) < 0)
            goto cleanup;

        if (virAsprintf(&(*def)->source.data.tcp.service, "%d",
                        parsedUri->port) < 0)
            goto cleanup;

        /* See vSphere API documentation about VirtualSerialPortURIBackingInfo */
        if (parsedUri->scheme == NULL ||
            STRCASEEQ(parsedUri->scheme, "tcp") ||
            STRCASEEQ(parsedUri->scheme, "tcp4") ||
            STRCASEEQ(parsedUri->scheme, "tcp6")) {
            (*def)->source.data.tcp.protocol = VIR_DOMAIN_CHR_TCP_PROTOCOL_RAW;
        } else if (STRCASEEQ(parsedUri->scheme, "telnet")) {
            (*def)->source.data.tcp.protocol
                = VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET;
        } else if (STRCASEEQ(parsedUri->scheme, "telnets")) {
            (*def)->source.data.tcp.protocol
                = VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNETS;
        } else if (STRCASEEQ(parsedUri->scheme, "ssl") ||
                   STRCASEEQ(parsedUri->scheme, "tcp+ssl") ||
                   STRCASEEQ(parsedUri->scheme, "tcp4+ssl") ||
                   STRCASEEQ(parsedUri->scheme, "tcp6+ssl")) {
            (*def)->source.data.tcp.protocol = VIR_DOMAIN_CHR_TCP_PROTOCOL_TLS;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("VMX entry '%s' contains unsupported scheme '%s'"),
                           fileName_name, parsedUri->scheme);
            goto cleanup;
        }

        if (network_endPoint == NULL || STRCASEEQ(network_endPoint, "server")) {
            (*def)->source.data.tcp.listen = true;
        } else if (STRCASEEQ(network_endPoint, "client")) {
            (*def)->source.data.tcp.listen = false;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Expecting VMX entry '%s' to be 'server' or 'client' "
                             "but found '%s'"), network_endPoint_name, network_endPoint);
            goto cleanup;
        }
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Expecting VMX entry '%s' to be 'device', 'file' or 'pipe' "
                         "or 'network' but found '%s'"), fileType_name, fileType);
        goto cleanup;
    }

    result = 0;

 cleanup:
    if (result < 0) {
        virDomainChrDefFree(*def);
        *def = NULL;
    }

    VIR_FREE(fileType);
    VIR_FREE(fileName);
    VIR_FREE(network_endPoint);
    virURIFree(parsedUri);

    return result;

 ignore:
    virDomainChrDefFree(*def);
    *def = NULL;

    result = 0;

    goto cleanup;
}



int
virVMXParseParallel(virVMXContext *ctx, virConfPtr conf, int port,
                    virDomainChrDefPtr *def)
{
    int result = -1;
    char prefix[48] = "";

    char present_name[48] = "";
    bool present = false;

    char startConnected_name[48] = "";
    bool startConnected = false;

    char fileType_name[48] = "";
    char *fileType = NULL;

    char fileName_name[48] = "";
    char *fileName = NULL;

    if (def == NULL || *def != NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (port < 0 || port > 2) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Parallel port index %d out of [0..2] range"), port);
        return -1;
    }

    if (VIR_ALLOC(*def) < 0)
        return -1;

    (*def)->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL;

    snprintf(prefix, sizeof(prefix), "parallel%d", port);

    VMX_BUILD_NAME(present);
    VMX_BUILD_NAME(startConnected);
    VMX_BUILD_NAME(fileType);
    VMX_BUILD_NAME(fileName);

    /* vmx:present */
    if (virVMXGetConfigBoolean(conf, present_name, &present, false, true) < 0) {
        goto cleanup;
    }

    /* vmx:startConnected */
    if (virVMXGetConfigBoolean(conf, startConnected_name, &startConnected,
                               true, true) < 0) {
        goto cleanup;
    }

    /* FIXME: Need to distiguish between active and inactive domains here */
    if (! present/* && ! startConnected*/) {
        goto ignore;
    }

    /* vmx:fileType -> def:type */
    if (virVMXGetConfigString(conf, fileType_name, &fileType, false) < 0) {
        goto cleanup;
    }

    /* vmx:fileName -> def:data.file.path */
    if (virVMXGetConfigString(conf, fileName_name, &fileName, false) < 0) {
        goto cleanup;
    }

    /* Setup virDomainChrDef */
    if (STRCASEEQ(fileType, "device")) {
        (*def)->target.port = port;
        (*def)->source.type = VIR_DOMAIN_CHR_TYPE_DEV;
        (*def)->source.data.file.path = fileName;

        fileName = NULL;
    } else if (STRCASEEQ(fileType, "file")) {
        (*def)->target.port = port;
        (*def)->source.type = VIR_DOMAIN_CHR_TYPE_FILE;
        (*def)->source.data.file.path = ctx->parseFileName(fileName,
                                                           ctx->opaque);

        if ((*def)->source.data.file.path == NULL) {
            goto cleanup;
        }
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Expecting VMX entry '%s' to be 'device' or 'file' but "
                         "found '%s'"), fileType_name, fileType);
        goto cleanup;
    }

    result = 0;

 cleanup:
    if (result < 0) {
        virDomainChrDefFree(*def);
        *def = NULL;
    }

    VIR_FREE(fileType);
    VIR_FREE(fileName);

    return result;

 ignore:
    virDomainChrDefFree(*def);
    *def = NULL;

    result = 0;

    goto cleanup;
}



int
virVMXParseSVGA(virConfPtr conf, virDomainVideoDefPtr *def)
{
    int result = -1;
    long long svga_vramSize = 0;

    if (def == NULL || *def != NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (VIR_ALLOC(*def) < 0)
        return -1;

    (*def)->type = VIR_DOMAIN_VIDEO_TYPE_VMVGA;

    /* vmx:vramSize */
    if (virVMXGetConfigLong(conf, "svga.vramSize", &svga_vramSize,
                            4 * 1024 * 1024, true) < 0) {
        goto cleanup;
    }

    (*def)->vram = VIR_DIV_UP(svga_vramSize, 1024); /* Scale from bytes to kilobytes */

    result = 0;

 cleanup:
    if (result < 0) {
        virDomainVideoDefFree(*def);
        *def = NULL;
    }

    return result;
}



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Domain XML -> VMX
 */

char *
virVMXFormatConfig(virVMXContext *ctx, virDomainXMLOptionPtr xmlopt, virDomainDefPtr def,
                   int virtualHW_version)
{
    char *vmx = NULL;
    size_t i;
    int sched_cpu_affinity_length;
    unsigned char zero[VIR_UUID_BUFLEN];
    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    char *preliminaryDisplayName = NULL;
    char *displayName = NULL;
    char *annotation = NULL;
    unsigned long long max_balloon;
    bool scsi_present[4] = { false, false, false, false };
    int scsi_virtualDev[4] = { -1, -1, -1, -1 };
    bool floppy_present[2] = { false, false };

    if (ctx->formatFileName == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("virVMXContext has no formatFileName function set"));
        return NULL;
    }

    memset(zero, 0, VIR_UUID_BUFLEN);

    if (def->virtType != VIR_DOMAIN_VIRT_VMWARE) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Expecting virt type to be '%s' but found '%s'"),
                       virDomainVirtTypeToString(VIR_DOMAIN_VIRT_VMWARE),
                       virDomainVirtTypeToString(def->virtType));
        return NULL;
    }

    /* vmx:.encoding */
    virBufferAddLit(&buffer, ".encoding = \"UTF-8\"\n");

    /* vmx:config.version */
    virBufferAddLit(&buffer, "config.version = \"8\"\n");

    /* vmx:virtualHW.version */
    virBufferAsprintf(&buffer, "virtualHW.version = \"%d\"\n",
                      virtualHW_version);

    /* def:os.arch -> vmx:guestOS */
    if (def->os.arch == VIR_ARCH_I686) {
        virBufferAddLit(&buffer, "guestOS = \"other\"\n");
    } else if (def->os.arch == VIR_ARCH_X86_64) {
        virBufferAddLit(&buffer, "guestOS = \"other-64\"\n");
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Expecting domain XML attribute 'arch' of entry 'os/type' "
                         "to be 'i686' or 'x86_64' but found '%s'"),
                       virArchToString(def->os.arch));
        goto cleanup;
    }

    /* def:os.smbios_mode -> vmx:smbios.reflecthost */
    if (def->os.smbios_mode == VIR_DOMAIN_SMBIOS_NONE ||
        def->os.smbios_mode == VIR_DOMAIN_SMBIOS_EMULATE) {
        /* nothing */
    } else if (def->os.smbios_mode == VIR_DOMAIN_SMBIOS_HOST) {
        virBufferAddLit(&buffer, "smbios.reflecthost = \"true\"\n");
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported SMBIOS mode '%s'"),
                       virDomainSmbiosModeTypeToString(def->os.smbios_mode));
        goto cleanup;
    }

    /* def:uuid -> vmx:uuid.action, vmx:uuid.bios */
    if (memcmp(def->uuid, zero, VIR_UUID_BUFLEN) == 0) {
        virBufferAddLit(&buffer, "uuid.action = \"create\"\n");
    } else {
        virBufferAsprintf(&buffer, "uuid.bios = \"%02x %02x %02x %02x %02x %02x "
                          "%02x %02x-%02x %02x %02x %02x %02x %02x %02x %02x\"\n",
                          def->uuid[0], def->uuid[1], def->uuid[2], def->uuid[3],
                          def->uuid[4], def->uuid[5], def->uuid[6], def->uuid[7],
                          def->uuid[8], def->uuid[9], def->uuid[10], def->uuid[11],
                          def->uuid[12], def->uuid[13], def->uuid[14],
                          def->uuid[15]);
    }

    /* def:name -> vmx:displayName */
    preliminaryDisplayName = virVMXEscapeHexPipe(def->name);

    if (preliminaryDisplayName == NULL) {
        goto cleanup;
    }

    displayName = virVMXEscapeHexPercent(preliminaryDisplayName);

    if (displayName == NULL) {
        goto cleanup;
    }

    virBufferAsprintf(&buffer, "displayName = \"%s\"\n", displayName);

    /* def:description -> vmx:annotation */
    if (def->description != NULL) {
        if (!(annotation = virVMXEscapeHexPipe(def->description)))
            goto cleanup;

        virBufferAsprintf(&buffer, "annotation = \"%s\"\n", annotation);
    }

    /* def:mem.max_balloon -> vmx:memsize */
    /* max-memory must be a multiple of 4096 kilobyte */
    max_balloon = VIR_DIV_UP(def->mem.max_balloon, 4096) * 4096;

    virBufferAsprintf(&buffer, "memsize = \"%llu\"\n",
                      max_balloon / 1024); /* Scale from kilobytes to megabytes */

    /* def:mem.cur_balloon -> vmx:sched.mem.max */
    if (def->mem.cur_balloon < max_balloon) {
        virBufferAsprintf(&buffer, "sched.mem.max = \"%llu\"\n",
                          VIR_DIV_UP(def->mem.cur_balloon,
                                     1024)); /* Scale from kilobytes to megabytes */
    }

    /* def:mem.min_guarantee -> vmx:sched.mem.minsize */
    if (def->mem.min_guarantee > 0) {
        virBufferAsprintf(&buffer, "sched.mem.minsize = \"%llu\"\n",
                          VIR_DIV_UP(def->mem.min_guarantee,
                                     1024)); /* Scale from kilobytes to megabytes */
    }

    /* def:maxvcpus -> vmx:numvcpus */
    if (def->vcpus != def->maxvcpus) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("No support for domain XML entry 'vcpu' attribute "
                         "'current'"));
        goto cleanup;
    }
    if (def->maxvcpus <= 0 || (def->maxvcpus % 2 != 0 && def->maxvcpus != 1)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Expecting domain XML entry 'vcpu' to be an unsigned "
                         "integer (1 or a multiple of 2) but found %d"),
                       def->maxvcpus);
        goto cleanup;
    }

    virBufferAsprintf(&buffer, "numvcpus = \"%d\"\n", def->maxvcpus);

    /* def:cpumask -> vmx:sched.cpu.affinity */
    if (def->cpumask && virBitmapSize(def->cpumask) > 0) {
        int bit;
        virBufferAddLit(&buffer, "sched.cpu.affinity = \"");

        sched_cpu_affinity_length = 0;

        bit = -1;
        while ((bit = virBitmapNextSetBit(def->cpumask, bit)) >= 0) {
            ++sched_cpu_affinity_length;
        }

        if (sched_cpu_affinity_length < def->maxvcpus) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Expecting domain XML attribute 'cpuset' of entry "
                             "'vcpu' to contain at least %d CPU(s)"),
                           def->maxvcpus);
            goto cleanup;
        }

        bit = -1;
        while ((bit = virBitmapNextSetBit(def->cpumask, bit)) >= 0) {
            virBufferAsprintf(&buffer, "%d", bit);

            if (sched_cpu_affinity_length > 1) {
                virBufferAddChar(&buffer, ',');
            }

            --sched_cpu_affinity_length;
        }

        virBufferAddLit(&buffer, "\"\n");
    }

    /* def:cputune.shares -> vmx:sched.cpu.shares */
    if (def->cputune.sharesSpecified) {
        /* See http://www.vmware.com/support/developer/vc-sdk/visdk41pubs/ApiReference/vim.SharesInfo.Level.html */
        if (def->cputune.shares == def->vcpus * 500) {
            virBufferAddLit(&buffer, "sched.cpu.shares = \"low\"\n");
        } else if (def->cputune.shares == def->vcpus * 1000) {
            virBufferAddLit(&buffer, "sched.cpu.shares = \"normal\"\n");
        } else if (def->cputune.shares == def->vcpus * 2000) {
            virBufferAddLit(&buffer, "sched.cpu.shares = \"high\"\n");
        } else {
            virBufferAsprintf(&buffer, "sched.cpu.shares = \"%lu\"\n",
                              def->cputune.shares);
        }
    }

    /* def:graphics */
    for (i = 0; i < def->ngraphics; ++i) {
        switch (def->graphics[i]->type) {
          case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
            if (virVMXFormatVNC(def->graphics[i], &buffer) < 0) {
                goto cleanup;
            }

            break;

          default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported graphics type '%s'"),
                           virDomainGraphicsTypeToString(def->graphics[i]->type));
            goto cleanup;
        }
    }

    /* def:disks */
    for (i = 0; i < def->ndisks; ++i) {
        if (virVMXVerifyDiskAddress(xmlopt, def->disks[i]) < 0 ||
            virVMXHandleLegacySCSIDiskDriverName(def, def->disks[i]) < 0) {
            goto cleanup;
        }
    }

    if (virVMXGatherSCSIControllers(ctx, def, scsi_virtualDev,
                                    scsi_present) < 0) {
        goto cleanup;
    }

    for (i = 0; i < 4; ++i) {
        if (scsi_present[i]) {
            virBufferAsprintf(&buffer, "scsi%zu.present = \"true\"\n", i);

            if (scsi_virtualDev[i] != -1) {
                virBufferAsprintf(&buffer, "scsi%zu.virtualDev = \"%s\"\n", i,
                                  virVMXControllerModelSCSITypeToString
                                    (scsi_virtualDev[i]));
            }
        }
    }

    for (i = 0; i < def->ndisks; ++i) {
        switch (def->disks[i]->device) {
          case VIR_DOMAIN_DISK_DEVICE_DISK:
          case VIR_DOMAIN_DISK_DEVICE_CDROM:
          case VIR_DOMAIN_DISK_DEVICE_LUN:
            if (virVMXFormatDisk(ctx, def->disks[i], &buffer) < 0) {
                goto cleanup;
            }

            break;

          case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
            if (virVMXFormatFloppy(ctx, def->disks[i], &buffer,
                                   floppy_present) < 0) {
                goto cleanup;
            }

            break;

          default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported disk device type '%s'"),
                           virDomainDiskDeviceTypeToString(def->disks[i]->device));
            goto cleanup;
        }
    }

    for (i = 0; i < 2; ++i) {
        /* floppy[0..1].present defaults to true, disable it explicitly */
        if (! floppy_present[i]) {
            virBufferAsprintf(&buffer, "floppy%zu.present = \"false\"\n", i);
        }
    }

    /* def:fss */
    if (def->nfss > 0) {
        virBufferAddLit(&buffer, "isolation.tools.hgfs.disable = \"false\"\n");
        virBufferAsprintf(&buffer, "sharedFolder.maxNum = \"%zu\"\n", def->nfss);
    }

    for (i = 0; i < def->nfss; ++i) {
        if (virVMXFormatFileSystem(def->fss[i], i, &buffer) < 0) {
            goto cleanup;
        }
    }

    /* def:nets */
    for (i = 0; i < def->nnets; ++i) {
        if (virVMXFormatEthernet(def->nets[i], i, &buffer) < 0) {
            goto cleanup;
        }
    }

    /* def:inputs */
    /* FIXME */

    /* def:sounds */
    /* FIXME */

    /* def:videos */
    if (def->nvideos > 0) {
        if (def->nvideos > 1) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("No support for multiple video devices"));
            goto cleanup;
        }

        if (virVMXFormatSVGA(def->videos[0], &buffer) < 0) {
            goto cleanup;
        }
    }

    /* def:hostdevs */
    /* FIXME */

    /* def:serials */
    for (i = 0; i < def->nserials; ++i) {
        if (virVMXFormatSerial(ctx, def->serials[i], &buffer) < 0) {
            goto cleanup;
        }
    }

    /* def:parallels */
    for (i = 0; i < def->nparallels; ++i) {
        if (virVMXFormatParallel(ctx, def->parallels[i], &buffer) < 0) {
            goto cleanup;
        }
    }

    /* Get final VMX output */
    if (virBufferError(&buffer)) {
        virReportOOMError();
        goto cleanup;
    }

    vmx = virBufferContentAndReset(&buffer);

 cleanup:
    if (vmx == NULL) {
        virBufferFreeAndReset(&buffer);
    }

    VIR_FREE(preliminaryDisplayName);
    VIR_FREE(displayName);
    VIR_FREE(annotation);

    return vmx;
}



int
virVMXFormatVNC(virDomainGraphicsDefPtr def, virBufferPtr buffer)
{
    const char *listenAddr;

    if (def->type != VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    virBufferAddLit(buffer, "RemoteDisplay.vnc.enabled = \"true\"\n");

    if (def->data.vnc.autoport) {
        VIR_WARN("VNC autoport is enabled, but the automatically assigned "
                  "VNC port cannot be read back");
    } else {
        if (def->data.vnc.port < 5900 || def->data.vnc.port > 5964) {
            VIR_WARN("VNC port %d it out of [5900..5964] range",
                     def->data.vnc.port);
        }

        virBufferAsprintf(buffer, "RemoteDisplay.vnc.port = \"%d\"\n",
                          def->data.vnc.port);
    }

    if ((listenAddr = virDomainGraphicsListenGetAddress(def, 0))) {
        virBufferAsprintf(buffer, "RemoteDisplay.vnc.ip = \"%s\"\n",
                          listenAddr);
    }

    if (def->data.vnc.keymap != NULL) {
        virBufferAsprintf(buffer, "RemoteDisplay.vnc.keymap = \"%s\"\n",
                          def->data.vnc.keymap);
    }

    if (def->data.vnc.auth.passwd != NULL) {
        virBufferAsprintf(buffer, "RemoteDisplay.vnc.password = \"%s\"\n",
                          def->data.vnc.auth.passwd);
    }

    return 0;
}

int
virVMXFormatDisk(virVMXContext *ctx, virDomainDiskDefPtr def,
                     virBufferPtr buffer)
{
    int controllerOrBus, unit;
    const char *vmxDeviceType = NULL;
    char *fileName = NULL;
    int type = virDomainDiskGetType(def);

    /* Convert a handful of types to their string values */
    const char *busType = virDomainDiskBusTypeToString(def->bus);
    const char *deviceType = virDomainDeviceTypeToString(def->device);
    const char *diskType = virDomainDeviceTypeToString(type);

    /* If we are dealing with a disk its a .vmdk, otherwise it must be
     * an ISO.
     */
    const char *fileExt = (def->device == VIR_DOMAIN_DISK_DEVICE_DISK) ?
                            ".vmdk" : ".iso";

    /* Check that we got a valid device type */
    if (def->device != VIR_DOMAIN_DISK_DEVICE_DISK &&
        def->device != VIR_DOMAIN_DISK_DEVICE_CDROM &&
        def->device != VIR_DOMAIN_DISK_DEVICE_LUN) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid device type supplied: %s"), deviceType);
        return -1;
    }

    /* We only support type='file' and type='block' */
    if (type != VIR_DOMAIN_DISK_TYPE_FILE &&
        type != VIR_DOMAIN_DISK_TYPE_BLOCK) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("%s %s '%s' has unsupported type '%s', expecting "
                         "'%s' or '%s'"), busType, deviceType, def->dst,
                       diskType,
                       virDomainDiskTypeToString(VIR_DOMAIN_DISK_TYPE_FILE),
                       virDomainDiskTypeToString(VIR_DOMAIN_DISK_TYPE_BLOCK));
        return -1;
    }

    if (def->bus == VIR_DOMAIN_DISK_BUS_SCSI) {
        if (virVMXSCSIDiskNameToControllerAndUnit(def->dst, &controllerOrBus,
                                                  &unit) < 0) {
            return -1;
        }
    } else if (def->bus == VIR_DOMAIN_DISK_BUS_IDE) {
        if (virVMXIDEDiskNameToBusAndUnit(def->dst, &controllerOrBus,
                                          &unit) < 0) {
            return -1;
        }
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported bus type '%s' for %s"),
                       busType, deviceType);
        return -1;
    }

    if (def->device == VIR_DOMAIN_DISK_DEVICE_DISK &&
        type == VIR_DOMAIN_DISK_TYPE_FILE) {
        vmxDeviceType = (def->bus == VIR_DOMAIN_DISK_BUS_SCSI) ?
            "scsi-hardDisk" : "ata-hardDisk";
    } else if (def->device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
        if (type == VIR_DOMAIN_DISK_TYPE_FILE)
            vmxDeviceType = "cdrom-image";
        else
            vmxDeviceType = "atapi-cdrom";
    } else if (def->device == VIR_DOMAIN_DISK_DEVICE_LUN) {
        vmxDeviceType = "cdrom-raw";
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("%s %s '%s' has an unsupported type '%s'"),
                       busType, deviceType, def->dst, diskType);
        return -1;
    }

    virBufferAsprintf(buffer, "%s%d:%d.present = \"true\"\n",
                      busType, controllerOrBus, unit);
    virBufferAsprintf(buffer, "%s%d:%d.deviceType = \"%s\"\n",
                      busType, controllerOrBus, unit, vmxDeviceType);

    if (type == VIR_DOMAIN_DISK_TYPE_FILE) {
        const char *src = virDomainDiskGetSource(def);

        if (src && ! virFileHasSuffix(src, fileExt)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Image file for %s %s '%s' has "
                             "unsupported suffix, expecting '%s'"),
                           busType, deviceType, def->dst, fileExt);
                return -1;
        }

        fileName = ctx->formatFileName(src, ctx->opaque);

        if (fileName == NULL) {
            return -1;
        }

        virBufferAsprintf(buffer, "%s%d:%d.fileName = \"%s\"\n",
                          busType, controllerOrBus, unit, fileName);

        VIR_FREE(fileName);
    } else if (type == VIR_DOMAIN_DISK_TYPE_BLOCK) {
        const char *src = virDomainDiskGetSource(def);

        if (!src &&
            def->startupPolicy == VIR_DOMAIN_STARTUP_POLICY_OPTIONAL) {
            virBufferAsprintf(buffer, "%s%d:%d.autodetect = \"true\"\n",
                              busType, controllerOrBus, unit);
            virBufferAsprintf(buffer, "%s%d:%d.fileName = \"auto detect\"\n",
                              busType, controllerOrBus, unit);
        } else {
            virBufferAsprintf(buffer, "%s%d:%d.fileName = \"%s\"\n",
                              busType, controllerOrBus, unit, src);
        }
    }

    if (def->bus == VIR_DOMAIN_DISK_BUS_SCSI) {
        if (def->cachemode == VIR_DOMAIN_DISK_CACHE_WRITETHRU) {
            virBufferAsprintf(buffer, "%s%d:%d.writeThrough = \"true\"\n",
                              busType, controllerOrBus, unit);
        } else if (def->cachemode != VIR_DOMAIN_DISK_CACHE_DEFAULT) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("%s harddisk '%s' has unsupported cache mode '%s'"),
                           busType, def->dst,
                           virDomainDiskCacheTypeToString(def->cachemode));
            return -1;
        }
    }

    if (def->transient)
        virBufferAsprintf(buffer,
                          "%s%d:%d.mode = \"independent-nonpersistent\"\n",
                          busType, controllerOrBus, unit);
    return 0;
}

int
virVMXFormatFloppy(virVMXContext *ctx, virDomainDiskDefPtr def,
                   virBufferPtr buffer, bool floppy_present[2])
{
    int unit;
    char *fileName = NULL;
    int type = virDomainDiskGetType(def);
    const char *src = virDomainDiskGetSource(def);

    if (def->device != VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (virVMXFloppyDiskNameToUnit(def->dst, &unit) < 0) {
        return -1;
    }

    floppy_present[unit] = true;

    virBufferAsprintf(buffer, "floppy%d.present = \"true\"\n", unit);

    if (type == VIR_DOMAIN_DISK_TYPE_FILE) {
        virBufferAsprintf(buffer, "floppy%d.fileType = \"file\"\n", unit);

        if (src) {
            fileName = ctx->formatFileName(src, ctx->opaque);

            if (fileName == NULL) {
                return -1;
            }

            virBufferAsprintf(buffer, "floppy%d.fileName = \"%s\"\n",
                              unit, fileName);

            VIR_FREE(fileName);
        }
    } else if (type == VIR_DOMAIN_DISK_TYPE_BLOCK) {
        virBufferAsprintf(buffer, "floppy%d.fileType = \"device\"\n", unit);

        if (src) {
            virBufferAsprintf(buffer, "floppy%d.fileName = \"%s\"\n",
                              unit, src);
        }
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Floppy '%s' has unsupported type '%s', expecting '%s' "
                         "or '%s'"), def->dst,
                       virDomainDiskTypeToString(type),
                       virDomainDiskTypeToString(VIR_DOMAIN_DISK_TYPE_FILE),
                       virDomainDiskTypeToString(VIR_DOMAIN_DISK_TYPE_BLOCK));
        return -1;
    }

    return 0;
}



int
virVMXFormatFileSystem(virDomainFSDefPtr def, int number, virBufferPtr buffer)
{
    if (def->type != VIR_DOMAIN_FS_TYPE_MOUNT) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Only '%s' filesystem type is supported"),
                       virDomainFSTypeToString(VIR_DOMAIN_FS_TYPE_MOUNT));
        return -1;
    }

    virBufferAsprintf(buffer, "sharedFolder%d.present = \"true\"\n", number);
    virBufferAsprintf(buffer, "sharedFolder%d.enabled = \"true\"\n", number);
    virBufferAsprintf(buffer, "sharedFolder%d.readAccess = \"true\"\n", number);
    virBufferAsprintf(buffer, "sharedFolder%d.writeAccess = \"%s\"\n", number,
                      def->readonly ? "false" : "true");
    virBufferAsprintf(buffer, "sharedFolder%d.hostPath = \"%s\"\n", number,
                      def->src);
    virBufferAsprintf(buffer, "sharedFolder%d.guestName = \"%s\"\n", number,
                      def->dst);

    return 0;
}



int
virVMXFormatEthernet(virDomainNetDefPtr def, int controller,
                     virBufferPtr buffer)
{
    char mac_string[VIR_MAC_STRING_BUFLEN];
    unsigned int prefix, suffix;

    if (controller < 0 || controller > 3) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Ethernet controller index %d out of [0..3] range"),
                       controller);
        return -1;
    }

    virBufferAsprintf(buffer, "ethernet%d.present = \"true\"\n", controller);

    /* def:model -> vmx:virtualDev, vmx:features */
    if (def->model != NULL) {
        if (STRCASENEQ(def->model, "vlance") &&
            STRCASENEQ(def->model, "vmxnet") &&
            STRCASENEQ(def->model, "vmxnet2") &&
            STRCASENEQ(def->model, "vmxnet3") &&
            STRCASENEQ(def->model, "e1000")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Expecting domain XML entry 'devices/interface/model' "
                             "to be 'vlance' or 'vmxnet' or 'vmxnet2' or 'vmxnet3' "
                             "or 'e1000' but found '%s'"), def->model);
            return -1;
        }

        if (STRCASEEQ(def->model, "vmxnet2")) {
            virBufferAsprintf(buffer, "ethernet%d.virtualDev = \"vmxnet\"\n",
                              controller);
            virBufferAsprintf(buffer, "ethernet%d.features = \"15\"\n",
                              controller);
        } else {
            virBufferAsprintf(buffer, "ethernet%d.virtualDev = \"%s\"\n",
                              controller, def->model);
        }
    }

    /* def:type, def:ifname -> vmx:connectionType */
    switch (def->type) {
      case VIR_DOMAIN_NET_TYPE_BRIDGE:
        if (STRNEQ(def->data.bridge.brname, ""))
            virBufferAsprintf(buffer, "ethernet%d.networkName = \"%s\"\n",
                              controller, def->data.bridge.brname);

        if (def->ifname != NULL) {
            virBufferAsprintf(buffer, "ethernet%d.connectionType = \"custom\"\n",
                              controller);
            virBufferAsprintf(buffer, "ethernet%d.vnet = \"%s\"\n",
                              controller, def->ifname);
        } else {
            virBufferAsprintf(buffer, "ethernet%d.connectionType = \"bridged\"\n",
                              controller);
        }

        break;

      case VIR_DOMAIN_NET_TYPE_USER:
        virBufferAsprintf(buffer, "ethernet%d.connectionType = \"nat\"\n",
                          controller);
        break;

      default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, _("Unsupported net type '%s'"),
                       virDomainNetTypeToString(def->type));
        return -1;
    }

    /* def:mac -> vmx:addressType, vmx:(generated)Address, vmx:checkMACAddress */
    virMacAddrFormat(&def->mac, mac_string);

    prefix = (def->mac.addr[0] << 16) | (def->mac.addr[1] << 8) | def->mac.addr[2];
    suffix = (def->mac.addr[3] << 16) | (def->mac.addr[4] << 8) | def->mac.addr[5];

    if (prefix == 0x000c29) {
        virBufferAsprintf(buffer, "ethernet%d.addressType = \"generated\"\n",
                          controller);
        virBufferAsprintf(buffer, "ethernet%d.generatedAddress = \"%s\"\n",
                          controller, mac_string);
        virBufferAsprintf(buffer, "ethernet%d.generatedAddressOffset = \"0\"\n",
                          controller);
    } else if (prefix == 0x005056 && suffix <= 0x3fffff) {
        virBufferAsprintf(buffer, "ethernet%d.addressType = \"static\"\n",
                          controller);
        virBufferAsprintf(buffer, "ethernet%d.address = \"%s\"\n",
                          controller, mac_string);
    } else if (prefix == 0x005056 && suffix >= 0x800000 && suffix <= 0xbfffff) {
        virBufferAsprintf(buffer, "ethernet%d.addressType = \"vpx\"\n",
                          controller);
        virBufferAsprintf(buffer, "ethernet%d.generatedAddress = \"%s\"\n",
                          controller, mac_string);
    } else {
        virBufferAsprintf(buffer, "ethernet%d.addressType = \"static\"\n",
                          controller);
        virBufferAsprintf(buffer, "ethernet%d.address = \"%s\"\n",
                          controller, mac_string);
        virBufferAsprintf(buffer, "ethernet%d.checkMACAddress = \"false\"\n",
                          controller);
    }

    return 0;
}



int
virVMXFormatSerial(virVMXContext *ctx, virDomainChrDefPtr def,
                   virBufferPtr buffer)
{
    char *fileName = NULL;
    const char *protocol;

    if (def->target.port < 0 || def->target.port > 3) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Serial port index %d out of [0..3] range"),
                       def->target.port);
        return -1;
    }

    virBufferAsprintf(buffer, "serial%d.present = \"true\"\n", def->target.port);

    /* def:type -> vmx:fileType and def:data.file.path -> vmx:fileName */
    switch (def->source.type) {
      case VIR_DOMAIN_CHR_TYPE_DEV:
        virBufferAsprintf(buffer, "serial%d.fileType = \"device\"\n",
                          def->target.port);
        virBufferAsprintf(buffer, "serial%d.fileName = \"%s\"\n",
                          def->target.port, def->source.data.file.path);
        break;

      case VIR_DOMAIN_CHR_TYPE_FILE:
        virBufferAsprintf(buffer, "serial%d.fileType = \"file\"\n",
                          def->target.port);

        fileName = ctx->formatFileName(def->source.data.file.path, ctx->opaque);

        if (fileName == NULL) {
            return -1;
        }

        virBufferAsprintf(buffer, "serial%d.fileName = \"%s\"\n",
                          def->target.port, fileName);

        VIR_FREE(fileName);
        break;

      case VIR_DOMAIN_CHR_TYPE_PIPE:
        virBufferAsprintf(buffer, "serial%d.fileType = \"pipe\"\n",
                          def->target.port);
        /* FIXME: Based on VI Client GUI default */
        virBufferAsprintf(buffer, "serial%d.pipe.endPoint = \"client\"\n",
                          def->target.port);
        /* FIXME: Based on VI Client GUI default */
        virBufferAsprintf(buffer, "serial%d.tryNoRxLoss = \"false\"\n",
                          def->target.port);
        virBufferAsprintf(buffer, "serial%d.fileName = \"%s\"\n",
                          def->target.port, def->source.data.file.path);
        break;

      case VIR_DOMAIN_CHR_TYPE_TCP:
        switch (def->source.data.tcp.protocol) {
          case VIR_DOMAIN_CHR_TCP_PROTOCOL_RAW:
            protocol = "tcp";
            break;

          case VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET:
            protocol = "telnet";
            break;

          case VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNETS:
            protocol = "telnets";
            break;

          case VIR_DOMAIN_CHR_TCP_PROTOCOL_TLS:
            protocol = "ssl";
            break;

          default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported character device TCP protocol '%s'"),
                           virDomainChrTcpProtocolTypeToString(
                               def->source.data.tcp.protocol));
            return -1;
        }

        virBufferAsprintf(buffer, "serial%d.fileType = \"network\"\n",
                          def->target.port);
        virBufferAsprintf(buffer, "serial%d.fileName = \"%s://%s:%s\"\n",
                          def->target.port, protocol, def->source.data.tcp.host,
                          def->source.data.tcp.service);
        virBufferAsprintf(buffer, "serial%d.network.endPoint = \"%s\"\n",
                          def->target.port,
                          def->source.data.tcp.listen ? "server" : "client");
        break;

      default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported character device type '%s'"),
                       virDomainChrTypeToString(def->source.type));
        return -1;
    }

    /* vmx:yieldOnMsrRead */
    /* FIXME: Based on VI Client GUI default */
    virBufferAsprintf(buffer, "serial%d.yieldOnMsrRead = \"true\"\n",
                      def->target.port);

    return 0;
}



int
virVMXFormatParallel(virVMXContext *ctx, virDomainChrDefPtr def,
                     virBufferPtr buffer)
{
    char *fileName = NULL;

    if (def->target.port < 0 || def->target.port > 2) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Parallel port index %d out of [0..2] range"),
                       def->target.port);
        return -1;
    }

    virBufferAsprintf(buffer, "parallel%d.present = \"true\"\n",
                      def->target.port);

    /* def:type -> vmx:fileType and def:data.file.path -> vmx:fileName */
    switch (def->source.type) {
      case VIR_DOMAIN_CHR_TYPE_DEV:
        virBufferAsprintf(buffer, "parallel%d.fileType = \"device\"\n",
                          def->target.port);
        virBufferAsprintf(buffer, "parallel%d.fileName = \"%s\"\n",
                          def->target.port, def->source.data.file.path);
        break;

      case VIR_DOMAIN_CHR_TYPE_FILE:
        virBufferAsprintf(buffer, "parallel%d.fileType = \"file\"\n",
                          def->target.port);

        fileName = ctx->formatFileName(def->source.data.file.path, ctx->opaque);

        if (fileName == NULL) {
            return -1;
        }

        virBufferAsprintf(buffer, "parallel%d.fileName = \"%s\"\n",
                          def->target.port, fileName);

        VIR_FREE(fileName);
        break;

      default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported character device type '%s'"),
                       virDomainChrTypeToString(def->source.type));
        return -1;
    }

    return 0;
}



int
virVMXFormatSVGA(virDomainVideoDefPtr def, virBufferPtr buffer)
{
    unsigned long long vram;

    if (def->type != VIR_DOMAIN_VIDEO_TYPE_VMVGA) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported video device type '%s'"),
                       virDomainVideoTypeToString(def->type));
        return -1;
    }

    /*
     * For Windows guests the VRAM size should be a multiple of 64 kilobyte.
     * See http://kb.vmware.com/kb/1003 and http://kb.vmware.com/kb/1001558
     */
    vram = VIR_DIV_UP(def->vram, 64) * 64;

    if (def->heads > 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Multi-head video devices are unsupported"));
        return -1;
    }

    virBufferAsprintf(buffer, "svga.vramSize = \"%lld\"\n",
                      vram * 1024); /* kilobyte to byte */

    return 0;
}
