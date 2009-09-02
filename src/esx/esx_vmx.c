
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
->arch
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
->dst = sd[<controller> * 16 + <id> mapped to [a-z]+]
->driverName = <driver>           <=>   scsi0.virtualDev = "<driver>"           # default depends on guestOS value
->driverType
->cachemode                       <=>   scsi0:0.writeThrough = "<value>"        # defaults to false, true -> _DISK_CACHE_WRITETHRU, false _DISK_CACHE_DEFAULT
->readonly
->shared
->slotnum


## disks: ide hard drive from .vmdk image ######################################

                                        ide0.present = "true"                   # defaults to "false"
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
->dst = sd[<controller> * 16 + <id> mapped to [a-z]+]
->driverName = <driver>           <=>   scsi0.virtualDev = "<driver>"           # default depends on guestOS value
->driverType
->cachemode
->readonly
->shared
->slotnum


## disks: ide cdrom from .iso image ############################################

                                        ide0.present = "true"                   # defaults to "false"
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

                                        ide0.present = "true"                   # defaults to "false"
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
                                        ethernet0.generatedAddressOffset = "0"  # ?
->mac = <value>                   <=>   ethernet0.generatedAddress = "<value>"


                                        ethernet0.addressType = "static"        # default to "generated"
->mac = <value>                   <=>   ethernet0.address = "<value>"


                                        ethernet0.addressType = "vpx"           # default to "generated"
->mac = <value>                   <=>   ethernet0.generatedAddress = "<value>"

                                                                                # 00:0c:29 prefix for autogenerated mac's
                                                                                # 00:50:56 prefix for manual configured mac's
                                                                                # 00:05:69 old prefix from esx 1.5


## nets: bridged ###############################################################

...
->type = _NET_TYPE_BRIDGE         <=>   ethernet0.connectionType = "bridged"    # defaults to "bridged"


## nets: hostonly ##############################################################

...                                                                             # FIXME: maybe not supported by ESX?
->type = _NET_TYPE_NETWORK        <=>   ethernet0.connectionType = "hostonly"   # defaults to "bridged"


## nets: nat ###################################################################

...                                                                             # FIXME: maybe not supported by ESX?
->type = _NET_TYPE_USER           <=>   ethernet0.connectionType = "nat"        # defaults to "bridged"


## nets: custom ################################################################

...
->type = _NET_TYPE_BRIDGE         <=>   ethernet0.connectionType = "custom"     # defaults to "bridged"
->data.bridge.brname = <value>    <=>   ethernet0.vnet = "<value>"



################################################################################
## serials #####################################################################

                                        serial[0..3] -> <port>

                                        serial0.present = "true"                # defaults to "false"
                                        serial0.startConnected = "true"         # defaults to "true"

def->serials[0]...
->dstPort = <port>


## serials: device #############################################################

->type = _CHR_TYPE_DEV            <=>   serial0.fileType = "device"
->data.file.path = <value>        <=>   serial0.fileName = "<value>"            # e.g. "/dev/ttyS0"
???                               <=>   serial0.tryNoRxLoss = "false"           # defaults to "false", FIXME: not representable


## serials: file ###############################################################

->type = _CHR_TYPE_FILE           <=>   serial0.fileType = "file"
->data.file.path = <value>        <=>   serial0.fileName = "<value>"            # e.g. "serial0.file"
???                               <=>   serial0.tryNoRxLoss = "false"           # defaults to "false", FIXME: not representable


## serials: pipe, far end -> app ###############################################

->type = _CHR_TYPE_PIPE           <=>   serial0.fileType = "pipe"
->data.file.path = <value>        <=>   serial0.fileName = "<value>"            # e.g. "serial0.pipe"
???                               <=>   serial0.pipe.endPoint = "client"        # defaults to "server", FIXME: not representable
???                               <=>   serial0.tryNoRxLoss = "true"            # defaults to "false", FIXME: not representable

->type = _CHR_TYPE_PIPE           <=>   serial0.fileType = "pipe"
->data.file.path = <value>        <=>   serial0.fileName = "<value>"            # e.g. "serial0.pipe"
???                               <=>   serial0.pipe.endPoint = "server"        # defaults to "server", FIXME: not representable
???                               <=>   serial0.tryNoRxLoss = "true"            # defaults to "false", FIXME: not representable


## serials: pipe, far end -> vm ################################################

->type = _CHR_TYPE_PIPE           <=>   serial0.fileType = "pipe"
->data.file.path = <value>        <=>   serial0.fileName = "<value>"            # e.g. "serial0.pipe"
???                               <=>   serial0.pipe.endPoint = "client"        # defaults to "server", FIXME: not representable
???                               <=>   serial0.tryNoRxLoss = "false"           # defaults to "false", FIXME: not representable

->type = _CHR_TYPE_PIPE           <=>   serial0.fileType = "pipe"
->data.file.path = <value>        <=>   serial0.fileName = "<value>"            # e.g. "serial0.pipe"
???                               <=>   serial0.pipe.endPoint = "server"        # defaults to "server", FIXME: not representable
???                               <=>   serial0.tryNoRxLoss = "false"           # defaults to "false", FIXME: not representable



################################################################################
## parallels ###################################################################

                                        parallel[0..2] -> <port>

                                        parallel0.present = "true"              # defaults to "false"
                                        parallel0.startConnected = "true"       # defaults to "true"

def->parallels[0]...
->dstPort = <port>


## parallels: device #############################################################

->type = _CHR_TYPE_DEV            <=>   parallel0.fileType = "device"
->data.file.path = <value>        <=>   parallel0.fileName = "<value>"          # e.g. "/dev/parport0"
???                               <=>   parallel0.bidirectional = "<value>"     # defaults to ?, FIXME: not representable


## parallels: file #############################################################

->type = _CHR_TYPE_FILE           <=>   parallel0.fileType = "file"
->data.file.path = <value>        <=>   parallel0.fileName = "<value>"          # e.g. "parallel0.file"
???                               <=>   parallel0.bidirectional = "<value>"     # must be "false" for fileType = "file", FIXME: not representable

*/

#define VIR_FROM_THIS VIR_FROM_ESX

#define ESX_ERROR(conn, code, fmt...)                                         \
    virReportErrorHelper (conn, VIR_FROM_ESX, code, __FILE__, __FUNCTION__,   \
                          __LINE__, fmt)



#define ESX_BUILD_VMX_NAME(_suffix)                                           \
    snprintf(_suffix##_name, sizeof(_suffix##_name), "%s."#_suffix, prefix);



virDomainDefPtr
esxVMX_ParseConfig(virConnectPtr conn, const char *vmx,
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
    int controller;
    int port;
    int present;
    char *scsi_virtualDev = NULL;
    int id;

    conf = virConfReadMem(vmx, strlen(vmx), VIR_CONF_FLAG_VMX_FORMAT);

    if (conf == NULL) {
        return NULL;
    }

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError(conn);
        goto failure;
    }

    def->virtType = VIR_DOMAIN_VIRT_VMWARE; /* FIXME: maybe add VIR_DOMAIN_VIRT_ESX ? */
    def->id = -1;

    if (esxUtil_GetConfigLong(conn, conf, "config.version",
                              &config_version, 0, 0) < 0) {
        goto failure;
    }

    if (config_version != 8) {
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                  "Expecting VMX entry 'config.version' to be 8 but found "
                  "%lld", config_version);
        goto failure;
    }

    if (esxUtil_GetConfigLong(conn, conf, "virtualHW.version",
                              &virtualHW_version, 0, 0) < 0) {
        goto failure;
    }

    switch (apiVersion) {
      case esxVI_APIVersion_25:
        if (virtualHW_version != 4) {
            ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                      "Expecting VMX entry 'virtualHW.version' to be 4 for "
                      "VI API version 2.5 but found %lld", virtualHW_version);
            goto failure;
        }

        break;

      case esxVI_APIVersion_40:
        if (virtualHW_version != 7) {
            ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                      "Expecting VMX entry 'virtualHW.version' to be 7 for "
                      "VI API version 4.0 but found %lld", virtualHW_version);
            goto failure;
        }

        break;

      case esxVI_APIVersion_Unknown:
        if (virtualHW_version != 4 && virtualHW_version != 7) {
            ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                      "Expecting VMX entry 'virtualHW.version' to be 4 or 7 "
                      "but found %lld", virtualHW_version);
            goto failure;
        }

        break;

      default:
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                  "Expecting VI API version 2.5 or 4.0");
        goto failure;
    }

    /* def:uuid */
    /* FIXME: Need to handle 'uuid.action = "create"' */
    if (esxUtil_GetConfigUUID(conn, conf, "uuid.bios", def->uuid, 1) < 0) {
        goto failure;
    }

    /* def:name */
    if (esxUtil_GetConfigString(conn, conf, "displayName",
                                &def->name, 1) < 0) {
        goto failure;
    }

    /* def:maxmem */
    if (esxUtil_GetConfigLong(conn, conf, "memsize", &memsize, 32, 1) < 0) {
        goto failure;
    }

    if (memsize <= 0 || memsize % 4 != 0) {
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                  "Expecting VMX entry 'memsize' to be an unsigned "
                  "integer (multiple of 4) but found %lld", memsize);
        goto failure;
    }

    def->maxmem = memsize * 1024; /* Scale from megabytes to kilobytes */

    /* def:memory */
    if (esxUtil_GetConfigLong(conn, conf, "sched.mem.max", &memory,
                              memsize, 1) < 0) {
        goto failure;
    }

    if (memory < 0) {
        memory = memsize;
    }

    def->memory = memory * 1024; /* Scale from megabytes to kilobytes */

    if (def->memory > def->maxmem) {
        def->memory = def->maxmem;
    }

    /* def:vcpus */
    if (esxUtil_GetConfigLong(conn, conf, "numvcpus", &numvcpus, 1, 1) < 0) {
        goto failure;
    }

    if (numvcpus <= 0 || (numvcpus % 2 != 0 && numvcpus != 1)) {
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                  "Expecting VMX entry 'numvcpus' to be an unsigned "
                  "integer (1 or a multiple of 2) but found %lld", numvcpus);
        goto failure;
    }

    def->vcpus = numvcpus;

    /* def:cpumask */
    // VirtualMachine:config.cpuAffinity.affinitySet
    if (esxUtil_GetConfigString(conn, conf, "sched.cpu.affinity",
                                &sched_cpu_affinity, 1) < 0) {
        goto failure;
    }

    if (sched_cpu_affinity != NULL && STRNEQ(sched_cpu_affinity, "all")) {
        const char *current = sched_cpu_affinity;
        int number, count = 0;

        def->cpumasklen = 0;

        if (VIR_ALLOC_N(def->cpumask, VIR_DOMAIN_CPUMASK_LEN) < 0) {
            virReportOOMError(conn);
            goto failure;
        }

        while (*current != '\0') {
            virSkipSpaces(&current);

            number = virParseNumber(&current);

            if (number < 0) {
                ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                          "Expecting VMX entry 'sched.cpu.affinity' to be "
                          "a comma separated list of unsigned integers but "
                          "found '%s'", sched_cpu_affinity);
                goto failure;
            }

            if (number >= VIR_DOMAIN_CPUMASK_LEN) {
                ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
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
                ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                          "Expecting VMX entry 'sched.cpu.affinity' to be "
                          "a comma separated list of unsigned integers but "
                          "found '%s'", sched_cpu_affinity);
                goto failure;
            }

            virSkipSpaces(&current);
        }

        if (count < numvcpus) {
            ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
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
        virReportOOMError(conn);
        goto failure;
    }

/*
    def->emulator
    def->features*/

/*
    def->localtime*/

    /* def:graphics */
    /* FIXME */

    /* def:disks: 4 * 16 scsi + 2 * 2 ide + 2 floppy = 70 */
    if (VIR_ALLOC_N(def->disks, 72) < 0) {
        virReportOOMError(conn);
        goto failure;
    }

    def->ndisks = 0;

    /* def:disks (scsi) */
    for (controller = 0; controller < 4; ++controller) {
        VIR_FREE(scsi_virtualDev);

        if (esxVMX_ParseSCSIController(conn, conf, controller,
                                       &present, &scsi_virtualDev) < 0) {
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

            if (esxVMX_ParseDisk(conn, conf, VIR_DOMAIN_DISK_DEVICE_DISK,
                                 VIR_DOMAIN_DISK_BUS_SCSI, controller, id,
                                 scsi_virtualDev,
                                 &def->disks[def->ndisks]) < 0) {
                goto failure;
            }

            if (def->disks[def->ndisks] != NULL) {
                ++def->ndisks;
                continue;
            }

            if (esxVMX_ParseDisk(conn, conf, VIR_DOMAIN_DISK_DEVICE_CDROM,
                                 VIR_DOMAIN_DISK_BUS_SCSI, controller, id,
                                 scsi_virtualDev,
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
            if (esxVMX_ParseDisk(conn, conf, VIR_DOMAIN_DISK_DEVICE_DISK,
                                 VIR_DOMAIN_DISK_BUS_IDE, controller, id,
                                 NULL, &def->disks[def->ndisks]) < 0) {
                goto failure;
            }

            if (def->disks[def->ndisks] != NULL) {
                ++def->ndisks;
                continue;
            }

            if (esxVMX_ParseDisk(conn, conf, VIR_DOMAIN_DISK_DEVICE_CDROM,
                                 VIR_DOMAIN_DISK_BUS_IDE, controller, id,
                                 NULL, &def->disks[def->ndisks]) < 0) {
                goto failure;
            }

            if (def->disks[def->ndisks] != NULL) {
                ++def->ndisks;
            }
        }
    }

    /* def:disks (floppy) */
    for (controller = 0; controller < 2; ++controller) {
        if (esxVMX_ParseDisk(conn, conf, VIR_DOMAIN_DISK_DEVICE_FLOPPY,
                             VIR_DOMAIN_DISK_BUS_FDC, controller, -1, NULL,
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
        virReportOOMError(conn);
        goto failure;
    }

    def->nnets = 0;

    for (controller = 0; controller < 4; ++controller) {
        if (esxVMX_ParseEthernet(conn, conf, controller,
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
        virReportOOMError(conn);
        goto failure;
    }

    def->nserials = 0;

    for (port = 0; port < 4; ++port) {
        if (esxVMX_ParseSerial(conn, conf, port,
                               &def->serials[def->nserials]) < 0) {
            goto failure;
        }

        if (def->serials[def->nserials] != NULL) {
            ++def->nserials;
        }
    }

    /* def:parallels */
    if (VIR_ALLOC_N(def->parallels, 3) < 0) {
        virReportOOMError(conn);
        goto failure;
    }

    def->nparallels = 0;

    for (port = 0; port < 3; ++port) {
        if (esxVMX_ParseParallel(conn, conf, port,
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
    VIR_FREE(scsi_virtualDev);

    return def;

failure:
    virDomainDefFree(def);
    def = NULL;

    goto cleanup;
}



int
esxVMX_ParseSCSIController(virConnectPtr conn, virConfPtr conf, int controller,
                           int *present, char **virtualDev)
{
    char present_name[32];
    char virtualDev_name[32];

    if (virtualDev == NULL || *virtualDev != NULL) {
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        goto failure;
    }

    if (controller < 0 || controller > 3) {
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                  "SCSI controller index %d out of [0..3] range",
                  controller);
        goto failure;
    }

    snprintf(present_name, sizeof(present_name), "scsi%d.present", controller);
    snprintf(virtualDev_name, sizeof(virtualDev_name), "scsi%d.virtualDev",
             controller);

    if (esxUtil_GetConfigBoolean(conn, conf, present_name, present, 0, 1) < 0) {
        goto failure;
    }

    if (! *present) {
        return 0;
    }

    if (esxUtil_GetConfigString(conn, conf, virtualDev_name,
                                virtualDev, 0) < 0) {
        goto failure;
    }

    if (*virtualDev != NULL &&
        STRCASENEQ(*virtualDev, "buslogic") &&
        STRCASENEQ(*virtualDev, "lsilogic")) {
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                  "Expecting VMX entry '%s' to be 'buslogic' or 'lsilogic' "
                  "but found '%s'", virtualDev_name, *virtualDev);
        goto failure;
    }

    return 0;

failure:
    VIR_FREE(*virtualDev);

    return -1;
}



char *
esxVMX_IndexToDiskName(virConnectPtr conn, int idx, const char *prefix)
{
    char buffer[32] = "";
    char *name = NULL;
    size_t length = strlen(prefix);

    if (length > sizeof (buffer) - 2 - 1) {
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                  "Disk name prefix '%s' is too long", prefix);
        return NULL;
    }

    strncpy(buffer, prefix, sizeof (buffer) - 1);
    buffer[sizeof (buffer) - 1] = '\0';

    if (idx < 26) {
        buffer[length] = 'a' + idx;
    } else if (idx < 702) {
        buffer[length] = 'a' + idx / 26 - 1;
        buffer[length + 1] = 'a' + idx % 26;
    } else {
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                  "Disk index %d is too large", idx);
        return NULL;
    }

    name = strdup(buffer);

    if (name == NULL) {
        virReportOOMError(conn);
        return NULL;
    }

    return name;
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
esxVMX_ParseDisk(virConnectPtr conn, virConfPtr conf, int device, int bus,
                 int controller, int id, const char *virtualDev,
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
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (VIR_ALLOC(*def) < 0) {
        virReportOOMError(conn);
        goto failure;
    }

    (*def)->device = device;
    (*def)->bus = bus;

    /* def:dst, def:driverName */
    if (device == VIR_DOMAIN_DISK_DEVICE_DISK ||
        device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
        if (bus == VIR_DOMAIN_DISK_BUS_SCSI) {
            if (controller < 0 || controller > 3) {
                ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                          "SCSI controller index %d out of [0..3] range",
                          controller);
                goto failure;
            }

            if (id < 0 || id > 15 || id == 7) {
                ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                          "SCSI ID %d out of [0..6,8..15] range", id);
                goto failure;
            }

            if (virAsprintf(&prefix, "scsi%d:%d", controller, id) < 0) {
                virReportOOMError(conn);
                goto failure;
            }

            (*def)->dst = esxVMX_IndexToDiskName(conn, controller * 16 + id,
                                                 "sd");

            if ((*def)->dst == NULL) {
                goto failure;
            }

            if (virtualDev != NULL) {
                (*def)->driverName = strdup(virtualDev);

                if ((*def)->driverName == NULL) {
                    virReportOOMError(conn);
                    goto failure;
                }
            }
        } else if (bus == VIR_DOMAIN_DISK_BUS_IDE) {
            if (controller < 0 || controller > 1) {
                ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                          "IDE controller index %d out of [0..1] range",
                          controller);
                goto failure;
            }

            if (id < 0 || id > 1) {
                ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                          "IDE ID %d out of [0..1] range", id);
                goto failure;
            }

            if (virAsprintf(&prefix, "ide%d:%d", controller, id) < 0) {
                virReportOOMError(conn);
                goto failure;
            }

            (*def)->dst = esxVMX_IndexToDiskName(conn, controller * 2 + id,
                                                 "hd");

            if ((*def)->dst == NULL) {
                goto failure;
            }
        } else {
            ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                      "Unsupported bus type '%s' for '%s' device type",
                      virDomainDiskBusTypeToString (bus),
                      virDomainDiskDeviceTypeToString (device));
            goto failure;
        }
    } else if (device == VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
        if (bus == VIR_DOMAIN_DISK_BUS_FDC) {
            if (controller < 0 || controller > 1) {
                ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                          "Floppy controller index %d out of [0..1] range",
                          controller);
                goto failure;
            }

            if (virAsprintf(&prefix, "floppy%d", controller) < 0) {
                virReportOOMError(conn);
                goto failure;
            }

            (*def)->dst = esxVMX_IndexToDiskName(conn, controller, "fd");

            if ((*def)->dst == NULL) {
                goto failure;
            }
        } else {
            ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                      "Unsupported bus type '%s' for '%s' device type",
                      virDomainDiskBusTypeToString (bus),
                      virDomainDiskDeviceTypeToString (device));
            goto failure;
        }
    } else {
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                  "Unsupported device type '%s'",
                  virDomainDiskDeviceTypeToString (device));
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
    if (esxUtil_GetConfigBoolean(conn, conf, present_name,
                                 &present, 0, 1) < 0) {
        goto failure;
    }

    /* vmx:startConnected */
    if (esxUtil_GetConfigBoolean(conn, conf, startConnected_name,
                                 &startConnected, 1, 1) < 0) {
        goto failure;
    }

    /* FIXME: Need to distiguish between active and inactive domains here */
    if (! present/* && ! startConnected*/) {
        goto ignore;
    }

    /* vmx:deviceType -> def:type */
    if (esxUtil_GetConfigString(conn, conf, deviceType_name,
                                &deviceType, 1) < 0) {
        goto failure;
    }

    /* vmx:clientDevice */
    if (esxUtil_GetConfigBoolean(conn, conf, clientDevice_name,
                                 &clientDevice, 0, 1) < 0) {
        goto failure;
    }

    if (clientDevice) {
        /*
         * Just ignore devices in client mode, because I have no clue how to
         * handle them (e.g. assign an image) without the VI client GUI.
         */
        goto ignore;
    }

    /* vmx:fileType -> def:type */
    if (esxUtil_GetConfigString(conn, conf, fileType_name, &fileType, 1) < 0) {
        goto failure;
    }

    /* vmx:fileName -> def:src, def:type */
    if (esxUtil_GetConfigString(conn, conf, fileName_name,
                                &fileName, 0) < 0) {
        goto failure;
    }

    /* vmx:writeThrough -> def:cachemode */
    if (esxUtil_GetConfigBoolean(conn, conf, writeThrough_name,
                                 &writeThrough, 0, 1) < 0) {
        goto failure;
    }

    /* Setup virDomainDiskDef */
    /* FIXME: Need the datastore name for fileName */
    if (device == VIR_DOMAIN_DISK_DEVICE_DISK) {
        if (esxUtil_EqualSuffix(fileName, ".vmdk")) {
            if (deviceType != NULL) {
                if (bus == VIR_DOMAIN_DISK_BUS_SCSI &&
                    STRCASENEQ(deviceType, "scsi-hardDisk")) {
                    ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                              "Expecting VMX entry '%s' to be 'scsi-hardDisk' "
                              "but found '%s'", deviceType_name, deviceType);
                    goto failure;
                } else if (bus == VIR_DOMAIN_DISK_BUS_IDE &&
                           STRCASENEQ(deviceType, "ata-hardDisk")) {
                    ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                              "Expecting VMX entry '%s' to be 'ata-hardDisk' "
                              "but found '%s'", deviceType_name, deviceType);
                    goto failure;
                }
            }

            (*def)->type = VIR_DOMAIN_DISK_TYPE_FILE;
            (*def)->src = fileName;
            (*def)->cachemode = writeThrough ? VIR_DOMAIN_DISK_CACHE_WRITETHRU
                                             : VIR_DOMAIN_DISK_CACHE_DEFAULT;

            fileName = NULL;
        } else if (esxUtil_EqualSuffix(fileName, ".iso") ||
                   STREQ(deviceType, "atapi-cdrom")) {
            /*
             * This function was called in order to parse a harddisk device,
             * but .iso files and 'atapi-cdrom' devices are for CDROM devices
             * only. Just ignore it, another call to this function to parse a
             * CDROM device may handle it.
             */
            goto ignore;
        } else {
            ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                      "Invalid or not yet handled value '%s' for VMX entry "
                      "'%s'", fileName, fileName_name);
            goto failure;
        }
    } else if (device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
        if (esxUtil_EqualSuffix(fileName, ".iso")) {
            if (deviceType != NULL) {
                if (STRCASENEQ(deviceType, "cdrom-image")) {
                    ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                              "Expecting VMX entry '%s' to be 'cdrom-image' "
                              "but found '%s'", deviceType_name, deviceType);
                    goto failure;
                }
            }

            (*def)->type = VIR_DOMAIN_DISK_TYPE_FILE;
            (*def)->src = fileName;

            fileName = NULL;
        } else if (esxUtil_EqualSuffix(fileName, ".vmdk")) {
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
            ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                      "Invalid or not yet handled value '%s' for VMX entry "
                      "'%s'", fileName, fileName_name);
            goto failure;
        }
    } else if (device == VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
        if (esxUtil_EqualSuffix(fileName, ".flp")) {
            if (fileType != NULL) {
                if (STRCASENEQ(fileType, "file")) {
                    ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                              "Expecting VMX entry '%s' to be 'file' but "
                              "found '%s'", fileType_name, fileType);
                    goto failure;
                }
            }

            (*def)->type = VIR_DOMAIN_DISK_TYPE_FILE;
            (*def)->src = fileName;

            fileName = NULL;
        } else if (fileType != NULL && STREQ(fileType, "device")) {
            (*def)->type = VIR_DOMAIN_DISK_TYPE_BLOCK;
            (*def)->src = fileName;

            fileName = NULL;
        } else {
            ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                      "Invalid or not yet handled value '%s' for VMX entry "
                      "'%s'", fileName, fileName_name);
            goto failure;
        }
    } else {
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                  "Unsupported device type '%s'",
                  virDomainDiskDeviceTypeToString (device));
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
esxVMX_ParseEthernet(virConnectPtr conn, virConfPtr conf, int controller,
                     virDomainNetDefPtr *def)
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

    if (def == NULL || *def != NULL) {
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (controller < 0 || controller > 3) {
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                  "Ethernet controller index %d out of [0..3] range",
                  controller);
        goto failure;
    }

    if (VIR_ALLOC(*def) < 0) {
        virReportOOMError(conn);
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
    ESX_BUILD_VMX_NAME(vnet);

    /* vmx:present */
    if (esxUtil_GetConfigBoolean(conn, conf, present_name,
                                 &present, 0, 1) < 0) {
        goto failure;
    }

    /* vmx:startConnected */
    if (esxUtil_GetConfigBoolean(conn, conf, startConnected_name,
                                 &startConnected, 1, 1) < 0) {
        goto failure;
    }

    /* FIXME: Need to distiguish between active and inactive domains here */
    if (! present/* && ! startConnected*/) {
        goto ignore;
    }

    /* vmx:connectionType -> def:type */
    if (esxUtil_GetConfigString(conn, conf, connectionType_name,
                                &connectionType, 1) < 0) {
        goto failure;
    }

    /* vmx:addressType, vmx:generatedAddress, vmx:address -> def:mac */
    if (esxUtil_GetConfigString(conn, conf, addressType_name,
                                &addressType, 1) < 0 ||
        esxUtil_GetConfigString(conn, conf, generatedAddress_name,
                                &generatedAddress, 1) < 0 ||
        esxUtil_GetConfigString(conn, conf, address_name, &address, 1) < 0) {
        goto failure;
    }

    if (addressType == NULL || STRCASEEQ(addressType, "generated") ||
        STRCASEEQ(addressType, "vpx")) {
        if (generatedAddress != NULL) {
            if (virParseMacAddr(generatedAddress, (*def)->mac) < 0) {
                ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                          "Expecting VMX entry '%s' to be MAC address but "
                          "found '%s'", generatedAddress_name,
                          generatedAddress);
                goto failure;
            }
        }
    } else if (STRCASEEQ(addressType, "static")) {
        if (address != NULL) {
            if (virParseMacAddr(address, (*def)->mac) < 0) {
                ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                          "Expecting VMX entry '%s' to be MAC address but "
                          "found '%s'", address_name, address);
                goto failure;
            }
        }
    } else {
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                  "Expecting VMX entry '%s' to be 'generated' or 'static' or "
                  "'vpx' but found '%s'", addressType_name, addressType);
        goto failure;
    }

    /* vmx:virtualDev -> def:model */
    if (esxUtil_GetConfigString(conn, conf, virtualDev_name,
                                &virtualDev, 1) < 0) {
        goto failure;
    }

    if (virtualDev != NULL &&
        STRCASENEQ(virtualDev, "vlance") &&
        STRCASENEQ(virtualDev, "vmxnet") &&
        STRCASENEQ(virtualDev, "e1000")) {
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                  "Expecting VMX entry '%s' to be 'vlance' or 'vmxnet' or "
                  "'e1000' but found '%s'", virtualDev_name, virtualDev);
        goto failure;
    }

    /* vmx:vnet -> def:data.bridge.brname */
    if (connectionType != NULL && STRCASEEQ(connectionType, "custom") &&
        esxUtil_GetConfigString(conn, conf, vnet_name, &vnet, 0) < 0) {
        goto failure;
    }

    /* Setup virDomainNetDef */
    if (connectionType == NULL || STRCASEEQ(connectionType, "bridged")) {
        (*def)->type = VIR_DOMAIN_NET_TYPE_BRIDGE;
        (*def)->model = virtualDev;

        virtualDev = NULL;
    } else if (STRCASEEQ(connectionType, "hostonly")) {
        /* FIXME */
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                  "No yet handled value '%s' for VMX entry '%s'",
                  connectionType, connectionType_name);
        goto failure;
    } else if (STRCASEEQ(connectionType, "nat")) {
        /* FIXME */
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                  "No yet handled value '%s' for VMX entry '%s'",
                  connectionType, connectionType_name);
        goto failure;
    } else if (STRCASEEQ(connectionType, "custom")) {
        (*def)->type = VIR_DOMAIN_NET_TYPE_BRIDGE;
        (*def)->model = virtualDev;
        (*def)->data.bridge.brname = vnet;

        virtualDev = NULL;
        vnet = NULL;
    } else {
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
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
esxVMX_ParseSerial(virConnectPtr conn, virConfPtr conf, int port,
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
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (port < 0 || port > 3) {
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                  "Serial port index %d out of [0..3] range", port);
        goto failure;
    }

    if (VIR_ALLOC(*def) < 0) {
        virReportOOMError(conn);
        goto failure;
    }

    snprintf(prefix, sizeof(prefix), "serial%d", port);

    ESX_BUILD_VMX_NAME(present);
    ESX_BUILD_VMX_NAME(startConnected);
    ESX_BUILD_VMX_NAME(fileType);
    ESX_BUILD_VMX_NAME(fileName);

    /* vmx:present */
    if (esxUtil_GetConfigBoolean(conn, conf, present_name,
                                 &present, 0, 1) < 0) {
        goto failure;
    }

    /* vmx:startConnected */
    if (esxUtil_GetConfigBoolean(conn, conf, startConnected_name,
                                 &startConnected, 1, 1) < 0) {
        goto failure;
    }

    /* FIXME: Need to distiguish between active and inactive domains here */
    if (! present/* && ! startConnected*/) {
        goto ignore;
    }

    /* vmx:fileType -> def:type */
    if (esxUtil_GetConfigString(conn, conf, fileType_name, &fileType, 0) < 0) {
        goto failure;
    }

    /* vmx:fileName -> def:data.file.path */
    if (esxUtil_GetConfigString(conn, conf, fileName_name, &fileName, 0) < 0) {
        goto failure;
    }

    /* Setup virDomainChrDef */
    if (STRCASEEQ(fileType, "device")) {
        (*def)->dstPort = port;
        (*def)->type = VIR_DOMAIN_CHR_TYPE_DEV;
        (*def)->data.file.path = fileName;

        fileName = NULL;
    } else if (STRCASEEQ(fileType, "file")) {
        (*def)->dstPort = port;
        (*def)->type = VIR_DOMAIN_CHR_TYPE_FILE;
        (*def)->data.file.path = fileName;

        fileName = NULL;
    } else if (STRCASEEQ(fileType, "pipe")) {
        /* FIXME */
        VIR_WARN("Serial port %d has currently unsupported type '%s', "
                 "ignoring it", port, fileType);
        goto ignore;
    } else {
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
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
esxVMX_ParseParallel(virConnectPtr conn, virConfPtr conf, int port,
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
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR, "Invalid argument");
        return -1;
    }

    if (port < 0 || port > 2) {
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                  "Parallel port index %d out of [0..2] range", port);
        goto failure;
    }

    if (VIR_ALLOC(*def) < 0) {
        virReportOOMError(conn);
        goto failure;
    }

    snprintf(prefix, sizeof(prefix), "parallel%d", port);

    ESX_BUILD_VMX_NAME(present);
    ESX_BUILD_VMX_NAME(startConnected);
    ESX_BUILD_VMX_NAME(fileType);
    ESX_BUILD_VMX_NAME(fileName);

    /* vmx:present */
    if (esxUtil_GetConfigBoolean(conn, conf, present_name,
                                 &present, 0, 1) < 0) {
        goto failure;
    }

    /* vmx:startConnected */
    if (esxUtil_GetConfigBoolean(conn, conf, startConnected_name,
                                 &startConnected, 1, 1) < 0) {
        goto failure;
    }

    /* FIXME: Need to distiguish between active and inactive domains here */
    if (! present/* && ! startConnected*/) {
        goto ignore;
    }

    /* vmx:fileType -> def:type */
    if (esxUtil_GetConfigString(conn, conf, fileType_name, &fileType, 0) < 0) {
        goto failure;
    }

    /* vmx:fileName -> def:data.file.path */
    if (esxUtil_GetConfigString(conn, conf, fileName_name, &fileName, 0) < 0) {
        goto failure;
    }

    /* Setup virDomainChrDef */
    if (STRCASEEQ(fileType, "device")) {
        (*def)->dstPort = port;
        (*def)->type = VIR_DOMAIN_CHR_TYPE_DEV;
        (*def)->data.file.path = fileName;

        fileName = NULL;
    } else if (STRCASEEQ(fileType, "file")) {
        (*def)->dstPort = port;
        (*def)->type = VIR_DOMAIN_CHR_TYPE_FILE;
        (*def)->data.file.path = fileName;

        fileName = NULL;
    } else {
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
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
