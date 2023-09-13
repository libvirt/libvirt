/*
 * domain_postparse.c: domain post parsing helpers
 *
 * Copyright (C) 2022 Red Hat, Inc.
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

#include "domain_postparse.h"
#include "viralloc.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN

VIR_LOG_INIT("conf.domain_postparse");

static int
virDomainDefPostParseMemory(virDomainDef *def,
                            unsigned int parseFlags)
{
    size_t i;
    unsigned long long numaMemory = 0;
    unsigned long long hotplugMemory = 0;

    /* Attempt to infer the initial memory size from the sum NUMA memory sizes
     * in case ABI updates are allowed or the <memory> element wasn't specified */
    if (def->mem.total_memory == 0 ||
        parseFlags & VIR_DOMAIN_DEF_PARSE_ABI_UPDATE ||
        parseFlags & VIR_DOMAIN_DEF_PARSE_ABI_UPDATE_MIGRATION)
        numaMemory = virDomainNumaGetMemorySize(def->numa);

    /* calculate the sizes of hotplug memory */
    for (i = 0; i < def->nmems; i++)
        hotplugMemory += def->mems[i]->size;

    if (numaMemory) {
        /* update the sizes in XML if nothing was set in the XML or ABI update
         * is supported */
        virDomainDefSetMemoryTotal(def, numaMemory + hotplugMemory);
    } else {
        /* verify that the sum of memory modules doesn't exceed the total
         * memory. This is necessary for virDomainDefGetMemoryInitial to work
         * properly. */
        if (hotplugMemory > def->mem.total_memory) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Total size of memory devices exceeds the total memory size"));
            return -1;
        }
    }

    if (virDomainDefGetMemoryInitial(def) == 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Memory size must be specified via <memory> or in the <numa> configuration"));
        return -1;
    }

    if (def->mem.cur_balloon > virDomainDefGetMemoryTotal(def) ||
        def->mem.cur_balloon == 0)
        def->mem.cur_balloon = virDomainDefGetMemoryTotal(def);

    if (def->mem.max_memory == 0 && def->mem.memory_slots > 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("maximum memory size must be specified when specifying number of memory slots"));
        return -1;
    }

    if (def->mem.max_memory &&
        def->mem.max_memory < virDomainDefGetMemoryTotal(def)) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("maximum memory size must be equal or greater than the actual memory size"));
        return -1;
    }

    return 0;
}


static int
virDomainDefPostParseOs(virDomainDef *def)
{
    if (!def->os.loader)
        return 0;

    if (def->os.loader->path &&
        def->os.loader->type == VIR_DOMAIN_LOADER_TYPE_NONE) {
        /* By default, loader is type of 'rom' */
        def->os.loader->type = VIR_DOMAIN_LOADER_TYPE_ROM;
    }

    return 0;
}


static void
virDomainDefPostParseMemtune(virDomainDef *def)
{
    size_t i;

    if (virDomainNumaGetNodeCount(def->numa) == 0) {
        /* If guest NUMA is not configured and any hugepage page has nodemask
         * set to "0" free and clear that nodemas, otherwise we would rise
         * an error that there is no guest NUMA node configured. */
        for (i = 0; i < def->mem.nhugepages; i++) {
            ssize_t nextBit;

            if (!def->mem.hugepages[i].nodemask)
                continue;

            nextBit = virBitmapNextSetBit(def->mem.hugepages[i].nodemask, 0);
            if (nextBit < 0) {
                g_clear_pointer(&def->mem.hugepages[i].nodemask,
                                virBitmapFree);
            }
        }
    }
}


static int
virDomainDefPostParseTimer(virDomainDef *def)
{
    size_t i;

    /* verify settings of guest timers */
    for (i = 0; i < def->clock.ntimers; i++) {
        virDomainTimerDef *timer = def->clock.timers[i];

        if (timer->name == VIR_DOMAIN_TIMER_NAME_KVMCLOCK ||
            timer->name == VIR_DOMAIN_TIMER_NAME_HYPERVCLOCK) {
            if (timer->tickpolicy) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("timer %1$s doesn't support setting of timer tickpolicy"),
                               virDomainTimerNameTypeToString(timer->name));
                return -1;
            }
        }

        if (timer->tickpolicy != VIR_DOMAIN_TIMER_TICKPOLICY_CATCHUP &&
            (timer->catchup.threshold != 0 ||
             timer->catchup.limit != 0 ||
             timer->catchup.slew != 0)) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("setting of timer catchup policies is only supported with tickpolicy='catchup'"));
            return -1;
        }

        if (timer->name != VIR_DOMAIN_TIMER_NAME_TSC) {
            if (timer->frequency != 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("timer %1$s doesn't support setting of timer frequency"),
                               virDomainTimerNameTypeToString(timer->name));
                return -1;
             }

            if (timer->mode) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("timer %1$s doesn't support setting of timer mode"),
                               virDomainTimerNameTypeToString(timer->name));
                return -1;
             }
        }

        if (timer->name != VIR_DOMAIN_TIMER_NAME_PLATFORM &&
            timer->name != VIR_DOMAIN_TIMER_NAME_RTC) {
            if (timer->track != VIR_DOMAIN_TIMER_TRACK_NONE) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("timer %1$s doesn't support setting of timer track"),
                               virDomainTimerNameTypeToString(timer->name));
                return -1;
            }
        }
    }

    return 0;
}


static void
virDomainDefPostParseGraphics(virDomainDef *def)
{
    size_t i;

    for (i = 0; i < def->ngraphics; i++) {
        virDomainGraphicsDef *graphics = def->graphics[i];

        /* If spice graphics is configured without ports and with autoport='no'
         * then we start qemu with Spice to not listen anywhere.  Let's convert
         * this configuration to the new listen type='none' which does the
         * same. */
        if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE) {
            virDomainGraphicsListenDef *glisten = &graphics->listens[0];

            if (glisten->type == VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS &&
                graphics->data.spice.port == 0 &&
                graphics->data.spice.tlsPort == 0 &&
                !graphics->data.spice.autoport) {
                VIR_FREE(glisten->address);
                glisten->type = VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NONE;
            }
        }
    }
}


/**
 * virDomainPostParseCheckISCSIPath
 * @srcpath: Source path read (a/k/a, IQN) either disk or hostdev
 *
 * The details of an IQN is defined by RFC 3720 and 3721, but
 * we just need to make sure there's a lun provided. If not
 * provided, then default to zero. For an ISCSI LUN that is
 * is provided by /dev/disk/by-path/... , then that path will
 * have the specific lun requested.
 */
static void
virDomainPostParseCheckISCSIPath(char **srcpath)
{
    char *path = NULL;

    if (strchr(*srcpath, '/'))
        return;

    path = g_strdup_printf("%s/0", *srcpath);
    g_free(*srcpath);
    *srcpath = g_steal_pointer(&path);
}


/* Find out the next usable "unit" of a specific controller */
static int
virDomainControllerSCSINextUnit(const virDomainDef *def,
                                unsigned int controller)
{
    size_t i;

    for (i = 0; i < def->scsiBusMaxUnit; i++) {
        /* Default to assigning addresses using bus = target = 0 */
        const virDomainDeviceDriveAddress addr = {controller, 0, 0, i, 0};

        if (!virDomainSCSIDriveAddressIsUsed(def, &addr))
            return i;
    }

    return -1;
}


static void
virDomainHostdevAssignAddress(virDomainXMLOption *xmlopt G_GNUC_UNUSED,
                              const virDomainDef *def,
                              virDomainHostdevDef *hostdev)
{
    int next_unit = 0;
    int controller = 0;

    /* NB: Do not attempt calling virDomainDefMaybeAddController to
     * automagically add a "new" controller. Doing so will result in
     * qemuDomainFindOrCreateSCSIDiskController "finding" the controller
     * in the domain def list and thus not hotplugging the controller as
     * well as the hostdev in the event that there are either no SCSI
     * controllers defined or there was no space on an existing one.
     *
     * Because we cannot add a controller, then we should not walk the
     * defined controllers list in order to find empty space. Doing
     * so fails to return the valid next unit number for the 2nd
     * hostdev being added to the as yet to be created controller.
     */
    do {
        next_unit = virDomainControllerSCSINextUnit(def, controller);
        if (next_unit < 0)
            controller++;
    } while (next_unit < 0);


    hostdev->info->type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE;
    hostdev->info->addr.drive.controller = controller;
    hostdev->info->addr.drive.bus = 0;
    hostdev->info->addr.drive.target = 0;
    hostdev->info->addr.drive.unit = next_unit;
}


static int
virDomainHostdevDefPostParse(virDomainHostdevDef *dev,
                             const virDomainDef *def,
                             virDomainXMLOption *xmlopt)
{
    virDomainHostdevSubsysSCSI *scsisrc;
    virDomainDeviceDriveAddress *addr = NULL;

    if (dev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
        return 0;

    switch (dev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
        scsisrc = &dev->source.subsys.u.scsi;
        if (scsisrc->protocol == VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI) {
            virDomainHostdevSubsysSCSIiSCSI *iscsisrc = &scsisrc->u.iscsi;
            virDomainPostParseCheckISCSIPath(&iscsisrc->src->path);
        }

        if (dev->info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            virDomainHostdevAssignAddress(xmlopt, def, dev);

        /* Ensure provided address doesn't conflict with existing
         * scsi disk drive address
         */
        addr = &dev->info->addr.drive;
        if (virDomainDriveAddressIsUsedByDisk(def,
                                              VIR_DOMAIN_DISK_BUS_SCSI,
                                              addr)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("SCSI host address controller='%1$u' bus='%2$u' target='%3$u' unit='%4$u' in use by a SCSI disk"),
                           addr->controller, addr->bus,
                           addr->target, addr->unit);
            return -1;
        }
        break;
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV: {
        int model = dev->source.subsys.u.mdev.model;

        if (dev->info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            return 0;

        if ((model == VIR_MDEV_MODEL_TYPE_VFIO_PCI &&
             dev->info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) ||
            (model == VIR_MDEV_MODEL_TYPE_VFIO_CCW &&
             dev->info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Unsupported address type '%1$s' with mediated device model '%2$s'"),
                           virDomainDeviceAddressTypeToString(dev->info->type),
                           virMediatedDeviceModelTypeToString(model));
            return -1;
        }
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
        break;
    }

    return 0;
}


static int
virDomainChrIsaSerialDefPostParse(virDomainDef *def)
{
    size_t i;
    size_t isa_serial_count = 0;
    bool used_serial_port[VIR_MAX_ISA_SERIAL_PORTS] = { false };

    /* Perform all the required checks. */
    for (i = 0; i < def->nserials; i++) {
        if (def->serials[i]->targetType != VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_ISA_SERIAL)
            continue;

        if (isa_serial_count++ >= VIR_MAX_ISA_SERIAL_PORTS ||
            def->serials[i]->target.port >= VIR_MAX_ISA_SERIAL_PORTS) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Maximum supported number of ISA serial ports is '%1$d'"),
                           VIR_MAX_ISA_SERIAL_PORTS);
            return -1;
        }

        if (def->serials[i]->target.port != -1) {
            if (used_serial_port[def->serials[i]->target.port]) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("target port '%1$d' already allocated"),
                               def->serials[i]->target.port);
                return -1;
            }
            used_serial_port[def->serials[i]->target.port] = true;
        }
    }

    /* Assign the ports to the devices. */
    for (i = 0; i < def->nserials; i++) {
        size_t j;

        if (def->serials[i]->targetType != VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_ISA_SERIAL ||
            def->serials[i]->target.port != -1)
            continue;

        for (j = 0; j < VIR_MAX_ISA_SERIAL_PORTS; j++) {
            if (!used_serial_port[j]) {
                def->serials[i]->target.port = j;
                used_serial_port[j] = true;
                break;
            }
        }
    }

    return 0;
}


static int
virDomainChrDefPostParse(virDomainChrDef *chr,
                         const virDomainDef *def)
{
    const virDomainChrDef **arrPtr;
    size_t i, cnt;

    virDomainChrGetDomainPtrs(def, chr->deviceType, &arrPtr, &cnt);

    if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
        chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_NONE) {
        chr->targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL;
    }

    if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL &&
        chr->targetType == VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_ISA_DEBUG &&
        !ARCH_IS_X86(def->os.arch)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("isa-debug serial type only valid on x86 architecture"));
        return -1;
    }

    if (chr->target.port == -1 &&
        (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL ||
         chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL ||
         chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE)) {
        int maxport = -1;

        for (i = 0; i < cnt; i++) {
            if (arrPtr[i]->target.port > maxport)
                maxport = arrPtr[i]->target.port;
        }

        chr->target.port = maxport + 1;
    }

    return 0;
}


static void
virDomainRNGDefPostParse(virDomainRNGDef *rng)
{
    /* set default path for virtio-rng "random" backend to /dev/random */
    if (rng->backend == VIR_DOMAIN_RNG_BACKEND_RANDOM &&
        !rng->source.file) {
        rng->source.file = g_strdup("/dev/random");
    }
}


static void
virDomainDiskExpandGroupIoTune(virDomainDiskDef *disk,
                               const virDomainDef *def)
{
    size_t i;

    if (!disk->blkdeviotune.group_name ||
        virDomainBlockIoTuneInfoHasAny(&disk->blkdeviotune))
        return;

    for (i = 0; i < def->ndisks; i++) {
        virDomainDiskDef *d = def->disks[i];

        if (STRNEQ_NULLABLE(disk->blkdeviotune.group_name, d->blkdeviotune.group_name) ||
            !virDomainBlockIoTuneInfoHasAny(&d->blkdeviotune))
            continue;


        VIR_FREE(disk->blkdeviotune.group_name);
        virDomainBlockIoTuneInfoCopy(&d->blkdeviotune, &disk->blkdeviotune);

        return;
    }
}


static int
virDomainDiskDefPostParse(virDomainDiskDef *disk,
                          const virDomainDef *def,
                          virDomainXMLOption *xmlopt)
{
    if (disk->dst) {
        char *newdst;

        /* Work around for compat with Xen driver in previous libvirt releases */
        if ((newdst = g_strdup(STRSKIP(disk->dst, "ioemu:")))) {
            g_free(disk->dst);
            disk->dst = newdst;
        }
    }

    /* Force CDROM to be listed as read only */
    if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM)
        disk->src->readonly = true;

    if (disk->bus == VIR_DOMAIN_DISK_BUS_NONE) {
        disk->bus = VIR_DOMAIN_DISK_BUS_IDE;

        if (disk->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
            disk->bus = VIR_DOMAIN_DISK_BUS_FDC;
        } else if (disk->dst) {
            if (STRPREFIX(disk->dst, "hd"))
                disk->bus = VIR_DOMAIN_DISK_BUS_IDE;
            else if (STRPREFIX(disk->dst, "sd"))
                disk->bus = VIR_DOMAIN_DISK_BUS_SCSI;
            else if (STRPREFIX(disk->dst, "vd"))
                disk->bus = VIR_DOMAIN_DISK_BUS_VIRTIO;
            else if (STRPREFIX(disk->dst, "xvd"))
                disk->bus = VIR_DOMAIN_DISK_BUS_XEN;
            else if (STRPREFIX(disk->dst, "ubd"))
                disk->bus = VIR_DOMAIN_DISK_BUS_UML;
        }
    }

    if (disk->snapshot == VIR_DOMAIN_SNAPSHOT_LOCATION_DEFAULT &&
        disk->src->readonly)
        disk->snapshot = VIR_DOMAIN_SNAPSHOT_LOCATION_NO;

    if (disk->src->type == VIR_STORAGE_TYPE_NETWORK &&
        disk->src->protocol == VIR_STORAGE_NET_PROTOCOL_ISCSI) {
        virDomainPostParseCheckISCSIPath(&disk->src->path);
    }

    if (disk->src->type == VIR_STORAGE_TYPE_NVME) {
        if (disk->src->nvme->managed == VIR_TRISTATE_BOOL_ABSENT)
            disk->src->nvme->managed = VIR_TRISTATE_BOOL_YES;
    }

    /* vhost-user doesn't allow us to snapshot, disable snapshots by default */
    if (disk->src->type == VIR_STORAGE_TYPE_VHOST_USER &&
        disk->snapshot == VIR_DOMAIN_SNAPSHOT_LOCATION_DEFAULT) {
        disk->snapshot = VIR_DOMAIN_SNAPSHOT_LOCATION_NO;
    }

    if (disk->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
        disk->dst &&
        virDomainDiskDefAssignAddress(xmlopt, disk, def) < 0) {
        return -1;
    }

    virDomainDiskExpandGroupIoTune(disk, def);

    return 0;
}


static void
virDomainVideoDefPostParse(virDomainVideoDef *video,
                           const virDomainDef *def)
{
    /* Fill out (V)RAM if the driver-specific callback did not do so */
    if (video->ram == 0 && video->type == VIR_DOMAIN_VIDEO_TYPE_QXL)
        video->ram = virDomainVideoDefaultRAM(def, video->type);
    if (video->vram == 0)
        video->vram = virDomainVideoDefaultRAM(def, video->type);

    video->ram = VIR_ROUND_UP_POWER_OF_TWO(video->ram);
    video->vram = VIR_ROUND_UP_POWER_OF_TWO(video->vram);
}


static int
virDomainControllerDefPostParse(virDomainControllerDef *cdev)
{
    if (cdev->iothread &&
        cdev->model != VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_SCSI &&
        cdev->model != VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_TRANSITIONAL &&
        cdev->model != VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_NON_TRANSITIONAL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("'iothread' attribute only supported for virtio scsi controllers"));
        return -1;
    }

    return 0;
}


static void
virDomainVsockDefPostParse(virDomainVsockDef *vsock)
{
    if (vsock->auto_cid == VIR_TRISTATE_BOOL_ABSENT) {
        if (vsock->guest_cid != 0)
            vsock->auto_cid = VIR_TRISTATE_BOOL_NO;
        else
            vsock->auto_cid = VIR_TRISTATE_BOOL_YES;
    }
}


static int
virDomainMemoryDefPostParse(virDomainMemoryDef *mem,
                            const virDomainDef *def)
{
    switch (mem->model) {
    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM:
        /* Virtio-pmem mandates shared access so that guest writes get
         * reflected in the underlying file. */
        if (mem->access == VIR_DOMAIN_MEMORY_ACCESS_DEFAULT)
            mem->access = VIR_DOMAIN_MEMORY_ACCESS_SHARED;
        break;

    case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
        /* If no NVDIMM UUID was provided in XML, generate one. */
        if (ARCH_IS_PPC64(def->os.arch) &&
            !mem->target.nvdimm.uuid) {

            mem->target.nvdimm.uuid = g_new0(unsigned char, VIR_UUID_BUFLEN);
            if (virUUIDGenerate(mem->target.nvdimm.uuid) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("Failed to generate UUID"));
                return -1;
            }
        }
        break;

    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM:
    case VIR_DOMAIN_MEMORY_MODEL_SGX_EPC:
    case VIR_DOMAIN_MEMORY_MODEL_DIMM:
    case VIR_DOMAIN_MEMORY_MODEL_NONE:
    case VIR_DOMAIN_MEMORY_MODEL_LAST:
        break;
    }

    return 0;
}


static int
virDomainFSDefPostParse(virDomainFSDef *fs)
{
    if (fs->accessmode == VIR_DOMAIN_FS_ACCESSMODE_DEFAULT && !fs->sock)
        fs->accessmode = VIR_DOMAIN_FS_ACCESSMODE_PASSTHROUGH;

    return 0;
}

static void
virDomainInputDefPostParse(virDomainInputDef *input,
                           const virDomainDef *def)
{
    if (input->bus == VIR_DOMAIN_INPUT_BUS_DEFAULT) {
        if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
            if ((input->type == VIR_DOMAIN_INPUT_TYPE_MOUSE ||
                 input->type == VIR_DOMAIN_INPUT_TYPE_KBD) &&
                (ARCH_IS_X86(def->os.arch) || def->os.arch == VIR_ARCH_NONE)) {
            } else if (ARCH_IS_S390(def->os.arch) ||
                       input->type == VIR_DOMAIN_INPUT_TYPE_PASSTHROUGH) {
                input->bus = VIR_DOMAIN_INPUT_BUS_VIRTIO;
            } else if (input->type == VIR_DOMAIN_INPUT_TYPE_EVDEV) {
                input->bus = VIR_DOMAIN_INPUT_BUS_NONE;
            } else {
                input->bus = VIR_DOMAIN_INPUT_BUS_USB;
            }
        } else if (def->os.type == VIR_DOMAIN_OSTYPE_XEN ||
                   def->os.type == VIR_DOMAIN_OSTYPE_XENPVH) {
            input->bus = VIR_DOMAIN_INPUT_BUS_XEN;
        } else {
            if ((def->virtType == VIR_DOMAIN_VIRT_VZ ||
                 def->virtType == VIR_DOMAIN_VIRT_PARALLELS))
                input->bus = VIR_DOMAIN_INPUT_BUS_PARALLELS;
        }
    }
}

static int
virDomainDeviceDefPostParseCommon(virDomainDeviceDef *dev,
                                  const virDomainDef *def,
                                  unsigned int parseFlags G_GNUC_UNUSED,
                                  virDomainXMLOption *xmlopt)
{
    int ret = -1;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_CHR:
        ret = virDomainChrDefPostParse(dev->data.chr, def);
        break;

    case VIR_DOMAIN_DEVICE_RNG:
        virDomainRNGDefPostParse(dev->data.rng);
        ret = 0;
        break;

    case VIR_DOMAIN_DEVICE_DISK:
        ret = virDomainDiskDefPostParse(dev->data.disk, def, xmlopt);
        break;

    case VIR_DOMAIN_DEVICE_VIDEO:
        virDomainVideoDefPostParse(dev->data.video, def);
        ret = 0;
        break;

    case VIR_DOMAIN_DEVICE_HOSTDEV:
        ret = virDomainHostdevDefPostParse(dev->data.hostdev, def, xmlopt);
        break;

    case VIR_DOMAIN_DEVICE_CONTROLLER:
        ret = virDomainControllerDefPostParse(dev->data.controller);
        break;

    case VIR_DOMAIN_DEVICE_VSOCK:
        virDomainVsockDefPostParse(dev->data.vsock);
        ret = 0;
        break;

    case VIR_DOMAIN_DEVICE_MEMORY:
        ret = virDomainMemoryDefPostParse(dev->data.memory, def);
        break;

    case VIR_DOMAIN_DEVICE_FS:
        ret = virDomainFSDefPostParse(dev->data.fs);
        break;

    case VIR_DOMAIN_DEVICE_INPUT:
        virDomainInputDefPostParse(dev->data.input, def);
        ret = 0;
        break;

    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_NET:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_IOMMU:
    case VIR_DOMAIN_DEVICE_AUDIO:
    case VIR_DOMAIN_DEVICE_CRYPTO:
        ret = 0;
        break;

    case VIR_DOMAIN_DEVICE_NONE:
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unexpected VIR_DOMAIN_DEVICE_NONE"));
        break;

    case VIR_DOMAIN_DEVICE_LAST:
    default:
        virReportEnumRangeError(virDomainDeviceType, dev->type);
        break;
    }

    return ret;
}


/**
 * virDomainDefCheckUnsupportedMemoryHotplug:
 * @def: domain definition
 *
 * Returns -1 if the domain definition would enable memory hotplug via the
 * <maxMemory> tunable and reports an error. Otherwise returns 0.
 */
static int
virDomainDefCheckUnsupportedMemoryHotplug(virDomainDef *def)
{
    /* memory hotplug tunables are not supported by this driver */
    if (virDomainDefHasMemoryHotplug(def)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("memory hotplug tunables <maxMemory> are not supported by this hypervisor driver"));
        return -1;
    }

    return 0;
}


/**
 * virDomainDeviceDefCheckUnsupportedMemoryDevice:
 * @dev: device definition
 *
 * Returns -1 if the device definition describes a memory device and reports an
 * error. Otherwise returns 0.
 */
static int
virDomainDeviceDefCheckUnsupportedMemoryDevice(virDomainDeviceDef *dev)
{
    /* This driver doesn't yet know how to handle memory devices */
    if (dev->type == VIR_DOMAIN_DEVICE_MEMORY) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("memory devices are not supported by this driver"));
        return -1;
    }

    return 0;
}


/**
 * virDomainDefRemoveOfflineVcpuPin:
 * @def: domain definition
 *
 * This function removes vcpu pinning information from offline vcpus. This is
 * designed to be used for drivers which don't support offline vcpupin.
 */
static void
virDomainDefRemoveOfflineVcpuPin(virDomainDef *def)
{
    size_t i;
    virDomainVcpuDef *vcpu;

    for (i = 0; i < virDomainDefGetVcpusMax(def); i++) {
        vcpu = virDomainDefGetVcpu(def, i);

        if (vcpu && !vcpu->online && vcpu->cpumask) {
            g_clear_pointer(&vcpu->cpumask, virBitmapFree);

            VIR_WARN("Ignoring unsupported vcpupin for offline vcpu '%zu'", i);
        }
    }
}


#define UNSUPPORTED(FEATURE) (!((FEATURE) & xmlopt->config.features))
/**
 * virDomainDefPostParseCheckFeatures:
 * @def: domain definition
 * @xmlopt: XML parser option object
 *
 * This function checks that the domain configuration is supported according to
 * the supported features for a given hypervisor. See virDomainDefFeatures and
 * virDomainDefParserConfig.
 *
 * Returns 0 on success and -1 on error with an appropriate libvirt error.
 */
static int
virDomainDefPostParseCheckFeatures(virDomainDef *def,
                                   virDomainXMLOption *xmlopt)
{
    if (UNSUPPORTED(VIR_DOMAIN_DEF_FEATURE_MEMORY_HOTPLUG) &&
        virDomainDefCheckUnsupportedMemoryHotplug(def) < 0)
        return -1;

    if (UNSUPPORTED(VIR_DOMAIN_DEF_FEATURE_OFFLINE_VCPUPIN))
        virDomainDefRemoveOfflineVcpuPin(def);

    if (UNSUPPORTED(VIR_DOMAIN_DEF_FEATURE_NAME_SLASH)) {
        if (def->name && strchr(def->name, '/')) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("name %1$s cannot contain '/'"), def->name);
            return -1;
        }
    }

    if (UNSUPPORTED(VIR_DOMAIN_DEF_FEATURE_INDIVIDUAL_VCPUS) &&
        def->individualvcpus) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("individual CPU state configuration is not supported"));
        return -1;
    }

    return 0;
}


/**
 * virDomainDeviceDefPostParseCheckFeatures:
 * @dev: device definition
 * @xmlopt: XML parser option object
 *
 * This function checks that the device configuration is supported according to
 * the supported features for a given hypervisor. See virDomainDefFeatures and
 * virDomainDefParserConfig.
 *
 * Returns 0 on success and -1 on error with an appropriate libvirt error.
 */
static int
virDomainDeviceDefPostParseCheckFeatures(virDomainDeviceDef *dev,
                                         virDomainXMLOption *xmlopt)
{
    if (UNSUPPORTED(VIR_DOMAIN_DEF_FEATURE_MEMORY_HOTPLUG) &&
        virDomainDeviceDefCheckUnsupportedMemoryDevice(dev) < 0)
        return -1;

    if (UNSUPPORTED(VIR_DOMAIN_DEF_FEATURE_NET_MODEL_STRING) &&
        dev->type == VIR_DOMAIN_DEVICE_NET &&
        dev->data.net->modelstr) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("driver does not support net model '%1$s'"),
                       dev->data.net->modelstr);
        return -1;
    }

    if (dev->type == VIR_DOMAIN_DEVICE_DISK &&
        dev->data.disk->src->fdgroup &&
        UNSUPPORTED(VIR_DOMAIN_DEF_FEATURE_DISK_FD)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("driver does not support FD passing for disk '%1$s'"),
                       dev->data.disk->dst);
        return -1;
    }

    return 0;
}
#undef UNSUPPORTED


static int
virDomainDeviceDefPostParse(virDomainDeviceDef *dev,
                            const virDomainDef *def,
                            unsigned int flags,
                            virDomainXMLOption *xmlopt,
                            void *parseOpaque)
{
    int ret;

    if (xmlopt->config.devicesPostParseCallback) {
        ret = xmlopt->config.devicesPostParseCallback(dev, def, flags,
                                                      xmlopt->config.priv,
                                                      parseOpaque);
        if (ret < 0)
            return ret;
    }

    if ((ret = virDomainDeviceDefPostParseCommon(dev, def, flags, xmlopt)) < 0)
        return ret;

    if (virDomainDeviceDefPostParseCheckFeatures(dev, xmlopt) < 0)
        return -1;

    return 0;
}


int
virDomainDeviceDefPostParseOne(virDomainDeviceDef *dev,
                               const virDomainDef *def,
                               unsigned int flags,
                               virDomainXMLOption *xmlopt,
                               void *parseOpaque)
{
    void *data = NULL;
    int ret;

    if (!parseOpaque && xmlopt->config.domainPostParseDataAlloc) {
        if (xmlopt->config.domainPostParseDataAlloc(def, flags,
                                                    xmlopt->config.priv,
                                                    &data) < 0)
            return -1;
        parseOpaque = data;
    }

    ret = virDomainDeviceDefPostParse(dev, def, flags, xmlopt, parseOpaque);

    if (data && xmlopt->config.domainPostParseDataFree)
        xmlopt->config.domainPostParseDataFree(data);

    return ret;
}


struct virDomainDefPostParseDeviceIteratorData {
    virDomainXMLOption *xmlopt;
    void *parseOpaque;
    unsigned int parseFlags;
};


static int
virDomainDefPostParseDeviceIterator(virDomainDef *def,
                                    virDomainDeviceDef *dev,
                                    virDomainDeviceInfo *info G_GNUC_UNUSED,
                                    void *opaque)
{
    struct virDomainDefPostParseDeviceIteratorData *data = opaque;
    return virDomainDeviceDefPostParse(dev, def,
                                       data->parseFlags, data->xmlopt,
                                       data->parseOpaque);
}


static int
virDomainVcpuDefPostParse(virDomainDef *def)
{
    virDomainVcpuDef *vcpu;
    size_t maxvcpus = virDomainDefGetVcpusMax(def);
    size_t i;

    for (i = 0; i < maxvcpus; i++) {
        vcpu = virDomainDefGetVcpu(def, i);

        /* impossible but some compilers don't like it */
        if (!vcpu)
            continue;

        switch (vcpu->hotpluggable) {
        case VIR_TRISTATE_BOOL_ABSENT:
            if (vcpu->online)
                vcpu->hotpluggable = VIR_TRISTATE_BOOL_NO;
            else
                vcpu->hotpluggable = VIR_TRISTATE_BOOL_YES;
            break;

        case VIR_TRISTATE_BOOL_NO:
            if (!vcpu->online) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("vcpu '%1$zu' is both offline and not hotpluggable"), i);
                return -1;
            }
            break;

        case VIR_TRISTATE_BOOL_YES:
        case VIR_TRISTATE_BOOL_LAST:
            break;
        }
    }

    return 0;
}


static int
virDomainDefPostParseCPU(virDomainDef *def)
{
    if (!def->cpu)
        return 0;

    if (def->cpu->mode == VIR_CPU_MODE_CUSTOM &&
        !def->cpu->model &&
        def->cpu->check != VIR_CPU_CHECK_DEFAULT) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("check attribute specified for CPU with no model"));
        return -1;
    }

    return 0;
}


static int
virDomainDefCollectBootOrder(virDomainDef *def G_GNUC_UNUSED,
                             virDomainDeviceDef *dev G_GNUC_UNUSED,
                             virDomainDeviceInfo *info,
                             void *data)
{
    GHashTable *bootHash = data;
    g_autofree char *order = NULL;

    if (info->bootIndex == 0)
        return 0;

    if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV &&
        dev->data.hostdev->parentnet) {
        /* This hostdev is a child of a higher level device
         * (e.g. interface), and thus already being counted on the
         * list for the other device type.
         */
        return 0;
    }
    order = g_strdup_printf("%u", info->bootIndex);

    if (virHashLookup(bootHash, order)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("boot order '%1$s' used for more than one device"),
                       order);
        return -1;
    }

    if (virHashAddEntry(bootHash, order, (void *) 1) < 0)
        return -1;

    return 0;
}


static int
virDomainDefBootOrderPostParse(virDomainDef *def)
{
    g_autoptr(GHashTable) bootHash = virHashNew(NULL);

    if (virDomainDeviceInfoIterate(def, virDomainDefCollectBootOrder, bootHash) < 0)
        return -1;

    if (def->os.nBootDevs > 0 && virHashSize(bootHash) > 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("per-device boot elements cannot be used together with os/boot elements"));
        return -1;
    }

    if (def->os.nBootDevs == 0 && virHashSize(bootHash) == 0) {
        def->os.nBootDevs = 1;
        def->os.bootDevs[0] = VIR_DOMAIN_BOOT_DISK;
    }

    return 0;
}


static int
virDomainDefPostParseVideo(virDomainDef *def,
                           void *opaque)
{
    if (def->nvideos == 0)
        return 0;

    if (def->videos[0]->type == VIR_DOMAIN_VIDEO_TYPE_NONE) {
        char *alias;

        /* we don't want to format any values we automatically fill in for
         * videos into the XML, so clear them, but retain any user-assigned
         * alias */
        alias = g_steal_pointer(&def->videos[0]->info.alias);
        virDomainVideoDefClear(def->videos[0]);
        def->videos[0]->type = VIR_DOMAIN_VIDEO_TYPE_NONE;
        def->videos[0]->info.alias = g_steal_pointer(&alias);
    } else {
        virDomainDeviceDef device = {
            .type = VIR_DOMAIN_DEVICE_VIDEO,
            .data.video = def->videos[0],
        };

        /* Mark the first video as primary. If the user specified
         * primary="yes", the parser already inserted the device at
         * def->videos[0]
         */
        def->videos[0]->primary = true;

        /* videos[0] might have been added in AddImplicitDevices, after we've
         * done the per-device post-parse */
        if (virDomainDefPostParseDeviceIterator(def, &device,
                                                NULL, opaque) < 0)
            return -1;
    }

    return 0;
}


static int
virDomainDefRejectDuplicateControllers(virDomainDef *def)
{
    int max_idx[VIR_DOMAIN_CONTROLLER_TYPE_LAST];
    virBitmap *bitmaps[VIR_DOMAIN_CONTROLLER_TYPE_LAST] = { NULL };
    virDomainControllerDef *cont;
    size_t nbitmaps = 0;
    int ret = -1;
    size_t i;

    memset(max_idx, -1, sizeof(max_idx));

    for (i = 0; i < def->ncontrollers; i++) {
        cont = def->controllers[i];
        if (cont->idx > max_idx[cont->type])
            max_idx[cont->type] = cont->idx;
    }

    /* multiple USB controllers with the same index are allowed */
    max_idx[VIR_DOMAIN_CONTROLLER_TYPE_USB] = -1;

    for (i = 0; i < VIR_DOMAIN_CONTROLLER_TYPE_LAST; i++) {
        if (max_idx[i] >= 0)
            bitmaps[i] = virBitmapNew(max_idx[i] + 1);
        nbitmaps++;
    }

    for (i = 0; i < def->ncontrollers; i++) {
        cont = def->controllers[i];

        if (max_idx[cont->type] == -1)
            continue;

        if (virBitmapIsBitSet(bitmaps[cont->type], cont->idx)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Multiple '%1$s' controllers with index '%2$d'"),
                           virDomainControllerTypeToString(cont->type),
                           cont->idx);
            goto cleanup;
        }
        ignore_value(virBitmapSetBit(bitmaps[cont->type], cont->idx));
    }

    ret = 0;
 cleanup:
    for (i = 0; i < nbitmaps; i++)
        virBitmapFree(bitmaps[i]);
    return ret;
}


static int
virDomainDefRejectDuplicatePanics(virDomainDef *def)
{
    bool exists[VIR_DOMAIN_PANIC_MODEL_LAST];
    size_t i;

    for (i = 0; i < VIR_DOMAIN_PANIC_MODEL_LAST; i++)
         exists[i] = false;

    for (i = 0; i < def->npanics; i++) {
        virDomainPanicModel model = def->panics[i]->model;
        if (exists[model]) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Multiple panic devices with model '%1$s'"),
                           virDomainPanicModelTypeToString(model));
            return -1;
        }
        exists[model] = true;
    }

    return 0;
}


static int
virDomainDefPostParseCommon(virDomainDef *def,
                            struct virDomainDefPostParseDeviceIteratorData *data,
                            virDomainXMLOption *xmlopt)
{
    size_t i;

    /* verify init path for container based domains */
    if (def->os.type == VIR_DOMAIN_OSTYPE_EXE && !def->os.init) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("init binary must be specified"));
        return -1;
    }

    if (virDomainVcpuDefPostParse(def) < 0)
        return -1;

    if (virDomainDefPostParseMemory(def, data->parseFlags) < 0)
        return -1;

    if (virDomainDefPostParseOs(def) < 0)
        return -1;

    virDomainDefPostParseMemtune(def);

    if (virDomainDefRejectDuplicateControllers(def) < 0)
        return -1;

    if (virDomainDefRejectDuplicatePanics(def) < 0)
        return -1;

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM &&
        !(data->xmlopt->config.features & VIR_DOMAIN_DEF_FEATURE_NO_BOOT_ORDER) &&
        virDomainDefBootOrderPostParse(def) < 0)
        return -1;

    if (virDomainDefPostParseTimer(def) < 0)
        return -1;

    if (virDomainDefAddImplicitDevices(def, xmlopt) < 0)
        return -1;

    if (virDomainDefPostParseVideo(def, data) < 0)
        return -1;

    if (def->nserials != 0) {
        virDomainDeviceDef device = {
            .type = VIR_DOMAIN_DEVICE_CHR,
            .data.chr = def->serials[0],
        };

        /* serials[0] might have been added in AddImplicitDevices, after we've
         * done the per-device post-parse */
        if (virDomainDefPostParseDeviceIterator(def, &device, NULL, data) < 0)
            return -1;
    }

    /* Implicit SCSI controllers without a defined model might have
     * been added in AddImplicitDevices, after we've done the per-device
     * post-parse. */
    for (i = 0; i < def->ncontrollers; i++) {
        if (def->controllers[i]->model == VIR_DOMAIN_CONTROLLER_MODEL_SCSI_DEFAULT &&
            def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI) {
            virDomainDeviceDef device = {
                .type = VIR_DOMAIN_DEVICE_CONTROLLER,
                .data.controller = def->controllers[i],
            };
            if (virDomainDefPostParseDeviceIterator(def, &device, NULL, data) < 0)
                return -1;
        }
    }

    /* clean up possibly duplicated metadata entries */
    virXMLNodeSanitizeNamespaces(def->metadata);

    virDomainDefPostParseGraphics(def);

    if (virDomainDefPostParseCPU(def) < 0)
        return -1;

    return 0;
}


static int
virDomainDefPostParseCheckFailure(virDomainDef *def,
                                  unsigned int parseFlags,
                                  int ret)
{
    if (ret != 0)
        def->postParseFailed = true;

    if (ret <= 0)
        return ret;

    if (!(parseFlags & VIR_DOMAIN_DEF_PARSE_ALLOW_POST_PARSE_FAIL))
        return -1;

    virResetLastError();
    return 0;
}


static void
virDomainAssignControllerIndexes(virDomainDef *def)
{
    /* the index attribute of a controller is optional in the XML, but
     * is required to be valid at any time after parse. When no index
     * is provided for a controller, assign one automatically by
     * looking at what indexes are already used for that controller
     * type in the domain - the unindexed controller gets the lowest
     * unused index.
     */
    size_t outer;

    for (outer = 0; outer < def->ncontrollers; outer++) {
        virDomainControllerDef *cont = def->controllers[outer];
        virDomainControllerDef *prev = NULL;
        size_t inner;

        if (cont->idx != -1)
            continue;

        if (outer > 0 && IS_USB2_CONTROLLER(cont)) {
            /* USB2 controllers are the only exception to the simple
             * "assign the lowest unused index". A group of USB2
             * "companions" should all be at the same index as other
             * USB2 controllers in the group, but only do this
             * automatically if it appears to be the intent. To prove
             * intent: the USB controller on the list just prior to
             * this one must also be a USB2 controller, and there must
             * not yet be a controller with the exact same model of
             * this one and the same index as the previously added
             * controller (e.g., if this controller is a UHCI1, then
             * the previous controller must be an EHCI1 or a UHCI[23],
             * and there must not already be a UHCI1 controller with
             * the same index as the previous controller). If all of
             * these are satisfied, set this controller to the same
             * index as the previous controller.
             */
            int prevIdx;

            prevIdx = outer - 1;
            while (prevIdx >= 0 &&
                   def->controllers[prevIdx]->type != VIR_DOMAIN_CONTROLLER_TYPE_USB)
                prevIdx--;
            if (prevIdx >= 0)
                prev = def->controllers[prevIdx];
            /* if the last USB controller isn't USB2, that breaks
             * the chain, so we need a new index for this new
             * controller
             */
            if (prev && !IS_USB2_CONTROLLER(prev))
                prev = NULL;

            /* if prev != NULL, we've found a potential index to
             * use. Make sure this index isn't already used by an
             * existing USB2 controller of the same model as the new
             * one.
             */
            for (inner = 0; prev && inner < def->ncontrollers; inner++) {
                if (def->controllers[inner]->type == VIR_DOMAIN_CONTROLLER_TYPE_USB &&
                    def->controllers[inner]->idx == prev->idx &&
                    def->controllers[inner]->model == cont->model) {
                    /* we already have a controller of this model with
                     * the proposed index, so we need to move to a new
                     * index for this controller
                     */
                    prev = NULL;
                }
            }
            if (prev)
                cont->idx = prev->idx;
        }
        /* if none of the above applied, prev will be NULL */
        if (!prev)
            cont->idx = virDomainControllerFindUnusedIndex(def, cont->type);
    }
}


int
virDomainDefPostParse(virDomainDef *def,
                      unsigned int parseFlags,
                      virDomainXMLOption *xmlopt,
                      void *parseOpaque)
{
    int ret = -1;
    bool localParseOpaque = false;
    struct virDomainDefPostParseDeviceIteratorData data = {
        .xmlopt = xmlopt,
        .parseFlags = parseFlags,
        .parseOpaque = parseOpaque,
    };

    def->postParseFailed = false;

    /* call the basic post parse callback */
    if (xmlopt->config.domainPostParseBasicCallback) {
        ret = xmlopt->config.domainPostParseBasicCallback(def,
                                                          xmlopt->config.priv);

        if (virDomainDefPostParseCheckFailure(def, parseFlags, ret) < 0)
            goto cleanup;
    }

    if (!data.parseOpaque &&
        xmlopt->config.domainPostParseDataAlloc) {
        ret = xmlopt->config.domainPostParseDataAlloc(def, parseFlags,
                                                      xmlopt->config.priv,
                                                      &data.parseOpaque);

        if (virDomainDefPostParseCheckFailure(def, parseFlags, ret) < 0)
            goto cleanup;
        localParseOpaque = true;
    }

    /* this must be done before the hypervisor-specific callback,
     * in case presence of a controller at a specific index is checked
     */
    virDomainAssignControllerIndexes(def);

    /* call the domain config callback */
    if (xmlopt->config.domainPostParseCallback) {
        ret = xmlopt->config.domainPostParseCallback(def, parseFlags,
                                                     xmlopt->config.priv,
                                                     data.parseOpaque);
        if (virDomainDefPostParseCheckFailure(def, parseFlags, ret) < 0)
            goto cleanup;
    }

    if (virDomainChrIsaSerialDefPostParse(def) < 0)
            return -1;

    /* iterate the devices */
    ret = virDomainDeviceInfoIterateFlags(def,
                                          virDomainDefPostParseDeviceIterator,
                                          DOMAIN_DEVICE_ITERATE_ALL_CONSOLES |
                                          DOMAIN_DEVICE_ITERATE_MISSING_INFO,
                                          &data);

    if (virDomainDefPostParseCheckFailure(def, parseFlags, ret) < 0)
        goto cleanup;

    if ((ret = virDomainDefPostParseCommon(def, &data, xmlopt)) < 0)
        goto cleanup;

    if (xmlopt->config.assignAddressesCallback) {
        ret = xmlopt->config.assignAddressesCallback(def, parseFlags,
                                                     xmlopt->config.priv,
                                                     data.parseOpaque);
        if (virDomainDefPostParseCheckFailure(def, parseFlags, ret) < 0)
            goto cleanup;
    }

    if ((ret = virDomainDefPostParseCheckFeatures(def, xmlopt)) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    if (localParseOpaque && xmlopt->config.domainPostParseDataFree)
        xmlopt->config.domainPostParseDataFree(data.parseOpaque);

    if (ret == 1)
        ret = -1;

    return ret;
}
