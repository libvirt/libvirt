/*
 * domain_conf.c: domain XML processing
 *
 * Copyright (C) 2006-2010 Red Hat, Inc.
 * Copyright (C) 2006-2008 Daniel P. Berrange
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>

#include "virterror_internal.h"
#include "datatypes.h"
#include "domain_conf.h"
#include "memory.h"
#include "verify.h"
#include "xml.h"
#include "uuid.h"
#include "util.h"
#include "buf.h"
#include "c-ctype.h"
#include "logging.h"
#include "network.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN

VIR_ENUM_IMPL(virDomainVirt, VIR_DOMAIN_VIRT_LAST,
              "qemu",
              "kqemu",
              "kvm",
              "xen",
              "lxc",
              "uml",
              "openvz",
              "vserver",
              "ldom",
              "test",
              "vmware",
              "hyperv",
              "vbox",
              "one",
              "phyp")

VIR_ENUM_IMPL(virDomainBoot, VIR_DOMAIN_BOOT_LAST,
              "fd",
              "cdrom",
              "hd",
              "network")

VIR_ENUM_IMPL(virDomainFeature, VIR_DOMAIN_FEATURE_LAST,
              "acpi",
              "apic",
              "pae")

VIR_ENUM_IMPL(virDomainLifecycle, VIR_DOMAIN_LIFECYCLE_LAST,
              "destroy",
              "restart",
              "rename-restart",
              "preserve")

VIR_ENUM_IMPL(virDomainDevice, VIR_DOMAIN_DEVICE_LAST,
              "disk",
              "filesystem",
              "interface",
              "input",
              "sound",
              "video",
              "hostdev",
              "watchdog",
              "controller")

VIR_ENUM_IMPL(virDomainDeviceAddress, VIR_DOMAIN_DEVICE_ADDRESS_TYPE_LAST,
              "none",
              "pci",
              "drive");

VIR_ENUM_IMPL(virDomainDisk, VIR_DOMAIN_DISK_TYPE_LAST,
              "block",
              "file",
              "dir")

VIR_ENUM_IMPL(virDomainDiskDevice, VIR_DOMAIN_DISK_DEVICE_LAST,
              "disk",
              "cdrom",
              "floppy")

VIR_ENUM_IMPL(virDomainDiskBus, VIR_DOMAIN_DISK_BUS_LAST,
              "ide",
              "fdc",
              "scsi",
              "virtio",
              "xen",
              "usb",
              "uml",
              "sata")

VIR_ENUM_IMPL(virDomainDiskCache, VIR_DOMAIN_DISK_CACHE_LAST,
              "default",
              "none",
              "writethrough",
              "writeback")

VIR_ENUM_IMPL(virDomainController, VIR_DOMAIN_CONTROLLER_TYPE_LAST,
              "ide",
              "fdc",
              "scsi",
              "sata")

VIR_ENUM_IMPL(virDomainFS, VIR_DOMAIN_FS_TYPE_LAST,
              "mount",
              "block",
              "file",
              "template")

VIR_ENUM_IMPL(virDomainNet, VIR_DOMAIN_NET_TYPE_LAST,
              "user",
              "ethernet",
              "server",
              "client",
              "mcast",
              "network",
              "bridge",
              "internal")

VIR_ENUM_IMPL(virDomainChrTarget, VIR_DOMAIN_CHR_TARGET_TYPE_LAST,
              "null",
              "monitor",
              "parallel",
              "serial",
              "console",
              "guestfwd")

VIR_ENUM_IMPL(virDomainChr, VIR_DOMAIN_CHR_TYPE_LAST,
              "null",
              "vc",
              "pty",
              "dev",
              "file",
              "pipe",
              "stdio",
              "udp",
              "tcp",
              "unix")

VIR_ENUM_IMPL(virDomainSoundModel, VIR_DOMAIN_SOUND_MODEL_LAST,
              "sb16",
              "es1370",
              "pcspk",
              "ac97")

VIR_ENUM_IMPL(virDomainWatchdogModel, VIR_DOMAIN_WATCHDOG_MODEL_LAST,
              "i6300esb",
              "ib700")

VIR_ENUM_IMPL(virDomainWatchdogAction, VIR_DOMAIN_WATCHDOG_ACTION_LAST,
              "reset",
              "shutdown",
              "poweroff",
              "pause",
              "none")

VIR_ENUM_IMPL(virDomainVideo, VIR_DOMAIN_VIDEO_TYPE_LAST,
              "vga",
              "cirrus",
              "vmvga",
              "xen",
              "vbox")

VIR_ENUM_IMPL(virDomainInput, VIR_DOMAIN_INPUT_TYPE_LAST,
              "mouse",
              "tablet")

VIR_ENUM_IMPL(virDomainInputBus, VIR_DOMAIN_INPUT_BUS_LAST,
              "ps2",
              "usb",
              "xen")

VIR_ENUM_IMPL(virDomainGraphics, VIR_DOMAIN_GRAPHICS_TYPE_LAST,
              "sdl",
              "vnc",
              "rdp",
              "desktop")

VIR_ENUM_IMPL(virDomainHostdevMode, VIR_DOMAIN_HOSTDEV_MODE_LAST,
              "subsystem",
              "capabilities")

VIR_ENUM_IMPL(virDomainHostdevSubsys, VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST,
              "usb",
              "pci")

VIR_ENUM_IMPL(virDomainState, VIR_DOMAIN_CRASHED+1,
              "nostate",
              "running",
              "blocked",
              "paused",
              "shutdown",
              "shutoff",
              "crashed")

VIR_ENUM_IMPL(virDomainSeclabel, VIR_DOMAIN_SECLABEL_LAST,
              "dynamic",
              "static")

#define virDomainReportError(conn, code, fmt...)                           \
        virReportErrorHelper(conn, VIR_FROM_DOMAIN, code, __FILE__,        \
                               __FUNCTION__, __LINE__, fmt)

#ifndef PROXY

int virDomainObjListInit(virDomainObjListPtr doms)
{
    doms->objs = virHashCreate(50);
    if (!doms->objs) {
        virReportOOMError(NULL);
        return -1;
    }
    return 0;
}


static void virDomainObjListDeallocator(void *payload, const char *name ATTRIBUTE_UNUSED)
{
    virDomainObjPtr obj = payload;
    virDomainObjLock(obj);
    if (virDomainObjUnref(obj) > 0)
        virDomainObjUnlock(obj);
}

void virDomainObjListDeinit(virDomainObjListPtr doms)
{
    if (doms->objs)
        virHashFree(doms->objs, virDomainObjListDeallocator);
}


static int virDomainObjListSearchID(const void *payload,
                                    const char *name ATTRIBUTE_UNUSED,
                                    const void *data)
{
    virDomainObjPtr obj = (virDomainObjPtr)payload;
    const int *id = data;
    int want = 0;

    virDomainObjLock(obj);
    if (virDomainObjIsActive(obj) &&
        obj->def->id == *id)
        want = 1;
    virDomainObjUnlock(obj);
    return want;
}

virDomainObjPtr virDomainFindByID(const virDomainObjListPtr doms,
                                  int id)
{
    virDomainObjPtr obj;
    obj = virHashSearch(doms->objs, virDomainObjListSearchID, &id);
    if (obj)
        virDomainObjLock(obj);
    return obj;
}


virDomainObjPtr virDomainFindByUUID(const virDomainObjListPtr doms,
                                    const unsigned char *uuid)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virDomainObjPtr obj;

    virUUIDFormat(uuid, uuidstr);

    obj = virHashLookup(doms->objs, uuidstr);
    if (obj)
        virDomainObjLock(obj);
    return obj;
}

static int virDomainObjListSearchName(const void *payload,
                                      const char *name ATTRIBUTE_UNUSED,
                                      const void *data)
{
    virDomainObjPtr obj = (virDomainObjPtr)payload;
    int want = 0;

    virDomainObjLock(obj);
    if (STREQ(obj->def->name, (const char *)data))
        want = 1;
    virDomainObjUnlock(obj);
    return want;
}

virDomainObjPtr virDomainFindByName(const virDomainObjListPtr doms,
                                    const char *name)
{
    virDomainObjPtr obj;
    obj = virHashSearch(doms->objs, virDomainObjListSearchName, name);
    if (obj)
        virDomainObjLock(obj);
    return obj;
}

#endif /* !PROXY */

void virDomainGraphicsDefFree(virDomainGraphicsDefPtr def)
{
    if (!def)
        return;

    switch (def->type) {
    case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
        VIR_FREE(def->data.vnc.listenAddr);
        VIR_FREE(def->data.vnc.keymap);
        VIR_FREE(def->data.vnc.passwd);
        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_SDL:
        VIR_FREE(def->data.sdl.display);
        VIR_FREE(def->data.sdl.xauth);
        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_RDP:
        VIR_FREE(def->data.rdp.listenAddr);
        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP:
        VIR_FREE(def->data.desktop.display);
        break;
    }

    VIR_FREE(def);
}

void virDomainInputDefFree(virDomainInputDefPtr def)
{
    if (!def)
        return;

    virDomainDeviceInfoClear(&def->info);
    VIR_FREE(def);
}

void virDomainDiskDefFree(virDomainDiskDefPtr def)
{
    if (!def)
        return;

    VIR_FREE(def->serial);
    VIR_FREE(def->src);
    VIR_FREE(def->dst);
    VIR_FREE(def->driverName);
    VIR_FREE(def->driverType);
    virStorageEncryptionFree(def->encryption);
    virDomainDeviceInfoClear(&def->info);

    VIR_FREE(def);
}

void virDomainControllerDefFree(virDomainControllerDefPtr def)
{
    if (!def)
        return;

    virDomainDeviceInfoClear(&def->info);

    VIR_FREE(def);
}

void virDomainFSDefFree(virDomainFSDefPtr def)
{
    if (!def)
        return;

    VIR_FREE(def->src);
    VIR_FREE(def->dst);
    virDomainDeviceInfoClear(&def->info);

    VIR_FREE(def);
}

void virDomainNetDefFree(virDomainNetDefPtr def)
{
    if (!def)
        return;

    VIR_FREE(def->model);

    switch (def->type) {
    case VIR_DOMAIN_NET_TYPE_ETHERNET:
        VIR_FREE(def->data.ethernet.dev);
        VIR_FREE(def->data.ethernet.script);
        VIR_FREE(def->data.ethernet.ipaddr);
        break;

    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_MCAST:
        VIR_FREE(def->data.socket.address);
        break;

    case VIR_DOMAIN_NET_TYPE_NETWORK:
        VIR_FREE(def->data.network.name);
        break;

    case VIR_DOMAIN_NET_TYPE_BRIDGE:
        VIR_FREE(def->data.bridge.brname);
        VIR_FREE(def->data.bridge.script);
        VIR_FREE(def->data.bridge.ipaddr);
        break;

    case VIR_DOMAIN_NET_TYPE_INTERNAL:
        VIR_FREE(def->data.internal.name);
        break;
    }

    VIR_FREE(def->ifname);

    virDomainDeviceInfoClear(&def->info);

    VIR_FREE(def);
}

void virDomainChrDefFree(virDomainChrDefPtr def)
{
    if (!def)
        return;

    switch (def->targetType) {
    case VIR_DOMAIN_CHR_TARGET_TYPE_GUESTFWD:
        VIR_FREE(def->target.addr);
        break;
    }

    switch (def->type) {
    case VIR_DOMAIN_CHR_TYPE_PTY:
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
        VIR_FREE(def->data.file.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_UDP:
        VIR_FREE(def->data.udp.bindHost);
        VIR_FREE(def->data.udp.bindService);
        VIR_FREE(def->data.udp.connectHost);
        VIR_FREE(def->data.udp.connectService);
        break;

    case VIR_DOMAIN_CHR_TYPE_TCP:
        VIR_FREE(def->data.tcp.host);
        VIR_FREE(def->data.tcp.service);
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        VIR_FREE(def->data.nix.path);
        break;
    }

    virDomainDeviceInfoClear(&def->info);

    VIR_FREE(def);
}

void virDomainSoundDefFree(virDomainSoundDefPtr def)
{
    if (!def)
        return;

    virDomainDeviceInfoClear(&def->info);

    VIR_FREE(def);
}

void virDomainWatchdogDefFree(virDomainWatchdogDefPtr def)
{
    if (!def)
        return;

    virDomainDeviceInfoClear(&def->info);

    VIR_FREE(def);
}

void virDomainVideoDefFree(virDomainVideoDefPtr def)
{
    if (!def)
        return;

    virDomainDeviceInfoClear(&def->info);

    VIR_FREE(def->accel);
    VIR_FREE(def);
}

void virDomainHostdevDefFree(virDomainHostdevDefPtr def)
{
    if (!def)
        return;

    VIR_FREE(def->target);
    virDomainDeviceInfoClear(&def->info);
    VIR_FREE(def);
}

void virDomainDeviceDefFree(virDomainDeviceDefPtr def)
{
    if (!def)
        return;

    switch (def->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        virDomainDiskDefFree(def->data.disk);
        break;
    case VIR_DOMAIN_DEVICE_NET:
        virDomainNetDefFree(def->data.net);
        break;
    case VIR_DOMAIN_DEVICE_INPUT:
        virDomainInputDefFree(def->data.input);
        break;
    case VIR_DOMAIN_DEVICE_SOUND:
        virDomainSoundDefFree(def->data.sound);
        break;
    case VIR_DOMAIN_DEVICE_VIDEO:
        virDomainVideoDefFree(def->data.video);
        break;
    case VIR_DOMAIN_DEVICE_HOSTDEV:
        virDomainHostdevDefFree(def->data.hostdev);
        break;
    case VIR_DOMAIN_DEVICE_WATCHDOG:
        virDomainWatchdogDefFree(def->data.watchdog);
        break;
    case VIR_DOMAIN_DEVICE_CONTROLLER:
        virDomainControllerDefFree(def->data.controller);
        break;
    }

    VIR_FREE(def);
}

void virSecurityLabelDefFree(virDomainDefPtr def);

void virSecurityLabelDefFree(virDomainDefPtr def)
{
    VIR_FREE(def->seclabel.model);
    VIR_FREE(def->seclabel.label);
    VIR_FREE(def->seclabel.imagelabel);
}

void virDomainDefFree(virDomainDefPtr def)
{
    unsigned int i;

    if (!def)
        return;

    for (i = 0 ; i < def->ngraphics ; i++)
        virDomainGraphicsDefFree(def->graphics[i]);
    VIR_FREE(def->graphics);

    for (i = 0 ; i < def->ninputs ; i++)
        virDomainInputDefFree(def->inputs[i]);
    VIR_FREE(def->inputs);

    for (i = 0 ; i < def->ndisks ; i++)
        virDomainDiskDefFree(def->disks[i]);
    VIR_FREE(def->disks);

    for (i = 0 ; i < def->ncontrollers ; i++)
        virDomainControllerDefFree(def->controllers[i]);
    VIR_FREE(def->controllers);

    for (i = 0 ; i < def->nfss ; i++)
        virDomainFSDefFree(def->fss[i]);
    VIR_FREE(def->fss);

    for (i = 0 ; i < def->nnets ; i++)
        virDomainNetDefFree(def->nets[i]);
    VIR_FREE(def->nets);

    for (i = 0 ; i < def->nserials ; i++)
        virDomainChrDefFree(def->serials[i]);
    VIR_FREE(def->serials);

    for (i = 0 ; i < def->nparallels ; i++)
        virDomainChrDefFree(def->parallels[i]);
    VIR_FREE(def->parallels);

    for (i = 0 ; i < def->nchannels ; i++)
        virDomainChrDefFree(def->channels[i]);
    VIR_FREE(def->channels);

    virDomainChrDefFree(def->console);

    for (i = 0 ; i < def->nsounds ; i++)
        virDomainSoundDefFree(def->sounds[i]);
    VIR_FREE(def->sounds);

    for (i = 0 ; i < def->nvideos ; i++)
        virDomainVideoDefFree(def->videos[i]);
    VIR_FREE(def->videos);

    for (i = 0 ; i < def->nhostdevs ; i++)
        virDomainHostdevDefFree(def->hostdevs[i]);
    VIR_FREE(def->hostdevs);

    VIR_FREE(def->os.type);
    VIR_FREE(def->os.arch);
    VIR_FREE(def->os.machine);
    VIR_FREE(def->os.init);
    VIR_FREE(def->os.kernel);
    VIR_FREE(def->os.initrd);
    VIR_FREE(def->os.cmdline);
    VIR_FREE(def->os.root);
    VIR_FREE(def->os.loader);
    VIR_FREE(def->os.bootloader);
    VIR_FREE(def->os.bootloaderArgs);

    VIR_FREE(def->name);
    VIR_FREE(def->cpumask);
    VIR_FREE(def->emulator);
    VIR_FREE(def->description);

    virDomainWatchdogDefFree(def->watchdog);

    virSecurityLabelDefFree(def);

    virCPUDefFree(def->cpu);

    VIR_FREE(def);
}

#ifndef PROXY

static void virDomainObjFree(virDomainObjPtr dom)
{
    if (!dom)
        return;

    VIR_DEBUG("obj=%p", dom);
    virDomainDefFree(dom->def);
    virDomainDefFree(dom->newDef);

    if (dom->privateDataFreeFunc)
        (dom->privateDataFreeFunc)(dom->privateData);

    virMutexDestroy(&dom->lock);

    VIR_FREE(dom);
}

void virDomainObjRef(virDomainObjPtr dom)
{
    dom->refs++;
    VIR_DEBUG("obj=%p refs=%d", dom, dom->refs);
}


int virDomainObjUnref(virDomainObjPtr dom)
{
    dom->refs--;
    VIR_DEBUG("obj=%p refs=%d", dom, dom->refs);
    if (dom->refs == 0) {
        virDomainObjUnlock(dom);
        virDomainObjFree(dom);
        return 0;
    }
    return dom->refs;
}

static virDomainObjPtr virDomainObjNew(virConnectPtr conn,
                                       virCapsPtr caps)
{
    virDomainObjPtr domain;

    if (VIR_ALLOC(domain) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    if (caps->privateDataAllocFunc &&
        !(domain->privateData = (caps->privateDataAllocFunc)())) {
        virReportOOMError(conn);
        VIR_FREE(domain);
        return NULL;
    }
    domain->privateDataFreeFunc = caps->privateDataFreeFunc;

    if (virMutexInit(&domain->lock) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("cannot initialize mutex"));
        if (domain->privateDataFreeFunc)
            (domain->privateDataFreeFunc)(domain->privateData);
        VIR_FREE(domain);
        return NULL;
    }

    virDomainObjLock(domain);
    domain->state = VIR_DOMAIN_SHUTOFF;
    domain->refs = 1;

    VIR_DEBUG("obj=%p", domain);
    return domain;
}

virDomainObjPtr virDomainAssignDef(virConnectPtr conn,
                                   virCapsPtr caps,
                                   virDomainObjListPtr doms,
                                   const virDomainDefPtr def)
{
    virDomainObjPtr domain;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if ((domain = virDomainFindByUUID(doms, def->uuid))) {
        if (!virDomainObjIsActive(domain)) {
            virDomainDefFree(domain->def);
            domain->def = def;
        } else {
            if (domain->newDef)
                virDomainDefFree(domain->newDef);
            domain->newDef = def;
        }

        return domain;
    }

    if (!(domain = virDomainObjNew(conn, caps)))
        return NULL;
    domain->def = def;

    virUUIDFormat(def->uuid, uuidstr);
    if (virHashAddEntry(doms->objs, uuidstr, domain) < 0) {
        VIR_FREE(domain);
        virReportOOMError(conn);
        return NULL;
    }

    return domain;
}

/*
 * The caller must hold a lock  on the driver owning 'doms',
 * and must also have locked 'dom', to ensure no one else
 * is either waiting for 'dom' or still usingn it
 */
void virDomainRemoveInactive(virDomainObjListPtr doms,
                             virDomainObjPtr dom)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virUUIDFormat(dom->def->uuid, uuidstr);

    virDomainObjUnlock(dom);

    virHashRemoveEntry(doms->objs, uuidstr, virDomainObjListDeallocator);
}


int virDomainDeviceAddressIsValid(virDomainDeviceInfoPtr info,
                                  int type)
{
    if (info->type != type)
        return 0;

    switch (info->type) {
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI:
        return virDomainDevicePCIAddressIsValid(&info->addr.pci);

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE:
        return virDomainDeviceDriveAddressIsValid(&info->addr.drive);
    }

    return 0;
}


int virDomainDevicePCIAddressIsValid(virDomainDevicePCIAddressPtr addr)
{
    return addr->domain || addr->bus || addr->slot;
}


int virDomainDeviceDriveAddressIsValid(virDomainDeviceDriveAddressPtr addr ATTRIBUTE_UNUSED)
{
    /*return addr->controller || addr->bus || addr->unit;*/
    return 1; /* 0 is valid for all fields, so any successfully parsed addr is valid */
}
#endif /* !PROXY */


int virDomainDeviceInfoIsSet(virDomainDeviceInfoPtr info)
{
    if (info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
        return 1;
    if (info->alias)
        return 1;
    return 0;
}


void virDomainDeviceInfoClear(virDomainDeviceInfoPtr info)
{
    VIR_FREE(info->alias);
    memset(&info->addr, 0, sizeof(info->addr));
    info->type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE;
}


static int virDomainDeviceInfoClearAlias(virDomainDefPtr def ATTRIBUTE_UNUSED,
                                         virDomainDeviceInfoPtr info,
                                         void *opaque ATTRIBUTE_UNUSED)
{
    VIR_FREE(info->alias);
    return 0;
}

static int virDomainDeviceInfoClearPCIAddress(virDomainDefPtr def ATTRIBUTE_UNUSED,
                                              virDomainDeviceInfoPtr info,
                                              void *opaque ATTRIBUTE_UNUSED)
{
    if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
        memset(&info->addr, 0, sizeof(info->addr));
        info->type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE;
    }
    return 0;
}

int virDomainDeviceInfoIterate(virDomainDefPtr def,
                               virDomainDeviceInfoCallback cb,
                               void *opaque)
{
    int i;

    for (i = 0; i < def->ndisks ; i++)
        if (cb(def, &def->disks[i]->info, opaque) < 0)
            return -1;
    for (i = 0; i < def->nnets ; i++)
        if (cb(def, &def->nets[i]->info, opaque) < 0)
            return -1;
    for (i = 0; i < def->nsounds ; i++)
        if (cb(def, &def->sounds[i]->info, opaque) < 0)
            return -1;
    for (i = 0; i < def->nhostdevs ; i++)
        if (cb(def, &def->hostdevs[i]->info, opaque) < 0)
            return -1;
    for (i = 0; i < def->nvideos ; i++)
        if (cb(def, &def->videos[i]->info, opaque) < 0)
            return -1;
    for (i = 0; i < def->ncontrollers ; i++)
        if (cb(def, &def->controllers[i]->info, opaque) < 0)
            return -1;
    for (i = 0; i < def->nserials ; i++)
        if (cb(def, &def->serials[i]->info, opaque) < 0)
            return -1;
    for (i = 0; i < def->nparallels ; i++)
        if (cb(def, &def->parallels[i]->info, opaque) < 0)
            return -1;
    for (i = 0; i < def->nchannels ; i++)
        if (cb(def, &def->channels[i]->info, opaque) < 0)
            return -1;
    for (i = 0; i < def->ninputs ; i++)
        if (cb(def, &def->inputs[i]->info, opaque) < 0)
            return -1;
    for (i = 0; i < def->nfss ; i++)
        if (cb(def, &def->fss[i]->info, opaque) < 0)
            return -1;
    if (def->watchdog)
        if (cb(def, &def->watchdog->info, opaque) < 0)
            return -1;
    if (def->console)
        if (cb(def, &def->console->info, opaque) < 0)
            return -1;
    return 0;
}


void virDomainDefClearPCIAddresses(virDomainDefPtr def)
{
    virDomainDeviceInfoIterate(def, virDomainDeviceInfoClearPCIAddress, NULL);
}

void virDomainDefClearDeviceAliases(virDomainDefPtr def)
{
    virDomainDeviceInfoIterate(def, virDomainDeviceInfoClearAlias, NULL);
}


/* Generate a string representation of a device address
 * @param address Device address to stringify
 */
static int virDomainDeviceInfoFormat(virBufferPtr buf,
                                     virDomainDeviceInfoPtr info,
                                     int flags)
{
    if (!info) {
        virDomainReportError(NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                             _("missing device information"));
        return -1;
    }

    if (info->alias &&
        !(flags & VIR_DOMAIN_XML_INACTIVE)) {
        virBufferVSprintf(buf, "      <alias name='%s'/>\n", info->alias);
    }

    if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
        return 0;

    /* We'll be in domain/devices/[device type]/ so 3 level indent */
    virBufferVSprintf(buf, "      <address type='%s'",
                      virDomainDeviceAddressTypeToString(info->type));

    switch (info->type) {
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI:
        virBufferVSprintf(buf, " domain='0x%.4x' bus='0x%.2x' slot='0x%.2x' function='0x%.1x'",
                          info->addr.pci.domain,
                          info->addr.pci.bus,
                          info->addr.pci.slot,
                          info->addr.pci.function);
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE:
        virBufferVSprintf(buf, " controller='%d' bus='%d' unit='%d'",
                          info->addr.drive.controller,
                          info->addr.drive.bus,
                          info->addr.drive.unit);
        break;

    default:
        virDomainReportError(NULL, VIR_ERR_INTERNAL_ERROR,
                             _("unknown address type '%d'"), info->type);
        return -1;
    }

    virBufferAddLit(buf, "/>\n");

    return 0;
}


#ifndef PROXY

int virDomainDevicePCIAddressEqual(virDomainDevicePCIAddressPtr a,
                                   virDomainDevicePCIAddressPtr b)
{
    if (a->domain == b->domain &&
        a->bus    == b->bus &&
        a->slot   == b->slot &&
        a->function == b->function)
        return 1;

    return 0;
}


int virDomainDeviceDriveAddressEqual(virDomainDeviceDriveAddressPtr a,
                                     virDomainDeviceDriveAddressPtr b)
{
    if (a->controller == b->controller &&
        a->bus == b->bus &&
        a->unit == b->unit)
        return 1;

    return 0;
}


static int
virDomainDevicePCIAddressParseXML(virConnectPtr conn,
                                  xmlNodePtr node,
                                  virDomainDevicePCIAddressPtr addr)
{
    char *domain, *slot, *bus, *function;
    int ret = -1;

    memset(addr, 0, sizeof(*addr));

    domain   = virXMLPropString(node, "domain");
    bus      = virXMLPropString(node, "bus");
    slot     = virXMLPropString(node, "slot");
    function = virXMLPropString(node, "function");

    if (domain &&
        virStrToLong_ui(domain, NULL, 16, &addr->domain) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                             _("Cannot parse <address> 'domain' attribute"));
        goto cleanup;
    }

    if (bus &&
        virStrToLong_ui(bus, NULL, 16, &addr->bus) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                             _("Cannot parse <address> 'bus' attribute"));
        goto cleanup;
    }

    if (slot &&
        virStrToLong_ui(slot, NULL, 16, &addr->slot) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                             _("Cannot parse <address> 'slot' attribute"));
        goto cleanup;
    }

    if (function &&
        virStrToLong_ui(function, NULL, 16, &addr->function) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                             _("Cannot parse <address> 'function' attribute"));
        goto cleanup;
    }

    if (!virDomainDevicePCIAddressIsValid(addr)) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                             _("Insufficient specification for PCI address"));
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FREE(domain);
    VIR_FREE(bus);
    VIR_FREE(slot);
    VIR_FREE(function);
    return ret;
}


static int
virDomainDeviceDriveAddressParseXML(virConnectPtr conn,
                                    xmlNodePtr node,
                                    virDomainDeviceDriveAddressPtr addr)
{
    char *bus, *unit, *controller;
    int ret = -1;

    memset(addr, 0, sizeof(*addr));

    controller = virXMLPropString(node, "controller");
    bus = virXMLPropString(node, "bus");
    unit = virXMLPropString(node, "unit");

    if (controller &&
        virStrToLong_ui(controller, NULL, 10, &addr->controller) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                             _("Cannot parse <address> 'controller' attribute"));
        goto cleanup;
    }

    if (bus &&
        virStrToLong_ui(bus, NULL, 10, &addr->bus) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                             _("Cannot parse <address> 'bus' attribute"));
        goto cleanup;
    }

    if (unit &&
        virStrToLong_ui(unit, NULL, 10, &addr->unit) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                             _("Cannot parse <address> 'unit' attribute"));
        goto cleanup;
    }

    if (!virDomainDeviceDriveAddressIsValid(addr)) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                             _("Insufficient specification for drive address"));
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FREE(controller);
    VIR_FREE(bus);
    VIR_FREE(unit);
    return ret;
}

/* Parse the XML definition for a device address
 * @param node XML nodeset to parse for device address definition
 */
static int
virDomainDeviceInfoParseXML(virConnectPtr conn,
                            xmlNodePtr node,
                            virDomainDeviceInfoPtr info,
                            int flags)
{
    xmlNodePtr cur;
    xmlNodePtr address = NULL;
    xmlNodePtr alias = NULL;
    char *type = NULL;
    int ret = -1;

    virDomainDeviceInfoClear(info);

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (alias == NULL &&
                !(flags & VIR_DOMAIN_XML_INACTIVE) &&
                xmlStrEqual(cur->name, BAD_CAST "alias")) {
                alias = cur;
            } else if (address == NULL &&
                       xmlStrEqual(cur->name, BAD_CAST "address")) {
                address = cur;
            }
        }
        cur = cur->next;
    }

    if (alias)
        info->alias = virXMLPropString(alias, "name");

    if (!address)
        return 0;

    type = virXMLPropString(address, "type");

    if (type) {
        if ((info->type = virDomainDeviceAddressTypeFromString(type)) < 0) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("unknown address type '%s'"), type);
            goto cleanup;
        }
    } else {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("No type specified for device address"));
        goto cleanup;
    }

    switch (info->type) {
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI:
        if (virDomainDevicePCIAddressParseXML(conn, address, &info->addr.pci) < 0)
            goto cleanup;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE:
        if (virDomainDeviceDriveAddressParseXML(conn, address, &info->addr.drive) < 0)
            goto cleanup;
        break;

    default:
        /* Should not happen */
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("Unknown device address type"));
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (ret == -1)
        VIR_FREE(info->alias);
    VIR_FREE(type);
    return ret;
}


void
virDomainDiskDefAssignAddress(virDomainDiskDefPtr def)
{
    int idx = virDiskNameToIndex(def->dst);

    switch (def->bus) {
    case VIR_DOMAIN_DISK_BUS_SCSI:
        /* For SCSI we define the default mapping to be 7 units
         * per bus, 1 bus per controller, many controllers */
        def->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE;
        def->info.addr.drive.controller = idx / 7;
        def->info.addr.drive.bus = 0;
        def->info.addr.drive.unit = idx % 7;
        break;

    case VIR_DOMAIN_DISK_BUS_IDE:
        /* For IDE we define the default mapping to be 2 units
         * per bus, 2 bus per controller, many controllers */
        def->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE;
        def->info.addr.drive.controller = idx / 4;
        def->info.addr.drive.bus = (idx % 4) / 2;
        def->info.addr.drive.unit = (idx % 2);
        break;

    case VIR_DOMAIN_DISK_BUS_FDC:
        /* For FDC we define the default mapping to be 2 units
         * per bus, 1 bus per controller, many controllers */
        def->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE;
        def->info.addr.drive.controller = idx / 2;
        def->info.addr.drive.bus = 0;
        def->info.addr.drive.unit = idx % 2;
        break;

    default:
        /* Other disk bus's aren't controller based */
        break;
    }
}

/* Parse the XML definition for a disk
 * @param node XML nodeset to parse for disk definition
 */
static virDomainDiskDefPtr
virDomainDiskDefParseXML(virConnectPtr conn,
                         xmlNodePtr node,
                         int flags) {
    virDomainDiskDefPtr def;
    xmlNodePtr cur;
    char *type = NULL;
    char *device = NULL;
    char *driverName = NULL;
    char *driverType = NULL;
    char *source = NULL;
    char *target = NULL;
    char *bus = NULL;
    char *cachetag = NULL;
    char *devaddr = NULL;
    virStorageEncryptionPtr encryption = NULL;
    char *serial = NULL;

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    type = virXMLPropString(node, "type");
    if (type) {
        if ((def->type = virDomainDiskTypeFromString(type)) < 0) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("unknown disk type '%s'"), type);
            goto error;
        }
    } else {
        def->type = VIR_DOMAIN_DISK_TYPE_FILE;
    }

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if ((source == NULL) &&
                (xmlStrEqual(cur->name, BAD_CAST "source"))) {

                switch (def->type) {
                case VIR_DOMAIN_DISK_TYPE_FILE:
                    source = virXMLPropString(cur, "file");
                    break;
                case VIR_DOMAIN_DISK_TYPE_BLOCK:
                    source = virXMLPropString(cur, "dev");
                    break;
                case VIR_DOMAIN_DISK_TYPE_DIR:
                    source = virXMLPropString(cur, "dir");
                    break;
                default:
                    virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                         _("unexpected disk type %s"),
                                         virDomainDiskTypeToString(def->type));
                    goto error;
                }

                /* People sometimes pass a bogus '' source path
                   when they mean to omit the source element
                   completely. eg CDROM without media. This is
                   just a little compatability check to help
                   those broken apps */
                if (source && STREQ(source, ""))
                    VIR_FREE(source);
            } else if ((target == NULL) &&
                       (xmlStrEqual(cur->name, BAD_CAST "target"))) {
                target = virXMLPropString(cur, "dev");
                bus = virXMLPropString(cur, "bus");

                /* HACK: Work around for compat with Xen
                 * driver in previous libvirt releases */
                if (target &&
                    STRPREFIX(target, "ioemu:"))
                    memmove(target, target+6, strlen(target)-5);
            } else if ((driverName == NULL) &&
                       (xmlStrEqual(cur->name, BAD_CAST "driver"))) {
                driverName = virXMLPropString(cur, "name");
                driverType = virXMLPropString(cur, "type");
                cachetag = virXMLPropString(cur, "cache");
            } else if (xmlStrEqual(cur->name, BAD_CAST "readonly")) {
                def->readonly = 1;
            } else if (xmlStrEqual(cur->name, BAD_CAST "shareable")) {
                def->shared = 1;
            } else if ((flags & VIR_DOMAIN_XML_INTERNAL_STATUS) &&
                       xmlStrEqual(cur->name, BAD_CAST "state")) {
                /* Legacy back-compat. Don't add any more attributes here */
                devaddr = virXMLPropString(cur, "devaddr");
            } else if (encryption == NULL &&
                       xmlStrEqual(cur->name, BAD_CAST "encryption")) {
                encryption = virStorageEncryptionParseNode(conn, node->doc,
                                                           cur);
                if (encryption == NULL)
                    goto error;
            } else if ((serial == NULL) &&
                       (xmlStrEqual(cur->name, BAD_CAST "serial"))) {
                serial = (char *)xmlNodeGetContent(cur);
            }
        }
        cur = cur->next;
    }

    device = virXMLPropString(node, "device");
    if (device) {
        if ((def->device = virDomainDiskDeviceTypeFromString(device)) < 0) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("unknown disk device '%s'"), device);
            goto error;
        }
    } else {
        def->device = VIR_DOMAIN_DISK_DEVICE_DISK;
    }

    /* Only CDROM and Floppy devices are allowed missing source path
     * to indicate no media present */
    if (source == NULL &&
        def->device != VIR_DOMAIN_DISK_DEVICE_CDROM &&
        def->device != VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
        virDomainReportError(conn, VIR_ERR_NO_SOURCE,
                             target ? "%s" : NULL, target);
        goto error;
    }

    if (target == NULL) {
        virDomainReportError(conn, VIR_ERR_NO_TARGET,
                             source ? "%s" : NULL, source);
        goto error;
    }

    if (def->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY &&
        !STRPREFIX(target, "fd")) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("Invalid floppy device name: %s"), target);
        goto error;
    }

    /* Force CDROM to be listed as read only */
    if (def->device == VIR_DOMAIN_DISK_DEVICE_CDROM)
        def->readonly = 1;

    if (def->device == VIR_DOMAIN_DISK_DEVICE_DISK &&
        !STRPREFIX((const char *)target, "hd") &&
        !STRPREFIX((const char *)target, "sd") &&
        !STRPREFIX((const char *)target, "vd") &&
        !STRPREFIX((const char *)target, "xvd") &&
        !STRPREFIX((const char *)target, "ubd")) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("Invalid harddisk device name: %s"), target);
        goto error;
    }

    if (bus) {
        if ((def->bus = virDomainDiskBusTypeFromString(bus)) < 0) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("unknown disk bus type '%s'"), bus);
            goto error;
        }
    } else {
        if (def->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
            def->bus = VIR_DOMAIN_DISK_BUS_FDC;
        } else {
            if (STRPREFIX(target, "hd"))
                def->bus = VIR_DOMAIN_DISK_BUS_IDE;
            else if (STRPREFIX(target, "sd"))
                def->bus = VIR_DOMAIN_DISK_BUS_SCSI;
            else if (STRPREFIX(target, "vd"))
                def->bus = VIR_DOMAIN_DISK_BUS_VIRTIO;
            else if (STRPREFIX(target, "xvd"))
                def->bus = VIR_DOMAIN_DISK_BUS_XEN;
            else if (STRPREFIX(target, "ubd"))
                def->bus = VIR_DOMAIN_DISK_BUS_UML;
            else
                def->bus = VIR_DOMAIN_DISK_BUS_IDE;
        }
    }

    if (def->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY &&
        def->bus != VIR_DOMAIN_DISK_BUS_FDC) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("Invalid bus type '%s' for floppy disk"), bus);
        goto error;
    }
    if (def->device != VIR_DOMAIN_DISK_DEVICE_FLOPPY &&
        def->bus == VIR_DOMAIN_DISK_BUS_FDC) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("Invalid bus type '%s' for disk"), bus);
        goto error;
    }

    if (cachetag &&
        (def->cachemode = virDomainDiskCacheTypeFromString(cachetag)) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unknown disk cache mode '%s'"), cachetag);
        goto error;
    }

    if (devaddr) {
        if (sscanf(devaddr, "%x:%x:%x",
                   &def->info.addr.pci.domain,
                   &def->info.addr.pci.bus,
                   &def->info.addr.pci.slot) < 3) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("Unable to parse devaddr parameter '%s'"),
                                 devaddr);
            goto error;
        }
        def->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
    } else {
        if (virDomainDeviceInfoParseXML(conn, node, &def->info, flags) < 0)
            goto error;
    }

    def->src = source;
    source = NULL;
    def->dst = target;
    target = NULL;
    def->driverName = driverName;
    driverName = NULL;
    def->driverType = driverType;
    driverType = NULL;
    def->encryption = encryption;
    encryption = NULL;
    def->serial = serial;
    serial = NULL;

    if (def->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
        virDomainDiskDefAssignAddress(def);

cleanup:
    VIR_FREE(bus);
    VIR_FREE(type);
    VIR_FREE(target);
    VIR_FREE(source);
    VIR_FREE(device);
    VIR_FREE(driverType);
    VIR_FREE(driverName);
    VIR_FREE(cachetag);
    VIR_FREE(devaddr);
    VIR_FREE(serial);
    virStorageEncryptionFree(encryption);

    return def;

 error:
    virDomainDiskDefFree(def);
    def = NULL;
    goto cleanup;
}


/* Parse the XML definition for a controller
 * @param node XML nodeset to parse for controller definition
 */
static virDomainControllerDefPtr
virDomainControllerDefParseXML(virConnectPtr conn,
                               xmlNodePtr node,
                               int flags)
{
    virDomainControllerDefPtr def;
    char *type = NULL;
    char *idx = NULL;

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    type = virXMLPropString(node, "type");
    if (type) {
        if ((def->type = virDomainDiskBusTypeFromString(type)) < 0) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("unknown disk controller type '%s'"), type);
            goto error;
        }
    }

    idx = virXMLPropString(node, "index");
    if (idx) {
        if (virStrToLong_i(idx, NULL, 10, &def->idx) < 0) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("cannot parse disk controller index %s"), idx);
            goto error;
        }
    }

    if (virDomainDeviceInfoParseXML(conn, node, &def->info, flags) < 0)
        goto error;

    if (def->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
        def->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                             _("Disk controllers must use the 'pci' address type"));
        goto error;
    }

cleanup:
    VIR_FREE(type);
    VIR_FREE(idx);

    return def;

 error:
    virDomainControllerDefFree(def);
    def = NULL;
    goto cleanup;
}

/* Parse the XML definition for a disk
 * @param node XML nodeset to parse for disk definition
 */
static virDomainFSDefPtr
virDomainFSDefParseXML(virConnectPtr conn,
                       xmlNodePtr node,
                       int flags) {
    virDomainFSDefPtr def;
    xmlNodePtr cur;
    char *type = NULL;
    char *source = NULL;
    char *target = NULL;

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    type = virXMLPropString(node, "type");
    if (type) {
        if ((def->type = virDomainFSTypeFromString(type)) < 0) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("unknown filesystem type '%s'"), type);
            goto error;
        }
    } else {
        def->type = VIR_DOMAIN_FS_TYPE_MOUNT;
    }

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if ((source == NULL) &&
                (xmlStrEqual(cur->name, BAD_CAST "source"))) {

                if (def->type == VIR_DOMAIN_FS_TYPE_MOUNT)
                    source = virXMLPropString(cur, "dir");
                else if (def->type == VIR_DOMAIN_FS_TYPE_FILE)
                    source = virXMLPropString(cur, "file");
                else if (def->type == VIR_DOMAIN_FS_TYPE_BLOCK)
                    source = virXMLPropString(cur, "dev");
                else if (def->type == VIR_DOMAIN_FS_TYPE_TEMPLATE)
                    source = virXMLPropString(cur, "name");
            } else if ((target == NULL) &&
                       (xmlStrEqual(cur->name, BAD_CAST "target"))) {
                target = virXMLPropString(cur, "dir");
            } else if (xmlStrEqual(cur->name, BAD_CAST "readonly")) {
                def->readonly = 1;
            }
        }
        cur = cur->next;
    }

    if (source == NULL) {
        virDomainReportError(conn, VIR_ERR_NO_SOURCE,
                             target ? "%s" : NULL, target);
        goto error;
    }

    if (target == NULL) {
        virDomainReportError(conn, VIR_ERR_NO_TARGET,
                             source ? "%s" : NULL, source);
        goto error;
    }

    def->src = source;
    source = NULL;
    def->dst = target;
    target = NULL;

    if (virDomainDeviceInfoParseXML(conn, node, &def->info, flags) < 0)
        goto error;

cleanup:
    VIR_FREE(type);
    VIR_FREE(target);
    VIR_FREE(source);

    return def;

 error:
    virDomainFSDefFree(def);
    def = NULL;
    goto cleanup;
}



/* Parse the XML definition for a network interface
 * @param node XML nodeset to parse for net definition
 * @return 0 on success, -1 on failure
 */
static virDomainNetDefPtr
virDomainNetDefParseXML(virConnectPtr conn,
                        virCapsPtr caps,
                        xmlNodePtr node,
                        int flags ATTRIBUTE_UNUSED) {
    virDomainNetDefPtr def;
    xmlNodePtr cur;
    char *macaddr = NULL;
    char *type = NULL;
    char *network = NULL;
    char *bridge = NULL;
    char *dev = NULL;
    char *ifname = NULL;
    char *script = NULL;
    char *address = NULL;
    char *port = NULL;
    char *model = NULL;
    char *internal = NULL;
    char *devaddr = NULL;

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    type = virXMLPropString(node, "type");
    if (type != NULL) {
        if ((def->type = virDomainNetTypeFromString(type)) < 0) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("unknown interface type '%s'"), type);
            goto error;
        }
    } else {
        def->type = VIR_DOMAIN_NET_TYPE_USER;
    }

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if ((macaddr == NULL) &&
                (xmlStrEqual(cur->name, BAD_CAST "mac"))) {
                macaddr = virXMLPropString(cur, "address");
            } else if ((network == NULL) &&
                       (def->type == VIR_DOMAIN_NET_TYPE_NETWORK) &&
                       (xmlStrEqual(cur->name, BAD_CAST "source"))) {
                network = virXMLPropString(cur, "network");
            } else if ((internal == NULL) &&
                       (def->type == VIR_DOMAIN_NET_TYPE_INTERNAL) &&
                       (xmlStrEqual(cur->name, BAD_CAST "source"))) {
                internal = virXMLPropString(cur, "name");
            } else if ((network == NULL) &&
                       (def->type == VIR_DOMAIN_NET_TYPE_BRIDGE) &&
                       (xmlStrEqual(cur->name, BAD_CAST "source"))) {
                bridge = virXMLPropString(cur, "bridge");
            } else if ((dev == NULL) &&
                       (def->type == VIR_DOMAIN_NET_TYPE_ETHERNET) &&
                       xmlStrEqual(cur->name, BAD_CAST "source")) {
                dev = virXMLPropString(cur, "dev");
            } else if ((network == NULL) &&
                       ((def->type == VIR_DOMAIN_NET_TYPE_SERVER) ||
                        (def->type == VIR_DOMAIN_NET_TYPE_CLIENT) ||
                        (def->type == VIR_DOMAIN_NET_TYPE_MCAST)) &&
                       (xmlStrEqual(cur->name, BAD_CAST "source"))) {
                address = virXMLPropString(cur, "address");
                port = virXMLPropString(cur, "port");
            } else if ((address == NULL) &&
                       (def->type == VIR_DOMAIN_NET_TYPE_ETHERNET ||
                        def->type == VIR_DOMAIN_NET_TYPE_BRIDGE) &&
                       (xmlStrEqual(cur->name, BAD_CAST "ip"))) {
                address = virXMLPropString(cur, "address");
            } else if ((ifname == NULL) &&
                       xmlStrEqual(cur->name, BAD_CAST "target")) {
                ifname = virXMLPropString(cur, "dev");
                if ((ifname != NULL) &&
                    (STRPREFIX((const char*)ifname, "vnet"))) {
                    /* An auto-generated target name, blank it out */
                    VIR_FREE(ifname);
                }
            } else if ((script == NULL) &&
                       (def->type == VIR_DOMAIN_NET_TYPE_ETHERNET ||
                        def->type == VIR_DOMAIN_NET_TYPE_BRIDGE) &&
                       xmlStrEqual(cur->name, BAD_CAST "script")) {
                script = virXMLPropString(cur, "path");
            } else if (xmlStrEqual (cur->name, BAD_CAST "model")) {
                model = virXMLPropString(cur, "type");
            } else if ((flags & VIR_DOMAIN_XML_INTERNAL_STATUS) &&
                       xmlStrEqual(cur->name, BAD_CAST "state")) {
                /* Legacy back-compat. Don't add any more attributes here */
                devaddr = virXMLPropString(cur, "devaddr");
            }
        }
        cur = cur->next;
    }

    if (macaddr) {
        if (virParseMacAddr((const char *)macaddr, def->mac) < 0) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("unable to parse mac address '%s'"),
                                 (const char *)macaddr);
            goto error;
        }
    } else {
        virCapabilitiesGenerateMac(caps, def->mac);
    }

    if (devaddr) {
        if (sscanf(devaddr, "%x:%x:%x",
                   &def->info.addr.pci.domain,
                   &def->info.addr.pci.bus,
                   &def->info.addr.pci.slot) < 3) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("Unable to parse devaddr parameter '%s'"),
                                 devaddr);
            goto error;
        }
        def->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
    } else {
        if (virDomainDeviceInfoParseXML(conn, node, &def->info, flags) < 0)
            goto error;
    }

    /* XXX what about ISA/USB based NIC models - once we support
     * them we should make sure address type is correct */
    if (def->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
        def->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                             _("Network interfaces must use 'pci' address type"));
        goto error;
    }

    switch (def->type) {
    case VIR_DOMAIN_NET_TYPE_NETWORK:
        if (network == NULL) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
    _("No <source> 'network' attribute specified with <interface type='network'/>"));
            goto error;
        }
        def->data.network.name = network;
        network = NULL;
        break;

    case VIR_DOMAIN_NET_TYPE_ETHERNET:

        if (script != NULL) {
            def->data.ethernet.script = script;
            script = NULL;
        }
        if (dev != NULL) {
            def->data.ethernet.dev = dev;
            dev = NULL;
        }
        if (address != NULL) {
            def->data.ethernet.ipaddr = address;
            address = NULL;
        }
        break;

    case VIR_DOMAIN_NET_TYPE_BRIDGE:
        if (bridge == NULL) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
    _("No <source> 'bridge' attribute specified with <interface type='bridge'/>"));
            goto error;
        }
        def->data.bridge.brname = bridge;
        bridge = NULL;
        if (script != NULL) {
            def->data.bridge.script = script;
            script = NULL;
        }
        if (address != NULL) {
            def->data.bridge.ipaddr = address;
            address = NULL;
        }
        break;

    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_MCAST:
        if (port == NULL) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
            _("No <source> 'port' attribute specified with socket interface"));
            goto error;
        }
        if (virStrToLong_i(port, NULL, 10, &def->data.socket.port) < 0) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
            _("Cannot parse <source> 'port' attribute with socket interface"));
            goto error;
        }

        if (address == NULL) {
            if (def->type == VIR_DOMAIN_NET_TYPE_CLIENT ||
                def->type == VIR_DOMAIN_NET_TYPE_MCAST) {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
        _("No <source> 'address' attribute specified with socket interface"));
                goto error;
            }
        } else {
            def->data.socket.address = address;
            address = NULL;
        }
        break;

    case VIR_DOMAIN_NET_TYPE_INTERNAL:
        if (internal == NULL) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
        _("No <source> 'name' attribute specified with <interface type='internal'/>"));
            goto error;
        }
        def->data.internal.name = internal;
        internal = NULL;
        break;
    }

    if (ifname != NULL) {
        def->ifname = ifname;
        ifname = NULL;
    }

    /* NIC model (see -net nic,model=?).  We only check that it looks
     * reasonable, not that it is a supported NIC type.  FWIW kvm
     * supports these types as of April 2008:
     * i82551 i82557b i82559er ne2k_pci pcnet rtl8139 e1000 virtio
     */
    if (model != NULL) {
        int i;
        for (i = 0 ; i < strlen(model) ; i++) {
            int char_ok = c_isalnum(model[i]) || model[i] == '_';
            if (!char_ok) {
                virDomainReportError (conn, VIR_ERR_INVALID_ARG, "%s",
                              _("Model name contains invalid characters"));
                goto error;
            }
        }
        def->model = model;
        model = NULL;
    }

cleanup:
    VIR_FREE(macaddr);
    VIR_FREE(network);
    VIR_FREE(address);
    VIR_FREE(port);
    VIR_FREE(ifname);
    VIR_FREE(dev);
    VIR_FREE(script);
    VIR_FREE(bridge);
    VIR_FREE(model);
    VIR_FREE(type);
    VIR_FREE(internal);
    VIR_FREE(devaddr);

    return def;

error:
    virDomainNetDefFree(def);
    def = NULL;
    goto cleanup;
}


/* Parse the XML definition for a character device
 * @param node XML nodeset to parse for net definition
 *
 * The XML we're dealing with looks like
 *
 * <serial type="pty">
 *   <source path="/dev/pts/3"/>
 *   <target port="1"/>
 * </serial>
 *
 * <serial type="dev">
 *   <source path="/dev/ttyS0"/>
 *   <target port="1"/>
 * </serial>
 *
 * <serial type="tcp">
 *   <source mode="connect" host="0.0.0.0" service="2445"/>
 *   <target port="1"/>
 * </serial>
 *
 * <serial type="tcp">
 *   <source mode="bind" host="0.0.0.0" service="2445"/>
 *   <target port="1"/>
 *   <protocol type='raw'/>
 * </serial>
 *
 * <serial type="udp">
 *   <source mode="bind" host="0.0.0.0" service="2445"/>
 *   <source mode="connect" host="0.0.0.0" service="2445"/>
 *   <target port="1"/>
 * </serial>
 *
 * <serial type="unix">
 *   <source mode="bind" path="/tmp/foo"/>
 *   <target port="1"/>
 * </serial>
 *
 */
static virDomainChrDefPtr
virDomainChrDefParseXML(virConnectPtr conn,
                        xmlNodePtr node,
                        int flags) {
    xmlNodePtr cur;
    char *type = NULL;
    char *bindHost = NULL;
    char *bindService = NULL;
    char *connectHost = NULL;
    char *connectService = NULL;
    char *path = NULL;
    char *mode = NULL;
    char *protocol = NULL;
    const char *nodeName;
    const char *targetType = NULL;
    const char *addrStr = NULL;
    const char *portStr = NULL;
    virDomainChrDefPtr def;

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    type = virXMLPropString(node, "type");
    if (type == NULL)
        def->type = VIR_DOMAIN_CHR_TYPE_PTY;
    else if ((def->type = virDomainChrTypeFromString(type)) < 0)
        def->type = VIR_DOMAIN_CHR_TYPE_NULL;

    nodeName = (const char *) node->name;
    if ((def->targetType = virDomainChrTargetTypeFromString(nodeName)) < 0) {
        /* channel is handled below */
        if (STRNEQ(nodeName, "channel")) {
            virDomainReportError(conn, VIR_ERR_XML_ERROR,
                              _("unknown target type for character device: %s"),
                                 nodeName);
            return NULL;
        }
        def->targetType = VIR_DOMAIN_CHR_TARGET_TYPE_NULL;
    }

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (xmlStrEqual(cur->name, BAD_CAST "source")) {
                if (mode == NULL)
                    mode = virXMLPropString(cur, "mode");

                switch (def->type) {
                case VIR_DOMAIN_CHR_TYPE_PTY:
                case VIR_DOMAIN_CHR_TYPE_DEV:
                case VIR_DOMAIN_CHR_TYPE_FILE:
                case VIR_DOMAIN_CHR_TYPE_PIPE:
                case VIR_DOMAIN_CHR_TYPE_UNIX:
                    if (path == NULL)
                        path = virXMLPropString(cur, "path");

                    break;

                case VIR_DOMAIN_CHR_TYPE_UDP:
                case VIR_DOMAIN_CHR_TYPE_TCP:
                    if (mode == NULL ||
                        STREQ((const char *)mode, "connect")) {

                        if (connectHost == NULL)
                            connectHost = virXMLPropString(cur, "host");
                        if (connectService == NULL)
                            connectService = virXMLPropString(cur, "service");
                    } else if (STREQ((const char *)mode, "bind")) {
                        if (bindHost == NULL)
                            bindHost = virXMLPropString(cur, "host");
                        if (bindService == NULL)
                            bindService = virXMLPropString(cur, "service");
                    } else {
                        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                             _("Unknown source mode '%s'"),
                                             mode);
                        goto error;
                    }

                    if (def->type == VIR_DOMAIN_CHR_TYPE_UDP)
                        VIR_FREE(mode);
                }
            } else if (xmlStrEqual(cur->name, BAD_CAST "protocol")) {
                if (protocol == NULL)
                    protocol = virXMLPropString(cur, "type");
            } else if (xmlStrEqual(cur->name, BAD_CAST "target")) {
                /* If target type isn't set yet, expect it to be set here */
                if (def->targetType == VIR_DOMAIN_CHR_TARGET_TYPE_NULL) {
                    targetType = virXMLPropString(cur, "type");
                    if (targetType == NULL) {
                        virDomainReportError(conn, VIR_ERR_XML_ERROR, "%s",
                                             _("character device target does "
                                               "not define a type"));
                        goto error;
                    }
                    if ((def->targetType =
                        virDomainChrTargetTypeFromString(targetType)) < 0)
                    {
                        virDomainReportError(conn, VIR_ERR_XML_ERROR,
                                             _("unknown target type for "
                                               "character device: %s"),
                                             targetType);
                        goto error;
                    }
                }

                unsigned int port;
                switch (def->targetType) {
                case VIR_DOMAIN_CHR_TARGET_TYPE_PARALLEL:
                case VIR_DOMAIN_CHR_TARGET_TYPE_SERIAL:
                case VIR_DOMAIN_CHR_TARGET_TYPE_CONSOLE:
                    portStr = virXMLPropString(cur, "port");
                    if (portStr == NULL) {
                        /* Not required. It will be assigned automatically
                         * later */
                        break;
                    }

                    if (virStrToLong_ui(portStr, NULL, 10, &port) < 0) {
                        virDomainReportError(conn, VIR_ERR_XML_ERROR,
                                             _("Invalid port number: %s"),
                                             portStr);
                        goto error;
                    }
                    break;

                case VIR_DOMAIN_CHR_TARGET_TYPE_GUESTFWD:
                    addrStr = virXMLPropString(cur, "address");
                    portStr = virXMLPropString(cur, "port");

                    if (addrStr == NULL) {
                        virDomainReportError(conn, VIR_ERR_XML_ERROR, "%s",
                                             _("guestfwd channel does not "
                                               "define a target address"));
                        goto error;
                    }
                    if (VIR_ALLOC(def->target.addr) < 0) {
                        virReportOOMError(conn);
                        goto error;
                    }
                    if (virSocketParseAddr(addrStr, def->target.addr, 0) < 0)
                    {
                        virDomainReportError(conn, VIR_ERR_XML_ERROR,
                                             _("%s is not a valid address"),
                                             addrStr);
                        goto error;
                    }

                    if (def->target.addr->stor.ss_family != AF_INET) {
                        virDomainReportError(conn, VIR_ERR_CONFIG_UNSUPPORTED,
                                     "%s", _("guestfwd channel only supports "
                                             "IPv4 addresses"));
                        goto error;
                    }

                    if (portStr == NULL) {
                        virDomainReportError(conn, VIR_ERR_XML_ERROR, "%s",
                                             _("guestfwd channel does "
                                               "not define a target port"));
                        goto error;
                    }
                    if (virStrToLong_ui(portStr, NULL, 10, &port) < 0) {
                        virDomainReportError(conn, VIR_ERR_XML_ERROR,
                                             _("Invalid port number: %s"),
                                             portStr);
                        goto error;
                    }
                    virSocketSetPort(def->target.addr, port);
                    break;

                default:
                    virDomainReportError(conn, VIR_ERR_XML_ERROR,
                                         _("unexpected target type type %u"),
                                         def->targetType);
                }
            }
        }
        cur = cur->next;
    }


    switch (def->type) {
    case VIR_DOMAIN_CHR_TYPE_NULL:
        /* Nada */
        break;

    case VIR_DOMAIN_CHR_TYPE_VC:
        break;

    case VIR_DOMAIN_CHR_TYPE_PTY:
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
        if (path == NULL &&
            def->type != VIR_DOMAIN_CHR_TYPE_PTY) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing source path attribute for char device"));
            goto error;
        }

        def->data.file.path = path;
        path = NULL;
        break;

    case VIR_DOMAIN_CHR_TYPE_STDIO:
        /* Nada */
        break;

    case VIR_DOMAIN_CHR_TYPE_TCP:
        if (mode == NULL ||
            STREQ(mode, "connect")) {
            if (connectHost == NULL) {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Missing source host attribute for char device"));
                goto error;
            }
            if (connectService == NULL) {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Missing source service attribute for char device"));
                goto error;
            }

            def->data.tcp.host = connectHost;
            connectHost = NULL;
            def->data.tcp.service = connectService;
            connectService = NULL;
            def->data.tcp.listen = 0;
        } else {
            if (bindHost == NULL) {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Missing source host attribute for char device"));
                goto error;
            }
            if (bindService == NULL) {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Missing source service attribute for char device"));
                goto error;
            }

            def->data.tcp.host = bindHost;
            bindHost = NULL;
            def->data.tcp.service = bindService;
            bindService = NULL;
            def->data.tcp.listen = 1;
        }

        if (protocol == NULL ||
            STREQ(protocol, "raw"))
            def->data.tcp.protocol = VIR_DOMAIN_CHR_TCP_PROTOCOL_RAW;
        else if (STREQ(protocol, "telnet"))
            def->data.tcp.protocol = VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET;
        else {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("Unknown protocol '%s'"), protocol);
            goto error;
        }

        break;

    case VIR_DOMAIN_CHR_TYPE_UDP:
        if (connectService == NULL) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                   _("Missing source service attribute for char device"));
            goto error;
        }

        def->data.udp.connectHost = connectHost;
        connectHost = NULL;
        def->data.udp.connectService = connectService;
        connectService = NULL;

        def->data.udp.bindHost = bindHost;
        bindHost = NULL;
        def->data.udp.bindService = bindService;
        bindService = NULL;
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        if (path == NULL) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                         _("Missing source path attribute for char device"));
            goto error;
        }

        if (mode != NULL &&
            STRNEQ(mode, "connect"))
            def->data.nix.listen = 1;
        else
            def->data.nix.listen = 0;

        def->data.nix.path = path;
        path = NULL;
        break;
    }

    if (virDomainDeviceInfoParseXML(conn, node, &def->info, flags) < 0)
        goto error;

cleanup:
    VIR_FREE(mode);
    VIR_FREE(protocol);
    VIR_FREE(type);
    VIR_FREE(bindHost);
    VIR_FREE(bindService);
    VIR_FREE(connectHost);
    VIR_FREE(connectService);
    VIR_FREE(path);
    VIR_FREE(targetType);
    VIR_FREE(addrStr);
    VIR_FREE(portStr);

    return def;

error:
    virDomainChrDefFree(def);
    def = NULL;
    goto cleanup;
}

/* Parse the XML definition for a network interface */
static virDomainInputDefPtr
virDomainInputDefParseXML(virConnectPtr conn,
                          const char *ostype,
                          xmlNodePtr node,
                          int flags) {
    virDomainInputDefPtr def;
    char *type = NULL;
    char *bus = NULL;

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    type = virXMLPropString(node, "type");
    bus = virXMLPropString(node, "bus");

    if (!type) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("missing input device type"));
        goto error;
    }

    if ((def->type = virDomainInputTypeFromString(type)) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unknown input device type '%s'"), type);
        goto error;
    }

    if (bus) {
        if ((def->bus = virDomainInputBusTypeFromString(bus)) < 0) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("unknown input bus type '%s'"), bus);
            goto error;
        }

        if (STREQ(ostype, "hvm")) {
            if (def->bus == VIR_DOMAIN_INPUT_BUS_PS2 && /* Only allow mouse for ps2 */
                def->type != VIR_DOMAIN_INPUT_TYPE_MOUSE) {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("ps2 bus does not support %s input device"),
                                     type);
                goto error;
            }
            if (def->bus == VIR_DOMAIN_INPUT_BUS_XEN) {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                     _("unsupported input bus %s"),
                                     bus);
                goto error;
            }
        } else {
            if (def->bus != VIR_DOMAIN_INPUT_BUS_XEN) {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                     _("unsupported input bus %s"),
                                     bus);
            }
            if (def->type != VIR_DOMAIN_INPUT_TYPE_MOUSE) {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("xen bus does not support %s input device"),
                                     type);
                goto error;
            }
        }
    } else {
        if (STREQ(ostype, "hvm")) {
            if (def->type == VIR_DOMAIN_INPUT_TYPE_MOUSE)
                def->bus = VIR_DOMAIN_INPUT_BUS_PS2;
            else
                def->bus = VIR_DOMAIN_INPUT_BUS_USB;
        } else {
            def->bus = VIR_DOMAIN_INPUT_BUS_XEN;
        }
    }

    if (virDomainDeviceInfoParseXML(conn, node, &def->info, flags) < 0)
        goto error;

cleanup:
    VIR_FREE(type);
    VIR_FREE(bus);

    return def;

error:
    virDomainInputDefFree(def);
    def = NULL;
    goto cleanup;
}


/* Parse the XML definition for a graphics device */
static virDomainGraphicsDefPtr
virDomainGraphicsDefParseXML(virConnectPtr conn,
                             xmlNodePtr node, int flags) {
    virDomainGraphicsDefPtr def;
    char *type = NULL;

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    type = virXMLPropString(node, "type");

    if (!type) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("missing graphics device type"));
        goto error;
    }

    if ((def->type = virDomainGraphicsTypeFromString(type)) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unknown graphics device type '%s'"), type);
        goto error;
    }

    if (def->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
        char *port = virXMLPropString(node, "port");
        char *autoport;

        if (port) {
            if (virStrToLong_i(port, NULL, 10, &def->data.vnc.port) < 0) {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                     _("cannot parse vnc port %s"), port);
                VIR_FREE(port);
                goto error;
            }
            VIR_FREE(port);
            /* Legacy compat syntax, used -1 for auto-port */
            if (def->data.vnc.port == -1) {
                if (flags & VIR_DOMAIN_XML_INACTIVE)
                    def->data.vnc.port = 0;
                def->data.vnc.autoport = 1;
            }
        } else {
            def->data.vnc.port = 0;
            def->data.vnc.autoport = 1;
        }

        if ((autoport = virXMLPropString(node, "autoport")) != NULL) {
            if (STREQ(autoport, "yes")) {
                if (flags & VIR_DOMAIN_XML_INACTIVE)
                    def->data.vnc.port = 0;
                def->data.vnc.autoport = 1;
            }
            VIR_FREE(autoport);
        }

        def->data.vnc.listenAddr = virXMLPropString(node, "listen");
        def->data.vnc.passwd = virXMLPropString(node, "passwd");
        def->data.vnc.keymap = virXMLPropString(node, "keymap");
    } else if (def->type == VIR_DOMAIN_GRAPHICS_TYPE_SDL) {
        char *fullscreen = virXMLPropString(node, "fullscreen");

        if (fullscreen != NULL) {
            if (STREQ(fullscreen, "yes")) {
                def->data.sdl.fullscreen = 1;
            } else if (STREQ(fullscreen, "no")) {
                def->data.sdl.fullscreen = 0;
            } else {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unknown fullscreen value '%s'"), fullscreen);
                VIR_FREE(fullscreen);
                goto error;
            }
            VIR_FREE(fullscreen);
        } else
            def->data.sdl.fullscreen = 0;
        def->data.sdl.xauth = virXMLPropString(node, "xauth");
        def->data.sdl.display = virXMLPropString(node, "display");
    } else if (def->type == VIR_DOMAIN_GRAPHICS_TYPE_RDP) {
        char *port = virXMLPropString(node, "port");
        char *autoport;
        char *replaceUser;
        char *multiUser;

        if (port) {
            if (virStrToLong_i(port, NULL, 10, &def->data.rdp.port) < 0) {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                     _("cannot parse rdp port %s"), port);
                VIR_FREE(port);
                goto error;
            }
            VIR_FREE(port);
        } else {
            def->data.rdp.port = 0;
            def->data.rdp.autoport = 1;
        }

        if ((autoport = virXMLPropString(node, "autoport")) != NULL) {
            if (STREQ(autoport, "yes")) {
                if (flags & VIR_DOMAIN_XML_INACTIVE)
                    def->data.rdp.port = 0;
                def->data.rdp.autoport = 1;
            }
            VIR_FREE(autoport);
        }

        if ((replaceUser = virXMLPropString(node, "replaceUser")) != NULL) {
            if (STREQ(replaceUser, "yes")) {
                def->data.rdp.replaceUser = 1;
            }
            VIR_FREE(replaceUser);
        }

        if ((multiUser = virXMLPropString(node, "multiUser")) != NULL) {
            if (STREQ(multiUser, "yes")) {
                def->data.rdp.multiUser = 1;
            }
            VIR_FREE(multiUser);
        }

        def->data.rdp.listenAddr = virXMLPropString(node, "listen");
    } else if (def->type == VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP) {
        char *fullscreen = virXMLPropString(node, "fullscreen");

        if (fullscreen != NULL) {
            if (STREQ(fullscreen, "yes")) {
                def->data.desktop.fullscreen = 1;
            } else if (STREQ(fullscreen, "no")) {
                def->data.desktop.fullscreen = 0;
            } else {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unknown fullscreen value '%s'"), fullscreen);
                VIR_FREE(fullscreen);
                goto error;
            }
            VIR_FREE(fullscreen);
        } else
            def->data.desktop.fullscreen = 0;

        def->data.desktop.display = virXMLPropString(node, "display");
    }

cleanup:
    VIR_FREE(type);

    return def;

error:
    virDomainGraphicsDefFree(def);
    def = NULL;
    goto cleanup;
}


static virDomainSoundDefPtr
virDomainSoundDefParseXML(virConnectPtr conn,
                          const xmlNodePtr node,
                          int flags)
{
    char *model;
    virDomainSoundDefPtr def;

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    model = virXMLPropString(node, "model");
    if ((def->model = virDomainSoundModelTypeFromString(model)) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unknown sound model '%s'"), model);
        goto error;
    }

    if (virDomainDeviceInfoParseXML(conn, node, &def->info, flags) < 0)
        goto error;

cleanup:
    VIR_FREE(model);

    return def;

error:
    virDomainSoundDefFree(def);
    def = NULL;
    goto cleanup;
}


static virDomainWatchdogDefPtr
virDomainWatchdogDefParseXML(virConnectPtr conn,
                             const xmlNodePtr node,
                             int flags)
{

    char *model = NULL;
    char *action = NULL;
    virDomainWatchdogDefPtr def;

    if (VIR_ALLOC (def) < 0) {
        virReportOOMError (conn);
        return NULL;
    }

    model = virXMLPropString (node, "model");
    if (model == NULL) {
        virDomainReportError (conn, VIR_ERR_INTERNAL_ERROR, "%s",
                              _("watchdog must contain model name"));
        goto error;
    }
    def->model = virDomainWatchdogModelTypeFromString (model);
    if (def->model < 0) {
        virDomainReportError (conn, VIR_ERR_INTERNAL_ERROR,
                              _("unknown watchdog model '%s'"), model);
        goto error;
    }

    action = virXMLPropString (node, "action");
    if (action == NULL)
        def->action = VIR_DOMAIN_WATCHDOG_ACTION_RESET;
    else {
        def->action = virDomainWatchdogActionTypeFromString (action);
        if (def->action < 0) {
            virDomainReportError (conn, VIR_ERR_INTERNAL_ERROR,
                                  _("unknown watchdog action '%s'"), action);
            goto error;
        }
    }

    if (virDomainDeviceInfoParseXML(conn, node, &def->info, flags) < 0)
        goto error;

cleanup:
    VIR_FREE (action);
    VIR_FREE (model);

    return def;

error:
    virDomainWatchdogDefFree (def);
    def = NULL;
    goto cleanup;
}


int
virDomainVideoDefaultRAM(virDomainDefPtr def,
                         int type)
{
    switch (type) {
        /* Wierd, QEMU defaults to 9 MB ??! */
    case VIR_DOMAIN_VIDEO_TYPE_VGA:
    case VIR_DOMAIN_VIDEO_TYPE_CIRRUS:
    case VIR_DOMAIN_VIDEO_TYPE_VMVGA:
        if (def->virtType == VIR_DOMAIN_VIRT_VBOX)
            return 8 * 1024;
        else if (def->virtType == VIR_DOMAIN_VIRT_VMWARE)
            return 4 * 1024;
        else
            return 9 * 1024;
        break;

    case VIR_DOMAIN_VIDEO_TYPE_XEN:
        /* Original Xen PVFB hardcoded to 4 MB */
        return 4 * 1024;

    default:
        return 0;
    }
}


int
virDomainVideoDefaultType(virDomainDefPtr def)
{
    switch (def->virtType) {
    case VIR_DOMAIN_VIRT_TEST:
    case VIR_DOMAIN_VIRT_QEMU:
    case VIR_DOMAIN_VIRT_KQEMU:
    case VIR_DOMAIN_VIRT_KVM:
    case VIR_DOMAIN_VIRT_XEN:
        if (def->os.type &&
            (STREQ(def->os.type, "xen") ||
             STREQ(def->os.type, "linux")))
            return VIR_DOMAIN_VIDEO_TYPE_XEN;
        else
            return VIR_DOMAIN_VIDEO_TYPE_CIRRUS;

    case VIR_DOMAIN_VIRT_VBOX:
        return VIR_DOMAIN_VIDEO_TYPE_VBOX;

    case VIR_DOMAIN_VIRT_VMWARE:
        return VIR_DOMAIN_VIDEO_TYPE_VMVGA;

    default:
        return -1;
    }
}

static virDomainVideoAccelDefPtr
virDomainVideoAccelDefParseXML(virConnectPtr conn, const xmlNodePtr node) {
    xmlNodePtr cur;
    virDomainVideoAccelDefPtr def;
    char *support3d = NULL;
    char *support2d = NULL;

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if ((support3d == NULL) && (support2d == NULL) &&
                xmlStrEqual(cur->name, BAD_CAST "acceleration")) {
                support3d = virXMLPropString(cur, "accel3d");
                support2d = virXMLPropString(cur, "accel2d");
            }
        }
        cur = cur->next;
    }

    if ((support3d == NULL) && (support2d == NULL))
        return(NULL);

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    if (support3d) {
        if (STREQ(support3d, "yes"))
            def->support3d = 1;
        else
            def->support3d = 0;
        VIR_FREE(support3d);
    }

    if (support2d) {
        if (STREQ(support2d, "yes"))
            def->support2d = 1;
        else
            def->support2d = 0;
        VIR_FREE(support2d);
    }

    return def;
}

static virDomainVideoDefPtr
virDomainVideoDefParseXML(virConnectPtr conn,
                          const xmlNodePtr node,
                          virDomainDefPtr dom,
                          int flags) {
    virDomainVideoDefPtr def;
    xmlNodePtr cur;
    char *type = NULL;
    char *heads = NULL;
    char *vram = NULL;

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if ((type == NULL) && (vram == NULL) && (heads == NULL) &&
                xmlStrEqual(cur->name, BAD_CAST "model")) {
                type = virXMLPropString(cur, "type");
                vram = virXMLPropString(cur, "vram");
                heads = virXMLPropString(cur, "heads");
                def->accel = virDomainVideoAccelDefParseXML(conn, cur);
            }
        }
        cur = cur->next;
    }

    if (type) {
        if ((def->type = virDomainVideoTypeFromString(type)) < 0) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("unknown video model '%s'"), type);
            goto error;
        }
    } else {
        if ((def->type = virDomainVideoDefaultType(dom)) < 0) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                                 _("missing video model and cannot determine default"));
            goto error;
        }
    }

    if (vram) {
        if (virStrToLong_ui(vram, NULL, 10, &def->vram) < 0) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("cannot parse video ram '%s'"), vram);
            goto error;
        }
    } else {
        def->vram = virDomainVideoDefaultRAM(dom, def->type);
    }

    if (heads) {
        if (virStrToLong_ui(heads, NULL, 10, &def->heads) < 0) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("cannot parse video heads '%s'"), heads);
            goto error;
        }
    } else {
        def->heads = 1;
    }

    if (virDomainDeviceInfoParseXML(conn, node, &def->info, flags) < 0)
        goto error;

    VIR_FREE(type);
    VIR_FREE(vram);
    VIR_FREE(heads);

    return def;

error:
    virDomainVideoDefFree(def);
    VIR_FREE(type);
    VIR_FREE(vram);
    VIR_FREE(heads);
    return NULL;
}

static int
virDomainHostdevSubsysUsbDefParseXML(virConnectPtr conn,
                                     const xmlNodePtr node,
                                     virDomainHostdevDefPtr def,
                                     int flags ATTRIBUTE_UNUSED) {

    int ret = -1;
    int got_product, got_vendor;
    xmlNodePtr cur;

    /* Product can validly be 0, so we need some extra help to determine
     * if it is uninitialized*/
    got_product = 0;
    got_vendor = 0;

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (xmlStrEqual(cur->name, BAD_CAST "vendor")) {
                char *vendor = virXMLPropString(cur, "id");

                if (vendor) {
                    got_vendor = 1;
                    if (virStrToLong_ui(vendor, NULL, 0,
                                    &def->source.subsys.u.usb.vendor) < 0) {
                        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("cannot parse vendor id %s"), vendor);
                        VIR_FREE(vendor);
                        goto out;
                    }
                    VIR_FREE(vendor);
                } else {
                    virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                         "%s", _("usb vendor needs id"));
                    goto out;
                }
            } else if (xmlStrEqual(cur->name, BAD_CAST "product")) {
                char* product = virXMLPropString(cur, "id");

                if (product) {
                    got_product = 1;
                    if (virStrToLong_ui(product, NULL, 0,
                                        &def->source.subsys.u.usb.product) < 0) {
                        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                             _("cannot parse product %s"),
                                             product);
                        VIR_FREE(product);
                        goto out;
                    }
                    VIR_FREE(product);
                } else {
                    virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                         "%s", _("usb product needs id"));
                    goto out;
                }
            } else if (xmlStrEqual(cur->name, BAD_CAST "address")) {
                char *bus, *device;

                bus = virXMLPropString(cur, "bus");
                if (bus) {
                    if (virStrToLong_ui(bus, NULL, 0,
                                        &def->source.subsys.u.usb.bus) < 0) {
                        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                             _("cannot parse bus %s"), bus);
                        VIR_FREE(bus);
                        goto out;
                    }
                    VIR_FREE(bus);
                } else {
                    virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                         "%s", _("usb address needs bus id"));
                    goto out;
                }

                device = virXMLPropString(cur, "device");
                if (device) {
                    if (virStrToLong_ui(device, NULL, 0,
                                        &def->source.subsys.u.usb.device) < 0)  {
                        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                             _("cannot parse device %s"),
                                             device);
                        VIR_FREE(device);
                        goto out;
                    }
                    VIR_FREE(device);
                } else {
                    virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                                         _("usb address needs device id"));
                    goto out;
                }
            } else {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                     _("unknown usb source type '%s'"),
                                     cur->name);
                goto out;
            }
        }
        cur = cur->next;
    }

    if (got_vendor && def->source.subsys.u.usb.vendor == 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
            "%s", _("vendor cannot be 0."));
        goto out;
    }

    if (!got_vendor && got_product) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
            "%s", _("missing vendor"));
        goto out;
    }
    if (got_vendor && !got_product) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
            "%s", _("missing product"));
        goto out;
    }

    ret = 0;
out:
    return ret;
}


static int
virDomainHostdevSubsysPciDefParseXML(virConnectPtr conn,
                                     const xmlNodePtr node,
                                     virDomainHostdevDefPtr def,
                                     int flags) {

    int ret = -1;
    xmlNodePtr cur;

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (xmlStrEqual(cur->name, BAD_CAST "address")) {
                virDomainDevicePCIAddressPtr addr =
                    &def->source.subsys.u.pci;

                if (virDomainDevicePCIAddressParseXML(conn, cur, addr) < 0)
                    goto out;
            } else if ((flags & VIR_DOMAIN_XML_INTERNAL_STATUS) &&
                       xmlStrEqual(cur->name, BAD_CAST "state")) {
                /* Legacy back-compat. Don't add any more attributes here */
                char *devaddr = virXMLPropString(cur, "devaddr");
                if (devaddr &&
                    sscanf(devaddr, "%x:%x:%x",
                           &def->info.addr.pci.domain,
                           &def->info.addr.pci.bus,
                           &def->info.addr.pci.slot) < 3) {
                    virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                         _("Unable to parse devaddr parameter '%s'"),
                                         devaddr);
                    VIR_FREE(devaddr);
                    goto out;
                }
                def->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
            } else {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                     _("unknown pci source type '%s'"),
                                     cur->name);
                goto out;
            }
        }
        cur = cur->next;
    }

    ret = 0;
out:
    return ret;
}


static virDomainHostdevDefPtr
virDomainHostdevDefParseXML(virConnectPtr conn,
                            const xmlNodePtr node,
                            int flags) {

    xmlNodePtr cur;
    virDomainHostdevDefPtr def;
    char *mode, *type = NULL, *managed = NULL;

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError(conn);
        return NULL;
    }
    def->target = NULL;

    mode = virXMLPropString(node, "mode");
    if (mode) {
        if ((def->mode=virDomainHostdevModeTypeFromString(mode)) < 0) {
             virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  _("unknown hostdev mode '%s'"), mode);
            goto error;
        }
    } else {
        def->mode = VIR_DOMAIN_HOSTDEV_MODE_SUBSYS;
    }

    type = virXMLPropString(node, "type");
    if (type) {
        if ((def->source.subsys.type = virDomainHostdevSubsysTypeFromString(type)) < 0) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("unknown host device type '%s'"), type);
            goto error;
        }
    } else {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("missing type in hostdev"));
        goto error;
    }

    managed = virXMLPropString(node, "managed");
    if (managed != NULL) {
        if (STREQ(managed, "yes"))
            def->managed = 1;
        VIR_FREE(managed);
    }

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (xmlStrEqual(cur->name, BAD_CAST "source")) {
                if (def->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
                    def->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB) {
                        if (virDomainHostdevSubsysUsbDefParseXML(conn, cur,
                                                                 def, flags) < 0)
                            goto error;
                }
                if (def->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
                    def->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI) {
                        if (virDomainHostdevSubsysPciDefParseXML(conn, cur, def, flags) < 0)
                            goto error;
                }
            } else if (xmlStrEqual(cur->name, BAD_CAST "address")) {
            } else {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                     _("unknown node %s"), cur->name);
            }
        }
        cur = cur->next;
    }

    if (def->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
        if (virDomainDeviceInfoParseXML(conn, node, &def->info, flags) < 0)
            goto error;
    }

    if (def->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {
        switch (def->source.subsys.type) {
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
            if (def->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
                def->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                                     _("PCI host devices must use 'pci' address type"));
                goto error;
            }
            break;
        }
    }

cleanup:
    VIR_FREE(type);
    VIR_FREE(mode);
    return def;

error:
    virDomainHostdevDefFree(def);
    def = NULL;
    goto cleanup;
}


static int virDomainLifecycleParseXML(virConnectPtr conn,
                                      xmlXPathContextPtr ctxt,
                                      const char *xpath,
                                      int *val,
                                      int defaultVal)
{
    char *tmp = virXPathString(conn, xpath, ctxt);
    if (tmp == NULL) {
        *val = defaultVal;
    } else {
        *val = virDomainLifecycleTypeFromString(tmp);
        if (*val < 0) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("unknown lifecycle action %s"), tmp);
            VIR_FREE(tmp);
            return -1;
        }
        VIR_FREE(tmp);
    }
    return 0;
}

static int
virSecurityLabelDefParseXML(virConnectPtr conn,
                            const virDomainDefPtr def,
                            xmlXPathContextPtr ctxt,
                            int flags)
{
    char *p;

    if (virXPathNode(conn, "./seclabel", ctxt) == NULL)
        return 0;

    p = virXPathStringLimit(conn, "string(./seclabel/@type)",
                            VIR_SECURITY_LABEL_BUFLEN-1, ctxt);
    if (p == NULL) {
        virDomainReportError(conn, VIR_ERR_XML_ERROR,
                             "%s", _("missing security type"));
        goto error;
    }
    def->seclabel.type = virDomainSeclabelTypeFromString(p);
    VIR_FREE(p);
    if (def->seclabel.type < 0) {
        virDomainReportError(conn, VIR_ERR_XML_ERROR,
                             "%s", _("invalid security type"));
        goto error;
    }

    /* Only parse details, if using static labels, or
     * if the 'live' VM XML is requested
     */
    if (def->seclabel.type == VIR_DOMAIN_SECLABEL_STATIC ||
        !(flags & VIR_DOMAIN_XML_INACTIVE)) {
        p = virXPathStringLimit(conn, "string(./seclabel/@model)",
                                VIR_SECURITY_MODEL_BUFLEN-1, ctxt);
        if (p == NULL) {
            virDomainReportError(conn, VIR_ERR_XML_ERROR,
                                 "%s", _("missing security model"));
            goto error;
        }
        def->seclabel.model = p;

        p = virXPathStringLimit(conn, "string(./seclabel/label[1])",
                                VIR_SECURITY_LABEL_BUFLEN-1, ctxt);
        if (p == NULL) {
            virDomainReportError(conn, VIR_ERR_XML_ERROR,
                                 "%s", _("security label is missing"));
            goto error;
        }

        def->seclabel.label = p;
    }

    /* Only parse imagelabel, if requested live XML for dynamic label */
    if (def->seclabel.type == VIR_DOMAIN_SECLABEL_DYNAMIC &&
        !(flags & VIR_DOMAIN_XML_INACTIVE)) {
        p = virXPathStringLimit(conn, "string(./seclabel/imagelabel[1])",
                                VIR_SECURITY_LABEL_BUFLEN-1, ctxt);
        if (p == NULL) {
            virDomainReportError(conn, VIR_ERR_XML_ERROR,
                                 "%s", _("security imagelabel is missing"));
            goto error;
        }
        def->seclabel.imagelabel = p;
    }

    return 0;

error:
    virSecurityLabelDefFree(def);
    return -1;
}

virDomainDeviceDefPtr virDomainDeviceDefParse(virConnectPtr conn,
                                              virCapsPtr caps,
                                              const virDomainDefPtr def,
                                              const char *xmlStr,
                                              int flags)
{
    xmlDocPtr xml;
    xmlNodePtr node;
    virDomainDeviceDefPtr dev = NULL;

    if (!(xml = xmlReadDoc(BAD_CAST xmlStr, "device.xml", NULL,
                           XML_PARSE_NOENT | XML_PARSE_NONET |
                           XML_PARSE_NOERROR | XML_PARSE_NOWARNING))) {
        virDomainReportError(conn, VIR_ERR_XML_ERROR, NULL);
        goto error;
    }

    node = xmlDocGetRootElement(xml);
    if (node == NULL) {
        virDomainReportError(conn, VIR_ERR_XML_ERROR,
                             "%s", _("missing root element"));
        goto error;
    }

    if (VIR_ALLOC(dev) < 0) {
        virReportOOMError(conn);
        goto error;
    }

    if (xmlStrEqual(node->name, BAD_CAST "disk")) {
        dev->type = VIR_DOMAIN_DEVICE_DISK;
        if (!(dev->data.disk = virDomainDiskDefParseXML(conn, node, flags)))
            goto error;
    } else if (xmlStrEqual(node->name, BAD_CAST "filesystem")) {
        dev->type = VIR_DOMAIN_DEVICE_FS;
        if (!(dev->data.fs = virDomainFSDefParseXML(conn, node, flags)))
            goto error;
    } else if (xmlStrEqual(node->name, BAD_CAST "interface")) {
        dev->type = VIR_DOMAIN_DEVICE_NET;
        if (!(dev->data.net = virDomainNetDefParseXML(conn, caps, node, flags)))
            goto error;
    } else if (xmlStrEqual(node->name, BAD_CAST "input")) {
        dev->type = VIR_DOMAIN_DEVICE_INPUT;
        if (!(dev->data.input = virDomainInputDefParseXML(conn, def->os.type,
                                                          node, flags)))
            goto error;
    } else if (xmlStrEqual(node->name, BAD_CAST "sound")) {
        dev->type = VIR_DOMAIN_DEVICE_SOUND;
        if (!(dev->data.sound = virDomainSoundDefParseXML(conn, node, flags)))
            goto error;
    } else if (xmlStrEqual(node->name, BAD_CAST "watchdog")) {
        dev->type = VIR_DOMAIN_DEVICE_WATCHDOG;
        if (!(dev->data.watchdog = virDomainWatchdogDefParseXML(conn, node, flags)))
            goto error;
    } else if (xmlStrEqual(node->name, BAD_CAST "video")) {
        dev->type = VIR_DOMAIN_DEVICE_VIDEO;
        if (!(dev->data.video = virDomainVideoDefParseXML(conn, node, def, flags)))
            goto error;
    } else if (xmlStrEqual(node->name, BAD_CAST "hostdev")) {
        dev->type = VIR_DOMAIN_DEVICE_HOSTDEV;
        if (!(dev->data.hostdev = virDomainHostdevDefParseXML(conn, node, flags)))
            goto error;
    } else if (xmlStrEqual(node->name, BAD_CAST "controller")) {
        dev->type = VIR_DOMAIN_DEVICE_CONTROLLER;
        if (!(dev->data.controller = virDomainControllerDefParseXML(conn, node, flags)))
            goto error;
    } else {
        virDomainReportError(conn, VIR_ERR_XML_ERROR,
                             "%s", _("unknown device type"));
        goto error;
    }

    xmlFreeDoc(xml);

    return dev;

  error:
    xmlFreeDoc(xml);
    VIR_FREE(dev);
    return NULL;
}
#endif


int virDomainDiskInsert(virDomainDefPtr def,
                        virDomainDiskDefPtr disk)
{

    if (VIR_REALLOC_N(def->disks, def->ndisks+1) < 0)
        return -1;

    virDomainDiskInsertPreAlloced(def, disk);

    return 0;
}

void virDomainDiskInsertPreAlloced(virDomainDefPtr def,
                                   virDomainDiskDefPtr disk)
{
    int i;
    /* Tenatively plan to insert disk at the end. */
    int insertAt = -1;

    /* Then work backwards looking for disks on
     * the same bus. If we find a disk with a drive
     * index greater than the new one, insert at
     * that position
     */
    for (i = (def->ndisks - 1) ; i >= 0 ; i--) {
        /* If bus matches and current disk is after
         * new disk, then new disk should go here */
        if (def->disks[i]->bus == disk->bus &&
            (virDiskNameToIndex(def->disks[i]->dst) >
             virDiskNameToIndex(disk->dst))) {
            insertAt = i;
        } else if (def->disks[i]->bus == disk->bus &&
                   insertAt == -1) {
            /* Last disk with match bus is before the
             * new disk, then put new disk just after
             */
            insertAt = i + 1;
        }
    }

    /* No disks with this bus yet, so put at end of list */
    if (insertAt == -1)
        insertAt = def->ndisks;

    if (insertAt < def->ndisks)
        memmove(def->disks + insertAt + 1,
                def->disks + insertAt,
                (sizeof(def->disks[0]) * (def->ndisks-insertAt)));

    def->disks[insertAt] = disk;
    def->ndisks++;
}


int virDomainControllerInsert(virDomainDefPtr def,
                              virDomainControllerDefPtr controller)
{

    if (VIR_REALLOC_N(def->controllers, def->ncontrollers+1) < 0)
        return -1;

    virDomainControllerInsertPreAlloced(def, controller);

    return 0;
}

void virDomainControllerInsertPreAlloced(virDomainDefPtr def,
                                         virDomainControllerDefPtr controller)
{
    int i;
    /* Tenatively plan to insert controller at the end. */
    int insertAt = -1;

    /* Then work backwards looking for controllers of
     * the same type. If we find a controller with a
     * index greater than the new one, insert at
     * that position
     */
    for (i = (def->ncontrollers - 1) ; i >= 0 ; i--) {
        /* If bus matches and current controller is after
         * new controller, then new controller should go here */
        if ((def->controllers[i]->type == controller->type) &&
            (def->controllers[i]->idx > controller->idx)) {
            insertAt = i;
        } else if (def->controllers[i]->type == controller->type &&
                   insertAt == -1) {
            /* Last controller with match bus is before the
             * new controller, then put new controller just after
             */
            insertAt = i + 1;
        }
    }

    /* No controllers with this bus yet, so put at end of list */
    if (insertAt == -1)
        insertAt = def->ncontrollers;

    if (insertAt < def->ncontrollers)
        memmove(def->controllers + insertAt + 1,
                def->controllers + insertAt,
                (sizeof(def->controllers[0]) * (def->ncontrollers-insertAt)));

    def->controllers[insertAt] = controller;
    def->ncontrollers++;
}


#ifndef PROXY
static char *virDomainDefDefaultEmulator(virConnectPtr conn,
                                         virDomainDefPtr def,
                                         virCapsPtr caps) {
    const char *type;
    const char *emulator;
    char *retemu;

    type = virDomainVirtTypeToString(def->virtType);
    if (!type) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("unknown virt type"));
        return NULL;
    }

    emulator = virCapabilitiesDefaultGuestEmulator(caps,
                                                   def->os.type,
                                                   def->os.arch,
                                                   type);

    if (!emulator) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("no emulator for domain %s os type %s on architecture %s"),
                             type, def->os.type, def->os.arch);
        return NULL;
    }

    retemu = strdup(emulator);
    if (!retemu)
        virReportOOMError(conn);

    return retemu;
}

static virDomainDefPtr virDomainDefParseXML(virConnectPtr conn,
                                            virCapsPtr caps,
                                            xmlXPathContextPtr ctxt, int flags)
{
    xmlNodePtr *nodes = NULL, node = NULL;
    char *tmp = NULL;
    int i, n;
    long id = -1;
    virDomainDefPtr def;

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    if (!(flags & VIR_DOMAIN_XML_INACTIVE))
        if ((virXPathLong(conn, "string(./@id)", ctxt, &id)) < 0)
            id = -1;
    def->id = (int)id;

    /* Find out what type of virtualization to use */
    if (!(tmp = virXPathString(conn, "string(./@type)", ctxt))) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("missing domain type attribute"));
        goto error;
    }

    if ((def->virtType = virDomainVirtTypeFromString(tmp)) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("invalid domain type %s"), tmp);
        goto error;
    }
    VIR_FREE(tmp);

    /* Extract domain name */
    if (!(def->name = virXPathString(conn, "string(./name[1])", ctxt))) {
        virDomainReportError(conn, VIR_ERR_NO_NAME, NULL);
        goto error;
    }

    /* Extract domain uuid */
    tmp = virXPathString(conn, "string(./uuid[1])", ctxt);
    if (!tmp) {
        if (virUUIDGenerate(def->uuid)) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("Failed to generate UUID"));
            goto error;
        }
    } else {
        if (virUUIDParse(tmp, def->uuid) < 0) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("malformed uuid element"));
            goto error;
        }
        VIR_FREE(tmp);
    }

    /* Extract documentation if present */
    def->description = virXPathString(conn, "string(./description[1])", ctxt);

    /* Extract domain memory */
    if (virXPathULong(conn, "string(./memory[1])", ctxt, &def->maxmem) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("missing memory element"));
        goto error;
    }

    if (virXPathULong(conn, "string(./currentMemory[1])", ctxt, &def->memory) < 0)
        def->memory = def->maxmem;

    node = virXPathNode(conn, "./memoryBacking/hugepages", ctxt);
    if (node)
        def->hugepage_backed = 1;

    if (virXPathULong(conn, "string(./vcpu[1])", ctxt, &def->vcpus) < 0)
        def->vcpus = 1;

    tmp = virXPathString(conn, "string(./vcpu[1]/@cpuset)", ctxt);
    if (tmp) {
        char *set = tmp;
        def->cpumasklen = VIR_DOMAIN_CPUMASK_LEN;
        if (VIR_ALLOC_N(def->cpumask, def->cpumasklen) < 0) {
            virReportOOMError(conn);
            goto error;
        }
        if (virDomainCpuSetParse(conn, (const char **)&set,
                                 0, def->cpumask,
                                 def->cpumasklen) < 0)
            goto error;
        VIR_FREE(tmp);
    }

    n = virXPathNodeSet(conn, "./features/*", ctxt, &nodes);
    if (n < 0)
        goto error;
    if (n) {
        for (i = 0 ; i < n ; i++) {
            int val = virDomainFeatureTypeFromString((const char *)nodes[i]->name);
            if (val < 0) {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                     _("unexpected feature %s"),
                                     nodes[i]->name);
                goto error;
            }
            def->features |= (1 << val);
        }
        VIR_FREE(nodes);
    }

    if (virDomainLifecycleParseXML(conn, ctxt, "string(./on_reboot[1])",
                                   &def->onReboot, VIR_DOMAIN_LIFECYCLE_RESTART) < 0)
        goto error;

    if (virDomainLifecycleParseXML(conn, ctxt, "string(./on_poweroff[1])",
                                   &def->onPoweroff, VIR_DOMAIN_LIFECYCLE_DESTROY) < 0)
        goto error;

    if (virDomainLifecycleParseXML(conn, ctxt, "string(./on_crash[1])",
                                   &def->onCrash, VIR_DOMAIN_LIFECYCLE_DESTROY) < 0)
        goto error;


    tmp = virXPathString(conn, "string(./clock/@offset)", ctxt);
    if (tmp && STREQ(tmp, "localtime"))
        def->localtime = 1;
    VIR_FREE(tmp);

    def->os.bootloader = virXPathString(conn, "string(./bootloader)", ctxt);
    def->os.bootloaderArgs = virXPathString(conn, "string(./bootloader_args)", ctxt);

    def->os.type = virXPathString(conn, "string(./os/type[1])", ctxt);
    if (!def->os.type) {
        if (def->os.bootloader) {
            def->os.type = strdup("xen");
            if (!def->os.type) {
                virReportOOMError(conn);
                goto error;
            }
        } else {
            virDomainReportError(conn, VIR_ERR_OS_TYPE,
                                 "%s", _("no OS type"));
            goto error;
        }
    }
    /*
     * HACK: For xen driver we previously used bogus 'linux' as the
     * os type for paravirt, whereas capabilities declare it to
     * be 'xen'. So we accept the former and convert
     */
    if (STREQ(def->os.type, "linux") &&
        def->virtType == VIR_DOMAIN_VIRT_XEN) {
        VIR_FREE(def->os.type);
        if (!(def->os.type = strdup("xen"))) {
            virReportOOMError(conn);
            goto error;
        }
    }

    if (!virCapabilitiesSupportsGuestOSType(caps, def->os.type)) {
        virDomainReportError(conn, VIR_ERR_OS_TYPE,
                             "%s", def->os.type);
        goto error;
    }

    def->os.arch = virXPathString(conn, "string(./os/type[1]/@arch)", ctxt);
    if (def->os.arch) {
        if (!virCapabilitiesSupportsGuestArch(caps, def->os.type, def->os.arch)) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("os type '%s' & arch '%s' combination is not supported"),
                                 def->os.type, def->os.arch);
            goto error;
        }
    } else {
        const char *defaultArch = virCapabilitiesDefaultGuestArch(caps, def->os.type, virDomainVirtTypeToString(def->virtType));
        if (defaultArch == NULL) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("no supported architecture for os type '%s'"),
                                 def->os.type);
            goto error;
        }
        if (!(def->os.arch = strdup(defaultArch))) {
            virReportOOMError(conn);
            goto error;
        }
    }

    def->os.machine = virXPathString(conn, "string(./os/type[1]/@machine)", ctxt);
    if (!def->os.machine) {
        const char *defaultMachine = virCapabilitiesDefaultGuestMachine(caps,
                                                                        def->os.type,
                                                                        def->os.arch,
                                                                        virDomainVirtTypeToString(def->virtType));
        if (defaultMachine != NULL) {
            if (!(def->os.machine = strdup(defaultMachine))) {
                virReportOOMError(conn);
                goto error;
            }
        }
    }

    /*
     * Booting options for different OS types....
     *
     *   - A bootloader (and optional kernel+initrd)  (xen)
     *   - A kernel + initrd                          (xen)
     *   - A boot device (and optional kernel+initrd) (hvm)
     *   - An init script                             (exe)
     */

    if (STREQ(def->os.type, "exe")) {
        def->os.init = virXPathString(conn, "string(./os/init[1])", ctxt);
    }

    if (STREQ(def->os.type, "xen") ||
        STREQ(def->os.type, "hvm") ||
        STREQ(def->os.type, "uml")) {
        def->os.kernel = virXPathString(conn, "string(./os/kernel[1])", ctxt);
        def->os.initrd = virXPathString(conn, "string(./os/initrd[1])", ctxt);
        def->os.cmdline = virXPathString(conn, "string(./os/cmdline[1])", ctxt);
        def->os.root = virXPathString(conn, "string(./os/root[1])", ctxt);
        def->os.loader = virXPathString(conn, "string(./os/loader[1])", ctxt);
    }

    if (STREQ(def->os.type, "hvm")) {
        /* analysis of the boot devices */
        if ((n = virXPathNodeSet(conn, "./os/boot", ctxt, &nodes)) < 0) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("cannot extract boot device"));
            goto error;
        }
        for (i = 0 ; i < n && i < VIR_DOMAIN_BOOT_LAST ; i++) {
            int val;
            char *dev = virXMLPropString(nodes[i], "dev");
            if (!dev) {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                     "%s", _("missing boot device"));
                goto error;
            }
            if ((val = virDomainBootTypeFromString(dev)) < 0) {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                     _("unknown boot device '%s'"),
                                     dev);
                VIR_FREE(dev);
                goto error;
            }
            VIR_FREE(dev);
            def->os.bootDevs[def->os.nBootDevs++] = val;
        }
        if (def->os.nBootDevs == 0) {
            def->os.nBootDevs = 1;
            def->os.bootDevs[0] = VIR_DOMAIN_BOOT_DISK;
        }
        VIR_FREE(nodes);
    }

    def->emulator = virXPathString(conn, "string(./devices/emulator[1])", ctxt);
    if (!def->emulator && virCapabilitiesIsEmulatorRequired(caps)) {
        def->emulator = virDomainDefDefaultEmulator(conn, def, caps);
        if (!def->emulator)
            goto error;
    }

    /* analysis of the disk devices */
    if ((n = virXPathNodeSet(conn, "./devices/disk", ctxt, &nodes)) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("cannot extract disk devices"));
        goto error;
    }
    if (n && VIR_ALLOC_N(def->disks, n) < 0)
        goto no_memory;
    for (i = 0 ; i < n ; i++) {
        virDomainDiskDefPtr disk = virDomainDiskDefParseXML(conn,
                                                            nodes[i],
                                                            flags);
        if (!disk)
            goto error;

        def->disks[def->ndisks++] = disk;
    }
    VIR_FREE(nodes);

    /* analysis of the controller devices */
    if ((n = virXPathNodeSet(conn, "./devices/controller", ctxt, &nodes)) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("cannot extract controller devices"));
        goto error;
    }
    if (n && VIR_ALLOC_N(def->controllers, n) < 0)
        goto no_memory;
    for (i = 0 ; i < n ; i++) {
        virDomainControllerDefPtr controller = virDomainControllerDefParseXML(conn,
                                                                              nodes[i],
                                                                              flags);
        if (!controller)
            goto error;

        def->controllers[def->ncontrollers++] = controller;
    }
    VIR_FREE(nodes);

    /* Auto-add any further disk controllers implied by declared <disk>
     * elements, but not present as <controller> elements
     */
    if (virDomainDefAddDiskControllers(def) < 0)
        goto error;

    /* analysis of the filesystems */
    if ((n = virXPathNodeSet(conn, "./devices/filesystem", ctxt, &nodes)) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("cannot extract filesystem devices"));
        goto error;
    }
    if (n && VIR_ALLOC_N(def->fss, n) < 0)
        goto no_memory;
    for (i = 0 ; i < n ; i++) {
        virDomainFSDefPtr fs = virDomainFSDefParseXML(conn,
                                                      nodes[i],
                                                      flags);
        if (!fs)
            goto error;

        def->fss[def->nfss++] = fs;
    }
    VIR_FREE(nodes);

    /* analysis of the network devices */
    if ((n = virXPathNodeSet(conn, "./devices/interface", ctxt, &nodes)) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("cannot extract network devices"));
        goto error;
    }
    if (n && VIR_ALLOC_N(def->nets, n) < 0)
        goto no_memory;
    for (i = 0 ; i < n ; i++) {
        virDomainNetDefPtr net = virDomainNetDefParseXML(conn,
                                                         caps,
                                                         nodes[i],
                                                         flags);
        if (!net)
            goto error;

        def->nets[def->nnets++] = net;
    }
    VIR_FREE(nodes);


    /* analysis of the character devices */
    if ((n = virXPathNodeSet(conn, "./devices/parallel", ctxt, &nodes)) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("cannot extract parallel devices"));
        goto error;
    }
    if (n && VIR_ALLOC_N(def->parallels, n) < 0)
        goto no_memory;

    for (i = 0 ; i < n ; i++) {
        virDomainChrDefPtr chr = virDomainChrDefParseXML(conn,
                                                         nodes[i],
                                                         flags);
        if (!chr)
            goto error;

        chr->target.port = i;
        def->parallels[def->nparallels++] = chr;
    }
    VIR_FREE(nodes);

    if ((n = virXPathNodeSet(conn, "./devices/serial", ctxt, &nodes)) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("cannot extract serial devices"));
        goto error;
    }
    if (n && VIR_ALLOC_N(def->serials, n) < 0)
        goto no_memory;

    for (i = 0 ; i < n ; i++) {
        virDomainChrDefPtr chr = virDomainChrDefParseXML(conn,
                                                         nodes[i],
                                                         flags);
        if (!chr)
            goto error;

        chr->target.port = i;
        def->serials[def->nserials++] = chr;
    }
    VIR_FREE(nodes);

    if ((node = virXPathNode(conn, "./devices/console[1]", ctxt)) != NULL) {
        virDomainChrDefPtr chr = virDomainChrDefParseXML(conn,
                                                         node,
                                                         flags);
        if (!chr)
            goto error;

        chr->target.port = 0;
        /*
         * For HVM console actually created a serial device
         * while for non-HVM it was a parvirt console
         */
        if (STREQ(def->os.type, "hvm")) {
            if (def->nserials != 0) {
                virDomainChrDefFree(chr);
            } else {
                if (VIR_ALLOC_N(def->serials, 1) < 0) {
                    virDomainChrDefFree(chr);
                    goto no_memory;
                }
                def->nserials = 1;
                def->serials[0] = chr;
                chr->targetType = VIR_DOMAIN_CHR_TARGET_TYPE_SERIAL;
            }
        } else {
            def->console = chr;
        }
    }

    if ((n = virXPathNodeSet(conn, "./devices/channel", ctxt, &nodes)) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("cannot extract channel devices"));
        goto error;
    }
    if (n && VIR_ALLOC_N(def->channels, n) < 0)
        goto no_memory;

    for (i = 0 ; i < n ; i++) {
        virDomainChrDefPtr chr = virDomainChrDefParseXML(conn,
                                                         nodes[i],
                                                         flags);
        if (!chr)
            goto error;

        def->channels[def->nchannels++] = chr;
    }
    VIR_FREE(nodes);


    /* analysis of the input devices */
    if ((n = virXPathNodeSet(conn, "./devices/input", ctxt, &nodes)) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("cannot extract input devices"));
        goto error;
    }
    if (n && VIR_ALLOC_N(def->inputs, n) < 0)
        goto no_memory;

    for (i = 0 ; i < n ; i++) {
        virDomainInputDefPtr input = virDomainInputDefParseXML(conn,
                                                               def->os.type,
                                                               nodes[i],
                                                               flags);
        if (!input)
            goto error;


        /* With QEMU / KVM / Xen graphics, mouse + PS/2 is implicit
         * with graphics, so don't store it.
         * XXX will this be true for other virt types ? */
        if ((STREQ(def->os.type, "hvm") &&
             input->bus == VIR_DOMAIN_INPUT_BUS_PS2 &&
             input->type == VIR_DOMAIN_INPUT_TYPE_MOUSE) ||
            (STRNEQ(def->os.type, "hvm") &&
             input->bus == VIR_DOMAIN_INPUT_BUS_XEN &&
             input->type == VIR_DOMAIN_INPUT_TYPE_MOUSE)) {
            virDomainInputDefFree(input);
            continue;
        }

        def->inputs[def->ninputs++] = input;
    }
    VIR_FREE(nodes);

    /* analysis of the graphics devices */
    if ((n = virXPathNodeSet(conn, "./devices/graphics", ctxt, &nodes)) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("cannot extract graphics devices"));
        goto error;
    }
    if (n && VIR_ALLOC_N(def->graphics, n) < 0)
        goto no_memory;
    for (i = 0 ; i < n ; i++) {
        virDomainGraphicsDefPtr graphics = virDomainGraphicsDefParseXML(conn,
                                                                        nodes[i],
                                                                        flags);
        if (!graphics)
            goto error;

        def->graphics[def->ngraphics++] = graphics;
    }
    VIR_FREE(nodes);

    /* If graphics are enabled, there's an implicit PS2 mouse */
    if (def->ngraphics > 0) {
        virDomainInputDefPtr input;

        if (VIR_ALLOC(input) < 0) {
            virReportOOMError(conn);
            goto error;
        }
        if (STREQ(def->os.type, "hvm")) {
            input->type = VIR_DOMAIN_INPUT_TYPE_MOUSE;
            input->bus = VIR_DOMAIN_INPUT_BUS_PS2;
        } else {
            input->type = VIR_DOMAIN_INPUT_TYPE_MOUSE;
            input->bus = VIR_DOMAIN_INPUT_BUS_XEN;
        }

        if (VIR_REALLOC_N(def->inputs, def->ninputs + 1) < 0) {
            virDomainInputDefFree(input);
            goto no_memory;
        }
        def->inputs[def->ninputs] = input;
        def->ninputs++;
    }


    /* analysis of the sound devices */
    if ((n = virXPathNodeSet(conn, "./devices/sound", ctxt, &nodes)) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("cannot extract sound devices"));
        goto error;
    }
    if (n && VIR_ALLOC_N(def->sounds, n) < 0)
        goto no_memory;
    for (i = 0 ; i < n ; i++) {
        virDomainSoundDefPtr sound = virDomainSoundDefParseXML(conn,
                                                               nodes[i],
                                                               flags);
        if (!sound)
            goto error;

        def->sounds[def->nsounds++] = sound;
    }
    VIR_FREE(nodes);

    /* analysis of the video devices */
    if ((n = virXPathNodeSet(conn, "./devices/video", ctxt, &nodes)) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("cannot extract video devices"));
        goto error;
    }
    if (n && VIR_ALLOC_N(def->videos, n) < 0)
        goto no_memory;
    for (i = 0 ; i < n ; i++) {
        virDomainVideoDefPtr video = virDomainVideoDefParseXML(conn,
                                                               nodes[i],
                                                               def,
                                                               flags);
        if (!video)
            goto error;
        def->videos[def->nvideos++] = video;
    }
    VIR_FREE(nodes);

    /* For backwards compatability, if no <video> tag is set but there
     * is a <graphics> tag, then we add a single video tag */
    if (def->ngraphics && !def->nvideos) {
        virDomainVideoDefPtr video;
        if (VIR_ALLOC(video) < 0)
            goto no_memory;
        video->type = virDomainVideoDefaultType(def);
        if (video->type < 0) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                                 _("cannot determine default video type"));
            VIR_FREE(video);
            goto error;
        }
        video->vram = virDomainVideoDefaultRAM(def, video->type);
        video->heads = 1;
        if (VIR_ALLOC_N(def->videos, 1) < 0) {
            virDomainVideoDefFree(video);
            goto no_memory;
        }
        def->videos[def->nvideos++] = video;
    }

    /* analysis of the host devices */
    if ((n = virXPathNodeSet(conn, "./devices/hostdev", ctxt, &nodes)) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("cannot extract host devices"));
        goto error;
    }
    if (n && VIR_ALLOC_N(def->hostdevs, n) < 0)
        goto no_memory;
    for (i = 0 ; i < n ; i++) {
        virDomainHostdevDefPtr hostdev = virDomainHostdevDefParseXML(conn,
                                                                     nodes[i],
                                                                     flags);
        if (!hostdev)
            goto error;

        def->hostdevs[def->nhostdevs++] = hostdev;
    }
    VIR_FREE(nodes);

    /* analysis of the watchdog devices */
    def->watchdog = NULL;
    if ((n = virXPathNodeSet(conn, "./devices/watchdog", ctxt, &nodes)) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("cannot extract watchdog devices"));
        goto error;
    }
    if (n > 1) {
        virDomainReportError (conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("only a single watchdog device is supported"));
        goto error;
    }
    if (n > 0) {
        virDomainWatchdogDefPtr watchdog =
            virDomainWatchdogDefParseXML(conn, nodes[0], flags);
        if (!watchdog)
            goto error;

        def->watchdog = watchdog;
        VIR_FREE(nodes);
    }

    /* analysis of security label */
    if (virSecurityLabelDefParseXML(conn, def, ctxt, flags) == -1)
        goto error;

    if ((node = virXPathNode(conn, "./cpu[1]", ctxt)) != NULL) {
        xmlNodePtr oldnode = ctxt->node;
        ctxt->node = node;
        def->cpu = virCPUDefParseXML(conn, node, ctxt, VIR_CPU_TYPE_GUEST);
        ctxt->node = oldnode;

        if (def->cpu == NULL)
            goto error;
    }

    return def;

no_memory:
    virReportOOMError(conn);
    /* fallthrough */

 error:
    VIR_FREE(tmp);
    VIR_FREE(nodes);
    virDomainDefFree(def);
    return NULL;
}


static virDomainObjPtr virDomainObjParseXML(virConnectPtr conn,
                                            virCapsPtr caps,
                                            xmlXPathContextPtr ctxt)
{
    char *tmp = NULL;
    long val;
    xmlNodePtr config;
    xmlNodePtr oldnode;
    virDomainObjPtr obj;

    if (!(obj = virDomainObjNew(conn, caps)))
        return NULL;

    if (!(config = virXPathNode(conn, "./domain", ctxt))) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("no domain config"));
        goto error;
    }

    oldnode = ctxt->node;
    ctxt->node = config;
    obj->def = virDomainDefParseXML(conn, caps, ctxt,
                                    VIR_DOMAIN_XML_INTERNAL_STATUS);
    ctxt->node = oldnode;
    if (!obj->def)
        goto error;

    if (!(tmp = virXPathString(conn, "string(./@state)", ctxt))) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("missing domain state"));
        goto error;
    }
    if ((obj->state = virDomainStateTypeFromString(tmp)) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("invalid domain state '%s'"), tmp);
        VIR_FREE(tmp);
        goto error;
    }
    VIR_FREE(tmp);

    if ((virXPathLong(conn, "string(./@pid)", ctxt, &val)) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("invalid pid"));
        goto error;
    }
    obj->pid = (pid_t)val;

    if (caps->privateDataXMLParse &&
        ((caps->privateDataXMLParse)(ctxt, obj->privateData)) < 0)
        goto error;

    return obj;

error:
    virDomainObjUnref(obj);
    return NULL;
}


/* Called from SAX on parsing errors in the XML. */
static void
catchXMLError (void *ctx, const char *msg ATTRIBUTE_UNUSED, ...)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;

    if (ctxt) {
        virConnectPtr conn = ctxt->_private;

        if (virGetLastError() == NULL &&
            ctxt->lastError.level == XML_ERR_FATAL &&
            ctxt->lastError.message != NULL) {
            virDomainReportError (conn, VIR_ERR_XML_DETAIL,
                                  _("at line %d: %s"),
                                  ctxt->lastError.line,
                                  ctxt->lastError.message);
        }
    }
}

virDomainDefPtr virDomainDefParseString(virConnectPtr conn,
                                        virCapsPtr caps,
                                        const char *xmlStr,
                                        int flags)
{
    xmlParserCtxtPtr pctxt;
    xmlDocPtr xml = NULL;
    xmlNodePtr root;
    virDomainDefPtr def = NULL;

    /* Set up a parser context so we can catch the details of XML errors. */
    pctxt = xmlNewParserCtxt ();
    if (!pctxt || !pctxt->sax)
        goto cleanup;
    pctxt->sax->error = catchXMLError;
    pctxt->_private = conn;

    if (conn) virResetError (&conn->err);
    xml = xmlCtxtReadDoc (pctxt, BAD_CAST xmlStr, "domain.xml", NULL,
                          XML_PARSE_NOENT | XML_PARSE_NONET |
                          XML_PARSE_NOWARNING);
    if (!xml) {
        if (virGetLastError() == NULL)
              virDomainReportError(conn, VIR_ERR_XML_ERROR,
                                   "%s", _("failed to parse xml document"));
        goto cleanup;
    }

    if ((root = xmlDocGetRootElement(xml)) == NULL) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("missing root element"));
        goto cleanup;
    }

    def = virDomainDefParseNode(conn, caps, xml, root, flags);

cleanup:
    xmlFreeParserCtxt (pctxt);
    xmlFreeDoc (xml);
    return def;
}

virDomainDefPtr virDomainDefParseFile(virConnectPtr conn,
                                      virCapsPtr caps,
                                      const char *filename, int flags)
{
    xmlParserCtxtPtr pctxt;
    xmlDocPtr xml = NULL;
    xmlNodePtr root;
    virDomainDefPtr def = NULL;

    /* Set up a parser context so we can catch the details of XML errors. */
    pctxt = xmlNewParserCtxt ();
    if (!pctxt || !pctxt->sax)
        goto cleanup;
    pctxt->sax->error = catchXMLError;
    pctxt->_private = conn;

    if (conn) virResetError (&conn->err);
    xml = xmlCtxtReadFile (pctxt, filename, NULL,
                           XML_PARSE_NOENT | XML_PARSE_NONET |
                           XML_PARSE_NOWARNING);
    if (!xml) {
        if (virGetLastError() == NULL)
              virDomainReportError(conn, VIR_ERR_XML_ERROR,
                                   "%s", _("failed to parse xml document"));
        goto cleanup;
    }

    if ((root = xmlDocGetRootElement(xml)) == NULL) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("missing root element"));
        goto cleanup;
    }

    def = virDomainDefParseNode(conn, caps, xml, root, flags);

cleanup:
    xmlFreeParserCtxt (pctxt);
    xmlFreeDoc (xml);
    return def;
}


virDomainDefPtr virDomainDefParseNode(virConnectPtr conn,
                                      virCapsPtr caps,
                                      xmlDocPtr xml,
                                      xmlNodePtr root,
                                      int flags)
{
    xmlXPathContextPtr ctxt = NULL;
    virDomainDefPtr def = NULL;

    if (!xmlStrEqual(root->name, BAD_CAST "domain")) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("incorrect root element"));
        goto cleanup;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        virReportOOMError(conn);
        goto cleanup;
    }

    ctxt->node = root;
    def = virDomainDefParseXML(conn, caps, ctxt, flags);

cleanup:
    xmlXPathFreeContext(ctxt);
    return def;
}


virDomainObjPtr virDomainObjParseFile(virConnectPtr conn,
                                      virCapsPtr caps,
                                      const char *filename)
{
    xmlParserCtxtPtr pctxt;
    xmlDocPtr xml = NULL;
    xmlNodePtr root;
    virDomainObjPtr obj = NULL;

    /* Set up a parser context so we can catch the details of XML errors. */
    pctxt = xmlNewParserCtxt ();
    if (!pctxt || !pctxt->sax)
        goto cleanup;
    pctxt->sax->error = catchXMLError;
    pctxt->_private = conn;

    if (conn) virResetError (&conn->err);
    xml = xmlCtxtReadFile (pctxt, filename, NULL,
                           XML_PARSE_NOENT | XML_PARSE_NONET |
                           XML_PARSE_NOWARNING);
    if (!xml) {
        if (virGetLastError() == NULL)
              virDomainReportError(conn, VIR_ERR_XML_ERROR,
                                   "%s", _("failed to parse xml document"));
        goto cleanup;
    }

    if ((root = xmlDocGetRootElement(xml)) == NULL) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("missing root element"));
        goto cleanup;
    }

    obj = virDomainObjParseNode(conn, caps, xml, root);

cleanup:
    xmlFreeParserCtxt (pctxt);
    xmlFreeDoc (xml);
    return obj;
}


virDomainObjPtr virDomainObjParseNode(virConnectPtr conn,
                                      virCapsPtr caps,
                                      xmlDocPtr xml,
                                      xmlNodePtr root)
{
    xmlXPathContextPtr ctxt = NULL;
    virDomainObjPtr obj = NULL;

    if (!xmlStrEqual(root->name, BAD_CAST "domstatus")) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("incorrect root element"));
        goto cleanup;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        virReportOOMError(conn);
        goto cleanup;
    }

    ctxt->node = root;
    obj = virDomainObjParseXML(conn, caps, ctxt);

cleanup:
    xmlXPathFreeContext(ctxt);
    return obj;
}

static int virDomainDefMaybeAddDiskController(virDomainDefPtr def,
                                              int type,
                                              int idx)
{
    int found = 0;
    int i;
    virDomainControllerDefPtr cont;

    for (i = 0 ; (i < def->ncontrollers) && !found; i++) {
        if (def->controllers[i]->type == type &&
            def->controllers[i]->idx == idx)
            found = 1;
    }

    if (found)
        return 0;

    if (VIR_ALLOC(cont) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    cont->type = type;
    cont->idx = idx;

    if (VIR_REALLOC_N(def->controllers, def->ncontrollers+1) < 0) {
        VIR_FREE(cont);
        virReportOOMError(NULL);
        return -1;
    }
    def->controllers[def->ncontrollers] = cont;
    def->ncontrollers++;

    return 0;
}

static int virDomainDefAddDiskControllersForType(virDomainDefPtr def,
                                                 int controllerType,
                                                 int diskBus)
{
    int i;
    int maxController = -1;

    for (i = 0 ; i < def->ndisks ; i++) {
        if (def->disks[i]->bus != diskBus)
            continue;

        if (def->disks[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE)
            continue;

        if ((int)def->disks[i]->info.addr.drive.controller > maxController)
            maxController = def->disks[i]->info.addr.drive.controller;
    }

    for (i = 0 ; i <= maxController ; i++) {
        if (virDomainDefMaybeAddDiskController(def, controllerType, i) < 0)
            return -1;
    }

    return 0;
}


/*
 * Based on the declared <address type=drive> info for any disks,
 * add neccessary drive controllers which are not already present
 * in the XML. This is for compat with existing apps which will
 * not know/care about <controller> info in the XML
 */
int virDomainDefAddDiskControllers(virDomainDefPtr def)
{
    if (virDomainDefAddDiskControllersForType(def,
                                              VIR_DOMAIN_CONTROLLER_TYPE_SCSI,
                                              VIR_DOMAIN_DISK_BUS_SCSI) < 0)
        return -1;

    if (virDomainDefAddDiskControllersForType(def,
                                              VIR_DOMAIN_CONTROLLER_TYPE_FDC,
                                              VIR_DOMAIN_DISK_BUS_FDC) < 0)
        return -1;

    if (virDomainDefAddDiskControllersForType(def,
                                              VIR_DOMAIN_CONTROLLER_TYPE_IDE,
                                              VIR_DOMAIN_DISK_BUS_IDE) < 0)
        return -1;

    return 0;
}


#endif /* ! PROXY */

/************************************************************************
 *                                                                        *
 * Parser and converter for the CPUset strings used in libvirt                *
 *                                                                        *
 ************************************************************************/
/**
 * virDomainCpuNumberParse
 * @str: pointer to the char pointer used
 * @maxcpu: maximum CPU number allowed
 *
 * Parse a CPU number
 *
 * Returns the CPU number or -1 in case of error. @str will be
 *         updated to skip the number.
 */
static int
virDomainCpuNumberParse(const char **str, int maxcpu)
{
    int ret = 0;
    const char *cur = *str;

    if (!c_isdigit(*cur))
        return (-1);

    while (c_isdigit(*cur)) {
        ret = ret * 10 + (*cur - '0');
        if (ret >= maxcpu)
            return (-1);
        cur++;
    }
    *str = cur;
    return (ret);
}

/**
 * virDomainCpuSetFormat:
 * @conn: connection
 * @cpuset: pointer to a char array for the CPU set
 * @maxcpu: number of elements available in @cpuset
 *
 * Serialize the cpuset to a string
 *
 * Returns the new string NULL in case of error. The string need to be
 *         freed by the caller.
 */
char *
virDomainCpuSetFormat(virConnectPtr conn, char *cpuset, int maxcpu)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    int start, cur;
    int first = 1;

    if ((cpuset == NULL) || (maxcpu <= 0) || (maxcpu > 100000))
        return (NULL);

    cur = 0;
    start = -1;
    while (cur < maxcpu) {
        if (cpuset[cur]) {
            if (start == -1)
                start = cur;
        } else if (start != -1) {
            if (!first)
                virBufferAddLit(&buf, ",");
            else
                first = 0;
            if (cur == start + 1)
                virBufferVSprintf(&buf, "%d", start);
            else
                virBufferVSprintf(&buf, "%d-%d", start, cur - 1);
            start = -1;
        }
        cur++;
    }
    if (start != -1) {
        if (!first)
            virBufferAddLit(&buf, ",");
        if (maxcpu == start + 1)
            virBufferVSprintf(&buf, "%d", start);
        else
            virBufferVSprintf(&buf, "%d-%d", start, maxcpu - 1);
    }

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError(conn);
        return NULL;
    }

    return virBufferContentAndReset(&buf);
}

/**
 * virDomainCpuSetParse:
 * @conn: connection
 * @str: pointer to a CPU set string pointer
 * @sep: potential character used to mark the end of string if not 0
 * @cpuset: pointer to a char array for the CPU set
 * @maxcpu: number of elements available in @cpuset
 *
 * Parse the cpu set, it will set the value for enabled CPUs in the @cpuset
 * to 1, and 0 otherwise. The syntax allows coma separated entries each
 * can be either a CPU number, ^N to unset that CPU or N-M for ranges.
 *
 * Returns the number of CPU found in that set, or -1 in case of error.
 *         @cpuset is modified accordingly to the value parsed.
 *         @str is updated to the end of the part parsed
 */
int
virDomainCpuSetParse(virConnectPtr conn, const char **str, char sep,
                     char *cpuset, int maxcpu)
{
    const char *cur;
    int ret = 0;
    int i, start, last;
    int neg = 0;

    if ((str == NULL) || (cpuset == NULL) || (maxcpu <= 0) ||
        (maxcpu > 100000))
        return (-1);

    cur = *str;
    virSkipSpaces(&cur);
    if (*cur == 0)
        goto parse_error;

    /* initialize cpumap to all 0s */
    for (i = 0; i < maxcpu; i++)
        cpuset[i] = 0;
    ret = 0;

    while ((*cur != 0) && (*cur != sep)) {
        /*
         * 3 constructs are allowed:
         *     - N   : a single CPU number
         *     - N-M : a range of CPU numbers with N < M
         *     - ^N  : remove a single CPU number from the current set
         */
        if (*cur == '^') {
            cur++;
            neg = 1;
        }

        if (!c_isdigit(*cur))
            goto parse_error;
        start = virDomainCpuNumberParse(&cur, maxcpu);
        if (start < 0)
            goto parse_error;
        virSkipSpaces(&cur);
        if ((*cur == ',') || (*cur == 0) || (*cur == sep)) {
            if (neg) {
                if (cpuset[start] == 1) {
                    cpuset[start] = 0;
                    ret--;
                }
            } else {
                if (cpuset[start] == 0) {
                    cpuset[start] = 1;
                    ret++;
                }
            }
        } else if (*cur == '-') {
            if (neg)
                goto parse_error;
            cur++;
            virSkipSpaces(&cur);
            last = virDomainCpuNumberParse(&cur, maxcpu);
            if (last < start)
                goto parse_error;
            for (i = start; i <= last; i++) {
                if (cpuset[i] == 0) {
                    cpuset[i] = 1;
                    ret++;
                }
            }
            virSkipSpaces(&cur);
        }
        if (*cur == ',') {
            cur++;
            virSkipSpaces(&cur);
            neg = 0;
        } else if ((*cur == 0) || (*cur == sep)) {
            break;
        } else
            goto parse_error;
    }
    *str = cur;
    return (ret);

  parse_error:
    virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("topology cpuset syntax error"));
    return (-1);
}


static int
virDomainLifecycleDefFormat(virConnectPtr conn,
                            virBufferPtr buf,
                            int type,
                            const char *name)
{
    const char *typeStr = virDomainLifecycleTypeToString(type);
    if (!typeStr) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unexpected lifecycle type %d"), type);
        return -1;
    }

    virBufferVSprintf(buf, "  <%s>%s</%s>\n", name, typeStr, name);

    return 0;
}


static int
virDomainDiskDefFormat(virConnectPtr conn,
                       virBufferPtr buf,
                       virDomainDiskDefPtr def,
                       int flags)
{
    const char *type = virDomainDiskTypeToString(def->type);
    const char *device = virDomainDiskDeviceTypeToString(def->device);
    const char *bus = virDomainDiskBusTypeToString(def->bus);
    const char *cachemode = virDomainDiskCacheTypeToString(def->cachemode);

    if (!type) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unexpected disk type %d"), def->type);
        return -1;
    }
    if (!device) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unexpected disk device %d"), def->device);
        return -1;
    }
    if (!bus) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unexpected disk bus %d"), def->bus);
        return -1;
    }
    if (!cachemode) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unexpected disk cache mode %d"), def->cachemode);
        return -1;
    }

    virBufferVSprintf(buf,
                      "    <disk type='%s' device='%s'>\n",
                      type, device);

    if (def->driverName) {
        virBufferVSprintf(buf, "      <driver name='%s'", def->driverName);
        if (def->driverType)
            virBufferVSprintf(buf, " type='%s'", def->driverType);
        if (def->cachemode)
            virBufferVSprintf(buf, " cache='%s'", cachemode);
        virBufferVSprintf(buf, "/>\n");
    }

    if (def->src) {
        switch (def->type) {
        case VIR_DOMAIN_DISK_TYPE_FILE:
            virBufferEscapeString(buf, "      <source file='%s'/>\n",
                                  def->src);
            break;
        case VIR_DOMAIN_DISK_TYPE_BLOCK:
            virBufferEscapeString(buf, "      <source dev='%s'/>\n",
                                  def->src);
            break;
        case VIR_DOMAIN_DISK_TYPE_DIR:
            virBufferEscapeString(buf, "      <source dir='%s'/>\n",
                                  def->src);
            break;
        default:
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("unexpected disk type %s"),
                                 virDomainDiskTypeToString(def->type));
            return -1;
        }
    }

    virBufferVSprintf(buf, "      <target dev='%s' bus='%s'/>\n",
                      def->dst, bus);

    if (def->readonly)
        virBufferAddLit(buf, "      <readonly/>\n");
    if (def->shared)
        virBufferAddLit(buf, "      <shareable/>\n");
    if (def->serial)
        virBufferEscapeString(buf, "      <serial>%s</serial>\n",
                              def->serial);
    if (def->encryption != NULL &&
        virStorageEncryptionFormat(conn, buf, def->encryption) < 0)
        return -1;

    if (virDomainDeviceInfoFormat(buf, &def->info, flags) < 0)
        return -1;

    virBufferAddLit(buf, "    </disk>\n");

    return 0;
}

static int
virDomainControllerDefFormat(virConnectPtr conn,
                             virBufferPtr buf,
                             virDomainControllerDefPtr def,
                             int flags)
{
    const char *type = virDomainControllerTypeToString(def->type);

    if (!type) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unexpected controller type %d"), def->type);
        return -1;
    }

    virBufferVSprintf(buf,
                      "    <controller type='%s' index='%d'",
                      type, def->idx);

    if (virDomainDeviceInfoIsSet(&def->info)) {
        virBufferAddLit(buf, ">\n");
        if (virDomainDeviceInfoFormat(buf, &def->info, flags) < 0)
            return -1;
        virBufferAddLit(buf, "    </controller>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }

    return 0;
}

static int
virDomainFSDefFormat(virConnectPtr conn,
                     virBufferPtr buf,
                     virDomainFSDefPtr def,
                     int flags)
{
    const char *type = virDomainFSTypeToString(def->type);

    if (!type) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unexpected filesystem type %d"), def->type);
        return -1;
    }

    virBufferVSprintf(buf,
                      "    <filesystem type='%s'>\n",
                      type);

    if (def->src) {
        switch (def->type) {
        case VIR_DOMAIN_FS_TYPE_MOUNT:
            virBufferEscapeString(buf, "      <source dir='%s'/>\n",
                                  def->src);
            break;

        case VIR_DOMAIN_FS_TYPE_BLOCK:
            virBufferEscapeString(buf, "      <source dev='%s'/>\n",
                                  def->src);
            break;

        case VIR_DOMAIN_FS_TYPE_FILE:
            virBufferEscapeString(buf, "      <source file='%s'/>\n",
                                  def->src);
            break;

        case VIR_DOMAIN_FS_TYPE_TEMPLATE:
            virBufferEscapeString(buf, "      <source name='%s'/>\n",
                                  def->src);
        }
    }

    virBufferVSprintf(buf, "      <target dir='%s'/>\n",
                      def->dst);

    if (def->readonly)
        virBufferAddLit(buf, "      <readonly/>\n");

    if (virDomainDeviceInfoFormat(buf, &def->info, flags) < 0)
        return -1;

    virBufferAddLit(buf, "    </filesystem>\n");

    return 0;
}

static int
virDomainNetDefFormat(virConnectPtr conn,
                      virBufferPtr buf,
                      virDomainNetDefPtr def,
                      int flags)
{
    const char *type = virDomainNetTypeToString(def->type);

    if (!type) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unexpected net type %d"), def->type);
        return -1;
    }

    virBufferVSprintf(buf, "    <interface type='%s'>\n", type);

    virBufferVSprintf(buf,
                      "      <mac address='%02x:%02x:%02x:%02x:%02x:%02x'/>\n",
                      def->mac[0], def->mac[1], def->mac[2],
                      def->mac[3], def->mac[4], def->mac[5]);

    switch (def->type) {
    case VIR_DOMAIN_NET_TYPE_NETWORK:
        virBufferEscapeString(buf, "      <source network='%s'/>\n",
                              def->data.network.name);
        break;

    case VIR_DOMAIN_NET_TYPE_ETHERNET:
        if (def->data.ethernet.dev)
            virBufferEscapeString(buf, "      <source dev='%s'/>\n",
                                  def->data.ethernet.dev);
        if (def->data.ethernet.ipaddr)
            virBufferVSprintf(buf, "      <ip address='%s'/>\n",
                              def->data.ethernet.ipaddr);
        if (def->data.ethernet.script)
            virBufferEscapeString(buf, "      <script path='%s'/>\n",
                                  def->data.ethernet.script);
        break;

    case VIR_DOMAIN_NET_TYPE_BRIDGE:
        virBufferEscapeString(buf, "      <source bridge='%s'/>\n",
                              def->data.bridge.brname);
        if (def->data.bridge.ipaddr)
            virBufferVSprintf(buf, "      <ip address='%s'/>\n",
                              def->data.bridge.ipaddr);
        if (def->data.bridge.script)
            virBufferEscapeString(buf, "      <script path='%s'/>\n",
                                  def->data.bridge.script);
        break;

    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_MCAST:
        if (def->data.socket.address)
            virBufferVSprintf(buf, "      <source address='%s' port='%d'/>\n",
                              def->data.socket.address, def->data.socket.port);
        else
            virBufferVSprintf(buf, "      <source port='%d'/>\n",
                              def->data.socket.port);
        break;

    case VIR_DOMAIN_NET_TYPE_INTERNAL:
        virBufferEscapeString(buf, "      <source name='%s'/>\n",
                              def->data.internal.name);
        break;

    }

    if (def->ifname)
        virBufferEscapeString(buf, "      <target dev='%s'/>\n",
                              def->ifname);
    if (def->model)
        virBufferEscapeString(buf, "      <model type='%s'/>\n",
                              def->model);

    if (virDomainDeviceInfoFormat(buf, &def->info, flags) < 0)
        return -1;

    virBufferAddLit(buf, "    </interface>\n");

    return 0;
}


static int
virDomainChrDefFormat(virConnectPtr conn,
                      virBufferPtr buf,
                      virDomainChrDefPtr def,
                      int flags)
{
    const char *type = virDomainChrTypeToString(def->type);
    const char *targetName = virDomainChrTargetTypeToString(def->targetType);
    const char *elementName;

    int ret = 0;

    switch (def->targetType) {
    /* channel types are in a common channel element */
    case VIR_DOMAIN_CHR_TARGET_TYPE_GUESTFWD:
        elementName = "channel";
        break;

    default:
        elementName = targetName;
    }

    if (!type) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unexpected char type %d"), def->type);
        return -1;
    }

    /* Compat with legacy  <console tty='/dev/pts/5'/> syntax */
    virBufferVSprintf(buf, "    <%s type='%s'",
                      elementName, type);
    if (def->targetType == VIR_DOMAIN_CHR_TARGET_TYPE_CONSOLE &&
        def->type == VIR_DOMAIN_CHR_TYPE_PTY &&
        !(flags & VIR_DOMAIN_XML_INACTIVE) &&
        def->data.file.path) {
        virBufferEscapeString(buf, " tty='%s'>\n",
                              def->data.file.path);
    } else {
        virBufferAddLit(buf, ">\n");
    }

    switch (def->type) {
    case VIR_DOMAIN_CHR_TYPE_NULL:
    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_STDIO:
        /* nada */
        break;

    case VIR_DOMAIN_CHR_TYPE_PTY:
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
        if (def->type != VIR_DOMAIN_CHR_TYPE_PTY ||
            (def->data.file.path && !(flags & VIR_DOMAIN_XML_INACTIVE))) {
            virBufferEscapeString(buf, "      <source path='%s'/>\n",
                                  def->data.file.path);
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_UDP:
        if (def->data.udp.bindService &&
            def->data.udp.bindHost) {
            virBufferVSprintf(buf, "      <source mode='bind' host='%s' service='%s'/>\n",
                              def->data.udp.bindHost,
                              def->data.udp.bindService);
        } else if (def->data.udp.bindHost) {
            virBufferVSprintf(buf, "      <source mode='bind' host='%s'/>\n",
                              def->data.udp.bindHost);
        } else if (def->data.udp.bindService) {
            virBufferVSprintf(buf, "      <source mode='bind' service='%s'/>\n",
                              def->data.udp.bindService);
        }

        if (def->data.udp.connectService &&
            def->data.udp.connectHost) {
            virBufferVSprintf(buf, "      <source mode='connect' host='%s' service='%s'/>\n",
                              def->data.udp.connectHost,
                              def->data.udp.connectService);
        } else if (def->data.udp.connectHost) {
            virBufferVSprintf(buf, "      <source mode='connect' host='%s'/>\n",
                              def->data.udp.connectHost);
        } else if (def->data.udp.connectService) {
            virBufferVSprintf(buf, "      <source mode='connect' service='%s'/>\n",
                              def->data.udp.connectService);
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_TCP:
        virBufferVSprintf(buf, "      <source mode='%s' host='%s' service='%s'/>\n",
                          def->data.tcp.listen ? "bind" : "connect",
                          def->data.tcp.host,
                          def->data.tcp.service);
        virBufferVSprintf(buf, "      <protocol type='%s'/>\n",
                          def->data.tcp.protocol ==
                          VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET
                          ? "telnet" : "raw");
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        virBufferVSprintf(buf, "      <source mode='%s'",
                          def->data.nix.listen ? "bind" : "connect");
        virBufferEscapeString(buf, " path='%s'/>\n",
                              def->data.nix.path);
        break;
    }

    switch (def->targetType) {
    case VIR_DOMAIN_CHR_TARGET_TYPE_GUESTFWD:
        {
            int port = virSocketGetPort(def->target.addr);
            if (port < 0) {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                                     _("Unable to format guestfwd port"));
                return -1;
            }
            const char *addr = virSocketFormatAddr(def->target.addr);
            if (addr == NULL) {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                                     _("Unable to format guestfwd address"));
                return -1;
            }
            virBufferVSprintf(buf,
                    "      <target type='guestfwd' address='%s' port='%d'/>\n",
                              addr, port);
            VIR_FREE(addr);
            break;
        }

    case VIR_DOMAIN_CHR_TARGET_TYPE_PARALLEL:
    case VIR_DOMAIN_CHR_TARGET_TYPE_SERIAL:
    case VIR_DOMAIN_CHR_TARGET_TYPE_CONSOLE:
        virBufferVSprintf(buf, "      <target port='%d'/>\n",
                          def->target.port);
        break;

    default:
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unexpected character destination type %d"),
                             def->targetType);
        return -1;
    }

    if (virDomainDeviceInfoFormat(buf, &def->info, flags) < 0)
        return -1;

    virBufferVSprintf(buf, "    </%s>\n",
                      elementName);

    return ret;
}

static int
virDomainSoundDefFormat(virConnectPtr conn,
                        virBufferPtr buf,
                        virDomainSoundDefPtr def,
                        int flags)
{
    const char *model = virDomainSoundModelTypeToString(def->model);

    if (!model) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unexpected sound model %d"), def->model);
        return -1;
    }

    virBufferVSprintf(buf, "    <sound model='%s'",
                      model);

    if (virDomainDeviceInfoIsSet(&def->info)) {
        virBufferAddLit(buf, ">\n");
        if (virDomainDeviceInfoFormat(buf, &def->info, flags) < 0)
            return -1;
        virBufferAddLit(buf, "    </sound>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }

    return 0;
}


static int
virDomainWatchdogDefFormat(virConnectPtr conn,
                           virBufferPtr buf,
                           virDomainWatchdogDefPtr def,
                           int flags)
{
    const char *model = virDomainWatchdogModelTypeToString (def->model);
    const char *action = virDomainWatchdogActionTypeToString (def->action);

    if (!model) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unexpected watchdog model %d"), def->model);
        return -1;
    }

    if (!action) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unexpected watchdog action %d"), def->action);
        return -1;
    }

    virBufferVSprintf(buf, "    <watchdog model='%s' action='%s'",
                      model, action);

    if (virDomainDeviceInfoIsSet(&def->info)) {
        virBufferAddLit(buf, ">\n");
        if (virDomainDeviceInfoFormat(buf, &def->info, flags) < 0)
            return -1;
        virBufferAddLit(buf, "    </watchdog>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }

    return 0;
}


static void
virDomainVideoAccelDefFormat(virBufferPtr buf,
                             virDomainVideoAccelDefPtr def)
{
    virBufferVSprintf(buf, "        <acceleration accel3d='%s'",
                      def->support3d ? "yes" : "no");
    virBufferVSprintf(buf, " accel2d='%s'",
                      def->support2d ? "yes" : "no");
    virBufferAddLit(buf, "/>\n");
}


static int
virDomainVideoDefFormat(virConnectPtr conn,
                        virBufferPtr buf,
                        virDomainVideoDefPtr def,
                        int flags)
{
    const char *model = virDomainVideoTypeToString(def->type);

    if (!model) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unexpected video model %d"), def->type);
        return -1;
    }

    virBufferAddLit(buf, "    <video>\n");
    virBufferVSprintf(buf, "      <model type='%s'",
                      model);
    if (def->vram)
        virBufferVSprintf(buf, " vram='%u'", def->vram);
    if (def->heads)
        virBufferVSprintf(buf, " heads='%u'", def->heads);
    if (def->accel) {
        virBufferAddLit(buf, ">\n");
        virDomainVideoAccelDefFormat(buf, def->accel);
        virBufferAddLit(buf, "      </model>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }

    if (virDomainDeviceInfoFormat(buf, &def->info, flags) < 0)
        return -1;

    virBufferAddLit(buf, "    </video>\n");

    return 0;
}

static int
virDomainInputDefFormat(virConnectPtr conn,
                        virBufferPtr buf,
                        virDomainInputDefPtr def,
                        int flags)
{
    const char *type = virDomainInputTypeToString(def->type);
    const char *bus = virDomainInputBusTypeToString(def->bus);

    if (!type) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unexpected input type %d"), def->type);
        return -1;
    }
    if (!bus) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unexpected input bus type %d"), def->bus);
        return -1;
    }

    virBufferVSprintf(buf, "    <input type='%s' bus='%s'",
                      type, bus);

    if (virDomainDeviceInfoIsSet(&def->info)) {
        virBufferAddLit(buf, ">\n");
        if (virDomainDeviceInfoFormat(buf, &def->info, flags) < 0)
            return -1;
        virBufferAddLit(buf, "    </input>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }

    return 0;
}


static int
virDomainGraphicsDefFormat(virConnectPtr conn,
                           virBufferPtr buf,
                           virDomainGraphicsDefPtr def,
                           int flags)
{
    const char *type = virDomainGraphicsTypeToString(def->type);

    if (!type) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unexpected net type %d"), def->type);
        return -1;
    }

    virBufferVSprintf(buf, "    <graphics type='%s'", type);

    switch (def->type) {
    case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
        if (def->data.vnc.port &&
            (!def->data.vnc.autoport || !(flags & VIR_DOMAIN_XML_INACTIVE)))
            virBufferVSprintf(buf, " port='%d'",
                              def->data.vnc.port);
        else if (def->data.vnc.autoport)
            virBufferAddLit(buf, " port='-1'");

        virBufferVSprintf(buf, " autoport='%s'",
                          def->data.vnc.autoport ? "yes" : "no");

        if (def->data.vnc.listenAddr)
            virBufferVSprintf(buf, " listen='%s'",
                              def->data.vnc.listenAddr);

        if (def->data.vnc.keymap)
            virBufferEscapeString(buf, " keymap='%s'",
                                  def->data.vnc.keymap);

        if (def->data.vnc.passwd &&
            (flags & VIR_DOMAIN_XML_SECURE))
            virBufferEscapeString(buf, " passwd='%s'",
                                  def->data.vnc.passwd);

        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_SDL:
        if (def->data.sdl.display)
            virBufferEscapeString(buf, " display='%s'",
                                  def->data.sdl.display);

        if (def->data.sdl.xauth)
            virBufferEscapeString(buf, " xauth='%s'",
                                  def->data.sdl.xauth);
        if (def->data.sdl.fullscreen)
            virBufferAddLit(buf, " fullscreen='yes'");

        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_RDP:
        if (def->data.rdp.port)
            virBufferVSprintf(buf, " port='%d'",
                              def->data.rdp.port);
        else if (def->data.rdp.autoport)
            virBufferAddLit(buf, " port='0'");

        if (def->data.rdp.autoport)
            virBufferVSprintf(buf, " autoport='yes'");

        if (def->data.rdp.replaceUser)
            virBufferVSprintf(buf, " replaceUser='yes'");

        if (def->data.rdp.multiUser)
            virBufferVSprintf(buf, " multiUser='yes'");

        if (def->data.rdp.listenAddr)
            virBufferVSprintf(buf, " listen='%s'", def->data.rdp.listenAddr);

        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP:
        if (def->data.desktop.display)
            virBufferEscapeString(buf, " display='%s'",
                                  def->data.desktop.display);

        if (def->data.desktop.fullscreen)
            virBufferAddLit(buf, " fullscreen='yes'");

        break;

    }

    virBufferAddLit(buf, "/>\n");

    return 0;
}


static int
virDomainHostdevDefFormat(virConnectPtr conn,
                          virBufferPtr buf,
                          virDomainHostdevDefPtr def,
                          int flags)
{
    const char *mode = virDomainHostdevModeTypeToString(def->mode);
    const char *type;

    if (!mode || def->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unexpected hostdev mode %d"), def->mode);
        return -1;
    }

    type = virDomainHostdevSubsysTypeToString(def->source.subsys.type);
    if (!type || (def->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB && def->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI) ) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unexpected hostdev type %d"),
                             def->source.subsys.type);
        return -1;
    }

    virBufferVSprintf(buf, "    <hostdev mode='%s' type='%s' managed='%s'>\n",
                      mode, type, def->managed ? "yes" : "no");
    virBufferAddLit(buf, "      <source>\n");

    if (def->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB) {
        if (def->source.subsys.u.usb.vendor) {
            virBufferVSprintf(buf, "        <vendor id='0x%.4x'/>\n",
                              def->source.subsys.u.usb.vendor);
            virBufferVSprintf(buf, "        <product id='0x%.4x'/>\n",
                              def->source.subsys.u.usb.product);
        }
        if (def->source.subsys.u.usb.bus ||
            def->source.subsys.u.usb.device)
            virBufferVSprintf(buf, "        <address bus='%d' device='%d'/>\n",
                              def->source.subsys.u.usb.bus,
                              def->source.subsys.u.usb.device);
    } else if (def->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI) {
        virBufferVSprintf(buf, "        <address domain='0x%.4x' bus='0x%.2x' slot='0x%.2x' function='0x%.1x'/>\n",
                          def->source.subsys.u.pci.domain,
                          def->source.subsys.u.pci.bus,
                          def->source.subsys.u.pci.slot,
                          def->source.subsys.u.pci.function);
    }

    virBufferAddLit(buf, "      </source>\n");

    if (virDomainDeviceInfoFormat(buf, &def->info, flags) < 0)
        return -1;

    virBufferAddLit(buf, "    </hostdev>\n");

    return 0;
}


char *virDomainDefFormat(virConnectPtr conn,
                         virDomainDefPtr def,
                         int flags)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    unsigned char *uuid;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    const char *type = NULL;
    int n, allones = 1;

    if (!(type = virDomainVirtTypeToString(def->virtType))) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                         _("unexpected domain type %d"), def->virtType);
        goto cleanup;
    }

    if (def->id == -1)
        flags |= VIR_DOMAIN_XML_INACTIVE;

    if (!(flags & VIR_DOMAIN_XML_INACTIVE))
        virBufferVSprintf(&buf, "<domain type='%s' id='%d'>\n", type, def->id);
    else
        virBufferVSprintf(&buf, "<domain type='%s'>\n", type);

    virBufferEscapeString(&buf, "  <name>%s</name>\n", def->name);

    uuid = def->uuid;
    virUUIDFormat(uuid, uuidstr);
    virBufferVSprintf(&buf, "  <uuid>%s</uuid>\n", uuidstr);

    if (def->description)
        virBufferEscapeString(&buf, "  <description>%s</description>\n",
                              def->description);

    virBufferVSprintf(&buf, "  <memory>%lu</memory>\n", def->maxmem);
    virBufferVSprintf(&buf, "  <currentMemory>%lu</currentMemory>\n",
                      def->memory);
    if (def->hugepage_backed) {
        virBufferAddLit(&buf, "  <memoryBacking>\n");
        virBufferAddLit(&buf, "    <hugepages/>\n");
        virBufferAddLit(&buf, "  </memoryBacking>\n");
    }
    for (n = 0 ; n < def->cpumasklen ; n++)
        if (def->cpumask[n] != 1)
            allones = 0;

    if (allones) {
        virBufferVSprintf(&buf, "  <vcpu>%lu</vcpu>\n", def->vcpus);
    } else {
        char *cpumask = NULL;
        if ((cpumask =
             virDomainCpuSetFormat(conn, def->cpumask, def->cpumasklen)) == NULL)
            goto cleanup;
        virBufferVSprintf(&buf, "  <vcpu cpuset='%s'>%lu</vcpu>\n",
                          cpumask, def->vcpus);
        VIR_FREE(cpumask);
    }

    if (def->os.bootloader) {
        virBufferEscapeString(&buf, "  <bootloader>%s</bootloader>\n",
                              def->os.bootloader);
        if (def->os.bootloaderArgs)
            virBufferEscapeString(&buf, "  <bootloader_args>%s</bootloader_args>\n",
                                  def->os.bootloaderArgs);
    }
    virBufferAddLit(&buf, "  <os>\n");

    virBufferAddLit(&buf, "    <type");
    if (def->os.arch)
        virBufferVSprintf(&buf, " arch='%s'", def->os.arch);
    if (def->os.machine)
        virBufferVSprintf(&buf, " machine='%s'", def->os.machine);
    /*
     * HACK: For xen driver we previously used bogus 'linux' as the
     * os type for paravirt, whereas capabilities declare it to
     * be 'xen'. So we convert to the former for backcompat
     */
    if (def->virtType == VIR_DOMAIN_VIRT_XEN &&
        STREQ(def->os.type, "xen"))
        virBufferVSprintf(&buf, ">%s</type>\n", "linux");
    else
        virBufferVSprintf(&buf, ">%s</type>\n", def->os.type);

    if (def->os.init)
        virBufferEscapeString(&buf, "    <init>%s</init>\n",
                              def->os.init);
    if (def->os.loader)
        virBufferEscapeString(&buf, "    <loader>%s</loader>\n",
                              def->os.loader);
    if (def->os.kernel)
        virBufferEscapeString(&buf, "    <kernel>%s</kernel>\n",
                              def->os.kernel);
    if (def->os.initrd)
        virBufferEscapeString(&buf, "    <initrd>%s</initrd>\n",
                              def->os.initrd);
    if (def->os.cmdline)
        virBufferEscapeString(&buf, "    <cmdline>%s</cmdline>\n",
                              def->os.cmdline);
    if (def->os.root)
        virBufferEscapeString(&buf, "    <root>%s</root>\n",
                              def->os.root);

    if (!def->os.bootloader) {
        for (n = 0 ; n < def->os.nBootDevs ; n++) {
            const char *boottype =
                virDomainBootTypeToString(def->os.bootDevs[n]);
            if (!boottype) {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                     _("unexpected boot device type %d"),
                                     def->os.bootDevs[n]);
                goto cleanup;
            }
            virBufferVSprintf(&buf, "    <boot dev='%s'/>\n", boottype);
        }
    }

    virBufferAddLit(&buf, "  </os>\n");

    if (def->features) {
        int i;
        virBufferAddLit(&buf, "  <features>\n");
        for (i = 0 ; i < VIR_DOMAIN_FEATURE_LAST ; i++) {
            if (def->features & (1 << i)) {
                const char *name = virDomainFeatureTypeToString(i);
                if (!name) {
                    virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                         _("unexpected feature %d"), i);
                    goto cleanup;
                }
                virBufferVSprintf(&buf, "    <%s/>\n", name);
            }
        }
        virBufferAddLit(&buf, "  </features>\n");
    }

    if (virCPUDefFormatBuf(conn, &buf, def->cpu, "  ", 0) < 0)
        goto cleanup;

    virBufferVSprintf(&buf, "  <clock offset='%s'/>\n",
                      def->localtime ? "localtime" : "utc");

    if (virDomainLifecycleDefFormat(conn, &buf, def->onPoweroff,
                                    "on_poweroff") < 0)
        goto cleanup;
    if (virDomainLifecycleDefFormat(conn, &buf, def->onReboot,
                                    "on_reboot") < 0)
        goto cleanup;
    if (virDomainLifecycleDefFormat(conn, &buf, def->onCrash,
                                    "on_crash") < 0)
        goto cleanup;

    virBufferAddLit(&buf, "  <devices>\n");

    if (def->emulator)
        virBufferEscapeString(&buf, "    <emulator>%s</emulator>\n",
                              def->emulator);

    for (n = 0 ; n < def->ndisks ; n++)
        if (virDomainDiskDefFormat(conn, &buf, def->disks[n], flags) < 0)
            goto cleanup;

    for (n = 0 ; n < def->ncontrollers ; n++)
        if (virDomainControllerDefFormat(conn, &buf, def->controllers[n], flags) < 0)
            goto cleanup;

    for (n = 0 ; n < def->nfss ; n++)
        if (virDomainFSDefFormat(conn, &buf, def->fss[n], flags) < 0)
            goto cleanup;


    for (n = 0 ; n < def->nnets ; n++)
        if (virDomainNetDefFormat(conn, &buf, def->nets[n], flags) < 0)
            goto cleanup;

    for (n = 0 ; n < def->nserials ; n++)
        if (virDomainChrDefFormat(conn, &buf, def->serials[n], flags) < 0)
            goto cleanup;

    for (n = 0 ; n < def->nparallels ; n++)
        if (virDomainChrDefFormat(conn, &buf, def->parallels[n], flags) < 0)
            goto cleanup;

    /* If there's a PV console that's preferred.. */
    if (def->console) {
        if (virDomainChrDefFormat(conn, &buf, def->console, flags) < 0)
            goto cleanup;
    } else if (def->nserials != 0) {
        /* ..else for legacy compat duplicate the first serial device as a
         * console */
        virDomainChrDef console;
        memcpy(&console, def->serials[0], sizeof(console));
        console.targetType = VIR_DOMAIN_CHR_TARGET_TYPE_CONSOLE;
        if (virDomainChrDefFormat(conn, &buf, &console, flags) < 0)
            goto cleanup;
    }

    for (n = 0 ; n < def->nchannels ; n++)
        if (virDomainChrDefFormat(conn, &buf, def->channels[n], flags) < 0)
            goto cleanup;

    for (n = 0 ; n < def->ninputs ; n++)
        if (def->inputs[n]->bus == VIR_DOMAIN_INPUT_BUS_USB &&
            virDomainInputDefFormat(conn, &buf, def->inputs[n], flags) < 0)
            goto cleanup;

    if (def->ngraphics > 0) {
        /* If graphics is enabled, add the implicit mouse */
        virDomainInputDef autoInput = {
            VIR_DOMAIN_INPUT_TYPE_MOUSE,
            STREQ(def->os.type, "hvm") ?
            VIR_DOMAIN_INPUT_BUS_PS2 : VIR_DOMAIN_INPUT_BUS_XEN,
            { .alias = NULL },
        };

        if (virDomainInputDefFormat(conn, &buf, &autoInput, flags) < 0)
            goto cleanup;

        for (n = 0 ; n < def->ngraphics ; n++)
            if (virDomainGraphicsDefFormat(conn, &buf, def->graphics[n], flags) < 0)
                goto cleanup;
    }

    for (n = 0 ; n < def->nsounds ; n++)
        if (virDomainSoundDefFormat(conn, &buf, def->sounds[n], flags) < 0)
            goto cleanup;

    for (n = 0 ; n < def->nvideos ; n++)
        if (virDomainVideoDefFormat(conn, &buf, def->videos[n], flags) < 0)
            goto cleanup;

    for (n = 0 ; n < def->nhostdevs ; n++)
        if (virDomainHostdevDefFormat(conn, &buf, def->hostdevs[n], flags) < 0)
            goto cleanup;

    if (def->watchdog)
        virDomainWatchdogDefFormat (conn, &buf, def->watchdog, flags);

    virBufferAddLit(&buf, "  </devices>\n");

    if (def->seclabel.model) {
        const char *sectype = virDomainSeclabelTypeToString(def->seclabel.type);
        if (!sectype)
            goto cleanup;
        if (!def->seclabel.label ||
            (def->seclabel.type == VIR_DOMAIN_SECLABEL_DYNAMIC &&
             (flags & VIR_DOMAIN_XML_INACTIVE))) {
            virBufferVSprintf(&buf, "  <seclabel type='%s' model='%s'/>\n",
                              sectype, def->seclabel.model);
        } else {
            virBufferVSprintf(&buf, "  <seclabel type='%s' model='%s'>\n",
                                  sectype, def->seclabel.model);
            virBufferEscapeString(&buf, "    <label>%s</label>\n",
                                  def->seclabel.label);
            if (def->seclabel.imagelabel &&
                def->seclabel.type == VIR_DOMAIN_SECLABEL_DYNAMIC)
                virBufferEscapeString(&buf, "    <imagelabel>%s</imagelabel>\n",
                                      def->seclabel.imagelabel);
            virBufferAddLit(&buf, "  </seclabel>\n");
        }
    }

    virBufferAddLit(&buf, "</domain>\n");

    if (virBufferError(&buf))
        goto no_memory;

    return virBufferContentAndReset(&buf);

 no_memory:
    virReportOOMError(conn);
 cleanup:
    virBufferFreeAndReset(&buf);
    return NULL;
}

char *virDomainObjFormat(virConnectPtr conn,
                         virCapsPtr caps,
                         virDomainObjPtr obj,
                         int flags)
{
    char *config_xml = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferVSprintf(&buf, "<domstatus state='%s' pid='%d'>\n",
                      virDomainStateTypeToString(obj->state),
                      obj->pid);

    if (caps->privateDataXMLFormat &&
        ((caps->privateDataXMLFormat)(&buf, obj->privateData)) < 0)
        goto error;

    if (!(config_xml = virDomainDefFormat(conn,
                                          obj->def,
                                          flags)))
        goto error;

    virBufferAdd(&buf, config_xml, strlen(config_xml));
    VIR_FREE(config_xml);
    virBufferAddLit(&buf, "</domstatus>\n");

    if (virBufferError(&buf))
        goto no_memory;

    return virBufferContentAndReset(&buf);

no_memory:
    virReportOOMError(conn);
error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


#ifndef PROXY

int virDomainSaveXML(virConnectPtr conn,
                     const char *configDir,
                     virDomainDefPtr def,
                     const char *xml)
{
    char *configFile = NULL;
    int fd = -1, ret = -1;
    size_t towrite;

    if ((configFile = virDomainConfigFile(conn, configDir, def->name)) == NULL)
        goto cleanup;

    if (virFileMakePath(configDir)) {
        virReportSystemError(conn, errno,
                             _("cannot create config directory '%s'"),
                             configDir);
        goto cleanup;
    }

    if ((fd = open(configFile,
                   O_WRONLY | O_CREAT | O_TRUNC,
                   S_IRUSR | S_IWUSR )) < 0) {
        virReportSystemError(conn, errno,
                             _("cannot create config file '%s'"),
                             configFile);
        goto cleanup;
    }

    towrite = strlen(xml);
    if (safewrite(fd, xml, towrite) < 0) {
        virReportSystemError(conn, errno,
                             _("cannot write config file '%s'"),
                             configFile);
        goto cleanup;
    }

    if (close(fd) < 0) {
        virReportSystemError(conn, errno,
                             _("cannot save config file '%s'"),
                             configFile);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    if (fd != -1)
        close(fd);
    VIR_FREE(configFile);
    return ret;
}

int virDomainSaveConfig(virConnectPtr conn,
                        const char *configDir,
                        virDomainDefPtr def)
{
    int ret = -1;
    char *xml;

    if (!(xml = virDomainDefFormat(conn,
                                   def,
                                   VIR_DOMAIN_XML_SECURE)))
        goto cleanup;

    if (virDomainSaveXML(conn, configDir, def, xml))
        goto cleanup;

    ret = 0;
cleanup:
    VIR_FREE(xml);
    return ret;
}

int virDomainSaveStatus(virConnectPtr conn,
                        virCapsPtr caps,
                        const char *statusDir,
                        virDomainObjPtr obj)
{
    int flags = VIR_DOMAIN_XML_SECURE|VIR_DOMAIN_XML_INTERNAL_STATUS;
    int ret = -1;
    char *xml;

    if (!(xml = virDomainObjFormat(conn, caps, obj, flags)))
        goto cleanup;

    if (virDomainSaveXML(conn, statusDir, obj->def, xml))
        goto cleanup;

    ret = 0;
cleanup:
    VIR_FREE(xml);
    return ret;
}


virDomainObjPtr virDomainLoadConfig(virConnectPtr conn,
                                    virCapsPtr caps,
                                    virDomainObjListPtr doms,
                                    const char *configDir,
                                    const char *autostartDir,
                                    const char *name,
                                    virDomainLoadConfigNotify notify,
                                    void *opaque)
{
    char *configFile = NULL, *autostartLink = NULL;
    virDomainDefPtr def = NULL;
    virDomainObjPtr dom;
    int autostart;
    int newVM = 1;

    if ((configFile = virDomainConfigFile(conn, configDir, name)) == NULL)
        goto error;
    if ((autostartLink = virDomainConfigFile(conn, autostartDir, name)) == NULL)
        goto error;

    if ((autostart = virFileLinkPointsTo(autostartLink, configFile)) < 0)
        goto error;

    if (!(def = virDomainDefParseFile(conn, caps, configFile,
                                      VIR_DOMAIN_XML_INACTIVE)))
        goto error;

    if ((dom = virDomainFindByName(doms, def->name))) {
        virDomainObjUnlock(dom);
        dom = NULL;
        newVM = 0;
    }

    if (!(dom = virDomainAssignDef(conn, caps, doms, def)))
        goto error;

    dom->autostart = autostart;

    if (notify)
        (*notify)(dom, newVM, opaque);

    VIR_FREE(configFile);
    VIR_FREE(autostartLink);
    return dom;

error:
    VIR_FREE(configFile);
    VIR_FREE(autostartLink);
    virDomainDefFree(def);
    return NULL;
}

static virDomainObjPtr virDomainLoadStatus(virConnectPtr conn,
                                           virCapsPtr caps,
                                           virDomainObjListPtr doms,
                                           const char *statusDir,
                                           const char *name,
                                           virDomainLoadConfigNotify notify,
                                           void *opaque)
{
    char *statusFile = NULL;
    virDomainObjPtr obj = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if ((statusFile = virDomainConfigFile(conn, statusDir, name)) == NULL)
        goto error;

    if (!(obj = virDomainObjParseFile(conn, caps, statusFile)))
        goto error;

    virUUIDFormat(obj->def->uuid, uuidstr);

    if (virHashLookup(doms->objs, uuidstr) != NULL) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unexpected domain %s already exists"),
                             obj->def->name);
        goto error;
    }

    if (virHashAddEntry(doms->objs, uuidstr, obj) < 0) {
        virReportOOMError(conn);
        goto error;
    }

    if (notify)
        (*notify)(obj, 1, opaque);

    VIR_FREE(statusFile);
    return obj;

error:
    if (obj)
        virDomainObjUnref(obj);
    VIR_FREE(statusFile);
    return NULL;
}

int virDomainLoadAllConfigs(virConnectPtr conn,
                            virCapsPtr caps,
                            virDomainObjListPtr doms,
                            const char *configDir,
                            const char *autostartDir,
                            int liveStatus,
                            virDomainLoadConfigNotify notify,
                            void *opaque)
{
    DIR *dir;
    struct dirent *entry;

    VIR_INFO("Scanning for configs in %s", configDir);

    if (!(dir = opendir(configDir))) {
        if (errno == ENOENT)
            return 0;
        virReportSystemError(conn, errno,
                             _("Failed to open dir '%s'"),
                             configDir);
        return -1;
    }

    while ((entry = readdir(dir))) {
        virDomainObjPtr dom;

        if (entry->d_name[0] == '.')
            continue;

        if (!virFileStripSuffix(entry->d_name, ".xml"))
            continue;

        /* NB: ignoring errors, so one malformed config doesn't
           kill the whole process */
        VIR_INFO("Loading config file '%s.xml'", entry->d_name);
        if (liveStatus)
            dom = virDomainLoadStatus(conn,
                                      caps,
                                      doms,
                                      configDir,
                                      entry->d_name,
                                      notify,
                                      opaque);
        else
            dom = virDomainLoadConfig(conn,
                                      caps,
                                      doms,
                                      configDir,
                                      autostartDir,
                                      entry->d_name,
                                      notify,
                                      opaque);
        if (dom) {
            virDomainObjUnlock(dom);
            if (!liveStatus)
                dom->persistent = 1;
        }
    }

    closedir(dir);

    return 0;
}

int virDomainDeleteConfig(virConnectPtr conn,
                          const char *configDir,
                          const char *autostartDir,
                          virDomainObjPtr dom)
{
    char *configFile = NULL, *autostartLink = NULL;
    int ret = -1;

    if ((configFile = virDomainConfigFile(conn, configDir, dom->def->name)) == NULL)
        goto cleanup;
    if ((autostartLink = virDomainConfigFile(conn, autostartDir, dom->def->name)) == NULL)
        goto cleanup;

    /* Not fatal if this doesn't work */
    unlink(autostartLink);

    if (unlink(configFile) < 0 &&
        errno != ENOENT) {
        virReportSystemError(conn, errno,
                             _("cannot remove config %s"),
                             configFile);
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FREE(configFile);
    VIR_FREE(autostartLink);
    return ret;
}

char *virDomainConfigFile(virConnectPtr conn,
                          const char *dir,
                          const char *name)
{
    char *ret = NULL;

    if (virAsprintf(&ret, "%s/%s.xml", dir, name) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    return ret;
}

/* Translates a device name of the form (regex) "[fhv]d[a-z]+" into
 * the corresponding bus,index combination (e.g. sda => (0,0), sdi (1,1),
 *                                               hdd => (1,1), vdaa => (0,26))
 * @param disk The disk device
 * @param busIdx parsed bus number
 * @param devIdx parsed device number
 * @return 0 on success, -1 on failure
 */
int virDiskNameToBusDeviceIndex(const virDomainDiskDefPtr disk,
                                int *busIdx,
                                int *devIdx) {

    int idx = virDiskNameToIndex(disk->dst);
    if (idx < 0)
        return -1;

    switch (disk->bus) {
        case VIR_DOMAIN_DISK_BUS_IDE:
            *busIdx = idx / 2;
            *devIdx = idx % 2;
            break;
        case VIR_DOMAIN_DISK_BUS_SCSI:
            *busIdx = idx / 7;
            *devIdx = idx % 7;
            break;
        case VIR_DOMAIN_DISK_BUS_FDC:
        case VIR_DOMAIN_DISK_BUS_USB:
        case VIR_DOMAIN_DISK_BUS_VIRTIO:
        case VIR_DOMAIN_DISK_BUS_XEN:
        default:
            *busIdx = 0;
            *devIdx = idx;
            break;
    }

    return 0;
}

virDomainFSDefPtr virDomainGetRootFilesystem(virDomainDefPtr def)
{
    int i;

    for (i = 0 ; i < def->nfss ; i++) {
        if (def->fss[i]->type != VIR_DOMAIN_FS_TYPE_MOUNT)
            continue;

        if (STREQ(def->fss[i]->dst, "/"))
            return def->fss[i];
    }

    return NULL;
}

/*
 * virDomainObjIsDuplicate:
 * @doms : virDomainObjListPtr to search
 * @def  : virDomainDefPtr definition of domain to lookup
 * @check_active: If true, ensure that domain is not active
 *
 * Returns: -1 on error
 *          0 if domain is new
 *          1 if domain is a duplicate
 */
int
virDomainObjIsDuplicate(virDomainObjListPtr doms,
                        virDomainDefPtr def,
                        unsigned int check_active)
{
    int ret = -1;
    int dupVM = 0;
    virDomainObjPtr vm = NULL;

    /* See if a VM with matching UUID already exists */
    vm = virDomainFindByUUID(doms, def->uuid);
    if (vm) {
        /* UUID matches, but if names don't match, refuse it */
        if (STRNEQ(vm->def->name, def->name)) {
            char uuidstr[VIR_UUID_STRING_BUFLEN];
            virUUIDFormat(vm->def->uuid, uuidstr);
            virDomainReportError(NULL, VIR_ERR_OPERATION_FAILED,
                            _("domain '%s' is already defined with uuid %s"),
                            vm->def->name, uuidstr);
            goto cleanup;
        }

        if (check_active) {
            /* UUID & name match, but if VM is already active, refuse it */
            if (virDomainObjIsActive(vm)) {
                virDomainReportError(NULL, VIR_ERR_OPERATION_INVALID,
                                     _("domain is already active as '%s'"),
                                     vm->def->name);
                goto cleanup;
            }
        }

        dupVM = 1;
    } else {
        /* UUID does not match, but if a name matches, refuse it */
        vm = virDomainFindByName(doms, def->name);
        if (vm) {
            char uuidstr[VIR_UUID_STRING_BUFLEN];
            virUUIDFormat(vm->def->uuid, uuidstr);
            virDomainReportError(NULL, VIR_ERR_OPERATION_FAILED,
                                 _("domain '%s' already exists with uuid %s"),
                                 def->name, uuidstr);
            goto cleanup;
        }
    }

    ret = dupVM;
cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}


void virDomainObjLock(virDomainObjPtr obj)
{
    virMutexLock(&obj->lock);
}

void virDomainObjUnlock(virDomainObjPtr obj)
{
    virMutexUnlock(&obj->lock);
}


static void virDomainObjListCountActive(void *payload, const char *name ATTRIBUTE_UNUSED, void *data)
{
    virDomainObjPtr obj = payload;
    int *count = data;
    virDomainObjLock(obj);
    if (virDomainObjIsActive(obj))
        (*count)++;
    virDomainObjUnlock(obj);
}

static void virDomainObjListCountInactive(void *payload, const char *name ATTRIBUTE_UNUSED, void *data)
{
    virDomainObjPtr obj = payload;
    int *count = data;
    virDomainObjLock(obj);
    if (!virDomainObjIsActive(obj))
        (*count)++;
    virDomainObjUnlock(obj);
}

int virDomainObjListNumOfDomains(virDomainObjListPtr doms, int active)
{
    int count = 0;
    if (active)
        virHashForEach(doms->objs, virDomainObjListCountActive, &count);
    else
        virHashForEach(doms->objs, virDomainObjListCountInactive, &count);
    return count;
}

struct virDomainIDData {
    int numids;
    int maxids;
    int *ids;
};

static void virDomainObjListCopyActiveIDs(void *payload, const char *name ATTRIBUTE_UNUSED, void *opaque)
{
    virDomainObjPtr obj = payload;
    struct virDomainIDData *data = opaque;
    virDomainObjLock(obj);
    if (virDomainObjIsActive(obj) && data->numids < data->maxids)
        data->ids[data->numids++] = obj->def->id;
    virDomainObjUnlock(obj);
}

int virDomainObjListGetActiveIDs(virDomainObjListPtr doms,
                                 int *ids,
                                 int maxids)
{
    struct virDomainIDData data = { 0, maxids, ids };
    virHashForEach(doms->objs, virDomainObjListCopyActiveIDs, &data);
    return data.numids;
}

struct virDomainNameData {
    int oom;
    int numnames;
    int maxnames;
    char **const names;
};

static void virDomainObjListCopyInactiveNames(void *payload, const char *name ATTRIBUTE_UNUSED, void *opaque)
{
    virDomainObjPtr obj = payload;
    struct virDomainNameData *data = opaque;

    if (data->oom)
        return;

    virDomainObjLock(obj);
    if (!virDomainObjIsActive(obj) && data->numnames < data->maxnames) {
        if (!(data->names[data->numnames] = strdup(obj->def->name)))
            data->oom = 1;
        else
            data->numnames++;
    }
    virDomainObjUnlock(obj);
}


int virDomainObjListGetInactiveNames(virDomainObjListPtr doms,
                                     char **const names,
                                     int maxnames)
{
    struct virDomainNameData data = { 0, 0, maxnames, names };
    int i;
    virHashForEach(doms->objs, virDomainObjListCopyInactiveNames, &data);
    if (data.oom) {
        virReportOOMError(NULL);
        goto cleanup;
    }

    return data.numnames;

cleanup:
    for (i = 0 ; i < data.numnames ; i++)
        VIR_FREE(data.names[i]);
    return -1;
}

#endif /* ! PROXY */
