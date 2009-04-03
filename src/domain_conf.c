/*
 * domain_conf.c: domain XML processing
 *
 * Copyright (C) 2006-2009 Red Hat, Inc.
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
              "hyperv")

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
              "hostdev")

VIR_ENUM_IMPL(virDomainDisk, VIR_DOMAIN_DISK_TYPE_LAST,
              "block",
              "file")

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
              "uml")

VIR_ENUM_IMPL(virDomainDiskCache, VIR_DOMAIN_DISK_CACHE_LAST,
              "default",
              "none",
              "writethrough",
              "writeback")

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
              "bridge")

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

VIR_ENUM_IMPL(virDomainInput, VIR_DOMAIN_INPUT_TYPE_LAST,
              "mouse",
              "tablet")

VIR_ENUM_IMPL(virDomainInputBus, VIR_DOMAIN_INPUT_BUS_LAST,
              "ps2",
              "usb",
              "xen")

VIR_ENUM_IMPL(virDomainGraphics, VIR_DOMAIN_GRAPHICS_TYPE_LAST,
              "sdl",
              "vnc")

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

virDomainObjPtr virDomainFindByID(const virDomainObjListPtr doms,
                                  int id)
{
    unsigned int i;

    for (i = 0 ; i < doms->count ; i++) {
        virDomainObjLock(doms->objs[i]);
        if (virDomainIsActive(doms->objs[i]) &&
            doms->objs[i]->def->id == id)
            return doms->objs[i];
        virDomainObjUnlock(doms->objs[i]);
    }

    return NULL;
}


virDomainObjPtr virDomainFindByUUID(const virDomainObjListPtr doms,
                                    const unsigned char *uuid)
{
    unsigned int i;

    for (i = 0 ; i < doms->count ; i++) {
        virDomainObjLock(doms->objs[i]);
        if (!memcmp(doms->objs[i]->def->uuid, uuid, VIR_UUID_BUFLEN))
            return doms->objs[i];
        virDomainObjUnlock(doms->objs[i]);
    }

    return NULL;
}

virDomainObjPtr virDomainFindByName(const virDomainObjListPtr doms,
                                    const char *name)
{
    unsigned int i;

    for (i = 0 ; i < doms->count ; i++) {
        virDomainObjLock(doms->objs[i]);
        if (STREQ(doms->objs[i]->def->name, name))
            return doms->objs[i];
        virDomainObjUnlock(doms->objs[i]);
    }

    return NULL;
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
    }

    VIR_FREE(def);
}

void virDomainInputDefFree(virDomainInputDefPtr def)
{
    if (!def)
        return;

    VIR_FREE(def);
}

void virDomainDiskDefFree(virDomainDiskDefPtr def)
{
    if (!def)
        return;

    VIR_FREE(def->src);
    VIR_FREE(def->dst);
    VIR_FREE(def->driverName);
    VIR_FREE(def->driverType);

    VIR_FREE(def);
}

void virDomainFSDefFree(virDomainFSDefPtr def)
{
    if (!def)
        return;

    VIR_FREE(def->src);
    VIR_FREE(def->dst);

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
    }

    VIR_FREE(def->ifname);
    VIR_FREE(def);
}

void virDomainChrDefFree(virDomainChrDefPtr def)
{
    if (!def)
        return;

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

    VIR_FREE(def);
}

void virDomainSoundDefFree(virDomainSoundDefPtr def)
{
    if (!def)
        return;

    VIR_FREE(def);
}

void virDomainHostdevDefFree(virDomainHostdevDefPtr def)
{
    if (!def)
        return;

    VIR_FREE(def->target);
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
    case VIR_DOMAIN_DEVICE_HOSTDEV:
        virDomainHostdevDefFree(def->data.hostdev);
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

    virDomainGraphicsDefFree(def->graphics);

    for (i = 0 ; i < def->ninputs ; i++)
        virDomainInputDefFree(def->inputs[i]);
    VIR_FREE(def->inputs);

    for (i = 0 ; i < def->ndisks ; i++)
        virDomainDiskDefFree(def->disks[i]);
    VIR_FREE(def->disks);

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

    virDomainChrDefFree(def->console);

    for (i = 0 ; i < def->nsounds ; i++)
        virDomainSoundDefFree(def->sounds[i]);
    VIR_FREE(def->sounds);

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

    virSecurityLabelDefFree(def);

    VIR_FREE(def);
}

#ifndef PROXY

void virDomainObjFree(virDomainObjPtr dom)
{
    if (!dom)
        return;

    virDomainDefFree(dom->def);
    virDomainDefFree(dom->newDef);

    VIR_FREE(dom->monitorpath);
    VIR_FREE(dom->vcpupids);

    virMutexDestroy(&dom->lock);

    VIR_FREE(dom);
}

void virDomainObjListFree(virDomainObjListPtr vms)
{
    unsigned int i;

    for (i = 0 ; i < vms->count ; i++)
        virDomainObjFree(vms->objs[i]);

    VIR_FREE(vms->objs);
    vms->count = 0;
}

virDomainObjPtr virDomainAssignDef(virConnectPtr conn,
                                   virDomainObjListPtr doms,
                                   const virDomainDefPtr def)
{
    virDomainObjPtr domain;

    if ((domain = virDomainFindByName(doms, def->name))) {
        if (!virDomainIsActive(domain)) {
            virDomainDefFree(domain->def);
            domain->def = def;
        } else {
            if (domain->newDef)
                virDomainDefFree(domain->newDef);
            domain->newDef = def;
        }

        return domain;
    }

    if (VIR_ALLOC(domain) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    if (virMutexInit(&domain->lock) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("cannot initialize mutex"));
        VIR_FREE(domain);
        return NULL;
    }

    virDomainObjLock(domain);
    domain->state = VIR_DOMAIN_SHUTOFF;
    domain->def = def;
    domain->monitorWatch = -1;
    domain->monitor = -1;

    if (VIR_REALLOC_N(doms->objs, doms->count + 1) < 0) {
        virReportOOMError(conn);
        VIR_FREE(domain);
        return NULL;
    }

    doms->objs[doms->count] = domain;
    doms->count++;

    return domain;
}

void virDomainRemoveInactive(virDomainObjListPtr doms,
                             virDomainObjPtr dom)
{
    unsigned int i;

    virDomainObjUnlock(dom);

    for (i = 0 ; i < doms->count ; i++) {
        virDomainObjLock(doms->objs[i]);
        if (doms->objs[i] == dom) {
            virDomainObjUnlock(doms->objs[i]);
            virDomainObjFree(doms->objs[i]);

            if (i < (doms->count - 1))
                memmove(doms->objs + i, doms->objs + i + 1,
                        sizeof(*(doms->objs)) * (doms->count - (i + 1)));

            if (VIR_REALLOC_N(doms->objs, doms->count - 1) < 0) {
                ; /* Failure to reduce memory allocation isn't fatal */
            }
            doms->count--;

            break;
        }
        virDomainObjUnlock(doms->objs[i]);
    }

}
#endif /* ! PROXY */


int virDomainDiskCompare(virDomainDiskDefPtr a,
                         virDomainDiskDefPtr b) {
    if (a->bus == b->bus)
        return virDiskNameToIndex(a->dst) - virDiskNameToIndex(b->dst);
    else
        return a->bus - b->bus;
}


#ifndef PROXY
/* Parse the XML definition for a disk
 * @param node XML nodeset to parse for disk definition
 */
static virDomainDiskDefPtr
virDomainDiskDefParseXML(virConnectPtr conn,
                         xmlNodePtr node,
                         int flags ATTRIBUTE_UNUSED) {
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

                if (def->type == VIR_DOMAIN_DISK_TYPE_FILE)
                    source = virXMLPropString(cur, "file");
                else
                    source = virXMLPropString(cur, "dev");

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

    def->src = source;
    source = NULL;
    def->dst = target;
    target = NULL;
    def->driverName = driverName;
    driverName = NULL;
    def->driverType = driverType;
    driverType = NULL;

cleanup:
    VIR_FREE(bus);
    VIR_FREE(type);
    VIR_FREE(target);
    VIR_FREE(source);
    VIR_FREE(device);
    VIR_FREE(driverType);
    VIR_FREE(driverName);
    VIR_FREE(cachetag);

    return def;

 error:
    virDomainDiskDefFree(def);
    def = NULL;
    goto cleanup;
}


/* Parse the XML definition for a disk
 * @param node XML nodeset to parse for disk definition
 */
static virDomainFSDefPtr
virDomainFSDefParseXML(virConnectPtr conn,
                       xmlNodePtr node,
                       int flags ATTRIBUTE_UNUSED) {
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
                if (STRPREFIX((const char*)ifname, "vnet")) {
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
            }
        }
        cur = cur->next;
    }

    if (macaddr) {
        virParseMacAddr((const char *)macaddr, def->mac);
    } else {
        virCapabilitiesGenerateMac(caps, def->mac);
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
    _("No <source> 'dev' attribute specified with <interface type='bridge'/>"));
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
                        int flags ATTRIBUTE_UNUSED) {
    xmlNodePtr cur;
    char *type = NULL;
    char *bindHost = NULL;
    char *bindService = NULL;
    char *connectHost = NULL;
    char *connectService = NULL;
    char *path = NULL;
    char *mode = NULL;
    char *protocol = NULL;
    virDomainChrDefPtr def;

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    def->type = VIR_DOMAIN_CHR_TYPE_PTY;
    type = virXMLPropString(node, "type");
    if (type != NULL) {
        if (STREQ(type, "null"))
            def->type = VIR_DOMAIN_CHR_TYPE_NULL;
        else if (STREQ(type, "vc"))
            def->type = VIR_DOMAIN_CHR_TYPE_VC;
        else if (STREQ(type, "pty"))
            def->type = VIR_DOMAIN_CHR_TYPE_PTY;
        else if (STREQ(type, "dev"))
            def->type = VIR_DOMAIN_CHR_TYPE_DEV;
        else if (STREQ(type, "file"))
            def->type = VIR_DOMAIN_CHR_TYPE_FILE;
        else if (STREQ(type, "pipe"))
            def->type = VIR_DOMAIN_CHR_TYPE_PIPE;
        else if (STREQ(type, "stdio"))
            def->type = VIR_DOMAIN_CHR_TYPE_STDIO;
        else if (STREQ(type, "udp"))
            def->type = VIR_DOMAIN_CHR_TYPE_UDP;
        else if (STREQ(type, "tcp"))
            def->type = VIR_DOMAIN_CHR_TYPE_TCP;
        else if (STREQ(type, "unix"))
            def->type = VIR_DOMAIN_CHR_TYPE_UNIX;
        else
            def->type = VIR_DOMAIN_CHR_TYPE_NULL;
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
                    } else {
                        if (bindHost == NULL)
                            bindHost = virXMLPropString(cur, "host");
                        if (bindService == NULL)
                            bindService = virXMLPropString(cur, "service");
                    }

                    if (def->type == VIR_DOMAIN_CHR_TYPE_UDP)
                        VIR_FREE(mode);
                }
            } else if (xmlStrEqual(cur->name, BAD_CAST "protocol")) {
                if (protocol == NULL)
                    protocol = virXMLPropString(cur, "type");
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
        if (protocol != NULL &&
            STREQ(protocol, "telnet"))
            def->data.tcp.protocol = VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET;
        else
            def->data.tcp.protocol = VIR_DOMAIN_CHR_TCP_PROTOCOL_RAW;
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

cleanup:
    VIR_FREE(mode);
    VIR_FREE(protocol);
    VIR_FREE(type);
    VIR_FREE(bindHost);
    VIR_FREE(bindService);
    VIR_FREE(connectHost);
    VIR_FREE(connectService);
    VIR_FREE(path);

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
                          int flags ATTRIBUTE_UNUSED) {
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
                          int flags ATTRIBUTE_UNUSED) {

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

cleanup:
    VIR_FREE(model);

    return def;

error:
    virDomainSoundDefFree(def);
    def = NULL;
    goto cleanup;
}

static int
virDomainHostdevSubsysUsbDefParseXML(virConnectPtr conn,
                                     const xmlNodePtr node,
                                     virDomainHostdevDefPtr def,
                                     int flags ATTRIBUTE_UNUSED) {

    int ret = -1;
    xmlNodePtr cur;

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (xmlStrEqual(cur->name, BAD_CAST "vendor")) {
                char *vendor = virXMLPropString(cur, "id");

                if (vendor) {
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

    if (def->source.subsys.u.usb.vendor == 0 &&
        def->source.subsys.u.usb.product != 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
            "%s", _("missing vendor"));
        goto out;
    }
    if (def->source.subsys.u.usb.vendor != 0 &&
        def->source.subsys.u.usb.product == 0) {
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
                                     virDomainHostdevDefPtr def) {

    int ret = -1;
    xmlNodePtr cur;

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (xmlStrEqual(cur->name, BAD_CAST "address")) {

                char *domain = virXMLPropString(cur, "domain");
                if (domain) {
                    if (virStrToLong_ui(domain, NULL, 0,
                                    &def->source.subsys.u.pci.domain) < 0) {
                        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                             _("cannot parse domain %s"),
                                             domain);
                        VIR_FREE(domain);
                        goto out;
                    }
                    VIR_FREE(domain);
                }

                char *bus = virXMLPropString(cur, "bus");
                if (bus) {
                    if (virStrToLong_ui(bus, NULL, 0,
                                        &def->source.subsys.u.pci.bus) < 0) {
                        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                             _("cannot parse bus %s"), bus);
                        VIR_FREE(bus);
                        goto out;
                    }
                    VIR_FREE(bus);
                } else {
                    virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                         "%s", _("pci address needs bus id"));
                    goto out;
                }

                char *slot = virXMLPropString(cur, "slot");
                if (slot) {
                    if (virStrToLong_ui(slot, NULL, 0,
                                        &def->source.subsys.u.pci.slot) < 0)  {
                        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                             _("cannot parse slot %s"),
                                             slot);
                        VIR_FREE(slot);
                        goto out;
                    }
                    VIR_FREE(slot);
                } else {
                    virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                         "%s", _("pci address needs slot id"));
                    goto out;
                }

                char *function = virXMLPropString(cur, "function");
                if (function) {
                    if (virStrToLong_ui(function, NULL, 0,
                                    &def->source.subsys.u.pci.function) < 0)  {
                        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                             _("cannot parse function %s"),
                                             function);
                        VIR_FREE(function);
                        goto out;
                    }
                    VIR_FREE(function);
                } else {
                    virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                                         _("pci address needs function id"));
                    goto out;
                }
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
                        if (virDomainHostdevSubsysPciDefParseXML(conn, cur, def) < 0)
                            goto error;
                }
            } else {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                     _("unknown node %s"), cur->name);
            }
        }
        cur = cur->next;
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
                             _("invalid security type"));
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
                                 _("security label is missing"));
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
                                 _("security imagelabel is missing"));
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
    } else if (xmlStrEqual(node->name, BAD_CAST "hostdev")) {
        dev->type = VIR_DOMAIN_DEVICE_HOSTDEV;
        if (!(dev->data.hostdev = virDomainHostdevDefParseXML(conn, node, flags)))
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

int virDomainDiskQSort(const void *a, const void *b)
{
    const virDomainDiskDefPtr *da = a;
    const virDomainDiskDefPtr *db = b;

    return virDomainDiskCompare(*da, *db);
}

#ifndef PROXY
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
        if((virXPathLong(conn, "string(./@id)", ctxt, &id)) < 0)
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
        int err;
        if ((err = virUUIDGenerate(def->uuid))) {
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

    /* Extract domain memory */
    if (virXPathULong(conn, "string(./memory[1])", ctxt, &def->maxmem) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("missing memory element"));
        goto error;
    }

    if (virXPathULong(conn, "string(./currentMemory[1])", ctxt, &def->memory) < 0)
        def->memory = def->maxmem;

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
                                                                        def->os.arch);
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
    qsort(def->disks, def->ndisks, sizeof(*def->disks),
          virDomainDiskQSort);
    VIR_FREE(nodes);

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

        chr->dstPort = i;
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

        chr->dstPort = i;
        def->serials[def->nserials++] = chr;
    }
    VIR_FREE(nodes);

    if ((node = virXPathNode(conn, "./devices/console[1]", ctxt)) != NULL) {
        virDomainChrDefPtr chr = virDomainChrDefParseXML(conn,
                                                         node,
                                                         flags);
        if (!chr)
            goto error;

        chr->dstPort = 0;
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
            }
        } else {
            def->console = chr;
        }
    }


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
    if (n > 0) {
        virDomainGraphicsDefPtr graphics = virDomainGraphicsDefParseXML(conn,
                                                                        nodes[0],
                                                                        flags);
        if (!graphics)
            goto error;

        def->graphics = graphics;
    }
    VIR_FREE(nodes);

    /* If graphics are enabled, there's an implicit PS2 mouse */
    if (def->graphics != NULL) {
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
        int collision = 0, j;
        virDomainSoundDefPtr sound = virDomainSoundDefParseXML(conn,
                                                               nodes[i],
                                                               flags);
        if (!sound)
            goto error;

        /* Verify there's no duplicated sound card */
        for (j = 0 ; j < def->nsounds ; j++) {
            if (def->sounds[j]->model == sound->model)
                collision = 1;
        }
        if (collision) {
            virDomainSoundDefFree(sound);
            continue;
        }

        def->sounds[def->nsounds++] = sound;
    }
    VIR_FREE(nodes);

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

    /* analysis of security label */
    if (virSecurityLabelDefParseXML(conn, def, ctxt, flags) == -1)
        goto error;

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
    virDomainReportError(conn, VIR_ERR_XEN_CALL,
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
                       virDomainDiskDefPtr def)
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
        if (def->type == VIR_DOMAIN_DISK_TYPE_FILE)
            virBufferEscapeString(buf, "      <source file='%s'/>\n",
                                  def->src);
        else
            virBufferEscapeString(buf, "      <source dev='%s'/>\n",
                                  def->src);
    }

    virBufferVSprintf(buf, "      <target dev='%s' bus='%s'/>\n",
                      def->dst, bus);

    if (def->readonly)
        virBufferAddLit(buf, "      <readonly/>\n");
    if (def->shared)
        virBufferAddLit(buf, "      <shareable/>\n");

    virBufferAddLit(buf, "    </disk>\n");

    return 0;
}

static int
virDomainFSDefFormat(virConnectPtr conn,
                     virBufferPtr buf,
                     virDomainFSDefPtr def)
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

    virBufferAddLit(buf, "    </filesystem>\n");

    return 0;
}

static int
virDomainNetDefFormat(virConnectPtr conn,
                      virBufferPtr buf,
                      virDomainNetDefPtr def)
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
    }

    if (def->ifname)
        virBufferEscapeString(buf, "      <target dev='%s'/>\n",
                              def->ifname);
    if (def->model)
        virBufferEscapeString(buf, "      <model type='%s'/>\n",
                              def->model);

    virBufferAddLit(buf, "    </interface>\n");

    return 0;
}


static int
virDomainChrDefFormat(virConnectPtr conn,
                      virBufferPtr buf,
                      virDomainChrDefPtr def,
                      const char *name)
{
    const char *type = virDomainChrTypeToString(def->type);

    if (!type) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unexpected char type %d"), def->type);
        return -1;
    }

    /* Compat with legacy  <console tty='/dev/pts/5'/> syntax */
    virBufferVSprintf(buf, "    <%s type='%s'",
                      name, type);
    if (STREQ(name, "console") &&
        def->type == VIR_DOMAIN_CHR_TYPE_PTY &&
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
            def->data.file.path) {
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

    virBufferVSprintf(buf, "      <target port='%d'/>\n",
                      def->dstPort);

    virBufferVSprintf(buf, "    </%s>\n",
                      name);

    return 0;
}

static int
virDomainSoundDefFormat(virConnectPtr conn,
                        virBufferPtr buf,
                        virDomainSoundDefPtr def)
{
    const char *model = virDomainSoundModelTypeToString(def->model);

    if (!model) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unexpected sound model %d"), def->model);
        return -1;
    }

    virBufferVSprintf(buf, "    <sound model='%s'/>\n",
                      model);

    return 0;
}

static int
virDomainInputDefFormat(virConnectPtr conn,
                        virBufferPtr buf,
                        virDomainInputDefPtr def)
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

    virBufferVSprintf(buf, "    <input type='%s' bus='%s'/>\n",
                      type, bus);

    return 0;
}


static int
virDomainGraphicsDefFormat(virConnectPtr conn,
                           virBufferPtr buf,
                           virDomainDefPtr vm,
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
            (!def->data.vnc.autoport || vm->id != -1))
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
    }

    virBufferAddLit(buf, "/>\n");

    return 0;
}


static int
virDomainHostdevDefFormat(virConnectPtr conn,
                          virBufferPtr buf,
                          virDomainHostdevDefPtr def)
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
        } else {
            virBufferVSprintf(buf, "        <address bus='%d' device='%d'/>\n",
                              def->source.subsys.u.usb.bus,
                              def->source.subsys.u.usb.device);
        }
    }
    if (def->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI) {
        virBufferVSprintf(buf, "        <address domain='0x%.4x' bus='0x%.2x' slot='0x%.2x' function='0x%.1x'/>\n",
                          def->source.subsys.u.pci.domain,
                          def->source.subsys.u.pci.bus,
                          def->source.subsys.u.pci.slot,
                          def->source.subsys.u.pci.function);
    }

    virBufferAddLit(buf, "      </source>\n");
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
    const char *type = NULL, *tmp;
    int n, allones = 1;

    if (!(type = virDomainVirtTypeToString(def->virtType))) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                         _("unexpected domain type %d"), def->virtType);
        goto cleanup;
    }

    if (def->id >= 0)
        virBufferVSprintf(&buf, "<domain type='%s' id='%d'>\n", type, def->id);
    else
        virBufferVSprintf(&buf, "<domain type='%s'>\n", type);

    virBufferEscapeString(&buf, "  <name>%s</name>\n", def->name);

    uuid = def->uuid;
    virUUIDFormat(uuid, uuidstr);
    virBufferVSprintf(&buf, "  <uuid>%s</uuid>\n", uuidstr);

    virBufferVSprintf(&buf, "  <memory>%lu</memory>\n", def->maxmem);
    virBufferVSprintf(&buf, "  <currentMemory>%lu</currentMemory>\n",
                      def->memory);

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
        if (virDomainDiskDefFormat(conn, &buf, def->disks[n]) < 0)
            goto cleanup;

    for (n = 0 ; n < def->nfss ; n++)
        if (virDomainFSDefFormat(conn, &buf, def->fss[n]) < 0)
            goto cleanup;


    for (n = 0 ; n < def->nnets ; n++)
        if (virDomainNetDefFormat(conn, &buf, def->nets[n]) < 0)
            goto cleanup;

    for (n = 0 ; n < def->nserials ; n++)
        if (virDomainChrDefFormat(conn, &buf, def->serials[n], "serial") < 0)
            goto cleanup;

    for (n = 0 ; n < def->nparallels ; n++)
        if (virDomainChrDefFormat(conn, &buf, def->parallels[n], "parallel") < 0)
            goto cleanup;

    /* If there's a PV console that's preferred.. */
    if (def->console) {
        if (virDomainChrDefFormat(conn, &buf, def->console, "console") < 0)
            goto cleanup;
    } else if (def->nserials != 0) {
        /* ..else for legacy compat duplicate the first serial device as a
         * console */
        if (virDomainChrDefFormat(conn, &buf, def->serials[0], "console") < 0)
            goto cleanup;
    }

    for (n = 0 ; n < def->ninputs ; n++)
        if (def->inputs[n]->bus == VIR_DOMAIN_INPUT_BUS_USB &&
            virDomainInputDefFormat(conn, &buf, def->inputs[n]) < 0)
            goto cleanup;

    if (def->graphics) {
        /* If graphics is enabled, add the implicit mouse */
        virDomainInputDef autoInput = {
            VIR_DOMAIN_INPUT_TYPE_MOUSE,
            STREQ(def->os.type, "hvm") ?
            VIR_DOMAIN_INPUT_BUS_PS2 : VIR_DOMAIN_INPUT_BUS_XEN
        };

        if (virDomainInputDefFormat(conn, &buf, &autoInput) < 0)
            goto cleanup;

        if (virDomainGraphicsDefFormat(conn, &buf, def, def->graphics, flags) < 0)
            goto cleanup;
    }

    for (n = 0 ; n < def->nsounds ; n++)
        if (virDomainSoundDefFormat(conn, &buf, def->sounds[n]) < 0)
            goto cleanup;

    for (n = 0 ; n < def->nhostdevs ; n++)
        if (virDomainHostdevDefFormat(conn, &buf, def->hostdevs[n]) < 0)
            goto cleanup;

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
    tmp = virBufferContentAndReset(&buf);
    VIR_FREE(tmp);
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
    int err;

    if ((configFile = virDomainConfigFile(conn, configDir, def->name)) == NULL)
        goto cleanup;

    if ((err = virFileMakePath(configDir))) {
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

    if (!(dom = virDomainAssignDef(conn, doms, def)))
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

int virDomainLoadAllConfigs(virConnectPtr conn,
                            virCapsPtr caps,
                            virDomainObjListPtr doms,
                            const char *configDir,
                            const char *autostartDir,
                            virDomainLoadConfigNotify notify,
                            void *opaque)
{
    DIR *dir;
    struct dirent *entry;

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

const char *virDomainDefDefaultEmulator(virConnectPtr conn,
                                        virDomainDefPtr def,
                                        virCapsPtr caps) {
    const char *type;
    const char *emulator;

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

    return emulator;
}


void virDomainObjLock(virDomainObjPtr obj)
{
    virMutexLock(&obj->lock);
}

void virDomainObjUnlock(virDomainObjPtr obj)
{
    virMutexUnlock(&obj->lock);
}

#endif /* ! PROXY */
