/*
 * domain_conf.c: domain XML processing
 *
 * Copyright (C) 2006-2008 Red Hat, Inc.
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

#include "internal.h"

#include "domain_conf.h"
#include "memory.h"
#include "verify.h"
#include "xml.h"
#include "uuid.h"
#include "util.h"
#include "buf.h"
#include "c-ctype.h"

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
              "usb")

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
              "pcspk");

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

static void virDomainReportError(virConnectPtr conn,
                                 int code, const char *fmt, ...)
  ATTRIBUTE_FORMAT(printf, 3, 4);

static void virDomainReportError(virConnectPtr conn,
                                 int code, const char *fmt, ...)
{
    va_list args;
    char errorMessage[1024];
    const char *virerr;

    if (fmt) {
        va_start(args, fmt);
        vsnprintf(errorMessage, sizeof(errorMessage)-1, fmt, args);
        va_end(args);
    } else {
        errorMessage[0] = '\0';
    }

    virerr = __virErrorMsg(code, (errorMessage[0] ? errorMessage : NULL));
    __virRaiseError(conn, NULL, NULL, VIR_FROM_DOMAIN, code, VIR_ERR_ERROR,
                    virerr, errorMessage, NULL, -1, -1, virerr, errorMessage);
}


virDomainObjPtr virDomainFindByID(const virDomainObjPtr doms,
                                  int id)
{
    virDomainObjPtr dom = doms;
    while (dom) {
        if (virDomainIsActive(dom) && dom->def->id == id)
            return dom;
        dom = dom->next;
    }

    return NULL;
}


virDomainObjPtr virDomainFindByUUID(const virDomainObjPtr doms,
                                    const unsigned char *uuid)
{
    virDomainObjPtr dom = doms;

    while (dom) {
        if (!memcmp(dom->def->uuid, uuid, VIR_UUID_BUFLEN))
            return dom;
        dom = dom->next;
    }

    return NULL;
}

virDomainObjPtr virDomainFindByName(const virDomainObjPtr doms,
                                    const char *name)
{
    virDomainObjPtr dom = doms;

    while (dom) {
        if (STREQ(dom->def->name, name))
            return dom;
        dom = dom->next;
    }

    return NULL;
}

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

    virDomainInputDefFree(def->next);
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

    virDomainDiskDefFree(def->next);
    VIR_FREE(def);
}

void virDomainFSDefFree(virDomainFSDefPtr def)
{
    if (!def)
        return;

    VIR_FREE(def->src);
    VIR_FREE(def->dst);

    virDomainFSDefFree(def->next);
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
        break;
    }

    VIR_FREE(def->ifname);
    virDomainNetDefFree(def->next);
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

    virDomainChrDefFree(def->next);
    VIR_FREE(def);
}

void virDomainSoundDefFree(virDomainSoundDefPtr def)
{
    if (!def)
        return;

    virDomainSoundDefFree(def->next);
    VIR_FREE(def);
}

void virDomainHostdevDefFree(virDomainHostdevDefPtr def)
{
    if (!def)
        return;

    VIR_FREE(def->target);
    virDomainHostdevDefFree(def->next);
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

void virDomainDefFree(virDomainDefPtr def)
{
    if (!def)
        return;

    virDomainGraphicsDefFree(def->graphics);
    virDomainInputDefFree(def->inputs);
    virDomainDiskDefFree(def->disks);
    virDomainFSDefFree(def->fss);
    virDomainNetDefFree(def->nets);
    virDomainChrDefFree(def->serials);
    virDomainChrDefFree(def->parallels);
    virDomainChrDefFree(def->console);
    virDomainSoundDefFree(def->sounds);
    virDomainHostdevDefFree(def->hostdevs);

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

    VIR_FREE(def);
}

void virDomainObjFree(virDomainObjPtr dom)
{
    if (!dom)
        return;

    virDomainDefFree(dom->def);
    virDomainDefFree(dom->newDef);

    VIR_FREE(dom->vcpupids);

    VIR_FREE(dom);
}

virDomainObjPtr virDomainAssignDef(virConnectPtr conn,
                                   virDomainObjPtr *doms,
                                   const virDomainDefPtr def)
{
    virDomainObjPtr domain;

    if ((domain = virDomainFindByName(*doms, def->name))) {
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
        virDomainReportError(conn, VIR_ERR_NO_MEMORY, NULL);
        return NULL;
    }

    domain->state = VIR_DOMAIN_SHUTOFF;
    domain->def = def;
    domain->next = *doms;

    *doms = domain;

    return domain;
}

void virDomainRemoveInactive(virDomainObjPtr *doms,
                             virDomainObjPtr dom)
{
    virDomainObjPtr prev = NULL;
    virDomainObjPtr curr = *doms;

    while (curr &&
           curr != dom) {
        prev = curr;
        curr = curr->next;
    }

    if (curr) {
        if (prev)
            prev->next = curr->next;
        else
            *doms = curr->next;
    }

    virDomainObjFree(dom);
}

#ifndef PROXY
int virDomainDiskCompare(virDomainDiskDefPtr a,
                         virDomainDiskDefPtr b) {
    if (a->bus == b->bus)
        return virDiskNameToIndex(a->dst) - virDiskNameToIndex(b->dst);
    else
        return a->bus - b->bus;
}


/* Parse the XML definition for a disk
 * @param node XML nodeset to parse for disk definition
 */
static virDomainDiskDefPtr
virDomainDiskDefParseXML(virConnectPtr conn,
                         xmlNodePtr node) {
    virDomainDiskDefPtr def;
    xmlNodePtr cur;
    char *type = NULL;
    char *device = NULL;
    char *driverName = NULL;
    char *driverType = NULL;
    char *source = NULL;
    char *target = NULL;
    char *bus = NULL;

    if (VIR_ALLOC(def) < 0) {
        virDomainReportError(conn, VIR_ERR_NO_MEMORY, NULL);
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
        !STRPREFIX((const char *)target, "xvd")) {
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
                       xmlNodePtr node) {
    virDomainFSDefPtr def;
    xmlNodePtr cur;
    char *type = NULL;
    char *source = NULL;
    char *target = NULL;

    if (VIR_ALLOC(def) < 0) {
        virDomainReportError(conn, VIR_ERR_NO_MEMORY, NULL);
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


static void virDomainNetRandomMAC(virDomainNetDefPtr def) {
    /* XXX there different vendor prefixes per hypervisor */
    def->mac[0] = 0x52;
    def->mac[1] = 0x54;
    def->mac[2] = 0x00;
    def->mac[3] = 1 + (int)(256*(rand()/(RAND_MAX+1.0)));
    def->mac[4] = 1 + (int)(256*(rand()/(RAND_MAX+1.0)));
    def->mac[5] = 1 + (int)(256*(rand()/(RAND_MAX+1.0)));
}


/* Parse the XML definition for a network interface
 * @param node XML nodeset to parse for net definition
 * @return 0 on success, -1 on failure
 */
virDomainNetDefPtr
virDomainNetDefParseXML(virConnectPtr conn,
                        xmlNodePtr node) {
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
        virDomainReportError(conn, VIR_ERR_NO_MEMORY, NULL);
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
                       (def->type == VIR_DOMAIN_NET_TYPE_ETHERNET) &&
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
                       (def->type == VIR_DOMAIN_NET_TYPE_ETHERNET) &&
                       xmlStrEqual(cur->name, BAD_CAST "script")) {
                script = virXMLPropString(cur, "path");
            } else if (xmlStrEqual (cur->name, BAD_CAST "model")) {
                model = virXMLPropString(cur, "type");
            }
        }
        cur = cur->next;
    }

    if (macaddr) {
        unsigned int mac[6];
        sscanf((const char *)macaddr, "%02x:%02x:%02x:%02x:%02x:%02x",
               (unsigned int*)&mac[0],
               (unsigned int*)&mac[1],
               (unsigned int*)&mac[2],
               (unsigned int*)&mac[3],
               (unsigned int*)&mac[4],
               (unsigned int*)&mac[5]);
        def->mac[0] = mac[0];
        def->mac[1] = mac[1];
        def->mac[2] = mac[2];
        def->mac[3] = mac[3];
        def->mac[4] = mac[4];
        def->mac[5] = mac[5];
    } else {
        virDomainNetRandomMAC(def);
    }

    switch (def->type) {
    case VIR_DOMAIN_NET_TYPE_NETWORK:
        if (network == NULL) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("No <source> 'network' attribute specified with <interface type='network'/>"));
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
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("No <source> 'dev' attribute specified with <interface type='bridge'/>"));
            goto error;
        }
        def->data.bridge.brname = bridge;
        bridge = NULL;
        break;

    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_MCAST:
        if (port == NULL) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("No <source> 'port' attribute specified with socket interface"));
            goto error;
        }
        if (virStrToLong_i(port, NULL, 10, &def->data.socket.port) < 0) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("Cannot parse <source> 'port' attribute with socket interface"));
            goto error;
        }

        if (address == NULL) {
            if (def->type == VIR_DOMAIN_NET_TYPE_CLIENT ||
                def->type == VIR_DOMAIN_NET_TYPE_MCAST) {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("No <source> 'address' attribute specified with socket interface"));
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
                        xmlNodePtr node) {
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
        virDomainReportError(conn, VIR_ERR_NO_MEMORY, NULL);
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
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("Missing source path attribute for char device"));
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
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                     "%s", _("Missing source host attribute for char device"));
                goto error;
            }
            if (connectService == NULL) {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                     "%s", _("Missing source service attribute for char device"));
                goto error;
            }

            def->data.tcp.host = connectHost;
            connectHost = NULL;
            def->data.tcp.service = connectService;
            connectService = NULL;
            def->data.tcp.listen = 0;
        } else {
            if (bindHost == NULL) {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                     "%s", _("Missing source host attribute for char device"));
                goto error;
            }
            if (bindService == NULL) {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                     "%s", _("Missing source service attribute for char device"));
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
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("Missing source service attribute for char device"));
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
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("Missing source path attribute for char device"));
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
                          xmlNodePtr node) {
    virDomainInputDefPtr def;
    char *type = NULL;
    char *bus = NULL;

    if (VIR_ALLOC(def) < 0) {
        virDomainReportError(conn, VIR_ERR_NO_MEMORY, NULL);
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
                             xmlNodePtr node) {
    virDomainGraphicsDefPtr def;
    char *type = NULL;

    if (VIR_ALLOC(def) < 0) {
        virDomainReportError(conn, VIR_ERR_NO_MEMORY, NULL);
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
                def->data.vnc.port = 0;
                def->data.vnc.autoport = 1;
            }
        } else {
            def->data.vnc.port = 0;
            def->data.vnc.autoport = 1;
        }

        if ((autoport = virXMLPropString(node, "autoport")) != NULL) {
            if (STREQ(autoport, "yes")) {
                def->data.vnc.port = 0;
                def->data.vnc.autoport = 1;
            }
            VIR_FREE(autoport);
        }

        def->data.vnc.listenAddr = virXMLPropString(node, "listen");
        def->data.vnc.passwd = virXMLPropString(node, "passwd");
        def->data.vnc.keymap = virXMLPropString(node, "keymap");
    } else if (def->type == VIR_DOMAIN_GRAPHICS_TYPE_SDL) {
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
                          const xmlNodePtr node) {

    char *model;
    virDomainSoundDefPtr def;

    if (VIR_ALLOC(def) < 0) {
        virDomainReportError(conn, VIR_ERR_NO_MEMORY, NULL);
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
                                     virDomainHostdevDefPtr def) {

    int ret = -1;
    xmlNodePtr cur;

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (xmlStrEqual(cur->name, BAD_CAST "vendor")) {
                char *vendor = virXMLPropString(cur, "id");

                if (vendor) {
                    if (virStrToLong_ui(vendor, NULL, 0,
                                        &def->source.subsys.usb.vendor) < 0) {
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
                                        &def->source.subsys.usb.product) < 0) {
                        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                            _("cannot parse product %s"), product);
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
                                        &def->source.subsys.usb.bus) < 0) {
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
                                        &def->source.subsys.usb.device) < 0)  {
                        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                             _("cannot parse device %s"),
                                             device);
                        VIR_FREE(device);
                        goto out;
                    }
                    VIR_FREE(device);
                } else {
                    virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                         "%s", _("usb address needs device id"));
                    goto out;
                }
            } else {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                     _("unknown usb source type '%s'"), cur->name);
                goto out;
            }
        }
        cur = cur->next;
    }

    if (def->source.subsys.usb.vendor == 0 &&
        def->source.subsys.usb.product != 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
            _("missing vendor"));
        goto out;
    }
    if (def->source.subsys.usb.vendor != 0 &&
        def->source.subsys.usb.product == 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
            _("missing product"));
        goto out;
    }

    ret = 0;
out:
    return ret;
}


static virDomainHostdevDefPtr
virDomainHostdevDefParseXML(virConnectPtr conn,
                            const xmlNodePtr node) {

    xmlNodePtr cur;
    virDomainHostdevDefPtr def;
    char *mode, *type = NULL;

    if (VIR_ALLOC(def) < 0) {
        virDomainReportError(conn, VIR_ERR_NO_MEMORY, NULL);
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

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (xmlStrEqual(cur->name, BAD_CAST "source")) {
                if (def->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
                    def->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB) {
                        if (virDomainHostdevSubsysUsbDefParseXML(conn, cur, def) < 0)
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


virDomainDeviceDefPtr virDomainDeviceDefParse(virConnectPtr conn,
                                              const virDomainDefPtr def,
                                              const char *xmlStr)
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
        virDomainReportError(conn, VIR_ERR_NO_MEMORY, NULL);
        goto error;
    }

    if (xmlStrEqual(node->name, BAD_CAST "disk")) {
        dev->type = VIR_DOMAIN_DEVICE_DISK;
        if (!(dev->data.disk = virDomainDiskDefParseXML(conn, node)))
            goto error;
    } else if (xmlStrEqual(node->name, BAD_CAST "filesystem")) {
        dev->type = VIR_DOMAIN_DEVICE_FS;
        if (!(dev->data.fs = virDomainFSDefParseXML(conn, node)))
            goto error;
    } else if (xmlStrEqual(node->name, BAD_CAST "interface")) {
        dev->type = VIR_DOMAIN_DEVICE_NET;
        if (!(dev->data.net = virDomainNetDefParseXML(conn, node)))
            goto error;
    } else if (xmlStrEqual(node->name, BAD_CAST "input")) {
        dev->type = VIR_DOMAIN_DEVICE_INPUT;
        if (!(dev->data.input = virDomainInputDefParseXML(conn, def->os.type, node)))
            goto error;
    } else if (xmlStrEqual(node->name, BAD_CAST "sound")) {
        dev->type = VIR_DOMAIN_DEVICE_SOUND;
        if (!(dev->data.sound = virDomainSoundDefParseXML(conn, node)))
            goto error;
    } else if (xmlStrEqual(node->name, BAD_CAST "hostdev")) {
        dev->type = VIR_DOMAIN_DEVICE_HOSTDEV;
        if (!(dev->data.hostdev = virDomainHostdevDefParseXML(conn, node)))
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


static virDomainDefPtr virDomainDefParseXML(virConnectPtr conn,
                                            virCapsPtr caps,
                                            xmlXPathContextPtr ctxt)
{
    xmlNodePtr *nodes = NULL, node = NULL;
    char *tmp = NULL;
    int i, n;
    virDomainDefPtr def;

    if (VIR_ALLOC(def) < 0) {
        virDomainReportError(conn, VIR_ERR_NO_MEMORY,
                         "%s", _("failed to allocate space for xmlXPathContext"));
        return NULL;
    }
    def->id = -1;

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
                                 _("Failed to generate UUID: %s"),
                                 strerror(err));
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
            virDomainReportError(conn, VIR_ERR_NO_MEMORY, NULL);
            goto error;
        }
        if (virDomainCpuSetParse(conn, (const char **)&set,
                                 0, def->cpumask,
                                 def->cpumasklen) < 0)
            goto error;
        VIR_FREE(tmp);
    }

    if ((n = virXPathNodeSet(conn, "./features/*", ctxt, &nodes)) > 0) {
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
    }
    VIR_FREE(nodes);

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
                virDomainReportError(conn, VIR_ERR_NO_MEMORY, NULL);
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
            virDomainReportError(conn, VIR_ERR_NO_MEMORY, NULL);
            goto error;
        }
    }

    if (!virCapabilitiesSupportsGuestOSType(caps, def->os.type)) {
        virDomainReportError(conn, VIR_ERR_OS_TYPE,
                             "%s", def->os.type);
        goto error;
    }

    def->os.arch = virXPathString(conn, "string(./os/type[1]/@arch)", ctxt);
    if (!def->os.arch) {
        const char *defaultArch = virCapabilitiesDefaultGuestArch(caps, def->os.type);
        if (defaultArch == NULL) {
            virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("no supported architecture for os type '%s'"),
                                 def->os.type);
            goto error;
        }
        if (!(def->os.arch = strdup(defaultArch))) {
            virDomainReportError(conn, VIR_ERR_NO_MEMORY, NULL);
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
                virDomainReportError(conn, VIR_ERR_NO_MEMORY, NULL);
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
        STREQ(def->os.type, "hvm")) {
        def->os.kernel = virXPathString(conn, "string(./os/kernel[1])", ctxt);
        def->os.initrd = virXPathString(conn, "string(./os/initrd[1])", ctxt);
        def->os.cmdline = virXPathString(conn, "string(./os/cmdline[1])", ctxt);
        def->os.root = virXPathString(conn, "string(./os/root[1])", ctxt);
        def->os.loader = virXPathString(conn, "string(./os/loader[1])", ctxt);

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
    for (i = 0 ; i < n ; i++) {
        virDomainDiskDefPtr disk = virDomainDiskDefParseXML(conn,
                                                            nodes[i]);
        if (!disk)
            goto error;

        /* Maintain list in sorted order according to target device name */
        virDomainDiskDefPtr ptr = def->disks;
        virDomainDiskDefPtr *prev = &(def->disks);
        while (ptr) {
            if (STREQ(disk->dst, ptr->dst)) {
                virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                     _("duplicate disk target '%s'"),
                                     disk->dst);
                goto error;
            }
            if (virDomainDiskCompare(disk, ptr) < 0) {
                disk->next = ptr;
                *prev = disk;
                break;
            }
            prev = &(ptr->next);
            ptr = ptr->next;
        }

        if (!ptr) {
            disk->next = ptr;
            *prev = disk;
        }
    }
    VIR_FREE(nodes);

    /* analysis of the filesystems */
    if ((n = virXPathNodeSet(conn, "./devices/filesystem", ctxt, &nodes)) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("cannot extract filesystem devices"));
        goto error;
    }
    for (i = n - 1 ; i >= 0 ; i--) {
        virDomainFSDefPtr fs = virDomainFSDefParseXML(conn,
                                                      nodes[i]);
        if (!fs)
            goto error;

        fs->next = def->fss;
        def->fss = fs;
    }
    VIR_FREE(nodes);

    /* analysis of the network devices */
    if ((n = virXPathNodeSet(conn, "./devices/interface", ctxt, &nodes)) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("cannot extract network devices"));
        goto error;
    }
    for (i = n - 1 ; i >= 0 ; i--) {
        virDomainNetDefPtr net = virDomainNetDefParseXML(conn,
                                                         nodes[i]);
        if (!net)
            goto error;

        net->next = def->nets;
        def->nets = net;
    }
    VIR_FREE(nodes);


    /* analysis of the character devices */
    if ((n = virXPathNodeSet(conn, "./devices/parallel", ctxt, &nodes)) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("cannot extract parallel devices"));
        goto error;
    }
    for (i = n - 1 ; i >= 0 ; i--) {
        virDomainChrDefPtr chr = virDomainChrDefParseXML(conn,
                                                         nodes[i]);
        if (!chr)
            goto error;

        chr->dstPort = i;
        chr->next = def->parallels;
        def->parallels = chr;
    }
    VIR_FREE(nodes);

    if ((n = virXPathNodeSet(conn, "./devices/serial", ctxt, &nodes)) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("cannot extract serial devices"));
        goto error;
    }
    for (i = n - 1 ; i >= 0 ; i--) {
        virDomainChrDefPtr chr = virDomainChrDefParseXML(conn,
                                                         nodes[i]);
        if (!chr)
            goto error;

        chr->dstPort = i;
        chr->next = def->serials;
        def->serials = chr;
    }
    VIR_FREE(nodes);

    /*
     * If no serial devices were listed, then look for console
     * devices which is the legacy syntax for the same thing
     */
    if (def->serials == NULL) {
        if ((node = virXPathNode(conn, "./devices/console[1]", ctxt)) != NULL) {
            virDomainChrDefPtr chr = virDomainChrDefParseXML(conn,
                                                             node);
            if (!chr)
                goto error;

            chr->dstPort = 0;
            /*
             * For HVM console actually created a serial device
             * while for non-HVM it was a parvirt console
             */
            if (STREQ(def->os.type, "hvm")) {
                chr->next = def->serials;
                def->serials = chr;
            } else {
                def->console = chr;
            }
        }
    }


    /* analysis of the input devices */
    if ((n = virXPathNodeSet(conn, "./devices/input", ctxt, &nodes)) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("cannot extract input devices"));
        goto error;
    }
    for (i = n - 1 ; i >= 0 ; i--) {
        virDomainInputDefPtr input = virDomainInputDefParseXML(conn,
                                                               def->os.type,
                                                               nodes[i]);
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

        input->next = def->inputs;
        def->inputs = input;
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
                                                                        nodes[0]);
        if (!graphics)
            goto error;

        def->graphics = graphics;
    }
    VIR_FREE(nodes);

    /* If graphics are enabled, there's an implicit PS2 mouse */
    if (def->graphics != NULL) {
        virDomainInputDefPtr input;

        if (VIR_ALLOC(input) < 0) {
            virDomainReportError(conn, VIR_ERR_NO_MEMORY, NULL);
            goto error;
        }
        if (STREQ(def->os.type, "hvm")) {
            input->type = VIR_DOMAIN_INPUT_TYPE_MOUSE;
            input->bus = VIR_DOMAIN_INPUT_BUS_PS2;
        } else {
            input->type = VIR_DOMAIN_INPUT_TYPE_MOUSE;
            input->bus = VIR_DOMAIN_INPUT_BUS_XEN;
        }
        input->next = def->inputs;
        def->inputs = input;
    }


    /* analysis of the sound devices */
    if ((n = virXPathNodeSet(conn, "./devices/sound", ctxt, &nodes)) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("cannot extract sound devices"));
        goto error;
    }
    for (i = n - 1 ; i >= 0 ; i--) {
        int collision = 0;
        virDomainSoundDefPtr check;
        virDomainSoundDefPtr sound = virDomainSoundDefParseXML(conn,
                                                               nodes[i]);
        if (!sound)
            goto error;

        /* Verify there's no duplicated sound card */
        check = def->sounds;
        while (check) {
            if (check->model == sound->model)
                collision = 1;
            check = check->next;
        }
        if (collision) {
            virDomainSoundDefFree(sound);
            continue;
        }

        sound->next = def->sounds;
        def->sounds = sound;
    }
    VIR_FREE(nodes);

    /* analysis of the host devices */
    if ((n = virXPathNodeSet(conn, "./devices/hostdev", ctxt, &nodes)) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             "%s", _("cannot extract host devices"));
        goto error;
    }
    for (i = 0 ; i < n ; i++) {
        virDomainHostdevDefPtr hostdev = virDomainHostdevDefParseXML(conn, nodes[i]);
        if (!hostdev)
            goto error;

        hostdev->next = def->hostdevs;
        def->hostdevs = hostdev;
    }
    VIR_FREE(nodes);

    return def;

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

        if (conn &&
            conn->err.code == VIR_ERR_NONE &&
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
                                        const char *xmlStr)
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
        if (conn && conn->err.code == VIR_ERR_NONE)
              virDomainReportError(conn, VIR_ERR_XML_ERROR,
                                   _("failed to parse xml document"));
        goto cleanup;
    }

    if ((root = xmlDocGetRootElement(xml)) == NULL) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("missing root element"));
        goto cleanup;
    }

    def = virDomainDefParseNode(conn, caps, xml, root);

cleanup:
    xmlFreeParserCtxt (pctxt);
    xmlFreeDoc (xml);
    return def;
}

virDomainDefPtr virDomainDefParseFile(virConnectPtr conn,
                                      virCapsPtr caps,
                                      const char *filename)
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
        if (conn && conn->err.code == VIR_ERR_NONE)
              virDomainReportError(conn, VIR_ERR_XML_ERROR,
                                   _("failed to parse xml document"));
        goto cleanup;
    }

    if ((root = xmlDocGetRootElement(xml)) == NULL) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("missing root element"));
        goto cleanup;
    }

    def = virDomainDefParseNode(conn, caps, xml, root);

cleanup:
    xmlFreeParserCtxt (pctxt);
    xmlFreeDoc (xml);
    return def;
}


virDomainDefPtr virDomainDefParseNode(virConnectPtr conn,
                                      virCapsPtr caps,
                                      xmlDocPtr xml,
                                      xmlNodePtr root)
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
        virDomainReportError(conn, VIR_ERR_NO_MEMORY, NULL);
        goto cleanup;
    }

    ctxt->node = root;
    def = virDomainDefParseXML(conn, caps, ctxt);

cleanup:
    xmlXPathFreeContext(ctxt);
    return def;
}
#endif /* ! PROXY */

/************************************************************************
 *									*
 * Parser and converter for the CPUset strings used in libvirt		*
 *									*
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
        virDomainReportError(conn, VIR_ERR_NO_MEMORY, NULL);
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

    virBufferVSprintf(buf,
                      "    <disk type='%s' device='%s'>\n",
                      type, device);

    if (def->driverName) {
        if (def->driverType)
            virBufferVSprintf(buf,
                              "      <driver name='%s' type='%s'/>\n",
                              def->driverName, def->driverType);
        else
            virBufferVSprintf(buf,
                              "      <driver name='%s'/>\n",
                              def->driverName);
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
    if (!type || def->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("unexpected hostdev type %d"),
                             def->source.subsys.type);
        return -1;
    }

    virBufferVSprintf(buf, "    <hostdev mode='%s' type='%s'>\n", mode, type);
    virBufferAddLit(buf, "      <source>\n");

    if (def->source.subsys.usb.vendor) {
        virBufferVSprintf(buf, "        <vendor id='0x%.4x'/>\n",
                          def->source.subsys.usb.vendor);
        virBufferVSprintf(buf, "        <product id='0x%.4x'/>\n",
                          def->source.subsys.usb.product);
    } else {
        virBufferVSprintf(buf, "        <address bus='%d' device='%d'/>\n",
                          def->source.subsys.usb.bus,
                          def->source.subsys.usb.device);
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
    virDomainDiskDefPtr disk;
    virDomainFSDefPtr fs;
    virDomainNetDefPtr net;
    virDomainSoundDefPtr sound;
    virDomainInputDefPtr input;
    virDomainChrDefPtr chr;
    virDomainHostdevDefPtr hostdev;
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

    disk = def->disks;
    while (disk) {
        if (virDomainDiskDefFormat(conn, &buf, disk) < 0)
            goto cleanup;
        disk = disk->next;
    }

    fs = def->fss;
    while (fs) {
        if (virDomainFSDefFormat(conn, &buf, fs) < 0)
            goto cleanup;
        fs = fs->next;
    }

    net = def->nets;
    while (net) {
        if (virDomainNetDefFormat(conn, &buf, net) < 0)
            goto cleanup;
        net = net->next;
    }


    chr = def->serials;
    while (chr) {
        if (virDomainChrDefFormat(conn, &buf, chr, "serial") < 0)
            goto cleanup;
        chr = chr->next;
    }

    chr = def->parallels;
    while (chr) {
        if (virDomainChrDefFormat(conn, &buf, chr, "parallel") < 0)
            goto cleanup;
        chr = chr->next;
    }

    /* If there's a PV console that's preferred.. */
    if (def->console) {
        if (virDomainChrDefFormat(conn, &buf, def->console, "console") < 0)
            goto cleanup;
    } else if (def->serials != NULL) {
        /* ..else for legacy compat duplicate the serial device as a console */
        if (virDomainChrDefFormat(conn, &buf, def->serials, "console") < 0)
            goto cleanup;
    }

    input = def->inputs;
    while (input) {
        if (input->bus == VIR_DOMAIN_INPUT_BUS_USB &&
            virDomainInputDefFormat(conn, &buf, input) < 0)
            goto cleanup;
        input = input->next;
    }

    if (def->graphics) {
        /* If graphics is enabled, add the implicit mouse */
        virDomainInputDef autoInput = {
            VIR_DOMAIN_INPUT_TYPE_MOUSE,
            STREQ(def->os.type, "hvm") ?
            VIR_DOMAIN_INPUT_BUS_PS2 : VIR_DOMAIN_INPUT_BUS_XEN,
            NULL };

        if (virDomainInputDefFormat(conn, &buf, &autoInput) < 0)
            goto cleanup;

        if (virDomainGraphicsDefFormat(conn, &buf, def, def->graphics, flags) < 0)
            goto cleanup;
    }

    sound = def->sounds;
    while(sound) {
        if (virDomainSoundDefFormat(conn, &buf, sound) < 0)
            goto cleanup;
        sound = sound->next;
    }

    hostdev = def->hostdevs;
    while (hostdev) {
        if (virDomainHostdevDefFormat(conn, &buf, hostdev) < 0)
            goto cleanup;
        hostdev = hostdev->next;
    }

    virBufferAddLit(&buf, "  </devices>\n");
    virBufferAddLit(&buf, "</domain>\n");

    if (virBufferError(&buf))
        goto no_memory;

    return virBufferContentAndReset(&buf);

 no_memory:
    virDomainReportError(conn, VIR_ERR_NO_MEMORY, NULL);
 cleanup:
    tmp = virBufferContentAndReset(&buf);
    VIR_FREE(tmp);
    return NULL;
}


#ifndef PROXY

int virDomainSaveConfig(virConnectPtr conn,
                        const char *configDir,
                        virDomainDefPtr def)
{
    char *xml;
    char *configFile = NULL;
    int fd = -1, ret = -1;
    size_t towrite;
    int err;

    if ((configFile = virDomainConfigFile(conn, configDir, def->name)) == NULL)
        goto cleanup;

    if (!(xml = virDomainDefFormat(conn,
                                   def,
                                   VIR_DOMAIN_XML_SECURE)))
        goto cleanup;

    if ((err = virFileMakePath(configDir))) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("cannot create config directory %s: %s"),
                             configDir, strerror(err));
        goto cleanup;
    }

    if ((fd = open(configFile,
                   O_WRONLY | O_CREAT | O_TRUNC,
                   S_IRUSR | S_IWUSR )) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("cannot create config file %s: %s"),
                             configFile, strerror(errno));
        goto cleanup;
    }

    towrite = strlen(xml);
    if (safewrite(fd, xml, towrite) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("cannot write config file %s: %s"),
                             configFile, strerror(errno));
        goto cleanup;
    }

    if (close(fd) < 0) {
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("cannot save config file %s: %s"),
                             configFile, strerror(errno));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(xml);
    if (fd != -1)
        close(fd);

    return ret;
}


virDomainObjPtr virDomainLoadConfig(virConnectPtr conn,
                                    virCapsPtr caps,
                                    virDomainObjPtr *doms,
                                    const char *configDir,
                                    const char *autostartDir,
                                    const char *name)
{
    char *configFile = NULL, *autostartLink = NULL;
    virDomainDefPtr def = NULL;
    virDomainObjPtr dom;
    int autostart;

    if ((configFile = virDomainConfigFile(conn, configDir, name)) == NULL)
        goto error;
    if ((autostartLink = virDomainConfigFile(conn, autostartDir, name)) == NULL)
        goto error;


    if ((autostart = virFileLinkPointsTo(autostartLink, configFile)) < 0)
        goto error;

    if (!(def = virDomainDefParseFile(conn, caps, configFile)))
        goto error;

    if (!(dom = virDomainAssignDef(conn, doms, def)))
        goto error;

    dom->state = VIR_DOMAIN_SHUTOFF;
    dom->autostart = autostart;

    return dom;

error:
    VIR_FREE(configFile);
    VIR_FREE(autostartLink);
    virDomainDefFree(def);
    return NULL;
}

int virDomainLoadAllConfigs(virConnectPtr conn,
                            virCapsPtr caps,
                            virDomainObjPtr *doms,
                            const char *configDir,
                            const char *autostartDir)
{
    DIR *dir;
    struct dirent *entry;

    if (!(dir = opendir(configDir))) {
        if (errno == ENOENT)
            return 0;
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("Failed to open dir '%s': %s"),
                              configDir, strerror(errno));
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
                                  entry->d_name);
        if (dom)
            dom->persistent = 1;
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
        virDomainReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("cannot remove config for %s: %s"),
                             dom->def->name, strerror(errno));
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

    if (asprintf(&ret, "%s/%s.xml", dir, name) < 0) {
        virDomainReportError(conn, VIR_ERR_NO_MEMORY, NULL);
        return NULL;
    }

    return ret;
}

/* Translates a device name of the form (regex) "[fhv]d[a-z]+" into
 * the corresponding bus,index combination (e.g. sda => (0,0), sdi (1,1),
 *                                               hdd => (1,1), vdaa => (0,27))
 * @param disk The disk device
 * @param busIdx parsed bus number
 * @param devIdx parsed device number
 * @return 0 on success, -1 on failure
 */
int virDiskNameToBusDeviceIndex(virDomainDiskDefPtr disk,
                                int *busIdx,
                                int *devIdx) {

    int idx = virDiskNameToIndex(disk->dst);
    if (idx < 1)
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


#endif /* ! PROXY */
