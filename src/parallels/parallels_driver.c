/*
 * parallels_driver.c: core driver functions for managing
 * Parallels Cloud Server hosts
 *
 * Copyright (C) 2014 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#include <config.h>

#include <sys/types.h>
#include <sys/poll.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <paths.h>
#include <pwd.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/statvfs.h>

#include "datatypes.h"
#include "virerror.h"
#include "viralloc.h"
#include "virlog.h"
#include "vircommand.h"
#include "configmake.h"
#include "virfile.h"
#include "virstoragefile.h"
#include "nodeinfo.h"
#include "c-ctype.h"
#include "virstring.h"

#include "parallels_driver.h"
#include "parallels_utils.h"

#define VIR_FROM_THIS VIR_FROM_PARALLELS

VIR_LOG_INIT("parallels.parallels_driver");

#define PRLCTL                      "prlctl"
#define PRLSRVCTL                   "prlsrvctl"

#define parallelsDomNotFoundError(domain)                                \
    do {                                                                 \
        char uuidstr[VIR_UUID_STRING_BUFLEN];                            \
        virUUIDFormat(domain->uuid, uuidstr);                            \
        virReportError(VIR_ERR_NO_DOMAIN,                                \
                       _("no domain with matching uuid '%s'"), uuidstr); \
    } while (0)

#define IS_CT(def)  (STREQ_NULLABLE(def->os.type, "exe"))

static int parallelsConnectClose(virConnectPtr conn);

static const char * parallelsGetDiskBusName(int bus) {
    switch (bus) {
    case VIR_DOMAIN_DISK_BUS_IDE:
        return "ide";
    case VIR_DOMAIN_DISK_BUS_SATA:
        return "sata";
    case VIR_DOMAIN_DISK_BUS_SCSI:
        return "scsi";
    default:
        return NULL;
    }
}

void
parallelsDriverLock(parallelsConnPtr driver)
{
    virMutexLock(&driver->lock);
}

void
parallelsDriverUnlock(parallelsConnPtr driver)
{
    virMutexUnlock(&driver->lock);
}


static void
parallelsDomObjFreePrivate(void *p)
{
    parallelsDomObjPtr pdom = p;

    if (!pdom)
        return;

    VIR_FREE(pdom->uuid);
    VIR_FREE(pdom->home);
    VIR_FREE(p);
};

static virCapsPtr
parallelsBuildCapabilities(void)
{
    virCapsPtr caps;
    virCapsGuestPtr guest;

    if ((caps = virCapabilitiesNew(virArchFromHost(),
                                   0, 0)) == NULL)
        return NULL;

    if (nodeCapsInitNUMA(caps) < 0)
        goto error;

    if ((guest = virCapabilitiesAddGuest(caps, "hvm",
                                         VIR_ARCH_X86_64,
                                         "parallels",
                                         NULL, 0, NULL)) == NULL)
        goto error;

    if (virCapabilitiesAddGuestDomain(guest,
                                      "parallels", NULL, NULL, 0, NULL) == NULL)
        goto error;

    if ((guest = virCapabilitiesAddGuest(caps, "exe",
                                         VIR_ARCH_X86_64,
                                         "parallels",
                                         NULL, 0, NULL)) == NULL)
        goto error;

    if (virCapabilitiesAddGuestDomain(guest,
                                      "parallels", NULL, NULL, 0, NULL) == NULL)
        goto error;

    return caps;

 error:
    virObjectUnref(caps);
    return NULL;
}

static char *
parallelsConnectGetCapabilities(virConnectPtr conn)
{
    parallelsConnPtr privconn = conn->privateData;
    char *xml;

    parallelsDriverLock(privconn);
    if ((xml = virCapabilitiesFormatXML(privconn->caps)) == NULL)
        virReportOOMError();
    parallelsDriverUnlock(privconn);
    return xml;
}

static int
parallelsGetSerialInfo(virDomainChrDefPtr chr,
                       const char *name, virJSONValuePtr value)
{
    const char *tmp;

    chr->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL;
    chr->targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL;
    if (virStrToLong_i(name + strlen("serial"),
                       NULL, 10, &chr->target.port) < 0) {
        parallelsParseError();
        return -1;
    }

    if (virJSONValueObjectHasKey(value, "output")) {
        chr->source.type = VIR_DOMAIN_CHR_TYPE_FILE;

        tmp = virJSONValueObjectGetString(value, "output");
        if (!tmp) {
            parallelsParseError();
            return -1;
        }

        if (VIR_STRDUP(chr->source.data.file.path, tmp) < 0)
            return -1;
    } else if (virJSONValueObjectHasKey(value, "socket")) {
        chr->source.type = VIR_DOMAIN_CHR_TYPE_UNIX;

        tmp = virJSONValueObjectGetString(value, "socket");
        if (!tmp) {
            parallelsParseError();
            return -1;
        }

        if (VIR_STRDUP(chr->source.data.nix.path, tmp) < 0)
            return -1;
        chr->source.data.nix.listen = false;
    } else if (virJSONValueObjectHasKey(value, "real")) {
        chr->source.type = VIR_DOMAIN_CHR_TYPE_DEV;

        tmp = virJSONValueObjectGetString(value, "real");
        if (!tmp) {
            parallelsParseError();
            return -1;
        }

        if (VIR_STRDUP(chr->source.data.file.path, tmp) < 0)
            return -1;
    } else {
        parallelsParseError();
        return -1;
    }

    return 0;
}

static int
parallelsAddSerialInfo(virDomainChrDefPtr **serials, size_t *nserials,
                       const char *key, virJSONValuePtr value)
{
    virDomainChrDefPtr chr = NULL;

    if (!(chr = virDomainChrDefNew()))
        goto cleanup;

    if (parallelsGetSerialInfo(chr, key, value))
        goto cleanup;

    if (VIR_APPEND_ELEMENT(*serials, *nserials, chr) < 0)
        goto cleanup;

    return 0;

 cleanup:
    virDomainChrDefFree(chr);
    return -1;
}

static int
parallelsAddVideoInfo(virDomainDefPtr def, virJSONValuePtr value)
{
    virDomainVideoDefPtr video = NULL;
    virDomainVideoAccelDefPtr accel = NULL;
    const char *tmp;
    char *endptr;
    unsigned long mem;

    if (!(tmp = virJSONValueObjectGetString(value, "size"))) {
        parallelsParseError();
        goto error;
    }

    if (virStrToLong_ul(tmp, &endptr, 10, &mem) < 0) {
        parallelsParseError();
        goto error;
    }

    if (!STREQ(endptr, "Mb")) {
        parallelsParseError();
        goto error;
    }

    if (VIR_ALLOC(video) < 0)
        goto error;

    if (VIR_ALLOC(accel) < 0)
        goto error;

    if (VIR_APPEND_ELEMENT_COPY(def->videos, def->nvideos, video) < 0)
        goto error;

    video->type = VIR_DOMAIN_VIDEO_TYPE_VGA;
    video->vram = mem << 20;
    video->heads = 1;
    video->accel = accel;

    return 0;

 error:
    VIR_FREE(accel);
    virDomainVideoDefFree(video);
    return -1;
}

static int
parallelsGetHddInfo(virDomainDefPtr def,
                    virDomainDiskDefPtr disk,
                    const char *key,
                    virJSONValuePtr value)
{
    const char *tmp;
    unsigned int idx;

    disk->device = VIR_DOMAIN_DISK_DEVICE_DISK;

    if (virJSONValueObjectHasKey(value, "real") == 1) {
        virDomainDiskSetType(disk, VIR_DOMAIN_DISK_TYPE_BLOCK);

        if (!(tmp = virJSONValueObjectGetString(value, "real"))) {
            parallelsParseError();
            return -1;
        }

        if (virDomainDiskSetSource(disk, tmp) < 0)
            return -1;
    } else {
        virDomainDiskSetType(disk, VIR_DOMAIN_DISK_TYPE_FILE);

        if (!(tmp = virJSONValueObjectGetString(value, "image"))) {
            parallelsParseError();
            return -1;
        }

        if (virDomainDiskSetSource(disk, tmp) < 0)
            return -1;
    }

    tmp = virJSONValueObjectGetString(value, "port");
    if (!tmp && !IS_CT(def)) {
        parallelsParseError();
        return -1;
    }

    if (tmp) {
        if (STRPREFIX(tmp, "ide")) {
            disk->bus = VIR_DOMAIN_DISK_BUS_IDE;
        } else if (STRPREFIX(tmp, "sata")) {
            disk->bus = VIR_DOMAIN_DISK_BUS_SATA;
        } else if (STRPREFIX(tmp, "scsi")) {
            disk->bus = VIR_DOMAIN_DISK_BUS_SCSI;
        } else {
            parallelsParseError();
            return -1;
        }

        char *colonp;
        unsigned int pos;

        if (!(colonp = strchr(tmp, ':'))) {
            parallelsParseError();
            return -1;
        }

        if (virStrToLong_ui(colonp + 1, NULL, 10, &pos) < 0) {
            parallelsParseError();
            return -1;
        }

        disk->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE;
        disk->info.addr.drive.target = pos;
    } else {
        /* Actually there are no disk devices in containers, but in
         * in Parallels Cloud Server we mount disk images as container's
         * root fs during start, so it looks like a disk device. */
        disk->bus = VIR_DOMAIN_DISK_BUS_IDE;
    }

    if (virStrToLong_ui(key + strlen("hdd"), NULL, 10, &idx) < 0) {
        parallelsParseError();
        return -1;
    }

    if (!(disk->dst = virIndexToDiskName(idx, "sd")))
        return -1;

    return 0;
}

static int
parallelsAddHddInfo(virDomainDefPtr def, const char *key, virJSONValuePtr value)
{
    virDomainDiskDefPtr disk = NULL;

    if (VIR_ALLOC(disk) < 0)
        goto error;

    if (parallelsGetHddInfo(def, disk, key, value))
        goto error;

    if (VIR_APPEND_ELEMENT(def->disks, def->ndisks, disk) < 0)
        goto error;

    return 0;

 error:
    virDomainDiskDefFree(disk);
    return -1;
}

static inline unsigned char hex2int(char c)
{
    if (c <= '9')
        return c - '0';
    else
        return 10 + c - 'A';
}

/*
 * Parse MAC address in format XXXXXXXXXXXX.
 */
static int
parallelsMacAddrParse(const char *str, virMacAddrPtr addr)
{
    size_t i;

    if (strlen(str) != 12)
        goto error;

    for (i = 0; i < 6; i++) {
        if (!c_isxdigit(str[2 * i]) || !c_isxdigit(str[2 * i + 1]))
            goto error;

        addr->addr[i] = (hex2int(str[2 * i]) << 4) + hex2int(str[2 * i + 1]);
    }

    return 0;
 error:
    virReportError(VIR_ERR_INVALID_ARG,
                   _("Invalid MAC address format '%s'"), str);
    return -1;
}

static int
parallelsGetNetInfo(virDomainNetDefPtr net,
                    const char *key,
                    virJSONValuePtr value)
{
    const char *tmp;

    /* use device name, shown by prlctl as target device
     * for identifying network adapter in virDomainDefineXML */
    if (VIR_STRDUP(net->ifname, key) < 0)
        goto error;

    net->type = VIR_DOMAIN_NET_TYPE_NETWORK;

    if (!(tmp = virJSONValueObjectGetString(value, "mac"))) {
        parallelsParseError();
        return -1;
    }

    if (parallelsMacAddrParse(tmp, &net->mac) < 0) {
        parallelsParseError();
        goto error;
    }


    if (virJSONValueObjectHasKey(value, "network")) {
        if (!(tmp = virJSONValueObjectGetString(value, "network"))) {
            parallelsParseError();
            goto error;
        }

        if (VIR_STRDUP(net->data.network.name, tmp) < 0)
            goto error;
    } else if (virJSONValueObjectHasKey(value, "type")) {
        if (!(tmp = virJSONValueObjectGetString(value, "type"))) {
            parallelsParseError();
            goto error;
        }

        if (!STREQ(tmp, "routed")) {
            parallelsParseError();
            goto error;
        }

        if (VIR_STRDUP(net->data.network.name,
                       PARALLELS_ROUTED_NETWORK_NAME) < 0)
            goto error;
    } else {
        parallelsParseError();
        goto error;
    }

    net->linkstate = VIR_DOMAIN_NET_INTERFACE_LINK_STATE_UP;
    if ((tmp = virJSONValueObjectGetString(value, "state")) &&
        STREQ(tmp, "disconnected")) {
        net->linkstate = VIR_DOMAIN_NET_INTERFACE_LINK_STATE_DOWN;
    }

    return 0;

 error:
    return -1;
}

static int
parallelsAddNetInfo(virDomainDefPtr def, const char *key, virJSONValuePtr value)
{
    virDomainNetDefPtr net = NULL;

    if (VIR_ALLOC(net) < 0)
        goto error;

    if (parallelsGetNetInfo(net, key, value))
        goto error;

    if (VIR_EXPAND_N(def->nets, def->nnets, 1) < 0)
        goto error;

    def->nets[def->nnets - 1] = net;

    return 0;

 error:
    virDomainNetDefFree(net);
    return -1;
}

static int
parallelsAddDomainHardware(virDomainDefPtr def, virJSONValuePtr jobj)
{
    int n;
    size_t i;
    virJSONValuePtr value;
    const char *key;

    n = virJSONValueObjectKeysNumber(jobj);
    if (n < 1)
        goto cleanup;

    for (i = 0; i < n; i++) {
        key = virJSONValueObjectGetKey(jobj, i);
        value = virJSONValueObjectGetValue(jobj, i);

        if (STRPREFIX(key, "serial")) {
            if (parallelsAddSerialInfo(&def->serials,
                                       &def->nserials, key, value))
                goto cleanup;
            if (def->nconsoles == 0) {
                if (parallelsAddSerialInfo(&def->consoles,
                                           &def->nconsoles, key, value))
                    goto cleanup;
            }
        } else if (STREQ(key, "video")) {
            if (parallelsAddVideoInfo(def, value))
                goto cleanup;
        } else if (STRPREFIX(key, "hdd")) {
            if (parallelsAddHddInfo(def, key, value))
                goto cleanup;
        } else if (STRPREFIX(key, "net")) {
            if (parallelsAddNetInfo(def, key, value))
                goto cleanup;
        }
    }

    return 0;

 cleanup:
    return -1;
}

static int
parallelsAddVNCInfo(virDomainDefPtr def, virJSONValuePtr jobj_root)
{
    const char *tmp;
    unsigned int port;
    virJSONValuePtr jobj;
    int ret = -1;
    virDomainGraphicsDefPtr gr = NULL;

    jobj = virJSONValueObjectGet(jobj_root, "Remote display");
    if (!jobj) {
        parallelsParseError();
        goto cleanup;
    }

    tmp = virJSONValueObjectGetString(jobj, "mode");
    if (!tmp) {
        parallelsParseError();
        goto cleanup;
    }

    if (STREQ(tmp, "off")) {
        ret = 0;
        goto cleanup;
    }

    if (VIR_ALLOC(gr) < 0)
        goto cleanup;

    if (STREQ(tmp, "auto")) {
        if (virJSONValueObjectGetNumberUint(jobj, "port", &port) < 0)
            port = 0;
        gr->data.vnc.autoport = true;
    } else {
        if (virJSONValueObjectGetNumberUint(jobj, "port", &port) < 0) {
            parallelsParseError();
            goto cleanup;
        }
        gr->data.vnc.autoport = false;
    }

    gr->type = VIR_DOMAIN_GRAPHICS_TYPE_VNC;
    gr->data.vnc.port = port;
    gr->data.vnc.keymap = NULL;
    gr->data.vnc.socket = NULL;
    gr->data.vnc.auth.passwd = NULL;
    gr->data.vnc.auth.expires = false;
    gr->data.vnc.auth.connected = 0;

    if (!(tmp = virJSONValueObjectGetString(jobj, "address"))) {
        parallelsParseError();
        goto cleanup;
    }

    if (VIR_ALLOC(gr->listens) < 0)
        goto cleanup;

    gr->nListens = 1;

    if (VIR_STRDUP(gr->listens[0].address, tmp) < 0)
        goto cleanup;

    gr->listens[0].type = VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS;

    if (VIR_APPEND_ELEMENT(def->graphics, def->ngraphics, gr) < 0)
        goto cleanup;

    return 0;

 cleanup:
    virDomainGraphicsDefFree(gr);
    return ret;
}

/*
 * Must be called with privconn->lock held
 */
static virDomainObjPtr
parallelsLoadDomain(parallelsConnPtr privconn, virJSONValuePtr jobj)
{
    virDomainObjPtr dom = NULL;
    virDomainDefPtr def = NULL;
    parallelsDomObjPtr pdom = NULL;
    virJSONValuePtr jobj2, jobj3;
    const char *tmp;
    char *endptr;
    unsigned long mem;
    unsigned int x;
    const char *autostart;
    const char *state;

    if (VIR_ALLOC(def) < 0)
        goto cleanup;

    def->virtType = VIR_DOMAIN_VIRT_PARALLELS;
    def->id = -1;

    if (!(tmp = virJSONValueObjectGetString(jobj, "Name"))) {
        parallelsParseError();
        goto cleanup;
    }
    if (VIR_STRDUP(def->name, tmp) < 0)
        goto cleanup;

    if (!(tmp = virJSONValueObjectGetString(jobj, "ID"))) {
        parallelsParseError();
        goto cleanup;
    }

    if (virUUIDParse(tmp, def->uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("UUID in config file malformed"));
        goto cleanup;
    }

    if (!(tmp = virJSONValueObjectGetString(jobj, "Description"))) {
        parallelsParseError();
        goto cleanup;
    }
    if (VIR_STRDUP(def->description, tmp) < 0)
        goto cleanup;

    if (!(jobj2 = virJSONValueObjectGet(jobj, "Hardware"))) {
        parallelsParseError();
        goto cleanup;
    }

    if (!(jobj3 = virJSONValueObjectGet(jobj2, "cpu"))) {
        parallelsParseError();
        goto cleanup;
    }

    if (virJSONValueObjectGetNumberUint(jobj3, "cpus", &x) == 0) {
        def->vcpus = x;
        def->maxvcpus = x;
    } else if ((tmp = virJSONValueObjectGetString(jobj3, "cpus"))) {
        if (STREQ(tmp, "unlimited")) {
            virNodeInfo nodeinfo;

            if (nodeGetInfo(&nodeinfo) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Can't get node info"));
                goto cleanup;
            }

            def->vcpus = nodeinfo.cpus;
            def->maxvcpus = def->vcpus;
        } else {
            parallelsParseError();
            goto cleanup;
        }
    } else {
        parallelsParseError();
        goto cleanup;
    }

    if (!(jobj3 = virJSONValueObjectGet(jobj2, "memory"))) {
        parallelsParseError();
        goto cleanup;
    }

    if (!(tmp = virJSONValueObjectGetString(jobj3, "size"))) {
        parallelsParseError();
        goto cleanup;
    }

    if (virStrToLong_ul(tmp, &endptr, 10, &mem) < 0) {
        parallelsParseError();
        goto cleanup;
    }

    if (!STREQ(endptr, "Mb")) {
        parallelsParseError();
        goto cleanup;
    }

    def->mem.max_balloon = mem;
    def->mem.max_balloon <<= 10;
    def->mem.cur_balloon = def->mem.max_balloon;

    if (!(tmp = virJSONValueObjectGetString(jobj, "Type"))) {
        parallelsParseError();
        goto cleanup;
    }

    if (STREQ(tmp, "CT")) {
        if (VIR_STRDUP(def->os.type, "exe") < 0)
            goto cleanup;
        if (VIR_STRDUP(def->os.init, "/sbin/init") < 0)
            goto cleanup;
    } else if (STREQ(tmp, "VM")) {
        if (VIR_STRDUP(def->os.type, "hvm") < 0)
            goto cleanup;
    }

    def->os.arch = VIR_ARCH_X86_64;

    if (VIR_ALLOC(pdom) < 0)
        goto cleanup;

    if (virJSONValueObjectGetNumberUint(jobj, "EnvID", &x) < 0)
        goto cleanup;
    pdom->id = x;
    if (!(tmp = virJSONValueObjectGetString(jobj, "ID"))) {
        parallelsParseError();
        goto cleanup;
    }
    if (VIR_STRDUP(pdom->uuid, tmp) < 0)
        goto cleanup;

    if (!(tmp = virJSONValueObjectGetString(jobj, "Home"))) {
        parallelsParseError();
        goto cleanup;
    }

    if (VIR_STRDUP(pdom->home, tmp) < 0)
        goto cleanup;

    if (!(state = virJSONValueObjectGetString(jobj, "State"))) {
        parallelsParseError();
        goto cleanup;
    }

    if (!(autostart = virJSONValueObjectGetString(jobj, "Autostart"))) {
        parallelsParseError();
        goto cleanup;
    }

    if (parallelsAddDomainHardware(def, jobj2) < 0)
        goto cleanup;

    if (parallelsAddVNCInfo(def, jobj) < 0)
        goto cleanup;

    if (!(dom = virDomainObjListAdd(privconn->domains, def,
                                    privconn->xmlopt,
                                    0, NULL)))
        goto cleanup;
    /* dom is locked here */

    dom->privateDataFreeFunc = parallelsDomObjFreePrivate;
    dom->privateData = pdom;
    dom->persistent = 1;

    /* TODO: handle all possible states */
    if (STREQ(state, "running")) {
        virDomainObjSetState(dom, VIR_DOMAIN_RUNNING,
                             VIR_DOMAIN_RUNNING_BOOTED);
        def->id = pdom->id;
    }

    if (STREQ(autostart, "on"))
        dom->autostart = 1;
    else
        dom->autostart = 0;

    virObjectUnlock(dom);

    return dom;

 cleanup:
    virDomainDefFree(def);
    parallelsDomObjFreePrivate(pdom);
    return NULL;
}

/*
 * Must be called with privconn->lock held
 *
 * if domain_name is NULL - load information about all
 * registered domains.
 */
static int
parallelsLoadDomains(parallelsConnPtr privconn, const char *domain_name)
{
    int count;
    size_t i;
    virJSONValuePtr jobj;
    virJSONValuePtr jobj2;
    virDomainObjPtr dom = NULL;
    int ret = -1;

    jobj = parallelsParseOutput(PRLCTL, "list", "-j", "-a", "-i", "-H",
                                "--vmtype", "all", domain_name, NULL);
    if (!jobj) {
        parallelsParseError();
        goto cleanup;
    }

    count = virJSONValueArraySize(jobj);
    if (count < 0) {
        parallelsParseError();
        goto cleanup;
    }

    for (i = 0; i < count; i++) {
        jobj2 = virJSONValueArrayGet(jobj, i);
        if (!jobj2) {
            parallelsParseError();
            goto cleanup;
        }

        dom = parallelsLoadDomain(privconn, jobj2);
        if (!dom)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    virJSONValueFree(jobj);
    return ret;
}


virDomainDefParserConfig parallelsDomainDefParserConfig = {
    .macPrefix = {0x42, 0x1C, 0x00},
};


static int
parallelsOpenDefault(virConnectPtr conn)
{
    parallelsConnPtr privconn;

    if (VIR_ALLOC(privconn) < 0)
        return VIR_DRV_OPEN_ERROR;
    if (virMutexInit(&privconn->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot initialize mutex"));
        goto error;
    }

    if (!(privconn->caps = parallelsBuildCapabilities()))
        goto error;

    if (!(privconn->xmlopt = virDomainXMLOptionNew(&parallelsDomainDefParserConfig,
                                                 NULL, NULL)))
        goto error;

    if (!(privconn->domains = virDomainObjListNew()))
        goto error;

    conn->privateData = privconn;

    if (parallelsLoadDomains(privconn, NULL))
        goto error;

    return VIR_DRV_OPEN_SUCCESS;

 error:
    virObjectUnref(privconn->domains);
    virObjectUnref(privconn->caps);
    virStoragePoolObjListFree(&privconn->pools);
    VIR_FREE(privconn);
    return VIR_DRV_OPEN_ERROR;
}

static virDrvOpenStatus
parallelsConnectOpen(virConnectPtr conn,
                     virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                     unsigned int flags)
{
    int ret;

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (!conn->uri)
        return VIR_DRV_OPEN_DECLINED;

    if (!conn->uri->scheme || STRNEQ(conn->uri->scheme, "parallels"))
        return VIR_DRV_OPEN_DECLINED;

    /* Remote driver should handle these. */
    if (conn->uri->server)
        return VIR_DRV_OPEN_DECLINED;

    /* From this point on, the connection is for us. */
    if (!STREQ_NULLABLE(conn->uri->path, "/system")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected Parallels URI path '%s', try parallels:///system"),
                       conn->uri->path);
        return VIR_DRV_OPEN_ERROR;
    }

    if ((ret = parallelsOpenDefault(conn)) != VIR_DRV_OPEN_SUCCESS)
        return ret;

    return VIR_DRV_OPEN_SUCCESS;
}

static int
parallelsConnectClose(virConnectPtr conn)
{
    parallelsConnPtr privconn = conn->privateData;

    parallelsDriverLock(privconn);
    virObjectUnref(privconn->caps);
    virObjectUnref(privconn->xmlopt);
    virObjectUnref(privconn->domains);
    conn->privateData = NULL;

    parallelsDriverUnlock(privconn);
    virMutexDestroy(&privconn->lock);

    VIR_FREE(privconn);
    return 0;
}

static int
parallelsConnectGetVersion(virConnectPtr conn ATTRIBUTE_UNUSED, unsigned long *hvVer)
{
    char *output, *sVer, *tmp;
    const char *searchStr = "prlsrvctl version ";
    int ret = -1;

    output = parallelsGetOutput(PRLSRVCTL, "--help", NULL);

    if (!output) {
        parallelsParseError();
        goto cleanup;
    }

    if (!(sVer = strstr(output, searchStr))) {
        parallelsParseError();
        goto cleanup;
    }

    sVer = sVer + strlen(searchStr);

    /* parallels server has versions number like 6.0.17977.782218,
     * so libvirt can handle only first two numbers. */
    if (!(tmp = strchr(sVer, '.'))) {
        parallelsParseError();
        goto cleanup;
    }

    if (!(tmp = strchr(tmp + 1, '.'))) {
        parallelsParseError();
        goto cleanup;
    }

    tmp[0] = '\0';
    if (virParseVersionString(sVer, hvVer, true) < 0) {
        parallelsParseError();
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(output);
    return ret;
}


static char *parallelsConnectGetHostname(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return virGetHostname();
}


static int
parallelsConnectListDomains(virConnectPtr conn, int *ids, int maxids)
{
    parallelsConnPtr privconn = conn->privateData;
    int n;

    parallelsDriverLock(privconn);
    n = virDomainObjListGetActiveIDs(privconn->domains, ids, maxids,
                                     NULL, NULL);
    parallelsDriverUnlock(privconn);

    return n;
}

static int
parallelsConnectNumOfDomains(virConnectPtr conn)
{
    parallelsConnPtr privconn = conn->privateData;
    int count;

    parallelsDriverLock(privconn);
    count = virDomainObjListNumOfDomains(privconn->domains, true,
                                         NULL, NULL);
    parallelsDriverUnlock(privconn);

    return count;
}

static int
parallelsConnectListDefinedDomains(virConnectPtr conn, char **const names, int maxnames)
{
    parallelsConnPtr privconn = conn->privateData;
    int n;

    parallelsDriverLock(privconn);
    memset(names, 0, sizeof(*names) * maxnames);
    n = virDomainObjListGetInactiveNames(privconn->domains, names,
                                         maxnames, NULL, NULL);
    parallelsDriverUnlock(privconn);

    return n;
}

static int
parallelsConnectNumOfDefinedDomains(virConnectPtr conn)
{
    parallelsConnPtr privconn = conn->privateData;
    int count;

    parallelsDriverLock(privconn);
    count = virDomainObjListNumOfDomains(privconn->domains, false,
                                         NULL, NULL);
    parallelsDriverUnlock(privconn);

    return count;
}

static int
parallelsConnectListAllDomains(virConnectPtr conn,
                               virDomainPtr **domains,
                               unsigned int flags)
{
    parallelsConnPtr privconn = conn->privateData;
    int ret = -1;

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_FILTERS_ALL, -1);
    parallelsDriverLock(privconn);
    ret = virDomainObjListExport(privconn->domains, conn, domains,
                                 NULL, flags);
    parallelsDriverUnlock(privconn);

    return ret;
}

static virDomainPtr
parallelsDomainLookupByID(virConnectPtr conn, int id)
{
    parallelsConnPtr privconn = conn->privateData;
    virDomainPtr ret = NULL;
    virDomainObjPtr dom;

    parallelsDriverLock(privconn);
    dom = virDomainObjListFindByID(privconn->domains, id);
    parallelsDriverUnlock(privconn);

    if (dom == NULL) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    ret = virGetDomain(conn, dom->def->name, dom->def->uuid);
    if (ret)
        ret->id = dom->def->id;

 cleanup:
    if (dom)
        virObjectUnlock(dom);
    return ret;
}

static virDomainPtr
parallelsDomainLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    parallelsConnPtr privconn = conn->privateData;
    virDomainPtr ret = NULL;
    virDomainObjPtr dom;

    parallelsDriverLock(privconn);
    dom = virDomainObjListFindByUUID(privconn->domains, uuid);
    parallelsDriverUnlock(privconn);

    if (dom == NULL) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    ret = virGetDomain(conn, dom->def->name, dom->def->uuid);
    if (ret)
        ret->id = dom->def->id;

 cleanup:
    if (dom)
        virObjectUnlock(dom);
    return ret;
}

static virDomainPtr
parallelsDomainLookupByName(virConnectPtr conn, const char *name)
{
    parallelsConnPtr privconn = conn->privateData;
    virDomainPtr ret = NULL;
    virDomainObjPtr dom;

    parallelsDriverLock(privconn);
    dom = virDomainObjListFindByName(privconn->domains, name);
    parallelsDriverUnlock(privconn);

    if (dom == NULL) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching name '%s'"), name);
        goto cleanup;
    }

    ret = virGetDomain(conn, dom->def->name, dom->def->uuid);
    if (ret)
        ret->id = dom->def->id;

 cleanup:
    if (dom)
        virObjectUnlock(dom);
    return ret;
}

static int
parallelsDomainGetInfo(virDomainPtr domain, virDomainInfoPtr info)
{
    parallelsConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    int ret = -1;

    parallelsDriverLock(privconn);
    privdom = virDomainObjListFindByUUID(privconn->domains, domain->uuid);
    parallelsDriverUnlock(privconn);

    if (privdom == NULL) {
        parallelsDomNotFoundError(domain);
        goto cleanup;
    }

    info->state = virDomainObjGetState(privdom, NULL);
    info->memory = privdom->def->mem.cur_balloon;
    info->maxMem = privdom->def->mem.max_balloon;
    info->nrVirtCpu = privdom->def->vcpus;
    info->cpuTime = 0;
    ret = 0;

 cleanup:
    if (privdom)
        virObjectUnlock(privdom);
    return ret;
}

static char *
parallelsDomainGetOSType(virDomainPtr domain)
{
    parallelsConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;

    char *ret = NULL;

    parallelsDriverLock(privconn);
    privdom = virDomainObjListFindByUUID(privconn->domains, domain->uuid);
    if (privdom == NULL) {
        parallelsDomNotFoundError(domain);
        goto cleanup;
    }

    ignore_value(VIR_STRDUP(ret, privdom->def->os.type));

 cleanup:
    if (privdom)
        virObjectUnlock(privdom);
    parallelsDriverUnlock(privconn);
    return ret;
}

static int
parallelsDomainIsPersistent(virDomainPtr domain)
{
    parallelsConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    int ret = -1;

    parallelsDriverLock(privconn);
    privdom = virDomainObjListFindByUUID(privconn->domains, domain->uuid);
    if (privdom == NULL) {
        parallelsDomNotFoundError(domain);
        goto cleanup;
    }

    ret = 1;

 cleanup:
    if (privdom)
        virObjectUnlock(privdom);
    parallelsDriverUnlock(privconn);
    return ret;
}

static int
parallelsDomainGetState(virDomainPtr domain,
                  int *state, int *reason, unsigned int flags)
{
    parallelsConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    int ret = -1;
    virCheckFlags(0, -1);

    parallelsDriverLock(privconn);
    privdom = virDomainObjListFindByUUID(privconn->domains, domain->uuid);
    parallelsDriverUnlock(privconn);

    if (privdom == NULL) {
        parallelsDomNotFoundError(domain);
        goto cleanup;
    }

    *state = virDomainObjGetState(privdom, reason);
    ret = 0;

 cleanup:
    if (privdom)
        virObjectUnlock(privdom);
    return ret;
}

static char *
parallelsDomainGetXMLDesc(virDomainPtr domain, unsigned int flags)
{
    parallelsConnPtr privconn = domain->conn->privateData;
    virDomainDefPtr def;
    virDomainObjPtr privdom;
    char *ret = NULL;

    /* Flags checked by virDomainDefFormat */

    parallelsDriverLock(privconn);
    privdom = virDomainObjListFindByUUID(privconn->domains, domain->uuid);
    parallelsDriverUnlock(privconn);

    if (privdom == NULL) {
        parallelsDomNotFoundError(domain);
        goto cleanup;
    }

    def = (flags & VIR_DOMAIN_XML_INACTIVE) &&
        privdom->newDef ? privdom->newDef : privdom->def;

    ret = virDomainDefFormat(def, flags);

 cleanup:
    if (privdom)
        virObjectUnlock(privdom);
    return ret;
}

static int
parallelsDomainGetAutostart(virDomainPtr domain, int *autostart)
{
    parallelsConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    int ret = -1;

    parallelsDriverLock(privconn);
    privdom = virDomainObjListFindByUUID(privconn->domains, domain->uuid);
    parallelsDriverUnlock(privconn);

    if (privdom == NULL) {
        parallelsDomNotFoundError(domain);
        goto cleanup;
    }

    *autostart = privdom->autostart;
    ret = 0;

 cleanup:
    if (privdom)
        virObjectUnlock(privdom);
    return ret;
}

typedef int (*parallelsChangeStateFunc)(virDomainObjPtr privdom);
#define PARALLELS_UUID(x)     (((parallelsDomObjPtr)(x->privateData))->uuid)

static int
parallelsDomainChangeState(virDomainPtr domain,
                           virDomainState req_state, const char *req_state_name,
                           parallelsChangeStateFunc chstate,
                           virDomainState new_state, int reason)
{
    parallelsConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    int state;
    int ret = -1;

    parallelsDriverLock(privconn);
    privdom = virDomainObjListFindByUUID(privconn->domains, domain->uuid);
    parallelsDriverUnlock(privconn);

    if (privdom == NULL) {
        parallelsDomNotFoundError(domain);
        goto cleanup;
    }

    state = virDomainObjGetState(privdom, NULL);
    if (state != req_state) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("domain '%s' not %s"),
                       privdom->def->name, req_state_name);
        goto cleanup;
    }

    if (chstate(privdom))
        goto cleanup;

    virDomainObjSetState(privdom, new_state, reason);

    ret = 0;

 cleanup:
    if (privdom)
        virObjectUnlock(privdom);

    return ret;
}

static int parallelsPause(virDomainObjPtr privdom)
{
    return parallelsCmdRun(PRLCTL, "pause", PARALLELS_UUID(privdom), NULL);
}

static int
parallelsDomainSuspend(virDomainPtr domain)
{
    return parallelsDomainChangeState(domain,
                                      VIR_DOMAIN_RUNNING, "running",
                                      parallelsPause,
                                      VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_USER);
}

static int parallelsResume(virDomainObjPtr privdom)
{
    return parallelsCmdRun(PRLCTL, "resume", PARALLELS_UUID(privdom), NULL);
}

static int
parallelsDomainResume(virDomainPtr domain)
{
    return parallelsDomainChangeState(domain,
                                      VIR_DOMAIN_PAUSED, "paused",
                                      parallelsResume,
                                      VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_UNPAUSED);
}

static int parallelsStart(virDomainObjPtr privdom)
{
    return parallelsCmdRun(PRLCTL, "start", PARALLELS_UUID(privdom), NULL);
}

static int
parallelsDomainCreate(virDomainPtr domain)
{
    return parallelsDomainChangeState(domain,
                                      VIR_DOMAIN_SHUTOFF, "stopped",
                                      parallelsStart,
                                      VIR_DOMAIN_RUNNING, VIR_DOMAIN_EVENT_STARTED_BOOTED);
}

static int parallelsKill(virDomainObjPtr privdom)
{
    return parallelsCmdRun(PRLCTL, "stop", PARALLELS_UUID(privdom), "--kill", NULL);
}

static int
parallelsDomainDestroy(virDomainPtr domain)
{
    return parallelsDomainChangeState(domain,
                                      VIR_DOMAIN_RUNNING, "running",
                                      parallelsKill,
                                      VIR_DOMAIN_SHUTOFF, VIR_DOMAIN_SHUTOFF_DESTROYED);
}

static int parallelsStop(virDomainObjPtr privdom)
{
    return parallelsCmdRun(PRLCTL, "stop", PARALLELS_UUID(privdom), NULL);
}

static int
parallelsDomainShutdown(virDomainPtr domain)
{
    return parallelsDomainChangeState(domain,
                                      VIR_DOMAIN_RUNNING, "running",
                                      parallelsStop,
                                      VIR_DOMAIN_SHUTOFF, VIR_DOMAIN_SHUTOFF_SHUTDOWN);
}

static int
parallelsApplyGraphicsParams(virDomainGraphicsDefPtr *oldgraphics, int nold,
                             virDomainGraphicsDefPtr *newgraphics, int nnew)
{
    virDomainGraphicsDefPtr new, old;

    /* parallels server supports only 1 VNC display per VM */
    if (nold != nnew || nnew > 1)
        goto error;

    if (nnew == 0)
        return 0;

    if (newgraphics[0]->type != VIR_DOMAIN_GRAPHICS_TYPE_VNC)
        goto error;

    old = oldgraphics[0];
    new = newgraphics[0];

    if (old->data.vnc.port != new->data.vnc.port &&
        (old->data.vnc.port != 0 && new->data.vnc.port != 0)) {

        goto error;
    } else if (old->data.vnc.autoport != new->data.vnc.autoport ||
        new->data.vnc.keymap != NULL ||
        new->data.vnc.socket != NULL ||
        !STREQ_NULLABLE(old->data.vnc.auth.passwd, new->data.vnc.auth.passwd) ||
        old->data.vnc.auth.expires != new->data.vnc.auth.expires ||
        old->data.vnc.auth.validTo != new->data.vnc.auth.validTo ||
        old->data.vnc.auth.connected != new->data.vnc.auth.connected) {

        goto error;
    } else if (old->nListens != new->nListens ||
               new->nListens > 1 ||
               old->listens[0].type != new->listens[0].type ||
                 !STREQ_NULLABLE(old->listens[0].address, new->listens[0].address) ||
                 !STREQ_NULLABLE(old->listens[0].network, new->listens[0].network)) {

        goto error;
    }

    return 0;
 error:
    virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                   _("changing display parameters is not supported "
                     "by parallels driver"));
    return -1;
}

static int
parallelsApplySerialParams(virDomainChrDefPtr *oldserials, int nold,
                           virDomainChrDefPtr *newserials, int nnew)
{
    size_t i, j;

    if (nold != nnew)
        goto error;

    for (i = 0; i < nold; i++) {
        virDomainChrDefPtr oldserial = oldserials[i];
        virDomainChrDefPtr newserial = NULL;

        for (j = 0; j < nnew; j++) {
            if (newserials[j]->target.port == oldserial->target.port) {
                newserial = newserials[j];
                break;
            }
        }

        if (!newserial)
            goto error;

        if (oldserial->source.type != newserial->source.type)
            goto error;

        if ((newserial->source.type == VIR_DOMAIN_CHR_TYPE_DEV ||
            newserial->source.type == VIR_DOMAIN_CHR_TYPE_FILE) &&
            !STREQ_NULLABLE(oldserial->source.data.file.path,
                            newserial->source.data.file.path))
            goto error;
        if (newserial->source.type == VIR_DOMAIN_CHR_TYPE_UNIX &&
           (!STREQ_NULLABLE(oldserial->source.data.nix.path,
                            newserial->source.data.nix.path) ||
            oldserial->source.data.nix.listen == newserial->source.data.nix.listen)) {

            goto error;
        }
    }

    return 0;
 error:
    virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                   _("changing serial device parameters is "
                     "not supported by parallels driver"));
    return -1;
}

static int
parallelsApplyVideoParams(parallelsDomObjPtr pdom,
                          virDomainVideoDefPtr *oldvideos, int nold,
                           virDomainVideoDefPtr *newvideos, int nnew)
{
    virDomainVideoDefPtr old, new;
    char str_vram[32];

    if (nold != 1 || nnew != 1) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("Only one video device is "
                         "supported by parallels driver"));
        return -1;
    }

    old = oldvideos[0];
    new = newvideos[0];
    if (new->type != VIR_DOMAIN_VIDEO_TYPE_VGA) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("Only VGA video device is "
                         "supported by parallels driver"));
        return -1;
    }

    if (new->heads != 1) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("Only one monitor is supported by parallels driver"));
        return -1;
    }

    /* old->accel must be always non-NULL */
    if (new->accel == NULL ||
        old->accel->support2d != new->accel->support2d ||
        old->accel->support3d != new->accel->support3d) {

        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                   _("Changing video acceleration parameters is "
                     "not supported by parallels driver"));
        return -1;
    }

    if (old->vram != new->vram) {
        if (new->vram % (1 << 20) != 0) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("Video RAM size should be multiple of 1Mb."));
            return -1;
        }

        snprintf(str_vram, 31, "%d", new->vram >> 20);
        str_vram[31] = '\0';

        if (parallelsCmdRun(PRLCTL, "set", pdom->uuid,
                            "--videosize", str_vram, NULL))
            return -1;
    }
    return 0;
}

static int parallelsAddHddByVolume(parallelsDomObjPtr pdom,
                                   virDomainDiskDefPtr disk,
                                   virStoragePoolObjPtr pool,
                                   virStorageVolDefPtr voldef)
{
    int ret = -1;
    const char *strbus;

    virCommandPtr cmd = virCommandNewArgList(PRLCTL, "set", pdom->uuid,
                                             "--device-add", "hdd", NULL);
    virCommandAddArgFormat(cmd, "--size=%lluM", voldef->capacity >> 20);

    if (!(strbus = parallelsGetDiskBusName(disk->bus))) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED,
                       _("Invalid disk bus: %d"), disk->bus);
        goto cleanup;
    }

    virCommandAddArgFormat(cmd, "--iface=%s", strbus);

    if (disk->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE)
        virCommandAddArgFormat(cmd, "--position=%d",
                               disk->info.addr.drive.target);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (parallelsStorageVolDefRemove(pool, voldef))
        goto cleanup;

    ret = 0;
 cleanup:
    virCommandFree(cmd);
    return ret;
}

static int parallelsAddHdd(virConnectPtr conn,
                           parallelsDomObjPtr pdom,
                           virDomainDiskDefPtr disk)
{
    parallelsConnPtr privconn = conn->privateData;
    virStorageVolDefPtr voldef = NULL;
    virStoragePoolObjPtr pool = NULL;
    virStorageVolPtr vol = NULL;
    int ret = -1;
    const char *src = virDomainDiskGetSource(disk);

    if (!(vol = parallelsStorageVolLookupByPathLocked(conn, src))) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Can't find volume with path '%s'"), src);
        return -1;
    }

    pool = virStoragePoolObjFindByName(&privconn->pools, vol->pool);
    if (!pool) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Can't find storage pool with name '%s'"),
                       vol->pool);
        goto cleanup;
    }

    voldef = virStorageVolDefFindByPath(pool, src);
    if (!voldef) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Can't find storage volume definition for path '%s'"),
                       src);
        goto cleanup;
    }

    ret = parallelsAddHddByVolume(pdom, disk, pool, voldef);

 cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    virObjectUnref(vol);
    return ret;
}

static int parallelsRemoveHdd(parallelsDomObjPtr pdom,
                              virDomainDiskDefPtr disk)
{
    char prlname[16];

    prlname[15] = '\0';
    snprintf(prlname, 15, "hdd%d", virDiskNameToIndex(disk->dst));

    if (parallelsCmdRun(PRLCTL, "set", pdom->uuid,
                        "--device-del", prlname,
                        "--detach-only", NULL))
        return -1;

    return 0;
}

static int
parallelsApplyDisksParams(virConnectPtr conn, parallelsDomObjPtr pdom,
                          virDomainDiskDefPtr *olddisks, int nold,
                          virDomainDiskDefPtr *newdisks, int nnew)
{
    size_t i, j;

    for (i = 0; i < nold; i++) {
        virDomainDiskDefPtr newdisk = NULL;
        virDomainDiskDefPtr olddisk = olddisks[i];
        for (j = 0; j < nnew; j++) {
            if (STREQ_NULLABLE(newdisks[j]->dst, olddisk->dst)) {
                newdisk = newdisks[j];
                break;
            }
        }

        if (!newdisk) {
            if (parallelsRemoveHdd(pdom, olddisk)) {
                virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED,
                               _("Can't remove disk '%s' "
                                 "in the specified config"), olddisks[i]->serial);
                return -1;
            }

            continue;
        }

        if (olddisk->bus != newdisk->bus ||
            olddisk->info.addr.drive.target != newdisk->info.addr.drive.target ||
            !STREQ_NULLABLE(virDomainDiskGetSource(olddisk),
                            virDomainDiskGetSource(newdisk))) {

            char prlname[16];
            char strpos[16];
            const char *strbus;

            prlname[15] = '\0';
            snprintf(prlname, 15, "hdd%d", virDiskNameToIndex(newdisk->dst));

            strpos[15] = '\0';
            snprintf(strpos, 15, "%d", newdisk->info.addr.drive.target);

            if (!(strbus = parallelsGetDiskBusName(newdisk->bus))) {
                virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED,
                               _("Unsupported disk bus: %d"), newdisk->bus);
                return -1;
            }

            if (parallelsCmdRun(PRLCTL, "set", pdom->uuid,
                                "--device-set", prlname,
                                "--iface", strbus,
                                "--position", strpos,
                                "--image", newdisk->src, NULL))
                return -1;
        }
    }

    for (i = 0; i < nnew; i++) {
        virDomainDiskDefPtr newdisk = newdisks[i];
        bool found = false;
        for (j = 0; j < nold; j++)
            if (STREQ_NULLABLE(olddisks[j]->dst, newdisk->dst))
                found = true;
        if (found)
            continue;

        if (parallelsAddHdd(conn, pdom, newdisk))
            return -1;
    }

    return 0;
}

static int parallelsApplyIfaceParams(parallelsDomObjPtr pdom,
                                     virDomainNetDefPtr oldnet,
                                     virDomainNetDefPtr newnet)
{
    bool create = false;
    bool is_changed = false;
    virCommandPtr cmd = NULL;
    char strmac[VIR_MAC_STRING_BUFLEN];
    size_t i;
    int ret = -1;

    if (!oldnet) {
        create = true;
        if (VIR_ALLOC(oldnet) < 0)
            return -1;
    }

    if (!create && oldnet->type != newnet->type) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("Changing network type is not supported"));
        goto cleanup;
    }

    if (!STREQ_NULLABLE(oldnet->model, newnet->model)) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("Changing network device model is not supported"));
        goto cleanup;
    }

    if (!STREQ_NULLABLE(oldnet->data.network.portgroup,
                        newnet->data.network.portgroup)) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("Changing network portgroup is not supported"));
        goto cleanup;
    }

    if (!virNetDevVPortProfileEqual(oldnet->virtPortProfile,
                                    newnet->virtPortProfile)) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("Changing virtual port profile is not supported"));
        goto cleanup;
    }

    if (newnet->tune.sndbuf_specified) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("Setting send buffer size is not supported"));
        goto cleanup;
    }

    if (!STREQ_NULLABLE(oldnet->script, newnet->script)) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("Setting startup script is not supported"));
        goto cleanup;
    }

    if (!STREQ_NULLABLE(oldnet->filter, newnet->filter)) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("Changing filter params is not supported"));
        goto cleanup;
    }

    if (newnet->bandwidth != NULL) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("Setting bandwidth params is not supported"));
        goto cleanup;
    }

    for (i = 0; i < sizeof(newnet->vlan); i++) {
        if (((char *)&newnet->vlan)[i] != 0) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                           _("Setting vlan params is not supported"));
            goto cleanup;
        }
    }

    /* Here we know, that there are no differences, that are forbidden.
     * Check is something changed, if no - do nothing */

    if (create) {
        cmd = virCommandNewArgList(PRLCTL, "set", pdom->uuid,
                                   "--device-add", "net", NULL);
    } else {
        cmd = virCommandNewArgList(PRLCTL, "set", pdom->uuid,
                                   "--device-set", newnet->ifname, NULL);
    }

    if (virMacAddrCmp(&oldnet->mac, &newnet->mac)) {
        virMacAddrFormat(&newnet->mac, strmac);
        virCommandAddArgFormat(cmd, "--mac=%s", strmac);
        is_changed = true;
    }

    if (!STREQ_NULLABLE(oldnet->data.network.name, newnet->data.network.name)) {
        if (STREQ_NULLABLE(newnet->data.network.name,
                           PARALLELS_ROUTED_NETWORK_NAME)) {
            virCommandAddArgFormat(cmd, "--type=routed");
        } else {
            virCommandAddArgFormat(cmd, "--network=%s",
                                   newnet->data.network.name);
        }

        is_changed = true;
    }

    if (oldnet->linkstate != newnet->linkstate) {
        if (newnet->linkstate == VIR_DOMAIN_NET_INTERFACE_LINK_STATE_UP) {
            virCommandAddArgFormat(cmd, "--connect");
        } else if (newnet->linkstate == VIR_DOMAIN_NET_INTERFACE_LINK_STATE_DOWN) {
            virCommandAddArgFormat(cmd, "--disconnect");
        }
        is_changed = true;
    }

    if (!create && !is_changed) {
        /* nothing changed - no need to run prlctl */
        ret = 0;
        goto cleanup;
    }

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    if (create)
        VIR_FREE(oldnet);
    virCommandFree(cmd);
    return ret;
}

static int
parallelsApplyIfacesParams(parallelsDomObjPtr pdom,
                            virDomainNetDefPtr *oldnets, int nold,
                            virDomainNetDefPtr *newnets, int nnew)
{
    size_t i, j;
    virDomainNetDefPtr newnet;
    virDomainNetDefPtr oldnet;
    bool found;

    for (i = 0; i < nold; i++) {
        newnet = NULL;
        oldnet = oldnets[i];
        for (j = 0; j < nnew; j++) {
            if (STREQ_NULLABLE(newnets[j]->ifname, oldnet->ifname)) {
                newnet = newnets[j];
                break;
            }
        }

        if (!newnet) {
            if (parallelsCmdRun(PRLCTL, "set", pdom->uuid,
                                "--device-del", oldnet->ifname, NULL) < 0)
                return -1;

            continue;
        }

        if (parallelsApplyIfaceParams(pdom, oldnet, newnet) < 0)
            return -1;
    }

    for (i = 0; i < nnew; i++) {
        newnet = newnets[i];
        found = false;

        for (j = 0; j < nold; j++)
            if (STREQ_NULLABLE(oldnets[j]->ifname, newnet->ifname))
                found = true;
        if (found)
            continue;

        if (parallelsApplyIfaceParams(pdom, NULL, newnet))
            return -1;
    }

    return 0;
}

static int
parallelsApplyChanges(virConnectPtr conn, virDomainObjPtr dom, virDomainDefPtr new)
{
    char buf[32];

    virDomainDefPtr old = dom->def;
    parallelsDomObjPtr pdom = dom->privateData;

    if (new->description && !STREQ_NULLABLE(old->description, new->description)) {
        if (parallelsCmdRun(PRLCTL, "set", pdom->uuid,
                            "--description", new->description, NULL))
            return -1;
    }

    if (new->name && !STREQ_NULLABLE(old->name, new->name)) {
        if (parallelsCmdRun(PRLCTL, "set", pdom->uuid,
                            "--name", new->name, NULL))
            return -1;
    }

    if (new->title && !STREQ_NULLABLE(old->title, new->title)) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("titles are not supported by parallels driver"));
        return -1;
    }

    if (new->blkio.ndevices > 0) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("blkio parameters are not supported "
                         "by parallels driver"));
        return -1;
    }

    if (old->mem.max_balloon != new->mem.max_balloon) {
        if (new->mem.max_balloon != new->mem.cur_balloon) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("changing balloon parameters is not supported "
                         "by parallels driver"));
           return -1;
        }

        if (new->mem.max_balloon % (1 << 10) != 0) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("Memory size should be multiple of 1Mb."));
            return -1;
        }

        snprintf(buf, 31, "%llu", new->mem.max_balloon >> 10);
        buf[31] = '\0';

        if (parallelsCmdRun(PRLCTL, "set", pdom->uuid,
                            "--memsize", buf, NULL))
            return -1;
    }

    if (old->mem.hugepage_backed != new->mem.hugepage_backed ||
        old->mem.hard_limit != new->mem.hard_limit ||
        old->mem.soft_limit != new->mem.soft_limit ||
        old->mem.min_guarantee != new->mem.min_guarantee ||
        old->mem.swap_hard_limit != new->mem.swap_hard_limit) {

        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("Memory parameter is not supported "
                         "by parallels driver"));
        return -1;
    }

    if (old->vcpus != new->vcpus) {
        if (new->vcpus != new->maxvcpus) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("current vcpus must be equal to maxvcpus"));
            return -1;
        }

        snprintf(buf, 31, "%d", new->vcpus);
        buf[31] = '\0';

        if (parallelsCmdRun(PRLCTL, "set", pdom->uuid,
                            "--cpus", buf, NULL))
            return -1;
    }

    if (old->placement_mode != new->placement_mode) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("changing cpu placement mode is not supported "
                         "by parallels driver"));
        return -1;
    }

    if ((old->cpumask != NULL || new->cpumask != NULL) &&
        (old->cpumask == NULL || new->cpumask == NULL ||
        !virBitmapEqual(old->cpumask, new->cpumask))) {

        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("changing cpu mask is not supported "
                         "by parallels driver"));
        return -1;
    }

    if (old->cputune.shares != new->cputune.shares ||
        old->cputune.sharesSpecified != new->cputune.sharesSpecified ||
        old->cputune.period != new->cputune.period ||
        old->cputune.quota != new->cputune.quota ||
        old->cputune.nvcpupin != new->cputune.nvcpupin) {

        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("cputune is not supported by parallels driver"));
        return -1;
    }

    if (old->numatune.memory.mode != new->numatune.memory.mode ||
        old->numatune.memory.placement_mode != new->numatune.memory.placement_mode ||
        ((old->numatune.memory.nodemask != NULL || new->numatune.memory.nodemask != NULL) &&
         (old->numatune.memory.nodemask == NULL || new->numatune.memory.nodemask == NULL ||
        !virBitmapEqual(old->numatune.memory.nodemask, new->numatune.memory.nodemask)))){

        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                        _("numa parameters are not supported "
                          "by parallels driver"));
        return -1;
    }

    if (old->onReboot != new->onReboot ||
        old->onPoweroff != new->onPoweroff ||
        old->onCrash != new->onCrash) {

        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("on_reboot, on_poweroff and on_crash parameters "
                         "are not supported by parallels driver"));
        return -1;
    }

    /* we fill only type and arch fields in parallelsLoadDomain for
     * hvm type and also init for containers, so we can check that all
     * other paramenters are null and boot devices config is default */

    if (!STREQ_NULLABLE(old->os.type, new->os.type) ||
        old->os.arch != new->os.arch ||
        new->os.machine != NULL || new->os.bootmenu != 0 ||
        new->os.kernel != NULL || new->os.initrd != NULL ||
        new->os.cmdline != NULL || new->os.root != NULL ||
        new->os.loader != NULL || new->os.bootloader != NULL ||
        new->os.bootloaderArgs != NULL || new->os.smbios_mode != 0 ||
        new->os.bios.useserial != 0) {

        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("changing OS parameters is not supported "
                         "by parallels driver"));
        return -1;
    }
    if (STREQ(new->os.type, "hvm")) {
        if (new->os.nBootDevs != 1 ||
            new->os.bootDevs[0] != VIR_DOMAIN_BOOT_DISK ||
            new->os.init != NULL || new->os.initargv != NULL) {

            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                           _("changing OS parameters is not supported "
                             "by parallels driver"));
            return -1;
        }
    } else {
        if (new->os.nBootDevs != 0 ||
            !STREQ_NULLABLE(old->os.init, new->os.init) ||
            (new->os.initargv != NULL && new->os.initargv[0] != NULL)) {

            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                           _("changing OS parameters is not supported "
                             "by parallels driver"));
            return -1;
        }
    }


    if (!STREQ_NULLABLE(old->emulator, new->emulator)) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("changing emulator is not supported "
                         "by parallels driver"));
        return -1;
    }

    if (old->features != new->features) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("changing features is not supported "
                         "by parallels driver"));
        return -1;
    }

    if (new->clock.offset != VIR_DOMAIN_CLOCK_OFFSET_UTC ||
        new->clock.ntimers != 0) {

        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("changing clock parameters is not supported "
                         "by parallels driver"));
        return -1;
    }

    if (parallelsApplyGraphicsParams(old->graphics, old->ngraphics,
                                   new->graphics, new->ngraphics) < 0)
        return -1;

    if (new->nfss != 0 ||
        new->nsounds != 0 || new->nhostdevs != 0 ||
        new->nredirdevs != 0 || new->nsmartcards != 0 ||
        new->nparallels || new->nchannels != 0 ||
        new->nleases != 0 || new->nhubs != 0) {

        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("changing devices parameters is not supported "
                         "by parallels driver"));
        return -1;
    }

    /* there may be one auto-input */
    if (new->ninputs > 1 ||
        (new->ninputs > 1 &&
        (new->inputs[0]->type != VIR_DOMAIN_INPUT_TYPE_MOUSE ||
        new->inputs[0]->bus != VIR_DOMAIN_INPUT_BUS_PS2))) {

        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("changing input devices parameters is not supported "
                         "by parallels driver"));
    }


    if (parallelsApplySerialParams(old->serials, old->nserials,
                                   new->serials, new->nserials) < 0)
        return -1;

    if (parallelsApplySerialParams(old->consoles, old->nconsoles,
                                   new->consoles, new->nconsoles) < 0)
        return -1;

    if (parallelsApplyVideoParams(pdom, old->videos, old->nvideos,
                                   new->videos, new->nvideos) < 0)
        return -1;
    if (parallelsApplyDisksParams(conn, pdom, old->disks, old->ndisks,
                                  new->disks, new->ndisks) < 0)
        return -1;
    if (parallelsApplyIfacesParams(pdom, old->nets, old->nnets,
                                  new->nets, new->nnets) < 0)
        return -1;

    return 0;
}

static int
parallelsCreateVm(virConnectPtr conn, virDomainDefPtr def)
{
    parallelsConnPtr privconn = conn->privateData;
    size_t i;
    virStorageVolDefPtr privvol = NULL;
    virStoragePoolObjPtr pool = NULL;
    virStorageVolPtr vol = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    const char *src;

    for (i = 0; i < def->ndisks; i++) {
        if (def->disks[i]->device != VIR_DOMAIN_DISK_DEVICE_DISK)
            continue;

        src = virDomainDiskGetSource(def->disks[i]);
        vol = parallelsStorageVolLookupByPathLocked(conn, src);
        if (!vol) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Can't find volume with path '%s'"),
                           src);
            return -1;
        }
        break;
    }

    if (!vol) {
        /* We determine path to VM directory from volume, so
         * let's report error if no disk until better solution
         * will be found */
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Can't create VM '%s' without hard disks"),
                       def->name ? def->name : _("(unnamed)"));
        return -1;
    }

    pool = virStoragePoolObjFindByName(&privconn->pools, vol->pool);
    if (!pool) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Can't find storage pool with name '%s'"),
                       vol->pool);
        goto error;
    }

    privvol = virStorageVolDefFindByPath(pool, src);
    if (!privvol) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Can't find storage volume definition for path '%s'"),
                       src);
        goto error2;
    }

    virUUIDFormat(def->uuid, uuidstr);

    if (parallelsCmdRun(PRLCTL, "create", def->name, "--dst",
                        pool->def->target.path, "--no-hdd",
                        "--uuid", uuidstr, NULL) < 0)
        goto error2;

    if (parallelsCmdRun(PRLCTL, "set", def->name, "--vnc-mode", "auto", NULL) < 0)
        goto error2;

    virStoragePoolObjUnlock(pool);
    virObjectUnref(vol);

    return 0;

 error2:
    virStoragePoolObjUnlock(pool);
 error:
    virObjectUnref(vol);
    return -1;
}

static int
parallelsCreateCt(virConnectPtr conn ATTRIBUTE_UNUSED, virDomainDefPtr def)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(def->uuid, uuidstr);

    if (def->nfss != 1 ||
        def->fss[0]->type != VIR_DOMAIN_FS_TYPE_TEMPLATE) {

        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("There must be only 1 template FS for "
                         "container creation"));
        goto error;
    }

    if (parallelsCmdRun(PRLCTL, "create", def->name, "--vmtype", "ct",
                        "--uuid", uuidstr,
                        "--ostemplate", def->fss[0]->src, NULL) < 0)
        goto error;

    if (parallelsCmdRun(PRLCTL, "set", def->name, "--vnc-mode", "auto", NULL) < 0)
        goto error;

    return 0;

 error:
    return -1;
}

static virDomainPtr
parallelsDomainDefineXML(virConnectPtr conn, const char *xml)
{
    parallelsConnPtr privconn = conn->privateData;
    virDomainPtr ret = NULL;
    virDomainDefPtr def;
    virDomainObjPtr dom = NULL, olddom = NULL;

    parallelsDriverLock(privconn);
    if ((def = virDomainDefParseString(xml, privconn->caps, privconn->xmlopt,
                                       1 << VIR_DOMAIN_VIRT_PARALLELS,
                                       VIR_DOMAIN_XML_INACTIVE)) == NULL) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Can't parse XML desc"));
        goto cleanup;
    }

    olddom = virDomainObjListFindByUUID(privconn->domains, def->uuid);
    if (olddom == NULL) {
        virResetLastError();
        if (STREQ(def->os.type, "hvm")) {
            if (parallelsCreateVm(conn, def))
                goto cleanup;
        } else if (STREQ(def->os.type, "exe")) {
            if (parallelsCreateCt(conn, def))
                goto cleanup;
        } else {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Unsupported OS type: %s"), def->os.type);
            goto cleanup;
        }
        if (parallelsLoadDomains(privconn, def->name))
            goto cleanup;
        olddom = virDomainObjListFindByName(privconn->domains, def->name);
        if (!olddom) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Domain for '%s' is not defined after creation"),
                           def->name ? def->name : _("(unnamed)"));
            goto cleanup;
        }
    }

    if (parallelsApplyChanges(conn, olddom, def) < 0) {
        virObjectUnlock(olddom);
        goto cleanup;
    }
    virObjectUnlock(olddom);

    if (!(dom = virDomainObjListAdd(privconn->domains, def,
                                    privconn->xmlopt,
                                    0, NULL))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Can't allocate domobj"));
        goto cleanup;
    }

    def = NULL;

    ret = virGetDomain(conn, dom->def->name, dom->def->uuid);
    if (ret)
        ret->id = dom->def->id;

 cleanup:
    virDomainDefFree(def);
    if (dom)
        virObjectUnlock(dom);
    parallelsDriverUnlock(privconn);
    return ret;
}

static int
parallelsNodeGetInfo(virConnectPtr conn ATTRIBUTE_UNUSED,
                     virNodeInfoPtr nodeinfo)
{
    return nodeGetInfo(nodeinfo);
}


static virDriver parallelsDriver = {
    .no = VIR_DRV_PARALLELS,
    .name = "Parallels",
    .connectOpen = parallelsConnectOpen,            /* 0.10.0 */
    .connectClose = parallelsConnectClose,          /* 0.10.0 */
    .connectGetVersion = parallelsConnectGetVersion,   /* 0.10.0 */
    .connectGetHostname = parallelsConnectGetHostname,      /* 0.10.0 */
    .nodeGetInfo = parallelsNodeGetInfo,      /* 0.10.0 */
    .connectGetCapabilities = parallelsConnectGetCapabilities,      /* 0.10.0 */
    .connectListDomains = parallelsConnectListDomains,      /* 0.10.0 */
    .connectNumOfDomains = parallelsConnectNumOfDomains,    /* 0.10.0 */
    .connectListDefinedDomains = parallelsConnectListDefinedDomains,        /* 0.10.0 */
    .connectNumOfDefinedDomains = parallelsConnectNumOfDefinedDomains,      /* 0.10.0 */
    .connectListAllDomains = parallelsConnectListAllDomains, /* 0.10.0 */
    .domainLookupByID = parallelsDomainLookupByID,    /* 0.10.0 */
    .domainLookupByUUID = parallelsDomainLookupByUUID,        /* 0.10.0 */
    .domainLookupByName = parallelsDomainLookupByName,        /* 0.10.0 */
    .domainGetOSType = parallelsDomainGetOSType,    /* 0.10.0 */
    .domainGetInfo = parallelsDomainGetInfo,  /* 0.10.0 */
    .domainGetState = parallelsDomainGetState,        /* 0.10.0 */
    .domainGetXMLDesc = parallelsDomainGetXMLDesc,    /* 0.10.0 */
    .domainIsPersistent = parallelsDomainIsPersistent,        /* 0.10.0 */
    .domainGetAutostart = parallelsDomainGetAutostart,        /* 0.10.0 */
    .domainSuspend = parallelsDomainSuspend,    /* 0.10.0 */
    .domainResume = parallelsDomainResume,    /* 0.10.0 */
    .domainDestroy = parallelsDomainDestroy,  /* 0.10.0 */
    .domainShutdown = parallelsDomainShutdown, /* 0.10.0 */
    .domainCreate = parallelsDomainCreate,    /* 0.10.0 */
    .domainDefineXML = parallelsDomainDefineXML,      /* 0.10.0 */
};

/**
 * parallelsRegister:
 *
 * Registers the parallels driver
 */
int
parallelsRegister(void)
{
    char *prlctl_path;

    prlctl_path = virFindFileInPath(PRLCTL);
    if (!prlctl_path) {
        VIR_DEBUG("%s", _("Can't find prlctl command in the PATH env"));
        return 0;
    }

    VIR_FREE(prlctl_path);

    if (virRegisterDriver(&parallelsDriver) < 0)
        return -1;
    if (parallelsStorageRegister())
        return -1;
    if (parallelsNetworkRegister())
        return -1;

    return 0;
}
