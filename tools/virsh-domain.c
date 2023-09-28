/*
 * virsh-domain.c: Commands to manage domain
 *
 * Copyright (C) 2005, 2007-2016 Red Hat, Inc.
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
#include "virsh-domain.h"
#include "virsh-util.h"

#include <fcntl.h>
#include <signal.h>

#include <libxml/parser.h>
#include <libxml/xpath.h>

#include "internal.h"
#include "virbitmap.h"
#include "virbuffer.h"
#include "conf/domain_conf.h"
#include "viralloc.h"
#include "vircommand.h"
#include "virfile.h"
#include "virjson.h"
#include "virkeycode.h"
#include "virmacaddr.h"
#include "virnetdevbandwidth.h"
#include "virprocess.h"
#include "virstring.h"
#include "virsh-console.h"
#include "virsh-domain-monitor.h"
#include "virsh-host.h"
#include "virtime.h"
#include "virtypedparam.h"
#include "virxml.h"
#include "viruri.h"
#include "vsh-table.h"
#include "virenum.h"
#include "virutil.h"

enum virshAddressType {
    VIRSH_ADDRESS_TYPE_PCI,
    VIRSH_ADDRESS_TYPE_SCSI,
    VIRSH_ADDRESS_TYPE_IDE,
    VIRSH_ADDRESS_TYPE_CCW,
    VIRSH_ADDRESS_TYPE_USB,
    VIRSH_ADDRESS_TYPE_SATA,

    VIRSH_ADDRESS_TYPE_LAST
};

VIR_ENUM_DECL(virshAddress);
VIR_ENUM_IMPL(virshAddress,
              VIRSH_ADDRESS_TYPE_LAST,
              "pci",
              "scsi",
              "ide",
              "ccw",
              "usb",
              "sata");

struct virshAddressPCI {
    unsigned int domain;
    unsigned int bus;
    unsigned int slot;
    unsigned int function;
    bool multifunction;
};

struct virshAddressDrive {
    unsigned int controller;
    unsigned int bus;
    unsigned long long unit;
};

struct virshAddressCCW {
    unsigned int cssid;
    unsigned int ssid;
    unsigned int devno;
};

struct virshAddressUSB {
    unsigned int bus;
    unsigned int port;
};

struct virshAddress {
    int type; /* enum virshAddressType */
    union {
        struct virshAddressPCI pci;
        struct virshAddressDrive drive;
        struct virshAddressCCW ccw;
        struct virshAddressUSB usb;
    } addr;
};


/* pci address pci:0000.00.0x0a.0 (domain:bus:slot:function)
 * ide disk address: ide:00.00.0 (controller:bus:unit)
 * scsi disk address: scsi:00.00.0 (controller:bus:unit)
 * ccw disk address: ccw:0xfe.0.0000 (cssid:ssid:devno)
 * usb disk address: usb:00.00 (bus:port)
 * sata disk address: sata:00.00.0 (controller:bus:unit)
 */
static int
virshAddressParse(const char *str,
                  bool multifunction,
                  struct virshAddress *addr)
{
    g_autofree char *type = g_strdup(str);
    char *a = strchr(type, ':');

    if (!a)
        return -1;

    *a = '\0';

    addr->type = virshAddressTypeFromString(type);

    switch ((enum virshAddressType) addr->type) {
    case VIRSH_ADDRESS_TYPE_PCI:
        addr->addr.pci.multifunction = multifunction;

        if (virStrToLong_uip(++a, &a, 16, &addr->addr.pci.domain) < 0 ||
            virStrToLong_uip(++a, &a, 16, &addr->addr.pci.bus) < 0 ||
            virStrToLong_uip(++a, &a, 16, &addr->addr.pci.slot) < 0 ||
            virStrToLong_uip(++a, &a, 16, &addr->addr.pci.function) < 0)
            return -1;
        break;

    case VIRSH_ADDRESS_TYPE_SATA:
    case VIRSH_ADDRESS_TYPE_IDE:
    case VIRSH_ADDRESS_TYPE_SCSI:
        if (virStrToLong_uip(++a, &a, 10, &addr->addr.drive.controller) < 0 ||
            virStrToLong_uip(++a, &a, 10, &addr->addr.drive.bus) < 0 ||
            virStrToLong_ullp(++a, &a, 10, &addr->addr.drive.unit) < 0)
            return -1;
        break;

    case VIRSH_ADDRESS_TYPE_CCW:
        if (virStrToLong_uip(++a, &a, 16, &addr->addr.ccw.cssid) < 0 ||
            virStrToLong_uip(++a, &a, 16, &addr->addr.ccw.ssid) < 0 ||
            virStrToLong_uip(++a, &a, 16, &addr->addr.ccw.devno) < 0)
            return -1;
        break;

    case VIRSH_ADDRESS_TYPE_USB:
        if (virStrToLong_uip(++a, &a, 10, &addr->addr.usb.bus) < 0 ||
            virStrToLong_uip(++a, &a, 10, &addr->addr.usb.port) < 0)
            return -1;
        break;

    case VIRSH_ADDRESS_TYPE_LAST:
    default:
        return -1;
    }

    return 0;
}


static void
virshAddressFormat(virBuffer *buf,
                   struct virshAddress *addr)
{
    switch ((enum virshAddressType) addr->type) {
    case VIRSH_ADDRESS_TYPE_PCI:
        virBufferAsprintf(buf,
                          "<address type='pci' domain='0x%04x' bus='0x%02x' slot='0x%02x' function='0x%0x'",
                          addr->addr.pci.domain,
                          addr->addr.pci.bus,
                          addr->addr.pci.slot,
                          addr->addr.pci.function);

        if (addr->addr.pci.multifunction)
            virBufferAddLit(buf, " multifunction='on'");

        virBufferAddLit(buf, "/>\n");
        break;

    case VIRSH_ADDRESS_TYPE_SATA:
    case VIRSH_ADDRESS_TYPE_IDE:
    case VIRSH_ADDRESS_TYPE_SCSI:
        virBufferAsprintf(buf,
                          "<address type='drive' controller='%u' bus='%u' unit='%llu'/>\n",
                          addr->addr.drive.controller,
                          addr->addr.drive.bus,
                          addr->addr.drive.unit);
        break;

    case VIRSH_ADDRESS_TYPE_CCW:
        virBufferAsprintf(buf,
                          "<address type='ccw' cssid='0x%02x' ssid='0x%01x' devno='0x%04x'/>\n",
                          addr->addr.ccw.cssid,
                          addr->addr.ccw.ssid,
                          addr->addr.ccw.devno);
        break;

    case VIRSH_ADDRESS_TYPE_USB:
        virBufferAsprintf(buf,
                          "<address type='usb' bus='%u' port='%u'/>\n",
                          addr->addr.usb.bus,
                          addr->addr.usb.port);
        break;

    case VIRSH_ADDRESS_TYPE_LAST:
    default:
        return;
    }
}


/**
 * virshFetchPassFdsList
 *
 * Helper to process the 'pass-fds' argument.
 */
static int
virshFetchPassFdsList(vshControl *ctl,
                      const vshCmd *cmd,
                      size_t *nfdsret,
                      int **fdsret)
{
    const char *fdopt;
    g_auto(GStrv) fdlist = NULL;
    g_autofree int *fds = NULL;
    size_t nfds = 0;
    size_t i;

    *nfdsret = 0;
    *fdsret = NULL;

    if (vshCommandOptStringQuiet(ctl, cmd, "pass-fds", &fdopt) <= 0)
        return 0;

    if (!(fdlist = g_strsplit(fdopt, ",", -1))) {
        vshError(ctl, _("Unable to split FD list '%1$s'"), fdopt);
        return -1;
    }

    nfds = g_strv_length(fdlist);
    fds = g_new0(int, nfds);

    for (i = 0; i < nfds; i++) {
        if (virStrToLong_i(fdlist[i], NULL, 10, fds + i) < 0) {
            vshError(ctl, _("Unable to parse FD number '%1$s'"), fdlist[i]);
            return -1;
        }
    }

    *fdsret = g_steal_pointer(&fds);
    *nfdsret = nfds;
    return 0;
}


#define VIRSH_COMMON_OPT_DOMAIN_PERSISTENT \
    {.name = "persistent", \
     .type = VSH_OT_BOOL, \
     .help = N_("make live change persistent") \
    }

#define VIRSH_COMMON_OPT_DOMAIN_CONFIG \
    VIRSH_COMMON_OPT_CONFIG(N_("affect next boot"))

#define VIRSH_COMMON_OPT_DOMAIN_LIVE \
    VIRSH_COMMON_OPT_LIVE(N_("affect running domain"))

#define VIRSH_COMMON_OPT_DOMAIN_CURRENT \
    VIRSH_COMMON_OPT_CURRENT(N_("affect current domain"))


static virDomainPtr
virshDomainDefine(virConnectPtr conn, const char *xml, unsigned int flags)
{
    virDomainPtr dom;

    if (!flags)
        return virDomainDefineXML(conn, xml);

    dom = virDomainDefineXMLFlags(conn, xml, flags);
    /* If validate is the only flag, just drop it and
     * try again.
     */
    if (!dom) {
        if ((virGetLastErrorCode() == VIR_ERR_NO_SUPPORT) &&
            (flags == VIR_DOMAIN_DEFINE_VALIDATE))
            dom = virDomainDefineXML(conn, xml);
    }
    return dom;
}

VIR_ENUM_DECL(virshDomainVcpuState);
VIR_ENUM_IMPL(virshDomainVcpuState,
              VIR_VCPU_LAST,
              N_("offline"),
              N_("running"),
              N_("blocked"));

static const char *
virshDomainVcpuStateToString(int state)
{
    const char *str = virshDomainVcpuStateTypeToString(state);
    return str ? _(str) : _("no state");
}

/*
 * Determine number of CPU nodes present by trying
 * virNodeGetCPUMap and falling back to virNodeGetInfo
 * if needed.
 */
static int
virshNodeGetCPUCount(virConnectPtr conn)
{
    int ret;
    virNodeInfo nodeinfo;

    if ((ret = virNodeGetCPUMap(conn, NULL, NULL, 0)) < 0) {
        /* fall back to nodeinfo */
        vshResetLibvirtError();
        if (virNodeGetInfo(conn, &nodeinfo) == 0)
            ret = VIR_NODEINFO_MAXCPUS(nodeinfo);
    }
    return ret;
}

/*
 * "attach-device" command
 */
static const vshCmdInfo info_attach_device[] = {
    {.name = "help",
     .data = N_("attach device from an XML file")
    },
    {.name = "desc",
     .data = N_("Attach device from an XML <file>.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_attach_device[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    VIRSH_COMMON_OPT_FILE(N_("XML file")),
    VIRSH_COMMON_OPT_DOMAIN_PERSISTENT,
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = NULL}
};

static bool
cmdAttachDevice(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *from = NULL;
    g_autofree char *buffer = NULL;
    int rv;
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;
    bool current = vshCommandOptBool(cmd, "current");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool persistent = vshCommandOptBool(cmd, "persistent");

    VSH_EXCLUSIVE_OPTIONS_VAR(persistent, current);

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (config || persistent)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        return false;

    if (persistent &&
        virDomainIsActive(dom) == 1)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0) {
        vshReportError(ctl);
        return false;
    }

    if (flags || current)
        rv = virDomainAttachDeviceFlags(dom, buffer, flags);
    else
        rv = virDomainAttachDevice(dom, buffer);

    if (rv < 0) {
        vshError(ctl, _("Failed to attach device from %1$s"), from);
        return false;
    }

    vshPrintExtra(ctl, "%s", _("Device attached successfully\n"));
    return true;
}

/*
 * "attach-disk" command
 */
static const vshCmdInfo info_attach_disk[] = {
    {.name = "help",
     .data = N_("attach disk device")
    },
    {.name = "desc",
     .data = N_("Attach new disk device.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_attach_disk[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "source",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ | VSH_OFLAG_EMPTY_OK,
     .help = N_("source of disk device or name of network disk")
    },
    {.name = "target",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshCompleteEmpty,
     .help = N_("target of disk device")
    },
    {.name = "targetbus",
     .type = VSH_OT_STRING,
     .help = N_("target bus of disk device")
    },
    {.name = "driver",
     .type = VSH_OT_STRING,
     .help = N_("driver of disk device")
    },
    {.name = "subdriver",
     .type = VSH_OT_STRING,
     .help = N_("subdriver of disk device")
    },
    {.name = "iothread",
     .type = VSH_OT_STRING,
     .completer = virshDomainIOThreadIdCompleter,
     .help = N_("IOThread to be used by supported device")
    },
    {.name = "cache",
     .type = VSH_OT_STRING,
     .help = N_("cache mode of disk device")
    },
    {.name = "io",
     .type = VSH_OT_STRING,
     .help = N_("io policy of disk device")
    },
    {.name = "type",
     .type = VSH_OT_STRING,
     .help = N_("target device type")
    },
    {.name = "shareable",
     .type = VSH_OT_ALIAS,
     .help = "mode=shareable"
    },
    {.name = "mode",
     .type = VSH_OT_STRING,
     .help = N_("mode of device reading and writing")
    },
    {.name = "sourcetype",
     .type = VSH_OT_STRING,
     .help = N_("type of source (block|file|network)")
    },
    {.name = "serial",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("serial of disk device")
    },
    {.name = "wwn",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("wwn of disk device")
    },
    {.name = "alias",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("custom alias name of disk device")
    },
    {.name = "rawio",
     .type = VSH_OT_BOOL,
     .help = N_("needs rawio capability")
    },
    {.name = "address",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("address of disk device")
    },
    {.name = "multifunction",
     .type = VSH_OT_BOOL,
     .help = N_("use multifunction pci under specified address")
    },
    {.name = "print-xml",
     .type = VSH_OT_BOOL,
     .help = N_("print XML document rather than attach the disk")
    },
    {.name = "source-protocol",
     .type = VSH_OT_STRING,
     .help = N_("protocol used by disk device source")
    },
    {.name = "source-host-name",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("host name for source of disk device")
    },
    {.name = "source-host-transport",
     .type = VSH_OT_STRING,
     .help = N_("host transport for source of disk device")
    },
    {.name = "source-host-socket",
     .type = VSH_OT_STRING,
     .help = N_("host socket for source of disk device")
    },
    VIRSH_COMMON_OPT_DOMAIN_PERSISTENT,
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = NULL}
};


static int
cmdAttachDiskFormatAddress(vshControl *ctl,
                           virBuffer *buf,
                           const char *straddr,
                           const char *target,
                           bool multifunction)
{
    struct virshAddress diskAddr;

    if (virshAddressParse(straddr, multifunction, &diskAddr) < 0) {
        vshError(ctl, _("Invalid address."));
        return -1;
    }

    if (STRPREFIX((const char *)target, "vd")) {
        if (diskAddr.type != VIRSH_ADDRESS_TYPE_PCI &&
            diskAddr.type != VIRSH_ADDRESS_TYPE_CCW) {
            vshError(ctl, "%s",
                     _("expecting a pci:0000.00.00.00 or ccw:00.0.0000 address."));
            return -1;
        }
    } else if (STRPREFIX((const char *)target, "sd")) {
        if (diskAddr.type != VIRSH_ADDRESS_TYPE_SCSI &&
            diskAddr.type != VIRSH_ADDRESS_TYPE_USB &&
            diskAddr.type != VIRSH_ADDRESS_TYPE_SATA) {
            vshError(ctl, "%s",
                     _("expecting a scsi:00.00.00 or usb:00.00 or sata:00.00.00 address."));
            return -1;
        }
    } else if (STRPREFIX((const char *)target, "hd")) {
        if (diskAddr.type != VIRSH_ADDRESS_TYPE_IDE) {
            vshError(ctl, "%s", _("expecting an ide:00.00.00 address."));
            return -1;
        }
    }

    virshAddressFormat(buf, &diskAddr);
    return 0;
}


enum virshAttachDiskSourceType {
    VIRSH_ATTACH_DISK_SOURCE_TYPE_NONE,
    VIRSH_ATTACH_DISK_SOURCE_TYPE_FILE,
    VIRSH_ATTACH_DISK_SOURCE_TYPE_BLOCK,
    VIRSH_ATTACH_DISK_SOURCE_TYPE_NETWORK,

    VIRSH_ATTACH_DISK_SOURCE_TYPE_LAST
};

VIR_ENUM_DECL(virshAttachDiskSource);
VIR_ENUM_IMPL(virshAttachDiskSource,
              VIRSH_ATTACH_DISK_SOURCE_TYPE_LAST,
              "",
              "file",
              "block",
              "network");


static bool
cmdAttachDisk(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *source = NULL;
    const char *target = NULL;
    const char *driver = NULL;
    const char *subdriver = NULL;
    const char *device = NULL;
    const char *mode = NULL;
    const char *iothread = NULL;
    const char *cache = NULL;
    const char *io = NULL;
    const char *serial = NULL;
    const char *straddr = NULL;
    const char *wwn = NULL;
    const char *targetbus = NULL;
    const char *alias = NULL;
    const char *source_protocol = NULL;
    const char *host_name = NULL;
    const char *host_transport = NULL;
    const char *host_socket = NULL;
    int ret;
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;
    const char *stype = NULL;
    int type = VIR_STORAGE_TYPE_NONE;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) diskAttrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) diskChildBuf = VIR_BUFFER_INIT_CHILD(&buf);
    g_auto(virBuffer) driverAttrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) sourceAttrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) sourceChildBuf = VIR_BUFFER_INIT_CHILD(&diskChildBuf);
    g_auto(virBuffer) hostAttrBuf = VIR_BUFFER_INITIALIZER;
    g_autofree char *xml = NULL;
    struct stat st;
    bool current = vshCommandOptBool(cmd, "current");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool persistent = vshCommandOptBool(cmd, "persistent");
    bool multifunction = vshCommandOptBool(cmd, "multifunction");

    VSH_EXCLUSIVE_OPTIONS_VAR(persistent, current);

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    VSH_REQUIRE_OPTION("source-host-name", "source-protocol");
    VSH_REQUIRE_OPTION("source-host-transport", "source-protocol");
    VSH_REQUIRE_OPTION("source-host-socket", "source-protocol");
    VSH_REQUIRE_OPTION("source-host-socket", "source-host-transport");

    VSH_EXCLUSIVE_OPTIONS("source-host-name", "source-host-socket");

    if (config || persistent)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (vshCommandOptStringReq(ctl, cmd, "source", &source) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "target", &target) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "driver", &driver) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "subdriver", &subdriver) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "type", &device) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "mode", &mode) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "iothread", &iothread) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "cache", &cache) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "io", &io) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "serial", &serial) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "wwn", &wwn) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "address", &straddr) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "targetbus", &targetbus) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "alias", &alias) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "sourcetype", &stype) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "source-protocol", &source_protocol) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "source-host-name", &host_name) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "source-host-transport", &host_transport) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "source-host-socket", &host_socket) < 0)
        return false;

    if (stype &&
        (type = virshAttachDiskSourceTypeFromString(stype)) < 0) {
        vshError(ctl, _("Unknown source type: '%1$s'"), stype);
        return false;
    }

    if (type == VIRSH_ATTACH_DISK_SOURCE_TYPE_NONE) {
        if (source_protocol) {
            type = VIRSH_ATTACH_DISK_SOURCE_TYPE_NETWORK;
        } else  if (STRNEQ_NULLABLE(driver, "file") &&
                    STRNEQ_NULLABLE(driver, "tap") &&
                    source &&
                    stat(source, &st) == 0 &&
                    S_ISBLK(st.st_mode)) {
            type = VIRSH_ATTACH_DISK_SOURCE_TYPE_BLOCK;
        } else {
            type = VIRSH_ATTACH_DISK_SOURCE_TYPE_FILE;
        }
    }

    if ((type == VIRSH_ATTACH_DISK_SOURCE_TYPE_NETWORK) != !!source_protocol) {
        vshError(ctl, _("--source-protocol option requires --sourcetype network"));
        return false;
    }

    if (mode && STRNEQ(mode, "readonly") && STRNEQ(mode, "shareable")) {
        vshError(ctl, _("No support for %1$s in command 'attach-disk'"), mode);
        return false;
    }

    if (wwn && !virValidateWWN(wwn))
        return false;

    virBufferAsprintf(&diskAttrBuf, " type='%s'", virshAttachDiskSourceTypeToString(type));
    virBufferEscapeString(&diskAttrBuf, " device='%s'", device);
    if (vshCommandOptBool(cmd, "rawio"))
        virBufferAddLit(&diskAttrBuf, " rawio='yes'");

    virBufferEscapeString(&driverAttrBuf, " name='%s'", driver);
    virBufferEscapeString(&driverAttrBuf, " type='%s'", subdriver);
    virBufferEscapeString(&driverAttrBuf, " iothread='%s'", iothread);
    virBufferEscapeString(&driverAttrBuf, " cache='%s'", cache);
    virBufferEscapeString(&driverAttrBuf, " io='%s'", io);

    virXMLFormatElement(&diskChildBuf, "driver", &driverAttrBuf, NULL);

    switch ((enum virshAttachDiskSourceType) type) {
    case VIRSH_ATTACH_DISK_SOURCE_TYPE_FILE:
        virBufferEscapeString(&sourceAttrBuf, " file='%s'", source);
        break;

    case VIRSH_ATTACH_DISK_SOURCE_TYPE_BLOCK:
        virBufferEscapeString(&sourceAttrBuf, " dev='%s'", source);
        break;

    case VIRSH_ATTACH_DISK_SOURCE_TYPE_NETWORK:
        virBufferEscapeString(&sourceAttrBuf, " protocol='%s'", source_protocol);
        virBufferEscapeString(&sourceAttrBuf, " name='%s'", source);

        virBufferEscapeString(&hostAttrBuf, " transport='%s'", host_transport);
        virBufferEscapeString(&hostAttrBuf, " socket='%s'", host_socket);

        if (host_name) {
            g_autofree char *host_name_copy = g_strdup(host_name);
            char *host_port = strchr(host_name_copy, ':');

            if (host_port) {
                *host_port = '\0';
                host_port++;
            }

            virBufferEscapeString(&hostAttrBuf, " name='%s'", host_name_copy);
            virBufferEscapeString(&hostAttrBuf, " port='%s'", host_port);
        }
        virXMLFormatElement(&sourceChildBuf, "host", &hostAttrBuf, NULL);
        break;

    case VIRSH_ATTACH_DISK_SOURCE_TYPE_NONE:
    case VIRSH_ATTACH_DISK_SOURCE_TYPE_LAST:
        break;
    }
    virXMLFormatElement(&diskChildBuf, "source", &sourceAttrBuf, &sourceChildBuf);

    virBufferAsprintf(&diskChildBuf, "<target dev='%s'", target);
    if (targetbus)
        virBufferAsprintf(&diskChildBuf, " bus='%s'", targetbus);
    virBufferAddLit(&diskChildBuf, "/>\n");

    if (mode)
        virBufferAsprintf(&diskChildBuf, "<%s/>\n", mode);

    if (serial)
        virBufferAsprintf(&diskChildBuf, "<serial>%s</serial>\n", serial);

    if (alias)
        virBufferAsprintf(&diskChildBuf, "<alias name='%s'/>\n", alias);

    if (wwn)
        virBufferAsprintf(&diskChildBuf, "<wwn>%s</wwn>\n", wwn);

    if (straddr &&
        cmdAttachDiskFormatAddress(ctl, &diskChildBuf, straddr, target, multifunction) < 0)
        return false;

    virXMLFormatElement(&buf, "disk", &diskAttrBuf, &diskChildBuf);

    xml = virBufferContentAndReset(&buf);

    if (vshCommandOptBool(cmd, "print-xml")) {
        vshPrint(ctl, "%s", xml);
        return true;
    }

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (persistent &&
        virDomainIsActive(dom) == 1)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (flags || current)
        ret = virDomainAttachDeviceFlags(dom, xml, flags);
    else
        ret = virDomainAttachDevice(dom, xml);

    if (ret < 0) {
        vshError(ctl, "%s", _("Failed to attach disk"));
        return false;
    }


    vshPrintExtra(ctl, "%s", _("Disk attached successfully\n"));
    return true;
}

/*
 * "attach-interface" command
 */
static const vshCmdInfo info_attach_interface[] = {
    {.name = "help",
     .data = N_("attach network interface")
    },
    {.name = "desc",
     .data = N_("Attach new network interface.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_attach_interface[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "type",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("network interface type")
    },
    {.name = "source",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("source of network interface")
    },
    {.name = "target",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("target network name")
    },
    {.name = "mac",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("MAC address")
    },
    {.name = "script",
     .type = VSH_OT_STRING,
     .help = N_("script used to bridge network interface")
    },
    {.name = "model",
     .type = VSH_OT_STRING,
     .help = N_("model type")
    },
    {.name = "alias",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("custom alias name of interface device")
    },
    {.name = "inbound",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("control domain's incoming traffics")
    },
    {.name = "outbound",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("control domain's outgoing traffics")
    },
    VIRSH_COMMON_OPT_DOMAIN_PERSISTENT,
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = "print-xml",
     .type = VSH_OT_BOOL,
     .help = N_("print XML document rather than attach the interface")
    },
    {.name = "managed",
     .type = VSH_OT_BOOL,
     .help = N_("libvirt will automatically detach/attach the device from/to host")
    },
    {.name = "source-mode",
     .type = VSH_OT_STRING,
     .completer = virshDomainInterfaceSourceModeCompleter,
     .help = N_("mode attribute of <source/> element")
    },
    {.name = NULL}
};

VIR_ENUM_IMPL(virshDomainInterfaceSourceMode,
              VIRSH_DOMAIN_INTERFACE_SOURCE_MODE_LAST,
              "server",
              "client");

/* parse inbound and outbound which are in the format of
 * 'average,peak,burst,floor', in which peak and burst are optional,
 * thus 'average,,burst' and 'average,peak' are also legal. */

#define VIRSH_PARSE_RATE_FIELD(index, name) \
    do { \
        if (index < ntok && \
            *tok[index] != '\0' && \
            virStrToLong_ullp(tok[index], NULL, 10, &rate->name) < 0) { \
            vshError(ctl, _("field '%1$s' is malformed"), #name); \
            return -1; \
        } \
    } while (0)

static int
virshParseRateStr(vshControl *ctl,
                  const char *rateStr,
                  virNetDevBandwidthRate *rate)
{
    g_auto(GStrv) tok = NULL;
    size_t ntok;

    if (!(tok = g_strsplit(rateStr, ",", 0)))
        return -1;

    if ((ntok = g_strv_length(tok)) > 4) {
        vshError(ctl, _("Rate string '%1$s' has too many fields"), rateStr);
        return -1;
    }

    VIRSH_PARSE_RATE_FIELD(0, average);
    VIRSH_PARSE_RATE_FIELD(1, peak);
    VIRSH_PARSE_RATE_FIELD(2, burst);
    VIRSH_PARSE_RATE_FIELD(3, floor);

    return 0;
}

#undef VIRSH_PARSE_RATE_FIELD

static bool
cmdAttachInterface(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *mac = NULL, *target = NULL, *script = NULL,
               *type = NULL, *source = NULL, *model = NULL,
               *inboundStr = NULL, *outboundStr = NULL, *alias = NULL;
    const char *sourceModeStr = NULL;
    int sourceMode = -1;
    virNetDevBandwidthRate inbound = { 0 };
    virNetDevBandwidthRate outbound = { 0 };
    virDomainNetType typ;
    int ret;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_autofree char *xml = NULL;
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;
    bool current = vshCommandOptBool(cmd, "current");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool persistent = vshCommandOptBool(cmd, "persistent");
    bool managed = vshCommandOptBool(cmd, "managed");

    VSH_EXCLUSIVE_OPTIONS_VAR(persistent, current);

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (config || persistent)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (vshCommandOptStringReq(ctl, cmd, "type", &type) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "source", &source) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "target", &target) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "mac", &mac) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "script", &script) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "model", &model) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "alias", &alias) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "inbound", &inboundStr) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "outbound", &outboundStr) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "source-mode", &sourceModeStr) < 0)
        return false;

    /* check interface type */
    if ((int)(typ = virDomainNetTypeFromString(type)) < 0) {
        vshError(ctl, _("No support for %1$s in command 'attach-interface'"),
                 type);
        return false;
    }

    if (sourceModeStr &&
        (sourceMode = virshDomainInterfaceSourceModeTypeFromString(sourceModeStr)) < 0) {
        vshError(ctl, _("Invalid source mode: %1$s"), sourceModeStr);
        return false;
    }

    if (inboundStr) {
        if (virshParseRateStr(ctl, inboundStr, &inbound) < 0)
            return false;
        if (!inbound.average && !inbound.floor) {
            vshError(ctl, _("either inbound average or floor is mandatory"));
            return false;
        }
    }
    if (outboundStr) {
        if (virshParseRateStr(ctl, outboundStr, &outbound) < 0)
            return false;
        if (outbound.average == 0) {
            vshError(ctl, _("outbound average is mandatory"));
            return false;
        }
        if (outbound.floor) {
            vshError(ctl, _("outbound floor is unsupported yet"));
            return false;
        }
    }

    /* Make XML of interface */
    virBufferAsprintf(&buf, "<interface type='%s'", type);

    if (managed)
        virBufferAddLit(&buf, " managed='yes'>\n");
    else
        virBufferAddLit(&buf, ">\n");
    virBufferAdjustIndent(&buf, 2);

    switch (typ) {
    case VIR_DOMAIN_NET_TYPE_NETWORK:
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
        virBufferAsprintf(&buf, "<source %s='%s'/>\n",
                          virDomainNetTypeToString(typ), source);
        break;
    case VIR_DOMAIN_NET_TYPE_DIRECT:
        virBufferAsprintf(&buf, "<source dev='%s'/>\n", source);
        break;
    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
    {
        g_autofree char *pciaddrstr = g_strdup_printf("pci:%s", source);
        struct virshAddress addr = { 0 };

        if (virshAddressParse(pciaddrstr, false, &addr) < 0) {
            vshError(ctl, _("cannot parse pci address '%1$s' for network interface"),
                     source);
            return false;
        }

        virBufferAddLit(&buf, "<source>\n");
        virBufferAdjustIndent(&buf, 2);
        virshAddressFormat(&buf, &addr);
        virBufferAdjustIndent(&buf, -2);
        virBufferAddLit(&buf, "</source>\n");
        break;
    }

    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
        if (sourceMode < 0) {
            vshError(ctl, _("source-mode is mandatory"));
            return false;
        }
        virBufferAsprintf(&buf, "<source type='unix' path='%s' mode='%s'/>\n",
                          source,
                          virshDomainInterfaceSourceModeTypeToString(sourceMode));
        break;

    case VIR_DOMAIN_NET_TYPE_USER:
    case VIR_DOMAIN_NET_TYPE_ETHERNET:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_UDP:
    case VIR_DOMAIN_NET_TYPE_VDPA:
    case VIR_DOMAIN_NET_TYPE_INTERNAL:
    case VIR_DOMAIN_NET_TYPE_NULL:
    case VIR_DOMAIN_NET_TYPE_VDS:
    case VIR_DOMAIN_NET_TYPE_LAST:
        vshError(ctl, _("No support for %1$s in command 'attach-interface'"),
                 type);
        return false;
        break;
    }

    if (target != NULL)
        virBufferAsprintf(&buf, "<target dev='%s'/>\n", target);
    if (mac != NULL)
        virBufferAsprintf(&buf, "<mac address='%s'/>\n", mac);
    if (script != NULL)
        virBufferAsprintf(&buf, "<script path='%s'/>\n", script);
    if (model != NULL)
        virBufferAsprintf(&buf, "<model type='%s'/>\n", model);

    if (alias != NULL)
        virBufferAsprintf(&buf, "<alias name='%s'/>\n", alias);

    if (inboundStr || outboundStr) {
        virBufferAddLit(&buf, "<bandwidth>\n");
        virBufferAdjustIndent(&buf, 2);
        if (inboundStr && (inbound.average || inbound.floor)) {
            virBufferAddLit(&buf, "<inbound");
            if (inbound.average > 0)
                virBufferAsprintf(&buf, " average='%llu'", inbound.average);
            if (inbound.peak > 0)
                virBufferAsprintf(&buf, " peak='%llu'", inbound.peak);
            if (inbound.burst > 0)
                virBufferAsprintf(&buf, " burst='%llu'", inbound.burst);
            if (inbound.floor > 0)
                virBufferAsprintf(&buf, " floor='%llu'", inbound.floor);
            virBufferAddLit(&buf, "/>\n");
        }
        if (outboundStr && outbound.average > 0) {
            virBufferAsprintf(&buf, "<outbound average='%llu'", outbound.average);
            if (outbound.peak > 0)
                virBufferAsprintf(&buf, " peak='%llu'", outbound.peak);
            if (outbound.burst > 0)
                virBufferAsprintf(&buf, " burst='%llu'", outbound.burst);
            virBufferAddLit(&buf, "/>\n");
        }
        virBufferAdjustIndent(&buf, -2);
        virBufferAddLit(&buf, "</bandwidth>\n");
    }

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</interface>\n");

    xml = virBufferContentAndReset(&buf);

    if (vshCommandOptBool(cmd, "print-xml")) {
        vshPrint(ctl, "%s", xml);
        return true;
    }

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (persistent &&
        virDomainIsActive(dom) == 1)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (flags || current)
        ret = virDomainAttachDeviceFlags(dom, xml, flags);
    else
        ret = virDomainAttachDevice(dom, xml);

    if (ret != 0) {
        vshError(ctl, "%s", _("Failed to attach interface"));
        return false;
    }

    vshPrintExtra(ctl, "%s", _("Interface attached successfully\n"));

    return true;
}

/*
 * "autostart" command
 */
static const vshCmdInfo info_autostart[] = {
    {.name = "help",
     .data = N_("autostart a domain")
    },
    {.name = "desc",
     .data = N_("Configure a domain to be automatically started at boot.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_autostart[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_PERSISTENT),
    {.name = "disable",
     .type = VSH_OT_BOOL,
     .help = N_("disable autostarting")
    },
    {.name = NULL}
};

static bool
cmdAutostart(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *name;
    int autostart;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    autostart = !vshCommandOptBool(cmd, "disable");

    if (virDomainSetAutostart(dom, autostart) < 0) {
        if (autostart)
            vshError(ctl, _("Failed to mark domain '%1$s' as autostarted"), name);
        else
            vshError(ctl, _("Failed to unmark domain '%1$s' as autostarted"), name);
        return false;
    }

    if (autostart)
        vshPrintExtra(ctl, _("Domain '%1$s' marked as autostarted\n"), name);
    else
        vshPrintExtra(ctl, _("Domain '%1$s' unmarked as autostarted\n"), name);

    return true;
}

/*
 * "blkdeviotune" command
 */
static const vshCmdInfo info_blkdeviotune[] = {
    {.name = "help",
     .data = N_("Set or query a block device I/O tuning parameters.")
    },
    {.name = "desc",
     .data = N_("Set or query disk I/O parameters such as block throttling.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_blkdeviotune[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "device",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshDomainDiskTargetCompleter,
     .help = N_("block device")
    },
    {.name = "total_bytes_sec",
     .type = VSH_OT_ALIAS,
     .help = "total-bytes-sec"
    },
    {.name = "total-bytes-sec",
     .type = VSH_OT_INT,
     .help = N_("total throughput limit, as scaled integer (default bytes)")
    },
    {.name = "read_bytes_sec",
     .type = VSH_OT_ALIAS,
     .help = "read-bytes-sec"
    },
    {.name = "read-bytes-sec",
     .type = VSH_OT_INT,
     .help = N_("read throughput limit, as scaled integer (default bytes)")
    },
    {.name = "write_bytes_sec",
     .type = VSH_OT_ALIAS,
     .help = "write-bytes-sec"
    },
    {.name = "write-bytes-sec",
     .type = VSH_OT_INT,
     .help =  N_("write throughput limit, as scaled integer (default bytes)")
    },
    {.name = "total_iops_sec",
     .type = VSH_OT_ALIAS,
     .help = "total-iops-sec"
    },
    {.name = "total-iops-sec",
     .type = VSH_OT_INT,
     .help = N_("total I/O operations limit per second")
    },
    {.name = "read_iops_sec",
     .type = VSH_OT_ALIAS,
     .help = "read-iops-sec"
    },
    {.name = "read-iops-sec",
     .type = VSH_OT_INT,
     .help = N_("read I/O operations limit per second")
    },
    {.name = "write_iops_sec",
     .type = VSH_OT_ALIAS,
     .help = "write-iops-sec"
    },
    {.name = "write-iops-sec",
     .type = VSH_OT_INT,
     .help = N_("write I/O operations limit per second")
    },
    {.name = "total_bytes_sec_max",
     .type = VSH_OT_ALIAS,
     .help = "total-bytes-sec-max"
    },
    {.name = "total-bytes-sec-max",
     .type = VSH_OT_INT,
     .help = N_("total max, as scaled integer (default bytes)")
    },
    {.name = "read_bytes_sec_max",
     .type = VSH_OT_ALIAS,
     .help = "read-bytes-sec-max"
    },
    {.name = "read-bytes-sec-max",
     .type = VSH_OT_INT,
     .help = N_("read max, as scaled integer (default bytes)")
    },
    {.name = "write_bytes_sec_max",
     .type = VSH_OT_ALIAS,
     .help = "write-bytes-sec-max"
    },
    {.name = "write-bytes-sec-max",
     .type = VSH_OT_INT,
     .help = N_("write max, as scaled integer (default bytes)")
    },
    {.name = "total_iops_sec_max",
     .type = VSH_OT_ALIAS,
     .help = "total-iops-sec-max"
    },
    {.name = "total-iops-sec-max",
     .type = VSH_OT_INT,
     .help = N_("total I/O operations max")
    },
    {.name = "read_iops_sec_max",
     .type = VSH_OT_ALIAS,
     .help = "read-iops-sec-max"
    },
    {.name = "read-iops-sec-max",
     .type = VSH_OT_INT,
     .help = N_("read I/O operations max")
    },
    {.name = "write_iops_sec_max",
     .type = VSH_OT_ALIAS,
     .help = "write-iops-sec-max"
    },
    {.name = "write-iops-sec-max",
     .type = VSH_OT_INT,
     .help = N_("write I/O operations max")
    },
    {.name = "size_iops_sec",
     .type = VSH_OT_ALIAS,
     .help = "size-iops-sec"
    },
    {.name = "size-iops-sec",
     .type = VSH_OT_INT,
     .help = N_("I/O size in bytes")
    },
    {.name = "group_name",
     .type = VSH_OT_ALIAS,
     .help = "group-name"
    },
    {.name = "group-name",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("group name to share I/O quota between multiple drives")
    },
    {.name = "total_bytes_sec_max_length",
     .type = VSH_OT_ALIAS,
     .help = "total-bytes-sec-max-length"
    },
    {.name = "total-bytes-sec-max-length",
     .type = VSH_OT_INT,
     .help = N_("duration in seconds to allow total max bytes")
    },
    {.name = "read_bytes_sec_max_length",
     .type = VSH_OT_ALIAS,
     .help = "read-bytes-sec-max-length"
    },
    {.name = "read-bytes-sec-max-length",
     .type = VSH_OT_INT,
     .help = N_("duration in seconds to allow read max bytes")
    },
    {.name = "write_bytes_sec_max_length",
     .type = VSH_OT_ALIAS,
     .help = "write-bytes-sec-max-length"
    },
    {.name = "write-bytes-sec-max-length",
     .type = VSH_OT_INT,
     .help = N_("duration in seconds to allow write max bytes")
    },
    {.name = "total_iops_sec_max_length",
     .type = VSH_OT_ALIAS,
     .help = "total-iops-sec-max-length"
    },
    {.name = "total-iops-sec-max-length",
     .type = VSH_OT_INT,
     .help = N_("duration in seconds to allow total I/O operations max")
    },
    {.name = "read_iops_sec_max_length",
     .type = VSH_OT_ALIAS,
     .help = "read-iops-sec-max-length"
    },
    {.name = "read-iops-sec-max-length",
     .type = VSH_OT_INT,
     .help = N_("duration in seconds to allow read I/O operations max")
    },
    {.name = "write_iops_sec_max_length",
     .type = VSH_OT_ALIAS,
     .help = "write-iops-sec-max-length"
    },
    {.name = "write-iops-sec-max-length",
     .type = VSH_OT_INT,
     .help = N_("duration in seconds to allow write I/O operations max")
    },
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = NULL}
};

static bool
cmdBlkdeviotune(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *name, *disk;
    const char *group_name = NULL;
    unsigned long long value;
    int nparams = 0;
    int maxparams = 0;
    virTypedParameterPtr params = NULL;
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;
    size_t i;
    int rv = 0;
    bool current = vshCommandOptBool(cmd, "current");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool ret = false;

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (config)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        goto cleanup;

    if (vshCommandOptStringReq(ctl, cmd, "device", &disk) < 0)
        goto cleanup;

#define VSH_ADD_IOTUNE_SCALED(PARAM, CONST) \
    if ((rv = vshCommandOptScaledInt(ctl, cmd, #PARAM, &value, \
                                     1, ULLONG_MAX)) < 0) { \
        goto interror; \
    } else if (rv > 0) { \
        if (virTypedParamsAddULLong(&params, &nparams, &maxparams, \
                                    VIR_DOMAIN_BLOCK_IOTUNE_##CONST, \
                                    value) < 0) \
            goto save_error; \
    }

    VSH_ADD_IOTUNE_SCALED(total-bytes-sec, TOTAL_BYTES_SEC);
    VSH_ADD_IOTUNE_SCALED(read-bytes-sec, READ_BYTES_SEC);
    VSH_ADD_IOTUNE_SCALED(write-bytes-sec, WRITE_BYTES_SEC);
    VSH_ADD_IOTUNE_SCALED(total-bytes-sec-max, TOTAL_BYTES_SEC_MAX);
    VSH_ADD_IOTUNE_SCALED(read-bytes-sec-max, READ_BYTES_SEC_MAX);
    VSH_ADD_IOTUNE_SCALED(write-bytes-sec-max, WRITE_BYTES_SEC_MAX);
#undef VSH_ADD_IOTUNE_SCALED

#define VSH_ADD_IOTUNE(PARAM, CONST) \
    if ((rv = vshCommandOptULongLong(ctl, cmd, #PARAM, &value)) < 0) { \
        goto interror; \
    } else if (rv > 0) { \
        if (virTypedParamsAddULLong(&params, &nparams, &maxparams, \
                                    VIR_DOMAIN_BLOCK_IOTUNE_##CONST, \
                                    value) < 0) \
            goto save_error; \
    }

    VSH_ADD_IOTUNE(total-iops-sec, TOTAL_IOPS_SEC);
    VSH_ADD_IOTUNE(read-iops-sec, READ_IOPS_SEC);
    VSH_ADD_IOTUNE(write-iops-sec, WRITE_IOPS_SEC);
    VSH_ADD_IOTUNE(total-iops-sec-max, TOTAL_IOPS_SEC_MAX);
    VSH_ADD_IOTUNE(read-iops-sec-max, READ_IOPS_SEC_MAX);
    VSH_ADD_IOTUNE(write-iops-sec-max, WRITE_IOPS_SEC_MAX);
    VSH_ADD_IOTUNE(size-iops-sec, SIZE_IOPS_SEC);

    VSH_ADD_IOTUNE(total-bytes-sec-max-length, TOTAL_BYTES_SEC_MAX_LENGTH);
    VSH_ADD_IOTUNE(read-bytes-sec-max-length, READ_BYTES_SEC_MAX_LENGTH);
    VSH_ADD_IOTUNE(write-bytes-sec-max-length, WRITE_BYTES_SEC_MAX_LENGTH);
    VSH_ADD_IOTUNE(total-iops-sec-max-length, TOTAL_IOPS_SEC_MAX_LENGTH);
    VSH_ADD_IOTUNE(read-iops-sec-max-length, READ_IOPS_SEC_MAX_LENGTH);
    VSH_ADD_IOTUNE(write-iops-sec-max-length, WRITE_IOPS_SEC_MAX_LENGTH);
#undef VSH_ADD_IOTUNE

    if (vshCommandOptStringReq(ctl, cmd, "group-name", &group_name) < 0) {
        vshError(ctl, "%s", _("Unable to parse group-name parameter"));
        goto cleanup;
    }

    if (group_name) {
        if (virTypedParamsAddString(&params, &nparams, &maxparams,
                                    VIR_DOMAIN_BLOCK_IOTUNE_GROUP_NAME,
                                    group_name) < 0)
            goto save_error;
    }


    if (nparams == 0) {
        if (virDomainGetBlockIoTune(dom, NULL, NULL, &nparams, flags) != 0) {
            vshError(ctl, "%s",
                     _("Unable to get number of block I/O throttle parameters"));
            goto cleanup;
        }

        if (nparams == 0) {
            ret = true;
            goto cleanup;
        }

        params = g_new0(virTypedParameter, nparams);

        if (virDomainGetBlockIoTune(dom, disk, params, &nparams, flags) != 0) {
            vshError(ctl, "%s",
                     _("Unable to get block I/O throttle parameters"));
            goto cleanup;
        }

        for (i = 0; i < nparams; i++) {
            g_autofree char *str = vshGetTypedParamValue(ctl, &params[i]);
            vshPrint(ctl, "%-15s: %s\n", params[i].field, str);
        }
    } else {
        if (virDomainSetBlockIoTune(dom, disk, params, nparams, flags) < 0)
            goto error;
    }

    ret = true;

 cleanup:
    virTypedParamsFree(params, nparams);
    return ret;

 save_error:
    vshSaveLibvirtError();
 error:
    vshError(ctl, "%s", _("Unable to change block I/O throttle"));
    goto cleanup;

 interror:
    vshError(ctl, "%s", _("Unable to parse integer parameter"));
    goto cleanup;
}

/*
 * "blkiotune" command
 */
static const vshCmdInfo info_blkiotune[] = {
    {.name = "help",
     .data = N_("Get or set blkio parameters")
    },
    {.name = "desc",
     .data = N_("Get or set the current blkio parameters for a guest"
                " domain.\n"
                "    To get the blkio parameters use following command: \n\n"
                "    virsh # blkiotune <domain>")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_blkiotune[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "weight",
     .type = VSH_OT_INT,
     .help = N_("IO Weight")
    },
    {.name = "device-weights",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("per-device IO Weights, in the form of /path/to/device,weight,...")
    },
    {.name = "device-read-iops-sec",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("per-device read I/O limit per second, in the form of /path/to/device,read_iops_sec,...")
    },
    {.name = "device-write-iops-sec",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("per-device write I/O limit per second, in the form of /path/to/device,write_iops_sec,...")
    },
    {.name = "device-read-bytes-sec",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("per-device bytes read per second, in the form of /path/to/device,read_bytes_sec,...")
    },
    {.name = "device-write-bytes-sec",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("per-device bytes wrote per second, in the form of /path/to/device,write_bytes_sec,...")
    },
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = NULL}
};

static bool
cmdBlkiotune(vshControl * ctl, const vshCmd * cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *device_weight = NULL;
    const char *device_riops = NULL;
    const char *device_wiops = NULL;
    const char *device_rbps = NULL;
    const char *device_wbps = NULL;
    int weight = 0;
    int nparams = 0;
    int maxparams = 0;
    int rv = 0;
    size_t i;
    virTypedParameterPtr params = NULL;
    bool ret = false;
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;
    bool current = vshCommandOptBool(cmd, "current");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (config)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if ((rv = vshCommandOptInt(ctl, cmd, "weight", &weight)) < 0) {
        goto cleanup;
    } else if (rv > 0) {
        if (weight <= 0) {
            vshError(ctl, _("Invalid value of %1$d for I/O weight"), weight);
            goto cleanup;
        }
        if (virTypedParamsAddUInt(&params, &nparams, &maxparams,
                                  VIR_DOMAIN_BLKIO_WEIGHT, weight) < 0)
            goto save_error;
    }

    rv = vshCommandOptStringQuiet(ctl, cmd, "device-weights", &device_weight);
    if (rv < 0) {
        vshError(ctl, "%s", _("Unable to parse string parameter"));
        goto cleanup;
    } else if (rv > 0) {
        if (virTypedParamsAddString(&params, &nparams, &maxparams,
                                    VIR_DOMAIN_BLKIO_DEVICE_WEIGHT,
                                    device_weight) < 0)
            goto save_error;
    }

    rv = vshCommandOptStringQuiet(ctl, cmd, "device-read-iops-sec", &device_riops);
    if (rv < 0) {
        vshError(ctl, "%s", _("Unable to parse string parameter"));
        goto cleanup;
    } else if (rv > 0) {
        if (virTypedParamsAddString(&params, &nparams, &maxparams,
                                    VIR_DOMAIN_BLKIO_DEVICE_READ_IOPS,
                                    device_riops) < 0)
            goto save_error;
    }

    rv = vshCommandOptStringQuiet(ctl, cmd, "device-write-iops-sec", &device_wiops);
    if (rv < 0) {
        vshError(ctl, "%s", _("Unable to parse string parameter"));
        goto cleanup;
    } else if (rv > 0) {
        if (virTypedParamsAddString(&params, &nparams, &maxparams,
                                    VIR_DOMAIN_BLKIO_DEVICE_WRITE_IOPS,
                                    device_wiops) < 0)
            goto save_error;
    }

    rv = vshCommandOptStringQuiet(ctl, cmd, "device-read-bytes-sec", &device_rbps);
    if (rv < 0) {
        vshError(ctl, "%s", _("Unable to parse string parameter"));
        goto cleanup;
    } else if (rv > 0) {
        if (virTypedParamsAddString(&params, &nparams, &maxparams,
                                    VIR_DOMAIN_BLKIO_DEVICE_READ_BPS,
                                    device_rbps) < 0)
            goto save_error;
    }

    rv = vshCommandOptStringQuiet(ctl, cmd, "device-write-bytes-sec", &device_wbps);
    if (rv < 0) {
        vshError(ctl, "%s", _("Unable to parse string parameter"));
        goto cleanup;
    } else if (rv > 0) {
        if (virTypedParamsAddString(&params, &nparams, &maxparams,
                                   VIR_DOMAIN_BLKIO_DEVICE_WRITE_BPS,
                                   device_wbps) < 0)
            goto save_error;
    }

    if (nparams == 0) {
        /* get the number of blkio parameters */
        if (virDomainGetBlkioParameters(dom, NULL, &nparams, flags) != 0) {
            vshError(ctl, "%s",
                     _("Unable to get number of blkio parameters"));
            goto cleanup;
        }

        if (nparams == 0) {
            /* nothing to output */
            ret = true;
            goto cleanup;
        }

        /* now go get all the blkio parameters */
        params = g_new0(virTypedParameter, nparams);
        if (virDomainGetBlkioParameters(dom, params, &nparams, flags) != 0) {
            vshError(ctl, "%s", _("Unable to get blkio parameters"));
            goto cleanup;
        }

        for (i = 0; i < nparams; i++) {
            g_autofree char *str = vshGetTypedParamValue(ctl, &params[i]);
            vshPrint(ctl, "%-15s: %s\n", params[i].field, str);
        }
    } else {
        /* set the blkio parameters */
        if (virDomainSetBlkioParameters(dom, params, nparams, flags) < 0)
            goto error;
    }

    ret = true;

 cleanup:
    virTypedParamsFree(params, nparams);
    return ret;

 save_error:
    vshSaveLibvirtError();
 error:
    vshError(ctl, "%s", _("Unable to change blkio parameters"));
    goto cleanup;
}


static void
virshPrintJobProgress(const char *label, unsigned long long remaining,
                      unsigned long long total)
{
    double progress = 100.00;

    /* if remaining == 0 migration has completed */
    if (remaining != 0) {
        /* use double to avoid overflow */
        progress = 100.00 - remaining * 100.00 / total;
        if (progress >= 100.00) {
            /* migration has not completed, do not print [100 %] */
            progress = 99.99;
        }
    }

    /* see comments in vshError about why we must flush */
    fflush(stdout);
    /* avoid auto-round-off of double by keeping only 2 decimals */
    fprintf(stderr, "\r%s: [%5.2f %%]", label, (int)(progress*100)/100.0);
    fflush(stderr);
}

static volatile sig_atomic_t intCaught;

#ifndef WIN32
static void virshCatchInt(int sig G_GNUC_UNUSED,
                          siginfo_t *siginfo G_GNUC_UNUSED,
                          void *context G_GNUC_UNUSED)
{
    intCaught = 1;
}
#endif /* !WIN32 */


typedef struct _virshBlockJobWaitData virshBlockJobWaitData;
struct _virshBlockJobWaitData {
    vshControl *ctl;
    virDomainPtr dom;
    const char *dev;
    const char *job_name;

    bool verbose;
    unsigned int timeout;
    bool async_abort;

    int cb_id;
    int cb_id2;
    int status;
};


static void
virshBlockJobStatusHandler(virConnectPtr conn G_GNUC_UNUSED,
                           virDomainPtr dom G_GNUC_UNUSED,
                           const char *disk,
                           int type G_GNUC_UNUSED,
                           int status,
                           void *opaque)
{
    virshBlockJobWaitData *data = opaque;

    if (STREQ_NULLABLE(disk, data->dev))
        data->status = status;
}


/**
 * virshBlockJobWaitInit:
 * @ctl: vsh control structure
 * @dom: domain object
 * @dev: block device name to wait for
 * @job_name: block job name to display in user-facing messages
 * @verbose: enable progress reporting
 * @timeout: number of milliseconds to wait before aborting the job
 * @async_abort: abort the job asynchronously
 *
 * Prepares virsh for waiting for completion of a block job. This function
 * registers event handlers for block job events and prepares the data structures
 * for them. A call to virshBlockJobWait then waits for completion of the given
 * block job. This function should be tolerant to different versions of daemon
 * and the reporting capabilities of those.
 *
 * Returns the data structure that holds data needed for block job waiting or
 * NULL in case of error.
 */
static virshBlockJobWaitData *
virshBlockJobWaitInit(vshControl *ctl,
                      virDomainPtr dom,
                      const char *dev,
                      const char *job_name,
                      bool verbose,
                      unsigned int timeout,
                      bool async_abort)
{
    virConnectDomainEventGenericCallback cb;
    virshBlockJobWaitData *ret;
    virshControl *priv = ctl->privData;

    ret = g_new0(virshBlockJobWaitData, 1);

    ret->ctl = ctl;
    ret->dom = dom;
    ret->dev = dev;
    ret->job_name = job_name;

    ret->async_abort = async_abort;
    ret->timeout = timeout;
    ret->verbose = verbose;

    ret->status = -1;

    cb = VIR_DOMAIN_EVENT_CALLBACK(virshBlockJobStatusHandler);

    if ((ret->cb_id = virConnectDomainEventRegisterAny(priv->conn, dom,
                                                       VIR_DOMAIN_EVENT_ID_BLOCK_JOB,
                                                       cb, ret, NULL)) < 0)
        vshResetLibvirtError();

    if ((ret->cb_id2 = virConnectDomainEventRegisterAny(priv->conn, dom,
                                                        VIR_DOMAIN_EVENT_ID_BLOCK_JOB_2,
                                                        cb, ret, NULL)) < 0)
        vshResetLibvirtError();

    return ret;
}


static void
virshBlockJobWaitFree(virshBlockJobWaitData *data)
{
    virshControl *priv = NULL;

    if (!data)
        return;

    priv = data->ctl->privData;
    if (data->cb_id >= 0)
        virConnectDomainEventDeregisterAny(priv->conn, data->cb_id);
    if (data->cb_id2 >= 0)
        virConnectDomainEventDeregisterAny(priv->conn, data->cb_id2);

    g_free(data);
}


/**
 * virshBlockJobWait:
 * @data: private data initialized by virshBlockJobWaitInit
 *
 * Waits for the block job to complete. This function prefers to wait for a
 * matching VIR_DOMAIN_EVENT_ID_BLOCK_JOB or VIR_DOMAIN_EVENT_ID_BLOCK_JOB_2
 * event from libvirt; however, it has a fallback mode should either of these
 * events not be available.
 *
 * This function returns values from the virConnectDomainEventBlockJobStatus
 * enum or -1 in case of an internal error.
 *
 * If the fallback mode is activated the returned event is
 * VIR_DOMAIN_BLOCK_JOB_COMPLETED if the block job vanishes or
 * VIR_DOMAIN_BLOCK_JOB_READY if the block job reaches 100%.
 */
static int
virshBlockJobWait(virshBlockJobWaitData *data)
{
    /* For two phase jobs like active commit or block copy, the marker reaches
     * 100% and an event fires. In case where virsh would not be able to match
     * the event to the given block job we will wait for the number of retries
     * before claiming that we entered synchronised phase */
    unsigned int retries = 5;
#ifndef WIN32
    struct sigaction sig_action;
    struct sigaction old_sig_action;
    sigset_t sigmask, oldsigmask;
#endif /* !WIN32 */
    unsigned long long start = 0;
    unsigned long long curr = 0;

    unsigned int abort_flags = 0;
    int ret = -1;
    virDomainBlockJobInfo info, last;
    int result;

    if (!data)
        return 0;

    if (data->async_abort)
        abort_flags |= VIR_DOMAIN_BLOCK_JOB_ABORT_ASYNC;

#ifndef WIN32
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);

    intCaught = 0;
    sig_action.sa_sigaction = virshCatchInt;
    sig_action.sa_flags = SA_SIGINFO;
    sigemptyset(&sig_action.sa_mask);
    sigaction(SIGINT, &sig_action, &old_sig_action);
#endif /* !WIN32 */

    if (data->timeout && virTimeMillisNow(&start) < 0) {
        vshSaveLibvirtError();
        goto cleanup;
    }

    last.cur = last.end = 0;

    while (true) {
#ifndef WIN32
        pthread_sigmask(SIG_BLOCK, &sigmask, &oldsigmask);
#endif /* !WIN32 */
        result = virDomainGetBlockJobInfo(data->dom, data->dev, &info, 0);
#ifndef WIN32
        pthread_sigmask(SIG_SETMASK, &oldsigmask, NULL);
#endif /* !WIN32 */

        if (result < 0) {
            vshError(data->ctl, _("failed to query job for disk %1$s"), data->dev);
            goto cleanup;
        }

        /* If either callback could be registered and we've got an event, we can
         * can end the waiting loop */
        if ((data->cb_id >= 0 || data->cb_id2 >= 0) && data->status != -1) {
            ret = data->status;
            break;
        }

        /* Fallback behaviour is only needed if one or both callbacks could not
         * be registered */
        if (data->cb_id < 0 || data->cb_id2 < 0) {
            /* If the block job vanishes, synthesize a COMPLETED event */
            if (result == 0) {
                ret = VIR_DOMAIN_BLOCK_JOB_COMPLETED;
                break;
            }

            /* If the block job hits 100%, wait a little while for a possible
             * event from libvirt unless both callbacks could not be registered
             * in order to synthesize our own READY event */
            if (info.end == info.cur &&
                ((data->cb_id < 0 && data->cb_id2 < 0) || --retries == 0)) {
                ret = VIR_DOMAIN_BLOCK_JOB_READY;
                break;
            }
        }

        if (data->verbose && (info.cur != last.cur || info.end != last.end))
            virshPrintJobProgress(data->job_name, info.end - info.cur,
                                  info.end);
        last = info;

        if (data->timeout && virTimeMillisNow(&curr) < 0) {
            vshSaveLibvirtError();
            goto cleanup;
        }

        if (intCaught || (data->timeout && (curr - start > data->timeout))) {
            if (virDomainBlockJobAbort(data->dom, data->dev, abort_flags) < 0) {
                vshError(data->ctl, _("failed to abort job for disk '%1$s'"),
                         data->dev);
                goto cleanup;
            }

            ret = VIR_DOMAIN_BLOCK_JOB_CANCELED;
            break;
        }

        g_usleep(500 * 1000);
    }

    /* print 100% completed */
    if (data->verbose &&
        (ret == VIR_DOMAIN_BLOCK_JOB_COMPLETED ||
         ret == VIR_DOMAIN_BLOCK_JOB_READY))
        virshPrintJobProgress(data->job_name, 0, 1);

 cleanup:
#ifndef WIN32
    sigaction(SIGINT, &old_sig_action, NULL);
#endif /* !WIN32 */
    return ret;
}


/*
 * "blockcommit" command
 */
static const vshCmdInfo info_blockcommit[] = {
    {.name = "help",
     .data = N_("Start a block commit operation.")
    },
    {.name = "desc",
     .data = N_("Commit changes from a snapshot down to its backing image.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_blockcommit[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "path",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshDomainDiskTargetCompleter,
     .help = N_("fully-qualified path of disk")
    },
    {.name = "bandwidth",
     .type = VSH_OT_INT,
     .help = N_("bandwidth limit in MiB/s")
    },
    {.name = "base",
     .type = VSH_OT_STRING,
     .completer = virshDomainBlockjobBaseTopCompleter,
     .help = N_("path of base file to commit into (default bottom of chain)")
    },
    {.name = "shallow",
     .type = VSH_OT_BOOL,
     .help = N_("use backing file of top as base")
    },
    {.name = "top",
     .type = VSH_OT_STRING,
     .completer = virshDomainBlockjobBaseTopCompleter,
     .help = N_("path of top file to commit from (default top of chain)")
    },
    {.name = "active",
     .type = VSH_OT_BOOL,
     .help = N_("trigger two-stage active commit of top file")
    },
    {.name = "delete",
     .type = VSH_OT_BOOL,
     .help = N_("delete files that were successfully committed")
    },
    {.name = "wait",
     .type = VSH_OT_BOOL,
     .help = N_("wait for job to complete "
                "(with --active, wait for job to sync)")
    },
    {.name = "verbose",
     .type = VSH_OT_BOOL,
     .help = N_("with --wait, display the progress")
    },
    {.name = "timeout",
     .type = VSH_OT_INT,
     .help = N_("implies --wait, abort if copy exceeds timeout (in seconds)")
    },
    {.name = "pivot",
     .type = VSH_OT_BOOL,
     .help = N_("implies --active --wait, pivot when commit is synced")
    },
    {.name = "keep-overlay",
     .type = VSH_OT_BOOL,
     .help = N_("implies --active --wait, quit when commit is synced")
    },
    {.name = "async",
     .type = VSH_OT_BOOL,
     .help = N_("with --wait, don't wait for cancel to finish")
    },
    {.name = "keep-relative",
     .type = VSH_OT_BOOL,
     .help = N_("keep the backing chain relatively referenced")
    },
    {.name = "bytes",
     .type = VSH_OT_BOOL,
     .help = N_("the bandwidth limit is in bytes/s rather than MiB/s")
    },
    {.name = NULL}
};

static bool
cmdBlockcommit(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    bool ret = false;
    bool verbose = vshCommandOptBool(cmd, "verbose");
    bool pivot = vshCommandOptBool(cmd, "pivot");
    bool finish = vshCommandOptBool(cmd, "keep-overlay");
    bool active = vshCommandOptBool(cmd, "active") || pivot || finish;
    bool blocking = vshCommandOptBool(cmd, "wait") || pivot || finish;
    bool async = vshCommandOptBool(cmd, "async");
    bool bytes = vshCommandOptBool(cmd, "bytes");
    int timeout = 0;
    const char *path = NULL;
    const char *base = NULL;
    const char *top = NULL;
    int abort_flags = 0;
    unsigned int flags = 0;
    unsigned long bandwidth = 0;
    virshBlockJobWaitData *bjWait = NULL;

    VSH_EXCLUSIVE_OPTIONS("pivot", "keep-overlay");

    if (vshCommandOptStringReq(ctl, cmd, "path", &path) < 0)
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "base", &base) < 0)
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "top", &top) < 0)
        return false;

    if (vshBlockJobOptionBandwidth(ctl, cmd, bytes, &bandwidth) < 0)
        return false;

    if (bytes)
        flags |= VIR_DOMAIN_BLOCK_COMMIT_BANDWIDTH_BYTES;

    if (vshCommandOptBool(cmd, "shallow"))
        flags |= VIR_DOMAIN_BLOCK_COMMIT_SHALLOW;

    if (vshCommandOptBool(cmd, "delete"))
        flags |= VIR_DOMAIN_BLOCK_COMMIT_DELETE;

    if (active)
        flags |= VIR_DOMAIN_BLOCK_COMMIT_ACTIVE;

   if (vshCommandOptBool(cmd, "keep-relative"))
        flags |= VIR_DOMAIN_BLOCK_COMMIT_RELATIVE;

    if (vshCommandOptTimeoutToMs(ctl, cmd, &timeout) < 0)
        return false;

    if (timeout)
        blocking = true;

    if (!blocking) {
        if (verbose) {
            vshError(ctl, "%s", _("--verbose requires at least one of --timeout, --wait, --pivot, or --keep-overlay"));
            return false;
        }

        if (async) {
            vshError(ctl, "%s", _("--async requires at least one of --timeout, --wait, --pivot, or --keep-overlay"));
            return false;
        }
    }

    if (async)
        abort_flags |= VIR_DOMAIN_BLOCK_JOB_ABORT_ASYNC;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (blocking &&
        !(bjWait = virshBlockJobWaitInit(ctl, dom, path, _("Block commit"),
                                         verbose, timeout, async)))
        goto cleanup;

    if (virDomainBlockCommit(dom, path, base, top, bandwidth, flags) < 0)
        goto cleanup;

    if (!blocking) {
        if (active)
            vshPrintExtra(ctl, "%s", _("Active Block Commit started"));
        else
            vshPrintExtra(ctl, "%s", _("Block Commit started"));

        ret = true;
        goto cleanup;
    }

    /* Execution continues here only if --wait or friends were specified */
    switch (virshBlockJobWait(bjWait)) {
        case -1:
            goto cleanup;

        case VIR_DOMAIN_BLOCK_JOB_CANCELED:
            vshPrintExtra(ctl, "\n%s", _("Commit aborted"));
            goto cleanup;
            break;

        case VIR_DOMAIN_BLOCK_JOB_FAILED:
            vshPrintExtra(ctl, "\n%s", _("Commit failed"));
            goto cleanup;
            break;

        case VIR_DOMAIN_BLOCK_JOB_READY:
        case VIR_DOMAIN_BLOCK_JOB_COMPLETED:
            break;
    }

    if (active) {
        if (pivot) {
            abort_flags |= VIR_DOMAIN_BLOCK_JOB_ABORT_PIVOT;
            if (virDomainBlockJobAbort(dom, path, abort_flags) < 0) {
                vshError(ctl, _("failed to pivot job for disk %1$s"), path);
                goto cleanup;
            }

            vshPrintExtra(ctl, "\n%s", _("Successfully pivoted"));
        } else if (finish) {
            if (virDomainBlockJobAbort(dom, path, abort_flags) < 0) {
                vshError(ctl, _("failed to finish job for disk %1$s"), path);
                goto cleanup;
            }

            vshPrintExtra(ctl, "\n%s", _("Commit complete, overlay image kept"));
        } else {
            vshPrintExtra(ctl, "\n%s", _("Now in synchronized phase"));
        }
    } else {
        vshPrintExtra(ctl, "\n%s", _("Commit complete"));
    }

    ret = true;
 cleanup:
    virshBlockJobWaitFree(bjWait);
    return ret;
}

/*
 * "blockcopy" command
 */
static const vshCmdInfo info_blockcopy[] = {
    {.name = "help",
     .data = N_("Start a block copy operation.")
    },
    {.name = "desc",
     .data = N_("Copy a disk backing image chain to dest.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_blockcopy[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "path",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshDomainDiskTargetCompleter,
     .help = N_("fully-qualified path of source disk")
    },
    {.name = "dest",
     .type = VSH_OT_STRING,
     .help = N_("path of the copy to create")
    },
    {.name = "bandwidth",
     .type = VSH_OT_INT,
     .help = N_("bandwidth limit in MiB/s")
    },
    {.name = "shallow",
     .type = VSH_OT_BOOL,
     .help = N_("make the copy share a backing chain")
    },
    {.name = "reuse-external",
     .type = VSH_OT_BOOL,
     .help = N_("reuse existing destination")
    },
    {.name = "raw",
     .type = VSH_OT_ALIAS,
     .help = "format=raw"
    },
    {.name = "blockdev",
     .type = VSH_OT_BOOL,
     .help = N_("copy destination is block device instead of regular file")
    },
    {.name = "wait",
     .type = VSH_OT_BOOL,
     .help = N_("wait for job to reach mirroring phase")
    },
    {.name = "verbose",
     .type = VSH_OT_BOOL,
     .help = N_("with --wait, display the progress")
    },
    {.name = "timeout",
     .type = VSH_OT_INT,
     .help = N_("implies --wait, abort if copy exceeds timeout (in seconds)")
    },
    {.name = "pivot",
     .type = VSH_OT_BOOL,
     .help = N_("implies --wait, pivot when mirroring starts")
    },
    {.name = "finish",
     .type = VSH_OT_BOOL,
     .help = N_("implies --wait, quit when mirroring starts")
    },
    {.name = "async",
     .type = VSH_OT_BOOL,
     .help = N_("with --wait, don't wait for cancel to finish")
    },
    {.name = "xml",
     .type = VSH_OT_STRING,
     .completer = virshCompletePathLocalExisting,
     .help = N_("filename containing XML description of the copy destination")
    },
    {.name = "format",
     .type = VSH_OT_STRING,
     .flags = VSH_OFLAG_NONE,
     .completer = virshDomainStorageFileFormatCompleter,
     .help = N_("format of the destination file")
    },
    {.name = "granularity",
     .type = VSH_OT_INT,
     .help = N_("power-of-two granularity to use during the copy")
    },
    {.name = "buf-size",
     .type = VSH_OT_INT,
     .help = N_("maximum amount of in-flight data during the copy")
    },
    {.name = "bytes",
     .type = VSH_OT_BOOL,
     .help = N_("the bandwidth limit is in bytes/s rather than MiB/s")
    },
    {.name = "transient-job",
     .type = VSH_OT_BOOL,
     .help = N_("the copy job is not persisted if VM is turned off")
    },
    {.name = "synchronous-writes",
     .type = VSH_OT_BOOL,
     .help = N_("the copy job forces guest writes to be synchronously written to the destination")
    },
    {.name = "print-xml",
     .type = VSH_OT_BOOL,
     .help = N_("print the XML used to start the copy job instead of starting the job")
    },
    {.name = NULL}
};

static bool
cmdBlockcopy(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *dest = NULL;
    const char *format = NULL;
    unsigned long bandwidth = 0;
    unsigned int granularity = 0;
    unsigned long long buf_size = 0;
    unsigned int flags = 0;
    bool ret = false;
    bool verbose = vshCommandOptBool(cmd, "verbose");
    bool pivot = vshCommandOptBool(cmd, "pivot");
    bool finish = vshCommandOptBool(cmd, "finish");
    bool blockdev = vshCommandOptBool(cmd, "blockdev");
    bool blocking = vshCommandOptBool(cmd, "wait") || finish || pivot;
    bool async = vshCommandOptBool(cmd, "async");
    bool bytes = vshCommandOptBool(cmd, "bytes");
    bool transientjob = vshCommandOptBool(cmd, "transient-job");
    bool syncWrites = vshCommandOptBool(cmd, "synchronous-writes");
    int timeout = 0;
    const char *path = NULL;
    int abort_flags = 0;
    const char *xml = NULL;
    g_autofree char *xmlstr = NULL;
    bool print_xml = vshCommandOptBool(cmd, "print-xml");
    virTypedParameterPtr params = NULL;
    virshBlockJobWaitData *bjWait = NULL;
    int nparams = 0;

    if (vshCommandOptStringReq(ctl, cmd, "path", &path) < 0)
        return false;
    if (vshCommandOptStringReq(ctl, cmd, "dest", &dest) < 0)
        return false;
    if (vshCommandOptStringReq(ctl, cmd, "xml", &xml) < 0)
        return false;
    if (vshCommandOptStringReq(ctl, cmd, "format", &format) < 0)
        return false;
    if (vshBlockJobOptionBandwidth(ctl, cmd, bytes, &bandwidth) < 0)
        return false;
    if (vshCommandOptUInt(ctl, cmd, "granularity", &granularity) < 0)
        return false;
    if (vshCommandOptULongLong(ctl, cmd, "buf-size", &buf_size) < 0)
        return false;
    /* Exploit that some VIR_DOMAIN_BLOCK_REBASE_* and
     * VIR_DOMAIN_BLOCK_COPY_* flags have the same values.  */
    if (vshCommandOptBool(cmd, "shallow"))
        flags |= VIR_DOMAIN_BLOCK_REBASE_SHALLOW;
    if (vshCommandOptBool(cmd, "reuse-external"))
        flags |= VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT;
    if (transientjob)
        flags |= VIR_DOMAIN_BLOCK_COPY_TRANSIENT_JOB;
    if (syncWrites)
        flags |= VIR_DOMAIN_BLOCK_COPY_SYNCHRONOUS_WRITES;
    if (vshCommandOptTimeoutToMs(ctl, cmd, &timeout) < 0)
        return false;

    if (timeout)
        blocking = true;

    if (async)
        abort_flags |= VIR_DOMAIN_BLOCK_JOB_ABORT_ASYNC;

    VSH_EXCLUSIVE_OPTIONS_VAR(dest, xml);
    VSH_EXCLUSIVE_OPTIONS_VAR(format, xml);
    VSH_EXCLUSIVE_OPTIONS_VAR(blockdev, xml);
    VSH_EXCLUSIVE_OPTIONS_VAR(pivot, finish);

    if (!dest && !xml) {
        vshError(ctl, "%s", _("need either --dest or --xml"));
        return false;
    }

    if (!blocking) {
        if (verbose) {
            vshError(ctl, "%s", _("--verbose requires at least one of --timeout, --wait, --pivot, or --finish"));
            return false;
        }

        if (async) {
            vshError(ctl, "%s", _("--async requires at least one of --timeout, --wait, --pivot, or --finish"));
            return false;
        }
    }

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        goto cleanup;

    if (blocking &&
        !(bjWait = virshBlockJobWaitInit(ctl, dom, path, _("Block Copy"),
                                         verbose, timeout, async)))
        goto cleanup;

    if (xml) {
        if (virFileReadAll(xml, VSH_MAX_XML_FILE, &xmlstr) < 0) {
            vshReportError(ctl);
            goto cleanup;
        }
    }

    if (granularity || buf_size || (format && STRNEQ(format, "raw")) || xml ||
        transientjob || syncWrites || print_xml) {
        /* New API */
        if (bandwidth || granularity || buf_size) {
            params = g_new0(virTypedParameter, 3);
            if (bandwidth) {
                if (!bytes) {
                    /* bandwidth is ulong MiB/s, but the typed parameter is
                     * ullong bytes/s; make sure we don't overflow */
                    unsigned long long limit = MIN(ULONG_MAX, ULLONG_MAX >> 20);
                    if (bandwidth > limit) {
                        vshError(ctl, _("bandwidth must be less than %1$llu"), limit);
                        goto cleanup;
                    }

                    bandwidth <<= 20ULL;
                }
                if (virTypedParameterAssign(&params[nparams++],
                                            VIR_DOMAIN_BLOCK_COPY_BANDWIDTH,
                                            VIR_TYPED_PARAM_ULLONG,
                                            bandwidth) < 0)
                    goto cleanup;
            }
            if (granularity &&
                virTypedParameterAssign(&params[nparams++],
                                        VIR_DOMAIN_BLOCK_COPY_GRANULARITY,
                                        VIR_TYPED_PARAM_UINT,
                                        granularity) < 0)
                goto cleanup;
            if (buf_size &&
                virTypedParameterAssign(&params[nparams++],
                                        VIR_DOMAIN_BLOCK_COPY_BUF_SIZE,
                                        VIR_TYPED_PARAM_ULLONG,
                                        buf_size) < 0)
                goto cleanup;
        }

        if (!xmlstr) {
            g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
            g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
            g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(&buf);

            if (blockdev) {
                virBufferAddLit(&attrBuf, " type='block'");
                virBufferEscapeString(&childBuf, "<source dev='%s'/>\n", dest);
            } else {
                virBufferAddLit(&attrBuf, " type='file'");
                virBufferEscapeString(&childBuf, "<source file='%s'/>\n", dest);
            }

            virBufferEscapeString(&childBuf, "<driver type='%s'/>\n", format);
            virXMLFormatElement(&buf, "disk", &attrBuf, &childBuf);
            xmlstr = virBufferContentAndReset(&buf);
        }

        if (print_xml) {
            vshPrint(ctl, "%s", xmlstr);
            ret = true;
            goto cleanup;
        }

        if (virDomainBlockCopy(dom, path, xmlstr, params, nparams, flags) < 0)
            goto cleanup;
    } else {
        /* Old API */
        flags |= VIR_DOMAIN_BLOCK_REBASE_COPY;
        if (blockdev)
            flags |= VIR_DOMAIN_BLOCK_REBASE_COPY_DEV;
        if (STREQ_NULLABLE(format, "raw"))
            flags |= VIR_DOMAIN_BLOCK_REBASE_COPY_RAW;
        if (bytes)
            flags |= VIR_DOMAIN_BLOCK_REBASE_BANDWIDTH_BYTES;

        if (virDomainBlockRebase(dom, path, dest, bandwidth, flags) < 0)
            goto cleanup;
    }

    if (!blocking) {
        vshPrintExtra(ctl, "%s", _("Block Copy started"));
        ret = true;
        goto cleanup;
    }

    /* Execution continues here only if --wait or friends were specified */
    switch (virshBlockJobWait(bjWait)) {
        case -1:
            goto cleanup;

        case VIR_DOMAIN_BLOCK_JOB_CANCELED:
            vshPrintExtra(ctl, "\n%s", _("Copy aborted"));
            goto cleanup;
            break;

        case VIR_DOMAIN_BLOCK_JOB_FAILED:
            vshPrintExtra(ctl, "\n%s", _("Copy failed"));
            goto cleanup;
            break;

        case VIR_DOMAIN_BLOCK_JOB_READY:
        case VIR_DOMAIN_BLOCK_JOB_COMPLETED:
            break;
    }

    if (pivot) {
        abort_flags |= VIR_DOMAIN_BLOCK_JOB_ABORT_PIVOT;
        if (virDomainBlockJobAbort(dom, path, abort_flags) < 0) {
            vshError(ctl, _("failed to pivot job for disk %1$s"), path);
            goto cleanup;
        }

        vshPrintExtra(ctl, "\n%s", _("Successfully pivoted"));
    } else if (finish) {
        if (virDomainBlockJobAbort(dom, path, abort_flags) < 0) {
            vshError(ctl, _("failed to finish job for disk %1$s"), path);
            goto cleanup;
        }

        vshPrintExtra(ctl, "\n%s", _("Successfully copied"));
    } else {
        vshPrintExtra(ctl, "\n%s", _("Now in mirroring phase"));
    }

    ret = true;

 cleanup:
    virTypedParamsFree(params, nparams);
    virshBlockJobWaitFree(bjWait);
    return ret;
}

/*
 * "blockjob" command
 */
static const vshCmdInfo info_blockjob[] = {
    {.name = "help",
     .data = N_("Manage active block operations")
    },
    {.name = "desc",
     .data = N_("Query, adjust speed, or cancel active block operations.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_blockjob[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "path",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshDomainDiskTargetCompleter,
     .help = N_("fully-qualified path of disk")
    },
    {.name = "abort",
     .type = VSH_OT_BOOL,
     .help = N_("abort the active job on the specified disk")
    },
    {.name = "async",
     .type = VSH_OT_BOOL,
     .help = N_("implies --abort; request but don't wait for job end")
    },
    {.name = "pivot",
     .type = VSH_OT_BOOL,
     .help = N_("implies --abort; conclude and pivot a copy or commit job")
    },
    {.name = "info",
     .type = VSH_OT_BOOL,
     .help = N_("get active job information for the specified disk")
    },
    {.name = "bytes",
     .type = VSH_OT_BOOL,
     .help = N_("get/set bandwidth in bytes rather than MiB/s")
    },
    {.name = "raw",
     .type = VSH_OT_BOOL,
     .help = N_("implies --info; output details rather than human summary")
    },
    {.name = "bandwidth",
     .type = VSH_OT_INT,
     .help = N_("set the bandwidth limit in MiB/s")
    },
    {.name = NULL}
};

static bool
virshBlockJobInfo(vshControl *ctl,
                  virDomainPtr dom,
                  const char *path,
                  bool raw,
                  bool bytes)
{
    virDomainBlockJobInfo info;
    virshControl *priv = ctl->privData;
    unsigned long long speed;
    unsigned int flags = 0;
    int rc = -1;

    /* If bytes were requested, or if raw mode is not forcing a MiB/s
     * query and cache can't prove failure, then query bytes/sec.  */
    if (bytes || !(raw || priv->blockJobNoBytes)) {
        flags |= VIR_DOMAIN_BLOCK_JOB_INFO_BANDWIDTH_BYTES;
        rc = virDomainGetBlockJobInfo(dom, path, &info, flags);
        if (rc < 0) {
            /* Check for particular errors, let all the rest be fatal. */
            switch (last_error->code) {
            case VIR_ERR_INVALID_ARG:
                priv->blockJobNoBytes = true;
                G_GNUC_FALLTHROUGH;
            case VIR_ERR_OVERFLOW:
                if (!bytes && !raw) {
                    /* try again with MiB/s, unless forcing bytes */
                    vshResetLibvirtError();
                    break;
                }
                G_GNUC_FALLTHROUGH;
            default:
                return false;
            }
        }
        speed = info.bandwidth;
    }
    /* If we don't already have a query result, query for MiB/s */
    if (rc < 0) {
        flags &= ~VIR_DOMAIN_BLOCK_JOB_INFO_BANDWIDTH_BYTES;
        if ((rc = virDomainGetBlockJobInfo(dom, path, &info, flags)) < 0)
            return false;
        speed = info.bandwidth;
        /* Scale to bytes/s unless in raw mode */
        if (!raw) {
            speed <<= 20;
            if (speed >> 20 != info.bandwidth) {
                vshError(ctl, _("overflow in converting %1$ld MiB/s to bytes\n"),
                         info.bandwidth);
                return false;
            }
        }
    }

    if (rc == 0) {
        if (!raw)
            vshPrintExtra(ctl, _("No current block job for %1$s"), path);
        return true;
    }

    if (raw) {
        vshPrint(ctl, _(" type=%1$s\n bandwidth=%2$lu\n cur=%3$llu\n end=%4$llu\n"),
                 virshDomainBlockJobTypeToString(info.type),
                 info.bandwidth, info.cur, info.end);
    } else {
        virshPrintJobProgress(virshDomainBlockJobToString(info.type),
                              info.end - info.cur, info.end);
        if (speed) {
            const char *unit;
            double val = vshPrettyCapacity(speed, &unit);
            vshPrint(ctl, _("    Bandwidth limit: %1$llu bytes/s (%2$-.3lf %3$s/s)"),
                     speed, val, unit);
        }
        vshPrint(ctl, "\n");
    }

    return true;
}


static bool
virshBlockJobSetSpeed(vshControl *ctl,
                      const vshCmd *cmd,
                      virDomainPtr dom,
                      const char *path,
                      bool bytes)
{
    unsigned long bandwidth;
    unsigned int flags = 0;

    if (bytes)
        flags |= VIR_DOMAIN_BLOCK_JOB_SPEED_BANDWIDTH_BYTES;

    if (vshBlockJobOptionBandwidth(ctl, cmd, bytes, &bandwidth) < 0)
        return false;

    if (virDomainBlockJobSetSpeed(dom, path, bandwidth, flags) < 0)
        return false;

    return true;
}


static bool
virshBlockJobAbort(virDomainPtr dom,
                   const char *path,
                   bool pivot,
                   bool async)
{
    unsigned int flags = 0;

    if (async)
        flags |= VIR_DOMAIN_BLOCK_JOB_ABORT_ASYNC;
    if (pivot)
        flags |= VIR_DOMAIN_BLOCK_JOB_ABORT_PIVOT;

    if (virDomainBlockJobAbort(dom, path, flags) < 0)
        return false;

    return true;
}


static bool
cmdBlockjob(vshControl *ctl, const vshCmd *cmd)
{
    bool raw = vshCommandOptBool(cmd, "raw");
    bool bytes = vshCommandOptBool(cmd, "bytes");
    bool abortMode = vshCommandOptBool(cmd, "abort");
    bool pivot = vshCommandOptBool(cmd, "pivot");
    bool async = vshCommandOptBool(cmd, "async");
    bool info = vshCommandOptBool(cmd, "info");
    bool bandwidth = vshCommandOptBool(cmd, "bandwidth");
    g_autoptr(virshDomain) dom = NULL;
    const char *path;

    VSH_EXCLUSIVE_OPTIONS("raw", "abort");
    VSH_EXCLUSIVE_OPTIONS_VAR(raw, pivot);
    VSH_EXCLUSIVE_OPTIONS_VAR(raw, async);
    VSH_EXCLUSIVE_OPTIONS_VAR(raw, bandwidth);

    VSH_EXCLUSIVE_OPTIONS("info", "abort");
    VSH_EXCLUSIVE_OPTIONS_VAR(info, pivot);
    VSH_EXCLUSIVE_OPTIONS_VAR(info, async);
    VSH_EXCLUSIVE_OPTIONS_VAR(info, bandwidth);

    VSH_EXCLUSIVE_OPTIONS("bytes", "abort");
    VSH_EXCLUSIVE_OPTIONS_VAR(bytes, pivot);
    VSH_EXCLUSIVE_OPTIONS_VAR(bytes, async);

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    /* XXX Allow path to be optional to list info on all devices at once */
    if (vshCommandOptStringReq(ctl, cmd, "path", &path) < 0)
        return false;

    if (bandwidth)
        return virshBlockJobSetSpeed(ctl, cmd, dom, path, bytes);
    if (abortMode || pivot || async)
        return virshBlockJobAbort(dom, path, pivot, async);
    return virshBlockJobInfo(ctl, dom, path, raw, bytes);
}

/*
 * "blockpull" command
 */
static const vshCmdInfo info_blockpull[] = {
    {.name = "help",
     .data = N_("Populate a disk from its backing image.")
    },
    {.name = "desc",
     .data = N_("Populate a disk from its backing image.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_blockpull[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "path",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshDomainDiskTargetCompleter,
     .help = N_("fully-qualified path of disk")
    },
    {.name = "bandwidth",
     .type = VSH_OT_INT,
     .help = N_("bandwidth limit in MiB/s")
    },
    {.name = "base",
     .type = VSH_OT_STRING,
     .completer = virshDomainBlockjobBaseTopCompleter,
     .help = N_("path of backing file in chain for a partial pull")
    },
    {.name = "wait",
     .type = VSH_OT_BOOL,
     .help = N_("wait for job to finish")
    },
    {.name = "verbose",
     .type = VSH_OT_BOOL,
     .help = N_("with --wait, display the progress")
    },
    {.name = "timeout",
     .type = VSH_OT_INT,
     .help = N_("with --wait, abort if pull exceeds timeout (in seconds)")
    },
    {.name = "async",
     .type = VSH_OT_BOOL,
     .help = N_("with --wait, don't wait for cancel to finish")
    },
    {.name = "keep-relative",
     .type = VSH_OT_BOOL,
     .help = N_("keep the backing chain relatively referenced")
    },
    {.name = "bytes",
     .type = VSH_OT_BOOL,
     .help = N_("the bandwidth limit is in bytes/s rather than MiB/s")
    },
    {.name = NULL}
};

static bool
cmdBlockpull(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    bool ret = false;
    bool blocking = vshCommandOptBool(cmd, "wait");
    bool verbose = vshCommandOptBool(cmd, "verbose");
    bool async = vshCommandOptBool(cmd, "async");
    bool bytes = vshCommandOptBool(cmd, "bytes");
    int timeout = 0;
    const char *path = NULL;
    const char *base = NULL;
    unsigned long bandwidth = 0;
    unsigned int flags = 0;
    virshBlockJobWaitData *bjWait = NULL;

    VSH_REQUIRE_OPTION("verbose", "wait");
    VSH_REQUIRE_OPTION("async", "wait");

    if (vshCommandOptStringReq(ctl, cmd, "path", &path) < 0)
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "base", &base) < 0)
        return false;

    if (vshBlockJobOptionBandwidth(ctl, cmd, bytes, &bandwidth) < 0)
        return false;

    if (vshCommandOptTimeoutToMs(ctl, cmd, &timeout) < 0)
        return false;

    if (vshCommandOptBool(cmd, "keep-relative"))
        flags |= VIR_DOMAIN_BLOCK_REBASE_RELATIVE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (blocking &&
        !(bjWait = virshBlockJobWaitInit(ctl, dom, path, _("Block Pull"),
                                         verbose, timeout, async)))
        goto cleanup;

    if (base || flags) {
        if (bytes)
            flags |= VIR_DOMAIN_BLOCK_REBASE_BANDWIDTH_BYTES;

        if (virDomainBlockRebase(dom, path, base, bandwidth, flags) < 0)
            goto cleanup;
    } else {
        if (bytes)
            flags |= VIR_DOMAIN_BLOCK_PULL_BANDWIDTH_BYTES;

        if (virDomainBlockPull(dom, path, bandwidth, flags) < 0)
            goto cleanup;
    }

    if (!blocking) {
        vshPrintExtra(ctl, "%s", _("Block Pull started"));
        ret = true;
        goto cleanup;
    }

    /* Execution continues here only if --wait or friends were specified */
    switch (virshBlockJobWait(bjWait)) {
        case -1:
            goto cleanup;

        case VIR_DOMAIN_BLOCK_JOB_CANCELED:
            vshPrintExtra(ctl, "\n%s", _("Pull aborted"));
            goto cleanup;
            break;

        case VIR_DOMAIN_BLOCK_JOB_FAILED:
            vshPrintExtra(ctl, "\n%s", _("Pull failed"));
            goto cleanup;
            break;

        case VIR_DOMAIN_BLOCK_JOB_READY:
        case VIR_DOMAIN_BLOCK_JOB_COMPLETED:
            vshPrintExtra(ctl, "\n%s", _("Pull complete"));
            break;
    }

    ret = true;

 cleanup:
    virshBlockJobWaitFree(bjWait);
    return ret;
}

/*
 * "blockresize" command
 */
static const vshCmdInfo info_blockresize[] = {
    {.name = "help",
     .data = N_("Resize block device of domain.")
    },
    {.name = "desc",
     .data = N_("Resize block device of domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_blockresize[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "path",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshDomainDiskTargetCompleter,
     .help = N_("Fully-qualified path of block device")
    },
    {.name = "size",
     .type = VSH_OT_INT,
     .flags = VSH_OFLAG_REQ,
     .help = N_("New size of the block device, as scaled integer (default KiB)")
    },
    {.name = NULL}
};

static bool
cmdBlockresize(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *path = NULL;
    unsigned long long size = 0;
    unsigned int flags = 0;

    if (vshCommandOptStringReq(ctl, cmd, "path", (const char **) &path) < 0)
        return false;

    if (vshCommandOptScaledInt(ctl, cmd, "size", &size, 1024, ULLONG_MAX) < 0)
        return false;

    /* Prefer the older interface of KiB.  */
    if (size % 1024 == 0)
        size /= 1024;
    else
        flags |= VIR_DOMAIN_BLOCK_RESIZE_BYTES;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virDomainBlockResize(dom, path, size, flags) < 0) {
        vshError(ctl, _("Failed to resize block device '%1$s'"), path);
        return false;
    }

    vshPrintExtra(ctl, _("Block device '%1$s' is resized"), path);
    return true;
}

#ifndef WIN32
/*
 * "console" command
 */
static const vshCmdInfo info_console[] = {
    {.name = "help",
     .data = N_("connect to the guest console")
    },
    {.name = "desc",
     .data = N_("Connect the virtual serial console for the guest")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_console[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "devname", /* sc_prohibit_devname */
     .type = VSH_OT_STRING,
     .completer = virshDomainConsoleCompleter,
     .help = N_("character device name")
    },
    {.name = "force",
     .type = VSH_OT_BOOL,
     .help =  N_("force console connection (disconnect already connected sessions)")
    },
    {.name = "resume",
     .type = VSH_OT_BOOL,
     .help =  N_("resume a paused guest after connecting to console")
    },
    {.name = "safe",
     .type = VSH_OT_BOOL,
     .help =  N_("only connect if safe console handling is supported")
    },
    {.name = NULL}
};

static bool
cmdRunConsole(vshControl *ctl, virDomainPtr dom,
              const char *name,
              const bool resume_domain,
              unsigned int flags)
{
    int state;
    virshControl *priv = ctl->privData;

    if ((state = virshDomainState(ctl, dom, NULL)) < 0) {
        vshError(ctl, "%s", _("Unable to get domain status"));
        return false;
    }

    if (state == VIR_DOMAIN_SHUTOFF) {
        vshError(ctl, "%s", _("The domain is not running"));
        return false;
    }

    if (!isatty(STDIN_FILENO)) {
        vshError(ctl, "%s", _("Cannot run interactive console without a controlling TTY"));
        return false;
    }

    vshPrintExtra(ctl, _("Connected to domain '%1$s'\n"), virDomainGetName(dom));
    vshPrintExtra(ctl, _("Escape character is %1$s"), priv->escapeChar);
    if (priv->escapeChar[0] == '^')
        vshPrintExtra(ctl, " (Ctrl + %c)", priv->escapeChar[1]);
    vshPrintExtra(ctl, "\n");
    fflush(stdout);
    if (virshRunConsole(ctl, dom, name, resume_domain, flags) == 0)
        return true;

    return false;
}

static bool
cmdConsole(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    bool force = vshCommandOptBool(cmd, "force");
    bool resume = vshCommandOptBool(cmd, "resume");
    bool safe = vshCommandOptBool(cmd, "safe");
    unsigned int flags = 0;
    const char *name = NULL;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "devname", &name) < 0) /* sc_prohibit_devname */
        return false;

    if (force)
        flags |= VIR_DOMAIN_CONSOLE_FORCE;
    if (safe)
        flags |= VIR_DOMAIN_CONSOLE_SAFE;

    return cmdRunConsole(ctl, dom, name, resume, flags);
}
#endif /* WIN32 */

/* "domif-setlink" command
 */
static const vshCmdInfo info_domif_setlink[] = {
    {.name = "help",
     .data = N_("set link state of a virtual interface")
    },
    {.name = "desc",
     .data = N_("Set link state of a domain's virtual interface. This command "
                "wraps usage of update-device command.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domif_setlink[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "interface",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshDomainInterfaceCompleter,
     .help = N_("interface device (MAC Address)")
    },
    {.name = "state",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshDomainInterfaceStateCompleter,
     .help = N_("new state of the device")
    },
    {.name = "persistent",
     .type = VSH_OT_ALIAS,
     .help = "config"
    },
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    {.name = "print-xml",
     .type = VSH_OT_BOOL,
     .help = N_("print XML document rather than set the interface link state")
    },
    {.name = NULL}
};

static bool
cmdDomIfSetLink(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *iface;
    const char *state;
    unsigned int flags = 0;
    unsigned int xmlflags = 0;
    size_t i;
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    g_autofree char *xml_buf = NULL;
    g_autofree xmlNodePtr *nodes = NULL;
    ssize_t nnodes;
    xmlNodePtr ifaceNode = NULL;
    xmlNodePtr linkNode = NULL;
    xmlAttrPtr stateAttr;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "interface", &iface) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "state", &state) < 0)
        return false;

    if (STRNEQ(state, "up") && STRNEQ(state, "down")) {
        vshError(ctl, _("invalid link state '%1$s'"), state);
        return false;
    }

    if (vshCommandOptBool(cmd, "config")) {
        flags = VIR_DOMAIN_AFFECT_CONFIG;
        xmlflags |= VIR_DOMAIN_XML_INACTIVE;
    } else {
        flags = VIR_DOMAIN_AFFECT_LIVE;
    }

    if (virDomainIsActive(dom) == 0)
        flags = VIR_DOMAIN_AFFECT_CONFIG;

    if (virshDomainGetXMLFromDom(ctl, dom, xmlflags, &xml, &ctxt) < 0)
        return false;

    if ((nnodes = virXPathNodeSet("/domain/devices/interface", ctxt, &nodes)) <= 0) {
        vshError(ctl, _("Failed to extract interface information or no interfaces found"));
        return false;
    }

    for (i = 0; i < nnodes; i++) {
        g_autofree char *macaddr = NULL;
        g_autofree char *target = NULL;

        ctxt->node = nodes[i];

        if ((macaddr = virXPathString("string(./mac/@address)", ctxt)) &&
            STRCASEEQ(macaddr, iface)) {
            ifaceNode = nodes[i];
            break;
        }

        if ((target = virXPathString("string(./target/@dev)", ctxt)) &&
            STRCASEEQ(target, iface)) {
            ifaceNode = nodes[i];
            break;
        }
    }

    if (!ifaceNode) {
        vshError(ctl, _("interface '%1$s' not found"), iface);
        return false;
    }

    ctxt->node = ifaceNode;

    /* try to find <link> element or create new one */
    if (!(linkNode = virXPathNode("./link", ctxt))) {
        if (!(linkNode = xmlNewChild(ifaceNode, NULL, BAD_CAST "link", NULL))) {
            vshError(ctl, _("failed to create XML node"));
            return false;
        }
    }

    if (xmlHasProp(linkNode, BAD_CAST "state"))
        stateAttr = xmlSetProp(linkNode, BAD_CAST "state", BAD_CAST state);
    else
        stateAttr = xmlNewProp(linkNode, BAD_CAST "state", BAD_CAST state);

    if (!stateAttr) {
        vshError(ctl, _("Failed to create or modify the state XML attribute"));
        return false;
    }

    if (!(xml_buf = virXMLNodeToString(xml, ifaceNode))) {
        vshSaveLibvirtError();
        vshError(ctl, _("Failed to create XML"));
        return false;
    }

    if (vshCommandOptBool(cmd, "print-xml")) {
        vshPrint(ctl, "%s", xml_buf);
        return true;
    }

    if (virDomainUpdateDeviceFlags(dom, xml_buf, flags) < 0) {
        vshError(ctl, _("Failed to update interface link state"));
        return false;
    }

    vshPrintExtra(ctl, "%s", _("Device updated successfully\n"));

    return true;
}

/* "domiftune" command
 */
static const vshCmdInfo info_domiftune[] = {
    {.name = "help",
     .data = N_("get/set parameters of a virtual interface")
    },
    {.name = "desc",
     .data = N_("Get/set parameters of a domain's virtual interface.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domiftune[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "interface",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshDomainInterfaceCompleter,
     .help = N_("interface device (MAC Address)")
    },
    {.name = "inbound",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("control domain's incoming traffics")
    },
    {.name = "outbound",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("control domain's outgoing traffics")
    },
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = NULL}
};

static bool
cmdDomIftune(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *name = NULL, *device = NULL,
               *inboundStr = NULL, *outboundStr = NULL;
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;
    int nparams = 0;
    int maxparams = 0;
    virTypedParameterPtr params = NULL;
    bool ret = false;
    bool current = vshCommandOptBool(cmd, "current");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    virNetDevBandwidthRate inbound = { 0 };
    virNetDevBandwidthRate outbound = { 0 };
    size_t i;

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (config)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "interface", &device) < 0)
        goto cleanup;

    if (vshCommandOptStringReq(ctl, cmd, "inbound", &inboundStr) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "outbound", &outboundStr) < 0)
        goto cleanup;

    if (inboundStr) {
        if (virshParseRateStr(ctl, inboundStr, &inbound) < 0)
            goto cleanup;
        /* we parse the rate as unsigned long long, but the API
         * only accepts UINT */
        if (inbound.average > UINT_MAX || inbound.peak > UINT_MAX ||
            inbound.burst > UINT_MAX) {
            vshError(ctl, _("inbound rate larger than maximum %1$u"),
                     UINT_MAX);
            goto cleanup;
        }

        if ((!inbound.average && (inbound.burst || inbound.peak)) &&
            !inbound.floor) {
            vshError(ctl, _("either inbound average or floor is mandatory"));
            goto cleanup;
        }

        if (virTypedParamsAddUInt(&params, &nparams, &maxparams,
                                  VIR_DOMAIN_BANDWIDTH_IN_AVERAGE,
                                  inbound.average) < 0)
            goto save_error;

        if (inbound.peak &&
            virTypedParamsAddUInt(&params, &nparams, &maxparams,
                                  VIR_DOMAIN_BANDWIDTH_IN_PEAK,
                                  inbound.peak) < 0)
            goto save_error;

        if (inbound.burst &&
            virTypedParamsAddUInt(&params, &nparams, &maxparams,
                                  VIR_DOMAIN_BANDWIDTH_IN_BURST,
                                  inbound.burst) < 0)
            goto save_error;

        if (inbound.floor &&
            virTypedParamsAddUInt(&params, &nparams, &maxparams,
                                  VIR_DOMAIN_BANDWIDTH_IN_FLOOR,
                                  inbound.floor) < 0)
            goto save_error;
    }

    if (outboundStr) {
        if (virshParseRateStr(ctl, outboundStr, &outbound) < 0)
            goto cleanup;
        if (outbound.average > UINT_MAX || outbound.peak > UINT_MAX ||
            outbound.burst > UINT_MAX) {
            vshError(ctl, _("outbound rate larger than maximum %1$u"),
                     UINT_MAX);
            goto cleanup;
        }
        if (outbound.average == 0 && (outbound.burst || outbound.peak)) {
            vshError(ctl, _("outbound average is mandatory"));
            goto cleanup;
        }

        if (outbound.floor) {
            vshError(ctl, _("outbound floor is unsupported yet"));
            goto cleanup;
        }

        if (virTypedParamsAddUInt(&params, &nparams, &maxparams,
                                  VIR_DOMAIN_BANDWIDTH_OUT_AVERAGE,
                                  outbound.average) < 0)
            goto save_error;

        if (outbound.peak &&
            virTypedParamsAddUInt(&params, &nparams, &maxparams,
                                  VIR_DOMAIN_BANDWIDTH_OUT_PEAK,
                                  outbound.peak) < 0)
            goto save_error;

        if (outbound.burst &&
            virTypedParamsAddUInt(&params, &nparams, &maxparams,
                                  VIR_DOMAIN_BANDWIDTH_OUT_BURST,
                                  outbound.burst) < 0)
            goto save_error;
    }

    if (nparams == 0) {
        /* get the number of interface parameters */
        if (virDomainGetInterfaceParameters(dom, device, NULL, &nparams, flags) != 0) {
            vshError(ctl, "%s",
                     _("Unable to get number of interface parameters"));
            goto cleanup;
        }

        if (nparams == 0) {
            /* nothing to output */
            ret = true;
            goto cleanup;
        }

        /* get all interface parameters */
        params = g_new0(virTypedParameter, nparams);
        if (virDomainGetInterfaceParameters(dom, device, params, &nparams, flags) != 0) {
            vshError(ctl, "%s", _("Unable to get interface parameters"));
            goto cleanup;
        }

        for (i = 0; i < nparams; i++) {
            g_autofree char *str = vshGetTypedParamValue(ctl, &params[i]);
            vshPrint(ctl, "%-15s: %s\n", params[i].field, str);
        }
    } else {
        if (virDomainSetInterfaceParameters(dom, device, params,
                                            nparams, flags) != 0)
            goto error;
    }

    ret = true;

 cleanup:
    virTypedParamsFree(params, nparams);
    return ret;

 save_error:
    vshSaveLibvirtError();
 error:
    vshError(ctl, "%s", _("Unable to set interface parameters"));
    goto cleanup;
}

/*
 * "suspend" command
 */
static const vshCmdInfo info_suspend[] = {
    {.name = "help",
     .data = N_("suspend a domain")
    },
    {.name = "desc",
     .data = N_("Suspend a running domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_suspend[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_RUNNING),
    {.name = NULL}
};

static bool
cmdSuspend(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *name;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (virDomainSuspend(dom) != 0) {
        vshError(ctl, _("Failed to suspend domain '%1$s'"), name);
        return false;
    }

    vshPrintExtra(ctl, _("Domain '%1$s' suspended\n"), name);
    return true;
}

/*
 * "dompmsuspend" command
 */
static const vshCmdInfo info_dom_pm_suspend[] = {
    {.name = "help",
     .data = N_("suspend a domain gracefully using power management "
                "functions")
    },
    {.name = "desc",
     .data = N_("Suspends a running domain using guest OS's power management. "
                "(Note: This requires a guest agent configured and running in "
                "the guest OS).")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_dom_pm_suspend[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_RUNNING),
    {.name = "target",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshNodeSuspendTargetCompleter,
     .help = N_("mem(Suspend-to-RAM), "
                "disk(Suspend-to-Disk), "
                "hybrid(Hybrid-Suspend)")
    },
    {.name = "duration",
     .type = VSH_OT_INT,
     .flags = VSH_OFLAG_REQ_OPT,
     .help = N_("duration in seconds")
    },
    {.name = NULL}
};

static bool
cmdDomPMSuspend(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *name;
    const char *target = NULL;
    int suspendTarget;
    unsigned long long duration = 0;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (vshCommandOptULongLong(ctl, cmd, "duration", &duration) < 0)
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "target", &target) < 0)
        return false;

    if ((suspendTarget = virshNodeSuspendTargetTypeFromString(target)) < 0) {
        vshError(ctl, "%s", _("Invalid target"));
        return false;
    }

    if (virDomainPMSuspendForDuration(dom, suspendTarget, duration, 0) < 0) {
        vshError(ctl, _("Domain '%1$s' could not be suspended"),
                 virDomainGetName(dom));
        return false;
    }

    vshPrintExtra(ctl, _("Domain '%1$s' successfully suspended"),
             virDomainGetName(dom));

    return true;
}

/*
 * "dompmwakeup" command
 */

static const vshCmdInfo info_dom_pm_wakeup[] = {
    {.name = "help",
     .data = N_("wakeup a domain from pmsuspended state")
    },
    {.name = "desc",
     .data = N_("Wakeup a domain that was previously suspended "
                "by power management.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_dom_pm_wakeup[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_OTHER),
    {.name = NULL}
};

static bool
cmdDomPMWakeup(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *name;
    unsigned int flags = 0;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (virDomainPMWakeup(dom, flags) < 0) {
        vshError(ctl, _("Domain '%1$s' could not be woken up"),
                 virDomainGetName(dom));
        return false;
    }

    vshPrintExtra(ctl, _("Domain '%1$s' successfully woken up"),
                  virDomainGetName(dom));

    return true;
}

/*
 * "undefine" command
 */
static const vshCmdInfo info_undefine[] = {
    {.name = "help",
     .data = N_("undefine a domain")
    },
    {.name = "desc",
     .data = N_("Undefine an inactive domain, or convert persistent to transient.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_undefine[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_PERSISTENT),
    {.name = "managed-save",
     .type = VSH_OT_BOOL,
     .help = N_("remove domain managed state file")
    },
    {.name = "storage",
     .type = VSH_OT_STRING,
     .completer = virshDomainUndefineStorageDisksCompleter,
     .help = N_("remove associated storage volumes (comma separated list of "
                "targets or source paths) (see domblklist)")
    },
    {.name = "remove-all-storage",
     .type = VSH_OT_BOOL,
     .help = N_("remove all associated storage volumes (use with caution)")
    },
    {.name = "delete-snapshots",
     .type = VSH_OT_ALIAS,
     .help = "delete-storage-volume-snapshots"
    },
    {.name = "delete-storage-volume-snapshots",
     .type = VSH_OT_BOOL,
     .help = N_("delete snapshots associated with volume(s), requires "
                "--remove-all-storage (must be supported by storage driver)")
    },
    {.name = "wipe-storage",
     .type = VSH_OT_BOOL,
     .help = N_("wipe data on the removed volumes")
    },
    {.name = "snapshots-metadata",
     .type = VSH_OT_BOOL,
     .help = N_("remove all domain snapshot metadata (vm must be inactive)")
    },
    {.name = "checkpoints-metadata",
     .type = VSH_OT_BOOL,
     .help = N_("remove all domain checkpoint metadata (vm must be inactive)")
    },
    {.name = "nvram",
     .type = VSH_OT_BOOL,
     .help = N_("remove nvram file")
    },
    {.name = "keep-nvram",
     .type = VSH_OT_BOOL,
     .help = N_("keep nvram file")
    },
    {.name = "tpm",
     .type = VSH_OT_BOOL,
     .help = N_("remove TPM state")
    },
    {.name = "keep-tpm",
     .type = VSH_OT_BOOL,
     .help = N_("keep TPM state")
    },
    {.name = NULL}
};

typedef struct {
    virStorageVolPtr vol;
    char *source;
    char *target;
} virshUndefineVolume;

static bool
cmdUndefine(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    bool ret = false;
    const char *name = NULL;
    /* Flags to attempt.  */
    unsigned int flags = 0;
    unsigned int vol_flags = 0;
    /* User-requested actions.  */
    bool managed_save = vshCommandOptBool(cmd, "managed-save");
    bool snapshots_metadata = vshCommandOptBool(cmd, "snapshots-metadata");
    bool checkpoints_metadata = vshCommandOptBool(cmd, "checkpoints-metadata");
    bool wipe_storage = vshCommandOptBool(cmd, "wipe-storage");
    bool remove_all_storage = vshCommandOptBool(cmd, "remove-all-storage");
    bool delete_snapshots = vshCommandOptBool(cmd, "delete-storage-volume-snapshots");
    bool nvram = vshCommandOptBool(cmd, "nvram");
    bool keep_nvram = vshCommandOptBool(cmd, "keep-nvram");
    bool tpm = vshCommandOptBool(cmd, "tpm");
    bool keep_tpm = vshCommandOptBool(cmd, "keep-tpm");
    /* Positive if these items exist.  */
    int has_managed_save = 0;
    int has_snapshots_metadata = 0;
    int has_snapshots = 0;
    /* True if undefine will not strand data, even on older servers.  */
    bool managed_save_safe = false;
    bool snapshots_safe = false;
    int rc = -1;
    int running;
    /* list of volumes to remove along with this domain */
    const char *vol_string = NULL;  /* string containing volumes to delete */
    char **vol_list = NULL;         /* tokenized vol_string */
    int nvol_list = 0;
    virshUndefineVolume *vols = NULL; /* info about the volumes to delete */
    size_t nvols = 0;
    g_autoptr(xmlDoc) doc = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    xmlNodePtr *vol_nodes = NULL;   /* XML nodes of volumes of the guest */
    int nvol_nodes;
    size_t i;
    size_t j;
    virshControl *priv = ctl->privData;

    VSH_REQUIRE_OPTION("delete-storage-volume-snapshots", "remove-all-storage");
    VSH_EXCLUSIVE_OPTIONS("nvram", "keep-nvram");
    VSH_EXCLUSIVE_OPTIONS("tpm", "keep-tpm");

    ignore_value(vshCommandOptStringQuiet(ctl, cmd, "storage", &vol_string));

    if (!(vol_string || remove_all_storage) && wipe_storage) {
        vshError(ctl,
                 _("'--wipe-storage' requires '--storage <string>' or '--remove-all-storage'"));
        return false;
    }

    if (delete_snapshots)
        vol_flags |= VIR_STORAGE_VOL_DELETE_WITH_SNAPSHOTS;

    if (managed_save) {
        flags |= VIR_DOMAIN_UNDEFINE_MANAGED_SAVE;
        managed_save_safe = true;
    }
    if (snapshots_metadata) {
        flags |= VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA;
        snapshots_safe = true;
    }
    if (checkpoints_metadata)
        flags |= VIR_DOMAIN_UNDEFINE_CHECKPOINTS_METADATA;
    if (nvram)
        flags |= VIR_DOMAIN_UNDEFINE_NVRAM;
    if (keep_nvram)
        flags |= VIR_DOMAIN_UNDEFINE_KEEP_NVRAM;
    if (tpm)
        flags |= VIR_DOMAIN_UNDEFINE_TPM;
    if (keep_tpm)
        flags |= VIR_DOMAIN_UNDEFINE_KEEP_TPM;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    /* Do some flag manipulation.  The goal here is to disable bits
     * from flags to reduce the likelihood of a server rejecting
     * unknown flag bits, as well as to track conditions which are
     * safe by default for the given hypervisor and server version.  */
    if ((running = virDomainIsActive(dom)) < 0)
        goto error;

    if (!running) {
        /* Undefine with snapshots only fails for inactive domains,
         * and managed save only exists on inactive domains; if
         * running, then we don't want to remove anything.  */
        has_managed_save = virDomainHasManagedSaveImage(dom, 0);
        if (has_managed_save < 0) {
            if (last_error->code != VIR_ERR_NO_SUPPORT)
                goto error;
            vshResetLibvirtError();
            has_managed_save = 0;
        }

        has_snapshots = virDomainSnapshotNum(dom, 0);
        if (has_snapshots < 0) {
            if (last_error->code != VIR_ERR_NO_SUPPORT)
                goto error;
            vshResetLibvirtError();
            has_snapshots = 0;
        }
        if (has_snapshots) {
            has_snapshots_metadata
                = virDomainSnapshotNum(dom, VIR_DOMAIN_SNAPSHOT_LIST_METADATA);
            if (has_snapshots_metadata < 0) {
                /* The server did not know the new flag, assume that all
                   snapshots have metadata.  */
                vshResetLibvirtError();
                has_snapshots_metadata = has_snapshots;
            } else {
                /* The server knew the new flag, all aspects of
                 * undefineFlags are safe.  */
                managed_save_safe = snapshots_safe = true;
            }
        }
    }
    if (!has_managed_save) {
        flags &= ~VIR_DOMAIN_UNDEFINE_MANAGED_SAVE;
        managed_save_safe = true;
    }
    if (has_snapshots == 0)
        snapshots_safe = true;
    if (has_snapshots_metadata == 0) {
        flags &= ~VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA;
        snapshots_safe = true;
    }

    /* Stash domain description for later use */
    if (vol_string || remove_all_storage) {
        if (running) {
            vshError(ctl,
                     _("Storage volume deletion is supported only on stopped domains"));
            goto cleanup;
        }

        if (vol_string && remove_all_storage) {
            vshError(ctl,
                     _("Specified both --storage and --remove-all-storage"));
            goto cleanup;
        }

        if (virshDomainGetXMLFromDom(ctl, dom, 0, &doc, &ctxt) < 0)
            goto cleanup;

        /* tokenize the string from user and save its parts into an array */
        if (vol_string &&
            (nvol_list = vshStringToArray(vol_string, &vol_list)) < 0)
            goto error;

        if ((nvol_nodes = virXPathNodeSet("./devices/disk", ctxt,
                                          &vol_nodes)) < 0)
            goto error;

        for (i = 0; i < nvol_nodes; i++) {
            g_autofree char *source = NULL;
            g_autofree char *target = NULL;
            g_autofree char *pool = NULL;
            virshUndefineVolume vol;

            ctxt->node = vol_nodes[i];

            /* get volume source and target paths */
            if (!(target = virXPathString("string(./target/@dev)", ctxt)))
                goto error;

            if (!(source = virXPathString("string("
                                          "./source/@file|"
                                          "./source/@dir|"
                                          "./source/@name|"
                                          "./source/@dev|"
                                          "./source/@volume)", ctxt)))
                continue;

            pool = virXPathString("string(./source/@pool)", ctxt);

            /* lookup if volume was selected by user */
            if (vol_list) {
                bool found = false;
                for (j = 0; j < nvol_list; j++) {
                    if (STREQ_NULLABLE(vol_list[j], target) ||
                        STREQ_NULLABLE(vol_list[j], source)) {
                        VIR_FREE(vol_list[j]);
                        found = true;
                        break;
                    }
                }
                if (!found)
                    continue;
            }

            if (pool) {
                g_autoptr(virshStoragePool) storagepool = NULL;

                if (!source) {
                    vshError(ctl,
                             _("Missing storage volume name for disk '%1$s'"),
                             target);
                    continue;
                }

                if (!(storagepool = virStoragePoolLookupByName(priv->conn,
                                                               pool))) {
                    vshError(ctl,
                             _("Storage pool '%1$s' for volume '%2$s' not found."),
                             pool, target);
                    vshResetLibvirtError();
                    continue;
                }

                vol.vol = virStorageVolLookupByName(storagepool, source);

            } else {
               vol.vol = virStorageVolLookupByPath(priv->conn, source);
            }

            if (!vol.vol) {
                vshError(ctl,
                         _("Storage volume '%1$s'(%2$s) is not managed by libvirt. Remove it manually.\n"),
                         target, source);
                vshResetLibvirtError();
                continue;
            }

            vol.source = g_steal_pointer(&source);
            vol.target = g_steal_pointer(&target);
            VIR_APPEND_ELEMENT(vols, nvols, vol);
        }

        /* print volumes specified by user that were not found in domain definition */
        if (vol_list) {
            bool found = false;
            for (i = 0; i < nvol_list; i++) {
                if (vol_list[i]) {
                    vshError(ctl,
                             _("Volume '%1$s' was not found in domain's definition.\n"),
                             vol_list[i]);
                    found = true;
                }
            }

            if (found)
                goto cleanup;
        }
    }

    /* Generally we want to try the new API first.  However, while
     * virDomainUndefineFlags was introduced at the same time as
     * VIR_DOMAIN_UNDEFINE_MANAGED_SAVE in 0.9.4, the
     * VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA flag was not present
     * until 0.9.5; skip to piecewise emulation if we couldn't prove
     * above that the new API is safe.
     * Moreover, only the newer UndefineFlags() API understands
     * the VIR_DOMAIN_UNDEFINE_NVRAM flag. So if user has
     * specified --nvram we must use the Flags() API. */
    if ((managed_save_safe && snapshots_safe) || nvram) {
        rc = virDomainUndefineFlags(dom, flags);
        if (rc == 0 || nvram ||
            (last_error->code != VIR_ERR_NO_SUPPORT &&
             last_error->code != VIR_ERR_INVALID_ARG))
            goto out;
        vshResetLibvirtError();
    }

    /* The new API is unsupported or unsafe; fall back to doing things
     * piecewise.  */
    if (has_managed_save) {
        if (!managed_save) {
            vshError(ctl, "%s",
                     _("Refusing to undefine while domain managed save image exists"));
            goto cleanup;
        }
        if (virDomainManagedSaveRemove(dom, 0) < 0) {
            vshReportError(ctl);
            goto cleanup;
        }
    }

    /* No way to emulate deletion of just snapshot metadata
     * without support for the newer flags.  Oh well.  */
    if (has_snapshots_metadata) {
        if (snapshots_metadata)
            vshError(ctl, _("Unable to remove metadata of %1$d snapshots"),
                     has_snapshots_metadata);
        else
            vshError(ctl, _("Refusing to undefine while %1$d snapshots exist"),
                     has_snapshots_metadata);

        goto cleanup;
    }

    rc = virDomainUndefine(dom);

 out:
    if (rc == 0) {
        vshPrintExtra(ctl, _("Domain '%1$s' has been undefined\n"), name);
        ret = true;
    } else {
        vshError(ctl, _("Failed to undefine domain '%1$s'"), name);
        goto cleanup;
    }

    /* try to undefine storage volumes associated with this domain, if it's requested */
    if (nvols) {
        for (i = 0; i < nvols; i++) {
            if (wipe_storage) {
                vshPrintExtra(ctl, _("Wiping volume '%1$s'(%2$s) ... "),
                              vols[i].target, vols[i].source);
                fflush(stdout);
                if (virStorageVolWipe(vols[i].vol, 0) < 0) {
                    vshError(ctl, _("Failed! Volume not removed."));
                    ret = false;
                    continue;
                } else {
                    vshPrintExtra(ctl, _("Done.\n"));
                }
            }

            /* delete the volume */
            if (virStorageVolDelete(vols[i].vol, vol_flags) < 0) {
                vshError(ctl, _("Failed to remove storage volume '%1$s'(%2$s)"),
                         vols[i].target, vols[i].source);
                ret = false;
            } else {
                vshPrintExtra(ctl, _("Volume '%1$s'(%2$s) removed.\n"),
                              vols[i].target, vols[i].source);
            }
        }
    }

 cleanup:
    for (i = 0; i < nvols; i++) {
        VIR_FREE(vols[i].source);
        VIR_FREE(vols[i].target);
        virshStorageVolFree(vols[i].vol);
    }
    VIR_FREE(vols);

    for (i = 0; i < nvol_list; i++)
        VIR_FREE(vol_list[i]);
    VIR_FREE(vol_list);

    VIR_FREE(vol_nodes);
    return ret;

 error:
    vshReportError(ctl);
    goto cleanup;
}

/*
 * "start" command
 */
static const vshCmdInfo info_start[] = {
    {.name = "help",
     .data = N_("start a (previously defined) inactive domain")
    },
    {.name = "desc",
     .data = N_("Start a domain, either from the last managedsave\n"
                "    state, or via a fresh boot if no managedsave state\n"
                "    is present.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_start[] = {
    VIRSH_COMMON_OPT_DOMAIN(N_("name of the inactive domain"),
                            VIR_CONNECT_LIST_DOMAINS_SHUTOFF),
#ifndef WIN32
    {.name = "console",
     .type = VSH_OT_BOOL,
     .help = N_("attach to console after creation")
    },
#endif
    {.name = "paused",
     .type = VSH_OT_BOOL,
     .help = N_("leave the guest paused after creation")
    },
    {.name = "autodestroy",
     .type = VSH_OT_BOOL,
     .help = N_("automatically destroy the guest when virsh disconnects")
    },
    {.name = "bypass-cache",
     .type = VSH_OT_BOOL,
     .help = N_("avoid file system cache when loading")
    },
    {.name = "force-boot",
     .type = VSH_OT_BOOL,
     .help = N_("force fresh boot by discarding any managed save")
    },
    {.name = "pass-fds",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("pass file descriptors N,M,... to the guest")
    },
    {.name = "reset-nvram",
     .type = VSH_OT_BOOL,
     .help = N_("re-initialize NVRAM from its pristine template")
    },
    {.name = NULL}
};

static int
virshDomainCreateHelper(virDomainPtr dom,
                        unsigned int nfds,
                        int *fds,
                        unsigned int flags)
{
    /* Prefer older API unless we have to pass a flag.  */
    if (nfds > 0) {
        return virDomainCreateWithFiles(dom, nfds, fds, flags);
    } else if (flags != 0) {
        return virDomainCreateWithFlags(dom, flags);
    }

    return virDomainCreate(dom);
}

static bool
cmdStart(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
#ifndef WIN32
    bool console = vshCommandOptBool(cmd, "console");
    bool resume_domain = false;
#endif
    unsigned int flags = VIR_DOMAIN_NONE;
    int rc;
    size_t nfds = 0;
    g_autofree int *fds = NULL;

    if (!(dom = virshCommandOptDomainBy(ctl, cmd, NULL,
                                        VIRSH_BYNAME | VIRSH_BYUUID)))
        return false;

    if (virDomainGetID(dom) != (unsigned int)-1) {
        vshError(ctl, "%s", _("Domain is already active"));
        return false;
    }

    if (virshFetchPassFdsList(ctl, cmd, &nfds, &fds) < 0)
        return false;

    if (vshCommandOptBool(cmd, "paused")) {
        flags |= VIR_DOMAIN_START_PAUSED;
#ifndef WIN32
    } else if (console) {
        flags |= VIR_DOMAIN_START_PAUSED;
        resume_domain = true;
#endif
    }
    if (vshCommandOptBool(cmd, "autodestroy"))
        flags |= VIR_DOMAIN_START_AUTODESTROY;
    if (vshCommandOptBool(cmd, "bypass-cache"))
        flags |= VIR_DOMAIN_START_BYPASS_CACHE;
    if (vshCommandOptBool(cmd, "force-boot"))
        flags |= VIR_DOMAIN_START_FORCE_BOOT;
    if (vshCommandOptBool(cmd, "reset-nvram"))
        flags |= VIR_DOMAIN_START_RESET_NVRAM;

    /* We can emulate force boot, even for older servers that reject it.  */
    if (flags & VIR_DOMAIN_START_FORCE_BOOT) {
        rc = virshDomainCreateHelper(dom, nfds, fds, flags);
        if (rc == 0)
            goto started;

        if (last_error->code != VIR_ERR_NO_SUPPORT &&
            last_error->code != VIR_ERR_INVALID_ARG) {
            vshReportError(ctl);
            return false;
        }
        vshResetLibvirtError();
        rc = virDomainHasManagedSaveImage(dom, 0);
        if (rc < 0) {
            /* No managed save image to remove */
            vshResetLibvirtError();
        } else if (rc > 0) {
            if (virDomainManagedSaveRemove(dom, 0) < 0) {
                vshReportError(ctl);
                return false;
            }
        }
        flags &= ~VIR_DOMAIN_START_FORCE_BOOT;
    }

    rc = virshDomainCreateHelper(dom, nfds, fds, flags);
#ifndef WIN32
    /* If the driver does not support the paused flag, let's fallback to the old
     * behavior without the flag. */
    if (rc < 0 && resume_domain &&
        last_error && last_error->code == VIR_ERR_INVALID_ARG) {

        vshResetLibvirtError();

        flags &= ~VIR_DOMAIN_START_PAUSED;
        resume_domain = false;
        rc = virshDomainCreateHelper(dom, nfds, fds, flags);
    }
#endif

    if (rc < 0) {
        vshError(ctl, _("Failed to start domain '%1$s'"), virDomainGetName(dom));
        return false;
    }

 started:
    vshPrintExtra(ctl, _("Domain '%1$s' started\n"),
                  virDomainGetName(dom));
#ifndef WIN32
    if (console && !cmdRunConsole(ctl, dom, NULL, resume_domain, 0))
        return false;
#endif

    return true;
}

/*
 * "save" command
 */
static const vshCmdInfo info_save[] = {
    {.name = "help",
     .data = N_("save a domain state to a file")
    },
    {.name = "desc",
     .data = N_("Save the RAM state of a running domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_save[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "file",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("where to save the data")
    },
    {.name = "bypass-cache",
     .type = VSH_OT_BOOL,
     .help = N_("avoid file system cache when saving")
    },
    {.name = "xml",
     .type = VSH_OT_STRING,
     .completer = virshCompletePathLocalExisting,
     .help = N_("filename containing updated XML for the target")
    },
    {.name = "running",
     .type = VSH_OT_BOOL,
     .help = N_("set domain to be running on restore")
    },
    {.name = "paused",
     .type = VSH_OT_BOOL,
     .help = N_("set domain to be paused on restore")
    },
    {.name = "verbose",
     .type = VSH_OT_BOOL,
     .help = N_("display the progress of save")
    },
    {.name = NULL}
};

static void
doSave(void *opaque)
{
    virshCtrlData *data = opaque;
    vshControl *ctl = data->ctl;
    const vshCmd *cmd = data->cmd;
    g_autoptr(virshDomain) dom = NULL;
    const char *name = NULL;
    const char *to = NULL;
    unsigned int flags = 0;
    const char *xmlfile = NULL;
    g_autofree char *xml = NULL;
    int rc;
#ifndef WIN32
    sigset_t sigmask, oldsigmask;

    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);
    if (pthread_sigmask(SIG_BLOCK, &sigmask, &oldsigmask) != 0)
        goto out_sig;
#endif /* !WIN32 */

    if (vshCommandOptStringReq(ctl, cmd, "file", &to) < 0)
        goto out;

    if (vshCommandOptBool(cmd, "bypass-cache"))
        flags |= VIR_DOMAIN_SAVE_BYPASS_CACHE;
    if (vshCommandOptBool(cmd, "running"))
        flags |= VIR_DOMAIN_SAVE_RUNNING;
    if (vshCommandOptBool(cmd, "paused"))
        flags |= VIR_DOMAIN_SAVE_PAUSED;

    if (vshCommandOptStringReq(ctl, cmd, "xml", &xmlfile) < 0)
        goto out;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        goto out;

    if (xmlfile &&
        virFileReadAll(xmlfile, VSH_MAX_XML_FILE, &xml) < 0) {
        vshReportError(ctl);
        goto out;
    }

    if (flags || xml) {
        rc = virDomainSaveFlags(dom, to, xml, flags);
    } else {
        rc = virDomainSave(dom, to);
    }

    if (rc < 0) {
        vshError(ctl, _("Failed to save domain '%1$s' to %2$s"), name, to);
        goto out;
    }

    data->ret = 0;

 out:
#ifndef WIN32
    pthread_sigmask(SIG_SETMASK, &oldsigmask, NULL);
 out_sig:
#endif /* !WIN32 */
    g_main_loop_quit(data->eventLoop);
}

typedef void (*jobWatchTimeoutFunc)(vshControl *ctl, virDomainPtr dom,
                                    void *opaque);

struct virshWatchData {
    vshControl *ctl;
    virDomainPtr dom;
    jobWatchTimeoutFunc timeout_func;
    void *opaque;
    const char *label;
    GIOChannel *stdin_ioc;
    bool jobStarted;
    bool verbose;
};

static gboolean
virshWatchTimeout(gpointer opaque)
{
    struct virshWatchData *data = opaque;

    /* suspend the domain when migration timeouts. */
    vshDebug(data->ctl, VSH_ERR_DEBUG, "watchJob: timeout\n");
    if (data->timeout_func)
        (data->timeout_func)(data->ctl, data->dom, data->opaque);

    return G_SOURCE_REMOVE;
}


static gboolean
virshWatchProgress(gpointer opaque)
{
    struct virshWatchData *data = opaque;
    virDomainJobInfo jobinfo;
    int ret;
#ifndef WIN32
    sigset_t sigmask, oldsigmask;

    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);

    pthread_sigmask(SIG_BLOCK, &sigmask, &oldsigmask);
#endif /* !WIN32 */
    vshDebug(data->ctl, VSH_ERR_DEBUG, "%s",
             "watchJob: progress update\n");
    ret = virDomainGetJobInfo(data->dom, &jobinfo);
#ifndef WIN32
    pthread_sigmask(SIG_SETMASK, &oldsigmask, NULL);
#endif /* !WIN32 */

    if (ret == 0) {
        if (data->verbose && jobinfo.dataTotal > 0)
            virshPrintJobProgress(data->label, jobinfo.dataRemaining,
                                  jobinfo.dataTotal);

        if (!data->jobStarted &&
            (jobinfo.type == VIR_DOMAIN_JOB_BOUNDED ||
             jobinfo.type == VIR_DOMAIN_JOB_UNBOUNDED)) {
            vshTTYDisableInterrupt(data->ctl);
            data->jobStarted = true;

            if (!data->verbose) {
                vshDebug(data->ctl, VSH_ERR_DEBUG,
                         "watchJob: job started, disabling callback\n");
                return G_SOURCE_REMOVE;
            }
        }
    } else {
        vshResetLibvirtError();
    }

    return G_SOURCE_CONTINUE;
}


static gboolean
virshWatchInterrupt(GIOChannel *source G_GNUC_UNUSED,
                    GIOCondition condition,
                    gpointer opaque)
{
    struct virshWatchData *data = opaque;
    char retchar;
    gsize nread = 0;

    vshDebug(data->ctl, VSH_ERR_DEBUG,
             "watchJob: stdin data %d\n", condition);
    if (condition & G_IO_IN) {
        g_io_channel_read_chars(data->stdin_ioc,
                                &retchar,
                                sizeof(retchar),
                                &nread,
                                NULL);

        vshDebug(data->ctl, VSH_ERR_DEBUG,
                 "watchJob: got %zu characters\n", nread);
        if (nread == 1 &&
            vshTTYIsInterruptCharacter(data->ctl, retchar)) {
            virDomainAbortJob(data->dom);
            return G_SOURCE_REMOVE;
        }
    }

    if (condition & (G_IO_ERR | G_IO_HUP)) {
        virDomainAbortJob(data->dom);
        return G_SOURCE_REMOVE;
    }

    return G_SOURCE_CONTINUE;
}


static void
virshWatchJob(vshControl *ctl,
              virDomainPtr dom,
              bool verbose,
              GMainLoop *eventLoop,
              int *job_err,
              int timeout_secs,
              jobWatchTimeoutFunc timeout_func,
              void *opaque,
              const char *label)
{
#ifndef WIN32
    struct sigaction sig_action;
    struct sigaction old_sig_action;
#endif /* !WIN32 */
    g_autoptr(GSource) timeout_src = NULL;
    g_autoptr(GSource) progress_src = NULL;
    g_autoptr(GSource) stdin_src = NULL;
    struct virshWatchData data = {
        .ctl = ctl,
        .dom = dom,
        .timeout_func = timeout_func,
        .opaque = opaque,
        .label = label,
        .stdin_ioc = NULL,
        .jobStarted = false,
        .verbose = verbose,
    };

#ifndef WIN32
    intCaught = 0;
    sig_action.sa_sigaction = virshCatchInt;
    sig_action.sa_flags = SA_SIGINFO;
    sigemptyset(&sig_action.sa_mask);
    sigaction(SIGINT, &sig_action, &old_sig_action);
#endif /* !WIN32 */

    /* don't poll on STDIN if we are not using a terminal */
    if (vshTTYAvailable(ctl)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s",
                 "watchJob: on TTY, enabling Ctrl-c processing\n");
#ifdef WIN32
        data.stdin_ioc = g_io_channel_win32_new_fd(STDIN_FILENO);
#else
        data.stdin_ioc = g_io_channel_unix_new(STDIN_FILENO);
#endif
        stdin_src = g_io_create_watch(data.stdin_ioc, G_IO_IN);
        g_source_set_callback(stdin_src,
                              (GSourceFunc)virshWatchInterrupt,
                              &data, NULL);
        g_source_attach(stdin_src,
                        g_main_loop_get_context(eventLoop));
    }

    if (timeout_secs) {
        vshDebug(ctl, VSH_ERR_DEBUG,
                 "watchJob: setting timeout of %d secs\n", timeout_secs);
        timeout_src = g_timeout_source_new_seconds(timeout_secs);
        g_source_set_callback(timeout_src,
                              virshWatchTimeout,
                              &data, NULL);
        g_source_attach(timeout_src,
                        g_main_loop_get_context(eventLoop));
    }

    progress_src = g_timeout_source_new(500);
    g_source_set_callback(progress_src,
                          virshWatchProgress,
                          &data, NULL);
    g_source_attach(progress_src,
                    g_main_loop_get_context(eventLoop));

    g_main_loop_run(eventLoop);

    vshDebug(ctl, VSH_ERR_DEBUG,
             "watchJob: job done, status %d\n", *job_err);
    if (*job_err == 0 && verbose) /* print [100 %] */
        virshPrintJobProgress(label, 0, 1);

    if (timeout_src)
        g_source_destroy(timeout_src);
    g_source_destroy(progress_src);
    if (stdin_src)
        g_source_destroy(stdin_src);

#ifndef WIN32
    sigaction(SIGINT, &old_sig_action, NULL);
#endif /* !WIN32 */
    vshTTYRestore(ctl);
    if (data.stdin_ioc)
        g_io_channel_unref(data.stdin_ioc);
}

static bool
cmdSave(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    virThread workerThread;
    bool verbose = false;
    const char *to = NULL;
    const char *name = NULL;
    g_autoptr(GMainContext) eventCtxt = g_main_context_new();
    g_autoptr(GMainLoop) eventLoop = g_main_loop_new(eventCtxt, FALSE);
    virshCtrlData data = {
        .ctl = ctl,
        .cmd = cmd,
        .eventLoop = eventLoop,
        .ret = -1,
    };

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "file", &to) < 0)
        return false;

    if (vshCommandOptBool(cmd, "verbose"))
        verbose = true;

    if (virThreadCreate(&workerThread,
                        true,
                        doSave,
                        &data) < 0)
        return false;

    virshWatchJob(ctl, dom, verbose, eventLoop,
                  &data.ret, 0, NULL, NULL, _("Save"));

    virThreadJoin(&workerThread);

    if (!data.ret)
        vshPrintExtra(ctl, _("\nDomain '%1$s' saved to %2$s\n"), name, to);

    return !data.ret;
}

/*
 * "save-image-dumpxml" command
 */
static const vshCmdInfo info_save_image_dumpxml[] = {
    {.name = "help",
     .data = N_("saved state domain information in XML")
    },
    {.name = "desc",
     .data = N_("Dump XML of domain information for a saved state file to stdout.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_save_image_dumpxml[] = {
    {.name = "file",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("saved state file to read")
    },
    {.name = "security-info",
     .type = VSH_OT_BOOL,
     .help = N_("include security sensitive information in XML dump")
    },
    {.name = "xpath",
     .type = VSH_OT_STRING,
     .flags = VSH_OFLAG_REQ_OPT,
     .completer = virshCompleteEmpty,
     .help = N_("xpath expression to filter the XML document")
    },
    {.name = "wrap",
     .type = VSH_OT_BOOL,
     .help = N_("wrap xpath results in an common root element"),
    },
    {.name = NULL}
};

static bool
cmdSaveImageDumpxml(vshControl *ctl, const vshCmd *cmd)
{
    const char *file = NULL;
    unsigned int flags = 0;
    g_autofree char *xml = NULL;
    virshControl *priv = ctl->privData;
    bool wrap = vshCommandOptBool(cmd, "wrap");
    const char *xpath = NULL;

    if (vshCommandOptBool(cmd, "security-info"))
        flags |= VIR_DOMAIN_XML_SECURE;

    if (vshCommandOptStringReq(ctl, cmd, "file", &file) < 0)
        return false;

    if (vshCommandOptStringQuiet(ctl, cmd, "xpath", &xpath) < 0)
        return false;

    xml = virDomainSaveImageGetXMLDesc(priv->conn, file, flags);
    if (!xml)
        return false;

    return virshDumpXML(ctl, xml, "domain-save-image", xpath, wrap);
}

/*
 * "save-image-define" command
 */
static const vshCmdInfo info_save_image_define[] = {
    {.name = "help",
     .data = N_("redefine the XML for a domain's saved state file")
    },
    {.name = "desc",
     .data = N_("Replace the domain XML associated with a saved state file")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_save_image_define[] = {
    {.name = "file",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("saved state file to modify")
    },
    {.name = "xml",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshCompletePathLocalExisting,
     .help = N_("filename containing updated XML for the target")
    },
    {.name = "running",
     .type = VSH_OT_BOOL,
     .help = N_("set domain to be running on restore")
    },
    {.name = "paused",
     .type = VSH_OT_BOOL,
     .help = N_("set domain to be paused on restore")
    },
    {.name = NULL}
};

static bool
cmdSaveImageDefine(vshControl *ctl, const vshCmd *cmd)
{
    const char *file = NULL;
    const char *xmlfile = NULL;
    g_autofree char *xml = NULL;
    unsigned int flags = 0;
    virshControl *priv = ctl->privData;

    if (vshCommandOptBool(cmd, "running"))
        flags |= VIR_DOMAIN_SAVE_RUNNING;
    if (vshCommandOptBool(cmd, "paused"))
        flags |= VIR_DOMAIN_SAVE_PAUSED;

    if (vshCommandOptStringReq(ctl, cmd, "file", &file) < 0)
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "xml", &xmlfile) < 0)
        return false;

    if (virFileReadAll(xmlfile, VSH_MAX_XML_FILE, &xml) < 0)
        return false;

    if (virDomainSaveImageDefineXML(priv->conn, file, xml, flags) < 0) {
        vshError(ctl, _("Failed to update %1$s"), file);
        return false;
    }

    vshPrintExtra(ctl, _("State file %1$s updated.\n"), file);
    return true;
}

/*
 * "save-image-edit" command
 */
static const vshCmdInfo info_save_image_edit[] = {
    {.name = "help",
     .data = N_("edit XML for a domain's saved state file")
    },
    {.name = "desc",
     .data = N_("Edit the domain XML associated with a saved state file")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_save_image_edit[] = {
    {.name = "file",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("saved state file to edit")
    },
    {.name = "running",
     .type = VSH_OT_BOOL,
     .help = N_("set domain to be running on restore")
    },
    {.name = "paused",
     .type = VSH_OT_BOOL,
     .help = N_("set domain to be paused on restore")
    },
    {.name = NULL}
};

static bool
cmdSaveImageEdit(vshControl *ctl, const vshCmd *cmd)
{
    const char *file = NULL;
    bool ret = false;
    unsigned int getxml_flags = VIR_DOMAIN_XML_SECURE;
    unsigned int define_flags = 0;
    virshControl *priv = ctl->privData;

    if (vshCommandOptBool(cmd, "running"))
        define_flags |= VIR_DOMAIN_SAVE_RUNNING;
    if (vshCommandOptBool(cmd, "paused"))
        define_flags |= VIR_DOMAIN_SAVE_PAUSED;

    /* Normally, we let the API reject mutually exclusive flags.
     * However, in the edit cycle, we let the user retry if the define
     * step fails, but the define step will always fail on invalid
     * flags, so we reject it up front to avoid looping.  */
    VSH_EXCLUSIVE_OPTIONS("running", "paused");

    if (vshCommandOptStringReq(ctl, cmd, "file", &file) < 0)
        return false;

#define EDIT_GET_XML \
    virDomainSaveImageGetXMLDesc(priv->conn, file, getxml_flags)
#define EDIT_NOT_CHANGED \
    do { \
        vshPrintExtra(ctl, _("Saved image %1$s XML configuration not changed.\n"), \
                      file); \
        ret = true; \
        goto edit_cleanup; \
    } while (0)
#define EDIT_DEFINE \
    (virDomainSaveImageDefineXML(priv->conn, file, doc_edited, define_flags) == 0)
#include "virsh-edit.c"

    vshPrintExtra(ctl, _("State file %1$s edited.\n"), file);
    ret = true;

 cleanup:
    return ret;
}

/*
 * "managedsave" command
 */
static const vshCmdInfo info_managedsave[] = {
    {.name = "help",
     .data = N_("managed save of a domain state")
    },
    {.name = "desc",
     .data = N_("Save and destroy a running domain, so it can be restarted from\n"
                "    the same state at a later time.  When the virsh 'start'\n"
                "    command is next run for the domain, it will automatically\n"
                "    be started from this saved state.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_managedsave[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "bypass-cache",
     .type = VSH_OT_BOOL,
     .help = N_("avoid file system cache when saving")
    },
    {.name = "running",
     .type = VSH_OT_BOOL,
     .help = N_("set domain to be running on next start")
    },
    {.name = "paused",
     .type = VSH_OT_BOOL,
     .help = N_("set domain to be paused on next start")
    },
    {.name = "verbose",
     .type = VSH_OT_BOOL,
     .help = N_("display the progress of save")
    },
    {.name = NULL}
};

static void
doManagedsave(void *opaque)
{
    virshCtrlData *data = opaque;
    vshControl *ctl = data->ctl;
    const vshCmd *cmd = data->cmd;
    g_autoptr(virshDomain) dom = NULL;
    const char *name;
    unsigned int flags = 0;
#ifndef WIN32
    sigset_t sigmask, oldsigmask;

    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);
    if (pthread_sigmask(SIG_BLOCK, &sigmask, &oldsigmask) != 0)
        goto out_sig;
#endif /* !WIN32 */

    if (vshCommandOptBool(cmd, "bypass-cache"))
        flags |= VIR_DOMAIN_SAVE_BYPASS_CACHE;
    if (vshCommandOptBool(cmd, "running"))
        flags |= VIR_DOMAIN_SAVE_RUNNING;
    if (vshCommandOptBool(cmd, "paused"))
        flags |= VIR_DOMAIN_SAVE_PAUSED;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        goto out;

    if (virDomainManagedSave(dom, flags) < 0) {
        vshError(ctl, _("Failed to save domain '%1$s' state"), name);
        goto out;
    }

    data->ret = 0;
 out:
#ifndef WIN32
    pthread_sigmask(SIG_SETMASK, &oldsigmask, NULL);
 out_sig:
#endif /* !WIN32 */
    g_main_loop_quit(data->eventLoop);
}

static bool
cmdManagedSave(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    bool verbose = false;
    const char *name = NULL;
    virThread workerThread;
    g_autoptr(GMainContext) eventCtxt = g_main_context_new();
    g_autoptr(GMainLoop) eventLoop = g_main_loop_new(eventCtxt, FALSE);
    virshCtrlData data = {
        .ctl = ctl,
        .cmd = cmd,
        .eventLoop = eventLoop,
        .ret = -1,
    };

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (vshCommandOptBool(cmd, "verbose"))
        verbose = true;

    if (virThreadCreate(&workerThread,
                        true,
                        doManagedsave,
                        &data) < 0)
        return false;

    virshWatchJob(ctl, dom, verbose, eventLoop,
                  &data.ret, 0, NULL, NULL, _("Managedsave"));

    virThreadJoin(&workerThread);

    if (!data.ret)
        vshPrintExtra(ctl, _("\nDomain '%1$s' state saved by libvirt\n"), name);

    return !data.ret;
}

/*
 * "managedsave-remove" command
 */
static const vshCmdInfo info_managedsaveremove[] = {
    {.name = "help",
     .data = N_("Remove managed save of a domain")
    },
    {.name = "desc",
     .data = N_("Remove an existing managed save state file from a domain")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_managedsaveremove[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_MANAGEDSAVE),
    {.name = NULL}
};

static bool
cmdManagedSaveRemove(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *name;
    int hassave;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    hassave = virDomainHasManagedSaveImage(dom, 0);
    if (hassave < 0) {
        vshError(ctl, "%s", _("Failed to check for domain managed save image"));
        return false;
    }

    if (hassave == 0) {
        vshPrintExtra(ctl, _("Domain '%1$s' has no manage save image; removal skipped"),
                      name);
        return true;
    }

    if (virDomainManagedSaveRemove(dom, 0) < 0) {
        vshError(ctl, _("Failed to remove managed save image for domain '%1$s'"),
                 name);
        return false;
    }

    vshPrintExtra(ctl, _("Removed managedsave image for domain '%1$s'"), name);

    return true;
}

/*
 * "managedsave-edit" command
 */
static const vshCmdInfo info_managed_save_edit[] = {
    {.name = "help",
     .data = N_("edit XML for a domain's managed save state file")
    },
    {.name = "desc",
     .data = N_("Edit the domain XML associated with the managed save state file")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_managed_save_edit[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_MANAGEDSAVE),
    {.name = "running",
     .type = VSH_OT_BOOL,
     .help = N_("set domain to be running on start")
    },
    {.name = "paused",
     .type = VSH_OT_BOOL,
     .help = N_("set domain to be paused on start")
    },
    {.name = NULL}
};

static bool
cmdManagedSaveEdit(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    g_autoptr(virshDomain) dom = NULL;
    unsigned int getxml_flags = VIR_DOMAIN_XML_SECURE;
    unsigned int define_flags = 0;

    if (vshCommandOptBool(cmd, "running"))
        define_flags |= VIR_DOMAIN_SAVE_RUNNING;
    if (vshCommandOptBool(cmd, "paused"))
        define_flags |= VIR_DOMAIN_SAVE_PAUSED;

    VSH_EXCLUSIVE_OPTIONS("running", "paused");

    dom = virshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        return false;

#define EDIT_GET_XML virDomainManagedSaveGetXMLDesc(dom, getxml_flags)
#define EDIT_NOT_CHANGED \
    do { \
        vshPrintExtra(ctl, _("Managed save image of domain '%1$s' XML configuration not changed.\n"), \
                      virDomainGetName(dom)); \
        ret = true; \
        goto edit_cleanup; \
    } while (0)
#define EDIT_DEFINE \
    (virDomainManagedSaveDefineXML(dom, doc_edited, define_flags) == 0)
#include "virsh-edit.c"

    vshPrintExtra(ctl, _("Managed save image of Domain '%1$s' XML configuration edited.\n"),
                  virDomainGetName(dom));
    ret = true;

 cleanup:
    return ret;
}

/*
 * "managedsave-dumpxml" command
 */
static const vshCmdInfo info_managed_save_dumpxml[] = {
   {.name = "help",
    .data = N_("Domain information of managed save state file in XML")
   },
   {.name = "desc",
    .data = N_("Dump XML of domain information for a managed save state file to stdout.")
   },
   {.name = NULL}
};

static const vshCmdOptDef opts_managed_save_dumpxml[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_MANAGEDSAVE),
    {.name = "security-info",
     .type = VSH_OT_BOOL,
     .help = N_("include security sensitive information in XML dump")
    },
    {.name = "xpath",
     .type = VSH_OT_STRING,
     .flags = VSH_OFLAG_REQ_OPT,
     .completer = virshCompleteEmpty,
     .help = N_("xpath expression to filter the XML document")
    },
    {.name = "wrap",
     .type = VSH_OT_BOOL,
     .help = N_("wrap xpath results in an common root element"),
    },
    {.name = NULL}
};

static bool
cmdManagedSaveDumpxml(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    unsigned int flags = 0;
    g_autofree char *xml = NULL;
    bool wrap = vshCommandOptBool(cmd, "wrap");
    const char *xpath = NULL;

    if (vshCommandOptBool(cmd, "security-info"))
        flags |= VIR_DOMAIN_XML_SECURE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringQuiet(ctl, cmd, "xpath", &xpath) < 0)
        return false;

    if (!(xml = virDomainManagedSaveGetXMLDesc(dom, flags)))
        return false;

    return virshDumpXML(ctl, xml, "domain-save-image", xpath, wrap);
}

/*
 * "managedsave-define" command
 */
static const vshCmdInfo info_managed_save_define[] = {
    {.name = "help",
     .data = N_("redefine the XML for a domain's managed save state file")
    },
    {.name = "desc",
     .data = N_("Replace the domain XML associated with a managed save state file")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_managed_save_define[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_MANAGEDSAVE),
    {.name = "xml",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshCompletePathLocalExisting,
     .help = N_("filename containing updated XML for the target")
    },
    {.name = "running",
     .type = VSH_OT_BOOL,
     .help = N_("set domain to be running on start")
    },
    {.name = "paused",
     .type = VSH_OT_BOOL,
     .help = N_("set domain to be paused on start")
    },
    {.name = NULL}
};

static bool
cmdManagedSaveDefine(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *xmlfile = NULL;
    g_autofree char *xml = NULL;
    unsigned int flags = 0;

    if (vshCommandOptBool(cmd, "running"))
        flags |= VIR_DOMAIN_SAVE_RUNNING;
    if (vshCommandOptBool(cmd, "paused"))
        flags |= VIR_DOMAIN_SAVE_PAUSED;

    VSH_EXCLUSIVE_OPTIONS("running", "paused");

    if (vshCommandOptStringReq(ctl, cmd, "xml", &xmlfile) < 0)
        return false;

    if (virFileReadAll(xmlfile, VSH_MAX_XML_FILE, &xml) < 0)
        return false;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virDomainManagedSaveDefineXML(dom, xml, flags) < 0) {
        vshError(ctl, _("Failed to update %1$s XML configuration"),
                        virDomainGetName(dom));
        return false;
    }

    vshPrintExtra(ctl, _("Managed save state file of domain '%1$s' updated.\n"),
                         virDomainGetName(dom));
    return true;
}

/*
 * "schedinfo" command
 */
static const vshCmdInfo info_schedinfo[] = {
    {.name = "help",
     .data = N_("show/set scheduler parameters")
    },
    {.name = "desc",
     .data = N_("Show/Set scheduler parameters.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_schedinfo[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "weight",
     .type = VSH_OT_INT,
     .flags = VSH_OFLAG_REQ_OPT,
     .help = N_("weight for XEN_CREDIT")
    },
    {.name = "cap",
     .type = VSH_OT_INT,
     .flags = VSH_OFLAG_REQ_OPT,
     .help = N_("cap for XEN_CREDIT")
    },
    VIRSH_COMMON_OPT_CURRENT(N_("get/set current scheduler info")),
    VIRSH_COMMON_OPT_CONFIG(N_("get/set value to be used on next boot")),
    VIRSH_COMMON_OPT_LIVE(N_("get/set value from running domain")),
    {.name = "set",
     .type = VSH_OT_ARGV,
     .flags = VSH_OFLAG_NONE,
     .help = N_("parameter=value")
    },
    {.name = NULL}
};

static int
cmdSchedInfoUpdateOne(vshControl *ctl,
                      virTypedParameterPtr src_params, int nsrc_params,
                      virTypedParameterPtr *params,
                      int *nparams, int *maxparams,
                      const char *field, const char *value)
{
    virTypedParameterPtr param;
    size_t i;

    for (i = 0; i < nsrc_params; i++) {
        param = &(src_params[i]);

        if (STRNEQ(field, param->field))
            continue;

        if (virTypedParamsAddFromString(params, nparams, maxparams,
                                        field, param->type,
                                        value) < 0) {
            vshSaveLibvirtError();
            return -1;
        }
        return 0;
    }

    vshError(ctl, _("invalid scheduler option: %1$s"), field);
    return -1;
}

static int
cmdSchedInfoUpdate(vshControl *ctl, const vshCmd *cmd,
                   virTypedParameterPtr src_params, int nsrc_params,
                   virTypedParameterPtr *update_params)
{
    char *set_val = NULL;
    const char *val = NULL;
    const vshCmdOpt *opt = NULL;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    int maxparams = 0;
    int ret = -1;
    int rv;

    while ((opt = vshCommandOptArgv(ctl, cmd, opt))) {
        g_autofree char *set_field = g_strdup(opt->data);

        if (!(set_val = strchr(set_field, '='))) {
            vshError(ctl, "%s", _("Invalid syntax for --set, expecting name=value"));
            goto cleanup;
        }

        *set_val = '\0';
        set_val++;

        if (cmdSchedInfoUpdateOne(ctl, src_params, nsrc_params,
                                  &params, &nparams, &maxparams,
                                  set_field, set_val) < 0)
            goto cleanup;
    }

    rv = vshCommandOptStringReq(ctl, cmd, "cap", &val);
    if (rv < 0 ||
        (val &&
         cmdSchedInfoUpdateOne(ctl, src_params, nsrc_params,
                               &params, &nparams, &maxparams,
                               "cap", val) < 0))
        goto cleanup;

    rv = vshCommandOptStringReq(ctl, cmd, "weight", &val);
    if (rv < 0 ||
        (val &&
         cmdSchedInfoUpdateOne(ctl, src_params, nsrc_params,
                               &params, &nparams, &maxparams,
                               "weight", val) < 0))
        goto cleanup;

    ret = nparams;
    *update_params = g_steal_pointer(&params);

 cleanup:
    virTypedParamsFree(params, nparams);
    return ret;
}

static bool
cmdSchedinfo(vshControl *ctl, const vshCmd *cmd)
{
    g_autofree char *schedulertype = NULL;
    g_autoptr(virshDomain) dom = NULL;
    virTypedParameterPtr params = NULL;
    virTypedParameterPtr updates = NULL;
    int nparams = 0;
    int nupdates = 0;
    size_t i;
    bool ret_val = false;
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;
    unsigned int queryflags = VIR_DOMAIN_AFFECT_CURRENT;
    bool current = vshCommandOptBool(cmd, "current");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (config)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    /* We cannot query both live and config at once, so settle
       on current in that case.  If we are setting, then the two values should
       match when we re-query; otherwise, we report the error later.  */
    if (config && live)
        queryflags = VIR_DOMAIN_AFFECT_CURRENT;
    else
        queryflags = flags;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    /* Print SchedulerType */
    if (!(schedulertype = virDomainGetSchedulerType(dom, &nparams))) {
        vshPrint(ctl, "%-15s: %s\n", _("Scheduler"), _("Unknown"));
        goto cleanup;
    }

    vshPrint(ctl, "%-15s: %s\n", _("Scheduler"), schedulertype);

    if (!nparams)
        goto cleanup;

    params = g_new0(virTypedParameter, nparams);
    memset(params, 0, sizeof(*params) * nparams);

    if (flags || current) {
        if (virDomainGetSchedulerParametersFlags(dom, params, &nparams, queryflags) == -1)
            goto cleanup;
    } else {
        if (virDomainGetSchedulerParameters(dom, params, &nparams) == -1)
            goto cleanup;
    }

    /* See if any params are being set */
    if ((nupdates = cmdSchedInfoUpdate(ctl, cmd, params, nparams,
                                       &updates)) < 0)
        goto cleanup;

    /* Update parameters & refresh data */
    if (nupdates > 0) {
        if (flags || current) {
            if (virDomainSetSchedulerParametersFlags(dom, updates,
                                                     nupdates, flags) == -1)
                goto cleanup;

            if (virDomainGetSchedulerParametersFlags(dom, params, &nparams, queryflags) == -1)
                goto cleanup;
        } else {
            if (virDomainSetSchedulerParameters(dom, updates, nupdates) == -1)
                goto cleanup;

            if (virDomainGetSchedulerParameters(dom, params, &nparams) == -1)
                goto cleanup;
        }
    } else {
        /* When not doing --set, --live and --config do not mix.  */
        if (live && config) {
            vshError(ctl, "%s",
                     _("cannot query both live and config at once"));
            goto cleanup;
        }
    }

    ret_val = true;
    for (i = 0; i < nparams; i++) {
        g_autofree char *str = vshGetTypedParamValue(ctl, &params[i]);
        vshPrint(ctl, "%-15s: %s\n", params[i].field, str);
    }

 cleanup:
    virTypedParamsFree(params, nparams);
    virTypedParamsFree(updates, nupdates);
    return ret_val;
}

/*
 * "restore" command
 */
static const vshCmdInfo info_restore[] = {
    {.name = "help",
     .data = N_("restore a domain from a saved state in a file")
    },
    {.name = "desc",
     .data = N_("Restore a domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_restore[] = {
    {.name = "file",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("the state to restore")
    },
    {.name = "bypass-cache",
     .type = VSH_OT_BOOL,
     .help = N_("avoid file system cache when restoring")
    },
    {.name = "xml",
     .type = VSH_OT_STRING,
     .completer = virshCompletePathLocalExisting,
     .help = N_("filename containing updated XML for the target")
    },
    {.name = "running",
     .type = VSH_OT_BOOL,
     .help = N_("restore domain into running state")
    },
    {.name = "paused",
     .type = VSH_OT_BOOL,
     .help = N_("restore domain into paused state")
    },
    {.name = "reset-nvram",
     .type = VSH_OT_BOOL,
     .help = N_("re-initialize NVRAM from its pristine template")
    },
    {.name = NULL}
};

static bool
cmdRestore(vshControl *ctl, const vshCmd *cmd)
{
    const char *from = NULL;
    unsigned int flags = 0;
    const char *xmlfile = NULL;
    g_autofree char *xml = NULL;
    virshControl *priv = ctl->privData;
    int rc;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        return false;

    if (vshCommandOptBool(cmd, "bypass-cache"))
        flags |= VIR_DOMAIN_SAVE_BYPASS_CACHE;
    if (vshCommandOptBool(cmd, "running"))
        flags |= VIR_DOMAIN_SAVE_RUNNING;
    if (vshCommandOptBool(cmd, "paused"))
        flags |= VIR_DOMAIN_SAVE_PAUSED;
    if (vshCommandOptBool(cmd, "reset-nvram"))
        flags |= VIR_DOMAIN_SAVE_RESET_NVRAM;

    if (vshCommandOptStringReq(ctl, cmd, "xml", &xmlfile) < 0)
        return false;

    if (xmlfile &&
        virFileReadAll(xmlfile, VSH_MAX_XML_FILE, &xml) < 0)
        return false;

    if (flags || xml) {
        rc = virDomainRestoreFlags(priv->conn, from, xml, flags);
    } else {
        rc = virDomainRestore(priv->conn, from);
    }

    if (rc < 0) {
        vshError(ctl, _("Failed to restore domain from %1$s"), from);
        return false;
    }

    vshPrintExtra(ctl, _("Domain restored from %1$s\n"), from);
    return true;
}

/*
 * "dump" command
 */
static const vshCmdInfo info_dump[] = {
    {.name = "help",
     .data = N_("dump the core of a domain to a file for analysis")
    },
    {.name = "desc",
     .data = N_("Core dump a domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_dump[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "file",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("where to dump the core")
    },
    VIRSH_COMMON_OPT_LIVE(N_("perform a live core dump if supported")),
    {.name = "crash",
     .type = VSH_OT_BOOL,
     .help = N_("crash the domain after core dump")
    },
    {.name = "bypass-cache",
     .type = VSH_OT_BOOL,
     .help = N_("avoid file system cache when dumping")
    },
    {.name = "reset",
     .type = VSH_OT_BOOL,
     .help = N_("reset the domain after core dump")
    },
    {.name = "verbose",
     .type = VSH_OT_BOOL,
     .help = N_("display the progress of dump")
    },
    {.name = "memory-only",
     .type = VSH_OT_BOOL,
     .help = N_("dump domain's memory only")
    },
    {.name = "format",
     .type = VSH_OT_STRING,
     .flags = VSH_OFLAG_NONE,
     .completer = virshDomainCoreDumpFormatCompleter,
     .help = N_("specify the format of memory-only dump")
    },
    {.name = NULL}
};

VIR_ENUM_IMPL(virshDomainCoreDumpFormat,
              VIR_DOMAIN_CORE_DUMP_FORMAT_LAST,
              "elf",
              "kdump-zlib",
              "kdump-lzo",
              "kdump-snappy",
              "win-dmp");

static void
doDump(void *opaque)
{
    virshCtrlData *data = opaque;
    vshControl *ctl = data->ctl;
    const vshCmd *cmd = data->cmd;
    g_autoptr(virshDomain) dom = NULL;
    const char *name = NULL;
    const char *to = NULL;
    unsigned int flags = 0;
    const char *format = NULL;
    int dumpformat = VIR_DOMAIN_CORE_DUMP_FORMAT_RAW;
#ifndef WIN32
    sigset_t sigmask, oldsigmask;

    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);
    if (pthread_sigmask(SIG_BLOCK, &sigmask, &oldsigmask) != 0)
        goto out_sig;
#endif /* !WIN32 */

    if (vshCommandOptStringReq(ctl, cmd, "file", &to) < 0)
        goto out;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        goto out;

    if (vshCommandOptBool(cmd, "live"))
        flags |= VIR_DUMP_LIVE;
    if (vshCommandOptBool(cmd, "crash"))
        flags |= VIR_DUMP_CRASH;
    if (vshCommandOptBool(cmd, "bypass-cache"))
        flags |= VIR_DUMP_BYPASS_CACHE;
    if (vshCommandOptBool(cmd, "reset"))
        flags |= VIR_DUMP_RESET;
    if (vshCommandOptBool(cmd, "memory-only"))
        flags |= VIR_DUMP_MEMORY_ONLY;

    if (vshCommandOptBool(cmd, "format")) {
        if (!(flags & VIR_DUMP_MEMORY_ONLY)) {
            vshError(ctl, "%s", _("--format only works with --memory-only"));
            goto out;
        }

        if (vshCommandOptStringQuiet(ctl, cmd, "format", &format) > 0) {
            if ((dumpformat = virshDomainCoreDumpFormatTypeFromString(format)) < 0) {
                vshError(ctl, _("format '%1$s' is not supported, expecting 'kdump-zlib', 'kdump-lzo', 'kdump-snappy', 'win-dmp' or 'elf'"),
                         format);
                goto out;
            }
        }
    }

    if (dumpformat != VIR_DOMAIN_CORE_DUMP_FORMAT_RAW) {
        if (virDomainCoreDumpWithFormat(dom, to, dumpformat, flags) < 0) {
            vshError(ctl, _("Failed to core dump domain '%1$s' to %2$s"), name, to);
            goto out;
        }
    } else {
        if (virDomainCoreDump(dom, to, flags) < 0) {
            vshError(ctl, _("Failed to core dump domain '%1$s' to %2$s"), name, to);
            goto out;
        }
    }

    data->ret = 0;
 out:
#ifndef WIN32
    pthread_sigmask(SIG_SETMASK, &oldsigmask, NULL);
 out_sig:
#endif /* !WIN32 */
    g_main_loop_quit(data->eventLoop);
}

static bool
cmdDump(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    bool verbose = false;
    const char *name = NULL;
    const char *to = NULL;
    virThread workerThread;
    g_autoptr(GMainContext) eventCtxt = g_main_context_new();
    g_autoptr(GMainLoop) eventLoop = g_main_loop_new(eventCtxt, FALSE);
    virshCtrlData data = {
        .ctl = ctl,
        .cmd = cmd,
        .eventLoop = eventLoop,
        .ret = -1,
    };

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "file", &to) < 0)
        return false;

    if (vshCommandOptBool(cmd, "verbose"))
        verbose = true;

    if (virThreadCreate(&workerThread,
                        true,
                        doDump,
                        &data) < 0)
        return false;

    virshWatchJob(ctl, dom, verbose, eventLoop,
                  &data.ret, 0, NULL, NULL, _("Dump"));

    virThreadJoin(&workerThread);

    if (data.ret)
        return false;

    vshPrintExtra(ctl, _("\nDomain '%1$s' dumped to %2$s\n"), name, to);

    return true;
}

static const vshCmdInfo info_screenshot[] = {
    {.name = "help",
     .data = N_("take a screenshot of a current domain console and store it "
                "into a file")
    },
    {.name = "desc",
     .data = N_("screenshot of a current domain console")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_screenshot[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "file",
     .type = VSH_OT_STRING,
     .completer = virshCompletePathLocalExisting,
     .help = N_("where to store the screenshot")
    },
    {.name = "screen",
     .type = VSH_OT_INT,
     .help = N_("ID of a screen to take screenshot of")
    },
    {.name = NULL}
};

/**
 * Generate string: '<domain name>-<timestamp>[<extension>]'
 */
static char *
virshGenFileName(vshControl *ctl, virDomainPtr dom, const char *mime)
{
    g_autoptr(GDateTime) now = g_date_time_new_now_local();
    g_autofree char *nowstr = NULL;
    const char *ext = NULL;

    if (!dom) {
        vshError(ctl, "%s", _("Invalid domain supplied"));
        return NULL;
    }

    if (STREQ(mime, "image/x-portable-pixmap"))
        ext = ".ppm";
    else if (STREQ(mime, "image/png"))
        ext = ".png";
    /* add mime type here */

    nowstr = g_date_time_format(now, "%Y-%m-%d-%H:%M:%S");

    return g_strdup_printf("%s-%s%s", virDomainGetName(dom),
                           nowstr, NULLSTR_EMPTY(ext));
}

static bool
cmdScreenshot(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *name = NULL;
    char *file = NULL;
    VIR_AUTOCLOSE fd = -1;
    g_autoptr(virshStream) st = NULL;
    unsigned int screen = 0;
    unsigned int flags = 0; /* currently unused */
    bool ret = false;
    bool created = false;
    bool generated = false;
    g_autofree char *mime = NULL;
    virshControl *priv = ctl->privData;
    virshStreamCallbackData cbdata;

    if (vshCommandOptStringReq(ctl, cmd, "file", (const char **) &file) < 0)
        return false;

    if (vshCommandOptUInt(ctl, cmd, "screen", &screen) < 0)
        return false;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (!(st = virStreamNew(priv->conn, 0)))
        goto cleanup;

    mime = virDomainScreenshot(dom, st, screen, flags);
    if (!mime) {
        vshError(ctl, _("could not take a screenshot of %1$s"), name);
        goto cleanup;
    }

    if (!file) {
        if (!(file = virshGenFileName(ctl, dom, mime)))
            goto cleanup;
        generated = true;
    }

    if ((fd = open(file, O_WRONLY|O_CREAT|O_EXCL, 0666)) < 0) {
        if (errno != EEXIST ||
            (fd = open(file, O_WRONLY|O_TRUNC, 0666)) < 0) {
            vshError(ctl, _("cannot create file %1$s"), file);
            goto cleanup;
        }
    } else {
        created = true;
    }

    cbdata.ctl = ctl;
    cbdata.fd = fd;

    if (virStreamRecvAll(st, virshStreamSink, &cbdata) < 0) {
        vshError(ctl, _("could not receive data from domain '%1$s'"), name);
        goto cleanup;
    }

    if (VIR_CLOSE(fd) < 0) {
        vshError(ctl, _("cannot close file %1$s"), file);
        goto cleanup;
    }

    if (virStreamFinish(st) < 0) {
        vshError(ctl, _("cannot close stream on domain '%1$s'"), name);
        goto cleanup;
    }

    vshPrintExtra(ctl, _("Screenshot saved to %1$s, with type of %2$s"), file, mime);
    ret = true;

 cleanup:
    if (!ret && created)
        unlink(file);
    if (generated)
        VIR_FREE(file);
    return ret;
}

/*
 * "set-lifecycle-action" command
 */
static const vshCmdInfo info_setLifecycleAction[] = {
    {.name = "help",
     .data = N_("change lifecycle actions")
    },
    {.name = "desc",
     .data = N_("Change lifecycle actions for the guest domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_setLifecycleAction[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "type",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshDomainLifecycleCompleter,
     .help = N_("lifecycle type to modify")
    },
    {.name = "action",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshDomainLifecycleActionCompleter,
     .help = N_("lifecycle action to set")
    },
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = NULL}
};

VIR_ENUM_IMPL(virshDomainLifecycle,
              VIR_DOMAIN_LIFECYCLE_LAST,
              "poweroff",
              "reboot",
              "crash");

VIR_ENUM_IMPL(virshDomainLifecycleAction,
              VIR_DOMAIN_LIFECYCLE_ACTION_LAST,
              "destroy",
              "restart",
              "rename-restart",
              "preserve",
              "coredump-destroy",
              "coredump-restart");

static bool
cmdSetLifecycleAction(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool current = vshCommandOptBool(cmd, "current");
    const char *typeStr;
    const char *actionStr;
    unsigned int type;
    unsigned int action;
    unsigned int flags = 0;
    int tmpVal;

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (config)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (vshCommandOptStringReq(ctl, cmd, "type", &typeStr) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "action", &actionStr) < 0) {
        return false;
    }

    if ((tmpVal = virshDomainLifecycleTypeFromString(typeStr)) < 0) {
        vshError(ctl, _("Invalid lifecycle type '%1$s'."), typeStr);
        return false;
    }
    type = tmpVal;

    if ((tmpVal = virshDomainLifecycleActionTypeFromString(actionStr)) < 0) {
        vshError(ctl, _("Invalid lifecycle action '%1$s'."), actionStr);
        return false;
    }
    action = tmpVal;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virDomainSetLifecycleAction(dom, type, action, flags) < 0) {
        vshError(ctl, "%s", _("Unable to change lifecycle action."));
        return false;
    }
    return true;
}

/*
 * "set-user-password" command
 */
static const vshCmdInfo info_set_user_password[] = {
    {.name = "help",
     .data = N_("set the user password inside the domain")
    },
    {.name = "desc",
     .data = N_("changes the password of the specified user inside the domain")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_set_user_password[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "user",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("the username")
    },
    {.name = "password",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshCompleteEmpty,
     .help = N_("the new password")
    },
    {.name = "encrypted",
     .type = VSH_OT_BOOL,
     .help = N_("the password is already encrypted")
    },
    {.name = NULL}
};

static bool
cmdSetUserPassword(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *name;
    const char *password = NULL;
    const char *user = NULL;
    unsigned int flags = 0;

    if (vshCommandOptBool(cmd, "encrypted"))
        flags = VIR_DOMAIN_PASSWORD_ENCRYPTED;

    if (vshCommandOptStringReq(ctl, cmd, "user", &user) < 0)
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "password", &password) < 0)
        return false;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (virDomainSetUserPassword(dom, user, password, flags) < 0)
        return false;

    vshPrintExtra(ctl, _("Password set successfully for %1$s in %2$s"), user, name);
    return true;
}
/*
 * "resume" command
 */
static const vshCmdInfo info_resume[] = {
    {.name = "help",
     .data = N_("resume a domain")
    },
    {.name = "desc",
     .data = N_("Resume a previously suspended domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_resume[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_PAUSED),
    {.name = NULL}
};

static bool
cmdResume(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *name;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (virDomainResume(dom) != 0) {
        vshError(ctl, _("Failed to resume domain '%1$s'"), name);
        return false;
    }

    vshPrintExtra(ctl, _("Domain '%1$s' resumed\n"), name);
    return true;
}

/*
 * "shutdown" command
 */
static const vshCmdInfo info_shutdown[] = {
    {.name = "help",
     .data = N_("gracefully shutdown a domain")
    },
    {.name = "desc",
     .data = N_("Run shutdown in the target domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_shutdown[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "mode",
     .type = VSH_OT_STRING,
     .completer = virshDomainShutdownModeCompleter,
     .help = N_("shutdown mode: acpi|agent|initctl|signal|paravirt")
    },
    {.name = NULL}
};

static bool
cmdShutdown(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *name;
    const char *mode = NULL;
    int flags = 0;
    int rv;
    g_auto(GStrv) modes = NULL;
    char **tmp;

    if (vshCommandOptStringReq(ctl, cmd, "mode", &mode) < 0)
        return false;

    if (mode && !(modes = g_strsplit(mode, ",", 0))) {
        vshError(ctl, "%s", _("Cannot parse mode string"));
        return false;
    }

    tmp = modes;
    while (tmp && *tmp) {
        mode = *tmp;
        if (STREQ(mode, "acpi")) {
            flags |= VIR_DOMAIN_SHUTDOWN_ACPI_POWER_BTN;
        } else if (STREQ(mode, "agent")) {
            flags |= VIR_DOMAIN_SHUTDOWN_GUEST_AGENT;
        } else if (STREQ(mode, "initctl")) {
            flags |= VIR_DOMAIN_SHUTDOWN_INITCTL;
        } else if (STREQ(mode, "signal")) {
            flags |= VIR_DOMAIN_SHUTDOWN_SIGNAL;
        } else if (STREQ(mode, "paravirt")) {
            flags |= VIR_DOMAIN_SHUTDOWN_PARAVIRT;
        } else {
            vshError(ctl, _("Unknown mode %1$s value, expecting 'acpi', 'agent', 'initctl', 'signal', or 'paravirt'"),
                     mode);
            return false;
        }
        tmp++;
    }

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (flags)
        rv = virDomainShutdownFlags(dom, flags);
    else
        rv = virDomainShutdown(dom);

    if (rv != 0) {
        vshError(ctl, _("Failed to shutdown domain '%1$s'"), name);
        return false;
    }

    vshPrintExtra(ctl, _("Domain '%1$s' is being shutdown\n"), name);
    return true;
}

/*
 * "reboot" command
 */
static const vshCmdInfo info_reboot[] = {
    {.name = "help",
     .data = N_("reboot a domain")
    },
    {.name = "desc",
     .data = N_("Run a reboot command in the target domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_reboot[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "mode",
     .type = VSH_OT_STRING,
     .completer = virshDomainShutdownModeCompleter,
     .help = N_("shutdown mode: acpi|agent|initctl|signal|paravirt")
    },
    {.name = NULL}
};

static bool
cmdReboot(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *name;
    const char *mode = NULL;
    int flags = 0;
    g_auto(GStrv) modes = NULL;
    char **tmp;

    if (vshCommandOptStringReq(ctl, cmd, "mode", &mode) < 0)
        return false;

    if (mode && !(modes = g_strsplit(mode, ",", 0))) {
        vshError(ctl, "%s", _("Cannot parse mode string"));
        return false;
    }

    tmp = modes;
    while (tmp && *tmp) {
        mode = *tmp;
        if (STREQ(mode, "acpi")) {
            flags |= VIR_DOMAIN_REBOOT_ACPI_POWER_BTN;
        } else if (STREQ(mode, "agent")) {
            flags |= VIR_DOMAIN_REBOOT_GUEST_AGENT;
        } else if (STREQ(mode, "initctl")) {
            flags |= VIR_DOMAIN_REBOOT_INITCTL;
        } else if (STREQ(mode, "signal")) {
            flags |= VIR_DOMAIN_REBOOT_SIGNAL;
        } else if (STREQ(mode, "paravirt")) {
            flags |= VIR_DOMAIN_REBOOT_PARAVIRT;
        } else {
            vshError(ctl, _("Unknown mode %1$s value, expecting 'acpi', 'agent', 'initctl', 'signal' or 'paravirt'"),
                     mode);
            return false;
        }
        tmp++;
    }

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (virDomainReboot(dom, flags) != 0) {
        vshError(ctl, _("Failed to reboot domain '%1$s'"), name);
        return false;
    }

    vshPrintExtra(ctl, _("Domain '%1$s' is being rebooted\n"), name);
    return true;
}

/*
 * "reset" command
 */
static const vshCmdInfo info_reset[] = {
    {.name = "help",
     .data = N_("reset a domain")
    },
    {.name = "desc",
     .data = N_("Reset the target domain as if by power button")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_reset[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = NULL}
};

static bool
cmdReset(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *name;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (virDomainReset(dom, 0) != 0) {
        vshError(ctl, _("Failed to reset domain '%1$s'"), name);
        return false;
    }

    vshPrintExtra(ctl, _("Domain '%1$s' was reset\n"), name);
    return true;
}

/*
 * "domjobinfo" command
 */
static const vshCmdInfo info_domjobinfo[] = {
    {.name = "help",
     .data = N_("domain job information")
    },
    {.name = "desc",
     .data = N_("Returns information about jobs running on a domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domjobinfo[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "completed",
     .type = VSH_OT_BOOL,
     .help = N_("return statistics of a recently completed job")
    },
    {.name = "keep-completed",
     .type = VSH_OT_BOOL,
     .help = N_("don't destroy statistics of a recently completed job when reading")
    },
    {.name = "anystats",
     .type = VSH_OT_BOOL,
     .help = N_("print statistics for any kind of job (even failed ones)")
    },
    {.name = "rawstats",
     .type = VSH_OT_BOOL,
     .help = N_("print the raw data returned by libvirt")
    },
    {.name = NULL}
};

VIR_ENUM_DECL(virshDomainJob);
VIR_ENUM_IMPL(virshDomainJob,
              VIR_DOMAIN_JOB_LAST,
              N_("None"),
              N_("Bounded"),
              N_("Unbounded"),
              N_("Completed"),
              N_("Failed"),
              N_("Cancelled"));

static const char *
virshDomainJobToString(int type)
{
    const char *str = virshDomainJobTypeToString(type);
    return str ? _(str) : _("unknown");
}

VIR_ENUM_DECL(virshDomainJobOperation);
VIR_ENUM_IMPL(virshDomainJobOperation,
              VIR_DOMAIN_JOB_OPERATION_LAST,
              N_("Unknown"),
              N_("Start"),
              N_("Save"),
              N_("Restore"),
              N_("Incoming migration"),
              N_("Outgoing migration"),
              N_("Snapshot"),
              N_("Snapshot revert"),
              N_("Dump"),
              N_("Backup"),
              N_("Snapshot delete"),
);

static const char *
virshDomainJobOperationToString(int op)
{
    const char *str = virshDomainJobOperationTypeToString(op);
    return str ? _(str) : _("unknown");
}


static int
virshDomainJobStatsToDomainJobInfo(virTypedParameterPtr params,
                                   int nparams,
                                   virDomainJobInfo *info)
{
    if (virTypedParamsGetULLong(params, nparams, VIR_DOMAIN_JOB_TIME_ELAPSED,
                                &info->timeElapsed) < 0 ||
        virTypedParamsGetULLong(params, nparams, VIR_DOMAIN_JOB_TIME_REMAINING,
                                &info->timeRemaining) < 0 ||
        virTypedParamsGetULLong(params, nparams, VIR_DOMAIN_JOB_DATA_TOTAL,
                                &info->dataTotal) < 0 ||
        virTypedParamsGetULLong(params, nparams, VIR_DOMAIN_JOB_DATA_PROCESSED,
                                &info->dataProcessed) < 0 ||
        virTypedParamsGetULLong(params, nparams, VIR_DOMAIN_JOB_DATA_REMAINING,
                                &info->dataRemaining) < 0 ||
        virTypedParamsGetULLong(params, nparams, VIR_DOMAIN_JOB_MEMORY_TOTAL,
                                &info->memTotal) < 0 ||
        virTypedParamsGetULLong(params, nparams, VIR_DOMAIN_JOB_MEMORY_PROCESSED,
                                &info->memProcessed) < 0 ||
        virTypedParamsGetULLong(params, nparams, VIR_DOMAIN_JOB_MEMORY_REMAINING,
                                &info->memRemaining) < 0 ||
        virTypedParamsGetULLong(params, nparams, VIR_DOMAIN_JOB_DISK_TOTAL,
                                &info->fileTotal) < 0 ||
        virTypedParamsGetULLong(params, nparams, VIR_DOMAIN_JOB_DISK_PROCESSED,
                                &info->fileProcessed) < 0 ||
        virTypedParamsGetULLong(params, nparams, VIR_DOMAIN_JOB_DISK_REMAINING,
                                &info->fileRemaining) < 0) {
        vshSaveLibvirtError();
        return -1;
    }

    return 0;
}


static bool
cmdDomjobinfo(vshControl *ctl, const vshCmd *cmd)
{
    virDomainJobInfo info = { 0 };
    g_autoptr(virshDomain) dom = NULL;
    bool ret = false;
    const char *unit;
    double val;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    unsigned long long value;
    unsigned int flags = 0;
    int ivalue;
    const char *svalue;
    int op;
    int rc;
    size_t i;
    bool rawstats = vshCommandOptBool(cmd, "rawstats");

    VSH_REQUIRE_OPTION("keep-completed", "completed");

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptBool(cmd, "completed"))
        flags |= VIR_DOMAIN_JOB_STATS_COMPLETED;

    if (vshCommandOptBool(cmd, "keep-completed"))
        flags |= VIR_DOMAIN_JOB_STATS_KEEP_COMPLETED;

    rc = virDomainGetJobStats(dom, &info.type, &params, &nparams, flags);
    if (rc == 0) {
        if (virshDomainJobStatsToDomainJobInfo(params, nparams, &info) < 0)
            goto cleanup;
    } else if (last_error->code == VIR_ERR_NO_SUPPORT) {
        if (flags != 0 || rawstats) {
            vshError(ctl, "%s",
                     _("Optional flags or --rawstats are not supported by the daemon"));
            goto cleanup;
        }
        vshDebug(ctl, VSH_ERR_DEBUG, "detailed statistics not supported\n");
        vshResetLibvirtError();
        rc = virDomainGetJobInfo(dom, &info);
    }
    if (rc < 0)
        goto cleanup;

    if (rawstats) {
        vshPrint(ctl, "Job type: %d\n\n", info.type);

        for (i = 0; i < nparams; i++) {
            g_autofree char *par = virTypedParameterToString(&params[i]);
            vshPrint(ctl, "%s: %s\n", params[i].field, NULLSTR(par));
        }

        ret = true;
        goto cleanup;
    }

    vshPrint(ctl, "%-17s %-12s\n", _("Job type:"),
             virshDomainJobToString(info.type));

    if (info.type == VIR_DOMAIN_JOB_NONE) {
        ret = true;
        goto cleanup;
    }

    op = VIR_DOMAIN_JOB_OPERATION_UNKNOWN;
    if ((rc = virTypedParamsGetInt(params, nparams,
                                   VIR_DOMAIN_JOB_OPERATION, &op)) < 0)
        goto save_error;

    vshPrint(ctl, "%-17s %-12s\n", _("Operation:"),
             virshDomainJobOperationToString(op));

    if (!vshCommandOptBool(cmd, "anystats") &&
        info.type != VIR_DOMAIN_JOB_BOUNDED &&
        info.type != VIR_DOMAIN_JOB_UNBOUNDED &&
        (!(flags & VIR_DOMAIN_JOB_STATS_COMPLETED) ||
         info.type != VIR_DOMAIN_JOB_COMPLETED)) {
        ret = true;
        goto cleanup;
    }

    vshPrint(ctl, "%-17s %-12llu ms\n", _("Time elapsed:"), info.timeElapsed);
    if ((rc = virTypedParamsGetULLong(params, nparams,
                                      VIR_DOMAIN_JOB_TIME_ELAPSED_NET,
                                      &value)) < 0) {
        goto save_error;
    } else if (rc) {
        vshPrint(ctl, "%-17s %-12llu ms\n", _("Time elapsed w/o network:"),
                 value);
    }

    if (info.type == VIR_DOMAIN_JOB_BOUNDED)
        vshPrint(ctl, "%-17s %-12llu ms\n", _("Time remaining:"),
                 info.timeRemaining);

    if (info.dataTotal || info.dataRemaining || info.dataProcessed) {
        val = vshPrettyCapacity(info.dataProcessed, &unit);
        vshPrint(ctl, "%-17s %-.3lf %s\n", _("Data processed:"), val, unit);
        val = vshPrettyCapacity(info.dataRemaining, &unit);
        vshPrint(ctl, "%-17s %-.3lf %s\n", _("Data remaining:"), val, unit);
        val = vshPrettyCapacity(info.dataTotal, &unit);
        vshPrint(ctl, "%-17s %-.3lf %s\n", _("Data total:"), val, unit);
    }

    if (info.memTotal || info.memRemaining || info.memProcessed) {
        val = vshPrettyCapacity(info.memProcessed, &unit);
        vshPrint(ctl, "%-17s %-.3lf %s\n", _("Memory processed:"), val, unit);
        val = vshPrettyCapacity(info.memRemaining, &unit);
        vshPrint(ctl, "%-17s %-.3lf %s\n", _("Memory remaining:"), val, unit);
        val = vshPrettyCapacity(info.memTotal, &unit);
        vshPrint(ctl, "%-17s %-.3lf %s\n", _("Memory total:"), val, unit);

        if ((rc = virTypedParamsGetULLong(params, nparams,
                                          VIR_DOMAIN_JOB_MEMORY_BPS,
                                          &value)) < 0) {
            goto save_error;
        } else if (rc && value) {
            val = vshPrettyCapacity(value, &unit);
            vshPrint(ctl, "%-17s %-.3lf %s/s\n",
                     _("Memory bandwidth:"), val, unit);
        }

        if ((rc = virTypedParamsGetULLong(params, nparams,
                                          VIR_DOMAIN_JOB_MEMORY_DIRTY_RATE,
                                          &value)) < 0) {
            goto save_error;
        } else if (rc) {
            vshPrint(ctl, "%-17s %-12llu pages/s\n", _("Dirty rate:"), value);
        }

        if ((rc = virTypedParamsGetULLong(params, nparams,
                                          VIR_DOMAIN_JOB_MEMORY_PAGE_SIZE,
                                          &value)) < 0) {
            goto save_error;
        } else if (rc) {
            vshPrint(ctl, "%-17s %-12llu bytes\n", _("Page size:"), value);
        }

        if ((rc = virTypedParamsGetULLong(params, nparams,
                                          VIR_DOMAIN_JOB_MEMORY_ITERATION,
                                          &value)) < 0) {
            goto save_error;
        } else if (rc) {
            vshPrint(ctl, "%-17s %-12llu\n", _("Iteration:"), value);
        }

        if ((rc = virTypedParamsGetULLong(params, nparams,
                                          VIR_DOMAIN_JOB_MEMORY_POSTCOPY_REQS,
                                          &value)) < 0) {
            goto save_error;
        } else if (rc) {
            vshPrint(ctl, "%-17s %-12llu\n", _("Postcopy requests:"), value);
        }
    }

    if (info.fileTotal || info.fileRemaining || info.fileProcessed) {
        val = vshPrettyCapacity(info.fileProcessed, &unit);
        vshPrint(ctl, "%-17s %-.3lf %s\n", _("File processed:"), val, unit);
        val = vshPrettyCapacity(info.fileRemaining, &unit);
        vshPrint(ctl, "%-17s %-.3lf %s\n", _("File remaining:"), val, unit);
        val = vshPrettyCapacity(info.fileTotal, &unit);
        vshPrint(ctl, "%-17s %-.3lf %s\n", _("File total:"), val, unit);

        if ((rc = virTypedParamsGetULLong(params, nparams,
                                          VIR_DOMAIN_JOB_DISK_BPS,
                                          &value)) < 0) {
            goto save_error;
        } else if (rc && value) {
            val = vshPrettyCapacity(value, &unit);
            vshPrint(ctl, "%-17s %-.3lf %s/s\n",
                     _("File bandwidth:"), val, unit);
        }
    }

    if ((rc = virTypedParamsGetULLong(params, nparams,
                                      VIR_DOMAIN_JOB_MEMORY_CONSTANT,
                                      &value)) < 0) {
        goto save_error;
    } else if (rc) {
        vshPrint(ctl, "%-17s %-12llu\n", _("Constant pages:"), value);
    }
    if ((rc = virTypedParamsGetULLong(params, nparams,
                                      VIR_DOMAIN_JOB_MEMORY_NORMAL,
                                      &value)) < 0) {
        goto save_error;
    } else if (rc) {
        vshPrint(ctl, "%-17s %-12llu\n", _("Normal pages:"), value);
    }
    if ((rc = virTypedParamsGetULLong(params, nparams,
                                      VIR_DOMAIN_JOB_MEMORY_NORMAL_BYTES,
                                      &value)) < 0) {
        goto save_error;
    } else if (rc) {
        val = vshPrettyCapacity(value, &unit);
        vshPrint(ctl, "%-17s %-.3lf %s\n", _("Normal data:"), val, unit);
    }

    if ((rc = virTypedParamsGetULLong(params, nparams,
                                      VIR_DOMAIN_JOB_DOWNTIME,
                                      &value)) < 0) {
        goto save_error;
    } else if (rc) {
        if (info.type == VIR_DOMAIN_JOB_COMPLETED) {
            vshPrint(ctl, "%-17s %-12llu ms\n",
                     _("Total downtime:"), value);
        } else {
            vshPrint(ctl, "%-17s %-12llu ms\n",
                     _("Expected downtime:"), value);
        }
    }

    if ((rc = virTypedParamsGetULLong(params, nparams,
                                      VIR_DOMAIN_JOB_DOWNTIME_NET,
                                      &value)) < 0)
        goto save_error;
    else if (rc)
        vshPrint(ctl, "%-17s %-12llu ms\n", _("Downtime w/o network:"), value);

    if ((rc = virTypedParamsGetULLong(params, nparams,
                                      VIR_DOMAIN_JOB_SETUP_TIME,
                                      &value)) < 0)
        goto save_error;
    else if (rc)
        vshPrint(ctl, "%-17s %-12llu ms\n", _("Setup time:"), value);

    if ((rc = virTypedParamsGetULLong(params, nparams,
                                      VIR_DOMAIN_JOB_COMPRESSION_CACHE,
                                      &value)) < 0) {
        goto save_error;
    } else if (rc) {
        val = vshPrettyCapacity(value, &unit);
        vshPrint(ctl, "%-17s %-.3lf %s\n", _("Compression cache:"), val, unit);
    }
    if ((rc = virTypedParamsGetULLong(params, nparams,
                                      VIR_DOMAIN_JOB_COMPRESSION_BYTES,
                                      &value)) < 0) {
        goto save_error;
    } else if (rc) {
        val = vshPrettyCapacity(value, &unit);
        vshPrint(ctl, "%-17s %-.3lf %s\n", _("Compressed data:"), val, unit);
    }
    if ((rc = virTypedParamsGetULLong(params, nparams,
                                      VIR_DOMAIN_JOB_COMPRESSION_PAGES,
                                      &value)) < 0) {
        goto save_error;
    } else if (rc) {
        vshPrint(ctl, "%-17s %-13llu\n", _("Compressed pages:"), value);
    }
    if ((rc = virTypedParamsGetULLong(params, nparams,
                                      VIR_DOMAIN_JOB_COMPRESSION_CACHE_MISSES,
                                      &value)) < 0) {
        goto save_error;
    } else if (rc) {
        vshPrint(ctl, "%-17s %-13llu\n", _("Compression cache misses:"), value);
    }
    if ((rc = virTypedParamsGetULLong(params, nparams,
                                      VIR_DOMAIN_JOB_COMPRESSION_OVERFLOW,
                                      &value)) < 0) {
        goto save_error;
    } else if (rc) {
        vshPrint(ctl, "%-17s %-13llu\n", _("Compression overflows:"), value);
    }

    if ((rc = virTypedParamsGetInt(params, nparams,
                                   VIR_DOMAIN_JOB_AUTO_CONVERGE_THROTTLE,
                                   &ivalue)) < 0) {
        goto save_error;
    } else if (rc) {
        vshPrint(ctl, "%-17s %-13d\n", _("Auto converge throttle:"), ivalue);
    }

    if ((rc = virTypedParamsGetULLong(params, nparams,
                                      VIR_DOMAIN_JOB_DISK_TEMP_USED,
                                      &value)) < 0) {
        goto save_error;
    } else if (rc) {
        val = vshPrettyCapacity(value, &unit);
        vshPrint(ctl, "%-17s %-.3lf %s\n", _("Temporary disk space use:"), val, unit);
    }

    if ((rc = virTypedParamsGetULLong(params, nparams,
                                      VIR_DOMAIN_JOB_DISK_TEMP_TOTAL,
                                      &value)) < 0) {
        goto save_error;
    } else if (rc) {
        val = vshPrettyCapacity(value, &unit);
        vshPrint(ctl, "%-17s %-.3lf %s\n", _("Temporary disk space total:"), val, unit);
    }

    if ((rc = virTypedParamsGetString(params, nparams, VIR_DOMAIN_JOB_ERRMSG,
                                      &svalue)) < 0) {
        goto save_error;
    } else if (rc == 1) {
        vshPrint(ctl, "%-17s %s\n", _("Error message:"), svalue);
    }

    ret = true;

 cleanup:
    virTypedParamsFree(params, nparams);
    return ret;

 save_error:
    vshSaveLibvirtError();
    goto cleanup;
}

/*
 * "domjobabort" command
 */
static const vshCmdInfo info_domjobabort[] = {
    {.name = "help",
     .data = N_("abort active domain job")
    },
    {.name = "desc",
     .data = N_("Aborts the currently running domain job")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domjobabort[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "postcopy",
     .type = VSH_OT_BOOL,
     .help = N_("interrupt post-copy migration")
    },
    {.name = NULL}
};

static bool
cmdDomjobabort(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    unsigned int flags = 0;
    int rc;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptBool(cmd, "postcopy"))
        flags |= VIR_DOMAIN_ABORT_JOB_POSTCOPY;

    if (flags == 0)
        rc = virDomainAbortJob(dom);
    else
        rc = virDomainAbortJobFlags(dom, flags);

    if (rc < 0)
        return false;

    return true;
}

/*
 * "vcpucount" command
 */
static const vshCmdInfo info_vcpucount[] = {
    {.name = "help",
     .data = N_("domain vcpu counts")
    },
    {.name = "desc",
     .data = N_("Returns the number of virtual CPUs used by the domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_vcpucount[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "maximum",
     .type = VSH_OT_BOOL,
     .help = N_("get maximum count of vcpus")
    },
    {.name = "active",
     .type = VSH_OT_BOOL,
     .help = N_("get number of currently active vcpus")
    },
    VIRSH_COMMON_OPT_LIVE(N_("get value from running domain")),
    VIRSH_COMMON_OPT_CONFIG(N_("get value to be used on next boot")),
    VIRSH_COMMON_OPT_CURRENT(N_("get value according to current domain state")),
    {.name = "guest",
     .type = VSH_OT_BOOL,
     .help = N_("retrieve vcpu count from the guest instead of the hypervisor")
    },
    {.name = NULL}
};

/**
 * Collect the number of vCPUs for a guest possibly with fallback means.
 *
 * Returns the count of vCPUs for a domain and certain flags. Returns -2 in case
 * of error. If @checkState is true, in case live stats can't be collected when
 * the domain is inactive or persistent stats can't be collected if domain is
 * transient -1 is returned and no error is reported.
 */

static int
virshCPUCountCollect(vshControl *ctl,
                     virDomainPtr dom,
                     unsigned int flags,
                     bool checkState)
{
    virDomainInfo info;
    int count;
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;

    if (checkState &&
        ((flags & VIR_DOMAIN_AFFECT_LIVE && virDomainIsActive(dom) < 1) ||
         (flags & VIR_DOMAIN_AFFECT_CONFIG && virDomainIsPersistent(dom) < 1)))
        return -1;

    /* In all cases, try the new API first; if it fails because we are talking
     * to an older daemon, generally we try a fallback API before giving up.
     * --current requires the new API, since we don't know whether the domain is
     *  running or inactive. */
    if ((count = virDomainGetVcpusFlags(dom, flags)) >= 0)
        return count;

    /* fallback code */
    if (!(last_error->code == VIR_ERR_NO_SUPPORT ||
          last_error->code == VIR_ERR_INVALID_ARG))
        return -2;

    if (flags & VIR_DOMAIN_VCPU_GUEST) {
        vshError(ctl, "%s", _("Failed to retrieve vCPU count from the guest"));
        return -2;
    }

    if (!(flags & (VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_AFFECT_CONFIG)) &&
        virDomainIsActive(dom) == 1)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    vshResetLibvirtError();

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (flags & VIR_DOMAIN_VCPU_MAXIMUM)
            return virDomainGetMaxVcpus(dom);

       if (virDomainGetInfo(dom, &info) < 0)
           return -2;

       return info.nrVirtCpu;
    }

    if (virshDomainGetXMLFromDom(ctl, dom, VIR_DOMAIN_XML_INACTIVE,
                                 &xml, &ctxt) < 0)
        return -2;

    if (flags & VIR_DOMAIN_VCPU_MAXIMUM) {
        if (virXPathInt("string(/domain/vcpu)", ctxt, &count) < 0) {
            vshError(ctl, "%s", _("Failed to retrieve maximum vcpu count"));
            return -2;
        }
    } else {
        if (virXPathInt("string(/domain/vcpu/@current)", ctxt, &count) < 0) {
            vshError(ctl, "%s", _("Failed to retrieve current vcpu count"));
            return -2;
        }
    }

    return count;
}

static bool
cmdVcpucount(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    bool maximum = vshCommandOptBool(cmd, "maximum");
    bool active = vshCommandOptBool(cmd, "active");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool current = vshCommandOptBool(cmd, "current");
    bool guest = vshCommandOptBool(cmd, "guest");
    bool all = maximum + active + current + config + live + guest == 0;
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;

    /* Backwards compatibility: prior to 0.9.4,
     * VIR_DOMAIN_AFFECT_CURRENT was unsupported, and --current meant
     * the opposite of --maximum.  Translate the old '--current
     * --live' into the new '--active --live', while treating the new
     * '--maximum --current' correctly rather than rejecting it as
     * '--maximum --active'.  */
    if (!maximum && !active && current)
        current = false;

    VSH_EXCLUSIVE_OPTIONS_VAR(live, config)
    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);
    VSH_EXCLUSIVE_OPTIONS_VAR(active, maximum);
    VSH_EXCLUSIVE_OPTIONS_VAR(guest, config);

    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;
    if (config)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (maximum)
        flags |= VIR_DOMAIN_VCPU_MAXIMUM;
    if (guest)
        flags |= VIR_DOMAIN_VCPU_GUEST;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (all) {
        int conf_max = virshCPUCountCollect(ctl, dom,
                                            VIR_DOMAIN_AFFECT_CONFIG |
                                            VIR_DOMAIN_VCPU_MAXIMUM, true);
        int conf_cur = virshCPUCountCollect(ctl, dom,
                                            VIR_DOMAIN_AFFECT_CONFIG, true);
        int live_max = virshCPUCountCollect(ctl, dom,
                                            VIR_DOMAIN_AFFECT_LIVE |
                                            VIR_DOMAIN_VCPU_MAXIMUM, true);
        int live_cur = virshCPUCountCollect(ctl, dom,
                                            VIR_DOMAIN_AFFECT_LIVE, true);

        if (conf_max == -2 || conf_cur == -2 || live_max == -2 || live_cur ==  -2)
            return false;

#define PRINT_COUNT(VAR, WHICH, STATE) if (VAR > 0) \
    vshPrint(ctl, "%-12s %-12s %3d\n", WHICH, STATE, VAR)
        PRINT_COUNT(conf_max, _("maximum"), _("config"));
        PRINT_COUNT(live_max, _("maximum"), _("live"));
        PRINT_COUNT(conf_cur, _("current"), _("config"));
        PRINT_COUNT(live_cur, _("current"), _("live"));
#undef PRINT_COUNT

    } else {
        int count = virshCPUCountCollect(ctl, dom, flags, false);

        if (count < 0)
            return false;

        vshPrint(ctl, "%d\n", count);
    }

    return true;
}

/*
 * "vcpuinfo" command
 */
static const vshCmdInfo info_vcpuinfo[] = {
    {.name = "help",
     .data = N_("detailed domain vcpu information")
    },
    {.name = "desc",
     .data = N_("Returns basic information about the domain virtual CPUs.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_vcpuinfo[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "pretty",
     .type = VSH_OT_BOOL,
     .help = N_("return human readable output")
    },
    {.name = NULL}
};


static int
virshVcpuinfoPrintAffinity(vshControl *ctl,
                           const unsigned char *cpumap,
                           int maxcpu,
                           bool pretty)
{
    g_autofree char *str = NULL;
    size_t i;

    vshPrint(ctl, "%-15s ", _("CPU Affinity:"));
    if (pretty) {
        if (!(str = virBitmapDataFormat(cpumap, VIR_CPU_MAPLEN(maxcpu))))
            return -1;
        vshPrint(ctl, _("%1$s (out of %2$d)"), str, maxcpu);
    } else {
        for (i = 0; i < maxcpu; i++) {
            if (VIR_CPU_USED(cpumap, i))
                vshPrint(ctl, "y");
            else
                vshPrint(ctl, "-");
        }
    }
    vshPrint(ctl, "\n");

    return 0;
}


static virBitmap *
virshDomainGetVcpuBitmap(vshControl *ctl,
                         virDomainPtr dom,
                         bool inactive)
{
    unsigned int flags = 0;
    g_autoptr(virBitmap) cpumap = NULL;
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    g_autofree xmlNodePtr *nodes = NULL;
    int nnodes;
    size_t i;
    unsigned int curvcpus = 0;
    unsigned int maxvcpus = 0;
    unsigned int vcpuid;

    if (inactive)
        flags |= VIR_DOMAIN_XML_INACTIVE;

    if (virshDomainGetXMLFromDom(ctl, dom, flags, &xml, &ctxt) < 0)
        return NULL;

    if (virXPathUInt("string(/domain/vcpu)", ctxt, &maxvcpus) < 0) {
        vshError(ctl, "%s", _("Failed to retrieve maximum vcpu count"));
        return NULL;
    }

    ignore_value(virXPathUInt("string(/domain/vcpu/@current)", ctxt, &curvcpus));

    if (curvcpus == 0)
        curvcpus = maxvcpus;

    cpumap = virBitmapNew(maxvcpus);

    if ((nnodes = virXPathNodeSet("/domain/vcpus/vcpu", ctxt, &nodes)) <= 0) {
        /* if the specific vcpu state is missing provide a fallback */
        for (i = 0; i < curvcpus; i++)
            ignore_value(virBitmapSetBit(cpumap, i));

        return g_steal_pointer(&cpumap);
    }

    for (i = 0; i < nnodes; i++) {
        g_autofree char *online = NULL;

        ctxt->node = nodes[i];

        if (virXPathUInt("string(@id)", ctxt, &vcpuid) < 0 ||
            !(online = virXPathString("string(@enabled)", ctxt)))
            continue;

        if (STREQ(online, "yes"))
            ignore_value(virBitmapSetBit(cpumap, vcpuid));
    }

    if (virBitmapCountBits(cpumap) != curvcpus) {
        vshError(ctl, "%s", _("Failed to retrieve vcpu state bitmap"));
        return NULL;
    }

    return g_steal_pointer(&cpumap);
}


static bool
virshVcpuinfoInactive(vshControl *ctl,
                      virDomainPtr dom,
                      int maxcpu,
                      bool pretty)
{
    g_autofree unsigned char *cpumaps = NULL;
    size_t cpumaplen;
    g_autoptr(virBitmap) vcpus = NULL;
    ssize_t nextvcpu = -1;
    bool first = true;

    if (!(vcpus = virshDomainGetVcpuBitmap(ctl, dom, true)))
        return false;

    cpumaplen = VIR_CPU_MAPLEN(maxcpu);
    cpumaps = g_new0(unsigned char, virBitmapSize(vcpus) * cpumaplen);

    if (virDomainGetVcpuPinInfo(dom, virBitmapSize(vcpus),
                                cpumaps, cpumaplen,
                                VIR_DOMAIN_AFFECT_CONFIG) < 0)
        return false;

    while ((nextvcpu = virBitmapNextSetBit(vcpus, nextvcpu)) >= 0) {
        if (!first)
            vshPrint(ctl, "\n");
        first = false;

        vshPrint(ctl, "%-15s %zd\n", _("VCPU:"), nextvcpu);
        vshPrint(ctl, "%-15s %s\n", _("CPU:"), _("N/A"));
        vshPrint(ctl, "%-15s %s\n", _("State:"), _("N/A"));
        vshPrint(ctl, "%-15s %s\n", _("CPU time"), _("N/A"));

        if (virshVcpuinfoPrintAffinity(ctl,
                                       VIR_GET_CPUMAP(cpumaps, cpumaplen, nextvcpu),
                                       maxcpu, pretty) < 0)
            return false;
    }

    return true;
}


static bool
cmdVcpuinfo(vshControl *ctl, const vshCmd *cmd)
{
    virDomainInfo info;
    g_autoptr(virshDomain) dom = NULL;
    g_autofree virVcpuInfoPtr cpuinfo = NULL;
    g_autofree unsigned char *cpumaps = NULL;
    int ncpus, maxcpu;
    size_t cpumaplen;
    bool pretty = vshCommandOptBool(cmd, "pretty");
    int n;
    virshControl *priv = ctl->privData;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if ((maxcpu = virshNodeGetCPUCount(priv->conn)) < 0)
        return false;

    if (virDomainGetInfo(dom, &info) != 0)
        return false;

    cpuinfo = g_new0(virVcpuInfo, info.nrVirtCpu);
    cpumaplen = VIR_CPU_MAPLEN(maxcpu);
    cpumaps = g_new0(unsigned char, info.nrVirtCpu * cpumaplen);

    if ((ncpus = virDomainGetVcpus(dom,
                                   cpuinfo, info.nrVirtCpu,
                                   cpumaps, cpumaplen)) < 0) {
        if (info.state != VIR_DOMAIN_SHUTOFF)
            return false;

        vshResetLibvirtError();

        /* for offline VMs we can return pinning information */
        return virshVcpuinfoInactive(ctl, dom, maxcpu, pretty);
    }

    for (n = 0; n < ncpus; n++) {
        vshPrint(ctl, "%-15s %d\n", _("VCPU:"), cpuinfo[n].number);
        vshPrint(ctl, "%-15s %d\n", _("CPU:"), cpuinfo[n].cpu);
        vshPrint(ctl, "%-15s %s\n", _("State:"),
                 virshDomainVcpuStateToString(cpuinfo[n].state));
        if (cpuinfo[n].cpuTime != 0) {
            double cpuUsed = cpuinfo[n].cpuTime;

            cpuUsed /= 1000000000.0;

            vshPrint(ctl, "%-15s %.1lfs\n", _("CPU time:"), cpuUsed);
        }

        if (virshVcpuinfoPrintAffinity(ctl, VIR_GET_CPUMAP(cpumaps, cpumaplen, n),
                                       maxcpu, pretty) < 0)
            return false;

        if (n < (ncpus - 1))
            vshPrint(ctl, "\n");
    }

    return true;
}

/*
 * "vcpupin" command
 */
static const vshCmdInfo info_vcpupin[] = {
    {.name = "help",
     .data = N_("control or query domain vcpu affinity")
    },
    {.name = "desc",
     .data = N_("Pin domain VCPUs to host physical CPUs.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_vcpupin[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "vcpu",
     .type = VSH_OT_INT,
     .completer = virshDomainVcpuCompleter,
     .help = N_("vcpu number")
    },
    {.name = "cpulist",
     .type = VSH_OT_STRING,
     .flags = VSH_OFLAG_EMPTY_OK,
     .completer = virshDomainCpulistCompleter,
     .help = N_("host cpu number(s) to set, or omit option to query")
    },
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = NULL}
};

/*
 * Helper function to print vcpupin info.
 */
static bool
virshPrintPinInfo(vshControl *ctl,
                  unsigned char *cpumap,
                  size_t cpumaplen)
{
    g_autofree char *str = NULL;

    if (!(str = virBitmapDataFormat(cpumap, cpumaplen)))
        return false;

    vshPrint(ctl, "%s", str);
    return true;
}


static bool
virshVcpuPinQuery(vshControl *ctl,
                  virDomainPtr dom,
                  unsigned int vcpu,
                  bool got_vcpu,
                  int maxcpu,
                  unsigned int flags)
{
    g_autofree unsigned char *cpumap = NULL;
    unsigned int countFlags = flags | VIR_DOMAIN_VCPU_MAXIMUM;
    int cpumaplen;
    size_t i;
    int ncpus;
    g_autoptr(vshTable) table = NULL;

    if ((ncpus = virshCPUCountCollect(ctl, dom, countFlags, true)) < 0) {
        if (ncpus == -1) {
            if (flags & VIR_DOMAIN_AFFECT_LIVE)
                vshError(ctl, "%s", _("cannot get vcpupin for offline domain"));
            else
                vshError(ctl, "%s", _("cannot get vcpupin for transient domain"));
        }
        return false;
    }

    if (got_vcpu && vcpu >= ncpus) {
        if (flags & VIR_DOMAIN_AFFECT_LIVE ||
            (!(flags & VIR_DOMAIN_AFFECT_CONFIG) &&
             virDomainIsActive(dom) == 1))
            vshError(ctl,
                     _("vcpu %1$d is out of range of live cpu count %2$d"),
                     vcpu, ncpus);
        else
            vshError(ctl,
                     _("vcpu %1$d is out of range of persistent cpu count %2$d"),
                     vcpu, ncpus);
        return false;
    }

    cpumaplen = VIR_CPU_MAPLEN(maxcpu);
    cpumap = g_new0(unsigned char, ncpus * cpumaplen);
    if ((ncpus = virDomainGetVcpuPinInfo(dom, ncpus, cpumap,
                                         cpumaplen, flags)) >= 0) {
        table = vshTableNew(_("VCPU"), _("CPU Affinity"), NULL);
        if (!table)
            return false;

        for (i = 0; i < ncpus; i++) {
            g_autofree char *pinInfo = NULL;
            g_autofree char *vcpuStr = NULL;
            if (got_vcpu && i != vcpu)
                continue;

            if (!(pinInfo = virBitmapDataFormat(VIR_GET_CPUMAP(cpumap, cpumaplen, i),
                                                cpumaplen)))
                return false;

            vcpuStr = g_strdup_printf("%zu", i);

            if (vshTableRowAppend(table, vcpuStr, pinInfo, NULL) < 0)
                return false;
        }

        vshTablePrintToStdout(table, ctl);
    }

    return true;
}


static unsigned char *
virshParseCPUList(vshControl *ctl, int *cpumaplen,
                  const char *cpulist, int maxcpu)
{
    unsigned char *cpumap = NULL;
    g_autoptr(virBitmap) map = NULL;

    if (cpulist[0] == 'r') {
        map = virBitmapNew(maxcpu);
        virBitmapSetAll(map);
    } else {
        int lastcpu;

        if (virBitmapParse(cpulist, &map, 1024) < 0 ||
            virBitmapIsAllClear(map)) {
            vshError(ctl, _("Invalid cpulist '%1$s'"), cpulist);
            return NULL;
        }
        lastcpu = virBitmapLastSetBit(map);
        if (lastcpu >= maxcpu) {
            vshError(ctl, _("CPU %1$d in cpulist '%2$s' exceed the maxcpu %3$d"),
                     lastcpu, cpulist, maxcpu);
            return NULL;
        }
    }

    if (virBitmapToData(map, &cpumap, cpumaplen) < 0)
        return NULL;

    return cpumap;
}

static bool
cmdVcpuPin(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    unsigned int vcpu = 0;
    const char *cpulist = NULL;
    g_autofree unsigned char *cpumap = NULL;
    int cpumaplen;
    int maxcpu;
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool current = vshCommandOptBool(cmd, "current");
    int got_vcpu;
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;
    virshControl *priv = ctl->privData;

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (config)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (vshCommandOptStringReq(ctl, cmd, "cpulist", &cpulist) < 0)
        return false;

    if (!cpulist)
        VSH_EXCLUSIVE_OPTIONS_VAR(live, config);

    if ((got_vcpu = vshCommandOptUInt(ctl, cmd, "vcpu", &vcpu)) < 0)
        return false;

    /* In pin mode, "vcpu" is necessary */
    if (cpulist && got_vcpu == 0) {
        vshError(ctl, "%s", _("vcpupin: Missing vCPU number in pin mode."));
        return false;
    }

    if ((maxcpu = virshNodeGetCPUCount(priv->conn)) < 0)
        return false;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    /* Query mode: show CPU affinity information then exit.*/
    if (!cpulist) {
        return virshVcpuPinQuery(ctl, dom, vcpu, got_vcpu, maxcpu, flags);
    }

    /* Pin mode: pinning specified vcpu to specified physical cpus */
    if (!(cpumap = virshParseCPUList(ctl, &cpumaplen, cpulist, maxcpu)))
        return false;

    /* use old API without any explicit flags */
    if (flags == VIR_DOMAIN_AFFECT_CURRENT && !current) {
        if (virDomainPinVcpu(dom, vcpu, cpumap, cpumaplen) != 0)
            return false;
    } else {
        if (virDomainPinVcpuFlags(dom, vcpu, cpumap, cpumaplen, flags) != 0)
            return false;
    }

    return true;
}

/*
 * "emulatorpin" command
 */
static const vshCmdInfo info_emulatorpin[] = {
    {.name = "help",
     .data = N_("control or query domain emulator affinity")
    },
    {.name = "desc",
     .data = N_("Pin domain emulator threads to host physical CPUs.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_emulatorpin[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "cpulist",
     .type = VSH_OT_STRING,
     .flags = VSH_OFLAG_EMPTY_OK,
     .completer = virshDomainCpulistCompleter,
     .help = N_("host cpu number(s) to set, or omit option to query")
    },
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = NULL}
};

static bool
cmdEmulatorPin(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *cpulist = NULL;
    g_autofree unsigned char *cpumap = NULL;
    int cpumaplen;
    int maxcpu;
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool current = vshCommandOptBool(cmd, "current");
    bool query = false; /* Query mode if no cpulist */
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;
    virshControl *priv = ctl->privData;

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (config)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;
    /* none of the options were specified */
    if (!current && !live && !config)
        flags = -1;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "cpulist", &cpulist) < 0) {
        return false;
    }
    query = !cpulist;

    if ((maxcpu = virshNodeGetCPUCount(priv->conn)) < 0) {
        return false;
    }

    /* Query mode: show CPU affinity information then exit.*/
    if (query) {
        bool ret = false;

        /* When query mode and neither "live", "config" nor "current"
         * is specified, set VIR_DOMAIN_AFFECT_CURRENT as flags */
        if (flags == -1)
            flags = VIR_DOMAIN_AFFECT_CURRENT;

        cpumaplen = VIR_CPU_MAPLEN(maxcpu);
        cpumap = g_new0(unsigned char, cpumaplen);
        if (virDomainGetEmulatorPinInfo(dom, cpumap,
                                        cpumaplen, flags) >= 0) {
            vshPrintExtra(ctl, "%s %s\n", _("emulator:"), _("CPU Affinity"));
            vshPrintExtra(ctl, "----------------------------------\n");
            vshPrintExtra(ctl, "       *: ");
            ret = virshPrintPinInfo(ctl, cpumap, cpumaplen);
            vshPrint(ctl, "\n");
        }
        return ret;
    }

    /* Pin mode: pinning emulator threads to specified physical cpus */
    if (!(cpumap = virshParseCPUList(ctl, &cpumaplen, cpulist, maxcpu)))
        return false;

    if (flags == -1)
        flags = VIR_DOMAIN_AFFECT_LIVE;

    if (virDomainPinEmulator(dom, cpumap, cpumaplen, flags) != 0)
        return false;

    return true;
}

/*
 * "setvcpus" command
 */
static const vshCmdInfo info_setvcpus[] = {
    {.name = "help",
     .data = N_("change number of virtual CPUs")
    },
    {.name = "desc",
     .data = N_("Change the number of virtual CPUs in the guest domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_setvcpus[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "count",
     .type = VSH_OT_INT,
     .flags = VSH_OFLAG_REQ,
     .help = N_("number of virtual CPUs")
    },
    {.name = "maximum",
     .type = VSH_OT_BOOL,
     .help = N_("set maximum limit on next boot")
    },
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = "guest",
     .type = VSH_OT_BOOL,
     .help = N_("modify cpu state in the guest")
    },
    {.name = "hotpluggable",
     .type = VSH_OT_BOOL,
     .help = N_("make added vcpus hot(un)pluggable")
    },
    {.name = NULL}
};

static bool
cmdSetvcpus(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    unsigned int count = 0;
    bool maximum = vshCommandOptBool(cmd, "maximum");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool current = vshCommandOptBool(cmd, "current");
    bool guest = vshCommandOptBool(cmd, "guest");
    bool hotpluggable = vshCommandOptBool(cmd, "hotpluggable");
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);
    VSH_EXCLUSIVE_OPTIONS_VAR(guest, config);

    VSH_REQUIRE_OPTION_VAR(maximum, config);

    if (config)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;
    if (guest)
        flags |= VIR_DOMAIN_VCPU_GUEST;
    if (maximum)
        flags |= VIR_DOMAIN_VCPU_MAXIMUM;
    if (hotpluggable)
        flags |= VIR_DOMAIN_VCPU_HOTPLUGGABLE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptUInt(ctl, cmd, "count", &count) < 0)
        return false;

    if (count == 0) {
        vshError(ctl, _("Can't set 0 processors for a VM"));
        return false;
    }

    /* none of the options were specified */
    if (!current && flags == 0) {
        if (virDomainSetVcpus(dom, count) != 0)
            return false;
    } else {
        if (virDomainSetVcpusFlags(dom, count, flags) < 0)
            return false;
    }

    return true;
}


/*
 * "guestvcpus" command
 */
static const vshCmdInfo info_guestvcpus[] = {
    {.name = "help",
     .data = N_("query or modify state of vcpu in the guest (via agent)")
    },
    {.name = "desc",
     .data = N_("Use the guest agent to query or set cpu state from guest's "
                "point of view")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_guestvcpus[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "cpulist",
     .type = VSH_OT_STRING,
     .completer = virshDomainVcpulistViaAgentCompleter,
     .help = N_("list of cpus to enable or disable")
    },
    {.name = "enable",
     .type = VSH_OT_BOOL,
     .help = N_("enable cpus specified by cpulist")
    },
    {.name = "disable",
     .type = VSH_OT_BOOL,
     .help = N_("disable cpus specified by cpulist")
    },
    {.name = NULL}
};

static bool
cmdGuestvcpus(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    bool enable = vshCommandOptBool(cmd, "enable");
    bool disable = vshCommandOptBool(cmd, "disable");
    virTypedParameterPtr params = NULL;
    unsigned int nparams = 0;
    const char *cpulist = NULL;
    int state = 0;
    size_t i;
    bool ret = false;

    VSH_EXCLUSIVE_OPTIONS_VAR(enable, disable);
    VSH_REQUIRE_OPTION("enable", "cpulist");
    VSH_REQUIRE_OPTION("disable", "cpulist");

    if (vshCommandOptStringReq(ctl, cmd, "cpulist", &cpulist))
        return false;

    if (cpulist && !(enable || disable)) {
        vshError(ctl, _("One of options --enable or --disable is required by option --cpulist"));
        return false;
    }

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (enable)
        state = 1;

    if (cpulist) {
        if (virDomainSetGuestVcpus(dom, cpulist, state, 0) < 0)
            goto cleanup;
    } else {
        if (virDomainGetGuestVcpus(dom, &params, &nparams, 0) < 0)
            goto cleanup;

        for (i = 0; i < nparams; i++) {
            g_autofree char *str = vshGetTypedParamValue(ctl, &params[i]);
            vshPrint(ctl, "%-15s: %s\n", params[i].field, str);
        }
    }

    ret = true;

 cleanup:
    virTypedParamsFree(params, nparams);
    return ret;
}


/*
 * "setvcpu" command
 */
static const vshCmdInfo info_setvcpu[] = {
    {.name = "help",
     .data = N_("attach/detach vcpu or groups of threads")
    },
    {.name = "desc",
     .data = N_("Add or remove vcpus")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_setvcpu[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "vcpulist",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshDomainVcpulistCompleter,
     .help = N_("ids of vcpus to manipulate")
    },
    {.name = "enable",
     .type = VSH_OT_BOOL,
     .help = N_("enable cpus specified by cpumap")
    },
    {.name = "disable",
     .type = VSH_OT_BOOL,
     .help = N_("disable cpus specified by cpumap")
    },
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = NULL}
};

static bool
cmdSetvcpu(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    bool enable = vshCommandOptBool(cmd, "enable");
    bool disable = vshCommandOptBool(cmd, "disable");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    const char *vcpulist = NULL;
    int state = 0;
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;

    VSH_EXCLUSIVE_OPTIONS_VAR(enable, disable);

    VSH_EXCLUSIVE_OPTIONS("current", "live");
    VSH_EXCLUSIVE_OPTIONS("current", "config");

    if (config)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (!(enable || disable)) {
        vshError(ctl, "%s", _("one of --enable, --disable is required"));
        return false;
    }

    if (vshCommandOptStringReq(ctl, cmd, "vcpulist", &vcpulist))
        return false;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (enable)
        state = 1;

    if (virDomainSetVcpu(dom, vcpulist, state, flags) < 0)
        return false;

    return true;
}


/*
 * "domblkthreshold" command
 */
static const vshCmdInfo info_domblkthreshold[] = {
    {.name = "help",
     .data = N_("set the threshold for block-threshold event for a given block "
                "device or it's backing chain element")
    },
    {.name = "desc",
     .data = N_("set threshold for block-threshold event for a block device")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domblkthreshold[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "dev",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshDomainDiskTargetCompleter,
     .help = N_("device to set threshold for")
    },
    {.name = "threshold",
     .type = VSH_OT_INT,
     .flags = VSH_OFLAG_REQ,
     .help = N_("threshold as a scaled number (by default bytes)")
    },
    {.name = NULL}
};

static bool
cmdDomblkthreshold(vshControl *ctl, const vshCmd *cmd)
{
    unsigned long long threshold;
    const char *dev = NULL;
    g_autoptr(virshDomain) dom = NULL;

    if (vshCommandOptStringReq(ctl, cmd, "dev", &dev))
        return false;

    if (vshCommandOptScaledInt(ctl, cmd, "threshold",
                               &threshold, 1, ULLONG_MAX) < 0)
        return false;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virDomainSetBlockThreshold(dom, dev, threshold, 0) < 0)
        return false;

    return true;
}


/*
 * "iothreadinfo" command
 */
static const vshCmdInfo info_iothreadinfo[] = {
    {.name = "help",
     .data = N_("view domain IOThreads")
    },
    {.name = "desc",
     .data = N_("Returns basic information about the domain IOThreads.")
    },
    {.name = NULL}
};
static const vshCmdOptDef opts_iothreadinfo[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = NULL}
};

static bool
cmdIOThreadInfo(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool current = vshCommandOptBool(cmd, "current");
    size_t niothreads = 0;
    virDomainIOThreadInfoPtr *info = NULL;
    size_t i;
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;
    g_autoptr(vshTable) table = NULL;
    bool ret = false;
    int rc;

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (config)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if ((rc = virDomainGetIOThreadInfo(dom, &info, flags)) < 0) {
        vshError(ctl, _("Unable to get domain IOThreads information"));
        goto cleanup;
    }
    niothreads = rc;

    if (niothreads == 0) {
        ret = true;
        vshPrintExtra(ctl, _("No IOThreads found for the domain"));
        goto cleanup;
    }

    table = vshTableNew(_("IOThread ID"), _("CPU Affinity"), NULL);
    if (!table)
        goto cleanup;

    for (i = 0; i < niothreads; i++) {
        g_autofree char *pinInfo = NULL;
        g_autofree char *iothreadIdStr = NULL;

        iothreadIdStr = g_strdup_printf("%u", info[i]->iothread_id);

        ignore_value(pinInfo = virBitmapDataFormat(info[i]->cpumap, info[i]->cpumaplen));

        if (vshTableRowAppend(table, iothreadIdStr, NULLSTR_EMPTY(pinInfo), NULL) < 0)
            goto cleanup;
    }

    vshTablePrintToStdout(table, ctl);

    ret = true;

 cleanup:
    for (i = 0; i < niothreads; i++)
        virDomainIOThreadInfoFree(info[i]);
    VIR_FREE(info);
    return ret;
}

/*
 * "iothreadpin" command
 */
static const vshCmdInfo info_iothreadpin[] = {
    {.name = "help",
     .data = N_("control domain IOThread affinity")
    },
    {.name = "desc",
     .data = N_("Pin domain IOThreads to host physical CPUs.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_iothreadpin[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "iothread",
     .type = VSH_OT_INT,
     .flags = VSH_OFLAG_REQ,
     .completer = virshDomainIOThreadIdCompleter,
     .help = N_("IOThread ID number")
    },
    {.name = "cpulist",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshDomainCpulistCompleter,
     .help = N_("host cpu number(s) to set")
    },
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = NULL}
};

static bool
cmdIOThreadPin(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *cpulist = NULL;
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool current = vshCommandOptBool(cmd, "current");
    unsigned int iothread_id = 0;
    int maxcpu;
    g_autofree unsigned char *cpumap = NULL;
    int cpumaplen;
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;
    virshControl *priv = ctl->privData;

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (config)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptUInt(ctl, cmd, "iothread", &iothread_id) < 0)
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "cpulist", &cpulist) < 0)
        return false;

    if ((maxcpu = virshNodeGetCPUCount(priv->conn)) < 0)
        return false;

    if (!(cpumap = virshParseCPUList(ctl, &cpumaplen, cpulist, maxcpu)))
        return false;

    if (virDomainPinIOThread(dom, iothread_id,
                             cpumap, cpumaplen, flags) != 0)
        return false;

    return true;
}

/*
 * "iothreadadd" command
 */
static const vshCmdInfo info_iothreadadd[] = {
    {.name = "help",
     .data = N_("add an IOThread to the guest domain")
    },
    {.name = "desc",
     .data = N_("Add an IOThread to the guest domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_iothreadadd[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "id",
     .type = VSH_OT_INT,
     .flags = VSH_OFLAG_REQ,
     .help = N_("iothread for the new IOThread")
    },
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = NULL}
};

static bool
cmdIOThreadAdd(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    int iothread_id = 0;
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool current = vshCommandOptBool(cmd, "current");
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (config)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptInt(ctl, cmd, "id", &iothread_id) < 0)
        return false;
    if (iothread_id <= 0) {
        vshError(ctl, _("Invalid IOThread id value: '%1$d'"), iothread_id);
        return false;
    }

    if (virDomainAddIOThread(dom, iothread_id, flags) < 0)
        return false;

    return true;
}


 /*
 * "iothreadset" command
 */
static const vshCmdInfo info_iothreadset[] = {
    {.name = "help",
     .data = N_("modifies an existing IOThread of the guest domain")
    },
    {.name = "desc",
     .data = N_("Modifies an existing IOThread of the guest domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_iothreadset[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "id",
     .type = VSH_OT_INT,
     .flags = VSH_OFLAG_REQ,
     .completer = virshDomainIOThreadIdCompleter,
     .help = N_("iothread id of existing IOThread")
    },
    {.name = "poll-max-ns",
     .type = VSH_OT_INT,
     .help = N_("set the maximum IOThread polling time in ns")
    },
    {.name = "poll-grow",
     .type = VSH_OT_INT,
     .help = N_("set the value to increase the IOThread polling time")
    },
    {.name = "poll-shrink",
     .type = VSH_OT_INT,
     .help = N_("set the value for reduction of the IOThread polling time")
    },
    {.name = "thread-pool-min",
     .type = VSH_OT_INT,
     .help = N_("lower boundary for worker thread pool")
    },
    {.name = "thread-pool-max",
     .type = VSH_OT_INT,
     .help = N_("upper boundary for worker thread pool")
    },
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = NULL}
};

static bool
cmdIOThreadSet(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    int id = 0;
    bool current = vshCommandOptBool(cmd, "current");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;
    g_autoptr(virTypedParamList) params = virTypedParamListNew();
    virTypedParameterPtr par;
    size_t npar = 0;
    unsigned long long poll_val;
    int thread_val;
    int rc;

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;
    if (config)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptInt(ctl, cmd, "id", &id) < 0)
        return false;
    if (id <= 0) {
        vshError(ctl, _("Invalid IOThread id value: '%1$d'"), id);
        return false;
    }

    if ((rc = vshCommandOptULongLong(ctl, cmd, "poll-max-ns", &poll_val)) < 0)
        return false;
    if (rc > 0)
        virTypedParamListAddULLong(params, poll_val, VIR_DOMAIN_IOTHREAD_POLL_MAX_NS);

    if ((rc = vshCommandOptULongLong(ctl, cmd, "poll-grow", &poll_val)) < 0)
        return false;
    if (rc > 0)
        virTypedParamListAddUnsigned(params, poll_val, VIR_DOMAIN_IOTHREAD_POLL_GROW);

    if ((rc = vshCommandOptULongLong(ctl, cmd, "poll-shrink", &poll_val)) < 0)
        return false;
    if (rc > 0)
        virTypedParamListAddUnsigned(params, poll_val, VIR_DOMAIN_IOTHREAD_POLL_SHRINK);

    if ((rc = vshCommandOptInt(ctl, cmd, "thread-pool-min", &thread_val)) < 0)
        return false;
    if (rc > 0)
        virTypedParamListAddInt(params, thread_val, VIR_DOMAIN_IOTHREAD_THREAD_POOL_MIN);

    if ((rc = vshCommandOptInt(ctl, cmd, "thread-pool-max", &thread_val)) < 0)
        return false;
    if (rc > 0)
        virTypedParamListAddInt(params, thread_val, VIR_DOMAIN_IOTHREAD_THREAD_POOL_MAX);

    if (virTypedParamListFetch(params, &par, &npar) < 0)
        return false;

    if (npar == 0) {
        vshError(ctl, _("Not enough arguments passed, nothing to set"));
        return false;
    }

    if (virDomainSetIOThreadParams(dom, id, par, npar, flags) < 0)
        return false;

    return true;
}


/*
 * "iothreaddel" command
 */
static const vshCmdInfo info_iothreaddel[] = {
    {.name = "help",
     .data = N_("delete an IOThread from the guest domain")
    },
    {.name = "desc",
     .data = N_("Delete an IOThread from the guest domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_iothreaddel[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "id",
     .type = VSH_OT_INT,
     .flags = VSH_OFLAG_REQ,
     .completer = virshDomainIOThreadIdCompleter,
     .help = N_("iothread_id for the IOThread to delete")
    },
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = NULL}
};

static bool
cmdIOThreadDel(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    int iothread_id = 0;
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool current = vshCommandOptBool(cmd, "current");
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (config)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptInt(ctl, cmd, "id", &iothread_id) < 0)
        return false;
    if (iothread_id <= 0) {
        vshError(ctl, _("Invalid IOThread id value: '%1$d'"), iothread_id);
        return false;
    }

    if (virDomainDelIOThread(dom, iothread_id, flags) < 0)
        return false;

    return true;
}

/*
 * "cpu-stats" command
 */
static const vshCmdInfo info_cpu_stats[] = {
    {.name = "help",
     .data = N_("show domain cpu statistics")
    },
    {.name = "desc",
     .data = N_("Display per-CPU and total statistics about the domain's CPUs")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_cpu_stats[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "total",
     .type = VSH_OT_BOOL,
     .help = N_("Show total statistics only")
    },
    {.name = "start",
     .type = VSH_OT_INT,
     .help = N_("Show statistics from this CPU")
    },
    {.name = "count",
     .type = VSH_OT_INT,
     .help = N_("Number of shown CPUs at most")
    },
    {.name = NULL}
};

static void
vshCPUStatsPrintField(vshControl *ctl,
                      virTypedParameterPtr param)
{
    vshPrint(ctl, "\t%-12s ", param->field);
    if ((STREQ(param->field, VIR_DOMAIN_CPU_STATS_CPUTIME) ||
         STREQ(param->field, VIR_DOMAIN_CPU_STATS_VCPUTIME) ||
         STREQ(param->field, VIR_DOMAIN_CPU_STATS_USERTIME) ||
         STREQ(param->field, VIR_DOMAIN_CPU_STATS_SYSTEMTIME)) &&
        param->type == VIR_TYPED_PARAM_ULLONG) {
        vshPrint(ctl, "%9lld.%09lld seconds\n",
                 param->value.ul / 1000000000,
                 param->value.ul % 1000000000);
    } else {
        g_autofree char *s = vshGetTypedParamValue(ctl, param);
        vshPrint(ctl, "%s\n", s);
    }
}

static bool
cmdCPUStats(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    virTypedParameterPtr params = NULL;
    int max_id, cpu = 0, show_count = -1, nparams = 0, stats_per_cpu;
    size_t i, j;
    bool show_total = false, show_per_cpu = false;
    bool ret = false;
    int rv = 0;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    show_total = vshCommandOptBool(cmd, "total");

    if ((rv = vshCommandOptInt(ctl, cmd, "start", &cpu)) < 0) {
        goto cleanup;
    } else if (rv > 0) {
        if (cpu < 0) {
            vshError(ctl, "%s", _("Invalid value for start CPU"));
            goto cleanup;
        }
        show_per_cpu = true;
    }

    if ((rv = vshCommandOptInt(ctl, cmd, "count", &show_count)) < 0) {
        goto cleanup;
    } else if (rv > 0) {
        if (show_count < 0) {
            vshError(ctl, "%s", _("Invalid value for number of CPUs to show"));
            goto cleanup;
        }
        show_per_cpu = true;
    }

    /* default show per_cpu and total */
    if (!show_total && !show_per_cpu) {
        show_total = true;
        show_per_cpu = true;
    }

    if (!show_per_cpu) /* show total stats only */
        goto do_show_total;

    /* get number of cpus on the node */
    if ((max_id = virDomainGetCPUStats(dom, NULL, 0, 0, 0, 0)) < 0)
        goto failed_stats;

    if (cpu >= max_id) {
        vshError(ctl, "Start CPU %d is out of range (min: 0, max: %d)",
                 cpu, max_id - 1);
        goto cleanup;
    }

    if (show_count < 0 || show_count > max_id) {
        if (show_count > max_id)
            vshPrint(ctl, _("Only %1$d CPUs available to show\n"), max_id);
        show_count = max_id - cpu;
    }

    /* get percpu information */
    if ((nparams = virDomainGetCPUStats(dom, NULL, 0, 0, 1, 0)) < 0)
        goto failed_stats;

    if (!nparams) {
        vshPrint(ctl, "%s", _("No per-CPU stats available"));
        if (show_total)
            goto do_show_total;
        goto cleanup;
    }

    params = g_new0(virTypedParameter, nparams * MIN(show_count, 128));

    while (show_count) {
        int ncpus = MIN(show_count, 128);

        if (virDomainGetCPUStats(dom, params, nparams, cpu, ncpus, 0) < 0)
            goto failed_stats;

        for (i = 0; i < ncpus; i++) {
            if (params[i * nparams].type == 0) /* this cpu is not in the map */
                continue;
            vshPrint(ctl, "CPU%zu:\n", cpu + i);

            for (j = 0; j < nparams; j++)
                vshCPUStatsPrintField(ctl, params + (i * nparams + j));
        }
        cpu += ncpus;
        show_count -= ncpus;
        virTypedParamsClear(params, nparams * ncpus);
    }
    VIR_FREE(params);

    if (!show_total) {
        ret = true;
        goto cleanup;
    }

 do_show_total:
    /* get supported num of parameter for total statistics */
    if ((nparams = virDomainGetCPUStats(dom, NULL, 0, -1, 1, 0)) < 0)
        goto failed_stats;

    if (!nparams) {
        vshPrint(ctl, "%s", _("No total stats available"));
        goto cleanup;
    }

    params = g_new0(virTypedParameter, nparams);

    /* passing start_cpu == -1 gives us domain's total status */
    if ((stats_per_cpu = virDomainGetCPUStats(dom, params, nparams,
                                              -1, 1, 0)) < 0)
        goto failed_stats;

    vshPrint(ctl, _("Total:\n"));
    for (i = 0; i < stats_per_cpu; i++)
        vshCPUStatsPrintField(ctl, params + i);

    ret = true;

 cleanup:
    virTypedParamsFree(params, nparams);
    return ret;

 failed_stats:
    vshError(ctl, _("Failed to retrieve CPU statistics for domain '%1$s'"),
             virDomainGetName(dom));
    goto cleanup;
}

/*
 * "create" command
 */
static const vshCmdInfo info_create[] = {
    {.name = "help",
     .data = N_("create a domain from an XML file")
    },
    {.name = "desc",
     .data = N_("Create a domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_create[] = {
    VIRSH_COMMON_OPT_FILE(N_("file containing an XML domain description")),
#ifndef WIN32
    {.name = "console",
     .type = VSH_OT_BOOL,
     .help = N_("attach to console after creation")
    },
#endif
    {.name = "paused",
     .type = VSH_OT_BOOL,
     .help = N_("leave the guest paused after creation")
    },
    {.name = "autodestroy",
     .type = VSH_OT_BOOL,
     .help = N_("automatically destroy the guest when virsh disconnects")
    },
    {.name = "pass-fds",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("pass file descriptors N,M,... to the guest")
    },
    {.name = "validate",
     .type = VSH_OT_BOOL,
     .help = N_("validate the XML against the schema")
    },
    {.name = "reset-nvram",
     .type = VSH_OT_BOOL,
     .help = N_("re-initialize NVRAM from its pristine template")
    },
    {.name = NULL}
};

static virshDomain *
virshDomainCreateXMLHelper(virConnectPtr conn,
                           const char *xmlDesc,
                           unsigned int nfds,
                           int *fds,
                           unsigned int flags)
{
    if (nfds) {
        return virDomainCreateXMLWithFiles(conn, xmlDesc, nfds, fds, flags);
    }

    return virDomainCreateXML(conn, xmlDesc, flags);
}

static bool
cmdCreate(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *from = NULL;
    g_autofree char *buffer = NULL;
#ifndef WIN32
    bool console = vshCommandOptBool(cmd, "console");
    bool resume_domain = false;
#endif
    unsigned int flags = 0;
    size_t nfds = 0;
    g_autofree int *fds = NULL;
    virshControl *priv = ctl->privData;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        return false;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    if (virshFetchPassFdsList(ctl, cmd, &nfds, &fds) < 0)
        return false;

    if (vshCommandOptBool(cmd, "paused")) {
        flags |= VIR_DOMAIN_START_PAUSED;
#ifndef WIN32
    } else if (console) {
        flags |= VIR_DOMAIN_START_PAUSED;
        resume_domain = true;
#endif
    }
    if (vshCommandOptBool(cmd, "autodestroy"))
        flags |= VIR_DOMAIN_START_AUTODESTROY;
    if (vshCommandOptBool(cmd, "validate"))
        flags |= VIR_DOMAIN_START_VALIDATE;
    if (vshCommandOptBool(cmd, "reset-nvram"))
        flags |= VIR_DOMAIN_START_RESET_NVRAM;

    dom = virshDomainCreateXMLHelper(priv->conn, buffer, nfds, fds, flags);
#ifndef WIN32
    /* If the driver does not support the paused flag, let's fallback to the old
     * behavior without the flag. */
    if (!dom && resume_domain && last_error && last_error->code == VIR_ERR_INVALID_ARG) {
      vshResetLibvirtError();

      flags &= ~VIR_DOMAIN_START_PAUSED;
      resume_domain = false;
      dom = virshDomainCreateXMLHelper(priv->conn, buffer, nfds, fds, flags);
    }
#endif

    if (!dom) {
        vshError(ctl, _("Failed to create domain from %1$s"), from);
        return false;
    }

    vshPrintExtra(ctl, _("Domain '%1$s' created from %2$s\n"),
                  virDomainGetName(dom), from);
#ifndef WIN32
    if (console)
        cmdRunConsole(ctl, dom, NULL, resume_domain, 0);
#endif
    return true;
}

/*
 * "define" command
 */
static const vshCmdInfo info_define[] = {
    {.name = "help",
     .data = N_("define (but don't start) a domain from an XML file")
    },
    {.name = "desc",
     .data = N_("Define a domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_define[] = {
    VIRSH_COMMON_OPT_FILE(N_("file containing an XML domain description")),
    {.name = "validate",
     .type = VSH_OT_BOOL,
     .help = N_("validate the XML against the schema")
    },
    {.name = NULL}
};

static bool
cmdDefine(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *from = NULL;
    g_autofree char *buffer = NULL;
    unsigned int flags = 0;
    virshControl *priv = ctl->privData;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        return false;

    if (vshCommandOptBool(cmd, "validate"))
        flags |= VIR_DOMAIN_DEFINE_VALIDATE;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    if (flags)
        dom = virDomainDefineXMLFlags(priv->conn, buffer, flags);
    else
        dom = virDomainDefineXML(priv->conn, buffer);

    if (!dom) {
        vshError(ctl, _("Failed to define domain from %1$s"), from);
        return false;
    }

    vshPrintExtra(ctl, _("Domain '%1$s' defined from %2$s\n"),
                  virDomainGetName(dom), from);
    return true;
}

/*
 * "destroy" command
 */
static const vshCmdInfo info_destroy[] = {
    {.name = "help",
     .data = N_("destroy (stop) a domain")
    },
    {.name = "desc",
     .data = N_("Forcefully stop a given domain, but leave its resources intact.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_destroy[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "graceful",
     .type = VSH_OT_BOOL,
     .help = N_("terminate gracefully")
    },
    {.name = "remove-logs",
     .type = VSH_OT_BOOL,
     .help = N_("remove domain logs")
    },
    {.name = NULL}
};

static bool
cmdDestroy(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *name;
    unsigned int flags = 0;
    int result;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (vshCommandOptBool(cmd, "graceful"))
       flags |= VIR_DOMAIN_DESTROY_GRACEFUL;
    if (vshCommandOptBool(cmd, "remove-logs"))
       flags |= VIR_DOMAIN_DESTROY_REMOVE_LOGS;

    if (flags)
       result = virDomainDestroyFlags(dom, flags);
    else
       result = virDomainDestroy(dom);

    if (result < 0) {
        vshError(ctl, _("Failed to destroy domain '%1$s'"), name);
        return false;
    }

    vshPrintExtra(ctl, _("Domain '%1$s' destroyed\n"), name);
    return true;
}

/*
 * "desc" command for managing domain description and title
 */
static const vshCmdInfo info_desc[] = {
    {.name = "help",
     .data = N_("show or set domain's description or title")
    },
    {.name = "desc",
     .data = N_("Allows setting or modifying the description or title of "
                "a domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_desc[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    VIRSH_COMMON_OPT_LIVE(N_("modify/get running state")),
    VIRSH_COMMON_OPT_CONFIG(N_("modify/get persistent configuration")),
    VIRSH_COMMON_OPT_CURRENT(N_("modify/get current state configuration")),
    {.name = "title",
     .type = VSH_OT_BOOL,
     .help = N_("modify/get the title instead of description")
    },
    {.name = "edit",
     .type = VSH_OT_BOOL,
     .help = N_("open an editor to modify the description")
    },
    {.name = "new-desc",
     .type = VSH_OT_ARGV,
     .help = N_("message")
    },
    {.name = NULL}
};

static bool
cmdDesc(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool current = vshCommandOptBool(cmd, "current");

    bool title = vshCommandOptBool(cmd, "title");
    bool edit = vshCommandOptBool(cmd, "edit");

    int state;
    int type;
    g_autofree char *descArg = NULL;
    const vshCmdOpt *opt = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;
    unsigned int queryflags = 0;

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (config) {
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
        queryflags |= VIR_DOMAIN_XML_INACTIVE;
    }
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if ((state = virshDomainState(ctl, dom, NULL)) < 0)
        return false;

    if (title)
        type = VIR_DOMAIN_METADATA_TITLE;
    else
        type = VIR_DOMAIN_METADATA_DESCRIPTION;

    while ((opt = vshCommandOptArgv(ctl, cmd, opt)))
        virBufferAsprintf(&buf, "%s ", opt->data);

    virBufferTrim(&buf, " ");

    descArg = virBufferContentAndReset(&buf);

    if (edit || descArg) {
        g_autofree char *descDom = NULL;
        g_autofree char *descNew = NULL;

        if (!(descDom = virshGetDomainDescription(ctl, dom, title, queryflags)))
            return false;

        if (!descArg)
            descArg = g_strdup(descDom);

        if (edit) {
            g_autoptr(vshTempFile) tmp = NULL;
            g_autofree char *desc_edited = NULL;
            char *tmpstr;

            /* Create and open the temporary file. */
            if (!(tmp = vshEditWriteToTempFile(ctl, descArg)))
                return false;

            /* Start the editor. */
            if (vshEditFile(ctl, tmp) == -1)
                return false;

            /* Read back the edited file. */
            if (!(desc_edited = vshEditReadBackFile(ctl, tmp)))
                return false;

            /* strip a possible newline at the end of file; some
             * editors enforce a newline, this makes editing the title
             * more convenient */
            if (title &&
                (tmpstr = strrchr(desc_edited, '\n')) &&
                *(tmpstr+1) == '\0')
                *tmpstr = '\0';

            /* Compare original XML with edited.  Has it changed at all? */
            if (STREQ(descDom, desc_edited)) {
                if (title)
                    vshPrintExtra(ctl, "%s", _("Domain title not changed\n"));
                else
                    vshPrintExtra(ctl, "%s", _("Domain description not changed\n"));

                return true;
            }

            descNew = g_steal_pointer(&desc_edited);
        } else {
            descNew = g_steal_pointer(&descArg);
        }

        if (virDomainSetMetadata(dom, type, descNew, NULL, NULL, flags) < 0) {
            if (title)
                vshError(ctl, "%s", _("Failed to set new domain title"));
            else
                vshError(ctl, "%s", _("Failed to set new domain description"));

            return false;
        }

        if (title)
            vshPrintExtra(ctl, "%s", _("Domain title updated successfully"));
        else
            vshPrintExtra(ctl, "%s", _("Domain description updated successfully"));

    } else {
        g_autofree char *desc = virshGetDomainDescription(ctl, dom, title, queryflags);
        if (!desc)
            return false;

        if (strlen(desc) > 0) {
            vshPrint(ctl, "%s", desc);
        } else {
            if (title)
                vshPrintExtra(ctl, _("No title for domain: %1$s"), virDomainGetName(dom));
            else
                vshPrintExtra(ctl, _("No description for domain: %1$s"), virDomainGetName(dom));
        }
    }

    return true;
}


static const vshCmdInfo info_metadata[] = {
    {.name = "help",
     .data = N_("show or set domain's custom XML metadata")
    },
    {.name = "desc",
     .data = N_("Shows or modifies the XML metadata of a domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_metadata[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "uri",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("URI of the namespace")
    },
    VIRSH_COMMON_OPT_LIVE(N_("modify/get running state")),
    VIRSH_COMMON_OPT_CONFIG(N_("modify/get persistent configuration")),
    VIRSH_COMMON_OPT_CURRENT(N_("modify/get current state configuration")),
    {.name = "edit",
     .type = VSH_OT_BOOL,
     .help = N_("use an editor to change the metadata")
    },
    {.name = "key",
     .type = VSH_OT_STRING,
     .help = N_("key to be used as a namespace identifier"),
    },
    {.name = "set",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("new metadata to set"),
    },
    {.name = "remove",
     .type = VSH_OT_BOOL,
     .help = N_("remove the metadata corresponding to an uri")
    },
    {.name = NULL}
};


/* helper to add new metadata using the --edit option */
static char *
virshDomainGetEditMetadata(vshControl *ctl G_GNUC_UNUSED,
                           virDomainPtr dom,
                           const char *uri,
                           unsigned int flags)
{
    char *ret;

    if (!(ret = virDomainGetMetadata(dom, VIR_DOMAIN_METADATA_ELEMENT,
                                     uri, flags))) {
        vshResetLibvirtError();
        ret = g_strdup("\n");
    }

    return ret;
}


static bool
cmdMetadata(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool current = vshCommandOptBool(cmd, "current");
    bool edit = vshCommandOptBool(cmd, "edit");
    bool rem = vshCommandOptBool(cmd, "remove");
    const char *set = NULL;
    const char *uri = NULL;
    const char *key = NULL;
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;
    bool ret = false;

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);
    VSH_EXCLUSIVE_OPTIONS("edit", "set");
    VSH_EXCLUSIVE_OPTIONS("remove", "set");
    VSH_EXCLUSIVE_OPTIONS("remove", "edit");

    if (config)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "uri", &uri) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "key", &key) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "set", &set) < 0)
        return false;

    if ((set || edit) && !key) {
        vshError(ctl, "%s",
                 _("namespace key is required when modifying metadata"));
        return false;
    }

    if (set || rem) {
        if (virDomainSetMetadata(dom, VIR_DOMAIN_METADATA_ELEMENT,
                                 set, key, uri, flags))
            return false;

        if (rem)
            vshPrintExtra(ctl, "%s\n", _("Metadata removed"));
        else
            vshPrintExtra(ctl, "%s\n", _("Metadata modified"));
    } else if (edit) {
#define EDIT_GET_XML \
        virshDomainGetEditMetadata(ctl, dom, uri, flags)
#define EDIT_NOT_CHANGED \
        do { \
            vshPrintExtra(ctl, "%s", _("Metadata not changed")); \
            ret = true; \
            goto edit_cleanup; \
        } while (0)

#define EDIT_DEFINE \
        (virDomainSetMetadata(dom, VIR_DOMAIN_METADATA_ELEMENT, doc_edited, \
                              key, uri, flags) == 0)
#include "virsh-edit.c"

        vshPrintExtra(ctl, "%s\n", _("Metadata modified"));
    } else {
        g_autofree char *data = NULL;
        /* get */
        if (!(data = virDomainGetMetadata(dom, VIR_DOMAIN_METADATA_ELEMENT,
                                          uri, flags)))
            return false;

        vshPrint(ctl, "%s\n", data);
    }

    ret = true;

 cleanup:
    return ret;
}


/*
 * "inject-nmi" command
 */
static const vshCmdInfo info_inject_nmi[] = {
    {.name = "help",
     .data = N_("Inject NMI to the guest")
    },
    {.name = "desc",
     .data = N_("Inject NMI to the guest domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_inject_nmi[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = NULL}
};

static bool
cmdInjectNMI(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virDomainInjectNMI(dom, 0) < 0)
        return false;

    return true;
}

/*
 * "send-key" command
 */
static const vshCmdInfo info_send_key[] = {
    {.name = "help",
     .data = N_("Send keycodes to the guest")
    },
    {.name = "desc",
     .data = N_("Send keycodes (integers or symbolic names) to the guest")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_send_key[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "codeset",
     .type = VSH_OT_STRING,
     .flags = VSH_OFLAG_REQ_OPT,
     .completer = virshCodesetNameCompleter,
     .help = N_("the codeset of keycodes, default:linux")
    },
    {.name = "holdtime",
     .type = VSH_OT_INT,
     .flags = VSH_OFLAG_REQ_OPT,
     .help = N_("the time (in milliseconds) how long the keys will be held")
    },
    {.name = "keycode",
     .type = VSH_OT_ARGV,
     .flags = VSH_OFLAG_REQ,
     .completer = virshKeycodeNameCompleter,
     .help = N_("the key code")
    },
    {.name = NULL}
};

static int
virshKeyCodeGetInt(const char *key_name)
{
    unsigned int val;

    if (virStrToLong_uip(key_name, NULL, 0, &val) < 0 || val > 0xffff)
        return -1;
    return val;
}

static bool
cmdSendKey(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *codeset_option;
    int codeset;
    unsigned int holdtime = 0;
    int count = 0;
    const vshCmdOpt *opt = NULL;
    int keycode;
    unsigned int keycodes[VIR_DOMAIN_SEND_KEY_MAX_KEYS];

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringQuiet(ctl, cmd, "codeset", &codeset_option) <= 0)
        codeset_option = "linux";

    if (vshCommandOptUInt(ctl, cmd, "holdtime", &holdtime) < 0)
        return false;

    /* The qnum codeset was originally called rfb, so we need to keep
     * accepting the old name for backwards compatibility reasons */
    if (STREQ(codeset_option, "rfb"))
        codeset_option = "qnum";

    codeset = virKeycodeSetTypeFromString(codeset_option);
    if (codeset < 0) {
        vshError(ctl, _("unknown codeset: '%1$s'"), codeset_option);
        return false;
    }

    while ((opt = vshCommandOptArgv(ctl, cmd, opt))) {
        if (count == VIR_DOMAIN_SEND_KEY_MAX_KEYS) {
            vshError(ctl, _("too many keycodes"));
            return false;
        }

        if ((keycode = virshKeyCodeGetInt(opt->data)) < 0) {
            if ((keycode = virKeycodeValueFromString(codeset, opt->data)) < 0) {
                vshError(ctl, _("invalid keycode: '%1$s'"), opt->data);
                return false;
            }
        }

        keycodes[count] = keycode;
        count++;
    }

    if (virDomainSendKey(dom, codeset, holdtime, keycodes, count, 0) < 0)
        return false;

    return true;
}

/*
 * "send-process-signal" command
 */
static const vshCmdInfo info_send_process_signal[] = {
    {.name = "help",
     .data = N_("Send signals to processes")
    },
    {.name = "desc",
     .data = N_("Send signals to processes in the guest")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_send_process_signal[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "pid",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshCompleteEmpty,
     .help = N_("the process ID")
    },
    {.name = "signame",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshDomainSignalCompleter,
     .help = N_("the signal number or name")
    },
    {.name = NULL}
};

VIR_ENUM_IMPL(virshDomainProcessSignal,
              VIR_DOMAIN_PROCESS_SIGNAL_LAST,
               "nop",    "hup",  "int",  "quit",  "ill", /* 0-4 */
              "trap",   "abrt",  "bus",   "fpe", "kill", /* 5-9 */
              "usr1",   "segv", "usr2",  "pipe", "alrm", /* 10-14 */
              "term", "stkflt", "chld",  "cont", "stop", /* 15-19 */
              "tstp",   "ttin", "ttou",   "urg", "xcpu", /* 20-24 */
              "xfsz", "vtalrm", "prof", "winch", "poll", /* 25-29 */
               "pwr",    "sys",  "rt0",   "rt1",  "rt2", /* 30-34 */
               "rt3",    "rt4",  "rt5",   "rt6",  "rt7", /* 35-39 */
               "rt8",    "rt9", "rt10",  "rt11", "rt12", /* 40-44 */
              "rt13",   "rt14", "rt15",  "rt16", "rt17", /* 45-49 */
              "rt18",   "rt19", "rt20",  "rt21", "rt22", /* 50-54 */
              "rt23",   "rt24", "rt25",  "rt26", "rt27", /* 55-59 */
              "rt28",   "rt29", "rt30",  "rt31", "rt32"); /* 60-64 */

static int getSignalNumber(const char *signame)
{
    size_t i;
    int signum;
    g_autofree char *str = g_strdup(signame);
    char *p = str;

    for (i = 0; signame[i]; i++)
        p[i] = g_ascii_tolower(signame[i]);

    if (virStrToLong_i(p, NULL, 10, &signum) >= 0)
        return signum;

    if (STRPREFIX(p, "sig_"))
        p += 4;
    else if (STRPREFIX(p, "sig"))
        p += 3;

    return virshDomainProcessSignalTypeFromString(p);
}

static bool
cmdSendProcessSignal(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *signame;
    long long pid_value;
    int signum;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptLongLong(ctl, cmd, "pid", &pid_value) < 0)
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "signame", &signame) < 0)
        return false;

    if ((signum = getSignalNumber(signame)) < 0) {
        vshError(ctl, _("malformed signal name: %1$s"), signame);
        return false;
    }

    if (virDomainSendProcessSignal(dom, pid_value, signum, 0) < 0)
        return false;

    return true;
}

/*
 * "setmem" command
 */
static const vshCmdInfo info_setmem[] = {
    {.name = "help",
     .data = N_("change memory allocation")
    },
    {.name = "desc",
     .data = N_("Change the current memory allocation in the guest domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_setmem[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "kilobytes",
     .type = VSH_OT_ALIAS,
     .help = "size"
    },
    {.name = "size",
     .type = VSH_OT_INT,
     .flags = VSH_OFLAG_REQ,
     .help = N_("new memory size, as scaled integer (default KiB)")
    },
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = NULL}
};

static bool
cmdSetmem(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    unsigned long long bytes = 0;
    unsigned long long max;
    unsigned long kibibytes = 0;
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool current = vshCommandOptBool(cmd, "current");
    unsigned int flags = VIR_DOMAIN_AFFECT_LIVE;

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (config || live || current) {
        flags = VIR_DOMAIN_AFFECT_CURRENT;

        if (config)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;

        if (live)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
    }

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    /* The API expects 'unsigned long' KiB, so depending on whether we
     * are 32-bit or 64-bit determines the maximum we can use.  */
    if (sizeof(kibibytes) < sizeof(max))
        max = 1024ull * ULONG_MAX;
    else
        max = ULONG_MAX;
    if (vshCommandOptScaledInt(ctl, cmd, "size", &bytes, 1024, max) < 0)
        return false;
    kibibytes = VIR_DIV_UP(bytes, 1024);

    if (virDomainSetMemoryFlags(dom, kibibytes, flags) < 0)
        return false;

    return true;
}

/*
 * "setmaxmem" command
 */
static const vshCmdInfo info_setmaxmem[] = {
    {.name = "help",
     .data = N_("change maximum memory limit")
    },
    {.name = "desc",
     .data = N_("Change the maximum memory allocation limit in the guest domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_setmaxmem[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "kilobytes",
     .type = VSH_OT_ALIAS,
     .help = "size"
    },
    {.name = "size",
     .type = VSH_OT_INT,
     .flags = VSH_OFLAG_REQ,
     .help = N_("new maximum memory size, as scaled integer (default KiB)")
    },
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = NULL}
};

static bool
cmdSetmaxmem(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    unsigned long long bytes = 0;
    unsigned long long max;
    unsigned long kibibytes = 0;
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool current = vshCommandOptBool(cmd, "current");
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (config)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    /* The API expects 'unsigned long' KiB, so depending on whether we
     * are 32-bit or 64-bit determines the maximum we can use.  */
    if (sizeof(kibibytes) < sizeof(max))
        max = 1024ull * ULONG_MAX;
    else
        max = ULONG_MAX;
    if (vshCommandOptScaledInt(ctl, cmd, "size", &bytes, 1024, max) < 0)
        return false;
    kibibytes = VIR_DIV_UP(bytes, 1024);

    if (virDomainSetMemoryFlags(dom, kibibytes, flags | VIR_DOMAIN_MEM_MAXIMUM) < 0) {
        vshError(ctl, "%s", _("Unable to change MaxMemorySize"));
        return false;
    }

    return true;
}


/*
 * "update-memory-device" command
 */
static const vshCmdInfo info_update_memory_device[] = {
    {.name = "help",
     .data = N_("update memory device of a domain")
    },
    {.name = "desc",
     .data = N_("Update values of a memory device of a domain")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_update_memory_device[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = "print-xml",
     .type = VSH_OT_BOOL,
     .help = N_("print updated memory device XML instead of executing the change")
    },
    {.name = "alias",
     .type = VSH_OT_STRING,
     .completer = virshDomainDeviceAliasCompleter,
     .help = N_("memory device alias")
    },
    {.name = "node",
     .type = VSH_OT_INT,
     .help = N_("memory device target node")
    },
    {.name = "requested-size",
     .type = VSH_OT_INT,
     .help = N_("new value of <requested/> size, as scaled integer (default KiB)")
    },
    {.name = NULL}
};

static int
virshGetUpdatedMemoryXML(char **updatedMemoryXML,
                         vshControl *ctl,
                         const vshCmd *cmd,
                         virDomainPtr dom,
                         unsigned int flags)
{
    const char *alias = NULL;
    bool nodeOpt = false;
    unsigned int node = 0;
    g_autoptr(xmlDoc) doc = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    g_autofree char *xpath = NULL;
    int nmems;
    g_autofree xmlNodePtr *mems = NULL;
    unsigned int domainXMLFlags = 0;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG)
        domainXMLFlags |= VIR_DOMAIN_XML_INACTIVE;

    if (virshDomainGetXMLFromDom(ctl, dom, domainXMLFlags, &doc, &ctxt) < 0)
        return -1;

    nodeOpt = vshCommandOptBool(cmd, "node");
    if (vshCommandOptStringReq(ctl, cmd, "alias", &alias) < 0 ||
        vshCommandOptUInt(ctl, cmd, "node", &node) < 0) {
        return -1;
    }

    if (nodeOpt) {
        xpath = g_strdup_printf("/domain/devices/memory[./target/node='%u']", node);
    } else if (alias) {
        xpath = g_strdup_printf("/domain/devices/memory[./alias/@name='%s']", alias);
    } else {
        xpath = g_strdup("/domain/devices/memory");
    }

    nmems = virXPathNodeSet(xpath, ctxt, &mems);
    if (nmems < 0) {
        vshSaveLibvirtError();
        return -1;
    } else if (nmems == 0) {
        vshError(ctl, _("no memory device found"));
        return -1;
    } else if (nmems > 1) {
        vshError(ctl, _("multiple memory devices found, use --alias or --node to select one"));
        return -1;
    }

    ctxt->node = mems[0];

    if (vshCommandOptBool(cmd, "requested-size")) {
        xmlNodePtr requestedSizeNode;
        g_autofree char *kibibytesStr = NULL;
        unsigned long long bytes = 0;
        unsigned long kibibytes = 0;

        if (vshCommandOptScaledInt(ctl, cmd, "requested-size", &bytes, 1024, ULLONG_MAX) < 0)
            return -1;
        kibibytes = VIR_DIV_UP(bytes, 1024);

        requestedSizeNode = virXPathNode("./target/requested", ctxt);

        if (!requestedSizeNode) {
            vshError(ctl, _("virtio-mem device is missing <requested/>"));
            return -1;
        }

        kibibytesStr = g_strdup_printf("%lu", kibibytes);
        xmlNodeSetContent(requestedSizeNode, BAD_CAST kibibytesStr);
    }

    if (!(*updatedMemoryXML = virXMLNodeToString(doc, mems[0]))) {
        vshSaveLibvirtError();
        return -1;
    }

    return 0;
}

static bool
cmdUpdateMemoryDevice(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool current = vshCommandOptBool(cmd, "current");
    g_autofree char *updatedMemoryXML = NULL;
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);
    VSH_EXCLUSIVE_OPTIONS("node", "alias");

    if (config)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virshGetUpdatedMemoryXML(&updatedMemoryXML, ctl, cmd, dom, flags) < 0)
        return false;

    if (vshCommandOptBool(cmd, "print-xml")) {
        vshPrint(ctl, "%s", updatedMemoryXML);
    } else {
        if (virDomainUpdateDeviceFlags(dom, updatedMemoryXML, flags) < 0)
            return false;
    }

    return true;
}


/*
 * "memtune" command
 */
static const vshCmdInfo info_memtune[] = {
    {.name = "help",
     .data = N_("Get or set memory parameters")
    },
    {.name = "desc",
     .data = N_("Get or set the current memory parameters for a guest"
                " domain.\n"
                "    To get the memory parameters use following command: \n\n"
                "    virsh # memtune <domain>")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_memtune[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "hard-limit",
     .type = VSH_OT_INT,
     .help = N_("Max memory, as scaled integer (default KiB)")
    },
    {.name = "soft-limit",
     .type = VSH_OT_INT,
     .help = N_("Memory during contention, as scaled integer (default KiB)")
    },
    {.name = "swap-hard-limit",
     .type = VSH_OT_INT,
     .help = N_("Max memory plus swap, as scaled integer (default KiB)")
    },
    {.name = "min-guarantee",
     .type = VSH_OT_INT,
     .help = N_("Min guaranteed memory, as scaled integer (default KiB)")
    },
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = NULL}
};

/**
 * virshMemtuneGetSize
 *
 * @cmd: pointer to vshCmd
 * @name: name of a parameter for which we would like to get a value
 * @value: pointer to variable where the value will be stored
 *
 * This function will parse virsh command line in order to load a value of
 * specified parameter. If the value is -1 we will handle it as unlimited and
 * use VIR_DOMAIN_MEMORY_PARAM_UNLIMITED instead.
 *
 * Returns:
 *  >0 if option found and valid
 *  0 if option not found and not required
 *  <0 in all other cases
 */
static int
virshMemtuneGetSize(vshControl *ctl, const vshCmd *cmd,
                    const char *name, long long *value)
{
    int ret;
    unsigned long long tmp;
    const char *str;
    char *end;

    ret = vshCommandOptStringQuiet(ctl, cmd, name, &str);
    if (ret <= 0)
        return ret;
    if (virStrToLong_ll(str, &end, 10, value) < 0)
        return -1;
    if (*value < 0) {
        *value = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;
        return 1;
    }
    tmp = *value;
    if (virScaleInteger(&tmp, end, 1024, LLONG_MAX) < 0)
        return -1;
    *value = VIR_DIV_UP(tmp, 1024);
    return 1;
}

static bool
cmdMemtune(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    long long tmpVal;
    int nparams = 0;
    int maxparams = 0;
    int rc;
    size_t i;
    virTypedParameterPtr params = NULL;
    bool ret = false;
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;
    bool current = vshCommandOptBool(cmd, "current");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (config)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

#define PARSE_MEMTUNE_PARAM(NAME, FIELD) \
    if ((rc = virshMemtuneGetSize(ctl, cmd, NAME, &tmpVal)) < 0) { \
        vshError(ctl, _("Unable to parse integer parameter %1$s"), NAME); \
        goto cleanup; \
    } \
    if (rc == 1) { \
        if (virTypedParamsAddULLong(&params, &nparams, &maxparams, \
                                    FIELD, tmpVal) < 0) \
            goto save_error; \
    }


    PARSE_MEMTUNE_PARAM("hard-limit", VIR_DOMAIN_MEMORY_HARD_LIMIT);
    PARSE_MEMTUNE_PARAM("soft-limit", VIR_DOMAIN_MEMORY_SOFT_LIMIT);
    PARSE_MEMTUNE_PARAM("swap-hard-limit", VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT);
    PARSE_MEMTUNE_PARAM("min-guarantee", VIR_DOMAIN_MEMORY_MIN_GUARANTEE);

#undef PARSE_MEMTUNE_PARAM

    if (nparams == 0) {
        /* get the number of memory parameters */
        if (virDomainGetMemoryParameters(dom, NULL, &nparams, flags) != 0) {
            vshError(ctl, "%s",
                     _("Unable to get number of memory parameters"));
            goto cleanup;
        }

        if (nparams == 0) {
            /* nothing to output */
            ret = true;
            goto cleanup;
        }

        /* now go get all the memory parameters */
        params = g_new0(virTypedParameter, nparams);
        if (virDomainGetMemoryParameters(dom, params, &nparams, flags) != 0) {
            vshError(ctl, "%s", _("Unable to get memory parameters"));
            goto cleanup;
        }

        for (i = 0; i < nparams; i++) {
            if (params[i].type == VIR_TYPED_PARAM_ULLONG &&
                params[i].value.ul == VIR_DOMAIN_MEMORY_PARAM_UNLIMITED) {
                vshPrint(ctl, "%-15s: %s\n", params[i].field, _("unlimited"));
            } else {
                g_autofree char *str = vshGetTypedParamValue(ctl, &params[i]);
                vshPrint(ctl, "%-15s: %s\n", params[i].field, str);
            }
        }
    } else {
        if (virDomainSetMemoryParameters(dom, params, nparams, flags) != 0)
            goto error;
    }

    ret = true;

 cleanup:
    virTypedParamsFree(params, nparams);
    return ret;

 save_error:
    vshSaveLibvirtError();
 error:
    vshError(ctl, "%s", _("Unable to change memory parameters"));
    goto cleanup;
}

/*
 * "perf" command
 */
static const vshCmdInfo info_perf[] = {
    {.name = "help",
        .data = N_("Get or set perf event")
    },
    {.name = "desc",
        .data = N_("Get or set the current perf events for a guest"
                   " domain.\n"
                   "    To get the perf events list use following command: \n\n"
                   "    virsh # perf <domain>")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_perf[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "enable",
     .type = VSH_OT_STRING,
     .completer = virshDomainPerfEnableCompleter,
     .help = N_("perf events which will be enabled")
    },
    {.name = "disable",
     .type = VSH_OT_STRING,
     .completer = virshDomainPerfDisableCompleter,
     .help = N_("perf events which will be disabled")
    },
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = NULL}
};

static int
virshParseEventStr(const char *event,
                   bool state,
                   virTypedParameterPtr *params,
                   int *nparams,
                   int *maxparams)
{
    g_auto(GStrv) tok = NULL;
    GStrv next;

    if (!(tok = g_strsplit(event, ",", 0)))
        return -1;

    for (next = tok; *next; next++) {
        if (*next[0] == '\0')
            continue;

        if (virTypedParamsAddBoolean(params, nparams, maxparams, *next, state) < 0)
            return -1;
    }

    return 0;
}

static void
virshPrintPerfStatus(vshControl *ctl, virTypedParameterPtr params, int nparams)
{
    size_t i;

    for (i = 0; i < nparams; i++) {
        if (params[i].type == VIR_TYPED_PARAM_BOOLEAN &&
            params[i].value.b) {
            vshPrintExtra(ctl, "%-15s: %s\n", params[i].field, _("enabled"));
        } else {
            vshPrintExtra(ctl, "%-15s: %s\n", params[i].field, _("disabled"));
        }
    }
}

static bool
cmdPerf(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    int nparams = 0;
    int maxparams = 0;
    virTypedParameterPtr params = NULL;
    bool ret = false;
    const char *enable = NULL, *disable = NULL;
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;
    bool current = vshCommandOptBool(cmd, "current");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (config)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (vshCommandOptStringReq(ctl, cmd, "enable", &enable) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "disable", &disable) < 0)
        return false;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (enable && virshParseEventStr(enable, true, &params,
                                     &nparams, &maxparams) < 0)
        goto cleanup;

    if (disable && virshParseEventStr(disable, false, &params,
                                      &nparams, &maxparams) < 0)
        goto cleanup;

    if (nparams == 0) {
        if (virDomainGetPerfEvents(dom, &params, &nparams, flags) != 0) {
            vshError(ctl, "%s", _("Unable to get perf events"));
            goto cleanup;
        }
        virshPrintPerfStatus(ctl, params, nparams);
    } else {
        if (virDomainSetPerfEvents(dom, params, nparams, flags) != 0) {
            vshError(ctl, "%s", _("Unable to enable/disable perf events"));
            goto cleanup;
        } else {
            virshPrintPerfStatus(ctl, params, nparams);
        }
    }

    ret = true;
 cleanup:
    virTypedParamsFree(params, nparams);
    return ret;
}


/*
 * "numatune" command
 */
static const vshCmdInfo info_numatune[] = {
    {.name = "help",
     .data = N_("Get or set numa parameters")
    },
    {.name = "desc",
     .data = N_("Get or set the current numa parameters for a guest"
                " domain.\n"
                "    To get the numa parameters use following command: \n\n"
                "    virsh # numatune <domain>")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_numatune[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "mode",
     .type = VSH_OT_STRING,
     .completer = virshDomainNumatuneModeCompleter,
     .help = N_("NUMA mode, one of strict, preferred and interleave \n"
                "or a number from the virDomainNumatuneMemMode enum")
    },
    {.name = "nodeset",
     .type = VSH_OT_STRING,
     .help = N_("NUMA node selections to set")
    },
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = NULL}
};

static bool
cmdNumatune(vshControl * ctl, const vshCmd * cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    int nparams = 0;
    int maxparams = 0;
    size_t i;
    virTypedParameterPtr params = NULL;
    const char *nodeset = NULL;
    bool ret = false;
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;
    bool current = vshCommandOptBool(cmd, "current");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    const char *mode = NULL;

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (config)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "nodeset", &nodeset) < 0)
        goto cleanup;

    if (nodeset &&
        virTypedParamsAddString(&params, &nparams, &maxparams,
                                VIR_DOMAIN_NUMA_NODESET, nodeset) < 0)
        goto save_error;

    if (vshCommandOptStringReq(ctl, cmd, "mode", &mode) < 0)
        goto cleanup;

    if (mode) {
        int m;
        /* Accept string or integer, in case server understands newer
         * integer than what strings we were compiled with
         */
        if ((m = virDomainNumatuneMemModeTypeFromString(mode)) < 0 &&
            virStrToLong_i(mode, NULL, 0, &m) < 0) {
            vshError(ctl, _("Invalid mode: %1$s"), mode);
            goto cleanup;
        }

        if (virTypedParamsAddInt(&params, &nparams, &maxparams,
                                 VIR_DOMAIN_NUMA_MODE, m) < 0)
            goto save_error;
    }

    if (nparams == 0) {
        /* get the number of numa parameters */
        if (virDomainGetNumaParameters(dom, NULL, &nparams, flags) != 0) {
            vshError(ctl, "%s",
                     _("Unable to get number of memory parameters"));
            goto cleanup;
        }

        if (nparams == 0) {
            /* nothing to output */
            ret = true;
            goto cleanup;
        }

        /* now go get all the numa parameters */
        params = g_new0(virTypedParameter, nparams);
        if (virDomainGetNumaParameters(dom, params, &nparams, flags) != 0) {
            vshError(ctl, "%s", _("Unable to get numa parameters"));
            goto cleanup;
        }

        for (i = 0; i < nparams; i++) {
            if (params[i].type == VIR_TYPED_PARAM_INT &&
                STREQ(params[i].field, VIR_DOMAIN_NUMA_MODE)) {
                vshPrint(ctl, "%-15s: %s\n", params[i].field,
                         virDomainNumatuneMemModeTypeToString(params[i].value.i));
            } else {
                g_autofree char *str = vshGetTypedParamValue(ctl, &params[i]);
                vshPrint(ctl, "%-15s: %s\n", params[i].field, str);
            }
        }
    } else {
        if (virDomainSetNumaParameters(dom, params, nparams, flags) != 0)
            goto error;
    }

    ret = true;

 cleanup:
    virTypedParamsFree(params, nparams);
    return ret;

 save_error:
    vshSaveLibvirtError();
 error:
    vshError(ctl, "%s", _("Unable to change numa parameters"));
    goto cleanup;
}

/*
 * "domlaunchsecinfo" command
 */
static const vshCmdInfo info_domlaunchsecinfo[] = {
    {.name = "help",
     .data = N_("Get domain launch security info")
    },
    {.name = "desc",
     .data = N_("Get the launch security parameters for a guest domain")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domlaunchsecinfo[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = NULL}
};

static bool
cmdDomLaunchSecInfo(vshControl * ctl, const vshCmd * cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    size_t i;
    int nparams = 0;
    virTypedParameterPtr params = NULL;
    bool ret = false;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virDomainGetLaunchSecurityInfo(dom, &params, &nparams, 0) != 0) {
        vshError(ctl, "%s", _("Unable to get launch security parameters"));
        goto cleanup;
    }

    for (i = 0; i < nparams; i++) {
        g_autofree char *str = vshGetTypedParamValue(ctl, &params[i]);
        vshPrint(ctl, "%-15s: %s\n", params[i].field, str);
    }

    ret = true;

 cleanup:
    virTypedParamsFree(params, nparams);
    return ret;
}

/*
 * "domsetlaunchsecstate" command
 */
static const vshCmdInfo info_domsetlaunchsecstate[] = {
    {.name = "help",
     .data = N_("Set domain launch security state")
    },
    {.name = "desc",
     .data = N_("Set a secret in the guest domain's memory")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domsetlaunchsecstate[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "secrethdr",
     .type = VSH_OT_STRING,
     .flags = VSH_OFLAG_REQ_OPT,
     .help = N_("path to file containing the secret header"),
    },
    {.name = "secret",
     .type = VSH_OT_STRING,
     .flags = VSH_OFLAG_REQ_OPT,
     .help = N_("path to file containing the secret"),
    },
    {.name = "set-address",
     .type = VSH_OT_INT,
     .help = N_("physical address within the guest domain's memory to set the secret"),
    },
    {.name = NULL}
};

static bool
cmdDomSetLaunchSecState(vshControl * ctl, const vshCmd * cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *sechdrfile = NULL;
    const char *secfile = NULL;
    g_autofree char *sechdr = NULL;
    g_autofree char *sec = NULL;
    unsigned long long setaddr;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    int maxparams = 0;
    int rv;
    bool ret = false;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "secrethdr", &sechdrfile) < 0)
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "secret", &secfile) < 0)
        return false;

    if (sechdrfile == NULL || secfile == NULL) {
        vshError(ctl, "%s", _("Both secret and the secret header are required"));
        return false;
    }

    if (virFileReadAll(sechdrfile, 1024*64, &sechdr) < 0) {
        vshSaveLibvirtError();
        return false;
    }

    if (virFileReadAll(secfile, 1024*64, &sec) < 0) {
        vshSaveLibvirtError();
        return false;
    }

    if (virTypedParamsAddString(&params, &nparams, &maxparams,
                                VIR_DOMAIN_LAUNCH_SECURITY_SEV_SECRET_HEADER,
                                sechdr) < 0)
        return false;

    if (virTypedParamsAddString(&params, &nparams, &maxparams,
                                VIR_DOMAIN_LAUNCH_SECURITY_SEV_SECRET,
                                sec) < 0)
        return false;


    if ((rv = vshCommandOptULongLong(ctl, cmd, "set-address", &setaddr)) < 0) {
        return false;
    } else if (rv > 0) {
        if (virTypedParamsAddULLong(&params, &nparams, &maxparams,
                                    VIR_DOMAIN_LAUNCH_SECURITY_SEV_SECRET_SET_ADDRESS,
                                    setaddr) < 0)
            return false;
    }

    if (virDomainSetLaunchSecurityState(dom, params, nparams, 0) != 0) {
        vshError(ctl, "%s", _("Unable to set launch security state"));
        goto cleanup;
    }

    ret = true;

 cleanup:
    virTypedParamsFree(params, nparams);
    return ret;
}


/*
 * "dom-fd-associate" command
 */
static const vshCmdInfo info_dom_fd_associate[] = {
    {.name = "help",
     .data = N_("associate a FD with a domain")
    },
    {.name = "desc",
     .data = N_("associate a FD with a domain")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_dom_fd_associate[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "name",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshCompleteEmpty,
     .help = N_("name of the FD group")
    },
    {.name = "pass-fds",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshCompleteEmpty,
     .help = N_("file descriptors N,M,... to associate")
    },
    {.name = "seclabel-writable",
     .type = VSH_OT_BOOL,
     .help = N_("use seclabels allowing writes")
    },
    {.name = "seclabel-restore",
     .type = VSH_OT_BOOL,
     .help = N_("try to restore security label after use if possible")
    },
    {.name = NULL}
};

static bool
cmdDomFdAssociate(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *name = NULL;
    unsigned int flags = 0;
    g_autofree int *fds = NULL;
    size_t nfds = 0;

    if (vshCommandOptBool(cmd, "seclabel-writable"))
        flags |= VIR_DOMAIN_FD_ASSOCIATE_SECLABEL_WRITABLE;

    if (vshCommandOptBool(cmd, "seclabel-restore"))
        flags |= VIR_DOMAIN_FD_ASSOCIATE_SECLABEL_RESTORE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "name", &name) < 0)
        return false;

    if (virshFetchPassFdsList(ctl, cmd, &nfds, &fds) < 0)
        return false;

    if (virDomainFDAssociate(dom, name, nfds, fds, flags) < 0)
        return false;

    return true;
}


/*
 * "qemu-monitor-command" command
 */
static const vshCmdInfo info_qemu_monitor_command[] = {
    {.name = "help",
     .data = N_("QEMU Monitor Command")
    },
    {.name = "desc",
     .data = N_("QEMU Monitor Command")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_qemu_monitor_command[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "hmp",
     .type = VSH_OT_BOOL,
     .help = N_("command is in human monitor protocol")
    },
    {.name = "pretty",
     .type = VSH_OT_BOOL,
     .help = N_("pretty-print any qemu monitor protocol output")
    },
    {.name = "return-value",
     .type = VSH_OT_BOOL,
     .help = N_("extract the value of the 'return' key from the returned string")
    },
    {.name = "pass-fds",
     .type = VSH_OT_STRING,
     .flags = VSH_OFLAG_REQ_OPT,
     .completer = virshCompleteEmpty,
     .help = N_("pass file descriptors N,M,... along with the command")
    },
    {.name = "cmd",
     .type = VSH_OT_ARGV,
     .flags = VSH_OFLAG_REQ,
     .help = N_("command")
    },
    {.name = NULL}
};


static char *
cmdQemuMonitorCommandConcatCmd(vshControl *ctl,
                               const vshCmd *cmd,
                               const vshCmdOpt *opt)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    while ((opt = vshCommandOptArgv(ctl, cmd, opt)))
        virBufferAsprintf(&buf, "%s ", opt->data);

    virBufferTrim(&buf, " ");

    return virBufferContentAndReset(&buf);
}


static char *
cmdQemuMonitorCommandQMPWrap(vshControl *ctl,
                             const vshCmd *cmd)
{
    g_autofree char *fullcmd = cmdQemuMonitorCommandConcatCmd(ctl, cmd, NULL);
    g_autoptr(virJSONValue) fullcmdjson = NULL;
    g_autofree char *fullargs = NULL;
    g_autoptr(virJSONValue) fullargsjson = NULL;
    const vshCmdOpt *opt = NULL;
    const char *commandname = NULL;
    g_autoptr(virJSONValue) command = NULL;
    g_autoptr(virJSONValue) arguments = NULL;

    if (!(fullcmdjson = virJSONValueFromString(fullcmd))) {
        /* Reset the error before adding wrapping. */
        vshResetLibvirtError();
    }

    /* if we've got a JSON object, pass it through */
    if (virJSONValueIsObject(fullcmdjson))
        return g_steal_pointer(&fullcmd);

    /* we try to wrap the command and possible arguments into a JSON object, if
     * we as fall back we pass through what we've got from the user */

    if ((opt = vshCommandOptArgv(ctl, cmd, opt)))
        commandname = opt->data;

    /* now we process arguments similarly to how we've dealt with the full command */
    if ((fullargs = cmdQemuMonitorCommandConcatCmd(ctl, cmd, opt)) &&
        !(fullargsjson = virJSONValueFromString(fullargs))) {
        /* Reset the error before adding wrapping. */
        vshResetLibvirtError();
    }

    /* for empty args or a valid JSON object we just use that */
    if (!fullargs || virJSONValueIsObject(fullargsjson)) {
        arguments = g_steal_pointer(&fullargsjson);
    } else {
        /* for a non-object we try to concatenate individual _ARGV bits into a
         * JSON object wrapper and try using that */
        g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

        virBufferAddLit(&buf, "{");
        /* opt points to the _ARGV option bit containing the command so we'll
         * iterate through the arguments now */
        while ((opt = vshCommandOptArgv(ctl, cmd, opt)))
            virBufferAsprintf(&buf, "%s,", opt->data);

        virBufferTrim(&buf, ",");
        virBufferAddLit(&buf, "}");

        if (!(arguments = virJSONValueFromString(virBufferCurrentContent(&buf)))) {
            vshError(ctl, _("failed to wrap arguments '%1$s' into a QMP command wrapper"),
                     fullargs);
            return NULL;
        }
    }

    if (virJSONValueObjectAdd(&command,
                              "s:execute", commandname,
                              "A:arguments", &arguments,
                              NULL) < 0)
        return NULL;

    return virJSONValueToString(command, false);
}


static bool
cmdQemuMonitorCommand(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    g_autofree char *monitor_cmd = NULL;
    g_autofree char *result = NULL;
    g_autoptr(virJSONValue) resultjson = NULL;
    unsigned int flags = 0;
    bool pretty = vshCommandOptBool(cmd, "pretty");
    bool returnval = vshCommandOptBool(cmd, "return-value");
    virJSONValue *formatjson;
    g_autofree char *jsonstr = NULL;
    g_autofree int *fds = NULL;
    size_t nfds = 0;

    VSH_EXCLUSIVE_OPTIONS("hmp", "pretty");
    VSH_EXCLUSIVE_OPTIONS("hmp", "return-value");

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptBool(cmd, "hmp")) {
        flags |= VIR_DOMAIN_QEMU_MONITOR_COMMAND_HMP;
        monitor_cmd = cmdQemuMonitorCommandConcatCmd(ctl, cmd, NULL);
    } else {
        monitor_cmd = cmdQemuMonitorCommandQMPWrap(ctl, cmd);
    }

    if (!monitor_cmd) {
        vshSaveLibvirtError();
        return NULL;
    }

    if (virshFetchPassFdsList(ctl, cmd, &nfds, &fds) < 0)
        return false;

    if (fds) {
        if (virDomainQemuMonitorCommandWithFiles(dom, monitor_cmd, nfds, fds,
                                                 NULL, NULL,
                                                 &result, flags) < 0)
            return false;
    } else {
        if (virDomainQemuMonitorCommand(dom, monitor_cmd, &result, flags) < 0)
            return false;
    }

    if (returnval || pretty) {
        resultjson = virJSONValueFromString(result);

        if (returnval && !resultjson) {
            vshError(ctl, "failed to parse JSON returned by qemu");
            return false;
        }
    }

    /* print raw non-prettified result */
    if (!resultjson) {
        vshPrint(ctl, "%s\n", result);
        return true;
    }

    if (returnval) {
        if (!(formatjson = virJSONValueObjectGet(resultjson, "return"))) {
            vshError(ctl, "'return' member missing");
            return false;
        }
    } else {
        formatjson = resultjson;
    }

    jsonstr = virJSONValueToString(formatjson, pretty);
    virTrimSpaces(jsonstr, NULL);
    vshPrint(ctl, "%s", jsonstr);
    return true;
}

/*
 * "qemu-monitor-event" command
 */

struct virshQemuEventData {
    vshControl *ctl;
    bool loop;
    bool pretty;
    bool timestamp;
    int count;
};
typedef struct virshQemuEventData virshQemuEventData;

static void
virshEventQemuPrint(virConnectPtr conn G_GNUC_UNUSED,
                    virDomainPtr dom,
                    const char *event,
                    long long seconds,
                    unsigned int micros,
                    const char *details,
                    void *opaque)
{
    virshQemuEventData *data = opaque;
    virJSONValue *pretty = NULL;
    g_autofree char *str = NULL;

    if (!data->loop && data->count)
        return;
    if (data->pretty && details) {
        pretty = virJSONValueFromString(details);
        if (pretty && (str = virJSONValueToString(pretty, true)))
            details = str;
    }

    if (data->timestamp) {
        char timestamp[VIR_TIME_STRING_BUFLEN];

        if (virTimeStringNowRaw(timestamp) < 0)
            timestamp[0] = '\0';

        vshPrint(data->ctl, "%s: event %s for domain '%s': %s\n",
                 timestamp, event, virDomainGetName(dom), NULLSTR(details));
    } else {
        vshPrint(data->ctl, "event %s at %lld.%06u for domain '%s': %s\n",
                 event, seconds, micros, virDomainGetName(dom), NULLSTR(details));
    }

    data->count++;
    if (!data->loop)
        vshEventDone(data->ctl);
}

static const vshCmdInfo info_qemu_monitor_event[] = {
    {.name = "help",
     .data = N_("QEMU Monitor Events")
    },
    {.name = "desc",
     .data = N_("Listen for QEMU Monitor Events")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_qemu_monitor_event[] = {
    VIRSH_COMMON_OPT_DOMAIN_OT_STRING(N_("filter by domain name, id or uuid"),
                                      0, 0),
    {.name = "event",
     .type = VSH_OT_STRING,
     .help = N_("filter by event name")
    },
    {.name = "pretty",
     .type = VSH_OT_BOOL,
     .help = N_("pretty-print any JSON output")
    },
    {.name = "loop",
     .type = VSH_OT_BOOL,
     .help = N_("loop until timeout or interrupt, rather than one-shot")
    },
    {.name = "timeout",
     .type = VSH_OT_INT,
     .help = N_("timeout seconds")
    },
    {.name = "regex",
     .type = VSH_OT_BOOL,
     .help = N_("treat event as a regex rather than literal filter")
    },
    {.name = "no-case",
     .type = VSH_OT_BOOL,
     .help = N_("treat event case-insensitively")
    },
    {.name = "timestamp",
     .type = VSH_OT_BOOL,
     .help = N_("show timestamp for each printed event")
    },
    {.name = NULL}
};

static bool
cmdQemuMonitorEvent(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    bool ret = false;
    unsigned int flags = 0;
    int eventId = -1;
    int timeout = 0;
    const char *event = NULL;
    virshQemuEventData data;
    virshControl *priv = ctl->privData;

    if (vshCommandOptBool(cmd, "regex"))
        flags |= VIR_CONNECT_DOMAIN_QEMU_MONITOR_EVENT_REGISTER_REGEX;
    if (vshCommandOptBool(cmd, "no-case"))
        flags |= VIR_CONNECT_DOMAIN_QEMU_MONITOR_EVENT_REGISTER_NOCASE;

    data.ctl = ctl;
    data.loop = vshCommandOptBool(cmd, "loop");
    data.pretty = vshCommandOptBool(cmd, "pretty");
    data.timestamp = vshCommandOptBool(cmd, "timestamp");
    data.count = 0;
    if (vshCommandOptTimeoutToMs(ctl, cmd, &timeout) < 0)
        return false;
    if (vshCommandOptStringReq(ctl, cmd, "event", &event) < 0)
        return false;

    if (vshCommandOptBool(cmd, "domain"))
        if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
            goto cleanup;

    if (vshEventStart(ctl, timeout) < 0)
        goto cleanup;

    if ((eventId = virConnectDomainQemuMonitorEventRegister(priv->conn, dom,
                                                            event,
                                                            virshEventQemuPrint,
                                                            &data, NULL,
                                                            flags)) < 0)
        goto cleanup;
    switch (vshEventWait(ctl)) {
    case VSH_EVENT_INTERRUPT:
        vshPrint(ctl, _("event loop interrupted\n"));
        break;
    case VSH_EVENT_TIMEOUT:
        vshPrint(ctl, _("event loop timed out\n"));
        break;
    case VSH_EVENT_DONE:
        break;
    default:
        goto cleanup;
    }
    vshPrint(ctl, _("events received: %1$d\n"), data.count);
    if (data.count)
        ret = true;

 cleanup:
    vshEventCleanup(ctl);
    if (eventId >= 0 &&
        virConnectDomainQemuMonitorEventDeregister(priv->conn, eventId) < 0)
        ret = false;

    return ret;
}

/*
 * "qemu-attach" command
 */
static const vshCmdInfo info_qemu_attach[] = {
    {.name = "help",
     .data = N_("QEMU Attach")
    },
    {.name = "desc",
     .data = N_("QEMU Attach")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_qemu_attach[] = {
    {.name = "pid",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshCompleteEmpty,
     .help = N_("pid")
    },
    {.name = NULL}
};

static bool
cmdQemuAttach(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    unsigned int flags = 0;
    unsigned int pid_value; /* API uses unsigned int, not pid_t */
    virshControl *priv = ctl->privData;

    if (vshCommandOptUInt(ctl, cmd, "pid", &pid_value) <= 0)
        return false;

    if (!(dom = virDomainQemuAttach(priv->conn, pid_value, flags))) {
        vshError(ctl, _("Failed to attach to pid %1$u"), pid_value);
        return false;
    }

    vshPrintExtra(ctl, _("Domain '%1$s' attached to pid %2$u\n"),
                  virDomainGetName(dom), pid_value);
    return true;
}

/*
 * "qemu-agent-command" command
 */
static const vshCmdInfo info_qemu_agent_command[] = {
    {.name = "help",
     .data = N_("QEMU Guest Agent Command")
    },
    {.name = "desc",
     .data = N_("Run an arbitrary qemu guest agent command; use at your own risk")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_qemu_agent_command[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "timeout",
     .type = VSH_OT_INT,
     .flags = VSH_OFLAG_REQ_OPT,
     .help = N_("timeout seconds. must be positive.")
    },
    {.name = "async",
     .type = VSH_OT_BOOL,
     .help = N_("execute command without waiting for timeout")
    },
    {.name = "block",
     .type = VSH_OT_BOOL,
     .help = N_("execute command without timeout")
    },
    {.name = "pretty",
     .type = VSH_OT_BOOL,
     .help = N_("pretty-print the output")
    },
    {.name = "cmd",
     .type = VSH_OT_ARGV,
     .flags = VSH_OFLAG_REQ,
     .help = N_("command")
    },
    {.name = NULL}
};

static bool
cmdQemuAgentCommand(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    bool ret = false;
    g_autofree char *guest_agent_cmd = NULL;
    char *result = NULL;
    int timeout = VIR_DOMAIN_QEMU_AGENT_COMMAND_DEFAULT;
    int judge = 0;
    unsigned int flags = 0;
    const vshCmdOpt *opt = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    virJSONValue *pretty = NULL;

    dom = virshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    while ((opt = vshCommandOptArgv(ctl, cmd, opt)))
        virBufferAsprintf(&buf, "%s ", opt->data);

    virBufferTrim(&buf, " ");

    guest_agent_cmd = virBufferContentAndReset(&buf);

    judge = vshCommandOptInt(ctl, cmd, "timeout", &timeout);
    if (judge < 0)
        goto cleanup;
    else if (judge > 0)
        judge = 1;
    if (judge && timeout < 1) {
        vshError(ctl, "%s", _("timeout must be positive"));
        goto cleanup;
    }

    if (vshCommandOptBool(cmd, "async")) {
        timeout = VIR_DOMAIN_QEMU_AGENT_COMMAND_NOWAIT;
        judge++;
    }
    if (vshCommandOptBool(cmd, "block")) {
        timeout = VIR_DOMAIN_QEMU_AGENT_COMMAND_BLOCK;
        judge++;
    }

    if (judge > 1) {
        vshError(ctl, "%s", _("timeout, async and block options are exclusive"));
        goto cleanup;
    }

    result = virDomainQemuAgentCommand(dom, guest_agent_cmd, timeout, flags);
    if (!result)
        goto cleanup;

    if (vshCommandOptBool(cmd, "pretty")) {
        char *tmp;
        pretty = virJSONValueFromString(result);
        if (pretty && (tmp = virJSONValueToString(pretty, true))) {
            VIR_FREE(result);
            result = tmp;
        } else {
            vshResetLibvirtError();
        }
    }

    vshPrint(ctl, "%s\n", result);

    ret = true;

 cleanup:
    VIR_FREE(result);

    return ret;
}

/*
 * "lxc-enter-namespace" namespace
 */
static const vshCmdInfo info_lxc_enter_namespace[] = {
    {.name = "help",
     .data = N_("LXC Guest Enter Namespace")
    },
    {.name = "desc",
     .data = N_("Run an arbitrary command in a lxc guest namespace; use at your own risk")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_lxc_enter_namespace[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "noseclabel",
     .type = VSH_OT_BOOL,
     .help = N_("Do not change process security label")
    },
    {.name = "cmd",
     .type = VSH_OT_ARGV,
     .flags = VSH_OFLAG_REQ,
     .help = N_("command to run")
    },
    {.name = NULL}
};

static bool
cmdLxcEnterNamespace(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const vshCmdOpt *opt = NULL;
    g_autofree char **cmdargv = NULL;
    size_t ncmdargv = 0;
    pid_t pid;
    int nfdlist;
    int *fdlist;
    size_t i;
    int status;
    bool setlabel = true;
    g_autofree virSecurityModelPtr secmodel = NULL;
    g_autofree virSecurityLabelPtr seclabel = NULL;
    virshControl *priv = ctl->privData;

    dom = virshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        return false;

    if (vshCommandOptBool(cmd, "noseclabel"))
        setlabel = false;

    while ((opt = vshCommandOptArgv(ctl, cmd, opt))) {
        VIR_EXPAND_N(cmdargv, ncmdargv, 1);
        cmdargv[ncmdargv-1] = opt->data;
    }
    VIR_EXPAND_N(cmdargv, ncmdargv, 1);
    cmdargv[ncmdargv - 1] = NULL;

    if ((nfdlist = virDomainLxcOpenNamespace(dom, &fdlist, 0)) < 0)
        return false;

    if (setlabel) {
        secmodel = g_new0(virSecurityModel, 1);
        seclabel = g_new0(virSecurityLabel, 1);

        if (virNodeGetSecurityModel(priv->conn, secmodel) < 0)
            return false;
        if (virDomainGetSecurityLabel(dom, seclabel) < 0)
            return false;
    }

    /* Fork once because we don't want to affect
     * virsh's namespace itself, and because user namespace
     * can only be changed in single-threaded process
     */
    if ((pid = virFork()) < 0)
        return false;

    if (pid != 0) {
        for (i = 0; i < nfdlist; i++)
            VIR_FORCE_CLOSE(fdlist[i]);
        VIR_FREE(fdlist);
        if (virProcessWait(pid, NULL, false) < 0) {
            vshReportError(ctl);
            return false;
        }
        return true;
    }

    if (setlabel &&
        virDomainLxcEnterSecurityLabel(secmodel, seclabel, NULL, 0) < 0)
        _exit(EXIT_CANCELED);

    if (virDomainLxcEnterCGroup(dom, 0) < 0)
        _exit(EXIT_CANCELED);

    if (virDomainLxcEnterNamespace(dom, nfdlist, fdlist, NULL, NULL, 0) < 0)
        _exit(EXIT_CANCELED);

    /* Fork a second time because entering the
     * pid namespace only takes effect after fork
     */
    if ((pid = virFork()) < 0)
        _exit(EXIT_CANCELED);

    if (pid == 0) {
        execv(cmdargv[0], cmdargv);
        _exit(errno == ENOENT ? EXIT_ENOENT : EXIT_CANNOT_INVOKE);
    }

    if (virProcessWait(pid, &status, true) < 0)
        _exit(EXIT_CANNOT_INVOKE);
    virProcessExitWithStatus(status);
    return true;
}

/*
 * "dumpxml" command
 */
static const vshCmdInfo info_dumpxml[] = {
    {.name = "help",
     .data = N_("domain information in XML")
    },
    {.name = "desc",
     .data = N_("Output the domain information as an XML dump to stdout.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_dumpxml[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "inactive",
     .type = VSH_OT_BOOL,
     .help = N_("show inactive defined XML")
    },
    {.name = "security-info",
     .type = VSH_OT_BOOL,
     .help = N_("include security sensitive information in XML dump")
    },
    {.name = "update-cpu",
     .type = VSH_OT_BOOL,
     .help = N_("update guest CPU according to host CPU")
    },
    {.name = "migratable",
     .type = VSH_OT_BOOL,
     .help = N_("provide XML suitable for migrations")
    },
    {.name = "xpath",
     .type = VSH_OT_STRING,
     .flags = VSH_OFLAG_REQ_OPT,
     .completer = virshCompleteEmpty,
     .help = N_("xpath expression to filter the XML document")
    },
    {.name = "wrap",
     .type = VSH_OT_BOOL,
     .help = N_("wrap xpath results in an common root element"),
    },
    {.name = NULL}
};

static bool
cmdDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    g_autofree char *xml = NULL;
    unsigned int flags = 0;
    bool inactive = vshCommandOptBool(cmd, "inactive");
    bool secure = vshCommandOptBool(cmd, "security-info");
    bool update = vshCommandOptBool(cmd, "update-cpu");
    bool migratable = vshCommandOptBool(cmd, "migratable");
    bool wrap = vshCommandOptBool(cmd, "wrap");
    const char *xpath = NULL;

    if (inactive)
        flags |= VIR_DOMAIN_XML_INACTIVE;
    if (secure)
        flags |= VIR_DOMAIN_XML_SECURE;
    if (update)
        flags |= VIR_DOMAIN_XML_UPDATE_CPU;
    if (migratable)
        flags |= VIR_DOMAIN_XML_MIGRATABLE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringQuiet(ctl, cmd, "xpath", &xpath) < 0)
        return false;

    if (!(xml = virDomainGetXMLDesc(dom, flags)))
        return false;

    return virshDumpXML(ctl, xml, "domain", xpath, wrap);
}

/*
 * "domxml-from-native" command
 */
static const vshCmdInfo info_domxmlfromnative[] = {
    {.name = "help",
     .data = N_("Convert native config to domain XML")
    },
    {.name = "desc",
     .data = N_("Convert native guest configuration format to domain XML format.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domxmlfromnative[] = {
    {.name = "format",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("source config data format")
    },
    {.name = "config",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshCompletePathLocalExisting,
     .help = N_("config data file to import from")
    },
    {.name = NULL}
};

static bool
cmdDomXMLFromNative(vshControl *ctl, const vshCmd *cmd)
{
    const char *format = NULL;
    const char *configFile = NULL;
    g_autofree char *configData = NULL;
    g_autofree char *xmlData = NULL;
    unsigned int flags = 0;
    virshControl *priv = ctl->privData;

    if (vshCommandOptStringReq(ctl, cmd, "format", &format) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "config", &configFile) < 0)
        return false;

    if (virFileReadAll(configFile, VSH_MAX_XML_FILE, &configData) < 0)
        return false;

    xmlData = virConnectDomainXMLFromNative(priv->conn, format, configData, flags);
    if (!xmlData)
        return false;

    vshPrint(ctl, "%s", xmlData);
    return true;
}

/*
 * "domxml-to-native" command
 */
static const vshCmdInfo info_domxmltonative[] = {
    {.name = "help",
     .data = N_("Convert domain XML to native config")
    },
    {.name = "desc",
     .data = N_("Convert domain XML config to a native guest configuration format.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domxmltonative[] = {
    {.name = "format",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("target config data type format")
    },
    VIRSH_COMMON_OPT_DOMAIN_OT_STRING_FULL(VSH_OFLAG_REQ_OPT, 0),
    {.name = "xml",
     .type = VSH_OT_STRING,
     .completer = virshCompletePathLocalExisting,
     .help = N_("xml data file to export from")
    },
    {.name = NULL}
};

static bool
cmdDomXMLToNative(vshControl *ctl, const vshCmd *cmd)
{
    const char *format = NULL;
    const char *xmlFile = NULL;
    g_autofree char *configData = NULL;
    g_autofree char *xmlData = NULL;
    unsigned int flags = 0;
    virshControl *priv = ctl->privData;
    g_autoptr(virshDomain) dom = NULL;

    if (vshCommandOptStringReq(ctl, cmd, "format", &format) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "xml", &xmlFile) < 0)
        return false;

    VSH_EXCLUSIVE_OPTIONS("domain", "xml");

    if (vshCommandOptBool(cmd, "domain") &&
        (!(dom = virshCommandOptDomain(ctl, cmd, NULL))))
            return false;

    if (dom) {
        xmlData = virDomainGetXMLDesc(dom, flags);
    } else if (xmlFile) {
        if (virFileReadAll(xmlFile, VSH_MAX_XML_FILE, &xmlData) < 0)
            return false;
    } else {
        vshError(ctl, "%s", _("need either domain or domain XML"));
        return false;
    }

    if (!xmlData) {
        vshError(ctl, "%s", _("failed to retrieve XML"));
        return false;
    }

    if (!(configData = virConnectDomainXMLToNative(priv->conn, format, xmlData, flags)))
        return false;

    vshPrint(ctl, "%s", configData);

    return true;
}

/*
 * "domname" command
 */
static const vshCmdInfo info_domname[] = {
    {.name = "help",
     .data = N_("convert a domain id or UUID to domain name")
    },
    {.name = "desc",
     .data = ""
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domname[] = {
    {.name = "domain",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshDomainUUIDCompleter,
     .help = N_("domain id or uuid")
    },
    {.name = NULL}
};

static bool
cmdDomname(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;

    if (!(dom = virshCommandOptDomainBy(ctl, cmd, NULL,
                                        VIRSH_BYID|VIRSH_BYUUID)))
        return false;

    vshPrint(ctl, "%s\n", virDomainGetName(dom));
    return true;
}

/*
 * "domrename" command
 */
static const vshCmdInfo info_domrename[] = {
    {.name = "help",
     .data = N_("rename a domain")
    },
    {.name = "desc",
     .data = "Rename an inactive domain."
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domrename[] = {
    VIRSH_COMMON_OPT_DOMAIN(N_("domain name or uuid"),
                            VIR_CONNECT_LIST_DOMAINS_INACTIVE),
    {.name = "new-name",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshCompleteEmpty,
     .help = N_("new domain name")
    },
    {.name = NULL}
};

static bool
cmdDomrename(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *new_name = NULL;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "new-name", &new_name) < 0)
        return false;

    if (virDomainRename(dom, new_name, 0) < 0)
        return false;

    vshPrintExtra(ctl, "Domain successfully renamed\n");

    return true;
}

/*
 * "domid" command
 */
static const vshCmdInfo info_domid[] = {
    {.name = "help",
     .data = N_("convert a domain name or UUID to domain id")
    },
    {.name = "desc",
     .data = ""
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domid[] = {
    VIRSH_COMMON_OPT_DOMAIN(N_("domain name or uuid"),
                            VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = NULL}
};

static bool
cmdDomid(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    unsigned int id;

    if (!(dom = virshCommandOptDomainBy(ctl, cmd, NULL,
                                        VIRSH_BYNAME|VIRSH_BYUUID)))
        return false;

    id = virDomainGetID(dom);
    if (id == ((unsigned int)-1))
        vshPrint(ctl, "%s\n", "-");
    else
        vshPrint(ctl, "%d\n", id);
    return true;
}

/*
 * "domuuid" command
 */
static const vshCmdInfo info_domuuid[] = {
    {.name = "help",
     .data = N_("convert a domain name or id to domain UUID")
    },
    {.name = "desc",
     .data = ""
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domuuid[] = {
    VIRSH_COMMON_OPT_DOMAIN(N_("domain id or name"), 0),
    {.name = NULL}
};

static bool
cmdDomuuid(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (!(dom = virshCommandOptDomainBy(ctl, cmd, NULL,
                                        VIRSH_BYNAME|VIRSH_BYID)))
        return false;

    if (virDomainGetUUIDString(dom, uuid) != -1)
        vshPrint(ctl, "%s\n", uuid);
    else
        vshError(ctl, "%s", _("failed to get domain UUID"));

    return true;
}

/*
 * "migrate" command
 */
static const vshCmdInfo info_migrate[] = {
    {.name = "help",
     .data = N_("migrate domain to another host")
    },
    {.name = "desc",
     .data = N_("Migrate domain to another host.  Add --live for live migration.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_migrate[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "desturi",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshCompleteEmpty,
     .help = N_("connection URI of the destination host as seen from the client(normal migration) or source(p2p migration)")
    },
    VIRSH_COMMON_OPT_LIVE(N_("live migration")),
    {.name = "offline",
     .type = VSH_OT_BOOL,
     .help = N_("offline migration")
    },
    {.name = "p2p",
     .type = VSH_OT_BOOL,
     .help = N_("peer-2-peer migration")
    },
    {.name = "direct",
     .type = VSH_OT_BOOL,
     .help = N_("direct migration")
    },
    {.name = "tunneled",
     .type = VSH_OT_ALIAS,
     .help = "tunnelled"
    },
    {.name = "tunnelled",
     .type = VSH_OT_BOOL,
     .help = N_("tunnelled migration")
    },
    {.name = "persistent",
     .type = VSH_OT_BOOL,
     .help = N_("persist VM on destination")
    },
    {.name = "undefinesource",
     .type = VSH_OT_BOOL,
     .help = N_("undefine VM on source")
    },
    {.name = "suspend",
     .type = VSH_OT_BOOL,
     .help = N_("do not restart the domain on the destination host")
    },
    {.name = "copy-storage-all",
     .type = VSH_OT_BOOL,
     .help = N_("migration with non-shared storage with full disk copy")
    },
    {.name = "copy-storage-inc",
     .type = VSH_OT_BOOL,
     .help = N_("migration with non-shared storage with incremental copy (same base image shared between source and destination)")
    },
    {.name = "copy-storage-synchronous-writes",
     .type = VSH_OT_BOOL,
     .help = N_("force guest disk writes to be synchronously written to the destination to improve storage migration convergence")
    },
    {.name = "change-protection",
     .type = VSH_OT_BOOL,
     .help = N_("prevent any configuration changes to domain until migration ends")
    },
    {.name = "unsafe",
     .type = VSH_OT_BOOL,
     .help = N_("force migration even if it may be unsafe")
    },
    {.name = "verbose",
     .type = VSH_OT_BOOL,
     .help = N_("display the progress of migration")
    },
    {.name = "compressed",
     .type = VSH_OT_BOOL,
     .help = N_("compress repeated pages during live migration")
    },
    {.name = "auto-converge",
     .type = VSH_OT_BOOL,
     .help = N_("force convergence during live migration")
    },
    {.name = "rdma-pin-all",
     .type = VSH_OT_BOOL,
     .help = N_("pin all memory before starting RDMA live migration")
    },
    {.name = "abort-on-error",
     .type = VSH_OT_BOOL,
     .help = N_("abort on soft errors during migration")
    },
    {.name = "postcopy",
     .type = VSH_OT_BOOL,
     .help = N_("enable post-copy migration; switch to it using migrate-postcopy command")
    },
    {.name = "postcopy-after-precopy",
     .type = VSH_OT_BOOL,
     .help = N_("automatically switch to post-copy migration after one pass of pre-copy")
    },
    {.name = "postcopy-resume",
     .type = VSH_OT_BOOL,
     .help = N_("resume failed post-copy migration")
    },
    {.name = "zerocopy",
     .type = VSH_OT_BOOL,
     .help = N_("use zero-copy mechanism for migrating memory pages")
    },
    {.name = "migrateuri",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("migration URI, usually can be omitted")
    },
    {.name = "graphicsuri",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("graphics URI to be used for seamless graphics migration")
    },
    {.name = "listen-address",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("listen address that destination should bind to for incoming migration")
    },
    {.name = "dname",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("rename to new name during migration (if supported)")
    },
    {.name = "timeout",
     .type = VSH_OT_INT,
     .help = N_("run action specified by --timeout-* option (suspend by "
                "default) if live migration exceeds timeout (in seconds)")
    },
    {.name = "timeout-suspend",
     .type = VSH_OT_BOOL,
     .help = N_("suspend the guest after timeout")
    },
    {.name = "timeout-postcopy",
     .type = VSH_OT_BOOL,
     .help = N_("switch to post-copy after timeout")
    },
    {.name = "xml",
     .type = VSH_OT_STRING,
     .completer = virshCompletePathLocalExisting,
     .help = N_("filename containing updated XML for the target")
    },
    {.name = "migrate-disks",
     .type = VSH_OT_STRING,
     .completer = virshDomainMigrateDisksCompleter,
     .help = N_("comma separated list of disks to be migrated")
    },
    {.name = "disks-port",
     .type = VSH_OT_INT,
     .help = N_("port to use by target server for incoming disks migration")
    },
    {.name = "disks-uri",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("URI to use for disks migration (overrides --disks-port)")
    },
    {.name = "comp-methods",
     .type = VSH_OT_STRING,
     .completer = virshDomainMigrateCompMethodsCompleter,
     .help = N_("comma separated list of compression methods to be used")
    },
    {.name = "comp-mt-level",
     .type = VSH_OT_INT,
     .help = N_("compress level for multithread compression")
    },
    {.name = "comp-mt-threads",
     .type = VSH_OT_INT,
     .help = N_("number of compression threads for multithread compression")
    },
    {.name = "comp-mt-dthreads",
     .type = VSH_OT_INT,
     .help = N_("number of decompression threads for multithread compression")
    },
    {.name = "comp-xbzrle-cache",
     .type = VSH_OT_INT,
     .help = N_("page cache size for xbzrle compression")
    },
    {.name = "auto-converge-initial",
     .type = VSH_OT_INT,
     .help = N_("initial CPU throttling rate for auto-convergence")
    },
    {.name = "auto-converge-increment",
     .type = VSH_OT_INT,
     .help = N_("CPU throttling rate increment for auto-convergence")
    },
    {.name = "persistent-xml",
     .type = VSH_OT_STRING,
     .completer = virshCompletePathLocalExisting,
     .help = N_("filename containing updated persistent XML for the target")
    },
    {.name = "tls",
     .type = VSH_OT_BOOL,
     .help = N_("use TLS for migration")
    },
    {.name = "postcopy-bandwidth",
     .type = VSH_OT_INT,
     .help = N_("post-copy migration bandwidth limit in MiB/s")
    },
    {.name = "parallel",
     .type = VSH_OT_BOOL,
     .help = N_("enable parallel migration")
    },
    {.name = "parallel-connections",
     .type = VSH_OT_INT,
     .help = N_("number of connections for parallel migration")
    },
    {.name = "bandwidth",
     .type = VSH_OT_INT,
     .help = N_("migration bandwidth limit in MiB/s")
    },
    {.name = "tls-destination",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
     .help = N_("override the destination host name used for TLS verification")
    },
    {.name = "comp-zlib-level",
     .type = VSH_OT_INT,
     .help = N_("compress level for zlib compression")
    },
    {.name = "comp-zstd-level",
     .type = VSH_OT_INT,
     .help = N_("compress level for zstd compression")
    },
    {.name = NULL}
};

struct doMigrateFlagMapping {
    const char *optionname;
    unsigned int migflag;
};

static void
doMigrate(void *opaque)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *desturi = NULL;
    const char *opt = NULL;
    unsigned int flags = 0;
    virshCtrlData *data = opaque;
    vshControl *ctl = data->ctl;
    const vshCmd *cmd = data->cmd;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    int maxparams = 0;
    int intOpt = 0;
    unsigned long long ullOpt = 0;
    int rv;
    virConnectPtr dconn = data->dconn;
    size_t i;

    static const struct doMigrateFlagMapping flagmap[] = {
        { "live", VIR_MIGRATE_LIVE },
        { "p2p", VIR_MIGRATE_PEER2PEER },
        { "tunnelled", VIR_MIGRATE_TUNNELLED },
        { "persistent", VIR_MIGRATE_PERSIST_DEST },
        { "undefinesource", VIR_MIGRATE_UNDEFINE_SOURCE },
        { "copy-storage-all", VIR_MIGRATE_NON_SHARED_DISK },
        { "copy-storage-inc", VIR_MIGRATE_NON_SHARED_INC },
        { "copy-storage-synchronous-writes", VIR_MIGRATE_NON_SHARED_SYNCHRONOUS_WRITES },
        { "change-protection", VIR_MIGRATE_CHANGE_PROTECTION },
        { "unsafe", VIR_MIGRATE_UNSAFE },
        { "compressed", VIR_MIGRATE_COMPRESSED },
        { "auto-converge", VIR_MIGRATE_AUTO_CONVERGE },
        { "rdma-pin-all", VIR_MIGRATE_RDMA_PIN_ALL },
        { "offline", VIR_MIGRATE_OFFLINE },
        { "abort-on-error", VIR_MIGRATE_ABORT_ON_ERROR },
        { "postcopy", VIR_MIGRATE_POSTCOPY },
        { "postcopy-resume", VIR_MIGRATE_POSTCOPY_RESUME },
        { "zerocopy", VIR_MIGRATE_ZEROCOPY },
        { "tls", VIR_MIGRATE_TLS },
        { "parallel", VIR_MIGRATE_PARALLEL },
        { "suspend", VIR_MIGRATE_PAUSED },
    };

#ifndef WIN32
    sigset_t sigmask, oldsigmask;

    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);
    if (pthread_sigmask(SIG_BLOCK, &sigmask, &oldsigmask) != 0)
        goto out_sig;
#endif /* !WIN32 */

    for (i = 0; i < G_N_ELEMENTS(flagmap); i++) {
        if (vshCommandOptBool(cmd, flagmap[i].optionname))
            flags |= flagmap[i].migflag;
    }

    if (flags & VIR_MIGRATE_NON_SHARED_SYNCHRONOUS_WRITES &&
        !(flags & (VIR_MIGRATE_NON_SHARED_DISK | VIR_MIGRATE_NON_SHARED_DISK))) {
        vshError(ctl, "'--copy-storage-synchronous-writes' requires one of '--copy-storage-all', '--copy-storage-inc'");
        goto out;
    }

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        goto out;

    if (vshCommandOptStringReq(ctl, cmd, "desturi", &desturi) < 0)
        goto out;

    if (vshCommandOptStringReq(ctl, cmd, "migrateuri", &opt) < 0)
        goto out;
    if (opt &&
        virTypedParamsAddString(&params, &nparams, &maxparams,
                                VIR_MIGRATE_PARAM_URI, opt) < 0)
        goto save_error;

    if (vshCommandOptStringReq(ctl, cmd, "graphicsuri", &opt) < 0)
        goto out;
    if (opt &&
        virTypedParamsAddString(&params, &nparams, &maxparams,
                                VIR_MIGRATE_PARAM_GRAPHICS_URI, opt) < 0)
        goto save_error;

    if (vshCommandOptStringReq(ctl, cmd, "listen-address", &opt) < 0)
        goto out;
    if (opt &&
        virTypedParamsAddString(&params, &nparams, &maxparams,
                                VIR_MIGRATE_PARAM_LISTEN_ADDRESS, opt) < 0)
        goto save_error;

    if (vshCommandOptInt(ctl, cmd, "disks-port", &intOpt) < 0)
        goto out;
    if (intOpt &&
        virTypedParamsAddInt(&params, &nparams, &maxparams,
                             VIR_MIGRATE_PARAM_DISKS_PORT, intOpt) < 0)
        goto save_error;

    if (vshCommandOptStringReq(ctl, cmd, "disks-uri", &opt) < 0)
        goto out;
    if (opt &&
        virTypedParamsAddString(&params, &nparams, &maxparams,
                                VIR_MIGRATE_PARAM_DISKS_URI,
                                opt) < 0)
        goto save_error;

    if (vshCommandOptStringReq(ctl, cmd, "dname", &opt) < 0)
        goto out;
    if (opt &&
        virTypedParamsAddString(&params, &nparams, &maxparams,
                                VIR_MIGRATE_PARAM_DEST_NAME, opt) < 0)
        goto save_error;

    if (vshCommandOptStringReq(ctl, cmd, "migrate-disks", &opt) < 0)
        goto out;
    if (opt) {
        g_autofree char **val = NULL;

        if (!(flags & (VIR_MIGRATE_NON_SHARED_DISK | VIR_MIGRATE_NON_SHARED_INC))) {
            vshError(ctl, "'--migrate-disks' requires one of '--copy-storage-all', '--copy-storage-inc'");
            goto out;
        }

        val = g_strsplit(opt, ",", 0);

        if (virTypedParamsAddStringList(&params,
                                        &nparams,
                                        &maxparams,
                                        VIR_MIGRATE_PARAM_MIGRATE_DISKS,
                                        (const char **)val) < 0) {
            goto save_error;
        }
    }

    if (vshCommandOptStringReq(ctl, cmd, "comp-methods", &opt) < 0)
        goto out;
    if (opt) {
        g_autofree char **val = g_strsplit(opt, ",", 0);

        if (virTypedParamsAddStringList(&params,
                                        &nparams,
                                        &maxparams,
                                        VIR_MIGRATE_PARAM_COMPRESSION,
                                        (const char **)val) < 0) {
            goto save_error;
        }
    }

    if ((rv = vshCommandOptInt(ctl, cmd, "comp-mt-level", &intOpt)) < 0) {
        goto out;
    } else if (rv > 0) {
        if (virTypedParamsAddInt(&params, &nparams, &maxparams,
                                 VIR_MIGRATE_PARAM_COMPRESSION_MT_LEVEL,
                                 intOpt) < 0)
            goto save_error;
    }

    if ((rv = vshCommandOptInt(ctl, cmd, "comp-mt-threads", &intOpt)) < 0) {
        goto out;
    } else if (rv > 0) {
        if (virTypedParamsAddInt(&params, &nparams, &maxparams,
                                 VIR_MIGRATE_PARAM_COMPRESSION_MT_THREADS,
                                 intOpt) < 0)
            goto save_error;
    }

    if ((rv = vshCommandOptInt(ctl, cmd, "comp-mt-dthreads", &intOpt)) < 0) {
        goto out;
    } else if (rv > 0) {
        if (virTypedParamsAddInt(&params, &nparams, &maxparams,
                                 VIR_MIGRATE_PARAM_COMPRESSION_MT_DTHREADS,
                                 intOpt) < 0)
            goto save_error;
    }

    if ((rv = vshCommandOptULongLong(ctl, cmd, "comp-xbzrle-cache", &ullOpt)) < 0) {
        goto out;
    } else if (rv > 0) {
        if (virTypedParamsAddULLong(&params, &nparams, &maxparams,
                                    VIR_MIGRATE_PARAM_COMPRESSION_XBZRLE_CACHE,
                                    ullOpt) < 0)
            goto save_error;
    }

    if (vshCommandOptStringReq(ctl, cmd, "xml", &opt) < 0)
        goto out;
    if (opt) {
        g_autofree char *xml = NULL;

        if (virFileReadAll(opt, VSH_MAX_XML_FILE, &xml) < 0) {
            vshError(ctl, _("cannot read file '%1$s'"), opt);
            goto save_error;
        }

        if (virTypedParamsAddString(&params, &nparams, &maxparams,
                                    VIR_MIGRATE_PARAM_DEST_XML, xml) < 0) {
            goto save_error;
        }
    }

    if (vshCommandOptStringReq(ctl, cmd, "persistent-xml", &opt) < 0)
        goto out;
    if (opt) {
        g_autofree char *xml = NULL;

        if (virFileReadAll(opt, VSH_MAX_XML_FILE, &xml) < 0) {
            vshError(ctl, _("cannot read file '%1$s'"), opt);
            goto save_error;
        }

        if (virTypedParamsAddString(&params, &nparams, &maxparams,
                                    VIR_MIGRATE_PARAM_PERSIST_XML, xml) < 0) {
            goto save_error;
        }
    }

    if ((rv = vshCommandOptInt(ctl, cmd, "auto-converge-initial", &intOpt)) < 0) {
        goto out;
    } else if (rv > 0) {
        if (virTypedParamsAddInt(&params, &nparams, &maxparams,
                                 VIR_MIGRATE_PARAM_AUTO_CONVERGE_INITIAL,
                                 intOpt) < 0)
            goto save_error;
    }

    if ((rv = vshCommandOptInt(ctl, cmd, "auto-converge-increment", &intOpt)) < 0) {
        goto out;
    } else if (rv > 0) {
        if (virTypedParamsAddInt(&params, &nparams, &maxparams,
                                 VIR_MIGRATE_PARAM_AUTO_CONVERGE_INCREMENT,
                                 intOpt) < 0)
            goto save_error;
    }

    if ((rv = vshCommandOptULongLong(ctl, cmd, "postcopy-bandwidth", &ullOpt)) < 0) {
        goto out;
    } else if (rv > 0) {
        if (virTypedParamsAddULLong(&params, &nparams, &maxparams,
                                    VIR_MIGRATE_PARAM_BANDWIDTH_POSTCOPY,
                                    ullOpt) < 0)
            goto save_error;
    }

    if ((rv = vshCommandOptInt(ctl, cmd, "parallel-connections", &intOpt)) < 0) {
        goto out;
    } else if (rv > 0) {
        if (virTypedParamsAddInt(&params, &nparams, &maxparams,
                                 VIR_MIGRATE_PARAM_PARALLEL_CONNECTIONS,
                                 intOpt) < 0)
            goto save_error;
    }

    if ((rv = vshCommandOptInt(ctl, cmd, "comp-zlib-level", &intOpt)) < 0) {
        goto out;
    } else if (rv > 0) {
        if (virTypedParamsAddInt(&params, &nparams, &maxparams,
                                 VIR_MIGRATE_PARAM_COMPRESSION_ZLIB_LEVEL,
                                 intOpt) < 0)
            goto save_error;
    }

    if ((rv = vshCommandOptInt(ctl, cmd, "comp-zstd-level", &intOpt)) < 0) {
        goto out;
    } else if (rv > 0) {
        if (virTypedParamsAddInt(&params, &nparams, &maxparams,
                                 VIR_MIGRATE_PARAM_COMPRESSION_ZSTD_LEVEL,
                                 intOpt) < 0)
            goto save_error;
    }

    if ((rv = vshCommandOptULongLong(ctl, cmd, "bandwidth", &ullOpt)) < 0) {
        goto out;
    } else if (rv > 0) {
        if (virTypedParamsAddULLong(&params, &nparams, &maxparams,
                                    VIR_MIGRATE_PARAM_BANDWIDTH,
                                    ullOpt) < 0)
            goto save_error;
    }

    if (vshCommandOptStringReq(ctl, cmd, "tls-destination", &opt) < 0)
        goto out;
    if (opt &&
        virTypedParamsAddString(&params, &nparams, &maxparams,
                                VIR_MIGRATE_PARAM_TLS_DESTINATION, opt) < 0)
        goto save_error;

    if (flags & VIR_MIGRATE_PEER2PEER || vshCommandOptBool(cmd, "direct")) {
        if (virDomainMigrateToURI3(dom, desturi, params, nparams, flags) == 0)
            data->ret = 0;
    } else {
        /* For traditional live migration, connect to the destination host directly. */
        g_autoptr(virshDomain) ddom = NULL;

        if ((ddom = virDomainMigrate3(dom, dconn, params, nparams, flags))) {
            data->ret = 0;
        }
    }

 out:
#ifndef WIN32
    pthread_sigmask(SIG_SETMASK, &oldsigmask, NULL);
 out_sig:
#endif /* !WIN32 */
    virTypedParamsFree(params, nparams);
    g_main_loop_quit(data->eventLoop);
    return;

 save_error:
    vshSaveLibvirtError();
    goto out;
}

typedef enum {
    VIRSH_MIGRATE_TIMEOUT_DEFAULT,
    VIRSH_MIGRATE_TIMEOUT_SUSPEND,
    VIRSH_MIGRATE_TIMEOUT_POSTCOPY,
} virshMigrateTimeoutAction;

static void
virshMigrateTimeout(vshControl *ctl,
                    virDomainPtr dom,
                    void *opaque)
{
    virshMigrateTimeoutAction action = *(virshMigrateTimeoutAction *) opaque;

    switch (action) {
    case VIRSH_MIGRATE_TIMEOUT_DEFAULT: /* unreachable */
    case VIRSH_MIGRATE_TIMEOUT_SUSPEND:
        vshDebug(ctl, VSH_ERR_DEBUG,
                 "migration timed out; suspending domain\n");
        if (virDomainSuspend(dom) < 0)
            vshDebug(ctl, VSH_ERR_INFO, "suspending domain failed\n");
        break;

    case VIRSH_MIGRATE_TIMEOUT_POSTCOPY:
        vshDebug(ctl, VSH_ERR_DEBUG,
                 "migration timed out; switching to post-copy\n");
        if (virDomainMigrateStartPostCopy(dom, 0) < 0)
            vshDebug(ctl, VSH_ERR_INFO, "switching to post-copy failed\n");
        break;
    }
}

static void
virshMigrateIteration(virConnectPtr conn G_GNUC_UNUSED,
                      virDomainPtr dom,
                      int iteration,
                      void *opaque)
{
    vshControl *ctl = opaque;

    if (iteration == 2) {
        vshDebug(ctl, VSH_ERR_DEBUG,
                 "iteration %d finished; switching to post-copy\n",
                 iteration - 1);
        if (virDomainMigrateStartPostCopy(dom, 0) < 0)
            vshDebug(ctl, VSH_ERR_INFO, "switching to post-copy failed\n");
    }
}

static bool
cmdMigrate(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    virThread workerThread;
    bool verbose = false;
    unsigned int timeout = 0;
    virshMigrateTimeoutAction timeoutAction = VIRSH_MIGRATE_TIMEOUT_DEFAULT;
    bool live_flag = false;
    virshControl *priv = ctl->privData;
    int iterEvent = -1;
    g_autoptr(GMainContext) eventCtxt = g_main_context_new();
    g_autoptr(GMainLoop) eventLoop = g_main_loop_new(eventCtxt, FALSE);
    virshCtrlData data = {
        .dconn = NULL,
        .ctl = ctl,
        .cmd = cmd,
        .eventLoop = eventLoop,
        .ret = -1,
    };

    VSH_EXCLUSIVE_OPTIONS("live", "offline");
    VSH_EXCLUSIVE_OPTIONS("timeout-suspend", "timeout-postcopy");
    VSH_REQUIRE_OPTION("postcopy-after-precopy", "postcopy");
    VSH_REQUIRE_OPTION("postcopy-resume", "postcopy");
    VSH_REQUIRE_OPTION("timeout-postcopy", "postcopy");
    VSH_REQUIRE_OPTION("persistent-xml", "persistent");
    VSH_REQUIRE_OPTION("tls-destination", "tls");

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptBool(cmd, "verbose"))
        verbose = true;

    if (vshCommandOptBool(cmd, "live"))
        live_flag = true;
    if (vshCommandOptUInt(ctl, cmd, "timeout", &timeout) < 0) {
        goto cleanup;
    } else if (timeout > 0 && !live_flag) {
        vshError(ctl, "%s",
                 _("migrate: Unexpected timeout for offline migration"));
        goto cleanup;
    }

    if (vshCommandOptBool(cmd, "timeout-suspend"))
        timeoutAction = VIRSH_MIGRATE_TIMEOUT_SUSPEND;
    if (vshCommandOptBool(cmd, "timeout-postcopy"))
        timeoutAction = VIRSH_MIGRATE_TIMEOUT_POSTCOPY;
    if (timeout > 0) {
        if (timeoutAction == VIRSH_MIGRATE_TIMEOUT_DEFAULT)
            timeoutAction = VIRSH_MIGRATE_TIMEOUT_SUSPEND;
    } else if (timeoutAction) {
        vshError(ctl, "%s",
                 _("migrate: Unexpected --timeout-* option without --timeout"));
        goto cleanup;
    }

    if (vshCommandOptBool(cmd, "postcopy-after-precopy")) {
        iterEvent = virConnectDomainEventRegisterAny(
                            priv->conn, dom,
                            VIR_DOMAIN_EVENT_ID_MIGRATION_ITERATION,
                            VIR_DOMAIN_EVENT_CALLBACK(virshMigrateIteration),
                            ctl, NULL);
        if (iterEvent < 0)
            goto cleanup;
    }

    if (vshCommandOptBool(cmd, "p2p") || vshCommandOptBool(cmd, "direct")) {
        data.dconn = NULL;
    } else {
        /* For traditional live migration, connect to the destination host. */
        virConnectPtr dconn = NULL;
        const char *desturi = NULL;

        if (vshCommandOptStringReq(ctl, cmd, "desturi", &desturi) < 0)
            goto cleanup;

        dconn = virshConnect(ctl, desturi, false);
        if (!dconn)
            goto cleanup;

        data.dconn = dconn;
    }

    if (virThreadCreate(&workerThread,
                        true,
                        doMigrate,
                        &data) < 0)
        goto cleanup;
    virshWatchJob(ctl, dom, verbose, eventLoop,
                  &data.ret, timeout,
                  virshMigrateTimeout,
                  &timeoutAction, _("Migration"));

    virThreadJoin(&workerThread);

 cleanup:
    if (data.dconn)
        virConnectClose(data.dconn);
    if (iterEvent != -1)
        virConnectDomainEventDeregisterAny(priv->conn, iterEvent);
    return !data.ret;
}

/*
 * "migrate-setmaxdowntime" command
 */
static const vshCmdInfo info_migrate_setmaxdowntime[] = {
    {.name = "help",
     .data = N_("set maximum tolerable downtime")
    },
    {.name = "desc",
     .data = N_("Set maximum tolerable downtime of a domain which is being live-migrated to another host.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_migrate_setmaxdowntime[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "downtime",
     .type = VSH_OT_INT,
     .flags = VSH_OFLAG_REQ,
     .help = N_("maximum tolerable downtime (in milliseconds) for migration")
    },
    {.name = NULL}
};

static bool
cmdMigrateSetMaxDowntime(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    unsigned long long downtime = 0;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptULongLong(ctl, cmd, "downtime", &downtime) < 0)
        return false;

    if (downtime < 1) {
        vshError(ctl, "%s", _("migrate: Invalid downtime"));
        return false;
    }

    return virDomainMigrateSetMaxDowntime(dom, downtime, 0) == 0;
}


/*
 * "migrate-getmaxdowntime" command
 */
static const vshCmdInfo info_migrate_getmaxdowntime[] = {
    {.name = "help",
     .data = N_("get maximum tolerable downtime")
    },
    {.name = "desc",
     .data = N_("Get maximum tolerable downtime of a domain which is being live-migrated to another host.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_migrate_getmaxdowntime[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = NULL}
};

static bool
cmdMigrateGetMaxDowntime(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    unsigned long long downtime;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virDomainMigrateGetMaxDowntime(dom, &downtime, 0) < 0)
        return false;

    vshPrint(ctl, "%llu\n", downtime);
    return true;
}


/*
 * "migrate-compcache" command
 */
static const vshCmdInfo info_migrate_compcache[] = {
    {.name = "help",
     .data = N_("get/set compression cache size")
    },
    {.name = "desc",
     .data = N_("Get/set size of the cache (in bytes) used for compressing "
                "repeatedly transferred memory pages during live migration.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_migrate_compcache[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "size",
     .type = VSH_OT_INT,
     .flags = VSH_OFLAG_REQ_OPT,
     .help = N_("requested size of the cache (in bytes) used for compression")
    },
    {.name = NULL}
};

static bool
cmdMigrateCompCache(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    unsigned long long size = 0;
    const char *unit;
    double value;
    int rc;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    rc = vshCommandOptULongLong(ctl, cmd, "size", &size);
    if (rc < 0)
        return false;

    if (rc != 0 &&
        (virDomainMigrateSetCompressionCache(dom, size, 0) < 0))
        return false;

    if (virDomainMigrateGetCompressionCache(dom, &size, 0) < 0)
        return false;

    value = vshPrettyCapacity(size, &unit);
    vshPrint(ctl, _("Compression cache: %1$.3lf %2$s"), value, unit);

    return true;
}

/*
 * "migrate-setspeed" command
 */
static const vshCmdInfo info_migrate_setspeed[] = {
    {.name = "help",
     .data = N_("Set the maximum migration bandwidth")
    },
    {.name = "desc",
     .data = N_("Set the maximum migration bandwidth (in MiB/s) for a domain "
                "which is being migrated to another host.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_migrate_setspeed[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "bandwidth",
     .type = VSH_OT_INT,
     .flags = VSH_OFLAG_REQ,
     .help = N_("migration bandwidth limit in MiB/s")
    },
    {.name = "postcopy",
     .type = VSH_OT_BOOL,
     .help = N_("set post-copy migration bandwidth")
    },
    {.name = NULL}
};

static bool
cmdMigrateSetMaxSpeed(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    unsigned long bandwidth = 0;
    unsigned int flags = 0;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptULWrap(ctl, cmd, "bandwidth", &bandwidth) < 0)
        return false;

    if (vshCommandOptBool(cmd, "postcopy"))
        flags |= VIR_DOMAIN_MIGRATE_MAX_SPEED_POSTCOPY;

    if (virDomainMigrateSetMaxSpeed(dom, bandwidth, flags) < 0)
        return false;

    return true;
}

/*
 * "migrate-getspeed" command
 */
static const vshCmdInfo info_migrate_getspeed[] = {
    {.name = "help",
     .data = N_("Get the maximum migration bandwidth")
    },
    {.name = "desc",
     .data = N_("Get the maximum migration bandwidth (in MiB/s) for a domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_migrate_getspeed[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "postcopy",
     .type = VSH_OT_BOOL,
     .help = N_("get post-copy migration bandwidth")
    },
    {.name = NULL}
};

static bool
cmdMigrateGetMaxSpeed(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    unsigned long bandwidth;
    unsigned int flags = 0;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptBool(cmd, "postcopy"))
        flags |= VIR_DOMAIN_MIGRATE_MAX_SPEED_POSTCOPY;

    if (virDomainMigrateGetMaxSpeed(dom, &bandwidth, flags) < 0)
        return false;

    vshPrint(ctl, "%lu\n", bandwidth);

    return true;
}

/*
 * "migrate-postcopy" command
 */
static const vshCmdInfo info_migrate_postcopy[] = {
    {.name = "help",
     .data = N_("Switch running migration from pre-copy to post-copy")
    },
    {.name = "desc",
     .data = N_("Switch running migration from pre-copy to post-copy. "
                "The migration must have been started with --postcopy option.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_migrate_postcopy[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = NULL}
};

static bool
cmdMigratePostCopy(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virDomainMigrateStartPostCopy(dom, 0) < 0)
        return false;

    return true;
}

/*
 * "domdisplay" command
 */
static const vshCmdInfo info_domdisplay[] = {
    {.name = "help",
     .data = N_("domain display connection URI")
    },
    {.name = "desc",
     .data = N_("Output the IP address and port number "
                "for the graphical display.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domdisplay[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "include-password",
     .type = VSH_OT_BOOL,
     .help = N_("includes the password into the connection URI if available")
    },
    {.name = "type",
     .type = VSH_OT_STRING,
     .help = N_("select particular graphical display "
                "(e.g. \"vnc\", \"spice\", \"rdp\", \"dbus\")")
    },
    {.name = "all",
     .type = VSH_OT_BOOL,
     .help = N_("show all possible graphical displays")
    },
    {.name = NULL}
};

static char *
virshGetDBusDisplay(vshControl *ctl, xmlXPathContext *ctxt)
{
    g_autofree char *addr = NULL;
    const char *xpath = "string(/domain/devices/graphics[@type='dbus']/@address)";

    addr = virXPathString(xpath, ctxt);
    if (!addr)
        return false;

    if (STRPREFIX(addr, "unix:path=")) {
        return g_strdup_printf("dbus+unix://%s", addr + 10);
    }

    vshError(ctl, _("'%1$s' D-Bus address is not handled"), addr);
    return NULL;
}

static char *
virshGetOneDisplay(vshControl *ctl,
                   const char *scheme,
                   xmlXPathContext *ctxt)
{
    const char *xpath_fmt = "string(/domain/devices/graphics[@type='%s']/%s)";
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_autofree char *xpathPort = NULL;
    g_autofree char *xpathPortTLS = NULL;
    g_autofree char *xpathListen = NULL;
    g_autofree char *xpathType = NULL;
    g_autofree char *xpathPasswd = NULL;
    g_autofree char *listen_addr = NULL;
    int port = 0;
    int tls_port = 0;
    g_autofree char *type_conn = NULL;
    g_autofree char *sockpath = NULL;
    g_autofree char *passwd = NULL;

    if (STREQ(scheme, "dbus"))
        return virshGetDBusDisplay(ctl, ctxt);

    /* Attempt to get the port number for the current graphics scheme */
    xpathPort = g_strdup_printf(xpath_fmt, scheme, "@port");

    if (virXPathInt(xpathPort, ctxt, &port) < 0)
        port = 0;

    /* Attempt to get the TLS port number */
    xpathPortTLS = g_strdup_printf(xpath_fmt, scheme, "@tlsPort");

    if (virXPathInt(xpathPortTLS, ctxt, &tls_port) < 0)
        tls_port = 0;

    /* Attempt to get the listening addr if set for the current graphics scheme */
    xpathListen = g_strdup_printf(xpath_fmt, scheme, "@listen");
    listen_addr = virXPathString(xpathListen, ctxt);

    /* Attempt to get the type of spice connection */
    xpathType = g_strdup_printf(xpath_fmt, scheme, "listen/@type");
    type_conn = virXPathString(xpathType, ctxt);

    if (STREQ_NULLABLE(type_conn, "socket")) {
        g_autofree char *xpathSockpath = g_strdup_printf(xpath_fmt, scheme, "listen/@socket");

        sockpath = virXPathString(xpathSockpath, ctxt);
    }

    if (!port && !tls_port && !sockpath)
        return NULL;

    if (!listen_addr) {
        g_autofree char *xpathListenAddress = NULL;
        /* The subelement address - <listen address='xyz'/> -
         * *should* have been automatically backfilled into its
         * parent <graphics listen='xyz'> (which we just tried to
         * retrieve into listen_addr above) but in some cases it
         * isn't, so we also do an explicit check for the
         * subelement (which, by the way, doesn't exist on libvirt
         * < 0.9.4, so we really do need to check both places)
         */
        xpathListenAddress = g_strdup_printf(xpath_fmt, scheme, "listen/@address");

        listen_addr = virXPathString(xpathListenAddress, ctxt);
    } else {
        virSocketAddr addr;

        /* If listen_addr is 0.0.0.0 or [::] we should try to parse URI and set
         * listen_addr based on current URI. If that fails we'll print
         * 'localhost' as the address as INADDR_ANY won't help the user. */
        if (virSocketAddrParse(&addr, listen_addr, AF_UNSPEC) > 0 &&
            virSocketAddrIsWildcard(&addr)) {

            virConnectPtr conn = ((virshControl *)(ctl->privData))->conn;
            g_autofree char *uriStr = virConnectGetURI(conn);
            g_autoptr(virURI) uri = NULL;

            g_clear_pointer(&listen_addr, g_free);

            if (uriStr && (uri = virURIParse(uriStr)))
                listen_addr = g_strdup(uri->server);
        }
    }

    /* Attempt to get the password.
     * We can query this info for all the graphics types since we'll
     * get nothing for the unsupported ones (just rdp for now).
     * Also the parameter '--include-password' was already taken
     * care of when getting the XML */
    xpathPasswd = g_strdup_printf(xpath_fmt, scheme, "@passwd");
    passwd = virXPathString(xpathPasswd, ctxt);

    /* Build up the full URI, starting with the scheme */
    if (sockpath)
        virBufferAsprintf(&buf, "%s+unix://", scheme);
    else
        virBufferAsprintf(&buf, "%s://", scheme);

    /* There is no user, so just append password if there's any */
    if (STREQ(scheme, "vnc") && passwd)
        virBufferAsprintf(&buf, ":%s@", passwd);

    /* Then host name or IP */
    if (!listen_addr && !sockpath)
        virBufferAddLit(&buf, "localhost");
    else if (!sockpath && strchr(listen_addr, ':'))
        virBufferAsprintf(&buf, "[%s]", listen_addr);
    else if (sockpath)
        virBufferAsprintf(&buf, "%s", sockpath);
    else
        virBufferAsprintf(&buf, "%s", listen_addr);

    /* Add the port */
    if (port) {
        if (STREQ(scheme, "vnc")) {
            /* VNC protocol handlers take their port number as
             * 'port' - 5900 */
            port -= 5900;
        }

        virBufferAsprintf(&buf, ":%d", port);
    }

    /* format the parameters part of the uri */
    virBufferAddLit(&buf, "?");

    /* TLS Port */
    if (tls_port) {
        virBufferAsprintf(&buf, "tls-port=%d&", tls_port);
    }

    if (STREQ(scheme, "spice") && passwd) {
        virBufferAsprintf(&buf, "password=%s&", passwd);
    }

    virBufferTrimLen(&buf, 1);

    return virBufferContentAndReset(&buf);
}


static bool
cmdDomDisplay(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    g_autoptr(virshDomain) dom = NULL;
    bool ret = false;
    const char *scheme[] = { "vnc", "spice", "rdp", "dbus", NULL };
    const char *type = NULL;
    int iter = 0;
    int flags = 0;
    bool all = vshCommandOptBool(cmd, "all");

    VSH_EXCLUSIVE_OPTIONS("all", "type");

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (!virDomainIsActive(dom)) {
        vshError(ctl, _("Domain is not running"));
        return false;
    }

    if (vshCommandOptBool(cmd, "include-password"))
        flags |= VIR_DOMAIN_XML_SECURE;

    if (vshCommandOptStringReq(ctl, cmd, "type", &type) < 0)
        return false;

    if (virshDomainGetXMLFromDom(ctl, dom, flags, &xml, &ctxt) < 0)
        return false;

    /* Attempt to grab our display info */
    for (iter = 0; scheme[iter] != NULL; iter++) {
        g_autofree char *display = NULL;

        /* Particular scheme requested */
        if (!all && type && STRNEQ(type, scheme[iter]))
            continue;

        if (!(display = virshGetOneDisplay(ctl, scheme[iter], ctxt)))
            continue;

        vshPrint(ctl, "%s", display);

        /* We got what we came for so return successfully */
        ret = true;
        if (!all)
            break;
        vshPrint(ctl, "\n");
    }

    if (!ret) {
        if (type)
            vshError(ctl, _("No graphical display with type '%1$s' found"), type);
        else
            vshError(ctl, _("No graphical display found"));
    }

    return ret;
}

/*
 * "vncdisplay" command
 */
static const vshCmdInfo info_vncdisplay[] = {
    {.name = "help",
     .data = N_("vnc display")
    },
    {.name = "desc",
     .data = N_("Output the IP address and port number for the VNC display.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_vncdisplay[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = NULL}
};

static bool
cmdVNCDisplay(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    g_autoptr(virshDomain) dom = NULL;
    int port = 0;
    g_autofree char *listen_addr = NULL;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    /* Check if the domain is active and don't rely on -1 for this */
    if (!virDomainIsActive(dom)) {
        vshError(ctl, _("Domain is not running"));
        return false;
    }

    if (virshDomainGetXMLFromDom(ctl, dom, 0, &xml, &ctxt) < 0)
        return false;

    /* Get the VNC port */
    if (virXPathInt("string(/domain/devices/graphics[@type='vnc']/@port)",
                    ctxt, &port)) {
        vshError(ctl, _("Failed to get VNC port. Is this domain using VNC?"));
        return false;
    }

    listen_addr = virXPathString("string(/domain/devices/graphics"
                                 "[@type='vnc']/@listen)", ctxt);
    if (!listen_addr) {
        /* The subelement address - <listen address='xyz'/> -
         * *should* have been automatically backfilled into its
         * parent <graphics listen='xyz'> (which we just tried to
         * retrieve into listen_addr above) but in some cases it
         * isn't, so we also do an explicit check for the
         * subelement (which, by the way, doesn't exist on libvirt
         * < 0.9.4, so we really do need to check both places)
         */
        listen_addr = virXPathString("string(/domain/devices/graphics"
                                     "[@type='vnc']/listen/@address)", ctxt);
    }
    if (listen_addr == NULL || STREQ(listen_addr, "0.0.0.0"))
        vshPrint(ctl, ":%d\n", port-5900);
    else
        vshPrint(ctl, "%s:%d\n", listen_addr, port-5900);

    return true;
}

/*
 * "ttyconsole" command
 */
static const vshCmdInfo info_ttyconsole[] = {
    {.name = "help",
     .data = N_("tty console")
    },
    {.name = "desc",
     .data = N_("Output the device for the TTY console.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_ttyconsole[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = NULL}
};

static bool
cmdTTYConsole(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    g_autofree char *tty = NULL;

    if (virshDomainGetXML(ctl, cmd, 0, &xml, &ctxt) < 0)
        return false;

    if (!(tty = virXPathString("string(/domain/devices/console/@tty)", ctxt)))
        return false;

    vshPrint(ctl, "%s\n", tty);
    return true;
}

/*
 * "domhostname" command
 */
static const vshCmdInfo info_domhostname[] = {
    {.name = "help",
     .data = N_("print the domain's hostname")
    },
    {.name = "desc",
     .data = ""
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domhostname[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "source",
     .type = VSH_OT_STRING,
     .flags = VSH_OFLAG_NONE,
     .completer = virshDomainHostnameSourceCompleter,
     .help = N_("address source: 'lease' or 'agent'")},
    {.name = NULL}
};

VIR_ENUM_IMPL(virshDomainHostnameSource,
              VIRSH_DOMAIN_HOSTNAME_SOURCE_LAST,
              "agent",
              "lease");

static bool
cmdDomHostname(vshControl *ctl, const vshCmd *cmd)
{
    g_autofree char *hostname = NULL;
    g_autoptr(virshDomain) dom = NULL;
    const char *sourcestr = NULL;
    int flags = 0; /* Use default value. Drivers can have its own default. */

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "source", &sourcestr) < 0)
        return false;

    if (sourcestr) {
        int source = virshDomainHostnameSourceTypeFromString(sourcestr);

        if (source < 0) {
            vshError(ctl, _("Unknown data source '%1$s'"), sourcestr);
            return false;
        }

        switch ((virshDomainHostnameSource) source) {
        case VIRSH_DOMAIN_HOSTNAME_SOURCE_AGENT:
            flags |= VIR_DOMAIN_GET_HOSTNAME_AGENT;
            break;
        case VIRSH_DOMAIN_HOSTNAME_SOURCE_LEASE:
            flags |= VIR_DOMAIN_GET_HOSTNAME_LEASE;
            break;
        case VIRSH_DOMAIN_HOSTNAME_SOURCE_LAST:
            break;
        }
    }

    hostname = virDomainGetHostname(dom, flags);
    if (hostname == NULL) {
        vshError(ctl, "%s", _("failed to get hostname"));
        return false;
    }

    vshPrint(ctl, "%s\n", hostname);
    return true;
}

/*
 * "detach-device" command
 */
static const vshCmdInfo info_detach_device[] = {
    {.name = "help",
     .data = N_("detach device from an XML file")
    },
    {.name = "desc",
     .data = N_("Detach device from an XML <file>")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_detach_device[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    VIRSH_COMMON_OPT_FILE(N_("XML file")),
    VIRSH_COMMON_OPT_DOMAIN_PERSISTENT,
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = NULL}
};

static bool
cmdDetachDevice(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *from = NULL;
    g_autofree char *buffer = NULL;
    int ret;
    bool current = vshCommandOptBool(cmd, "current");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool persistent = vshCommandOptBool(cmd, "persistent");
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;

    VSH_EXCLUSIVE_OPTIONS_VAR(persistent, current);

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (config || persistent)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (persistent &&
        virDomainIsActive(dom) == 1)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        return false;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0) {
        vshReportError(ctl);
        return false;
    }

    if (flags != 0 || current)
        ret = virDomainDetachDeviceFlags(dom, buffer, flags);
    else
        ret = virDomainDetachDevice(dom, buffer);

    if (ret < 0) {
        vshError(ctl, _("Failed to detach device from %1$s"), from);
        return false;
    }

    vshPrintExtra(ctl, "%s", _("Device detached successfully\n"));
    return true;
}


/*
 * "detach-device-alias" command
 */
static const vshCmdInfo info_detach_device_alias[] = {
    {.name = "help",
     .data = N_("detach device from an alias")
    },
    {.name = "desc",
     .data = N_("Detach device identified by the given alias from a domain")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_detach_device_alias[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "alias",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshDomainDeviceAliasCompleter,
     .help = N_("device alias")
    },
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = NULL}
};

static bool
cmdDetachDeviceAlias(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *alias = NULL;
    bool current = vshCommandOptBool(cmd, "current");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (config)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "alias", &alias) < 0)
        return false;

    if (virDomainDetachDeviceAlias(dom, alias, flags) < 0) {
        vshError(ctl, _("Failed to detach device with alias %1$s"), alias);
        return false;
    }

    vshPrintExtra(ctl, "%s", _("Device detach request sent successfully\n"));
    return true;
}


/*
 * "update-device" command
 */
static const vshCmdInfo info_update_device[] = {
    {.name = "help",
     .data = N_("update device from an XML file")
    },
    {.name = "desc",
     .data = N_("Update device from an XML <file>.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_update_device[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    VIRSH_COMMON_OPT_FILE(N_("XML file")),
    VIRSH_COMMON_OPT_DOMAIN_PERSISTENT,
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = "force",
     .type = VSH_OT_BOOL,
     .help = N_("force device update")
    },
    {.name = NULL}
};

static bool
cmdUpdateDevice(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *from = NULL;
    g_autofree char *buffer = NULL;
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;
    bool current = vshCommandOptBool(cmd, "current");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool persistent = vshCommandOptBool(cmd, "persistent");

    VSH_EXCLUSIVE_OPTIONS_VAR(persistent, current);

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (config || persistent)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        return false;

    if (persistent &&
        virDomainIsActive(dom) == 1)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0) {
        vshReportError(ctl);
        return false;
    }

    if (vshCommandOptBool(cmd, "force"))
        flags |= VIR_DOMAIN_DEVICE_MODIFY_FORCE;

    if (virDomainUpdateDeviceFlags(dom, buffer, flags) < 0) {
        vshError(ctl, _("Failed to update device from %1$s"), from);
        return false;
    }

    vshPrintExtra(ctl, "%s", _("Device updated successfully\n"));

    return true;
}

/*
 * "detach-interface" command
 */
static const vshCmdInfo info_detach_interface[] = {
    {.name = "help",
     .data = N_("detach network interface")
    },
    {.name = "desc",
     .data = N_("Detach network interface.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_detach_interface[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "type",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("network interface type")
    },
    {.name = "mac",
     .type = VSH_OT_STRING,
     .completer = virshDomainInterfaceCompleter,
     .completer_flags = VIRSH_DOMAIN_INTERFACE_COMPLETER_MAC,
     .help = N_("MAC address")
    },
    VIRSH_COMMON_OPT_DOMAIN_PERSISTENT,
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = "print-xml",
     .type = VSH_OT_BOOL,
     .help = N_("print XML document rather than detach the interface")
    },
    {.name = NULL}
};

static bool
virshDomainDetachInterface(char *doc,
                           unsigned int flags,
                           virDomainPtr dom,
                           vshControl *ctl,
                           bool current,
                           const char *type,
                           const char *mac,
                           bool printxml)
{
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    g_autofree char *detach_xml = NULL;
    g_autofree char *xpath = g_strdup_printf("/domain/devices/interface[@type='%s']", type);
    g_autofree xmlNodePtr *nodes = NULL;
    ssize_t nnodes;
    xmlNodePtr matchNode = NULL;
    size_t i;

    if (!(xml = virXMLParseStringCtxt(doc, _("(domain_definition)"), &ctxt))) {
        vshError(ctl, "%s", _("Failed to get interface information"));
        return false;
    }

    if ((nnodes = virXPathNodeSet(xpath, ctxt, &nodes)) <= 0) {
        vshError(ctl, _("No interface found whose type is %1$s"), type);
        return false;
    }

    if (mac) {
        for (i = 0; i < nnodes; i++) {
            g_autofree char *tmp_mac = NULL;

            ctxt->node = nodes[i];

            if ((tmp_mac = virXPathString("string(./mac/@address)", ctxt))) {

                if (virMacAddrCompare(tmp_mac, mac) == 0) {
                    if (matchNode) {
                        /* this is the 2nd match, so it's ambiguous */
                        vshError(ctl, _("Domain has multiple interfaces matching MAC address %1$s. You must use detach-device and specify the device pci address to remove it."),
                                 mac);
                        return false;
                    }

                    matchNode = nodes[i];
                }
            }
        }
    } else {
        if (nnodes > 1) {
            vshError(ctl, _("Domain has %1$zd interfaces. Please specify which one to detach using --mac"),
                     nnodes);
            return false;
        }

        matchNode = nodes[0];
    }

    if (!matchNode) {
        vshError(ctl, _("No interface with MAC address %1$s was found"), mac);
        return false;
    }

    if (!(detach_xml = virXMLNodeToString(xml, matchNode))) {
        vshSaveLibvirtError();
        return false;
    }

    if (printxml) {
        vshPrint(ctl, "%s", detach_xml);
        return true;
    }

    if (flags != 0 || current)
        return virDomainDetachDeviceFlags(dom, detach_xml, flags) == 0;
    return virDomainDetachDevice(dom, detach_xml) == 0;
}


static bool
cmdDetachInterface(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    g_autofree char *doc_live = NULL;
    g_autofree char *doc_config = NULL;
    const char *mac = NULL, *type = NULL;
    int flags = 0;
    bool ret = false, affect_config, affect_live;
    bool current = vshCommandOptBool(cmd, "current");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool persistent = vshCommandOptBool(cmd, "persistent");
    bool printxml = vshCommandOptBool(cmd, "print-xml");

    VSH_EXCLUSIVE_OPTIONS_VAR(persistent, current);

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "type", &type) < 0)
        goto cleanup;

    if (vshCommandOptStringReq(ctl, cmd, "mac", &mac) < 0)
        goto cleanup;

    affect_config = (config || persistent);

    if (affect_config) {
        if (!(doc_config = virDomainGetXMLDesc(dom, VIR_DOMAIN_XML_INACTIVE)))
            goto cleanup;
        if (!(ret = virshDomainDetachInterface(doc_config,
                                               flags | VIR_DOMAIN_AFFECT_CONFIG,
                                               dom, ctl, current, type, mac,
                                               printxml)))
            goto cleanup;
    }

    affect_live = (live || (persistent && virDomainIsActive(dom) == 1));

    if (affect_live || !affect_config) {
        flags = 0;

        if (affect_live)
            flags |= VIR_DOMAIN_AFFECT_LIVE;

        if (!(doc_live = virDomainGetXMLDesc(dom, 0)))
            goto cleanup;

        ret = virshDomainDetachInterface(doc_live, flags,
                                         dom, ctl, current, type, mac, printxml);
    }

    if (printxml)
        return ret;

 cleanup:
    if (!ret) {
        vshError(ctl, "%s", _("Failed to detach interface"));
    } else {
        vshPrintExtra(ctl, "%s", _("Interface detached successfully\n"));
    }
    return ret;
}


static void
virshDiskDropBackingStore(xmlNodePtr disk_node)
{
    xmlNodePtr tmp = virXMLNodeGetSubelement(disk_node, "backingStore");

    if (!tmp)
        return;

    xmlUnlinkNode(tmp);
    xmlFreeNode(tmp);
}


typedef enum {
    VIRSH_FIND_DISK_NORMAL,
    VIRSH_FIND_DISK_CHANGEABLE,
} virshFindDiskType;

/* Helper function to find disk device in XML doc.  Returns the disk
 * node on success, or NULL on failure. Caller must free the result
 * @path: Fully-qualified path or target of disk device.
 * @type: Either VIRSH_FIND_DISK_NORMAL or VIRSH_FIND_DISK_CHANGEABLE.
 */
static xmlNodePtr
virshFindDisk(const char *doc,
              const char *path,
              int type)
{
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    g_autofree xmlNodePtr *nodes = NULL;
    ssize_t nnodes;
    size_t i;

    xml = virXMLParseStringCtxt(doc, _("(domain_definition)"), &ctxt);
    if (!xml) {
        vshError(NULL, "%s", _("Failed to get disk information"));
        return NULL;
    }

    if ((nnodes = virXPathNodeSet("/domain/devices/disk", ctxt, &nodes)) <= 0) {
        vshError(NULL, "%s", _("Failed to get disk information"));
        return NULL;
    }

    /* search disk using @path */
    for (i = 0; i < nnodes; i++) {
        xmlNodePtr sourceNode;
        g_autofree char *sourceFile = NULL;
        g_autofree char *sourceDev = NULL;
        g_autofree char *sourceDir = NULL;
        g_autofree char *sourceName = NULL;
        g_autofree char *targetDev = NULL;

        if (type == VIRSH_FIND_DISK_CHANGEABLE) {
            g_autofree char *device = virXMLPropString(nodes[i], "device");

            /* Check if the disk is CDROM or floppy disk */
            if (device &&
                STRNEQ(device, "cdrom") &&
                STRNEQ(device, "floppy"))
                continue;
        }

        if ((sourceNode = virXMLNodeGetSubelement(nodes[i], "source"))) {
            sourceFile = virXMLPropString(sourceNode, "file");
            sourceDev = virXMLPropString(sourceNode, "dev");
            sourceDir = virXMLPropString(sourceNode, "dir");
            sourceName = virXMLPropString(sourceNode, "name");
        }

        ctxt->node = nodes[i];
        targetDev = virXPathString("string(./target/@dev)", ctxt);

        if (STREQ_NULLABLE(targetDev, path) ||
            STREQ_NULLABLE(sourceFile, path) ||
            STREQ_NULLABLE(sourceDev, path) ||
            STREQ_NULLABLE(sourceDir, path) ||
            STREQ_NULLABLE(sourceName, path)) {
            xmlNodePtr ret = xmlCopyNode(nodes[i], 1);
            /* drop backing store since they are not needed here */
            virshDiskDropBackingStore(ret);
            return ret;
        }
    }

    vshError(NULL, _("No disk found whose source path or target is %1$s"), path);

    return NULL;
}

typedef enum {
    VIRSH_UPDATE_DISK_XML_EJECT,
    VIRSH_UPDATE_DISK_XML_INSERT,
    VIRSH_UPDATE_DISK_XML_UPDATE,
} virshUpdateDiskXMLType;

/* Helper function to prepare disk XML. Could be used for disk
 * detaching, media changing(ejecting, inserting, updating)
 * for changeable disk. Returns the processed XML as string on
 * success, or NULL on failure. Caller must free the result.
 */
static char *
virshUpdateDiskXML(xmlNodePtr disk_node,
                   const char *new_source,
                   bool source_block,
                   const char *target,
                   virshUpdateDiskXMLType type)
{
    xmlNodePtr source = NULL;
    g_autofree char *device_type = NULL;
    char *ret = NULL;
    g_autofree char *startupPolicy = NULL;
    g_autofree char *source_path = NULL;

    if (!disk_node)
        return NULL;

    device_type = virXMLPropString(disk_node, "device");

    if (!(STREQ_NULLABLE(device_type, "cdrom") ||
          STREQ_NULLABLE(device_type, "floppy"))) {
        vshError(NULL, _("The disk device '%1$s' is not removable"), target);
        return NULL;
    }

    source = virXMLNodeGetSubelement(disk_node, "source");

    if (type == VIRSH_UPDATE_DISK_XML_EJECT) {
        if (!source) {
            vshError(NULL, _("The disk device '%1$s' doesn't have media"), target);
            return NULL;
        }

        /* forcibly switch to empty file cdrom */
        source_block = false;
        new_source = NULL;
    } else if (!new_source) {
        vshError(NULL, _("New disk media source was not specified"));
        return NULL;
    }

    if (source) {
        if (!(source_path = virXMLPropString(source, "file")) &&
            !(source_path = virXMLPropString(source, "dev")) &&
            !(source_path = virXMLPropString(source, "dir")) &&
            !(source_path = virXMLPropString(source, "pool")))
            source_path = virXMLPropString(source, "name");

        if (source_path && type == VIRSH_UPDATE_DISK_XML_INSERT) {
            vshError(NULL, _("The disk device '%1$s' already has media"), target);
            return NULL;
        }

        startupPolicy = virXMLPropString(source, "startupPolicy");

        /* remove current source */
        xmlUnlinkNode(source);
        g_clear_pointer(&source, xmlFreeNode);
    }

    /* set the correct disk type */
    if (source_block)
        xmlSetProp(disk_node, BAD_CAST "type", BAD_CAST "block");
    else
        xmlSetProp(disk_node, BAD_CAST "type", BAD_CAST "file");

    if (new_source) {
        /* create new source subelement */
        source = virXMLNewNode(NULL, "source");

        if (source_block)
            xmlNewProp(source, BAD_CAST "dev", BAD_CAST new_source);
        else
            xmlNewProp(source, BAD_CAST "file", BAD_CAST new_source);

        if (startupPolicy)
            xmlNewProp(source, BAD_CAST "startupPolicy", BAD_CAST startupPolicy);

        xmlAddChild(disk_node, source);
    }

    if (!(ret = virXMLNodeToString(NULL, disk_node))) {
        vshSaveLibvirtError();
        return NULL;
    }

    return ret;
}


/*
 * "detach-disk" command
 */
static const vshCmdInfo info_detach_disk[] = {
    {.name = "help",
     .data = N_("detach disk device")
    },
    {.name = "desc",
     .data = N_("Detach disk device.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_detach_disk[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "target",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshDomainDiskTargetCompleter,
     .help = N_("target of disk device")
    },
    VIRSH_COMMON_OPT_DOMAIN_PERSISTENT,
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = "print-xml",
     .type = VSH_OT_BOOL,
     .help = N_("print XML document rather than detach the disk")
    },
    {.name = NULL}
};

static bool
cmdDetachDisk(vshControl *ctl, const vshCmd *cmd)
{
    g_autofree char *disk_xml = NULL;
    g_autoptr(virshDomain) dom = NULL;
    const char *target = NULL;
    g_autofree char *doc = NULL;
    int ret;
    g_autoptr(xmlNode) disk_node = NULL;
    bool current = vshCommandOptBool(cmd, "current");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool persistent = vshCommandOptBool(cmd, "persistent");
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;

    VSH_EXCLUSIVE_OPTIONS_VAR(persistent, current);

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (config || persistent)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "target", &target) < 0)
        return false;

    if (flags == VIR_DOMAIN_AFFECT_CONFIG)
        doc = virDomainGetXMLDesc(dom, VIR_DOMAIN_XML_INACTIVE);
    else
        doc = virDomainGetXMLDesc(dom, 0);

    if (!doc)
        return false;

    if (persistent &&
        virDomainIsActive(dom) == 1)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (!(disk_node = virshFindDisk(doc, target, VIRSH_FIND_DISK_NORMAL)))
        return false;

    if (!(disk_xml = virXMLNodeToString(NULL, disk_node))) {
        vshSaveLibvirtError();
        return false;
    }

    if (vshCommandOptBool(cmd, "print-xml")) {
        vshPrint(ctl, "%s", disk_xml);
        return true;
    }

    if (flags != 0 || current)
        ret = virDomainDetachDeviceFlags(dom, disk_xml, flags);
    else
        ret = virDomainDetachDevice(dom, disk_xml);

    if (ret != 0) {
        vshError(ctl, "%s", _("Failed to detach disk"));
        return false;
    }

    vshPrintExtra(ctl, "%s", _("Disk detached successfully\n"));
    return true;
}

/*
 * "edit" command
 */
static const vshCmdInfo info_edit[] = {
    {.name = "help",
     .data = N_("edit XML configuration for a domain")
    },
    {.name = "desc",
     .data = N_("Edit the XML configuration for a domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_edit[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "skip-validate",
     .type = VSH_OT_BOOL,
     .help = N_("skip validation of the XML against the schema")
    },
    {.name = NULL}
};

static bool
cmdEdit(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    g_autoptr(virshDomain) dom = NULL;
    g_autoptr(virshDomain) dom_edited = NULL;
    unsigned int query_flags = VIR_DOMAIN_XML_SECURE | VIR_DOMAIN_XML_INACTIVE;
    unsigned int define_flags = VIR_DOMAIN_DEFINE_VALIDATE;
    virshControl *priv = ctl->privData;

    dom = virshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    if (vshCommandOptBool(cmd, "skip-validate"))
        define_flags &= ~VIR_DOMAIN_DEFINE_VALIDATE;

#define EDIT_GET_XML virDomainGetXMLDesc(dom, query_flags)
#define EDIT_NOT_CHANGED \
    do { \
        vshPrintExtra(ctl, _("Domain '%1$s' XML configuration not changed.\n"), \
                      virDomainGetName(dom)); \
        ret = true; \
        goto edit_cleanup; \
    } while (0)
#define EDIT_DEFINE \
    (dom_edited = virshDomainDefine(priv->conn, doc_edited, define_flags))
#define EDIT_RELAX \
    do { \
        define_flags &= ~VIR_DOMAIN_DEFINE_VALIDATE; \
    } while (0);

#include "virsh-edit.c"
#undef EDIT_RELAX

    vshPrintExtra(ctl, _("Domain '%1$s' XML configuration edited.\n"),
                  virDomainGetName(dom_edited));

    ret = true;

 cleanup:

    return ret;
}


/*
 * "change-media" command
 */
static const vshCmdInfo info_change_media[] = {
    {.name = "help",
     .data = N_("Change media of CD or floppy drive")
    },
    {.name = "desc",
     .data = N_("Change media of CD or floppy drive.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_change_media[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "path",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshDomainDiskTargetCompleter,
     .help = N_("Fully-qualified path or target of disk device")
    },
    {.name = "source",
     .type = VSH_OT_STRING,
     .help = N_("source of the media")
    },
    {.name = "eject",
     .type = VSH_OT_BOOL,
     .help = N_("Eject the media")
    },
    {.name = "insert",
     .type = VSH_OT_BOOL,
     .help = N_("Insert the media")
    },
    {.name = "update",
     .type = VSH_OT_BOOL,
     .help = N_("Update the media")
    },
    VIRSH_COMMON_OPT_CURRENT(N_("can be either or both of --live and "
                                "--config, depends on implementation "
                                "hypervisor driver")),
    VIRSH_COMMON_OPT_LIVE(N_("alter live configuration of running domain")),
    VIRSH_COMMON_OPT_CONFIG(N_("alter persistent configuration, effect "
                               "observed on next boot")),
    {.name = "force",
     .type = VSH_OT_BOOL,
     .help = N_("force media changing")
    },
    {.name = "print-xml",
     .type = VSH_OT_BOOL,
     .help = N_("print XML document rather than change media")
    },
    {.name = "block",
     .type = VSH_OT_BOOL,
     .help = N_("source media is a block device")
    },
    {.name = NULL}
};

static bool
cmdChangeMedia(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *source = NULL;
    const char *path = NULL;
    g_autofree char *doc = NULL;
    g_autoptr(xmlNode) disk_node = NULL;
    g_autofree char *disk_xml = NULL;
    virshUpdateDiskXMLType update_type;
    const char *action = NULL;
    const char *success_msg = NULL;
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool current = vshCommandOptBool(cmd, "current");
    bool force = vshCommandOptBool(cmd, "force");
    bool eject = vshCommandOptBool(cmd, "eject");
    bool insert = vshCommandOptBool(cmd, "insert");
    bool update = vshCommandOptBool(cmd, "update");
    bool block = vshCommandOptBool(cmd, "block");
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;

    VSH_EXCLUSIVE_OPTIONS_VAR(eject, insert);
    VSH_EXCLUSIVE_OPTIONS_VAR(eject, update);
    VSH_EXCLUSIVE_OPTIONS_VAR(insert, update);

    VSH_EXCLUSIVE_OPTIONS_VAR(eject, block);

    if (vshCommandOptStringReq(ctl, cmd, "source", &source) < 0)
        return false;

    /* Docs state that update without source is eject */
    if (update && !source) {
        update = false;
        eject = true;
    }

    if (eject) {
        update_type = VIRSH_UPDATE_DISK_XML_EJECT;
        action = "eject";
        success_msg = _("Successfully ejected media.");
    }

    if (insert) {
        update_type = VIRSH_UPDATE_DISK_XML_INSERT;
        action = "insert";
        success_msg = _("Successfully inserted media.");
    }

    if (update || (!eject && !insert)) {
        update_type = VIRSH_UPDATE_DISK_XML_UPDATE;
        action = "update";
        success_msg = _("Successfully updated media.");
    }

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (config)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;
    if (force)
        flags |= VIR_DOMAIN_DEVICE_MODIFY_FORCE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "path", &path) < 0)
        return false;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG)
        doc = virDomainGetXMLDesc(dom, VIR_DOMAIN_XML_INACTIVE);
    else
        doc = virDomainGetXMLDesc(dom, 0);
    if (!doc)
        return false;

    if (!(disk_node = virshFindDisk(doc, path, VIRSH_FIND_DISK_CHANGEABLE)))
        return false;

    if (!(disk_xml = virshUpdateDiskXML(disk_node, source, block, path,
                                        update_type)))
        return false;

    if (vshCommandOptBool(cmd, "print-xml")) {
        vshPrint(ctl, "%s", disk_xml);
        return true;
    }

    if (virDomainUpdateDeviceFlags(dom, disk_xml, flags) != 0) {
        vshError(ctl, _("Failed to complete action %1$s on media"), action);
        return false;
    }

    vshPrint(ctl, "%s", success_msg);
    return true;
}

static const vshCmdInfo info_domfstrim[] = {
    {.name = "help",
     .data = N_("Invoke fstrim on domain's mounted filesystems.")
    },
    {.name = "desc",
     .data = N_("Invoke fstrim on domain's mounted filesystems.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domfstrim[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "minimum",
     .type = VSH_OT_INT,
     .help = N_("Just a hint to ignore contiguous "
                "free ranges smaller than this (Bytes)")
    },
    {.name = "mountpoint",
     .type = VSH_OT_STRING,
     .completer = virshDomainFSMountpointsCompleter,
     .help = N_("which mount point to trim")
    },
    {.name = NULL}
};
static bool
cmdDomFSTrim(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    unsigned long long minimum = 0;
    const char *mountPoint = NULL;
    unsigned int flags = 0;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptULongLong(ctl, cmd, "minimum", &minimum) < 0)
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "mountpoint", &mountPoint) < 0)
        return false;

    if (virDomainFSTrim(dom, mountPoint, minimum, flags) < 0) {
        vshError(ctl, _("Unable to invoke fstrim"));
        return false;
    }

    return true;
}

static const vshCmdInfo info_domfsfreeze[] = {
    {.name = "help",
     .data = N_("Freeze domain's mounted filesystems.")
    },
    {.name = "desc",
     .data = N_("Freeze domain's mounted filesystems.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domfsfreeze[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "mountpoint",
     .type = VSH_OT_ARGV,
     .completer = virshDomainFSMountpointsCompleter,
     .help = N_("mountpoint path to be frozen")
    },
    {.name = NULL}
};
static bool
cmdDomFSFreeze(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const vshCmdOpt *opt = NULL;
    g_autofree const char **mountpoints = NULL;
    size_t nmountpoints = 0;
    int count = 0;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    while ((opt = vshCommandOptArgv(ctl, cmd, opt))) {
        VIR_EXPAND_N(mountpoints, nmountpoints, 1);
        mountpoints[nmountpoints-1] = opt->data;
    }

    if ((count = virDomainFSFreeze(dom, mountpoints, nmountpoints, 0)) < 0) {
        vshError(ctl, _("Unable to freeze filesystems"));
        return false;
    }

    vshPrintExtra(ctl, _("Froze %1$d filesystem(s)\n"), count);
    return true;
}

static const vshCmdInfo info_domfsthaw[] = {
    {.name = "help",
     .data = N_("Thaw domain's mounted filesystems.")
    },
    {.name = "desc",
     .data = N_("Thaw domain's mounted filesystems.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domfsthaw[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "mountpoint",
     .type = VSH_OT_ARGV,
     .completer = virshDomainFSMountpointsCompleter,
     .help = N_("mountpoint path to be thawed")
    },
    {.name = NULL}
};
static bool
cmdDomFSThaw(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const vshCmdOpt *opt = NULL;
    g_autofree const char **mountpoints = NULL;
    size_t nmountpoints = 0;
    int count = 0;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    while ((opt = vshCommandOptArgv(ctl, cmd, opt))) {
        VIR_EXPAND_N(mountpoints, nmountpoints, 1);
        mountpoints[nmountpoints-1] = opt->data;
    }

    if ((count = virDomainFSThaw(dom, mountpoints, nmountpoints, 0)) < 0) {
        vshError(ctl, _("Unable to thaw filesystems"));
        return false;
    }

    vshPrintExtra(ctl, _("Thawed %1$d filesystem(s)\n"), count);
    return true;
}

static const vshCmdInfo info_domfsinfo[] = {
    {.name = "help",
     .data = N_("Get information of domain's mounted filesystems.")
    },
    {.name = "desc",
     .data = N_("Get information of domain's mounted filesystems.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domfsinfo[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = NULL}
};

static bool
cmdDomFSInfo(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    int rc = -1;
    size_t i, j;
    virDomainFSInfoPtr *info = NULL;
    g_autoptr(vshTable) table = NULL;
    size_t ninfos = 0;
    bool ret = false;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    rc = virDomainGetFSInfo(dom, &info, 0);
    if (rc < 0) {
        vshError(ctl, _("Unable to get filesystem information"));
        goto cleanup;
    }
    ninfos = rc;

    if (ninfos == 0) {
        ret = true;
        vshPrintExtra(ctl, _("No filesystems are mounted in the domain"));
        goto cleanup;
    }

    if (info) {
        table = vshTableNew(_("Mountpoint"), _("Name"), _("Type"), _("Target"), NULL);
        if (!table)
            goto cleanup;

        for (i = 0; i < ninfos; i++) {
            g_auto(virBuffer) targetsBuff = VIR_BUFFER_INITIALIZER;
            g_autofree char *targets = NULL;

            for (j = 0; j < info[i]->ndevAlias; j++)
                virBufferAsprintf(&targetsBuff, "%s,", info[i]->devAlias[j]);
            virBufferTrim(&targetsBuff, ",");

            targets = virBufferContentAndReset(&targetsBuff);

            if (vshTableRowAppend(table,
                                  info[i]->mountpoint,
                                  info[i]->name,
                                  info[i]->fstype,
                                  NULLSTR_EMPTY(targets),
                                  NULL) < 0)
                goto cleanup;
        }

        vshTablePrintToStdout(table, ctl);
    }

    ret = true;

 cleanup:
    if (info) {
        for (i = 0; i < ninfos; i++)
            virDomainFSInfoFree(info[i]);
        VIR_FREE(info);
    }
    return ret;
}

/*
 * "guest-agent-timeout" command
 */
static const vshCmdInfo info_guest_agent_timeout[] = {
    {.name = "help",
     .data = N_("Set the guest agent timeout")
    },
    {.name = "desc",
     .data = N_("Set the number of seconds to wait for a response from the guest agent.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_guest_agent_timeout[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "timeout",
     .type = VSH_OT_INT,
     .flags = VSH_OFLAG_REQ_OPT,
     .help = N_("timeout seconds.")
    },
    {.name = NULL}
};

static bool
cmdGuestAgentTimeout(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    int timeout = VIR_DOMAIN_AGENT_RESPONSE_TIMEOUT_BLOCK;
    const unsigned int flags = 0;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptInt(ctl, cmd, "timeout", &timeout) < 0)
        return false;

    if (virDomainAgentSetResponseTimeout(dom, timeout, flags) < 0)
        return false;

    return true;
}

/*
 * "guestinfo" command
 */
static const vshCmdInfo info_guestinfo[] = {
    {.name = "help",
     .data = N_("query information about the guest (via agent)")
    },
    {.name = "desc",
     .data = N_("Use the guest agent to query various information from guest's "
                "point of view")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_guestinfo[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "user",
     .type = VSH_OT_BOOL,
     .help = N_("report active users"),
    },
    {.name = "os",
     .type = VSH_OT_BOOL,
     .help = N_("report operating system information"),
    },
    {.name = "timezone",
     .type = VSH_OT_BOOL,
     .help = N_("report timezone information"),
    },
    {.name = "hostname",
     .type = VSH_OT_BOOL,
     .help = N_("report hostname"),
    },
    {.name = "filesystem",
     .type = VSH_OT_BOOL,
     .help = N_("report filesystem information"),
    },
    {.name = "disk",
     .type = VSH_OT_BOOL,
     .help = N_("report disk information"),
    },
    {.name = "interface",
     .type = VSH_OT_BOOL,
     .help = N_("report interface information"),
    },
    {.name = NULL}
};

static bool
cmdGuestInfo(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    bool ret = false;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    size_t i;
    unsigned int types = 0;

    if (vshCommandOptBool(cmd, "user"))
        types |= VIR_DOMAIN_GUEST_INFO_USERS;
    if (vshCommandOptBool(cmd, "os"))
        types |= VIR_DOMAIN_GUEST_INFO_OS;
    if (vshCommandOptBool(cmd, "timezone"))
        types |= VIR_DOMAIN_GUEST_INFO_TIMEZONE;
    if (vshCommandOptBool(cmd, "hostname"))
        types |= VIR_DOMAIN_GUEST_INFO_HOSTNAME;
    if (vshCommandOptBool(cmd, "filesystem"))
        types |= VIR_DOMAIN_GUEST_INFO_FILESYSTEM;
    if (vshCommandOptBool(cmd, "disk"))
        types |= VIR_DOMAIN_GUEST_INFO_DISKS;
    if (vshCommandOptBool(cmd, "interface"))
        types |= VIR_DOMAIN_GUEST_INFO_INTERFACES;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virDomainGetGuestInfo(dom, types, &params, &nparams, 0) < 0)
        goto cleanup;

    for (i = 0; i < nparams; i++) {
        g_autofree char *str = vshGetTypedParamValue(ctl, &params[i]);
        vshPrint(ctl, "%-20s: %s\n", params[i].field, str);
    }

    ret = true;

 cleanup:
    virTypedParamsFree(params, nparams);
    return ret;
}

/*
 * "get-user-sshkeys" command
 */
static const vshCmdInfo info_get_user_sshkeys[] = {
    {.name = "help",
     .data = N_("list authorized SSH keys for given user (via agent)")
    },
    {.name = "desc",
     .data = N_("Use the guest agent to query authorized SSH keys for given "
                "user")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_get_user_sshkeys[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "user",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("user to list authorized keys for"),
    },
    {.name = NULL}
};

static bool
cmdGetUserSSHKeys(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *user;
    g_auto(GStrv) keys = NULL;
    int nkeys = 0;
    size_t i;
    const unsigned int flags = 0;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "user", &user) < 0)
        return false;

    nkeys = virDomainAuthorizedSSHKeysGet(dom, user, &keys, flags);
    if (nkeys < 0)
        return false;

    for (i = 0; i < nkeys; i++) {
        vshPrint(ctl, "%s", keys[i]);
    }

    return true;
}


/*
 * "set-user-sshkeys" command
 */
static const vshCmdInfo info_set_user_sshkeys[] = {
    {.name = "help",
     .data = N_("manipulate authorized SSH keys file for given user (via agent)")
    },
    {.name = "desc",
     .data = N_("Append, reset or remove specified key from the authorized "
                "keys file for given user")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_set_user_sshkeys[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(VIR_CONNECT_LIST_DOMAINS_ACTIVE),
    {.name = "user",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("user to set authorized keys for"),
    },
    {.name = "file",
     .type = VSH_OT_STRING,
     .completer = virshCompletePathLocalExisting,
     .help = N_("optional file to read keys from"),
    },
    {.name = "reset",
     .type = VSH_OT_BOOL,
     .help = N_("clear out authorized keys file before adding new keys"),
    },
    {.name = "remove",
     .type = VSH_OT_BOOL,
     .help = N_("remove keys from the authorized keys file"),
    },
    {.name = NULL}
};

static bool
cmdSetUserSSHKeys(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    const char *user;
    const char *from;
    g_autofree char *buffer = NULL;
    g_auto(GStrv) keys = NULL;
    int nkeys = 0;
    unsigned int flags = 0;

    VSH_REQUIRE_OPTION("remove", "file");
    VSH_EXCLUSIVE_OPTIONS("reset", "remove");

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "user", &user) < 0)
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        return false;

    if (vshCommandOptBool(cmd, "remove")) {
        flags |= VIR_DOMAIN_AUTHORIZED_SSH_KEYS_SET_REMOVE;
    } else {
        if (!vshCommandOptBool(cmd, "reset")) {
            flags |= VIR_DOMAIN_AUTHORIZED_SSH_KEYS_SET_APPEND;

            if (!from) {
                vshError(ctl, _("Option --file is required"));
                return false;
            }
        }
    }

    if (from) {
        if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0) {
            vshSaveLibvirtError();
            return false;
        }

        if (!(keys = g_strsplit(buffer, "\n", -1)))
            return false;

        nkeys = g_strv_length(keys);
        if (nkeys == 0) {
            vshError(ctl, _("File %1$s contains no keys"), from);
            return false;
        }
    }

    if (virDomainAuthorizedSSHKeysSet(dom, user,
                                      (const char **) keys, nkeys, flags) < 0) {
        return false;
    }

    return true;
}


/*
 * "domdirtyrate" command
 */
static const vshCmdInfo info_domdirtyrate_calc[] = {
    {.name = "help",
     .data = N_("Calculate a vm's memory dirty rate")
    },
    {.name = "desc",
     .data = N_("Calculate memory dirty rate of a domain in order to "
                "decide whether it's proper to be migrated out or not.\n"
                "The calculated dirty rate information is available by "
                "calling 'domstats --dirtyrate'.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domdirtyrate_calc[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL(0),
    {.name = "seconds",
     .type = VSH_OT_INT,
     .help = N_("calculate memory dirty rate within specified seconds, "
                "the supported value range from 1 to 60, default to 1.")
    },
    {.name = "mode",
     .type = VSH_OT_STRING,
     .completer = virshDomainDirtyRateCalcModeCompleter,
     .help = N_("dirty page rate calculation mode, either of these 3 options "
                "'page-sampling, dirty-bitmap, dirty-ring' can be specified.")
    },
    {.name = NULL}
};

VIR_ENUM_IMPL(virshDomainDirtyRateCalcMode,
              VIRSH_DOMAIN_DIRTYRATE_CALC_MODE_LAST,
              "page-sampling",
              "dirty-bitmap",
              "dirty-ring");

static bool
cmdDomDirtyRateCalc(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    int seconds = 1; /* the default value is 1 */
    const char *modestr = NULL;
    unsigned int flags = 0;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptInt(ctl, cmd, "seconds", &seconds) < 0)
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "mode", &modestr) < 0)
        return false;

    if (modestr) {
        int mode = virshDomainDirtyRateCalcModeTypeFromString(modestr);

        if (mode < 0) {
            vshError(ctl, _("Unknown calculation mode '%1$s'"), modestr);
            return false;
        }

        switch ((virshDomainDirtyRateCalcMode) mode) {
        case VIRSH_DOMAIN_DIRTYRATE_CALC_MODE_PAGE_SAMPLING:
            flags |= VIR_DOMAIN_DIRTYRATE_MODE_PAGE_SAMPLING;
            break;
        case VIRSH_DOMAIN_DIRTYRATE_CALC_MODE_DIRTY_BITMAP:
            flags |= VIR_DOMAIN_DIRTYRATE_MODE_DIRTY_BITMAP;
            break;
        case VIRSH_DOMAIN_DIRTYRATE_CALC_MODE_DIRTY_RING:
            flags |= VIR_DOMAIN_DIRTYRATE_MODE_DIRTY_RING;
            break;
        case VIRSH_DOMAIN_DIRTYRATE_CALC_MODE_LAST:
            break;
        }
    }

    if (virDomainStartDirtyRateCalc(dom, seconds, flags) < 0)
        return false;

    vshPrintExtra(ctl, _("Start to calculate domain's memory dirty rate successfully.\n"));

    return true;
}


const vshCmdDef domManagementCmds[] = {
    {.name = "attach-device",
     .handler = cmdAttachDevice,
     .opts = opts_attach_device,
     .info = info_attach_device,
     .flags = 0
    },
    {.name = "attach-disk",
     .handler = cmdAttachDisk,
     .opts = opts_attach_disk,
     .info = info_attach_disk,
     .flags = 0
    },
    {.name = "attach-interface",
     .handler = cmdAttachInterface,
     .opts = opts_attach_interface,
     .info = info_attach_interface,
     .flags = 0
    },
    {.name = "autostart",
     .handler = cmdAutostart,
     .opts = opts_autostart,
     .info = info_autostart,
     .flags = 0
    },
    {.name = "blkdeviotune",
     .handler = cmdBlkdeviotune,
     .opts = opts_blkdeviotune,
     .info = info_blkdeviotune,
     .flags = 0
    },
    {.name = "blkiotune",
     .handler = cmdBlkiotune,
     .opts = opts_blkiotune,
     .info = info_blkiotune,
     .flags = 0
    },
    {.name = "blockcommit",
     .handler = cmdBlockcommit,
     .opts = opts_blockcommit,
     .info = info_blockcommit,
     .flags = 0
    },
    {.name = "blockcopy",
     .handler = cmdBlockcopy,
     .opts = opts_blockcopy,
     .info = info_blockcopy,
     .flags = 0
    },
    {.name = "blockjob",
     .handler = cmdBlockjob,
     .opts = opts_blockjob,
     .info = info_blockjob,
     .flags = 0
    },
    {.name = "blockpull",
     .handler = cmdBlockpull,
     .opts = opts_blockpull,
     .info = info_blockpull,
     .flags = 0
    },
    {.name = "blockresize",
     .handler = cmdBlockresize,
     .opts = opts_blockresize,
     .info = info_blockresize,
     .flags = 0
    },
    {.name = "change-media",
     .handler = cmdChangeMedia,
     .opts = opts_change_media,
     .info = info_change_media,
     .flags = 0
    },
#ifndef WIN32
    {.name = "console",
     .handler = cmdConsole,
     .opts = opts_console,
     .info = info_console,
     .flags = 0
    },
#endif
    {.name = "cpu-stats",
     .handler = cmdCPUStats,
     .opts = opts_cpu_stats,
     .info = info_cpu_stats,
     .flags = 0
    },
    {.name = "create",
     .handler = cmdCreate,
     .opts = opts_create,
     .info = info_create,
     .flags = 0
    },
    {.name = "define",
     .handler = cmdDefine,
     .opts = opts_define,
     .info = info_define,
     .flags = 0
    },
    {.name = "desc",
     .handler = cmdDesc,
     .opts = opts_desc,
     .info = info_desc,
     .flags = 0
    },
    {.name = "destroy",
     .handler = cmdDestroy,
     .opts = opts_destroy,
     .info = info_destroy,
     .flags = 0
    },
    {.name = "detach-device",
     .handler = cmdDetachDevice,
     .opts = opts_detach_device,
     .info = info_detach_device,
     .flags = 0
    },
    {.name = "detach-device-alias",
     .handler = cmdDetachDeviceAlias,
     .opts = opts_detach_device_alias,
     .info = info_detach_device_alias,
     .flags = 0
    },
    {.name = "detach-disk",
     .handler = cmdDetachDisk,
     .opts = opts_detach_disk,
     .info = info_detach_disk,
     .flags = 0
    },
    {.name = "detach-interface",
     .handler = cmdDetachInterface,
     .opts = opts_detach_interface,
     .info = info_detach_interface,
     .flags = 0
    },
    {.name = "domdisplay",
     .handler = cmdDomDisplay,
     .opts = opts_domdisplay,
     .info = info_domdisplay,
     .flags = 0
    },
    {.name = "domfsfreeze",
     .handler = cmdDomFSFreeze,
     .opts = opts_domfsfreeze,
     .info = info_domfsfreeze,
     .flags = 0
    },
    {.name = "domfsthaw",
     .handler = cmdDomFSThaw,
     .opts = opts_domfsthaw,
     .info = info_domfsthaw,
     .flags = 0
    },
    {.name = "domfsinfo",
     .handler = cmdDomFSInfo,
     .opts = opts_domfsinfo,
     .info = info_domfsinfo,
     .flags = 0
    },
    {.name = "domfstrim",
     .handler = cmdDomFSTrim,
     .opts = opts_domfstrim,
     .info = info_domfstrim,
     .flags = 0
    },
    {.name = "domhostname",
     .handler = cmdDomHostname,
     .opts = opts_domhostname,
     .info = info_domhostname,
     .flags = 0
    },
    {.name = "domid",
     .handler = cmdDomid,
     .opts = opts_domid,
     .info = info_domid,
     .flags = 0
    },
    {.name = "domif-setlink",
     .handler = cmdDomIfSetLink,
     .opts = opts_domif_setlink,
     .info = info_domif_setlink,
     .flags = 0
    },
    {.name = "domiftune",
     .handler = cmdDomIftune,
     .opts = opts_domiftune,
     .info = info_domiftune,
     .flags = 0
    },
    {.name = "domjobabort",
     .handler = cmdDomjobabort,
     .opts = opts_domjobabort,
     .info = info_domjobabort,
     .flags = 0
    },
    {.name = "domjobinfo",
     .handler = cmdDomjobinfo,
     .opts = opts_domjobinfo,
     .info = info_domjobinfo,
     .flags = 0
    },
    {.name = "domlaunchsecinfo",
     .handler = cmdDomLaunchSecInfo,
     .opts = opts_domlaunchsecinfo,
     .info = info_domlaunchsecinfo,
     .flags = 0
    },
    {.name = "domsetlaunchsecstate",
     .handler = cmdDomSetLaunchSecState,
     .opts = opts_domsetlaunchsecstate,
     .info = info_domsetlaunchsecstate,
     .flags = 0
    },
    {.name = "domname",
     .handler = cmdDomname,
     .opts = opts_domname,
     .info = info_domname,
     .flags = 0
    },
    {.name = "domrename",
     .handler = cmdDomrename,
     .opts = opts_domrename,
     .info = info_domrename,
     .flags = 0
    },
    {.name = "dompmsuspend",
     .handler = cmdDomPMSuspend,
     .opts = opts_dom_pm_suspend,
     .info = info_dom_pm_suspend,
     .flags = 0
    },
    {.name = "dompmwakeup",
     .handler = cmdDomPMWakeup,
     .opts = opts_dom_pm_wakeup,
     .info = info_dom_pm_wakeup,
     .flags = 0
    },
    {.name = "domuuid",
     .handler = cmdDomuuid,
     .opts = opts_domuuid,
     .info = info_domuuid,
     .flags = 0
    },
    {.name = "domxml-from-native",
     .handler = cmdDomXMLFromNative,
     .opts = opts_domxmlfromnative,
     .info = info_domxmlfromnative,
     .flags = 0
    },
    {.name = "domxml-to-native",
     .handler = cmdDomXMLToNative,
     .opts = opts_domxmltonative,
     .info = info_domxmltonative,
     .flags = 0
    },
    {.name = "dump",
     .handler = cmdDump,
     .opts = opts_dump,
     .info = info_dump,
     .flags = 0
    },
    {.name = "dumpxml",
     .handler = cmdDumpXML,
     .opts = opts_dumpxml,
     .info = info_dumpxml,
     .flags = 0
    },
    {.name = "edit",
     .handler = cmdEdit,
     .opts = opts_edit,
     .info = info_edit,
     .flags = 0
    },
    {.name = "get-user-sshkeys",
     .handler = cmdGetUserSSHKeys,
     .opts = opts_get_user_sshkeys,
     .info = info_get_user_sshkeys,
     .flags = 0
    },
    {.name = "inject-nmi",
     .handler = cmdInjectNMI,
     .opts = opts_inject_nmi,
     .info = info_inject_nmi,
     .flags = 0
    },
    {.name = "iothreadinfo",
     .handler = cmdIOThreadInfo,
     .opts = opts_iothreadinfo,
     .info = info_iothreadinfo,
     .flags = 0
    },
    {.name = "iothreadpin",
     .handler = cmdIOThreadPin,
     .opts = opts_iothreadpin,
     .info = info_iothreadpin,
     .flags = 0
    },
    {.name = "iothreadadd",
     .handler = cmdIOThreadAdd,
     .opts = opts_iothreadadd,
     .info = info_iothreadadd,
     .flags = 0
    },
    {.name = "iothreadset",
     .handler = cmdIOThreadSet,
     .opts = opts_iothreadset,
     .info = info_iothreadset,
     .flags = 0
    },
    {.name = "iothreaddel",
     .handler = cmdIOThreadDel,
     .opts = opts_iothreaddel,
     .info = info_iothreaddel,
     .flags = 0
    },
    {.name = "send-key",
     .handler = cmdSendKey,
     .opts = opts_send_key,
     .info = info_send_key,
     .flags = 0
    },
    {.name = "send-process-signal",
     .handler = cmdSendProcessSignal,
     .opts = opts_send_process_signal,
     .info = info_send_process_signal,
     .flags = 0
    },
    {.name = "lxc-enter-namespace",
     .handler = cmdLxcEnterNamespace,
     .opts = opts_lxc_enter_namespace,
     .info = info_lxc_enter_namespace,
     .flags = 0
    },
    {.name = "managedsave",
     .handler = cmdManagedSave,
     .opts = opts_managedsave,
     .info = info_managedsave,
     .flags = 0
    },
    {.name = "managedsave-remove",
     .handler = cmdManagedSaveRemove,
     .opts = opts_managedsaveremove,
     .info = info_managedsaveremove,
     .flags = 0
    },
    {.name = "managedsave-edit",
     .handler = cmdManagedSaveEdit,
     .opts = opts_managed_save_edit,
     .info = info_managed_save_edit,
     .flags = 0
    },
    {.name = "managedsave-dumpxml",
     .handler = cmdManagedSaveDumpxml,
     .opts = opts_managed_save_dumpxml,
     .info = info_managed_save_dumpxml,
     .flags = 0
    },
    {.name = "managedsave-define",
     .handler = cmdManagedSaveDefine,
     .opts = opts_managed_save_define,
     .info = info_managed_save_define,
     .flags = 0
    },
    {.name = "memtune",
     .handler = cmdMemtune,
     .opts = opts_memtune,
     .info = info_memtune,
     .flags = 0
    },
    {.name = "perf",
     .handler = cmdPerf,
     .opts = opts_perf,
     .info = info_perf,
     .flags = 0
    },
    {.name = "metadata",
     .handler = cmdMetadata,
     .opts = opts_metadata,
     .info = info_metadata,
     .flags = 0
    },
    {.name = "migrate",
     .handler = cmdMigrate,
     .opts = opts_migrate,
     .info = info_migrate,
     .flags = 0
    },
    {.name = "migrate-setmaxdowntime",
     .handler = cmdMigrateSetMaxDowntime,
     .opts = opts_migrate_setmaxdowntime,
     .info = info_migrate_setmaxdowntime,
     .flags = 0
    },
    {.name = "migrate-getmaxdowntime",
     .handler = cmdMigrateGetMaxDowntime,
     .opts = opts_migrate_getmaxdowntime,
     .info = info_migrate_getmaxdowntime,
     .flags = 0
    },
    {.name = "migrate-compcache",
     .handler = cmdMigrateCompCache,
     .opts = opts_migrate_compcache,
     .info = info_migrate_compcache,
     .flags = 0
    },
    {.name = "migrate-setspeed",
     .handler = cmdMigrateSetMaxSpeed,
     .opts = opts_migrate_setspeed,
     .info = info_migrate_setspeed,
     .flags = 0
    },
    {.name = "migrate-getspeed",
     .handler = cmdMigrateGetMaxSpeed,
     .opts = opts_migrate_getspeed,
     .info = info_migrate_getspeed,
     .flags = 0
    },
    {.name = "migrate-postcopy",
     .handler = cmdMigratePostCopy,
     .opts = opts_migrate_postcopy,
     .info = info_migrate_postcopy,
     .flags = 0
    },
    {.name = "numatune",
     .handler = cmdNumatune,
     .opts = opts_numatune,
     .info = info_numatune,
     .flags = 0
    },
    {.name = "qemu-attach",
     .handler = cmdQemuAttach,
     .opts = opts_qemu_attach,
     .info = info_qemu_attach,
     .flags = 0
    },
    {.name = "qemu-monitor-command",
     .handler = cmdQemuMonitorCommand,
     .opts = opts_qemu_monitor_command,
     .info = info_qemu_monitor_command,
     .flags = 0
    },
    {.name = "qemu-monitor-event",
     .handler = cmdQemuMonitorEvent,
     .opts = opts_qemu_monitor_event,
     .info = info_qemu_monitor_event,
     .flags = 0
    },
    {.name = "qemu-agent-command",
     .handler = cmdQemuAgentCommand,
     .opts = opts_qemu_agent_command,
     .info = info_qemu_agent_command,
     .flags = 0
    },
    {.name = "guest-agent-timeout",
     .handler = cmdGuestAgentTimeout,
     .opts = opts_guest_agent_timeout,
     .info = info_guest_agent_timeout,
     .flags = 0
    },
    {.name = "reboot",
     .handler = cmdReboot,
     .opts = opts_reboot,
     .info = info_reboot,
     .flags = 0
    },
    {.name = "reset",
     .handler = cmdReset,
     .opts = opts_reset,
     .info = info_reset,
     .flags = 0
    },
    {.name = "restore",
     .handler = cmdRestore,
     .opts = opts_restore,
     .info = info_restore,
     .flags = 0
    },
    {.name = "resume",
     .handler = cmdResume,
     .opts = opts_resume,
     .info = info_resume,
     .flags = 0
    },
    {.name = "save",
     .handler = cmdSave,
     .opts = opts_save,
     .info = info_save,
     .flags = 0
    },
    {.name = "save-image-define",
     .handler = cmdSaveImageDefine,
     .opts = opts_save_image_define,
     .info = info_save_image_define,
     .flags = 0
    },
    {.name = "save-image-dumpxml",
     .handler = cmdSaveImageDumpxml,
     .opts = opts_save_image_dumpxml,
     .info = info_save_image_dumpxml,
     .flags = 0
    },
    {.name = "save-image-edit",
     .handler = cmdSaveImageEdit,
     .opts = opts_save_image_edit,
     .info = info_save_image_edit,
     .flags = 0
    },
    {.name = "schedinfo",
     .handler = cmdSchedinfo,
     .opts = opts_schedinfo,
     .info = info_schedinfo,
     .flags = 0
    },
    {.name = "screenshot",
     .handler = cmdScreenshot,
     .opts = opts_screenshot,
     .info = info_screenshot,
     .flags = 0
    },
    {.name = "set-lifecycle-action",
     .handler = cmdSetLifecycleAction,
     .opts = opts_setLifecycleAction,
     .info = info_setLifecycleAction,
     .flags = 0
    },
    {.name = "set-user-sshkeys",
     .handler = cmdSetUserSSHKeys,
     .opts = opts_set_user_sshkeys,
     .info = info_set_user_sshkeys,
     .flags = 0
    },
    {.name = "set-user-password",
     .handler = cmdSetUserPassword,
     .opts = opts_set_user_password,
     .info = info_set_user_password,
     .flags = 0
    },
    {.name = "setmaxmem",
     .handler = cmdSetmaxmem,
     .opts = opts_setmaxmem,
     .info = info_setmaxmem,
     .flags = 0
    },
    {.name = "setmem",
     .handler = cmdSetmem,
     .opts = opts_setmem,
     .info = info_setmem,
     .flags = 0
    },
    {.name = "setvcpus",
     .handler = cmdSetvcpus,
     .opts = opts_setvcpus,
     .info = info_setvcpus,
     .flags = 0
    },
    {.name = "shutdown",
     .handler = cmdShutdown,
     .opts = opts_shutdown,
     .info = info_shutdown,
     .flags = 0
    },
    {.name = "start",
     .handler = cmdStart,
     .opts = opts_start,
     .info = info_start,
     .flags = 0
    },
    {.name = "suspend",
     .handler = cmdSuspend,
     .opts = opts_suspend,
     .info = info_suspend,
     .flags = 0
    },
    {.name = "ttyconsole",
     .handler = cmdTTYConsole,
     .opts = opts_ttyconsole,
     .info = info_ttyconsole,
     .flags = 0
    },
    {.name = "undefine",
     .handler = cmdUndefine,
     .opts = opts_undefine,
     .info = info_undefine,
     .flags = 0
    },
    {.name = "update-device",
     .handler = cmdUpdateDevice,
     .opts = opts_update_device,
     .info = info_update_device,
     .flags = 0
    },
    {.name = "update-memory-device",
     .handler = cmdUpdateMemoryDevice,
     .opts = opts_update_memory_device,
     .info = info_update_memory_device,
     .flags = 0
    },
    {.name = "vcpucount",
     .handler = cmdVcpucount,
     .opts = opts_vcpucount,
     .info = info_vcpucount,
     .flags = 0
    },
    {.name = "vcpuinfo",
     .handler = cmdVcpuinfo,
     .opts = opts_vcpuinfo,
     .info = info_vcpuinfo,
     .flags = 0
    },
    {.name = "vcpupin",
     .handler = cmdVcpuPin,
     .opts = opts_vcpupin,
     .info = info_vcpupin,
     .flags = 0
    },
    {.name = "emulatorpin",
     .handler = cmdEmulatorPin,
     .opts = opts_emulatorpin,
     .info = info_emulatorpin,
     .flags = 0
    },
    {.name = "vncdisplay",
     .handler = cmdVNCDisplay,
     .opts = opts_vncdisplay,
     .info = info_vncdisplay,
     .flags = 0
    },
    {.name = "guestvcpus",
     .handler = cmdGuestvcpus,
     .opts = opts_guestvcpus,
     .info = info_guestvcpus,
     .flags = 0
    },
    {.name = "setvcpu",
     .handler = cmdSetvcpu,
     .opts = opts_setvcpu,
     .info = info_setvcpu,
     .flags = 0
    },
    {.name = "domblkthreshold",
     .handler = cmdDomblkthreshold,
     .opts = opts_domblkthreshold,
     .info = info_domblkthreshold,
     .flags = 0
    },
    {.name = "guestinfo",
     .handler = cmdGuestInfo,
     .opts = opts_guestinfo,
     .info = info_guestinfo,
     .flags = 0
    },
    {.name = "domdirtyrate-calc",
     .handler = cmdDomDirtyRateCalc,
     .opts = opts_domdirtyrate_calc,
     .info = info_domdirtyrate_calc,
     .flags = 0
    },
    {.name = "dom-fd-associate",
     .handler = cmdDomFdAssociate,
     .opts = opts_dom_fd_associate,
     .info = info_dom_fd_associate,
     .flags = 0
    },
    {.name = NULL}
};
