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
 *
 *  Daniel Veillard <veillard@redhat.com>
 *  Karel Zak <kzak@redhat.com>
 *  Daniel P. Berrange <berrange@redhat.com>
 *
 */

#include <config.h>
#include "virsh-domain.h"
#include "virsh-util.h"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/time.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xmlsave.h>

#include "internal.h"
#include "virbitmap.h"
#include "virbuffer.h"
#include "c-ctype.h"
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
#include "virerror.h"
#include "virtime.h"
#include "virtypedparam.h"
#include "virxml.h"
#include "virsh-nodedev.h"
#include "viruri.h"

/* Gnulib doesn't guarantee SA_SIGINFO support.  */
#ifndef SA_SIGINFO
# define SA_SIGINFO 0
#endif

#define VIRSH_COMMON_OPT_DOMAIN_FULL                       \
    VIRSH_COMMON_OPT_DOMAIN(N_("domain name, id or uuid")) \

#define VIRSH_COMMON_OPT_DOMAIN_PERSISTENT             \
    {.name = "persistent",                             \
     .type = VSH_OT_BOOL,                              \
     .help = N_("make live change persistent")         \
    }                                                  \

#define VIRSH_COMMON_OPT_DOMAIN_CONFIG                 \
    VIRSH_COMMON_OPT_CONFIG(N_("affect next boot"))    \

#define VIRSH_COMMON_OPT_DOMAIN_LIVE                   \
    VIRSH_COMMON_OPT_LIVE(N_("affect running domain")) \

#define VIRSH_COMMON_OPT_DOMAIN_CURRENT                   \
    VIRSH_COMMON_OPT_CURRENT(N_("affect current domain")) \


static virDomainPtr
virshDomainDefine(virConnectPtr conn, const char *xml, unsigned int flags)
{
    virDomainPtr dom;
    if (flags) {
        dom = virDomainDefineXMLFlags(conn, xml, flags);
        /* If validate is the only flag, just drop it and
         * try again.
         */
        if (!dom) {
            virErrorPtr err = virGetLastError();
            if (err &&
                (err->code == VIR_ERR_NO_SUPPORT) &&
                (flags == VIR_DOMAIN_DEFINE_VALIDATE))
                dom = virDomainDefineXML(conn, xml);
        }
    } else {
        dom = virDomainDefineXML(conn, xml);
    }
    return dom;
}

VIR_ENUM_DECL(virshDomainVcpuState)
VIR_ENUM_IMPL(virshDomainVcpuState,
              VIR_VCPU_LAST,
              N_("offline"),
              N_("running"),
              N_("blocked"))

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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
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
    virDomainPtr dom;
    const char *from = NULL;
    char *buffer;
    int rv;
    bool ret = false;
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
        goto cleanup;

    if (persistent &&
        virDomainIsActive(dom) == 1)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0) {
        vshReportError(ctl);
        goto cleanup;
    }

    if (flags || current)
        rv = virDomainAttachDeviceFlags(dom, buffer, flags);
    else
        rv = virDomainAttachDevice(dom, buffer);

    VIR_FREE(buffer);

    if (rv < 0) {
        vshError(ctl, _("Failed to attach device from %s"), from);
        goto cleanup;
    }

    vshPrintExtra(ctl, "%s", _("Device attached successfully\n"));
    ret = true;

 cleanup:
    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "source",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ | VSH_OFLAG_EMPTY_OK,
     .help = N_("source of disk device")
    },
    {.name = "target",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
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
     .help = N_("type of source (block|file)")
    },
    {.name = "serial",
     .type = VSH_OT_STRING,
     .help = N_("serial of disk device")
    },
    {.name = "wwn",
     .type = VSH_OT_STRING,
     .help = N_("wwn of disk device")
    },
    {.name = "rawio",
     .type = VSH_OT_BOOL,
     .help = N_("needs rawio capability")
    },
    {.name = "address",
     .type = VSH_OT_STRING,
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
    VIRSH_COMMON_OPT_DOMAIN_PERSISTENT,
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = NULL}
};

enum {
    DISK_ADDR_TYPE_INVALID,
    DISK_ADDR_TYPE_PCI,
    DISK_ADDR_TYPE_SCSI,
    DISK_ADDR_TYPE_IDE,
    DISK_ADDR_TYPE_CCW,
};

struct PCIAddress {
    unsigned int domain;
    unsigned int bus;
    unsigned int slot;
    unsigned int function;
};

struct SCSIAddress {
    unsigned int controller;
    unsigned int bus;
    unsigned long long unit;
};

struct IDEAddress {
    unsigned int controller;
    unsigned int bus;
    unsigned int unit;
};

struct CCWAddress {
    unsigned int cssid;
    unsigned int ssid;
    unsigned int devno;
};

struct DiskAddress {
    int type;
    union {
        struct PCIAddress pci;
        struct SCSIAddress scsi;
        struct IDEAddress ide;
        struct CCWAddress ccw;
    } addr;
};

static int str2PCIAddress(const char *str, struct PCIAddress *pciAddr)
{
    char *domain, *bus, *slot, *function;

    if (!pciAddr)
        return -1;
    if (!str)
        return -1;

    domain = (char *)str;

    if (virStrToLong_uip(domain, &bus, 16, &pciAddr->domain) != 0)
        return -1;

    bus++;
    if (virStrToLong_uip(bus, &slot, 16, &pciAddr->bus) != 0)
        return -1;

    slot++;
    if (virStrToLong_uip(slot, &function, 16, &pciAddr->slot) != 0)
        return -1;

    function++;
    if (virStrToLong_uip(function, NULL, 16, &pciAddr->function) != 0)
        return -1;

    return 0;
}

static int str2SCSIAddress(const char *str, struct SCSIAddress *scsiAddr)
{
    char *controller, *bus, *unit;

    if (!scsiAddr)
        return -1;
    if (!str)
        return -1;

    controller = (char *)str;

    if (virStrToLong_uip(controller, &bus, 10, &scsiAddr->controller) != 0)
        return -1;

    bus++;
    if (virStrToLong_uip(bus, &unit, 10, &scsiAddr->bus) != 0)
        return -1;

    unit++;
    if (virStrToLong_ullp(unit, NULL, 10, &scsiAddr->unit) != 0)
        return -1;

    return 0;
}

static int str2IDEAddress(const char *str, struct IDEAddress *ideAddr)
{
    char *controller, *bus, *unit;

    if (!ideAddr)
        return -1;
    if (!str)
        return -1;

    controller = (char *)str;

    if (virStrToLong_uip(controller, &bus, 10, &ideAddr->controller) != 0)
        return -1;

    bus++;
    if (virStrToLong_uip(bus, &unit, 10, &ideAddr->bus) != 0)
        return -1;

    unit++;
    if (virStrToLong_uip(unit, NULL, 10, &ideAddr->unit) != 0)
        return -1;

    return 0;
}

static int str2CCWAddress(const char *str, struct CCWAddress *ccwAddr)
{
    char *cssid, *ssid, *devno;

    if (!ccwAddr)
        return -1;
    if (!str)
        return -1;

    cssid = (char *)str;

    if (virStrToLong_uip(cssid, &ssid, 16, &ccwAddr->cssid) != 0)
        return -1;

    ssid++;
    if (virStrToLong_uip(ssid, &devno, 16, &ccwAddr->ssid) != 0)
        return -1;

    devno++;
    if (virStrToLong_uip(devno, NULL, 16, &ccwAddr->devno) != 0)
        return -1;

    return 0;
}

/* pci address pci:0000.00.0x0a.0 (domain:bus:slot:function)
 * ide disk address: ide:00.00.0 (controller:bus:unit)
 * scsi disk address: scsi:00.00.0 (controller:bus:unit)
 * ccw disk address: ccw:0xfe.0.0000 (cssid:ssid:devno)
 */

static int str2DiskAddress(const char *str, struct DiskAddress *diskAddr)
{
    char *type, *addr;

    if (!diskAddr)
        return -1;
    if (!str)
        return -1;

    type = (char *)str;
    addr = strchr(type, ':');
    if (!addr)
        return -1;

    if (STREQLEN(type, "pci", addr - type)) {
        diskAddr->type = DISK_ADDR_TYPE_PCI;
        return str2PCIAddress(addr + 1, &diskAddr->addr.pci);
    } else if (STREQLEN(type, "scsi", addr - type)) {
        diskAddr->type = DISK_ADDR_TYPE_SCSI;
        return str2SCSIAddress(addr + 1, &diskAddr->addr.scsi);
    } else if (STREQLEN(type, "ide", addr - type)) {
        diskAddr->type = DISK_ADDR_TYPE_IDE;
        return str2IDEAddress(addr + 1, &diskAddr->addr.ide);
    } else if (STREQLEN(type, "ccw", addr - type)) {
        diskAddr->type = DISK_ADDR_TYPE_CCW;
        return str2CCWAddress(addr + 1, &diskAddr->addr.ccw);
    }

    return -1;
}

static bool
cmdAttachDisk(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    const char *source = NULL, *target = NULL, *driver = NULL,
                *subdriver = NULL, *type = NULL, *mode = NULL,
                *iothread = NULL, *cache = NULL, *io = NULL,
                *serial = NULL, *straddr = NULL, *wwn = NULL,
                *targetbus = NULL;
    struct DiskAddress diskAddr;
    bool isFile = false, functionReturn = false;
    int ret;
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;
    const char *stype = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *xml = NULL;
    struct stat st;
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

    if (vshCommandOptStringReq(ctl, cmd, "source", &source) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "target", &target) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "driver", &driver) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "subdriver", &subdriver) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "type", &type) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "mode", &mode) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "iothread", &iothread) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "cache", &cache) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "io", &io) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "serial", &serial) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "wwn", &wwn) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "address", &straddr) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "targetbus", &targetbus) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "sourcetype", &stype) < 0)
        goto cleanup;

    if (!stype) {
        if (driver && (STREQ(driver, "file") || STREQ(driver, "tap"))) {
            isFile = true;
        } else {
            if (source && !stat(source, &st))
                isFile = S_ISREG(st.st_mode) ? true : false;
        }
    } else if (STREQ(stype, "file")) {
        isFile = true;
    } else if (STRNEQ(stype, "block")) {
        vshError(ctl, _("Unknown source type: '%s'"), stype);
        goto cleanup;
    }

    if (mode) {
        if (STRNEQ(mode, "readonly") && STRNEQ(mode, "shareable")) {
            vshError(ctl, _("No support for %s in command 'attach-disk'"),
                     mode);
            goto cleanup;
        }
    }

    if (wwn && !virValidateWWN(wwn))
        goto cleanup;

    /* Make XML of disk */
    virBufferAsprintf(&buf, "<disk type='%s'",
                      isFile ? "file" : "block");
    if (type)
        virBufferAsprintf(&buf, " device='%s'", type);
    if (vshCommandOptBool(cmd, "rawio"))
        virBufferAddLit(&buf, " rawio='yes'");
    virBufferAddLit(&buf, ">\n");
    virBufferAdjustIndent(&buf, 2);

    if (driver || subdriver || iothread || cache || io) {
        virBufferAddLit(&buf, "<driver");

        if (driver)
            virBufferAsprintf(&buf, " name='%s'", driver);
        if (subdriver)
            virBufferAsprintf(&buf, " type='%s'", subdriver);
        if (iothread)
            virBufferAsprintf(&buf, " iothread='%s'", iothread);
        if (cache)
            virBufferAsprintf(&buf, " cache='%s'", cache);
        if (io)
            virBufferAsprintf(&buf, " io='%s'", io);

        virBufferAddLit(&buf, "/>\n");
    }

    if (source)
        virBufferAsprintf(&buf, "<source %s='%s'/>\n",
                          isFile ? "file" : "dev", source);
    virBufferAsprintf(&buf, "<target dev='%s'", target);
    if (targetbus)
        virBufferAsprintf(&buf, " bus='%s'", targetbus);
    virBufferAddLit(&buf, "/>\n");

    if (mode)
        virBufferAsprintf(&buf, "<%s/>\n", mode);

    if (serial)
        virBufferAsprintf(&buf, "<serial>%s</serial>\n", serial);

    if (wwn)
        virBufferAsprintf(&buf, "<wwn>%s</wwn>\n", wwn);

    if (straddr) {
        if (str2DiskAddress(straddr, &diskAddr) != 0) {
            vshError(ctl, _("Invalid address."));
            goto cleanup;
        }

        if (STRPREFIX((const char *)target, "vd")) {
            if (diskAddr.type == DISK_ADDR_TYPE_PCI) {
                virBufferAsprintf(&buf,
                                  "<address type='pci' domain='0x%04x'"
                                  " bus ='0x%02x' slot='0x%02x' function='0x%0x'",
                                  diskAddr.addr.pci.domain, diskAddr.addr.pci.bus,
                                  diskAddr.addr.pci.slot, diskAddr.addr.pci.function);
                if (vshCommandOptBool(cmd, "multifunction"))
                    virBufferAddLit(&buf, " multifunction='on'");
                virBufferAddLit(&buf, "/>\n");
            } else if (diskAddr.type == DISK_ADDR_TYPE_CCW) {
                virBufferAsprintf(&buf,
                                  "<address type='ccw' cssid='0x%02x'"
                                  " ssid='0x%01x' devno='0x%04x' />\n",
                                  diskAddr.addr.ccw.cssid, diskAddr.addr.ccw.ssid,
                                  diskAddr.addr.ccw.devno);
            } else {
                vshError(ctl, "%s",
                         _("expecting a pci:0000.00.00.00 or ccw:00.0.0000 address."));
                goto cleanup;
            }
        } else if (STRPREFIX((const char *)target, "sd")) {
            if (diskAddr.type == DISK_ADDR_TYPE_SCSI) {
                virBufferAsprintf(&buf,
                                  "<address type='drive' controller='%u'"
                                  " bus='%u' unit='%llu' />\n",
                                  diskAddr.addr.scsi.controller, diskAddr.addr.scsi.bus,
                                  diskAddr.addr.scsi.unit);
            } else {
                vshError(ctl, "%s", _("expecting a scsi:00.00.00 address."));
                goto cleanup;
            }
        } else if (STRPREFIX((const char *)target, "hd")) {
            if (diskAddr.type == DISK_ADDR_TYPE_IDE) {
                virBufferAsprintf(&buf,
                                  "<address type='drive' controller='%u'"
                                  " bus='%u' unit='%u' />\n",
                                  diskAddr.addr.ide.controller, diskAddr.addr.ide.bus,
                                  diskAddr.addr.ide.unit);
            } else {
                vshError(ctl, "%s", _("expecting an ide:00.00.00 address."));
                goto cleanup;
            }
        }
    }

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</disk>\n");

    if (virBufferError(&buf)) {
        vshError(ctl, "%s", _("Failed to allocate XML buffer"));
        goto cleanup;
    }

    xml = virBufferContentAndReset(&buf);

    if (vshCommandOptBool(cmd, "print-xml")) {
        vshPrint(ctl, "%s", xml);
        functionReturn = true;
        goto cleanup;
    }

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        goto cleanup;

    if (persistent &&
        virDomainIsActive(dom) == 1)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (flags || current)
        ret = virDomainAttachDeviceFlags(dom, xml, flags);
    else
        ret = virDomainAttachDevice(dom, xml);

    if (ret != 0) {
        vshError(ctl, "%s", _("Failed to attach disk"));
    } else {
        vshPrintExtra(ctl, "%s", _("Disk attached successfully\n"));
        functionReturn = true;
    }

 cleanup:
    VIR_FREE(xml);
    virshDomainFree(dom);
    virBufferFreeAndReset(&buf);
    return functionReturn;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
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
     .help = N_("target network name")
    },
    {.name = "mac",
     .type = VSH_OT_STRING,
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
    {.name = "inbound",
     .type = VSH_OT_STRING,
     .help = N_("control domain's incoming traffics")
    },
    {.name = "outbound",
     .type = VSH_OT_STRING,
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
    {.name = NULL}
};

/* parse inbound and outbound which are in the format of
 * 'average,peak,burst,floor', in which peak and burst are optional,
 * thus 'average,,burst' and 'average,peak' are also legal. */

#define VIRSH_PARSE_RATE_FIELD(index, name)                                      \
    do {                                                                       \
        if (index < ntok &&                                                    \
            *tok[index] != '\0' &&                                             \
            virStrToLong_ullp(tok[index], NULL, 10, &rate->name) < 0) {        \
            vshError(ctl, _("field '%s' is malformed"), #name);                \
            goto cleanup;                                                      \
        }                                                                      \
    } while (0)

static int
virshParseRateStr(vshControl *ctl,
                  const char *rateStr,
                  virNetDevBandwidthRatePtr rate)
{
    char **tok = NULL;
    size_t ntok;
    int ret = -1;

    if (!(tok = virStringSplitCount(rateStr, ",", 0, &ntok)))
        return -1;

    if (ntok > 4) {
        vshError(ctl, _("Rate string '%s' has too many fields"), rateStr);
        goto cleanup;
    }

    VIRSH_PARSE_RATE_FIELD(0, average);
    VIRSH_PARSE_RATE_FIELD(1, peak);
    VIRSH_PARSE_RATE_FIELD(2, burst);
    VIRSH_PARSE_RATE_FIELD(3, floor);

    ret = 0;
 cleanup:
    virStringListFree(tok);
    return ret;
}

#undef VIRSH_PARSE_RATE_FIELD

static bool
cmdAttachInterface(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    const char *mac = NULL, *target = NULL, *script = NULL,
               *type = NULL, *source = NULL, *model = NULL,
               *inboundStr = NULL, *outboundStr = NULL;
    virNetDevBandwidthRate inbound, outbound;
    virDomainNetType typ;
    int ret;
    bool functionReturn = false;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *xml = NULL;
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
        vshCommandOptStringReq(ctl, cmd, "inbound", &inboundStr) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "outbound", &outboundStr) < 0)
        goto cleanup;

    /* check interface type */
    if ((int)(typ = virDomainNetTypeFromString(type)) < 0) {
        vshError(ctl, _("No support for %s in command 'attach-interface'"),
                 type);
        goto cleanup;
    }

    if (inboundStr) {
        memset(&inbound, 0, sizeof(inbound));
        if (virshParseRateStr(ctl, inboundStr, &inbound) < 0)
            goto cleanup;
        if (!inbound.average && !inbound.floor) {
            vshError(ctl, _("either inbound average or floor is mandatory"));
            goto cleanup;
        }
    }
    if (outboundStr) {
        memset(&outbound, 0, sizeof(outbound));
        if (virshParseRateStr(ctl, outboundStr, &outbound) < 0)
            goto cleanup;
        if (outbound.average == 0) {
            vshError(ctl, _("outbound average is mandatory"));
            goto cleanup;
        }
        if (outbound.floor) {
            vshError(ctl, _("outbound floor is unsupported yet"));
            goto cleanup;
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
        struct PCIAddress pciAddr = {0, 0, 0, 0};

        if (str2PCIAddress(source, &pciAddr) < 0) {
            vshError(ctl, _("cannot parse pci address '%s' for network "
                            "interface"), source);
            goto cleanup;
        }

        virBufferAddLit(&buf, "<source>\n");
        virBufferAdjustIndent(&buf, 2);
        virBufferAsprintf(&buf, "<address type='pci' domain='0x%.4x'"
                          " bus='0x%.2x' slot='0x%.2x' function='0x%.1x'/>\n",
                          pciAddr.domain, pciAddr.bus,
                          pciAddr.slot, pciAddr.function);
        virBufferAdjustIndent(&buf, -2);
        virBufferAddLit(&buf, "</source>\n");
        break;
    }

    case VIR_DOMAIN_NET_TYPE_USER:
    case VIR_DOMAIN_NET_TYPE_ETHERNET:
    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_UDP:
    case VIR_DOMAIN_NET_TYPE_INTERNAL:
    case VIR_DOMAIN_NET_TYPE_LAST:
        vshError(ctl, _("No support for %s in command 'attach-interface'"),
                 type);
        goto cleanup;
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

    if (virBufferError(&buf)) {
        vshError(ctl, "%s", _("Failed to allocate XML buffer"));
        goto cleanup;
    }

    xml = virBufferContentAndReset(&buf);

    if (vshCommandOptBool(cmd, "print-xml")) {
        vshPrint(ctl, "%s", xml);
        functionReturn = true;
        goto cleanup;
    }

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        goto cleanup;

    if (persistent &&
        virDomainIsActive(dom) == 1)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (flags || current)
        ret = virDomainAttachDeviceFlags(dom, xml, flags);
    else
        ret = virDomainAttachDevice(dom, xml);

    if (ret != 0) {
        vshError(ctl, "%s", _("Failed to attach interface"));
    } else {
        vshPrintExtra(ctl, "%s", _("Interface attached successfully\n"));
        functionReturn = true;
    }

 cleanup:
    VIR_FREE(xml);
    virshDomainFree(dom);
    virBufferFreeAndReset(&buf);
    return functionReturn;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "disable",
     .type = VSH_OT_BOOL,
     .help = N_("disable autostarting")
    },
    {.name = NULL}
};

static bool
cmdAutostart(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *name;
    int autostart;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    autostart = !vshCommandOptBool(cmd, "disable");

    if (virDomainSetAutostart(dom, autostart) < 0) {
        if (autostart)
            vshError(ctl, _("Failed to mark domain %s as autostarted"), name);
        else
            vshError(ctl, _("Failed to unmark domain %s as autostarted"), name);
        virshDomainFree(dom);
        return false;
    }

    if (autostart)
        vshPrintExtra(ctl, _("Domain %s marked as autostarted\n"), name);
    else
        vshPrintExtra(ctl, _("Domain %s unmarked as autostarted\n"), name);

    virshDomainFree(dom);
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "device",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
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
    virDomainPtr dom = NULL;
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

#define VSH_ADD_IOTUNE_SCALED(PARAM, CONST)                                    \
    if ((rv = vshCommandOptScaledInt(ctl, cmd, #PARAM, &value,                 \
                                     1, ULLONG_MAX)) < 0) {                    \
        goto interror;                                                         \
    } else if (rv > 0) {                                                       \
        if (virTypedParamsAddULLong(&params, &nparams, &maxparams,             \
                                    VIR_DOMAIN_BLOCK_IOTUNE_##CONST,           \
                                    value) < 0)                                \
            goto save_error;                                                   \
    }                                                                          \

    VSH_ADD_IOTUNE_SCALED(total-bytes-sec, TOTAL_BYTES_SEC);
    VSH_ADD_IOTUNE_SCALED(read-bytes-sec, READ_BYTES_SEC);
    VSH_ADD_IOTUNE_SCALED(write-bytes-sec, WRITE_BYTES_SEC);
    VSH_ADD_IOTUNE_SCALED(total-bytes-sec-max, TOTAL_BYTES_SEC_MAX);
    VSH_ADD_IOTUNE_SCALED(read-bytes-sec-max, READ_BYTES_SEC_MAX);
    VSH_ADD_IOTUNE_SCALED(write-bytes-sec-max, WRITE_BYTES_SEC_MAX);
#undef VSH_ADD_IOTUNE_SCALED

#define VSH_ADD_IOTUNE(PARAM, CONST)                                           \
    if ((rv = vshCommandOptULongLong(ctl, cmd, #PARAM, &value)) < 0) {         \
        goto interror;                                                         \
    } else if (rv > 0) {                                                       \
        if (virTypedParamsAddULLong(&params, &nparams, &maxparams,             \
                                    VIR_DOMAIN_BLOCK_IOTUNE_##CONST,           \
                                    value) < 0)                                \
            goto save_error;                                                   \
    }                                                                          \

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

        params = vshCalloc(ctl, nparams, sizeof(*params));

        if (virDomainGetBlockIoTune(dom, disk, params, &nparams, flags) != 0) {
            vshError(ctl, "%s",
                     _("Unable to get block I/O throttle parameters"));
            goto cleanup;
        }

        for (i = 0; i < nparams; i++) {
            char *str = vshGetTypedParamValue(ctl, &params[i]);
            vshPrint(ctl, "%-15s: %s\n", params[i].field, str);
            VIR_FREE(str);
        }
    } else {
        if (virDomainSetBlockIoTune(dom, disk, params, nparams, flags) < 0)
            goto error;
    }

    ret = true;

 cleanup:
    virTypedParamsFree(params, nparams);
    virshDomainFree(dom);
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "weight",
     .type = VSH_OT_INT,
     .help = N_("IO Weight")
    },
    {.name = "device-weights",
     .type = VSH_OT_STRING,
     .help = N_("per-device IO Weights, in the form of /path/to/device,weight,...")
    },
    {.name = "device-read-iops-sec",
     .type = VSH_OT_STRING,
     .help = N_("per-device read I/O limit per second, in the form of /path/to/device,read_iops_sec,...")
    },
    {.name = "device-write-iops-sec",
     .type = VSH_OT_STRING,
     .help = N_("per-device write I/O limit per second, in the form of /path/to/device,write_iops_sec,...")
    },
    {.name = "device-read-bytes-sec",
     .type = VSH_OT_STRING,
     .help = N_("per-device bytes read per second, in the form of /path/to/device,read_bytes_sec,...")
    },
    {.name = "device-write-bytes-sec",
     .type = VSH_OT_STRING,
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
    virDomainPtr dom;
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
            vshError(ctl, _("Invalid value of %d for I/O weight"), weight);
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
        params = vshCalloc(ctl, nparams, sizeof(*params));
        if (virDomainGetBlkioParameters(dom, params, &nparams, flags) != 0) {
            vshError(ctl, "%s", _("Unable to get blkio parameters"));
            goto cleanup;
        }

        for (i = 0; i < nparams; i++) {
            char *str = vshGetTypedParamValue(ctl, &params[i]);
            vshPrint(ctl, "%-15s: %s\n", params[i].field, str);
            VIR_FREE(str);
        }
    } else {
        /* set the blkio parameters */
        if (virDomainSetBlkioParameters(dom, params, nparams, flags) < 0)
            goto error;
    }

    ret = true;

 cleanup:
    virTypedParamsFree(params, nparams);
    virshDomainFree(dom);
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
    int progress;

    if (remaining == 0) {
        /* migration has completed */
        progress = 100;
    } else {
        /* use float to avoid overflow */
        progress = (int)(100.0 - remaining * 100.0 / total);
        if (progress >= 100) {
            /* migration has not completed, do not print [100 %] */
            progress = 99;
        }
    }

    /* see comments in vshError about why we must flush */
    fflush(stdout);
    fprintf(stderr, "\r%s: [%3d %%]", label, progress);
    fflush(stderr);
}

static volatile sig_atomic_t intCaught;

static void virshCatchInt(int sig ATTRIBUTE_UNUSED,
                          siginfo_t *siginfo ATTRIBUTE_UNUSED,
                          void *context ATTRIBUTE_UNUSED)
{
    intCaught = 1;
}


typedef struct _virshBlockJobWaitData virshBlockJobWaitData;
typedef virshBlockJobWaitData *virshBlockJobWaitDataPtr;
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
virshBlockJobStatusHandler(virConnectPtr conn ATTRIBUTE_UNUSED,
                           virDomainPtr dom ATTRIBUTE_UNUSED,
                           const char *disk,
                           int type ATTRIBUTE_UNUSED,
                           int status,
                           void *opaque)
{
    virshBlockJobWaitDataPtr data = opaque;

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
static virshBlockJobWaitDataPtr
virshBlockJobWaitInit(vshControl *ctl,
                      virDomainPtr dom,
                      const char *dev,
                      const char *job_name,
                      bool verbose,
                      unsigned int timeout,
                      bool async_abort)
{
    virshBlockJobWaitDataPtr ret;
    virshControlPtr priv = ctl->privData;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    ret->ctl = ctl;
    ret->dom = dom;
    ret->dev = dev;
    ret->job_name = job_name;

    ret->async_abort = async_abort;
    ret->timeout = timeout;
    ret->verbose = verbose;

    ret->status = -1;

    virConnectDomainEventGenericCallback cb =
        VIR_DOMAIN_EVENT_CALLBACK(virshBlockJobStatusHandler);

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
virshBlockJobWaitFree(virshBlockJobWaitDataPtr data)
{
    virshControlPtr priv = NULL;

    if (!data)
        return;

    priv = data->ctl->privData;
    if (data->cb_id >= 0)
        virConnectDomainEventDeregisterAny(priv->conn, data->cb_id);
    if (data->cb_id2 >= 0)
        virConnectDomainEventDeregisterAny(priv->conn, data->cb_id2);

    VIR_FREE(data);
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
virshBlockJobWait(virshBlockJobWaitDataPtr data)
{
    /* For two phase jobs like active commit or block copy, the marker reaches
     * 100% and an event fires. In case where virsh would not be able to match
     * the event to the given block job we will wait for the number of retries
     * before claiming that we entered synchronised phase */
    unsigned int retries = 5;

    struct sigaction sig_action;
    struct sigaction old_sig_action;
    sigset_t sigmask, oldsigmask;

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

    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);

    intCaught = 0;
    sig_action.sa_sigaction = virshCatchInt;
    sig_action.sa_flags = SA_SIGINFO;
    sigemptyset(&sig_action.sa_mask);
    sigaction(SIGINT, &sig_action, &old_sig_action);

    if (data->timeout && virTimeMillisNow(&start) < 0) {
        vshSaveLibvirtError();
        goto cleanup;
    }

    last.cur = last.end = 0;

    while (true) {
        pthread_sigmask(SIG_BLOCK, &sigmask, &oldsigmask);
        result = virDomainGetBlockJobInfo(data->dom, data->dev, &info, 0);
        pthread_sigmask(SIG_SETMASK, &oldsigmask, NULL);

        if (result < 0) {
            vshError(data->ctl, _("failed to query job for disk %s"), data->dev);
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
                vshError(data->ctl, _("failed to abort job for disk '%s'"),
                         data->dev);
                goto cleanup;
            }

            ret = VIR_DOMAIN_BLOCK_JOB_CANCELED;
            break;
        }

        usleep(500 * 1000);
    }

    /* print 100% completed */
    if (data->verbose &&
        (ret == VIR_DOMAIN_BLOCK_JOB_COMPLETED ||
         ret == VIR_DOMAIN_BLOCK_JOB_READY))
        virshPrintJobProgress(data->job_name, 0, 1);

 cleanup:
    sigaction(SIGINT, &old_sig_action, NULL);
    return ret;
}


/*
 * "blockcommit" command
 */
static const vshCmdInfo info_block_commit[] = {
    {.name = "help",
     .data = N_("Start a block commit operation.")
    },
    {.name = "desc",
     .data = N_("Commit changes from a snapshot down to its backing image.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_block_commit[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "path",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("fully-qualified path of disk")
    },
    {.name = "bandwidth",
     .type = VSH_OT_INT,
     .help = N_("bandwidth limit in MiB/s")
    },
    {.name = "base",
     .type = VSH_OT_STRING,
     .help = N_("path of base file to commit into (default bottom of chain)")
    },
    {.name = "shallow",
     .type = VSH_OT_BOOL,
     .help = N_("use backing file of top as base")
    },
    {.name = "top",
     .type = VSH_OT_STRING,
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
cmdBlockCommit(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
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
    virshBlockJobWaitDataPtr bjWait = NULL;

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
            vshError(ctl, "%s", _("--verbose requires at least one of --timeout, "
                                  "--wait, --pivot, or --keep-overlay"));
            return false;
        }

        if (async) {
            vshError(ctl, "%s", _("--async requires at least one of --timeout, "
                                  "--wait, --pivot, or --keep-overlay"));
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
            vshError(ctl, "\n%s", _("Commit failed"));
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
                vshError(ctl, _("failed to pivot job for disk %s"), path);
                goto cleanup;
            }

            vshPrintExtra(ctl, "\n%s", _("Successfully pivoted"));
        } else if (finish) {
            if (virDomainBlockJobAbort(dom, path, abort_flags) < 0) {
                vshError(ctl, _("failed to finish job for disk %s"), path);
                goto cleanup;
            }

            vshPrintExtra(ctl, "\n%s", _("Commit complete, overlay "
                                         "image kept"));
        } else {
            vshPrintExtra(ctl, "\n%s", _("Now in synchronized phase"));
        }
    } else {
        vshPrintExtra(ctl, "\n%s", _("Commit complete"));
    }

    ret = true;
 cleanup:
    virshDomainFree(dom);
    virshBlockJobWaitFree(bjWait);
    return ret;
}

/*
 * "blockcopy" command
 */
static const vshCmdInfo info_block_copy[] = {
    {.name = "help",
     .data = N_("Start a block copy operation.")
    },
    {.name = "desc",
     .data = N_("Copy a disk backing image chain to dest.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_block_copy[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "path",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
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
     .help = N_("filename containing XML description of the copy destination")
    },
    {.name = "format",
     .type = VSH_OT_STRING,
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
    {.name = NULL}
};

static bool
cmdBlockCopy(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
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
    int timeout = 0;
    const char *path = NULL;
    int abort_flags = 0;
    const char *xml = NULL;
    char *xmlstr = NULL;
    virTypedParameterPtr params = NULL;
    virshBlockJobWaitDataPtr bjWait = NULL;
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
            vshError(ctl, "%s", _("--verbose requires at least one of --timeout, "
                                  "--wait, --pivot, or --finish"));
            return false;
        }

        if (async) {
            vshError(ctl, "%s", _("--async requires at least one of --timeout, "
                                  "--wait, --pivot, or --finish"));
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
        transientjob) {
        /* New API */
        if (bandwidth || granularity || buf_size) {
            params = vshCalloc(ctl, 3, sizeof(*params));
            if (bandwidth) {
                if (!bytes) {
                    /* bandwidth is ulong MiB/s, but the typed parameter is
                     * ullong bytes/s; make sure we don't overflow */
                    unsigned long long limit = MIN(ULONG_MAX, ULLONG_MAX >> 20);
                    if (bandwidth > limit) {
                        vshError(ctl, _("bandwidth must be less than %llu"), limit);
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
            virBuffer buf = VIR_BUFFER_INITIALIZER;
            virBufferAsprintf(&buf, "<disk type='%s'>\n",
                              blockdev ? "block" : "file");
            virBufferAdjustIndent(&buf, 2);
            virBufferAsprintf(&buf, "<source %s", blockdev ? "dev" : "file");
            virBufferEscapeString(&buf, "='%s'/>\n", dest);
            virBufferEscapeString(&buf, "<driver type='%s'/>\n", format);
            virBufferAdjustIndent(&buf, -2);
            virBufferAddLit(&buf, "</disk>\n");
            if (virBufferCheckError(&buf) < 0)
                goto cleanup;
            xmlstr = virBufferContentAndReset(&buf);
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
            vshError(ctl, "\n%s", _("Copy failed"));
            goto cleanup;
            break;

        case VIR_DOMAIN_BLOCK_JOB_READY:
        case VIR_DOMAIN_BLOCK_JOB_COMPLETED:
            break;
    }

    if (pivot) {
        abort_flags |= VIR_DOMAIN_BLOCK_JOB_ABORT_PIVOT;
        if (virDomainBlockJobAbort(dom, path, abort_flags) < 0) {
            vshError(ctl, _("failed to pivot job for disk %s"), path);
            goto cleanup;
        }

        vshPrintExtra(ctl, "\n%s", _("Successfully pivoted"));
    } else if (finish) {
        if (virDomainBlockJobAbort(dom, path, abort_flags) < 0) {
            vshError(ctl, _("failed to finish job for disk %s"), path);
            goto cleanup;
        }

        vshPrintExtra(ctl, "\n%s", _("Successfully copied"));
    } else {
        vshPrintExtra(ctl, "\n%s", _("Now in mirroring phase"));
    }

    ret = true;

 cleanup:
    VIR_FREE(xmlstr);
    virTypedParamsFree(params, nparams);
    virshDomainFree(dom);
    virshBlockJobWaitFree(bjWait);
    return ret;
}

/*
 * "blockjob" command
 */
static const vshCmdInfo info_block_job[] = {
    {.name = "help",
     .data = N_("Manage active block operations")
    },
    {.name = "desc",
     .data = N_("Query, adjust speed, or cancel active block operations.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_block_job[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "path",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
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

VIR_ENUM_DECL(virshDomainBlockJob)
VIR_ENUM_IMPL(virshDomainBlockJob,
              VIR_DOMAIN_BLOCK_JOB_TYPE_LAST,
              N_("Unknown job"),
              N_("Block Pull"),
              N_("Block Copy"),
              N_("Block Commit"),
              N_("Active Block Commit"))

static const char *
virshDomainBlockJobToString(int type)
{
    const char *str = virshDomainBlockJobTypeToString(type);
    return str ? _(str) : _("Unknown job");
}


static bool
virshBlockJobInfo(vshControl *ctl,
                  virDomainPtr dom,
                  const char *path,
                  bool raw,
                  bool bytes)
{
    virDomainBlockJobInfo info;
    virshControlPtr priv = ctl->privData;
    unsigned long long speed;
    unsigned int flags = 0;
    bool ret = false;
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
                /* fallthrough */
            case VIR_ERR_OVERFLOW:
                if (!bytes && !raw) {
                    /* try again with MiB/s, unless forcing bytes */
                    vshResetLibvirtError();
                    break;
                }
                /* fallthrough */
            default:
                goto cleanup;
            }
        }
        speed = info.bandwidth;
    }
    /* If we don't already have a query result, query for MiB/s */
    if (rc < 0) {
        flags &= ~VIR_DOMAIN_BLOCK_JOB_INFO_BANDWIDTH_BYTES;
        if ((rc = virDomainGetBlockJobInfo(dom, path, &info, flags)) < 0)
            goto cleanup;
        speed = info.bandwidth;
        /* Scale to bytes/s unless in raw mode */
        if (!raw) {
            speed <<= 20;
            if (speed >> 20 != info.bandwidth) {
                vshError(ctl, _("overflow in converting %ld MiB/s to bytes\n"),
                         info.bandwidth);
                goto cleanup;
            }
        }
    }

    if (rc == 0) {
        if (!raw)
            vshPrintExtra(ctl, _("No current block job for %s"), path);
        ret = true;
        goto cleanup;
    }

    if (raw) {
        vshPrint(ctl, _(" type=%s\n bandwidth=%lu\n cur=%llu\n end=%llu\n"),
                 virshDomainBlockJobTypeToString(info.type),
                 info.bandwidth, info.cur, info.end);
    } else {
        virshPrintJobProgress(virshDomainBlockJobToString(info.type),
                              info.end - info.cur, info.end);
        if (speed) {
            const char *unit;
            double val = vshPrettyCapacity(speed, &unit);
            vshPrint(ctl, _("    Bandwidth limit: %llu bytes/s (%-.3lf %s/s)"),
                     speed, val, unit);
        }
        vshPrint(ctl, "\n");
    }

    ret = true;

 cleanup:
    return ret;
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
cmdBlockJob(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    bool raw = vshCommandOptBool(cmd, "raw");
    bool bytes = vshCommandOptBool(cmd, "bytes");
    bool abortMode = vshCommandOptBool(cmd, "abort");
    bool pivot = vshCommandOptBool(cmd, "pivot");
    bool async = vshCommandOptBool(cmd, "async");
    bool info = vshCommandOptBool(cmd, "info");
    bool bandwidth = vshCommandOptBool(cmd, "bandwidth");
    virDomainPtr dom = NULL;
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
        goto cleanup;

    /* XXX Allow path to be optional to list info on all devices at once */
    if (vshCommandOptStringReq(ctl, cmd, "path", &path) < 0)
        goto cleanup;

    if (bandwidth)
        ret = virshBlockJobSetSpeed(ctl, cmd, dom, path, bytes);
    else if (abortMode || pivot || async)
        ret = virshBlockJobAbort(dom, path, pivot, async);
    else
        ret = virshBlockJobInfo(ctl, dom, path, raw, bytes);

 cleanup:
    virshDomainFree(dom);
    return ret;
}

/*
 * "blockpull" command
 */
static const vshCmdInfo info_block_pull[] = {
    {.name = "help",
     .data = N_("Populate a disk from its backing image.")
    },
    {.name = "desc",
     .data = N_("Populate a disk from its backing image.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_block_pull[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "path",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("fully-qualified path of disk")
    },
    {.name = "bandwidth",
     .type = VSH_OT_INT,
     .help = N_("bandwidth limit in MiB/s")
    },
    {.name = "base",
     .type = VSH_OT_STRING,
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
cmdBlockPull(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
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
    virshBlockJobWaitDataPtr bjWait = NULL;

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
            vshError(ctl, "\n%s", _("Pull failed"));
            goto cleanup;
            break;

        case VIR_DOMAIN_BLOCK_JOB_READY:
        case VIR_DOMAIN_BLOCK_JOB_COMPLETED:
            vshPrintExtra(ctl, "\n%s", _("Pull complete"));
            break;
    }

    ret = true;

 cleanup:
    virshDomainFree(dom);
    virshBlockJobWaitFree(bjWait);
    return ret;
}

/*
 * "blockresize" command
 */
static const vshCmdInfo info_block_resize[] = {
    {.name = "help",
     .data = N_("Resize block device of domain.")
    },
    {.name = "desc",
     .data = N_("Resize block device of domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_block_resize[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "path",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
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
cmdBlockResize(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *path = NULL;
    unsigned long long size = 0;
    unsigned int flags = 0;
    bool ret = false;

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
        vshError(ctl, _("Failed to resize block device '%s'"), path);
    } else {
        vshPrintExtra(ctl, _("Block device '%s' is resized"), path);
        ret = true;
    }

    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "devname", /* sc_prohibit_devname */
     .type = VSH_OT_STRING,
     .help = N_("character device name")
    },
    {.name = "force",
     .type = VSH_OT_BOOL,
     .help =  N_("force console connection (disconnect already connected sessions)")
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
              unsigned int flags)
{
    bool ret = false;
    int state;
    virshControlPtr priv = ctl->privData;

    if ((state = virshDomainState(ctl, dom, NULL)) < 0) {
        vshError(ctl, "%s", _("Unable to get domain status"));
        goto cleanup;
    }

    if (state == VIR_DOMAIN_SHUTOFF) {
        vshError(ctl, "%s", _("The domain is not running"));
        goto cleanup;
    }

    if (!isatty(STDIN_FILENO)) {
        vshError(ctl, "%s", _("Cannot run interactive console without a controlling TTY"));
        goto cleanup;
    }

    vshPrintExtra(ctl, _("Connected to domain %s\n"), virDomainGetName(dom));
    vshPrintExtra(ctl, _("Escape character is %s\n"), priv->escapeChar);
    fflush(stdout);
    if (virshRunConsole(ctl, dom, name, flags) == 0)
        ret = true;

 cleanup:

    return ret;
}

static bool
cmdConsole(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = false;
    bool force = vshCommandOptBool(cmd, "force");
    bool safe = vshCommandOptBool(cmd, "safe");
    unsigned int flags = 0;
    const char *name = NULL;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "devname", &name) < 0) /* sc_prohibit_devname */
        goto cleanup;

    if (force)
        flags |= VIR_DOMAIN_CONSOLE_FORCE;
    if (safe)
        flags |= VIR_DOMAIN_CONSOLE_SAFE;

    ret = cmdRunConsole(ctl, dom, name, flags);

 cleanup:
    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "interface",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("interface device (MAC Address)")
    },
    {.name = "state",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("new state of the device")
    },
    {.name = "persistent",
     .type = VSH_OT_ALIAS,
     .help = "config"
    },
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    {.name = NULL}
};

static bool
cmdDomIfSetLink(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *iface;
    const char *state;
    char *value;
    virMacAddr macaddr;
    const char *element;
    const char *attr;
    bool config;
    bool ret = false;
    unsigned int flags = 0;
    unsigned int xmlflags = 0;
    size_t i;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlXPathObjectPtr obj = NULL;
    xmlNodePtr cur = NULL;
    char *xml_buf = NULL;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "interface", &iface) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "state", &state) < 0)
        goto cleanup;

    config = vshCommandOptBool(cmd, "config");

    if (STRNEQ(state, "up") && STRNEQ(state, "down")) {
        vshError(ctl, _("invalid link state '%s'"), state);
        goto cleanup;
    }

    if (config) {
        flags = VIR_DOMAIN_AFFECT_CONFIG;
        xmlflags |= VIR_DOMAIN_XML_INACTIVE;
    } else {
        flags = VIR_DOMAIN_AFFECT_LIVE;
    }

    if (virDomainIsActive(dom) == 0)
        flags = VIR_DOMAIN_AFFECT_CONFIG;

    if (virshDomainGetXMLFromDom(ctl, dom, xmlflags, &xml, &ctxt) < 0)
        goto cleanup;

    obj = xmlXPathEval(BAD_CAST "/domain/devices/interface", ctxt);
    if (obj == NULL || obj->type != XPATH_NODESET ||
        obj->nodesetval == NULL || obj->nodesetval->nodeNr == 0) {
        vshError(ctl, _("Failed to extract interface information or no interfaces found"));
        goto cleanup;
    }

    if (virMacAddrParse(iface, &macaddr) == 0) {
        element = "mac";
        attr = "address";
    } else {
        element = "target";
        attr = "dev";
    }

    /* find interface with matching mac addr */
    for (i = 0; i < obj->nodesetval->nodeNr; i++) {
        cur = obj->nodesetval->nodeTab[i]->children;

        while (cur) {
            if (cur->type == XML_ELEMENT_NODE &&
                xmlStrEqual(cur->name, BAD_CAST element)) {
                value = virXMLPropString(cur, attr);

                if (STRCASEEQ(value, iface)) {
                    VIR_FREE(value);
                    goto hit;
                }
                VIR_FREE(value);
            }
            cur = cur->next;
        }
    }

    vshError(ctl, _("interface (%s: %s) not found"), element, iface);
    goto cleanup;

 hit:
    /* find and modify/add link state node */
    /* try to find <link> element */
    cur = obj->nodesetval->nodeTab[i]->children;

    while (cur) {
        if (cur->type == XML_ELEMENT_NODE &&
            xmlStrEqual(cur->name, BAD_CAST "link")) {
            /* found, just modify the property */
            xmlSetProp(cur, BAD_CAST "state", BAD_CAST state);

            break;
        }
        cur = cur->next;
    }

    if (!cur) {
        /* element <link> not found, add one */
        cur = xmlNewChild(obj->nodesetval->nodeTab[i],
                          NULL,
                          BAD_CAST "link",
                          NULL);
        if (!cur)
            goto cleanup;

        if (xmlNewProp(cur, BAD_CAST "state", BAD_CAST state) == NULL)
            goto cleanup;
    }

    if (!(xml_buf = virXMLNodeToString(xml, obj->nodesetval->nodeTab[i]))) {
        vshSaveLibvirtError();
        vshError(ctl, _("Failed to create XML"));
        goto cleanup;
    }

    if (virDomainUpdateDeviceFlags(dom, xml_buf, flags) < 0) {
        vshError(ctl, _("Failed to update interface link state"));
        goto cleanup;
    } else {
        vshPrintExtra(ctl, "%s", _("Device updated successfully\n"));
        ret = true;
    }

 cleanup:
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    VIR_FREE(xml_buf);
    virshDomainFree(dom);

    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "interface",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("interface device (MAC Address)")
    },
    {.name = "inbound",
     .type = VSH_OT_STRING,
     .help = N_("control domain's incoming traffics")
    },
    {.name = "outbound",
     .type = VSH_OT_STRING,
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
    virDomainPtr dom;
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
    virNetDevBandwidthRate inbound, outbound;
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

    memset(&inbound, 0, sizeof(inbound));
    memset(&outbound, 0, sizeof(outbound));

    if (inboundStr) {
        if (virshParseRateStr(ctl, inboundStr, &inbound) < 0)
            goto cleanup;
        /* we parse the rate as unsigned long long, but the API
         * only accepts UINT */
        if (inbound.average > UINT_MAX || inbound.peak > UINT_MAX ||
            inbound.burst > UINT_MAX) {
            vshError(ctl, _("inbound rate larger than maximum %u"),
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
            vshError(ctl, _("outbound rate larger than maximum %u"),
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
        params = vshCalloc(ctl, nparams, sizeof(*params));
        if (virDomainGetInterfaceParameters(dom, device, params, &nparams, flags) != 0) {
            vshError(ctl, "%s", _("Unable to get interface parameters"));
            goto cleanup;
        }

        for (i = 0; i < nparams; i++) {
            char *str = vshGetTypedParamValue(ctl, &params[i]);
            vshPrint(ctl, "%-15s: %s\n", params[i].field, str);
            VIR_FREE(str);
        }
    } else {
        if (virDomainSetInterfaceParameters(dom, device, params,
                                            nparams, flags) != 0)
            goto error;
    }

    ret = true;

 cleanup:
    virTypedParamsFree(params, nparams);
    virshDomainFree(dom);
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = NULL}
};

static bool
cmdSuspend(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *name;
    bool ret = true;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (virDomainSuspend(dom) == 0) {
        vshPrintExtra(ctl, _("Domain %s suspended\n"), name);
    } else {
        vshError(ctl, _("Failed to suspend domain %s"), name);
        ret = false;
    }

    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "target",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
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
    virDomainPtr dom;
    const char *name;
    bool ret = false;
    const char *target = NULL;
    unsigned int suspendTarget;
    unsigned long long duration = 0;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (vshCommandOptULongLong(ctl, cmd, "duration", &duration) < 0)
        goto cleanup;

    if (vshCommandOptStringReq(ctl, cmd, "target", &target) < 0)
        goto cleanup;

    if (STREQ(target, "mem")) {
        suspendTarget = VIR_NODE_SUSPEND_TARGET_MEM;
    } else if (STREQ(target, "disk")) {
        suspendTarget = VIR_NODE_SUSPEND_TARGET_DISK;
    } else if (STREQ(target, "hybrid")) {
        suspendTarget = VIR_NODE_SUSPEND_TARGET_HYBRID;
    } else {
        vshError(ctl, "%s", _("Invalid target"));
        goto cleanup;
    }

    if (virDomainPMSuspendForDuration(dom, suspendTarget, duration, 0) < 0) {
        vshError(ctl, _("Domain %s could not be suspended"),
                 virDomainGetName(dom));
        goto cleanup;
    }

    vshPrintExtra(ctl, _("Domain %s successfully suspended"),
             virDomainGetName(dom));

    ret = true;

 cleanup:
    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = NULL}
};

static bool
cmdDomPMWakeup(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *name;
    bool ret = false;
    unsigned int flags = 0;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (virDomainPMWakeup(dom, flags) < 0) {
        vshError(ctl, _("Domain %s could not be woken up"),
                 virDomainGetName(dom));
        goto cleanup;
    }

    vshPrintExtra(ctl, _("Domain %s successfully woken up"),
                  virDomainGetName(dom));

    ret = true;

 cleanup:
    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "managed-save",
     .type = VSH_OT_BOOL,
     .help = N_("remove domain managed state file")
    },
    {.name = "storage",
     .type = VSH_OT_STRING,
     .help = N_("remove associated storage volumes (comma separated list of "
                "targets or source paths) (see domblklist)")
    },
    {.name = "remove-all-storage",
     .type = VSH_OT_BOOL,
     .help = N_("remove all associated storage volumes (use with caution)")
    },
    {.name = "delete-snapshots",
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
     .help = N_("remove all domain snapshot metadata, if inactive")
    },
    {.name = "nvram",
     .type = VSH_OT_BOOL,
     .help = N_("remove nvram file, if inactive")
    },
    {.name = "keep-nvram",
     .type = VSH_OT_BOOL,
     .help = N_("keep nvram file, if inactive")
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
    virDomainPtr dom;
    bool ret = false;
    const char *name = NULL;
    /* Flags to attempt.  */
    unsigned int flags = 0;
    unsigned int vol_flags = 0;
    /* User-requested actions.  */
    bool managed_save = vshCommandOptBool(cmd, "managed-save");
    bool snapshots_metadata = vshCommandOptBool(cmd, "snapshots-metadata");
    bool wipe_storage = vshCommandOptBool(cmd, "wipe-storage");
    bool remove_all_storage = vshCommandOptBool(cmd, "remove-all-storage");
    bool delete_snapshots = vshCommandOptBool(cmd, "delete-snapshots");
    bool nvram = vshCommandOptBool(cmd, "nvram");
    bool keep_nvram = vshCommandOptBool(cmd, "keep-nvram");
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
    virshUndefineVolume *vols = NULL; /* info about the volumes to delete*/
    size_t nvols = 0;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr *vol_nodes = NULL;   /* XML nodes of volumes of the guest */
    int nvol_nodes;
    char *source = NULL;
    char *target = NULL;
    char *pool = NULL;
    size_t i;
    size_t j;
    virshControlPtr priv = ctl->privData;

    VSH_REQUIRE_OPTION("delete-snapshots", "remove-all-storage");
    VSH_EXCLUSIVE_OPTIONS("nvram", "keep-nvram");

    ignore_value(vshCommandOptStringQuiet(ctl, cmd, "storage", &vol_string));

    if (!(vol_string || remove_all_storage) && wipe_storage) {
        vshError(ctl,
                 _("'--wipe-storage' requires '--storage <string>' or "
                   "'--remove-all-storage'"));
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
    if (nvram)
        flags |= VIR_DOMAIN_UNDEFINE_NVRAM;
    if (keep_nvram)
        flags |= VIR_DOMAIN_UNDEFINE_KEEP_NVRAM;

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
                     _("Storage volume deletion is supported only on "
                       "stopped domains"));
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
            ctxt->node = vol_nodes[i];
            virshUndefineVolume vol;
            VIR_FREE(source);
            VIR_FREE(target);
            VIR_FREE(pool);

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
                virStoragePoolPtr storagepool = NULL;

                if (!source) {
                    vshError(ctl,
                             _("Missing storage volume name for disk '%s'"),
                             target);
                    continue;
                }

                if (!(storagepool = virStoragePoolLookupByName(priv->conn,
                                                               pool))) {
                    vshError(ctl,
                             _("Storage pool '%s' for volume '%s' not found."),
                             pool, target);
                    vshResetLibvirtError();
                    continue;
                }

                vol.vol = virStorageVolLookupByName(storagepool, source);
                virStoragePoolFree(storagepool);

            } else {
               vol.vol = virStorageVolLookupByPath(priv->conn, source);
            }

            if (!vol.vol) {
                vshError(ctl,
                         _("Storage volume '%s'(%s) is not managed by libvirt. "
                           "Remove it manually.\n"), target, source);
                vshResetLibvirtError();
                continue;
            }

            vol.source = source;
            vol.target = target;
            source = NULL;
            target = NULL;
            if (VIR_APPEND_ELEMENT(vols, nvols, vol) < 0)
                goto cleanup;
        }

        /* print volumes specified by user that were not found in domain definition */
        if (vol_list) {
            bool found = false;
            for (i = 0; i < nvol_list; i++) {
                if (vol_list[i]) {
                    vshError(ctl,
                             _("Volume '%s' was not found in domain's "
                               "definition.\n"), vol_list[i]);
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
                     _("Refusing to undefine while domain managed save "
                       "image exists"));
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
        vshError(ctl,
                 snapshots_metadata ?
                 _("Unable to remove metadata of %d snapshots") :
                 _("Refusing to undefine while %d snapshots exist"),
                 has_snapshots_metadata);
        goto cleanup;
    }

    rc = virDomainUndefine(dom);

 out:
    if (rc == 0) {
        vshPrintExtra(ctl, _("Domain %s has been undefined\n"), name);
        ret = true;
    } else {
        vshError(ctl, _("Failed to undefine domain %s"), name);
        goto cleanup;
    }

    /* try to undefine storage volumes associated with this domain, if it's requested */
    if (nvols) {
        for (i = 0; i < nvols; i++) {
            if (wipe_storage) {
                vshPrintExtra(ctl, _("Wiping volume '%s'(%s) ... "),
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
                vshError(ctl, _("Failed to remove storage volume '%s'(%s)"),
                         vols[i].target, vols[i].source);
                ret = false;
            } else {
                vshPrintExtra(ctl, _("Volume '%s'(%s) removed.\n"),
                              vols[i].target, vols[i].source);
            }
        }
    }

 cleanup:
    VIR_FREE(source);
    VIR_FREE(target);
    VIR_FREE(pool);
    for (i = 0; i < nvols; i++) {
        VIR_FREE(vols[i].source);
        VIR_FREE(vols[i].target);
        if (vols[i].vol)
            virStorageVolFree(vols[i].vol);
    }
    VIR_FREE(vols);

    for (i = 0; i < nvol_list; i++)
        VIR_FREE(vol_list[i]);
    VIR_FREE(vol_list);

    VIR_FREE(vol_nodes);
    xmlFreeDoc(doc);
    xmlXPathFreeContext(ctxt);
    virshDomainFree(dom);
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
    VIRSH_COMMON_OPT_DOMAIN(N_("name of the inactive domain")),
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
     .help = N_("pass file descriptors N,M,... to the guest")
    },
    {.name = NULL}
};

static int
cmdStartGetFDs(vshControl *ctl,
               const vshCmd *cmd,
               size_t *nfdsret,
               int **fdsret)
{
    const char *fdopt;
    char **fdlist = NULL;
    int *fds = NULL;
    size_t nfds = 0;
    size_t i;

    *nfdsret = 0;
    *fdsret = NULL;

    if (vshCommandOptStringQuiet(ctl, cmd, "pass-fds", &fdopt) <= 0)
        return 0;

    if (!(fdlist = virStringSplit(fdopt, ",", -1))) {
        vshError(ctl, _("Unable to split FD list '%s'"), fdopt);
        return -1;
    }

    for (i = 0; fdlist[i] != NULL; i++) {
        int fd;
        if (virStrToLong_i(fdlist[i], NULL, 10, &fd) < 0) {
            vshError(ctl, _("Unable to parse FD number '%s'"), fdlist[i]);
            goto error;
        }
        if (VIR_EXPAND_N(fds, nfds, 1) < 0) {
            vshError(ctl, "%s", _("Unable to allocate FD list"));
            goto error;
        }
        fds[nfds - 1] = fd;
    }

    virStringListFree(fdlist);

    *fdsret = fds;
    *nfdsret = nfds;
    return 0;

 error:
    virStringListFree(fdlist);
    VIR_FREE(fds);
    return -1;
}

static bool
cmdStart(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = false;
#ifndef WIN32
    bool console = vshCommandOptBool(cmd, "console");
#endif
    unsigned int flags = VIR_DOMAIN_NONE;
    int rc;
    size_t nfds = 0;
    int *fds = NULL;

    if (!(dom = virshCommandOptDomainBy(ctl, cmd, NULL,
                                        VIRSH_BYNAME | VIRSH_BYUUID)))
        return false;

    if (virDomainGetID(dom) != (unsigned int)-1) {
        vshError(ctl, "%s", _("Domain is already active"));
        goto cleanup;
    }

    if (cmdStartGetFDs(ctl, cmd, &nfds, &fds) < 0)
        goto cleanup;

    if (vshCommandOptBool(cmd, "paused"))
        flags |= VIR_DOMAIN_START_PAUSED;
    if (vshCommandOptBool(cmd, "autodestroy"))
        flags |= VIR_DOMAIN_START_AUTODESTROY;
    if (vshCommandOptBool(cmd, "bypass-cache"))
        flags |= VIR_DOMAIN_START_BYPASS_CACHE;
    if (vshCommandOptBool(cmd, "force-boot"))
        flags |= VIR_DOMAIN_START_FORCE_BOOT;

    /* We can emulate force boot, even for older servers that reject it.  */
    if (flags & VIR_DOMAIN_START_FORCE_BOOT) {
        if ((nfds ?
             virDomainCreateWithFiles(dom, nfds, fds, flags) :
             virDomainCreateWithFlags(dom, flags)) == 0)
            goto started;
        if (last_error->code != VIR_ERR_NO_SUPPORT &&
            last_error->code != VIR_ERR_INVALID_ARG) {
            vshReportError(ctl);
            goto cleanup;
        }
        vshResetLibvirtError();
        rc = virDomainHasManagedSaveImage(dom, 0);
        if (rc < 0) {
            /* No managed save image to remove */
            vshResetLibvirtError();
        } else if (rc > 0) {
            if (virDomainManagedSaveRemove(dom, 0) < 0) {
                vshReportError(ctl);
                goto cleanup;
            }
        }
        flags &= ~VIR_DOMAIN_START_FORCE_BOOT;
    }

    /* Prefer older API unless we have to pass a flag.  */
    if ((nfds ? virDomainCreateWithFiles(dom, nfds, fds, flags) :
         (flags ? virDomainCreateWithFlags(dom, flags)
          : virDomainCreate(dom))) < 0) {
        vshError(ctl, _("Failed to start domain %s"), virDomainGetName(dom));
        goto cleanup;
    }

 started:
    vshPrintExtra(ctl, _("Domain %s started\n"),
                  virDomainGetName(dom));
#ifndef WIN32
    if (console && !cmdRunConsole(ctl, dom, NULL, 0))
        goto cleanup;
#endif

    ret = true;

 cleanup:
    virshDomainFree(dom);
    VIR_FREE(fds);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    VIRSH_COMMON_OPT_FILE(N_("where to save the data")),
    {.name = "bypass-cache",
     .type = VSH_OT_BOOL,
     .help = N_("avoid file system cache when saving")
    },
    {.name = "xml",
     .type = VSH_OT_STRING,
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
    char ret = '1';
    virDomainPtr dom = NULL;
    const char *name = NULL;
    const char *to = NULL;
    unsigned int flags = 0;
    const char *xmlfile = NULL;
    char *xml = NULL;
    sigset_t sigmask, oldsigmask;

    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);
    if (pthread_sigmask(SIG_BLOCK, &sigmask, &oldsigmask) < 0)
        goto out_sig;

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

    if (((flags || xml)
         ? virDomainSaveFlags(dom, to, xml, flags)
         : virDomainSave(dom, to)) < 0) {
        vshError(ctl, _("Failed to save domain %s to %s"), name, to);
        goto out;
    }

    ret = '0';

 out:
    pthread_sigmask(SIG_SETMASK, &oldsigmask, NULL);
 out_sig:
    virshDomainFree(dom);
    VIR_FREE(xml);
    ignore_value(safewrite(data->writefd, &ret, sizeof(ret)));
}

typedef void (*jobWatchTimeoutFunc)(vshControl *ctl, virDomainPtr dom,
                                    void *opaque);

static bool
virshWatchJob(vshControl *ctl,
              virDomainPtr dom,
              bool verbose,
              int pipe_fd,
              int timeout_ms,
              jobWatchTimeoutFunc timeout_func,
              void *opaque,
              const char *label)
{
    struct sigaction sig_action;
    struct sigaction old_sig_action;
    struct pollfd pollfd[2] = {{.fd = pipe_fd, .events = POLLIN, .revents = 0},
                               {.fd = STDIN_FILENO, .events = POLLIN, .revents = 0}};
    struct timeval start, curr;
    virDomainJobInfo jobinfo;
    int ret = -1;
    char retchar;
    bool functionReturn = false;
    sigset_t sigmask, oldsigmask;
    bool jobStarted = false;
    nfds_t npollfd = 2;

    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);

    intCaught = 0;
    sig_action.sa_sigaction = virshCatchInt;
    sig_action.sa_flags = SA_SIGINFO;
    sigemptyset(&sig_action.sa_mask);
    sigaction(SIGINT, &sig_action, &old_sig_action);

    /* don't poll on STDIN if we are not using a terminal */
    if (!vshTTYAvailable(ctl))
        npollfd = 1;

    GETTIMEOFDAY(&start);
    while (1) {
        ret = poll((struct pollfd *)&pollfd, npollfd, 500);
        if (ret > 0) {
            if (pollfd[1].revents & POLLIN &&
                saferead(STDIN_FILENO, &retchar, sizeof(retchar)) > 0) {
                if (vshTTYIsInterruptCharacter(ctl, retchar))
                    virDomainAbortJob(dom);
                continue;
            }

            if (pollfd[0].revents & POLLIN &&
                saferead(pipe_fd, &retchar, sizeof(retchar)) > 0 &&
                retchar == '0') {
                if (verbose) {
                    /* print [100 %] */
                    virshPrintJobProgress(label, 0, 1);
                }
                break;
            }
            goto cleanup;
        }

        if (ret < 0) {
            if (errno == EINTR) {
                if (intCaught) {
                    virDomainAbortJob(dom);
                    intCaught = 0;
                }
                continue;
            }
            goto cleanup;
        }

        GETTIMEOFDAY(&curr);
        if (timeout_ms && (((int)(curr.tv_sec - start.tv_sec)  * 1000 +
                            (int)(curr.tv_usec - start.tv_usec) / 1000) >
                           timeout_ms)) {
            /* suspend the domain when migration timeouts. */
            vshDebug(ctl, VSH_ERR_DEBUG, "%s timeout", label);
            if (timeout_func)
                (timeout_func)(ctl, dom, opaque);
            timeout_ms = 0;
        }

        if (verbose || !jobStarted) {
            pthread_sigmask(SIG_BLOCK, &sigmask, &oldsigmask);
            ret = virDomainGetJobInfo(dom, &jobinfo);
            pthread_sigmask(SIG_SETMASK, &oldsigmask, NULL);
            if (ret == 0) {
                if (verbose && jobinfo.dataTotal > 0)
                    virshPrintJobProgress(label, jobinfo.dataRemaining,
                                          jobinfo.dataTotal);

                if (!jobStarted &&
                    (jobinfo.type == VIR_DOMAIN_JOB_BOUNDED ||
                     jobinfo.type == VIR_DOMAIN_JOB_UNBOUNDED)) {
                    vshTTYDisableInterrupt(ctl);
                    jobStarted = true;
                }
            } else {
                vshResetLibvirtError();
            }
        }
    }

    functionReturn = true;

 cleanup:
    sigaction(SIGINT, &old_sig_action, NULL);
    vshTTYRestore(ctl);
    return functionReturn;
}

static bool
cmdSave(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    virDomainPtr dom = NULL;
    int p[2] = {-1. -1};
    virThread workerThread;
    bool verbose = false;
    virshCtrlData data;
    const char *to = NULL;
    const char *name = NULL;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "file", &to) < 0)
        goto cleanup;

    if (vshCommandOptBool(cmd, "verbose"))
        verbose = true;

    if (pipe(p) < 0)
        goto cleanup;

    data.ctl = ctl;
    data.cmd = cmd;
    data.writefd = p[1];

    if (virThreadCreate(&workerThread,
                        true,
                        doSave,
                        &data) < 0)
        goto cleanup;

    ret = virshWatchJob(ctl, dom, verbose, p[0], 0, NULL, NULL, _("Save"));

    virThreadJoin(&workerThread);

    if (ret)
        vshPrintExtra(ctl, _("\nDomain %s saved to %s\n"), name, to);

 cleanup:
    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_FILE(N_("saved state file to read")),
    {.name = "security-info",
     .type = VSH_OT_BOOL,
     .help = N_("include security sensitive information in XML dump")
    },
    {.name = NULL}
};

static bool
cmdSaveImageDumpxml(vshControl *ctl, const vshCmd *cmd)
{
    const char *file = NULL;
    bool ret = false;
    unsigned int flags = 0;
    char *xml = NULL;
    virshControlPtr priv = ctl->privData;

    if (vshCommandOptBool(cmd, "security-info"))
        flags |= VIR_DOMAIN_XML_SECURE;

    if (vshCommandOptStringReq(ctl, cmd, "file", &file) < 0)
        return false;

    xml = virDomainSaveImageGetXMLDesc(priv->conn, file, flags);
    if (!xml)
        goto cleanup;

    vshPrint(ctl, "%s", xml);
    ret = true;

 cleanup:
    VIR_FREE(xml);
    return ret;
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
    VIRSH_COMMON_OPT_FILE(N_("saved state file to modify")),
    {.name = "xml",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
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
    bool ret = false;
    const char *xmlfile = NULL;
    char *xml = NULL;
    unsigned int flags = 0;
    virshControlPtr priv = ctl->privData;

    if (vshCommandOptBool(cmd, "running"))
        flags |= VIR_DOMAIN_SAVE_RUNNING;
    if (vshCommandOptBool(cmd, "paused"))
        flags |= VIR_DOMAIN_SAVE_PAUSED;

    if (vshCommandOptStringReq(ctl, cmd, "file", &file) < 0)
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "xml", &xmlfile) < 0)
        return false;

    if (virFileReadAll(xmlfile, VSH_MAX_XML_FILE, &xml) < 0)
        goto cleanup;

    if (virDomainSaveImageDefineXML(priv->conn, file, xml, flags) < 0) {
        vshError(ctl, _("Failed to update %s"), file);
        goto cleanup;
    }

    vshPrintExtra(ctl, _("State file %s updated.\n"), file);
    ret = true;

 cleanup:
    VIR_FREE(xml);
    return ret;
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
    VIRSH_COMMON_OPT_FILE(N_("saved state file to edit")),
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
    virshControlPtr priv = ctl->privData;

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
#define EDIT_NOT_CHANGED                                             \
    do {                                                             \
        vshPrintExtra(ctl, _("Saved image %s XML configuration "     \
                             "not changed.\n"), file);               \
        ret = true;                                                  \
        goto edit_cleanup;                                           \
    } while (0)
#define EDIT_DEFINE \
    (virDomainSaveImageDefineXML(priv->conn, file, doc_edited, define_flags) == 0)
#include "virsh-edit.c"

    vshPrintExtra(ctl, _("State file %s edited.\n"), file);
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
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
    char ret = '1';
    virshCtrlData *data = opaque;
    vshControl *ctl = data->ctl;
    const vshCmd *cmd = data->cmd;
    virDomainPtr dom = NULL;
    const char *name;
    unsigned int flags = 0;
    sigset_t sigmask, oldsigmask;

    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);
    if (pthread_sigmask(SIG_BLOCK, &sigmask, &oldsigmask) < 0)
        goto out_sig;

    if (vshCommandOptBool(cmd, "bypass-cache"))
        flags |= VIR_DOMAIN_SAVE_BYPASS_CACHE;
    if (vshCommandOptBool(cmd, "running"))
        flags |= VIR_DOMAIN_SAVE_RUNNING;
    if (vshCommandOptBool(cmd, "paused"))
        flags |= VIR_DOMAIN_SAVE_PAUSED;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        goto out;

    if (virDomainManagedSave(dom, flags) < 0) {
        vshError(ctl, _("Failed to save domain %s state"), name);
        goto out;
    }

    ret = '0';
 out:
    pthread_sigmask(SIG_SETMASK, &oldsigmask, NULL);
 out_sig:
    virshDomainFree(dom);
    ignore_value(safewrite(data->writefd, &ret, sizeof(ret)));
}

static bool
cmdManagedSave(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    int p[2] = { -1, -1};
    bool ret = false;
    bool verbose = false;
    const char *name = NULL;
    virshCtrlData data;
    virThread workerThread;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (vshCommandOptBool(cmd, "verbose"))
        verbose = true;

    if (pipe(p) < 0)
        goto cleanup;

    data.ctl = ctl;
    data.cmd = cmd;
    data.writefd = p[1];

    if (virThreadCreate(&workerThread,
                        true,
                        doManagedsave,
                        &data) < 0)
        goto cleanup;

    ret = virshWatchJob(ctl, dom, verbose, p[0], 0,
                        NULL, NULL, _("Managedsave"));

    virThreadJoin(&workerThread);

    if (ret)
        vshPrintExtra(ctl, _("\nDomain %s state saved by libvirt\n"), name);

 cleanup:
    virshDomainFree(dom);
    VIR_FORCE_CLOSE(p[0]);
    VIR_FORCE_CLOSE(p[1]);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = NULL}
};

static bool
cmdManagedSaveRemove(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *name;
    bool ret = false;
    int hassave;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    hassave = virDomainHasManagedSaveImage(dom, 0);
    if (hassave < 0) {
        vshError(ctl, "%s", _("Failed to check for domain managed save image"));
        goto cleanup;
    }

    if (hassave) {
        if (virDomainManagedSaveRemove(dom, 0) < 0) {
            vshError(ctl, _("Failed to remove managed save image for domain %s"),
                     name);
            goto cleanup;
        }
        else
            vshPrintExtra(ctl, _("Removed managedsave image for domain %s"), name);
    }
    else
        vshPrintExtra(ctl, _("Domain %s has no manage save image; removal skipped"),
                      name);

    ret = true;

 cleanup:
    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
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
    int ret = -1;
    size_t i;

    for (i = 0; i < nsrc_params; i++) {
        param = &(src_params[i]);

        if (STRNEQ(field, param->field))
            continue;

        if (virTypedParamsAddFromString(params, nparams, maxparams,
                                        field, param->type,
                                        value) < 0) {
            vshSaveLibvirtError();
            goto cleanup;
        }
        ret = 0;
        break;
    }

    if (ret < 0)
        vshError(ctl, _("invalid scheduler option: %s"), field);

 cleanup:
    return ret;
}

static int
cmdSchedInfoUpdate(vshControl *ctl, const vshCmd *cmd,
                   virTypedParameterPtr src_params, int nsrc_params,
                   virTypedParameterPtr *update_params)
{
    char *set_field = NULL;
    char *set_val = NULL;
    const char *val = NULL;
    const vshCmdOpt *opt = NULL;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    int maxparams = 0;
    int ret = -1;
    int rv;

    while ((opt = vshCommandOptArgv(ctl, cmd, opt))) {
        set_field = vshStrdup(ctl, opt->data);
        if (!(set_val = strchr(set_field, '='))) {
            vshError(ctl, "%s", _("Invalid syntax for --set, "
                                  "expecting name=value"));
            goto cleanup;
        }

        *set_val = '\0';
        set_val++;

        if (cmdSchedInfoUpdateOne(ctl, src_params, nsrc_params,
                                  &params, &nparams, &maxparams,
                                  set_field, set_val) < 0)
            goto cleanup;

        VIR_FREE(set_field);
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
    *update_params = params;
    params = NULL;

 cleanup:
    VIR_FREE(set_field);
    virTypedParamsFree(params, nparams);
    return ret;
}

static bool
cmdSchedinfo(vshControl *ctl, const vshCmd *cmd)
{
    char *schedulertype;
    virDomainPtr dom;
    virTypedParameterPtr params = NULL;
    virTypedParameterPtr updates = NULL;
    int nparams = 0;
    int nupdates = 0;
    size_t i;
    int ret;
    bool ret_val = false;
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

    /* Print SchedulerType */
    schedulertype = virDomainGetSchedulerType(dom, &nparams);
    if (schedulertype != NULL) {
        vshPrint(ctl, "%-15s: %s\n", _("Scheduler"), schedulertype);
        VIR_FREE(schedulertype);
    } else {
        vshPrint(ctl, "%-15s: %s\n", _("Scheduler"), _("Unknown"));
        goto cleanup;
    }

    if (nparams) {
        params = vshMalloc(ctl, sizeof(*params) * nparams);

        memset(params, 0, sizeof(*params) * nparams);
        if (flags || current) {
            /* We cannot query both live and config at once, so settle
               on current in that case.  If we are setting, then the
               two values should match when we re-query; otherwise, we
               report the error later.  */
            ret = virDomainGetSchedulerParametersFlags(dom, params, &nparams,
                                                       ((live && config) ? 0
                                                        : flags));
        } else {
            ret = virDomainGetSchedulerParameters(dom, params, &nparams);
        }
        if (ret == -1)
            goto cleanup;

        /* See if any params are being set */
        if ((nupdates = cmdSchedInfoUpdate(ctl, cmd, params, nparams,
                                           &updates)) < 0)
            goto cleanup;

        /* Update parameters & refresh data */
        if (nupdates > 0) {
            if (flags || current)
                ret = virDomainSetSchedulerParametersFlags(dom, updates,
                                                           nupdates, flags);
            else
                ret = virDomainSetSchedulerParameters(dom, updates, nupdates);

            if (ret == -1)
                goto cleanup;

            if (flags || current)
                ret = virDomainGetSchedulerParametersFlags(dom, params,
                                                           &nparams,
                                                           ((live && config) ? 0
                                                            : flags));
            else
                ret = virDomainGetSchedulerParameters(dom, params, &nparams);
            if (ret == -1)
                goto cleanup;
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
            char *str = vshGetTypedParamValue(ctl, &params[i]);
            vshPrint(ctl, "%-15s: %s\n", params[i].field, str);
            VIR_FREE(str);
        }
    }

 cleanup:
    virTypedParamsFree(params, nparams);
    virTypedParamsFree(updates, nupdates);
    virshDomainFree(dom);
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
    VIRSH_COMMON_OPT_FILE(N_("the state to restore")),
    {.name = "bypass-cache",
     .type = VSH_OT_BOOL,
     .help = N_("avoid file system cache when restoring")
    },
    {.name = "xml",
     .type = VSH_OT_STRING,
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
    {.name = NULL}
};

static bool
cmdRestore(vshControl *ctl, const vshCmd *cmd)
{
    const char *from = NULL;
    bool ret = false;
    unsigned int flags = 0;
    const char *xmlfile = NULL;
    char *xml = NULL;
    virshControlPtr priv = ctl->privData;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        return false;

    if (vshCommandOptBool(cmd, "bypass-cache"))
        flags |= VIR_DOMAIN_SAVE_BYPASS_CACHE;
    if (vshCommandOptBool(cmd, "running"))
        flags |= VIR_DOMAIN_SAVE_RUNNING;
    if (vshCommandOptBool(cmd, "paused"))
        flags |= VIR_DOMAIN_SAVE_PAUSED;

    if (vshCommandOptStringReq(ctl, cmd, "xml", &xmlfile) < 0)
        return false;

    if (xmlfile &&
        virFileReadAll(xmlfile, VSH_MAX_XML_FILE, &xml) < 0)
        goto cleanup;

    if (((flags || xml)
         ? virDomainRestoreFlags(priv->conn, from, xml, flags)
         : virDomainRestore(priv->conn, from)) < 0) {
        vshError(ctl, _("Failed to restore domain from %s"), from);
        goto cleanup;
    }

    vshPrintExtra(ctl, _("Domain restored from %s\n"), from);
    ret = true;

 cleanup:
    VIR_FREE(xml);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    VIRSH_COMMON_OPT_FILE(N_("where to dump the core")),
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
     .help = N_("specify the format of memory-only dump")
    },
    {.name = NULL}
};

static void
doDump(void *opaque)
{
    char ret = '1';
    virshCtrlData *data = opaque;
    vshControl *ctl = data->ctl;
    const vshCmd *cmd = data->cmd;
    virDomainPtr dom = NULL;
    sigset_t sigmask, oldsigmask;
    const char *name = NULL;
    const char *to = NULL;
    unsigned int flags = 0;
    const char *format = NULL;
    unsigned int dumpformat = VIR_DOMAIN_CORE_DUMP_FORMAT_RAW;

    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);
    if (pthread_sigmask(SIG_BLOCK, &sigmask, &oldsigmask) < 0)
        goto out_sig;

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
            if (STREQ(format, "kdump-zlib")) {
                dumpformat = VIR_DOMAIN_CORE_DUMP_FORMAT_KDUMP_ZLIB;
            } else if (STREQ(format, "kdump-lzo")) {
                dumpformat = VIR_DOMAIN_CORE_DUMP_FORMAT_KDUMP_LZO;
            } else if (STREQ(format, "kdump-snappy")) {
                dumpformat = VIR_DOMAIN_CORE_DUMP_FORMAT_KDUMP_SNAPPY;
            } else if (STREQ(format, "elf")) {
                dumpformat = VIR_DOMAIN_CORE_DUMP_FORMAT_RAW;
            } else {
                vshError(ctl, _("format '%s' is not supported, expecting "
                                "'kdump-zlib', 'kdump-lzo', 'kdump-snappy' "
                                "or 'elf'"), format);
                goto out;
            }
        }
    }

    if (dumpformat != VIR_DOMAIN_CORE_DUMP_FORMAT_RAW) {
        if (virDomainCoreDumpWithFormat(dom, to, dumpformat, flags) < 0) {
            vshError(ctl, _("Failed to core dump domain %s to %s"), name, to);
            goto out;
        }
    } else {
        if (virDomainCoreDump(dom, to, flags) < 0) {
            vshError(ctl, _("Failed to core dump domain %s to %s"), name, to);
            goto out;
        }
    }

    ret = '0';
 out:
    pthread_sigmask(SIG_SETMASK, &oldsigmask, NULL);
 out_sig:
    if (dom)
        virshDomainFree(dom);
    ignore_value(safewrite(data->writefd, &ret, sizeof(ret)));
}

static bool
cmdDump(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    int p[2] = { -1, -1};
    bool ret = false;
    bool verbose = false;
    const char *name = NULL;
    const char *to = NULL;
    virshCtrlData data;
    virThread workerThread;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "file", &to) < 0)
        goto cleanup;

    if (vshCommandOptBool(cmd, "verbose"))
        verbose = true;

    if (pipe(p) < 0)
        goto cleanup;

    data.ctl = ctl;
    data.cmd = cmd;
    data.writefd = p[1];

    if (virThreadCreate(&workerThread,
                        true,
                        doDump,
                        &data) < 0)
        goto cleanup;

    ret = virshWatchJob(ctl, dom, verbose, p[0], 0, NULL, NULL, _("Dump"));

    virThreadJoin(&workerThread);

    if (ret)
        vshPrintExtra(ctl, _("\nDomain %s dumped to %s\n"), name, to);

 cleanup:
    virshDomainFree(dom);
    VIR_FORCE_CLOSE(p[0]);
    VIR_FORCE_CLOSE(p[1]);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "file",
     .type = VSH_OT_STRING,
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
    char timestr[100];
    time_t cur_time;
    struct tm time_info;
    const char *ext = NULL;
    char *ret = NULL;

    if (!dom) {
        vshError(ctl, "%s", _("Invalid domain supplied"));
        return NULL;
    }

    if (STREQ(mime, "image/x-portable-pixmap"))
        ext = ".ppm";
    else if (STREQ(mime, "image/png"))
        ext = ".png";
    /* add mime type here */

    time(&cur_time);
    localtime_r(&cur_time, &time_info);
    strftime(timestr, sizeof(timestr), "%Y-%m-%d-%H:%M:%S", &time_info);

    if (virAsprintf(&ret, "%s-%s%s", virDomainGetName(dom),
                    timestr, ext ? ext : "") < 0) {
        vshError(ctl, "%s", _("Out of memory"));
        return NULL;
    }

    return ret;
}

static bool
cmdScreenshot(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *name = NULL;
    char *file = NULL;
    int fd = -1;
    virStreamPtr st = NULL;
    unsigned int screen = 0;
    unsigned int flags = 0; /* currently unused */
    bool ret = false;
    bool created = false;
    bool generated = false;
    char *mime = NULL;
    virshControlPtr priv = ctl->privData;

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
        vshError(ctl, _("could not take a screenshot of %s"), name);
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
            vshError(ctl, _("cannot create file %s"), file);
            goto cleanup;
        }
    } else {
        created = true;
    }

    if (virStreamRecvAll(st, virshStreamSink, &fd) < 0) {
        vshError(ctl, _("could not receive data from domain %s"), name);
        goto cleanup;
    }

    if (VIR_CLOSE(fd) < 0) {
        vshError(ctl, _("cannot close file %s"), file);
        goto cleanup;
    }

    if (virStreamFinish(st) < 0) {
        vshError(ctl, _("cannot close stream on domain %s"), name);
        goto cleanup;
    }

    vshPrintExtra(ctl, _("Screenshot saved to %s, with type of %s"), file, mime);
    ret = true;

 cleanup:
    if (!ret && created)
        unlink(file);
    if (generated)
        VIR_FREE(file);
    virshDomainFree(dom);
    if (st)
        virStreamFree(st);
    VIR_FORCE_CLOSE(fd);
    VIR_FREE(mime);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "user",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("the username")
    },
    {.name = "password",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
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
    virDomainPtr dom;
    const char *name;
    const char *password = NULL;
    const char *user = NULL;
    unsigned int flags = 0;
    bool ret = false;

    if (vshCommandOptBool(cmd, "encrypted"))
        flags = VIR_DOMAIN_PASSWORD_ENCRYPTED;

    if (vshCommandOptStringReq(ctl, cmd, "user", &user) < 0)
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "password", &password) < 0)
        return false;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (virDomainSetUserPassword(dom, user, password, flags) < 0)
        goto cleanup;

    vshPrintExtra(ctl, _("Password set successfully for %s in %s"), user, name);
    ret = true;

 cleanup:
    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = NULL}
};

static bool
cmdResume(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = true;
    const char *name;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (virDomainResume(dom) == 0) {
        vshPrintExtra(ctl, _("Domain %s resumed\n"), name);
    } else {
        vshError(ctl, _("Failed to resume domain %s"), name);
        ret = false;
    }

    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "mode",
     .type = VSH_OT_STRING,
     .help = N_("shutdown mode: acpi|agent|initctl|signal|paravirt")
    },
    {.name = NULL}
};

static bool
cmdShutdown(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    const char *name;
    const char *mode = NULL;
    int flags = 0;
    int rv;
    char **modes = NULL, **tmp;

    if (vshCommandOptStringReq(ctl, cmd, "mode", &mode) < 0)
        return false;

    if (mode && !(modes = virStringSplit(mode, ",", 0))) {
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
            vshError(ctl, _("Unknown mode %s value, expecting "
                            "'acpi', 'agent', 'initctl', 'signal', "
                            "or 'paravirt'"), mode);
            goto cleanup;
        }
        tmp++;
    }

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        goto cleanup;

    if (flags)
        rv = virDomainShutdownFlags(dom, flags);
    else
        rv = virDomainShutdown(dom);
    if (rv == 0) {
        vshPrintExtra(ctl, _("Domain %s is being shutdown\n"), name);
    } else {
        vshError(ctl, _("Failed to shutdown domain %s"), name);
        goto cleanup;
    }

    ret = true;
 cleanup:
    virshDomainFree(dom);
    virStringListFree(modes);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "mode",
     .type = VSH_OT_STRING,
     .help = N_("shutdown mode: acpi|agent|initctl|signal|paravirt")
    },
    {.name = NULL}
};

static bool
cmdReboot(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    const char *name;
    const char *mode = NULL;
    int flags = 0;
    char **modes = NULL, **tmp;

    if (vshCommandOptStringReq(ctl, cmd, "mode", &mode) < 0)
        return false;

    if (mode && !(modes = virStringSplit(mode, ",", 0))) {
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
            vshError(ctl, _("Unknown mode %s value, expecting "
                            "'acpi', 'agent', 'initctl', 'signal' "
                            "or 'paravirt'"), mode);
            goto cleanup;
        }
        tmp++;
    }

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        goto cleanup;

    if (virDomainReboot(dom, flags) == 0) {
        vshPrintExtra(ctl, _("Domain %s is being rebooted\n"), name);
    } else {
        vshError(ctl, _("Failed to reboot domain %s"), name);
        goto cleanup;
    }

    ret = true;
 cleanup:
    virshDomainFree(dom);
    virStringListFree(modes);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = NULL}
};

static bool
cmdReset(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = true;
    const char *name;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (virDomainReset(dom, 0) == 0) {
        vshPrintExtra(ctl, _("Domain %s was reset\n"), name);
    } else {
        vshError(ctl, _("Failed to reset domain %s"), name);
        ret = false;
    }

    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "completed",
     .type = VSH_OT_BOOL,
     .help = N_("return statistics of a recently completed job")
    },
    {.name = NULL}
};

VIR_ENUM_DECL(virshDomainJob)
VIR_ENUM_IMPL(virshDomainJob,
              VIR_DOMAIN_JOB_LAST,
              N_("None"),
              N_("Bounded"),
              N_("Unbounded"),
              N_("Completed"),
              N_("Failed"),
              N_("Cancelled"))

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
              N_("Dump"))

static const char *
virshDomainJobOperationToString(int op)
{
    const char *str = virshDomainJobOperationTypeToString(op);
    return str ? _(str) : _("unknown");
}

static bool
cmdDomjobinfo(vshControl *ctl, const vshCmd *cmd)
{
    virDomainJobInfo info;
    virDomainPtr dom;
    bool ret = false;
    const char *unit;
    double val;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    unsigned long long value;
    unsigned int flags = 0;
    int ivalue;
    int op;
    int rc;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptBool(cmd, "completed"))
        flags |= VIR_DOMAIN_JOB_STATS_COMPLETED;

    memset(&info, 0, sizeof(info));

    rc = virDomainGetJobStats(dom, &info.type, &params, &nparams, flags);
    if (rc == 0) {
        if (virTypedParamsGetULLong(params, nparams,
                                    VIR_DOMAIN_JOB_TIME_ELAPSED,
                                    &info.timeElapsed) < 0 ||
            virTypedParamsGetULLong(params, nparams,
                                    VIR_DOMAIN_JOB_TIME_REMAINING,
                                    &info.timeRemaining) < 0 ||
            virTypedParamsGetULLong(params, nparams,
                                    VIR_DOMAIN_JOB_DATA_TOTAL,
                                    &info.dataTotal) < 0 ||
            virTypedParamsGetULLong(params, nparams,
                                    VIR_DOMAIN_JOB_DATA_PROCESSED,
                                    &info.dataProcessed) < 0 ||
            virTypedParamsGetULLong(params, nparams,
                                    VIR_DOMAIN_JOB_DATA_REMAINING,
                                    &info.dataRemaining) < 0 ||
            virTypedParamsGetULLong(params, nparams,
                                    VIR_DOMAIN_JOB_MEMORY_TOTAL,
                                    &info.memTotal) < 0 ||
            virTypedParamsGetULLong(params, nparams,
                                    VIR_DOMAIN_JOB_MEMORY_PROCESSED,
                                    &info.memProcessed) < 0 ||
            virTypedParamsGetULLong(params, nparams,
                                    VIR_DOMAIN_JOB_MEMORY_REMAINING,
                                    &info.memRemaining) < 0 ||
            virTypedParamsGetULLong(params, nparams,
                                    VIR_DOMAIN_JOB_DISK_TOTAL,
                                    &info.fileTotal) < 0 ||
            virTypedParamsGetULLong(params, nparams,
                                    VIR_DOMAIN_JOB_DISK_PROCESSED,
                                    &info.fileProcessed) < 0 ||
            virTypedParamsGetULLong(params, nparams,
                                    VIR_DOMAIN_JOB_DISK_REMAINING,
                                    &info.fileRemaining) < 0)
            goto save_error;
    } else if (last_error->code == VIR_ERR_NO_SUPPORT) {
        if (flags) {
            vshError(ctl, "%s", _("Optional flags are not supported by the "
                                  "daemon"));
            goto cleanup;
        }
        vshDebug(ctl, VSH_ERR_DEBUG, "detailed statistics not supported\n");
        vshResetLibvirtError();
        rc = virDomainGetJobInfo(dom, &info);
    }
    if (rc < 0)
        goto cleanup;

    vshPrint(ctl, "%-17s %-12s\n", _("Job type:"),
             virshDomainJobToString(info.type));
    if (info.type != VIR_DOMAIN_JOB_BOUNDED &&
        info.type != VIR_DOMAIN_JOB_UNBOUNDED &&
        (!(flags & VIR_DOMAIN_JOB_STATS_COMPLETED) ||
         info.type != VIR_DOMAIN_JOB_COMPLETED)) {
        ret = true;
        goto cleanup;
    }

    op = VIR_DOMAIN_JOB_OPERATION_UNKNOWN;
    if ((rc = virTypedParamsGetInt(params, nparams,
                                   VIR_DOMAIN_JOB_OPERATION, &op)) < 0)
        goto save_error;

    vshPrint(ctl, "%-17s %-12s\n", _("Operation:"),
             virshDomainJobOperationToString(op));

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
                                          VIR_DOMAIN_JOB_MEMORY_ITERATION,
                                          &value)) < 0) {
            goto save_error;
        } else if (rc) {
            vshPrint(ctl, "%-17s %-12llu\n", _("Iteration:"), value);
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

    ret = true;

 cleanup:
    virshDomainFree(dom);
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = NULL}
};

static bool
cmdDomjobabort(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = true;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virDomainAbortJob(dom) < 0)
        ret = false;

    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
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
    int ret = -2;
    virDomainInfo info;
    int count;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;

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
        goto cleanup;

    if (flags & VIR_DOMAIN_VCPU_GUEST) {
        vshError(ctl, "%s", _("Failed to retrieve vCPU count from the guest"));
        goto cleanup;
    }

    if (!(flags & (VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_AFFECT_CONFIG)) &&
        virDomainIsActive(dom) == 1)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    vshResetLibvirtError();

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (flags & VIR_DOMAIN_VCPU_MAXIMUM) {
            count = virDomainGetMaxVcpus(dom);
        } else {
           if (virDomainGetInfo(dom, &info) < 0)
               goto cleanup;

           count = info.nrVirtCpu;
        }
    } else {
        if (virshDomainGetXMLFromDom(ctl, dom, VIR_DOMAIN_XML_INACTIVE,
                                     &xml, &ctxt) < 0)
            goto cleanup;

        if (flags & VIR_DOMAIN_VCPU_MAXIMUM) {
            if (virXPathInt("string(/domain/vcpu)", ctxt, &count) < 0) {
                vshError(ctl, "%s", _("Failed to retrieve maximum vcpu count"));
                goto cleanup;
            }
        } else {
            if (virXPathInt("string(/domain/vcpu/@current)", ctxt, &count) < 0) {
                vshError(ctl, "%s", _("Failed to retrieve current vcpu count"));
                goto cleanup;
            }
        }
    }

    ret = count;
 cleanup:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);

    return ret;
}

static bool
cmdVcpucount(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = false;
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
            goto cleanup;

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
            goto cleanup;

        vshPrint(ctl, "%d\n", count);
    }

    ret = true;

 cleanup:
    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
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
    char *str = NULL;
    size_t i;
    int ret = -1;

    vshPrint(ctl, "%-15s ", _("CPU Affinity:"));
    if (pretty) {
        if (!(str = virBitmapDataToString(cpumap, VIR_CPU_MAPLEN(maxcpu))))
            goto cleanup;
        vshPrint(ctl, _("%s (out of %d)"), str, maxcpu);
    } else {
        for (i = 0; i < maxcpu; i++)
            vshPrint(ctl, "%c", VIR_CPU_USED(cpumap, i) ? 'y' : '-');
    }
    vshPrint(ctl, "\n");

    ret = 0;

 cleanup:
    VIR_FREE(str);
    return ret;
}


static virBitmapPtr
virshDomainGetVcpuBitmap(vshControl *ctl,
                         virDomainPtr dom,
                         bool inactive)
{
    unsigned int flags = 0;
    virBitmapPtr ret = NULL;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr *nodes = NULL;
    xmlNodePtr old;
    int nnodes;
    size_t i;
    unsigned int curvcpus = 0;
    unsigned int maxvcpus = 0;
    unsigned int vcpuid;
    char *online = NULL;

    if (inactive)
        flags |= VIR_DOMAIN_XML_INACTIVE;

    if (virshDomainGetXMLFromDom(ctl, dom, flags, &xml, &ctxt) < 0)
        goto cleanup;

    if (virXPathUInt("string(/domain/vcpu)", ctxt, &maxvcpus) < 0) {
        vshError(ctl, "%s", _("Failed to retrieve maximum vcpu count"));
        goto cleanup;
    }

    ignore_value(virXPathUInt("string(/domain/vcpu/@current)", ctxt, &curvcpus));

    if (curvcpus == 0)
        curvcpus = maxvcpus;

    if (!(ret = virBitmapNew(maxvcpus)))
        goto cleanup;

    if ((nnodes = virXPathNodeSet("/domain/vcpus/vcpu", ctxt, &nodes)) <= 0) {
        /* if the specific vcpu state is missing provide a fallback */
        for (i = 0; i < curvcpus; i++)
            ignore_value(virBitmapSetBit(ret, i));

        goto cleanup;
    }

    old = ctxt->node;

    for (i = 0; i < nnodes; i++) {
        ctxt->node = nodes[i];

        if (virXPathUInt("string(@id)", ctxt, &vcpuid) < 0 ||
            !(online = virXPathString("string(@enabled)", ctxt)))
            continue;

        if (STREQ(online, "yes"))
            ignore_value(virBitmapSetBit(ret, vcpuid));

        VIR_FREE(online);
    }

    ctxt->node = old;

    if (virBitmapCountBits(ret) != curvcpus) {
        vshError(ctl, "%s", _("Failed to retrieve vcpu state bitmap"));
        virBitmapFree(ret);
        ret = NULL;
    }

 cleanup:
    VIR_FREE(online);
    VIR_FREE(nodes);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    return ret;
}


static bool
virshVcpuinfoInactive(vshControl *ctl,
                      virDomainPtr dom,
                      int maxcpu,
                      bool pretty)
{
    unsigned char *cpumaps = NULL;
    size_t cpumaplen;
    int ncpus;
    virBitmapPtr vcpus = NULL;
    ssize_t nextvcpu = -1;
    bool ret = false;
    bool first = true;

    if (!(vcpus = virshDomainGetVcpuBitmap(ctl, dom, true)))
        goto cleanup;

    cpumaplen = VIR_CPU_MAPLEN(maxcpu);
    cpumaps = vshMalloc(ctl, virBitmapSize(vcpus) * cpumaplen);

    if ((ncpus = virDomainGetVcpuPinInfo(dom, virBitmapSize(vcpus),
                                         cpumaps, cpumaplen,
                                         VIR_DOMAIN_AFFECT_CONFIG)) < 0)
        goto cleanup;

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
            goto cleanup;
    }

    ret = true;

 cleanup:
    virBitmapFree(vcpus);
    VIR_FREE(cpumaps);
    return ret;
}


static bool
cmdVcpuinfo(vshControl *ctl, const vshCmd *cmd)
{
    virDomainInfo info;
    virDomainPtr dom;
    virVcpuInfoPtr cpuinfo = NULL;
    unsigned char *cpumaps = NULL;
    int ncpus, maxcpu;
    size_t cpumaplen;
    bool ret = false;
    bool pretty = vshCommandOptBool(cmd, "pretty");
    int n;
    virshControlPtr priv = ctl->privData;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if ((maxcpu = virshNodeGetCPUCount(priv->conn)) < 0)
        goto cleanup;

    if (virDomainGetInfo(dom, &info) != 0)
        goto cleanup;

    cpuinfo = vshMalloc(ctl, sizeof(virVcpuInfo)*info.nrVirtCpu);
    cpumaplen = VIR_CPU_MAPLEN(maxcpu);
    cpumaps = vshMalloc(ctl, info.nrVirtCpu * cpumaplen);

    if ((ncpus = virDomainGetVcpus(dom,
                                   cpuinfo, info.nrVirtCpu,
                                   cpumaps, cpumaplen)) < 0) {
        if (info.state != VIR_DOMAIN_SHUTOFF)
            goto cleanup;

        vshResetLibvirtError();

        /* for offline VMs we can return pinning information */
        ret = virshVcpuinfoInactive(ctl, dom, maxcpu, pretty);
        goto cleanup;
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
            goto cleanup;

        if (n < (ncpus - 1))
            vshPrint(ctl, "\n");
    }

    ret = true;

 cleanup:
    VIR_FREE(cpumaps);
    VIR_FREE(cpuinfo);
    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "vcpu",
     .type = VSH_OT_INT,
     .help = N_("vcpu number")
    },
    {.name = "cpulist",
     .type = VSH_OT_STRING,
     .flags = VSH_OFLAG_EMPTY_OK,
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
    char *str = NULL;

    if (!(str = virBitmapDataToString(cpumap, cpumaplen)))
        return false;

    vshPrint(ctl, "%s", str);
    VIR_FREE(str);
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
    unsigned char *cpumap = NULL;
    unsigned int countFlags = flags | VIR_DOMAIN_VCPU_MAXIMUM;
    int cpumaplen;
    size_t i;
    int ncpus;
    bool ret = false;

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
                     _("vcpu %d is out of range of live cpu count %d"),
                     vcpu, ncpus);
        else
            vshError(ctl,
                     _("vcpu %d is out of range of persistent cpu count %d"),
                     vcpu, ncpus);
        return false;
    }

    cpumaplen = VIR_CPU_MAPLEN(maxcpu);
    cpumap = vshMalloc(ctl, ncpus * cpumaplen);
    if ((ncpus = virDomainGetVcpuPinInfo(dom, ncpus, cpumap,
                                         cpumaplen, flags)) >= 0) {
        vshPrintExtra(ctl, "%s %s\n", _("VCPU:"), _("CPU Affinity"));
        vshPrintExtra(ctl, "----------------------------------\n");
        for (i = 0; i < ncpus; i++) {
            if (got_vcpu && i != vcpu)
                continue;

            vshPrint(ctl, "%4zu: ", i);
            ret = virshPrintPinInfo(ctl, VIR_GET_CPUMAP(cpumap, cpumaplen, i),
                                    cpumaplen);
            vshPrint(ctl, "\n");
            if (!ret)
                break;
        }
    }

    VIR_FREE(cpumap);
    return ret;
}


static unsigned char *
virshParseCPUList(vshControl *ctl, int *cpumaplen,
                  const char *cpulist, int maxcpu)
{
    unsigned char *cpumap = NULL;
    virBitmapPtr map = NULL;

    if (cpulist[0] == 'r') {
        if (!(map = virBitmapNew(maxcpu)))
            return NULL;
        virBitmapSetAll(map);
    } else {
        if (virBitmapParse(cpulist, &map, 1024) < 0 ||
            virBitmapIsAllClear(map)) {
            vshError(ctl, _("Invalid cpulist '%s'"), cpulist);
            goto cleanup;
        }
        int lastcpu = virBitmapLastSetBit(map);
        if (lastcpu >= maxcpu) {
            vshError(ctl, _("CPU %d in cpulist '%s' exceed the maxcpu %d"),
                     lastcpu, cpulist, maxcpu);
            goto cleanup;
        }
    }

    if (virBitmapToData(map, &cpumap, cpumaplen) < 0)
        goto cleanup;

 cleanup:
    virBitmapFree(map);
    return cpumap;
}

static bool
cmdVcpuPin(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    unsigned int vcpu = 0;
    const char *cpulist = NULL;
    bool ret = false;
    unsigned char *cpumap = NULL;
    int cpumaplen;
    int maxcpu;
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool current = vshCommandOptBool(cmd, "current");
    int got_vcpu;
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;
    virshControlPtr priv = ctl->privData;

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
        ret = virshVcpuPinQuery(ctl, dom, vcpu, got_vcpu, maxcpu, flags);
        goto cleanup;
    }

    /* Pin mode: pinning specified vcpu to specified physical cpus*/
    if (!(cpumap = virshParseCPUList(ctl, &cpumaplen, cpulist, maxcpu)))
        goto cleanup;

    /* use old API without any explicit flags */
    if (flags == VIR_DOMAIN_AFFECT_CURRENT && !current) {
        if (virDomainPinVcpu(dom, vcpu, cpumap, cpumaplen) != 0)
            goto cleanup;
    } else {
        if (virDomainPinVcpuFlags(dom, vcpu, cpumap, cpumaplen, flags) != 0)
            goto cleanup;
    }
    ret = true;

 cleanup:
    VIR_FREE(cpumap);
    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "cpulist",
     .type = VSH_OT_STRING,
     .flags = VSH_OFLAG_EMPTY_OK,
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
    virDomainPtr dom;
    const char *cpulist = NULL;
    bool ret = false;
    unsigned char *cpumap = NULL;
    int cpumaplen;
    int maxcpu;
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool current = vshCommandOptBool(cmd, "current");
    bool query = false; /* Query mode if no cpulist */
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;
    virshControlPtr priv = ctl->privData;

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
        virshDomainFree(dom);
        return false;
    }
    query = !cpulist;

    if ((maxcpu = virshNodeGetCPUCount(priv->conn)) < 0) {
        virshDomainFree(dom);
        return false;
    }

    /* Query mode: show CPU affinity information then exit.*/
    if (query) {
        /* When query mode and neither "live", "config" nor "current"
         * is specified, set VIR_DOMAIN_AFFECT_CURRENT as flags */
        if (flags == -1)
            flags = VIR_DOMAIN_AFFECT_CURRENT;

        cpumaplen = VIR_CPU_MAPLEN(maxcpu);
        cpumap = vshMalloc(ctl, cpumaplen);
        if (virDomainGetEmulatorPinInfo(dom, cpumap,
                                        cpumaplen, flags) >= 0) {
            vshPrintExtra(ctl, "%s %s\n", _("emulator:"), _("CPU Affinity"));
            vshPrintExtra(ctl, "----------------------------------\n");
            vshPrintExtra(ctl, "       *: ");
            ret = virshPrintPinInfo(ctl, cpumap, cpumaplen);
            vshPrint(ctl, "\n");
        }
        goto cleanup;
    }

    /* Pin mode: pinning emulator threads to specified physical cpus*/
    if (!(cpumap = virshParseCPUList(ctl, &cpumaplen, cpulist, maxcpu)))
        goto cleanup;

    if (flags == -1)
        flags = VIR_DOMAIN_AFFECT_LIVE;

    if (virDomainPinEmulator(dom, cpumap, cpumaplen, flags) != 0)
        goto cleanup;

    ret = true;
 cleanup:
    VIR_FREE(cpumap);
    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
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
    virDomainPtr dom;
    unsigned int count = 0;
    bool ret = false;
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
        goto cleanup;

    if (count == 0) {
        vshError(ctl, _("Can't set 0 processors for a VM"));
        goto cleanup;
    }

    /* none of the options were specified */
    if (!current && flags == 0) {
        if (virDomainSetVcpus(dom, count) != 0)
            goto cleanup;
    } else {
        if (virDomainSetVcpusFlags(dom, count, flags) < 0)
            goto cleanup;
    }

    ret = true;

 cleanup:
    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "cpulist",
     .type = VSH_OT_STRING,
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
    virDomainPtr dom;
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

    if (cpulist && !(enable | disable)) {
        vshError(ctl, _("One of options --enable or --disable is required by "
                        "option --cpulist"));
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
            char *str = vshGetTypedParamValue(ctl, &params[i]);
            vshPrint(ctl, "%-15s: %s\n", params[i].field, str);
            VIR_FREE(str);
        }
    }

    ret = true;

 cleanup:
    virTypedParamsFree(params, nparams);
    virshDomainFree(dom);
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "vcpulist",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
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
    virDomainPtr dom;
    bool enable = vshCommandOptBool(cmd, "enable");
    bool disable = vshCommandOptBool(cmd, "disable");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    const char *vcpulist = NULL;
    int state = 0;
    bool ret = false;
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
        goto cleanup;

    ret = true;

 cleanup:
    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "dev",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
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
    virDomainPtr dom;
    bool ret = false;

    if (vshCommandOptStringReq(ctl, cmd, "dev", &dev))
        return false;

    if (vshCommandOptScaledInt(ctl, cmd, "threshold",
                               &threshold, 1, ULLONG_MAX) < 0)
        return false;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virDomainSetBlockThreshold(dom, dev, threshold, 0) < 0)
        goto cleanup;

    ret = true;

 cleanup:
    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = NULL}
};

static bool
cmdIOThreadInfo(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool current = vshCommandOptBool(cmd, "current");
    int niothreads = 0;
    virDomainIOThreadInfoPtr *info;
    size_t i;
    int maxcpu;
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;
    virshControlPtr priv = ctl->privData;

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (config)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if ((maxcpu = virshNodeGetCPUCount(priv->conn)) < 0)
        goto cleanup;

    if ((niothreads = virDomainGetIOThreadInfo(dom, &info, flags)) < 0) {
        vshError(ctl, _("Unable to get domain IOThreads information"));
        goto cleanup;
    }

    if (niothreads == 0) {
        vshPrintExtra(ctl, _("No IOThreads found for the domain"));
        goto cleanup;
    }

    vshPrintExtra(ctl, " %-15s %-15s\n",
                  _("IOThread ID"), _("CPU Affinity"));
    vshPrintExtra(ctl, "---------------------------------------------------\n");
    for (i = 0; i < niothreads; i++) {

        vshPrint(ctl, " %-15u ", info[i]->iothread_id);
        ignore_value(virshPrintPinInfo(ctl, info[i]->cpumap, info[i]->cpumaplen));
        vshPrint(ctl, "\n");
        virDomainIOThreadInfoFree(info[i]);
    }
    VIR_FREE(info);

 cleanup:
    virshDomainFree(dom);
    return niothreads >= 0;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "iothread",
     .type = VSH_OT_INT,
     .flags = VSH_OFLAG_REQ,
     .help = N_("IOThread ID number")
    },
    {.name = "cpulist",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
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
    virDomainPtr dom;
    const char *cpulist = NULL;
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool current = vshCommandOptBool(cmd, "current");
    unsigned int iothread_id = 0;
    int maxcpu;
    bool ret = false;
    unsigned char *cpumap = NULL;
    int cpumaplen;
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;
    virshControlPtr priv = ctl->privData;

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (config)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptUInt(ctl, cmd, "iothread", &iothread_id) < 0)
        goto cleanup;

    if (vshCommandOptStringReq(ctl, cmd, "cpulist", &cpulist) < 0)
        goto cleanup;

    if ((maxcpu = virshNodeGetCPUCount(priv->conn)) < 0)
        goto cleanup;

    if (!(cpumap = virshParseCPUList(ctl, &cpumaplen, cpulist, maxcpu)))
        goto cleanup;

    if (virDomainPinIOThread(dom, iothread_id,
                             cpumap, cpumaplen, flags) != 0)
        goto cleanup;

    ret = true;

 cleanup:
    VIR_FREE(cpumap);
    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
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
    virDomainPtr dom;
    int iothread_id = 0;
    bool ret = false;
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
        goto cleanup;
    if (iothread_id <= 0) {
        vshError(ctl, _("Invalid IOThread id value: '%d'"), iothread_id);
        goto cleanup;
    }

    if (virDomainAddIOThread(dom, iothread_id, flags) < 0)
        goto cleanup;

    ret = true;

 cleanup:
    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "id",
     .type = VSH_OT_INT,
     .flags = VSH_OFLAG_REQ,
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
    virDomainPtr dom;
    int iothread_id = 0;
    bool ret = false;
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
        goto cleanup;
    if (iothread_id <= 0) {
        vshError(ctl, _("Invalid IOThread id value: '%d'"), iothread_id);
        goto cleanup;
    }

    if (virDomainDelIOThread(dom, iothread_id, flags) < 0)
        goto cleanup;

    ret = true;

 cleanup:
    virshDomainFree(dom);
    return ret;
}

/*
 * "cpu-compare" command
 */
static const vshCmdInfo info_cpu_compare[] = {
    {.name = "help",
     .data = N_("compare host CPU with a CPU described by an XML file")
    },
    {.name = "desc",
     .data = N_("compare CPU with host CPU")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_cpu_compare[] = {
    VIRSH_COMMON_OPT_FILE(N_("file containing an XML CPU description")),
    {.name = "error",
     .type = VSH_OT_BOOL,
     .help = N_("report error if CPUs are incompatible")
    },
    {.name = NULL}
};

static bool
cmdCPUCompare(vshControl *ctl, const vshCmd *cmd)
{
    const char *from = NULL;
    bool ret = false;
    char *buffer;
    int result;
    char *snippet = NULL;
    unsigned int flags = 0;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr node;
    virshControlPtr priv = ctl->privData;

    if (vshCommandOptBool(cmd, "error"))
        flags |= VIR_CONNECT_COMPARE_CPU_FAIL_INCOMPATIBLE;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        return false;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    /* try to extract the CPU element from as it would appear in a domain XML*/
    if (!(xml = virXMLParseStringCtxt(buffer, from, &ctxt)))
        goto cleanup;

    if ((node = virXPathNode("/cpu|"
                             "/domain/cpu|"
                              "/capabilities/host/cpu", ctxt))) {
        if (!(snippet = virXMLNodeToString(xml, node))) {
            vshSaveLibvirtError();
            goto cleanup;
        }
    } else {
        vshError(ctl, _("File '%s' does not contain a <cpu> element or is not "
                        "a valid domain or capabilities XML"), from);
        goto cleanup;
    }

    result = virConnectCompareCPU(priv->conn, snippet, flags);

    switch (result) {
    case VIR_CPU_COMPARE_INCOMPATIBLE:
        vshPrint(ctl, _("CPU described in %s is incompatible with host CPU\n"),
                 from);
        goto cleanup;
        break;

    case VIR_CPU_COMPARE_IDENTICAL:
        vshPrint(ctl, _("CPU described in %s is identical to host CPU\n"),
                 from);
        break;

    case VIR_CPU_COMPARE_SUPERSET:
        vshPrint(ctl, _("Host CPU is a superset of CPU described in %s\n"),
                 from);
        break;

    case VIR_CPU_COMPARE_ERROR:
    default:
        vshError(ctl, _("Failed to compare host CPU with %s"), from);
        goto cleanup;
    }

    ret = true;

 cleanup:
    VIR_FREE(buffer);
    VIR_FREE(snippet);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);

    return ret;
}

/*
 * "cpu-baseline" command
 */
static const vshCmdInfo info_cpu_baseline[] = {
    {.name = "help",
     .data = N_("compute baseline CPU")
    },
    {.name = "desc",
     .data = N_("Compute baseline CPU for a set of given CPUs.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_cpu_baseline[] = {
    VIRSH_COMMON_OPT_FILE(N_("file containing XML CPU descriptions")),
    {.name = "features",
     .type = VSH_OT_BOOL,
     .help = N_("Show features that are part of the CPU model type")
    },
    {.name = "migratable",
     .type = VSH_OT_BOOL,
     .help = N_("Do not include features that block migration")
    },
    {.name = NULL}
};

static bool
cmdCPUBaseline(vshControl *ctl, const vshCmd *cmd)
{
    const char *from = NULL;
    bool ret = false;
    char *buffer;
    char *result = NULL;
    char **list = NULL;
    unsigned int flags = 0;
    int count = 0;

    xmlDocPtr xml = NULL;
    xmlNodePtr *node_list = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    size_t i;
    virshControlPtr priv = ctl->privData;

    if (vshCommandOptBool(cmd, "features"))
        flags |= VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES;
    if (vshCommandOptBool(cmd, "migratable"))
        flags |= VIR_CONNECT_BASELINE_CPU_MIGRATABLE;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        return false;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    /* add a separate container around the xml */
    virBufferStrcat(&buf, "<container>", buffer, "</container>", NULL);
    if (virBufferError(&buf))
        goto no_memory;

    VIR_FREE(buffer);
    buffer = virBufferContentAndReset(&buf);


    if (!(xml = virXMLParseStringCtxt(buffer, from, &ctxt)))
        goto cleanup;

    if ((count = virXPathNodeSet("//cpu[not(ancestor::cpus)]",
                                 ctxt, &node_list)) == -1)
        goto cleanup;

    if (count == 0) {
        vshError(ctl, _("No host CPU specified in '%s'"), from);
        goto cleanup;
    }

    list = vshCalloc(ctl, count, sizeof(const char *));

    for (i = 0; i < count; i++) {
        if (!(list[i] = virXMLNodeToString(xml, node_list[i]))) {
            vshSaveLibvirtError();
            goto cleanup;
        }
    }

    result = virConnectBaselineCPU(priv->conn,
                                   (const char **)list, count, flags);

    if (result) {
        vshPrint(ctl, "%s", result);
        ret = true;
    }

 cleanup:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    VIR_FREE(result);
    if (list != NULL && count > 0) {
        for (i = 0; i < count; i++)
            VIR_FREE(list[i]);
    }
    VIR_FREE(list);
    VIR_FREE(buffer);
    VIR_FREE(node_list);

    return ret;

 no_memory:
    vshError(ctl, "%s", _("Out of memory"));
    ret = false;
    goto cleanup;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
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
        char *s = vshGetTypedParamValue(ctl, param);
        vshPrint(ctl, "%s\n", s);
        VIR_FREE(s);
    }
}

static bool
cmdCPUStats(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
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
            vshPrint(ctl, _("Only %d CPUs available to show\n"), max_id);
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

    if (VIR_ALLOC_N(params, nparams * MIN(show_count, 128)) < 0)
        goto cleanup;

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

    if (VIR_ALLOC_N(params, nparams) < 0)
        goto cleanup;

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
    virshDomainFree(dom);
    return ret;

 failed_stats:
    vshError(ctl, _("Failed to retrieve CPU statistics for domain '%s'"),
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
     .help = N_("pass file descriptors N,M,... to the guest")
    },
    {.name = "validate",
     .type = VSH_OT_BOOL,
     .help = N_("validate the XML against the schema")
    },
    {.name = NULL}
};

static bool
cmdCreate(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *from = NULL;
    bool ret = false;
    char *buffer;
#ifndef WIN32
    bool console = vshCommandOptBool(cmd, "console");
#endif
    unsigned int flags = 0;
    size_t nfds = 0;
    int *fds = NULL;
    virshControlPtr priv = ctl->privData;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        return false;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    if (cmdStartGetFDs(ctl, cmd, &nfds, &fds) < 0)
        goto cleanup;

    if (vshCommandOptBool(cmd, "paused"))
        flags |= VIR_DOMAIN_START_PAUSED;
    if (vshCommandOptBool(cmd, "autodestroy"))
        flags |= VIR_DOMAIN_START_AUTODESTROY;
    if (vshCommandOptBool(cmd, "validate"))
        flags |= VIR_DOMAIN_START_VALIDATE;

    if (nfds)
        dom = virDomainCreateXMLWithFiles(priv->conn, buffer, nfds, fds, flags);
    else
        dom = virDomainCreateXML(priv->conn, buffer, flags);

    if (!dom) {
        vshError(ctl, _("Failed to create domain from %s"), from);
        goto cleanup;
    }

    vshPrintExtra(ctl, _("Domain %s created from %s\n"),
                  virDomainGetName(dom), from);
#ifndef WIN32
    if (console)
        cmdRunConsole(ctl, dom, NULL, 0);
#endif
    virshDomainFree(dom);
    ret = true;

 cleanup:
    VIR_FREE(buffer);
    VIR_FREE(fds);
    return ret;
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
    virDomainPtr dom;
    const char *from = NULL;
    bool ret = true;
    char *buffer;
    unsigned int flags = 0;
    virshControlPtr priv = ctl->privData;

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
    VIR_FREE(buffer);

    if (dom != NULL) {
        vshPrintExtra(ctl, _("Domain %s defined from %s\n"),
                      virDomainGetName(dom), from);
        virshDomainFree(dom);
    } else {
        vshError(ctl, _("Failed to define domain from %s"), from);
        ret = false;
    }
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "graceful",
     .type = VSH_OT_BOOL,
     .help = N_("terminate gracefully")
    },
    {.name = NULL}
};

static bool
cmdDestroy(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = true;
    const char *name;
    unsigned int flags = 0;
    int result;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (vshCommandOptBool(cmd, "graceful"))
       flags |= VIR_DOMAIN_DESTROY_GRACEFUL;

    if (flags)
       result = virDomainDestroyFlags(dom, VIR_DOMAIN_DESTROY_GRACEFUL);
    else
       result = virDomainDestroy(dom);

    if (result == 0) {
        vshPrintExtra(ctl, _("Domain %s destroyed\n"), name);
    } else {
        vshError(ctl, _("Failed to destroy domain %s"), name);
        ret = false;
    }

    virshDomainFree(dom);
    return ret;
}

/*
 * "desc" command for managing domain description and title
 */
static const vshCmdInfo info_desc[] = {
    {.name = "help",
     .data = N_("show or set domain's description or title")
    },
    {.name = "desc",
     .data = N_("Allows to show or modify description or title of a domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_desc[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL,
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
    virDomainPtr dom;
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool current = vshCommandOptBool(cmd, "current");

    bool title = vshCommandOptBool(cmd, "title");
    bool edit = vshCommandOptBool(cmd, "edit");

    int state;
    int type;
    char *desc = NULL;
    char *desc_edited = NULL;
    char *tmp = NULL;
    char *tmpstr;
    const vshCmdOpt *opt = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    bool pad = false;
    bool ret = false;
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);

    if (config)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if ((state = virshDomainState(ctl, dom, NULL)) < 0)
        goto cleanup;

    while ((opt = vshCommandOptArgv(ctl, cmd, opt))) {
        if (pad)
            virBufferAddChar(&buf, ' ');
        pad = true;
        virBufferAdd(&buf, opt->data, -1);
    }

    if (title)
        type = VIR_DOMAIN_METADATA_TITLE;
    else
        type = VIR_DOMAIN_METADATA_DESCRIPTION;

    if (virBufferError(&buf)) {
        vshError(ctl, "%s", _("Failed to collect new description/title"));
        goto cleanup;
    }
    desc = virBufferContentAndReset(&buf);

    if (edit || desc) {
        if (!desc) {
                desc = virshGetDomainDescription(ctl, dom, title,
                                           config?VIR_DOMAIN_XML_INACTIVE:0);
                if (!desc)
                    goto cleanup;
        }

        if (edit) {
            /* Create and open the temporary file. */
            if (!(tmp = vshEditWriteToTempFile(ctl, desc)))
                goto cleanup;

            /* Start the editor. */
            if (vshEditFile(ctl, tmp) == -1)
                goto cleanup;

            /* Read back the edited file. */
            if (!(desc_edited = vshEditReadBackFile(ctl, tmp)))
                goto cleanup;

            /* strip a possible newline at the end of file; some
             * editors enforce a newline, this makes editing the title
             * more convenient */
            if (title &&
                (tmpstr = strrchr(desc_edited, '\n')) &&
                *(tmpstr+1) == '\0')
                *tmpstr = '\0';

            /* Compare original XML with edited.  Has it changed at all? */
            if (STREQ(desc, desc_edited)) {
                vshPrintExtra(ctl, "%s",
                              title ? _("Domain title not changed\n") :
                                      _("Domain description not changed\n"));
                ret = true;
                goto cleanup;
            }

            VIR_FREE(desc);
            desc = desc_edited;
            desc_edited = NULL;
        }

        if (virDomainSetMetadata(dom, type, desc, NULL, NULL, flags) < 0) {
            vshError(ctl, "%s",
                     title ? _("Failed to set new domain title") :
                             _("Failed to set new domain description"));
            goto cleanup;
        }
        vshPrintExtra(ctl, "%s",
                      title ? _("Domain title updated successfully") :
                              _("Domain description updated successfully"));
    } else {
        desc = virshGetDomainDescription(ctl, dom, title,
                                       config?VIR_DOMAIN_XML_INACTIVE:0);
        if (!desc)
            goto cleanup;

        if (strlen(desc) > 0)
            vshPrint(ctl, "%s", desc);
        else
            vshPrintExtra(ctl,
                          title ? _("No title for domain: %s") :
                                  _("No description for domain: %s"),
                          virDomainGetName(dom));
    }

    ret = true;
 cleanup:
    VIR_FREE(desc_edited);
    VIR_FREE(desc);
    if (tmp) {
        unlink(tmp);
        VIR_FREE(tmp);
    }
    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
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
virshDomainGetEditMetadata(vshControl *ctl,
                           virDomainPtr dom,
                           const char *uri,
                           unsigned int flags)
{
    char *ret;

    if (!(ret = virDomainGetMetadata(dom, VIR_DOMAIN_METADATA_ELEMENT,
                                     uri, flags))) {
        vshResetLibvirtError();
        ret = vshStrdup(ctl, "\n");
    }

    return ret;
}


static bool
cmdMetadata(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
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
        goto cleanup;

    if ((set || edit) && !key) {
        vshError(ctl, "%s",
                 _("namespace key is required when modifying metadata"));
        goto cleanup;
    }

    if (set || rem) {
        if (virDomainSetMetadata(dom, VIR_DOMAIN_METADATA_ELEMENT,
                                 set, key, uri, flags))
            goto cleanup;

        if (rem)
            vshPrintExtra(ctl, "%s\n", _("Metadata removed"));
        else
            vshPrintExtra(ctl, "%s\n", _("Metadata modified"));
    } else if (edit) {
#define EDIT_GET_XML \
        virshDomainGetEditMetadata(ctl, dom, uri, flags)
#define EDIT_NOT_CHANGED                                        \
        do {                                                    \
            vshPrintExtra(ctl, "%s", _("Metadata not changed")); \
            ret = true;                                         \
            goto edit_cleanup;                                  \
        } while (0)

#define EDIT_DEFINE                                                         \
        (virDomainSetMetadata(dom, VIR_DOMAIN_METADATA_ELEMENT, doc_edited, \
                              key, uri, flags) == 0)
#include "virsh-edit.c"

        vshPrintExtra(ctl, "%s\n", _("Metadata modified"));
    } else {
        char *data;
        /* get */
        if (!(data = virDomainGetMetadata(dom, VIR_DOMAIN_METADATA_ELEMENT,
                                          uri, flags)))
            goto cleanup;

        vshPrint(ctl, "%s\n", data);
        VIR_FREE(data);
    }

    ret = true;

 cleanup:
    virshDomainFree(dom);
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = NULL}
};

static bool
cmdInjectNMI(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = true;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virDomainInjectNMI(dom, 0) < 0)
            ret = false;

    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "codeset",
     .type = VSH_OT_STRING,
     .flags = VSH_OFLAG_REQ_OPT,
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
    virDomainPtr dom;
    bool ret = false;
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
        goto cleanup;

    codeset = virKeycodeSetTypeFromString(codeset_option);
    if (codeset < 0) {
        vshError(ctl, _("unknown codeset: '%s'"), codeset_option);
        goto cleanup;
    }

    while ((opt = vshCommandOptArgv(ctl, cmd, opt))) {
        if (count == VIR_DOMAIN_SEND_KEY_MAX_KEYS) {
            vshError(ctl, _("too many keycodes"));
            goto cleanup;
        }

        if ((keycode = virshKeyCodeGetInt(opt->data)) < 0) {
            if ((keycode = virKeycodeValueFromString(codeset, opt->data)) < 0) {
                vshError(ctl, _("invalid keycode: '%s'"), opt->data);
                goto cleanup;
            }
        }

        keycodes[count] = keycode;
        count++;
    }

    if (!(virDomainSendKey(dom, codeset, holdtime, keycodes, count, 0) < 0))
        ret = true;

 cleanup:
    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "pid",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("the process ID")
    },
    {.name = "signame",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("the signal number or name")
    },
    {.name = NULL}
};

VIR_ENUM_DECL(virDomainProcessSignal)
VIR_ENUM_IMPL(virDomainProcessSignal,
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
              "rt28",   "rt29", "rt30",  "rt31", "rt32") /* 60-64 */

static int getSignalNumber(vshControl *ctl, const char *signame)
{
    size_t i;
    int signum;
    char *lower = vshStrdup(ctl, signame);
    char *tmp = lower;

    for (i = 0; signame[i]; i++)
        lower[i] = c_tolower(signame[i]);

    if (virStrToLong_i(lower, NULL, 10, &signum) >= 0)
        goto cleanup;

    if (STRPREFIX(lower, "sig_"))
        lower += 4;
    else if (STRPREFIX(lower, "sig"))
        lower += 3;

    if ((signum = virDomainProcessSignalTypeFromString(lower)) >= 0)
        goto cleanup;

    signum = -1;
 cleanup:
    VIR_FREE(tmp);
    return signum;
}

static bool
cmdSendProcessSignal(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = false;
    const char *signame;
    long long pid_value;
    int signum;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptLongLong(ctl, cmd, "pid", &pid_value) < 0)
        goto cleanup;

    if (vshCommandOptStringReq(ctl, cmd, "signame", &signame) < 0)
        goto cleanup;

    if ((signum = getSignalNumber(ctl, signame)) < 0) {
        vshError(ctl, _("malformed signal name: %s"), signame);
        goto cleanup;
    }

    if (virDomainSendProcessSignal(dom, pid_value, signum, 0) < 0)
        goto cleanup;

    ret = true;

 cleanup:
    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
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
    virDomainPtr dom;
    unsigned long long bytes = 0;
    unsigned long long max;
    unsigned long kibibytes = 0;
    bool ret = true;
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
    /* none of the options were specified */
    if (!current && !live && !config)
        flags = -1;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    /* The API expects 'unsigned long' KiB, so depending on whether we
     * are 32-bit or 64-bit determines the maximum we can use.  */
    if (sizeof(kibibytes) < sizeof(max))
        max = 1024ull * ULONG_MAX;
    else
        max = ULONG_MAX;
    if (vshCommandOptScaledInt(ctl, cmd, "size", &bytes, 1024, max) < 0) {
        virshDomainFree(dom);
        return false;
    }
    kibibytes = VIR_DIV_UP(bytes, 1024);

    if (flags == -1) {
        if (virDomainSetMemory(dom, kibibytes) != 0)
            ret = false;
    } else {
        if (virDomainSetMemoryFlags(dom, kibibytes, flags) < 0)
            ret = false;
    }

    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
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
    virDomainPtr dom;
    unsigned long long bytes = 0;
    unsigned long long max;
    unsigned long kibibytes = 0;
    bool ret = true;
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool current = vshCommandOptBool(cmd, "current");
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT | VIR_DOMAIN_MEM_MAXIMUM;

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

    /* The API expects 'unsigned long' KiB, so depending on whether we
     * are 32-bit or 64-bit determines the maximum we can use.  */
    if (sizeof(kibibytes) < sizeof(max))
        max = 1024ull * ULONG_MAX;
    else
        max = ULONG_MAX;
    if (vshCommandOptScaledInt(ctl, cmd, "size", &bytes, 1024, max) < 0) {
        virshDomainFree(dom);
        return false;
    }
    kibibytes = VIR_DIV_UP(bytes, 1024);

    if (flags == -1) {
        if (virDomainSetMaxMemory(dom, kibibytes) != 0) {
            vshError(ctl, "%s", _("Unable to change MaxMemorySize"));
            ret = false;
        }
    } else {
        if (virDomainSetMemoryFlags(dom, kibibytes, flags) < 0) {
            vshError(ctl, "%s", _("Unable to change MaxMemorySize"));
            ret = false;
        }
    }

    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
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
    virDomainPtr dom;
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

#define PARSE_MEMTUNE_PARAM(NAME, FIELD)                                    \
    if ((rc = virshMemtuneGetSize(ctl, cmd, NAME, &tmpVal)) < 0) {            \
        vshError(ctl, _("Unable to parse integer parameter %s"), NAME);     \
        goto cleanup;                                                       \
    }                                                                       \
    if (rc == 1) {                                                          \
        if (virTypedParamsAddULLong(&params, &nparams, &maxparams,          \
                                    FIELD, tmpVal) < 0)                     \
            goto save_error;                                                \
    }                                                                       \


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
        params = vshCalloc(ctl, nparams, sizeof(*params));
        if (virDomainGetMemoryParameters(dom, params, &nparams, flags) != 0) {
            vshError(ctl, "%s", _("Unable to get memory parameters"));
            goto cleanup;
        }

        for (i = 0; i < nparams; i++) {
            if (params[i].type == VIR_TYPED_PARAM_ULLONG &&
                params[i].value.ul == VIR_DOMAIN_MEMORY_PARAM_UNLIMITED) {
                vshPrint(ctl, "%-15s: %s\n", params[i].field, _("unlimited"));
            } else {
                char *str = vshGetTypedParamValue(ctl, &params[i]);
                vshPrint(ctl, "%-15s: %s\n", params[i].field, str);
                VIR_FREE(str);
            }
        }
    } else {
        if (virDomainSetMemoryParameters(dom, params, nparams, flags) != 0)
            goto error;
    }

    ret = true;

 cleanup:
    virTypedParamsFree(params, nparams);
    virshDomainFree(dom);
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "enable",
     .type = VSH_OT_STRING,
     .help = N_("perf events which will be enabled")
    },
    {.name = "disable",
     .type = VSH_OT_STRING,
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
    char **tok = NULL;
    size_t i, ntok;
    int ret = -1;

    if (!(tok = virStringSplitCount(event, ",", 0, &ntok)))
        return -1;

    for (i = 0; i < ntok; i++) {
        if ((*tok[i] != '\0') &&
            virTypedParamsAddBoolean(params, nparams,
                                     maxparams, tok[i], state) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    virStringListFree(tok);
    return ret;
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
    virDomainPtr dom;
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
    virshDomainFree(dom);
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "mode",
     .type = VSH_OT_STRING,
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
    virDomainPtr dom;
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
            vshError(ctl, _("Invalid mode: %s"), mode);
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
        params = vshCalloc(ctl, nparams, sizeof(*params));
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
                char *str = vshGetTypedParamValue(ctl, &params[i]);
                vshPrint(ctl, "%-15s: %s\n", params[i].field, str);
                VIR_FREE(str);
            }
        }
    } else {
        if (virDomainSetNumaParameters(dom, params, nparams, flags) != 0)
            goto error;
    }

    ret = true;

 cleanup:
    virTypedParamsFree(params, nparams);
    virshDomainFree(dom);
    return ret;

 save_error:
    vshSaveLibvirtError();
 error:
    vshError(ctl, "%s", _("Unable to change numa parameters"));
    goto cleanup;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "hmp",
     .type = VSH_OT_BOOL,
     .help = N_("command is in human monitor protocol")
    },
    {.name = "pretty",
     .type = VSH_OT_BOOL,
     .help = N_("pretty-print any qemu monitor protocol output")
    },
    {.name = "cmd",
     .type = VSH_OT_ARGV,
     .flags = VSH_OFLAG_REQ,
     .help = N_("command")
    },
    {.name = NULL}
};

static bool
cmdQemuMonitorCommand(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    char *monitor_cmd = NULL;
    char *result = NULL;
    unsigned int flags = 0;
    const vshCmdOpt *opt = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virJSONValuePtr pretty = NULL;

    VSH_EXCLUSIVE_OPTIONS("hmp", "pretty");

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    while ((opt = vshCommandOptArgv(ctl, cmd, opt)))
        virBufferAsprintf(&buf, "%s ", opt->data);

    virBufferTrim(&buf, " ", -1);

    if (virBufferError(&buf)) {
        vshError(ctl, "%s", _("Failed to collect command"));
        goto cleanup;
    }
    monitor_cmd = virBufferContentAndReset(&buf);

    if (vshCommandOptBool(cmd, "hmp"))
        flags |= VIR_DOMAIN_QEMU_MONITOR_COMMAND_HMP;

    if (virDomainQemuMonitorCommand(dom, monitor_cmd, &result, flags) < 0)
        goto cleanup;

    if (vshCommandOptBool(cmd, "pretty")) {
        char *tmp;
        pretty = virJSONValueFromString(result);
        if (pretty && (tmp = virJSONValueToString(pretty, true))) {
            VIR_FREE(result);
            result = tmp;
            virTrimSpaces(result, NULL);
        } else {
            vshResetLibvirtError();
        }
    }
    vshPrint(ctl, "%s\n", result);

    ret = true;

 cleanup:
    VIR_FREE(result);
    VIR_FREE(monitor_cmd);
    virJSONValueFree(pretty);
    virshDomainFree(dom);

    return ret;
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
virshEventQemuPrint(virConnectPtr conn ATTRIBUTE_UNUSED,
                    virDomainPtr dom,
                    const char *event,
                    long long seconds,
                    unsigned int micros,
                    const char *details,
                    void *opaque)
{
    virshQemuEventData *data = opaque;
    virJSONValuePtr pretty = NULL;
    char *str = NULL;

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

        vshPrint(data->ctl, "%s: event %s for domain %s: %s\n",
                 timestamp, event, virDomainGetName(dom), NULLSTR(details));
    } else {
        vshPrint(data->ctl, "event %s at %lld.%06u for domain %s: %s\n",
                 event, seconds, micros, virDomainGetName(dom), NULLSTR(details));
    }

    data->count++;
    if (!data->loop)
        vshEventDone(data->ctl);

    VIR_FREE(str);
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
    {.name = "domain",
     .type = VSH_OT_STRING,
     .help = N_("filter by domain name, id or uuid")
    },
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
    virDomainPtr dom = NULL;
    bool ret = false;
    unsigned int flags = 0;
    int eventId = -1;
    int timeout = 0;
    const char *event = NULL;
    virshQemuEventData data;
    virshControlPtr priv = ctl->privData;

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
        dom = virshCommandOptDomain(ctl, cmd, NULL);
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
    vshPrint(ctl, _("events received: %d\n"), data.count);
    if (data.count)
        ret = true;

 cleanup:
    vshEventCleanup(ctl);
    if (eventId >= 0 &&
        virConnectDomainQemuMonitorEventDeregister(priv->conn, eventId) < 0)
        ret = false;
    virshDomainFree(dom);

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
     .help = N_("pid")
    },
    {.name = NULL}
};

static bool
cmdQemuAttach(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    unsigned int flags = 0;
    unsigned int pid_value; /* API uses unsigned int, not pid_t */
    virshControlPtr priv = ctl->privData;

    if (vshCommandOptUInt(ctl, cmd, "pid", &pid_value) <= 0)
        goto cleanup;

    if (!(dom = virDomainQemuAttach(priv->conn, pid_value, flags))) {
        vshError(ctl, _("Failed to attach to pid %u"), pid_value);
        goto cleanup;
    }

    vshPrintExtra(ctl, _("Domain %s attached to pid %u\n"),
                  virDomainGetName(dom), pid_value);
    virshDomainFree(dom);
    ret = true;

 cleanup:
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
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
    virDomainPtr dom = NULL;
    bool ret = false;
    char *guest_agent_cmd = NULL;
    char *result = NULL;
    int timeout = VIR_DOMAIN_QEMU_AGENT_COMMAND_DEFAULT;
    int judge = 0;
    unsigned int flags = 0;
    const vshCmdOpt *opt = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    bool pad = false;
    virJSONValuePtr pretty = NULL;

    dom = virshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    while ((opt = vshCommandOptArgv(ctl, cmd, opt))) {
        if (pad)
            virBufferAddChar(&buf, ' ');
        pad = true;
        virBufferAdd(&buf, opt->data, -1);
    }
    if (virBufferError(&buf)) {
        vshError(ctl, "%s", _("Failed to collect command"));
        goto cleanup;
    }
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
    VIR_FREE(guest_agent_cmd);
    virshDomainFree(dom);

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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
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
    virDomainPtr dom = NULL;
    bool ret = false;
    const vshCmdOpt *opt = NULL;
    char **cmdargv = NULL;
    size_t ncmdargv = 0;
    pid_t pid;
    int nfdlist;
    int *fdlist;
    size_t i;
    bool setlabel = true;
    virSecurityModelPtr secmodel = NULL;
    virSecurityLabelPtr seclabel = NULL;
    virshControlPtr priv = ctl->privData;

    dom = virshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    if (vshCommandOptBool(cmd, "noseclabel"))
        setlabel = false;

    while ((opt = vshCommandOptArgv(ctl, cmd, opt))) {
        if (VIR_EXPAND_N(cmdargv, ncmdargv, 1) < 0) {
            vshError(ctl, _("%s: %d: failed to allocate argv"),
                     __FILE__, __LINE__);
        }
        cmdargv[ncmdargv-1] = opt->data;
    }
    if (VIR_EXPAND_N(cmdargv, ncmdargv, 1) < 0) {
        vshError(ctl, _("%s: %d: failed to allocate argv"),
                 __FILE__, __LINE__);
    }
    cmdargv[ncmdargv - 1] = NULL;

    if ((nfdlist = virDomainLxcOpenNamespace(dom, &fdlist, 0)) < 0)
        goto cleanup;

    if (setlabel) {
        if (VIR_ALLOC(secmodel) < 0) {
            vshError(ctl, "%s", _("Failed to allocate security model"));
            goto cleanup;
        }
        if (VIR_ALLOC(seclabel) < 0) {
            vshError(ctl, "%s", _("Failed to allocate security label"));
            goto cleanup;
        }
        if (virNodeGetSecurityModel(priv->conn, secmodel) < 0)
            goto cleanup;
        if (virDomainGetSecurityLabel(dom, seclabel) < 0)
            goto cleanup;
    }

    /* Fork once because we don't want to affect
     * virsh's namespace itself, and because user namespace
     * can only be changed in single-threaded process
     */
    if ((pid = virFork()) < 0)
        goto cleanup;
    if (pid == 0) {
        int status;

        if (setlabel &&
            virDomainLxcEnterSecurityLabel(secmodel,
                                           seclabel,
                                           NULL,
                                           0) < 0)
            _exit(EXIT_CANCELED);

        if (virDomainLxcEnterCGroup(dom, 0) < 0)
            _exit(EXIT_CANCELED);

        if (virDomainLxcEnterNamespace(dom,
                                       nfdlist,
                                       fdlist,
                                       NULL,
                                       NULL,
                                       0) < 0)
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
    } else {
        for (i = 0; i < nfdlist; i++)
            VIR_FORCE_CLOSE(fdlist[i]);
        VIR_FREE(fdlist);
        if (virProcessWait(pid, NULL, false) < 0) {
            vshReportError(ctl);
            goto cleanup;
        }
    }

    ret = true;

 cleanup:
    VIR_FREE(seclabel);
    VIR_FREE(secmodel);
    virshDomainFree(dom);
    VIR_FREE(cmdargv);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
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
    {.name = NULL}
};

static bool
cmdDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = true;
    char *dump;
    unsigned int flags = 0;
    bool inactive = vshCommandOptBool(cmd, "inactive");
    bool secure = vshCommandOptBool(cmd, "security-info");
    bool update = vshCommandOptBool(cmd, "update-cpu");
    bool migratable = vshCommandOptBool(cmd, "migratable");

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

    dump = virDomainGetXMLDesc(dom, flags);
    if (dump != NULL) {
        vshPrint(ctl, "%s", dump);
        VIR_FREE(dump);
    } else {
        ret = false;
    }

    virshDomainFree(dom);
    return ret;
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
     .help = N_("config data file to import from")
    },
    {.name = NULL}
};

static bool
cmdDomXMLFromNative(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = true;
    const char *format = NULL;
    const char *configFile = NULL;
    char *configData;
    char *xmlData;
    unsigned int flags = 0;
    virshControlPtr priv = ctl->privData;

    if (vshCommandOptStringReq(ctl, cmd, "format", &format) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "config", &configFile) < 0)
        return false;

    if (virFileReadAll(configFile, VSH_MAX_XML_FILE, &configData) < 0)
        return false;

    xmlData = virConnectDomainXMLFromNative(priv->conn, format, configData, flags);
    if (xmlData != NULL) {
        vshPrint(ctl, "%s", xmlData);
        VIR_FREE(xmlData);
    } else {
        ret = false;
    }

    VIR_FREE(configData);
    return ret;
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
    {.name = "xml",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("xml data file to export from")
    },
    {.name = NULL}
};

static bool
cmdDomXMLToNative(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = true;
    const char *format = NULL;
    const char *xmlFile = NULL;
    char *configData;
    char *xmlData;
    unsigned int flags = 0;
    virshControlPtr priv = ctl->privData;

    if (vshCommandOptStringReq(ctl, cmd, "format", &format) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "xml", &xmlFile) < 0)
        return false;

    if (virFileReadAll(xmlFile, VSH_MAX_XML_FILE, &xmlData) < 0)
        return false;

    configData = virConnectDomainXMLToNative(priv->conn, format, xmlData, flags);
    if (configData != NULL) {
        vshPrint(ctl, "%s", configData);
        VIR_FREE(configData);
    } else {
        ret = false;
    }

    VIR_FREE(xmlData);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN(N_("domain id or uuid")),
    {.name = NULL}
};

static bool
cmdDomname(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;

    if (!(dom = virshCommandOptDomainBy(ctl, cmd, NULL,
                                        VIRSH_BYID|VIRSH_BYUUID)))
        return false;

    vshPrint(ctl, "%s\n", virDomainGetName(dom));
    virshDomainFree(dom);
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "new-name",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("new domain name")
    },
    {.name = NULL}
};

static bool
cmdDomrename(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *new_name = NULL;
    bool ret = false;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return ret;

    if (vshCommandOptStringReq(ctl, cmd, "new-name", &new_name) < 0)
        goto cleanup;

    if (virDomainRename(dom, new_name, 0) < 0)
        goto cleanup;

    vshPrintExtra(ctl, "Domain successfully renamed\n");
    ret = true;

 cleanup:
    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN(N_("domain name or uuid")),
    {.name = NULL}
};

static bool
cmdDomid(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    unsigned int id;

    if (!(dom = virshCommandOptDomainBy(ctl, cmd, NULL,
                                        VIRSH_BYNAME|VIRSH_BYUUID)))
        return false;

    id = virDomainGetID(dom);
    if (id == ((unsigned int)-1))
        vshPrint(ctl, "%s\n", "-");
    else
        vshPrint(ctl, "%d\n", id);
    virshDomainFree(dom);
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
    VIRSH_COMMON_OPT_DOMAIN(N_("domain id or name")),
    {.name = NULL}
};

static bool
cmdDomuuid(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (!(dom = virshCommandOptDomainBy(ctl, cmd, NULL,
                                        VIRSH_BYNAME|VIRSH_BYID)))
        return false;

    if (virDomainGetUUIDString(dom, uuid) != -1)
        vshPrint(ctl, "%s\n", uuid);
    else
        vshError(ctl, "%s", _("failed to get domain UUID"));

    virshDomainFree(dom);
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "desturi",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
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
    {.name = "migrateuri",
     .type = VSH_OT_STRING,
     .help = N_("migration URI, usually can be omitted")
    },
    {.name = "graphicsuri",
     .type = VSH_OT_STRING,
     .help = N_("graphics URI to be used for seamless graphics migration")
    },
    {.name = "listen-address",
     .type = VSH_OT_STRING,
     .help = N_("listen address that destination should bind to for incoming migration")
    },
    {.name = "dname",
     .type = VSH_OT_STRING,
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
     .help = N_("filename containing updated XML for the target")
    },
    {.name = "migrate-disks",
     .type = VSH_OT_STRING,
     .help = N_("comma separated list of disks to be migrated")
    },
    {.name = "disks-port",
     .type = VSH_OT_INT,
     .help = N_("port to use by target server for incoming disks migration")
    },
    {.name = "comp-methods",
     .type = VSH_OT_STRING,
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
     .help = N_("filename containing updated persistent XML for the target")
    },
    {.name = "tls",
     .type = VSH_OT_BOOL,
     .help = N_("use TLS for migration")
    },
    {.name = NULL}
};

static void
doMigrate(void *opaque)
{
    char ret = '1';
    virDomainPtr dom = NULL;
    const char *desturi = NULL;
    const char *opt = NULL;
    int disksPort = 0;
    unsigned int flags = 0;
    virshCtrlData *data = opaque;
    vshControl *ctl = data->ctl;
    const vshCmd *cmd = data->cmd;
    sigset_t sigmask, oldsigmask;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    int maxparams = 0;
    int intOpt = 0;
    unsigned long long ullOpt = 0;
    int rv;
    virConnectPtr dconn = data->dconn;

    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);
    if (pthread_sigmask(SIG_BLOCK, &sigmask, &oldsigmask) < 0)
        goto out_sig;

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

    if (vshCommandOptInt(ctl, cmd, "disks-port", &disksPort) < 0)
        goto out;
    if (disksPort &&
        virTypedParamsAddInt(&params, &nparams, &maxparams,
                             VIR_MIGRATE_PARAM_DISKS_PORT, disksPort) < 0)
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
        char **val = NULL;

        val = virStringSplit(opt, ",", 0);

        if (virTypedParamsAddStringList(&params,
                                        &nparams,
                                        &maxparams,
                                        VIR_MIGRATE_PARAM_MIGRATE_DISKS,
                                        (const char **)val) < 0) {
            VIR_FREE(val);
            goto save_error;
        }

        VIR_FREE(val);
    }

    if (vshCommandOptStringReq(ctl, cmd, "comp-methods", &opt) < 0)
        goto out;
    if (opt) {
        char **val = virStringSplit(opt, ",", 0);

        if (virTypedParamsAddStringList(&params,
                                        &nparams,
                                        &maxparams,
                                        VIR_MIGRATE_PARAM_COMPRESSION,
                                        (const char **)val) < 0) {
            VIR_FREE(val);
            goto save_error;
        }

        VIR_FREE(val);
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
        char *xml;

        if (virFileReadAll(opt, VSH_MAX_XML_FILE, &xml) < 0) {
            vshError(ctl, _("cannot read file '%s'"), opt);
            goto save_error;
        }

        if (virTypedParamsAddString(&params, &nparams, &maxparams,
                                    VIR_MIGRATE_PARAM_DEST_XML, xml) < 0) {
            VIR_FREE(xml);
            goto save_error;
        }
        VIR_FREE(xml);
    }

    if (vshCommandOptStringReq(ctl, cmd, "persistent-xml", &opt) < 0)
        goto out;
    if (opt) {
        char *xml;

        if (virFileReadAll(opt, VSH_MAX_XML_FILE, &xml) < 0) {
            vshError(ctl, _("cannot read file '%s'"), opt);
            goto save_error;
        }

        if (virTypedParamsAddString(&params, &nparams, &maxparams,
                                    VIR_MIGRATE_PARAM_PERSIST_XML, xml) < 0) {
            VIR_FREE(xml);
            goto save_error;
        }
        VIR_FREE(xml);
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

    if (vshCommandOptBool(cmd, "live"))
        flags |= VIR_MIGRATE_LIVE;
    if (vshCommandOptBool(cmd, "p2p"))
        flags |= VIR_MIGRATE_PEER2PEER;
    if (vshCommandOptBool(cmd, "tunnelled"))
        flags |= VIR_MIGRATE_TUNNELLED;

    if (vshCommandOptBool(cmd, "persistent"))
        flags |= VIR_MIGRATE_PERSIST_DEST;
    if (vshCommandOptBool(cmd, "undefinesource"))
        flags |= VIR_MIGRATE_UNDEFINE_SOURCE;

    if (vshCommandOptBool(cmd, "suspend"))
        flags |= VIR_MIGRATE_PAUSED;

    if (vshCommandOptBool(cmd, "copy-storage-all"))
        flags |= VIR_MIGRATE_NON_SHARED_DISK;

    if (vshCommandOptBool(cmd, "copy-storage-inc"))
        flags |= VIR_MIGRATE_NON_SHARED_INC;

    if (vshCommandOptBool(cmd, "change-protection"))
        flags |= VIR_MIGRATE_CHANGE_PROTECTION;

    if (vshCommandOptBool(cmd, "unsafe"))
        flags |= VIR_MIGRATE_UNSAFE;

    if (vshCommandOptBool(cmd, "compressed"))
        flags |= VIR_MIGRATE_COMPRESSED;

    if (vshCommandOptBool(cmd, "auto-converge"))
        flags |= VIR_MIGRATE_AUTO_CONVERGE;

    if (vshCommandOptBool(cmd, "rdma-pin-all"))
        flags |= VIR_MIGRATE_RDMA_PIN_ALL;

    if (vshCommandOptBool(cmd, "offline"))
        flags |= VIR_MIGRATE_OFFLINE;

    if (vshCommandOptBool(cmd, "abort-on-error"))
        flags |= VIR_MIGRATE_ABORT_ON_ERROR;

    if (vshCommandOptBool(cmd, "postcopy"))
        flags |= VIR_MIGRATE_POSTCOPY;

    if (vshCommandOptBool(cmd, "tls"))
        flags |= VIR_MIGRATE_TLS;

    if (flags & VIR_MIGRATE_PEER2PEER || vshCommandOptBool(cmd, "direct")) {
        if (virDomainMigrateToURI3(dom, desturi, params, nparams, flags) == 0)
            ret = '0';
    } else {
        /* For traditional live migration, connect to the destination host directly. */
        virDomainPtr ddom = NULL;

        if ((ddom = virDomainMigrate3(dom, dconn, params, nparams, flags))) {
            virshDomainFree(ddom);
            ret = '0';
        }
    }

 out:
    pthread_sigmask(SIG_SETMASK, &oldsigmask, NULL);
 out_sig:
    virTypedParamsFree(params, nparams);
    virshDomainFree(dom);
    ignore_value(safewrite(data->writefd, &ret, sizeof(ret)));
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
virshMigrateIteration(virConnectPtr conn ATTRIBUTE_UNUSED,
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
    virDomainPtr dom = NULL;
    int p[2] = {-1, -1};
    virThread workerThread;
    bool verbose = false;
    bool functionReturn = false;
    int timeout = 0;
    virshMigrateTimeoutAction timeoutAction = VIRSH_MIGRATE_TIMEOUT_DEFAULT;
    bool live_flag = false;
    virshCtrlData data = { .dconn = NULL };
    virshControlPtr priv = ctl->privData;
    int iterEvent = -1;

    VSH_EXCLUSIVE_OPTIONS("live", "offline");
    VSH_EXCLUSIVE_OPTIONS("timeout-suspend", "timeout-postcopy");
    VSH_REQUIRE_OPTION("postcopy-after-precopy", "postcopy");
    VSH_REQUIRE_OPTION("persistent-xml", "persistent");

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptBool(cmd, "verbose"))
        verbose = true;

    if (vshCommandOptBool(cmd, "live"))
        live_flag = true;
    if (vshCommandOptTimeoutToMs(ctl, cmd, &timeout) < 0) {
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

    if (pipe(p) < 0)
        goto cleanup;

    data.ctl = ctl;
    data.cmd = cmd;
    data.writefd = p[1];

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
    functionReturn = virshWatchJob(ctl, dom, verbose, p[0], timeout,
                                   virshMigrateTimeout,
                                   &timeoutAction, _("Migration"));

    virThreadJoin(&workerThread);

 cleanup:
    if (data.dconn)
        virConnectClose(data.dconn);
    if (iterEvent != -1)
        virConnectDomainEventDeregisterAny(priv->conn, iterEvent);
    virshDomainFree(dom);
    VIR_FORCE_CLOSE(p[0]);
    VIR_FORCE_CLOSE(p[1]);
    return functionReturn;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
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
    virDomainPtr dom = NULL;
    long long downtime = 0;
    bool ret = false;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptLongLong(ctl, cmd, "downtime", &downtime) < 0)
        goto done;
    if (downtime < 1) {
        vshError(ctl, "%s", _("migrate: Invalid downtime"));
        goto done;
    }

    if (virDomainMigrateSetMaxDowntime(dom, downtime, 0))
        goto done;

    ret = true;

 done:
    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
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
    virDomainPtr dom = NULL;
    unsigned long long size = 0;
    bool ret = false;
    const char *unit;
    double value;
    int rc;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    rc = vshCommandOptULongLong(ctl, cmd, "size", &size);
    if (rc < 0) {
        goto cleanup;
    } else if (rc != 0) {
        if (virDomainMigrateSetCompressionCache(dom, size, 0) < 0)
            goto cleanup;
    }

    if (virDomainMigrateGetCompressionCache(dom, &size, 0) < 0)
        goto cleanup;

    value = vshPrettyCapacity(size, &unit);
    vshPrint(ctl, _("Compression cache: %.3lf %s"), value, unit);

    ret = true;
 cleanup:
    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "bandwidth",
     .type = VSH_OT_INT,
     .flags = VSH_OFLAG_REQ,
     .help = N_("migration bandwidth limit in MiB/s")
    },
    {.name = NULL}
};

static bool
cmdMigrateSetMaxSpeed(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    unsigned long bandwidth = 0;
    bool ret = false;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptULWrap(ctl, cmd, "bandwidth", &bandwidth) < 0)
        goto done;

    if (virDomainMigrateSetMaxSpeed(dom, bandwidth, 0) < 0)
        goto done;

    ret = true;

 done:
    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = NULL}
};

static bool
cmdMigrateGetMaxSpeed(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    unsigned long bandwidth;
    bool ret = false;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virDomainMigrateGetMaxSpeed(dom, &bandwidth, 0) < 0)
        goto done;

    vshPrint(ctl, "%lu\n", bandwidth);

    ret = true;

 done:
    virshDomainFree(dom);
    return ret;
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
    {.name = "domain",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("domain name, id or uuid")
    },
    {.name = NULL}
};

static bool
cmdMigratePostCopy(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = false;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virDomainMigrateStartPostCopy(dom, 0) < 0)
        goto cleanup;

    ret = true;

 cleanup:
    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "include-password",
     .type = VSH_OT_BOOL,
     .help = N_("includes the password into the connection URI if available")
    },
    {.name = "type",
     .type = VSH_OT_STRING,
     .help = N_("select particular graphical display "
                "(e.g. \"vnc\", \"spice\", \"rdp\")")
    },
    {.name = "all",
     .type = VSH_OT_BOOL,
     .help = N_("show all possible graphical displays")
    },
    {.name = NULL}
};

static bool
cmdDomDisplay(vshControl *ctl, const vshCmd *cmd)
{
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virDomainPtr dom;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    bool ret = false;
    char *xpath = NULL;
    char *listen_addr = NULL;
    int port, tls_port = 0;
    char *passwd = NULL;
    char *output = NULL;
    const char *scheme[] = { "vnc", "spice", "rdp", NULL };
    const char *type = NULL;
    int iter = 0;
    int tmp;
    int flags = 0;
    bool params = false;
    bool all = vshCommandOptBool(cmd, "all");
    const char *xpath_fmt = "string(/domain/devices/graphics[@type='%s']/%s)";
    virSocketAddr addr;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (!virDomainIsActive(dom)) {
        vshError(ctl, _("Domain is not running"));
        goto cleanup;
    }

    if (vshCommandOptBool(cmd, "include-password"))
        flags |= VIR_DOMAIN_XML_SECURE;

    if (vshCommandOptStringReq(ctl, cmd, "type", &type) < 0)
        goto cleanup;

    if (virshDomainGetXMLFromDom(ctl, dom, flags, &xml, &ctxt) < 0)
        goto cleanup;

    /* Attempt to grab our display info */
    for (iter = 0; scheme[iter] != NULL; iter++) {
        /* Particular scheme requested */
        if (!all && type && STRNEQ(type, scheme[iter]))
            continue;

        /* Create our XPATH lookup for the current display's port */
        VIR_FREE(xpath);
        if (virAsprintf(&xpath, xpath_fmt, scheme[iter], "@port") < 0)
            goto cleanup;

        /* Attempt to get the port number for the current graphics scheme */
        tmp = virXPathInt(xpath, ctxt, &port);
        VIR_FREE(xpath);

        /* If there is no port number for this type, then jump to the next
         * scheme */
        if (tmp)
            port = 0;

        /* Create our XPATH lookup for TLS Port (automatically skipped
         * for unsupported schemes */
        if (virAsprintf(&xpath, xpath_fmt, scheme[iter], "@tlsPort") < 0)
            goto cleanup;

        /* Attempt to get the TLS port number */
        tmp = virXPathInt(xpath, ctxt, &tls_port);
        VIR_FREE(xpath);
        if (tmp)
            tls_port = 0;

        if (!port && !tls_port)
            continue;

        /* Create our XPATH lookup for the current display's address */
        if (virAsprintf(&xpath, xpath_fmt, scheme[iter], "@listen") < 0)
            goto cleanup;

        /* Attempt to get the listening addr if set for the current
         * graphics scheme */
        VIR_FREE(listen_addr);
        listen_addr = virXPathString(xpath, ctxt);
        VIR_FREE(xpath);

        if (!listen_addr) {
            /* The subelement address - <listen address='xyz'/> -
             * *should* have been automatically backfilled into its
             * parent <graphics listen='xyz'> (which we just tried to
             * retrieve into listen_addr above) but in some cases it
             * isn't, so we also do an explicit check for the
             * subelement (which, by the way, doesn't exist on libvirt
             * < 0.9.4, so we really do need to check both places)
             */
            if (virAsprintf(&xpath, xpath_fmt, scheme[iter], "listen/@address") < 0)
                goto cleanup;

            listen_addr = virXPathString(xpath, ctxt);
            VIR_FREE(xpath);
        }

        /* If listen_addr is 0.0.0.0 or [::] we should try to parse URI and set
         * listen_addr based on current URI. */
        if (listen_addr) {
            if (virSocketAddrParse(&addr, listen_addr, AF_UNSPEC) > 0 &&
                virSocketAddrIsWildcard(&addr)) {

                virConnectPtr conn = ((virshControlPtr)(ctl->privData))->conn;
                char *uriStr = virConnectGetURI(conn);
                virURIPtr uri = NULL;

                if (uriStr) {
                    uri = virURIParse(uriStr);
                    VIR_FREE(uriStr);
                }

                /* It's safe to free the listen_addr even if parsing of URI
                 * fails, if there is no listen_addr we will print "localhost". */
                VIR_FREE(listen_addr);

                if (uri) {
                    listen_addr = vshStrdup(ctl, uri->server);
                    virURIFree(uri);
                }
            }
        }

        /* We can query this info for all the graphics types since we'll
         * get nothing for the unsupported ones (just rdp for now).
         * Also the parameter '--include-password' was already taken
         * care of when getting the XML */

        /* Create our XPATH lookup for the password */
        if (virAsprintf(&xpath, xpath_fmt, scheme[iter], "@passwd") < 0)
            goto cleanup;

        /* Attempt to get the password */
        VIR_FREE(passwd);
        passwd = virXPathString(xpath, ctxt);
        VIR_FREE(xpath);

        /* Build up the full URI, starting with the scheme */
        virBufferAsprintf(&buf, "%s://", scheme[iter]);

        /* There is no user, so just append password if there's any */
        if (STREQ(scheme[iter], "vnc") && passwd)
            virBufferAsprintf(&buf, ":%s@", passwd);

        /* Then host name or IP */
        if (!listen_addr)
            virBufferAddLit(&buf, "localhost");
        else if (strchr(listen_addr, ':'))
            virBufferAsprintf(&buf, "[%s]", listen_addr);
        else
            virBufferAsprintf(&buf, "%s", listen_addr);

        /* Add the port */
        if (port) {
            if (STREQ(scheme[iter], "vnc")) {
                /* VNC protocol handlers take their port number as
                 * 'port' - 5900 */
                port -= 5900;
            }

            virBufferAsprintf(&buf, ":%d", port);
        }

        /* TLS Port */
        if (tls_port) {
            virBufferAsprintf(&buf,
                              "?tls-port=%d",
                              tls_port);
            params = true;
        }

        if (STREQ(scheme[iter], "spice") && passwd) {
            virBufferAsprintf(&buf,
                              "%spassword=%s",
                              params ? "&" : "?",
                              passwd);
            params = true;
        }

        /* Ensure we can print our URI */
        if (virBufferError(&buf)) {
            vshError(ctl, "%s", _("Failed to create display URI"));
            goto cleanup;
        }

        /* Print out our full URI */
        VIR_FREE(output);
        output = virBufferContentAndReset(&buf);
        vshPrint(ctl, "%s", output);

        /* We got what we came for so return successfully */
        ret = true;
        if (!all) {
            break;
        } else {
            vshPrint(ctl, "\n");
        }
    }

    if (!ret) {
        if (type)
            vshError(ctl, _("No graphical display with type '%s' found"), type);
        else
            vshError(ctl, _("No graphical display found"));
    }

 cleanup:
    VIR_FREE(xpath);
    VIR_FREE(passwd);
    VIR_FREE(listen_addr);
    VIR_FREE(output);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = NULL}
};

static bool
cmdVNCDisplay(vshControl *ctl, const vshCmd *cmd)
{
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virDomainPtr dom;
    bool ret = false;
    int port = 0;
    char *listen_addr = NULL;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    /* Check if the domain is active and don't rely on -1 for this */
    if (!virDomainIsActive(dom)) {
        vshError(ctl, _("Domain is not running"));
        goto cleanup;
    }

    if (virshDomainGetXMLFromDom(ctl, dom, 0, &xml, &ctxt) < 0)
        goto cleanup;

    /* Get the VNC port */
    if (virXPathInt("string(/domain/devices/graphics[@type='vnc']/@port)",
                    ctxt, &port)) {
        vshError(ctl, _("Failed to get VNC port. Is this domain using VNC?"));
        goto cleanup;
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

    ret = true;

 cleanup:
    VIR_FREE(listen_addr);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = NULL}
};

static bool
cmdTTYConsole(vshControl *ctl, const vshCmd *cmd)
{
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    bool ret = false;
    char *tty = NULL;

    if (virshDomainGetXML(ctl, cmd, 0, &xml, &ctxt) < 0)
        return false;

    if (!(tty = virXPathString("string(/domain/devices/console/@tty)", ctxt)))
        goto cleanup;

    vshPrint(ctl, "%s\n", tty);
    ret = true;

 cleanup:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    VIR_FREE(tty);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = NULL}
};

static bool
cmdDomHostname(vshControl *ctl, const vshCmd *cmd)
{
    char *hostname;
    virDomainPtr dom;
    bool ret = false;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    hostname = virDomainGetHostname(dom, 0);
    if (hostname == NULL) {
        vshError(ctl, "%s", _("failed to get hostname"));
        goto error;
    }

    vshPrint(ctl, "%s\n", hostname);
    ret = true;

 error:
    VIR_FREE(hostname);
    virshDomainFree(dom);
    return ret;
}

/**
 * Check if n1 is superset of n2, meaning n1 contains all elements and
 * attributes as n2 at least. Including children.
 * @n1 first node
 * @n2 second node
 * returns true in case n1 covers n2, false otherwise.
 */
ATTRIBUTE_UNUSED
static bool
virshNodeIsSuperset(xmlNodePtr n1, xmlNodePtr n2)
{
    xmlNodePtr child1, child2;
    xmlAttrPtr attr;
    char *prop1, *prop2;
    bool found;
    bool visited;
    bool ret = false;
    long n1_child_size, n2_child_size, n1_iter;
    virBitmapPtr bitmap;

    if (!n1 && !n2)
        return true;

    if (!n1 || !n2)
        return false;

    if (!xmlStrEqual(n1->name, n2->name))
        return false;

    /* Iterate over n2 attributes and check if n1 contains them*/
    attr = n2->properties;
    while (attr) {
        if (attr->type == XML_ATTRIBUTE_NODE) {
            prop1 = virXMLPropString(n1, (const char *) attr->name);
            prop2 = virXMLPropString(n2, (const char *) attr->name);
            if (STRNEQ_NULLABLE(prop1, prop2)) {
                xmlFree(prop1);
                xmlFree(prop2);
                return false;
            }
            xmlFree(prop1);
            xmlFree(prop2);
        }
        attr = attr->next;
    }

    n1_child_size = virXMLChildElementCount(n1);
    n2_child_size = virXMLChildElementCount(n2);
    if (n1_child_size < 0 || n2_child_size < 0 ||
        n1_child_size < n2_child_size)
        return false;

    if (n1_child_size == 0 && n2_child_size == 0)
        return true;

    if (!(bitmap = virBitmapNew(n1_child_size)))
        return false;

    child2 = n2->children;
    while (child2) {
        if (child2->type != XML_ELEMENT_NODE) {
            child2 = child2->next;
            continue;
        }

        child1 = n1->children;
        n1_iter = 0;
        found = false;
        while (child1) {
            if (child1->type != XML_ELEMENT_NODE) {
                child1 = child1->next;
                continue;
            }

            if (virBitmapGetBit(bitmap, n1_iter, &visited) < 0) {
                vshError(NULL, "%s", _("Bad child elements counting."));
                goto cleanup;
            }

            if (visited) {
                child1 = child1->next;
                n1_iter++;
                continue;
            }

            if (xmlStrEqual(child1->name, child2->name)) {
                found = true;
                if (virBitmapSetBit(bitmap, n1_iter) < 0) {
                    vshError(NULL, "%s", _("Bad child elements counting."));
                    goto cleanup;
                }

                if (!virshNodeIsSuperset(child1, child2))
                    goto cleanup;

                break;
            }

            child1 = child1->next;
            n1_iter++;
        }

        if (!found)
            goto cleanup;

        child2 = child2->next;
    }

    ret = true;

 cleanup:
    virBitmapFree(bitmap);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
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
    virDomainPtr dom = NULL;
    const char *from = NULL;
    char *buffer = NULL;
    int ret;
    bool funcRet = false;
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
        goto cleanup;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0) {
        vshReportError(ctl);
        goto cleanup;
    }

    if (flags != 0 || current)
        ret = virDomainDetachDeviceFlags(dom, buffer, flags);
    else
        ret = virDomainDetachDevice(dom, buffer);

    if (ret < 0) {
        vshError(ctl, _("Failed to detach device from %s"), from);
        goto cleanup;
    }

    vshPrintExtra(ctl, "%s", _("Device detached successfully\n"));
    funcRet = true;

 cleanup:
    VIR_FREE(buffer);
    virshDomainFree(dom);
    return funcRet;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
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
    virDomainPtr dom;
    const char *from = NULL;
    char *buffer = NULL;
    bool ret = false;
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
        goto cleanup;

    if (persistent &&
        virDomainIsActive(dom) == 1)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0) {
        vshReportError(ctl);
        goto cleanup;
    }

    if (vshCommandOptBool(cmd, "force"))
        flags |= VIR_DOMAIN_DEVICE_MODIFY_FORCE;

    if (virDomainUpdateDeviceFlags(dom, buffer, flags) < 0) {
        vshError(ctl, _("Failed to update device from %s"), from);
        goto cleanup;
    }

    vshPrintExtra(ctl, "%s", _("Device updated successfully\n"));
    ret = true;

 cleanup:
    VIR_FREE(buffer);
    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "type",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("network interface type")
    },
    {.name = "mac",
     .type = VSH_OT_STRING,
     .help = N_("MAC address")
    },
    VIRSH_COMMON_OPT_DOMAIN_PERSISTENT,
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = NULL}
};

static bool
virshDomainDetachInterface(char *doc,
                           unsigned int flags,
                           virDomainPtr dom,
                           vshControl *ctl,
                           bool current,
                           const char *type,
                           const char *mac)
{
    xmlDocPtr xml = NULL;
    xmlXPathObjectPtr obj = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr cur = NULL, matchNode = NULL;
    char *detach_xml = NULL, buf[64];
    int diff_mac, ret = -1;
    size_t i;

    if (!(xml = virXMLParseStringCtxt(doc, _("(domain_definition)"), &ctxt))) {
        vshError(ctl, "%s", _("Failed to get interface information"));
        goto cleanup;
    }

    snprintf(buf, sizeof(buf), "/domain/devices/interface[@type='%s']", type);
    obj = xmlXPathEval(BAD_CAST buf, ctxt);
    if (obj == NULL || obj->type != XPATH_NODESET ||
        obj->nodesetval == NULL || obj->nodesetval->nodeNr == 0) {
        vshError(ctl, _("No interface found whose type is %s"), type);
        goto cleanup;
    }

    if (!mac && obj->nodesetval->nodeNr > 1) {
        vshError(ctl, _("Domain has %d interfaces. Please specify which one "
                        "to detach using --mac"), obj->nodesetval->nodeNr);
        goto cleanup;
    }

    if (!mac) {
        matchNode = obj->nodesetval->nodeTab[0];
        goto hit;
    }

    /* multiple possibilities, so search for matching mac */
    for (i = 0; i < obj->nodesetval->nodeNr; i++) {
        cur = obj->nodesetval->nodeTab[i]->children;
        while (cur != NULL) {
            if (cur->type == XML_ELEMENT_NODE &&
                xmlStrEqual(cur->name, BAD_CAST "mac")) {
                char *tmp_mac = virXMLPropString(cur, "address");
                diff_mac = virMacAddrCompare(tmp_mac, mac);
                VIR_FREE(tmp_mac);
                if (!diff_mac) {
                    if (matchNode) {
                        /* this is the 2nd match, so it's ambiguous */
                        vshError(ctl, _("Domain has multiple interfaces matching "
                                        "MAC address %s. You must use detach-device and "
                                        "specify the device pci address to remove it."),
                                 mac);
                        goto cleanup;
                    }
                    matchNode = obj->nodesetval->nodeTab[i];
                }
            }
            cur = cur->next;
        }
    }
    if (!matchNode) {
        vshError(ctl, _("No interface with MAC address %s was found"), mac);
        goto cleanup;
    }

 hit:
    if (!(detach_xml = virXMLNodeToString(xml, matchNode))) {
        vshSaveLibvirtError();
        goto cleanup;
    }

    if (flags != 0 || current)
        ret = virDomainDetachDeviceFlags(dom, detach_xml, flags);
    else
        ret = virDomainDetachDevice(dom, detach_xml);

 cleanup:
    VIR_FREE(detach_xml);
    xmlFreeDoc(xml);
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctxt);
    return ret == 0;
}


static bool
cmdDetachInterface(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    char *doc_live = NULL, *doc_config = NULL;
    const char *mac = NULL, *type = NULL;
    int flags = 0;
    bool ret = false, affect_config, affect_live;
    bool current = vshCommandOptBool(cmd, "current");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool persistent = vshCommandOptBool(cmd, "persistent");

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
                                               dom, ctl, current, type, mac)))
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
                                         dom, ctl, current, type, mac);
    }

 cleanup:
    if (!ret) {
        vshError(ctl, "%s", _("Failed to detach interface"));
    } else {
        vshPrintExtra(ctl, "%s", _("Interface detached successfully\n"));
    }
    VIR_FREE(doc_live);
    VIR_FREE(doc_config);
    virshDomainFree(dom);
    return ret;
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
    xmlDocPtr xml = NULL;
    xmlXPathObjectPtr obj = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr cur = NULL;
    xmlNodePtr ret = NULL;
    size_t i;

    xml = virXMLParseStringCtxt(doc, _("(domain_definition)"), &ctxt);
    if (!xml) {
        vshError(NULL, "%s", _("Failed to get disk information"));
        goto cleanup;
    }

    obj = xmlXPathEval(BAD_CAST "/domain/devices/disk", ctxt);
    if (obj == NULL ||
        obj->type != XPATH_NODESET ||
        obj->nodesetval == NULL ||
        obj->nodesetval->nodeNr == 0) {
        vshError(NULL, "%s", _("Failed to get disk information"));
        goto cleanup;
    }

    /* search disk using @path */
    for (i = 0; i < obj->nodesetval->nodeNr; i++) {
        bool is_supported = true;

        if (type == VIRSH_FIND_DISK_CHANGEABLE) {
            xmlNodePtr n = obj->nodesetval->nodeTab[i];
            is_supported = false;

            /* Check if the disk is CDROM or floppy disk */
            if (xmlStrEqual(n->name, BAD_CAST "disk")) {
                char *device_value = virXMLPropString(n, "device");

                if (STREQ(device_value, "cdrom") ||
                    STREQ(device_value, "floppy"))
                    is_supported = true;

                VIR_FREE(device_value);
            }

            if (!is_supported)
                continue;
        }

        cur = obj->nodesetval->nodeTab[i]->children;
        while (cur != NULL) {
            if (cur->type == XML_ELEMENT_NODE) {
                char *tmp = NULL;

                if (xmlStrEqual(cur->name, BAD_CAST "source")) {
                    if ((tmp = virXMLPropString(cur, "file")) ||
                        (tmp = virXMLPropString(cur, "dev")) ||
                        (tmp = virXMLPropString(cur, "dir")) ||
                        (tmp = virXMLPropString(cur, "name"))) {
                    }
                } else if (xmlStrEqual(cur->name, BAD_CAST "target")) {
                    tmp = virXMLPropString(cur, "dev");
                }

                if (STREQ_NULLABLE(tmp, path)) {
                    ret = xmlCopyNode(obj->nodesetval->nodeTab[i], 1);
                    VIR_FREE(tmp);
                    goto cleanup;
                }
                VIR_FREE(tmp);
            }
            cur = cur->next;
        }
    }

    vshError(NULL, _("No disk found whose source path or target is %s"), path);

 cleanup:
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    return ret;
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
    xmlNodePtr tmp = NULL;
    xmlNodePtr source = NULL;
    xmlNodePtr backingStore = NULL;
    xmlNodePtr target_node = NULL;
    xmlNodePtr text_node = NULL;
    char *device_type = NULL;
    char *ret = NULL;
    char *startupPolicy = NULL;
    char *source_path = NULL;

    if (!disk_node)
        return NULL;

    device_type = virXMLPropString(disk_node, "device");

    if (!(STREQ_NULLABLE(device_type, "cdrom") ||
          STREQ_NULLABLE(device_type, "floppy"))) {
        vshError(NULL, _("The disk device '%s' is not removable"), target);
        goto cleanup;
    }

    /* find the current source subelement */
    for (tmp = disk_node->children; tmp; tmp = tmp->next) {
        /*
         * Save the last text node before the <target/>.  The
         * reasoning behind this is that the target node will be
         * present in this case and also has a proper indentation.
         */
        if (!target_node && tmp->type == XML_TEXT_NODE)
            text_node = tmp;

        /*
         * We need only element nodes from now on.
         */
        if (tmp->type != XML_ELEMENT_NODE)
            continue;

        if (xmlStrEqual(tmp->name, BAD_CAST "source"))
            source = tmp;

        if (xmlStrEqual(tmp->name, BAD_CAST "target"))
            target_node = tmp;

        if (xmlStrEqual(tmp->name, BAD_CAST "backingStore"))
            backingStore = tmp;

        /*
         * We've found all we needed.
         */
        if (source && target_node && backingStore)
            break;
    }

    /* drop the <backingStore> subtree since it would become invalid */
    if (backingStore) {
        xmlUnlinkNode(backingStore);
        xmlFreeNode(backingStore);
    }

    if (type == VIRSH_UPDATE_DISK_XML_EJECT) {
        if (!source) {
            vshError(NULL, _("The disk device '%s' doesn't have media"), target);
            goto cleanup;
        }

        /* forcibly switch to empty file cdrom */
        source_block = false;
        new_source = NULL;
    } else if (!new_source) {
        vshError(NULL, _("New disk media source was not specified"));
        goto cleanup;
    }

    if (source) {
        if (!(source_path = virXMLPropString(source, "file")) &&
            !(source_path = virXMLPropString(source, "dev")) &&
            !(source_path = virXMLPropString(source, "dir")) &&
            !(source_path = virXMLPropString(source, "pool")))
            source_path = virXMLPropString(source, "name");

        if (source_path && type == VIRSH_UPDATE_DISK_XML_INSERT) {
            vshError(NULL, _("The disk device '%s' already has media"), target);
            goto cleanup;
        }

        startupPolicy = virXMLPropString(source, "startupPolicy");

        /* remove current source */
        xmlUnlinkNode(source);
        xmlFreeNode(source);
        source = NULL;
    }

    /* set the correct disk type */
    if (source_block)
        xmlSetProp(disk_node, BAD_CAST "type", BAD_CAST "block");
    else
        xmlSetProp(disk_node, BAD_CAST "type", BAD_CAST "file");

    if (new_source) {
        /* create new source subelement */
        if (!(source = xmlNewNode(NULL, BAD_CAST "source"))) {
            vshError(NULL, _("Failed to allocate new source node"));
            goto cleanup;
        }

        if (source_block)
            xmlNewProp(source, BAD_CAST "dev", BAD_CAST new_source);
        else
            xmlNewProp(source, BAD_CAST "file", BAD_CAST new_source);

        if (startupPolicy)
            xmlNewProp(source, BAD_CAST "startupPolicy", BAD_CAST startupPolicy);

        /*
         * So that the output XML looks nice in case anyone calls
         * 'change-media' with '--print-xml', let's attach the source
         * before target...
         */
        xmlAddPrevSibling(target_node, source);

        /*
         * ... and duplicate the text node doing the indentation just
         * so it's more easily readable.  And don't make it fatal.
         */
        if ((tmp = xmlCopyNode(text_node, 0))) {
            if (!xmlAddPrevSibling(target_node, tmp))
                xmlFreeNode(tmp);
        }
    }

    if (!(ret = virXMLNodeToString(NULL, disk_node))) {
        vshSaveLibvirtError();
        goto cleanup;
    }

 cleanup:
    VIR_FREE(device_type);
    VIR_FREE(startupPolicy);
    VIR_FREE(source_path);
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "target",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("target of disk device")
    },
    VIRSH_COMMON_OPT_DOMAIN_PERSISTENT,
    VIRSH_COMMON_OPT_DOMAIN_CONFIG,
    VIRSH_COMMON_OPT_DOMAIN_LIVE,
    VIRSH_COMMON_OPT_DOMAIN_CURRENT,
    {.name = NULL}
};

static bool
cmdDetachDisk(vshControl *ctl, const vshCmd *cmd)
{
    char *disk_xml = NULL;
    virDomainPtr dom = NULL;
    const char *target = NULL;
    char *doc = NULL;
    int ret;
    bool functionReturn = false;
    xmlNodePtr disk_node = NULL;
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
        goto cleanup;

    if (flags == VIR_DOMAIN_AFFECT_CONFIG)
        doc = virDomainGetXMLDesc(dom, VIR_DOMAIN_XML_INACTIVE);
    else
        doc = virDomainGetXMLDesc(dom, 0);

    if (!doc)
        goto cleanup;

    if (persistent &&
        virDomainIsActive(dom) == 1)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (!(disk_node = virshFindDisk(doc, target, VIRSH_FIND_DISK_NORMAL)))
        goto cleanup;

    if (!(disk_xml = virXMLNodeToString(NULL, disk_node))) {
        vshSaveLibvirtError();
        goto cleanup;
    }

    if (flags != 0 || current)
        ret = virDomainDetachDeviceFlags(dom, disk_xml, flags);
    else
        ret = virDomainDetachDevice(dom, disk_xml);

    if (ret != 0) {
        vshError(ctl, "%s", _("Failed to detach disk"));
        goto cleanup;
    }

    vshPrintExtra(ctl, "%s", _("Disk detached successfully\n"));
    functionReturn = true;

 cleanup:
    xmlFreeNode(disk_node);
    VIR_FREE(disk_xml);
    VIR_FREE(doc);
    virshDomainFree(dom);
    return functionReturn;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
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
    virDomainPtr dom = NULL;
    virDomainPtr dom_edited = NULL;
    unsigned int query_flags = VIR_DOMAIN_XML_SECURE | VIR_DOMAIN_XML_INACTIVE;
    unsigned int define_flags = VIR_DOMAIN_DEFINE_VALIDATE;
    virshControlPtr priv = ctl->privData;

    dom = virshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    if (vshCommandOptBool(cmd, "skip-validate"))
        define_flags &= ~VIR_DOMAIN_DEFINE_VALIDATE;

#define EDIT_GET_XML virDomainGetXMLDesc(dom, query_flags)
#define EDIT_NOT_CHANGED                                                     \
    do {                                                                     \
        vshPrintExtra(ctl, _("Domain %s XML configuration not changed.\n"),  \
                      virDomainGetName(dom));                                \
        ret = true;                                                          \
        goto edit_cleanup;                                                   \
    } while (0)
#define EDIT_DEFINE \
    (dom_edited = virshDomainDefine(priv->conn, doc_edited, define_flags))
#define EDIT_RELAX                                      \
    do {                                                \
        define_flags &= ~VIR_DOMAIN_DEFINE_VALIDATE;    \
    } while (0);

#include "virsh-edit.c"
#undef EDIT_RELAX

    vshPrintExtra(ctl, _("Domain %s XML configuration edited.\n"),
                  virDomainGetName(dom_edited));

    ret = true;

 cleanup:
    virshDomainFree(dom);
    virshDomainFree(dom_edited);

    return ret;
}


/*
 * "event" command
 */
VIR_ENUM_DECL(virshDomainEvent)
VIR_ENUM_IMPL(virshDomainEvent,
              VIR_DOMAIN_EVENT_LAST,
              N_("Defined"),
              N_("Undefined"),
              N_("Started"),
              N_("Suspended"),
              N_("Resumed"),
              N_("Stopped"),
              N_("Shutdown"),
              N_("PMSuspended"),
              N_("Crashed"))

static const char *
virshDomainEventToString(int event)
{
    const char *str = virshDomainEventTypeToString(event);
    return str ? _(str) : _("unknown");
}

VIR_ENUM_DECL(virshDomainEventDefined)
VIR_ENUM_IMPL(virshDomainEventDefined,
              VIR_DOMAIN_EVENT_DEFINED_LAST,
              N_("Added"),
              N_("Updated"),
              N_("Renamed"),
              N_("Snapshot"))

VIR_ENUM_DECL(virshDomainEventUndefined)
VIR_ENUM_IMPL(virshDomainEventUndefined,
              VIR_DOMAIN_EVENT_UNDEFINED_LAST,
              N_("Removed"),
              N_("Renamed"))

VIR_ENUM_DECL(virshDomainEventStarted)
VIR_ENUM_IMPL(virshDomainEventStarted,
              VIR_DOMAIN_EVENT_STARTED_LAST,
              N_("Booted"),
              N_("Migrated"),
              N_("Restored"),
              N_("Snapshot"),
              N_("Event wakeup"))

VIR_ENUM_DECL(virshDomainEventSuspended)
VIR_ENUM_IMPL(virshDomainEventSuspended,
              VIR_DOMAIN_EVENT_SUSPENDED_LAST,
              N_("Paused"),
              N_("Migrated"),
              N_("I/O Error"),
              N_("Watchdog"),
              N_("Restored"),
              N_("Snapshot"),
              N_("API error"),
              N_("Post-copy"),
              N_("Post-copy Error"))

VIR_ENUM_DECL(virshDomainEventResumed)
VIR_ENUM_IMPL(virshDomainEventResumed,
              VIR_DOMAIN_EVENT_RESUMED_LAST,
              N_("Unpaused"),
              N_("Migrated"),
              N_("Snapshot"),
              N_("Post-copy"))

VIR_ENUM_DECL(virshDomainEventStopped)
VIR_ENUM_IMPL(virshDomainEventStopped,
              VIR_DOMAIN_EVENT_STOPPED_LAST,
              N_("Shutdown"),
              N_("Destroyed"),
              N_("Crashed"),
              N_("Migrated"),
              N_("Saved"),
              N_("Failed"),
              N_("Snapshot"))

VIR_ENUM_DECL(virshDomainEventShutdown)
VIR_ENUM_IMPL(virshDomainEventShutdown,
              VIR_DOMAIN_EVENT_SHUTDOWN_LAST,
              N_("Finished"),
              N_("Finished after guest request"),
              N_("Finished after host request"))

VIR_ENUM_DECL(virshDomainEventPMSuspended)
VIR_ENUM_IMPL(virshDomainEventPMSuspended,
              VIR_DOMAIN_EVENT_PMSUSPENDED_LAST,
              N_("Memory"),
              N_("Disk"))

VIR_ENUM_DECL(virshDomainEventCrashed)
VIR_ENUM_IMPL(virshDomainEventCrashed,
              VIR_DOMAIN_EVENT_CRASHED_LAST,
              N_("Panicked"))

static const char *
virshDomainEventDetailToString(int event, int detail)
{
    const char *str = NULL;
    switch ((virDomainEventType) event) {
    case VIR_DOMAIN_EVENT_DEFINED:
        str = virshDomainEventDefinedTypeToString(detail);
        break;
    case VIR_DOMAIN_EVENT_UNDEFINED:
        str = virshDomainEventUndefinedTypeToString(detail);
        break;
    case VIR_DOMAIN_EVENT_STARTED:
        str = virshDomainEventStartedTypeToString(detail);
        break;
    case VIR_DOMAIN_EVENT_SUSPENDED:
        str = virshDomainEventSuspendedTypeToString(detail);
        break;
    case VIR_DOMAIN_EVENT_RESUMED:
        str = virshDomainEventResumedTypeToString(detail);
        break;
    case VIR_DOMAIN_EVENT_STOPPED:
        str = virshDomainEventStoppedTypeToString(detail);
        break;
    case VIR_DOMAIN_EVENT_SHUTDOWN:
        str = virshDomainEventShutdownTypeToString(detail);
        break;
    case VIR_DOMAIN_EVENT_PMSUSPENDED:
        str = virshDomainEventPMSuspendedTypeToString(detail);
        break;
    case VIR_DOMAIN_EVENT_CRASHED:
        str = virshDomainEventCrashedTypeToString(detail);
        break;
    case VIR_DOMAIN_EVENT_LAST:
        break;
    }
    return str ? _(str) : _("unknown");
}

VIR_ENUM_DECL(virshDomainEventWatchdog)
VIR_ENUM_IMPL(virshDomainEventWatchdog,
              VIR_DOMAIN_EVENT_WATCHDOG_LAST,
              N_("none"),
              N_("pause"),
              N_("reset"),
              N_("poweroff"),
              N_("shutdown"),
              N_("debug"),
              N_("inject-nmi"))

static const char *
virshDomainEventWatchdogToString(int action)
{
    const char *str = virshDomainEventWatchdogTypeToString(action);
    return str ? _(str) : _("unknown");
}

VIR_ENUM_DECL(virshDomainEventIOError)
VIR_ENUM_IMPL(virshDomainEventIOError,
              VIR_DOMAIN_EVENT_IO_ERROR_LAST,
              N_("none"),
              N_("pause"),
              N_("report"))

static const char *
virshDomainEventIOErrorToString(int action)
{
    const char *str = virshDomainEventIOErrorTypeToString(action);
    return str ? _(str) : _("unknown");
}

VIR_ENUM_DECL(virshGraphicsPhase)
VIR_ENUM_IMPL(virshGraphicsPhase,
              VIR_DOMAIN_EVENT_GRAPHICS_LAST,
              N_("connect"),
              N_("initialize"),
              N_("disconnect"))

static const char *
virshGraphicsPhaseToString(int phase)
{
    const char *str = virshGraphicsPhaseTypeToString(phase);
    return str ? _(str) : _("unknown");
}

VIR_ENUM_DECL(virshGraphicsAddress)
VIR_ENUM_IMPL(virshGraphicsAddress,
              VIR_DOMAIN_EVENT_GRAPHICS_ADDRESS_LAST,
              N_("IPv4"),
              N_("IPv6"),
              N_("unix"))

static const char *
virshGraphicsAddressToString(int family)
{
    const char *str = virshGraphicsAddressTypeToString(family);
    return str ? _(str) : _("unknown");
}

VIR_ENUM_DECL(virshDomainBlockJobStatus)
VIR_ENUM_IMPL(virshDomainBlockJobStatus,
              VIR_DOMAIN_BLOCK_JOB_LAST,
              N_("completed"),
              N_("failed"),
              N_("canceled"),
              N_("ready"))

static const char *
virshDomainBlockJobStatusToString(int status)
{
    const char *str = virshDomainBlockJobStatusTypeToString(status);
    return str ? _(str) : _("unknown");
}

VIR_ENUM_DECL(virshDomainEventDiskChange)
VIR_ENUM_IMPL(virshDomainEventDiskChange,
              VIR_DOMAIN_EVENT_DISK_CHANGE_LAST,
              N_("changed"),
              N_("dropped"))

static const char *
virshDomainEventDiskChangeToString(int reason)
{
    const char *str = virshDomainEventDiskChangeTypeToString(reason);
    return str ? _(str) : _("unknown");
}

VIR_ENUM_DECL(virshDomainEventTrayChange)
VIR_ENUM_IMPL(virshDomainEventTrayChange,
              VIR_DOMAIN_EVENT_TRAY_CHANGE_LAST,
              N_("opened"),
              N_("closed"))

static const char *
virshDomainEventTrayChangeToString(int reason)
{
    const char *str = virshDomainEventTrayChangeTypeToString(reason);
    return str ? _(str) : _("unknown");
}

struct vshEventCallback {
    const char *name;
    virConnectDomainEventGenericCallback cb;
};
typedef struct vshEventCallback vshEventCallback;

struct virshDomEventData {
    vshControl *ctl;
    bool loop;
    int *count;
    bool timestamp;
    vshEventCallback *cb;
    int id;
};
typedef struct virshDomEventData virshDomEventData;

/**
 * virshEventPrint:
 *
 * @data: opaque data passed to all event callbacks
 * @buf: string buffer describing the event
 *
 * Print the event description found in @buf and update virshDomEventData.
 *
 * This function resets @buf and frees all memory consumed by its content.
 */
static void
virshEventPrint(virshDomEventData *data,
                virBufferPtr buf)
{
    char *msg;

    if (!(msg = virBufferContentAndReset(buf)))
        return;

    if (!data->loop && *data->count)
        goto cleanup;

    if (data->timestamp) {
        char timestamp[VIR_TIME_STRING_BUFLEN];

        if (virTimeStringNowRaw(timestamp) < 0)
            timestamp[0] = '\0';

        vshPrint(data->ctl, "%s: %s", timestamp, msg);
    } else {
        vshPrint(data->ctl, "%s", msg);
    }

    (*data->count)++;
    if (!data->loop)
        vshEventDone(data->ctl);

 cleanup:
    VIR_FREE(msg);
}

static void
virshEventGenericPrint(virConnectPtr conn ATTRIBUTE_UNUSED,
                       virDomainPtr dom,
                       void *opaque)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event '%s' for domain %s\n"),
                      ((virshDomEventData *) opaque)->cb->name,
                      virDomainGetName(dom));
    virshEventPrint(opaque, &buf);
}

static void
virshEventLifecyclePrint(virConnectPtr conn ATTRIBUTE_UNUSED,
                         virDomainPtr dom,
                         int event,
                         int detail,
                         void *opaque)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'lifecycle' for domain %s: %s %s\n"),
                      virDomainGetName(dom),
                      virshDomainEventToString(event),
                      virshDomainEventDetailToString(event, detail));
    virshEventPrint(opaque, &buf);
}

static void
virshEventRTCChangePrint(virConnectPtr conn ATTRIBUTE_UNUSED,
                         virDomainPtr dom,
                         long long utcoffset,
                         void *opaque)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'rtc-change' for domain %s: %lld\n"),
                      virDomainGetName(dom),
                      utcoffset);
    virshEventPrint(opaque, &buf);
}

static void
virshEventWatchdogPrint(virConnectPtr conn ATTRIBUTE_UNUSED,
                        virDomainPtr dom,
                        int action,
                        void *opaque)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'watchdog' for domain %s: %s\n"),
                      virDomainGetName(dom),
                      virshDomainEventWatchdogToString(action));
    virshEventPrint(opaque, &buf);
}

static void
virshEventIOErrorPrint(virConnectPtr conn ATTRIBUTE_UNUSED,
                       virDomainPtr dom,
                       const char *srcPath,
                       const char *devAlias,
                       int action,
                       void *opaque)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'io-error' for domain %s: %s (%s) %s\n"),
                      virDomainGetName(dom),
                      srcPath,
                      devAlias,
                      virshDomainEventIOErrorToString(action));
    virshEventPrint(opaque, &buf);
}

static void
virshEventGraphicsPrint(virConnectPtr conn ATTRIBUTE_UNUSED,
                        virDomainPtr dom,
                        int phase,
                        const virDomainEventGraphicsAddress *local,
                        const virDomainEventGraphicsAddress *remote,
                        const char *authScheme,
                        const virDomainEventGraphicsSubject *subject,
                        void *opaque)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    size_t i;

    virBufferAsprintf(&buf, _("event 'graphics' for domain %s: "
                              "%s local[%s %s %s] remote[%s %s %s] %s\n"),
                      virDomainGetName(dom),
                      virshGraphicsPhaseToString(phase),
                      virshGraphicsAddressToString(local->family),
                      local->node,
                      local->service,
                      virshGraphicsAddressToString(remote->family),
                      remote->node,
                      remote->service,
                      authScheme);
    for (i = 0; i < subject->nidentity; i++) {
        virBufferAsprintf(&buf, "\t%s=%s\n",
                          subject->identities[i].type,
                          subject->identities[i].name);
    }
    virshEventPrint(opaque, &buf);
}

static void
virshEventIOErrorReasonPrint(virConnectPtr conn ATTRIBUTE_UNUSED,
                             virDomainPtr dom,
                             const char *srcPath,
                             const char *devAlias,
                             int action,
                             const char *reason,
                             void *opaque)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'io-error-reason' for domain %s: "
                              "%s (%s) %s due to %s\n"),
                      virDomainGetName(dom),
                      srcPath,
                      devAlias,
                      virshDomainEventIOErrorToString(action),
                      reason);
    virshEventPrint(opaque, &buf);
}

static void
virshEventBlockJobPrint(virConnectPtr conn ATTRIBUTE_UNUSED,
                        virDomainPtr dom,
                        const char *disk,
                        int type,
                        int status,
                        void *opaque)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event '%s' for domain %s: %s for %s %s\n"),
                      ((virshDomEventData *) opaque)->cb->name,
                      virDomainGetName(dom),
                      virshDomainBlockJobToString(type),
                      disk,
                      virshDomainBlockJobStatusToString(status));
    virshEventPrint(opaque, &buf);
}

static void
virshEventDiskChangePrint(virConnectPtr conn ATTRIBUTE_UNUSED,
                          virDomainPtr dom,
                          const char *oldSrc,
                          const char *newSrc,
                          const char *alias,
                          int reason,
                          void *opaque)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'disk-change' for domain %s disk %s: "
                              "%s -> %s: %s\n"),
                      virDomainGetName(dom),
                      alias,
                      NULLSTR(oldSrc),
                      NULLSTR(newSrc),
                      virshDomainEventDiskChangeToString(reason));
    virshEventPrint(opaque, &buf);
}

static void
virshEventTrayChangePrint(virConnectPtr conn ATTRIBUTE_UNUSED,
                          virDomainPtr dom,
                          const char *alias,
                          int reason,
                          void *opaque)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'tray-change' for domain %s disk %s: %s\n"),
                      virDomainGetName(dom),
                      alias,
                      virshDomainEventTrayChangeToString(reason));
    virshEventPrint(opaque, &buf);
}

static void
virshEventPMChangePrint(virConnectPtr conn ATTRIBUTE_UNUSED,
                        virDomainPtr dom,
                        int reason ATTRIBUTE_UNUSED,
                        void *opaque)
{
    /* As long as libvirt.h doesn't define any reasons, we might as
     * well treat all PM state changes as generic events.  */
    virshEventGenericPrint(conn, dom, opaque);
}

static void
virshEventBalloonChangePrint(virConnectPtr conn ATTRIBUTE_UNUSED,
                             virDomainPtr dom,
                             unsigned long long actual,
                             void *opaque)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'balloon-change' for domain %s: %lluKiB\n"),
                      virDomainGetName(dom),
                      actual);
    virshEventPrint(opaque, &buf);
}

static void
virshEventDeviceRemovedPrint(virConnectPtr conn ATTRIBUTE_UNUSED,
                             virDomainPtr dom,
                             const char *alias,
                             void *opaque)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'device-removed' for domain %s: %s\n"),
                      virDomainGetName(dom),
                      alias);
    virshEventPrint(opaque, &buf);
}

static void
virshEventDeviceAddedPrint(virConnectPtr conn ATTRIBUTE_UNUSED,
                           virDomainPtr dom,
                           const char *alias,
                           void *opaque)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'device-added' for domain %s: %s\n"),
                      virDomainGetName(dom),
                      alias);
    virshEventPrint(opaque, &buf);
}

static void
virshEventTunablePrint(virConnectPtr conn ATTRIBUTE_UNUSED,
                       virDomainPtr dom,
                       virTypedParameterPtr params,
                       int nparams,
                       void *opaque)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    size_t i;
    char *value;

    virBufferAsprintf(&buf, _("event 'tunable' for domain %s:\n"),
                      virDomainGetName(dom));
    for (i = 0; i < nparams; i++) {
        value = virTypedParameterToString(&params[i]);
        if (value) {
            virBufferAsprintf(&buf, "\t%s: %s\n", params[i].field, value);
            VIR_FREE(value);
        }
    }
    virshEventPrint(opaque, &buf);
}

VIR_ENUM_DECL(virshEventAgentLifecycleState)
VIR_ENUM_IMPL(virshEventAgentLifecycleState,
              VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_STATE_LAST,
              N_("unknown"),
              N_("connected"),
              N_("disconnected"))

VIR_ENUM_DECL(virshEventAgentLifecycleReason)
VIR_ENUM_IMPL(virshEventAgentLifecycleReason,
              VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_REASON_LAST,
              N_("unknown"),
              N_("domain started"),
              N_("channel event"))

#define UNKNOWNSTR(str) (str ? str : N_("unsupported value"))
static void
virshEventAgentLifecyclePrint(virConnectPtr conn ATTRIBUTE_UNUSED,
                              virDomainPtr dom,
                              int state,
                              int reason,
                              void *opaque)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'agent-lifecycle' for domain %s: state: "
                              "'%s' reason: '%s'\n"),
                      virDomainGetName(dom),
                      UNKNOWNSTR(virshEventAgentLifecycleStateTypeToString(state)),
                      UNKNOWNSTR(virshEventAgentLifecycleReasonTypeToString(reason)));
    virshEventPrint(opaque, &buf);
}

static void
virshEventMigrationIterationPrint(virConnectPtr conn ATTRIBUTE_UNUSED,
                                  virDomainPtr dom,
                                  int iteration,
                                  void *opaque)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'migration-iteration' for domain %s: "
                              "iteration: '%d'\n"),
                      virDomainGetName(dom),
                      iteration);

    virshEventPrint(opaque, &buf);
}

static void
virshEventJobCompletedPrint(virConnectPtr conn ATTRIBUTE_UNUSED,
                            virDomainPtr dom,
                            virTypedParameterPtr params,
                            int nparams,
                            void *opaque)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    size_t i;
    char *value;

    virBufferAsprintf(&buf, _("event 'job-completed' for domain %s:\n"),
                      virDomainGetName(dom));
    for (i = 0; i < nparams; i++) {
        value = virTypedParameterToString(&params[i]);
        if (value) {
            virBufferAsprintf(&buf, "\t%s: %s\n", params[i].field, value);
            VIR_FREE(value);
        }
    }
    virshEventPrint(opaque, &buf);
}


static void
virshEventDeviceRemovalFailedPrint(virConnectPtr conn ATTRIBUTE_UNUSED,
                                   virDomainPtr dom,
                                   const char *alias,
                                   void *opaque)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'device-removal-failed' for domain %s: %s\n"),
                      virDomainGetName(dom),
                      alias);
    virshEventPrint(opaque, &buf);
}

VIR_ENUM_DECL(virshEventMetadataChangeType)
VIR_ENUM_IMPL(virshEventMetadataChangeType,
              VIR_DOMAIN_METADATA_LAST,
              N_("description"),
              N_("title"),
              N_("element"))

static void
virshEventMetadataChangePrint(virConnectPtr conn ATTRIBUTE_UNUSED,
                              virDomainPtr dom,
                              int type,
                              const char *nsuri,
                              void *opaque)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'metdata-change' for domain %s: %s %s\n"),
                      virDomainGetName(dom),
                      UNKNOWNSTR(virshEventMetadataChangeTypeTypeToString(type)),
                      NULLSTR(nsuri));
    virshEventPrint(opaque, &buf);
}


static void
virshEventBlockThresholdPrint(virConnectPtr conn ATTRIBUTE_UNUSED,
                              virDomainPtr dom,
                              const char *dev,
                              const char *path,
                              unsigned long long threshold,
                              unsigned long long excess,
                              void *opaque)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'block-threshold' for domain %s: "
                              "dev: %s(%s) %llu %llu\n"),
                      virDomainGetName(dom),
                      dev, NULLSTR(path), threshold, excess);
    virshEventPrint(opaque, &buf);
}


static vshEventCallback vshEventCallbacks[] = {
    { "lifecycle",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventLifecyclePrint), },
    { "reboot", virshEventGenericPrint, },
    { "rtc-change",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventRTCChangePrint), },
    { "watchdog",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventWatchdogPrint), },
    { "io-error",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventIOErrorPrint), },
    { "graphics",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventGraphicsPrint), },
    { "io-error-reason",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventIOErrorReasonPrint), },
    { "control-error", virshEventGenericPrint, },
    { "block-job",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventBlockJobPrint), },
    { "disk-change",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventDiskChangePrint), },
    { "tray-change",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventTrayChangePrint), },
    { "pm-wakeup",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventPMChangePrint), },
    { "pm-suspend",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventPMChangePrint), },
    { "balloon-change",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventBalloonChangePrint), },
    { "pm-suspend-disk",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventPMChangePrint), },
    { "device-removed",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventDeviceRemovedPrint), },
    { "block-job-2",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventBlockJobPrint), },
    { "tunable",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventTunablePrint), },
    { "agent-lifecycle",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventAgentLifecyclePrint), },
    { "device-added",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventDeviceAddedPrint), },
    { "migration-iteration",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventMigrationIterationPrint), },
    { "job-completed",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventJobCompletedPrint), },
    { "device-removal-failed",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventDeviceRemovalFailedPrint), },
    { "metadata-change",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventMetadataChangePrint), },
    { "block-threshold",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventBlockThresholdPrint), },
};
verify(VIR_DOMAIN_EVENT_ID_LAST == ARRAY_CARDINALITY(vshEventCallbacks));

static const vshCmdInfo info_event[] = {
    {.name = "help",
     .data = N_("Domain Events")
    },
    {.name = "desc",
     .data = N_("List event types, or wait for domain events to occur")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_event[] = {
    {.name = "domain",
     .type = VSH_OT_STRING,
     .help = N_("filter by domain name, id, or uuid")
    },
    {.name = "event",
     .type = VSH_OT_STRING,
     .help = N_("which event type to wait for")
    },
    {.name = "all",
     .type = VSH_OT_BOOL,
     .help = N_("wait for all events instead of just one type")
    },
    {.name = "loop",
     .type = VSH_OT_BOOL,
     .help = N_("loop until timeout or interrupt, rather than one-shot")
    },
    {.name = "timeout",
     .type = VSH_OT_INT,
     .help = N_("timeout seconds")
    },
    {.name = "list",
     .type = VSH_OT_BOOL,
     .help = N_("list valid event types")
    },
    {.name = "timestamp",
     .type = VSH_OT_BOOL,
     .help = N_("show timestamp for each printed event")
    },
    {.name = NULL}
};

static bool
cmdEvent(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    int timeout = 0;
    virshDomEventData *data = NULL;
    size_t i;
    const char *eventName = NULL;
    int event = -1;
    bool all = vshCommandOptBool(cmd, "all");
    bool loop = vshCommandOptBool(cmd, "loop");
    bool timestamp = vshCommandOptBool(cmd, "timestamp");
    int count = 0;
    virshControlPtr priv = ctl->privData;

    if (vshCommandOptBool(cmd, "list")) {
        for (event = 0; event < VIR_DOMAIN_EVENT_ID_LAST; event++)
            vshPrint(ctl, "%s\n", vshEventCallbacks[event].name);
        return true;
    }

    if (vshCommandOptStringReq(ctl, cmd, "event", &eventName) < 0)
        return false;
    if (eventName) {
        for (event = 0; event < VIR_DOMAIN_EVENT_ID_LAST; event++)
            if (STREQ(eventName, vshEventCallbacks[event].name))
                break;
        if (event == VIR_DOMAIN_EVENT_ID_LAST) {
            vshError(ctl, _("unknown event type %s"), eventName);
            return false;
        }
    } else if (!all) {
        vshError(ctl, "%s",
                 _("one of --list, --all, or --event <type> is required"));
        return false;
    }

    if (all) {
        if (VIR_ALLOC_N(data, VIR_DOMAIN_EVENT_ID_LAST) < 0)
            goto cleanup;
        for (i = 0; i < VIR_DOMAIN_EVENT_ID_LAST; i++) {
            data[i].ctl = ctl;
            data[i].loop = loop;
            data[i].count = &count;
            data[i].timestamp = timestamp;
            data[i].cb = &vshEventCallbacks[i];
            data[i].id = -1;
        }
    } else {
        if (VIR_ALLOC_N(data, 1) < 0)
            goto cleanup;
        data[0].ctl = ctl;
        data[0].loop = vshCommandOptBool(cmd, "loop");
        data[0].count = &count;
        data[0].timestamp = timestamp;
        data[0].cb = &vshEventCallbacks[event];
        data[0].id = -1;
    }
    if (vshCommandOptTimeoutToMs(ctl, cmd, &timeout) < 0)
        goto cleanup;

    if (vshCommandOptBool(cmd, "domain"))
        dom = virshCommandOptDomain(ctl, cmd, NULL);
    if (vshEventStart(ctl, timeout) < 0)
        goto cleanup;

    for (i = 0; i < (all ? VIR_DOMAIN_EVENT_ID_LAST : 1); i++) {
        if ((data[i].id = virConnectDomainEventRegisterAny(priv->conn, dom,
                                                           all ? i : event,
                                                           data[i].cb->cb,
                                                           &data[i],
                                                           NULL)) < 0) {
            /* When registering for all events: if the first
             * registration succeeds, silently ignore failures on all
             * later registrations on the assumption that the server
             * is older and didn't know quite as many events.  */
            if (i)
                vshResetLibvirtError();
            else
                goto cleanup;
        }
    }
    switch (vshEventWait(ctl)) {
    case VSH_EVENT_INTERRUPT:
        vshPrint(ctl, "%s", _("event loop interrupted\n"));
        break;
    case VSH_EVENT_TIMEOUT:
        vshPrint(ctl, "%s", _("event loop timed out\n"));
        break;
    case VSH_EVENT_DONE:
        break;
    default:
        goto cleanup;
    }
    vshPrint(ctl, _("events received: %d\n"), count);
    if (count)
        ret = true;

 cleanup:
    vshEventCleanup(ctl);
    if (data) {
        for (i = 0; i < (all ? VIR_DOMAIN_EVENT_ID_LAST : 1); i++) {
            if (data[i].id >= 0 &&
                virConnectDomainEventDeregisterAny(priv->conn, data[i].id) < 0)
                ret = false;
        }
        VIR_FREE(data);
    }
    virshDomainFree(dom);
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "path",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
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
    virDomainPtr dom = NULL;
    const char *source = NULL;
    const char *path = NULL;
    char *doc = NULL;
    xmlNodePtr disk_node = NULL;
    char *disk_xml = NULL;
    bool ret = false;
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
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG)
        doc = virDomainGetXMLDesc(dom, VIR_DOMAIN_XML_INACTIVE);
    else
        doc = virDomainGetXMLDesc(dom, 0);
    if (!doc)
        goto cleanup;

    if (!(disk_node = virshFindDisk(doc, path, VIRSH_FIND_DISK_CHANGEABLE)))
        goto cleanup;

    if (!(disk_xml = virshUpdateDiskXML(disk_node, source, block, path,
                                        update_type)))
        goto cleanup;

    if (vshCommandOptBool(cmd, "print-xml")) {
        vshPrint(ctl, "%s", disk_xml);
    } else {
        if (virDomainUpdateDeviceFlags(dom, disk_xml, flags) != 0) {
            vshError(ctl, _("Failed to complete action %s on media"), action);
            goto cleanup;
        }

        vshPrint(ctl, "%s", success_msg);
    }

    ret = true;

 cleanup:
    VIR_FREE(doc);
    xmlFreeNode(disk_node);
    VIR_FREE(disk_xml);
    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "minimum",
     .type = VSH_OT_INT,
     .help = N_("Just a hint to ignore contiguous "
                "free ranges smaller than this (Bytes)")
    },
    {.name = "mountpoint",
     .type = VSH_OT_STRING,
     .help = N_("which mount point to trim")
    },
    {.name = NULL}
};
static bool
cmdDomFSTrim(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    unsigned long long minimum = 0;
    const char *mountPoint = NULL;
    unsigned int flags = 0;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return ret;

    if (vshCommandOptULongLong(ctl, cmd, "minimum", &minimum) < 0)
        goto cleanup;

    if (vshCommandOptStringReq(ctl, cmd, "mountpoint", &mountPoint) < 0)
        goto cleanup;

    if (virDomainFSTrim(dom, mountPoint, minimum, flags) < 0) {
        vshError(ctl, _("Unable to invoke fstrim"));
        goto cleanup;
    }

    ret = true;

 cleanup:
    virshDomainFree(dom);
    return ret;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "mountpoint",
     .type = VSH_OT_ARGV,
     .help = N_("mountpoint path to be frozen")
    },
    {.name = NULL}
};
static bool
cmdDomFSFreeze(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    int ret = -1;
    const vshCmdOpt *opt = NULL;
    const char **mountpoints = NULL;
    size_t nmountpoints = 0;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    while ((opt = vshCommandOptArgv(ctl, cmd, opt))) {
        if (VIR_EXPAND_N(mountpoints, nmountpoints, 1) < 0) {
            vshError(ctl, _("%s: %d: failed to allocate mountpoints"),
                     __FILE__, __LINE__);
            goto cleanup;
        }
        mountpoints[nmountpoints-1] = opt->data;
    }

    ret = virDomainFSFreeze(dom, mountpoints, nmountpoints, 0);
    if (ret < 0) {
        vshError(ctl, _("Unable to freeze filesystems"));
        goto cleanup;
    }

    vshPrintExtra(ctl, _("Froze %d filesystem(s)\n"), ret);

 cleanup:
    VIR_FREE(mountpoints);
    virshDomainFree(dom);
    return ret >= 0;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "mountpoint",
     .type = VSH_OT_ARGV,
     .help = N_("mountpoint path to be thawed")
    },
    {.name = NULL}
};
static bool
cmdDomFSThaw(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    int ret = -1;
    const vshCmdOpt *opt = NULL;
    const char **mountpoints = NULL;
    size_t nmountpoints = 0;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    while ((opt = vshCommandOptArgv(ctl, cmd, opt))) {
        if (VIR_EXPAND_N(mountpoints, nmountpoints, 1) < 0) {
            vshError(ctl, _("%s: %d: failed to allocate mountpoints"),
                     __FILE__, __LINE__);
            goto cleanup;
        }
        mountpoints[nmountpoints-1] = opt->data;
    }

    ret = virDomainFSThaw(dom, mountpoints, nmountpoints, 0);
    if (ret < 0) {
        vshError(ctl, _("Unable to thaw filesystems"));
        goto cleanup;
    }

    vshPrintExtra(ctl, _("Thawed %d filesystem(s)\n"), ret);

 cleanup:
    VIR_FREE(mountpoints);
    virshDomainFree(dom);
    return ret >= 0;
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = NULL}
};

static bool
cmdDomFSInfo(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    int ret = -1;
    size_t i, j;
    virDomainFSInfoPtr *info;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    ret = virDomainGetFSInfo(dom, &info, 0);
    if (ret < 0) {
        vshError(ctl, _("Unable to get filesystem information"));
        goto cleanup;
    }
    if (ret == 0) {
        vshError(ctl, _("No filesystems are mounted in the domain"));
        goto cleanup;
    }

    if (info) {
        vshPrintExtra(ctl, "%-36s %-8s %-8s %s\n",
                      _("Mountpoint"), _("Name"), _("Type"), _("Target"));
        vshPrintExtra(ctl, "-------------------------------------------------------------------\n");
        for (i = 0; i < ret; i++) {
            vshPrint(ctl, "%-36s %-8s %-8s ",
                     info[i]->mountpoint, info[i]->name, info[i]->fstype);
            for (j = 0; j < info[i]->ndevAlias; j++) {
                vshPrint(ctl, "%s", info[i]->devAlias[j]);
                if (j != info[i]->ndevAlias - 1)
                    vshPrint(ctl, ",");
            }
            vshPrint(ctl, "\n");

            virDomainFSInfoFree(info[i]);
        }
        VIR_FREE(info);
    }

 cleanup:
    virshDomainFree(dom);
    return ret >= 0;
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
     .handler = cmdBlockCommit,
     .opts = opts_block_commit,
     .info = info_block_commit,
     .flags = 0
    },
    {.name = "blockcopy",
     .handler = cmdBlockCopy,
     .opts = opts_block_copy,
     .info = info_block_copy,
     .flags = 0
    },
    {.name = "blockjob",
     .handler = cmdBlockJob,
     .opts = opts_block_job,
     .info = info_block_job,
     .flags = 0
    },
    {.name = "blockpull",
     .handler = cmdBlockPull,
     .opts = opts_block_pull,
     .info = info_block_pull,
     .flags = 0
    },
    {.name = "blockresize",
     .handler = cmdBlockResize,
     .opts = opts_block_resize,
     .info = info_block_resize,
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
    {.name = "cpu-baseline",
     .handler = cmdCPUBaseline,
     .opts = opts_cpu_baseline,
     .info = info_cpu_baseline,
     .flags = 0
    },
    {.name = "cpu-compare",
     .handler = cmdCPUCompare,
     .opts = opts_cpu_compare,
     .info = info_cpu_compare,
     .flags = 0
    },
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
    {.name = "event",
     .handler = cmdEvent,
     .opts = opts_event,
     .info = info_event,
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
    {.name = NULL}
};
