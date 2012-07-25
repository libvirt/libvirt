/*
 * virsh-domain.c: Commands to manage domain
 *
 * Copyright (C) 2005, 2007-2012 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 *  Daniel Veillard <veillard@redhat.com>
 *  Karel Zak <kzak@redhat.com>
 *  Daniel P. Berrange <berrange@redhat.com>
 *
 */

static const char *
vshDomainVcpuStateToString(int state)
{
    switch (state) {
    case VIR_VCPU_OFFLINE:
        return N_("offline");
    case VIR_VCPU_BLOCKED:
        return N_("idle");
    case VIR_VCPU_RUNNING:
        return N_("running");
    default:
        ;/*FALLTHROUGH*/
    }
    return N_("no state");
}

/*
 * "attach-device" command
 */
static const vshCmdInfo info_attach_device[] = {
    {"help", N_("attach device from an XML file")},
    {"desc", N_("Attach device from an XML <file>.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_attach_device[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"file",   VSH_OT_DATA, VSH_OFLAG_REQ, N_("XML file")},
    {"persistent", VSH_OT_ALIAS, 0, "config"},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {NULL, 0, 0, NULL}
};

static bool
cmdAttachDevice(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *from = NULL;
    char *buffer;
    int ret;
    unsigned int flags;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0) {
        virDomainFree(dom);
        return false;
    }

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0) {
        virshReportError(ctl);
        virDomainFree(dom);
        return false;
    }

    if (vshCommandOptBool(cmd, "config")) {
        flags = VIR_DOMAIN_AFFECT_CONFIG;
        if (virDomainIsActive(dom) == 1)
           flags |= VIR_DOMAIN_AFFECT_LIVE;
        ret = virDomainAttachDeviceFlags(dom, buffer, flags);
    } else {
        ret = virDomainAttachDevice(dom, buffer);
    }
    VIR_FREE(buffer);

    if (ret < 0) {
        vshError(ctl, _("Failed to attach device from %s"), from);
        virDomainFree(dom);
        return false;
    } else {
        vshPrint(ctl, "%s", _("Device attached successfully\n"));
    }

    virDomainFree(dom);
    return true;
}

/*
 * "attach-disk" command
 */
static const vshCmdInfo info_attach_disk[] = {
    {"help", N_("attach disk device")},
    {"desc", N_("Attach new disk device.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_attach_disk[] = {
    {"domain",  VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"source",  VSH_OT_DATA, VSH_OFLAG_REQ | VSH_OFLAG_EMPTY_OK,
     N_("source of disk device")},
    {"target",  VSH_OT_DATA, VSH_OFLAG_REQ, N_("target of disk device")},
    {"driver",    VSH_OT_STRING, 0, N_("driver of disk device")},
    {"subdriver", VSH_OT_STRING, 0, N_("subdriver of disk device")},
    {"cache",     VSH_OT_STRING, 0, N_("cache mode of disk device")},
    {"type",    VSH_OT_STRING, 0, N_("target device type")},
    {"mode",    VSH_OT_STRING, 0, N_("mode of device reading and writing")},
    {"persistent", VSH_OT_ALIAS, 0, "config"},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {"sourcetype", VSH_OT_STRING, 0, N_("type of source (block|file)")},
    {"serial", VSH_OT_STRING, 0, N_("serial of disk device")},
    {"shareable", VSH_OT_BOOL, 0, N_("shareable between domains")},
    {"rawio", VSH_OT_BOOL, 0, N_("needs rawio capability")},
    {"address", VSH_OT_STRING, 0, N_("address of disk device")},
    {"multifunction", VSH_OT_BOOL, 0,
     N_("use multifunction pci under specified address")},
    {NULL, 0, 0, NULL}
};

enum {
    DISK_ADDR_TYPE_INVALID,
    DISK_ADDR_TYPE_PCI,
    DISK_ADDR_TYPE_SCSI,
    DISK_ADDR_TYPE_IDE,
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
    unsigned int unit;
};

struct IDEAddress {
    unsigned int controller;
    unsigned int bus;
    unsigned int unit;
};

struct DiskAddress {
    int type;
    union {
        struct PCIAddress pci;
        struct SCSIAddress scsi;
        struct IDEAddress ide;
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

    if (virStrToLong_ui(domain, &bus, 0, &pciAddr->domain) != 0)
        return -1;

    bus++;
    if (virStrToLong_ui(bus, &slot, 0, &pciAddr->bus) != 0)
        return -1;

    slot++;
    if (virStrToLong_ui(slot, &function, 0, &pciAddr->slot) != 0)
        return -1;

    function++;
    if (virStrToLong_ui(function, NULL, 0, &pciAddr->function) != 0)
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

    if (virStrToLong_ui(controller, &bus, 0, &scsiAddr->controller) != 0)
        return -1;

    bus++;
    if (virStrToLong_ui(bus, &unit, 0, &scsiAddr->bus) != 0)
        return -1;

    unit++;
    if (virStrToLong_ui(unit, NULL, 0, &scsiAddr->unit) != 0)
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

    if (virStrToLong_ui(controller, &bus, 0, &ideAddr->controller) != 0)
        return -1;

    bus++;
    if (virStrToLong_ui(bus, &unit, 0, &ideAddr->bus) != 0)
        return -1;

    unit++;
    if (virStrToLong_ui(unit, NULL, 0, &ideAddr->unit) != 0)
        return -1;

    return 0;
}

/* pci address pci:0000.00.0x0a.0 (domain:bus:slot:function)
 * ide disk address: ide:00.00.0 (controller:bus:unit)
 * scsi disk address: scsi:00.00.0 (controller:bus:unit)
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
    }

    return -1;
}

static bool
cmdAttachDisk(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    const char *source = NULL, *target = NULL, *driver = NULL,
                *subdriver = NULL, *type = NULL, *mode = NULL,
                *cache = NULL, *serial = NULL, *straddr = NULL;
    struct DiskAddress diskAddr;
    bool isFile = false, functionReturn = false;
    int ret;
    unsigned int flags;
    const char *stype = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *xml;
    struct stat st;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        goto cleanup;

    if (vshCommandOptString(cmd, "source", &source) <= 0)
        goto cleanup;
    /* Allow empty string as a placeholder that implies no source, for
     * use in adding a cdrom drive with no disk.  */
    if (!*source)
        source = NULL;

    if (vshCommandOptString(cmd, "target", &target) <= 0)
        goto cleanup;

    if (vshCommandOptString(cmd, "driver", &driver) < 0 ||
        vshCommandOptString(cmd, "subdriver", &subdriver) < 0 ||
        vshCommandOptString(cmd, "type", &type) < 0 ||
        vshCommandOptString(cmd, "mode", &mode) < 0 ||
        vshCommandOptString(cmd, "cache", &cache) < 0 ||
        vshCommandOptString(cmd, "serial", &serial) < 0 ||
        vshCommandOptString(cmd, "address", &straddr) < 0 ||
        vshCommandOptString(cmd, "sourcetype", &stype) < 0) {
        vshError(ctl, "%s", _("missing option"));
        goto cleanup;
    }

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

    /* Make XML of disk */
    virBufferAsprintf(&buf, "<disk type='%s'",
                      (isFile) ? "file" : "block");
    if (type)
        virBufferAsprintf(&buf, " device='%s'", type);
    if (vshCommandOptBool(cmd, "rawio"))
        virBufferAddLit(&buf, " rawio='yes'");
    virBufferAddLit(&buf, ">\n");

    if (driver || subdriver || cache) {
        virBufferAsprintf(&buf, "  <driver");

        if (driver)
            virBufferAsprintf(&buf, " name='%s'", driver);
        if (subdriver)
            virBufferAsprintf(&buf, " type='%s'", subdriver);
        if (cache)
            virBufferAsprintf(&buf, " cache='%s'", cache);

        virBufferAddLit(&buf, "/>\n");
    }

    if (source)
        virBufferAsprintf(&buf, "  <source %s='%s'/>\n",
                          (isFile) ? "file" : "dev",
                          source);
    virBufferAsprintf(&buf, "  <target dev='%s'/>\n", target);
    if (mode)
        virBufferAsprintf(&buf, "  <%s/>\n", mode);

    if (serial)
        virBufferAsprintf(&buf, "  <serial>%s</serial>\n", serial);

    if (vshCommandOptBool(cmd, "shareable"))
        virBufferAsprintf(&buf, "  <shareable/>\n");

    if (straddr) {
        if (str2DiskAddress(straddr, &diskAddr) != 0) {
            vshError(ctl, _("Invalid address."));
            goto cleanup;
        }

        if (STRPREFIX((const char *)target, "vd")) {
            if (diskAddr.type == DISK_ADDR_TYPE_PCI) {
                virBufferAsprintf(&buf,
                                  "  <address type='pci' domain='0x%04x'"
                                  " bus ='0x%02x' slot='0x%02x' function='0x%0x'",
                                  diskAddr.addr.pci.domain, diskAddr.addr.pci.bus,
                                  diskAddr.addr.pci.slot, diskAddr.addr.pci.function);
                if (vshCommandOptBool(cmd, "multifunction"))
                    virBufferAddLit(&buf, " multifunction='on'");
                virBufferAddLit(&buf, "/>\n");
            } else {
                vshError(ctl, "%s", _("expecting a pci:0000.00.00.00 address."));
                goto cleanup;
            }
        } else if (STRPREFIX((const char *)target, "sd")) {
            if (diskAddr.type == DISK_ADDR_TYPE_SCSI) {
                virBufferAsprintf(&buf,
                                  "  <address type='drive' controller='%d'"
                                  " bus='%d' unit='%d' />\n",
                                  diskAddr.addr.scsi.controller, diskAddr.addr.scsi.bus,
                                  diskAddr.addr.scsi.unit);
            } else {
                vshError(ctl, "%s", _("expecting a scsi:00.00.00 address."));
                goto cleanup;
            }
        } else if (STRPREFIX((const char *)target, "hd")) {
            if (diskAddr.type == DISK_ADDR_TYPE_IDE) {
                virBufferAsprintf(&buf,
                                  "  <address type='drive' controller='%d'"
                                  " bus='%d' unit='%d' />\n",
                                  diskAddr.addr.ide.controller, diskAddr.addr.ide.bus,
                                  diskAddr.addr.ide.unit);
            } else {
                vshError(ctl, "%s", _("expecting an ide:00.00.00 address."));
                goto cleanup;
            }
        }
    }

    virBufferAddLit(&buf, "</disk>\n");

    if (virBufferError(&buf)) {
        vshPrint(ctl, "%s", _("Failed to allocate XML buffer"));
        return false;
    }

    xml = virBufferContentAndReset(&buf);

    if (vshCommandOptBool(cmd, "config")) {
        flags = VIR_DOMAIN_AFFECT_CONFIG;
        if (virDomainIsActive(dom) == 1)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
        ret = virDomainAttachDeviceFlags(dom, xml, flags);
    } else {
        ret = virDomainAttachDevice(dom, xml);
    }

    VIR_FREE(xml);

    if (ret != 0) {
        vshError(ctl, "%s", _("Failed to attach disk"));
    } else {
        vshPrint(ctl, "%s", _("Disk attached successfully\n"));
        functionReturn = true;
    }

 cleanup:
    if (dom)
        virDomainFree(dom);
    virBufferFreeAndReset(&buf);
    return functionReturn;
}

/*
 * "attach-interface" command
 */
static const vshCmdInfo info_attach_interface[] = {
    {"help", N_("attach network interface")},
    {"desc", N_("Attach new network interface.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_attach_interface[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"type",   VSH_OT_DATA, VSH_OFLAG_REQ, N_("network interface type")},
    {"source", VSH_OT_DATA, VSH_OFLAG_REQ, N_("source of network interface")},
    {"target", VSH_OT_DATA, 0, N_("target network name")},
    {"mac",    VSH_OT_DATA, 0, N_("MAC address")},
    {"script", VSH_OT_DATA, 0, N_("script used to bridge network interface")},
    {"model", VSH_OT_DATA, 0, N_("model type")},
    {"persistent", VSH_OT_ALIAS, 0, "config"},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {"inbound", VSH_OT_DATA, VSH_OFLAG_NONE, N_("control domain's incoming traffics")},
    {"outbound", VSH_OT_DATA, VSH_OFLAG_NONE, N_("control domain's outgoing traffics")},
    {NULL, 0, 0, NULL}
};

/* parse inbound and outbound which are in the format of
 * 'average,peak,burst', in which peak and burst are optional,
 * thus 'average,,burst' and 'average,peak' are also legal. */
static int parseRateStr(const char *rateStr, virNetDevBandwidthRatePtr rate)
{
    const char *average = NULL;
    char *peak = NULL, *burst = NULL;

    average = rateStr;
    if (!average)
        return -1;
    if (virStrToLong_ull(average, &peak, 10, &rate->average) < 0)
        return -1;

    /* peak will be updated to point to the end of rateStr in case
     * of 'average' */
    if (peak && *peak != '\0') {
        burst = strchr(peak + 1, ',');
        if (!(burst && (burst - peak == 1))) {
            if (virStrToLong_ull(peak + 1, &burst, 10, &rate->peak) < 0)
                return -1;
        }

        /* burst will be updated to point to the end of rateStr in case
         * of 'average,peak' */
        if (burst && *burst != '\0') {
            if (virStrToLong_ull(burst + 1, NULL, 10, &rate->burst) < 0)
                return -1;
        }
    }


    return 0;
}

static bool
cmdAttachInterface(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    const char *mac = NULL, *target = NULL, *script = NULL,
                *type = NULL, *source = NULL, *model = NULL,
                *inboundStr = NULL, *outboundStr = NULL;
    virNetDevBandwidthRate inbound, outbound;
    int typ;
    int ret;
    bool functionReturn = false;
    unsigned int flags;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *xml;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        goto cleanup;

    if (vshCommandOptString(cmd, "type", &type) <= 0)
        goto cleanup;

    if (vshCommandOptString(cmd, "source", &source) < 0 ||
        vshCommandOptString(cmd, "target", &target) < 0 ||
        vshCommandOptString(cmd, "mac", &mac) < 0 ||
        vshCommandOptString(cmd, "script", &script) < 0 ||
        vshCommandOptString(cmd, "model", &model) < 0 ||
        vshCommandOptString(cmd, "inbound", &inboundStr) < 0 ||
        vshCommandOptString(cmd, "outbound", &outboundStr) < 0) {
        vshError(ctl, "missing argument");
        goto cleanup;
    }

    /* check interface type */
    if (STREQ(type, "network")) {
        typ = 1;
    } else if (STREQ(type, "bridge")) {
        typ = 2;
    } else {
        vshError(ctl, _("No support for %s in command 'attach-interface'"),
                 type);
        goto cleanup;
    }

    if (inboundStr) {
        memset(&inbound, 0, sizeof(inbound));
        if (parseRateStr(inboundStr, &inbound) < 0) {
            vshError(ctl, _("inbound format is incorrect"));
            goto cleanup;
        }
        if (inbound.average == 0) {
            vshError(ctl, _("inbound average is mandatory"));
            goto cleanup;
        }
    }
    if (outboundStr) {
        memset(&outbound, 0, sizeof(outbound));
        if (parseRateStr(outboundStr, &outbound) < 0) {
            vshError(ctl, _("outbound format is incorrect"));
            goto cleanup;
        }
        if (outbound.average == 0) {
            vshError(ctl, _("outbound average is mandatory"));
            goto cleanup;
        }
    }

    /* Make XML of interface */
    virBufferAsprintf(&buf, "<interface type='%s'>\n", type);

    if (typ == 1)
        virBufferAsprintf(&buf, "  <source network='%s'/>\n", source);
    else if (typ == 2)
        virBufferAsprintf(&buf, "  <source bridge='%s'/>\n", source);

    if (target != NULL)
        virBufferAsprintf(&buf, "  <target dev='%s'/>\n", target);
    if (mac != NULL)
        virBufferAsprintf(&buf, "  <mac address='%s'/>\n", mac);
    if (script != NULL)
        virBufferAsprintf(&buf, "  <script path='%s'/>\n", script);
    if (model != NULL)
        virBufferAsprintf(&buf, "  <model type='%s'/>\n", model);

    if (inboundStr || outboundStr) {
        virBufferAsprintf(&buf, "  <bandwidth>\n");
        if (inboundStr && inbound.average > 0) {
            virBufferAsprintf(&buf, "    <inbound average='%llu'", inbound.average);
            if (inbound.peak > 0)
                virBufferAsprintf(&buf, " peak='%llu'", inbound.peak);
            if (inbound.burst > 0)
                virBufferAsprintf(&buf, " burst='%llu'", inbound.burst);
            virBufferAsprintf(&buf, "/>\n");
        }
        if (outboundStr && outbound.average > 0) {
            virBufferAsprintf(&buf, "    <outbound average='%llu'", outbound.average);
            if (outbound.peak > 0)
                virBufferAsprintf(&buf, " peak='%llu'", outbound.peak);
            if (outbound.burst > 0)
                virBufferAsprintf(&buf, " burst='%llu'", outbound.burst);
            virBufferAsprintf(&buf, "/>\n");
        }
        virBufferAsprintf(&buf, "  </bandwidth>\n");
    }

    virBufferAddLit(&buf, "</interface>\n");

    if (virBufferError(&buf)) {
        vshPrint(ctl, "%s", _("Failed to allocate XML buffer"));
        goto cleanup;
    }

    xml = virBufferContentAndReset(&buf);

    if (vshCommandOptBool(cmd, "config")) {
        flags = VIR_DOMAIN_AFFECT_CONFIG;
        if (virDomainIsActive(dom) == 1)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
        ret = virDomainAttachDeviceFlags(dom, xml, flags);
    } else {
        ret = virDomainAttachDevice(dom, xml);
    }

    VIR_FREE(xml);

    if (ret != 0) {
        vshError(ctl, "%s", _("Failed to attach interface"));
    } else {
        vshPrint(ctl, "%s", _("Interface attached successfully\n"));
        functionReturn = true;
    }

 cleanup:
    if (dom)
        virDomainFree(dom);
    virBufferFreeAndReset(&buf);
    return functionReturn;
}

/*
 * "autostart" command
 */
static const vshCmdInfo info_autostart[] = {
    {"help", N_("autostart a domain")},
    {"desc",
     N_("Configure a domain to be automatically started at boot.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_autostart[] = {
    {"domain",  VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"disable", VSH_OT_BOOL, 0, N_("disable autostarting")},
    {NULL, 0, 0, NULL}
};

static bool
cmdAutostart(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *name;
    int autostart;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    autostart = !vshCommandOptBool(cmd, "disable");

    if (virDomainSetAutostart(dom, autostart) < 0) {
        if (autostart)
            vshError(ctl, _("Failed to mark domain %s as autostarted"), name);
        else
            vshError(ctl, _("Failed to unmark domain %s as autostarted"), name);
        virDomainFree(dom);
        return false;
    }

    if (autostart)
        vshPrint(ctl, _("Domain %s marked as autostarted\n"), name);
    else
        vshPrint(ctl, _("Domain %s unmarked as autostarted\n"), name);

    virDomainFree(dom);
    return true;
}

/*
 * "blkdeviotune" command
 */
static const vshCmdInfo info_blkdeviotune[] = {
    {"help", N_("Set or query a block device I/O tuning parameters.")},
    {"desc", N_("Set or query disk I/O parameters such as block throttling.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_blkdeviotune[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"device", VSH_OT_DATA, VSH_OFLAG_REQ, N_("block device")},
    {"total_bytes_sec", VSH_OT_ALIAS, 0, "total-bytes-sec"},
    {"total-bytes-sec", VSH_OT_INT, VSH_OFLAG_NONE,
     N_("total throughput limit in bytes per second")},
    {"read_bytes_sec", VSH_OT_ALIAS, 0, "read-bytes-sec"},
    {"read-bytes-sec", VSH_OT_INT, VSH_OFLAG_NONE,
     N_("read throughput limit in bytes per second")},
    {"write_bytes_sec", VSH_OT_ALIAS, 0, "write-bytes-sec"},
    {"write-bytes-sec", VSH_OT_INT, VSH_OFLAG_NONE,
     N_("write throughput limit in bytes per second")},
    {"total_iops_sec", VSH_OT_ALIAS, 0, "total-iops-sec"},
    {"total-iops-sec", VSH_OT_INT, VSH_OFLAG_NONE,
     N_("total I/O operations limit per second")},
    {"read_iops_sec", VSH_OT_ALIAS, 0, "read-iops-sec"},
    {"read-iops-sec", VSH_OT_INT, VSH_OFLAG_NONE,
     N_("read I/O operations limit per second")},
    {"write_iops_sec", VSH_OT_ALIAS, 0, "write-iops-sec"},
    {"write-iops-sec", VSH_OT_INT, VSH_OFLAG_NONE,
     N_("write I/O operations limit per second")},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {"live", VSH_OT_BOOL, 0, N_("affect running domain")},
    {"current", VSH_OT_BOOL, 0, N_("affect current domain")},
    {NULL, 0, 0, NULL}
};

static bool
cmdBlkdeviotune(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    const char *name, *disk;
    unsigned long long total_bytes_sec = 0, read_bytes_sec = 0, write_bytes_sec = 0;
    unsigned long long total_iops_sec = 0, read_iops_sec = 0, write_iops_sec = 0;
    int nparams = 0;
    virTypedParameterPtr params = NULL;
    unsigned int flags = 0, i = 0;
    int rv = 0;
    bool current = vshCommandOptBool(cmd, "current");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool ret = false;

    if (current) {
        if (live || config) {
            vshError(ctl, "%s", _("--current must be specified exclusively"));
            return false;
        }
        flags = VIR_DOMAIN_AFFECT_CURRENT;
    } else {
        if (config)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        if (live)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        goto cleanup;

    if (vshCommandOptString(cmd, "device", &disk) < 0)
        goto cleanup;

    if ((rv = vshCommandOptULongLong(cmd, "total-bytes-sec",
                                     &total_bytes_sec)) < 0) {
        vshError(ctl, "%s",
                 _("Unable to parse integer parameter"));
        goto cleanup;
    } else if (rv > 0) {
        nparams++;
    }

    if ((rv = vshCommandOptULongLong(cmd, "read-bytes-sec",
                                     &read_bytes_sec)) < 0) {
        vshError(ctl, "%s",
                 _("Unable to parse integer parameter"));
        goto cleanup;
    } else if (rv > 0) {
        nparams++;
    }

    if ((rv = vshCommandOptULongLong(cmd, "write-bytes-sec",
                                     &write_bytes_sec)) < 0) {
        vshError(ctl, "%s",
                 _("Unable to parse integer parameter"));
        goto cleanup;
    } else if (rv > 0) {
        nparams++;
    }

    if ((rv = vshCommandOptULongLong(cmd, "total-iops-sec",
                                     &total_iops_sec)) < 0) {
        vshError(ctl, "%s",
                 _("Unable to parse integer parameter"));
        goto cleanup;
    } else if (rv > 0) {
        nparams++;
    }

    if ((rv = vshCommandOptULongLong(cmd, "read-iops-sec",
                                     &read_iops_sec)) < 0) {
        vshError(ctl, "%s",
                 _("Unable to parse integer parameter"));
        goto cleanup;
    } else if (rv > 0) {
        nparams++;
    }

    if ((rv = vshCommandOptULongLong(cmd, "write-iops-sec",
                                     &write_iops_sec)) < 0) {
        vshError(ctl, "%s",
                 _("Unable to parse integer parameter"));
        goto cleanup;
    } else if (rv > 0) {
        nparams++;
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

        ret = true;
        goto cleanup;
    } else {
        /* Set the block I/O throttle, match by opt since parameters can be 0 */
        params = vshCalloc(ctl, nparams, sizeof(*params));
        i = 0;

        if (i < nparams && vshCommandOptBool(cmd, "total-bytes-sec") &&
            virTypedParameterAssign(&params[i++],
                                    VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_BYTES_SEC,
                                    VIR_TYPED_PARAM_ULLONG,
                                    total_bytes_sec) < 0)
            goto error;

        if (i < nparams && vshCommandOptBool(cmd, "read-bytes-sec") &&
            virTypedParameterAssign(&params[i++],
                                    VIR_DOMAIN_BLOCK_IOTUNE_READ_BYTES_SEC,
                                    VIR_TYPED_PARAM_ULLONG,
                                    read_bytes_sec) < 0)
            goto error;

        if (i < nparams && vshCommandOptBool(cmd, "write-bytes-sec") &&
            virTypedParameterAssign(&params[i++],
                                    VIR_DOMAIN_BLOCK_IOTUNE_WRITE_BYTES_SEC,
                                    VIR_TYPED_PARAM_ULLONG,
                                    write_bytes_sec) < 0)
            goto error;

        if (i < nparams && vshCommandOptBool(cmd, "total-iops-sec") &&
            virTypedParameterAssign(&params[i++],
                                    VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_IOPS_SEC,
                                    VIR_TYPED_PARAM_ULLONG,
                                    total_iops_sec) < 0)
            goto error;

        if (i < nparams && vshCommandOptBool(cmd, "read-iops-sec") &&
            virTypedParameterAssign(&params[i++],
                                    VIR_DOMAIN_BLOCK_IOTUNE_READ_IOPS_SEC,
                                    VIR_TYPED_PARAM_ULLONG,
                                    read_iops_sec) < 0)
            goto error;

        if (i < nparams && vshCommandOptBool(cmd, "write-iops-sec") &&
            virTypedParameterAssign(&params[i++],
                                    VIR_DOMAIN_BLOCK_IOTUNE_WRITE_IOPS_SEC,
                                    VIR_TYPED_PARAM_ULLONG,
                                    write_iops_sec) < 0)
            goto error;

        if (virDomainSetBlockIoTune(dom, disk, params, nparams, flags) < 0)
            goto error;
    }

    ret = true;

cleanup:
    VIR_FREE(params);
    virDomainFree(dom);
    return ret;

error:
    vshError(ctl, "%s", _("Unable to change block I/O throttle"));
    goto cleanup;
}

/*
 * "blkiotune" command
 */
static const vshCmdInfo info_blkiotune[] = {
    {"help", N_("Get or set blkio parameters")},
    {"desc", N_("Get or set the current blkio parameters for a guest"
                " domain.\n"
                "    To get the blkio parameters use following command: \n\n"
                "    virsh # blkiotune <domain>")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_blkiotune[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"weight", VSH_OT_INT, VSH_OFLAG_NONE,
     N_("IO Weight in range [100, 1000]")},
    {"device-weights", VSH_OT_STRING, VSH_OFLAG_NONE,
     N_("per-device IO Weights, in the form of /path/to/device,weight,...")},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {"live", VSH_OT_BOOL, 0, N_("affect running domain")},
    {"current", VSH_OT_BOOL, 0, N_("affect current domain")},
    {NULL, 0, 0, NULL}
};

static bool
cmdBlkiotune(vshControl * ctl, const vshCmd * cmd)
{
    virDomainPtr dom;
    const char *device_weight = NULL;
    int weight = 0;
    int nparams = 0;
    int rv = 0;
    unsigned int i = 0;
    virTypedParameterPtr params = NULL, temp = NULL;
    bool ret = false;
    unsigned int flags = 0;
    bool current = vshCommandOptBool(cmd, "current");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");

    if (current) {
        if (live || config) {
            vshError(ctl, "%s", _("--current must be specified exclusively"));
            return false;
        }
        flags = VIR_DOMAIN_AFFECT_CURRENT;
    } else {
        if (config)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        if (live)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if ((rv = vshCommandOptInt(cmd, "weight", &weight)) < 0) {
        vshError(ctl, "%s",
                 _("Unable to parse integer parameter"));
        goto cleanup;
    }

    if (rv > 0) {
        nparams++;
        if (weight <= 0) {
            vshError(ctl, _("Invalid value of %d for I/O weight"), weight);
            goto cleanup;
        }
    }

    rv = vshCommandOptString(cmd, "device-weights", &device_weight);
    if (rv < 0) {
        vshError(ctl, "%s",
                 _("Unable to parse string parameter"));
        goto cleanup;
    }
    if (rv > 0) {
        nparams++;
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
        params = vshCalloc(ctl, nparams, sizeof(*params));

        for (i = 0; i < nparams; i++) {
            temp = &params[i];
            temp->type = VIR_TYPED_PARAM_UINT;

            if (weight) {
                temp->value.ui = weight;
                if (!virStrcpy(temp->field, VIR_DOMAIN_BLKIO_WEIGHT,
                               sizeof(temp->field)))
                    goto cleanup;
                weight = 0;
            } else if (device_weight) {
                temp->value.s = vshStrdup(ctl, device_weight);
                temp->type = VIR_TYPED_PARAM_STRING;
                if (!virStrcpy(temp->field, VIR_DOMAIN_BLKIO_DEVICE_WEIGHT,
                               sizeof(temp->field)))
                    goto cleanup;
                device_weight = NULL;
            }
        }

        if (virDomainSetBlkioParameters(dom, params, nparams, flags) < 0) {
            vshError(ctl, "%s", _("Unable to change blkio parameters"));
            goto cleanup;
        }
    }

    ret = true;

  cleanup:
    virTypedParameterArrayClear(params, nparams);
    VIR_FREE(params);
    virDomainFree(dom);
    return ret;
}

typedef enum {
    VSH_CMD_BLOCK_JOB_ABORT = 0,
    VSH_CMD_BLOCK_JOB_INFO = 1,
    VSH_CMD_BLOCK_JOB_SPEED = 2,
    VSH_CMD_BLOCK_JOB_PULL = 3,
    VSH_CMD_BLOCK_JOB_COPY = 4,
} vshCmdBlockJobMode;

static int
blockJobImpl(vshControl *ctl, const vshCmd *cmd,
             virDomainBlockJobInfoPtr info, int mode,
             virDomainPtr *pdom)
{
    virDomainPtr dom = NULL;
    const char *name, *path;
    unsigned long bandwidth = 0;
    int ret = -1;
    const char *base = NULL;
    unsigned int flags = 0;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        goto cleanup;

    if (vshCommandOptString(cmd, "path", &path) < 0)
        goto cleanup;

    if (vshCommandOptUL(cmd, "bandwidth", &bandwidth) < 0) {
        vshError(ctl, "%s", _("bandwidth must be a number"));
        goto cleanup;
    }

    switch ((vshCmdBlockJobMode) mode) {
    case  VSH_CMD_BLOCK_JOB_ABORT:
        if (vshCommandOptBool(cmd, "async"))
            flags |= VIR_DOMAIN_BLOCK_JOB_ABORT_ASYNC;
        if (vshCommandOptBool(cmd, "pivot"))
            flags |= VIR_DOMAIN_BLOCK_JOB_ABORT_PIVOT;
        ret = virDomainBlockJobAbort(dom, path, flags);
        break;
    case VSH_CMD_BLOCK_JOB_INFO:
        ret = virDomainGetBlockJobInfo(dom, path, info, 0);
        break;
    case VSH_CMD_BLOCK_JOB_SPEED:
        ret = virDomainBlockJobSetSpeed(dom, path, bandwidth, 0);
        break;
    case VSH_CMD_BLOCK_JOB_PULL:
        if (vshCommandOptString(cmd, "base", &base) < 0)
            goto cleanup;
        if (base)
            ret = virDomainBlockRebase(dom, path, base, bandwidth, 0);
        else
            ret = virDomainBlockPull(dom, path, bandwidth, 0);
        break;
    case VSH_CMD_BLOCK_JOB_COPY:
        flags |= VIR_DOMAIN_BLOCK_REBASE_COPY;
        if (vshCommandOptBool(cmd, "shallow"))
            flags |= VIR_DOMAIN_BLOCK_REBASE_SHALLOW;
        if (vshCommandOptBool(cmd, "reuse-external"))
            flags |= VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT;
        if (vshCommandOptBool(cmd, "raw"))
            flags |= VIR_DOMAIN_BLOCK_REBASE_COPY_RAW;
        if (vshCommandOptString(cmd, "dest", &base) < 0)
            goto cleanup;
        ret = virDomainBlockRebase(dom, path, base, bandwidth, flags);
    }

cleanup:
    if (pdom && ret == 0)
        *pdom = dom;
    else if (dom)
        virDomainFree(dom);
    return ret;
}

static void
print_job_progress(const char *label, unsigned long long remaining,
                   unsigned long long total)
{
    int progress;

    if (total == 0)
        /* migration has not been started */
        return;

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

/*
 * "blockcopy" command
 */
static const vshCmdInfo info_block_copy[] = {
    {"help", N_("Start a block copy operation.")},
    {"desc", N_("Populate a disk from its backing image.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_block_copy[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"path", VSH_OT_DATA, VSH_OFLAG_REQ, N_("fully-qualified path of disk")},
    {"dest", VSH_OT_DATA, VSH_OFLAG_REQ, N_("path of the copy to create")},
    {"bandwidth", VSH_OT_DATA, VSH_OFLAG_NONE, N_("bandwidth limit in MiB/s")},
    {"shallow", VSH_OT_BOOL, 0, N_("make the copy share a backing chain")},
    {"reuse-external", VSH_OT_BOOL, 0, N_("reuse existing destination")},
    {"raw", VSH_OT_BOOL, 0, N_("use raw destination file")},
    {"wait", VSH_OT_BOOL, 0, N_("wait for job to reach mirroring phase")},
    {"verbose", VSH_OT_BOOL, 0, N_("with --wait, display the progress")},
    {"timeout", VSH_OT_INT, VSH_OFLAG_NONE,
     N_("with --wait, abort if copy exceeds timeout (in seconds)")},
    {"pivot", VSH_OT_BOOL, 0, N_("with --wait, pivot when mirroring starts")},
    {"finish", VSH_OT_BOOL, 0, N_("with --wait, quit when mirroring starts")},
    {"async", VSH_OT_BOOL, 0,
     N_("with --wait, don't wait for cancel to finish")},
    {NULL, 0, 0, NULL}
};

static bool
cmdBlockCopy(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    bool blocking = vshCommandOptBool(cmd, "wait");
    bool verbose = vshCommandOptBool(cmd, "verbose");
    bool pivot = vshCommandOptBool(cmd, "pivot");
    bool finish = vshCommandOptBool(cmd, "finish");
    int timeout = 0;
    struct sigaction sig_action;
    struct sigaction old_sig_action;
    sigset_t sigmask;
    struct timeval start;
    struct timeval curr;
    const char *path = NULL;
    bool quit = false;
    int abort_flags = 0;

    if (blocking) {
        if (pivot && finish) {
            vshError(ctl, "%s", _("cannot mix --pivot and --finish"));
            return false;
        }
        if (vshCommandOptInt(cmd, "timeout", &timeout) > 0) {
            if (timeout < 1) {
                vshError(ctl, "%s", _("migrate: Invalid timeout"));
                return false;
            }

            /* Ensure that we can multiply by 1000 without overflowing. */
            if (timeout > INT_MAX / 1000) {
                vshError(ctl, "%s", _("migrate: Timeout is too big"));
                return false;
            }
        }
        if (vshCommandOptString(cmd, "path", &path) < 0)
            return false;
        if (vshCommandOptBool(cmd, "async"))
            abort_flags |= VIR_DOMAIN_BLOCK_JOB_ABORT_ASYNC;

        sigemptyset(&sigmask);
        sigaddset(&sigmask, SIGINT);

        intCaught = 0;
        sig_action.sa_sigaction = vshCatchInt;
        sig_action.sa_flags = SA_SIGINFO;
        sigemptyset(&sig_action.sa_mask);
        sigaction(SIGINT, &sig_action, &old_sig_action);

        GETTIMEOFDAY(&start);
    } else if (verbose || vshCommandOptBool(cmd, "timeout") ||
               vshCommandOptBool(cmd, "async") || pivot || finish) {
        vshError(ctl, "%s", _("blocking control options require --wait"));
        return false;
    }

    if (blockJobImpl(ctl, cmd, NULL, VSH_CMD_BLOCK_JOB_COPY, &dom) < 0)
        goto cleanup;

    if (!blocking) {
        vshPrint(ctl, "%s", _("Block Copy started"));
        ret = true;
        goto cleanup;
    }

    while (blocking) {
        virDomainBlockJobInfo info;
        int result = virDomainGetBlockJobInfo(dom, path, &info, 0);

        if (result <= 0) {
            vshError(ctl, _("failed to query job for disk %s"), path);
            goto cleanup;
        }
        if (verbose)
            print_job_progress(_("Block Copy"), info.end - info.cur, info.end);
        if (info.cur == info.end)
            break;

        GETTIMEOFDAY(&curr);
        if (intCaught || (timeout &&
                          (((int)(curr.tv_sec - start.tv_sec)  * 1000 +
                            (int)(curr.tv_usec - start.tv_usec) / 1000) >
                           timeout * 1000))) {
            vshDebug(ctl, VSH_ERR_DEBUG,
                     intCaught ? "interrupted" : "timeout");
            intCaught = 0;
            timeout = 0;
            quit = true;
            if (virDomainBlockJobAbort(dom, path, abort_flags) < 0) {
                vshError(ctl, _("failed to abort job for disk %s"), path);
                goto cleanup;
            }
            if (abort_flags & VIR_DOMAIN_BLOCK_JOB_ABORT_ASYNC)
                break;
        } else {
            usleep(500 * 1000);
        }
    }

    if (pivot) {
        abort_flags |= VIR_DOMAIN_BLOCK_JOB_ABORT_PIVOT;
        if (virDomainBlockJobAbort(dom, path, abort_flags) < 0) {
            vshError(ctl, _("failed to pivot job for disk %s"), path);
            goto cleanup;
        }
    } else if (finish && virDomainBlockJobAbort(dom, path, abort_flags) < 0) {
        vshError(ctl, _("failed to finish job for disk %s"), path);
        goto cleanup;
    }
    vshPrint(ctl, "\n%s",
             quit ? _("Copy aborted") :
             pivot ? _("Successfully pivoted") :
             finish ? _("Successfully copied") :
             _("Now in mirroring phase"));

    ret = true;
cleanup:
    if (dom)
        virDomainFree(dom);
    if (blocking)
        sigaction(SIGINT, &old_sig_action, NULL);
    return ret;
}

/*
 * "blockjob" command
 */
static const vshCmdInfo info_block_job[] = {
    {"help", N_("Manage active block operations")},
    {"desc", N_("Query, adjust speed, or cancel active block operations.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_block_job[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"path", VSH_OT_DATA, VSH_OFLAG_REQ, N_("fully-qualified path of disk")},
    {"abort", VSH_OT_BOOL, VSH_OFLAG_NONE,
     N_("abort the active job on the specified disk")},
    {"async", VSH_OT_BOOL, VSH_OFLAG_NONE,
     N_("don't wait for --abort to complete")},
    {"pivot", VSH_OT_BOOL, VSH_OFLAG_NONE,
     N_("conclude and pivot a copy job")},
    {"info", VSH_OT_BOOL, VSH_OFLAG_NONE,
     N_("get active job information for the specified disk")},
    {"bandwidth", VSH_OT_DATA, VSH_OFLAG_NONE,
     N_("set the Bandwidth limit in MiB/s")},
    {NULL, 0, 0, NULL}
};

static bool
cmdBlockJob(vshControl *ctl, const vshCmd *cmd)
{
    int mode;
    virDomainBlockJobInfo info;
    const char *type;
    int ret;
    bool abortMode = (vshCommandOptBool(cmd, "abort") ||
                      vshCommandOptBool(cmd, "async") ||
                      vshCommandOptBool(cmd, "pivot"));
    bool infoMode = vshCommandOptBool(cmd, "info");
    bool bandwidth = vshCommandOptBool(cmd, "bandwidth");

    if (abortMode + infoMode + bandwidth > 1) {
        vshError(ctl, "%s",
                 _("conflict between --abort, --info, and --bandwidth modes"));
        return false;
    }

    if (abortMode)
        mode = VSH_CMD_BLOCK_JOB_ABORT;
    else if (bandwidth)
        mode = VSH_CMD_BLOCK_JOB_SPEED;
    else
        mode = VSH_CMD_BLOCK_JOB_INFO;

    ret = blockJobImpl(ctl, cmd, &info, mode, NULL);
    if (ret < 0)
        return false;

    if (ret == 0 || mode != VSH_CMD_BLOCK_JOB_INFO)
        return true;

    switch (info.type) {
    case VIR_DOMAIN_BLOCK_JOB_TYPE_PULL:
        type = _("Block Pull");
        break;
    case VIR_DOMAIN_BLOCK_JOB_TYPE_COPY:
        type = _("Block Copy");
        break;
    default:
        type = _("Unknown job");
        break;
    }

    print_job_progress(type, info.end - info.cur, info.end);
    if (info.bandwidth != 0)
        vshPrint(ctl, _("    Bandwidth limit: %lu MiB/s\n"), info.bandwidth);
    return true;
}

/*
 * "blockpull" command
 */
static const vshCmdInfo info_block_pull[] = {
    {"help", N_("Populate a disk from its backing image.")},
    {"desc", N_("Populate a disk from its backing image.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_block_pull[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"path", VSH_OT_DATA, VSH_OFLAG_REQ, N_("fully-qualified path of disk")},
    {"bandwidth", VSH_OT_DATA, VSH_OFLAG_NONE, N_("bandwidth limit in MiB/s")},
    {"base", VSH_OT_DATA, VSH_OFLAG_NONE,
     N_("path of backing file in chain for a partial pull")},
    {"wait", VSH_OT_BOOL, 0, N_("wait for job to finish")},
    {"verbose", VSH_OT_BOOL, 0, N_("with --wait, display the progress")},
    {"timeout", VSH_OT_INT, VSH_OFLAG_NONE,
     N_("with --wait, abort if pull exceeds timeout (in seconds)")},
    {"async", VSH_OT_BOOL, 0,
     N_("with --wait, don't wait for cancel to finish")},
    {NULL, 0, 0, NULL}
};

static bool
cmdBlockPull(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    bool blocking = vshCommandOptBool(cmd, "wait");
    bool verbose = vshCommandOptBool(cmd, "verbose");
    int timeout = 0;
    struct sigaction sig_action;
    struct sigaction old_sig_action;
    sigset_t sigmask;
    struct timeval start;
    struct timeval curr;
    const char *path = NULL;
    bool quit = false;
    int abort_flags = 0;

    if (blocking) {
        if (vshCommandOptInt(cmd, "timeout", &timeout) > 0) {
            if (timeout < 1) {
                vshError(ctl, "%s", _("invalid timeout"));
                return false;
            }

            /* Ensure that we can multiply by 1000 without overflowing. */
            if (timeout > INT_MAX / 1000) {
                vshError(ctl, "%s", _("timeout is too big"));
                return false;
            }
        }
        if (vshCommandOptString(cmd, "path", &path) < 0)
            return false;
        if (vshCommandOptBool(cmd, "async"))
            abort_flags |= VIR_DOMAIN_BLOCK_JOB_ABORT_ASYNC;

        sigemptyset(&sigmask);
        sigaddset(&sigmask, SIGINT);

        intCaught = 0;
        sig_action.sa_sigaction = vshCatchInt;
        sig_action.sa_flags = SA_SIGINFO;
        sigemptyset(&sig_action.sa_mask);
        sigaction(SIGINT, &sig_action, &old_sig_action);

        GETTIMEOFDAY(&start);
    } else if (verbose || vshCommandOptBool(cmd, "timeout") ||
               vshCommandOptBool(cmd, "async")) {
        vshError(ctl, "%s", _("blocking control options require --wait"));
        return false;
    }

    if (blockJobImpl(ctl, cmd, NULL, VSH_CMD_BLOCK_JOB_PULL, &dom) < 0)
        goto cleanup;

    if (!blocking) {
        vshPrint(ctl, "%s", _("Block Pull started"));
        ret = true;
        goto cleanup;
    }

    while (blocking) {
        virDomainBlockJobInfo info;
        int result = virDomainGetBlockJobInfo(dom, path, &info, 0);

        if (result < 0) {
            vshError(ctl, _("failed to query job for disk %s"), path);
            goto cleanup;
        }
        if (result == 0)
            break;

        if (verbose)
            print_job_progress(_("Block Pull"), info.end - info.cur, info.end);

        GETTIMEOFDAY(&curr);
        if (intCaught || (timeout &&
                          (((int)(curr.tv_sec - start.tv_sec)  * 1000 +
                            (int)(curr.tv_usec - start.tv_usec) / 1000) >
                           timeout * 1000))) {
            vshDebug(ctl, VSH_ERR_DEBUG,
                     intCaught ? "interrupted" : "timeout");
            intCaught = 0;
            timeout = 0;
            quit = true;
            if (virDomainBlockJobAbort(dom, path, abort_flags) < 0) {
                vshError(ctl, _("failed to abort job for disk %s"), path);
                goto cleanup;
            }
            if (abort_flags & VIR_DOMAIN_BLOCK_JOB_ABORT_ASYNC)
                break;
        } else {
            usleep(500 * 1000);
        }
    }

    if (verbose && !quit) {
        /* printf [100 %] */
        print_job_progress(_("Block Pull"), 0, 1);
    }
    vshPrint(ctl, "\n%s", quit ? _("Pull aborted") : _("Pull complete"));

    ret = true;
cleanup:
    if (dom)
        virDomainFree(dom);
    if (blocking)
        sigaction(SIGINT, &old_sig_action, NULL);
    return ret;
}

/*
 * "blockresize" command
 */
static const vshCmdInfo info_block_resize[] = {
    {"help", N_("Resize block device of domain.")},
    {"desc", N_("Resize block device of domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_block_resize[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"path", VSH_OT_DATA, VSH_OFLAG_REQ,
     N_("Fully-qualified path of block device")},
    {"size", VSH_OT_INT, VSH_OFLAG_REQ,
     N_("New size of the block device, as scaled integer (default KiB)")},
    {NULL, 0, 0, NULL}
};

static bool
cmdBlockResize(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *path = NULL;
    unsigned long long size = 0;
    unsigned int flags = 0;
    int ret = false;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "path", (const char **) &path) < 0) {
        vshError(ctl, "%s", _("Path must not be empty"));
        return false;
    }

    if (vshCommandOptScaledInt(cmd, "size", &size, 1024, ULLONG_MAX) < 0) {
        vshError(ctl, "%s", _("Unable to parse integer"));
        return false;
    }

    /* Prefer the older interface of KiB.  */
    if (size % 1024 == 0)
        size /= 1024;
    else
        flags |= VIR_DOMAIN_BLOCK_RESIZE_BYTES;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virDomainBlockResize(dom, path, size, flags) < 0) {
        vshError(ctl, _("Failed to resize block device '%s'"), path);
    } else {
        vshPrint(ctl, _("Block device '%s' is resized"), path);
        ret = true;
    }

    virDomainFree(dom);
    return ret;
}

#ifndef WIN32
/*
 * "console" command
 */
static const vshCmdInfo info_console[] = {
    {"help", N_("connect to the guest console")},
    {"desc",
     N_("Connect the virtual serial console for the guest")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_console[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"devname", VSH_OT_STRING, 0, N_("character device name")},
    {"force", VSH_OT_BOOL, 0,
      N_("force console connection (disconnect already connected sessions)")},
    {"safe", VSH_OT_BOOL, 0,
      N_("only connect if safe console handling is supported")},
    {NULL, 0, 0, NULL}
};

static bool
cmdRunConsole(vshControl *ctl, virDomainPtr dom,
              const char *name,
              unsigned int flags)
{
    bool ret = false;
    int state;

    if ((state = vshDomainState(ctl, dom, NULL)) < 0) {
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
    vshPrintExtra(ctl, _("Escape character is %s\n"), ctl->escapeChar);
    fflush(stdout);
    if (vshRunConsole(dom, name, ctl->escapeChar, flags) == 0)
        ret = true;

 cleanup:

    return ret;
}
#endif /* WIN32 */

static bool
cmdConsole(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = false;
    bool force = vshCommandOptBool(cmd, "force");
    bool safe = vshCommandOptBool(cmd, "safe");
    unsigned int flags = 0;
    const char *name = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptString(cmd, "devname", &name) < 0) {
        vshError(ctl, "%s", _("Invalid devname"));
        goto cleanup;
    }

    if (force)
        flags |= VIR_DOMAIN_CONSOLE_FORCE;
    if (safe)
        flags |= VIR_DOMAIN_CONSOLE_SAFE;

    ret = cmdRunConsole(ctl, dom, name, flags);

cleanup:
    virDomainFree(dom);
    return ret;
}

/* "domif-setlink" command
 */
static const vshCmdInfo info_domif_setlink[] = {
    {"help", N_("set link state of a virtual interface")},
    {"desc", N_("Set link state of a domain's virtual interface. This command wraps usage of update-device command.")},
    {NULL,NULL}
};

static const vshCmdOptDef opts_domif_setlink[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"interface", VSH_OT_DATA, VSH_OFLAG_REQ, N_("interface device (MAC Address)")},
    {"state", VSH_OT_DATA, VSH_OFLAG_REQ, N_("new state of the device")},
    {"persistent", VSH_OT_ALIAS, 0, "config"},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomIfSetLink(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *iface;
    const char *state;
    const char *value;
    const char *desc;
    virMacAddr macaddr;
    const char *element;
    const char *attr;
    bool config;
    bool ret = false;
    unsigned int flags = 0;
    int i;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlXPathObjectPtr obj = NULL;
    xmlNodePtr cur = NULL;
    xmlBufferPtr xml_buf = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptString(cmd, "interface", &iface) <= 0)
        goto cleanup;

    if (vshCommandOptString(cmd, "state", &state) <= 0)
        goto cleanup;

    config = vshCommandOptBool(cmd, "config");

    if (STRNEQ(state, "up") && STRNEQ(state, "down")) {
        vshError(ctl, _("invalid link state '%s'"), state);
        goto cleanup;
    }

    /* get persistent or live description of network device */
    desc = virDomainGetXMLDesc(dom, config ? VIR_DOMAIN_XML_INACTIVE : 0);
    if (desc == NULL) {
        vshError(ctl, _("Failed to get domain description xml"));
        goto cleanup;
    }

    if (config)
        flags = VIR_DOMAIN_AFFECT_CONFIG;
    else
        flags = VIR_DOMAIN_AFFECT_LIVE;

    if (virDomainIsActive(dom) == 0)
        flags = VIR_DOMAIN_AFFECT_CONFIG;

    /* extract current network device description */
    xml = virXMLParseStringCtxt(desc, _("(domain_definition)"), &ctxt);
    VIR_FREE(desc);
    if (!xml) {
        vshError(ctl, _("Failed to parse domain description xml"));
        goto cleanup;
    }

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

    xml_buf = xmlBufferCreate();
    if (!xml_buf) {
        vshError(ctl, _("Failed to allocate memory"));
        goto cleanup;
    }

    if (xmlNodeDump(xml_buf, xml, obj->nodesetval->nodeTab[i], 0, 0) < 0 ) {
        vshError(ctl, _("Failed to create XML"));
        goto cleanup;
    }

    if (virDomainUpdateDeviceFlags(dom, (char *)xmlBufferContent(xml_buf), flags) < 0) {
        vshError(ctl, _("Failed to update interface link state"));
        goto cleanup;
    } else {
        vshPrint(ctl, "%s", _("Device updated successfully\n"));
        ret = true;
    }

cleanup:
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    xmlBufferFree(xml_buf);

    if (dom)
        virDomainFree(dom);

    return ret;
}

/* "domiftune" command
 */
static const vshCmdInfo info_domiftune[] = {
    {"help", N_("get/set parameters of a virtual interface")},
    {"desc", N_("Get/set parameters of a domain's virtual interface.")},
    {NULL,NULL}
};

static const vshCmdOptDef opts_domiftune[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"interface", VSH_OT_DATA, VSH_OFLAG_REQ, N_("interface device (MAC Address)")},
    {"inbound", VSH_OT_DATA, VSH_OFLAG_NONE, N_("control domain's incoming traffics")},
    {"outbound", VSH_OT_DATA, VSH_OFLAG_NONE, N_("control domain's outgoing traffics")},
    {"config", VSH_OT_BOOL, VSH_OFLAG_NONE, N_("affect next boot")},
    {"live", VSH_OT_BOOL, VSH_OFLAG_NONE, N_("affect running domain")},
    {"current", VSH_OT_BOOL, VSH_OFLAG_NONE, N_("affect current domain")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomIftune(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *name = NULL, *device = NULL,
               *inboundStr = NULL, *outboundStr = NULL;
    unsigned int flags = 0;
    int nparams = 0;
    virTypedParameterPtr params = NULL;
    bool ret = false;
    bool current = vshCommandOptBool(cmd, "current");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    virNetDevBandwidthRate inbound, outbound;
    int i;

    if (current) {
        if (live || config) {
            vshError(ctl, "%s", _("--current must be specified exclusively"));
            return false;
        }
        flags = VIR_DOMAIN_AFFECT_CURRENT;
    } else {
        if (config)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        if (live)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (vshCommandOptString(cmd, "interface", &device) <= 0) {
        virDomainFree(dom);
        return false;
    }

    if (vshCommandOptString(cmd, "inbound", &inboundStr) < 0 ||
        vshCommandOptString(cmd, "outbound", &outboundStr) < 0) {
        vshError(ctl, "missing argument");
        goto cleanup;
    }

    memset(&inbound, 0, sizeof(inbound));
    memset(&outbound, 0, sizeof(outbound));

    if (inboundStr) {
        if (parseRateStr(inboundStr, &inbound) < 0) {
            vshError(ctl, _("inbound format is incorrect"));
            goto cleanup;
        }
        if (inbound.average == 0) {
            vshError(ctl, _("inbound average is mandatory"));
            goto cleanup;
        }
        nparams++; /* average */
        if (inbound.peak) nparams++;
        if (inbound.burst) nparams++;
    }
    if (outboundStr) {
        if (parseRateStr(outboundStr, &outbound) < 0) {
            vshError(ctl, _("outbound format is incorrect"));
            goto cleanup;
        }
        if (outbound.average == 0) {
            vshError(ctl, _("outbound average is mandatory"));
            goto cleanup;
        }
        nparams++; /* average */
        if (outbound.peak) nparams++;
        if (outbound.burst) nparams++;
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
        if (!params) {
            virReportOOMError();
            goto cleanup;
        }
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
        /* set the interface parameters */
        params = vshCalloc(ctl, nparams, sizeof(*params));
        if (!params) {
            virReportOOMError();
            goto cleanup;
        }

        for (i = 0; i < nparams; i++)
            params[i].type = VIR_TYPED_PARAM_UINT;

        i = 0;
        if (inbound.average && i < nparams) {
            if (!virStrcpy(params[i].field, VIR_DOMAIN_BANDWIDTH_IN_AVERAGE,
                           sizeof(params[i].field)))
                goto cleanup;
            params[i].value.ui = inbound.average;
            i++;
        }
        if (inbound.peak && i < nparams) {
            if (!virStrcpy(params[i].field, VIR_DOMAIN_BANDWIDTH_IN_PEAK,
                           sizeof(params[i].field)))
                goto cleanup;
            params[i].value.ui = inbound.peak;
            i++;
        }
        if (inbound.burst && i < nparams) {
            if (!virStrcpy(params[i].field, VIR_DOMAIN_BANDWIDTH_IN_BURST,
                           sizeof(params[i].field)))
                goto cleanup;
            params[i].value.ui = inbound.burst;
            i++;
        }
        if (outbound.average && i < nparams) {
            if (!virStrcpy(params[i].field, VIR_DOMAIN_BANDWIDTH_OUT_AVERAGE,
                           sizeof(params[i].field)))
                goto cleanup;
            params[i].value.ui = outbound.average;
            i++;
        }
        if (outbound.peak && i < nparams) {
            if (!virStrcpy(params[i].field, VIR_DOMAIN_BANDWIDTH_OUT_PEAK,
                           sizeof(params[i].field)))
                goto cleanup;
            params[i].value.ui = outbound.peak;
            i++;
        }
        if (outbound.burst && i < nparams) {
            if (!virStrcpy(params[i].field, VIR_DOMAIN_BANDWIDTH_OUT_BURST,
                           sizeof(params[i].field)))
                goto cleanup;
            params[i].value.ui = outbound.burst;
            i++;
        }

        if (virDomainSetInterfaceParameters(dom, device, params, nparams, flags) != 0) {
            vshError(ctl, "%s", _("Unable to set interface parameters"));
            goto cleanup;
        }
    }

    ret = true;

cleanup:
    virTypedParameterArrayClear(params, nparams);
    VIR_FREE(params);
    virDomainFree(dom);
    return ret;
}

/*
 * "suspend" command
 */
static const vshCmdInfo info_suspend[] = {
    {"help", N_("suspend a domain")},
    {"desc", N_("Suspend a running domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_suspend[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSuspend(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *name;
    bool ret = true;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (virDomainSuspend(dom) == 0) {
        vshPrint(ctl, _("Domain %s suspended\n"), name);
    } else {
        vshError(ctl, _("Failed to suspend domain %s"), name);
        ret = false;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "dompmsuspend" command
 */
static const vshCmdInfo info_dom_pm_suspend[] = {
    {"help", N_("suspend a domain gracefully using power management "
                "functions")},
    {"desc", N_("Suspends a running domain using guest OS's power management. "
                "(Note: This requires a guest agent configured and running in "
                "the guest OS).")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_dom_pm_suspend[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"duration", VSH_OT_INT, VSH_OFLAG_REQ_OPT, N_("duration in seconds")},
    {"target", VSH_OT_STRING, VSH_OFLAG_REQ, N_("mem(Suspend-to-RAM), "
                                                "disk(Suspend-to-Disk), "
                                                "hybrid(Hybrid-Suspend)")},
    {NULL, 0, 0, NULL}
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

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (vshCommandOptULongLong(cmd, "duration", &duration) < 0) {
        vshError(ctl, _("Invalid duration argument"));
        goto cleanup;
    }

    if (vshCommandOptString(cmd, "target", &target) < 0) {
        vshError(ctl, _("Invalid target argument"));
        goto cleanup;
    }

    if (STREQ(target, "mem"))
        suspendTarget = VIR_NODE_SUSPEND_TARGET_MEM;
    else if (STREQ(target, "disk"))
        suspendTarget = VIR_NODE_SUSPEND_TARGET_DISK;
    else if (STREQ(target, "hybrid"))
        suspendTarget = VIR_NODE_SUSPEND_TARGET_HYBRID;
    else {
        vshError(ctl, "%s", _("Invalid target"));
        goto cleanup;
    }

    if (virDomainPMSuspendForDuration(dom, suspendTarget, duration, 0) < 0) {
        vshError(ctl, _("Domain %s could not be suspended"),
                 virDomainGetName(dom));
        goto cleanup;
    }

    vshPrint(ctl, _("Domain %s successfully suspended"),
             virDomainGetName(dom));

    ret = true;

cleanup:
    virDomainFree(dom);
    return ret;
}

/*
 * "dompmwakeup" command
 */

static const vshCmdInfo info_dom_pm_wakeup[] = {
    {"help", N_("wakeup a domain suspended by dompmsuspend command")},
    {"desc", N_("Wakeup a domain previously suspended "
                "by dompmsuspend command.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_dom_pm_wakeup[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomPMWakeup(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *name;
    bool ret = false;
    unsigned int flags = 0;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (virDomainPMWakeup(dom, flags) < 0) {
        vshError(ctl, _("Domain %s could not be woken up"),
                 virDomainGetName(dom));
        goto cleanup;
    }

    vshPrint(ctl, _("Domain %s successfully woken up"),
             virDomainGetName(dom));

    ret = true;

cleanup:
    virDomainFree(dom);
    return ret;
}

/*
 * "undefine" command
 */
static const vshCmdInfo info_undefine[] = {
    {"help", N_("undefine a domain")},
    {"desc",
     N_("Undefine an inactive domain, or convert persistent to transient.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_undefine[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name or uuid")},
    {"managed-save", VSH_OT_BOOL, 0, N_("remove domain managed state file")},
    {"storage", VSH_OT_DATA, VSH_OFLAG_NONE,
     N_("remove associated storage volumes (comma separated list of targets "
        "or source paths) (see domblklist)")},
    {"remove-all-storage", VSH_OT_BOOL, 0,
     N_("remove all associated storage volumes (use with caution)")},
    {"wipe-storage", VSH_OT_BOOL, VSH_OFLAG_NONE,
     N_("wipe data on the removed volumes")},
    {"snapshots-metadata", VSH_OT_BOOL, 0,
     N_("remove all domain snapshot metadata, if inactive")},
    {NULL, 0, 0, NULL}
};

typedef struct {
    virStorageVolPtr vol;
    char *source;
    char *target;
} vshUndefineVolume;

static bool
cmdUndefine(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = false;
    const char *name = NULL;
    /* Flags to attempt.  */
    unsigned int flags = 0;
    /* User-requested actions.  */
    bool managed_save = vshCommandOptBool(cmd, "managed-save");
    bool snapshots_metadata = vshCommandOptBool(cmd, "snapshots-metadata");
    bool wipe_storage = vshCommandOptBool(cmd, "wipe-storage");
    bool remove_all_storage = vshCommandOptBool(cmd, "remove-all-storage");
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
    vshUndefineVolume *vlist = NULL;
    int nvols = 0;
    const char *volumes_arg = NULL;
    char *volumes = NULL;
    char **volume_tokens = NULL;
    char *volume_tok = NULL;
    int nvolume_tokens = 0;
    char *def = NULL;
    char *source = NULL;
    char *target = NULL;
    int vol_i;
    int tok_i;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr *vol_nodes = NULL;
    int nvolumes = 0;
    bool vol_not_found = false;

    ignore_value(vshCommandOptString(cmd, "storage", &volumes_arg));
    volumes = vshStrdup(ctl, volumes_arg);

    if (managed_save) {
        flags |= VIR_DOMAIN_UNDEFINE_MANAGED_SAVE;
        managed_save_safe = true;
    }
    if (snapshots_metadata) {
        flags |= VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA;
        snapshots_safe = true;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
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
    if (has_snapshots == 0) {
        snapshots_safe = true;
    }
    if (has_snapshots_metadata == 0) {
        flags &= ~VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA;
        snapshots_safe = true;
    }

    /* Stash domain description for later use */
    if (volumes || remove_all_storage) {
        if (running) {
            vshError(ctl, _("Storage volume deletion is supported only on stopped domains"));
            goto cleanup;
        }

        if (volumes && remove_all_storage) {
            vshError(ctl, _("Specified both --storage and --remove-all-storage"));
            goto cleanup;
        }

        if (!(def = virDomainGetXMLDesc(dom, 0))) {
            vshError(ctl, _("Could not retrieve domain XML description"));
            goto cleanup;
        }

        if (!(doc = virXMLParseStringCtxt(def, _("(domain_definition)"),
                                          &ctxt)))
            goto error;

        /* tokenize the string from user and save it's parts into an array */
        if (volumes) {
            /* count the delimiters */
            volume_tok = volumes;
            nvolume_tokens = 1; /* we need at least one member */
            while (*volume_tok) {
                if (*(volume_tok++) == ',')
                    nvolume_tokens++;
            }

            volume_tokens = vshCalloc(ctl, nvolume_tokens, sizeof(char *));

            /* tokenize the input string */
            nvolume_tokens = 0;
            volume_tok = volumes;
            do {
                volume_tokens[nvolume_tokens] = strsep(&volume_tok, ",");
                nvolume_tokens++;
            } while (volume_tok);
        }

        if ((nvolumes = virXPathNodeSet("./devices/disk", ctxt,
                                        &vol_nodes)) < 0)
            goto error;

        if (nvolumes > 0)
            vlist = vshCalloc(ctl, nvolumes, sizeof(*vlist));

        for (vol_i = 0; vol_i < nvolumes; vol_i++) {
            ctxt->node = vol_nodes[vol_i];

            /* get volume source and target paths */
            if (!(target = virXPathString("string(./target/@dev)", ctxt)))
                goto error;

            if (!(source = virXPathString("string("
                                          "./source/@file|"
                                          "./source/@dir|"
                                          "./source/@name|"
                                          "./source/@dev)", ctxt))) {
                if (last_error && last_error->code != VIR_ERR_OK)
                    goto error;
                else
                    continue;
            }

            /* lookup if volume was selected by user */
            if (volumes) {
                volume_tok = NULL;
                for (tok_i = 0; tok_i < nvolume_tokens; tok_i++) {
                    if (volume_tokens[tok_i] &&
                        (STREQ(volume_tokens[tok_i], target) ||
                         STREQ(volume_tokens[tok_i], source))) {
                        volume_tok = volume_tokens[tok_i];
                        volume_tokens[tok_i] = NULL;
                        break;
                    }
                }
                if (!volume_tok)
                    continue;
            }

            if (!(vlist[nvols].vol = virStorageVolLookupByPath(ctl->conn,
                                                               source))) {
                vshPrint(ctl,
                         _("Storage volume '%s'(%s) is not managed by libvirt. "
                           "Remove it manually.\n"), target, source);
                vshResetLibvirtError();
                continue;
            }
            vlist[nvols].source = source;
            vlist[nvols].target = target;
            nvols++;
        }

        /* print volumes specified by user that were not found in domain definition */
        if (volumes) {
            for (tok_i = 0; tok_i < nvolume_tokens; tok_i++) {
                if (volume_tokens[tok_i]) {
                    vshError(ctl, _("Volume '%s' was not found in domain's "
                                    "definition.\n"),
                             volume_tokens[tok_i]);
                    vol_not_found = true;
                }
            }

            if (vol_not_found)
                goto cleanup;
        }
    }

    /* Generally we want to try the new API first.  However, while
     * virDomainUndefineFlags was introduced at the same time as
     * VIR_DOMAIN_UNDEFINE_MANAGED_SAVE in 0.9.4, the
     * VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA flag was not present
     * until 0.9.5; skip to piecewise emulation if we couldn't prove
     * above that the new API is safe.  */
    if (managed_save_safe && snapshots_safe) {
        rc = virDomainUndefineFlags(dom, flags);
        if (rc == 0 || (last_error->code != VIR_ERR_NO_SUPPORT &&
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
            virshReportError(ctl);
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
        vshPrint(ctl, _("Domain %s has been undefined\n"), name);
        ret = true;
    } else {
        vshError(ctl, _("Failed to undefine domain %s"), name);
        goto cleanup;
    }

    /* try to undefine storage volumes associated with this domain, if it's requested */
    if (nvols) {
        for (vol_i = 0; vol_i < nvols; vol_i++) {
            if (wipe_storage) {
                vshPrint(ctl, _("Wiping volume '%s'(%s) ... "),
                         vlist[vol_i].target, vlist[vol_i].source);
                fflush(stdout);
                if (virStorageVolWipe(vlist[vol_i].vol, 0) < 0) {
                    vshError(ctl, _("Failed! Volume not removed."));
                    ret = false;
                    continue;
                } else {
                    vshPrint(ctl, _("Done.\n"));
                }
            }

            /* delete the volume */
            if (virStorageVolDelete(vlist[vol_i].vol, 0) < 0) {
                vshError(ctl, _("Failed to remove storage volume '%s'(%s)"),
                         vlist[vol_i].target, vlist[vol_i].source);
                ret = false;
            } else {
                vshPrint(ctl, _("Volume '%s'(%s) removed.\n"),
                         vlist[vol_i].target, vlist[vol_i].source);
            }
        }
    }

cleanup:
    for (vol_i = 0; vol_i < nvols; vol_i++) {
        VIR_FREE(vlist[vol_i].source);
        VIR_FREE(vlist[vol_i].target);
        if (vlist[vol_i].vol)
            virStorageVolFree(vlist[vol_i].vol);
    }
    VIR_FREE(vlist);

    VIR_FREE(volumes);
    VIR_FREE(volume_tokens);
    VIR_FREE(def);
    VIR_FREE(vol_nodes);
    xmlFreeDoc(doc);
    xmlXPathFreeContext(ctxt);
    virDomainFree(dom);
    return ret;

error:
    virshReportError(ctl);
    goto cleanup;
}

/*
 * "start" command
 */
static const vshCmdInfo info_start[] = {
    {"help", N_("start a (previously defined) inactive domain")},
    {"desc", N_("Start a domain, either from the last managedsave\n"
                "    state, or via a fresh boot if no managedsave state\n"
                "    is present.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_start[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("name of the inactive domain")},
#ifndef WIN32
    {"console", VSH_OT_BOOL, 0, N_("attach to console after creation")},
#endif
    {"paused", VSH_OT_BOOL, 0, N_("leave the guest paused after creation")},
    {"autodestroy", VSH_OT_BOOL, 0,
     N_("automatically destroy the guest when virsh disconnects")},
    {"bypass-cache", VSH_OT_BOOL, 0,
     N_("avoid file system cache when loading")},
    {"force-boot", VSH_OT_BOOL, 0,
     N_("force fresh boot by discarding any managed save")},
    {NULL, 0, 0, NULL}
};

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

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomainBy(ctl, cmd, NULL,
                                      VSH_BYNAME | VSH_BYUUID)))
        return false;

    if (virDomainGetID(dom) != (unsigned int)-1) {
        vshError(ctl, "%s", _("Domain is already active"));
        virDomainFree(dom);
        return false;
    }

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
        if (virDomainCreateWithFlags(dom, flags) == 0)
            goto started;
        if (last_error->code != VIR_ERR_NO_SUPPORT &&
            last_error->code != VIR_ERR_INVALID_ARG) {
            virshReportError(ctl);
            goto cleanup;
        }
        vshResetLibvirtError();
        rc = virDomainHasManagedSaveImage(dom, 0);
        if (rc < 0) {
            /* No managed save image to remove */
            vshResetLibvirtError();
        } else if (rc > 0) {
            if (virDomainManagedSaveRemove(dom, 0) < 0) {
                virshReportError(ctl);
                goto cleanup;
            }
        }
        flags &= ~VIR_DOMAIN_START_FORCE_BOOT;
    }

    /* Prefer older API unless we have to pass a flag.  */
    if ((flags ? virDomainCreateWithFlags(dom, flags)
         : virDomainCreate(dom)) < 0) {
        vshError(ctl, _("Failed to start domain %s"), virDomainGetName(dom));
        goto cleanup;
    }

started:
    vshPrint(ctl, _("Domain %s started\n"),
             virDomainGetName(dom));
#ifndef WIN32
    if (console && !cmdRunConsole(ctl, dom, NULL, 0))
        goto cleanup;
#endif

    ret = true;

cleanup:
    virDomainFree(dom);
    return ret;
}

/*
 * "save" command
 */
static const vshCmdInfo info_save[] = {
    {"help", N_("save a domain state to a file")},
    {"desc", N_("Save the RAM state of a running domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_save[] = {
    {"bypass-cache", VSH_OT_BOOL, 0, N_("avoid file system cache when saving")},
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("where to save the data")},
    {"xml", VSH_OT_STRING, 0,
     N_("filename containing updated XML for the target")},
    {"running", VSH_OT_BOOL, 0, N_("set domain to be running on restore")},
    {"paused", VSH_OT_BOOL, 0, N_("set domain to be paused on restore")},
    {"verbose", VSH_OT_BOOL, 0, N_("display the progress of save")},
    {NULL, 0, 0, NULL}
};

static void
doSave(void *opaque)
{
    vshCtrlData *data = opaque;
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

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto out;

    if (vshCommandOptString(cmd, "file", &to) <= 0)
        goto out;

    if (vshCommandOptBool(cmd, "bypass-cache"))
        flags |= VIR_DOMAIN_SAVE_BYPASS_CACHE;
    if (vshCommandOptBool(cmd, "running"))
        flags |= VIR_DOMAIN_SAVE_RUNNING;
    if (vshCommandOptBool(cmd, "paused"))
        flags |= VIR_DOMAIN_SAVE_PAUSED;

    if (vshCommandOptString(cmd, "xml", &xmlfile) < 0) {
        vshError(ctl, "%s", _("malformed xml argument"));
        goto out;
    }

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        goto out;

    if (xmlfile &&
        virFileReadAll(xmlfile, 8192, &xml) < 0)
        goto out;

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
    if (dom) virDomainFree(dom);
    VIR_FREE(xml);
    ignore_value(safewrite(data->writefd, &ret, sizeof(ret)));
}

static bool
cmdSave(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    virDomainPtr dom = NULL;
    int p[2] = {-1. -1};
    virThread workerThread;
    bool verbose = false;
    vshCtrlData data;
    const char *to = NULL;
    const char *name = NULL;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (vshCommandOptString(cmd, "file", &to) <= 0)
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

    ret = vshWatchJob(ctl, dom, verbose, p[0], 0, NULL, NULL, _("Save"));

    virThreadJoin(&workerThread);

    if (ret)
        vshPrint(ctl, _("\nDomain %s saved to %s\n"), name, to);

cleanup:
    if (dom)
        virDomainFree(dom);
    return ret;
}

/*
 * "save-image-dumpxml" command
 */
static const vshCmdInfo info_save_image_dumpxml[] = {
    {"help", N_("saved state domain information in XML")},
    {"desc", N_("Output the domain information for a saved state file,\n"
                "as an XML dump to stdout.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_save_image_dumpxml[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("saved state file to read")},
    {"security-info", VSH_OT_BOOL, 0, N_("include security sensitive information in XML dump")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSaveImageDumpxml(vshControl *ctl, const vshCmd *cmd)
{
    const char *file = NULL;
    bool ret = false;
    unsigned int flags = 0;
    char *xml = NULL;

    if (vshCommandOptBool(cmd, "security-info"))
        flags |= VIR_DOMAIN_XML_SECURE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", &file) <= 0)
        return false;

    xml = virDomainSaveImageGetXMLDesc(ctl->conn, file, flags);
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
    {"help", N_("redefine the XML for a domain's saved state file")},
    {"desc", N_("Replace the domain XML associated with a saved state file")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_save_image_define[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("saved state file to modify")},
    {"xml", VSH_OT_STRING, VSH_OFLAG_REQ,
     N_("filename containing updated XML for the target")},
    {"running", VSH_OT_BOOL, 0, N_("set domain to be running on restore")},
    {"paused", VSH_OT_BOOL, 0, N_("set domain to be paused on restore")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSaveImageDefine(vshControl *ctl, const vshCmd *cmd)
{
    const char *file = NULL;
    bool ret = false;
    const char *xmlfile = NULL;
    char *xml = NULL;
    unsigned int flags = 0;

    if (vshCommandOptBool(cmd, "running"))
        flags |= VIR_DOMAIN_SAVE_RUNNING;
    if (vshCommandOptBool(cmd, "paused"))
        flags |= VIR_DOMAIN_SAVE_PAUSED;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", &file) <= 0)
        return false;

    if (vshCommandOptString(cmd, "xml", &xmlfile) <= 0) {
        vshError(ctl, "%s", _("malformed or missing xml argument"));
        return false;
    }

    if (virFileReadAll(xmlfile, 8192, &xml) < 0)
        goto cleanup;

    if (virDomainSaveImageDefineXML(ctl->conn, file, xml, flags) < 0) {
        vshError(ctl, _("Failed to update %s"), file);
        goto cleanup;
    }

    vshPrint(ctl, _("State file %s updated.\n"), file);
    ret = true;

cleanup:
    VIR_FREE(xml);
    return ret;
}

/*
 * "save-image-edit" command
 */
static const vshCmdInfo info_save_image_edit[] = {
    {"help", N_("edit XML for a domain's saved state file")},
    {"desc", N_("Edit the domain XML associated with a saved state file")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_save_image_edit[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("saved state file to edit")},
    {"running", VSH_OT_BOOL, 0, N_("set domain to be running on restore")},
    {"paused", VSH_OT_BOOL, 0, N_("set domain to be paused on restore")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSaveImageEdit(vshControl *ctl, const vshCmd *cmd)
{
    const char *file = NULL;
    bool ret = false;
    unsigned int getxml_flags = VIR_DOMAIN_XML_SECURE;
    unsigned int define_flags = 0;

    if (vshCommandOptBool(cmd, "running"))
        define_flags |= VIR_DOMAIN_SAVE_RUNNING;
    if (vshCommandOptBool(cmd, "paused"))
        define_flags |= VIR_DOMAIN_SAVE_PAUSED;

    /* Normally, we let the API reject mutually exclusive flags.
     * However, in the edit cycle, we let the user retry if the define
     * step fails, but the define step will always fail on invalid
     * flags, so we reject it up front to avoid looping.  */
    if (define_flags == (VIR_DOMAIN_SAVE_RUNNING | VIR_DOMAIN_SAVE_PAUSED)) {
        vshError(ctl, "%s", _("--running and --saved are mutually exclusive"));
        return false;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", &file) <= 0)
        return false;

#define EDIT_GET_XML \
    virDomainSaveImageGetXMLDesc(ctl->conn, file, getxml_flags)
#define EDIT_NOT_CHANGED \
    vshPrint(ctl, _("Saved image %s XML configuration " \
                    "not changed.\n"), file);           \
    ret = true; goto edit_cleanup;
#define EDIT_DEFINE \
    virDomainSaveImageDefineXML(ctl->conn, file, doc_edited, define_flags)
#define EDIT_FREE /* */
#include "virsh-edit.c"

    vshPrint(ctl, _("State file %s edited.\n"), file);
    ret = true;

cleanup:
    return ret;
}

/*
 * "managedsave" command
 */
static const vshCmdInfo info_managedsave[] = {
    {"help", N_("managed save of a domain state")},
    {"desc", N_("Save and destroy a running domain, so it can be restarted from\n"
                "    the same state at a later time.  When the virsh 'start'\n"
                "    command is next run for the domain, it will automatically\n"
                "    be started from this saved state.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_managedsave[] = {
    {"bypass-cache", VSH_OT_BOOL, 0, N_("avoid file system cache when saving")},
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"running", VSH_OT_BOOL, 0, N_("set domain to be running on next start")},
    {"paused", VSH_OT_BOOL, 0, N_("set domain to be paused on next start")},
    {"verbose", VSH_OT_BOOL, 0, N_("display the progress of save")},
    {NULL, 0, 0, NULL}
};

static void
doManagedsave(void *opaque)
{
    char ret = '1';
    vshCtrlData *data = opaque;
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

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto out;

    if (vshCommandOptBool(cmd, "bypass-cache"))
        flags |= VIR_DOMAIN_SAVE_BYPASS_CACHE;
    if (vshCommandOptBool(cmd, "running"))
        flags |= VIR_DOMAIN_SAVE_RUNNING;
    if (vshCommandOptBool(cmd, "paused"))
        flags |= VIR_DOMAIN_SAVE_PAUSED;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        goto out;

    if (virDomainManagedSave(dom, flags) < 0) {
        vshError(ctl, _("Failed to save domain %s state"), name);
        goto out;
    }

    ret = '0';
out:
    pthread_sigmask(SIG_SETMASK, &oldsigmask, NULL);
out_sig:
    if (dom)
        virDomainFree(dom);
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
    vshCtrlData data;
    virThread workerThread;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
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

    ret = vshWatchJob(ctl, dom, verbose, p[0], 0,
                      NULL, NULL, _("Managedsave"));

    virThreadJoin(&workerThread);

    if (ret)
        vshPrint(ctl, _("\nDomain %s state saved by libvirt\n"), name);

cleanup:
    virDomainFree(dom);
    VIR_FORCE_CLOSE(p[0]);
    VIR_FORCE_CLOSE(p[1]);
    return ret;
}

/*
 * "managedsave-remove" command
 */
static const vshCmdInfo info_managedsaveremove[] = {
    {"help", N_("Remove managed save of a domain")},
    {"desc", N_("Remove an existing managed save state file from a domain")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_managedsaveremove[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdManagedSaveRemove(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *name;
    bool ret = false;
    int hassave;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
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
            vshPrint(ctl, _("Removed managedsave image for domain %s"), name);
    }
    else
        vshPrint(ctl, _("Domain %s has no manage save image; removal skipped"),
                 name);

    ret = true;

cleanup:
    virDomainFree(dom);
    return ret;
}

/*
 * "schedinfo" command
 */
static const vshCmdInfo info_schedinfo[] = {
    {"help", N_("show/set scheduler parameters")},
    {"desc", N_("Show/Set scheduler parameters.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_schedinfo[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"set", VSH_OT_STRING, VSH_OFLAG_NONE, N_("parameter=value")},
    {"weight", VSH_OT_INT, VSH_OFLAG_NONE, N_("weight for XEN_CREDIT")},
    {"cap", VSH_OT_INT, VSH_OFLAG_NONE, N_("cap for XEN_CREDIT")},
    {"current", VSH_OT_BOOL, 0, N_("get/set current scheduler info")},
    {"config", VSH_OT_BOOL, 0, N_("get/set value to be used on next boot")},
    {"live", VSH_OT_BOOL, 0, N_("get/set value from running domain")},
    {NULL, 0, 0, NULL}
};

static int
cmdSchedInfoUpdate(vshControl *ctl, const vshCmd *cmd,
                   virTypedParameterPtr param)
{
    const char *data = NULL;

    /* Legacy 'weight' parameter */
    if (STREQ(param->field, "weight") &&
        param->type == VIR_TYPED_PARAM_UINT &&
        vshCommandOptBool(cmd, "weight")) {
        int val;
        if (vshCommandOptInt(cmd, "weight", &val) <= 0) {
            vshError(ctl, "%s", _("Invalid value of weight"));
            return -1;
        } else {
            param->value.ui = val;
        }
        return 1;
    }

    /* Legacy 'cap' parameter */
    if (STREQ(param->field, "cap") &&
        param->type == VIR_TYPED_PARAM_UINT &&
        vshCommandOptBool(cmd, "cap")) {
        int val;
        if (vshCommandOptInt(cmd, "cap", &val) <= 0) {
            vshError(ctl, "%s", _("Invalid value of cap"));
            return -1;
        } else {
            param->value.ui = val;
        }
        return 1;
    }

    if (vshCommandOptString(cmd, "set", &data) > 0) {
        char *val = strchr(data, '=');
        int match = 0;
        if (!val) {
            vshError(ctl, "%s", _("Invalid syntax for --set, expecting name=value"));
            return -1;
        }
        *val = '\0';
        match = STREQ(data, param->field);
        *val = '=';
        val++;

        if (!match)
            return 0;

        switch (param->type) {
        case VIR_TYPED_PARAM_INT:
            if (virStrToLong_i(val, NULL, 10, &param->value.i) < 0) {
                vshError(ctl, "%s",
                         _("Invalid value for parameter, expecting an int"));
                return -1;
            }
            break;
        case VIR_TYPED_PARAM_UINT:
            if (virStrToLong_ui(val, NULL, 10, &param->value.ui) < 0) {
                vshError(ctl, "%s",
                         _("Invalid value for parameter, expecting an unsigned int"));
                return -1;
            }
            break;
        case VIR_TYPED_PARAM_LLONG:
            if (virStrToLong_ll(val, NULL, 10, &param->value.l) < 0) {
                vshError(ctl, "%s",
                         _("Invalid value for parameter, expecting a long long"));
                return -1;
            }
            break;
        case VIR_TYPED_PARAM_ULLONG:
            if (virStrToLong_ull(val, NULL, 10, &param->value.ul) < 0) {
                vshError(ctl, "%s",
                         _("Invalid value for parameter, expecting an unsigned long long"));
                return -1;
            }
            break;
        case VIR_TYPED_PARAM_DOUBLE:
            if (virStrToDouble(val, NULL, &param->value.d) < 0) {
                vshError(ctl, "%s", _("Invalid value for parameter, expecting a double"));
                return -1;
            }
            break;
        case VIR_TYPED_PARAM_BOOLEAN:
            param->value.b = STREQ(val, "0") ? 0 : 1;
        }
        return 1;
    }

    return 0;
}

static bool
cmdSchedinfo(vshControl *ctl, const vshCmd *cmd)
{
    char *schedulertype;
    virDomainPtr dom;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    int update = 0;
    int i, ret;
    bool ret_val = false;
    unsigned int flags = 0;
    bool current = vshCommandOptBool(cmd, "current");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");

    if (current) {
        if (live || config) {
            vshError(ctl, "%s", _("--current must be specified exclusively"));
            return false;
        }
        flags = VIR_DOMAIN_AFFECT_CURRENT;
    } else {
        if (config)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        if (live)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    /* Print SchedulerType */
    schedulertype = virDomainGetSchedulerType(dom, &nparams);
    if (schedulertype != NULL) {
        vshPrint(ctl, "%-15s: %s\n", _("Scheduler"),
             schedulertype);
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
        for (i = 0; i < nparams; i++) {
            ret = cmdSchedInfoUpdate(ctl, cmd, &(params[i]));
            if (ret == -1)
                goto cleanup;

            if (ret == 1)
                update = 1;
        }

        /* Update parameters & refresh data */
        if (update) {
            if (flags || current)
                ret = virDomainSetSchedulerParametersFlags(dom, params,
                                                           nparams, flags);
            else
                ret = virDomainSetSchedulerParameters(dom, params, nparams);
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
            /* See if we've tried to --set var=val.  If so, the fact that
               we reach this point (with update == 0) means that "var" did
               not match any of the settable parameters.  Report the error.  */
            const char *var_value_pair = NULL;
            if (vshCommandOptString(cmd, "set", &var_value_pair) > 0) {
                vshError(ctl, _("invalid scheduler option: %s"),
                         var_value_pair);
                goto cleanup;
            }
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
    VIR_FREE(params);
    virDomainFree(dom);
    return ret_val;
}

/*
 * "restore" command
 */
static const vshCmdInfo info_restore[] = {
    {"help", N_("restore a domain from a saved state in a file")},
    {"desc", N_("Restore a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_restore[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("the state to restore")},
    {"bypass-cache", VSH_OT_BOOL, 0,
     N_("avoid file system cache when restoring")},
    {"xml", VSH_OT_STRING, 0,
     N_("filename containing updated XML for the target")},
    {"running", VSH_OT_BOOL, 0, N_("restore domain into running state")},
    {"paused", VSH_OT_BOOL, 0, N_("restore domain into paused state")},
    {NULL, 0, 0, NULL}
};

static bool
cmdRestore(vshControl *ctl, const vshCmd *cmd)
{
    const char *from = NULL;
    bool ret = false;
    unsigned int flags = 0;
    const char *xmlfile = NULL;
    char *xml = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0)
        return false;

    if (vshCommandOptBool(cmd, "bypass-cache"))
        flags |= VIR_DOMAIN_SAVE_BYPASS_CACHE;
    if (vshCommandOptBool(cmd, "running"))
        flags |= VIR_DOMAIN_SAVE_RUNNING;
    if (vshCommandOptBool(cmd, "paused"))
        flags |= VIR_DOMAIN_SAVE_PAUSED;

    if (vshCommandOptString(cmd, "xml", &xmlfile) < 0) {
        vshError(ctl, "%s", _("malformed xml argument"));
        return false;
    }

    if (xmlfile &&
        virFileReadAll(xmlfile, 8192, &xml) < 0)
        goto cleanup;

    if (((flags || xml)
         ? virDomainRestoreFlags(ctl->conn, from, xml, flags)
         : virDomainRestore(ctl->conn, from)) < 0) {
        vshError(ctl, _("Failed to restore domain from %s"), from);
        goto cleanup;
    }

    vshPrint(ctl, _("Domain restored from %s\n"), from);
    ret = true;

cleanup:
    VIR_FREE(xml);
    return ret;
}

/*
 * "dump" command
 */
static const vshCmdInfo info_dump[] = {
    {"help", N_("dump the core of a domain to a file for analysis")},
    {"desc", N_("Core dump a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_dump[] = {
    {"live", VSH_OT_BOOL, 0, N_("perform a live core dump if supported")},
    {"crash", VSH_OT_BOOL, 0, N_("crash the domain after core dump")},
    {"bypass-cache", VSH_OT_BOOL, 0,
     N_("avoid file system cache when saving")},
    {"reset", VSH_OT_BOOL, 0, N_("reset the domain after core dump")},
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("where to dump the core")},
    {"verbose", VSH_OT_BOOL, 0, N_("display the progress of dump")},
    {"memory-only", VSH_OT_BOOL, 0, N_("dump domain's memory only")},
    {NULL, 0, 0, NULL}
};

static void
doDump(void *opaque)
{
    char ret = '1';
    vshCtrlData *data = opaque;
    vshControl *ctl = data->ctl;
    const vshCmd *cmd = data->cmd;
    virDomainPtr dom = NULL;
    sigset_t sigmask, oldsigmask;
    const char *name = NULL;
    const char *to = NULL;
    unsigned int flags = 0;

    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);
    if (pthread_sigmask(SIG_BLOCK, &sigmask, &oldsigmask) < 0)
        goto out_sig;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto out;

    if (vshCommandOptString(cmd, "file", &to) <= 0)
        goto out;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
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

    if (virDomainCoreDump(dom, to, flags) < 0) {
        vshError(ctl, _("Failed to core dump domain %s to %s"), name, to);
        goto out;
    }

    ret = '0';
out:
    pthread_sigmask(SIG_SETMASK, &oldsigmask, NULL);
out_sig:
    if (dom)
        virDomainFree(dom);
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
    vshCtrlData data;
    virThread workerThread;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (vshCommandOptString(cmd, "file", &to) <= 0)
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
                        doDump,
                        &data) < 0)
        goto cleanup;

    ret = vshWatchJob(ctl, dom, verbose, p[0], 0, NULL, NULL, _("Dump"));

    virThreadJoin(&workerThread);

    if (ret)
        vshPrint(ctl, _("\nDomain %s dumped to %s\n"), name, to);

cleanup:
    virDomainFree(dom);
    VIR_FORCE_CLOSE(p[0]);
    VIR_FORCE_CLOSE(p[1]);
    return ret;
}

static const vshCmdInfo info_screenshot[] = {
    {"help", N_("take a screenshot of a current domain console and store it "
                "into a file")},
    {"desc", N_("screenshot of a current domain console")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_screenshot[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"file", VSH_OT_DATA, VSH_OFLAG_NONE, N_("where to store the screenshot")},
    {"screen", VSH_OT_INT, VSH_OFLAG_NONE, N_("ID of a screen to take screenshot of")},
    {NULL, 0, 0, NULL}
};

/**
 * Generate string: '<domain name>-<timestamp>[<extension>]'
 */
static char *
vshGenFileName(vshControl *ctl, virDomainPtr dom, const char *mime)
{
    char timestr[100];
    struct timeval cur_time;
    struct tm time_info;
    const char *ext = NULL;
    char *ret = NULL;

    /* We should be already connected, but doesn't
     * hurt to check */
    if (!vshConnectionUsability(ctl, ctl->conn))
        return NULL;

    if (!dom) {
        vshError(ctl, "%s", _("Invalid domain supplied"));
        return NULL;
    }

    if (STREQ(mime, "image/x-portable-pixmap"))
        ext = ".ppm";
    else if (STREQ(mime, "image/png"))
        ext = ".png";
    /* add mime type here */

    gettimeofday(&cur_time, NULL);
    localtime_r(&cur_time.tv_sec, &time_info);
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
    int ret = false;
    bool created = false;
    bool generated = false;
    char *mime = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", (const char **) &file) < 0) {
        vshError(ctl, "%s", _("file must not be empty"));
        return false;
    }

    if (vshCommandOptUInt(cmd, "screen", &screen) < 0) {
        vshError(ctl, "%s", _("invalid screen ID"));
        return false;
    }

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    st = virStreamNew(ctl->conn, 0);

    mime = virDomainScreenshot(dom, st, screen, flags);
    if (!mime) {
        vshError(ctl, _("could not take a screenshot of %s"), name);
        goto cleanup;
    }

    if (!file) {
        if (!(file=vshGenFileName(ctl, dom, mime)))
            return false;
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

    if (virStreamRecvAll(st, vshStreamSink, &fd) < 0) {
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

    vshPrint(ctl, _("Screenshot saved to %s, with type of %s"), file, mime);
    ret = true;

cleanup:
    if (!ret && created)
        unlink(file);
    if (generated)
        VIR_FREE(file);
    virDomainFree(dom);
    if (st)
        virStreamFree(st);
    VIR_FORCE_CLOSE(fd);
    VIR_FREE(mime);
    return ret;
}

/*
 * "resume" command
 */
static const vshCmdInfo info_resume[] = {
    {"help", N_("resume a domain")},
    {"desc", N_("Resume a previously suspended domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_resume[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdResume(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = true;
    const char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (virDomainResume(dom) == 0) {
        vshPrint(ctl, _("Domain %s resumed\n"), name);
    } else {
        vshError(ctl, _("Failed to resume domain %s"), name);
        ret = false;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "shutdown" command
 */
static const vshCmdInfo info_shutdown[] = {
    {"help", N_("gracefully shutdown a domain")},
    {"desc", N_("Run shutdown in the target domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_shutdown[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"mode", VSH_OT_STRING, VSH_OFLAG_NONE, N_("shutdown mode: acpi|agent")},
    {NULL, 0, 0, NULL}
};

static bool
cmdShutdown(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = true;
    const char *name;
    const char *mode = NULL;
    int flags = 0;
    int rv;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "mode", &mode) < 0) {
        vshError(ctl, "%s", _("Invalid type"));
        return false;
    }

    if (mode) {
        if (STREQ(mode, "acpi")) {
            flags |= VIR_DOMAIN_SHUTDOWN_ACPI_POWER_BTN;
        } else if (STREQ(mode, "agent")) {
            flags |= VIR_DOMAIN_SHUTDOWN_GUEST_AGENT;
        } else {
            vshError(ctl, _("Unknown mode %s value, expecting 'acpi' or 'agent'"), mode);
            return false;
        }
    }

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (flags)
        rv = virDomainShutdownFlags(dom, flags);
    else
        rv = virDomainShutdown(dom);
    if (rv == 0) {
        vshPrint(ctl, _("Domain %s is being shutdown\n"), name);
    } else {
        vshError(ctl, _("Failed to shutdown domain %s"), name);
        ret = false;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "reboot" command
 */
static const vshCmdInfo info_reboot[] = {
    {"help", N_("reboot a domain")},
    {"desc", N_("Run a reboot command in the target domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_reboot[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"mode", VSH_OT_STRING, VSH_OFLAG_NONE, N_("shutdown mode: acpi|agent")},
    {NULL, 0, 0, NULL}
};

static bool
cmdReboot(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = true;
    const char *name;
    const char *mode = NULL;
    int flags = 0;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "mode", &mode) < 0) {
        vshError(ctl, "%s", _("Invalid type"));
        return false;
    }

    if (mode) {
        if (STREQ(mode, "acpi")) {
            flags |= VIR_DOMAIN_SHUTDOWN_ACPI_POWER_BTN;
        } else if (STREQ(mode, "agent")) {
            flags |= VIR_DOMAIN_SHUTDOWN_GUEST_AGENT;
        } else {
            vshError(ctl, _("Unknown mode %s value, expecting 'acpi' or 'agent'"), mode);
            return false;
        }
    }

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (virDomainReboot(dom, flags) == 0) {
        vshPrint(ctl, _("Domain %s is being rebooted\n"), name);
    } else {
        vshError(ctl, _("Failed to reboot domain %s"), name);
        ret = false;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "reset" command
 */
static const vshCmdInfo info_reset[] = {
    {"help", N_("reset a domain")},
    {"desc", N_("Reset the target domain as if by power button")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_reset[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdReset(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = true;
    const char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (virDomainReset(dom, 0) == 0) {
        vshPrint(ctl, _("Domain %s was reset\n"), name);
    } else {
        vshError(ctl, _("Failed to reset domain %s"), name);
        ret = false;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "domjobinfo" command
 */
static const vshCmdInfo info_domjobinfo[] = {
    {"help", N_("domain job information")},
    {"desc", N_("Returns information about jobs running on a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domjobinfo[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomjobinfo(vshControl *ctl, const vshCmd *cmd)
{
    virDomainJobInfo info;
    virDomainPtr dom;
    bool ret = true;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virDomainGetJobInfo(dom, &info) == 0) {
        const char *unit;
        double val;

        vshPrint(ctl, "%-17s ", _("Job type:"));
        switch (info.type) {
        case VIR_DOMAIN_JOB_BOUNDED:
            vshPrint(ctl, "%-12s\n", _("Bounded"));
            break;

        case VIR_DOMAIN_JOB_UNBOUNDED:
            vshPrint(ctl, "%-12s\n", _("Unbounded"));
            break;

        case VIR_DOMAIN_JOB_NONE:
        default:
            vshPrint(ctl, "%-12s\n", _("None"));
            goto cleanup;
        }

        vshPrint(ctl, "%-17s %-12llu ms\n", _("Time elapsed:"), info.timeElapsed);
        if (info.type == VIR_DOMAIN_JOB_BOUNDED)
            vshPrint(ctl, "%-17s %-12llu ms\n", _("Time remaining:"), info.timeRemaining);
        if (info.dataTotal || info.dataRemaining || info.dataProcessed) {
            val = prettyCapacity(info.dataProcessed, &unit);
            vshPrint(ctl, "%-17s %-.3lf %s\n", _("Data processed:"), val, unit);
            val = prettyCapacity(info.dataRemaining, &unit);
            vshPrint(ctl, "%-17s %-.3lf %s\n", _("Data remaining:"), val, unit);
            val = prettyCapacity(info.dataTotal, &unit);
            vshPrint(ctl, "%-17s %-.3lf %s\n", _("Data total:"), val, unit);
        }
        if (info.memTotal || info.memRemaining || info.memProcessed) {
            val = prettyCapacity(info.memProcessed, &unit);
            vshPrint(ctl, "%-17s %-.3lf %s\n", _("Memory processed:"), val, unit);
            val = prettyCapacity(info.memRemaining, &unit);
            vshPrint(ctl, "%-17s %-.3lf %s\n", _("Memory remaining:"), val, unit);
            val = prettyCapacity(info.memTotal, &unit);
            vshPrint(ctl, "%-17s %-.3lf %s\n", _("Memory total:"), val, unit);
        }
        if (info.fileTotal || info.fileRemaining || info.fileProcessed) {
            val = prettyCapacity(info.fileProcessed, &unit);
            vshPrint(ctl, "%-17s %-.3lf %s\n", _("File processed:"), val, unit);
            val = prettyCapacity(info.fileRemaining, &unit);
            vshPrint(ctl, "%-17s %-.3lf %s\n", _("File remaining:"), val, unit);
            val = prettyCapacity(info.fileTotal, &unit);
            vshPrint(ctl, "%-17s %-.3lf %s\n", _("File total:"), val, unit);
        }
    } else {
        ret = false;
    }
cleanup:
    virDomainFree(dom);
    return ret;
}

/*
 * "domjobabort" command
 */
static const vshCmdInfo info_domjobabort[] = {
    {"help", N_("abort active domain job")},
    {"desc", N_("Aborts the currently running domain job")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domjobabort[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomjobabort(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = true;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virDomainAbortJob(dom) < 0)
        ret = false;

    virDomainFree(dom);
    return ret;
}

/*
 * "maxvcpus" command
 */
static const vshCmdInfo info_maxvcpus[] = {
    {"help", N_("connection vcpu maximum")},
    {"desc", N_("Show maximum number of virtual CPUs for guests on this connection.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_maxvcpus[] = {
    {"type", VSH_OT_STRING, 0, N_("domain type")},
    {NULL, 0, 0, NULL}
};

static bool
cmdMaxvcpus(vshControl *ctl, const vshCmd *cmd)
{
    const char *type = NULL;
    int vcpus;

    if (vshCommandOptString(cmd, "type", &type) < 0) {
        vshError(ctl, "%s", _("Invalid type"));
        return false;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    vcpus = virConnectGetMaxVcpus(ctl->conn, type);
    if (vcpus < 0)
        return false;
    vshPrint(ctl, "%d\n", vcpus);

    return true;
}

/*
 * "vcpucount" command
 */
static const vshCmdInfo info_vcpucount[] = {
    {"help", N_("domain vcpu counts")},
    {"desc", N_("Returns the number of virtual CPUs used by the domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vcpucount[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"maximum", VSH_OT_BOOL, 0, N_("get maximum cap on vcpus")},
    {"active", VSH_OT_BOOL, 0, N_("get number of currently active vcpus")},
    {"live", VSH_OT_BOOL, 0, N_("get value from running domain")},
    {"config", VSH_OT_BOOL, 0, N_("get value to be used on next boot")},
    {"current", VSH_OT_BOOL, 0,
     N_("get value according to current domain state")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVcpucount(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = true;
    bool maximum = vshCommandOptBool(cmd, "maximum");
    bool active = vshCommandOptBool(cmd, "active");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool current = vshCommandOptBool(cmd, "current");
    bool all = maximum + active + current + config + live == 0;
    int count;

    /* We want one of each pair of mutually exclusive options; that
     * is, use of flags requires exactly two options.  We reject the
     * use of more than 2 flags later on.  */
    if (maximum + active + current + config + live == 1) {
        if (maximum || active) {
            vshError(ctl,
                     _("when using --%s, one of --config, --live, or --current "
                       "must be specified"),
                     maximum ? "maximum" : "active");
        } else {
            vshError(ctl,
                     _("when using --%s, either --maximum or --active must be "
                       "specified"),
                     (current ? "current" : config ? "config" : "live"));
        }
        return false;
    }

    /* Backwards compatibility: prior to 0.9.4,
     * VIR_DOMAIN_AFFECT_CURRENT was unsupported, and --current meant
     * the opposite of --maximum.  Translate the old '--current
     * --live' into the new '--active --live', while treating the new
     * '--maximum --current' correctly rather than rejecting it as
     * '--maximum --active'.  */
    if (!maximum && !active && current) {
        current = false;
        active = true;
    }

    if (maximum && active) {
        vshError(ctl, "%s",
                 _("--maximum and --active cannot both be specified"));
        return false;
    }
    if (current + config + live > 1) {
        vshError(ctl, "%s",
                 _("--config, --live, and --current are mutually exclusive"));
        return false;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    /* In all cases, try the new API first; if it fails because we are
     * talking to an older client, generally we try a fallback API
     * before giving up.  --current requires the new API, since we
     * don't know whether the domain is running or inactive.  */
    if (current) {
        count = virDomainGetVcpusFlags(dom,
                                       maximum ? VIR_DOMAIN_VCPU_MAXIMUM : 0);
        if (count < 0) {
            virshReportError(ctl);
            ret = false;
        } else {
            vshPrint(ctl, "%d\n", count);
        }
    }

    if (all || (maximum && config)) {
        count = virDomainGetVcpusFlags(dom, (VIR_DOMAIN_VCPU_MAXIMUM |
                                             VIR_DOMAIN_AFFECT_CONFIG));
        if (count < 0 && (last_error->code == VIR_ERR_NO_SUPPORT
                          || last_error->code == VIR_ERR_INVALID_ARG)) {
            char *tmp;
            char *xml = virDomainGetXMLDesc(dom, VIR_DOMAIN_XML_INACTIVE);
            if (xml && (tmp = strstr(xml, "<vcpu"))) {
                tmp = strchr(tmp, '>');
                if (!tmp || virStrToLong_i(tmp + 1, &tmp, 10, &count) < 0)
                    count = -1;
            }
            vshResetLibvirtError();
            VIR_FREE(xml);
        }

        if (count < 0) {
            virshReportError(ctl);
            ret = false;
        } else if (all) {
            vshPrint(ctl, "%-12s %-12s %3d\n", _("maximum"), _("config"),
                     count);
        } else {
            vshPrint(ctl, "%d\n", count);
        }
        vshResetLibvirtError();
    }

    if (all || (maximum && live)) {
        count = virDomainGetVcpusFlags(dom, (VIR_DOMAIN_VCPU_MAXIMUM |
                                             VIR_DOMAIN_AFFECT_LIVE));
        if (count < 0 && (last_error->code == VIR_ERR_NO_SUPPORT
                          || last_error->code == VIR_ERR_INVALID_ARG)) {
            count = virDomainGetMaxVcpus(dom);
        }

        if (count < 0) {
            virshReportError(ctl);
            ret = false;
        } else if (all) {
            vshPrint(ctl, "%-12s %-12s %3d\n", _("maximum"), _("live"),
                     count);
        } else {
            vshPrint(ctl, "%d\n", count);
        }
        vshResetLibvirtError();
    }

    if (all || (active && config)) {
        count = virDomainGetVcpusFlags(dom, VIR_DOMAIN_AFFECT_CONFIG);
        if (count < 0 && (last_error->code == VIR_ERR_NO_SUPPORT
                          || last_error->code == VIR_ERR_INVALID_ARG)) {
            char *tmp, *end;
            char *xml = virDomainGetXMLDesc(dom, VIR_DOMAIN_XML_INACTIVE);
            if (xml && (tmp = strstr(xml, "<vcpu"))) {
                end = strchr(tmp, '>');
                if (end) {
                    *end = '\0';
                    tmp = strstr(tmp, "current=");
                    if (!tmp)
                        tmp = end + 1;
                    else {
                        tmp += strlen("current=");
                        tmp += *tmp == '\'' || *tmp == '"';
                    }
                }
                if (!tmp || virStrToLong_i(tmp, &tmp, 10, &count) < 0)
                    count = -1;
            }
            VIR_FREE(xml);
        }

        if (count < 0) {
            virshReportError(ctl);
            ret = false;
        } else if (all) {
            vshPrint(ctl, "%-12s %-12s %3d\n", _("current"), _("config"),
                     count);
        } else {
            vshPrint(ctl, "%d\n", count);
        }
        vshResetLibvirtError();
    }

    if (all || (active && live)) {
        count = virDomainGetVcpusFlags(dom, VIR_DOMAIN_AFFECT_LIVE);
        if (count < 0 && (last_error->code == VIR_ERR_NO_SUPPORT
                          || last_error->code == VIR_ERR_INVALID_ARG)) {
            virDomainInfo info;
            if (virDomainGetInfo(dom, &info) == 0)
                count = info.nrVirtCpu;
        }

        if (count < 0) {
            virshReportError(ctl);
            ret = false;
        } else if (all) {
            vshPrint(ctl, "%-12s %-12s %3d\n", _("current"), _("live"),
                     count);
        } else {
            vshPrint(ctl, "%d\n", count);
        }
        vshResetLibvirtError();
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "vcpuinfo" command
 */
static const vshCmdInfo info_vcpuinfo[] = {
    {"help", N_("detailed domain vcpu information")},
    {"desc", N_("Returns basic information about the domain virtual CPUs.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vcpuinfo[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVcpuinfo(vshControl *ctl, const vshCmd *cmd)
{
    virDomainInfo info;
    virDomainPtr dom;
    virNodeInfo nodeinfo;
    virVcpuInfoPtr cpuinfo;
    unsigned char *cpumaps;
    int ncpus, maxcpu;
    size_t cpumaplen;
    bool ret = true;
    int n, m;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virNodeGetInfo(ctl->conn, &nodeinfo) != 0) {
        virDomainFree(dom);
        return false;
    }

    if (virDomainGetInfo(dom, &info) != 0) {
        virDomainFree(dom);
        return false;
    }

    cpuinfo = vshMalloc(ctl, sizeof(virVcpuInfo)*info.nrVirtCpu);
    maxcpu = VIR_NODEINFO_MAXCPUS(nodeinfo);
    cpumaplen = VIR_CPU_MAPLEN(maxcpu);
    cpumaps = vshMalloc(ctl, info.nrVirtCpu * cpumaplen);

    if ((ncpus = virDomainGetVcpus(dom,
                                   cpuinfo, info.nrVirtCpu,
                                   cpumaps, cpumaplen)) >= 0) {
        for (n = 0 ; n < ncpus ; n++) {
            vshPrint(ctl, "%-15s %d\n", _("VCPU:"), n);
            vshPrint(ctl, "%-15s %d\n", _("CPU:"), cpuinfo[n].cpu);
            vshPrint(ctl, "%-15s %s\n", _("State:"),
                     _(vshDomainVcpuStateToString(cpuinfo[n].state)));
            if (cpuinfo[n].cpuTime != 0) {
                double cpuUsed = cpuinfo[n].cpuTime;

                cpuUsed /= 1000000000.0;

                vshPrint(ctl, "%-15s %.1lfs\n", _("CPU time:"), cpuUsed);
            }
            vshPrint(ctl, "%-15s ", _("CPU Affinity:"));
            for (m = 0; m < maxcpu; m++) {
                vshPrint(ctl, "%c", VIR_CPU_USABLE(cpumaps, cpumaplen, n, m) ? 'y' : '-');
            }
            vshPrint(ctl, "\n");
            if (n < (ncpus - 1)) {
                vshPrint(ctl, "\n");
            }
        }
    } else {
        if (info.state == VIR_DOMAIN_SHUTOFF &&
            (ncpus = virDomainGetVcpuPinInfo(dom, info.nrVirtCpu,
                                             cpumaps, cpumaplen,
                                             VIR_DOMAIN_AFFECT_CONFIG)) >= 0) {

            /* fallback plan to use virDomainGetVcpuPinInfo */

            for (n = 0; n < ncpus; n++) {
                vshPrint(ctl, "%-15s %d\n", _("VCPU:"), n);
                vshPrint(ctl, "%-15s %s\n", _("CPU:"), _("N/A"));
                vshPrint(ctl, "%-15s %s\n", _("State:"), _("N/A"));
                vshPrint(ctl, "%-15s %s\n", _("CPU time"), _("N/A"));
                vshPrint(ctl, "%-15s ", _("CPU Affinity:"));
                for (m = 0; m < maxcpu; m++) {
                    vshPrint(ctl, "%c",
                             VIR_CPU_USABLE(cpumaps, cpumaplen, n, m) ? 'y' : '-');
                }
                vshPrint(ctl, "\n");
                if (n < (ncpus - 1)) {
                    vshPrint(ctl, "\n");
                }
            }
        } else {
            ret = false;
        }
    }

    VIR_FREE(cpumaps);
    VIR_FREE(cpuinfo);
    virDomainFree(dom);
    return ret;
}

/*
 * "vcpupin" command
 */
static const vshCmdInfo info_vcpupin[] = {
    {"help", N_("control or query domain vcpu affinity")},
    {"desc", N_("Pin domain VCPUs to host physical CPUs.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vcpupin[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"vcpu", VSH_OT_INT, 0, N_("vcpu number")},
    {"cpulist", VSH_OT_DATA, VSH_OFLAG_EMPTY_OK,
     N_("host cpu number(s) to set, or omit option to query")},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {"live", VSH_OT_BOOL, 0, N_("affect running domain")},
    {"current", VSH_OT_BOOL, 0, N_("affect current domain")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVcpuPin(vshControl *ctl, const vshCmd *cmd)
{
    virDomainInfo info;
    virDomainPtr dom;
    virNodeInfo nodeinfo;
    int vcpu = -1;
    const char *cpulist = NULL;
    bool ret = true;
    unsigned char *cpumap = NULL;
    unsigned char *cpumaps = NULL;
    size_t cpumaplen;
    bool bit, lastbit, isInvert;
    int i, cpu, lastcpu, maxcpu, ncpus;
    bool unuse = false;
    const char *cur;
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool current = vshCommandOptBool(cmd, "current");
    bool query = false; /* Query mode if no cpulist */
    unsigned int flags = 0;

    if (current) {
        if (live || config) {
            vshError(ctl, "%s", _("--current must be specified exclusively"));
            return false;
        }
        flags = VIR_DOMAIN_AFFECT_CURRENT;
    } else {
        if (config)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        if (live)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
        /* neither option is specified */
        if (!live && !config)
            flags = -1;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptString(cmd, "cpulist", &cpulist) < 0) {
        vshError(ctl, "%s", _("vcpupin: Missing cpulist."));
        virDomainFree(dom);
        return false;
    }
    query = !cpulist;

    /* In query mode, "vcpu" is optional */
    if (vshCommandOptInt(cmd, "vcpu", &vcpu) < !query) {
        vshError(ctl, "%s",
                 _("vcpupin: Invalid or missing vCPU number."));
        virDomainFree(dom);
        return false;
    }

    if (virNodeGetInfo(ctl->conn, &nodeinfo) != 0) {
        virDomainFree(dom);
        return false;
    }

    if (virDomainGetInfo(dom, &info) != 0) {
        vshError(ctl, "%s", _("vcpupin: failed to get domain information."));
        virDomainFree(dom);
        return false;
    }

    if (vcpu >= info.nrVirtCpu) {
        vshError(ctl, "%s", _("vcpupin: Invalid vCPU number."));
        virDomainFree(dom);
        return false;
    }

    maxcpu = VIR_NODEINFO_MAXCPUS(nodeinfo);
    cpumaplen = VIR_CPU_MAPLEN(maxcpu);

    /* Query mode: show CPU affinity information then exit.*/
    if (query) {
        /* When query mode and neither "live", "config" nor "current"
         * is specified, set VIR_DOMAIN_AFFECT_CURRENT as flags */
        if (flags == -1)
            flags = VIR_DOMAIN_AFFECT_CURRENT;

        cpumaps = vshMalloc(ctl, info.nrVirtCpu * cpumaplen);
        if ((ncpus = virDomainGetVcpuPinInfo(dom, info.nrVirtCpu,
                                             cpumaps, cpumaplen, flags)) >= 0) {

            vshPrint(ctl, "%s %s\n", _("VCPU:"), _("CPU Affinity"));
            vshPrint(ctl, "----------------------------------\n");
            for (i = 0; i < ncpus; i++) {

               if (vcpu != -1 && i != vcpu)
                   continue;

               bit = lastbit = isInvert = false;
               lastcpu = -1;

               vshPrint(ctl, "%4d: ", i);
               for (cpu = 0; cpu < maxcpu; cpu++) {

                   bit = VIR_CPU_USABLE(cpumaps, cpumaplen, i, cpu);

                   isInvert = (bit ^ lastbit);
                   if (bit && isInvert) {
                       if (lastcpu == -1)
                           vshPrint(ctl, "%d", cpu);
                       else
                           vshPrint(ctl, ",%d", cpu);
                       lastcpu = cpu;
                   }
                   if (!bit && isInvert && lastcpu != cpu - 1)
                       vshPrint(ctl, "-%d", cpu - 1);
                   lastbit = bit;
               }
               if (bit && !isInvert) {
                  vshPrint(ctl, "-%d", maxcpu - 1);
               }
               vshPrint(ctl, "\n");
            }

        } else {
            ret = false;
        }
        VIR_FREE(cpumaps);
        goto cleanup;
    }

    /* Pin mode: pinning specified vcpu to specified physical cpus*/

    cpumap = vshCalloc(ctl, cpumaplen, sizeof(cpumap));
    /* Parse cpulist */
    cur = cpulist;
    if (*cur == 0) {
        goto parse_error;
    } else if (*cur == 'r') {
        for (cpu = 0; cpu < maxcpu; cpu++)
            VIR_USE_CPU(cpumap, cpu);
        cur = "";
    }

    while (*cur != 0) {

        /* the char '^' denotes exclusive */
        if (*cur == '^') {
            cur++;
            unuse = true;
        }

        /* parse physical CPU number */
        if (!c_isdigit(*cur))
            goto parse_error;
        cpu  = virParseNumber(&cur);
        if (cpu < 0) {
            goto parse_error;
        }
        if (cpu >= maxcpu) {
            vshError(ctl, _("Physical CPU %d doesn't exist."), cpu);
            goto parse_error;
        }
        virSkipSpaces(&cur);

        if (*cur == ',' || *cur == 0) {
            if (unuse) {
                VIR_UNUSE_CPU(cpumap, cpu);
            } else {
                VIR_USE_CPU(cpumap, cpu);
            }
        } else if (*cur == '-') {
            /* the char '-' denotes range */
            if (unuse) {
                goto parse_error;
            }
            cur++;
            virSkipSpaces(&cur);
            /* parse the end of range */
            lastcpu = virParseNumber(&cur);
            if (lastcpu < cpu) {
                goto parse_error;
            }
            if (lastcpu >= maxcpu) {
                vshError(ctl, _("Physical CPU %d doesn't exist."), maxcpu);
                goto parse_error;
            }
            for (i = cpu; i <= lastcpu; i++) {
                VIR_USE_CPU(cpumap, i);
            }
            virSkipSpaces(&cur);
        }

        if (*cur == ',') {
            cur++;
            virSkipSpaces(&cur);
            unuse = false;
        } else if (*cur == 0) {
            break;
        } else {
            goto parse_error;
        }
    }

    if (flags == -1) {
        if (virDomainPinVcpu(dom, vcpu, cpumap, cpumaplen) != 0) {
            ret = false;
        }
    } else {
        if (virDomainPinVcpuFlags(dom, vcpu, cpumap, cpumaplen, flags) != 0) {
            ret = false;
        }
    }

cleanup:
    VIR_FREE(cpumap);
    virDomainFree(dom);
    return ret;

parse_error:
    vshError(ctl, "%s", _("cpulist: Invalid format."));
    ret = false;
    goto cleanup;
}

/*
 * "setvcpus" command
 */
static const vshCmdInfo info_setvcpus[] = {
    {"help", N_("change number of virtual CPUs")},
    {"desc", N_("Change the number of virtual CPUs in the guest domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_setvcpus[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"count", VSH_OT_INT, VSH_OFLAG_REQ, N_("number of virtual CPUs")},
    {"maximum", VSH_OT_BOOL, 0, N_("set maximum limit on next boot")},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {"live", VSH_OT_BOOL, 0, N_("affect running domain")},
    {"current", VSH_OT_BOOL, 0, N_("affect current domain")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSetvcpus(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    int count = 0;
    bool ret = true;
    bool maximum = vshCommandOptBool(cmd, "maximum");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool current = vshCommandOptBool(cmd, "current");
    unsigned int flags = 0;

    if (current) {
        if (live || config) {
            vshError(ctl, "%s", _("--current must be specified exclusively"));
            return false;
        }
        flags = VIR_DOMAIN_AFFECT_CURRENT;
    } else {
        if (config)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        if (live)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
        /* neither option is specified */
        if (!live && !config && !maximum)
            flags = -1;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptInt(cmd, "count", &count) < 0 || count <= 0) {
        vshError(ctl, "%s", _("Invalid number of virtual CPUs"));
        goto cleanup;
    }

    if (flags == -1) {
        if (virDomainSetVcpus(dom, count) != 0) {
            ret = false;
        }
    } else {
        /* If the --maximum flag was given, we need to ensure only the
           --config flag is in effect as well */
        if (maximum) {
            vshDebug(ctl, VSH_ERR_DEBUG, "--maximum flag was given\n");

            flags |= VIR_DOMAIN_VCPU_MAXIMUM;

            /* If neither the --config nor --live flags were given, OR
               if just the --live flag was given, we need to error out
               warning the user that the --maximum flag can only be used
               with the --config flag */
            if (live || !config) {

                /* Warn the user about the invalid flag combination */
                vshError(ctl, _("--maximum must be used with --config only"));
                ret = false;
                goto cleanup;
            }
        }

        /* Apply the virtual cpu changes */
        if (virDomainSetVcpusFlags(dom, count, flags) < 0) {
            ret = false;
        }
    }

  cleanup:
    virDomainFree(dom);
    return ret;
}

/*
 * "cpu-compare" command
 */
static const vshCmdInfo info_cpu_compare[] = {
    {"help", N_("compare host CPU with a CPU described by an XML file")},
    {"desc", N_("compare CPU with host CPU")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_cpu_compare[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("file containing an XML CPU description")},
    {NULL, 0, 0, NULL}
};

static bool
cmdCPUCompare(vshControl *ctl, const vshCmd *cmd)
{
    const char *from = NULL;
    bool ret = false;
    char *buffer;
    int result;
    const char *snippet;

    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlBufferPtr xml_buf = NULL;
    xmlNodePtr node;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0)
        return false;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0) {
        vshError(ctl, _("Failed to read file '%s' to compare"),
                 from);
        return false;
    }

    /* try to extract the CPU element from as it would appear in a domain XML*/
    if (!(xml = virXMLParseStringCtxt(buffer, from, &ctxt)))
        goto cleanup;

    if ((node = virXPathNode("/cpu|"
                             "/domain/cpu|"
                              "/capabilities/host/cpu", ctxt))) {
        if (!(xml_buf = xmlBufferCreate())) {
            vshError(ctl, _("Can't create XML buffer to extract CPU element."));
            goto cleanup;
        }

        if (xmlNodeDump(xml_buf, xml, node, 0, 0) < 0) {
            vshError(ctl, _("Failed to extract CPU element snippet from domain XML."));
            goto cleanup;
        }

        snippet = (const char *) xmlBufferContent(xml_buf);
    } else {
        vshError(ctl, _("File '%s' does not contain a <cpu> element or is not "
                        "a valid domain or capabilities XML"), from);
        goto cleanup;
    }

    result = virConnectCompareCPU(ctl->conn, snippet, 0);

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
    xmlBufferFree(xml_buf);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);

    return ret;
}

/*
 * "cpu-baseline" command
 */
static const vshCmdInfo info_cpu_baseline[] = {
    {"help", N_("compute baseline CPU")},
    {"desc", N_("Compute baseline CPU for a set of given CPUs.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_cpu_baseline[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("file containing XML CPU descriptions")},
    {NULL, 0, 0, NULL}
};

static bool
cmdCPUBaseline(vshControl *ctl, const vshCmd *cmd)
{
    const char *from = NULL;
    bool ret = false;
    char *buffer;
    char *result = NULL;
    const char **list = NULL;
    int count = 0;

    xmlDocPtr xml = NULL;
    xmlNodePtr *node_list = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlBufferPtr xml_buf = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    int i;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0)
        return false;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
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

    if (!(xml_buf = xmlBufferCreate()))
        goto no_memory;

    for (i = 0; i < count; i++) {
        xmlBufferEmpty(xml_buf);

        if (xmlNodeDump(xml_buf, xml,  node_list[i], 0, 0) < 0) {
            vshError(ctl, _("Failed to extract <cpu> element"));
            goto cleanup;
        }

        list[i] = vshStrdup(ctl, (const char *)xmlBufferContent(xml_buf));
    }

    result = virConnectBaselineCPU(ctl->conn, list, count, 0);

    if (result) {
        vshPrint(ctl, "%s", result);
        ret = true;
    }

cleanup:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    xmlBufferFree(xml_buf);
    VIR_FREE(result);
    if (list != NULL && count > 0) {
        for (i = 0; i < count; i++)
            VIR_FREE(list[i]);
    }
    VIR_FREE(list);
    VIR_FREE(buffer);

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
    {"help", N_("show domain cpu statistics")},
    {"desc",
     N_("Display per-CPU and total statistics about the domain's CPUs")},
    {NULL, NULL},
};

static const vshCmdOptDef opts_cpu_stats[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"total", VSH_OT_BOOL, 0, N_("Show total statistics only")},
    {"start", VSH_OT_INT, 0, N_("Show statistics from this CPU")},
    {"count", VSH_OT_INT, 0, N_("Number of shown CPUs at most")},
    {NULL, 0, 0, NULL},
};

static bool
cmdCPUStats(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    virTypedParameterPtr params = NULL;
    int i, j, pos, max_id, cpu = -1, show_count = -1, nparams;
    bool show_total = false, show_per_cpu = false;
    unsigned int flags = 0;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    show_total = vshCommandOptBool(cmd, "total");
    if (vshCommandOptInt(cmd, "start", &cpu) > 0)
        show_per_cpu = true;
    if (vshCommandOptInt(cmd, "count", &show_count) > 0)
        show_per_cpu = true;

    /* default show per_cpu and total */
    if (!show_total && !show_per_cpu) {
        show_total = true;
        show_per_cpu = true;
    }

    if (!show_per_cpu) /* show total stats only */
        goto do_show_total;

    /* check cpu, show_count, and ignore wrong argument */
    if (cpu < 0)
        cpu = 0;

    /* get number of cpus on the node */
    if ((max_id = virDomainGetCPUStats(dom, NULL, 0, 0, 0, flags)) < 0)
        goto failed_stats;
    if (show_count < 0 || show_count > max_id)
        show_count = max_id;

    /* get percpu information */
    if ((nparams = virDomainGetCPUStats(dom, NULL, 0, 0, 1, flags)) < 0)
        goto failed_stats;

    if (!nparams) {
        vshPrint(ctl, "%s", _("No per-CPU stats available"));
        goto do_show_total;
    }

    if (VIR_ALLOC_N(params, nparams * MIN(show_count, 128)) < 0)
        goto failed_params;

    while (show_count) {
        int ncpus = MIN(show_count, 128);

        if (virDomainGetCPUStats(dom, params, nparams, cpu, ncpus, flags) < 0)
            goto failed_stats;

        for (i = 0; i < ncpus; i++) {
            if (params[i * nparams].type == 0) /* this cpu is not in the map */
                continue;
            vshPrint(ctl, "CPU%d:\n", cpu + i);

            for (j = 0; j < nparams; j++) {
                pos = i * nparams + j;
                vshPrint(ctl, "\t%-12s ", params[pos].field);
                if ((STREQ(params[pos].field, VIR_DOMAIN_CPU_STATS_CPUTIME) ||
                     STREQ(params[pos].field, VIR_DOMAIN_CPU_STATS_VCPUTIME)) &&
                    params[j].type == VIR_TYPED_PARAM_ULLONG) {
                    vshPrint(ctl, "%9lld.%09lld seconds\n",
                             params[pos].value.ul / 1000000000,
                             params[pos].value.ul % 1000000000);
                } else {
                    const char *s = vshGetTypedParamValue(ctl, &params[pos]);
                    vshPrint(ctl, _("%s\n"), s);
                    VIR_FREE(s);
                }
            }
        }
        cpu += ncpus;
        show_count -= ncpus;
        virTypedParameterArrayClear(params, nparams * ncpus);
    }
    VIR_FREE(params);

do_show_total:
    if (!show_total)
        goto cleanup;

    /* get supported num of parameter for total statistics */
    if ((nparams = virDomainGetCPUStats(dom, NULL, 0, -1, 1, flags)) < 0)
        goto failed_stats;

    if (!nparams) {
        vshPrint(ctl, "%s", _("No total stats available"));
        goto cleanup;
    }

    if (VIR_ALLOC_N(params, nparams))
        goto failed_params;

    /* passing start_cpu == -1 gives us domain's total status */
    if ((nparams = virDomainGetCPUStats(dom, params, nparams, -1, 1, flags)) < 0)
        goto failed_stats;

    vshPrint(ctl, _("Total:\n"));
    for (i = 0; i < nparams; i++) {
        vshPrint(ctl, "\t%-12s ", params[i].field);
        if ((STREQ(params[i].field, VIR_DOMAIN_CPU_STATS_CPUTIME) ||
             STREQ(params[i].field, VIR_DOMAIN_CPU_STATS_USERTIME) ||
             STREQ(params[i].field, VIR_DOMAIN_CPU_STATS_SYSTEMTIME)) &&
            params[i].type == VIR_TYPED_PARAM_ULLONG) {
            vshPrint(ctl, "%9lld.%09lld seconds\n",
                     params[i].value.ul / 1000000000,
                     params[i].value.ul % 1000000000);
        } else {
            char *s = vshGetTypedParamValue(ctl, &params[i]);
            vshPrint(ctl, "%s\n", s);
            VIR_FREE(s);
        }
    }
    virTypedParameterArrayClear(params, nparams);
    VIR_FREE(params);

cleanup:
    virDomainFree(dom);
    return true;

failed_params:
    virReportOOMError();
    virDomainFree(dom);
    return false;

failed_stats:
    vshError(ctl, _("Failed to virDomainGetCPUStats()\n"));
    VIR_FREE(params);
    virDomainFree(dom);
    return false;
}

/*
 * "create" command
 */
static const vshCmdInfo info_create[] = {
    {"help", N_("create a domain from an XML file")},
    {"desc", N_("Create a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_create[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("file containing an XML domain description")},
#ifndef WIN32
    {"console", VSH_OT_BOOL, 0, N_("attach to console after creation")},
#endif
    {"paused", VSH_OT_BOOL, 0, N_("leave the guest paused after creation")},
    {"autodestroy", VSH_OT_BOOL, 0, N_("automatically destroy the guest when virsh disconnects")},
    {NULL, 0, 0, NULL}
};

static bool
cmdCreate(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *from = NULL;
    bool ret = true;
    char *buffer;
#ifndef WIN32
    bool console = vshCommandOptBool(cmd, "console");
#endif
    unsigned int flags = VIR_DOMAIN_NONE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0)
        return false;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    if (vshCommandOptBool(cmd, "paused"))
        flags |= VIR_DOMAIN_START_PAUSED;
    if (vshCommandOptBool(cmd, "autodestroy"))
        flags |= VIR_DOMAIN_START_AUTODESTROY;

    dom = virDomainCreateXML(ctl->conn, buffer, flags);
    VIR_FREE(buffer);

    if (dom != NULL) {
        vshPrint(ctl, _("Domain %s created from %s\n"),
                 virDomainGetName(dom), from);
#ifndef WIN32
        if (console)
            cmdRunConsole(ctl, dom, NULL, 0);
#endif
        virDomainFree(dom);
    } else {
        vshError(ctl, _("Failed to create domain from %s"), from);
        ret = false;
    }
    return ret;
}

/*
 * "define" command
 */
static const vshCmdInfo info_define[] = {
    {"help", N_("define (but don't start) a domain from an XML file")},
    {"desc", N_("Define a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_define[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("file containing an XML domain description")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDefine(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *from = NULL;
    bool ret = true;
    char *buffer;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0)
        return false;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    dom = virDomainDefineXML(ctl->conn, buffer);
    VIR_FREE(buffer);

    if (dom != NULL) {
        vshPrint(ctl, _("Domain %s defined from %s\n"),
                 virDomainGetName(dom), from);
        virDomainFree(dom);
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
    {"help", N_("destroy (stop) a domain")},
    {"desc",
     N_("Forcefully stop a given domain, but leave its resources intact.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_destroy[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"graceful", VSH_OT_BOOL, VSH_OFLAG_NONE, N_("terminate gracefully")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDestroy(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = true;
    const char *name;
    unsigned int flags = 0;
    int result;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (vshCommandOptBool(cmd, "graceful"))
       flags |= VIR_DOMAIN_DESTROY_GRACEFUL;

    if (flags)
       result = virDomainDestroyFlags(dom, VIR_DOMAIN_DESTROY_GRACEFUL);
    else
       result = virDomainDestroy(dom);

    if (result == 0) {
        vshPrint(ctl, _("Domain %s destroyed\n"), name);
    } else {
        vshError(ctl, _("Failed to destroy domain %s"), name);
        ret = false;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "desc" command for managing domain description and title
 */
static const vshCmdInfo info_desc[] = {
    {"help", N_("show or set domain's description or title")},
    {"desc", N_("Allows to show or modify description or title of a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_desc[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"live", VSH_OT_BOOL, 0, N_("modify/get running state")},
    {"config", VSH_OT_BOOL, 0, N_("modify/get persistent configuration")},
    {"current", VSH_OT_BOOL, 0, N_("modify/get current state configuration")},
    {"title", VSH_OT_BOOL, 0, N_("modify/get the title instead of description")},
    {"edit", VSH_OT_BOOL, 0, N_("open an editor to modify the description")},
    {"new-desc", VSH_OT_ARGV, 0, N_("message")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDesc(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
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

    if (current) {
        if (live || config) {
            vshError(ctl, "%s", _("--current must be specified exclusively"));
            return false;
        }
        flags = VIR_DOMAIN_AFFECT_CURRENT;
    } else {
        if (config)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        if (live)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if ((state = vshDomainState(ctl, dom, NULL)) < 0)
        goto cleanup;

    while ((opt = vshCommandOptArgv(cmd, opt))) {
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
        vshPrint(ctl, "%s", _("Failed to collect new description/title"));
        goto cleanup;
    }
    desc = virBufferContentAndReset(&buf);

    if (edit || desc) {
        if (!desc) {
                desc = vshGetDomainDescription(ctl, dom, title,
                                           config?VIR_DOMAIN_XML_INACTIVE:0);
                if (!desc)
                    goto cleanup;
        }

        if (edit) {
            /* Create and open the temporary file. */
            if (!(tmp = editWriteToTempFile(ctl, desc)))
                goto cleanup;

            /* Start the editor. */
            if (editFile(ctl, tmp) == -1)
                goto cleanup;

            /* Read back the edited file. */
            if (!(desc_edited = editReadBackFile(ctl, tmp)))
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
                vshPrint(ctl, _("Domain description not changed.\n"));
                ret = true;
                goto cleanup;
            }

            VIR_FREE(desc);
            desc = desc_edited;
            desc_edited = NULL;
        }

        if (virDomainSetMetadata(dom, type, desc, NULL, NULL, flags) < 0) {
            vshError(ctl, "%s",
                     _("Failed to set new domain description"));
            goto cleanup;
        }
        vshPrint(ctl, "%s", _("Domain description updated successfully"));
    } else {
        desc = vshGetDomainDescription(ctl, dom, title,
                                       config?VIR_DOMAIN_XML_INACTIVE:0);
        if (!desc)
            goto cleanup;

        if (strlen(desc) > 0)
            vshPrint(ctl, "%s", desc);
        else
            vshPrint(ctl, _("No description for domain: %s"),
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
    if (dom)
        virDomainFree(dom);
    return ret;
}

/*
 * "inject-nmi" command
 */
static const vshCmdInfo info_inject_nmi[] = {
    {"help", N_("Inject NMI to the guest")},
    {"desc", N_("Inject NMI to the guest domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_inject_nmi[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdInjectNMI(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    int ret = true;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virDomainInjectNMI(dom, 0) < 0)
            ret = false;

    virDomainFree(dom);
    return ret;
}

/*
 * "send-key" command
 */
static const vshCmdInfo info_send_key[] = {
    {"help", N_("Send keycodes to the guest")},
    {"desc", N_("Send keycodes (integers or symbolic names) to the guest")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_send_key[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"codeset", VSH_OT_STRING, VSH_OFLAG_REQ_OPT,
     N_("the codeset of keycodes, default:linux")},
    {"holdtime", VSH_OT_INT, VSH_OFLAG_REQ_OPT,
     N_("the time (in milliseconds) how long the keys will be held")},
    {"keycode", VSH_OT_ARGV, VSH_OFLAG_REQ, N_("the key code")},
    {NULL, 0, 0, NULL}
};

static int
get_integer_keycode(const char *key_name)
{
    unsigned int val;

    if (virStrToLong_ui(key_name, NULL, 0, &val) < 0 || val > 0xffff || !val)
        return -1;
    return val;
}

static bool
cmdSendKey(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    int ret = false;
    const char *codeset_option;
    int codeset;
    int holdtime;
    int count = 0;
    const vshCmdOpt *opt = NULL;
    int keycode;
    unsigned int keycodes[VIR_DOMAIN_SEND_KEY_MAX_KEYS];

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptString(cmd, "codeset", &codeset_option) <= 0)
        codeset_option = "linux";

    if (vshCommandOptInt(cmd, "holdtime", &holdtime) <= 0)
        holdtime = 0;

    codeset = virKeycodeSetTypeFromString(codeset_option);
    if ((int)codeset < 0) {
        vshError(ctl, _("unknown codeset: '%s'"), codeset_option);
        goto cleanup;
    }

    while ((opt = vshCommandOptArgv(cmd, opt))) {
        if (count == VIR_DOMAIN_SEND_KEY_MAX_KEYS) {
            vshError(ctl, _("too many keycodes"));
            goto cleanup;
        }

        if ((keycode = get_integer_keycode(opt->data)) <= 0) {
            if ((keycode = virKeycodeValueFromString(codeset, opt->data)) <= 0) {
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
    virDomainFree(dom);
    return ret;
}

/*
 * "setmem" command
 */
static const vshCmdInfo info_setmem[] = {
    {"help", N_("change memory allocation")},
    {"desc", N_("Change the current memory allocation in the guest domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_setmem[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"kilobytes", VSH_OT_ALIAS, 0, "size"},
    {"size", VSH_OT_INT, VSH_OFLAG_REQ,
     N_("new memory size, as scaled integer (default KiB)")},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {"live", VSH_OT_BOOL, 0, N_("affect running domain")},
    {"current", VSH_OT_BOOL, 0, N_("affect current domain")},
    {NULL, 0, 0, NULL}
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
    unsigned int flags = 0;

    if (current) {
        if (live || config) {
            vshError(ctl, "%s", _("--current must be specified exclusively"));
            return false;
        }
        flags = VIR_DOMAIN_AFFECT_CURRENT;
    } else {
        if (config)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        if (live)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
        /* neither option is specified */
        if (!live && !config)
            flags = -1;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    /* The API expects 'unsigned long' KiB, so depending on whether we
     * are 32-bit or 64-bit determines the maximum we can use.  */
    if (sizeof(kibibytes) < sizeof(max))
        max = 1024ull * ULONG_MAX;
    else
        max = ULONG_MAX;
    if (vshCommandOptScaledInt(cmd, "size", &bytes, 1024, max) < 0) {
        vshError(ctl, "%s", _("memory size has to be a number"));
        virDomainFree(dom);
        return false;
    }
    kibibytes = VIR_DIV_UP(bytes, 1024);

    if (flags == -1) {
        if (virDomainSetMemory(dom, kibibytes) != 0) {
            ret = false;
        }
    } else {
        if (virDomainSetMemoryFlags(dom, kibibytes, flags) < 0) {
            ret = false;
        }
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "setmaxmem" command
 */
static const vshCmdInfo info_setmaxmem[] = {
    {"help", N_("change maximum memory limit")},
    {"desc", N_("Change the maximum memory allocation limit in the guest domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_setmaxmem[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"kilobytes", VSH_OT_ALIAS, 0, "size"},
    {"size", VSH_OT_INT, VSH_OFLAG_REQ,
     N_("new maximum memory size, as scaled integer (default KiB)")},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {"live", VSH_OT_BOOL, 0, N_("affect running domain")},
    {"current", VSH_OT_BOOL, 0, N_("affect current domain")},
    {NULL, 0, 0, NULL}
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
    unsigned int flags = VIR_DOMAIN_MEM_MAXIMUM;

    if (current) {
        if (live || config) {
            vshError(ctl, "%s", _("--current must be specified exclusively"));
            return false;
        }
    } else {
        if (config)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        if (live)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
        /* neither option is specified */
        if (!live && !config)
            flags = -1;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    /* The API expects 'unsigned long' KiB, so depending on whether we
     * are 32-bit or 64-bit determines the maximum we can use.  */
    if (sizeof(kibibytes) < sizeof(max))
        max = 1024ull * ULONG_MAX;
    else
        max = ULONG_MAX;
    if (vshCommandOptScaledInt(cmd, "size", &bytes, 1024, max) < 0) {
        vshError(ctl, "%s", _("memory size has to be a number"));
        virDomainFree(dom);
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

    virDomainFree(dom);
    return ret;
}

/*
 * "memtune" command
 */
static const vshCmdInfo info_memtune[] = {
    {"help", N_("Get or set memory parameters")},
    {"desc", N_("Get or set the current memory parameters for a guest"
                " domain.\n"
                "    To get the memory parameters use following command: \n\n"
                "    virsh # memtune <domain>")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_memtune[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"hard-limit", VSH_OT_INT, VSH_OFLAG_NONE,
     N_("Max memory, as scaled integer (default KiB)")},
    {"soft-limit", VSH_OT_INT, VSH_OFLAG_NONE,
     N_("Memory during contention, as scaled integer (default KiB)")},
    {"swap-hard-limit", VSH_OT_INT, VSH_OFLAG_NONE,
     N_("Max memory plus swap, as scaled integer (default KiB)")},
    {"min-guarantee", VSH_OT_INT, VSH_OFLAG_NONE,
     N_("Min guaranteed memory, as scaled integer (default KiB)")},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {"live", VSH_OT_BOOL, 0, N_("affect running domain")},
    {"current", VSH_OT_BOOL, 0, N_("affect current domain")},
    {NULL, 0, 0, NULL}
};

static int
vshMemtuneGetSize(const vshCmd *cmd, const char *name, long long *value)
{
    int ret;
    unsigned long long tmp;
    const char *str;
    char *end;

    ret = vshCommandOptString(cmd, name, &str);
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
    return 0;
}

static bool
cmdMemtune(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    long long hard_limit = 0, soft_limit = 0, swap_hard_limit = 0;
    long long min_guarantee = 0;
    int nparams = 0;
    unsigned int i = 0;
    virTypedParameterPtr params = NULL, temp = NULL;
    bool ret = false;
    unsigned int flags = 0;
    bool current = vshCommandOptBool(cmd, "current");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");

    if (current) {
        if (live || config) {
            vshError(ctl, "%s", _("--current must be specified exclusively"));
            return false;
        }
        flags = VIR_DOMAIN_AFFECT_CURRENT;
    } else {
        if (config)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        if (live)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshMemtuneGetSize(cmd, "hard-limit", &hard_limit) < 0 ||
        vshMemtuneGetSize(cmd, "soft-limit", &soft_limit) < 0 ||
        vshMemtuneGetSize(cmd, "swap-hard-limit", &swap_hard_limit) < 0 ||
        vshMemtuneGetSize(cmd, "min-guarantee", &min_guarantee) < 0) {
        vshError(ctl, "%s",
                 _("Unable to parse integer parameter"));
        goto cleanup;
    }

    if (hard_limit)
        nparams++;

    if (soft_limit)
        nparams++;

    if (swap_hard_limit)
        nparams++;

    if (min_guarantee)
        nparams++;

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

        ret = true;
    } else {
        /* set the memory parameters */
        params = vshCalloc(ctl, nparams, sizeof(*params));

        for (i = 0; i < nparams; i++) {
            temp = &params[i];

            /*
             * Some magic here, this is used to fill the params structure with
             * the valid arguments passed, after filling the particular
             * argument we purposely make them 0, so on the next pass it goes
             * to the next valid argument and so on.
             */
            if (soft_limit) {
                if (virTypedParameterAssign(temp,
                                            VIR_DOMAIN_MEMORY_SOFT_LIMIT,
                                            VIR_TYPED_PARAM_ULLONG,
                                            soft_limit) < 0)
                    goto error;
                soft_limit = 0;
            } else if (hard_limit) {
                if (virTypedParameterAssign(temp,
                                            VIR_DOMAIN_MEMORY_HARD_LIMIT,
                                            VIR_TYPED_PARAM_ULLONG,
                                            hard_limit) < 0)
                    goto error;
                hard_limit = 0;
            } else if (swap_hard_limit) {
                if (virTypedParameterAssign(temp,
                                            VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT,
                                            VIR_TYPED_PARAM_ULLONG,
                                            swap_hard_limit) < 0)
                    goto error;
                swap_hard_limit = 0;
            } else if (min_guarantee) {
                if (virTypedParameterAssign(temp,
                                            VIR_DOMAIN_MEMORY_MIN_GUARANTEE,
                                            VIR_TYPED_PARAM_ULLONG,
                                            min_guarantee) < 0)
                    goto error;
                min_guarantee = 0;
            }

            /* If the user has passed -1, we interpret it as unlimited */
            if (temp->value.ul == -1)
                temp->value.ul = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;
        }
        if (virDomainSetMemoryParameters(dom, params, nparams, flags) != 0)
            goto error;
        else
            ret = true;
    }

cleanup:
    VIR_FREE(params);
    virDomainFree(dom);
    return ret;

error:
    vshError(ctl, "%s", _("Unable to change memory parameters"));
    goto cleanup;
}

/*
 * "numatune" command
 */
static const vshCmdInfo info_numatune[] = {
    {"help", N_("Get or set numa parameters")},
    {"desc", N_("Get or set the current numa parameters for a guest"
                " domain.\n"
                "    To get the numa parameters use following command: \n\n"
                "    virsh # numatune <domain>")},
    {NULL, NULL}

};

static const vshCmdOptDef opts_numatune[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"mode", VSH_OT_DATA, VSH_OFLAG_NONE,
     N_("NUMA mode, one of strict, preferred and interleave")},
    {"nodeset", VSH_OT_DATA, VSH_OFLAG_NONE,
     N_("NUMA node selections to set")},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {"live", VSH_OT_BOOL, 0, N_("affect running domain")},
    {"current", VSH_OT_BOOL, 0, N_("affect current domain")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNumatune(vshControl * ctl, const vshCmd * cmd)
{
    virDomainPtr dom;
    int nparams = 0;
    unsigned int i = 0;
    virTypedParameterPtr params = NULL, temp = NULL;
    const char *nodeset = NULL;
    bool ret = false;
    unsigned int flags = 0;
    bool current = vshCommandOptBool(cmd, "current");
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    const char *mode = NULL;

    if (current) {
        if (live || config) {
            vshError(ctl, "%s", _("--current must be specified exclusively"));
            return false;
        }
        flags = VIR_DOMAIN_AFFECT_CURRENT;
    } else {
        if (config)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        if (live)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptString(cmd, "nodeset", &nodeset) < 0) {
        vshError(ctl, "%s", _("Unable to parse nodeset."));
        virDomainFree(dom);
        return false;
    }
    if (nodeset)
        nparams++;
    if (vshCommandOptString(cmd, "mode", &mode) < 0) {
        vshError(ctl, "%s", _("Unable to parse mode."));
        virDomainFree(dom);
        return false;
    }
    if (mode)
        nparams++;

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

        ret = true;
    } else {
        /* set the numa parameters */
        params = vshCalloc(ctl, nparams, sizeof(*params));

        for (i = 0; i < nparams; i++) {
            temp = &params[i];

            /*
             * Some magic here, this is used to fill the params structure with
             * the valid arguments passed, after filling the particular
             * argument we purposely make them 0, so on the next pass it goes
             * to the next valid argument and so on.
             */
            if (mode) {
                /* Accept string or integer, in case server
                 * understands newer integer than what strings we were
                 * compiled with */
                if ((temp->value.i =
                    virDomainNumatuneMemModeTypeFromString(mode)) < 0 &&
                    virStrToLong_i(mode, NULL, 0, &temp->value.i) < 0) {
                    vshError(ctl, _("Invalid mode: %s"), mode);
                    goto cleanup;
                }
                if (!virStrcpy(temp->field, VIR_DOMAIN_NUMA_MODE,
                               sizeof(temp->field)))
                    goto cleanup;
                temp->type = VIR_TYPED_PARAM_INT;
                mode = NULL;
            } else if (nodeset) {
                temp->value.s = vshStrdup(ctl, nodeset);
                temp->type = VIR_TYPED_PARAM_STRING;
                if (!virStrcpy(temp->field, VIR_DOMAIN_NUMA_NODESET,
                               sizeof(temp->field)))
                    goto cleanup;
                nodeset = NULL;
            }
        }
        if (virDomainSetNumaParameters(dom, params, nparams, flags) != 0)
            vshError(ctl, "%s", _("Unable to change numa parameters"));
        else
            ret = true;
    }

  cleanup:
    virTypedParameterArrayClear(params, nparams);
    VIR_FREE(params);
    virDomainFree(dom);
    return ret;
}

/*
 * "dumpxml" command
 */
static const vshCmdInfo info_dumpxml[] = {
    {"help", N_("domain information in XML")},
    {"desc", N_("Output the domain information as an XML dump to stdout.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_dumpxml[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"inactive", VSH_OT_BOOL, 0, N_("show inactive defined XML")},
    {"security-info", VSH_OT_BOOL, 0, N_("include security sensitive information in XML dump")},
    {"update-cpu", VSH_OT_BOOL, 0, N_("update guest CPU according to host CPU")},
    {NULL, 0, 0, NULL}
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

    if (inactive)
        flags |= VIR_DOMAIN_XML_INACTIVE;
    if (secure)
        flags |= VIR_DOMAIN_XML_SECURE;
    if (update)
        flags |= VIR_DOMAIN_XML_UPDATE_CPU;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    dump = virDomainGetXMLDesc(dom, flags);
    if (dump != NULL) {
        vshPrint(ctl, "%s", dump);
        VIR_FREE(dump);
    } else {
        ret = false;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "domxml-from-native" command
 */
static const vshCmdInfo info_domxmlfromnative[] = {
    {"help", N_("Convert native config to domain XML")},
    {"desc", N_("Convert native guest configuration format to domain XML format.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domxmlfromnative[] = {
    {"format", VSH_OT_DATA, VSH_OFLAG_REQ, N_("source config data format")},
    {"config", VSH_OT_DATA, VSH_OFLAG_REQ, N_("config data file to import from")},
    {NULL, 0, 0, NULL}
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

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "format", &format) < 0 ||
        vshCommandOptString(cmd, "config", &configFile) < 0)
        return false;

    if (virFileReadAll(configFile, 1024*1024, &configData) < 0)
        return false;

    xmlData = virConnectDomainXMLFromNative(ctl->conn, format, configData, flags);
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
    {"help", N_("Convert domain XML to native config")},
    {"desc", N_("Convert domain XML config to a native guest configuration format.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domxmltonative[] = {
    {"format", VSH_OT_DATA, VSH_OFLAG_REQ, N_("target config data type format")},
    {"xml", VSH_OT_DATA, VSH_OFLAG_REQ, N_("xml data file to export from")},
    {NULL, 0, 0, NULL}
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

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "format", &format) < 0
        || vshCommandOptString(cmd, "xml", &xmlFile) < 0)
        return false;

    if (virFileReadAll(xmlFile, 1024*1024, &xmlData) < 0)
        return false;

    configData = virConnectDomainXMLToNative(ctl->conn, format, xmlData, flags);
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
    {"help", N_("convert a domain id or UUID to domain name")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domname[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomname(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;
    if (!(dom = vshCommandOptDomainBy(ctl, cmd, NULL,
                                      VSH_BYID|VSH_BYUUID)))
        return false;

    vshPrint(ctl, "%s\n", virDomainGetName(dom));
    virDomainFree(dom);
    return true;
}

/*
 * "domid" command
 */
static const vshCmdInfo info_domid[] = {
    {"help", N_("convert a domain name or UUID to domain id")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domid[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomid(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    unsigned int id;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;
    if (!(dom = vshCommandOptDomainBy(ctl, cmd, NULL,
                                      VSH_BYNAME|VSH_BYUUID)))
        return false;

    id = virDomainGetID(dom);
    if (id == ((unsigned int)-1))
        vshPrint(ctl, "%s\n", "-");
    else
        vshPrint(ctl, "%d\n", id);
    virDomainFree(dom);
    return true;
}

/*
 * "domuuid" command
 */
static const vshCmdInfo info_domuuid[] = {
    {"help", N_("convert a domain name or id to domain UUID")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domuuid[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain id or name")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomuuid(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;
    if (!(dom = vshCommandOptDomainBy(ctl, cmd, NULL,
                                      VSH_BYNAME|VSH_BYID)))
        return false;

    if (virDomainGetUUIDString(dom, uuid) != -1)
        vshPrint(ctl, "%s\n", uuid);
    else
        vshError(ctl, "%s", _("failed to get domain UUID"));

    virDomainFree(dom);
    return true;
}

/*
 * "migrate" command
 */
static const vshCmdInfo info_migrate[] = {
    {"help", N_("migrate domain to another host")},
    {"desc", N_("Migrate domain to another host.  Add --live for live migration.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_migrate[] = {
    {"live", VSH_OT_BOOL, 0, N_("live migration")},
    {"p2p", VSH_OT_BOOL, 0, N_("peer-2-peer migration")},
    {"direct", VSH_OT_BOOL, 0, N_("direct migration")},
    {"tunneled", VSH_OT_ALIAS, 0, "tunnelled"},
    {"tunnelled", VSH_OT_BOOL, 0, N_("tunnelled migration")},
    {"persistent", VSH_OT_BOOL, 0, N_("persist VM on destination")},
    {"undefinesource", VSH_OT_BOOL, 0, N_("undefine VM on source")},
    {"suspend", VSH_OT_BOOL, 0, N_("do not restart the domain on the destination host")},
    {"copy-storage-all", VSH_OT_BOOL, 0, N_("migration with non-shared storage with full disk copy")},
    {"copy-storage-inc", VSH_OT_BOOL, 0, N_("migration with non-shared storage with incremental copy (same base image shared between source and destination)")},
    {"change-protection", VSH_OT_BOOL, 0,
     N_("prevent any configuration changes to domain until migration ends)")},
    {"unsafe", VSH_OT_BOOL, 0, N_("force migration even if it may be unsafe")},
    {"verbose", VSH_OT_BOOL, 0, N_("display the progress of migration")},
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"desturi", VSH_OT_DATA, VSH_OFLAG_REQ, N_("connection URI of the destination host as seen from the client(normal migration) or source(p2p migration)")},
    {"migrateuri", VSH_OT_DATA, 0, N_("migration URI, usually can be omitted")},
    {"dname", VSH_OT_DATA, 0, N_("rename to new name during migration (if supported)")},
    {"timeout", VSH_OT_INT, 0, N_("force guest to suspend if live migration exceeds timeout (in seconds)")},
    {"xml", VSH_OT_STRING, 0, N_("filename containing updated XML for the target")},
    {NULL, 0, 0, NULL}
};

static void
doMigrate(void *opaque)
{
    char ret = '1';
    virDomainPtr dom = NULL;
    const char *desturi = NULL;
    const char *migrateuri = NULL;
    const char *dname = NULL;
    unsigned int flags = 0;
    vshCtrlData *data = opaque;
    vshControl *ctl = data->ctl;
    const vshCmd *cmd = data->cmd;
    const char *xmlfile = NULL;
    char *xml = NULL;
    sigset_t sigmask, oldsigmask;

    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);
    if (pthread_sigmask(SIG_BLOCK, &sigmask, &oldsigmask) < 0)
        goto out_sig;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto out;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        goto out;

    if (vshCommandOptString(cmd, "desturi", &desturi) <= 0 ||
        vshCommandOptString(cmd, "migrateuri", &migrateuri) < 0 ||
        vshCommandOptString(cmd, "dname", &dname) < 0) {
        vshError(ctl, "%s", _("missing argument"));
        goto out;
    }

    if (vshCommandOptString(cmd, "xml", &xmlfile) < 0) {
        vshError(ctl, "%s", _("malformed xml argument"));
        goto out;
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

    if (xmlfile &&
        virFileReadAll(xmlfile, 8192, &xml) < 0) {
        vshError(ctl, _("file '%s' doesn't exist"), xmlfile);
        goto out;
    }

    if ((flags & VIR_MIGRATE_PEER2PEER) ||
        vshCommandOptBool(cmd, "direct")) {
        /* For peer2peer migration or direct migration we only expect one URI
         * a libvirt URI, or a hypervisor specific URI. */

        if (migrateuri != NULL) {
            vshError(ctl, "%s", _("migrate: Unexpected migrateuri for peer2peer/direct migration"));
            goto out;
        }

        if (virDomainMigrateToURI2(dom, desturi, NULL, xml, flags, dname, 0) == 0)
            ret = '0';
    } else {
        /* For traditional live migration, connect to the destination host directly. */
        virConnectPtr dconn = NULL;
        virDomainPtr ddom = NULL;

        dconn = virConnectOpenAuth(desturi, virConnectAuthPtrDefault, 0);
        if (!dconn) goto out;

        ddom = virDomainMigrate2(dom, dconn, xml, flags, dname, migrateuri, 0);
        if (ddom) {
            virDomainFree(ddom);
            ret = '0';
        }
        virConnectClose(dconn);
    }

out:
    pthread_sigmask(SIG_SETMASK, &oldsigmask, NULL);
out_sig:
    if (dom) virDomainFree(dom);
    VIR_FREE(xml);
    ignore_value(safewrite(data->writefd, &ret, sizeof(ret)));
}

static void
vshMigrationTimeout(vshControl *ctl,
                    virDomainPtr dom,
                    void *opaque ATTRIBUTE_UNUSED)
{
    vshDebug(ctl, VSH_ERR_DEBUG, "suspending the domain, "
             "since migration timed out\n");
    virDomainSuspend(dom);
}

static bool
vshWatchJob(vshControl *ctl,
            virDomainPtr dom,
            bool verbose,
            int pipe_fd,
            int timeout,
            jobWatchTimeoutFunc timeout_func,
            void *opaque,
            const char *label)
{
    struct sigaction sig_action;
    struct sigaction old_sig_action;
    struct pollfd pollfd;
    struct timeval start, curr;
    virDomainJobInfo jobinfo;
    int ret = -1;
    char retchar;
    bool functionReturn = false;
    sigset_t sigmask, oldsigmask;

    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);

    intCaught = 0;
    sig_action.sa_sigaction = vshCatchInt;
    sig_action.sa_flags = SA_SIGINFO;
    sigemptyset(&sig_action.sa_mask);
    sigaction(SIGINT, &sig_action, &old_sig_action);

    pollfd.fd = pipe_fd;
    pollfd.events = POLLIN;
    pollfd.revents = 0;

    GETTIMEOFDAY(&start);
    while (1) {
repoll:
        ret = poll(&pollfd, 1, 500);
        if (ret > 0) {
            if (pollfd.revents & POLLIN &&
                saferead(pipe_fd, &retchar, sizeof(retchar)) > 0 &&
                retchar == '0') {
                if (verbose) {
                    /* print [100 %] */
                    print_job_progress(label, 0, 1);
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
                } else {
                    goto repoll;
                }
            }
            goto cleanup;
        }

        GETTIMEOFDAY(&curr);
        if (timeout && (((int)(curr.tv_sec - start.tv_sec)  * 1000 +
                         (int)(curr.tv_usec - start.tv_usec) / 1000) >
                        timeout * 1000)) {
            /* suspend the domain when migration timeouts. */
            vshDebug(ctl, VSH_ERR_DEBUG, "%s timeout", label);
            if (timeout_func)
                (timeout_func)(ctl, dom, opaque);
            timeout = 0;
        }

        if (verbose) {
            pthread_sigmask(SIG_BLOCK, &sigmask, &oldsigmask);
            ret = virDomainGetJobInfo(dom, &jobinfo);
            pthread_sigmask(SIG_SETMASK, &oldsigmask, NULL);
            if (ret == 0)
                print_job_progress(label, jobinfo.dataRemaining,
                                   jobinfo.dataTotal);
        }
    }

    functionReturn = true;

cleanup:
    sigaction(SIGINT, &old_sig_action, NULL);
    return functionReturn;
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
    bool live_flag = false;
    vshCtrlData data;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptBool(cmd, "verbose"))
        verbose = true;

    if (vshCommandOptBool(cmd, "live"))
        live_flag = true;
    if (vshCommandOptInt(cmd, "timeout", &timeout) > 0) {
        if (! live_flag) {
            vshError(ctl, "%s",
                     _("migrate: Unexpected timeout for offline migration"));
            goto cleanup;
        }

        if (timeout < 1) {
            vshError(ctl, "%s", _("migrate: Invalid timeout"));
            goto cleanup;
        }

        /* Ensure that we can multiply by 1000 without overflowing. */
        if (timeout > INT_MAX / 1000) {
            vshError(ctl, "%s", _("migrate: Timeout is too big"));
            goto cleanup;
        }
    }

    if (pipe(p) < 0)
        goto cleanup;

    data.ctl = ctl;
    data.cmd = cmd;
    data.writefd = p[1];

    if (virThreadCreate(&workerThread,
                        true,
                        doMigrate,
                        &data) < 0)
        goto cleanup;
    functionReturn = vshWatchJob(ctl, dom, verbose, p[0], timeout,
                                 vshMigrationTimeout, NULL, _("Migration"));

    virThreadJoin(&workerThread);

cleanup:
    virDomainFree(dom);
    VIR_FORCE_CLOSE(p[0]);
    VIR_FORCE_CLOSE(p[1]);
    return functionReturn;
}

/*
 * "migrate-setmaxdowntime" command
 */
static const vshCmdInfo info_migrate_setmaxdowntime[] = {
    {"help", N_("set maximum tolerable downtime")},
    {"desc", N_("Set maximum tolerable downtime of a domain which is being live-migrated to another host.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_migrate_setmaxdowntime[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"downtime", VSH_OT_INT, VSH_OFLAG_REQ, N_("maximum tolerable downtime (in milliseconds) for migration")},
    {NULL, 0, 0, NULL}
};

static bool
cmdMigrateSetMaxDowntime(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    long long downtime = 0;
    bool ret = false;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptLongLong(cmd, "downtime", &downtime) < 0 ||
        downtime < 1) {
        vshError(ctl, "%s", _("migrate: Invalid downtime"));
        goto done;
    }

    if (virDomainMigrateSetMaxDowntime(dom, downtime, 0))
        goto done;

    ret = true;

done:
    virDomainFree(dom);
    return ret;
}

/*
 * "migrate-setspeed" command
 */
static const vshCmdInfo info_migrate_setspeed[] = {
    {"help", N_("Set the maximum migration bandwidth")},
    {"desc", N_("Set the maximum migration bandwidth (in MiB/s) for a domain "
                "which is being migrated to another host.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_migrate_setspeed[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"bandwidth", VSH_OT_INT, VSH_OFLAG_REQ,
     N_("migration bandwidth limit in MiB/s")},
    {NULL, 0, 0, NULL}
};

static bool
cmdMigrateSetMaxSpeed(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    unsigned long bandwidth = 0;
    bool ret = false;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptUL(cmd, "bandwidth", &bandwidth) < 0) {
        vshError(ctl, "%s", _("migrate: Invalid bandwidth"));
        goto done;
    }

    if (virDomainMigrateSetMaxSpeed(dom, bandwidth, 0) < 0)
        goto done;

    ret = true;

done:
    virDomainFree(dom);
    return ret;
}

/*
 * "migrate-getspeed" command
 */
static const vshCmdInfo info_migrate_getspeed[] = {
    {"help", N_("Get the maximum migration bandwidth")},
    {"desc", N_("Get the maximum migration bandwidth (in MiB/s) for a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_migrate_getspeed[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdMigrateGetMaxSpeed(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    unsigned long bandwidth;
    bool ret = false;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virDomainMigrateGetMaxSpeed(dom, &bandwidth, 0) < 0)
        goto done;

    vshPrint(ctl, "%lu\n", bandwidth);

    ret = true;

done:
    virDomainFree(dom);
    return ret;
}

/*
 * "domdisplay" command
 */
static const vshCmdInfo info_domdisplay[] = {
    {"help", N_("domain display connection URI")},
    {"desc", N_("Output the IP address and port number for the graphical display.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domdisplay[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"include-password", VSH_OT_BOOL, VSH_OFLAG_NONE, N_("includes the password into the connection URI if available")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomDisplay(vshControl *ctl, const vshCmd *cmd)
{
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virDomainPtr dom;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    bool ret = false;
    char *doc;
    char *xpath;
    char *listen_addr;
    int port, tls_port = 0;
    char *passwd = NULL;
    char *output = NULL;
    const char *scheme[] = { "vnc", "spice", "rdp", NULL };
    int iter = 0;
    int tmp;
    int flags = 0;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (!virDomainIsActive(dom)) {
        vshError(ctl, _("Domain is not running"));
        goto cleanup;
    }

    if (vshCommandOptBool(cmd, "include-password"))
        flags |= VIR_DOMAIN_XML_SECURE;

    doc = virDomainGetXMLDesc(dom, flags);

    if (!doc)
        goto cleanup;

    xml = virXMLParseStringCtxt(doc, _("(domain_definition)"), &ctxt);
    VIR_FREE(doc);
    if (!xml)
        goto cleanup;

    /* Attempt to grab our display info */
    for (iter = 0; scheme[iter] != NULL; iter++) {
        /* Create our XPATH lookup for the current display's port */
        virAsprintf(&xpath, "string(/domain/devices/graphics[@type='%s']"
                "/@port)", scheme[iter]);
        if (!xpath) {
            virReportOOMError();
            goto cleanup;
        }

        /* Attempt to get the port number for the current graphics scheme */
        tmp = virXPathInt(xpath, ctxt, &port);
        VIR_FREE(xpath);

        /* If there is no port number for this type, then jump to the next
         * scheme
         */
        if (tmp)
            continue;

        /* Create our XPATH lookup for the current display's address */
        virAsprintf(&xpath, "string(/domain/devices/graphics[@type='%s']"
                "/@listen)", scheme[iter]);
        if (!xpath) {
            virReportOOMError();
            goto cleanup;
        }

        /* Attempt to get the listening addr if set for the current
         * graphics scheme
         */
        listen_addr = virXPathString(xpath, ctxt);
        VIR_FREE(xpath);

        /* Per scheme data mangling */
        if (STREQ(scheme[iter], "vnc")) {
            /* VNC protocol handlers take their port number as 'port' - 5900 */
            port -= 5900;
        } else if (STREQ(scheme[iter], "spice")) {
            /* Create our XPATH lookup for the SPICE TLS Port */
            virAsprintf(&xpath, "string(/domain/devices/graphics[@type='%s']"
                    "/@tlsPort)", scheme[iter]);
            if (!xpath) {
                virReportOOMError();
                goto cleanup;
            }

            /* Attempt to get the TLS port number for SPICE */
            tmp = virXPathInt(xpath, ctxt, &tls_port);
            VIR_FREE(xpath);
            if (tmp)
                tls_port = 0;

            if (vshCommandOptBool(cmd, "include-password")) {
                /* Create our XPATH lookup for the SPICE password */
                virAsprintf(&xpath, "string(/domain/devices/graphics"
                        "[@type='%s']/@passwd)", scheme[iter]);
                if (!xpath) {
                    virReportOOMError();
                    goto cleanup;
                }

                /* Attempt to get the SPICE password */
                passwd = virXPathString(xpath, ctxt);
                VIR_FREE(xpath);
            }
        }

        /* Build up the full URI, starting with the scheme */
        virBufferAsprintf(&buf, "%s://", scheme[iter]);

        /* Then host name or IP */
        if (!listen_addr || STREQ((const char *)listen_addr, "0.0.0.0"))
            virBufferAddLit(&buf, "localhost");
        else
            virBufferAsprintf(&buf, "%s", listen_addr);

        VIR_FREE(listen_addr);

        /* Add the port */
        if (STREQ(scheme[iter], "spice"))
            virBufferAsprintf(&buf, "?port=%d", port);
        else
            virBufferAsprintf(&buf, ":%d", port);

        /* TLS Port */
        if (tls_port)
            virBufferAsprintf(&buf, "&tls-port=%d", tls_port);

        /* Password */
        if (passwd) {
            virBufferAsprintf(&buf, "&password=%s", passwd);
            VIR_FREE(passwd);
        }

        /* Ensure we can print our URI */
        if (virBufferError(&buf)) {
            vshPrint(ctl, "%s", _("Failed to create display URI"));
            goto cleanup;
        }

        /* Print out our full URI */
        output = virBufferContentAndReset(&buf);
        vshPrint(ctl, "%s", output);
        VIR_FREE(output);

        /* We got what we came for so return successfully */
        ret = true;
        break;
    }

cleanup:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    virDomainFree(dom);
    return ret;
}

/*
 * "vncdisplay" command
 */
static const vshCmdInfo info_vncdisplay[] = {
    {"help", N_("vnc display")},
    {"desc", N_("Output the IP address and port number for the VNC display.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vncdisplay[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVNCDisplay(vshControl *ctl, const vshCmd *cmd)
{
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virDomainPtr dom;
    bool ret = false;
    int port = 0;
    char *doc = NULL;
    char *listen_addr = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    /* Check if the domain is active and don't rely on -1 for this */
    if (!virDomainIsActive(dom)) {
        vshError(ctl, _("Domain is not running"));
        goto cleanup;
    }

    if (!(doc = virDomainGetXMLDesc(dom, 0)))
        goto cleanup;

    if (!(xml = virXMLParseStringCtxt(doc, _("(domain_definition)"), &ctxt)))
        goto cleanup;

    /* Get the VNC port */
    if (virXPathInt("string(/domain/devices/graphics[@type='vnc']/@port)",
                    ctxt, &port)) {
        vshError(ctl, _("Failed to get VNC port. Is this domain using VNC?"));
        goto cleanup;
    }

    listen_addr = virXPathString("string(/domain/devices/graphics"
                                 "[@type='vnc']/@listen)", ctxt);
    if (listen_addr == NULL || STREQ(listen_addr, "0.0.0.0"))
        vshPrint(ctl, ":%d\n", port-5900);
    else
        vshPrint(ctl, "%s:%d\n", listen_addr, port-5900);

    ret = true;

 cleanup:
    VIR_FREE(doc);
    VIR_FREE(listen_addr);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    virDomainFree(dom);
    return ret;
}

/*
 * "ttyconsole" command
 */
static const vshCmdInfo info_ttyconsole[] = {
    {"help", N_("tty console")},
    {"desc", N_("Output the device for the TTY console.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_ttyconsole[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdTTYConsole(vshControl *ctl, const vshCmd *cmd)
{
    xmlDocPtr xml = NULL;
    xmlXPathObjectPtr obj = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virDomainPtr dom;
    bool ret = false;
    char *doc;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    doc = virDomainGetXMLDesc(dom, 0);
    if (!doc)
        goto cleanup;

    xml = virXMLParseStringCtxt(doc, _("(domain_definition)"), &ctxt);
    VIR_FREE(doc);
    if (!xml)
        goto cleanup;

    obj = xmlXPathEval(BAD_CAST "string(/domain/devices/console/@tty)", ctxt);
    if (obj == NULL || obj->type != XPATH_STRING ||
        obj->stringval == NULL || obj->stringval[0] == 0) {
        goto cleanup;
    }
    vshPrint(ctl, "%s\n", (const char *)obj->stringval);
    ret = true;

 cleanup:
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    virDomainFree(dom);
    return ret;
}

/*
 * "domhostname" command
 */
static const vshCmdInfo info_domhostname[] = {
    {"help", N_("print the domain's hostname")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domhostname[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomHostname(vshControl *ctl, const vshCmd *cmd)
{
    char *hostname;
    virDomainPtr dom;
    bool ret = false;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
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
    virDomainFree(dom);
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
vshNodeIsSuperset(xmlNodePtr n1, xmlNodePtr n2)
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

    if (!(bitmap = virBitmapAlloc(n1_child_size))) {
        virReportOOMError();
        return false;
    }

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

                if (!vshNodeIsSuperset(child1, child2))
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

/**
 * vshCompleteXMLFromDomain:
 * @ctl vshControl for error messages printing
 * @dom domain
 * @oldXML device XML before
 * @newXML and after completion
 *
 * For given domain and (probably incomplete) device XML specification try to
 * find such device in domain and complete missing parts. This is however
 * possible only when given device XML is sufficiently precise so it addresses
 * only one device.
 *
 * Returns -2 when no such device exists in domain, -3 when given XML selects many
 *          (is too ambiguous), 0 in case of success. Otherwise returns -1. @newXML
 *          is touched only in case of success.
 */
ATTRIBUTE_UNUSED
static int
vshCompleteXMLFromDomain(vshControl *ctl, virDomainPtr dom, char *oldXML,
                         char **newXML)
{
    int funcRet = -1;
    char *domXML = NULL;
    xmlDocPtr domDoc = NULL, devDoc = NULL;
    xmlNodePtr node = NULL;
    xmlXPathContextPtr domCtxt = NULL, devCtxt = NULL;
    xmlNodePtr *devices = NULL;
    xmlSaveCtxtPtr sctxt = NULL;
    int devices_size;
    char *xpath = NULL;
    xmlBufferPtr buf = NULL;
    int i = 0;
    int indx = -1;

    if (!(domXML = virDomainGetXMLDesc(dom, 0))) {
        vshError(ctl, _("couldn't get XML description of domain %s"),
                 virDomainGetName(dom));
        goto cleanup;
    }

    domDoc = virXMLParseStringCtxt(domXML, _("(domain_definition)"), &domCtxt);
    if (!domDoc) {
        vshError(ctl, _("Failed to parse domain definition xml"));
        goto cleanup;
    }

    devDoc = virXMLParseStringCtxt(oldXML, _("(device_definition)"), &devCtxt);
    if (!devDoc) {
        vshError(ctl, _("Failed to parse device definition xml"));
        goto cleanup;
    }

    node = xmlDocGetRootElement(devDoc);

    buf = xmlBufferCreate();
    if (!buf) {
        vshError(ctl, "%s", _("out of memory"));
        goto cleanup;
    }

    /* Get all possible devices */
    virAsprintf(&xpath, "/domain/devices/%s", node->name);
    if (!xpath) {
        virReportOOMError();
        goto cleanup;
    }
    devices_size = virXPathNodeSet(xpath, domCtxt, &devices);

    if (devices_size < 0) {
        /* error */
        vshError(ctl, "%s", _("error when selecting nodes"));
        goto cleanup;
    } else if (devices_size == 0) {
        /* no such device */
        funcRet = -2;
        goto cleanup;
    }

    /* and refine */
    for (i = 0; i < devices_size; i++) {
        if (vshNodeIsSuperset(devices[i], node)) {
            if (indx >= 0) {
                funcRet = -3; /* ambiguous */
                goto cleanup;
            }
            indx = i;
        }
    }

    if (indx < 0) {
        funcRet = -2; /* no such device */
        goto cleanup;
    }

    vshDebug(ctl, VSH_ERR_DEBUG, "Found device at pos %d\n", indx);

    if (newXML) {
        sctxt = xmlSaveToBuffer(buf, NULL, 0);
        if (!sctxt) {
            vshError(ctl, "%s", _("failed to create document saving context"));
            goto cleanup;
        }

        xmlSaveTree(sctxt, devices[indx]);
        xmlSaveClose(sctxt);
        *newXML = (char *) xmlBufferContent(buf);
        if (!*newXML) {
            virReportOOMError();
            goto cleanup;
        }
        buf->content = NULL;
    }

    vshDebug(ctl, VSH_ERR_DEBUG, "Old xml:\n%s\nNew xml:\n%s\n", oldXML,
             newXML ? NULLSTR(*newXML) : "(null)");

    funcRet = 0;

cleanup:
    xmlBufferFree(buf);
    VIR_FREE(devices);
    xmlXPathFreeContext(devCtxt);
    xmlXPathFreeContext(domCtxt);
    xmlFreeDoc(devDoc);
    xmlFreeDoc(domDoc);
    VIR_FREE(domXML);
    VIR_FREE(xpath);
    return funcRet;
}

/*
 * "detach-device" command
 */
static const vshCmdInfo info_detach_device[] = {
    {"help", N_("detach device from an XML file")},
    {"desc", N_("Detach device from an XML <file>")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_detach_device[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"file",   VSH_OT_DATA, VSH_OFLAG_REQ, N_("XML file")},
    {"persistent", VSH_OT_ALIAS, 0, "config"},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDetachDevice(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    const char *from = NULL;
    char *buffer = NULL;
    int ret;
    bool funcRet = false;
    unsigned int flags;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0)
        goto cleanup;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0) {
        virshReportError(ctl);
        goto cleanup;
    }

    if (vshCommandOptBool(cmd, "config")) {
        flags = VIR_DOMAIN_AFFECT_CONFIG;
        if (virDomainIsActive(dom) == 1)
           flags |= VIR_DOMAIN_AFFECT_LIVE;
        ret = virDomainDetachDeviceFlags(dom, buffer, flags);
    } else {
        ret = virDomainDetachDevice(dom, buffer);
    }

    if (ret < 0) {
        vshError(ctl, _("Failed to detach device from %s"), from);
        goto cleanup;
    }

    vshPrint(ctl, "%s", _("Device detached successfully\n"));
    funcRet = true;

cleanup:
    VIR_FREE(buffer);
    virDomainFree(dom);
    return funcRet;
}

/*
 * "update-device" command
 */
static const vshCmdInfo info_update_device[] = {
    {"help", N_("update device from an XML file")},
    {"desc", N_("Update device from an XML <file>.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_update_device[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"file",   VSH_OT_DATA, VSH_OFLAG_REQ, N_("XML file")},
    {"persistent", VSH_OT_ALIAS, 0, "config"},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {"force",  VSH_OT_BOOL, 0, N_("force device update")},
    {NULL, 0, 0, NULL}
};

static bool
cmdUpdateDevice(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *from = NULL;
    char *buffer;
    int ret;
    unsigned int flags;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0) {
        virDomainFree(dom);
        return false;
    }

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0) {
        virshReportError(ctl);
        virDomainFree(dom);
        return false;
    }

    if (vshCommandOptBool(cmd, "config")) {
        flags = VIR_DOMAIN_AFFECT_CONFIG;
        if (virDomainIsActive(dom) == 1)
           flags |= VIR_DOMAIN_AFFECT_LIVE;
    } else {
        flags = VIR_DOMAIN_AFFECT_LIVE;
    }

    if (vshCommandOptBool(cmd, "force"))
        flags |= VIR_DOMAIN_DEVICE_MODIFY_FORCE;

    ret = virDomainUpdateDeviceFlags(dom, buffer, flags);
    VIR_FREE(buffer);

    if (ret < 0) {
        vshError(ctl, _("Failed to update device from %s"), from);
        virDomainFree(dom);
        return false;
    } else {
        vshPrint(ctl, "%s", _("Device updated successfully\n"));
    }

    virDomainFree(dom);
    return true;
}

/*
 * "detach-interface" command
 */
static const vshCmdInfo info_detach_interface[] = {
    {"help", N_("detach network interface")},
    {"desc", N_("Detach network interface.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_detach_interface[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"type",   VSH_OT_DATA, VSH_OFLAG_REQ, N_("network interface type")},
    {"mac",    VSH_OT_STRING, 0, N_("MAC address")},
    {"persistent", VSH_OT_ALIAS, 0, "config"},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDetachInterface(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    xmlDocPtr xml = NULL;
    xmlXPathObjectPtr obj=NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr cur = NULL;
    xmlBufferPtr xml_buf = NULL;
    const char *mac =NULL, *type = NULL;
    char *doc;
    char buf[64];
    int i = 0, diff_mac;
    int ret;
    int functionReturn = false;
    unsigned int flags;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        goto cleanup;

    if (vshCommandOptString(cmd, "type", &type) <= 0)
        goto cleanup;

    if (vshCommandOptString(cmd, "mac", &mac) < 0) {
        vshError(ctl, "%s", _("missing option"));
        goto cleanup;
    }

    doc = virDomainGetXMLDesc(dom, 0);
    if (!doc)
        goto cleanup;

    xml = virXMLParseStringCtxt(doc, _("(domain_definition)"), &ctxt);
    VIR_FREE(doc);
    if (!xml) {
        vshError(ctl, "%s", _("Failed to get interface information"));
        goto cleanup;
    }

    snprintf(buf, sizeof(buf), "/domain/devices/interface[@type='%s']", type);
    obj = xmlXPathEval(BAD_CAST buf, ctxt);
    if (obj == NULL || obj->type != XPATH_NODESET ||
        obj->nodesetval == NULL || obj->nodesetval->nodeNr == 0) {
        vshError(ctl, _("No found interface whose type is %s"), type);
        goto cleanup;
    }

    if (!mac && obj->nodesetval->nodeNr > 1) {
        vshError(ctl, _("Domain has %d interfaces. Please specify which one "
                        "to detach using --mac"), obj->nodesetval->nodeNr);
        goto cleanup;
    }

    if (!mac)
        goto hit;

    /* search mac */
    for (; i < obj->nodesetval->nodeNr; i++) {
        cur = obj->nodesetval->nodeTab[i]->children;
        while (cur != NULL) {
            if (cur->type == XML_ELEMENT_NODE &&
                xmlStrEqual(cur->name, BAD_CAST "mac")) {
                char *tmp_mac = virXMLPropString(cur, "address");
                diff_mac = virMacAddrCompare(tmp_mac, mac);
                VIR_FREE(tmp_mac);
                if (!diff_mac) {
                    goto hit;
                }
            }
            cur = cur->next;
        }
    }
    vshError(ctl, _("No found interface whose MAC address is %s"), mac);
    goto cleanup;

 hit:
    xml_buf = xmlBufferCreate();
    if (!xml_buf) {
        vshError(ctl, "%s", _("Failed to allocate memory"));
        goto cleanup;
    }

    if (xmlNodeDump(xml_buf, xml, obj->nodesetval->nodeTab[i], 0, 0) < 0) {
        vshError(ctl, "%s", _("Failed to create XML"));
        goto cleanup;
    }

    if (vshCommandOptBool(cmd, "config")) {
        flags = VIR_DOMAIN_AFFECT_CONFIG;
        if (virDomainIsActive(dom) == 1)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
        ret = virDomainDetachDeviceFlags(dom,
                                         (char *)xmlBufferContent(xml_buf),
                                         flags);
    } else {
        ret = virDomainDetachDevice(dom, (char *)xmlBufferContent(xml_buf));
    }

    if (ret != 0) {
        vshError(ctl, "%s", _("Failed to detach interface"));
    } else {
        vshPrint(ctl, "%s", _("Interface detached successfully\n"));
        functionReturn = true;
    }

 cleanup:
    if (dom)
        virDomainFree(dom);
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    xmlBufferFree(xml_buf);
    return functionReturn;
}

typedef enum {
    VSH_FIND_DISK_NORMAL,
    VSH_FIND_DISK_CHANGEABLE,
} vshFindDiskType;

/* Helper function to find disk device in XML doc.  Returns the disk
 * node on success, or NULL on failure. Caller must free the result
 * @path: Fully-qualified path or target of disk device.
 * @type: Either VSH_FIND_DISK_NORMAL or VSH_FIND_DISK_CHANGEABLE.
 */
static xmlNodePtr
vshFindDisk(const char *doc,
            const char *path,
            int type)
{
    xmlDocPtr xml = NULL;
    xmlXPathObjectPtr obj= NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr cur = NULL;
    xmlNodePtr ret = NULL;
    int i = 0;

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
    for (; i < obj->nodesetval->nodeNr; i++) {
        bool is_supported = true;

        if (type == VSH_FIND_DISK_CHANGEABLE) {
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

    vshError(NULL, _("No found disk whose source path or target is %s"), path);

cleanup:
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    return ret;
}

typedef enum {
    VSH_PREPARE_DISK_XML_NONE = 0,
    VSH_PREPARE_DISK_XML_EJECT,
    VSH_PREPARE_DISK_XML_INSERT,
    VSH_PREPARE_DISK_XML_UPDATE,
} vshPrepareDiskXMLType;

/* Helper function to prepare disk XML. Could be used for disk
 * detaching, media changing(ejecting, inserting, updating)
 * for changeable disk. Returns the processed XML as string on
 * success, or NULL on failure. Caller must free the result.
 */
static char *
vshPrepareDiskXML(xmlNodePtr disk_node,
                  const char *source,
                  const char *path,
                  int type)
{
    xmlNodePtr cur = NULL;
    xmlBufferPtr xml_buf = NULL;
    const char *disk_type = NULL;
    const char *device_type = NULL;
    xmlNodePtr new_node = NULL;
    char *ret = NULL;

    if (!disk_node)
        return NULL;

    xml_buf = xmlBufferCreate();
    if (!xml_buf) {
        vshError(NULL, "%s", _("Failed to allocate memory"));
        return NULL;
    }

    device_type = virXMLPropString(disk_node, "device");

    if (STREQ_NULLABLE(device_type, "cdrom") ||
        STREQ_NULLABLE(device_type, "floppy")) {
        bool has_source = false;
        disk_type = virXMLPropString(disk_node, "type");

        cur = disk_node->children;
        while (cur != NULL) {
            if (cur->type == XML_ELEMENT_NODE &&
                xmlStrEqual(cur->name, BAD_CAST "source")) {
                has_source = true;
                break;
            }
            cur = cur->next;
        }

        if (!has_source) {
            if (type == VSH_PREPARE_DISK_XML_EJECT) {
                vshError(NULL, _("The disk device '%s' doesn't have media"),
                         path);
                goto error;
            }

            if (source) {
                new_node = xmlNewNode(NULL, BAD_CAST "source");
                xmlNewProp(new_node, (const xmlChar *)disk_type,
                           (const xmlChar *)source);
                xmlAddChild(disk_node, new_node);
            } else if (type == VSH_PREPARE_DISK_XML_INSERT) {
                vshError(NULL, _("No source is specified for inserting media"));
                goto error;
            } else if (type == VSH_PREPARE_DISK_XML_UPDATE) {
                vshError(NULL, _("No source is specified for updating media"));
                goto error;
            }
        }

        if (has_source) {
            if (type == VSH_PREPARE_DISK_XML_INSERT) {
                vshError(NULL, _("The disk device '%s' already has media"),
                         path);
                goto error;
            }

            /* Remove the source if it tends to eject/update media. */
            xmlUnlinkNode(cur);
            xmlFreeNode(cur);

            if (source && (type == VSH_PREPARE_DISK_XML_UPDATE)) {
                new_node = xmlNewNode(NULL, BAD_CAST "source");
                xmlNewProp(new_node, (const xmlChar *)disk_type,
                           (const xmlChar *)source);
                xmlAddChild(disk_node, new_node);
            }
        }
    }

    if (xmlNodeDump(xml_buf, NULL, disk_node, 0, 0) < 0) {
        vshError(NULL, "%s", _("Failed to create XML"));
        goto error;
    }

    goto cleanup;

cleanup:
    VIR_FREE(device_type);
    VIR_FREE(disk_type);
    if (xml_buf) {
        int len = xmlBufferLength(xml_buf);
        if (VIR_ALLOC_N(ret, len + 1) < 0) {
            virReportOOMError();
            return NULL;
        }
        memcpy(ret, (char *)xmlBufferContent(xml_buf), len);
        ret[len] = '\0';
        xmlBufferFree(xml_buf);
    }
    return ret;

error:
    xmlBufferFree(xml_buf);
    xml_buf = NULL;
    goto cleanup;
}


/*
 * "detach-disk" command
 */
static const vshCmdInfo info_detach_disk[] = {
    {"help", N_("detach disk device")},
    {"desc", N_("Detach disk device.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_detach_disk[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"target", VSH_OT_DATA, VSH_OFLAG_REQ, N_("target of disk device")},
    {"persistent", VSH_OT_ALIAS, 0, "config"},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {NULL, 0, 0, NULL}
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
    unsigned int flags;
    xmlNodePtr disk_node = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        goto cleanup;

    if (vshCommandOptString(cmd, "target", &target) <= 0)
        goto cleanup;

    doc = virDomainGetXMLDesc(dom, 0);
    if (!doc)
        goto cleanup;

    if (!(disk_node = vshFindDisk(doc, target, VSH_FIND_DISK_NORMAL)))
        goto cleanup;

    if (!(disk_xml = vshPrepareDiskXML(disk_node, NULL, NULL,
                                       VSH_PREPARE_DISK_XML_NONE)))
        goto cleanup;

    if (vshCommandOptBool(cmd, "config")) {
        flags = VIR_DOMAIN_AFFECT_CONFIG;
        if (virDomainIsActive(dom) == 1)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
        ret = virDomainDetachDeviceFlags(dom,
                                         disk_xml,
                                         flags);
    } else {
        ret = virDomainDetachDevice(dom, disk_xml);
    }

    if (ret != 0) {
        vshError(ctl, "%s", _("Failed to detach disk"));
    } else {
        vshPrint(ctl, "%s", _("Disk detached successfully\n"));
        functionReturn = true;
    }

 cleanup:
    xmlFreeNode(disk_node);
    VIR_FREE(disk_xml);
    VIR_FREE(doc);
    if (dom)
        virDomainFree(dom);
    return functionReturn;
}

/*
 * "edit" command
 */
static const vshCmdInfo info_edit[] = {
    {"help", N_("edit XML configuration for a domain")},
    {"desc", N_("Edit the XML configuration for a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_edit[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdEdit(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    virDomainPtr dom = NULL;
    virDomainPtr dom_edited = NULL;
    unsigned int flags = VIR_DOMAIN_XML_SECURE | VIR_DOMAIN_XML_INACTIVE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    dom = vshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

#define EDIT_GET_XML virDomainGetXMLDesc(dom, flags)
#define EDIT_NOT_CHANGED \
    vshPrint(ctl, _("Domain %s XML configuration not changed.\n"),  \
             virDomainGetName(dom));                                \
    ret = true; goto edit_cleanup;
#define EDIT_DEFINE \
    (dom_edited = virDomainDefineXML(ctl->conn, doc_edited))
#define EDIT_FREE \
    if (dom_edited) \
        virDomainFree(dom_edited);
#include "virsh-edit.c"

    vshPrint(ctl, _("Domain %s XML configuration edited.\n"),
             virDomainGetName(dom_edited));

    ret = true;

 cleanup:
    if (dom)
        virDomainFree(dom);
    if (dom_edited)
        virDomainFree(dom_edited);

    return ret;
}

/*
 * "change-media" command
 */
static const vshCmdInfo info_change_media[] = {
    {"help", N_("Change media of CD or floppy drive")},
    {"desc", N_("Change media of CD or floppy drive.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_change_media[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"path", VSH_OT_DATA, VSH_OFLAG_REQ, N_("Fully-qualified path or "
                                            "target of disk device")},
    {"source", VSH_OT_DATA, 0, N_("source of the media")},
    {"eject", VSH_OT_BOOL, 0, N_("Eject the media")},
    {"insert", VSH_OT_BOOL, 0, N_("Insert the media")},
    {"update", VSH_OT_BOOL, 0, N_("Update the media")},
    {"current", VSH_OT_BOOL, 0, N_("can be either or both of --live and --config, "
                                   "depends on implementation of hypervisor driver")},
    {"live", VSH_OT_BOOL, 0, N_("alter live configuration of running domain")},
    {"config", VSH_OT_BOOL, 0, N_("alter persistent configuration, effect observed on next boot")},
    {"force",  VSH_OT_BOOL, 0, N_("force media insertion")},
    {NULL, 0, 0, NULL}
};

static bool
cmdChangeMedia(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    const char *source = NULL;
    const char *path = NULL;
    const char *doc = NULL;
    xmlNodePtr disk_node = NULL;
    const char *disk_xml = NULL;
    int flags = 0;
    bool config, live, current, force = false;
    bool eject, insert, update = false;
    bool ret = false;
    int prepare_type = 0;
    const char *action = NULL;

    config = vshCommandOptBool(cmd, "config");
    live = vshCommandOptBool(cmd, "live");
    current = vshCommandOptBool(cmd, "current");
    force = vshCommandOptBool(cmd, "force");
    eject = vshCommandOptBool(cmd, "eject");
    insert = vshCommandOptBool(cmd, "insert");
    update = vshCommandOptBool(cmd, "update");

    if (eject + insert + update > 1) {
        vshError(ctl, "%s", _("--eject, --insert, and --update must be specified "
                            "exclusively."));
        return false;
    }

    if (eject) {
        prepare_type = VSH_PREPARE_DISK_XML_EJECT;
        action = "eject";
    }

    if (insert) {
        prepare_type = VSH_PREPARE_DISK_XML_INSERT;
        action = "insert";
    }

    if (update || (!eject && !insert)) {
        prepare_type = VSH_PREPARE_DISK_XML_UPDATE;
        action = "update";
    }

    if (current) {
        if (live || config) {
            vshError(ctl, "%s", _("--current must be specified exclusively"));
            return false;
        }
        flags = VIR_DOMAIN_AFFECT_CURRENT;
    } else {
        if (config)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        if (live)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
    }

    if (force)
        flags |= VIR_DOMAIN_DEVICE_MODIFY_FORCE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        goto cleanup;

    if (vshCommandOptString(cmd, "path", &path) <= 0)
        goto cleanup;

    if (vshCommandOptString(cmd, "source", &source) < 0)
        goto cleanup;

    if (insert && !source) {
        vshError(ctl, "%s", _("No disk source specified for inserting"));
        goto cleanup;
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG)
        doc = virDomainGetXMLDesc(dom, VIR_DOMAIN_XML_INACTIVE);
    else
        doc = virDomainGetXMLDesc(dom, 0);
    if (!doc)
        goto cleanup;

    if (!(disk_node = vshFindDisk(doc, path, VSH_FIND_DISK_CHANGEABLE)))
        goto cleanup;

    if (!(disk_xml = vshPrepareDiskXML(disk_node, source, path, prepare_type)))
        goto cleanup;

    if (virDomainUpdateDeviceFlags(dom, disk_xml, flags) != 0) {
        vshError(ctl, _("Failed to complete action %s on media"), action);
        goto cleanup;
    }

    vshPrint(ctl, _("succeeded to complete action %s on media\n"), action);
    ret = true;

cleanup:
    VIR_FREE(doc);
    xmlFreeNode(disk_node);
    VIR_FREE(disk_xml);
    if (dom)
        virDomainFree(dom);
    return ret;
}

static const vshCmdDef domManagementCmds[] = {
    {"attach-device", cmdAttachDevice, opts_attach_device,
     info_attach_device, 0},
    {"attach-disk", cmdAttachDisk, opts_attach_disk,
     info_attach_disk, 0},
    {"attach-interface", cmdAttachInterface, opts_attach_interface,
     info_attach_interface, 0},
    {"autostart", cmdAutostart, opts_autostart, info_autostart, 0},
    {"blkdeviotune", cmdBlkdeviotune, opts_blkdeviotune, info_blkdeviotune, 0},
    {"blkiotune", cmdBlkiotune, opts_blkiotune, info_blkiotune, 0},
    {"blockcopy", cmdBlockCopy, opts_block_copy, info_block_copy, 0},
    {"blockjob", cmdBlockJob, opts_block_job, info_block_job, 0},
    {"blockpull", cmdBlockPull, opts_block_pull, info_block_pull, 0},
    {"blockresize", cmdBlockResize, opts_block_resize, info_block_resize, 0},
    {"change-media", cmdChangeMedia, opts_change_media, info_change_media, 0},
#ifndef WIN32
    {"console", cmdConsole, opts_console, info_console, 0},
#endif
    {"cpu-baseline", cmdCPUBaseline, opts_cpu_baseline, info_cpu_baseline, 0},
    {"cpu-compare", cmdCPUCompare, opts_cpu_compare, info_cpu_compare, 0},
    {"cpu-stats", cmdCPUStats, opts_cpu_stats, info_cpu_stats, 0},
    {"create", cmdCreate, opts_create, info_create, 0},
    {"define", cmdDefine, opts_define, info_define, 0},
    {"desc", cmdDesc, opts_desc, info_desc, 0},
    {"destroy", cmdDestroy, opts_destroy, info_destroy, 0},
    {"detach-device", cmdDetachDevice, opts_detach_device,
     info_detach_device, 0},
    {"detach-disk", cmdDetachDisk, opts_detach_disk, info_detach_disk, 0},
    {"detach-interface", cmdDetachInterface, opts_detach_interface,
     info_detach_interface, 0},
    {"domdisplay", cmdDomDisplay, opts_domdisplay, info_domdisplay, 0},
    {"domhostname", cmdDomHostname, opts_domhostname, info_domhostname, 0},
    {"domid", cmdDomid, opts_domid, info_domid, 0},
    {"domif-setlink", cmdDomIfSetLink, opts_domif_setlink, info_domif_setlink, 0},
    {"domiftune", cmdDomIftune, opts_domiftune, info_domiftune, 0},
    {"domjobabort", cmdDomjobabort, opts_domjobabort, info_domjobabort, 0},
    {"domjobinfo", cmdDomjobinfo, opts_domjobinfo, info_domjobinfo, 0},
    {"domname", cmdDomname, opts_domname, info_domname, 0},
    {"dompmsuspend", cmdDomPMSuspend,
     opts_dom_pm_suspend, info_dom_pm_suspend, 0},
    {"dompmwakeup", cmdDomPMWakeup,
     opts_dom_pm_wakeup, info_dom_pm_wakeup, 0},
    {"domuuid", cmdDomuuid, opts_domuuid, info_domuuid, 0},
    {"domxml-from-native", cmdDomXMLFromNative, opts_domxmlfromnative,
     info_domxmlfromnative, 0},
    {"domxml-to-native", cmdDomXMLToNative, opts_domxmltonative,
     info_domxmltonative, 0},
    {"dump", cmdDump, opts_dump, info_dump, 0},
    {"dumpxml", cmdDumpXML, opts_dumpxml, info_dumpxml, 0},
    {"edit", cmdEdit, opts_edit, info_edit, 0},
    {"inject-nmi", cmdInjectNMI, opts_inject_nmi, info_inject_nmi, 0},
    {"send-key", cmdSendKey, opts_send_key, info_send_key, 0},
    {"managedsave", cmdManagedSave, opts_managedsave, info_managedsave, 0},
    {"managedsave-remove", cmdManagedSaveRemove, opts_managedsaveremove,
     info_managedsaveremove, 0},
    {"maxvcpus", cmdMaxvcpus, opts_maxvcpus, info_maxvcpus, 0},
    {"memtune", cmdMemtune, opts_memtune, info_memtune, 0},
    {"migrate", cmdMigrate, opts_migrate, info_migrate, 0},
    {"migrate-setmaxdowntime", cmdMigrateSetMaxDowntime,
     opts_migrate_setmaxdowntime, info_migrate_setmaxdowntime, 0},
    {"migrate-setspeed", cmdMigrateSetMaxSpeed,
     opts_migrate_setspeed, info_migrate_setspeed, 0},
    {"migrate-getspeed", cmdMigrateGetMaxSpeed,
     opts_migrate_getspeed, info_migrate_getspeed, 0},
    {"numatune", cmdNumatune, opts_numatune, info_numatune, 0},
    {"reboot", cmdReboot, opts_reboot, info_reboot, 0},
    {"reset", cmdReset, opts_reset, info_reset, 0},
    {"restore", cmdRestore, opts_restore, info_restore, 0},
    {"resume", cmdResume, opts_resume, info_resume, 0},
    {"save", cmdSave, opts_save, info_save, 0},
    {"save-image-define", cmdSaveImageDefine, opts_save_image_define,
     info_save_image_define, 0},
    {"save-image-dumpxml", cmdSaveImageDumpxml, opts_save_image_dumpxml,
     info_save_image_dumpxml, 0},
    {"save-image-edit", cmdSaveImageEdit, opts_save_image_edit,
     info_save_image_edit, 0},
    {"schedinfo", cmdSchedinfo, opts_schedinfo, info_schedinfo, 0},
    {"screenshot", cmdScreenshot, opts_screenshot, info_screenshot, 0},
    {"setmaxmem", cmdSetmaxmem, opts_setmaxmem, info_setmaxmem, 0},
    {"setmem", cmdSetmem, opts_setmem, info_setmem, 0},
    {"setvcpus", cmdSetvcpus, opts_setvcpus, info_setvcpus, 0},
    {"shutdown", cmdShutdown, opts_shutdown, info_shutdown, 0},
    {"start", cmdStart, opts_start, info_start, 0},
    {"suspend", cmdSuspend, opts_suspend, info_suspend, 0},
    {"ttyconsole", cmdTTYConsole, opts_ttyconsole, info_ttyconsole, 0},
    {"undefine", cmdUndefine, opts_undefine, info_undefine, 0},
    {"update-device", cmdUpdateDevice, opts_update_device,
     info_update_device, 0},
    {"vcpucount", cmdVcpucount, opts_vcpucount, info_vcpucount, 0},
    {"vcpuinfo", cmdVcpuinfo, opts_vcpuinfo, info_vcpuinfo, 0},
    {"vcpupin", cmdVcpuPin, opts_vcpupin, info_vcpupin, 0},
    {"vncdisplay", cmdVNCDisplay, opts_vncdisplay, info_vncdisplay, 0},
    {NULL, NULL, NULL, NULL, 0}
};
