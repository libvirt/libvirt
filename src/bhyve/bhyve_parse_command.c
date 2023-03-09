/*
 * bhyve_parse_command.c: Bhyve command parser
 *
 * Copyright (C) 2006-2016 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
 * Copyright (c) 2011 NetApp, Inc.
 * Copyright (C) 2020 Fabian Freyer
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
#include <libutil.h>

#include "bhyve_capabilities.h"
#include "bhyve_command.h"
#include "bhyve_parse_command.h"
#include "viralloc.h"
#include "virlog.h"
#include "virstring.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_BHYVE

VIR_LOG_INIT("bhyve.bhyve_parse_command");

/*
 * This function takes a string representation of the command line and removes
 * all newline characters, if they are prefixed by a backslash. The result
 * should be a string with one command per line.
 *
 * NB: command MUST be NULL-Terminated.
 */
static char *
bhyveParseCommandLineUnescape(const char *command)
{
    size_t len = strlen(command);
    char *unescaped = NULL;
    char *curr_src = NULL;
    char *curr_dst = NULL;

    /* Since we are only removing characters, allocating a buffer of the same
     * size as command shouldn't be a problem here */
    unescaped = g_new0(char, len + 1);

    /* Iterate over characters in the command, skipping "\\\n", "\\\r" as well
     * as "\\\r\n". */
    for (curr_src = (char*) command, curr_dst = unescaped; *curr_src != '\0';
        curr_src++, curr_dst++) {
        if (*curr_src == '\\') {
            switch (*(curr_src + 1)) {
                case '\n': /* \LF */
                    curr_src++;
                    curr_dst--;
                    break;
                case '\r': /* \CR */
                    curr_src++;
                    curr_dst--;
                    if (*curr_src == '\n') /* \CRLF */
                        curr_src++;
                    break;
                default:
                    *curr_dst = '\\';
            }
        } else {
            *curr_dst = *curr_src;
        }
    }

    return unescaped;
}

/*
 * This function is adapted from vm_parse_memsize in
 * /lib/libvmmapi/vmmapi.c in the FreeBSD Source tree.
 */
static int
bhyveParseMemsize(const char *arg, size_t *ret_memsize)
{
    size_t val;
    int error;

    if (virStrToLong_ul(arg, NULL, 10, &val) == 0) {
        /*
         * For the sake of backward compatibility if the memory size
         * specified on the command line is less than a megabyte then
         * it is interpreted as being in units of MB.
         */
        if (val < 1024 * 1024UL)
            val *= 1024 * 1024UL;
        *ret_memsize = val;
        error = 0;
    } else {
        error = expand_number(arg, ret_memsize);
    }

    /* use memory in KiB here */
    *ret_memsize /= 1024UL;

    return error;
}

/*
 * Try to extract loader and bhyve argv lists from a command line string.
 */
static int
bhyveCommandLineToArgv(const char *nativeConfig,
                      int *loader_argc,
                      char ***loader_argv,
                      int *bhyve_argc,
                      char ***bhyve_argv)
{
    const char *curr = NULL;
    char *nativeConfig_unescaped = NULL;
    const char *start;
    const char *next;
    char *line;
    g_auto(GStrv) lines = NULL;
    size_t i;
    size_t line_count = 0;
    size_t lines_alloc = 0;
    char **_bhyve_argv = NULL;
    char **_loader_argv = NULL;

    nativeConfig_unescaped = bhyveParseCommandLineUnescape(nativeConfig);
    if (nativeConfig_unescaped == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to unescape command line string"));
        goto error;
    }

    curr = nativeConfig_unescaped;

    /* Iterate over string, splitting on sequences of '\n' */
    while (curr && *curr != '\0') {
        start = curr;
        next = strchr(curr, '\n');

        if (next)
            line = g_strndup(curr, next - curr);
        else
            line = g_strdup(curr);

        VIR_RESIZE_N(lines, lines_alloc, line_count, 2);

        if (*line)
            lines[line_count++] = line;
        lines[line_count] = NULL;

        while (next && (*next == '\n' || *next == '\r'
                        || STRPREFIX(next, "\r\n")))
            next++;

        curr = next;
    }

    for (i = 0; i < line_count; i++) {
        size_t j;
        g_auto(GStrv) arglist = NULL;
        size_t args_count = 0;
        size_t args_alloc = 0;

        curr = lines[i];

        /* iterate over each line, splitting on sequences of ' '. This code is
         * adapted from qemu/qemu_parse_command.c. */
        while (curr && *curr != '\0') {
            char *arg;
            start = curr;

            if (*start == '\'') {
                if (start == curr)
                    curr++;
                next = strchr(start + 1, '\'');
            } else if (*start == '"') {
                if (start == curr)
                    curr++;
                next = strchr(start + 1, '"');
            } else {
                next = strchr(start, ' ');
            }

            if (next)
                arg = g_strndup(curr, next - curr);
            else
                arg = g_strdup(curr);

            if (next && (*next == '\'' || *next == '"'))
                next++;

            VIR_RESIZE_N(arglist, args_alloc, args_count, 2);
            arglist[args_count++] = arg;
            arglist[args_count] = NULL;

            while (next && g_ascii_isspace(*next))
                next++;

            curr = next;
        }

        VIR_FREE(nativeConfig_unescaped);

        /* To prevent a memory leak here, only set the argument lists when
         * the first matching command is found. This shouldn't really be a
         * problem, since usually no multiple loaders or bhyverun commands
         * are specified (this wouldn't really be valid anyways).
         * Otherwise, later argument lists may be assigned to _argv without
         * freeing the earlier ones. */
        if (!_bhyve_argv && STREQ(arglist[0], "/usr/sbin/bhyve")) {
            VIR_REALLOC_N(_bhyve_argv, args_count + 1);
            if (!bhyve_argc)
                goto error;
            for (j = 0; j < args_count; j++)
                _bhyve_argv[j] = g_steal_pointer(&arglist[j]);
            _bhyve_argv[j] = NULL;
            *bhyve_argc = args_count-1;
        } else if (!_loader_argv) {
            VIR_REALLOC_N(_loader_argv, args_count + 1);
            if (!loader_argc)
                goto error;
            for (j = 0; j < args_count; j++)
                _loader_argv[j] = g_steal_pointer(&arglist[j]);
            _loader_argv[j] = NULL;
            *loader_argc = args_count-1;
        }
    }

    *loader_argv = _loader_argv;
    if (!(*bhyve_argv = _bhyve_argv))
        goto error;

    return 0;

 error:
    VIR_FREE(_loader_argv);
    VIR_FREE(_bhyve_argv);
    return -1;
}

static int
bhyveParseBhyveLPCArg(virDomainDef *def,
                      unsigned caps G_GNUC_UNUSED,
                      const char *arg)
{
    /* -l emulation[,config] */
    const char *separator = NULL;
    const char *param = NULL;
    size_t last = 0;
    virDomainChrDef *chr = NULL;
    char *type = NULL;

    separator = strchr(arg, ',');

    if (!separator)
        goto error;

    param = separator + 1;
    type = g_strndup(arg, separator - arg);

    /* Only support com%d */
    if (STRPREFIX(type, "com") && type[4] == 0) {
        if (!(chr = virDomainChrDefNew(NULL)))
            goto error;

        chr->source->type = VIR_DOMAIN_CHR_TYPE_NMDM;
        chr->source->data.nmdm.master = NULL;
        chr->source->data.nmdm.slave = NULL;
        chr->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL;

        if (!STRPREFIX(param, "/dev/nmdm")) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("Failed to set com port %1$s: does not start with '/dev/nmdm'."),
                           type);
                goto error;
        }

        chr->source->data.nmdm.master = g_strdup(param);
        chr->source->data.nmdm.slave = g_strdup(chr->source->data.file.path);

        /* If the last character of the master is 'A', the slave will be 'B'
         * and vice versa */
        last = strlen(chr->source->data.nmdm.master) - 1;
        switch (chr->source->data.file.path[last]) {
            case 'A':
                chr->source->data.nmdm.slave[last] = 'B';
                break;
            case 'B':
                chr->source->data.nmdm.slave[last] = 'A';
                break;
            default:
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("Failed to set slave for %1$s: last letter not 'A' or 'B'"),
                               NULLSTR(chr->source->data.nmdm.master));
                goto error;
        }

        switch (type[3]-'0') {
        case 1:
        case 2:
            chr->target.port = type[3] - '1';
            break;
        default:
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("Failed to parse %1$s: only com1 and com2 supported."),
                           type);
            goto error;
            break;
        }

        VIR_APPEND_ELEMENT(def->serials, def->nserials, chr);
    }

    VIR_FREE(type);
    return 0;

 error:
    virDomainChrDefFree(chr);
    VIR_FREE(type);
    return -1;
}

static int
bhyveParsePCISlot(const char *slotdef,
                  unsigned *bus,
                  unsigned *slot,
                  unsigned *function)
{
    /* slot[:function] | bus:slot:function */
    const char *curr = NULL;
    const char *next = NULL;
    unsigned values[3];
    size_t i;

    curr = slotdef;
    for (i = 0; i < 3; i++) {
       char *val = NULL;

       next = strchr(curr, ':');

       if (next)
           val = g_strndup(curr, next - curr);
       else
           val = g_strdup(curr);

       if (virStrToLong_ui(val, NULL, 10, &values[i]) < 0)
           return -1;

       VIR_FREE(val);

       if (!next)
           break;

       curr = next +1;
    }

    *bus = 0;
    *slot = 0;
    *function = 0;

    switch (i + 1) {
    case 2:
        /* pcislot[:function] */
        *function = values[1];
    case 1:
        *slot = values[0];
        break;
    case 3:
        /* bus:pcislot:function */
        *bus = values[0];
        *slot = values[1];
        *function = values[2];
        break;
    }

    return 0;
}

static int
bhyveParsePCIDisk(virDomainDef *def,
                  unsigned caps G_GNUC_UNUSED,
                  unsigned pcibus,
                  unsigned pcislot,
                  unsigned function,
                  int bus,
                  int device,
                  unsigned *nvirtiodisk,
                  unsigned *nahcidisk,
                  char *config)
{
    /* -s slot,virtio-blk|ahci-cd|ahci-hd,/path/to/file */
    const char *separator = NULL;
    int idx = -1;
    virDomainDiskDef *disk = NULL;

    if (!(disk = virDomainDiskDefNew(NULL)))
        return 0;

    disk->bus = bus;
    disk->device = device;

    disk->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
    disk->info.addr.pci.bus = pcibus;
    disk->info.addr.pci.slot = pcislot;
    disk->info.addr.pci.function = function;

    if (!config)
        goto error;

    if (STRPREFIX(config, "/dev/"))
        disk->src->type = VIR_STORAGE_TYPE_BLOCK;
    else
        disk->src->type = VIR_STORAGE_TYPE_FILE;

    separator = strchr(config, ',');
    if (separator)
        disk->src->path = g_strndup(config, separator - config);
    else
        disk->src->path = g_strdup(config);

    if (bus == VIR_DOMAIN_DISK_BUS_VIRTIO) {
        idx = *nvirtiodisk;
        *nvirtiodisk += 1;
        disk->dst = g_strdup("vda");
    } else if (bus == VIR_DOMAIN_DISK_BUS_SATA) {
        idx = *nahcidisk;
        *nahcidisk += 1;
        disk->dst = g_strdup("sda");
    }

    if (idx > 'z' - 'a') {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("too many disks"));
        goto error;
    }

    disk->dst[2] = 'a' + idx;

    VIR_APPEND_ELEMENT(def->disks, def->ndisks, disk);

    return 0;

 error:
    virDomainDiskDefFree(disk);
    return -1;
}

static int
bhyveParsePCINet(virDomainDef *def,
                 virDomainXMLOption *xmlopt,
                 unsigned caps G_GNUC_UNUSED,
                 unsigned bus,
                 unsigned slot,
                 unsigned function,
                 int model,
                 const char *config)
{
    /* -s slot,virtio-net,tapN[,mac=xx:xx:xx:xx:xx:xx] */

    virDomainNetDef *net = NULL;
    const char *separator = NULL;
    const char *mac = NULL;

    if (!(net = virDomainNetDefNew(xmlopt)))
        goto cleanup;

    /* As we only support interface type='bridge' and cannot
     * guess the actual bridge name from the command line,
     * try to come up with some reasonable defaults */
    net->type = VIR_DOMAIN_NET_TYPE_BRIDGE;
    net->data.bridge.brname = g_strdup("virbr0");

    net->model = model;
    net->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
    net->info.addr.pci.bus = bus;
    net->info.addr.pci.slot = slot;
    net->info.addr.pci.function = function;

    if (!config)
        goto error;

    if (!STRPREFIX(config, "tap")) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Only tap devices supported"));
        goto error;
    }

    separator = strchr(config, ',');
    if (separator)
        net->ifname = g_strndup(config, separator - config);
    else
        net->ifname = g_strdup(config);

    if (!separator)
        goto cleanup;

    if (!STRPREFIX(++separator, "mac=")) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Only mac option can be specified for virt-net"));
        goto error;
    }
    mac = separator + 4;

    if (virMacAddrParse(mac, &net->mac) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to parse mac address '%1$s'"),
                       mac);
        goto cleanup;
     }

 cleanup:
    if (!mac)
        virDomainNetGenerateMAC(xmlopt, &net->mac);

    VIR_APPEND_ELEMENT(def->nets, def->nnets, net);
    return 0;

 error:
    virDomainNetDefFree(net);
    return -1;
}

static int
bhyveParsePCIFbuf(virDomainDef *def,
                  virDomainXMLOption *xmlopt,
                  unsigned caps G_GNUC_UNUSED,
                  unsigned bus,
                  unsigned slot,
                  unsigned function,
                  const char *config)
{
    /* -s slot,fbuf,wait,vga=on|io|off,rfb=<ip>:port,w=width,h=height */

    virDomainVideoDef *video = NULL;
    virDomainGraphicsDef *graphics = NULL;
    g_auto(GStrv) params = NULL;
    GStrv next;

    if (!(video = virDomainVideoDefNew(xmlopt)))
        goto cleanup;

    video->type = VIR_DOMAIN_VIDEO_TYPE_GOP;

    if (!(graphics = virDomainGraphicsDefNew(xmlopt)))
        goto cleanup;

    graphics->type = VIR_DOMAIN_GRAPHICS_TYPE_VNC;
    video->info.addr.pci.bus = bus;
    video->info.addr.pci.slot = slot;
    video->info.addr.pci.function = function;

    if (!config)
        goto error;

    if (!(params = g_strsplit(config, ",", 0)))
        goto error;

    for (next = params; *next; next++) {
        char *param = *next;
        char *separator;
        if (!video->driver)
            video->driver = g_new0(virDomainVideoDriverDef, 1);

        if (STREQ(param, "vga=on"))
            video->driver->vgaconf = VIR_DOMAIN_VIDEO_VGACONF_ON;

        if (STREQ(param, "vga=io"))
            video->driver->vgaconf = VIR_DOMAIN_VIDEO_VGACONF_IO;

        if (STREQ(param, "vga=off"))
            video->driver->vgaconf = VIR_DOMAIN_VIDEO_VGACONF_OFF;

        if (STRPREFIX(param, "rfb=") || STRPREFIX(param, "tcp=")) {
            /* fortunately, this is the same length as "tcp=" */
            param += strlen("rfb=");

            if (!(separator = strchr(param, ':')))
                goto error;

            *separator = '\0';

            if (separator != param)
                virDomainGraphicsListenAppendAddress(graphics, param);
            else
                /* Default to 127.0.0.1, just like bhyve does */
                virDomainGraphicsListenAppendAddress(graphics, "127.0.0.1");

            param = ++separator;
            if (virStrToLong_i(param, NULL, 10, &graphics->data.vnc.port))
                goto error;
        }

        if (STRPREFIX(param, "w=")) {
            param += strlen("w=");

            if (video->res == NULL)
                video->res = g_new0(virDomainVideoResolutionDef, 1);

            if (virStrToLong_uip(param, NULL, 10, &video->res->x))
                goto error;
        }

        if (STRPREFIX(param, "h=")) {
            param += strlen("h=");

            if (video->res == NULL)
                video->res = g_new0(virDomainVideoResolutionDef, 1);

            if (virStrToLong_uip(param, NULL, 10, &video->res->y))
                goto error;
        }

        if (STRPREFIX(param, "password=")) {
            param += strlen("password=");
            graphics->data.vnc.auth.passwd = g_strdup(param);
        }
    }

 cleanup:
    VIR_APPEND_ELEMENT(def->videos, def->nvideos, video);
    VIR_APPEND_ELEMENT(def->graphics, def->ngraphics, graphics);

    return 0;

 error:
    virDomainVideoDefFree(video);
    virDomainGraphicsDefFree(graphics);
    return -1;
}

static int
bhyveParseBhyvePCIArg(virDomainDef *def,
                      virDomainXMLOption *xmlopt,
                      unsigned caps,
                      unsigned *nvirtiodisk,
                      unsigned *nahcidisk,
                      const char *arg)
{
    /* -s slot,emulation[,conf] */
    const char *separator = NULL;
    char *slotdef = NULL;
    char *emulation = NULL;
    char *conf = NULL;
    unsigned bus, slot, function;

    separator = strchr(arg, ',');

    if (!separator)
        goto error;
    else
        separator++; /* Skip comma */

    slotdef = g_strndup(arg, separator - arg - 1);

    conf = strchr(separator+1, ',');
    if (conf) {
        conf++; /* Skip initial comma */
        emulation = g_strndup(separator, conf - separator - 1);
    } else {
        emulation = g_strdup(separator);
    }

    if (bhyveParsePCISlot(slotdef, &bus, &slot, &function) < 0)
        goto error;

    if (STREQ(emulation, "ahci-cd"))
        bhyveParsePCIDisk(def, caps, bus, slot, function,
                          VIR_DOMAIN_DISK_BUS_SATA,
                          VIR_DOMAIN_DISK_DEVICE_CDROM,
                          nvirtiodisk,
                          nahcidisk,
                          conf);
    else if (STREQ(emulation, "ahci-hd"))
        bhyveParsePCIDisk(def, caps, bus, slot, function,
                          VIR_DOMAIN_DISK_BUS_SATA,
                          VIR_DOMAIN_DISK_DEVICE_DISK,
                          nvirtiodisk,
                          nahcidisk,
                          conf);
    else if (STREQ(emulation, "virtio-blk"))
        bhyveParsePCIDisk(def, caps, bus, slot, function,
                          VIR_DOMAIN_DISK_BUS_VIRTIO,
                          VIR_DOMAIN_DISK_DEVICE_DISK,
                          nvirtiodisk,
                          nahcidisk,
                          conf);
    else if (STREQ(emulation, "virtio-net"))
        bhyveParsePCINet(def, xmlopt, caps, bus, slot, function,
                         VIR_DOMAIN_NET_MODEL_VIRTIO, conf);
    else if (STREQ(emulation, "e1000"))
        bhyveParsePCINet(def, xmlopt, caps, bus, slot, function,
                         VIR_DOMAIN_NET_MODEL_E1000, conf);
    else if (STREQ(emulation, "fbuf"))
        bhyveParsePCIFbuf(def, xmlopt, caps, bus, slot, function, conf);

    VIR_FREE(emulation);
    VIR_FREE(slotdef);
    return 0;
 error:
    VIR_FREE(emulation);
    VIR_FREE(slotdef);
    return -1;
}

#define CONSUME_ARG(var) \
    if ((opti + 1) == argc) { \
        virReportError(VIR_ERR_INVALID_ARG, _("Missing argument for '%1$s'"), \
                       argv[opti]); \
        return -1; \
    } \
    var = argv[++opti]

/*
 * Parse the /usr/sbin/bhyve command line.
 */
static int
bhyveParseBhyveCommandLine(virDomainDef *def,
                           virDomainXMLOption *xmlopt,
                           unsigned caps,
                           int argc, char **argv)
{
    int vcpus = 1;
    size_t memory = 0;
    unsigned nahcidisks = 0;
    unsigned nvirtiodisks = 0;
    size_t opti;
    const char *arg;

    for (opti = 1; opti < argc; opti++) {
        if (argv[opti][0] != '-')
            break;

        switch (argv[opti][1]) {
        case 'A':
            def->features[VIR_DOMAIN_FEATURE_ACPI] = VIR_TRISTATE_SWITCH_ON;
            break;
        case 'c':
            CONSUME_ARG(arg);
            if (virStrToLong_i(arg, NULL, 10, &vcpus) < 0) {
                virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                               _("Failed to parse number of vCPUs"));
                return -1;
            }
            if (virDomainDefSetVcpusMax(def, vcpus, xmlopt) < 0)
                return -1;
            if (virDomainDefSetVcpus(def, vcpus) < 0)
                return -1;
            break;
        case 'l':
            CONSUME_ARG(arg);
            if (bhyveParseBhyveLPCArg(def, caps, arg))
                return -1;
            break;
        case 's':
            CONSUME_ARG(arg);
            if (bhyveParseBhyvePCIArg(def,
                                      xmlopt,
                                      caps,
                                      &nahcidisks,
                                      &nvirtiodisks,
                                      arg))
                return -1;
            break;
        case 'm':
            CONSUME_ARG(arg);
            if (bhyveParseMemsize(arg, &memory)) {
                virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                               _("Failed to parse memory"));
                return -1;
            }
            if (def->mem.cur_balloon != 0 && def->mem.cur_balloon != memory) {
                virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("Failed to parse memory: size mismatch"));
                return -1;
            }
            def->mem.cur_balloon = memory;
            virDomainDefSetMemoryTotal(def, memory);
            break;
        case 'I':
            /* While this flag was deprecated in FreeBSD r257423, keep checking
             * for it for backwards compatibility. */
            def->features[VIR_DOMAIN_FEATURE_APIC] = VIR_TRISTATE_SWITCH_ON;
            break;
        case 'u':
            def->clock.offset = VIR_DOMAIN_CLOCK_OFFSET_UTC;
            break;
        case 'U':
            CONSUME_ARG(arg);
            if (virUUIDParse(arg, def->uuid) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Cannot parse UUID '%1$s'"), arg);
                return -1;
            }
            break;
        case 'S':
            def->mem.locked = true;
            break;
        case 'p':
        case 'g':
            CONSUME_ARG(arg);
        }
    }

    if (argc != opti) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Failed to parse arguments for bhyve command"));
        return -1;
    }

    if (def->name == NULL) {
        def->name = g_strdup(argv[argc]);
    } else if (STRNEQ(def->name, argv[argc])) {
        /* the vm name of the loader and the bhyverun command differ, throw an
         * error here */
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Failed to parse arguments: VM name mismatch"));
        return -1;
    }

    return 0;
}

/*
 * Parse the /usr/sbin/bhyveload command line.
 */
static int
bhyveParseBhyveLoadCommandLine(virDomainDef *def,
                               int argc, char **argv)
{
    /* bhyveload called with default arguments when only -m and -d are given.
     * Store this in a bit field and check if only those two options are given
     * later */
    unsigned arguments = 0;
    size_t memory = 0;
    size_t i = 0;
    size_t opti;
    const char *arg;

    for (opti = 1; opti < argc; opti++) {
        if (argv[opti][0] != '-')
            break;

        switch (argv[opti][1]) {
        case 'd':
            CONSUME_ARG(arg);
            arguments |= 1;
            /* Iterate over the disks of the domain trying to match up the
             * source */
            for (i = 0; i < def->ndisks; i++) {
                if (STREQ(virDomainDiskGetSource(def->disks[i]),
                          arg)) {
                    def->disks[i]->info.bootIndex = i;
                    break;
                }
            }
            break;
        case 'm':
            CONSUME_ARG(arg);
            arguments |= 2;
            if (bhyveParseMemsize(arg, &memory)) {
                virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                               _("Failed to parse memory"));
                return -1;
            }
            if (def->mem.cur_balloon != 0 && def->mem.cur_balloon != memory) {
                virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                               _("Failed to parse memory: size mismatch"));
                return -1;
            }
            def->mem.cur_balloon = memory;
            virDomainDefSetMemoryTotal(def, memory);
            break;
        default:
            arguments |= 4;
        }
    }

    if (argc != opti) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Failed to parse arguments for bhyve command"));
        return -1;
    }

    if (arguments != 3) {
        /* Set os.bootloader since virDomainDefFormatInternal will only format
         * the bootloader arguments if os->bootloader is set. */
        def->os.bootloader = g_strdup(argv[0]);
        def->os.bootloaderArgs = g_strjoinv(" ", &argv[1]);
    }

    if (def->name == NULL) {
        def->name = g_strdup(argv[argc]);
    } else if (STRNEQ(def->name, argv[argc])) {
        /* the vm name of the loader and the bhyverun command differ, throw an
         * error here */
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Failed to parse arguments: VM name mismatch"));
        return -1;
    }

    return 0;
}

#undef CONSUME_ARG

static int
bhyveParseCustomLoaderCommandLine(virDomainDef *def,
                                  int argc G_GNUC_UNUSED,
                                  char **argv)
{
    if (!argv)
        return -1;

    def->os.bootloader = g_strdup(argv[0]);
    def->os.bootloaderArgs = g_strjoinv(" ", &argv[1]);

    return 0;
}

virDomainDef *
bhyveParseCommandLineString(const char* nativeConfig,
                            unsigned caps,
                            virDomainXMLOption *xmlopt)
{
    g_autoptr(virDomainDef) def = NULL;
    int bhyve_argc = 0;
    g_auto(GStrv) bhyve_argv = NULL;
    int loader_argc = 0;
    g_auto(GStrv) loader_argv = NULL;

    if (!(def = virDomainDefNew(xmlopt)))
        return NULL;

    /* Initialize defaults. */
    def->virtType = VIR_DOMAIN_VIRT_BHYVE;
    if (virUUIDGenerate(def->uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to generate UUID"));
        return NULL;
    }
    def->id = -1;
    def->clock.offset = VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME;

    if (bhyveCommandLineToArgv(nativeConfig,
                               &loader_argc, &loader_argv,
                               &bhyve_argc, &bhyve_argv)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to convert the command string to argv-lists"));
        return NULL;
    }

    if (bhyveParseBhyveCommandLine(def, xmlopt, caps, bhyve_argc, bhyve_argv))
        return NULL;
    if (loader_argv && STREQ(loader_argv[0], "/usr/sbin/bhyveload")) {
        if (bhyveParseBhyveLoadCommandLine(def, loader_argc, loader_argv))
            return NULL;
    } else if (loader_argv) {
        if (bhyveParseCustomLoaderCommandLine(def, loader_argc, loader_argv))
            return NULL;
    }

    return g_steal_pointer(&def);
}
