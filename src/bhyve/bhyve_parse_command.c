/*
 * bhyve_parse_command.c: Bhyve command parser
 *
 * Copyright (C) 2006-2016 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
 * Copyright (c) 2011 NetApp, Inc.
 * Copyright (C) 2016 Fabian Freyer
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
 * Author: Fabian Freyer <fabian.freyer@physik.tu-berlin.de>
 */

#include <config.h>
#include <libutil.h>
#include <getopt_int.h>

#include "bhyve_capabilities.h"
#include "bhyve_command.h"
#include "bhyve_parse_command.h"
#include "viralloc.h"
#include "virlog.h"
#include "virstring.h"
#include "virutil.h"
#include "c-ctype.h"

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
    if (VIR_ALLOC_N(unescaped, len+1) < 0)
        return NULL;

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
    char **lines = NULL;
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

        if (VIR_STRNDUP(line, curr, next ? next - curr : -1) < 0)
            goto error;

        if (VIR_RESIZE_N(lines, lines_alloc, line_count, 2) < 0) {
            VIR_FREE(line);
            goto error;
        }

        if (*line)
            lines[line_count++] = line;
        lines[line_count] = NULL;

        while (next && (*next == '\n' || *next == '\r'
                        || STRPREFIX(next, "\r\n")))
            next++;

        curr = next;
    }

    for (i = 0; i < line_count; i++) {
        curr = lines[i];
        size_t j;
        char **arglist = NULL;
        size_t args_count = 0;
        size_t args_alloc = 0;

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

            if (VIR_STRNDUP(arg, curr, next ? next - curr : -1) < 0)
                goto error;

            if (next && (*next == '\'' || *next == '"'))
                next++;

            if (VIR_RESIZE_N(arglist, args_alloc, args_count, 2) < 0) {
                VIR_FREE(arg);
                goto error;
            }

            arglist[args_count++] = arg;
            arglist[args_count] = NULL;

            while (next && c_isspace(*next))
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
            if ((VIR_REALLOC_N(_bhyve_argv, args_count + 1) < 0)
                || (!bhyve_argc))
                goto error;
            for (j = 0; j < args_count; j++)
                _bhyve_argv[j] = arglist[j];
            _bhyve_argv[j] = NULL;
            *bhyve_argc = args_count-1;
            VIR_FREE(arglist);
        } else if (!_loader_argv) {
            if ((VIR_REALLOC_N(_loader_argv, args_count + 1) < 0)
                || (!loader_argc))
                goto error;
            for (j = 0; j < args_count; j++)
                _loader_argv[j] = arglist[j];
            _loader_argv[j] = NULL;
            *loader_argc = args_count-1;
            VIR_FREE(arglist);
        } else {
            /* To prevent a use-after-free here, only free the argument list
             * when it is definitely not going to be used */
            virStringListFree(arglist);
        }
    }

    *loader_argv = _loader_argv;
    if (!(*bhyve_argv = _bhyve_argv))
        goto error;

    virStringListFree(lines);
    return 0;

 error:
    VIR_FREE(_loader_argv);
    VIR_FREE(_bhyve_argv);
    virStringListFree(lines);
    return -1;
}

static int
bhyveParseBhyveLPCArg(virDomainDefPtr def,
                      unsigned caps ATTRIBUTE_UNUSED,
                      const char *arg)
{
    /* -l emulation[,config] */
    const char *separator = NULL;
    const char *param = NULL;
    size_t last = 0;
    virDomainChrDefPtr chr = NULL;
    char *type = NULL;

    separator = strchr(arg, ',');
    param = separator + 1;

    if (!separator)
        goto error;

    if (VIR_STRNDUP(type, arg, separator - arg) < 0)
        goto error;

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
                           _("Failed to set com port %s: does not start with "
                             "'/dev/nmdm'."), type);
                goto error;
        }

        if (VIR_STRDUP(chr->source->data.nmdm.master, param) < 0) {
            virDomainChrDefFree(chr);
            goto error;
        }

        if (VIR_STRDUP(chr->source->data.nmdm.slave, chr->source->data.file.path)
            < 0) {
            virDomainChrDefFree(chr);
            goto error;
        }

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
                               _("Failed to set slave for %s: last letter not "
                                 "'A' or 'B'"),
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
                           _("Failed to parse %s: only com1 and com2"
                             " supported."), type);
            goto error;
            break;
        }

        if (VIR_APPEND_ELEMENT(def->serials, def->nserials, chr) < 0) {
            virDomainChrDefFree(chr);
            goto error;
        }
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
                  unsigned *pcislot,
                  unsigned *bus,
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

       if (VIR_STRNDUP(val, curr, next? next - curr : -1) < 0)
           goto error;

       if (virStrToLong_ui(val, NULL, 10, &values[i]) < 0)
           goto error;

       VIR_FREE(val);

       if (!next)
           break;

       curr = next +1;
    }

    *bus = 0;
    *pcislot = 0;
    *function = 0;

    switch (i + 1) {
    case 2:
        /* pcislot[:function] */
        *function = values[1];
    case 1:
        *pcislot = values[0];
        break;
    case 3:
        /* bus:pcislot:function */
        *bus = values[0];
        *pcislot = values[1];
        *function = values[2];
        break;
    }

    return 0;
 error:
    return -1;
}

static int
bhyveParsePCIDisk(virDomainDefPtr def,
                  unsigned caps ATTRIBUTE_UNUSED,
                  unsigned pcislot,
                  unsigned pcibus,
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
    virDomainDiskDefPtr disk = NULL;

    if (VIR_ALLOC(disk) < 0)
        goto cleanup;
    if (VIR_ALLOC(disk->src) < 0)
        goto error;

    disk->bus = bus;
    disk->device = device;

    disk->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
    disk->info.addr.pci.slot = pcislot;
    disk->info.addr.pci.bus = pcibus;
    disk->info.addr.pci.function = function;

    if (STRPREFIX(config, "/dev/"))
        disk->src->type = VIR_STORAGE_TYPE_BLOCK;
    else
        disk->src->type = VIR_STORAGE_TYPE_FILE;

    if (!config)
        goto error;

    separator = strchr(config, ',');
    if (VIR_STRNDUP(disk->src->path, config,
                    separator? separator - config : -1) < 0)
        goto error;

    if (bus == VIR_DOMAIN_DISK_BUS_VIRTIO) {
        idx = *nvirtiodisk;
        *nvirtiodisk += 1;
        if (VIR_STRDUP(disk->dst, "vda") < 0)
            goto error;
    } else if (bus == VIR_DOMAIN_DISK_BUS_SATA) {
        idx = *nahcidisk;
        *nahcidisk += 1;
        if (VIR_STRDUP(disk->dst, "sda") < 0)
            goto error;
    }

    if (idx > 'z' - 'a') {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("too many disks"));
        goto error;
    }

    disk->dst[2] = 'a' + idx;

    if (VIR_APPEND_ELEMENT(def->disks, def->ndisks, disk) < 0)
        goto error;

 cleanup:
    return 0;

 error:
    virDomainDiskDefFree(disk);
    return -1;
}

static int
bhyveParsePCINet(virDomainDefPtr def,
                 virDomainXMLOptionPtr xmlopt,
                 unsigned caps ATTRIBUTE_UNUSED,
                 unsigned pcislot,
                 unsigned pcibus,
                 unsigned function,
                 const char *model,
                 const char *config)
{
    /* -s slot,virtio-net,tapN[,mac=xx:xx:xx:xx:xx:xx] */

    virDomainNetDefPtr net = NULL;
    const char *separator = NULL;
    const char *mac = NULL;

    if (VIR_ALLOC(net) < 0)
        goto cleanup;

    /* As we only support interface type='bridge' and cannot
     * guess the actual bridge name from the command line,
     * try to come up with some reasonable defaults */
    net->type = VIR_DOMAIN_NET_TYPE_BRIDGE;
    if (VIR_STRDUP(net->data.bridge.brname, "virbr0") < 0)
        goto error;

    if (VIR_STRDUP(net->model, model) < 0)
        goto error;

    net->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
    net->info.addr.pci.slot = pcislot;
    net->info.addr.pci.bus = pcibus;
    net->info.addr.pci.function = function;

    if (!config)
        goto error;

    if (!STRPREFIX(config, "tap")) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Only tap devices supported"));
        goto error;
    }

    separator = strchr(config, ',');
    if (VIR_STRNDUP(net->ifname, config,
                    separator? separator - config : -1) < 0)
        goto error;

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
                       _("unable to parse mac address '%s'"),
                       mac);
        goto cleanup;
     }

 cleanup:
    if (!mac)
        virDomainNetGenerateMAC(xmlopt, &net->mac);

    if (VIR_APPEND_ELEMENT(def->nets, def->nnets, net) < 0)
        goto error;
    return 0;

 error:
    virDomainNetDefFree(net);
    return -1;
}

static int
bhyveParseBhyvePCIArg(virDomainDefPtr def,
                      virDomainXMLOptionPtr xmlopt,
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
    unsigned pcislot, bus, function;

    separator = strchr(arg, ',');

    if (!separator)
        goto error;
    else
        separator++; /* Skip comma */

    if (VIR_STRNDUP(slotdef, arg, separator - arg - 1) < 0)
        goto error;

    conf = strchr(separator+1, ',');
    if (conf)
        conf++; /* Skip initial comma */

    if (VIR_STRNDUP(emulation, separator, conf? conf - separator - 1 : -1) < 0)
        goto error;

    if (bhyveParsePCISlot(slotdef, &pcislot, &bus, &function) < 0)
        goto error;

    if (STREQ(emulation, "ahci-cd"))
        bhyveParsePCIDisk(def, caps, pcislot, bus, function,
                          VIR_DOMAIN_DISK_BUS_SATA,
                          VIR_DOMAIN_DISK_DEVICE_CDROM,
                          nvirtiodisk,
                          nahcidisk,
                          conf);
    else if (STREQ(emulation, "ahci-hd"))
        bhyveParsePCIDisk(def, caps, pcislot, bus, function,
                          VIR_DOMAIN_DISK_BUS_SATA,
                          VIR_DOMAIN_DISK_DEVICE_DISK,
                          nvirtiodisk,
                          nahcidisk,
                          conf);
    else if (STREQ(emulation, "virtio-blk"))
        bhyveParsePCIDisk(def, caps, pcislot, bus, function,
                          VIR_DOMAIN_DISK_BUS_VIRTIO,
                          VIR_DOMAIN_DISK_DEVICE_DISK,
                          nvirtiodisk,
                          nahcidisk,
                          conf);
    else if (STREQ(emulation, "virtio-net"))
        bhyveParsePCINet(def, xmlopt, caps, pcislot, bus, function,
                         "virtio", conf);
    else if (STREQ(emulation, "e1000"))
        bhyveParsePCINet(def, xmlopt, caps, pcislot, bus, function,
                         "e1000", conf);

    VIR_FREE(emulation);
    VIR_FREE(slotdef);
    return 0;
 error:
    VIR_FREE(emulation);
    VIR_FREE(slotdef);
    return -1;
}

/*
 * Parse the /usr/sbin/bhyve command line.
 */
static int
bhyveParseBhyveCommandLine(virDomainDefPtr def,
                           virDomainXMLOptionPtr xmlopt,
                           unsigned caps,
                           int argc, char **argv)
{
    int c;
    const char optstr[] = "abehuwxACHIPSWYp:g:c:s:m:l:U:";
    int vcpus = 1;
    size_t memory = 0;
    unsigned nahcidisks = 0;
    unsigned nvirtiodisks = 0;
    struct _getopt_data *parser;

    if (!argv)
        goto error;

    if (VIR_ALLOC(parser) < 0)
        goto error;

    while ((c = _getopt_internal_r(argc, argv, optstr,
            NULL, NULL, 0, parser, 0)) != -1) {
        switch (c) {
        case 'A':
            def->features[VIR_DOMAIN_FEATURE_ACPI] = VIR_TRISTATE_SWITCH_ON;
            break;
        case 'c':
            if (virStrToLong_i(parser->optarg, NULL, 10, &vcpus) < 0) {
                virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                               _("Failed to parse number of vCPUs"));
                goto error;
            }
            if (virDomainDefSetVcpusMax(def, vcpus, xmlopt) < 0)
                goto error;
            if (virDomainDefSetVcpus(def, vcpus) < 0)
                goto error;
            break;
        case 'l':
            if (bhyveParseBhyveLPCArg(def, caps, parser->optarg))
                goto error;
            break;
        case 's':
            if (bhyveParseBhyvePCIArg(def,
                                      xmlopt,
                                      caps,
                                      &nahcidisks,
                                      &nvirtiodisks,
                                      parser->optarg))
                goto error;
            break;
        case 'm':
            if (bhyveParseMemsize(parser->optarg, &memory)) {
                virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                               _("Failed to parse memory"));
                goto error;
            }
            if (def->mem.cur_balloon != 0 && def->mem.cur_balloon != memory) {
                virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("Failed to parse memory: size mismatch"));
                goto error;
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
            if (virUUIDParse(parser->optarg, def->uuid) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Cannot parse UUID '%s'"), parser->optarg);
                goto error;
            }
            break;
        }
    }

    if (argc != parser->optind) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Failed to parse arguments for bhyve command"));
        goto error;
    }

    if (def->name == NULL) {
        if (VIR_STRDUP(def->name, argv[argc]) < 0)
            goto error;
    } else if (STRNEQ(def->name, argv[argc])) {
        /* the vm name of the loader and the bhyverun command differ, throw an
         * error here */
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Failed to parse arguments: VM name mismatch"));
        goto error;
    }

    VIR_FREE(parser);
    return 0;

 error:
    VIR_FREE(parser);
    return -1;
}

/*
 * Parse the /usr/sbin/bhyveload command line.
 */
static int
bhyveParseBhyveLoadCommandLine(virDomainDefPtr def,
                               int argc, char **argv)
{
    int c;
    /* bhyveload called with default arguments when only -m and -d are given.
     * Store this in a bit field and check if only those two options are given
     * later */
    unsigned arguments = 0;
    size_t memory = 0;
    struct _getopt_data *parser;
    size_t i = 0;
    int ret = -1;

    const char optstr[] = "CSc:d:e:h:l:m:";

    if (!argv)
        goto error;

    if (VIR_ALLOC(parser) < 0)
        goto error;

    while ((c = _getopt_internal_r(argc, argv, optstr,
            NULL, NULL, 0, parser, 0)) != -1) {
        switch (c) {
        case 'd':
            arguments |= 1;
            /* Iterate over the disks of the domain trying to match up the
             * source */
            for (i = 0; i < def->ndisks; i++) {
                if (STREQ(virDomainDiskGetSource(def->disks[i]),
                          parser->optarg)) {
                    def->disks[i]->info.bootIndex = i;
                    break;
                }
            }
            break;
        case 'm':
            arguments |= 2;
            if (bhyveParseMemsize(parser->optarg, &memory)) {
                virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                               _("Failed to parse memory"));
                goto error;
            }
            if (def->mem.cur_balloon != 0 && def->mem.cur_balloon != memory) {
                virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                               _("Failed to parse memory: size mismatch"));
                goto error;
            }
            def->mem.cur_balloon = memory;
            virDomainDefSetMemoryTotal(def, memory);
            break;
        default:
            arguments |= 4;
        }
    }

    if (arguments != 3) {
        /* Set os.bootloader since virDomainDefFormatInternal will only format
         * the bootloader arguments if os->bootloader is set. */
        if (VIR_STRDUP(def->os.bootloader, argv[0]) < 0)
           goto error;

        def->os.bootloaderArgs = virStringListJoin((const char**) &argv[1], " ");
    }

    if (argc != parser->optind) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Failed to parse arguments for bhyveload command"));
        goto error;
    }

    if (def->name == NULL) {
        if (VIR_STRDUP(def->name, argv[argc]) < 0)
            goto error;
    } else if (STRNEQ(def->name, argv[argc])) {
        /* the vm name of the loader and the bhyverun command differ, throw an
         * error here */
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Failed to parse arguments: VM name mismatch"));
        goto error;
    }

    ret = 0;
 error:
    VIR_FREE(parser);
    return ret;
}

static int
bhyveParseCustomLoaderCommandLine(virDomainDefPtr def,
                                  int argc ATTRIBUTE_UNUSED,
                                  char **argv)
{
    if (!argv)
        goto error;

    if (VIR_STRDUP(def->os.bootloader, argv[0]) < 0)
       goto error;

    def->os.bootloaderArgs = virStringListJoin((const char**) &argv[1], " ");

    return 0;
 error:
    return -1;
}

virDomainDefPtr
bhyveParseCommandLineString(const char* nativeConfig,
                            unsigned caps,
                            virDomainXMLOptionPtr xmlopt)
{
    virDomainDefPtr def = NULL;
    int bhyve_argc = 0;
    char **bhyve_argv = NULL;
    int loader_argc = 0;
    char **loader_argv = NULL;

    if (!(def = virDomainDefNew()))
        goto cleanup;

    /* Initialize defaults. */
    def->virtType = VIR_DOMAIN_VIRT_BHYVE;
    if (virUUIDGenerate(def->uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to generate uuid"));
        virDomainDefFree(def);
        def = NULL;
        goto cleanup;
    }
    def->id = -1;
    def->clock.offset = VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME;

    if (bhyveCommandLineToArgv(nativeConfig,
                               &loader_argc, &loader_argv,
                               &bhyve_argc, &bhyve_argv)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to convert the command string to argv-lists"));
        goto error;
    }

    if (bhyveParseBhyveCommandLine(def, xmlopt, caps, bhyve_argc, bhyve_argv))
        goto error;
    if (loader_argv && STREQ(loader_argv[0], "/usr/sbin/bhyveload")) {
        if (bhyveParseBhyveLoadCommandLine(def, loader_argc, loader_argv))
            goto error;
    } else if (loader_argv) {
        if (bhyveParseCustomLoaderCommandLine(def, loader_argc, loader_argv))
            goto error;
    }

 cleanup:
    virStringListFree(loader_argv);
    virStringListFree(bhyve_argv);
    return def;
 error:
    virDomainDefFree(def);
    def = NULL;
    goto cleanup;
}
