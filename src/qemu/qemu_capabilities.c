/*
 * qemu_capabilities.c: QEMU capabilities generation
 *
 * Copyright (C) 2006-2012 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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

#include "qemu_capabilities.h"
#include "memory.h"
#include "logging.h"
#include "virterror_internal.h"
#include "util.h"
#include "virfile.h"
#include "nodeinfo.h"
#include "cpu/cpu.h"
#include "domain_conf.h"
#include "qemu_conf.h"
#include "command.h"
#include "virnodesuspend.h"

#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <stdarg.h>

#define VIR_FROM_THIS VIR_FROM_QEMU

/* While not public, these strings must not change. They
 * are used in domain status files which are read on
 * daemon restarts
 */
VIR_ENUM_IMPL(qemuCaps, QEMU_CAPS_LAST,
              "kqemu",  /* 0 */
              "vnc-colon",
              "no-reboot",
              "drive",
              "drive-boot",

              "name", /* 5 */
              "uuid",
              "domid",
              "vnet-hdr",
              "migrate-kvm-stdio",

              "migrate-qemu-tcp", /* 10 */
              "migrate-qemu-exec",
              "drive-cache-v2",
              "kvm",
              "drive-format",

              "vga", /* 15 */
              "0.10",
              "pci-device",
              "mem-path",
              "drive-serial",

              "xen-domid", /* 20 */
              "migrate-qemu-unix",
              "chardev",
              "enable-kvm",
              "monitor-json",

              "balloon", /* 25 */
              "device",
              "sdl",
              "smp-topology",
              "netdev",

              "rtc", /* 30 */
              "vhost-net",
              "rtc-td-hack",
              "no-hpet",
              "no-kvm-pit",

              "tdf", /* 35 */
              "pci-configfd",
              "nodefconfig",
              "boot-menu",
              "enable-kqemu",

              "fsdev", /* 40 */
              "nesting",
              "name-process",
              "drive-readonly",
              "smbios-type",

              "vga-qxl", /* 45 */
              "spice",
              "vga-none",
              "migrate-qemu-fd",
              "boot-index",

              "hda-duplex", /* 50 */
              "drive-aio",
              "pci-multibus",
              "pci-bootindex",
              "ccid-emulated",

              "ccid-passthru", /* 55 */
              "chardev-spicevmc",
              "device-spicevmc",
              "virtio-tx-alg",
              "device-qxl-vga",

              "pci-multifunction", /* 60 */
              "virtio-blk-pci.ioeventfd",
              "sga",
              "virtio-blk-pci.event_idx",
              "virtio-net-pci.event_idx",

              "cache-directsync", /* 65 */
              "piix3-usb-uhci",
              "piix4-usb-uhci",
              "usb-ehci",
              "ich9-usb-ehci1",

              "vt82c686b-usb-uhci", /* 70 */
              "pci-ohci",
              "usb-redir",
              "usb-hub",
              "no-shutdown",

              "cache-unsafe", /* 75 */
              "rombar",
              "ich9-ahci",
              "no-acpi",
              "fsdev-readonly",

              "virtio-blk-pci.scsi", /* 80 */
              "blk-sg-io",
              "drive-copy-on-read",
              "cpu-host",
              "fsdev-writeout",

              "drive-iotune", /* 85 */
              "system_wakeup",
              "scsi-disk.channel",
              "scsi-block",
              "transaction",
    );

struct qemu_feature_flags {
    const char *name;
    const int default_on;
    const int toggle;
};

struct qemu_arch_info {
    const char *arch;
    int wordsize;
    const char *machine;
    const char *binary;
    const char *altbinary;
    const struct qemu_feature_flags *flags;
    int nflags;
};

/* Feature flags for the architecture info */
static const struct qemu_feature_flags const arch_info_i686_flags [] = {
    { "pae",  1, 0 },
    { "nonpae",  1, 0 },
    { "acpi", 1, 1 },
    { "apic", 1, 0 },
};

static const struct qemu_feature_flags const arch_info_x86_64_flags [] = {
    { "acpi", 1, 1 },
    { "apic", 1, 0 },
};

/* The archicture tables for supported QEMU archs */
static const struct qemu_arch_info const arch_info_hvm[] = {
    {  "i686",   32, NULL, "qemu",
       "qemu-system-x86_64", arch_info_i686_flags, 4 },
    {  "x86_64", 64, NULL, "qemu-system-x86_64",
       NULL, arch_info_x86_64_flags, 2 },
    {  "arm",    32, NULL, "qemu-system-arm",    NULL, NULL, 0 },
    {  "microblaze", 32, NULL, "qemu-system-microblaze",   NULL, NULL, 0 },
    {  "microblazeel", 32, NULL, "qemu-system-microblazeel",   NULL, NULL, 0 },
    {  "mips",   32, NULL, "qemu-system-mips",   NULL, NULL, 0 },
    {  "mipsel", 32, NULL, "qemu-system-mipsel", NULL, NULL, 0 },
    {  "sparc",  32, NULL, "qemu-system-sparc",  NULL, NULL, 0 },
    {  "ppc",    32, NULL, "qemu-system-ppc",    NULL, NULL, 0 },
    {  "ppc64",    64, NULL, "qemu-system-ppc64",    NULL, NULL, 0 },
    {  "itanium", 64, NULL, "qemu-system-ia64",  NULL, NULL, 0 },
    {  "s390x",  64, NULL, "qemu-system-s390x",  NULL, NULL, 0 },
};

static const struct qemu_arch_info const arch_info_xen[] = {
    {  "i686",   32, "xenner", "xenner", NULL, arch_info_i686_flags, 4 },
    {  "x86_64", 64, "xenner", "xenner", NULL, arch_info_x86_64_flags, 2 },
};


/* Format is:
 * <machine> <desc> [(default)|(alias of <canonical>)]
 */
static int
qemuCapsParseMachineTypesStr(const char *output,
                             virCapsGuestMachinePtr **machines,
                             int *nmachines)
{
    const char *p = output;
    const char *next;
    virCapsGuestMachinePtr *list = NULL;
    int nitems = 0;

    do {
        const char *t;
        virCapsGuestMachinePtr machine;

        if ((next = strchr(p, '\n')))
            ++next;

        if (STRPREFIX(p, "Supported machines are:"))
            continue;

        if (!(t = strchr(p, ' ')) || (next && t >= next))
            continue;

        if (VIR_ALLOC(machine) < 0)
            goto no_memory;

        if (!(machine->name = strndup(p, t - p))) {
            VIR_FREE(machine);
            goto no_memory;
        }

        if (VIR_REALLOC_N(list, nitems + 1) < 0) {
            VIR_FREE(machine->name);
            VIR_FREE(machine);
            goto no_memory;
        }

        p = t;
        if (!(t = strstr(p, "(default)")) || (next && t >= next)) {
            list[nitems++] = machine;
        } else {
            /* put the default first in the list */
            memmove(list + 1, list, sizeof(*list) * nitems);
            list[0] = machine;
            nitems++;
        }

        if ((t = strstr(p, "(alias of ")) && (!next || t < next)) {
            p = t + strlen("(alias of ");
            if (!(t = strchr(p, ')')) || (next && t >= next))
                continue;

            if (!(machine->canonical = strndup(p, t - p)))
                goto no_memory;
        }
    } while ((p = next));

    *machines = list;
    *nmachines = nitems;

    return 0;

  no_memory:
    virReportOOMError();
    virCapabilitiesFreeMachines(list, nitems);
    return -1;
}

int
qemuCapsProbeMachineTypes(const char *binary,
                          virCapsGuestMachinePtr **machines,
                          int *nmachines)
{
    char *output;
    int ret = -1;
    virCommandPtr cmd;
    int status;

    /* Make sure the binary we are about to try exec'ing exists.
     * Technically we could catch the exec() failure, but that's
     * in a sub-process so it's hard to feed back a useful error.
     */
    if (!virFileIsExecutable(binary)) {
        virReportSystemError(errno, _("Cannot find QEMU binary %s"), binary);
        return -1;
    }

    cmd = virCommandNewArgList(binary, "-M", "?", NULL);
    virCommandAddEnvPassCommon(cmd);
    virCommandSetOutputBuffer(cmd, &output);
    virCommandClearCaps(cmd);

    /* Ignore failure from older qemu that did not understand '-M ?'.  */
    if (virCommandRun(cmd, &status) < 0)
        goto cleanup;

    if (qemuCapsParseMachineTypesStr(output, machines, nmachines) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    VIR_FREE(output);
    virCommandFree(cmd);

    return ret;
}

static int
qemuCapsGetOldMachinesFromInfo(virCapsGuestDomainInfoPtr info,
                               const char *emulator,
                               time_t emulator_mtime,
                               virCapsGuestMachinePtr **machines,
                               int *nmachines)
{
    virCapsGuestMachinePtr *list;
    int i;

    if (!info->nmachines)
        return 0;

    if (!info->emulator || !STREQ(emulator, info->emulator))
        return 0;

    if (emulator_mtime != info->emulator_mtime) {
        VIR_DEBUG("mtime on %s has changed, refreshing machine types",
                  info->emulator);
        return 0;
    }

    if (VIR_ALLOC_N(list, info->nmachines) < 0) {
        virReportOOMError();
        return 0;
    }

    for (i = 0; i < info->nmachines; i++) {
        if (VIR_ALLOC(list[i]) < 0) {
            goto no_memory;
        }
        if (info->machines[i]->name &&
            !(list[i]->name = strdup(info->machines[i]->name))) {
            goto no_memory;
        }
        if (info->machines[i]->canonical &&
            !(list[i]->canonical = strdup(info->machines[i]->canonical))) {
            goto no_memory;
        }
    }

    *machines = list;
    *nmachines = info->nmachines;

    return 1;

  no_memory:
    virReportOOMError();
    virCapabilitiesFreeMachines(list, info->nmachines);
    return 0;
}

static int
qemuCapsGetOldMachines(const char *ostype,
                       const char *arch,
                       int wordsize,
                       const char *emulator,
                       time_t emulator_mtime,
                       virCapsPtr old_caps,
                       virCapsGuestMachinePtr **machines,
                       int *nmachines)
{
    int i;

    for (i = 0; i < old_caps->nguests; i++) {
        virCapsGuestPtr guest = old_caps->guests[i];
        int j;

        if (!STREQ(ostype, guest->ostype) ||
            !STREQ(arch, guest->arch.name) ||
            wordsize != guest->arch.wordsize)
            continue;

        for (j = 0; j < guest->arch.ndomains; j++) {
            virCapsGuestDomainPtr dom = guest->arch.domains[j];

            if (qemuCapsGetOldMachinesFromInfo(&dom->info,
                                               emulator, emulator_mtime,
                                               machines, nmachines))
                return 1;
        }

        if (qemuCapsGetOldMachinesFromInfo(&guest->arch.defaultInfo,
                                           emulator, emulator_mtime,
                                           machines, nmachines))
            return 1;
    }

    return 0;
}


typedef int
(*qemuCapsParseCPUModels)(const char *output,
                       unsigned int *retcount,
                       const char ***retcpus);

/* Format:
 *      <arch> <model>
 * qemu-0.13 encloses some model names in []:
 *      <arch> [<model>]
 */
static int
qemuCapsParseX86Models(const char *output,
                       unsigned int *retcount,
                       const char ***retcpus)
{
    const char *p = output;
    const char *next;
    unsigned int count = 0;
    const char **cpus = NULL;
    int i;

    do {
        const char *t;

        if ((next = strchr(p, '\n')))
            next++;

        if (!(t = strchr(p, ' ')) || (next && t >= next))
            continue;

        if (!STRPREFIX(p, "x86"))
            continue;

        p = t;
        while (*p == ' ')
            p++;

        if (*p == '\0' || *p == '\n')
            continue;

        if (retcpus) {
            unsigned int len;

            if (VIR_REALLOC_N(cpus, count + 1) < 0) {
                virReportOOMError();
                goto error;
            }

            if (next)
                len = next - p - 1;
            else
                len = strlen(p);

            if (len > 2 && *p == '[' && p[len - 1] == ']') {
                p++;
                len -= 2;
            }

            if (!(cpus[count] = strndup(p, len))) {
                virReportOOMError();
                goto error;
            }
        }
        count++;
    } while ((p = next));

    if (retcount)
        *retcount = count;
    if (retcpus)
        *retcpus = cpus;

    return 0;

error:
    if (cpus) {
        for (i = 0; i < count; i++)
            VIR_FREE(cpus[i]);
    }
    VIR_FREE(cpus);

    return -1;
}

/* ppc64 parser.
 * Format : PowerPC <machine> <description>
 */
static int
qemuCapsParsePPCModels(const char *output,
                       unsigned int *retcount,
                       const char ***retcpus)
{
    const char *p = output;
    const char *next;
    unsigned int count = 0;
    const char **cpus = NULL;
    int i, ret = -1;

    do {
        const char *t;

        if ((next = strchr(p, '\n')))
            next++;

        if (!STRPREFIX(p, "PowerPC "))
            continue;

        /* Skip the preceding sub-string "PowerPC " */
        p += 8;

        /*Malformed string, does not obey the format 'PowerPC <model> <desc>'*/
        if (!(t = strchr(p, ' ')) || (next && t >= next))
            continue;

        if (*p == '\0')
            break;

        if (*p == '\n')
            continue;

        if (retcpus) {
            unsigned int len;

            if (VIR_REALLOC_N(cpus, count + 1) < 0) {
                virReportOOMError();
                goto cleanup;
            }

            len = t - p - 1;

            if (!(cpus[count] = strndup(p, len))) {
                virReportOOMError();
                goto cleanup;
            }
        }
        count++;
    } while ((p = next));

    if (retcount)
        *retcount = count;
    if (retcpus) {
        *retcpus = cpus;
        cpus = NULL;
    }
    ret = 0;

cleanup:
    if (cpus) {
        for (i = 0; i < count; i++)
            VIR_FREE(cpus[i]);
        VIR_FREE(cpus);
    }
    return ret;
}

int
qemuCapsProbeCPUModels(const char *qemu,
                       virBitmapPtr qemuCaps,
                       const char *arch,
                       unsigned int *count,
                       const char ***cpus)
{
    char *output = NULL;
    int ret = -1;
    qemuCapsParseCPUModels parse;
    virCommandPtr cmd;

    if (count)
        *count = 0;
    if (cpus)
        *cpus = NULL;

    if (STREQ(arch, "i686") || STREQ(arch, "x86_64"))
        parse = qemuCapsParseX86Models;
    else if (STREQ(arch, "ppc64"))
        parse = qemuCapsParsePPCModels;
    else {
        VIR_DEBUG("don't know how to parse %s CPU models", arch);
        return 0;
    }

    cmd = virCommandNewArgList(qemu, "-cpu", "?", NULL);
    if (qemuCapsGet(qemuCaps, QEMU_CAPS_NODEFCONFIG))
        virCommandAddArg(cmd, "-nodefconfig");
    virCommandAddEnvPassCommon(cmd);
    virCommandSetOutputBuffer(cmd, &output);
    virCommandClearCaps(cmd);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (parse(output, count, cpus) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    VIR_FREE(output);
    virCommandFree(cmd);

    return ret;
}


static int
qemuCapsInitGuest(virCapsPtr caps,
                  virCapsPtr old_caps,
                  const char *hostmachine,
                  const struct qemu_arch_info *info,
                  int hvm)
{
    virCapsGuestPtr guest;
    int i;
    int haskvm = 0;
    int haskqemu = 0;
    char *kvmbin = NULL;
    char *binary = NULL;
    time_t binary_mtime;
    virCapsGuestMachinePtr *machines = NULL;
    int nmachines = 0;
    struct stat st;
    unsigned int ncpus;
    virBitmapPtr qemuCaps = NULL;
    int ret = -1;

    /* Check for existance of base emulator, or alternate base
     * which can be used with magic cpu choice
     */
    binary = virFindFileInPath(info->binary);

    if (binary == NULL || !virFileIsExecutable(binary)) {
        VIR_FREE(binary);
        binary = virFindFileInPath(info->altbinary);
    }

    /* Can use acceleration for KVM/KQEMU if
     *  - host & guest arches match
     * Or
     *  - hostarch is x86_64 and guest arch is i686
     * The latter simply needs "-cpu qemu32"
     */
    if (STREQ(info->arch, hostmachine) ||
        (STREQ(hostmachine, "x86_64") && STREQ(info->arch, "i686"))) {
        if (access("/dev/kvm", F_OK) == 0) {
            const char *const kvmbins[] = { "/usr/libexec/qemu-kvm", /* RHEL */
                                            "qemu-kvm", /* Fedora */
                                            "kvm" }; /* Upstream .spec */

            for (i = 0; i < ARRAY_CARDINALITY(kvmbins); ++i) {
                kvmbin = virFindFileInPath(kvmbins[i]);

                if (!kvmbin)
                    continue;

                haskvm = 1;
                if (!binary)
                    binary = kvmbin;

                break;
            }
        }

        if (access("/dev/kqemu", F_OK) == 0)
            haskqemu = 1;
    }

    if (!binary)
        return 0;

    /* Ignore binary if extracting version info fails */
    if (qemuCapsExtractVersionInfo(binary, info->arch, NULL, &qemuCaps) < 0) {
        ret = 0;
        goto cleanup;
    }

    if (stat(binary, &st) == 0) {
        binary_mtime = st.st_mtime;
    } else {
        char ebuf[1024];
        VIR_WARN("Failed to stat %s, most peculiar : %s",
                 binary, virStrerror(errno, ebuf, sizeof(ebuf)));
        binary_mtime = 0;
    }

    if (info->machine) {
        virCapsGuestMachinePtr machine;

        if (VIR_ALLOC(machine) < 0) {
            goto no_memory;
        }

        if (!(machine->name = strdup(info->machine))) {
            VIR_FREE(machine);
            goto no_memory;
        }

        nmachines = 1;

        if (VIR_ALLOC_N(machines, nmachines) < 0) {
            VIR_FREE(machine->name);
            VIR_FREE(machine);
            goto no_memory;
        }

        machines[0] = machine;
    } else {
        int probe = 1;
        if (old_caps && binary_mtime)
            probe = !qemuCapsGetOldMachines(hvm ? "hvm" : "xen", info->arch,
                                            info->wordsize, binary, binary_mtime,
                                            old_caps, &machines, &nmachines);
        if (probe &&
            qemuCapsProbeMachineTypes(binary, &machines, &nmachines) < 0)
            goto error;
    }

    /* We register kvm as the base emulator too, since we can
     * just give -no-kvm to disable acceleration if required */
    if ((guest = virCapabilitiesAddGuest(caps,
                                         hvm ? "hvm" : "xen",
                                         info->arch,
                                         info->wordsize,
                                         binary,
                                         NULL,
                                         nmachines,
                                         machines)) == NULL)
        goto error;

    machines = NULL;
    nmachines = 0;

    guest->arch.defaultInfo.emulator_mtime = binary_mtime;

    if (caps->host.cpu &&
        qemuCapsProbeCPUModels(binary, NULL, info->arch, &ncpus, NULL) == 0 &&
        ncpus > 0 &&
        !virCapabilitiesAddGuestFeature(guest, "cpuselection", 1, 0))
        goto error;

    if (qemuCapsGet(qemuCaps, QEMU_CAPS_BOOTINDEX) &&
        !virCapabilitiesAddGuestFeature(guest, "deviceboot", 1, 0))
        goto error;

    if (hvm) {
        if (virCapabilitiesAddGuestDomain(guest,
                                          "qemu",
                                          NULL,
                                          NULL,
                                          0,
                                          NULL) == NULL)
            goto error;

        if (haskqemu &&
            virCapabilitiesAddGuestDomain(guest,
                                          "kqemu",
                                          NULL,
                                          NULL,
                                          0,
                                          NULL) == NULL)
            goto error;

        if (haskvm) {
            virCapsGuestDomainPtr dom;

            if (stat(kvmbin, &st) == 0) {
                binary_mtime = st.st_mtime;
            } else {
                char ebuf[1024];
                VIR_WARN("Failed to stat %s, most peculiar : %s",
                         binary, virStrerror(errno, ebuf, sizeof(ebuf)));
                binary_mtime = 0;
            }

            if (!STREQ(binary, kvmbin)) {
                int probe = 1;
                if (old_caps && binary_mtime)
                    probe = !qemuCapsGetOldMachines("hvm", info->arch, info->wordsize,
                                                    kvmbin, binary_mtime,
                                                    old_caps, &machines, &nmachines);
                if (probe &&
                    qemuCapsProbeMachineTypes(kvmbin, &machines, &nmachines) < 0)
                    goto error;
            }

            if ((dom = virCapabilitiesAddGuestDomain(guest,
                                                     "kvm",
                                                     kvmbin,
                                                     NULL,
                                                     nmachines,
                                                     machines)) == NULL) {
                goto error;
            }

            machines = NULL;
            nmachines = 0;

            dom->info.emulator_mtime = binary_mtime;
        }
    } else {
        if (virCapabilitiesAddGuestDomain(guest,
                                          "kvm",
                                          NULL,
                                          NULL,
                                          0,
                                          NULL) == NULL)
            goto error;
    }

    if (info->nflags) {
        for (i = 0 ; i < info->nflags ; i++) {
            if (virCapabilitiesAddGuestFeature(guest,
                                               info->flags[i].name,
                                               info->flags[i].default_on,
                                               info->flags[i].toggle) == NULL)
                goto error;
        }
    }

    ret = 0;

cleanup:
    if (binary == kvmbin) {
        /* don't double free */
        VIR_FREE(binary);
    } else {
        VIR_FREE(binary);
        VIR_FREE(kvmbin);
    }
    qemuCapsFree(qemuCaps);

    return ret;

no_memory:
    virReportOOMError();

error:
    virCapabilitiesFreeMachines(machines, nmachines);

    goto cleanup;
}


static int
qemuCapsInitCPU(virCapsPtr caps,
                 const char *arch)
{
    virCPUDefPtr cpu = NULL;
    union cpuData *data = NULL;
    virNodeInfo nodeinfo;
    int ret = -1;

    if (VIR_ALLOC(cpu) < 0
        || !(cpu->arch = strdup(arch))) {
        virReportOOMError();
        goto error;
    }

    if (nodeGetInfo(NULL, &nodeinfo))
        goto error;

    cpu->type = VIR_CPU_TYPE_HOST;
    cpu->sockets = nodeinfo.sockets;
    cpu->cores = nodeinfo.cores;
    cpu->threads = nodeinfo.threads;

    if (!(data = cpuNodeData(arch))
        || cpuDecode(cpu, data, NULL, 0, NULL) < 0)
        goto error;

    caps->host.cpu = cpu;

    ret = 0;

cleanup:
    cpuDataFree(arch, data);

    return ret;

error:
    virCPUDefFree(cpu);
    goto cleanup;
}


static int qemuDefaultConsoleType(const char *ostype ATTRIBUTE_UNUSED)
{
    return VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL;
}


virCapsPtr qemuCapsInit(virCapsPtr old_caps)
{
    struct utsname utsname;
    virCapsPtr caps;
    int i;
    char *xenner = NULL;

    /* Really, this never fails - look at the man-page. */
    uname (&utsname);

    if ((caps = virCapabilitiesNew(utsname.machine,
                                   1, 1)) == NULL)
        goto no_memory;

    /* Using KVM's mac prefix for QEMU too */
    virCapabilitiesSetMacPrefix(caps, (unsigned char[]){ 0x52, 0x54, 0x00 });

    /* Some machines have problematic NUMA toplogy causing
     * unexpected failures. We don't want to break the QEMU
     * driver in this scenario, so log errors & carry on
     */
    if (nodeCapsInitNUMA(caps) < 0) {
        virCapabilitiesFreeNUMAInfo(caps);
        VIR_WARN("Failed to query host NUMA topology, disabling NUMA capabilities");
    }

    if (old_caps == NULL || old_caps->host.cpu == NULL) {
        if (qemuCapsInitCPU(caps, utsname.machine) < 0)
            VIR_WARN("Failed to get host CPU");
    }
    else {
        caps->host.cpu = old_caps->host.cpu;
        old_caps->host.cpu = NULL;
    }

    /* Add the power management features of the host */

    if (virNodeSuspendGetTargetMask(&caps->host.powerMgmt) < 0)
        VIR_WARN("Failed to get host power management capabilities");

    virCapabilitiesAddHostMigrateTransport(caps,
                                           "tcp");

    /* First the pure HVM guests */
    for (i = 0 ; i < ARRAY_CARDINALITY(arch_info_hvm) ; i++)
        if (qemuCapsInitGuest(caps, old_caps,
                              utsname.machine,
                              &arch_info_hvm[i], 1) < 0)
            goto no_memory;

    /* Then possibly the Xen paravirt guests (ie Xenner */
    xenner = virFindFileInPath("xenner");

    if (xenner != NULL && virFileIsExecutable(xenner) == 0 &&
        access("/dev/kvm", F_OK) == 0) {
        for (i = 0 ; i < ARRAY_CARDINALITY(arch_info_xen) ; i++)
            /* Allow Xen 32-on-32, 32-on-64 and 64-on-64 */
            if (STREQ(arch_info_xen[i].arch, utsname.machine) ||
                (STREQ(utsname.machine, "x86_64") &&
                 STREQ(arch_info_xen[i].arch, "i686"))) {
                if (qemuCapsInitGuest(caps, old_caps,
                                      utsname.machine,
                                      &arch_info_xen[i], 0) < 0)
                    goto no_memory;
            }
    }

    VIR_FREE(xenner);

    /* QEMU Requires an emulator in the XML */
    virCapabilitiesSetEmulatorRequired(caps);

    caps->defaultConsoleTargetType = qemuDefaultConsoleType;

    return caps;

 no_memory:
    VIR_FREE(xenner);
    virCapabilitiesFree(caps);
    return NULL;
}


static int
qemuCapsComputeCmdFlags(const char *help,
                        unsigned int version,
                        unsigned int is_kvm,
                        unsigned int kvm_version,
                        virBitmapPtr flags,
                        bool check_yajl ATTRIBUTE_UNUSED)
{
    const char *p;
    const char *fsdev;

    if (strstr(help, "-no-kqemu"))
        qemuCapsSet(flags, QEMU_CAPS_KQEMU);
    if (strstr(help, "-enable-kqemu"))
        qemuCapsSet(flags, QEMU_CAPS_ENABLE_KQEMU);
    if (strstr(help, "-no-kvm"))
        qemuCapsSet(flags, QEMU_CAPS_KVM);
    if (strstr(help, "-enable-kvm"))
        qemuCapsSet(flags, QEMU_CAPS_ENABLE_KVM);
    if (strstr(help, "-no-reboot"))
        qemuCapsSet(flags, QEMU_CAPS_NO_REBOOT);
    if (strstr(help, "-name")) {
        qemuCapsSet(flags, QEMU_CAPS_NAME);
        if (strstr(help, ",process="))
            qemuCapsSet(flags, QEMU_CAPS_NAME_PROCESS);
    }
    if (strstr(help, "-uuid"))
        qemuCapsSet(flags, QEMU_CAPS_UUID);
    if (strstr(help, "-xen-domid"))
        qemuCapsSet(flags, QEMU_CAPS_XEN_DOMID);
    else if (strstr(help, "-domid"))
        qemuCapsSet(flags, QEMU_CAPS_DOMID);
    if (strstr(help, "-drive")) {
        const char *cache = strstr(help, "cache=");

        qemuCapsSet(flags, QEMU_CAPS_DRIVE);
        if (cache && (p = strchr(cache, ']'))) {
            if (memmem(cache, p - cache, "on|off", sizeof("on|off") - 1) == NULL)
                qemuCapsSet(flags, QEMU_CAPS_DRIVE_CACHE_V2);
            if (memmem(cache, p - cache, "directsync", sizeof("directsync") - 1))
                qemuCapsSet(flags, QEMU_CAPS_DRIVE_CACHE_DIRECTSYNC);
            if (memmem(cache, p - cache, "unsafe", sizeof("unsafe") - 1))
                qemuCapsSet(flags, QEMU_CAPS_DRIVE_CACHE_UNSAFE);
        }
        if (strstr(help, "format="))
            qemuCapsSet(flags, QEMU_CAPS_DRIVE_FORMAT);
        if (strstr(help, "readonly="))
            qemuCapsSet(flags, QEMU_CAPS_DRIVE_READONLY);
        if (strstr(help, "aio=threads|native"))
            qemuCapsSet(flags, QEMU_CAPS_DRIVE_AIO);
        if (strstr(help, "copy-on-read=on|off"))
            qemuCapsSet(flags, QEMU_CAPS_DRIVE_COPY_ON_READ);
        if (strstr(help, "bps="))
            qemuCapsSet(flags, QEMU_CAPS_DRIVE_IOTUNE);
    }
    if ((p = strstr(help, "-vga")) && !strstr(help, "-std-vga")) {
        const char *nl = strstr(p, "\n");

        qemuCapsSet(flags, QEMU_CAPS_VGA);

        if (strstr(p, "|qxl"))
            qemuCapsSet(flags, QEMU_CAPS_VGA_QXL);
        if ((p = strstr(p, "|none")) && p < nl)
            qemuCapsSet(flags, QEMU_CAPS_VGA_NONE);
    }
    if (strstr(help, "-spice"))
        qemuCapsSet(flags, QEMU_CAPS_SPICE);
    if (strstr(help, "boot=on"))
        qemuCapsSet(flags, QEMU_CAPS_DRIVE_BOOT);
    if (strstr(help, "serial=s"))
        qemuCapsSet(flags, QEMU_CAPS_DRIVE_SERIAL);
    if (strstr(help, "-pcidevice"))
        qemuCapsSet(flags, QEMU_CAPS_PCIDEVICE);
    if (strstr(help, "-mem-path"))
        qemuCapsSet(flags, QEMU_CAPS_MEM_PATH);
    if (strstr(help, "-chardev")) {
        qemuCapsSet(flags, QEMU_CAPS_CHARDEV);
        if (strstr(help, "-chardev spicevmc"))
            qemuCapsSet(flags, QEMU_CAPS_CHARDEV_SPICEVMC);
    }
    if (strstr(help, "-balloon"))
        qemuCapsSet(flags, QEMU_CAPS_BALLOON);
    if (strstr(help, "-device")) {
        qemuCapsSet(flags, QEMU_CAPS_DEVICE);
        /*
         * When -device was introduced, qemu already supported drive's
         * readonly option but didn't advertise that.
         */
        qemuCapsSet(flags, QEMU_CAPS_DRIVE_READONLY);
    }
    if (strstr(help, "-nodefconfig"))
        qemuCapsSet(flags, QEMU_CAPS_NODEFCONFIG);
    /* The trailing ' ' is important to avoid a bogus match */
    if (strstr(help, "-rtc "))
        qemuCapsSet(flags, QEMU_CAPS_RTC);
    /* to wit */
    if (strstr(help, "-rtc-td-hack"))
        qemuCapsSet(flags, QEMU_CAPS_RTC_TD_HACK);
    if (strstr(help, "-no-hpet"))
        qemuCapsSet(flags, QEMU_CAPS_NO_HPET);
    if (strstr(help, "-no-acpi"))
        qemuCapsSet(flags, QEMU_CAPS_NO_ACPI);
    if (strstr(help, "-no-kvm-pit-reinjection"))
        qemuCapsSet(flags, QEMU_CAPS_NO_KVM_PIT);
    if (strstr(help, "-tdf"))
        qemuCapsSet(flags, QEMU_CAPS_TDF);
    if (strstr(help, "-enable-nesting"))
        qemuCapsSet(flags, QEMU_CAPS_NESTING);
    if (strstr(help, ",menu=on"))
        qemuCapsSet(flags, QEMU_CAPS_BOOT_MENU);
    if ((fsdev = strstr(help, "-fsdev"))) {
        qemuCapsSet(flags, QEMU_CAPS_FSDEV);
        if (strstr(fsdev, "readonly"))
            qemuCapsSet(flags, QEMU_CAPS_FSDEV_READONLY);
        if (strstr(fsdev, "writeout"))
            qemuCapsSet(flags, QEMU_CAPS_FSDEV_WRITEOUT);
    }
    if (strstr(help, "-smbios type"))
        qemuCapsSet(flags, QEMU_CAPS_SMBIOS_TYPE);

    if (strstr(help, "-netdev")) {
        /* Disable -netdev on 0.12 since although it exists,
         * the corresponding netdev_add/remove monitor commands
         * do not, and we need them to be able to do hotplug.
         * But see below about RHEL build. */
        if (version >= 13000)
            qemuCapsSet(flags, QEMU_CAPS_NETDEV);
    }

    if (strstr(help, "-sdl"))
        qemuCapsSet(flags, QEMU_CAPS_SDL);
    if (strstr(help, "cores=") &&
        strstr(help, "threads=") &&
        strstr(help, "sockets="))
        qemuCapsSet(flags, QEMU_CAPS_SMP_TOPOLOGY);

    if (version >= 9000)
        qemuCapsSet(flags, QEMU_CAPS_VNC_COLON);

    if (is_kvm && (version >= 10000 || kvm_version >= 74))
        qemuCapsSet(flags, QEMU_CAPS_VNET_HDR);

    if (strstr(help, ",vhost=")) {
        qemuCapsSet(flags, QEMU_CAPS_VHOST_NET);
    }

    /* Do not use -no-shutdown if qemu doesn't support it or SIGTERM handling
     * is most likely buggy when used with -no-shutdown (which applies for qemu
     * 0.14.* and 0.15.0)
     */
    if (strstr(help, "-no-shutdown") && (version < 14000 || version > 15000))
        qemuCapsSet(flags, QEMU_CAPS_NO_SHUTDOWN);

    /*
     * Handling of -incoming arg with varying features
     *  -incoming tcp    (kvm >= 79, qemu >= 0.10.0)
     *  -incoming exec   (kvm >= 80, qemu >= 0.10.0)
     *  -incoming unix   (qemu >= 0.12.0)
     *  -incoming fd     (qemu >= 0.12.0)
     *  -incoming stdio  (all earlier kvm)
     *
     * NB, there was a pre-kvm-79 'tcp' support, but it
     * was broken, because it blocked the monitor console
     * while waiting for data, so pretend it doesn't exist
     */
    if (version >= 10000) {
        qemuCapsSet(flags, QEMU_CAPS_MIGRATE_QEMU_TCP);
        qemuCapsSet(flags, QEMU_CAPS_MIGRATE_QEMU_EXEC);
        if (version >= 12000) {
            qemuCapsSet(flags, QEMU_CAPS_MIGRATE_QEMU_UNIX);
            qemuCapsSet(flags, QEMU_CAPS_MIGRATE_QEMU_FD);
        }
    } else if (kvm_version >= 79) {
        qemuCapsSet(flags, QEMU_CAPS_MIGRATE_QEMU_TCP);
        if (kvm_version >= 80)
            qemuCapsSet(flags, QEMU_CAPS_MIGRATE_QEMU_EXEC);
    } else if (kvm_version > 0) {
        qemuCapsSet(flags, QEMU_CAPS_MIGRATE_KVM_STDIO);
    }

    if (version >= 10000)
        qemuCapsSet(flags, QEMU_CAPS_0_10);

    if (version >= 11000)
        qemuCapsSet(flags, QEMU_CAPS_VIRTIO_BLK_SG_IO);

    /* While JSON mode was available in 0.12.0, it was too
     * incomplete to contemplate using. The 0.13.0 release
     * is good enough to use, even though it lacks one or
     * two features. This is also true of versions of qemu
     * built for RHEL, labeled 0.12.1, but with extra text
     * in the help output that mentions that features were
     * backported for libvirt. The benefits of JSON mode now
     * outweigh the downside.
     */
#if HAVE_YAJL
    if (version >= 13000) {
        qemuCapsSet(flags, QEMU_CAPS_MONITOR_JSON);
    } else if (version >= 12000 &&
               strstr(help, "libvirt")) {
        qemuCapsSet(flags, QEMU_CAPS_MONITOR_JSON);
        qemuCapsSet(flags, QEMU_CAPS_NETDEV);
    }
#else
    /* Starting with qemu 0.15 and newer, upstream qemu no longer
     * promises to keep the human interface stable, but requests that
     * we use QMP (the JSON interface) for everything.  If the user
     * forgot to include YAJL libraries when building their own
     * libvirt but is targetting a newer qemu, we are better off
     * telling them to recompile (the spec file includes the
     * dependency, so distros won't hit this).  */
    if (version >= 15000 ||
        (version >= 12000 && strstr(help, "libvirt"))) {
        if (check_yajl) {
            qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                            _("this qemu binary requires libvirt to be "
                              "compiled with yajl"));
            return -1;
        }
        qemuCapsSet(flags, QEMU_CAPS_NETDEV);
    }
#endif

    if (version >= 13000)
        qemuCapsSet(flags, QEMU_CAPS_PCI_MULTIFUNCTION);

    /* Although very new versions of qemu advertise the presence of
     * the rombar option in the output of "qemu -device pci-assign,?",
     * this advertisement was added to the code long after the option
     * itself. According to qemu developers, though, rombar is
     * available in all qemu binaries from release 0.12 onward.
     * Setting the capability this way makes it available in more
     * cases where it might be needed, and shouldn't cause any false
     * positives (in the case that it did, qemu would produce an error
     * log and refuse to start, so it would be immediately obvious).
     */
    if (version >= 12000)
        qemuCapsSet(flags, QEMU_CAPS_PCI_ROMBAR);

    if (version >= 11000)
        qemuCapsSet(flags, QEMU_CAPS_CPU_HOST);
    return 0;
}

/* We parse the output of 'qemu -help' to get the QEMU
 * version number. The first bit is easy, just parse
 * 'QEMU PC emulator version x.y.z'
 * or
 * 'QEMU emulator version x.y.z'.
 *
 * With qemu-kvm, however, that is followed by a string
 * in parenthesis as follows:
 *  - qemu-kvm-x.y.z in stable releases
 *  - kvm-XX for kvm versions up to kvm-85
 *  - qemu-kvm-devel-XX for kvm version kvm-86 and later
 *
 * For qemu-kvm versions before 0.10.z, we need to detect
 * the KVM version number for some features. With 0.10.z
 * and later, we just need the QEMU version number and
 * whether it is KVM QEMU or mainline QEMU.
 */
#define QEMU_VERSION_STR_1  "QEMU emulator version"
#define QEMU_VERSION_STR_2  "QEMU PC emulator version"
#define QEMU_KVM_VER_PREFIX "(qemu-kvm-"
#define KVM_VER_PREFIX      "(kvm-"

#define SKIP_BLANKS(p) do { while ((*(p) == ' ') || (*(p) == '\t')) (p)++; } while (0)

int qemuCapsParseHelpStr(const char *qemu,
                         const char *help,
                         virBitmapPtr flags,
                         unsigned int *version,
                         unsigned int *is_kvm,
                         unsigned int *kvm_version,
                         bool check_yajl)
{
    unsigned major, minor, micro;
    const char *p = help;
    char *strflags;

    *version = *is_kvm = *kvm_version = 0;

    if (STRPREFIX(p, QEMU_VERSION_STR_1))
        p += strlen(QEMU_VERSION_STR_1);
    else if (STRPREFIX(p, QEMU_VERSION_STR_2))
        p += strlen(QEMU_VERSION_STR_2);
    else
        goto fail;

    SKIP_BLANKS(p);

    major = virParseNumber(&p);
    if (major == -1 || *p != '.')
        goto fail;

    ++p;

    minor = virParseNumber(&p);
    if (minor == -1)
        goto fail;

    if (*p != '.') {
        micro = 0;
    } else {
        ++p;
        micro = virParseNumber(&p);
        if (micro == -1)
            goto fail;
    }

    SKIP_BLANKS(p);

    if (STRPREFIX(p, QEMU_KVM_VER_PREFIX)) {
        *is_kvm = 1;
        p += strlen(QEMU_KVM_VER_PREFIX);
    } else if (STRPREFIX(p, KVM_VER_PREFIX)) {
        int ret;

        *is_kvm = 1;
        p += strlen(KVM_VER_PREFIX);

        ret = virParseNumber(&p);
        if (ret == -1)
            goto fail;

        *kvm_version = ret;
    }

    *version = (major * 1000 * 1000) + (minor * 1000) + micro;

    if (qemuCapsComputeCmdFlags(help, *version, *is_kvm, *kvm_version,
                                flags, check_yajl) < 0)
        goto cleanup;

    strflags = virBitmapString(flags);
    VIR_DEBUG("Version %u.%u.%u, cooked version %u, flags %s",
              major, minor, micro, *version, NULLSTR(strflags));
    VIR_FREE(strflags);

    if (*kvm_version)
        VIR_DEBUG("KVM version %d detected", *kvm_version);
    else if (*is_kvm)
        VIR_DEBUG("qemu-kvm version %u.%u.%u detected", major, minor, micro);

    return 0;

fail:
    p = strchr(help, '\n');
    if (!p)
        p = strchr(help, '\0');

    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                    _("cannot parse %s version number in '%.*s'"),
                    qemu, (int) (p - help), help);

cleanup:
    return -1;
}

static int
qemuCapsExtractDeviceStr(const char *qemu,
                         virBitmapPtr flags)
{
    char *output = NULL;
    virCommandPtr cmd;
    int ret = -1;

    /* Cram together all device-related queries into one invocation;
     * the output format makes it possible to distinguish what we
     * need.  With qemu 0.13.0 and later, unrecognized '-device
     * bogus,?' cause an error in isolation, but are silently ignored
     * in combination with '-device ?'.  Upstream qemu 0.12.x doesn't
     * understand '-device name,?', and always exits with status 1 for
     * the simpler '-device ?', so this function is really only useful
     * if -help includes "device driver,?".  */
    cmd = virCommandNewArgList(qemu,
                               "-device", "?",
                               "-device", "pci-assign,?",
                               "-device", "virtio-blk-pci,?",
                               "-device", "virtio-net-pci,?",
                               "-device", "scsi-disk,?",
                               NULL);
    virCommandAddEnvPassCommon(cmd);
    /* qemu -help goes to stdout, but qemu -device ? goes to stderr.  */
    virCommandSetErrorBuffer(cmd, &output);
    virCommandClearCaps(cmd);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = qemuCapsParseDeviceStr(output, flags);

cleanup:
    VIR_FREE(output);
    virCommandFree(cmd);
    return ret;
}


int
qemuCapsParseDeviceStr(const char *str, virBitmapPtr flags)
{
    /* Which devices exist. */
    if (strstr(str, "name \"hda-duplex\""))
        qemuCapsSet(flags, QEMU_CAPS_HDA_DUPLEX);
    if (strstr(str, "name \"ccid-card-emulated\""))
        qemuCapsSet(flags, QEMU_CAPS_CCID_EMULATED);
    if (strstr(str, "name \"ccid-card-passthru\""))
        qemuCapsSet(flags, QEMU_CAPS_CCID_PASSTHRU);

    if (strstr(str, "name \"piix3-usb-uhci\""))
        qemuCapsSet(flags, QEMU_CAPS_PIIX3_USB_UHCI);
    if (strstr(str, "name \"piix4-usb-uhci\""))
        qemuCapsSet(flags, QEMU_CAPS_PIIX4_USB_UHCI);
    if (strstr(str, "name \"usb-ehci\""))
        qemuCapsSet(flags, QEMU_CAPS_USB_EHCI);
    if (strstr(str, "name \"ich9-usb-ehci1\""))
        qemuCapsSet(flags, QEMU_CAPS_ICH9_USB_EHCI1);
    if (strstr(str, "name \"vt82c686b-usb-uhci\""))
        qemuCapsSet(flags, QEMU_CAPS_VT82C686B_USB_UHCI);
    if (strstr(str, "name \"pci-ohci\""))
        qemuCapsSet(flags, QEMU_CAPS_PCI_OHCI);
    if (strstr(str, "name \"usb-redir\""))
        qemuCapsSet(flags, QEMU_CAPS_USB_REDIR);
    if (strstr(str, "name \"usb-hub\""))
        qemuCapsSet(flags, QEMU_CAPS_USB_HUB);
    if (strstr(str, "name \"ich9-ahci\""))
        qemuCapsSet(flags, QEMU_CAPS_ICH9_AHCI);

    /* Prefer -chardev spicevmc (detected earlier) over -device spicevmc */
    if (!qemuCapsGet(flags, QEMU_CAPS_CHARDEV_SPICEVMC) &&
        strstr(str, "name \"spicevmc\""))
        qemuCapsSet(flags, QEMU_CAPS_DEVICE_SPICEVMC);

    /* Features of given devices. */
    if (strstr(str, "pci-assign.configfd"))
        qemuCapsSet(flags, QEMU_CAPS_PCI_CONFIGFD);
    if (strstr(str, "virtio-blk-pci.multifunction"))
        qemuCapsSet(flags, QEMU_CAPS_PCI_MULTIFUNCTION);
    if (strstr(str, "virtio-blk-pci.bootindex")) {
        qemuCapsSet(flags, QEMU_CAPS_BOOTINDEX);
        if (strstr(str, "pci-assign.bootindex"))
            qemuCapsSet(flags, QEMU_CAPS_PCI_BOOTINDEX);
    }
    if (strstr(str, "virtio-net-pci.tx="))
        qemuCapsSet(flags, QEMU_CAPS_VIRTIO_TX_ALG);
    if (strstr(str, "name \"qxl-vga\""))
        qemuCapsSet(flags, QEMU_CAPS_DEVICE_QXL_VGA);
    if (strstr(str, "virtio-blk-pci.ioeventfd"))
        qemuCapsSet(flags, QEMU_CAPS_VIRTIO_IOEVENTFD);
    if (strstr(str, "name \"sga\""))
        qemuCapsSet(flags, QEMU_CAPS_SGA);
    if (strstr(str, "virtio-blk-pci.event_idx"))
        qemuCapsSet(flags, QEMU_CAPS_VIRTIO_BLK_EVENT_IDX);
    if (strstr(str, "virtio-net-pci.event_idx"))
        qemuCapsSet(flags, QEMU_CAPS_VIRTIO_NET_EVENT_IDX);
    if (strstr(str, "virtio-blk-pci.scsi"))
        qemuCapsSet(flags, QEMU_CAPS_VIRTIO_BLK_SCSI);
    if (strstr(str, "scsi-disk.channel"))
        qemuCapsSet(flags, QEMU_CAPS_SCSI_DISK_CHANNEL);
    if (strstr(str, "scsi-block"))
        qemuCapsSet(flags, QEMU_CAPS_SCSI_BLOCK);

    return 0;
}

int qemuCapsExtractVersionInfo(const char *qemu, const char *arch,
                               unsigned int *retversion,
                               virBitmapPtr *retflags)
{
    int ret = -1;
    unsigned int version, is_kvm, kvm_version;
    virBitmapPtr flags = NULL;
    char *help = NULL;
    virCommandPtr cmd;

    if (retflags)
        *retflags = NULL;
    if (retversion)
        *retversion = 0;

    /* Make sure the binary we are about to try exec'ing exists.
     * Technically we could catch the exec() failure, but that's
     * in a sub-process so it's hard to feed back a useful error.
     */
    if (!virFileIsExecutable(qemu)) {
        virReportSystemError(errno, _("Cannot find QEMU binary %s"), qemu);
        return -1;
    }

    cmd = virCommandNewArgList(qemu, "-help", NULL);
    virCommandAddEnvPassCommon(cmd);
    virCommandSetOutputBuffer(cmd, &help);
    virCommandClearCaps(cmd);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (!(flags = qemuCapsNew()) ||
        qemuCapsParseHelpStr(qemu, help, flags,
                             &version, &is_kvm, &kvm_version, true) == -1)
        goto cleanup;

    /* Currently only x86_64 and i686 support PCI-multibus. */
    if (STREQLEN(arch, "x86_64", 6) ||
        STREQLEN(arch, "i686", 4)) {
        qemuCapsSet(flags, QEMU_CAPS_PCI_MULTIBUS);
    }

    /* qemuCapsExtractDeviceStr will only set additional flags if qemu
     * understands the 0.13.0+ notion of "-device driver,".  */
    if (qemuCapsGet(flags, QEMU_CAPS_DEVICE) &&
        strstr(help, "-device driver,?") &&
        qemuCapsExtractDeviceStr(qemu, flags) < 0)
        goto cleanup;

    if (retversion)
        *retversion = version;
    if (retflags) {
        *retflags = flags;
        flags = NULL;
    }

    ret = 0;

cleanup:
    VIR_FREE(help);
    virCommandFree(cmd);
    qemuCapsFree(flags);

    return ret;
}

static void
uname_normalize (struct utsname *ut)
{
    uname(ut);

    /* Map i386, i486, i586 to i686.  */
    if (ut->machine[0] == 'i' &&
        ut->machine[1] != '\0' &&
        ut->machine[2] == '8' &&
        ut->machine[3] == '6' &&
        ut->machine[4] == '\0')
        ut->machine[1] = '6';
}

int qemuCapsExtractVersion(virCapsPtr caps,
                           unsigned int *version)
{
    const char *binary;
    struct stat sb;
    struct utsname ut;

    if (*version > 0)
        return 0;

    uname_normalize(&ut);
    if ((binary = virCapabilitiesDefaultGuestEmulator(caps,
                                                      "hvm",
                                                      ut.machine,
                                                      "qemu")) == NULL) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("Cannot find suitable emulator for %s"), ut.machine);
        return -1;
    }

    if (stat(binary, &sb) < 0) {
        virReportSystemError(errno,
                             _("Cannot find QEMU binary %s"), binary);
        return -1;
    }

    if (qemuCapsExtractVersionInfo(binary, ut.machine, version, NULL) < 0) {
        return -1;
    }

    return 0;
}


virBitmapPtr
qemuCapsNew(void)
{
    virBitmapPtr caps;

    if (!(caps = virBitmapAlloc(QEMU_CAPS_LAST)))
        virReportOOMError();

    return caps;
}


void
qemuCapsSet(virBitmapPtr caps,
            enum qemuCapsFlags flag)
{
    ignore_value(virBitmapSetBit(caps, flag));
}


void
qemuCapsSetList(virBitmapPtr caps, ...)
{
    va_list list;
    int flag;

    va_start(list, caps);
    while ((flag = va_arg(list, int)) < QEMU_CAPS_LAST)
        ignore_value(virBitmapSetBit(caps, flag));
    va_end(list);
}


void
qemuCapsClear(virBitmapPtr caps,
              enum qemuCapsFlags flag)
{
    ignore_value(virBitmapClearBit(caps, flag));
}


bool
qemuCapsGet(virBitmapPtr caps,
            enum qemuCapsFlags flag)
{
    bool b;

    if (!caps || virBitmapGetBit(caps, flag, &b) < 0)
        return false;
    else
        return b;
}
