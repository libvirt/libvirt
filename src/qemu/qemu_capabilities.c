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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
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
#include "virpidfile.h"
#include "virprocess.h"
#include "nodeinfo.h"
#include "cpu/cpu.h"
#include "domain_conf.h"
#include "command.h"
#include "bitmap.h"
#include "virnodesuspend.h"
#include "qemu_monitor.h"

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

              "block-job-sync", /* 90 */
              "block-job-async",
              "scsi-cd",
              "ide-cd",
              "no-user-config",

              "hda-micro", /* 95 */
              "dump-guest-memory",
              "nec-usb-xhci",
              "virtio-s390",
              "balloon-event",

              "bridge", /* 100 */
              "lsi",
              "virtio-scsi-pci",
              "blockio",
              "disable-s3",

              "disable-s4", /* 105 */
              "usb-redir.filter",
              "ide-drive.wwn",
              "scsi-disk.wwn",
              "seccomp-sandbox",

              "reboot-timeout", /* 110 */
              "dump-guest-core",
              "seamless-migration",
              "block-commit",
              "vnc",

              "drive-mirror", /* 115 */
    );

struct _qemuCaps {
    virObject object;

    bool usedQMP;

    char *binary;
    time_t mtime;

    virBitmapPtr flags;

    unsigned int version;
    unsigned int kvmVersion;

    char *arch;

    size_t ncpuDefinitions;
    char **cpuDefinitions;

    size_t nmachineTypes;
    char **machineTypes;
    char **machineAliases;
};

struct _qemuCapsCache {
    virMutex lock;
    virHashTablePtr binaries;
    char *libDir;
    char *runDir;
};


static virClassPtr qemuCapsClass;
static void qemuCapsDispose(void *obj);

static int qemuCapsOnceInit(void)
{
    if (!(qemuCapsClass = virClassNew("qemuCaps",
                                      sizeof(qemuCaps),
                                      qemuCapsDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(qemuCaps)

static virCommandPtr
qemuCapsProbeCommand(const char *qemu,
                     qemuCapsPtr caps)
{
    virCommandPtr cmd = virCommandNew(qemu);

    if (caps) {
        if (qemuCapsGet(caps, QEMU_CAPS_NO_USER_CONFIG))
            virCommandAddArg(cmd, "-no-user-config");
        else if (qemuCapsGet(caps, QEMU_CAPS_NODEFCONFIG))
            virCommandAddArg(cmd, "-nodefconfig");
    }

    virCommandAddEnvPassCommon(cmd);
    virCommandClearCaps(cmd);

    return cmd;
}


/* Format is:
 * <machine> <desc> [(default)|(alias of <canonical>)]
 */
static int
qemuCapsParseMachineTypesStr(const char *output,
                             qemuCapsPtr caps)
{
    const char *p = output;
    const char *next;
    size_t defIdx = 0;

    do {
        const char *t;
        char *name;
        char *canonical = NULL;

        if ((next = strchr(p, '\n')))
            ++next;

        if (STRPREFIX(p, "Supported machines are:"))
            continue;

        if (!(t = strchr(p, ' ')) || (next && t >= next))
            continue;

        if (!(name = strndup(p, t - p)))
            goto no_memory;

        p = t;
        if ((t = strstr(p, "(default)")) && (!next || t < next))
            defIdx = caps->nmachineTypes;

        if ((t = strstr(p, "(alias of ")) && (!next || t < next)) {
            p = t + strlen("(alias of ");
            if (!(t = strchr(p, ')')) || (next && t >= next))
                continue;

            if (!(canonical = strndup(p, t - p))) {
                VIR_FREE(name);
                goto no_memory;
            }
        }

        if (VIR_REALLOC_N(caps->machineTypes, caps->nmachineTypes + 1) < 0 ||
            VIR_REALLOC_N(caps->machineAliases, caps->nmachineTypes + 1) < 0) {
            VIR_FREE(name);
            VIR_FREE(canonical);
            goto no_memory;
        }
        caps->nmachineTypes++;
        if (canonical) {
            caps->machineTypes[caps->nmachineTypes-1] = canonical;
            caps->machineAliases[caps->nmachineTypes-1] = name;
        } else {
            caps->machineTypes[caps->nmachineTypes-1] = name;
            caps->machineAliases[caps->nmachineTypes-1] = NULL;
        }
    } while ((p = next));


    if (defIdx != 0) {
        char *name = caps->machineTypes[defIdx];
        char *alias = caps->machineAliases[defIdx];
        memmove(caps->machineTypes + 1,
                caps->machineTypes,
                sizeof(caps->machineTypes[0]) * defIdx);
        memmove(caps->machineAliases + 1,
                caps->machineAliases,
                sizeof(caps->machineAliases[0]) * defIdx);
        caps->machineTypes[0] = name;
        caps->machineAliases[0] = alias;
    }

    return 0;

no_memory:
    virReportOOMError();
    return -1;
}

static int
qemuCapsProbeMachineTypes(qemuCapsPtr caps)
{
    char *output;
    int ret = -1;
    virCommandPtr cmd;
    int status;

    /* Make sure the binary we are about to try exec'ing exists.
     * Technically we could catch the exec() failure, but that's
     * in a sub-process so it's hard to feed back a useful error.
     */
    if (!virFileIsExecutable(caps->binary)) {
        virReportSystemError(errno, _("Cannot find QEMU binary %s"),
                             caps->binary);
        return -1;
    }

    cmd = qemuCapsProbeCommand(caps->binary, caps);
    virCommandAddArgList(cmd, "-M", "?", NULL);
    virCommandSetOutputBuffer(cmd, &output);

    /* Ignore failure from older qemu that did not understand '-M ?'.  */
    if (virCommandRun(cmd, &status) < 0)
        goto cleanup;

    if (qemuCapsParseMachineTypesStr(output, caps) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    VIR_FREE(output);
    virCommandFree(cmd);

    return ret;
}


typedef int
(*qemuCapsParseCPUModels)(const char *output,
                          qemuCapsPtr caps);

/* Format:
 *      <arch> <model>
 * qemu-0.13 encloses some model names in []:
 *      <arch> [<model>]
 */
static int
qemuCapsParseX86Models(const char *output,
                       qemuCapsPtr caps)
{
    const char *p = output;
    const char *next;
    int ret = -1;

    do {
        const char *t;
        size_t len;

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

        if (VIR_EXPAND_N(caps->cpuDefinitions, caps->ncpuDefinitions, 1) < 0) {
            virReportOOMError();
            goto cleanup;
        }

        if (next)
            len = next - p - 1;
        else
            len = strlen(p);

        if (len > 2 && *p == '[' && p[len - 1] == ']') {
            p++;
            len -= 2;
        }

        if (!(caps->cpuDefinitions[caps->ncpuDefinitions - 1] = strndup(p, len))) {
            virReportOOMError();
            goto cleanup;
        }
    } while ((p = next));

    ret = 0;

cleanup:
    return ret;
}

/* ppc64 parser.
 * Format : PowerPC <machine> <description>
 */
static int
qemuCapsParsePPCModels(const char *output,
                       qemuCapsPtr caps)
{
    const char *p = output;
    const char *next;
    int ret = -1;

    do {
        const char *t;
        size_t len;

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

        if (VIR_EXPAND_N(caps->cpuDefinitions, caps->ncpuDefinitions, 1) < 0) {
            virReportOOMError();
            goto cleanup;
        }

        len = t - p - 1;

        if (!(caps->cpuDefinitions[caps->ncpuDefinitions - 1] = strndup(p, len))) {
            virReportOOMError();
            goto cleanup;
        }
    } while ((p = next));

    ret = 0;

cleanup:
    return ret;
}

static int
qemuCapsProbeCPUModels(qemuCapsPtr caps)
{
    char *output = NULL;
    int ret = -1;
    qemuCapsParseCPUModels parse;
    virCommandPtr cmd;

    if (STREQ(caps->arch, "i686") ||
        STREQ(caps->arch, "x86_64"))
        parse = qemuCapsParseX86Models;
    else if (STREQ(caps->arch, "ppc64"))
        parse = qemuCapsParsePPCModels;
    else {
        VIR_DEBUG("don't know how to parse %s CPU models",
                  caps->arch);
        return 0;
    }

    cmd = qemuCapsProbeCommand(caps->binary, caps);
    virCommandAddArgList(cmd, "-cpu", "?", NULL);
    virCommandSetOutputBuffer(cmd, &output);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (parse(output, caps) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    VIR_FREE(output);
    virCommandFree(cmd);

    return ret;
}


static char *
qemuCapsFindBinaryForArch(const char *hostarch,
                          const char *guestarch)
{
    char *ret;

    if (STREQ(guestarch, "i686")) {
        ret = virFindFileInPath("qemu-system-i386");
        if (ret && !virFileIsExecutable(ret))
            VIR_FREE(ret);

        if (!ret && STREQ(hostarch, "x86_64")) {
            ret = virFindFileInPath("qemu-system-x86_64");
            if (ret && !virFileIsExecutable(ret))
                VIR_FREE(ret);
        }

        if (!ret)
            ret = virFindFileInPath("qemu");
    } else if (STREQ(guestarch, "itanium")) {
        ret = virFindFileInPath("qemu-system-ia64");
    } else {
        char *bin;
        if (virAsprintf(&bin, "qemu-system-%s", guestarch) < 0) {
            virReportOOMError();
            return NULL;
        }
        ret = virFindFileInPath(bin);
        VIR_FREE(bin);
    }
    if (ret && !virFileIsExecutable(ret))
        VIR_FREE(ret);
    return ret;
}

static int
qemuCapsGetArchWordSize(const char *guestarch)
{
    if (STREQ(guestarch, "i686") ||
        STREQ(guestarch, "ppc") ||
        STREQ(guestarch, "sparc") ||
        STREQ(guestarch, "mips") ||
        STREQ(guestarch, "mipsel"))
        return 32;
    return 64;
}

static bool
qemuCapsIsValidForKVM(const char *hostarch,
                      const char *guestarch)
{
    if (STREQ(hostarch, guestarch))
        return true;
    if (STREQ(hostarch, "x86_64") &&
        STREQ(guestarch, "i686"))
        return true;
    return false;
}

static int
qemuCapsInitGuest(virCapsPtr caps,
                  qemuCapsCachePtr cache,
                  const char *hostarch,
                  const char *guestarch)
{
    virCapsGuestPtr guest;
    int i;
    int haskvm = 0;
    int haskqemu = 0;
    char *kvmbin = NULL;
    char *binary = NULL;
    virCapsGuestMachinePtr *machines = NULL;
    size_t nmachines = 0;
    qemuCapsPtr qemubinCaps = NULL;
    qemuCapsPtr kvmbinCaps = NULL;
    int ret = -1;

    /* Check for existence of base emulator, or alternate base
     * which can be used with magic cpu choice
     */
    binary = qemuCapsFindBinaryForArch(hostarch, guestarch);

    /* Ignore binary if extracting version info fails */
    if (binary) {
        if (!(qemubinCaps = qemuCapsCacheLookup(cache, binary))) {
            virResetLastError();
            VIR_FREE(binary);
        }
    }

    /* qemu-kvm/kvm binaries can only be used if
     *  - host & guest arches match
     * Or
     *  - hostarch is x86_64 and guest arch is i686
     * The latter simply needs "-cpu qemu32"
     */
    if (qemuCapsIsValidForKVM(hostarch, guestarch)) {
        const char *const kvmbins[] = { "/usr/libexec/qemu-kvm", /* RHEL */
                                        "qemu-kvm", /* Fedora */
                                        "kvm" }; /* Upstream .spec */

        for (i = 0; i < ARRAY_CARDINALITY(kvmbins); ++i) {
            kvmbin = virFindFileInPath(kvmbins[i]);

            if (!kvmbin)
                continue;

            if (!(kvmbinCaps = qemuCapsCacheLookup(cache, kvmbin))) {
                virResetLastError();
                VIR_FREE(kvmbin);
                continue;
            }

            if (!binary) {
                binary = kvmbin;
                qemubinCaps = kvmbinCaps;
                kvmbin = NULL;
                kvmbinCaps = NULL;
            }
            break;
        }
    }

    if (!binary)
        return 0;

    if (access("/dev/kvm", F_OK) == 0 &&
        (qemuCapsGet(qemubinCaps, QEMU_CAPS_KVM) ||
         qemuCapsGet(qemubinCaps, QEMU_CAPS_ENABLE_KVM) ||
         kvmbin))
        haskvm = 1;

    if (access("/dev/kqemu", F_OK) == 0 &&
        qemuCapsGet(qemubinCaps, QEMU_CAPS_KQEMU))
        haskqemu = 1;

    if (qemuCapsGetMachineTypesCaps(qemubinCaps, &nmachines, &machines) < 0)
        goto error;

    /* We register kvm as the base emulator too, since we can
     * just give -no-kvm to disable acceleration if required */
    if ((guest = virCapabilitiesAddGuest(caps,
                                         "hvm",
                                         guestarch,
                                         qemuCapsGetArchWordSize(guestarch),
                                         binary,
                                         NULL,
                                         nmachines,
                                         machines)) == NULL)
        goto error;

    machines = NULL;
    nmachines = 0;

    if (caps->host.cpu &&
        caps->host.cpu->model &&
        qemuCapsGetCPUDefinitions(qemubinCaps, NULL) > 0 &&
        !virCapabilitiesAddGuestFeature(guest, "cpuselection", 1, 0))
        goto error;

    if (qemuCapsGet(qemubinCaps, QEMU_CAPS_BOOTINDEX) &&
        !virCapabilitiesAddGuestFeature(guest, "deviceboot", 1, 0))
        goto error;

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

        if (kvmbin &&
            qemuCapsGetMachineTypesCaps(kvmbinCaps, &nmachines, &machines) < 0)
            goto error;

        if ((dom = virCapabilitiesAddGuestDomain(guest,
                                                 "kvm",
                                                 kvmbin ? kvmbin : binary,
                                                 NULL,
                                                 nmachines,
                                                 machines)) == NULL) {
            goto error;
        }

        machines = NULL;
        nmachines = 0;

    }

    if ((STREQ(guestarch, "i686") ||
         STREQ(guestarch, "x86_64")) &&
        (virCapabilitiesAddGuestFeature(guest, "acpi", 1, 1) == NULL ||
         virCapabilitiesAddGuestFeature(guest, "apic", 1, 0) == NULL))
        goto error;

    if (STREQ(guestarch, "i686") &&
        (virCapabilitiesAddGuestFeature(guest, "pae", 1, 0) == NULL ||
         virCapabilitiesAddGuestFeature(guest, "nonpae", 1, 0) == NULL))
        goto error;

    ret = 0;

cleanup:
    VIR_FREE(binary);
    VIR_FREE(kvmbin);
    virObjectUnref(qemubinCaps);
    virObjectUnref(kvmbinCaps);

    return ret;

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
    caps->host.cpu = cpu;

    if (!(data = cpuNodeData(arch))
        || cpuDecode(cpu, data, NULL, 0, NULL) < 0)
        goto cleanup;

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


virCapsPtr qemuCapsInit(qemuCapsCachePtr cache)
{
    struct utsname utsname;
    virCapsPtr caps;
    int i;
    const char *const arches[] = {
        "i686", "x86_64", "arm",
        "microblaze", "microblazeel",
        "mips", "mipsel", "sparc",
        "ppc", "ppc64", "itanium",
        "s390x"
    };

    /* Really, this never fails - look at the man-page. */
    uname (&utsname);

    if ((caps = virCapabilitiesNew(utsname.machine,
                                   1, 1)) == NULL)
        goto error;

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

    if (qemuCapsInitCPU(caps, utsname.machine) < 0)
        VIR_WARN("Failed to get host CPU");

    /* Add the power management features of the host */

    if (virNodeSuspendGetTargetMask(&caps->host.powerMgmt) < 0)
        VIR_WARN("Failed to get host power management capabilities");

    virCapabilitiesAddHostMigrateTransport(caps,
                                           "tcp");

    /* First the pure HVM guests */
    for (i = 0 ; i < ARRAY_CARDINALITY(arches) ; i++)
        if (qemuCapsInitGuest(caps, cache,
                              utsname.machine,
                              arches[i]) < 0)
            goto error;

    /* QEMU Requires an emulator in the XML */
    virCapabilitiesSetEmulatorRequired(caps);

    caps->defaultConsoleTargetType = qemuDefaultConsoleType;

    return caps;

error:
    virCapabilitiesFree(caps);
    return NULL;
}


static int
qemuCapsComputeCmdFlags(const char *help,
                        unsigned int version,
                        unsigned int is_kvm,
                        unsigned int kvm_version,
                        qemuCapsPtr caps,
                        bool check_yajl ATTRIBUTE_UNUSED)
{
    const char *p;
    const char *fsdev, *netdev;

    if (strstr(help, "-no-kqemu"))
        qemuCapsSet(caps, QEMU_CAPS_KQEMU);
    if (strstr(help, "-enable-kqemu"))
        qemuCapsSet(caps, QEMU_CAPS_ENABLE_KQEMU);
    if (strstr(help, "-no-kvm"))
        qemuCapsSet(caps, QEMU_CAPS_KVM);
    if (strstr(help, "-enable-kvm"))
        qemuCapsSet(caps, QEMU_CAPS_ENABLE_KVM);
    if (strstr(help, "-no-reboot"))
        qemuCapsSet(caps, QEMU_CAPS_NO_REBOOT);
    if (strstr(help, "-name")) {
        qemuCapsSet(caps, QEMU_CAPS_NAME);
        if (strstr(help, ",process="))
            qemuCapsSet(caps, QEMU_CAPS_NAME_PROCESS);
    }
    if (strstr(help, "-uuid"))
        qemuCapsSet(caps, QEMU_CAPS_UUID);
    if (strstr(help, "-xen-domid"))
        qemuCapsSet(caps, QEMU_CAPS_XEN_DOMID);
    else if (strstr(help, "-domid"))
        qemuCapsSet(caps, QEMU_CAPS_DOMID);
    if (strstr(help, "-drive")) {
        const char *cache = strstr(help, "cache=");

        qemuCapsSet(caps, QEMU_CAPS_DRIVE);
        if (cache && (p = strchr(cache, ']'))) {
            if (memmem(cache, p - cache, "on|off", sizeof("on|off") - 1) == NULL)
                qemuCapsSet(caps, QEMU_CAPS_DRIVE_CACHE_V2);
            if (memmem(cache, p - cache, "directsync", sizeof("directsync") - 1))
                qemuCapsSet(caps, QEMU_CAPS_DRIVE_CACHE_DIRECTSYNC);
            if (memmem(cache, p - cache, "unsafe", sizeof("unsafe") - 1))
                qemuCapsSet(caps, QEMU_CAPS_DRIVE_CACHE_UNSAFE);
        }
        if (strstr(help, "format="))
            qemuCapsSet(caps, QEMU_CAPS_DRIVE_FORMAT);
        if (strstr(help, "readonly="))
            qemuCapsSet(caps, QEMU_CAPS_DRIVE_READONLY);
        if (strstr(help, "aio=threads|native"))
            qemuCapsSet(caps, QEMU_CAPS_DRIVE_AIO);
        if (strstr(help, "copy-on-read=on|off"))
            qemuCapsSet(caps, QEMU_CAPS_DRIVE_COPY_ON_READ);
        if (strstr(help, "bps="))
            qemuCapsSet(caps, QEMU_CAPS_DRIVE_IOTUNE);
    }
    if ((p = strstr(help, "-vga")) && !strstr(help, "-std-vga")) {
        const char *nl = strstr(p, "\n");

        qemuCapsSet(caps, QEMU_CAPS_VGA);

        if (strstr(p, "|qxl"))
            qemuCapsSet(caps, QEMU_CAPS_VGA_QXL);
        if ((p = strstr(p, "|none")) && p < nl)
            qemuCapsSet(caps, QEMU_CAPS_VGA_NONE);
    }
    if (strstr(help, "-spice"))
        qemuCapsSet(caps, QEMU_CAPS_SPICE);
    if (strstr(help, "-vnc"))
        qemuCapsSet(caps, QEMU_CAPS_VNC);
    if (strstr(help, "seamless-migration="))
        qemuCapsSet(caps, QEMU_CAPS_SEAMLESS_MIGRATION);
    if (strstr(help, "boot=on"))
        qemuCapsSet(caps, QEMU_CAPS_DRIVE_BOOT);
    if (strstr(help, "serial=s"))
        qemuCapsSet(caps, QEMU_CAPS_DRIVE_SERIAL);
    if (strstr(help, "-pcidevice"))
        qemuCapsSet(caps, QEMU_CAPS_PCIDEVICE);
    if (strstr(help, "-mem-path"))
        qemuCapsSet(caps, QEMU_CAPS_MEM_PATH);
    if (strstr(help, "-chardev")) {
        qemuCapsSet(caps, QEMU_CAPS_CHARDEV);
        if (strstr(help, "-chardev spicevmc"))
            qemuCapsSet(caps, QEMU_CAPS_CHARDEV_SPICEVMC);
    }
    if (strstr(help, "-balloon"))
        qemuCapsSet(caps, QEMU_CAPS_BALLOON);
    if (strstr(help, "-device")) {
        qemuCapsSet(caps, QEMU_CAPS_DEVICE);
        /*
         * When -device was introduced, qemu already supported drive's
         * readonly option but didn't advertise that.
         */
        qemuCapsSet(caps, QEMU_CAPS_DRIVE_READONLY);
    }
    if (strstr(help, "-nodefconfig"))
        qemuCapsSet(caps, QEMU_CAPS_NODEFCONFIG);
    if (strstr(help, "-no-user-config"))
        qemuCapsSet(caps, QEMU_CAPS_NO_USER_CONFIG);
    /* The trailing ' ' is important to avoid a bogus match */
    if (strstr(help, "-rtc "))
        qemuCapsSet(caps, QEMU_CAPS_RTC);
    /* to wit */
    if (strstr(help, "-rtc-td-hack"))
        qemuCapsSet(caps, QEMU_CAPS_RTC_TD_HACK);
    if (strstr(help, "-no-hpet"))
        qemuCapsSet(caps, QEMU_CAPS_NO_HPET);
    if (strstr(help, "-no-acpi"))
        qemuCapsSet(caps, QEMU_CAPS_NO_ACPI);
    if (strstr(help, "-no-kvm-pit-reinjection"))
        qemuCapsSet(caps, QEMU_CAPS_NO_KVM_PIT);
    if (strstr(help, "-tdf"))
        qemuCapsSet(caps, QEMU_CAPS_TDF);
    if (strstr(help, "-enable-nesting"))
        qemuCapsSet(caps, QEMU_CAPS_NESTING);
    if (strstr(help, ",menu=on"))
        qemuCapsSet(caps, QEMU_CAPS_BOOT_MENU);
    if (strstr(help, ",reboot-timeout=rb_time"))
        qemuCapsSet(caps, QEMU_CAPS_REBOOT_TIMEOUT);
    if ((fsdev = strstr(help, "-fsdev"))) {
        qemuCapsSet(caps, QEMU_CAPS_FSDEV);
        if (strstr(fsdev, "readonly"))
            qemuCapsSet(caps, QEMU_CAPS_FSDEV_READONLY);
        if (strstr(fsdev, "writeout"))
            qemuCapsSet(caps, QEMU_CAPS_FSDEV_WRITEOUT);
    }
    if (strstr(help, "-smbios type"))
        qemuCapsSet(caps, QEMU_CAPS_SMBIOS_TYPE);
    if (strstr(help, "-sandbox"))
        qemuCapsSet(caps, QEMU_CAPS_SECCOMP_SANDBOX);

    if ((netdev = strstr(help, "-netdev"))) {
        /* Disable -netdev on 0.12 since although it exists,
         * the corresponding netdev_add/remove monitor commands
         * do not, and we need them to be able to do hotplug.
         * But see below about RHEL build. */
        if (version >= 13000) {
            if (strstr(netdev, "bridge"))
                qemuCapsSet(caps, QEMU_CAPS_NETDEV_BRIDGE);
           qemuCapsSet(caps, QEMU_CAPS_NETDEV);
        }
    }

    if (strstr(help, "-sdl"))
        qemuCapsSet(caps, QEMU_CAPS_SDL);
    if (strstr(help, "cores=") &&
        strstr(help, "threads=") &&
        strstr(help, "sockets="))
        qemuCapsSet(caps, QEMU_CAPS_SMP_TOPOLOGY);

    if (version >= 9000)
        qemuCapsSet(caps, QEMU_CAPS_VNC_COLON);

    if (is_kvm && (version >= 10000 || kvm_version >= 74))
        qemuCapsSet(caps, QEMU_CAPS_VNET_HDR);

    if (strstr(help, ",vhost=")) {
        qemuCapsSet(caps, QEMU_CAPS_VHOST_NET);
    }

    /* Do not use -no-shutdown if qemu doesn't support it or SIGTERM handling
     * is most likely buggy when used with -no-shutdown (which applies for qemu
     * 0.14.* and 0.15.0)
     */
    if (strstr(help, "-no-shutdown") && (version < 14000 || version > 15000))
        qemuCapsSet(caps, QEMU_CAPS_NO_SHUTDOWN);

    if (strstr(help, "dump-guest-core=on|off"))
        qemuCapsSet(caps, QEMU_CAPS_DUMP_GUEST_CORE);

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
        qemuCapsSet(caps, QEMU_CAPS_MIGRATE_QEMU_TCP);
        qemuCapsSet(caps, QEMU_CAPS_MIGRATE_QEMU_EXEC);
        if (version >= 12000) {
            qemuCapsSet(caps, QEMU_CAPS_MIGRATE_QEMU_UNIX);
            qemuCapsSet(caps, QEMU_CAPS_MIGRATE_QEMU_FD);
        }
    } else if (kvm_version >= 79) {
        qemuCapsSet(caps, QEMU_CAPS_MIGRATE_QEMU_TCP);
        if (kvm_version >= 80)
            qemuCapsSet(caps, QEMU_CAPS_MIGRATE_QEMU_EXEC);
    } else if (kvm_version > 0) {
        qemuCapsSet(caps, QEMU_CAPS_MIGRATE_KVM_STDIO);
    }

    if (version >= 10000)
        qemuCapsSet(caps, QEMU_CAPS_0_10);

    if (version >= 11000)
        qemuCapsSet(caps, QEMU_CAPS_VIRTIO_BLK_SG_IO);

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
        qemuCapsSet(caps, QEMU_CAPS_MONITOR_JSON);
    } else if (version >= 12000 &&
               strstr(help, "libvirt")) {
        qemuCapsSet(caps, QEMU_CAPS_MONITOR_JSON);
        qemuCapsSet(caps, QEMU_CAPS_NETDEV);
    }
#else
    /* Starting with qemu 0.15 and newer, upstream qemu no longer
     * promises to keep the human interface stable, but requests that
     * we use QMP (the JSON interface) for everything.  If the user
     * forgot to include YAJL libraries when building their own
     * libvirt but is targetting a newer qemu, we are better off
     * telling them to recompile (the spec file includes the
     * dependency, so distros won't hit this).  This check is
     * also in configure.ac (see $with_yajl).  */
    if (version >= 15000 ||
        (version >= 12000 && strstr(help, "libvirt"))) {
        if (check_yajl) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("this qemu binary requires libvirt to be "
                             "compiled with yajl"));
            return -1;
        }
        qemuCapsSet(caps, QEMU_CAPS_NETDEV);
    }
#endif

    if (version >= 13000)
        qemuCapsSet(caps, QEMU_CAPS_PCI_MULTIFUNCTION);

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
        qemuCapsSet(caps, QEMU_CAPS_PCI_ROMBAR);

    if (version >= 11000)
        qemuCapsSet(caps, QEMU_CAPS_CPU_HOST);
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
                         qemuCapsPtr caps,
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
                                caps, check_yajl) < 0)
        goto cleanup;

    strflags = virBitmapString(caps->flags);
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

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("cannot parse %s version number in '%.*s'"),
                   qemu, (int) (p - help), help);

cleanup:
    return -1;
}


struct qemuCapsStringFlags {
    const char *value;
    int flag;
};


struct qemuCapsStringFlags qemuCapsObjectTypes[] = {
    { "hda-duplex", QEMU_CAPS_HDA_DUPLEX },
    { "hda-micro", QEMU_CAPS_HDA_MICRO },
    { "ccid-card-emulated", QEMU_CAPS_CCID_EMULATED },
    { "ccid-card-passthru", QEMU_CAPS_CCID_PASSTHRU },
    { "piix3-usb-uhci", QEMU_CAPS_PIIX3_USB_UHCI },
    { "piix4-usb-uhci", QEMU_CAPS_PIIX4_USB_UHCI },
    { "usb-ehci", QEMU_CAPS_USB_EHCI },
    { "ich9-usb-ehci1", QEMU_CAPS_ICH9_USB_EHCI1 },
    { "vt82c686b-usb-uhci", QEMU_CAPS_VT82C686B_USB_UHCI },
    { "pci-ohci", QEMU_CAPS_PCI_OHCI },
    { "nec-usb-xhci", QEMU_CAPS_NEC_USB_XHCI },
    { "usb-redir", QEMU_CAPS_USB_REDIR },
    { "usb-hub", QEMU_CAPS_USB_HUB },
    { "ich9-ahci", QEMU_CAPS_ICH9_AHCI },
    { "virtio-blk-s390", QEMU_CAPS_VIRTIO_S390 },
    { "lsi53c895a", QEMU_CAPS_SCSI_LSI },
    { "virtio-scsi-pci", QEMU_CAPS_VIRTIO_SCSI_PCI },
    { "spicevmc", QEMU_CAPS_DEVICE_SPICEVMC },
    { "qxl-vga", QEMU_CAPS_DEVICE_QXL_VGA },
    { "qxl", QEMU_CAPS_VGA_QXL },
    { "sga", QEMU_CAPS_SGA },
    { "scsi-block", QEMU_CAPS_SCSI_BLOCK },
    { "scsi-cd", QEMU_CAPS_SCSI_CD },
    { "ide-cd", QEMU_CAPS_IDE_CD },
};


static struct qemuCapsStringFlags qemuCapsObjectPropsVirtioBlk[] = {
    { "multifunction", QEMU_CAPS_PCI_MULTIFUNCTION },
    { "bootindex", QEMU_CAPS_BOOTINDEX },
    { "ioeventfd", QEMU_CAPS_VIRTIO_IOEVENTFD },
    { "event_idx", QEMU_CAPS_VIRTIO_BLK_EVENT_IDX },
    { "scsi", QEMU_CAPS_VIRTIO_BLK_SCSI },
    { "logical_block_size", QEMU_CAPS_BLOCKIO },
};

static struct qemuCapsStringFlags qemuCapsObjectPropsVirtioNet[] = {
    { "tx", QEMU_CAPS_VIRTIO_TX_ALG },
    { "event_idx", QEMU_CAPS_VIRTIO_NET_EVENT_IDX },
};

static struct qemuCapsStringFlags qemuCapsObjectPropsPciAssign[] = {
    { "rombar", QEMU_CAPS_PCI_ROMBAR },
    { "configfd", QEMU_CAPS_PCI_CONFIGFD },
    { "bootindex", QEMU_CAPS_PCI_BOOTINDEX },
};

static struct qemuCapsStringFlags qemuCapsObjectPropsScsiDisk[] = {
    { "channel", QEMU_CAPS_SCSI_DISK_CHANNEL },
    { "wwn", QEMU_CAPS_SCSI_DISK_WWN },
};

static struct qemuCapsStringFlags qemuCapsObjectPropsIDEDrive[] = {
    { "wwn", QEMU_CAPS_IDE_DRIVE_WWN },
};

static struct qemuCapsStringFlags qemuCapsObjectPropsPixx4PM[] = {
    { "disable_s3", QEMU_CAPS_DISABLE_S3 },
    { "disable_s4", QEMU_CAPS_DISABLE_S4 },
};

static struct qemuCapsStringFlags qemuCapsObjectPropsUsbRedir[] = {
    { "filter", QEMU_CAPS_USB_REDIR_FILTER },
};

struct qemuCapsObjectTypeProps {
    const char *type;
    struct qemuCapsStringFlags *props;
    size_t nprops;
};

static struct qemuCapsObjectTypeProps qemuCapsObjectProps[] = {
    { "virtio-blk-pci", qemuCapsObjectPropsVirtioBlk,
      ARRAY_CARDINALITY(qemuCapsObjectPropsVirtioBlk) },
    { "virtio-net-pci", qemuCapsObjectPropsVirtioNet,
      ARRAY_CARDINALITY(qemuCapsObjectPropsVirtioNet) },
    { "pci-assign", qemuCapsObjectPropsPciAssign,
      ARRAY_CARDINALITY(qemuCapsObjectPropsPciAssign) },
    { "kvm-pci-assign", qemuCapsObjectPropsPciAssign,
      ARRAY_CARDINALITY(qemuCapsObjectPropsPciAssign) },
    { "scsi-disk", qemuCapsObjectPropsScsiDisk,
      ARRAY_CARDINALITY(qemuCapsObjectPropsScsiDisk) },
    { "ide-drive", qemuCapsObjectPropsIDEDrive,
      ARRAY_CARDINALITY(qemuCapsObjectPropsIDEDrive) },
    { "PIIX4_PM", qemuCapsObjectPropsPixx4PM,
      ARRAY_CARDINALITY(qemuCapsObjectPropsPixx4PM) },
    { "usb-redir", qemuCapsObjectPropsUsbRedir,
      ARRAY_CARDINALITY(qemuCapsObjectPropsUsbRedir) },
};


static void
qemuCapsProcessStringFlags(qemuCapsPtr caps,
                           size_t nflags,
                           struct qemuCapsStringFlags *flags,
                           size_t nvalues,
                           char *const*values)
{
    size_t i, j;
    for (i = 0 ; i < nflags ; i++) {
        for (j = 0 ; j < nvalues ; j++) {
            if (STREQ(values[j], flags[i].value)) {
                qemuCapsSet(caps, flags[i].flag);
                break;
            }
        }
    }
}


static void
qemuCapsFreeStringList(size_t len,
                       char **values)
{
    size_t i;
    for (i = 0 ; i < len ; i++)
        VIR_FREE(values[i]);
    VIR_FREE(values);
}


#define OBJECT_TYPE_PREFIX "name \""

static int
qemuCapsParseDeviceStrObjectTypes(const char *str,
                                  char ***types)
{
    const char *tmp = str;
    int ret = -1;
    size_t ntypelist = 0;
    char **typelist = NULL;

    *types = NULL;

    while ((tmp = strstr(tmp, OBJECT_TYPE_PREFIX))) {
        char *end;
        tmp += strlen(OBJECT_TYPE_PREFIX);
        end = strstr(tmp, "\"");
        if (!end) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Malformed QEMU device list string, missing quote"));
            goto cleanup;
        }

        if (VIR_EXPAND_N(typelist, ntypelist, 1) < 0) {
            virReportOOMError();
            goto cleanup;
        }
        if (!(typelist[ntypelist-1] = strndup(tmp, end-tmp))) {
            virReportOOMError();
            goto cleanup;
        }
    }

    *types = typelist;
    ret = ntypelist;

cleanup:
    if (ret < 0)
        qemuCapsFreeStringList(ntypelist, typelist);
    return ret;
}


static int
qemuCapsParseDeviceStrObjectProps(const char *str,
                                  const char *type,
                                  char ***props)
{
    const char *tmp = str;
    int ret = -1;
    size_t nproplist = 0;
    char **proplist = NULL;

    VIR_DEBUG("Extract type %s", type);
    *props = NULL;

    while ((tmp = strchr(tmp, '\n'))) {
        char *end;
        tmp += 1;

        if (*tmp == '\0')
            break;

        if (STRPREFIX(tmp, OBJECT_TYPE_PREFIX))
            continue;

        if (!STRPREFIX(tmp, type))
            continue;

        tmp += strlen(type);
        if (*tmp != '.')
            continue;
        tmp++;

        end = strstr(tmp, "=");
        if (!end) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Malformed QEMU device list string, missing '='"));
            goto cleanup;
        }
        if (VIR_EXPAND_N(proplist, nproplist, 1) < 0) {
            virReportOOMError();
            goto cleanup;
        }
        if (!(proplist[nproplist-1] = strndup(tmp, end-tmp))) {
            virReportOOMError();
            goto cleanup;
        }
    }

    *props = proplist;
    ret = nproplist;

cleanup:
    if (ret < 0)
        qemuCapsFreeStringList(nproplist, proplist);
    return ret;
}


int
qemuCapsParseDeviceStr(qemuCapsPtr caps, const char *str)
{
    int nvalues;
    char **values;
    size_t i;

    if ((nvalues = qemuCapsParseDeviceStrObjectTypes(str, &values)) < 0)
        return -1;
    qemuCapsProcessStringFlags(caps,
                               ARRAY_CARDINALITY(qemuCapsObjectTypes),
                               qemuCapsObjectTypes,
                               nvalues, values);
    qemuCapsFreeStringList(nvalues, values);

    for (i = 0 ; i < ARRAY_CARDINALITY(qemuCapsObjectProps); i++) {
        const char *type = qemuCapsObjectProps[i].type;
        if ((nvalues = qemuCapsParseDeviceStrObjectProps(str,
                                                         type,
                                                         &values)) < 0)
            return -1;
        qemuCapsProcessStringFlags(caps,
                                   qemuCapsObjectProps[i].nprops,
                                   qemuCapsObjectProps[i].props,
                                   nvalues, values);
        qemuCapsFreeStringList(nvalues, values);
    }

    /* Prefer -chardev spicevmc (detected earlier) over -device spicevmc */
    if (qemuCapsGet(caps, QEMU_CAPS_CHARDEV_SPICEVMC))
        qemuCapsClear(caps, QEMU_CAPS_DEVICE_SPICEVMC);

    return 0;
}


static int
qemuCapsExtractDeviceStr(const char *qemu,
                         qemuCapsPtr caps)
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
    cmd = qemuCapsProbeCommand(qemu, caps);
    virCommandAddArgList(cmd,
                         "-device", "?",
                         "-device", "pci-assign,?",
                         "-device", "virtio-blk-pci,?",
                         "-device", "virtio-net-pci,?",
                         "-device", "scsi-disk,?",
                         "-device", "PIIX4_PM,?",
                         "-device", "usb-redir,?",
                         "-device", "ide-drive,?",
                         NULL);
    /* qemu -help goes to stdout, but qemu -device ? goes to stderr.  */
    virCommandSetErrorBuffer(cmd, &output);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = qemuCapsParseDeviceStr(caps, output);

cleanup:
    VIR_FREE(output);
    virCommandFree(cmd);
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

int qemuCapsGetDefaultVersion(virCapsPtr caps,
                              qemuCapsCachePtr capsCache,
                              unsigned int *version)
{
    const char *binary;
    struct utsname ut;
    qemuCapsPtr qemucaps;

    if (*version > 0)
        return 0;

    uname_normalize(&ut);
    if ((binary = virCapabilitiesDefaultGuestEmulator(caps,
                                                      "hvm",
                                                      ut.machine,
                                                      "qemu")) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot find suitable emulator for %s"), ut.machine);
        return -1;
    }

    if (!(qemucaps = qemuCapsCacheLookup(capsCache, binary)))
        return -1;

    *version = qemuCapsGetVersion(qemucaps);
    virObjectUnref(qemucaps);
    return 0;
}




qemuCapsPtr
qemuCapsNew(void)
{
    qemuCapsPtr caps;

    if (qemuCapsInitialize() < 0)
        return NULL;

    if (!(caps = virObjectNew(qemuCapsClass)))
        return NULL;

    if (!(caps->flags = virBitmapNew(QEMU_CAPS_LAST)))
        goto no_memory;

    return caps;

no_memory:
    virReportOOMError();
    virObjectUnref(caps);
    return NULL;
}


qemuCapsPtr qemuCapsNewCopy(qemuCapsPtr caps)
{
    qemuCapsPtr ret = qemuCapsNew();
    size_t i;

    if (!ret)
        return NULL;

    virBitmapCopy(ret->flags, caps->flags);

    ret->version = caps->version;
    ret->kvmVersion = caps->kvmVersion;

    if (caps->arch &&
        !(ret->arch = strdup(caps->arch)))
        goto no_memory;

    if (VIR_ALLOC_N(ret->cpuDefinitions, caps->ncpuDefinitions) < 0)
        goto no_memory;
    ret->ncpuDefinitions = caps->ncpuDefinitions;
    for (i = 0 ; i < caps->ncpuDefinitions ; i++) {
        if (!(ret->cpuDefinitions[i] = strdup(caps->cpuDefinitions[i])))
            goto no_memory;
    }

    if (VIR_ALLOC_N(ret->machineTypes, caps->nmachineTypes) < 0)
        goto no_memory;
    if (VIR_ALLOC_N(ret->machineAliases, caps->nmachineTypes) < 0)
        goto no_memory;
    ret->nmachineTypes = caps->nmachineTypes;
    for (i = 0 ; i < caps->nmachineTypes ; i++) {
        if (!(ret->machineTypes[i] = strdup(caps->machineTypes[i])))
            goto no_memory;
        if (caps->machineAliases[i] &&
            !(ret->machineAliases[i] = strdup(caps->machineAliases[i])))
            goto no_memory;
    }

    return ret;

no_memory:
    virReportOOMError();
    virObjectUnref(ret);
    return NULL;
}


void qemuCapsDispose(void *obj)
{
    qemuCapsPtr caps = obj;
    size_t i;

    VIR_FREE(caps->arch);

    for (i = 0 ; i < caps->nmachineTypes ; i++) {
        VIR_FREE(caps->machineTypes[i]);
        VIR_FREE(caps->machineAliases[i]);
    }
    VIR_FREE(caps->machineTypes);
    VIR_FREE(caps->machineAliases);

    for (i = 0 ; i < caps->ncpuDefinitions ; i++) {
        VIR_FREE(caps->cpuDefinitions[i]);
    }
    VIR_FREE(caps->cpuDefinitions);

    virBitmapFree(caps->flags);

    VIR_FREE(caps->binary);
}

void
qemuCapsSet(qemuCapsPtr caps,
            enum qemuCapsFlags flag)
{
    ignore_value(virBitmapSetBit(caps->flags, flag));
}


void
qemuCapsSetList(qemuCapsPtr caps, ...)
{
    va_list list;
    int flag;

    va_start(list, caps);
    while ((flag = va_arg(list, int)) < QEMU_CAPS_LAST)
        ignore_value(virBitmapSetBit(caps->flags, flag));
    va_end(list);
}


void
qemuCapsClear(qemuCapsPtr caps,
              enum qemuCapsFlags flag)
{
    ignore_value(virBitmapClearBit(caps->flags, flag));
}


char *qemuCapsFlagsString(qemuCapsPtr caps)
{
    return virBitmapString(caps->flags);
}


bool
qemuCapsGet(qemuCapsPtr caps,
            enum qemuCapsFlags flag)
{
    bool b;

    if (!caps || virBitmapGetBit(caps->flags, flag, &b) < 0)
        return false;
    else
        return b;
}


const char *qemuCapsGetBinary(qemuCapsPtr caps)
{
    return caps->binary;
}

const char *qemuCapsGetArch(qemuCapsPtr caps)
{
    return caps->arch;
}


unsigned int qemuCapsGetVersion(qemuCapsPtr caps)
{
    return caps->version;
}


unsigned int qemuCapsGetKVMVersion(qemuCapsPtr caps)
{
    return caps->kvmVersion;
}


int qemuCapsAddCPUDefinition(qemuCapsPtr caps,
                             const char *name)
{
    char *tmp = strdup(name);
    if (!tmp) {
        virReportOOMError();
        return -1;
    }
    if (VIR_EXPAND_N(caps->cpuDefinitions, caps->ncpuDefinitions, 1) < 0) {
        VIR_FREE(tmp);
        virReportOOMError();
        return -1;
    }
    caps->cpuDefinitions[caps->ncpuDefinitions-1] = tmp;
    return 0;
}


size_t qemuCapsGetCPUDefinitions(qemuCapsPtr caps,
                                 char ***names)
{
    if (names)
        *names = caps->cpuDefinitions;
    return caps->ncpuDefinitions;
}


size_t qemuCapsGetMachineTypes(qemuCapsPtr caps,
                               char ***names)
{
    if (names)
        *names = caps->machineTypes;
    return caps->nmachineTypes;
}

int qemuCapsGetMachineTypesCaps(qemuCapsPtr caps,
                                size_t *nmachines,
                                virCapsGuestMachinePtr **machines)
{
    size_t i;

    *nmachines = 0;
    *machines = NULL;
    if (VIR_ALLOC_N(*machines, caps->nmachineTypes) < 0)
        goto no_memory;
    *nmachines = caps->nmachineTypes;

    for (i = 0 ; i < caps->nmachineTypes ; i++) {
        virCapsGuestMachinePtr mach;
        if (VIR_ALLOC(mach) < 0)
            goto no_memory;
        if (caps->machineAliases[i]) {
            if (!(mach->name = strdup(caps->machineAliases[i])))
                goto no_memory;
            if (!(mach->canonical = strdup(caps->machineTypes[i])))
                goto no_memory;
        } else {
            if (!(mach->name = strdup(caps->machineTypes[i])))
                goto no_memory;
        }
        (*machines)[i] = mach;
    }

    return 0;

no_memory:
    virCapabilitiesFreeMachines(*machines, *nmachines);
    *nmachines = 0;
    *machines = NULL;
    return -1;
}




const char *qemuCapsGetCanonicalMachine(qemuCapsPtr caps,
                                        const char *name)

{
    size_t i;

    for (i = 0 ; i < caps->nmachineTypes ; i++) {
        if (!caps->machineAliases[i])
            continue;
        if (STREQ(caps->machineAliases[i], name))
            return caps->machineTypes[i];
    }

    return name;
}


static int
qemuCapsProbeQMPCommands(qemuCapsPtr caps,
                         qemuMonitorPtr mon)
{
    char **commands = NULL;
    int ncommands;
    size_t i;

    if ((ncommands = qemuMonitorGetCommands(mon, &commands)) < 0)
        return -1;

    for (i = 0 ; i < ncommands ; i++) {
        char *name = commands[i];
        if (STREQ(name, "system_wakeup"))
            qemuCapsSet(caps, QEMU_CAPS_WAKEUP);
        else if (STREQ(name, "transaction"))
            qemuCapsSet(caps, QEMU_CAPS_TRANSACTION);
        else if (STREQ(name, "block_job_cancel"))
            qemuCapsSet(caps, QEMU_CAPS_BLOCKJOB_SYNC);
        else if (STREQ(name, "block-job-cancel"))
            qemuCapsSet(caps, QEMU_CAPS_BLOCKJOB_ASYNC);
        else if (STREQ(name, "dump-guest-memory"))
            qemuCapsSet(caps, QEMU_CAPS_DUMP_GUEST_MEMORY);
        else if (STREQ(name, "query-spice"))
            qemuCapsSet(caps, QEMU_CAPS_SPICE);
        else if (STREQ(name, "query-kvm"))
            qemuCapsSet(caps, QEMU_CAPS_KVM);
        else if (STREQ(name, "block-commit"))
            qemuCapsSet(caps, QEMU_CAPS_BLOCK_COMMIT);
        else if (STREQ(name, "query-vnc"))
            qemuCapsSet(caps, QEMU_CAPS_VNC);
        else if (STREQ(name, "drive-mirror"))
            qemuCapsSet(caps, QEMU_CAPS_DRIVE_MIRROR);
        VIR_FREE(name);
    }
    VIR_FREE(commands);

    return 0;
}


static int
qemuCapsProbeQMPEvents(qemuCapsPtr caps,
                       qemuMonitorPtr mon)
{
    char **events = NULL;
    int nevents;
    size_t i;

    if ((nevents = qemuMonitorGetEvents(mon, &events)) < 0)
        return -1;

    for (i = 0 ; i < nevents ; i++) {
        char *name = events[i];

        if (STREQ(name, "BALLOON_CHANGE"))
            qemuCapsSet(caps, QEMU_CAPS_BALLOON_EVENT);
        if (STREQ(name, "SPICE_MIGRATE_COMPLETED"))
            qemuCapsSet(caps, QEMU_CAPS_SEAMLESS_MIGRATION);
        VIR_FREE(name);
    }
    VIR_FREE(events);

    return 0;
}


static int
qemuCapsProbeQMPObjects(qemuCapsPtr caps,
                        qemuMonitorPtr mon)
{
    int nvalues;
    char **values;
    size_t i;

    if ((nvalues = qemuMonitorGetObjectTypes(mon, &values)) < 0)
        return -1;
    qemuCapsProcessStringFlags(caps,
                               ARRAY_CARDINALITY(qemuCapsObjectTypes),
                               qemuCapsObjectTypes,
                               nvalues, values);
    qemuCapsFreeStringList(nvalues, values);

    for (i = 0 ; i < ARRAY_CARDINALITY(qemuCapsObjectProps); i++) {
        const char *type = qemuCapsObjectProps[i].type;
        if ((nvalues = qemuMonitorGetObjectProps(mon,
                                                 type,
                                                 &values)) < 0)
            return -1;
        qemuCapsProcessStringFlags(caps,
                                   qemuCapsObjectProps[i].nprops,
                                   qemuCapsObjectProps[i].props,
                                   nvalues, values);
        qemuCapsFreeStringList(nvalues, values);
    }

    /* Prefer -chardev spicevmc (detected earlier) over -device spicevmc */
    if (qemuCapsGet(caps, QEMU_CAPS_CHARDEV_SPICEVMC))
        qemuCapsClear(caps, QEMU_CAPS_DEVICE_SPICEVMC);

    return 0;
}


static int
qemuCapsProbeQMPMachineTypes(qemuCapsPtr caps,
                             qemuMonitorPtr mon)
{
    qemuMonitorMachineInfoPtr *machines = NULL;
    int nmachines = 0;
    int ret = -1;
    size_t i;

    if ((nmachines = qemuMonitorGetMachines(mon, &machines)) < 0)
        goto cleanup;

    if (VIR_ALLOC_N(caps->machineTypes, nmachines) < 0) {
        virReportOOMError();
        goto cleanup;
    }
    if (VIR_ALLOC_N(caps->machineAliases, nmachines) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    for (i = 0 ; i < nmachines ; i++) {
        if (machines[i]->alias) {
            if (!(caps->machineAliases[i] = strdup(machines[i]->name))) {
                virReportOOMError();
                goto cleanup;
            }
            if (!(caps->machineTypes[i] = strdup(machines[i]->alias))) {
                virReportOOMError();
                goto cleanup;
            }
        } else {
            if (!(caps->machineTypes[i] = strdup(machines[i]->name))) {
                virReportOOMError();
                goto cleanup;
            }
        }
    }

    ret = 0;

cleanup:
    for (i = 0 ; i < nmachines ; i++)
        qemuMonitorMachineInfoFree(machines[i]);
    VIR_FREE(machines);
    return ret;
}


static int
qemuCapsProbeQMPCPUDefinitions(qemuCapsPtr caps,
                               qemuMonitorPtr mon)
{
    int ncpuDefinitions;
    char **cpuDefinitions;

    if ((ncpuDefinitions = qemuMonitorGetCPUDefinitions(mon, &cpuDefinitions)) < 0)
        return -1;

    caps->ncpuDefinitions = ncpuDefinitions;
    caps->cpuDefinitions = cpuDefinitions;

    return 0;
}


int qemuCapsProbeQMP(qemuCapsPtr caps,
                     qemuMonitorPtr mon)
{
    VIR_DEBUG("caps=%p mon=%p", caps, mon);

    if (caps->usedQMP)
        return 0;

    if (qemuCapsProbeQMPCommands(caps, mon) < 0)
        return -1;

    if (qemuCapsProbeQMPEvents(caps, mon) < 0)
        return -1;

    return 0;
}


#define QEMU_SYSTEM_PREFIX "qemu-system-"

static int
qemuCapsInitHelp(qemuCapsPtr caps)
{
    virCommandPtr cmd = NULL;
    unsigned int is_kvm;
    char *help = NULL;
    int ret = -1;
    const char *tmp;
    struct utsname ut;

    VIR_DEBUG("caps=%p", caps);

    tmp = strstr(caps->binary, QEMU_SYSTEM_PREFIX);
    if (tmp) {
        tmp += strlen(QEMU_SYSTEM_PREFIX);

        /* For historical compat we use 'itanium' as arch name */
        if (STREQ(tmp, "ia64"))
            tmp = "itanium";
        else if (STREQ(tmp, "i386"))
            tmp = "i686";
    } else {
        uname_normalize(&ut);
        tmp = ut.machine;
    }
    if (!(caps->arch = strdup(tmp))) {
        virReportOOMError();
        goto cleanup;
    }

    cmd = qemuCapsProbeCommand(caps->binary, NULL);
    virCommandAddArgList(cmd, "-help", NULL);
    virCommandSetOutputBuffer(cmd, &help);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (qemuCapsParseHelpStr(caps->binary,
                             help, caps,
                             &caps->version,
                             &is_kvm,
                             &caps->kvmVersion,
                             false) < 0)
        goto cleanup;

    /* Currently only x86_64 and i686 support PCI-multibus. */
    if (STREQLEN(caps->arch, "x86_64", 6) ||
        STREQLEN(caps->arch, "i686", 4)) {
        qemuCapsSet(caps, QEMU_CAPS_PCI_MULTIBUS);
    }

    /* S390 and probably other archs do not support no-acpi -
       maybe the qemu option parsing should be re-thought. */
    if (STRPREFIX(caps->arch, "s390"))
        qemuCapsClear(caps, QEMU_CAPS_NO_ACPI);

    /* qemuCapsExtractDeviceStr will only set additional caps if qemu
     * understands the 0.13.0+ notion of "-device driver,".  */
    if (qemuCapsGet(caps, QEMU_CAPS_DEVICE) &&
        strstr(help, "-device driver,?") &&
        qemuCapsExtractDeviceStr(caps->binary, caps) < 0)
        goto cleanup;

    if (qemuCapsProbeCPUModels(caps) < 0)
        goto cleanup;

    if (qemuCapsProbeMachineTypes(caps) < 0)
        goto cleanup;

    ret = 0;
cleanup:
    virCommandFree(cmd);
    VIR_FREE(help);
    return ret;
}


static void qemuCapsMonitorNotify(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                                  virDomainObjPtr vm ATTRIBUTE_UNUSED)
{
}

static qemuMonitorCallbacks callbacks = {
    .eofNotify = qemuCapsMonitorNotify,
    .errorNotify = qemuCapsMonitorNotify,
};


/* Capabilities that we assume are always enabled
 * for QEMU >= 1.2.0
 */
static void
qemuCapsInitQMPBasic(qemuCapsPtr caps)
{
    qemuCapsSet(caps, QEMU_CAPS_VNC_COLON);
    qemuCapsSet(caps, QEMU_CAPS_NO_REBOOT);
    qemuCapsSet(caps, QEMU_CAPS_DRIVE);
    qemuCapsSet(caps, QEMU_CAPS_NAME);
    qemuCapsSet(caps, QEMU_CAPS_UUID);
    qemuCapsSet(caps, QEMU_CAPS_VNET_HDR);
    qemuCapsSet(caps, QEMU_CAPS_MIGRATE_QEMU_TCP);
    qemuCapsSet(caps, QEMU_CAPS_MIGRATE_QEMU_EXEC);
    qemuCapsSet(caps, QEMU_CAPS_DRIVE_CACHE_V2);
    qemuCapsSet(caps, QEMU_CAPS_DRIVE_FORMAT);
    qemuCapsSet(caps, QEMU_CAPS_VGA);
    qemuCapsSet(caps, QEMU_CAPS_0_10);
    qemuCapsSet(caps, QEMU_CAPS_MEM_PATH);
    qemuCapsSet(caps, QEMU_CAPS_DRIVE_SERIAL);
    qemuCapsSet(caps, QEMU_CAPS_MIGRATE_QEMU_UNIX);
    qemuCapsSet(caps, QEMU_CAPS_CHARDEV);
    qemuCapsSet(caps, QEMU_CAPS_ENABLE_KVM);
    qemuCapsSet(caps, QEMU_CAPS_MONITOR_JSON);
    qemuCapsSet(caps, QEMU_CAPS_BALLOON);
    qemuCapsSet(caps, QEMU_CAPS_DEVICE);
    qemuCapsSet(caps, QEMU_CAPS_SDL);
    qemuCapsSet(caps, QEMU_CAPS_SMP_TOPOLOGY);
    qemuCapsSet(caps, QEMU_CAPS_NETDEV);
    qemuCapsSet(caps, QEMU_CAPS_RTC);
    qemuCapsSet(caps, QEMU_CAPS_VHOST_NET);
    qemuCapsSet(caps, QEMU_CAPS_NO_HPET);
    qemuCapsSet(caps, QEMU_CAPS_NODEFCONFIG);
    qemuCapsSet(caps, QEMU_CAPS_BOOT_MENU);
    qemuCapsSet(caps, QEMU_CAPS_FSDEV);
    qemuCapsSet(caps, QEMU_CAPS_NAME_PROCESS);
    qemuCapsSet(caps, QEMU_CAPS_DRIVE_READONLY);
    qemuCapsSet(caps, QEMU_CAPS_SMBIOS_TYPE);
    qemuCapsSet(caps, QEMU_CAPS_VGA_NONE);
    qemuCapsSet(caps, QEMU_CAPS_MIGRATE_QEMU_FD);
    qemuCapsSet(caps, QEMU_CAPS_DRIVE_AIO);
    qemuCapsSet(caps, QEMU_CAPS_CHARDEV_SPICEVMC);
    qemuCapsSet(caps, QEMU_CAPS_DEVICE_QXL_VGA);
    qemuCapsSet(caps, QEMU_CAPS_DRIVE_CACHE_DIRECTSYNC);
    qemuCapsSet(caps, QEMU_CAPS_NO_SHUTDOWN);
    qemuCapsSet(caps, QEMU_CAPS_DRIVE_CACHE_UNSAFE);
    qemuCapsSet(caps, QEMU_CAPS_NO_ACPI);
    qemuCapsSet(caps, QEMU_CAPS_FSDEV_READONLY);
    qemuCapsSet(caps, QEMU_CAPS_VIRTIO_BLK_SG_IO);
    qemuCapsSet(caps, QEMU_CAPS_DRIVE_COPY_ON_READ);
    qemuCapsSet(caps, QEMU_CAPS_CPU_HOST);
    qemuCapsSet(caps, QEMU_CAPS_FSDEV_WRITEOUT);
    qemuCapsSet(caps, QEMU_CAPS_DRIVE_IOTUNE);
    qemuCapsSet(caps, QEMU_CAPS_WAKEUP);
    qemuCapsSet(caps, QEMU_CAPS_NO_USER_CONFIG);
    qemuCapsSet(caps, QEMU_CAPS_NETDEV_BRIDGE);
}


static int
qemuCapsInitQMP(qemuCapsPtr caps,
                const char *libDir,
                const char *runDir)
{
    int ret = -1;
    virCommandPtr cmd = NULL;
    qemuMonitorPtr mon = NULL;
    int major, minor, micro;
    char *package;
    int status = 0;
    virDomainChrSourceDef config;
    char *monarg = NULL;
    char *monpath = NULL;
    char *pidfile = NULL;

    /* the ".sock" sufix is important to avoid a possible clash with a qemu
     * domain called "capabilities"
     */
    if (virAsprintf(&monpath, "%s/%s", libDir, "capabilities.monitor.sock") < 0) {
        virReportOOMError();
        goto cleanup;
    }
    if (virAsprintf(&monarg, "unix:%s,server,nowait", monpath) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    /* ".pidfile" suffix is used rather than ".pid" to avoid a possible clash
     * with a qemu domain called "capabilities"
     */
    if (virAsprintf(&pidfile, "%s/%s", runDir, "capabilities.pidfile") < 0) {
        virReportOOMError();
        goto cleanup;
    }

    memset(&config, 0, sizeof(config));
    config.type = VIR_DOMAIN_CHR_TYPE_UNIX;
    config.data.nix.path = monpath;
    config.data.nix.listen = false;

    VIR_DEBUG("Try to get caps via QMP caps=%p", caps);

    cmd = virCommandNewArgList(caps->binary,
                               "-S",
                               "-no-user-config",
                               "-nodefaults",
                               "-nographic",
                               "-M", "none",
                               "-qmp", monarg,
                               "-pidfile", pidfile,
                               "-daemonize",
                               NULL);
    virCommandAddEnvPassCommon(cmd);
    virCommandClearCaps(cmd);

    if (virCommandRun(cmd, &status) < 0)
        goto cleanup;

    if (status != 0) {
        ret = 0;
        VIR_DEBUG("QEMU %s exited with status %d", caps->binary, status);
        goto cleanup;
    }

    if (!(mon = qemuMonitorOpen(NULL, &config, true, &callbacks)))
        goto cleanup;

    qemuMonitorLock(mon);

    if (qemuMonitorSetCapabilities(mon) < 0) {
        virErrorPtr err = virGetLastError();
        VIR_DEBUG("Failed to set monitor capabilities %s",
                  err ? err->message : "<unknown problem>");
        ret = 0;
        goto cleanup;
    }

    if (qemuMonitorGetVersion(mon,
                              &major, &minor, &micro,
                              &package) < 0) {
        virErrorPtr err = virGetLastError();
        VIR_DEBUG("Failed to query monitor version %s",
                  err ? err->message : "<unknown problem>");
        ret = 0;
        goto cleanup;
    }

    VIR_DEBUG("Got version %d.%d.%d (%s)",
              major, minor, micro, NULLSTR(package));

    if (!(major >= 1 || (major == 1 && minor >= 1))) {
        VIR_DEBUG("Not new enough for QMP capabilities detection");
        ret = 0;
        goto cleanup;
    }

    caps->usedQMP = true;

    qemuCapsInitQMPBasic(caps);

    if (!(caps->arch = qemuMonitorGetTargetArch(mon)))
        goto cleanup;

    /* Currently only x86_64 and i686 support PCI-multibus. */
    if (STREQLEN(caps->arch, "x86_64", 6) ||
        STREQLEN(caps->arch, "i686", 4)) {
        qemuCapsSet(caps, QEMU_CAPS_PCI_MULTIBUS);
    }

    /* S390 and probably other archs do not support no-acpi -
       maybe the qemu option parsing should be re-thought. */
    if (STRPREFIX(caps->arch, "s390"))
        qemuCapsClear(caps, QEMU_CAPS_NO_ACPI);

    if (qemuCapsProbeQMPCommands(caps, mon) < 0)
        goto cleanup;
    if (qemuCapsProbeQMPEvents(caps, mon) < 0)
        goto cleanup;
    if (qemuCapsProbeQMPObjects(caps, mon) < 0)
        goto cleanup;
    if (qemuCapsProbeQMPMachineTypes(caps, mon) < 0)
        goto cleanup;
    if (qemuCapsProbeQMPCPUDefinitions(caps, mon) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    if (mon)
        qemuMonitorUnlock(mon);
    qemuMonitorClose(mon);
    virCommandAbort(cmd);
    virCommandFree(cmd);
    VIR_FREE(monarg);
    VIR_FREE(monpath);

    if (pidfile) {
        char ebuf[1024];
        pid_t pid;
        int rc;

        if ((rc = virPidFileReadPath(pidfile, &pid)) < 0) {
            VIR_DEBUG("Failed to read pidfile %s: %s",
                      pidfile, virStrerror(-rc, ebuf, sizeof(ebuf)));
        } else {
            VIR_DEBUG("Killing QMP caps process %lld", (long long) pid);
            if (virProcessKill(pid, SIGKILL) < 0 && errno != ESRCH)
                VIR_ERROR(_("Failed to kill process %lld: %s"),
                          (long long) pid,
                          virStrerror(errno, ebuf, sizeof(ebuf)));
        }
        unlink(pidfile);
        VIR_FREE(pidfile);
    }
    return ret;
}


qemuCapsPtr qemuCapsNewForBinary(const char *binary,
                                 const char *libDir,
                                 const char *runDir)
{
    qemuCapsPtr caps = qemuCapsNew();
    struct stat sb;
    int rv;

    if (!(caps->binary = strdup(binary)))
        goto no_memory;

    /* We would also want to check faccessat if we cared about ACLs,
     * but we don't.  */
    if (stat(binary, &sb) < 0) {
        virReportSystemError(errno, _("Cannot check QEMU binary %s"),
                             binary);
        goto error;
    }
    caps->mtime = sb.st_mtime;

    /* Make sure the binary we are about to try exec'ing exists.
     * Technically we could catch the exec() failure, but that's
     * in a sub-process so it's hard to feed back a useful error.
     */
    if (!virFileIsExecutable(binary)) {
        virReportSystemError(errno, _("QEMU binary %s is not executable"),
                             binary);
        goto error;
    }

    if ((rv = qemuCapsInitQMP(caps, libDir, runDir)) < 0)
        goto error;

    if (!caps->usedQMP &&
        qemuCapsInitHelp(caps) < 0)
        goto error;

    return caps;

no_memory:
    virReportOOMError();
error:
    virObjectUnref(caps);
    caps = NULL;
    return NULL;
}


bool qemuCapsIsValid(qemuCapsPtr caps)
{
    struct stat sb;

    if (!caps->binary)
        return true;

    if (stat(caps->binary, &sb) < 0)
        return false;

    return sb.st_mtime == caps->mtime;
}


static void
qemuCapsHashDataFree(void *payload, const void *key ATTRIBUTE_UNUSED)
{
    virObjectUnref(payload);
}


qemuCapsCachePtr
qemuCapsCacheNew(const char *libDir, const char *runDir)
{
    qemuCapsCachePtr cache;

    if (VIR_ALLOC(cache) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (virMutexInit(&cache->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to initialize mutex"));
        VIR_FREE(cache);
        return NULL;
    }

    if (!(cache->binaries = virHashCreate(10, qemuCapsHashDataFree)))
        goto error;
    if (!(cache->libDir = strdup(libDir)) ||
        !(cache->runDir = strdup(runDir))) {
        virReportOOMError();
        goto error;
    }

    return cache;

error:
    qemuCapsCacheFree(cache);
    return NULL;
}


qemuCapsPtr
qemuCapsCacheLookup(qemuCapsCachePtr cache, const char *binary)
{
    qemuCapsPtr ret = NULL;
    virMutexLock(&cache->lock);
    ret = virHashLookup(cache->binaries, binary);
    if (ret &&
        !qemuCapsIsValid(ret)) {
        VIR_DEBUG("Cached capabilities %p no longer valid for %s",
                  ret, binary);
        virHashRemoveEntry(cache->binaries, binary);
        ret = NULL;
    }
    if (!ret) {
        VIR_DEBUG("Creating capabilities for %s",
                  binary);
        ret = qemuCapsNewForBinary(binary, cache->libDir, cache->runDir);
        if (ret) {
            VIR_DEBUG("Caching capabilities %p for %s",
                      ret, binary);
            if (virHashAddEntry(cache->binaries, binary, ret) < 0) {
                virObjectUnref(ret);
                ret = NULL;
            }
        }
    }
    VIR_DEBUG("Returning caps %p for %s", ret, binary);
    virObjectRef(ret);
    virMutexUnlock(&cache->lock);
    return ret;
}


qemuCapsPtr
qemuCapsCacheLookupCopy(qemuCapsCachePtr cache, const char *binary)
{
    qemuCapsPtr caps = qemuCapsCacheLookup(cache, binary);
    qemuCapsPtr ret;

    if (!caps)
        return NULL;

    ret = qemuCapsNewCopy(caps);
    virObjectUnref(caps);
    return ret;
}


void
qemuCapsCacheFree(qemuCapsCachePtr cache)
{
    if (!cache)
        return;

    VIR_FREE(cache->libDir);
    VIR_FREE(cache->runDir);
    virHashFree(cache->binaries);
    virMutexDestroy(&cache->lock);
    VIR_FREE(cache);
}
