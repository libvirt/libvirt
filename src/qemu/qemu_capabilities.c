/*
 * qemu_capabilities.c: QEMU capabilities generation
 *
 * Copyright (C) 2006-2007, 2009-2010 Red Hat, Inc.
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
#include "files.h"
#include "nodeinfo.h"
#include "cpu/cpu.h"
#include "domain_conf.h"
#include "qemu_conf.h"

#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/utsname.h>

#define VIR_FROM_THIS VIR_FROM_QEMU

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
    {  "mips",   32, NULL, "qemu-system-mips",   NULL, NULL, 0 },
    {  "mipsel", 32, NULL, "qemu-system-mipsel", NULL, NULL, 0 },
    {  "sparc",  32, NULL, "qemu-system-sparc",  NULL, NULL, 0 },
    {  "ppc",    32, NULL, "qemu-system-ppc",    NULL, NULL, 0 },
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
    const char *const qemuarg[] = { binary, "-M", "?", NULL };
    const char *const qemuenv[] = { "LC_ALL=C", NULL };
    char *output;
    enum { MAX_MACHINES_OUTPUT_SIZE = 1024*4 };
    pid_t child;
    int newstdout = -1, len;
    int ret = -1, status;

    if (virExec(qemuarg, qemuenv, NULL,
                &child, -1, &newstdout, NULL, VIR_EXEC_CLEAR_CAPS) < 0)
        return -1;

    len = virFileReadLimFD(newstdout, MAX_MACHINES_OUTPUT_SIZE, &output);
    if (len < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to read 'qemu -M ?' output"));
        goto cleanup;
    }

    if (qemuCapsParseMachineTypesStr(output, machines, nmachines) < 0)
        goto cleanup2;

    ret = 0;

cleanup2:
    VIR_FREE(output);
cleanup:
    if (VIR_CLOSE(newstdout) < 0)
        ret = -1;

rewait:
    if (waitpid(child, &status, 0) != child) {
        if (errno == EINTR)
            goto rewait;

        VIR_ERROR(_("Unexpected exit status from qemu %d pid %lu"),
                  WEXITSTATUS(status), (unsigned long)child);
        ret = -1;
    }
    /* Check & log unexpected exit status, but don't fail,
     * as there's really no need to throw an error if we did
     * actually read a valid version number above */
    if (WEXITSTATUS(status) != 0) {
        VIR_WARN("Unexpected exit status '%d', qemu probably failed",
                 WEXITSTATUS(status));
    }

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

            if (VIR_REALLOC_N(cpus, count + 1) < 0)
                goto error;

            if (next)
                len = next - p - 1;
            else
                len = strlen(p);

            if (len > 2 && *p == '[' && p[len - 1] == ']') {
                p++;
                len -= 2;
            }

            if (!(cpus[count] = strndup(p, len)))
                goto error;
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


int
qemuCapsProbeCPUModels(const char *qemu,
                       unsigned long long qemuCmdFlags,
                       const char *arch,
                       unsigned int *count,
                       const char ***cpus)
{
    const char *const qemuarg[] = {
        qemu,
        "-cpu", "?",
        (qemuCmdFlags & QEMUD_CMD_FLAG_NODEFCONFIG) ? "-nodefconfig" : NULL,
        NULL
    };
    const char *const qemuenv[] = { "LC_ALL=C", NULL };
    enum { MAX_MACHINES_OUTPUT_SIZE = 1024*4 };
    char *output = NULL;
    int newstdout = -1;
    int ret = -1;
    pid_t child;
    int status;
    int len;
    qemuCapsParseCPUModels parse;

    if (count)
        *count = 0;
    if (cpus)
        *cpus = NULL;

    if (STREQ(arch, "i686") || STREQ(arch, "x86_64"))
        parse = qemuCapsParseX86Models;
    else {
        VIR_DEBUG("don't know how to parse %s CPU models", arch);
        return 0;
    }

    if (virExec(qemuarg, qemuenv, NULL,
                &child, -1, &newstdout, NULL, VIR_EXEC_CLEAR_CAPS) < 0)
        return -1;

    len = virFileReadLimFD(newstdout, MAX_MACHINES_OUTPUT_SIZE, &output);
    if (len < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to read QEMU supported CPU models"));
        goto cleanup;
    }

    if (parse(output, count, cpus) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FREE(output);
    if (VIR_CLOSE(newstdout) < 0)
        ret = -1;

rewait:
    if (waitpid(child, &status, 0) != child) {
        if (errno == EINTR)
            goto rewait;

        VIR_ERROR(_("Unexpected exit status from qemu %d pid %lu"),
                  WEXITSTATUS(status), (unsigned long)child);
        ret = -1;
    }
    /* Check & log unexpected exit status, but don't fail,
     * as there's really no need to throw an error if we did
     * actually read a valid version number above */
    if (WEXITSTATUS(status) != 0) {
        VIR_WARN("Unexpected exit status '%d', qemu probably failed",
                 WEXITSTATUS(status));
    }

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
    int ret = -1;

    /* Check for existance of base emulator, or alternate base
     * which can be used with magic cpu choice
     */
    binary = virFindFileInPath(info->binary);

    if (binary == NULL || access(binary, X_OK) != 0) {
        VIR_FREE(binary);
        binary = virFindFileInPath(info->altbinary);

        if (binary != NULL && access(binary, X_OK) != 0)
            VIR_FREE(binary);
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

                if (kvmbin == NULL || access(kvmbin, X_OK) != 0) {
                    VIR_FREE(kvmbin);
                    continue;
                }

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
        qemuCapsProbeCPUModels(binary, 0, info->arch, &ncpus, NULL) == 0 &&
        ncpus > 0 &&
        !virCapabilitiesAddGuestFeature(guest, "cpuselection", 1, 0))
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
        VIR_WARN0("Failed to query host NUMA topology, disabling NUMA capabilities");
    }

    if (old_caps == NULL || old_caps->host.cpu == NULL) {
        if (qemuCapsInitCPU(caps, utsname.machine) < 0)
            VIR_WARN0("Failed to get host CPU");
    }
    else {
        caps->host.cpu = old_caps->host.cpu;
        old_caps->host.cpu = NULL;
    }

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

    if (xenner != NULL && access(xenner, X_OK) == 0 &&
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

    caps->defaultConsoleTargetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL;

    return caps;

 no_memory:
    VIR_FREE(xenner);
    virCapabilitiesFree(caps);
    return NULL;
}


static unsigned long long
qemuCapsComputeCmdFlags(const char *help,
                        unsigned int version,
                        unsigned int is_kvm,
                        unsigned int kvm_version)
{
    unsigned long long flags = 0;
    const char *p;

    if (strstr(help, "-no-kqemu"))
        flags |= QEMUD_CMD_FLAG_KQEMU;
    if (strstr(help, "-enable-kqemu"))
        flags |= QEMUD_CMD_FLAG_ENABLE_KQEMU;
    if (strstr(help, "-no-kvm"))
        flags |= QEMUD_CMD_FLAG_KVM;
    if (strstr(help, "-enable-kvm"))
        flags |= QEMUD_CMD_FLAG_ENABLE_KVM;
    if (strstr(help, "-no-reboot"))
        flags |= QEMUD_CMD_FLAG_NO_REBOOT;
    if (strstr(help, "-name")) {
        flags |= QEMUD_CMD_FLAG_NAME;
        if (strstr(help, ",process="))
            flags |= QEMUD_CMD_FLAG_NAME_PROCESS;
    }
    if (strstr(help, "-uuid"))
        flags |= QEMUD_CMD_FLAG_UUID;
    if (strstr(help, "-xen-domid"))
        flags |= QEMUD_CMD_FLAG_XEN_DOMID;
    else if (strstr(help, "-domid"))
        flags |= QEMUD_CMD_FLAG_DOMID;
    if (strstr(help, "-drive")) {
        flags |= QEMUD_CMD_FLAG_DRIVE;
        if (strstr(help, "cache=") &&
            !strstr(help, "cache=on|off"))
            flags |= QEMUD_CMD_FLAG_DRIVE_CACHE_V2;
        if (strstr(help, "format="))
            flags |= QEMUD_CMD_FLAG_DRIVE_FORMAT;
        if (strstr(help, "readonly="))
            flags |= QEMUD_CMD_FLAG_DRIVE_READONLY;
    }
    if ((p = strstr(help, "-vga")) && !strstr(help, "-std-vga")) {
        const char *nl = strstr(p, "\n");

        flags |= QEMUD_CMD_FLAG_VGA;

        if (strstr(p, "|qxl"))
            flags |= QEMUD_CMD_FLAG_VGA_QXL;
        if ((p = strstr(p, "|none")) && p < nl)
            flags |= QEMUD_CMD_FLAG_VGA_NONE;
    }
    if (strstr(help, "-spice"))
        flags |= QEMUD_CMD_FLAG_SPICE;
    if (strstr(help, "boot=on"))
        flags |= QEMUD_CMD_FLAG_DRIVE_BOOT;
    if (strstr(help, "serial=s"))
        flags |= QEMUD_CMD_FLAG_DRIVE_SERIAL;
    if (strstr(help, "-pcidevice"))
        flags |= QEMUD_CMD_FLAG_PCIDEVICE;
    if (strstr(help, "-mem-path"))
        flags |= QEMUD_CMD_FLAG_MEM_PATH;
    if (strstr(help, "-chardev"))
        flags |= QEMUD_CMD_FLAG_CHARDEV;
    if (strstr(help, "-balloon"))
        flags |= QEMUD_CMD_FLAG_BALLOON;
    if (strstr(help, "-device")) {
        flags |= QEMUD_CMD_FLAG_DEVICE;
        /*
         * When -device was introduced, qemu already supported drive's
         * readonly option but didn't advertise that.
         */
        flags |= QEMUD_CMD_FLAG_DRIVE_READONLY;
    }
    if (strstr(help, "-nodefconfig"))
        flags |= QEMUD_CMD_FLAG_NODEFCONFIG;
    /* The trailing ' ' is important to avoid a bogus match */
    if (strstr(help, "-rtc "))
        flags |= QEMUD_CMD_FLAG_RTC;
    /* to wit */
    if (strstr(help, "-rtc-td-hack"))
        flags |= QEMUD_CMD_FLAG_RTC_TD_HACK;
    if (strstr(help, "-no-hpet"))
        flags |= QEMUD_CMD_FLAG_NO_HPET;
    if (strstr(help, "-no-kvm-pit-reinjection"))
        flags |= QEMUD_CMD_FLAG_NO_KVM_PIT;
    if (strstr(help, "-tdf"))
        flags |= QEMUD_CMD_FLAG_TDF;
    if (strstr(help, "-enable-nesting"))
        flags |= QEMUD_CMD_FLAG_NESTING;
    if (strstr(help, ",menu=on"))
        flags |= QEMUD_CMD_FLAG_BOOT_MENU;
    if (strstr(help, "-fsdev"))
        flags |= QEMUD_CMD_FLAG_FSDEV;
    if (strstr(help, "-smbios type"))
        flags |= QEMUD_CMD_FLAG_SMBIOS_TYPE;

    if (strstr(help, "-netdev")) {
        /* Disable -netdev on 0.12 since although it exists,
         * the corresponding netdev_add/remove monitor commands
         * do not, and we need them to be able todo hotplug */
        if (version >= 13000)
            flags |= QEMUD_CMD_FLAG_NETDEV;
    }

    if (strstr(help, "-sdl"))
        flags |= QEMUD_CMD_FLAG_SDL;
    if (strstr(help, "cores=") &&
        strstr(help, "threads=") &&
        strstr(help, "sockets="))
        flags |= QEMUD_CMD_FLAG_SMP_TOPOLOGY;

    if (version >= 9000)
        flags |= QEMUD_CMD_FLAG_VNC_COLON;

    if (is_kvm && (version >= 10000 || kvm_version >= 74))
        flags |= QEMUD_CMD_FLAG_VNET_HDR;

    if (is_kvm && strstr(help, ",vhost=")) {
        flags |= QEMUD_CMD_FLAG_VNET_HOST;
    }

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
        flags |= QEMUD_CMD_FLAG_MIGRATE_QEMU_TCP;
        flags |= QEMUD_CMD_FLAG_MIGRATE_QEMU_EXEC;
        if (version >= 12000) {
            flags |= QEMUD_CMD_FLAG_MIGRATE_QEMU_UNIX;
            flags |= QEMUD_CMD_FLAG_MIGRATE_QEMU_FD;
        }
    } else if (kvm_version >= 79) {
        flags |= QEMUD_CMD_FLAG_MIGRATE_QEMU_TCP;
        if (kvm_version >= 80)
            flags |= QEMUD_CMD_FLAG_MIGRATE_QEMU_EXEC;
    } else if (kvm_version > 0) {
        flags |= QEMUD_CMD_FLAG_MIGRATE_KVM_STDIO;
    }

    if (version >= 10000)
        flags |= QEMUD_CMD_FLAG_0_10;

    /* While JSON mode was available in 0.12.0, it was too
     * incomplete to contemplate using. The 0.13.0 release
     * is good enough to use, even though it lacks one or
     * two features. The benefits of JSON mode now outweigh
     * the downside.
     */
     if (version >= 13000)
        flags |= QEMUD_CMD_FLAG_MONITOR_JSON;

    return flags;
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
                         unsigned long long *flags,
                         unsigned int *version,
                         unsigned int *is_kvm,
                         unsigned int *kvm_version)
{
    unsigned major, minor, micro;
    const char *p = help;

    *flags = *version = *is_kvm = *kvm_version = 0;

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
    if (minor == -1 || *p != '.')
        goto fail;

    ++p;

    micro = virParseNumber(&p);
    if (micro == -1)
        goto fail;

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

    *flags = qemuCapsComputeCmdFlags(help, *version, *is_kvm, *kvm_version);

    VIR_DEBUG("Version %u.%u.%u, cooked version %u, flags 0x%llx",
              major, minor, micro, *version, *flags);
    if (*kvm_version)
        VIR_DEBUG("KVM version %d detected", *kvm_version);
    else if (*is_kvm)
        VIR_DEBUG("qemu-kvm version %u.%u.%u detected", major, minor, micro);

    return 0;

fail:
    p = strchr(help, '\n');
    if (p)
        p = strndup(help, p - help);

    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                    _("cannot parse %s version number in '%s'"),
                    qemu, p ? p : help);

    VIR_FREE(p);

    return -1;
}

static void
qemuCapsParsePCIDeviceStrs(const char *qemu,
                           unsigned long long *flags)
{
    const char *const qemuarg[] = { qemu, "-device", "pci-assign,?", NULL };
    const char *const qemuenv[] = { "LC_ALL=C", NULL };
    pid_t child;
    int status;
    int newstderr = -1;

    if (virExec(qemuarg, qemuenv, NULL,
                &child, -1, NULL, &newstderr, VIR_EXEC_CLEAR_CAPS) < 0)
        return;

    char *pciassign = NULL;
    enum { MAX_PCI_OUTPUT_SIZE = 1024*4 };
    int len = virFileReadLimFD(newstderr, MAX_PCI_OUTPUT_SIZE, &pciassign);
    if (len < 0) {
        virReportSystemError(errno,
                             _("Unable to read %s pci-assign device output"),
                             qemu);
        goto cleanup;
    }

    if (strstr(pciassign, "pci-assign.configfd"))
        *flags |= QEMUD_CMD_FLAG_PCI_CONFIGFD;

cleanup:
    VIR_FREE(pciassign);
    VIR_FORCE_CLOSE(newstderr);
rewait:
    if (waitpid(child, &status, 0) != child) {
        if (errno == EINTR)
            goto rewait;

        VIR_ERROR(_("Unexpected exit status from qemu %d pid %lu"),
                  WEXITSTATUS(status), (unsigned long)child);
    }
    if (WEXITSTATUS(status) != 0) {
        VIR_WARN("Unexpected exit status '%d', qemu probably failed",
                 WEXITSTATUS(status));
    }
}

int qemuCapsExtractVersionInfo(const char *qemu,
                               unsigned int *retversion,
                               unsigned long long *retflags)
{
    const char *const qemuarg[] = { qemu, "-help", NULL };
    const char *const qemuenv[] = { "LC_ALL=C", NULL };
    pid_t child;
    int newstdout = -1;
    int ret = -1, status;
    unsigned int version, is_kvm, kvm_version;
    unsigned long long flags = 0;

    if (retflags)
        *retflags = 0;
    if (retversion)
        *retversion = 0;

    /* Make sure the binary we are about to try exec'ing exists.
     * Technically we could catch the exec() failure, but that's
     * in a sub-process so it's hard to feed back a useful error.
     */
    if (access(qemu, X_OK) < 0) {
        virReportSystemError(errno, _("Cannot find QEMU binary %s"), qemu);
        return -1;
    }

    if (virExec(qemuarg, qemuenv, NULL,
                &child, -1, &newstdout, NULL, VIR_EXEC_CLEAR_CAPS) < 0)
        return -1;

    char *help = NULL;
    enum { MAX_HELP_OUTPUT_SIZE = 1024*64 };
    int len = virFileReadLimFD(newstdout, MAX_HELP_OUTPUT_SIZE, &help);
    if (len < 0) {
        virReportSystemError(errno,
                             _("Unable to read %s help output"), qemu);
        goto cleanup2;
    }

    if (qemuCapsParseHelpStr(qemu, help, &flags,
                             &version, &is_kvm, &kvm_version) == -1)
        goto cleanup2;

    if (flags & QEMUD_CMD_FLAG_DEVICE)
        qemuCapsParsePCIDeviceStrs(qemu, &flags);

    if (retversion)
        *retversion = version;
    if (retflags)
        *retflags = flags;

    ret = 0;

cleanup2:
    VIR_FREE(help);
    if (VIR_CLOSE(newstdout) < 0)
        ret = -1;

rewait:
    if (waitpid(child, &status, 0) != child) {
        if (errno == EINTR)
            goto rewait;

        VIR_ERROR(_("Unexpected exit status from qemu %d pid %lu"),
                  WEXITSTATUS(status), (unsigned long)child);
        ret = -1;
    }
    /* Check & log unexpected exit status, but don't fail,
     * as there's really no need to throw an error if we did
     * actually read a valid version number above */
    if (WEXITSTATUS(status) != 0) {
        VIR_WARN("Unexpected exit status '%d', qemu probably failed",
                 WEXITSTATUS(status));
    }

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

    if (qemuCapsExtractVersionInfo(binary, version, NULL) < 0) {
        return -1;
    }

    return 0;
}
