/*
 * virhostcpu.c: helper APIs for host CPU info
 *
 * Copyright (C) 2006-2016 Red Hat, Inc.
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <dirent.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#if HAVE_LINUX_KVM_H
# include <linux/kvm.h>
#endif

#if defined(__FreeBSD__) || defined(__APPLE__)
# include <sys/time.h>
# include <sys/types.h>
# include <sys/sysctl.h>
# include <sys/resource.h>
#endif

#include "c-ctype.h"
#include "viralloc.h"
#include "virhostcpupriv.h"
#include "physmem.h"
#include "virerror.h"
#include "count-one-bits.h"
#include "intprops.h"
#include "virarch.h"
#include "virfile.h"
#include "virtypedparam.h"
#include "virstring.h"
#include "virsysfs.h"
#include "virnuma.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.hostcpu");

#define KVM_DEVICE "/dev/kvm"


#if defined(__FreeBSD__) || defined(__APPLE__)
static int
virHostCPUGetCountAppleFreeBSD(void)
{
    int ncpu_mib[2] = { CTL_HW, HW_NCPU };
    unsigned long ncpu;
    size_t ncpu_len = sizeof(ncpu);

    if (sysctl(ncpu_mib, 2, &ncpu, &ncpu_len, NULL, 0) == -1) {
        virReportSystemError(errno, "%s", _("Cannot obtain CPU count"));
        return -1;
    }

    return ncpu;
}
#endif /* defined(__FreeBSD__) || defined(__APPLE__) */

#ifdef __FreeBSD__
# define BSD_CPU_STATS_ALL 4
# define BSD_MEMORY_STATS_ALL 4

# define TICK_TO_NSEC (1000ull * 1000ull * 1000ull / (stathz ? stathz : hz))

static int
virHostCPUGetStatsFreeBSD(int cpuNum,
                          virNodeCPUStatsPtr params,
                          int *nparams)
{
    const char *sysctl_name;
    long *cpu_times;
    struct clockinfo clkinfo;
    size_t i, j, cpu_times_size, clkinfo_size;
    int cpu_times_num, offset, hz, stathz, ret = -1;
    struct field_cpu_map {
        const char *field;
        int idx[CPUSTATES];
    } cpu_map[] = {
        {VIR_NODE_CPU_STATS_KERNEL, {CP_SYS}},
        {VIR_NODE_CPU_STATS_USER, {CP_USER, CP_NICE}},
        {VIR_NODE_CPU_STATS_IDLE, {CP_IDLE}},
        {VIR_NODE_CPU_STATS_INTR, {CP_INTR}},
        {NULL, {0}}
    };

    if ((*nparams) == 0) {
        *nparams = BSD_CPU_STATS_ALL;
        return 0;
    }

    if ((*nparams) != BSD_CPU_STATS_ALL) {
        virReportInvalidArg(*nparams,
                            _("nparams in %s must be equal to %d"),
                            __FUNCTION__, BSD_CPU_STATS_ALL);
        return -1;
    }

    clkinfo_size = sizeof(clkinfo);
    if (sysctlbyname("kern.clockrate", &clkinfo, &clkinfo_size, NULL, 0) < 0) {
        virReportSystemError(errno,
                             _("sysctl failed for '%s'"),
                             "kern.clockrate");
        return -1;
    }

    stathz = clkinfo.stathz;
    hz = clkinfo.hz;

    if (cpuNum == VIR_NODE_CPU_STATS_ALL_CPUS) {
        sysctl_name = "kern.cp_time";
        cpu_times_num = 1;
        offset = 0;
    } else {
        sysctl_name = "kern.cp_times";
        cpu_times_num = virHostCPUGetCountAppleFreeBSD();

        if (cpuNum >= cpu_times_num) {
            virReportInvalidArg(cpuNum,
                                _("Invalid cpuNum in %s"),
                                __FUNCTION__);
            return -1;
        }

        offset = cpu_times_num * CPUSTATES;
    }

    cpu_times_size = sizeof(long) * cpu_times_num * CPUSTATES;

    if (VIR_ALLOC_N(cpu_times, cpu_times_num * CPUSTATES) < 0)
        goto cleanup;

    if (sysctlbyname(sysctl_name, cpu_times, &cpu_times_size, NULL, 0) < 0) {
        virReportSystemError(errno,
                             _("sysctl failed for '%s'"),
                             sysctl_name);
        goto cleanup;
    }

    for (i = 0; cpu_map[i].field != NULL; i++) {
        virNodeCPUStatsPtr param = &params[i];

        if (virStrcpyStatic(param->field, cpu_map[i].field) == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Field '%s' too long for destination"),
                           cpu_map[i].field);
            goto cleanup;
        }

        param->value = 0;
        for (j = 0; j < ARRAY_CARDINALITY(cpu_map[i].idx); j++)
            param->value += cpu_times[offset + cpu_map[i].idx[j]] * TICK_TO_NSEC;
    }

    ret = 0;

 cleanup:
    VIR_FREE(cpu_times);

    return ret;
}

#endif /* __FreeBSD__ */

#ifdef __linux__
# define CPUINFO_PATH "/proc/cpuinfo"
# define PROCSTAT_PATH "/proc/stat"
# define VIR_HOST_CPU_MASK_LEN 1024

# define LINUX_NB_CPU_STATS 4


static unsigned long
virHostCPUCountThreadSiblings(unsigned int cpu)
{
    unsigned long ret = 0;
    int rv = -1;
    char *str = NULL;
    size_t i;

    rv = virSysfsGetCpuValueString(cpu, "topology/thread_siblings", &str);
    if (rv == -2) {
        ret = 1;
        goto cleanup;
    }
    if (rv < 0)
        goto cleanup;

    for (i = 0; str[i] != '\0'; i++) {
        if (c_isxdigit(str[i]))
            ret += count_one_bits(virHexToBin(str[i]));
    }

 cleanup:
    VIR_FREE(str);
    return ret;
}

int
virHostCPUGetSocket(unsigned int cpu, unsigned int *socket)
{
    int tmp;
    int ret = virSysfsGetCpuValueInt(cpu,
                                     "topology/physical_package_id",
                                     &tmp);

    /* If the file is not there, it's 0 */
    if (ret == -2)
        tmp = 0;
    else if (ret < 0)
        return -1;

    /* Some architectures might have '-1' validly in the file, but that actually
     * means there are no sockets, so from our point of view it's all one socket,
     * i.e. socket 0.  Similarly when the file does not exist. */
    if (tmp < 0)
        tmp = 0;

    *socket = tmp;

    return 0;
}

int
virHostCPUGetCore(unsigned int cpu, unsigned int *core)
{
    int ret = virSysfsGetCpuValueUint(cpu, "topology/core_id", core);

    /* If the file is not there, it's 0 */
    if (ret == -2)
        *core = 0;
    else if (ret < 0)
        return -1;

    return 0;
}

int
virHostCPUGetOnline(unsigned int cpu, bool *online)
{
    unsigned int tmp = 0;
    int ret = virSysfsGetCpuValueUint(cpu, "online", &tmp);


    /* If the file is not there, it's online (doesn't support offlining) */
    if (ret == -2)
        tmp = 1;
    else if (ret < 0)
        return -1;

    *online = tmp;

    return 0;
}

virBitmapPtr
virHostCPUGetSiblingsList(unsigned int cpu)
{
    virBitmapPtr ret = NULL;
    int rv = -1;

    rv = virSysfsGetCpuValueBitmap(cpu, "topology/thread_siblings_list", &ret);
    if (rv == -2) {
        /* If the file doesn't exist, the threadis its only sibling */
        ret = virBitmapNew(cpu + 1);
        if (ret)
            ignore_value(virBitmapSetBit(ret, cpu));
    }

    return ret;
}

/* parses a node entry, returning number of processors in the node and
 * filling arguments */
static int
ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3)
ATTRIBUTE_NONNULL(4) ATTRIBUTE_NONNULL(6)
ATTRIBUTE_NONNULL(7) ATTRIBUTE_NONNULL(8)
ATTRIBUTE_NONNULL(9)
virHostCPUParseNode(const char *node,
                    virArch arch,
                    virBitmapPtr present_cpus_map,
                    virBitmapPtr online_cpus_map,
                    int threads_per_subcore,
                    int *sockets,
                    int *cores,
                    int *threads,
                    int *offline)
{
    /* Biggest value we can expect to be used as either socket id
     * or core id. Bitmaps will need to be sized accordingly */
    const int ID_MAX = 4095;
    int ret = -1;
    int processors = 0;
    DIR *cpudir = NULL;
    struct dirent *cpudirent = NULL;
    virBitmapPtr node_cpus_map = NULL;
    virBitmapPtr sockets_map = NULL;
    virBitmapPtr *cores_maps = NULL;
    int npresent_cpus = virBitmapSize(present_cpus_map);
    unsigned int sock_max = 0;
    unsigned int sock;
    unsigned int core;
    size_t i;
    int siblings;
    unsigned int cpu;
    int direrr;

    *threads = 0;
    *cores = 0;
    *sockets = 0;

    if (virDirOpen(&cpudir, node) < 0)
        goto cleanup;

    /* Keep track of the CPUs that belong to the current node */
    if (!(node_cpus_map = virBitmapNew(npresent_cpus)))
        goto cleanup;

    /* enumerate sockets in the node */
    if (!(sockets_map = virBitmapNew(ID_MAX + 1)))
        goto cleanup;

    while ((direrr = virDirRead(cpudir, &cpudirent, node)) > 0) {
        if (sscanf(cpudirent->d_name, "cpu%u", &cpu) != 1)
            continue;

        if (!virBitmapIsBitSet(present_cpus_map, cpu))
            continue;

        /* Mark this CPU as part of the current node */
        if (virBitmapSetBit(node_cpus_map, cpu) < 0)
            goto cleanup;

        if (!virBitmapIsBitSet(online_cpus_map, cpu))
            continue;

        if (virHostCPUGetSocket(cpu, &sock) < 0)
            goto cleanup;
        if (sock > ID_MAX) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Socket %d can't be handled (max socket is %d)"),
                           sock, ID_MAX);
            goto cleanup;
        }

        if (virBitmapSetBit(sockets_map, sock) < 0)
            goto cleanup;

        if (sock > sock_max)
            sock_max = sock;
    }

    if (direrr < 0)
        goto cleanup;

    sock_max++;

    /* allocate cores maps for each socket */
    if (VIR_ALLOC_N(cores_maps, sock_max) < 0)
        goto cleanup;

    for (i = 0; i < sock_max; i++)
        if (!(cores_maps[i] = virBitmapNew(ID_MAX + 1)))
            goto cleanup;

    /* Iterate over all CPUs in the node, in ascending order */
    for (cpu = 0; cpu < npresent_cpus; cpu++) {

        /* Skip CPUs that are not part of the current node */
        if (!virBitmapIsBitSet(node_cpus_map, cpu))
            continue;

        if (!virBitmapIsBitSet(online_cpus_map, cpu)) {
            if (threads_per_subcore > 0 &&
                cpu % threads_per_subcore != 0 &&
                virBitmapIsBitSet(online_cpus_map,
                                  cpu - (cpu % threads_per_subcore))) {
                /* Secondary offline threads are counted as online when
                 * subcores are in use and the corresponding primary
                 * thread is online */
                processors++;
            } else {
                /* But they are counted as offline otherwise */
                (*offline)++;
            }
            continue;
        }

        processors++;

        if (virHostCPUGetSocket(cpu, &sock) < 0)
            goto cleanup;
        if (!virBitmapIsBitSet(sockets_map, sock)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("CPU socket topology has changed"));
            goto cleanup;
        }

        /* Parse core */
        if (ARCH_IS_S390(arch)) {
            /* logical cpu is equivalent to a core on s390 */
            core = cpu;
        } else {
            if (virHostCPUGetCore(cpu, &core) < 0)
                goto cleanup;
        }
        if (core > ID_MAX) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Core %d can't be handled (max core is %d)"),
                           core, ID_MAX);
            goto cleanup;
        }

        if (virBitmapSetBit(cores_maps[sock], core) < 0)
            goto cleanup;

        if (!(siblings = virHostCPUCountThreadSiblings(cpu)))
            goto cleanup;

        if (siblings > *threads)
            *threads = siblings;
    }

    /* finalize the returned data */
    *sockets = virBitmapCountBits(sockets_map);

    for (i = 0; i < sock_max; i++) {
        if (!virBitmapIsBitSet(sockets_map, i))
            continue;

        core = virBitmapCountBits(cores_maps[i]);
        if (core > *cores)
            *cores = core;
    }

    if (threads_per_subcore > 0) {
        /* The thread count ignores offline threads, which means that only
         * only primary threads have been considered so far. If subcores
         * are in use, we need to also account for secondary threads */
        *threads *= threads_per_subcore;
    }
    ret = processors;

 cleanup:
    VIR_DIR_CLOSE(cpudir);
    if (cores_maps)
        for (i = 0; i < sock_max; i++)
            virBitmapFree(cores_maps[i]);
    VIR_FREE(cores_maps);
    virBitmapFree(sockets_map);
    virBitmapFree(node_cpus_map);

    return ret;
}

/* Check whether the host subcore configuration is valid.
 *
 * A valid configuration is one where no secondary thread is online;
 * the primary thread in a subcore is always the first one */
static bool
virHostCPUHasValidSubcoreConfiguration(int threads_per_subcore)
{
    virBitmapPtr online_cpus = NULL;
    int cpu = -1;
    bool ret = false;

    /* No point in checking if subcores are not in use */
    if (threads_per_subcore <= 0)
        goto cleanup;

    if (!(online_cpus = virHostCPUGetOnlineBitmap()))
        goto cleanup;

    while ((cpu = virBitmapNextSetBit(online_cpus, cpu)) >= 0) {

        /* A single online secondary thread is enough to
         * make the configuration invalid */
        if (cpu % threads_per_subcore != 0)
            goto cleanup;
    }

    ret = true;

 cleanup:
    virBitmapFree(online_cpus);

    return ret;
}

int
virHostCPUGetInfoPopulateLinux(FILE *cpuinfo,
                               virArch arch,
                               unsigned int *cpus,
                               unsigned int *mhz,
                               unsigned int *nodes,
                               unsigned int *sockets,
                               unsigned int *cores,
                               unsigned int *threads)
{
    virBitmapPtr present_cpus_map = NULL;
    virBitmapPtr online_cpus_map = NULL;
    char line[1024];
    DIR *nodedir = NULL;
    struct dirent *nodedirent = NULL;
    int nodecpus, nodecores, nodesockets, nodethreads, offline = 0;
    int threads_per_subcore = 0;
    unsigned int node;
    int ret = -1;
    char *sysfs_nodedir = NULL;
    char *sysfs_cpudir = NULL;
    int direrr;

    *mhz = 0;
    *cpus = *nodes = *sockets = *cores = *threads = 0;

    /* Start with parsing CPU clock speed from /proc/cpuinfo */
    while (fgets(line, sizeof(line), cpuinfo) != NULL) {
        if (ARCH_IS_X86(arch)) {
            char *buf = line;
            if (STRPREFIX(buf, "cpu MHz")) {
                char *p;
                unsigned int ui;

                buf += 7;
                while (*buf && c_isspace(*buf))
                    buf++;

                if (*buf != ':' || !buf[1]) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("parsing cpu MHz from cpuinfo"));
                    goto cleanup;
                }

                if (virStrToLong_ui(buf+1, &p, 10, &ui) == 0 &&
                    /* Accept trailing fractional part.  */
                    (*p == '\0' || *p == '.' || c_isspace(*p)))
                    *mhz = ui;
            }
        } else if (ARCH_IS_PPC(arch)) {
            char *buf = line;
            if (STRPREFIX(buf, "clock")) {
                char *p;
                unsigned int ui;

                buf += 5;
                while (*buf && c_isspace(*buf))
                    buf++;

                if (*buf != ':' || !buf[1]) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("parsing cpu MHz from cpuinfo"));
                    goto cleanup;
                }

                if (virStrToLong_ui(buf+1, &p, 10, &ui) == 0 &&
                    /* Accept trailing fractional part.  */
                    (*p == '\0' || *p == '.' || c_isspace(*p)))
                    *mhz = ui;
                /* No other interesting infos are available in /proc/cpuinfo.
                 * However, there is a line identifying processor's version,
                 * identification and machine, but we don't want it to be caught
                 * and parsed in next iteration, because it is not in expected
                 * format and thus lead to error. */
            }
        } else if (ARCH_IS_ARM(arch)) {
            char *buf = line;
            if (STRPREFIX(buf, "BogoMIPS")) {
                char *p;
                unsigned int ui;

                buf += 8;
                while (*buf && c_isspace(*buf))
                    buf++;

                if (*buf != ':' || !buf[1]) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("parsing cpu MHz from cpuinfo"));
                    goto cleanup;
                }

                if (virStrToLong_ui(buf+1, &p, 10, &ui) == 0
                    /* Accept trailing fractional part.  */
                    && (*p == '\0' || *p == '.' || c_isspace(*p)))
                    *mhz = ui;
            }
        } else if (ARCH_IS_S390(arch)) {
            /* s390x has no realistic value for CPU speed,
             * assign a value of zero to signify this */
            *mhz = 0;
        } else {
            VIR_WARN("Parser for /proc/cpuinfo needs to be adapted for your architecture");
            break;
        }
    }

    /* Get information about what CPUs are present in the host and what
     * CPUs are online, so that we don't have to so for each node */
    present_cpus_map = virHostCPUGetPresentBitmap();
    if (!present_cpus_map)
        goto cleanup;
    online_cpus_map = virHostCPUGetOnlineBitmap();
    if (!online_cpus_map)
        goto cleanup;

    /* OK, we've parsed clock speed out of /proc/cpuinfo. Get the
     * core, node, socket, thread and topology information from /sys
     */
    if (virAsprintf(&sysfs_nodedir, "%s/node", virSysfsGetSystemPath()) < 0)
        goto cleanup;

    if (virDirOpenQuiet(&nodedir, sysfs_nodedir) < 0) {
        /* the host isn't probably running a NUMA architecture */
        goto fallback;
    }

    /* PPC-KVM needs the secondary threads of a core to be offline on the
     * host. The kvm scheduler brings the secondary threads online in the
     * guest context. Moreover, P8 processor has split-core capability
     * where, there can be 1,2 or 4 subcores per core. The primaries of the
     * subcores alone will be online on the host for a subcore in the
     * host. Even though the actual threads per core for P8 processor is 8,
     * depending on the subcores_per_core = 1, 2 or 4, the threads per
     * subcore will vary accordingly to 8, 4 and 2 respectively.
     * So, On host threads_per_core what is arrived at from sysfs in the
     * current logic is actually the subcores_per_core. Threads per subcore
     * can only be obtained from the kvm device. For example, on P8 wih 1
     * core having 8 threads, sub_cores_percore=4, the threads 0,2,4 & 6
     * will be online. The sysfs reflects this and in the current logic
     * variable 'threads' will be 4 which is nothing but subcores_per_core.
     * If the user tampers the cpu online/offline states using chcpu or other
     * means, then it is an unsupported configuration for kvm.
     * The code below tries to keep in mind
     *  - when the libvirtd is run inside a KVM guest or Phyp based guest.
     *  - Or on the kvm host where user manually tampers the cpu states to
     *    offline/online randomly.
     * On hosts other than POWER this will be 0, in which case a simpler
     * thread-counting logic will be used  */
    if ((threads_per_subcore = virHostCPUGetThreadsPerSubcore(arch)) < 0)
        goto cleanup;

    /* If the subcore configuration is not valid, just pretend subcores
     * are not in use and count threads one by one */
    if (!virHostCPUHasValidSubcoreConfiguration(threads_per_subcore))
        threads_per_subcore = 0;

    while ((direrr = virDirRead(nodedir, &nodedirent, sysfs_nodedir)) > 0) {
        if (sscanf(nodedirent->d_name, "node%u", &node) != 1)
            continue;

        (*nodes)++;

        if (virAsprintf(&sysfs_cpudir, "%s/node/%s",
                        virSysfsGetSystemPath(), nodedirent->d_name) < 0)
            goto cleanup;

        if ((nodecpus = virHostCPUParseNode(sysfs_cpudir, arch,
                                            present_cpus_map,
                                            online_cpus_map,
                                            threads_per_subcore,
                                            &nodesockets, &nodecores,
                                            &nodethreads, &offline)) < 0)
            goto cleanup;

        VIR_FREE(sysfs_cpudir);

        *cpus += nodecpus;

        if (nodesockets > *sockets)
            *sockets = nodesockets;

        if (nodecores > *cores)
            *cores = nodecores;

        if (nodethreads > *threads)
            *threads = nodethreads;
    }

    if (direrr < 0)
        goto cleanup;

    if (*cpus && *nodes)
        goto done;

 fallback:
    VIR_FREE(sysfs_cpudir);

    if (virAsprintf(&sysfs_cpudir, "%s/cpu", virSysfsGetSystemPath()) < 0)
        goto cleanup;

    if ((nodecpus = virHostCPUParseNode(sysfs_cpudir, arch,
                                        present_cpus_map,
                                        online_cpus_map,
                                        threads_per_subcore,
                                        &nodesockets, &nodecores,
                                        &nodethreads, &offline)) < 0)
        goto cleanup;

    *nodes = 1;
    *cpus = nodecpus;
    *sockets = nodesockets;
    *cores = nodecores;
    *threads = nodethreads;

 done:
    /* There should always be at least one cpu, socket, node, and thread. */
    if (*cpus == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("no CPUs found"));
        goto cleanup;
    }

    if (*sockets == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("no sockets found"));
        goto cleanup;
    }

    if (*threads == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("no threads found"));
        goto cleanup;
    }

    /* Now check if the topology makes sense. There are machines that don't
     * expose their real number of nodes or for example the AMD Bulldozer
     * architecture that exposes their Clustered integer core modules as both
     * threads and cores. This approach throws off our detection. Unfortunately
     * the nodeinfo structure isn't designed to carry the full topology so
     * we're going to lie about the detected topology to notify the user
     * to check the host capabilities for the actual topology. */
    if ((*nodes *
         *sockets *
         *cores *
         *threads) != (*cpus + offline)) {
        *nodes = 1;
        *sockets = 1;
        *cores = *cpus + offline;
        *threads = 1;
    }

    ret = 0;

 cleanup:
    VIR_DIR_CLOSE(nodedir);
    virBitmapFree(present_cpus_map);
    virBitmapFree(online_cpus_map);
    VIR_FREE(sysfs_nodedir);
    VIR_FREE(sysfs_cpudir);
    return ret;
}

# define TICK_TO_NSEC (1000ull * 1000ull * 1000ull / sysconf(_SC_CLK_TCK))

int
virHostCPUGetStatsLinux(FILE *procstat,
                        int cpuNum,
                        virNodeCPUStatsPtr params,
                        int *nparams)
{
    int ret = -1;
    char line[1024];
    unsigned long long usr, ni, sys, idle, iowait;
    unsigned long long irq, softirq, steal, guest, guest_nice;
    char cpu_header[4 + INT_BUFSIZE_BOUND(cpuNum)];

    if ((*nparams) == 0) {
        /* Current number of cpu stats supported by linux */
        *nparams = LINUX_NB_CPU_STATS;
        ret = 0;
        goto cleanup;
    }

    if ((*nparams) != LINUX_NB_CPU_STATS) {
        virReportInvalidArg(*nparams,
                            _("nparams in %s must be equal to %d"),
                            __FUNCTION__, LINUX_NB_CPU_STATS);
        goto cleanup;
    }

    if (cpuNum == VIR_NODE_CPU_STATS_ALL_CPUS) {
        strcpy(cpu_header, "cpu ");
    } else {
        snprintf(cpu_header, sizeof(cpu_header), "cpu%d ", cpuNum);
    }

    while (fgets(line, sizeof(line), procstat) != NULL) {
        char *buf = line;

        if (STRPREFIX(buf, cpu_header)) { /* aka logical CPU time */
            if (sscanf(buf,
                       "%*s %llu %llu %llu %llu %llu" // user ~ iowait
                       "%llu %llu %llu %llu %llu",    // irq  ~ guest_nice
                       &usr, &ni, &sys, &idle, &iowait,
                       &irq, &softirq, &steal, &guest, &guest_nice) < 4) {
                continue;
            }

            if (virHostCPUStatsAssign(&params[0], VIR_NODE_CPU_STATS_KERNEL,
                                      (sys + irq + softirq) * TICK_TO_NSEC) < 0)
                goto cleanup;

            if (virHostCPUStatsAssign(&params[1], VIR_NODE_CPU_STATS_USER,
                                      (usr + ni) * TICK_TO_NSEC) < 0)
                goto cleanup;

            if (virHostCPUStatsAssign(&params[2], VIR_NODE_CPU_STATS_IDLE,
                                      idle * TICK_TO_NSEC) < 0)
                goto cleanup;

            if (virHostCPUStatsAssign(&params[3], VIR_NODE_CPU_STATS_IOWAIT,
                                      iowait * TICK_TO_NSEC) < 0)
                goto cleanup;

            ret = 0;
            goto cleanup;
        }
    }

    virReportInvalidArg(cpuNum,
                        _("Invalid cpuNum in %s"),
                        __FUNCTION__);

 cleanup:
    return ret;
}


/* Determine the number of CPUs (maximum CPU id + 1) from a file containing
 * a list of CPU ids, like the Linux sysfs cpu/present file */
static int
virHostCPUParseCountLinux(void)
{
    char *str = NULL;
    char *tmp;
    int ret = -1;

    if (virSysfsGetValueString("cpu/present", &str) < 0)
        return -1;

    tmp = str;
    do {
        if (virStrToLong_i(tmp, &tmp, 10, &ret) < 0 ||
            !strchr(",-\n", *tmp)) {
            virReportError(VIR_ERR_NO_SUPPORT,
                           _("failed to parse %s"), str);
            ret = -1;
            goto cleanup;
        }
    } while (*tmp++ != '\n');
    ret++;

 cleanup:
    VIR_FREE(str);
    return ret;
}
#endif


int
virHostCPUStatsAssign(virNodeCPUStatsPtr param,
                      const char *name,
                      unsigned long long value)
{
    if (virStrcpyStatic(param->field, name) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("kernel cpu time field is too long"
                               " for the destination"));
        return -1;
    }
    param->value = value;
    return 0;
}


int
virHostCPUGetInfo(virArch hostarch ATTRIBUTE_UNUSED,
                  unsigned int *cpus ATTRIBUTE_UNUSED,
                  unsigned int *mhz ATTRIBUTE_UNUSED,
                  unsigned int *nodes ATTRIBUTE_UNUSED,
                  unsigned int *sockets ATTRIBUTE_UNUSED,
                  unsigned int *cores ATTRIBUTE_UNUSED,
                  unsigned int *threads ATTRIBUTE_UNUSED)
{
#ifdef __linux__
    int ret = -1;
    FILE *cpuinfo = fopen(CPUINFO_PATH, "r");

    if (!cpuinfo) {
        virReportSystemError(errno,
                             _("cannot open %s"), CPUINFO_PATH);
        return -1;
    }

    ret = virHostCPUGetInfoPopulateLinux(cpuinfo, hostarch,
                                         cpus, mhz, nodes,
                                         sockets, cores, threads);
    if (ret < 0)
        goto cleanup;

 cleanup:
    VIR_FORCE_FCLOSE(cpuinfo);
    return ret;
#elif defined(__FreeBSD__) || defined(__APPLE__)
    unsigned long cpu_freq;
    size_t cpu_freq_len = sizeof(cpu_freq);

    *cpus = virHostCPUGetCountAppleFreeBSD();
    if (*cpus == -1)
        return -1;

    *nodes = 1;
    *sockets = 1;
    *cores = *cpus;
    *threads = 1;

# ifdef __FreeBSD__
    /* dev.cpu.%d.freq reports current active CPU frequency. It is provided by
     * the cpufreq(4) framework. However, it might be disabled or no driver
     * available. In this case fallback to "hw.clockrate" which reports boot time
     * CPU frequency. */

    if (sysctlbyname("dev.cpu.0.freq", &cpu_freq, &cpu_freq_len, NULL, 0) < 0) {
        if (sysctlbyname("hw.clockrate", &cpu_freq, &cpu_freq_len, NULL, 0) < 0) {
            virReportSystemError(errno, "%s", _("cannot obtain CPU freq"));
            return -1;
        }
    }

    *mhz = cpu_freq;
# else
    if (sysctlbyname("hw.cpufrequency", &cpu_freq, &cpu_freq_len, NULL, 0) < 0) {
        virReportSystemError(errno, "%s", _("cannot obtain CPU freq"));
        return -1;
    }

    *mhz = cpu_freq / 1000000;
# endif

    return 0;
#else
    /* XXX Solaris will need an impl later if they port QEMU driver */
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("node info not implemented on this platform"));
    return -1;
#endif
}


int
virHostCPUGetStats(int cpuNum ATTRIBUTE_UNUSED,
                   virNodeCPUStatsPtr params ATTRIBUTE_UNUSED,
                   int *nparams ATTRIBUTE_UNUSED,
                   unsigned int flags)
{
    virCheckFlags(0, -1);

#ifdef __linux__
    {
        int ret;
        FILE *procstat = fopen(PROCSTAT_PATH, "r");
        if (!procstat) {
            virReportSystemError(errno,
                                 _("cannot open %s"), PROCSTAT_PATH);
            return -1;
        }
        ret = virHostCPUGetStatsLinux(procstat, cpuNum, params, nparams);
        VIR_FORCE_FCLOSE(procstat);

        return ret;
    }
#elif defined(__FreeBSD__)
    return virHostCPUGetStatsFreeBSD(cpuNum, params, nparams);
#else
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("node CPU stats not implemented on this platform"));
    return -1;
#endif
}


int
virHostCPUGetCount(void)
{
#if defined(__linux__)
    return virHostCPUParseCountLinux();
#elif defined(__FreeBSD__) || defined(__APPLE__)
    return virHostCPUGetCountAppleFreeBSD();
#else
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("host cpu counting not implemented on this platform"));
    return -1;
#endif
}

bool
virHostCPUHasBitmap(void)
{
#ifdef __linux__
    return true;
#else
    return false;
#endif
}

virBitmapPtr
virHostCPUGetPresentBitmap(void)
{
#ifdef __linux__
    virBitmapPtr ret = NULL;

    virSysfsGetValueBitmap("cpu/present", &ret);

    return ret;
#else
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("node present CPU map not implemented on this platform"));
    return NULL;
#endif
}

virBitmapPtr
virHostCPUGetOnlineBitmap(void)
{
#ifdef __linux__
    virBitmapPtr ret = NULL;

    virSysfsGetValueBitmap("cpu/online", &ret);

    return ret;
#else
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("node online CPU map not implemented on this platform"));
    return NULL;
#endif
}


int
virHostCPUGetMap(unsigned char **cpumap,
                 unsigned int *online,
                 unsigned int flags)
{
    virBitmapPtr cpus = NULL;
    int ret = -1;
    int dummy;

    virCheckFlags(0, -1);

    if (!cpumap && !online)
        return virHostCPUGetCount();

    if (!(cpus = virHostCPUGetOnlineBitmap()))
        goto cleanup;

    if (cpumap && virBitmapToData(cpus, cpumap, &dummy) < 0)
        goto cleanup;
    if (online)
        *online = virBitmapCountBits(cpus);

    ret = virBitmapSize(cpus);

 cleanup:
    if (ret < 0 && cpumap)
        VIR_FREE(*cpumap);
    virBitmapFree(cpus);
    return ret;
}


#if HAVE_LINUX_KVM_H && defined(KVM_CAP_PPC_SMT)

/* Get the number of threads per subcore.
 *
 * This will be 2, 4 or 8 on POWER hosts, depending on the current
 * micro-threading configuration, and 0 everywhere else.
 *
 * Returns the number of threads per subcore if subcores are in use, zero
 * if subcores are not in use, and a negative value on error */
int
virHostCPUGetThreadsPerSubcore(virArch arch)
{
    int threads_per_subcore = 0;
    int kvmfd;

    if (ARCH_IS_PPC64(arch)) {

        /* It's okay if /dev/kvm doesn't exist, because
         *   a. we might be running in a guest
         *   b. the kvm module might not be installed or enabled
         * In either case, falling back to the subcore-unaware thread
         * counting logic is the right thing to do */
        if (!virFileExists(KVM_DEVICE))
            goto out;

        if ((kvmfd = open(KVM_DEVICE, O_RDONLY)) < 0) {
            /* This can happen when running as a regular user if
             * permissions are tight enough, in which case erroring out
             * is better than silently falling back and reporting
             * different nodeinfo depending on the user */
            virReportSystemError(errno,
                                 _("Failed to open '%s'"),
                                 KVM_DEVICE);
            threads_per_subcore = -1;
            goto out;
        }

        /* For Phyp and KVM based guests the ioctl for KVM_CAP_PPC_SMT
         * returns zero and both primary and secondary threads will be
         * online */
        threads_per_subcore = ioctl(kvmfd,
                                    KVM_CHECK_EXTENSION,
                                    KVM_CAP_PPC_SMT);

        VIR_FORCE_CLOSE(kvmfd);
    }

 out:
    return threads_per_subcore;
}

#else

/* Fallback for nodeGetThreadsPerSubcore() used when KVM headers
 * are not available on the system */
int
virHostCPUGetThreadsPerSubcore(virArch arch ATTRIBUTE_UNUSED)
{
    return 0;
}

#endif /* HAVE_LINUX_KVM_H && defined(KVM_CAP_PPC_SMT) */

#if HAVE_LINUX_KVM_H
int
virHostCPUGetKVMMaxVCPUs(void)
{
    int fd;
    int ret;

    if ((fd = open(KVM_DEVICE, O_RDONLY)) < 0) {
        virReportSystemError(errno, _("Unable to open %s"), KVM_DEVICE);
        return -1;
    }

# ifdef KVM_CAP_MAX_VCPUS
    /* at first try KVM_CAP_MAX_VCPUS to determine the maximum count */
    if ((ret = ioctl(fd, KVM_CHECK_EXTENSION, KVM_CAP_MAX_VCPUS)) > 0)
        goto cleanup;
# endif /* KVM_CAP_MAX_VCPUS */

    /* as a fallback get KVM_CAP_NR_VCPUS (the recommended maximum number of
     * vcpus). Note that on most machines this is set to 160. */
    if ((ret = ioctl(fd, KVM_CHECK_EXTENSION, KVM_CAP_NR_VCPUS)) > 0)
        goto cleanup;

    /* if KVM_CAP_NR_VCPUS doesn't exist either, kernel documentation states
     * that 4 should be used as the maximum number of cpus */
    ret = 4;

 cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}
#else
int
virHostCPUGetKVMMaxVCPUs(void)
{
    virReportSystemError(ENOSYS, "%s",
                         _("KVM is not supported on this platform"));
    return -1;
}
#endif /* HAVE_LINUX_KVM_H */
