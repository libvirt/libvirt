/*
 * virhostmem.c: helper APIs for host memory info
 *
 * Copyright (C) 2006-2008, 2010-2015 Red Hat, Inc.
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
 */

#include <config.h>

#include <fcntl.h>
#include <unistd.h>

#if defined(__FreeBSD__) || defined(__APPLE__)
# include <sys/time.h>
# include <sys/types.h>
# include <sys/sysctl.h>
# include <sys/resource.h>
#endif

#ifdef WIN32
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
#endif

#include "virhostmem.h"
#include "virerror.h"
#include "virfile.h"
#include "virtypedparam.h"
#include "virstring.h"
#include "virnuma.h"
#include "virlog.h"
#include "virthread.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.hostmem");

static unsigned long long virHostTHPPMDSize; /* in kibibytes */
static virOnceControl virHostMemGetTHPSizeOnce = VIR_ONCE_CONTROL_INITIALIZER;

#ifdef __FreeBSD__
# define BSD_MEMORY_STATS_ALL 4

static int
virHostMemGetStatsFreeBSD(virNodeMemoryStatsPtr params,
                          int *nparams)
{
    size_t i, j = 0;
    unsigned long pagesize = getpagesize() >> 10;
    long bufpages;
    size_t bufpages_size = sizeof(bufpages);
    struct field_sysctl_map {
        const char *field;
        const char *sysctl_name;
    } sysctl_map[] = {
        {VIR_NODE_MEMORY_STATS_TOTAL, "vm.stats.vm.v_page_count"},
        {VIR_NODE_MEMORY_STATS_FREE, "vm.stats.vm.v_free_count"},
        {VIR_NODE_MEMORY_STATS_CACHED, "vm.stats.vm.v_cache_count"},
        {NULL, NULL}
    };

    if ((*nparams) == 0) {
        *nparams = BSD_MEMORY_STATS_ALL;
        return 0;
    }

    if ((*nparams) != BSD_MEMORY_STATS_ALL) {
        virReportInvalidArg(nparams,
                            _("nparams in %1$s must be %2$d"),
                            __FUNCTION__, BSD_MEMORY_STATS_ALL);
        return -1;
    }

    for (i = 0; sysctl_map[i].field != NULL; i++) {
        u_int value;
        size_t value_size = sizeof(value);
        virNodeMemoryStatsPtr param;

        if (sysctlbyname(sysctl_map[i].sysctl_name, &value,
                         &value_size, NULL, 0) < 0) {
            virReportSystemError(errno,
                                 _("sysctl failed for '%1$s'"),
                                 sysctl_map[i].sysctl_name);
            return -1;
        }

        param = &params[j++];
        if (virStrcpyStatic(param->field, sysctl_map[i].field) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Field '%1$s' too long for destination"),
                           sysctl_map[i].field);
            return -1;
        }
        param->value = (unsigned long long)value * pagesize;
    }

    {
        virNodeMemoryStatsPtr param = &params[j++];

        if (sysctlbyname("vfs.bufspace", &bufpages, &bufpages_size, NULL, 0) < 0) {
            virReportSystemError(errno,
                                 _("sysctl failed for '%1$s'"),
                                 "vfs.bufspace");
            return -1;
        }
        if (virStrcpyStatic(param->field, VIR_NODE_MEMORY_STATS_BUFFERS) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Field '%1$s' too long for destination"),
                           VIR_NODE_MEMORY_STATS_BUFFERS);
            return -1;
        }
        param->value = (unsigned long long)bufpages >> 10;
    }

    return 0;
}
#endif /* __FreeBSD__ */

#ifdef __linux__
# define SYSFS_SYSTEM_PATH "/sys/devices/system"
# define MEMINFO_PATH "/proc/meminfo"
# define SYSFS_MEMORY_SHARED_PATH "/sys/kernel/mm/ksm"
# define SYSFS_THREAD_SIBLINGS_LIST_LENGTH_MAX 8192

# define LINUX_NB_MEMORY_STATS_ALL 4
# define LINUX_NB_MEMORY_STATS_CELL 2

static int
virHostMemGetStatsLinux(FILE *meminfo,
                        int cellNum,
                        virNodeMemoryStatsPtr params,
                        int *nparams)
{
    size_t i = 0, j = 0, k = 0;
    int found = 0;
    int nr_param;
    char line[1024];
    char meminfo_hdr[VIR_NODE_MEMORY_STATS_FIELD_LENGTH + 1];
    unsigned long val;
    struct field_conv {
        const char *meminfo_hdr;  /* meminfo header */
        const char *field;        /* MemoryStats field name */
    } field_conv[] = {
        {"MemTotal:", VIR_NODE_MEMORY_STATS_TOTAL},
        {"MemFree:",  VIR_NODE_MEMORY_STATS_FREE},
        {"Buffers:",  VIR_NODE_MEMORY_STATS_BUFFERS},
        {"Cached:",   VIR_NODE_MEMORY_STATS_CACHED},
        {NULL,        NULL}
    };

    if (cellNum == VIR_NODE_MEMORY_STATS_ALL_CELLS) {
        nr_param = LINUX_NB_MEMORY_STATS_ALL;
    } else {
        nr_param = LINUX_NB_MEMORY_STATS_CELL;
    }

    if ((*nparams) == 0) {
        /* Current number of memory stats supported by linux */
        *nparams = nr_param;
        return 0;
    }

    if ((*nparams) != nr_param) {
        virReportInvalidArg(nparams,
                            _("nparams in %1$s must be %2$d"),
                            __FUNCTION__, nr_param);
        return -1;
    }

    while (fgets(line, sizeof(line), meminfo) != NULL) {
        char *buf = line;

        if (STRPREFIX(buf, "Node ")) {
            /*
             * /sys/devices/system/node/nodeX/meminfo format is below.
             * So, skip prefix "Node XX ".
             *
             * Node 0 MemTotal:        8386980 kB
             * Node 0 MemFree:         5300920 kB
             *         :
             */
            char *p;

            p = buf;
            for (i = 0; i < 2; i++) {
                p = strchr(p, ' ');
                if (p == NULL) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("no prefix found"));
                    return -1;
                }
                p++;
            }
            buf = p;
        }

# define MEM_MAX_LEN G_STRINGIFY(VIR_NODE_MEMORY_STATS_FIELD_LENGTH)
        if (sscanf(buf, "%" MEM_MAX_LEN "s %lu kB", meminfo_hdr, &val) < 2)
            continue;
# undef MEM_MAX_LEN

        for (j = 0; field_conv[j].meminfo_hdr != NULL; j++) {
            struct field_conv *convp = &field_conv[j];

            if (STREQ(meminfo_hdr, convp->meminfo_hdr)) {
                virNodeMemoryStatsPtr param = &params[k++];

                if (virStrcpyStatic(param->field, convp->field) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("Field kernel memory too long for destination"));
                    return -1;
                }
                param->value = val;
                found++;
                break;
            }
        }
        if (found >= nr_param)
            break;
    }

    if (found == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("no available memory line found"));
        return -1;
    }

    return 0;
}
#endif


int
virHostMemGetStats(int cellNum G_GNUC_UNUSED,
                   virNodeMemoryStatsPtr params G_GNUC_UNUSED,
                   int *nparams G_GNUC_UNUSED,
                   unsigned int flags)
{
    virCheckFlags(0, -1);

#ifdef __linux__
    {
        int ret;
        g_autofree char *meminfo_path = NULL;
        FILE *meminfo;
        int max_node;

        /*
         * Even if built without numactl, libvirt claims
         * to have a one-cells NUMA topology. In such a
         * case return the statistics for the entire host.
         */
        if (!virNumaIsAvailable() && cellNum == 0)
            cellNum = VIR_NODE_MEMORY_STATS_ALL_CELLS;

        if (cellNum == VIR_NODE_MEMORY_STATS_ALL_CELLS) {
            meminfo_path = g_strdup(MEMINFO_PATH);
        } else {
            if ((max_node = virNumaGetMaxNode()) < 0)
                return -1;

            if (cellNum > max_node) {
                virReportInvalidArg(cellNum,
                                    _("cellNum in %1$s must be less than or equal to %2$d"),
                                    __FUNCTION__, max_node);
                return -1;
            }

            meminfo_path = g_strdup_printf(
                                           SYSFS_SYSTEM_PATH "/node/node%d/meminfo", cellNum);
        }
        meminfo = fopen(meminfo_path, "r");

        if (!meminfo) {
            virReportSystemError(errno,
                                 _("cannot open %1$s"), meminfo_path);
            return -1;
        }
        ret = virHostMemGetStatsLinux(meminfo, cellNum, params, nparams);
        VIR_FORCE_FCLOSE(meminfo);

        return ret;
    }
#elif defined(__FreeBSD__)
    return virHostMemGetStatsFreeBSD(params, nparams);
#else
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("node memory stats not implemented on this platform"));
    return -1;
#endif
}


#ifdef __linux__
static int
virHostMemSetParameterValue(virTypedParameterPtr param)
{
    g_autofree char *path = NULL;
    g_autofree char *strval = NULL;
    int rc = -1;

    char *field = strchr(param->field, '_');
    field++;
    path = g_strdup_printf("%s/%s", SYSFS_MEMORY_SHARED_PATH, field);

    strval = g_strdup_printf("%u", param->value.ui);

    if ((rc = virFileWriteStr(path, strval, 0)) < 0) {
        virReportSystemError(-rc, _("failed to set %1$s"), param->field);
        return -1;
    }

    return 0;
}

static bool
virHostMemParametersAreAllSupported(virTypedParameterPtr params,
                                    int nparams)
{
    size_t i;

    for (i = 0; i < nparams; i++) {
        g_autofree char *path = NULL;
        virTypedParameterPtr param = &params[i];

        char *field = strchr(param->field, '_');
        field++;
        path = g_strdup_printf("%s/%s", SYSFS_MEMORY_SHARED_PATH, field);

        if (!virFileExists(path)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("Parameter '%1$s' is not supported by this kernel"),
                           param->field);
            return false;
        }
    }

    return true;
}
#endif

#ifdef __linux__
int
virHostMemSetParameters(virTypedParameterPtr params G_GNUC_UNUSED,
                        int nparams G_GNUC_UNUSED,
                        unsigned int flags)
{
    size_t i;

    virCheckFlags(0, -1);

    if (virTypedParamsValidate(params, nparams,
                               VIR_NODE_MEMORY_SHARED_PAGES_TO_SCAN,
                               VIR_TYPED_PARAM_UINT,
                               VIR_NODE_MEMORY_SHARED_SLEEP_MILLISECS,
                               VIR_TYPED_PARAM_UINT,
                               VIR_NODE_MEMORY_SHARED_MERGE_ACROSS_NODES,
                               VIR_TYPED_PARAM_UINT,
                               NULL) < 0)
        return -1;

    if (!virHostMemParametersAreAllSupported(params, nparams))
        return -1;

    for (i = 0; i < nparams; i++) {
        if (virHostMemSetParameterValue(&params[i]) < 0)
            return -1;
    }

    return 0;
}
#else
int
virHostMemSetParameters(virTypedParameterPtr params G_GNUC_UNUSED,
                        int nparams G_GNUC_UNUSED,
                        unsigned int flags)
{
    virCheckFlags(0, -1);

    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("node set memory parameters not implemented on this platform"));
    return -1;
}
#endif

#ifdef __linux__
static int
virHostMemGetParameterValue(const char *field,
                            void *value)
{
    g_autofree char *path = NULL;
    g_autofree char *buf = NULL;
    char *tmp = NULL;
    int rc = -1;

    path = g_strdup_printf("%s/%s", SYSFS_MEMORY_SHARED_PATH, field);

    if (!virFileExists(path))
        return -2;

    if (virFileReadAll(path, 1024, &buf) < 0)
        return -1;

    if ((tmp = strchr(buf, '\n')))
        *tmp = '\0';

    if (STREQ(field, "pages_to_scan")   ||
        STREQ(field, "sleep_millisecs") ||
        STREQ(field, "merge_across_nodes"))
        rc = virStrToLong_ui(buf, NULL, 10, (unsigned int *)value);
    else if (STREQ(field, "pages_shared")    ||
             STREQ(field, "pages_sharing")   ||
             STREQ(field, "pages_unshared")  ||
             STREQ(field, "pages_volatile")  ||
             STREQ(field, "full_scans"))
        rc = virStrToLong_ull(buf, NULL, 10, (unsigned long long *)value);

    if (rc < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to parse %1$s"), field);
        return -1;
    }

    return 0;
}
#endif

#define NODE_MEMORY_PARAMETERS_NUM 8
#ifdef __linux__
int
virHostMemGetParameters(virTypedParameterPtr params G_GNUC_UNUSED,
                        int *nparams G_GNUC_UNUSED,
                        unsigned int flags)
{
    unsigned int pages_to_scan;
    unsigned int sleep_millisecs;
    unsigned int merge_across_nodes;
    unsigned long long pages_shared;
    unsigned long long pages_sharing;
    unsigned long long pages_unshared;
    unsigned long long pages_volatile;
    unsigned long long full_scans = 0;
    size_t i;
    int ret;

    virCheckFlags(VIR_TYPED_PARAM_STRING_OKAY, -1);

    if ((*nparams) == 0) {
        *nparams = NODE_MEMORY_PARAMETERS_NUM;
        return 0;
    }

    for (i = 0; i < *nparams && i < NODE_MEMORY_PARAMETERS_NUM; i++) {
        virTypedParameterPtr param = &params[i];

        switch (i) {
        case 0:
            ret = virHostMemGetParameterValue("pages_to_scan", &pages_to_scan);
            if (ret == -2)
                continue;
            else if (ret == -1)
                return -1;

            if (virTypedParameterAssign(param, VIR_NODE_MEMORY_SHARED_PAGES_TO_SCAN,
                                        VIR_TYPED_PARAM_UINT, pages_to_scan) < 0)
                return -1;

            break;

        case 1:
            ret = virHostMemGetParameterValue("sleep_millisecs", &sleep_millisecs);
            if (ret == -2)
                continue;
            else if (ret == -1)
                return -1;

            if (virTypedParameterAssign(param, VIR_NODE_MEMORY_SHARED_SLEEP_MILLISECS,
                                        VIR_TYPED_PARAM_UINT, sleep_millisecs) < 0)
                return -1;

            break;

        case 2:
            ret = virHostMemGetParameterValue("pages_shared", &pages_shared);
            if (ret == -2)
                continue;
            else if (ret == -1)
                return -1;

            if (virTypedParameterAssign(param, VIR_NODE_MEMORY_SHARED_PAGES_SHARED,
                                        VIR_TYPED_PARAM_ULLONG, pages_shared) < 0)
                return -1;

            break;

        case 3:
            ret = virHostMemGetParameterValue("pages_sharing", &pages_sharing);
            if (ret == -2)
                continue;
            else if (ret == -1)
                return -1;

            if (virTypedParameterAssign(param, VIR_NODE_MEMORY_SHARED_PAGES_SHARING,
                                        VIR_TYPED_PARAM_ULLONG, pages_sharing) < 0)
                return -1;

            break;

        case 4:
            ret = virHostMemGetParameterValue("pages_unshared", &pages_unshared);
            if (ret == -2)
                continue;
            else if (ret == -1)
                return -1;

            if (virTypedParameterAssign(param, VIR_NODE_MEMORY_SHARED_PAGES_UNSHARED,
                                        VIR_TYPED_PARAM_ULLONG, pages_unshared) < 0)
                return -1;

            break;

        case 5:
            ret = virHostMemGetParameterValue("pages_volatile", &pages_volatile);
            if (ret == -2)
                continue;
            else if (ret == -1)
                return -1;

            if (virTypedParameterAssign(param, VIR_NODE_MEMORY_SHARED_PAGES_VOLATILE,
                                        VIR_TYPED_PARAM_ULLONG, pages_volatile) < 0)
                return -1;

            break;

        case 6:
            ret = virHostMemGetParameterValue("full_scans", &full_scans);
            if (ret == -2)
                continue;
            else if (ret == -1)
                return -1;

            if (virTypedParameterAssign(param, VIR_NODE_MEMORY_SHARED_FULL_SCANS,
                                        VIR_TYPED_PARAM_ULLONG, full_scans) < 0)
                return -1;

            break;

        case 7:
            ret = virHostMemGetParameterValue("merge_across_nodes", &merge_across_nodes);
            if (ret == -2)
                continue;
            else if (ret == -1)
                return -1;

            if (virTypedParameterAssign(param, VIR_NODE_MEMORY_SHARED_MERGE_ACROSS_NODES,
                                        VIR_TYPED_PARAM_UINT, merge_across_nodes) < 0)
                return -1;

            break;
        }
    }

    return 0;
}
#else
int
virHostMemGetParameters(virTypedParameterPtr params G_GNUC_UNUSED,
                        int *nparams G_GNUC_UNUSED,
                        unsigned int flags)
{
    virCheckFlags(VIR_TYPED_PARAM_STRING_OKAY, -1);

    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("node get memory parameters not implemented on this platform"));
    return -1;
}
#endif


#ifdef WIN32
/*  MEMORYSTATUSEX is missing from older windows headers, so define
    a local replacement.  */
typedef struct
{
  DWORD dwLength;
  DWORD dwMemoryLoad;
  DWORDLONG ullTotalPhys;
  DWORDLONG ullAvailPhys;
  DWORDLONG ullTotalPageFile;
  DWORDLONG ullAvailPageFile;
  DWORDLONG ullTotalVirtual;
  DWORDLONG ullAvailVirtual;
  DWORDLONG ullAvailExtendedVirtual;
} lMEMORYSTATUSEX;
typedef WINBOOL(WINAPI *PFN_MS_EX) (lMEMORYSTATUSEX*);
#endif /* !WIN32 */

static unsigned long long
virHostMemGetTotal(void)
{
#if defined WITH_SYSCTLBYNAME
    /* This works on freebsd & macOS. */
    unsigned long long physmem = 0;
    size_t len = sizeof(physmem);

    if (sysctlbyname("hw.physmem", &physmem, &len, NULL, 0) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to query memory total"));
        return 0;
    }

    return physmem;
#elif defined _SC_PHYS_PAGES && defined _SC_PAGESIZE
    /* this works on linux */
    long long pages;
    long long pagesize;
    if ((pages = sysconf(_SC_PHYS_PAGES)) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to query memory total"));
        return 0;
    }
    if ((pagesize = sysconf(_SC_PAGESIZE)) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to query memory page size"));
        return 0;
    }
    return (unsigned long long)pages * (unsigned long long)pagesize;
#elif defined WIN32
    PFN_MS_EX pfnex;
    HMODULE h = GetModuleHandle("kernel32.dll");

    if (!h) {
        virReportSystemError(errno, "%s",
                             _("Unable to access kernel32.dll"));
        return 0;
    }

    /*  Use GlobalMemoryStatusEx if available.  */
    if ((pfnex = (PFN_MS_EX) GetProcAddress(h, "GlobalMemoryStatusEx"))) {
        lMEMORYSTATUSEX lms_ex;
        lms_ex.dwLength = sizeof(lms_ex);
        if (!pfnex(&lms_ex)) {
            virReportSystemError(EIO, "%s",
                                 _("Unable to query memory total"));
            return 0;
        }
        return lms_ex.ullTotalPhys;
    } else {
        /*  Fall back to GlobalMemoryStatus which is always available.
            but returns wrong results for physical memory > 4GB.  */
        MEMORYSTATUS ms;
        GlobalMemoryStatus(&ms);
        return  ms.dwTotalPhys;
    }
#endif
}


static unsigned long long
virHostMemGetAvailable(void)
{
#if defined WITH_SYSCTLBYNAME
    /* This works on freebsd and macOS */
    unsigned long long usermem = 0;
    size_t len = sizeof(usermem);

    if (sysctlbyname("hw.usermem", &usermem, &len, NULL, 0) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to query memory available"));
        return 0;
    }

    return usermem;
#elif defined _SC_AVPHYS_PAGES && defined _SC_PAGESIZE
    /* this works on linux */
    long long pages;
    long long pagesize;
    if ((pages = sysconf(_SC_AVPHYS_PAGES)) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to query memory available"));
        return 0;
    }
    if ((pagesize = sysconf(_SC_PAGESIZE)) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to query memory page size"));
        return 0;
    }
    return (unsigned long long)pages * (unsigned long long)pagesize;
#elif defined WIN32
    PFN_MS_EX pfnex;
    HMODULE h = GetModuleHandle("kernel32.dll");

    if (!h) {
        virReportSystemError(errno, "%s",
                             _("Unable to access kernel32.dll"));
        return 0;
    }

    /*  Use GlobalMemoryStatusEx if available.  */
    if ((pfnex = (PFN_MS_EX) GetProcAddress(h, "GlobalMemoryStatusEx"))) {
        lMEMORYSTATUSEX lms_ex;
        lms_ex.dwLength = sizeof(lms_ex);
        if (!pfnex(&lms_ex)) {
            virReportSystemError(EIO, "%s",
                                 _("Unable to query memory available"));
            return 0;
        }
        return lms_ex.ullAvailPhys;
    } else {
        /*  Fall back to GlobalMemoryStatus which is always available.
            but returns wrong results for physical memory > 4GB  */
        MEMORYSTATUS ms;
        GlobalMemoryStatus(&ms);
        return ms.dwAvailPhys;
    }
#endif
}


static int
virHostMemGetCellsFreeFake(unsigned long long *freeMems,
                           int startCell,
                           int maxCells G_GNUC_UNUSED)
{
    if (startCell != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("start cell %1$d out of range (0-%2$d)"),
                       startCell, 0);
        return -1;
    }

    if ((freeMems[0] = virHostMemGetAvailable()) == 0)
        return -1;

    return 1;
}

static int
virHostMemGetInfoFake(unsigned long long *mem,
                      unsigned long long *freeMem)
{
    if (mem &&
        (*mem = virHostMemGetTotal()) == 0)
        return -1;

    if (freeMem &&
        (*freeMem = virHostMemGetAvailable()) == 0)
        return -1;

    return 0;
}


int
virHostMemGetCellsFree(unsigned long long *freeMems,
                       int startCell,
                       int maxCells)
{
    unsigned long long mem;
    int n, lastCell, numCells;
    int maxCell;

    if (!virNumaIsAvailable())
        return virHostMemGetCellsFreeFake(freeMems,
                                          startCell, maxCells);

    if ((maxCell = virNumaGetMaxNode()) < 0)
        return 0;

    if (startCell > maxCell) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("start cell %1$d out of range (0-%2$d)"),
                       startCell, maxCell);
        return -1;
    }
    lastCell = startCell + maxCells - 1;
    if (lastCell > maxCell)
        lastCell = maxCell;

    for (numCells = 0, n = startCell; n <= lastCell; n++) {
        virNumaGetNodeMemory(n, NULL, &mem);

        freeMems[numCells++] = mem;
    }
    return numCells;
}

int
virHostMemGetInfo(unsigned long long *mem,
                  unsigned long long *freeMem)
{
    int max_node;
    int n;

    if (mem)
        *mem = 0;

    if (freeMem)
        *freeMem = 0;

    if (!virNumaIsAvailable())
        return virHostMemGetInfoFake(mem, freeMem);

    if ((max_node = virNumaGetMaxNode()) < 0)
        return -1;

    for (n = 0; n <= max_node; n++) {
        unsigned long long tmp_mem = 0, tmp_freeMem = 0;

        if (!virNumaNodeIsAvailable(n))
            continue;

        if (virNumaGetNodeMemory(n, &tmp_mem, &tmp_freeMem) < 0)
            return -1;

        if (mem)
            *mem += tmp_mem;

        if (freeMem)
            *freeMem += tmp_freeMem;
    }

    return 0;
}

int
virHostMemGetFreePages(unsigned int npages,
                       unsigned int *pages,
                       int startCell,
                       unsigned int cellCount,
                       int lastCell,
                       unsigned long long *counts)
{
    int cell;
    size_t i, ncounts = 0;

    if (!virNumaIsAvailable() && lastCell == 0 &&
        startCell == 0 && cellCount == 1) {
        /* As a special case, if we were built without numactl and want to
         * fetch info on the fake NUMA node set startCell to -1 to make the
         * loop below fetch overall info. */
        startCell = -1;
    }

    if (startCell > lastCell) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("start cell %1$d out of range (0-%2$d)"),
                       startCell, lastCell);
        return -1;
    }

    lastCell = MIN(lastCell, startCell + (int) cellCount - 1);

    for (cell = startCell; cell <= lastCell; cell++) {
        for (i = 0; i < npages; i++) {
            unsigned int page_size = pages[i];
            unsigned long long page_free;

            if (virNumaGetPageInfo(cell, page_size, 0, NULL, &page_free) < 0)
                return -1;

            counts[ncounts++] = page_free;
        }
    }

    if (!ncounts) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("no suitable info found"));
        return -1;
    }

    return ncounts;
}

int
virHostMemAllocPages(unsigned int npages,
                     unsigned int *pageSizes,
                     unsigned long long *pageCounts,
                     int startCell,
                     unsigned int cellCount,
                     int lastCell,
                     bool add)
{
    int cell;
    size_t i, ncounts = 0;

    if (!virNumaIsAvailable() && lastCell == 0 &&
        startCell == 0 && cellCount == 1) {
        /* As a special case, if we were built without numactl and want to
         * allocate hugepages on the fake NUMA node set startCell to -1 to make
         * the loop below operate on NUMA agnostic sysfs paths. */
        startCell = -1;
    }

    if (startCell > lastCell) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("start cell %1$d out of range (0-%2$d)"),
                       startCell, lastCell);
        return -1;
    }

    lastCell = MIN(lastCell, startCell + (int) cellCount - 1);

    for (cell = startCell; cell <= lastCell; cell++) {
        for (i = 0; i < npages; i++) {
            unsigned int page_size = pageSizes[i];
            unsigned long long page_count = pageCounts[i];

            if (virNumaSetPagePoolSize(cell, page_size, page_count, add) < 0)
                return -1;

            ncounts++;
        }
    }

    return ncounts;
}

#if defined(__linux__)
# define HPAGE_PMD_SIZE_PATH "/sys/kernel/mm/transparent_hugepage/hpage_pmd_size"
static void
virHostMemGetTHPSizeSysfs(unsigned long long *size)
{
    if (virFileReadValueUllong(size, "%s", HPAGE_PMD_SIZE_PATH) < 0) {
        VIR_WARN("unable to get THP PMD size: %s", g_strerror(errno));
        return;
    }

    /* Size is now in bytes. Convert to KiB. */
    *size >>= 10;
}
#endif /* defined(__linux__) */


static void
virHostMemGetTHPSizeOnceInit(void)
{
#if defined(__linux__)
    virHostMemGetTHPSizeSysfs(&virHostTHPPMDSize);
#else /* !defined(__linux__) */
    VIR_WARN("Getting THP size not ported yet");
#endif /* !defined(__linux__) */
}


/**
 * virHostMemGetTHPSize:
 * @size: returned size of THP in kibibytes
 *
 * Obtain Transparent Huge Page size in kibibytes. The size
 * depends on host architecture and kernel. Because of virOnce(),
 * do not rely on errno in case of failure.
 *
 * Returns: 0 on success,
 *         -1 on failure.
 */
int
virHostMemGetTHPSize(unsigned long long *size)
{
    if (virOnce(&virHostMemGetTHPSizeOnce, virHostMemGetTHPSizeOnceInit) < 0)
        return -1;

    if (virHostTHPPMDSize == 0)
        return -1;

    *size = virHostTHPPMDSize;
    return 0;
}
