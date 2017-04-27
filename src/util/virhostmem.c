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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#if defined(__FreeBSD__) || defined(__APPLE__)
# include <sys/time.h>
# include <sys/types.h>
# include <sys/sysctl.h>
# include <sys/resource.h>
#endif

#include "viralloc.h"
#include "virhostmem.h"
#include "physmem.h"
#include "virerror.h"
#include "count-one-bits.h"
#include "virarch.h"
#include "virfile.h"
#include "virtypedparam.h"
#include "virstring.h"
#include "virnuma.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.hostmem");


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
                            _("nparams in %s must be %d"),
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
                                 _("sysctl failed for '%s'"),
                                 sysctl_map[i].sysctl_name);
            return -1;
        }

        param = &params[j++];
        if (virStrcpyStatic(param->field, sysctl_map[i].field) == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Field '%s' too long for destination"),
                           sysctl_map[i].field);
            return -1;
        }
        param->value = (unsigned long long)value * pagesize;
    }

    {
        virNodeMemoryStatsPtr param = &params[j++];

        if (sysctlbyname("vfs.bufspace", &bufpages, &bufpages_size, NULL, 0) < 0) {
            virReportSystemError(errno,
                                 _("sysctl failed for '%s'"),
                                 "vfs.bufspace");
            return -1;
        }
        if (virStrcpyStatic(param->field, VIR_NODE_MEMORY_STATS_BUFFERS) == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Field '%s' too long for destination"),
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
    int ret = -1;
    size_t i = 0, j = 0, k = 0;
    int found = 0;
    int nr_param;
    char line[1024];
    char meminfo_hdr[VIR_NODE_MEMORY_STATS_FIELD_LENGTH];
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
        ret = 0;
        goto cleanup;
    }

    if ((*nparams) != nr_param) {
        virReportInvalidArg(nparams,
                            _("nparams in %s must be %d"),
                            __FUNCTION__, nr_param);
        goto cleanup;
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
                    goto cleanup;
                }
                p++;
            }
            buf = p;
        }

        if (sscanf(buf, "%s %lu kB", meminfo_hdr, &val) < 2)
            continue;

        for (j = 0; field_conv[j].meminfo_hdr != NULL; j++) {
            struct field_conv *convp = &field_conv[j];

            if (STREQ(meminfo_hdr, convp->meminfo_hdr)) {
                virNodeMemoryStatsPtr param = &params[k++];

                if (virStrcpyStatic(param->field, convp->field) == NULL) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("Field kernel memory too long for destination"));
                    goto cleanup;
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
        goto cleanup;
    }

    ret = 0;

 cleanup:
    return ret;
}
#endif


int
virHostMemGetStats(int cellNum ATTRIBUTE_UNUSED,
                   virNodeMemoryStatsPtr params ATTRIBUTE_UNUSED,
                   int *nparams ATTRIBUTE_UNUSED,
                   unsigned int flags)
{
    virCheckFlags(0, -1);

#ifdef __linux__
    {
        int ret;
        char *meminfo_path = NULL;
        FILE *meminfo;
        int max_node;

        if (cellNum == VIR_NODE_MEMORY_STATS_ALL_CELLS) {
            if (VIR_STRDUP(meminfo_path, MEMINFO_PATH) < 0)
                return -1;
        } else {
            if ((max_node = virNumaGetMaxNode()) < 0)
                return -1;

            if (cellNum > max_node) {
                virReportInvalidArg(cellNum,
                                    _("cellNum in %s must be less than or equal to %d"),
                                    __FUNCTION__, max_node);
                return -1;
            }

            if (virAsprintf(&meminfo_path,
                            SYSFS_SYSTEM_PATH "/node/node%d/meminfo",
                            cellNum) < 0)
                return -1;
        }
        meminfo = fopen(meminfo_path, "r");

        if (!meminfo) {
            virReportSystemError(errno,
                                 _("cannot open %s"), meminfo_path);
            VIR_FREE(meminfo_path);
            return -1;
        }
        ret = virHostMemGetStatsLinux(meminfo, cellNum, params, nparams);
        VIR_FORCE_FCLOSE(meminfo);
        VIR_FREE(meminfo_path);

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
    char *path = NULL;
    char *strval = NULL;
    int ret = -1;
    int rc = -1;

    char *field = strchr(param->field, '_');
    sa_assert(field);
    field++;
    if (virAsprintf(&path, "%s/%s",
                    SYSFS_MEMORY_SHARED_PATH, field) < 0) {
        ret = -2;
        goto cleanup;
    }

    if (virAsprintf(&strval, "%u", param->value.ui) == -1) {
        ret = -2;
        goto cleanup;
    }

    if ((rc = virFileWriteStr(path, strval, 0)) < 0) {
        virReportSystemError(-rc, _("failed to set %s"), param->field);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(path);
    VIR_FREE(strval);
    return ret;
}

static bool
virHostMemParametersAreAllSupported(virTypedParameterPtr params,
                                    int nparams)
{
    char *path = NULL;
    size_t i;

    for (i = 0; i < nparams; i++) {
        virTypedParameterPtr param = &params[i];

        char *field = strchr(param->field, '_');
        sa_assert(field);
        field++;
        if (virAsprintf(&path, "%s/%s",
                        SYSFS_MEMORY_SHARED_PATH, field) < 0)
            return false;

        if (!virFileExists(path)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("Parameter '%s' is not supported by "
                             "this kernel"), param->field);
            VIR_FREE(path);
            return false;
        }

        VIR_FREE(path);
    }

    return true;
}
#endif

int
virHostMemSetParameters(virTypedParameterPtr params ATTRIBUTE_UNUSED,
                        int nparams ATTRIBUTE_UNUSED,
                        unsigned int flags)
{
    virCheckFlags(0, -1);

#ifdef __linux__
    size_t i;
    int rc;

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
        rc = virHostMemSetParameterValue(&params[i]);

        if (rc < 0)
            return -1;
    }

    return 0;
#else
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("node set memory parameters not implemented"
                     " on this platform"));
    return -1;
#endif
}

#ifdef __linux__
static int
virHostMemGetParameterValue(const char *field,
                            void *value)
{
    char *path = NULL;
    char *buf = NULL;
    char *tmp = NULL;
    int ret = -1;
    int rc = -1;

    if (virAsprintf(&path, "%s/%s",
                    SYSFS_MEMORY_SHARED_PATH, field) < 0)
        goto cleanup;

    if (!virFileExists(path)) {
        ret = -2;
        goto cleanup;
    }

    if (virFileReadAll(path, 1024, &buf) < 0)
        goto cleanup;

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
                       _("failed to parse %s"), field);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(path);
    VIR_FREE(buf);
    return ret;
}
#endif

#define NODE_MEMORY_PARAMETERS_NUM 8
int
virHostMemGetParameters(virTypedParameterPtr params ATTRIBUTE_UNUSED,
                        int *nparams ATTRIBUTE_UNUSED,
                        unsigned int flags)
{
    virCheckFlags(VIR_TYPED_PARAM_STRING_OKAY, -1);

#ifdef __linux__
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
#else
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("node get memory parameters not implemented"
                     " on this platform"));
    return -1;
#endif
}


static int
virHostMemGetCellsFreeFake(unsigned long long *freeMems,
                           int startCell,
                           int maxCells ATTRIBUTE_UNUSED)
{
    double avail = physmem_available();

    if (startCell != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("start cell %d out of range (0-%d)"),
                       startCell, 0);
        return -1;
    }

    freeMems[0] = (unsigned long long)avail;

    if (!freeMems[0]) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot determine free memory"));
        return -1;
    }

    return 1;
}

static int
virHostMemGetInfoFake(unsigned long long *mem,
                      unsigned long long *freeMem)
{
    int ret = -1;

    if (mem) {
        double total = physmem_total();
        if (!total) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Cannot determine free memory"));
            goto cleanup;
        }

        *mem = (unsigned long long) total;
    }

    if (freeMem) {
        double avail = physmem_available();

        if (!avail) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Cannot determine free memory"));
            goto cleanup;
        }

        *freeMem = (unsigned long long) avail;
    }

    ret = 0;
 cleanup:
    return ret;
}


int
virHostMemGetCellsFree(unsigned long long *freeMems,
                       int startCell,
                       int maxCells)
{
    unsigned long long mem;
    int n, lastCell, numCells;
    int ret = -1;
    int maxCell;

    if (!virNumaIsAvailable())
        return virHostMemGetCellsFreeFake(freeMems,
                                          startCell, maxCells);

    if ((maxCell = virNumaGetMaxNode()) < 0)
        return 0;

    if (startCell > maxCell) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("start cell %d out of range (0-%d)"),
                       startCell, maxCell);
        goto cleanup;
    }
    lastCell = startCell + maxCells - 1;
    if (lastCell > maxCell)
        lastCell = maxCell;

    for (numCells = 0, n = startCell; n <= lastCell; n++) {
        virNumaGetNodeMemory(n, NULL, &mem);

        freeMems[numCells++] = mem;
    }
    ret = numCells;

 cleanup:
    return ret;
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
                       unsigned long long *counts)
{
    int ret = -1;
    int cell, lastCell;
    size_t i, ncounts = 0;

    if ((lastCell = virNumaGetMaxNode()) < 0)
        return 0;

    if (startCell > lastCell) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("start cell %d out of range (0-%d)"),
                       startCell, lastCell);
        goto cleanup;
    }

    lastCell = MIN(lastCell, startCell + (int) cellCount - 1);

    for (cell = startCell; cell <= lastCell; cell++) {
        for (i = 0; i < npages; i++) {
            unsigned int page_size = pages[i];
            unsigned int page_free;

            if (virNumaGetPageInfo(cell, page_size, 0, NULL, &page_free) < 0)
                goto cleanup;

            counts[ncounts++] = page_free;
        }
    }

    if (!ncounts) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("no suitable info found"));
        goto cleanup;
    }

    ret = ncounts;
 cleanup:
    return ret;
}

int
virHostMemAllocPages(unsigned int npages,
                     unsigned int *pageSizes,
                     unsigned long long *pageCounts,
                     int startCell,
                     unsigned int cellCount,
                     bool add)
{
    int ret = -1;
    int cell, lastCell;
    size_t i, ncounts = 0;

    if ((lastCell = virNumaGetMaxNode()) < 0)
        return 0;

    if (startCell > lastCell) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("start cell %d out of range (0-%d)"),
                       startCell, lastCell);
        goto cleanup;
    }

    lastCell = MIN(lastCell, startCell + (int) cellCount - 1);

    for (cell = startCell; cell <= lastCell; cell++) {
        for (i = 0; i < npages; i++) {
            unsigned int page_size = pageSizes[i];
            unsigned long long page_count = pageCounts[i];

            if (virNumaSetPagePoolSize(cell, page_size, page_count, add) < 0)
                goto cleanup;

            ncounts++;
        }
    }

    ret = ncounts;
 cleanup:
    return ret;
}
