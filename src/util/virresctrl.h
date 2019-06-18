/*
 * virresctrl.h:
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

#pragma once

#include "internal.h"

#include "virbitmap.h"
#include "virutil.h"
#include "virenum.h"

typedef enum {
    VIR_CACHE_TYPE_BOTH,
    VIR_CACHE_TYPE_CODE,
    VIR_CACHE_TYPE_DATA,

    VIR_CACHE_TYPE_LAST
} virCacheType;

VIR_ENUM_DECL(virCache);
VIR_ENUM_DECL(virCacheKernel);

typedef enum {
    VIR_RESCTRL_MONITOR_TYPE_UNSUPPORT,
    VIR_RESCTRL_MONITOR_TYPE_CACHE,
    VIR_RESCTRL_MONITOR_TYPE_MEMBW,

    VIR_RESCTRL_MONITOR_TYPE_LAST
} virResctrlMonitorType;

VIR_ENUM_DECL(virResctrlMonitorPrefix);


typedef struct _virResctrlInfoPerCache virResctrlInfoPerCache;
typedef virResctrlInfoPerCache *virResctrlInfoPerCachePtr;
struct _virResctrlInfoPerCache {
    /* Smallest possible increase of the allocation size in bytes */
    unsigned long long granularity;
    /* Minimal allocatable size in bytes (if different from granularity) */
    unsigned long long min;
    /* Type of the allocation */
    virCacheType scope;
    /* Maximum number of simultaneous allocations */
    unsigned int max_allocation;
};

typedef struct _virResctrlInfoMemBWPerNode virResctrlInfoMemBWPerNode;
typedef virResctrlInfoMemBWPerNode *virResctrlInfoMemBWPerNodePtr;
struct _virResctrlInfoMemBWPerNode {
    /* Smallest possible increase of the allocation bandwidth in percentage */
    unsigned int granularity;
    /* Minimal allocatable bandwidth in percentage */
    unsigned int min;
    /* Maximum number of simultaneous allocations */
    unsigned int max_allocation;
};

typedef struct _virResctrlInfoMon virResctrlInfoMon;
typedef virResctrlInfoMon *virResctrlInfoMonPtr;
struct _virResctrlInfoMon {
    /* Maximum number of simultaneous monitors */
    unsigned int max_monitor;
    /* null-terminal string list for monitor features */
    char **features;
    /* Number of monitor features */
    size_t nfeatures;
    /* Monitor type */
    virResctrlMonitorType type;
    /* This adjustable value affects the final reuse of resources used by
     * monitor. After the action of removing a monitor, the kernel may not
     * release all hardware resources that monitor used immediately if the
     * cache occupancy value associated with 'removed' monitor is above this
     * threshold. Once the cache occupancy is below this threshold, the
     * underlying hardware resource will be reclaimed and be put into the
     * resource pool for next reusing.*/
    unsigned int cache_reuse_threshold;
    /* The cache 'level' that has the monitor capability */
    unsigned int cache_level;
};

typedef struct _virResctrlInfo virResctrlInfo;
typedef virResctrlInfo *virResctrlInfoPtr;

virResctrlInfoPtr
virResctrlInfoNew(void);

int
virResctrlInfoGetCache(virResctrlInfoPtr resctrl,
                       unsigned int level,
                       unsigned long long size,
                       size_t *ncontrols,
                       virResctrlInfoPerCachePtr **controls);

int
virResctrlInfoGetMemoryBandwidth(virResctrlInfoPtr resctrl,
                                 unsigned int level,
                                 virResctrlInfoMemBWPerNodePtr control);
/* Alloc-related things */
typedef struct _virResctrlAlloc virResctrlAlloc;
typedef virResctrlAlloc *virResctrlAllocPtr;

typedef int virResctrlAllocForeachCacheCallback(unsigned int level,
                                                virCacheType type,
                                                unsigned int cache,
                                                unsigned long long size,
                                                void *opaque);

typedef int virResctrlAllocForeachMemoryCallback(unsigned int id,
                                                 unsigned int size,
                                                 void *opaque);

virResctrlAllocPtr
virResctrlAllocNew(void);

bool
virResctrlAllocIsEmpty(virResctrlAllocPtr alloc);

int
virResctrlAllocSetCacheSize(virResctrlAllocPtr alloc,
                            unsigned int level,
                            virCacheType type,
                            unsigned int cache,
                            unsigned long long size);

int
virResctrlAllocForeachCache(virResctrlAllocPtr alloc,
                            virResctrlAllocForeachCacheCallback cb,
                            void *opaque);

int
virResctrlAllocSetMemoryBandwidth(virResctrlAllocPtr alloc,
                                  unsigned int id,
                                  unsigned int memory_bandwidth);

int
virResctrlAllocForeachMemory(virResctrlAllocPtr resctrl,
                             virResctrlAllocForeachMemoryCallback cb,
                             void *opaque);

int
virResctrlAllocSetID(virResctrlAllocPtr alloc,
                     const char *id);
const char *
virResctrlAllocGetID(virResctrlAllocPtr alloc);

char *
virResctrlAllocFormat(virResctrlAllocPtr alloc);

int
virResctrlAllocDeterminePath(virResctrlAllocPtr alloc,
                             const char *machinename);

int
virResctrlAllocCreate(virResctrlInfoPtr r_info,
                      virResctrlAllocPtr alloc,
                      const char *machinename);

int
virResctrlAllocAddPID(virResctrlAllocPtr alloc,
                      pid_t pid);

int
virResctrlAllocRemove(virResctrlAllocPtr alloc);

void
virResctrlInfoMonFree(virResctrlInfoMonPtr mon);

int
virResctrlInfoGetMonitorPrefix(virResctrlInfoPtr resctrl,
                               const char *prefix,
                               virResctrlInfoMonPtr *monitor);

/* Monitor-related things */

typedef struct _virResctrlMonitor virResctrlMonitor;
typedef virResctrlMonitor *virResctrlMonitorPtr;

typedef struct _virResctrlMonitorStats virResctrlMonitorStats;
typedef virResctrlMonitorStats *virResctrlMonitorStatsPtr;
struct _virResctrlMonitorStats {
    unsigned int id;
    unsigned int val;
};

virResctrlMonitorPtr
virResctrlMonitorNew(void);

int
virResctrlMonitorDeterminePath(virResctrlMonitorPtr monitor,
                               const char *machinename);

int
virResctrlMonitorAddPID(virResctrlMonitorPtr monitor,
                        pid_t pid);

int
virResctrlMonitorCreate(virResctrlMonitorPtr monitor,
                        const char *machinename);

int
virResctrlMonitorSetID(virResctrlMonitorPtr monitor,
                       const char *id);

const char *
virResctrlMonitorGetID(virResctrlMonitorPtr monitor);

void
virResctrlMonitorSetAlloc(virResctrlMonitorPtr monitor,
                          virResctrlAllocPtr alloc);

int
virResctrlMonitorRemove(virResctrlMonitorPtr monitor);

int
virResctrlMonitorGetCacheOccupancy(virResctrlMonitorPtr monitor,
                                   virResctrlMonitorStatsPtr **stats,
                                   size_t *nstats);

void
virResctrlMonitorFreeStats(virResctrlMonitorStatsPtr *stats,
                           size_t nstats);
