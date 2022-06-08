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

#include "virobject.h"
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
struct _virResctrlInfoMemBWPerNode {
    /* Smallest possible increase of the allocation bandwidth in percentage */
    unsigned int granularity;
    /* Minimal allocatable bandwidth in percentage */
    unsigned int min;
    /* Maximum number of simultaneous allocations */
    unsigned int max_allocation;
};

typedef struct _virResctrlInfoMon virResctrlInfoMon;
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

virResctrlInfo *
virResctrlInfoNew(void);

int
virResctrlInfoGetCache(virResctrlInfo *resctrl,
                       unsigned int level,
                       unsigned long long size,
                       size_t *ncontrols,
                       virResctrlInfoPerCache ***controls);

int
virResctrlInfoGetMemoryBandwidth(virResctrlInfo *resctrl,
                                 unsigned int level,
                                 virResctrlInfoMemBWPerNode *control);
/* Alloc-related things */
typedef struct _virResctrlAlloc virResctrlAlloc;

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virResctrlAlloc, virObjectUnref);


typedef int virResctrlAllocForeachCacheCallback(unsigned int level,
                                                virCacheType type,
                                                unsigned int cache,
                                                unsigned long long size,
                                                void *opaque);

typedef int virResctrlAllocForeachMemoryCallback(unsigned int id,
                                                 unsigned int size,
                                                 void *opaque);

virResctrlAlloc *
virResctrlAllocNew(void);

bool
virResctrlAllocIsEmpty(virResctrlAlloc *alloc);

int
virResctrlAllocSetCacheSize(virResctrlAlloc *alloc,
                            unsigned int level,
                            virCacheType type,
                            unsigned int cache,
                            unsigned long long size);

int
virResctrlAllocForeachCache(virResctrlAlloc *alloc,
                            virResctrlAllocForeachCacheCallback cb,
                            void *opaque);

int
virResctrlAllocSetMemoryBandwidth(virResctrlAlloc *alloc,
                                  unsigned int id,
                                  unsigned int memory_bandwidth);

int
virResctrlAllocForeachMemory(virResctrlAlloc *alloc,
                             virResctrlAllocForeachMemoryCallback cb,
                             void *opaque);

int
virResctrlAllocSetID(virResctrlAlloc *alloc,
                     const char *id);
const char *
virResctrlAllocGetID(virResctrlAlloc *alloc);

char *
virResctrlAllocFormat(virResctrlAlloc *alloc);

int
virResctrlAllocDeterminePath(virResctrlAlloc *alloc,
                             const char *machinename);

int
virResctrlAllocCreate(virResctrlInfo *r_info,
                      virResctrlAlloc *alloc,
                      const char *machinename);

int
virResctrlAllocAddPID(virResctrlAlloc *alloc,
                      pid_t pid);

int
virResctrlAllocRemove(virResctrlAlloc *alloc);

void
virResctrlInfoMonFree(virResctrlInfoMon *mon);

int
virResctrlInfoGetMonitorPrefix(virResctrlInfo *resctrl,
                               const char *prefix,
                               virResctrlInfoMon **monitor);

/* Monitor-related things */

typedef struct _virResctrlMonitor virResctrlMonitor;

typedef struct _virResctrlMonitorStats virResctrlMonitorStats;
struct _virResctrlMonitorStats {
    /* The system assigned cache ID associated with statistical record */
     unsigned int id;
    /* @features is a NULL terminal string list tracking the statistical record
     * name.*/
    char **features;
    /* @vals store the statistical record values and @val[0] is the value for
     * @features[0], @val[1] for@features[1] ... respectively */
    unsigned long long *vals;
    /* The length of @vals array */
    size_t nvals;
};

virResctrlMonitor *
virResctrlMonitorNew(void);

int
virResctrlMonitorDeterminePath(virResctrlMonitor *monitor,
                               const char *machinename);

int
virResctrlMonitorAddPID(virResctrlMonitor *monitor,
                        pid_t pid);

int
virResctrlMonitorCreate(virResctrlMonitor *monitor,
                        const char *machinename);

int
virResctrlMonitorSetID(virResctrlMonitor *monitor,
                       const char *id);

const char *
virResctrlMonitorGetID(virResctrlMonitor *monitor);

void
virResctrlMonitorSetAlloc(virResctrlMonitor *monitor,
                          virResctrlAlloc *alloc);

int
virResctrlMonitorRemove(virResctrlMonitor *monitor);

int
virResctrlMonitorGetStats(virResctrlMonitor *monitor,
                          const char **resources,
                          virResctrlMonitorStats ***stats,
                          size_t *nstats);

void
virResctrlMonitorStatsFree(virResctrlMonitorStats *stats);
