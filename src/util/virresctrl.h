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

#ifndef __VIR_RESCTRL_H__
# define __VIR_RESCTRL_H__

# include "internal.h"

# include "virbitmap.h"
# include "virutil.h"


typedef enum {
    VIR_CACHE_TYPE_BOTH,
    VIR_CACHE_TYPE_CODE,
    VIR_CACHE_TYPE_DATA,

    VIR_CACHE_TYPE_LAST
} virCacheType;

VIR_ENUM_DECL(virCache);
VIR_ENUM_DECL(virCacheKernel);


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

#endif /*  __VIR_RESCTRL_H__ */
