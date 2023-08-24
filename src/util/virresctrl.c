/*
 * virresctrl.c:
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

#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define LIBVIRT_VIRRESCTRLPRIV_H_ALLOW
#include "virresctrlpriv.h"
#include "viralloc.h"
#include "virbuffer.h"
#include "virfile.h"
#include "virlog.h"
#include "virobject.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_RESCTRL

VIR_LOG_INIT("util.virresctrl");


/* Resctrl is short for Resource Control.  It might be implemented for various
 * resources. Currently this supports cache allocation technology (aka CAT),
 * memory bandwidth allocation (aka MBA) and cache monitoring technology (aka
 * CMT). More resources technologies may be added in the future.
 */


/* Common definitions */
#define SYSFS_RESCTRL_PATH "/sys/fs/resctrl"


/* Following are three different enum implementations for the same enum.  Each
 * one of them helps translating to/from strings for different interfaces.  The
 * delimiter must be VIR_CACHE_TYPE_LAST for all of them in order to stay
 * consistent in between all of them. */

/* Cache name mapping for Linux kernel naming. */
VIR_ENUM_IMPL(virCacheKernel,
              VIR_CACHE_TYPE_LAST,
              "Unified",
              "Instruction",
              "Data",
);

/* Cache name mapping for our XML naming. */
VIR_ENUM_IMPL(virCache,
              VIR_CACHE_TYPE_LAST,
              "both",
              "code",
              "data",
);

/* Cache name mapping for resctrl interface naming. */
VIR_ENUM_DECL(virResctrl);
VIR_ENUM_IMPL(virResctrl,
              VIR_CACHE_TYPE_LAST,
              "",
              "CODE",
              "DATA",
);

/* Monitor feature name prefix mapping for monitor naming */
VIR_ENUM_IMPL(virResctrlMonitorPrefix,
              VIR_RESCTRL_MONITOR_TYPE_LAST,
              "__unsupported__",
              "llc_",
              "mbm_",
);


/* All private typedefs so that they exist for all later definitions.  This way
 * structs can be included in one or another without reorganizing the code every
 * time. */
typedef struct _virResctrlInfoPerType virResctrlInfoPerType;

typedef struct _virResctrlInfoPerLevel virResctrlInfoPerLevel;

typedef struct _virResctrlInfoMemBW virResctrlInfoMemBW;

typedef struct _virResctrlInfoMongrp virResctrlInfoMongrp;

typedef struct _virResctrlAllocPerType virResctrlAllocPerType;

typedef struct _virResctrlAllocPerLevel virResctrlAllocPerLevel;

typedef struct _virResctrlAllocMemBW virResctrlAllocMemBW;


/* Class definitions and initializations */
static virClass *virResctrlInfoClass;
static virClass *virResctrlAllocClass;
static virClass *virResctrlMonitorClass;


/* virResctrlInfo */
struct _virResctrlInfoPerType {
    /* Kernel-provided information */
    unsigned int min_cbm_bits;

    /* Our computed information from the above */
    unsigned int bits;
    unsigned int max_cache_id;

    /* In order to be self-sufficient we need size information per cache.
     * Funnily enough, one of the outcomes of the resctrl design is that it
     * does not account for different sizes per cache on the same level.  So
     * for the sake of easiness, let's copy that, for now. */
    unsigned long long size;

    /* Information that we will return upon request (this is public struct) as
     * until now all the above is internal to this module */
    virResctrlInfoPerCache control;
};

struct _virResctrlInfoPerLevel {
    virResctrlInfoPerType **types;
};

/* Information about memory bandwidth allocation */
struct _virResctrlInfoMemBW {
    /* minimum memory bandwidth allowed */
    unsigned int min_bandwidth;
    /* bandwidth granularity */
    unsigned int bandwidth_granularity;
    /* Maximum number of simultaneous allocations */
    unsigned int max_allocation;
    /* level number of last level cache */
    unsigned int last_level_cache;
    /* max id of last level cache, this is used to track
     * how many last level cache available in host system,
     * the number of memory bandwidth allocation controller
     * is identical with last level cache. */
    unsigned int max_id;
};

struct _virResctrlInfoMongrp {
    /* Maximum number of simultaneous monitors */
    unsigned int max_monitor;
    /* null-terminal string list for monitor features */
    char **features;
    /* Number of monitor features */
    size_t nfeatures;

    /* Last level cache related information */

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

struct _virResctrlInfo {
    virObject parent;

    virResctrlInfoPerLevel **levels;
    size_t nlevels;

    virResctrlInfoMemBW *membw_info;

    virResctrlInfoMongrp *monitor_info;
};


static void
virResctrlInfoDispose(void *obj)
{
    size_t i = 0;
    size_t j = 0;

    virResctrlInfo *resctrl = obj;

    for (i = 0; i < resctrl->nlevels; i++) {
        virResctrlInfoPerLevel *level = resctrl->levels[i];

        if (!level)
            continue;

        if (level->types) {
            for (j = 0; j < VIR_CACHE_TYPE_LAST; j++)
                g_free(level->types[j]);
        }
        g_free(level->types);
        g_free(level);
    }

    if (resctrl->monitor_info)
        g_strfreev(resctrl->monitor_info->features);

    g_free(resctrl->membw_info);
    g_free(resctrl->levels);
    g_free(resctrl->monitor_info);
}


void
virResctrlInfoMonFree(virResctrlInfoMon *mon)
{
    if (!mon)
        return;

    g_strfreev(mon->features);
    g_free(mon);
}


/* virResctrlAlloc and virResctrlMonitor */

/*
 * virResctrlAlloc and virResctrlMonitor are representing a resource control
 * group (in XML under cputune/cachetune and consequently a directory under
 * /sys/fs/resctrl). virResctrlAlloc is the data structure for resource
 * allocation, while the virResctrlMonitor represents the resource monitoring
 * part.
 *
 * virResctrlAlloc represents one allocation. Since it can have multiple
 * parts of multiple caches allocated it is represented as bunch of nested
 * sparse arrays (by sparse I mean array of pointers so that each might be NULL
 * in case there is no allocation for that particular cache allocation (level,
 * cache, ...) or memory allocation for particular node).
 *
 * Allocation corresponding to root directory, /sys/fs/sysctrl/, defines the
 * default resource allocating policy, which is created immediately after
 * mounting, and owns all the tasks and cpus in the system. Cache or memory
 * bandwidth resource will be shared for tasks in this allocation.
 *
 * =====Cache allocation technology (CAT)=====
 *
 * Since one allocation can be made for caches on different levels, the first
 * nested sparse array is of types virResctrlAllocPerLevel.  For example if you
 * have allocation for level 3 cache, there will be three NULL pointers and then
 * allocated pointer to virResctrlAllocPerLevel.  That way you can access it by
 * `alloc[level]` as O(1) is desired instead of crawling through normal arrays
 * or lists in three nested loops.  The code uses a lot of direct accesses.
 *
 * Each virResctrlAllocPerLevel can have allocations for different cache
 * allocation types.  You can allocate instruction cache (VIR_CACHE_TYPE_CODE),
 * data cache (VIR_CACHE_TYPE_DATA) or unified cache (VIR_CACHE_TYPE_BOTH).
 * Those allocations are kept in sparse array of virResctrlAllocPerType pointers.
 *
 * For each virResctrlAllocPerType users can request some size of the cache to
 * be allocated.  That's what the sparse array `sizes` is for.  Non-NULL
 * pointers represent requested size allocations.  The array is indexed by host
 * cache id (gotten from `/sys/devices/system/cpu/cpuX/cache/indexY/id`).  Users
 * can see this information e.g. in the output of `virsh capabilities` (for that
 * information there's the other struct, namely `virResctrlInfo`).
 *
 * When allocation is being created we need to find unused part of the cache for
 * all of them.  While doing that we store the bitmask in a sparse array of
 * virBitmaps named `masks` indexed the same way as `sizes`.  The upper bounds
 * of the sparse arrays are stored in nmasks or nsizes, respectively.
 *
 * =====Memory Bandwidth allocation technology (MBA)=====
 *
 * The memory bandwidth allocation support in virResctrlAlloc works in the
 * same fashion as CAT. However, memory bandwidth controller doesn't have a
 * hierarchy organization as cache, each node have one memory bandwidth
 * controller to memory bandwidth distribution. The number of memory bandwidth
 * controller is identical with number of last level cache. So MBA also employs
 * a sparse array to represent whether a memory bandwidth allocation happens
 * on corresponding node. The available memory controller number is collected
 * in 'virResctrlInfo'.
 *
 * =====Cache monitoring technology (CMT)=====
 *
 * Cache monitoring technology is used to perceive how many cache the process
 * is using actually. virResctrlMonitor represents the resource control
 * monitoring group, it is supported to monitor resource utilization
 * information on granularity of vcpu.
 *
 * From a hardware perspective, cache monitoring technology (CMT), memory
 * bandwidth technology (MBM), as well as the CAT and MBA, are all orthogonal
 * features. The monitor will be created under the scope of default resctrl
 * group if no specific CAT or MBA entries are provided for the guest."
 */
struct _virResctrlAllocPerType {
    /* There could be bool saying whether this is set or not, but since everything
     * in virResctrlAlloc (and most of libvirt) goes with pointer arrays we would
     * have to have one more level of allocation anyway, so this stays faithful to
     * the concept */
    unsigned long long **sizes;
    size_t nsizes;

    /* Mask for each cache */
    virBitmap **masks;
    size_t nmasks;
};

struct _virResctrlAllocPerLevel {
    virResctrlAllocPerType **types; /* Indexed with enum virCacheType */
    /* There is no `ntypes` member variable as it is always allocated for
     * VIR_CACHE_TYPE_LAST number of items */
};

/*
 * virResctrlAllocMemBW represents one memory bandwidth allocation.
 * Since it can have several last level caches in a NUMA system, it is
 * also represented as a nested sparse arrays as virRestrlAllocPerLevel.
 */
struct _virResctrlAllocMemBW {
    unsigned int **bandwidths;
    size_t nbandwidths;
};

struct _virResctrlAlloc {
    virObject parent;

    virResctrlAllocPerLevel **levels;
    size_t nlevels;

    virResctrlAllocMemBW *mem_bw;

    /* The identifier (any unique string for now) */
    char *id;
    /* libvirt-generated path in /sys/fs/resctrl for this particular
     * allocation */
    char *path;
};

/*
 * virResctrlMonitor is the data structure for resctrl monitor. Resctrl
 * monitor represents a resctrl monitoring group, which can be used to
 * monitor the resource utilization information for either cache or
 * memory bandwidth.
 */
struct _virResctrlMonitor {
    virObject parent;

    /* Each virResctrlMonitor is associated with one specific allocation,
     * either the root directory allocation under /sys/fs/resctrl or a
     * specific allocation defined under the root directory.
     * This pointer points to the allocation this monitor is associated with.
     */
    virResctrlAlloc *alloc;
    /* The monitor identifier. For a monitor has the same @path name as its
     * @alloc, the @id will be set to the same value as it is in @alloc->id.
     */
    char *id;
    /* libvirt-generated path in /sys/fs/resctrl for this particular
     * monitor */
    char *path;
};


static void
virResctrlAllocDispose(void *obj)
{
    size_t i = 0;
    size_t j = 0;
    size_t k = 0;

    virResctrlAlloc *alloc = obj;

    for (i = 0; i < alloc->nlevels; i++) {
        virResctrlAllocPerLevel *level = alloc->levels[i];

        if (!level)
            continue;

        for (j = 0; j < VIR_CACHE_TYPE_LAST; j++) {
            virResctrlAllocPerType *type = level->types[j];

            if (!type)
                continue;

            for (k = 0; k < type->nsizes; k++)
                g_free(type->sizes[k]);

            for (k = 0; k < type->nmasks; k++)
                virBitmapFree(type->masks[k]);

            g_free(type->sizes);
            g_free(type->masks);
            g_free(type);
        }
        g_free(level->types);
        g_free(level);
    }

    if (alloc->mem_bw) {
        virResctrlAllocMemBW *mem_bw = alloc->mem_bw;
        for (i = 0; i < mem_bw->nbandwidths; i++)
            g_free(mem_bw->bandwidths[i]);
        g_free(alloc->mem_bw->bandwidths);
        g_free(alloc->mem_bw);
    }

    g_free(alloc->id);
    g_free(alloc->path);
    g_free(alloc->levels);
}


static void
virResctrlMonitorDispose(void *obj)
{
    virResctrlMonitor *monitor = obj;

    virObjectUnref(monitor->alloc);
    g_free(monitor->id);
    g_free(monitor->path);
}


/* Global initialization for classes */
static int
virResctrlOnceInit(void)
{
    if (!VIR_CLASS_NEW(virResctrlInfo, virClassForObject()))
        return -1;

    if (!VIR_CLASS_NEW(virResctrlAlloc, virClassForObject()))
        return -1;

    if (!VIR_CLASS_NEW(virResctrlMonitor, virClassForObject()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virResctrl);


/* Common functions */
#ifndef WIN32

static int
virResctrlLock(void)
{
    int fd = open(SYSFS_RESCTRL_PATH, O_RDONLY | O_CLOEXEC);

    if (fd < 0) {
        virReportSystemError(errno, "%s", _("Cannot open resctrl"));
        return -1;
    }

    if (flock(fd, LOCK_EX) < 0) {
        virReportSystemError(errno, "%s", _("Cannot lock resctrl"));
        VIR_FORCE_CLOSE(fd);
        return -1;
    }

    return fd;
}


static int
virResctrlUnlock(int fd)
{
    if (fd == -1)
        return 0;

    /* The lock gets unlocked by closing the fd, which we need to do anyway in
     * order to clean up properly */
    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno, "%s", _("Cannot close resctrl"));

        /* Trying to save the already broken */
        if (flock(fd, LOCK_UN) < 0)
            virReportSystemError(errno, "%s", _("Cannot unlock resctrl"));

        return -1;
    }

    return 0;
}

#else /* WIN32 */

static int
virResctrlLock(void)
{
    virReportSystemError(ENOSYS, "%s",
                         _("resctrl locking is not supported on this platform"));
    return -1;
}


static int
virResctrlUnlock(int fd G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("resctrl locking is not supported on this platform"));
    return -1;
}

#endif /* WIN32 */


/* virResctrlInfo-related definitions */
static int
virResctrlGetCacheInfo(virResctrlInfo *resctrl,
                       DIR *dirp)
{
    int rv = -1;
    struct dirent *ent = NULL;

    while ((rv = virDirRead(dirp, &ent, SYSFS_RESCTRL_PATH "/info")) > 0) {
        g_autofree char *cbm_mask_str = NULL;
        g_autoptr(virBitmap) cbm_mask_map = NULL;
        char *endptr = NULL;
        int type = 0;
        unsigned int level = 0;
        virResctrlInfoPerLevel *i_level = NULL;
        g_autofree virResctrlInfoPerType *i_type = NULL;

        VIR_DEBUG("Parsing info type '%s'", ent->d_name);
        if (ent->d_name[0] != 'L')
            continue;

        if (virStrToLong_uip(ent->d_name + 1, &endptr, 10, &level) < 0) {
            VIR_DEBUG("Cannot parse resctrl cache info level '%s'", ent->d_name + 1);
            continue;
        }

        type = virResctrlTypeFromString(endptr);
        if (type < 0) {
            VIR_DEBUG("Ignoring resctrl cache info with suffix '%s'", endptr);
            continue;
        }

        i_type = g_new0(virResctrlInfoPerType, 1);
        i_type->control.scope = type;

        rv = virFileReadValueUint(&i_type->control.max_allocation,
                                  SYSFS_RESCTRL_PATH "/info/%s/num_closids",
                                  ent->d_name);
        if (rv == -2) {
            /* The file doesn't exist, so it's unusable for us,
             *  but we can scan further */
            VIR_WARN("The path '" SYSFS_RESCTRL_PATH "/info/%s/num_closids' "
                     "does not exist",
                     ent->d_name);
        } else if (rv < 0) {
            /* Other failures are fatal, so just quit */
            return -1;
        }

        rv = virFileReadValueString(&cbm_mask_str,
                                    SYSFS_RESCTRL_PATH
                                    "/info/%s/cbm_mask",
                                    ent->d_name);
        if (rv == -2) {
            /* If the previous file exists, so should this one.  Hence -2 is
             * fatal in this case as well (errors out in next condition) - the
             * kernel interface might've changed too much or something else is
             * wrong. */
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Cannot get cbm_mask from resctrl cache info"));
        }
        if (rv < 0)
            return -1;

        virStringTrimOptionalNewline(cbm_mask_str);

        if (!(cbm_mask_map = virBitmapNewString(cbm_mask_str))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Cannot parse cbm_mask from resctrl cache info"));
            return -1;
        }

        i_type->bits = virBitmapCountBits(cbm_mask_map);

        rv = virFileReadValueUint(&i_type->min_cbm_bits,
                                  SYSFS_RESCTRL_PATH "/info/%s/min_cbm_bits",
                                  ent->d_name);
        if (rv == -2)
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Cannot get min_cbm_bits from resctrl cache info"));
        if (rv < 0)
            return -1;

        if (resctrl->nlevels <= level)
            VIR_EXPAND_N(resctrl->levels, resctrl->nlevels,
                         level - resctrl->nlevels + 1);

        if (!resctrl->levels[level]) {
            virResctrlInfoPerType **types = NULL;

            types = g_new0(virResctrlInfoPerType *, VIR_CACHE_TYPE_LAST);

            resctrl->levels[level] = g_new0(virResctrlInfoPerLevel, 1);
            resctrl->levels[level]->types = types;
        }

        i_level = resctrl->levels[level];

        if (i_level->types[type]) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Duplicate cache type in resctrl for level %1$u"),
                           level);
            return -1;
        }

        i_level->types[type] = g_steal_pointer(&i_type);
    }

    return 0;
}


static int
virResctrlGetMemoryBandwidthInfo(virResctrlInfo *resctrl)
{
    int rv = -1;
    g_autofree virResctrlInfoMemBW *i_membw = NULL;

    /* query memory bandwidth allocation info */
    i_membw = g_new0(virResctrlInfoMemBW, 1);
    rv = virFileReadValueUint(&i_membw->bandwidth_granularity,
                              SYSFS_RESCTRL_PATH "/info/MB/bandwidth_gran");
    if (rv == -2) {
        /* The file doesn't exist, so it's unusable for us,
         * probably memory bandwidth allocation unsupported */
        VIR_INFO("The path '" SYSFS_RESCTRL_PATH "/info/MB/bandwidth_gran'"
                 "does not exist");
        return 0;
    } else if (rv < 0) {
        /* Other failures are fatal, so just quit */
        return -1;
    }

    rv = virFileReadValueUint(&i_membw->min_bandwidth,
                              SYSFS_RESCTRL_PATH "/info/MB/min_bandwidth");
    if (rv == -2) {
        /* If the previous file exists, so should this one. Hence -2 is
         * fatal in this case (errors out in next condition) - the kernel
         * interface might've changed too much or something else is wrong. */
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot get min bandwidth from resctrl memory info"));
    }
    if (rv < 0)
        return -1;

    rv = virFileReadValueUint(&i_membw->max_allocation,
                              SYSFS_RESCTRL_PATH "/info/MB/num_closids");
    if (rv == -2) {
        /* Similar reasoning to min_bandwidth above. */
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot get max allocation from resctrl memory info"));
    }
    if (rv < 0)
        return -1;

    resctrl->membw_info = g_steal_pointer(&i_membw);
    return 0;
}


/*
 * Retrieve monitor capability from the resource control file system.
 *
 * The monitor capability is exposed through "SYSFS_RESCTRL_PATH/info/L3_MON"
 * directory under the resource control file system. The monitor capability is
 * parsed by reading the interface files and stored in the structure
 * 'virResctrlInfoMongrp'.
 *
 * Not all host supports the resource monitor, leave the pointer
 * @resctrl->monitor_info empty if not supported.
 */
static int
virResctrlGetMonitorInfo(virResctrlInfo *resctrl)
{
    int rv = -1;
    g_autofree char *featurestr = NULL;
    g_autofree virResctrlInfoMongrp *info_monitor = NULL;

    info_monitor = g_new0(virResctrlInfoMongrp, 1);

    /* For now, monitor only exists in level 3 cache */
    info_monitor->cache_level = 3;

    rv = virFileReadValueUint(&info_monitor->max_monitor,
                              SYSFS_RESCTRL_PATH "/info/L3_MON/num_rmids");
    if (rv == -2) {
        /* The file doesn't exist, so it's unusable for us, probably resource
         * monitor unsupported */
        VIR_INFO("The file '" SYSFS_RESCTRL_PATH "/info/L3_MON/num_rmids' "
                 "does not exist");
        return 0;
    } else if (rv < 0) {
        /* Other failures are fatal, so just quit */
        return -1;
    }

    rv = virFileReadValueUint(&info_monitor->cache_reuse_threshold,
                              SYSFS_RESCTRL_PATH
                              "/info/L3_MON/max_threshold_occupancy");
    if (rv == -2) {
        /* If CMT is not supported, then 'max_threshold_occupancy' file
         * will not exist. */
        VIR_DEBUG("File '" SYSFS_RESCTRL_PATH
                  "/info/L3_MON/max_threshold_occupancy' does not exist");
    } else if (rv < 0) {
        return -1;
    }

    rv = virFileReadValueString(&featurestr,
                                SYSFS_RESCTRL_PATH
                                "/info/L3_MON/mon_features");
    if (rv == -2)
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot get mon_features from resctrl"));
    if (rv < 0)
        return -1;

    if (!*featurestr) {
        /* If no feature found in "/info/L3_MON/mon_features",
         * some error happens */
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Got empty feature list from resctrl"));
        return -1;
    }

    info_monitor->features = g_strsplit(featurestr, "\n", 0);
    info_monitor->nfeatures = g_strv_length(info_monitor->features);
    VIR_DEBUG("Resctrl supported %zd monitoring features", info_monitor->nfeatures);

    resctrl->monitor_info = g_steal_pointer(&info_monitor);

    return 0;
}


static int
virResctrlGetInfo(virResctrlInfo *resctrl)
{
    g_autoptr(DIR) dirp = NULL;
    int ret = -1;

    ret = virDirOpenIfExists(&dirp, SYSFS_RESCTRL_PATH "/info");
    if (ret <= 0)
        return ret;

    if ((ret = virResctrlGetMemoryBandwidthInfo(resctrl)) < 0)
        return -1;

    if ((ret = virResctrlGetCacheInfo(resctrl, dirp)) < 0)
        return -1;

    if ((ret = virResctrlGetMonitorInfo(resctrl)) < 0)
        return -1;

    return 0;
}


virResctrlInfo *
virResctrlInfoNew(void)
{
    virResctrlInfo *ret = NULL;

    if (virResctrlInitialize() < 0)
        return NULL;

    ret = virObjectNew(virResctrlInfoClass);
    if (!ret)
        return NULL;

    if (virResctrlGetInfo(ret) < 0) {
        virObjectUnref(ret);
        return NULL;
    }

    return ret;
}


static bool
virResctrlInfoIsEmpty(virResctrlInfo *resctrl)
{
    size_t i = 0;
    size_t j = 0;

    if (!resctrl)
        return true;

    if (resctrl->membw_info)
        return false;

    if (resctrl->monitor_info)
        return false;

    for (i = 0; i < resctrl->nlevels; i++) {
        virResctrlInfoPerLevel *i_level = resctrl->levels[i];

        if (!i_level)
            continue;

        for (j = 0; j < VIR_CACHE_TYPE_LAST; j++) {
            if (i_level->types[j])
                return false;
        }
    }

    return true;
}


int
virResctrlInfoGetMemoryBandwidth(virResctrlInfo *resctrl,
                                 unsigned int level,
                                 virResctrlInfoMemBWPerNode *control)
{
    virResctrlInfoMemBW *membw_info = resctrl->membw_info;

    if (!membw_info)
        return 0;

    if (membw_info->last_level_cache != level)
        return 0;

    control->granularity = membw_info->bandwidth_granularity;
    control->min = membw_info->min_bandwidth;
    control->max_allocation = membw_info->max_allocation;
    return 1;
}


int
virResctrlInfoGetCache(virResctrlInfo *resctrl,
                       unsigned int level,
                       unsigned long long size,
                       size_t *ncontrols,
                       virResctrlInfoPerCache ***controls)
{
    virResctrlInfoPerLevel *i_level = NULL;
    virResctrlInfoPerType *i_type = NULL;
    size_t i = 0;

    if (virResctrlInfoIsEmpty(resctrl))
        return 0;

    /* Let's take the opportunity to update the number of last level
     * cache. This number of memory bandwidth controller is same with
     * last level cache */
    if (resctrl->membw_info) {
        virResctrlInfoMemBW *membw_info = resctrl->membw_info;

        if (level > membw_info->last_level_cache) {
            membw_info->last_level_cache = level;
            membw_info->max_id = 0;
        } else if (membw_info->last_level_cache == level) {
            membw_info->max_id++;
        }
    }

    if (level >= resctrl->nlevels)
        return 0;

    i_level = resctrl->levels[level];
    if (!i_level)
        return 0;

    for (i = 0; i < VIR_CACHE_TYPE_LAST; i++) {
        i_type = i_level->types[i];
        if (!i_type)
            continue;

        /* Let's take the opportunity to update our internal information about
         * the cache size */
        if (!i_type->size) {
            i_type->size = size;
            i_type->control.granularity = size / i_type->bits;
            if (i_type->min_cbm_bits != 1)
                i_type->control.min = i_type->min_cbm_bits * i_type->control.granularity;
        } else {
            if (i_type->size != size) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("level %1$u cache size %2$llu does not match expected size %3$llu"),
                               level, i_type->size, size);
                goto error;
            }
            i_type->max_cache_id++;
        }

        VIR_EXPAND_N(*controls, *ncontrols, 1);
        (*controls)[*ncontrols - 1] = g_new0(virResctrlInfoPerCache, 1);
        memcpy((*controls)[*ncontrols - 1], &i_type->control, sizeof(i_type->control));
    }

    return 0;
 error:
    while (*ncontrols)
        VIR_FREE((*controls)[--*ncontrols]);
    VIR_FREE(*controls);
    return -1;
}


/* virResctrlInfoGetMonitorPrefix
 *
 * @resctrl: Pointer to virResctrlInfo
 * @prefix: Monitor prefix name for monitor looking for.
 * @monitor: Returns the capability information for target monitor if the
 * monitor with @prefex is supported by host.
 *
 * Return monitor capability information for @prefix through @monitor.
 * If monitor with @prefix is not supported in system, @monitor will be
 * cleared to NULL.
 *
 * Returns 0 if @monitor is created or monitor type with @prefix is not
 * supported by host, -1 on failure with error message set.
 */
int
virResctrlInfoGetMonitorPrefix(virResctrlInfo *resctrl,
                               const char *prefix,
                               virResctrlInfoMon **monitor)
{
    size_t i = 0;
    virResctrlInfoMongrp *mongrp_info = NULL;
    virResctrlInfoMon *mon = NULL;
    int ret = -1;

    if (!prefix) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Empty prefix name for resctrl monitor"));
        return -1;
    }

    if (virResctrlInfoIsEmpty(resctrl))
        return 0;

    mongrp_info = resctrl->monitor_info;

    if (!mongrp_info) {
        VIR_INFO("Monitor is not supported in host");
        return 0;
    }

    for (i = 0; i < VIR_RESCTRL_MONITOR_TYPE_LAST; i++) {
        if (STREQ(prefix, virResctrlMonitorPrefixTypeToString(i))) {
            mon = g_new0(virResctrlInfoMon, 1);
            mon->type = i;
            break;
        }
    }

    if (!mon) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Bad prefix name '%1$s' for resctrl monitor"),
                       prefix);
        return -1;
    }

    mon->max_monitor = mongrp_info->max_monitor;

    if (mon->type == VIR_RESCTRL_MONITOR_TYPE_CACHE) {
        mon->cache_reuse_threshold =  mongrp_info->cache_reuse_threshold;
        mon->cache_level = mongrp_info->cache_level;
    }

    mon->features = g_new0(char *, mongrp_info->nfeatures + 1);

    for (i = 0; i < mongrp_info->nfeatures; i++) {
        if (STRPREFIX(mongrp_info->features[i], prefix))
            mon->features[mon->nfeatures++] = g_strdup(mongrp_info->features[i]);
    }

    mon->features = g_renew(char *, mon->features, mon->nfeatures + 1);

    ret = 0;

    /* In case *monitor is pointed to some monitor, clean it. */
    virResctrlInfoMonFree(*monitor);

    if (mon->nfeatures == 0) {
        /* No feature found for current monitor, means host does not support
         * monitor type with @prefix name.
         * Telling caller this monitor is supported by hardware specification,
         * but not supported by this host. */
        VIR_INFO("No resctrl monitor features using prefix '%s' found", prefix);
        goto cleanup;
    }

    *monitor = g_steal_pointer(&mon);
 cleanup:
    virResctrlInfoMonFree(mon);
    return ret;
}


/* virResctrlAlloc-related definitions */
virResctrlAlloc *
virResctrlAllocNew(void)
{
    if (virResctrlInitialize() < 0)
        return NULL;

    return virObjectNew(virResctrlAllocClass);
}


bool
virResctrlAllocIsEmpty(virResctrlAlloc *alloc)
{
    size_t i = 0;
    size_t j = 0;
    size_t k = 0;

    if (!alloc)
        return true;

    if (alloc->mem_bw)
        return false;

    for (i = 0; i < alloc->nlevels; i++) {
        virResctrlAllocPerLevel *a_level = alloc->levels[i];

        if (!a_level)
            continue;

        for (j = 0; j < VIR_CACHE_TYPE_LAST; j++) {
            virResctrlAllocPerType *a_type = a_level->types[j];

            if (!a_type)
                continue;

            for (k = 0; k < a_type->nsizes; k++) {
                if (a_type->sizes[k])
                    return false;
            }

            for (k = 0; k < a_type->nmasks; k++) {
                if (a_type->masks[k])
                    return false;
            }
        }
    }

    return true;
}


static virResctrlAllocPerType *
virResctrlAllocGetType(virResctrlAlloc *alloc,
                       unsigned int level,
                       virCacheType type)
{
    virResctrlAllocPerLevel *a_level = NULL;

    if (alloc->nlevels <= level)
        VIR_EXPAND_N(alloc->levels, alloc->nlevels, level - alloc->nlevels + 1);

    if (!alloc->levels[level]) {
        virResctrlAllocPerType **types = NULL;

        types = g_new0(virResctrlAllocPerType *, VIR_CACHE_TYPE_LAST);

        alloc->levels[level] = g_new0(virResctrlAllocPerLevel, 1);
        alloc->levels[level]->types = types;
    }

    a_level = alloc->levels[level];

    if (!a_level->types[type])
        a_level->types[type] = g_new0(virResctrlAllocPerType, 1);

    return a_level->types[type];
}


static int
virResctrlAllocUpdateMask(virResctrlAlloc *alloc,
                          unsigned int level,
                          virCacheType type,
                          unsigned int cache,
                          virBitmap *mask)
{
    virResctrlAllocPerType *a_type = virResctrlAllocGetType(alloc, level, type);

    if (!a_type)
        return -1;

    if (a_type->nmasks <= cache)
        VIR_EXPAND_N(a_type->masks, a_type->nmasks,
                     cache - a_type->nmasks + 1);

    if (a_type->masks[cache])
        virBitmapFree(a_type->masks[cache]);

    a_type->masks[cache] = virBitmapNewCopy(mask);

    return 0;
}


static int
virResctrlAllocUpdateSize(virResctrlAlloc *alloc,
                          unsigned int level,
                          virCacheType type,
                          unsigned int cache,
                          unsigned long long size)
{
    virResctrlAllocPerType *a_type = virResctrlAllocGetType(alloc, level, type);

    if (!a_type)
        return -1;

    if (a_type->nsizes <= cache)
        VIR_EXPAND_N(a_type->sizes, a_type->nsizes,
                     cache - a_type->nsizes + 1);

    if (!a_type->sizes[cache])
        a_type->sizes[cache] = g_new0(unsigned long long, 1);

    *(a_type->sizes[cache]) = size;

    return 0;
}


/*
 * Check if there is an allocation for this level/type/cache already.  Called
 * before updating the structure.  VIR_CACHE_TYPE_BOTH collides with any type,
 * the other types collide with itself.  This code basically checks if either:
 * `alloc[level]->types[type]->sizes[cache]`
 * or
 * `alloc[level]->types[VIR_CACHE_TYPE_BOTH]->sizes[cache]`
 * is non-NULL.  All the fuzz around it is checking for NULL pointers along
 * the way.
 */
static bool
virResctrlAllocCheckCollision(virResctrlAlloc *alloc,
                              unsigned int level,
                              virCacheType type,
                              unsigned int cache)
{
    virResctrlAllocPerLevel *a_level = NULL;
    virResctrlAllocPerType *a_type = NULL;

    if (!alloc)
        return false;

    if (alloc->nlevels <= level)
        return false;

    a_level = alloc->levels[level];

    if (!a_level)
        return false;

    a_type = a_level->types[VIR_CACHE_TYPE_BOTH];

    /* If there is an allocation for type 'both', there can be no other
     * allocation for the same cache */
    if (a_type && a_type->nsizes > cache && a_type->sizes[cache])
        return true;

    if (type == VIR_CACHE_TYPE_BOTH) {
        a_type = a_level->types[VIR_CACHE_TYPE_CODE];

        if (a_type && a_type->nsizes > cache && a_type->sizes[cache])
            return true;

        a_type = a_level->types[VIR_CACHE_TYPE_DATA];

        if (a_type && a_type->nsizes > cache && a_type->sizes[cache])
            return true;
    } else {
        a_type = a_level->types[type];

        if (a_type && a_type->nsizes > cache && a_type->sizes[cache])
            return true;
    }

    return false;
}


int
virResctrlAllocSetCacheSize(virResctrlAlloc *alloc,
                            unsigned int level,
                            virCacheType type,
                            unsigned int cache,
                            unsigned long long size)
{
    if (virResctrlAllocCheckCollision(alloc, level, type, cache)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Colliding cache allocations for cache level '%1$u' id '%2$u', type '%3$s'"),
                       level, cache, virCacheTypeToString(type));
        return -1;
    }

    return virResctrlAllocUpdateSize(alloc, level, type, cache, size);
}


int
virResctrlAllocForeachCache(virResctrlAlloc *alloc,
                            virResctrlAllocForeachCacheCallback cb,
                            void *opaque)
{
    int ret = 0;
    unsigned int level = 0;
    unsigned int type = 0;
    unsigned int cache = 0;

    if (!alloc)
        return 0;

    for (level = 0; level < alloc->nlevels; level++) {
        virResctrlAllocPerLevel *a_level = alloc->levels[level];

        if (!a_level)
            continue;

        for (type = 0; type < VIR_CACHE_TYPE_LAST; type++) {
            virResctrlAllocPerType *a_type = a_level->types[type];

            if (!a_type)
                continue;

            for (cache = 0; cache < a_type->nsizes; cache++) {
                unsigned long long *size = a_type->sizes[cache];

                if (!size)
                    continue;

                ret = cb(level, type, cache, *size, opaque);
                if (ret < 0)
                    return ret;
            }
        }
    }

    return 0;
}


/* virResctrlAllocSetMemoryBandwidth
 * @alloc: Pointer to an active allocation
 * @id: node id of MBA to be set
 * @memory_bandwidth: new memory bandwidth value
 *
 * Set the @memory_bandwidth for the node @id entry in the @alloc.
 *
 * Returns 0 on success, -1 on failure with error message set.
 */
int
virResctrlAllocSetMemoryBandwidth(virResctrlAlloc *alloc,
                                  unsigned int id,
                                  unsigned int memory_bandwidth)
{
    virResctrlAllocMemBW *mem_bw = alloc->mem_bw;

    if (memory_bandwidth > 100) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Memory Bandwidth value exceeding 100 is invalid."));
        return -1;
    }

    if (!mem_bw) {
        mem_bw = g_new0(virResctrlAllocMemBW, 1);
        alloc->mem_bw = mem_bw;
    }

    if (mem_bw->nbandwidths <= id)
        VIR_EXPAND_N(mem_bw->bandwidths, mem_bw->nbandwidths,
                     id - mem_bw->nbandwidths + 1);

    if (mem_bw->bandwidths[id]) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Memory Bandwidth already defined for node %1$u"),
                       id);
        return -1;
    }

    mem_bw->bandwidths[id] = g_new0(unsigned int, 1);
    *(mem_bw->bandwidths[id]) = memory_bandwidth;
    return 0;
}


/* virResctrlAllocForeachMemory
 * @alloc: Pointer to an active allocation
 * @cb: Callback function
 * @opaque: Opaque data to be passed to @cb
 *
 * If available, traverse the defined memory bandwidth allocations and
 * call the @cb function.
 *
 * Returns 0 on success, -1 and immediate failure if the @cb has any failure.
 */
int
virResctrlAllocForeachMemory(virResctrlAlloc *alloc,
                             virResctrlAllocForeachMemoryCallback cb,
                             void *opaque)
{
    size_t i = 0;
    virResctrlAllocMemBW *mem_bw;

    if (!alloc || !alloc->mem_bw)
        return 0;

    mem_bw = alloc->mem_bw;
    for (i = 0; i < mem_bw->nbandwidths; i++) {
        if (mem_bw->bandwidths[i]) {
            if (cb(i, *mem_bw->bandwidths[i], opaque) < 0)
                return -1;
        }
    }

    return 0;
}


static int
virResctrlSetID(char **resctrlid,
                const char *id)
{
    if (!id) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("New resctrl 'id' cannot be NULL"));
        return -1;
    }

    if (*resctrlid) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Attempt to overwrite resctrlid='%1$s' with id='%2$s'"),
                       *resctrlid, id);
        return -1;
    }

    *resctrlid = g_strdup(id);
    return 0;
}


int
virResctrlAllocSetID(virResctrlAlloc *alloc,
                     const char *id)
{
    return virResctrlSetID(&alloc->id, id);
}


const char *
virResctrlAllocGetID(virResctrlAlloc *alloc)
{
    return alloc->id;
}


/* Format the Memory Bandwidth Allocation line that will be found in
 * the schemata files. The line should be start with "MB:" and be
 * followed by "id=value" pairs separated by a semi-colon such as:
 *
 *     MB:0=100;1=100
 *
 * which indicates node id 0 has 100 percent bandwidth and node id 1
 * has 100 percent bandwidth. A trailing semi-colon is not formatted.
 */
static int
virResctrlAllocMemoryBandwidthFormat(virResctrlAlloc *alloc,
                                     virBuffer *buf)
{
    size_t i;

    if (!alloc->mem_bw)
        return 0;

    virBufferAddLit(buf, "MB:");

    for (i = 0; i < alloc->mem_bw->nbandwidths; i++) {
        if (alloc->mem_bw->bandwidths[i]) {
            virBufferAsprintf(buf, "%zd=%u;", i,
                              *(alloc->mem_bw->bandwidths[i]));
        }
    }

    virBufferTrim(buf, ";");
    virBufferAddChar(buf, '\n');
    return 0;
}


static int
virResctrlAllocParseProcessMemoryBandwidth(virResctrlInfo *resctrl,
                                           virResctrlAlloc *alloc,
                                           char *mem_bw)
{
    unsigned int bandwidth;
    unsigned int id;
    char *tmp = NULL;

    tmp = strchr(mem_bw, '=');
    if (!tmp)
        return 0;
    *tmp = '\0';
    tmp++;

    if (virStrToLong_uip(mem_bw, NULL, 10, &id) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid node id %1$u "), id);
        return -1;
    }
    if (virStrToLong_uip(tmp, NULL, 10, &bandwidth) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid bandwidth %1$u"), bandwidth);
        return -1;
    }
    if (bandwidth < resctrl->membw_info->min_bandwidth ||
        id > resctrl->membw_info->max_id) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Missing or inconsistent resctrl info for memory bandwidth node '%1$u'"),
                       id);
        return -1;
    }
    if (alloc->mem_bw->nbandwidths <= id) {
        VIR_EXPAND_N(alloc->mem_bw->bandwidths, alloc->mem_bw->nbandwidths,
                     id - alloc->mem_bw->nbandwidths + 1);
    }
    if (!alloc->mem_bw->bandwidths[id])
        alloc->mem_bw->bandwidths[id] = g_new0(unsigned int, 1);

    *(alloc->mem_bw->bandwidths[id]) = bandwidth;
    return 0;
}


/* Parse a schemata formatted MB: entry. Format details are described in
 * virResctrlAllocMemoryBandwidthFormat.
 */
static int
virResctrlAllocParseMemoryBandwidthLine(virResctrlInfo *resctrl,
                                        virResctrlAlloc *alloc,
                                        char *line)
{
    g_auto(GStrv) mbs = NULL;
    GStrv next;
    char *tmp = NULL;

    /* For no reason there can be spaces */
    virSkipSpaces((const char **) &line);

    if (STRNEQLEN(line, "MB", 2))
        return 0;

    if (!resctrl || !resctrl->membw_info ||
        !resctrl->membw_info->min_bandwidth ||
        !resctrl->membw_info->bandwidth_granularity) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing or inconsistent resctrl info for memory bandwidth allocation"));
        return -1;
    }

    if (!alloc->mem_bw)
        alloc->mem_bw = g_new0(virResctrlAllocMemBW, 1);

    tmp = strchr(line, ':');
    if (!tmp)
        return 0;
    tmp++;

    mbs = g_strsplit(tmp, ";", 0);
    for (next = mbs; *next; next++) {
        if (virResctrlAllocParseProcessMemoryBandwidth(resctrl, alloc, *next) < 0)
            return -1;
    }

    return 0;
}


static int
virResctrlAllocFormatCache(virResctrlAlloc *alloc,
                           virBuffer *buf)
{
    unsigned int level = 0;
    unsigned int type = 0;
    unsigned int cache = 0;

    for (level = 0; level < alloc->nlevels; level++) {
        virResctrlAllocPerLevel *a_level = alloc->levels[level];

        if (!a_level)
            continue;

        for (type = 0; type < VIR_CACHE_TYPE_LAST; type++) {
            virResctrlAllocPerType *a_type = a_level->types[type];

            if (!a_type)
                continue;

            virBufferAsprintf(buf, "L%u%s:", level, virResctrlTypeToString(type));

            for (cache = 0; cache < a_type->nmasks; cache++) {
                virBitmap *mask = a_type->masks[cache];
                char *mask_str = NULL;

                if (!mask)
                    continue;

                mask_str = virBitmapToString(mask);
                if (!mask_str)
                    return -1;

                virBufferAsprintf(buf, "%u=%s;", cache, mask_str);
                VIR_FREE(mask_str);
            }

            virBufferTrim(buf, ";");
            virBufferAddChar(buf, '\n');
        }
    }

    return 0;
}


char *
virResctrlAllocFormat(virResctrlAlloc *alloc)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    if (!alloc)
        return NULL;

    if (virResctrlAllocFormatCache(alloc, &buf) < 0)
        return NULL;

    if (virResctrlAllocMemoryBandwidthFormat(alloc, &buf) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
}


static int
virResctrlAllocParseProcessCache(virResctrlInfo *resctrl,
                                 virResctrlAlloc *alloc,
                                 unsigned int level,
                                 virCacheType type,
                                 char *cache)
{
    char *tmp = strchr(cache, '=');
    unsigned int cache_id = 0;
    g_autoptr(virBitmap) mask = NULL;

    if (!tmp)
        return 0;

    *tmp = '\0';
    tmp++;

    if (virStrToLong_uip(cache, NULL, 10, &cache_id) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid cache id '%1$s'"), cache);
        return -1;
    }

    mask = virBitmapNewString(tmp);
    if (!mask)
        return -1;

    if (!resctrl ||
        level >= resctrl->nlevels ||
        !resctrl->levels[level] ||
        !resctrl->levels[level]->types[type]) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Missing or inconsistent resctrl info for level '%1$u' type '%2$s'"),
                       level, virCacheTypeToString(type));
        return -1;
    }

    virBitmapShrink(mask, resctrl->levels[level]->types[type]->bits);

    if (virResctrlAllocUpdateMask(alloc, level, type, cache_id, mask) < 0)
        return -1;

    return 0;
}


static int
virResctrlAllocParseCacheLine(virResctrlInfo *resctrl,
                              virResctrlAlloc *alloc,
                              char *line)
{
    g_auto(GStrv) caches = NULL;
    GStrv next;
    char *tmp = NULL;
    unsigned int level = 0;
    int type = -1;

    /* For no reason there can be spaces */
    virSkipSpaces((const char **) &line);

    /* Skip lines that don't concern caches, e.g. MB: etc. */
    if (line[0] != 'L')
        return 0;

    /* And lines that we can't parse too */
    tmp = strchr(line, ':');
    if (!tmp)
        return 0;

    *tmp = '\0';
    tmp++;

    if (virStrToLong_uip(line + 1, &line, 10, &level) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot parse resctrl schema level '%1$s'"),
                       line + 1);
        return -1;
    }

    type = virResctrlTypeFromString(line);
    if (type < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot parse resctrl schema level '%1$s'"),
                       line + 1);
        return -1;
    }

    caches = g_strsplit(tmp, ";", 0);
    if (!caches)
        return 0;

    for (next = caches; *next; next++) {
        if (virResctrlAllocParseProcessCache(resctrl, alloc, level, type, *next) < 0)
            return -1;
    }

    return 0;
}


static int
virResctrlAllocParse(virResctrlInfo *resctrl,
                     virResctrlAlloc *alloc,
                     const char *schemata)
{
    g_auto(GStrv) lines = NULL;
    GStrv next;

    lines = g_strsplit(schemata, "\n", 0);
    for (next = lines; *next; next++) {
        if (virResctrlAllocParseCacheLine(resctrl, alloc, *next) < 0)
            return -1;
        if (virResctrlAllocParseMemoryBandwidthLine(resctrl, alloc, *next) < 0)
            return -1;
    }

    return 0;
}


static int
virResctrlAllocGetGroup(virResctrlInfo *resctrl,
                        const char *groupname,
                        virResctrlAlloc **alloc)
{
    char *schemata = NULL;
    int rv = virFileReadValueString(&schemata,
                                    SYSFS_RESCTRL_PATH "/%s/schemata",
                                    groupname);

    *alloc = NULL;

    if (rv < 0)
        return rv;

    *alloc = virResctrlAllocNew();
    if (!*alloc)
        goto error;

    if (virResctrlAllocParse(resctrl, *alloc, schemata) < 0)
        goto error;

    VIR_FREE(schemata);
    return 0;

 error:
    VIR_FREE(schemata);
    g_clear_pointer(alloc, virObjectUnref);
    return -1;
}


static virResctrlAlloc *
virResctrlAllocGetDefault(virResctrlInfo *resctrl)
{
    virResctrlAlloc *ret = NULL;
    int rv = virResctrlAllocGetGroup(resctrl, ".", &ret);

    if (rv == -2) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not read schemata file for the default group"));
    }

    return ret;
}


static void
virResctrlAllocSubtractPerType(virResctrlAllocPerType *dst,
                               virResctrlAllocPerType *src)
{
    size_t i = 0;

    if (!dst || !src)
        return;

    for (i = 0; i < dst->nmasks && i < src->nmasks; i++) {
        if (dst->masks[i] && src->masks[i])
            virBitmapSubtract(dst->masks[i], src->masks[i]);
    }
}


static void
virResctrlAllocSubtract(virResctrlAlloc *dst,
                        virResctrlAlloc *src)
{
    size_t i = 0;
    size_t j = 0;

    if (!src)
        return;

    for (i = 0; i < dst->nlevels && i < src->nlevels; i++) {
        if (dst->levels[i] && src->levels[i]) {
            for (j = 0; j < VIR_CACHE_TYPE_LAST; j++) {
                virResctrlAllocSubtractPerType(dst->levels[i]->types[j],
                                               src->levels[i]->types[j]);
            }
        }
    }
}


static virResctrlAlloc *
virResctrlAllocNewFromInfo(virResctrlInfo *info)
{
    size_t i = 0;
    g_autoptr(virResctrlAlloc) ret = virResctrlAllocNew();

    if (!ret)
        return NULL;

    for (i = 0; i < info->nlevels; i++) {
        virResctrlInfoPerLevel *i_level = info->levels[i];
        size_t j = 0;

        if (!i_level)
            continue;

        for (j = 0; j < VIR_CACHE_TYPE_LAST; j++) {
            virResctrlInfoPerType *i_type = i_level->types[j];
            g_autoptr(virBitmap) mask = NULL;
            size_t k = 0;

            if (!i_type)
                continue;

            mask = virBitmapNew(i_type->bits);
            virBitmapSetAll(mask);

            for (k = 0; k <= i_type->max_cache_id; k++) {
                if (virResctrlAllocUpdateMask(ret, i, j, k, mask) < 0)
                    return NULL;
            }
        }
    }

    /* set default free memory bandwidth to 100% */
    if (info->membw_info) {
        ret->mem_bw = g_new0(virResctrlAllocMemBW, 1);

        VIR_EXPAND_N(ret->mem_bw->bandwidths, ret->mem_bw->nbandwidths,
                     info->membw_info->max_id + 1);

        for (i = 0; i < ret->mem_bw->nbandwidths; i++) {
            ret->mem_bw->bandwidths[i] = g_new0(unsigned int, 1);
            *(ret->mem_bw->bandwidths[i]) = 100;
        }
    }

    return g_steal_pointer(&ret);
}

/*
 * This function creates an allocation that represents all unused parts of all
 * caches in the system.  It uses virResctrlInfo for creating a new full
 * allocation with all bits set (using virResctrlAllocNewFromInfo()) and then
 * scans for all allocations under /sys/fs/resctrl and subtracts each one of
 * them from it.  That way it can then return an allocation with only bit set
 * being those that are not mentioned in any other allocation.  It is used for
 * two things, a) calculating the masks when creating allocations and b) from
 * tests.
 *
 * MBA (Memory Bandwidth Allocation) is not taken into account as it is a
 * limiting setting, not an allocating one.  The way it works is also vastly
 * different from CAT.
 */
virResctrlAlloc *
virResctrlAllocGetUnused(virResctrlInfo *resctrl)
{
    g_autoptr(virResctrlAlloc) ret = NULL;
    g_autoptr(virResctrlAlloc) alloc_default = NULL;
    struct dirent *ent = NULL;
    g_autoptr(DIR) dirp = NULL;
    int rv = -1;

    if (virResctrlInfoIsEmpty(resctrl)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Resource control is not supported on this host"));
        return NULL;
    }

    ret = virResctrlAllocNewFromInfo(resctrl);
    if (!ret)
        return NULL;

    alloc_default = virResctrlAllocGetDefault(resctrl);
    if (!alloc_default)
        return NULL;

    virResctrlAllocSubtract(ret, alloc_default);

    if (virDirOpen(&dirp, SYSFS_RESCTRL_PATH) < 0)
        return NULL;

    while ((rv = virDirRead(dirp, &ent, SYSFS_RESCTRL_PATH)) > 0) {
        g_autoptr(virResctrlAlloc) alloc = NULL;

        if (STREQ(ent->d_name, "info"))
            continue;

        rv = virResctrlAllocGetGroup(resctrl, ent->d_name, &alloc);
        if (rv == -2)
            continue;

        if (rv < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not read schemata file for group %1$s"),
                           ent->d_name);
            return NULL;
        }

        virResctrlAllocSubtract(ret, alloc);
    }
    if (rv < 0)
        return NULL;

    return g_steal_pointer(&ret);
}


/*
 * Given the information about requested allocation type `a_type`, the host
 * cache for a particular type `i_type` and unused bits in the system `f_type`
 * this function tries to find the smallest free space in which the allocation
 * for cache id `cache` would fit.  We're looking for the smallest place in
 * order to minimize fragmentation and maximize the possibility of succeeding.
 *
 * Per-cache allocation for the @level, @type and @cache must already be
 * allocated for @alloc (does not have to exist though).
 */
static int
virResctrlAllocFindUnused(virResctrlAlloc *alloc,
                          virResctrlInfoPerType *i_type,
                          virResctrlAllocPerType *f_type,
                          unsigned int level,
                          unsigned int type,
                          unsigned int cache)
{
    unsigned long long *size = alloc->levels[level]->types[type]->sizes[cache];
    g_autoptr(virBitmap) a_mask = NULL;
    virBitmap *f_mask = NULL;
    unsigned long long need_bits;
    size_t i = 0;
    ssize_t pos = -1;
    ssize_t last_bits = 0;
    ssize_t last_pos = -1;

    if (!size)
        return 0;

    if (cache >= f_type->nmasks) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Cache with id %1$u does not exists for level %2$d"),
                       cache, level);
        return -1;
    }

    f_mask = f_type->masks[cache];
    if (!f_mask) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Cache level %1$d id %2$u does not support tuning for scope type '%3$s'"),
                       level, cache, virCacheTypeToString(type));
        return -1;
    }

    if (*size == i_type->size) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Cache allocation for the whole cache is not possible, specify size smaller than %1$llu"),
                       i_type->size);
        return -1;
    }

    need_bits = *size / i_type->control.granularity;

    if (*size % i_type->control.granularity) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Cache allocation of size %1$llu is not divisible by granularity %2$llu"),
                       *size, i_type->control.granularity);
        return -1;
    }

    if (need_bits < i_type->min_cbm_bits) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Cache allocation of size %1$llu is smaller than the minimum allowed allocation %2$llu"),
                       *size,
                       i_type->control.granularity * i_type->min_cbm_bits);
        return -1;
    }

    while ((pos = virBitmapNextSetBit(f_mask, pos)) >= 0) {
        ssize_t pos_clear = virBitmapNextClearBit(f_mask, pos);
        ssize_t bits;

        if (pos_clear < 0)
            pos_clear = virBitmapSize(f_mask);

        bits = pos_clear - pos;

        /* Not enough bits, move on and skip all of them */
        if (bits < need_bits) {
            pos = pos_clear;
            continue;
        }

        /* This fits perfectly */
        if (bits == need_bits) {
            last_pos = pos;
            break;
        }

        /* Remember the smaller region if we already found on before */
        if (last_pos < 0 || (last_bits && bits < last_bits)) {
            last_bits = bits;
            last_pos = pos;
        }

        pos = pos_clear;
    }

    if (last_pos < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Not enough room for allocation of %1$llu bytes for level %2$u cache %3$u scope type '%4$s'"),
                       *size, level, cache,
                       virCacheTypeToString(type));
        return -1;
    }

    a_mask = virBitmapNew(i_type->bits);

    for (i = last_pos; i < last_pos + need_bits; i++)
        ignore_value(virBitmapSetBit(a_mask, i));

    if (virResctrlAllocUpdateMask(alloc, level, type, cache, a_mask) < 0)
        return -1;

    return 0;
}


static int
virResctrlAllocMemoryBandwidth(virResctrlInfo *resctrl,
                               virResctrlAlloc *alloc)
{
    size_t i;
    virResctrlAllocMemBW *mem_bw_alloc = alloc->mem_bw;
    virResctrlInfoMemBW *mem_bw_info = resctrl->membw_info;

    if (!mem_bw_alloc)
        return 0;

    if (!mem_bw_info) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("RDT Memory Bandwidth allocation unsupported"));
        return -1;
    }

    for (i = 0; i < mem_bw_alloc->nbandwidths; i++) {
        if (!mem_bw_alloc->bandwidths[i])
            continue;

        if (*(mem_bw_alloc->bandwidths[i]) % mem_bw_info->bandwidth_granularity) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Memory Bandwidth allocation of size %1$u is not divisible by granularity %2$u"),
                           *(mem_bw_alloc->bandwidths[i]),
                           mem_bw_info->bandwidth_granularity);
            return -1;
        }
        if (*(mem_bw_alloc->bandwidths[i]) < mem_bw_info->min_bandwidth) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Memory Bandwidth allocation of size %1$u is smaller than the minimum allowed allocation %2$u"),
                           *(mem_bw_alloc->bandwidths[i]),
                           mem_bw_info->min_bandwidth);
            return -1;
        }
        if (i > mem_bw_info->max_id) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("bandwidth controller id %1$zd does not exist, max controller id %2$u"),
                           i, mem_bw_info->max_id);
            return -1;
        }
    }
    return 0;
}


static int
virResctrlAllocCopyMemBW(virResctrlAlloc *dst,
                         virResctrlAlloc *src)
{
    size_t i = 0;
    virResctrlAllocMemBW *dst_bw = NULL;
    virResctrlAllocMemBW *src_bw = src->mem_bw;

    if (!src->mem_bw)
        return 0;

    if (!dst->mem_bw)
        dst->mem_bw = g_new0(virResctrlAllocMemBW, 1);

    dst_bw = dst->mem_bw;

    if (src_bw->nbandwidths > dst_bw->nbandwidths)
        VIR_EXPAND_N(dst_bw->bandwidths, dst_bw->nbandwidths,
                     src_bw->nbandwidths - dst_bw->nbandwidths);

    for (i = 0; i < src_bw->nbandwidths; i++) {
        if (dst_bw->bandwidths[i])
            continue;
        dst_bw->bandwidths[i] = g_new0(unsigned int, 1);
        *dst_bw->bandwidths[i] = *src_bw->bandwidths[i];
    }

    return 0;
}


static int
virResctrlAllocCopyMasks(virResctrlAlloc *dst,
                         virResctrlAlloc *src)
{
    unsigned int level = 0;

    for (level = 0; level < src->nlevels; level++) {
        virResctrlAllocPerLevel *s_level = src->levels[level];
        unsigned int type = 0;

        if (!s_level)
            continue;

        for (type = 0; type < VIR_CACHE_TYPE_LAST; type++) {
            virResctrlAllocPerType *s_type = s_level->types[type];
            virResctrlAllocPerType *d_type = NULL;
            unsigned int cache = 0;

            if (!s_type)
                continue;

            d_type = virResctrlAllocGetType(dst, level, type);
            if (!d_type)
                return -1;

            for (cache = 0; cache < s_type->nmasks; cache++) {
                virBitmap *mask = s_type->masks[cache];

                if (mask && virResctrlAllocUpdateMask(dst, level, type, cache, mask) < 0)
                    return -1;
            }
        }
    }

    return 0;
}


/*
 * This function is called when creating an allocation in the system.
 * What it does is that it gets all the unused resources using
 * virResctrlAllocGetUnused and then tries to find a proper space for
 * every requested allocation effectively transforming `sizes` into `masks`.
 */
static int
virResctrlAllocAssign(virResctrlInfo *resctrl,
                      virResctrlAlloc *alloc)
{
    unsigned int level = 0;
    g_autoptr(virResctrlAlloc) alloc_free = NULL;
    g_autoptr(virResctrlAlloc) alloc_default = NULL;

    alloc_free = virResctrlAllocGetUnused(resctrl);
    if (!alloc_free)
        return -1;

    alloc_default = virResctrlAllocGetDefault(resctrl);
    if (!alloc_default)
        return -1;

    if (virResctrlAllocMemoryBandwidth(resctrl, alloc) < 0)
        return -1;

    if (virResctrlAllocCopyMasks(alloc, alloc_default) < 0)
        return -1;

    if (virResctrlAllocCopyMemBW(alloc, alloc_default) < 0)
        return -1;

    for (level = 0; level < alloc->nlevels; level++) {
        virResctrlAllocPerLevel *a_level = alloc->levels[level];
        virResctrlAllocPerLevel *f_level = NULL;
        unsigned int type = 0;

        if (!a_level)
            continue;

        if (level < alloc_free->nlevels)
            f_level = alloc_free->levels[level];

        if (!f_level) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Cache level %1$d does not support tuning"),
                           level);
            return -1;
        }

        for (type = 0; type < VIR_CACHE_TYPE_LAST; type++) {
            virResctrlAllocPerType *a_type = a_level->types[type];
            virResctrlAllocPerType *f_type = f_level->types[type];
            unsigned int cache = 0;

            if (!a_type)
                continue;

            if (!f_type) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Cache level %1$d does not support tuning for scope type '%2$s'"),
                               level, virCacheTypeToString(type));
                return -1;
            }

            for (cache = 0; cache < a_type->nsizes; cache++) {
                virResctrlInfoPerLevel *i_level = resctrl->levels[level];
                virResctrlInfoPerType *i_type = i_level->types[type];

                if (virResctrlAllocFindUnused(alloc, i_type, f_type, level, type, cache) < 0)
                    return -1;
            }
        }
    }

    return 0;
}


static char *
virResctrlDeterminePath(const char *parentpath,
                        const char *prefix,
                        const char *id)
{
    if (!id) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Resctrl ID must be set before determining resctrl parentpath='%1$s' prefix='%2$s'"),
                       parentpath, prefix);
        return NULL;
    }

    return g_strdup_printf("%s/%s-%s", parentpath, prefix, id);
}


int
virResctrlAllocDeterminePath(virResctrlAlloc *alloc,
                             const char *machinename)
{
    if (alloc->path) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Resctrl allocation path is already set to '%1$s'"),
                       alloc->path);
        return -1;
    }

    /* If the allocation is empty, then the path will be SYSFS_RESCTRL_PATH */
    if (virResctrlAllocIsEmpty(alloc)) {
        alloc->path = g_strdup(SYSFS_RESCTRL_PATH);

        return 0;
    }

    alloc->path = virResctrlDeterminePath(SYSFS_RESCTRL_PATH,
                                          machinename, alloc->id);

    if (!alloc->path)
        return -1;

    return 0;
}


/* This function creates a resctrl directory in resource control file system,
 * and the directory path is specified by @path. */
static int
virResctrlCreateGroupPath(const char *path)
{
    /* Directory exists, return */
    if (virFileExists(path))
        return 0;

    if (g_mkdir_with_parents(path, 0777) < 0) {
        virReportSystemError(errno,
                             _("Cannot create resctrl directory '%1$s'"),
                             path);
        return -1;
    }

    return 0;
}


/* This checks if the directory for the alloc exists.  If not it tries to create
 * it and apply appropriate alloc settings. */
int
virResctrlAllocCreate(virResctrlInfo *resctrl,
                      virResctrlAlloc *alloc,
                      const char *machinename)
{
    g_autofree char *schemata_path = NULL;
    g_autofree char *alloc_str = NULL;
    int ret = -1;
    int lockfd = -1;

    if (!alloc)
        return 0;

    if (virResctrlInfoIsEmpty(resctrl)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Resource control is not supported on this host"));
        return -1;
    }

    if (virResctrlAllocDeterminePath(alloc, machinename) < 0)
        return -1;

    /* If using the system/default path for the allocation, then we're done */
    if (STREQ(alloc->path, SYSFS_RESCTRL_PATH))
        return 0;

    lockfd = virResctrlLock();
    if (lockfd < 0)
        goto cleanup;

    if (virResctrlAllocAssign(resctrl, alloc) < 0)
        goto cleanup;

    if (virResctrlCreateGroupPath(alloc->path) < 0)
        goto cleanup;

    alloc_str = virResctrlAllocFormat(alloc);
    if (!alloc_str)
        goto cleanup;

    schemata_path = g_strdup_printf("%s/schemata", alloc->path);

    VIR_DEBUG("Writing resctrl schemata '%s' into '%s'", alloc_str, schemata_path);
    if (virFileWriteStr(schemata_path, alloc_str, 0) < 0) {
        rmdir(alloc->path);
        virReportSystemError(errno,
                             _("Cannot write into schemata file '%1$s'"),
                             schemata_path);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virResctrlUnlock(lockfd);
    return ret;
}


static int
virResctrlAddPID(const char *path,
                 pid_t pid)
{
    g_autofree char *tasks = NULL;
    g_autofree char *pidstr = NULL;

    if (!path) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot add pid to non-existing resctrl group"));
        return -1;
    }

    tasks = g_strdup_printf("%s/tasks", path);

    pidstr = g_strdup_printf("%lld", (long long int)pid);

    if (virFileWriteStr(tasks, pidstr, 0) < 0) {
        virReportSystemError(errno,
                             _("Cannot write pid in tasks file '%1$s'"),
                             tasks);
        return -1;
    }

    return 0;
}


int
virResctrlAllocAddPID(virResctrlAlloc *alloc,
                      pid_t pid)
{
    /* If the allocation is empty, then it is impossible to add a PID to
     * allocation due to lacking of its 'tasks' file so just return */
    if (virResctrlAllocIsEmpty(alloc))
        return 0;

    return virResctrlAddPID(alloc->path, pid);
}


int
virResctrlAllocRemove(virResctrlAlloc *alloc)
{
    int ret = 0;

    if (!alloc->path)
        return 0;

    /* Do not destroy if path is the system/default path for the allocation */
    if (STREQ(alloc->path, SYSFS_RESCTRL_PATH))
        return 0;

    VIR_DEBUG("Removing resctrl allocation %s", alloc->path);
    if (rmdir(alloc->path) != 0 && errno != ENOENT) {
        ret = -errno;
        VIR_ERROR(_("Unable to remove %1$s (%2$d)"), alloc->path, errno);
    }

    return ret;
}


/* virResctrlMonitor-related definitions */

virResctrlMonitor *
virResctrlMonitorNew(void)
{
    if (virResctrlInitialize() < 0)
        return NULL;

    return virObjectNew(virResctrlMonitorClass);
}


/*
 * virResctrlMonitorDeterminePath
 *
 * @monitor: Pointer to a resctrl monitor
 * @machinename: Name string of the VM
 *
 * Determines the directory path that the underlying resctrl group will be
 * created with.
 *
 * A monitor represents a directory under resource control file system,
 * its directory path could be the same path as @monitor->alloc, could be a
 * path of directory under 'mon_groups' of @monitor->alloc, or a path of
 * directory under '/sys/fs/resctrl/mon_groups' if @monitor->alloc is NULL.
 *
 * Returns 0 on success, -1 on error.
 */
int
virResctrlMonitorDeterminePath(virResctrlMonitor *monitor,
                               const char *machinename)
{
    g_autofree char *parentpath = NULL;

    if (!monitor) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Invalid resctrl monitor"));
        return -1;
    }

    if (!monitor->alloc) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing resctrl monitor alloc"));
        return -1;
    }

    if (monitor->path) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Resctrl monitor path is already set to '%1$s'"),
                       monitor->path);
        return -1;
    }

    if (!virResctrlAllocIsEmpty(monitor->alloc) &&
        STREQ_NULLABLE(monitor->id, monitor->alloc->id)) {
        monitor->path = g_strdup(monitor->alloc->path);
        return 0;
    }

    parentpath = g_strdup_printf("%s/mon_groups", monitor->alloc->path);

    monitor->path = virResctrlDeterminePath(parentpath, machinename,
                                            monitor->id);
    if (!monitor->path)
        return -1;

    return 0;
}


int
virResctrlMonitorAddPID(virResctrlMonitor *monitor,
                        pid_t pid)
{
    return virResctrlAddPID(monitor->path, pid);
}


int
virResctrlMonitorCreate(virResctrlMonitor *monitor,
                        const char *machinename)
{
    int lockfd = -1;
    int ret = -1;

    if (!monitor)
        return 0;

    if (virResctrlMonitorDeterminePath(monitor, machinename) < 0)
        return -1;

    lockfd = virResctrlLock();
    if (lockfd < 0)
        return -1;

    ret = virResctrlCreateGroupPath(monitor->path);

    virResctrlUnlock(lockfd);
    return ret;
}


int
virResctrlMonitorSetID(virResctrlMonitor *monitor,
                       const char *id)

{
    return virResctrlSetID(&monitor->id, id);
}


const char *
virResctrlMonitorGetID(virResctrlMonitor *monitor)
{
    return monitor->id;
}


void
virResctrlMonitorSetAlloc(virResctrlMonitor *monitor,
                          virResctrlAlloc *alloc)
{
    monitor->alloc = virObjectRef(alloc);
}


int
virResctrlMonitorRemove(virResctrlMonitor *monitor)
{
    int ret = 0;

    if (!monitor->path)
        return 0;

    if (STREQ(monitor->path, monitor->alloc->path))
        return 0;

    VIR_DEBUG("Removing resctrl monitor path=%s", monitor->path);
    if (rmdir(monitor->path) != 0 && errno != ENOENT) {
        ret = -errno;
        VIR_ERROR(_("Unable to remove %1$s (%2$d)"), monitor->path, errno);
    }

    return ret;
}


static int
virResctrlMonitorStatsSorter(const void *a,
                             const void *b)
{
    return (*(virResctrlMonitorStats **)a)->id
        - (*(virResctrlMonitorStats **)b)->id;
}


/*
 * virResctrlMonitorGetStats
 *
 * @monitor: The monitor that the statistic data will be retrieved from.
 * @resources: A string list for the monitor feature names.
 * @stats: Pointer of of virResctrlMonitorStats * array for holding cache or
 * memory bandwidth usage data.
 * @nstats: A size_t pointer to hold the returned array length of @stats
 *
 * Get cache or memory bandwidth utilization information.
 *
 * Returns 0 on success, -1 on error.
 */
int
virResctrlMonitorGetStats(virResctrlMonitor *monitor,
                          const char **resources,
                          virResctrlMonitorStats ***stats,
                          size_t *nstats)
{
    int rv = -1;
    int ret = -1;
    size_t i = 0;
    unsigned long long val = 0;
    g_autoptr(DIR) dirp = NULL;
    g_autofree char *datapath = NULL;
    struct dirent *ent = NULL;
    virResctrlMonitorStats *stat = NULL;
    size_t nresources = g_strv_length((char **) resources);

    if (!monitor) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Invalid resctrl monitor"));
        return -1;
    }

    datapath = g_strdup_printf("%s/mon_data", monitor->path);

    if (virDirOpen(&dirp, datapath) < 0)
        goto cleanup;

    *nstats = 0;
    while (virDirRead(dirp, &ent, datapath) > 0) {
        g_autofree char *filepath = NULL;
        char *node_id = NULL;

        /* Looking for directory that contains resource utilization
         * information file. The directory name is arranged in format
         * "mon_<node_name>_<node_id>". For example, "mon_L3_00" and
         * "mon_L3_01" are two target directories for a two nodes system
         * with resource utilization data file for each node respectively.
         */
        filepath = g_strdup_printf("%s/%s", datapath, ent->d_name);

        if (!virFileIsDir(filepath))
            continue;

        /* Looking for directory has a prefix 'mon_L' */
        if (!(node_id = STRSKIP(ent->d_name, "mon_L")))
            continue;

        /* Looking for directory has another '_' */
        node_id = strchr(node_id, '_');
        if (!node_id)
            continue;

        /* Skip the character '_' */
        if (!(node_id = STRSKIP(node_id, "_")))
            continue;

        stat = g_new0(virResctrlMonitorStats, 1);
        stat->features = g_new0(char *, nresources + 1);

        /* The node ID number should be here, parsing it. */
        if (virStrToLong_uip(node_id, NULL, 0, &stat->id) < 0)
            goto cleanup;

        for (i = 0; resources[i]; i++) {
            rv = virFileReadValueUllong(&val, "%s/%s/%s", datapath,
                                        ent->d_name, resources[i]);
            if (rv == -2) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("File '%1$s/%2$s/%3$s' does not exist."),
                               datapath, ent->d_name, resources[i]);
            }
            if (rv < 0)
                goto cleanup;

            VIR_APPEND_ELEMENT(stat->vals, stat->nvals, val);

            stat->features[i] = g_strdup(resources[i]);
        }

        VIR_APPEND_ELEMENT(*stats, *nstats, stat);
    }

    /* Sort in id's ascending order */
    if (*nstats)
        qsort(*stats, *nstats, sizeof(**stats), virResctrlMonitorStatsSorter);

    ret = 0;
 cleanup:
    virResctrlMonitorStatsFree(stat);
    return ret;
}


void
virResctrlMonitorStatsFree(virResctrlMonitorStats *stat)
{
    if (!stat)
        return;

    g_strfreev(stat->features);
    g_free(stat->vals);
    g_free(stat);
}
