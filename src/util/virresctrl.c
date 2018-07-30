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

#include "virresctrlpriv.h"
#include "viralloc.h"
#include "virfile.h"
#include "virlog.h"
#include "virobject.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_RESCTRL

VIR_LOG_INIT("util.virresctrl")


/* Resctrl is short for Resource Control.  It might be implemented for various
 * resources. Currently this supports cache allocation technology (aka CAT) and
 * memory bandwidth allocation (aka MBA). More resources technologies may be
 * added in the future.
 */


/* Common definitions */
#define SYSFS_RESCTRL_PATH "/sys/fs/resctrl"


/* Following are three different enum implementations for the same enum.  Each
 * one of them helps translating to/from strings for different interfaces.  The
 * delimiter must be VIR_CACHE_TYPE_LAST for all of them in order to stay
 * consistent in between all of them. */

/* Cache name mapping for Linux kernel naming. */
VIR_ENUM_IMPL(virCacheKernel, VIR_CACHE_TYPE_LAST,
              "Unified",
              "Instruction",
              "Data")

/* Cache name mapping for our XML naming. */
VIR_ENUM_IMPL(virCache, VIR_CACHE_TYPE_LAST,
              "both",
              "code",
              "data")

/* Cache name mapping for resctrl interface naming. */
VIR_ENUM_DECL(virResctrl)
VIR_ENUM_IMPL(virResctrl, VIR_CACHE_TYPE_LAST,
              "",
              "CODE",
              "DATA")


/* All private typedefs so that they exist for all later definitions.  This way
 * structs can be included in one or another without reorganizing the code every
 * time. */
typedef struct _virResctrlInfoPerType virResctrlInfoPerType;
typedef virResctrlInfoPerType *virResctrlInfoPerTypePtr;

typedef struct _virResctrlInfoPerLevel virResctrlInfoPerLevel;
typedef virResctrlInfoPerLevel *virResctrlInfoPerLevelPtr;

typedef struct _virResctrlInfoMemBW virResctrlInfoMemBW;
typedef virResctrlInfoMemBW *virResctrlInfoMemBWPtr;

typedef struct _virResctrlAllocPerType virResctrlAllocPerType;
typedef virResctrlAllocPerType *virResctrlAllocPerTypePtr;

typedef struct _virResctrlAllocPerLevel virResctrlAllocPerLevel;
typedef virResctrlAllocPerLevel *virResctrlAllocPerLevelPtr;

typedef struct _virResctrlAllocMemBW virResctrlAllocMemBW;
typedef virResctrlAllocMemBW *virResctrlAllocMemBWPtr;


/* Class definitions and initializations */
static virClassPtr virResctrlInfoClass;
static virClassPtr virResctrlAllocClass;


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
    virResctrlInfoPerTypePtr *types;
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

struct _virResctrlInfo {
    virObject parent;

    virResctrlInfoPerLevelPtr *levels;
    size_t nlevels;

    virResctrlInfoMemBWPtr membw_info;
};


static void
virResctrlInfoDispose(void *obj)
{
    size_t i = 0;
    size_t j = 0;

    virResctrlInfoPtr resctrl = obj;

    for (i = 0; i < resctrl->nlevels; i++) {
        virResctrlInfoPerLevelPtr level = resctrl->levels[i];

        if (!level)
            continue;

        if (level->types) {
            for (j = 0; j < VIR_CACHE_TYPE_LAST; j++)
                VIR_FREE(level->types[j]);
        }
        VIR_FREE(level->types);
        VIR_FREE(level);
    }

    VIR_FREE(resctrl->membw_info);
    VIR_FREE(resctrl->levels);
}


/* virResctrlAlloc */

/*
 * virResctrlAlloc represents one allocation (in XML under cputune/cachetune and
 * consequently a directory under /sys/fs/resctrl).  Since it can have multiple
 * parts of multiple caches allocated it is represented as bunch of nested
 * sparse arrays (by sparse I mean array of pointers so that each might be NULL
 * in case there is no allocation for that particular cache allocation (level,
 * cache, ...) or memory allocation for particular node).
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
 + *
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
 */
struct _virResctrlAllocPerType {
    /* There could be bool saying whether this is set or not, but since everything
     * in virResctrlAlloc (and most of libvirt) goes with pointer arrays we would
     * have to have one more level of allocation anyway, so this stays faithful to
     * the concept */
    unsigned long long **sizes;
    size_t nsizes;

    /* Mask for each cache */
    virBitmapPtr *masks;
    size_t nmasks;
};

struct _virResctrlAllocPerLevel {
    virResctrlAllocPerTypePtr *types; /* Indexed with enum virCacheType */
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

    virResctrlAllocPerLevelPtr *levels;
    size_t nlevels;

    virResctrlAllocMemBWPtr mem_bw;

    /* The identifier (any unique string for now) */
    char *id;
    /* libvirt-generated path in /sys/fs/resctrl for this particular
     * allocation */
    char *path;
};


static void
virResctrlAllocDispose(void *obj)
{
    size_t i = 0;
    size_t j = 0;
    size_t k = 0;

    virResctrlAllocPtr alloc = obj;

    for (i = 0; i < alloc->nlevels; i++) {
        virResctrlAllocPerLevelPtr level = alloc->levels[i];

        if (!level)
            continue;

        for (j = 0; j < VIR_CACHE_TYPE_LAST; j++) {
            virResctrlAllocPerTypePtr type = level->types[j];

            if (!type)
                continue;

            for (k = 0; k < type->nsizes; k++)
                VIR_FREE(type->sizes[k]);

            for (k = 0; k < type->nmasks; k++)
                virBitmapFree(type->masks[k]);

            VIR_FREE(type->sizes);
            VIR_FREE(type->masks);
            VIR_FREE(type);
        }
        VIR_FREE(level->types);
        VIR_FREE(level);
    }

    if (alloc->mem_bw) {
        virResctrlAllocMemBWPtr mem_bw = alloc->mem_bw;
        for (i = 0; i < mem_bw->nbandwidths; i++)
            VIR_FREE(mem_bw->bandwidths[i]);
        VIR_FREE(alloc->mem_bw);
    }

    VIR_FREE(alloc->id);
    VIR_FREE(alloc->path);
    VIR_FREE(alloc->levels);
}


/* Global initialization for classes */
static int
virResctrlOnceInit(void)
{
    if (!VIR_CLASS_NEW(virResctrlInfo, virClassForObject()))
        return -1;

    if (!VIR_CLASS_NEW(virResctrlAlloc, virClassForObject()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virResctrl)


/* Common functions */
static int
virResctrlLockWrite(void)
{
    int fd = open(SYSFS_RESCTRL_PATH, O_DIRECTORY | O_CLOEXEC);

    if (fd < 0) {
        virReportSystemError(errno, "%s", _("Cannot open resctrl"));
        return -1;
    }

    if (virFileFlock(fd, true, true) < 0) {
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
        if (virFileFlock(fd, false, false) < 0)
            virReportSystemError(errno, "%s", _("Cannot unlock resctrl"));

        return -1;
    }

    return 0;
}


/* virResctrlInfo-related definitions */
static int
virResctrlGetCacheInfo(virResctrlInfoPtr resctrl,
                       DIR *dirp)
{
    char *endptr = NULL;
    char *tmp_str = NULL;
    int ret = -1;
    int rv = -1;
    int type = 0;
    struct dirent *ent = NULL;
    unsigned int level = 0;
    virBitmapPtr tmp_map = NULL;
    virResctrlInfoPerLevelPtr i_level = NULL;
    virResctrlInfoPerTypePtr i_type = NULL;

    while ((rv = virDirRead(dirp, &ent, SYSFS_RESCTRL_PATH "/info")) > 0) {
        VIR_DEBUG("Parsing info type '%s'", ent->d_name);
        if (ent->d_name[0] != 'L')
            continue;

        if (virStrToLong_uip(ent->d_name + 1, &endptr, 10, &level) < 0) {
            VIR_DEBUG("Cannot parse resctrl cache info level '%s'", ent->d_name + 1);
            continue;
        }

        type = virResctrlTypeFromString(endptr);
        if (type < 0) {
            VIR_DEBUG("Cannot parse resctrl cache info type '%s'", endptr);
            continue;
        }

        if (VIR_ALLOC(i_type) < 0)
            goto cleanup;

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
            goto cleanup;
        }

        rv = virFileReadValueString(&tmp_str,
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
            goto cleanup;

        virStringTrimOptionalNewline(tmp_str);

        tmp_map = virBitmapNewString(tmp_str);
        VIR_FREE(tmp_str);
        if (!tmp_map) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Cannot parse cbm_mask from resctrl cache info"));
            goto cleanup;
        }

        i_type->bits = virBitmapCountBits(tmp_map);
        virBitmapFree(tmp_map);
        tmp_map = NULL;

        rv = virFileReadValueUint(&i_type->min_cbm_bits,
                                  SYSFS_RESCTRL_PATH "/info/%s/min_cbm_bits",
                                  ent->d_name);
        if (rv == -2)
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Cannot get min_cbm_bits from resctrl cache info"));
        if (rv < 0)
            goto cleanup;

        if (resctrl->nlevels <= level &&
            VIR_EXPAND_N(resctrl->levels, resctrl->nlevels,
                         level - resctrl->nlevels + 1) < 0)
            goto cleanup;

        if (!resctrl->levels[level]) {
            virResctrlInfoPerTypePtr *types = NULL;

            if (VIR_ALLOC_N(types, VIR_CACHE_TYPE_LAST) < 0)
                goto cleanup;

            if (VIR_ALLOC(resctrl->levels[level]) < 0) {
                VIR_FREE(types);
                goto cleanup;
            }
            resctrl->levels[level]->types = types;
        }

        i_level = resctrl->levels[level];

        if (i_level->types[type]) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Duplicate cache type in resctrl for level %u"),
                           level);
            goto cleanup;
        }

        VIR_STEAL_PTR(i_level->types[type], i_type);
    }

    ret = 0;
 cleanup:
    VIR_FREE(i_type);
    return ret;
}


static int
virResctrlGetMemoryBandwidthInfo(virResctrlInfoPtr resctrl)
{
    int ret = -1;
    int rv = -1;
    virResctrlInfoMemBWPtr i_membw = NULL;

    /* query memory bandwidth allocation info */
    if (VIR_ALLOC(i_membw) < 0)
        goto cleanup;
    rv = virFileReadValueUint(&i_membw->bandwidth_granularity,
                              SYSFS_RESCTRL_PATH "/info/MB/bandwidth_gran");
    if (rv == -2) {
        /* The file doesn't exist, so it's unusable for us,
         * probably memory bandwidth allocation unsupported */
        VIR_INFO("The path '" SYSFS_RESCTRL_PATH "/info/MB/bandwidth_gran'"
                 "does not exist");
        ret = 0;
        goto cleanup;
    } else if (rv < 0) {
        /* Other failures are fatal, so just quit */
        goto cleanup;
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
        goto cleanup;

    rv = virFileReadValueUint(&i_membw->max_allocation,
                              SYSFS_RESCTRL_PATH "/info/MB/num_closids");
    if (rv == -2) {
         /* Similar reasoning to min_bandwidth above. */
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot get max allocation from resctrl memory info"));
    }
    if (rv < 0)
        goto cleanup;

    VIR_STEAL_PTR(resctrl->membw_info, i_membw);
    ret = 0;
 cleanup:
    VIR_FREE(i_membw);
    return ret;
}


static int
virResctrlGetInfo(virResctrlInfoPtr resctrl)
{
    DIR *dirp = NULL;
    int ret = -1;

    ret = virDirOpenIfExists(&dirp, SYSFS_RESCTRL_PATH "/info");
    if (ret <= 0)
        goto cleanup;

    ret = virResctrlGetMemoryBandwidthInfo(resctrl);
    if (ret < 0)
        goto cleanup;

    ret = virResctrlGetCacheInfo(resctrl, dirp);
    if (ret < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_DIR_CLOSE(dirp);
    return ret;
}


virResctrlInfoPtr
virResctrlInfoNew(void)
{
    virResctrlInfoPtr ret = NULL;

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
virResctrlInfoIsEmpty(virResctrlInfoPtr resctrl)
{
    size_t i = 0;
    size_t j = 0;

    if (!resctrl)
        return true;

    if (resctrl->membw_info)
        return false;

    for (i = 0; i < resctrl->nlevels; i++) {
        virResctrlInfoPerLevelPtr i_level = resctrl->levels[i];

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
virResctrlInfoGetMemoryBandwidth(virResctrlInfoPtr resctrl,
                                 unsigned int level,
                                 virResctrlInfoMemBWPerNodePtr control)
{
    virResctrlInfoMemBWPtr membw_info = resctrl->membw_info;

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
virResctrlInfoGetCache(virResctrlInfoPtr resctrl,
                       unsigned int level,
                       unsigned long long size,
                       size_t *ncontrols,
                       virResctrlInfoPerCachePtr **controls)
{
    virResctrlInfoPerLevelPtr i_level = NULL;
    virResctrlInfoPerTypePtr i_type = NULL;
    size_t i = 0;
    int ret = -1;

    if (virResctrlInfoIsEmpty(resctrl))
        return 0;

    /* Let's take the opportunity to update the number of last level
     * cache. This number of memory bandwidth controller is same with
     * last level cache */
    if (resctrl->membw_info) {
        virResctrlInfoMemBWPtr membw_info = resctrl->membw_info;

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
                               _("level %u cache size %llu does not match "
                                 "expected size %llu"),
                                 level, i_type->size, size);
                goto error;
            }
            i_type->max_cache_id++;
        }

        if (VIR_EXPAND_N(*controls, *ncontrols, 1) < 0)
            goto error;
        if (VIR_ALLOC((*controls)[*ncontrols - 1]) < 0)
            goto error;

        memcpy((*controls)[*ncontrols - 1], &i_type->control, sizeof(i_type->control));
    }

    ret = 0;
 cleanup:
    return ret;
 error:
    while (*ncontrols)
        VIR_FREE((*controls)[--*ncontrols]);
    VIR_FREE(*controls);
    goto cleanup;
}


/* virResctrlAlloc-related definitions */
virResctrlAllocPtr
virResctrlAllocNew(void)
{
    if (virResctrlInitialize() < 0)
        return NULL;

    return virObjectNew(virResctrlAllocClass);
}


bool
virResctrlAllocIsEmpty(virResctrlAllocPtr alloc)
{
    size_t i = 0;
    size_t j = 0;
    size_t k = 0;

    if (!alloc)
        return true;

    if (alloc->mem_bw)
        return false;

    for (i = 0; i < alloc->nlevels; i++) {
        virResctrlAllocPerLevelPtr a_level = alloc->levels[i];

        if (!a_level)
            continue;

        for (j = 0; j < VIR_CACHE_TYPE_LAST; j++) {
            virResctrlAllocPerTypePtr a_type = a_level->types[j];

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


static virResctrlAllocPerTypePtr
virResctrlAllocGetType(virResctrlAllocPtr alloc,
                       unsigned int level,
                       virCacheType type)
{
    virResctrlAllocPerLevelPtr a_level = NULL;

    if (alloc->nlevels <= level &&
        VIR_EXPAND_N(alloc->levels, alloc->nlevels, level - alloc->nlevels + 1) < 0)
        return NULL;

    if (!alloc->levels[level]) {
        virResctrlAllocPerTypePtr *types = NULL;

        if (VIR_ALLOC_N(types, VIR_CACHE_TYPE_LAST) < 0)
            return NULL;

        if (VIR_ALLOC(alloc->levels[level]) < 0) {
            VIR_FREE(types);
            return NULL;
        }
        alloc->levels[level]->types = types;
    }

    a_level = alloc->levels[level];

    if (!a_level->types[type] && VIR_ALLOC(a_level->types[type]) < 0)
        return NULL;

    return a_level->types[type];
}


static int
virResctrlAllocUpdateMask(virResctrlAllocPtr alloc,
                          unsigned int level,
                          virCacheType type,
                          unsigned int cache,
                          virBitmapPtr mask)
{
    virResctrlAllocPerTypePtr a_type = virResctrlAllocGetType(alloc, level, type);

    if (!a_type)
        return -1;

    if (a_type->nmasks <= cache &&
        VIR_EXPAND_N(a_type->masks, a_type->nmasks,
                     cache - a_type->nmasks + 1) < 0)
        return -1;

    if (!a_type->masks[cache]) {
        a_type->masks[cache] = virBitmapNew(virBitmapSize(mask));

        if (!a_type->masks[cache])
            return -1;
    }

    return virBitmapCopy(a_type->masks[cache], mask);
}


static int
virResctrlAllocUpdateSize(virResctrlAllocPtr alloc,
                          unsigned int level,
                          virCacheType type,
                          unsigned int cache,
                          unsigned long long size)
{
    virResctrlAllocPerTypePtr a_type = virResctrlAllocGetType(alloc, level, type);

    if (!a_type)
        return -1;

    if (a_type->nsizes <= cache &&
        VIR_EXPAND_N(a_type->sizes, a_type->nsizes,
                     cache - a_type->nsizes + 1) < 0)
        return -1;

    if (!a_type->sizes[cache] && VIR_ALLOC(a_type->sizes[cache]) < 0)
        return -1;

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
virResctrlAllocCheckCollision(virResctrlAllocPtr alloc,
                              unsigned int level,
                              virCacheType type,
                              unsigned int cache)
{
    virResctrlAllocPerLevelPtr a_level = NULL;
    virResctrlAllocPerTypePtr a_type = NULL;

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
virResctrlAllocSetCacheSize(virResctrlAllocPtr alloc,
                            unsigned int level,
                            virCacheType type,
                            unsigned int cache,
                            unsigned long long size)
{
    if (virResctrlAllocCheckCollision(alloc, level, type, cache)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Colliding cache allocations for cache "
                         "level '%u' id '%u', type '%s'"),
                       level, cache, virCacheTypeToString(type));
        return -1;
    }

    return virResctrlAllocUpdateSize(alloc, level, type, cache, size);
}


int
virResctrlAllocForeachCache(virResctrlAllocPtr alloc,
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
        virResctrlAllocPerLevelPtr a_level = alloc->levels[level];

        if (!a_level)
            continue;

        for (type = 0; type < VIR_CACHE_TYPE_LAST; type++) {
            virResctrlAllocPerTypePtr a_type = a_level->types[type];

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
virResctrlAllocSetMemoryBandwidth(virResctrlAllocPtr alloc,
                                  unsigned int id,
                                  unsigned int memory_bandwidth)
{
    virResctrlAllocMemBWPtr mem_bw = alloc->mem_bw;

    if (memory_bandwidth > 100) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Memory Bandwidth value exceeding 100 is invalid."));
        return -1;
    }

    if (!mem_bw) {
        if (VIR_ALLOC(mem_bw) < 0)
            return -1;
        alloc->mem_bw = mem_bw;
    }

    if (mem_bw->nbandwidths <= id &&
        VIR_EXPAND_N(mem_bw->bandwidths, mem_bw->nbandwidths,
                     id - mem_bw->nbandwidths + 1) < 0)
        return -1;

    if (mem_bw->bandwidths[id]) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Memory Bandwidth already defined for node %u"),
                       id);
        return -1;
    }

    if (VIR_ALLOC(mem_bw->bandwidths[id]) < 0)
        return -1;

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
virResctrlAllocForeachMemory(virResctrlAllocPtr alloc,
                             virResctrlAllocForeachMemoryCallback cb,
                             void *opaque)
{
    size_t i = 0;
    virResctrlAllocMemBWPtr mem_bw;

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


int
virResctrlAllocSetID(virResctrlAllocPtr alloc,
                     const char *id)
{
    if (!id) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Resctrl allocation 'id' cannot be NULL"));
        return -1;
    }

    return VIR_STRDUP(alloc->id, id);
}


const char *
virResctrlAllocGetID(virResctrlAllocPtr alloc)
{
    return alloc->id;
}


/* Format the Memory Bandwidth Allocation line that will be found in
 * the schemata files. The line should be start with "MB:" and be
 * followed by "id=value" pairs separated by a semi-colon such as:
 *
 *     MB:0=100;1=100
 *
 * which indicates node id 0 has 100 percent bandwith and node id 1
 * has 100 percent bandwidth. A trailing semi-colon is not formatted.
 */
static int
virResctrlAllocMemoryBandwidthFormat(virResctrlAllocPtr alloc,
                                     virBufferPtr buf)
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

    virBufferTrim(buf, ";", 1);
    virBufferAddChar(buf, '\n');
    return virBufferCheckError(buf);
}


static int
virResctrlAllocParseProcessMemoryBandwidth(virResctrlInfoPtr resctrl,
                                           virResctrlAllocPtr alloc,
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
                       _("Invalid node id %u "), id);
        return -1;
    }
    if (virStrToLong_uip(tmp, NULL, 10, &bandwidth) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid bandwidth %u"), bandwidth);
        return -1;
    }
    if (bandwidth < resctrl->membw_info->min_bandwidth ||
        id > resctrl->membw_info->max_id) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Missing or inconsistent resctrl info for "
                         "memory bandwidth node '%u'"), id);
        return -1;
    }
    if (alloc->mem_bw->nbandwidths <= id &&
        VIR_EXPAND_N(alloc->mem_bw->bandwidths, alloc->mem_bw->nbandwidths,
                     id - alloc->mem_bw->nbandwidths + 1) < 0) {
        return -1;
    }
    if (!alloc->mem_bw->bandwidths[id]) {
        if (VIR_ALLOC(alloc->mem_bw->bandwidths[id]) < 0)
            return -1;
    }

    *(alloc->mem_bw->bandwidths[id]) = bandwidth;
    return 0;
}


/* Parse a schemata formatted MB: entry. Format details are described in
 * virResctrlAllocMemoryBandwidthFormat.
 */
static int
virResctrlAllocParseMemoryBandwidthLine(virResctrlInfoPtr resctrl,
                                        virResctrlAllocPtr alloc,
                                        char *line)
{
    char **mbs = NULL;
    char *tmp = NULL;
    size_t nmbs = 0;
    size_t i;
    int ret = -1;

    /* For no reason there can be spaces */
    virSkipSpaces((const char **) &line);

    if (STRNEQLEN(line, "MB", 2))
        return 0;

    if (!resctrl || !resctrl->membw_info ||
        !resctrl->membw_info->min_bandwidth ||
        !resctrl->membw_info->bandwidth_granularity) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing or inconsistent resctrl info for "
                         "memory bandwidth allocation"));
        return -1;
    }

    if (!alloc->mem_bw) {
        if (VIR_ALLOC(alloc->mem_bw) < 0)
            return -1;
    }

    tmp = strchr(line, ':');
    if (!tmp)
        return 0;
    tmp++;

    mbs = virStringSplitCount(tmp, ";", 0, &nmbs);
    for (i = 0; i < nmbs; i++) {
        if (virResctrlAllocParseProcessMemoryBandwidth(resctrl, alloc, mbs[i]) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    virStringListFree(mbs);
    return ret;
}


static int
virResctrlAllocFormatCache(virResctrlAllocPtr alloc,
                           virBufferPtr buf)
{
    unsigned int level = 0;
    unsigned int type = 0;
    unsigned int cache = 0;

    for (level = 0; level < alloc->nlevels; level++) {
        virResctrlAllocPerLevelPtr a_level = alloc->levels[level];

        if (!a_level)
            continue;

        for (type = 0; type < VIR_CACHE_TYPE_LAST; type++) {
            virResctrlAllocPerTypePtr a_type = a_level->types[type];

            if (!a_type)
                continue;

            virBufferAsprintf(buf, "L%u%s:", level, virResctrlTypeToString(type));

            for (cache = 0; cache < a_type->nmasks; cache++) {
                virBitmapPtr mask = a_type->masks[cache];
                char *mask_str = NULL;

                if (!mask)
                    continue;

                mask_str = virBitmapToString(mask, false, true);
                if (!mask_str)
                    return -1;

                virBufferAsprintf(buf, "%u=%s;", cache, mask_str);
                VIR_FREE(mask_str);
            }

            virBufferTrim(buf, ";", 1);
            virBufferAddChar(buf, '\n');
        }
    }

    return virBufferCheckError(buf);
}


char *
virResctrlAllocFormat(virResctrlAllocPtr alloc)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (!alloc)
        return NULL;

    if (virResctrlAllocFormatCache(alloc, &buf) < 0) {
        virBufferFreeAndReset(&buf);
        return NULL;
    }

    if (virResctrlAllocMemoryBandwidthFormat(alloc, &buf) < 0) {
        virBufferFreeAndReset(&buf);
        return NULL;
    }

    return virBufferContentAndReset(&buf);
}


static int
virResctrlAllocParseProcessCache(virResctrlInfoPtr resctrl,
                                 virResctrlAllocPtr alloc,
                                 unsigned int level,
                                 virCacheType type,
                                 char *cache)
{
    char *tmp = strchr(cache, '=');
    unsigned int cache_id = 0;
    virBitmapPtr mask = NULL;
    int ret = -1;

    if (!tmp)
        return 0;

    *tmp = '\0';
    tmp++;

    if (virStrToLong_uip(cache, NULL, 10, &cache_id) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid cache id '%s'"), cache);
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
                       _("Missing or inconsistent resctrl info for "
                         "level '%u' type '%s'"),
                       level, virCacheTypeToString(type));
        goto cleanup;
    }

    virBitmapShrink(mask, resctrl->levels[level]->types[type]->bits);

    if (virResctrlAllocUpdateMask(alloc, level, type, cache_id, mask) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virBitmapFree(mask);
    return ret;
}


static int
virResctrlAllocParseCacheLine(virResctrlInfoPtr resctrl,
                              virResctrlAllocPtr alloc,
                              char *line)
{
    char **caches = NULL;
    char *tmp = NULL;
    unsigned int level = 0;
    int type = -1;
    size_t ncaches = 0;
    size_t i = 0;
    int ret = -1;

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
                       _("Cannot parse resctrl schema level '%s'"),
                       line + 1);
        return -1;
    }

    type = virResctrlTypeFromString(line);
    if (type < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot parse resctrl schema level '%s'"),
                       line + 1);
        return -1;
    }

    caches = virStringSplitCount(tmp, ";", 0, &ncaches);
    if (!caches)
        return 0;

    for (i = 0; i < ncaches; i++) {
        if (virResctrlAllocParseProcessCache(resctrl, alloc, level, type, caches[i]) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    virStringListFree(caches);
    return ret;
}


static int
virResctrlAllocParse(virResctrlInfoPtr resctrl,
                     virResctrlAllocPtr alloc,
                     const char *schemata)
{
    char **lines = NULL;
    size_t nlines = 0;
    size_t i = 0;
    int ret = -1;

    lines = virStringSplitCount(schemata, "\n", 0, &nlines);
    for (i = 0; i < nlines; i++) {
        if (virResctrlAllocParseCacheLine(resctrl, alloc, lines[i]) < 0)
            goto cleanup;
        if (virResctrlAllocParseMemoryBandwidthLine(resctrl, alloc, lines[i]) < 0)
            goto cleanup;

    }

    ret = 0;
 cleanup:
    virStringListFree(lines);
    return ret;
}


static int
virResctrlAllocGetGroup(virResctrlInfoPtr resctrl,
                        const char *groupname,
                        virResctrlAllocPtr *alloc)
{
    char *schemata = NULL;
    int rv = virFileReadValueString(&schemata,
                                     SYSFS_RESCTRL_PATH
                                     "/%s/schemata",
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
    virObjectUnref(*alloc);
    *alloc = NULL;
    return -1;
}


static virResctrlAllocPtr
virResctrlAllocGetDefault(virResctrlInfoPtr resctrl)
{
    virResctrlAllocPtr ret = NULL;
    int rv = virResctrlAllocGetGroup(resctrl, ".", &ret);

    if (rv == -2) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not read schemata file for the default group"));
    }

    return ret;
}


static void
virResctrlAllocSubtractPerType(virResctrlAllocPerTypePtr dst,
                               virResctrlAllocPerTypePtr src)
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
virResctrlAllocSubtract(virResctrlAllocPtr dst,
                        virResctrlAllocPtr src)
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


static void
virResctrlMemoryBandwidthSubtract(virResctrlAllocPtr free,
                                  virResctrlAllocPtr used)
{
    size_t i;

    if (!used->mem_bw)
        return;

    for (i = 0; i < used->mem_bw->nbandwidths; i++) {
        if (used->mem_bw->bandwidths[i])
            *(free->mem_bw->bandwidths[i]) -= *(used->mem_bw->bandwidths[i]);
    }
}


static virResctrlAllocPtr
virResctrlAllocNewFromInfo(virResctrlInfoPtr info)
{
    size_t i = 0;
    size_t j = 0;
    size_t k = 0;
    virResctrlAllocPtr ret = virResctrlAllocNew();
    virBitmapPtr mask = NULL;

    if (!ret)
        return NULL;

    for (i = 0; i < info->nlevels; i++) {
        virResctrlInfoPerLevelPtr i_level = info->levels[i];

        if (!i_level)
            continue;

        for (j = 0; j < VIR_CACHE_TYPE_LAST; j++) {
            virResctrlInfoPerTypePtr i_type = i_level->types[j];

            if (!i_type)
                continue;

            virBitmapFree(mask);
            mask = virBitmapNew(i_type->bits);
            if (!mask)
                goto error;
            virBitmapSetAll(mask);

            for (k = 0; k <= i_type->max_cache_id; k++) {
                if (virResctrlAllocUpdateMask(ret, i, j, k, mask) < 0)
                    goto error;
            }
        }
    }

    /* set default free memory bandwidth to 100%*/
    if (info->membw_info) {
        if (VIR_ALLOC(ret->mem_bw) < 0)
            goto error;

        if (VIR_EXPAND_N(ret->mem_bw->bandwidths, ret->mem_bw->nbandwidths,
                         info->membw_info->max_id + 1) < 0)
            goto error;

        for (i = 0; i < ret->mem_bw->nbandwidths; i++) {
            if (VIR_ALLOC(ret->mem_bw->bandwidths[i]) < 0)
                goto error;
            *(ret->mem_bw->bandwidths[i]) = 100;
        }
    }

 cleanup:
    virBitmapFree(mask);
    return ret;
 error:
    virObjectUnref(ret);
    ret = NULL;
    goto cleanup;
}

/*
 * This function creates an allocation that represents all unused parts of
 * all caches and memory bandwidth in the system. It uses virResctrlInfo
 * for creating a new full allocation with all bits set (using the
 * virResctrlAllocNewFromInfo()), sets memory bandwidth 100%, and then scans
 * for all allocations under /sys/fs/resctrl and subtracts each one of them
 * from it. That way it can then return an allocation with only bit set
 * being those that are not mentioned in any other allocation for CAT and
 * available memory bandwidth for MBA. It is used for two things, calculating
 * the masks and bandwidth available when creating allocations and from tests.
 */
virResctrlAllocPtr
virResctrlAllocGetUnused(virResctrlInfoPtr resctrl)
{
    virResctrlAllocPtr ret = NULL;
    virResctrlAllocPtr alloc = NULL;
    struct dirent *ent = NULL;
    DIR *dirp = NULL;
    int rv = -1;

    if (virResctrlInfoIsEmpty(resctrl)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Resource control is not supported on this host"));
        return NULL;
    }

    ret = virResctrlAllocNewFromInfo(resctrl);
    if (!ret)
        return NULL;

    alloc = virResctrlAllocGetDefault(resctrl);
    if (!alloc)
        goto error;

    virResctrlAllocSubtract(ret, alloc);
    virObjectUnref(alloc);

    if (virDirOpen(&dirp, SYSFS_RESCTRL_PATH) < 0)
        goto error;

    while ((rv = virDirRead(dirp, &ent, SYSFS_RESCTRL_PATH)) > 0) {
        if (STREQ(ent->d_name, "info"))
            continue;

        rv = virResctrlAllocGetGroup(resctrl, ent->d_name, &alloc);
        if (rv == -2)
            continue;

        if (rv < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not read schemata file for group %s"),
                           ent->d_name);
            goto error;
        }

        virResctrlMemoryBandwidthSubtract(ret, alloc);
        virResctrlAllocSubtract(ret, alloc);
        virObjectUnref(alloc);
        alloc = NULL;
    }
    if (rv < 0)
        goto error;

 cleanup:
    virObjectUnref(alloc);
    VIR_DIR_CLOSE(dirp);
    return ret;

 error:
    virObjectUnref(ret);
    ret = NULL;
    goto cleanup;
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
virResctrlAllocFindUnused(virResctrlAllocPtr alloc,
                          virResctrlInfoPerTypePtr i_type,
                          virResctrlAllocPerTypePtr f_type,
                          unsigned int level,
                          unsigned int type,
                          unsigned int cache)
{
    unsigned long long *size = alloc->levels[level]->types[type]->sizes[cache];
    virBitmapPtr a_mask = NULL;
    virBitmapPtr f_mask = NULL;
    unsigned long long need_bits;
    size_t i = 0;
    ssize_t pos = -1;
    ssize_t last_bits = 0;
    ssize_t last_pos = -1;
    int ret = -1;

    if (!size)
        return 0;

    if (cache >= f_type->nmasks) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Cache with id %u does not exists for level %d"),
                       cache, level);
        return -1;
    }

    f_mask = f_type->masks[cache];
    if (!f_mask) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Cache level %d id %u does not support tuning for "
                         "scope type '%s'"),
                       level, cache, virCacheTypeToString(type));
        return -1;
    }

    if (*size == i_type->size) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Cache allocation for the whole cache is not "
                         "possible, specify size smaller than %llu"),
                       i_type->size);
        return -1;
    }

    need_bits = *size / i_type->control.granularity;

    if (*size % i_type->control.granularity) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Cache allocation of size %llu is not "
                         "divisible by granularity %llu"),
                       *size, i_type->control.granularity);
        return -1;
    }

    if (need_bits < i_type->min_cbm_bits) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Cache allocation of size %llu is smaller "
                         "than the minimum allowed allocation %llu"),
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
                       _("Not enough room for allocation of "
                         "%llu bytes for level %u cache %u "
                         "scope type '%s'"),
                       *size, level, cache,
                       virCacheTypeToString(type));
        return -1;
    }

    a_mask = virBitmapNew(i_type->bits);
    if (!a_mask)
        return -1;

    for (i = last_pos; i < last_pos + need_bits; i++)
        ignore_value(virBitmapSetBit(a_mask, i));

    if (virResctrlAllocUpdateMask(alloc, level, type, cache, a_mask) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virBitmapFree(a_mask);
    return ret;
}


static int
virResctrlAllocMemoryBandwidth(virResctrlInfoPtr resctrl,
                               virResctrlAllocPtr alloc,
                               virResctrlAllocPtr free)
{
    size_t i;
    virResctrlAllocMemBWPtr mem_bw_alloc = alloc->mem_bw;
    virResctrlAllocMemBWPtr mem_bw_free = free->mem_bw;
    virResctrlInfoMemBWPtr mem_bw_info = resctrl->membw_info;

    if (!mem_bw_alloc)
        return 0;

    if (mem_bw_alloc && !mem_bw_info) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("RDT Memory Bandwidth allocation unsupported"));
        return -1;
    }

    for (i = 0; i < mem_bw_alloc->nbandwidths; i++) {
        if (!mem_bw_alloc->bandwidths[i])
            continue;

        if (*(mem_bw_alloc->bandwidths[i]) % mem_bw_info->bandwidth_granularity) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Memory Bandwidth allocation of size "
                             "%u is not divisible by granularity %u"),
                           *(mem_bw_alloc->bandwidths[i]),
                           mem_bw_info->bandwidth_granularity);
            return -1;
        }
        if (*(mem_bw_alloc->bandwidths[i]) < mem_bw_info->min_bandwidth) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Memory Bandwidth allocation of size "
                             "%u is smaller than the minimum "
                             "allowed allocation %u"),
                           *(mem_bw_alloc->bandwidths[i]),
                           mem_bw_info->min_bandwidth);
            return -1;
        }
        if (i > mem_bw_info->max_id) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("bandwidth controller id %zd does not "
                             "exist, max controller id %u"),
                           i, mem_bw_info->max_id);
            return -1;
        }
        if (*(mem_bw_alloc->bandwidths[i]) > *(mem_bw_free->bandwidths[i])) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Not enough room for allocation of %u%% "
                             "bandwidth on node %zd, available bandwidth %u%%"),
                           *(mem_bw_alloc->bandwidths[i]), i,
                           *(mem_bw_free->bandwidths[i]));
            return -1;
        }
    }
    return 0;
}


static int
virResctrlAllocCopyMasks(virResctrlAllocPtr dst,
                         virResctrlAllocPtr src)
{
    unsigned int level = 0;

    for (level = 0; level < src->nlevels; level++) {
        virResctrlAllocPerLevelPtr s_level = src->levels[level];
        unsigned int type = 0;

        if (!s_level)
            continue;

        for (type = 0; type < VIR_CACHE_TYPE_LAST; type++) {
            virResctrlAllocPerTypePtr s_type = s_level->types[type];
            virResctrlAllocPerTypePtr d_type = NULL;
            unsigned int cache = 0;

            if (!s_type)
                continue;

            d_type = virResctrlAllocGetType(dst, level, type);
            if (!d_type)
                return -1;

            for (cache = 0; cache < s_type->nmasks; cache++) {
                virBitmapPtr mask = s_type->masks[cache];

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
virResctrlAllocAssign(virResctrlInfoPtr resctrl,
                      virResctrlAllocPtr alloc)
{
    int ret = -1;
    unsigned int level = 0;
    virResctrlAllocPtr alloc_free = NULL;
    virResctrlAllocPtr alloc_default = NULL;

    alloc_free = virResctrlAllocGetUnused(resctrl);
    if (!alloc_free)
        return -1;

    alloc_default = virResctrlAllocGetDefault(resctrl);
    if (!alloc_default)
        goto cleanup;

    if (virResctrlAllocMemoryBandwidth(resctrl, alloc, alloc_free) < 0)
        goto cleanup;

    if (virResctrlAllocCopyMasks(alloc, alloc_default) < 0)
        goto cleanup;

    for (level = 0; level < alloc->nlevels; level++) {
        virResctrlAllocPerLevelPtr a_level = alloc->levels[level];
        virResctrlAllocPerLevelPtr f_level = NULL;
        unsigned int type = 0;

        if (!a_level)
            continue;

        if (level < alloc_free->nlevels)
            f_level = alloc_free->levels[level];

        if (!f_level) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Cache level %d does not support tuning"),
                           level);
            goto cleanup;
        }

        for (type = 0; type < VIR_CACHE_TYPE_LAST; type++) {
            virResctrlAllocPerTypePtr a_type = a_level->types[type];
            virResctrlAllocPerTypePtr f_type = f_level->types[type];
            unsigned int cache = 0;

            if (!a_type)
                continue;

            if (!f_type) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Cache level %d does not support tuning for "
                                 "scope type '%s'"),
                               level, virCacheTypeToString(type));
                goto cleanup;
            }

            for (cache = 0; cache < a_type->nsizes; cache++) {
                virResctrlInfoPerLevelPtr i_level = resctrl->levels[level];
                virResctrlInfoPerTypePtr i_type = i_level->types[type];

                if (virResctrlAllocFindUnused(alloc, i_type, f_type, level, type, cache) < 0)
                    goto cleanup;
            }
        }
    }

    ret = 0;
 cleanup:
    virObjectUnref(alloc_free);
    virObjectUnref(alloc_default);
    return ret;
}


int
virResctrlAllocDeterminePath(virResctrlAllocPtr alloc,
                             const char *machinename)
{
    if (!alloc->id) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Resctrl Allocation ID must be set before creation"));
        return -1;
    }

    if (!alloc->path &&
        virAsprintf(&alloc->path, "%s/%s-%s",
                    SYSFS_RESCTRL_PATH, machinename, alloc->id) < 0)
        return -1;

    return 0;
}


/* This checks if the directory for the alloc exists.  If not it tries to create
 * it and apply appropriate alloc settings. */
int
virResctrlAllocCreate(virResctrlInfoPtr resctrl,
                      virResctrlAllocPtr alloc,
                      const char *machinename)
{
    char *schemata_path = NULL;
    char *alloc_str = NULL;
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

    if (virFileExists(alloc->path)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Path '%s' for resctrl allocation exists"),
                       alloc->path);
        goto cleanup;
    }

    lockfd = virResctrlLockWrite();
    if (lockfd < 0)
        goto cleanup;

    if (virResctrlAllocAssign(resctrl, alloc) < 0)
        goto cleanup;

    alloc_str = virResctrlAllocFormat(alloc);
    if (!alloc_str)
        goto cleanup;

    if (virAsprintf(&schemata_path, "%s/schemata", alloc->path) < 0)
        goto cleanup;

    if (virFileMakePath(alloc->path) < 0) {
        virReportSystemError(errno,
                             _("Cannot create resctrl directory '%s'"),
                             alloc->path);
        goto cleanup;
    }

    VIR_DEBUG("Writing resctrl schemata '%s' into '%s'", alloc_str, schemata_path);
    if (virFileWriteStr(schemata_path, alloc_str, 0) < 0) {
        rmdir(alloc->path);
        virReportSystemError(errno,
                             _("Cannot write into schemata file '%s'"),
                             schemata_path);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virResctrlUnlock(lockfd);
    VIR_FREE(alloc_str);
    VIR_FREE(schemata_path);
    return ret;
}


int
virResctrlAllocAddPID(virResctrlAllocPtr alloc,
                      pid_t pid)
{
    char *tasks = NULL;
    char *pidstr = NULL;
    int ret = 0;

    if (!alloc->path) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot add pid to non-existing resctrl allocation"));
        return -1;
    }

    if (virAsprintf(&tasks, "%s/tasks", alloc->path) < 0)
        return -1;

    if (virAsprintf(&pidstr, "%lld", (long long int) pid) < 0)
        goto cleanup;

    if (virFileWriteStr(tasks, pidstr, 0) < 0) {
        virReportSystemError(errno,
                             _("Cannot write pid in tasks file '%s'"),
                             tasks);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(tasks);
    VIR_FREE(pidstr);
    return ret;
}


int
virResctrlAllocRemove(virResctrlAllocPtr alloc)
{
    int ret = 0;

    if (!alloc->path)
        return 0;

    VIR_DEBUG("Removing resctrl allocation %s", alloc->path);
    if (rmdir(alloc->path) != 0 && errno != ENOENT) {
        ret = -errno;
        VIR_ERROR(_("Unable to remove %s (%d)"), alloc->path, errno);
    }

    return ret;
}
