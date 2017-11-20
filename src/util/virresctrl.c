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

#include "virresctrl.h"

#include "c-ctype.h"
#include "count-one-bits.h"
#include "viralloc.h"
#include "virfile.h"
#include "virlog.h"
#include "virobject.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_RESCTRL

VIR_LOG_INIT("util.virresctrl")


/* Common definitions */
#define SYSFS_RESCTRL_PATH "/sys/fs/resctrl"

/* Resctrl is short for Resource Control.  It might be implemented for various
 * resources, but at the time of this writing this is only supported for cache
 * allocation technology (aka CAT).  Hence the reson for leaving 'Cache' out of
 * all the structure and function names for now (can be added later if needed.
 */

/* Our naming for cache types and scopes */
VIR_ENUM_IMPL(virCache, VIR_CACHE_TYPE_LAST,
              "both",
              "code",
              "data")

/*
 * This is the same enum, but for the resctrl naming
 * of the type (L<level><type>)
 */
VIR_ENUM_DECL(virResctrl)
VIR_ENUM_IMPL(virResctrl, VIR_CACHE_TYPE_LAST,
              "",
              "CODE",
              "DATA")


/* Info-related definitions and InfoClass-related functions */
typedef struct _virResctrlInfoPerType virResctrlInfoPerType;
typedef virResctrlInfoPerType *virResctrlInfoPerTypePtr;
struct _virResctrlInfoPerType {
    /* Kernel-provided information */
    char *cbm_mask;
    unsigned int min_cbm_bits;

    /* Our computed information from the above */
    unsigned int bits;
    unsigned int max_cache_id;

    /* In order to be self-sufficient we need size information per cache.
     * Funnily enough, one of the outcomes of the resctrlfs design is that it
     * does not account for different sizes per cache on the same level.  So
     * for the sake of easiness, let's copy that, for now. */
    unsigned long long size;

    /* Information that we will return upon request (this is public struct) as
     * until now all the above is internal to this module */
    virResctrlInfoPerCache control;
};

typedef struct _virResctrlInfoPerLevel virResctrlInfoPerLevel;
typedef virResctrlInfoPerLevel *virResctrlInfoPerLevelPtr;
struct _virResctrlInfoPerLevel {
    virResctrlInfoPerTypePtr *types;
};

struct _virResctrlInfo {
    virObject parent;

    virResctrlInfoPerLevelPtr *levels;
    size_t nlevels;
};

static virClassPtr virResctrlInfoClass;

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
            for (j = 0; j < VIR_CACHE_TYPE_LAST; j++) {
                if (level->types[j])
                    VIR_FREE(level->types[j]->cbm_mask);
                VIR_FREE(level->types[j]);
            }
        }
        VIR_FREE(level->types);
        VIR_FREE(level);
    }

    VIR_FREE(resctrl->levels);
}


static int
virResctrlInfoOnceInit(void)
{
    if (!(virResctrlInfoClass = virClassNew(virClassForObject(),
                                            "virResctrlInfo",
                                            sizeof(virResctrlInfo),
                                            virResctrlInfoDispose)))
        return -1;

    return 0;
}


VIR_ONCE_GLOBAL_INIT(virResctrlInfo)


virResctrlInfoPtr
virResctrlInfoNew(void)
{
    if (virResctrlInfoInitialize() < 0)
        return NULL;

    return virObjectNew(virResctrlInfoClass);
}


/* Info-related functions */
static bool
virResctrlInfoIsEmpty(virResctrlInfoPtr resctrl)
{
    size_t i = 0;
    size_t j = 0;

    if (!resctrl)
        return true;

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
virResctrlGetInfo(virResctrlInfoPtr resctrl)
{
    DIR *dirp = NULL;
    char *info_path = NULL;
    char *endptr = NULL;
    char *tmp_str = NULL;
    int ret = -1;
    int rv = -1;
    int type = 0;
    struct dirent *ent = NULL;
    unsigned int level = 0;
    virResctrlInfoPerLevelPtr i_level = NULL;
    virResctrlInfoPerTypePtr i_type = NULL;

    rv = virDirOpenIfExists(&dirp, SYSFS_RESCTRL_PATH "/info");
    if (rv <= 0) {
        ret = rv;
        goto cleanup;
    }

    while ((rv = virDirRead(dirp, &ent, SYSFS_RESCTRL_PATH "/info")) > 0) {
        if (ent->d_type != DT_DIR)
            continue;

        if (ent->d_name[0] != 'L')
            continue;

        if (virStrToLong_uip(ent->d_name + 1, &endptr, 10, &level) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Cannot parse resctrl cache info level"));
            goto cleanup;
        }

        type = virResctrlTypeFromString(endptr);
        if (type < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Cannot parse resctrl cache info type"));
            goto cleanup;
        }

        if (VIR_ALLOC(i_type) < 0)
            goto cleanup;

        i_type->control.scope = type;

        rv = virFileReadValueUint(&i_type->control.max_allocation,
                                  SYSFS_RESCTRL_PATH "/info/%s/num_closids",
                                  ent->d_name);
        if (rv == -2)
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Cannot get num_closids from resctrl cache info"));
        if (rv < 0)
            goto cleanup;

        rv = virFileReadValueString(&i_type->cbm_mask,
                                    SYSFS_RESCTRL_PATH
                                    "/info/%s/cbm_mask",
                                    ent->d_name);
        if (rv == -2)
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Cannot get cbm_mask from resctrl cache info"));
        if (rv < 0)
            goto cleanup;

        virStringTrimOptionalNewline(i_type->cbm_mask);

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

        if (!resctrl->levels[level] &&
            (VIR_ALLOC(resctrl->levels[level]) < 0 ||
             VIR_ALLOC_N(resctrl->levels[level]->types, VIR_CACHE_TYPE_LAST) < 0))
            goto cleanup;
        i_level = resctrl->levels[level];

        if (i_level->types[type]) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Duplicate cache type in resctrlfs for level %u"),
                           level);
            goto cleanup;
        }

        for (tmp_str = i_type->cbm_mask; *tmp_str != '\0'; tmp_str++) {
            if (!c_isxdigit(*tmp_str)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Cannot parse cbm_mask from resctrl cache info"));
                goto cleanup;
            }

            i_type->bits += count_one_bits(virHexToBin(*tmp_str));
        }

        VIR_STEAL_PTR(i_level->types[type], i_type);
    }

    ret = 0;
 cleanup:
    VIR_DIR_CLOSE(dirp);
    VIR_FREE(info_path);
    if (i_type)
        VIR_FREE(i_type->cbm_mask);
    VIR_FREE(i_type);
    return ret;
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
