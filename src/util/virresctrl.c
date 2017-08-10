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
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_RESCTRL

VIR_LOG_INIT("util.virresctrl")

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

int
virResctrlGetCacheInfo(unsigned int level,
                       unsigned long long size,
                       virCacheType scope,
                       virResctrlInfoPtr **controls,
                       size_t *ncontrols)
{
    int ret = -1;
    char *tmp = NULL;
    char *path = NULL;
    char *cbm_mask = NULL;
    char *type_upper = NULL;
    unsigned int bits = 0;
    unsigned int min_cbm_bits = 0;
    virResctrlInfoPtr control;

    if (VIR_ALLOC(control) < 0)
        goto cleanup;

    if (scope != VIR_CACHE_TYPE_BOTH &&
        virStringToUpper(&type_upper, virCacheTypeToString(scope)) < 0)
        goto cleanup;

    if (virFileReadValueUint(&control->max_allocation,
                             SYSFS_RESCTRL_PATH "/info/L%u%s/num_closids",
                             level,
                             type_upper ? type_upper : "") < 0)
        goto cleanup;

    if (virFileReadValueString(&cbm_mask,
                               SYSFS_RESCTRL_PATH
                               "/info/L%u%s/cbm_mask",
                               level,
                               type_upper ? type_upper: "") < 0)
        goto cleanup;

    if (virFileReadValueUint(&min_cbm_bits,
                             SYSFS_RESCTRL_PATH "/info/L%u%s/min_cbm_bits",
                             level,
                             type_upper ? type_upper : "") < 0)
        goto cleanup;

    virStringTrimOptionalNewline(cbm_mask);

    for (tmp = cbm_mask; *tmp != '\0'; tmp++) {
        if (c_isxdigit(*tmp))
            bits += count_one_bits(virHexToBin(*tmp));
    }

    control->granularity = size / bits;
    if (min_cbm_bits != 1)
        control->min = min_cbm_bits * control->granularity;

    control->scope = scope;

    if (VIR_APPEND_ELEMENT(*controls, *ncontrols, control) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(path);
    VIR_FREE(cbm_mask);
    VIR_FREE(type_upper);
    VIR_FREE(control);
    return ret;
}


static inline int
virResctrlGetCacheDir(char **path,
                      const char *prefix,
                      unsigned int level,
                      virCacheType type)
{
    return virAsprintf(path,
                       SYSFS_RESCTRL_PATH "%s/L%u%s",
                       prefix ? prefix : "",
                       level,
                       virResctrlTypeToString(type));
}


/*
 * This function tests whether TYPE of cache control is supported or not.
 *
 * Returns 0 if not, 1 if yes and negative value on error.
 */
static int
virResctrlGetCacheSupport(unsigned int level, virCacheType type)
{
    int ret = -1;
    char *path = NULL;

    if (virResctrlGetCacheDir(&path, "/info", level, type) < 0)
        return -1;

    ret = virFileExists(path);
    VIR_FREE(path);
    return ret;
}


/*
 * This function tests which TYPE of cache control is supported
 * Return values are:
 *  -1: error
 *   0: none
 *   1: CAT
 *   2: CDP
 */
int
virResctrlGetCacheControlType(unsigned int level)
{
    int rv = -1;

    rv = virResctrlGetCacheSupport(level, VIR_CACHE_TYPE_BOTH);
    if (rv < 0)
        return -1;
    if (rv)
        return 1;

    rv = virResctrlGetCacheSupport(level, VIR_CACHE_TYPE_CODE);
    if (rv < 0)
        return -1;
    if (rv)
        return 2;

    return 0;
}
