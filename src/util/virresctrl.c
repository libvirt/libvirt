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

int
virResctrlGetCacheInfo(unsigned int level,
                       unsigned long long size,
                       virCacheType scope,
                       virResctrlPtr **controls,
                       size_t *ncontrols)
{
    int ret = -1;
    char *tmp = NULL;
    char *path = NULL;
    char *cbm_mask = NULL;
    char *type_upper = NULL;
    unsigned int bits = 0;
    unsigned int min_cbm_bits = 0;
    virResctrlPtr control;

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


/*
 * This function tests which TYPE of cache control is supported
 * Return values are:
 *  -1: not supported
 *   0: CAT
 *   1: CDP
 */
int
virResctrlGetCacheControlType(unsigned int level)
{
    int ret = -1;
    char *path = NULL;

    if (virAsprintf(&path,
                    SYSFS_RESCTRL_PATH "/info/L%u",
                    level) < 0)
        return -1;

    if (virFileExists(path)) {
        ret = 0;
    } else {
        VIR_FREE(path);
        /*
         * If CDP is enabled, there will be both CODE and DATA, but it's enough
         * to check one of those only.
         */
        if (virAsprintf(&path,
                        SYSFS_RESCTRL_PATH "/info/L%uCODE",
                        level) < 0)
            return -1;
        if (virFileExists(path))
            ret = 1;
    }

    VIR_FREE(path);
    return ret;
}
