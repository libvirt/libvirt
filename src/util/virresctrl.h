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


typedef struct _virResctrlInfo virResctrlInfo;
typedef virResctrlInfo *virResctrlInfoPtr;
struct _virResctrlInfo {
    /* Smallest possible increase of the allocation size in bytes */
    unsigned long long granularity;
    /* Minimal allocatable size in bytes (if different from granularity) */
    unsigned long long min;
    /* Type of the allocation */
    virCacheType scope;
    /* Maximum number of simultaneous allocations */
    unsigned int max_allocation;
};


int
virResctrlGetCacheInfo(unsigned int level,
                       unsigned long long size,
                       virCacheType scope,
                       virResctrlInfoPtr **controls,
                       size_t *ncontrols);

int
virResctrlGetCacheControlType(unsigned int level);

#endif /*  __VIR_RESCTRL_H__ */
