/*
 * virnuma.h: helper APIs for managing numa
 *
 * Copyright (C) 2011-2013 Red Hat, Inc.
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
 */

#ifndef __VIR_NUMA_H__
# define __VIR_NUMA_H__

# include "internal.h"
# include "virbitmap.h"
# include "virutil.h"

enum virNumaTuneMemPlacementMode {
    VIR_NUMA_TUNE_MEM_PLACEMENT_MODE_DEFAULT = 0,
    VIR_NUMA_TUNE_MEM_PLACEMENT_MODE_STATIC,
    VIR_NUMA_TUNE_MEM_PLACEMENT_MODE_AUTO,

    VIR_NUMA_TUNE_MEM_PLACEMENT_MODE_LAST
};

VIR_ENUM_DECL(virNumaTuneMemPlacementMode)

VIR_ENUM_DECL(virDomainNumatuneMemMode)

typedef struct _virNumaTuneDef virNumaTuneDef;
typedef virNumaTuneDef *virNumaTuneDefPtr;
struct _virNumaTuneDef {
    struct {
        virBitmapPtr nodemask;
        int mode;
        int placement_mode; /* enum virNumaTuneMemPlacementMode */
    } memory;

    /* Future NUMA tuning related stuff should go here. */
};

char *virNumaGetAutoPlacementAdvice(unsigned short vcups,
                                    unsigned long long balloon);

int virNumaSetupMemoryPolicy(virNumaTuneDef numatune,
                             virBitmapPtr nodemask);
#endif /* __VIR_NUMA_H__ */
