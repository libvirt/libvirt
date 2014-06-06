/*
 * numatune_conf.h
 *
 * Copyright (C) 2014 Red Hat, Inc.
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
 * Author: Martin Kletzander <mkletzan@redhat.com>
 */

#ifndef __NUMATUNE_CONF_H__
# define __NUMATUNE_CONF_H__

# include "internal.h"
# include "virutil.h"
# include "virbitmap.h"

typedef enum {
    VIR_NUMA_TUNE_MEM_PLACEMENT_MODE_DEFAULT = 0,
    VIR_NUMA_TUNE_MEM_PLACEMENT_MODE_STATIC,
    VIR_NUMA_TUNE_MEM_PLACEMENT_MODE_AUTO,

    VIR_NUMA_TUNE_MEM_PLACEMENT_MODE_LAST
} virDomainNumaTuneMemPlacementMode;

VIR_ENUM_DECL(virNumaTuneMemPlacementMode)

VIR_ENUM_DECL(virDomainNumatuneMemMode)

typedef struct _virNumaTuneDef virNumaTuneDef;
typedef virNumaTuneDef *virNumaTuneDefPtr;
struct _virNumaTuneDef {
    struct {
        virBitmapPtr nodemask;
        int mode;           /* enum virDomainNumatuneMemMode */
        int placement_mode; /* enum virNumaTuneMemPlacementMode */
    } memory;               /* pinning for all the memory */

    /* Future NUMA tuning related stuff should go here. */
};

#endif /* __NUMATUNE_CONF_H__ */
