/*
 * numa_conf.h
 *
 * Copyright (C) 2014-2015 Red Hat, Inc.
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

#ifndef __NUMA_CONF_H__
# define __NUMA_CONF_H__

# include <libxml/xpath.h>

# include "internal.h"
# include "virutil.h"
# include "virbitmap.h"
# include "virbuffer.h"
# include "cpu_conf.h"


typedef struct _virDomainNuma virDomainNuma;
typedef virDomainNuma *virDomainNumaPtr;

typedef enum {
    VIR_DOMAIN_NUMATUNE_PLACEMENT_DEFAULT = 0,
    VIR_DOMAIN_NUMATUNE_PLACEMENT_STATIC,
    VIR_DOMAIN_NUMATUNE_PLACEMENT_AUTO,

    VIR_DOMAIN_NUMATUNE_PLACEMENT_LAST
} virDomainNumatunePlacement;

VIR_ENUM_DECL(virDomainNumatunePlacement)
VIR_ENUM_DECL(virDomainNumatuneMemMode)


void virDomainNumaFree(virDomainNumaPtr numa);

/*
 * XML Parse/Format functions
 */
int virDomainNumatuneParseXML(virDomainNumaPtr *numatunePtr,
                              bool placement_static,
                              size_t ncells,
                              xmlXPathContextPtr ctxt)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4);

int virDomainNumatuneFormatXML(virBufferPtr buf, virDomainNumaPtr numatune)
    ATTRIBUTE_NONNULL(1);

/*
 * Getters
 */
virDomainNumatuneMemMode virDomainNumatuneGetMode(virDomainNumaPtr numatune,
                                                  int cellid);

virBitmapPtr virDomainNumatuneGetNodeset(virDomainNumaPtr numatune,
                                         virBitmapPtr auto_nodeset,
                                         int cellid);

int virDomainNumatuneMaybeGetNodeset(virDomainNumaPtr numatune,
                                     virBitmapPtr auto_nodeset,
                                     virBitmapPtr *retNodeset,
                                     int cellid);

/*
 * Formatters
 */
char *virDomainNumatuneFormatNodeset(virDomainNumaPtr numatune,
                                     virBitmapPtr auto_nodeset,
                                     int cellid);

int virDomainNumatuneMaybeFormatNodeset(virDomainNumaPtr numatune,
                                        virBitmapPtr auto_nodeset,
                                        char **mask,
                                        int cellid);

/*
 * Setters
 */
int virDomainNumatuneSet(virDomainNumaPtr *numatunePtr,
                         bool placement_static,
                         int placement,
                         int mode,
                         virBitmapPtr nodeset)
    ATTRIBUTE_NONNULL(1);

/*
 * Other accessors
 */
bool virDomainNumaEquals(virDomainNumaPtr n1,
                         virDomainNumaPtr n2);

bool virDomainNumatuneHasPlacementAuto(virDomainNumaPtr numatune);

bool virDomainNumatuneHasPerNodeBinding(virDomainNumaPtr numatune);

int virDomainNumatuneSpecifiedMaxNode(virDomainNumaPtr numatune);

bool virDomainNumatuneNodesetIsAvailable(virDomainNumaPtr numatune,
                                         virBitmapPtr auto_nodeset);

bool virDomainNumatuneNodeSpecified(virDomainNumaPtr numatune,
                                    int cellid);

int virDomainNumaDefCPUParseXML(virCPUDefPtr def, xmlXPathContextPtr ctxt);
int virDomainNumaDefCPUFormat(virBufferPtr buf, virCPUDefPtr def);

#endif /* __NUMA_CONF_H__ */
