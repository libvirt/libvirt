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

# include <libxml/xpath.h>

# include "internal.h"
# include "virutil.h"
# include "virbitmap.h"
# include "virbuffer.h"

/*
 * Since numatune configuration is closely bound to the whole config,
 * and because we don't have separate domain_conf headers for
 * typedefs, structs and functions, we need to have a forward
 * declaration here for virDomainDef due to circular dependencies.
 */
typedef struct _virDomainDef virDomainDef;
typedef virDomainDef *virDomainDefPtr;


typedef struct _virDomainNumatune virDomainNumatune;
typedef virDomainNumatune *virDomainNumatunePtr;

typedef enum {
    VIR_DOMAIN_NUMATUNE_PLACEMENT_DEFAULT = 0,
    VIR_DOMAIN_NUMATUNE_PLACEMENT_STATIC,
    VIR_DOMAIN_NUMATUNE_PLACEMENT_AUTO,

    VIR_DOMAIN_NUMATUNE_PLACEMENT_LAST
} virDomainNumatunePlacement;

VIR_ENUM_DECL(virDomainNumatunePlacement)
VIR_ENUM_DECL(virDomainNumatuneMemMode)


void virDomainNumatuneFree(virDomainNumatunePtr numatune);

/*
 * XML Parse/Format functions
 */
int virDomainNumatuneParseXML(virDomainDefPtr def, xmlXPathContextPtr ctxt)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int virDomainNumatuneFormatXML(virBufferPtr buf, virDomainNumatunePtr numatune)
    ATTRIBUTE_NONNULL(1);

/*
 * Getters
 */
virDomainNumatuneMemMode virDomainNumatuneGetMode(virDomainNumatunePtr numatune,
                                                  int cellid);

virBitmapPtr virDomainNumatuneGetNodeset(virDomainNumatunePtr numatune,
                                         virBitmapPtr auto_nodeset,
                                         int cellid);

/*
 * Formatters
 */
char *virDomainNumatuneFormatNodeset(virDomainNumatunePtr numatune,
                                     virBitmapPtr auto_nodeset,
                                     int cellid);

int virDomainNumatuneMaybeFormatNodeset(virDomainNumatunePtr numatune,
                                        virBitmapPtr auto_nodeset,
                                        char **mask,
                                        int cellid);

/*
 * Setters
 */
int virDomainNumatuneSet(virDomainDefPtr def, int placement,
                         int mode, virBitmapPtr nodeset)
    ATTRIBUTE_NONNULL(1);

/*
 * Other accessors
 */
bool virDomainNumatuneEquals(virDomainNumatunePtr n1,
                             virDomainNumatunePtr n2);

bool virDomainNumatuneHasPlacementAuto(virDomainNumatunePtr numatune);

bool virDomainNumatuneHasPerNodeBinding(virDomainNumatunePtr numatune);

#endif /* __NUMATUNE_CONF_H__ */
