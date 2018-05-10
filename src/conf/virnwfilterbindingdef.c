/*
 * virnwfilterbindingdef.c: network filter binding XML processing
 *
 * Copyright (C) 2018 Red Hat, Inc.
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

#include "viralloc.h"
#include "virerror.h"
#include "virstring.h"
#include "nwfilter_params.h"
#include "virnwfilterbindingdef.h"


#define VIR_FROM_THIS VIR_FROM_NWFILTER

void
virNWFilterBindingDefFree(virNWFilterBindingDefPtr def)
{
    if (!def)
        return;

    VIR_FREE(def->ownername);
    VIR_FREE(def->portdevname);
    VIR_FREE(def->linkdevname);
    VIR_FREE(def->filter);
    virHashFree(def->filterparams);

    VIR_FREE(def);
}


virNWFilterBindingDefPtr
virNWFilterBindingDefCopy(virNWFilterBindingDefPtr src)
{
    virNWFilterBindingDefPtr ret;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    if (VIR_STRDUP(ret->ownername, src->ownername) < 0)
        goto error;

    memcpy(ret->owneruuid, src->owneruuid, sizeof(ret->owneruuid));

    if (VIR_STRDUP(ret->portdevname, src->portdevname) < 0)
        goto error;

    if (VIR_STRDUP(ret->linkdevname, src->linkdevname) < 0)
        goto error;

    ret->mac = src->mac;

    if (VIR_STRDUP(ret->filter, src->filter) < 0)
        goto error;

    if (!(ret->filterparams = virNWFilterHashTableCreate(0)))
        goto error;

    if (virNWFilterHashTablePutAll(src->filterparams, ret->filterparams) < 0)
        goto error;

    return ret;

 error:
    virNWFilterBindingDefFree(ret);
    return NULL;
}
