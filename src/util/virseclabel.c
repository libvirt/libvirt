/*
 * virseclabel.c: security label utility functions
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
 * Copyright (C) 2006-2008 Daniel P. Berrange
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

#include "internal.h"
#include "viralloc.h"
#include "virseclabel.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE


void
virSecurityLabelDefFree(virSecurityLabelDefPtr def)
{
    if (!def)
        return;
    VIR_FREE(def->model);
    VIR_FREE(def->label);
    VIR_FREE(def->imagelabel);
    VIR_FREE(def->baselabel);
    VIR_FREE(def);
}


void
virSecurityDeviceLabelDefFree(virSecurityDeviceLabelDefPtr def)
{
    if (!def)
        return;
    VIR_FREE(def->model);
    VIR_FREE(def->label);
    VIR_FREE(def);
}


virSecurityLabelDefPtr
virSecurityLabelDefNew(const char *model)
{
    virSecurityLabelDefPtr seclabel = NULL;

    if (VIR_ALLOC(seclabel) < 0 ||
        VIR_STRDUP(seclabel->model, model) < 0) {
        virSecurityLabelDefFree(seclabel);
        return NULL;
    }

    seclabel->relabel = true;

    return seclabel;
}

virSecurityDeviceLabelDefPtr
virSecurityDeviceLabelDefNew(const char *model)
{
    virSecurityDeviceLabelDefPtr seclabel = NULL;

    if (VIR_ALLOC(seclabel) < 0 ||
        VIR_STRDUP(seclabel->model, model) < 0) {
        virSecurityDeviceLabelDefFree(seclabel);
        seclabel = NULL;
    }

    return seclabel;
}


virSecurityDeviceLabelDefPtr
virSecurityDeviceLabelDefCopy(const virSecurityDeviceLabelDef *src)
{
    virSecurityDeviceLabelDefPtr ret;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    ret->relabel = src->relabel;
    ret->labelskip = src->labelskip;

    if (VIR_STRDUP(ret->model, src->model) < 0 ||
        VIR_STRDUP(ret->label, src->label) < 0)
        goto error;

    return ret;

 error:
    virSecurityDeviceLabelDefFree(ret);
    return NULL;
}
