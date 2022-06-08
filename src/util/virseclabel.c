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
#include "virseclabel.h"

#define VIR_FROM_THIS VIR_FROM_NONE


void
virSecurityLabelDefFree(virSecurityLabelDef *def)
{
    if (!def)
        return;
    g_free(def->model);
    g_free(def->label);
    g_free(def->imagelabel);
    g_free(def->baselabel);
    g_free(def);
}


void
virSecurityDeviceLabelDefFree(virSecurityDeviceLabelDef *def)
{
    if (!def)
        return;
    g_free(def->model);
    g_free(def->label);
    g_free(def);
}


virSecurityLabelDef *
virSecurityLabelDefNew(const char *model)
{
    virSecurityLabelDef *seclabel = NULL;

    seclabel = g_new0(virSecurityLabelDef, 1);

    seclabel->model = g_strdup(model);

    seclabel->relabel = true;

    return seclabel;
}

virSecurityDeviceLabelDef *
virSecurityDeviceLabelDefNew(const char *model)
{
    virSecurityDeviceLabelDef *seclabel = NULL;

    seclabel = g_new0(virSecurityDeviceLabelDef, 1);

    seclabel->model = g_strdup(model);

    return seclabel;
}


virSecurityDeviceLabelDef *
virSecurityDeviceLabelDefCopy(const virSecurityDeviceLabelDef *src)
{
    virSecurityDeviceLabelDef *ret;

    ret = g_new0(virSecurityDeviceLabelDef, 1);

    ret->relabel = src->relabel;
    ret->labelskip = src->labelskip;

    ret->model = g_strdup(src->model);
    ret->label = g_strdup(src->label);

    return ret;
}
