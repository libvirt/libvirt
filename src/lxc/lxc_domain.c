/*
 * Copyright (C) 2010-2012 Red Hat, Inc.
 * Copyright IBM Corp. 2008
 *
 * lxc_domain.h: LXC domain helpers
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include "lxc_domain.h"

#include "memory.h"

static void *lxcDomainObjPrivateAlloc(void)
{
    lxcDomainObjPrivatePtr priv;

    if (VIR_ALLOC(priv) < 0)
        return NULL;

    priv->monitor = -1;
    priv->monitorWatch = -1;

    return priv;
}

static void lxcDomainObjPrivateFree(void *data)
{
    lxcDomainObjPrivatePtr priv = data;

    VIR_FREE(priv);
}


void lxcDomainSetPrivateDataHooks(virCapsPtr caps)
{
    caps->privateDataAllocFunc = lxcDomainObjPrivateAlloc;
    caps->privateDataFreeFunc = lxcDomainObjPrivateFree;
}
