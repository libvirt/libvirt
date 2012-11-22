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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include "lxc_domain.h"

#include "memory.h"
#include "logging.h"
#include "virterror_internal.h"

#define VIR_FROM_THIS VIR_FROM_LXC

static void *virLXCDomainObjPrivateAlloc(void)
{
    virLXCDomainObjPrivatePtr priv;

    if (VIR_ALLOC(priv) < 0)
        return NULL;

    return priv;
}

static void virLXCDomainObjPrivateFree(void *data)
{
    virLXCDomainObjPrivatePtr priv = data;

    VIR_FREE(priv);
}


static int virLXCDomainObjPrivateXMLFormat(virBufferPtr buf, void *data)
{
    virLXCDomainObjPrivatePtr priv = data;

    virBufferAsprintf(buf, "  <init pid='%llu'/>\n",
                      (unsigned long long)priv->initpid);

    return 0;
}

static int virLXCDomainObjPrivateXMLParse(xmlXPathContextPtr ctxt, void *data)
{
    virLXCDomainObjPrivatePtr priv = data;
    unsigned long long thepid;

    if (virXPathULongLong("string(./init[1]/@pid)", ctxt, &thepid) < 0) {
        virErrorPtr err = virGetLastError();
        VIR_WARN("Failed to load init pid from state %s", err ? err->message : "null");
        priv->initpid = 0;
    } else {
        priv->initpid = thepid;
    }

    return 0;
}

void virLXCDomainSetPrivateDataHooks(virCapsPtr caps)
{
    caps->privateDataAllocFunc = virLXCDomainObjPrivateAlloc;
    caps->privateDataFreeFunc = virLXCDomainObjPrivateFree;
    caps->privateDataXMLFormat = virLXCDomainObjPrivateXMLFormat;
    caps->privateDataXMLParse = virLXCDomainObjPrivateXMLParse;
}
