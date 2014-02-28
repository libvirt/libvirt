/*
 * Copyright (C) 2010-2014 Red Hat, Inc.
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

#include "viralloc.h"
#include "virlog.h"
#include "virerror.h"

#define VIR_FROM_THIS VIR_FROM_LXC

VIR_LOG_INIT("lxc.lxc_domain");

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

    virCgroupFree(&priv->cgroup);

    VIR_FREE(priv);
}


static int virLXCDomainObjPrivateXMLFormat(virBufferPtr buf, void *data)
{
    virLXCDomainObjPrivatePtr priv = data;

    virBufferAsprintf(buf, "<init pid='%llu'/>\n",
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

virDomainXMLPrivateDataCallbacks virLXCDriverPrivateDataCallbacks = {
    .alloc = virLXCDomainObjPrivateAlloc,
    .free = virLXCDomainObjPrivateFree,
    .format = virLXCDomainObjPrivateXMLFormat,
    .parse  = virLXCDomainObjPrivateXMLParse,
};

static int
virLXCDomainDefPostParse(virDomainDefPtr def,
                         virCapsPtr caps,
                         void *opaque ATTRIBUTE_UNUSED)
{
    /* check for emulator and create a default one if needed */
    if (!def->emulator &&
        !(def->emulator = virDomainDefGetDefaultEmulator(def, caps)))
        return -1;

    return 0;
}


static int
virLXCDomainDeviceDefPostParse(virDomainDeviceDefPtr dev,
                               const virDomainDef *def ATTRIBUTE_UNUSED,
                               virCapsPtr caps ATTRIBUTE_UNUSED,
                               void *opaque ATTRIBUTE_UNUSED)
{
    if (dev->type == VIR_DOMAIN_DEVICE_CHR &&
        dev->data.chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
        dev->data.chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_NONE)
        dev->data.chr->targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_LXC;

    return 0;
}


virDomainDefParserConfig virLXCDriverDomainDefParserConfig = {
    .domainPostParseCallback = virLXCDomainDefPostParse,
    .devicesPostParseCallback = virLXCDomainDeviceDefPostParse,
};
