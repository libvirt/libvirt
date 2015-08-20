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
#include <libxml/xpathInternals.h>
#include "virstring.h"
#include "virutil.h"
#include "virfile.h"

#define VIR_FROM_THIS VIR_FROM_LXC
#define LXC_NAMESPACE_HREF "http://libvirt.org/schemas/domain/lxc/1.0"

VIR_LOG_INIT("lxc.lxc_domain");

static void *virLXCDomainObjPrivateAlloc(void)
{
    virLXCDomainObjPrivatePtr priv;

    if (VIR_ALLOC(priv) < 0)
        return NULL;

    return priv;
}

VIR_ENUM_IMPL(virLXCDomainNamespace,
              VIR_LXC_DOMAIN_NAMESPACE_LAST,
              "sharenet",
              "shareipc",
              "shareuts")

VIR_ENUM_IMPL(virLXCDomainNamespaceSource,
              VIR_LXC_DOMAIN_NAMESPACE_SOURCE_LAST,
              "none",
              "name",
              "pid",
              "netns")

static void
lxcDomainDefNamespaceFree(void *nsdata)
{
    size_t i;
    lxcDomainDefPtr lxcDef = nsdata;
    for (i = 0; i < VIR_LXC_DOMAIN_NAMESPACE_LAST; i++)
        VIR_FREE(lxcDef->ns_val[i]);
    VIR_FREE(nsdata);
}

static int
lxcDomainDefNamespaceParse(xmlDocPtr xml ATTRIBUTE_UNUSED,
                           xmlNodePtr root ATTRIBUTE_UNUSED,
                           xmlXPathContextPtr ctxt,
                           void **data)
{
    lxcDomainDefPtr lxcDef = NULL;
    xmlNodePtr *nodes = NULL;
    bool uses_lxc_ns = false;
    xmlNodePtr node;
    int feature;
    int n;
    char *tmp = NULL;
    size_t i;

    if (xmlXPathRegisterNs(ctxt, BAD_CAST "lxc", BAD_CAST LXC_NAMESPACE_HREF) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to register xml namespace '%s'"),
                       LXC_NAMESPACE_HREF);
        return -1;
    }

    if (VIR_ALLOC(lxcDef) < 0)
        return -1;

    node = ctxt->node;
    if ((n = virXPathNodeSet("./lxc:namespace/*", ctxt, &nodes)) < 0)
        goto error;
    uses_lxc_ns |= n > 0;

    for (i = 0; i < n; i++) {
        if ((feature = virLXCDomainNamespaceTypeFromString(
                 (const char *) nodes[i]->name)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                            _("unsupported Namespace feature: %s"),
                            nodes[i]->name);
            goto error;
        }

        ctxt->node = nodes[i];

        if (!(tmp = virXMLPropString(nodes[i], "type"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("No lxc environment type specified"));
            goto error;
        }
        if ((lxcDef->ns_source[feature] =
             virLXCDomainNamespaceSourceTypeFromString(tmp)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown LXC namespace source '%s'"),
                           tmp);
            VIR_FREE(tmp);
            goto error;
        }
        VIR_FREE(tmp);

        if (!(lxcDef->ns_val[feature] =
              virXMLPropString(nodes[i], "value"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("No lxc environment type specified"));
            goto error;
        }
    }
    VIR_FREE(nodes);
    ctxt->node = node;
    if (uses_lxc_ns)
        *data = lxcDef;
    else
        VIR_FREE(lxcDef);
    return 0;
 error:
    VIR_FREE(nodes);
    lxcDomainDefNamespaceFree(lxcDef);
    return -1;
}


static int
lxcDomainDefNamespaceFormatXML(virBufferPtr buf,
                               void *nsdata)
{
    lxcDomainDefPtr lxcDef = nsdata;
    size_t i;

    if (!lxcDef)
       return 0;

    virBufferAddLit(buf, "<lxc:namespace>\n");
    virBufferAdjustIndent(buf, 2);

    for (i = 0; i < VIR_LXC_DOMAIN_NAMESPACE_LAST; i++) {
        if (lxcDef->ns_source[i] == VIR_LXC_DOMAIN_NAMESPACE_SOURCE_NONE)
            continue;

        virBufferAsprintf(buf, "<lxc:%s type='%s' value='%s'/>\n",
                          virLXCDomainNamespaceTypeToString(i),
                          virLXCDomainNamespaceSourceTypeToString(
                              lxcDef->ns_source[i]),
                          lxcDef->ns_val[i]);
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</lxc:namespace>\n");
    return 0;
}

static const char *
lxcDomainDefNamespaceHref(void)
{
    return "xmlns:lxc='" LXC_NAMESPACE_HREF "'";
}


virDomainXMLNamespace virLXCDriverDomainXMLNamespace = {
    .parse = lxcDomainDefNamespaceParse,
    .free = lxcDomainDefNamespaceFree,
    .format = lxcDomainDefNamespaceFormatXML,
    .href = lxcDomainDefNamespaceHref,
};


static void virLXCDomainObjPrivateFree(void *data)
{
    virLXCDomainObjPrivatePtr priv = data;

    virCgroupFree(&priv->cgroup);

    VIR_FREE(priv);
}


static int
virLXCDomainObjPrivateXMLFormat(virBufferPtr buf,
                                virDomainObjPtr vm)
{
    virLXCDomainObjPrivatePtr priv = vm->privateData;

    virBufferAsprintf(buf, "<init pid='%llu'/>\n",
                      (unsigned long long)priv->initpid);

    return 0;
}

static int
virLXCDomainObjPrivateXMLParse(xmlXPathContextPtr ctxt,
                               virDomainObjPtr vm,
                               virDomainDefParserConfigPtr config ATTRIBUTE_UNUSED)
{
    virLXCDomainObjPrivatePtr priv = vm->privateData;
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

    /* memory hotplug tunables are not supported by this driver */
    if (virDomainDefCheckUnsupportedMemoryHotplug(def) < 0)
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


    if (virDomainDeviceDefCheckUnsupportedMemoryDevice(dev) < 0)
        return -1;

    return 0;
}


virDomainDefParserConfig virLXCDriverDomainDefParserConfig = {
    .domainPostParseCallback = virLXCDomainDefPostParse,
    .devicesPostParseCallback = virLXCDomainDeviceDefPostParse,
};
