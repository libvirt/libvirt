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

#include "virlog.h"
#include "virerror.h"
#include "virtime.h"
#include "virsystemd.h"
#include "virinitctl.h"
#include "domain_driver.h"

#define VIR_FROM_THIS VIR_FROM_LXC

VIR_LOG_INIT("lxc.lxc_domain");


static void *
virLXCDomainObjPrivateAlloc(void *opaque)
{
    virLXCDomainObjPrivate *priv = g_new0(virLXCDomainObjPrivate, 1);

    priv->driver = opaque;

    return priv;
}


static void
virLXCDomainObjPrivateFree(void *data)
{
    virLXCDomainObjPrivate *priv = data;

    virCgroupFree(priv->cgroup);
    g_free(priv);
}



VIR_ENUM_IMPL(virLXCDomainNamespace,
              VIR_LXC_DOMAIN_NAMESPACE_LAST,
              "sharenet",
              "shareipc",
              "shareuts",
);

VIR_ENUM_IMPL(virLXCDomainNamespaceSource,
              VIR_LXC_DOMAIN_NAMESPACE_SOURCE_LAST,
              "none",
              "name",
              "pid",
              "netns",
);

static void
lxcDomainDefNamespaceFree(void *nsdata)
{
    size_t i;
    lxcDomainDef *lxcDef = nsdata;

    if (!lxcDef)
        return;

    for (i = 0; i < VIR_LXC_DOMAIN_NAMESPACE_LAST; i++)
        g_free(lxcDef->ns_val[i]);
    g_free(nsdata);
}

static int
lxcDomainDefNamespaceParse(xmlXPathContextPtr ctxt,
                           void **data)
{
    lxcDomainDef *lxcDef = NULL;
    g_autofree xmlNodePtr *nodes = NULL;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    int n;
    size_t i;
    int ret = -1;

    if ((n = virXPathNodeSet("./lxc:namespace/*", ctxt, &nodes)) < 0)
        return -1;

    if (n == 0)
        return 0;

    lxcDef = g_new0(lxcDomainDef, 1);

    for (i = 0; i < n; i++) {
        g_autofree char *tmp = NULL;
        int feature;

        if ((feature = virLXCDomainNamespaceTypeFromString(
                 (const char *)nodes[i]->name)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported Namespace feature: %1$s"),
                           nodes[i]->name);
            goto cleanup;
        }

        ctxt->node = nodes[i];

        if (!(tmp = virXMLPropString(nodes[i], "type"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("No lxc environment type specified"));
            goto cleanup;
        }
        if ((lxcDef->ns_source[feature] =
             virLXCDomainNamespaceSourceTypeFromString(tmp)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown LXC namespace source '%1$s'"),
                           tmp);
            goto cleanup;
        }

        if (!(lxcDef->ns_val[feature] =
              virXMLPropString(nodes[i], "value"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("No lxc environment type specified"));
            goto cleanup;
        }
    }

    *data = g_steal_pointer(&lxcDef);
    ret = 0;

 cleanup:
    lxcDomainDefNamespaceFree(lxcDef);
    return ret;
}


static int
lxcDomainDefNamespaceFormatXML(virBuffer *buf,
                               void *nsdata)
{
    lxcDomainDef *lxcDef = nsdata;
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


virXMLNamespace virLXCDriverDomainXMLNamespace = {
    .parse = lxcDomainDefNamespaceParse,
    .free = lxcDomainDefNamespaceFree,
    .format = lxcDomainDefNamespaceFormatXML,
    .prefix = "lxc",
    .uri = "http://libvirt.org/schemas/domain/lxc/1.0",
};


static int
virLXCDomainObjPrivateXMLFormat(virBuffer *buf,
                                virDomainObj *vm)
{
    virLXCDomainObjPrivate *priv = vm->privateData;

    virBufferAsprintf(buf, "<init pid='%lld'/>\n",
                      (long long)priv->initpid);

    return 0;
}

static int
virLXCDomainObjPrivateXMLParse(xmlXPathContextPtr ctxt,
                               virDomainObj *vm,
                               virDomainDefParserConfig *config G_GNUC_UNUSED)
{
    virLXCDomainObjPrivate *priv = vm->privateData;
    long long thepid;

    if (virXPathLongLong("string(./init[1]/@pid)", ctxt, &thepid) < 0) {
        VIR_WARN("Failed to load init pid from state %s",
                 virGetLastErrorMessage());
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
virLXCDomainDefPostParse(virDomainDef *def,
                         unsigned int parseFlags G_GNUC_UNUSED,
                         void *opaque,
                         void *parseOpaque G_GNUC_UNUSED)
{
    virLXCDriver *driver = opaque;
    g_autoptr(virCaps) caps = virLXCDriverGetCapabilities(driver, false);
    if (!caps)
        return -1;
    if (!virCapabilitiesDomainSupported(caps, def->os.type,
                                        def->os.arch,
                                        def->virtType))
        return -1;

    /* check for emulator and create a default one if needed */
    if (!def->emulator &&
        !(def->emulator = virDomainDefGetDefaultEmulator(def, caps)))
        return -1;

    return 0;
}


static int
virLXCDomainDeviceDefPostParse(virDomainDeviceDef *dev,
                               const virDomainDef *def G_GNUC_UNUSED,
                               unsigned int parseFlags G_GNUC_UNUSED,
                               void *opaque G_GNUC_UNUSED,
                               void *parseOpaque G_GNUC_UNUSED)
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


char *
virLXCDomainGetMachineName(virDomainDef *def, pid_t pid)
{
    char *ret = NULL;

    if (pid) {
        ret = virSystemdGetMachineNameByPID(pid);
        if (!ret)
            virResetLastError();
    }

    if (!ret)
        ret = virDomainDriverGenerateMachineName("lxc", NULL, def->id, def->name, true);

    return ret;
}


typedef struct _lxcDomainInitctlCallbackData lxcDomainInitctlCallbackData;
struct _lxcDomainInitctlCallbackData {
    int runlevel;
    bool *st_valid;
    struct stat *st;
};


static int
lxcDomainInitctlCallback(pid_t pid G_GNUC_UNUSED,
                         void *opaque)
{
    lxcDomainInitctlCallbackData *data = opaque;
    size_t i;

    for (i = 0; virInitctlFifos[i]; i++) {
        const char *fifo = virInitctlFifos[i];
        struct stat cont_sb;

        if (stat(fifo, &cont_sb) < 0) {
            if (errno == ENOENT)
                continue;

            virReportSystemError(errno, _("Unable to stat %1$s"), fifo);
            return -1;
        }

        /* Check if the init fifo is not the very one that's on
         * the host. We don't want to change the host's runlevel.
         */
        if (data->st_valid[i] &&
            data->st[i].st_dev == cont_sb.st_dev &&
            data->st[i].st_ino == cont_sb.st_ino)
            continue;

        return virInitctlSetRunLevel(fifo, data->runlevel);
    }

    /* If no usable fifo was found then declare success. Caller
     * will try killing the domain with signal. */
    return 0;
}


int
virLXCDomainSetRunlevel(virDomainObj *vm,
                        int runlevel)
{
    virLXCDomainObjPrivate *priv = vm->privateData;
    lxcDomainInitctlCallbackData data = { 0 };
    size_t nfifos = 0;
    size_t i;
    int ret = -1;

    data.runlevel = runlevel;

    for (nfifos = 0; virInitctlFifos[nfifos]; nfifos++)
        ;

    data.st = g_new0(struct stat, nfifos);
    data.st_valid = g_new0(bool, nfifos);

    for (i = 0; virInitctlFifos[i]; i++) {
        const char *fifo = virInitctlFifos[i];

        if (stat(fifo, &(data.st[i])) < 0) {
            if (errno == ENOENT)
                continue;

            virReportSystemError(errno, _("Unable to stat %1$s"), fifo);
            goto cleanup;
        }

        data.st_valid[i] = true;
    }

    ret = virProcessRunInMountNamespace(priv->initpid,
                                        lxcDomainInitctlCallback,
                                        &data);
 cleanup:
    g_clear_pointer(&data.st, g_free);
    g_clear_pointer(&data.st_valid, g_free);
    return ret;
}
