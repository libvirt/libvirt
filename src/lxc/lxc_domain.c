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
#include "virtime.h"
#include "virsystemd.h"
#include "virinitctl.h"

#define VIR_FROM_THIS VIR_FROM_LXC
#define LXC_NAMESPACE_HREF "http://libvirt.org/schemas/domain/lxc/1.0"

VIR_ENUM_IMPL(virLXCDomainJob,
              LXC_JOB_LAST,
              "none",
              "query",
              "destroy",
              "modify",
);

VIR_LOG_INIT("lxc.lxc_domain");

static int
virLXCDomainObjInitJob(virLXCDomainObjPrivatePtr priv)
{
    memset(&priv->job, 0, sizeof(priv->job));

    if (virCondInit(&priv->job.cond) < 0)
        return -1;

    return 0;
}

static void
virLXCDomainObjResetJob(virLXCDomainObjPrivatePtr priv)
{
    struct virLXCDomainJobObj *job = &priv->job;

    job->active = LXC_JOB_NONE;
    job->owner = 0;
}

static void
virLXCDomainObjFreeJob(virLXCDomainObjPrivatePtr priv)
{
    ignore_value(virCondDestroy(&priv->job.cond));
}

/* Give up waiting for mutex after 30 seconds */
#define LXC_JOB_WAIT_TIME (1000ull * 30)

/*
 * obj must be locked before calling, virLXCDriverPtr must NOT be locked
 *
 * This must be called by anything that will change the VM state
 * in any way
 *
 * Upon successful return, the object will have its ref count increased.
 * Successful calls must be followed by EndJob eventually.
 */
int
virLXCDomainObjBeginJob(virLXCDriverPtr driver ATTRIBUTE_UNUSED,
                       virDomainObjPtr obj,
                       enum virLXCDomainJob job)
{
    virLXCDomainObjPrivatePtr priv = obj->privateData;
    unsigned long long now;
    unsigned long long then;

    if (virTimeMillisNow(&now) < 0)
        return -1;
    then = now + LXC_JOB_WAIT_TIME;

    while (priv->job.active) {
        VIR_DEBUG("Wait normal job condition for starting job: %s",
                  virLXCDomainJobTypeToString(job));
        if (virCondWaitUntil(&priv->job.cond, &obj->parent.lock, then) < 0)
            goto error;
    }

    virLXCDomainObjResetJob(priv);

    VIR_DEBUG("Starting job: %s", virLXCDomainJobTypeToString(job));
    priv->job.active = job;
    priv->job.owner = virThreadSelfID();

    return 0;

 error:
    VIR_WARN("Cannot start job (%s) for domain %s;"
             " current job is (%s) owned by (%d)",
             virLXCDomainJobTypeToString(job),
             obj->def->name,
             virLXCDomainJobTypeToString(priv->job.active),
             priv->job.owner);

    if (errno == ETIMEDOUT)
        virReportError(VIR_ERR_OPERATION_TIMEOUT,
                       "%s", _("cannot acquire state change lock"));
    else
        virReportSystemError(errno,
                             "%s", _("cannot acquire job mutex"));
    return -1;
}


/*
 * obj must be locked and have a reference before calling
 *
 * To be called after completing the work associated with the
 * earlier virLXCDomainBeginJob() call
 */
void
virLXCDomainObjEndJob(virLXCDriverPtr driver ATTRIBUTE_UNUSED,
                     virDomainObjPtr obj)
{
    virLXCDomainObjPrivatePtr priv = obj->privateData;
    enum virLXCDomainJob job = priv->job.active;

    VIR_DEBUG("Stopping job: %s",
              virLXCDomainJobTypeToString(job));

    virLXCDomainObjResetJob(priv);
    virCondSignal(&priv->job.cond);
}


static void *
virLXCDomainObjPrivateAlloc(void *opaque ATTRIBUTE_UNUSED)
{
    virLXCDomainObjPrivatePtr priv;

    if (VIR_ALLOC(priv) < 0)
        return NULL;

    if (virLXCDomainObjInitJob(priv) < 0) {
        VIR_FREE(priv);
        return NULL;
    }

    return priv;
}


static void
virLXCDomainObjPrivateFree(void *data)
{
    virLXCDomainObjPrivatePtr priv = data;

    virCgroupFree(&priv->cgroup);
    virLXCDomainObjFreeJob(priv);
    VIR_FREE(priv);
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
    lxcDomainDefPtr lxcDef = nsdata;
    for (i = 0; i < VIR_LXC_DOMAIN_NAMESPACE_LAST; i++)
        VIR_FREE(lxcDef->ns_val[i]);
    VIR_FREE(nsdata);
}

static int
lxcDomainDefNamespaceParse(xmlXPathContextPtr ctxt,
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
                 (const char *)nodes[i]->name)) < 0) {
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


virXMLNamespace virLXCDriverDomainXMLNamespace = {
    .parse = lxcDomainDefNamespaceParse,
    .free = lxcDomainDefNamespaceFree,
    .format = lxcDomainDefNamespaceFormatXML,
    .prefix = "lxc",
    .href = lxcDomainDefNamespaceHref,
};


static int
virLXCDomainObjPrivateXMLFormat(virBufferPtr buf,
                                virDomainObjPtr vm)
{
    virLXCDomainObjPrivatePtr priv = vm->privateData;

    virBufferAsprintf(buf, "<init pid='%lld'/>\n",
                      (long long)priv->initpid);

    return 0;
}

static int
virLXCDomainObjPrivateXMLParse(xmlXPathContextPtr ctxt,
                               virDomainObjPtr vm,
                               virDomainDefParserConfigPtr config ATTRIBUTE_UNUSED)
{
    virLXCDomainObjPrivatePtr priv = vm->privateData;
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
virLXCDomainDefPostParse(virDomainDefPtr def,
                         virCapsPtr caps,
                         unsigned int parseFlags ATTRIBUTE_UNUSED,
                         void *opaque ATTRIBUTE_UNUSED,
                         void *parseOpaque ATTRIBUTE_UNUSED)
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
                               unsigned int parseFlags ATTRIBUTE_UNUSED,
                               void *opaque ATTRIBUTE_UNUSED,
                               void *parseOpaque ATTRIBUTE_UNUSED)
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
virLXCDomainGetMachineName(virDomainDefPtr def, pid_t pid)
{
    char *ret = NULL;

    if (pid) {
        ret = virSystemdGetMachineNameByPID(pid);
        if (!ret)
            virResetLastError();
    }

    if (!ret)
        ret = virDomainGenerateMachineName("lxc", def->id, def->name, true);

    return ret;
}


typedef struct _lxcDomainInitctlCallbackData lxcDomainInitctlCallbackData;
struct _lxcDomainInitctlCallbackData {
    int runlevel;
    bool *st_valid;
    struct stat *st;
};


static int
lxcDomainInitctlCallback(pid_t pid ATTRIBUTE_UNUSED,
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

            virReportSystemError(errno, _("Unable to stat %s"), fifo);
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
virLXCDomainSetRunlevel(virDomainObjPtr vm,
                        int runlevel)
{
    virLXCDomainObjPrivatePtr priv = vm->privateData;
    lxcDomainInitctlCallbackData data;
    size_t nfifos = 0;
    size_t i;
    int ret = -1;

    memset(&data, 0, sizeof(data));

    data.runlevel = runlevel;

    for (nfifos = 0; virInitctlFifos[nfifos]; nfifos++)
        ;

    if (VIR_ALLOC_N(data.st, nfifos) < 0 ||
        VIR_ALLOC_N(data.st_valid, nfifos) < 0)
        goto cleanup;

    for (i = 0; virInitctlFifos[i]; i++) {
        const char *fifo = virInitctlFifos[i];

        if (stat(fifo, &(data.st[i])) < 0) {
            if (errno == ENOENT)
                continue;

            virReportSystemError(errno, _("Unable to stat %s"), fifo);
            goto cleanup;
        }

        data.st_valid[i] = true;
    }

    ret = virProcessRunInMountNamespace(priv->initpid,
                                        lxcDomainInitctlCallback,
                                        &data);
 cleanup:
    VIR_FREE(data.st);
    VIR_FREE(data.st_valid);
    return ret;
}
