/*
 * cpu_conf.c: CPU XML handling
 *
 * Copyright (C) 2009-2015 Red Hat, Inc.
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
 * Authors:
 *      Jiri Denemark <jdenemar@redhat.com>
 */

#include <config.h>

#include "virerror.h"
#include "viralloc.h"
#include "virbuffer.h"
#include "cpu_conf.h"
#include "domain_conf.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_CPU

VIR_ENUM_IMPL(virCPU, VIR_CPU_TYPE_LAST,
              "host", "guest", "auto")

VIR_ENUM_IMPL(virCPUMode, VIR_CPU_MODE_LAST,
              "custom",
              "host-model",
              "host-passthrough")

VIR_ENUM_IMPL(virCPUMatch, VIR_CPU_MATCH_LAST,
              "minimum",
              "exact",
              "strict")

VIR_ENUM_IMPL(virCPUCheck, VIR_CPU_CHECK_LAST,
              "default",
              "none",
              "partial",
              "full")

VIR_ENUM_IMPL(virCPUFallback, VIR_CPU_FALLBACK_LAST,
              "allow",
              "forbid")

VIR_ENUM_IMPL(virCPUFeaturePolicy, VIR_CPU_FEATURE_LAST,
              "force",
              "require",
              "optional",
              "disable",
              "forbid")

void
virCPUDefFreeFeatures(virCPUDefPtr def)
{
    size_t i;

    for (i = 0; i < def->nfeatures; i++)
        VIR_FREE(def->features[i].name);
    VIR_FREE(def->features);

    def->nfeatures = def->nfeatures_max = 0;
}


void ATTRIBUTE_NONNULL(1)
virCPUDefFreeModel(virCPUDefPtr def)
{

    VIR_FREE(def->model);
    VIR_FREE(def->vendor);
    VIR_FREE(def->vendor_id);
    virCPUDefFreeFeatures(def);
}

void
virCPUDefFree(virCPUDefPtr def)
{
    if (!def)
        return;

    virCPUDefFreeModel(def);
    VIR_FREE(def);
}


int ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
virCPUDefCopyModel(virCPUDefPtr dst,
                   const virCPUDef *src,
                   bool resetPolicy)
{
    return virCPUDefCopyModelFilter(dst, src, resetPolicy, NULL, NULL);
}


int
virCPUDefCopyModelFilter(virCPUDefPtr dst,
                         const virCPUDef *src,
                         bool resetPolicy,
                         virCPUDefFeatureFilter filter,
                         void *opaque)
{
    size_t i;
    size_t n;

    if (VIR_STRDUP(dst->model, src->model) < 0 ||
        VIR_STRDUP(dst->vendor, src->vendor) < 0 ||
        VIR_STRDUP(dst->vendor_id, src->vendor_id) < 0 ||
        VIR_ALLOC_N(dst->features, src->nfeatures) < 0)
        return -1;
    dst->nfeatures_max = src->nfeatures;
    dst->nfeatures = 0;

    for (i = 0; i < src->nfeatures; i++) {
        if (filter && !filter(src->features[i].name, opaque))
            continue;

        n = dst->nfeatures++;
        if (dst->type != src->type && resetPolicy) {
            if (dst->type == VIR_CPU_TYPE_HOST)
                dst->features[n].policy = -1;
            else if (src->features[i].policy == -1)
                dst->features[n].policy = VIR_CPU_FEATURE_REQUIRE;
            else
                dst->features[n].policy = src->features[i].policy;
        } else {
            dst->features[n].policy = src->features[i].policy;
        }

        if (VIR_STRDUP(dst->features[n].name, src->features[i].name) < 0)
            return -1;
    }

    return 0;
}


/**
 * virCPUDefStealModel:
 *
 * Move CPU model related parts virCPUDef from @src to @dst. If @keepVendor
 * is true, the function keeps the original vendor/vendor_id in @dst rather
 * than overwriting it with the values from @src.
 */
void
virCPUDefStealModel(virCPUDefPtr dst,
                    virCPUDefPtr src,
                    bool keepVendor)
{
    char *vendor = NULL;
    char *vendor_id = NULL;

    if (keepVendor) {
        VIR_STEAL_PTR(vendor, dst->vendor);
        VIR_STEAL_PTR(vendor_id, dst->vendor_id);
    }

    virCPUDefFreeModel(dst);

    VIR_STEAL_PTR(dst->model, src->model);
    VIR_STEAL_PTR(dst->features, src->features);
    dst->nfeatures_max = src->nfeatures_max;
    src->nfeatures_max = 0;
    dst->nfeatures = src->nfeatures;
    src->nfeatures = 0;

    if (keepVendor) {
        dst->vendor = vendor;
        dst->vendor_id = vendor_id;
    } else {
        VIR_STEAL_PTR(dst->vendor, src->vendor);
        VIR_STEAL_PTR(dst->vendor_id, src->vendor_id);
    }
}


virCPUDefPtr
virCPUDefCopyWithoutModel(const virCPUDef *cpu)
{
    virCPUDefPtr copy;

    if (!cpu || VIR_ALLOC(copy) < 0)
        return NULL;

    copy->type = cpu->type;
    copy->mode = cpu->mode;
    copy->match = cpu->match;
    copy->check = cpu->check;
    copy->fallback = cpu->fallback;
    copy->sockets = cpu->sockets;
    copy->cores = cpu->cores;
    copy->threads = cpu->threads;
    copy->arch = cpu->arch;

    return copy;
}


virCPUDefPtr
virCPUDefCopy(const virCPUDef *cpu)
{
    virCPUDefPtr copy;

    if (!(copy = virCPUDefCopyWithoutModel(cpu)))
        return NULL;

    if (virCPUDefCopyModel(copy, cpu, false) < 0)
        goto error;

    return copy;

 error:
    virCPUDefFree(copy);
    return NULL;
}


virCPUDefPtr
virCPUDefParseXML(xmlNodePtr node,
                  xmlXPathContextPtr ctxt,
                  virCPUType mode)
{
    virCPUDefPtr def;
    xmlNodePtr *nodes = NULL;
    xmlNodePtr oldnode = ctxt->node;
    int n;
    size_t i;
    char *cpuMode;
    char *fallback = NULL;
    char *vendor_id = NULL;

    if (!xmlStrEqual(node->name, BAD_CAST "cpu")) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("XML does not contain expected 'cpu' element"));
        return NULL;
    }

    if (VIR_ALLOC(def) < 0)
        return NULL;

    if (mode == VIR_CPU_TYPE_AUTO) {
        if (virXPathBoolean("boolean(./arch)", ctxt)) {
            if (virXPathBoolean("boolean(./@match)", ctxt)) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("'arch' element cannot be used inside 'cpu'"
                                 " element with 'match' attribute'"));
                goto error;
            }
            def->type = VIR_CPU_TYPE_HOST;
        } else {
            def->type = VIR_CPU_TYPE_GUEST;
        }
    } else {
        def->type = mode;
    }

    if ((cpuMode = virXMLPropString(node, "mode"))) {
        if (def->type == VIR_CPU_TYPE_HOST) {
            VIR_FREE(cpuMode);
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Attribute mode is only allowed for guest CPU"));
            goto error;
        } else {
            def->mode = virCPUModeTypeFromString(cpuMode);

            if (def->mode < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Invalid mode attribute '%s'"),
                               cpuMode);
                VIR_FREE(cpuMode);
                goto error;
            }
            VIR_FREE(cpuMode);
        }
    } else {
        if (def->type == VIR_CPU_TYPE_HOST)
            def->mode = -1;
        else
            def->mode = VIR_CPU_MODE_CUSTOM;
    }

    if (def->type == VIR_CPU_TYPE_GUEST) {
        char *match = virXMLPropString(node, "match");
        char *check;

        if (!match) {
            if (virXPathBoolean("boolean(./model)", ctxt))
                def->match = VIR_CPU_MATCH_EXACT;
            else
                def->match = -1;
        } else {
            def->match = virCPUMatchTypeFromString(match);
            VIR_FREE(match);

            if (def->match < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Invalid match attribute for CPU "
                                 "specification"));
                goto error;
            }
        }

        if ((check = virXMLPropString(node, "check"))) {
            int value = virCPUCheckTypeFromString(check);
            VIR_FREE(check);

            if (value < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Invalid check attribute for CPU "
                                 "specification"));
                goto error;
            }
            def->check = value;
        }
    }

    if (def->type == VIR_CPU_TYPE_HOST) {
        char *arch = virXPathString("string(./arch[1])", ctxt);
        if (!arch) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing CPU architecture"));
            goto error;
        }
        if ((def->arch = virArchFromString(arch)) == VIR_ARCH_NONE) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unknown architecture %s"), arch);
            VIR_FREE(arch);
            goto error;
        }
        VIR_FREE(arch);
    }

    if (!(def->model = virXPathString("string(./model[1])", ctxt)) &&
        def->type == VIR_CPU_TYPE_HOST) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                        _("Missing CPU model name"));
        goto error;
    }

    if (def->type == VIR_CPU_TYPE_GUEST &&
        def->mode != VIR_CPU_MODE_HOST_PASSTHROUGH) {

        if ((fallback = virXPathString("string(./model[1]/@fallback)", ctxt))) {
            if ((def->fallback = virCPUFallbackTypeFromString(fallback)) < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Invalid fallback attribute"));
                goto error;
            }
        }

        if ((vendor_id = virXPathString("string(./model[1]/@vendor_id)",
                                        ctxt))) {
            if (strlen(vendor_id) != VIR_CPU_VENDOR_ID_LENGTH) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("vendor_id must be exactly %d characters long"),
                               VIR_CPU_VENDOR_ID_LENGTH);
                goto error;
            }

            /* ensure that the string can be passed to qemu*/
            if (strchr(vendor_id, ',')) {
                    virReportError(VIR_ERR_XML_ERROR, "%s",
                                   _("vendor id is invalid"));
                    goto error;
            }

            def->vendor_id = vendor_id;
            vendor_id = NULL;
        }
    }

    def->vendor = virXPathString("string(./vendor[1])", ctxt);
    if (def->vendor && !def->model) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("CPU vendor specified without CPU model"));
        goto error;
    }

    if (virXPathNode("./topology[1]", ctxt)) {
        int ret;
        unsigned long ul;

        ret = virXPathULong("string(./topology[1]/@sockets)",
                            ctxt, &ul);
        if (ret < 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing 'sockets' attribute in CPU topology"));
            goto error;
        }
        def->sockets = (unsigned int) ul;

        ret = virXPathULong("string(./topology[1]/@cores)",
                            ctxt, &ul);
        if (ret < 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing 'cores' attribute in CPU topology"));
            goto error;
        }
        def->cores = (unsigned int) ul;

        ret = virXPathULong("string(./topology[1]/@threads)",
                            ctxt, &ul);
        if (ret < 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing 'threads' attribute in CPU topology"));
            goto error;
        }
        def->threads = (unsigned int) ul;

        if (!def->sockets || !def->cores || !def->threads) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Invalid CPU topology"));
            goto error;
        }
    }

    if ((n = virXPathNodeSet("./feature", ctxt, &nodes)) < 0)
        goto error;

    if (n > 0) {
        if (!def->model && def->mode == VIR_CPU_MODE_CUSTOM) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Non-empty feature list specified without "
                             "CPU model"));
            goto error;
        }

        if (VIR_RESIZE_N(def->features, def->nfeatures_max,
                         def->nfeatures, n) < 0)
            goto error;

        def->nfeatures = n;
    }

    for (i = 0; i < n; i++) {
        char *name;
        int policy; /* enum virDomainCPUFeaturePolicy */
        size_t j;

        if (def->type == VIR_CPU_TYPE_GUEST) {
            char *strpolicy;

            strpolicy = virXMLPropString(nodes[i], "policy");
            if (strpolicy == NULL)
                policy = VIR_CPU_FEATURE_REQUIRE;
            else
                policy = virCPUFeaturePolicyTypeFromString(strpolicy);
            VIR_FREE(strpolicy);

            if (policy < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Invalid CPU feature policy"));
                goto error;
            }
        } else {
            policy = -1;
        }

        if (!(name = virXMLPropString(nodes[i], "name")) || *name == 0) {
            VIR_FREE(name);
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Invalid CPU feature name"));
            goto error;
        }

        for (j = 0; j < i; j++) {
            if (STREQ(name, def->features[j].name)) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("CPU feature '%s' specified more than once"),
                               name);
                VIR_FREE(name);
                goto error;
            }
        }

        def->features[i].name = name;
        def->features[i].policy = policy;
    }

 cleanup:
    ctxt->node = oldnode;
    VIR_FREE(fallback);
    VIR_FREE(vendor_id);
    VIR_FREE(nodes);
    return def;

 error:
    virCPUDefFree(def);
    def = NULL;
    goto cleanup;
}


char *
virCPUDefFormat(virCPUDefPtr def,
                virDomainNumaPtr numa,
                bool updateCPU)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (virCPUDefFormatBufFull(&buf, def, numa, updateCPU) < 0)
        goto cleanup;

    if (virBufferCheckError(&buf) < 0)
        goto cleanup;

    return virBufferContentAndReset(&buf);

 cleanup:
    virBufferFreeAndReset(&buf);
    return NULL;
}


int
virCPUDefFormatBufFull(virBufferPtr buf,
                       virCPUDefPtr def,
                       virDomainNumaPtr numa,
                       bool updateCPU)
{
    int ret = -1;
    virBuffer attributeBuf = VIR_BUFFER_INITIALIZER;
    virBuffer childrenBuf = VIR_BUFFER_INITIALIZER;
    int indent = virBufferGetIndent(buf, false);

    if (!def)
        return 0;

    /* Format attributes */
    if (def->type == VIR_CPU_TYPE_GUEST) {
        const char *tmp;

        if (def->mode != VIR_CPU_MODE_CUSTOM || def->model) {
            if (!(tmp = virCPUModeTypeToString(def->mode))) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unexpected CPU mode %d"), def->mode);
                goto cleanup;
            }
            virBufferAsprintf(&attributeBuf, " mode='%s'", tmp);
        }

        if (def->model &&
            (def->mode == VIR_CPU_MODE_CUSTOM ||
             updateCPU)) {
            if (!(tmp = virCPUMatchTypeToString(def->match))) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unexpected CPU match policy %d"),
                               def->match);
                goto cleanup;
            }
            virBufferAsprintf(&attributeBuf, " match='%s'", tmp);
        }

        if (def->check) {
            virBufferAsprintf(&attributeBuf, " check='%s'",
                              virCPUCheckTypeToString(def->check));
        }
    }

    /* Format children */
    virBufferAdjustIndent(&childrenBuf, indent + 2);
    if (def->type == VIR_CPU_TYPE_HOST && def->arch)
        virBufferAsprintf(&childrenBuf, "<arch>%s</arch>\n",
                          virArchToString(def->arch));
    if (virCPUDefFormatBuf(&childrenBuf, def, updateCPU) < 0)
        goto cleanup;

    if (virDomainNumaDefCPUFormat(&childrenBuf, numa) < 0)
        goto cleanup;

    /* Put it all together */
    if (virBufferUse(&attributeBuf) || virBufferUse(&childrenBuf)) {
        virBufferAddLit(buf, "<cpu");

        if (virBufferUse(&attributeBuf))
            virBufferAddBuffer(buf, &attributeBuf);

        if (virBufferUse(&childrenBuf)) {
            virBufferAddLit(buf, ">\n");
            virBufferAddBuffer(buf, &childrenBuf);
            virBufferAddLit(buf, "</cpu>\n");
        } else {
            virBufferAddLit(buf, "/>\n");
        }
    }

    ret = 0;
 cleanup:
    virBufferFreeAndReset(&attributeBuf);
    virBufferFreeAndReset(&childrenBuf);
    return ret;
}

int
virCPUDefFormatBuf(virBufferPtr buf,
                   virCPUDefPtr def,
                   bool updateCPU)
{
    size_t i;
    bool formatModel;
    bool formatFallback;

    if (!def)
        return 0;

    formatModel = (def->mode == VIR_CPU_MODE_CUSTOM ||
                   def->mode == VIR_CPU_MODE_HOST_MODEL ||
                   updateCPU);
    formatFallback = (def->type == VIR_CPU_TYPE_GUEST &&
                      (def->mode == VIR_CPU_MODE_HOST_MODEL ||
                       (def->mode == VIR_CPU_MODE_CUSTOM && def->model)));

    if (!def->model && def->mode == VIR_CPU_MODE_CUSTOM && def->nfeatures) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Non-empty feature list specified without CPU model"));
        return -1;
    }

    if ((formatModel && def->model) || formatFallback) {
        virBufferAddLit(buf, "<model");
        if (formatFallback) {
            const char *fallback;

            fallback = virCPUFallbackTypeToString(def->fallback);
            if (!fallback) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unexpected CPU fallback value: %d"),
                               def->fallback);
                return -1;
            }
            virBufferAsprintf(buf, " fallback='%s'", fallback);
            if (def->vendor_id)
                virBufferEscapeString(buf, " vendor_id='%s'", def->vendor_id);
        }
        if (formatModel && def->model) {
            virBufferEscapeString(buf, ">%s</model>\n", def->model);
        } else {
            virBufferAddLit(buf, "/>\n");
        }
    }

    if (formatModel && def->vendor)
        virBufferEscapeString(buf, "<vendor>%s</vendor>\n", def->vendor);

    if (def->sockets && def->cores && def->threads) {
        virBufferAddLit(buf, "<topology");
        virBufferAsprintf(buf, " sockets='%u'", def->sockets);
        virBufferAsprintf(buf, " cores='%u'", def->cores);
        virBufferAsprintf(buf, " threads='%u'", def->threads);
        virBufferAddLit(buf, "/>\n");
    }

    for (i = 0; i < def->nfeatures; i++) {
        virCPUFeatureDefPtr feature = def->features + i;

        if (!feature->name) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing CPU feature name"));
            return -1;
        }

        if (def->type == VIR_CPU_TYPE_GUEST) {
            const char *policy;

            policy = virCPUFeaturePolicyTypeToString(feature->policy);
            if (!policy) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unexpected CPU feature policy %d"),
                               feature->policy);
                return -1;
            }
            virBufferAsprintf(buf, "<feature policy='%s' name='%s'/>\n",
                              policy, feature->name);
        } else {
            virBufferAsprintf(buf, "<feature name='%s'/>\n",
                              feature->name);
        }
    }

    return 0;
}

static int
virCPUDefUpdateFeatureInternal(virCPUDefPtr def,
                               const char *name,
                               int policy,
                               bool update)
{
    size_t i;

    if (def->type == VIR_CPU_TYPE_HOST)
        policy = -1;

    for (i = 0; i < def->nfeatures; i++) {
        if (STREQ(name, def->features[i].name)) {
            if (update) {
                def->features[i].policy = policy;
                return 0;
            }

            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("CPU feature '%s' specified more than once"),
                           name);

            return -1;
        }
    }

    if (VIR_RESIZE_N(def->features, def->nfeatures_max,
                     def->nfeatures, 1) < 0)
        return -1;

    if (VIR_STRDUP(def->features[def->nfeatures].name, name) < 0)
        return -1;

    def->features[def->nfeatures].policy = policy;
    def->nfeatures++;

    return 0;
}

int
virCPUDefUpdateFeature(virCPUDefPtr def,
                       const char *name,
                       int policy)
{
    return virCPUDefUpdateFeatureInternal(def, name, policy, true);
}

int
virCPUDefAddFeature(virCPUDefPtr def,
                    const char *name,
                    int policy)
{
    return virCPUDefUpdateFeatureInternal(def, name, policy, false);
}

bool
virCPUDefIsEqual(virCPUDefPtr src,
                 virCPUDefPtr dst)
{
    bool identical = false;
    size_t i;

    if (!src && !dst)
        return true;

    if ((src && !dst) || (!src && dst)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target CPU does not match source"));
        goto cleanup;
    }

    if (src->type != dst->type) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target CPU type %s does not match source %s"),
                       virCPUTypeToString(dst->type),
                       virCPUTypeToString(src->type));
        goto cleanup;
    }

    if (src->mode != dst->mode) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target CPU mode %s does not match source %s"),
                       virCPUModeTypeToString(dst->mode),
                       virCPUModeTypeToString(src->mode));
        goto cleanup;
    }

    if (src->arch != dst->arch) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target CPU arch %s does not match source %s"),
                       virArchToString(dst->arch),
                       virArchToString(src->arch));
        goto cleanup;
    }

    if (STRNEQ_NULLABLE(src->model, dst->model)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target CPU model %s does not match source %s"),
                       NULLSTR(dst->model), NULLSTR(src->model));
        goto cleanup;
    }

    if (STRNEQ_NULLABLE(src->vendor, dst->vendor)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target CPU vendor %s does not match source %s"),
                       NULLSTR(dst->vendor), NULLSTR(src->vendor));
        goto cleanup;
    }

    if (STRNEQ_NULLABLE(src->vendor_id, dst->vendor_id)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target CPU vendor id %s does not match source %s"),
                       NULLSTR(dst->vendor_id), NULLSTR(src->vendor_id));
        goto cleanup;
    }

    if (src->sockets != dst->sockets) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target CPU sockets %d does not match source %d"),
                       dst->sockets, src->sockets);
        goto cleanup;
    }

    if (src->cores != dst->cores) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target CPU cores %d does not match source %d"),
                       dst->cores, src->cores);
        goto cleanup;
    }

    if (src->threads != dst->threads) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target CPU threads %d does not match source %d"),
                       dst->threads, src->threads);
        goto cleanup;
    }

    if (src->nfeatures != dst->nfeatures) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target CPU feature count %zu does not match source %zu"),
                       dst->nfeatures, src->nfeatures);
        goto cleanup;
    }

    for (i = 0; i < src->nfeatures; i++) {
        if (STRNEQ(src->features[i].name, dst->features[i].name)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target CPU feature %s does not match source %s"),
                           dst->features[i].name, src->features[i].name);
            goto cleanup;
        }

        if (src->features[i].policy != dst->features[i].policy) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target CPU feature policy %s does not match source %s"),
                           virCPUFeaturePolicyTypeToString(dst->features[i].policy),
                           virCPUFeaturePolicyTypeToString(src->features[i].policy));
            goto cleanup;
        }
    }

    identical = true;

 cleanup:
    return identical;
}
