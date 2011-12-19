/*
 * cpu_conf.h: CPU XML handling
 *
 * Copyright (C) 2009-2011 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Authors:
 *      Jiri Denemark <jdenemar@redhat.com>
 */

#include <config.h>

#include "virterror_internal.h"
#include "memory.h"
#include "util.h"
#include "buf.h"
#include "cpu_conf.h"
#include "domain_conf.h"

#define VIR_FROM_THIS VIR_FROM_CPU

#define virCPUReportError(code, ...)                              \
    virReportErrorHelper(VIR_FROM_CPU, code, __FILE__,            \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

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

VIR_ENUM_IMPL(virCPUFallback, VIR_CPU_FALLBACK_LAST,
              "allow",
              "forbid")

VIR_ENUM_IMPL(virCPUFeaturePolicy, VIR_CPU_FEATURE_LAST,
              "force",
              "require",
              "optional",
              "disable",
              "forbid")


void ATTRIBUTE_NONNULL(1)
virCPUDefFreeModel(virCPUDefPtr def)
{
    unsigned int i;

    VIR_FREE(def->model);
    VIR_FREE(def->vendor);

    for (i = 0; i < def->nfeatures; i++)
        VIR_FREE(def->features[i].name);
    VIR_FREE(def->features);
}

void
virCPUDefFree(virCPUDefPtr def)
{
    unsigned int i;

    if (!def)
        return;

    VIR_FREE(def->arch);
    virCPUDefFreeModel(def);

    for (i = 0 ; i < def->ncells ; i++) {
        VIR_FREE(def->cells[i].cpumask);
        VIR_FREE(def->cells[i].cpustr);
    }
    VIR_FREE(def->cells);

    VIR_FREE(def);
}


int ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
virCPUDefCopyModel(virCPUDefPtr dst,
                   const virCPUDefPtr src,
                   bool resetPolicy)
{
    unsigned int i;

    if ((src->model && !(dst->model = strdup(src->model)))
        || (src->vendor && !(dst->vendor = strdup(src->vendor)))
        || VIR_ALLOC_N(dst->features, src->nfeatures) < 0)
        goto no_memory;
    dst->nfeatures_max = dst->nfeatures = src->nfeatures;

    for (i = 0; i < dst->nfeatures; i++) {
        if (dst->type != src->type && resetPolicy) {
            if (dst->type == VIR_CPU_TYPE_HOST)
                dst->features[i].policy = -1;
            else if (src->features[i].policy == -1)
                dst->features[i].policy = VIR_CPU_FEATURE_REQUIRE;
            else
                dst->features[i].policy = src->features[i].policy;
        } else {
            dst->features[i].policy = src->features[i].policy;
        }

        if (!(dst->features[i].name = strdup(src->features[i].name)))
            goto no_memory;
    }

    return 0;

no_memory:
    virReportOOMError();
    return -1;
}

virCPUDefPtr
virCPUDefCopy(const virCPUDefPtr cpu)
{
    virCPUDefPtr copy;
    unsigned int i;

    if (!cpu)
        return NULL;

    if (VIR_ALLOC(copy) < 0)
        goto no_memory;

    copy->type = cpu->type;
    copy->mode = cpu->mode;
    copy->match = cpu->match;
    copy->fallback = cpu->fallback;
    copy->sockets = cpu->sockets;
    copy->cores = cpu->cores;
    copy->threads = cpu->threads;

    if (cpu->arch && !(copy->arch = strdup(cpu->arch)))
        goto no_memory;

    if (virCPUDefCopyModel(copy, cpu, false) < 0)
        goto error;

    if (cpu->ncells) {
        if (VIR_ALLOC_N(copy->cells, cpu->ncells) < 0)
            goto no_memory;
        copy->ncells_max = copy->ncells = cpu->ncells;

        for (i = 0; i < cpu->ncells; i++) {
            copy->cells[i].cellid = cpu->cells[i].cellid;
            copy->cells[i].mem = cpu->cells[i].mem;

            if (VIR_ALLOC_N(copy->cells[i].cpumask,
                            VIR_DOMAIN_CPUMASK_LEN) < 0)
                goto no_memory;
            memcpy(copy->cells[i].cpumask, cpu->cells[i].cpumask,
                   VIR_DOMAIN_CPUMASK_LEN);

            if (!(copy->cells[i].cpustr = strdup(cpu->cells[i].cpustr)))
                goto no_memory;
        }
        copy->cells_cpus = cpu->cells_cpus;
    }

    return copy;

no_memory:
    virReportOOMError();
error:
    virCPUDefFree(copy);
    return NULL;
}

virCPUDefPtr
virCPUDefParseXML(const xmlNodePtr node,
                  xmlXPathContextPtr ctxt,
                  enum virCPUType mode)
{
    virCPUDefPtr def;
    xmlNodePtr *nodes = NULL;
    int n;
    unsigned int i;
    char *cpuMode;

    if (!xmlStrEqual(node->name, BAD_CAST "cpu")) {
        virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                          "%s",
                          _("XML does not contain expected 'cpu' element"));
        return NULL;
    }

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (mode == VIR_CPU_TYPE_AUTO) {
        if (virXPathBoolean("boolean(./arch)", ctxt)) {
            if (virXPathBoolean("boolean(./@match)", ctxt)) {
                virCPUReportError(VIR_ERR_XML_ERROR, "%s",
                        _("'arch' element element cannot be used inside 'cpu'"
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
            virCPUReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                              _("Attribute mode is only allowed for guest CPU"));
            goto error;
        } else {
            def->mode = virCPUModeTypeFromString(cpuMode);
            VIR_FREE(cpuMode);

            if (def->mode < 0) {
                virCPUReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                  _("Invalid mode attribute"));
                goto error;
            }
        }
    } else {
        if (def->type == VIR_CPU_TYPE_HOST)
            def->mode = -1;
        else
            def->mode = VIR_CPU_MODE_CUSTOM;
    }

    if (def->type == VIR_CPU_TYPE_GUEST) {
        char *match = virXMLPropString(node, "match");

        if (!match) {
            if (virXPathBoolean("boolean(./model)", ctxt))
                def->match = VIR_CPU_MATCH_EXACT;
            else
                def->match = -1;
        } else {
            def->match = virCPUMatchTypeFromString(match);
            VIR_FREE(match);

            if (def->match < 0) {
                virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("Invalid match attribute for CPU specification"));
                goto error;
            }
        }
    }

    if (def->type == VIR_CPU_TYPE_HOST) {
        def->arch = virXPathString("string(./arch[1])", ctxt);
        if (!def->arch) {
            virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("Missing CPU architecture"));
            goto error;
        }
    }

    if (!(def->model = virXPathString("string(./model[1])", ctxt)) &&
        def->type == VIR_CPU_TYPE_HOST) {
        virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                "%s", _("Missing CPU model name"));
        goto error;
    }

    if (def->type == VIR_CPU_TYPE_GUEST &&
        def->mode != VIR_CPU_MODE_HOST_PASSTHROUGH &&
        virXPathBoolean("boolean(./model[1]/@fallback)", ctxt)) {
        const char *fallback;

        fallback = virXPathString("string(./model[1]/@fallback)", ctxt);
        if (fallback) {
            def->fallback = virCPUFallbackTypeFromString(fallback);
            VIR_FREE(fallback);
            if (def->fallback < 0) {
                virCPUReportError(VIR_ERR_XML_ERROR, "%s",
                                  _("Invalid fallback attribute"));
                goto error;
            }
        }
    }

    def->vendor = virXPathString("string(./vendor[1])", ctxt);
    if (def->vendor && !def->model) {
        virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                "%s", _("CPU vendor specified without CPU model"));
        goto error;
    }

    if (virXPathNode("./topology[1]", ctxt)) {
        int ret;
        unsigned long ul;

        ret = virXPathULong("string(./topology[1]/@sockets)",
                            ctxt, &ul);
        if (ret < 0) {
            virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("Missing 'sockets' attribute in CPU topology"));
            goto error;
        }
        def->sockets = (unsigned int) ul;

        ret = virXPathULong("string(./topology[1]/@cores)",
                            ctxt, &ul);
        if (ret < 0) {
            virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("Missing 'cores' attribute in CPU topology"));
            goto error;
        }
        def->cores = (unsigned int) ul;

        ret = virXPathULong("string(./topology[1]/@threads)",
                            ctxt, &ul);
        if (ret < 0) {
            virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("Missing 'threads' attribute in CPU topology"));
            goto error;
        }
        def->threads = (unsigned int) ul;

        if (!def->sockets || !def->cores || !def->threads) {
            virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("Invalid CPU topology"));
            goto error;
        }
    }

    n = virXPathNodeSet("./feature", ctxt, &nodes);
    if (n < 0)
        goto error;

    if (n > 0) {
        if (!def->model) {
            virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("Non-empty feature list specified without CPU model"));
            goto error;
        }

        if (VIR_RESIZE_N(def->features, def->nfeatures_max,
                         def->nfeatures, n) < 0)
            goto no_memory;
        def->nfeatures = n;
    }

    for (i = 0 ; i < n ; i++) {
        char *name;
        int policy; /* enum virDomainCPUFeaturePolicy */
        unsigned int j;

        if (def->type == VIR_CPU_TYPE_GUEST) {
            char *strpolicy;

            strpolicy = virXMLPropString(nodes[i], "policy");
            if (strpolicy == NULL)
                policy = VIR_CPU_FEATURE_REQUIRE;
            else
                policy = virCPUFeaturePolicyTypeFromString(strpolicy);
            VIR_FREE(strpolicy);

            if (policy < 0) {
                virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("Invalid CPU feature policy"));
                goto error;
            }
        } else {
            policy = -1;
        }

        if (!(name = virXMLPropString(nodes[i], "name")) || *name == 0) {
            VIR_FREE(name);
            virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("Invalid CPU feature name"));
            goto error;
        }

        for (j = 0 ; j < i ; j++) {
            if (STREQ(name, def->features[j].name)) {
                virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                        _("CPU feature `%s' specified more than once"),
                        name);
                VIR_FREE(name);
                goto error;
            }
        }

        def->features[i].name = name;
        def->features[i].policy = policy;
    }

    if (virXPathNode("./numa[1]", ctxt)) {
        VIR_FREE(nodes);
        n = virXPathNodeSet("./numa[1]/cell", ctxt, &nodes);
        if (n <= 0) {
            virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("NUMA topology defined without NUMA cells"));
            goto error;
        }

        if (VIR_RESIZE_N(def->cells, def->ncells_max,
                         def->ncells, n) < 0)
            goto no_memory;

        def->ncells = n;

        for (i = 0 ; i < n ; i++) {
            char *cpus, *memory;
            int cpumasklen = VIR_DOMAIN_CPUMASK_LEN;
            int ret, ncpus = 0;

            def->cells[i].cellid = i;
            cpus = virXMLPropString(nodes[i], "cpus");
            if (!cpus) {
                virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("Missing 'cpus' attribute in NUMA cell"));
                goto error;
            }
            def->cells[i].cpustr = cpus;

            if (VIR_ALLOC_N(def->cells[i].cpumask, cpumasklen) < 0)
                goto no_memory;

            ncpus = virDomainCpuSetParse(cpus, 0, def->cells[i].cpumask,
                                         cpumasklen);
            if (ncpus <= 0)
                goto error;
            def->cells_cpus += ncpus;

            memory = virXMLPropString(nodes[i], "memory");
            if (!memory) {
                virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("Missing 'memory' attribute in NUMA cell"));
                goto error;
            }

            ret  = virStrToLong_ui(memory, NULL, 10, &def->cells[i].mem);
            if (ret == -1) {
                virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("Invalid 'memory' attribute in NUMA cell"));
                VIR_FREE(memory);
                goto error;
            }
            VIR_FREE(memory);
        }
    }

cleanup:
    VIR_FREE(nodes);
    return def;

no_memory:
    virReportOOMError();

error:
    virCPUDefFree(def);
    def = NULL;
    goto cleanup;
}


char *
virCPUDefFormat(virCPUDefPtr def,
                unsigned int flags)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (virCPUDefFormatBufFull(&buf, def, flags) < 0)
        goto cleanup;

    if (virBufferError(&buf))
        goto no_memory;

    return virBufferContentAndReset(&buf);

no_memory:
    virReportOOMError();
cleanup:
    virBufferFreeAndReset(&buf);
    return NULL;
}


int
virCPUDefFormatBufFull(virBufferPtr buf,
                       virCPUDefPtr def,
                       unsigned int flags)
{
    if (!def)
        return 0;

    virBufferAddLit(buf, "<cpu");
    if (def->type == VIR_CPU_TYPE_GUEST) {
        const char *tmp;

        if (def->mode != VIR_CPU_MODE_CUSTOM || def->model) {
            if (!(tmp = virCPUModeTypeToString(def->mode))) {
                virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                                  _("Unexpected CPU mode %d"), def->mode);
                return -1;
            }
            virBufferAsprintf(buf, " mode='%s'", tmp);
        }

        if (def->model &&
            (def->mode == VIR_CPU_MODE_CUSTOM ||
             (flags & VIR_DOMAIN_XML_UPDATE_CPU))) {
            if (!(tmp = virCPUMatchTypeToString(def->match))) {
                virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                                  _("Unexpected CPU match policy %d"),
                                  def->match);
                return -1;
            }
            virBufferAsprintf(buf, " match='%s'", tmp);
        }
    }
    virBufferAddLit(buf, ">\n");

    if (def->arch)
        virBufferAsprintf(buf, "  <arch>%s</arch>\n", def->arch);

    virBufferAdjustIndent(buf, 2);
    if (virCPUDefFormatBuf(buf, def, flags) < 0)
        return -1;
    virBufferAdjustIndent(buf, -2);

    virBufferAddLit(buf, "</cpu>\n");

    return 0;
}

int
virCPUDefFormatBuf(virBufferPtr buf,
                   virCPUDefPtr def,
                   unsigned int flags)
{
    unsigned int i;
    bool formatModel;
    bool formatFallback;

    if (!def)
        return 0;

    formatModel = (def->mode == VIR_CPU_MODE_CUSTOM ||
                   (flags & VIR_DOMAIN_XML_UPDATE_CPU));
    formatFallback = (def->type == VIR_CPU_TYPE_GUEST &&
                      (def->mode == VIR_CPU_MODE_HOST_MODEL ||
                       (def->mode == VIR_CPU_MODE_CUSTOM && def->model)));

    if (!def->model && def->nfeatures) {
        virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                "%s", _("Non-empty feature list specified without CPU model"));
        return -1;
    }

    if ((formatModel && def->model) || formatFallback) {
        virBufferAddLit(buf, "<model");
        if (formatFallback) {
            const char *fallback;

            fallback = virCPUFallbackTypeToString(def->fallback);
            if (!fallback) {
                virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                                  _("Unexpected CPU fallback value: %d"),
                                  def->fallback);
                return -1;
            }
            virBufferAsprintf(buf, " fallback='%s'", fallback);
        }
        if (formatModel && def->model) {
            virBufferAsprintf(buf, ">%s</model>\n", def->model);
        } else {
            virBufferAddLit(buf, "/>\n");
        }
    }

    if (formatModel && def->vendor)
        virBufferAsprintf(buf, "<vendor>%s</vendor>\n", def->vendor);

    if (def->sockets && def->cores && def->threads) {
        virBufferAddLit(buf, "<topology");
        virBufferAsprintf(buf, " sockets='%u'", def->sockets);
        virBufferAsprintf(buf, " cores='%u'", def->cores);
        virBufferAsprintf(buf, " threads='%u'", def->threads);
        virBufferAddLit(buf, "/>\n");
    }

    if (formatModel) {
        for (i = 0 ; i < def->nfeatures ; i++) {
            virCPUFeatureDefPtr feature = def->features + i;

            if (!feature->name) {
                virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("Missing CPU feature name"));
                return -1;
            }

            if (def->type == VIR_CPU_TYPE_GUEST) {
                const char *policy;

                policy = virCPUFeaturePolicyTypeToString(feature->policy);
                if (!policy) {
                    virCPUReportError(VIR_ERR_INTERNAL_ERROR,
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
    }

    if (def->ncells) {
        virBufferAddLit(buf, "<numa>\n");
        for (i = 0; i < def->ncells; i++) {
            virBufferAddLit(buf, "  <cell");
            virBufferAsprintf(buf, " cpus='%s'", def->cells[i].cpustr);
            virBufferAsprintf(buf, " memory='%d'", def->cells[i].mem);
            virBufferAddLit(buf, "/>\n");
        }
        virBufferAddLit(buf, "</numa>\n");
    }
    return 0;
}


int
virCPUDefAddFeature(virCPUDefPtr def,
                    const char *name,
                    int policy)
{
    int i;

    for (i = 0 ; i < def->nfeatures ; i++) {
        if (STREQ(name, def->features[i].name)) {
            virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                    _("CPU feature `%s' specified more than once"), name);
            return -1;
        }
    }

    if (VIR_RESIZE_N(def->features, def->nfeatures_max,
                     def->nfeatures, 1) < 0)
        goto no_memory;

    if (def->type == VIR_CPU_TYPE_HOST)
        policy = -1;

    if (!(def->features[def->nfeatures].name = strdup(name)))
        goto no_memory;

    def->features[def->nfeatures].policy = policy;
    def->nfeatures++;

    return 0;

no_memory:
    virReportOOMError();
    return -1;
}

bool
virCPUDefIsEqual(virCPUDefPtr src,
                 virCPUDefPtr dst)
{
    bool identical = false;
    int i;

    if (!src && !dst)
        return true;

    if ((src && !dst) || (!src && dst)) {
        virCPUReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                          _("Target CPU does not match source"));
        goto cleanup;
    }

    if (src->type != dst->type) {
        virCPUReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                          _("Target CPU type %s does not match source %s"),
                          virCPUTypeToString(dst->type),
                          virCPUTypeToString(src->type));
        goto cleanup;
    }

    if (src->mode != dst->mode) {
        virCPUReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                          _("Target CPU mode %s does not match source %s"),
                          virCPUModeTypeToString(dst->mode),
                          virCPUModeTypeToString(src->mode));
        goto cleanup;
    }

    if (STRNEQ_NULLABLE(src->arch, dst->arch)) {
        virCPUReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                          _("Target CPU arch %s does not match source %s"),
                          NULLSTR(dst->arch), NULLSTR(src->arch));
        goto cleanup;
    }

    if (STRNEQ_NULLABLE(src->model, dst->model)) {
        virCPUReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                          _("Target CPU model %s does not match source %s"),
                          NULLSTR(dst->model), NULLSTR(src->model));
        goto cleanup;
    }

    if (STRNEQ_NULLABLE(src->vendor, dst->vendor)) {
        virCPUReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                          _("Target CPU vendor %s does not match source %s"),
                          NULLSTR(dst->vendor), NULLSTR(src->vendor));
        goto cleanup;
    }

    if (src->sockets != dst->sockets) {
        virCPUReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                          _("Target CPU sockets %d does not match source %d"),
                          dst->sockets, src->sockets);
        goto cleanup;
    }

    if (src->cores != dst->cores) {
        virCPUReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                          _("Target CPU cores %d does not match source %d"),
                          dst->cores, src->cores);
        goto cleanup;
    }

    if (src->threads != dst->threads) {
        virCPUReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                          _("Target CPU threads %d does not match source %d"),
                          dst->threads, src->threads);
        goto cleanup;
    }

    if (src->nfeatures != dst->nfeatures) {
        virCPUReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                          _("Target CPU feature count %zu does not match source %zu"),
                          dst->nfeatures, src->nfeatures);
        goto cleanup;
    }

    for (i = 0 ; i < src->nfeatures ; i++) {
        if (STRNEQ(src->features[i].name, dst->features[i].name)) {
            virCPUReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                              _("Target CPU feature %s does not match source %s"),
                              dst->features[i].name, src->features[i].name);
            goto cleanup;
        }

        if (src->features[i].policy != dst->features[i].policy) {
            virCPUReportError(VIR_ERR_CONFIG_UNSUPPORTED,
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
