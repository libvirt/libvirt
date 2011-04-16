/*
 * cpu_conf.h: CPU XML handling
 *
 * Copyright (C) 2009, 2010 Red Hat, Inc.
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

#define VIR_FROM_THIS VIR_FROM_CPU

#define virCPUReportError(code, ...)                              \
    virReportErrorHelper(VIR_FROM_CPU, code, __FILE__,            \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

VIR_ENUM_IMPL(virCPUMatch, VIR_CPU_MATCH_LAST,
              "minimum",
              "exact",
              "strict")

VIR_ENUM_IMPL(virCPUFeaturePolicy, VIR_CPU_FEATURE_LAST,
              "force",
              "require",
              "optional",
              "disable",
              "forbid")


void
virCPUDefFree(virCPUDefPtr def)
{
    unsigned int i;

    if (!def)
        return;

    VIR_FREE(def->model);
    VIR_FREE(def->arch);
    VIR_FREE(def->vendor);

    for (i = 0 ; i < def->nfeatures ; i++)
        VIR_FREE(def->features[i].name);
    VIR_FREE(def->features);

    VIR_FREE(def);
}


virCPUDefPtr
virCPUDefCopy(const virCPUDefPtr cpu)
{
    virCPUDefPtr copy;
    unsigned int i;

    if (!cpu)
        return NULL;

    if (VIR_ALLOC(copy) < 0
        || (cpu->arch && !(copy->arch = strdup(cpu->arch)))
        || (cpu->model && !(copy->model = strdup(cpu->model)))
        || (cpu->vendor && !(copy->vendor = strdup(cpu->vendor)))
        || VIR_ALLOC_N(copy->features, cpu->nfeatures) < 0)
        goto no_memory;
    copy->nfeatures_max = cpu->nfeatures;

    copy->type = cpu->type;
    copy->match = cpu->match;
    copy->sockets = cpu->sockets;
    copy->cores = cpu->cores;
    copy->threads = cpu->threads;
    copy->nfeatures = cpu->nfeatures;

    for (i = 0; i < copy->nfeatures; i++) {
        copy->features[i].policy = cpu->features[i].policy;
        if (!(copy->features[i].name = strdup(cpu->features[i].name)))
            goto no_memory;
    }

    return copy;

no_memory:
    virReportOOMError();
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
        } else
            def->type = VIR_CPU_TYPE_GUEST;
    } else
        def->type = mode;

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
        }
        else
            policy = -1;

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
                const char *indent,
                int flags)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (virCPUDefFormatBuf(&buf, def, indent, flags) < 0)
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
virCPUDefFormatBuf(virBufferPtr buf,
                   virCPUDefPtr def,
                   const char *indent,
                   int flags)
{
    unsigned int i;

    if (!def)
        return 0;

    if (indent == NULL)
        indent = "";

    if (!def->model && def->nfeatures) {
        virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                "%s", _("Non-empty feature list specified without CPU model"));
        return -1;
    }

    if (!(flags & VIR_CPU_FORMAT_EMBEDED)) {
        if (def->type == VIR_CPU_TYPE_GUEST && def->model) {
            const char *match;
            if (!(match = virCPUMatchTypeToString(def->match))) {
                virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                        _("Unexpected CPU match policy %d"), def->match);
                return -1;
            }

            virBufferVSprintf(buf, "%s<cpu match='%s'>\n", indent, match);
        }
        else
            virBufferVSprintf(buf, "%s<cpu>\n", indent);

        if (def->arch)
            virBufferVSprintf(buf, "%s  <arch>%s</arch>\n", indent, def->arch);
    }

    if (def->model)
        virBufferVSprintf(buf, "%s  <model>%s</model>\n", indent, def->model);

    if (def->vendor) {
        virBufferVSprintf(buf, "%s  <vendor>%s</vendor>\n",
                          indent, def->vendor);
    }

    if (def->sockets && def->cores && def->threads) {
        virBufferVSprintf(buf, "%s  <topology", indent);
        virBufferVSprintf(buf, " sockets='%u'", def->sockets);
        virBufferVSprintf(buf, " cores='%u'", def->cores);
        virBufferVSprintf(buf, " threads='%u'", def->threads);
        virBufferAddLit(buf, "/>\n");
    }

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
                        _("Unexpected CPU feature policy %d"), feature->policy);
                return -1;
            }
            virBufferVSprintf(buf, "%s  <feature policy='%s' name='%s'/>\n",
                    indent, policy, feature->name);
        }
        else {
            virBufferVSprintf(buf, "%s  <feature name='%s'/>\n",
                    indent, feature->name);
        }
    }

    if (!(flags & VIR_CPU_FORMAT_EMBEDED))
        virBufferVSprintf(buf, "%s</cpu>\n", indent);

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
