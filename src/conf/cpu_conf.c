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
 */

#include <config.h>

#include "configmake.h"
#include "virerror.h"
#include "viralloc.h"
#include "virbuffer.h"
#include "virfile.h"
#include "cpu_conf.h"
#include "domain_conf.h"
#include "virstring.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_CPU

VIR_LOG_INIT("conf.cpu_conf");

VIR_ENUM_IMPL(virCPU,
              VIR_CPU_TYPE_LAST,
              "host", "guest", "auto",
);

VIR_ENUM_IMPL(virCPUMode,
              VIR_CPU_MODE_LAST,
              "custom",
              "host-model",
              "host-passthrough",
              "maximum",
);

VIR_ENUM_IMPL(virCPUMatch,
              VIR_CPU_MATCH_LAST,
              "exact",
              "minimum",
              "strict",
);

VIR_ENUM_IMPL(virCPUCheck,
              VIR_CPU_CHECK_LAST,
              "default",
              "none",
              "partial",
              "full",
);

VIR_ENUM_IMPL(virCPUFallback,
              VIR_CPU_FALLBACK_LAST,
              "allow",
              "forbid",
);

VIR_ENUM_IMPL(virCPUFeaturePolicy,
              VIR_CPU_FEATURE_LAST,
              "force",
              "require",
              "optional",
              "disable",
              "forbid",
);

VIR_ENUM_IMPL(virCPUCacheMode,
              VIR_CPU_CACHE_MODE_LAST,
              "emulate",
              "passthrough",
              "disable",
);


virCPUDef *virCPUDefNew(void)
{
    virCPUDef *cpu = g_new0(virCPUDef, 1);
    cpu->refs = 1;
    return cpu;
}

void
virCPUDefFreeFeatures(virCPUDef *def)
{
    size_t i;

    for (i = 0; i < def->nfeatures; i++)
        VIR_FREE(def->features[i].name);
    VIR_FREE(def->features);

    def->nfeatures = def->nfeatures_max = 0;
}


void ATTRIBUTE_NONNULL(1)
virCPUDefFreeModel(virCPUDef *def)
{
    VIR_FREE(def->model);
    VIR_FREE(def->vendor);
    VIR_FREE(def->vendor_id);
    virCPUDefFreeFeatures(def);
}

void
virCPUDefRef(virCPUDef *def)
{
    g_atomic_int_inc(&def->refs);
}

void
virCPUDefFree(virCPUDef *def)
{
    if (!def)
        return;

    if (g_atomic_int_dec_and_test(&def->refs)) {
        virCPUDefFreeModel(def);
        g_free(def->cache);
        g_free(def->tsc);
        g_free(def);
    }
}


int ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
virCPUDefCopyModel(virCPUDef *dst,
                   const virCPUDef *src,
                   bool resetPolicy)
{
    return virCPUDefCopyModelFilter(dst, src, resetPolicy, NULL, NULL);
}


int
virCPUDefCopyModelFilter(virCPUDef *dst,
                         const virCPUDef *src,
                         bool resetPolicy,
                         virCPUDefFeatureFilter filter,
                         void *opaque)
{
    size_t i;
    size_t n;

    dst->features = g_new0(virCPUFeatureDef, src->nfeatures);
    dst->model = g_strdup(src->model);
    dst->vendor = g_strdup(src->vendor);
    dst->vendor_id = g_strdup(src->vendor_id);
    dst->microcodeVersion = src->microcodeVersion;
    dst->nfeatures_max = src->nfeatures;
    dst->nfeatures = 0;

    for (i = 0; i < src->nfeatures; i++) {
        if (filter && !filter(src->features[i].name, src->features[i].policy, opaque))
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

        dst->features[n].name = g_strdup(src->features[i].name);
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
virCPUDefStealModel(virCPUDef *dst,
                    virCPUDef *src,
                    bool keepVendor)
{
    char *vendor = NULL;
    char *vendor_id = NULL;

    if (keepVendor) {
        vendor = g_steal_pointer(&dst->vendor);
        vendor_id = g_steal_pointer(&dst->vendor_id);
    }

    virCPUDefFreeModel(dst);

    dst->model = g_steal_pointer(&src->model);
    dst->features = g_steal_pointer(&src->features);
    dst->microcodeVersion = src->microcodeVersion;
    dst->nfeatures_max = src->nfeatures_max;
    src->nfeatures_max = 0;
    dst->nfeatures = src->nfeatures;
    src->nfeatures = 0;

    if (keepVendor) {
        dst->vendor = vendor;
        dst->vendor_id = vendor_id;
    } else {
        dst->vendor = g_steal_pointer(&src->vendor);
        dst->vendor_id = g_steal_pointer(&src->vendor_id);
    }
}


virCPUDef *
virCPUDefCopyWithoutModel(const virCPUDef *cpu)
{
    g_autoptr(virCPUDef) copy = NULL;

    if (!cpu)
        return NULL;

    copy = virCPUDefNew();
    copy->type = cpu->type;
    copy->mode = cpu->mode;
    copy->match = cpu->match;
    copy->check = cpu->check;
    copy->fallback = cpu->fallback;
    copy->sockets = cpu->sockets;
    copy->dies = cpu->dies;
    copy->cores = cpu->cores;
    copy->threads = cpu->threads;
    copy->arch = cpu->arch;
    copy->migratable = cpu->migratable;

    if (cpu->cache) {
        copy->cache = g_new0(virCPUCacheDef, 1);
        *copy->cache = *cpu->cache;
    }

    if (cpu->tsc) {
        copy->tsc = g_new0(virHostCPUTscInfo, 1);
        *copy->tsc = *cpu->tsc;
    }

    return g_steal_pointer(&copy);
}


virCPUDef *
virCPUDefCopy(const virCPUDef *cpu)
{
    g_autoptr(virCPUDef) copy = NULL;

    if (!(copy = virCPUDefCopyWithoutModel(cpu)))
        return NULL;

    if (virCPUDefCopyModel(copy, cpu, false) < 0)
        return NULL;

    return g_steal_pointer(&copy);
}


int
virCPUDefParseXMLString(const char *xml,
                        virCPUType type,
                        virCPUDef **cpu,
                        bool validateXML)
{
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    int ret = -1;

    if (!xml) {
        virReportError(VIR_ERR_INVALID_ARG, "%s", _("missing CPU definition"));
        goto cleanup;
    }

    if (!(doc = virXMLParseStringCtxt(xml, _("(CPU_definition)"), &ctxt)))
        goto cleanup;

    if (virCPUDefParseXML(ctxt, NULL, type, cpu, validateXML) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    xmlFreeDoc(doc);
    xmlXPathFreeContext(ctxt);
    return ret;
}


/*
 * Parses CPU definition XML from a node pointed to by @xpath. If @xpath is
 * NULL, the current node of @ctxt is used (i.e., it is a shortcut to ".").
 *
 * Missing <cpu> element in the XML document is not considered an error unless
 * @xpath is NULL in which case the function expects it was provided with a
 * valid <cpu> element already. In other words, the function returns success
 * and sets @cpu to NULL if @xpath is not NULL and the node pointed to by
 * @xpath is not found.
 *
 * Returns 0 on success, -1 on error.
 */
int
virCPUDefParseXML(xmlXPathContextPtr ctxt,
                  const char *xpath,
                  virCPUType type,
                  virCPUDef **cpu,
                  bool validateXML)
{
    g_autoptr(virCPUDef) def = NULL;
    g_autofree xmlNodePtr *nodes = NULL;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    int n;
    size_t i;
    g_autofree char *cpuMode = NULL;
    g_autofree char *fallback = NULL;
    g_autofree char *vendor_id = NULL;
    g_autofree char *tscScaling = NULL;
    g_autofree char *migratable = NULL;
    g_autofree virHostCPUTscInfo *tsc = NULL;

    *cpu = NULL;

    if (xpath && !(ctxt->node = virXPathNode(xpath, ctxt)))
        return 0;

    if (!virXMLNodeNameEqual(ctxt->node, "cpu")) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("XML does not contain expected 'cpu' element"));
        return -1;
    }

    if (validateXML) {
        g_autofree char *schemafile = NULL;

        if (!(schemafile = virFileFindResource("cpu.rng",
                                               abs_top_srcdir "/docs/schemas",
                                               PKGDATADIR "/schemas")))
            return -1;

        if (virXMLValidateNodeAgainstSchema(schemafile, ctxt->node) < 0)
            return -1;
    }

    def = virCPUDefNew();

    if (type == VIR_CPU_TYPE_AUTO) {
        if (virXPathBoolean("boolean(./arch)", ctxt)) {
            if (virXPathBoolean("boolean(./@match)", ctxt)) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("'arch' element cannot be used inside 'cpu'"
                                 " element with 'match' attribute'"));
                return -1;
            }
            def->type = VIR_CPU_TYPE_HOST;
        } else {
            def->type = VIR_CPU_TYPE_GUEST;
        }
    } else {
        def->type = type;
    }

    if ((cpuMode = virXMLPropString(ctxt->node, "mode"))) {
        if (def->type == VIR_CPU_TYPE_HOST) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Attribute mode is only allowed for guest CPU"));
            return -1;
        } else {
            def->mode = virCPUModeTypeFromString(cpuMode);

            if (def->mode < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Invalid mode attribute '%s'"),
                               cpuMode);
                return -1;
            }
        }
    } else {
        if (def->type == VIR_CPU_TYPE_HOST)
            def->mode = -1;
        else
            def->mode = VIR_CPU_MODE_CUSTOM;
    }

    if ((migratable = virXMLPropString(ctxt->node, "migratable"))) {
        int val;

        if (def->mode != VIR_CPU_MODE_HOST_PASSTHROUGH &&
            def->mode != VIR_CPU_MODE_MAXIMUM) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Attribute migratable is only allowed for "
                             "'host-passthrough' / 'maximum' CPU mode"));
            return -1;
        }

        if ((val = virTristateSwitchTypeFromString(migratable)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Invalid value in migratable attribute: '%s'"),
                           migratable);
            return -1;
        }

        def->migratable = val;
    }

    if (def->type == VIR_CPU_TYPE_GUEST) {
        g_autofree char *match = virXMLPropString(ctxt->node, "match");

        if (match) {
            def->match = virCPUMatchTypeFromString(match);
            if (def->match < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Invalid match attribute for CPU "
                                 "specification"));
                return -1;
            }
        }

        if (virXMLPropEnum(ctxt->node, "check", virCPUCheckTypeFromString,
                           VIR_XML_PROP_NONE, &def->check) < 0)
            return -1;
    }

    if (def->type == VIR_CPU_TYPE_HOST) {
        g_autofree char *arch = virXPathString("string(./arch[1])", ctxt);
        if (!arch) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing CPU architecture"));
            return -1;
        }
        if ((def->arch = virArchFromString(arch)) == VIR_ARCH_NONE) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unknown architecture %s"), arch);
            return -1;
        }

        if (virXPathBoolean("boolean(./microcode[1]/@version)", ctxt) > 0 &&
            virXPathUInt("string(./microcode[1]/@version)", ctxt,
                         &def->microcodeVersion) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("invalid microcode version"));
            return -1;
        }

        if (virXPathBoolean("boolean(./counter[@name='tsc'])", ctxt) > 0) {
            tsc = g_new0(virHostCPUTscInfo, 1);

            if (virXPathULongLong("string(./counter[@name='tsc']/@frequency)",
                                  ctxt, &tsc->frequency) < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Invalid TSC frequency"));
                return -1;
            }

            tscScaling = virXPathString("string(./counter[@name='tsc']/@scaling)",
                                        ctxt);
            if (tscScaling) {
                int scaling = virTristateBoolTypeFromString(tscScaling);
                if (scaling < 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("Invalid TSC scaling attribute"));
                    return -1;
                }
                tsc->scaling = scaling;
            }

            def->tsc = g_steal_pointer(&tsc);
        }
    }

    if (!(def->model = virXPathString("string(./model[1])", ctxt)) &&
        def->type == VIR_CPU_TYPE_HOST) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                        _("Missing CPU model name"));
        return -1;
    }

    if (def->type == VIR_CPU_TYPE_GUEST &&
        def->mode != VIR_CPU_MODE_HOST_PASSTHROUGH &&
        def->mode != VIR_CPU_MODE_MAXIMUM) {

        if ((fallback = virXPathString("string(./model[1]/@fallback)", ctxt))) {
            if ((def->fallback = virCPUFallbackTypeFromString(fallback)) < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Invalid fallback attribute"));
                return -1;
            }
        }

        if ((vendor_id = virXPathString("string(./model[1]/@vendor_id)",
                                        ctxt))) {
            if (strlen(vendor_id) != VIR_CPU_VENDOR_ID_LENGTH) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("vendor_id must be exactly %d characters long"),
                               VIR_CPU_VENDOR_ID_LENGTH);
                return -1;
            }

            /* ensure that the string can be passed to qemu */
            if (strchr(vendor_id, ',')) {
                    virReportError(VIR_ERR_XML_ERROR, "%s",
                                   _("vendor id is invalid"));
                    return -1;
            }

            def->vendor_id = g_steal_pointer(&vendor_id);
        }
    }

    def->vendor = virXPathString("string(./vendor[1])", ctxt);
    if (def->vendor && !def->model) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("CPU vendor specified without CPU model"));
        return -1;
    }

    if (virXPathNode("./topology[1]", ctxt)) {
        unsigned long ul;

        if (virXPathULong("string(./topology[1]/@sockets)", ctxt, &ul) < 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing 'sockets' attribute in CPU topology"));
            return -1;
        }
        def->sockets = (unsigned int) ul;

        if (virXPathNode("./topology[1]/@dies", ctxt)) {
            if (virXPathULong("string(./topology[1]/@dies)", ctxt, &ul) < 0) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("Malformed 'dies' attribute in CPU topology"));
                return -1;
            }
            def->dies = (unsigned int) ul;
        } else {
            def->dies = 1;
        }

        if (virXPathULong("string(./topology[1]/@cores)", ctxt, &ul) < 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing 'cores' attribute in CPU topology"));
            return -1;
        }
        def->cores = (unsigned int) ul;

        if (virXPathULong("string(./topology[1]/@threads)", ctxt, &ul) < 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing 'threads' attribute in CPU topology"));
            return -1;
        }
        def->threads = (unsigned int) ul;

        if (!def->sockets || !def->cores || !def->threads || !def->dies) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Invalid CPU topology"));
            return -1;
        }
    }

    if ((n = virXPathNodeSet("./feature", ctxt, &nodes)) < 0)
        return -1;

    if (n > 0) {
        if (!def->model && def->mode == VIR_CPU_MODE_CUSTOM) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Non-empty feature list specified without "
                             "CPU model"));
            return -1;
        }

        VIR_RESIZE_N(def->features, def->nfeatures_max, def->nfeatures, n);
        def->nfeatures = n;
    }

    for (i = 0; i < n; i++) {
        g_autofree char *name = NULL;
        int policy; /* enum virDomainCPUFeaturePolicy */
        size_t j;

        if (def->type == VIR_CPU_TYPE_GUEST) {
            g_autofree char *strpolicy = NULL;

            strpolicy = virXMLPropString(nodes[i], "policy");
            if (strpolicy == NULL)
                policy = VIR_CPU_FEATURE_REQUIRE;
            else
                policy = virCPUFeaturePolicyTypeFromString(strpolicy);

            if (policy < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Invalid CPU feature policy"));
                return -1;
            }
        } else {
            policy = -1;
        }

        if (!(name = virXMLPropString(nodes[i], "name")) || *name == 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Invalid CPU feature name"));
            return -1;
        }

        for (j = 0; j < i; j++) {
            if (STREQ(name, def->features[j].name)) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("CPU feature '%s' specified more than once"),
                               name);
                return -1;
            }
        }

        def->features[i].name = g_steal_pointer(&name);
        def->features[i].policy = policy;
    }

    if (virXPathInt("count(./cache)", ctxt, &n) < 0) {
        return -1;
    } else if (n > 1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("at most one CPU cache element may be specified"));
        return -1;
    } else if (n == 1) {
        int level = -1;
        g_autofree char *strmode = NULL;
        int mode;

        if (virXPathBoolean("boolean(./cache[1]/@level)", ctxt) == 1 &&
            (virXPathInt("string(./cache[1]/@level)", ctxt, &level) < 0 ||
             level < 1 || level > 3)) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("invalid CPU cache level, must be in range [1,3]"));
            return -1;
        }

        if (!(strmode = virXPathString("string(./cache[1]/@mode)", ctxt)) ||
            (mode = virCPUCacheModeTypeFromString(strmode)) < 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing or invalid CPU cache mode"));
            return -1;
        }

        def->cache = g_new0(virCPUCacheDef, 1);
        def->cache->level = level;
        def->cache->mode = mode;
    }

    *cpu = g_steal_pointer(&def);
    return 0;
}


char *
virCPUDefFormat(virCPUDef *def,
                virDomainNuma *numa)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    if (virCPUDefFormatBufFull(&buf, def, numa) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
}


int
virCPUDefFormatBufFull(virBuffer *buf,
                       virCPUDef *def,
                       virDomainNuma *numa)
{
    g_auto(virBuffer) attributeBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childrenBuf = VIR_BUFFER_INIT_CHILD(buf);

    if (!def)
        return 0;

    /* Format attributes for guest CPUs unless they only specify
     * topology or cache. */
    if (def->type == VIR_CPU_TYPE_GUEST &&
        (def->mode != VIR_CPU_MODE_CUSTOM || def->model)) {
        const char *tmp;

        if (!(tmp = virCPUModeTypeToString(def->mode))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unexpected CPU mode %d"), def->mode);
            return -1;
        }
        virBufferAsprintf(&attributeBuf, " mode='%s'", tmp);

        if (def->mode == VIR_CPU_MODE_CUSTOM) {
            if (!(tmp = virCPUMatchTypeToString(def->match))) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unexpected CPU match policy %d"),
                               def->match);
                return -1;
            }
            virBufferAsprintf(&attributeBuf, " match='%s'", tmp);
        }

        if (def->check) {
            virBufferAsprintf(&attributeBuf, " check='%s'",
                              virCPUCheckTypeToString(def->check));
        }

        if ((def->mode == VIR_CPU_MODE_HOST_PASSTHROUGH ||
             def->mode == VIR_CPU_MODE_MAXIMUM) &&
            def->migratable) {
            virBufferAsprintf(&attributeBuf, " migratable='%s'",
                              virTristateSwitchTypeToString(def->migratable));
        }
    }

    /* Format children */
    if (def->type == VIR_CPU_TYPE_HOST && def->arch)
        virBufferAsprintf(&childrenBuf, "<arch>%s</arch>\n",
                          virArchToString(def->arch));
    if (virCPUDefFormatBuf(&childrenBuf, def) < 0)
        return -1;

    if (virDomainNumaDefFormatXML(&childrenBuf, numa) < 0)
        return -1;

    virXMLFormatElement(buf, "cpu", &attributeBuf, &childrenBuf);

    return 0;
}

int
virCPUDefFormatBuf(virBuffer *buf,
                   virCPUDef *def)
{
    size_t i;
    bool formatModel;

    if (!def)
        return 0;

    formatModel = (def->mode == VIR_CPU_MODE_CUSTOM ||
                   def->mode == VIR_CPU_MODE_HOST_MODEL);

    if (!def->model && def->mode == VIR_CPU_MODE_CUSTOM && def->nfeatures) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Non-empty feature list specified without CPU model"));
        return -1;
    }

    if (formatModel && (def->model || def->vendor_id)) {
        virBufferAddLit(buf, "<model");

        if (def->type == VIR_CPU_TYPE_GUEST && def->model) {
            const char *fallback;

            fallback = virCPUFallbackTypeToString(def->fallback);
            if (!fallback) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unexpected CPU fallback value: %d"),
                               def->fallback);
                return -1;
            }
            virBufferAsprintf(buf, " fallback='%s'", fallback);
        }

        if (def->type == VIR_CPU_TYPE_GUEST)
            virBufferEscapeString(buf, " vendor_id='%s'", def->vendor_id);

        if (def->model)
            virBufferEscapeString(buf, ">%s</model>\n", def->model);
        else
            virBufferAddLit(buf, "/>\n");
    }

    if (formatModel && def->vendor)
        virBufferEscapeString(buf, "<vendor>%s</vendor>\n", def->vendor);

    if (def->type == VIR_CPU_TYPE_HOST && def->microcodeVersion)
        virBufferAsprintf(buf, "<microcode version='%u'/>\n",
                          def->microcodeVersion);

    if (def->type == VIR_CPU_TYPE_HOST && def->tsc) {
        virBufferAddLit(buf, "<counter name='tsc'");
        virBufferAsprintf(buf, " frequency='%llu'", def->tsc->frequency);
        if (def->tsc->scaling) {
            virBufferAsprintf(buf, " scaling='%s'",
                              virTristateBoolTypeToString(def->tsc->scaling));
        }
        virBufferAddLit(buf, "/>\n");
    }

    if (def->sockets && def->dies && def->cores && def->threads) {
        virBufferAddLit(buf, "<topology");
        virBufferAsprintf(buf, " sockets='%u'", def->sockets);
        virBufferAsprintf(buf, " dies='%u'", def->dies);
        virBufferAsprintf(buf, " cores='%u'", def->cores);
        virBufferAsprintf(buf, " threads='%u'", def->threads);
        virBufferAddLit(buf, "/>\n");
    }

    if (def->cache) {
        virBufferAddLit(buf, "<cache ");
        if (def->cache->level != -1)
            virBufferAsprintf(buf, "level='%d' ", def->cache->level);
        virBufferAsprintf(buf, "mode='%s'",
                          virCPUCacheModeTypeToString(def->cache->mode));
        virBufferAddLit(buf, "/>\n");
    }

    for (i = 0; i < def->nfeatures; i++) {
        virCPUFeatureDef *feature = def->features + i;

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


typedef enum {
    VIR_CPU_ADD_FEATURE_MODE_EXCLUSIVE, /* Fail if feature exists */
    VIR_CPU_ADD_FEATURE_MODE_UPDATE,    /* Add feature or update policy */
    VIR_CPU_ADD_FEATURE_MODE_NEW,       /* Add feature if it does not exist */
} virCPUDefAddFeatureMode;

static int
virCPUDefAddFeatureInternal(virCPUDef *def,
                            const char *name,
                            int policy,
                            virCPUDefAddFeatureMode mode)
{
    virCPUFeatureDef *feat;

    if (def->type == VIR_CPU_TYPE_HOST)
        policy = -1;

    if ((feat = virCPUDefFindFeature(def, name))) {
        switch (mode) {
        case VIR_CPU_ADD_FEATURE_MODE_NEW:
            return 0;

        case VIR_CPU_ADD_FEATURE_MODE_UPDATE:
            feat->policy = policy;
            return 0;

        case VIR_CPU_ADD_FEATURE_MODE_EXCLUSIVE:
        default:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("CPU feature '%s' specified more than once"),
                           name);
            return -1;
        }
    }

    VIR_RESIZE_N(def->features, def->nfeatures_max, def->nfeatures, 1);
    def->features[def->nfeatures].name = g_strdup(name);
    def->features[def->nfeatures].policy = policy;
    def->nfeatures++;

    return 0;
}

int
virCPUDefUpdateFeature(virCPUDef *def,
                       const char *name,
                       int policy)
{
    return virCPUDefAddFeatureInternal(def, name, policy,
                                       VIR_CPU_ADD_FEATURE_MODE_UPDATE);
}

int
virCPUDefAddFeature(virCPUDef *def,
                    const char *name,
                    int policy)
{
    return virCPUDefAddFeatureInternal(def, name, policy,
                                       VIR_CPU_ADD_FEATURE_MODE_EXCLUSIVE);
}


int
virCPUDefAddFeatureIfMissing(virCPUDef *def,
                             const char *name,
                             int policy)
{
    return virCPUDefAddFeatureInternal(def, name, policy,
                                       VIR_CPU_ADD_FEATURE_MODE_NEW);
}


virCPUFeatureDef *
virCPUDefFindFeature(const virCPUDef *def,
                     const char *name)
{
    size_t i;

    for (i = 0; i < def->nfeatures; i++) {
        if (STREQ(name, def->features[i].name))
            return def->features + i;
    }

    return NULL;
}


int
virCPUDefFilterFeatures(virCPUDef *cpu,
                        virCPUDefFeatureFilter filter,
                        void *opaque)
{
    size_t i = 0;

    while (i < cpu->nfeatures) {
        if (filter(cpu->features[i].name, cpu->features[i].policy, opaque)) {
            i++;
            continue;
        }

        VIR_FREE(cpu->features[i].name);
        if (VIR_DELETE_ELEMENT_INPLACE(cpu->features, i, cpu->nfeatures) < 0)
            return -1;
    }

    return 0;
}


/**
 * virCPUDefCheckFeatures:
 *
 * Check CPU features for which @filter reports true and store them in a NULL
 * terminated list returned via @features.
 *
 * Returns the number of features matching @filter or -1 on error.
 */
int
virCPUDefCheckFeatures(virCPUDef *cpu,
                       virCPUDefFeatureFilter filter,
                       void *opaque,
                       char ***features)
{
    size_t n = 0;
    size_t i;

    *features = NULL;

    if (cpu->nfeatures == 0)
        return 0;

    *features = g_new0(char *, cpu->nfeatures + 1);

    for (i = 0; i < cpu->nfeatures; i++) {
        if (filter(cpu->features[i].name, cpu->features[i].policy, opaque))
            (*features)[n++] = g_strdup(cpu->features[i].name);
    }

    return n;
}


bool
virCPUDefIsEqual(virCPUDef *src,
                 virCPUDef *dst,
                 bool reportError)
{
    size_t i;

    if (!src && !dst)
        return true;

#define MISMATCH(fmt, ...) \
    if (reportError) \
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, fmt, __VA_ARGS__)

    if ((src && !dst) || (!src && dst)) {
        MISMATCH("%s", _("Target CPU does not match source"));
        return false;
    }

    if (src->type != dst->type) {
        MISMATCH(_("Target CPU type %s does not match source %s"),
                 virCPUTypeToString(dst->type),
                 virCPUTypeToString(src->type));
        return false;
    }

    if (src->mode != dst->mode) {
        MISMATCH(_("Target CPU mode %s does not match source %s"),
                 virCPUModeTypeToString(dst->mode),
                 virCPUModeTypeToString(src->mode));
        return false;
    }

    if (src->check != dst->check) {
        MISMATCH(_("Target CPU check %s does not match source %s"),
                 virCPUCheckTypeToString(dst->check),
                 virCPUCheckTypeToString(src->check));
        return false;
    }

    if (src->arch != dst->arch) {
        MISMATCH(_("Target CPU arch %s does not match source %s"),
                 virArchToString(dst->arch),
                 virArchToString(src->arch));
        return false;
    }

    if (STRNEQ_NULLABLE(src->model, dst->model)) {
        MISMATCH(_("Target CPU model %s does not match source %s"),
                 NULLSTR(dst->model), NULLSTR(src->model));
        return false;
    }

    if (STRNEQ_NULLABLE(src->vendor, dst->vendor)) {
        MISMATCH(_("Target CPU vendor %s does not match source %s"),
                 NULLSTR(dst->vendor), NULLSTR(src->vendor));
        return false;
    }

    if (STRNEQ_NULLABLE(src->vendor_id, dst->vendor_id)) {
        MISMATCH(_("Target CPU vendor id %s does not match source %s"),
                 NULLSTR(dst->vendor_id), NULLSTR(src->vendor_id));
        return false;
    }

    if (src->sockets != dst->sockets) {
        MISMATCH(_("Target CPU sockets %d does not match source %d"),
                 dst->sockets, src->sockets);
        return false;
    }

    if (src->dies != dst->dies) {
        MISMATCH(_("Target CPU dies %d does not match source %d"),
                 dst->dies, src->dies);
        return false;
    }

    if (src->cores != dst->cores) {
        MISMATCH(_("Target CPU cores %d does not match source %d"),
                 dst->cores, src->cores);
        return false;
    }

    if (src->threads != dst->threads) {
        MISMATCH(_("Target CPU threads %d does not match source %d"),
                 dst->threads, src->threads);
        return false;
    }

    if (src->nfeatures != dst->nfeatures) {
        MISMATCH(_("Target CPU feature count %zu does not match source %zu"),
                 dst->nfeatures, src->nfeatures);
        return false;
    }

    for (i = 0; i < src->nfeatures; i++) {
        if (STRNEQ(src->features[i].name, dst->features[i].name)) {
            MISMATCH(_("Target CPU feature %s does not match source %s"),
                     dst->features[i].name, src->features[i].name);
            return false;
        }

        if (src->features[i].policy != dst->features[i].policy) {
            MISMATCH(_("Target CPU feature policy %s does not match source %s"),
                     virCPUFeaturePolicyTypeToString(dst->features[i].policy),
                     virCPUFeaturePolicyTypeToString(src->features[i].policy));
            return false;
        }
    }

    if ((src->cache && !dst->cache) ||
        (!src->cache && dst->cache) ||
        (src->cache && dst->cache &&
         (src->cache->level != dst->cache->level ||
          src->cache->mode != dst->cache->mode))) {
        MISMATCH("%s", _("Target CPU cache does not match source"));
        return false;
    }

#undef MISMATCH

    return true;
}


/*
 * Parses a list of CPU XMLs into a NULL-terminated list of CPU defs.
 */
virCPUDef **
virCPUDefListParse(const char **xmlCPUs,
                   unsigned int ncpus,
                   virCPUType cpuType)
{
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virCPUDef **cpus = NULL;
    size_t i;

    VIR_DEBUG("xmlCPUs=%p, ncpus=%u", xmlCPUs, ncpus);

    if (xmlCPUs) {
        for (i = 0; i < ncpus; i++)
            VIR_DEBUG("xmlCPUs[%zu]=%s", i, NULLSTR(xmlCPUs[i]));
    }

    if (!xmlCPUs && ncpus != 0) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("nonzero ncpus doesn't match with NULL xmlCPUs"));
        goto error;
    }

    if (ncpus == 0) {
        virReportError(VIR_ERR_INVALID_ARG, "%s", _("no CPUs given"));
        goto error;
    }

    cpus = g_new0(virCPUDef *, ncpus + 1);

    for (i = 0; i < ncpus; i++) {
        if (!(doc = virXMLParseStringCtxt(xmlCPUs[i], _("(CPU_definition)"), &ctxt)))
            goto error;

        if (virCPUDefParseXML(ctxt, NULL, cpuType, &cpus[i], false) < 0)
            goto error;

        xmlXPathFreeContext(ctxt);
        xmlFreeDoc(doc);
        ctxt = NULL;
        doc = NULL;
    }

    return cpus;

 error:
    virCPUDefListFree(cpus);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(doc);
    return NULL;
}


/*
 * Frees NULL-terminated list of CPUs created by virCPUDefListParse.
 */
void
virCPUDefListFree(virCPUDef **cpus)
{
    virCPUDef **cpu;

    if (!cpus)
        return;

    for (cpu = cpus; *cpu != NULL; cpu++)
        virCPUDefFree(*cpu);

    g_free(cpus);
}
