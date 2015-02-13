/*
 * cpu_map.c: internal functions for handling CPU mapping configuration
 *
 * Copyright (C) 2009-2010 Red Hat, Inc.
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

#include "viralloc.h"
#include "virfile.h"
#include "cpu.h"
#include "cpu_map.h"
#include "configmake.h"
#include "virstring.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_CPU

VIR_LOG_INIT("cpu.cpu_map");

VIR_ENUM_IMPL(cpuMapElement, CPU_MAP_ELEMENT_LAST,
    "vendor",
    "feature",
    "model")


static int load(xmlXPathContextPtr ctxt,
                cpuMapElement element,
                cpuMapLoadCallback callback,
                void *data)
{
    int ret = -1;
    xmlNodePtr ctxt_node;
    xmlNodePtr cur;

    ctxt_node = ctxt->node;

    cur = ctxt_node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE &&
            xmlStrEqual(cur->name,
                        BAD_CAST cpuMapElementTypeToString(element))) {
            ctxt->node = cur;
            if (callback(element, ctxt, data) < 0)
                goto cleanup;
        }

        cur = cur->next;
    }

    ret = 0;

 cleanup:
    ctxt->node = ctxt_node;

    return ret;
}


int cpuMapLoad(const char *arch,
               cpuMapLoadCallback cb,
               void *data)
{
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *xpath = NULL;
    int ret = -1;
    int element;
    char *mapfile;

    if (!(mapfile = virFileFindResource("cpu_map.xml",
                                        abs_topsrcdir "/src/cpu",
                                        PKGDATADIR)))
        return -1;

    VIR_DEBUG("Loading CPU map from %s", mapfile);

    if (arch == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("undefined hardware architecture"));
        goto cleanup;
    }

    if (cb == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("no callback provided"));
        goto cleanup;
    }

    if ((xml = xmlParseFile(mapfile)) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot parse CPU map file: %s"),
                       mapfile);
        goto cleanup;
    }

    if ((ctxt = xmlXPathNewContext(xml)) == NULL) {
        virReportOOMError();
        goto cleanup;
    }

    virBufferAsprintf(&buf, "./arch[@name='%s']", arch);
    if (virBufferCheckError(&buf) < 0)
        goto cleanup;

    xpath = virBufferContentAndReset(&buf);

    ctxt->node = xmlDocGetRootElement(xml);

    if ((ctxt->node = virXPathNode(xpath, ctxt)) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot find CPU map for %s architecture"), arch);
        goto cleanup;
    }

    for (element = 0; element < CPU_MAP_ELEMENT_LAST; element++) {
        if (load(ctxt, element, cb, data) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot parse CPU map for %s architecture"), arch);
            goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    VIR_FREE(xpath);
    VIR_FREE(mapfile);

    return ret;
}
