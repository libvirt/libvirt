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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Authors:
 *      Jiri Denemark <jdenemar@redhat.com>
 */

#include <config.h>

#include "memory.h"
#include "cpu.h"
#include "cpu_map.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_CPU

#define CPUMAPFILE PKGDATADIR "/cpu_map.xml"

static char *cpumap;

VIR_ENUM_IMPL(cpuMapElement, CPU_MAP_ELEMENT_LAST,
    "vendor",
    "feature",
    "model")


static int load(xmlXPathContextPtr ctxt,
                enum cpuMapElement element,
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
    const char *mapfile = (cpumap ? cpumap : CPUMAPFILE);

    if (arch == NULL) {
        virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                          "%s", _("undefined hardware architecture"));
        return -1;
    }

    if (cb == NULL) {
        virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                          "%s", _("no callback provided"));
        return -1;
    }

    if ((xml = xmlParseFile(mapfile)) == NULL) {
        virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                _("cannot parse CPU map file: %s"),
                mapfile);
        goto cleanup;
    }

    if ((ctxt = xmlXPathNewContext(xml)) == NULL)
        goto no_memory;

    virBufferAsprintf(&buf, "./arch[@name='%s']", arch);
    if (virBufferError(&buf))
        goto no_memory;

    xpath = virBufferContentAndReset(&buf);

    ctxt->node = xmlDocGetRootElement(xml);

    if ((ctxt->node = virXPathNode(xpath, ctxt)) == NULL) {
        virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                _("cannot find CPU map for %s architecture"), arch);
        goto cleanup;
    }

    for (element = 0; element < CPU_MAP_ELEMENT_LAST; element++) {
        if (load(ctxt, element, cb, data) < 0) {
            virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                    _("cannot parse CPU map for %s architecture"), arch);
            goto cleanup;
        }
    }

    ret = 0;

cleanup:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    VIR_FREE(xpath);

    return ret;

no_memory:
    virReportOOMError();
    goto cleanup;
}


int
cpuMapOverride(const char *path)
{
    char *map;

    if (!(map = strdup(path)))
        return -1;

    VIR_FREE(cpumap);
    cpumap = map;
    return 0;
}
