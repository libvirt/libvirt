/*
 * Copyright (C) 2014 Red Hat, Inc.
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

#include "testutils.h"
#include "testutilsqemu.h"
#include "qemu/qemu_capabilities.h"


#define VIR_FROM_THIS VIR_FROM_NONE


typedef struct _testQemuData testQemuData;
struct _testQemuData {
    const char *inputDir;
    const char *outputDir;
    const char *prefix;
    const char *version;
    const char *archName;
    const char *suffix;
    int ret;
};

static int
testQemuDataInit(testQemuData *data)
{
    data->outputDir = abs_srcdir "/qemucaps2xmloutdata";

    data->ret = 0;

    return 0;
}

static virQEMUCaps *
testQemuGetCaps(char *caps)
{
    virQEMUCaps *qemuCaps = NULL;
    xmlDocPtr xml;
    xmlXPathContextPtr ctxt = NULL;
    ssize_t i, n;
    g_autofree xmlNodePtr *nodes = NULL;

    if (!(xml = virXMLParseStringCtxt(caps, "(test caps)", &ctxt)))
        goto error;

    if ((n = virXPathNodeSet("/qemuCaps/flag", ctxt, &nodes)) < 0) {
        fprintf(stderr, "failed to parse qemu capabilities flags");
        goto error;
    }

    if (!(qemuCaps = virQEMUCapsNew()))
        goto error;

    for (i = 0; i < n; i++) {
        g_autofree char *str = virXMLPropString(nodes[i], "name");
        if (str) {
            int flag = virQEMUCapsTypeFromString(str);
            if (flag < 0) {
                fprintf(stderr, "Unknown qemu capabilities flag %s", str);
                goto error;
            }
            virQEMUCapsSet(qemuCaps, flag);
        }
    }

    xmlFreeDoc(xml);
    xmlXPathFreeContext(ctxt);
    return qemuCaps;

 error:
    virObjectUnref(qemuCaps);
    xmlFreeDoc(xml);
    xmlXPathFreeContext(ctxt);
    return NULL;
}

static virCaps *
testGetCaps(char *capsData, const testQemuData *data)
{
    g_autoptr(virQEMUCaps) qemuCaps = NULL;
    virCaps *caps = NULL;
    virArch arch = virArchFromString(data->archName);
    g_autofree char *binary = NULL;

    binary = g_strdup_printf("/usr/bin/qemu-system-%s", data->archName);

    if ((qemuCaps = testQemuGetCaps(capsData)) == NULL) {
        fprintf(stderr, "failed to parse qemu capabilities flags");
        goto error;
    }

    if ((caps = virCapabilitiesNew(arch, false, false)) == NULL) {
        fprintf(stderr, "failed to create the fake capabilities");
        goto error;
    }

    if (virQEMUCapsInitGuestFromBinary(caps,
                                       binary,
                                       qemuCaps,
                                       arch) < 0) {
        fprintf(stderr, "failed to create the capabilities from qemu");
        goto error;
    }

    return caps;

 error:
    virObjectUnref(caps);
    return NULL;
}

static int
testQemuCapsXML(const void *opaque)
{
    const testQemuData *data = opaque;
    g_autofree char *capsFile = NULL;
    g_autofree char *xmlFile = NULL;
    g_autofree char *capsData = NULL;
    g_autofree char *capsXml = NULL;
    g_autoptr(virCaps) capsProvided = NULL;

    xmlFile = g_strdup_printf("%s/caps.%s.xml", data->outputDir, data->archName);

    capsFile = g_strdup_printf("%s/%s_%s.%s.%s",
                               data->inputDir, data->prefix, data->version,
                               data->archName, data->suffix);

    if (virTestLoadFile(capsFile, &capsData) < 0)
        return -1;

    if (!(capsProvided = testGetCaps(capsData, data)))
        return -1;

    capsXml = virCapabilitiesFormatXML(capsProvided);
    if (!capsXml)
        return -1;

    if (virTestCompareToFile(capsXml, xmlFile) < 0)
        return -1;

    return 0;
}

static int
doCapsTest(const char *inputDir,
           const char *prefix,
           const char *version,
           const char *archName,
           const char *suffix,
           void *opaque)
{
    testQemuData *data = (testQemuData *) opaque;
    g_autofree char *title = NULL;

    title = g_strdup_printf("%s (%s)", version, archName);

    data->inputDir = inputDir;
    data->prefix = prefix;
    data->version = version;
    data->archName = archName;
    data->suffix = suffix;

    if (virTestRun(title, testQemuCapsXML, data) < 0)
        data->ret = -1;

    return 0;
}

static int
mymain(void)
{
    testQemuData data;

    virEventRegisterDefaultImpl();

    if (testQemuDataInit(&data) < 0)
        return EXIT_FAILURE;

    if (testQemuCapsIterate(".xml", doCapsTest, &data) < 0)
        return EXIT_FAILURE;

    return (data.ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("qemucaps2xml"))
