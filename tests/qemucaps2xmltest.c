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
typedef testQemuData *testQemuDataPtr;
struct _testQemuData {
    const char *inputDir;
    const char *outputDir;
    const char *base;
    const char *archName;
    int ret;
};

static int
testQemuDataInit(testQemuDataPtr data)
{
    data->inputDir = TEST_QEMU_CAPS_PATH;
    data->outputDir = abs_srcdir "/qemucaps2xmloutdata";

    data->ret = 0;

    return 0;
}

static virQEMUCapsPtr
testQemuGetCaps(char *caps)
{
    virQEMUCapsPtr qemuCaps = NULL;
    xmlDocPtr xml;
    xmlXPathContextPtr ctxt = NULL;
    ssize_t i, n;
    xmlNodePtr *nodes = NULL;

    if (!(xml = virXMLParseStringCtxt(caps, "(test caps)", &ctxt)))
        goto error;

    if ((n = virXPathNodeSet("/qemuCaps/flag", ctxt, &nodes)) < 0) {
        fprintf(stderr, "failed to parse qemu capabilities flags");
        goto error;
    }

    if (!(qemuCaps = virQEMUCapsNew()))
        goto error;

    for (i = 0; i < n; i++) {
        char *str = virXMLPropString(nodes[i], "name");
        if (str) {
            int flag = virQEMUCapsTypeFromString(str);
            if (flag < 0) {
                fprintf(stderr, "Unknown qemu capabilities flag %s", str);
                VIR_FREE(str);
                goto error;
            }
            VIR_FREE(str);
            virQEMUCapsSet(qemuCaps, flag);
        }
    }

    VIR_FREE(nodes);
    xmlFreeDoc(xml);
    xmlXPathFreeContext(ctxt);
    return qemuCaps;

 error:
    VIR_FREE(nodes);
    virObjectUnref(qemuCaps);
    xmlFreeDoc(xml);
    xmlXPathFreeContext(ctxt);
    return NULL;
}

static virCapsPtr
testGetCaps(char *capsData, const testQemuData *data)
{
    virQEMUCapsPtr qemuCaps = NULL;
    virCapsPtr caps = NULL;
    virArch arch = virArchFromString(data->archName);
    VIR_AUTOFREE(char *) binary = NULL;

    if (virAsprintf(&binary, "/usr/bin/qemu-system-%s", data->archName) < 0)
        goto error;

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

    virObjectUnref(qemuCaps);
    return caps;

 error:
    virObjectUnref(qemuCaps);
    virObjectUnref(caps);
    return NULL;
}

static int
testQemuCapsXML(const void *opaque)
{
    int ret = -1;
    const testQemuData *data = opaque;
    char *capsFile = NULL, *xmlFile = NULL;
    char *capsData = NULL;
    char *capsXml = NULL;
    virCapsPtr capsProvided = NULL;

    if (virAsprintf(&xmlFile, "%s/caps.%s.xml",
                    data->outputDir, data->archName) < 0)
        goto cleanup;

    if (virAsprintf(&capsFile, "%s/%s.%s.xml",
                    data->inputDir, data->base, data->archName) < 0)
        goto cleanup;

    if (virTestLoadFile(capsFile, &capsData) < 0)
        goto cleanup;

    if (!(capsProvided = testGetCaps(capsData, data)))
        goto cleanup;

    capsXml = virCapabilitiesFormatXML(capsProvided);
    if (!capsXml)
        goto cleanup;

    if (virTestCompareToFile(capsXml, xmlFile) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(xmlFile);
    VIR_FREE(capsFile);
    VIR_FREE(capsXml);
    VIR_FREE(capsData);
    virObjectUnref(capsProvided);
    return ret;
}

static int
doCapsTest(const char *base,
           const char *archName,
           void *opaque)
{
    testQemuDataPtr data = (testQemuDataPtr) opaque;
    VIR_AUTOFREE(char *) title = NULL;

    if (virAsprintf(&title, "%s (%s)", base, archName) < 0)
        return -1;

    data->base = base;
    data->archName = archName;

    if (virTestRun(title, testQemuCapsXML, data) < 0)
        data->ret = -1;

    return 0;
}

static int
mymain(void)
{
    testQemuData data;

#if !WITH_YAJL
    fputs("libvirt not compiled with JSON support, skipping this test\n", stderr);
    return EXIT_AM_SKIP;
#endif

    virEventRegisterDefaultImpl();

    if (testQemuDataInit(&data) < 0)
        return EXIT_FAILURE;

    if (testQemuCapsIterate(".xml", doCapsTest, &data) < 0)
        return EXIT_FAILURE;

    return (data.ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("qemucaps2xml"))
