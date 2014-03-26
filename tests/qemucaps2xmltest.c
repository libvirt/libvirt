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
 *
 * Authors:
 *      Francesco Romani <fromani@redhat.com>
 */

#include <config.h>

#include "testutils.h"
#include "qemu/qemu_capabilities.h"


#define VIR_FROM_THIS VIR_FROM_NONE


static int
testCompareXMLToXML(const char *inxmldata, const char *outxmldata)
{
    int ret = 1;

    if (STRNEQ(outxmldata, inxmldata)) {
        virtTestDifference(stderr, outxmldata, inxmldata);
        goto cleanup;
    }

    ret = 0;
 cleanup:

    return ret;
}


typedef struct _testQemuData testQemuData;
typedef testQemuData *testQemuDataPtr;
struct _testQemuData {
    const char *base;
    virArch guestarch;
};

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

    if ((qemuCaps = testQemuGetCaps(capsData)) == NULL) {
        fprintf(stderr, "failed to parse qemu capabilities flags");
        goto error;
    }

    if ((caps = virCapabilitiesNew(data->guestarch, 0, 0)) == NULL) {
        fprintf(stderr, "failed to create the fake capabilities");
        goto error;
    }

    if (virQEMUCapsInitGuestFromBinary(caps,
                                       "/usr/bin/qemu-system-i386",
                                       qemuCaps,
                                       NULL,
                                       NULL,
                                       data->guestarch) < 0) {
        fprintf(stderr, "failed to create the capabilities from qemu");
        goto error;
    }

    virObjectUnref(qemuCaps);
    return caps;

 error:
    virObjectUnref(qemuCaps);
    return NULL;
}

static int
testQemuCapsXML(const void *opaque)
{
    int ret = -1;
    const testQemuData *data = opaque;
    char *capsFile = NULL, *xmlFile = NULL;
    char *capsData = NULL, *xmlData = NULL;
    char *capsXml = NULL;
    virCapsPtr capsProvided = NULL;

   if (virAsprintf(&xmlFile, "%s/qemucaps2xmldata/%s.xml",
                    abs_srcdir, data->base) < 0)
        goto cleanup;

    if (virAsprintf(&capsFile, "%s/qemucaps2xmldata/%s.caps",
                    abs_srcdir, data->base) < 0)
        goto cleanup;

    if (virtTestLoadFile(xmlFile, &xmlData) < 0)
        goto cleanup;

    if (virtTestLoadFile(capsFile, &capsData) < 0)
        goto cleanup;

    if (!(capsProvided = testGetCaps(capsData, data)))
        goto cleanup;

    capsXml = virCapabilitiesFormatXML(capsProvided);
    if (!capsXml)
        goto cleanup;

    ret = testCompareXMLToXML(capsXml, xmlData);

 cleanup:
    VIR_FREE(xmlFile);
    VIR_FREE(capsFile);
    VIR_FREE(capsXml);
    VIR_FREE(capsData);
    VIR_FREE(xmlData);
    virObjectUnref(capsProvided);
    return ret;
}

static int
mymain(void)
{
    int ret = 0;

    testQemuData data;

#if !WITH_YAJL
    fputs("libvirt not compiled with yajl, skipping this test\n", stderr);
    return EXIT_AM_SKIP;
#endif

    if (virThreadInitialize() < 0)
        return EXIT_FAILURE;

    virEventRegisterDefaultImpl();

#define DO_TEST_FULL(name, guest)                       \
    data.base = name;                                   \
    data.guestarch = guest;                             \
    if (virtTestRun(name, testQemuCapsXML, &data) < 0)  \
        ret = -1

#define DO_TEST(name) DO_TEST_FULL(name, VIR_ARCH_I686)

    DO_TEST("all_1.6.0-1");
    DO_TEST("nodisksnapshot_1.6.0-1");

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
