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


typedef struct _testQemuData testQemuData;
typedef testQemuData *testQemuDataPtr;
struct _testQemuData {
    const char *base;
    const char *archName;
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
    virArch arch = virArchFromString(data->archName);
    char *binary = NULL;

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
    VIR_FREE(binary);
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

    if (virAsprintf(&xmlFile, "%s/qemucaps2xmloutdata/%s.%s.xml",
                    abs_srcdir, data->base, data->archName) < 0)
        goto cleanup;

    if (virAsprintf(&capsFile, "%s/qemucapabilitiesdata/%s.%s.xml",
                    abs_srcdir, data->base, data->archName) < 0)
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
mymain(void)
{
    int ret = 0;

    testQemuData data;

#if !WITH_YAJL
    fputs("libvirt not compiled with JSON support, skipping this test\n", stderr);
    return EXIT_AM_SKIP;
#endif

    if (virThreadInitialize() < 0)
        return EXIT_FAILURE;

    virEventRegisterDefaultImpl();

#define DO_TEST(arch, name) \
    data.archName = arch; \
    data.base = name; \
    if (virTestRun(name "(" arch ")", testQemuCapsXML, &data) < 0) \
        ret = -1

    /* Keep this in sync with qemucapabilitiestest */
    DO_TEST("x86_64", "caps_1.5.3");
    DO_TEST("x86_64", "caps_1.6.0");
    DO_TEST("x86_64", "caps_1.7.0");
    DO_TEST("x86_64", "caps_2.1.1");
    DO_TEST("x86_64", "caps_2.4.0");
    DO_TEST("x86_64", "caps_2.5.0");
    DO_TEST("x86_64", "caps_2.6.0");
    DO_TEST("x86_64", "caps_2.7.0");
    DO_TEST("x86_64", "caps_2.8.0");
    DO_TEST("x86_64", "caps_2.9.0");
    DO_TEST("x86_64", "caps_2.10.0");
    DO_TEST("x86_64", "caps_2.11.0");
    DO_TEST("x86_64", "caps_2.12.0");
    DO_TEST("x86_64", "caps_3.0.0");
    DO_TEST("x86_64", "caps_3.1.0");
    DO_TEST("aarch64", "caps_2.6.0");
    DO_TEST("aarch64", "caps_2.10.0");
    DO_TEST("aarch64", "caps_2.12.0");
    DO_TEST("ppc64", "caps_2.6.0");
    DO_TEST("ppc64", "caps_2.9.0");
    DO_TEST("ppc64", "caps_2.10.0");
    DO_TEST("ppc64", "caps_2.12.0");
    DO_TEST("ppc64", "caps_3.0.0");
    DO_TEST("ppc64", "caps_3.1.0");
    DO_TEST("s390x", "caps_2.7.0");
    DO_TEST("s390x", "caps_2.8.0");
    DO_TEST("s390x", "caps_2.9.0");
    DO_TEST("s390x", "caps_2.10.0");
    DO_TEST("s390x", "caps_2.11.0");
    DO_TEST("s390x", "caps_2.12.0");
    DO_TEST("s390x", "caps_3.0.0");
    DO_TEST("riscv32", "caps_3.0.0");
    DO_TEST("riscv64", "caps_3.0.0");

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, abs_builddir "/.libs/qemucaps2xmlmock.so")
