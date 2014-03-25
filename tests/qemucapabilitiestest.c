/*
 * Copyright (C) 2011-2013 Red Hat, Inc.
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
 */

#include <config.h>

#include "testutils.h"
#include "testutilsqemu.h"
#include "qemumonitortestutils.h"


#define VIR_FROM_THIS VIR_FROM_NONE

typedef struct _testQemuData testQemuData;
typedef testQemuData *testQemuDataPtr;
struct _testQemuData {
    virDomainXMLOptionPtr xmlopt;
    const char *base;
    bool fips;
};

static qemuMonitorTestPtr
testQemuFeedMonitor(char *replies,
                    virDomainXMLOptionPtr xmlopt)
{
    qemuMonitorTestPtr test = NULL;
    char *tmp = replies;
    char *singleReply = tmp;

    /* Our JSON parser expects replies to be separated by a newline character.
     * Hence we must preprocess the file a bit. */
    while ((tmp = strchr(tmp, '\n'))) {
        /* It is safe to touch tmp[1] since all strings ends with '\0'. */
        bool eof = !tmp[1];

        if (*(tmp + 1) != '\n') {
            *tmp = ' ';
            tmp++;
        } else {
            /* Cut off a single reply. */
            *(tmp + 1) = '\0';

            if (test) {
                if (qemuMonitorTestAddItem(test, NULL, singleReply) < 0)
                    goto error;
            } else {
                /* Create new mocked monitor with our greeting */
                if (!(test = qemuMonitorTestNew(true, xmlopt, NULL, NULL, singleReply)))
                    goto error;
            }

            if (!eof) {
                /* Move the @tmp and @singleReply. */
                tmp += 2;
                singleReply = tmp;
            }
        }

        if (eof)
            break;
    }

    if (test && qemuMonitorTestAddItem(test, NULL, singleReply) < 0)
        goto error;

    return test;

 error:
    qemuMonitorTestFree(test);
    return NULL;
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

    if (n > 0) {
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

static int
testQemuCapsCompare(virQEMUCapsPtr capsProvided,
                    virQEMUCapsPtr capsComputed)
{
    int ret = 0;
    size_t i;

    for (i = 0; i < QEMU_CAPS_LAST; i++) {
        if (virQEMUCapsGet(capsProvided, i) &&
            !virQEMUCapsGet(capsComputed, i)) {
            fprintf(stderr, "Caps mismatch: capsComputed is missing %s\n",
                    virQEMUCapsTypeToString(i));
            ret = -1;
        }

        if (virQEMUCapsGet(capsComputed, i) &&
            !virQEMUCapsGet(capsProvided, i)) {
            fprintf(stderr, "Caps mismatch: capsProvided is missing %s\n",
                    virQEMUCapsTypeToString(i));
            ret = -1;
        }
    }

    return ret;
}

static int
testQemuCaps(const void *opaque)
{
    int ret = -1;
    const testQemuData *data = opaque;
    char *repliesFile = NULL, *capsFile = NULL;
    char *replies = NULL, *caps = NULL;
    qemuMonitorTestPtr mon = NULL;
    virQEMUCapsPtr capsProvided = NULL, capsComputed = NULL;

    if (virAsprintf(&repliesFile, "%s/qemucapabilitiesdata/%s.replies",
                    abs_srcdir, data->base) < 0 ||
        virAsprintf(&capsFile, "%s/qemucapabilitiesdata/%s.caps",
                    abs_srcdir, data->base) < 0)
        goto cleanup;

    if (virtTestLoadFile(repliesFile, &replies) < 0 ||
        virtTestLoadFile(capsFile, &caps) < 0)
        goto cleanup;

    if (!(mon = testQemuFeedMonitor(replies, data->xmlopt)))
        goto cleanup;

    if (!(capsProvided = testQemuGetCaps(caps)))
        goto cleanup;

    if (!(capsComputed = virQEMUCapsNew()))
        goto cleanup;

    if (virQEMUCapsInitQMPMonitor(capsComputed,
                                  qemuMonitorTestGetMonitor(mon)) < 0)
        goto cleanup;

    /* So that our test does not depend on the contents of /proc, we
     * hoisted the setting of ENABLE_FIPS to virQEMUCapsInitQMP.  But
     * we do want to test the effect of that flag.  */
    if (data->fips)
        virQEMUCapsSet(capsComputed, QEMU_CAPS_ENABLE_FIPS);

    if (testQemuCapsCompare(capsProvided, capsComputed) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(repliesFile);
    VIR_FREE(capsFile);
    VIR_FREE(replies);
    VIR_FREE(caps);
    qemuMonitorTestFree(mon);
    virObjectUnref(capsProvided);
    virObjectUnref(capsComputed);
    return ret;
}

static int
mymain(void)
{
    int ret = 0;
    virDomainXMLOptionPtr xmlopt;
    testQemuData data;

#if !WITH_YAJL
    fputs("libvirt not compiled with yajl, skipping this test\n", stderr);
    return EXIT_AM_SKIP;
#endif

    if (virThreadInitialize() < 0 ||
        !(xmlopt = virQEMUDriverCreateXMLConf(NULL)))
        return EXIT_FAILURE;

    virEventRegisterDefaultImpl();

    data.xmlopt = xmlopt;

#define DO_TEST_FULL(name, use_fips)                 \
    data.base = name;                                \
    data.fips = use_fips;                            \
    if (virtTestRun(name, testQemuCaps, &data) < 0)  \
        ret = -1

#define DO_TEST(name) DO_TEST_FULL(name, false)

    DO_TEST_FULL("caps_1.2.2-1", true);
    DO_TEST("caps_1.3.1-1");
    DO_TEST("caps_1.4.2-1");
    DO_TEST("caps_1.5.3-1");
    DO_TEST_FULL("caps_1.6.0-1", true);
    DO_TEST("caps_1.6.50-1");

    virObjectUnref(xmlopt);
    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
