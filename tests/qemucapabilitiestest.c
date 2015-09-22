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
    char *replies = NULL;
    qemuMonitorTestPtr mon = NULL;
    virQEMUCapsPtr capsProvided = NULL, capsComputed = NULL;

    if (virAsprintf(&repliesFile, "%s/qemucapabilitiesdata/%s.replies",
                    abs_srcdir, data->base) < 0 ||
        virAsprintf(&capsFile, "%s/qemucapabilitiesdata/%s.caps",
                    abs_srcdir, data->base) < 0)
        goto cleanup;

    if (virtTestLoadFile(repliesFile, &replies) < 0)
        goto cleanup;

    if (!(mon = testQemuFeedMonitor(replies, data->xmlopt)))
        goto cleanup;

    if (!(capsProvided = qemuTestParseCapabilities(capsFile)))
        goto cleanup;

    if (!(capsComputed = virQEMUCapsNew()))
        goto cleanup;

    if (virQEMUCapsInitQMPMonitor(capsComputed,
                                  qemuMonitorTestGetMonitor(mon)) < 0)
        goto cleanup;

    if (testQemuCapsCompare(capsProvided, capsComputed) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(repliesFile);
    VIR_FREE(capsFile);
    VIR_FREE(replies);
    qemuMonitorTestFree(mon);
    virObjectUnref(capsProvided);
    virObjectUnref(capsComputed);
    return ret;
}

static int
mymain(void)
{
    int ret = 0;
    virQEMUDriver driver;
    testQemuData data;

#if !WITH_YAJL
    fputs("libvirt not compiled with yajl, skipping this test\n", stderr);
    return EXIT_AM_SKIP;
#endif

    if (virThreadInitialize() < 0 ||
        qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    virEventRegisterDefaultImpl();

    data.xmlopt = driver.xmlopt;

#define DO_TEST(name)                                   \
    do {                                                \
        data.base = name;                               \
        if (virtTestRun(name, testQemuCaps, &data) < 0) \
            ret = -1;                                   \
    } while (0)

    DO_TEST("caps_1.2.2-1");
    DO_TEST("caps_1.3.1-1");
    DO_TEST("caps_1.4.2-1");
    DO_TEST("caps_1.5.3-1");
    DO_TEST("caps_1.6.0-1");
    DO_TEST("caps_1.6.50-1");
    DO_TEST("caps_2.1.1-1");

    qemuTestDriverFree(&driver);

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
