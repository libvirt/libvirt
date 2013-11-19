/*
 * sysinfotest.c: Testcase(s) for virSysinfoRead
 *
 * Copyright (C) 2013 Red Hat, Inc.
 * Copyright IBM Corp. 2012
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
 *      Viktor Mihajlovski <mihajlov@linux.vnet.ibm.com>
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "internal.h"

#include "virbuffer.h"
#include "virsysinfo.h"
#include "testutils.h"
#include "virfile.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#if defined (__linux__)

# if defined(__s390__) || defined(__s390x__) || \
     defined(__powerpc__) || defined(__powerpc64__) || \
     defined(__i386__) || defined(__x86_64__) || defined(__amd64__) || \
     defined(__arm__) || defined(__aarch64__)

/* from sysinfo.c */
void virSysinfoSetup(const char *decoder,
                     const char *sysinfo,
                     const char *cpuinfo);

struct testSysinfoData {
    char *decoder; /* name of dmi decoder binary/script */
    char *sysinfo; /* name of /proc/sysinfo substitute file */
    char *cpuinfo; /* name of /proc/cpuinfo substitute file */
    char *expected; /* (required) file containing output of virSysinfoFormat */
};

static int
testSysinfo(const void *data)
{
    int result = -1;
    char *sysfsExpectData = NULL;
    const char *sysfsActualData;
    virSysinfoDefPtr ret = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const struct testSysinfoData *testdata = data;

    virSysinfoSetup(testdata->decoder, testdata->sysinfo, testdata->cpuinfo);

    if (!testdata->expected ||
        virtTestLoadFile(testdata->expected, &sysfsExpectData) < 0 ||
        !(ret = virSysinfoRead())) {
        goto cleanup;
    }

    if (virSysinfoFormat(&buf, ret) < 0)
        goto cleanup;

    if (!(sysfsActualData = virBufferCurrentContent(&buf)))
        goto cleanup;

    if (STRNEQ(sysfsActualData, sysfsExpectData)) {
        virtTestDifference(stderr, sysfsActualData, sysfsExpectData);
        goto cleanup;
    }

    result = 0;

cleanup:
    VIR_FREE(sysfsExpectData);
    virSysinfoDefFree(ret);
    virBufferFreeAndReset(&buf);

    return result;
}

static int
sysinfotest_run(const char *test,
                const char *decoder,
                const char *sysinfo,
                const char *cpuinfo,
                const char *expected)
{
    struct testSysinfoData testdata = { NULL };
    int ret = EXIT_FAILURE;

    if ((decoder &&
         virAsprintf(&testdata.decoder, "%s/%s", abs_srcdir, decoder) < 0) ||
        (sysinfo &&
         virAsprintf(&testdata.sysinfo, "%s/%s", abs_srcdir, sysinfo) < 0) ||
        (cpuinfo &&
         virAsprintf(&testdata.cpuinfo, "%s/%s", abs_srcdir, cpuinfo) < 0) ||
        (expected &&
         virAsprintf(&testdata.expected, "%s/%s", abs_srcdir, expected) < 0)) {
        goto error;
    }

    if (virtTestRun(test, testSysinfo, &testdata) < 0)
        goto error;

    ret = EXIT_SUCCESS;

error:
    VIR_FREE(testdata.decoder);
    VIR_FREE(testdata.sysinfo);
    VIR_FREE(testdata.cpuinfo);
    VIR_FREE(testdata.expected);
    return ret;
}
# endif

# if defined(__s390__) || defined(__s390x__)
static int
test_s390(void)
{
    return sysinfotest_run("s390 sysinfo",
                           NULL,
                           "/sysinfodata/s390sysinfo.data",
                           "/sysinfodata/s390cpuinfo.data",
                           "/sysinfodata/s390sysinfo.expect");
}

VIRT_TEST_MAIN(test_s390)
# elif defined(__powerpc__) || defined(__powerpc64__)
static int
test_ppc(void)
{
    return sysinfotest_run("ppc sysinfo",
                           NULL,
                           NULL,
                           "/sysinfodata/ppccpuinfo.data",
                           "/sysinfodata/ppcsysinfo.expect");
}

VIRT_TEST_MAIN(test_ppc)
# elif defined(__i386__) || defined(__x86_64__) || defined(__amd64__)
static int
test_x86(void)
{
    return sysinfotest_run("x86 sysinfo",
                           "/sysinfodata/dmidecode.sh",
                           NULL,
                           NULL,
                           "/sysinfodata/x86sysinfo.expect");
}

VIRT_TEST_MAIN(test_x86)
# elif defined(__arm__)
static int
test_arm(void)
{
    return sysinfotest_run("arm sysinfo",
                           NULL,
                           NULL,
                           "/sysinfodata/armcpuinfo.data",
                           "/sysinfodata/armsysinfo.expect");
}

VIRT_TEST_MAIN(test_arm)
# elif defined(__aarch64__)
static int
test_aarch64(void)
{
    return sysinfotest_run("aarch64 sysinfo",
                           NULL,
                           NULL,
                           "/sysinfodata/aarch64cpuinfo.data",
                           "/sysinfodata/aarch64sysinfo.expect");
}

VIRT_TEST_MAIN(test_aarch64)
# else
int
main(void)
{
    return EXIT_AM_SKIP;
}
# endif /* defined(__s390__) ... */
#else
int
main(void)
{
    return EXIT_AM_SKIP;
}
#endif /* defined(__linux__) */
