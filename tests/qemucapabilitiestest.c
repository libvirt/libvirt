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
#define LIBVIRT_QEMU_CAPSPRIV_H_ALLOW
#include "qemu/qemu_capspriv.h"
#define LIBVIRT_QEMU_MONITOR_PRIV_H_ALLOW
#include "qemu/qemu_monitor_priv.h"
#define LIBVIRT_QEMU_PROCESSPRIV_H_ALLOW
#include "qemu/qemu_processpriv.h"

#define VIR_FROM_THIS VIR_FROM_NONE

typedef struct _testQemuData testQemuData;
struct _testQemuData {
    virQEMUDriver driver;
    const char *inputDir;
    const char *outputDir;
    const char *prefix;
    const char *version;
    const char *archName;
    const char *variant;
    const char *suffix;
    int ret;
};

bool isHVF = false;

bool
virQEMUCapsProbeHVF(virQEMUCaps *qemuCaps G_GNUC_UNUSED)
{
    return isHVF;
}


static int
testQemuDataInit(testQemuData *data)
{
    if (qemuTestDriverInit(&data->driver) < 0)
        return -1;

    data->outputDir = TEST_QEMU_CAPS_PATH;

    data->ret = 0;

    return 0;
}


static void
testQemuDataReset(testQemuData *data)
{
    qemuTestDriverFree(&data->driver);
}


static int
testQemuCaps(const void *opaque)
{
    testQemuData *data = (void *) opaque;
    g_autofree char *repliesFile = NULL;
    g_autofree char *capsFile = NULL;
    g_autoptr(qemuMonitorTest) mon = NULL;
    g_autoptr(virQEMUCaps) capsActual = NULL;
    g_autofree char *binary = NULL;
    g_autofree char *actual = NULL;
    unsigned int fakeMicrocodeVersion = 0;
    const char *p;

    repliesFile = g_strdup_printf("%s/%s_%s_%s%s.%s",
                                  data->inputDir, data->prefix, data->version,
                                  data->archName, data->variant, data->suffix);
    capsFile = g_strdup_printf("%s/%s_%s_%s%s.xml",
                               data->outputDir, data->prefix, data->version,
                               data->archName, data->variant);

    if (!(mon = qemuMonitorTestNewFromFileFull(repliesFile, &data->driver, NULL,
                                               NULL)))
        return -1;

    isHVF = STREQ(data->variant, "+hvf");

    if (qemuProcessQMPInitMonitor(qemuMonitorTestGetMonitor(mon)) < 0)
        return -1;

    binary = g_strdup_printf("/usr/bin/qemu-system-%s",
                             data->archName);

    capsActual = virQEMUCapsNewBinary(binary);

    if (virQEMUCapsInitQMPMonitor(capsActual, qemuMonitorTestGetMonitor(mon)) < 0)
        return -1;

    if (virQEMUCapsHaveAccel(capsActual) &&
        virQEMUCapsGet(capsActual, QEMU_CAPS_TCG)) {
        qemuMonitorResetCommandID(qemuMonitorTestGetMonitor(mon));

        if (qemuProcessQMPInitMonitor(qemuMonitorTestGetMonitor(mon)) < 0)
            return -1;

        if (virQEMUCapsInitQMPMonitorTCG(capsActual,
                                         qemuMonitorTestGetMonitor(mon)) < 0)
            return -1;

        /* calculate fake microcode version based on filename for a reproducible
         * number for testing which does not change with the contents */
        for (p = data->archName; *p; p++)
            fakeMicrocodeVersion += *p;

        fakeMicrocodeVersion *= 100000;

        for (p = data->version; *p; p++)
            fakeMicrocodeVersion += *p;

        virQEMUCapsSetMicrocodeVersion(capsActual, fakeMicrocodeVersion);
    }

    if (!(actual = virQEMUCapsFormatCache(capsActual)))
        return -1;

    if (virTestCompareToFile(actual, capsFile) < 0)
        return -1;

    return 0;
}


static int
testQemuCapsCopy(const void *opaque)
{
    const testQemuData *data = opaque;
    g_autofree char *capsFile = NULL;
    g_autoptr(virQEMUCaps) orig = NULL;
    g_autoptr(virQEMUCaps) copy = NULL;
    g_autofree char *actual = NULL;

    capsFile = g_strdup_printf("%s/%s_%s_%s%s.xml",
                               data->outputDir, data->prefix, data->version,
                               data->archName, data->variant);

    if (!(orig = qemuTestParseCapabilitiesArch(
              virArchFromString(data->archName), capsFile)))
        return -1;

    copy = virQEMUCapsNewCopy(orig);

    if (!(actual = virQEMUCapsFormatCache(copy)))
        return -1;

    if (virTestCompareToFile(actual, capsFile) < 0)
        return -1;

    return 0;
}


static int
doCapsTest(const char *inputDir,
           const char *prefix,
           const char *version,
           const char *archName,
           const char *variant,
           const char *suffix,
           void *opaque)
{
    testQemuData *data = (testQemuData *) opaque;
    g_autofree char *title = NULL;
    g_autofree char *copyTitle = NULL;

    title = g_strdup_printf("%s (%s)", version, archName);
    copyTitle = g_strdup_printf("copy %s (%s)", version, archName);

    data->inputDir = inputDir;
    data->prefix = prefix;
    data->version = version;
    data->archName = archName;
    data->variant = variant,
    data->suffix = suffix;

    if (virTestRun(title, testQemuCaps, data) < 0)
        data->ret = -1;

    if (virTestRun(copyTitle, testQemuCapsCopy, data) < 0)
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

    if (testQemuCapsIterate(".replies", doCapsTest, &data) < 0)
        return EXIT_FAILURE;

    /* See documentation in qemucapabilitiesdata/README.rst */

    testQemuDataReset(&data);

    return (data.ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain,
                      VIR_TEST_MOCK("domaincaps"))
