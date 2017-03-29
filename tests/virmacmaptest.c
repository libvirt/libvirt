/*
 * Copyright (C) 2016 Red Hat, Inc.
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
 * Author: Michal Privoznik <mprivozn@redhat.com>
 */

#include <config.h>

#include "testutils.h"
#include "virmacmap.h"

#define VIR_FROM_THIS VIR_FROM_NONE

struct testData {
    const char *file;
    const char *domain;
    const char * const * macs;
    virMacMapPtr mgr;
};


static int
testMACLookup(const void *opaque)
{
    const struct testData *data = opaque;
    virMacMapPtr mgr = NULL;
    const char * const * macs;
    size_t i, j;
    char *file = NULL;
    int ret = -1;

    if (virAsprintf(&file, "%s/virmacmaptestdata/%s.json",
                    abs_srcdir, data->file) < 0)
        goto cleanup;

    if (!(mgr = virMacMapNew(file)))
        goto cleanup;

    macs = virMacMapLookup(mgr, data->domain);

    for (i = 0; macs && macs[i]; i++) {
        for (j = 0; data->macs && data->macs[j]; j++) {
            if (STREQ(macs[i], data->macs[j]))
                break;
        }

        if (!data->macs || !data->macs[j]) {
            fprintf(stderr,
                    "Unexpected %s in the returned list of MACs\n", macs[i]);
            goto cleanup;
        }
    }

    for (i = 0; data->macs && data->macs[i]; i++) {
        for (j = 0; macs && macs[j]; j++) {
            if (STREQ(data->macs[i], macs[j]))
                break;
        }

        if (!macs || !macs[j]) {
            fprintf(stderr,
                    "Expected %s in the returned list of MACs\n", data->macs[i]);
            goto cleanup;
        }
    }

    ret = 0;
 cleanup:
    VIR_FREE(file);
    virObjectUnref(mgr);
    return ret;
}


static int
testMACRemove(const void *opaque)
{
    const struct testData *data = opaque;
    virMacMapPtr mgr = NULL;
    const char * const * macs;
    size_t i;
    char *file = NULL;
    int ret = -1;

    if (virAsprintf(&file, "%s/virmacmaptestdata/%s.json",
                    abs_srcdir, data->file) < 0)
        goto cleanup;

    if (!(mgr = virMacMapNew(file)))
        goto cleanup;

    for (i = 0; data->macs && data->macs[i]; i++) {
        if (virMacMapRemove(mgr, data->domain, data->macs[i]) < 0) {
            fprintf(stderr,
                    "Error when removing %s from the list of MACs\n", data->macs[i]);
            goto cleanup;
        }
    }

    if ((macs = virMacMapLookup(mgr, data->domain))) {
        fprintf(stderr,
                "Not removed all MACs for domain %s: %s\n", data->domain, macs[0]);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(file);
    virObjectUnref(mgr);
    return ret;
}


static int
testMACFlush(const void *opaque)
{
    const struct testData *data = opaque;
    char *file = NULL;
    char *str = NULL;
    int ret = -1;

    if (virAsprintf(&file, "%s/virmacmaptestdata/%s.json",
                    abs_srcdir, data->file) < 0)
        goto cleanup;

    if (virMacMapDumpStr(data->mgr, &str) < 0)
        goto cleanup;

    if (virTestCompareToFile(str, file) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(file);
    VIR_FREE(str);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;
    virMacMapPtr mgr = NULL;

#define DO_TEST_BASIC(f, d, ...)                                    \
    do {                                                            \
        const char * const m[] = {__VA_ARGS__, NULL };              \
        struct testData data = {.file = f, .domain = d, .macs = m}; \
        if (virTestRun("Lookup " #d " in " #f,                      \
                       testMACLookup, &data) < 0)                   \
            ret = -1;                                               \
        if (virTestRun("Remove " #d " in " #f,                      \
                       testMACRemove, &data) < 0)                   \
            ret = -1;                                               \
    } while (0)

#define DO_TEST_FLUSH_PROLOGUE                                      \
    do {                                                            \
        if (!(mgr = virMacMapNew(NULL))) {                          \
            ret = -1;                                               \
            goto cleanup;                                           \
        }                                                           \
    } while (0)

#define DO_TEST_FLUSH(d, ...)                                       \
    do {                                                            \
        const char * const m[] = {__VA_ARGS__, NULL };              \
        size_t i;                                                   \
        for (i = 0; m[i]; i++)  {                                   \
            if (virMacMapAdd(mgr, d, m[i]) < 0) {                   \
                virObjectUnref(mgr);                                \
                mgr = NULL;                                         \
                ret = -1;                                           \
            }                                                       \
        }                                                           \
    } while (0)


#define DO_TEST_FLUSH_EPILOGUE(f)                                   \
    do {                                                            \
        struct testData data = {.file = f, .mgr = mgr};             \
        if (virTestRun("Flush " #f, testMACFlush, &data) < 0)       \
            ret = -1;                                               \
        virObjectUnref(mgr);                                        \
        mgr = NULL;                                                 \
    } while (0)

    DO_TEST_BASIC("empty", "none", NULL);
    DO_TEST_BASIC("simple", "f24", "aa:bb:cc:dd:ee:ff");
    DO_TEST_BASIC("simple2", "f24", "aa:bb:cc:dd:ee:ff", "a1:b2:c3:d4:e5:f6");
    DO_TEST_BASIC("simple2", "f25", "00:11:22:33:44:55", "aa:bb:cc:00:11:22");

    DO_TEST_FLUSH_PROLOGUE;
    DO_TEST_FLUSH_EPILOGUE("empty");

    DO_TEST_FLUSH_PROLOGUE;
    DO_TEST_FLUSH("f24", "aa:bb:cc:dd:ee:ff");
    DO_TEST_FLUSH_EPILOGUE("simple");

    DO_TEST_FLUSH_PROLOGUE;
    DO_TEST_FLUSH("f24", "aa:bb:cc:dd:ee:ff", "a1:b2:c3:d4:e5:f6");
    DO_TEST_FLUSH("f25", "00:11:22:33:44:55", "aa:bb:cc:00:11:22");
    DO_TEST_FLUSH_EPILOGUE("simple2");

    DO_TEST_FLUSH_PROLOGUE;
    DO_TEST_FLUSH("dom0", "e1:81:5d:f3:41:57", "76:0a:2a:a0:51:86", "01:c7:fc:01:c7:fc");
    DO_TEST_FLUSH("dom0", "8e:82:53:60:32:4a", "14:7a:25:dc:7d:a0", "f8:d7:75:f8:d7:75");
    DO_TEST_FLUSH("dom0", "73:d2:50:fb:0f:b1", "82:ee:a7:9b:e3:69", "a8:b4:cb:a8:b4:cb");
    DO_TEST_FLUSH("dom0", "7e:81:86:0f:0b:fb", "94:e2:00:d9:4c:70", "dc:7b:83:dc:7b:83");
    DO_TEST_FLUSH("dom0", "d1:19:a5:a1:52:a8", "22:03:a0:bf:cb:4a", "e3:c7:f8:e3:c7:f8");
    DO_TEST_FLUSH("dom0", "aa:bf:3f:4f:21:8d", "28:67:45:72:8f:47", "eb:08:cd:eb:08:cd");
    DO_TEST_FLUSH("dom0", "bd:f8:a7:e5:e2:bd", "c7:80:e3:b9:18:4d", "ce:da:c0:ce:da:c0");
    DO_TEST_FLUSH("dom1", "8b:51:1d:9f:2f:29", "7c:ae:4c:3e:e1:11", "c6:68:4e:98:ff:6a");
    DO_TEST_FLUSH("dom1", "43:0e:33:a1:3f:0f", "7a:3e:ed:bb:15:27", "b1:17:fd:95:d2:1b");
    DO_TEST_FLUSH("dom1", "9e:89:49:99:51:0e", "89:b4:3f:08:88:2c", "54:0b:4c:e2:0a:39");
    DO_TEST_FLUSH("dom1", "bb:88:07:19:51:9d", "b7:f1:1a:40:a2:95", "88:94:39:a3:90:b4");
    DO_TEST_FLUSH_EPILOGUE("complex");
 cleanup:
    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, abs_builddir "/.libs/virmacmapmock.so")
