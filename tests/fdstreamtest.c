/*
 * Copyright (C) 2013 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <fcntl.h>

#include "testutils.h"

#include "virfdstream.h"
#include "datatypes.h"
#include "virlog.h"
#include "virfile.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.fdstreamtest");

#define PATTERN_LEN 256

static int testFDStreamReadCommon(const char *scratchdir, bool blocking)
{
    VIR_AUTOCLOSE fd = -1;
    g_autofree char *file = NULL;
    int ret = -1;
    g_autofree char *pattern = NULL;
    g_autofree char *buf = NULL;
    virStreamPtr st = NULL;
    size_t i;
    virConnectPtr conn = NULL;
    int flags = 0;

    if (!blocking)
        flags |= VIR_STREAM_NONBLOCK;

    if (!(conn = virConnectOpen("test:///default")))
        goto cleanup;

    pattern = g_new0(char, PATTERN_LEN);
    buf = g_new0(char, PATTERN_LEN);

    for (i = 0; i < PATTERN_LEN; i++)
        pattern[i] = i;

    file = g_strdup_printf("%s/input.data", scratchdir);

    if ((fd = open(file, O_CREAT|O_WRONLY|O_EXCL, 0600)) < 0)
        goto cleanup;

    for (i = 0; i < 10; i++) {
        if (safewrite(fd, pattern, PATTERN_LEN) != PATTERN_LEN)
            goto cleanup;
    }

    if (VIR_CLOSE(fd) < 0)
        goto cleanup;

    if (!(st = virStreamNew(conn, flags)))
        goto cleanup;

    /* Start reading 1/2 way through first pattern
     * and end 1/2 way through last pattern
     */
    if (virFDStreamOpenFile(st, file,
                            PATTERN_LEN / 2, PATTERN_LEN * 9,
                            O_RDONLY) < 0)
        goto cleanup;

    for (i = 0; i < 10; i++) {
        size_t offset = 0;
        size_t want;
        if (i == 0)
            want = PATTERN_LEN / 2;
        else
            want = PATTERN_LEN;

        while (want > 0) {
            int got;
        reread:
            got = st->driver->streamRecv(st, buf + offset, want);
            if (got < 0) {
                if (got == -2 && !blocking) {
                    g_usleep(20 * 1000);
                    goto reread;
                }
                fprintf(stderr, "Failed to read stream: %s\n",
                        virGetLastErrorMessage());
                goto cleanup;
            }
            if (got == 0) {
                /* Expect EOF 1/2 through last pattern */
                if (i == 9 && want == (PATTERN_LEN / 2))
                    break;
                fprintf(stderr, "Unexpected EOF block %zu want %zu\n",
                        i, want);
                goto cleanup;
            }
            offset += got;
            want -= got;
        }
        if (i == 0) {
            if (memcmp(buf, pattern + (PATTERN_LEN / 2), PATTERN_LEN / 2) != 0) {
                fprintf(stderr, "Mismatched pattern data iteration %zu\n", i);
                goto cleanup;
            }
        } else if (i == 9) {
            if (memcmp(buf, pattern, PATTERN_LEN / 2) != 0) {
                fprintf(stderr, "Mismatched pattern data iteration %zu\n", i);
                goto cleanup;
            }
        } else {
            if (memcmp(buf, pattern, PATTERN_LEN) != 0) {
                fprintf(stderr, "Mismatched pattern data iteration %zu\n", i);
                goto cleanup;
            }
        }
    }

    if (st->driver->streamFinish(st) != 0) {
        fprintf(stderr, "Failed to finish stream: %s\n",
                virGetLastErrorMessage());
        goto cleanup;
    }

    ret = 0;
 cleanup:
    if (st)
        virStreamFree(st);
    if (file != NULL)
        unlink(file);
    if (conn)
        virConnectClose(conn);
    return ret;
}


static int testFDStreamReadBlock(const void *data)
{
    return testFDStreamReadCommon(data, true);
}
static int testFDStreamReadNonblock(const void *data)
{
    return testFDStreamReadCommon(data, false);
}


static int testFDStreamWriteCommon(const char *scratchdir, bool blocking)
{
    VIR_AUTOCLOSE fd = -1;
    g_autofree char *file = NULL;
    int ret = -1;
    g_autofree char *pattern = NULL;
    g_autofree char *buf = NULL;
    virStreamPtr st = NULL;
    size_t i;
    virConnectPtr conn = NULL;
    int flags = 0;

    if (!blocking)
        flags |= VIR_STREAM_NONBLOCK;

    if (!(conn = virConnectOpen("test:///default")))
        goto cleanup;

    pattern = g_new0(char, PATTERN_LEN);
    buf = g_new0(char, PATTERN_LEN);

    for (i = 0; i < PATTERN_LEN; i++)
        pattern[i] = i;

    file = g_strdup_printf("%s/input.data", scratchdir);

    if (!(st = virStreamNew(conn, flags)))
        goto cleanup;

    /* Start writing 1/2 way through first pattern
     * and end 1/2 way through last pattern
     */
    if (virFDStreamCreateFile(st, file,
                              PATTERN_LEN / 2, PATTERN_LEN * 9,
                              O_WRONLY, 0600) < 0)
        goto cleanup;

    for (i = 0; i < 10; i++) {
        size_t offset = 0;
        size_t want;
        if (i == 0)
            want = PATTERN_LEN / 2;
        else
            want = PATTERN_LEN;

        while (want > 0) {
            int got;
        rewrite:
            got = st->driver->streamSend(st, pattern + offset, want);
            if (got < 0) {
                if (got == -2 && !blocking) {
                    g_usleep(20 * 1000);
                    goto rewrite;
                }
                if (i == 9 &&
                    want == (PATTERN_LEN / 2))
                    break;
                fprintf(stderr, "Failed to write stream: %s\n",
                        virGetLastErrorMessage());
                goto cleanup;
            }
            offset += got;
            want -= got;
        }
    }

    if (st->driver->streamFinish(st) != 0) {
        fprintf(stderr, "Failed to finish stream: %s\n",
                virGetLastErrorMessage());
        goto cleanup;
   }

    if ((fd = open(file, O_RDONLY)) < 0)
        goto cleanup;

    for (i = 0; i < 10; i++) {
        size_t want, got;
        if (i == 9)
            want = PATTERN_LEN / 2;
        else
            want = PATTERN_LEN;

        if ((got = saferead(fd, buf, want)) != want) {
            fprintf(stderr,
                    "Short read from data, i=%zu got=%zu want=%zu\n",
                    i, got, want);
            goto cleanup;
        }

        if (i == 0) {
            size_t j;
            for (j = 0; j < (PATTERN_LEN / 2); j++) {
                if (buf[j] != 0) {
                    fprintf(stderr, "Mismatched pattern data iteration %zu\n", i);
                    goto cleanup;
                }
            }
            if (memcmp(buf + (PATTERN_LEN / 2), pattern, PATTERN_LEN / 2) != 0) {
                fprintf(stderr, "Mismatched pattern data iteration %zu\n", i);
                goto cleanup;
            }
        } else if (i == 9) {
            if (memcmp(buf, pattern, PATTERN_LEN / 2) != 0) {
                fprintf(stderr, "Mismatched pattern data iteration %zu\n", i);
                goto cleanup;
            }
        } else {
            if (memcmp(buf, pattern, PATTERN_LEN) != 0) {
                fprintf(stderr, "Mismatched pattern data iteration %zu\n", i);
                goto cleanup;
            }
        }
    }

    if (VIR_CLOSE(fd) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    if (st)
        virStreamFree(st);
    if (file != NULL)
        unlink(file);
    if (conn)
        virConnectClose(conn);
    return ret;
}


static int testFDStreamWriteBlock(const void *data)
{
    return testFDStreamWriteCommon(data, true);
}
static int testFDStreamWriteNonblock(const void *data)
{
    return testFDStreamWriteCommon(data, false);
}

#define SCRATCHDIRTEMPLATE abs_builddir "/fdstreamdir-XXXXXX"

static int
mymain(void)
{
    char scratchdir[] = SCRATCHDIRTEMPLATE;
    int ret = 0;

    if (!g_mkdtemp(scratchdir)) {
        fprintf(stderr, "Cannot create fdstreamdir");
        abort();
    }

    if (virTestRun("Stream read blocking ", testFDStreamReadBlock, scratchdir) < 0)
        ret = -1;
    if (virTestRun("Stream read non-blocking ", testFDStreamReadNonblock, scratchdir) < 0)
        ret = -1;
    if (virTestRun("Stream write blocking ", testFDStreamWriteBlock, scratchdir) < 0)
        ret = -1;
    if (virTestRun("Stream write non-blocking ", testFDStreamWriteNonblock, scratchdir) < 0)
        ret = -1;

    if (getenv("LIBVIRT_SKIP_CLEANUP") == NULL)
        virFileDeleteTree(scratchdir);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
