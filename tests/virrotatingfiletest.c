/*
 * Copyright (C) 2015 Red Hat, Inc.
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
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "virrotatingfile.h"
#include "virlog.h"
#include "testutils.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.rotatingfiletest");

#define FILENAME "virrotatingfiledata.txt"
#define FILENAME0 "virrotatingfiledata.txt.0"
#define FILENAME1 "virrotatingfiledata.txt.1"

#define FILEBYTE 0xde
#define FILEBYTE0 0xad
#define FILEBYTE1 0xbe

static int testRotatingFileWriterAssertOneFileSize(const char *filename,
                                                   off_t size)
{
    struct stat sb;

    if (stat(filename, &sb) < 0) {
        if (size == (off_t)-1) {
            return 0;
        } else {
            fprintf(stderr, "File %s does not exist\n", filename);
            return -1;
        }
    } else {
        if (size == (off_t)-1) {
            fprintf(stderr, "File %s should not exist\n", filename);
            return -1;
        } else if (sb.st_size != size) {
            fprintf(stderr, "File %s should be %llu bytes not %llu\n",
                    filename, (unsigned long long)size,
                    (unsigned long long)sb.st_size);
            return -1;
        } else {
            return 0;
        }
    }
}

static int testRotatingFileWriterAssertFileSizes(off_t baseSize,
                                                 off_t backup0Size,
                                                 off_t backup1Size)
{
    if (testRotatingFileWriterAssertOneFileSize(FILENAME, baseSize) < 0 ||
        testRotatingFileWriterAssertOneFileSize(FILENAME0, backup0Size) < 0 ||
        testRotatingFileWriterAssertOneFileSize(FILENAME1, backup1Size) < 0)
        return -1;
    return 0;
}


static int testRotatingFileReaderAssertBufferContent(const char *buf,
                                                     size_t buflen,
                                                     size_t nregions,
                                                     size_t *sizes)
{
    size_t i, j;
    char bytes[] = { FILEBYTE, FILEBYTE0, FILEBYTE1 };
    size_t total = 0;

    if (nregions > G_N_ELEMENTS(bytes)) {
        fprintf(stderr, "Too many regions %zu\n", nregions);
        return -1;
    }

    for (i = 0; i < nregions; i++)
        total += sizes[i];

    if (total != buflen) {
        fprintf(stderr, "Expected %zu bytes in file not %zu\n",
                total, buflen);
        return -1;
    }

    for (i = 0; i < nregions; i++) {
        char want = bytes[nregions - (i + 1)];
        for (j = 0; j < sizes[i]; j++) {
            if (*buf != want) {
                fprintf(stderr,
                        "Expected '0x%x' but got '0x%x' at region %zu byte %zu\n",
                        want & 0xff, *buf & 0xff, i, j);
                return -1;
            }
            buf++;
        }
    }

    return 0;
}


static int testRotatingFileInitOne(const char *filename,
                                   off_t size,
                                   char pattern)
{
    if (size == (off_t)-1) {
        VIR_DEBUG("Deleting %s", filename);
        unlink(filename);
    } else {
        char buf[1024];
        VIR_AUTOCLOSE fd = -1;

        VIR_DEBUG("Creating %s size %zu", filename, (size_t)size);

        fd = open(filename, O_WRONLY|O_CREAT|O_TRUNC, 0700);
        if (fd < 0) {
            fprintf(stderr, "Cannot create %s\n", filename);
            return -1;
        }
        memset(buf, pattern, sizeof(buf));
        while (size) {
            size_t towrite = size;
            if (towrite > sizeof(buf))
                towrite = sizeof(buf);

            if (safewrite(fd, buf, towrite) != towrite) {
                fprintf(stderr, "Cannot write to %s\n", filename);
                return -1;
            }
            size -= towrite;
        }
    }
    return 0;
}

static int testRotatingFileInitFiles(off_t baseSize,
                                     off_t backup0Size,
                                     off_t backup1Size)
{
    if (testRotatingFileInitOne(FILENAME, baseSize, FILEBYTE) < 0 ||
        testRotatingFileInitOne(FILENAME0, backup0Size, FILEBYTE0) < 0 ||
        testRotatingFileInitOne(FILENAME1, backup1Size, FILEBYTE1) < 0) {
        return -1;
    }
    return 0;
}

static int testRotatingFileWriterNew(const void *data G_GNUC_UNUSED)
{
    virRotatingFileWriter *file;
    int ret = -1;
    char buf[512];

    if (testRotatingFileInitFiles((off_t)-1,
                                  (off_t)-1,
                                  (off_t)-1) < 0)
        return -1;

    file = virRotatingFileWriterNew(FILENAME,
                                    1024,
                                    2,
                                    false,
                                    0700);
    if (!file)
        goto cleanup;

    if (testRotatingFileWriterAssertFileSizes(0,
                                              (off_t)-1,
                                              (off_t)-1) < 0)
        goto cleanup;

    memset(buf, 0x5e, sizeof(buf));

    virRotatingFileWriterAppend(file, buf, sizeof(buf));

    if (testRotatingFileWriterAssertFileSizes(sizeof(buf),
                                              (off_t)-1,
                                              (off_t)-1) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virRotatingFileWriterFree(file);
    unlink(FILENAME);
    unlink(FILENAME0);
    unlink(FILENAME1);
    return ret;
}


static int testRotatingFileWriterAppend(const void *data G_GNUC_UNUSED)
{
    virRotatingFileWriter *file;
    int ret = -1;
    char buf[512];

    if (testRotatingFileInitFiles(512,
                                  (off_t)-1,
                                  (off_t)-1) < 0)
        return -1;

    file = virRotatingFileWriterNew(FILENAME,
                                    1024,
                                    2,
                                    false,
                                    0700);
    if (!file)
        goto cleanup;

    if (testRotatingFileWriterAssertFileSizes(512,
                                              (off_t)-1,
                                              (off_t)-1) < 0)
        goto cleanup;

    memset(buf, 0x5e, sizeof(buf));

    virRotatingFileWriterAppend(file, buf, sizeof(buf));

    if (testRotatingFileWriterAssertFileSizes(1024,
                                              (off_t)-1,
                                              (off_t)-1) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virRotatingFileWriterFree(file);
    unlink(FILENAME);
    unlink(FILENAME0);
    unlink(FILENAME1);
    return ret;
}


static int testRotatingFileWriterTruncate(const void *data G_GNUC_UNUSED)
{
    virRotatingFileWriter *file;
    int ret = -1;
    char buf[512];

    if (testRotatingFileInitFiles(512,
                                  (off_t)-1,
                                  (off_t)-1) < 0)
        return -1;

    file = virRotatingFileWriterNew(FILENAME,
                                    1024,
                                    2,
                                    true,
                                    0700);
    if (!file)
        goto cleanup;

    if (testRotatingFileWriterAssertFileSizes(0,
                                              (off_t)-1,
                                              (off_t)-1) < 0)
        goto cleanup;

    memset(buf, 0x5e, sizeof(buf));

    virRotatingFileWriterAppend(file, buf, sizeof(buf));

    if (testRotatingFileWriterAssertFileSizes(512,
                                              (off_t)-1,
                                              (off_t)-1) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virRotatingFileWriterFree(file);
    unlink(FILENAME);
    unlink(FILENAME0);
    unlink(FILENAME1);
    return ret;
}


static int testRotatingFileWriterRolloverNone(const void *data G_GNUC_UNUSED)
{
    virRotatingFileWriter *file;
    int ret = -1;
    char buf[512];

    if (testRotatingFileInitFiles((off_t)-1,
                                  (off_t)-1,
                                  (off_t)-1) < 0)
        return -1;

    file = virRotatingFileWriterNew(FILENAME,
                                    200,
                                    0,
                                    false,
                                    0700);
    if (!file)
        goto cleanup;

    if (testRotatingFileWriterAssertFileSizes(0,
                                              (off_t)-1,
                                              (off_t)-1) < 0)
        goto cleanup;

    memset(buf, 0x5e, sizeof(buf));

    virRotatingFileWriterAppend(file, buf, sizeof(buf));

    if (testRotatingFileWriterAssertFileSizes(112,
                                              (off_t)-1,
                                              (off_t)-1) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virRotatingFileWriterFree(file);
    unlink(FILENAME);
    unlink(FILENAME0);
    unlink(FILENAME1);
    return ret;
}


static int testRotatingFileWriterRolloverOne(const void *data G_GNUC_UNUSED)
{
    virRotatingFileWriter *file;
    int ret = -1;
    char buf[512];

    if (testRotatingFileInitFiles((off_t)-1,
                                  (off_t)-1,
                                  (off_t)-1) < 0)
        return -1;

    file = virRotatingFileWriterNew(FILENAME,
                                    1024,
                                    2,
                                    false,
                                    0700);
    if (!file)
        goto cleanup;

    if (testRotatingFileWriterAssertFileSizes(0,
                                              (off_t)-1,
                                              (off_t)-1) < 0)
        goto cleanup;

    memset(buf, 0x5e, sizeof(buf));

    virRotatingFileWriterAppend(file, buf, sizeof(buf));
    virRotatingFileWriterAppend(file, buf, sizeof(buf));
    virRotatingFileWriterAppend(file, buf, sizeof(buf));

    if (testRotatingFileWriterAssertFileSizes(512,
                                              1024,
                                              (off_t)-1) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virRotatingFileWriterFree(file);
    unlink(FILENAME);
    unlink(FILENAME0);
    unlink(FILENAME1);
    return ret;
}


static int testRotatingFileWriterRolloverAppend(const void *data G_GNUC_UNUSED)
{
    virRotatingFileWriter *file;
    int ret = -1;
    char buf[512];

    if (testRotatingFileInitFiles((off_t)768,
                                  (off_t)-1,
                                  (off_t)-1) < 0)
        return -1;

    file = virRotatingFileWriterNew(FILENAME,
                                    1024,
                                    2,
                                    false,
                                    0700);
    if (!file)
        goto cleanup;

    if (testRotatingFileWriterAssertFileSizes(768,
                                              (off_t)-1,
                                              (off_t)-1) < 0)
        goto cleanup;

    memset(buf, 0x5e, sizeof(buf));

    virRotatingFileWriterAppend(file, buf, sizeof(buf));

    if (testRotatingFileWriterAssertFileSizes(256,
                                              1024,
                                              (off_t)-1) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virRotatingFileWriterFree(file);
    unlink(FILENAME);
    unlink(FILENAME0);
    unlink(FILENAME1);
    return ret;
}


static int testRotatingFileWriterRolloverMany(const void *data G_GNUC_UNUSED)
{
    virRotatingFileWriter *file;
    int ret = -1;
    char buf[512];

    if (testRotatingFileInitFiles((off_t)-1,
                                  (off_t)-1,
                                  (off_t)-1) < 0)
        return -1;

    file = virRotatingFileWriterNew(FILENAME,
                                    1024,
                                    2,
                                    false,
                                    0700);
    if (!file)
        goto cleanup;

    if (testRotatingFileWriterAssertFileSizes(0,
                                              (off_t)-1,
                                              (off_t)-1) < 0)
        goto cleanup;

    memset(buf, 0x5e, sizeof(buf));

    virRotatingFileWriterAppend(file, buf, sizeof(buf));
    virRotatingFileWriterAppend(file, buf, sizeof(buf));
    virRotatingFileWriterAppend(file, buf, sizeof(buf));
    virRotatingFileWriterAppend(file, buf, sizeof(buf));
    virRotatingFileWriterAppend(file, buf, sizeof(buf));
    virRotatingFileWriterAppend(file, buf, sizeof(buf));
    virRotatingFileWriterAppend(file, buf, sizeof(buf));

    if (testRotatingFileWriterAssertFileSizes(512,
                                              1024,
                                              1024) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virRotatingFileWriterFree(file);
    unlink(FILENAME);
    unlink(FILENAME0);
    unlink(FILENAME1);
    return ret;
}


static int testRotatingFileWriterRolloverLineBreak(const void *data G_GNUC_UNUSED)
{
    virRotatingFileWriter *file;
    int ret = -1;
    const char *buf = "The quick brown fox jumps over the lazy dog\n"
        "The wizard quickly jinxed the gnomes before they vaporized\n";

    if (testRotatingFileInitFiles(100,
                                  (off_t)-1,
                                  (off_t)-1) < 0)
        return -1;

    file = virRotatingFileWriterNew(FILENAME,
                                    160,
                                    2,
                                    false,
                                    0700);
    if (!file)
        goto cleanup;

    if (testRotatingFileWriterAssertFileSizes(100,
                                              (off_t)-1,
                                              (off_t)-1) < 0)
        goto cleanup;

    virRotatingFileWriterAppend(file, buf, strlen(buf));

    if (testRotatingFileWriterAssertFileSizes(59,
                                              144,
                                              (off_t)-1) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virRotatingFileWriterFree(file);
    unlink(FILENAME);
    unlink(FILENAME0);
    unlink(FILENAME1);
    return ret;
}


static int testRotatingFileWriterLargeFile(const void *data G_GNUC_UNUSED)
{
    virRotatingFileWriter *file;
    int ret = -1;
    const char *buf = "The quick brown fox jumps over the lazy dog\n"
        "The wizard quickly jinxed the gnomes before they vaporized\n";

    if (testRotatingFileInitFiles(200,
                                  (off_t)-1,
                                  (off_t)-1) < 0)
        return -1;

    file = virRotatingFileWriterNew(FILENAME,
                                    160,
                                    2,
                                    false,
                                    0700);
    if (!file)
        goto cleanup;

    if (testRotatingFileWriterAssertFileSizes(200,
                                              (off_t)-1,
                                              (off_t)-1) < 0)
        goto cleanup;

    virRotatingFileWriterAppend(file, buf, strlen(buf));

    if (testRotatingFileWriterAssertFileSizes(103,
                                              200,
                                              (off_t)-1) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virRotatingFileWriterFree(file);
    unlink(FILENAME);
    unlink(FILENAME0);
    unlink(FILENAME1);
    return ret;
}


static int testRotatingFileReaderOne(const void *data G_GNUC_UNUSED)
{
    virRotatingFileReader *file;
    int ret = -1;
    char buf[512];
    ssize_t got;
    size_t regions[] = { 256 };

    if (testRotatingFileInitFiles(256, (off_t)-1, (off_t)-1) < 0)
        return -1;

    file = virRotatingFileReaderNew(FILENAME, 2);
    if (!file)
        goto cleanup;

    if ((got = virRotatingFileReaderConsume(file, buf, sizeof(buf))) < 0)
        goto cleanup;

    if (testRotatingFileReaderAssertBufferContent(buf, got,
                                                  G_N_ELEMENTS(regions),
                                                  regions) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virRotatingFileReaderFree(file);
    unlink(FILENAME);
    unlink(FILENAME0);
    unlink(FILENAME1);
    return ret;
}

static int testRotatingFileReaderAll(const void *data G_GNUC_UNUSED)
{
    virRotatingFileReader *file;
    int ret = -1;
    char buf[768];
    ssize_t got;
    size_t regions[] = { 256, 256, 256 };

    if (testRotatingFileInitFiles(256, 256, 256) < 0)
        return -1;

    file = virRotatingFileReaderNew(FILENAME, 2);
    if (!file)
        goto cleanup;

    if ((got = virRotatingFileReaderConsume(file, buf, sizeof(buf))) < 0)
        goto cleanup;

    if (testRotatingFileReaderAssertBufferContent(buf, got,
                                                  G_N_ELEMENTS(regions),
                                                  regions) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virRotatingFileReaderFree(file);
    unlink(FILENAME);
    unlink(FILENAME0);
    unlink(FILENAME1);
    return ret;
}

static int testRotatingFileReaderPartial(const void *data G_GNUC_UNUSED)
{
    virRotatingFileReader *file;
    int ret = -1;
    char buf[600];
    ssize_t got;
    size_t regions[] = { 256, 256, 88 };

    if (testRotatingFileInitFiles(256, 256, 256) < 0)
        return -1;

    file = virRotatingFileReaderNew(FILENAME, 2);
    if (!file)
        goto cleanup;

    if ((got = virRotatingFileReaderConsume(file, buf, sizeof(buf))) < 0)
        goto cleanup;

    if (testRotatingFileReaderAssertBufferContent(buf, got,
                                                  G_N_ELEMENTS(regions),
                                                  regions) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virRotatingFileReaderFree(file);
    unlink(FILENAME);
    unlink(FILENAME0);
    unlink(FILENAME1);
    return ret;
}

static int testRotatingFileReaderSeek(const void *data G_GNUC_UNUSED)
{
    virRotatingFileReader *file;
    int ret = -1;
    char buf[600];
    ssize_t got;
    size_t regions[] = { 156, 256 };
    struct stat sb;

    if (testRotatingFileInitFiles(256, 256, 256) < 0)
        return -1;

    file = virRotatingFileReaderNew(FILENAME, 2);
    if (!file)
        goto cleanup;

    if (stat(FILENAME0, &sb) < 0) {
        virReportSystemError(errno, "Cannot stat %s", FILENAME0);
        goto cleanup;
    }

    if (virRotatingFileReaderSeek(file, sb.st_ino, 100) < 0)
        goto cleanup;

    if ((got = virRotatingFileReaderConsume(file, buf, sizeof(buf))) < 0)
        goto cleanup;

    if (testRotatingFileReaderAssertBufferContent(buf, got,
                                                  G_N_ELEMENTS(regions),
                                                  regions) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virRotatingFileReaderFree(file);
    unlink(FILENAME);
    unlink(FILENAME0);
    unlink(FILENAME1);
    return ret;
}

static int
mymain(void)
{
    int ret = 0;

    if (virTestRun("Rotating file write new", testRotatingFileWriterNew, NULL) < 0)
        ret = -1;

    if (virTestRun("Rotating file write append", testRotatingFileWriterAppend, NULL) < 0)
        ret = -1;

    if (virTestRun("Rotating file write truncate", testRotatingFileWriterTruncate, NULL) < 0)
        ret = -1;

    if (virTestRun("Rotating file write rollover no backup", testRotatingFileWriterRolloverNone, NULL) < 0)
        ret = -1;

    if (virTestRun("Rotating file write rollover one", testRotatingFileWriterRolloverOne, NULL) < 0)
        ret = -1;

    if (virTestRun("Rotating file write rollover append", testRotatingFileWriterRolloverAppend, NULL) < 0)
        ret = -1;

    if (virTestRun("Rotating file write rollover many", testRotatingFileWriterRolloverMany, NULL) < 0)
        ret = -1;

    if (virTestRun("Rotating file write rollover line break", testRotatingFileWriterRolloverLineBreak, NULL) < 0)
        ret = -1;

    if (virTestRun("Rotating file write to file larger then maxlen", testRotatingFileWriterLargeFile, NULL) < 0)
        ret = -1;

    if (virTestRun("Rotating file read one", testRotatingFileReaderOne, NULL) < 0)
        ret = -1;

    if (virTestRun("Rotating file read all", testRotatingFileReaderAll, NULL) < 0)
        ret = -1;

    if (virTestRun("Rotating file read partial", testRotatingFileReaderPartial, NULL) < 0)
        ret = -1;

    if (virTestRun("Rotating file read seek", testRotatingFileReaderSeek, NULL) < 0)
        ret = -1;

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
