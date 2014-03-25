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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Eric Blake <eblake@redhat.com>
 */

#include <config.h>

#include <stdlib.h>

#include "testutils.h"
#include "vircommand.h"
#include "virerror.h"
#include "virfile.h"
#include "virlog.h"
#include "virstoragefile.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.storagetest");

#define datadir abs_builddir "/virstoragedata"

/* This test creates the following files, all in datadir:

 * raw: 1024-byte raw file
 * qcow2: qcow2 file with 'raw' as backing
 * wrap: qcow2 file with 'qcow2' as backing
 * qed: qed file with 'raw' as backing
 * sub/link1: symlink to qcow2
 * sub/link2: symlink to wrap
 *
 * Relative names to these files are known at compile time, but absolute
 * and canonical names depend on where the test is run; for convenience,
 * we pre-populate the computation of these names for use during the test.
*/

static char *qemuimg;
static char *absraw;
static char *canonraw;
static char *absqcow2;
static char *canonqcow2;
static char *abswrap;
static char *absqed;
static char *abslink2;

static void
testCleanupImages(void)
{
    virCommandPtr cmd;

    VIR_FREE(qemuimg);
    VIR_FREE(absraw);
    VIR_FREE(canonraw);
    VIR_FREE(absqcow2);
    VIR_FREE(canonqcow2);
    VIR_FREE(abswrap);
    VIR_FREE(absqed);
    VIR_FREE(abslink2);

    if (chdir(abs_builddir) < 0) {
        fprintf(stderr, "unable to return to correct directory, refusing to "
                "clean up %s\n", datadir);
        return;
    }

    cmd = virCommandNewArgList("rm", "-rf", datadir, NULL);
    ignore_value(virCommandRun(cmd, NULL));
    virCommandFree(cmd);
}

static int
testPrepImages(void)
{
    int ret = EXIT_FAILURE;
    virCommandPtr cmd = NULL;
    char *buf = NULL;
    bool compat = false;

    qemuimg = virFindFileInPath("kvm-img");
    if (!qemuimg)
        qemuimg = virFindFileInPath("qemu-img");
    if (!qemuimg)
        goto skip;

    /* See if qemu-img supports '-o compat=xxx'.  If so, we force the
     * use of both v2 and v3 files; if not, it is v2 only but the test
     * still works. */
    cmd = virCommandNewArgList(qemuimg, "create", "-f", "qcow2",
                               "-o?", "/dev/null", NULL);
    virCommandSetOutputBuffer(cmd, &buf);
    if (virCommandRun(cmd, NULL) < 0)
        goto skip;
    if (strstr(buf, "compat "))
        compat = true;
    VIR_FREE(buf);

    if (virAsprintf(&absraw, "%s/raw", datadir) < 0 ||
        virAsprintf(&absqcow2, "%s/qcow2", datadir) < 0 ||
        virAsprintf(&abswrap, "%s/wrap", datadir) < 0 ||
        virAsprintf(&absqed, "%s/qed", datadir) < 0 ||
        virAsprintf(&abslink2, "%s/sub/link2", datadir) < 0)
        goto cleanup;

    if (virFileMakePath(datadir "/sub") < 0) {
        fprintf(stderr, "unable to create directory %s\n", datadir "/sub");
        goto cleanup;
    }

    if (chdir(datadir) < 0) {
        fprintf(stderr, "unable to test relative backing chains\n");
        goto cleanup;
    }

    if (virAsprintf(&buf, "%1024d", 0) < 0 ||
        virFileWriteStr("raw", buf, 0600) < 0) {
        fprintf(stderr, "unable to create raw file\n");
        goto cleanup;
    }
    if (!(canonraw = canonicalize_file_name(absraw))) {
        virReportOOMError();
        goto cleanup;
    }

    /* Create a qcow2 wrapping relative raw; later on, we modify its
     * metadata to test other configurations */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "create", "-f", "qcow2", NULL);
    virCommandAddArgFormat(cmd, "-obacking_file=raw,backing_fmt=raw%s",
                           compat ? ",compat=0.10" : "");
    virCommandAddArg(cmd, "qcow2");
    if (virCommandRun(cmd, NULL) < 0)
        goto skip;
    /* Make sure our later uses of 'qemu-img rebase' will work */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "raw", "-b", "raw", "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        goto skip;
    if (!(canonqcow2 = canonicalize_file_name(absqcow2))) {
        virReportOOMError();
        goto cleanup;
    }

    /* Create a second qcow2 wrapping the first, to be sure that we
     * can correctly avoid insecure probing.  */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "create", "-f", "qcow2", NULL);
    virCommandAddArgFormat(cmd, "-obacking_file=%s,backing_fmt=qcow2%s",
                           absqcow2, compat ? ",compat=1.1" : "");
    virCommandAddArg(cmd, "wrap");
    if (virCommandRun(cmd, NULL) < 0)
        goto skip;

    /* Create a qed file. */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "create", "-f", "qed", NULL);
    virCommandAddArgFormat(cmd, "-obacking_file=%s,backing_fmt=raw",
                           absraw);
    virCommandAddArg(cmd, "qed");
    if (virCommandRun(cmd, NULL) < 0)
        goto skip;

#ifdef HAVE_SYMLINK
    /* Create some symlinks in a sub-directory. */
    if (symlink("../qcow2", datadir "/sub/link1") < 0 ||
        symlink("../wrap", datadir "/sub/link2") < 0) {
        fprintf(stderr, "unable to create symlink");
        goto cleanup;
    }
#endif

    ret = 0;
 cleanup:
    VIR_FREE(buf);
    virCommandFree(cmd);
    if (ret)
        testCleanupImages();
    return ret;

 skip:
    fputs("qemu-img is too old; skipping this test\n", stderr);
    ret = EXIT_AM_SKIP;
    goto cleanup;
}

typedef struct _testFileData testFileData;
struct _testFileData
{
    const char *expBackingStore;
    const char *expBackingStoreRaw;
    const char *expDirectory;
    enum virStorageFileFormat expFormat;
    bool expIsFile;
    unsigned long long expCapacity;
    bool expEncrypted;
};

enum {
    EXP_PASS = 0,
    EXP_FAIL = 1,
    EXP_WARN = 2,
    ALLOW_PROBE = 4,
};

struct testChainData
{
    const char *start;
    enum virStorageFileFormat format;
    const testFileData *files;
    int nfiles;
    unsigned int flags;
};

static int
testStorageChain(const void *args)
{
    const struct testChainData *data = args;
    int ret = -1;
    virStorageFileMetadataPtr meta;
    virStorageFileMetadataPtr elt;
    size_t i = 0;

    meta = virStorageFileGetMetadata(data->start, data->format, -1, -1,
                                     (data->flags & ALLOW_PROBE) != 0);
    if (!meta) {
        if (data->flags & EXP_FAIL) {
            virResetLastError();
            ret = 0;
        }
        goto cleanup;
    } else if (data->flags & EXP_FAIL) {
        fprintf(stderr, "call should have failed\n");
        goto cleanup;
    }
    if (data->flags & EXP_WARN) {
        if (!virGetLastError()) {
            fprintf(stderr, "call should have warned\n");
            goto cleanup;
        }
        virResetLastError();
    } else if (virGetLastError()) {
        fprintf(stderr, "call should not have warned\n");
        goto cleanup;
    }

    elt = meta;
    while (elt) {
        char *expect = NULL;
        char *actual = NULL;

        if (i == data->nfiles) {
            fprintf(stderr, "probed chain was too long\n");
            goto cleanup;
        }

        if (virAsprintf(&expect,
                        "store:%s\nraw:%s\ndirectory:%s\nother:%d %d %lld %d",
                        NULLSTR(data->files[i].expBackingStore),
                        NULLSTR(data->files[i].expBackingStoreRaw),
                        NULLSTR(data->files[i].expDirectory),
                        data->files[i].expFormat,
                        data->files[i].expIsFile,
                        data->files[i].expCapacity,
                        data->files[i].expEncrypted) < 0 ||
            virAsprintf(&actual,
                        "store:%s\nraw:%s\ndirectory:%s\nother:%d %d %lld %d",
                        NULLSTR(elt->backingStore),
                        NULLSTR(elt->backingStoreRaw),
                        NULLSTR(elt->directory),
                        elt->backingStoreFormat, elt->backingStoreIsFile,
                        elt->capacity, elt->encrypted) < 0) {
            VIR_FREE(expect);
            VIR_FREE(actual);
            goto cleanup;
        }
        if (STRNEQ(expect, actual)) {
            virtTestDifference(stderr, expect, actual);
            VIR_FREE(expect);
            VIR_FREE(actual);
            goto cleanup;
        }
        VIR_FREE(expect);
        VIR_FREE(actual);
        elt = elt->backingMeta;
        i++;
    }
    if (i != data->nfiles) {
        fprintf(stderr, "probed chain was too short\n");
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virStorageFileFreeMetadata(meta);
    return ret;
}

static int
mymain(void)
{
    int ret;
    virCommandPtr cmd = NULL;

    /* Prep some files with qemu-img; if that is not found on PATH, or
     * if it lacks support for qcow2 and qed, skip this test.  */
    if ((ret = testPrepImages()) != 0)
        return ret;

#define TEST_ONE_CHAIN(id, start, format, chain, flags)              \
    do {                                                             \
        struct testChainData data = {                                \
            start, format, chain, ARRAY_CARDINALITY(chain), flags,   \
        };                                                           \
        if (virtTestRun("Storage backing chain " id,                 \
                        testStorageChain, &data) < 0)                \
            ret = -1;                                                \
    } while (0)

#define TEST_CHAIN(id, relstart, absstart, format, chain1, flags1,   \
                   chain2, flags2, chain3, flags3, chain4, flags4)   \
    do {                                                             \
        TEST_ONE_CHAIN(#id "a", relstart, format, chain1, flags1);   \
        TEST_ONE_CHAIN(#id "b", relstart, format, chain2, flags2);   \
        TEST_ONE_CHAIN(#id "c", absstart, format, chain3, flags3);   \
        TEST_ONE_CHAIN(#id "d", absstart, format, chain4, flags4);   \
    } while (0)

    /* Expected details about files in chains */
    const testFileData raw = {
        NULL, NULL, NULL, VIR_STORAGE_FILE_NONE, false, 0, false,
    };
    const testFileData qcow2_relback_relstart = {
        canonraw, "raw", ".", VIR_STORAGE_FILE_RAW, true, 1024, false,
    };
    const testFileData qcow2_relback_absstart = {
        canonraw, "raw", datadir, VIR_STORAGE_FILE_RAW, true, 1024, false,
    };
    const testFileData qcow2_absback = {
        canonraw, absraw, datadir, VIR_STORAGE_FILE_RAW, true, 1024, false,
    };
    const testFileData qcow2_as_probe = {
        canonraw, absraw, datadir, VIR_STORAGE_FILE_AUTO, true, 1024, false,
    };
    const testFileData qcow2_bogus = {
        NULL, datadir "/bogus", datadir, VIR_STORAGE_FILE_NONE,
        false, 1024, false,
    };
    const testFileData qcow2_protocol = {
        "nbd:example.org:6000", NULL, NULL, VIR_STORAGE_FILE_RAW,
        false, 1024, false,
    };
    const testFileData wrap = {
        canonqcow2, absqcow2, datadir, VIR_STORAGE_FILE_QCOW2,
        true, 1024, false,
    };
    const testFileData wrap_as_raw = {
        canonqcow2, absqcow2, datadir, VIR_STORAGE_FILE_RAW,
        true, 1024, false,
    };
    const testFileData wrap_as_probe = {
        canonqcow2, absqcow2, datadir, VIR_STORAGE_FILE_AUTO,
        true, 1024, false,
    };
    const testFileData qed = {
        canonraw, absraw, datadir, VIR_STORAGE_FILE_RAW,
        true, 1024, false,
    };
#if HAVE_SYMLINK
    const testFileData link1_rel = {
        canonraw, "../raw", "sub/../sub/..", VIR_STORAGE_FILE_RAW,
        true, 1024, false,
    };
    const testFileData link1_abs = {
        canonraw, "../raw", datadir "/sub/../sub/..", VIR_STORAGE_FILE_RAW,
        true, 1024, false,
    };
    const testFileData link2_rel = {
        canonqcow2, "../sub/link1", "sub/../sub", VIR_STORAGE_FILE_QCOW2,
        true, 1024, false,
    };
    const testFileData link2_abs = {
        canonqcow2, "../sub/link1", datadir "/sub/../sub",
        VIR_STORAGE_FILE_QCOW2, true, 1024, false,
    };
#endif

    /* The actual tests, in several groups. */

    /* Missing file */
    const testFileData chain0[] = { };
    TEST_ONE_CHAIN("0", "bogus", VIR_STORAGE_FILE_RAW, chain0, EXP_FAIL);

    /* Raw image, whether with right format or no specified format */
    const testFileData chain1[] = { raw };
    TEST_CHAIN(1, "raw", absraw, VIR_STORAGE_FILE_RAW,
               chain1, EXP_PASS,
               chain1, ALLOW_PROBE | EXP_PASS,
               chain1, EXP_PASS,
               chain1, ALLOW_PROBE | EXP_PASS);
    TEST_CHAIN(2, "raw", absraw, VIR_STORAGE_FILE_AUTO,
               chain1, EXP_PASS,
               chain1, ALLOW_PROBE | EXP_PASS,
               chain1, EXP_PASS,
               chain1, ALLOW_PROBE | EXP_PASS);

    /* Qcow2 file with relative raw backing, format provided */
    const testFileData chain3a[] = { qcow2_relback_relstart, raw };
    const testFileData chain3c[] = { qcow2_relback_absstart, raw };
    const testFileData chain4a[] = { raw };
    TEST_CHAIN(3, "qcow2", absqcow2, VIR_STORAGE_FILE_QCOW2,
               chain3a, EXP_PASS,
               chain3a, ALLOW_PROBE | EXP_PASS,
               chain3c, EXP_PASS,
               chain3c, ALLOW_PROBE | EXP_PASS);
    TEST_CHAIN(4, "qcow2", absqcow2, VIR_STORAGE_FILE_AUTO,
               chain4a, EXP_PASS,
               chain3a, ALLOW_PROBE | EXP_PASS,
               chain4a, EXP_PASS,
               chain3c, ALLOW_PROBE | EXP_PASS);

    /* Rewrite qcow2 file to use absolute backing name */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "raw", "-b", absraw, "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;

    /* Qcow2 file with raw as absolute backing, backing format provided */
    const testFileData chain5[] = { qcow2_absback, raw };
    const testFileData chain6[] = { raw };
    TEST_CHAIN(5, "qcow2", absqcow2, VIR_STORAGE_FILE_QCOW2,
               chain5, EXP_PASS,
               chain5, ALLOW_PROBE | EXP_PASS,
               chain5, EXP_PASS,
               chain5, ALLOW_PROBE | EXP_PASS);
    TEST_CHAIN(6, "qcow2", absqcow2, VIR_STORAGE_FILE_AUTO,
               chain6, EXP_PASS,
               chain5, ALLOW_PROBE | EXP_PASS,
               chain6, EXP_PASS,
               chain5, ALLOW_PROBE | EXP_PASS);

    /* Wrapped file access */
    const testFileData chain7[] = { wrap, qcow2_absback, raw };
    TEST_CHAIN(7, "wrap", abswrap, VIR_STORAGE_FILE_QCOW2,
               chain7, EXP_PASS,
               chain7, ALLOW_PROBE | EXP_PASS,
               chain7, EXP_PASS,
               chain7, ALLOW_PROBE | EXP_PASS);

    /* Rewrite qcow2 and wrap file to omit backing file type */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-b", absraw, "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;

    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-b", absqcow2, "wrap", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;

    /* Qcow2 file with raw as absolute backing, backing format omitted */
    const testFileData chain8a[] = { wrap_as_raw, raw };
    const testFileData chain8b[] = { wrap_as_probe, qcow2_as_probe, raw };
    TEST_CHAIN(8, "wrap", abswrap, VIR_STORAGE_FILE_QCOW2,
               chain8a, EXP_PASS,
               chain8b, ALLOW_PROBE | EXP_PASS,
               chain8a, EXP_PASS,
               chain8b, ALLOW_PROBE | EXP_PASS);

    /* Rewrite qcow2 to a missing backing file, with backing type */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "qcow2", "-b", datadir "/bogus",
                               "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;

    /* Qcow2 file with missing backing file but specified type */
    const testFileData chain9[] = { qcow2_bogus };
    TEST_CHAIN(9, "qcow2", absqcow2, VIR_STORAGE_FILE_QCOW2,
               chain9, EXP_WARN,
               chain9, ALLOW_PROBE | EXP_WARN,
               chain9, EXP_WARN,
               chain9, ALLOW_PROBE | EXP_WARN);

    /* Rewrite qcow2 to a missing backing file, without backing type */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-b", datadir "/bogus", "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;

    /* Qcow2 file with missing backing file and no specified type */
    const testFileData chain10[] = { qcow2_bogus };
    TEST_CHAIN(10, "qcow2", absqcow2, VIR_STORAGE_FILE_QCOW2,
               chain10, EXP_WARN,
               chain10, ALLOW_PROBE | EXP_WARN,
               chain10, EXP_WARN,
               chain10, ALLOW_PROBE | EXP_WARN);

    /* Rewrite qcow2 to use an nbd: protocol as backend */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "raw", "-b", "nbd:example.org:6000",
                               "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;

    /* Qcow2 file with backing protocol instead of file */
    const testFileData chain11[] = { qcow2_protocol };
    TEST_CHAIN(11, "qcow2", absqcow2, VIR_STORAGE_FILE_QCOW2,
               chain11, EXP_PASS,
               chain11, ALLOW_PROBE | EXP_PASS,
               chain11, EXP_PASS,
               chain11, ALLOW_PROBE | EXP_PASS);

    /* qed file */
    const testFileData chain12a[] = { raw };
    const testFileData chain12b[] = { qed, raw };
    TEST_CHAIN(12, "qed", absqed, VIR_STORAGE_FILE_AUTO,
               chain12a, EXP_PASS,
               chain12b, ALLOW_PROBE | EXP_PASS,
               chain12a, EXP_PASS,
               chain12b, ALLOW_PROBE | EXP_PASS);

#ifdef HAVE_SYMLINK
    /* Rewrite qcow2 and wrap file to use backing names relative to a
     * symlink from a different directory */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "raw", "-b", "../raw", "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;

    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "qcow2", "-b", "../sub/link1", "wrap",
                               NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;

    /* Behavior of symlinks to qcow2 with relative backing files */
    const testFileData chain13a[] = { link2_rel, link1_rel, raw };
    const testFileData chain13c[] = { link2_abs, link1_abs, raw };
    TEST_CHAIN(13, "sub/link2", abslink2, VIR_STORAGE_FILE_QCOW2,
               chain13a, EXP_PASS,
               chain13a, ALLOW_PROBE | EXP_PASS,
               chain13c, EXP_PASS,
               chain13c, ALLOW_PROBE | EXP_PASS);
#endif

    /* Final cleanup */
    testCleanupImages();
    virCommandFree(cmd);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
