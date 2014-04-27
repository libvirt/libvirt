/*
 * Copyright (C) 2013-2014 Red Hat, Inc.
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
#include "dirname.h"

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
static char *canonwrap;
static char *absqed;
static char *canonqed;
static char *absdir;
static char *canondir;
static char *abslink2;

static void
testCleanupImages(void)
{
    VIR_FREE(qemuimg);
    VIR_FREE(absraw);
    VIR_FREE(canonraw);
    VIR_FREE(absqcow2);
    VIR_FREE(canonqcow2);
    VIR_FREE(abswrap);
    VIR_FREE(canonwrap);
    VIR_FREE(absqed);
    VIR_FREE(canonqed);
    VIR_FREE(absdir);
    VIR_FREE(canondir);
    VIR_FREE(abslink2);

    if (chdir(abs_builddir) < 0) {
        fprintf(stderr, "unable to return to correct directory, refusing to "
                "clean up %s\n", datadir);
        return;
    }

    virFileDeleteTree(datadir);
}


static virStorageSourcePtr
testStorageFileGetMetadata(const char *path,
                           int format,
                           uid_t uid, gid_t gid,
                           bool allow_probe)
{
    virStorageSourcePtr ret = NULL;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    ret->type = VIR_STORAGE_TYPE_FILE;
    ret->format = format;

    if (VIR_STRDUP(ret->relPath, path) < 0)
        goto error;

    if (!(ret->relDir = mdir_name(path))) {
        virReportOOMError();
        goto error;
    }

    if (!(ret->path = canonicalize_file_name(path))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "failed to resolve '%s'", path);
        goto error;
    }

    if (virStorageFileGetMetadata(ret, uid, gid, allow_probe) < 0)
        goto error;

    return ret;

 error:
    virStorageSourceFree(ret);
    return NULL;
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

    /* Clean up from any earlier failed tests */
    virFileDeleteTree(datadir);

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
        virAsprintf(&absdir, "%s/dir", datadir) < 0 ||
        virAsprintf(&abslink2, "%s/sub/link2", datadir) < 0)
        goto cleanup;

    if (virFileMakePath(datadir "/sub") < 0) {
        fprintf(stderr, "unable to create directory %s\n", datadir "/sub");
        goto cleanup;
    }
    if (virFileMakePath(datadir "/dir") < 0) {
        fprintf(stderr, "unable to create directory %s\n", datadir "/dir");
        goto cleanup;
    }
    if (!(canondir = canonicalize_file_name(absdir))) {
        virReportOOMError();
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
    if (!(canonwrap = canonicalize_file_name(abswrap))) {
        virReportOOMError();
        goto cleanup;
    }

    /* Create a qed file. */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "create", "-f", "qed", NULL);
    virCommandAddArgFormat(cmd, "-obacking_file=%s,backing_fmt=raw",
                           absraw);
    virCommandAddArg(cmd, "qed");
    if (virCommandRun(cmd, NULL) < 0)
        goto skip;
    if (!(canonqed = canonicalize_file_name(absqed))) {
        virReportOOMError();
        goto cleanup;
    }

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

/* Many fields of virStorageFileMetadata have the same content whether
 * we access the file relatively or absolutely; but file names differ
 * depending on how the chain was opened.  For ease of testing, we
 * test both relative and absolute starts, and use a flag to say which
 * of the two variations to compare against.  */
typedef struct _testFileData testFileData;
struct _testFileData
{
    const char *expBackingStore;
    const char *expBackingStoreRaw;
    unsigned long long expCapacity;
    bool expEncrypted;
    const char *pathRel;
    const char *pathAbs;
    const char *path;
    const char *relDirRel;
    const char *relDirAbs;
    int type;
    int format;
};

enum {
    EXP_PASS = 0,
    EXP_FAIL = 1,
    EXP_WARN = 2,
    ALLOW_PROBE = 4,
    ABS_START = 8,
};

struct testChainData
{
    const char *start;
    virStorageFileFormat format;
    const testFileData *files[4];
    int nfiles;
    unsigned int flags;
};

static int
testStorageChain(const void *args)
{
    const struct testChainData *data = args;
    int ret = -1;
    virStorageSourcePtr meta;
    virStorageSourcePtr elt;
    size_t i = 0;
    char *broken = NULL;
    bool isAbs = !!(data->flags & ABS_START);

    meta = testStorageFileGetMetadata(data->start, data->format, -1, -1,
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
        if (virStorageFileChainGetBroken(meta, &broken) || !broken) {
            fprintf(stderr, "call should identify broken part of chain\n");
            goto cleanup;
        }
    } else {
        if (virGetLastError()) {
            fprintf(stderr, "call should not have warned\n");
            goto cleanup;
        }
        if (virStorageFileChainGetBroken(meta, &broken) || broken) {
            fprintf(stderr, "chain should not be identified as broken\n");
            goto cleanup;
        }
    }

    elt = meta;
    while (elt) {
        char *expect = NULL;
        char *actual = NULL;
        const char *expPath;
        const char *expRelDir;

        if (i == data->nfiles) {
            fprintf(stderr, "probed chain was too long\n");
            goto cleanup;
        }

        expPath = isAbs ? data->files[i]->pathAbs
            : data->files[i]->pathRel;
        expRelDir = isAbs ? data->files[i]->relDirAbs
            : data->files[i]->relDirRel;
        if (virAsprintf(&expect,
                        "store:%s\nraw:%s\nother:%lld %d\n"
                        "relPath:%s\npath:%s\nrelDir:%s\ntype:%d %d\n",
                        NULLSTR(data->files[i]->expBackingStore),
                        NULLSTR(data->files[i]->expBackingStoreRaw),
                        data->files[i]->expCapacity,
                        data->files[i]->expEncrypted,
                        NULLSTR(expPath),
                        NULLSTR(data->files[i]->path),
                        NULLSTR(expRelDir),
                        data->files[i]->type,
                        data->files[i]->format) < 0 ||
            virAsprintf(&actual,
                        "store:%s\nraw:%s\nother:%lld %d\n"
                        "relPath:%s\npath:%s\nrelDir:%s\ntype:%d %d\n",
                        NULLSTR(elt->backingStore ? elt->backingStore->path : NULL),
                        NULLSTR(elt->backingStoreRaw),
                        elt->capacity, !!elt->encryption,
                        NULLSTR(elt->relPath),
                        NULLSTR(elt->path),
                        NULLSTR(elt->relDir),
                        elt->type, elt->format) < 0) {
            VIR_FREE(expect);
            VIR_FREE(actual);
            goto cleanup;
        }
        if (STRNEQ(expect, actual)) {
            fprintf(stderr, "chain member %zu", i);
            virtTestDifference(stderr, expect, actual);
            VIR_FREE(expect);
            VIR_FREE(actual);
            goto cleanup;
        }
        VIR_FREE(expect);
        VIR_FREE(actual);
        elt = elt->backingStore;
        i++;
    }
    if (i != data->nfiles) {
        fprintf(stderr, "probed chain was too short\n");
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(broken);
    virStorageSourceFree(meta);
    return ret;
}

struct testLookupData
{
    virStorageSourcePtr chain;
    const char *target;
    const char *name;
    unsigned int expIndex;
    const char *expResult;
    virStorageSourcePtr expMeta;
    const char *expParent;
};

static int
testStorageLookup(const void *args)
{
    const struct testLookupData *data = args;
    int ret = 0;
    virStorageSourcePtr result;
    const char *actualParent;
    unsigned int idx;

    if (virStorageFileParseChainIndex(data->target, data->name, &idx) < 0 &&
        data->expIndex) {
        fprintf(stderr, "call should not have failed\n");
        ret = -1;
    }
    if (idx != data->expIndex) {
        fprintf(stderr, "index: expected %u, got %u\n", data->expIndex, idx);
        ret = -1;
    }

     /* Test twice to ensure optional parameter doesn't cause NULL deref. */
    result = virStorageFileChainLookup(data->chain, NULL,
                                       idx ? NULL : data->name,
                                       idx, NULL);

    if (!data->expResult) {
        if (!virGetLastError()) {
            fprintf(stderr, "call should have failed\n");
            ret = -1;
        }
        virResetLastError();
    } else {
        if (virGetLastError()) {
            fprintf(stderr, "call should not have warned\n");
            ret = -1;
        }
    }

    if (!result) {
        if (data->expResult) {
            fprintf(stderr, "result 1: expected %s, got NULL\n",
                    data->expResult);
            ret = -1;
        }
    } else if (STRNEQ_NULLABLE(data->expResult, result->path)) {
        fprintf(stderr, "result 1: expected %s, got %s\n",
                NULLSTR(data->expResult), NULLSTR(result->path));
        ret = -1;
    }

    result = virStorageFileChainLookup(data->chain, data->chain,
                                       data->name, idx, &actualParent);
    if (!data->expResult)
        virResetLastError();

    if (!result) {
        if (data->expResult) {
            fprintf(stderr, "result 2: expected %s, got NULL\n",
                    data->expResult);
            ret = -1;
        }
    } else if (STRNEQ_NULLABLE(data->expResult, result->path)) {
        fprintf(stderr, "result 2: expected %s, got %s\n",
                NULLSTR(data->expResult), NULLSTR(result->path));
        ret = -1;
    }
    if (data->expMeta != result) {
        fprintf(stderr, "meta: expected %p, got %p\n",
                data->expMeta, result);
        ret = -1;
    }
    if (STRNEQ_NULLABLE(data->expParent, actualParent)) {
        fprintf(stderr, "parent: expected %s, got %s\n",
                NULLSTR(data->expParent), NULLSTR(actualParent));
        ret = -1;
    }

    return ret;
}

static int
mymain(void)
{
    int ret;
    virCommandPtr cmd = NULL;
    struct testChainData data;
    virStorageSourcePtr chain = NULL;

    /* Prep some files with qemu-img; if that is not found on PATH, or
     * if it lacks support for qcow2 and qed, skip this test.  */
    if ((ret = testPrepImages()) != 0)
        return ret;

#define TEST_ONE_CHAIN(id, start, format, flags, ...)                \
    do {                                                             \
        size_t i;                                                    \
        memset(&data, 0, sizeof(data));                              \
        data = (struct testChainData){                               \
            start, format, { __VA_ARGS__ }, 0, flags,                \
        };                                                           \
        for (i = 0; i < ARRAY_CARDINALITY(data.files); i++)          \
            if (data.files[i])                                       \
                data.nfiles++;                                       \
        if (virtTestRun("Storage backing chain " id,                 \
                        testStorageChain, &data) < 0)                \
            ret = -1;                                                \
    } while (0)

#define VIR_FLATTEN_2(...) __VA_ARGS__
#define VIR_FLATTEN_1(_1) VIR_FLATTEN_2 _1

#define TEST_CHAIN(id, relstart, absstart, format, chain1, flags1,   \
                   chain2, flags2, chain3, flags3, chain4, flags4)   \
    do {                                                             \
        TEST_ONE_CHAIN(#id "a", relstart, format, flags1,            \
                       VIR_FLATTEN_1(chain1));                       \
        TEST_ONE_CHAIN(#id "b", relstart, format, flags2,            \
                       VIR_FLATTEN_1(chain2));                       \
        TEST_ONE_CHAIN(#id "c", absstart, format, flags3 | ABS_START,\
                       VIR_FLATTEN_1(chain3));                       \
        TEST_ONE_CHAIN(#id "d", absstart, format, flags4 | ABS_START,\
                       VIR_FLATTEN_1(chain4));                       \
    } while (0)

    /* The actual tests, in several groups. */

    /* Missing file */
    TEST_ONE_CHAIN("0", "bogus", VIR_STORAGE_FILE_RAW, EXP_FAIL);

    /* Raw image, whether with right format or no specified format */
    testFileData raw = {
        .pathRel = "raw",
        .pathAbs = canonraw,
        .path = canonraw,
        .relDirRel = ".",
        .relDirAbs = datadir,
        .type = VIR_STORAGE_TYPE_FILE,
        .format = VIR_STORAGE_FILE_RAW,
    };
    TEST_CHAIN(1, "raw", absraw, VIR_STORAGE_FILE_RAW,
               (&raw), EXP_PASS,
               (&raw), ALLOW_PROBE | EXP_PASS,
               (&raw), EXP_PASS,
               (&raw), ALLOW_PROBE | EXP_PASS);
    TEST_CHAIN(2, "raw", absraw, VIR_STORAGE_FILE_AUTO,
               (&raw), EXP_PASS,
               (&raw), ALLOW_PROBE | EXP_PASS,
               (&raw), EXP_PASS,
               (&raw), ALLOW_PROBE | EXP_PASS);

    /* Qcow2 file with relative raw backing, format provided */
    raw.pathAbs = "raw";
    testFileData qcow2 = {
        .expBackingStore = canonraw,
        .expBackingStoreRaw = "raw",
        .expCapacity = 1024,
        .pathRel = "qcow2",
        .pathAbs = canonqcow2,
        .path = canonqcow2,
        .relDirRel = ".",
        .relDirAbs = datadir,
        .type = VIR_STORAGE_TYPE_FILE,
        .format = VIR_STORAGE_FILE_QCOW2,
    };
    testFileData qcow2_as_raw = {
        .pathRel = "qcow2",
        .pathAbs = canonqcow2,
        .path = canonqcow2,
        .relDirRel = ".",
        .relDirAbs = datadir,
        .type = VIR_STORAGE_TYPE_FILE,
        .format = VIR_STORAGE_FILE_RAW,
    };
    TEST_CHAIN(3, "qcow2", absqcow2, VIR_STORAGE_FILE_QCOW2,
               (&qcow2, &raw), EXP_PASS,
               (&qcow2, &raw), ALLOW_PROBE | EXP_PASS,
               (&qcow2, &raw), EXP_PASS,
               (&qcow2, &raw), ALLOW_PROBE | EXP_PASS);
    TEST_CHAIN(4, "qcow2", absqcow2, VIR_STORAGE_FILE_AUTO,
               (&qcow2_as_raw), EXP_PASS,
               (&qcow2, &raw), ALLOW_PROBE | EXP_PASS,
               (&qcow2_as_raw), EXP_PASS,
               (&qcow2, &raw), ALLOW_PROBE | EXP_PASS);

    /* Rewrite qcow2 file to use absolute backing name */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "raw", "-b", absraw, "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;
    qcow2.expBackingStoreRaw = absraw;
    raw.pathRel = absraw;
    raw.pathAbs = absraw;
    raw.relDirRel = datadir;

    /* Qcow2 file with raw as absolute backing, backing format provided */
    TEST_CHAIN(5, "qcow2", absqcow2, VIR_STORAGE_FILE_QCOW2,
               (&qcow2, &raw), EXP_PASS,
               (&qcow2, &raw), ALLOW_PROBE | EXP_PASS,
               (&qcow2, &raw), EXP_PASS,
               (&qcow2, &raw), ALLOW_PROBE | EXP_PASS);
    TEST_CHAIN(6, "qcow2", absqcow2, VIR_STORAGE_FILE_AUTO,
               (&qcow2_as_raw), EXP_PASS,
               (&qcow2, &raw), ALLOW_PROBE | EXP_PASS,
               (&qcow2_as_raw), EXP_PASS,
               (&qcow2, &raw), ALLOW_PROBE | EXP_PASS);

    /* Wrapped file access */
    testFileData wrap = {
        .expBackingStore = canonqcow2,
        .expBackingStoreRaw = absqcow2,
        .expCapacity = 1024,
        .pathRel = "wrap",
        .pathAbs = abswrap,
        .path = canonwrap,
        .relDirRel = ".",
        .relDirAbs = datadir,
        .type = VIR_STORAGE_TYPE_FILE,
        .format = VIR_STORAGE_FILE_QCOW2,
    };
    qcow2.pathRel = absqcow2;
    qcow2.relDirRel = datadir;
    TEST_CHAIN(7, "wrap", abswrap, VIR_STORAGE_FILE_QCOW2,
               (&wrap, &qcow2, &raw), EXP_PASS,
               (&wrap, &qcow2, &raw), ALLOW_PROBE | EXP_PASS,
               (&wrap, &qcow2, &raw), EXP_PASS,
               (&wrap, &qcow2, &raw), ALLOW_PROBE | EXP_PASS);

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
    qcow2_as_raw.pathRel = absqcow2;
    qcow2_as_raw.relDirRel = datadir;

    /* Qcow2 file with raw as absolute backing, backing format omitted */
    testFileData wrap_as_raw = {
        .expBackingStore = canonqcow2,
        .expBackingStoreRaw = absqcow2,
        .expCapacity = 1024,
        .pathRel = "wrap",
        .pathAbs = abswrap,
        .path = canonwrap,
        .relDirRel = ".",
        .relDirAbs = datadir,
        .type = VIR_STORAGE_TYPE_FILE,
        .format = VIR_STORAGE_FILE_QCOW2,
    };
    TEST_CHAIN(8, "wrap", abswrap, VIR_STORAGE_FILE_QCOW2,
               (&wrap_as_raw, &qcow2_as_raw), EXP_PASS,
               (&wrap, &qcow2, &raw), ALLOW_PROBE | EXP_PASS,
               (&wrap_as_raw, &qcow2_as_raw), EXP_PASS,
               (&wrap, &qcow2, &raw), ALLOW_PROBE | EXP_PASS);

    /* Rewrite qcow2 to a missing backing file, with backing type */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "qcow2", "-b", datadir "/bogus",
                               "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;
    qcow2.expBackingStore = NULL;
    qcow2.expBackingStoreRaw = datadir "/bogus";
    qcow2.pathRel = "qcow2";
    qcow2.relDirRel = ".";

    /* Qcow2 file with missing backing file but specified type */
    TEST_CHAIN(9, "qcow2", absqcow2, VIR_STORAGE_FILE_QCOW2,
               (&qcow2), EXP_WARN,
               (&qcow2), ALLOW_PROBE | EXP_WARN,
               (&qcow2), EXP_WARN,
               (&qcow2), ALLOW_PROBE | EXP_WARN);

    /* Rewrite qcow2 to a missing backing file, without backing type */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-b", datadir "/bogus", "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;

    /* Qcow2 file with missing backing file and no specified type */
    TEST_CHAIN(10, "qcow2", absqcow2, VIR_STORAGE_FILE_QCOW2,
               (&qcow2), EXP_WARN,
               (&qcow2), ALLOW_PROBE | EXP_WARN,
               (&qcow2), EXP_WARN,
               (&qcow2), ALLOW_PROBE | EXP_WARN);

    /* Rewrite qcow2 to use an nbd: protocol as backend */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "raw", "-b", "nbd:example.org:6000",
                               "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;
    qcow2.expBackingStore = "nbd:example.org:6000";
    qcow2.expBackingStoreRaw = "nbd:example.org:6000";

    /* Qcow2 file with backing protocol instead of file */
    testFileData nbd = {
        .pathRel = "nbd:example.org:6000",
        .pathAbs = "nbd:example.org:6000",
        .path = "nbd:example.org:6000",
        .type = VIR_STORAGE_TYPE_NETWORK,
        .format = VIR_STORAGE_FILE_RAW,
    };
    TEST_CHAIN(11, "qcow2", absqcow2, VIR_STORAGE_FILE_QCOW2,
               (&qcow2, &nbd), EXP_PASS,
               (&qcow2, &nbd), ALLOW_PROBE | EXP_PASS,
               (&qcow2, &nbd), EXP_PASS,
               (&qcow2, &nbd), ALLOW_PROBE | EXP_PASS);

    /* qed file */
    testFileData qed = {
        .expBackingStore = canonraw,
        .expBackingStoreRaw = absraw,
        .expCapacity = 1024,
        .pathRel = "qed",
        .pathAbs = absqed,
        .path = canonqed,
        .relDirRel = ".",
        .relDirAbs = datadir,
        .type = VIR_STORAGE_TYPE_FILE,
        .format = VIR_STORAGE_FILE_QED,
    };
    testFileData qed_as_raw = {
        .pathRel = "qed",
        .pathAbs = absqed,
        .path = canonqed,
        .relDirRel = ".",
        .relDirAbs = datadir,
        .type = VIR_STORAGE_TYPE_FILE,
        .format = VIR_STORAGE_FILE_RAW,
    };
    TEST_CHAIN(12, "qed", absqed, VIR_STORAGE_FILE_AUTO,
               (&qed_as_raw), EXP_PASS,
               (&qed, &raw), ALLOW_PROBE | EXP_PASS,
               (&qed_as_raw), EXP_PASS,
               (&qed, &raw), ALLOW_PROBE | EXP_PASS);

    /* directory */
    testFileData dir = {
        .pathRel = "dir",
        .pathAbs = absdir,
        .path = canondir,
        .relDirRel = ".",
        .relDirAbs = datadir,
        .type = VIR_STORAGE_TYPE_DIR,
        .format = VIR_STORAGE_FILE_DIR,
    };
    TEST_CHAIN(13, "dir", absdir, VIR_STORAGE_FILE_AUTO,
               (&dir), EXP_PASS,
               (&dir), ALLOW_PROBE | EXP_PASS,
               (&dir), EXP_PASS,
               (&dir), ALLOW_PROBE | EXP_PASS);
    TEST_CHAIN(14, "dir", absdir, VIR_STORAGE_FILE_DIR,
               (&dir), EXP_PASS,
               (&dir), ALLOW_PROBE | EXP_PASS,
               (&dir), EXP_PASS,
               (&dir), ALLOW_PROBE | EXP_PASS);

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
    testFileData link1 = {
        .expBackingStore = canonraw,
        .expBackingStoreRaw = "../raw",
        .expCapacity = 1024,
        .pathRel = "../sub/link1",
        .pathAbs = "../sub/link1",
        .path = canonqcow2,
        .relDirRel = "sub/../sub",
        .relDirAbs = datadir "/sub/../sub",
        .type = VIR_STORAGE_TYPE_FILE,
        .format = VIR_STORAGE_FILE_QCOW2,
    };
    testFileData link2 = {
        .expBackingStore = canonqcow2,
        .expBackingStoreRaw = "../sub/link1",
        .expCapacity = 1024,
        .pathRel = "sub/link2",
        .pathAbs = abslink2,
        .path = canonwrap,
        .relDirRel = "sub",
        .relDirAbs = datadir "/sub",
        .type = VIR_STORAGE_TYPE_FILE,
        .format = VIR_STORAGE_FILE_QCOW2,
    };
    raw.pathRel = "../raw";
    raw.pathAbs = "../raw";
    raw.relDirRel = "sub/../sub/..";
    raw.relDirAbs = datadir "/sub/../sub/..";
    TEST_CHAIN(15, "sub/link2", abslink2, VIR_STORAGE_FILE_QCOW2,
               (&link2, &link1, &raw), EXP_PASS,
               (&link2, &link1, &raw), ALLOW_PROBE | EXP_PASS,
               (&link2, &link1, &raw), EXP_PASS,
               (&link2, &link1, &raw), ALLOW_PROBE | EXP_PASS);
#endif

    /* Rewrite qcow2 to be a self-referential loop */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "qcow2", "-b", "qcow2", "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;
    qcow2.expBackingStore = NULL;
    qcow2.expBackingStoreRaw = "qcow2";

    /* Behavior of an infinite loop chain */
    TEST_CHAIN(16, "qcow2", absqcow2, VIR_STORAGE_FILE_QCOW2,
               (&qcow2), EXP_WARN,
               (&qcow2), ALLOW_PROBE | EXP_WARN,
               (&qcow2), EXP_WARN,
               (&qcow2), ALLOW_PROBE | EXP_WARN);

    /* Rewrite wrap and qcow2 to be mutually-referential loop */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "qcow2", "-b", "wrap", "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;

    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "qcow2", "-b", absqcow2, "wrap", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;
    qcow2.expBackingStoreRaw = "wrap";
    qcow2.pathRel = absqcow2;
    qcow2.relDirRel =  datadir;

    /* Behavior of an infinite loop chain */
    TEST_CHAIN(17, "wrap", abswrap, VIR_STORAGE_FILE_QCOW2,
               (&wrap, &qcow2), EXP_WARN,
               (&wrap, &qcow2), ALLOW_PROBE | EXP_WARN,
               (&wrap, &qcow2), EXP_WARN,
               (&wrap, &qcow2), ALLOW_PROBE | EXP_WARN);

    /* Rewrite wrap and qcow2 back to 3-deep chain, absolute backing */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "qcow2", "-b", absraw, "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;

    /* Test behavior of chain lookups, absolute backing from relative start */
    chain = testStorageFileGetMetadata("wrap", VIR_STORAGE_FILE_QCOW2,
                                       -1, -1, false);
    if (!chain) {
        ret = -1;
        goto cleanup;
    }

#define TEST_LOOKUP_TARGET(id, target, name, index, result, meta, parent)   \
    do {                                                                    \
        struct testLookupData data2 = { chain, target, name, index,         \
                                        result, meta, parent, };            \
        if (virtTestRun("Chain lookup " #id,                                \
                        testStorageLookup, &data2) < 0)                     \
            ret = -1;                                                       \
    } while (0)
#define TEST_LOOKUP(id, name, result, meta, parent)                         \
    TEST_LOOKUP_TARGET(id, NULL, name, 0, result, meta, parent)

    TEST_LOOKUP(0, "bogus", NULL, NULL, NULL);
    TEST_LOOKUP(1, "wrap", chain->path, chain, NULL);
    TEST_LOOKUP(2, abswrap, chain->path, chain, NULL);
    TEST_LOOKUP(3, "qcow2", chain->backingStore->path, chain->backingStore,
                chain->path);
    TEST_LOOKUP(4, absqcow2, chain->backingStore->path, chain->backingStore,
                chain->path);
    TEST_LOOKUP(5, "raw", chain->backingStore->backingStore->path,
                chain->backingStore->backingStore, chain->backingStore->path);
    TEST_LOOKUP(6, absraw, chain->backingStore->backingStore->path,
                chain->backingStore->backingStore, chain->backingStore->path);
    TEST_LOOKUP(7, NULL, chain->backingStore->backingStore->path,
                chain->backingStore->backingStore, chain->backingStore->path);

    /* Rewrite wrap and qcow2 back to 3-deep chain, relative backing */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "raw", "-b", "raw", "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;

    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "qcow2", "-b", "qcow2", "wrap", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;

    /* Test behavior of chain lookups, relative backing from absolute start */
    virStorageSourceFree(chain);
    chain = testStorageFileGetMetadata(abswrap, VIR_STORAGE_FILE_QCOW2,
                                       -1, -1, false);
    if (!chain) {
        ret = -1;
        goto cleanup;
    }

    TEST_LOOKUP(8, "bogus", NULL, NULL, NULL);
    TEST_LOOKUP(9, "wrap", chain->path, chain, NULL);
    TEST_LOOKUP(10, abswrap, chain->path, chain, NULL);
    TEST_LOOKUP(11, "qcow2", chain->backingStore->path, chain->backingStore,
                chain->path);
    TEST_LOOKUP(12, absqcow2, chain->backingStore->path, chain->backingStore,
                chain->path);
    TEST_LOOKUP(13, "raw", chain->backingStore->backingStore->path,
                chain->backingStore->backingStore, chain->backingStore->path);
    TEST_LOOKUP(14, absraw, chain->backingStore->backingStore->path,
                chain->backingStore->backingStore, chain->backingStore->path);
    TEST_LOOKUP(15, NULL, chain->backingStore->backingStore->path,
                chain->backingStore->backingStore, chain->backingStore->path);

    /* Use link to wrap with cross-directory relative backing */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "qcow2", "-b", "../qcow2", "wrap", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;

    /* Test behavior of chain lookups, relative backing */
    virStorageSourceFree(chain);
    chain = testStorageFileGetMetadata("sub/link2", VIR_STORAGE_FILE_QCOW2,
                                       -1, -1, false);
    if (!chain) {
        ret = -1;
        goto cleanup;
    }

    TEST_LOOKUP(16, "bogus", NULL, NULL, NULL);
    TEST_LOOKUP(17, "sub/link2", chain->path, chain, NULL);
    TEST_LOOKUP(18, "wrap", chain->path, chain, NULL);
    TEST_LOOKUP(19, abswrap, chain->path, chain, NULL);
    TEST_LOOKUP(20, "../qcow2", chain->backingStore->path, chain->backingStore,
                chain->path);
    TEST_LOOKUP(21, "qcow2", NULL, NULL, NULL);
    TEST_LOOKUP(22, absqcow2, chain->backingStore->path, chain->backingStore,
                chain->path);
    TEST_LOOKUP(23, "raw", chain->backingStore->backingStore->path,
                chain->backingStore->backingStore, chain->backingStore->path);
    TEST_LOOKUP(24, absraw, chain->backingStore->backingStore->path,
                chain->backingStore->backingStore, chain->backingStore->path);
    TEST_LOOKUP(25, NULL, chain->backingStore->backingStore->path,
                chain->backingStore->backingStore, chain->backingStore->path);

    TEST_LOOKUP_TARGET(26, "vda", "bogus[1]", 0, NULL, NULL, NULL);
    TEST_LOOKUP_TARGET(27, "vda", "vda[-1]", 0, NULL, NULL, NULL);
    TEST_LOOKUP_TARGET(28, "vda", "vda[1][1]", 0, NULL, NULL, NULL);
    TEST_LOOKUP_TARGET(29, "vda", "wrap", 0, chain->path, chain, NULL);
    TEST_LOOKUP_TARGET(30, "vda", "vda[0]", 0, NULL, NULL, NULL);
    TEST_LOOKUP_TARGET(31, "vda", "vda[1]", 1,
                       chain->backingStore->path,
                       chain->backingStore,
                       chain->path);
    TEST_LOOKUP_TARGET(32, "vda", "vda[2]", 2,
                       chain->backingStore->backingStore->path,
                       chain->backingStore->backingStore,
                       chain->backingStore->path);
    TEST_LOOKUP_TARGET(33, "vda", "vda[3]", 3, NULL, NULL, NULL);

 cleanup:
    /* Final cleanup */
    virStorageSourceFree(chain);
    testCleanupImages();
    virCommandFree(cmd);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
