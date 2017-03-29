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

#include "storage/storage_driver.h"
#include "storage/storage_backend.h"

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
    struct stat st;
    virStorageSourcePtr ret = NULL;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    ret->type = VIR_STORAGE_TYPE_FILE;
    ret->format = format;

    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            ret->type = VIR_STORAGE_TYPE_DIR;
            ret->format = VIR_STORAGE_FILE_DIR;
        } else if (S_ISBLK(st.st_mode)) {
            ret->type = VIR_STORAGE_TYPE_BLOCK;
        }
    }

    if (VIR_STRDUP(ret->path, path) < 0)
        goto error;

    if (virStorageFileGetMetadata(ret, uid, gid, allow_probe, false) < 0)
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
    const char *expBackingStoreRaw;
    unsigned long long expCapacity;
    bool expEncrypted;
    const char *pathRel;
    const char *path;
    int type;
    int format;
    const char *secret;
    const char *hostname;
    int protocol;
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
    virStorageFileFormat format;
    const testFileData *files[4];
    int nfiles;
    unsigned int flags;
};


static const char testStorageChainFormat[] =
    "chain member: %zu\n"
    "path:%s\n"
    "backingStoreRaw: %s\n"
    "capacity: %lld\n"
    "encryption: %d\n"
    "relPath:%s\n"
    "type:%d\n"
    "format:%d\n"
    "protocol:%s\n"
    "hostname:%s\n"
    "secret:%s\n";

static int
testStorageChain(const void *args)
{
    const struct testChainData *data = args;
    int ret = -1;
    virStorageSourcePtr meta;
    virStorageSourcePtr elt;
    size_t i = 0;
    char *broken = NULL;

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

        if (i == data->nfiles) {
            fprintf(stderr, "probed chain was too long\n");
            goto cleanup;
        }

        if (virAsprintf(&expect,
                        testStorageChainFormat, i,
                        NULLSTR(data->files[i]->path),
                        NULLSTR(data->files[i]->expBackingStoreRaw),
                        data->files[i]->expCapacity,
                        data->files[i]->expEncrypted,
                        NULLSTR(data->files[i]->pathRel),
                        data->files[i]->type,
                        data->files[i]->format,
                        virStorageNetProtocolTypeToString(data->files[i]->protocol),
                        NULLSTR(data->files[i]->hostname),
                        NULLSTR(data->files[i]->secret)) < 0 ||
            virAsprintf(&actual,
                        testStorageChainFormat, i,
                        NULLSTR(elt->path),
                        NULLSTR(elt->backingStoreRaw),
                        elt->capacity,
                        !!elt->encryption,
                        NULLSTR(elt->relPath),
                        elt->type,
                        elt->format,
                        virStorageNetProtocolTypeToString(elt->protocol),
                        NULLSTR(elt->nhosts ? elt->hosts[0].name : NULL),
                        NULLSTR(elt->auth ? elt->auth->username : NULL)) < 0) {
            VIR_FREE(expect);
            VIR_FREE(actual);
            goto cleanup;
        }
        if (STRNEQ(expect, actual)) {
            virTestDifference(stderr, expect, actual);
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
    virStorageSourcePtr from;
    const char *name;
    unsigned int expIndex;
    const char *expResult;
    virStorageSourcePtr expMeta;
    virStorageSourcePtr expParent;
};

static int
testStorageLookup(const void *args)
{
    const struct testLookupData *data = args;
    int ret = 0;
    virStorageSourcePtr result;
    virStorageSourcePtr actualParent;
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
    result = virStorageFileChainLookup(data->chain, data->from,
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

    result = virStorageFileChainLookup(data->chain, data->from,
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
    if (data->expParent != actualParent) {
        fprintf(stderr, "parent: expected %s, got %s\n",
                NULLSTR(data->expParent ? data->expParent->path : NULL),
                NULLSTR(actualParent ? actualParent->path : NULL));
        ret = -1;
    }

    return ret;
}


struct testPathCanonicalizeData
{
    const char *path;
    const char *expect;
};

static const char *testPathCanonicalizeSymlinks[][2] =
{
    {"/path/blah", "/other/path/huzah"},
    {"/path/to/relative/symlink", "../../actual/file"},
    {"/cycle", "/cycle"},
    {"/cycle2/link", "./link"},
};

static int
testPathCanonicalizeReadlink(const char *path,
                             char **linkpath,
                             void *data ATTRIBUTE_UNUSED)
{
    size_t i;

    *linkpath = NULL;

    for (i = 0; i < ARRAY_CARDINALITY(testPathCanonicalizeSymlinks); i++) {
        if (STREQ(path, testPathCanonicalizeSymlinks[i][0])) {
            if (VIR_STRDUP(*linkpath, testPathCanonicalizeSymlinks[i][1]) < 0)
                return -1;

            return 0;
        }
    }

    return 1;
}


static int
testPathCanonicalize(const void *args)
{
    const struct testPathCanonicalizeData *data = args;
    char *canon = NULL;
    int ret = -1;

    canon = virStorageFileCanonicalizePath(data->path,
                                           testPathCanonicalizeReadlink,
                                           NULL);

    if (STRNEQ_NULLABLE(data->expect, canon)) {
        fprintf(stderr,
                "path canonicalization of '%s' failed: expected '%s' got '%s'\n",
                data->path, NULLSTR(data->expect), NULLSTR(canon));

        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(canon);

    return ret;
}

static virStorageSource backingchain[12];

static void
testPathRelativePrepare(void)
{
    size_t i;

    for (i = 0; i < ARRAY_CARDINALITY(backingchain); i++) {
        if (i < ARRAY_CARDINALITY(backingchain) - 1)
            backingchain[i].backingStore = &backingchain[i + 1];
        else
            backingchain[i].backingStore = NULL;

        backingchain[i].relPath = NULL;
    }

    /* normal relative backing chain */
    backingchain[0].path = (char *) "/path/to/some/img";

    backingchain[1].path = (char *) "/path/to/some/asdf";
    backingchain[1].relPath = (char *) "asdf";

    backingchain[2].path = (char *) "/path/to/some/test";
    backingchain[2].relPath = (char *) "test";

    backingchain[3].path = (char *) "/path/to/some/blah";
    backingchain[3].relPath = (char *) "blah";

    /* ovirt's backing chain */
    backingchain[4].path = (char *) "/path/to/volume/image1";

    backingchain[5].path = (char *) "/path/to/volume/image2";
    backingchain[5].relPath = (char *) "../volume/image2";

    backingchain[6].path = (char *) "/path/to/volume/image3";
    backingchain[6].relPath = (char *) "../volume/image3";

    backingchain[7].path = (char *) "/path/to/volume/image4";
    backingchain[7].relPath = (char *) "../volume/image4";

    /* some arbitrarily crazy backing chains */
    backingchain[8].path = (char *) "/crazy/base/image";

    backingchain[9].path = (char *) "/crazy/base/directory/stuff/volumes/garbage/image2";
    backingchain[9].relPath = (char *) "directory/stuff/volumes/garbage/image2";

    backingchain[10].path = (char *) "/crazy/base/directory/image3";
    backingchain[10].relPath = (char *) "../../../image3";

    backingchain[11].path = (char *) "/crazy/base/blah/image4";
    backingchain[11].relPath = (char *) "../blah/image4";
}


struct testPathRelativeBacking
{
    virStorageSourcePtr top;
    virStorageSourcePtr base;

    const char *expect;
};

static int
testPathRelative(const void *args)
{
    const struct testPathRelativeBacking *data = args;
    char *actual = NULL;
    int ret = -1;

    if (virStorageFileGetRelativeBackingPath(data->top,
                                             data->base,
                                             &actual) < 0) {
        fprintf(stderr, "relative backing path resolution failed\n");
        goto cleanup;
    }

    if (STRNEQ_NULLABLE(data->expect, actual)) {
        fprintf(stderr, "relative path resolution from '%s' to '%s': "
                "expected '%s', got '%s'\n",
                data->top->path, data->base->path,
                NULLSTR(data->expect), NULLSTR(actual));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(actual);

    return ret;
}


struct testBackingParseData {
    const char *backing;
    const char *expect;
};

static int
testBackingParse(const void *args)
{
    const struct testBackingParseData *data = args;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virStorageSourcePtr src = NULL;
    char *xml = NULL;
    int ret = -1;

    if (!(src = virStorageSourceNewFromBackingAbsolute(data->backing))) {
        if (!data->expect)
            ret = 0;

        goto cleanup;
    }

    if (src && !data->expect) {
        fprintf(stderr, "parsing of backing store string '%s' should "
                        "have failed\n", data->backing);
        goto cleanup;
    }

    if (virDomainDiskSourceFormat(&buf, src, 0, 0) < 0 ||
        !(xml = virBufferContentAndReset(&buf))) {
        fprintf(stderr, "failed to format disk source xml\n");
        goto cleanup;
    }

    if (STRNEQ(xml, data->expect)) {
        fprintf(stderr, "\n backing store string '%s'\n"
                        "expected storage source xml:\n%s\n"
                        "actual storage source xml:\n%s\n",
                        data->backing, data->expect, xml);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virStorageSourceFree(src);
    virBufferFreeAndReset(&buf);
    VIR_FREE(xml);

    return ret;
}


static int
mymain(void)
{
    int ret;
    virCommandPtr cmd = NULL;
    struct testChainData data;
    struct testLookupData data2;
    struct testPathCanonicalizeData data3;
    struct testPathRelativeBacking data4;
    struct testBackingParseData data5;
    virStorageSourcePtr chain = NULL;
    virStorageSourcePtr chain2; /* short for chain->backingStore */
    virStorageSourcePtr chain3; /* short for chain2->backingStore */

    if (virStorageBackendDriversRegister(false) < 0)
       return -1;

    /* Prep some files with qemu-img; if that is not found on PATH, or
     * if it lacks support for qcow2 and qed, skip this test.  */
    if ((ret = testPrepImages()) != 0)
        return ret;

#define TEST_ONE_CHAIN(start, format, flags, ...)                    \
    do {                                                             \
        size_t i;                                                    \
        memset(&data, 0, sizeof(data));                              \
        data = (struct testChainData){                               \
            start, format, { __VA_ARGS__ }, 0, flags,                \
        };                                                           \
        for (i = 0; i < ARRAY_CARDINALITY(data.files); i++)          \
            if (data.files[i])                                       \
                data.nfiles++;                                       \
        if (virTestRun(virTestCounterNext(),                         \
                       testStorageChain, &data) < 0)                 \
            ret = -1;                                                \
    } while (0)

#define VIR_FLATTEN_2(...) __VA_ARGS__
#define VIR_FLATTEN_1(_1) VIR_FLATTEN_2 _1

#define TEST_CHAIN(path, format, chain1, flags1, chain2, flags2)      \
    do {                                                              \
        TEST_ONE_CHAIN(path, format, flags1, VIR_FLATTEN_1(chain1));  \
        TEST_ONE_CHAIN(path, format, flags2, VIR_FLATTEN_1(chain2));  \
    } while (0)

    /* The actual tests, in several groups. */
    virTestCounterReset("Storage backing chain ");

    /* Missing file */
    TEST_ONE_CHAIN("bogus", VIR_STORAGE_FILE_RAW, EXP_FAIL);

    /* Raw image, whether with right format or no specified format */
    testFileData raw = {
        .path = canonraw,
        .type = VIR_STORAGE_TYPE_FILE,
        .format = VIR_STORAGE_FILE_RAW,
    };
    TEST_CHAIN(absraw, VIR_STORAGE_FILE_RAW,
               (&raw), EXP_PASS,
               (&raw), ALLOW_PROBE | EXP_PASS);
    TEST_CHAIN(absraw, VIR_STORAGE_FILE_AUTO,
               (&raw), EXP_PASS,
               (&raw), ALLOW_PROBE | EXP_PASS);

    /* Qcow2 file with relative raw backing, format provided */
    raw.pathRel = "raw";
    testFileData qcow2 = {
        .expBackingStoreRaw = "raw",
        .expCapacity = 1024,
        .path = canonqcow2,
        .type = VIR_STORAGE_TYPE_FILE,
        .format = VIR_STORAGE_FILE_QCOW2,
    };
    testFileData qcow2_as_raw = {
        .path = canonqcow2,
        .type = VIR_STORAGE_TYPE_FILE,
        .format = VIR_STORAGE_FILE_RAW,
    };
    TEST_CHAIN(absqcow2, VIR_STORAGE_FILE_QCOW2,
               (&qcow2, &raw), EXP_PASS,
               (&qcow2, &raw), ALLOW_PROBE | EXP_PASS);
    TEST_CHAIN(absqcow2, VIR_STORAGE_FILE_AUTO,
               (&qcow2_as_raw), EXP_PASS,
               (&qcow2, &raw), ALLOW_PROBE | EXP_PASS);

    /* Rewrite qcow2 file to use absolute backing name */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "raw", "-b", absraw, "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;
    qcow2.expBackingStoreRaw = absraw;
    raw.pathRel = NULL;

    /* Qcow2 file with raw as absolute backing, backing format provided */
    TEST_CHAIN(absqcow2, VIR_STORAGE_FILE_QCOW2,
               (&qcow2, &raw), EXP_PASS,
               (&qcow2, &raw), ALLOW_PROBE | EXP_PASS);
    TEST_CHAIN(absqcow2, VIR_STORAGE_FILE_AUTO,
               (&qcow2_as_raw), EXP_PASS,
               (&qcow2, &raw), ALLOW_PROBE | EXP_PASS);

    /* Wrapped file access */
    testFileData wrap = {
        .expBackingStoreRaw = absqcow2,
        .expCapacity = 1024,
        .path = canonwrap,
        .type = VIR_STORAGE_TYPE_FILE,
        .format = VIR_STORAGE_FILE_QCOW2,
    };
    TEST_CHAIN(abswrap, VIR_STORAGE_FILE_QCOW2,
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

    /* Qcow2 file with raw as absolute backing, backing format omitted */
    testFileData wrap_as_raw = {
        .expBackingStoreRaw = absqcow2,
        .expCapacity = 1024,
        .path = canonwrap,
        .type = VIR_STORAGE_TYPE_FILE,
        .format = VIR_STORAGE_FILE_QCOW2,
    };
    TEST_CHAIN(abswrap, VIR_STORAGE_FILE_QCOW2,
               (&wrap_as_raw, &qcow2_as_raw), EXP_PASS,
               (&wrap, &qcow2, &raw), ALLOW_PROBE | EXP_PASS);

    /* Rewrite qcow2 to a missing backing file, with backing type */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "qcow2", "-b", datadir "/bogus",
                               "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;
    qcow2.expBackingStoreRaw = datadir "/bogus";

    /* Qcow2 file with missing backing file but specified type */
    TEST_CHAIN(absqcow2, VIR_STORAGE_FILE_QCOW2,
               (&qcow2), EXP_WARN,
               (&qcow2), ALLOW_PROBE | EXP_WARN);

    /* Rewrite qcow2 to a missing backing file, without backing type */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-b", datadir "/bogus", "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;

    /* Qcow2 file with missing backing file and no specified type */
    TEST_CHAIN(absqcow2, VIR_STORAGE_FILE_QCOW2,
               (&qcow2), EXP_WARN,
               (&qcow2), ALLOW_PROBE | EXP_WARN);

    /* Rewrite qcow2 to use an nbd: protocol as backend */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "raw", "-b", "nbd:example.org:6000:exportname=blah",
                               "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;
    qcow2.expBackingStoreRaw = "nbd:example.org:6000:exportname=blah";

    /* Qcow2 file with backing protocol instead of file */
    testFileData nbd = {
        .path = "blah",
        .type = VIR_STORAGE_TYPE_NETWORK,
        .format = VIR_STORAGE_FILE_RAW,
        .protocol = VIR_STORAGE_NET_PROTOCOL_NBD,
        .hostname = "example.org",
    };
    TEST_CHAIN(absqcow2, VIR_STORAGE_FILE_QCOW2,
               (&qcow2, &nbd), EXP_PASS,
               (&qcow2, &nbd), ALLOW_PROBE | EXP_PASS);

    /* Rewrite qcow2 to use an nbd: protocol as backend */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "raw", "-b", "nbd+tcp://example.org:6000/blah",
                               "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;
    qcow2.expBackingStoreRaw = "nbd+tcp://example.org:6000/blah";

    /* Qcow2 file with backing protocol instead of file */
    testFileData nbd2 = {
        .path = "blah",
        .type = VIR_STORAGE_TYPE_NETWORK,
        .format = VIR_STORAGE_FILE_RAW,
        .protocol = VIR_STORAGE_NET_PROTOCOL_NBD,
        .hostname = "example.org",
    };
    TEST_CHAIN(absqcow2, VIR_STORAGE_FILE_QCOW2,
               (&qcow2, &nbd2), EXP_PASS,
               (&qcow2, &nbd2), ALLOW_PROBE | EXP_PASS);

    /* Rewrite qcow2 to use an nbd: protocol without path as backend */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "raw", "-b", "nbd://example.org",
                               "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;
    qcow2.expBackingStoreRaw = "nbd://example.org";

    nbd2.path = NULL;
    TEST_CHAIN(absqcow2, VIR_STORAGE_FILE_QCOW2,
               (&qcow2, &nbd2), EXP_PASS,
               (&qcow2, &nbd2), ALLOW_PROBE | EXP_PASS);

    /* qed file */
    testFileData qed = {
        .expBackingStoreRaw = absraw,
        .expCapacity = 1024,
        .path = canonqed,
        .type = VIR_STORAGE_TYPE_FILE,
        .format = VIR_STORAGE_FILE_QED,
    };
    testFileData qed_as_raw = {
        .path = canonqed,
        .type = VIR_STORAGE_TYPE_FILE,
        .format = VIR_STORAGE_FILE_RAW,
    };
    TEST_CHAIN(absqed, VIR_STORAGE_FILE_AUTO,
               (&qed_as_raw), EXP_PASS,
               (&qed, &raw), ALLOW_PROBE | EXP_PASS);

    /* directory */
    testFileData dir = {
        .path = canondir,
        .type = VIR_STORAGE_TYPE_DIR,
        .format = VIR_STORAGE_FILE_DIR,
    };
    TEST_CHAIN(absdir, VIR_STORAGE_FILE_AUTO,
               (&dir), EXP_PASS,
               (&dir), ALLOW_PROBE | EXP_PASS);
    TEST_CHAIN(absdir, VIR_STORAGE_FILE_DIR,
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
        .expBackingStoreRaw = "../raw",
        .expCapacity = 1024,
        .pathRel = "../sub/link1",
        .path = datadir "/sub/../sub/link1",
        .type = VIR_STORAGE_TYPE_FILE,
        .format = VIR_STORAGE_FILE_QCOW2,
    };
    testFileData link2 = {
        .expBackingStoreRaw = "../sub/link1",
        .expCapacity = 1024,
        .path = abslink2,
        .type = VIR_STORAGE_TYPE_FILE,
        .format = VIR_STORAGE_FILE_QCOW2,
    };

    raw.path = datadir "/sub/../sub/../raw";
    raw.pathRel = "../raw";
    TEST_CHAIN(abslink2, VIR_STORAGE_FILE_QCOW2,
               (&link2, &link1, &raw), EXP_PASS,
               (&link2, &link1, &raw), ALLOW_PROBE | EXP_PASS);
#endif

    /* Rewrite qcow2 to be a self-referential loop */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "qcow2", "-b", "qcow2", "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;
    qcow2.expBackingStoreRaw = "qcow2";

    /* Behavior of an infinite loop chain */
    TEST_CHAIN(absqcow2, VIR_STORAGE_FILE_QCOW2,
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

    /* Behavior of an infinite loop chain */
    TEST_CHAIN(abswrap, VIR_STORAGE_FILE_QCOW2,
               (&wrap, &qcow2), EXP_WARN,
               (&wrap, &qcow2), ALLOW_PROBE | EXP_WARN);

    /* Rewrite qcow2 to use an rbd: protocol as backend */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "raw", "-b", "rbd:testshare",
                               "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;
    qcow2.expBackingStoreRaw = "rbd:testshare";

    /* Qcow2 file with backing protocol instead of file */
    testFileData rbd1 = {
        .path = "testshare",
        .type = VIR_STORAGE_TYPE_NETWORK,
        .format = VIR_STORAGE_FILE_RAW,
        .protocol = VIR_STORAGE_NET_PROTOCOL_RBD,
    };
    TEST_CHAIN(absqcow2, VIR_STORAGE_FILE_QCOW2,
               (&qcow2, &rbd1), EXP_PASS,
               (&qcow2, &rbd1), ALLOW_PROBE | EXP_PASS);

    /* Rewrite qcow2 to use an rbd: protocol as backend */
    virCommandFree(cmd);
    cmd = virCommandNewArgList(qemuimg, "rebase", "-u", "-f", "qcow2",
                               "-F", "raw", "-b", "rbd:testshare:id=asdf:mon_host=example.com",
                               "qcow2", NULL);
    if (virCommandRun(cmd, NULL) < 0)
        ret = -1;
    qcow2.expBackingStoreRaw = "rbd:testshare:id=asdf:mon_host=example.com";

    /* Qcow2 file with backing protocol instead of file */
    testFileData rbd2 = {
        .path = "testshare",
        .type = VIR_STORAGE_TYPE_NETWORK,
        .format = VIR_STORAGE_FILE_RAW,
        .protocol = VIR_STORAGE_NET_PROTOCOL_RBD,
        .secret = "asdf",
        .hostname = "example.com",
    };
    TEST_CHAIN(absqcow2, VIR_STORAGE_FILE_QCOW2,
               (&qcow2, &rbd2), EXP_PASS,
               (&qcow2, &rbd2), ALLOW_PROBE | EXP_PASS);


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
    chain2 = chain->backingStore;
    chain3 = chain2->backingStore;

#define TEST_LOOKUP_TARGET(id, target, from, name, index, result,       \
                           meta, parent)                                \
    do {                                                                \
        data2 = (struct testLookupData){                                \
            chain, target, from, name, index,                           \
            result, meta, parent, };                                    \
        if (virTestRun("Chain lookup " #id,                             \
                       testStorageLookup, &data2) < 0)                  \
            ret = -1;                                                   \
    } while (0)
#define TEST_LOOKUP(id, from, name, result, meta, parent)               \
    TEST_LOOKUP_TARGET(id, NULL, from, name, 0, result, meta, parent)

    TEST_LOOKUP(0, NULL, "bogus", NULL, NULL, NULL);
    TEST_LOOKUP(1, chain, "bogus", NULL, NULL, NULL);
    TEST_LOOKUP(2, NULL, "wrap", chain->path, chain, NULL);
    TEST_LOOKUP(3, chain, "wrap", NULL, NULL, NULL);
    TEST_LOOKUP(4, chain2, "wrap", NULL, NULL, NULL);
    TEST_LOOKUP(5, NULL, abswrap, chain->path, chain, NULL);
    TEST_LOOKUP(6, chain, abswrap, NULL, NULL, NULL);
    TEST_LOOKUP(7, chain2, abswrap, NULL, NULL, NULL);
    TEST_LOOKUP(8, NULL, "qcow2", chain2->path, chain2, chain);
    TEST_LOOKUP(9, chain, "qcow2", chain2->path, chain2, chain);
    TEST_LOOKUP(10, chain2, "qcow2", NULL, NULL, NULL);
    TEST_LOOKUP(11, chain3, "qcow2", NULL, NULL, NULL);
    TEST_LOOKUP(12, NULL, absqcow2, chain2->path, chain2, chain);
    TEST_LOOKUP(13, chain, absqcow2, chain2->path, chain2, chain);
    TEST_LOOKUP(14, chain2, absqcow2, NULL, NULL, NULL);
    TEST_LOOKUP(15, chain3, absqcow2, NULL, NULL, NULL);
    TEST_LOOKUP(16, NULL, "raw", chain3->path, chain3, chain2);
    TEST_LOOKUP(17, chain, "raw", chain3->path, chain3, chain2);
    TEST_LOOKUP(18, chain2, "raw", chain3->path, chain3, chain2);
    TEST_LOOKUP(19, chain3, "raw", NULL, NULL, NULL);
    TEST_LOOKUP(20, NULL, absraw, chain3->path, chain3, chain2);
    TEST_LOOKUP(21, chain, absraw, chain3->path, chain3, chain2);
    TEST_LOOKUP(22, chain2, absraw, chain3->path, chain3, chain2);
    TEST_LOOKUP(23, chain3, absraw, NULL, NULL, NULL);
    TEST_LOOKUP(24, NULL, NULL, chain3->path, chain3, chain2);
    TEST_LOOKUP(25, chain, NULL, chain3->path, chain3, chain2);
    TEST_LOOKUP(26, chain2, NULL, chain3->path, chain3, chain2);
    TEST_LOOKUP(27, chain3, NULL, NULL, NULL, NULL);

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
    chain2 = chain->backingStore;
    chain3 = chain2->backingStore;

    TEST_LOOKUP(28, NULL, "bogus", NULL, NULL, NULL);
    TEST_LOOKUP(29, chain, "bogus", NULL, NULL, NULL);
    TEST_LOOKUP(30, NULL, "wrap", chain->path, chain, NULL);
    TEST_LOOKUP(31, chain, "wrap", NULL, NULL, NULL);
    TEST_LOOKUP(32, chain2, "wrap", NULL, NULL, NULL);
    TEST_LOOKUP(33, NULL, abswrap, chain->path, chain, NULL);
    TEST_LOOKUP(34, chain, abswrap, NULL, NULL, NULL);
    TEST_LOOKUP(35, chain2, abswrap, NULL, NULL, NULL);
    TEST_LOOKUP(36, NULL, "qcow2", chain2->path, chain2, chain);
    TEST_LOOKUP(37, chain, "qcow2", chain2->path, chain2, chain);
    TEST_LOOKUP(38, chain2, "qcow2", NULL, NULL, NULL);
    TEST_LOOKUP(39, chain3, "qcow2", NULL, NULL, NULL);
    TEST_LOOKUP(40, NULL, absqcow2, chain2->path, chain2, chain);
    TEST_LOOKUP(41, chain, absqcow2, chain2->path, chain2, chain);
    TEST_LOOKUP(42, chain2, absqcow2, NULL, NULL, NULL);
    TEST_LOOKUP(43, chain3, absqcow2, NULL, NULL, NULL);
    TEST_LOOKUP(44, NULL, "raw", chain3->path, chain3, chain2);
    TEST_LOOKUP(45, chain, "raw", chain3->path, chain3, chain2);
    TEST_LOOKUP(46, chain2, "raw", chain3->path, chain3, chain2);
    TEST_LOOKUP(47, chain3, "raw", NULL, NULL, NULL);
    TEST_LOOKUP(48, NULL, absraw, chain3->path, chain3, chain2);
    TEST_LOOKUP(49, chain, absraw, chain3->path, chain3, chain2);
    TEST_LOOKUP(50, chain2, absraw, chain3->path, chain3, chain2);
    TEST_LOOKUP(51, chain3, absraw, NULL, NULL, NULL);
    TEST_LOOKUP(52, NULL, NULL, chain3->path, chain3, chain2);
    TEST_LOOKUP(53, chain, NULL, chain3->path, chain3, chain2);
    TEST_LOOKUP(54, chain2, NULL, chain3->path, chain3, chain2);
    TEST_LOOKUP(55, chain3, NULL, NULL, NULL, NULL);

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
    chain2 = chain->backingStore;
    chain3 = chain2->backingStore;

    TEST_LOOKUP(56, NULL, "bogus", NULL, NULL, NULL);
    TEST_LOOKUP(57, NULL, "sub/link2", chain->path, chain, NULL);
    TEST_LOOKUP(58, NULL, "wrap", chain->path, chain, NULL);
    TEST_LOOKUP(59, NULL, abswrap, chain->path, chain, NULL);
    TEST_LOOKUP(60, NULL, "../qcow2", chain2->path, chain2, chain);
    TEST_LOOKUP(61, NULL, "qcow2", NULL, NULL, NULL);
    TEST_LOOKUP(62, NULL, absqcow2, chain2->path, chain2, chain);
    TEST_LOOKUP(63, NULL, "raw", chain3->path, chain3, chain2);
    TEST_LOOKUP(64, NULL, absraw, chain3->path, chain3, chain2);
    TEST_LOOKUP(65, NULL, NULL, chain3->path, chain3, chain2);

    TEST_LOOKUP_TARGET(66, "vda", NULL, "bogus[1]", 0, NULL, NULL, NULL);
    TEST_LOOKUP_TARGET(67, "vda", NULL, "vda[-1]", 0, NULL, NULL, NULL);
    TEST_LOOKUP_TARGET(68, "vda", NULL, "vda[1][1]", 0, NULL, NULL, NULL);
    TEST_LOOKUP_TARGET(69, "vda", NULL, "wrap", 0, chain->path, chain, NULL);
    TEST_LOOKUP_TARGET(70, "vda", chain, "wrap", 0, NULL, NULL, NULL);
    TEST_LOOKUP_TARGET(71, "vda", chain2, "wrap", 0, NULL, NULL, NULL);
    TEST_LOOKUP_TARGET(72, "vda", NULL, "vda[0]", 0, NULL, NULL, NULL);
    TEST_LOOKUP_TARGET(73, "vda", NULL, "vda[1]", 1, chain2->path, chain2, chain);
    TEST_LOOKUP_TARGET(74, "vda", chain, "vda[1]", 1, chain2->path, chain2, chain);
    TEST_LOOKUP_TARGET(75, "vda", chain2, "vda[1]", 1, NULL, NULL, NULL);
    TEST_LOOKUP_TARGET(76, "vda", chain3, "vda[1]", 1, NULL, NULL, NULL);
    TEST_LOOKUP_TARGET(77, "vda", NULL, "vda[2]", 2, chain3->path, chain3, chain2);
    TEST_LOOKUP_TARGET(78, "vda", chain, "vda[2]", 2, chain3->path, chain3, chain2);
    TEST_LOOKUP_TARGET(79, "vda", chain2, "vda[2]", 2, chain3->path, chain3, chain2);
    TEST_LOOKUP_TARGET(80, "vda", chain3, "vda[2]", 2, NULL, NULL, NULL);
    TEST_LOOKUP_TARGET(81, "vda", NULL, "vda[3]", 3, NULL, NULL, NULL);

#define TEST_PATH_CANONICALIZE(id, PATH, EXPECT)                            \
    do {                                                                    \
        data3.path = PATH;                                                  \
        data3.expect = EXPECT;                                              \
        if (virTestRun("Path canonicalize " #id,                            \
                       testPathCanonicalize, &data3) < 0)                   \
            ret = -1;                                                       \
    } while (0)

    TEST_PATH_CANONICALIZE(1, "/", "/");
    TEST_PATH_CANONICALIZE(2, "/path", "/path");
    TEST_PATH_CANONICALIZE(3, "/path/to/blah", "/path/to/blah");
    TEST_PATH_CANONICALIZE(4, "/path/", "/path");
    TEST_PATH_CANONICALIZE(5, "///////", "/");
    TEST_PATH_CANONICALIZE(6, "//", "//");
    TEST_PATH_CANONICALIZE(7, "", "");
    TEST_PATH_CANONICALIZE(8, ".", ".");
    TEST_PATH_CANONICALIZE(9, "../", "..");
    TEST_PATH_CANONICALIZE(10, "../../", "../..");
    TEST_PATH_CANONICALIZE(11, "../../blah", "../../blah");
    TEST_PATH_CANONICALIZE(12, "/./././blah", "/blah");
    TEST_PATH_CANONICALIZE(13, ".././../././../blah", "../../../blah");
    TEST_PATH_CANONICALIZE(14, "/././", "/");
    TEST_PATH_CANONICALIZE(15, "./././", ".");
    TEST_PATH_CANONICALIZE(16, "blah/../foo", "foo");
    TEST_PATH_CANONICALIZE(17, "foo/bar/../blah", "foo/blah");
    TEST_PATH_CANONICALIZE(18, "foo/bar/.././blah", "foo/blah");
    TEST_PATH_CANONICALIZE(19, "/path/to/foo/bar/../../../../../../../../baz", "/baz");
    TEST_PATH_CANONICALIZE(20, "path/to/foo/bar/../../../../../../../../baz", "../../../../baz");
    TEST_PATH_CANONICALIZE(21, "path/to/foo/bar", "path/to/foo/bar");
    TEST_PATH_CANONICALIZE(22, "//foo//bar", "//foo/bar");
    TEST_PATH_CANONICALIZE(23, "/bar//foo", "/bar/foo");
    TEST_PATH_CANONICALIZE(24, "//../blah", "//blah");

    /* test paths with symlinks */
    TEST_PATH_CANONICALIZE(25, "/path/blah", "/other/path/huzah");
    TEST_PATH_CANONICALIZE(26, "/path/to/relative/symlink", "/path/actual/file");
    TEST_PATH_CANONICALIZE(27, "/path/to/relative/symlink/blah", "/path/actual/file/blah");
    TEST_PATH_CANONICALIZE(28, "/path/blah/yippee", "/other/path/huzah/yippee");
    TEST_PATH_CANONICALIZE(29, "/cycle", NULL);
    TEST_PATH_CANONICALIZE(30, "/cycle2/link", NULL);
    TEST_PATH_CANONICALIZE(31, "///", "/");

#define TEST_RELATIVE_BACKING(id, TOP, BASE, EXPECT)                        \
    do {                                                                    \
        data4.top = &TOP;                                                   \
        data4.base = &BASE;                                                 \
        data4.expect = EXPECT;                                              \
        if (virTestRun("Path relative resolve " #id,                        \
                       testPathRelative, &data4) < 0)                       \
            ret = -1;                                                       \
    } while (0)

    testPathRelativePrepare();

    /* few negative tests first */

    /* a non-relative image is in the backing chain span */
    TEST_RELATIVE_BACKING(1, backingchain[0], backingchain[1], NULL);
    TEST_RELATIVE_BACKING(2, backingchain[0], backingchain[2], NULL);
    TEST_RELATIVE_BACKING(3, backingchain[0], backingchain[3], NULL);
    TEST_RELATIVE_BACKING(4, backingchain[1], backingchain[5], NULL);

    /* image is not in chain (specified backwards) */
    TEST_RELATIVE_BACKING(5, backingchain[2], backingchain[1], NULL);

    /* positive tests */
    TEST_RELATIVE_BACKING(6, backingchain[1], backingchain[1], "asdf");
    TEST_RELATIVE_BACKING(7, backingchain[1], backingchain[2], "test");
    TEST_RELATIVE_BACKING(8, backingchain[1], backingchain[3], "blah");
    TEST_RELATIVE_BACKING(9, backingchain[2], backingchain[2], "test");
    TEST_RELATIVE_BACKING(10, backingchain[2], backingchain[3], "blah");
    TEST_RELATIVE_BACKING(11, backingchain[3], backingchain[3], "blah");

    /* oVirt spelling */
    TEST_RELATIVE_BACKING(12, backingchain[5], backingchain[5], "../volume/image2");
    TEST_RELATIVE_BACKING(13, backingchain[5], backingchain[6], "../volume/../volume/image3");
    TEST_RELATIVE_BACKING(14, backingchain[5], backingchain[7], "../volume/../volume/../volume/image4");
    TEST_RELATIVE_BACKING(15, backingchain[6], backingchain[6], "../volume/image3");
    TEST_RELATIVE_BACKING(16, backingchain[6], backingchain[7], "../volume/../volume/image4");
    TEST_RELATIVE_BACKING(17, backingchain[7], backingchain[7], "../volume/image4");

    /* crazy spellings */
    TEST_RELATIVE_BACKING(17, backingchain[9], backingchain[9], "directory/stuff/volumes/garbage/image2");
    TEST_RELATIVE_BACKING(18, backingchain[9], backingchain[10], "directory/stuff/volumes/garbage/../../../image3");
    TEST_RELATIVE_BACKING(19, backingchain[9], backingchain[11], "directory/stuff/volumes/garbage/../../../../blah/image4");
    TEST_RELATIVE_BACKING(20, backingchain[10], backingchain[10], "../../../image3");
    TEST_RELATIVE_BACKING(21, backingchain[10], backingchain[11], "../../../../blah/image4");
    TEST_RELATIVE_BACKING(22, backingchain[11], backingchain[11], "../blah/image4");


    virTestCounterReset("Backing store parse ");

#define TEST_BACKING_PARSE(bck, xml)                                           \
    do {                                                                       \
        data5.backing = bck;                                                   \
        data5.expect = xml;                                                    \
        if (virTestRun(virTestCounterNext(),                                   \
                       testBackingParse, &data5) < 0)                          \
            ret = -1;                                                          \
    } while (0)

    TEST_BACKING_PARSE("path", "<source file='path'/>\n");
    TEST_BACKING_PARSE("://", NULL);
    TEST_BACKING_PARSE("http://example.com/file",
                       "<source protocol='http' name='file'>\n"
                       "  <host name='example.com'/>\n"
                       "</source>\n");
    TEST_BACKING_PARSE("rbd:testshare:id=asdf:mon_host=example.com",
                       "<source protocol='rbd' name='testshare'>\n"
                       "  <host name='example.com'/>\n"
                       "</source>\n");
    TEST_BACKING_PARSE("nbd:example.org:6000:exportname=blah",
                       "<source protocol='nbd' name='blah'>\n"
                       "  <host name='example.org' port='6000'/>\n"
                       "</source>\n");
    TEST_BACKING_PARSE("json:", NULL);
    TEST_BACKING_PARSE("json:asdgsdfg", NULL);
    TEST_BACKING_PARSE("json:{}", NULL);
    TEST_BACKING_PARSE("json: { \"file.driver\":\"blah\"}", NULL);
    TEST_BACKING_PARSE("json:{\"file.driver\":\"file\"}", NULL);
    TEST_BACKING_PARSE("json:{\"file.driver\":\"file\", "
                             "\"file.filename\":\"/path/to/file\"}",
                       "<source file='/path/to/file'/>\n");
    TEST_BACKING_PARSE("json:{\"file.driver\":\"file\", "
                             "\"filename\":\"/path/to/file\"}", NULL);
    TEST_BACKING_PARSE("json:{\"file\" : { \"driver\":\"file\","
                                          "\"filename\":\"/path/to/file\""
                                        "}"
                            "}",
                       "<source file='/path/to/file'/>\n");
    TEST_BACKING_PARSE("json:{\"file.driver\":\"host_device\", "
                             "\"file.filename\":\"/path/to/dev\"}",
                       "<source dev='/path/to/dev'/>\n");
    TEST_BACKING_PARSE("json:{\"file.driver\":\"host_cdrom\", "
                             "\"file.filename\":\"/path/to/cdrom\"}",
                       "<source dev='/path/to/cdrom'/>\n");
    TEST_BACKING_PARSE("json:{\"file.driver\":\"http\", "
                             "\"file.url\":\"http://example.com/file\"}",
                       "<source protocol='http' name='file'>\n"
                       "  <host name='example.com'/>\n"
                       "</source>\n");
    TEST_BACKING_PARSE("json:{\"file\":{ \"driver\":\"http\","
                                        "\"url\":\"http://example.com/file\""
                                      "}"
                            "}",
                       "<source protocol='http' name='file'>\n"
                       "  <host name='example.com'/>\n"
                       "</source>\n");
    TEST_BACKING_PARSE("json:{\"file.driver\":\"ftp\", "
                             "\"file.url\":\"http://example.com/file\"}",
                       NULL);
    TEST_BACKING_PARSE("json:{\"file.driver\":\"gluster\", "
                             "\"file.filename\":\"gluster://example.com/vol/file\"}",
                       "<source protocol='gluster' name='vol/file'>\n"
                       "  <host name='example.com'/>\n"
                       "</source>\n");
    TEST_BACKING_PARSE("json:{\"file\":{\"driver\":\"gluster\","
                                       "\"volume\":\"testvol\","
                                       "\"path\":\"img.qcow2\","
                                       "\"server\":[ { \"type\":\"tcp\","
                                                      "\"host\":\"example.com\","
                                                      "\"port\":\"1234\""
                                                    "},"
                                                    "{ \"type\":\"unix\","
                                                      "\"socket\":\"/path/socket\""
                                                    "},"
                                                    "{ \"type\":\"tcp\","
                                                      "\"host\":\"example.com\""
                                                    "}"
                                                  "]"
                                      "}"
                             "}",
                        "<source protocol='gluster' name='testvol/img.qcow2'>\n"
                        "  <host name='example.com' port='1234'/>\n"
                        "  <host transport='unix' socket='/path/socket'/>\n"
                        "  <host name='example.com'/>\n"
                        "</source>\n");
    TEST_BACKING_PARSE("json:{\"file.driver\":\"gluster\","
                             "\"file.volume\":\"testvol\","
                             "\"file.path\":\"img.qcow2\","
                             "\"file.server\":[ { \"type\":\"tcp\","
                                                 "\"host\":\"example.com\","
                                                 "\"port\":\"1234\""
                                               "},"
                                               "{ \"type\":\"unix\","
                                                 "\"socket\":\"/path/socket\""
                                               "},"
                                               "{ \"type\":\"tcp\","
                                                 "\"host\":\"example.com\""
                                               "}"
                                             "]"
                            "}",
                        "<source protocol='gluster' name='testvol/img.qcow2'>\n"
                        "  <host name='example.com' port='1234'/>\n"
                        "  <host transport='unix' socket='/path/socket'/>\n"
                        "  <host name='example.com'/>\n"
                        "</source>\n");
    TEST_BACKING_PARSE("json:{\"file\":{\"driver\":\"nbd\","
                                       "\"path\":\"/path/to/socket\""
                                      "}"
                            "}",
                       "<source protocol='nbd'>\n"
                       "  <host transport='unix' socket='/path/to/socket'/>\n"
                       "</source>\n");
    TEST_BACKING_PARSE("json:{\"file.driver\":\"nbd\","
                             "\"file.path\":\"/path/to/socket\""
                            "}",
                       "<source protocol='nbd'>\n"
                       "  <host transport='unix' socket='/path/to/socket'/>\n"
                       "</source>\n");
    TEST_BACKING_PARSE("json:{\"file\":{\"driver\":\"nbd\","
                                       "\"export\":\"blah\","
                                       "\"host\":\"example.org\","
                                       "\"port\":\"6000\""
                                      "}"
                            "}",
                       "<source protocol='nbd' name='blah'>\n"
                       "  <host name='example.org' port='6000'/>\n"
                       "</source>\n");
    TEST_BACKING_PARSE("json:{\"file.driver\":\"nbd\","
                             "\"file.export\":\"blah\","
                             "\"file.host\":\"example.org\","
                             "\"file.port\":\"6000\""
                            "}",
                       "<source protocol='nbd' name='blah'>\n"
                       "  <host name='example.org' port='6000'/>\n"
                       "</source>\n");
    TEST_BACKING_PARSE("json:{\"file\":{\"driver\":\"ssh\","
                                       "\"host\":\"example.org\","
                                       "\"port\":\"6000\","
                                       "\"path\":\"blah\","
                                       "\"user\":\"user\""
                                      "}"
                            "}",
                       "<source protocol='ssh' name='blah'>\n"
                       "  <host name='example.org' port='6000'/>\n"
                       "</source>\n");
    TEST_BACKING_PARSE("json:{\"file.driver\":\"ssh\","
                             "\"file.host\":\"example.org\","
                             "\"file.port\":\"6000\","
                             "\"file.path\":\"blah\","
                             "\"file.user\":\"user\""
                            "}",
                       "<source protocol='ssh' name='blah'>\n"
                       "  <host name='example.org' port='6000'/>\n"
                       "</source>\n");
    TEST_BACKING_PARSE("json:{\"file.driver\":\"rbd\","
                             "\"file.filename\":\"rbd:testshare:id=asdf:mon_host=example.com\""
                            "}",
                       "<source protocol='rbd' name='testshare'>\n"
                       "  <host name='example.com'/>\n"
                       "</source>\n");
    TEST_BACKING_PARSE("json:{ \"file\": { "
                                "\"driver\": \"raw\","
                                "\"file\": {"
                                    "\"driver\": \"file\","
                                    "\"filename\": \"/path/to/file\" } } }",
                       "<source file='/path/to/file'/>\n");

 cleanup:
    /* Final cleanup */
    virStorageSourceFree(chain);
    testCleanupImages();
    virCommandFree(cmd);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
