#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "hash.h"
#include "hashdata.h"
#include "testutils.h"


#define testError(...)                                          \
    do {                                                        \
        fprintf(stderr, __VA_ARGS__);                           \
        /* Pad to line up with test name ... in virTestRun */   \
        fprintf(stderr, "%74s", "... ");                        \
    } while (0)


static virHashTablePtr
testHashInit(int size)
{
    virHashTablePtr hash;
    int i;

    if (!(hash = virHashCreate(size, NULL)))
        return NULL;

    /* entires are added in reverse order so that they will be linked in
     * collision list in the same order as in the uuids array
     */
    for (i = ARRAY_CARDINALITY(uuids) - 1; i >= 0; i--) {
        if (virHashAddEntry(hash, uuids[i], (void *) uuids[i]) < 0) {
            virHashFree(hash);
            return NULL;
        }
    }

    return hash;
}


static int
testHashCheckCount(virHashTablePtr hash, int count)
{
    if (virHashSize(hash) != count) {
        testError("\nhash contains %d instead of %d elements\n",
                  virHashSize(hash), count);
        return -1;
    }

    return 0;
}


struct testInfo {
    void *data;
    int count;
};


const int testHashCountRemoveForEachSome =
    ARRAY_CARDINALITY(uuids) - ARRAY_CARDINALITY(uuids_subset);

static void
testHashRemoveForEachSome(void *payload ATTRIBUTE_UNUSED,
                          const void *name,
                          void *data)
{
    virHashTablePtr hash = data;
    int i;

    for (i = 0; i < ARRAY_CARDINALITY(uuids_subset); i++) {
        if (STREQ(uuids_subset[i], name)) {
            if (virHashRemoveEntry(hash, name) < 0 && virTestGetVerbose()) {
                fprintf(stderr, "\nentry \"%s\" could not be removed",
                        uuids_subset[i]);
            }
            break;
        }
    }
}


const int testHashCountRemoveForEachAll = 0;

static void
testHashRemoveForEachAll(void *payload ATTRIBUTE_UNUSED,
                         const void *name,
                         void *data)
{
    virHashTablePtr hash = data;

    virHashRemoveEntry(hash, name);
}


static int
testHashRemoveForEach(const void *data)
{
    const struct testInfo *info = data;
    virHashTablePtr hash;
    int count;
    int ret = -1;

    if (!(hash = testHashInit(0)))
        return -1;

    count = virHashForEach(hash, (virHashIterator) info->data, hash);

    if (count != ARRAY_CARDINALITY(uuids)) {
        if (virTestGetVerbose()) {
            testError("\nvirHashForEach didn't go through all entries,"
                      " %d != %lu\n",
                      count, ARRAY_CARDINALITY(uuids));
        }
        goto cleanup;
    }

    if (testHashCheckCount(hash, info->count) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    virHashFree(hash);
    return ret;
}


static int
mymain(int argc ATTRIBUTE_UNUSED,
       char **argv ATTRIBUTE_UNUSED)
{
    int ret = 0;

#define DO_TEST_FULL(name, cmd, data, count)                        \
    do {                                                            \
        struct testInfo info = { data, count };                     \
        if (virtTestRun(name, 1, testHash ## cmd, &info) < 0)       \
            ret = -1;                                               \
    } while (0)

#define DO_TEST_DATA(name, cmd, data)                               \
    DO_TEST_FULL(name "(" #data ")",                                \
                 cmd,                                               \
                 testHash ## cmd ## data,                           \
                 testHashCount ## cmd ## data)

    DO_TEST_DATA("Remove in ForEach", RemoveForEach, Some);
    DO_TEST_DATA("Remove in ForEach", RemoveForEach, All);

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
