#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "internal.h"
#include "virhash.h"
#include "virhashdata.h"
#include "testutils.h"
#include "viralloc.h"
#include "virlog.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.hashtest");

static virHashTablePtr
testHashInit(int size)
{
    virHashTablePtr hash;
    ssize_t i;

    if (!(hash = virHashCreate(size, NULL)))
        return NULL;

    /* entires are added in reverse order so that they will be linked in
     * collision list in the same order as in the uuids array
     */
    for (i = ARRAY_CARDINALITY(uuids) - 1; i >= 0; i--) {
        ssize_t oldsize = virHashTableSize(hash);
        if (virHashAddEntry(hash, uuids[i], (void *) uuids[i]) < 0) {
            virHashFree(hash);
            return NULL;
        }

        if (virHashTableSize(hash) != oldsize) {
            VIR_TEST_DEBUG("hash grown from %zd to %zd",
                     (size_t)oldsize, (size_t)virHashTableSize(hash));
        }
    }

    for (i = 0; i < ARRAY_CARDINALITY(uuids); i++) {
        if (!virHashLookup(hash, uuids[i])) {
            VIR_TEST_VERBOSE("\nentry \"%s\" could not be found\n", uuids[i]);
            virHashFree(hash);
            return NULL;
        }
    }

    if (size && size != virHashTableSize(hash))
        VIR_TEST_DEBUG("\n");

    return hash;
}

static int
testHashCheckForEachCount(void *payload ATTRIBUTE_UNUSED,
                          const void *name ATTRIBUTE_UNUSED,
                          void *data ATTRIBUTE_UNUSED)
{
    size_t *count = data;
    *count += 1;
    return 0;
}

static int
testHashCheckCount(virHashTablePtr hash, size_t count)
{
    size_t iter_count = 0;

    if (virHashSize(hash) != count) {
        VIR_TEST_VERBOSE("\nhash contains %zd instead of %zu elements\n",
                         virHashSize(hash), count);
        return -1;
    }

    virHashForEach(hash, testHashCheckForEachCount, &iter_count);
    if (count != iter_count) {
        VIR_TEST_VERBOSE("\nhash claims to have %zu elements but iteration"
                         "finds %zu\n", count, iter_count);
        return -1;
    }

    return 0;
}


struct testInfo {
    void *data;
    size_t count;
};


static int
testHashGrow(const void *data)
{
    const struct testInfo *info = data;
    virHashTablePtr hash;
    int ret = -1;

    if (!(hash = testHashInit(info->count)))
        return -1;

    if (testHashCheckCount(hash, ARRAY_CARDINALITY(uuids)) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virHashFree(hash);
    return ret;
}


static int
testHashUpdate(const void *data ATTRIBUTE_UNUSED)
{
    int count = ARRAY_CARDINALITY(uuids) + ARRAY_CARDINALITY(uuids_new);
    virHashTablePtr hash;
    size_t i;
    int ret = -1;

    if (!(hash = testHashInit(0)))
        return -1;

    for (i = 0; i < ARRAY_CARDINALITY(uuids_subset); i++) {
        if (virHashUpdateEntry(hash, uuids_subset[i], (void *) 1) < 0) {
            VIR_TEST_VERBOSE("\nentry \"%s\" could not be updated\n",
                    uuids_subset[i]);
            goto cleanup;
        }
    }

    for (i = 0; i < ARRAY_CARDINALITY(uuids_new); i++) {
        if (virHashUpdateEntry(hash, uuids_new[i], (void *) 1) < 0) {
            VIR_TEST_VERBOSE("\nnew entry \"%s\" could not be updated\n",
                    uuids_new[i]);
            goto cleanup;
        }
    }

    if (testHashCheckCount(hash, count) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virHashFree(hash);
    return ret;
}


static int
testHashRemove(const void *data ATTRIBUTE_UNUSED)
{
    int count = ARRAY_CARDINALITY(uuids) - ARRAY_CARDINALITY(uuids_subset);
    virHashTablePtr hash;
    size_t i;
    int ret = -1;

    if (!(hash = testHashInit(0)))
        return -1;

    for (i = 0; i < ARRAY_CARDINALITY(uuids_subset); i++) {
        if (virHashRemoveEntry(hash, uuids_subset[i]) < 0) {
            VIR_TEST_VERBOSE("\nentry \"%s\" could not be removed\n",
                    uuids_subset[i]);
            goto cleanup;
        }
    }

    if (testHashCheckCount(hash, count) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virHashFree(hash);
    return ret;
}


const int testHashCountRemoveForEachSome =
    ARRAY_CARDINALITY(uuids) - ARRAY_CARDINALITY(uuids_subset);

static int
testHashRemoveForEachSome(void *payload ATTRIBUTE_UNUSED,
                          const void *name,
                          void *data)
{
    virHashTablePtr hash = data;
    size_t i;

    for (i = 0; i < ARRAY_CARDINALITY(uuids_subset); i++) {
        if (STREQ(uuids_subset[i], name)) {
            if (virHashRemoveEntry(hash, name) < 0) {
                VIR_TEST_VERBOSE("\nentry \"%s\" could not be removed",
                        uuids_subset[i]);
            }
            break;
        }
    }
    return 0;
}


const int testHashCountRemoveForEachAll = 0;

static int
testHashRemoveForEachAll(void *payload ATTRIBUTE_UNUSED,
                         const void *name,
                         void *data)
{
    virHashTablePtr hash = data;

    virHashRemoveEntry(hash, name);
    return 0;
}


const int testHashCountRemoveForEachForbidden = ARRAY_CARDINALITY(uuids);

static int
testHashRemoveForEachForbidden(void *payload ATTRIBUTE_UNUSED,
                               const void *name,
                               void *data)
{
    virHashTablePtr hash = data;
    size_t i;

    for (i = 0; i < ARRAY_CARDINALITY(uuids_subset); i++) {
        if (STREQ(uuids_subset[i], name)) {
            int next = (i + 1) % ARRAY_CARDINALITY(uuids_subset);

            if (virHashRemoveEntry(hash, uuids_subset[next]) == 0) {
                VIR_TEST_VERBOSE(
                        "\nentry \"%s\" should not be allowed to be removed",
                        uuids_subset[next]);
            }
            break;
        }
    }
    return 0;
}


static int
testHashRemoveForEach(const void *data)
{
    const struct testInfo *info = data;
    virHashTablePtr hash;
    int ret = -1;

    if (!(hash = testHashInit(0)))
        return -1;

    if (virHashForEach(hash, (virHashIterator) info->data, hash)) {
        VIR_TEST_VERBOSE("\nvirHashForEach didn't go through all entries");
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
testHashSteal(const void *data ATTRIBUTE_UNUSED)
{
    int count = ARRAY_CARDINALITY(uuids) - ARRAY_CARDINALITY(uuids_subset);
    virHashTablePtr hash;
    size_t i;
    int ret = -1;

    if (!(hash = testHashInit(0)))
        return -1;

    for (i = 0; i < ARRAY_CARDINALITY(uuids_subset); i++) {
        if (!virHashSteal(hash, uuids_subset[i])) {
            VIR_TEST_VERBOSE("\nentry \"%s\" could not be stolen\n",
                    uuids_subset[i]);
            goto cleanup;
        }
    }

    if (testHashCheckCount(hash, count) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virHashFree(hash);
    return ret;
}


static int
testHashIter(void *payload ATTRIBUTE_UNUSED,
             const void *name ATTRIBUTE_UNUSED,
             void *data ATTRIBUTE_UNUSED)
{
    return 0;
}

static int
testHashForEachIter(void *payload ATTRIBUTE_UNUSED,
                    const void *name ATTRIBUTE_UNUSED,
                    void *data)
{
    virHashTablePtr hash = data;

    if (virHashAddEntry(hash, uuids_new[0], NULL) == 0)
        VIR_TEST_VERBOSE("\nadding entries in ForEach should be forbidden");

    if (virHashUpdateEntry(hash, uuids_new[0], NULL) == 0)
        VIR_TEST_VERBOSE("\nupdating entries in ForEach should be forbidden");

    if (virHashSteal(hash, uuids_new[0]) != NULL)
        VIR_TEST_VERBOSE("\nstealing entries in ForEach should be forbidden");

    if (virHashSteal(hash, uuids_new[0]) != NULL)
        VIR_TEST_VERBOSE("\nstealing entries in ForEach should be forbidden");

    if (virHashForEach(hash, testHashIter, NULL) >= 0)
        VIR_TEST_VERBOSE("\niterating through hash in ForEach"
                " should be forbidden");
    return 0;
}

static int
testHashForEach(const void *data ATTRIBUTE_UNUSED)
{
    virHashTablePtr hash;
    int ret = -1;

    if (!(hash = testHashInit(0)))
        return -1;

    if (virHashForEach(hash, testHashForEachIter, hash)) {
        VIR_TEST_VERBOSE("\nvirHashForEach didn't go through all entries");
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virHashFree(hash);
    return ret;
}


static int
testHashRemoveSetIter(const void *payload ATTRIBUTE_UNUSED,
                      const void *name,
                      const void *data)
{
    int *count = (int *) data;
    bool rem = false;
    size_t i;

    for (i = 0; i < ARRAY_CARDINALITY(uuids_subset); i++) {
        if (STREQ(uuids_subset[i], name)) {
            rem = true;
            break;
        }
    }

    if (rem || rand() % 2) {
        (*count)++;
        return 1;
    } else {
        return 0;
    }
}

static int
testHashRemoveSet(const void *data ATTRIBUTE_UNUSED)
{
    virHashTablePtr hash;
    int count = 0;
    int rcount;
    int ret = -1;

    if (!(hash = testHashInit(0)))
        return -1;

    /* seed the generator so that rand() provides reproducible sequence */
    srand(9000);

    rcount = virHashRemoveSet(hash, testHashRemoveSetIter, &count);

    if (count != rcount) {
        VIR_TEST_VERBOSE("\nvirHashRemoveSet didn't remove expected number of"
                  " entries, %d != %u\n",
                  rcount, count);
        goto cleanup;
    }

    if (testHashCheckCount(hash, ARRAY_CARDINALITY(uuids) - count) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virHashFree(hash);
    return ret;
}


const int testSearchIndex = ARRAY_CARDINALITY(uuids_subset) / 2;

static int
testHashSearchIter(const void *payload ATTRIBUTE_UNUSED,
                   const void *name,
                   const void *data ATTRIBUTE_UNUSED)
{
    return STREQ(uuids_subset[testSearchIndex], name);
}

static int
testHashSearch(const void *data ATTRIBUTE_UNUSED)
{
    virHashTablePtr hash;
    void *entry;
    int ret = -1;

    if (!(hash = testHashInit(0)))
        return -1;

    entry = virHashSearch(hash, testHashSearchIter, NULL);

    if (!entry || STRNEQ(uuids_subset[testSearchIndex], entry)) {
        VIR_TEST_VERBOSE("\nvirHashSearch didn't find entry '%s'\n",
                  uuids_subset[testSearchIndex]);
        goto cleanup;
    }

    if (testHashCheckCount(hash, ARRAY_CARDINALITY(uuids)) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virHashFree(hash);
    return ret;
}


static int
testHashGetItemsCompKey(const virHashKeyValuePair *a,
                        const virHashKeyValuePair *b)
{
    return strcmp(a->key, b->key);
}

static int
testHashGetItemsCompValue(const virHashKeyValuePair *a,
                          const virHashKeyValuePair *b)
{
    return strcmp(a->value, b->value);
}

static int
testHashGetItems(const void *data ATTRIBUTE_UNUSED)
{
    virHashTablePtr hash;
    virHashKeyValuePairPtr array = NULL;
    int ret = -1;
    char keya[] = "a";
    char keyb[] = "b";
    char keyc[] = "c";
    char value1[] = "1";
    char value2[] = "2";
    char value3[] = "3";

    if (!(hash = virHashCreate(0, NULL)) ||
        virHashAddEntry(hash, keya, value3) < 0 ||
        virHashAddEntry(hash, keyc, value1) < 0 ||
        virHashAddEntry(hash, keyb, value2) < 0) {
        VIR_TEST_VERBOSE("\nfailed to create hash");
        goto cleanup;
    }

    if (!(array = virHashGetItems(hash, NULL)) ||
        array[3].key || array[3].value) {
        VIR_TEST_VERBOSE("\nfailed to get items with NULL sort");
        goto cleanup;
    }
    VIR_FREE(array);

    if (!(array = virHashGetItems(hash, testHashGetItemsCompKey)) ||
        STRNEQ(array[0].key, "a") ||
        STRNEQ(array[0].value, "3") ||
        STRNEQ(array[1].key, "b") ||
        STRNEQ(array[1].value, "2") ||
        STRNEQ(array[2].key, "c") ||
        STRNEQ(array[2].value, "1") ||
        array[3].key || array[3].value) {
        VIR_TEST_VERBOSE("\nfailed to get items with key sort");
        goto cleanup;
    }
    VIR_FREE(array);

    if (!(array = virHashGetItems(hash, testHashGetItemsCompValue)) ||
        STRNEQ(array[0].key, "c") ||
        STRNEQ(array[0].value, "1") ||
        STRNEQ(array[1].key, "b") ||
        STRNEQ(array[1].value, "2") ||
        STRNEQ(array[2].key, "a") ||
        STRNEQ(array[2].value, "3") ||
        array[3].key || array[3].value) {
        VIR_TEST_VERBOSE("\nfailed to get items with value sort");
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(array);
    virHashFree(hash);
    return ret;
}

static int
testHashEqualCompValue(const void *value1, const void *value2)
{
    return c_strcasecmp(value1, value2);
}

static int
testHashEqual(const void *data ATTRIBUTE_UNUSED)
{
    virHashTablePtr hash1, hash2 = NULL;
    int ret = -1;
    char keya[] = "a";
    char keyb[] = "b";
    char keyc[] = "c";
    char value1_l[] = "m";
    char value2_l[] = "n";
    char value3_l[] = "o";
    char value1_u[] = "M";
    char value2_u[] = "N";
    char value3_u[] = "O";
    char value4_u[] = "P";

    if (!(hash1 = virHashCreate(0, NULL)) ||
        !(hash2 = virHashCreate(0, NULL)) ||
        virHashAddEntry(hash1, keya, value1_l) < 0 ||
        virHashAddEntry(hash1, keyb, value2_l) < 0 ||
        virHashAddEntry(hash1, keyc, value3_l) < 0 ||
        virHashAddEntry(hash2, keya, value1_u) < 0 ||
        virHashAddEntry(hash2, keyb, value2_u) < 0) {
        VIR_TEST_VERBOSE("\nfailed to create hashes");
        goto cleanup;
    }

    if (virHashEqual(hash1, hash2, testHashEqualCompValue)) {
        VIR_TEST_VERBOSE("\nfailed equal test for different number of elements");
        goto cleanup;
    }

    if (virHashAddEntry(hash2, keyc, value4_u) < 0) {
        VIR_TEST_VERBOSE("\nfailed to add element to hash2");
        goto cleanup;
    }

    if (virHashEqual(hash1, hash2, testHashEqualCompValue)) {
        VIR_TEST_VERBOSE("\nfailed equal test for same number of elements");
        goto cleanup;
    }

    if (virHashUpdateEntry(hash2, keyc, value3_u) < 0) {
        VIR_TEST_VERBOSE("\nfailed to update element in hash2");
        goto cleanup;
    }

    if (!virHashEqual(hash1, hash2, testHashEqualCompValue)) {
        VIR_TEST_VERBOSE("\nfailed equal test for equal hash tables");
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virHashFree(hash1);
    virHashFree(hash2);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;

#define DO_TEST_FULL(name, cmd, data, count)                        \
    do {                                                            \
        struct testInfo info = { data, count };                     \
        if (virTestRun(name, testHash ## cmd, &info) < 0)           \
            ret = -1;                                               \
    } while (0)

#define DO_TEST_DATA(name, cmd, data)                               \
    DO_TEST_FULL(name "(" #data ")",                                \
                 cmd,                                               \
                 testHash ## cmd ## data,                           \
                 testHashCount ## cmd ## data)

#define DO_TEST_COUNT(name, cmd, count)                             \
    DO_TEST_FULL(name "(" #count ")", cmd, NULL, count)

#define DO_TEST(name, cmd)                                          \
    DO_TEST_FULL(name, cmd, NULL, -1)

    DO_TEST_COUNT("Grow", Grow, 1);
    DO_TEST_COUNT("Grow", Grow, 10);
    DO_TEST_COUNT("Grow", Grow, 42);
    DO_TEST("Update", Update);
    DO_TEST("Remove", Remove);
    DO_TEST_DATA("Remove in ForEach", RemoveForEach, Some);
    DO_TEST_DATA("Remove in ForEach", RemoveForEach, All);
    DO_TEST_DATA("Remove in ForEach", RemoveForEach, Forbidden);
    DO_TEST("Steal", Steal);
    DO_TEST("Forbidden ops in ForEach", ForEach);
    DO_TEST("RemoveSet", RemoveSet);
    DO_TEST("Search", Search);
    DO_TEST("GetItems", GetItems);
    DO_TEST("Equal", Equal);

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
