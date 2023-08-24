#include <config.h>

#include <time.h>

#include "internal.h"
#include "virjson.h"
#include "testutils.h"

#define VIR_FROM_THIS VIR_FROM_NONE

struct testInfo {
    const char *name;
    const char *doc;
    const char *expect;
    bool pass;
};


static int
testJSONFromFile(const void *data)
{
    const struct testInfo *info = data;
    g_autoptr(virJSONValue) injson = NULL;
    g_autofree char *infile = NULL;
    g_autofree char *indata = NULL;
    g_autofree char *outfile = NULL;
    g_autofree char *actual = NULL;

    infile = g_strdup_printf("%s/virjsondata/parse-%s-in.json",
                             abs_srcdir, info->name);
    outfile = g_strdup_printf("%s/virjsondata/parse-%s-out.json",
                              abs_srcdir, info->name);

    if (virTestLoadFile(infile, &indata) < 0)
        return -1;

    injson = virJSONValueFromString(indata);

    if (!injson) {
        if (info->pass) {
            VIR_TEST_VERBOSE("Failed to parse %s", info->doc);
            return -1;
        } else {
            VIR_TEST_DEBUG("As expected, failed to parse %s", info->doc);
            return 0;
        }
    } else {
        if (!info->pass) {
            VIR_TEST_VERBOSE("Unexpected success while parsing %s", info->doc);
            return -1;
        }
    }

    if (!(actual = virJSONValueToString(injson, false)))
        return -1;

    if (virTestCompareToFile(actual, outfile) < 0)
        return -1;

    return 0;
}


static int
testJSONFromString(const void *data)
{
    const struct testInfo *info = data;
    g_autoptr(virJSONValue) json = NULL;
    const char *expectstr = info->expect ? info->expect : info->doc;
    g_autofree char *formatted = NULL;

    json = virJSONValueFromString(info->doc);

    if (!json) {
        if (info->pass) {
            VIR_TEST_VERBOSE("Failed to parse %s", info->doc);
            return -1;
        } else {
            VIR_TEST_DEBUG("As expected, failed to parse %s", info->doc);
            return 0;
        }
    } else {
        if (!info->pass) {
            VIR_TEST_VERBOSE("Unexpected success while parsing %s", info->doc);
            return -1;
        }
    }

    VIR_TEST_DEBUG("Parsed %s", info->doc);

    if (!(formatted = virJSONValueToString(json, false))) {
        VIR_TEST_VERBOSE("Failed to format json data");
        return -1;
    }

    if (virTestCompareToString(expectstr, formatted) < 0) {
        return -1;
    }

    return 0;
}


static int
testJSONAddRemove(const void *data)
{
    const struct testInfo *info = data;
    g_autoptr(virJSONValue) json = NULL;
    g_autoptr(virJSONValue) name = NULL;
    g_autofree char *infile = NULL;
    g_autofree char *indata = NULL;
    g_autofree char *outfile = NULL;
    g_autofree char *actual = NULL;

    infile = g_strdup_printf("%s/virjsondata/add-remove-%s-in.json",
                             abs_srcdir, info->name);
    outfile = g_strdup_printf("%s/virjsondata/add-remove-%s-out.json",
                              abs_srcdir, info->name);

    if (virTestLoadFile(infile, &indata) < 0)
        return -1;

    json = virJSONValueFromString(indata);
    if (!json) {
        VIR_TEST_VERBOSE("Fail to parse %s", info->name);
        return -1;
    }

    switch (virJSONValueObjectRemoveKey(json, "name", &name)) {
    case 1:
        if (!info->pass) {
            VIR_TEST_VERBOSE("should not remove from non-object %s",
                             info->name);
            return -1;
        }
        break;
    case -1:
        if (!info->pass)
            return 0;
        else
            VIR_TEST_VERBOSE("Fail to recognize non-object %s", info->name);
        return -1;
    default:
        VIR_TEST_VERBOSE("unexpected result when removing from %s",
                         info->name);
        return -1;
    }
    if (STRNEQ_NULLABLE(virJSONValueGetString(name), "sample")) {
        VIR_TEST_VERBOSE("unexpected value after removing name: %s",
                         NULLSTR(virJSONValueGetString(name)));
        return -1;
    }
    if (virJSONValueObjectRemoveKey(json, "name", NULL)) {
        VIR_TEST_VERBOSE("%s",
                         "unexpected success when removing missing key");
        return -1;
    }
    if (virJSONValueObjectAppendString(json, "newname", "foo") < 0) {
        VIR_TEST_VERBOSE("%s", "unexpected failure adding new key");
        return -1;
    }
    if (!(actual = virJSONValueToString(json, false))) {
        VIR_TEST_VERBOSE("%s", "failed to stringize result");
        return -1;
    }

    if (virTestCompareToFile(actual, outfile) < 0)
        return -1;

    return 0;
}


static int
testJSONLookup(const void *data)
{
    const struct testInfo *info = data;
    g_autoptr(virJSONValue) json = NULL;
    virJSONValue *value = NULL;
    g_autofree char *result = NULL;
    int rc;
    int number;
    const char *str;

    json = virJSONValueFromString(info->doc);
    if (!json) {
        VIR_TEST_VERBOSE("Fail to parse %s", info->doc);
        return -1;
    }

    value = virJSONValueObjectGetObject(json, "a");
    if (value) {
        if (!info->pass) {
            VIR_TEST_VERBOSE("lookup for 'a' in '%s' should have failed",
                             info->doc);
            return -1;
        } else {
            result = virJSONValueToString(value, false);
            if (STRNEQ_NULLABLE(result, "{}")) {
                VIR_TEST_VERBOSE("lookup for 'a' in '%s' found '%s' but "
                                 "should have found '{}'",
                                 info->doc, NULLSTR(result));
                return -1;
            }
            VIR_FREE(result);
        }
    } else if (info->pass) {
        VIR_TEST_VERBOSE("lookup for 'a' in '%s' should have succeeded",
                         info->doc);
        return -1;
    }

    number = 2;
    rc = virJSONValueObjectGetNumberInt(json, "b", &number);
    if (rc == 0) {
        if (!info->pass) {
            VIR_TEST_VERBOSE("lookup for 'b' in '%s' should have failed",
                             info->doc);
            return -1;
        } else if (number != 1) {
            VIR_TEST_VERBOSE("lookup for 'b' in '%s' found %d but "
                             "should have found 1",
                             info->doc, number);
            return -1;
        }
    } else if (info->pass) {
        VIR_TEST_VERBOSE("lookup for 'b' in '%s' should have succeeded",
                         info->doc);
        return -1;
    }

    str = virJSONValueObjectGetString(json, "c");
    if (str) {
        if (!info->pass) {
            VIR_TEST_VERBOSE("lookup for 'c' in '%s' should have failed",
                             info->doc);
            return -1;
        } else if (STRNEQ(str, "str")) {
            VIR_TEST_VERBOSE("lookup for 'c' in '%s' found '%s' but "
                             "should have found 'str'", info->doc, str);
                return -1;
        }
    } else if (info->pass) {
        VIR_TEST_VERBOSE("lookup for 'c' in '%s' should have succeeded",
                         info->doc);
        return -1;
    }

    value = virJSONValueObjectGetArray(json, "d");
    if (value) {
        if (!info->pass) {
            VIR_TEST_VERBOSE("lookup for 'd' in '%s' should have failed",
                             info->doc);
            return -1;
        } else {
            result = virJSONValueToString(value, false);
            if (STRNEQ_NULLABLE(result, "[]")) {
                VIR_TEST_VERBOSE("lookup for 'd' in '%s' found '%s' but "
                                 "should have found '[]'",
                                 info->doc, NULLSTR(result));
                return -1;
            }
            VIR_FREE(result);
        }
    } else if (info->pass) {
        VIR_TEST_VERBOSE("lookup for 'd' in '%s' should have succeeded",
                         info->doc);
        return -1;
    }

    return 0;
}


static int
testJSONCopy(const void *data)
{
    const struct testInfo *info = data;
    g_autoptr(virJSONValue) json = NULL;
    g_autoptr(virJSONValue) jsonCopy = NULL;
    g_autofree char *result = NULL;
    g_autofree char *resultCopy = NULL;

    json = virJSONValueFromString(info->doc);
    if (!json) {
        VIR_TEST_VERBOSE("Failed to parse %s", info->doc);
        return -1;
    }

    jsonCopy = virJSONValueCopy(json);
    if (!jsonCopy) {
        VIR_TEST_VERBOSE("Failed to copy JSON data");
        return -1;
    }

    result = virJSONValueToString(json, false);
    if (!result) {
        VIR_TEST_VERBOSE("Failed to format original JSON data");
        return -1;
    }

    resultCopy = virJSONValueToString(json, false);
    if (!resultCopy) {
        VIR_TEST_VERBOSE("Failed to format copied JSON data");
        return -1;
    }

    if (STRNEQ(result, resultCopy)) {
        if (virTestGetVerbose())
            virTestDifference(stderr, result, resultCopy);
        return -1;
    }

    VIR_FREE(result);
    VIR_FREE(resultCopy);

    result = virJSONValueToString(json, true);
    if (!result) {
        VIR_TEST_VERBOSE("Failed to format original JSON data");
        return -1;
    }

    resultCopy = virJSONValueToString(json, true);
    if (!resultCopy) {
        VIR_TEST_VERBOSE("Failed to format copied JSON data");
        return -1;
    }

    if (STRNEQ(result, resultCopy)) {
        if (virTestGetVerbose())
            virTestDifference(stderr, result, resultCopy);
        return -1;
    }

    return 0;
}


static int
testJSONDeflatten(const void *data)
{
    const struct testInfo *info = data;
    g_autoptr(virJSONValue) injson = NULL;
    g_autoptr(virJSONValue) deflattened = NULL;
    g_autofree char *infile = NULL;
    g_autofree char *indata = NULL;
    g_autofree char *outfile = NULL;
    g_autofree char *actual = NULL;

    infile = g_strdup_printf("%s/virjsondata/deflatten-%s-in.json",
                             abs_srcdir, info->name);
    outfile = g_strdup_printf("%s/virjsondata/deflatten-%s-out.json",
                              abs_srcdir, info->name);

    if (virTestLoadFile(infile, &indata) < 0)
        return -1;

    if (!(injson = virJSONValueFromString(indata)))
        return -1;

    if ((deflattened = virJSONValueObjectDeflatten(injson))) {
        if (!info->pass) {
            VIR_TEST_VERBOSE("%s: deflattening should have failed", info->name);
            return -1;
        }
    } else {
        if (!info->pass)
            return 0;

        return -1;
    }

    if (!(actual = virJSONValueToString(deflattened, true)))
        return -1;

    if (virTestCompareToFile(actual, outfile) < 0)
        return -1;

    return 0;
}


static int
testJSONEscapeObj(const void *data G_GNUC_UNUSED)
{
    g_autoptr(virJSONValue) json = NULL;
    g_autoptr(virJSONValue) nestjson = NULL;
    g_autoptr(virJSONValue) parsejson = NULL;
    g_autofree char *neststr = NULL;
    g_autofree char *result = NULL;
    const char *parsednestedstr;

    if (virJSONValueObjectAdd(&nestjson,
                              "s:stringkey", "stringvalue",
                              "i:numberkey", 1234,
                              "b:booleankey", false, NULL) < 0) {
        VIR_TEST_VERBOSE("failed to create nested json object");
        return -1;
    }

    if (!(neststr = virJSONValueToString(nestjson, false))) {
        VIR_TEST_VERBOSE("failed to format nested json object");
        return -1;
    }

    if (virJSONValueObjectAdd(&json, "s:test", neststr, NULL) < 0) {
        VIR_TEST_VERBOSE("Failed to create json object");
        return -1;
    }

    if (!(result = virJSONValueToString(json, false))) {
        VIR_TEST_VERBOSE("Failed to format json object");
        return -1;
    }

    if (!(parsejson = virJSONValueFromString(result))) {
        VIR_TEST_VERBOSE("Failed to parse JSON with nested JSON in string");
        return -1;
    }

    if (!(parsednestedstr = virJSONValueObjectGetString(parsejson, "test"))) {
        VIR_TEST_VERBOSE("Failed to retrieve string containing nested json");
        return -1;
    }

    if (virTestCompareToString(neststr, parsednestedstr) < 0) {
        return -1;
    }

    return 0;
}


static int
testJSONObjectFormatSteal(const void *opaque G_GNUC_UNUSED)
{
    g_autoptr(virJSONValue) a1 = NULL;
    g_autoptr(virJSONValue) a2 = NULL;
    g_autoptr(virJSONValue) t1 = NULL;
    g_autoptr(virJSONValue) t2 = NULL;

    if (!(a1 = virJSONValueNewString(g_strdup("test"))) ||
        !(a2 = virJSONValueNewString(g_strdup("test")))) {
        VIR_TEST_VERBOSE("Failed to create json object");
    }

    if (virJSONValueObjectAdd(&t1, "a:t", &a1, "s:f", NULL, NULL) != -1) {
        VIR_TEST_VERBOSE("virJSONValueObjectAdd(t1) should have failed");
        return -1;
    }

    if (a1) {
        VIR_TEST_VERBOSE("appended object a1 was not consumed");
        return -1;
    }

    if (virJSONValueObjectAdd(&t2, "s:f", NULL, "a:t", &a1, NULL) != -1) {
        VIR_TEST_VERBOSE("virJSONValueObjectAdd(t2) should have failed");
        return -1;
    }

    if (!a2) {
        VIR_TEST_VERBOSE("appended object a2 was consumed");
        return -1;
    }

    return 0;
}


static int
mymain(void)
{
    int ret = 0;

#define DO_TEST_FULL(name, cmd, doc, expect, pass) \
    do { \
        struct testInfo info = { name, doc, expect, pass }; \
        if (virTestRun(name, testJSON ## cmd, &info) < 0) \
            ret = -1; \
    } while (0)

/**
 * DO_TEST_PARSE:
 * @name: test name
 * @doc: source JSON string
 * @expect: expected output JSON formatted from parsed @doc
 *
 * Parses @doc and formats it back. If @expect is NULL the result has to be
 * identical to @doc.
 */
#define DO_TEST_PARSE(name, doc, expect) \
    DO_TEST_FULL(name, FromString, doc, expect, true)

#define DO_TEST_PARSE_FAIL(name, doc) \
    DO_TEST_FULL(name, FromString, doc, NULL, false)

#define DO_TEST_PARSE_FILE(name) \
    DO_TEST_FULL(name, FromFile, NULL, NULL, true)


    DO_TEST_PARSE_FILE("Simple");
    DO_TEST_PARSE_FILE("NotSoSimple");
    DO_TEST_PARSE_FILE("Harder");
    DO_TEST_PARSE_FILE("VeryHard");

    DO_TEST_FULL("success", AddRemove, NULL, NULL, true);
    DO_TEST_FULL("failure", AddRemove, NULL, NULL, false);

    DO_TEST_FULL("copy and free", Copy,
                 "{\"return\": [{\"name\": \"quit\"}, {\"name\": \"eject\"},"
                 "{\"name\": \"change\"}, {\"name\": \"screendump\"},"
                 "{\"name\": \"stop\"}, {\"name\": \"cont\"}, {\"name\": "
                 "\"system_reset\"}, {\"name\": \"system_powerdown\"}, "
                 "{\"name\": \"device_add\"}, {\"name\": \"device_del\"}, "
                 "{\"name\": \"cpu\"}, {\"name\": \"memsave\"}, {\"name\": "
                 "\"pmemsave\"}, {\"name\": \"migrate\"}, {\"name\": "
                 "\"migrate_cancel\"}, {\"name\": \"migrate_set_speed\"},"
                 "{\"name\": \"client_migrate_info\"}, {\"name\": "
                 "\"migrate_set_downtime\"}, {\"name\": \"netdev_add\"}, "
                 "{\"name\": \"netdev_del\"}, {\"name\": \"block_resize\"},"
                 "{\"name\": \"balloon\"}, {\"name\": \"set_link\"}, {\"name\":"
                 "\"getfd\"}, {\"name\": \"closefd\"}, {\"name\": \"block_passwd\"},"
                 "{\"name\": \"set_password\"}, {\"name\": \"expire_password\"},"
                 "{\"name\": \"qmp_capabilities\"}, {\"name\": "
                 "\"human-monitor-command\"}, {\"name\": \"query-version\"},"
                 "{\"name\": \"query-commands\"}, {\"name\": \"query-chardev\"},"
                 "{\"name\": \"query-block\"}, {\"name\": \"query-blockstats\"}, "
                 "{\"name\": \"query-cpus\"}, {\"name\": \"query-pci\"}, {\"name\":"
                 "\"query-kvm\"}, {\"name\": \"query-status\"}, {\"name\": "
                 "\"query-mice\"}, {\"name\": \"query-vnc\"}, {\"name\": "
                 "\"query-spice\"}, {\"name\": \"query-name\"}, {\"name\": "
                 "\"query-uuid\"}, {\"name\": \"query-migrate\"}, {\"name\": "
                 "\"query-balloon\"}], \"id\": \"libvirt-2\"}", NULL, true);


    DO_TEST_PARSE("almost nothing", "[]", NULL);
    DO_TEST_PARSE_FAIL("nothing", "");

    DO_TEST_PARSE("number without garbage", "[ 234545 ]", "[234545]");
    DO_TEST_PARSE_FAIL("number with garbage", "[ 2345b45 ]");

    DO_TEST_PARSE("float without garbage", "[ 1.024e19 ]", "[1.024e19]");
    DO_TEST_PARSE_FAIL("float with garbage", "[ 0.0314159ee+100 ]");

    DO_TEST_PARSE("unsigned minus one", "[ 18446744073709551615 ]", "[18446744073709551615]");
    DO_TEST_PARSE("another big number", "[ 9223372036854775808 ]", "[9223372036854775808]");

    DO_TEST_PARSE("string", "[ \"The meaning of life\" ]",
                  "[\"The meaning of life\"]");
    DO_TEST_PARSE_FAIL("unterminated string", "[ \"The meaning of lif ]");

    DO_TEST_PARSE("integer", "1", NULL);
    DO_TEST_PARSE("boolean", "true", NULL);
    DO_TEST_PARSE("null", "null", NULL);
    DO_TEST_PARSE("[]", "[]", NULL);

    DO_TEST_PARSE("escaping symbols", "[\"\\\"\\t\\n\\\\\"]", NULL);
    DO_TEST_PARSE("escaped strings", "[\"{\\\"blurb\\\":\\\"test\\\"}\"]", NULL);

    DO_TEST_PARSE_FAIL("incomplete keyword", "tr");
    DO_TEST_PARSE_FAIL("overdone keyword", "[ truest ]");
    DO_TEST_PARSE_FAIL("unknown keyword", "huh");
    DO_TEST_PARSE_FAIL("comments", "[ /* nope */\n1 // not this either\n]");
    DO_TEST_PARSE_FAIL("trailing garbage", "[] []");
    DO_TEST_PARSE_FAIL("list without array", "1, 1");
    DO_TEST_PARSE_FAIL("parser abuse", "1] [2");
    DO_TEST_PARSE_FAIL("invalid UTF-8", "\"\x80\"");

    DO_TEST_PARSE_FAIL("object with numeric keys", "{ 1:1, 2:1, 3:2 }");
    DO_TEST_PARSE_FAIL("unterminated object", "{ \"1\":1, \"2\":1, \"3\":2");
    DO_TEST_PARSE_FAIL("unterminated array of objects",
                       "[ {\"name\": \"John\"}, {\"name\": \"Paul\"}, ");
    DO_TEST_PARSE_FAIL("array of an object with an array as a key",
                       "[ {[\"key1\", \"key2\"]: \"value\"} ]");
    DO_TEST_PARSE_FAIL("object with unterminated key", "{ \"key:7 }");
    DO_TEST_PARSE_FAIL("duplicate key", "{ \"a\": 1, \"a\": 1 }");

    DO_TEST_FULL("lookup on array", Lookup,
                 "[ 1 ]", NULL, false);
    DO_TEST_FULL("lookup on string", Lookup,
                 "\"str\"", NULL, false);
    DO_TEST_FULL("lookup on integer", Lookup,
                 "1", NULL, false);
    DO_TEST_FULL("lookup with missing key", Lookup,
                 "{ }", NULL, false);
    DO_TEST_FULL("lookup with wrong type", Lookup,
                 "{ \"a\": 1, \"b\": \"str\", \"c\": [], \"d\": {} }",
                 NULL, false);
    DO_TEST_FULL("lookup with correct type", Lookup,
                 "{ \"a\": {}, \"b\": 1, \"c\": \"str\", \"d\": [] }",
                 NULL, true);
    DO_TEST_FULL("create object with nested json in attribute", EscapeObj,
                 NULL, NULL, true);
    DO_TEST_FULL("stealing of attributes while creating objects",
                 ObjectFormatSteal, NULL, NULL, true);

#define DO_TEST_DEFLATTEN(name, pass) \
    DO_TEST_FULL(name, Deflatten, NULL, NULL, pass)

    DO_TEST_DEFLATTEN("unflattened", true);
    DO_TEST_DEFLATTEN("basic-file", true);
    DO_TEST_DEFLATTEN("basic-generic", true);
    DO_TEST_DEFLATTEN("deep-file", true);
    DO_TEST_DEFLATTEN("deep-generic", true);
    DO_TEST_DEFLATTEN("nested", true);
    DO_TEST_DEFLATTEN("double-key", false);
    DO_TEST_DEFLATTEN("concat", true);
    DO_TEST_DEFLATTEN("concat-double-key", false);
    DO_TEST_DEFLATTEN("qemu-sheepdog", true);
    DO_TEST_DEFLATTEN("dotted-array", true);

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
