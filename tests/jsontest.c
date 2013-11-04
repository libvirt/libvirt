#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "internal.h"
#include "virjson.h"
#include "testutils.h"

struct testInfo {
    const char *doc;
    const char *expect;
    bool pass;
};


static int
testJSONFromString(const void *data)
{
    const struct testInfo *info = data;
    virJSONValuePtr json;
    int ret = -1;

    json = virJSONValueFromString(info->doc);

    if (info->pass) {
        if (!json) {
            if (virTestGetVerbose())
                fprintf(stderr, "Fail to parse %s\n", info->doc);
            ret = -1;
            goto cleanup;
        } else {
            if (virTestGetDebug())
                fprintf(stderr, "Parsed %s\n", info->doc);
        }
    } else {
        if (json) {
            if (virTestGetVerbose())
                fprintf(stderr, "Should not have parsed %s\n", info->doc);
            ret = -1;
            goto cleanup;
        } else {
            if (virTestGetDebug())
                fprintf(stderr, "Fail to parse %s\n", info->doc);
        }
    }

    ret = 0;

cleanup:
    virJSONValueFree(json);
    return ret;
}


static int
testJSONAddRemove(const void *data)
{
    const struct testInfo *info = data;
    virJSONValuePtr json;
    virJSONValuePtr name = NULL;
    char *result = NULL;
    int ret = -1;

    json = virJSONValueFromString(info->doc);
    if (!json) {
        if (virTestGetVerbose())
            fprintf(stderr, "Fail to parse %s\n", info->doc);
        ret = -1;
        goto cleanup;
    }

    switch (virJSONValueObjectRemoveKey(json, "name", &name)) {
    case 1:
        if (!info->pass) {
            if (virTestGetVerbose())
                fprintf(stderr, "should not remove from non-object %s\n",
                        info->doc);
            goto cleanup;
        }
        break;
    case -1:
        if (!info->pass)
            ret = 0;
        else if (virTestGetVerbose())
            fprintf(stderr, "Fail to recognize non-object %s\n", info->doc);
        goto cleanup;
    default:
        if (virTestGetVerbose())
            fprintf(stderr, "unexpected result when removing from %s\n",
                    info->doc);
        goto cleanup;
    }
    if (STRNEQ_NULLABLE(virJSONValueGetString(name), "sample")) {
        if (virTestGetVerbose())
            fprintf(stderr, "unexpected value after removing name: %s\n",
                    NULLSTR(virJSONValueGetString(name)));
        goto cleanup;
    }
    if (virJSONValueObjectRemoveKey(json, "name", NULL)) {
        if (virTestGetVerbose())
            fprintf(stderr, "%s",
                    "unexpected success when removing missing key\n");
        goto cleanup;
    }
    if (virJSONValueObjectAppendString(json, "newname", "foo") < 0) {
        if (virTestGetVerbose())
            fprintf(stderr, "%s", "unexpected failure adding new key\n");
        goto cleanup;
    }
    if (!(result = virJSONValueToString(json, false))) {
        if (virTestGetVerbose())
            fprintf(stderr, "%s", "failed to stringize result\n");
        goto cleanup;
    }
    if (STRNEQ(info->expect, result)) {
        if (virTestGetVerbose())
            virtTestDifference(stderr, info->expect, result);
        goto cleanup;
    }
    ret = 0;

cleanup:
    virJSONValueFree(json);
    virJSONValueFree(name);
    VIR_FREE(result);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;

#define DO_TEST_FULL(name, cmd, doc, expect, pass)                  \
    do {                                                            \
        struct testInfo info = { doc, expect, pass };               \
        if (virtTestRun(name, testJSON ## cmd, &info) < 0)          \
            ret = -1;                                               \
    } while (0)

#define DO_TEST_PARSE(name, doc)                \
    DO_TEST_FULL(name, FromString, doc, NULL, true)

#define DO_TEST_PARSE_FAIL(name, doc)           \
    DO_TEST_FULL(name, FromString, doc, NULL, false)


    DO_TEST_PARSE("Simple", "{\"return\": {}, \"id\": \"libvirt-1\"}");
    DO_TEST_PARSE("NotSoSimple", "{\"QMP\": {\"version\": {\"qemu\":"
            "{\"micro\": 91, \"minor\": 13, \"major\": 0},"
            "\"package\": \" (qemu-kvm-devel)\"}, \"capabilities\": []}}");


    DO_TEST_PARSE("Harder", "{\"return\": [{\"filename\": "
                  "\"unix:/home/berrange/.libvirt/qemu/lib/tck.monitor,server\","
                  "\"label\": \"charmonitor\"}, {\"filename\": \"pty:/dev/pts/158\","
                  "\"label\": \"charserial0\"}], \"id\": \"libvirt-3\"}");

    DO_TEST_PARSE("VeryHard", "{\"return\": [{\"name\": \"quit\"}, {\"name\":"
                  "\"eject\"}, {\"name\": \"change\"}, {\"name\": \"screendump\"},"
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
                  "\"query-balloon\"}], \"id\": \"libvirt-2\"}");

    DO_TEST_FULL("add and remove", AddRemove,
                 "{\"name\": \"sample\", \"value\": true}",
                 "{\"value\":true,\"newname\":\"foo\"}",
                 true);
    DO_TEST_FULL("add and remove", AddRemove,
                 "[ 1 ]", NULL, false);


    DO_TEST_PARSE("almost nothing", "[]");
    DO_TEST_PARSE_FAIL("nothing", "");

    DO_TEST_PARSE("number without garbage", "[ 234545 ]");
    DO_TEST_PARSE_FAIL("number with garbage", "[ 2345b45 ]");

    DO_TEST_PARSE("float without garbage", "[ 0.0314159e+100 ]");
    DO_TEST_PARSE_FAIL("float with garbage", "[ 0.0314159ee+100 ]");

    DO_TEST_PARSE("string", "[ \"The meaning of life\" ]");
    DO_TEST_PARSE_FAIL("unterminated string", "[ \"The meaning of lif ]");


    DO_TEST_PARSE_FAIL("object with numeric keys", "{ 1:1, 2:1, 3:2 }");
    DO_TEST_PARSE_FAIL("unterminated object", "{ \"1\":1, \"2\":1, \"3\":2");
    DO_TEST_PARSE_FAIL("unterminated array of objects",
                       "[ {\"name\": \"John\"}, {\"name\": \"Paul\"}, ");
    DO_TEST_PARSE_FAIL("array of an object with an array as a key",
                       "[ {[\"key1\", \"key2\"]: \"value\"} ]");
    DO_TEST_PARSE_FAIL("object with unterminated key", "{ \"key:7 }");

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
