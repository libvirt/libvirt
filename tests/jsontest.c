#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "internal.h"
#include "json.h"
#include "testutils.h"

struct testInfo {
    const char *doc;
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
mymain(void)
{
    int ret = 0;

#define DO_TEST_FULL(name, cmd, doc, pass)                          \
    do {                                                            \
        struct testInfo info = { doc, pass };                       \
        if (virtTestRun(name, 1, testJSON ## cmd, &info) < 0)       \
            ret = -1;                                               \
    } while (0)

#define DO_TEST_PARSE(name, doc)                \
    DO_TEST_FULL(name, FromString, doc, true)

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

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
