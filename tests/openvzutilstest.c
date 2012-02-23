#include <config.h>

#ifdef WITH_OPENVZ

# include <stdio.h>
# include <string.h>
# include <unistd.h>

# include "internal.h"
# include "memory.h"
# include "testutils.h"
# include "util.h"
# include "openvz/openvz_conf.h"

static int
testLocateConfFile(int vpsid ATTRIBUTE_UNUSED, char **conffile,
                   const char *ext ATTRIBUTE_UNUSED)
{
    return virAsprintf(conffile, "%s/openvzutilstest.conf", abs_srcdir);
}

struct testConfigParam {
    const char *param;
    const char *value;
    int ret;
};

static struct testConfigParam configParams[] = {
    { "OSTEMPLATE", "rhel-5-lystor", 1 },
    { "IP_ADDRESS", "194.44.18.88", 1 },
    { "THIS_PARAM_IS_MISSING", NULL, 0 },
};

static int
testReadConfigParam(const void *data ATTRIBUTE_UNUSED)
{
    int result = -1;
    int i;
    char *conf = NULL;
    char *value = NULL;

    if (virAsprintf(&conf, "%s/openvzutilstest.conf", abs_srcdir) < 0) {
        return -1;
    }

    for (i = 0; i < ARRAY_CARDINALITY(configParams); ++i) {
        if (openvzReadConfigParam(conf, configParams[i].param,
                                  &value) != configParams[i].ret) {
            goto cleanup;
        }

        if (configParams[i].ret != 1) {
            continue;
        }

        if (STRNEQ(configParams[i].value, value)) {
            virtTestDifference(stderr, configParams[i].value, value);
            goto cleanup;
        }
    }

    result = 0;

cleanup:
    VIR_FREE(conf);
    VIR_FREE(value);

    return result;
}

static int
testReadNetworkConf(const void *data ATTRIBUTE_UNUSED)
{
    int result = -1;
    virDomainDefPtr def = NULL;
    char *actual = NULL;
    virErrorPtr err = NULL;
    const char *expected =
        "<domain type='openvz'>\n"
        "  <uuid>00000000-0000-0000-0000-000000000000</uuid>\n"
        "  <memory unit='KiB'>0</memory>\n"
        "  <currentMemory unit='KiB'>0</currentMemory>\n"
        "  <vcpu>0</vcpu>\n"
        "  <os>\n"
        "    <type>exe</type>\n"
        "    <init>/sbin/init</init>\n"
        "  </os>\n"
        "  <clock offset='utc'/>\n"
        "  <on_poweroff>destroy</on_poweroff>\n"
        "  <on_reboot>destroy</on_reboot>\n"
        "  <on_crash>destroy</on_crash>\n"
        "  <devices>\n"
        "    <interface type='ethernet'>\n"
        "      <mac address='00:00:00:00:00:00'/>\n"
        "      <ip address='194.44.18.88'/>\n"
        "    </interface>\n"
        "    <interface type='bridge'>\n"
        "      <mac address='00:18:51:c1:05:ee'/>\n"
        "      <target dev='veth105.10'/>\n"
        "    </interface>\n"
        "  </devices>\n"
        "</domain>\n";

    if (VIR_ALLOC(def) < 0 ||
        !(def->os.type = strdup("exe")) ||
        !(def->os.init = strdup("/sbin/init")))
        goto cleanup;

    def->virtType = VIR_DOMAIN_VIRT_OPENVZ;

    if (openvzReadNetworkConf(def, 1) < 0) {
        err = virGetLastError();
        fprintf(stderr, "ERROR: %s\n", err != NULL ? err->message : "<unknown>");
        goto cleanup;
    }

    actual = virDomainDefFormat(def, VIR_DOMAIN_XML_INACTIVE);

    if (actual == NULL) {
        err = virGetLastError();
        fprintf(stderr, "ERROR: %s\n", err != NULL ? err->message : "<unknown>");
        goto cleanup;
    }

    if (STRNEQ(expected, actual)) {
        virtTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    result = 0;

cleanup:
    VIR_FREE(actual);
    virDomainDefFree(def);

    return result;
}

static int
mymain(void)
{
    int result = 0;

    openvzLocateConfFile = testLocateConfFile;

# define DO_TEST(_name)                                                       \
        do {                                                                  \
            if (virtTestRun("OpenVZ "#_name, 1, test##_name,                  \
                            NULL) < 0) {                                      \
                result = -1;                                                  \
            }                                                                 \
        } while (0)

    DO_TEST(ReadConfigParam);
    DO_TEST(ReadNetworkConf);

    return result == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)

#else
# include "testutils.h"

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_OPENVZ */
