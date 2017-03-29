#include <config.h>

#include "testutils.h"

#ifdef WITH_OPENVZ

# include <stdio.h>
# include <string.h>
# include <unistd.h>

# include "internal.h"
# include "viralloc.h"
# include "openvz/openvz_conf.h"
# include "virstring.h"

# define VIR_FROM_THIS VIR_FROM_OPENVZ

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
    size_t i;
    char *conf = NULL;
    char *value = NULL;

    if (virAsprintf(&conf, "%s/openvzutilstest.conf", abs_srcdir) < 0)
        return -1;

    for (i = 0; i < ARRAY_CARDINALITY(configParams); ++i) {
        if (openvzReadConfigParam(conf, configParams[i].param,
                                  &value) != configParams[i].ret) {
            goto cleanup;
        }

        if (configParams[i].ret != 1)
            continue;

        if (STRNEQ(configParams[i].value, value)) {
            virTestDifference(stderr, configParams[i].value, value);
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
    const char *expected =
        "<domain type='openvz'>\n"
        "  <uuid>00000000-0000-0000-0000-000000000000</uuid>\n"
        "  <memory unit='KiB'>0</memory>\n"
        "  <currentMemory unit='KiB'>0</currentMemory>\n"
        "  <vcpu placement='static'>0</vcpu>\n"
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
        "      <ip address='194.44.18.88' family='ipv4'/>\n"
        "    </interface>\n"
        "    <interface type='bridge'>\n"
        "      <mac address='00:18:51:c1:05:ee'/>\n"
        "      <target dev='veth105.10'/>\n"
        "    </interface>\n"
        "  </devices>\n"
        "</domain>\n";

    if (!(def = virDomainDefNew()) ||
        VIR_STRDUP(def->os.init, "/sbin/init") < 0)
        goto cleanup;

    def->virtType = VIR_DOMAIN_VIRT_OPENVZ;
    def->os.type = VIR_DOMAIN_OSTYPE_EXE;

    if (openvzReadNetworkConf(def, 1) < 0) {
        fprintf(stderr, "ERROR: %s\n", virGetLastErrorMessage());
        goto cleanup;
    }

    actual = virDomainDefFormat(def, NULL, VIR_DOMAIN_DEF_FORMAT_INACTIVE);

    if (actual == NULL) {
        fprintf(stderr, "ERROR: %s\n", virGetLastErrorMessage());
        goto cleanup;
    }

    if (STRNEQ(expected, actual)) {
        virTestDifference(stderr, expected, actual);
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
            if (virTestRun("OpenVZ "#_name, test##_name,                      \
                            NULL) < 0) {                                      \
                result = -1;                                                  \
            }                                                                 \
        } while (0)

    DO_TEST(ReadConfigParam);
    DO_TEST(ReadNetworkConf);

    return result == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)

#else

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_OPENVZ */
