#include <config.h>

#include "testutils.h"

#ifdef WITH_OPENVZ

# include <unistd.h>

# include "internal.h"
# include "openvz/openvz_conf.h"

# define VIR_FROM_THIS VIR_FROM_OPENVZ

static int
testLocateConfFile(int vpsid G_GNUC_UNUSED, char **conffile,
                   const char *ext G_GNUC_UNUSED)
{
    *conffile = g_strdup_printf("%s/openvzutilstest.conf", abs_srcdir);
    return 0;
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
testReadConfigParam(const void *data G_GNUC_UNUSED)
{
    size_t i;
    g_autofree char *conf = NULL;
    g_autofree char *value = NULL;

    conf = g_strdup_printf("%s/openvzutilstest.conf", abs_srcdir);

    for (i = 0; i < G_N_ELEMENTS(configParams); ++i) {
        if (openvzReadConfigParam(conf, configParams[i].param,
                                  &value) != configParams[i].ret) {
            return -1;
        }

        if (configParams[i].ret != 1)
            continue;

        if (virTestCompareToString(configParams[i].value, value) < 0) {
            return -1;
        }
    }

    return 0;
}

static int
testReadNetworkConf(const void *data G_GNUC_UNUSED)
{
    int result = -1;
    g_autoptr(virDomainDef) def = NULL;
    g_autofree char *actual = NULL;
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
    struct openvz_driver driver = {
        .xmlopt = openvzXMLOption(&driver),
        .caps = openvzCapsInit(),
    };

    if (!(def = virDomainDefNew(driver.xmlopt)))
        goto cleanup;

    def->os.init = g_strdup("/sbin/init");

    def->virtType = VIR_DOMAIN_VIRT_OPENVZ;
    def->os.type = VIR_DOMAIN_OSTYPE_EXE;

    if (openvzReadNetworkConf(def, 1) < 0) {
        fprintf(stderr, "ERROR: %s\n", virGetLastErrorMessage());
        goto cleanup;
    }

    actual = virDomainDefFormat(def, driver.xmlopt, VIR_DOMAIN_DEF_FORMAT_INACTIVE);

    if (actual == NULL) {
        fprintf(stderr, "ERROR: %s\n", virGetLastErrorMessage());
        goto cleanup;
    }

    if (virTestCompareToString(expected, actual) < 0) {
        goto cleanup;
    }

    result = 0;

 cleanup:
    virObjectUnref(driver.xmlopt);
    virObjectUnref(driver.caps);

    return result;
}

static int
mymain(void)
{
    int result = 0;

    openvzLocateConfFile = testLocateConfFile;

# define DO_TEST(_name) \
        do { \
            if (virTestRun("OpenVZ "#_name, test##_name, \
                            NULL) < 0) { \
                result = -1; \
            } \
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
