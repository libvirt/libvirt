#include <config.h>

#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>

#include "internal.h"
#include "testutils.h"
#include "network_conf.h"
#include "bridge_driver.h"
#define LIBVIRT_BRIDGE_DRIVER_PRIV_H_ALLOW
#include "bridge_driver_priv.h"
#define LIBVIRT_VIRCOMMANDPRIV_H_ALLOW
#include "vircommandpriv.h"

#define VIR_FROM_THIS VIR_FROM_NONE

typedef enum {
    TEST_COMPARE_NET_XML2XML_RESULT_SUCCESS,
    TEST_COMPARE_NET_XML2XML_RESULT_FAIL_PARSE,
    TEST_COMPARE_NET_XML2XML_RESULT_FAIL_VALIDATE,
    TEST_COMPARE_NET_XML2XML_RESULT_FAIL_FORMAT,
    TEST_COMPARE_NET_XML2XML_RESULT_FAIL_COMPARE,
} testCompareNetXML2XMLResult;

struct _testInfo {
    const char *name;
    unsigned int flags;
    testCompareNetXML2XMLResult expectResult;
    virNetworkXMLOption *xmlopt; /* borrowed, immutable */
    dnsmasqCaps *caps;
    virNetworkDef *def;
    char *inxml;
    char *outxml;
    char *outconf;
    char *outhostsfile;
};

typedef struct _testInfo testInfo;
void testInfoFree(testInfo *info);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(testInfo, testInfoFree);

void testInfoFree(testInfo *info)
{
    if (!info)
        return;

    virNetworkDefFree(info->def);
    VIR_FREE(info->inxml);
    VIR_FREE(info->outxml);
    VIR_FREE(info->outconf);
    VIR_FREE(info->outhostsfile);
    VIR_FREE(info);
}

static int
testCompareXMLToXMLFiles(const void *data)
{
    testInfo *info = (void *) data;
    g_autofree char *actual = NULL;
    int ret;
    testCompareNetXML2XMLResult result = TEST_COMPARE_NET_XML2XML_RESULT_SUCCESS;
    g_autoptr(virNetworkDef) def = NULL;

    if (!(def = virNetworkDefParse(NULL, info->inxml, info->xmlopt, false))) {
        result = TEST_COMPARE_NET_XML2XML_RESULT_FAIL_PARSE;
        goto cleanup;
    }
    if (info->expectResult == TEST_COMPARE_NET_XML2XML_RESULT_FAIL_PARSE)
        goto cleanup;

    if (networkValidateTests(def) < 0) {
        result = TEST_COMPARE_NET_XML2XML_RESULT_FAIL_VALIDATE;
        goto cleanup;
    }
    if (info->expectResult == TEST_COMPARE_NET_XML2XML_RESULT_FAIL_VALIDATE)
        goto cleanup;

    if (!(actual = virNetworkDefFormat(def, info->xmlopt, info->flags))) {
        result = TEST_COMPARE_NET_XML2XML_RESULT_FAIL_FORMAT;
        goto cleanup;
    }
    if (info->expectResult == TEST_COMPARE_NET_XML2XML_RESULT_FAIL_FORMAT)
        goto cleanup;

    if (virTestCompareToFile(actual, info->outxml) < 0) {
        result = TEST_COMPARE_NET_XML2XML_RESULT_FAIL_COMPARE;
        goto cleanup;
    }
    if (info->expectResult == TEST_COMPARE_NET_XML2XML_RESULT_FAIL_COMPARE)
        goto cleanup;

 cleanup:
    if (result == info->expectResult) {
        ret = 0;
        if (info->expectResult != TEST_COMPARE_NET_XML2XML_RESULT_SUCCESS) {
            VIR_TEST_DEBUG("Got expected failure code=%d msg=%s",
                           result, virGetLastErrorMessage());
        } else {
            info->def = g_steal_pointer(&def);
        }
    } else {
        ret = -1;
        VIR_TEST_DEBUG("Expected result code=%d but received code=%d",
                       info->expectResult, result);
    }
    virResetLastError();

    return ret;
}


static int
testCompareXMLToConfFiles(const void *data)
{
    testInfo *info = (void *) data;
    char *confactual = NULL;
    g_autofree char *hostsfileactual = NULL;
    int ret = -1;
    virNetworkDef *def = NULL;
    virNetworkObj *obj = NULL;
    g_autofree char *pidfile = NULL;
    g_autoptr(dnsmasqContext) dctx = NULL;
    bool compareFailed = false;

    if (!(obj = virNetworkObjNew()))
        goto fail;

    if (!(def = g_steal_pointer(&info->def))) {
        /* Previous test wasn't executed. */
        if (!(def = virNetworkDefParse(NULL, info->inxml, info->xmlopt, false)))
            goto fail;

        if (networkValidateTests(def) < 0) {
            virNetworkDefFree(def);
            goto fail;
        }
    }

    virNetworkObjSetDef(obj, def);

    if (!networkNeedsDnsmasq(def)) {
        ret = EXIT_AM_SKIP;
        goto fail;
    }

    dctx = dnsmasqContextNew(def->name, "/var/lib/libvirt/dnsmasq");

    if (dctx == NULL)
        goto fail;

    if (networkDnsmasqConfContents(obj, pidfile, &confactual,
                                   &hostsfileactual, dctx, info->caps) < 0)
        goto fail;

    /* Any changes to this function ^^ should be reflected here too. */
#ifndef __linux__
    {
        char * tmp;

        if (!(tmp = virStringReplace(confactual,
                                     "except-interface=lo0\n",
                                     "except-interface=lo\n")))
            goto fail;
        VIR_FREE(confactual);
        confactual = g_steal_pointer(&tmp);
    }
#endif

    if (virTestCompareToFile(confactual, info->outconf) < 0)
        compareFailed = true;

    if (hostsfileactual) {
        if (virTestCompareToFile(hostsfileactual, info->outhostsfile) < 0) {
            compareFailed = true;
        }
    } else {
        if (virFileExists(info->outhostsfile)) {
            VIR_TEST_DEBUG("%s: hostsfile exists but the configuration did not specify any host",
                           info->outhostsfile);
            compareFailed = true;
        }
    }

    if (compareFailed)
        goto fail;

    ret = 0;

 fail:
    VIR_FREE(confactual);
    virNetworkObjEndAPI(&obj);
    return ret;
}

static void
buildCapsCallback(const char *const*args,
                  const char *const*env G_GNUC_UNUSED,
                  const char *input G_GNUC_UNUSED,
                  char **output,
                  char **error G_GNUC_UNUSED,
                  int *status,
                  void *opaque G_GNUC_UNUSED)
{
    if (STREQ(args[0], "/usr/sbin/dnsmasq") && STREQ(args[1], "--version")) {
        *output = g_strdup("Dnsmasq version 2.67\n");
        *status = EXIT_SUCCESS;
    } else {
        *status = EXIT_FAILURE;
    }
}


static dnsmasqCaps *
buildCaps(void)
{
    g_autoptr(dnsmasqCaps) caps = NULL;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, NULL, true, true, buildCapsCallback, NULL);

    caps = dnsmasqCapsNewFromBinary();

    return g_steal_pointer(&caps);
}


static void
testRun(const char *name,
        int *ret,
        virNetworkXMLOption *xmlopt,
        dnsmasqCaps *caps,
        testCompareNetXML2XMLResult expectResult,
        unsigned int flags)
{
    g_autofree char *name_xml2xml = g_strdup_printf("Network XML-2-XML %s", name);
    g_autofree char *name_xml2conf = g_strdup_printf("Network XML-2-Conf %s", name);
    g_autoptr(testInfo) info = g_new0(testInfo, 1);

    info->name = name;
    info->flags = flags;
    info->expectResult = expectResult;
    info->xmlopt = xmlopt;
    info->caps = caps;
    info->inxml = g_strdup_printf("%s/networkxmlconfdata/%s.xml", abs_srcdir, name);
    info->outxml = g_strdup_printf("%s/networkxmlconfdata/%s.expect.xml", abs_srcdir, name);
    info->outconf = g_strdup_printf("%s/networkxmlconfdata/%s.conf", abs_srcdir, name);
    info->outhostsfile = g_strdup_printf("%s/networkxmlconfdata/%s.hostsfile", abs_srcdir, name);

    virTestRunLog(ret, name_xml2xml, testCompareXMLToXMLFiles, info);

    if (expectResult == TEST_COMPARE_NET_XML2XML_RESULT_SUCCESS)
        virTestRunLog(ret, name_xml2conf, testCompareXMLToConfFiles, info);
}

static int
mymain(void)
{
    g_autoptr(virNetworkXMLOption) xmlopt = NULL;
    g_autoptr(dnsmasqCaps) caps = NULL;
    int ret = 0;

    if (!(xmlopt = networkDnsmasqCreateXMLConf()))
        return -1;

    if (!(caps = buildCaps()))
        return -1;

#define DO_TEST_FULL(name, flags, expectResult) \
    testRun(name, &ret, xmlopt, caps, expectResult, flags)
#define DO_TEST(name) \
    DO_TEST_FULL(name, 0, TEST_COMPARE_NET_XML2XML_RESULT_SUCCESS)
#define DO_TEST_FLAGS(name, flags) \
    DO_TEST_FULL(name, flags, TEST_COMPARE_NET_XML2XML_RESULT_SUCCESS)
#define DO_TEST_PARSE_ERROR(name) \
    DO_TEST_FULL(name, 0, TEST_COMPARE_NET_XML2XML_RESULT_FAIL_PARSE)
#define DO_TEST_VALIDATE_ERROR(name) \
    DO_TEST_FULL(name, 0, TEST_COMPARE_NET_XML2XML_RESULT_FAIL_VALIDATE)

    DO_TEST("dhcp6-network");
    DO_TEST("dhcp6-nat-network");
    DO_TEST("dhcp6host-routed-network");
    DO_TEST("empty-allow-ipv6");
    DO_TEST("isolated-network");
    DO_TEST("routed-network");
    DO_TEST("routed-network-no-dns");
    DO_TEST_PARSE_ERROR("routed-network-no-dns-extra-elements");
    DO_TEST("open-network");
    DO_TEST_PARSE_ERROR("open-network-with-forward-dev");
    DO_TEST("nat-network");
    DO_TEST("netboot-network");
    DO_TEST("netboot-proxy-network");
    DO_TEST("netboot-tftp");
    DO_TEST("nat-network-dns-txt-record");
    DO_TEST("nat-network-dns-srv-record");
    DO_TEST("nat-network-dns-srv-records");
    DO_TEST("nat-network-dns-srv-record-minimal");
    DO_TEST("nat-network-dns-hosts");
    DO_TEST("nat-network-dns-forward-plain");
    DO_TEST("nat-network-dns-forwarders");
    DO_TEST("nat-network-dns-forwarder-no-resolv");
    DO_TEST("nat-network-dns-local-domain");
    DO_TEST("nat-network-forward-nat-ipv6");
    DO_TEST("nat-network-forward-nat-address");
    DO_TEST("nat-network-forward-nat-no-address");
    DO_TEST("nat-network-name-with-quotes");
    DO_TEST("nat-network-mtu");
    DO_TEST("8021Qbh-net");
    DO_TEST("direct-net");
    DO_TEST("host-bridge-net");
    DO_TEST("vepa-net");
    DO_TEST("bandwidth-network");
    DO_TEST("openvswitch-net");
    DO_TEST_VALIDATE_ERROR("passthrough-pf");
    DO_TEST("hostdev");
    DO_TEST_FLAGS("hostdev-pf", VIR_NETWORK_XML_INACTIVE);
    DO_TEST_FLAGS("hostdev-pf-driver-model", VIR_NETWORK_XML_INACTIVE);
    DO_TEST("ptr-domains-auto");
    DO_TEST_VALIDATE_ERROR("passthrough-address-crash");
    DO_TEST("nat-network-explicit-flood");
    DO_TEST("host-bridge-no-flood");
    DO_TEST_PARSE_ERROR("hostdev-duplicate");
    DO_TEST_PARSE_ERROR("passthrough-duplicate");
    DO_TEST("metadata");
    DO_TEST("set-mtu");
    DO_TEST("dnsmasq-options");
    DO_TEST("leasetime-seconds");
    DO_TEST("leasetime-minutes");
    DO_TEST("leasetime-hours");
    DO_TEST("leasetime-infinite");
    DO_TEST("isolated-ports");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain,
                      VIR_TEST_MOCK("virpci"),
                      VIR_TEST_MOCK("virdnsmasq"),
                      VIR_TEST_MOCK("virrandom"))
