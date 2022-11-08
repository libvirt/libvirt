#include <config.h>

#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>

#include "internal.h"
#include "testutils.h"
#include "network_conf.h"
#include "viralloc.h"
#include "network/bridge_driver.h"
#define LIBVIRT_VIRCOMMANDPRIV_H_ALLOW
#include "vircommandpriv.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static int
testCompareXMLToConfFiles(const char *inxml, const char *outconf,
                          char *outhostsfile, dnsmasqCaps *caps)
{
    char *confactual = NULL;
    g_autofree char *hostsfileactual = NULL;
    int ret = -1;
    virNetworkDef *def = NULL;
    virNetworkObj *obj = NULL;
    g_autofree char *pidfile = NULL;
    g_autoptr(dnsmasqContext) dctx = NULL;
    g_autoptr(virNetworkXMLOption) xmlopt = NULL;

    if (!(xmlopt = networkDnsmasqCreateXMLConf()))
        goto fail;

    if (!(def = virNetworkDefParse(NULL, inxml, xmlopt, false)))
        goto fail;

    if (!(obj = virNetworkObjNew()))
        goto fail;

    virNetworkObjSetDef(obj, def);

    dctx = dnsmasqContextNew(def->name, "/var/lib/libvirt/dnsmasq");

    if (dctx == NULL)
        goto fail;

    if (networkDnsmasqConfContents(obj, pidfile, &confactual,
                                   &hostsfileactual, dctx, caps) < 0)
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

    if (virTestCompareToFile(confactual, outconf) < 0)
        goto fail;

    if (virFileExists(outhostsfile)) {
        if (!hostsfileactual) {
            VIR_TEST_DEBUG("%s: hostsfile exists but the configuration did "
                           "not specify any host", outhostsfile);
            goto fail;
        } else if (virTestCompareToFile(hostsfileactual, outhostsfile) < 0) {
            goto fail;
        }
    } else if (hostsfileactual) {
        VIR_TEST_DEBUG("%s: file does not exist but actual data was expected",
                       outhostsfile);
        goto fail;
    }

    ret = 0;

 fail:
    VIR_FREE(confactual);
    virNetworkObjEndAPI(&obj);
    return ret;
}

typedef struct {
    const char *name;
    dnsmasqCaps *caps;
} testInfo;

static int
testCompareXMLToConfHelper(const void *data)
{
    int result = -1;
    const testInfo *info = data;
    g_autofree char *inxml = NULL;
    g_autofree char *outconf = NULL;
    g_autofree char *outhostsfile = NULL;

    inxml = g_strdup_printf("%s/networkxml2confdata/%s.xml", abs_srcdir, info->name);
    outconf = g_strdup_printf("%s/networkxml2confdata/%s.conf", abs_srcdir, info->name);
    outhostsfile = g_strdup_printf("%s/networkxml2confdata/%s.hostsfile", abs_srcdir, info->name);

    result = testCompareXMLToConfFiles(inxml, outconf, outhostsfile, info->caps);

    return result;
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


static int
mymain(void)
{
    int ret = 0;
    g_autoptr(dnsmasqCaps) full = NULL;

    if (!(full = buildCaps())) {
        fprintf(stderr, "failed to create the fake capabilities: %s",
                virGetLastErrorMessage());
        return EXIT_FAILURE;
    }

#define DO_TEST(xname, xcaps) \
    do { \
        static testInfo info; \
 \
        info.name = xname; \
        info.caps = xcaps; \
        if (virTestRun("Network XML-2-Conf " xname, \
                       testCompareXMLToConfHelper, &info) < 0) { \
            ret = -1; \
        } \
    } while (0)

    DO_TEST("isolated-network", full);
    DO_TEST("netboot-network", full);
    DO_TEST("netboot-proxy-network", full);
    DO_TEST("netboot-tftp", full);
    DO_TEST("nat-network-dns-srv-record-minimal", full);
    DO_TEST("nat-network-name-with-quotes", full);
    DO_TEST("routed-network", full);
    DO_TEST("routed-network-no-dns", full);
    DO_TEST("open-network", full);
    DO_TEST("nat-network", full);
    DO_TEST("nat-network-dns-txt-record", full);
    DO_TEST("nat-network-dns-srv-record", full);
    DO_TEST("nat-network-dns-hosts", full);
    DO_TEST("nat-network-dns-forward-plain", full);
    DO_TEST("nat-network-dns-forwarders", full);
    DO_TEST("nat-network-dns-forwarder-no-resolv", full);
    DO_TEST("nat-network-dns-local-domain", full);
    DO_TEST("nat-network-mtu", full);
    DO_TEST("dhcp6-network", full);
    DO_TEST("dhcp6-nat-network", full);
    DO_TEST("dhcp6host-routed-network", full);
    DO_TEST("ptr-domains-auto", full);
    DO_TEST("dnsmasq-options", full);
    DO_TEST("leasetime-seconds", full);
    DO_TEST("leasetime-minutes", full);
    DO_TEST("leasetime-hours", full);
    DO_TEST("leasetime-infinite", full);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain,
                      VIR_TEST_MOCK("virdnsmasq"))
