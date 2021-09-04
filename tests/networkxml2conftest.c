#include <config.h>

#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>

#include "internal.h"
#include "testutils.h"
#include "network_conf.h"
#include "vircommand.h"
#include "viralloc.h"
#include "network/bridge_driver.h"
#include "virstring.h"

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
    virCommand *cmd = NULL;
    g_autofree char *pidfile = NULL;
    dnsmasqContext *dctx = NULL;
    g_autoptr(virNetworkXMLOption) xmlopt = NULL;

    if (!(xmlopt = networkDnsmasqCreateXMLConf()))
        goto fail;

    if (!(def = virNetworkDefParseFile(inxml, xmlopt)))
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
    char * tmp;

    if (!(tmp = virStringReplace(confactual,
                                 "except-interface=lo0\n",
                                 "except-interface=lo\n")))
        goto fail;
    VIR_FREE(confactual);
    confactual = g_steal_pointer(&tmp);
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
    virCommandFree(cmd);
    virNetworkObjEndAPI(&obj);
    dnsmasqContextFree(dctx);
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

static int
mymain(void)
{
    int ret = 0;
    dnsmasqCaps *restricted
        = dnsmasqCapsNewFromBuffer("Dnsmasq version 2.48");
    dnsmasqCaps *full
        = dnsmasqCapsNewFromBuffer("Dnsmasq version 2.63\n--bind-dynamic");
    dnsmasqCaps *dhcpv6
        = dnsmasqCapsNewFromBuffer("Dnsmasq version 2.64\n--bind-dynamic");

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

    DO_TEST("isolated-network", restricted);
    DO_TEST("netboot-network", restricted);
    DO_TEST("netboot-proxy-network", restricted);
    DO_TEST("nat-network-dns-srv-record-minimal", restricted);
    DO_TEST("nat-network-name-with-quotes", restricted);
    DO_TEST("routed-network", full);
    DO_TEST("routed-network-no-dns", full);
    DO_TEST("open-network", full);
    DO_TEST("nat-network", dhcpv6);
    DO_TEST("nat-network-dns-txt-record", full);
    DO_TEST("nat-network-dns-srv-record", full);
    DO_TEST("nat-network-dns-hosts", full);
    DO_TEST("nat-network-dns-forward-plain", full);
    DO_TEST("nat-network-dns-forwarders", full);
    DO_TEST("nat-network-dns-forwarder-no-resolv", full);
    DO_TEST("nat-network-dns-local-domain", full);
    DO_TEST("nat-network-mtu", dhcpv6);
    DO_TEST("dhcp6-network", dhcpv6);
    DO_TEST("dhcp6-nat-network", dhcpv6);
    DO_TEST("dhcp6host-routed-network", dhcpv6);
    DO_TEST("ptr-domains-auto", dhcpv6);
    DO_TEST("dnsmasq-options", dhcpv6);
    DO_TEST("leasetime-seconds", full);
    DO_TEST("leasetime-minutes", full);
    DO_TEST("leasetime-hours", full);
    DO_TEST("leasetime-infinite", full);

    virObjectUnref(dhcpv6);
    virObjectUnref(full);
    virObjectUnref(restricted);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
