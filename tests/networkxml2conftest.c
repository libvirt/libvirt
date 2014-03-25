#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

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
testCompareXMLToConfFiles(const char *inxml, const char *outconf, dnsmasqCapsPtr caps)
{
    char *inXmlData = NULL;
    char *outConfData = NULL;
    char *actual = NULL;
    int ret = -1;
    virNetworkDefPtr dev = NULL;
    virNetworkObjPtr obj = NULL;
    virCommandPtr cmd = NULL;
    char *pidfile = NULL;
    dnsmasqContext *dctx = NULL;

    if (virtTestLoadFile(inxml, &inXmlData) < 0)
        goto fail;

    if (virtTestLoadFile(outconf, &outConfData) < 0)
        goto fail;

    if (!(dev = virNetworkDefParseString(inXmlData)))
        goto fail;

    if (VIR_ALLOC(obj) < 0)
        goto fail;

    obj->def = dev;
    dctx = dnsmasqContextNew(dev->name, "/var/lib/libvirt/dnsmasq");

    if (dctx == NULL)
        goto fail;

    if (networkDnsmasqConfContents(obj, pidfile, &actual,
                        dctx, caps) < 0)
        goto fail;

    if (STRNEQ(outConfData, actual)) {
        virtTestDifference(stderr, outConfData, actual);
        goto fail;
    }

    ret = 0;

 fail:
    VIR_FREE(inXmlData);
    VIR_FREE(outConfData);
    VIR_FREE(actual);
    VIR_FREE(pidfile);
    virCommandFree(cmd);
    virNetworkObjFree(obj);
    dnsmasqContextFree(dctx);
    return ret;
}

typedef struct {
    const char *name;
    dnsmasqCapsPtr caps;
} testInfo;

static int
testCompareXMLToConfHelper(const void *data)
{
    int result = -1;
    const testInfo *info = data;
    char *inxml = NULL;
    char *outxml = NULL;

    if (virAsprintf(&inxml, "%s/networkxml2confdata/%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&outxml, "%s/networkxml2confdata/%s.conf",
                    abs_srcdir, info->name) < 0) {
        goto cleanup;
    }

    result = testCompareXMLToConfFiles(inxml, outxml, info->caps);

 cleanup:
    VIR_FREE(inxml);
    VIR_FREE(outxml);

    return result;
}

static char *
testDnsmasqLeaseFileName(const char *netname)
{
    char *leasefile;

    ignore_value(virAsprintf(&leasefile, "/var/lib/libvirt/dnsmasq/%s.leases",
                             netname));
    return leasefile;
}

static int
mymain(void)
{
    int ret = 0;
    dnsmasqCapsPtr restricted
        = dnsmasqCapsNewFromBuffer("Dnsmasq version 2.48", DNSMASQ);
    dnsmasqCapsPtr full
        = dnsmasqCapsNewFromBuffer("Dnsmasq version 2.63\n--bind-dynamic", DNSMASQ);
    dnsmasqCapsPtr dhcpv6
        = dnsmasqCapsNewFromBuffer("Dnsmasq version 2.64\n--bind-dynamic", DNSMASQ);

    networkDnsmasqLeaseFileName = testDnsmasqLeaseFileName;

#define DO_TEST(xname, xcaps)                                        \
    do {                                                             \
        static testInfo info;                                        \
                                                                     \
        info.name = xname;                                           \
        info.caps = xcaps;                                           \
        if (virtTestRun("Network XML-2-Conf " xname,                 \
                        testCompareXMLToConfHelper, &info) < 0) {    \
            ret = -1;                                                \
        }                                                            \
    } while (0)

    DO_TEST("isolated-network", restricted);
    DO_TEST("netboot-network", restricted);
    DO_TEST("netboot-proxy-network", restricted);
    DO_TEST("nat-network-dns-srv-record-minimal", restricted);
    DO_TEST("routed-network", full);
    DO_TEST("nat-network", dhcpv6);
    DO_TEST("nat-network-dns-txt-record", full);
    DO_TEST("nat-network-dns-srv-record", full);
    DO_TEST("nat-network-dns-hosts", full);
    DO_TEST("nat-network-dns-forward-plain", full);
    DO_TEST("nat-network-dns-forwarders", full);
    DO_TEST("dhcp6-network", dhcpv6);
    DO_TEST("dhcp6-nat-network", dhcpv6);
    DO_TEST("dhcp6host-routed-network", dhcpv6);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
