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
    char *actual = NULL;
    int ret = -1;
    virNetworkDefPtr def = NULL;
    virNetworkObjPtr obj = NULL;
    virCommandPtr cmd = NULL;
    char *pidfile = NULL;
    dnsmasqContext *dctx = NULL;

    if (!(def = virNetworkDefParseFile(inxml)))
        goto fail;

    if (!(obj = virNetworkObjNew()))
        goto fail;

    virNetworkObjSetDef(obj, def);

    dctx = dnsmasqContextNew(def->name, "/var/lib/libvirt/dnsmasq");

    if (dctx == NULL)
        goto fail;

    if (networkDnsmasqConfContents(obj, pidfile, &actual, dctx, caps) < 0)
        goto fail;

    /* Any changes to this function ^^ should be reflected here too. */
#ifndef __linux__
    char * tmp;

    if (!(tmp = virStringReplace(actual,
                                 "except-interface=lo0\n",
                                 "except-interface=lo\n")))
        goto fail;
    VIR_FREE(actual);
    actual = tmp;
    tmp = NULL;
#endif

    if (virTestCompareToFile(actual, outconf) < 0)
        goto fail;

    ret = 0;

 fail:
    VIR_FREE(actual);
    VIR_FREE(pidfile);
    virCommandFree(cmd);
    virNetworkObjEndAPI(&obj);
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
    char *outconf = NULL;

    if (virAsprintf(&inxml, "%s/networkxml2confdata/%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&outconf, "%s/networkxml2confdata/%s.conf",
                    abs_srcdir, info->name) < 0) {
        goto cleanup;
    }

    result = testCompareXMLToConfFiles(inxml, outconf, info->caps);

 cleanup:
    VIR_FREE(inxml);
    VIR_FREE(outconf);

    return result;
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

#define DO_TEST(xname, xcaps)                                        \
    do {                                                             \
        static testInfo info;                                        \
                                                                     \
        info.name = xname;                                           \
        info.caps = xcaps;                                           \
        if (virTestRun("Network XML-2-Conf " xname,                  \
                       testCompareXMLToConfHelper, &info) < 0) {     \
            ret = -1;                                                \
        }                                                            \
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
    DO_TEST("dhcp6-network", dhcpv6);
    DO_TEST("dhcp6-nat-network", dhcpv6);
    DO_TEST("dhcp6host-routed-network", dhcpv6);
    DO_TEST("ptr-domains-auto", dhcpv6);

    virObjectUnref(dhcpv6);
    virObjectUnref(full);
    virObjectUnref(restricted);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
