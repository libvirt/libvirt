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
#include "command.h"
#include "memory.h"
#include "network/bridge_driver.h"

static int testCompareXMLToArgvFiles(const char *inxml, const char *outargv) {
    char *inXmlData = NULL;
    char *outArgvData = NULL;
    char *actual = NULL;
    int ret = -1;
    virNetworkDefPtr dev = NULL;
    virNetworkObjPtr obj = NULL;
    virCommandPtr cmd = NULL;
    char *pidfile = NULL;
    dnsmasqContext *dctx = NULL;

    if (virtTestLoadFile(inxml, &inXmlData) < 0)
        goto fail;

    if (virtTestLoadFile(outargv, &outArgvData) < 0)
        goto fail;

    if (!(dev = virNetworkDefParseString(inXmlData)))
        goto fail;

    if (VIR_ALLOC(obj) < 0)
        goto fail;

    obj->def = dev;
    dctx = dnsmasqContextNew(dev->name, "/var/lib/libvirt/dnsmasq");

    if (dctx == NULL)
        goto fail;

    if (networkBuildDhcpDaemonCommandLine(obj, &cmd, pidfile, dctx) < 0)
        goto fail;

    if (!(actual = virCommandToString(cmd)))
        goto fail;

    if (STRNEQ(outArgvData, actual)) {
        virtTestDifference(stderr, outArgvData, actual);
        goto fail;
    }

    ret = 0;

 fail:
    free(inXmlData);
    free(outArgvData);
    free(actual);
    VIR_FREE(pidfile);
    virCommandFree(cmd);
    virNetworkObjFree(obj);
    dnsmasqContextFree(dctx);
    return ret;
}

static int
testCompareXMLToArgvHelper(const void *data)
{
    int result = -1;
    char *inxml = NULL;
    char *outxml = NULL;

    if (virAsprintf(&inxml, "%s/networkxml2argvdata/%s.xml",
                    abs_srcdir, (const char*)data) < 0 ||
        virAsprintf(&outxml, "%s/networkxml2argvdata/%s.argv",
                    abs_srcdir, (const char*)data) < 0) {
        goto cleanup;
    }

    result = testCompareXMLToArgvFiles(inxml, outxml);

cleanup:
    free(inxml);
    free(outxml);

    return result;
}

static char *
testDnsmasqLeaseFileName(const char *netname)
{
    char *leasefile;

    virAsprintf(&leasefile, "/var/lib/libvirt/dnsmasq/%s.leases",
                netname);

    return leasefile;
}

static int
mymain(void)
{
    int ret = 0;

    networkDnsmasqLeaseFileName = testDnsmasqLeaseFileName;

#define DO_TEST(name) \
    if (virtTestRun("Network XML-2-Argv " name, \
                    1, testCompareXMLToArgvHelper, (name)) < 0) \
        ret = -1

    DO_TEST("isolated-network");
    DO_TEST("routed-network");
    DO_TEST("nat-network");
    DO_TEST("netboot-network");
    DO_TEST("netboot-proxy-network");
    DO_TEST("nat-network-dns-txt-record");
    DO_TEST("nat-network-dns-hosts");

    return (ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

VIRT_TEST_MAIN(mymain)
