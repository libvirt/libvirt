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

/* Replace all occurrences of @token in @buf by @replacement and adjust size of
 * @buf accordingly. Returns 0 on success and -1 on out-of-memory errors. */
static int replaceTokens(char **buf, const char *token, const char *replacement) {
    char *token_start, *token_end;
    size_t buf_len, rest_len;
    const size_t token_len = strlen(token);
    const size_t replacement_len = strlen(replacement);
    const int diff = replacement_len - token_len;

    buf_len = rest_len = strlen(*buf) + 1;
    token_end = *buf;
    for (;;) {
        token_start = strstr(token_end, token);
        if (token_start == NULL)
            break;
        rest_len -= token_start + token_len - token_end;
        token_end = token_start + token_len;
        buf_len += diff;
        if (diff > 0)
            if (VIR_REALLOC_N(*buf, buf_len) < 0)
                return -1;
        if (diff != 0)
            memmove(token_end + diff, token_end, rest_len);
        memcpy(token_start, replacement, replacement_len);
        token_end += diff;
    }
    /* if diff < 0, we could shrink the buffer here... */
    return 0;
}

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

    if (replaceTokens(&outArgvData, "@DNSMASQ@", DNSMASQ))
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
    VIR_FREE(inXmlData);
    VIR_FREE(outArgvData);
    VIR_FREE(actual);
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
    VIR_FREE(inxml);
    VIR_FREE(outxml);

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
    DO_TEST("nat-network-dns-srv-record");
    DO_TEST("nat-network-dns-srv-record-minimal");
    DO_TEST("nat-network-dns-hosts");

    return ret==0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
