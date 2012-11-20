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
    size_t token_start, token_end;
    size_t buf_len, rest_len;
    const size_t token_len = strlen(token);
    const size_t replacement_len = strlen(replacement);
    const int diff = replacement_len - token_len;

    buf_len = rest_len = strlen(*buf) + 1;
    token_end = 0;
    for (;;) {
        char *match = strstr(*buf + token_end, token);
        if (match == NULL)
            break;
        token_start = match - *buf;
        rest_len -= token_start + token_len - token_end;
        token_end = token_start + token_len;
        buf_len += diff;
        if (diff > 0)
            if (VIR_REALLOC_N(*buf, buf_len) < 0)
                return -1;
        if (diff != 0)
            memmove(*buf + token_end + diff, *buf + token_end, rest_len);
        memcpy(*buf + token_start, replacement, replacement_len);
        token_end += diff;
    }
    /* if diff < 0, we could shrink the buffer here... */
    return 0;
}

static int
testCompareXMLToArgvFiles(const char *inxml, const char *outargv, dnsmasqCapsPtr caps)
{
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

    if (networkBuildDhcpDaemonCommandLine(obj, &cmd, pidfile, dctx, caps) < 0)
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

typedef struct {
    const char *name;
    dnsmasqCapsPtr caps;
} testInfo;

static int
testCompareXMLToArgvHelper(const void *data)
{
    int result = -1;
    const testInfo *info = data;
    char *inxml = NULL;
    char *outxml = NULL;

    if (virAsprintf(&inxml, "%s/networkxml2argvdata/%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&outxml, "%s/networkxml2argvdata/%s.argv",
                    abs_srcdir, info->name) < 0) {
        goto cleanup;
    }

    result = testCompareXMLToArgvFiles(inxml, outxml, info->caps);

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
    dnsmasqCapsPtr restricted
        = dnsmasqCapsNewFromBuffer("Dnsmasq version 2.48", DNSMASQ);
    dnsmasqCapsPtr full
        = dnsmasqCapsNewFromBuffer("Dnsmasq version 2.63\n--bind-dynamic", DNSMASQ);

    networkDnsmasqLeaseFileName = testDnsmasqLeaseFileName;

#define DO_TEST(xname, xcaps)                                        \
    do {                                                             \
        static testInfo info;                                        \
                                                                     \
        info.name = xname;                                           \
        info.caps = xcaps;                                           \
        if (virtTestRun("Network XML-2-Argv " xname,                 \
                        1, testCompareXMLToArgvHelper, &info) < 0) { \
            ret = -1;                                                \
        }                                                            \
    } while (0)

    DO_TEST("isolated-network", restricted);
    DO_TEST("netboot-network", restricted);
    DO_TEST("netboot-proxy-network", restricted);
    DO_TEST("nat-network-dns-srv-record-minimal", restricted);
    DO_TEST("routed-network", full);
    DO_TEST("nat-network", full);
    DO_TEST("nat-network-dns-txt-record", full);
    DO_TEST("nat-network-dns-srv-record", full);
    DO_TEST("nat-network-dns-hosts", full);

    return ret==0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
