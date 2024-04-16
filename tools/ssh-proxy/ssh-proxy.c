/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * For given domain and port create a VSOCK socket and pass it onto STDOUT.
 */

#include <config.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>

#include "internal.h"
#include "virsocket.h"
#include "virstring.h"
#include "virfile.h"
#include "datatypes.h"
#include "virgettext.h"
#include "virxml.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#define SYS_ERROR(...) \
do { \
    int err = errno; \
    fprintf(stderr, "ERROR %s:%d : ", __FUNCTION__, __LINE__); \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, " : %s\n", g_strerror(err)); \
    fprintf(stderr, "\n"); \
} while (0)

#define ERROR(...) \
do { \
    fprintf(stderr, "ERROR %s:%d : ", __FUNCTION__, __LINE__); \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n"); \
} while (0)

#define HOSTNAME_PREFIX "qemu"
#define QEMU_SYSTEM_URI "qemu:///system"
#define QEMU_SESSION_URI "qemu:///session"

static void
dummyErrorHandler(void *opaque G_GNUC_UNUSED,
                  virErrorPtr error G_GNUC_UNUSED)
{

}

static void
printUsage(const char *argv0)
{
    const char *progname;

    if (!(progname = strrchr(argv0, '/')))
        progname = argv0;
    else
        progname++;

    printf(_("\n"
             "Usage:\n"
             "%1$s hostname port\n"
             "\n"
             "Hostname should be in one of the following forms:\n"
             "\n"
             "  qemu:system/$domname\t\tfor domains under qemu:///system\n"
             "  qemu:session/$domname\t\tfor domains under qemu:///session\n"
             "  qemu/$domname\t\t\ttries looking up $domname under system followed by session URI\n"),
           progname);
}

static int
parseArgs(int argc,
          char *argv[],
          const char **uriRet,
          const char **domname,
          unsigned int *port)
{
    const char *uri = NULL;

    /* Accepted URIs are:
     *
     *   qemu/virtualMachine
     *   qemu:system/virtualMachine
     *   qemu:session/virtualMachine
     *
     * The last two result in system or session connection URIs passed to
     * virConnectOpen(), the first one tries to find the machine under system
     * connection first, followed by session connection.
     */
    if (argc != 3 ||
        !(uri = STRSKIP(argv[1], HOSTNAME_PREFIX))) {
        ERROR(_("Bad usage"));
        printUsage(argv[0]);
        return -1;
    }

    if (*uri == ':') {
        const char *tmp = NULL;

        uri++;
        if ((tmp = STRSKIP(uri, "system"))) {
            *uriRet = QEMU_SYSTEM_URI;
        } else if ((tmp = STRSKIP(uri, "session"))) {
            *uriRet = QEMU_SESSION_URI;
        } else {
            ERROR(_("Unknown connection URI: '%1$s'"), uri);
            printUsage(argv[0]);
            return -1;
        }

        uri = tmp;
    } else {
        *uriRet = NULL;
    }

    if (!(*domname = STRSKIP(uri, "/")) ||
        **domname == '\0') {
        ERROR(_("Bad usage"));
        printUsage(argv[0]);
        return -1;
    }

    if (virStrToLong_ui(argv[2], NULL, 10, port) < 0) {
        ERROR(_("Unable to parse port: %1$s"), argv[2]);
        printUsage(argv[0]);
        return -1;
    }

    return 0;
}


#define VSOCK_CID_XPATH "/domain/devices/vsock/cid"

static int
extractCID(virDomainPtr dom,
           unsigned long long *cidRet)
{
    g_autofree char *domxml = NULL;
    g_autoptr(xmlDoc) doc = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    g_autofree xmlNodePtr *nodes = NULL;
    int nnodes = 0;
    size_t i;

    if (!(domxml = virDomainGetXMLDesc(dom, 0)))
        return -1;

    doc = virXMLParseStringCtxtWithIndent(domxml, "domain", &ctxt);
    if (!doc)
        return -1;

    if ((nnodes = virXPathNodeSet(VSOCK_CID_XPATH, ctxt, &nodes)) < 0) {
        return -1;
    }

    for (i = 0; i < nnodes; i++) {
        unsigned long long cid;

        if (virXMLPropULongLong(nodes[i], "address", 10, 0, &cid) > 0) {
            *cidRet = cid;
            return 0;
        }
    }

    return -1;
}

#undef VSOCK_CID_XPATH


static int
lookupDomainAndFetchCID(const char *uri,
                        const char *domname,
                        unsigned long long *cid)
{
    g_autoptr(virConnect) conn = NULL;
    g_autoptr(virDomain) dom = NULL;

    if (!(conn = virConnectOpenReadOnly(uri)))
        return -1;

    dom = virDomainLookupByName(conn, domname);
    if (!dom)
        dom = virDomainLookupByUUIDString(conn, domname);
    if (!dom) {
        int id;

        if (virStrToLong_i(domname, NULL, 10, &id) >= 0)
            dom = virDomainLookupByID(conn, id);
    }
    if (!dom)
        return -1;

    return extractCID(dom, cid);
}


static int
findDomain(const char *domname,
           unsigned long long *cid)
{
    const char *uris[] = {QEMU_SYSTEM_URI, QEMU_SESSION_URI};
    const uid_t userid = geteuid();
    size_t i;

    for (i = 0; i < G_N_ELEMENTS(uris); i++) {
        if (userid == 0 &&
            STREQ(uris[i], "qemu:///session")) {
            continue;
        }

        if (lookupDomainAndFetchCID(uris[i], domname, cid) >= 0)
            return 0;
    }

    return -1;
}


static int
processVsock(const char *uri,
             const char *domname,
             unsigned int port)
{
    struct sockaddr_vm sa = {
        .svm_family = AF_VSOCK,
        .svm_port = port,
    };
    VIR_AUTOCLOSE fd = -1;
    unsigned long long cid = -1;

    if (uri) {
        lookupDomainAndFetchCID(uri, domname, &cid);
    } else {
        findDomain(domname, &cid);
    }

    if (cid == -1) {
        ERROR(_("No usable vsock found"));
        return -1;
    }

    sa.svm_cid = cid;

    fd = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        SYS_ERROR(_("Failed to allocate AF_VSOCK socket"));
        return -1;
    }

    if (connect(fd, (const struct sockaddr *)&sa, sizeof(sa)) < 0) {
        SYS_ERROR(_("Failed to connect to vsock (cid=%1$llu port=%2$u)"),
                  cid, port);
        return -1;
    }

    /* OpenSSH wants us to send a single byte along with the file descriptor,
     * hence do so. */
    if (virSocketSendFD(STDOUT_FILENO, fd) < 0) {
        SYS_ERROR(_("Failed to send file descriptor %1$d"), fd);
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    const char *uri = NULL;
    const char *domname = NULL;
    unsigned int port;

    if (virGettextInitialize() < 0)
        return EXIT_FAILURE;

    if (virInitialize() < 0) {
        ERROR(_("Failed to initialize libvirt"));
        return EXIT_FAILURE;
    }

    virSetErrorFunc(NULL, dummyErrorHandler);

    if (parseArgs(argc, argv, &uri, &domname, &port) < 0)
        return EXIT_FAILURE;

    if (processVsock(uri, domname, port) < 0)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}
