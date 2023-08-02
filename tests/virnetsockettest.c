/*
 * Copyright (C) 2011, 2014 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <signal.h>
#include <unistd.h>
#ifdef WITH_IFADDRS_H
# include <ifaddrs.h>
#endif

#include "testutils.h"
#include "virerror.h"
#include "viralloc.h"
#include "virlog.h"
#include "virfile.h"

#include "rpc/virnetsocket.h"
#include "rpc/virnetclient.h"

#define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("tests.netsockettest");

#if WITH_IFADDRS_H
# define BASE_PORT 5672

static int
checkProtocols(bool *hasIPv4, bool *hasIPv6,
               int *freePort)
{
    size_t i;

    *freePort = 0;
    if (virNetSocketCheckProtocols(hasIPv4, hasIPv6) < 0)
        return -1;

    for (i = 0; i < 50; i++) {
        struct sockaddr_in in4 = { 0 };
        struct sockaddr_in6 in6 = { 0 };
        VIR_AUTOCLOSE s4 = -1;
        VIR_AUTOCLOSE s6 = -1;

        if (*hasIPv4) {
            if ((s4 = socket(AF_INET, SOCK_STREAM, 0)) < 0)
                return -1;
        }

        if (*hasIPv6) {
            int only = 1;

            if ((s6 = socket(AF_INET6, SOCK_STREAM, 0)) < 0)
                return -1;

            if (setsockopt(s6, IPPROTO_IPV6, IPV6_V6ONLY, &only, sizeof(only)) < 0)
                return -1;
        }

        in4.sin_family = AF_INET;
        in4.sin_port = htons(BASE_PORT + i);
        in4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        in6.sin6_family = AF_INET6;
        in6.sin6_port = htons(BASE_PORT + i);
        in6.sin6_addr = in6addr_loopback;

        if (*hasIPv4) {
            if (bind(s4, (struct sockaddr *)&in4, sizeof(in4)) < 0) {
                if (errno == EADDRINUSE) {
                    continue;
                }
                return -1;
            }
        }

        if (*hasIPv6) {
            if (bind(s6, (struct sockaddr *)&in6, sizeof(in6)) < 0) {
                if (errno == EADDRINUSE) {
                    continue;
                }
                return -1;
            }
        }

        *freePort = BASE_PORT + i;
        break;
    }

    VIR_DEBUG("Choose port %d", *freePort);

    return 0;
}

struct testClientData {
    const char *path;
    const char *cnode;
    const char *portstr;
};

static void
testSocketClient(void *opaque)
{
    struct testClientData *data = opaque;
    char c;
    virNetSocket *csock = NULL;

    if (data->path) {
        if (virNetSocketNewConnectUNIX(data->path,
                                       NULL, &csock) < 0)
            return;
    } else {
        if (virNetSocketNewConnectTCP(data->cnode, data->portstr,
                                      AF_UNSPEC,
                                      &csock) < 0)
            return;
    }

    virNetSocketSetBlocking(csock, true);

    if (virNetSocketRead(csock, &c, 1) != 1) {
        VIR_DEBUG("Cannot read from server");
        goto done;
    }
    if (virNetSocketWrite(csock, &c, 1) != 1) {
        VIR_DEBUG("Cannot write to server");
        goto done;
    }

 done:
    virObjectUnref(csock);
}


static void
testSocketIncoming(virNetSocket *sock,
                   int events G_GNUC_UNUSED,
                   void *opaque)
{
    virNetSocket **retsock = opaque;
    VIR_DEBUG("Incoming sock=%p events=%d", sock, events);
    *retsock = sock;
}


struct testSocketData {
    const char *lnode;
    int port;
    const char *cnode;
};


static int
testSocketAccept(const void *opaque)
{
    virNetSocket **lsock = NULL; /* Listen socket */
    size_t nlsock = 0, i;
    virNetSocket *ssock = NULL; /* Server socket */
    virNetSocket *rsock = NULL; /* Incoming client socket */
    const struct testSocketData *data = opaque;
    int ret = -1;
    char portstr[100];
    char *tmpdir = NULL;
    g_autofree char *path = NULL;
    char template[] = "/tmp/libvirt_XXXXXX";
    virThread th;
    struct testClientData cdata = { 0 };
    bool goodsock = false;
    char a = 'a';
    char b = '\0';

    if (!data) {
        virNetSocket *usock;
        tmpdir = g_mkdtemp(template);
        if (tmpdir == NULL) {
            VIR_WARN("Failed to create temporary directory");
            goto cleanup;
        }
        path = g_strdup_printf("%s/test.sock", tmpdir);

        if (virNetSocketNewListenUNIX(path, 0700, -1, getegid(), &usock) < 0)
            goto cleanup;

        lsock = g_new0(virNetSocket *, 1);
        lsock[0] = usock;
        nlsock = 1;

        cdata.path = path;
    } else {
        g_snprintf(portstr, sizeof(portstr), "%d", data->port);
        if (virNetSocketNewListenTCP(data->lnode, portstr,
                                     AF_UNSPEC,
                                     &lsock, &nlsock) < 0)
            goto cleanup;

        cdata.cnode = data->cnode;
        cdata.portstr = portstr;
    }

    for (i = 0; i < nlsock; i++) {
        if (virNetSocketListen(lsock[i], 0) < 0)
            goto cleanup;

        if (virNetSocketAddIOCallback(lsock[i],
                                      VIR_EVENT_HANDLE_READABLE,
                                      testSocketIncoming,
                                      &rsock,
                                      NULL) < 0) {
            goto cleanup;
        }
    }

    if (virThreadCreate(&th, true,
                        testSocketClient,
                        &cdata) < 0)
        goto cleanup;

    while (rsock == NULL) {
        if (virEventRunDefaultImpl() < 0)
            break;
    }

    for (i = 0; i < nlsock; i++) {
        if (lsock[i] == rsock) {
            goodsock = true;
            break;
        }
    }

    if (!goodsock) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Unexpected server socket seen");
        goto join;
    }

    if (virNetSocketAccept(rsock, &ssock) < 0)
        goto join;

    if (!ssock) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Client went away unexpectedly");
        goto join;
    }

    virNetSocketSetBlocking(ssock, true);

    if (virNetSocketWrite(ssock, &a, 1) < 0 ||
        virNetSocketRead(ssock, &b, 1) < 0) {
        goto join;
    }

    if (a != b) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Bad data received '%x' != '%x'", a, b);
        goto join;
    }

    g_clear_pointer(&ssock, virObjectUnref);

    ret = 0;

 join:
    virThreadJoin(&th);

 cleanup:
    virObjectUnref(ssock);
    for (i = 0; i < nlsock; i++) {
        virNetSocketRemoveIOCallback(lsock[i]);
        virNetSocketClose(lsock[i]);
        virObjectUnref(lsock[i]);
    }
    VIR_FREE(lsock);
    if (tmpdir)
        rmdir(tmpdir);
    return ret;
}
#endif


#ifndef WIN32
static int testSocketUNIXAddrs(const void *data G_GNUC_UNUSED)
{
    virNetSocket *lsock = NULL; /* Listen socket */
    virNetSocket *ssock = NULL; /* Server socket */
    virNetSocket *csock = NULL; /* Client socket */
    int ret = -1;

    g_autofree char *path = NULL;
    char *tmpdir;
    char template[] = "/tmp/libvirt_XXXXXX";

    tmpdir = g_mkdtemp(template);
    if (tmpdir == NULL) {
        VIR_WARN("Failed to create temporary directory");
        goto cleanup;
    }
    path = g_strdup_printf("%s/test.sock", tmpdir);

    if (virNetSocketNewListenUNIX(path, 0700, -1, getegid(), &lsock) < 0)
        goto cleanup;

    if (STRNEQ(virNetSocketLocalAddrStringSASL(lsock), "127.0.0.1;0")) {
        VIR_DEBUG("Unexpected local address");
        goto cleanup;
    }

    if (virNetSocketRemoteAddrStringSASL(lsock) != NULL) {
        VIR_DEBUG("Unexpected remote address");
        goto cleanup;
    }

    if (virNetSocketListen(lsock, 0) < 0)
        goto cleanup;

    if (virNetSocketNewConnectUNIX(path, NULL, &csock) < 0)
        goto cleanup;

    if (STRNEQ(virNetSocketLocalAddrStringSASL(csock), "127.0.0.1;0")) {
        VIR_DEBUG("Unexpected local address");
        goto cleanup;
    }

    if (STRNEQ(virNetSocketRemoteAddrStringSASL(csock), "127.0.0.1;0")) {
        VIR_DEBUG("Unexpected remote address");
        goto cleanup;
    }

    if (STRNEQ(virNetSocketRemoteAddrStringURI(csock), "127.0.0.1:0")) {
        VIR_DEBUG("Unexpected remote address");
        goto cleanup;
    }


    if (virNetSocketAccept(lsock, &ssock) < 0) {
        VIR_DEBUG("Unexpected client socket missing");
        goto cleanup;
    }


    if (STRNEQ(virNetSocketLocalAddrStringSASL(ssock), "127.0.0.1;0")) {
        VIR_DEBUG("Unexpected local address");
        goto cleanup;
    }

    if (STRNEQ(virNetSocketRemoteAddrStringSASL(ssock), "127.0.0.1;0")) {
        VIR_DEBUG("Unexpected remote address");
        goto cleanup;
    }

    if (STRNEQ(virNetSocketRemoteAddrStringURI(ssock), "127.0.0.1:0")) {
        VIR_DEBUG("Unexpected remote address");
        goto cleanup;
    }


    ret = 0;

 cleanup:
    virObjectUnref(lsock);
    virObjectUnref(ssock);
    virObjectUnref(csock);
    if (tmpdir)
        rmdir(tmpdir);
    return ret;
}

static int testSocketCommandNormal(const void *data G_GNUC_UNUSED)
{
    virNetSocket *csock = NULL; /* Client socket */
    char buf[100];
    size_t i;
    int ret = -1;
    g_autoptr(virCommand) cmd = virCommandNewArgList("/bin/cat", "/dev/zero", NULL);

    virCommandAddEnvPassCommon(cmd);

    if (virNetSocketNewConnectCommand(cmd, &csock) < 0)
        goto cleanup;

    virNetSocketSetBlocking(csock, true);

    if (virNetSocketRead(csock, buf, sizeof(buf)) < 0)
        goto cleanup;

    for (i = 0; i < sizeof(buf); i++)
        if (buf[i] != '\0')
            goto cleanup;

    ret = 0;

 cleanup:
    virObjectUnref(csock);
    return ret;
}

static int testSocketCommandFail(const void *data G_GNUC_UNUSED)
{
    virNetSocket *csock = NULL; /* Client socket */
    char buf[100];
    int ret = -1;
    g_autoptr(virCommand) cmd = virCommandNewArgList("/bin/cat", "/dev/does-not-exist", NULL);

    virCommandAddEnvPassCommon(cmd);

    if (virNetSocketNewConnectCommand(cmd, &csock) < 0)
        goto cleanup;

    virNetSocketSetBlocking(csock, true);

    if (virNetSocketRead(csock, buf, sizeof(buf)) == 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virObjectUnref(csock);
    return ret;
}

struct testSSHData {
    const char *nodename;
    const char *service;
    const char *binary;
    const char *username;
    bool noTTY;
    bool noVerify;
    virNetClientProxy proxy;
    const char *netcat;
    const char *keyfile;
    const char *path;

    const char *expectOut;
    bool failConnect;
    bool dieEarly;
};

static int testSocketSSH(const void *opaque)
{
    const struct testSSHData *data = opaque;
    virNetSocket *csock = NULL; /* Client socket */
    int ret = -1;
    char buf[1024];
    g_autofree char *command = virNetClientSSHHelperCommand(data->proxy,
                                                            data->netcat,
                                                            data->path,
                                                            "qemu:///session",
                                                            true);

    if (virNetSocketNewConnectSSH(data->nodename,
                                  data->service,
                                  data->binary,
                                  data->username,
                                  data->noTTY,
                                  data->noVerify,
                                  data->keyfile,
                                  command,
                                  &csock) < 0)
        goto cleanup;

    virNetSocketSetBlocking(csock, true);

    if (data->failConnect) {
        if (virNetSocketRead(csock, buf, sizeof(buf)-1) >= 0) {
            VIR_DEBUG("Expected connect failure, but got some socket data");
            goto cleanup;
        }
    } else {
        ssize_t rv;
        if ((rv = virNetSocketRead(csock, buf, sizeof(buf)-1)) < 0) {
            VIR_DEBUG("Didn't get any socket data");
            goto cleanup;
        }
        buf[rv] = '\0';

        if (virTestCompareToString(data->expectOut, buf) < 0) {
            goto cleanup;
        }

        if (data->dieEarly &&
            virNetSocketRead(csock, buf, sizeof(buf)-1) >= 0) {
            VIR_DEBUG("Got too much socket data");
            goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    virObjectUnref(csock);
    return ret;
}

#endif


static int
mymain(void)
{
    int ret = 0;
#ifdef WITH_IFADDRS_H
    bool hasIPv4, hasIPv6;
    int freePort;
#endif

#ifndef WIN32
    signal(SIGPIPE, SIG_IGN);
#endif /* WIN32 */

    virEventRegisterDefaultImpl();

#ifdef WITH_IFADDRS_H
    if (checkProtocols(&hasIPv4, &hasIPv6, &freePort) < 0) {
        fprintf(stderr, "Cannot identify IPv4/6 availability\n");
        return EXIT_FAILURE;
    }

    if (hasIPv4) {
        struct testSocketData tcpData = { "127.0.0.1", freePort, "127.0.0.1" };
        if (virTestRun("Socket TCP/IPv4 Accept", testSocketAccept, &tcpData) < 0)
            ret = -1;
    }
    if (hasIPv6) {
        struct testSocketData tcpData = { "::1", freePort, "::1" };
        if (virTestRun("Socket TCP/IPv6 Accept", testSocketAccept, &tcpData) < 0)
            ret = -1;
    }
    if (hasIPv6 && hasIPv4) {
        struct testSocketData tcpData = { NULL, freePort, "127.0.0.1" };
        if (virTestRun("Socket TCP/IPv4+IPv6 Accept", testSocketAccept, &tcpData) < 0)
            ret = -1;

        tcpData.cnode = "::1";
        if (virTestRun("Socket TCP/IPv4+IPv6 Accept", testSocketAccept, &tcpData) < 0)
            ret = -1;
    }
#endif

#ifndef WIN32
    if (virTestRun("Socket UNIX Accept", testSocketAccept, NULL) < 0)
        ret = -1;

    if (virTestRun("Socket UNIX Addrs", testSocketUNIXAddrs, NULL) < 0)
        ret = -1;

    if (virTestRun("Socket External Command /dev/zero", testSocketCommandNormal, NULL) < 0)
        ret = -1;
    if (virTestRun("Socket External Command /dev/does-not-exist", testSocketCommandFail, NULL) < 0)
        ret = -1;

    VIR_WARNINGS_NO_DECLARATION_AFTER_STATEMENT
    struct testSSHData sshData1 = {
        .nodename = "somehost",
        .path = "/tmp/socket",
        .netcat = "nc",
        .expectOut = "-T -e none -- somehost sh -c '"
                         "if 'nc' -q 2>&1 | grep \"requires an argument\" >/dev/null 2>&1; then "
                             "ARG=-q0;"
                         "else "
                             "ARG=;"
                         "fi;"
                         "'nc' $ARG -U /tmp/socket"
                     "'\n",
    };
    if (virTestRun("SSH test 1", testSocketSSH, &sshData1) < 0)
        ret = -1;

    struct testSSHData sshData2 = {
        .nodename = "somehost",
        .service = "9000",
        .username = "fred",
        .netcat = "netcat",
        .noTTY = true,
        .noVerify = false,
        .path = "/tmp/socket",
        .expectOut = "-p 9000 -l fred -T -e none -o BatchMode=yes -- somehost sh -c '"
                         "if 'netcat' -q 2>&1 | grep \"requires an argument\" >/dev/null 2>&1; then "
                             "ARG=-q0;"
                         "else "
                             "ARG=;"
                         "fi;"
                         "'netcat' $ARG -U /tmp/socket"
                     "'\n",
    };
    if (virTestRun("SSH test 2", testSocketSSH, &sshData2) < 0)
        ret = -1;

    struct testSSHData sshData3 = {
        .nodename = "somehost",
        .service = "9000",
        .username = "fred",
        .netcat = "netcat",
        .noTTY = false,
        .noVerify = true,
        .path = "/tmp/socket",
        .expectOut = "-p 9000 -l fred -T -e none -o StrictHostKeyChecking=no -- somehost sh -c '"
                         "if 'netcat' -q 2>&1 | grep \"requires an argument\" >/dev/null 2>&1; then "
                             "ARG=-q0;"
                         "else "
                             "ARG=;"
                         "fi;"
                         "'netcat' $ARG -U /tmp/socket"
                     "'\n",
    };
    if (virTestRun("SSH test 3", testSocketSSH, &sshData3) < 0)
        ret = -1;

    struct testSSHData sshData4 = {
        .nodename = "nosuchhost",
        .path = "/tmp/socket",
        .failConnect = true,
    };
    if (virTestRun("SSH test 4", testSocketSSH, &sshData4) < 0)
        ret = -1;

    struct testSSHData sshData5 = {
        .nodename = "crashyhost",
        .path = "/tmp/socket",
        .netcat = "nc",
        .expectOut = "-T -e none -- crashyhost sh -c '"
                         "if 'nc' -q 2>&1 | grep \"requires an argument\" >/dev/null 2>&1; then "
                             "ARG=-q0;"
                         "else "
                             "ARG=;"
                         "fi;"
                         "'nc' $ARG -U /tmp/socket"
                     "'\n",
        .dieEarly = true,
    };
    if (virTestRun("SSH test 5", testSocketSSH, &sshData5) < 0)
        ret = -1;

    struct testSSHData sshData6 = {
        .nodename = "example.com",
        .path = "/tmp/socket",
        .netcat = "nc",
        .keyfile = "/root/.ssh/example_key",
        .noVerify = true,
        .expectOut = "-i /root/.ssh/example_key -T -e none -o StrictHostKeyChecking=no -- example.com sh -c '"
                         "if 'nc' -q 2>&1 | grep \"requires an argument\" >/dev/null 2>&1; then "
                             "ARG=-q0;"
                         "else "
                             "ARG=;"
                         "fi;"
                         "'nc' $ARG -U /tmp/socket"
                     "'\n",
    };
    if (virTestRun("SSH test 6", testSocketSSH, &sshData6) < 0)
        ret = -1;

    struct testSSHData sshData7 = {
        .nodename = "somehost",
        .netcat = "n c",
        .path = "/tmp/socket",
        .expectOut = "-T -e none -- somehost sh -c '"
                         "if '''\\''n c'\\'''' -q 2>&1 | grep \"requires an argument\" >/dev/null 2>&1; then "
                             "ARG=-q0;"
                         "else "
                             "ARG=;"
                         "fi;"
                         "'''\\''n c'\\'''' $ARG -U /tmp/socket"
                     "'\n",
    };
    if (virTestRun("SSH test 7", testSocketSSH, &sshData7) < 0)
        ret = -1;

    struct testSSHData sshData8 = {
        .nodename = "somehost",
        .netcat = "n'c",
        .path = "/tmp/socket",
        .expectOut = "-T -e none -- somehost sh -c '"
                         "if '''\\''n'\\''\\'\\'''\\''c'\\'''' -q 2>&1 | grep \"requires an argument\" >/dev/null 2>&1; then "
                             "ARG=-q0;"
                         "else "
                             "ARG=;"
                         "fi;"
                         "'''\\''n'\\''\\'\\'''\\''c'\\'''' $ARG -U /tmp/socket"
                     "'\n",
    };
    if (virTestRun("SSH test 8", testSocketSSH, &sshData8) < 0)
        ret = -1;

    struct testSSHData sshData9 = {
        .nodename = "somehost",
        .netcat = "n\"c",
        .path = "/tmp/socket",
        .expectOut = "-T -e none -- somehost sh -c '"
                         "if '''\\''n\"c'\\'''' -q 2>&1 | grep \"requires an argument\" >/dev/null 2>&1; then "
                             "ARG=-q0;"
                         "else "
                             "ARG=;"
                         "fi;"
                         "'''\\''n\"c'\\'''' $ARG -U /tmp/socket"
                     "'\n",
    };
    if (virTestRun("SSH test 9", testSocketSSH, &sshData9) < 0)
        ret = -1;

    struct testSSHData sshData10 = {
        .nodename = "somehost",
        .path = "/tmp/socket",
        .expectOut = "-T -e none -- somehost sh -c '"
                         "which virt-ssh-helper 1>/dev/null 2>&1; "
                         "if test $? = 0; then "
                         "    virt-ssh-helper -r 'qemu:///session'; "
                         "else"
                         "    if 'nc' -q 2>&1 | grep \"requires an argument\" >/dev/null 2>&1; then "
                                 "ARG=-q0;"
                             "else "
                                 "ARG=;"
                             "fi;"
                             "'nc' $ARG -U /tmp/socket; "
                         "fi"
                     "'\n"
    };
    if (virTestRun("SSH test 10", testSocketSSH, &sshData10) < 0)
        ret = -1;

    struct testSSHData sshData11 = {
        .nodename = "somehost",
        .proxy = VIR_NET_CLIENT_PROXY_NATIVE,
        .expectOut = "-T -e none -- somehost sh -c '"
                         "virt-ssh-helper -r 'qemu:///session'"
                     "'\n"
    };
    if (virTestRun("SSH test 11", testSocketSSH, &sshData11) < 0)
        ret = -1;
    VIR_WARNINGS_RESET
#endif

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
