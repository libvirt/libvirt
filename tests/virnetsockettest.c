/*
 * Copyright (C) 2011 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <stdlib.h>
#include <signal.h>
#ifdef HAVE_IFADDRS_H
# include <ifaddrs.h>
#endif
#include <netdb.h>

#include "testutils.h"
#include "util.h"
#include "virterror_internal.h"
#include "memory.h"
#include "logging.h"
#include "virfile.h"

#include "rpc/virnetsocket.h"

#define VIR_FROM_THIS VIR_FROM_RPC

#if HAVE_IFADDRS_H
# define BASE_PORT 5672

static int
checkProtocols(bool *hasIPv4, bool *hasIPv6,
               int *freePort)
{
    struct ifaddrs *ifaddr = NULL, *ifa;
    struct addrinfo hints;
    struct addrinfo *ai = NULL;
    struct sockaddr_in in4;
    struct sockaddr_in6 in6;
    int s4 = -1, s6 = -1;
    int i;
    int ret = -1;

    memset(&hints, 0, sizeof(hints));

    *hasIPv4 = *hasIPv6 = false;
    *freePort = 0;

    if (getifaddrs(&ifaddr) < 0)
        goto cleanup;

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET)
            *hasIPv4 = true;
        if (ifa->ifa_addr->sa_family == AF_INET6)
            *hasIPv6 = true;
    }

    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo("::1", "5672", &hints, &ai) != 0)
        *hasIPv6 = false;

    freeaddrinfo(ai);

    VIR_DEBUG("Protocols: v4 %d v6 %d\n", *hasIPv4, *hasIPv6);

    freeifaddrs(ifaddr);

    for (i = 0 ; i < 50 ; i++) {
        int only = 1;
        if ((s4 = socket(AF_INET, SOCK_STREAM, 0)) < 0)
            goto cleanup;

        if ((s6 = socket(AF_INET6, SOCK_STREAM, 0)) < 0)
            goto cleanup;

        if (setsockopt(s6, IPPROTO_IPV6, IPV6_V6ONLY, &only, sizeof(only)) < 0)
            goto cleanup;

        memset(&in4, 0, sizeof(in4));
        memset(&in6, 0, sizeof(in6));

        in4.sin_family = AF_INET;
        in4.sin_port = htons(BASE_PORT + i);
        in4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        in6.sin6_family = AF_INET6;
        in6.sin6_port = htons(BASE_PORT + i);
        in6.sin6_addr = in6addr_loopback;

        if (bind(s4, (struct sockaddr *)&in4, sizeof(in4)) < 0) {
            if (errno == EADDRINUSE) {
                VIR_FORCE_CLOSE(s4);
                VIR_FORCE_CLOSE(s6);
                continue;
            }
            goto cleanup;
        }
        if (bind(s6, (struct sockaddr *)&in6, sizeof(in6)) < 0) {
            if (errno == EADDRINUSE) {
                VIR_FORCE_CLOSE(s4);
                VIR_FORCE_CLOSE(s6);
                continue;
            }
            goto cleanup;
        }

        *freePort = BASE_PORT + i;
        break;
    }

    VIR_DEBUG("Choose port %d\n", *freePort);

    ret = 0;

cleanup:
    VIR_FORCE_CLOSE(s4);
    VIR_FORCE_CLOSE(s6);
    return ret;
}


struct testTCPData {
    const char *lnode;
    int port;
    const char *cnode;
};

static int testSocketTCPAccept(const void *opaque)
{
    virNetSocketPtr *lsock = NULL; /* Listen socket */
    size_t nlsock = 0, i;
    virNetSocketPtr ssock = NULL; /* Server socket */
    virNetSocketPtr csock = NULL; /* Client socket */
    const struct testTCPData *data = opaque;
    int ret = -1;
    char portstr[100];

    snprintf(portstr, sizeof(portstr), "%d", data->port);

    if (virNetSocketNewListenTCP(data->lnode, portstr, &lsock, &nlsock) < 0)
        goto cleanup;

    for (i = 0 ; i < nlsock ; i++) {
        if (virNetSocketListen(lsock[i], 0) < 0)
            goto cleanup;
    }

    if (virNetSocketNewConnectTCP(data->cnode, portstr, &csock) < 0)
        goto cleanup;

    virNetSocketFree(csock);

    for (i = 0 ; i < nlsock ; i++) {
        if (virNetSocketAccept(lsock[i], &ssock) != -1 && ssock) {
            char c = 'a';
            if (virNetSocketWrite(ssock, &c, 1) != -1 &&
                virNetSocketRead(ssock, &c, 1) != -1) {
                VIR_DEBUG("Unexpected client socket present");
                goto cleanup;
            }
        }
        virNetSocketFree(ssock);
        ssock = NULL;
    }

    ret = 0;

cleanup:
    virNetSocketFree(ssock);
    for (i = 0 ; i < nlsock ; i++)
        virNetSocketFree(lsock[i]);
    VIR_FREE(lsock);
    return ret;
}
#endif


#ifndef WIN32
static int testSocketUNIXAccept(const void *data ATTRIBUTE_UNUSED)
{
    virNetSocketPtr lsock = NULL; /* Listen socket */
    virNetSocketPtr ssock = NULL; /* Server socket */
    virNetSocketPtr csock = NULL; /* Client socket */
    int ret = -1;

    char *path;
    char *tmpdir;
    char template[] = "/tmp/libvirt_XXXXXX";

    tmpdir = mkdtemp(template);
    if (tmpdir == NULL) {
        VIR_WARN("Failed to create temporary directory");
        goto cleanup;
    }
    if (virAsprintf(&path, "%s/test.sock", tmpdir) < 0)
        goto cleanup;

    if (virNetSocketNewListenUNIX(path, 0700, -1, getgid(), &lsock) < 0)
        goto cleanup;

    if (virNetSocketListen(lsock, 0) < 0)
        goto cleanup;

    if (virNetSocketNewConnectUNIX(path, false, NULL, &csock) < 0)
        goto cleanup;

    virNetSocketFree(csock);

    if (virNetSocketAccept(lsock, &ssock) != -1) {
        char c = 'a';
        if (virNetSocketWrite(ssock, &c, 1) != -1) {
            VIR_DEBUG("Unexpected client socket present");
            goto cleanup;
        }
    }

    ret = 0;

cleanup:
    VIR_FREE(path);
    virNetSocketFree(lsock);
    virNetSocketFree(ssock);
    if (tmpdir)
        rmdir(tmpdir);
    return ret;
}


static int testSocketUNIXAddrs(const void *data ATTRIBUTE_UNUSED)
{
    virNetSocketPtr lsock = NULL; /* Listen socket */
    virNetSocketPtr ssock = NULL; /* Server socket */
    virNetSocketPtr csock = NULL; /* Client socket */
    int ret = -1;

    char *path;
    char *tmpdir;
    char template[] = "/tmp/libvirt_XXXXXX";

    tmpdir = mkdtemp(template);
    if (tmpdir == NULL) {
        VIR_WARN("Failed to create temporary directory");
        goto cleanup;
    }
    if (virAsprintf(&path, "%s/test.sock", tmpdir) < 0)
        goto cleanup;

    if (virNetSocketNewListenUNIX(path, 0700, -1, getgid(), &lsock) < 0)
        goto cleanup;

    if (STRNEQ(virNetSocketLocalAddrString(lsock), "127.0.0.1;0")) {
        VIR_DEBUG("Unexpected local address");
        goto cleanup;
    }

    if (virNetSocketRemoteAddrString(lsock) != NULL) {
        VIR_DEBUG("Unexpected remote address");
        goto cleanup;
    }

    if (virNetSocketListen(lsock, 0) < 0)
        goto cleanup;

    if (virNetSocketNewConnectUNIX(path, false, NULL, &csock) < 0)
        goto cleanup;

    if (STRNEQ(virNetSocketLocalAddrString(csock), "127.0.0.1;0")) {
        VIR_DEBUG("Unexpected local address");
        goto cleanup;
    }

    if (STRNEQ(virNetSocketRemoteAddrString(csock), "127.0.0.1;0")) {
        VIR_DEBUG("Unexpected local address");
        goto cleanup;
    }


    if (virNetSocketAccept(lsock, &ssock) < 0) {
        VIR_DEBUG("Unexpected client socket missing");
        goto cleanup;
    }


    if (STRNEQ(virNetSocketLocalAddrString(ssock), "127.0.0.1;0")) {
        VIR_DEBUG("Unexpected local address");
        goto cleanup;
    }

    if (STRNEQ(virNetSocketRemoteAddrString(ssock), "127.0.0.1;0")) {
        VIR_DEBUG("Unexpected local address");
        goto cleanup;
    }


    ret = 0;

cleanup:
    VIR_FREE(path);
    virNetSocketFree(lsock);
    virNetSocketFree(ssock);
    virNetSocketFree(csock);
    if (tmpdir)
        rmdir(tmpdir);
    return ret;
}

static int testSocketCommandNormal(const void *data ATTRIBUTE_UNUSED)
{
    virNetSocketPtr csock = NULL; /* Client socket */
    char buf[100];
    size_t i;
    int ret = -1;
    virCommandPtr cmd = virCommandNewArgList("/bin/cat", "/dev/zero", NULL);
    virCommandAddEnvPassCommon(cmd);

    if (virNetSocketNewConnectCommand(cmd, &csock) < 0)
        goto cleanup;

    virNetSocketSetBlocking(csock, true);

    if (virNetSocketRead(csock, buf, sizeof(buf)) < 0)
        goto cleanup;

    for (i = 0 ; i < sizeof(buf) ; i++)
        if (buf[i] != '\0')
            goto cleanup;

    ret = 0;

cleanup:
    virNetSocketFree(csock);
    return ret;
}

static int testSocketCommandFail(const void *data ATTRIBUTE_UNUSED)
{
    virNetSocketPtr csock = NULL; /* Client socket */
    char buf[100];
    int ret = -1;
    virCommandPtr cmd = virCommandNewArgList("/bin/cat", "/dev/does-not-exist", NULL);
    virCommandAddEnvPassCommon(cmd);

    if (virNetSocketNewConnectCommand(cmd, &csock) < 0)
        goto cleanup;

    virNetSocketSetBlocking(csock, true);

    if (virNetSocketRead(csock, buf, sizeof(buf)) == 0)
        goto cleanup;

    ret = 0;

cleanup:
    virNetSocketFree(csock);
    return ret;
}

struct testSSHData {
    const char *nodename;
    const char *service;
    const char *binary;
    const char *username;
    bool noTTY;
    bool noVerify;
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
    virNetSocketPtr csock = NULL; /* Client socket */
    int ret = -1;
    char buf[1024];

    if (virNetSocketNewConnectSSH(data->nodename,
                                  data->service,
                                  data->binary,
                                  data->username,
                                  data->noTTY,
                                  data->noVerify,
                                  data->netcat,
                                  data->keyfile,
                                  data->path,
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

        if (!STREQ(buf, data->expectOut)) {
            virtTestDifference(stderr, data->expectOut, buf);
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
    virNetSocketFree(csock);
    return ret;
}

#endif


static int
mymain(void)
{
    int ret = 0;
#ifdef HAVE_IFADDRS_H
    bool hasIPv4, hasIPv6;
    int freePort;
#endif

    signal(SIGPIPE, SIG_IGN);

#ifdef HAVE_IFADDRS_H
    if (checkProtocols(&hasIPv4, &hasIPv6, &freePort) < 0) {
        fprintf(stderr, "Cannot identify IPv4/6 availability\n");
        return EXIT_FAILURE;
    }

    if (hasIPv4) {
        struct testTCPData tcpData = { "127.0.0.1", freePort, "127.0.0.1" };
        if (virtTestRun("Socket TCP/IPv4 Accept", 1, testSocketTCPAccept, &tcpData) < 0)
            ret = -1;
    }
    if (hasIPv6) {
        struct testTCPData tcpData = { "::1", freePort, "::1" };
        if (virtTestRun("Socket TCP/IPv6 Accept", 1, testSocketTCPAccept, &tcpData) < 0)
            ret = -1;
    }
    if (hasIPv6 && hasIPv4) {
        struct testTCPData tcpData = { NULL, freePort, "127.0.0.1" };
        if (virtTestRun("Socket TCP/IPv4+IPv6 Accept", 1, testSocketTCPAccept, &tcpData) < 0)
            ret = -1;

        tcpData.cnode = "::1";
        if (virtTestRun("Socket TCP/IPv4+IPv6 Accept", 1, testSocketTCPAccept, &tcpData) < 0)
            ret = -1;
    }
#endif

#ifndef WIN32
    if (virtTestRun("Socket UNIX Accept", 1, testSocketUNIXAccept, NULL) < 0)
        ret = -1;

    if (virtTestRun("Socket UNIX Addrs", 1, testSocketUNIXAddrs, NULL) < 0)
        ret = -1;

    if (virtTestRun("Socket External Command /dev/zero", 1, testSocketCommandNormal, NULL) < 0)
        ret = -1;
    if (virtTestRun("Socket External Command /dev/does-not-exist", 1, testSocketCommandFail, NULL) < 0)
        ret = -1;

    struct testSSHData sshData1 = {
        .nodename = "somehost",
        .path = "/tmp/socket",
        .expectOut = "somehost sh -c 'if 'nc' -q 2>&1 | grep \"requires an argument\" >/dev/null 2>&1; then "
                                         "ARG=-q0;"
                                     "else "
                                         "ARG=;"
                                     "fi;"
                                     "'nc' $ARG -U /tmp/socket'\n",
    };
    if (virtTestRun("SSH test 1", 1, testSocketSSH, &sshData1) < 0)
        ret = -1;

    struct testSSHData sshData2 = {
        .nodename = "somehost",
        .service = "9000",
        .username = "fred",
        .netcat = "netcat",
        .noTTY = true,
        .noVerify = false,
        .path = "/tmp/socket",
        .expectOut = "-p 9000 -l fred -T -o BatchMode=yes -e none somehost sh -c '"
                     "if 'netcat' -q 2>&1 | grep \"requires an argument\" >/dev/null 2>&1; then "
                         "ARG=-q0;"
                     "else "
                         "ARG=;"
                     "fi;"
                     "'netcat' $ARG -U /tmp/socket'\n",
    };
    if (virtTestRun("SSH test 2", 1, testSocketSSH, &sshData2) < 0)
        ret = -1;

    struct testSSHData sshData3 = {
        .nodename = "somehost",
        .service = "9000",
        .username = "fred",
        .netcat = "netcat",
        .noTTY = false,
        .noVerify = true,
        .path = "/tmp/socket",
        .expectOut = "-p 9000 -l fred -o StrictHostKeyChecking=no somehost sh -c '"
                     "if 'netcat' -q 2>&1 | grep \"requires an argument\" >/dev/null 2>&1; then "
                         "ARG=-q0;"
                     "else "
                         "ARG=;"
                     "fi;"
                     "'netcat' $ARG -U /tmp/socket'\n",
    };
    if (virtTestRun("SSH test 3", 1, testSocketSSH, &sshData3) < 0)
        ret = -1;

    struct testSSHData sshData4 = {
        .nodename = "nosuchhost",
        .path = "/tmp/socket",
        .failConnect = true,
    };
    if (virtTestRun("SSH test 4", 1, testSocketSSH, &sshData4) < 0)
        ret = -1;

    struct testSSHData sshData5 = {
        .nodename = "crashyhost",
        .path = "/tmp/socket",
        .expectOut = "crashyhost sh -c "
                     "'if 'nc' -q 2>&1 | grep \"requires an argument\" >/dev/null 2>&1; then "
                         "ARG=-q0;"
                     "else "
                         "ARG=;"
                     "fi;"
                     "'nc' $ARG -U /tmp/socket'\n",
        .dieEarly = true,
    };
    if (virtTestRun("SSH test 5", 1, testSocketSSH, &sshData5) < 0)
        ret = -1;

    struct testSSHData sshData6 = {
        .nodename = "example.com",
        .path = "/tmp/socket",
        .keyfile = "/root/.ssh/example_key",
        .noVerify = true,
        .expectOut = "-i /root/.ssh/example_key -o StrictHostKeyChecking=no example.com sh -c '"
                     "if 'nc' -q 2>&1 | grep \"requires an argument\" >/dev/null 2>&1; then "
                         "ARG=-q0;"
                     "else "
                         "ARG=;"
                     "fi;"
                     "'nc' $ARG -U /tmp/socket'\n",
    };
    if (virtTestRun("SSH test 6", 1, testSocketSSH, &sshData6) < 0)
        ret = -1;

    struct testSSHData sshData7 = {
        .nodename = "somehost",
        .netcat = "nc -4",
        .path = "/tmp/socket",
        .expectOut = "somehost sh -c 'if ''nc -4'' -q 2>&1 | grep \"requires an argument\" >/dev/null 2>&1; then "
                                         "ARG=-q0;"
                                     "else "
                                         "ARG=;"
                                     "fi;"
                                     "''nc -4'' $ARG -U /tmp/socket'\n",
    };
    if (virtTestRun("SSH test 7", 1, testSocketSSH, &sshData7) < 0)
        ret = -1;

#endif

    return ret==0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
