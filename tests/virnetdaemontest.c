/*
 * Copyright (C) 2015 Red Hat, Inc.
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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "testutils.h"
#include "virerror.h"
#include "rpc/virnetdaemon.h"

#define VIR_FROM_THIS VIR_FROM_RPC

#if defined(HAVE_SOCKETPAIR) && defined(WITH_YAJL)
static virNetServerPtr
testCreateServer(const char *server_name, const char *host, int family)
{
    virNetServerPtr srv = NULL;
    virNetServerServicePtr svc1 = NULL, svc2 = NULL;
    virNetServerClientPtr cln1 = NULL, cln2 = NULL;
    virNetSocketPtr sk1 = NULL, sk2 = NULL;
    int fdclient[2];
    const char *mdns_entry = NULL;
    const char *mdns_group = NULL;

# ifdef WITH_AVAHI
    mdns_entry = "libvirt-ro";
    mdns_group = "libvirtTest";
# endif

    if (socketpair(PF_UNIX, SOCK_STREAM, 0, fdclient) < 0) {
        virReportSystemError(errno, "%s",
                             "Cannot create socket pair");
        goto cleanup;
    }

    if (!(srv = virNetServerNew(server_name, 1,
                                10, 50, 5, 100, 10,
                                120, 5,
                                mdns_group,
                                NULL,
                                NULL,
                                NULL,
                                NULL)))
        goto error;

    if (!(svc1 = virNetServerServiceNewTCP(host,
                                           NULL,
                                           family,
                                           VIR_NET_SERVER_SERVICE_AUTH_NONE,
# ifdef WITH_GNUTLS
                                           NULL,
# endif
                                           true,
                                           5,
                                           2)))
        goto error;

    if (!(svc2 = virNetServerServiceNewTCP(host,
                                           NULL,
                                           family,
                                           VIR_NET_SERVER_SERVICE_AUTH_POLKIT,
# ifdef WITH_GNUTLS
                                           NULL,
# endif
                                           false,
                                           25,
                                           5)))
        goto error;

    if (virNetServerAddService(srv, svc1, mdns_entry) < 0)
        goto error;
    if (virNetServerAddService(srv, svc2, mdns_entry) < 0)
        goto error;

    if (virNetSocketNewConnectSockFD(fdclient[0], &sk1) < 0)
        goto error;
    if (virNetSocketNewConnectSockFD(fdclient[1], &sk2) < 0)
        goto error;

    if (!(cln1 = virNetServerClientNew(virNetServerNextClientID(srv),
                                       sk1,
                                       VIR_NET_SERVER_SERVICE_AUTH_SASL,
                                       true,
                                       15,
# ifdef WITH_GNUTLS
                                       NULL,
# endif
                                       NULL, NULL, NULL, NULL)))
        goto error;

    if (!(cln2 = virNetServerClientNew(virNetServerNextClientID(srv),
                                       sk2,
                                       VIR_NET_SERVER_SERVICE_AUTH_POLKIT,
                                       true,
                                       66,
# ifdef WITH_GNUTLS
                                       NULL,
# endif
                                       NULL, NULL, NULL, NULL)))
        goto error;

    if (virNetServerAddClient(srv, cln1) < 0)
        goto error;

    if (virNetServerAddClient(srv, cln2) < 0)
        goto error;

 cleanup:
    if (!srv)
        virDispatchError(NULL);
    virObjectUnref(cln1);
    virObjectUnref(cln2);
    virObjectUnref(svc1);
    virObjectUnref(svc2);
    virObjectUnref(sk1);
    virObjectUnref(sk2);
    return srv;

 error:
    virObjectUnref(srv);
    srv = NULL;
    goto cleanup;
}

static char *testGenerateJSON(const char *server_name)
{
    virNetDaemonPtr dmn = NULL;
    virNetServerPtr srv = NULL;
    virJSONValuePtr json = NULL;
    char *jsonstr = NULL;
    bool has_ipv4, has_ipv6;

    /* Our pre-saved JSON file is created so that each service
     * only has one socket. If we let libvirt bind to IPv4 and
     * IPv6 we might end up with two sockets, so force one or
     * the other based on what's available on thehost
     */
    if (virNetSocketCheckProtocols(&has_ipv4,
                                   &has_ipv6) < 0)
        return NULL;

    if (!has_ipv4 && !has_ipv6)
        return NULL;

    if (!(srv = testCreateServer(server_name,
                                 has_ipv4 ? "127.0.0.1" : "::1",
                                 has_ipv4 ? AF_INET : AF_INET6)))
        goto cleanup;

    if (!(dmn = virNetDaemonNew()))
        goto cleanup;

    if (virNetDaemonAddServer(dmn, srv) < 0)
        goto cleanup;

    if (!(json = virNetDaemonPreExecRestart(dmn)))
        goto cleanup;

    if (!(jsonstr = virJSONValueToString(json, true)))
        goto cleanup;

    fprintf(stderr, "%s\n", jsonstr);
 cleanup:
    virNetServerClose(srv);
    virObjectUnref(srv);
    virObjectUnref(dmn);
    virJSONValueFree(json);
    if (!jsonstr)
        virDispatchError(NULL);
    return jsonstr;
}


struct testExecRestartData {
    const char *jsonfile;
    const char **serverNames;
    int nservers;
    bool pass;
};

static int testExecRestart(const void *opaque)
{
    size_t i;
    int ret = -1;
    virNetDaemonPtr dmn = NULL;
    virNetServerPtr srv = NULL;
    const struct testExecRestartData *data = opaque;
    char *infile = NULL, *outfile = NULL;
    char *injsonstr = NULL, *outjsonstr = NULL;
    virJSONValuePtr injson = NULL, outjson = NULL;
    int fdclient[2] = { -1, -1 }, fdserver[2] = { -1, -1 };

    if (socketpair(PF_UNIX, SOCK_STREAM, 0, fdclient) < 0) {
        virReportSystemError(errno, "%s",
                             "Cannot create socket pair");
        goto cleanup;
    }

    if (socketpair(PF_UNIX, SOCK_STREAM, 0, fdserver) < 0) {
        virReportSystemError(errno, "%s",
                             "Cannot create socket pair");
        goto cleanup;
    }

    /* We're blindly assuming the test case isn't using
     * fds 100->103 for something else, which is probably
     * fairly reasonable in general
     */
    dup2(fdserver[0], 100);
    dup2(fdserver[1], 101);
    dup2(fdclient[0], 102);
    dup2(fdclient[1], 103);

    if (virAsprintf(&infile, "%s/virnetdaemondata/input-data-%s.json",
                    abs_srcdir, data->jsonfile) < 0)
        goto cleanup;

    if (virAsprintf(&outfile, "%s/virnetdaemondata/output-data-%s.json",
                    abs_srcdir, data->jsonfile) < 0)
        goto cleanup;

    if (virFileReadAll(infile, 8192, &injsonstr) < 0)
        goto cleanup;

    if (!(injson = virJSONValueFromString(injsonstr)))
        goto cleanup;

    if (!(dmn = virNetDaemonNewPostExecRestart(injson)))
        goto cleanup;

    for (i = 0; i < data->nservers; i++) {
        if (!(srv = virNetDaemonAddServerPostExec(dmn, data->serverNames[i],
                                                  NULL, NULL, NULL,
                                                  NULL, NULL)))
            goto cleanup;
        srv = NULL;
    }

    if (!(outjson = virNetDaemonPreExecRestart(dmn)))
        goto cleanup;

    if (!(outjsonstr = virJSONValueToString(outjson, true)))
        goto cleanup;

    if (virTestCompareToFile(outjsonstr, outfile) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    if (ret < 0) {
        if (!data->pass) {
            VIR_TEST_DEBUG("Got expected error: %s\n",
                           virGetLastErrorMessage());
            virResetLastError();
            ret = 0;
        }
    } else if (!data->pass) {
            VIR_TEST_DEBUG("Test should have failed\n");
            ret = -1;
    }
    VIR_FREE(infile);
    VIR_FREE(outfile);
    VIR_FREE(injsonstr);
    VIR_FREE(outjsonstr);
    virJSONValueFree(injson);
    virJSONValueFree(outjson);
    virObjectUnref(dmn);
    VIR_FORCE_CLOSE(fdserver[0]);
    VIR_FORCE_CLOSE(fdserver[1]);
    VIR_FORCE_CLOSE(fdclient[0]);
    VIR_FORCE_CLOSE(fdclient[1]);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;
    const char *server_names[] = { "testServer0", "testServer1" };

    if (virInitialize() < 0 ||
        virEventRegisterDefaultImpl() < 0) {
        virDispatchError(NULL);
        return EXIT_FAILURE;
    }

    /* Hack to make it easier to generate new JSON files when
     * the RPC classes change. Just set this env var, save
     * the generated JSON, and replace the file descriptor
     * numbers with 100, 101, 102, 103.
     */
    if (getenv("VIR_GENERATE_JSON")) {
        char *json = testGenerateJSON(server_names[0]);
        if (!json)
            return EXIT_FAILURE;

        fprintf(stdout, "%s\n", json);
        VIR_FREE(json);
        return ret;
    }

# define EXEC_RESTART_TEST_FULL(file, nservers, pass)         \
    do {                                                      \
        struct testExecRestartData data = {                   \
            file, server_names, nservers, pass                \
        };                                                    \
        if (virTestRun("ExecRestart " file,                   \
                       testExecRestart, &data) < 0)           \
            ret = -1;                                         \
    } while (0)

# define EXEC_RESTART_TEST(file, N) EXEC_RESTART_TEST_FULL(file, N, true)
# define EXEC_RESTART_TEST_FAIL(file, N) EXEC_RESTART_TEST_FULL(file, N, false)


# ifdef WITH_AVAHI
    EXEC_RESTART_TEST("initial", 1);
# endif
    EXEC_RESTART_TEST("initial-nomdns", 1);
    EXEC_RESTART_TEST("anon-clients", 1);
    EXEC_RESTART_TEST("admin-nomdns", 2);
    EXEC_RESTART_TEST("admin-server-names", 2);
    EXEC_RESTART_TEST("no-keepalive-required", 2);
    EXEC_RESTART_TEST("client-ids", 1);
    EXEC_RESTART_TEST("client-timestamp", 1);
    EXEC_RESTART_TEST_FAIL("anon-clients", 2);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
VIR_TEST_MAIN_PRELOAD(mymain, abs_builddir "/.libs/virnetdaemonmock.so")
#else
static int
mymain(void)
{
    return EXIT_AM_SKIP;
}
VIR_TEST_MAIN(mymain);
#endif
