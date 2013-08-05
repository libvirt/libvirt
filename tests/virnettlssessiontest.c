/*
 * Copyright (C) 2011-2012 Red Hat, Inc.
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

#include <stdlib.h>
#include <fcntl.h>
#include <sys/socket.h>

#include "testutils.h"
#include "virnettlshelpers.h"
#include "virutil.h"
#include "virerror.h"
#include "viralloc.h"
#include "virlog.h"
#include "virfile.h"
#include "vircommand.h"
#include "virsocketaddr.h"

#if !defined WIN32 && HAVE_LIBTASN1_H && LIBGNUTLS_VERSION_NUMBER >= 0x020600

# define VIR_FROM_THIS VIR_FROM_RPC

struct testTLSSessionData {
    struct testTLSCertReq careq;
    struct testTLSCertReq othercareq;
    struct testTLSCertReq serverreq;
    struct testTLSCertReq clientreq;
    bool expectServerFail;
    bool expectClientFail;
    const char *hostname;
    const char *const* wildcards;
};


static ssize_t testWrite(const char *buf, size_t len, void *opaque)
{
    int *fd = opaque;

    return write(*fd, buf, len);
}

static ssize_t testRead(char *buf, size_t len, void *opaque)
{
    int *fd = opaque;

    return read(*fd, buf, len);
}

/*
 * This tests validation checking of peer certificates
 *
 * This is replicating the checks that are done for an
 * active TLS session after handshake completes. To
 * simulate that we create our TLS contexts, skipping
 * sanity checks. When then get a socketpair, and
 * initiate a TLS session across them. Finally do
 * do actual cert validation tests
 */
static int testTLSSessionInit(const void *opaque)
{
    struct testTLSSessionData *data = (struct testTLSSessionData *)opaque;
    virNetTLSContextPtr clientCtxt = NULL;
    virNetTLSContextPtr serverCtxt = NULL;
    virNetTLSSessionPtr clientSess = NULL;
    virNetTLSSessionPtr serverSess = NULL;
    int ret = -1;
    int channel[2];
    bool clientShake = false;
    bool serverShake = false;


    /* We'll use this for our fake client-server connection */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, channel) < 0)
        abort();

    /*
     * We have an evil loop to do the handshake in a single
     * thread, so we need these non-blocking to avoid deadlock
     * of ourselves
     */
    ignore_value(virSetNonBlock(channel[0]));
    ignore_value(virSetNonBlock(channel[1]));


    /* Generate all the certs we need for this test */
    testTLSGenerateCert(&data->careq);
    data->serverreq.cacrt = data->careq.crt;
    testTLSGenerateCert(&data->serverreq);

    if (data->othercareq.filename) {
        testTLSGenerateCert(&data->othercareq);
        data->clientreq.cacrt = data->othercareq.crt;
    } else {
        data->clientreq.cacrt = data->careq.crt;
    }
    testTLSGenerateCert(&data->clientreq);


    /* We skip initial sanity checks here because we
     * want to make sure that problems are being
     * detected at the TLS session validation stage
     */
    serverCtxt = virNetTLSContextNewServer(data->careq.filename,
                                           NULL,
                                           data->serverreq.filename,
                                           keyfile,
                                           data->wildcards,
                                           false,
                                           true);

    clientCtxt = virNetTLSContextNewClient(data->othercareq.filename ?
                                           data->othercareq.filename :
                                           data->careq.filename,
                                           NULL,
                                           data->clientreq.filename,
                                           keyfile,
                                           false,
                                           true);

    if (!serverCtxt) {
        VIR_WARN("Unexpected failure loading %s against %s",
                 data->careq.filename, data->serverreq.filename);
        goto cleanup;
    }
    if (!clientCtxt) {
        VIR_WARN("Unexpected failure loading %s against %s",
                 data->othercareq.filename ? data->othercareq.filename :
                 data->careq.filename, data->clientreq.filename);
        goto cleanup;
    }


    /* Now the real part of the test, setup the sessions */
    serverSess = virNetTLSSessionNew(serverCtxt, NULL);
    clientSess = virNetTLSSessionNew(clientCtxt, data->hostname);

    if (!serverSess) {
        VIR_WARN("Unexpected failure using %s against %s",
                 data->careq.filename, data->serverreq.filename);
        goto cleanup;
    }
    if (!clientSess) {
        VIR_WARN("Unexpected failure using %s against %s",
                 data->othercareq.filename ? data->othercareq.filename :
                 data->careq.filename, data->clientreq.filename);
        goto cleanup;
    }

    /* For handshake to work, we need to set the I/O callbacks
     * to read/write over the socketpair
     */
    virNetTLSSessionSetIOCallbacks(serverSess, testWrite, testRead, &channel[0]);
    virNetTLSSessionSetIOCallbacks(clientSess, testWrite, testRead, &channel[1]);

    /*
     * Finally we loop around & around doing handshake on each
     * session until we get an error, or the handshake completes.
     * This relies on the socketpair being nonblocking to avoid
     * deadlocking ourselves upon handshake
     */
    do {
        int rv;
        if (!serverShake) {
            rv = virNetTLSSessionHandshake(serverSess);
            if (rv < 0)
                goto cleanup;
            if (rv == VIR_NET_TLS_HANDSHAKE_COMPLETE)
                serverShake = true;
        }
        if (!clientShake) {
            rv = virNetTLSSessionHandshake(clientSess);
            if (rv < 0)
                goto cleanup;
            if (rv == VIR_NET_TLS_HANDSHAKE_COMPLETE)
                clientShake = true;
        }
    } while (!clientShake && !serverShake);


    /* Finally make sure the server validation does what
     * we were expecting
     */
    if (virNetTLSContextCheckCertificate(serverCtxt,
                                         serverSess) < 0) {
        if (!data->expectServerFail) {
            VIR_WARN("Unexpected server cert check fail");
            goto cleanup;
        } else {
            VIR_DEBUG("Got expected server cert fail");
        }
    } else {
        if (data->expectServerFail) {
            VIR_WARN("Expected server cert check fail");
            goto cleanup;
        } else {
            VIR_DEBUG("Not unexpected server cert fail");
        }
    }

    /*
     * And the same for the client validation check
     */
    if (virNetTLSContextCheckCertificate(clientCtxt,
                                         clientSess) < 0) {
        if (!data->expectClientFail) {
            VIR_WARN("Unexpected client cert check fail");
            goto cleanup;
        } else {
            VIR_DEBUG("Got expected client cert fail");
        }
    } else {
        if (data->expectClientFail) {
            VIR_WARN("Expected client cert check fail");
            goto cleanup;
        } else {
            VIR_DEBUG("Not unexpected client cert fail");
        }
    }

    ret = 0;

cleanup:
    virObjectUnref(serverCtxt);
    virObjectUnref(clientCtxt);
    virObjectUnref(serverSess);
    virObjectUnref(clientSess);

    testTLSDiscardCert(&data->careq);
    if (data->othercareq.filename)
        testTLSDiscardCert(&data->othercareq);
    testTLSDiscardCert(&data->clientreq);
    testTLSDiscardCert(&data->serverreq);

    VIR_FORCE_CLOSE(channel[0]);
    VIR_FORCE_CLOSE(channel[1]);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;

    testTLSInit();

# define DO_SESS_TEST(_caReq, _serverReq, _clientReq, _expectServerFail,\
                      _expectClientFail, _hostname, _wildcards)         \
    do {                                                                \
        static struct testTLSSessionData data;                          \
        static struct testTLSCertReq other;                             \
        data.careq = _caReq;                                            \
        data.othercareq = other;                                        \
        data.serverreq = _serverReq;                                    \
        data.clientreq = _clientReq;                                    \
        data.expectServerFail = _expectServerFail;                      \
        data.expectClientFail = _expectClientFail;                      \
        data.hostname = _hostname;                                      \
        data.wildcards = _wildcards;                                    \
        if (virtTestRun("TLS Session", 1, testTLSSessionInit, &data) < 0) \
            ret = -1;                                                   \
    } while (0)

# define DO_SESS_TEST_EXT(_caReq, _othercaReq, _serverReq, _clientReq,  \
                          _expectServerFail, _expectClientFail,         \
                          _hostname, _wildcards)                        \
    do {                                                                \
        static struct testTLSSessionData data;                          \
        data.careq = _caReq;                                            \
        data.othercareq = _othercaReq;                                  \
        data.serverreq = _serverReq;                                    \
        data.clientreq = _clientReq;                                    \
        data.expectServerFail = _expectServerFail;                      \
        data.expectClientFail = _expectClientFail;                      \
        data.hostname = _hostname;                                      \
        data.wildcards = _wildcards;                                    \
        if (virtTestRun("TLS Session", 1, testTLSSessionInit, &data) < 0) \
            ret = -1;                                                   \
    } while (0)

    /* A perfect CA, perfect client & perfect server */

    /* Basic:CA:critical */
    static struct testTLSCertReq cacertreq = {
        NULL, NULL, "cacert.pem", "UK",
        "libvirt CA", NULL, NULL, NULL, NULL,
        true, true, true,
        true, true, GNUTLS_KEY_KEY_CERT_SIGN,
        false, false, NULL, NULL,
        0, 0,
    };
    static struct testTLSCertReq cacert1req = {
        NULL, NULL, "cacert1.pem", "UK",
        "libvirt CA 1", NULL, NULL, NULL, NULL,
        true, true, true,
        false, false, 0,
        false, false, NULL, NULL,
        0, 0,
    };
    static struct testTLSCertReq servercertreq = {
        NULL, NULL, "servercert.pem", "UK",
        "libvirt.org", NULL, NULL, NULL, NULL,
        true, true, false,
        true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT,
        true, true, GNUTLS_KP_TLS_WWW_SERVER, NULL,
        0, 0,
    };
    static struct testTLSCertReq clientcertreq = {
        NULL, NULL, "clientcert.pem", "UK",
        "libvirt", NULL, NULL, NULL, NULL,
        true, true, false,
        true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT,
        true, true, GNUTLS_KP_TLS_WWW_CLIENT, NULL,
        0, 0,
    };

    DO_SESS_TEST(cacertreq, servercertreq, clientcertreq, false, false, "libvirt.org", NULL);
    DO_SESS_TEST_EXT(cacertreq, cacert1req, servercertreq, clientcertreq, true, true, "libvirt.org", NULL);

    /* When an altname is set, the CN is ignored, so it must be duplicated
     * as an altname for it to match */
    static struct testTLSCertReq servercertalt1req = {
        NULL, NULL, "servercert.pem", "UK",
        "libvirt.org", "www.libvirt.org", "libvirt.org", "192.168.122.1", "fec0::dead:beaf",
        true, true, false,
        true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT,
        true, true, GNUTLS_KP_TLS_WWW_SERVER, NULL,
        0, 0,
    };
    /* This intentionally doesn't replicate */
    static struct testTLSCertReq servercertalt2req = {
        NULL, NULL, "servercert.pem", "UK",
        "libvirt.org", "www.libvirt.org", "wiki.libvirt.org", "192.168.122.1", "fec0::dead:beaf",
        true, true, false,
        true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT,
        true, true, GNUTLS_KP_TLS_WWW_SERVER, NULL,
        0, 0,
    };

    DO_SESS_TEST(cacertreq, servercertalt1req, clientcertreq, false, false, "libvirt.org", NULL);
    DO_SESS_TEST(cacertreq, servercertalt1req, clientcertreq, false, false, "www.libvirt.org", NULL);
    DO_SESS_TEST(cacertreq, servercertalt1req, clientcertreq, false, true, "wiki.libvirt.org", NULL);

    DO_SESS_TEST(cacertreq, servercertalt2req, clientcertreq, false, true, "libvirt.org", NULL);
    DO_SESS_TEST(cacertreq, servercertalt2req, clientcertreq, false, false, "www.libvirt.org", NULL);
    DO_SESS_TEST(cacertreq, servercertalt2req, clientcertreq, false, false, "wiki.libvirt.org", NULL);

    const char *const wildcards1[] = {
        "C=UK,CN=dogfood",
        NULL,
    };
    const char *const wildcards2[] = {
        "C=UK,CN=libvirt",
        NULL,
    };
    const char *const wildcards3[] = {
        "C=UK,CN=dogfood",
        "C=UK,CN=libvirt",
        NULL,
    };
    const char *const wildcards4[] = {
        "C=UK,CN=libvirtstuff",
        NULL,
    };
    const char *const wildcards5[] = {
        "C=UK,CN=libvirt*",
        NULL,
    };
    const char *const wildcards6[] = {
        "C=UK,CN=*virt*",
        NULL,
    };

    DO_SESS_TEST(cacertreq, servercertreq, clientcertreq, true, false, "libvirt.org", wildcards1);
    DO_SESS_TEST(cacertreq, servercertreq, clientcertreq, false, false, "libvirt.org", wildcards2);
    DO_SESS_TEST(cacertreq, servercertreq, clientcertreq, false, false, "libvirt.org", wildcards3);
    DO_SESS_TEST(cacertreq, servercertreq, clientcertreq, true, false, "libvirt.org", wildcards4);
    DO_SESS_TEST(cacertreq, servercertreq, clientcertreq, false, false, "libvirt.org", wildcards5);
    DO_SESS_TEST(cacertreq, servercertreq, clientcertreq, false, false, "libvirt.org", wildcards6);

    testTLSCleanup();

    return ret==0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)

#else

int
main(void)
{
    return EXIT_AM_SKIP;
}

#endif
