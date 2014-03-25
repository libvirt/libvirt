/*
 * Copyright (C) 2011-2012, 2014 Red Hat, Inc.
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

VIR_LOG_INIT("tests.nettlssessiontest");

# define KEYFILE "key-sess.pem"

struct testTLSSessionData {
    const char *servercacrt;
    const char *clientcacrt;
    const char *servercrt;
    const char *clientcrt;
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


    /* We skip initial sanity checks here because we
     * want to make sure that problems are being
     * detected at the TLS session validation stage
     */
    serverCtxt = virNetTLSContextNewServer(data->servercacrt,
                                           NULL,
                                           data->servercrt,
                                           KEYFILE,
                                           data->wildcards,
                                           false,
                                           true);

    clientCtxt = virNetTLSContextNewClient(data->clientcacrt,
                                           NULL,
                                           data->clientcrt,
                                           KEYFILE,
                                           false,
                                           true);

    if (!serverCtxt) {
        VIR_WARN("Unexpected failure loading %s against %s",
                 data->servercacrt, data->servercrt);
        goto cleanup;
    }
    if (!clientCtxt) {
        VIR_WARN("Unexpected failure loading %s against %s",
                 data->clientcacrt, data->clientcrt);
        goto cleanup;
    }


    /* Now the real part of the test, setup the sessions */
    serverSess = virNetTLSSessionNew(serverCtxt, NULL);
    clientSess = virNetTLSSessionNew(clientCtxt, data->hostname);

    if (!serverSess) {
        VIR_WARN("Unexpected failure using %s against %s",
                 data->servercacrt, data->servercrt);
        goto cleanup;
    }
    if (!clientSess) {
        VIR_WARN("Unexpected failure using %s against %s",
                 data->clientcacrt, data->clientcrt);
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
            VIR_DEBUG("No unexpected server cert fail");
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
            VIR_DEBUG("No unexpected client cert fail");
        }
    }

    ret = 0;

 cleanup:
    virObjectUnref(serverCtxt);
    virObjectUnref(clientCtxt);
    virObjectUnref(serverSess);
    virObjectUnref(clientSess);

    VIR_FORCE_CLOSE(channel[0]);
    VIR_FORCE_CLOSE(channel[1]);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;

    testTLSInit(KEYFILE);

# define DO_SESS_TEST(_caCrt, _serverCrt, _clientCrt, _expectServerFail, \
                      _expectClientFail, _hostname, _wildcards)         \
    do {                                                                \
        static struct testTLSSessionData data;                          \
        data.servercacrt = _caCrt;                                      \
        data.clientcacrt = _caCrt;                                      \
        data.servercrt = _serverCrt;                                    \
        data.clientcrt = _clientCrt;                                    \
        data.expectServerFail = _expectServerFail;                      \
        data.expectClientFail = _expectClientFail;                      \
        data.hostname = _hostname;                                      \
        data.wildcards = _wildcards;                                    \
        if (virtTestRun("TLS Session " #_serverCrt " + " #_clientCrt,   \
                        testTLSSessionInit, &data) < 0)                 \
            ret = -1;                                                   \
    } while (0)

# define DO_SESS_TEST_EXT(_serverCaCrt, _clientCaCrt, _serverCrt, _clientCrt, \
                          _expectServerFail, _expectClientFail,         \
                          _hostname, _wildcards)                        \
    do {                                                                \
        static struct testTLSSessionData data;                          \
        data.servercacrt = _serverCaCrt;                                \
        data.clientcacrt = _clientCaCrt;                                \
        data.servercrt = _serverCrt;                                    \
        data.clientcrt = _clientCrt;                                    \
        data.expectServerFail = _expectServerFail;                      \
        data.expectClientFail = _expectClientFail;                      \
        data.hostname = _hostname;                                      \
        data.wildcards = _wildcards;                                    \
        if (virtTestRun("TLS Session " #_serverCrt " + " #_clientCrt,   \
                        testTLSSessionInit, &data) < 0)                 \
            ret = -1;                                                   \
    } while (0)

# define TLS_CERT_REQ(varname, cavarname,                               \
                      co, cn, an1, an2, ia1, ia2, bce, bcc, bci,        \
                      kue, kuc, kuv, kpe, kpc, kpo1, kpo2, so, eo)      \
    static struct testTLSCertReq varname = {                            \
        NULL, #varname "-sess.pem",                                     \
        co, cn, an1, an2, ia1, ia2, bce, bcc, bci,                      \
        kue, kuc, kuv, kpe, kpc, kpo1, kpo2, so, so                     \
    };                                                                  \
    testTLSGenerateCert(&varname, cavarname.crt)

# define TLS_ROOT_REQ(varname,                                          \
                      co, cn, an1, an2, ia1, ia2, bce, bcc, bci,        \
                      kue, kuc, kuv, kpe, kpc, kpo1, kpo2, so, eo)      \
    static struct testTLSCertReq varname = {                            \
        NULL, #varname "-sess.pem",                                     \
        co, cn, an1, an2, ia1, ia2, bce, bcc, bci,                      \
        kue, kuc, kuv, kpe, kpc, kpo1, kpo2, so, so                     \
    };                                                                  \
    testTLSGenerateCert(&varname, NULL)

    /* A perfect CA, perfect client & perfect server */

    /* Basic:CA:critical */
    TLS_ROOT_REQ(cacertreq,
                  "UK", "libvirt CA", NULL, NULL, NULL, NULL,
                  true, true, true,
                  true, true, GNUTLS_KEY_KEY_CERT_SIGN,
                  false, false, NULL, NULL,
                  0, 0);

    TLS_ROOT_REQ(altcacertreq,
                 "UK", "libvirt CA 1", NULL, NULL, NULL, NULL,
                 true, true, true,
                 false, false, 0,
                 false, false, NULL, NULL,
                 0, 0);

    TLS_CERT_REQ(servercertreq, cacertreq,
                 "UK", "libvirt.org", NULL, NULL, NULL, NULL,
                 true, true, false,
                 true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT,
                 true, true, GNUTLS_KP_TLS_WWW_SERVER, NULL,
                 0, 0);
    TLS_CERT_REQ(clientcertreq, cacertreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, false,
                 true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT,
                 true, true, GNUTLS_KP_TLS_WWW_CLIENT, NULL,
                 0, 0);

    TLS_CERT_REQ(clientcertaltreq, altcacertreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, false,
                 true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT,
                 true, true, GNUTLS_KP_TLS_WWW_CLIENT, NULL,
                 0, 0);

    DO_SESS_TEST(cacertreq.filename, servercertreq.filename, clientcertreq.filename,
                 false, false, "libvirt.org", NULL);
    DO_SESS_TEST_EXT(cacertreq.filename, altcacertreq.filename, servercertreq.filename,
                     clientcertaltreq.filename, true, true, "libvirt.org", NULL);


    /* When an altname is set, the CN is ignored, so it must be duplicated
     * as an altname for it to match */
    TLS_CERT_REQ(servercertalt1req, cacertreq,
                 "UK", "libvirt.org", "www.libvirt.org", "libvirt.org", "192.168.122.1", "fec0::dead:beaf",
                 true, true, false,
                 true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT,
                 true, true, GNUTLS_KP_TLS_WWW_SERVER, NULL,
                 0, 0);
    /* This intentionally doesn't replicate */
    TLS_CERT_REQ(servercertalt2req, cacertreq,
                 "UK", "libvirt.org", "www.libvirt.org", "wiki.libvirt.org", "192.168.122.1", "fec0::dead:beaf",
                 true, true, false,
                 true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT,
                 true, true, GNUTLS_KP_TLS_WWW_SERVER, NULL,
                 0, 0);

    DO_SESS_TEST(cacertreq.filename, servercertalt1req.filename, clientcertreq.filename,
                 false, false, "libvirt.org", NULL);
    DO_SESS_TEST(cacertreq.filename, servercertalt1req.filename, clientcertreq.filename,
                 false, false, "www.libvirt.org", NULL);
    DO_SESS_TEST(cacertreq.filename, servercertalt1req.filename, clientcertreq.filename,
                 false, true, "wiki.libvirt.org", NULL);

    DO_SESS_TEST(cacertreq.filename, servercertalt2req.filename, clientcertreq.filename,
                 false, true, "libvirt.org", NULL);
    DO_SESS_TEST(cacertreq.filename, servercertalt2req.filename, clientcertreq.filename,
                 false, false, "www.libvirt.org", NULL);
    DO_SESS_TEST(cacertreq.filename, servercertalt2req.filename, clientcertreq.filename,
                 false, false, "wiki.libvirt.org", NULL);

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

    DO_SESS_TEST(cacertreq.filename, servercertreq.filename, clientcertreq.filename,
                 true, false, "libvirt.org", wildcards1);
    DO_SESS_TEST(cacertreq.filename, servercertreq.filename, clientcertreq.filename,
                 false, false, "libvirt.org", wildcards2);
    DO_SESS_TEST(cacertreq.filename, servercertreq.filename, clientcertreq.filename,
                 false, false, "libvirt.org", wildcards3);
    DO_SESS_TEST(cacertreq.filename, servercertreq.filename, clientcertreq.filename,
                 true, false, "libvirt.org", wildcards4);
    DO_SESS_TEST(cacertreq.filename, servercertreq.filename, clientcertreq.filename,
                 false, false, "libvirt.org", wildcards5);
    DO_SESS_TEST(cacertreq.filename, servercertreq.filename, clientcertreq.filename,
                 false, false, "libvirt.org", wildcards6);

    TLS_ROOT_REQ(cacertrootreq,
                 "UK", "libvirt root", NULL, NULL, NULL, NULL,
                 true, true, true,
                 true, true, GNUTLS_KEY_KEY_CERT_SIGN,
                 false, false, NULL, NULL,
                 0, 0);
    TLS_CERT_REQ(cacertlevel1areq, cacertrootreq,
                 "UK", "libvirt level 1a", NULL, NULL, NULL, NULL,
                 true, true, true,
                 true, true, GNUTLS_KEY_KEY_CERT_SIGN,
                 false, false, NULL, NULL,
                 0, 0);
    TLS_CERT_REQ(cacertlevel1breq, cacertrootreq,
                 "UK", "libvirt level 1b", NULL, NULL, NULL, NULL,
                 true, true, true,
                 true, true, GNUTLS_KEY_KEY_CERT_SIGN,
                 false, false, NULL, NULL,
                 0, 0);
    TLS_CERT_REQ(cacertlevel2areq, cacertlevel1areq,
                 "UK", "libvirt level 2a", NULL, NULL, NULL, NULL,
                 true, true, true,
                 true, true, GNUTLS_KEY_KEY_CERT_SIGN,
                 false, false, NULL, NULL,
                 0, 0);
    TLS_CERT_REQ(servercertlevel3areq, cacertlevel2areq,
                 "UK", "libvirt.org", NULL, NULL, NULL, NULL,
                 true, true, false,
                 true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT,
                 true, true, GNUTLS_KP_TLS_WWW_SERVER, NULL,
                 0, 0);
    TLS_CERT_REQ(clientcertlevel2breq, cacertlevel1breq,
                 "UK", "libvirt client level 2b", NULL, NULL, NULL, NULL,
                 true, true, false,
                 true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT,
                 true, true, GNUTLS_KP_TLS_WWW_CLIENT, NULL,
                 0, 0);

    gnutls_x509_crt_t certchain[] = {
        cacertrootreq.crt,
        cacertlevel1areq.crt,
        cacertlevel1breq.crt,
        cacertlevel2areq.crt,
    };

    testTLSWriteCertChain("cacertchain-sess.pem",
                          certchain,
                          ARRAY_CARDINALITY(certchain));

    DO_SESS_TEST("cacertchain-sess.pem", servercertlevel3areq.filename, clientcertlevel2breq.filename,
                 false, false, "libvirt.org", NULL);

    testTLSDiscardCert(&clientcertreq);
    testTLSDiscardCert(&clientcertaltreq);

    testTLSDiscardCert(&servercertreq);
    testTLSDiscardCert(&servercertalt1req);
    testTLSDiscardCert(&servercertalt2req);

    testTLSDiscardCert(&cacertreq);
    testTLSDiscardCert(&altcacertreq);

    testTLSDiscardCert(&cacertrootreq);
    testTLSDiscardCert(&cacertlevel1areq);
    testTLSDiscardCert(&cacertlevel1breq);
    testTLSDiscardCert(&cacertlevel2areq);
    testTLSDiscardCert(&servercertlevel3areq);
    testTLSDiscardCert(&clientcertlevel2breq);
    unlink("cacertchain-sess.pem");

    testTLSCleanup(KEYFILE);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)

#else

int
main(void)
{
    return EXIT_AM_SKIP;
}

#endif
