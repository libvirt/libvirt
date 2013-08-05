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

# include "rpc/virnettlscontext.h"

# define VIR_FROM_THIS VIR_FROM_RPC

struct testTLSContextData {
    bool isServer;
    struct testTLSCertReq careq;
    struct testTLSCertReq certreq;
    bool expectFail;
};


/*
 * This tests sanity checking of our own certificates
 *
 * This code is done when libvirtd starts up, or before
 * a libvirt client connects. The test is ensuring that
 * the creation of virNetTLSContextPtr fails if we
 * give bogus certs, or succeeds for good certs
 */
static int testTLSContextInit(const void *opaque)
{
    struct testTLSContextData *data = (struct testTLSContextData *)opaque;
    virNetTLSContextPtr ctxt = NULL;
    int ret = -1;

    testTLSGenerateCert(&data->careq);
    data->certreq.cacrt = data->careq.crt;
    testTLSGenerateCert(&data->certreq);

    if (data->isServer) {
        ctxt = virNetTLSContextNewServer(data->careq.filename,
                                         NULL,
                                         data->certreq.filename,
                                         keyfile,
                                         NULL,
                                         true,
                                         true);
    } else {
        ctxt = virNetTLSContextNewClient(data->careq.filename,
                                         NULL,
                                         data->certreq.filename,
                                         keyfile,
                                         true,
                                         true);
    }

    if (ctxt) {
        if (data->expectFail) {
            VIR_WARN("Expected failure %s against %s",
                     data->careq.filename, data->certreq.filename);
            goto cleanup;
        }
    } else {
        virErrorPtr err = virGetLastError();
        if (!data->expectFail) {
            VIR_WARN("Unexpected failure %s against %s",
                     data->careq.filename, data->certreq.filename);
            goto cleanup;
        }
        VIR_DEBUG("Got error %s", err ? err->message : "<unknown>");
    }

    ret = 0;

cleanup:
    virObjectUnref(ctxt);
    testTLSDiscardCert(&data->careq);
    testTLSDiscardCert(&data->certreq);
    return ret;
}



static int
mymain(void)
{
    int ret = 0;

    testTLSInit();

# define DO_CTX_TEST(_isServer, _caReq, _certReq, _expectFail)          \
    do {                                                                \
        static struct testTLSContextData data;                          \
        data.isServer = _isServer;                                      \
        data.careq = _caReq;                                            \
        data.certreq = _certReq;                                        \
        data.expectFail = _expectFail;                                  \
        if (virtTestRun("TLS Context", 1, testTLSContextInit, &data) < 0) \
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


    DO_CTX_TEST(true, cacertreq, servercertreq, false);
    DO_CTX_TEST(false, cacertreq, clientcertreq, false);


    /* Some other CAs which are good */

    /* Basic:CA:critical */
    static struct testTLSCertReq cacert1req = {
        NULL, NULL, "cacert1.pem", "UK",
        "libvirt CA 1", NULL, NULL, NULL, NULL,
        true, true, true,
        false, false, 0,
        false, false, NULL, NULL,
        0, 0,
    };
    /* Basic:CA:not-critical */
    static struct testTLSCertReq cacert2req = {
        NULL, NULL, "cacert2.pem", "UK",
        "libvirt CA 2", NULL, NULL, NULL, NULL,
        true, false, true,
        false, false, 0,
        false, false, NULL, NULL,
        0, 0,
    };
    /* Key usage:cert-sign:critical */
    static struct testTLSCertReq cacert3req = {
        NULL, NULL, "cacert3.pem", "UK",
        "libvirt CA 3", NULL, NULL, NULL, NULL,
        true, true, true,
        true, true, GNUTLS_KEY_KEY_CERT_SIGN,
        false, false, NULL, NULL,
        0, 0,
    };

    DO_CTX_TEST(true, cacert1req, servercertreq, false);
    DO_CTX_TEST(true, cacert2req, servercertreq, false);
    DO_CTX_TEST(true, cacert3req, servercertreq, false);

    /* Now some bad certs */

    /* Key usage:dig-sig:not-critical */
    static struct testTLSCertReq cacert4req = {
        NULL, NULL, "cacert4.pem", "UK",
        "libvirt CA 4", NULL, NULL, NULL, NULL,
        true, true, true,
        true, false, GNUTLS_KEY_DIGITAL_SIGNATURE,
        false, false, NULL, NULL,
        0, 0,
    };
    /* no-basic */
    static struct testTLSCertReq cacert5req = {
        NULL, NULL, "cacert5.pem", "UK",
        "libvirt CA 5", NULL, NULL, NULL, NULL,
        false, false, false,
        false, false, 0,
        false, false, NULL, NULL,
        0, 0,
    };
    /* Key usage:dig-sig:critical */
    static struct testTLSCertReq cacert6req = {
        NULL, NULL, "cacert6.pem", "UK",
        "libvirt CA 6", NULL, NULL, NULL, NULL,
        true, true, true,
        true, true, GNUTLS_KEY_DIGITAL_SIGNATURE,
        false, false, NULL, NULL,
        0, 0,
    };

    /* Technically a CA cert with basic constraints
     * key purpose == key signing + non-critical should
     * be rejected. GNUTLS < 3 does not reject it and
     * we don't anticipate them changing this behaviour
     */
    DO_CTX_TEST(true, cacert4req, servercertreq, GNUTLS_VERSION_MAJOR >= 3);
    DO_CTX_TEST(true, cacert5req, servercertreq, true);
    DO_CTX_TEST(true, cacert6req, servercertreq, true);


    /* Various good servers */
    /* no usage or purpose */
    static struct testTLSCertReq servercert1req = {
        NULL, NULL, "servercert1.pem", "UK",
        "libvirt", NULL, NULL, NULL, NULL,
        true, true, false,
        false, false, 0,
        false, false, NULL, NULL,
        0, 0,
    };
    /* usage:cert-sign+dig-sig+encipher:critical */
    static struct testTLSCertReq servercert2req = {
        NULL, NULL, "servercert2.pem", "UK",
        "libvirt", NULL, NULL, NULL, NULL,
        true, true, false,
        true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT | GNUTLS_KEY_KEY_CERT_SIGN,
        false, false, NULL, NULL,
        0, 0,
    };
    /* usage:cert-sign:not-critical */
    static struct testTLSCertReq servercert3req = {
        NULL, NULL, "servercert3.pem", "UK",
        "libvirt", NULL, NULL, NULL, NULL,
        true, true, false,
        true, false, GNUTLS_KEY_KEY_CERT_SIGN,
        false, false, NULL, NULL,
        0, 0,
    };
    /* purpose:server:critical */
    static struct testTLSCertReq servercert4req = {
        NULL, NULL, "servercert4.pem", "UK",
        "libvirt", NULL, NULL, NULL, NULL,
        true, true, false,
        false, false, 0,
        true, true, GNUTLS_KP_TLS_WWW_SERVER, NULL,
        0, 0,
    };
    /* purpose:server:not-critical */
    static struct testTLSCertReq servercert5req = {
        NULL, NULL, "servercert5.pem", "UK",
        "libvirt", NULL, NULL, NULL, NULL,
        true, true, false,
        false, false, 0,
        true, false, GNUTLS_KP_TLS_WWW_SERVER, NULL,
        0, 0,
    };
    /* purpose:client+server:critical */
    static struct testTLSCertReq servercert6req = {
        NULL, NULL, "servercert6.pem", "UK",
        "libvirt", NULL, NULL, NULL, NULL,
        true, true, false,
        false, false, 0,
        true, true, GNUTLS_KP_TLS_WWW_CLIENT, GNUTLS_KP_TLS_WWW_SERVER,
        0, 0,
    };
    /* purpose:client+server:not-critical */
    static struct testTLSCertReq servercert7req = {
        NULL, NULL, "servercert7.pem", "UK",
        "libvirt", NULL, NULL, NULL, NULL,
        true, true, false,
        false, false, 0,
        true, false, GNUTLS_KP_TLS_WWW_CLIENT, GNUTLS_KP_TLS_WWW_SERVER,
        0, 0,
    };

    DO_CTX_TEST(true, cacertreq, servercert1req, false);
    DO_CTX_TEST(true, cacertreq, servercert2req, false);
    DO_CTX_TEST(true, cacertreq, servercert3req, false);
    DO_CTX_TEST(true, cacertreq, servercert4req, false);
    DO_CTX_TEST(true, cacertreq, servercert5req, false);
    DO_CTX_TEST(true, cacertreq, servercert6req, false);
    DO_CTX_TEST(true, cacertreq, servercert7req, false);
    /* Bad servers */

    /* usage:cert-sign:critical */
    static struct testTLSCertReq servercert8req = {
        NULL, NULL, "servercert8.pem", "UK",
        "libvirt", NULL, NULL, NULL, NULL,
        true, true, false,
        true, true, GNUTLS_KEY_KEY_CERT_SIGN,
        false, false, NULL, NULL,
        0, 0,
    };
    /* purpose:client:critical */
    static struct testTLSCertReq servercert9req = {
        NULL, NULL, "servercert9.pem", "UK",
        "libvirt", NULL, NULL, NULL, NULL,
        true, true, false,
        false, false, 0,
        true, true, GNUTLS_KP_TLS_WWW_CLIENT, NULL,
        0, 0,
    };
    /* usage: none:critical */
    static struct testTLSCertReq servercert10req = {
        NULL, NULL, "servercert10.pem", "UK",
        "libvirt", NULL, NULL, NULL, NULL,
        true, true, false,
        true, true, 0,
        false, false, NULL, NULL,
        0, 0,
    };

    DO_CTX_TEST(true, cacertreq, servercert8req, true);
    DO_CTX_TEST(true, cacertreq, servercert9req, true);
    DO_CTX_TEST(true, cacertreq, servercert10req, true);



    /* Various good clients */
    /* no usage or purpose */
    static struct testTLSCertReq clientcert1req = {
        NULL, NULL, "clientcert1.pem", "UK",
        "libvirt", NULL, NULL, NULL, NULL,
        true, true, false,
        false, false, 0,
        false, false, NULL, NULL,
        0, 0,
    };
    /* usage:cert-sign+dig-sig+encipher:critical */
    static struct testTLSCertReq clientcert2req = {
        NULL, NULL, "clientcert2.pem", "UK",
        "libvirt", NULL, NULL, NULL, NULL,
        true, true, false,
        true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT | GNUTLS_KEY_KEY_CERT_SIGN,
        false, false, NULL, NULL,
        0, 0,
    };
    /* usage:cert-sign:not-critical */
    static struct testTLSCertReq clientcert3req = {
        NULL, NULL, "clientcert3.pem", "UK",
        "libvirt", NULL, NULL, NULL, NULL,
        true, true, false,
        true, false, GNUTLS_KEY_KEY_CERT_SIGN,
        false, false, NULL, NULL,
        0, 0,
    };
    /* purpose:client:critical */
    static struct testTLSCertReq clientcert4req = {
        NULL, NULL, "clientcert4.pem", "UK",
        "libvirt", NULL, NULL, NULL, NULL,
        true, true, false,
        false, false, 0,
        true, true, GNUTLS_KP_TLS_WWW_CLIENT, NULL,
        0, 0,
    };
    /* purpose:client:not-critical */
    static struct testTLSCertReq clientcert5req = {
        NULL, NULL, "clientcert5.pem", "UK",
        "libvirt", NULL, NULL, NULL, NULL,
        true, true, false,
        false, false, 0,
        true, false, GNUTLS_KP_TLS_WWW_CLIENT, NULL,
        0, 0,
    };
    /* purpose:client+client:critical */
    static struct testTLSCertReq clientcert6req = {
        NULL, NULL, "clientcert6.pem", "UK",
        "libvirt", NULL, NULL, NULL, NULL,
        true, true, false,
        false, false, 0,
        true, true, GNUTLS_KP_TLS_WWW_CLIENT, GNUTLS_KP_TLS_WWW_SERVER,
        0, 0,
    };
    /* purpose:client+client:not-critical */
    static struct testTLSCertReq clientcert7req = {
        NULL, NULL, "clientcert7.pem", "UK",
        "libvirt", NULL, NULL, NULL, NULL,
        true, true, false,
        false, false, 0,
        true, false, GNUTLS_KP_TLS_WWW_CLIENT, GNUTLS_KP_TLS_WWW_SERVER,
        0, 0,
    };

    DO_CTX_TEST(false, cacertreq, clientcert1req, false);
    DO_CTX_TEST(false, cacertreq, clientcert2req, false);
    DO_CTX_TEST(false, cacertreq, clientcert3req, false);
    DO_CTX_TEST(false, cacertreq, clientcert4req, false);
    DO_CTX_TEST(false, cacertreq, clientcert5req, false);
    DO_CTX_TEST(false, cacertreq, clientcert6req, false);
    DO_CTX_TEST(false, cacertreq, clientcert7req, false);
    /* Bad clients */

    /* usage:cert-sign:critical */
    static struct testTLSCertReq clientcert8req = {
        NULL, NULL, "clientcert8.pem", "UK",
        "libvirt", NULL, NULL, NULL, NULL,
        true, true, false,
        true, true, GNUTLS_KEY_KEY_CERT_SIGN,
        false, false, NULL, NULL,
        0, 0,
    };
    /* purpose:client:critical */
    static struct testTLSCertReq clientcert9req = {
        NULL, NULL, "clientcert9.pem", "UK",
        "libvirt", NULL, NULL, NULL, NULL,
        true, true, false,
        false, false, 0,
        true, true, GNUTLS_KP_TLS_WWW_SERVER, NULL,
        0, 0,
    };
    /* usage: none:critical */
    static struct testTLSCertReq clientcert10req = {
        NULL, NULL, "clientcert10.pem", "UK",
        "libvirt", NULL, NULL, NULL, NULL,
        true, true, false,
        true, true, 0,
        false, false, NULL, NULL,
        0, 0,
    };

    DO_CTX_TEST(false, cacertreq, clientcert8req, true);
    DO_CTX_TEST(false, cacertreq, clientcert9req, true);
    DO_CTX_TEST(false, cacertreq, clientcert10req, true);



    /* Expired stuff */

    static struct testTLSCertReq cacertexpreq = {
        NULL, NULL, "cacert.pem", "UK",
        "libvirt", NULL, NULL, NULL, NULL,
        true, true, true,
        true, true, GNUTLS_KEY_KEY_CERT_SIGN,
        false, false, NULL, NULL,
        0, -1,
    };
    static struct testTLSCertReq servercertexpreq = {
        NULL, NULL, "servercert.pem", "UK",
        "libvirt", NULL, NULL, NULL, NULL,
        true, true, false,
        true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT,
        true, true, GNUTLS_KP_TLS_WWW_SERVER, NULL,
        0, -1,
    };
    static struct testTLSCertReq clientcertexpreq = {
        NULL, NULL, "clientcert.pem", "UK",
        "libvirt", NULL, NULL, NULL, NULL,
        true, true, false,
        true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT,
        true, true, GNUTLS_KP_TLS_WWW_CLIENT, NULL,
        0, -1,
    };

    DO_CTX_TEST(true, cacertexpreq, servercertreq, true);
    DO_CTX_TEST(true, cacertreq, servercertexpreq, true);
    DO_CTX_TEST(false, cacertreq, clientcertexpreq, true);


    /* Not activated stuff */

    static struct testTLSCertReq cacertnewreq = {
        NULL, NULL, "cacert.pem", "UK",
        "libvirt", NULL, NULL, NULL, NULL,
        true, true, true,
        true, true, GNUTLS_KEY_KEY_CERT_SIGN,
        false, false, NULL, NULL,
        1, 2,
    };
    static struct testTLSCertReq servercertnewreq = {
        NULL, NULL, "servercert.pem", "UK",
        "libvirt", NULL, NULL, NULL, NULL,
        true, true, false,
        true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT,
        true, true, GNUTLS_KP_TLS_WWW_SERVER, NULL,
        1, 2,
    };
    static struct testTLSCertReq clientcertnewreq = {
        NULL, NULL, "clientcert.pem", "UK",
        "libvirt", NULL, NULL, NULL, NULL,
        true, true, false,
        true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT,
        true, true, GNUTLS_KP_TLS_WWW_CLIENT, NULL,
        1, 2,
    };

    DO_CTX_TEST(true, cacertnewreq, servercertreq, true);
    DO_CTX_TEST(true, cacertreq, servercertnewreq, true);
    DO_CTX_TEST(false, cacertreq, clientcertnewreq, true);

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
