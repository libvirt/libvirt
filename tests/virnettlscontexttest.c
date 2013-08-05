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
        if (virtTestRun("TLS Context " #_caReq  " + " #_certReq, 1,     \
                        testTLSContextInit, &data) < 0)                 \
            ret = -1;                                                   \
    } while (0)

# define TLS_CERT_REQ(varname, cavarname,                               \
                      co, cn, an1, an2, ia1, ia2, bce, bcc, bci,        \
                      kue, kuc, kuv, kpe, kpc, kpo1, kpo2, so, eo)      \
    static struct testTLSCertReq varname = {                            \
        NULL, #varname ".pem",                                          \
        co, cn, an1, an2, ia1, ia2, bce, bcc, bci,                      \
        kue, kuc, kuv, kpe, kpc, kpo1, kpo2, so, eo                     \
    };                                                                  \
    testTLSGenerateCert(&varname, cavarname.crt)

# define TLS_ROOT_REQ(varname,                                          \
                      co, cn, an1, an2, ia1, ia2, bce, bcc, bci,        \
                      kue, kuc, kuv, kpe, kpc, kpo1, kpo2, so, eo)      \
    static struct testTLSCertReq varname = {                            \
        NULL, #varname ".pem",                                          \
        co, cn, an1, an2, ia1, ia2, bce, bcc, bci,                      \
        kue, kuc, kuv, kpe, kpc, kpo1, kpo2, so, eo                     \
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

    DO_CTX_TEST(true, cacertreq, servercertreq, false);
    DO_CTX_TEST(false, cacertreq, clientcertreq, false);


    /* Some other CAs which are good */

    /* Basic:CA:critical */
    TLS_ROOT_REQ(cacert1req,
                 "UK", "libvirt CA 1", NULL, NULL, NULL, NULL,
                 true, true, true,
                 false, false, 0,
                 false, false, NULL, NULL,
                 0, 0);
    TLS_CERT_REQ(servercert1req, cacert1req,
                 "UK", "libvirt.org", NULL, NULL, NULL, NULL,
                 true, true, false,
                 true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT,
                 true, true, GNUTLS_KP_TLS_WWW_SERVER, NULL,
                 0, 0);

    /* Basic:CA:not-critical */
    TLS_ROOT_REQ(cacert2req,
                 "UK", "libvirt CA 2", NULL, NULL, NULL, NULL,
                 true, false, true,
                 false, false, 0,
                 false, false, NULL, NULL,
                 0, 0);
    TLS_CERT_REQ(servercert2req, cacert2req,
                 "UK", "libvirt.org", NULL, NULL, NULL, NULL,
                 true, true, false,
                 true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT,
                 true, true, GNUTLS_KP_TLS_WWW_SERVER, NULL,
                 0, 0);

    /* Key usage:cert-sign:critical */
    TLS_ROOT_REQ(cacert3req,
                 "UK", "libvirt CA 3", NULL, NULL, NULL, NULL,
                 true, true, true,
                 true, true, GNUTLS_KEY_KEY_CERT_SIGN,
                 false, false, NULL, NULL,
                 0, 0);
    TLS_CERT_REQ(servercert3req, cacert3req,
                 "UK", "libvirt.org", NULL, NULL, NULL, NULL,
                 true, true, false,
                 true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT,
                 true, true, GNUTLS_KP_TLS_WWW_SERVER, NULL,
                 0, 0);

    DO_CTX_TEST(true, cacert1req, servercert1req, false);
    DO_CTX_TEST(true, cacert2req, servercert2req, false);
    DO_CTX_TEST(true, cacert3req, servercert3req, false);

    /* Now some bad certs */

    /* Key usage:dig-sig:not-critical */
    TLS_ROOT_REQ(cacert4req,
                 "UK", "libvirt CA 4", NULL, NULL, NULL, NULL,
                 true, true, true,
                 true, false, GNUTLS_KEY_DIGITAL_SIGNATURE,
                 false, false, NULL, NULL,
                 0, 0);
    TLS_CERT_REQ(servercert4req, cacert4req,
                 "UK", "libvirt.org", NULL, NULL, NULL, NULL,
                 true, true, false,
                 true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT,
                 true, true, GNUTLS_KP_TLS_WWW_SERVER, NULL,
                 0, 0);
    /* no-basic */
    TLS_ROOT_REQ(cacert5req,
                 "UK", "libvirt CA 5", NULL, NULL, NULL, NULL,
                 false, false, false,
                 false, false, 0,
                 false, false, NULL, NULL,
                 0, 0);
    TLS_CERT_REQ(servercert5req, cacert5req,
                 "UK", "libvirt.org", NULL, NULL, NULL, NULL,
                 true, true, false,
                 true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT,
                 true, true, GNUTLS_KP_TLS_WWW_SERVER, NULL,
                 0, 0);
    /* Key usage:dig-sig:critical */
    TLS_ROOT_REQ(cacert6req,
                 "UK", "libvirt CA 6", NULL, NULL, NULL, NULL,
                 true, true, true,
                 true, true, GNUTLS_KEY_DIGITAL_SIGNATURE,
                 false, false, NULL, NULL,
                 0, 0);
    TLS_CERT_REQ(servercert6req, cacert6req,
                 "UK", "libvirt.org", NULL, NULL, NULL, NULL,
                 true, true, false,
                 true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT,
                 true, true, GNUTLS_KP_TLS_WWW_SERVER, NULL,
                 0, 0);

    /* Technically a CA cert with basic constraints
     * key purpose == key signing + non-critical should
     * be rejected. GNUTLS < 3 does not reject it and
     * we don't anticipate them changing this behaviour
     */
    DO_CTX_TEST(true, cacert4req, servercert4req, GNUTLS_VERSION_MAJOR >= 3);
    DO_CTX_TEST(true, cacert5req, servercert5req, true);
    DO_CTX_TEST(true, cacert6req, servercert6req, true);


    /* Various good servers */
    /* no usage or purpose */
    TLS_CERT_REQ(servercert7req, cacertreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, false,
                 false, false, 0,
                 false, false, NULL, NULL,
                 0, 0);
    /* usage:cert-sign+dig-sig+encipher:critical */
    TLS_CERT_REQ(servercert8req, cacertreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, false,
                 true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT | GNUTLS_KEY_KEY_CERT_SIGN,
                 false, false, NULL, NULL,
                 0, 0);
    /* usage:cert-sign:not-critical */
    TLS_CERT_REQ(servercert9req, cacertreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, false,
                 true, false, GNUTLS_KEY_KEY_CERT_SIGN,
                 false, false, NULL, NULL,
                 0, 0);
    /* purpose:server:critical */
    TLS_CERT_REQ(servercert10req, cacertreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, false,
                 false, false, 0,
                 true, true, GNUTLS_KP_TLS_WWW_SERVER, NULL,
                 0, 0);
    /* purpose:server:not-critical */
    TLS_CERT_REQ(servercert11req, cacertreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, false,
                 false, false, 0,
                 true, false, GNUTLS_KP_TLS_WWW_SERVER, NULL,
                 0, 0);
    /* purpose:client+server:critical */
    TLS_CERT_REQ(servercert12req, cacertreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, false,
                 false, false, 0,
                 true, true, GNUTLS_KP_TLS_WWW_CLIENT, GNUTLS_KP_TLS_WWW_SERVER,
                 0, 0);
    /* purpose:client+server:not-critical */
    TLS_CERT_REQ(servercert13req, cacertreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, false,
                 false, false, 0,
                 true, false, GNUTLS_KP_TLS_WWW_CLIENT, GNUTLS_KP_TLS_WWW_SERVER,
                 0, 0);

    DO_CTX_TEST(true, cacertreq, servercert7req, false);
    DO_CTX_TEST(true, cacertreq, servercert8req, false);
    DO_CTX_TEST(true, cacertreq, servercert9req, false);
    DO_CTX_TEST(true, cacertreq, servercert10req, false);
    DO_CTX_TEST(true, cacertreq, servercert11req, false);
    DO_CTX_TEST(true, cacertreq, servercert12req, false);
    DO_CTX_TEST(true, cacertreq, servercert13req, false);
    /* Bad servers */

    /* usage:cert-sign:critical */
    TLS_CERT_REQ(servercert14req, cacertreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, false,
                 true, true, GNUTLS_KEY_KEY_CERT_SIGN,
                 false, false, NULL, NULL,
                 0, 0);
    /* purpose:client:critical */
    TLS_CERT_REQ(servercert15req, cacertreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, false,
                 false, false, 0,
                 true, true, GNUTLS_KP_TLS_WWW_CLIENT, NULL,
                 0, 0);
    /* usage: none:critical */
    TLS_CERT_REQ(servercert16req, cacertreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, false,
                 true, true, 0,
                 false, false, NULL, NULL,
                 0, 0);

    DO_CTX_TEST(true, cacertreq, servercert14req, true);
    DO_CTX_TEST(true, cacertreq, servercert15req, true);
    DO_CTX_TEST(true, cacertreq, servercert16req, true);



    /* Various good clients */
    /* no usage or purpose */
    TLS_CERT_REQ(clientcert1req, cacertreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, false,
                 false, false, 0,
                 false, false, NULL, NULL,
                 0, 0);
    /* usage:cert-sign+dig-sig+encipher:critical */
    TLS_CERT_REQ(clientcert2req, cacertreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, false,
                 true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT | GNUTLS_KEY_KEY_CERT_SIGN,
                 false, false, NULL, NULL,
                 0, 0);
    /* usage:cert-sign:not-critical */
    TLS_CERT_REQ(clientcert3req, cacertreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, false,
                 true, false, GNUTLS_KEY_KEY_CERT_SIGN,
                 false, false, NULL, NULL,
                 0, 0);
    /* purpose:client:critical */
    TLS_CERT_REQ(clientcert4req, cacertreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, false,
                 false, false, 0,
                 true, true, GNUTLS_KP_TLS_WWW_CLIENT, NULL,
                 0, 0);
    /* purpose:client:not-critical */
    TLS_CERT_REQ(clientcert5req, cacertreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, false,
                 false, false, 0,
                 true, false, GNUTLS_KP_TLS_WWW_CLIENT, NULL,
                 0, 0);
    /* purpose:client+client:critical */
    TLS_CERT_REQ(clientcert6req, cacertreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, false,
                 false, false, 0,
                 true, true, GNUTLS_KP_TLS_WWW_CLIENT, GNUTLS_KP_TLS_WWW_SERVER,
                 0, 0);
    /* purpose:client+client:not-critical */
    TLS_CERT_REQ(clientcert7req, cacertreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, false,
                 false, false, 0,
                 true, false, GNUTLS_KP_TLS_WWW_CLIENT, GNUTLS_KP_TLS_WWW_SERVER,
                 0, 0);

    DO_CTX_TEST(false, cacertreq, clientcert1req, false);
    DO_CTX_TEST(false, cacertreq, clientcert2req, false);
    DO_CTX_TEST(false, cacertreq, clientcert3req, false);
    DO_CTX_TEST(false, cacertreq, clientcert4req, false);
    DO_CTX_TEST(false, cacertreq, clientcert5req, false);
    DO_CTX_TEST(false, cacertreq, clientcert6req, false);
    DO_CTX_TEST(false, cacertreq, clientcert7req, false);
    /* Bad clients */

    /* usage:cert-sign:critical */
    TLS_CERT_REQ(clientcert8req, cacertreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, false,
                 true, true, GNUTLS_KEY_KEY_CERT_SIGN,
                 false, false, NULL, NULL,
                 0, 0);
    /* purpose:client:critical */
    TLS_CERT_REQ(clientcert9req, cacertreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, false,
                 false, false, 0,
                 true, true, GNUTLS_KP_TLS_WWW_SERVER, NULL,
                 0, 0);
    /* usage: none:critical */
    TLS_CERT_REQ(clientcert10req, cacertreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, false,
                 true, true, 0,
                 false, false, NULL, NULL,
                 0, 0);

    DO_CTX_TEST(false, cacertreq, clientcert8req, true);
    DO_CTX_TEST(false, cacertreq, clientcert9req, true);
    DO_CTX_TEST(false, cacertreq, clientcert10req, true);



    /* Expired stuff */

    TLS_ROOT_REQ(cacertexpreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, true,
                 true, true, GNUTLS_KEY_KEY_CERT_SIGN,
                 false, false, NULL, NULL,
                 0, -1);
    TLS_CERT_REQ(servercertexpreq, cacertexpreq,
                 "UK", "libvirt.org", NULL, NULL, NULL, NULL,
                 true, true, false,
                 true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT,
                 true, true, GNUTLS_KP_TLS_WWW_SERVER, NULL,
                 0, 0);
    TLS_CERT_REQ(servercertexp1req, cacertreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, false,
                 true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT,
                 true, true, GNUTLS_KP_TLS_WWW_SERVER, NULL,
                 0, -1);
    TLS_CERT_REQ(clientcertexp1req, cacertreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, false,
                 true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT,
                 true, true, GNUTLS_KP_TLS_WWW_CLIENT, NULL,
                 0, -1);

    DO_CTX_TEST(true, cacertexpreq, servercertexpreq, true);
    DO_CTX_TEST(true, cacertreq, servercertexp1req, true);
    DO_CTX_TEST(false, cacertreq, clientcertexp1req, true);


    /* Not activated stuff */

    TLS_ROOT_REQ(cacertnewreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, true,
                 true, true, GNUTLS_KEY_KEY_CERT_SIGN,
                 false, false, NULL, NULL,
                 1, 2);
    TLS_CERT_REQ(servercertnewreq, cacertnewreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, false,
                 true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT,
                 true, true, GNUTLS_KP_TLS_WWW_SERVER, NULL,
                 0, 0);
    TLS_CERT_REQ(servercertnew1req, cacertreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, false,
                 true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT,
                 true, true, GNUTLS_KP_TLS_WWW_SERVER, NULL,
                 1, 2);
    TLS_CERT_REQ(clientcertnew1req, cacertreq,
                 "UK", "libvirt", NULL, NULL, NULL, NULL,
                 true, true, false,
                 true, true, GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT,
                 true, true, GNUTLS_KP_TLS_WWW_CLIENT, NULL,
                 1, 2);

    DO_CTX_TEST(true, cacertnewreq, servercertnewreq, true);
    DO_CTX_TEST(true, cacertreq, servercertnew1req, true);
    DO_CTX_TEST(false, cacertreq, clientcertnew1req, true);

    testTLSDiscardCert(&cacertreq);
    testTLSDiscardCert(&cacert1req);
    testTLSDiscardCert(&cacert2req);
    testTLSDiscardCert(&cacert3req);
    testTLSDiscardCert(&cacert4req);
    testTLSDiscardCert(&cacert5req);
    testTLSDiscardCert(&cacert6req);

    testTLSDiscardCert(&servercertreq);
    testTLSDiscardCert(&servercert1req);
    testTLSDiscardCert(&servercert2req);
    testTLSDiscardCert(&servercert3req);
    testTLSDiscardCert(&servercert4req);
    testTLSDiscardCert(&servercert5req);
    testTLSDiscardCert(&servercert6req);
    testTLSDiscardCert(&servercert7req);
    testTLSDiscardCert(&servercert8req);
    testTLSDiscardCert(&servercert9req);
    testTLSDiscardCert(&servercert10req);
    testTLSDiscardCert(&servercert11req);
    testTLSDiscardCert(&servercert12req);
    testTLSDiscardCert(&servercert13req);
    testTLSDiscardCert(&servercert14req);
    testTLSDiscardCert(&servercert15req);
    testTLSDiscardCert(&servercert16req);

    testTLSDiscardCert(&clientcertreq);
    testTLSDiscardCert(&clientcert1req);
    testTLSDiscardCert(&clientcert2req);
    testTLSDiscardCert(&clientcert3req);
    testTLSDiscardCert(&clientcert4req);
    testTLSDiscardCert(&clientcert5req);
    testTLSDiscardCert(&clientcert6req);
    testTLSDiscardCert(&clientcert7req);
    testTLSDiscardCert(&clientcert8req);
    testTLSDiscardCert(&clientcert9req);
    testTLSDiscardCert(&clientcert10req);

    testTLSDiscardCert(&cacertexpreq);
    testTLSDiscardCert(&servercertexpreq);
    testTLSDiscardCert(&servercertexp1req);
    testTLSDiscardCert(&clientcertexp1req);

    testTLSDiscardCert(&cacertnewreq);
    testTLSDiscardCert(&servercertnewreq);
    testTLSDiscardCert(&servercertnew1req);
    testTLSDiscardCert(&clientcertnew1req);

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
