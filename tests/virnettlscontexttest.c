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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <stdlib.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "testutils.h"
#include "util.h"
#include "virterror_internal.h"
#include "memory.h"
#include "logging.h"
#include "virfile.h"
#include "command.h"
#include "virsocketaddr.h"
#include "gnutls_1_0_compat.h"

#if !defined WIN32 && HAVE_LIBTASN1_H && LIBGNUTLS_VERSION_NUMBER >= 0x020600
# include <libtasn1.h>

# include "rpc/virnettlscontext.h"

# define VIR_FROM_THIS VIR_FROM_RPC

const char *keyfile = abs_builddir "/virnettlscontexttest-key.pem";

/*
 * These store some static data that is needed when
 * encoding extensions in the x509 certs
 */
ASN1_TYPE pkix_asn1;
extern const ASN1_ARRAY_TYPE pkix_asn1_tab[];

/*
 * To avoid consuming random entropy to generate keys,
 * here's one we prepared earlier :-)
 */
gnutls_x509_privkey_t privkey;
# define PRIVATE_KEY                                              \
    "-----BEGIN PRIVATE KEY-----\n"                               \
    "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBALVcr\n"     \
    "BL40Tm6yq88FBhJNw1aaoCjmtg0l4dWQZ/e9Fimx4ARxFpT+ji4FE\n"     \
    "Cgl9s/SGqC+1nvlkm9ViSo0j7MKDbnDB+VRHDvMAzQhA2X7e8M0n9\n"     \
    "rPolUY2lIVC83q0BBaOBkCj2RSmT2xTEbbC2xLukSrg2WP/ihVOxc\n"     \
    "kXRuyFtzAgMBAAECgYB7slBexDwXrtItAMIH6m/U+LUpNe0Xx48OL\n"     \
    "IOn4a4whNgO/o84uIwygUK27ZGFZT0kAGAk8CdF9hA6ArcbQ62s1H\n"     \
    "myxrUbF9/mrLsQw1NEqpuUk9Ay2Tx5U/wPx35S3W/X2AvR/ZpTnCn\n"     \
    "2q/7ym9fyiSoj86drD7BTvmKXlOnOwQJBAPOFMp4mMa9NGpGuEssO\n"     \
    "m3Uwbp6lhcP0cA9MK+iOmeANpoKWfBdk5O34VbmeXnGYWEkrnX+9J\n"     \
    "bM4wVhnnBWtgBMCQQC+qAEmvwcfhauERKYznMVUVksyeuhxhCe7EK\n"     \
    "mPh+U2+g0WwdKvGDgO0PPt1gq0ILEjspMDeMHVdTwkaVBo/uMhAkA\n"     \
    "Z5SsZyCP2aTOPFDypXRdI4eqRcjaEPOUBq27r3uYb/jeboVb2weLa\n"     \
    "L1MmVuHiIHoa5clswPdWVI2y0em2IGoDAkBPSp/v9VKJEZabk9Frd\n"     \
    "a+7u4fanrM9QrEjY3KhduslSilXZZSxrWjjAJPyPiqFb3M8XXA26W\n"     \
    "nz1KYGnqYKhLcBAkB7dt57n9xfrhDpuyVEv+Uv1D3VVAhZlsaZ5Pp\n"     \
    "dcrhrkJn2sa/+O8OKvdrPSeeu/N5WwYhJf61+CPoenMp7IFci\n"         \
    "-----END PRIVATE KEY-----\n"


/*
 * This contains parameter about how to generate
 * certificates.
 */
struct testTLSCertReq {
    gnutls_x509_crt_t crt;
    gnutls_x509_crt_t cacrt; /* If not set, then the cert will be self-signed */

    const char *filename;

    /* Identifying information */
    const char *country;
    const char *cn;
    const char *altname1;
    const char *altname2;
    const char *ipaddr1;
    const char *ipaddr2;

    /* Basic constraints */
    bool basicConstraintsEnable;
    bool basicConstraintsCritical;
    bool basicConstraintsIsCA;

    /* Key usage */
    bool keyUsageEnable;
    bool keyUsageCritical;
    int keyUsageValue;

    /* Key purpose (aka Extended key usage) */
    bool keyPurposeEnable;
    bool keyPurposeCritical;
    const char *keyPurposeOID1;
    const char *keyPurposeOID2;

    /* zero for current time, or non-zero for hours from now */
    int start_offset;
    /* zero for 24 hours from now, or non-zero for hours from now */
    int expire_offset;
};


/*
 * Turns an ASN1 object into a DER encoded byte array
 */
static void testTLSDerEncode(ASN1_TYPE src,
                             const char *src_name,
                             gnutls_datum_t * res)
{
  int size;
  char *data = NULL;

  size = 0;
  asn1_der_coding(src, src_name, NULL, &size, NULL);

  if (VIR_ALLOC_N(data, size) < 0)
      abort();

  asn1_der_coding(src, src_name, data, &size, NULL);

  res->data = (unsigned char *)data;
  res->size = size;
}


/*
 * This is a fairly lame x509 certificate generator.
 *
 * Do not copy/use this code for generating real certificates
 * since it leaves out many things that you would want in
 * certificates for real world usage.
 *
 * This is good enough only for doing tests of the libvirt
 * TLS certificate code
 */
static void
testTLSGenerateCert(struct testTLSCertReq *req)
{
    gnutls_x509_crt_t crt;
    int err;
    static char buffer[1024*1024];
    size_t size = sizeof(buffer);
    char serial[5] = { 1, 2, 3, 4, 0 };
    gnutls_datum_t der = { (unsigned char *)buffer, size };
    time_t start = time(NULL) + (60*60*req->start_offset);
    time_t expire = time(NULL) + (60*60*(req->expire_offset
                                         ? req->expire_offset : 24));

    /*
     * Prepare our new certificate object
     */
    if ((err = gnutls_x509_crt_init(&crt)) < 0) {
        VIR_WARN("Failed to initialize certificate %s", gnutls_strerror(err));
        abort();
    }
    if ((err = gnutls_x509_crt_set_key(crt, privkey)) < 0) {
        VIR_WARN("Failed to set certificate key %s", gnutls_strerror(err));
        abort();
    }

    /*
     * A v3 certificate is required in order to be able
     * set any of the basic constraints, key purpose and
     * key usage data
     */
    gnutls_x509_crt_set_version(crt, 3);

    if (req->country) {
        if ((err = gnutls_x509_crt_set_dn_by_oid(crt, GNUTLS_OID_X520_COUNTRY_NAME, 0,
                                                 req->country, strlen(req->country))) < 0) {
            VIR_WARN("Failed to set certificate country name %s", gnutls_strerror(err));
            abort();
        }
    }
    if (req->cn) {
        if ((err = gnutls_x509_crt_set_dn_by_oid(crt, GNUTLS_OID_X520_COMMON_NAME, 0,
                                                 req->cn, strlen(req->cn))) < 0) {
            VIR_WARN("Failed to set certificate common name %s", gnutls_strerror(err));
            abort();
        }
    }

    /*
     * Setup the subject altnames, which are used
     * for hostname checks in live sessions
     */
    if (req->altname1) {
        if ((err = gnutls_x509_crt_set_subject_alt_name(crt, GNUTLS_SAN_DNSNAME,
                                                        req->altname1,
                                                        strlen(req->altname1),
                                                        GNUTLS_FSAN_APPEND))) {
            VIR_WARN("Failed to set certificate alt name %s", gnutls_strerror(err));
            abort();
        }
    }
    if (req->altname2) {
        if ((err = gnutls_x509_crt_set_subject_alt_name(crt, GNUTLS_SAN_DNSNAME,
                                                        req->altname2,
                                                        strlen(req->altname2),
                                                        GNUTLS_FSAN_APPEND))) {
            VIR_WARN("Failed to set certificate %s alt name", gnutls_strerror(err));
            abort();
        }
    }

    /*
     * IP address need to be put into the cert in their
     * raw byte form, not strings, hence this is a little
     * more complicated
     */
    if (req->ipaddr1) {
        virSocketAddr addr;
        char *data;
        int len;
        if (virSocketAddrParse(&addr, req->ipaddr1, 0) < 0) {
            VIR_WARN("Cannot parse %s", req->ipaddr1);
            abort();
        }

        if (addr.data.sa.sa_family == AF_INET) {
            data = (char*)&addr.data.inet4.sin_addr;
            len = 4;
        } else {
            data = (char*)&addr.data.inet6.sin6_addr;
            len = 16;
        }

        if ((err = gnutls_x509_crt_set_subject_alt_name(crt, GNUTLS_SAN_IPADDRESS,
                                                        data, len, GNUTLS_FSAN_APPEND))) {
            VIR_WARN("Failed to set certificate alt name %s", gnutls_strerror(err));
            abort();
        }
    }
    if (req->ipaddr2) {
        virSocketAddr addr;
        char *data;
        int len;
        if (virSocketAddrParse(&addr, req->ipaddr2, 0) < 0) {
            VIR_WARN("Cannot parse %s", req->ipaddr2);
            abort();
        }

        if (addr.data.sa.sa_family == AF_INET) {
            data = (char*)&addr.data.inet4.sin_addr;
            len = 4;
        } else {
            data = (char*)&addr.data.inet6.sin6_addr;
            len = 16;
        }

        if ((err = gnutls_x509_crt_set_subject_alt_name(crt, GNUTLS_SAN_IPADDRESS,
                                                        data, len, GNUTLS_FSAN_APPEND))) {
            VIR_WARN("Failed to set certificate alt name %s", gnutls_strerror(err));
            abort();
        }
    }


    /*
     * Basic constraints are used to decide if the cert
     * is for a CA or not. We can't use the convenient
     * gnutls API for setting this, since it hardcodes
     * the 'critical' field which we want control over
     */
    if (req->basicConstraintsEnable) {
        ASN1_TYPE ext = ASN1_TYPE_EMPTY;

        asn1_create_element(pkix_asn1, "PKIX1.BasicConstraints", &ext);
        asn1_write_value(ext, "cA", req->basicConstraintsIsCA ? "TRUE" : "FALSE", 1);
        asn1_write_value(ext, "pathLenConstraint", NULL, 0);
        testTLSDerEncode(ext, "", &der);
        if ((err = gnutls_x509_crt_set_extension_by_oid(crt,
                                                        "2.5.29.19",
                                                        der.data,
                                                        der.size,
                                                        req->basicConstraintsCritical)) < 0) {
            VIR_WARN("Failed to set certificate basic constraints %s", gnutls_strerror(err));
            abort();
        }
        asn1_delete_structure(&ext);
        VIR_FREE(der.data);
    }

    /*
     * Next up the key usage extension. Again we can't
     * use the gnutls API since it hardcodes the extension
     * to be 'critical'
     */
    if (req->keyUsageEnable) {
        ASN1_TYPE ext = ASN1_TYPE_EMPTY;
        char str[2];

        str[0] = req->keyUsageValue & 0xff;
        str[1] = (req->keyUsageValue >> 8) & 0xff;

        asn1_create_element(pkix_asn1, "PKIX1.KeyUsage", &ext);
        asn1_write_value(ext, "", str, 9);
        testTLSDerEncode(ext, "", &der);
        if ((err = gnutls_x509_crt_set_extension_by_oid(crt,
                                                        "2.5.29.15",
                                                        der.data,
                                                        der.size,
                                                        req->keyUsageCritical)) < 0) {
            VIR_WARN("Failed to set certificate key usage %s", gnutls_strerror(err));
            abort();
        }
        asn1_delete_structure(&ext);
        VIR_FREE(der.data);
    }

    /*
     * Finally the key purpose extension. This time
     * gnutls has the opposite problem, always hardcoding
     * it to be non-critical. So once again we have to
     * set this the hard way building up ASN1 data ourselves
     */
    if (req->keyPurposeEnable) {
        ASN1_TYPE ext = ASN1_TYPE_EMPTY;

        asn1_create_element(pkix_asn1, "PKIX1.ExtKeyUsageSyntax", &ext);
        if (req->keyPurposeOID1) {
            asn1_write_value(ext, "", "NEW", 1);
            asn1_write_value(ext, "?LAST", req->keyPurposeOID1, 1);
        }
        if (req->keyPurposeOID2) {
            asn1_write_value(ext, "", "NEW", 1);
            asn1_write_value(ext, "?LAST", req->keyPurposeOID2, 1);
        }
        testTLSDerEncode(ext, "", &der);
        if ((err = gnutls_x509_crt_set_extension_by_oid(crt,
                                                        "2.5.29.37",
                                                        der.data,
                                                        der.size,
                                                        req->keyPurposeCritical)) < 0) {
            VIR_WARN("Failed to set certificate key purpose %s", gnutls_strerror(err));
            abort();
        }
        asn1_delete_structure(&ext);
        VIR_FREE(der.data);
    }

    /*
     * Any old serial number will do, so lets pick 5
     */
    if ((err = gnutls_x509_crt_set_serial(crt, serial, 5)) < 0) {
        VIR_WARN("Failed to set certificate serial %s", gnutls_strerror(err));
        abort();
    }

    if ((err = gnutls_x509_crt_set_activation_time(crt, start)) < 0) {
        VIR_WARN("Failed to set certificate activation %s", gnutls_strerror(err));
        abort();
    }
    if ((err = gnutls_x509_crt_set_expiration_time(crt, expire)) < 0) {
        VIR_WARN("Failed to set certificate expiration %s", gnutls_strerror(err));
        abort();
    }


    /*
     * If no 'cart' is set then we are self signing
     * the cert. This is done for CA certs
     */
    if ((err = gnutls_x509_crt_sign(crt, req->cacrt ? req->cacrt : crt, privkey) < 0)) {
        VIR_WARN("Failed to sign certificate %s", gnutls_strerror(err));
        abort();
    }

    /*
     * Finally write the new cert out to disk
     */
    if ((err = gnutls_x509_crt_export(crt, GNUTLS_X509_FMT_PEM, buffer, &size) < 0)) {
        VIR_WARN("Failed to export certificate %s", gnutls_strerror(err));
        abort();
    }

    if (virFileWriteStr(req->filename, buffer, 0600) < 0) {
        VIR_WARN("Failed to write certificate %s %s", req->filename, gnutls_strerror(err));
        abort();
    }

    req->crt = crt;
    return;
}


/*
 * This loads the private key we defined earlier
 */
static gnutls_x509_privkey_t testTLSLoadKey(void)
{
    gnutls_x509_privkey_t key;
    const gnutls_datum_t data = { (unsigned char *)PRIVATE_KEY, strlen(PRIVATE_KEY) };
    int err;

    if ((err = gnutls_x509_privkey_init(&key)) < 0) {
        VIR_WARN("Failed to init key %s", gnutls_strerror(err));
        abort();
    }

    if ((err = gnutls_x509_privkey_import(key, &data,
                                          GNUTLS_X509_FMT_PEM)) < 0) {
        if (err != GNUTLS_E_BASE64_UNEXPECTED_HEADER_ERROR) {
            VIR_WARN("Failed to import key %s", gnutls_strerror(err));
            abort();
        }

        if ((err = gnutls_x509_privkey_import_pkcs8(key, &data, GNUTLS_X509_FMT_PEM, NULL, 0)) < 0) {
            VIR_WARN("Failed to import PKCS8 key %s", gnutls_strerror(err));
            abort();
        }
    }

    return key;
}


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
 * give bogus certs, or suceeds for good certs
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
    virNetTLSContextFree(ctxt);
    gnutls_x509_crt_deinit(data->careq.crt);
    gnutls_x509_crt_deinit(data->certreq.crt);
    data->careq.crt = data->certreq.crt = NULL;
    /* When troubleshooting this tests, we often want to leave the certs on disk */
    if (getenv("VIRT_TEST_DEBUG_CERTS") == NULL) {
        unlink(data->careq.filename);
        unlink(data->certreq.filename);
    }
    return ret;
}



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
                serverShake = true;
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
    virNetTLSContextFree(serverCtxt);
    virNetTLSContextFree(clientCtxt);
    virNetTLSSessionFree(serverSess);
    virNetTLSSessionFree(clientSess);
    gnutls_x509_crt_deinit(data->careq.crt);
    if (data->othercareq.filename)
        gnutls_x509_crt_deinit(data->othercareq.crt);
    gnutls_x509_crt_deinit(data->clientreq.crt);
    gnutls_x509_crt_deinit(data->serverreq.crt);
    data->careq.crt = data->othercareq.crt = data->clientreq.crt = data->serverreq.crt = NULL;

    /* When troubleshooting this tests, we often want to leave the certs on disk */
    if (getenv("VIRT_TEST_DEBUG_CERTS") == NULL) {
        unlink(data->careq.filename);
        if (data->othercareq.filename)
            unlink(data->othercareq.filename);
        unlink(data->clientreq.filename);
        unlink(data->serverreq.filename);
    }
    VIR_FORCE_CLOSE(channel[0]);
    VIR_FORCE_CLOSE(channel[1]);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;
    if (asn1_array2tree(pkix_asn1_tab, &pkix_asn1, NULL) != ASN1_SUCCESS)
        abort();

    gnutls_global_init();

    privkey = testTLSLoadKey();

    if (virFileWriteStr(keyfile, PRIVATE_KEY, 0600) < 0)
        return EXIT_FAILURE;

# define DO_CTX_TEST(isServer, caReq, certReq, expectFail)              \
    do {                                                                \
        struct testTLSContextData data = {                              \
            isServer, caReq, certReq, expectFail,                       \
        };                                                              \
        if (virtTestRun("TLS Context", 1, testTLSContextInit, &data) < 0) \
            ret = -1;                                                   \
    } while (0)

# define DO_SESS_TEST(caReq, serverReq, clientReq, expectServerFail, expectClientFail, hostname, wildcards) \
    do {                                                                \
        struct testTLSSessionData data = {                              \
            caReq, { 0 }, serverReq, clientReq,                         \
            expectServerFail, expectClientFail, hostname, wildcards     \
        };                                                              \
        if (virtTestRun("TLS Session", 1, testTLSSessionInit, &data) < 0) \
            ret = -1;                                                   \
    } while (0)

# define DO_SESS_TEST_EXT(caReq, othercaReq, serverReq, clientReq, expectServerFail, expectClientFail, hostname, wildcards) \
    do {                                                                \
        struct testTLSSessionData data = {                              \
            caReq, othercaReq, serverReq, clientReq,                    \
            expectServerFail, expectClientFail, hostname, wildcards     \
        };                                                              \
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
    /* Basic:not-CA:not-critical */
# if 0
    /* Default GNUTLS session config forbids use of CAs without
     * basic constraints, so skip this otherwise valid test
     */
    static struct testTLSCertReq cacert3req = {
        NULL, NULL, "cacert3.pem", "UK",
        "libvirt CA 3", NULL, NULL, NULL, NULL,
        true, false, false,
        false, false, 0,
        false, false, NULL, NULL,
        0, 0,
    };
# endif
    /* Key usage:cert-sign:critical */
    static struct testTLSCertReq cacert4req = {
        NULL, NULL, "cacert4.pem", "UK",
        "libvirt CA 4", NULL, NULL, NULL, NULL,
        true, true, true,
        true, true, GNUTLS_KEY_KEY_CERT_SIGN,
        false, false, NULL, NULL,
        0, 0,
    };
    /* Key usage:dig-sig:not-critical */
    static struct testTLSCertReq cacert5req = {
        NULL, NULL, "cacert5.pem", "UK",
        "libvirt CA 5", NULL, NULL, NULL, NULL,
        true, true, true,
        true, false, GNUTLS_KEY_DIGITAL_SIGNATURE,
        false, false, NULL, NULL,
        0, 0,
    };

    DO_CTX_TEST(true, cacert1req, servercertreq, false);
    DO_CTX_TEST(true, cacert2req, servercertreq, false);
# if 0
    DO_CTX_TEST(true, cacert3req, servercertreq, false);
# endif
    DO_CTX_TEST(true, cacert4req, servercertreq, false);
    DO_CTX_TEST(true, cacert5req, servercertreq, false);

    /* Now some bad certs */

    /* no-basic */
    static struct testTLSCertReq cacert6req = {
        NULL, NULL, "cacert6.pem", "UK",
        "libvirt CA 6", NULL, NULL, NULL, NULL,
        false, false, false,
        false, false, 0,
        false, false, NULL, NULL,
        0, 0,
    };
    /* Key usage:dig-sig:critical */
    static struct testTLSCertReq cacert7req = {
        NULL, NULL, "cacert7.pem", "UK",
        "libvirt CA 7", NULL, NULL, NULL, NULL,
        true, true, true,
        true, true, GNUTLS_KEY_DIGITAL_SIGNATURE,
        false, false, NULL, NULL,
        0, 0,
    };

    DO_CTX_TEST(true, cacert6req, servercertreq, true);
    DO_CTX_TEST(true, cacert7req, servercertreq, true);


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

    unlink(keyfile);

    asn1_delete_structure(&pkix_asn1);

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
