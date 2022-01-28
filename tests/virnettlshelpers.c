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
 */

#include <config.h>

#include <fcntl.h>

#include "virnettlshelpers.h"
#include "viralloc.h"
#include "virlog.h"
#include "virfile.h"
#include "virsocketaddr.h"
#include "virutil.h"

#if !defined WIN32 && WITH_LIBTASN1_H && LIBGNUTLS_VERSION_NUMBER >= 0x020600

# define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("tests.nettlshelpers");

/*
 * These store some static data that is needed when
 * encoding extensions in the x509 certs
 */
asn1_node pkix_asn1;
extern const asn1_static_node pkix_asn1_tab[];

/*
 * To avoid consuming random entropy to generate keys,
 * here's one we prepared earlier :-)
 */
gnutls_x509_privkey_t privkey;
# define PRIVATE_KEY \
    "-----BEGIN PRIVATE KEY-----\n" \
    "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDD39t6GRLeEmsYjRGR6\n" \
    "iQiIN2S4zXsgLGS/2GloXdG7K+i/3vEJDt9celZ0DfCLcG6hZANiAAQTJIe13jy7\n" \
    "k4KTXMkHQHEJa/asH263JaPL5kTbfRa6tMq3DS3pzWlOj+NHY/9JzthrKD+Ece+g\n" \
    "2g/POHa0gfXRYXGiHTs8mY0AHFqNNmF38eIVGjOqobIi90MkyI3wx4g=\n" \
    "-----END PRIVATE KEY-----\n"

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
        if (err != GNUTLS_E_BASE64_UNEXPECTED_HEADER_ERROR &&
            err != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
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


void testTLSInit(const char *keyfile)
{
    gnutls_global_init();

    if (asn1_array2tree(pkix_asn1_tab, &pkix_asn1, NULL) != ASN1_SUCCESS)
        abort();

    privkey = testTLSLoadKey();
    if (virFileWriteStr(keyfile, PRIVATE_KEY, 0600) < 0)
        abort();
}


void testTLSCleanup(const char *keyfile)
{
    asn1_delete_structure(&pkix_asn1);
    unlink(keyfile);
}

/*
 * Turns an ASN1 object into a DER encoded byte array
 */
static void testTLSDerEncode(asn1_node src,
                             const char *src_name,
                             gnutls_datum_t * res)
{
    int size;
    char *data = NULL;

    size = 0;
    asn1_der_coding(src, src_name, NULL, &size, NULL);

    data = g_new0(char, size);

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
void
testTLSGenerateCert(struct testTLSCertReq *req,
                    gnutls_x509_crt_t ca)
{
    gnutls_x509_crt_t crt;
    int err;
    static char buffer[1024*1024];
    size_t size = sizeof(buffer);
    char serial[5] = { 1, 2, 3, 4, 0 };
    gnutls_datum_t der;
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
        asn1_node ext = NULL;

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
            VIR_FREE(der.data);
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
        asn1_node ext = NULL;
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
            VIR_FREE(der.data);
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
        asn1_node ext = NULL;

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
            VIR_FREE(der.data);
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
     * If no 'ca' is set then we are self signing
     * the cert. This is done for the root CA certs
     */
    if ((err = gnutls_x509_crt_sign2(crt, ca ? ca : crt, privkey, GNUTLS_DIG_SHA256, 0)) < 0) {
        VIR_WARN("Failed to sign certificate %s", gnutls_strerror(err));
        abort();
    }

    /*
     * Finally write the new cert out to disk
     */
    if ((err = gnutls_x509_crt_export(crt, GNUTLS_X509_FMT_PEM, buffer, &size)) < 0) {
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


void testTLSWriteCertChain(const char *filename,
                           gnutls_x509_crt_t *certs,
                           size_t ncerts)
{
    size_t i;
    VIR_AUTOCLOSE fd = -1;
    int err;
    static char buffer[1024*1024];
    size_t size;

    if ((fd = open(filename, O_WRONLY|O_CREAT, 0600)) < 0) {
        VIR_WARN("Failed to open %s", filename);
        abort();
    }

    for (i = 0; i < ncerts; i++) {
        size = sizeof(buffer);
        if ((err = gnutls_x509_crt_export(certs[i], GNUTLS_X509_FMT_PEM, buffer, &size)) < 0) {
            VIR_WARN("Failed to export certificate %s", gnutls_strerror(err));
            unlink(filename);
            abort();
        }

        if (safewrite(fd, buffer, size) != size) {
            VIR_WARN("Failed to write certificate to %s", filename);
            unlink(filename);
            abort();
        }
    }
}


void testTLSDiscardCert(struct testTLSCertReq *req)
{
    if (!req->crt)
        return;

    g_clear_pointer(&req->crt, gnutls_x509_crt_deinit);

    if (getenv("VIRT_TEST_DEBUG_CERTS") == NULL)
        unlink(req->filename);
}

#endif
