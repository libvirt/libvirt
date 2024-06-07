/*
 * virnettlscert.c: TLS x509 certificate helpers
 *
 * Copyright (C) 2010-2024 Red Hat, Inc.
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

#include <unistd.h>

#include "virnettlscert.h"

#include "viralloc.h"
#include "virfile.h"
#include "virlog.h"
#include "virerror.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("rpc.nettlscert");

static int virNetTLSCertCheckTimes(gnutls_x509_crt_t cert,
                                   const char *certFile,
                                   bool isServer,
                                   bool isCA)
{
    time_t now;

    if ((now = time(NULL)) == ((time_t)-1)) {
        virReportSystemError(errno, "%s",
                             _("cannot get current time"));
        return -1;
    }

    if (gnutls_x509_crt_get_expiration_time(cert) < now) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       (isCA ?
                        _("The CA certificate %1$s has expired") :
                        (isServer ?
                         _("The server certificate %1$s has expired") :
                         _("The client certificate %1$s has expired"))),
                       certFile);
        return -1;
    }

    if (gnutls_x509_crt_get_activation_time(cert) > now) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       (isCA ?
                        _("The CA certificate %1$s is not yet active") :
                        (isServer ?
                         _("The server certificate %1$s is not yet active") :
                         _("The client certificate %1$s is not yet active"))),
                       certFile);
        return -1;
    }

    return 0;
}


static int virNetTLSCertCheckBasicConstraints(gnutls_x509_crt_t cert,
                                              const char *certFile,
                                              bool isServer,
                                              bool isCA)
{
    int status;

    status = gnutls_x509_crt_get_basic_constraints(cert, NULL, NULL, NULL);
    VIR_DEBUG("Cert %s basic constraints %d", certFile, status);

    if (status > 0) { /* It is a CA cert */
        if (!isCA) {
            virReportError(VIR_ERR_SYSTEM_ERROR, isServer ?
                           _("The certificate %1$s basic constraints show a CA, but we need one for a server") :
                           _("The certificate %1$s basic constraints show a CA, but we need one for a client"),
                           certFile);
            return -1;
        }
    } else if (status == 0) { /* It is not a CA cert */
        if (isCA) {
            virReportError(VIR_ERR_SYSTEM_ERROR,
                           _("The certificate %1$s basic constraints do not show a CA"),
                           certFile);
            return -1;
        }
    } else if (status == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) { /* Missing basicConstraints */
        if (isCA) {
            virReportError(VIR_ERR_SYSTEM_ERROR,
                           _("The certificate %1$s is missing basic constraints for a CA"),
                           certFile);
            return -1;
        }
    } else { /* General error */
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("Unable to query certificate %1$s basic constraints %2$s"),
                       certFile, gnutls_strerror(status));
        return -1;
    }

    return 0;
}


static int virNetTLSCertCheckKeyUsage(gnutls_x509_crt_t cert,
                                      const char *certFile,
                                      bool isCA)
{
    int status;
    unsigned int usage = 0;
    unsigned int critical = 0;

    status = gnutls_x509_crt_get_key_usage(cert, &usage, &critical);

    VIR_DEBUG("Cert %s key usage status %d usage %d critical %u", certFile, status, usage, critical);
    if (status < 0) {
        if (status == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
            usage = isCA ? GNUTLS_KEY_KEY_CERT_SIGN :
                GNUTLS_KEY_DIGITAL_SIGNATURE|GNUTLS_KEY_KEY_ENCIPHERMENT;
        } else {
            virReportError(VIR_ERR_SYSTEM_ERROR,
                           _("Unable to query certificate %1$s key usage %2$s"),
                           certFile, gnutls_strerror(status));
            return -1;
        }
    }

    if (isCA) {
        if (!(usage & GNUTLS_KEY_KEY_CERT_SIGN)) {
            if (critical) {
                virReportError(VIR_ERR_SYSTEM_ERROR,
                               _("Certificate %1$s usage does not permit certificate signing"),
                               certFile);
                return -1;
            } else {
                VIR_WARN("Certificate %s usage does not permit certificate signing",
                         certFile);
            }
        }
    } else {
        if (!(usage & GNUTLS_KEY_DIGITAL_SIGNATURE)) {
            if (critical) {
                virReportError(VIR_ERR_SYSTEM_ERROR,
                               _("Certificate %1$s usage does not permit digital signature"),
                               certFile);
                return -1;
            } else {
                VIR_WARN("Certificate %s usage does not permit digital signature",
                         certFile);
            }
        }
        if (!(usage & GNUTLS_KEY_KEY_ENCIPHERMENT)) {
            if (critical) {
                virReportError(VIR_ERR_SYSTEM_ERROR,
                               _("Certificate %1$s usage does not permit key encipherment"),
                               certFile);
                return -1;
            } else {
                VIR_WARN("Certificate %s usage does not permit key encipherment",
                         certFile);
            }
        }
    }

    return 0;
}


static int virNetTLSCertCheckKeyPurpose(gnutls_x509_crt_t cert,
                                        const char *certFile,
                                        bool isServer)
{
    int status;
    size_t i;
    unsigned int purposeCritical;
    unsigned int critical;
    char *buffer = NULL;
    size_t size;
    bool allowClient = false, allowServer = false;

    critical = 0;
    for (i = 0; ; i++) {
        size = 0;
        status = gnutls_x509_crt_get_key_purpose_oid(cert, i, buffer, &size, NULL);

        if (status == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
            VIR_DEBUG("No key purpose data available at slot %zu", i);

            /* If there is no data at all, then we must allow client/server to pass */
            if (i == 0)
                allowServer = allowClient = true;
            break;
        }
        if (status != GNUTLS_E_SHORT_MEMORY_BUFFER) {
            virReportError(VIR_ERR_SYSTEM_ERROR,
                           _("Unable to query certificate %1$s key purpose %2$s"),
                           certFile, gnutls_strerror(status));
            return -1;
        }

        buffer = g_new0(char, size);
        status = gnutls_x509_crt_get_key_purpose_oid(cert, i, buffer, &size, &purposeCritical);
        if (status < 0) {
            VIR_FREE(buffer);
            virReportError(VIR_ERR_SYSTEM_ERROR,
                           _("Unable to query certificate %1$s key purpose %2$s"),
                           certFile, gnutls_strerror(status));
            return -1;
        }
        if (purposeCritical)
            critical = true;

        VIR_DEBUG("Key purpose %d %s critical %u", status, buffer, purposeCritical);
        if (STREQ(buffer, GNUTLS_KP_TLS_WWW_SERVER)) {
            allowServer = true;
        } else if (STREQ(buffer, GNUTLS_KP_TLS_WWW_CLIENT)) {
            allowClient = true;
        } else if (STRNEQ(buffer, GNUTLS_KP_ANY)) {
            allowServer = allowClient = true;
        }

        VIR_FREE(buffer);
    }

    if (isServer) {
        if (!allowServer) {
            if (critical) {
                virReportError(VIR_ERR_SYSTEM_ERROR,
                               _("Certificate %1$s purpose does not allow use for with a TLS server"),
                               certFile);
                return -1;
            } else {
                VIR_WARN("Certificate %s purpose does not allow use for with a TLS server",
                         certFile);
            }
        }
    } else {
        if (!allowClient) {
            if (critical) {
                virReportError(VIR_ERR_SYSTEM_ERROR,
                               _("Certificate %1$s purpose does not allow use for with a TLS client"),
                               certFile);
                return -1;
            } else {
                VIR_WARN("Certificate %s purpose does not allow use for with a TLS client",
                         certFile);
            }
        }
    }

    return 0;
}

/* Check DN is on tls_allowed_dn_list. */
static int
virNetTLSCertCheckDNACL(const char *dname,
                        const char *const *wildcards)
{
    while (*wildcards) {
        if (g_pattern_match_simple(*wildcards, dname))
            return 1;

        wildcards++;
    }

    /* Log the client's DN for debugging */
    VIR_DEBUG("Failed ACL check for client DN '%s'", dname);

    /* This is the most common error: make it informative. */
    virReportError(VIR_ERR_SYSTEM_ERROR, "%s",
                   _("Client's Distinguished Name is not on the list of allowed clients (tls_allowed_dn_list).  Use 'virt-pki-query-dn clientcert.pem' to view the Distinguished Name field in the client certificate, or run this daemon with --verbose option."));
    return 0;
}


static int
virNetTLSCertCheckDN(gnutls_x509_crt_t cert,
                     const char *certFile,
                     const char *hostname,
                     const char *dname,
                     const char *const *acl)
{
    if (acl && dname &&
        virNetTLSCertCheckDNACL(dname, acl) <= 0)
        return -1;

    if (hostname &&
        !gnutls_x509_crt_check_hostname(cert, hostname)) {
        virReportError(VIR_ERR_RPC,
                       _("Certificate %1$s owner does not match the hostname %2$s"),
                       certFile, hostname);
        return -1;
    }

    return 0;
}


static int virNetTLSCertCheck(gnutls_x509_crt_t cert,
                              const char *certFile,
                              bool isServer,
                              bool isCA)
{
    if (virNetTLSCertCheckTimes(cert, certFile, isServer, isCA) < 0)
        return -1;

    if (virNetTLSCertCheckBasicConstraints(cert, certFile, isServer, isCA) < 0)
        return -1;

    if (virNetTLSCertCheckKeyUsage(cert, certFile, isCA) < 0)
        return -1;

    if (!isCA &&
        virNetTLSCertCheckKeyPurpose(cert, certFile, isServer) < 0)
        return -1;

    return 0;
}


static int virNetTLSCertCheckPair(gnutls_x509_crt_t cert,
                                         const char *certFile,
                                         gnutls_x509_crt_t *cacerts,
                                         size_t ncacerts,
                                         const char *cacertFile,
                                         bool isServer)
{
    unsigned int status;

    if (gnutls_x509_crt_list_verify(&cert, 1,
                                    cacerts, ncacerts,
                                    NULL, 0,
                                    0, &status) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR, isServer ?
                       _("Unable to verify server certificate %1$s against CA certificate %2$s") :
                       _("Unable to verify client certificate %1$s against CA certificate %2$s"),
                       certFile, cacertFile);
        return -1;
    }

    if (status != 0) {
        const char *reason = _("Invalid certificate");

        if (status & GNUTLS_CERT_INVALID)
            reason = _("The certificate is not trusted.");

        if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
            reason = _("The certificate hasn't got a known issuer.");

        if (status & GNUTLS_CERT_REVOKED)
            reason = _("The certificate has been revoked.");

        if (status & GNUTLS_CERT_INSECURE_ALGORITHM)
            reason = _("The certificate uses an insecure algorithm");

        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("Our own certificate %1$s failed validation against %2$s: %3$s"),
                       certFile, cacertFile, reason);
        return -1;
    }

    return 0;
}


gnutls_x509_crt_t virNetTLSCertLoadFromFile(const char *certFile,
                                            bool isServer)
{
    gnutls_datum_t data;
    gnutls_x509_crt_t cert = NULL;
    g_autofree char *buf = NULL;
    int ret = -1;

    VIR_DEBUG("isServer %d certFile %s",
              isServer, certFile);

    if (gnutls_x509_crt_init(&cert) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR, "%s",
                       _("Unable to initialize certificate"));
        goto cleanup;
    }

    if (virFileReadAll(certFile, (1<<16), &buf) < 0)
        goto cleanup;

    data.data = (unsigned char *)buf;
    data.size = strlen(buf);

    if (gnutls_x509_crt_import(cert, &data, GNUTLS_X509_FMT_PEM) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR, isServer ?
                       _("Unable to import server certificate %1$s") :
                       _("Unable to import client certificate %1$s"),
                       certFile);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    if (ret != 0) {
        g_clear_pointer(&cert, gnutls_x509_crt_deinit);
    }
    return cert;
}


static int virNetTLSCertLoadCAListFromFile(const char *certFile,
                                           gnutls_x509_crt_t *certs,
                                           unsigned int certMax,
                                           size_t *ncerts)
{
    gnutls_datum_t data;
    g_autofree char *buf = NULL;

    *ncerts = 0;
    VIR_DEBUG("certFile %s", certFile);

    if (virFileReadAll(certFile, (1<<16), &buf) < 0)
        return -1;

    data.data = (unsigned char *)buf;
    data.size = strlen(buf);

    if (gnutls_x509_crt_list_import(certs, &certMax, &data, GNUTLS_X509_FMT_PEM, 0) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("Unable to import CA certificate list %1$s"),
                       certFile);
        return -1;
    }
    *ncerts = certMax;

    return 0;
}


#define MAX_CERTS 16
int virNetTLSCertSanityCheck(bool isServer,
                             const char *cacertFile,
                             const char *certFile)
{
    gnutls_x509_crt_t cert = NULL;
    gnutls_x509_crt_t cacerts[MAX_CERTS] = { 0 };
    size_t ncacerts = 0;
    size_t i;
    int ret = -1;

    if ((access(certFile, R_OK) == 0) &&
        !(cert = virNetTLSCertLoadFromFile(certFile, isServer)))
        goto cleanup;
    if ((access(cacertFile, R_OK) == 0) &&
        virNetTLSCertLoadCAListFromFile(cacertFile, cacerts,
                                        MAX_CERTS, &ncacerts) < 0)
        goto cleanup;

    if (cert &&
        virNetTLSCertCheck(cert, certFile, isServer, false) < 0)
        goto cleanup;

    for (i = 0; i < ncacerts; i++) {
        if (virNetTLSCertCheck(cacerts[i], cacertFile, isServer, true) < 0)
            goto cleanup;
    }

    if (cert && ncacerts &&
        virNetTLSCertCheckPair(cert, certFile, cacerts, ncacerts, cacertFile, isServer) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    if (cert)
        gnutls_x509_crt_deinit(cert);
    for (i = 0; i < ncacerts; i++)
        gnutls_x509_crt_deinit(cacerts[i]);
    return ret;
}

int virNetTLSCertValidateCA(gnutls_x509_crt_t cert,
                            bool isServer)
{
    if (virNetTLSCertCheckTimes(cert, "[session]",
                                isServer, true) < 0) {
        return -1;
    }
    return 0;
}

char *virNetTLSCertValidate(gnutls_x509_crt_t cert,
                            bool isServer,
                            const char *hostname,
                            const char *const *x509dnACL)
{
    size_t dnamesize = 256;
    g_autofree char *dname = g_new0(char, dnamesize);
    int ret;

    if (virNetTLSCertCheckTimes(cert, "[session]",
                                isServer, false) < 0) {
        return NULL;
    }

    ret = gnutls_x509_crt_get_dn(cert, dname, &dnamesize);
    if (ret == GNUTLS_E_SHORT_MEMORY_BUFFER) {
        VIR_DEBUG("Reallocating dname to fit %zu bytes", dnamesize);
        dname = g_realloc(dname, dnamesize);
        ret = gnutls_x509_crt_get_dn(cert, dname, &dnamesize);
    }
    if (ret != 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("Failed to get certificate %1$s distinguished name: %2$s"),
                       "[session]", gnutls_strerror(ret));
        return NULL;
    }

    VIR_DEBUG("Peer DN is %s", dname);

    if (virNetTLSCertCheckDN(cert, "[session]", hostname,
                             dname, x509dnACL) < 0) {
        return NULL;
    }

    /* !isServer, since on the client, we're validating the
     * server's cert, and on the server, the client's cert
     */
    if (virNetTLSCertCheckBasicConstraints(cert, "[session]",
                                           !isServer, false) < 0) {
        return NULL;
    }

    if (virNetTLSCertCheckKeyUsage(cert, "[session]",
                                   false) < 0) {
        return NULL;
    }

    /* !isServer - as above */
    if (virNetTLSCertCheckKeyPurpose(cert, "[session]",
                                     !isServer) < 0) {
        return NULL;
    }

    return g_steal_pointer(&dname);
}
