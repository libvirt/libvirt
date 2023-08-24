/*
 * virnettlscontext.c: TLS encryption/x509 handling
 *
 * Copyright (C) 2010-2014 Red Hat, Inc.
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

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>

#include "virnettlscontext.h"
#include "virstring.h"

#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "virutil.h"
#include "virlog.h"
#include "virprobe.h"
#include "virthread.h"
#include "configmake.h"

#define LIBVIRT_PKI_DIR SYSCONFDIR "/pki"
#define LIBVIRT_CACERT LIBVIRT_PKI_DIR "/CA/cacert.pem"
#define LIBVIRT_CACRL LIBVIRT_PKI_DIR "/CA/cacrl.pem"
#define LIBVIRT_CLIENTKEY LIBVIRT_PKI_DIR "/libvirt/private/clientkey.pem"
#define LIBVIRT_CLIENTCERT LIBVIRT_PKI_DIR "/libvirt/clientcert.pem"
#define LIBVIRT_SERVERKEY LIBVIRT_PKI_DIR "/libvirt/private/serverkey.pem"
#define LIBVIRT_SERVERCERT LIBVIRT_PKI_DIR "/libvirt/servercert.pem"

#define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("rpc.nettlscontext");

struct _virNetTLSContext {
    virObjectLockable parent;

    gnutls_certificate_credentials_t x509cred;

    bool isServer;
    bool requireValidCert;
    const char *const *x509dnACL;
    char *priority;
};

struct _virNetTLSSession {
    virObjectLockable parent;

    bool handshakeComplete;

    bool isServer;
    char *hostname;
    gnutls_session_t session;
    virNetTLSSessionWriteFunc writeFunc;
    virNetTLSSessionReadFunc readFunc;
    void *opaque;
    char *x509dname;
};

static virClass *virNetTLSContextClass;
static virClass *virNetTLSSessionClass;
static void virNetTLSContextDispose(void *obj);
static void virNetTLSSessionDispose(void *obj);


static int virNetTLSContextOnceInit(void)
{
    if (!VIR_CLASS_NEW(virNetTLSContext, virClassForObjectLockable()))
        return -1;

    if (!VIR_CLASS_NEW(virNetTLSSession, virClassForObjectLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virNetTLSContext);


static int
virNetTLSContextCheckCertFile(const char *type, const char *file, bool allowMissing)
{
    if (!virFileExists(file)) {
        if (allowMissing)
            return 1;

        virReportSystemError(errno,
                             _("Cannot read %1$s '%2$s'"),
                             type, file);
        return -1;
    }
    return 0;
}


static void virNetTLSLog(int level G_GNUC_UNUSED,
                         const char *str G_GNUC_UNUSED)
{
    VIR_DEBUG("%d %s", level, str);
}


static int virNetTLSContextCheckCertTimes(gnutls_x509_crt_t cert,
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


static int virNetTLSContextCheckCertBasicConstraints(gnutls_x509_crt_t cert,
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


static int virNetTLSContextCheckCertKeyUsage(gnutls_x509_crt_t cert,
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


static int virNetTLSContextCheckCertKeyPurpose(gnutls_x509_crt_t cert,
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
virNetTLSContextCheckCertDNACL(const char *dname,
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
virNetTLSContextCheckCertDN(gnutls_x509_crt_t cert,
                            const char *certFile,
                            const char *hostname,
                            const char *dname,
                            const char *const *acl)
{
    if (acl && dname &&
        virNetTLSContextCheckCertDNACL(dname, acl) <= 0)
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


static int virNetTLSContextCheckCert(gnutls_x509_crt_t cert,
                                     const char *certFile,
                                     bool isServer,
                                     bool isCA)
{
    if (virNetTLSContextCheckCertTimes(cert, certFile,
                                       isServer, isCA) < 0)
        return -1;

    if (virNetTLSContextCheckCertBasicConstraints(cert, certFile,
                                                  isServer, isCA) < 0)
        return -1;

    if (virNetTLSContextCheckCertKeyUsage(cert, certFile,
                                          isCA) < 0)
        return -1;

    if (!isCA &&
        virNetTLSContextCheckCertKeyPurpose(cert, certFile,
                                            isServer) < 0)
        return -1;

    return 0;
}


static int virNetTLSContextCheckCertPair(gnutls_x509_crt_t cert,
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


static gnutls_x509_crt_t virNetTLSContextLoadCertFromFile(const char *certFile,
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


static int virNetTLSContextLoadCACertListFromFile(const char *certFile,
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
static int virNetTLSContextSanityCheckCredentials(bool isServer,
                                                  const char *cacertFile,
                                                  const char *certFile)
{
    gnutls_x509_crt_t cert = NULL;
    gnutls_x509_crt_t cacerts[MAX_CERTS] = { 0 };
    size_t ncacerts = 0;
    size_t i;
    int ret = -1;

    if ((access(certFile, R_OK) == 0) &&
        !(cert = virNetTLSContextLoadCertFromFile(certFile, isServer)))
        goto cleanup;
    if ((access(cacertFile, R_OK) == 0) &&
        virNetTLSContextLoadCACertListFromFile(cacertFile, cacerts,
                                               MAX_CERTS, &ncacerts) < 0)
        goto cleanup;

    if (cert &&
        virNetTLSContextCheckCert(cert, certFile, isServer, false) < 0)
        goto cleanup;

    for (i = 0; i < ncacerts; i++) {
        if (virNetTLSContextCheckCert(cacerts[i], cacertFile, isServer, true) < 0)
            goto cleanup;
    }

    if (cert && ncacerts &&
        virNetTLSContextCheckCertPair(cert, certFile, cacerts, ncacerts, cacertFile, isServer) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    if (cert)
        gnutls_x509_crt_deinit(cert);
    for (i = 0; i < ncacerts; i++)
        gnutls_x509_crt_deinit(cacerts[i]);
    return ret;
}


static int virNetTLSContextLoadCredentials(virNetTLSContext *ctxt,
                                           bool isServer,
                                           const char *cacert,
                                           const char *cacrl,
                                           const char *cert,
                                           const char *key)
{
    int err;

    if (cacert && cacert[0] != '\0') {
        if (virNetTLSContextCheckCertFile("CA certificate", cacert, false) < 0)
            return -1;

        VIR_DEBUG("loading CA cert from %s", cacert);
        err = gnutls_certificate_set_x509_trust_file(ctxt->x509cred,
                                                     cacert,
                                                     GNUTLS_X509_FMT_PEM);
        if (err < 0) {
            virReportError(VIR_ERR_SYSTEM_ERROR,
                           _("Unable to set x509 CA certificate: %1$s: %2$s"),
                           cacert, gnutls_strerror(err));
            return -1;
        }
    }

    if (cacrl && cacrl[0] != '\0') {
        int rv;
        if ((rv = virNetTLSContextCheckCertFile("CA revocation list", cacrl, true)) < 0)
            return -1;

        if (rv == 0) {
            VIR_DEBUG("loading CRL from %s", cacrl);
            err = gnutls_certificate_set_x509_crl_file(ctxt->x509cred,
                                                       cacrl,
                                                       GNUTLS_X509_FMT_PEM);
            if (err < 0) {
                virReportError(VIR_ERR_SYSTEM_ERROR,
                               _("Unable to set x509 certificate revocation list: %1$s: %2$s"),
                               cacrl, gnutls_strerror(err));
                return -1;
            }
        } else {
            VIR_DEBUG("Skipping non-existent CA CRL %s", cacrl);
        }
    }

    if (cert && cert[0] != '\0' && key && key[0] != '\0') {
        int rv;
        if ((rv = virNetTLSContextCheckCertFile("certificate", cert, !isServer)) < 0)
            return -1;
        if (rv == 0 &&
            (rv = virNetTLSContextCheckCertFile("private key", key, !isServer)) < 0)
            return -1;

        if (rv == 0) {
            VIR_DEBUG("loading cert and key from %s and %s", cert, key);
            err =
                gnutls_certificate_set_x509_key_file(ctxt->x509cred,
                                                     cert, key,
                                                     GNUTLS_X509_FMT_PEM);
            if (err < 0) {
                virReportError(VIR_ERR_SYSTEM_ERROR,
                               _("Unable to set x509 key and certificate: %1$s, %2$s: %3$s"),
                               key, cert, gnutls_strerror(err));
                return -1;
            }
        } else {
            VIR_DEBUG("Skipping non-existent cert %s key %s on client",
                      cert, key);
        }
    }

    return 0;
}


static virNetTLSContext *virNetTLSContextNew(const char *cacert,
                                               const char *cacrl,
                                               const char *cert,
                                               const char *key,
                                               const char *const *x509dnACL,
                                               const char *priority,
                                               bool sanityCheckCert,
                                               bool requireValidCert,
                                               bool isServer)
{
    virNetTLSContext *ctxt;
    int err;

    if (virNetTLSContextInitialize() < 0)
        return NULL;

    if (!(ctxt = virObjectLockableNew(virNetTLSContextClass)))
        return NULL;

    ctxt->priority = g_strdup(priority);

    err = gnutls_certificate_allocate_credentials(&ctxt->x509cred);
    if (err) {
        /* While gnutls_certificate_credentials_t will free any
         * partially allocated credentials struct, it does not
         * set the returned pointer back to NULL after it is
         * freed in an error path.
         */
        ctxt->x509cred = NULL;

        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("Unable to allocate x509 credentials: %1$s"),
                       gnutls_strerror(err));
        goto error;
    }

    if (sanityCheckCert &&
        virNetTLSContextSanityCheckCredentials(isServer, cacert, cert) < 0)
        goto error;

    if (virNetTLSContextLoadCredentials(ctxt, isServer, cacert, cacrl, cert, key) < 0)
        goto error;

    ctxt->requireValidCert = requireValidCert;
    ctxt->x509dnACL = x509dnACL;
    ctxt->isServer = isServer;

    PROBE(RPC_TLS_CONTEXT_NEW,
          "ctxt=%p cacert=%s cacrl=%s cert=%s key=%s sanityCheckCert=%d requireValidCert=%d isServer=%d",
          ctxt, cacert, NULLSTR(cacrl), cert, key, sanityCheckCert, requireValidCert, isServer);

    return ctxt;

 error:
    virObjectUnref(ctxt);
    return NULL;
}


static int virNetTLSContextLocateCredentials(const char *pkipath,
                                             bool tryUserPkiPath,
                                             bool isServer,
                                             char **cacert,
                                             char **cacrl,
                                             char **cert,
                                             char **key)
{
    char *userdir = NULL;
    char *user_pki_path = NULL;

    *cacert = NULL;
    *cacrl = NULL;
    *key = NULL;
    *cert = NULL;

    VIR_DEBUG("pkipath=%s isServer=%d tryUserPkiPath=%d",
              pkipath, isServer, tryUserPkiPath);

    /* Explicit path, then use that no matter whether the
     * files actually exist there
     */
    if (pkipath) {
        VIR_DEBUG("Told to use TLS credentials in %s", pkipath);
        *cacert = g_strdup_printf("%s/%s", pkipath, "cacert.pem");
        *cacrl = g_strdup_printf("%s/%s", pkipath, "cacrl.pem");
        *key = g_strdup_printf("%s/%s", pkipath,
                               isServer ? "serverkey.pem" : "clientkey.pem");

        *cert = g_strdup_printf("%s/%s", pkipath,
                                isServer ? "servercert.pem" : "clientcert.pem");
    } else if (tryUserPkiPath) {
        /* Check to see if $HOME/.pki contains at least one of the
         * files and if so, use that
         */
        userdir = virGetUserDirectory();

        user_pki_path = g_strdup_printf("%s/.pki/libvirt", userdir);

        VIR_DEBUG("Trying to find TLS user credentials in %s", user_pki_path);

        *cacert = g_strdup_printf("%s/%s", user_pki_path, "cacert.pem");

        *cacrl = g_strdup_printf("%s/%s", user_pki_path, "cacrl.pem");

        *key = g_strdup_printf("%s/%s", user_pki_path,
                               isServer ? "serverkey.pem" : "clientkey.pem");

        *cert = g_strdup_printf("%s/%s", user_pki_path,
                                isServer ? "servercert.pem" : "clientcert.pem");

        /*
         * If some of the files can't be found, fallback
         * to the global location for them
         */
        if (!virFileExists(*cacert))
            VIR_FREE(*cacert);
        if (!virFileExists(*cacrl))
            VIR_FREE(*cacrl);

        /* Check these as a pair, since it they are
         * mutually dependent
         */
        if (!virFileExists(*key) || !virFileExists(*cert)) {
            VIR_FREE(*key);
            VIR_FREE(*cert);
        }
    }

    /* No explicit path, or user path didn't exist, so
     * fallback to global defaults
     */
    if (!*cacert) {
        VIR_DEBUG("Using default TLS CA certificate path");
        *cacert = g_strdup(LIBVIRT_CACERT);
    }

    if (!*cacrl) {
        VIR_DEBUG("Using default TLS CA revocation list path");
        *cacrl = g_strdup(LIBVIRT_CACRL);
    }

    if (!*key && !*cert) {
        VIR_DEBUG("Using default TLS key/certificate path");
        *key = g_strdup(isServer ? LIBVIRT_SERVERKEY : LIBVIRT_CLIENTKEY);

        *cert = g_strdup(isServer ? LIBVIRT_SERVERCERT : LIBVIRT_CLIENTCERT);
    }

    VIR_FREE(user_pki_path);
    VIR_FREE(userdir);

    return 0;
}


static virNetTLSContext *virNetTLSContextNewPath(const char *pkipath,
                                                   bool tryUserPkiPath,
                                                   const char *const *x509dnACL,
                                                   const char *priority,
                                                   bool sanityCheckCert,
                                                   bool requireValidCert,
                                                   bool isServer)
{
    char *cacert = NULL, *cacrl = NULL, *key = NULL, *cert = NULL;
    virNetTLSContext *ctxt = NULL;

    if (virNetTLSContextLocateCredentials(pkipath, tryUserPkiPath, isServer,
                                          &cacert, &cacrl, &cert, &key) < 0)
        return NULL;

    ctxt = virNetTLSContextNew(cacert, cacrl, cert, key,
                               x509dnACL, priority, sanityCheckCert,
                               requireValidCert, isServer);

    VIR_FREE(cacert);
    VIR_FREE(cacrl);
    VIR_FREE(key);
    VIR_FREE(cert);

    return ctxt;
}

virNetTLSContext *virNetTLSContextNewServerPath(const char *pkipath,
                                                  bool tryUserPkiPath,
                                                  const char *const *x509dnACL,
                                                  const char *priority,
                                                  bool sanityCheckCert,
                                                  bool requireValidCert)
{
    return virNetTLSContextNewPath(pkipath, tryUserPkiPath, x509dnACL, priority,
                                   sanityCheckCert, requireValidCert, true);
}

virNetTLSContext *virNetTLSContextNewClientPath(const char *pkipath,
                                                  bool tryUserPkiPath,
                                                  const char *priority,
                                                  bool sanityCheckCert,
                                                  bool requireValidCert)
{
    return virNetTLSContextNewPath(pkipath, tryUserPkiPath, NULL, priority,
                                   sanityCheckCert, requireValidCert, false);
}


virNetTLSContext *virNetTLSContextNewServer(const char *cacert,
                                              const char *cacrl,
                                              const char *cert,
                                              const char *key,
                                              const char *const *x509dnACL,
                                              const char *priority,
                                              bool sanityCheckCert,
                                              bool requireValidCert)
{
    return virNetTLSContextNew(cacert, cacrl, cert, key, x509dnACL, priority,
                               sanityCheckCert, requireValidCert, true);
}


int virNetTLSContextReloadForServer(virNetTLSContext *ctxt,
                                    bool tryUserPkiPath)
{
    gnutls_certificate_credentials_t x509credBak;
    int err;
    g_autofree char *cacert = NULL;
    g_autofree char *cacrl = NULL;
    g_autofree char *cert = NULL;
    g_autofree char *key = NULL;

    x509credBak = g_steal_pointer(&ctxt->x509cred);

    if (virNetTLSContextLocateCredentials(NULL, tryUserPkiPath, true,
                                          &cacert, &cacrl, &cert, &key))
        goto error;

    err = gnutls_certificate_allocate_credentials(&ctxt->x509cred);
    if (err) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("Unable to allocate x509 credentials: %1$s"),
                       gnutls_strerror(err));
        goto error;
    }

    if (virNetTLSContextSanityCheckCredentials(true, cacert, cert))
        goto error;

    if (virNetTLSContextLoadCredentials(ctxt, true, cacert, cacrl, cert, key))
        goto error;

    gnutls_certificate_free_credentials(x509credBak);

    return 0;

 error:
    if (ctxt->x509cred)
        gnutls_certificate_free_credentials(ctxt->x509cred);
    ctxt->x509cred = x509credBak;
    return -1;
}


virNetTLSContext *virNetTLSContextNewClient(const char *cacert,
                                              const char *cacrl,
                                              const char *cert,
                                              const char *key,
                                              const char *priority,
                                              bool sanityCheckCert,
                                              bool requireValidCert)
{
    return virNetTLSContextNew(cacert, cacrl, cert, key, NULL, priority,
                               sanityCheckCert, requireValidCert, false);
}


static int virNetTLSContextValidCertificate(virNetTLSContext *ctxt,
                                            virNetTLSSession *sess)
{
    int ret;
    unsigned int status;
    const gnutls_datum_t *certs;
    unsigned int nCerts;
    size_t i;
    size_t dnamesize = 256;
    g_autofree char *dname = g_new0(char, dnamesize);
    char *dnameptr = dname;

    if ((ret = gnutls_certificate_verify_peers2(sess->session, &status)) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("Unable to verify TLS peer: %1$s"),
                       gnutls_strerror(ret));
        goto authdeny;
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
                       _("Certificate failed validation: %1$s"),
                       reason);
        goto authdeny;
    }

    if (gnutls_certificate_type_get(sess->session) != GNUTLS_CRT_X509) {
        virReportError(VIR_ERR_SYSTEM_ERROR, "%s",
                       _("Only x509 certificates are supported"));
        goto authdeny;
    }

    if (!(certs = gnutls_certificate_get_peers(sess->session, &nCerts))) {
        virReportError(VIR_ERR_SYSTEM_ERROR, "%s",
                       _("The certificate has no peers"));
        goto authdeny;
    }

    for (i = 0; i < nCerts; i++) {
        gnutls_x509_crt_t cert;

        if (gnutls_x509_crt_init(&cert) < 0) {
            virReportError(VIR_ERR_SYSTEM_ERROR, "%s",
                           _("Unable to initialize certificate"));
            goto authfail;
        }

        if (gnutls_x509_crt_import(cert, &certs[i], GNUTLS_X509_FMT_DER) < 0) {
            virReportError(VIR_ERR_SYSTEM_ERROR, "%s",
                           _("Unable to load certificate"));
            gnutls_x509_crt_deinit(cert);
            goto authfail;
        }

        if (virNetTLSContextCheckCertTimes(cert, "[session]",
                                           sess->isServer, i > 0) < 0) {
            gnutls_x509_crt_deinit(cert);
            goto authdeny;
        }

        if (i == 0) {
            ret = gnutls_x509_crt_get_dn(cert, dname, &dnamesize);
            if (ret == GNUTLS_E_SHORT_MEMORY_BUFFER) {
                VIR_DEBUG("Reallocating dname to fit %zu bytes", dnamesize);
                dname = g_realloc(dname, dnamesize);
                dnameptr = dname;
                ret = gnutls_x509_crt_get_dn(cert, dname, &dnamesize);
            }
            if (ret != 0) {
                virReportError(VIR_ERR_SYSTEM_ERROR,
                               _("Failed to get certificate %1$s distinguished name: %2$s"),
                               "[session]", gnutls_strerror(ret));
                goto authfail;
            }
            sess->x509dname = g_steal_pointer(&dname);
            VIR_DEBUG("Peer DN is %s", dnameptr);

            if (virNetTLSContextCheckCertDN(cert, "[session]", sess->hostname,
                                            dnameptr, ctxt->x509dnACL) < 0) {
                gnutls_x509_crt_deinit(cert);
                goto authdeny;
            }

            /* !sess->isServer, since on the client, we're validating the
             * server's cert, and on the server, the client's cert
             */
            if (virNetTLSContextCheckCertBasicConstraints(cert, "[session]",
                                                          !sess->isServer, false) < 0) {
                gnutls_x509_crt_deinit(cert);
                goto authdeny;
            }

            if (virNetTLSContextCheckCertKeyUsage(cert, "[session]",
                                                  false) < 0) {
                gnutls_x509_crt_deinit(cert);
                goto authdeny;
            }

            /* !sess->isServer - as above */
            if (virNetTLSContextCheckCertKeyPurpose(cert, "[session]",
                                                    !sess->isServer) < 0) {
                gnutls_x509_crt_deinit(cert);
                goto authdeny;
            }
        }
        gnutls_x509_crt_deinit(cert);
    }

    PROBE(RPC_TLS_CONTEXT_SESSION_ALLOW,
          "ctxt=%p sess=%p dname=%s",
          ctxt, sess, dnameptr);

    return 0;

 authdeny:
    PROBE(RPC_TLS_CONTEXT_SESSION_DENY,
          "ctxt=%p sess=%p dname=%s",
          ctxt, sess, dnameptr);

    return -1;

 authfail:
    PROBE(RPC_TLS_CONTEXT_SESSION_FAIL,
          "ctxt=%p sess=%p",
          ctxt, sess);

    return -1;
}

int virNetTLSContextCheckCertificate(virNetTLSContext *ctxt,
                                     virNetTLSSession *sess)
{
    int ret = -1;

    virObjectLock(ctxt);
    virObjectLock(sess);
    if (virNetTLSContextValidCertificate(ctxt, sess) < 0) {
        VIR_WARN("Certificate check failed %s", virGetLastErrorMessage());
        if (ctxt->requireValidCert) {
            virReportError(VIR_ERR_AUTH_FAILED, "%s",
                           _("Failed to verify peer's certificate"));
            goto cleanup;
        }
        virResetLastError();
        VIR_INFO("Ignoring bad certificate at user request");
    }

    ret = 0;

 cleanup:
    virObjectUnlock(ctxt);
    virObjectUnlock(sess);

    return ret;
}

void virNetTLSContextDispose(void *obj)
{
    virNetTLSContext *ctxt = obj;

    PROBE(RPC_TLS_CONTEXT_DISPOSE,
          "ctxt=%p", ctxt);

    g_free(ctxt->priority);
    gnutls_certificate_free_credentials(ctxt->x509cred);
}


static ssize_t
virNetTLSSessionPush(void *opaque, const void *buf, size_t len)
{
    virNetTLSSession *sess = opaque;
    if (!sess->writeFunc) {
        VIR_WARN("TLS session push with missing write function");
        errno = EIO;
        return -1;
    };

    return sess->writeFunc(buf, len, sess->opaque);
}


static ssize_t
virNetTLSSessionPull(void *opaque, void *buf, size_t len)
{
    virNetTLSSession *sess = opaque;
    if (!sess->readFunc) {
        VIR_WARN("TLS session pull with missing read function");
        errno = EIO;
        return -1;
    };

    return sess->readFunc(buf, len, sess->opaque);
}


virNetTLSSession *virNetTLSSessionNew(virNetTLSContext *ctxt,
                                        const char *hostname)
{
    virNetTLSSession *sess;
    int err;
    const char *priority;

    VIR_DEBUG("ctxt=%p hostname=%s isServer=%d",
              ctxt, NULLSTR(hostname), ctxt->isServer);

    if (!(sess = virObjectLockableNew(virNetTLSSessionClass)))
        return NULL;

    sess->hostname = g_strdup(hostname);

    if ((err = gnutls_init(&sess->session,
                           ctxt->isServer ? GNUTLS_SERVER : GNUTLS_CLIENT)) != 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("Failed to initialize TLS session: %1$s"),
                       gnutls_strerror(err));
        goto error;
    }

    /* avoid calling all the priority functions, since the defaults
     * are adequate.
     */
    priority = ctxt->priority ? ctxt->priority : TLS_PRIORITY;
    VIR_DEBUG("Setting priority string '%s'", priority);
    if ((err = gnutls_priority_set_direct(sess->session,
                                          priority,
                                          NULL)) != 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("Failed to set TLS session priority to %1$s: %2$s"),
                       priority, gnutls_strerror(err));
        goto error;
    }

    if ((err = gnutls_credentials_set(sess->session,
                                      GNUTLS_CRD_CERTIFICATE,
                                      ctxt->x509cred)) != 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("Failed set TLS x509 credentials: %1$s"),
                       gnutls_strerror(err));
        goto error;
    }

    /* request client certificate if any.
     */
    if (ctxt->isServer) {
        gnutls_certificate_server_set_request(sess->session, GNUTLS_CERT_REQUEST);
    }

    gnutls_transport_set_ptr(sess->session, sess);
    gnutls_transport_set_push_function(sess->session,
                                       virNetTLSSessionPush);
    gnutls_transport_set_pull_function(sess->session,
                                       virNetTLSSessionPull);

    sess->isServer = ctxt->isServer;

    PROBE(RPC_TLS_SESSION_NEW,
          "sess=%p ctxt=%p hostname=%s isServer=%d",
          sess, ctxt, hostname, sess->isServer);

    return sess;

 error:
    virObjectUnref(sess);
    return NULL;
}


void virNetTLSSessionSetIOCallbacks(virNetTLSSession *sess,
                                    virNetTLSSessionWriteFunc writeFunc,
                                    virNetTLSSessionReadFunc readFunc,
                                    void *opaque)
{
    virObjectLock(sess);
    sess->writeFunc = writeFunc;
    sess->readFunc = readFunc;
    sess->opaque = opaque;
    virObjectUnlock(sess);
}


ssize_t virNetTLSSessionWrite(virNetTLSSession *sess,
                              const char *buf, size_t len)
{
    ssize_t ret;

    virObjectLock(sess);
    ret = gnutls_record_send(sess->session, buf, len);

    if (ret >= 0)
        goto cleanup;

    switch (ret) {
    case GNUTLS_E_AGAIN:
        errno = EAGAIN;
        break;
    case GNUTLS_E_INTERRUPTED:
        errno = EINTR;
        break;
    case GNUTLS_E_UNEXPECTED_PACKET_LENGTH:
        errno = ENOMSG;
        break;
    default:
        errno = EIO;
        break;
    }

    ret = -1;

 cleanup:
    virObjectUnlock(sess);
    return ret;
}

ssize_t virNetTLSSessionRead(virNetTLSSession *sess,
                             char *buf, size_t len)
{
    ssize_t ret;

    virObjectLock(sess);
    ret = gnutls_record_recv(sess->session, buf, len);

    if (ret >= 0)
        goto cleanup;

    switch (ret) {
    case GNUTLS_E_AGAIN:
        errno = EAGAIN;
        break;
    case GNUTLS_E_INTERRUPTED:
        errno = EINTR;
        break;
    default:
        errno = EIO;
        break;
    }

    ret = -1;

 cleanup:
    virObjectUnlock(sess);
    return ret;
}

int virNetTLSSessionHandshake(virNetTLSSession *sess)
{
    int ret;
    VIR_DEBUG("sess=%p", sess);
    virObjectLock(sess);
    ret = gnutls_handshake(sess->session);
    VIR_DEBUG("Ret=%d", ret);
    if (ret == 0) {
        sess->handshakeComplete = true;
        VIR_DEBUG("Handshake is complete");
        goto cleanup;
    }
    if (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN) {
        ret = 1;
        goto cleanup;
    }

#if 0
    PROBE(CLIENT_TLS_FAIL, "fd=%d",
          virNetServerClientGetFD(client));
#endif

    virReportError(VIR_ERR_AUTH_FAILED,
                   _("TLS handshake failed %1$s"),
                   gnutls_strerror(ret));
    ret = -1;

 cleanup:
    virObjectUnlock(sess);
    return ret;
}

virNetTLSSessionHandshakeStatus
virNetTLSSessionGetHandshakeStatus(virNetTLSSession *sess)
{
    virNetTLSSessionHandshakeStatus ret;
    virObjectLock(sess);
    if (sess->handshakeComplete)
        ret = VIR_NET_TLS_HANDSHAKE_COMPLETE;
    else if (gnutls_record_get_direction(sess->session) == 0)
        ret = VIR_NET_TLS_HANDSHAKE_RECVING;
    else
        ret = VIR_NET_TLS_HANDSHAKE_SENDING;
    virObjectUnlock(sess);
    return ret;
}

int virNetTLSSessionGetKeySize(virNetTLSSession *sess)
{
    gnutls_cipher_algorithm_t cipher;
    int ssf;
    virObjectLock(sess);
    cipher = gnutls_cipher_get(sess->session);
    if (!(ssf = gnutls_cipher_get_key_size(cipher))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("invalid cipher size for TLS session"));
        ssf = -1;
        goto cleanup;
    }

 cleanup:
    virObjectUnlock(sess);
    return ssf;
}

const char *virNetTLSSessionGetX509DName(virNetTLSSession *sess)
{
    const char *ret = NULL;

    virObjectLock(sess);

    ret = sess->x509dname;

    virObjectUnlock(sess);

    return ret;
}

void virNetTLSSessionDispose(void *obj)
{
    virNetTLSSession *sess = obj;

    PROBE(RPC_TLS_SESSION_DISPOSE,
          "sess=%p", sess);

    g_free(sess->x509dname);
    g_free(sess->hostname);
    gnutls_deinit(sess->session);
}

/*
 * This function MUST be called before any
 * virNetTLS* because it initializes
 * underlying GnuTLS library. According to
 * it's documentation, it's safe to be called
 * many times, but is not thread safe.
 *
 * There is no corresponding "Deinit" / "Cleanup"
 * function because there is no safe way to call
 * 'gnutls_global_deinit' from a multi-threaded
 * library, where other libraries linked into the
 * application may also be using gnutls.
 */
void virNetTLSInit(void)
{
    const char *gnutlsdebug;
    if ((gnutlsdebug = getenv("LIBVIRT_GNUTLS_DEBUG")) != NULL) {
        int val;
        if (virStrToLong_i(gnutlsdebug, NULL, 10, &val) < 0)
            val = 10;
        gnutls_global_set_log_level(val);
        gnutls_global_set_log_function(virNetTLSLog);
        VIR_DEBUG("Enabled GNUTLS debug");
    }

    gnutls_global_init();
}
