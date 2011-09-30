/*
 * virnettlscontext.c: TLS encryption/x509 handling
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
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
 */

#include <config.h>

#include <unistd.h>
#include <fnmatch.h>
#include <stdlib.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include "gnutls_1_0_compat.h"

#include "virnettlscontext.h"

#include "memory.h"
#include "virterror_internal.h"
#include "util.h"
#include "logging.h"
#include "threads.h"
#include "configmake.h"

#define DH_BITS 1024

#define LIBVIRT_PKI_DIR SYSCONFDIR "/pki"
#define LIBVIRT_CACERT LIBVIRT_PKI_DIR "/CA/cacert.pem"
#define LIBVIRT_CACRL LIBVIRT_PKI_DIR "/CA/cacrl.pem"
#define LIBVIRT_CLIENTKEY LIBVIRT_PKI_DIR "/libvirt/private/clientkey.pem"
#define LIBVIRT_CLIENTCERT LIBVIRT_PKI_DIR "/libvirt/clientcert.pem"
#define LIBVIRT_SERVERKEY LIBVIRT_PKI_DIR "/libvirt/private/serverkey.pem"
#define LIBVIRT_SERVERCERT LIBVIRT_PKI_DIR "/libvirt/servercert.pem"

#define VIR_FROM_THIS VIR_FROM_RPC
#define virNetError(code, ...)                                    \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,           \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

struct _virNetTLSContext {
    virMutex lock;
    int refs;

    gnutls_certificate_credentials_t x509cred;
    gnutls_dh_params_t dhParams;

    bool isServer;
    bool requireValidCert;
    const char *const*x509dnWhitelist;
};

struct _virNetTLSSession {
    virMutex lock;

    int refs;

    bool handshakeComplete;

    bool isServer;
    char *hostname;
    gnutls_session_t session;
    virNetTLSSessionWriteFunc writeFunc;
    virNetTLSSessionReadFunc readFunc;
    void *opaque;
};


static int
virNetTLSContextCheckCertFile(const char *type, const char *file, bool allowMissing)
{
    if (!virFileExists(file)) {
        if (allowMissing)
            return 1;

        virReportSystemError(errno,
                             _("Cannot read %s '%s'"),
                             type, file);
        return -1;
    }
    return 0;
}


static void virNetTLSLog(int level ATTRIBUTE_UNUSED,
                         const char *str ATTRIBUTE_UNUSED) {
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
        virNetError(VIR_ERR_SYSTEM_ERROR,
                    (isCA ?
                     _("The CA certificate %s has expired") :
                     (isServer ?
                      _("The server certificate %s has expired") :
                      _("The client certificate %s has expired"))),
                    certFile);
        return -1;
    }

    if (gnutls_x509_crt_get_activation_time(cert) > now) {
        virNetError(VIR_ERR_SYSTEM_ERROR,
                    (isCA ?
                     _("The CA certificate %s is not yet active") :
                     (isServer ?
                      _("The server certificate %s is not yet active") :
                      _("The client certificate %s is not yet active"))),
                    certFile);
        return -1;
    }

    return 0;
}


#ifndef GNUTLS_1_0_COMPAT
/*
 * The gnutls_x509_crt_get_basic_constraints function isn't
 * available in GNUTLS 1.0.x branches. This isn't critical
 * though, since gnutls_certificate_verify_peers2 will do
 * pretty much the same check at runtime, so we can just
 * disable this code
 */
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
            virNetError(VIR_ERR_SYSTEM_ERROR, isServer ?
                        _("The certificate %s basic constraints show a CA, but we need one for a server") :
                        _("The certificate %s basic constraints show a CA, but we need one for a client"),
                        certFile);
            return -1;
        }
    } else if (status == 0) { /* It is not a CA cert */
        if (isCA) {
            virNetError(VIR_ERR_SYSTEM_ERROR,
                        _("The certificate %s basic constraints do not show a CA"),
                        certFile);
            return -1;
        }
    } else if (status == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) { /* Missing basicConstraints */
        if (isCA) {
            virNetError(VIR_ERR_SYSTEM_ERROR,
                        _("The certificate %s is missing basic constraints for a CA"),
                        certFile);
            return -1;
        }
    } else { /* General error */
        virNetError(VIR_ERR_SYSTEM_ERROR,
                    _("Unable to query certificate %s basic constraints %s"),
                    certFile, gnutls_strerror(status));
        return -1;
    }

    return 0;
}
#endif


static int virNetTLSContextCheckCertKeyUsage(gnutls_x509_crt_t cert,
                                             const char *certFile,
                                             bool isCA)
{
    int status;
    unsigned int usage;
    unsigned int critical;

    status = gnutls_x509_crt_get_key_usage(cert, &usage, &critical);

    VIR_DEBUG("Cert %s key usage status %d usage %d critical %u", certFile, status, usage, critical);
    if (status < 0) {
        if (status == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
            usage = isCA ? GNUTLS_KEY_KEY_CERT_SIGN :
                GNUTLS_KEY_DIGITAL_SIGNATURE|GNUTLS_KEY_KEY_ENCIPHERMENT;
        } else {
            virNetError(VIR_ERR_SYSTEM_ERROR,
                        _("Unable to query certificate %s key usage %s"),
                        certFile, gnutls_strerror(status));
            return -1;
        }
    }

    if (isCA) {
        if (!(usage & GNUTLS_KEY_KEY_CERT_SIGN)) {
            if (critical) {
                virNetError(VIR_ERR_SYSTEM_ERROR,
                            _("Certificate %s usage does not permit certificate signing"),
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
                virNetError(VIR_ERR_SYSTEM_ERROR,
                            _("Certificate %s usage does not permit digital signature"),
                            certFile);
                return -1;
            } else {
                VIR_WARN("Certificate %s usage does not permit digital signature",
                         certFile);
            }
        }
        if (!(usage & GNUTLS_KEY_KEY_ENCIPHERMENT)) {
            if (critical) {
                virNetError(VIR_ERR_SYSTEM_ERROR,
                            _("Certificate %s usage does not permit key encipherment"),
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
    int i;
    unsigned int purposeCritical;
    unsigned int critical;
    char *buffer = NULL;
    size_t size;
    bool allowClient = false, allowServer = false;

    critical = 0;
    for (i = 0 ; ; i++) {
        size = 0;
        status = gnutls_x509_crt_get_key_purpose_oid(cert, i, buffer, &size, NULL);

        if (status == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
            VIR_DEBUG("No key purpose data available at slot %d", i);

            /* If there is no data at all, then we must allow client/server to pass */
            if (i == 0)
                allowServer = allowClient = true;
            break;
        }
        if (status != GNUTLS_E_SHORT_MEMORY_BUFFER) {
            virNetError(VIR_ERR_SYSTEM_ERROR,
                        _("Unable to query certificate %s key purpose %s"),
                        certFile, gnutls_strerror(status));
            return -1;
        }

        if (VIR_ALLOC_N(buffer, size) < 0) {
            virReportOOMError();
            return -1;
        }

        status = gnutls_x509_crt_get_key_purpose_oid(cert, i, buffer, &size, &purposeCritical);
        if (status < 0) {
            VIR_FREE(buffer);
            virNetError(VIR_ERR_SYSTEM_ERROR,
                        _("Unable to query certificate %s key purpose %s"),
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
                virNetError(VIR_ERR_SYSTEM_ERROR,
                            _("Certificate %s purpose does not allow use for with a TLS server"),
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
                virNetError(VIR_ERR_SYSTEM_ERROR,
                            _("Certificate %s purpose does not allow use for with a TLS client"),
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
virNetTLSContextCheckCertDNWhitelist(const char *dname,
                                     const char *const*wildcards)
{
    while (*wildcards) {
        int ret = fnmatch (*wildcards, dname, 0);
        if (ret == 0) /* Succesful match */
            return 1;
        if (ret != FNM_NOMATCH) {
            virNetError(VIR_ERR_INTERNAL_ERROR,
                        _("Malformed TLS whitelist regular expression '%s'"),
                        *wildcards);
            return -1;
        }

        wildcards++;
    }

    /* Log the client's DN for debugging */
    VIR_DEBUG("Failed whitelist check for client DN '%s'", dname);

    /* This is the most common error: make it informative. */
    virNetError(VIR_ERR_SYSTEM_ERROR, "%s",
                _("Client's Distinguished Name is not on the list "
                  "of allowed clients (tls_allowed_dn_list).  Use "
                  "'certtool -i --infile clientcert.pem' to view the"
                  "Distinguished Name field in the client certificate,"
                  "or run this daemon with --verbose option."));
    return 0;
}


static int
virNetTLSContextCheckCertDN(gnutls_x509_crt_t cert,
                            const char *certFile,
                            const char *hostname,
                            const char *dname,
                            const char *const* whitelist)
{
    if (whitelist && dname &&
        virNetTLSContextCheckCertDNWhitelist(dname, whitelist) <= 0)
        return -1;

    if (hostname &&
        !gnutls_x509_crt_check_hostname(cert, hostname)) {
        virNetError(VIR_ERR_RPC,
                    _("Certificate %s owner does not match the hostname %s"),
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

#ifndef GNUTLS_1_0_COMPAT
    if (virNetTLSContextCheckCertBasicConstraints(cert, certFile,
                                                  isServer, isCA) < 0)
        return -1;
#endif

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
                                         gnutls_x509_crt_t cacert,
                                         const char *cacertFile,
                                         bool isServer)
{
    unsigned int status;

    if (gnutls_x509_crt_list_verify(&cert, 1,
                                    &cacert, 1,
                                    NULL, 0,
                                    0, &status) < 0) {
        virNetError(VIR_ERR_SYSTEM_ERROR, isServer ?
                    _("Unable to verify server certificate %s against CA certificate %s") :
                    _("Unable to verify client certificate %s against CA certificate %s"),
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

#ifndef GNUTLS_1_0_COMPAT
        if (status & GNUTLS_CERT_INSECURE_ALGORITHM)
            reason = _("The certificate uses an insecure algorithm");
#endif

        virNetError(VIR_ERR_SYSTEM_ERROR,
                    _("Our own certificate %s failed validation against %s: %s"),
                    certFile, cacertFile, reason);
        return -1;
    }

    return 0;
}


static gnutls_x509_crt_t virNetTLSContextLoadCertFromFile(const char *certFile,
                                                          bool isServer,
                                                          bool isCA ATTRIBUTE_UNUSED)
{
    gnutls_datum_t data;
    gnutls_x509_crt_t cert = NULL;
    char *buf = NULL;
    int ret = -1;

    VIR_DEBUG("isServer %d isCA %d certFile %s",
              isServer, isCA, certFile);

    if (gnutls_x509_crt_init(&cert) < 0) {
        virNetError(VIR_ERR_SYSTEM_ERROR, "%s",
                    _("Unable to initialize certificate"));
        goto cleanup;
    }

    if (virFileReadAll(certFile, (1<<16), &buf) < 0)
        goto cleanup;

    data.data = (unsigned char *)buf;
    data.size = strlen(buf);

    if (gnutls_x509_crt_import(cert, &data, GNUTLS_X509_FMT_PEM) < 0) {
        virNetError(VIR_ERR_SYSTEM_ERROR, isServer ?
                    _("Unable to import server certificate %s") :
                    _("Unable to import client certificate %s"),
                    certFile);
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (ret != 0) {
        gnutls_x509_crt_deinit(cert);
        cert = NULL;
    }
    VIR_FREE(buf);
    return cert;
}


static int virNetTLSContextSanityCheckCredentials(bool isServer,
                                                  const char *cacertFile,
                                                  const char *certFile)
{
    gnutls_x509_crt_t cert = NULL;
    gnutls_x509_crt_t cacert = NULL;
    int ret = -1;

    if ((access(certFile, R_OK) == 0) &&
        !(cert = virNetTLSContextLoadCertFromFile(certFile, isServer, false)))
        goto cleanup;
    if ((access(cacertFile, R_OK) == 0) &&
        !(cacert = virNetTLSContextLoadCertFromFile(cacertFile, isServer, false)))
        goto cleanup;

    if (cert &&
        virNetTLSContextCheckCert(cert, certFile, isServer, false) < 0)
        goto cleanup;

    if (cacert &&
        virNetTLSContextCheckCert(cacert, cacertFile, isServer, true) < 0)
        goto cleanup;

    if (cert && cacert &&
        virNetTLSContextCheckCertPair(cert, certFile, cacert, cacertFile, isServer) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    if (cert)
        gnutls_x509_crt_deinit(cert);
    if (cacert)
        gnutls_x509_crt_deinit(cacert);
    return ret;
}


static int virNetTLSContextLoadCredentials(virNetTLSContextPtr ctxt,
                                           bool isServer,
                                           const char *cacert,
                                           const char *cacrl,
                                           const char *cert,
                                           const char *key)
{
    int ret = -1;
    int err;

    if (cacert && cacert[0] != '\0') {
        if (virNetTLSContextCheckCertFile("CA certificate", cacert, false) < 0)
            goto cleanup;

        VIR_DEBUG("loading CA cert from %s", cacert);
        err = gnutls_certificate_set_x509_trust_file(ctxt->x509cred,
                                                     cacert,
                                                     GNUTLS_X509_FMT_PEM);
        if (err < 0) {
            virNetError(VIR_ERR_SYSTEM_ERROR,
                        _("Unable to set x509 CA certificate: %s: %s"),
                        cacert, gnutls_strerror (err));
            goto cleanup;
        }
    }

    if (cacrl && cacrl[0] != '\0') {
        int rv;
        if ((rv = virNetTLSContextCheckCertFile("CA revocation list", cacrl, true)) < 0)
            goto cleanup;

        if (rv == 0) {
            VIR_DEBUG("loading CRL from %s", cacrl);
            err = gnutls_certificate_set_x509_crl_file(ctxt->x509cred,
                                                       cacrl,
                                                       GNUTLS_X509_FMT_PEM);
            if (err < 0) {
                virNetError(VIR_ERR_SYSTEM_ERROR,
                            _("Unable to set x509 certificate revocation list: %s: %s"),
                            cacrl, gnutls_strerror(err));
                goto cleanup;
            }
        } else {
            VIR_DEBUG("Skipping non-existent CA CRL %s", cacrl);
        }
    }

    if (cert && cert[0] != '\0' && key && key[0] != '\0') {
        int rv;
        if ((rv = virNetTLSContextCheckCertFile("certificate", cert, !isServer)) < 0)
            goto cleanup;
        if (rv == 0 &&
            (rv = virNetTLSContextCheckCertFile("private key", key, !isServer)) < 0)
            goto cleanup;

        if (rv == 0) {
            VIR_DEBUG("loading cert and key from %s and %s", cert, key);
            err =
                gnutls_certificate_set_x509_key_file(ctxt->x509cred,
                                                     cert, key,
                                                     GNUTLS_X509_FMT_PEM);
            if (err < 0) {
                virNetError(VIR_ERR_SYSTEM_ERROR,
                            _("Unable to set x509 key and certificate: %s, %s: %s"),
                            key, cert, gnutls_strerror(err));
                goto cleanup;
            }
        } else {
            VIR_DEBUG("Skipping non-existant cert %s key %s on client", cert, key);
        }
    }

    ret = 0;

cleanup:
    return ret;
}


static virNetTLSContextPtr virNetTLSContextNew(const char *cacert,
                                               const char *cacrl,
                                               const char *cert,
                                               const char *key,
                                               const char *const*x509dnWhitelist,
                                               bool sanityCheckCert,
                                               bool requireValidCert,
                                               bool isServer)
{
    virNetTLSContextPtr ctxt;
    char *gnutlsdebug;
    int err;

    if (VIR_ALLOC(ctxt) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (virMutexInit(&ctxt->lock) < 0) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("Failed to initialized mutex"));
        VIR_FREE(ctxt);
        return NULL;
    }

    ctxt->refs = 1;

    if ((gnutlsdebug = getenv("LIBVIRT_GNUTLS_DEBUG")) != NULL) {
        int val;
        if (virStrToLong_i(gnutlsdebug, NULL, 10, &val) < 0)
            val = 10;
        gnutls_global_set_log_level(val);
        gnutls_global_set_log_function(virNetTLSLog);
        VIR_DEBUG("Enabled GNUTLS debug");
    }


    err = gnutls_certificate_allocate_credentials(&ctxt->x509cred);
    if (err) {
        virNetError(VIR_ERR_SYSTEM_ERROR,
                    _("Unable to allocate x509 credentials: %s"),
                    gnutls_strerror(err));
        goto error;
    }

    if (sanityCheckCert &&
        virNetTLSContextSanityCheckCredentials(isServer, cacert, cert) < 0)
        goto error;

    if (virNetTLSContextLoadCredentials(ctxt, isServer, cacert, cacrl, cert, key) < 0)
        goto error;

    /* Generate Diffie Hellman parameters - for use with DHE
     * kx algorithms. These should be discarded and regenerated
     * once a day, once a week or once a month. Depending on the
     * security requirements.
     */
    if (isServer) {
        err = gnutls_dh_params_init(&ctxt->dhParams);
        if (err < 0) {
            virNetError(VIR_ERR_SYSTEM_ERROR,
                        _("Unable to initialize diffie-hellman parameters: %s"),
                        gnutls_strerror(err));
            goto error;
        }
        err = gnutls_dh_params_generate2(ctxt->dhParams, DH_BITS);
        if (err < 0) {
            virNetError(VIR_ERR_SYSTEM_ERROR,
                        _("Unable to generate diffie-hellman parameters: %s"),
                        gnutls_strerror(err));
            goto error;
        }

        gnutls_certificate_set_dh_params(ctxt->x509cred,
                                         ctxt->dhParams);
    }

    ctxt->requireValidCert = requireValidCert;
    ctxt->x509dnWhitelist = x509dnWhitelist;
    ctxt->isServer = isServer;

    PROBE(RPC_TLS_CONTEXT_NEW,
          "ctxt=%p refs=%d cacert=%s cacrl=%s cert=%s key=%s sanityCheckCert=%d requireValidCert=%d isServer=%d",
          ctxt, ctxt->refs, cacert, NULLSTR(cacrl), cert, key, sanityCheckCert, requireValidCert, isServer);

    return ctxt;

error:
    if (isServer)
        gnutls_dh_params_deinit(ctxt->dhParams);
    gnutls_certificate_free_credentials(ctxt->x509cred);
    VIR_FREE(ctxt);
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
        if ((virAsprintf(cacert, "%s/%s", pkipath,
                         "cacert.pem")) < 0)
            goto out_of_memory;
        if ((virAsprintf(cacrl, "%s/%s", pkipath,
                         "cacrl.pem")) < 0)
            goto out_of_memory;
        if ((virAsprintf(key, "%s/%s", pkipath,
                         isServer ? "serverkey.pem" : "clientkey.pem")) < 0)
            goto out_of_memory;

        if ((virAsprintf(cert, "%s/%s", pkipath,
                         isServer ? "servercert.pem" : "clientcert.pem")) < 0)
             goto out_of_memory;
    } else if (tryUserPkiPath) {
        /* Check to see if $HOME/.pki contains at least one of the
         * files and if so, use that
         */
        userdir = virGetUserDirectory(getuid());

        if (!userdir)
            goto out_of_memory;

        if (virAsprintf(&user_pki_path, "%s/.pki/libvirt", userdir) < 0)
            goto out_of_memory;

        VIR_DEBUG("Trying to find TLS user credentials in %s", user_pki_path);

        if ((virAsprintf(cacert, "%s/%s", user_pki_path,
                         "cacert.pem")) < 0)
            goto out_of_memory;

        if ((virAsprintf(cacrl, "%s/%s", user_pki_path,
                         "cacrl.pem")) < 0)
            goto out_of_memory;

        if ((virAsprintf(key, "%s/%s", user_pki_path,
                         isServer ? "serverkey.pem" : "clientkey.pem")) < 0)
            goto out_of_memory;

        if ((virAsprintf(cert, "%s/%s", user_pki_path,
                         isServer ? "servercert.pem" : "clientcert.pem")) < 0)
            goto out_of_memory;

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
        if (!(*cacert = strdup(LIBVIRT_CACERT)))
            goto out_of_memory;
    }

    if (!*cacrl) {
        VIR_DEBUG("Using default TLS CA revocation list path");
        if (!(*cacrl = strdup(LIBVIRT_CACRL)))
            goto out_of_memory;
    }

    if (!*key && !*cert) {
        VIR_DEBUG("Using default TLS key/certificate path");
        if (!(*key = strdup(isServer ? LIBVIRT_SERVERKEY : LIBVIRT_CLIENTKEY)))
            goto out_of_memory;

        if (!(*cert = strdup(isServer ? LIBVIRT_SERVERCERT : LIBVIRT_CLIENTCERT)))
            goto out_of_memory;
    }

    VIR_FREE(user_pki_path);
    VIR_FREE(userdir);

    return 0;

out_of_memory:
    virReportOOMError();
    VIR_FREE(*cacert);
    VIR_FREE(*cacrl);
    VIR_FREE(*key);
    VIR_FREE(*cert);
    VIR_FREE(user_pki_path);
    VIR_FREE(userdir);
    return -1;
}


static virNetTLSContextPtr virNetTLSContextNewPath(const char *pkipath,
                                                   bool tryUserPkiPath,
                                                   const char *const*x509dnWhitelist,
                                                   bool sanityCheckCert,
                                                   bool requireValidCert,
                                                   bool isServer)
{
    char *cacert = NULL, *cacrl = NULL, *key = NULL, *cert = NULL;
    virNetTLSContextPtr ctxt = NULL;

    if (virNetTLSContextLocateCredentials(pkipath, tryUserPkiPath, isServer,
                                          &cacert, &cacrl, &cert, &key) < 0)
        return NULL;

    ctxt = virNetTLSContextNew(cacert, cacrl, cert, key,
                               x509dnWhitelist, sanityCheckCert,
                               requireValidCert, isServer);

    VIR_FREE(cacert);
    VIR_FREE(cacrl);
    VIR_FREE(key);
    VIR_FREE(cert);

    return ctxt;
}

virNetTLSContextPtr virNetTLSContextNewServerPath(const char *pkipath,
                                                  bool tryUserPkiPath,
                                                  const char *const*x509dnWhitelist,
                                                  bool sanityCheckCert,
                                                  bool requireValidCert)
{
    return virNetTLSContextNewPath(pkipath, tryUserPkiPath, x509dnWhitelist,
                                   sanityCheckCert, requireValidCert, true);
}

virNetTLSContextPtr virNetTLSContextNewClientPath(const char *pkipath,
                                                  bool tryUserPkiPath,
                                                  bool sanityCheckCert,
                                                  bool requireValidCert)
{
    return virNetTLSContextNewPath(pkipath, tryUserPkiPath, NULL,
                                   sanityCheckCert, requireValidCert, false);
}


virNetTLSContextPtr virNetTLSContextNewServer(const char *cacert,
                                              const char *cacrl,
                                              const char *cert,
                                              const char *key,
                                              const char *const*x509dnWhitelist,
                                              bool sanityCheckCert,
                                              bool requireValidCert)
{
    return virNetTLSContextNew(cacert, cacrl, cert, key, x509dnWhitelist,
                               sanityCheckCert, requireValidCert, true);
}


virNetTLSContextPtr virNetTLSContextNewClient(const char *cacert,
                                              const char *cacrl,
                                              const char *cert,
                                              const char *key,
                                              bool sanityCheckCert,
                                              bool requireValidCert)
{
    return virNetTLSContextNew(cacert, cacrl, cert, key, NULL,
                               sanityCheckCert, requireValidCert, false);
}


void virNetTLSContextRef(virNetTLSContextPtr ctxt)
{
    virMutexLock(&ctxt->lock);
    ctxt->refs++;
    PROBE(RPC_TLS_CONTEXT_REF,
          "ctxt=%p refs=%d",
          ctxt, ctxt->refs);
    virMutexUnlock(&ctxt->lock);
}


static int virNetTLSContextValidCertificate(virNetTLSContextPtr ctxt,
                                            virNetTLSSessionPtr sess)
{
    int ret;
    unsigned int status;
    const gnutls_datum_t *certs;
    unsigned int nCerts, i;
    char dname[256];
    size_t dnamesize = sizeof(dname);

    memset(dname, 0, dnamesize);

    if ((ret = gnutls_certificate_verify_peers2(sess->session, &status)) < 0){
        virNetError(VIR_ERR_SYSTEM_ERROR,
                    _("Unable to verify TLS peer: %s"),
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

#ifndef GNUTLS_1_0_COMPAT
        if (status & GNUTLS_CERT_INSECURE_ALGORITHM)
            reason = _("The certificate uses an insecure algorithm");
#endif

        virNetError(VIR_ERR_SYSTEM_ERROR,
                    _("Certificate failed validation: %s"),
                    reason);
        goto authdeny;
    }

    if (gnutls_certificate_type_get(sess->session) != GNUTLS_CRT_X509) {
        virNetError(VIR_ERR_SYSTEM_ERROR, "%s",
                    _("Only x509 certificates are supported"));
        goto authdeny;
    }

    if (!(certs = gnutls_certificate_get_peers(sess->session, &nCerts))) {
        virNetError(VIR_ERR_SYSTEM_ERROR, "%s",
                    _("The certificate has no peers"));
        goto authdeny;
    }

    for (i = 0; i < nCerts; i++) {
        gnutls_x509_crt_t cert;

        if (gnutls_x509_crt_init(&cert) < 0) {
            virNetError(VIR_ERR_SYSTEM_ERROR, "%s",
                        _("Unable to initialize certificate"));
            goto authfail;
        }

        if (gnutls_x509_crt_import(cert, &certs[i], GNUTLS_X509_FMT_DER) < 0) {
            virNetError(VIR_ERR_SYSTEM_ERROR, "%s",
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
            if (ret != 0) {
                virNetError(VIR_ERR_SYSTEM_ERROR,
                            _("Failed to get certificate %s distinguished name: %s"),
                            "[session]", gnutls_strerror(ret));
                goto authfail;
            }
            VIR_DEBUG("Peer DN is %s", dname);

            if (virNetTLSContextCheckCertDN(cert, "[session]", sess->hostname, dname,
                                            ctxt->x509dnWhitelist) < 0) {
                gnutls_x509_crt_deinit(cert);
                goto authdeny;
            }

            /* !sess->isServer, since on the client, we're validating the
             * server's cert, and on the server, the client's cert
             */
#ifndef GNUTLS_1_0_COMPAT
            if (virNetTLSContextCheckCertBasicConstraints(cert, "[session]",
                                                          !sess->isServer, false) < 0) {
                gnutls_x509_crt_deinit(cert);
                goto authdeny;
            }
#endif

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
          ctxt, sess, dname);

    return 0;

authdeny:
    PROBE(RPC_TLS_CONTEXT_SESSION_DENY,
          "ctxt=%p sess=%p dname=%s",
          ctxt, sess, dname);

    return -1;

authfail:
    PROBE(RPC_TLS_CONTEXT_SESSION_FAIL,
          "ctxt=%p sess=%p",
          ctxt, sess);

    return -1;
}

int virNetTLSContextCheckCertificate(virNetTLSContextPtr ctxt,
                                     virNetTLSSessionPtr sess)
{
    int ret = -1;

    virMutexLock(&ctxt->lock);
    virMutexLock(&sess->lock);
    if (virNetTLSContextValidCertificate(ctxt, sess) < 0) {
        virErrorPtr err = virGetLastError();
        VIR_WARN("Certificate check failed %s", err && err->message ? err->message : "<unknown>");
        if (ctxt->requireValidCert) {
            virNetError(VIR_ERR_AUTH_FAILED, "%s",
                        _("Failed to verify peer's certificate"));
            goto cleanup;
        }
        virResetLastError();
        VIR_INFO("Ignoring bad certificate at user request");
    }

    ret = 0;

cleanup:
    virMutexUnlock(&ctxt->lock);
    virMutexUnlock(&sess->lock);

    return ret;
}

void virNetTLSContextFree(virNetTLSContextPtr ctxt)
{
    if (!ctxt)
        return;

    virMutexLock(&ctxt->lock);
    PROBE(RPC_TLS_CONTEXT_FREE,
          "ctxt=%p refs=%d",
          ctxt, ctxt->refs);
    ctxt->refs--;
    if (ctxt->refs > 0) {
        virMutexUnlock(&ctxt->lock);
        return;
    }

    gnutls_dh_params_deinit(ctxt->dhParams);
    gnutls_certificate_free_credentials(ctxt->x509cred);
    virMutexUnlock(&ctxt->lock);
    virMutexDestroy(&ctxt->lock);
    VIR_FREE(ctxt);
}



static ssize_t
virNetTLSSessionPush(void *opaque, const void *buf, size_t len)
{
    virNetTLSSessionPtr sess = opaque;
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
    virNetTLSSessionPtr sess = opaque;
    if (!sess->readFunc) {
        VIR_WARN("TLS session pull with missing read function");
        errno = EIO;
        return -1;
    };

    return sess->readFunc(buf, len, sess->opaque);
}


virNetTLSSessionPtr virNetTLSSessionNew(virNetTLSContextPtr ctxt,
                                        const char *hostname)
{
    virNetTLSSessionPtr sess;
    int err;

    VIR_DEBUG("ctxt=%p hostname=%s isServer=%d",
              ctxt, NULLSTR(hostname), ctxt->isServer);

    if (VIR_ALLOC(sess) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (virMutexInit(&sess->lock) < 0) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("Failed to initialized mutex"));
        VIR_FREE(sess);
        return NULL;
    }

    sess->refs = 1;
    if (hostname &&
        !(sess->hostname = strdup(hostname))) {
        virReportOOMError();
        goto error;
    }

    if ((err = gnutls_init(&sess->session,
                           ctxt->isServer ? GNUTLS_SERVER : GNUTLS_CLIENT)) != 0) {
        virNetError(VIR_ERR_SYSTEM_ERROR,
                    _("Failed to initialize TLS session: %s"),
                    gnutls_strerror(err));
        goto error;
    }

    /* avoid calling all the priority functions, since the defaults
     * are adequate.
     */
    if ((err = gnutls_set_default_priority(sess->session)) != 0) {
        virNetError(VIR_ERR_SYSTEM_ERROR,
                    _("Failed to set TLS session priority %s"),
                    gnutls_strerror(err));
        goto error;
    }

    if ((err = gnutls_credentials_set(sess->session,
                                      GNUTLS_CRD_CERTIFICATE,
                                      ctxt->x509cred)) != 0) {
        virNetError(VIR_ERR_SYSTEM_ERROR,
                    _("Failed set TLS x509 credentials: %s"),
                    gnutls_strerror(err));
        goto error;
    }

    /* request client certificate if any.
     */
    if (ctxt->isServer) {
        gnutls_certificate_server_set_request(sess->session, GNUTLS_CERT_REQUEST);

        gnutls_dh_set_prime_bits(sess->session, DH_BITS);
    }

    gnutls_transport_set_ptr(sess->session, sess);
    gnutls_transport_set_push_function(sess->session,
                                       virNetTLSSessionPush);
    gnutls_transport_set_pull_function(sess->session,
                                       virNetTLSSessionPull);

    sess->isServer = ctxt->isServer;

    PROBE(RPC_TLS_SESSION_NEW,
          "sess=%p refs=%d ctxt=%p hostname=%s isServer=%d",
          sess, sess->refs, ctxt, hostname, sess->isServer);

    return sess;

error:
    virNetTLSSessionFree(sess);
    return NULL;
}


void virNetTLSSessionRef(virNetTLSSessionPtr sess)
{
    virMutexLock(&sess->lock);
    sess->refs++;
    PROBE(RPC_TLS_SESSION_REF,
          "sess=%p refs=%d",
          sess, sess->refs);
    virMutexUnlock(&sess->lock);
}

void virNetTLSSessionSetIOCallbacks(virNetTLSSessionPtr sess,
                                    virNetTLSSessionWriteFunc writeFunc,
                                    virNetTLSSessionReadFunc readFunc,
                                    void *opaque)
{
    virMutexLock(&sess->lock);
    sess->writeFunc = writeFunc;
    sess->readFunc = readFunc;
    sess->opaque = opaque;
    virMutexUnlock(&sess->lock);
}


ssize_t virNetTLSSessionWrite(virNetTLSSessionPtr sess,
                              const char *buf, size_t len)
{
    ssize_t ret;

    virMutexLock(&sess->lock);
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
    virMutexUnlock(&sess->lock);
    return ret;
}

ssize_t virNetTLSSessionRead(virNetTLSSessionPtr sess,
                             char *buf, size_t len)
{
    ssize_t ret;

    virMutexLock(&sess->lock);
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
    virMutexUnlock(&sess->lock);
    return ret;
}

int virNetTLSSessionHandshake(virNetTLSSessionPtr sess)
{
    int ret;
    VIR_DEBUG("sess=%p", sess);
    virMutexLock(&sess->lock);
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

    virNetError(VIR_ERR_AUTH_FAILED,
                _("TLS handshake failed %s"),
                gnutls_strerror(ret));
    ret = -1;

cleanup:
    virMutexUnlock(&sess->lock);
    return ret;
}

virNetTLSSessionHandshakeStatus
virNetTLSSessionGetHandshakeStatus(virNetTLSSessionPtr sess)
{
    virNetTLSSessionHandshakeStatus ret;
    virMutexLock(&sess->lock);
    if (sess->handshakeComplete)
        ret = VIR_NET_TLS_HANDSHAKE_COMPLETE;
    else if (gnutls_record_get_direction(sess->session) == 0)
        ret = VIR_NET_TLS_HANDSHAKE_RECVING;
    else
        ret = VIR_NET_TLS_HANDSHAKE_SENDING;
    virMutexUnlock(&sess->lock);
    return ret;
}

int virNetTLSSessionGetKeySize(virNetTLSSessionPtr sess)
{
    gnutls_cipher_algorithm_t cipher;
    int ssf;
    virMutexLock(&sess->lock);
    cipher = gnutls_cipher_get(sess->session);
    if (!(ssf = gnutls_cipher_get_key_size(cipher))) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("invalid cipher size for TLS session"));
        ssf = -1;
        goto cleanup;
    }

cleanup:
    virMutexUnlock(&sess->lock);
    return ssf;
}


void virNetTLSSessionFree(virNetTLSSessionPtr sess)
{
    if (!sess)
        return;

    virMutexLock(&sess->lock);
    PROBE(RPC_TLS_SESSION_FREE,
          "sess=%p refs=%d",
          sess, sess->refs);
    sess->refs--;
    if (sess->refs > 0) {
        virMutexUnlock(&sess->lock);
        return;
    }

    VIR_FREE(sess->hostname);
    gnutls_deinit(sess->session);
    virMutexUnlock(&sess->lock);
    virMutexDestroy(&sess->lock);
    VIR_FREE(sess);
}

/*
 * This function MUST be called before any
 * virNetTLS* because it initializes
 * underlying GnuTLS library. According to
 * it's documentation, it's safe to be called
 * many times, but is not thread safe. Each
 * call SHOULD be later followed by
 * virNetTLSContextDeinit.
 */
void virNetTLSInit(void)
{
    gnutls_global_init();
}
