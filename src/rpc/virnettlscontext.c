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
#include "virnettlsconfig.h"
#include "virnettlscert.h"
#include "virstring.h"

#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "virutil.h"
#include "virlog.h"
#include "virprobe.h"
#include "virthread.h"

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
        virNetTLSCertSanityCheck(isServer, cacert, cert) < 0)
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
        virNetTLSConfigCustomCreds(pkipath, isServer,
                                   cacert, cacrl,
                                   cert, key);
    } else if (tryUserPkiPath) {
        virNetTLSConfigUserCreds(isServer,
                                 cacert, cacrl,
                                 cert, key);

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

    virNetTLSConfigSystemCreds(isServer,
                               cacert, cacrl,
                               cert, key);

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

    if (virNetTLSCertSanityCheck(true, cacert, cert))
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

        if (i == 0) {
            if (!(sess->x509dname = virNetTLSCertValidate(cert,
                                                          sess->isServer,
                                                          sess->hostname,
                                                          ctxt->x509dnACL))) {
                gnutls_x509_crt_deinit(cert);
                goto authdeny;
            }
        } else {
            if (virNetTLSCertValidateCA(cert,
                                        sess->isServer) < 0) {
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
