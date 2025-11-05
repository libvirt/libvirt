/*
 * virnettlsconfig.c: TLS x509 configuration helpers
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

#include "virnettlsconfig.h"
#include "viralloc.h"
#include "virlog.h"
#include "virutil.h"
#include "virfile.h"
#include "virerror.h"

#define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("rpc.nettlsconfig");

char *virNetTLSConfigUserPKIBaseDir(void)
{
    g_autofree char *userdir = virGetUserDirectory();

    return g_strdup_printf("%s/.pki/libvirt", userdir);
}

static void virNetTLSConfigTrust(const char *cacertdir,
                                 const char *cacrldir,
                                 char **cacert,
                                 char **cacrl)
{
    if (!*cacert)
        *cacert = g_strdup_printf("%s/%s", cacertdir, "cacert.pem");
    if (!*cacrl)
        *cacrl = g_strdup_printf("%s/%s", cacrldir, "cacrl.pem");

    VIR_DEBUG("TLS CA cert %s", *cacert);
    VIR_DEBUG("TLS CA CRL %s", *cacrl);
}

static void virNetTLSConfigIdentity(bool isServer,
                                    const char *certdir,
                                    const char *keydir,
                                    char **cert,
                                    char **key)
{
    if (!*key)
        *key = g_strdup_printf("%s/%s", keydir,
                               isServer ? "serverkey.pem" : "clientkey.pem");
    if (!*cert)
        *cert = g_strdup_printf("%s/%s", certdir,
                                isServer ? "servercert.pem" : "clientcert.pem");

    VIR_DEBUG("TLS key %s", *key);
    VIR_DEBUG("TLS cert %s", *cert);
}

void virNetTLSConfigCustomTrust(const char *pkipath,
                                char **cacert,
                                char **cacrl)
{
    VIR_DEBUG("Locating trust chain in custom dir %s", pkipath);
    virNetTLSConfigTrust(pkipath,
                         pkipath,
                         cacert,
                         cacrl);
}

void virNetTLSConfigUserTrust(char **cacert,
                              char **cacrl)
{
    g_autofree char *pkipath = virNetTLSConfigUserPKIBaseDir();

    VIR_DEBUG("Locating trust chain in user dir %s", pkipath);

    virNetTLSConfigTrust(pkipath,
                         pkipath,
                         cacert,
                         cacrl);
}

void virNetTLSConfigSystemTrust(char **cacert,
                                char **cacrl)
{
    VIR_DEBUG("Locating trust chain in system dir %s", LIBVIRT_PKI_DIR);

    virNetTLSConfigTrust(LIBVIRT_CACERT_DIR,
                         LIBVIRT_CACRL_DIR,
                         cacert,
                         cacrl);
}

void virNetTLSConfigCustomIdentity(const char *pkipath,
                                   bool isServer,
                                   char **cert,
                                   char **key)
{
    VIR_DEBUG("Locating creds in custom dir %s", pkipath);
    virNetTLSConfigIdentity(isServer,
                            pkipath,
                            pkipath,
                            cert,
                            key);
}

void virNetTLSConfigUserIdentity(bool isServer,
                                 char **cert,
                                 char **key)
{
    g_autofree char *pkipath = virNetTLSConfigUserPKIBaseDir();

    VIR_DEBUG("Locating creds in user dir %s", pkipath);

    virNetTLSConfigIdentity(isServer,
                            pkipath,
                            pkipath,
                            cert,
                            key);
}

void virNetTLSConfigSystemIdentity(bool isServer,
                                   char **cert,
                                   char **key)
{
    VIR_DEBUG("Locating creds in system dir %s", LIBVIRT_PKI_DIR);

    virNetTLSConfigIdentity(isServer,
                            LIBVIRT_CERT_DIR,
                            LIBVIRT_KEY_DIR,
                            cert,
                            key);
}


int virNetTLSConfigCheckTrust(const char *cacert, const char *cacrl,
                              bool *cacertExists, bool *cacrlExists,
                              bool allowMissingCA)
{
    if (cacertExists)
        *cacertExists = true;
    if (cacrlExists)
        *cacrlExists = true;
    VIR_DEBUG("Checking CA certificate '%s' and CRL '%s'", cacert, NULLSTR(cacrl));
    if (!virFileExists(cacert)) {
        if (allowMissingCA) {
            VIR_DEBUG("CA certificate '%s' does not exist", cacert);
            if (cacertExists)
                *cacertExists = false;
        } else {
            virReportSystemError(errno, _("CA certificate '%1$s' does not exist"),
                             cacert);
            return -1;
        }
    }
    if (cacrl != NULL && !virFileExists(cacrl)) {
        VIR_DEBUG("CA CRL '%s' does not exist", cacrl);
        if (cacrlExists)
            *cacrlExists = false;
    }
    return 0;
}

static int virNetTLSConfigEnsureTrust(char **cacert, char **cacrl,
                                      bool allowMissingCA)
{
    bool cacertExists, cacrlExists;

    if (virNetTLSConfigCheckTrust(*cacert, *cacrl,
                                  &cacertExists, &cacrlExists,
                                  allowMissingCA) < 0)
        return -1;

    if (!cacertExists)
        VIR_FREE(*cacert);
    if (!cacrlExists)
        VIR_FREE(*cacrl);

    return 0;
}

int virNetTLSConfigCheckIdentity(const char *cert, const char *key,
                                 bool *identityExists, bool allowMissing)
{
    if (identityExists)
        *identityExists = true;
    VIR_DEBUG("Checking certificate '%s' and key '%s'", cert, key);
    if (!virFileExists(cert)) {
        int saved_errno = errno;
        if (allowMissing) {
            if (virFileExists(key)) {
                virReportSystemError(
                    saved_errno,
                    _("Certificate '%1$s' does not exist, but key '%2$s' does"),
                    cert, key);
                return -1;
            }
            if (identityExists)
                *identityExists = false;
            VIR_DEBUG("Missing cert '%s' / key '%s'", cert, key);
            return 0;
        } else {
            virReportSystemError(saved_errno, _("Certificate '%1$s' does not exist"),
                                 cert);
            return -1;
        }
    } else {
        if (!virFileExists(key)) {
            virReportSystemError(errno,
                                 _("Key '%1$s' does not exist, but certificate '%2$s' does"),
                                 key, cert);
            return -1;
        }
    }

    return 0;
}


static int virNetTLSConfigEnsureIdentity(char **cert, char **key,
                                         bool allowMissing)
{
    bool identityExists;

    if (virNetTLSConfigCheckIdentity(*cert, *key, &identityExists,
                                     allowMissing) < 0)
      return -1;

    if (!identityExists) {
        VIR_FREE(*cert);
        VIR_FREE(*key);
    }

    return 0;
}


static int virNetTLSConfigCreds(const char *cacertdir,
                                const char *cacrldir,
                                const char *certdir,
                                const char *keydir,
                                bool isServer,
                                bool allowMissingCA,
                                bool allowMissingIdentity,
                                char **cacert,
                                char **cacrl,
                                char **cert,
                                char **key)
{
    virNetTLSConfigTrust(cacertdir,
                         cacrldir,
                         cacert,
                         cacrl);

    if (virNetTLSConfigEnsureTrust(cacert, cacrl, allowMissingCA) < 0)
        return -1;

    virNetTLSConfigIdentity(isServer,
                            certdir,
                            keydir,
                            cert,
                            key);

    if (virNetTLSConfigEnsureIdentity(cert, key, allowMissingIdentity) < 0)
        return -1;

    return 0;
}


int virNetTLSConfigCustomCreds(const char *pkipath,
                               bool isServer,
                               char **cacert,
                               char **cacrl,
                               char **cert,
                               char **key)
{
    VIR_DEBUG("Locating creds in custom dir %s", pkipath);

    return virNetTLSConfigCreds(pkipath, pkipath,
                                pkipath, pkipath,
                                isServer,
                                false,
                                !isServer,
                                cacert, cacrl,
                                cert, key);
}


int virNetTLSConfigUserCreds(bool isServer,
                             char **cacert,
                             char **cacrl,
                             char **cert,
                             char **key)
{
    g_autofree char *pkipath = virNetTLSConfigUserPKIBaseDir();

    VIR_DEBUG("Locating creds in user dir %s", pkipath);

    return virNetTLSConfigCreds(pkipath, pkipath,
                                pkipath, pkipath,
                                isServer,
                                true,
                                true,
                                cacert, cacrl,
                                cert, key);
}

int virNetTLSConfigSystemCreds(bool isServer,
                               char **cacert,
                               char **cacrl,
                               char **cert,
                               char **key)
{
    VIR_DEBUG("Locating creds in system dir %s", LIBVIRT_PKI_DIR);

    return virNetTLSConfigCreds(LIBVIRT_CACERT_DIR,
                                LIBVIRT_CACRL_DIR,
                                LIBVIRT_CERT_DIR,
                                LIBVIRT_KEY_DIR,
                                isServer,
                                false,
                                !isServer,
                                cacert, cacrl,
                                cert, key);
}
