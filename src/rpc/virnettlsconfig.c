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
#include "virlog.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("rpc.nettlscontext");

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

static void virNetTLSConfigIdentity(int isServer,
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
                                   int isServer,
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

void virNetTLSConfigUserIdentity(int isServer,
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

void virNetTLSConfigSystemIdentity(int isServer,
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

void virNetTLSConfigCustomCreds(const char *pkipath,
                                int isServer,
                                char **cacert,
                                char **cacrl,
                                char **cert,
                                char **key)
{
    VIR_DEBUG("Locating creds in custom dir %s", pkipath);
    virNetTLSConfigTrust(pkipath,
                         pkipath,
                         cacert,
                         cacrl);
    virNetTLSConfigIdentity(isServer,
                            pkipath,
                            pkipath,
                            cert,
                            key);
}

void virNetTLSConfigUserCreds(int isServer,
                              char **cacert,
                              char **cacrl,
                              char **cert,
                              char **key)
{
    g_autofree char *pkipath = virNetTLSConfigUserPKIBaseDir();

    VIR_DEBUG("Locating creds in user dir %s", pkipath);

    virNetTLSConfigTrust(pkipath,
                         pkipath,
                         cacert,
                         cacrl);
    virNetTLSConfigIdentity(isServer,
                            pkipath,
                            pkipath,
                            cert,
                            key);
}

void virNetTLSConfigSystemCreds(int isServer,
                                char **cacert,
                                char **cacrl,
                                char **cert,
                                char **key)
{
    VIR_DEBUG("Locating creds in system dir %s", LIBVIRT_PKI_DIR);

    virNetTLSConfigTrust(LIBVIRT_CACERT_DIR,
                         LIBVIRT_CACRL_DIR,
                         cacert,
                         cacrl);
    virNetTLSConfigIdentity(isServer,
                            LIBVIRT_CERT_DIR,
                            LIBVIRT_KEY_DIR,
                            cert,
                            key);
}
