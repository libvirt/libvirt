/*
 * virnettlsconfig.h: TLS x509 configuration helpers
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

#pragma once

#include "configmake.h"

#define LIBVIRT_PKI_DIR SYSCONFDIR "/pki"
#define LIBVIRT_CACERT_DIR LIBVIRT_PKI_DIR "/CA"
#define LIBVIRT_CACRL_DIR LIBVIRT_PKI_DIR "/CA"
#define LIBVIRT_KEY_DIR LIBVIRT_PKI_DIR "/libvirt/private"
#define LIBVIRT_CERT_DIR LIBVIRT_PKI_DIR "/libvirt"

char *virNetTLSConfigUserPKIBaseDir(void);

void virNetTLSConfigCustomTrust(const char *pkipath,
                                char **cacert,
                                char **cacrl);
void virNetTLSConfigUserTrust(char **cacert,
                              char **cacrl);
void virNetTLSConfigSystemTrust(char **cacert,
                                char **cacrl);

void virNetTLSConfigCustomIdentity(const char *pkipath,
                                   int isServer,
                                   char **cert,
                                   char **key);
void virNetTLSConfigUserIdentity(int isServer,
                                 char **cert,
                                 char **key);
void virNetTLSConfigSystemIdentity(int isServer,
                                   char **cert,
                                   char **key);


void virNetTLSConfigCustomCreds(const char *pkipath,
                                int isServer,
                                char **cacert,
                                char **cacrl,
                                char **cert,
                                char **key);
void virNetTLSConfigUserCreds(int isServer,
                              char **cacert,
                              char **cacrl,
                              char **cert,
                              char **key);
void virNetTLSConfigSystemCreds(int isServer,
                                char **cacert,
                                char **cacrl,
                                char **cert,
                                char **key);
