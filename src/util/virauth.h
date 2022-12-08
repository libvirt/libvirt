/*
 * virauth.h: authentication related utility functions
 *
 * Copyright (C) 2013 Red Hat, Inc.
 * Copyright (C) 2010 Matthias Bolte <matthias.bolte@googlemail.com>
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
 */

#pragma once

#include "internal.h"
#include "viruri.h"

int virAuthGetConfigFilePath(virConnectPtr conn,
                             char **path);

int virAuthGetConfigFilePathURI(virURI *uri,
                                char **path);


char *virAuthGetUsername(virConnectPtr conn,
                         virConnectAuthPtr auth,
                         const char *servicename,
                         const char *defaultUsername,
                         const char *hostname);
char *virAuthGetPassword(virConnectPtr conn,
                         virConnectAuthPtr auth,
                         const char *servicename,
                         const char *username,
                         const char *hostname);
int virAuthGetCredential(const char *servicename,
                         const char *hostname,
                         const char *credname,
                         const char *path,
                         char **value);
char * virAuthGetUsernamePath(const char *path,
                              virConnectAuthPtr auth,
                              const char *servicename,
                              const char *defaultUsername,
                              const char *hostname);
char * virAuthGetPasswordPath(const char *path,
                              virConnectAuthPtr auth,
                              const char *servicename,
                              const char *username,
                              const char *hostname);

virConnectCredential *virAuthAskCredential(virConnectAuthPtr auth,
                                           const char *prompt,
                                           bool echo);

void virAuthConnectCredentialFree(virConnectCredential *cred);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virConnectCredential, virAuthConnectCredentialFree);
