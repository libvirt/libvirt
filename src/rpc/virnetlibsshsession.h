/*
 * virnetlibsshsession.h: ssh transport provider based on libssh
 *
 * Copyright (C) 2012-2016 Red Hat, Inc.
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

#include "internal.h"
#include "viruri.h"

typedef struct _virNetLibsshSession virNetLibsshSession;

virNetLibsshSession *virNetLibsshSessionNew(const char *username);
void virNetLibsshSessionFree(virNetLibsshSession *sess);

typedef enum {
    VIR_NET_LIBSSH_HOSTKEY_VERIFY_NORMAL,
    VIR_NET_LIBSSH_HOSTKEY_VERIFY_AUTO_ADD,
    VIR_NET_LIBSSH_HOSTKEY_VERIFY_IGNORE
} virNetLibsshHostkeyVerify;

void virNetLibsshSessionSetChannelCommand(virNetLibsshSession *sess,
                                          const char *command);

int virNetLibsshSessionAuthSetCallback(virNetLibsshSession *sess,
                                       virConnectAuthPtr auth);

int virNetLibsshSessionAuthAddPasswordAuth(virNetLibsshSession *sess,
                                           virURI *uri);

int virNetLibsshSessionAuthAddAgentAuth(virNetLibsshSession *sess);

int virNetLibsshSessionAuthAddPrivKeyAuth(virNetLibsshSession *sess,
                                          const char *keyfile);

int virNetLibsshSessionAuthAddKeyboardAuth(virNetLibsshSession *sess,
                                           int tries);

int virNetLibsshSessionSetHostKeyVerification(virNetLibsshSession *sess,
                                              const char *hostname,
                                              int port,
                                              const char *hostsfile,
                                              virNetLibsshHostkeyVerify opt);

int virNetLibsshSessionConnect(virNetLibsshSession *sess,
                               int sock);

ssize_t virNetLibsshChannelRead(virNetLibsshSession *sess,
                                char *buf,
                                size_t len);

ssize_t virNetLibsshChannelWrite(virNetLibsshSession *sess,
                                 const char *buf,
                                 size_t len);

bool virNetLibsshSessionHasCachedData(virNetLibsshSession *sess);
