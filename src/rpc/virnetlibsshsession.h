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
typedef virNetLibsshSession *virNetLibsshSessionPtr;

virNetLibsshSessionPtr virNetLibsshSessionNew(const char *username);
void virNetLibsshSessionFree(virNetLibsshSessionPtr sess);

typedef enum {
    VIR_NET_LIBSSH_HOSTKEY_VERIFY_NORMAL,
    VIR_NET_LIBSSH_HOSTKEY_VERIFY_AUTO_ADD,
    VIR_NET_LIBSSH_HOSTKEY_VERIFY_IGNORE
} virNetLibsshHostkeyVerify;

int virNetLibsshSessionSetChannelCommand(virNetLibsshSessionPtr sess,
                                         const char *command);

int virNetLibsshSessionAuthSetCallback(virNetLibsshSessionPtr sess,
                                       virConnectAuthPtr auth);

int virNetLibsshSessionAuthAddPasswordAuth(virNetLibsshSessionPtr sess,
                                           virURIPtr uri);

int virNetLibsshSessionAuthAddAgentAuth(virNetLibsshSessionPtr sess);

int virNetLibsshSessionAuthAddPrivKeyAuth(virNetLibsshSessionPtr sess,
                                          const char *keyfile,
                                          const char *password);

int virNetLibsshSessionAuthAddKeyboardAuth(virNetLibsshSessionPtr sess,
                                           int tries);

int virNetLibsshSessionSetHostKeyVerification(virNetLibsshSessionPtr sess,
                                              const char *hostname,
                                              int port,
                                              const char *hostsfile,
                                              virNetLibsshHostkeyVerify opt);

int virNetLibsshSessionConnect(virNetLibsshSessionPtr sess,
                               int sock);

ssize_t virNetLibsshChannelRead(virNetLibsshSessionPtr sess,
                                char *buf,
                                size_t len);

ssize_t virNetLibsshChannelWrite(virNetLibsshSessionPtr sess,
                                 const char *buf,
                                 size_t len);

bool virNetLibsshSessionHasCachedData(virNetLibsshSessionPtr sess);
