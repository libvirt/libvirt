/*
 * virnetsshsession.h: ssh transport provider based on libssh2
 *
 * Copyright (C) 2012 Red Hat, Inc.
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

typedef struct _virNetSSHSession virNetSSHSession;
typedef virNetSSHSession *virNetSSHSessionPtr;

virNetSSHSessionPtr virNetSSHSessionNew(void);
void virNetSSHSessionFree(virNetSSHSessionPtr sess);

typedef enum {
    VIR_NET_SSH_HOSTKEY_VERIFY_NORMAL,
    VIR_NET_SSH_HOSTKEY_VERIFY_AUTO_ADD,
    VIR_NET_SSH_HOSTKEY_VERIFY_IGNORE
} virNetSSHHostkeyVerify;

typedef enum {
    VIR_NET_SSH_HOSTKEY_FILE_READONLY = 1 << 0,
    VIR_NET_SSH_HOSTKEY_FILE_CREATE   = 1 << 1,
} virNetSSHHostKeyFileFlags;

int virNetSSHSessionSetChannelCommand(virNetSSHSessionPtr sess,
                                      const char *command);

void virNetSSHSessionAuthReset(virNetSSHSessionPtr sess);

int virNetSSHSessionAuthSetCallback(virNetSSHSessionPtr sess,
                                    virConnectAuthPtr auth);

int virNetSSHSessionAuthAddPasswordAuth(virNetSSHSessionPtr sess,
                                        virURIPtr uri,
                                        const char *username);

int virNetSSHSessionAuthAddAgentAuth(virNetSSHSessionPtr sess,
                                     const char *username);

int virNetSSHSessionAuthAddPrivKeyAuth(virNetSSHSessionPtr sess,
                                       const char *username,
                                       const char *keyfile,
                                       const char *password);

int virNetSSHSessionAuthAddKeyboardAuth(virNetSSHSessionPtr sess,
                                        const char *username,
                                        int tries);

int virNetSSHSessionSetHostKeyVerification(virNetSSHSessionPtr sess,
                                           const char *hostname,
                                           int port,
                                           const char *hostsfile,
                                           virNetSSHHostkeyVerify opt,
                                           unsigned int flags);

int virNetSSHSessionConnect(virNetSSHSessionPtr sess,
                            int sock);

ssize_t virNetSSHChannelRead(virNetSSHSessionPtr sess,
                             char *buf,
                             size_t len);

ssize_t virNetSSHChannelWrite(virNetSSHSessionPtr sess,
                              const char *buf,
                              size_t len);

bool virNetSSHSessionHasCachedData(virNetSSHSessionPtr sess);
