/*
 * viridentity.h: helper APIs for managing user identities
 *
 * Copyright (C) 2012-2013 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#pragma once

#include "internal.h"
#include <glib-object.h>
#include "virtypedparam.h"

#define VIR_TYPE_IDENTITY vir_identity_get_type()
G_DECLARE_FINAL_TYPE(virIdentity, vir_identity, VIR, IDENTITY, GObject);

#define VIR_IDENTITY_AUTORESTORE __attribute__((cleanup(virIdentityRestoreHelper)))

virIdentity *virIdentityGetCurrent(void);
int virIdentitySetCurrent(virIdentity *ident);
virIdentity *virIdentityElevateCurrent(void);

void virIdentityRestoreHelper(virIdentity **identptr);

int virIdentityIsCurrentElevated(void);
virIdentity *virIdentityGetSystem(void);

virIdentity *virIdentityNew(void);
virIdentity *virIdentityNewCopy(virIdentity *src);

int virIdentityGetUserName(virIdentity *ident,
                           const char **username);
int virIdentityGetUNIXUserID(virIdentity *ident,
                             uid_t *uid);
int virIdentityGetGroupName(virIdentity *ident,
                            const char **groupname);
int virIdentityGetUNIXGroupID(virIdentity *ident,
                              gid_t *gid);
int virIdentityGetProcessID(virIdentity *ident,
                            pid_t *pid);
int virIdentityGetProcessTime(virIdentity *ident,
                              unsigned long long *timestamp);
int virIdentityGetSASLUserName(virIdentity *ident,
                               const char **username);
int virIdentityGetX509DName(virIdentity *ident,
                            const char **dname);
int virIdentityGetSELinuxContext(virIdentity *ident,
                                 const char **context);
int virIdentityGetSystemToken(virIdentity *ident,
                              const char **token);


int virIdentitySetUserName(virIdentity *ident,
                           const char *username);
int virIdentitySetUNIXUserID(virIdentity *ident,
                             uid_t uid);
int virIdentitySetGroupName(virIdentity *ident,
                            const char *groupname);
int virIdentitySetUNIXGroupID(virIdentity *ident,
                              gid_t gid);
int virIdentitySetProcessID(virIdentity *ident,
                            pid_t pid);
int virIdentitySetProcessTime(virIdentity *ident,
                              unsigned long long timestamp);
int virIdentitySetSASLUserName(virIdentity *ident,
                               const char *username);
int virIdentitySetX509DName(virIdentity *ident,
                            const char *dname);
int virIdentitySetSELinuxContext(virIdentity *ident,
                                 const char *context);
int virIdentitySetSystemToken(virIdentity *ident,
                              const char *token);

int virIdentitySetParameters(virIdentity *ident,
                             virTypedParameterPtr params,
                             int nparams);

virTypedParamList *virIdentityGetParameters(virIdentity *ident);
