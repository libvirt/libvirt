/*
 * parallels_sdk.h: core driver functions for managing
 * Parallels Cloud Server hosts
 *
 * Copyright (C) 2014 Parallels, Inc.
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

#include <Parallels.h>

#include "parallels_utils.h"

int prlsdkInit(parallelsConnPtr privconn);
void prlsdkDeinit(void);
int prlsdkConnect(parallelsConnPtr privconn);
void prlsdkDisconnect(parallelsConnPtr privconn);
int
prlsdkLoadDomains(parallelsConnPtr privconn);
virDomainObjPtr
prlsdkAddDomain(parallelsConnPtr privconn, const unsigned char *uuid);
int prlsdkUpdateDomain(parallelsConnPtr privconn, virDomainObjPtr dom);
int prlsdkSubscribeToPCSEvents(parallelsConnPtr privconn);
void prlsdkUnsubscribeFromPCSEvents(parallelsConnPtr privconn);
int prlsdkStart(parallelsConnPtr privconn, PRL_HANDLE sdkdom);
int prlsdkKill(parallelsConnPtr privconn, PRL_HANDLE sdkdom);
int prlsdkStop(parallelsConnPtr privconn, PRL_HANDLE sdkdom);
int prlsdkPause(parallelsConnPtr privconn, PRL_HANDLE sdkdom);
int prlsdkResume(parallelsConnPtr privconn, PRL_HANDLE sdkdom);

typedef PRL_RESULT (*prlsdkChangeStateFunc)(parallelsConnPtr privconn, PRL_HANDLE sdkdom);
int
prlsdkDomainChangeState(virDomainPtr domain,
                        prlsdkChangeStateFunc chstate);
int
prlsdkApplyConfig(virConnectPtr conn,
                  virDomainObjPtr dom,
                  virDomainDefPtr new);
int prlsdkCreateVm(virConnectPtr conn, virDomainDefPtr def);
int prlsdkCreateCt(virConnectPtr conn, virDomainDefPtr def);
int
prlsdkUnregisterDomain(parallelsConnPtr privconn, virDomainObjPtr dom);
