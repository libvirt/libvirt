/*
 * virebtables.h: Helper APIs for managing ebtables
 *
 * Copyright (C) 2007-2008, 2013 Red Hat, Inc.
 * Copyright (C) 2009 IBM Corp.
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

#include "virmacaddr.h"

typedef struct _ebtablesContext ebtablesContext;

ebtablesContext *ebtablesContextNew              (const char *driver);
void             ebtablesContextFree             (ebtablesContext *ctx);

int              ebtablesAddForwardAllowIn       (ebtablesContext *ctx,
                                                  const char *iface,
                                                  const virMacAddr *mac);
int              ebtablesRemoveForwardAllowIn    (ebtablesContext *ctx,
                                                  const char *iface,
                                                  const virMacAddr *mac);

int              ebtablesAddForwardPolicyReject(ebtablesContext *ctx);
