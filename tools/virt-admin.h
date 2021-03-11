/*
 * virt-admin.h: a shell to exercise the libvirt admin API
 *
 * Copyright (C) 2015 Red Hat, Inc.
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
#include "vsh.h"

#define VIR_FROM_THIS VIR_FROM_NONE

/*
 * Command group types
 */

typedef struct _vshAdmControl vshAdmControl;

/*
 * adminControl
 */
struct _vshAdmControl {
    virAdmConnectPtr conn;      /* connection to a daemon's admin server */
    bool wantReconnect;
};
