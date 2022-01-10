/*
 * virsh-network.h: Commands to manage network
 *
 * Copyright (C) 2005, 2007-2012 Red Hat, Inc.
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

#include "virsh.h"

virNetworkPtr
virshCommandOptNetworkBy(vshControl *ctl, const vshCmd *cmd,
                         const char **name, unsigned int flags);

virNetworkPortPtr
virshCommandOptNetworkPort(vshControl *ctl, const vshCmd *cmd,
                           virNetworkPtr net,
                           const char **name);

/* default is lookup by Name and UUID */
#define virshCommandOptNetwork(_ctl, _cmd, _name) \
    virshCommandOptNetworkBy(_ctl, _cmd, _name, \
                             VIRSH_BYUUID | VIRSH_BYNAME)

struct virshNetworkEventCallback {
    const char *name;
    virConnectNetworkEventGenericCallback cb;
};
typedef struct virshNetworkEventCallback virshNetworkEventCallback;

extern virshNetworkEventCallback virshNetworkEventCallbacks[];

VIR_ENUM_DECL(virshNetworkUpdateCommand);
VIR_ENUM_DECL(virshNetworkSection);

extern const vshCmdDef networkCmds[];
