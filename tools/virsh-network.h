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
 *
 *  Daniel Veillard <veillard@redhat.com>
 *  Karel Zak <kzak@redhat.com>
 *  Daniel P. Berrange <berrange@redhat.com>
 *
 */

#ifndef VIRSH_NETWORK_H
# define VIRSH_NETWORK_H

# include "virsh.h"

virNetworkPtr
vshCommandOptNetworkBy(vshControl *ctl, const vshCmd *cmd,
                       const char **name, unsigned int flags);

/* default is lookup by Name and UUID */
# define vshCommandOptNetwork(_ctl, _cmd, _name)                    \
    vshCommandOptNetworkBy(_ctl, _cmd, _name,                      \
                           VSH_BYUUID|VSH_BYNAME)

extern const vshCmdDef networkCmds[];

#endif /* VIRSH_NETWORK_H */
