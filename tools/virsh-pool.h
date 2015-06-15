/*
 * virsh-pool.h: Commands to manage storage pool
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

#ifndef VIRSH_POOL_H
# define VIRSH_POOL_H

# include "virsh.h"

virStoragePoolPtr
virshCommandOptPoolBy(vshControl *ctl, const vshCmd *cmd, const char *optname,
                      const char **name, unsigned int flags);

/* default is lookup by Name and UUID */
# define virshCommandOptPool(_ctl, _cmd, _optname, _name)           \
    virshCommandOptPoolBy(_ctl, _cmd, _optname, _name,              \
                          VIRSH_BYUUID | VIRSH_BYNAME)

extern const vshCmdDef storagePoolCmds[];

#endif /* VIRSH_POOL_H */
