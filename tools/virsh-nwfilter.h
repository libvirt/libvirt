/*
 * virsh-nwfilter.h: Commands to manage network filters
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

virNWFilterPtr
virshCommandOptNWFilterBy(vshControl *ctl, const vshCmd *cmd,
                          const char **name, unsigned int flags);

virNWFilterBindingPtr
virshCommandOptNWFilterBindingBy(vshControl *ctl, const vshCmd *cmd,
                                 const char **name, unsigned int flags);

/* default is lookup by Name and UUID */
#define virshCommandOptNWFilter(_ctl, _cmd, _name) \
    virshCommandOptNWFilterBy(_ctl, _cmd, _name, \
                              VIRSH_BYUUID | VIRSH_BYNAME)

/* default is lookup by port dev */
#define virshCommandOptNWFilterBinding(_ctl, _cmd, _name) \
    virshCommandOptNWFilterBindingBy(_ctl, _cmd, _name, 0)

extern const vshCmdDef nwfilterCmds[];
