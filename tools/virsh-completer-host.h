/*
 * virsh-completer-host.h: virsh completer callbacks related to host
 *
 * Copyright (C) 2019 Red Hat, Inc.
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

#include "vsh.h"

char **
virshAllocpagesPagesizeCompleter(vshControl *ctl,
                                 const vshCmd *cmd,
                                 unsigned int flags);

char **
virshCellnoCompleter(vshControl *ctl,
                     const vshCmd *cmd,
                     unsigned int flags);

char **
virshNodeCpuCompleter(vshControl *ctl,
                      const vshCmd *cmd,
                      unsigned int flags);

char **
virshNodeSuspendTargetCompleter(vshControl *ctl,
                                const vshCmd *cmd,
                                unsigned int flags);

char **
virshDomainVirtTypeCompleter(vshControl *ctl,
                             const vshCmd *cmd,
                             unsigned int flags);

char **
virshArchCompleter(vshControl *ctl,
                   const vshCmd *cmd,
                   unsigned int flags);

char **
virshCPUModelCompleter(vshControl *ctl,
                       const vshCmd *cmd,
                       unsigned int flags);
