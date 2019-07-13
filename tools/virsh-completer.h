/*
 * virsh-completer.h: virsh completer callbacks
 *
 * Copyright (C) 2017 Red Hat, Inc.
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

#include "virsh-completer-domain.h"
#include "virsh-completer-pool.h"

char ** virshCommaStringListComplete(const char *input,
                                     const char **options);

char ** virshStorageVolNameCompleter(vshControl *ctl,
                                     const vshCmd *cmd,
                                     unsigned int flags);

char ** virshInterfaceNameCompleter(vshControl *ctl,
                                    const vshCmd *cmd,
                                    unsigned int flags);

char ** virshNetworkNameCompleter(vshControl *ctl,
                                  const vshCmd *cmd,
                                  unsigned int flags);

char ** virshNetworkEventNameCompleter(vshControl *ctl,
                                       const vshCmd *cmd,
                                       unsigned int flags);

char ** virshNetworkPortUUIDCompleter(vshControl *ctl,
                                      const vshCmd *cmd,
                                      unsigned int flags);

char ** virshNodeDeviceNameCompleter(vshControl *ctl,
                                     const vshCmd *cmd,
                                     unsigned int flags);

char ** virshNWFilterNameCompleter(vshControl *ctl,
                                   const vshCmd *cmd,
                                   unsigned int flags);

char ** virshNWFilterBindingNameCompleter(vshControl *ctl,
                                          const vshCmd *cmd,
                                          unsigned int flags);

char ** virshSecretUUIDCompleter(vshControl *ctl,
                                 const vshCmd *cmd,
                                 unsigned int flags);

char ** virshCheckpointNameCompleter(vshControl *ctl,
                                     const vshCmd *cmd,
                                     unsigned int flags);

char ** virshSnapshotNameCompleter(vshControl *ctl,
                                   const vshCmd *cmd,
                                   unsigned int flags);

char ** virshAllocpagesPagesizeCompleter(vshControl *ctl,
                                         const vshCmd *cmd,
                                         unsigned int flags);

char ** virshSecretEventNameCompleter(vshControl *ctl,
                                      const vshCmd *cmd,
                                      unsigned int flags);

char ** virshNodeDeviceEventNameCompleter(vshControl *ctl,
                                          const vshCmd *cmd,
                                          unsigned int flags);

char ** virshNodeDeviceCapabilityNameCompleter(vshControl *ctl,
                                               const vshCmd *cmd,
                                               unsigned int flags);

char ** virshCellnoCompleter(vshControl *ctl,
                             const vshCmd *cmd,
                             unsigned int flags);
