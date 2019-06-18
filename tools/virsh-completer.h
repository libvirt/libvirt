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

char ** virshDomainNameCompleter(vshControl *ctl,
                                 const vshCmd *cmd,
                                 unsigned int flags);

enum {
    VIRSH_DOMAIN_INTERFACE_COMPLETER_MAC = 1 << 0, /* Return just MACs */
};

char ** virshDomainInterfaceCompleter(vshControl *ctl,
                                      const vshCmd *cmd,
                                      unsigned int flags);

char ** virshDomainDiskTargetCompleter(vshControl *ctl,
                                       const vshCmd *cmd,
                                       unsigned int flags);

char ** virshStoragePoolNameCompleter(vshControl *ctl,
                                      const vshCmd *cmd,
                                      unsigned int flags);

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

char ** virshSnapshotNameCompleter(vshControl *ctl,
                                   const vshCmd *cmd,
                                   unsigned int flags);

char ** virshAllocpagesPagesizeCompleter(vshControl *ctl,
                                         const vshCmd *cmd,
                                         unsigned int flags);

char ** virshSecretEventNameCompleter(vshControl *ctl,
                                      const vshCmd *cmd,
                                      unsigned int flags);

char ** virshDomainEventNameCompleter(vshControl *ctl,
                                      const vshCmd *cmd,
                                      unsigned int flags);

char ** virshPoolEventNameCompleter(vshControl *ctl,
                                    const vshCmd *cmd,
                                    unsigned int flags);

char ** virshDomainInterfaceStateCompleter(vshControl *ctl,
                                           const vshCmd *cmd,
                                           unsigned int flags);

char ** virshNodedevEventNameCompleter(vshControl *ctl,
                                       const vshCmd *cmd,
                                       unsigned int flags);

char ** virshDomainDeviceAliasCompleter(vshControl *ctl,
                                        const vshCmd *cmd,
                                        unsigned int flags);

char ** virshCellnoCompleter(vshControl *ctl,
                             const vshCmd *cmd,
                             unsigned int flags);

char ** virshDomainShutdownModeCompleter(vshControl *ctl,
                                         const vshCmd *cmd,
                                         unsigned int flags);
