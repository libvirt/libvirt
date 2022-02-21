/*
 * virsh-completer-domain.h: virsh completer callbacks related to domains
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
virshDomainNameCompleter(vshControl *ctl,
                         const vshCmd *cmd,
                         unsigned int flags);

enum {
    VIRSH_DOMAIN_INTERFACE_COMPLETER_MAC = 1 << 0, /* Return just MACs */
};

char **
virshDomainInterfaceCompleter(vshControl *ctl,
                              const vshCmd *cmd,
                              unsigned int flags);

char **
virshDomainDiskTargetCompleter(vshControl *ctl,
                               const vshCmd *cmd,
                               unsigned int flags);

char **
virshDomainInterfaceStateCompleter(vshControl *ctl,
                                   const vshCmd *cmd,
                                   unsigned int flags);

char **
virshDomainDeviceAliasCompleter(vshControl *ctl,
                                const vshCmd *cmd,
                                unsigned int flags);

char **
virshDomainShutdownModeCompleter(vshControl *ctl,
                                 const vshCmd *cmd,
                                 unsigned int flags);

char **
virshDomainInterfaceAddrSourceCompleter(vshControl *ctl,
                                        const vshCmd *cmd,
                                        unsigned int flags);

char **
virshDomainInterfaceSourceModeCompleter(vshControl *ctl,
                                        const vshCmd *cmd,
                                        unsigned int flags);

char **
virshDomainHostnameSourceCompleter(vshControl *ctl,
                                   const vshCmd *cmd,
                                   unsigned int flags);

char **
virshDomainPerfEnableCompleter(vshControl *ctl,
                               const vshCmd *cmd,
                               unsigned int flags);

char **
virshDomainPerfDisableCompleter(vshControl *ctl,
                                const vshCmd *cmd,
                                unsigned int flags);

char **
virshDomainUUIDCompleter(vshControl *ctl,
                         const vshCmd *cmd,
                         unsigned int flags);

char **
virshDomainIOThreadIdCompleter(vshControl *ctl,
                               const vshCmd *cmd,
                               unsigned int flags);

char **
virshDomainVcpuCompleter(vshControl *ctl,
                         const vshCmd *cmd,
                         unsigned int flags);

char **
virshDomainVcpulistCompleter(vshControl *ctl,
                             const vshCmd *cmd,
                             unsigned int flags);

char **
virshDomainCpulistCompleter(vshControl *ctl,
                            const vshCmd *cmd,
                            unsigned int flags);

char **
virshDomainVcpulistViaAgentCompleter(vshControl *ctl,
                                     const vshCmd *cmd,
                                     unsigned int flags);

char **
virshDomainConsoleCompleter(vshControl *ctl,
                            const vshCmd *cmd,
                            unsigned int flags);

char **
virshDomainSignalCompleter(vshControl *ctl,
                           const vshCmd *cmd,
                           unsigned int flags);

char **
virshDomainLifecycleCompleter(vshControl *ctl,
                              const vshCmd *cmd,
                              unsigned int flags);

char **
virshDomainLifecycleActionCompleter(vshControl *ctl,
                                    const vshCmd *cmd,
                                    unsigned int flags);

char **
virshCodesetNameCompleter(vshControl *ctl,
                          const vshCmd *cmd,
                          unsigned int flags);

char **
virshKeycodeNameCompleter(vshControl *ctl,
                          const vshCmd *cmd,
                          unsigned int flags);

char **
virshDomainFSMountpointsCompleter(vshControl *ctl,
                                  const vshCmd *cmd,
                                  unsigned int flags);

char **
virshDomainCoreDumpFormatCompleter(vshControl *ctl,
                                   const vshCmd *cmd,
                                   unsigned int flags);

char **
virshDomainMigrateCompMethodsCompleter(vshControl *ctl,
                                       const vshCmd *cmd,
                                       unsigned int flags);


char **
virshDomainStorageFileFormatCompleter(vshControl *ctl,
                                      const vshCmd *cmd,
                                      unsigned int flags);

char **
virshDomainMigrateDisksCompleter(vshControl *ctl,
                                 const vshCmd *cmd,
                                 unsigned int completeflags);

char **
virshDomainUndefineStorageDisksCompleter(vshControl *ctl,
                                 const vshCmd *cmd,
                                 unsigned int completeflags);

char **
virshDomainBlockjobBaseTopCompleter(vshControl *ctl,
                                    const vshCmd *cmd,
                                    unsigned int flags);

char **
virshDomainNumatuneModeCompleter(vshControl *ctl,
                                 const vshCmd *cmd,
                                 unsigned int flags);
char **
virshDomainDirtyRateCalcModeCompleter(vshControl *ctl,
                                      const vshCmd *cmd,
                                      unsigned int flags);
