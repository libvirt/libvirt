/*
 * qemu_fd.h: QEMU fd and fdpass passing helpers
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

#include "vircommand.h"
#include "qemu_monitor.h"

typedef struct _qemuFDPass qemuFDPass;

void
qemuFDPassFree(qemuFDPass *fdpass);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuFDPass, qemuFDPassFree);

qemuFDPass *
qemuFDPassNew(const char *prefix,
              void *dompriv);
qemuFDPass *
qemuFDPassNewDirect(const char *prefix,
                    void *dompriv);

int
qemuFDPassAddFD(qemuFDPass *fdpass,
                int *fd,
                const char *suffix);

void
qemuFDPassTransferCommand(qemuFDPass *fdpass,
                          virCommand *cmd);

int
qemuFDPassTransferMonitor(qemuFDPass *fdpass,
                          qemuMonitor *mon);

void
qemuFDPassTransferMonitorFake(qemuFDPass *fdpass);

void
qemuFDPassTransferMonitorRollback(qemuFDPass *fdpass,
                                  qemuMonitor *mon);

const char *
qemuFDPassGetPath(qemuFDPass *fdpass);
