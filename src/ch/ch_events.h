/*
 * Copyright Microsoft Corp. 2024
 *
 * ch_events.h: header file for handling Cloud-Hypervisor events
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

#include "ch_monitor.h"

#define CH_EVENT_BUFFER_SZ  PIPE_BUF

typedef enum {
    /* source: vmm */
    VIR_CH_EVENT_VMM_STARTING = 0,
    VIR_CH_EVENT_VMM_SHUTDOWN,

    /* source: vm */
    VIR_CH_EVENT_VM_BOOTING,
    VIR_CH_EVENT_VM_BOOTED,
    VIR_CH_EVENT_VM_REBOOTING,
    VIR_CH_EVENT_VM_REBOOTED,
    VIR_CH_EVENT_VM_SHUTDOWN,
    VIR_CH_EVENT_VM_DELETED,
    VIR_CH_EVENT_VM_PAUSING,
    VIR_CH_EVENT_VM_PAUSED,
    VIR_CH_EVENT_VM_RESUMING,
    VIR_CH_EVENT_VM_RESUMED,
    VIR_CH_EVENT_VM_SNAPSHOTTING,
    VIR_CH_EVENT_VM_SNAPSHOTTED,
    VIR_CH_EVENT_VM_RESTORING,
    VIR_CH_EVENT_VM_RESTORED,

    VIR_CH_EVENT_LAST
} virCHEvent;

VIR_ENUM_DECL(virCHEvent);

int virCHStartEventHandler(virCHMonitor *mon);
void virCHStopEventHandler(virCHMonitor *mon);
