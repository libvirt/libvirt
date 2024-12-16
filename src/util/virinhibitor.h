/*
 * virinhibitor.h: helper APIs for inhibiting host actions
 *
 * Copyright (C) 2024 Red Hat, Inc.
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

#include "internal.h"

typedef struct _virInhibitor virInhibitor;

typedef enum {
    VIR_INHIBITOR_WHAT_NONE          = 0,
    VIR_INHIBITOR_WHAT_SLEEP         = (1 << 1),
    VIR_INHIBITOR_WHAT_SHUTDOWN      = (1 << 2),
    VIR_INHIBITOR_WHAT_IDLE          = (1 << 3),
    VIR_INHIBITOR_WHAT_POWER_KEY     = (1 << 4),
    VIR_INHIBITOR_WHAT_SUSPEND_KEY   = (1 << 5),
    VIR_INHIBITOR_WHAT_HIBERNATE_KEY = (1 << 6),
    VIR_INHIBITOR_WHAT_LID_SWITCH    = (1 << 7),
} virInhibitorWhat;

typedef enum {
    VIR_INHIBITOR_MODE_BLOCK,
    VIR_INHIBITOR_MODE_DELAY,

    VIR_INHIBITOR_MODE_LAST
} virInhibitorMode;

typedef void (*virInhibitorAction)(bool inhibited,
                                   void *opaque);

virInhibitor *virInhibitorNew(virInhibitorWhat what,
                              const char *who,
                              const char *why,
                              virInhibitorMode mode,
                              virInhibitorAction action,
                              void *actionData);

void virInhibitorHold(virInhibitor *inhibitor);
void virInhibitorRelease(virInhibitor *inhibitor);

void virInhibitorFree(virInhibitor *inhibitor);
