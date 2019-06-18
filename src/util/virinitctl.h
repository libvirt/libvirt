/*
 * virinitctl.h: API for talking to init systems via initctl
 *
 * Copyright (C) 2012-2014 Red Hat, Inc.
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

typedef enum {
    VIR_INITCTL_RUNLEVEL_POWEROFF = 0,
    VIR_INITCTL_RUNLEVEL_1 = 1,
    VIR_INITCTL_RUNLEVEL_2 = 2,
    VIR_INITCTL_RUNLEVEL_3 = 3,
    VIR_INITCTL_RUNLEVEL_4 = 4,
    VIR_INITCTL_RUNLEVEL_5 = 5,
    VIR_INITCTL_RUNLEVEL_REBOOT = 6,

    VIR_INITCTL_RUNLEVEL_LAST
} virInitctlRunLevel;


extern const char *virInitctlFifos[];

int virInitctlSetRunLevel(const char *fifo,
                          virInitctlRunLevel level);
