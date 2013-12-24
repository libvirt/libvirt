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
 *
 * Authors:
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_INITCTL_H__
# define __VIR_INITCTL_H__

typedef enum virInitctlRunLevel virInitctlRunLevel;
enum virInitctlRunLevel {
    VIR_INITCTL_RUNLEVEL_POWEROFF = 0,
    VIR_INITCTL_RUNLEVEL_1 = 1,
    VIR_INITCTL_RUNLEVEL_2 = 2,
    VIR_INITCTL_RUNLEVEL_3 = 3,
    VIR_INITCTL_RUNLEVEL_4 = 4,
    VIR_INITCTL_RUNLEVEL_5 = 5,
    VIR_INITCTL_RUNLEVEL_REBOOT = 6,

    VIR_INITCTL_RUNLEVEL_LAST
};

int virInitctlSetRunLevel(virInitctlRunLevel level);

#endif
