/*
 * vireventglibwatch.h: GSource impl for sockets
 *
 * Copyright (C) 2015-2020 Red Hat, Inc.
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
 * License along with this library. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "internal.h"

/**
 * virEventGLibCreateSocketWatch:
 * @fd: the file descriptor
 * @condition: the I/O condition
 *
 * Create a new main loop source that is able to
 * monitor the file descriptor @fd for the
 * I/O conditions in @condition.
 *
 * Returns: the new main loop source
 */
GSource *virEventGLibCreateSocketWatch(int fd,
                                       GIOCondition condition);

typedef gboolean (*virEventGLibSocketFunc)(int fd,
                                           GIOCondition condition,
                                           gpointer data);

GSource *virEventGLibAddSocketWatch(int fd,
                                    GIOCondition condition,
                                    GMainContext *context,
                                    virEventGLibSocketFunc func,
                                    gpointer opaque,
                                    GDestroyNotify notify)
    G_GNUC_WARN_UNUSED_RESULT;
