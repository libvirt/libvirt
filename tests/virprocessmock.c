/*
 * Copyright (C) 2019 Red Hat, Inc.
 * Copyright (C) 2019 IBM Corp.
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
 */

#include <config.h>
#include "virprocess.h"

int
virProcessGetMaxMemLock(pid_t pid G_GNUC_UNUSED,
                        unsigned long long *bytes)
{
    *bytes = 0;
    return 0;
}

int
virProcessSetMaxMemLock(pid_t pid G_GNUC_UNUSED, unsigned long long bytes G_GNUC_UNUSED)
{
    return 0;
}
