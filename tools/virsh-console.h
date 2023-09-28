/*
 * virsh-console.h: A dumb serial console client
 *
 * Copyright (C) 2007, 2010, 2012-2013 Red Hat, Inc.
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

#ifndef WIN32

# include <virsh.h>

int virshRunConsole(vshControl *ctl,
                    virDomainPtr dom,
                    const char *dev_name,
                    const bool resume_domain,
                    unsigned int flags);

#endif /* !WIN32 */
