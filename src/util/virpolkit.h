/*
 * virpolkit.h: helpers for using polkit APIs
 *
 * Copyright (C) 2013 Red Hat, Inc.
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

#ifndef LIBVIRT_VIRPOLKIT_H
# define LIBVIRT_VIRPOLKIT_H

# include "internal.h"
# include "vircommand.h"

# define PKTTYAGENT "/usr/bin/pkttyagent"

int virPolkitCheckAuth(const char *actionid,
                       pid_t pid,
                       unsigned long long startTime,
                       uid_t uid,
                       const char **details,
                       bool allowInteraction);

typedef struct _virPolkitAgent virPolkitAgent;
typedef virPolkitAgent *virPolkitAgentPtr;

void virPolkitAgentDestroy(virPolkitAgentPtr cmd);
virPolkitAgentPtr virPolkitAgentCreate(void);

#endif /* LIBVIRT_VIRPOLKIT_H */
