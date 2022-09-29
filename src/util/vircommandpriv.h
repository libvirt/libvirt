/*
 * vircommandpriv.h: Functions for testing virCommand APIs
 *
 * Copyright (C) 2014 Red Hat, Inc.
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

#ifndef LIBVIRT_VIRCOMMANDPRIV_H_ALLOW
# error "vircommandpriv.h may only be included by vircommand.c or test suites"
#endif /* LIBVIRT_VIRCOMMANDPRIV_H_ALLOW */

#pragma once

#include "vircommand.h"

typedef void (*virCommandDryRunCallback)(const char *const*args,
                                         const char *const*env,
                                         const char *input,
                                         char **output,
                                         char **error,
                                         int *status,
                                         void *opaque);

typedef struct _virCommandDryRunToken virCommandDryRunToken;

virCommandDryRunToken * virCommandDryRunTokenNew(void);
void virCommandDryRunTokenFree(virCommandDryRunToken *token);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virCommandDryRunToken, virCommandDryRunTokenFree);

void virCommandSetDryRun(virCommandDryRunToken *tok,
                         virBuffer *buf,
                         bool bufArgLinebreaks,
                         bool bufCommandStripPath,
                         virCommandDryRunCallback cb,
                         void *opaque);

void virCommandPeekSendBuffers(virCommand *cmd,
                               virCommandSendBuffer **buffers,
                               int *nbuffers);
