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

#ifndef __VIR_COMMAND_PRIV_H_ALLOW__
# error "vircommandpriv.h may only be included by vircommand.c or test suites"
#endif

#ifndef __VIR_COMMAND_PRIV_H__
# define __VIR_COMMAND_PRIV_H__

# include "vircommand.h"

typedef void (*virCommandDryRunCallback)(const char *const*args,
                                         const char *const*env,
                                         const char *input,
                                         char **output,
                                         char **error,
                                         int *status,
                                         void *opaque);

void virCommandSetDryRun(virBufferPtr buf,
                         virCommandDryRunCallback cb,
                         void *opaque);

#endif /* __VIR_COMMAND_PRIV_H__ */
