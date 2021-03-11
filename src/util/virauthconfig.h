/*
 * virauthconfig.h: authentication config handling
 *
 * Copyright (C) 2012 Red Hat, Inc.
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

typedef struct _virAuthConfig virAuthConfig;

virAuthConfig *virAuthConfigNew(const char *path);
virAuthConfig *virAuthConfigNewData(const char *path,
                                      const char *data,
                                      size_t len);

void virAuthConfigFree(virAuthConfig *auth);

int virAuthConfigLookup(virAuthConfig *auth,
                        const char *service,
                        const char *hostname,
                        const char *credname,
                        char **value);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virAuthConfig, virAuthConfigFree);
