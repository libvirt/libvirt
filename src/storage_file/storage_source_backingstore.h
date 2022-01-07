/*
 * storage_source_backingstore.h: helpers for parsing backing store strings
 *
 * Copyright (C) 2007-2009, 2012-2016 Red Hat, Inc.
 * Copyright (C) 2007-2008 Daniel P. Berrange
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

#include "storage_source_conf.h"

int
virStorageSourceParseBackingURI(virStorageSource *src,
                                const char *uristr);

int
virStorageSourceParseRBDColonString(const char *rbdstr,
                                    virStorageSource *src)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
virStorageSourceParseBackingColon(virStorageSource *src,
                                  const char *path);

int
virStorageSourceParseBackingJSON(virStorageSource *src,
                                 const char *json);
