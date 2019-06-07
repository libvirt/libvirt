/*
 * esx_stream.h: libcurl based stream driver
 *
 * Copyright (C) 2012-2014 Matthias Bolte <matthias.bolte@googlemail.com>
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

#pragma once

#include "internal.h"
#include "esx_private.h"

int esxStreamOpenUpload(virStreamPtr stream, esxPrivate *priv, const char *url);
int esxStreamOpenDownload(virStreamPtr stream, esxPrivate *priv, const char *url,
                          unsigned long long offset, unsigned long long length);
