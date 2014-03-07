/*
 * storage_backend_sheepdog.h: storage backend for Sheepdog handling
 *
 * Copyright (C) 2012 Wido den Hollander
 * Copyright (C) 2012 Frank Spijkerman
 * Copyright (C) 2012 Sebastian Wiedenroth
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
 * Author: Wido den Hollander <wido@widodh.nl>
 *         Frank Spijkerman <frank.spijkerman@avira.com>
 *         Sebastian Wiedenroth <sebastian.wiedenroth@skylime.net>
 */

#ifndef __VIR_STORAGE_BACKEND_SHEEPDOG_H__
# define __VIR_STORAGE_BACKEND_SHEEPDOG_H__

# include "storage_backend.h"

int virStorageBackendSheepdogParseNodeInfo(virStoragePoolDefPtr pool,
                                           char *output);
int virStorageBackendSheepdogParseVdiList(virStorageVolDefPtr vol,
                                          char *output);

extern virStorageBackend virStorageBackendSheepdog;

#endif /* __VIR_STORAGE_BACKEND_SHEEPDOG_H__ */
