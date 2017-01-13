/*
 * storage_backend_mpath.h: storage backend for multipath handling
 *
 * Copyright (C) 2009-2009 Red Hat, Inc.
 * Copyright (C) 2009-2008 Dave Allan
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
 * Author: Dave Allan <dallan@redhat.com>
 */

#ifndef __VIR_STORAGE_BACKEND_MPATH_H__
# define __VIR_STORAGE_BACKEND_MPATH_H__

int virStorageBackendMpathRegister(void);

#endif /* __VIR_STORAGE_BACKEND_MPATH_H__ */
