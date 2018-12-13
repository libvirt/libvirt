/*
 * storage_backend_sheepdog_priv.h: header for functions necessary in tests
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

#ifndef __VIR_STORAGE_BACKEND_SHEEPDOG_PRIV_ALLOW_H__
# error "storage_backend_sheepdog_priv.h may only be included by storage_backend_sheepdog.c or test suites"
#endif /* __VIR_STORAGE_BACKEND_SHEEPDOG_PRIV_ALLOW_H__ */

#ifndef __VIR_STORAGE_BACKEND_SHEEPDOG_PRIV_H__
# define __VIR_STORAGE_BACKEND_SHEEPDOG_PRIV_H__

# include "conf/storage_conf.h"

int virStorageBackendSheepdogParseNodeInfo(virStoragePoolDefPtr pool,
                                           char *output);
int virStorageBackendSheepdogParseVdiList(virStorageVolDefPtr vol,
                                          char *output);

#endif /* __VIR_STORAGE_BACKEND_SHEEPDOG_PRIV_H__ */
