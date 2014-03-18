/*
 * bhyve_process.h: bhyve process management
 *
 * Copyright (C) 2014 Roman Bogorodskiy
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

#ifndef __BHYVE_PROCESS_H__
# define __BHYVE_PROCESS_H__

# include "bhyve_utils.h"

int virBhyveProcessStart(virConnectPtr conn,
                         bhyveConnPtr driver,
                         virDomainObjPtr vm,
                         virDomainRunningReason reason,
                         unsigned int flags);

int virBhyveProcessStop(bhyveConnPtr driver,
                        virDomainObjPtr vm,
                        virDomainShutoffReason reason);

typedef enum {
    VIR_BHYVE_PROCESS_START_AUTODESTROY = 1 << 0,
} bhyveProcessStartFlags;

#endif /* __BHYVE_PROCESS_H__ */
