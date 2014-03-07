/*
 * esx_vi_methods.h: client for the VMware VI API 2.5 to manage ESX hosts
 *
 * Copyright (C) 2009, 2010 Matthias Bolte <matthias.bolte@googlemail.com>
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

#ifndef __ESX_VI_METHODS_H__
# define __ESX_VI_METHODS_H__

# include "esx_vi.h"
# include "esx_vi_types.h"



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Methods
 */

int esxVI_RetrieveServiceContent
      (esxVI_Context *ctx,
       esxVI_ServiceContent **serviceContent);             /* required */

int esxVI_ValidateMigration
      (esxVI_Context *ctx,
       esxVI_ManagedObjectReference *vm,                   /* required, list */
       esxVI_VirtualMachinePowerState state,               /* optional */
       esxVI_String *testType,                             /* optional, list */
       esxVI_ManagedObjectReference *pool,                 /* optional */
       esxVI_ManagedObjectReference *host,                 /* optional */
       esxVI_Event **output);                              /* optional, list */

# include "esx_vi_methods.generated.h"

#endif /* __ESX_VI_METHODS_H__ */
