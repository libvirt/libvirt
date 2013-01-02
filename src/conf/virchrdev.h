/**
 * virchrdev.h: api to guarantee mutually exclusive
 * access to domain's character devices
 *
 * Copyright (C) 2011-2012 Red Hat, Inc.
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
 * Author: Peter Krempa <pkrempa@redhat.com>
 */
#ifndef __VIR_CHRDEV_H__
# define __VIR_CHRDEV_H__

# include "internal.h"
# include "domain_conf.h"

typedef struct _virChrdevs virChrdevs;
typedef virChrdevs *virChrdevsPtr;

virChrdevsPtr virChrdevAlloc(void);
void virChrdevFree(virChrdevsPtr devs);

int virChrdevOpen(virChrdevsPtr devs, virDomainChrSourceDefPtr source,
                  virStreamPtr st, bool force);
#endif /*__VIR_CHRDEV_H__*/
