/*
 * virgic.h: ARM Generic Interrupt Controller support
 *
 * Copyright (C) 2016 Red Hat, Inc.
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
 * Author: Andrea Bolognani <abologna@redhat.com>
 */

#ifndef __VIR_GIC_H__
# define __VIR_GIC_H__

# include "virutil.h"

typedef enum {
    VIR_GIC_VERSION_NONE = 0,
    VIR_GIC_VERSION_HOST,
    VIR_GIC_VERSION_2,
    VIR_GIC_VERSION_3,
    VIR_GIC_VERSION_LAST
} virGICVersion;

VIR_ENUM_DECL(virGICVersion);

typedef enum {
    VIR_GIC_IMPLEMENTATION_NONE = 0,
    VIR_GIC_IMPLEMENTATION_KERNEL = (1 << 1),
    VIR_GIC_IMPLEMENTATION_EMULATED = (1 << 2)
} virGICImplementation;

typedef struct _virGICCapability virGICCapability;
typedef virGICCapability *virGICCapabilityPtr;
struct _virGICCapability {
    virGICVersion version;
    virGICImplementation implementation;
};

#endif /* __VIR_GIC_H__ */
