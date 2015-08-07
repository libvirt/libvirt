/*
 * cpu_ppc64_data.h: 64-bit PowerPC CPU specific data
 *
 * Copyright (C) 2012 IBM Corporation.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Authors:
 *      Li Zhang <zhlcindy@linux.vnet.ibm.com>
 */

#ifndef __VIR_CPU_PPC64_DATA_H__
# define __VIR_CPU_PPC64_DATA_H__

# include <stdint.h>

typedef struct _virCPUppc64PVR virCPUppc64PVR;
struct _virCPUppc64PVR {
    uint32_t value;
    uint32_t mask;
};

typedef struct _virCPUppc64Data virCPUppc64Data;
struct _virCPUppc64Data {
    size_t len;
    virCPUppc64PVR *pvr;
};

#endif /* __VIR_CPU_PPC64_DATA_H__ */
