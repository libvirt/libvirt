
/*
 * hyperv_private.h: private driver struct for the Microsoft Hyper-V driver
 *
 * Copyright (C) 2011 Matthias Bolte <matthias.bolte@googlemail.com>
 * Copyright (C) 2009 Michael Sievers <msievers83@googlemail.com>
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#ifndef __HYPERV_PRIVATE_H__
# define __HYPERV_PRIVATE_H__

# include "internal.h"
# include "virterror_internal.h"

# define HYPERV_ERROR(code, ...)                                              \
    virReportErrorHelper(VIR_FROM_HYPERV, code, __FILE__, __FUNCTION__,       \
                         __LINE__, __VA_ARGS__)

#endif /* __HYPERV_PRIVATE_H__ */
