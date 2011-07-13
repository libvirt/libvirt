
/*
 * hyperv_wmi_classes.c: WMI classes for managing Microsoft Hyper-V hosts
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

#include <config.h>

#include "hyperv_wmi_classes.h"

SER_TYPEINFO_BOOL;
SER_TYPEINFO_STRING;
SER_TYPEINFO_INT8;
SER_TYPEINFO_INT16;
SER_TYPEINFO_INT32;
SER_TYPEINFO_UINT8;
SER_TYPEINFO_UINT16;
SER_TYPEINFO_UINT32;

#include "hyperv_wmi_classes.generated.c"
