/*
 * Copyright (C) 2009 Canonical Ltd.
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

#pragma once

#include "security_driver.h"

extern virSecurityDriver virAppArmorSecurityDriver;

#define AA_PREFIX  "libvirt-"
#define PROFILE_NAME_SIZE  8 + VIR_UUID_STRING_BUFLEN /* AA_PREFIX + uuid */
#define MAX_FILE_LEN       (1024*1024*10)  /* 10MB limit for sanity check */
