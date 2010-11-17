
/*
 * Copyright (C) 2009 Canonical Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * Author:
 *   Jamie Strandboge <jamie@canonical.com>
 *
 */
#ifndef __VIR_SECURITY_APPARMOR_H__
# define __VIR_SECURITY_APPARMOR_H__

# include "security_driver.h"

extern virSecurityDriver virAppArmorSecurityDriver;

# define AA_PREFIX  "libvirt-"
# define PROFILE_NAME_SIZE  8 + VIR_UUID_STRING_BUFLEN /* AA_PREFIX + uuid */
# define MAX_FILE_LEN       (1024*1024*10)  /* 10MB limit for sanity check */

#endif /* __VIR_SECURITY_APPARMOR_H__ */
