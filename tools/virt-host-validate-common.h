/*
 * virt-host-validate-common.h: Sanity check helper APIs
 *
 * Copyright (C) 2012 Red Hat, Inc.
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

#ifndef __VIRT_HOST_VALIDATE_COMMON_H__
# define __VIRT_HOST_VALIDATE_COMMON_H__

# include "internal.h"

typedef enum {
    VIR_HOST_VALIDATE_FAIL,
    VIR_HOST_VALIDATE_WARN,
    VIR_HOST_VALIDATE_NOTE,

    VIR_HOST_VALIDATE_LAST,
} virHostValidateLevel;

extern void virHostMsgSetQuiet(bool quietFlag);

extern void virHostMsgCheck(const char *prefix,
                            const char *format,
                            ...) ATTRIBUTE_FMT_PRINTF(2, 3);

extern void virHostMsgPass(void);
extern void virHostMsgFail(virHostValidateLevel level,
                           const char *hint);

extern int virHostValidateDevice(const char *hvname,
                                 const char *devname,
                                 virHostValidateLevel level,
                                 const char *hint);

extern bool virHostValidateHasCPUFlag(const char *name);

extern int virHostValidateLinuxKernel(const char *hvname,
                                      int version,
                                      virHostValidateLevel level,
                                      const char *hint);

#endif /* __VIRT_HOST_VALIDATE_COMMON_H__ */
