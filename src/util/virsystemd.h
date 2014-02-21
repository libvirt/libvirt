/*
 * virsystemd.h: helpers for using systemd APIs
 *
 * Copyright (C) 2013 Red Hat, Inc.
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

#ifndef __VIR_SYSTEMD_H__
# define __VIR_SYSTEMD_H__

# include "internal.h"

char *virSystemdMakeScopeName(const char *name,
                              const char *drivername,
                              const char *slicename);
char *virSystemdMakeSliceName(const char *partition);

char *virSystemdMakeMachineName(const char *name,
                                const char *drivername,
                                bool privileged);

int virSystemdCreateMachine(const char *name,
                            const char *drivername,
                            bool privileged,
                            const unsigned char *uuid,
                            const char *rootdir,
                            pid_t pidleader,
                            bool iscontainer,
                            const char *partition);

int virSystemdTerminateMachine(const char *name,
                               const char *drivername,
                               bool privileged);

void virSystemdNotifyStartup(void);

#endif /* __VIR_SYSTEMD_H__ */
