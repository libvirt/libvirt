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

#ifndef LIBVIRT_VIRSYSTEMD_H
# define LIBVIRT_VIRSYSTEMD_H

# include "internal.h"

char *virSystemdMakeScopeName(const char *name,
                              const char *drivername,
                              bool legacy_behaviour);
char *virSystemdMakeSliceName(const char *partition);

int virSystemdCreateMachine(const char *name,
                            const char *drivername,
                            const unsigned char *uuid,
                            const char *rootdir,
                            pid_t pidleader,
                            bool iscontainer,
                            size_t nnicindexes,
                            int *nicindexes,
                            const char *partition);

int virSystemdTerminateMachine(const char *name);

void virSystemdNotifyStartup(void);

int virSystemdCanSuspend(bool *result);

int virSystemdCanHibernate(bool *result);

int virSystemdCanHybridSleep(bool *result);

char *virSystemdGetMachineNameByPID(pid_t pid);

#endif /* LIBVIRT_VIRSYSTEMD_H */
