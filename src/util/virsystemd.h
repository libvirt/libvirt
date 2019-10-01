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

#pragma once

#include "internal.h"
#include "virautoclean.h"

typedef struct _virSystemdActivation virSystemdActivation;
typedef virSystemdActivation *virSystemdActivationPtr;

/*
 * Back compat for systemd < v227 which lacks LISTEN_FDNAMES.
 * Delete when min systemd is increased ie RHEL7 dropped
 */
typedef struct _virSystemdActivationMap {
    const char *name;
    int family;
    int port; /* if family == AF_INET/AF_INET6 */
    const char *path; /* if family == AF_UNIX */
} virSystemdActivationMap;

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
                            const char *partition,
                            unsigned int maxthreads);

int virSystemdTerminateMachine(const char *name);

void virSystemdNotifyStartup(void);

int virSystemdHasLogind(void);

int virSystemdCanSuspend(bool *result);

int virSystemdCanHibernate(bool *result);

int virSystemdCanHybridSleep(bool *result);

char *virSystemdGetMachineNameByPID(pid_t pid);

int virSystemdGetActivation(virSystemdActivationMap *map,
                            size_t nmap,
                            virSystemdActivationPtr *act);

bool virSystemdActivationHasName(virSystemdActivationPtr act,
                                 const char *name);

int virSystemdActivationComplete(virSystemdActivationPtr act);

void virSystemdActivationClaimFDs(virSystemdActivationPtr act,
                                  const char *name,
                                  int **fds,
                                  size_t *nfds);

void virSystemdActivationFree(virSystemdActivationPtr act);

VIR_DEFINE_AUTOPTR_FUNC(virSystemdActivation, virSystemdActivationFree);
