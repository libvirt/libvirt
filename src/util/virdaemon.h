/*
 * virdaemon.h: shared daemon setup code
 *
 * Copyright (C) 2020 Red Hat, Inc.
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
 */

#pragma once

#include "virenum.h"

enum {
    VIR_DAEMON_ERR_NONE = 0,
    VIR_DAEMON_ERR_PIDFILE,
    VIR_DAEMON_ERR_RUNDIR,
    VIR_DAEMON_ERR_INIT,
    VIR_DAEMON_ERR_SIGNAL,
    VIR_DAEMON_ERR_PRIVS,
    VIR_DAEMON_ERR_NETWORK,
    VIR_DAEMON_ERR_CONFIG,
    VIR_DAEMON_ERR_HOOKS,
    VIR_DAEMON_ERR_REEXEC,
    VIR_DAEMON_ERR_AUDIT,
    VIR_DAEMON_ERR_DRIVER,

    VIR_DAEMON_ERR_LAST
};

VIR_ENUM_DECL(virDaemonErr);
VIR_ENUM_IMPL(virDaemonErr,
              VIR_DAEMON_ERR_LAST,
              "Initialization successful",
              "Unable to obtain pidfile",
              "Unable to create rundir",
              "Unable to initialize libvirt",
              "Unable to setup signal handlers",
              "Unable to drop privileges",
              "Unable to initialize network sockets",
              "Unable to load configuration file",
              "Unable to look for hook scripts",
              "Unable to re-execute daemon",
              "Unable to initialize audit system",
              "Unable to initialize driver",
);

int virDaemonForkIntoBackground(const char *argv0);

int virDaemonSetupLogging(const char *daemon_name,
                          unsigned int log_level,
                          char *log_filters,
                          char *log_outputs,
                          bool privileged,
                          bool verbose,
                          bool godaemon);

int virDaemonUnixSocketPaths(const char *sock_prefix,
                             bool privileged,
                             char *unix_sock_dir,
                             char **sockfile,
                             char **rosockfile,
                             char **adminSockfile);
