/*
 * log_daemon.h: log management daemon
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_LOG_DAEMON_H__
# define __VIR_LOG_DAEMON_H__

# include "virthread.h"
# include "log_handler.h"

typedef struct _virLogDaemon virLogDaemon;
typedef virLogDaemon *virLogDaemonPtr;

typedef struct _virLogDaemonClient virLogDaemonClient;
typedef virLogDaemonClient *virLogDaemonClientPtr;

struct _virLogDaemonClient {
    virMutex lock;

    pid_t clientPid;
};

extern virLogDaemonPtr logDaemon;

virLogHandlerPtr virLogDaemonGetHandler(virLogDaemonPtr dmn);

#endif /* __VIR_LOG_DAEMON_H__ */
