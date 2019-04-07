/*
 * virnetserverprogram.h: generic network RPC server program
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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

#ifndef LIBVIRT_VIRNETSERVERPROGRAM_H
# define LIBVIRT_VIRNETSERVERPROGRAM_H

# include "virnetmessage.h"
# include "virnetserverclient.h"
# include "virobject.h"

typedef struct _virNetDaemon virNetDaemon;
typedef virNetDaemon *virNetDaemonPtr;

typedef struct _virNetServerService virNetServerService;
typedef virNetServerService *virNetServerServicePtr;

typedef struct _virNetServerProgram virNetServerProgram;
typedef virNetServerProgram *virNetServerProgramPtr;

typedef struct _virNetServerProgramProc virNetServerProgramProc;
typedef virNetServerProgramProc *virNetServerProgramProcPtr;

typedef int (*virNetServerProgramDispatchFunc)(virNetServerPtr server,
                                               virNetServerClientPtr client,
                                               virNetMessagePtr msg,
                                               virNetMessageErrorPtr rerr,
                                               void *args,
                                               void *ret);

struct _virNetServerProgramProc {
    virNetServerProgramDispatchFunc func;
    size_t arg_len;
    xdrproc_t arg_filter;
    size_t ret_len;
    xdrproc_t ret_filter;
    bool needAuth;
    unsigned int priority;
};

virNetServerProgramPtr virNetServerProgramNew(unsigned program,
                                              unsigned version,
                                              virNetServerProgramProcPtr procs,
                                              size_t nprocs);

int virNetServerProgramGetID(virNetServerProgramPtr prog);
int virNetServerProgramGetVersion(virNetServerProgramPtr prog);

unsigned int virNetServerProgramGetPriority(virNetServerProgramPtr prog,
                                            int procedure);

int virNetServerProgramMatches(virNetServerProgramPtr prog,
                               virNetMessagePtr msg);

int virNetServerProgramDispatch(virNetServerProgramPtr prog,
                                virNetServerPtr server,
                                virNetServerClientPtr client,
                                virNetMessagePtr msg);

int virNetServerProgramSendReplyError(virNetServerProgramPtr prog,
                                      virNetServerClientPtr client,
                                      virNetMessagePtr msg,
                                      virNetMessageErrorPtr rerr,
                                      virNetMessageHeaderPtr req);

int virNetServerProgramSendStreamError(virNetServerProgramPtr prog,
                                       virNetServerClientPtr client,
                                       virNetMessagePtr msg,
                                       virNetMessageErrorPtr rerr,
                                       int procedure,
                                       unsigned int serial);

int virNetServerProgramUnknownError(virNetServerClientPtr client,
                                    virNetMessagePtr msg,
                                    virNetMessageHeaderPtr req);

int virNetServerProgramSendStreamData(virNetServerProgramPtr prog,
                                      virNetServerClientPtr client,
                                      virNetMessagePtr msg,
                                      int procedure,
                                      unsigned int serial,
                                      const char *data,
                                      size_t len);

int virNetServerProgramSendStreamHole(virNetServerProgramPtr prog,
                                      virNetServerClientPtr client,
                                      virNetMessagePtr msg,
                                      int procedure,
                                      unsigned int serial,
                                      long long length,
                                      unsigned int flags);

#endif /* LIBVIRT_VIRNETSERVERPROGRAM_H */
