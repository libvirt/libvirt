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

#pragma once

#include "virnetmessage.h"
#include "virnetserverclient.h"

typedef struct _virNetDaemon virNetDaemon;

typedef struct _virNetServerService virNetServerService;

typedef struct _virNetServerProgram virNetServerProgram;

typedef struct _virNetServerProgramProc virNetServerProgramProc;

typedef int (*virNetServerProgramDispatchFunc)(virNetServer *server,
                                               virNetServerClient *client,
                                               virNetMessage *msg,
                                               struct virNetMessageError *rerr,
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

virNetServerProgram *virNetServerProgramNew(unsigned program,
                                              unsigned version,
                                              virNetServerProgramProc *procs,
                                              size_t nprocs);

int virNetServerProgramGetID(virNetServerProgram *prog);
int virNetServerProgramGetVersion(virNetServerProgram *prog);

unsigned int virNetServerProgramGetPriority(virNetServerProgram *prog,
                                            int procedure);

int virNetServerProgramMatches(virNetServerProgram *prog,
                               virNetMessage *msg);

int virNetServerProgramDispatch(virNetServerProgram *prog,
                                virNetServer *server,
                                virNetServerClient *client,
                                virNetMessage *msg);

int virNetServerProgramSendReplyError(virNetServerProgram *prog,
                                      virNetServerClient *client,
                                      virNetMessage *msg,
                                      struct virNetMessageError *rerr,
                                      struct virNetMessageHeader *req);

int virNetServerProgramSendStreamError(virNetServerProgram *prog,
                                       virNetServerClient *client,
                                       virNetMessage *msg,
                                       struct virNetMessageError *rerr,
                                       int procedure,
                                       unsigned int serial);

int virNetServerProgramUnknownError(virNetServerClient *client,
                                    virNetMessage *msg,
                                    struct virNetMessageHeader *req);

int virNetServerProgramSendStreamData(virNetServerProgram *prog,
                                      virNetServerClient *client,
                                      virNetMessage *msg,
                                      int procedure,
                                      unsigned int serial,
                                      const char *data,
                                      size_t len);

int virNetServerProgramSendStreamHole(virNetServerProgram *prog,
                                      virNetServerClient *client,
                                      virNetMessage *msg,
                                      int procedure,
                                      unsigned int serial,
                                      long long length,
                                      unsigned int flags);
