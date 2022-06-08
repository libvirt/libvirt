/*
 * virnetclientprogram.h: generic network RPC client program
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
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

#include <rpc/types.h>
#include <rpc/xdr.h>

#include "virnetmessage.h"

typedef struct _virNetClient virNetClient;

typedef struct _virNetClientProgram virNetClientProgram;

typedef struct _virNetClientProgramEvent virNetClientProgramEvent;

typedef struct _virNetClientProgramErrorHandler virNetClientProgramErrorHander;


typedef void (*virNetClientProgramDispatchFunc)(virNetClientProgram *prog,
                                                virNetClient *client,
                                                void *msg,
                                                void *opaque);

struct _virNetClientProgramEvent {
    int proc;
    virNetClientProgramDispatchFunc func;
    size_t msg_len;
    xdrproc_t msg_filter;
};

virNetClientProgram *virNetClientProgramNew(unsigned program,
                                              unsigned version,
                                              virNetClientProgramEvent *events,
                                              size_t nevents,
                                              void *eventOpaque);

unsigned virNetClientProgramGetProgram(virNetClientProgram *prog);
unsigned virNetClientProgramGetVersion(virNetClientProgram *prog);

int virNetClientProgramMatches(virNetClientProgram *prog,
                               virNetMessage *msg);

int virNetClientProgramDispatch(virNetClientProgram *prog,
                                virNetClient *client,
                                virNetMessage *msg);

int virNetClientProgramCall(virNetClientProgram *prog,
                            virNetClient *client,
                            unsigned serial,
                            int proc,
                            size_t noutfds,
                            int *outfds,
                            size_t *ninfds,
                            int **infds,
                            xdrproc_t args_filter, void *args,
                            xdrproc_t ret_filter, void *ret);
