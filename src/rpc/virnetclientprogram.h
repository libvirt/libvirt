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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_NET_CLIENT_PROGRAM_H__
# define __VIR_NET_CLIENT_PROGRAM_H__

# include <rpc/types.h>
# include <rpc/xdr.h>

# include "virnetmessage.h"

typedef struct _virNetClient virNetClient;
typedef virNetClient *virNetClientPtr;

typedef struct _virNetClientProgram virNetClientProgram;
typedef virNetClientProgram *virNetClientProgramPtr;

typedef struct _virNetClientProgramEvent virNetClientProgramEvent;
typedef virNetClientProgramEvent *virNetClientProgramEventPtr;

typedef struct _virNetClientProgramErrorHandler virNetClientProgramErrorHander;
typedef virNetClientProgramErrorHander *virNetClientProgramErrorHanderPtr;


typedef void (*virNetClientProgramDispatchFunc)(virNetClientProgramPtr prog,
                                                virNetClientPtr client,
                                                void *msg,
                                                void *opaque);

struct _virNetClientProgramEvent {
    int proc;
    virNetClientProgramDispatchFunc func;
    size_t msg_len;
    xdrproc_t msg_filter;
};

virNetClientProgramPtr virNetClientProgramNew(unsigned program,
                                              unsigned version,
                                              virNetClientProgramEventPtr events,
                                              size_t nevents,
                                              void *eventOpaque);

unsigned virNetClientProgramGetProgram(virNetClientProgramPtr prog);
unsigned virNetClientProgramGetVersion(virNetClientProgramPtr prog);

void virNetClientProgramRef(virNetClientProgramPtr prog);

void virNetClientProgramFree(virNetClientProgramPtr prog);

int virNetClientProgramMatches(virNetClientProgramPtr prog,
                               virNetMessagePtr msg);

int virNetClientProgramDispatch(virNetClientProgramPtr prog,
                                virNetClientPtr client,
                                virNetMessagePtr msg);

int virNetClientProgramCall(virNetClientProgramPtr prog,
                            virNetClientPtr client,
                            unsigned serial,
                            int proc,
                            size_t noutfds,
                            int *outfds,
                            size_t *ninfds,
                            int **infds,
                            xdrproc_t args_filter, void *args,
                            xdrproc_t ret_filter, void *ret);



#endif /* __VIR_NET_CLIENT_PROGRAM_H__ */
