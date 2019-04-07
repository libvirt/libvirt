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

#ifndef LIBVIRT_VIRNETCLIENTPROGRAM_H
# define LIBVIRT_VIRNETCLIENTPROGRAM_H

# include <rpc/types.h>
# include <rpc/xdr.h>

# include "virnetmessage.h"
# include "virobject.h"

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



#endif /* LIBVIRT_VIRNETCLIENTPROGRAM_H */
