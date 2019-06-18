/*
 * remote_daemon.h: daemon data structure definitions
 *
 * Copyright (C) 2006-2018 Red Hat, Inc.
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

#define VIR_ENUM_SENTINELS

#include <rpc/types.h>
#include <rpc/xdr.h>
#include "remote_protocol.h"
#include "lxc_protocol.h"
#include "qemu_protocol.h"
#include "virthread.h"

#if WITH_SASL
# include "virnetsaslcontext.h"
#endif
#include "virnetserverprogram.h"

typedef struct daemonClientStream daemonClientStream;
typedef daemonClientStream *daemonClientStreamPtr;
typedef struct daemonClientPrivate daemonClientPrivate;
typedef daemonClientPrivate *daemonClientPrivatePtr;
typedef struct daemonClientEventCallback daemonClientEventCallback;
typedef daemonClientEventCallback *daemonClientEventCallbackPtr;

/* Stores the per-client connection state */
struct daemonClientPrivate {
    /* Hold while accessing any data except conn */
    virMutex lock;

    daemonClientEventCallbackPtr *domainEventCallbacks;
    size_t ndomainEventCallbacks;
    daemonClientEventCallbackPtr *networkEventCallbacks;
    size_t nnetworkEventCallbacks;
    daemonClientEventCallbackPtr *qemuEventCallbacks;
    size_t nqemuEventCallbacks;
    daemonClientEventCallbackPtr *storageEventCallbacks;
    size_t nstorageEventCallbacks;
    daemonClientEventCallbackPtr *nodeDeviceEventCallbacks;
    size_t nnodeDeviceEventCallbacks;
    daemonClientEventCallbackPtr *secretEventCallbacks;
    size_t nsecretEventCallbacks;
    bool closeRegistered;

#if WITH_SASL
    virNetSASLSessionPtr sasl;
#endif

    /* This is only valid if a remote open call has been made on this
     * connection, otherwise it will be NULL.  Also if remote close is
     * called, it will be set back to NULL if that succeeds.
     */
    virConnectPtr conn;
    virConnectPtr interfaceConn;
    virConnectPtr networkConn;
    virConnectPtr nodedevConn;
    virConnectPtr nwfilterConn;
    virConnectPtr secretConn;
    virConnectPtr storageConn;

    daemonClientStreamPtr streams;
};


#if WITH_SASL
extern virNetSASLContextPtr saslCtxt;
#endif
extern virNetServerProgramPtr remoteProgram;
extern virNetServerProgramPtr qemuProgram;
