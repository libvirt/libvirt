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
#include "lxc_protocol.h"
#include "qemu_protocol.h"
#include "virthread.h"

#if WITH_SASL
# include "virnetsaslcontext.h"
#endif
#include "virnetserverprogram.h"

typedef struct daemonClientStream daemonClientStream;
typedef struct daemonClientPrivate daemonClientPrivate;
typedef struct daemonClientEventCallback daemonClientEventCallback;

/* Stores the per-client connection state */
struct daemonClientPrivate {
    /* Hold while accessing any data except conn */
    virMutex lock;

    daemonClientEventCallback **domainEventCallbacks;
    size_t ndomainEventCallbacks;
    daemonClientEventCallback **networkEventCallbacks;
    size_t nnetworkEventCallbacks;
    daemonClientEventCallback **qemuEventCallbacks;
    size_t nqemuEventCallbacks;
    daemonClientEventCallback **storageEventCallbacks;
    size_t nstorageEventCallbacks;
    daemonClientEventCallback **nodeDeviceEventCallbacks;
    size_t nnodeDeviceEventCallbacks;
    daemonClientEventCallback **secretEventCallbacks;
    size_t nsecretEventCallbacks;
    bool closeRegistered;

#if WITH_SASL
    virNetSASLSession *sasl;
#endif

    /* This is only valid if a remote open call has been made on this
     * connection, otherwise it will be NULL.  Also if remote close is
     * called, it will be set back to NULL if that succeeds.
     */
    virConnectPtr conn;

    /* These secondary drivers may point back to 'conn'
     * in the monolithic daemon setups. Otherwise they
     * can be NULL and opened on first use, pointing
     * to remote driver use of an external daemon
     */
    virConnectPtr interfaceConn;
    const char *interfaceURI;
    virConnectPtr networkConn;
    const char *networkURI;
    virConnectPtr nodedevConn;
    const char *nodedevURI;
    virConnectPtr nwfilterConn;
    const char *nwfilterURI;
    virConnectPtr secretConn;
    const char *secretURI;
    virConnectPtr storageConn;
    const char *storageURI;
    bool readonly;

    daemonClientStream *streams;
};


#if WITH_SASL
extern virNetSASLContext *saslCtxt;
#endif
extern virNetServerProgram *remoteProgram;
extern virNetServerProgram *qemuProgram;
