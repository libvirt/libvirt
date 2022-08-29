/*
 * virclosecallbacks.c: Connection close callbacks routines
 *
 * Copyright (C) 2013-2014 Red Hat, Inc.
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

#include <config.h>

#include "viralloc.h"
#include "virclosecallbacks.h"
#include "virlog.h"
#include "virobject.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.closecallbacks");


struct _virCloseCallbacksDomainData {
    virConnectPtr conn;
    virCloseCallback cb;
};
typedef struct _virCloseCallbacksDomainData virCloseCallbacksDomainData;


static void
virCloseCallbacksDomainDataFree(virCloseCallbacksDomainData* data)
{
    g_free(data);
}
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virCloseCallbacksDomainData, virCloseCallbacksDomainDataFree);


virClass *virCloseCallbacksDomainListClass;

struct _virCloseCallbacksDomainList {
    virObjectLockable parent;

    GList *callbacks;
};
typedef struct _virCloseCallbacksDomainList virCloseCallbacksDomainList;


static void
virCloseCallbacksDomainListDispose(void *obj G_GNUC_UNUSED)
{
    virCloseCallbacksDomainList *cc = obj;

    g_list_free_full(cc->callbacks, (GDestroyNotify) virCloseCallbacksDomainDataFree);
}


static int
virCloseCallbacksDomainListOnceInit(void)
{
    if (!(VIR_CLASS_NEW(virCloseCallbacksDomainList, virClassForObjectLockable())))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virCloseCallbacksDomainList);


/**
 * virCloseCallbacksDomainAlloc:
 *
 * Allocates and returns a data structure for holding close callback data in
 * a virDomainObj.
 */
virObject *
virCloseCallbacksDomainAlloc(void)
{
    if (virCloseCallbacksDomainListInitialize() < 0)
        abort();

    return virObjectNew(virCloseCallbacksDomainListClass);
}


/**
 * virCloseCallbacksDomainAdd:
 * @vm: domain object
 * @conn: pointer to the connection which should trigger the close callback
 * @cb: pointer to the callback function
 *
 * Registers @cb as a connection close callback for the @conn connection with
 * the @vm domain. Duplicate registrations are ignored.
 *
 * Caller must hold lock on @vm.
 */
void
virCloseCallbacksDomainAdd(virDomainObj *vm,
                           virConnectPtr conn,
                           virCloseCallback cb)
{
    virCloseCallbacksDomainList *cc = (virCloseCallbacksDomainList *) vm->closecallbacks;

    if (!conn || !cb)
        return;

    VIR_WITH_OBJECT_LOCK_GUARD(cc) {
        virCloseCallbacksDomainData *data;
        GList *n;

        for (n = cc->callbacks; n; n = n->next) {
            data = n->data;

            if (data->cb == cb && data->conn == conn)
                return;
        }

        data = g_new0(virCloseCallbacksDomainData, 1);
        data->conn = conn;
        data->cb = cb;

        cc->callbacks = g_list_prepend(cc->callbacks, data);
    }
}


/**
 * virCloseCallbacksDomainMatch:
 * @data: pointer to a close callback data structure
 * @conn: connection pointer matched against @data
 * @cb: callback pointer matched against @data
 *
 * Returns true if the @data callback structure matches the requested @conn
 * and/or @cb parameters. If either of @conn/@cb is NULL it is interpreted as
 * a wildcard.
 */
static bool
virCloseCallbacksDomainMatch(virCloseCallbacksDomainData *data,
                             virConnectPtr conn,
                             virCloseCallback cb)
{
    if (conn && cb)
        return data->conn == conn && data->cb == cb;

    if (conn)
        return data->conn == conn;

    if (cb)
        return data->cb == cb;

    return true;
}


/**
 * virCloseCallbacksDomainIsRegistered:
 * @vm: domain object
 * @conn: connection pointer
 * @cb: callback pointer
 *
 * Returns true if @vm has one or more matching (see virCloseCallbacksDomainMatch)
 * callback(s) registered. Caller must hold lock on @vm.
 */
bool
virCloseCallbacksDomainIsRegistered(virDomainObj *vm,
                                    virConnectPtr conn,
                                    virCloseCallback cb)
{
    virCloseCallbacksDomainList *cc = (virCloseCallbacksDomainList *) vm->closecallbacks;

    VIR_WITH_OBJECT_LOCK_GUARD(cc) {
        GList *n;

        for (n = cc->callbacks; n; n = n->next) {
            virCloseCallbacksDomainData *data = n->data;

            if (virCloseCallbacksDomainMatch(data, conn, cb))
                return true;
        }
    }

    return false;
}


/**
 * virCloseCallbacksDomainRemove:
 * @vm: domain object
 * @conn: connection pointer
 * @cb: callback pointer
 *
 * Removes all the registered matching (see virCloseCallbacksDomainMatch)
 * callbacks for @vm. Caller must hold lock on @vm.
 */
void
virCloseCallbacksDomainRemove(virDomainObj *vm,
                              virConnectPtr conn,
                              virCloseCallback cb)
{
    virCloseCallbacksDomainList *cc = (virCloseCallbacksDomainList *) vm->closecallbacks;

    VIR_WITH_OBJECT_LOCK_GUARD(cc) {
        GList *n = cc->callbacks;

        while (n) {
            GList *cur = n;

            n = n->next;

            if (virCloseCallbacksDomainMatch(cur->data, conn, cb)) {
                cc->callbacks = g_list_remove_link(cc->callbacks, cur);
                g_list_free_full(cur, (GDestroyNotify) virCloseCallbacksDomainDataFree);
            }
        }
    }
}


/**
 * virCloseCallbacksDomainFetchForConn:
 * @vm: domain object
 * @conn: pointer to connection being closed
 *
 * Fetches connection close callbacks for @conn from @vm. The fetched close
 * callbacks are removed from the list of callbacks of @vm. This function
 * must be called with lock on @vm held. Caller is responsible for freeing the
 * returned list.
 */
static GList *
virCloseCallbacksDomainFetchForConn(virDomainObj *vm,
                                    virConnectPtr conn)
{
    virCloseCallbacksDomainList *cc = (virCloseCallbacksDomainList *) vm->closecallbacks;
    GList *conncallbacks = NULL;

    VIR_WITH_OBJECT_LOCK_GUARD(cc) {
        GList *n;

        for (n = cc->callbacks; n;) {
            virCloseCallbacksDomainData *data = n->data;
            GList *cur = n;

            n = n->next;

            if (data->conn == conn) {
                cc->callbacks = g_list_remove_link(cc->callbacks, cur);
                conncallbacks = g_list_concat(cur, conncallbacks);
            }
        }
    }

    return conncallbacks;
}


/**
 * virCloseCallbacksDomainRun
 * @vm: domain object
 * @conn: pointer to connection being closed
 *
 * Fetches and sequentially calls all connection close callbacks for @conn from
 * @vm. This function must be called with lock on @vm held.
 */
static void
virCloseCallbacksDomainRun(virDomainObj *vm,
                           virConnectPtr conn)
{
    g_autolist(virCloseCallbacksDomainData) callbacks = NULL;
    GList *n;

    callbacks = virCloseCallbacksDomainFetchForConn(vm, conn);

    for (n = callbacks; n; n = n->next) {
        virCloseCallbacksDomainData *data = n->data;

        VIR_DEBUG("vm='%s' cb='%p'", vm->def->name, data->cb);

        (data->cb)(vm, conn);
    }
}


/**
 * virCloseCallbacksDomainHasCallbackForConn:
 * @vm: domain object
 * @conn: connection being closed
 *
 * Returns true if @vm has a callback registered for the @conn connection. This
 * function doesn't require a lock being held on @vm.
 */
static bool
virCloseCallbacksDomainHasCallbackForConn(virDomainObj *vm,
                                          virConnectPtr conn)
{
    /* we can access vm->closecallbacks as it's a immutable pointer */
    virCloseCallbacksDomainList *cc = (virCloseCallbacksDomainList *) vm->closecallbacks;

    if (!cc)
        return false;

    VIR_WITH_OBJECT_LOCK_GUARD(cc) {
        GList *n;

        for (n = cc->callbacks; n; n = n->next) {
            virCloseCallbacksDomainData *data = n->data;

            if (data->conn == conn)
                return true;
        }
    }

    return false;
}


/**
 * virCloseCallbacksDomainRunForConn:
 * @domains: domain list object
 * @conn: connection being closed
 *
 * Finds all domains in @domains which registered one or more connection close
 * callbacks for @conn and calls the callbacks. This function is designed to
 * be called from virDrvConnectClose function of individual drivers.
 *
 * To minimize lock contention the function first fetches a list of all domain
 * objects, then checks whether a connect close callback is actually registered
 * for the domain object and just then acquires the lock on the VM object.
 */
void
virCloseCallbacksDomainRunForConn(virDomainObjList *domains,
                                  virConnectPtr conn)
{
    virDomainObj **vms = NULL;
    size_t nvms;
    size_t i;

    VIR_DEBUG("conn=%p", conn);

    virDomainObjListCollectAll(domains, &vms, &nvms);

    for (i = 0; i < nvms; i++) {
        virDomainObj *vm = vms[i];

        if (!virCloseCallbacksDomainHasCallbackForConn(vm, conn))
            continue;

        VIR_WITH_OBJECT_LOCK_GUARD(vm) {
            /* VIR_WITH_OBJECT_LOCK_GUARD is a for loop, so this break applies to that */
            if (vm->removing)
                break;

            virCloseCallbacksDomainRun(vm, conn);
        }
    }

    virObjectListFreeCount(vms, nvms);
}
