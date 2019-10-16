/*
 * virdbus.c: helper for using DBus
 *
 * Copyright (C) 2012-2014 Red Hat, Inc.
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
 *
 */

#include <config.h>

#define LIBVIRT_VIRDBUSPRIV_H_ALLOW
#include "virdbuspriv.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "virthread.h"
#include "virstring.h"
#include "virprobe.h"

#define VIR_FROM_THIS VIR_FROM_DBUS

VIR_LOG_INIT("util.dbus");

#ifdef WITH_DBUS

static bool sharedBus = true;
static DBusConnection *systembus;
static DBusConnection *sessionbus;
static virOnceControl systemonce = VIR_ONCE_CONTROL_INITIALIZER;
static virOnceControl sessiononce = VIR_ONCE_CONTROL_INITIALIZER;
static DBusError systemdbuserr;
static DBusError sessiondbuserr;

static dbus_bool_t virDBusAddWatch(DBusWatch *watch, void *data);
static void virDBusRemoveWatch(DBusWatch *watch, void *data);
static void virDBusToggleWatch(DBusWatch *watch, void *data);

void virDBusSetSharedBus(bool shared)
{
    sharedBus = shared;
}

static DBusConnection *virDBusBusInit(DBusBusType type, DBusError *dbuserr)
{
    DBusConnection *bus;

    /* Allocate and initialize a new HAL context */
    dbus_connection_set_change_sigpipe(FALSE);
    dbus_threads_init_default();

    dbus_error_init(dbuserr);
    bus = sharedBus ?
        dbus_bus_get(type, dbuserr) :
        dbus_bus_get_private(type, dbuserr);
    if (!bus)
        return NULL;

    dbus_connection_set_exit_on_disconnect(bus, FALSE);

    /* Register dbus watch callbacks */
    if (!dbus_connection_set_watch_functions(bus,
                                             virDBusAddWatch,
                                             virDBusRemoveWatch,
                                             virDBusToggleWatch,
                                             bus, NULL)) {
        return NULL;
    }
    return bus;
}

static void virDBusSystemBusInit(void)
{
    systembus = virDBusBusInit(DBUS_BUS_SYSTEM, &systemdbuserr);
}

static DBusConnection *
virDBusGetSystemBusInternal(void)
{
    if (virOnce(&systemonce, virDBusSystemBusInit) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to run one time DBus initializer"));
        return NULL;
    }

    return systembus;
}


DBusConnection *
virDBusGetSystemBus(void)
{
    DBusConnection *bus;

    if (!(bus = virDBusGetSystemBusInternal())) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to get DBus system bus connection: %s"),
                       systemdbuserr.message ? systemdbuserr.message : "watch setup failed");
        return NULL;
    }

    return bus;
}


/**
 * virDBusHasSystemBus:
 *
 * Check if dbus system bus is running. This does not
 * imply that we have a connection. DBus might be running
 * and refusing connections due to its client limit. The
 * latter must be treated as a fatal error.
 *
 * Return false if dbus is not available, true if probably available.
 */
bool
virDBusHasSystemBus(void)
{
    if (virDBusGetSystemBusInternal())
        return true;

    if (systemdbuserr.name &&
        (STREQ(systemdbuserr.name, "org.freedesktop.DBus.Error.FileNotFound") ||
         STREQ(systemdbuserr.name, "org.freedesktop.DBus.Error.NoServer"))) {
        VIR_DEBUG("System DBus not available: %s", NULLSTR(systemdbuserr.message));
        return false;
    }
    return true;
}


void virDBusCloseSystemBus(void)
{
    if (systembus && !sharedBus) {
        dbus_connection_close(systembus);
        dbus_connection_unref(systembus);
        systembus = NULL;
    }
}

static void virDBusSessionBusInit(void)
{
    sessionbus = virDBusBusInit(DBUS_BUS_SESSION, &sessiondbuserr);
}

DBusConnection *virDBusGetSessionBus(void)
{
    if (virOnce(&sessiononce, virDBusSessionBusInit) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to run one time DBus initializer"));
        return NULL;
    }

    if (!sessionbus) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to get DBus session bus connection: %s"),
                       sessiondbuserr.message ? sessiondbuserr.message : "watch setup failed");
        return NULL;
    }

    return sessionbus;
}

struct virDBusWatch
{
    int watch;
    DBusConnection *bus;
};

static void virDBusWatchCallback(int fdatch G_GNUC_UNUSED,
                                 int fd G_GNUC_UNUSED,
                                 int events, void *opaque)
{
    DBusWatch *watch = opaque;
    struct virDBusWatch *info;
    int dbus_flags = 0;

    info = dbus_watch_get_data(watch);

    if (events & VIR_EVENT_HANDLE_READABLE)
        dbus_flags |= DBUS_WATCH_READABLE;
    if (events & VIR_EVENT_HANDLE_WRITABLE)
        dbus_flags |= DBUS_WATCH_WRITABLE;
    if (events & VIR_EVENT_HANDLE_ERROR)
        dbus_flags |= DBUS_WATCH_ERROR;
    if (events & VIR_EVENT_HANDLE_HANGUP)
        dbus_flags |= DBUS_WATCH_HANGUP;

    if (dbus_watch_handle(watch, dbus_flags) == FALSE)
        VIR_DEBUG("dbus_watch_handle() returned FALSE");

    dbus_connection_ref(info->bus);
    while (dbus_connection_dispatch(info->bus) == DBUS_DISPATCH_DATA_REMAINS)
        /* keep dispatching while data remains */;
    dbus_connection_unref(info->bus);
}


static int virDBusTranslateWatchFlags(int dbus_flags)
{
    unsigned int flags = 0;
    if (dbus_flags & DBUS_WATCH_READABLE)
        flags |= VIR_EVENT_HANDLE_READABLE;
    if (dbus_flags & DBUS_WATCH_WRITABLE)
        flags |= VIR_EVENT_HANDLE_WRITABLE;
    if (dbus_flags & DBUS_WATCH_ERROR)
        flags |= VIR_EVENT_HANDLE_ERROR;
    if (dbus_flags & DBUS_WATCH_HANGUP)
        flags |= VIR_EVENT_HANDLE_HANGUP;
    return flags;
}


static void virDBusWatchFree(void *data)
{
    struct virDBusWatch *info = data;
    VIR_FREE(info);
}

static dbus_bool_t virDBusAddWatch(DBusWatch *watch,
                                   void *data)
{
    int flags = 0;
    int fd;
    struct virDBusWatch *info;

    if (VIR_ALLOC(info) < 0)
        return FALSE;

    if (dbus_watch_get_enabled(watch))
        flags = virDBusTranslateWatchFlags(dbus_watch_get_flags(watch));

# if HAVE_DBUS_WATCH_GET_UNIX_FD
    fd = dbus_watch_get_unix_fd(watch);
# else
    fd = dbus_watch_get_fd(watch);
# endif
    dbus_watch_set_data(watch, info, virDBusWatchFree);
    info->bus = (DBusConnection *)data;
    info->watch = virEventAddHandle(fd, flags,
                                    virDBusWatchCallback,
                                    watch, NULL);
    if (info->watch < 0) {
        dbus_watch_set_data(watch, NULL, NULL);
        return FALSE;
    }

    return TRUE;
}


static void virDBusRemoveWatch(DBusWatch *watch,
                               void *data G_GNUC_UNUSED)
{
    struct virDBusWatch *info;

    info = dbus_watch_get_data(watch);

    (void)virEventRemoveHandle(info->watch);
}


static void virDBusToggleWatch(DBusWatch *watch,
                               void *data G_GNUC_UNUSED)
{
    int flags = 0;
    struct virDBusWatch *info;

    if (dbus_watch_get_enabled(watch))
        flags = virDBusTranslateWatchFlags(dbus_watch_get_flags(watch));

    info = dbus_watch_get_data(watch);

    (void)virEventUpdateHandle(info->watch, flags);
}

# define VIR_DBUS_TYPE_STACK_MAX_DEPTH 32

static const char virDBusBasicTypes[] = {
    DBUS_TYPE_BYTE,
    DBUS_TYPE_BOOLEAN,
    DBUS_TYPE_INT16,
    DBUS_TYPE_UINT16,
    DBUS_TYPE_INT32,
    DBUS_TYPE_UINT32,
    DBUS_TYPE_INT64,
    DBUS_TYPE_UINT64,
    DBUS_TYPE_DOUBLE,
    DBUS_TYPE_STRING,
    DBUS_TYPE_OBJECT_PATH,
    DBUS_TYPE_SIGNATURE,
};

static bool virDBusIsBasicType(char c)
{
    return !!memchr(virDBusBasicTypes, c, G_N_ELEMENTS(virDBusBasicTypes));
}

/*
 * All code related to virDBusMessageIterEncode and
 * virDBusMessageIterDecode is derived from systemd
 * bus_message_append_ap()/message_read_ap() in
 * bus-message.c under the terms of the LGPLv2+
 */
static int
virDBusSignatureLengthInternal(const char *s,
                               bool allowDict,
                               unsigned arrayDepth,
                               unsigned structDepth,
                               size_t *skiplen,
                               size_t *siglen)
{
    if (virDBusIsBasicType(*s) || *s == DBUS_TYPE_VARIANT) {
        *skiplen = *siglen = 1;
        return 0;
    }

    if (*s == DBUS_TYPE_ARRAY) {
        size_t skiplencont;
        size_t siglencont;
        bool arrayref = false;

        if (arrayDepth >= VIR_DBUS_TYPE_STACK_MAX_DEPTH) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Signature '%s' too deeply nested"),
                           s);
            return -1;
        }

        if (*(s + 1) == '&') {
            arrayref = true;
            s++;
        }

        if (virDBusSignatureLengthInternal(s + 1,
                                           true,
                                           arrayDepth + 1,
                                           structDepth,
                                           &skiplencont,
                                           &siglencont) < 0)
            return -1;

        *skiplen = skiplencont + 1;
        *siglen = siglencont + 1;
        if (arrayref)
            (*skiplen)++;
        return 0;
    }

    if (*s == DBUS_STRUCT_BEGIN_CHAR) {
        const char *p = s + 1;

        if (structDepth >= VIR_DBUS_TYPE_STACK_MAX_DEPTH) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Signature '%s' too deeply nested"),
                           s);
            return -1;
        }

        *skiplen = *siglen = 2;

        while (*p != DBUS_STRUCT_END_CHAR) {
            size_t skiplencont;
            size_t siglencont;

            if (virDBusSignatureLengthInternal(p,
                                               false,
                                               arrayDepth,
                                               structDepth + 1,
                                               &skiplencont,
                                               &siglencont) < 0)
                return -1;

            p += skiplencont;
            *skiplen += skiplencont;
            *siglen += siglencont;
        }

        return 0;
    }

    if (*s == DBUS_DICT_ENTRY_BEGIN_CHAR && allowDict) {
        const char *p = s + 1;
        unsigned n = 0;
        if (structDepth >= VIR_DBUS_TYPE_STACK_MAX_DEPTH) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Signature '%s' too deeply nested"),
                           s);
            return -1;
        }

        *skiplen = *siglen = 2;

        while (*p != DBUS_DICT_ENTRY_END_CHAR) {
            size_t skiplencont;
            size_t siglencont;

            if (n == 0 && !virDBusIsBasicType(*p)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Dict entry in signature '%s' must be a basic type"),
                               s);
                return -1;
            }

            if (virDBusSignatureLengthInternal(p,
                                               false,
                                               arrayDepth,
                                               structDepth + 1,
                                               &skiplencont,
                                               &siglencont) < 0)
                return -1;

            p += skiplencont;
            *skiplen += skiplencont;
            *siglen += siglencont;
            n++;
        }

        if (n != 2) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Dict entry in signature '%s' is wrong size"),
                           s);
            return -1;
        }

        return 0;
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Unexpected signature '%s'"), s);
    return -1;
}


static int virDBusSignatureLength(const char *s, size_t *skiplen, size_t *siglen)
{
    return virDBusSignatureLengthInternal(s, true, 0, 0, skiplen, siglen);
}


static char *virDBusCopyContainerSignature(const char *sig,
                                           size_t *skiplen,
                                           size_t *siglen)
{
    size_t i, j;
    char *contsig;
    bool isGroup;

    isGroup = (sig[0] == DBUS_STRUCT_BEGIN_CHAR ||
               sig[0] == DBUS_DICT_ENTRY_BEGIN_CHAR);

    if (virDBusSignatureLength(isGroup ? sig : sig + 1, skiplen, siglen) < 0)
        return NULL;

    if (VIR_ALLOC_N(contsig, *siglen + 1) < 0)
        return NULL;

    for (i = 0, j = 0; i < *skiplen && j < *siglen; i++) {
        if (sig[i + 1] == '&')
            continue;
        contsig[j] = sig[i + 1];
        j++;
    }
    contsig[*siglen] = '\0';
    VIR_DEBUG("Extracted '%s' from '%s'", contsig, sig);
    return contsig;
}


/* Ideally, we'd just call ourselves recursively on every
 * complex type. However, the state of a va_list that is
 * passed to a function is undefined after that function
 * returns. This means we need to decode the va_list linearly
 * in a single stackframe. We hence implement our own
 * home-grown stack in an array. */

typedef struct _virDBusTypeStack virDBusTypeStack;
struct _virDBusTypeStack {
    const char *types;
    size_t nstruct;
    size_t narray;
    DBusMessageIter *iter;
};

static int virDBusTypeStackPush(virDBusTypeStack **stack,
                                size_t *nstack,
                                DBusMessageIter *iter,
                                const char *types,
                                size_t nstruct,
                                size_t narray)
{
    if (*nstack >= VIR_DBUS_TYPE_STACK_MAX_DEPTH) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("DBus type too deeply nested"));
        return -1;
    }

    if (VIR_EXPAND_N(*stack, *nstack, 1) < 0)
        return -1;

    (*stack)[(*nstack) - 1].iter = iter;
    (*stack)[(*nstack) - 1].types = types;
    (*stack)[(*nstack) - 1].nstruct = nstruct;
    (*stack)[(*nstack) - 1].narray = narray;
    VIR_DEBUG("Pushed types='%s' nstruct=%zu narray=%zd",
              types, nstruct, (ssize_t)narray);
    return 0;
}


static int virDBusTypeStackPop(virDBusTypeStack **stack,
                               size_t *nstack,
                               DBusMessageIter **iter,
                               const char **types,
                               size_t *nstruct,
                               size_t *narray)
{
    if (*nstack == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("DBus type stack is empty"));
        return -1;
    }

    *iter = (*stack)[(*nstack) - 1].iter;
    *types = (*stack)[(*nstack) - 1].types;
    *nstruct = (*stack)[(*nstack) - 1].nstruct;
    *narray = (*stack)[(*nstack) - 1].narray;
    VIR_DEBUG("Popped types='%s' nstruct=%zu narray=%zd",
              *types, *nstruct, (ssize_t)*narray);
    VIR_SHRINK_N(*stack, *nstack, 1);

    return 0;
}


static void virDBusTypeStackFree(virDBusTypeStack **stack,
                                 size_t *nstack)
{
    size_t i;

    if (!*stack)
        return;

    /* The iter in the first level of the stack is the
     * root iter which must not be freed
     */
    for (i = 1; i < *nstack; i++)
        VIR_FREE((*stack)[i].iter);
    VIR_FREE(*stack);
}


static bool
virDBusIsAllowedRefType(const char *sig)
{
    if (*sig == '{') {
        if (strlen(sig) != 4)
            return false;
        if (!virDBusIsBasicType(sig[1]) ||
            !virDBusIsBasicType(sig[2]) ||
            sig[1] != sig[2])
            return false;
        if (sig[3] != '}')
            return false;
    } else {
        if (strlen(sig) != 1)
            return false;
        if (!virDBusIsBasicType(sig[0]))
            return false;
    }
    return true;
}


# define SET_NEXT_VAL(dbustype, vargtype, arrtype, sigtype, fmt) \
    do { \
        dbustype x; \
        if (arrayref) { \
            arrtype valarray = arrayptr; \
            x = (dbustype)*valarray; \
            valarray++; \
            arrayptr = valarray; \
        } else { \
            x = (dbustype)va_arg(args, vargtype); \
        } \
        if (!dbus_message_iter_append_basic(iter, sigtype, &x)) { \
            virReportError(VIR_ERR_INTERNAL_ERROR, \
                           _("Cannot append basic type %s"), #vargtype);\
            goto cleanup; \
        } \
        VIR_DEBUG("Appended basic type '" #dbustype "' varg '" #vargtype\
                  "' sig '%c' val '" fmt "'", sigtype, (vargtype)x); \
    } while (0)


static int
virDBusMessageIterEncode(DBusMessageIter *rootiter,
                         const char *types,
                         va_list args)
{
    int ret = -1;
    size_t narray;
    size_t nstruct;
    bool arrayref = false;
    void *arrayptr = NULL;
    virDBusTypeStack *stack = NULL;
    size_t nstack = 0;
    size_t siglen;
    size_t skiplen;
    char *contsig = NULL;
    const char *vsig;
    DBusMessageIter *newiter = NULL;
    DBusMessageIter *iter = rootiter;

    VIR_DEBUG("rootiter=%p types=%s", rootiter, types);

    if (!types)
        return 0;

    narray = (size_t)-1;
    nstruct = strlen(types);

    for (;;) {
        const char *t;

        VIR_DEBUG("Loop nstack=%zu narray=%zd nstruct=%zu types='%s'",
                  nstack, (ssize_t)narray, nstruct, types);
        if (narray == 0 ||
            (narray == (size_t)-1 &&
             nstruct == 0)) {
            DBusMessageIter *thisiter = iter;
            if (*types != '}') {
                VIR_DEBUG("Reset array ref");
                arrayref = false;
                arrayptr = NULL;
            }
            VIR_DEBUG("Popping iter=%p", iter);
            if (nstack == 0)
                break;
            if (virDBusTypeStackPop(&stack, &nstack, &iter,
                                    &types, &nstruct, &narray) < 0)
                goto cleanup;
            VIR_DEBUG("Popped iter=%p", iter);

            if (!dbus_message_iter_close_container(iter, thisiter)) {
                if (thisiter != rootiter)
                    VIR_FREE(thisiter);
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Cannot close container iterator"));
                goto cleanup;
            }
            if (thisiter != rootiter)
                VIR_FREE(thisiter);
            continue;
        }

        t = types;
        if (narray != (size_t)-1) {
            narray--;
        } else {
            types++;
            nstruct--;
        }

        switch (*t) {
        case DBUS_TYPE_BYTE:
            SET_NEXT_VAL(unsigned char, int, unsigned char *, *t, "%d");
            break;

        case DBUS_TYPE_BOOLEAN:
            SET_NEXT_VAL(dbus_bool_t, int, bool *, *t, "%d");
            break;

        case DBUS_TYPE_INT16:
            SET_NEXT_VAL(dbus_int16_t, int, short *, *t, "%d");
            break;

        case DBUS_TYPE_UINT16:
            SET_NEXT_VAL(dbus_uint16_t, unsigned int, unsigned short *,
                         *t, "%d");
            break;

        case DBUS_TYPE_INT32:
            SET_NEXT_VAL(dbus_int32_t, int, int *, *t, "%d");
            break;

        case DBUS_TYPE_UINT32:
            SET_NEXT_VAL(dbus_uint32_t, unsigned int, unsigned int *,
                         *t, "%u");
            break;

        case DBUS_TYPE_INT64:
            SET_NEXT_VAL(dbus_int64_t, long long, long long *, *t, "%lld");
            break;

        case DBUS_TYPE_UINT64:
            SET_NEXT_VAL(dbus_uint64_t, unsigned long long,
                         unsigned long long *, *t, "%llu");
            break;

        case DBUS_TYPE_DOUBLE:
            SET_NEXT_VAL(double, double, double *, *t, "%lf");
            break;

        case DBUS_TYPE_STRING:
        case DBUS_TYPE_OBJECT_PATH:
        case DBUS_TYPE_SIGNATURE:
            SET_NEXT_VAL(char *, char *, char **, *t, "%s");
            break;

        case DBUS_TYPE_ARRAY:
            arrayptr = NULL;
            if (t[1] == '&') {
                VIR_DEBUG("Got array ref");
                t++;
                types++;
                nstruct--;
                arrayref = true;
            } else {
                VIR_DEBUG("Got array non-ref");
                arrayref = false;
            }

            if (!(contsig = virDBusCopyContainerSignature(t, &skiplen, &siglen)))
                goto cleanup;

            if (arrayref && !virDBusIsAllowedRefType(contsig)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Got array ref but '%s' is not a single basic type "
                                 "or dict with matching key+value type"),
                               contsig);
                goto cleanup;
            }

            if (narray == (size_t)-1) {
                types += skiplen;
                nstruct -= skiplen;
            }

            if (VIR_ALLOC(newiter) < 0)
                goto cleanup;
            VIR_DEBUG("Contsig '%s' skip='%zu' len='%zu'", contsig, skiplen, siglen);
            if (!dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
                                                  contsig, newiter))
                goto cleanup;
            if (virDBusTypeStackPush(&stack, &nstack,
                                     iter, types,
                                     nstruct, narray) < 0) {
                VIR_FREE(newiter);
                goto cleanup;
            }
            VIR_FREE(contsig);
            iter = g_steal_pointer(&newiter);
            types = t + 1;
            nstruct = skiplen;
            narray = (size_t)va_arg(args, int);
            if (arrayref)
                arrayptr = va_arg(args, void *);
            break;

        case DBUS_TYPE_VARIANT:
            vsig = va_arg(args, const char *);
            if (!vsig) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Missing variant type signature"));
                goto cleanup;
            }
            if (VIR_ALLOC(newiter) < 0)
                goto cleanup;
            if (!dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
                                                  vsig, newiter))
                goto cleanup;
            if (virDBusTypeStackPush(&stack, &nstack,
                                     iter, types,
                                     nstruct, narray) < 0) {
                VIR_FREE(newiter);
                goto cleanup;
            }
            iter = g_steal_pointer(&newiter);
            types = vsig;
            nstruct = strlen(types);
            narray = (size_t)-1;
            break;

        case DBUS_STRUCT_BEGIN_CHAR:
        case DBUS_DICT_ENTRY_BEGIN_CHAR:
            if (!(contsig = virDBusCopyContainerSignature(t, &skiplen, &siglen)))
                goto cleanup;

            if (VIR_ALLOC(newiter) < 0)
                goto cleanup;
            VIR_DEBUG("Contsig '%s' skip='%zu' len='%zu'", contsig, skiplen, siglen);
            if (!dbus_message_iter_open_container(iter,
                                                  *t == DBUS_STRUCT_BEGIN_CHAR ?
                                                  DBUS_TYPE_STRUCT : DBUS_TYPE_DICT_ENTRY,
                                                  NULL, newiter))
                goto cleanup;
            if (narray == (size_t)-1) {
                types += skiplen - 1;
                nstruct -= skiplen - 1;
            }

            if (virDBusTypeStackPush(&stack, &nstack,
                                     iter, types,
                                     nstruct, narray) < 0) {
                VIR_FREE(newiter);
                goto cleanup;
            }
            VIR_FREE(contsig);
            iter = g_steal_pointer(&newiter);
            types = t + 1;
            nstruct = skiplen - 2;
            narray = (size_t)-1;

            break;

        default:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown type '%x' in signature '%s'"),
                           (int)*t, types);
            goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    while (nstack > 0) {
        DBusMessageIter *thisiter = iter;
        VIR_DEBUG("Popping iter=%p", iter);
        ignore_value(virDBusTypeStackPop(&stack, &nstack, &iter,
                                         &types, &nstruct, &narray));
        VIR_DEBUG("Popped iter=%p", iter);

        if (thisiter != rootiter)
            VIR_FREE(thisiter);
    }

    virDBusTypeStackFree(&stack, &nstack);
    VIR_FREE(contsig);
    VIR_FREE(newiter);
    return ret;
}
# undef SET_NEXT_VAL


# define GET_NEXT_VAL(dbustype, member, vargtype, fmt) \
    do { \
        DBusBasicValue v; \
        dbustype *x = (dbustype *)&v.member; \
        vargtype *y; \
        if (arrayref) { \
            VIR_DEBUG("Use arrayref"); \
            vargtype **xptrptr = arrayptr; \
            if (VIR_EXPAND_N(*xptrptr, *narrayptr, 1) < 0) \
                goto cleanup; \
            y = (*xptrptr + (*narrayptr - 1)); \
            VIR_DEBUG("Expanded to %zu", *narrayptr); \
        } else { \
            y = va_arg(args, vargtype *); \
        } \
        dbus_message_iter_get_basic(iter, x); \
        *y = *x; \
        VIR_DEBUG("Read basic type '" #dbustype "' varg '" #vargtype \
                  "' val '" fmt "'", (vargtype)*y); \
    } while (0)


static int
virDBusMessageIterDecode(DBusMessageIter *rootiter,
                         const char *types,
                         va_list args)
{
    int ret = -1;
    size_t narray;
    size_t nstruct;
    bool arrayref = false;
    void *arrayptr = NULL;
    size_t *narrayptr = 0;
    virDBusTypeStack *stack = NULL;
    size_t nstack = 0;
    size_t skiplen;
    size_t siglen;
    char *contsig = NULL;
    const char *vsig;
    DBusMessageIter *newiter = NULL;
    DBusMessageIter *iter = rootiter;

    VIR_DEBUG("rootiter=%p types=%s", rootiter, types);

    if (!types)
        return 0;

    narray = (size_t)-1;
    nstruct = strlen(types);

    for (;;) {
        const char *t;
        bool advanceiter = true;

        VIR_DEBUG("Loop nstack=%zu narray=%zd nstruct=%zu type='%s'",
                  nstack, (ssize_t)narray, nstruct, types);
        if (narray == 0 ||
            (narray == (size_t)-1 &&
             nstruct == 0)) {
            DBusMessageIter *thisiter = iter;
            VIR_DEBUG("Popping iter=%p", iter);
            if (nstack == 0)
                break;
            if (virDBusTypeStackPop(&stack, &nstack, &iter,
                                    &types, &nstruct, &narray) < 0)
                goto cleanup;
            VIR_DEBUG("Popped iter=%p types=%s", iter, types);
            if (strchr(types, '}') == NULL) {
                arrayref = false;
                arrayptr = NULL;
                VIR_DEBUG("Clear array ref flag");
            }
            if (thisiter != rootiter)
                VIR_FREE(thisiter);
            if (arrayref) {
                if (!dbus_message_iter_has_next(iter))
                    narray = 0;
                else
                    narray = 1;
                VIR_DEBUG("Pop set narray=%zd", (ssize_t)narray);
            }
            if (!(narray == 0 ||
                  (narray == (size_t)-1 &&
                   nstruct == 0)) &&
                !dbus_message_iter_next(iter)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Not enough fields in message for signature"));
                goto cleanup;
            }
            continue;
        }

        t = types;
        if (narray != (size_t)-1) {
            if (!arrayref)
                narray--;
        } else {
            types++;
            nstruct--;
        }

        switch (*t) {
        case DBUS_TYPE_BYTE:
            GET_NEXT_VAL(unsigned char, byt, unsigned char, "%d");
            break;

        case DBUS_TYPE_BOOLEAN:
            GET_NEXT_VAL(dbus_bool_t, bool_val, bool, "%d");
            break;

        case DBUS_TYPE_INT16:
            GET_NEXT_VAL(dbus_int16_t, i16, short, "%d");
            break;

        case DBUS_TYPE_UINT16:
            GET_NEXT_VAL(dbus_uint16_t, u16, unsigned short, "%d");
            break;

        case DBUS_TYPE_INT32:
            GET_NEXT_VAL(dbus_uint32_t, i32, int, "%d");
            break;

        case DBUS_TYPE_UINT32:
            GET_NEXT_VAL(dbus_uint32_t, u32, unsigned int, "%u");
            break;

        case DBUS_TYPE_INT64:
            GET_NEXT_VAL(dbus_uint64_t, i64, long long, "%lld");
            break;

        case DBUS_TYPE_UINT64:
            GET_NEXT_VAL(dbus_uint64_t, u64, unsigned long long, "%llu");
            break;

        case DBUS_TYPE_DOUBLE:
            GET_NEXT_VAL(double, dbl, double, "%lf");
            break;

        case DBUS_TYPE_STRING:
        case DBUS_TYPE_OBJECT_PATH:
        case DBUS_TYPE_SIGNATURE:
            do {
                char **x;
                if (arrayref) {
                    char ***xptrptr = arrayptr;
                    if (VIR_EXPAND_N(*xptrptr, *narrayptr, 1) < 0)
                        goto cleanup;
                    x = (char **)(*xptrptr + (*narrayptr - 1));
                    VIR_DEBUG("Expanded to %zu", *narrayptr);
                } else {
                    x = (char **)va_arg(args, char **);
                }
                char *s;
                dbus_message_iter_get_basic(iter, &s);
                if (VIR_STRDUP(*x, s) < 0)
                    goto cleanup;
                VIR_DEBUG("Read basic type 'char *' varg 'char **'"
                          "' val '%s'", *x);
            } while (0);
            break;

        case DBUS_TYPE_ARRAY:
            arrayptr = NULL;
            if (t[1] == '&') {
                VIR_DEBUG("Got array ref");
                t++;
                types++;
                nstruct--;
                arrayref = true;
            } else {
                VIR_DEBUG("Got array non-ref");
                arrayref = false;
            }

            advanceiter = false;
            if (!(contsig = virDBusCopyContainerSignature(t, &skiplen, &siglen)))
                goto cleanup;

            if (arrayref && !virDBusIsAllowedRefType(contsig)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Got array ref but '%s' is not a single basic type / dict"),
                               contsig);
                goto cleanup;
            }

            if (narray == (size_t)-1) {
                types += skiplen;
                nstruct -= skiplen;
            }

            if (VIR_ALLOC(newiter) < 0)
                goto cleanup;
            VIR_DEBUG("Array contsig='%s' skip=%'zu' len='%zu' types='%s'",
                      contsig, skiplen, siglen, types);
            dbus_message_iter_recurse(iter, newiter);
            if (virDBusTypeStackPush(&stack, &nstack,
                                     iter, types,
                                     nstruct, narray) < 0)
                goto cleanup;
            VIR_FREE(contsig);
            iter = g_steal_pointer(&newiter);
            types = t + 1;
            nstruct = skiplen;
            if (arrayref) {
                narrayptr = va_arg(args, size_t *);
                arrayptr = va_arg(args, void *);
                *narrayptr = 0;
                *(char **)arrayptr = NULL;
            } else {
                narray = va_arg(args, int);
            }
            break;

        case DBUS_TYPE_VARIANT:
            advanceiter = false;
            vsig = va_arg(args, const char *);
            if (!vsig) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Missing variant type signature"));
                goto cleanup;
            }
            if (VIR_ALLOC(newiter) < 0)
                goto cleanup;
            dbus_message_iter_recurse(iter, newiter);
            if (virDBusTypeStackPush(&stack, &nstack,
                                     iter, types,
                                     nstruct, narray) < 0) {
                VIR_DEBUG("Push failed");
                goto cleanup;
            }
            iter = g_steal_pointer(&newiter);
            types = vsig;
            nstruct = strlen(types);
            narray = (size_t)-1;
            break;

        case DBUS_STRUCT_BEGIN_CHAR:
        case DBUS_DICT_ENTRY_BEGIN_CHAR:
            advanceiter = false;
            if (!(contsig = virDBusCopyContainerSignature(t, &skiplen, &siglen)))
                goto cleanup;

            if (VIR_ALLOC(newiter) < 0)
                goto cleanup;
            VIR_DEBUG("Dict/struct contsig='%s' skip='%zu' len='%zu' types='%s'",
                      contsig, skiplen, siglen, types);
            dbus_message_iter_recurse(iter, newiter);
            if (narray == (size_t)-1) {
                types += skiplen - 1;
                nstruct -= skiplen - 1;
            }

            if (virDBusTypeStackPush(&stack, &nstack,
                                     iter, types,
                                     nstruct, narray) < 0)
                goto cleanup;
            VIR_FREE(contsig);
            iter = g_steal_pointer(&newiter);
            types = t + 1;
            nstruct = skiplen - 2;
            narray = (size_t)-1;

            break;

        default:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown type '%c' in signature '%s'"),
                           *t, types);
            goto cleanup;
        }

        VIR_DEBUG("After nstack=%zu narray=%zd nstruct=%zu types='%s'",
                  nstack, (ssize_t)narray, nstruct, types);

        if (arrayref) {
            if (dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_INVALID) {
                narray = 0;
            } else {
                if (advanceiter)
                    dbus_message_iter_next(iter);
                if (dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_INVALID) {
                    narray = 0;
                } else {
                    narray = 1;
                }
            }
            VIR_DEBUG("Set narray=%zd", (ssize_t)narray);
        } else {
            if (advanceiter &&
                !(narray == 0 ||
                  (narray == (size_t)-1 &&
                   nstruct == 0)) &&
                !dbus_message_iter_next(iter)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Not enough fields in message for signature"));
                goto cleanup;
            }
        }
    }

    if (dbus_message_iter_has_next(iter)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Too many fields in message for signature"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virDBusTypeStackFree(&stack, &nstack);
    VIR_FREE(contsig);
    VIR_FREE(newiter);
    return ret;
}
# undef GET_NEXT_VAL

int
virDBusMessageEncodeArgs(DBusMessage* msg,
                         const char *types,
                         va_list args)
{
    DBusMessageIter iter;
    int ret = -1;

    memset(&iter, 0, sizeof(iter));

    dbus_message_iter_init_append(msg, &iter);

    ret = virDBusMessageIterEncode(&iter, types, args);

    return ret;
}


int virDBusMessageDecodeArgs(DBusMessage* msg,
                             const char *types,
                             va_list args)
{
    DBusMessageIter iter;
    int ret = -1;

    if (!dbus_message_iter_init(msg, &iter)) {
        if (*types != '\0') {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("No args present for signature %s"),
                           types);
        } else {
            ret = 0;
        }
        goto cleanup;
    }

    ret = virDBusMessageIterDecode(&iter, types, args);

 cleanup:
    return ret;
}


int virDBusMessageEncode(DBusMessage* msg,
                         const char *types,
                         ...)
{
    int ret;
    va_list args;
    va_start(args, types);
    ret = virDBusMessageEncodeArgs(msg, types, args);
    va_end(args);
    return ret;
}


/**
 * virDBusMessageDecode:
 * @msg: the reply to decode
 * @types: type signature for following return values
 * @...: pointers in which to store return values
 *
 * The @types type signature is the same format as
 * that used for the virDBusCallMethod. The difference
 * is that each variadic parameter must be a pointer to
 * be filled with the values. eg instead of passing an
 * 'int', pass an 'int *'.
 *
 */
int
virDBusMessageDecode(DBusMessage* msg,
                     const char *types,
                     ...)
{
    int ret;
    va_list args;
    va_start(args, types);
    ret = virDBusMessageDecodeArgs(msg, types, args);
    va_end(args);
    return ret;
}

# define VIR_DBUS_METHOD_CALL_TIMEOUT_MILLIS 30 * 1000

/**
 * virDBusCreateMethodV:
 * @call: pointer to be filled with a method call message
 * @destination: bus identifier of the target service
 * @path: object path of the target service
 * @iface: the interface of the object
 * @member: the name of the method in the interface
 * @types: type signature for following method arguments
 * @args: method arguments
 *
 * This creates a DBus method call message and saves a
 * pointer to it in @call. The @destination, @path, @iface
 * and @member parameters identify the object method to
 * be invoked. The optional @replyout parameter will be
 * filled with any reply to the method call. The method
 * can be later invoked using virDBusCall.
 *
 * The @types parameter is a DBus signature describing
 * the method call parameters which will be provided
 * as variadic args. Each character in @types must
 * correspond to one of the following DBus codes for
 * basic types:
 *
 * 'y' - 8-bit byte, promoted to an 'int'
 * 'b' - bool value, promoted to an 'int'
 * 'n' - 16-bit signed integer, promoted to an 'int'
 * 'q' - 16-bit unsigned integer, promoted to an 'int'
 * 'i' - 32-bit signed integer, passed as an 'int'
 * 'u' - 32-bit unsigned integer, passed as an 'int'
 * 'x' - 64-bit signed integer, passed as a 'long long'
 * 't' - 64-bit unsigned integer, passed as an 'unsigned long long'
 * 'd' - 8-byte floating point, passed as a 'double'
 * 's' - NUL-terminated string, in UTF-8
 * 'o' - NUL-terminated string, representing a valid object path
 * 'g' - NUL-terminated string, representing a valid type signature
 *
 * or use one of the compound types
 *
 * 'a' - array of values
 * 'v' - a variadic type.
 * '(' - start of a struct
 * ')' - end of a struct
 * '{' - start of a dictionary entry (pair of types)
 * '}' - start of a dictionary entry (pair of types)
 *
 * At this time, there is no support for Unix fd's ('h'), which only
 * newer DBus supports.
 *
 * Passing values in variadic args for basic types is
 * simple, the value is just passed directly using the
 * corresponding C type listed against the type code
 * above. Note how any integer value smaller than an
 * 'int' is promoted to an 'int' by the C rules for
 * variadic args.
 *
 * Passing values in variadic args for compound types
 * requires a little further explanation.
 *
 * - Variant: the first arg is a string containing
 *   the type signature for the values to be stored
 *   inside the variant. This is then followed by
 *   the values corresponding to the type signature
 *   in the normal manner.
 *
 * - Array: when 'a' appears in a type signature, it
 *   must be followed by a single type describing the
 *   array element type. For example 'as' is an array
 *   of strings. 'a(is)' is an array of structs, each
 *   struct containing an int and a string.
 *
 *   The first variadic arg for an array, is an 'int'
 *   specifying the number of elements in the array.
 *   This is then followed by additional variadic args,
 *   one for each element of the array.
 *
 * - Array reference: when 'a' appears in a type signature,
 *   followed by '&', this signifies an array passed by
 *   reference.
 *
 *   Array references may only be used when the
 *   element values are basic types, or a dict
 *   entry where both keys and values are using
 *   the same basic type.
 *
 *   The first variadic arg for an array, is an 'int'
 *   specifying the number of elements in the array.
 *   When the element is a basic type, the second
 *   variadic arg is a pointer to an array containing
 *   the element values. When the element is a dict
 *   entry, the second variadic arg is a pointer to
 *   an array containing the dict keys, and the
 *   third variadic arg is a pointer to an array
 *   containing the dict values.
 *
 * - Struct: when a '(' appears in a type signature,
 *   it must be followed by one or more types describing
 *   the elements in the array, terminated by a ')'.
 *
 * - Dict entry: when a '{' appears in a type signature it
 *   must be followed by exactly two types, one describing
 *   the type of the hash key, the other describing the
 *   type of the hash entry. The hash key type must be
 *   a basic type, not a compound type.
 *
 * Example signatures, with their corresponding variadic
 * args:
 *
 * - "biiss" - some basic types
 *
 *     (true, 7, 42, "hello", "world")
 *
 * - "as" - an array with a basic type element
 *
 *     (3, "one", "two", "three")
 *
 * - "a(is)" - an array with a struct element
 *
 *     (3, 1, "one", 2, "two", 3, "three")
 *
 * - "svs" - some basic types with a variant as an int
 *
 *     ("hello", "i", 3, "world")
 *
 * - "svs" - some basic types with a variant as an array of ints
 *
 *     ("hello", "ai", 4, 1, 2, 3, 4, "world")
 *
 * - "a{ss}" - a hash table (aka array + dict entry)
 *
 *     (3, "title", "Mr", "forename", "Joe", "surname", "Bloggs")
 *
 * - "a{sv}" - a hash table (aka array + dict entry)
 *
 *     (3, "email", "s", "joe@blogs.com", "age", "i", 35,
 *      "address", "as", 3, "Some house", "Some road", "some city")
 */
int virDBusCreateMethodV(DBusMessage **call,
                         const char *destination,
                         const char *path,
                         const char *iface,
                         const char *member,
                         const char *types,
                         va_list args)
{
    int ret = -1;

    if (!(*call = dbus_message_new_method_call(destination,
                                               path,
                                               iface,
                                               member))) {
        virReportOOMError();
        goto cleanup;
    }

    if (virDBusMessageEncodeArgs(*call, types, args) < 0) {
        virDBusMessageUnref(*call);
        *call = NULL;
        goto cleanup;
    }

    ret = 0;
 cleanup:
    return ret;
}


/**
 * virDBusCreateMethod:
 * @call: pointer to be filled with a method call message
 * @destination: bus identifier of the target service
 * @path: object path of the target service
 * @iface: the interface of the object
 * @member: the name of the method in the interface
 * @types: type signature for following method arguments
 * @...: method arguments
 *
 * See virDBusCreateMethodV for a description of the
 * behaviour of this method.
 */
int virDBusCreateMethod(DBusMessage **call,
                        const char *destination,
                        const char *path,
                        const char *iface,
                        const char *member,
                        const char *types, ...)
{
    va_list args;
    int ret;

    va_start(args, types);
    ret = virDBusCreateMethodV(call, destination, path,
                               iface, member, types, args);
    va_end(args);

    return ret;
}


/**
 * virDBusCreateReplyV:
 * @reply: pointer to be filled with a method reply message
 * @types: type signature for following method arguments
 * @args: method arguments
 *
 * This creates a DBus method reply message and saves a
 * pointer to it in @reply.
 *
 * The @types parameter is a DBus signature describing
 * the method call parameters which will be provided
 * as variadic args. See virDBusCreateMethodV for a
 * description of this parameter.
 */
int virDBusCreateReplyV(DBusMessage **reply,
                        const char *types,
                        va_list args)
{
    int ret = -1;

    if (!(*reply = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_RETURN))) {
        virReportOOMError();
        goto cleanup;
    }

    if (virDBusMessageEncodeArgs(*reply, types, args) < 0) {
        virDBusMessageUnref(*reply);
        *reply = NULL;
        goto cleanup;
    }

    ret = 0;
 cleanup:
    return ret;
}


/**
 * virDBusCreateReply:
 * @reply: pointer to be filled with a method reply message
 * @types: type signature for following method arguments
 * @...: method arguments
 *
 * See virDBusCreateReplyV for a description of the
 * behaviour of this method.
 */
int virDBusCreateReply(DBusMessage **reply,
                       const char *types, ...)
{
    va_list args;
    int ret;

    va_start(args, types);
    ret = virDBusCreateReplyV(reply, types, args);
    va_end(args);

    return ret;
}


/**
 * virDBusCall:
 * @conn: a DBus connection
 * @call: pointer to a message to send
 * @replyout: pointer to receive reply message, or NULL
 * @error: pointer to receive error message
 *
 * This invokes a method encoded in @call on a remote
 * service on the DBus bus @conn. The optional @replyout
 * parameter will be filled with any reply to the method
 * call. The virDBusMethodReply method can be used to
 * decode the return values.
 *
 * If @error is NULL then a libvirt error will be raised
 * when a DBus error is received and the return value will
 * be -1. If @error is non-NULL then any DBus error will
 * be saved into that object and the return value will
 * be 0.
 *
 * Returns 0 on success, or -1 upon error
 */
static int
virDBusCall(DBusConnection *conn,
            DBusMessage *call,
            DBusMessage **replyout,
            virErrorPtr error)

{
    DBusMessage *reply = NULL;
    DBusError localerror;
    int ret = -1;
    const char *iface, *member, *path, *dest;

    dbus_error_init(&localerror);
    if (error)
        memset(error, 0, sizeof(*error));

    iface = dbus_message_get_interface(call);
    member = dbus_message_get_member(call);
    path = dbus_message_get_path(call);
    dest = dbus_message_get_destination(call);

    PROBE(DBUS_METHOD_CALL,
          "'%s.%s' on '%s' at '%s'",
          iface, member, path, dest);

    if (!(reply = dbus_connection_send_with_reply_and_block(conn,
                                                            call,
                                                            VIR_DBUS_METHOD_CALL_TIMEOUT_MILLIS,
                                                            &localerror))) {
        PROBE(DBUS_METHOD_ERROR,
              "'%s.%s' on '%s' at '%s' error %s: %s",
              iface, member, path, dest,
              localerror.name,
              localerror.message);
        if (error) {
            error->level = VIR_ERR_ERROR;
            error->code = VIR_ERR_DBUS_SERVICE;
            error->domain = VIR_FROM_DBUS;
            if (VIR_STRDUP(error->message, localerror.message) < 0)
                goto cleanup;
            if (VIR_STRDUP(error->str1, localerror.name) < 0)
                goto cleanup;
            ret = 0;
        } else {
            virReportError(VIR_ERR_DBUS_SERVICE, _("%s: %s"), member,
                           localerror.message ? : _("unknown error"));
        }
        goto cleanup;
    }

    PROBE(DBUS_METHOD_REPLY,
          "'%s.%s' on '%s' at '%s'",
          iface, member, path, dest);

    ret = 0;

 cleanup:
    if (ret < 0 && error)
        virResetError(error);
    dbus_error_free(&localerror);
    if (reply) {
        if (ret == 0 && replyout)
            *replyout = reply;
        else
            virDBusMessageUnref(reply);
    }
    return ret;
}


/**
 * virDBusCallMethod:
 * @conn: a DBus connection
 * @replyout: pointer to receive reply message, or NULL
 * @destination: bus identifier of the target service
 * @path: object path of the target service
 * @iface: the interface of the object
 * @member: the name of the method in the interface
 * @types: type signature for following method arguments
 * @...: method arguments
 *
 * This invokes a method on a remote service on the
 * DBus bus @conn. The @destination, @path, @iface
 * and @member parameters identify the object method to
 * be invoked. The optional @replyout parameter will be
 * filled with any reply to the method call. The
 * virDBusMethodReply method can be used to decode the
 * return values.
 *
 * The @types parameter is a DBus signature describing
 * the method call parameters which will be provided
 * as variadic args. See virDBusCreateMethodV for a
 * description of this parameter.
 *
 *
 * If @error is NULL then a libvirt error will be raised
 * when a DBus error is received and the return value will
 * be -1. If @error is non-NULL then any DBus error will
 * be saved into that object and the return value will
 * be 0. If an error occurs while encoding method args
 * the return value will always be -1 regardless of whether
 * @error is set.
 *
 * Returns 0 on success, or -1 upon error
 */
int virDBusCallMethod(DBusConnection *conn,
                      DBusMessage **replyout,
                      virErrorPtr error,
                      const char *destination,
                      const char *path,
                      const char *iface,
                      const char *member,
                      const char *types, ...)
{
    DBusMessage *call = NULL;
    int ret = -1;
    va_list args;

    va_start(args, types);
    ret = virDBusCreateMethodV(&call, destination, path,
                               iface, member, types, args);
    va_end(args);
    if (ret < 0)
        goto cleanup;

    ret = virDBusCall(conn, call, replyout, error);

 cleanup:
    virDBusMessageUnref(call);
    return ret;
}


static int virDBusIsServiceInList(const char *listMethod, const char *name)
{
    DBusConnection *conn;
    DBusMessage *reply = NULL;
    DBusMessageIter iter, sub;
    int ret = -1;

    if (!virDBusHasSystemBus())
        return -2;

    if (!(conn = virDBusGetSystemBus()))
        return -1;

    if (virDBusCallMethod(conn,
                          &reply,
                          NULL,
                          "org.freedesktop.DBus",
                          "/org/freedesktop/DBus",
                          "org.freedesktop.DBus",
                          listMethod,
                          NULL) < 0)
        return ret;

    if (!dbus_message_iter_init(reply, &iter) ||
        dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Reply message incorrect"));
        goto cleanup;
    }

    ret = -2;
    dbus_message_iter_recurse(&iter, &sub);
    while (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRING) {
        const char *service = NULL;

        dbus_message_iter_get_basic(&sub, &service);
        dbus_message_iter_next(&sub);

        if (STREQ(service, name)) {
            ret = 0;
            break;
        }
    }

 cleanup:
    virDBusMessageUnref(reply);
    return ret;
}

/**
 * virDBusIsServiceEnabled:
 * @name: service name
 *
 * Returns 0 if service is available, -1 on fatal error, or -2 if service is not available
 */
int virDBusIsServiceEnabled(const char *name)
{
    int ret = virDBusIsServiceInList("ListActivatableNames", name);

    VIR_DEBUG("Service %s is %s", name, ret ? "unavailable" : "available");

    return ret;
}

/**
 * virDBusIsServiceRegistered
 * @name: service name
 *
 * Returns 0 if service is registered, -1 on fatal error, or -2 if service is not registered
 */
int virDBusIsServiceRegistered(const char *name)
{
    int ret = virDBusIsServiceInList("ListNames", name);

    VIR_DEBUG("Service %s is %s", name, ret ? "not registered" : "registered");

    return ret;
}

void virDBusMessageUnref(DBusMessage *msg)
{
    if (msg)
        dbus_message_unref(msg);
}

#else /* ! WITH_DBUS */
void virDBusSetSharedBus(bool shared G_GNUC_UNUSED)
{
    /* nothing */
}

DBusConnection *virDBusGetSystemBus(void)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("DBus support not compiled into this binary"));
    return NULL;
}


bool
virDBusHasSystemBus(void)
{
    VIR_DEBUG("DBus support not compiled into this binary");
    return false;
}

void virDBusCloseSystemBus(void)
{
    /* nothing */
}

DBusConnection *virDBusGetSessionBus(void)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("DBus support not compiled into this binary"));
    return NULL;
}

int virDBusCreateMethod(DBusMessage **call G_GNUC_UNUSED,
                        const char *destination G_GNUC_UNUSED,
                        const char *path G_GNUC_UNUSED,
                        const char *iface G_GNUC_UNUSED,
                        const char *member G_GNUC_UNUSED,
                        const char *types G_GNUC_UNUSED, ...)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("DBus support not compiled into this binary"));
    return -1;
}

int virDBusCreateMethodV(DBusMessage **call G_GNUC_UNUSED,
                         const char *destination G_GNUC_UNUSED,
                         const char *path G_GNUC_UNUSED,
                         const char *iface G_GNUC_UNUSED,
                         const char *member G_GNUC_UNUSED,
                         const char *types G_GNUC_UNUSED,
                         va_list args G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("DBus support not compiled into this binary"));
    return -1;
}

int virDBusCreateReplyV(DBusMessage **reply G_GNUC_UNUSED,
                        const char *types G_GNUC_UNUSED,
                        va_list args G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("DBus support not compiled into this binary"));
    return -1;
}

int virDBusCreateReply(DBusMessage **reply G_GNUC_UNUSED,
                       const char *types G_GNUC_UNUSED, ...)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("DBus support not compiled into this binary"));
    return -1;
}

int virDBusCallMethod(DBusConnection *conn G_GNUC_UNUSED,
                      DBusMessage **reply G_GNUC_UNUSED,
                      virErrorPtr error G_GNUC_UNUSED,
                      const char *destination G_GNUC_UNUSED,
                      const char *path G_GNUC_UNUSED,
                      const char *iface G_GNUC_UNUSED,
                      const char *member G_GNUC_UNUSED,
                      const char *types G_GNUC_UNUSED, ...)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("DBus support not compiled into this binary"));
    return -1;
}


int virDBusMessageEncode(DBusMessage* msg G_GNUC_UNUSED,
                         const char *types G_GNUC_UNUSED,
                         ...)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("DBus support not compiled into this binary"));
    return -1;
}

int virDBusMessageDecode(DBusMessage* msg G_GNUC_UNUSED,
                         const char *types G_GNUC_UNUSED,
                         ...)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("DBus support not compiled into this binary"));
    return -1;
}

int virDBusIsServiceEnabled(const char *name G_GNUC_UNUSED)
{
    VIR_DEBUG("DBus support not compiled into this binary");
    return -2;
}

int virDBusIsServiceRegistered(const char *name G_GNUC_UNUSED)
{
    VIR_DEBUG("DBus support not compiled into this binary");
    return -2;
}

void virDBusMessageUnref(DBusMessage *msg G_GNUC_UNUSED)
{
    /* nothing */
}
#endif /* ! WITH_DBUS */

bool virDBusErrorIsUnknownMethod(virErrorPtr err)
{
    return err->domain == VIR_FROM_DBUS &&
        err->code == VIR_ERR_DBUS_SERVICE &&
        err->level == VIR_ERR_ERROR &&
        STREQ_NULLABLE("org.freedesktop.DBus.Error.UnknownMethod",
                       err->str1);
}
