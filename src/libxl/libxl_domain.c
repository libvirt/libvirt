/*
 * libxl_domain.c: libxl domain object private state
 *
 * Copyright (C) 2011-2013 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 * Authors:
 *     Jim Fehlig <jfehlig@suse.com>
 */

#include <config.h>

#include "libxl_domain.h"

#include "viralloc.h"
#include "virfile.h"
#include "virerror.h"
#include "virlog.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_LIBXL


/* Append an event registration to the list of registrations */
#define LIBXL_EV_REG_APPEND(head, add)                 \
    do {                                               \
        libxlEventHookInfoPtr temp;                    \
        if (head) {                                    \
            temp = head;                               \
            while (temp->next)                         \
                temp = temp->next;                     \
            temp->next = add;                          \
        } else {                                       \
            head = add;                                \
        }                                              \
    } while (0)

/* Remove an event registration from the list of registrations */
#define LIBXL_EV_REG_REMOVE(head, del)                 \
    do {                                               \
        libxlEventHookInfoPtr temp;                    \
        if (head == del) {                             \
            head = head->next;                         \
        } else {                                       \
            temp = head;                               \
            while (temp->next && temp->next != del)    \
                temp = temp->next;                     \
            if (temp->next) {                          \
                temp->next = del->next;                \
            }                                          \
        }                                              \
    } while (0)

/* Object used to store info related to libxl event registrations */
struct _libxlEventHookInfo {
    libxlEventHookInfoPtr next;
    libxlDomainObjPrivatePtr priv;
    void *xl_priv;
    int id;
};

static virClassPtr libxlDomainObjPrivateClass;

static void
libxlDomainObjPrivateDispose(void *obj);

static int
libxlDomainObjPrivateOnceInit(void)
{
    if (!(libxlDomainObjPrivateClass = virClassNew(virClassForObjectLockable(),
                                                   "libxlDomainObjPrivate",
                                                   sizeof(libxlDomainObjPrivate),
                                                   libxlDomainObjPrivateDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(libxlDomainObjPrivate)

static void
libxlDomainObjEventHookInfoFree(void *obj)
{
    libxlEventHookInfoPtr info = obj;

    /* Drop reference on libxlDomainObjPrivate */
    virObjectUnref(info->priv);
    VIR_FREE(info);
}

static void
libxlDomainObjFDEventCallback(int watch ATTRIBUTE_UNUSED,
                              int fd,
                              int vir_events,
                              void *fd_info)
{
    libxlEventHookInfoPtr info = fd_info;
    int events = 0;

    virObjectLock(info->priv);
    if (vir_events & VIR_EVENT_HANDLE_READABLE)
        events |= POLLIN;
    if (vir_events & VIR_EVENT_HANDLE_WRITABLE)
        events |= POLLOUT;
    if (vir_events & VIR_EVENT_HANDLE_ERROR)
        events |= POLLERR;
    if (vir_events & VIR_EVENT_HANDLE_HANGUP)
        events |= POLLHUP;

    virObjectUnlock(info->priv);
    libxl_osevent_occurred_fd(info->priv->ctx, info->xl_priv, fd, 0, events);
}

static int
libxlDomainObjFDRegisterEventHook(void *priv,
                                  int fd,
                                  void **hndp,
                                  short events,
                                  void *xl_priv)
{
    int vir_events = VIR_EVENT_HANDLE_ERROR;
    libxlEventHookInfoPtr info;

    if (VIR_ALLOC(info) < 0)
        return -1;

    info->priv = priv;
    /*
     * Take a reference on the domain object.  Reference is dropped in
     * libxlDomainObjEventHookInfoFree, ensuring the domain object outlives
     * the fd event objects.
     */
    virObjectRef(info->priv);
    info->xl_priv = xl_priv;

    if (events & POLLIN)
        vir_events |= VIR_EVENT_HANDLE_READABLE;
    if (events & POLLOUT)
        vir_events |= VIR_EVENT_HANDLE_WRITABLE;

    info->id = virEventAddHandle(fd, vir_events, libxlDomainObjFDEventCallback,
                                 info, libxlDomainObjEventHookInfoFree);
    if (info->id < 0) {
        virObjectUnref(info->priv);
        VIR_FREE(info);
        return -1;
    }

    *hndp = info;

    return 0;
}

static int
libxlDomainObjFDModifyEventHook(void *priv ATTRIBUTE_UNUSED,
                                int fd ATTRIBUTE_UNUSED,
                                void **hndp,
                                short events)
{
    libxlEventHookInfoPtr info = *hndp;
    int vir_events = VIR_EVENT_HANDLE_ERROR;

    virObjectLock(info->priv);
    if (events & POLLIN)
        vir_events |= VIR_EVENT_HANDLE_READABLE;
    if (events & POLLOUT)
        vir_events |= VIR_EVENT_HANDLE_WRITABLE;

    virEventUpdateHandle(info->id, vir_events);
    virObjectUnlock(info->priv);

    return 0;
}

static void
libxlDomainObjFDDeregisterEventHook(void *priv ATTRIBUTE_UNUSED,
                                    int fd ATTRIBUTE_UNUSED,
                                    void *hnd)
{
    libxlEventHookInfoPtr info = hnd;
    libxlDomainObjPrivatePtr p = info->priv;

    virObjectLock(p);
    virEventRemoveHandle(info->id);
    virObjectUnlock(p);
}

static void
libxlDomainObjTimerCallback(int timer ATTRIBUTE_UNUSED, void *timer_info)
{
    libxlEventHookInfoPtr info = timer_info;
    libxlDomainObjPrivatePtr p = info->priv;

    virObjectLock(p);
    /*
     * libxl expects the event to be deregistered when calling
     * libxl_osevent_occurred_timeout, but we dont want the event info
     * destroyed.  Disable the timeout and only remove it after returning
     * from libxl.
     */
    virEventUpdateTimeout(info->id, -1);
    virObjectUnlock(p);
    libxl_osevent_occurred_timeout(p->ctx, info->xl_priv);
    virObjectLock(p);
    /*
     * Timeout could have been freed while the lock was dropped.
     * Only remove it from the list if it still exists.
     */
    if (virEventRemoveTimeout(info->id) == 0)
        LIBXL_EV_REG_REMOVE(p->timerRegistrations, info);
    virObjectUnlock(p);
}

static int
libxlDomainObjTimeoutRegisterEventHook(void *priv,
                                       void **hndp,
                                       struct timeval abs_t,
                                       void *xl_priv)
{
    libxlEventHookInfoPtr info;
    struct timeval now;
    struct timeval res;
    static struct timeval zero;
    int timeout;

    if (VIR_ALLOC(info) < 0)
        return -1;

    info->priv = priv;
    /*
     * Also take a reference on the domain object.  Reference is dropped in
     * libxlDomainObjEventHookInfoFree, ensuring the domain object outlives the
     * timeout event objects.
     */
    virObjectRef(info->priv);
    info->xl_priv = xl_priv;

    gettimeofday(&now, NULL);
    timersub(&abs_t, &now, &res);
    /* Ensure timeout is not overflowed */
    if (timercmp(&res, &zero, <)) {
        timeout = 0;
    } else if (res.tv_sec > INT_MAX / 1000) {
        timeout = INT_MAX;
    } else {
        timeout = res.tv_sec * 1000 + (res.tv_usec + 999) / 1000;
    }
    info->id = virEventAddTimeout(timeout, libxlDomainObjTimerCallback,
                                  info, libxlDomainObjEventHookInfoFree);
    if (info->id < 0) {
        virObjectUnref(info->priv);
        VIR_FREE(info);
        return -1;
    }

    virObjectLock(info->priv);
    LIBXL_EV_REG_APPEND(info->priv->timerRegistrations, info);
    virObjectUnlock(info->priv);
    *hndp = info;

    return 0;
}

/*
 * Note:  There are two changes wrt timeouts starting with xen-unstable
 * changeset 26469:
 *
 * 1. Timeout modify callbacks will only be invoked with an abs_t of {0,0},
 * i.e. make the timeout fire immediately.  Prior to this commit, timeout
 * modify callbacks were never invoked.
 *
 * 2. Timeout deregister hooks will no longer be called.
 */
static int
libxlDomainObjTimeoutModifyEventHook(void *priv ATTRIBUTE_UNUSED,
                                     void **hndp,
                                     struct timeval abs_t ATTRIBUTE_UNUSED)
{
    libxlEventHookInfoPtr info = *hndp;

    virObjectLock(info->priv);
    /* Make the timeout fire */
    virEventUpdateTimeout(info->id, 0);
    virObjectUnlock(info->priv);

    return 0;
}

static void
libxlDomainObjTimeoutDeregisterEventHook(void *priv ATTRIBUTE_UNUSED,
                                         void *hnd)
{
    libxlEventHookInfoPtr info = hnd;
    libxlDomainObjPrivatePtr p = info->priv;

    virObjectLock(p);
    /*
     * Only remove the timeout from the list if removal from the
     * event loop is successful.
     */
    if (virEventRemoveTimeout(info->id) == 0)
        LIBXL_EV_REG_REMOVE(p->timerRegistrations, info);
    virObjectUnlock(p);
}


static const libxl_osevent_hooks libxl_event_callbacks = {
    .fd_register = libxlDomainObjFDRegisterEventHook,
    .fd_modify = libxlDomainObjFDModifyEventHook,
    .fd_deregister = libxlDomainObjFDDeregisterEventHook,
    .timeout_register = libxlDomainObjTimeoutRegisterEventHook,
    .timeout_modify = libxlDomainObjTimeoutModifyEventHook,
    .timeout_deregister = libxlDomainObjTimeoutDeregisterEventHook,
};

static void *
libxlDomainObjPrivateAlloc(void)
{
    libxlDomainObjPrivatePtr priv;

    if (libxlDomainObjPrivateInitialize() < 0)
        return NULL;

    if (!(priv = virObjectLockableNew(libxlDomainObjPrivateClass)))
        return NULL;

    if (!(priv->devs = virChrdevAlloc())) {
        virObjectUnref(priv);
        return NULL;
    }

    return priv;
}

static void
libxlDomainObjPrivateDispose(void *obj)
{
    libxlDomainObjPrivatePtr priv = obj;

    if (priv->deathW)
        libxl_evdisable_domain_death(priv->ctx, priv->deathW);

    virChrdevFree(priv->devs);
    libxl_ctx_free(priv->ctx);
    if (priv->logger_file)
        VIR_FORCE_FCLOSE(priv->logger_file);

    xtl_logger_destroy(priv->logger);
}

static void
libxlDomainObjPrivateFree(void *data)
{
    libxlDomainObjPrivatePtr priv = data;

    if (priv->deathW) {
        libxl_evdisable_domain_death(priv->ctx, priv->deathW);
        priv->deathW = NULL;
    }

    virObjectUnref(priv);
}

virDomainXMLPrivateDataCallbacks libxlDomainXMLPrivateDataCallbacks = {
    .alloc = libxlDomainObjPrivateAlloc,
    .free = libxlDomainObjPrivateFree,
};


static int
libxlDomainDeviceDefPostParse(virDomainDeviceDefPtr dev,
                              const virDomainDef *def,
                              virCapsPtr caps ATTRIBUTE_UNUSED,
                              void *opaque ATTRIBUTE_UNUSED)
{
    if (dev->type == VIR_DOMAIN_DEVICE_CHR &&
        dev->data.chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
        dev->data.chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_NONE &&
        STRNEQ(def->os.type, "hvm"))
        dev->data.chr->targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_XEN;

    return 0;
}

virDomainDefParserConfig libxlDomainDefParserConfig = {
    .macPrefix = { 0x00, 0x16, 0x3e },
    .devicesPostParseCallback = libxlDomainDeviceDefPostParse,
};

int
libxlDomainObjPrivateInitCtx(virDomainObjPtr vm)
{
    libxlDomainObjPrivatePtr priv = vm->privateData;
    char *log_file;
    int ret = -1;

    if (priv->ctx)
        return 0;

    if (virAsprintf(&log_file, "%s/%s.log", LIBXL_LOG_DIR, vm->def->name) < 0)
        return -1;

    if ((priv->logger_file = fopen(log_file, "a")) == NULL)  {
        virReportSystemError(errno,
                             _("failed to open logfile %s"),
                             log_file);
        goto cleanup;
    }

    priv->logger =
        (xentoollog_logger *)xtl_createlogger_stdiostream(priv->logger_file,
                                                          XTL_DEBUG, 0);
    if (!priv->logger) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot create libxenlight logger for domain %s"),
                       vm->def->name);
        goto cleanup;
    }

    if (libxl_ctx_alloc(&priv->ctx, LIBXL_VERSION, 0, priv->logger)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed libxl context initialization"));
        goto cleanup;
    }

    libxl_osevent_register_hooks(priv->ctx, &libxl_event_callbacks, priv);

    ret = 0;

cleanup:
    VIR_FREE(log_file);
    return ret;
}

void
libxlDomainObjRegisteredTimeoutsCleanup(libxlDomainObjPrivatePtr priv)
{
    libxlEventHookInfoPtr info;

    virObjectLock(priv);
    info = priv->timerRegistrations;
    while (info) {
        /*
         * libxl expects the event to be deregistered when calling
         * libxl_osevent_occurred_timeout, but we dont want the event info
         * destroyed.  Disable the timeout and only remove it after returning
         * from libxl.
         */
        virEventUpdateTimeout(info->id, -1);
        libxl_osevent_occurred_timeout(priv->ctx, info->xl_priv);
        virEventRemoveTimeout(info->id);
        info = info->next;
    }
    priv->timerRegistrations = NULL;
    virObjectUnlock(priv);
}
