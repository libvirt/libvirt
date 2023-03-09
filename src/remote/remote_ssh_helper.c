/*
 * remote_ssh_helper.c: a netcat replacement for proxying ssh tunnel to daemon
 *
 * Copyright (C) 2020 Red Hat, Inc.
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

#include <unistd.h>

#include "rpc/virnetsocket.h"
#include "viralloc.h"
#include "virlog.h"
#include "virgettext.h"
#include "virfile.h"

#include "remote_sockets.h"

#define VIR_FROM_THIS VIR_FROM_REMOTE

#define SSH_BUF_SIZE (1024 * 1024)

VIR_LOG_INIT("remote.remote_ssh_helper");

struct virRemoteSSHHelperBuffer {
    size_t length;
    size_t offset;
    char *data;
};

typedef struct virRemoteSSHHelper virRemoteSSHHelper;
struct virRemoteSSHHelper {
    bool quit;
    virNetSocket *sock;
    int sockEvents;
    int stdinWatch;
    int stdinEvents;
    int stdoutWatch;
    int stdoutEvents;

    struct virRemoteSSHHelperBuffer sockToTerminal;
    struct virRemoteSSHHelperBuffer terminalToSock;
};


static void
virRemoteSSHHelperShutdown(virRemoteSSHHelper *proxy)
{
    if (proxy->sock) {
        virNetSocketRemoveIOCallback(proxy->sock);
        virNetSocketClose(proxy->sock);
        g_clear_pointer(&proxy->sock, virObjectUnref);
    }
    VIR_FREE(proxy->sockToTerminal.data);
    VIR_FREE(proxy->terminalToSock.data);
    if (proxy->stdinWatch != -1)
        virEventRemoveHandle(proxy->stdinWatch);
    if (proxy->stdoutWatch != -1)
        virEventRemoveHandle(proxy->stdoutWatch);
    proxy->stdinWatch = -1;
    proxy->stdoutWatch = -1;
    if (!proxy->quit)
        proxy->quit = true;
}


static void
virRemoteSSHHelperUpdateEvents(virRemoteSSHHelper *proxy)
{
    int sockEvents = 0;
    int stdinEvents = 0;
    int stdoutEvents = 0;

    if (proxy->terminalToSock.offset != 0)
        sockEvents |= VIR_EVENT_HANDLE_WRITABLE;
    if (proxy->terminalToSock.offset < proxy->terminalToSock.length)
        stdinEvents |= VIR_EVENT_HANDLE_READABLE;

    if (proxy->sockToTerminal.offset != 0)
        stdoutEvents |= VIR_EVENT_HANDLE_WRITABLE;
    if (proxy->sockToTerminal.offset < proxy->sockToTerminal.length)
        sockEvents |= VIR_EVENT_HANDLE_READABLE;

    if (sockEvents != proxy->sockEvents) {
        VIR_DEBUG("Update sock events %d -> %d", proxy->sockEvents, sockEvents);
        virNetSocketUpdateIOCallback(proxy->sock, sockEvents);
        proxy->sockEvents = sockEvents;
    }
    if (stdinEvents != proxy->stdinEvents) {
        VIR_DEBUG("Update stdin events %d -> %d", proxy->stdinEvents, stdinEvents);
        virEventUpdateHandle(proxy->stdinWatch, stdinEvents);
        proxy->stdinEvents = stdinEvents;
    }
    if (stdoutEvents != proxy->stdoutEvents) {
        VIR_DEBUG("Update stdout events %d -> %d", proxy->stdoutEvents, stdoutEvents);
        virEventUpdateHandle(proxy->stdoutWatch, stdoutEvents);
        proxy->stdoutEvents = stdoutEvents;
    }
}

static void
virRemoteSSHHelperEventOnSocket(virNetSocket *sock,
                                int events,
                                void *opaque)
{
    virRemoteSSHHelper *proxy = opaque;

    /* we got late event after proxy was shutdown */
    if (!proxy->sock)
        return;

    if (events & VIR_EVENT_HANDLE_READABLE) {
        size_t avail = proxy->sockToTerminal.length -
            proxy->sockToTerminal.offset;
        int got;

        if (avail == 0) {
            VIR_DEBUG("Unexpectedly called with no space in buffer");
            goto cleanup;
        }

        got = virNetSocketRead(sock,
                               proxy->sockToTerminal.data +
                               proxy->sockToTerminal.offset,
                               avail);
        if (got == -2)
            return; /* blocking */
        if (got == 0) {
            VIR_DEBUG("EOF on socket, shutting down");
            virRemoteSSHHelperShutdown(proxy);
            return;
        }
        if (got < 0) {
            virRemoteSSHHelperShutdown(proxy);
            return;
        }
        proxy->sockToTerminal.offset += got;
    }

    if (events & VIR_EVENT_HANDLE_WRITABLE &&
        proxy->terminalToSock.offset) {
        ssize_t done;
        done = virNetSocketWrite(proxy->sock,
                                 proxy->terminalToSock.data,
                                 proxy->terminalToSock.offset);
        if (done == -2)
            return; /* blocking */
        if (done < 0) {
            virRemoteSSHHelperShutdown(proxy);
            return;
        }

        memmove(proxy->terminalToSock.data,
                proxy->terminalToSock.data + done,
                proxy->terminalToSock.offset - done);
        proxy->terminalToSock.offset -= done;
    }

    if (events & VIR_EVENT_HANDLE_ERROR ||
        events & VIR_EVENT_HANDLE_HANGUP) {
        virRemoteSSHHelperShutdown(proxy);
        return;
    }

 cleanup:
    virRemoteSSHHelperUpdateEvents(proxy);
}


static void
virRemoteSSHHelperEventOnStdin(int watch G_GNUC_UNUSED,
                               int fd G_GNUC_UNUSED,
                               int events,
                               void *opaque)
{
    virRemoteSSHHelper *proxy = opaque;

    /* we got late event after console was shutdown */
    if (!proxy->sock)
        return;

    if (events & VIR_EVENT_HANDLE_READABLE) {
        size_t avail = proxy->terminalToSock.length -
            proxy->terminalToSock.offset;
        int got;

        if (avail == 0) {
            VIR_DEBUG("Unexpectedly called with no space in buffer");
            goto cleanup;
        }

        got = read(fd,
                   proxy->terminalToSock.data +
                   proxy->terminalToSock.offset,
                   avail);
        if (got < 0) {
            if (errno != EAGAIN) {
                virReportSystemError(errno, "%s", _("cannot read from stdin"));
                virRemoteSSHHelperShutdown(proxy);
            }
            return;
        }
        if (got == 0) {
            VIR_DEBUG("EOF on stdin, shutting down");
            virRemoteSSHHelperShutdown(proxy);
            return;
        }

        proxy->terminalToSock.offset += got;
    }

    if (events & VIR_EVENT_HANDLE_ERROR) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("IO error on stdin"));
        virRemoteSSHHelperShutdown(proxy);
        return;
    }

    if (events & VIR_EVENT_HANDLE_HANGUP) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("EOF on stdin"));
        virRemoteSSHHelperShutdown(proxy);
        return;
    }

 cleanup:
    virRemoteSSHHelperUpdateEvents(proxy);
}


static void
virRemoteSSHHelperEventOnStdout(int watch G_GNUC_UNUSED,
                                int fd,
                                int events,
                                void *opaque)
{
    virRemoteSSHHelper *proxy = opaque;

    /* we got late event after console was shutdown */
    if (!proxy->sock)
        return;

    if (events & VIR_EVENT_HANDLE_WRITABLE &&
        proxy->sockToTerminal.offset) {
        ssize_t done;
        done = write(fd, /* sc_avoid_write */
                     proxy->sockToTerminal.data,
                     proxy->sockToTerminal.offset);
        if (done < 0) {
            if (errno != EAGAIN) {
                virReportSystemError(errno, "%s", _("cannot write to stdout"));
                virRemoteSSHHelperShutdown(proxy);
            }
            return;
        }
        memmove(proxy->sockToTerminal.data,
                proxy->sockToTerminal.data + done,
                proxy->sockToTerminal.offset - done);
        proxy->sockToTerminal.offset -= done;
    }

    if (events & VIR_EVENT_HANDLE_ERROR) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("IO error stdout"));
        virRemoteSSHHelperShutdown(proxy);
        return;
    }

    if (events & VIR_EVENT_HANDLE_HANGUP) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("EOF on stdout"));
        virRemoteSSHHelperShutdown(proxy);
        return;
    }

    virRemoteSSHHelperUpdateEvents(proxy);
}


static int
virRemoteSSHHelperRun(virNetSocket *sock)
{
    int ret = -1;
    virRemoteSSHHelper proxy = {
        .sock = sock,
        .sockEvents = VIR_EVENT_HANDLE_READABLE,
        .stdinWatch = -1,
        .stdinEvents = VIR_EVENT_HANDLE_READABLE,
        .stdoutWatch = -1,
        .stdoutEvents = 0,
        .sockToTerminal = {
            .offset = 0,
            .length = SSH_BUF_SIZE,
            .data = g_new0(char, SSH_BUF_SIZE),
        },
        .terminalToSock = {
            .offset = 0,
            .length = SSH_BUF_SIZE,
            .data = g_new0(char, SSH_BUF_SIZE),
        },
    };

    virEventRegisterDefaultImpl();

    if ((proxy.stdinWatch = virEventAddHandle(STDIN_FILENO,
                                              VIR_EVENT_HANDLE_READABLE,
                                              virRemoteSSHHelperEventOnStdin,
                                              &proxy,
                                              NULL)) < 0)
        goto cleanup;

    if ((proxy.stdoutWatch = virEventAddHandle(STDOUT_FILENO,
                                               0,
                                               virRemoteSSHHelperEventOnStdout,
                                               &proxy,
                                               NULL)) < 0)
        goto cleanup;

    if (virNetSocketAddIOCallback(proxy.sock,
                                  VIR_EVENT_HANDLE_READABLE,
                                  virRemoteSSHHelperEventOnSocket,
                                  &proxy,
                                  NULL) < 0)
        goto cleanup;

    while (!proxy.quit)
        virEventRunDefaultImpl();

    if (virGetLastErrorCode() != VIR_ERR_OK)
        goto cleanup;

    ret = 0;
 cleanup:
    if (proxy.stdinWatch != -1)
        virEventRemoveHandle(proxy.stdinWatch);
    if (proxy.stdoutWatch != -1)
        virEventRemoveHandle(proxy.stdoutWatch);
    return ret;
}

int main(int argc, char **argv)
{
    const char *uri_str = NULL;
    g_autoptr(virURI) uri = NULL;
    g_autofree char *driver = NULL;
    remoteDriverTransport transport;
    int mode = REMOTE_DRIVER_MODE_AUTO;
    const char *mode_str = NULL;
    gboolean version = false;
    gboolean readonly = false;
    g_autofree char *sock_path = NULL;
    g_autofree char *daemon_path = NULL;
    g_autoptr(virNetSocket) sock = NULL;
    GError *error = NULL;
    g_autoptr(GOptionContext) context = NULL;
    GOptionEntry entries[] = {
        { "readonly", 'r', 0, G_OPTION_ARG_NONE, &readonly, "Connect read-only", NULL },
        { "version", 'V', 0, G_OPTION_ARG_NONE, &version, "Display version information", NULL },
        { NULL, '\0', 0, 0, NULL, NULL, NULL }
    };
    unsigned int flags;
    size_t i;

    context = g_option_context_new("URI - libvirt socket proxy");
    g_option_context_set_summary(context,
                                 "Internal tool used to handle connections coming from remote\n"
                                 "clients. Not intended to be called directly by the user.");
    g_option_context_add_main_entries(context, entries, PACKAGE);
    if (!g_option_context_parse(context, &argc, &argv, &error)) {
        g_printerr(_("option parsing failed: %1$s\n"), error->message);
        exit(EXIT_FAILURE);
    }

    if (version) {
        g_print("%s (%s) %s\n", argv[0], PACKAGE_NAME, PACKAGE_VERSION);
        exit(EXIT_SUCCESS);
    }

    if (argc != 2) {
        g_autofree char *help = g_option_context_get_help(context, TRUE, NULL);
        g_printerr("%s", help);
        exit(EXIT_FAILURE);
    }

    virSetErrorFunc(NULL, NULL);
    virSetErrorLogPriorityFunc(NULL);

    if (virGettextInitialize() < 0 ||
        virErrorInitialize() < 0) {
        g_printerr(_("%1$s: initialization failed\n"), argv[0]);
        exit(EXIT_FAILURE);
    }

    virFileActivateDirOverrideForProg(argv[0]);

    /* Initialize the log system */
    if (virLogSetFromEnv() < 0)
        exit(EXIT_FAILURE);

    uri_str = argv[1];
    VIR_DEBUG("Using URI %s", uri_str);

    if (!(uri = virURIParse(uri_str))) {
        g_printerr(("%s: cannot parse '%s': %s\n"),
                   argv[0], uri_str, virGetLastErrorMessage());
        exit(EXIT_FAILURE);
    }

    if (remoteSplitURIScheme(uri, &driver, &transport) < 0) {
        g_printerr(_("%1$s: cannot parse URI transport '%2$s': %3$s\n"),
                   argv[0], uri_str, virGetLastErrorMessage());
        exit(EXIT_FAILURE);
    }

    if (transport != REMOTE_DRIVER_TRANSPORT_UNIX) {
        g_printerr(_("%1$s: unexpected URI transport '%2$s'\n"),
                   argv[0], uri_str);
        exit(EXIT_FAILURE);
    }

    remoteGetURIDaemonInfo(uri, transport, &flags);
    if (readonly)
        flags |= REMOTE_DRIVER_OPEN_RO;

    for (i = 0; i < uri->paramsCount; i++) {
        virURIParam *var = &uri->params[i];

        if (STRCASEEQ(var->name, "mode")) {
            mode_str = var->value;
            continue;
        } else if (STRCASEEQ(var->name, "socket")) {
            sock_path = g_strdup(var->value);
            continue;
        }
    }

    if (mode_str &&
        (mode = remoteDriverModeTypeFromString(mode_str)) < 0) {
        g_printerr(_("%1$s: unknown remote mode '%2$s'"), argv[0], mode_str);
        exit(EXIT_FAILURE);
    }

    if (!sock_path &&
        !(sock_path = remoteGetUNIXSocket(transport, mode,
                                          driver, flags, &daemon_path))) {
        g_printerr(_("%1$s: failed to generate UNIX socket path"), argv[0]);
        exit(EXIT_FAILURE);
    }

    if (virNetSocketNewConnectUNIX(sock_path, daemon_path, &sock) < 0) {
        g_printerr(_("%1$s: cannot connect to '%2$s': %3$s\n"),
                   argv[0], sock_path, virGetLastErrorMessage());
        exit(EXIT_FAILURE);
    }

    if (virRemoteSSHHelperRun(sock) < 0) {
        g_printerr(_("%1$s: could not proxy traffic: %2$s\n"),
                   argv[0], virGetLastErrorMessage());
        exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);
}
