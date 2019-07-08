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

VIR_LOG_INIT("remote.remote_ssh_helper");

struct virRemoteSSHHelperBuffer {
    size_t length;
    size_t offset;
    char *data;
};

typedef struct virRemoteSSHHelper virRemoteSSHHelper;
typedef virRemoteSSHHelper *virRemoteSSHHelperPtr;
struct virRemoteSSHHelper {
    bool quit;
    virNetSocketPtr sock;
    int stdinWatch;
    int stdoutWatch;

    struct virRemoteSSHHelperBuffer sockToTerminal;
    struct virRemoteSSHHelperBuffer terminalToSock;
};


static void
virRemoteSSHHelperShutdown(virRemoteSSHHelperPtr proxy)
{
    if (proxy->sock) {
        virNetSocketRemoveIOCallback(proxy->sock);
        virNetSocketClose(proxy->sock);
        virObjectUnref(proxy->sock);
        proxy->sock = NULL;
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
virRemoteSSHHelperEventOnSocket(virNetSocketPtr sock,
                                int events,
                                void *opaque)
{
    virRemoteSSHHelperPtr proxy = opaque;

    /* we got late event after proxy was shutdown */
    if (!proxy->sock)
        return;

    if (events & VIR_EVENT_HANDLE_READABLE) {
        size_t avail = proxy->sockToTerminal.length -
            proxy->sockToTerminal.offset;
        int got;

        if (avail < 1024) {
            if (VIR_REALLOC_N(proxy->sockToTerminal.data,
                              proxy->sockToTerminal.length + 1024) < 0) {
                virRemoteSSHHelperShutdown(proxy);
                return;
            }
            proxy->sockToTerminal.length += 1024;
            avail += 1024;
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
        if (proxy->sockToTerminal.offset)
            virEventUpdateHandle(proxy->stdoutWatch,
                                 VIR_EVENT_HANDLE_WRITABLE);
    }

    if (events & VIR_EVENT_HANDLE_WRITABLE &&
        proxy->terminalToSock.offset) {
        ssize_t done;
        size_t avail;
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

        avail = proxy->terminalToSock.length - proxy->terminalToSock.offset;
        if (avail > 1024) {
            ignore_value(VIR_REALLOC_N(proxy->terminalToSock.data,
                                       proxy->terminalToSock.offset + 1024));
            proxy->terminalToSock.length = proxy->terminalToSock.offset + 1024;
        }
    }
    if (!proxy->terminalToSock.offset)
        virNetSocketUpdateIOCallback(proxy->sock,
                                     VIR_EVENT_HANDLE_READABLE);

    if (events & VIR_EVENT_HANDLE_ERROR ||
        events & VIR_EVENT_HANDLE_HANGUP) {
        virRemoteSSHHelperShutdown(proxy);
    }
}


static void
virRemoteSSHHelperEventOnStdin(int watch G_GNUC_UNUSED,
                               int fd G_GNUC_UNUSED,
                               int events,
                               void *opaque)
{
    virRemoteSSHHelperPtr proxy = opaque;

    /* we got late event after console was shutdown */
    if (!proxy->sock)
        return;

    if (events & VIR_EVENT_HANDLE_READABLE) {
        size_t avail = proxy->terminalToSock.length -
            proxy->terminalToSock.offset;
        int got;

        if (avail < 1024) {
            if (VIR_REALLOC_N(proxy->terminalToSock.data,
                              proxy->terminalToSock.length + 1024) < 0) {
                virRemoteSSHHelperShutdown(proxy);
                return;
            }
            proxy->terminalToSock.length += 1024;
            avail += 1024;
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
        if (proxy->terminalToSock.offset)
            virNetSocketUpdateIOCallback(proxy->sock,
                                         VIR_EVENT_HANDLE_READABLE |
                                         VIR_EVENT_HANDLE_WRITABLE);
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
}


static void
virRemoteSSHHelperEventOnStdout(int watch G_GNUC_UNUSED,
                                int fd,
                                int events,
                                void *opaque)
{
    virRemoteSSHHelperPtr proxy = opaque;

    /* we got late event after console was shutdown */
    if (!proxy->sock)
        return;

    if (events & VIR_EVENT_HANDLE_WRITABLE &&
        proxy->sockToTerminal.offset) {
        ssize_t done;
        size_t avail;
        done = write(fd,
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

        avail = proxy->sockToTerminal.length - proxy->sockToTerminal.offset;
        if (avail > 1024) {
            ignore_value(VIR_REALLOC_N(proxy->sockToTerminal.data,
                                       proxy->sockToTerminal.offset + 1024));
            proxy->sockToTerminal.length = proxy->sockToTerminal.offset + 1024;
        }
    }

    if (!proxy->sockToTerminal.offset)
        virEventUpdateHandle(proxy->stdoutWatch, 0);

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
}


static int
virRemoteSSHHelperRun(virNetSocketPtr sock)
{
    int ret = -1;
    virRemoteSSHHelper proxy = {
        .sock = sock,
        .stdinWatch = -1,
        .stdoutWatch = -1,
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
    bool user = false;
    bool autostart = false;
    gboolean version = false;
    gboolean readonly = false;
    g_autofree char *sock_path = NULL;
    g_autofree char *daemon_name = NULL;
    g_autoptr(virNetSocket) sock = NULL;
    GError *error = NULL;
    g_autoptr(GOptionContext) context = NULL;
    GOptionEntry entries[] = {
        { "readonly", 'r', 0, G_OPTION_ARG_NONE, &readonly, "Connect read-only", NULL },
        { "version", 'V', 0, G_OPTION_ARG_NONE, &version, "Display version information", NULL },
        { NULL, '\0', 0, 0, NULL, NULL, NULL }
    };

    context = g_option_context_new("- libvirt socket proxy");
    g_option_context_add_main_entries(context, entries, PACKAGE);
    if (!g_option_context_parse(context, &argc, &argv, &error)) {
        g_printerr(_("option parsing failed: %s\n"), error->message);
        exit(EXIT_FAILURE);
    }

    if (version) {
        g_print("%s (%s) %s\n", argv[0], PACKAGE_NAME, PACKAGE_VERSION);
        exit(EXIT_SUCCESS);
    }

    virSetErrorFunc(NULL, NULL);
    virSetErrorLogPriorityFunc(NULL);

    if (virGettextInitialize() < 0 ||
        virErrorInitialize() < 0) {
        g_printerr(_("%s: initialization failed\n"), argv[0]);
        exit(EXIT_FAILURE);
    }

    virFileActivateDirOverrideForProg(argv[0]);

    /* Initialize the log system */
    virLogSetFromEnv();

    if (optind != (argc - 1)) {
        g_printerr("%s: expected a URI\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    uri_str = argv[optind];
    VIR_DEBUG("Using URI %s", uri_str);

    if (!(uri = virURIParse(uri_str))) {
        g_printerr(("%s: cannot parse '%s': %s\n"),
                   argv[0], uri_str, virGetLastErrorMessage());
        exit(EXIT_FAILURE);
    }

    if (remoteSplitURIScheme(uri, &driver, &transport) < 0) {
        g_printerr(_("%s: cannot parse URI transport '%s': %s\n"),
                   argv[0], uri_str, virGetLastErrorMessage());
        exit(EXIT_FAILURE);
    }

    if (transport != REMOTE_DRIVER_TRANSPORT_UNIX) {
        g_printerr(_("%s: unexpected URI transport '%s'\n"),
                   argv[0], uri_str);
        exit(EXIT_FAILURE);
    }

    remoteGetURIDaemonInfo(uri, transport, &user, &autostart);

    sock_path = remoteGetUNIXSocket(transport,
                                    REMOTE_DRIVER_MODE_AUTO,
                                    driver,
                                    !!readonly,
                                    user,
                                    &daemon_name);

    if (virNetSocketNewConnectUNIX(sock_path, autostart, daemon_name, &sock) < 0) {
        g_printerr(_("%s: cannot connect to '%s': %s\n"),
                   argv[0], sock_path, virGetLastErrorMessage());
        exit(EXIT_FAILURE);
    }

    if (virRemoteSSHHelperRun(sock) < 0) {
        g_printerr(_("%s: could not proxy traffic: %s\n"),
                   argv[0], virGetLastErrorMessage());
        exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);
}
