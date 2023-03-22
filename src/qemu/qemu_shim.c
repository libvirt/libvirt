/*
 * qemu_shim.c: standalone binary for running QEMU instances
 *
 * Copyright (C) 2019 Red Hat, Inc.
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

#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>

#include "virfile.h"
#include "virgettext.h"
#include "viridentity.h"
#include "virthread.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

static GMutex eventLock;
static bool eventPreventQuitFlag;
static bool eventQuitFlag;
static int eventQuitFD = -1;
static virDomainPtr dom;

/* Runs in event loop thread context */
static void *
qemuShimEventLoop(void *opaque G_GNUC_UNUSED)
{
    bool quit = false;
    while (!quit) {
        g_mutex_lock(&eventLock);
        if (eventQuitFlag && !eventPreventQuitFlag) {
            quit = true;
            if (dom) {
                virDomainDestroy(dom);
            }
        }
        g_mutex_unlock(&eventLock);
        virEventRunDefaultImpl();
    }

    return NULL;
}

/* Runs in any thread context */
static bool
qemuShimEventLoopPreventQuit(void)
{
    bool quitting;
    g_mutex_lock(&eventLock);
    quitting = eventQuitFlag;
    if (!quitting)
        eventPreventQuitFlag = true;
    g_mutex_unlock(&eventLock);
    return quitting;
}

/* Runs in any thread context */
static bool
qemuShimEventLoopAllowQuit(void)
{
    bool quitting;
    g_mutex_lock(&eventLock);
    eventPreventQuitFlag = false;
    /* kick the event loop thread again immediately */
    quitting = eventQuitFlag;
    if (quitting)
        ignore_value(safewrite(eventQuitFD, "c", 1));
    g_mutex_unlock(&eventLock);
    return quitting;
}


/* Runs in event loop thread context */
static void
qemuShimEventLoopStop(int watch G_GNUC_UNUSED,
                      int fd,
                      int event G_GNUC_UNUSED,
                      void *opaque G_GNUC_UNUSED)
{
    char c;
    ignore_value(read(fd, &c, 1));
    g_mutex_lock(&eventLock);
    eventQuitFlag = true;
    g_mutex_unlock(&eventLock);
}

/* Runs in event loop thread context */
static int
qemuShimDomShutdown(virConnectPtr econn G_GNUC_UNUSED,
                    virDomainPtr edom G_GNUC_UNUSED,
                    int event,
                    int detail G_GNUC_UNUSED,
                    void *opaque G_GNUC_UNUSED)
{
    if (event == VIR_DOMAIN_EVENT_STOPPED) {
        g_mutex_lock(&eventLock);
        eventQuitFlag = true;
        g_mutex_unlock(&eventLock);
    }

    return 0;
}

/* Runs in unknown thread context */
static void
qemuShimSigShutdown(int sig G_GNUC_UNUSED)
{
    if (dom)
        virDomainDestroy(dom);
    ignore_value(safewrite(eventQuitFD, "c", 1));
}

static void
qemuShimQuench(void *userData G_GNUC_UNUSED,
               virErrorPtr error G_GNUC_UNUSED)
{
}

int main(int argc, char **argv)
{
    g_autoptr(virIdentity) sysident = NULL;
    GThread *eventLoopThread = NULL;
    virConnectPtr conn = NULL;
    virConnectPtr sconn = NULL;
    g_autofree char *xml = NULL;
    g_autofree char *uri = NULL;
    g_autofree char *suri = NULL;
    const char *root = NULL;
    g_autofree char *escaped = NULL;
    bool tmproot = false;
    int ret = 1;
    g_autoptr(GError) error = NULL;
    g_auto(GStrv) secrets = NULL;
    gboolean verbose = false;
    gboolean debug = false;
    GStrv tmpsecrets;
    GOptionContext *ctx;
    GOptionEntry entries[] = {
        { "secret", 's', 0, G_OPTION_ARG_STRING_ARRAY, &secrets, "Load secret file", "SECRET-XML-FILE,SECRET-VALUE-FILE" },
        { "root", 'r', 0, G_OPTION_ARG_STRING, &root, "Root directory", "DIR" },
        { "debug", 'd', 0, G_OPTION_ARG_NONE, &debug, "Debug output", NULL },
        { "verbose", 'v', 0, G_OPTION_ARG_NONE, &verbose, "Verbose output", NULL },
        { 0 }
    };
    int quitfd[2] = {-1, -1};
    bool quitting;
    long long start = g_get_monotonic_time();

#define deltams() ((long long)g_get_monotonic_time() - start)

    ctx = g_option_context_new("GUEST-XML-FILE - run a standalone QEMU process");
    g_option_context_add_main_entries(ctx, entries, PACKAGE);
    if (!g_option_context_parse(ctx, &argc, &argv, &error)) {
        g_printerr("%s: option parsing failed: %s\n",
                   argv[0], error->message);
        return 1;
    }

    if (argc != 2) {
        g_autofree char *help = g_option_context_get_help(ctx, TRUE, NULL);
        g_printerr("%s", help);
        return 1;
    }

    if (verbose)
        g_printerr("%s: %lld: initializing libvirt %llu\n",
                   argv[0], deltams(), virThreadSelfID());

    if (virInitialize() < 0) {
        g_printerr("%s: cannot initialize libvirt\n", argv[0]);
        return 1;
    }
    if (virGettextInitialize() < 0) {
        g_printerr("%s: cannot initialize libvirt translations\n", argv[0]);
        return 1;
    }

    virSetErrorFunc(NULL, qemuShimQuench);

    sysident = virIdentityGetSystem();
    virIdentitySetCurrent(sysident);

    if (verbose)
        g_printerr("%s: %lld: initializing signal handlers\n",
                   argv[0], deltams());

    signal(SIGTERM, qemuShimSigShutdown);
    signal(SIGINT, qemuShimSigShutdown);
    signal(SIGQUIT, qemuShimSigShutdown);
    signal(SIGHUP, qemuShimSigShutdown);
    signal(SIGPIPE, SIG_IGN);

    if (root == NULL) {
        if (!(root = g_dir_make_tmp("virt-qemu-run-XXXXXX", &error))) {
            g_printerr("%s: cannot create temporary dir: %s\n",
                       argv[0], error->message);
            return 1;
        }
        tmproot = true;

    } else {
        if (!g_path_is_absolute(root)) {
            g_printerr("%s: the root directory must be an absolute path\n",
                       argv[0]);
            goto cleanup;
        }

        if (g_mkdir_with_parents(root, 0755) < 0) {
            g_printerr("%s: cannot create dir: %s\n",
                       argv[0], g_strerror(errno));
            goto cleanup;
        }
    }

    if (chmod(root, 0755) < 0) {
        g_printerr("%s: cannot chmod temporary dir: %s\n",
                   argv[0], g_strerror(errno));
        goto cleanup;
    }

    escaped = g_uri_escape_string(root, NULL, true);

    virFileActivateDirOverrideForProg(argv[0]);

    if (verbose)
        g_printerr("%s: %lld: preparing event loop thread\n",
                   argv[0], deltams());
    virEventRegisterDefaultImpl();

    if (pipe(quitfd) < 0) {
        g_printerr("%s: cannot create event loop pipe: %s",
                   argv[0], g_strerror(errno));
        goto cleanup;
    }

    if (virEventAddHandle(quitfd[0], VIR_EVENT_HANDLE_READABLE, qemuShimEventLoopStop, NULL, NULL) < 0) {
        VIR_FORCE_CLOSE(quitfd[0]);
        VIR_FORCE_CLOSE(quitfd[1]);
        quitfd[0] = quitfd[1] = -1;
        g_printerr("%s: cannot register event loop handle: %s",
                   argv[0], virGetLastErrorMessage());
        goto cleanup;
    }
    eventQuitFD = quitfd[1];

    eventLoopThread = g_thread_new("event-loop", qemuShimEventLoop, NULL);

    if (secrets && *secrets) {
        suri = g_strdup_printf("secret:///embed?root=%s", escaped);

        if (verbose)
            g_printerr("%s: %lld: opening %s\n",
                       argv[0], deltams(), suri);

        sconn = virConnectOpen(suri);
        if (!sconn) {
            g_printerr("%s: cannot open %s: %s\n",
                       argv[0], suri, virGetLastErrorMessage());
            goto cleanup;
        }

        tmpsecrets = secrets;
        while (tmpsecrets && *tmpsecrets) {
            g_auto(GStrv) bits = g_strsplit(*tmpsecrets, ",", 2);
            g_autofree char *sxml = NULL;
            g_autofree char *value = NULL;
            virSecretPtr sec;
            size_t nvalue;

            if (!bits || bits[0] == NULL || bits[1] == NULL) {
                g_printerr("%s: expected a pair of filenames for --secret argument\n",
                    argv[0]);
                goto cleanup;
            }

            if (verbose)
                g_printerr("%s: %lld: loading secret %s and %s\n",
                           argv[0], deltams(), bits[0], bits[1]);

            if (!g_file_get_contents(bits[0], &sxml, NULL, &error)) {
                g_printerr("%s: cannot read secret XML %s: %s\n",
                           argv[0], bits[0], error->message);
                goto cleanup;
            }

            if (!g_file_get_contents(bits[1], &value, &nvalue, &error)) {
                g_printerr("%s: cannot read secret value %s: %s\n",
                           argv[0], bits[1], error->message);
                goto cleanup;
            }

            if (!(sec = virSecretDefineXML(sconn, sxml, 0))) {
                g_printerr("%s: cannot define secret %s: %s\n",
                           argv[0], bits[0], virGetLastErrorMessage());
                goto cleanup;
            }

            if (virSecretSetValue(sec, (unsigned char *)value, nvalue, 0) < 0) {
                virSecretFree(sec);
                g_printerr("%s: cannot set value for secret %s: %s\n",
                argv[0], bits[0], virGetLastErrorMessage());
                goto cleanup;
            }
            virSecretFree(sec);

            tmpsecrets++;
        }
    }

    uri = g_strdup_printf("qemu:///embed?root=%s", escaped);

    if (verbose)
        g_printerr("%s: %lld: opening %s\n",
                   argv[0], deltams(), uri);

    conn = virConnectOpen(uri);
    if (!conn) {
        g_printerr("%s: cannot open %s: %s\n",
                   argv[0], uri, virGetLastErrorMessage());
        goto cleanup;
    }

    if (virConnectDomainEventRegisterAny(
            conn, dom, VIR_DOMAIN_EVENT_ID_LIFECYCLE,
            VIR_DOMAIN_EVENT_CALLBACK(qemuShimDomShutdown),
            NULL, NULL) < 0) {
        g_printerr("%s: cannot register for lifecycle events: %s\n",
                   argv[0], virGetLastErrorMessage());
        goto cleanup;
    }

    if (verbose)
        g_printerr("%s: %lld: fetching guest config %s\n",
                   argv[0], deltams(), argv[1]);

    if (!g_file_get_contents(argv[1], &xml, NULL, &error)) {
        g_printerr("%s: cannot read %s: %s\n",
                   argv[0], argv[1], error->message);
        goto cleanup;
    }

    if (verbose)
        g_printerr("%s: %lld: starting guest %s\n",
                   argv[0], deltams(), argv[1]);

    /*
     * If the user issues a ctrl-C at this time, we need to
     * let the virDomainCreateXML call complete, so that we
     * can then clean up the guest correctly. We must also
     * ensure that the event loop doesn't quit yet, because
     * it might be needed to complete VM startup & shutdown
     * during the cleanup.
     */
    quitting = qemuShimEventLoopPreventQuit();
    if (quitting)
        goto cleanup;
    dom = virDomainCreateXML(conn, xml, 0);
    quitting = qemuShimEventLoopAllowQuit();

    if (!dom) {
        g_printerr("%s: cannot start VM: %s\n",
                   argv[0], virGetLastErrorMessage());
        goto cleanup;
    }
    if (verbose)
        g_printerr("%s: %lld: guest running, Ctrl-C to stop now\n",
                   argv[0], deltams());
    if (quitting)
        goto cleanup;

    if (debug) {
        g_autofree char *newxml = NULL;
        newxml = virDomainGetXMLDesc(dom, 0);
        g_printerr("%s: XML: %s\n", argv[0], newxml);
    }

    ret = 0;

 cleanup:
    if (ret != 0 && eventQuitFD != -1)
        ignore_value(safewrite(eventQuitFD, "c", 1));

    if (eventLoopThread != NULL && (ret == 0 || eventQuitFD != -1))
        g_thread_join(eventLoopThread);

    VIR_FORCE_CLOSE(quitfd[0]);
    VIR_FORCE_CLOSE(quitfd[1]);

    if (dom != NULL)
        virDomainFree(dom);
    if (sconn != NULL)
        virConnectClose(sconn);
    if (conn != NULL)
        virConnectClose(conn);
    if (tmproot)
        virFileDeleteTree(root);

    if (verbose)
        g_printerr("%s: %lld: cleaned up, exiting\n",
                   argv[0], deltams());
    return ret;
}
