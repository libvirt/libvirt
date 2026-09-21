/*
 * daemonstreamtest.c: test the daemon side of client streams
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

#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include "testutils.h"
#include "virerror.h"
#include "virevent.h"
#include "virfdstream.h"
#include "virfile.h"
#include "virthread.h"
#include "virutil.h"
#include "remote/remote_daemon_stream.h"
#include "rpc/virnetserverclient.h"
#include "rpc/virnetserverprogram.h"

#define VIR_FROM_THIS VIR_FROM_RPC

#ifndef WIN32

# define TEST_PROGRAM 0x11111111
# define TEST_TIMEOUT 5

static bool closeHookDone;

static void *
testClientPrivNew(virNetServerClient *client G_GNUC_UNUSED,
                  void *opaque G_GNUC_UNUSED)
{
    daemonClientPrivate *priv = g_new0(daemonClientPrivate, 1);

    if (virMutexInit(&priv->lock) < 0) {
        g_free(priv);
        return NULL;
    }

    return priv;
}


static void
testClientPrivFree(void *opaque)
{
    daemonClientPrivate *priv = opaque;

    virMutexDestroy(&priv->lock);
    g_free(priv);
}


/* Same locking as remoteClientFreePrivateCallbacks(), which is what the
 * daemon installs here. */
static void
testClientClose(virNetServerClient *client)
{
    daemonClientPrivate *priv = virNetServerClientGetPrivateData(client);
    VIR_LOCK_GUARD lock = virLockGuardLock(&priv->lock);

    closeHookDone = true;
}


static void
testAlarm(int sig G_GNUC_UNUSED)
{
    static const char msg[] = "daemonStreamEvent() deadlocked closing the client\n";

    ignore_value(safewrite(STDERR_FILENO, msg, sizeof(msg) - 1));
    _exit(EXIT_FAILURE);
}


/* A stream event delivered for a client that is already marked for close
 * must not deadlock the thread running the event loop. The error reply
 * cannot be queued to such a client, so the event handler closes it, and
 * the close hook takes the same lock the handler holds. */
static int
testStreamEventClose(const void *opaque G_GNUC_UNUSED)
{
    struct virNetMessageHeader header = { .proc = 1, .serial = 1 };
    virConnectPtr conn = NULL;
    virNetServerClient *client = NULL;
    virNetServerProgram *prog = NULL;
    daemonClientStream *stream = NULL;
    virNetSocket *sock = NULL;
    virStreamPtr st = NULL;
    int pipeFD[2] = { -1, -1 };
    int sv[2] = { -1, -1 };
    int ret = -1;
    size_t i;

    closeHookDone = false;

    if (!(conn = virConnectOpen("test:///default")))
        return -1;

    if (socketpair(PF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        virReportSystemError(errno, "%s", "Cannot create socket pair");
        return -1;
    }

    if (virNetSocketNewConnectSockFD(sv[0], &sock) < 0)
        goto cleanup;
    sv[0] = -1;

    if (!(client = virNetServerClientNew(1, sock, 0, false, 1, NULL,
                                         testClientPrivNew, NULL,
                                         testClientPrivFree, NULL)))
        goto cleanup;

    virNetServerClientSetCloseHook(client, testClientClose);

    if (!(prog = virNetServerProgramNew(TEST_PROGRAM, 1, NULL, 0)))
        goto cleanup;

    if (virPipe(pipeFD) < 0)
        goto cleanup;

    if (!(st = virStreamNew(conn, VIR_STREAM_NONBLOCK)))
        goto cleanup;

    if (virFDStreamOpen(st, pipeFD[0]) < 0)
        goto cleanup;
    pipeFD[0] = -1;

    if (!(stream = daemonCreateClientStream(client, st, prog, &header, false)))
        goto cleanup;

    if (daemonAddClientStream(client, stream, true) < 0)
        goto cleanup;

    virNetServerClientImmediateClose(client);

    /* Hangs up the read end, so the stream reports EOF */
    VIR_FORCE_CLOSE(pipeFD[1]);

    signal(SIGALRM, testAlarm);
    alarm(TEST_TIMEOUT);

    for (i = 0; i < 100 && !closeHookDone; i++) {
        if (virEventRunDefaultImpl() < 0)
            break;
    }

    alarm(0);

    if (!closeHookDone) {
        fprintf(stderr, "Client was not closed by the stream event\n");
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virStreamFree(st);
    if (conn)
        virConnectClose(conn);
    virObjectUnref(prog);
    virObjectUnref(sock);
    if (client)
        virNetServerClientClose(client);
    virObjectUnref(client);
    VIR_FORCE_CLOSE(pipeFD[0]);
    VIR_FORCE_CLOSE(pipeFD[1]);
    VIR_FORCE_CLOSE(sv[0]);
    VIR_FORCE_CLOSE(sv[1]);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;

    virEventRegisterDefaultImpl();

    if (virTestRun("Stream event on a client marked for close",
                   testStreamEventClose, NULL) < 0)
        ret = -1;

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
#else /* WIN32 */
static int
mymain(void)
{
    return EXIT_AM_SKIP;
}
#endif /* WIN32 */
VIR_TEST_MAIN(mymain);
