/*
 * commandtest.c: Test the libCommand API
 *
 * Copyright (C) 2010-2014 Red Hat, Inc.
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
#include <signal.h>
#include <sys/stat.h>
#ifndef WIN32
# include <sys/wait.h>
# include <poll.h>
#endif
#include <fcntl.h>

#include "testutils.h"
#include "internal.h"
#include "viralloc.h"
#include "vircommand.h"
#include "virfile.h"
#include "virpidfile.h"
#include "virerror.h"
#include "virprocess.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#ifdef WIN32

int
main(void)
{
    return EXIT_AM_SKIP;
}

#else

/* Some UNIX lack it in headers & it doesn't hurt to redeclare */
extern char **environ;

static int checkoutput(const char *testname)
{
    int ret = -1;
    g_autofree char *expectname = NULL;
    g_autofree char *actualname = NULL;
    g_autofree char *actuallog = NULL;

    expectname = g_strdup_printf("%s/commanddata/%s.log", abs_srcdir, testname);
    actualname = g_strdup_printf("%s/commandhelper.log", abs_builddir);

    if (virFileReadAll(actualname, 1024*64, &actuallog) < 0) {
        fprintf(stderr, "cannot read %s\n", actualname);
        goto cleanup;
    }

    ret = virTestCompareToFile(actuallog, expectname);

 cleanup:
    if (actualname)
        unlink(actualname);
    return ret;
}

/*
 * Run program, no args, inherit all ENV, keep CWD.
 * Only stdin/out/err open
 * No slot for return status must log error.
 */
static int test0(const void *unused G_GNUC_UNUSED)
{
    g_autoptr(virCommand) cmd = NULL;

    cmd = virCommandNew(abs_builddir "/commandhelper-doesnotexist");
    if (virCommandRun(cmd, NULL) == 0)
        return -1;

    if (virGetLastErrorCode() == VIR_ERR_OK)
        return -1;

    virResetLastError();
    return 0;
}

/*
 * Run program, no args, inherit all ENV, keep CWD.
 * Only stdin/out/err open
 * Capturing return status must not log error.
 */
static int test1(const void *unused G_GNUC_UNUSED)
{
    g_autoptr(virCommand) cmd = NULL;
    int status;

    cmd = virCommandNew(abs_builddir "/commandhelper-doesnotexist");
    if (virCommandRun(cmd, &status) < 0)
        return -1;
    if (status != EXIT_ENOENT)
        return -1;

    virCommandRawStatus(cmd);
    if (virCommandRun(cmd, &status) < 0)
        return -1;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_ENOENT)
        return -1;

    return 0;
}

/*
 * Run program (twice), no args, inherit all ENV, keep CWD.
 * Only stdin/out/err open
 */
static int test2(const void *unused G_GNUC_UNUSED)
{
    g_autoptr(virCommand) cmd = virCommandNew(abs_builddir "/commandhelper");
    int ret;

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        return -1;
    }

    if ((ret = checkoutput("test2")) != 0)
        return ret;

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        return -1;
    }

    return checkoutput("test2");
}

/*
 * Run program, no args, inherit all ENV, keep CWD.
 * stdin/out/err + two extra FD open
 */
static int test3(const void *unused G_GNUC_UNUSED)
{
    g_autoptr(virCommand) cmd = virCommandNew(abs_builddir "/commandhelper");
    VIR_AUTOCLOSE newfd1 = dup(STDERR_FILENO);
    VIR_AUTOCLOSE newfd2 = dup(STDERR_FILENO);
    int newfd3 = dup(STDERR_FILENO);
    struct stat before, after;

    if (fstat(newfd3, &before) < 0) {
        perror("fstat");
        return -1;
    }
    virCommandPassFD(cmd, newfd1, 0);
    virCommandPassFD(cmd, newfd3,
                     VIR_COMMAND_PASS_FD_CLOSE_PARENT);

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        return -1;
    }

    if (fcntl(newfd1, F_GETFL) < 0 ||
        fcntl(newfd2, F_GETFL) < 0) {
        puts("fds 1/2 were not open");
        return -1;
    }

    /* We expect newfd3 to be closed, but the
     * fd might have already been reused by
     * the event loop. So if it is open, we
     * check if it matches the stat info we
     * got earlier
     */
    if (fcntl(newfd3, F_GETFL) >= 0 &&
        fstat(newfd3, &after) >= 0) {

        if (before.st_ino == after.st_ino &&
            before.st_dev == after.st_dev &&
            before.st_mode == after.st_mode) {
            puts("fd 3 should not be open");
            return -1;
        }
    }

    return checkoutput("test3");
}


/*
 * Run program, no args, inherit all ENV, CWD is /
 * Only stdin/out/err open.
 * Daemonized
 */
static int test4(const void *unused G_GNUC_UNUSED)
{
    g_autoptr(virCommand) cmd = virCommandNewArgList(abs_builddir "/commandhelper",
                                                     "--check-daemonize", NULL);
    g_autofree char *pidfile = virPidFileBuildPath(abs_builddir, "commandhelper");
    pid_t pid;
    int ret = -1;

    if (!pidfile)
        goto cleanup;

    virCommandSetPidFile(cmd, pidfile);
    virCommandDaemonize(cmd);

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        goto cleanup;
    }

    if (virPidFileRead(abs_builddir, "commandhelper", &pid) < 0) {
        printf("cannot read pidfile\n");
        goto cleanup;
    }
    while (kill(pid, 0) != -1)
        g_usleep(100*1000);

    ret = checkoutput("test4");

 cleanup:
    if (pidfile)
        unlink(pidfile);
    return ret;
}


/*
 * Run program, no args, inherit filtered ENV, keep CWD.
 * Only stdin/out/err open
 */
static int test5(const void *unused G_GNUC_UNUSED)
{
    g_autoptr(virCommand) cmd = virCommandNew(abs_builddir "/commandhelper");

    virCommandAddEnvPassCommon(cmd);

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        return -1;
    }

    return checkoutput("test5");
}


/*
 * Run program, no args, inherit filtered ENV, keep CWD.
 * Only stdin/out/err open
 */
static int test6(const void *unused G_GNUC_UNUSED)
{
    g_autoptr(virCommand) cmd = virCommandNew(abs_builddir "/commandhelper");

    virCommandAddEnvPass(cmd, "DISPLAY");
    virCommandAddEnvPass(cmd, "DOESNOTEXIST");

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        return -1;
    }

    return checkoutput("test6");
}


/*
 * Run program, no args, inherit filtered ENV, keep CWD.
 * Only stdin/out/err open
 */
static int test7(const void *unused G_GNUC_UNUSED)
{
    g_autoptr(virCommand) cmd = virCommandNew(abs_builddir "/commandhelper");

    virCommandAddEnvPassCommon(cmd);
    virCommandAddEnvPass(cmd, "DISPLAY");
    virCommandAddEnvPass(cmd, "DOESNOTEXIST");

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        return -1;
    }

    return checkoutput("test7");
}

/*
 * Run program, no args, inherit filtered ENV, keep CWD.
 * Only stdin/out/err open
 */
static int test8(const void *unused G_GNUC_UNUSED)
{
    g_autoptr(virCommand) cmd = virCommandNew(abs_builddir "/commandhelper");

    virCommandAddEnvString(cmd, "USER=bogus");
    virCommandAddEnvString(cmd, "LANG=C");
    virCommandAddEnvPair(cmd, "USER", "also bogus");
    virCommandAddEnvPair(cmd, "USER", "test");

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        return -1;
    }

    return checkoutput("test8");
}


/*
 * Run program, some args, inherit all ENV, keep CWD.
 * Only stdin/out/err open
 */
static int test9(const void *unused G_GNUC_UNUSED)
{
    g_autoptr(virCommand) cmd = virCommandNew(abs_builddir "/commandhelper");
    const char* const args[] = { "arg1", "arg2", NULL };
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virCommandAddArg(cmd, "-version");
    virCommandAddArgPair(cmd, "-log", "bar.log");
    virCommandAddArgSet(cmd, args);
    virCommandAddArgBuffer(cmd, &buf);
    virBufferAddLit(&buf, "arg4");
    virCommandAddArgBuffer(cmd, &buf);
    virCommandAddArgList(cmd, "arg5", "arg6", NULL);

    if (virBufferUse(&buf)) {
        printf("Buffer not transferred\n");
        return -1;
    }

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        return -1;
    }

    return checkoutput("test9");
}


/*
 * Run program, some args, inherit all ENV, keep CWD.
 * Only stdin/out/err open
 */
static int test10(const void *unused G_GNUC_UNUSED)
{
    g_autoptr(virCommand) cmd = virCommandNew(abs_builddir "/commandhelper");
    const char *const args[] = {
        "-version", "-log=bar.log", NULL,
    };

    virCommandAddArgSet(cmd, args);

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        return -1;
    }

    return checkoutput("test10");
}

/*
 * Run program, some args, inherit all ENV, keep CWD.
 * Only stdin/out/err open
 */
static int test11(const void *unused G_GNUC_UNUSED)
{
    const char *args[] = {
        abs_builddir "/commandhelper",
        "-version", "-log=bar.log", NULL,
    };
    g_autoptr(virCommand) cmd = virCommandNewArgs(args);

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        return -1;
    }

    return checkoutput("test11");
}

/*
 * Run program, no args, inherit all ENV, keep CWD.
 * Only stdin/out/err open. Set stdin data
 */
static int test12(const void *unused G_GNUC_UNUSED)
{
    g_autoptr(virCommand) cmd = virCommandNew(abs_builddir "/commandhelper");

    virCommandSetInputBuffer(cmd, "Hello World\n");

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        return -1;
    }

    return checkoutput("test12");
}

/*
 * Run program, no args, inherit all ENV, keep CWD.
 * Only stdin/out/err open. Set stdin data
 */
static int test13(const void *unused G_GNUC_UNUSED)
{
    virCommand *cmd = virCommandNew(abs_builddir "/commandhelper");
    g_autofree char *outactual = NULL;
    const char *outexpect = "BEGIN STDOUT\n"
        "Hello World\n"
        "END STDOUT\n";
    int ret = -1;

    virCommandSetInputBuffer(cmd, "Hello World\n");
    virCommandSetOutputBuffer(cmd, &outactual);

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        goto cleanup;
    }
    if (!outactual)
        goto cleanup;

    g_clear_pointer(&cmd, virCommandFree);

    if (virTestCompareToString(outexpect, outactual) < 0) {
        goto cleanup;
    }

    ret = checkoutput("test13");

 cleanup:
    virCommandFree(cmd);
    return ret;
}

/*
 * Run program, no args, inherit all ENV, keep CWD.
 * Only stdin/out/err open. Set stdin data
 */
static int test14(const void *unused G_GNUC_UNUSED)
{
    virCommand *cmd = virCommandNew(abs_builddir "/commandhelper");
    g_autofree char *outactual = NULL;
    const char *outexpect = "BEGIN STDOUT\n"
        "Hello World\n"
        "END STDOUT\n";
    g_autofree char *erractual = NULL;
    const char *errexpect = "BEGIN STDERR\n"
        "Hello World\n"
        "END STDERR\n";

    g_autofree char *jointactual = NULL;
    const char *jointexpect = "BEGIN STDOUT\n"
        "BEGIN STDERR\n"
        "Hello World\n"
        "Hello World\n"
        "END STDOUT\n"
        "END STDERR\n";
    int ret = -1;

    virCommandSetInputBuffer(cmd, "Hello World\n");
    virCommandSetOutputBuffer(cmd, &outactual);
    virCommandSetErrorBuffer(cmd, &erractual);

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        goto cleanup;
    }
    if (!outactual || !erractual)
        goto cleanup;

    virCommandFree(cmd);

    cmd = virCommandNew(abs_builddir "/commandhelper");
    virCommandSetInputBuffer(cmd, "Hello World\n");
    virCommandSetOutputBuffer(cmd, &jointactual);
    virCommandSetErrorBuffer(cmd, &jointactual);
    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        goto cleanup;
    }
    if (!jointactual)
        goto cleanup;

    if (virTestCompareToString(outexpect, outactual) < 0) {
        goto cleanup;
    }
    if (virTestCompareToString(errexpect, erractual) < 0) {
        goto cleanup;
    }
    if (virTestCompareToString(jointexpect, jointactual) < 0) {
        goto cleanup;
    }

    ret = checkoutput("test14");

 cleanup:
    virCommandFree(cmd);
    return ret;
}


/*
 * Run program, no args, inherit all ENV, change CWD.
 * Only stdin/out/err open
 */
static int test15(const void *unused G_GNUC_UNUSED)
{
    g_autoptr(virCommand) cmd = virCommandNew(abs_builddir "/commandhelper");
    g_autofree char *cwd = NULL;

    cwd = g_strdup_printf("%s/commanddata", abs_srcdir);
    virCommandSetWorkingDirectory(cmd, cwd);
    virCommandSetUmask(cmd, 002);

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        return -1;
    }

    return checkoutput("test15");
}

/*
 * Don't run program; rather, log what would be run.
 */
static int test16(const void *unused G_GNUC_UNUSED)
{
    g_autoptr(virCommand) cmd = virCommandNew("true");
    g_autofree char *outactual = NULL;
    const char *outexpect = "A=B C='D  E' true F 'G  H'";
    VIR_AUTOCLOSE fd = -1;

    virCommandAddEnvPair(cmd, "A", "B");
    virCommandAddEnvPair(cmd, "C", "D  E");
    virCommandAddArg(cmd, "F");
    virCommandAddArg(cmd, "G  H");

    if ((outactual = virCommandToString(cmd, false)) == NULL) {
        printf("Cannot convert to string: %s\n", virGetLastErrorMessage());
        return -1;
    }
    if ((fd = open(abs_builddir "/commandhelper.log",
                   O_CREAT | O_TRUNC | O_WRONLY, 0600)) < 0) {
        printf("Cannot open log file: %s\n", g_strerror(errno));
        return -1;
    }
    virCommandWriteArgLog(cmd, fd);
    if (VIR_CLOSE(fd) < 0) {
        printf("Cannot close log file: %s\n", g_strerror(errno));
        return -1;
    }

    if (virTestCompareToString(outexpect, outactual) < 0) {
        return -1;
    }

    return checkoutput("test16");
}

/*
 * Test string handling when no output is present.
 */
static int test17(const void *unused G_GNUC_UNUSED)
{
    g_autoptr(virCommand) cmd = virCommandNew("true");
    int ret = -1;
    char *outbuf = NULL;
    g_autofree char *errbuf = NULL;

    virCommandSetOutputBuffer(cmd, &outbuf);
    if (outbuf != NULL) {
        puts("buffer not sanitized at registration");
        goto cleanup;
    }

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        goto cleanup;
    }

    if (*outbuf) {
        puts("output buffer is not an allocated empty string");
        goto cleanup;
    }
    VIR_FREE(outbuf);
    outbuf = g_strdup("should not be leaked");

    virCommandSetErrorBuffer(cmd, &errbuf);
    if (errbuf != NULL) {
        puts("buffer not sanitized at registration");
        goto cleanup;
    }

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        goto cleanup;
    }

    if (*outbuf || *errbuf) {
        puts("output buffers are not allocated empty strings");
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(outbuf);
    return ret;
}

/*
 * Run long-running daemon, to ensure no hang.
 */
static int test18(const void *unused G_GNUC_UNUSED)
{
    virCommand *cmd = virCommandNewArgList("sleep", "100", NULL);
    g_autofree char *pidfile = virPidFileBuildPath(abs_builddir, "commandhelper");
    pid_t pid;
    int ret = -1;

    if (!pidfile)
        goto cleanup;

    virCommandSetPidFile(cmd, pidfile);
    virCommandDaemonize(cmd);

    alarm(5);
    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        goto cleanup;
    }
    alarm(0);

    if (virPidFileRead(abs_builddir, "commandhelper", &pid) < 0) {
        printf("cannot read pidfile\n");
        goto cleanup;
    }

    g_clear_pointer(&cmd, virCommandFree);
    if (kill(pid, 0) != 0) {
        printf("daemon should still be running\n");
        goto cleanup;
    }

    while (kill(pid, SIGINT) != -1)
        g_usleep(100*1000);

    ret = 0;

 cleanup:
    virCommandFree(cmd);
    if (pidfile)
        unlink(pidfile);
    return ret;
}

/*
 * Asynchronously run long-running daemon, to ensure no hang.
 */
static int test19(const void *unused G_GNUC_UNUSED)
{
    g_autoptr(virCommand) cmd = virCommandNewArgList("sleep", "100", NULL);
    pid_t pid;

    alarm(5);
    if (virCommandRunAsync(cmd, &pid) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        return -1;
    }

    if (kill(pid, 0) != 0) {
        printf("Child should still be running");
        return -1;
    }

    virCommandAbort(cmd);

    if (kill(pid, 0) == 0) {
        printf("Child should be aborted");
        return -1;
    }

    alarm(0);

    return 0;
}

/*
 * Run program, no args, inherit all ENV, keep CWD.
 * Ignore huge stdin data, to provoke SIGPIPE or EPIPE in parent.
 */
static int test20(const void *unused G_GNUC_UNUSED)
{
    g_autoptr(virCommand) cmd = virCommandNewArgList(abs_builddir "/commandhelper",
                                                     "--close-stdin", NULL);
    g_autofree char *buf = NULL;

    struct sigaction sig_action;

    sig_action.sa_handler = SIG_IGN;
    sig_action.sa_flags = 0;
    sigemptyset(&sig_action.sa_mask);

    sigaction(SIGPIPE, &sig_action, NULL);

    buf = g_strdup_printf("1\n%100000d\n", 2);
    virCommandSetInputBuffer(cmd, buf);

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        return -1;
    }

    return checkoutput("test20");
}

static const char *const newenv[] = {
    "PATH=/usr/bin:/bin",
    "HOSTNAME=test",
    "LANG=C",
    "HOME=/home/test",
    "USER=test",
    "LOGNAME=test",
    "TMPDIR=/tmp",
    "DISPLAY=:0.0",
    NULL
};

static int test21(const void *unused G_GNUC_UNUSED)
{
    g_autoptr(virCommand) cmd = virCommandNew(abs_builddir "/commandhelper");
    const char *wrbuf = "Hello world\n";
    g_autofree char *outbuf = NULL;
    g_autofree char *errbuf = NULL;
    const char *outbufExpected = "BEGIN STDOUT\n"
        "Hello world\n"
        "END STDOUT\n";
    const char *errbufExpected = "BEGIN STDERR\n"
        "Hello world\n"
        "END STDERR\n";

    virCommandSetInputBuffer(cmd, wrbuf);
    virCommandSetOutputBuffer(cmd, &outbuf);
    virCommandSetErrorBuffer(cmd, &errbuf);
    virCommandDoAsyncIO(cmd);

    if (virCommandRunAsync(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        return -1;
    }

    if (virCommandWait(cmd, NULL) < 0)
        return -1;

    if (virTestGetVerbose())
        printf("STDOUT:%s\nSTDERR:%s\n", NULLSTR(outbuf), NULLSTR(errbuf));

    if (virTestCompareToString(outbufExpected, outbuf) < 0) {
        return -1;
    }

    if (virTestCompareToString(errbufExpected, errbuf) < 0) {
        return -1;
    }

    return checkoutput("test21");
}

static int
test22(const void *unused G_GNUC_UNUSED)
{
    int ret = -1;
    virCommand *cmd;
    int status = -1;

    cmd = virCommandNewArgList("/bin/sh", "-c", "exit 3", NULL);

    if (virCommandRun(cmd, &status) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        goto cleanup;
    }
    if (status != 3) {
        printf("Unexpected status %d\n", status);
        goto cleanup;
    }

    virCommandRawStatus(cmd);
    if (virCommandRun(cmd, &status) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        goto cleanup;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 3) {
        printf("Unexpected status %d\n", status);
        goto cleanup;
    }

    virCommandFree(cmd);
    cmd = virCommandNewArgList("/bin/sh", "-c", "kill -9 $$", NULL);

    if (virCommandRun(cmd, &status) == 0) {
        printf("Death by signal not detected, status %d\n", status);
        goto cleanup;
    }

    virCommandRawStatus(cmd);
    if (virCommandRun(cmd, &status) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        goto cleanup;
    }
    if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) {
        printf("Unexpected status %d\n", status);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virCommandFree(cmd);
    return ret;
}


static int
test23(const void *unused G_GNUC_UNUSED)
{
    /* Not strictly a virCommand test, but this is the easiest place
     * to test this lower-level interface.  It takes a double fork to
     * test virProcessExitWithStatus.  */
    int status = -1;
    pid_t pid;

    if ((pid = virFork()) < 0)
        return -1;
    if (pid == 0) {
        if ((pid = virFork()) < 0)
            _exit(EXIT_FAILURE);
        if (pid == 0)
            _exit(42);
        if (virProcessWait(pid, &status, true) < 0)
            _exit(EXIT_FAILURE);
        virProcessExitWithStatus(status);
        _exit(EXIT_FAILURE);
    }

    if (virProcessWait(pid, &status, true) < 0)
        return -1;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 42) {
        printf("Unexpected status %d\n", status);
        return -1;
    }

    if ((pid = virFork()) < 0)
        return -1;
    if (pid == 0) {
        if ((pid = virFork()) < 0)
            _exit(EXIT_FAILURE);
        if (pid == 0) {
            raise(SIGKILL);
            _exit(EXIT_FAILURE);
        }
        if (virProcessWait(pid, &status, true) < 0)
            _exit(EXIT_FAILURE);
        virProcessExitWithStatus(status);
        _exit(EXIT_FAILURE);
    }

    if (virProcessWait(pid, &status, true) < 0)
        return -1;
    if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) {
        printf("Unexpected status %d\n", status);
        return -1;
    }

    return 0;
}

static int test25(const void *unused G_GNUC_UNUSED)
{
    int ret = -1;
    int pipeFD[2] = { -1, -1};
    int rv = 0;
    ssize_t tries = 100;
    pid_t pid;
    g_autofree gid_t *groups = NULL;
    int ngroups;
    g_autoptr(virCommand) cmd = virCommandNew("some/nonexistent/binary");

    if (virPipeQuiet(pipeFD) < 0) {
        fprintf(stderr, "Unable to create pipe\n");
        goto cleanup;
    }

    if (virSetNonBlock(pipeFD[0]) < 0) {
        fprintf(stderr, "Unable to make read end of pipe nonblocking\n");
        goto cleanup;
    }

    if ((ngroups = virGetGroupList(virCommandGetUID(cmd), virCommandGetGID(cmd),
                                   &groups)) < 0)
        goto cleanup;

    /* Now, fork and try to exec a nonexistent binary. */
    pid = virFork();
    if (pid < 0) {
        fprintf(stderr, "Unable to spawn child\n");
        goto cleanup;
    }

    if (pid == 0) {
        /* Child */
        rv = virCommandExec(cmd, groups, ngroups);

        if (safewrite(pipeFD[1], &rv, sizeof(rv)) < 0)
            fprintf(stderr, "Unable to write to pipe\n");
        _exit(EXIT_FAILURE);
    }

    /* Parent */
    while (--tries) {
        if (saferead(pipeFD[0], &rv, sizeof(rv)) < 0) {
            if (errno != EWOULDBLOCK) {
                fprintf(stderr, "Unable to read from pipe\n");
                goto cleanup;
            }

            g_usleep(10 * 1000);
        } else {
            break;
        }
    }

    if (!tries) {
        fprintf(stderr, "Child hasn't returned anything\n");
        goto cleanup;
    }

    if (rv >= 0) {
        fprintf(stderr, "Child should have returned an error\n");
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FORCE_CLOSE(pipeFD[0]);
    VIR_FORCE_CLOSE(pipeFD[1]);
    return ret;
}


/*
 * Don't run program; rather, log what would be run.
 */
static int test26(const void *unused G_GNUC_UNUSED)
{
    g_autoptr(virCommand) cmd = virCommandNew("true");
    g_autofree char *outactual = NULL;
    const char *outexpect =
        "A=B \\\n"
        "C='D  E' \\\n"
        "true \\\n"
        "--foo bar \\\n"
        "--oooh \\\n"
        "-f \\\n"
        "--wizz 'eek eek' \\\n"
        "--m-m-m-multiarg arg arg2 \\\n"
        "-w \\\n"
        "-z \\\n"
        "-l \\\n"
        "--mmm flash \\\n"
        "bang \\\n"
        "wallop";

    VIR_AUTOCLOSE fd = -1;

    virCommandAddEnvPair(cmd, "A", "B");
    virCommandAddEnvPair(cmd, "C", "D  E");
    virCommandAddArgList(cmd, "--foo", "bar", "--oooh", "-f",
                         "--wizz", "eek eek",
                         "--m-m-m-multiarg", "arg", "arg2",
                         "-w", "-z", "-l",
                         "--mmm", "flash", "bang", "wallop",
                         NULL);

    if ((outactual = virCommandToString(cmd, true)) == NULL) {
        printf("Cannot convert to string: %s\n", virGetLastErrorMessage());
        return -1;
    }
    if ((fd = open(abs_builddir "/commandhelper.log",
                   O_CREAT | O_TRUNC | O_WRONLY, 0600)) < 0) {
        printf("Cannot open log file: %s\n", g_strerror(errno));
        return -1;
    }
    virCommandWriteArgLog(cmd, fd);
    if (VIR_CLOSE(fd) < 0) {
        printf("Cannot close log file: %s\n", g_strerror(errno));
        return -1;
    }

    if (virTestCompareToString(outexpect, outactual) < 0) {
        return -1;
    }

    return checkoutput("test26");
}

static int test27(const void *unused G_GNUC_UNUSED)
{
    g_autoptr(virCommand) cmd = virCommandNew(abs_builddir "/commandhelper");
    int buf1fd;
    int buf2fd;
    size_t buflen = 1024 * 128;
    g_autofree char *buffer0 = NULL;
    g_autofree unsigned char *buffer1 = NULL;
    g_autofree unsigned char *buffer2 = NULL;
    g_autofree char *outactual = NULL;
    g_autofree char *erractual = NULL;
    g_autofree char *outexpect = NULL;
# define TEST27_OUTEXPECT_TEMP "BEGIN STDOUT\n" \
        "%s%s%s" \
        "END STDOUT\n"
    g_autofree char *errexpect = NULL;
# define TEST27_ERREXPECT_TEMP "BEGIN STDERR\n" \
        "%s%s%s" \
        "END STDERR\n"

    buffer0 = g_new0(char, buflen);
    buffer1 = g_new0(unsigned char, buflen);
    buffer2 = g_new0(unsigned char, buflen);

    memset(buffer0, 'H', buflen - 2);
    buffer0[buflen - 2] = '\n';
    buffer0[buflen - 1] = 0;

    memset(buffer1, '1', buflen - 2);
    buffer1[buflen - 2] = '\n';
    buffer1[buflen - 1] = 0;

    memset(buffer2, '2', buflen - 2);
    buffer2[buflen - 2] = '\n';
    buffer2[buflen - 1] = 0;

    outexpect = g_strdup_printf(TEST27_OUTEXPECT_TEMP,
                                buffer0, buffer1, buffer2);
    errexpect = g_strdup_printf(TEST27_ERREXPECT_TEMP,
                                buffer0, buffer1, buffer2);

    buf1fd = virCommandSetSendBuffer(cmd, &buffer1, buflen - 1);
    buf2fd = virCommandSetSendBuffer(cmd, &buffer2, buflen - 1);

    virCommandAddArg(cmd, "--readfd");
    virCommandAddArgFormat(cmd, "%d", buf1fd);

    virCommandAddArg(cmd, "--readfd");
    virCommandAddArgFormat(cmd, "%d", buf2fd);

    virCommandSetInputBuffer(cmd, buffer0);
    virCommandSetOutputBuffer(cmd, &outactual);
    virCommandSetErrorBuffer(cmd, &erractual);

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        return -1;
    }

    if (!outactual || !erractual)
        return -1;

    if (virTestCompareToString(outexpect, outactual) < 0) {
        return -1;
    }
    if (virTestCompareToString(errexpect, erractual) < 0) {
        return -1;
    }

    if (checkoutput("test27") < 0)
        return -1;

    return 0;
}


static int
test28Callback(pid_t pid G_GNUC_UNUSED,
               void *opaque G_GNUC_UNUSED)
{
    virReportSystemError(ENODATA, "%s", "some error message");
    return -1;
}


static int
test28(const void *unused G_GNUC_UNUSED)
{
    /* Not strictly a virCommand test, but this is the easiest place
     * to test this lower-level interface. */
    virErrorPtr err;
    g_autofree char *msg = g_strdup_printf("some error message: %s", g_strerror(ENODATA));

    if (virProcessRunInFork(test28Callback, NULL) != -1) {
        fprintf(stderr, "virProcessRunInFork did not fail\n");
        return -1;
    }

    if (!(err = virGetLastError())) {
        fprintf(stderr, "Expected error but got nothing\n");
        return -1;
    }

    if (!(err->code == VIR_ERR_SYSTEM_ERROR &&
          err->domain == 0 &&
          STREQ(err->message, msg) &&
          err->level == VIR_ERR_ERROR &&
          STREQ(err->str1, "%s") &&
          STREQ(err->str2, msg) &&
          err->int1 == ENODATA &&
          err->int2 == -1)) {
        fprintf(stderr, "Unexpected error object\n");
        return -1;
    }

    return 0;
}


static int
test29(const void *unused G_GNUC_UNUSED)
{
    g_autoptr(virCommand) cmd = virCommandNew(abs_builddir "/commandhelper");
    g_autofree char *pidfile = virPidFileBuildPath(abs_builddir, "commandhelper");
    pid_t pid;
    int buffd;
    VIR_AUTOCLOSE outfd = -1;
    size_t buflen = 1024 * 10;
    g_autofree unsigned char *buffer = NULL;
    g_autofree char *outactual = NULL;
    g_autofree char *outexpect = NULL;
    size_t i;
    size_t outactuallen = 0;
    int ret = -1;

    if (!pidfile)
        return -1;

    buffer = g_new0(unsigned char, buflen + 1);
    for (i = 0; i < buflen; i++) {
        buffer[i] = 'a' + i % ('z' - 'a' + 1);
    }
    buffer[buflen] = '\0';

    outexpect = g_strdup_printf("BEGIN STDOUT\n%sEND STDOUT\n", buffer);

    buffd = virCommandSetSendBuffer(cmd, &buffer, buflen);

    virCommandAddArg(cmd, "--close-stdin");
    virCommandAddArg(cmd, "--check-daemonize");
    virCommandAddArg(cmd, "--readfd");
    virCommandAddArgFormat(cmd, "%d", buffd);

    virCommandSetOutputFD(cmd, &outfd);
    virCommandSetPidFile(cmd, pidfile);
    virCommandDaemonize(cmd);
    virCommandDoAsyncIO(cmd);

    if (virCommandRun(cmd, NULL) < 0) {
        fprintf(stderr, "Cannot run child %s\n", virGetLastErrorMessage());
        goto cleanup;
    }

    if (virPidFileReadPath(pidfile, &pid) < 0) {
        fprintf(stderr, "cannot read pidfile: %s\n", pidfile);
        goto cleanup;
    }

    while (1) {
        char buf[1024] = { 0 };
        struct pollfd pfd = {.fd = outfd, .events = POLLIN, .revents = 0};
        int rc = 0;

        rc = poll(&pfd, 1, 1000);
        if (rc < 0) {
            if (errno == EINTR)
                continue;

            fprintf(stderr, "poll() returned errno = %d\n", errno);
            goto cleanup;
        }

        if (pfd.revents & POLLIN) {
            rc = read(outfd, buf, sizeof(buf));
            if (rc < 0) {
                fprintf(stderr, "cannot read from output pipe: errno=%d\n", errno);
                goto cleanup;
            }

            if (rc == 0)
                break;

            outactual = g_renew(char, outactual, outactuallen + rc + 1);
            memcpy(outactual + outactuallen, buf, rc);
            outactuallen += rc;
            outactual[outactuallen] = '\0';
        } else if (pfd.revents & POLLERR ||
                   pfd.revents & POLLHUP) {
            break;
        }
    }

    if (virTestCompareToString(outexpect, outactual) < 0) {
        goto cleanup;
    }

    ret = checkoutput("test29");

 cleanup:
    if (pidfile)
        unlink(pidfile);

    return ret;
}


static int
mymain(void)
{
    int ret = 0;
    int fd;
    int virinitret;

    if (chdir("/tmp") < 0)
        return EXIT_FAILURE;

    umask(022);

    setpgid(0, 0);
    ignore_value(setsid());

    virCloseRangeInit();

    /* Our test expects particular fd values; to get that, we must not
     * leak fds that we inherited from a lazy parent.  At the same
     * time, virInitialize may open some fds (perhaps via third-party
     * libraries that it uses), and we must not kill off an fd that
     * this process opens as it might break expectations of a
     * pthread_atfork handler, as well as interfering with our tests
     * trying to ensure we aren't leaking to our children.  The
     * solution is to do things in two phases - reserve the fds we
     * want by overwriting any externally inherited fds, then
     * initialize, then clear the slots for testing.  */
    if ((fd = open("/dev/null", O_RDONLY)) < 0 ||
        dup2(fd, 3) < 0 ||
        dup2(fd, 4) < 0 ||
        dup2(fd, 5) < 0 ||
        dup2(fd, 6) < 0 ||
        dup2(fd, 7) < 0 ||
        dup2(fd, 8) < 0 ||
        (fd > 8 && VIR_CLOSE(fd) < 0)) {
        VIR_FORCE_CLOSE(fd);
        return EXIT_FAILURE;
    }

    /* Prime the debug/verbose settings from the env vars,
     * since we're about to reset 'environ' */
    ignore_value(virTestGetDebug());
    ignore_value(virTestGetVerbose());
    ignore_value(virTestGetRegenerate());

    /* Make sure to not leak fd's */
    virinitret = virInitialize();

    /* Phase two of killing interfering fds; see above.  */
    fd = 3;
    VIR_FORCE_CLOSE(fd);
    fd = 4;
    VIR_FORCE_CLOSE(fd);
    fd = 5;
    VIR_FORCE_CLOSE(fd);
    fd = 6;
    VIR_FORCE_CLOSE(fd);
    fd = 7;
    VIR_FORCE_CLOSE(fd);
    fd = 8;
    VIR_FORCE_CLOSE(fd);

    if (virinitret < 0)
        return EXIT_FAILURE;

    environ = (char **)newenv;

# define DO_TEST(NAME) \
    if (virTestRun("Command Exec " #NAME " test", \
                   NAME, NULL) < 0) \
        ret = -1

    DO_TEST(test0);
    DO_TEST(test1);
    DO_TEST(test2);
    DO_TEST(test3);
    DO_TEST(test4);
    DO_TEST(test5);
    DO_TEST(test6);
    DO_TEST(test7);
    DO_TEST(test8);
    DO_TEST(test9);
    DO_TEST(test10);
    DO_TEST(test11);
    DO_TEST(test12);
    DO_TEST(test13);
    DO_TEST(test14);
    DO_TEST(test15);
    DO_TEST(test16);
    DO_TEST(test17);
    DO_TEST(test18);
    DO_TEST(test19);
    DO_TEST(test20);
    DO_TEST(test21);
    DO_TEST(test22);
    DO_TEST(test23);
    DO_TEST(test25);
    DO_TEST(test26);
    DO_TEST(test27);
    DO_TEST(test28);
    DO_TEST(test29);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)

#endif /* !WIN32 */
