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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "testutils.h"
#include "internal.h"
#include "viralloc.h"
#include "vircommand.h"
#include "virfile.h"
#include "virpidfile.h"
#include "virerror.h"
#include "virthread.h"
#include "virstring.h"
#include "virprocess.h"

#define VIR_FROM_THIS VIR_FROM_NONE

typedef struct _virCommandTestData virCommandTestData;
typedef virCommandTestData *virCommandTestDataPtr;
struct _virCommandTestData {
    virMutex lock;
    virThread thread;
    bool quit;
    bool running;
};

#ifdef WIN32

int
main(void)
{
    return EXIT_AM_SKIP;
}

#else

static int checkoutput(const char *testname,
                       char *prefix)
{
    int ret = -1;
    char *expectname = NULL;
    char *expectlog = NULL;
    char *actualname = NULL;
    char *actuallog = NULL;

    if (virAsprintf(&expectname, "%s/commanddata/%s.log", abs_srcdir,
                    testname) < 0)
        goto cleanup;
    if (virAsprintf(&actualname, "%s/commandhelper.log", abs_builddir) < 0)
        goto cleanup;

    if (virFileReadAll(expectname, 1024*64, &expectlog) < 0) {
        fprintf(stderr, "cannot read %s\n", expectname);
        goto cleanup;
    }

    if (virFileReadAll(actualname, 1024*64, &actuallog) < 0) {
        fprintf(stderr, "cannot read %s\n", actualname);
        goto cleanup;
    }

    if (prefix) {
        char *tmp = NULL;

        if (virAsprintf(&tmp, "%s%s", prefix, expectlog) < 0)
            goto cleanup;

        VIR_FREE(expectlog);
        expectlog = tmp;
    }

    if (STRNEQ(expectlog, actuallog)) {
        virTestDifference(stderr, expectlog, actuallog);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    if (actualname)
        unlink(actualname);
    VIR_FREE(actuallog);
    VIR_FREE(actualname);
    VIR_FREE(expectlog);
    VIR_FREE(expectname);
    return ret;
}

/*
 * Run program, no args, inherit all ENV, keep CWD.
 * Only stdin/out/err open
 * No slot for return status must log error.
 */
static int test0(const void *unused ATTRIBUTE_UNUSED)
{
    virCommandPtr cmd;
    int ret = -1;

    cmd = virCommandNew(abs_builddir "/commandhelper-doesnotexist");
    if (virCommandRun(cmd, NULL) == 0)
        goto cleanup;

    if (virGetLastError() == NULL)
        goto cleanup;

    virResetLastError();
    ret = 0;

 cleanup:
    virCommandFree(cmd);
    return ret;
}

/*
 * Run program, no args, inherit all ENV, keep CWD.
 * Only stdin/out/err open
 * Capturing return status must not log error.
 */
static int test1(const void *unused ATTRIBUTE_UNUSED)
{
    virCommandPtr cmd;
    int ret = -1;
    int status;

    cmd = virCommandNew(abs_builddir "/commandhelper-doesnotexist");
    if (virCommandRun(cmd, &status) < 0)
        goto cleanup;
    if (status != EXIT_ENOENT)
        goto cleanup;

    virCommandRawStatus(cmd);
    if (virCommandRun(cmd, &status) < 0)
        goto cleanup;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_ENOENT)
        goto cleanup;
    ret = 0;

 cleanup:
    virCommandFree(cmd);
    return ret;
}

/*
 * Run program (twice), no args, inherit all ENV, keep CWD.
 * Only stdin/out/err open
 */
static int test2(const void *unused ATTRIBUTE_UNUSED)
{
    virCommandPtr cmd = virCommandNew(abs_builddir "/commandhelper");
    int ret;

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        virCommandFree(cmd);
        return -1;
    }

    if ((ret = checkoutput("test2", NULL)) != 0) {
        virCommandFree(cmd);
        return ret;
    }

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        virCommandFree(cmd);
        return -1;
    }

    virCommandFree(cmd);

    return checkoutput("test2", NULL);
}

/*
 * Run program, no args, inherit all ENV, keep CWD.
 * stdin/out/err + two extra FD open
 */
static int test3(const void *unused ATTRIBUTE_UNUSED)
{
    virCommandPtr cmd = virCommandNew(abs_builddir "/commandhelper");
    int newfd1 = dup(STDERR_FILENO);
    int newfd2 = dup(STDERR_FILENO);
    int newfd3 = dup(STDERR_FILENO);
    int ret = -1;

    virCommandPassFD(cmd, newfd1, 0);
    virCommandPassFD(cmd, newfd3,
                     VIR_COMMAND_PASS_FD_CLOSE_PARENT);

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        goto cleanup;
    }

    if (fcntl(newfd1, F_GETFL) < 0 ||
        fcntl(newfd2, F_GETFL) < 0 ||
        fcntl(newfd3, F_GETFL) >= 0) {
        puts("fds in wrong state");
        goto cleanup;
    }

    ret = checkoutput("test3", NULL);

 cleanup:
    virCommandFree(cmd);
    /* coverity[double_close] */
    VIR_FORCE_CLOSE(newfd1);
    VIR_FORCE_CLOSE(newfd2);
    return ret;
}


/*
 * Run program, no args, inherit all ENV, CWD is /
 * Only stdin/out/err open.
 * Daemonized
 */
static int test4(const void *unused ATTRIBUTE_UNUSED)
{
    virCommandPtr cmd = virCommandNew(abs_builddir "/commandhelper");
    char *pidfile = virPidFileBuildPath(abs_builddir, "commandhelper");
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
        usleep(100*1000);

    ret = checkoutput("test4", NULL);

 cleanup:
    virCommandFree(cmd);
    if (pidfile)
        unlink(pidfile);
    VIR_FREE(pidfile);
    return ret;
}


/*
 * Run program, no args, inherit filtered ENV, keep CWD.
 * Only stdin/out/err open
 */
static int test5(const void *unused ATTRIBUTE_UNUSED)
{
    virCommandPtr cmd = virCommandNew(abs_builddir "/commandhelper");

    virCommandAddEnvPassCommon(cmd);

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        virCommandFree(cmd);
        return -1;
    }

    virCommandFree(cmd);

    return checkoutput("test5", NULL);
}


/*
 * Run program, no args, inherit filtered ENV, keep CWD.
 * Only stdin/out/err open
 */
static int test6(const void *unused ATTRIBUTE_UNUSED)
{
    virCommandPtr cmd = virCommandNew(abs_builddir "/commandhelper");

    virCommandAddEnvPassBlockSUID(cmd, "DISPLAY", NULL);
    virCommandAddEnvPassBlockSUID(cmd, "DOESNOTEXIST", NULL);

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        virCommandFree(cmd);
        return -1;
    }

    virCommandFree(cmd);

    return checkoutput("test6", NULL);
}


/*
 * Run program, no args, inherit filtered ENV, keep CWD.
 * Only stdin/out/err open
 */
static int test7(const void *unused ATTRIBUTE_UNUSED)
{
    virCommandPtr cmd = virCommandNew(abs_builddir "/commandhelper");

    virCommandAddEnvPassCommon(cmd);
    virCommandAddEnvPassBlockSUID(cmd, "DISPLAY", NULL);
    virCommandAddEnvPassBlockSUID(cmd, "DOESNOTEXIST", NULL);

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        virCommandFree(cmd);
        return -1;
    }

    virCommandFree(cmd);

    return checkoutput("test7", NULL);
}

/*
 * Run program, no args, inherit filtered ENV, keep CWD.
 * Only stdin/out/err open
 */
static int test8(const void *unused ATTRIBUTE_UNUSED)
{
    virCommandPtr cmd = virCommandNew(abs_builddir "/commandhelper");

    virCommandAddEnvString(cmd, "USER=bogus");
    virCommandAddEnvString(cmd, "LANG=C");
    virCommandAddEnvPair(cmd, "USER", "also bogus");
    virCommandAddEnvPair(cmd, "USER", "test");

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        virCommandFree(cmd);
        return -1;
    }

    virCommandFree(cmd);

    return checkoutput("test8", NULL);
}


/*
 * Run program, some args, inherit all ENV, keep CWD.
 * Only stdin/out/err open
 */
static int test9(const void *unused ATTRIBUTE_UNUSED)
{
    virCommandPtr cmd = virCommandNew(abs_builddir "/commandhelper");
    const char* const args[] = { "arg1", "arg2", NULL };
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virCommandAddArg(cmd, "-version");
    virCommandAddArgPair(cmd, "-log", "bar.log");
    virCommandAddArgSet(cmd, args);
    virCommandAddArgBuffer(cmd, &buf);
    virBufferAddLit(&buf, "arg4");
    virCommandAddArgBuffer(cmd, &buf);
    virCommandAddArgList(cmd, "arg5", "arg6", NULL);

    if (virBufferUse(&buf)) {
        printf("Buffer not transferred\n");
        virBufferFreeAndReset(&buf);
        virCommandFree(cmd);
        return -1;
    }

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        virCommandFree(cmd);
        return -1;
    }

    virCommandFree(cmd);

    return checkoutput("test9", NULL);
}


/*
 * Run program, some args, inherit all ENV, keep CWD.
 * Only stdin/out/err open
 */
static int test10(const void *unused ATTRIBUTE_UNUSED)
{
    virCommandPtr cmd = virCommandNew(abs_builddir "/commandhelper");
    const char *const args[] = {
        "-version", "-log=bar.log", NULL,
    };

    virCommandAddArgSet(cmd, args);

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        virCommandFree(cmd);
        return -1;
    }

    virCommandFree(cmd);

    return checkoutput("test10", NULL);
}

/*
 * Run program, some args, inherit all ENV, keep CWD.
 * Only stdin/out/err open
 */
static int test11(const void *unused ATTRIBUTE_UNUSED)
{
    const char *args[] = {
        abs_builddir "/commandhelper",
        "-version", "-log=bar.log", NULL,
    };
    virCommandPtr cmd = virCommandNewArgs(args);

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        virCommandFree(cmd);
        return -1;
    }

    virCommandFree(cmd);

    return checkoutput("test11", NULL);
}

/*
 * Run program, no args, inherit all ENV, keep CWD.
 * Only stdin/out/err open. Set stdin data
 */
static int test12(const void *unused ATTRIBUTE_UNUSED)
{
    virCommandPtr cmd = virCommandNew(abs_builddir "/commandhelper");

    virCommandSetInputBuffer(cmd, "Hello World\n");

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        virCommandFree(cmd);
        return -1;
    }

    virCommandFree(cmd);

    return checkoutput("test12", NULL);
}

/*
 * Run program, no args, inherit all ENV, keep CWD.
 * Only stdin/out/err open. Set stdin data
 */
static int test13(const void *unused ATTRIBUTE_UNUSED)
{
    virCommandPtr cmd = virCommandNew(abs_builddir "/commandhelper");
    char *outactual = NULL;
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

    virCommandFree(cmd);
    cmd = NULL;

    if (STRNEQ(outactual, outexpect)) {
        virTestDifference(stderr, outexpect, outactual);
        goto cleanup;
    }

    ret = checkoutput("test13", NULL);

 cleanup:
    virCommandFree(cmd);
    VIR_FREE(outactual);
    return ret;
}

/*
 * Run program, no args, inherit all ENV, keep CWD.
 * Only stdin/out/err open. Set stdin data
 */
static int test14(const void *unused ATTRIBUTE_UNUSED)
{
    virCommandPtr cmd = virCommandNew(abs_builddir "/commandhelper");
    char *outactual = NULL;
    const char *outexpect = "BEGIN STDOUT\n"
        "Hello World\n"
        "END STDOUT\n";
    char *erractual = NULL;
    const char *errexpect = "BEGIN STDERR\n"
        "Hello World\n"
        "END STDERR\n";

    char *jointactual = NULL;
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

    if (STRNEQ(outactual, outexpect)) {
        virTestDifference(stderr, outexpect, outactual);
        goto cleanup;
    }
    if (STRNEQ(erractual, errexpect)) {
        virTestDifference(stderr, errexpect, erractual);
        goto cleanup;
    }
    if (STRNEQ(jointactual, jointexpect)) {
        virTestDifference(stderr, jointexpect, jointactual);
        goto cleanup;
    }

    ret = checkoutput("test14", NULL);

 cleanup:
    virCommandFree(cmd);
    VIR_FREE(outactual);
    VIR_FREE(erractual);
    VIR_FREE(jointactual);
    return ret;
}


/*
 * Run program, no args, inherit all ENV, change CWD.
 * Only stdin/out/err open
 */
static int test15(const void *unused ATTRIBUTE_UNUSED)
{
    virCommandPtr cmd = virCommandNew(abs_builddir "/commandhelper");
    char *cwd = NULL;
    int ret = -1;

    if (virAsprintf(&cwd, "%s/commanddata", abs_srcdir) < 0)
        goto cleanup;
    virCommandSetWorkingDirectory(cmd, cwd);
    virCommandSetUmask(cmd, 002);

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        goto cleanup;
    }

    ret = checkoutput("test15", NULL);

 cleanup:
    VIR_FREE(cwd);
    virCommandFree(cmd);

    return ret;
}

/*
 * Don't run program; rather, log what would be run.
 */
static int test16(const void *unused ATTRIBUTE_UNUSED)
{
    virCommandPtr cmd = virCommandNew("true");
    char *outactual = NULL;
    const char *outexpect = "A=B C='D  E' true F 'G  H'";
    int ret = -1;
    int fd = -1;

    virCommandAddEnvPair(cmd, "A", "B");
    virCommandAddEnvPair(cmd, "C", "D  E");
    virCommandAddArg(cmd, "F");
    virCommandAddArg(cmd, "G  H");

    if ((outactual = virCommandToString(cmd)) == NULL) {
        printf("Cannot convert to string: %s\n", virGetLastErrorMessage());
        goto cleanup;
    }
    if ((fd = open(abs_builddir "/commandhelper.log",
                   O_CREAT | O_TRUNC | O_WRONLY, 0600)) < 0) {
        printf("Cannot open log file: %s\n", strerror(errno));
        goto cleanup;
    }
    virCommandWriteArgLog(cmd, fd);
    if (VIR_CLOSE(fd) < 0) {
        printf("Cannot close log file: %s\n", strerror(errno));
        goto cleanup;
    }

    if (STRNEQ(outactual, outexpect)) {
        virTestDifference(stderr, outexpect, outactual);
        goto cleanup;
    }

    ret = checkoutput("test16", NULL);

 cleanup:
    virCommandFree(cmd);
    VIR_FORCE_CLOSE(fd);
    VIR_FREE(outactual);
    return ret;
}

/*
 * Test string handling when no output is present.
 */
static int test17(const void *unused ATTRIBUTE_UNUSED)
{
    virCommandPtr cmd = virCommandNew("true");
    int ret = -1;
    char *outbuf;
    char *errbuf = NULL;

    virCommandSetOutputBuffer(cmd, &outbuf);
    if (outbuf != NULL) {
        puts("buffer not sanitized at registration");
        goto cleanup;
    }

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        goto cleanup;
    }

    sa_assert(outbuf);
    if (*outbuf) {
        puts("output buffer is not an allocated empty string");
        goto cleanup;
    }
    VIR_FREE(outbuf);
    if (VIR_STRDUP(outbuf, "should not be leaked") < 0) {
        puts("test framework failure");
        goto cleanup;
    }

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
    virCommandFree(cmd);
    VIR_FREE(outbuf);
    VIR_FREE(errbuf);
    return ret;
}

/*
 * Run long-running daemon, to ensure no hang.
 */
static int test18(const void *unused ATTRIBUTE_UNUSED)
{
    virCommandPtr cmd = virCommandNewArgList("sleep", "100", NULL);
    char *pidfile = virPidFileBuildPath(abs_builddir, "commandhelper");
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

    virCommandFree(cmd);
    cmd = NULL;
    if (kill(pid, 0) != 0) {
        printf("daemon should still be running\n");
        goto cleanup;
    }

    while (kill(pid, SIGINT) != -1)
        usleep(100*1000);

    ret = 0;

 cleanup:
    virCommandFree(cmd);
    if (pidfile)
        unlink(pidfile);
    VIR_FREE(pidfile);
    return ret;
}

/*
 * Asynchronously run long-running daemon, to ensure no hang.
 */
static int test19(const void *unused ATTRIBUTE_UNUSED)
{
    virCommandPtr cmd = virCommandNewArgList("sleep", "100", NULL);
    pid_t pid;
    int ret = -1;

    alarm(5);
    if (virCommandRunAsync(cmd, &pid) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        goto cleanup;
    }

    if (kill(pid, 0) != 0) {
        printf("Child should still be running");
        goto cleanup;
    }

    virCommandAbort(cmd);

    if (kill(pid, 0) == 0) {
        printf("Child should be aborted");
        goto cleanup;
    }

    alarm(0);

    ret = 0;

 cleanup:
    virCommandFree(cmd);
    return ret;
}

/*
 * Run program, no args, inherit all ENV, keep CWD.
 * Ignore huge stdin data, to provoke SIGPIPE or EPIPE in parent.
 */
static int test20(const void *unused ATTRIBUTE_UNUSED)
{
    virCommandPtr cmd = virCommandNewArgList(abs_builddir "/commandhelper",
                                             "--close-stdin", NULL);
    char *buf;
    int ret = -1;

    struct sigaction sig_action;

    sig_action.sa_handler = SIG_IGN;
    sig_action.sa_flags = 0;
    sigemptyset(&sig_action.sa_mask);

    sigaction(SIGPIPE, &sig_action, NULL);

    if (virAsprintf(&buf, "1\n%100000d\n", 2) < 0)
        goto cleanup;
    virCommandSetInputBuffer(cmd, buf);

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        goto cleanup;
    }

    ret = checkoutput("test20", NULL);
 cleanup:
    virCommandFree(cmd);
    VIR_FREE(buf);
    return ret;
}

static const char *const newenv[] = {
    "PATH=/usr/bin:/bin",
    "HOSTNAME=test",
    "LANG=C",
    "HOME=/home/test",
    "USER=test",
    "LOGNAME=test"
    "TMPDIR=/tmp",
    "DISPLAY=:0.0",
    NULL
};

static int test21(const void *unused ATTRIBUTE_UNUSED)
{
    virCommandPtr cmd = virCommandNew(abs_builddir "/commandhelper");
    int ret = -1;
    const char *wrbuf = "Hello world\n";
    char *outbuf = NULL, *errbuf = NULL;
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
        goto cleanup;
    }

    if (virCommandWait(cmd, NULL) < 0)
        goto cleanup;

    if (virTestGetVerbose())
        printf("STDOUT:%s\nSTDERR:%s\n", NULLSTR(outbuf), NULLSTR(errbuf));

    if (STRNEQ(outbuf, outbufExpected)) {
        virTestDifference(stderr, outbufExpected, outbuf);
        goto cleanup;
    }

    if (STRNEQ(errbuf, errbufExpected)) {
        virTestDifference(stderr, errbufExpected, errbuf);
        goto cleanup;
    }

    ret = checkoutput("test21", NULL);
 cleanup:
    VIR_FREE(outbuf);
    VIR_FREE(errbuf);
    virCommandFree(cmd);
    return ret;
}

static int
test22(const void *unused ATTRIBUTE_UNUSED)
{
    int ret = -1;
    virCommandPtr cmd;
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
test23(const void *unused ATTRIBUTE_UNUSED)
{
    /* Not strictly a virCommand test, but this is the easiest place
     * to test this lower-level interface.  It takes a double fork to
     * test virProcessExitWithStatus.  */
    int ret = -1;
    int status = -1;
    pid_t pid;

    if ((pid = virFork()) < 0)
        goto cleanup;
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
        goto cleanup;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 42) {
        printf("Unexpected status %d\n", status);
        goto cleanup;
    }

    if ((pid = virFork()) < 0)
        goto cleanup;
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
        goto cleanup;
    if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) {
        printf("Unexpected status %d\n", status);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    return ret;
}

static int test24(const void *unused ATTRIBUTE_UNUSED)
{
    char *pidfile = virPidFileBuildPath(abs_builddir, "commandhelper");
    char *prefix = NULL;
    int newfd1 = dup(STDERR_FILENO);
    int newfd2 = dup(STDERR_FILENO);
    int newfd3 = dup(STDERR_FILENO);
    int ret = -1;
    pid_t pid;
    virCommandPtr cmd = virCommandNew(abs_builddir "/commandhelper");

    if (!pidfile)
        goto cleanup;

    if (VIR_CLOSE(newfd1) < 0)
        printf("Cannot close fd %d\n", newfd1);

    virCommandSetPidFile(cmd, pidfile);
    virCommandDaemonize(cmd);
    virCommandPassFD(cmd, newfd2, VIR_COMMAND_PASS_FD_CLOSE_PARENT);
    virCommandPassFD(cmd, newfd3, VIR_COMMAND_PASS_FD_CLOSE_PARENT);
    virCommandPassListenFDs(cmd);

    if (virCommandRun(cmd, NULL) < 0) {
        printf("Cannot run child %s\n", virGetLastErrorMessage());
        goto cleanup;
    }

    if (virPidFileRead(abs_builddir, "commandhelper", &pid) < 0) {
        printf("cannot read pidfile\n");
        goto cleanup;
    }

    if (virAsprintf(&prefix,
                    "ENV:LISTEN_FDS=2\nENV:LISTEN_PID=%u\n",
                    pid) < 0)
        goto cleanup;

    while (kill(pid, 0) != -1)
        usleep(100*1000);

    ret = checkoutput("test24", prefix);

 cleanup:
    if (pidfile)
        unlink(pidfile);
    VIR_FREE(pidfile);
    VIR_FREE(prefix);
    virCommandFree(cmd);
    VIR_FORCE_CLOSE(newfd1);
    /* coverity[double_close] */
    VIR_FORCE_CLOSE(newfd2);
    VIR_FORCE_CLOSE(newfd3);
    return ret;
}


static int test25(const void *unused ATTRIBUTE_UNUSED)
{
    int ret = -1;
    int pipeFD[2] = { -1, -1};
    int rv = 0;
    ssize_t tries = 100;
    pid_t pid;

    if (pipe(pipeFD) < 0) {
        fprintf(stderr, "Unable to create pipe\n");
        goto cleanup;
    }

    if (virSetNonBlock(pipeFD[0]) < 0) {
        fprintf(stderr, "Unable to make read end of pipe nonblocking\n");
        goto cleanup;
    }

    /* Now, fork and try to exec a nonexistent binary. */
    pid = virFork();
    if (pid < 0) {
        fprintf(stderr, "Unable to spawn child\n");
        goto cleanup;
    }

    if (pid == 0) {
        /* Child */
        virCommandPtr cmd = virCommandNew("some/nonexistent/binary");

        rv = virCommandExec(cmd);

        virCommandFree(cmd);

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

            usleep(10 * 1000);
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


static void virCommandThreadWorker(void *opaque)
{
    virCommandTestDataPtr test = opaque;

    virMutexLock(&test->lock);

    while (!test->quit) {
        virMutexUnlock(&test->lock);

        if (virEventRunDefaultImpl() < 0) {
            test->quit = true;
            break;
        }

        virMutexLock(&test->lock);
    }

    test->running = false;

    virMutexUnlock(&test->lock);
    return;
}

static void
virCommandTestFreeTimer(int timer ATTRIBUTE_UNUSED,
                        void *opaque ATTRIBUTE_UNUSED)
{
    /* nothing to be done here */
}

static int
mymain(void)
{
    int ret = 0;
    int fd;
    virCommandTestDataPtr test = NULL;
    int timer = -1;
    int virinitret;

    if (virThreadInitialize() < 0)
        return EXIT_FAILURE;

    if (chdir("/tmp") < 0)
        return EXIT_FAILURE;

    umask(022);

    setpgid(0, 0);
    ignore_value(setsid());

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

    /* Make sure to not leak fd's */
    virinitret = virInitialize();

    /* Phase two of killing interfering fds; see above.  */
    /* coverity[overwrite_var] - silence the obvious */
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

    virEventRegisterDefaultImpl();
    if (VIR_ALLOC(test) < 0)
        goto cleanup;

    if (virMutexInit(&test->lock) < 0) {
        printf("Unable to init mutex: %d\n", errno);
        goto cleanup;
    }

    virMutexLock(&test->lock);

    if (virThreadCreate(&test->thread,
                        true,
                        virCommandThreadWorker,
                        test) < 0) {
        virMutexUnlock(&test->lock);
        goto cleanup;
    }

    test->running = true;
    virMutexUnlock(&test->lock);

    environ = (char **)newenv;

# define DO_TEST(NAME)                                                \
    if (virTestRun("Command Exec " #NAME " test",                     \
                   NAME, NULL) < 0)                                   \
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
    DO_TEST(test24);
    DO_TEST(test25);

    virMutexLock(&test->lock);
    if (test->running) {
        test->quit = true;
        /* HACK: Add a dummy timeout to break event loop */
        timer = virEventAddTimeout(0, virCommandTestFreeTimer, NULL, NULL);
    }
    virMutexUnlock(&test->lock);

 cleanup:
    if (test->running)
        virThreadJoin(&test->thread);

    if (timer != -1)
        virEventRemoveTimeout(timer);

    virMutexDestroy(&test->lock);
    VIR_FREE(test);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)

#endif /* !WIN32 */
