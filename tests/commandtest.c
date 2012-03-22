/*
 * commandtest.c: Test the libCommand API
 *
 * Copyright (C) 2010-2012 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "testutils.h"
#include "internal.h"
#include "nodeinfo.h"
#include "util.h"
#include "memory.h"
#include "command.h"
#include "virfile.h"
#include "virpidfile.h"

#ifdef WIN32

int
main(void)
{
    return EXIT_AM_SKIP;
}

#else

static int checkoutput(const char *testname)
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

    if (STRNEQ(expectlog, actuallog)) {
        virtTestDifference(stderr, expectlog, actuallog);
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
    if (status == 0)
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
        virErrorPtr err = virGetLastError();
        printf("Cannot run child %s\n", err->message);
        virCommandFree(cmd);
        return -1;
    }

    if ((ret = checkoutput("test2")) != 0) {
        virCommandFree(cmd);
        return ret;
    }

    if (virCommandRun(cmd, NULL) < 0) {
        virErrorPtr err = virGetLastError();
        printf("Cannot run child %s\n", err->message);
        virCommandFree(cmd);
        return -1;
    }

    virCommandFree(cmd);

    return checkoutput("test2");
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

    virCommandPreserveFD(cmd, newfd1);
    virCommandTransferFD(cmd, newfd3);

    if (virCommandRun(cmd, NULL) < 0) {
        virErrorPtr err = virGetLastError();
        printf("Cannot run child %s\n", err->message);
        goto cleanup;
    }

    if (fcntl(newfd1, F_GETFL) < 0 ||
        fcntl(newfd2, F_GETFL) < 0 ||
        fcntl(newfd3, F_GETFL) >= 0) {
        puts("fds in wrong state");
        goto cleanup;
    }

    ret = checkoutput("test3");

cleanup:
    virCommandFree(cmd);
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
        virErrorPtr err = virGetLastError();
        printf("Cannot run child %s\n", err->message);
        goto cleanup;
    }

    if (virPidFileRead(abs_builddir, "commandhelper", &pid) < 0) {
        printf("cannot read pidfile\n");
        goto cleanup;
    }
    while (kill(pid, 0) != -1)
        usleep(100*1000);

    ret = checkoutput("test4");

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
        virErrorPtr err = virGetLastError();
        printf("Cannot run child %s\n", err->message);
        virCommandFree(cmd);
        return -1;
    }

    virCommandFree(cmd);

    return checkoutput("test5");
}


/*
 * Run program, no args, inherit filtered ENV, keep CWD.
 * Only stdin/out/err open
 */
static int test6(const void *unused ATTRIBUTE_UNUSED)
{
    virCommandPtr cmd = virCommandNew(abs_builddir "/commandhelper");

    virCommandAddEnvPass(cmd, "DISPLAY");
    virCommandAddEnvPass(cmd, "DOESNOTEXIST");

    if (virCommandRun(cmd, NULL) < 0) {
        virErrorPtr err = virGetLastError();
        printf("Cannot run child %s\n", err->message);
        virCommandFree(cmd);
        return -1;
    }

    virCommandFree(cmd);

    return checkoutput("test6");
}


/*
 * Run program, no args, inherit filtered ENV, keep CWD.
 * Only stdin/out/err open
 */
static int test7(const void *unused ATTRIBUTE_UNUSED)
{
    virCommandPtr cmd = virCommandNew(abs_builddir "/commandhelper");

    virCommandAddEnvPassCommon(cmd);
    virCommandAddEnvPass(cmd, "DISPLAY");
    virCommandAddEnvPass(cmd, "DOESNOTEXIST");

    if (virCommandRun(cmd, NULL) < 0) {
        virErrorPtr err = virGetLastError();
        printf("Cannot run child %s\n", err->message);
        virCommandFree(cmd);
        return -1;
    }

    virCommandFree(cmd);

    return checkoutput("test7");
}

/*
 * Run program, no args, inherit filtered ENV, keep CWD.
 * Only stdin/out/err open
 */
static int test8(const void *unused ATTRIBUTE_UNUSED)
{
    virCommandPtr cmd = virCommandNew(abs_builddir "/commandhelper");

    virCommandAddEnvString(cmd, "LANG=C");
    virCommandAddEnvPair(cmd, "USER", "test");

    if (virCommandRun(cmd, NULL) < 0) {
        virErrorPtr err = virGetLastError();
        printf("Cannot run child %s\n", err->message);
        virCommandFree(cmd);
        return -1;
    }

    virCommandFree(cmd);

    return checkoutput("test8");
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
        virErrorPtr err = virGetLastError();
        printf("Cannot run child %s\n", err->message);
        virCommandFree(cmd);
        return -1;
    }

    virCommandFree(cmd);

    return checkoutput("test9");
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
        virErrorPtr err = virGetLastError();
        printf("Cannot run child %s\n", err->message);
        virCommandFree(cmd);
        return -1;
    }

    virCommandFree(cmd);

    return checkoutput("test10");
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
        virErrorPtr err = virGetLastError();
        printf("Cannot run child %s\n", err->message);
        virCommandFree(cmd);
        return -1;
    }

    virCommandFree(cmd);

    return checkoutput("test11");
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
        virErrorPtr err = virGetLastError();
        printf("Cannot run child %s\n", err->message);
        virCommandFree(cmd);
        return -1;
    }

    virCommandFree(cmd);

    return checkoutput("test12");
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
        virErrorPtr err = virGetLastError();
        printf("Cannot run child %s\n", err->message);
        goto cleanup;
    }
    if (!outactual)
        goto cleanup;

    virCommandFree(cmd);
    cmd = NULL;

    if (!STREQ(outactual, outexpect)) {
        virtTestDifference(stderr, outexpect, outactual);
        goto cleanup;
    }

    ret = checkoutput("test13");

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
        virErrorPtr err = virGetLastError();
        printf("Cannot run child %s\n", err->message);
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
        virErrorPtr err = virGetLastError();
        printf("Cannot run child %s\n", err->message);
        goto cleanup;
    }
    if (!jointactual)
        goto cleanup;

    if (!STREQ(outactual, outexpect)) {
        virtTestDifference(stderr, outexpect, outactual);
        goto cleanup;
    }
    if (!STREQ(erractual, errexpect)) {
        virtTestDifference(stderr, errexpect, erractual);
        goto cleanup;
    }
    if (!STREQ(jointactual, jointexpect)) {
        virtTestDifference(stderr, jointexpect, jointactual);
        goto cleanup;
    }

    ret = checkoutput("test14");

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

    if (virCommandRun(cmd, NULL) < 0) {
        virErrorPtr err = virGetLastError();
        printf("Cannot run child %s\n", err->message);
        goto cleanup;
    }

    ret = checkoutput("test15");

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
    const char *outexpect = "A=B true C";
    int ret = -1;
    int fd = -1;

    virCommandAddEnvPair(cmd, "A", "B");
    virCommandAddArg(cmd, "C");

    if ((outactual = virCommandToString(cmd)) == NULL) {
        virErrorPtr err = virGetLastError();
        printf("Cannot convert to string: %s\n", err->message);
        goto cleanup;
    }
    if ((fd = open(abs_builddir "/commandhelper.log",
                   O_CREAT | O_TRUNC | O_WRONLY, 0600)) < 0) {
        printf("Cannot open log file: %s\n", strerror (errno));
        goto cleanup;
    }
    virCommandWriteArgLog(cmd, fd);
    if (VIR_CLOSE(fd) < 0) {
        printf("Cannot close log file: %s\n", strerror (errno));
        goto cleanup;
    }

    if (!STREQ(outactual, outexpect)) {
        virtTestDifference(stderr, outexpect, outactual);
        goto cleanup;
    }

    ret = checkoutput("test16");

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
    char *errbuf;

    virCommandSetOutputBuffer(cmd, &outbuf);
    if (outbuf != NULL) {
        puts("buffer not sanitized at registration");
        goto cleanup;
    }

    if (virCommandRun(cmd, NULL) < 0) {
        virErrorPtr err = virGetLastError();
        printf("Cannot run child %s\n", err->message);
        goto cleanup;
    }

    if (!outbuf || *outbuf) {
        puts("output buffer is not an allocated empty string");
        goto cleanup;
    }
    VIR_FREE(outbuf);
    if ((outbuf = strdup("should not be leaked")) == NULL) {
        puts("test framework failure");
        goto cleanup;
    }

    virCommandSetErrorBuffer(cmd, &errbuf);
    if (errbuf != NULL) {
        puts("buffer not sanitized at registration");
        goto cleanup;
    }

    if (virCommandRun(cmd, NULL) < 0) {
        virErrorPtr err = virGetLastError();
        printf("Cannot run child %s\n", err->message);
        goto cleanup;
    }

    if (!outbuf || *outbuf || !errbuf || *errbuf) {
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
        virErrorPtr err = virGetLastError();
        printf("Cannot run child %s\n", err->message);
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
        virErrorPtr err = virGetLastError();
        printf("Cannot run child %s\n", err->message);
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

static int
mymain(void)
{
    int ret = 0;
    int fd;

    if (chdir("/tmp") < 0)
        return EXIT_FAILURE;

    setpgid(0, 0);
    setsid();

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
        (fd > 5 && VIR_CLOSE(fd) < 0))
        return EXIT_FAILURE;

    /* Prime the debug/verbose settings from the env vars,
     * since we're about to reset 'environ' */
    virTestGetDebug();
    virTestGetVerbose();

    virInitialize();

    /* Phase two of killing interfering fds; see above.  */
    fd = 3;
    VIR_FORCE_CLOSE(fd);
    fd = 4;
    VIR_FORCE_CLOSE(fd);
    fd = 5;
    VIR_FORCE_CLOSE(fd);

    environ = (char **)newenv;

# define DO_TEST(NAME)                                                \
    if (virtTestRun("Command Exec " #NAME " test",                    \
                    1, NAME, NULL) < 0)                               \
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

    return ret==0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)

#endif /* !WIN32 */
