/*
 * testutils.c: basic test utils
 *
 * Copyright (C) 2005-2007 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Karel Zak <kzak@redhat.com>
 *
 * $Id$
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include "testutils.h"

#ifdef HAVE_PATHS_H
#include <paths.h>
#endif

#ifndef _PATH_DEVNULL
#define	_PATH_DEVNULL	"/dev/null"
#endif

#define GETTIMEOFDAY(T) gettimeofday(T, NULL)
#define DIFF_MSEC(T, U)                                 \
    ((((int) ((T)->tv_sec - (U)->tv_sec)) * 1000000.0 +	\
      ((int) ((T)->tv_usec - (U)->tv_usec))) / 1000.0)

double
virtTestCountAverage(double *items, int nitems)
{
    long double sum = 0;
    int i;

    for (i=1; i < nitems; i++)
        sum += items[i];

    return (double) (sum / nitems);
}

/*
 * Runs test and count average time (if the nloops is grater than 1)
 *
 * returns: -1 = error, 0 = success
 */
int
virtTestRun(const char *title, int nloops, int (*body)(void *data), void *data)
{
    int i, ret = 0;
    double *ts = NULL;

    if (nloops > 1 && (ts = calloc(nloops,
                                   sizeof(double)))==NULL)
        return -1;

    for (i=0; i < nloops; i++) {
        struct timeval before, after;

        if (ts)
            GETTIMEOFDAY(&before);
        if ((ret = body(data)) != 0)
            break;
        if (ts)	{
            GETTIMEOFDAY(&after);
            ts[i] = DIFF_MSEC(&after, &before);
        }
    }
    if (ret == 0 && ts)
        fprintf(stderr, "%-50s ... OK     [%.5f ms]\n", title,
                virtTestCountAverage(ts, nloops));
    else if (ret == 0)
        fprintf(stderr, "%-50s ... OK\n", title);
    else
        fprintf(stderr, "%-50s ... FAILED\n", title);

    if (ts)
        free(ts);
    return ret;
}

int virtTestLoadFile(const char *name,
                     char **buf,
                     int buflen) {
    FILE *fp = fopen(name, "r");
    struct stat st;

    if (!fp)
        return -1;

    if (fstat(fileno(fp), &st) < 0) {
        fclose(fp);
        return -1;
    }

    if (st.st_size > (buflen-1)) {
        fclose(fp);
        return -1;
    }

    if (st.st_size) {
        if (fread(*buf, st.st_size, 1, fp) != 1) {
            fclose(fp);
            return -1;
        }
    }
    (*buf)[st.st_size] = '\0';

    fclose(fp);
    return st.st_size;
}

static
void virtTestCaptureProgramExecChild(const char *const argv[],
                                     int pipefd) {
    int i;
    int open_max;
    int stdinfd = -1;
    int stderrfd = -1;
    const char *const env[] = {
        "LANG=C",
        NULL
    };

    if ((stdinfd = open(_PATH_DEVNULL, O_RDONLY)) < 0)
        goto cleanup;
    if ((stderrfd = open(_PATH_DEVNULL, O_WRONLY)) < 0)
        goto cleanup;

    open_max = sysconf (_SC_OPEN_MAX);
    for (i = 0; i < open_max; i++) {
        if (i != stdinfd &&
            i != stderrfd &&
            i != pipefd)
            close(i);
    }

    if (dup2(stdinfd, STDIN_FILENO) != STDIN_FILENO)
        goto cleanup;
    if (dup2(pipefd, STDOUT_FILENO) != STDOUT_FILENO)
        goto cleanup;
    if (dup2(stderrfd, STDERR_FILENO) != STDERR_FILENO)
        goto cleanup;

    /* SUS is crazy here, hence the cast */
    execve(argv[0], (char *const*)argv, (char *const*)env);

 cleanup:
    if (stdinfd != -1)
        close(stdinfd);
    if (stderrfd != -1)
        close(stderrfd);
}


int virtTestCaptureProgramOutput(const char *const argv[],
                                 char **buf,
                                 int buflen) {
    int pipefd[2];

    if (pipe(pipefd) < 0)
        return -1;

    int pid = fork();
    switch (pid) {
    case 0:
        close(pipefd[0]);
        virtTestCaptureProgramExecChild(argv, pipefd[1]);

        close(pipefd[1]);
        _exit(1);

    case -1:
        return -1;

    default:
        {
            int got = 0;
            int ret = -1;
            int want = buflen-1;

            close(pipefd[1]);

            while (want) {
                if ((ret = read(pipefd[0], (*buf)+got, want)) <= 0)
                    break;
                got += ret;
                want -= ret;
            }
            close(pipefd[0]);

            if (!ret)
                (*buf)[got] = '\0';

            waitpid(pid, NULL, 0);

            return ret;
        }
    }
}


/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
