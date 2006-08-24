/*
 * utils.c: basic test utils
 *
 * Copyright (C) 2005 Red Hat, Inc.
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
#include <unistd.h>

#include "testutils.h"

#define GETTIMEOFDAY(T) gettimeofday(T, NULL)
#define DIFF_MSEC(T, U) \
	        ((((int) ((T)->tv_sec - (U)->tv_sec)) * 1000000.0 + \
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

    if (fread(*buf, st.st_size, 1, fp) != 1) {
        fclose(fp);
        return -1;
    }
    (*buf)[st.st_size] = '\0';

    fclose(fp);
    return st.st_size;
}

