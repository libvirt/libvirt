/*
 * common, generic utility functions
 *
 * Copyright (C) 2006, 2007, 2008 Red Hat, Inc.
 * See COPYING.LIB for the License of this software
 */

#include <config.h>

#include <unistd.h>
#include <errno.h>

#include "util-lib.h"

/* Like read(), but restarts after EINTR */
int saferead(int fd, void *buf, size_t count)
{
        size_t nread = 0;
        while (count > 0) {
                ssize_t r = read(fd, buf, count);
                if (r < 0 && errno == EINTR)
                        continue;
                if (r < 0)
                        return r;
                if (r == 0)
                        return nread;
                buf = (char *)buf + r;
                count -= r;
                nread += r;
        }
        return nread;
}

/* Like write(), but restarts after EINTR */
ssize_t safewrite(int fd, const void *buf, size_t count)
{
        size_t nwritten = 0;
        while (count > 0) {
                ssize_t r = write(fd, buf, count);

                if (r < 0 && errno == EINTR)
                        continue;
                if (r < 0)
                        return r;
                if (r == 0)
                        return nwritten;
                buf = (const char *)buf + r;
                count -= r;
                nwritten += r;
        }
        return nwritten;
}
