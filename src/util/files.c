/*
 * memory.c: safer file handling
 *
 * Copyright (C) 2010 IBM Corporation
 * Copyright (C) 2010 Stefan Berger
 * Copyright (C) 2010 RedHat, Inc.
 * Copyright (C) 2010 Eric Blake
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
 *
 */

#include <config.h>

#include <unistd.h>

#include "files.h"

int virClose(int *fdptr, bool preserve_errno)
{
    int saved_errno;
    int rc = 0;

    if (*fdptr >= 0) {
        if (preserve_errno)
            saved_errno = errno;
        rc = close(*fdptr);
        *fdptr = -1;
        if (preserve_errno)
            errno = saved_errno;
    }

    return rc;
}


int virFclose(FILE **file, bool preserve_errno)
{
    int saved_errno;
    int rc = 0;

    if (*file) {
        if (preserve_errno)
            saved_errno = errno;
        rc = fclose(*file);
        *file = NULL;
        if (preserve_errno)
            errno = saved_errno;
    }

    return rc;
}


FILE *virFdopen(int *fdptr, const char *mode)
{
    FILE *file = NULL;

    if (*fdptr >= 0) {
        file = fdopen(*fdptr, mode);
        if (file)
            *fdptr = -1;
    } else {
        errno = EBADF;
    }

    return file;
}
