/*
 * Copyright (C) 2011, 2013 Red Hat, Inc.
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

#define VIR_NO_GLIB_STDIO /* This file intentionally does not link to libvirt/glib */
#include "testutils.h"

#ifndef WIN32

int main(int argc, char **argv)
{
    size_t i;
    bool failConnect = false; /* Exit -1, with no data on stdout, msg on stderr */
    bool dieEarly = false;    /* Exit -1, with partial data on stdout, msg on stderr */

    for (i = 1; i < argc; i++) {
        if (STREQ(argv[i], "nosuchhost"))
            failConnect = true;
        else if (STREQ(argv[i], "crashinghost"))
            dieEarly = true;
    }

    if (failConnect) {
        fprintf(stderr, "%s", "Cannot connect to host nosuchhost\n");
        return -1;
    }

    if (dieEarly) {
        printf("%s\n", "Hello World");
        fprintf(stderr, "%s", "Hangup from host\n");
        return -1;
    }

    for (i = 1; i < argc; i++)
        printf("%s%c", argv[i], i == (argc -1) ? '\n' : ' ');

    return 0;
}

#else

int
main(void)
{
    return EXIT_AM_SKIP;
}

#endif
