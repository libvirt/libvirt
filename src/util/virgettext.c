/*
 * virgettext.c: gettext helper routines
 *
 * Copyright (C) 2016 Red Hat, Inc.
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

#include <locale.h>
#ifdef WITH_XLOCALE_H
# include <xlocale.h>
#endif

#include "configmake.h"
#include "internal.h"
#include "virgettext.h"


/**
 * virGettextInitialize:
 *
 * Initialize standard gettext setup
 * Returns -1 on fatal error
 */
int
virGettextInitialize(void)
{
#if WITH_LIBINTL_H
    if (!setlocale(LC_ALL, "")) {
        perror("setlocale");
        /* failure to setup locale is not fatal */
    }

    if (!bindtextdomain(PACKAGE, LOCALEDIR)) {
        perror("bindtextdomain");
        return -1;
    }

    if (!textdomain(PACKAGE)) {
        perror("textdomain");
        return -1;
    }
#endif /* WITH_LIBINTL_H */
    return 0;
}
