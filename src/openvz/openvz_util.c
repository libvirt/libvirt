/*
 * openvz_driver.c: core driver methods for managing OpenVZ VEs
 *
 * Copyright (C) 2012 Guido Günther
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

#include "internal.h"

#include "virterror_internal.h"

#include "openvz_conf.h"
#include "openvz_util.h"


long
openvzKBPerPages(void)
{
    static long kb_per_pages = 0;

    if (kb_per_pages == 0) {
        kb_per_pages = sysconf(_SC_PAGESIZE);
        if (kb_per_pages > 0) {
            kb_per_pages /= 1024;
        } else {
            openvzError(VIR_ERR_INTERNAL_ERROR,
                        _("Can't determine page size"));
            kb_per_pages = 0;
            return -1;
        }
    }
    return kb_per_pages;
}
