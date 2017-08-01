/*
 * virmocklibxl.c: mocking of xenstore/libxs for libxl
 *
 * Copyright (C) 2014 Red Hat, Inc.
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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#if defined(WITH_LIBXL) && defined(WITH_YAJL)
# include "virmock.h"
# include <sys/stat.h>
# include <unistd.h>
# include <libxl.h>
# include <xenstore.h>
# include <xenctrl.h>

VIR_MOCK_IMPL_RET_VOID(xs_daemon_open,
                       struct xs_handle *)
{
    VIR_MOCK_REAL_INIT(xs_daemon_open);
    return (void*)0x1;
}

VIR_MOCK_IMPL_RET_ARGS(xc_interface_open,
                       xc_interface *,
                       xentoollog_logger *, logger,
                       xentoollog_logger *, dombuild_logger,
                       unsigned, open_flags)
{
    VIR_MOCK_REAL_INIT(xc_interface_open);
    return (void*)0x1;
}


VIR_MOCK_STUB_RET_ARGS(xc_interface_close,
                       int, 0,
                       xc_interface *, handle)

VIR_MOCK_STUB_VOID_ARGS(xs_daemon_close,
                        struct xs_handle *, handle)

VIR_MOCK_IMPL_RET_ARGS(__xstat, int,
                       int, ver,
                       const char *, path,
                       struct stat *, sb)
{
    VIR_MOCK_REAL_INIT(__xstat);

    if (strstr(path, "xenstored.pid")) {
        memset(sb, 0, sizeof(*sb));
        return 0;
    }

    return real___xstat(ver, path, sb);
}

VIR_MOCK_IMPL_RET_ARGS(stat, int,
                       const char *, path,
                       struct stat *, sb)
{
    VIR_MOCK_REAL_INIT(stat);

    if (strstr(path, "xenstored.pid")) {
        memset(sb, 0, sizeof(*sb));
        return 0;
    }

    return real_stat(path, sb);
}

#endif /* WITH_LIBXL && WITH_YAJL */
