/*
 * libxlmock.c: mocking of xenstore/libxs for libxl
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
 */

#include <config.h>

#if defined(WITH_LIBXL) && defined(WITH_YAJL)
# include "virmock.h"
# include <sys/stat.h>
# include <unistd.h>
# include <libxl.h>
# include <xenstore.h>
# include <xenctrl.h>

# include "libxl/libxl_capabilities.h"

VIR_MOCK_IMPL_RET_VOID(xs_daemon_open,
                       struct xs_handle *)
{
    VIR_MOCK_REAL_INIT(xs_daemon_open);
    return (void*)0x1;
}

VIR_MOCK_IMPL_RET_ARGS(xs_open,
                       struct xs_handle *,
                       unsigned long, flags)
{
    VIR_MOCK_REAL_INIT(xs_open);
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


VIR_MOCK_IMPL_RET_ARGS(libxl_get_version_info,
                       const libxl_version_info*,
                       libxl_ctx *, ctx)
{
    static libxl_version_info info = { 0 };

    /* silence gcc warning about unused function */
    if (0)
        real_libxl_get_version_info(ctx);
    return &info;
}

VIR_MOCK_IMPL_RET_ARGS(libxl_get_physinfo,
                       int,
                       libxl_ctx *, ctx,
                       libxl_physinfo *, physinfo)
{
    memset(physinfo, 0, sizeof(*physinfo));
    physinfo->nr_nodes = 6;

    /* silence gcc warning about unused function */
    if (0)
        real_libxl_get_physinfo(ctx, physinfo);

    return 0;
}

VIR_MOCK_STUB_RET_ARGS(libxl_get_free_memory,
                       int, 0,
                       libxl_ctx *, ctx,
# if LIBXL_API_VERSION < 0x040800
                       uint32_t *,
# else
                       uint64_t *,
# endif
                       memkb);

VIR_MOCK_STUB_RET_ARGS(xc_interface_close,
                       int, 0,
                       xc_interface *, handle)

VIR_MOCK_STUB_RET_ARGS(xc_physinfo,
                       int, 0,
                       xc_interface *, handle,
                       xc_physinfo_t *, put_info)

VIR_MOCK_STUB_RET_ARGS(xc_sharing_freed_pages,
                       long, 0,
                       xc_interface *, handle)

VIR_MOCK_STUB_RET_ARGS(xc_sharing_used_frames,
                       long, 0,
                       xc_interface *, handle)

VIR_MOCK_STUB_VOID_ARGS(xs_daemon_close,
                        struct xs_handle *, handle)

VIR_MOCK_STUB_VOID_ARGS(xs_close,
                        struct xs_handle *, xsh)

VIR_MOCK_STUB_RET_ARGS(bind,
                       int, 0,
                       int, sockfd,
                       const struct sockaddr *, addr,
                       socklen_t, addrlen)

VIR_MOCK_IMPL_RET_ARGS(libxl_get_required_shadow_memory,
                       unsigned long,
                       unsigned long, maxmem_kb,
                       unsigned int, smp_cpus)
{
    /* silence gcc warning about unused function */
    if (0)
        real_libxl_get_required_shadow_memory(maxmem_kb, smp_cpus);
    return 1234;
}

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

int
libxlDomainGetEmulatorType(const virDomainDef *def G_GNUC_UNUSED)
{
    return LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN;
}

#endif /* WITH_LIBXL && WITH_YAJL */
