/*
 * libxl_api_wrapper.h: handle various libxl API variants
 *
 * Copyright (C) 2021 SUSE LLC
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

#pragma once

#include <limits.h>
#include <libxl.h>

static inline int
libxlDomainCreateRestoreWrapper(libxl_ctx *ctx,
                                libxl_domain_config *d_config,
                                uint32_t *domid,
                                int restore_fd,
                                const libxl_domain_restore_params *params,
                                const libxl_asyncprogress_how *aop_console_how)
{
    int ret;

#if LIBXL_API_VERSION < 0x040700
    ret = libxl_domain_create_restore(ctx, d_config, domid, restore_fd, params,
                                      NULL, aop_console_how);
#else
    ret = libxl_domain_create_restore(ctx, d_config, domid, restore_fd, -1,
                                      params, NULL, aop_console_how);
#endif

    return ret;
}

static inline int
libxlRetrieveDomainConfigurationWrapper(libxl_ctx *ctx,
                                        uint32_t domid,
                                        libxl_domain_config *d_config)
{
    int ret;

#if LIBXL_API_VERSION < 0x041300
    ret = libxl_retrieve_domain_configuration(ctx, domid, d_config);
#else
    ret = libxl_retrieve_domain_configuration(ctx, domid, d_config, NULL);
#endif

    return ret;
}

static inline int
libxlDomainShutdownWrapper(libxl_ctx *ctx, uint32_t domid)
{
    int ret;

#if LIBXL_API_VERSION < 0x041300
    ret = libxl_domain_shutdown(ctx, domid);
#else
    ret = libxl_domain_shutdown(ctx, domid, NULL);
#endif

    return ret;
}

static inline int
libxlDomainRebootWrapper(libxl_ctx *ctx, uint32_t domid)
{
    int ret;

#if LIBXL_API_VERSION < 0x041300
    ret = libxl_domain_reboot(ctx, domid);
#else
    ret = libxl_domain_reboot(ctx, domid, NULL);
#endif

    return ret;
}

static inline int
libxlDomainPauseWrapper(libxl_ctx *ctx, uint32_t domid)
{
    int ret;

#if LIBXL_API_VERSION < 0x041300
    ret = libxl_domain_pause(ctx, domid);
#else
    ret = libxl_domain_pause(ctx, domid, NULL);
#endif

    return ret;
}

static inline int
libxlDomainUnpauseWrapper(libxl_ctx *ctx, uint32_t domid)
{
    int ret;

#if LIBXL_API_VERSION < 0x041300
    ret = libxl_domain_unpause(ctx, domid);
#else
    ret = libxl_domain_unpause(ctx, domid, NULL);
#endif

    return ret;
}

#define INVALID_DOMID ~0
static inline int
libxlDomainNeedMemoryWrapper(libxl_ctx *ctx,
                             libxl_domain_config *d_config,
                             uint64_t *need_memkb)
{
    int ret;

#if LIBXL_API_VERSION < 0x040800
    {
        uint32_t val32 = 0;

        ret = libxl_domain_need_memory(ctx, &d_config->b_info, &val32);
        *need_memkb = val32;
    }
#elif LIBXL_API_VERSION < 0x041300
    ret = libxl_domain_need_memory(ctx, &d_config->b_info, need_memkb);
#else
    ret = libxl_domain_need_memory(ctx, d_config, INVALID_DOMID, need_memkb);
#endif

    return ret;
}

static inline int
libxlGetFreeMemoryWrapper(libxl_ctx *ctx, uint64_t *memkb)
{
    int ret;

#if LIBXL_API_VERSION < 0x040800
    {
        uint32_t val32 = 0;

        ret = libxl_get_free_memory(ctx, &val32);
        *memkb = val32;
    }
#else
    ret = libxl_get_free_memory(ctx, memkb);
#endif

    return ret;
}

static inline int
libxlSetVcpuonlineWrapper(libxl_ctx *ctx, uint32_t domid, libxl_bitmap *cpumap)
{
    int ret;

#if LIBXL_API_VERSION < 0x041300
    ret = libxl_set_vcpuonline(ctx, domid, cpumap);
#else
    ret = libxl_set_vcpuonline(ctx, domid, cpumap, NULL);
#endif

    return ret;
}

static inline int
libxlSendTriggerWrapper(libxl_ctx *ctx,
                        uint32_t domid,
                        libxl_trigger trigger,
                        uint32_t vcpuid)
{
    int ret;

#if LIBXL_API_VERSION < 0x041300
    ret = libxl_send_trigger(ctx, domid, trigger, vcpuid);
#else
    ret = libxl_send_trigger(ctx, domid, trigger, vcpuid, NULL);
#endif

    return ret;
}

static inline int
libxlSetMemoryTargetWrapper(libxl_ctx *ctx,
                        uint32_t domid,
                        int64_t target_memkb,
                        int relative,
                        int enforce)
{
    int ret = -1;

#ifdef LIBXL_HAVE_MEMKB_64BITS
    ret = libxl_set_memory_target(ctx, domid, target_memkb, relative, enforce);
#else
    if (target_memkb < INT_MAX) {
        int32_t val32 = target_memkb;

        ret = libxl_set_memory_target(ctx, domid, val32, relative, enforce);
    }
#endif

    return ret;
}
