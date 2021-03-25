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
