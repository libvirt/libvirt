/*
 * lxc_native.h: LXC native configuration import
 *
 * Copyright (c) 2013 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 * Author: Cedric Bosdonnat <cbosdonnat@suse.com>
 */

#ifndef __LXC_NATIVE_H__
# define __LXC_NATIVE_H__

# include "domain_conf.h"

# define LXC_CONFIG_FORMAT "lxc-tools"

virDomainDefPtr lxcParseConfigString(const char *config);

#endif /* __LXC_NATIVE_H__ */
