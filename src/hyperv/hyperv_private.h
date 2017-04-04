/*
 * hyperv_private.h: private driver struct for the Microsoft Hyper-V driver
 *
 * Copyright (C) 2011 Matthias Bolte <matthias.bolte@googlemail.com>
 * Copyright (C) 2009 Michael Sievers <msievers83@googlemail.com>
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
 */

#ifndef __HYPERV_PRIVATE_H__
# define __HYPERV_PRIVATE_H__

# include "internal.h"
# include "virerror.h"
# include "hyperv_util.h"
# include "openwsman.h"

typedef enum _hypervWmiVersion hypervWmiVersion;
enum _hypervWmiVersion {
    HYPERV_WMI_VERSION_V1,
    HYPERV_WMI_VERSION_V2,
};

typedef struct _hypervPrivate hypervPrivate;
struct _hypervPrivate {
    hypervParsedUri *parsedUri;
    WsManClient *client;
    hypervWmiVersion wmiVersion;
};

#endif /* __HYPERV_PRIVATE_H__ */
