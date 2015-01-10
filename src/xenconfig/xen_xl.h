/*
 * xen_xl.h: Xen XL parsing functions
 *
 * Copyright (c) 2015 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 * Author: Kiarie Kahurani<davidkiarie4@gmail.com>
 */

#ifndef __VIR_XEN_XL_H__
# define __VIR_XEN_XL_H__

# include "virconf.h"
# include "domain_conf.h"
# include "xen_common.h"

virDomainDefPtr xenParseXL(virConfPtr conn, virCapsPtr caps,
                           int xendConfigVersion);
virConfPtr xenFormatXL(virDomainDefPtr def,
                       virConnectPtr, int xendConfigVersion);

#endif /* __VIR_XEN_XL_H__ */
