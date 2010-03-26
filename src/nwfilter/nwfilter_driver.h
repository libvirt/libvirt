/*
 * nwfilter_driver.h: core driver for nwfilter APIs
 *                    (based on storage driver)
 *
 * Copyright (C) 2006-2008 Red Hat, Inc.
 * Copyright (C) 2006-2008 Daniel P. Berrange
 * Copyright (C) 2010 IBM Corporation
 * Copyright (C) 2010 Stefan Berger
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 *         Stefan Berger <stefanb@us.ibm.com>
 */

#ifndef __VIR_NWFILTER_DRIVER_H__
# define __VIR_NWFILTER_DRIVER_H__

# include "nwfilter_params.h"
# include "nwfilter_conf.h"

int nwfilterRegister(void);

#endif /* __VIR_NWFILTER_DRIVER_H__ */
