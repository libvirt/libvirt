/*
 * esx_nwfilter_driver.h: nwfilter driver functions for managing VMware ESX
 *                        firewall rules
 *
 * Copyright (C) 2010 Matthias Bolte <matthias.bolte@googlemail.com>
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

#ifndef __ESX_NWFILTER_DRIVER_H__
# define __ESX_NWFILTER_DRIVER_H__

int esxNWFilterRegister(void);

#endif /* __ESX_NWFILTER_DRIVER_H__ */
