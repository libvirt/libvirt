/*
 * virsysinfopriv.h: Header for functions tested in the test suite
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

#ifndef __VIR_SYSINFO_PRIV_H_ALLOW__
# error "virsysinfopriv.h may only be included by virsysinfo.c or test suites"
#endif

#ifndef __VIR_SYSINFO_PRIV_H__
# define __VIR_SYSINFO_PRIV_H__

virSysinfoDefPtr
virSysinfoReadPPC(void);

virSysinfoDefPtr
virSysinfoReadARM(void);

virSysinfoDefPtr
virSysinfoReadS390(void);

virSysinfoDefPtr
virSysinfoReadX86(void);

#endif /* __VIR_SYSINFO_PRIV_H__ */
