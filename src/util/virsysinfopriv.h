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

#ifndef LIBVIRT_VIRSYSINFOPRIV_H_ALLOW
# error "virsysinfopriv.h may only be included by virsysinfo.c or test suites"
#endif /* LIBVIRT_VIRSYSINFOPRIV_H_ALLOW */

#ifndef LIBVIRT_VIRSYSINFOPRIV_H
# define LIBVIRT_VIRSYSINFOPRIV_H

void
virSysinfoSetup(const char *dmidecode,
                const char *sysinfo,
                const char *cpuinfo);

virSysinfoDefPtr
virSysinfoReadPPC(void);

virSysinfoDefPtr
virSysinfoReadARM(void);

virSysinfoDefPtr
virSysinfoReadS390(void);

virSysinfoDefPtr
virSysinfoReadDMI(void);

#endif /* LIBVIRT_VIRSYSINFOPRIV_H */
