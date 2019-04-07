/*
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

#ifndef LIBVIRT_TESTUTILSQEMU_H
# define LIBVIRT_TESTUTILSQEMU_H

# ifdef WITH_QEMU

#  include "capabilities.h"
#  include "virfilecache.h"
#  include "domain_conf.h"
#  include "qemu/qemu_capabilities.h"
#  include "qemu/qemu_conf.h"

enum {
    GIC_NONE = 0,
    GIC_V2,
    GIC_V3,
    GIC_BOTH,
};

virCapsPtr testQemuCapsInit(void);
virDomainXMLOptionPtr testQemuXMLConfInit(void);


virQEMUCapsPtr qemuTestParseCapabilitiesArch(virArch arch,
                                             const char *capsFile);
virQEMUCapsPtr qemuTestParseCapabilities(virCapsPtr caps,
                                         const char *capsFile);

extern virCPUDefPtr cpuDefault;
extern virCPUDefPtr cpuHaswell;
extern virCPUDefPtr cpuPower8;
extern virCPUDefPtr cpuPower9;

void qemuTestSetHostArch(virCapsPtr caps,
                        virArch arch);
void qemuTestSetHostCPU(virCapsPtr caps,
                        virCPUDefPtr cpu);

int qemuTestDriverInit(virQEMUDriver *driver);
void qemuTestDriverFree(virQEMUDriver *driver);
int qemuTestCapsCacheInsert(virFileCachePtr cache,
                            virQEMUCapsPtr caps);

int testQemuCapsSetGIC(virQEMUCapsPtr qemuCaps,
                       int gic);

char *testQemuGetLatestCapsForArch(const char *dirname,
                                   const char *arch,
                                   const char *suffix);

typedef int (*testQemuCapsIterateCallback)(const char *base,
                                           const char *archName,
                                           void *opaque);
int testQemuCapsIterate(const char *dirname,
                        const char *suffix,
                        testQemuCapsIterateCallback callback,
                        void *opaque);

# endif

#endif /* LIBVIRT_TESTUTILSQEMU_H */
