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

#pragma once

#ifdef WITH_QEMU

# include "capabilities.h"
# include "virfilecache.h"
# include "domain_conf.h"
# include "qemu/qemu_capabilities.h"
# include "qemu/qemu_conf.h"

# define TEST_QEMU_CAPS_PATH abs_srcdir "/qemucapabilitiesdata"

enum {
    GIC_NONE = 0,
    GIC_V2,
    GIC_V3,
    GIC_BOTH,
};

typedef enum {
    ARG_QEMU_CAPS,
    ARG_GIC,
    ARG_MIGRATE_FROM,
    ARG_MIGRATE_FD,
    ARG_FLAGS,
    ARG_PARSEFLAGS,
    ARG_CAPS_ARCH,
    ARG_CAPS_VER,
    ARG_END,
} testQemuInfoArgName;

typedef enum {
    FLAG_EXPECT_FAILURE     = 1 << 0,
    FLAG_EXPECT_PARSE_ERROR = 1 << 1,
    FLAG_FIPS_HOST          = 1 << 2, /* simulate host with FIPS mode enabled */
    FLAG_REAL_CAPS          = 1 << 3,
    FLAG_SKIP_LEGACY_CPUS   = 1 << 4,
    FLAG_SLIRP_HELPER       = 1 << 5,
} testQemuInfoFlags;

struct testQemuInfo {
    const char *name;
    char *infile;
    char *outfile;
    char *errfile;
    virQEMUCaps *qemuCaps;
    const char *migrateFrom;
    int migrateFd;
    unsigned int flags;
    unsigned int parseFlags;
    virArch arch;
    char *schemafile;
    GHashTable *qapiSchemaCache;
};

virCaps *testQemuCapsInit(void);
virDomainXMLOption *testQemuXMLConfInit(void);


virQEMUCaps *qemuTestParseCapabilitiesArch(virArch arch,
                                             const char *capsFile);

extern virCPUDef *cpuDefault;
extern virCPUDef *cpuHaswell;
extern virCPUDef *cpuPower8;
extern virCPUDef *cpuPower9;

void qemuTestSetHostArch(virQEMUDriver *driver,
                         virArch arch);
void qemuTestSetHostCPU(virQEMUDriver *driver,
                        virArch arch,
                        virCPUDef *cpu);

int qemuTestDriverInit(virQEMUDriver *driver);
void qemuTestDriverFree(virQEMUDriver *driver);
int qemuTestCapsCacheInsert(virFileCache *cache,
                            virQEMUCaps *caps);

int testQemuCapsSetGIC(virQEMUCaps *qemuCaps,
                       int gic);

char *testQemuGetLatestCapsForArch(const char *arch,
                                   const char *suffix);
GHashTable *testQemuGetLatestCaps(void);

typedef int (*testQemuCapsIterateCallback)(const char *inputDir,
                                           const char *prefix,
                                           const char *version,
                                           const char *archName,
                                           const char *suffix,
                                           void *opaque);
int testQemuCapsIterate(const char *suffix,
                        testQemuCapsIterateCallback callback,
                        void *opaque);

int testQemuInfoSetArgs(struct testQemuInfo *info,
                        GHashTable *capscache,
                        GHashTable *capslatest, ...);
void testQemuInfoClear(struct testQemuInfo *info);

#endif
