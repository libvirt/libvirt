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
# define TEST_TPM_ENV_VAR "VIR_TEST_MOCK_FAKE_TPM_VERSION"
# define TPM_VER_1_2 "1.2"
# define TPM_VER_2_0 "2.0"
# define TEST_NBDKIT_PATH "/fakebindir/nbdkit"

enum {
    GIC_NONE = 0,
    GIC_V2,
    GIC_V3,
    GIC_BOTH,
};

typedef enum {
    ARG_QEMU_CAPS = QEMU_CAPS_LAST + 1,
    ARG_QEMU_CAPS_DEL,
    ARG_GIC,
    ARG_MIGRATE_FROM,
    ARG_MIGRATE_FD,
    ARG_FLAGS,
    ARG_PARSEFLAGS,
    ARG_CAPS_ARCH,
    ARG_CAPS_VER,
    ARG_CAPS_VARIANT,
    ARG_CAPS_HOST_CPU_MODEL,
    ARG_FD_GROUP, /* name, nfds, fd[0], ... fd[n-1] */
    ARG_VDPA_FD, /* vdpadev, fd */
    ARG_NBDKIT_CAPS,
    ARG_END,
} testQemuInfoArgName;

typedef enum {
    FLAG_EXPECT_FAILURE     = 1 << 0,
    FLAG_EXPECT_PARSE_ERROR = 1 << 1,
    FLAG_FIPS_HOST          = 1 << 2, /* simulate host with FIPS mode enabled */
    FLAG_REAL_CAPS          = 1 << 3,
    FLAG_SLIRP_HELPER       = 1 << 4,
    FLAG_SKIP_CONFIG_ACTIVE = 1 << 5, /* Skip 'active' config test in qemuxml2xmltest */
} testQemuInfoFlags;

struct testQemuConf {
    GHashTable *capscache;
    GHashTable *capslatest;
    GHashTable *qapiSchemaCache;
};

typedef enum {
    QEMU_CPU_DEF_DEFAULT,
    QEMU_CPU_DEF_HASWELL,
    QEMU_CPU_DEF_POWER8,
    QEMU_CPU_DEF_POWER9,
    QEMU_CPU_DEF_POWER10,
} qemuTestCPUDef;

struct testQemuArgs {
    bool newargs;
    virBitmap *fakeCapsAdd;
    virBitmap *fakeCapsDel;
    virBitmap *fakeNbdkitCaps;
    char *capsver;
    char *capsarch;
    const char *capsvariant;
    qemuTestCPUDef capsHostCPUModel;
    int gic;
    GHashTable *fds;
    GHashTable *vdpafds;
    bool invalidarg;
};

struct testQemuInfo {
    const char *name;
    char *infile;
    char *outfile;
    char *errfile;
    virQEMUCaps *qemuCaps;
    qemuNbdkitCaps *nbdkitCaps;
    const char *migrateFrom;
    int migrateFd;
    unsigned int flags;
    unsigned int parseFlags;
    virArch arch;
    GHashTable *qmpSchema; /* borrowed pointer from the cache */

    struct testQemuArgs args;
    struct testQemuConf *conf;
};

virDomainXMLOption *testQemuXMLConfInit(void);


virQEMUCaps *qemuTestParseCapabilitiesArch(virArch arch,
                                             const char *capsFile);
virCPUDef *qemuTestGetCPUDef(qemuTestCPUDef d);

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
                                           const char *variant,
                                           const char *suffix,
                                           void *opaque);
int testQemuCapsIterate(const char *suffix,
                        testQemuCapsIterateCallback callback,
                        void *opaque);

void testQemuInfoSetArgs(struct testQemuInfo *info,
                         struct testQemuConf *conf,
                         ...);
int testQemuInfoInitArgs(struct testQemuInfo *info);
void testQemuInfoClear(struct testQemuInfo *info);

int testQemuPrepareHostBackendChardevOne(virDomainDeviceDef *dev,
                                         virDomainChrSourceDef *chardev,
                                         void *opaque);

virQEMUCaps *
testQemuGetRealCaps(const char *arch,
                    const char *version,
                    const char *variant,
                    GHashTable *capsLatestFiles,
                    GHashTable *capsCache,
                    GHashTable *schemaCache,
                    GHashTable **schema);

int
testQemuInsertRealCaps(virFileCache *cache,
                       const char *arch,
                       const char *version,
                       const char *variant,
                       GHashTable *capsLatestFiles,
                       GHashTable *capsCache,
                       GHashTable *schemaCache,
                       GHashTable **schema);
#endif
