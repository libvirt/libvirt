#ifdef WITH_QEMU

# include "capabilities.h"
# include "domain_conf.h"
# include "qemu/qemu_capabilities.h"
# include "qemu/qemu_conf.h"

enum {
    GIC_NONE = 0,
    GIC_V2,
    GIC_V3,
    GIC_BOTH,
};

virCapsPtr testQemuCapsInit(void);
virDomainXMLOptionPtr testQemuXMLConfInit(void);

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
int qemuTestCapsCacheInsert(virQEMUCapsCachePtr cache,
                            virQEMUCapsPtr caps);

int testQemuCapsSetGIC(virQEMUCapsPtr qemuCaps,
                       int gic);
#endif
