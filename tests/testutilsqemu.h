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

virQEMUCapsPtr qemuTestParseCapabilities(const char *capsFile);

extern virCPUDefPtr cpuDefault;
extern virCPUDefPtr cpuHaswell;
void testQemuCapsSetCPU(virCapsPtr caps,
                        virCPUDefPtr hostCPU);

int qemuTestDriverInit(virQEMUDriver *driver);
void qemuTestDriverFree(virQEMUDriver *driver);
int qemuTestCapsCacheInsert(virQEMUCapsCachePtr cache, const char *binary,
                            virQEMUCapsPtr caps);

int testQemuCapsSetGIC(virQEMUCapsPtr qemuCaps,
                       int gic);

/* This variable is actually defined in src/qemu/qemu_capabilities.c */
extern const char *qemuTestCapsName;
#endif
