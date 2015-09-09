#ifdef WITH_QEMU

# include "capabilities.h"
# include "domain_conf.h"
# include "qemu/qemu_command.h"
# include "qemu/qemu_capabilities.h"

virCapsPtr testQemuCapsInit(void);
virDomainXMLOptionPtr testQemuXMLConfInit(void);
extern qemuBuildCommandLineCallbacks testCallbacks;

virQEMUCapsPtr qemuTestParseCapabilities(const char *capsFile);

extern virCPUDefPtr cpuDefault;
extern virCPUDefPtr cpuHaswell;
void testQemuCapsSetCPU(virCapsPtr caps,
                        virCPUDefPtr hostCPU);

int qemuTestDriverInit(virQEMUDriver *driver);
void qemuTestDriverFree(virQEMUDriver *driver);
int qemuTestCapsCacheInsert(virQEMUCapsCachePtr cache, const char *binary,
                            virQEMUCapsPtr caps);

/* This variable is actually defined in src/qemu/qemu_capabilities.c */
extern const char *qemuTestCapsName;
#endif
