#ifdef WITH_QEMU

# include "capabilities.h"
# include "domain_conf.h"
# include "qemu/qemu_command.h"
# include "qemu/qemu_capabilities.h"

virCapsPtr testQemuCapsInit(void);
virDomainXMLOptionPtr testQemuXMLConfInit(void);
extern qemuBuildCommandLineCallbacks testCallbacks;

virQEMUCapsPtr qemuTestParseCapabilities(const char *capsFile);
#endif
