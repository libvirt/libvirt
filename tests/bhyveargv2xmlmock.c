#include <config.h>

#include "virnetdev.h"
#include "internal.h"
#include "testutilshostcpus.h"
#include "util/viruuid.h"
#include "cpu/cpu.h"

#define VIR_FROM_THIS VIR_FROM_BHYVE

void
virMacAddrGenerate(const unsigned char prefix[VIR_MAC_PREFIX_BUFLEN],
                   virMacAddr *addr)
{
    addr->addr[0] = prefix[0];
    addr->addr[1] = prefix[1];
    addr->addr[2] = prefix[2];
    addr->addr[3] = 0;
    addr->addr[4] = 0;
    addr->addr[5] = 0;
}

int
virUUIDGenerate(unsigned char *uuid)
{
    if (virUUIDParse("c7a5fdbd-edaf-9455-926a-d65c16db1809", uuid) < 0)
        return -1;
    return 0;
}

virCPUDef *
virCPUProbeHost(virArch arch)
{
    return testUtilsHostCpusGetDefForArch(arch);
}
