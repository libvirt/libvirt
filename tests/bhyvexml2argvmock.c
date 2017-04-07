#include <config.h>

#include "viralloc.h"
#include "virstring.h"
#include "virnetdev.h"
#include "virnetdevtap.h"
#include "internal.h"

#define VIR_FROM_THIS VIR_FROM_BHYVE

void virMacAddrGenerate(const unsigned char prefix[VIR_MAC_PREFIX_BUFLEN],
                        virMacAddrPtr addr)
{
    addr->addr[0] = prefix[0];
    addr->addr[1] = prefix[1];
    addr->addr[2] = prefix[2];
    addr->addr[3] = 0;
    addr->addr[4] = 0;
    addr->addr[5] = 0;
}

int virNetDevTapCreateInBridgePort(const char *brname ATTRIBUTE_UNUSED,
                                   char **ifname,
                                   const virMacAddr *macaddr ATTRIBUTE_UNUSED,
                                   const unsigned char *vmuuid ATTRIBUTE_UNUSED,
                                   const char *tunpath ATTRIBUTE_UNUSED,
                                   int *tapfd ATTRIBUTE_UNUSED,
                                   size_t tapfdSize ATTRIBUTE_UNUSED,
                                   virNetDevVPortProfilePtr virtPortProfile ATTRIBUTE_UNUSED,
                                   virNetDevVlanPtr virtVlan ATTRIBUTE_UNUSED,
                                   virNetDevCoalescePtr coalesce ATTRIBUTE_UNUSED,
                                   unsigned int mtu ATTRIBUTE_UNUSED,
                                   unsigned int *actualMTU ATTRIBUTE_UNUSED,
                                   unsigned int fakeflags ATTRIBUTE_UNUSED)
{
    VIR_FREE(*ifname);
    if (VIR_STRDUP(*ifname, "vnet0") < 0)
        return -1;
    return 0;
}

char *virNetDevTapGetRealDeviceName(char *name ATTRIBUTE_UNUSED)
{
    char *fakename;

    if (VIR_STRDUP(fakename, "faketapdev") < 0)
        return NULL;
    return fakename;
}

int virNetDevSetOnline(const char *ifname ATTRIBUTE_UNUSED,
                       bool online ATTRIBUTE_UNUSED)
{
    return 0;
}
