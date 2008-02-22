#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "stats_linux.h"
#include "internal.h"

#if WITH_XEN
static void testQuietError(void *userData ATTRIBUTE_UNUSED,
                           virErrorPtr error ATTRIBUTE_UNUSED)
{
    /* nada */
}
#endif

#if __linux__ && WITH_XEN
static int testDevice(const char *path, int expect)
{
    int actual = xenLinuxDomainDeviceID(NULL, 1, path);

    if (actual == expect) {
        fprintf(stderr, "%-14s == %-6d           OK\n", path, expect);
        return 0;
    } else {
        fprintf(stderr, "%-14s == %-6d (%-6d)  FAILED\n", path, expect, actual);
        return -1;
    }
}
#endif

int
main(void)
{
    int ret = 0;
#if __linux__ && WITH_XEN
    /* Some of our tests delibrately test failure cases, so
     * register a handler to stop error messages cluttering
     * up display
     */
    if (!getenv("DEBUG_TESTS"))
        virSetErrorFunc(NULL, testQuietError);

    /********************************
     * Xen paravirt disks
     ********************************/

    /* first valid disk */
    if (testDevice("xvda", 51712) < 0)
        ret = -1;
    if (testDevice("xvda1", 51713) < 0)
        ret = -1;
    if (testDevice("xvda15", 51727) < 0)
        ret = -1;
    /* Last valid disk */
    if (testDevice("xvdp", 51952) < 0)
        ret = -1;
    if (testDevice("xvdp1", 51953) < 0)
        ret = -1;
    if (testDevice("xvdp15", 51967) < 0)
        ret = -1;

    /* Disk letter to large */
    if (testDevice("xvdq", -1) < 0)
        ret = -1;
    /* missing disk letter */
    if (testDevice("xvd1", -1) < 0)
        ret = -1;
    /* partition to large */
    if (testDevice("xvda16", -1) < 0)
        ret = -1;
    /* partition to small */
    if (testDevice("xvda0", -1) < 0)
        ret = -1;
    /* leading zeros */
    if (testDevice("xvda01", -1) < 0)
        ret = -1;
    /* leading + */
    if (testDevice("xvda+1", -1) < 0)
        ret = -1;
    /* leading - */
    if (testDevice("xvda-1", -1) < 0)
        ret = -1;

    /********************************
     * IDE disks
     ********************************/

    /* odd numbered disk */
    if (testDevice("hda", 768) < 0)
        ret = -1;
    if (testDevice("hda1", 769) < 0)
        ret = -1;
    if (testDevice("hda63", 831) < 0)
        ret = -1;
    /* even number disk */
    if (testDevice("hdd", 5695) < 0)
        ret = -1;
    if (testDevice("hdd1", 5696) < 0)
        ret = -1;
    if (testDevice("hdd63", 5758) < 0)
        ret = -1;
    /* last valid disk */
    if (testDevice("hdt", 23359) < 0)
        ret = -1;
    if (testDevice("hdt1", 23360) < 0)
        ret = -1;
    if (testDevice("hdt63", 23422) < 0)
        ret = -1;

    /* Disk letter to large */
    if (testDevice("hdu", -1) < 0)
        ret = -1;
    /* missing disk letter */
    if (testDevice("hd1", -1) < 0)
        ret = -1;
    /* partition to large */
    if (testDevice("hda64", -1) < 0)
        ret = -1;
    /* partition to small */
    if (testDevice("hda0", -1) < 0)
        ret = -1;



    /********************************
     * SCSI disks
     ********************************/

    /* first valid disk */
    if (testDevice("sda", 2048) < 0)
        ret = -1;
    if (testDevice("sda1", 2049) < 0)
        ret = -1;
    if (testDevice("sda15", 2063) < 0)
        ret = -1;
    /* last valid disk of first SCSI major number */
    if (testDevice("sdp", 2288) < 0)
        ret = -1;
    if (testDevice("sdp1", 2289) < 0)
        ret = -1;
    if (testDevice("sdp15", 2303) < 0)
        ret = -1;
    /* first valid disk of second SCSI major number */
    if (testDevice("sdq", 16640) < 0)
        ret = -1;
    if (testDevice("sdq1", 16641) < 0)
        ret = -1;
    if (testDevice("sdq15", 16655) < 0)
        ret = -1;
    /* last valid single letter disk */
    if (testDevice("sdz", 16784) < 0)
        ret = -1;
    if (testDevice("sdz1", 16785) < 0)
        ret = -1;
    if (testDevice("sdz15", 16799) < 0)
        ret = -1;
    /* first valid dual letter disk */
    if (testDevice("sdaa", 16800) < 0)
        ret = -1;
    if (testDevice("sdaa1", 16801) < 0)
        ret = -1;
    if (testDevice("sdaa15", 16815) < 0)
        ret = -1;
    /* second valid dual letter disk */
    if (testDevice("sdab", 16816) < 0)
        ret = -1;
    if (testDevice("sdab1", 16817) < 0)
        ret = -1;
    if (testDevice("sdab15", 16831) < 0)
        ret = -1;
    /* first letter of second sequence of dual letter disk */
    if (testDevice("sdba", 17216) < 0)
        ret = -1;
    if (testDevice("sdba1", 17217) < 0)
        ret = -1;
    if (testDevice("sdba15", 17231) < 0)
        ret = -1;
    /* last valid dual letter disk */
    if (testDevice("sdiv", 34800) < 0)
        ret = -1;
    if (testDevice("sdiv1", 34801) < 0)
        ret = -1;
    if (testDevice("sdiv15", 34815) < 0)
        ret = -1;

    /* Disk letter to large */
    if (testDevice("sdix", -1) < 0)
        ret = -1;
    /* missing disk letter */
    if (testDevice("sd1", -1) < 0)
        ret = -1;
    /* partition to large */
    if (testDevice("sda16", -1) < 0)
        ret = -1;
    /* partition to small */
    if (testDevice("sda0", -1) < 0)
        ret = -1;


    /* Path stripping */
    if (testDevice("/dev", -1) < 0)
        ret = -1;
    if (testDevice("/dev/", -1) < 0)
        ret = -1;
    if (testDevice("/dev/xvd", -1) < 0)
        ret = -1;
    if (testDevice("/dev/xvda", 51712) < 0)
        ret = -1;
    if (testDevice("/dev/xvda1", 51713) < 0)
        ret = -1;
    if (testDevice("/dev/xvda15", 51727) < 0)
        ret = -1;

#endif
    exit(ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
