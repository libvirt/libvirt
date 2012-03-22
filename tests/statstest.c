#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

#include "stats_linux.h"
#include "internal.h"
#include "xen/block_stats.h"
#include "testutils.h"
#include "command.h"

static void testQuietError(void *userData ATTRIBUTE_UNUSED,
                           virErrorPtr error ATTRIBUTE_UNUSED)
{
    /* nada */
}

static int testDevice(const char *path, int expect)
{
    int actual = xenLinuxDomainDeviceID(1, path);

    if (actual == expect) {
        return 0;
    } else {
        if (virTestGetDebug())
            fprintf(stderr, "Expect %-6d Actual %-6d\n", expect, actual);
        return -1;
    }
}

struct testInfo
{
    const char *dev;
    int num;
};

static int testDeviceHelper(const void *data)
{
    const struct testInfo *info = data;
    return testDevice(info->dev, info->num);
}

static int
mymain(void)
{
    int ret = 0;
    int status;
    virCommandPtr cmd;
    struct utsname ut;

    /* Skip test if xend is not running.  Calling xend on a non-xen
       kernel causes some versions of xend to issue a crash report, so
       we first probe uname results.  */
    uname(&ut);
    if (strstr(ut.release, "xen") == NULL)
        return EXIT_AM_SKIP;
    cmd = virCommandNewArgList("/usr/sbin/xend", "status", NULL);
    if (virCommandRun(cmd, &status) != 0 || status != 0) {
        virCommandFree(cmd);
        return EXIT_AM_SKIP;
    }
    virCommandFree(cmd);

    /* Some of our tests deliberately test failure cases, so
     * register a handler to stop error messages cluttering
     * up display
     */
    if (!virTestGetDebug())
        virSetErrorFunc(NULL, testQuietError);

#define DO_TEST(dev, num)                                              \
    do {                                                               \
        struct testInfo info = { dev, num };                           \
        if (virtTestRun("Device " dev " -> " # num,                    \
                        1, testDeviceHelper, &info) < 0)               \
            ret = -1;                                                  \
    } while (0)

    /********************************
     * Xen paravirt disks
     ********************************/

    DO_TEST("xvd", -1);

    /* first valid disk */
    DO_TEST("xvda", 51712);
    DO_TEST("xvda1", 51713);
    DO_TEST("xvda15", 51727);
    /* Last non-extended disk */
    DO_TEST("xvdp", 51952);
    DO_TEST("xvdp1", 51953);
    DO_TEST("xvdp15", 51967);

    /* First extended disk */
    DO_TEST("xvdq", 268439552);
    DO_TEST("xvdq1", 268439553);
    DO_TEST("xvdq15", 268439567);
    /* Last extended disk */
    DO_TEST("xvdiz", 268501760);
    DO_TEST("xvdiz1", 268501761);
    DO_TEST("xvdiz15", 268501775);

    /* Disk letter too large */
    DO_TEST("xvdja", -1);

    /* missing disk letter */
    DO_TEST("xvd1", -1);
    /* partition too large */
    DO_TEST("xvda16", -1);
    /* partition too small */
    DO_TEST("xvda0", -1);
    /* leading zeros */
    DO_TEST("xvda01", -1);
    /* leading + */
    DO_TEST("xvda+1", -1);
    /* leading - */
    DO_TEST("xvda-1", -1);

    /********************************
     * IDE disks
     ********************************/

    DO_TEST("hd", -1);

    /* first numbered disk */
    DO_TEST("hda", 768);
    DO_TEST("hda1", 769);
    DO_TEST("hda63", 831);
    /* second numbered disk */
    DO_TEST("hdb", 832);
    DO_TEST("hdb1", 833);
    DO_TEST("hdb63", 895);
    /* third numbered disk */
    DO_TEST("hdc", 5632);
    DO_TEST("hdc1", 5633);
    DO_TEST("hdc63", 5695);
    /* fourth numbered disk */
    DO_TEST("hdd", 5696);
    DO_TEST("hdd1", 5697);
    DO_TEST("hdd63", 5759);
    /* last valid disk */
    DO_TEST("hdt", 23360);
    DO_TEST("hdt1", 23361);
    DO_TEST("hdt63", 23423);

    /* Disk letter to large */
    DO_TEST("hdu", -1);
    /* missing disk letter */
    DO_TEST("hd1", -1);
    /* partition too large */
    DO_TEST("hda64", -1);
    /* partition too small */
    DO_TEST("hda0", -1);



    /********************************
     * SCSI disks
     ********************************/

    DO_TEST("sd", -1);

    /* first valid disk */
    DO_TEST("sda", 2048);
    DO_TEST("sda1", 2049);
    DO_TEST("sda15", 2063);
    /* last valid disk of first SCSI major number */
    DO_TEST("sdp", 2288);
    DO_TEST("sdp1", 2289);
    DO_TEST("sdp15", 2303);
    /* first valid disk of second SCSI major number */
    DO_TEST("sdq", 16640);
    DO_TEST("sdq1", 16641);
    DO_TEST("sdq15", 16655);
    /* last valid single letter disk */
    DO_TEST("sdz", 16784);
    DO_TEST("sdz1", 16785);
    DO_TEST("sdz15", 16799);
    /* first valid dual letter disk */
    DO_TEST("sdaa", 16800);
    DO_TEST("sdaa1", 16801);
    DO_TEST("sdaa15", 16815);
    /* second valid dual letter disk */
    DO_TEST("sdab", 16816);
    DO_TEST("sdab1", 16817);
    DO_TEST("sdab15", 16831);
    /* first letter of second sequence of dual letter disk */
    DO_TEST("sdba", 17216);
    DO_TEST("sdba1", 17217);
    DO_TEST("sdba15", 17231);
    /* last valid dual letter disk */
    DO_TEST("sdiv", 34800);
    DO_TEST("sdiv1", 34801);
    DO_TEST("sdiv15", 34815);

    /* Disk letter too large */
    DO_TEST("sdix", -1);
    /* missing disk letter */
    DO_TEST("sd1", -1);
    /* partition too large */
    DO_TEST("sda16", -1);
    /* partition too small */
    DO_TEST("sda0", -1);


    /* Path stripping */
    DO_TEST("/dev", -1);
    DO_TEST("/dev/", -1);
    DO_TEST("/dev/xvd", -1);
    DO_TEST("/dev/xvda", 51712);
    DO_TEST("/dev/xvda1", 51713);
    DO_TEST("/dev/xvda15", 51727);

    return ret==0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
