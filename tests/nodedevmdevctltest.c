#include <config.h>

#include "internal.h"
#include "testutils.h"
#include "node_device/node_device_driver.h"
#include "vircommand.h"
#define LIBVIRT_VIRCOMMANDPRIV_H_ALLOW
#include "vircommandpriv.h"

#define VIR_FROM_THIS VIR_FROM_NODEDEV

#define VIRT_TYPE "QEMU"

static virNodeDeviceDefParserCallbacks parser_callbacks = {
    .postParse = nodeDeviceDefPostParse,
    .validate = nodeDeviceDefValidate
};

struct TestInfo {
    const char *filename;
    virMdevctlCommand command;
};

/* capture stdin passed to command */
static void
testCommandDryRunCallback(const char *const*args G_GNUC_UNUSED,
                          const char *const*env G_GNUC_UNUSED,
                          const char *input,
                          char **output G_GNUC_UNUSED,
                          char **error G_GNUC_UNUSED,
                          int *status G_GNUC_UNUSED,
                          void *opaque G_GNUC_UNUSED)
{
    char **stdinbuf = opaque;

    *stdinbuf = g_strdup(input);
}

typedef virCommand * (*MdevctlCmdFunc)(virNodeDeviceDef *, char **, char **);


static int
testMdevctlCmd(virMdevctlCommand cmd_type,
               const char *mdevxml,
               const char *cmdfile,
               const char *jsonfile)
{
    g_autoptr(virNodeDeviceDef) def = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    const char *actualCmdline = NULL;
    g_autofree char *outbuf = NULL;
    g_autofree char *errbuf = NULL;
    g_autofree char *stdinbuf = NULL;
    g_autoptr(virCommand) cmd = NULL;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();
    int create;

    switch (cmd_type) {
        case MDEVCTL_CMD_CREATE:
        case MDEVCTL_CMD_DEFINE:
            create = CREATE_DEVICE;
            break;
        case MDEVCTL_CMD_START:
        case MDEVCTL_CMD_STOP:
        case MDEVCTL_CMD_UNDEFINE:
            create = EXISTING_DEVICE;
            break;
        case MDEVCTL_CMD_LAST:
        default:
            return -1;
    }

    if (!(def = virNodeDeviceDefParse(NULL, mdevxml, create, VIRT_TYPE,
                                      &parser_callbacks, NULL, false)))
        return -1;

    /* this function will set a stdin buffer containing the json configuration
     * of the device. The json value is captured in the callback above */
    cmd = nodeDeviceGetMdevctlCommand(def, cmd_type, &outbuf, &errbuf);

    if (!cmd)
        return -1;

    if (create)
        virCommandSetDryRun(dryRunToken, &buf, true, true,
                            testCommandDryRunCallback, &stdinbuf);
    else
        virCommandSetDryRun(dryRunToken, &buf, true, true, NULL, NULL);

    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    if (!(actualCmdline = virBufferCurrentContent(&buf)))
        return -1;

    if (virTestCompareToFileFull(actualCmdline, cmdfile, false) < 0)
        return -1;

    if (create && virTestCompareToFile(stdinbuf, jsonfile) < 0)
        return -1;

    return 0;
}


static int
testMdevctlHelper(const void *data)
{
    const struct TestInfo *info = data;
    const char *cmd = virMdevctlCommandTypeToString(info->command);
    g_autofree char *mdevxml = NULL;
    g_autofree char *cmdlinefile = NULL;
    g_autofree char *jsonfile = NULL;

    mdevxml = g_strdup_printf("%s/nodedevschemadata/%s.xml", abs_srcdir,
                              info->filename);
    cmdlinefile = g_strdup_printf("%s/nodedevmdevctldata/%s-%s.argv",
                                  abs_srcdir, info->filename, cmd);
    jsonfile = g_strdup_printf("%s/nodedevmdevctldata/%s-%s.json", abs_srcdir,
                               info->filename, cmd);

    return testMdevctlCmd(info->command, mdevxml, cmdlinefile, jsonfile);
}


static int
testMdevctlAutostart(const void *data G_GNUC_UNUSED)
{
    g_autoptr(virNodeDeviceDef) def = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *actualCmdline = NULL;
    int ret = -1;
    g_autoptr(virCommand) enablecmd = NULL;
    g_autoptr(virCommand) disablecmd = NULL;
    g_autofree char *errmsg = NULL;
    /* just concatenate both calls into the same output file */
    g_autofree char *cmdlinefile =
        g_strdup_printf("%s/nodedevmdevctldata/mdevctl-autostart.argv",
                        abs_srcdir);
    g_autofree char *mdevxml =
        g_strdup_printf("%s/nodedevschemadata/mdev_d069d019_36ea_4111_8f0a_8c9a70e21366.xml",
                        abs_srcdir);
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    if (!(def = virNodeDeviceDefParse(NULL, mdevxml, CREATE_DEVICE, VIRT_TYPE,
                                      &parser_callbacks, NULL, false)))
        return -1;

    virCommandSetDryRun(dryRunToken, &buf, true, true, NULL, NULL);

    if (!(enablecmd = nodeDeviceGetMdevctlSetAutostartCommand(def, true, &errmsg)))
        goto cleanup;

    if (virCommandRun(enablecmd, NULL) < 0)
        goto cleanup;

    if (!(disablecmd = nodeDeviceGetMdevctlSetAutostartCommand(def, false, &errmsg)))
        goto cleanup;

    if (virCommandRun(disablecmd, NULL) < 0)
        goto cleanup;

    if (!(actualCmdline = virBufferCurrentContent(&buf)))
        goto cleanup;

    if (virTestCompareToFileFull(actualCmdline, cmdlinefile, false) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virBufferFreeAndReset(&buf);
    return ret;
}

static int
testMdevctlListDefined(const void *data G_GNUC_UNUSED)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *actualCmdline = NULL;
    int ret = -1;
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *output = NULL;
    g_autofree char *errmsg = NULL;
    g_autofree char *cmdlinefile =
        g_strdup_printf("%s/nodedevmdevctldata/mdevctl-list-defined.argv",
                        abs_srcdir);
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    cmd = nodeDeviceGetMdevctlListCommand(true, &output, &errmsg);

    if (!cmd)
        goto cleanup;

    virCommandSetDryRun(dryRunToken, &buf, true, true, NULL, NULL);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (!(actualCmdline = virBufferCurrentContent(&buf)))
        goto cleanup;

    if (virTestCompareToFileFull(actualCmdline, cmdlinefile, false) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virBufferFreeAndReset(&buf);
    return ret;
}

static int
testMdevctlParse(const void *data)
{
    g_autofree char *buf = NULL;
    const char *filename = data;
    g_autofree char *jsonfile = g_strdup_printf("%s/nodedevmdevctldata/%s.json",
                                                abs_srcdir, filename);
    g_autofree char *xmloutfile = g_strdup_printf("%s/nodedevmdevctldata/%s.out.xml",
                                                  abs_srcdir, filename);
    int ret = -1;
    int nmdevs = 0;
    virNodeDeviceDef **mdevs = NULL;
    virBuffer xmloutbuf = VIR_BUFFER_INITIALIZER;
    size_t i;

    if (virFileReadAll(jsonfile, 1024*1024, &buf) < 0) {
        VIR_TEST_DEBUG("Unable to read file %s", jsonfile);
        return -1;
    }

    if ((nmdevs = nodeDeviceParseMdevctlJSON(buf, &mdevs)) < 0) {
        VIR_TEST_DEBUG("Unable to parse json for %s", filename);
        return -1;
    }

    for (i = 0; i < nmdevs; i++) {
        g_autofree char *devxml = virNodeDeviceDefFormat(mdevs[i]);
        if (!devxml)
            goto cleanup;
        virBufferAddStr(&xmloutbuf, devxml);
    }

    if (virTestCompareToFileFull(virBufferCurrentContent(&xmloutbuf), xmloutfile, false) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virBufferFreeAndReset(&xmloutbuf);
    for (i = 0; i < nmdevs; i++)
        virNodeDeviceDefFree(mdevs[i]);
    g_free(mdevs);

    return ret;
}

static void
nodedevTestDriverFree(virNodeDeviceDriverState *drv)
{
    if (!drv)
        return;

    virNodeDeviceObjListFree(drv->devs);
    virCondDestroy(&drv->initCond);
    virMutexDestroy(&drv->lock);
    g_free(drv->stateDir);
    g_free(drv);
}

/* Add a fake root 'computer' device */
static virNodeDeviceDef *
fakeRootDevice(void)
{
    virNodeDeviceDef *def = NULL;

    def = g_new0(virNodeDeviceDef, 1);
    def->caps = g_new0(virNodeDevCapsDef, 1);
    def->name = g_strdup("computer");

    return def;
}

/* Add a fake pci device that can be used as a parent device for mediated
 * devices. For our purposes, it only needs to have a name that matches the
 * parent of the mdev, and it needs a PCI address
 */
static virNodeDeviceDef *
fakePCIDevice(void)
{
    virNodeDeviceDef *def = NULL;
    virNodeDevCapPCIDev *pci_dev;

    def = g_new0(virNodeDeviceDef, 1);
    def->caps = g_new0(virNodeDevCapsDef, 1);

    def->name = g_strdup("pci_0000_00_02_0");
    def->parent = g_strdup("computer");

    def->caps->data.type = VIR_NODE_DEV_CAP_PCI_DEV;
    pci_dev = &def->caps->data.pci_dev;
    pci_dev->domain = 0;
    pci_dev->bus = 0;
    pci_dev->slot = 2;
    pci_dev->function = 0;

    return def;
}


/* Add a fake matrix device that can be used as a parent device for mediated
 * devices. For our purposes, it only needs to have a name that matches the
 * parent of the mdev, and it needs the proper name
 */
static virNodeDeviceDef *
fakeMatrixDevice(void)
{
    virNodeDeviceDef *def = NULL;
    virNodeDevCapAPMatrix *cap;

    def = g_new0(virNodeDeviceDef, 1);
    def->caps = g_new0(virNodeDevCapsDef, 1);

    def->name = g_strdup("ap_matrix");
    def->parent = g_strdup("computer");

    def->caps->data.type = VIR_NODE_DEV_CAP_AP_MATRIX;
    cap = &def->caps->data.ap_matrix;
    cap->addr = g_strdup("matrix");

    return def;
}

/* Add a fake css device that can be used as a parent device for mediated
 * devices. For our purposes, it only needs to have a name that matches the
 * parent of the mdev, and it needs the proper name
 */
static virNodeDeviceDef *
fakeCSSDevice(void)
{
    virNodeDeviceDef *def = NULL;
    virNodeDevCapCCW *css_dev;

    def = g_new0(virNodeDeviceDef, 1);
    def->caps = g_new0(virNodeDevCapsDef, 1);

    def->name = g_strdup("css_0_0_0052");
    def->parent = g_strdup("computer");

    def->caps->data.type = VIR_NODE_DEV_CAP_CSS_DEV;
    css_dev = &def->caps->data.ccw_dev;
    css_dev->cssid = 0;
    css_dev->ssid = 0;
    css_dev->devno = 82;

    return def;
}

static int
addDevice(virNodeDeviceDef *def)
{
    virNodeDeviceObj *obj;
    if (!def)
        return -1;

    obj = virNodeDeviceObjListAssignDef(driver->devs, def);

    if (!obj) {
        virNodeDeviceDefFree(def);
        return -1;
    }

    virNodeDeviceObjEndAPI(&obj);
    return 0;
}

static int
nodedevTestDriverAddTestDevices(void)
{
    if (addDevice(fakeRootDevice()) < 0 ||
        addDevice(fakePCIDevice()) < 0 ||
        addDevice(fakeMatrixDevice()) < 0 ||
        addDevice(fakeCSSDevice()) < 0)
        return -1;

    return 0;
}

/* Bare minimum driver init to be able to test nodedev functionality */
static int
nodedevTestDriverInit(void)
{
    int ret = -1;
    driver = g_new0(virNodeDeviceDriverState, 1);

    driver->lockFD = -1;
    if (virMutexInit(&driver->lock) < 0 ||
        virCondInit(&driver->initCond) < 0) {
        VIR_TEST_DEBUG("Unable to initialize test nodedev driver");
        goto error;
    }

    if (!(driver->devs = virNodeDeviceObjListNew()))
        goto error;

    return 0;

 error:
    nodedevTestDriverFree(driver);
    return ret;
}

static int
mymain(void)
{
    int ret = 0;

    if (nodedevTestDriverInit() < 0)
        return EXIT_FAILURE;

    /* add a mock device to the device list so it can be used as a parent
     * reference */
    if (nodedevTestDriverAddTestDevices() < 0) {
        ret = EXIT_FAILURE;
        goto done;
    }

#define DO_TEST_FULL(desc, func, info) \
    if (virTestRun(desc, func, info) < 0) \
        ret = -1;

#define DO_TEST_CMD(desc, filename, command) \
    do { \
        struct TestInfo info = { filename, command }; \
        DO_TEST_FULL(desc, testMdevctlHelper, &info); \
       } \
    while (0)

#define DO_TEST_CREATE(filename) \
    DO_TEST_CMD("create mdev " filename, filename, MDEVCTL_CMD_CREATE)

#define DO_TEST_DEFINE(filename) \
    DO_TEST_CMD("define mdev " filename, filename, MDEVCTL_CMD_DEFINE)

#define DO_TEST_STOP(filename) \
    DO_TEST_CMD("stop mdev " filename, filename, MDEVCTL_CMD_STOP)

#define DO_TEST_UNDEFINE(filename) \
    DO_TEST_CMD("undefine mdev" filename, filename, MDEVCTL_CMD_UNDEFINE)

#define DO_TEST_START(filename) \
    DO_TEST_CMD("start mdev " filename, filename, MDEVCTL_CMD_START)

#define DO_TEST_LIST_DEFINED() \
    DO_TEST_FULL("list defined mdevs", testMdevctlListDefined, NULL)

#define DO_TEST_AUTOSTART() \
    DO_TEST_FULL("autostart mdevs", testMdevctlAutostart, NULL)

#define DO_TEST_PARSE_JSON(filename) \
    DO_TEST_FULL("parse mdevctl json " filename, testMdevctlParse, filename)

    DO_TEST_CREATE("mdev_d069d019_36ea_4111_8f0a_8c9a70e21366");
    DO_TEST_CREATE("mdev_fedc4916_1ca8_49ac_b176_871d16c13076");
    DO_TEST_CREATE("mdev_d2441d39_495e_4243_ad9f_beb3f14c23d9");
    DO_TEST_CREATE("mdev_cc000052_9b13_9b13_9b13_cc23009b1326");

    /* Test mdevctl stop command, pass an arbitrary uuid */
    DO_TEST_STOP("mdev_d069d019_36ea_4111_8f0a_8c9a70e21366");

    DO_TEST_LIST_DEFINED();

    DO_TEST_PARSE_JSON("mdevctl-list-empty");
    DO_TEST_PARSE_JSON("mdevctl-list-empty-array");
    DO_TEST_PARSE_JSON("mdevctl-list-multiple");

    DO_TEST_DEFINE("mdev_d069d019_36ea_4111_8f0a_8c9a70e21366");
    DO_TEST_DEFINE("mdev_fedc4916_1ca8_49ac_b176_871d16c13076");
    DO_TEST_DEFINE("mdev_d2441d39_495e_4243_ad9f_beb3f14c23d9");
    DO_TEST_DEFINE("mdev_cc000052_9b13_9b13_9b13_cc23009b1326");

    DO_TEST_UNDEFINE("mdev_d069d019_36ea_4111_8f0a_8c9a70e21366");

    DO_TEST_START("mdev_d069d019_36ea_4111_8f0a_8c9a70e21366");

    DO_TEST_AUTOSTART();

 done:
    nodedevTestDriverFree(driver);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
