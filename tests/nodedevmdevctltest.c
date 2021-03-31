#include <config.h>

#include "internal.h"
#include "testutils.h"
#include "datatypes.h"
#include "node_device/node_device_driver.h"
#include "vircommand.h"
#define LIBVIRT_VIRCOMMANDPRIV_H_ALLOW
#include "vircommandpriv.h"

#define VIR_FROM_THIS VIR_FROM_NODEDEV

struct startTestInfo {
    const char *virt_type;
    int create;
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

typedef virCommand* (*MdevctlCmdFunc)(virNodeDeviceDef *, char **, char **);


static int
testMdevctlCreateOrDefine(const char *virt_type,
                          int create,
                          MdevctlCmdFunc mdevctl_cmd_func,
                          const char *mdevxml,
                          const char *cmdfile,
                          const char *jsonfile)
{
    g_autoptr(virNodeDeviceDef) def = NULL;
    virNodeDeviceObj *obj = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    const char *actualCmdline = NULL;
    int ret = -1;
    g_autofree char *uuid = NULL;
    g_autofree char *errmsg = NULL;
    g_autofree char *stdinbuf = NULL;
    g_autoptr(virCommand) cmd = NULL;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    if (!(def = virNodeDeviceDefParseFile(mdevxml, create, virt_type)))
        goto cleanup;

    /* this function will set a stdin buffer containing the json configuration
     * of the device. The json value is captured in the callback above */
    cmd = mdevctl_cmd_func(def, &uuid, &errmsg);

    if (!cmd)
        goto cleanup;

    virCommandSetDryRun(dryRunToken, &buf, true, true, testCommandDryRunCallback, &stdinbuf);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (!(actualCmdline = virBufferCurrentContent(&buf)))
        goto cleanup;

    if (virTestCompareToFileFull(actualCmdline, cmdfile, false) < 0)
        goto cleanup;

    if (virTestCompareToFile(stdinbuf, jsonfile) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virNodeDeviceObjEndAPI(&obj);
    return ret;
}

static int
testMdevctlCreateOrDefineHelper(const void *data)
{
    const struct startTestInfo *info = data;
    const char *cmd;
    MdevctlCmdFunc func;
    g_autofree char *mdevxml = NULL;
    g_autofree char *cmdlinefile = NULL;
    g_autofree char *jsonfile = NULL;

    if (info->command == MDEVCTL_CMD_CREATE) {
        cmd = "create";
        func = nodeDeviceGetMdevctlCreateCommand;
    } else if (info->command == MDEVCTL_CMD_DEFINE) {
        cmd = "define";
        func = nodeDeviceGetMdevctlDefineCommand;
    } else {
        return -1;
    }

    mdevxml = g_strdup_printf("%s/nodedevschemadata/%s.xml", abs_srcdir,
                              info->filename);
    cmdlinefile = g_strdup_printf("%s/nodedevmdevctldata/%s-%s.argv",
                                  abs_srcdir, info->filename, cmd);
    jsonfile = g_strdup_printf("%s/nodedevmdevctldata/%s-%s.json", abs_srcdir,
                               info->filename, cmd);

    return testMdevctlCreateOrDefine(info->virt_type, info->create, func,
                                     mdevxml, cmdlinefile, jsonfile);
}

typedef virCommand* (*GetStopUndefineCmdFunc)(const char *uuid, char **errbuf);
struct UuidCommandTestInfo {
    const char *filename;
    virMdevctlCommand command;
};

static int
testMdevctlUuidCommand(GetStopUndefineCmdFunc func,
                       const char *mdevxml, const char *outfile)
{
    g_autoptr(virNodeDeviceDef) def = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    const char *actualCmdline = NULL;
    int ret = -1;
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *errmsg = NULL;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    if (!(def = virNodeDeviceDefParseFile(mdevxml, EXISTING_DEVICE, "QEMU")))
        goto cleanup;

    cmd = func(def->caps->data.mdev.uuid, &errmsg);

    if (!cmd)
        goto cleanup;

    virCommandSetDryRun(dryRunToken, &buf, true, true, NULL, NULL);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (!(actualCmdline = virBufferCurrentContent(&buf)))
        goto cleanup;

    if (virTestCompareToFileFull(actualCmdline, outfile, false) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    return ret;
}

static int
testMdevctlUuidCommandHelper(const void *data)
{
    const struct UuidCommandTestInfo *info = data;
    GetStopUndefineCmdFunc func;
    const char *cmd;
    g_autofree char *cmdlinefile = NULL;
    g_autofree char *mdevxml = NULL;

    if (info->command == MDEVCTL_CMD_STOP) {
        cmd = "stop";
        func = nodeDeviceGetMdevctlStopCommand;
    } else if (info->command == MDEVCTL_CMD_UNDEFINE) {
        cmd = "undefine";
        func = nodeDeviceGetMdevctlUndefineCommand;
    }else if (info->command == MDEVCTL_CMD_START) {
        cmd = "start";
        func = nodeDeviceGetMdevctlStartCommand;
    } else {
        return -1;
    }

    mdevxml = g_strdup_printf("%s/nodedevschemadata/%s.xml", abs_srcdir,
                              info->filename);
    cmdlinefile = g_strdup_printf("%s/nodedevmdevctldata/mdevctl-%s.argv",
                                  abs_srcdir, cmd);

    return testMdevctlUuidCommand(func, mdevxml, cmdlinefile);
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
fakeParentDevice(void)
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
        addDevice(fakeParentDevice()) < 0)
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

#define DO_TEST_CMD(desc, virt_type, create, filename, command) \
    do { \
        struct startTestInfo info = { virt_type, create, filename, command }; \
        DO_TEST_FULL(desc, testMdevctlCreateOrDefineHelper, &info); \
       } \
    while (0)

#define DO_TEST_CREATE(filename) \
    DO_TEST_CMD("mdevctl create " filename, "QEMU", CREATE_DEVICE, filename, MDEVCTL_CMD_CREATE)

#define DO_TEST_DEFINE(filename) \
    DO_TEST_CMD("mdevctl define " filename, "QEMU", CREATE_DEVICE, filename, MDEVCTL_CMD_DEFINE)

#define DO_TEST_UUID_COMMAND_FULL(desc, filename, command) \
    do { \
        struct UuidCommandTestInfo info = { filename, command }; \
        DO_TEST_FULL(desc, testMdevctlUuidCommandHelper, &info); \
       } \
    while (0)

#define DO_TEST_STOP(filename) \
    DO_TEST_UUID_COMMAND_FULL("mdevctl stop " filename, filename, MDEVCTL_CMD_STOP)

#define DO_TEST_UNDEFINE(filename) \
    DO_TEST_UUID_COMMAND_FULL("mdevctl undefine " filename, filename, MDEVCTL_CMD_UNDEFINE)

#define DO_TEST_START(filename) \
    DO_TEST_UUID_COMMAND_FULL("mdevctl start " filename, filename, MDEVCTL_CMD_START)

#define DO_TEST_LIST_DEFINED() \
    DO_TEST_FULL("mdevctl list --defined", testMdevctlListDefined, NULL)

#define DO_TEST_PARSE_JSON(filename) \
    DO_TEST_FULL("parse mdevctl json " filename, testMdevctlParse, filename)

    DO_TEST_CREATE("mdev_d069d019_36ea_4111_8f0a_8c9a70e21366");
    DO_TEST_CREATE("mdev_fedc4916_1ca8_49ac_b176_871d16c13076");
    DO_TEST_CREATE("mdev_d2441d39_495e_4243_ad9f_beb3f14c23d9");

    /* Test mdevctl stop command, pass an arbitrary uuid */
    DO_TEST_STOP("mdev_d069d019_36ea_4111_8f0a_8c9a70e21366");

    DO_TEST_LIST_DEFINED();

    DO_TEST_PARSE_JSON("mdevctl-list-multiple");

    DO_TEST_DEFINE("mdev_d069d019_36ea_4111_8f0a_8c9a70e21366");
    DO_TEST_DEFINE("mdev_fedc4916_1ca8_49ac_b176_871d16c13076");
    DO_TEST_DEFINE("mdev_d2441d39_495e_4243_ad9f_beb3f14c23d9");

    DO_TEST_UNDEFINE("mdev_d069d019_36ea_4111_8f0a_8c9a70e21366");

    DO_TEST_START("mdev_d069d019_36ea_4111_8f0a_8c9a70e21366");

 done:
    nodedevTestDriverFree(driver);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
