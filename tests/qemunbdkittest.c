#include <config.h>

#include <fcntl.h>
#include "internal.h"
#include "testutils.h"
#include "testutilsqemu.h"
#include "qemu/qemu_domain.h"
#include "qemu/qemu_nbdkit.h"
#define LIBVIRT_QEMU_NBDKITPRIV_H_ALLOW
#include "qemu/qemu_nbdkitpriv.h"
#include "vircommand.h"
#define LIBVIRT_VIRCOMMANDPRIV_H_ALLOW
#include "vircommandpriv.h"
#include "virutil.h"
#include "virsecret.h"
#include "datatypes.h"
#include "virmock.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

static virQEMUDriver driver;


/* Some mock implementations for testing */
#define PIPE_FD_START 777
static int mockpipefd = PIPE_FD_START;

static int (*real_virPipeQuiet)(int fds[2]);
static void
init_syms(void)
{
    VIR_MOCK_REAL_INIT(virPipeQuiet);
}

static int
moveToStableFd(int fd)
{
    int newfd;

    /* don't overwrite an existing fd */
    if (fcntl(mockpipefd, F_GETFD) != -1)
        abort();

    newfd = dup2(fd, mockpipefd++);

    VIR_FORCE_CLOSE(fd);

    return newfd;
}


int
virPipeQuiet(int fds[2])
{
    int tempfds[2];

    init_syms();

    if (real_virPipeQuiet(tempfds) < 0)
        return -1;

    if ((fds[0] = moveToStableFd(tempfds[0])) < 0 ||
        (fds[1] = moveToStableFd(tempfds[1])) < 0)
        return -1;

    return 0;
}


int
virSecretGetSecretString(virConnectPtr conn G_GNUC_UNUSED,
                         virSecretLookupTypeDef *seclookupdef,
                         virSecretUsageType secretUsageType,
                         uint8_t **secret,
                         size_t *secret_size)
{
    char uuidstr[VIR_UUID_BUFLEN];
    const char *secretname = NULL;
    char *tmp = NULL;

    switch (seclookupdef->type) {
        case VIR_SECRET_LOOKUP_TYPE_UUID:
            virUUIDFormat(seclookupdef->u.uuid, uuidstr);
            secretname = uuidstr;
            break;
        case VIR_SECRET_LOOKUP_TYPE_USAGE:
            secretname = seclookupdef->u.usage;
            break;
        case VIR_SECRET_LOOKUP_TYPE_NONE:
        case VIR_SECRET_LOOKUP_TYPE_LAST:
        default:
            virReportEnumRangeError(virSecretLookupType, seclookupdef->type);
            return -1;
    };

    /* For testing, just generate a value for the secret that includes the type
     * and the id of the secret */
    tmp = g_strdup_printf("%s-%s-secret", virSecretUsageTypeToString(secretUsageType), secretname);
    *secret = (uint8_t*)tmp;
    *secret_size = strlen(tmp) + 1;

    return 0;
}

virConnectPtr virGetConnectSecret(void)
{
    return virGetConnect();
}

/* end of mock implementations */


typedef struct {
    const char *name;
    char* infile;
    char* outtemplate;
    qemuNbdkitCaps *nbdkitcaps;
    bool expectFail;
} TestInfo;


typedef enum {
    NBDKIT_ARG_CAPS,
    NBDKIT_ARG_EXPECT_FAIL,
    NBDKIT_ARG_END
} NbdkitArgName;


static void
testInfoSetPaths(TestInfo *info)
{
    info->infile = g_strdup_printf("%s/qemuxml2argvdata/%s.xml",
                                   abs_srcdir, info->name);
    info->outtemplate = g_strdup_printf("%s/qemunbdkitdata/%s",
                                        abs_srcdir, info->name);
}

static void
testInfoClear(TestInfo *info)
{
    g_free(info->infile);
    g_free(info->outtemplate);
    g_clear_object(&info->nbdkitcaps);
}

static void
testInfoSetArgs(TestInfo *info, ...)
{
    va_list argptr;
    NbdkitArgName argname;
    unsigned int cap;

    va_start(argptr, info);
    while ((argname = va_arg(argptr, NbdkitArgName)) != NBDKIT_ARG_END) {
        switch (argname) {
            case NBDKIT_ARG_CAPS:
                while ((cap = va_arg(argptr, unsigned int)) < QEMU_NBDKIT_CAPS_LAST)
                    qemuNbdkitCapsSet(info->nbdkitcaps, cap);
                break;
            case NBDKIT_ARG_EXPECT_FAIL:
                info->expectFail = va_arg(argptr, unsigned int);
                break;
            case NBDKIT_ARG_END:
            default:
                break;
        }
    }
}


static int
testNbdkit(const void *data)
{
    const TestInfo *info = data;
    g_autoptr(virDomainDef) def = NULL;
    size_t i;
    int ret = 0;

    /* restart mock pipe fds so tests are consistent */
    mockpipefd = PIPE_FD_START;

    if (!virFileExists(info->infile)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Test input file '%s' is missing", info->infile);
        return -1;
    }

    if (!(def = virDomainDefParseFile(info->infile, driver.xmlopt, NULL,
                                      VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE)))
        return -1;

    for (i = 0; i < def->ndisks; i++) {
        virDomainDiskDef *disk = def->disks[i];
        g_autofree char *statedir = g_strdup_printf("/tmp/statedir-%zi", i);
        g_autofree char *alias = g_strdup_printf("test-disk-%zi", i);
        g_autofree char *cmdfile = g_strdup_printf("%s.args.disk%zi",
                                                   info->outtemplate, i);

        if (qemuNbdkitInitStorageSource(info->nbdkitcaps, disk->src, statedir,
                                        alias, 101, 101)) {
            qemuDomainStorageSourcePrivate *srcPriv =
                qemuDomainStorageSourcePrivateFetch(disk->src);
            g_autoptr(virCommand) cmd = NULL;
            g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();
            g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
            g_autofree char *actualCmdline = NULL;
            virCommandSendBuffer *sendbuffers;
            int nsendbuffers;
            size_t j;

            virCommandSetDryRun(dryRunToken, &buf, true, true, NULL, NULL);
            cmd = qemuNbdkitProcessBuildCommand(srcPriv->nbdkitProcess);

            if (virCommandRun(cmd, NULL) < 0) {
                ret = -1;
                continue;
            }
            virCommandPeekSendBuffers(cmd, &sendbuffers, &nsendbuffers);

            if (!(actualCmdline = virBufferContentAndReset(&buf))) {
                ret = -1;
                continue;
            }

            if (virTestCompareToFileFull(actualCmdline, cmdfile, false) < 0)
                ret = -1;

            for (j = 0; j < nsendbuffers; j++) {
                virCommandSendBuffer *buffer = &sendbuffers[j];
                g_autofree char *pipefile = g_strdup_printf("%s.pipe.%i",
                                                            cmdfile,
                                                            buffer->fd);

                if (virTestCompareToFile((const char*)buffer->buffer, pipefile) < 0)
                    ret = -1;
            }
        } else {
            if (virFileExists(cmdfile)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               "qemuNbdkitInitStorageSource() was not expected to fail");
                ret = -1;
            }
        }
    }

    if (info->expectFail) {
        if (ret == 0) {
            ret = -1;
            VIR_TEST_DEBUG("Error expected but there wasn't any.");
        } else {
            ret = 0;
        }
    }
    return ret;
}

static int
mymain(void)
{
    g_autoptr(GHashTable) capslatest = testQemuGetLatestCaps();
    g_autoptr(GHashTable) capscache = virHashNew(virObjectUnref);
    int ret = 0;

    if (qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    if (testQemuInsertRealCaps(driver.qemuCapsCache, "x86_64", "latest", "",
                               capslatest, capscache, NULL, NULL) < 0) {
        ret = -1;
        goto cleanup;
    }

#define DO_TEST_FULL(_name, ...) \
    do { \
        TestInfo info = { \
            .name = _name, \
            .nbdkitcaps = qemuNbdkitCapsNew(TEST_NBDKIT_PATH), \
        }; \
        testInfoSetPaths(&info); \
        testInfoSetArgs(&info, __VA_ARGS__); \
        virTestRunLog(&ret, "nbdkit " _name, testNbdkit, &info); \
        testInfoClear(&info); \
    } while (0)

#define DO_TEST(_name, ...) \
    DO_TEST_FULL(_name, NBDKIT_ARG_CAPS, __VA_ARGS__, QEMU_NBDKIT_CAPS_LAST, NBDKIT_ARG_END)

#define DO_TEST_FAILURE(_name, ...) \
    DO_TEST_FULL(_name, \
                 NBDKIT_ARG_EXPECT_FAIL, 1, \
                 NBDKIT_ARG_CAPS, __VA_ARGS__, QEMU_NBDKIT_CAPS_LAST, NBDKIT_ARG_END)

#define DO_TEST_NOCAPS(_name) \
    DO_TEST_FULL(_name, NBDKIT_ARG_END)

    DO_TEST("disk-cdrom-network", QEMU_NBDKIT_CAPS_PLUGIN_CURL);
    DO_TEST("disk-network-http", QEMU_NBDKIT_CAPS_PLUGIN_CURL);
    DO_TEST("disk-network-source-curl-nbdkit-backing", QEMU_NBDKIT_CAPS_PLUGIN_CURL);
    DO_TEST("disk-network-source-curl", QEMU_NBDKIT_CAPS_PLUGIN_CURL);
    DO_TEST("disk-network-ssh", QEMU_NBDKIT_CAPS_PLUGIN_SSH);
    DO_TEST("disk-network-ssh-password", QEMU_NBDKIT_CAPS_PLUGIN_SSH);
    DO_TEST("disk-network-ssh-key", QEMU_NBDKIT_CAPS_PLUGIN_SSH);

 cleanup:
    qemuTestDriverFree(&driver);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
