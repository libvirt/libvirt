/*
 * qemu_saveimage.c: Infrastructure for saving qemu state to a file
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include "qemu_saveimage.h"
#include "qemu_domain.h"
#include "qemu_migration.h"
#include "qemu_process.h"
#include "qemu_security.h"

#include "domain_audit.h"

#include "virerror.h"
#include "virlog.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_saveimage");

typedef enum {
    QEMU_SAVE_FORMAT_RAW = 0,
    QEMU_SAVE_FORMAT_GZIP = 1,
    QEMU_SAVE_FORMAT_BZIP2 = 2,
    /*
     * Deprecated by xz and never used as part of a release
     * QEMU_SAVE_FORMAT_LZMA
     */
    QEMU_SAVE_FORMAT_XZ = 3,
    QEMU_SAVE_FORMAT_LZOP = 4,
    /* Note: add new members only at the end.
       These values are used in the on-disk format.
       Do not change or re-use numbers. */

    QEMU_SAVE_FORMAT_LAST
} virQEMUSaveFormat;

VIR_ENUM_DECL(qemuSaveCompression);
VIR_ENUM_IMPL(qemuSaveCompression,
              QEMU_SAVE_FORMAT_LAST,
              "raw",
              "gzip",
              "bzip2",
              "xz",
              "lzop",
);

static inline void
qemuSaveImageBswapHeader(virQEMUSaveHeader *hdr)
{
    hdr->version = GUINT32_SWAP_LE_BE(hdr->version);
    hdr->data_len = GUINT32_SWAP_LE_BE(hdr->data_len);
    hdr->was_running = GUINT32_SWAP_LE_BE(hdr->was_running);
    hdr->compressed = GUINT32_SWAP_LE_BE(hdr->compressed);
    hdr->cookieOffset = GUINT32_SWAP_LE_BE(hdr->cookieOffset);
}


void
virQEMUSaveDataFree(virQEMUSaveData *data)
{
    if (!data)
        return;

    g_free(data->xml);
    g_free(data->cookie);
    g_free(data);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virQEMUSaveData, virQEMUSaveDataFree);

/**
 * This function steals @domXML on success.
 */
virQEMUSaveData *
virQEMUSaveDataNew(char *domXML,
                   qemuDomainSaveCookie *cookieObj,
                   bool running,
                   int compressed,
                   virDomainXMLOption *xmlopt)
{
    virQEMUSaveData *data = NULL;
    virQEMUSaveHeader *header;

    data = g_new0(virQEMUSaveData, 1);

    if (cookieObj &&
        !(data->cookie = virSaveCookieFormat((virObject *) cookieObj,
                                             virDomainXMLOptionGetSaveCookie(xmlopt))))
        goto error;

    header = &data->header;
    memcpy(header->magic, QEMU_SAVE_PARTIAL, sizeof(header->magic));
    header->version = QEMU_SAVE_VERSION;
    header->was_running = running ? 1 : 0;
    header->compressed = compressed;

    data->xml = domXML;
    return data;

 error:
    virQEMUSaveDataFree(data);
    return NULL;
}


/* virQEMUSaveDataWrite:
 *
 * Writes libvirt's header (including domain XML) into a saved image of a
 * running domain. If @header has data_len filled in (because it was previously
 * read from the file), the function will make sure the new data will fit
 * within data_len.
 *
 * Returns -1 on failure, or 0 on success.
 */
int
virQEMUSaveDataWrite(virQEMUSaveData *data,
                     int fd,
                     const char *path)
{
    virQEMUSaveHeader *header = &data->header;
    size_t len;
    size_t xml_len;
    size_t cookie_len = 0;
    size_t zerosLen = 0;
    g_autofree char *zeros = NULL;

    xml_len = strlen(data->xml) + 1;
    if (data->cookie)
        cookie_len = strlen(data->cookie) + 1;

    len = xml_len + cookie_len;

    if (header->data_len == 0) {
        /* This 64kb padding allows the user to edit the XML in
         * a saved state image and have the new XML be larger
         * that what was originally saved
         */
        header->data_len = len + (64 * 1024);
    } else {
        if (len > header->data_len) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("new xml too large to fit in file"));
            return -1;
        }
    }

    zerosLen = header->data_len - len;
    zeros = g_new0(char, zerosLen);

    if (data->cookie)
        header->cookieOffset = xml_len;

    if (safewrite(fd, header, sizeof(*header)) != sizeof(*header)) {
        virReportSystemError(errno,
                             _("failed to write header to domain save file '%s'"),
                             path);
        return -1;
    }

    if (safewrite(fd, data->xml, xml_len) != xml_len) {
        virReportSystemError(errno,
                             _("failed to write domain xml to '%s'"),
                             path);
        return -1;
    }

    if (data->cookie &&
        safewrite(fd, data->cookie, cookie_len) != cookie_len) {
        virReportSystemError(errno,
                             _("failed to write cookie to '%s'"),
                             path);
        return -1;
    }

    if (safewrite(fd, zeros, zerosLen) != zerosLen) {
        virReportSystemError(errno,
                             _("failed to write padding to '%s'"),
                             path);
        return -1;
    }

    return 0;
}


static int
virQEMUSaveDataFinish(virQEMUSaveData *data,
                      int *fd,
                      const char *path)
{
    virQEMUSaveHeader *header = &data->header;

    memcpy(header->magic, QEMU_SAVE_MAGIC, sizeof(header->magic));

    if (safewrite(*fd, header, sizeof(*header)) != sizeof(*header) ||
        VIR_CLOSE(*fd) < 0) {
        virReportSystemError(errno,
                             _("failed to write header to domain save file '%s'"),
                             path);
        return -1;
    }

    return 0;
}


static virCommand *
qemuSaveImageGetCompressionCommand(virQEMUSaveFormat compression)
{
    virCommand *ret = NULL;
    const char *prog = qemuSaveCompressionTypeToString(compression);

    if (!prog) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Invalid compressed save format %d"),
                       compression);
        return NULL;
    }

    ret = virCommandNew(prog);
    virCommandAddArg(ret, "-dc");

    if (compression == QEMU_SAVE_FORMAT_LZOP)
        virCommandAddArg(ret, "--ignore-warn");

    return ret;
}


/* Helper function to execute a migration to file with a correct save header
 * the caller needs to make sure that the processors are stopped and do all other
 * actions besides saving memory */
int
qemuSaveImageCreate(virQEMUDriver *driver,
                    virDomainObj *vm,
                    const char *path,
                    virQEMUSaveData *data,
                    virCommand *compressor,
                    unsigned int flags,
                    virDomainAsyncJob asyncJob)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    bool needUnlink = false;
    int ret = -1;
    int fd = -1;
    int directFlag = 0;
    virFileWrapperFd *wrapperFd = NULL;
    unsigned int wrapperFlags = VIR_FILE_WRAPPER_NON_BLOCKING;

    /* Obtain the file handle.  */
    if ((flags & VIR_DOMAIN_SAVE_BYPASS_CACHE)) {
        wrapperFlags |= VIR_FILE_WRAPPER_BYPASS_CACHE;
        directFlag = virFileDirectFdFlag();
        if (directFlag < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("bypass cache unsupported by this system"));
            goto cleanup;
        }
    }

    fd = virQEMUFileOpenAs(cfg->user, cfg->group, false, path,
                           O_WRONLY | O_TRUNC | O_CREAT | directFlag,
                           &needUnlink);
    if (fd < 0)
        goto cleanup;

    if (qemuSecuritySetImageFDLabel(driver->securityManager, vm->def, fd) < 0)
        goto cleanup;

    if (!(wrapperFd = virFileWrapperFdNew(&fd, path, wrapperFlags)))
        goto cleanup;

    if (virQEMUSaveDataWrite(data, fd, path) < 0)
        goto cleanup;

    /* Perform the migration */
    if (qemuMigrationSrcToFile(driver, vm, fd, compressor, asyncJob) < 0)
        goto cleanup;

    /* Touch up file header to mark image complete. */

    /* Reopen the file to touch up the header, since we aren't set
     * up to seek backwards on wrapperFd.  The reopened fd will
     * trigger a single page of file system cache pollution, but
     * that's acceptable.  */
    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno, _("unable to close %s"), path);
        goto cleanup;
    }

    if (qemuDomainFileWrapperFDClose(vm, wrapperFd) < 0)
        goto cleanup;

    if ((fd = qemuDomainOpenFile(cfg, vm->def, path, O_WRONLY, NULL)) < 0 ||
        virQEMUSaveDataFinish(data, &fd, path) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FORCE_CLOSE(fd);
    if (qemuDomainFileWrapperFDClose(vm, wrapperFd) < 0)
        ret = -1;
    virFileWrapperFdFree(wrapperFd);

    if (ret < 0 && needUnlink)
        unlink(path);

    return ret;
}


/* qemuSaveImageGetCompressionProgram:
 * @imageFormat: String representation from qemu.conf for the compression
 *               image format being used (dump, save, or snapshot).
 * @compresspath: Pointer to a character string to store the fully qualified
 *                path from virFindFileInPath.
 * @styleFormat: String representing the style of format (dump, save, snapshot)
 * @use_raw_on_fail: Boolean indicating how to handle the error path. For
 *                   callers that are OK with invalid data or inability to
 *                   find the compression program, just return a raw format
 *                   and let the path remain as NULL.
 *
 * Returns:
 *    virQEMUSaveFormat    - Integer representation of the compression
 *                           program to be used for particular style
 *                           (e.g. dump, save, or snapshot).
 *    QEMU_SAVE_FORMAT_RAW - If there is no qemu.conf imageFormat value or
 *                           no there was an error, then just return RAW
 *                           indicating none.
 */
int
qemuSaveImageGetCompressionProgram(const char *imageFormat,
                                   virCommand **compressor,
                                   const char *styleFormat,
                                   bool use_raw_on_fail)
{
    int ret;
    const char *prog;

    *compressor = NULL;

    if (!imageFormat)
        return QEMU_SAVE_FORMAT_RAW;

    if ((ret = qemuSaveCompressionTypeFromString(imageFormat)) < 0)
        goto error;

    if (ret == QEMU_SAVE_FORMAT_RAW)
        return QEMU_SAVE_FORMAT_RAW;

    if (!(prog = virFindFileInPath(imageFormat)))
        goto error;

    *compressor = virCommandNew(prog);
    virCommandAddArg(*compressor, "-c");
    if (ret == QEMU_SAVE_FORMAT_XZ)
        virCommandAddArg(*compressor, "-3");

    return ret;

 error:
    if (ret < 0) {
        if (use_raw_on_fail)
            VIR_WARN("Invalid %s image format specified in "
                     "configuration file, using raw",
                     styleFormat);
        else
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("Invalid %s image format specified "
                             "in configuration file"),
                           styleFormat);
    } else {
        if (use_raw_on_fail)
            VIR_WARN("Compression program for %s image format in "
                     "configuration file isn't available, using raw",
                     styleFormat);
        else
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("Compression program for %s image format "
                             "in configuration file isn't available"),
                           styleFormat);
    }

    /* Use "raw" as the format if the specified format is not valid,
     * or the compress program is not available. */
    if (use_raw_on_fail)
        return QEMU_SAVE_FORMAT_RAW;

    return -1;
}


/**
 * qemuSaveImageOpen:
 * @driver: qemu driver data
 * @qemuCaps: pointer to qemuCaps if the domain is running or NULL
 * @path: path of the save image
 * @ret_def: returns domain definition created from the XML stored in the image
 * @ret_data: returns structure filled with data from the image header
 * @bypass_cache: bypass cache when opening the file
 * @wrapperFd: returns the file wrapper structure
 * @open_write: open the file for writing (for updates)
 * @unlink_corrupt: remove the image file if it is corrupted
 *
 * Returns the opened fd of the save image file and fills the appropriate fields
 * on success. On error returns -1 on most failures, -3 if corrupt image was
 * unlinked (no error raised).
 */
int
qemuSaveImageOpen(virQEMUDriver *driver,
                  virQEMUCaps *qemuCaps,
                  const char *path,
                  virDomainDef **ret_def,
                  virQEMUSaveData **ret_data,
                  bool bypass_cache,
                  virFileWrapperFd **wrapperFd,
                  bool open_write,
                  bool unlink_corrupt)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    VIR_AUTOCLOSE fd = -1;
    int ret = -1;
    g_autoptr(virQEMUSaveData) data = NULL;
    virQEMUSaveHeader *header;
    g_autoptr(virDomainDef) def = NULL;
    int oflags = open_write ? O_RDWR : O_RDONLY;
    size_t xml_len;
    size_t cookie_len;

    if (bypass_cache) {
        int directFlag = virFileDirectFdFlag();
        if (directFlag < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("bypass cache unsupported by this system"));
            return -1;
        }
        oflags |= directFlag;
    }

    if ((fd = qemuDomainOpenFile(cfg, NULL, path, oflags, NULL)) < 0)
        return -1;

    if (bypass_cache &&
        !(*wrapperFd = virFileWrapperFdNew(&fd, path,
                                           VIR_FILE_WRAPPER_BYPASS_CACHE)))
        return -1;

    data = g_new0(virQEMUSaveData, 1);

    header = &data->header;
    if (saferead(fd, header, sizeof(*header)) != sizeof(*header)) {
        if (unlink_corrupt) {
            if (unlink(path) < 0) {
                virReportSystemError(errno,
                                     _("cannot remove corrupt file: %s"),
                                     path);
                return -1;
            } else {
                return -3;
            }
        }

        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("failed to read qemu header"));
        return -1;
    }

    if (memcmp(header->magic, QEMU_SAVE_MAGIC, sizeof(header->magic)) != 0) {
        if (memcmp(header->magic, QEMU_SAVE_PARTIAL, sizeof(header->magic)) == 0) {
            if (unlink_corrupt) {
                if (unlink(path) < 0) {
                    virReportSystemError(errno,
                                         _("cannot remove corrupt file: %s"),
                                         path);
                    return -1;
                } else {
                    return -3;
                }
            }

            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("save image is incomplete"));
            return -1;
        }

        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("image magic is incorrect"));
        return -1;
    }

    if (header->version > QEMU_SAVE_VERSION) {
        /* convert endianness and try again */
        qemuSaveImageBswapHeader(header);
    }

    if (header->version > QEMU_SAVE_VERSION) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("image version is not supported (%d > %d)"),
                       header->version, QEMU_SAVE_VERSION);
        return -1;
    }

    if (header->data_len <= 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("invalid header data length: %d"), header->data_len);
        return -1;
    }

    if (header->cookieOffset)
        xml_len = header->cookieOffset;
    else
        xml_len = header->data_len;

    cookie_len = header->data_len - xml_len;

    data->xml = g_new0(char, xml_len);

    if (saferead(fd, data->xml, xml_len) != xml_len) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("failed to read domain XML"));
        return -1;
    }

    if (cookie_len > 0) {
        data->cookie = g_new0(char, cookie_len);

        if (saferead(fd, data->cookie, cookie_len) != cookie_len) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("failed to read cookie"));
            return -1;
        }
    }

    /* Create a domain from this XML */
    if (!(def = virDomainDefParseString(data->xml, driver->xmlopt, qemuCaps,
                                        VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                        VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE)))
        return -1;

    *ret_def = g_steal_pointer(&def);
    *ret_data = g_steal_pointer(&data);

    ret = fd;
    fd = -1;

    return ret;
}

int
qemuSaveImageStartVM(virConnectPtr conn,
                     virQEMUDriver *driver,
                     virDomainObj *vm,
                     int *fd,
                     virQEMUSaveData *data,
                     const char *path,
                     bool start_paused,
                     bool reset_nvram,
                     virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    int ret = -1;
    bool started = false;
    virObjectEvent *event;
    VIR_AUTOCLOSE intermediatefd = -1;
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *errbuf = NULL;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    virQEMUSaveHeader *header = &data->header;
    g_autoptr(qemuDomainSaveCookie) cookie = NULL;
    int rc = 0;
    unsigned int start_flags = VIR_QEMU_PROCESS_START_PAUSED |
        VIR_QEMU_PROCESS_START_GEN_VMID;

    if (reset_nvram)
        start_flags |= VIR_QEMU_PROCESS_START_RESET_NVRAM;

    if (virSaveCookieParseString(data->cookie, (virObject **)&cookie,
                                 virDomainXMLOptionGetSaveCookie(driver->xmlopt)) < 0)
        goto cleanup;

    if ((header->version == 2) &&
        (header->compressed != QEMU_SAVE_FORMAT_RAW)) {
        if (!(cmd = qemuSaveImageGetCompressionCommand(header->compressed)))
            goto cleanup;

        intermediatefd = *fd;
        *fd = -1;

        virCommandSetInputFD(cmd, intermediatefd);
        virCommandSetOutputFD(cmd, fd);
        virCommandSetErrorBuffer(cmd, &errbuf);
        virCommandDoAsyncIO(cmd);

        if (virCommandRunAsync(cmd, NULL) < 0) {
            *fd = intermediatefd;
            intermediatefd = -1;
            goto cleanup;
        }
    }

    /* No cookie means libvirt which saved the domain was too old to mess up
     * the CPU definitions.
     */
    if (cookie &&
        qemuDomainFixupCPUs(vm, &cookie->cpu) < 0)
        goto cleanup;

    if (cookie && !cookie->slirpHelper)
        priv->disableSlirp = true;

    if (qemuProcessStart(conn, driver, vm, cookie ? cookie->cpu : NULL,
                         asyncJob, "stdio", *fd, path, NULL,
                         VIR_NETDEV_VPORT_PROFILE_OP_RESTORE,
                         start_flags) == 0)
        started = true;

    if (intermediatefd != -1) {
        virErrorPtr orig_err = NULL;

        if (!started) {
            /* if there was an error setting up qemu, the intermediate
             * process will wait forever to write to stdout, so we
             * must manually kill it and ignore any error related to
             * the process
             */
            virErrorPreserveLast(&orig_err);
            VIR_FORCE_CLOSE(intermediatefd);
            VIR_FORCE_CLOSE(*fd);
        }

        rc = virCommandWait(cmd, NULL);
        VIR_DEBUG("Decompression binary stderr: %s", NULLSTR(errbuf));
        virErrorRestore(&orig_err);
    }
    if (VIR_CLOSE(*fd) < 0) {
        virReportSystemError(errno, _("cannot close file: %s"), path);
        rc = -1;
    }

    virDomainAuditStart(vm, "restored", started);
    if (!started || rc < 0)
        goto cleanup;

    /* qemuProcessStart doesn't unset the qemu error reporting infrastructure
     * in case of migration (which is used in this case) so we need to reset it
     * so that the handle to virtlogd is not held open unnecessarily */
    qemuMonitorSetDomainLog(qemuDomainGetMonitor(vm), NULL, NULL, NULL);

    event = virDomainEventLifecycleNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_RESTORED);
    virObjectEventStateQueue(driver->domainEventState, event);

    if (qemuProcessRefreshState(driver, vm, asyncJob) < 0)
        goto cleanup;

    /* If it was running before, resume it now unless caller requested pause. */
    if (header->was_running && !start_paused) {
        if (qemuProcessStartCPUs(driver, vm,
                                 VIR_DOMAIN_RUNNING_RESTORED,
                                 asyncJob) < 0) {
            if (virGetLastErrorCode() == VIR_ERR_OK)
                virReportError(VIR_ERR_OPERATION_FAILED,
                               "%s", _("failed to resume domain"));
            goto cleanup;
        }
        if (virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0) {
            VIR_WARN("Failed to save status on vm %s", vm->def->name);
            goto cleanup;
        }
    } else {
        int detail = (start_paused ? VIR_DOMAIN_EVENT_SUSPENDED_PAUSED :
                      VIR_DOMAIN_EVENT_SUSPENDED_RESTORED);
        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         detail);
        virObjectEventStateQueue(driver->domainEventState, event);
    }

    ret = 0;

 cleanup:
    if (ret < 0 && started) {
        qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED,
                        asyncJob, VIR_QEMU_PROCESS_STOP_MIGRATED);
    }
    return ret;
}


/**
 * qemuSaveImageUpdateDef:
 * @driver: qemu driver data
 * @def: def of the domain from the save image
 * @newxml: user provided replacement XML
 *
 * Returns the new domain definition in case @newxml is ABI compatible with the
 * guest.
 */
virDomainDef *
qemuSaveImageUpdateDef(virQEMUDriver *driver,
                       virDomainDef *def,
                       const char *newxml)
{
    g_autoptr(virDomainDef) newdef_migr = NULL;
    g_autoptr(virDomainDef) newdef = NULL;

    if (!(newdef = virDomainDefParseString(newxml, driver->xmlopt, NULL,
                                           VIR_DOMAIN_DEF_PARSE_INACTIVE)))
        return NULL;

    if (!(newdef_migr = qemuDomainDefCopy(driver, NULL,
                                          newdef,
                                          QEMU_DOMAIN_FORMAT_LIVE_FLAGS |
                                          VIR_DOMAIN_XML_MIGRATABLE)))
        return NULL;

    if (!virDomainDefCheckABIStability(def, newdef_migr, driver->xmlopt)) {
        virErrorPtr save_err;

        virErrorPreserveLast(&save_err);

        /* Due to a bug in older version of external snapshot creation
         * code, the XML saved in the save image was not a migratable
         * XML. To ensure backwards compatibility with the change of the
         * saved XML type, we need to check the ABI compatibility against
         * the user provided XML if the check against the migratable XML
         * fails. Snapshots created prior to v1.1.3 have this issue. */
        if (!virDomainDefCheckABIStability(def, newdef, driver->xmlopt)) {
            virErrorRestore(&save_err);
            return NULL;
        }
        virFreeError(save_err);

        /* use the user provided XML */
        return g_steal_pointer(&newdef);
    }

    return g_steal_pointer(&newdef_migr);
}
