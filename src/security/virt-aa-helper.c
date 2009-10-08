
/*
 * virt-aa-helper: wrapper program used by AppArmor security driver.
 * Copyright (C) 2009 Canonical Ltd.
 *
 * See COPYING.LIB for the License of this software
 *
 * Author:
 *   Jamie Strandboge <jamie@canonical.com>
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <sys/utsname.h>

#include "internal.h"
#include "buf.h"
#include "util.h"
#include "memory.h"

#include "security_driver.h"
#include "security_apparmor.h"
#include "domain_conf.h"
#include "xml.h"
#include "uuid.h"
#include "hostusb.h"
#include "pci.h"

static char *progname;

typedef struct {
    char uuid[PROFILE_NAME_SIZE];       /* UUID of vm */
    bool dryrun;                /* dry run */
    char cmd;                   /* 'c'   create
                                 * 'a'   add (load)
                                 * 'r'   replace
                                 * 'R'   remove */
    char *files;                /* list of files */
    virDomainDefPtr def;        /* VM definition */
    virCapsPtr caps;            /* VM capabilities */
    char *hvm;                  /* type of hypervisor (eg hvm, xen) */
    int bits;                   /* bits in the guest */
    char *newdisk;              /* newly added disk */
} vahControl;

static int
vahDeinit(vahControl * ctl)
{
    if (ctl == NULL)
        return -1;

    VIR_FREE(ctl->def);
    if (ctl->caps)
        virCapabilitiesFree(ctl->caps);
    free(ctl->files);
    free(ctl->hvm);
    free(ctl->newdisk);

    return 0;
}

/*
 * Print usage
 */
static void
vah_usage(void)
{
    fprintf(stdout, "\n%s [options] [< def.xml]\n\n"
            "  Options:\n"
            "    -a | --add                     load profile\n"
            "    -c | --create                  create profile from template\n"
            "    -D | --delete                  unload and delete profile\n"
            "    -r | --replace                 reload profile\n"
            "    -R | --remove                  unload profile\n"
            "    -h | --help                    this help\n"
            "    -u | --uuid <uuid>             uuid (profile name)\n"
            "    -H | --hvm <hvm>               hypervisor type\n"
            "    -b | --bits <bits>             architecture bits\n"
            "\n", progname);

    fprintf(stdout, "This command is intended to be used by libvirtd "
            "and not used directly.\n");
    return;
}

static void
vah_error(vahControl * ctl, int doexit, const char *str)
{
    fprintf(stderr, _("%s: error: %s\n"), progname, str);

    if (doexit) {
        if (ctl != NULL)
            vahDeinit(ctl);
        exit(EXIT_FAILURE);
    }
}

static void
vah_warning(const char *str)
{
    fprintf(stderr, _("%s: warning: %s\n"), progname, str);
}

static void
vah_info(const char *str)
{
    fprintf(stderr, _("%s:\n%s\n"), progname, str);
}

/*
 * Replace @oldstr in @orig with @repstr
 * @len is number of bytes allocated for @orig. Assumes @orig, @oldstr and
 * @repstr are null terminated
 */
static int
replace_string(char *orig, const size_t len, const char *oldstr,
               const char *repstr)
{
    int idx;
    char *pos = NULL;
    char *tmp = NULL;

    if ((pos = strstr(orig, oldstr)) == NULL) {
        vah_error(NULL, 0, "could not find replacement string");
        return -1;
    }

    if (VIR_ALLOC_N(tmp, len) < 0) {
        vah_error(NULL, 0, "could not allocate memory for string");
        return -1;
    }
    tmp[0] = '\0';

    idx = abs(pos - orig);

    /* copy everything up to oldstr */
    strncat(tmp, orig, idx);

    /* add the replacement string */
    if (strlen(tmp) + strlen(repstr) > len - 1) {
        vah_error(NULL, 0, "not enough space in target buffer");
        VIR_FREE(tmp);
        return -1;
    }
    strcat(tmp, repstr);

    /* add everything after oldstr */
    if (strlen(tmp) + strlen(orig) - (idx + strlen(oldstr)) > len - 1) {
        vah_error(NULL, 0, "not enough space in target buffer");
        VIR_FREE(tmp);
        return -1;
    }
    strncat(tmp, orig + idx + strlen(oldstr),
            strlen(orig) - (idx + strlen(oldstr)));

    if (virStrcpy(orig, tmp, len) == NULL) {
        vah_error(NULL, 0, "error replacing string");
        VIR_FREE(tmp);
        return -1;
    }
    VIR_FREE(tmp);

    return 0;
}

/*
 * run an apparmor_parser command
 */
static int
parserCommand(const char *profile_name, const char cmd)
{
    char flag[3];
    char profile[PATH_MAX];

    if (strchr("arR", cmd) == NULL) {
        vah_error(NULL, 0, "invalid flag");
        return -1;
    }

    snprintf(flag, 3, "-%c", cmd);

    if (snprintf(profile, PATH_MAX, "%s/%s",
                 APPARMOR_DIR "/libvirt", profile_name) > PATH_MAX - 1) {
        vah_error(NULL, 0, "profile name exceeds maximum length");
        return -1;
    }

    if (!virFileExists(profile)) {
        vah_error(NULL, 0, "profile does not exist");
        return -1;
    } else {
        const char * const argv[] = {
            "/sbin/apparmor_parser", flag, profile, NULL
        };
        if (virRun(NULL, argv, NULL) != 0) {
            vah_error(NULL, 0, "failed to run apparmor_parser");
            return -1;
        }
    }

    return 0;
}

/*
 * Update the dynamic files
 */
static int
update_include_file(const char *include_file, const char *included_files)
{
    int rc = -1;
    int plen;
    int fd;
    char *pcontent = NULL;
    const char *warning =
         "# DO NOT EDIT THIS FILE DIRECTLY. IT IS MANAGED BY LIBVIRT.\n";

    if (virAsprintf(&pcontent, "%s%s", warning, included_files) == -1) {
        vah_error(NULL, 0, "could not allocate memory for profile");
        return rc;
    }

    plen = strlen(pcontent);
    if (plen > MAX_FILE_LEN) {
        vah_error(NULL, 0, "invalid length for new profile");
        goto clean;
    }

    /* only update the disk profile if it is different */
    if (virFileExists(include_file)) {
        char *existing = NULL;
        int flen = virFileReadAll(include_file, MAX_FILE_LEN, &existing);
        if (flen < 0)
            goto clean;

        if (flen == plen) {
            if (STREQLEN(existing, pcontent, plen)) {
                rc = 0;
                VIR_FREE(existing);
                goto clean;
            }
        }
        VIR_FREE(existing);
    }

    /* write the file */
    if ((fd = open(include_file, O_CREAT | O_TRUNC | O_WRONLY, 0644)) == -1) {
        vah_error(NULL, 0, "failed to create include file");
        goto clean;
    }

    if (safewrite(fd, pcontent, plen) < 0) { /* don't write the '\0' */
        close(fd);
        vah_error(NULL, 0, "failed to write to profile");
        goto clean;
    }

    if (close(fd) != 0) {
        vah_error(NULL, 0, "failed to close or write to profile");
        goto clean;
    }
    rc = 0;

  clean:
    VIR_FREE(pcontent);

    return rc;
}

/*
 * Create a profile based on a template
 */
static int
create_profile(const char *profile, const char *profile_name,
               const char *profile_files)
{
    char template[PATH_MAX];
    char *tcontent = NULL;
    char *pcontent = NULL;
    char *replace_name = NULL;
    char *replace_files = NULL;
    const char *template_name = "\nprofile LIBVIRT_TEMPLATE";
    const char *template_end = "\n}";
    int tlen, plen;
    int fd;
    int rc = -1;

    if (virFileExists(profile)) {
        vah_error(NULL, 0, "profile exists");
        goto end;
    }

    if (snprintf(template, PATH_MAX, "%s/TEMPLATE",
                 APPARMOR_DIR "/libvirt") > PATH_MAX - 1) {
        vah_error(NULL, 0, "template name exceeds maximum length");
        goto end;
    }

    if (!virFileExists(template)) {
        vah_error(NULL, 0, "template does not exist");
        goto end;
    }

    if ((tlen = virFileReadAll(template, MAX_FILE_LEN, &tcontent)) < 0) {
        vah_error(NULL, 0, "failed to read AppArmor template");
        goto end;
    }

    if (strstr(tcontent, template_name) == NULL) {
        vah_error(NULL, 0, "no replacement string in template");
        goto clean_tcontent;
    }

    if (strstr(tcontent, template_end) == NULL) {
        vah_error(NULL, 0, "no replacement string in template");
        goto clean_tcontent;
    }

    /* '\nprofile <profile_name>\0' */
    if (virAsprintf(&replace_name, "\nprofile %s", profile_name) == -1) {
        vah_error(NULL, 0, "could not allocate memory for profile name");
        goto clean_tcontent;
    }

    /* '\n<profile_files>\n}\0' */
    if (virAsprintf(&replace_files, "\n%s\n}", profile_files) == -1) {
        vah_error(NULL, 0, "could not allocate memory for profile files");
        VIR_FREE(replace_name);
        goto clean_tcontent;
    }

    plen = tlen + strlen(replace_name) - strlen(template_name) +
           strlen(replace_files) - strlen(template_end) + 1;
    if (plen > MAX_FILE_LEN || plen < tlen) {
        vah_error(NULL, 0, "invalid length for new profile");
        goto clean_replace;
    }

    if (VIR_ALLOC_N(pcontent, plen) < 0) {
        vah_error(NULL, 0, "could not allocate memory for profile");
        goto clean_replace;
    }
    pcontent[0] = '\0';
    strcpy(pcontent, tcontent);

    if (replace_string(pcontent, plen, template_name, replace_name) < 0)
        goto clean_all;

    if (replace_string(pcontent, plen, template_end, replace_files) < 0)
        goto clean_all;

    /* write the file */
    if ((fd = open(profile, O_CREAT | O_EXCL | O_WRONLY, 0644)) == -1) {
        vah_error(NULL, 0, "failed to create profile");
        goto clean_all;
    }

    if (safewrite(fd, pcontent, plen - 1) < 0) { /* don't write the '\0' */
        close(fd);
        vah_error(NULL, 0, "failed to write to profile");
        goto clean_all;
    }

    if (close(fd) != 0) {
        vah_error(NULL, 0, "failed to close or write to profile");
        goto clean_all;
    }
    rc = 0;

  clean_all:
    VIR_FREE(pcontent);
  clean_replace:
    VIR_FREE(replace_name);
    VIR_FREE(replace_files);
  clean_tcontent:
    VIR_FREE(tcontent);
  end:
    return rc;
}

/*
 * Load an existing profile
 */
static int
parserLoad(const char *profile_name)
{
    return parserCommand(profile_name, 'a');
}

/*
 * Remove an existing profile
 */
static int
parserRemove(const char *profile_name)
{
    return parserCommand(profile_name, 'R');
}

/*
 * Replace an existing profile
 */
static int
parserReplace(const char *profile_name)
{
    return parserCommand(profile_name, 'r');
}

static int
valid_uuid(const char *uuid)
{
    unsigned char rawuuid[VIR_UUID_BUFLEN];

    if (strlen(uuid) != PROFILE_NAME_SIZE - 1)
        return -1;

    if (!STRPREFIX(uuid, AA_PREFIX))
        return -1;

    if (virUUIDParse(uuid + strlen(AA_PREFIX), rawuuid) < 0)
        return -1;

    return 0;
}

static int
valid_name(const char *name)
{
    /* just try to filter out any dangerous characters in the name that can be
     * used to subvert the profile */
    const char *bad = " /[]*";

    if (strlen(name) == 0 || strlen(name) > PATH_MAX - 1)
        return -1;

    if (strcspn(name, bad) != strlen(name))
        return -1;

    return 0;
}

/* see if one of the strings in arr starts with str */
static int
array_starts_with(const char *str, const char * const *arr, const long size)
{
    int i;
    for (i = 0; i < size; i++) {
        if (strlen(str) < strlen(arr[i]))
            continue;

        if (STRPREFIX(str, arr[i]))
            return 0;
    }
    return 1;
}

/*
 * Don't allow access to special files or restricted paths such as /bin, /sbin,
 * /usr/bin, /usr/sbin and /etc. This is in an effort to prevent read/write
 * access to system files which could be used to elevate privileges. This is a
 * safety measure in case libvirtd is under a restrictive profile and is
 * subverted and trying to escape confinement.
 *
 * Note that we cannot exclude block devices because they are valid devices.
 * The TEMPLATE file can be adjusted to explicitly disallow these if needed.
 *
 * RETURN: -1 on error, 0 if ok, 1 if blocked
 */
static int
valid_path(const char *path, const bool readonly)
{
    struct stat sb;
    int npaths;
    const char * const restricted[] = {
        "/bin/",
        "/etc/",
        "/lib",
        "/lost+found/",
        "/proc/",
        "/sbin/",
        "/selinux/",
        "/sys/",
        "/usr/bin/",
        "/usr/lib",
        "/usr/sbin/",
        "/usr/share/",
        "/usr/local/bin/",
        "/usr/local/etc/",
        "/usr/local/lib",
        "/usr/local/sbin/"
    };
    /* these paths are ok for readonly, but not read/write */
    const char * const restricted_rw[] = {
        "/boot/",
        "/vmlinuz",
        "/initrd",
        "/initrd.img"
    };

    if (path == NULL || strlen(path) > PATH_MAX - 1) {
        vah_error(NULL, 0, "bad pathname");
        return -1;
    }

    /* Don't allow double quotes, since we use them to quote the filename
     * and this will confuse the apparmor parser.
     */
    if (strchr(path, '"') != NULL)
        return 1;

    if (!virFileExists(path))
        vah_warning("path does not exist, skipping file type checks");
    else {
        if (stat(path, &sb) == -1)
            return -1;

        switch (sb.st_mode & S_IFMT) {
            case S_IFDIR:
                return 1;
                break;
            case S_IFIFO:
                return 1;
                break;
            case S_IFSOCK:
                return 1;
                break;
            default:
                break;
        }
    }

    npaths = sizeof(restricted)/sizeof *(restricted);
    if (array_starts_with(path, restricted, npaths) == 0)
        return 1;

    npaths = sizeof(restricted_rw)/sizeof *(restricted_rw);
    if (!readonly) {
        if (array_starts_with(path, restricted_rw, npaths) == 0)
            return 1;
    }

    return 0;
}

static int
get_definition(vahControl * ctl, const char *xmlStr)
{
    int rc = -1;
    struct utsname utsname;
    virCapsGuestPtr guest;  /* this is freed when caps is freed */

    /*
     * mock up some capabilities. We don't currently use these explicitly,
     * but need them for virDomainDefParseString().
     */

    /* Really, this never fails - look at the man-page. */
    uname (&utsname);

    /* set some defaults if not specified */
    if (!ctl->bits)
        ctl->bits = 32;
    if (!ctl->hvm)
        ctl->hvm = strdup("hvm");

    if ((ctl->caps = virCapabilitiesNew(utsname.machine, 1, 1)) == NULL) {
        vah_error(ctl, 0, "could not allocate memory");
        goto exit;
    }

    if ((guest = virCapabilitiesAddGuest(ctl->caps,
                                         ctl->hvm,
                                         utsname.machine,
                                         ctl->bits,
                                         NULL,
                                         NULL,
                                         0,
                                         NULL)) == NULL) {
        vah_error(ctl, 0, "could not allocate memory");
        goto exit;
    }

    ctl->def = virDomainDefParseString(NULL, ctl->caps, xmlStr, 0);
    if (ctl->def == NULL) {
        vah_error(ctl, 0, "could not parse XML");
        goto exit;
    }

    if (!ctl->def->name) {
        vah_error(ctl, 0, "could not find name in XML");
        goto exit;
    }

    if (valid_name(ctl->def->name) != 0) {
        vah_error(ctl, 0, "bad name");
        goto exit;
    }

    rc = 0;

  exit:
    return rc;
}

static int
vah_add_file(virBufferPtr buf, const char *path, const char *perms)
{
    char *tmp = NULL;
    int rc = -1;
    bool readonly = true;

    if (path == NULL)
        return rc;

    if (virFileExists(path)) {
        if ((tmp = realpath(path, NULL)) == NULL) {
            vah_error(NULL, 0, path);
            vah_error(NULL, 0, "  could not find realpath for disk");
            return rc;
        }
    } else
        if ((tmp = strdup(path)) == NULL)
            return rc;

    if (strchr(perms, 'w') != NULL)
        readonly = false;

    rc = valid_path(tmp, readonly);
    if (rc != 0) {
        if (rc > 0) {
            vah_error(NULL, 0, path);
            vah_error(NULL, 0, "  skipped restricted file");
        }
        goto clean;
    }

    virBufferVSprintf(buf, "  \"%s\" %s,\n", tmp, perms);

  clean:
    free(tmp);

    return rc;
}

static int
file_iterate_cb(virConnectPtr conn ATTRIBUTE_UNUSED,
                usbDevice *dev ATTRIBUTE_UNUSED,
                const char *file, void *opaque)
{
    virBufferPtr buf = opaque;
    return vah_add_file(buf, file, "rw");
}

static int
get_files(vahControl * ctl)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    int rc = -1;
    int i;
    char *uuid;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    /* verify uuid is same as what we were given on the command line */
    virUUIDFormat(ctl->def->uuid, uuidstr);
    if (virAsprintf(&uuid, "%s%s", AA_PREFIX, uuidstr) == -1) {
        vah_error(ctl, 0, "could not allocate memory");
        return rc;
    }

    if (STRNEQ(uuid, ctl->uuid)) {
        vah_error(ctl, 0, "given uuid does not match XML uuid");
        goto clean;
    }

    for (i = 0; i < ctl->def->ndisks; i++)
        if (ctl->def->disks[i] && ctl->def->disks[i]->src) {
            int ret;

            if (ctl->def->disks[i]->readonly)
                ret = vah_add_file(&buf, ctl->def->disks[i]->src, "r");
            else
                ret = vah_add_file(&buf, ctl->def->disks[i]->src, "rw");

            if (ret != 0)
                goto clean;
        }

    for (i = 0; i < ctl->def->nserials; i++)
        if (ctl->def->serials[i] && ctl->def->serials[i]->data.file.path)
            if (vah_add_file(&buf,
                             ctl->def->serials[i]->data.file.path, "w") != 0)
                goto clean;

    if (ctl->def->console && ctl->def->console->data.file.path)
        if (vah_add_file(&buf, ctl->def->console->data.file.path, "w") != 0)
            goto clean;

    if (ctl->def->os.kernel && ctl->def->os.kernel)
        if (vah_add_file(&buf, ctl->def->os.kernel, "r") != 0)
            goto clean;

    if (ctl->def->os.initrd && ctl->def->os.initrd)
        if (vah_add_file(&buf, ctl->def->os.initrd, "r") != 0)
            goto clean;

    if (ctl->def->os.loader && ctl->def->os.loader)
        if (vah_add_file(&buf, ctl->def->os.loader, "r") != 0)
            goto clean;

    for (i = 0; i < ctl->def->nhostdevs; i++)
        if (ctl->def->hostdevs[i]) {
            virDomainHostdevDefPtr dev = ctl->def->hostdevs[i];
            switch (dev->source.subsys.type) {
            case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB: {
                if (dev->source.subsys.u.usb.bus &&
                    dev->source.subsys.u.usb.device) {
                    usbDevice *usb = usbGetDevice(NULL,
                               dev->source.subsys.u.usb.bus,
                               dev->source.subsys.u.usb.device);
                    if (usb == NULL)
                        continue;
                    rc = usbDeviceFileIterate(NULL, usb,
                                              file_iterate_cb, &buf);
                    usbFreeDevice(NULL, usb);
                    if (rc != 0)
                        goto clean;
                    else {
                        /* TODO: deal with product/vendor better */
                        rc = 0;
                    }
                }
                break;
            }
/* TODO: update so files in /sys are readonly
            case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI: {
                pciDevice *pci = pciGetDevice(NULL,
                           dev->source.subsys.u.pci.domain,
                           dev->source.subsys.u.pci.bus,
                           dev->source.subsys.u.pci.slot,
                           dev->source.subsys.u.pci.function);

                if (pci == NULL)
                    continue;

                rc = pciDeviceFileIterate(NULL, pci, file_iterate_cb, &buf);
                pciFreeDevice(NULL, pci);

                break;
            }
*/
            default:
                rc = 0;
                break;
            } /* switch */
        }

    if (ctl->newdisk)
        if (vah_add_file(&buf, ctl->newdisk, "rw") != 0)
            goto clean;

    if (virBufferError(&buf)) {
         vah_error(NULL, 0, "failed to allocate file buffer");
         goto clean;
    }

    rc = 0;
    ctl->files = virBufferContentAndReset(&buf);

  clean:
    VIR_FREE(uuid);
    return rc;
}

static int
vahParseArgv(vahControl * ctl, int argc, char **argv)
{
    int arg, idx = 0;
    struct option opt[] = {
        {"add", 0, 0, 'a'},
        {"create", 0, 0, 'c'},
        {"dryrun", 0, 0, 'd'},
        {"delete", 0, 0, 'D'},
        {"add-file", 0, 0, 'f'},
        {"help", 0, 0, 'h'},
        {"replace", 0, 0, 'r'},
        {"remove", 0, 0, 'R'},
        {"uuid", 1, 0, 'u'},
        {"hvm", 1, 0, 'H'},
        {"bits", 1, 0, 'b'},
        {0, 0, 0, 0}
    };
    int bits;

    while ((arg = getopt_long(argc, argv, "acdDhrRH:b:u:f:", opt,
            &idx)) != -1) {
        switch (arg) {
            case 'a':
                ctl->cmd = 'a';
                break;
            case 'b':
                bits = atoi(optarg);
                if (bits == 32 || bits == 64)
                    ctl->bits = bits;
                else
                    vah_error(ctl, 1, "invalid bits (should be 32 or 64)");
                break;
            case 'c':
                ctl->cmd = 'c';
                break;
            case 'd':
                ctl->dryrun = true;
                break;
            case 'D':
                ctl->cmd = 'D';
                break;
            case 'f':
                if ((ctl->newdisk = strdup(optarg)) == NULL)
                    vah_error(ctl, 1, "could not allocate memory for disk");
                break;
            case 'h':
                vah_usage();
                exit(EXIT_SUCCESS);
                break;
            case 'H':
                if ((ctl->hvm = strdup(optarg)) == NULL)
                    vah_error(ctl, 1, "could not allocate memory for hvm");
                break;
            case 'r':
                ctl->cmd = 'r';
                break;
            case 'R':
                ctl->cmd = 'R';
                break;
            case 'u':
                if (strlen(optarg) > PROFILE_NAME_SIZE - 1)
                    vah_error(ctl, 1, "invalid UUID");
                if (virStrcpy((char *) ctl->uuid, optarg,
                    PROFILE_NAME_SIZE) == NULL)
                    vah_error(ctl, 1, "error copying UUID");
                break;
            default:
                vah_error(ctl, 1, "unsupported option");
                break;
        }
    }
    if (strchr("acDrR", ctl->cmd) == NULL)
        vah_error(ctl, 1, "bad command");

    if (valid_uuid(ctl->uuid) != 0)
        vah_error(ctl, 1, "invalid UUID");

    if (!ctl->cmd) {
        vah_usage();
        exit(EXIT_FAILURE);
    }

    if (ctl->cmd == 'c' || ctl->cmd == 'r') {
        char *xmlStr = NULL;
        if (virFileReadLimFD(STDIN_FILENO, MAX_FILE_LEN, &xmlStr) < 0)
            vah_error(ctl, 1, "could not read xml file");

        if (get_definition(ctl, xmlStr) != 0 || ctl->def == NULL) {
            VIR_FREE(xmlStr);
            vah_error(ctl, 1, "could not get VM definition");
        }
        VIR_FREE(xmlStr);

        if (get_files(ctl) != 0)
            vah_error(ctl, 1, "invalid VM definition");
    }
    return 0;
}


/*
 * virt-aa-helper -c -u UUID < file.xml
 * virt-aa-helper -r -u UUID [-f <file>] < file.xml
 * virt-aa-helper -a -u UUID
 * virt-aa-helper -R -u UUID
 * virt-aa-helper -D -u UUID
 */
int
main(int argc, char **argv)
{
    vahControl _ctl, *ctl = &_ctl;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    int rc = -1;
    char profile[PATH_MAX];
    char include_file[PATH_MAX];

    /* clear the environment */
    environ = NULL;
    if (setenv("PATH", "/sbin:/usr/sbin", 1) != 0) {
        vah_error(ctl, 1, "could not set PATH");
    }
    if (setenv("IFS", " \t\n", 1) != 0) {
        vah_error(ctl, 1, "could not set IFS");
    }

    if (!(progname = strrchr(argv[0], '/')))
        progname = argv[0];
    else
        progname++;

    memset(ctl, 0, sizeof(vahControl));

    if (vahParseArgv(ctl, argc, argv) != 0)
        vah_error(ctl, 1, "could not parse arguments");

    if (snprintf(profile, PATH_MAX, "%s/%s",
                 APPARMOR_DIR "/libvirt", ctl->uuid) > PATH_MAX - 1)
        vah_error(ctl, 1, "profile name exceeds maximum length");

    if (snprintf(include_file, PATH_MAX, "%s/%s.files",
                 APPARMOR_DIR "/libvirt", ctl->uuid) > PATH_MAX - 1)
        vah_error(ctl, 1, "disk profile name exceeds maximum length");

    if (ctl->cmd == 'a')
        rc = parserLoad(ctl->uuid);
    else if (ctl->cmd == 'R' || ctl->cmd == 'D') {
        rc = parserRemove(ctl->uuid);
        if (ctl->cmd == 'D') {
            unlink(include_file);
            unlink(profile);
        }
    } else if (ctl->cmd == 'c' || ctl->cmd == 'r') {
        char *included_files = NULL;

        if (ctl->cmd == 'c' && virFileExists(profile))
            vah_error(ctl, 1, "profile exists");

        virBufferVSprintf(&buf, "  \"%s/log/libvirt/**/%s.log\" w,\n",
                          LOCAL_STATE_DIR, ctl->def->name);
        virBufferVSprintf(&buf, "  \"%s/lib/libvirt/**/%s.monitor\" rw,\n",
                          LOCAL_STATE_DIR, ctl->def->name);
        virBufferVSprintf(&buf, "  \"%s/run/libvirt/**/%s.pid\" rwk,\n",
                          LOCAL_STATE_DIR, ctl->def->name);
        if (ctl->files)
            virBufferVSprintf(&buf, "%s", ctl->files);

        if (virBufferError(&buf))
            vah_error(ctl, 1, "failed to allocate buffer");

        included_files = virBufferContentAndReset(&buf);

        /* (re)create the include file using included_files */
        if (ctl->dryrun) {
            vah_info(include_file);
            vah_info(included_files);
            rc = 0;
        } else if ((rc = update_include_file(include_file,
                                             included_files)) != 0)
            goto clean;


        /* create the profile from TEMPLATE */
        if (ctl->cmd == 'c') {
            char *tmp = NULL;
            if (virAsprintf(&tmp, "  #include <libvirt/%s.files>\n",
                            ctl->uuid) == -1) {
                vah_error(ctl, 0, "could not allocate memory");
                goto clean;
            }

            if (ctl->dryrun) {
                vah_info(profile);
                vah_info(ctl->uuid);
                vah_info(tmp);
                rc = 0;
            } else if ((rc = create_profile(profile, ctl->uuid, tmp)) != 0) {
                vah_error(ctl, 0, "could not create profile");
                unlink(include_file);
            }
            VIR_FREE(tmp);
        }

        if (rc == 0 && !ctl->dryrun) {
            if (ctl->cmd == 'c')
                rc = parserLoad(ctl->uuid);
            else
                rc = parserReplace(ctl->uuid);

            /* cleanup */
            if (rc != 0) {
                unlink(include_file);
                if (ctl->cmd == 'c')
                    unlink(profile);
            }
        }
      clean:
        VIR_FREE(included_files);
    }

    vahDeinit(ctl);
    exit(rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
