/*
 * virt-aa-helper: wrapper program used by AppArmor security driver.
 *
 * Copyright (C) 2010-2014 Red Hat, Inc.
 * Copyright (C) 2009-2011 Canonical Ltd.
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

#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/utsname.h>

#include "internal.h"
#include "virbuffer.h"
#include "viralloc.h"
#include "vircommand.h"
#include "virlog.h"
#include "driver.h"

#include "security_driver.h"
#include "security_apparmor.h"
#include "storage_source.h"
#include "domain_conf.h"
#include "virxml.h"
#include "viruuid.h"
#include "virusb.h"
#include "virutil.h"
#include "virpci.h"
#include "virfile.h"
#include "configmake.h"
#include "virrandom.h"
#include "virstring.h"
#include "virgettext.h"
#include "virhostdev.h"

#define VIR_FROM_THIS VIR_FROM_SECURITY

static char *progname;

typedef struct {
    char uuid[PROFILE_NAME_SIZE];       /* UUID of vm */
    bool dryrun;                /* dry run */
    char cmd;                   /* 'c'   create
                                 * 'a'   add (load)
                                 * 'r'   replace
                                 * 'R'   remove */
    char *files;                /* list of files */
    virDomainDef *def;        /* VM definition */
    virCaps *caps;            /* VM capabilities */
    virDomainXMLOption *xmlopt; /* XML parser data */
    char *virtType;                  /* type of hypervisor (eg qemu, xen, lxc) */
    char *os;                   /* type of os (eg hvm, xen, exe) */
    virArch arch;               /* machine architecture */
    char *newfile;              /* newly added file */
    bool append;                /* append to .files instead of rewrite */
} vahControl;

static int
vahDeinit(vahControl * ctl)
{
    if (ctl == NULL)
        return -1;

    virDomainDefFree(ctl->def);
    virObjectUnref(ctl->caps);
    virObjectUnref(ctl->xmlopt);
    VIR_FREE(ctl->files);
    VIR_FREE(ctl->virtType);
    VIR_FREE(ctl->os);
    VIR_FREE(ctl->newfile);

    return 0;
}

/*
 * Print usage
 */
static void
vah_usage(void)
{
    printf(_("\n%1$s mode [options] [extra file] [< def.xml]\n\n"
            "  Modes:\n"
            "    -a | --add                     load profile\n"
            "    -c | --create                  create profile from template\n"
            "    -D | --delete                  unload profile and delete generated rules\n"
            "    -r | --replace                 reload profile\n"
            "    -R | --remove                  unload profile\n"
            "  Options:\n"
            "    -d | --dryrun                  dry run\n"
            "    -u | --uuid <uuid>             uuid (profile name)\n"
            "    -h | --help                    this help\n"
            "  Extra File:\n"
            "    -f | --add-file <file>         add file to a profile generated from XML\n"
            "    -F | --append-file <file>      append file to an existing profile\n"
            "\n"), progname);

    puts(_("This command is intended to be used by libvirtd and not used directly.\n"));
    return;
}

static void
vah_error(vahControl * ctl, int doexit, const char *str)
{
    fprintf(stderr, _("%1$s: error: %2$s%3$c"), progname, str, '\n');

    if (doexit) {
        if (ctl != NULL)
            vahDeinit(ctl);
        exit(EXIT_FAILURE);
    }
}

static void
vah_warning(const char *str)
{
    fprintf(stderr, _("%1$s: warning: %2$s%3$c"), progname, str, '\n');
}

static void
vah_info(const char *str)
{
    fprintf(stderr, _("%1$s:\n%2$s%3$c"), progname, str, '\n');
}

/*
 * run an apparmor_parser command
 */
static int
parserCommand(const char *profile_name, const char cmd)
{
    char flag[3];
    g_autofree char *profile = NULL;
    int status;
    int ret;

    if (strchr("arR", cmd) == NULL) {
        vah_error(NULL, 0, _("invalid flag"));
        return -1;
    }

    g_snprintf(flag, 3, "-%c", cmd);

    profile = g_strdup_printf("%s/%s", APPARMOR_DIR "/libvirt", profile_name);

    if (!virFileExists(profile)) {
        vah_error(NULL, 0, _("profile does not exist"));
        return -1;
    } else {
        const char * const argv[] = {
            "/sbin/apparmor_parser", flag, profile, NULL
        };
        g_autoptr(virCommand) command = virCommandNewArgs(argv);

        virCommandRawStatus(command);
        if ((ret = virCommandRun(command, &status)) != 0 ||
            (WIFEXITED(status) && WEXITSTATUS(status) != 0)) {
            if (ret != 0) {
                vah_error(NULL, 0, _("failed to run apparmor_parser"));
                return -1;
            } else if (cmd == 'R' && WIFEXITED(status) &&
                       WEXITSTATUS(status) == 234) {
                vah_warning(_("unable to unload already unloaded profile"));
            } else {
                vah_error(NULL, 0, _("apparmor_parser exited with error"));
                return -1;
            }
        }
    }

    return 0;
}

/*
 * Update the dynamic files
 */
static int
update_include_file(const char *include_file, const char *included_files,
                    bool append)
{
    int plen, flen = 0;
    int fd;
    g_autofree char *pcontent = NULL;
    g_autofree char *existing = NULL;
    const char *warning =
         "# DO NOT EDIT THIS FILE DIRECTLY. IT IS MANAGED BY LIBVIRT.\n";

    if (virFileExists(include_file)) {
        flen = virFileReadAll(include_file, MAX_FILE_LEN, &existing);
        if (flen < 0)
            return -1;
    }

    if (append && existing) {
        /* Duplicate check: include_files might contain multiple rules
         * the best is to check for each rule (separated by \n) but
         * it might be overkilled, just do the check for the whole
         * include_files.
         * Most of the time, include_files contains only one rule
         * so this check is OK to avoid the overflow of the profile
         * duplicates might still exist though.
         */
        if (strstr(existing, included_files) != NULL)
            return 0;
        pcontent = g_strdup_printf("%s%s", existing, included_files);
    } else {
        pcontent = g_strdup_printf("%s%s", warning, included_files);
    }

    plen = strlen(pcontent);
    if (plen > MAX_FILE_LEN) {
        vah_error(NULL, 0, _("invalid length for new profile"));
        return -1;
    }

    /* only update the disk profile if it is different */
    if (flen > 0 && flen == plen && STREQLEN(existing, pcontent, plen)) {
        return 0;
    }

    /* write the file */
    if ((fd = open(include_file, O_CREAT | O_TRUNC | O_WRONLY, 0644)) == -1) {
        vah_error(NULL, 0, _("failed to create include file"));
        return -1;
    }

    if (safewrite(fd, pcontent, plen) < 0) { /* don't write the '\0' */
        VIR_FORCE_CLOSE(fd);
        vah_error(NULL, 0, _("failed to write to profile"));
        return -1;
    }

    if (VIR_CLOSE(fd) != 0) {
        vah_error(NULL, 0, _("failed to close or write to profile"));
        return -1;
    }
    return 0;
}

/*
 * Create a profile based on a template
 */
static int
create_profile(const char *profile, const char *profile_name,
               const char *profile_files, int virtType)
{
    g_autofree char *template = NULL;
    g_autofree char *tcontent = NULL;
    g_autofree char *pcontent = NULL;
    g_autofree char *replace_name = NULL;
    g_autofree char *replace_files = NULL;
    char *tmp = NULL;
    const char *template_name = "\nprofile LIBVIRT_TEMPLATE";
    const char *template_end = "\n}";
    int tlen, plen;
    int fd;
    const char *driver_name = NULL;

    if (virFileExists(profile)) {
        vah_error(NULL, 0, _("profile exists"));
        return -1;
    }

    switch (virtType) {
    case VIR_DOMAIN_VIRT_QEMU:
    case VIR_DOMAIN_VIRT_KQEMU:
    case VIR_DOMAIN_VIRT_KVM:
        driver_name = "qemu";
        break;
    default:
        driver_name = virDomainVirtTypeToString(virtType);
    }

    template = g_strdup_printf("%s/TEMPLATE.%s", APPARMOR_DIR "/libvirt", driver_name);

    if (!virFileExists(template)) {
        vah_error(NULL, 0, _("template does not exist"));
        return -1;
    }

    if ((tlen = virFileReadAll(template, MAX_FILE_LEN, &tcontent)) < 0) {
        vah_error(NULL, 0, _("failed to read AppArmor template"));
        return -1;
    }

    if (strstr(tcontent, template_name) == NULL) {
        vah_error(NULL, 0, _("no replacement string in template"));
        return -1;
    }

    if (strstr(tcontent, template_end) == NULL) {
        vah_error(NULL, 0, _("no replacement string in template"));
        return -1;
    }

    /* '\nprofile <profile_name>\0' */
    replace_name = g_strdup_printf("\nprofile %s", profile_name);

    /* '\n<profile_files>\n}\0' */
    if (virtType != VIR_DOMAIN_VIRT_LXC)
    replace_files = g_strdup_printf("\n%s\n}", profile_files);

    plen = tlen + strlen(replace_name) - strlen(template_name) + 1;

    if (virtType != VIR_DOMAIN_VIRT_LXC)
        plen += strlen(replace_files) - strlen(template_end);

    if (plen > MAX_FILE_LEN || plen < tlen) {
        vah_error(NULL, 0, _("invalid length for new profile"));
        return -1;
    }

    if (!(pcontent = virStringReplace(tcontent, template_name, replace_name)))
        return -1;

    if (virtType != VIR_DOMAIN_VIRT_LXC) {
        if (!(tmp = virStringReplace(pcontent, template_end, replace_files)))
            return -1;
        VIR_FREE(pcontent);
        pcontent = g_steal_pointer(&tmp);
    }

    /* write the file */
    if ((fd = open(profile, O_CREAT | O_EXCL | O_WRONLY, 0644)) == -1) {
        vah_error(NULL, 0, _("failed to create profile"));
        return -1;
    }

    if (safewrite(fd, pcontent, plen - 1) < 0) { /* don't write the '\0' */
        VIR_FORCE_CLOSE(fd);
        vah_error(NULL, 0, _("failed to write to profile"));
        return -1;
    }

    if (VIR_CLOSE(fd) != 0) {
        vah_error(NULL, 0, _("failed to close or write to profile"));
        return -1;
    }

    return 0;
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
    const char *bad = "/[]{}?^,\"*";

    if (strlen(name) == 0)
        return -1;

    if (strcspn(name, bad) != strlen(name))
        return -1;

    return 0;
}

/* see if one of the strings in arr starts with str */
static int
array_starts_with(const char *str, const char * const *arr, const long size)
{
    size_t i;
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
        "/initrd.img",
        "/usr/share/edk2/",
        "/usr/share/edk2-ovmf/",
        "/usr/share/OVMF/",
        "/usr/share/ovmf/",
        "/usr/share/AAVMF/",
        "/usr/share/qemu-efi/",              /* for AAVMF images */
        "/usr/share/qemu-efi-aarch64/",
        "/usr/share/qemu-efi-loongarch64/",
        "/usr/share/qemu-efi-riscv64/",
        "/usr/share/qemu/",                  /* SUSE path for OVMF and AAVMF images */
        "/usr/lib/u-boot/",
        "/usr/lib/riscv64-linux-gnu/opensbi",
    };
    /* override the above with these */
    const char * const override[] = {
        "/sys/devices/pci",                /* for hostdev pci devices */
        "/sys/kernel/config/target/vhost", /* for hostdev vhost_scsi devices */
        "/etc/libvirt-sandbox/services/"   /* for virt-sandbox service config */
    };

    const int nropaths = G_N_ELEMENTS(restricted);
    const int nrwpaths = G_N_ELEMENTS(restricted_rw);
    const int nopaths = G_N_ELEMENTS(override);

    if (path == NULL) {
        vah_error(NULL, 0, _("bad pathname"));
        return -1;
    }

    /* Don't allow double quotes, since we use them to quote the filename
     * and this will confuse the apparmor parser.
     */
    if (strchr(path, '"') != NULL)
        return 1;

    /* Require an absolute path */
    if (STRNEQLEN(path, "/", 1))
        return 1;

    if (!virFileExists(path))
        vah_warning(_("path does not exist, skipping file type checks"));

    /* overrides are always allowed */
    if (array_starts_with(path, override, nopaths) == 0)
        return 0;

    /* allow read only paths upfront */
    if (readonly) {
        if (array_starts_with(path, restricted_rw, nrwpaths) == 0)
            return 0;
    }

    /* disallow RW access to all paths in restricted and restriced_rw */
    if ((array_starts_with(path, restricted, nropaths) == 0 ||
         array_starts_with(path, restricted_rw, nrwpaths) == 0))
        return 1;

    return 0;
}

static int
verify_xpath_context(xmlXPathContextPtr ctxt)
{
    char *tmp = NULL;

    if (!ctxt) {
        vah_warning(_("Invalid context"));
        return -1;
    }

    /* check if have <name> */
    if (!(tmp = virXPathString("string(./name[1])", ctxt))) {
        vah_warning(_("Could not find <name>"));
        return -1;
    }
    VIR_FREE(tmp);

    /* check if have <uuid> */
    if (!(tmp = virXPathString("string(./uuid[1])", ctxt))) {
        vah_warning(_("Could not find <uuid>"));
        return -1;
    }
    VIR_FREE(tmp);

    return 0;
}

/*
 * Parse the xml we received to fill in the following:
 * ctl->virtType
 * ctl->os
 * ctl->arch
 *
 * These are suitable for setting up a virCaps *
 */
static int
caps_mockup(vahControl * ctl, const char *xmlStr)
{
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    g_autofree char *arch = NULL;

    if (!(xml = virXMLParse(NULL, xmlStr, _("(domain_definition)"),
                            "domain", &ctxt, NULL, false))) {
        return -1;
    }

    /* Quick sanity check for some required elements */
    if (verify_xpath_context(ctxt) != 0)
        return -1;

    ctl->virtType = virXPathString("string(./@type)", ctxt);
    if (!ctl->virtType) {
        vah_error(ctl, 0, _("domain type is not defined"));
        return -1;
    }
    ctl->os = virXPathString("string(./os/type[1])", ctxt);
    if (!ctl->os) {
        vah_error(ctl, 0, _("os.type is not defined"));
        return -1;
    }
    arch = virXPathString("string(./os/type[1]/@arch)", ctxt);
    if (!arch) {
        ctl->arch = virArchFromHost();
    } else {
        ctl->arch = virArchFromString(arch);
    }

    return 0;
}

virDomainDefParserConfig virAAHelperDomainDefParserConfig = {
    .features = VIR_DOMAIN_DEF_FEATURE_MEMORY_HOTPLUG |
                VIR_DOMAIN_DEF_FEATURE_OFFLINE_VCPUPIN |
                VIR_DOMAIN_DEF_FEATURE_INDIVIDUAL_VCPUS |
                VIR_DOMAIN_DEF_FEATURE_NET_MODEL_STRING |
                VIR_DOMAIN_DEF_FEATURE_DISK_FD,
};

static int
get_definition(vahControl * ctl, const char *xmlStr)
{
    int ostype, virtType;
    virCapsGuest *guest;  /* this is freed when caps is freed */

    /*
     * mock up some capabilities. We don't currently use these explicitly,
     * but need them for virDomainDefParseString().
     */
    if (caps_mockup(ctl, xmlStr) != 0)
        return -1;

    if ((ctl->caps = virCapabilitiesNew(ctl->arch, true, true)) == NULL) {
        vah_error(ctl, 0, _("could not allocate memory"));
        return -1;
    }

    if (!(ctl->xmlopt = virDomainXMLOptionNew(&virAAHelperDomainDefParserConfig,
                                              NULL, NULL, NULL, NULL, NULL))) {
        vah_error(ctl, 0, _("Failed to create XML config object"));
        return -1;
    }

    if ((ostype = virDomainOSTypeFromString(ctl->os)) < 0) {
        vah_error(ctl, 0, _("unknown OS type"));
        return -1;
    }

    guest = virCapabilitiesAddGuest(ctl->caps, ostype, ctl->arch,
                                    NULL, NULL, 0, NULL);

    if ((virtType = virDomainVirtTypeFromString(ctl->virtType)) < 0) {
        vah_error(ctl, 0, _("unknown virtualization type"));
        return -1;
    }

    virCapabilitiesAddGuestDomain(guest, virtType,
                                  NULL, NULL, 0, NULL);

    ctl->def = virDomainDefParseString(xmlStr,
                                       ctl->xmlopt, NULL,
                                       VIR_DOMAIN_DEF_PARSE_SKIP_SECLABEL |
                                       VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE |
                                       VIR_DOMAIN_DEF_PARSE_VOLUME_TRANSLATED);

    if (ctl->def == NULL) {
        vah_error(ctl, 0, _("could not parse XML"));
        return -1;
    }

    if (!ctl->def->name) {
        vah_error(ctl, 0, _("could not find name in XML"));
        return -1;
    }

    if (valid_name(ctl->def->name) != 0) {
        vah_error(ctl, 0, _("bad name"));
        return -1;
    }

    return 0;
}

/**
  * The permissions allowed are apparmor valid permissions and 'R'. 'R' stands for
  * read with no explicit deny rule.
  */
static int
vah_add_path(virBuffer *buf, const char *path, const char *perms, bool recursive)
{
    int rc = -1;
    bool readonly = true;
    bool explicit_deny_rule = true;
    char *sub = NULL;
    g_autofree char *tmp = NULL;
    g_autofree char *perms_new = NULL;
    g_autofree char *pathdir = NULL;
    g_autofree char *pathtmp = NULL;
    g_autofree char *pathreal = NULL;

    if (path == NULL)
        return rc;

    /* Skip files without an absolute path. Not having one confuses the
     * apparmor parser and this also ensures things like tcp consoles don't
     * get added to the profile.
     */
    if (STRNEQLEN(path, "/", 1)) {
        vah_warning(path);
        vah_warning(_("skipped non-absolute path"));
        return 0;
    }

    /* files might be created by qemu later on and not exist right now.
     * But realpath needs a valid path to work on, therefore:
     * 1. walk the path to find longest valid path
     * 2. get the realpath of that valid path
     * 3. re-combine the realpath with the remaining suffix
     * Note: A totally non existent path is used as-is
     */
     pathdir = g_strdup(path);
     while (!virFileExists(pathdir)) {
         pathtmp = g_path_get_dirname(pathdir);
         VIR_FREE(pathdir);
         pathdir = g_steal_pointer(&pathtmp);
     }

    if (strlen(pathdir) == 1) {
        /* nothing of the path does exist yet */
        tmp = g_strdup(path);
    } else {
        pathtmp = g_strdup(path + strlen(pathdir));
        if (!(pathreal = virFileCanonicalizePath(pathdir))) {
            vah_error(NULL, 0, pathdir);
            vah_error(NULL, 0, _("could not find realpath"));
            return rc;
        }
        tmp = g_strdup_printf("%s%s", pathreal, pathtmp);
    }

    perms_new = g_strdup(perms);

    if (strchr(perms_new, 'w') != NULL) {
        readonly = false;
        explicit_deny_rule = false;
    }

    if ((sub = strchr(perms_new, 'R')) != NULL) {
        /* Don't write the invalid R permission, replace it with 'r' */
        sub[0] = 'r';
        explicit_deny_rule = false;
    }

    rc = valid_path(tmp, readonly);
    if (rc != 0) {
        if (rc > 0) {
            vah_error(NULL, 0, path);
            vah_error(NULL, 0, _("skipped restricted file"));
        }
        return rc;
    }

    if (tmp[strlen(tmp) - 1] == '/')
        tmp[strlen(tmp) - 1] = '\0';

    virBufferAsprintf(buf, "  \"%s%s\" %s,\n", tmp, recursive ? "/**" : "",
                      perms_new);
    if (explicit_deny_rule) {
        virBufferAddLit(buf, "  # don't audit writes to readonly files\n");
        virBufferAsprintf(buf, "  deny \"%s%s\" w,\n", tmp, recursive ? "/**" : "");
    }
    if (recursive) {
        /* allow reading (but not creating) the dir */
        virBufferAsprintf(buf, "  \"%s/\" r,\n", tmp);
    }

    return rc;
}

static int
vah_add_file(virBuffer *buf, const char *path, const char *perms)
{
    return vah_add_path(buf, path, perms, false);
}

static int
vah_add_file_chardev(virBuffer *buf,
                     const char *path,
                     const char *perms,
                     const int type)
{
    g_autofree char *pipe_in = NULL;
    g_autofree char *pipe_out = NULL;

    if (type == VIR_DOMAIN_CHR_TYPE_PIPE) {
        /* add the pipe input */
        pipe_in = g_strdup_printf("%s.in", path);

        if (vah_add_file(buf, pipe_in, perms) != 0)
            return -1;

        /* add the pipe output */
        pipe_out = g_strdup_printf("%s.out", path);

        if (vah_add_file(buf, pipe_out, perms) != 0)
            return -1;
    } else {
        /* add the file */
        if (vah_add_file(buf, path, perms) != 0)
            return -1;
    }

    return 0;
}

static int
file_iterate_hostdev_cb(virUSBDevice *dev G_GNUC_UNUSED,
                        const char *file, void *opaque)
{
    virBuffer *buf = opaque;
    return vah_add_file(buf, file, "rw");
}

static int
file_iterate_pci_cb(virPCIDevice *dev G_GNUC_UNUSED,
                    const char *file, void *opaque)
{
    virBuffer *buf = opaque;
    return vah_add_file(buf, file, "rw");
}

static int
add_file_path(virStorageSource *src,
              size_t depth,
              virBuffer *buf)
{
    int ret;

    /* execute the callback only for local storage */
    if (!src->path || !virStorageSourceIsLocalStorage(src))
        return 0;

    if (depth == 0) {
        if (src->readonly)
            ret = vah_add_file(buf, src->path, "rk");
        else
            ret = vah_add_file(buf, src->path, "rwk");
    } else {
        ret = vah_add_file(buf, src->path, "rk");
    }

    if (ret != 0)
        ret = -1;

    return ret;
}


static int
storage_source_add_files(virStorageSource *src,
                         virBuffer *buf,
                         size_t depth)
{
    virStorageSource *tmp;

    for (tmp = src; virStorageSourceIsBacking(tmp); tmp = tmp->backingStore) {
        if (add_file_path(tmp, depth, buf) < 0)
            return -1;

        if (tmp->dataFileStore &&
            add_file_path(tmp->dataFileStore, depth, buf) < 0)
            return -1;

        depth++;
    }

    return 0;
}

static int
get_files(vahControl * ctl)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    int rc;
    size_t i;
    g_autofree char *uuid = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    bool needsVfio = false, needsvhost = false, needsgl = false;

    /* verify uuid is same as what we were given on the command line */
    virUUIDFormat(ctl->def->uuid, uuidstr);
    uuid = g_strdup_printf("%s%s", AA_PREFIX, uuidstr);

    if (STRNEQ(uuid, ctl->uuid)) {
        vah_error(ctl, 0, _("given uuid does not match XML uuid"));
        return -1;
    }

    /* load the storage driver so that backing store can be accessed */
#ifdef WITH_STORAGE
    virDriverLoadModule("storage", "storageRegister", false);
#endif

    for (i = 0; i < ctl->def->ndisks; i++) {
        virDomainDiskDef *disk = ctl->def->disks[i];

        if (virStorageSourceIsEmpty(disk->src))
            continue;
        /* XXX - if we knew the qemu user:group here we could send it in
         *        so that the open could be re-tried as that user:group.
         *
         * The maximum depth is limited to 200 layers similarly to the qemu
         * implementation.
         */
        if (!disk->src->backingStore)
            virStorageSourceGetMetadata(disk->src, -1, -1, 200, false);

         /* XXX should handle open errors more careful than just ignoring them.
         */
        if (storage_source_add_files(disk->src, &buf, 0) < 0)
            return -1;
    }

    for (i = 0; i < ctl->def->nserials; i++) {
        virDomainChrDef *chr = ctl->def->serials[i];

        if ((chr->source->type == VIR_DOMAIN_CHR_TYPE_PTY ||
             chr->source->type == VIR_DOMAIN_CHR_TYPE_DEV ||
             chr->source->type == VIR_DOMAIN_CHR_TYPE_FILE ||
             chr->source->type == VIR_DOMAIN_CHR_TYPE_UNIX ||
             chr->source->type == VIR_DOMAIN_CHR_TYPE_PIPE) &&
            chr->source->data.file.path &&
            chr->source->data.file.path[0] != '\0') {
            if (vah_add_file_chardev(&buf,
                                     chr->source->data.file.path,
                                     "rw",
                                     chr->source->type) != 0) {
                return -1;
            }
        }
    }

    for (i = 0; i < ctl->def->nconsoles; i++) {
        virDomainChrDef *chr = ctl->def->consoles[i];

        if ((chr->source->type == VIR_DOMAIN_CHR_TYPE_PTY ||
             chr->source->type == VIR_DOMAIN_CHR_TYPE_DEV ||
             chr->source->type == VIR_DOMAIN_CHR_TYPE_FILE ||
             chr->source->type == VIR_DOMAIN_CHR_TYPE_UNIX ||
             chr->source->type == VIR_DOMAIN_CHR_TYPE_PIPE) &&
            chr->source->data.file.path &&
            chr->source->data.file.path[0] != '\0') {
            if (vah_add_file(&buf,
                             chr->source->data.file.path, "rw") != 0) {
                return -1;
            }
        }
    }

    for (i = 0; i < ctl->def->nparallels; i++) {
        virDomainChrDef *chr = ctl->def->parallels[i];

        if ((chr->source->type == VIR_DOMAIN_CHR_TYPE_PTY ||
             chr->source->type == VIR_DOMAIN_CHR_TYPE_DEV ||
             chr->source->type == VIR_DOMAIN_CHR_TYPE_FILE ||
             chr->source->type == VIR_DOMAIN_CHR_TYPE_UNIX ||
             chr->source->type == VIR_DOMAIN_CHR_TYPE_PIPE) &&
            chr->source->data.file.path &&
            chr->source->data.file.path[0] != '\0') {
            if (vah_add_file_chardev(&buf,
                                     chr->source->data.file.path,
                                     "rw",
                                     chr->source->type) != 0) {
                return -1;
            }
        }
    }

    for (i = 0; i < ctl->def->nchannels; i++) {
        virDomainChrDef *chr = ctl->def->channels[i];

        if ((chr->source->type == VIR_DOMAIN_CHR_TYPE_PTY ||
             chr->source->type == VIR_DOMAIN_CHR_TYPE_DEV ||
             chr->source->type == VIR_DOMAIN_CHR_TYPE_FILE ||
             chr->source->type == VIR_DOMAIN_CHR_TYPE_UNIX ||
             chr->source->type == VIR_DOMAIN_CHR_TYPE_PIPE) &&
            chr->source->data.file.path &&
            chr->source->data.file.path[0] != '\0') {
            if (vah_add_file_chardev(&buf,
                                     chr->source->data.file.path,
                                     "rw",
                                     chr->source->type) != 0) {
                return -1;
            }
        }
    }

    if (ctl->def->os.kernel &&
        vah_add_file(&buf, ctl->def->os.kernel, "r") != 0) {
        return -1;
    }

    if (ctl->def->os.initrd &&
        vah_add_file(&buf, ctl->def->os.initrd, "r") != 0) {
        return -1;
    }

    if (ctl->def->os.shim &&
        vah_add_file(&buf, ctl->def->os.shim, "r") != 0) {
        return -1;
    }

    if (ctl->def->os.dtb &&
        vah_add_file(&buf, ctl->def->os.dtb, "r") != 0) {
        return -1;
    }

    for (i = 0; i < ctl->def->os.nacpiTables; i++) {
        if (vah_add_file(&buf, ctl->def->os.acpiTables[i]->path, "r") != 0)
            return -1;
    }

    if (ctl->def->pstore &&
        vah_add_file(&buf, ctl->def->pstore->path, "rw") != 0) {
        return -1;
    }

    if (ctl->def->os.loader && ctl->def->os.loader->path) {
        bool readonly = false;
        virTristateBoolToBool(ctl->def->os.loader->readonly, &readonly);
        if (vah_add_file(&buf,
                         ctl->def->os.loader->path,
                         readonly ? "rk" : "rwk") != 0) {
            return -1;
        }
    }

    if (ctl->def->os.loader && ctl->def->os.loader->nvram &&
        storage_source_add_files(ctl->def->os.loader->nvram, &buf, 0) < 0) {
        return -1;
    }

    for (i = 0; i < ctl->def->ngraphics; i++) {
        virDomainGraphicsDef *graphics = ctl->def->graphics[i];
        size_t n;
        const char *rendernode = virDomainGraphicsGetRenderNode(graphics);

        if (rendernode) {
            if (vah_add_file(&buf, rendernode, "rw") != 0)
                return -1;
            needsgl = true;
        } else {
            if (virDomainGraphicsNeedsAutoRenderNode(graphics)) {
                g_autofree char *defaultRenderNode = virHostGetDRMRenderNode();
                needsgl = true;

                if (defaultRenderNode &&
                    vah_add_file(&buf, defaultRenderNode, "rw") != 0) {
                    return -1;
                }
            }
        }

        for (n = 0; n < graphics->nListens; n++) {
            virDomainGraphicsListenDef listenObj = graphics->listens[n];

            if (listenObj.type == VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET &&
                listenObj.socket &&
                vah_add_file(&buf, listenObj.socket, "rw"))
                return -1;
        }
    }

    if (ctl->def->ngraphics == 1 &&
        ctl->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_SDL &&
        vah_add_file(&buf, ctl->def->graphics[0]->data.sdl.xauth, "r") != 0) {
        return -1;
    }

    for (i = 0; i < ctl->def->nhostdevs; i++) {
        virDomainHostdevDef *dev = ctl->def->hostdevs[i];

        if (dev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;

        switch (dev->source.subsys.type) {
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB: {
            g_autoptr(virUSBDevice) usb = NULL;

            if (virHostdevFindUSBDevice(dev, true, &usb) < 0)
                continue;

            if (dev->missing)
                continue;

            rc = virUSBDeviceFileIterate(usb, file_iterate_hostdev_cb, &buf);
            if (rc != 0)
                return -1;
            break;
        }

        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV: {
            virDomainHostdevSubsysMediatedDev *mdevsrc = &dev->source.subsys.u.mdev;
            switch (mdevsrc->model) {
            case VIR_MDEV_MODEL_TYPE_VFIO_PCI:
            case VIR_MDEV_MODEL_TYPE_VFIO_AP:
            case VIR_MDEV_MODEL_TYPE_VFIO_CCW:
                needsVfio = true;
                break;
            case VIR_MDEV_MODEL_TYPE_LAST:
            default:
                virReportEnumRangeError(virMediatedDeviceModelType,
                                        mdevsrc->model);
                break;
            }
            break;
        }

        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI: {
            virPCIDevice *pci = virPCIDeviceNew(&dev->source.subsys.u.pci.addr);

            virDeviceHostdevPCIDriverName driverName = dev->source.subsys.u.pci.driver.name;

            if (driverName == VIR_DEVICE_HOSTDEV_PCI_DRIVER_NAME_VFIO ||
                driverName == VIR_DEVICE_HOSTDEV_PCI_DRIVER_NAME_DEFAULT) {
                needsVfio = true;
            }

            if (pci == NULL)
                continue;

            rc = virPCIDeviceFileIterate(pci, file_iterate_pci_cb, &buf);
            virPCIDeviceFree(pci);

            break;
        }

        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
        default:
            rc = 0;
            break;
        } /* switch */
    }

    for (i = 0; i < ctl->def->nfss; i++) {
        virDomainFSDef *fs = ctl->def->fss[i];

        if (fs->type == VIR_DOMAIN_FS_TYPE_MOUNT &&
            (fs->fsdriver == VIR_DOMAIN_FS_DRIVER_TYPE_PATH ||
             fs->fsdriver == VIR_DOMAIN_FS_DRIVER_TYPE_DEFAULT) &&
            fs->src) {

            /* We don't need to add deny rw rules for readonly mounts,
             * this can only lead to troubles when mounting / readonly.
             */
            if (vah_add_path(&buf, fs->src->path, fs->readonly ? "R" : "rwl", true) != 0)
                return -1;
        }
    }

    for (i = 0; i < ctl->def->ninputs; i++) {
        virDomainInputDef *input = ctl->def->inputs[i];

        if (input->type == VIR_DOMAIN_INPUT_TYPE_PASSTHROUGH ||
            input->type == VIR_DOMAIN_INPUT_TYPE_EVDEV) {
            if (vah_add_file(&buf, ctl->def->inputs[i]->source.evdev, "rw") != 0)
                return -1;
        }
    }

    for (i = 0; i < ctl->def->nnets; i++) {
        virDomainNetDef *net = ctl->def->nets[i];

        if (net->type == VIR_DOMAIN_NET_TYPE_VHOSTUSER &&
            net->data.vhostuser) {
            virDomainChrSourceDef *vhu = ctl->def->nets[i]->data.vhostuser;

            if (vah_add_file_chardev(&buf, vhu->data.nix.path, "rw",
                                     vhu->type) != 0)
                return -1;
        }
    }

    for (i = 0; i < ctl->def->nmems; i++) {
        virDomainMemoryDef *mem = ctl->def->mems[i];

        switch (mem->model) {
        case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
            if (vah_add_file(&buf, mem->source.nvdimm.path, "rw") != 0)
                return -1;
            break;
        case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM:
            if (vah_add_file(&buf, mem->source.virtio_pmem.path, "rw") != 0)
                return -1;
            break;
        case VIR_DOMAIN_MEMORY_MODEL_SGX_EPC:
            if (vah_add_file(&buf, DEV_SGX_VEPC, "rw") != 0 ||
                vah_add_file(&buf, DEV_SGX_PROVISION, "r") != 0) {
                return -1;
            }
            break;

        case VIR_DOMAIN_MEMORY_MODEL_DIMM:
        case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM:
        case VIR_DOMAIN_MEMORY_MODEL_NONE:
        case VIR_DOMAIN_MEMORY_MODEL_LAST:
            break;
        }
    }

    for (i = 0; i < ctl->def->nsysinfo; i++) {
        virSysinfoDef *sysinfo = ctl->def->sysinfo[i];
        size_t j;

        for (j = 0; j < sysinfo->nfw_cfgs; j++) {
            virSysinfoFWCfgDef *f = &sysinfo->fw_cfgs[j];

            if (f->file &&
                vah_add_file(&buf, f->file, "r") != 0)
                return -1;
        }
    }

    for (i = 0; i < ctl->def->nshmems; i++) {
        virDomainShmemDef *shmem = ctl->def->shmems[i];
        /* explicit server paths can be on any model to overwrites defaults.
         * When the server path is enabled, use it - otherwise fallback to
         * model dependent defaults. */
        if (shmem->server.enabled &&
            shmem->server.chr->data.nix.path) {
            if (vah_add_file(&buf, shmem->server.chr->data.nix.path,
                             "rw") != 0)
                return -1;
        } else {
            g_autofree char *mem_path = NULL;

            switch (shmem->model) {
            case VIR_DOMAIN_SHMEM_MODEL_IVSHMEM_PLAIN:
                /* until exposed, recreate qemuBuildShmemBackendMemProps */
                mem_path = g_strdup_printf("/dev/shm/%s", shmem->name);
                break;
            case VIR_DOMAIN_SHMEM_MODEL_IVSHMEM_DOORBELL:
            case VIR_DOMAIN_SHMEM_MODEL_IVSHMEM:
                /* until exposed, recreate qemuDomainPrepareShmemChardev */
                mem_path = g_strdup_printf("/var/lib/libvirt/shmem-%s-sock",
                                           shmem->name);
                break;
            case VIR_DOMAIN_SHMEM_MODEL_LAST:
                virReportEnumRangeError(virDomainShmemModel,
                                        shmem->model);
                break;
            }
            if (mem_path != NULL &&
                vah_add_file(&buf, mem_path, "rw") != 0) {
                return -1;
            }
        }
    }


    for (i = 0; i < ctl->def->ntpms; i++) {
        virDomainTPMDef *tpm = ctl->def->tpms[i];
        g_autofree char *shortName = NULL;
        const char *tpmpath = NULL;

        if (tpm->type != VIR_DOMAIN_TPM_TYPE_EMULATOR)
            continue;

        shortName = virDomainDefGetShortName(ctl->def);

        switch (tpm->data.emulator.version) {
        case VIR_DOMAIN_TPM_VERSION_1_2:
            tpmpath = "tpm1.2";
            break;
        case VIR_DOMAIN_TPM_VERSION_2_0:
            tpmpath = "tpm2";
            break;
        case VIR_DOMAIN_TPM_VERSION_DEFAULT:
        case VIR_DOMAIN_TPM_VERSION_LAST:
            break;
        }

        /* Unix socket for QEMU and swtpm to use */
        virBufferAsprintf(&buf,
                          "  \"%s/libvirt/qemu/swtpm/%s-swtpm.sock\" rw,\n",
                          RUNSTATEDIR, shortName);
        /* Paths for swtpm to use: give it access to its state
         * directory (state files and fsync on dir), log, and PID files.
         */
        virBufferAsprintf(&buf,
                          "  \"%s/lib/libvirt/swtpm/%s/%s/\" r,\n",
                          LOCALSTATEDIR, uuidstr, tpmpath);
        virBufferAsprintf(&buf,
                          "  \"%s/lib/libvirt/swtpm/%s/%s/**\" rwk,\n",
                          LOCALSTATEDIR, uuidstr, tpmpath);
        virBufferAsprintf(&buf,
                          "  \"%s/log/swtpm/libvirt/qemu/%s-swtpm.log\" w,\n",
                          LOCALSTATEDIR, ctl->def->name);
        virBufferAsprintf(&buf,
                          "  \"%s/libvirt/qemu/swtpm/%s-swtpm.pid\" rw,\n",
                          RUNSTATEDIR, shortName);
    }

    for (i = 0; i < ctl->def->nsmartcards; i++) {
        virDomainSmartcardDef *sc = ctl->def->smartcards[i];
        virDomainSmartcardType sc_type = sc->type;
        char *sc_db = (char *)VIR_DOMAIN_SMARTCARD_DEFAULT_DATABASE;
        if (sc->data.cert.database)
            sc_db = sc->data.cert.database;
        switch (sc_type) {
            /*
             * Note: At time of writing, to get this working, qemu seccomp sandbox has
             * to be disabled or the host must be running QEMU with commit
             * 9a1565a03b79d80b236bc7cc2dbce52a2ef3a1b8.
             * It's possibly due to libcacard:vcard_emul_new_event_thread(), which calls
             * PR_CreateThread(), which calls {g,s}etpriority(). And resourcecontrol seccomp
             * filter forbids it (cf src/qemu/qemu_command.c which seems to always use
             * resourcecontrol=deny).
             */
            case VIR_DOMAIN_SMARTCARD_TYPE_HOST:
                virBufferAddLit(&buf, "  \"/etc/pki/nssdb/{,*}\" rk,\n");
                break;
            case VIR_DOMAIN_SMARTCARD_TYPE_HOST_CERTIFICATES:
                virBufferAsprintf(&buf, "  \"%s/{,*}\" rk,\n", sc_db);
                break;
            /*
             * Nothing to do for passthrough, as the smartcard
             * access is done through TCP or Spice
             */
            case VIR_DOMAIN_SMARTCARD_TYPE_PASSTHROUGH:
                break;
            case VIR_DOMAIN_SMARTCARD_TYPE_LAST:
                break;
        }
    }

    if (ctl->def->virtType == VIR_DOMAIN_VIRT_KVM) {
        for (i = 0; i < ctl->def->nnets; i++) {
            virDomainNetDef *net = ctl->def->nets[i];
            if (net && virDomainNetGetModelString(net)) {
                if (net->driver.virtio.name == VIR_DOMAIN_NET_DRIVER_TYPE_QEMU)
                    continue;
                if (!virDomainNetIsVirtioModel(net))
                    continue;
            }
            needsvhost = true;
        }
    }
    if (needsvhost)
        virBufferAddLit(&buf, "  \"/dev/vhost-net\" rw,\n");

    if (needsVfio) {
        virBufferAddLit(&buf, "  \"/dev/vfio/vfio\" rw,\n");
        virBufferAddLit(&buf, "  \"/dev/vfio/[0-9]*\" rw,\n");
    }
    if (needsgl) {
        /* if using gl all sorts of further dri related paths will be needed */
        virBufferAddLit(&buf, "  # DRI/Mesa/(e)GL config and driver paths\n");
        virBufferAddLit(&buf, "  \"/usr/lib{,32,64}/dri/*.so*\" mr,\n");
        virBufferAddLit(&buf, "  \"/usr/lib/@{multiarch}/dri/*.so*\" mr,\n");
        virBufferAddLit(&buf, "  \"/usr/lib/fglrx/dri/*.so*\" mr,\n");
        virBufferAddLit(&buf, "  \"/etc/drirc\" r,\n");
        virBufferAddLit(&buf, "  \"/usr/share/drirc.d/{,*.conf}\" r,\n");
        virBufferAddLit(&buf, "  \"/etc/glvnd/egl_vendor.d/{,*}\" r,\n");
        virBufferAddLit(&buf, "  \"/usr/share/glvnd/egl_vendor.d/{,*}\" r,\n");
        virBufferAddLit(&buf, "  \"/usr/share/egl/egl_external_platform.d/\" r,\n");
        virBufferAddLit(&buf, "  \"/usr/share/egl/egl_external_platform.d/*\" r,\n");
        virBufferAddLit(&buf, "  \"/proc/modules\" r,\n");
        virBufferAddLit(&buf, "  \"/proc/driver/nvidia/params\" r,\n");
        virBufferAddLit(&buf, "  \"/dev/nvidiactl\" rw,\n");
        virBufferAddLit(&buf, "  # Probe DRI device attributes\n");
        virBufferAddLit(&buf, "  \"/dev/dri/\" r,\n");
        virBufferAddLit(&buf, "  \"/sys/devices/**/{uevent,vendor,device,subsystem_vendor,subsystem_device,config,revision}\" r,\n");
        virBufferAddLit(&buf, "  # dri libs will trigger that, but t is not requited and DAC would deny it anyway\n");
        virBufferAddLit(&buf, "  deny \"/var/lib/libvirt/.cache/\" w,\n");
    }

    /* AMD-SEV VM needs to read/write the character device /dev/sev */
    if (ctl->def->sec) {
        switch (ctl->def->sec->sectype) {
        case VIR_DOMAIN_LAUNCH_SECURITY_SEV:
        case VIR_DOMAIN_LAUNCH_SECURITY_SEV_SNP:
            virBufferAddLit(&buf, "  \"/dev/sev\" rw,\n");
            break;
        case VIR_DOMAIN_LAUNCH_SECURITY_PV:
        case VIR_DOMAIN_LAUNCH_SECURITY_TDX:
        case VIR_DOMAIN_LAUNCH_SECURITY_NONE:
        case VIR_DOMAIN_LAUNCH_SECURITY_LAST:
            break;
        }
    }

    if (ctl->newfile &&
        vah_add_file(&buf, ctl->newfile, "rwk") != 0) {
        return -1;
    }

    ctl->files = virBufferContentAndReset(&buf);
    return 0;
}

static int
vahParseArgv(vahControl * ctl, int argc, char **argv)
{
    int arg, idx = 0;
    struct option opt[] = {
        { "add", 0, 0, 'a' },
        { "create", 0, 0, 'c' },
        { "dryrun", 0, 0, 'd' },
        { "delete", 0, 0, 'D' },
        { "add-file", 0, 0, 'f' },
        { "append-file", 0, 0, 'F' },
        { "help", 0, 0, 'h' },
        { "replace", 0, 0, 'r' },
        { "remove", 0, 0, 'R' },
        { "uuid", 1, 0, 'u' },
        { 0, 0, 0, 0 },
    };

    while ((arg = getopt_long(argc, argv, "acdDhrRH:b:u:p:f:F:", opt,
            &idx)) != -1) {
        switch (arg) {
            case 'a':
                ctl->cmd = 'a';
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
            case 'F':
                ctl->newfile = g_strdup(optarg);
                ctl->append = arg == 'F';
                break;
            case 'h':
                vah_usage();
                exit(EXIT_SUCCESS);
                break;
            case 'r':
                ctl->cmd = 'r';
                break;
            case 'R':
                ctl->cmd = 'R';
                break;
            case 'u':
                if (strlen(optarg) > PROFILE_NAME_SIZE - 1)
                    vah_error(ctl, 1, _("invalid UUID"));
                if (virStrcpy((char *)ctl->uuid, optarg,
                    PROFILE_NAME_SIZE) < 0)
                    vah_error(ctl, 1, _("error copying UUID"));
                break;
            default:
                vah_error(ctl, 1, _("unsupported option"));
                break;
        }
    }
    if (strchr("acDrR", ctl->cmd) == NULL)
        vah_error(ctl, 1, _("bad command"));

    if (valid_uuid(ctl->uuid) != 0)
        vah_error(ctl, 1, _("invalid UUID"));

    if (!ctl->cmd) {
        vah_usage();
        exit(EXIT_FAILURE);
    }

    if (ctl->cmd == 'c' || ctl->cmd == 'r') {
        g_autofree char *xmlStr = NULL;
        if (virFileReadLimFD(STDIN_FILENO, MAX_FILE_LEN, &xmlStr) < 0)
            vah_error(ctl, 1, _("could not read xml file"));

        if (get_definition(ctl, xmlStr) != 0 || ctl->def == NULL) {
            vah_error(ctl, 1, _("could not get VM definition"));
        }

        if (get_files(ctl) != 0)
            vah_error(ctl, 1, _("invalid VM definition"));
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
    vahControl _ctl = { 0 };
    vahControl *ctl = &_ctl;
    int rc = -1;
    g_autofree char *profile = NULL;
    g_autofree char *include_file = NULL;
    off_t size;
    bool purged = 0;

    if (virGettextInitialize() < 0 ||
        virErrorInitialize() < 0) {
        fprintf(stderr, _("%1$s: initialization failed\n"), argv[0]);
        exit(EXIT_FAILURE);
    }

    virFileActivateDirOverrideForProg(argv[0]);

    /* Initialize the log system */
    if (virLogSetFromEnv() < 0)
        exit(EXIT_FAILURE);

    /* clear the environment */
    environ = NULL;
    if (g_setenv("PATH", "/sbin:/usr/sbin", TRUE) == FALSE)
        vah_error(ctl, 1, _("could not set PATH"));

    /* ensure the traditional IFS setting */
    if (g_setenv("IFS", " \t\n", TRUE) == FALSE)
        vah_error(ctl, 1, _("could not set IFS"));

    if (!(progname = strrchr(argv[0], '/')))
        progname = argv[0];
    else
        progname++;

    if (vahParseArgv(ctl, argc, argv) != 0)
        vah_error(ctl, 1, _("could not parse arguments"));

    profile = g_strdup_printf("%s/%s", APPARMOR_DIR "/libvirt", ctl->uuid);
    include_file = g_strdup_printf("%s/%s.files", APPARMOR_DIR "/libvirt", ctl->uuid);

    if (ctl->cmd == 'a') {
        rc = parserLoad(ctl->uuid);
    } else if (ctl->cmd == 'R' || ctl->cmd == 'D') {
        rc = parserRemove(ctl->uuid);
        if (ctl->cmd == 'D')
            unlink(include_file);
    } else if (ctl->cmd == 'c' || ctl->cmd == 'r') {
        g_autofree char *included_files = NULL;
        g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

        if (ctl->cmd == 'c' && virFileExists(profile))
            vah_error(ctl, 1, _("profile exists"));

        /*
         * Rare cases can leave corrupted empty files behind breaking
         * the guest. An empty file is never correct as virt-aa-helper
         * would at least add the basic rules, therefore clean this up
         * for a proper refresh.
         */
        if (virFileExists(profile)) {
                size = virFileLength(profile, -1);
                if (size == 0) {
                        vah_warning(_("Profile of 0 size detected, will attempt to remove it"));
                        if ((rc = parserRemove(ctl->uuid)) != 0)
                                vah_error(ctl, 1, _("could not remove profile"));
                        unlink(profile);
                        purged = true;
                }
        }
        if (ctl->append && ctl->newfile) {
            if (vah_add_file(&buf, ctl->newfile, "rwk") != 0)
                goto cleanup;
        } else {
            if (ctl->def->virtType == VIR_DOMAIN_VIRT_QEMU ||
                ctl->def->virtType == VIR_DOMAIN_VIRT_KQEMU ||
                ctl->def->virtType == VIR_DOMAIN_VIRT_KVM) {
                virBufferAsprintf(&buf, "  \"%s/log/libvirt/**/%s.log\" w,\n",
                                  LOCALSTATEDIR, ctl->def->name);
                virBufferAsprintf(&buf, "  \"%s/lib/libvirt/qemu/domain-%s/monitor.sock\" rw,\n",
                                  LOCALSTATEDIR, ctl->def->name);
                virBufferAsprintf(&buf, "  \"%s/lib/libvirt/qemu/domain-%d-%.*s/*\" rw,\n",
                                  LOCALSTATEDIR, ctl->def->id, 20, ctl->def->name);
                virBufferAsprintf(&buf, "  \"%s/libvirt/**/%s.pid\" rwk,\n",
                                  RUNSTATEDIR, ctl->def->name);
                virBufferAsprintf(&buf, "  \"%s/libvirt/**/*.tunnelmigrate.dest.%s\" rw,\n",
                                  RUNSTATEDIR, ctl->def->name);
            }
            if (ctl->files)
                virBufferAdd(&buf, ctl->files, -1);
        }

        included_files = virBufferContentAndReset(&buf);

        /* (re)create the include file using included_files */
        if (ctl->dryrun) {
            vah_info(include_file);
            vah_info(included_files);
            rc = 0;
        } else if (ctl->def->virtType == VIR_DOMAIN_VIRT_LXC) {
            rc = 0;
        } else if ((rc = update_include_file(include_file,
                                             included_files,
                                             ctl->append)) != 0) {
            goto cleanup;
        }


        /* create the profile from TEMPLATE */
        if (ctl->cmd == 'c' || purged) {
            g_autofree char *tmp = g_strdup_printf(
                "  #include if exists <libvirt/%s.files>\n", ctl->uuid);

            if (ctl->dryrun) {
                vah_info(profile);
                vah_info(ctl->uuid);
                vah_info(tmp);
                rc = 0;
            } else if ((rc = create_profile(profile, ctl->uuid, tmp,
                                            ctl->def->virtType)) != 0) {
                vah_error(ctl, 0, _("could not create profile"));
                unlink(include_file);
            }
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
    }
 cleanup:
    vahDeinit(ctl);

    exit(rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
