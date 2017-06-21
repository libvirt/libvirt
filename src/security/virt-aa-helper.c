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
#include <sys/utsname.h>

#include "internal.h"
#include "virbuffer.h"
#include "viralloc.h"
#include "vircommand.h"
#include "virlog.h"

#include "security_driver.h"
#include "security_apparmor.h"
#include "domain_conf.h"
#include "virxml.h"
#include "viruuid.h"
#include "virusb.h"
#include "virpci.h"
#include "virfile.h"
#include "configmake.h"
#include "virrandom.h"
#include "virstring.h"
#include "virgettext.h"

#include "storage/storage_source.h"

#define VIR_FROM_THIS VIR_FROM_SECURITY

static char *progname;

typedef struct {
    bool allowDiskFormatProbing;
    char uuid[PROFILE_NAME_SIZE];       /* UUID of vm */
    bool dryrun;                /* dry run */
    char cmd;                   /* 'c'   create
                                 * 'a'   add (load)
                                 * 'r'   replace
                                 * 'R'   remove */
    char *files;                /* list of files */
    virDomainDefPtr def;        /* VM definition */
    virCapsPtr caps;            /* VM capabilities */
    virDomainXMLOptionPtr xmlopt; /* XML parser data */
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

    VIR_FREE(ctl->def);
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
    printf(_("\n%s [options] [< def.xml]\n\n"
            "  Options:\n"
            "    -a | --add                     load profile\n"
            "    -c | --create                  create profile from template\n"
            "    -d | --dryrun                  dry run\n"
            "    -D | --delete                  unload and delete profile\n"
            "    -f | --add-file <file>         add file to profile\n"
            "    -F | --append-file <file>      append file to profile\n"
            "    -r | --replace                 reload profile\n"
            "    -R | --remove                  unload profile\n"
            "    -h | --help                    this help\n"
            "    -p | --probing [0|1]           allow disk format probing\n"
            "    -u | --uuid <uuid>             uuid (profile name)\n"
            "\n"), progname);

    puts(_("This command is intended to be used by libvirtd "
           "and not used directly.\n"));
    return;
}

static void
vah_error(vahControl * ctl, int doexit, const char *str)
{
    fprintf(stderr, _("%s: error: %s%c"), progname, str, '\n');

    if (doexit) {
        if (ctl != NULL)
            vahDeinit(ctl);
        exit(EXIT_FAILURE);
    }
}

static void
vah_warning(const char *str)
{
    fprintf(stderr, _("%s: warning: %s%c"), progname, str, '\n');
}

static void
vah_info(const char *str)
{
    fprintf(stderr, _("%s:\n%s%c"), progname, str, '\n');
}

/*
 * run an apparmor_parser command
 */
static int
parserCommand(const char *profile_name, const char cmd)
{
    int result = -1;
    char flag[3];
    char *profile;
    int status;
    int ret;

    if (strchr("arR", cmd) == NULL) {
        vah_error(NULL, 0, _("invalid flag"));
        return -1;
    }

    snprintf(flag, 3, "-%c", cmd);

    if (virAsprintfQuiet(&profile, "%s/%s",
                         APPARMOR_DIR "/libvirt", profile_name) < 0) {
        vah_error(NULL, 0, _("profile name exceeds maximum length"));
        return -1;
    }

    if (!virFileExists(profile)) {
        vah_error(NULL, 0, _("profile does not exist"));
        goto cleanup;
    } else {
        const char * const argv[] = {
            "/sbin/apparmor_parser", flag, profile, NULL
        };
        if ((ret = virRun(argv, &status)) != 0 ||
            (WIFEXITED(status) && WEXITSTATUS(status) != 0)) {
            if (ret != 0) {
                vah_error(NULL, 0, _("failed to run apparmor_parser"));
                goto cleanup;
            } else if (cmd == 'R' && WIFEXITED(status) &&
                       WEXITSTATUS(status) == 234) {
                vah_warning(_("unable to unload already unloaded profile"));
            } else {
                vah_error(NULL, 0, _("apparmor_parser exited with error"));
                goto cleanup;
            }
        }
    }

    result = 0;

 cleanup:
    VIR_FREE(profile);

    return result;
}

/*
 * Update the dynamic files
 */
static int
update_include_file(const char *include_file, const char *included_files,
                    bool append)
{
    int rc = -1;
    int plen, flen = 0;
    int fd;
    char *pcontent = NULL;
    char *existing = NULL;
    const char *warning =
         "# DO NOT EDIT THIS FILE DIRECTLY. IT IS MANAGED BY LIBVIRT.\n";

    if (virFileExists(include_file)) {
        flen = virFileReadAll(include_file, MAX_FILE_LEN, &existing);
        if (flen < 0)
            return rc;
    }

    if (append && virFileExists(include_file)) {
        if (virAsprintfQuiet(&pcontent, "%s%s", existing, included_files) == -1) {
            vah_error(NULL, 0, _("could not allocate memory for profile"));
            goto cleanup;
        }
    } else {
        if (virAsprintfQuiet(&pcontent, "%s%s", warning, included_files) == -1) {
            vah_error(NULL, 0, _("could not allocate memory for profile"));
            goto cleanup;
        }
    }

    plen = strlen(pcontent);
    if (plen > MAX_FILE_LEN) {
        vah_error(NULL, 0, _("invalid length for new profile"));
        goto cleanup;
    }

    /* only update the disk profile if it is different */
    if (flen > 0 && flen == plen && STREQLEN(existing, pcontent, plen)) {
        rc = 0;
        goto cleanup;
    }

    /* write the file */
    if ((fd = open(include_file, O_CREAT | O_TRUNC | O_WRONLY, 0644)) == -1) {
        vah_error(NULL, 0, _("failed to create include file"));
        goto cleanup;
    }

    if (safewrite(fd, pcontent, plen) < 0) { /* don't write the '\0' */
        VIR_FORCE_CLOSE(fd);
        vah_error(NULL, 0, _("failed to write to profile"));
        goto cleanup;
    }

    if (VIR_CLOSE(fd) != 0) {
        vah_error(NULL, 0, _("failed to close or write to profile"));
        goto cleanup;
    }
    rc = 0;

 cleanup:
    VIR_FREE(pcontent);
    VIR_FREE(existing);

    return rc;
}

/*
 * Create a profile based on a template
 */
static int
create_profile(const char *profile, const char *profile_name,
               const char *profile_files, int virtType)
{
    char *template;
    char *tcontent = NULL;
    char *pcontent = NULL;
    char *replace_name = NULL;
    char *replace_files = NULL;
    char *tmp = NULL;
    const char *template_name = "\nprofile LIBVIRT_TEMPLATE";
    const char *template_end = "\n}";
    int tlen, plen;
    int fd;
    int rc = -1;
    const char *driver_name = NULL;

    if (virFileExists(profile)) {
        vah_error(NULL, 0, _("profile exists"));
        goto end;
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

    if (virAsprintfQuiet(&template, "%s/TEMPLATE.%s", APPARMOR_DIR "/libvirt",
                         driver_name) < 0) {
        vah_error(NULL, 0, _("template name exceeds maximum length"));
        goto end;
    }

    if (!virFileExists(template)) {
        vah_error(NULL, 0, _("template does not exist"));
        goto end;
    }

    if ((tlen = virFileReadAll(template, MAX_FILE_LEN, &tcontent)) < 0) {
        vah_error(NULL, 0, _("failed to read AppArmor template"));
        goto end;
    }

    if (strstr(tcontent, template_name) == NULL) {
        vah_error(NULL, 0, _("no replacement string in template"));
        goto clean_tcontent;
    }

    if (strstr(tcontent, template_end) == NULL) {
        vah_error(NULL, 0, _("no replacement string in template"));
        goto clean_tcontent;
    }

    /* '\nprofile <profile_name>\0' */
    if (virAsprintfQuiet(&replace_name, "\nprofile %s", profile_name) == -1) {
        vah_error(NULL, 0, _("could not allocate memory for profile name"));
        goto clean_tcontent;
    }

    /* '\n<profile_files>\n}\0' */
    if ((virtType != VIR_DOMAIN_VIRT_LXC) &&
            virAsprintfQuiet(&replace_files, "\n%s\n}", profile_files) == -1) {
        vah_error(NULL, 0, _("could not allocate memory for profile files"));
        VIR_FREE(replace_name);
        goto clean_tcontent;
    }

    plen = tlen + strlen(replace_name) - strlen(template_name) + 1;

    if (virtType != VIR_DOMAIN_VIRT_LXC)
        plen += strlen(replace_files) - strlen(template_end);

    if (plen > MAX_FILE_LEN || plen < tlen) {
        vah_error(NULL, 0, _("invalid length for new profile"));
        goto clean_replace;
    }

    if (!(pcontent = virStringReplace(tcontent, template_name, replace_name)))
        goto clean_all;

    if (virtType != VIR_DOMAIN_VIRT_LXC) {
        if (!(tmp = virStringReplace(pcontent, template_end, replace_files)))
            goto clean_all;
        VIR_FREE(pcontent);
        pcontent = tmp;
        tmp = NULL;
    }

    /* write the file */
    if ((fd = open(profile, O_CREAT | O_EXCL | O_WRONLY, 0644)) == -1) {
        vah_error(NULL, 0, _("failed to create profile"));
        goto clean_all;
    }

    if (safewrite(fd, pcontent, plen - 1) < 0) { /* don't write the '\0' */
        VIR_FORCE_CLOSE(fd);
        vah_error(NULL, 0, _("failed to write to profile"));
        goto clean_all;
    }

    if (VIR_CLOSE(fd) != 0) {
        vah_error(NULL, 0, _("failed to close or write to profile"));
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
    VIR_FREE(template);
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
        "/usr/share/OVMF/",              /* for OVMF images */
        "/usr/share/ovmf/",              /* for OVMF images */
        "/usr/share/AAVMF/",             /* for AAVMF images */
        "/usr/share/qemu-efi/"           /* for AAVMF images */
    };
    /* override the above with these */
    const char * const override[] = {
        "/sys/devices/pci",              /* for hostdev pci devices */
        "/etc/libvirt-sandbox/services/" /* for virt-sandbox service config */
    };

    const int nropaths = ARRAY_CARDINALITY(restricted);
    const int nrwpaths = ARRAY_CARDINALITY(restricted_rw);
    const int nopaths = ARRAY_CARDINALITY(override);

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

    /* disallow RW acess to all paths in restricted and restriced_rw */
    if ((array_starts_with(path, restricted, nropaths) == 0 ||
         array_starts_with(path, restricted_rw, nrwpaths) == 0))
        return 1;

    return 0;
}

static int
verify_xpath_context(xmlXPathContextPtr ctxt)
{
    int rc = -1;
    char *tmp = NULL;

    if (!ctxt) {
        vah_warning(_("Invalid context"));
        goto error;
    }

    /* check if have <name> */
    if (!(tmp = virXPathString("string(./name[1])", ctxt))) {
        vah_warning(_("Could not find <name>"));
        goto error;
    }
    VIR_FREE(tmp);

    /* check if have <uuid> */
    if (!(tmp = virXPathString("string(./uuid[1])", ctxt))) {
        vah_warning(_("Could not find <uuid>"));
        goto error;
    }
    VIR_FREE(tmp);

    rc = 0;

 error:
    return rc;
}

/*
 * Parse the xml we received to fill in the following:
 * ctl->virtType
 * ctl->os
 * ctl->arch
 *
 * These are suitable for setting up a virCapsPtr
 */
static int
caps_mockup(vahControl * ctl, const char *xmlStr)
{
    int rc = -1;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    char *arch;

    if (!(xml = virXMLParseStringCtxt(xmlStr, _("(domain_definition)"),
                                      &ctxt))) {
        goto cleanup;
    }

    if (!xmlStrEqual(ctxt->node->name, BAD_CAST "domain")) {
        vah_error(NULL, 0, _("unexpected root element, expecting <domain>"));
        goto cleanup;
    }

    /* Quick sanity check for some required elements */
    if (verify_xpath_context(ctxt) != 0)
        goto cleanup;

    ctl->virtType = virXPathString("string(./@type)", ctxt);
    if (!ctl->virtType) {
        vah_error(ctl, 0, _("domain type is not defined"));
        goto cleanup;
    }
    ctl->os = virXPathString("string(./os/type[1])", ctxt);
    if (!ctl->os) {
        vah_error(ctl, 0, _("os.type is not defined"));
        goto cleanup;
    }
    arch = virXPathString("string(./os/type[1]/@arch)", ctxt);
    if (!arch) {
        ctl->arch = virArchFromHost();
    } else {
        ctl->arch = virArchFromString(arch);
        VIR_FREE(arch);
    }

    rc = 0;

 cleanup:
    xmlFreeDoc(xml);
    xmlXPathFreeContext(ctxt);

    return rc;
}


static int
get_definition(vahControl * ctl, const char *xmlStr)
{
    int rc = -1, ostype, virtType;
    virCapsGuestPtr guest;  /* this is freed when caps is freed */

    /*
     * mock up some capabilities. We don't currently use these explicitly,
     * but need them for virDomainDefParseString().
     */
    if (caps_mockup(ctl, xmlStr) != 0)
        goto exit;

    if ((ctl->caps = virCapabilitiesNew(ctl->arch, true, true)) == NULL) {
        vah_error(ctl, 0, _("could not allocate memory"));
        goto exit;
    }

    if (!(ctl->xmlopt = virDomainXMLOptionNew(NULL, NULL, NULL, NULL, NULL))) {
        vah_error(ctl, 0, _("Failed to create XML config object"));
        goto exit;
    }

    if ((ostype = virDomainOSTypeFromString(ctl->os)) < 0) {
        vah_error(ctl, 0, _("unknown OS type"));
        goto exit;
    }

    if ((guest = virCapabilitiesAddGuest(ctl->caps,
                                         ostype,
                                         ctl->arch,
                                         NULL,
                                         NULL,
                                         0,
                                         NULL)) == NULL) {
        vah_error(ctl, 0, _("could not allocate memory"));
        goto exit;
    }

    if ((virtType = virDomainVirtTypeFromString(ctl->virtType)) < 0) {
        vah_error(ctl, 0, _("unknown virtualization type"));
        goto exit;
    }

    if (virCapabilitiesAddGuestDomain(guest,
                                      virtType,
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL) {
        vah_error(ctl, 0, _("could not allocate memory"));
        goto exit;
    }

    ctl->def = virDomainDefParseString(xmlStr,
                                       ctl->caps, ctl->xmlopt, NULL,
                                       VIR_DOMAIN_DEF_PARSE_SKIP_SECLABEL |
                                       VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE);

    if (ctl->def == NULL) {
        vah_error(ctl, 0, _("could not parse XML"));
        goto exit;
    }

    if (!ctl->def->name) {
        vah_error(ctl, 0, _("could not find name in XML"));
        goto exit;
    }

    if (valid_name(ctl->def->name) != 0) {
        vah_error(ctl, 0, _("bad name"));
        goto exit;
    }

    rc = 0;

 exit:
    return rc;
}

/**
  * The permissions allowed are apparmor valid permissions and 'R'. 'R' stands for
  * read with no explicit deny rule.
  */
static int
vah_add_path(virBufferPtr buf, const char *path, const char *perms, bool recursive)
{
    char *tmp = NULL;
    int rc = -1;
    bool readonly = true;
    bool explicit_deny_rule = true;
    char *sub = NULL;
    char *perms_new = NULL;

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

    if (virFileExists(path)) {
        if ((tmp = realpath(path, NULL)) == NULL) {
            vah_error(NULL, 0, path);
            vah_error(NULL, 0, _("could not find realpath for disk"));
            return rc;
        }
    } else if (VIR_STRDUP_QUIET(tmp, path) < 0) {
        return rc;
    }

    if (VIR_STRDUP_QUIET(perms_new, perms) < 0)
        goto cleanup;

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
        goto cleanup;
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

 cleanup:
    VIR_FREE(perms_new);
    VIR_FREE(tmp);

    return rc;
}

static int
vah_add_file(virBufferPtr buf, const char *path, const char *perms)
{
    return vah_add_path(buf, path, perms, false);
}

static int
vah_add_file_chardev(virBufferPtr buf,
                     const char *path,
                     const char *perms,
                     const int type)
{
    char *pipe_in;
    char *pipe_out;
    int rc = -1;

    if (type == VIR_DOMAIN_CHR_TYPE_PIPE) {
        /* add the pipe input */
        if (virAsprintfQuiet(&pipe_in, "%s.in", path) == -1) {
            vah_error(NULL, 0, _("could not allocate memory"));
            goto cleanup;
        }

        if (vah_add_file(buf, pipe_in, perms) != 0)
            goto clean_pipe_in;

        /* add the pipe output */
        if (virAsprintfQuiet(&pipe_out, "%s.out", path) == -1) {
            vah_error(NULL, 0, _("could not allocate memory"));
            goto clean_pipe_in;
        }

        if (vah_add_file(buf, pipe_out, perms) != 0)
            goto clean_pipe_out;

        rc = 0;
      clean_pipe_out:
        VIR_FREE(pipe_out);
      clean_pipe_in:
        VIR_FREE(pipe_in);
    } else {
        /* add the file */
        if (vah_add_file(buf, path, perms) != 0)
            goto cleanup;
        rc = 0;
    }

 cleanup:
    return rc;
}

static int
file_iterate_hostdev_cb(virUSBDevicePtr dev ATTRIBUTE_UNUSED,
                        const char *file, void *opaque)
{
    virBufferPtr buf = opaque;
    return vah_add_file(buf, file, "rw");
}

static int
file_iterate_pci_cb(virPCIDevicePtr dev ATTRIBUTE_UNUSED,
                    const char *file, void *opaque)
{
    virBufferPtr buf = opaque;
    return vah_add_file(buf, file, "rw");
}

static int
add_file_path(virDomainDiskDefPtr disk,
              const char *path,
              size_t depth,
              void *opaque)
{
    virBufferPtr buf = opaque;
    int ret;

    if (depth == 0) {
        if (disk->src->readonly)
            ret = vah_add_file(buf, path, "r");
        else
            ret = vah_add_file(buf, path, "rw");
    } else {
        ret = vah_add_file(buf, path, "r");
    }

    if (ret != 0)
        ret = -1;

    return ret;
}

static int
get_files(vahControl * ctl)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    int rc = -1;
    size_t i;
    char *uuid;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    bool needsVfio = false, needsvhost = false;

    /* verify uuid is same as what we were given on the command line */
    virUUIDFormat(ctl->def->uuid, uuidstr);
    if (virAsprintfQuiet(&uuid, "%s%s", AA_PREFIX, uuidstr) == -1) {
        vah_error(ctl, 0, _("could not allocate memory"));
        return rc;
    }

    if (STRNEQ(uuid, ctl->uuid)) {
        vah_error(ctl, 0, _("given uuid does not match XML uuid"));
        goto cleanup;
    }

    for (i = 0; i < ctl->def->ndisks; i++) {
        virDomainDiskDefPtr disk = ctl->def->disks[i];

        if (!virDomainDiskGetSource(disk))
            continue;
        /* XXX - if we knew the qemu user:group here we could send it in
         *        so that the open could be re-tried as that user:group.
         */
        if (!disk->src->backingStore) {
            bool probe = ctl->allowDiskFormatProbing;
            virStorageFileGetMetadata(disk->src, -1, -1, probe, false);
        }

        /* XXX passing ignoreOpenFailure = true to get back to the behavior
         * from before using virDomainDiskDefForeachPath. actually we should
         * be passing ignoreOpenFailure = false and handle open errors more
         * careful than just ignoring them.
         */
        if (virDomainDiskDefForeachPath(disk, true, add_file_path, &buf) < 0)
            goto cleanup;
    }

    for (i = 0; i < ctl->def->nserials; i++)
        if (ctl->def->serials[i] &&
            (ctl->def->serials[i]->source->type == VIR_DOMAIN_CHR_TYPE_PTY ||
             ctl->def->serials[i]->source->type == VIR_DOMAIN_CHR_TYPE_DEV ||
             ctl->def->serials[i]->source->type == VIR_DOMAIN_CHR_TYPE_FILE ||
             ctl->def->serials[i]->source->type == VIR_DOMAIN_CHR_TYPE_UNIX ||
             ctl->def->serials[i]->source->type == VIR_DOMAIN_CHR_TYPE_PIPE) &&
            ctl->def->serials[i]->source->data.file.path &&
            ctl->def->serials[i]->source->data.file.path[0] != '\0')
            if (vah_add_file_chardev(&buf,
                                     ctl->def->serials[i]->source->data.file.path,
                                     "rw",
                                     ctl->def->serials[i]->source->type) != 0)
                goto cleanup;

    for (i = 0; i < ctl->def->nconsoles; i++)
        if (ctl->def->consoles[i] &&
            (ctl->def->consoles[i]->source->type == VIR_DOMAIN_CHR_TYPE_PTY ||
             ctl->def->consoles[i]->source->type == VIR_DOMAIN_CHR_TYPE_DEV ||
             ctl->def->consoles[i]->source->type == VIR_DOMAIN_CHR_TYPE_FILE ||
             ctl->def->consoles[i]->source->type == VIR_DOMAIN_CHR_TYPE_UNIX ||
             ctl->def->consoles[i]->source->type == VIR_DOMAIN_CHR_TYPE_PIPE) &&
            ctl->def->consoles[i]->source->data.file.path &&
            ctl->def->consoles[i]->source->data.file.path[0] != '\0')
            if (vah_add_file(&buf,
                             ctl->def->consoles[i]->source->data.file.path, "rw") != 0)
                goto cleanup;

    for (i = 0; i < ctl->def->nparallels; i++)
        if (ctl->def->parallels[i] &&
            (ctl->def->parallels[i]->source->type == VIR_DOMAIN_CHR_TYPE_PTY ||
             ctl->def->parallels[i]->source->type == VIR_DOMAIN_CHR_TYPE_DEV ||
             ctl->def->parallels[i]->source->type == VIR_DOMAIN_CHR_TYPE_FILE ||
             ctl->def->parallels[i]->source->type == VIR_DOMAIN_CHR_TYPE_UNIX ||
             ctl->def->parallels[i]->source->type == VIR_DOMAIN_CHR_TYPE_PIPE) &&
            ctl->def->parallels[i]->source->data.file.path &&
            ctl->def->parallels[i]->source->data.file.path[0] != '\0')
            if (vah_add_file_chardev(&buf,
                                     ctl->def->parallels[i]->source->data.file.path,
                                     "rw",
                                     ctl->def->parallels[i]->source->type) != 0)
                goto cleanup;

    for (i = 0; i < ctl->def->nchannels; i++)
        if (ctl->def->channels[i] &&
            (ctl->def->channels[i]->source->type == VIR_DOMAIN_CHR_TYPE_PTY ||
             ctl->def->channels[i]->source->type == VIR_DOMAIN_CHR_TYPE_DEV ||
             ctl->def->channels[i]->source->type == VIR_DOMAIN_CHR_TYPE_FILE ||
             ctl->def->channels[i]->source->type == VIR_DOMAIN_CHR_TYPE_UNIX ||
             ctl->def->channels[i]->source->type == VIR_DOMAIN_CHR_TYPE_PIPE) &&
            ctl->def->channels[i]->source->data.file.path &&
            ctl->def->channels[i]->source->data.file.path[0] != '\0')
            if (vah_add_file_chardev(&buf,
                                     ctl->def->channels[i]->source->data.file.path,
                                     "rw",
                                     ctl->def->channels[i]->source->type) != 0)
                goto cleanup;

    if (ctl->def->os.kernel)
        if (vah_add_file(&buf, ctl->def->os.kernel, "r") != 0)
            goto cleanup;

    if (ctl->def->os.initrd)
        if (vah_add_file(&buf, ctl->def->os.initrd, "r") != 0)
            goto cleanup;

    if (ctl->def->os.dtb)
        if (vah_add_file(&buf, ctl->def->os.dtb, "r") != 0)
            goto cleanup;

    if (ctl->def->os.slic_table)
        if (vah_add_file(&buf, ctl->def->os.slic_table, "r") != 0)
            goto cleanup;

    if (ctl->def->os.loader && ctl->def->os.loader->path)
        if (vah_add_file(&buf, ctl->def->os.loader->path, "r") != 0)
            goto cleanup;

    if (ctl->def->os.loader && ctl->def->os.loader->nvram)
        if (vah_add_file(&buf, ctl->def->os.loader->nvram, "rw") != 0)
            goto cleanup;

    for (i = 0; i < ctl->def->ngraphics; i++) {
        virDomainGraphicsDefPtr graphics = ctl->def->graphics[i];
        size_t n;

        for (n = 0; n < graphics->nListens; n++) {
            virDomainGraphicsListenDef listenObj = graphics->listens[n];

            if (listenObj.type == VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET &&
                listenObj.socket &&
                vah_add_file(&buf, listenObj.socket, "rw"))
                goto cleanup;
        }
    }

    if (ctl->def->ngraphics == 1 &&
        ctl->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_SDL)
        if (vah_add_file(&buf, ctl->def->graphics[0]->data.sdl.xauth,
                         "r") != 0)
            goto cleanup;

    for (i = 0; i < ctl->def->nhostdevs; i++)
        if (ctl->def->hostdevs[i]) {
            virDomainHostdevDefPtr dev = ctl->def->hostdevs[i];
            virDomainHostdevSubsysUSBPtr usbsrc = &dev->source.subsys.u.usb;
            switch (dev->source.subsys.type) {
            case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB: {
                virUSBDevicePtr usb =
                    virUSBDeviceNew(usbsrc->bus, usbsrc->device, NULL);

                if (usb == NULL)
                    continue;

                rc = virUSBDeviceFileIterate(usb, file_iterate_hostdev_cb, &buf);
                virUSBDeviceFree(usb);
                if (rc != 0)
                    goto cleanup;
                break;
            }

            case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI: {
                virPCIDevicePtr pci = virPCIDeviceNew(
                           dev->source.subsys.u.pci.addr.domain,
                           dev->source.subsys.u.pci.addr.bus,
                           dev->source.subsys.u.pci.addr.slot,
                           dev->source.subsys.u.pci.addr.function);

                virDomainHostdevSubsysPCIBackendType backend = dev->source.subsys.u.pci.backend;
                if (backend == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO ||
                        backend == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_DEFAULT) {
                    needsVfio = true;
                }

                if (pci == NULL)
                    continue;

                rc = virPCIDeviceFileIterate(pci, file_iterate_pci_cb, &buf);
                virPCIDeviceFree(pci);

                break;
            }

            default:
                rc = 0;
                break;
            } /* switch */
        }

    for (i = 0; i < ctl->def->nfss; i++) {
        if (ctl->def->fss[i] &&
                ctl->def->fss[i]->type == VIR_DOMAIN_FS_TYPE_MOUNT &&
                (ctl->def->fss[i]->fsdriver == VIR_DOMAIN_FS_DRIVER_TYPE_PATH ||
                 ctl->def->fss[i]->fsdriver == VIR_DOMAIN_FS_DRIVER_TYPE_DEFAULT) &&
                ctl->def->fss[i]->src) {
            virDomainFSDefPtr fs = ctl->def->fss[i];

            /* We don't need to add deny rw rules for readonly mounts,
             * this can only lead to troubles when mounting / readonly.
             */
            if (vah_add_path(&buf, fs->src->path, fs->readonly ? "R" : "rw", true) != 0)
                goto cleanup;
        }
    }

    for (i = 0; i < ctl->def->nnets; i++) {
        if (ctl->def->nets[i] &&
                ctl->def->nets[i]->type == VIR_DOMAIN_NET_TYPE_VHOSTUSER &&
                ctl->def->nets[i]->data.vhostuser) {
            virDomainChrSourceDefPtr vhu = ctl->def->nets[i]->data.vhostuser;

            if (vah_add_file_chardev(&buf, vhu->data.nix.path, "rw",
                       vhu->type) != 0)
                goto cleanup;
        }
    }

    if (ctl->def->virtType == VIR_DOMAIN_VIRT_KVM) {
        for (i = 0; i < ctl->def->nnets; i++) {
            virDomainNetDefPtr net = ctl->def->nets[i];
            if (net && net->model) {
                if (net->driver.virtio.name == VIR_DOMAIN_NET_BACKEND_TYPE_QEMU)
                    continue;
                if (STRNEQ(net->model, "virtio"))
                    continue;
            }
            needsvhost = true;
        }
    }
    if (needsvhost)
        virBufferAddLit(&buf, "  /dev/vhost-net rw,\n");

    if (needsVfio) {
        virBufferAddLit(&buf, "  /dev/vfio/vfio rw,\n");
        virBufferAddLit(&buf, "  /dev/vfio/[0-9]* rw,\n");
    }

    if (ctl->newfile)
        if (vah_add_file(&buf, ctl->newfile, "rw") != 0)
            goto cleanup;

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        vah_error(NULL, 0, _("failed to allocate file buffer"));
        goto cleanup;
    }

    rc = 0;
    ctl->files = virBufferContentAndReset(&buf);

 cleanup:
    VIR_FREE(uuid);
    return rc;
}

static int
vahParseArgv(vahControl * ctl, int argc, char **argv)
{
    int arg, idx = 0;
    struct option opt[] = {
        {"probing", 1, 0, 'p' },
        {"add", 0, 0, 'a'},
        {"create", 0, 0, 'c'},
        {"dryrun", 0, 0, 'd'},
        {"delete", 0, 0, 'D'},
        {"add-file", 0, 0, 'f'},
        {"append-file", 0, 0, 'F'},
        {"help", 0, 0, 'h'},
        {"replace", 0, 0, 'r'},
        {"remove", 0, 0, 'R'},
        {"uuid", 1, 0, 'u'},
        {0, 0, 0, 0}
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
                if (VIR_STRDUP_QUIET(ctl->newfile, optarg) < 0)
                    vah_error(ctl, 1, _("could not allocate memory for disk"));
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
                if (virStrcpy((char *) ctl->uuid, optarg,
                    PROFILE_NAME_SIZE) == NULL)
                    vah_error(ctl, 1, _("error copying UUID"));
                break;
            case 'p':
                if (STREQ(optarg, "1"))
                    ctl->allowDiskFormatProbing = true;
                else
                    ctl->allowDiskFormatProbing = false;
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
        char *xmlStr = NULL;
        if (virFileReadLimFD(STDIN_FILENO, MAX_FILE_LEN, &xmlStr) < 0)
            vah_error(ctl, 1, _("could not read xml file"));

        if (get_definition(ctl, xmlStr) != 0 || ctl->def == NULL) {
            VIR_FREE(xmlStr);
            vah_error(ctl, 1, _("could not get VM definition"));
        }
        VIR_FREE(xmlStr);

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
    vahControl _ctl, *ctl = &_ctl;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    int rc = -1;
    char *profile = NULL;
    char *include_file = NULL;

    if (virGettextInitialize() < 0 ||
        virThreadInitialize() < 0 ||
        virErrorInitialize() < 0) {
        fprintf(stderr, _("%s: initialization failed\n"), argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Initialize the log system */
    virLogSetFromEnv();

    /* clear the environment */
    environ = NULL;
    if (setenv("PATH", "/sbin:/usr/sbin", 1) != 0)
        vah_error(ctl, 1, _("could not set PATH"));

    /* ensure the traditional IFS setting */
    if (setenv("IFS", " \t\n", 1) != 0)
        vah_error(ctl, 1, _("could not set IFS"));

    if (!(progname = strrchr(argv[0], '/')))
        progname = argv[0];
    else
        progname++;

    memset(ctl, 0, sizeof(vahControl));

    if (vahParseArgv(ctl, argc, argv) != 0)
        vah_error(ctl, 1, _("could not parse arguments"));

    if (virAsprintfQuiet(&profile, "%s/%s",
                         APPARMOR_DIR "/libvirt", ctl->uuid) < 0)
        vah_error(ctl, 0, _("could not allocate memory"));

    if (virAsprintfQuiet(&include_file, "%s/%s.files",
                         APPARMOR_DIR "/libvirt", ctl->uuid) < 0)
        vah_error(ctl, 0, _("could not allocate memory"));

    if (ctl->cmd == 'a') {
        rc = parserLoad(ctl->uuid);
    } else if (ctl->cmd == 'R' || ctl->cmd == 'D') {
        rc = parserRemove(ctl->uuid);
        if (ctl->cmd == 'D') {
            unlink(include_file);
            unlink(profile);
        }
    } else if (ctl->cmd == 'c' || ctl->cmd == 'r') {
        char *included_files = NULL;

        if (ctl->cmd == 'c' && virFileExists(profile))
            vah_error(ctl, 1, _("profile exists"));

        if (ctl->append && ctl->newfile) {
            if (vah_add_file(&buf, ctl->newfile, "rw") != 0)
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
                virBufferAsprintf(&buf, "  \"%s/lib/libvirt/qemu/channel/target/domain-%d-%.*s/*\" rw,\n",
                                  LOCALSTATEDIR, ctl->def->id, 20, ctl->def->name);
                virBufferAsprintf(&buf, "  \"%s/run/libvirt/**/%s.pid\" rwk,\n",
                                  LOCALSTATEDIR, ctl->def->name);
                virBufferAsprintf(&buf, "  \"/run/libvirt/**/%s.pid\" rwk,\n",
                                  ctl->def->name);
                virBufferAsprintf(&buf, "  \"%s/run/libvirt/**/*.tunnelmigrate.dest.%s\" rw,\n",
                                  LOCALSTATEDIR, ctl->def->name);
                virBufferAsprintf(&buf, "  \"/run/libvirt/**/*.tunnelmigrate.dest.%s\" rw,\n",
                                  ctl->def->name);
            }
            if (ctl->files)
                virBufferAdd(&buf, ctl->files, -1);
        }

        if (virBufferError(&buf)) {
            virBufferFreeAndReset(&buf);
            vah_error(ctl, 1, _("failed to allocate buffer"));
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
        if (ctl->cmd == 'c') {
            char *tmp = NULL;
            if (virAsprintfQuiet(&tmp, "  #include <libvirt/%s.files>\n",
                                 ctl->uuid) == -1) {
                vah_error(ctl, 0, _("could not allocate memory"));
                goto cleanup;
            }

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
      cleanup:
        VIR_FREE(included_files);
    }

    vahDeinit(ctl);

    VIR_FREE(profile);
    VIR_FREE(include_file);

    exit(rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
