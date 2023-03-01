/*
 * Copyright (C) 2014 Red Hat, Inc.
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
 */

#include <config.h>

#include "testutils.h"

#ifdef __linux__

# include <fcntl.h>
# include <sys/stat.h>
# include <unistd.h>
# include "virlog.h"
# include "virscsihost.h"

# define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.scsihosttest");

char *scsihost_class_path;
# define TEST_SCSIHOST_CLASS_PATH scsihost_class_path

/*
 * Initialized/create a mock sysfs environment with 4 scsi_host devices
 * located on "0000:00:1f.1" and "0000:00:1f.2".  Each directory will
 * contain 4 unique_id files having the same value.
 *
 * The environment is:
 *
 *  4 files:
 *
 *     sys/devices/pci0000:00/0000:00:1f.1/ata1/host0/scsi_host/host0/unique_id
 *     sys/devices/pci0000:00/0000:00:1f.1/ata2/host1/scsi_host/host1/unique_id
 *     sys/devices/pci0000:00/0000:00:1f.2/ata1/host0/scsi_host/host0/unique_id
 *     sys/devices/pci0000:00/0000:00:1f.2/ata2/host1/scsi_host/host1/unique_id
 *
 *  4 symlinks:
 *
 *     sys/class/scsi_host/host0 -> link to 1f.1 host 0
 *     sys/class/scsi_host/host1 -> link to 1f.1 host 1
 *     sys/class/scsi_host/host2 -> link to 1f.2 host 0
 *     sys/class/scsi_host/host3 -> link to 1f.2 host 1
 *
 *  The unique_id's for host0 and host2 are set to "1"
 *  The unique_id's for host1 and host3 are set to "2"
 */

static int
create_scsihost(const char *fakesysfsdir, const char *devicepath,
                const char *unique_id, const char *hostname)
{
    g_autofree char *unique_id_path = NULL;
    g_autofree char *link_path = NULL;
    char *spot;
    VIR_AUTOCLOSE fd = -1;

    unique_id_path = g_strdup_printf("%s/devices/pci0000:00/%s/unique_id",
                                     fakesysfsdir, devicepath);
    link_path = g_strdup_printf("%s/class/scsi_host/%s",
                                fakesysfsdir, hostname);

    /* Rather than create path & file, temporarily snip off the file to
     * create the path
     */
    if (!(spot = strstr(unique_id_path, "unique_id"))) {
        fprintf(stderr, "Did not find unique_id in path\n");
        return -1;
    }
    spot--;
    *spot = '\0';
    if (g_mkdir_with_parents(unique_id_path, 0755) < 0) {
        fprintf(stderr, "Unable to make path to '%s'\n", unique_id_path);
        return -1;
    }
    *spot = '/';

    /* Rather than create path & file, temporarily snip off the file to
     * create the path
     */
    if (!(spot = strstr(link_path, hostname))) {
        fprintf(stderr, "Did not find hostname in path\n");
        return -1;
    }
    spot--;
    *spot = '\0';
    if (g_mkdir_with_parents(link_path, 0755) < 0) {
        fprintf(stderr, "Unable to make path to '%s'\n", link_path);
        return -1;
    }
    *spot = '/';

    if ((fd = open(unique_id_path, O_CREAT|O_WRONLY, 0444)) < 0) {
        fprintf(stderr, "Unable to create '%s'\n", unique_id_path);
        return -1;
    }

    if (safewrite(fd, unique_id, 1) != 1) {
        fprintf(stderr, "Unable to write '%s'\n", unique_id);
        return -1;
    }
    VIR_DEBUG("Created unique_id '%s'", unique_id_path);

    /* The link is to the path not the file - so remove the file */
    if (!(spot = strstr(unique_id_path, "unique_id"))) {
        fprintf(stderr, "Did not find unique_id in path\n");
        return -1;
    }
    spot--;
    *spot = '\0';
    if (symlink(unique_id_path, link_path) < 0) {
        fprintf(stderr, "Unable to create symlink '%s' to '%s'\n",
                link_path, unique_id_path);
        return -1;
    }
    VIR_DEBUG("Created symlink '%s'", link_path);

    return 0;
}

static int
init_scsihost_sysfs(const char *fakesysfsdir)
{
    int ret = 0;

    if (create_scsihost(fakesysfsdir,
                        "0000:00:1f.1/ata1/host0/scsi_host/host0",
                        "1", "host0") < 0 ||
        create_scsihost(fakesysfsdir,
                        "0000:00:1f.1/ata2/host1/scsi_host/host1",
                        "2", "host1") < 0 ||
        create_scsihost(fakesysfsdir,
                        "0000:00:1f.2/ata1/host0/scsi_host/host0",
                        "1", "host2") < 0 ||
        create_scsihost(fakesysfsdir,
                        "0000:00:1f.2/ata2/host1/scsi_host/host1",
                        "2", "host3") < 0)
        ret = -1;

    return ret;
}

/* Test virReadSCSIUniqueId */
static int
testVirReadSCSIUniqueId(const void *data G_GNUC_UNUSED)
{
    int hostnum, unique_id;

    for (hostnum = 0; hostnum < 4; hostnum++) {
        if ((unique_id = virSCSIHostGetUniqueId(TEST_SCSIHOST_CLASS_PATH,
                                                hostnum)) < 0) {
            fprintf(stderr, "Failed to read hostnum=%d unique_id\n", hostnum);
            return -1;
        }

        /* host0 and host2 have unique_id == 1
         * host1 and host3 have unique_id == 2
         */
        if ((hostnum == 0 || hostnum == 2) && unique_id != 1) {
            fprintf(stderr, "The unique_id='%d' for hostnum=%d is wrong\n",
                    unique_id, hostnum);
            return -1;
        } else if ((hostnum == 1 || hostnum == 3) && unique_id != 2) {
            fprintf(stderr, "The unique_id='%d' for hostnum=%d is wrong\n",
                    unique_id, hostnum);
            return -1;
        }
    }

    return 0;
}

/* Test virSCSIHostFindByPCI */
static int
testVirFindSCSIHostByPCI(const void *data G_GNUC_UNUSED)
{
    unsigned int unique_id1 = 1;
    unsigned int unique_id2 = 2;
    const char *pci_addr1 = "0000:00:1f.1";
    const char *pci_addr2 = "0000:00:1f.2";
    char *ret_host = NULL;
    int ret = -1;

    if (!(ret_host = virSCSIHostFindByPCI(TEST_SCSIHOST_CLASS_PATH,
                                          pci_addr1, unique_id1)) ||
        STRNEQ(ret_host, "host0"))
        goto cleanup;
    VIR_FREE(ret_host);

    if (!(ret_host = virSCSIHostFindByPCI(TEST_SCSIHOST_CLASS_PATH,
                                          pci_addr1, unique_id2)) ||
        STRNEQ(ret_host, "host1"))
        goto cleanup;
    VIR_FREE(ret_host);

    if (!(ret_host = virSCSIHostFindByPCI(TEST_SCSIHOST_CLASS_PATH,
                                          pci_addr2, unique_id1)) ||
        STRNEQ(ret_host, "host2"))
        goto cleanup;
    VIR_FREE(ret_host);

    if (!(ret_host = virSCSIHostFindByPCI(TEST_SCSIHOST_CLASS_PATH,
                                          pci_addr2, unique_id2)) ||
        STRNEQ(ret_host, "host3"))
        goto cleanup;
    VIR_FREE(ret_host);

    ret = 0;

 cleanup:
    VIR_FREE(ret_host);
    return ret;
}

static int
mymain(void)
{
    int ret = -1;
    const char *fakerootdir = NULL;
    g_autofree char *fakesysfsdir = NULL;

    if (!(fakerootdir = g_getenv("LIBVIRT_FAKE_ROOT_DIR")))
        return EXIT_FAILURE;

    fakesysfsdir = g_strdup_printf("%s/sys", fakerootdir);

    if (init_scsihost_sysfs(fakesysfsdir) < 0) {
        fprintf(stderr, "Failed to create fakesysfs='%s'\n", fakesysfsdir);
        goto cleanup;
    }

    scsihost_class_path = g_strdup_printf("%s/class/scsi_host", fakesysfsdir);
    VIR_DEBUG("Reading from '%s'", scsihost_class_path);

    if (virTestRun("testVirReadSCSIUniqueId",
                   testVirReadSCSIUniqueId, NULL) < 0) {
        ret = -1;
        goto cleanup;
    }

    if (virTestRun("testVirFindSCSIHostByPCI",
                   testVirFindSCSIHostByPCI, NULL) < 0) {
        ret = -1;
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(scsihost_class_path);
    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
#else
int
main(void)
{
    return EXIT_AM_SKIP;
}
#endif
