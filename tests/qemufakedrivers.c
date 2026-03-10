/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <config.h>

#include "qemufakedrivers.h"
#include "testutils.h"
#include "datatypes.h"
#include "storage_conf.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

static unsigned char *
fakeSecretGetValue(virSecretPtr obj G_GNUC_UNUSED,
                   size_t *value_size,
                   unsigned int fakeflags G_GNUC_UNUSED)
{
    char *secret;
    secret = g_strdup("AQCVn5hO6HzFAhAAq0NCv8jtJcIcE+HOBlMQ1A");
    *value_size = strlen(secret);
    return (unsigned char *) secret;
}


static virSecretPtr
fakeSecretLookupByUsage(virConnectPtr conn,
                        int usageType,
                        const char *usageID)
{
    unsigned char uuid[VIR_UUID_BUFLEN];
    if (usageType == VIR_SECRET_USAGE_TYPE_VOLUME) {
        if (!STRPREFIX(usageID, "/storage/guest_disks/")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "test provided invalid volume storage prefix '%s'",
                           usageID);
            return NULL;
        }
    } else if (STRNEQ(usageID, "mycluster_myname") &&
               STRNEQ(usageID, "client.admin secret")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "test provided incorrect usage '%s'", usageID);
        return NULL;
    }

    if (virUUIDGenerate(uuid) < 0)
        return NULL;

    return virGetSecret(conn, uuid, usageType, usageID);
}


static virSecretPtr
fakeSecretLookupByUUID(virConnectPtr conn,
                       const unsigned char *uuid)
{
    /* NB: This mocked value could be "tls" or "volume" depending on
     * which test is being run, we'll leave at NONE (or 0) */
    return virGetSecret(conn, uuid, VIR_SECRET_USAGE_TYPE_NONE, "");
}


static virSecretDriver fakeSecretDriver = {
    .secretLookupByUUID = fakeSecretLookupByUUID,
    .secretLookupByUsage = fakeSecretLookupByUsage,
    .secretGetValue = fakeSecretGetValue,
};


virSecretDriver *
testQemuGetFakeSecretDriver(void)
{
    return &fakeSecretDriver;
}


#define STORAGE_POOL_XML_PATH "storagepoolxml2xmlout/"
static const unsigned char fakeUUID[VIR_UUID_BUFLEN] = "fakeuuid";

static virStoragePoolPtr
fakeStoragePoolLookupByName(virConnectPtr conn,
                            const char *name)
{
    g_autofree char *xmlpath = NULL;

    if (STRNEQ(name, "inactive")) {
        xmlpath = g_strdup_printf("%s/%s%s.xml", abs_srcdir,
                                  STORAGE_POOL_XML_PATH, name);

        if (!virFileExists(xmlpath)) {
            virReportError(VIR_ERR_NO_STORAGE_POOL,
                           "File '%s' not found", xmlpath);
            return NULL;
        }
    }

    return virGetStoragePool(conn, name, fakeUUID, NULL, NULL);
}


static virStorageVolPtr
fakeStorageVolLookupByName(virStoragePoolPtr pool,
                           const char *name)
{
    g_auto(GStrv) volinfo = NULL;

    if (STREQ(pool->name, "inactive")) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "storage pool '%s' is not active", pool->name);
        return NULL;
    }

    if (STREQ(name, "nonexistent")) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       "no storage vol with matching name '%s'", name);
        return NULL;
    }

    if (!(volinfo = g_strsplit(name, "+", 2)))
        return NULL;

    if (!volinfo[1]) {
        return virGetStorageVol(pool->conn, pool->name, name, "block", NULL, NULL);
    }

    return virGetStorageVol(pool->conn, pool->name, volinfo[1], volinfo[0],
                           NULL, NULL);
}


static int
fakeStorageVolGetInfo(virStorageVolPtr vol,
                      virStorageVolInfoPtr info)
{
    memset(info, 0, sizeof(*info));

    info->type = virStorageVolTypeFromString(vol->key);

    if (info->type < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Invalid volume type '%s'", vol->key);
        return -1;
    }

    return 0;
}


static char *
fakeStorageVolGetPath(virStorageVolPtr vol)
{
    return g_strdup_printf("/some/%s/device/%s", vol->key, vol->name);
}


static char *
fakeStoragePoolGetXMLDesc(virStoragePoolPtr pool,
                          unsigned int flags_unused G_GNUC_UNUSED)
{
    g_autofree char *xmlpath = NULL;
    char *xmlbuf = NULL;

    if (STREQ(pool->name, "inactive")) {
        virReportError(VIR_ERR_NO_STORAGE_POOL, NULL);
        return NULL;
    }

    xmlpath = g_strdup_printf("%s/%s%s.xml", abs_srcdir, STORAGE_POOL_XML_PATH,
                              pool->name);

    if (virTestLoadFile(xmlpath, &xmlbuf) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "failed to load XML file '%s'",
                       xmlpath);
        return NULL;
    }

    return xmlbuf;
}


static int
fakeStoragePoolIsActive(virStoragePoolPtr pool)
{
    if (STREQ(pool->name, "inactive"))
        return 0;

    return 1;
}


/* Test storage pool implementation
 *
 * These functions aid testing of storage pool related stuff when creating a
 * qemu command line.
 *
 * There are a few "magic" values to pass to these functions:
 *
 * 1) "inactive" as a pool name to create an inactive pool. All other names are
 * interpreted as file names in storagepoolxml2xmlout/ and are used as the
 * definition for the pool. If the file doesn't exist the pool doesn't exist.
 *
 * 2) "nonexistent" returns an error while looking up a volume. Otherwise
 * pattern VOLUME_TYPE+VOLUME_PATH can be used to simulate a volume in a pool.
 * This creates a fake path for this volume. If the '+' sign is omitted, block
 * type is assumed.
 */
static virStorageDriver fakeStorageDriver = {
    .storagePoolLookupByName = fakeStoragePoolLookupByName,
    .storageVolLookupByName = fakeStorageVolLookupByName,
    .storagePoolGetXMLDesc = fakeStoragePoolGetXMLDesc,
    .storageVolGetPath = fakeStorageVolGetPath,
    .storageVolGetInfo = fakeStorageVolGetInfo,
    .storagePoolIsActive = fakeStoragePoolIsActive,
};


virStorageDriver *
testQemuGetFakeStorageDriver(void)
{
    return &fakeStorageDriver;
}


/* virNetDevOpenvswitchGetVhostuserIfname mocks a portdev name - handle that */
static virNWFilterBindingPtr
fakeNWFilterBindingLookupByPortDev(virConnectPtr conn,
                                   const char *portdev)
{
    if (STREQ(portdev, "vhost-user0"))
        return virGetNWFilterBinding(conn, "fake_vnet0", "fakeFilterName");

    virReportError(VIR_ERR_NO_NWFILTER_BINDING,
                   "no nwfilter binding for port dev '%s'", portdev);
    return NULL;
}


static int
fakeNWFilterBindingDelete(virNWFilterBindingPtr binding G_GNUC_UNUSED)
{
    return 0;
}


static virNWFilterDriver fakeNWFilterDriver = {
    .nwfilterBindingLookupByPortDev = fakeNWFilterBindingLookupByPortDev,
    .nwfilterBindingDelete = fakeNWFilterBindingDelete,
};


virNWFilterDriver *
testQemuGetFakeNWFilterDriver(void)
{
    return &fakeNWFilterDriver;
}


/* name of the fake network shall be constructed as:
 *  NETWORKXMLNAME;NETWORKPORTXMLNAME
 *  where:
 *  NETWORKXMLNAME resolves to abs_srcdir/networkxmlconfdata/NETWORKXMLNAME.xml
 *  NETWORKPORTXMLNAME resolves to abs_srcdir/virnetworkportxml2xmldata/NETWORKPORTXMLNAME.xml
 */
static virNetworkPtr
fakeNetworkLookupByName(virConnectPtr conn,
                        const char *name)
{
    unsigned char uuid[VIR_UUID_BUFLEN];
    g_autofree char *netname = g_strdup(name);
    g_autofree char *path = NULL;
    char *tmp;

    memset(uuid, 0, VIR_UUID_BUFLEN);

    if ((tmp = strchr(netname, ';'))) {
        *tmp = '\0';
    } else {
        virReportError(VIR_ERR_NO_NETWORK,
                       "Malformed fake network name '%s'. See fakeNetworkLookupByName.",
                       name);
        return NULL;
    }

    path = g_strdup_printf(abs_srcdir "/networkxmlconfdata/%s.xml", netname);

    if (!virFileExists(path)) {
        virReportError(VIR_ERR_NO_NETWORK, "fake network '%s' not found", path);
        return NULL;
    }

    return virGetNetwork(conn, name, uuid);
}


static char *
fakeNetworkGetXMLDesc(virNetworkPtr network,
                      unsigned int noflags G_GNUC_UNUSED)
{
    g_autofree char *netname = g_strdup(network->name);
    g_autofree char *path = NULL;
    char *xml = NULL;

    *(strchr(netname, ';')) = '\0';

    path = g_strdup_printf(abs_srcdir "/networkxmlconfdata/%s.xml", netname);

    if (virFileReadAll(path, 4 * 1024, &xml) < 0)
        return NULL;

    return xml;
}


static virNetworkPortPtr
fakeNetworkPortCreateXML(virNetworkPtr net,
                         const char *xmldesc G_GNUC_UNUSED,
                         unsigned int noflags G_GNUC_UNUSED)
{
    unsigned char uuid[VIR_UUID_BUFLEN];
    g_autofree char *portname = g_strdup(strchr(net->name, ';') + 1);
    g_autofree char *path = g_strdup_printf(abs_srcdir "/virnetworkportxml2xmldata/%s.xml", portname);

    memset(uuid, 0, VIR_UUID_BUFLEN);

    if (!virFileExists(path)) {
        virReportError(VIR_ERR_NO_NETWORK_PORT, "fake network port '%s' not found", path);
        return NULL;
    }

    return virGetNetworkPort(net, uuid);
}


static char *
fakeNetworkPortGetXMLDesc(virNetworkPortPtr port,
                          unsigned int noflags G_GNUC_UNUSED)
{
    g_autofree char *portname = g_strdup(strchr(port->net->name, ';') + 1);
    g_autofree char *path = g_strdup_printf(abs_srcdir "/virnetworkportxml2xmldata/%s.xml", portname);
    char *xml = NULL;

    if (virFileReadAll(path, 4 * 1024, &xml) < 0)
        return NULL;

    return xml;
}


static virNetworkDriver fakeNetworkDriver = {
    .networkLookupByName = fakeNetworkLookupByName,
    .networkGetXMLDesc = fakeNetworkGetXMLDesc,
    .networkPortCreateXML = fakeNetworkPortCreateXML,
    .networkPortGetXMLDesc = fakeNetworkPortGetXMLDesc,
};


virNetworkDriver *
testQemuGetFakeNetworkDriver(void)
{
    return &fakeNetworkDriver;
}
