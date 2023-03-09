#include <config.h>

#include "virerror.h"
#include "virfile.h"
#include "storage_backend_vstorage.h"
#include "virlog.h"
#include "virutil.h"
#include <mntent.h>
#include <paths.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include "storage_util.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_backend_vstorage");


/**
 * @pool storage pool to build
 * @flags controls the pool formatting behaviour
 *
 * Does not support @flags, if provided an error will occur.
 *
 * Returns 0 on success, -1 on error
 */
static int
virStorageBackendVzPoolBuild(virStoragePoolObj *pool,
                             unsigned int flags)
{
    virCheckFlags(0, -1);

    return virStorageBackendBuildLocal(pool);
}


static int
virStorageBackendVzPoolStart(virStoragePoolObj *pool)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    g_autofree char *grp_name = NULL;
    g_autofree char *usr_name = NULL;
    g_autofree char *mode = NULL;
    g_autoptr(virCommand) cmd = NULL;
    int ret;

    /* Check the permissions */
    if (def->target.perms.mode == (mode_t)-1)
        def->target.perms.mode = VIR_STORAGE_DEFAULT_POOL_PERM_MODE;
    if (def->target.perms.uid == (uid_t)-1)
        def->target.perms.uid = geteuid();
    if (def->target.perms.gid == (gid_t)-1)
        def->target.perms.gid = getegid();

    /* Convert ids to names because vstorage uses names */

    if (!(grp_name = virGetGroupName(def->target.perms.gid)))
        return -1;

    if (!(usr_name = virGetUserName(def->target.perms.uid)))
        return -1;

    mode = g_strdup_printf("%o", def->target.perms.mode);

    cmd = virCommandNewArgList("vstorage-mount",
                               "-c", def->source.name,
                               def->target.path,
                               "-m", mode,
                               "-g", grp_name, "-u", usr_name,
                               NULL);

    /* Mounting a shared FS might take a long time. Don't hold
     * the pool locked meanwhile. */
    virObjectUnlock(pool);
    ret = virCommandRun(cmd, NULL);
    virObjectLock(pool);

    return ret;
}


static int
virStorageBackendVzIsMounted(virStoragePoolObj *pool)
{
    int ret = -1;
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    FILE *mtab;
    struct mntent ent;
    char buf[1024];
    g_autofree char *cluster = NULL;

    cluster = g_strdup_printf("vstorage://%s", def->source.name);

    if ((mtab = fopen(_PATH_MOUNTED, "r")) == NULL) {
        virReportSystemError(errno,
                             _("cannot read mount list '%1$s'"),
                             _PATH_MOUNTED);
        goto cleanup;
    }

    while ((getmntent_r(mtab, &ent, buf, sizeof(buf))) != NULL) {

        if (STREQ(ent.mnt_dir, def->target.path) &&
            STREQ(ent.mnt_fsname, cluster)) {
            ret = 1;
            goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    VIR_FORCE_FCLOSE(mtab);
    return ret;
}


static int
virStorageBackendVzPoolStop(virStoragePoolObj *pool)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    int rc;
    g_autoptr(virCommand) cmd = NULL;

    /* Short-circuit if already unmounted */
    if ((rc = virStorageBackendVzIsMounted(pool)) != 1)
        return rc;

    cmd = virCommandNewArgList("umount", def->target.path, NULL);
    return virCommandRun(cmd, NULL);
}


/*
 * Check whether the cluster is mounted
 */
static int
virStorageBackendVzCheck(virStoragePoolObj *pool,
                         bool *isActive)
{
    int ret = -1;
    *isActive = false;
    if ((ret = virStorageBackendVzIsMounted(pool)) != 0) {
        if (ret < 0)
            return -1;
        *isActive = true;
    }

    return 0;
}


virStorageBackend virStorageBackendVstorage = {
    .type = VIR_STORAGE_POOL_VSTORAGE,

    .buildPool = virStorageBackendVzPoolBuild,
    .startPool = virStorageBackendVzPoolStart,
    .stopPool = virStorageBackendVzPoolStop,
    .deletePool = virStorageBackendDeleteLocal,
    .refreshPool = virStorageBackendRefreshLocal,
    .checkPool = virStorageBackendVzCheck,
    .buildVol = virStorageBackendVolBuildLocal,
    .buildVolFrom = virStorageBackendVolBuildFromLocal,
    .createVol = virStorageBackendVolCreateLocal,
    .refreshVol = virStorageBackendVolRefreshLocal,
    .deleteVol = virStorageBackendVolDeleteLocal,
    .resizeVol = virStorageBackendVolResizeLocal,
    .uploadVol = virStorageBackendVolUploadLocal,
    .downloadVol = virStorageBackendVolDownloadLocal,
    .wipeVol = virStorageBackendVolWipeLocal,
};


int
virStorageBackendVstorageRegister(void)
{
    return virStorageBackendRegister(&virStorageBackendVstorage);
}
