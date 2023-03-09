/*
 * log_cleaner.c: cleans obsolete log files
 *
 * Copyright (C) 2022 Virtuozzo International GmbH
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <unistd.h>

#include "log_cleaner.h"
#include "log_handler.h"

#include "virerror.h"
#include "virobject.h"
#include "virfile.h"
#include "viralloc.h"
#include "virlog.h"
#include "virrotatingfile.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_LOGGING

VIR_LOG_INIT("logging.log_cleaner");

/* Cleanup log root (/var/log/libvirt) and all subfolders (e.g. /var/log/libvirt/qemu) */
#define CLEANER_LOG_DEPTH 1
#define CLEANER_LOG_TIMEOUT_MS (24 * 3600 * 1000) /* One day */
#define MAX_TIME ((time_t) G_MAXINT64)

static GRegex *log_regex;

typedef struct _virLogCleanerChain virLogCleanerChain;
struct _virLogCleanerChain {
    int rotated_max_index;
    time_t last_modified;
};

typedef struct _virLogCleanerData virLogCleanerData;
struct _virLogCleanerData {
    virLogHandler *handler;
    time_t oldest_to_keep;
    GHashTable *chains;
};

static char *
virLogCleanerParseFilename(const char *path,
                           int *rotated_index)
{
    g_autoptr(GMatchInfo) matchInfo = NULL;
    g_autofree char *rotated_index_str = NULL;
    g_autofree char *clear_path = NULL;
    char *chain_prefix = NULL;

    clear_path = realpath(path, NULL);
    if (!clear_path) {
        VIR_WARN("Failed to resolve path %s: %s", path, g_strerror(errno));
        return NULL;
    }

    if (!g_regex_match(log_regex, path, 0, &matchInfo))
        return NULL;

    chain_prefix = g_match_info_fetch(matchInfo, 1);
    if (!rotated_index)
        return chain_prefix;

    *rotated_index = 0;
    rotated_index_str = g_match_info_fetch(matchInfo, 3);

    if (!rotated_index_str)
        return chain_prefix;

    if (virStrToLong_i(rotated_index_str, NULL, 10, rotated_index) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to parse rotated index from '%1$s'"),
                       rotated_index_str);
        return NULL;
    }
    return chain_prefix;
}

static void
virLogCleanerDeleteFile(const char *path)
{
    if (unlink(path) < 0 && errno != ENOENT)
        VIR_WARN("Unable to delete %s: %s", path, g_strerror(errno));
}

static void
virLogCleanerProcessFile(virLogCleanerData *data,
                         const char *path,
                         struct stat *sb)
{
    int rotated_index = 0;
    g_autofree char *chain_prefix = NULL;
    virLogCleanerChain *chain;

    if (!S_ISREG(sb->st_mode))
        return;

    chain_prefix = virLogCleanerParseFilename(path, &rotated_index);

    if (!chain_prefix)
        return;

    if (rotated_index > data->handler->config->max_backups) {
        virLogCleanerDeleteFile(path);
        return;
    }

    chain = g_hash_table_lookup(data->chains, chain_prefix);

    if (!chain) {
        chain = g_new0(virLogCleanerChain, 1);
        g_hash_table_insert(data->chains, g_steal_pointer(&chain_prefix), chain);
    }

    chain->last_modified = MAX(chain->last_modified, sb->st_mtime);
    chain->rotated_max_index = MAX(chain->rotated_max_index,
                                   rotated_index);
}

static GHashTable *
virLogCleanerCreateTable(virLogHandler *handler)
{
    /* HashTable: (const char*) chain_prefix -> (virLogCleanerChain*) chain */
    GHashTable *chains = g_hash_table_new_full(g_str_hash, g_str_equal,
                                               g_free, g_free);
    size_t i;
    virLogHandlerLogFile *file;
    char *chain_prefix;
    virLogCleanerChain *chain;
    VIR_LOCK_GUARD lock = virObjectLockGuard(handler);

    for (i = 0; i < handler->nfiles; i++) {
        file = handler->files[i];
        chain_prefix = virLogCleanerParseFilename(virRotatingFileWriterGetPath(file->file),
                                                  NULL);
        if (!chain_prefix)
            continue;

        chain = g_new0(virLogCleanerChain, 1);
        chain->last_modified = MAX_TIME; /* Here we set MAX_TIME to the currently
                                          * opened files to prevent its deletion. */
        g_hash_table_insert(chains, chain_prefix, chain);
    }

    return chains;
}

static void
virLogCleanerProcessFolder(virLogCleanerData *data,
                           const char *path,
                           int depth_left)
{
    DIR *dir;
    struct dirent *entry;
    struct stat sb;

    if (virDirOpenIfExists(&dir, path) < 0)
        return;

    while (virDirRead(dir, &entry, path) > 0) {
        g_autofree char *newpath = g_strdup_printf("%s/%s", path, entry->d_name);

        if (stat(newpath, &sb) < 0) {
            VIR_WARN("Unable to stat %s: %s", newpath, g_strerror(errno));
            continue;
        }

        if (S_ISDIR(sb.st_mode)) {
            if (depth_left > 0)
                virLogCleanerProcessFolder(data, newpath, depth_left - 1);
            continue;
        }

        virLogCleanerProcessFile(data, newpath, &sb);
    }

    virDirClose(dir);
}

static void
virLogCleanerChainCB(gpointer key,
                     gpointer value,
                     gpointer user_data)
{
    char *chain_prefix = key;
    virLogCleanerChain *chain = value;
    virLogCleanerData *data = user_data;
    g_autofree char *path = NULL;
    size_t i;

    if (chain->last_modified > data->oldest_to_keep)
        return;

    path = g_strdup_printf("%s.log", chain_prefix);
    virLogCleanerDeleteFile(path);

    for (i = 0; i <= chain->rotated_max_index; i++) {
        g_autofree char *rotated_path = g_strdup_printf("%s.%zu", path, i);

        virLogCleanerDeleteFile(rotated_path);
    }
}

static void
virLogCleanerTimer(int timer G_GNUC_UNUSED, void *opaque)
{
    virLogHandler *handler = opaque;
    virLogCleanerData data = {
        .handler = handler,
        .oldest_to_keep = time(NULL) - 3600 * 24 * handler->config->max_age_days,
        .chains = virLogCleanerCreateTable(handler),
    };

    /* First prepare the hashmap of chains to delete */
    virLogCleanerProcessFolder(&data,
                               handler->config->log_root,
                               CLEANER_LOG_DEPTH);
    g_hash_table_foreach(data.chains, virLogCleanerChainCB, &data);
    g_hash_table_destroy(data.chains);
}

int
virLogCleanerInit(virLogHandler *handler)
{
    if (handler->config->max_age_days <= 0)
        return 0;

    log_regex = g_regex_new("^(.*)\\.log(\\.(\\d+))?$", 0, 0, NULL);
    if (!log_regex) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Unable to compile regex"));
        return -1;
    }

    handler->cleanup_log_timer = virEventAddTimeout(CLEANER_LOG_TIMEOUT_MS,
                                                    virLogCleanerTimer,
                                                    handler, NULL);
    return handler->cleanup_log_timer;
}

void
virLogCleanerShutdown(virLogHandler *handler)
{
    if (handler->cleanup_log_timer != -1) {
        virEventRemoveTimeout(handler->cleanup_log_timer);
        handler->cleanup_log_timer = -1;
    }

    g_clear_pointer(&log_regex, g_regex_unref);
}
