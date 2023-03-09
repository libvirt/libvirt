/*
 * virrotatingfile.c: file I/O with size rotation
 *
 * Copyright (C) 2015 Red Hat, Inc.
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

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "virrotatingfile.h"
#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "virlog.h"

VIR_LOG_INIT("util.rotatingfile");

#define VIR_FROM_THIS VIR_FROM_NONE

#define VIR_MAX_MAX_BACKUP 32

typedef struct virRotatingFileWriterEntry virRotatingFileWriterEntry;

typedef struct virRotatingFileReaderEntry virRotatingFileReaderEntry;

struct virRotatingFileWriterEntry {
    int fd;
    off_t inode;
    off_t pos;
    off_t len;
};

struct virRotatingFileWriter {
    char *basepath;
    virRotatingFileWriterEntry *entry;
    size_t maxbackup;
    mode_t mode;
    size_t maxlen;
};


struct virRotatingFileReaderEntry {
    char *path;
    int fd;
    off_t inode;
};

struct virRotatingFileReader {
    virRotatingFileReaderEntry **entries;
    size_t nentries;
    size_t current;
};


static void
virRotatingFileWriterEntryFree(virRotatingFileWriterEntry *entry)
{
    if (!entry)
        return;

    VIR_FORCE_CLOSE(entry->fd);
    g_free(entry);
}


static void
virRotatingFileReaderEntryFree(virRotatingFileReaderEntry *entry)
{
    if (!entry)
        return;

    g_free(entry->path);
    VIR_FORCE_CLOSE(entry->fd);
    g_free(entry);
}


static virRotatingFileWriterEntry *
virRotatingFileWriterEntryNew(const char *path,
                              mode_t mode)
{
    virRotatingFileWriterEntry *entry;
    struct stat sb;

    VIR_DEBUG("Opening %s mode=0%02o", path, mode);

    entry = g_new0(virRotatingFileWriterEntry, 1);

    if ((entry->fd = open(path, O_CREAT|O_APPEND|O_WRONLY|O_CLOEXEC, mode)) < 0) {
        virReportSystemError(errno,
                             _("Unable to open file: %1$s"), path);
        goto error;
    }

    entry->pos = lseek(entry->fd, 0, SEEK_END);
    if (entry->pos == (off_t)-1) {
        virReportSystemError(errno,
                             _("Unable to determine current file offset: %1$s"),
                             path);
        goto error;
    }

    if (fstat(entry->fd, &sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to determine current file inode: %1$s"),
                             path);
        goto error;
    }

    entry->len = sb.st_size;
    entry->inode = sb.st_ino;

    return entry;

 error:
    virRotatingFileWriterEntryFree(entry);
    return NULL;
}


static virRotatingFileReaderEntry *
virRotatingFileReaderEntryNew(const char *path)
{
    virRotatingFileReaderEntry *entry;
    struct stat sb;

    VIR_DEBUG("Opening %s", path);

    entry = g_new0(virRotatingFileReaderEntry, 1);

    if ((entry->fd = open(path, O_RDONLY|O_CLOEXEC)) < 0) {
        if (errno != ENOENT) {
            virReportSystemError(errno,
                                 _("Unable to open file: %1$s"), path);
            goto error;
        }
    }

    if (entry->fd != -1) {
        if (fstat(entry->fd, &sb) < 0) {
            virReportSystemError(errno,
                                 _("Unable to determine current file inode: %1$s"),
                                 path);
            goto error;
        }

        entry->inode = sb.st_ino;
    }

    entry->path = g_strdup(path);

    return entry;

 error:
    virRotatingFileReaderEntryFree(entry);
    return NULL;
}


static int
virRotatingFileWriterDelete(virRotatingFileWriter *file)
{
    size_t i;

    if (unlink(file->basepath) < 0 &&
        errno != ENOENT) {
        virReportSystemError(errno,
                             _("Unable to delete file %1$s"),
                             file->basepath);
        return -1;
    }

    for (i = 0; i < file->maxbackup; i++) {
        char *oldpath;
        oldpath = g_strdup_printf("%s.%zu", file->basepath, i);

        if (unlink(oldpath) < 0 &&
            errno != ENOENT) {
            virReportSystemError(errno,
                                 _("Unable to delete file %1$s"),
                                 oldpath);
            VIR_FREE(oldpath);
            return -1;
        }
        VIR_FREE(oldpath);
    }

    return 0;
}


/**
 * virRotatingFileWriterNew
 * @path: the base path for files
 * @maxlen: the maximum number of bytes to write before rollover
 * @maxbackup: number of backup files to keep when rolling over
 * @trunc: whether to truncate the current files when opening
 * @mode: the file mode to use for creating new files
 *
 * Create a new object for writing data to a file with
 * automatic rollover. If @maxbackup is zero, no backup
 * files will be created. The primary file will just get
 * truncated and reopened.
 *
 * The files will never exceed @maxlen bytes in size,
 * but may be rolled over before they reach this size
 * in order to avoid splitting lines. If @maxlen is
 * zero then no rollover will be performed.
 */
virRotatingFileWriter *
virRotatingFileWriterNew(const char *path,
                         off_t maxlen,
                         size_t maxbackup,
                         bool trunc,
                         mode_t mode)
{
    virRotatingFileWriter *file;

    file = g_new0(virRotatingFileWriter, 1);

    file->basepath = g_strdup(path);

    if (maxbackup > VIR_MAX_MAX_BACKUP) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Max backup %1$zu must be less than or equal to %2$d"),
                       maxbackup, VIR_MAX_MAX_BACKUP);
        goto error;
    }

    file->mode = mode;
    file->maxbackup = maxbackup;
    file->maxlen = maxlen;

    if (trunc &&
        virRotatingFileWriterDelete(file) < 0)
        goto error;

    if (!(file->entry = virRotatingFileWriterEntryNew(file->basepath,
                                                      mode)))
        goto error;

    return file;

 error:
    virRotatingFileWriterFree(file);
    return NULL;
}


/**
 * virRotatingFileReaderNew:
 * @path: the base path for files
 * @maxbackup: number of backup files to read history from
 *
 * Create a new object for reading from a set of rolling files.
 * I/O will start from the oldest file and proceed through
 * files until the end of the newest one.
 *
 * If @maxbackup is zero the only the newest file will be read.
 */
virRotatingFileReader *
virRotatingFileReaderNew(const char *path,
                         size_t maxbackup)
{
    virRotatingFileReader *file;
    size_t i;

    file = g_new0(virRotatingFileReader, 1);

    if (maxbackup > VIR_MAX_MAX_BACKUP) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Max backup %1$zu must be less than or equal to %2$d"),
                       maxbackup, VIR_MAX_MAX_BACKUP);
        goto error;
    }

    file->nentries = maxbackup + 1;
    file->entries = g_new0(virRotatingFileReaderEntry *, file->nentries);

    if (!(file->entries[file->nentries - 1] = virRotatingFileReaderEntryNew(path)))
        goto error;

    for (i = 0; i < maxbackup; i++) {
        char *tmppath;
        tmppath = g_strdup_printf("%s.%zu", path, i);

        file->entries[file->nentries - (i + 2)] = virRotatingFileReaderEntryNew(tmppath);
        VIR_FREE(tmppath);
        if (!file->entries[file->nentries - (i + 2)])
            goto error;
    }

    return file;

 error:
    virRotatingFileReaderFree(file);
    return NULL;
}


/**
 * virRotatingFileWriterGetPath:
 * @file: the file context
 *
 * Return the primary file path
 */
const char *
virRotatingFileWriterGetPath(virRotatingFileWriter *file)
{
    return file->basepath;
}


/**
 * virRotatingFileWriterGetINode:
 * @file: the file context
 *
 * Return the inode of the file currently being written to
 */
ino_t
virRotatingFileWriterGetINode(virRotatingFileWriter *file)
{
    return file->entry->inode;
}


/**
 * virRotatingFileWriterGetOffset:
 * @file: the file context
 *
 * Return the offset at which data is currently being written
 */
off_t
virRotatingFileWriterGetOffset(virRotatingFileWriter *file)
{
    return file->entry->pos;
}


static int
virRotatingFileWriterRollover(virRotatingFileWriter *file)
{
    size_t i;
    char *nextpath = NULL;
    char *thispath = NULL;
    int ret = -1;

    VIR_DEBUG("Rollover %s", file->basepath);
    if (file->maxbackup == 0) {
        if (unlink(file->basepath) < 0 &&
            errno != ENOENT) {
            virReportSystemError(errno,
                                 _("Unable to remove %1$s"),
                                 file->basepath);
            goto cleanup;
        }
    } else {
        nextpath = g_strdup_printf("%s.%zu", file->basepath, file->maxbackup - 1);

        for (i = file->maxbackup; i > 0; i--) {
            if (i == 1) {
                thispath = g_strdup(file->basepath);
            } else {
                thispath = g_strdup_printf("%s.%zu", file->basepath, i - 2);
            }
            VIR_DEBUG("Rollover %s -> %s", thispath, nextpath);

            if (rename(thispath, nextpath) < 0 &&
                errno != ENOENT) {
                virReportSystemError(errno,
                                     _("Unable to rename %1$s to %2$s"),
                                     thispath, nextpath);
                goto cleanup;
            }

            VIR_FREE(nextpath);
            nextpath = g_steal_pointer(&thispath);
        }
    }

    VIR_DEBUG("Rollover done %s", file->basepath);

    ret = 0;
 cleanup:
    VIR_FREE(nextpath);
    VIR_FREE(thispath);
    return ret;
}


/**
 * virRotatingFileWriterAppend:
 * @file: the file context
 * @buf: the data buffer
 * @len: the number of bytes in @buf
 *
 * Append the data in @buf to the file, performing rollover
 * of the files if their size would exceed the limit
 *
 * Returns the number of bytes written, or -1 on error
 */
ssize_t
virRotatingFileWriterAppend(virRotatingFileWriter *file,
                            const char *buf,
                            size_t len)
{
    ssize_t ret = 0;
    size_t i;
    while (len) {
        size_t towrite = len;
        bool forceRollover = false;

        if (file->maxlen != 0) {
            if (file->entry->pos > file->maxlen) {
                /* If existing file is for some reason larger then max length we
                 * won't write to this file anymore, but we rollover this file.*/
                forceRollover = true;
                towrite = 0;
            } else if ((file->entry->pos + towrite) > file->maxlen) {
                towrite = file->maxlen - file->entry->pos;

                /*
                 * If there's a newline in the last 80 chars
                 * we're about to write, then break at that
                 * point to avoid splitting lines across
                 * separate files
                 */
                for (i = 0; i < towrite && i < 80; i++) {
                    if (buf[towrite - i - 1] == '\n') {
                        towrite -= i;
                        forceRollover = true;
                        break;
                    }
                }
            }
        }

        if (towrite) {
            if (safewrite(file->entry->fd, buf, towrite) != towrite) {
                virReportSystemError(errno,
                                     _("Unable to write to file %1$s"),
                                     file->basepath);
                return -1;
            }

            len -= towrite;
            buf += towrite;
            ret += towrite;
            file->entry->pos += towrite;
            file->entry->len += towrite;
        }

        if (file->maxlen != 0 &&
            ((file->entry->pos == file->maxlen && len) ||
             forceRollover)) {
            virRotatingFileWriterEntry *tmp;
            VIR_DEBUG("Hit max size %zu on %s (force=%d)",
                      file->maxlen, file->basepath, forceRollover);

            if (virRotatingFileWriterRollover(file) < 0)
                return -1;

            if (!(tmp = virRotatingFileWriterEntryNew(file->basepath,
                                                      file->mode)))
                return -1;

            virRotatingFileWriterEntryFree(file->entry);
            file->entry = tmp;
        }
    }

    return ret;
}


/**
 * virRotatingFileReaderSeek
 * @file: the file context
 * @inode: the inode of the file to seek to
 * @offset: the offset within the file to seek to
 *
 * Seek to @offset in the file identified by @inode.
 * If no file with a inode matching @inode currently
 * exists, then seeks to the start of the oldest
 * file, on the basis that the requested file has
 * probably been rotated out of existence
 */
int
virRotatingFileReaderSeek(virRotatingFileReader *file,
                          ino_t inode,
                          off_t offset)
{
    size_t i;
    off_t ret;

    for (i = 0; i < file->nentries; i++) {
        virRotatingFileReaderEntry *entry = file->entries[i];
        if (entry->inode != inode ||
            entry->fd == -1)
            continue;

        ret = lseek(entry->fd, offset, SEEK_SET);
        if (ret == (off_t)-1) {
            virReportSystemError(errno,
                                 _("Unable to seek to inode %1$llu offset %2$llu"),
                                 (unsigned long long)inode, (unsigned long long)offset);
            return -1;
        }

        file->current = i;
        return 0;
    }

    file->current = 0;
    ret = lseek(file->entries[0]->fd, offset, SEEK_SET);
    if (ret == (off_t)-1) {
        virReportSystemError(errno,
                             _("Unable to seek to inode %1$llu offset %2$llu"),
                             (unsigned long long)inode, (unsigned long long)offset);
        return -1;
    }
    return 0;
}


/**
 * virRotatingFileReaderConsume:
 * @file: the file context
 * @buf: the buffer to fill with data
 * @len: the size of @buf
 *
 * Reads data from the file starting at the current offset.
 * The returned data may be pulled from multiple files.
 *
 * Returns: the number of bytes read or -1 on error
 */
ssize_t
virRotatingFileReaderConsume(virRotatingFileReader *file,
                             char *buf,
                             size_t len)
{
    ssize_t ret = 0;

    VIR_DEBUG("Consume %p %zu", buf, len);
    while (len) {
        virRotatingFileReaderEntry *entry;
        ssize_t got;

        if (file->current >= file->nentries)
            break;

        entry = file->entries[file->current];
        if (entry->fd == -1) {
            file->current++;
            continue;
        }

        got = saferead(entry->fd, buf + ret, len);
        if (got < 0) {
            virReportSystemError(errno,
                                 _("Unable to read from file %1$s"),
                                 entry->path);
            return -1;
        }

        if (got == 0) {
            file->current++;
            continue;
        }

        ret += got;
        len -= got;
    }

    return ret;
}


/**
 * virRotatingFileWriterFree:
 * @file: the file context
 *
 * Close the current file and release all resources
 */
void
virRotatingFileWriterFree(virRotatingFileWriter *file)
{
    if (!file)
        return;

    virRotatingFileWriterEntryFree(file->entry);
    g_free(file->basepath);
    g_free(file);
}


/**
 * virRotatingFileReaderFree:
 * @file: the file context
 *
 * Close the files and release all resources
 */
void
virRotatingFileReaderFree(virRotatingFileReader *file)
{
    size_t i;

    if (!file)
        return;

    for (i = 0; i < file->nentries; i++)
        virRotatingFileReaderEntryFree(file->entries[i]);
    g_free(file->entries);
    g_free(file);
}
