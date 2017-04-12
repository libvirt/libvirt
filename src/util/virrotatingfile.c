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
#include "virstring.h"
#include "virfile.h"
#include "virlog.h"

VIR_LOG_INIT("util.rotatingfile");

#define VIR_FROM_THIS VIR_FROM_NONE

#define VIR_MAX_MAX_BACKUP 32

typedef struct virRotatingFileWriterEntry virRotatingFileWriterEntry;
typedef virRotatingFileWriterEntry *virRotatingFileWriterEntryPtr;

typedef struct virRotatingFileReaderEntry virRotatingFileReaderEntry;
typedef virRotatingFileReaderEntry *virRotatingFileReaderEntryPtr;

struct virRotatingFileWriterEntry {
    int fd;
    off_t inode;
    off_t pos;
    off_t len;
};

struct virRotatingFileWriter {
    char *basepath;
    virRotatingFileWriterEntryPtr entry;
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
    virRotatingFileReaderEntryPtr *entries;
    size_t nentries;
    size_t current;
};


static void
virRotatingFileWriterEntryFree(virRotatingFileWriterEntryPtr entry)
{
    if (!entry)
        return;

    VIR_FORCE_CLOSE(entry->fd);
    VIR_FREE(entry);
}


static void
virRotatingFileReaderEntryFree(virRotatingFileReaderEntryPtr entry)
{
    if (!entry)
        return;

    VIR_FREE(entry->path);
    VIR_FORCE_CLOSE(entry->fd);
    VIR_FREE(entry);
}


static virRotatingFileWriterEntryPtr
virRotatingFileWriterEntryNew(const char *path,
                              mode_t mode)
{
    virRotatingFileWriterEntryPtr entry;
    struct stat sb;

    VIR_DEBUG("Opening %s mode=%02o", path, mode);

    if (VIR_ALLOC(entry) < 0)
        return NULL;

    if ((entry->fd = open(path, O_CREAT|O_APPEND|O_WRONLY|O_CLOEXEC, mode)) < 0) {
        virReportSystemError(errno,
                             _("Unable to open file: %s"), path);
        goto error;
    }

    entry->pos = lseek(entry->fd, 0, SEEK_END);
    if (entry->pos == (off_t)-1) {
        virReportSystemError(errno,
                             _("Unable to determine current file offset: %s"),
                             path);
        goto error;
    }

    if (fstat(entry->fd, &sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to determine current file inode: %s"),
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


static virRotatingFileReaderEntryPtr
virRotatingFileReaderEntryNew(const char *path)
{
    virRotatingFileReaderEntryPtr entry;
    struct stat sb;

    VIR_DEBUG("Opening %s", path);

    if (VIR_ALLOC(entry) < 0)
        return NULL;

    if ((entry->fd = open(path, O_RDONLY|O_CLOEXEC)) < 0) {
        if (errno != ENOENT) {
            virReportSystemError(errno,
                                 _("Unable to open file: %s"), path);
            goto error;
        }
    }

    if (entry->fd != -1) {
        if (fstat(entry->fd, &sb) < 0) {
            virReportSystemError(errno,
                                 _("Unable to determine current file inode: %s"),
                                 path);
            goto error;
        }

        entry->inode = sb.st_ino;
    }

    if (VIR_STRDUP(entry->path, path) < 0)
        goto error;

    return entry;

 error:
    virRotatingFileReaderEntryFree(entry);
    return NULL;
}


static int
virRotatingFileWriterDelete(virRotatingFileWriterPtr file)
{
    size_t i;

    if (unlink(file->basepath) < 0 &&
        errno != ENOENT) {
        virReportSystemError(errno,
                             _("Unable to delete file %s"),
                             file->basepath);
        return -1;
    }

    for (i = 0; i < file->maxbackup; i++) {
        char *oldpath;
        if (virAsprintf(&oldpath, "%s.%zu", file->basepath, i) < 0)
            return -1;

        if (unlink(oldpath) < 0 &&
            errno != ENOENT) {
            virReportSystemError(errno,
                                 _("Unable to delete file %s"),
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
 * in order to avoid splitting lines
 */
virRotatingFileWriterPtr
virRotatingFileWriterNew(const char *path,
                         off_t maxlen,
                         size_t maxbackup,
                         bool trunc,
                         mode_t mode)
{
    virRotatingFileWriterPtr file;

    if (VIR_ALLOC(file) < 0)
        goto error;

    if (VIR_STRDUP(file->basepath, path) < 0)
        goto error;

    if (maxbackup > VIR_MAX_MAX_BACKUP) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Max backup %zu must be less than or equal to %d"),
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
virRotatingFileReaderPtr
virRotatingFileReaderNew(const char *path,
                         size_t maxbackup)
{
    virRotatingFileReaderPtr file;
    size_t i;

    if (VIR_ALLOC(file) < 0)
        goto error;

    if (maxbackup > VIR_MAX_MAX_BACKUP) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Max backup %zu must be less than or equal to %d"),
                       maxbackup, VIR_MAX_MAX_BACKUP);
        goto error;
    }

    file->nentries = maxbackup + 1;
    if (VIR_ALLOC_N(file->entries, file->nentries) < 0)
        goto error;

    if (!(file->entries[file->nentries - 1] = virRotatingFileReaderEntryNew(path)))
        goto error;

    for (i = 0; i < maxbackup; i++) {
        char *tmppath;
        if (virAsprintf(&tmppath, "%s.%zu", path, i) < 0)
            goto error;

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
virRotatingFileWriterGetPath(virRotatingFileWriterPtr file)
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
virRotatingFileWriterGetINode(virRotatingFileWriterPtr file)
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
virRotatingFileWriterGetOffset(virRotatingFileWriterPtr file)
{
    return file->entry->pos;
}


static int
virRotatingFileWriterRollover(virRotatingFileWriterPtr file)
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
                                 _("Unable to remove %s"),
                                 file->basepath);
            goto cleanup;
        }
    } else {
        if (virAsprintf(&nextpath, "%s.%zu", file->basepath, file->maxbackup - 1) < 0)
            return -1;

        for (i = file->maxbackup; i > 0; i--) {
            if (i == 1) {
                if (VIR_STRDUP(thispath, file->basepath) < 0)
                    goto cleanup;
            } else {
                if (virAsprintf(&thispath, "%s.%zu", file->basepath, i - 2) < 0)
                    goto cleanup;
            }
            VIR_DEBUG("Rollover %s -> %s", thispath, nextpath);

            if (rename(thispath, nextpath) < 0 &&
                errno != ENOENT) {
                virReportSystemError(errno,
                                     _("Unable to rename %s to %s"),
                                     thispath, nextpath);
                goto cleanup;
            }

            VIR_FREE(nextpath);
            nextpath = thispath;
            thispath = NULL;
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
virRotatingFileWriterAppend(virRotatingFileWriterPtr file,
                            const char *buf,
                            size_t len)
{
    ssize_t ret = 0;
    size_t i;
    while (len) {
        size_t towrite = len;
        bool forceRollover = false;

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

        if (towrite) {
            if (safewrite(file->entry->fd, buf, towrite) != towrite) {
                virReportSystemError(errno,
                                     _("Unable to write to file %s"),
                                     file->basepath);
                return -1;
            }

            len -= towrite;
            buf += towrite;
            ret += towrite;
            file->entry->pos += towrite;
            file->entry->len += towrite;
        }

        if ((file->entry->pos == file->maxlen && len) ||
            forceRollover) {
            virRotatingFileWriterEntryPtr tmp;
            VIR_DEBUG("Hit max size %zu on %s (force=%d)\n",
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
virRotatingFileReaderSeek(virRotatingFileReaderPtr file,
                          ino_t inode,
                          off_t offset)
{
    size_t i;
    off_t ret;

    for (i = 0; i < file->nentries; i++) {
        virRotatingFileReaderEntryPtr entry = file->entries[i];
        if (entry->inode != inode ||
            entry->fd == -1)
            continue;

        ret = lseek(entry->fd, offset, SEEK_SET);
        if (ret == (off_t)-1) {
            virReportSystemError(errno,
                                 _("Unable to seek to inode %llu offset %llu"),
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
                             _("Unable to seek to inode %llu offset %llu"),
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
virRotatingFileReaderConsume(virRotatingFileReaderPtr file,
                             char *buf,
                             size_t len)
{
    ssize_t ret = 0;

    VIR_DEBUG("Consume %p %zu\n", buf, len);
    while (len) {
        virRotatingFileReaderEntryPtr entry;
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
                                 _("Unable to read from file %s"),
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
virRotatingFileWriterFree(virRotatingFileWriterPtr file)
{
    if (!file)
        return;

    virRotatingFileWriterEntryFree(file->entry);
    VIR_FREE(file->basepath);
    VIR_FREE(file);
}


/**
 * virRotatingFileReaderFree:
 * @file: the file context
 *
 * Close the files and release all resources
 */
void
virRotatingFileReaderFree(virRotatingFileReaderPtr file)
{
    size_t i;

    if (!file)
        return;

    for (i = 0; i < file->nentries; i++)
        virRotatingFileReaderEntryFree(file->entries[i]);
    VIR_FREE(file->entries);
    VIR_FREE(file);
}
