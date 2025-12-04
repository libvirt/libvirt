/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

/* This enum resides in a separate file to allow inclusion into qemu_conf.h */
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
    QEMU_SAVE_FORMAT_ZSTD = 5,
    QEMU_SAVE_FORMAT_SPARSE = 6,
    /* Note: add new members only at the end.
       These values are used in the on-disk format.
       Do not change or re-use numbers. */

    QEMU_SAVE_FORMAT_LAST
} virQEMUSaveFormat;
