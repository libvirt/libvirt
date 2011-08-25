/*
 * Copyright (c) 2011 Lai Jiangshan
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <config.h>
#include "virkeycode.h"
#include <string.h>
#include <stddef.h>

#define getfield(object, field_type, field_offset) \
    (*(typeof(field_type) *)((char *)(object) + field_offset))

struct keycode {
    const char *linux_name;
    const char *os_x_name;
    const char *win32_name;
    unsigned short linux_keycode;
    unsigned short os_x;
    unsigned short atset1;
    unsigned short atset2;
    unsigned short atset3;
    unsigned short xt;
    unsigned short xt_kbd;
    unsigned short usb;
    unsigned short win32;
    unsigned short rfb;
};

#define VIRT_KEY_INTERNAL
#include "virkeymaps.h"

static unsigned int codeOffset[] = {
    [VIR_KEYCODE_SET_LINUX] =
        offsetof(struct keycode, linux_keycode),
    [VIR_KEYCODE_SET_XT] =
        offsetof(struct keycode, xt),
    [VIR_KEYCODE_SET_ATSET1] =
        offsetof(struct keycode, atset1),
    [VIR_KEYCODE_SET_ATSET2] =
        offsetof(struct keycode, atset2),
    [VIR_KEYCODE_SET_ATSET3] =
        offsetof(struct keycode, atset3),
    [VIR_KEYCODE_SET_OSX] =
        offsetof(struct keycode, os_x),
    [VIR_KEYCODE_SET_XT_KBD] =
        offsetof(struct keycode, xt_kbd),
    [VIR_KEYCODE_SET_USB] =
        offsetof(struct keycode, usb),
    [VIR_KEYCODE_SET_WIN32] =
        offsetof(struct keycode, win32),
    [VIR_KEYCODE_SET_RFB] =
        offsetof(struct keycode, rfb),
};
verify(ARRAY_CARDINALITY(codeOffset) == VIR_KEYCODE_SET_LAST);

VIR_ENUM_IMPL(virKeycodeSet, VIR_KEYCODE_SET_LAST,
    "linux",
    "xt",
    "atset1",
    "atset2",
    "atset3",
    "os_x",
    "xt_kbd",
    "usb",
    "win32",
    "rfb",
);

static int __virKeycodeValueFromString(unsigned int name_offset,
                                           unsigned int code_offset,
                                           const char *keyname)
{
    int i;

    for (i = 0; i < ARRAY_CARDINALITY(virKeycodes); i++) {
        const char *name = getfield(virKeycodes + i, const char *, name_offset);

        if (name && STREQ(name, keyname))
            return getfield(virKeycodes + i, unsigned short, code_offset);
    }

    return -1;
}

int virKeycodeValueFromString(virKeycodeSet codeset, const char *keyname)
{
    switch (codeset) {
    case VIR_KEYCODE_SET_LINUX:
        return __virKeycodeValueFromString(offsetof(struct keycode, linux_name),
                                           offsetof(struct keycode, linux_keycode),
                                           keyname);
    case VIR_KEYCODE_SET_OSX:
        return __virKeycodeValueFromString(offsetof(struct keycode, os_x_name),
                                           offsetof(struct keycode, os_x),
                                           keyname);
    case VIR_KEYCODE_SET_WIN32:
        return __virKeycodeValueFromString(offsetof(struct keycode, win32_name),
                                           offsetof(struct keycode, win32),
                                           keyname);
    default:
        return -1;
    }
}

static int __virKeycodeValueTranslate(unsigned int from_offset,
                                      unsigned int to_offset,
                                      int key_value)
{
    int i;

    for (i = 0; i < ARRAY_CARDINALITY(virKeycodes); i++) {
        if (getfield(virKeycodes + i, unsigned short, from_offset) == key_value)
            return getfield(virKeycodes + i, unsigned short, to_offset);
    }

    return -1;
}

int virKeycodeValueTranslate(virKeycodeSet from_codeset,
                             virKeycodeSet to_codeset,
                             int key_value)
{
    if (key_value <= 0)
        return -1;

    key_value = __virKeycodeValueTranslate(codeOffset[from_codeset],
                                           codeOffset[to_codeset],
                                           key_value);
    if (key_value <= 0)
        return -1;

    return key_value;
}
