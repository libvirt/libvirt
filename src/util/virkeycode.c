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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#include <config.h>
#include "virkeycode.h"
#include <string.h>
#include <stddef.h>

#include "virkeycodetable_atset1.h"
#include "virkeycodetable_atset2.h"
#include "virkeycodetable_atset3.h"
#include "virkeycodetable_linux.h"
#include "virkeycodetable_osx.h"
#include "virkeycodetable_rfb.h"
#include "virkeycodetable_usb.h"
#include "virkeycodetable_win32.h"
#include "virkeycodetable_xt.h"
#include "virkeycodetable_xtkbd.h"
#include "virkeynametable_linux.h"
#include "virkeynametable_osx.h"
#include "virkeynametable_win32.h"

static const char **virKeymapNames[VIR_KEYCODE_SET_LAST] = {
    [VIR_KEYCODE_SET_LINUX] = virKeyNameTable_linux,
    [VIR_KEYCODE_SET_OSX] = virKeyNameTable_osx,
    [VIR_KEYCODE_SET_WIN32] = virKeyNameTable_win32,
};

static const unsigned short *virKeymapValues[VIR_KEYCODE_SET_LAST] = {
    [VIR_KEYCODE_SET_LINUX] = virKeyCodeTable_linux,
    [VIR_KEYCODE_SET_XT] = virKeyCodeTable_xt,
    [VIR_KEYCODE_SET_ATSET1] = virKeyCodeTable_atset1,
    [VIR_KEYCODE_SET_ATSET2] = virKeyCodeTable_atset2,
    [VIR_KEYCODE_SET_ATSET3] = virKeyCodeTable_atset3,
    [VIR_KEYCODE_SET_OSX] = virKeyCodeTable_osx,
    [VIR_KEYCODE_SET_XT_KBD] = virKeyCodeTable_xtkbd,
    [VIR_KEYCODE_SET_USB] = virKeyCodeTable_usb,
    [VIR_KEYCODE_SET_WIN32] = virKeyCodeTable_win32,
    [VIR_KEYCODE_SET_RFB] = virKeyCodeTable_rfb,
};

#define VIR_KEYMAP_ENTRY_MAX ARRAY_CARDINALITY(virKeyCodeTable_linux)

verify(VIR_KEYMAP_ENTRY_MAX == ARRAY_CARDINALITY(virKeyCodeTable_xt));
verify(VIR_KEYMAP_ENTRY_MAX == ARRAY_CARDINALITY(virKeyCodeTable_atset1));
verify(VIR_KEYMAP_ENTRY_MAX == ARRAY_CARDINALITY(virKeyCodeTable_atset2));
verify(VIR_KEYMAP_ENTRY_MAX == ARRAY_CARDINALITY(virKeyCodeTable_atset3));
verify(VIR_KEYMAP_ENTRY_MAX == ARRAY_CARDINALITY(virKeyCodeTable_osx));
verify(VIR_KEYMAP_ENTRY_MAX == ARRAY_CARDINALITY(virKeyCodeTable_xtkbd));
verify(VIR_KEYMAP_ENTRY_MAX == ARRAY_CARDINALITY(virKeyCodeTable_usb));
verify(VIR_KEYMAP_ENTRY_MAX == ARRAY_CARDINALITY(virKeyCodeTable_win32));
verify(VIR_KEYMAP_ENTRY_MAX == ARRAY_CARDINALITY(virKeyCodeTable_rfb));
verify(VIR_KEYMAP_ENTRY_MAX == ARRAY_CARDINALITY(virKeyNameTable_linux));
verify(VIR_KEYMAP_ENTRY_MAX == ARRAY_CARDINALITY(virKeyNameTable_osx));
verify(VIR_KEYMAP_ENTRY_MAX == ARRAY_CARDINALITY(virKeyNameTable_win32));

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

int virKeycodeValueFromString(virKeycodeSet codeset,
                              const char *keyname)
{
    size_t i;

    for (i = 0; i < VIR_KEYMAP_ENTRY_MAX; i++) {
        if (!virKeymapNames[codeset] ||
            !virKeymapValues[codeset])
            continue;

        const char *name = virKeymapNames[codeset][i];

        if (name && STREQ_NULLABLE(name, keyname))
            return virKeymapValues[codeset][i];
    }

    return -1;
}


int virKeycodeValueTranslate(virKeycodeSet from_codeset,
                             virKeycodeSet to_codeset,
                             int key_value)
{
    size_t i;

    if (key_value < 0)
        return -1;


    for (i = 0; i < VIR_KEYMAP_ENTRY_MAX; i++) {
        if (virKeymapValues[from_codeset][i] == key_value)
            return virKeymapValues[to_codeset][i];
    }

    return -1;
}
