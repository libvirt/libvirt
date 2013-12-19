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


#define VIRT_KEY_INTERNAL
#include "virkeymaps.h"

static const char **virKeymapNames[] = {
    [VIR_KEYCODE_SET_LINUX] =
      virKeymapNames_linux,
    [VIR_KEYCODE_SET_XT] =
      NULL,
    [VIR_KEYCODE_SET_ATSET1] =
      NULL,
    [VIR_KEYCODE_SET_ATSET2] =
      NULL,
    [VIR_KEYCODE_SET_ATSET3] =
      NULL,
    [VIR_KEYCODE_SET_OSX] =
      virKeymapNames_os_x,
    [VIR_KEYCODE_SET_XT_KBD] =
      NULL,
    [VIR_KEYCODE_SET_USB] =
      NULL,
    [VIR_KEYCODE_SET_WIN32] =
      virKeymapNames_win32,
    [VIR_KEYCODE_SET_RFB] =
      NULL,
};
verify(ARRAY_CARDINALITY(virKeymapNames) == VIR_KEYCODE_SET_LAST);

static int *virKeymapValues[] = {
    [VIR_KEYCODE_SET_LINUX] =
      virKeymapValues_linux,
    [VIR_KEYCODE_SET_XT] =
      virKeymapValues_xt,
    [VIR_KEYCODE_SET_ATSET1] =
      virKeymapValues_atset1,
    [VIR_KEYCODE_SET_ATSET2] =
      virKeymapValues_atset2,
    [VIR_KEYCODE_SET_ATSET3] =
      virKeymapValues_atset3,
    [VIR_KEYCODE_SET_OSX] =
      virKeymapValues_os_x,
    [VIR_KEYCODE_SET_XT_KBD] =
      virKeymapValues_xt_kbd,
    [VIR_KEYCODE_SET_USB] =
      virKeymapValues_usb,
    [VIR_KEYCODE_SET_WIN32] =
      virKeymapValues_win32,
    [VIR_KEYCODE_SET_RFB] =
      virKeymapValues_rfb,
};
verify(ARRAY_CARDINALITY(virKeymapValues) == VIR_KEYCODE_SET_LAST);

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
