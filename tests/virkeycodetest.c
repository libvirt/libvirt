/*
 * Copyright (C) 2013 Red Hat, Inc.
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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <stdlib.h>

#include "testutils.h"

#include "virkeycode.h"
#include "virutil.h"
#include "virerror.h"
#include "viralloc.h"
#include "virlog.h"

#include "virlockspace.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.keycodetest");

static int testKeycodeMapping(const void *data ATTRIBUTE_UNUSED)
{
    int ret = -1;
    int got;

#define TRANSLATE(from, to, val, want)                                  \
    do {                                                                \
        if ((got = virKeycodeValueTranslate(VIR_KEYCODE_SET_##from,     \
                                            VIR_KEYCODE_SET_##to,       \
                                            val)) != want) {            \
            fprintf(stderr, "Translating %d from %s to %s, got %d want %d\n", \
                    val, #from, #to, got, want);                        \
            goto cleanup;                                               \
        }                                                               \
    } while (0)

    TRANSLATE(LINUX, LINUX, 111, 111);
    TRANSLATE(LINUX, USB, 111, 76);
    TRANSLATE(LINUX, RFB, 88, 88);
    TRANSLATE(LINUX, RFB, 160, 163);
    TRANSLATE(ATSET2, ATSET3, 259, 55);

#undef TRANSLATE

    ret = 0;
 cleanup:
    return ret;
}


static int testKeycodeStrings(const void *data ATTRIBUTE_UNUSED)
{
    int ret = -1;
    int got;

#define TRANSLATE(from, str, want)                                      \
    do {                                                                \
        if ((got = virKeycodeValueFromString(VIR_KEYCODE_SET_##from,    \
                                             str)) != want) {           \
            fprintf(stderr, "Converting %s from %s, got %d want %d\n",  \
                    str, #from, got, want);                             \
            goto cleanup;                                               \
        }                                                               \
    } while (0)

    TRANSLATE(LINUX, "KEY_DELETE", 111);
    TRANSLATE(OSX, "Function", 0x3f);
    TRANSLATE(WIN32, "VK_UP", 0x26);

#undef TRANSLATE

    ret = 0;
 cleanup:
    return ret;
}

static int
mymain(void)
{
    int ret = 0;

    if (virTestRun("Keycode mapping ", testKeycodeMapping, NULL) < 0)
        ret = -1;
    if (virTestRun("Keycode strings ", testKeycodeStrings, NULL) < 0)
        ret = -1;

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
