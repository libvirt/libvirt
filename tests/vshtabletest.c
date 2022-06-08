/*
 * Copyright (C) 2018 Red Hat, Inc.
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
 */

#include <config.h>

#include <locale.h>
#ifdef WITH_XLOCALE_H
# include <xlocale.h>
#endif
#include <wchar.h>
#include <wctype.h>

#include "internal.h"
#include "testutils.h"
#include "../tools/vsh-table.h"

static int
testVshTableNew(const void *opaque G_GNUC_UNUSED)
{
    g_autoptr(vshTable) table = vshTableNew(NULL, NULL);

    if (table) {
        fprintf(stderr, "expected failure when passing null to vshTableNew\n");
        return -1;
    }

    return 0;
}

static int
testVshTableHeader(const void *opaque G_GNUC_UNUSED)
{
    int ret = 0;
    g_autofree char *act = NULL;
    g_autofree char *act2 = NULL;
    const char *exp =
        " 1   fedora28   running\n"
        " 2   rhel7.5    running\n";
    const char *exp2 =
        " Id   Name       State\n"
        "--------------------------\n"
        " 1    fedora28   running\n"
        " 2    rhel7.5    running\n";

    g_autoptr(vshTable) table = vshTableNew("Id", "Name", "State",
                                    NULL); //to ask about return
    if (!table)
        return -1;

    vshTableRowAppend(table, "1", "fedora28", "running", NULL);
    vshTableRowAppend(table, "2", "rhel7.5", "running",
                      NULL);

    act = vshTablePrintToString(table, false);
    if (virTestCompareToString(exp, act) < 0)
        ret = -1;

    act2 = vshTablePrintToString(table, true);
    if (virTestCompareToString(exp2, act2) < 0)
        ret = -1;

    return ret;
}

static int
testVshTableRowAppend(const void *opaque G_GNUC_UNUSED)
{
    g_autoptr(vshTable) table = vshTableNew("Id", "Name", NULL);
    if (!table)
        return -1;

    if (vshTableRowAppend(table, NULL, NULL) >= 0) {
        fprintf(stderr, "Appending NULL shouldn't work\n");
        return -1;
    }

    if (vshTableRowAppend(table, "2", NULL) >= 0) {
        fprintf(stderr, "Appending less items than in header\n");
        return -1;
    }

    if (vshTableRowAppend(table, "2", "rhel7.5", "running",
                      NULL) >= 0) {
        fprintf(stderr, "Appending more items than in header\n");
        return -1;
    }

    if (vshTableRowAppend(table, "2", "rhel7.5", NULL) < 0) {
        fprintf(stderr, "Appending same number of items as in header"
                        " should not return NULL\n");
        return -1;
    }

    return 0;
}

static int
testUnicode(const void *opaque G_GNUC_UNUSED)
{
    g_autofree char *act = NULL;

    const char *exp =
        " Id   名稱                  государство\n"
        "-----------------------------------------\n"
        " 1    fedora28              running\n"
        " 2    つへソrhel7.5つへソ   running\n";
    g_autoptr(vshTable) table = NULL;

    table = vshTableNew("Id", "名稱", "государство", NULL);
    if (!table)
        return -1;

    vshTableRowAppend(table, "1", "fedora28", "running", NULL);
    vshTableRowAppend(table, "2", "つへソrhel7.5つへソ", "running",
                      NULL);

    act = vshTablePrintToString(table, true);
    if (virTestCompareToString(exp, act) < 0)
        return -1;

    return 0;
}

/* Point of this test is to see how table behaves with right to left writing */
static int
testUnicodeArabic(const void *opaque G_GNUC_UNUSED)
{
    g_autofree char *act = NULL;

    const char *exp =
        " ﻡﺍ ﻢﻣﺍ ﻕﺎﺌﻣﺓ   ﺓ ﺎﻠﺼﻋ                                                 ﺍﻸﺜﻧﺎﻧ\n"
        "-------------------------------------------------------------------------------------------\n"
        " 1              ﻉﺪﻴﻟ ﺎﻠﺜﻘﻴﻟ ﻕﺎﻣ ﻊﻧ, ٣٠ ﻎﻴﻨﻳﺍ ﻮﺘﻧﺎﻤﺗ ﺎﻠﺛﺎﻠﺛ، ﺄﺳﺭ, ﺩﻮﻟ   ﺩﻮﻟ. ﺄﻣﺎﻣ ﺍ ﺎﻧ ﻲﻜﻧ\n"
        " ﺺﻔﺣﺓ           ﺖﻜﺘﻴﻛﺍً ﻊﻟ, ﺎﻠﺠﻧﻭﺩ ﻭﺎﻠﻌﺗﺍﺩ                              ﺵﺭ\n";
    g_autoptr(vshTable) table = NULL;
    wchar_t wc;

    /* If this char is not classed as printable, the actual
     * output won't match what this test expects. The code
     * is still operating correctly, but we have different
     * layout */
    mbrtowc(&wc, "،", MB_CUR_MAX, NULL);
    if (!iswprint(wc))
        return EXIT_AM_SKIP;

    table = vshTableNew("ﻡﺍ ﻢﻣﺍ ﻕﺎﺌﻣﺓ", "ﺓ ﺎﻠﺼﻋ", "ﺍﻸﺜﻧﺎﻧ", NULL);
    if (!table)
        return -1;
    vshTableRowAppend(table,
                      "1",
                      "ﻉﺪﻴﻟ ﺎﻠﺜﻘﻴﻟ ﻕﺎﻣ ﻊﻧ, ٣٠ ﻎﻴﻨﻳﺍ ﻮﺘﻧﺎﻤﺗ ﺎﻠﺛﺎﻠﺛ، ﺄﺳﺭ, ﺩﻮﻟ",
                      "ﺩﻮﻟ. ﺄﻣﺎﻣ ﺍ ﺎﻧ ﻲﻜﻧ",
                      NULL);
    vshTableRowAppend(table, "ﺺﻔﺣﺓ", "ﺖﻜﺘﻴﻛﺍً ﻊﻟ, ﺎﻠﺠﻧﻭﺩ ﻭﺎﻠﻌﺗﺍﺩ", "ﺵﺭ",
                      NULL);
    act = vshTablePrintToString(table, true);
    if (virTestCompareToString(exp, act) < 0)
        return -1;

    return 0;
}

/* Testing zero-width characters by inserting few zero-width spaces */
static int
testUnicodeZeroWidthChar(const void *opaque G_GNUC_UNUSED)
{
    g_autoptr(vshTable) table = NULL;
    const char *exp =
        " I\u200Bd   Name       \u200BStatus\n"
        "--------------------------\n"
        " 1\u200B    fedora28   run\u200Bning\n"
        " 2    rhel7.5    running\n";
    g_autofree char *act = NULL;
    wchar_t wc;

    /* If this char is not classed as printable, the actual
     * output won't match what this test expects. The code
     * is still operating correctly, but we have different
     * layout */
    mbrtowc(&wc, "\u200B", MB_CUR_MAX, NULL);
    if (!iswprint(wc))
        return EXIT_AM_SKIP;

    table = vshTableNew("I\u200Bd", "Name", "\u200BStatus", NULL);
    if (!table)
        return -1;
    vshTableRowAppend(table, "1\u200B", "fedora28", "run\u200Bning", NULL);
    vshTableRowAppend(table, "2", "rhel7.5", "running", NULL);
    act = vshTablePrintToString(table, true);

    if (virTestCompareToString(exp, act) < 0)
        return -1;

    return 0;
}

static int
testUnicodeCombiningChar(const void *opaque G_GNUC_UNUSED)
{
    g_autoptr(vshTable) table = NULL;
    const char *exp =
        " Id   Náme       Ⓢtatus\n"
        "--------------------------\n"
        " 1    fědora28   running\n"
        " 2    rhel       running\n";
    g_autofree char *act = NULL;

    table = vshTableNew("Id", "Náme", "Ⓢtatus", NULL);
    if (!table)
        return -1;
    vshTableRowAppend(table, "1", "fědora28", "running", NULL);
    vshTableRowAppend(table, "2", "rhel", "running", NULL);
    act = vshTablePrintToString(table, true);

    if (virTestCompareToString(exp, act) < 0)
        return -1;

    return 0;
}

/* Testing zero-width characters by inserting few zero-width spaces */
static int
testUnicodeNonPrintableChar(const void *opaque G_GNUC_UNUSED)
{
    g_autoptr(vshTable) table = NULL;
    const char *exp =
        " I\\x09d   Name           Status\n"
        "----------------------------------\n"
        " 1        f\\x07edora28   running\n"
        " 2        rhel7.5        running\n";
    g_autofree char *act = NULL;

    table = vshTableNew("I\td", "Name", "Status", NULL);
    if (!table)
        return -1;
    vshTableRowAppend(table, "1", "f\aedora28", "running", NULL);
    vshTableRowAppend(table, "2", "rhel7.5", "running", NULL);
    act = vshTablePrintToString(table, true);

    if (virTestCompareToString(exp, act) < 0)
        return -1;

    return 0;
}

static int
testNTables(const void *opaque G_GNUC_UNUSED)
{
    g_autoptr(vshTable) table1 = NULL;
    g_autoptr(vshTable) table2 = NULL;
    g_autoptr(vshTable) table3 = NULL;
    const char *exp1 =
        " Id   Name       Status\n"
        "--------------------------\n"
        " 1    fedora28   running\n"
        " 2    rhel7.5    running\n"
        " 3    gazpacho   \n";
    const char *exp2 =
        " Id   Name   Status\n"
        "---------------------\n";
    const char *exp3 =
        " Id\n"
        "-----\n"
        " 1\n"
        " 2\n"
        " 3\n"
        " 4\n";
    g_autofree char *act1 = NULL;
    g_autofree char *act2 = NULL;
    g_autofree char *act3 = NULL;

    table1 = vshTableNew("Id", "Name", "Status", NULL);
    if (!table1)
        return -1;
    vshTableRowAppend(table1, "1", "fedora28", "running", NULL);
    vshTableRowAppend(table1, "2", "rhel7.5", "running", NULL);
    vshTableRowAppend(table1, "3", "gazpacho", "", NULL);
    act1 = vshTablePrintToString(table1, true);

    table2 = vshTableNew("Id", "Name", "Status", NULL);
    if (!table2)
        return -1;
    act2 = vshTablePrintToString(table2, true);

    table3 = vshTableNew("Id", NULL);
    if (!table3)
        return -1;
    vshTableRowAppend(table3, "1", NULL);
    vshTableRowAppend(table3, "2", NULL);
    vshTableRowAppend(table3, "3", NULL);
    vshTableRowAppend(table3, "4", NULL);
    act3 = vshTablePrintToString(table3, true);

    if (virTestCompareToString(exp1, act1) < 0)
        return -1;
    if (virTestCompareToString(exp2, act2) < 0)
        return -1;
    if (virTestCompareToString(exp3, act3) < 0)
        return -1;

    return 0;
}

static int
mymain(void)
{
    int ret = 0;

    if (!setlocale(LC_CTYPE, "en_US.UTF-8"))
        return EXIT_AM_SKIP;

    if (virTestRun("testVshTableNew", testVshTableNew, NULL) < 0)
        ret = -1;

    if (virTestRun("testVshTableHeader", testVshTableHeader, NULL) < 0)
        ret = -1;

    if (virTestRun("testVshTableRowAppend", testVshTableRowAppend, NULL) < 0)
        ret = -1;

    if (virTestRun("testUnicode", testUnicode, NULL) < 0)
        ret = -1;

    if (virTestRun("testUnicodeArabic", testUnicodeArabic, NULL) < 0)
        ret = -1;

    if (virTestRun("testUnicodeZeroWidthChar",
                   testUnicodeZeroWidthChar,
                   NULL) < 0)
        ret = -1;

    if (virTestRun("testUnicodeCombiningChar",
                   testUnicodeCombiningChar,
                   NULL) < 0)
        ret = -1;

    if (virTestRun("testUnicodeNonPrintableChar",
                   testUnicodeNonPrintableChar,
                   NULL) < 0)
        ret = -1;

    if (virTestRun("testNTables", testNTables, NULL) < 0)
        ret = -1;

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
