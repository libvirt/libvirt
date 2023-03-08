/*
 * qemucapabilitiesnumbering.c: swiss-army knife for qemu capability data manipulation
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

#include "testutils.h"
#include "testutilsqemu.h"
#include "qemumonitortestutils.h"

struct qmpTuple {
    virJSONValue *command;
    virJSONValue *reply;
};

struct qmpCommandList {
    struct qmpTuple *items;
    size_t nitems;
};

typedef struct qmpCommandList qmpCommandList;


static int
modify(struct qmpCommandList *list G_GNUC_UNUSED)
{
    /* in case you want to programmatically modify the replies file enable the
     * following block and modify it to your needs. After compiling run this
     * with:
     *
     * VIR_TEST_REGENERATE_OUTPUT=1 tests/qemucapabilitiesnumbering
     *
     * This applies the modification along with updating the files. Use git to
     * your advantage to roll back mistakes.
     */
#if 0
    struct qmpTuple tmptuple = { NULL, NULL };
    size_t found = 0;
    size_t i;

    for (i = 0; i < list->nitems; i++) {
        struct qmpTuple *item = list->items + i;
        const char *cmdname = virJSONValueObjectGetString(item->command, "execute");

        if (STREQ_NULLABLE(cmdname, "qom-list-properties")) {
            found = i;
            // break; /* uncomment if you want to find the first occurrence */
        }
    }

    if (found == 0) {
        fprintf(stderr, "entry not found!!!\n");
        return -1;
    }

    tmptuple.command = virJSONValueFromString("{\"execute\":\"dummy\"}");
    tmptuple.reply = virJSONValueFromString("{\"return\":{}}");
    // tmptuple.reply = virTestLoadFileJSON("path/", "to/", "file.json");

    ignore_value(VIR_INSERT_ELEMENT(list->items, found + 1, list->nitems, tmptuple));
#endif

    return 0;
}


static void
qmpCommandListFree(qmpCommandList* list)
{
    size_t i;

    if (!list)
        return;

    for (i = 0; i < list->nitems; i++) {
        struct qmpTuple *item = list->items + i;

        virJSONValueFree(item->command);
        virJSONValueFree(item->reply);
    }

    g_free(list->items);
    g_free(list);
}


G_DEFINE_AUTOPTR_CLEANUP_FUNC(qmpCommandList, qmpCommandListFree);


static qmpCommandList *
loadReplies(const char *filename)
{
    g_autofree char *replies = NULL;
    g_autofree struct qemuMonitorTestCommandReplyTuple *items = NULL;
    size_t nitems = 0;
    g_autoptr(qmpCommandList) list = NULL;
    size_t i;

    if (virTestLoadFile(filename, &replies) < 0) {
        fprintf(stderr, "Failed to load '%s'\n", filename);
        return NULL;
    }

    if (qemuMonitorTestProcessFileEntries(replies, filename, &items, &nitems) < 0)
        return NULL;

    list = g_new0(qmpCommandList, 1);
    list->items = g_new0(struct qmpTuple, nitems);

    for (i = 0; i < nitems; i++) {
        struct qemuMonitorTestCommandReplyTuple *item = items + i;

        if (!(list->items[list->nitems].command = virJSONValueFromString(item->command)) ||
            !(list->items[list->nitems++].reply = virJSONValueFromString(item->reply)))
            return NULL;
    }

    return g_steal_pointer(&list);
}

/* see printLineSkipEmpty in tests/qemucapsprobemock.c */
static void
printLineSkipEmpty(const char *p,
                   virBuffer *buf)
{
    for (; *p; p++) {
        if (p[0] == '\n' && p[1] == '\n')
            continue;

        virBufferAddChar(buf, *p);
    }
}


static void
renumberItem(virJSONValue *val,
             size_t num)
{
    g_autoptr(virJSONValue) label = virJSONValueNewString(g_strdup_printf("libvirt-%zu", num));

    virJSONValueObjectReplaceValue(val, "id", &label);
}


static int
output(virBuffer *buf,
       qmpCommandList *list)
{
    size_t commandindex = 1;
    size_t i;

    for (i = 0; i < list->nitems; i++) {
        struct qmpTuple *item = list->items + i;
        g_autofree char *jsoncommand = NULL;
        g_autofree char *jsonreply = NULL;

        if (STREQ_NULLABLE(virJSONValueObjectGetString(item->command, "execute"), "qmp_capabilities"))
            commandindex = 1;

        /* fix numbering */
        renumberItem(item->command, commandindex);
        renumberItem(item->reply, commandindex);
        commandindex++;

        /* output formatting */
        if (!(jsoncommand = virJSONValueToString(item->command, true)) ||
            !(jsonreply = virJSONValueToString(item->reply, true)))
            return -1;

        printLineSkipEmpty(jsoncommand, buf);
        virBufferAddLit(buf, "\n");
        printLineSkipEmpty(jsonreply, buf);
        virBufferAddLit(buf, "\n");
    }

    virBufferTrim(buf, "\n");

    return 0;
}


static int
testCapsFile(const void *opaque)
{
    const char *repliesFile = opaque;
    g_autoptr(qmpCommandList) list = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    if (!(list = loadReplies(repliesFile)))
        return -1;

    if (virTestGetRegenerate() > 0) {
        if (modify(list) < 0)
            return -1;
    }

    output(&buf, list);

    if (virTestCompareToFile(virBufferCurrentContent(&buf), repliesFile) < 0)
        return -1;

    return 0;
}


static int
iterateCapsFile(const char *inputDir,
                const char *prefix,
                const char *version,
                const char *archName,
                const char *variant,
                const char *suffix,
                void *opaque G_GNUC_UNUSED)
{
    g_autofree char *repliesFile = g_strdup_printf("%s/%s_%s_%s%s.%s",
                                                   inputDir, prefix, version,
                                                   archName, variant, suffix);

    return virTestRun(repliesFile, testCapsFile, repliesFile);
}


static int
testmain(void)
{
    if (testQemuCapsIterate(".replies", iterateCapsFile, NULL) < 0)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

VIR_TEST_MAIN(testmain)
