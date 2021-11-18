#include <config.h>

#include "testutils.h"
#include "virfilewrapper.h"
#include "virprocess.h"


struct testData {
    const char *filename;
    const char *command;
    size_t count;
    bool self;
};


static int
test_virProcessGetStat(const void *opaque)
{
    struct testData *data = (struct testData *) opaque;
    g_autofree char *data_dir = NULL;
    g_auto(GStrv) proc_stat = NULL;
    size_t len = 0;
    id_t id = data->self ? 0 : -1;
    const char *command = NULL;

    data_dir = g_strdup_printf("%s/virprocessstatdata/%s/",
                               abs_srcdir, data->filename);

    /* We are using predictable id of -1 because this case we will clearly see
     * that the test failed in case of virFileWrapper failure */
    if (id)
        virFileWrapperAddPrefix("/proc/-1/task/-1/", data_dir);
    else
        virFileWrapperAddPrefix("/proc/self/", data_dir);

    proc_stat = virProcessGetStat(id, id);

    virFileWrapperClearPrefixes();

    if (!proc_stat) {
        fprintf(stderr, "Could not get process stats\n");
        return -1;
    }

    len = g_strv_length(proc_stat);
    if (data->count != len) {
        fprintf(stderr, "Count incorrect, expected %zu, got %zu\n",
                data->count, len);
        return -1;
    }

    command = proc_stat[VIR_PROCESS_STAT_COMM];
    if (!STREQ_NULLABLE(data->command, command)) {
        fprintf(stderr, "Command incorrect, expected %s, got %s\n",
                data->command, command);
        return -1;
    }

    return 0;
}


static int
mymain(void)
{
    struct testData data = {0};
    int ret = 0;

#define DO_TEST(_filename, _command, _count, _self) \
    do { \
        data = (struct testData){ \
            .filename = _filename, \
            .command = _command, \
            .count = _count, \
            .self = _self, \
        }; \
        if (virTestRun("Reading process stat: " _filename, \
                       test_virProcessGetStat, &data) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST("simple", "command", 5, true);
    DO_TEST("complex", "this) is ( a \t weird )\n)( (command ( ", 100, false);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
