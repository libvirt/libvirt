#include <config.h>

#ifdef WITH_OPENVZ

# include <stdio.h>
# include <string.h>
# include <unistd.h>

# include "internal.h"
# include "memory.h"
# include "testutils.h"
# include "util.h"
# include "openvz/openvz_conf.h"

struct testConfigParam {
    const char *param;
    const char *value;
    int ret;
};

static struct testConfigParam configParams[] = {
    { "OSTEMPLATE", "rhel-5-lystor", 1 },
    { "IP_ADDRESS", "194.44.18.88", 1 },
    { "THIS_PARAM_IS_MISSING", NULL, 0 },
};

static int
testReadConfigParam(const void *data ATTRIBUTE_UNUSED)
{
    int result = -1;
    int i;
    char *conf = NULL;
    char *value = NULL;

    if (virAsprintf(&conf, "%s/openvzutilstest.conf", abs_srcdir) < 0) {
        return -1;
    }

    for (i = 0; i < ARRAY_CARDINALITY(configParams); ++i) {
        if (openvzReadConfigParam(conf, configParams[i].param,
                                  &value) != configParams[i].ret) {
            goto cleanup;
        }

        if (configParams[i].ret != 1) {
            continue;
        }

        if (STRNEQ(configParams[i].value, value)) {
            virtTestDifference(stderr, configParams[i].value, value);
            goto cleanup;
        }
    }

    result = 0;

cleanup:
    VIR_FREE(conf);
    VIR_FREE(value);

    return result;
}

static int
mymain(void)
{
    int result = 0;

# define DO_TEST(_name)                                                       \
        do {                                                                  \
            if (virtTestRun("OpenVZ "#_name, 1, test##_name,                  \
                            NULL) < 0) {                                      \
                result = -1;                                                  \
            }                                                                 \
        } while (0)

    DO_TEST(ReadConfigParam);

    return result == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)

#else

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_OPENVZ */
