#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "util.h"
#include "testutils.h"
#include "buf.h"
#include "memory.h"

#define TEST_ERROR(...)                             \
    do {                                            \
        if (virTestGetDebug())                      \
            fprintf(stderr, __VA_ARGS__);           \
    } while (0)

struct testInfo {
    int doEscape;
};

static int testBufInfiniteLoop(const void *data ATTRIBUTE_UNUSED)
{
    virBuffer bufinit = VIR_BUFFER_INITIALIZER;
    virBufferPtr buf = &bufinit;
    char *addstr = NULL, *bufret = NULL;
    int ret = -1;
    const struct testInfo *info = data;

    /* This relies of virBuffer internals, so may break if things change
     * in the future */
    virBufferAddChar(buf, 'a');
    if (buf->a != 1002 || buf->b != 1) {
        TEST_ERROR("Buf was not expected size, size=%d use=%d\n",
                   buf->a, buf->b);
        goto out;
    }

    /*
     * Infinite loop triggers if:
     * (strlen + 1 > 1000) && (strlen == buf-size - buf-use - 1)
     */
    if (virAsprintf(&addstr, "%*s", buf->a - buf->b - 1, "a") < 0) {
        goto out;
    }

    if (info->doEscape)
        virBufferEscapeString(buf, "%s", addstr);
    else
        virBufferVSprintf(buf, "%s", addstr);

    ret = 0;
out:
    bufret = virBufferContentAndReset(buf);
    if (!bufret) {
        TEST_ERROR("Buffer had error set");
        ret = -1;
    }

    VIR_FREE(addstr);
    VIR_FREE(bufret);
    return ret;
}

static int
mymain(int argc ATTRIBUTE_UNUSED,
       char **argv ATTRIBUTE_UNUSED)
{
    int ret = 0;


#define DO_TEST(msg, cb, data)                                         \
    do {                                                               \
        struct testInfo info = { data };                               \
        if (virtTestRun("Buf: " msg, 1, cb, &info) < 0)                 \
            ret = -1;                                                  \
    } while (0)

    DO_TEST("EscapeString infinite loop", testBufInfiniteLoop, 1);
    DO_TEST("VSprintf infinite loop", testBufInfiniteLoop, 0);

    return(ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

VIRT_TEST_MAIN(mymain)
