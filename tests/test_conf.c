#include <config.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "virconf.h"
#include "viralloc.h"

int main(int argc, char **argv)
{
    int ret, exit_code = EXIT_FAILURE;
    virConfPtr conf;
    int len = 10000;
    char *buffer = NULL;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s conf_file\n", argv[0]);
        goto cleanup;
    }

    if (VIR_ALLOC_N_QUIET(buffer, len) < 0) {
        fprintf(stderr, "out of memory\n");
        goto cleanup;
    }
    conf = virConfReadFile(argv[1], 0);
    if (conf == NULL) {
        fprintf(stderr, "Failed to process %s\n", argv[1]);
        goto cleanup;
    }
    ret = virConfWriteMem(buffer, &len, conf);
    if (ret < 0) {
        fprintf(stderr, "Failed to serialize %s back\n", argv[1]);
        goto cleanup;
    }
    virConfFree(conf);
    if (fwrite(buffer, 1, len, stdout) != len) {
        fprintf(stderr, "Write failed: %s\n", strerror(errno));
        goto cleanup;
    }

    exit_code = EXIT_SUCCESS;

 cleanup:
    VIR_FREE(buffer);
    return exit_code;
}
