#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <unistd.h>
#include <libvirt/libvirt-admin.h>
#include <libvirt/virterror.h>

static void printHelp(const char *argv0)
{
    fprintf(stderr,
            ("Usage:\n"
              "  %s [options]\n"
              "\n"
              "Options:\n"
              "  -h          Print this message.\n"
              "  -o [string] Specify new log outputs.\n"
              "  -f [string] Specify new log filters.\n"
              "\n"),
            argv0);
}

int main(int argc, char **argv)
{
    int ret, c;
    virAdmConnectPtr conn = NULL;
    char *get_outputs = NULL;
    char *get_filters = NULL;
    const char *set_outputs = NULL;
    const char *set_filters = NULL;

    ret = c = -1;
    opterr = 0;

    while ((c = getopt(argc, argv, ":hpo:f:")) > 0) {
        switch (c) {
        case 'h':
            printHelp(argv[0]);
            exit(EXIT_SUCCESS);
        case 'o':
            set_outputs = optarg;
            break;
        case 'f':
            set_filters = optarg;
            break;
        case ':':
            fprintf(stderr, "Missing argument for option -%c\n", optopt);
            exit(EXIT_FAILURE);
        case '?':
            fprintf(stderr, "Unrecognized option '-%c'\n", optopt);
            exit(EXIT_FAILURE);
        }
    }

    /* first, open a connection to the daemon */
    if (!(conn = virAdmConnectOpen(NULL, 0)))
        goto cleanup;

    /* get the currently defined log outputs and filters */
    if (virAdmConnectGetLoggingOutputs(conn, &get_outputs, 0) < 0 ||
        virAdmConnectGetLoggingFilters(conn, &get_filters, 0) < 0)
        goto cleanup;

    fprintf(stdout,
            "Current settings:\n"
            " outputs: %s\n"
            " filters: %s\n"
            "\n",
            get_outputs, get_filters ? get_filters : "None");

    free(get_outputs);
    free(get_filters);

    /* no arguments were provided */
    if (argc == 1) {
        ret = 0;
        goto cleanup;
    }

    /* now, try to change the current log output and filters */
    if (virAdmConnectSetLoggingOutputs(conn, set_outputs, 0) < 0)
        goto cleanup;

    if (virAdmConnectSetLoggingFilters(conn, set_filters, 0) < 0)
        goto cleanup;

    /* get the currently defined log outputs and filters */
    if (virAdmConnectGetLoggingOutputs(conn, &get_outputs, 0) < 0 ||
        virAdmConnectGetLoggingFilters(conn, &get_filters, 0) < 0)
        goto cleanup;

    fprintf(stdout,
            "New settings:\n"
            " outputs: %s\n"
            " filters: %s\n"
            "\n",
            get_outputs ? get_outputs : "Default",
            get_filters ? get_filters : "None");

    free(get_outputs);
    free(get_filters);

    ret = 0;
 cleanup:
    virAdmConnectClose(conn);
    return ret;
}
