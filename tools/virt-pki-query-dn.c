/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#include "internal.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "virgettext.h"


static void
glib_auto_cleanup_gnutls_x509_crt_t(gnutls_x509_crt_t *pointer)
{
    gnutls_x509_crt_deinit(*pointer);
}


static void
print_usage(const char *progname,
            FILE *out)
{
  fprintf(out,
          _("Usage:\n"
            "  %1$s FILE\n"
            "  %2$s { -v | -h }\n"
            "\n"
            "Extract Distinguished Name from a PEM certificate.\n"
            "The output is meant to be used in the tls_allowed_dn_list\n"
            "configuration option in the libvirtd.conf file.\n"
            "\n"
            "  FILE            certificate file to extract the DN from\n"
            "\n"
            "options:\n"
            "  -h | --help     display this help and exit\n"
            "  -v | --version  output version information and exit\n"),
          progname, progname);
}


int
main(int argc,
     char **argv)
{
    const char *progname = NULL;
    const char *filename = NULL;
    size_t dnamesize = 256;
    size_t bufsize = 0;
    g_autofree char *dname = g_new0(char, dnamesize);
    g_autofree char *buf = NULL;
    g_auto(gnutls_x509_crt_t) crt = {0};
    gnutls_datum_t crt_data = {0};
    g_autoptr(GError) error = NULL;
    int arg = 0;
    int rv = 0;

    struct option opt[] = {
        { "help", no_argument, NULL, 'h' },
        { "version", optional_argument, NULL, 'v' },
        { NULL, 0, NULL, 0 },
    };

    if (virGettextInitialize() < 0)
        return EXIT_FAILURE;

    if (!(progname = strrchr(argv[0], '/')))
        progname = argv[0];
    else
        progname++;

    while ((arg = getopt_long(argc, argv, "hv", opt, NULL)) != -1) {
        switch (arg) {
        case 'v':
            printf("%s\n", PACKAGE_VERSION);
            return EXIT_SUCCESS;
        case 'h':
            print_usage(progname, stdout);
            return EXIT_SUCCESS;
        default:
            print_usage(progname, stderr);
            return EXIT_FAILURE;
        }
    }

    if (optind != argc - 1) {
        print_usage(progname, stderr);
        return EXIT_FAILURE;
    }

    filename = argv[optind];

    g_file_get_contents(filename, &buf, &bufsize, &error);
    if (error) {
        g_printerr("%s: %s\n", progname, error->message);
        return EXIT_FAILURE;
    }

    if (bufsize > UINT_MAX) {
        g_printerr(_("%1$s: File '%2$s' is too large\n"), progname, filename);
        return EXIT_FAILURE;
    }

    crt_data.data = (unsigned char *)buf;
    crt_data.size = bufsize;

    rv = gnutls_x509_crt_init(&crt);
    if (rv < 0) {
        g_printerr(_("Unable to initialize certificate: %1$s\n"),
                   gnutls_strerror(rv));
        return EXIT_FAILURE;
    }

    rv = gnutls_x509_crt_import(crt, &crt_data, GNUTLS_X509_FMT_PEM);
    if (rv < 0) {
        g_printerr(_("Unable to load certificate, make sure it is in PEM format: %1$s\n"),
                   gnutls_strerror(rv));
        return EXIT_FAILURE;
    }

    rv = gnutls_x509_crt_get_dn(crt, dname, &dnamesize);
    if (rv == GNUTLS_E_SHORT_MEMORY_BUFFER) {
        dname = g_realloc(dname, dnamesize);
        rv = gnutls_x509_crt_get_dn(crt, dname, &dnamesize);
    }
    if (rv != 0) {
        g_printerr(_("Failed to get distinguished name: %1$s\n"),
                   gnutls_strerror(rv));
        return EXIT_FAILURE;
    }

    printf("%s\n", dname);

    return EXIT_SUCCESS;
}
