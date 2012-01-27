/*
 * virt-host-check.c: Sanity check a hypervisor host
 *
 * Copyright (C) 2012 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <gettext.h>
#include <getopt.h>
#include <locale.h>

#include "internal.h"
#include "configmake.h"

#include "virt-host-validate-common.h"
#if WITH_QEMU
# include "virt-host-validate-qemu.h"
#endif
#if WITH_LXC
# include "virt-host-validate-lxc.h"
#endif

static void
show_help(FILE *out, const char *argv0)
{
    fprintf(out,
            _("\n"
              "syntax: %s [OPTIONS] [HVTYPE]\n"
              "\n"
              " Hypervisor types:\n"
              "\n"
              "   - qemu\n"
              "   - lxc\n"
              "\n"
              " Options:\n"
              "   -h, --help     Display command line help\n"
              "   -v, --version  Display command version\n"
              "   -q, --quiet    Don't display progress information\n"
              "\n"),
            argv0);
}

static void
show_version(FILE *out, const char *argv0)
{
    fprintf(out, "version: %s %s\n", argv0, VERSION);
}

static const struct option argOptions[] = {
    { "help", 0, NULL, 'h', },
    { "version", 0, NULL, 'v', },
    { "quiet", 0, NULL, 'q', },
    { NULL, 0, NULL, '\0', }
};

int
main(int argc, char **argv)
{
    const char *hvname = NULL;
    int c;
    int ret = EXIT_SUCCESS;
    bool quiet = false;
    bool usedHvname = false;

    if (!setlocale(LC_ALL, "")) {
        perror("setlocale");
        /* failure to setup locale is not fatal */
    }
    if (!bindtextdomain(PACKAGE, LOCALEDIR)) {
        perror("bindtextdomain");
        return EXIT_FAILURE;
    }
    if (!textdomain(PACKAGE)) {
        perror("textdomain");
        return EXIT_FAILURE;
    }

    while ((c = getopt_long(argc, argv, "hvq", argOptions, NULL)) != -1) {
        switch (c) {
        case 'v':
            show_version(stdout, argv[0]);
            return EXIT_SUCCESS;

        case 'h':
            show_help(stdout, argv[0]);
            return EXIT_SUCCESS;

        case 'q':
            quiet = true;
            break;

        case '?':
        default:
            show_help(stderr, argv[0]);
            return EXIT_FAILURE;
        }
    }

    if ((argc-optind) > 2) {
        fprintf(stderr, _("%s: too many command line arguments\n"), argv[0]);
        show_help(stderr, argv[0]);
        return EXIT_FAILURE;
    }

    if (argc > 1)
        hvname = argv[optind];

    virHostMsgSetQuiet(quiet);

#if WITH_QEMU
    if (!hvname || STREQ(hvname, "qemu")) {
        usedHvname = true;
        if (virHostValidateQEMU() < 0)
            ret = EXIT_FAILURE;
    }
#endif

#if WITH_LXC
    if (!hvname || STREQ(hvname, "lxc")) {
        usedHvname = true;
        if (virHostValidateLXC() < 0)
            ret = EXIT_FAILURE;
    }
#endif

    if (hvname && !usedHvname) {
        fprintf(stderr, _("%s: unsupported hypervisor name %s\n"),
                argv[0], hvname);
        return EXIT_FAILURE;
    }

    return ret;
}

/*

=pod

=head1 NAME

  virt-host-validate - validate host virtualization setup

=head1 SYNOPSIS

  virt-host-validate [OPTIONS...] [HV-TYPE]

=head1 DESCRIPTION

This tool validates that the host is configured in a suitable
way to run libvirt hypervisor drivers. If invoked without any
arguments it will check support for all hypervisor drivers it
is aware of. Optionally it can be given a particular hypervisor
type ('qemu' or 'lxc') to restrict the checks to those relevant
for that virtualization technology

=head1 OPTIONS

=over 4

=item C<-v>, C<--version>

Display the command version

=item C<-h>, C<--help>

Display the command line help

=item C<-q>, C<--quiet>

Don't display details of individual checks being performed.
Only display output if a check does not pass.

=back

=head1 EXIT STATUS

Upon successful validation, an exit status of 0 will be set. Upon
failure a non-zero status will be set.

=head1 AUTHOR

Daniel P. Berrange

=head1 BUGS

Report any bugs discovered to the libvirt community via the
mailing list C<http://libvirt.org/contact.html> or bug tracker C<http://libvirt.org/bugs.html>.
Alternatively report bugs to your software distributor / vendor.

=head1 COPYRIGHT

Copyright (C) 2012 by Red Hat, Inc.

=head1 LICENSE

virt-host-validate is distributed under the terms of the GNU GPL v2+.
This is free software; see the source for copying conditions. There
is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE

=head1 SEE ALSO

C<virsh(1)>, C<virt-pki-validate>, C<virt-xml-validate>

=cut

*/
