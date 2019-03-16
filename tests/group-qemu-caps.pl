#!/usr/bin/env perl
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.  If not, see
# <http://www.gnu.org/licenses/>.
#
#
# Regroup array values into smaller groups separated by numbered comments.
#
# If --check is the first parameter, the script will return
# a non-zero value if a file is not grouped correctly.
# Otherwise the files are regrouped in place.

use strict;
use warnings;

my $check = 0;

if (defined $ARGV[0] && $ARGV[0] eq "--check") {
    $check = 1;
    shift @ARGV;
}

my $prefix = '';
if (defined $ARGV[0]) {
    $prefix = $ARGV[0];
    shift @ARGV;
}

my $ret = 0;
if (&regroup_caps($prefix . 'src/qemu/qemu_capabilities.c',
                  'virQEMUCaps grouping marker',
                  '\);',
                  0,
                  "              ") < 0) {
    $ret = 1;
}
if (&regroup_caps($prefix . 'src/qemu/qemu_capabilities.h',
                  'virQEMUCapsFlags grouping marker',
                  'QEMU_CAPS_LAST \/\* this must',
                  1,
                  "    ") < 0) {
    $ret = 1;
}

exit $ret;

sub regroup_caps {
    my $filename = shift;
    my $start_regex = shift;
    my $end_regex = shift;
    my $trailing_newline = shift;
    my $counter_prefix = shift;
    my $step = 5;

    open FILE, '<', $filename or die "cannot open $filename: $!";
    my @original = <FILE>;
    close FILE;

    my @fixed;
    my $game_on = 0;
    my $counter = 0;
    foreach (@original) {
        if ($game_on) {
            next if ($_ =~ '/\* [0-9]+ \*/');
            next if (/^\s+$/);
            if ($counter % $step == 0) {
                if ($counter != 0) {
                    push @fixed, "\n";
                }
                push @fixed, "$counter_prefix/* $counter */\n";
            }
            if (!($_ =~ '/\*' && !($_ =~ '\*/'))) {
                # count two-line comments as one line
                $counter++;
            }
        }
        if (/$start_regex/) {
            $game_on = 1;
        } elsif ($game_on && $_ =~ /$end_regex/) {
            if (($counter -1) % $step == 0) {
                pop @fixed; # /* $counter */
                if ($counter != 1) {
                    pop @fixed; # \n
                }
            }
            if ($trailing_newline) {
                push @fixed, "\n";
            }
            $game_on = 0;
        }
        push @fixed, $_;
    }

    if ($check) {
        my $nl = join('', @fixed);
        my $ol = join('', @original);
        unless ($nl eq $ol) {
            open DIFF, "| diff -u $filename -" or die "cannot run diff: $!";
            print DIFF $nl;
            close DIFF;

            print STDERR "Incorrect array grouping in $filename\n";
            print STDERR "Use group-qemu-caps.pl to group long array members\n";
            return -1;
        }
    } else {
        open FILE, '>', $filename or die "cannot open $filename: $!";
        foreach my $line (@fixed) {
            print FILE $line;
        }
        close FILE;
    }
}
