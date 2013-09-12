#!/usr/bin/perl
#
# Copyright (C) 2013 Red Hat, Inc.
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
# This script just validates that the stringified version of
# a virAccessPerm enum matches the enum constant name. We do
# a lot of auto-generation of code, so when these don't match
# problems occur, preventing auth from succeeding at all.

my $hdr = shift;
my $impl = shift;

my %perms;

my @perms;

open HDR, $hdr or die "cannot read $hdr: $!";

while (<HDR>) {
    if (/^\s+VIR_ACCESS_PERM_([_A-Z]+)(,?|\s|$)/) {
        my $perm = $1;

        $perms{$perm} = 1 unless ($perm =~ /_LAST$/);
    }
}

close HDR;


open IMPL, $impl or die "cannot read $impl: $!";

my $group;
my $warned = 0;

while (defined (my $line = <IMPL>)) {
    if ($line =~ /VIR_ACCESS_PERM_([_A-Z]+)_LAST/) {
        $group = $1;
    } elsif ($line =~ /"[_a-z]+"/) {
        my @bits = split /,/, $line;
        foreach my $bit (@bits) {
            if ($bit =~ /"([_a-z]+)"/) {
                my $perm = uc($group . "_" . $1);
                if (!exists $perms{$perm}) {
                    print STDERR "Unknown perm string $1 for group $group\n";
                    $warned = 1;
                }
                delete $perms{$perm};
            }
        }
    }
}
close IMPL;

foreach my $perm (keys %perms) {
    print STDERR "Perm $perm had not string form\n";
    $warned = 1;
}

exit $warned;
