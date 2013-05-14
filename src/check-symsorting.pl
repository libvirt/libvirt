#!/usr/bin/perl

# Copyright (C) 2012-2013 Red Hat, Inc.
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

use strict;
use warnings;

die "syntax: $0 SRCDIR SYMFILE..." unless int(@ARGV) >= 2;

my $ret = 0;
my $srcdir = shift;
my $lastgroup = undef;
foreach my $symfile (@ARGV) {
    open SYMFILE, $symfile or die "cannot read $symfile: $!";

    my $line = 0;
    my $groupfile = "";
    my @group;

    while (<SYMFILE>) {
        chomp;

        if (/^#\s*((\w+\/)*(\w+\.h))\s*$/) {
            $groupfile = $1;
        } elsif (/^#/) {
            # Ignore comments
        } elsif (/^\s*$/) {
            if (@group) {
                &check_sorting(\@group, $symfile, $line, $groupfile);
            }
            @group = ();
            $line = $.;
        } else {
            $_ =~ s/;//;
            push @group, $_;
        }
    }

    close SYMFILE;
    if (@group) {
        &check_sorting(\@group, $symfile, $line, $groupfile);
    }
    $lastgroup = undef;
}

sub check_sorting {
    my $group = shift;
    my $symfile = shift;
    my $line = shift;
    my $groupfile = shift;

    my @group = @{$group};
    my @sorted = sort { lc $a cmp lc $b } @group;
    my $sorted = 1;
    my $first;
    my $last;

    # Check that groups are in order and groupfile exists
    if (defined $lastgroup && lc $lastgroup ge lc $groupfile) {
        print "Symbol block at $symfile:$line: block not sorted\n";
        print "Move $groupfile block before $lastgroup block\n";
        print "\n";
        $ret = 1;
    }
    if (! -e "$srcdir/$groupfile") {
        print "Symbol block at $symfile:$line: $groupfile not found\n";
        print "\n";
        $ret = 1;
    }
    $lastgroup = $groupfile;

    # Check that symbols within a group are in order
    for (my $i = 0 ; $i <= $#sorted ; $i++) {
        if ($sorted[$i] ne $group[$i]) {
            $first = $i unless defined $first;
            $last = $i;
            $sorted = 0;
        }
    }
    if (!$sorted) {
        @group = splice @group, $first, ($last-$first+1);
        @sorted = splice @sorted, $first, ($last-$first+1);
        print "Symbol block at $symfile:$line: symbols not sorted\n";
        print map { "  " . $_ . "\n" } @group;
        print "Correct ordering\n";
        print map { "  " . $_ . "\n" } @sorted;
        print "\n";
        $ret = 1;
    }
}

exit $ret;
