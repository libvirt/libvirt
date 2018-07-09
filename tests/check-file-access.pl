#!/usr/bin/env perl
#
# Copyright (C) 2016 Red Hat, Inc.
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
# This script is supposed to check test_file_access.txt file and
# warn about file accesses outside our working tree.
#
#

use strict;
use warnings;

my $access_file = "test_file_access.txt";
my $whitelist_file = "file_access_whitelist.txt";

my @known_actions = ("open", "fopen", "access", "stat", "lstat", "connect");

my @files;
my @whitelist;

open FILE, "<", $access_file or die "Unable to open $access_file: $!";
while (<FILE>) {
    chomp;
    if (/^(\S*):\s*(\S*):\s*(\S*)(\s*:\s*(.*))?$/) {
        my %rec;
        ${rec}{path} = $1;
        ${rec}{action} = $2;
        ${rec}{progname} = $3;
        if (defined $5) {
            ${rec}{testname} = $5;
        }
        push (@files, \%rec);
    } else {
        die "Malformed line $_";
    }
}
close FILE;

open FILE, "<", $whitelist_file or die "Unable to open $whitelist_file: $!";
while (<FILE>) {
    chomp;
    if (/^\s*#.*$/) {
        # comment
    } elsif (/^(\S*):\s*(\S*)(:\s*(\S*)(\s*:\s*(.*))?)?$/ and
            grep /^$2$/, @known_actions) {
        # $path: $action: $progname: $testname
        my %rec;
        ${rec}{path} = $1;
        ${rec}{action} = $3;
        if (defined $4) {
            ${rec}{progname} = $4;
        }
        if (defined $6) {
            ${rec}{testname} = $6;
        }
        push (@whitelist, \%rec);
    } elsif (/^(\S*)(:\s*(\S*)(\s*:\s*(.*))?)?$/) {
        # $path: $progname: $testname
        my %rec;
        ${rec}{path} = $1;
        if (defined $3) {
            ${rec}{progname} = $3;
        }
        if (defined $5) {
            ${rec}{testname} = $5;
        }
        push (@whitelist, \%rec);
    } else {
        die "Malformed line $_";
    }
}
close FILE;

# Now we should check if %traces is included in $whitelist. For
# now checking just keys is sufficient
my $error = 0;
for my $file (@files) {
    my $match = 0;

    for my $rule (@whitelist) {
        if (not %${file}{path} =~ m/^$rule->{path}$/) {
            next;
        }

        if (defined %${rule}{action} and
            not %${file}{action} =~ m/^$rule->{action}$/) {
            next;
        }

        if (defined %${rule}{progname} and
            not %${file}{progname} =~ m/^$rule->{progname}$/) {
            next;
        }

        if (defined %${rule}{testname} and
            defined %${file}{testname} and
            not %${file}{testname} =~ m/^$rule->{testname}$/) {
            next;
        }

        $match = 1;
    }

    if (not $match) {
        $error = 1;
        print "$file->{path}: $file->{action}: $file->{progname}";
        print ": $file->{testname}" if defined %${file}{testname};
        print "\n";
    }
}

exit $error;
