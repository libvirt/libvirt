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

use strict;
use warnings;

my $drvfile = shift;
my @symfiles = @ARGV;

my %symbols;

foreach my $symfile (@symfiles) {
    open SYMFILE, "<", $symfile
        or die "cannot read $symfile: $!";
    while (<SYMFILE>) {
        if (/^\s*(vir\w+)\s*;\s*$/) {
            $symbols{$1} = 1;
        }
    }

    close SYMFILE;
}

open DRVFILE, "<", $drvfile
    or die "cannot read $drvfile: $!";

my $status = 0;

while (<DRVFILE>) {
    next if /virDrvConnectSupportsFeature/;
    if (/\*(virDrv\w+)\s*\)/) {

        my $drv = $1;

        next if $drv =~ /virDrvState/;
        next if $drv =~ /virDrvDomainMigrate(Prepare|Perform|Confirm|Begin|Finish)/;

        my $sym = $drv;
        $sym =~ s/virDrv/vir/;

        unless (exists $symbols{$sym}) {
            print "Driver method name $drv doesn't match public API name\n";
            $status = 1;
        }
    } elsif (/^\*(vir\w+)\s*\)/) {
        my $name = $1;
        print "Bogus name $1\n";
        $status = 1;
    } elsif (/^\s*(virDrv\w+)\s+(\w+);\s*/) {
        my $drv = $1;
        my $field = $2;

        my $tmp = $drv;
        $tmp =~ s/virDrv//;
        $tmp =~ s/^NWFilter/nwfilter/;
        $tmp =~ s/^(\w)/lc $1/e;

        unless ($tmp eq $field) {
            print "Driver struct field $field should be named $tmp\n";
            $status = 1;
        }
    }
}

close DRVFILE;

exit $status;
