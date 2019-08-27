#!/usr/bin/env perl
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

my @objects = (
    "CONNECT", "DOMAIN", "INTERFACE",
    "NETWORK_PORT", "NETWORK", "NODE_DEVICE",
    "NWFILTER_BINDING", "NWFILTER",
     "SECRET", "STORAGE_POOL", "STORAGE_VOL",
    );

my %class;

foreach my $object (@objects) {
    my $class = lc $object;

    $class =~ s/(^\w|_\w)/uc $1/eg;
    $class =~ s/_//g;
    $class =~ s/Nwfilter/NWFilter/;
    $class = "vir" . $class . "Ptr";

    $class{$object} = $class;
}

my $objects = join ("|", @objects);

my %opts;
my $in_opts = 0;

my %perms;

while (<>) {
    if ($in_opts) {
        if (m,\*/,) {
            $in_opts = 0;
        } elsif (/\*\s*\@(\w+):\s*(.*?)\s*$/) {
            $opts{$1} = $2;
        }
    } elsif (m,/\*\*,) {
        $in_opts = 1;
    } elsif (/VIR_ACCESS_PERM_($objects)_((?:\w|_)+),/) {
        my $object = $1;
        my $perm = lc $2;
        next if $perm eq "last";

        $perm =~ s/_/-/g;

        $perms{$object} = {} unless exists $perms{$object};
        $perms{$object}->{$perm} = {
            desc => $opts{desc},
            message => $opts{message},
            anonymous => $opts{anonymous}
        };
        %opts = ();
    }
}

print <<EOF;
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
  <body>
EOF

foreach my $object (sort { $a cmp $b } keys %perms) {
    my $class = $class{$object};
    my $olink = lc "object_" . $object;
    print <<EOF;
<h3><a id="$olink">$class</a></h3>
<table class="acl">
  <thead>
    <tr>
      <th>Permission</th>
      <th>Description</th>
    </tr>
  </thead>
  <tbody>
EOF

    foreach my $perm (sort { $a cmp $b } keys %{$perms{$object}}) {
        my $description = $perms{$object}->{$perm}->{desc};

        die "missing description for $object.$perm" unless
            defined $description;

        my $plink = lc "perm_" . $object . "_" . $perm;
        $plink =~ s/-/_/g;

        print <<EOF;
    <tr>
      <td><a id="$plink">$perm</a></td>
      <td>$description</td>
    </tr>
EOF

    }

    print <<EOF;
  </tbody>
</table>
EOF
}

print <<EOF;
  </body>
</html>
EOF
