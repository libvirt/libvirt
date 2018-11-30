#!/usr/bin/env perl
#
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
#

use strict;
use warnings;

my @objects = (
    "CONNECT", "DOMAIN", "INTERFACE", "NETWORK_PORT",
    "NETWORK","NODE_DEVICE", "NWFILTER_BINDING", "NWFILTER",
    "SECRET", "STORAGE_POOL", "STORAGE_VOL",
    );

my $objects = join ("|", @objects);

# Data we're going to be generating looks like this
#
# <policyconfig>
#   <action id="org.libvirt.unix.monitor">
#     <description>Monitor local virtualized systems</description>
#     <message>System policy prevents monitoring of local virtualized systems</message>
#     <defaults>
#       <allow_any>yes</allow_any>
#       <allow_inactive>yes</allow_inactive>
#       <allow_active>yes</allow_active>
#     </defaults>
#   </action>
#   ...more <action> rules...
# </policyconfig>

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
        my $object = lc $1;
        my $perm = lc $2;
        next if $perm eq "last";

        $object =~ s/_/-/g;
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
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD polkit Policy Configuration 1.0//EN"
    "http://www.freedesktop.org/software/polkit/policyconfig-1.dtd">
<policyconfig>
  <vendor>Libvirt Project</vendor>
  <vendor_url>https://libvirt.org</vendor_url>
EOF

foreach my $object (sort { $a cmp $b } keys %perms) {
    foreach my $perm (sort { $a cmp $b } keys %{$perms{$object}}) {
        my $description = $perms{$object}->{$perm}->{desc};
        my $message = $perms{$object}->{$perm}->{message};
        my $anonymous = $perms{$object}->{$perm}->{anonymous};

        die "missing description for $object.$perm" unless
            defined $description;
        die "missing message for $object.$perm" unless
            defined $message;

        my $allow_any = $anonymous ? "yes" : "no";
        my $allow_inactive = $allow_any;
        my $allow_active = $allow_any;

        print <<EOF;
  <action id="org.libvirt.api.$object.$perm">
    <description>$description</description>
    <message>$message</message>
    <defaults>
      <allow_any>$allow_any</allow_any>
      <allow_inactive>$allow_inactive</allow_inactive>
      <allow_active>$allow_active</allow_active>
    </defaults>
  </action>
EOF

    }
}

print <<EOF;
</policyconfig>
EOF
