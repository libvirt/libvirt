#!/usr/bin/env perl
#
# augeas-gentest.pl: Generate an augeas test file, from an
#                    example config file + test file template
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

die "syntax: $0 CONFIG TEMPLATE\n" unless @ARGV == 2;

my $config = shift @ARGV;
my $template = shift @ARGV;

open CONFIG, "<", $config or die "cannot read $config: $!";
open TEMPLATE, "<", $template or die "cannot read $template: $!";

my $group = 0;
while (<TEMPLATE>) {
    if (/::CONFIG::/) {
        my $group = 0;
        print "  let conf = \"";
        while (<CONFIG>) {
            if (/^#\w/) {
                s/^#//;
                s/\"/\\\"/g;
                print $_;
                $group = /\[\s$/;
            } elsif ($group) {
                s/\"/\\\"/g;
                if (/#\s*\]/) {
                    $group = 0;
                }
                if (/^#/) {
                    s/^#//;
                    print $_;
                }
            }
        }
        print "\"\n";
    } else {
        print $_;
    }
}

close TEMPLATE;
close CONFIG;
