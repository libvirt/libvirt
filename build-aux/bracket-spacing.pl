#!/usr/bin/perl
#
# bracket-spacing.pl: Report any usage of 'function (..args..)'
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
# Authors:
#     Daniel P. Berrange <berrange@redhat.com>

use strict;
use warnings;

my $ret = 0;
my $incomment = 0;

foreach my $file (@ARGV) {
    open FILE, $file;

    while (defined (my $line = <FILE>)) {
        my $data = $line;

        # Kill any quoted strongs
        $data =~ s,".*?","XXX",g;

        # Kill any C++ style comments
        $data =~ s,//.*$,//,;

        next if $data =~ /^#/;

        # Kill contents of multi-line comments
        # and detect end of multi-line comments
        if ($incomment) {
            if ($data =~ m,\*/,) {
                $incomment = 0;
                $data =~ s,^.*\*/,*/,;
            } else {
                $data = "";
            }
        }

        # Kill single line comments, and detect
        # start of multi-line comments
        if ($data =~ m,/\*.*\*/,) {
            $data =~ s,/\*.*\*/,/* */,;
        } elsif ($data =~ m,/\*,) {
            $incomment = 1;
            $data =~ s,/\*.*,/*,;
        }

        # We need to match things like
        #
        #  int foo (int bar, bool wizz);
        #  foo (bar, wizz);
        #
        # but not match things like:
        #
        #  typedef int (*foo)(bar wizz)
        #
        # we can't do this (efficiently) without
        # missing things like
        #
        #  foo (*bar, wizz);
        #
        while ($data =~ /(\w+)\s\((?!\*)/) {
            my $kw = $1;

            # Allow space after keywords only
            if ($kw =~ /^(if|for|while|switch|return)$/) {
                $data =~ s/($kw\s\()/XXX(/;
            } else {
                print "$file:$.: $line";
                $ret = 1;
                last;
            }
        }

        # Require whitespace immediately after keywords,
        # but none after the opening bracket
        while ($data =~ /(if|for|while|switch|return)\(/ ||
               $data =~ /(if|for|while|switch|return)\s+\(\s/) {
            print "$file:$.: $line";
            $ret = 1;
            last;
        }

        # Forbid whitespace between )( of a function typedef
        while ($data =~ /\(\*\w+\)\s+\(/) {
            print "$file:$.: $line";
            $ret = 1;
            last;
        }

        # Forbid whitespace following ( or prior to )
        while ($data =~ /\S\s+\)/ ||
               $data =~ /\(\s+\S/) {
            print "$file:$.: $line";
            $ret = 1;
            last;
        }
    }
    close FILE;
}

exit $ret;
