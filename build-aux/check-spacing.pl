#!/usr/bin/env perl
#
# check-spacing.pl: Report any usage of 'function (..args..)'
# Also check for other syntax issues, such as correct use of ';'
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

my $ret = 0;
my $incomment = 0;

foreach my $file (@ARGV) {
    open FILE, $file;

    while (defined (my $line = <FILE>)) {
        my $data = $line;
        # For temporary modifications
        my $tmpdata;

        # Kill any quoted , ; = or "
        $data =~ s/'[";,=]'/'X'/g;

        # Kill any quoted strings
        $data =~ s,"(?:[^\\\"]|\\.)*","XXX",g;

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
        # We also don't want to spoil the $data so it can be used
        # later on.
        $tmpdata = $data;
        while ($tmpdata =~ /(\w+)\s\((?!\*)/) {
            my $kw = $1;

            # Allow space after keywords only
            if ($kw =~ /^(?:if|for|while|switch|return)$/) {
                $tmpdata =~ s/(?:$kw\s\()/XXX(/;
            } else {
                print "Whitespace after non-keyword:\n";
                print "$file:$.: $line";
                $ret = 1;
                last;
            }
        }

        # Require whitespace immediately after keywords
        if ($data =~ /\b(?:if|for|while|switch|return)\(/) {
            print "No whitespace after keyword:\n";
            print "$file:$.: $line";
            $ret = 1;
        }

        # Forbid whitespace between )( of a function typedef
        if ($data =~ /\(\*\w+\)\s+\(/) {
            print "Whitespace between ')' and '(':\n";
            print "$file:$.: $line";
            $ret = 1;
        }

        # Forbid whitespace following ( or prior to )
        # but allow whitespace before ) on a single line
        # (optionally followed by a semicolon)
        if (($data =~ /\s\)/ && not $data =~ /^\s+\);?$/) ||
            $data =~ /\((?!$)\s/) {
            print "Whitespace after '(' or before ')':\n";
            print "$file:$.: $line";
            $ret = 1;
        }

        # Forbid whitespace before ";" or ",". Things like below are allowed:
        #
        # 1) The expression is empty for "for" loop. E.g.
        #   for (i = 0; ; i++)
        #
        # 2) An empty statement. E.g.
        #   while (write(statuswrite, &status, 1) == -1 &&
        #          errno == EINTR)
        #       ;
        #
        if ($data =~ /\s[;,]/) {
            unless ($data =~ /\S; ; / ||
                    $data =~ /^\s+;/) {
                print "Whitespace before semicolon or comma:\n";
                print "$file:$.: $line";
                $ret = 1;
            }
        }

        # Require EOL, macro line continuation, or whitespace after ";".
        # Allow "for (;;)" as an exception.
        if ($data =~ /;[^	 \\\n;)]/) {
            print "Invalid character after semicolon:\n";
            print "$file:$.: $line";
            $ret = 1;
        }

        # Require EOL, space, or enum/struct end after comma.
        if ($data =~ /,[^ \\\n)}]/) {
            print "Invalid character after comma:\n";
            print "$file:$.: $line";
            $ret = 1;
        }

        # Require spaces around assignment '=', compounds and '=='
        if ($data =~ /[^ ]\b[!<>&|\-+*\/%\^=]?=/ ||
            $data =~ /=[^= \\\n]/) {
            print "Spacing around '=' or '==':\n";
            print "$file:$.: $line";
            $ret = 1;
        }
    }
    close FILE;
}

exit $ret;
