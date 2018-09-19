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
#
# Authors:
#     Daniel P. Berrange <berrange@redhat.com>

use strict;
use warnings;

#
# CheckFunctionBody:
# $_[0]: $data(in)
# $_[1]: $location(in), which format is file-path:line-num:line-code
# $_[2]: $fn_linenum(inout), maintains start line-num of function body
# Returns 0 in case of success or 1 on failure
#
# Check incorrect indentation and blank first line in function body.
# For efficiency, it only checks the first line of function body.
# But it's enough for most cases.
# (It could be better that we use *state* to declare @fn_linenum and
#  move it into this subroutine. But *state* requires version >= v5.10.)
#
sub CheckFunctionBody {
    my $ret = 0;
    my ($data, $location, $fn_linenum) = @_;

    # Check first line of function block
    if ($$fn_linenum) {
        if ($$data =~ /^\s*$/) {
            print "Blank line before content in function body:\n$$location";
            $ret = 1;
        } elsif ($$data !~ /^[ ]{4}\S/) {
            unless ($$data =~ /^[ ]\w+:$/ || $$data =~ /^}/) {
                print "Incorrect indentation in function body:\n$$location";
                $ret = 1;
            }
        }
        $$fn_linenum = 0;
    }

    # Detect start of function block
    if ($$data =~ /^{$/) {
        $$fn_linenum = $.;
    }

    return $ret;
}

#
# KillComments:
# $_[0]: $data(inout)
# $_[1]: $incomment(inout)
#
# Remove all content of comments
# (Also, the @incomment could be declared with *state* and move it in.)
#
sub KillComments {
    my ($data, $incomment) = @_;

    # Kill contents of multi-line comments
    # and detect end of multi-line comments
    if ($$incomment) {
        if ($$data =~ m,\*/,) {
            $$incomment = 0;
            $$data =~ s,^.*\*/,*/,;
        } else {
            $$data = "";
        }
    }

    # Kill single line comments, and detect
    # start of multi-line comments
    if ($$data =~ m,/\*.*\*/,) {
        $$data =~ s,/\*.*\*/,/* */,;
    } elsif ($$data =~ m,/\*,) {
        $$incomment = 1;
        $$data =~ s,/\*.*,/*,;
    }

    return;
}

#
# CheckWhiteSpaces:
# $_[0]: $data(in)
# $_[1]: $location(in), which format is file-path:line-num:line-code
#
# Check whitespaces according to code spec of libvirt.
#
sub CheckWhiteSpaces {
    my $ret = 0;
    my ($data, $location) = @_;

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

    # For temporary modifications
    my $tmpdata = $$data;
    while ($tmpdata =~ /(\w+)\s\((?!\*)/) {
        my $kw = $1;

        # Allow space after keywords only
        if ($kw =~ /^(?:if|for|while|switch|return)$/) {
            $tmpdata =~ s/(?:$kw\s\()/XXX(/;
        } else {
            print "Whitespace after non-keyword:\n$$location";
            $ret = 1;
            last;
        }
    }

    # Require whitespace immediately after keywords
    if ($$data =~ /\b(?:if|for|while|switch|return)\(/) {
        print "No whitespace after keyword:\n$$location";
        $ret = 1;
    }

    # Forbid whitespace between )( of a function typedef
    if ($$data =~ /\(\*\w+\)\s+\(/) {
        print "Whitespace between ')' and '(':\n$$location";
        $ret = 1;
    }

    # Forbid whitespace following ( or prior to )
    # but allow whitespace before ) on a single line
    # (optionally followed by a semicolon)
    if (($$data =~ /\s\)/ && not $$data =~ /^\s+\);?$/) ||
        $$data =~ /\((?!$)\s/) {
        print "Whitespace after '(' or before ')':\n$$location";
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
    if ($$data =~ /\s[;,]/) {
        unless ($$data =~ /\S; ; / ||
                $$data =~ /^\s+;/) {
            print "Whitespace before semicolon or comma:\n$$location";
            $ret = 1;
        }
    }

    # Require EOL, macro line continuation, or whitespace after ";".
    # Allow "for (;;)" as an exception.
    if ($$data =~ /;[^	 \\\n;)]/) {
        print "Invalid character after semicolon:\n$$location";
        $ret = 1;
    }

    # Require EOL, space, or enum/struct end after comma.
    if ($$data =~ /,[^ \\\n)}]/) {
        print "Invalid character after comma:\n$$location";
        $ret = 1;
    }

    # Require spaces around assignment '=', compounds and '=='
    if ($$data =~ /[^ ]\b[!<>&|\-+*\/%\^=]?=/ ||
        $$data =~ /=[^= \\\n]/) {
        print "Spacing around '=' or '==':\n$$location";
        $ret = 1;
    }

    return $ret;
}

#
# CheckCurlyBrackets:
# $_[0]: $data(in)
# $_[1]: $file(in)
# $_[2]: $line(in)
# $_[3]: $cb_linenum(inout)
# $_[4]: $cb_code(inout)
# $_[5]: $cb_scolon(inout)
#
# Check whitespaces according to code spec of libvirt.
#
sub CheckCurlyBrackets {
    my $ret = 0;
    my ($data, $file, $line, $cb_linenum, $cb_code, $cb_scolon) = @_;

    # One line conditional statements with one line bodies should
    # not use curly brackets.
    if ($$data =~ /^\s*(if|while|for)\b.*\{$/) {
        $$cb_linenum = $.;
        $$cb_code = $$line;
        $$cb_scolon = 0;
    }

    # We need to check for exactly one semicolon inside the body,
    # because empty statements (e.g. with comment only) are
    # allowed
    if ($$cb_linenum == $. - 1 && $$data =~ /^[^;]*;[^;]*$/) {
        $$cb_code .= $$line;
        $$cb_scolon = 1;
    }

    if ($$data =~ /^\s*}\s*$/ &&
        $$cb_linenum == $. - 2 &&
        $$cb_scolon) {

        print "Curly brackets around single-line body:\n";
        print "$$file:$$cb_linenum-$.:\n$$cb_code$$line";
        $ret = 1;

        # There _should_ be no need to reset the values; but to
        # keep my inner peace...
        $$cb_linenum = 0;
        $$cb_scolon = 0;
        $$cb_code = "";
    }

    return $ret;
}

my $ret = 0;

foreach my $file (@ARGV) {
    # Per-file variables for multiline Curly Bracket (cb_) check
    my $cb_linenum = 0;
    my $cb_code = "";
    my $cb_scolon = 0;
    my $fn_linenum = 0;
    my $incomment = 0;

    open FILE, $file;

    while (defined (my $line = <FILE>)) {
        my $data = $line;
        my $location = "$file:$.:\n$line";

        # Kill any quoted , ; = or "
        $data =~ s/'[";,=]'/'X'/g;

        # Kill any quoted strings
        $data =~ s,"(?:[^\\\"]|\\.)*","XXX",g;

        # Kill any C++ style comments
        $data =~ s,//.*$,//,;

        next if $data =~ /^#/;

        $ret = 1 if CheckFunctionBody(\$data, \$location, \$fn_linenum);

        KillComments(\$data, \$incomment);

        $ret = 1 if CheckWhiteSpaces(\$data, \$location);

        $ret = 1 if CheckCurlyBrackets(\$data, \$file, \$line,
                                       \$cb_linenum, \$cb_code, \$cb_scolon);
    }
    close FILE;
}

exit $ret;
