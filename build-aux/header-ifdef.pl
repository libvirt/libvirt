#!/usr/bin/perl
#
# Validate that header files follow a standard layout:
#
# /*
#  ...copyright header...
#  */
# <one blank line>
# #ifndef SYMBOL
# # define SYMBOL
# ....content....
# #endif /* SYMBOL */
#
# For any file ending priv.h, before the #ifndef
# We will have a further section
#
# #ifndef SYMBOL_ALLOW
# # error ....
# #endif /* SYMBOL_ALLOW */
# <one blank line>

use strict;
use warnings;

my $STATE_COPYRIGHT_COMMENT = 0;
my $STATE_COPYRIGHT_BLANK = 1;
my $STATE_PRIV_START = 2;
my $STATE_PRIV_ERROR = 3;
my $STATE_PRIV_END = 4;
my $STATE_PRIV_BLANK = 5;
my $STATE_GUARD_START = 6;
my $STATE_GUARD_DEFINE = 7;
my $STATE_GUARD_END = 8;
my $STATE_EOF = 9;
my $STATE_PRAGMA = 10;

my $file = " ";
my $ret = 0;
my $ifdef = "";
my $ifdefpriv = "";

my $state = $STATE_EOF;
my $mistake = 0;

sub mistake {
    my $msg = shift;
    warn $msg;
    $mistake = 1;
    $ret = 1;
}

while (<>) {
    if (not $file eq $ARGV) {
        if ($state == $STATE_COPYRIGHT_COMMENT) {
            &mistake("$file: missing copyright comment");
        } elsif ($state == $STATE_COPYRIGHT_BLANK) {
            &mistake("$file: missing blank line after copyright header");
        } elsif ($state == $STATE_PRIV_START) {
            &mistake("$file: missing '#ifndef $ifdefpriv'");
        } elsif ($state == $STATE_PRIV_ERROR) {
            &mistake("$file: missing '# error ...priv allow...'");
        } elsif ($state == $STATE_PRIV_END) {
            &mistake("$file: missing '#endif /* $ifdefpriv */'");
        } elsif ($state == $STATE_PRIV_BLANK) {
            &mistake("$file: missing blank line after priv header check");
        } elsif ($state == $STATE_GUARD_START) {
            &mistake("$file: missing '#ifndef $ifdef'");
        } elsif ($state == $STATE_GUARD_DEFINE) {
            &mistake("$file: missing '# define $ifdef'");
        } elsif ($state == $STATE_GUARD_END) {
            &mistake("$file: missing '#endif /* $ifdef */'");
        }

        $ifdef = uc $ARGV;
        $ifdef =~ s,.*/,,;
        $ifdef =~ s,[^A-Z0-9],_,g;
        $ifdef =~ s,__+,_,g;
        unless ($ifdef =~ /^LIBVIRT_/ && $ARGV !~ /libvirt_internal.h/) {
            $ifdef = "LIBVIRT_" . $ifdef;
        }
        $ifdefpriv = $ifdef . "_ALLOW";

        $file = $ARGV;
        $state = $STATE_COPYRIGHT_COMMENT;
        $mistake = 0;
    }

    if ($mistake ||
        $ARGV =~ /config-post\.h$/ ||
        $ARGV =~ /vbox_(CAPI|XPCOM)/) {
        $state = $STATE_EOF;
        next;
    }

    if ($state == $STATE_COPYRIGHT_COMMENT) {
        if (m,\*/,) {
            $state = $STATE_COPYRIGHT_BLANK;
        }
    } elsif ($state == $STATE_COPYRIGHT_BLANK) {
        if (! /^$/) {
            &mistake("$file: missing blank line after copyright header");
        }
        if ($ARGV =~ /priv\.h$/) {
            $state = $STATE_PRIV_START;
        } else {
            $state = $STATE_GUARD_START;
        }
    } elsif ($state == $STATE_PRIV_START) {
        if (/^$/) {
            &mistake("$file: too many blank lines after copyright header");
        } elsif (/#ifndef $ifdefpriv$/) {
            $state = $STATE_PRIV_ERROR;
        } else {
            &mistake("$file: missing '#ifndef $ifdefpriv'");
        }
    } elsif ($state == $STATE_PRIV_ERROR) {
        if (/# error ".*"$/) {
            $state = $STATE_PRIV_END;
        } else {
            &mistake("$file: missing '# error ...priv allow...'");
        }
    } elsif ($state == $STATE_PRIV_END) {
        if (m,#endif /\* $ifdefpriv \*/,) {
            $state = $STATE_PRIV_BLANK;
        } else {
            &mistake("$file: missing '#endif /* $ifdefpriv */'");
        }
    } elsif ($state == $STATE_PRIV_BLANK) {
        if (! /^$/) {
            &mistake("$file: missing blank line after priv guard");
        }
        $state = $STATE_GUARD_START;
    } elsif ($state == $STATE_GUARD_START) {
        if (/^$/) {
            &mistake("$file: too many blank lines after copyright header");
        } elsif(/#pragma once/) {
            $state = $STATE_PRAGMA;
        } elsif (/#ifndef $ifdef$/) {
            $state = $STATE_GUARD_DEFINE;
        } else {
            &mistake("$file: missing '#ifndef $ifdef'");
        }
    } elsif ($state == $STATE_GUARD_DEFINE) {
        if (/# define $ifdef$/) {
            $state = $STATE_GUARD_END;
        } else {
            &mistake("$file: missing '# define $ifdef'");
        }
    } elsif ($state == $STATE_GUARD_END) {
        if (m,#endif /\* $ifdef \*/$,) {
            $state = $STATE_EOF;
        }
    } elsif ($state == $STATE_PRAGMA) {
        next;
    } elsif ($state == $STATE_EOF) {
        die "$file: unexpected content after '#endif /* $ifdef */'";
    } else {
        die "$file: unexpected state $state";
    }
}
exit $ret;
