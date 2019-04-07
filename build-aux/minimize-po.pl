#!/usr/bin/perl

my @block;
my $msgstr = 0;
my $empty = 0;
my $unused = 0;
my $fuzzy = 0;
while (<>) {
    if (/^$/) {
        if (!$empty && !$unused && !$fuzzy) {
            print @block;
        }
        @block = ();
        $msgstr = 0;
        $fuzzy = 0;
        push @block, $_;
    } else {
        if (/^msgstr/) {
            $msgstr = 1;
            $empty = 1;
        }
        if (/^#.*fuzzy/) {
            $fuzzy = 1;
        }
        if (/^#~ msgstr/) {
            $unused = 1;
        }
        if ($msgstr && /".+"/) {
            $empty = 0;
        }
        push @block, $_;
    }
}

if (@block && !$empty && !$unused) {
    print @block;
}
