#!/usr/bin/perl

die "syntax: $0 SYMFILE ELFLIB(S)" unless int(@ARGV) >= 2;

my $symfile = shift @ARGV;
my @elflibs = @ARGV;

my %wantsyms;
my %gotsyms;

my $ret = 0;

open SYMFILE, $symfile or die "cannot read $symfile: $!";

while (<SYMFILE>) {
    next if /{/;
    next if /}/;
    next if /global:/;
    next if /local:/;
    next if /^\s*$/;
    next if /^\s*#/;
    next if /\*/;

    die "malformed line $_" unless /^\s*(\S+);$/;

    if (exists $wantsyms{$1}) {
        print STDERR "Symbol $1 is listed twice\n";
        $ret = 1;
    } else {
        $wantsyms{$1} = 1;
    }
}
close SYMFILE;

foreach my $elflib (@elflibs) {
    open NM, "-|", "nm", $elflib or die "cannot run 'nm $elflib': $!";

    while (<NM>) {
        next unless /^\S+\s(?:[TBD])\s(\S+)\s*$/;

        $gotsyms{$1} = 1;
    }

    close NM;
}

foreach my $sym (@wantsyms) {
    next if exists $gotsyms{$sym};

    print STDERR "Expected symbol $sym is not in ELF library\n";
    $ret = 1;
}

exit($ret);
