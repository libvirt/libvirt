#!/usr/bin/perl

use strict;
use warnings;

use BZ::Client;
use BZ::Client::Bug;

use Config::Record;

my $cfg = Config::Record->new(file => "todo.cfg");
my $server = $cfg->get("bugzilla/server", "https://bugzilla.redhat.com");
my $username = $cfg->get("bugzilla/username");
my $password = $cfg->get("bugzilla/password");

my $product = $cfg->get("query/product", "Virtualization Tools");
my $todoalias = $cfg->get("query/todoalias", "libvirtTodo");

my $title = $cfg->get("output/title", undef);
my $blurb = $cfg->get("output/blurb", undef);

$SIG{__DIE__} = sub {
    my $err = shift;
    if (UNIVERSAL::isa($err, "BZ::Client::Exception")) {
	die "Unable to access bugzilla: " . $err->message;
    }
    die $err;
};

my $client = BZ::Client->new(url => $server,
			     user => $username,
			     password => $password);

my $todo = BZ::Client::Bug->search($client, {'product' => $product,
					     'alias' => $todoalias});

die "Cannot find bug alias 'libvirtTodo'" unless $#{$todo} > -1;
my $todoid = $todo->[0]->{'bug_id'};
my $todosummary = $todo->[0]->{'short_desc'};
$todosummary =~ s/^\s*RFE\s*:\s*//;
$todosummary =~ s/^\s*\[\s*RFE\s*\]\s*:?\s*//;
$todosummary =~ s/^\s*Tracker\s*:\s*//;

my $trackers = BZ::Client::Bug->search($client, {'product' => $product,
						 'blocked' => $todoid });

my @trackers;

foreach my $tracker (@{$trackers}) {
    next if $tracker->{'bug_status'} eq "CLOSED";

    my $summary = $tracker->{'short_desc'};
    $summary =~ s/^\s*RFE\s*:\s*//;
    $summary =~ s/^\s*\[\s*RFE\s*\]\s*:?\s*//;
    $summary =~ s/^\s*Tracker\s*:\s*//;

    push @trackers, {
	id => $tracker->{'bug_id'},
	summary => $summary,
	features => [],
    };
}

foreach my $tracker (@trackers) {
    my $features = BZ::Client::Bug->search($client, {'product' => $product,
						     'blocked' => $tracker->{id}});

    foreach my $feature (@{$features}) {
	next if $feature->{'bug_status'} eq "CLOSED";

	my $summary = $feature->{'short_desc'};
	$summary =~ s/^\s*RFE\s*:\s*//;
	$summary =~ s/^\s*\[\s*RFE\s*\]\s*:?\s*//;

	push @{$tracker->{features}}, {
	    id => $feature->{'bug_id'},
	    summary => $summary,
	};
    }
}

sub escape {
    my $txt = shift;
    $txt =~ s/&/&amp;/g;
    $txt =~ s/</&lt;/g;
    $txt =~ s/>/&gt;/g;
    return $txt;
};

print "<?xml version=\"1.0\"?>\n";
print "<html>\n";
print "  <body>\n";
if (defined $title) {
    print "    <h1>", &escape($title), "</h1>\n";
} else {
    print "    <h1>", &escape($todosummary), "</h1>\n";
}
if (defined $blurb) {
    print "    <p>\n";
    print $blurb;
    print "    </p>\n";
}
foreach my $tracker (sort { $a->{summary} cmp $b->{summary} } @trackers) {
    next unless $#{$tracker->{features}} >= 0;

    my $summary = &escape($tracker->{summary});
    my $id = $tracker->{id};
    print "    <h2><a href=\"$server/$id\">$summary</a></h2>\n";
    print "    <ul>\n";
    foreach my $feature (sort { $a->{summary} cmp $b->{summary} } @{$tracker->{features}}) {
	$summary = &escape($feature->{summary});
	$summary =~ s,^([^:]+):,<strong>$1</strong>,;

	$id = $feature->{id};
	print "      <li>$summary (<strong>rhbz <a href=\"$server/$id\">$id</a></strong>)</li>\n";
    }
    print "    </ul>\n";
}

print "    <p>\n";
print "    This page is automatically generated from <a href=\"$server/$todoid\">", &escape($todosummary), "</a>\n";
print "    </p>\n";
print "  </body>\n";
print "</html>\n";
