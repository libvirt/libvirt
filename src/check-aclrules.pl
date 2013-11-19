#!/usr/bin/perl
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
# This script validates that the driver implementation of any
# public APIs contain ACL checks.
#
# As the script reads each source file, it attempts to identify
# top level function names.
#
# When reading the body of the functions, it looks for anything
# that looks like an API called named  XXXEnsureACL. It will
# validate that the XXX prefix matches the name of the function
# it occurs in.
#
# When it later finds the virDriverPtr table, for each entry
# point listed, it will validate if there was a previously
# detected EnsureACL call recorded.
#
use strict;
use warnings;

my $status = 0;

my $brace = 0;
my $maybefunc;
my $intable = 0;
my $table;

my %acls;
my %aclfilters;

my %whitelist = (
    "connectClose" => 1,
    "connectIsEncrypted" => 1,
    "connectIsSecure" => 1,
    "connectIsAlive" => 1,
    "networkOpen" => 1,
    "networkClose" => 1,
    "nwfilterOpen" => 1,
    "nwfilterClose" => 1,
    "secretOpen" => 1,
    "secretClose" => 1,
    "storageOpen" => 1,
    "storageClose" => 1,
    "interfaceOpen" => 1,
    "interfaceClose" => 1,
    );

# Temp hack - remove it once xen driver is fixed
my %implwhitelist = (
    "xenUnifiedDomainRestore" => 1,
    "xenUnifiedDomainRestoreFlags" => 1,
    "xenUnifiedDomainMigratePrepare" => 1,
    "xenUnifiedNodeDeviceDettach" => 1,
    "xenUnifiedNodeDeviceDetachFlags" => 1,
    "xenUnifiedNodeDeviceReset" => 1,
    "xenUnifiedDomainIsActive" => 1,
    "xenUnifiedDomainIsPersistent" => 1,
    "xenUnifiedDomainIsUpdated" => 1,
    "xenUnifiedDomainOpenConsole" => 1,
    );
my %filterimplwhitelist = (
    "xenUnifiedConnectListDomains" => 1,
    "xenUnifiedConnectNumOfDomains" => 1,
    "xenUnifiedConnectListDefinedDomains" => 1,
    "xenUnifiedConnectNumOfDefinedDomains" => 1,
    );

my $lastfile;

sub fixup_name {
    my $name = shift;

    $name =~ s/Nwfilter/NWFilter/;
    $name =~ s/Xml$/XML/;
    $name =~ s/Uri$/URI/;
    $name =~ s/Uuid$/UUID/;
    $name =~ s/Id$/ID/;
    $name =~ s/Mac$/MAC/;
    $name =~ s/Cpu$/CPU/;
    $name =~ s/Os$/OS/;
    $name =~ s/Nmi$/NMI/;
    $name =~ s/Pm/PM/;
    $name =~ s/Fstrim$/FSTrim/;
    $name =~ s/Scsi/SCSI/;
    $name =~ s/Wwn$/WWN/;

    return $name;
}

sub name_to_ProcName {
    my $name = shift;

    my @elems;
    if ($name =~ /_/ || (lc $name) eq "open" || (lc $name) eq "close") {
        @elems = split /_/, $name;
        @elems = map lc, @elems;
        @elems = map ucfirst, @elems;
    } else {
        @elems = $name;
    }
    @elems = map { fixup_name($_) } @elems;
    my $procname = join "", @elems;

    $procname =~ s/^([A-Z])/lc $1/e;

    return $procname;
}


my $proto = shift @ARGV;

open PROTO, "<$proto" or die "cannot read $proto";

my %filtered;
my $incomment = 0;
my $filtered = 0;
while (<PROTO>) {
    if (m,/\*\*,) {
        $incomment = 1;
        $filtered = 0;
    } elsif ($incomment) {
        if (m,\*\s\@aclfilter,) {
            $filtered = 1;
        } elsif ($filtered &&
                 m,REMOTE_PROC_(.*)\s+=\s*\d+,) {
            my $api = name_to_ProcName($1);
            $filtered{$api} = 1;
            $incomment = 0;
        }
    }
}

close PROTO;

while (<>) {
    if (!defined $lastfile ||
        $lastfile ne $ARGV) {
        %acls = ();
        $brace = 0;
        $maybefunc = undef;
        $lastfile = $ARGV;
    }
    if ($brace == 0) {
        # Looks for anything which appears to be a function
        # body name. Doesn't matter if we pick up bogus stuff
        # here, as long as we don't miss valid stuff
        if (m,\b(\w+)\(,) {
            $maybefunc = $1;
        }
    } elsif ($brace > 0) {
        if (m,(\w+)EnsureACL,) {
            # Record the fact that maybefunc contains an
            # ACL call, and make sure it is the right call!
            my $func = $1;
            $func =~ s/^vir//;
            if (!defined $maybefunc) {
                print "$ARGV:$. Unexpected check '$func' outside function\n";
                $status = 1;
            } else {
                unless ($maybefunc =~ /$func$/i) {
                    print "$ARGV:$. Mismatch check 'vir${func}EnsureACL' for function '$maybefunc'\n";
                    $status = 1;
                }
            }
            $acls{$maybefunc} = 1;
        } elsif (m,(\w+)CheckACL,) {
            # Record the fact that maybefunc contains an
            # ACL filter call, and make sure it is the right call!
            my $func = $1;
            $func =~ s/^vir//;
            if (!defined $maybefunc) {
                print "$ARGV:$. Unexpected check '$func' outside function\n";
                $status = 1;
            } else {
                unless ($maybefunc =~ /$func$/i) {
                    print "$ARGV:$. Mismatch check 'vir${func}CheckACL' for function '$maybefunc'\n";
                    $status = 1;
                }
            }
            $aclfilters{$maybefunc} = 1;
        } elsif (m,\b(\w+)\(,) {
            # Handles case where we replaced an API with a new
            # one which  adds new parameters, and we're left with
            # a simple stub calling the new API.
            my $callfunc = $1;
            if (exists $acls{$callfunc}) {
                $acls{$maybefunc} = 1;
            }
            if (exists $aclfilters{$callfunc}) {
                $aclfilters{$maybefunc} = 1;
            }
        }
    }

    # Pass the vir*DriverPtr tables and make sure that
    # every func listed there, has an impl which calls
    # an ACL function
    if ($intable) {
        if (/\}/) {
            $intable = 0;
            $table = undef;
        } elsif (/\.(\w+)\s*=\s*(\w+),?/) {
            my $api = $1;
            my $impl = $2;

            if ($api ne "no" &&
                $api ne "name" &&
                $table ne "virStateDriver" &&
                !exists $acls{$impl} &&
                !exists $whitelist{$api} &&
                !exists $implwhitelist{$impl}) {
                print "$ARGV:$. Missing ACL check in function '$impl' for '$api'\n";
                $status = 1;
            }

            if (exists $filtered{$api} &&
                !exists $aclfilters{$impl} &&
                !exists $filterimplwhitelist{$impl}) {
                print "$ARGV:$. Missing ACL filter in function '$impl' for '$api'\n";
                $status = 1;
            }
        }
    } elsif (/^(?:static\s+)?(vir(?:\w+)?Driver)\s+/) {
        if ($1 ne "virNWFilterCallbackDriver" &&
            $1 ne "virNWFilterTechDriver" &&
            $1 ne "virDomainConfNWFilterDriver") {
            $intable = 1;
            $table = $1;
        }
    }


    my $count;
    $count = s/{//g;
    $brace += $count;
    $count = s/}//g;
    $brace -= $count;
}

exit $status;
