#!/usr/bin/perl
#
# Copyright (C) 2011 Red Hat, Inc.
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
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
#
# Author: Daniel P. Berrange <berrange@redhat.com>
#
# Generate a set of systemtap functions for translating various
# RPC enum values into strings
#
#   perl gensystemtap.pl */*.x > libvirt_functions.stp
#

use strict;

my %funcs;

my %type;
my %status;
my %auth;

my $instatus = 0;
my $intype = 0;
my $inauth = 0;
while (<>) {
    if (/enum\s+virNetMessageType/) {
	$intype = 1;
    } elsif (/enum\s+virNetMessageStatus/) {
	$instatus = 1;
    } elsif (/enum remote_auth_type/) {
	$inauth = 1;
    } elsif (/}/) {
	$instatus = $intype = $inauth = 0;
    } elsif ($instatus) {
	if (/^\s+VIR_NET_(\w+)\s*=\s*(\d+),?$/) {
	    $status{$2} = lc $1;
	}
    } elsif ($intype) {
	if (/^\s+VIR_NET_(\w+)\s*=\s*(\d+),?$/) {
	    $type{$2} = lc $1;
	}
    } elsif ($inauth) {
	if (/^\s+REMOTE_AUTH_(\w+)\s*=\s*(\d+),?$/) {
	    $auth{$2} = lc $1;
	}
    } else {
	if (/(\w+)_PROGRAM\s*=\s*0x([a-fA-F0-9]+)\s*;/) {
	    $funcs{lc $1} = { id => hex($2), version => undef, progs => [] };
	} elsif (/(\w+)_PROTOCOL_VERSION\s*=\s*(\d+)\s*;/) {
	    $funcs{lc $1}->{version} = $2;
	} elsif (/(\w+)_PROC_(.*?)\s+=\s+(\d+)/) {
	    $funcs{lc $1}->{progs}->[$3] = lc $2;
	}
    }
}

print <<EOF;
function libvirt_rpc_auth_name(type, verbose)
{
EOF
my $first = 1;
foreach my $type (keys %auth) {
    my $cond = $first ? "if" : "} else if";
    $first = 0;
    print "  $cond (type == ", $type, ") {\n";
    print "      typestr = \"", $auth{$type}, "\"\n";
}
print <<EOF;
  } else {
      typestr = "unknown";
      verbose = 1;
  }
  if (verbose) {
      typestr = typestr . sprintf(":%d", type)
  }
  return typestr;
}
EOF

print <<EOF;
function libvirt_rpc_type_name(type, verbose)
{
EOF
$first = 1;
foreach my $type (keys %type) {
    my $cond = $first ? "if" : "} else if";
    $first = 0;
    print "  $cond (type == ", $type, ") {\n";
    print "      typestr = \"", $type{$type}, "\"\n";
}
print <<EOF;
  } else {
      typestr = "unknown";
      verbose = 1;
  }
  if (verbose) {
      typestr = typestr . sprintf(":%d", type)
  }
  return typestr;
}
EOF

print <<EOF;
function libvirt_rpc_status_name(status, verbose)
{
EOF
$first = 1;
foreach my $status (keys %status) {
    my $cond = $first ? "if" : "} else if";
    $first = 0;
    print "  $cond (status == ", $status, ") {\n";
    print "      statusstr = \"", $status{$status}, "\"\n";
}
print <<EOF;
  } else {
      statusstr = "unknown";
      verbose = 1;
  }
  if (verbose) {
      statusstr = statusstr . sprintf(":%d", status)
  }
  return statusstr;
}
EOF

print <<EOF;
function libvirt_rpc_program_name(program, verbose)
{
EOF
$first = 1;
foreach my $prog (keys %funcs) {
    my $cond = $first ? "if" : "} else if";
    $first = 0;
    print "  $cond (program == ", $funcs{$prog}->{id}, ") {\n";
    print "      programstr = \"", $prog, "\"\n";
}
print <<EOF;
  } else {
      programstr = "unknown";
      verbose = 1;
  }
  if (verbose) {
      programstr = programstr . sprintf(":%d", program)
  }
  return programstr;
}
EOF


print <<EOF;
function libvirt_rpc_procedure_name(program, version, proc, verbose)
{
EOF
$first = 1;
foreach my $prog (keys %funcs) {
    my $cond = $first ? "if" : "} else if";
    $first = 0;
    print "  $cond (program == ", $funcs{$prog}->{id}, " && version == ", $funcs{$prog}->{version}, ") {\n";

    my $pfirst = 1;
    for (my $id = 1 ; $id <= $#{$funcs{$prog}->{progs}} ; $id++) {
	my $cond = $pfirst ? "if" : "} else if";
	$pfirst = 0;
	print "      $cond (proc == $id) {\n";
	print "          procstr = \"", $funcs{$prog}->{progs}->[$id], "\";\n";
    }
    print "      } else {\n";
    print "          procstr = \"unknown\";\n";
    print "          verbose = 1;\n";
    print "      }\n";
}
print <<EOF;
  } else {
      procstr = "unknown";
      verbose = 1;
  }
  if (verbose) {
      procstr = procstr . sprintf(":%d", proc)
  }
  return procstr;
}
EOF
