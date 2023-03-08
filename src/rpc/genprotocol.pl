#!/usr/bin/env perl
#
# Generate code for an XDR protocol, applying
# fixups to the glibc rpcgen code so that it compiles
# with warnings turned on.
#
# This code is evil.  Arguably better would be just to compile
# without -Werror.  Update: The IXDR_PUT_LONG replacements are
# actually fixes for 64 bit, so this file is necessary.  Arguably
# so is the type-punning fix.
#
# Copyright (C) 2007, 2011-2013 Red Hat, Inc.
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
# Richard Jones <rjones@redhat.com>

use strict;

my $in_function = 0;
my @function = ();

my $rpcgen = shift;
my $mode = shift;
my $xdrdef = shift;
my $target = shift;

unlink $target;

if ($rpcgen =~ /portable-rpcgen/) {
    $rpcgen = "$rpcgen -o -";
}
open RPCGEN, "-|", "$rpcgen $mode $xdrdef"
    or die "cannot run $rpcgen $mode $xdrdef: $!";
open TARGET, ">$target"
    or die "cannot create $target: $!";

if ($mode eq "-c") {
    print TARGET "#include <config.h>\n";
}

while (<RPCGEN>) {
    if (m/^{/) {
        $in_function = 1;
        print TARGET;
        next;
    }

    s/\t/        /g;

    # Fix VPATH builds
    s,#include ".*/([^/]+)protocol\.h",#include "${1}protocol.h",;

    # Portability for Solaris RPC
    s/u_quad_t/uint64_t/g;
    s/quad_t/int64_t/g;
    s/xdr_u_quad_t/xdr_uint64_t/g;
    s/xdr_quad_t/xdr_int64_t/g;
    s/(?<!IXDR_GET_INT32 )IXDR_GET_LONG/IXDR_GET_INT32/g;

    if (m/^}/) {
        $in_function = 0;

        # Note: The body of the function is in @function.

        # Remove decl of buf, if buf isn't used in the function.
        my @uses = grep /[^.>]\bbuf\b/, @function;
        @function = grep !/[^.>]\bbuf\b/, @function if @uses == 1;

        # Remove decl of i, if i isn't used in the function.
        @uses = grep /[^.>]\bi\b/, @function;
        @function = grep !/[^.>]\bi\b/, @function if @uses == 1;

        # (char **)&objp->... gives:
        # warning: dereferencing type-punned pointer will break
        #   strict-aliasing rules
        # so rewrite it.
        my %uses = ();
        my $i = 0;
        foreach (@function) {
            $uses{$1} = $i++ if m/\(char \*\*\)\&(objp->[a-z_.]+_val)/i;
        }
        if (keys %uses >= 1) {
            my $i = 1;

            foreach (sort(keys %uses)) {
                $i = $uses{$_};
                unshift @function,
                ("        char **objp_cpp$i = (char **) (void *) &$_;\n");
                $i++;
            }
            @function =
                map { s{\(char \*\*\)\&(objp->[a-z_.]+_val)}
                       {objp_cpp$uses{$1}}gi; $_ } @function;
        }

        # The code uses 'IXDR_PUT_{U_,}LONG' but it's wrong in two
        # ways: Firstly these functions are deprecated and don't
        # work on 64 bit platforms.  Secondly the return value should
        # be ignored.  Correct both these mistakes.
        @function =
            map { s/\bIXDR_PUT_((U_)?)LONG\b/(void)IXDR_PUT_$1INT32/; $_ }
            map { s/\bXDR_INLINE\b/(int32_t*)XDR_INLINE/; $_ }
            @function;

        print TARGET (join ("", @function));
        @function = ();
    }

    unless ($in_function) {
        print TARGET;
    } else {
        push @function, $_;
    }
}

close TARGET
    or die "cannot save $target: $!";
close RPCGEN
    or die "cannot shutdown $rpcgen: $!";

chmod 0444, $target
    or die "cannot set $target readonly: $!";
