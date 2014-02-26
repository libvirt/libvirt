#!/usr/bin/env perl
# genxdrstub.pl --- Generate C header file which used by packet-libvirt.[ch]
#
# Copyright (C) 2013 Yuto KAWAMURA(kawamuray) <kawamuray.dadada@gmail.com>
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
# Author: Yuto KAWAMURA(kawamuray)
#
# For XDR syntax, see http://tools.ietf.org/html/rfc4506#section-6.3
# This script does not strictly check syntax of xdr protocol specification.
# Make sure the specification files you have are correctly compilable with rpcgen(1).
# If something fails with this script in spite of you had confirmed that the `make' with libvirt was succeed,
# please report your error output to kawamuray<kawamuray.dadada@gmail.com>.
use strict;
use warnings;
use File::Spec;

my $DEBUG = 0; # Enable if you want to see debug output
sub dbg { print STDERR @_ if $DEBUG }

die "ERROR: No arguments" unless @ARGV;

# Context object referenced from entire this script
my $c = Context->new;

for my $proto (@ARGV) {
    # We need to do this heuristic parsing to determine
    # variable name of enum <protocol>_procedures.
    my ($name) = $proto =~ m{(?:vir)?([^/]+?)_?protocol\.x$};
    unless ($name) {
        warn "WARNING: Cannot extract protocol name from $proto, skipping.";
        next;
    }
    $c->add_to_set(progs => $name);

    my $source;
    {
        open my $fh, '<', $proto
            or die "Cannot open $proto: $!";
        local $/;
        $source = <$fh>;
        close $fh;
    }

    $c->add_header_file($name, sub {
        dbg "*** Start parsing $proto\n";
        my @lexs = Lexicalizer->parse($source);
        for my $lex (@lexs) {
            next if $lex->ident eq "enum $name\_procedure";

            if ($lex->isa('Sym::Variable')) {
                $c->print(sprintf "#define %s (%s)\n", $lex->ident, $lex->value);
            } elsif ($lex->isa('Sym::Type')) {
                # Top level of name path is type identification of itself
                $lex->define_dissector($lex->idstrip);
            } else {
                die "Unknown lexical appeared: $lex";
            }
        }

        my $procs = $c->symbol("enum $name\_procedure")
            or die "Cannot find procedures enumeration: enum $name\_procedure";
        # Procedure numbers are expected to be containing gaps, but needed to be sorted in ascending order.
        my @procedures = sort { $a->value <=> $b->value } @{ $procs->members };
        my @dissectors = map {
            (my $ident = lc($_->ident)) =~ s/^$name\_proc/$name/;
            +{
                value => $_->value,
                map { $_ => $c->rinc($c->symbols->{"$ident\_$_"} ? "dissect_xdr_$ident\_$_" : 'NULL') }
                    qw{ args ret msg }
            };
        } @procedures;
        $c->print(PT->render('code.dissectorlist', {
            name       => $name,
            dissectors => \@dissectors,
        }));
        $c->print(PT->render('code.procedure_strings', {
            name       => $name,
            procedures => \@procedures,
        }));
    });
}

$c->add_header_file('protocol', sub {
    for my $prog (@{ $c->get_set('progs') }) {
        $c->print("#include \"libvirt/$prog.h\"\n");
    }

    # hf_ variables set
    $c->print(PT->render('macro.hfvars', {
        programs => $c->get_set('progs'),
        hfvars   => [ grep $_->{segment}{refcnt}, @{ $c->get_set('hfvars') } ],
    }));
    # ett_ variables set
    $c->print(PT->render('macro.ettvars', {
        ettvars => [ map $_->{sym}, grep $_->{refcnt}, @{ $c->get_set('ettvars') } ],
    }));
    # value_string program_strings
    $c->print(PT->render('code.program_strings', { programs => $c->get_set('progs') }));
    $c->print("static int hf_$_\_procedure = -1;\n") for @{ $c->get_set('progs') };
    $c->print(PT->render('code.program_data', { programs => $c->get_set('progs') }));
});

$c->finalize; exit 0;

# Used for handy class building
sub register_profile {
    my %prof = @_;
    my $caller = caller;
    no strict 'refs';
    if ($prof{isa}) {
        push @{ "$caller\::ISA" }, $prof{isa};
    }
    while (my ($name, $v) = each %{ $prof{consts} || {} }) {
        *{ "$caller\::$name" } = sub { $v };
    }
    for my $attr (@{ $prof{attrs} || [] }) {
        *{ "$caller\::$attr" } = sub {
            if (@_ > 1) { $_[0]->{$attr} = $_[1]; $_[0] }
            else        { $_[0]->{$attr} }
        };
    }
    while (my ($klass, $meths) = each %{ $prof{roles} || {} }) {
        for my $meth (@$meths) {
            # This assignment cannot be like: *{ "$caller\::$meth" } = \&{ "$klass\::$meth" }.
            # "$klass\::$meth" maybe not defined yet(e.g. Methods defined by PT)
            *{ "$caller\::$meth" } = sub { goto &{ "$klass\::$meth" } };
        }
    }
}

# Minimal template engine for code generating
package PT; # is PicoTemplate
our $Token;
our %Templates;
INIT { # Load templates from __END__ section
    $Token = join '', map { chr(65 + rand(26)) } 1..64;
    my $current;
    while (my $l = <main::DATA>) {
        if ($l =~ /^\@\@\s*(.+)/) {
            $current = \($Templates{$1} = '');
        } else {
            $$current .= $l if $current;
        }
    }
    for my $name (keys %Templates) {
        $Templates{$name} = __PACKAGE__->compile($Templates{$name});
        if ($name =~ /^([\w:]+)#([^#]+)$/) {
            no strict 'refs';
            my $meth = "$1\::$2";
            unless (defined &$meth) {
                *$meth = $Templates{$name};
            }
        }
    }
}
sub compile {
    my ($class, $tmpl) = @_;

    $tmpl =~ s{<%(=)?(.*?)%>\n?|((?:(?!<%).)+)}{
        $2 ? $1 ? "\$$Token .= qq{\@{[do{ $2 }]}};" : $2
           : "\$$Token .= substr <<$Token, 0, -1;\n".quotemeta($3)."\n$Token\n";
    }gse;
    eval "sub { my \$$Token = ''; $tmpl \$$Token }"
        or die "ERROR: Cannot compile template: $@";
}
sub render {
    my ($class, $name, $vars, @args) = @_;
    local $_ = $vars || {};
    my $renderer = $Templates{$name}
        or die "No such template: $name";
    $renderer->(@args);
}
# / package PT

package Sym;
BEGIN{::register_profile(
    attrs => [qw[ ident ]],
)}

sub new {
    my ($class, %args) = @_;

    CORE::bless \%args, $class;
}

sub bless {
    my ($self, $klass) = @_;

    CORE::bless $self, "Sym::$klass"
        if ref($self) ne "Sym::$klass";
    $self;
}

sub idstrip {
    my $ident = shift()->ident;
    $ident =~ s/^(?:struct|enum|union)\s+// if $ident;
    $ident;
}
# / package Sym

package Sym::Type;
BEGIN{::register_profile(
    isa   => 'Sym',
    attrs => [qw[ alias ]],
)}

sub is_primitive { !(shift)->alias }

sub dealias {
    my ($self) = @_;

    $self->is_primitive ? $self : $self->alias->dealias;
}

sub xdr_type {
    my ($self) = @_;

    if (!$self->is_primitive) {
        return $self->dealias->xdr_type;
    }

    my $type = ref $self;
    if ($type eq __PACKAGE__) {
        $type = $self->ident;
    } else {
        $type =~ s/^.*:://;
    }
    uc($type);
}

sub render_caller {
    my ($self, $hfid) = @_;
    my $name = $c->rinc( 'dissect_xdr_'.($self->idstrip || lc($self->xdr_type)) );
    "$name(tvb, tree, xdrs, hf)";
}

sub ft_type {
    my ($self) = @_;
    return $self->dealias->ft_type unless $self->is_primitive;
    my $xt = $self->xdr_type;
    +{
        INT     => 'INT32',
        U_INT   => 'UINT32',
        SHORT   => 'INT16',
        U_SHORT => 'UINT16',
        CHAR    => 'INT8',
        U_CHAR  => 'UINT8',
        HYPER   => 'INT64',
        U_HYPER => 'UINT64',
        BOOL    => 'BOOLEAN',
    }->{$xt} || $xt;
}

sub hf_base {
    my ($self) = @_;
    $self->is_primitive
        ? $self->ft_type =~ /INT/ ? 'DEC' : 'NONE'
        : $self->dealias->hf_base;
}

sub define_dissector {
    my ($self, @path) = @_;
    $self->declare_hfvar(@path);
    my $path = join '__', @path;
    my $code = $self->render_dissector($path);
    $c->print({ sym => "dissect_xdr_$path", body => $code })
        if $code;
}

sub declare_hfvar {
    my ($self, @path) = @_;
    my $path = join '__', @path;
    $c->add_to_set(hfvars => {
        segment => $c->print({
            sym  => "hf_$path",
            body => "static int hf_$path = -1;\n"
        }),
        name    => $path[-1],
        abbrev  => join('.', @path),
        ft_type => $self->ft_type,
        hf_base => $self->hf_base,
    });
}
# / package Sym

package Sym::Type::HasAnonTypes; # Types which possibly have anonymous subtypes
BEGIN{::register_profile(
    isa => 'Sym::Type',
)}

sub declare_anontypes {
    my ($self, @path) = @_;

    for my $m (@{ $self->members }) {
        unless (defined $m->type->ident) {
            $m->type->ident(join '__', @path, $m->ident);
        }
        $m->type->define_dissector(@path, $m->ident);
    }
}

sub define_dissector {
    my ($self, @path) = @_;

    $self->declare_anontypes(@path);
    $self->SUPER::define_dissector(@path);
}

package Sym::Type::HasSubtree; # Types which should be declare ett variables

sub declare_ettvar {
    my ($self) = @_;
    my $ettvar = 'ett_'.$self->idstrip;
    $c->add_to_set(ettvars => $c->print({
        sym  => $ettvar,
        body => "static gint $ettvar = -1;\n",
    }));
}

package Sym::Type::HasReference; # Types which references subtype
BEGIN{::register_profile(
    attrs  => [qw[ reftype ]],
    consts => { ft_type => 'NONE' },
)}

sub render_caller {
    my ($self) = @_;
    my ($klass) = ref($self) =~ /([^:]+)$/;
    sprintf '%s(tvb, tree, xdrs, hf, %s)',
        $c->rinc('dissect_xdr_'.lc($klass)),
        $c->rinc('dissect_xdr_'.$self->reftype->idstrip);
}

package Sym::Type::HasLength; # Types which has length attribute
BEGIN{::register_profile(
    attrs  => [qw[ length ]],
    consts => { ft_type => 'NONE' },
)}

sub render_caller {
    my ($self, $hfid) = @_;
    my ($klass) = ref($self) =~ /([^:]+)$/;
    sprintf '%s(tvb, tree, xdrs, hf, %s)',
        $c->rinc('dissect_xdr_'.lc($klass)), $self->length || '~0';
}

package Sym::Type::Struct;
BEGIN{::register_profile(
    isa    => 'Sym::Type',
    attrs  => [qw[ members ]],
    consts => { ft_type => 'NONE' },
    roles  => {
        'Sym::Type::HasAnonTypes' => [qw[ declare_anontypes ]],
        'Sym::Type::HasSubtree'   => [qw[ declare_ettvar ]],
    },
)}

sub define_dissector {
    my ($self, @path) = @_;
    $self->declare_anontypes(@path);
    $self->declare_ettvar;
    $self->SUPER::define_dissector(@path);
}

package Sym::Type::Enum;
BEGIN{::register_profile(
    isa    => 'Sym::Type',
    attrs  => [qw[ members ]],
    consts => { ft_type => 'UINT32' },
)}
package Sym::Type::Union;
BEGIN{::register_profile(
    isa    => 'Sym::Type',
    attrs  => [qw[ decl case_specs ]],
    consts => { ft_type => 'NONE' },
    roles  => {
        'Sym::Type::HasAnonTypes' => [qw[ declare_anontypes define_dissector ]],
    },
)}
sub members {
    my ($self) = @_;
    [ map { $_->[1] } @{ $self->case_specs } ];
}

package Sym::Type::String;
BEGIN{::register_profile(
    isa    => 'Sym::Type',
    consts => { ft_type => 'STRING' },
    roles  => {
        'Sym::Type::HasLength' => [qw[ length render_caller ]],
    },
)}
package Sym::Type::Opaque;
BEGIN{::register_profile(
    isa    => 'Sym::Type',
    consts => { ft_type => 'BYTES' },
    roles  => {
        'Sym::Type::HasLength' => [qw[ length render_caller ]],
    },
)}
package Sym::Type::Bytes;
BEGIN{::register_profile(
    isa    => 'Sym::Type',
    consts => { ft_type => 'BYTES' },
    roles  => {
        'Sym::Type::HasLength' => [qw[ length render_caller ]],
    },
)}
package Sym::Type::Pointer;
BEGIN{::register_profile(
    isa    => 'Sym::Type',
    roles  => {
        'Sym::Type::HasReference' => [qw[ reftype render_caller ]],
    },
)}
sub ft_type { (shift)->reftype->ft_type }

package Sym::Type::Array; # a.k.a Variable-Length Array
BEGIN{::register_profile(
    isa   => 'Sym::Type',
    roles => {
        'Sym::Type::HasLength'    => [qw[ length ft_type ]],
        'Sym::Type::HasReference' => [qw[ reftype ]],
        'Sym::Type::HasSubtree'   => [qw[ declare_ettvar ]],
    },
)}

sub render_caller {
    my ($self, $hfid) = @_;
    my ($pname) = reverse split /__/, $hfid;
    sprintf 'dissect_xdr_array(tvb, tree, xdrs, hf, %s, %s, "%s", %s, %s)',
        $c->rinc('ett_'.$self->idstrip),
        $c->rinc("hf_$hfid\__$pname"),
        $self->reftype->idstrip,
        $self->length || '~0',
        $c->rinc('dissect_xdr_'.$self->reftype->idstrip);
}

sub define_dissector {
    my ($self, @path) = @_;
    $self->reftype->declare_hfvar(@path, $path[-1]);
    $self->declare_ettvar;
    $self->SUPER::define_dissector(@path);
}

package Sym::Type::Vector; # a.k.a Fixed-Length Array
BEGIN{::register_profile(
    isa   => 'Sym::Type',
    roles => {
        'Sym::Type::HasLength'    => [qw[ length ft_type ]],
        'Sym::Type::HasReference' => [qw[ reftype ]],
        'Sym::Type::Array'        => [qw[ define_dissector ]],
        'Sym::Type::HasSubtree'   => [qw[ declare_ettvar ]],
    },
)}

sub render_caller {
    my ($self, $hfid) = @_;
    my ($pname) = reverse split /__/, $hfid;
    sprintf 'dissect_xdr_vector(tvb, tree, xdrs, hf, %s, %s, "%s", %s, %s)',
        $c->rinc('ett_'.$self->idstrip),
        $c->rinc("hf_$hfid\__$pname"),
        $self->reftype->idstrip,
        $self->length || '~0',
        $c->rinc('dissect_xdr_'.$self->reftype->idstrip);
}

package Sym::Variable;
BEGIN{::register_profile(
    isa   => 'Sym',
    attrs => [qw[ type value ]],
)}

package Context;
BEGIN{::register_profile(
    attrs => [qw[ symbols ]],
)}

sub new {
    my ($class) = @_;

    bless {
        symbols  => {},
        segments => {},
    }, $class;
}

sub symbol {
    my ($self, $ident) = @_;
    my $sym = $self->symbols->{$ident} ||= Sym->new;
    $sym->ident($ident);
    # In XDR syntax specification, defining struct/enum/union will automatically
    # create alias having symbol which excludes its prefix type specifier.
    # e.g:
    #      struct foo { int bar; }; will convert to:
    #      struct foo { int bar; }; typedef struct foo foo;
    if ($ident =~ s/^(?:struct|enum|union)\s+//) {
        $self->symbol($ident)->bless('Type')->alias($sym);
    }
    $sym;
}

sub add_to_set {
    my ($self, $set, @elems) = @_;
    $self->{sets} ||= {};
    $self->{sets}{$set} ||= [];
    push @{ $self->{sets}{$set} }, @elems;
}

sub get_set {
    my ($self, $set) = @_;
    $self->{sets}{$set} || [];
}

# $c->print(...string...); # Does work as regular 'print'
# $c->print({ sym => symbol, body => ...string... });
#  Does treat segment as code block should be referenced.
#  It will not printed unless it is referenced from other code by $c->rinc();
sub print {
    my $self = shift;
    my $content;
    if (ref $_[0]) {
        $content = $self->{segments}{ $_[0]{sym} } ||= $_[0];
        $content->{refcnt} //= 0;
        $content->{body} = $_[0]{body};
    } else {
        $content = join '', @_;
    }
    push @{ $self->{header_contents} }, $content;
    $content;
}

sub rinc {
    my ($self, $sym) = @_;
    ($self->{segments}{$sym} ||= { sym => $sym, refcnt => 0 })->{refcnt}++;
    $sym;
}

sub add_header_file {
    my ($self, $name, $block) = @_;

    $self->{headers} ||= [];

    local $self->{header_contents} = [];
    $self->print("/* *DO NOT MODIFY* this file directly.\n");
    $self->print(" * This file was generated by $0 from libvirt version $ENV{LIBVIRT_VERSION} */\n");
    my $ucname = uc $name;
    $self->print("#ifndef _$ucname\_H_\n");
    $self->print("#define _$ucname\_H_\n");
    $block->();
    $self->print("#endif /* _$ucname\_H_ */");
    push @{ $self->{headers} }, [ $name, delete $self->{header_contents} ];
}

sub finalize {
    my ($self) = @_;

    # Referenced from macro defined in packet-libvirt.h
    $self->rinc('dissect_xdr_remote_error');

    for my $header (@{ $self->{headers} || [] }) {
        my ($name, $contents) = @$header;
        my $file = File::Spec->catfile($ENV{PWD}, 'libvirt', "$name.h");
        open my $fh, '>', $file
            or die "Cannot open file $file: $!";
        CORE::print $fh map { ref($_) ? ($_->{refcnt} ? $_->{body} : ()) : $_ } @$contents;
        CORE::print $fh "\n";
        close $fh;
    }
}
# / package Context

package Lexicalizer;
our $Depth;

INIT { # Wrap all lexicalizer subroutine by debugger function
    $Depth = 0;
    no strict 'refs';
    no warnings 'redefine';
    for my $name (keys %{ __PACKAGE__.'::' }) {
        next if $name =~ /^(?:parse|adv)$/;
        my $fullname = __PACKAGE__."::$name";
        next unless defined &$fullname;
        my $sub = \&$fullname;
        *$fullname = sub {
            my (undef, undef, $line) = caller;
            ::dbg ' 'x($Depth*2), "$name L$line", "\n";
            local $Depth = $Depth + 1;
            $sub->(@_);
        };
    }
}

# Check if passed regexp does match to next token and  advance position.
# Return matched string if matched. Die else.
sub adv {
    my ($rx) = @_;
    ::dbg ' 'x($Depth*2+1), "- adv( $rx ) = ";
    # Remove  Comments     Comments C++ style, PP directives
    s{\A(?:\s*(?:/\*.*?\*/|(?://|%).*?(?:\n+|\z)))*\s*}{}s;
    if (s/^(?:$rx)//s) {
        ::dbg "'$&'\n";
        return $&;
    }
    ::dbg "UNMATCH\n";
    die;
}

sub lexor {
    my $snapshot = $_;
    while (my $handler = shift) {
        my $ret = eval { $handler->() };
        if (defined $ret) {
            return $ret;
        }
        $_ = $snapshot;
    }
    die;
}

sub decimal_constant {
    adv '\-?[0-9]+';
}

sub hexadecimal_constant {
    adv '\-?0x[0-9A-Fa-f]+';
}

sub octal_constant {
    adv '\-?0[0-9]+';
}

sub constant {
    lexor \&hexadecimal_constant, \&octal_constant, \&decimal_constant;
}

sub identifier {
    adv '[_a-zA-Z][_a-zA-Z0-9]*';
}

sub value {
    lexor \&constant, \&identifier;
}

sub enum_type_spec {
    adv 'enum';
    my $body = lexor \&enum_body, \&identifier;
    if (ref $body eq 'ARRAY') {
        Sym::Type::Enum->new(members => $body);
    } else {
        $c->symbol("enum $body")->bless('Type::Enum');
    }
}

sub enum_body {
    adv '{';
    my @members;
    do {
        my $ident = identifier();
        adv '=';
        my $value = value();
        push @members, $c->symbol($ident)->bless('Variable')->value($value);
    } while adv('[},]') eq ',';
    \@members;
}

sub struct_type_spec {
    adv 'struct';
    my $body = lexor \&struct_body, \&identifier;
    if (ref $body eq 'ARRAY') {
        Sym::Type::Struct->new(members => $body);
    } else {
        $c->symbol("struct $body")->bless('Type::Struct');
    }
}

sub struct_body {
    adv '{';
    local $c->{symbols} = { %{ $c->{symbols} } };
    my @members;
    while (my $decl = lexor \&declaration, sub { adv('}') }) {
        last if $decl eq '}';
        adv ';';
        push @members, $decl;
    }
    \@members;
}

sub case_spec {
    my @cases;
    while (my $case = eval { adv 'case' }) {
        push @cases, value();
        adv ':';
    }
    my $decl = declaration();
    adv ';';
    [ \@cases, $decl ];
}

sub union_type_spec {
    adv 'union';
    local $c->{symbols} = { %{ $c->{symbols} } };
    my $body = lexor \&union_body, \&identifier;
    if (ref $body eq 'ARRAY') {
        Sym::Type::Union->new(decl => $body->[0], case_specs => $body->[1]);
    } else {
        $c->symbol("union $body")->bless('Type::Union');
    }
}

sub union_body {
    adv 'switch'; adv '\(';
    my $decl = declaration();
    adv '\)'; adv '{';
    my @case_specs;
    while (my $spec = eval { case_spec() }) {
        push @case_specs, $spec;
    }
    # TODO: parse default
    adv '}';
    [ $decl, \@case_specs ];
}

sub constant_def {
    adv 'const';
    my $ident = identifier();
    adv '=';
    my $value = lexor \&constant, \&identifier;
    adv ';';

    $c->symbol($ident)->bless('Variable')->value($value);
}

sub type_def {
    my $ret = lexor sub {
        adv 'typedef';
        my $var = declaration();
        my $type = $var->type;
        $var->bless('Type')->alias($type);
    }, sub {
        adv 'enum';
        my $ident = identifier();
        my $body = enum_body();
        $c->symbol("enum $ident")->bless('Type::Enum')->members($body);
    }, sub {
        adv 'struct';
        my $ident = identifier();
        my $body = struct_body();
        $c->symbol("struct $ident")->bless('Type::Struct')->members($body);
    }, sub {
        adv 'union';
        my $ident = identifier();
        my $body = union_body();
        $c->symbol("union $ident")->bless('Type::Union')
            ->decl($body->[0])->case_specs($body->[1]);
    };
    adv ';';
    $ret;
}

sub type_specifier {
    lexor sub {
        my $ts = adv '(?:unsigned\s+)?(?:int|hyper|char|short)|float|double|quadruple|bool';
        $ts =~ s/^unsigned\s+/u_/;
        $c->symbol($ts)->bless('Type');
    }, \&enum_type_spec, \&struct_type_spec, \&union_type_spec, sub {
        my $ident = identifier();
        $c->symbol($ident)->bless('Type');
    };
}

sub declaration {
    lexor sub {
        my $type = lexor sub {
            my $type = adv 'opaque|string';
            my $klass = ucfirst $type;
            "Sym::Type::$klass"->new;
        }, \&type_specifier;
        my $ident = identifier();
        # I know that type 'string' does not accept '[]'(fixed length), but I don't care about that
        if (my $ex = eval { adv '[<\[]' }) {
            my $value = eval { value() };
            die if !$value && $ex ne '<'; # Length could be null if it is variable length

            adv($ex eq '<' ? '>' : '\]');
            if (ref($type) eq 'Sym::Type') { # Expect Array or Vector
                my $vtype = ($ex eq '<') ? 'Array' : 'Vector';
                $type = "Sym::Type::$vtype"->new(length => $value, reftype => $type);
            } else {
                $type->length($value);
                $type->bless('Type::Bytes') if $type->isa('Sym::Type::Opaque') && $ex eq '<';
            }
        } elsif ($type->can('length')) { # Found String or Opaque but not followed by length specifier
            die;
        }

        $c->symbol($ident)->bless('Variable')->type($type);
    }, sub {
        my $type = type_specifier();
        adv '\*';
        my $ident = identifier();

        $c->symbol($ident)->bless('Variable')->type(
            Sym::Type::Pointer->new(reftype => $type));
    }, sub {
        adv 'void';
        $c->symbol('void')->bless('Type');
    };
}

sub definition {
    lexor \&type_def, \&constant_def;
}

sub parse {
    my ($class, $source) = @_;

    my $nlines = @{[$source =~ /\n/g]};
    my @lexs;
    while ($source =~ /\S/s) {
        (local $_ = $source) =~ s/\A\s*//s;
        my $lex = eval { definition() };
        if (!$lex) {
            my $line = $nlines - @{[/\n/g]} + 1;
            my ($near) = /\A((?:.+?\n){0,5})/s;
            die "ERROR: Unexpected character near line $line.\n",
                "Please check debug output by enabling \$DEBUG flag at top of script.\n",
                join("\n", map { ">> $_" } split /\n/, $near);
        }
        ::dbg ' 'x($Depth*2), sprintf "*** Found %s<%s>\n", ref($lex), $lex->ident;
        push @lexs, $lex;
        $source = $_;
    }
    @lexs;
}

# Followings are code templates handled by PT
__END__<<DUMMY # Dummy heredoc to disable perl syntax highlighting
@@ Sym::Type#render_dissector
<%
my ($self, $ident) = @_;
return if $self->is_primitive;
%>
static gboolean dissect_xdr_<%= $ident %>(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf)
{
    return <%= $self->dealias->render_caller($self->ident eq $ident ? undef : $ident) %>;
}
@@ Sym::Type::Struct#render_dissector
<% my ($self, $ident) = @_;
   my $hfvar = $c->rinc('hf_'.$self->idstrip);
%>
static gboolean dissect_xdr_<%= $ident %>(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf)
{
    goffset start;
    proto_item *ti;

    start = xdr_getpos(xdrs);
    if (hf == -1) {
        ti = proto_tree_add_item(tree, <%= $hfvar %>, tvb, start, -1, ENC_NA);
    } else {
        header_field_info *hfinfo;
        hfinfo = proto_registrar_get_nth(<%= $hfvar %>);
        ti = proto_tree_add_item(tree, hf, tvb, start, -1, ENC_NA);
        proto_item_append_text(ti, " :: %s", hfinfo->name);
    }
    tree = proto_item_add_subtree(ti, <%= $c->rinc('ett_'.$self->idstrip) %>);
<% for my $m (@{ $self->members }) { %>

    hf = <%= $c->rinc('hf_'.$ident.'__'.$m->ident) %>;
    if (!<%= $m->type->render_caller($ident.'__'.$m->ident) %>) return FALSE;
<% } %>
    proto_item_set_len(ti, xdr_getpos(xdrs) - start);
    return TRUE;
}
@@ Sym::Type::Enum#render_dissector
<% my ($self, $ident) = @_; %>
static gboolean dissect_xdr_<%= $ident %>(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf)
{
    goffset start;
    enum { DUMMY } es;

    start = xdr_getpos(xdrs);
    if (xdr_enum(xdrs, (enum_t *)&es)) {
        switch ((guint)es) {
<% for my $m (@{ $self->members }) { %>
        case <%= $m->value %>:
            proto_tree_add_uint_format_value(tree, hf, tvb, start, xdr_getpos(xdrs) - start, (guint)es, "<%= $m->idstrip %>(<%= $m->value %>)");
            return TRUE;
<% } %>
        }
    } else {
        proto_tree_add_text(tree, tvb, start, -1, "(unknown)");
    }
    return FALSE;
}
@@ Sym::Type::Union#render_dissector
<%
my ($self, $ident) = @_;
my $decl_type = $self->decl->type->idstrip;
%>
static gboolean dissect_xdr_<%= $ident %>(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf)
{
    gboolean rc = TRUE;
    goffset start;
    <%= $decl_type %> type = 0;

    start = xdr_getpos(xdrs);
    if (!xdr_<%= $decl_type %>(xdrs, &type))
        return FALSE;
    switch (type) {
<% for my $cs (@{ $self->case_specs }) {
       my ($vals, $decl) = @$cs;
%>
<% for my $v (@$vals) { %>
    case <%= $v %>:
<% } %>
        hf = <%= $c->rinc('hf_'.$ident.'__'.$decl->ident) %>;
        rc = <%= $decl->type->render_caller($ident.'__'.$decl->ident) %>; break;
<% } %>
    }
    if (!rc) {
        proto_tree_add_text(tree, tvb, start, -1, "(unknown)");
    }
    return rc;
}
@@ macro.hfvars
#define VIR_DYNAMIC_HFSET \
<% for my $prog (@{ $_->{programs} }) { %>
        { &hf_<%= $prog %>_procedure,\
          { "procedure", "libvirt.procedure",\
            FT_INT32, BASE_DEC,\
            VALS(<%= $prog %>_procedure_strings), 0x0,\
            NULL, HFILL}\
        },\
<% } %>
<% for my $hf (@{ $_->{hfvars} }) { %>
        { &<%= $hf->{segment}{sym} %>,\
          { "<%= $hf->{name} %>", "libvirt.<%= $hf->{abbrev} %>",\
            FT_<%= $hf->{ft_type} %>, BASE_<%= $hf->{hf_base} %>,\
            NULL, 0x0,\
            NULL, HFILL}\
        },\
<% } %>
/* End of #define VIR_DYNAMIC_HFSET */

@@ macro.ettvars
#define VIR_DYNAMIC_ETTSET \
<% for my $ett (@{ $_->{ettvars} }) { %>
&<%= $ett %>,\
<% } %>
/* End of #define VIR_DYNAMIC_ETTSET */

@@ code.dissectorlist
static const vir_dissector_index_t <%= $_->{name} %>_dissectors[] = {
<% for my $d (@{ $_->{dissectors} }) { %>
    { <%= $d->{value} %>, <%= $d->{args} %>, <%= $d->{ret} %>, <%= $d->{msg} %> },
<% } %>
};
static const gsize <%= $_->{name} %>_dissectors_len = array_length(<%= $_->{name} %>_dissectors);
@@ code.procedure_strings
static const value_string <%= $_->{name} %>_procedure_strings[] = {
<% for my $proc (@{ $_->{procedures} }) {
       my $ident = $proc->ident;
       $ident =~ s/^$_->{name}_proc_//i;
%>
    { <%= $proc->value %>, "<%= $ident %>" },
<% } %>
    { 0, NULL }
};
@@ code.program_strings
static const value_string program_strings[] = {
<% for my $prog (map uc, @{ $_->{programs} }) { %>
    { <%= $c->symbol("$prog\_PROGRAM")->value %>, "<%= $prog %>" },
<% } %>
    { 0, NULL }
};
@@ code.program_data
static const void *program_data[][VIR_PROGRAM_LAST] = {
<% for my $p (@{ $_->{programs} }) { %>
    { &hf_<%= $p %>_procedure, <%= $p %>_procedure_strings, <%= $p %>_dissectors, &<%= $p %>_dissectors_len },
<% } %>
};

static const void *
get_program_data(guint32 prog, enum vir_program_data_index index)
{
    if (index < VIR_PROGRAM_LAST) {
        switch (prog) {
<% my $i = 0; %>
<% for my $prog (@{ $_->{programs} }) { %>
        case <%= uc($prog) %>_PROGRAM:
            return program_data[<%= $i++ %>][index];
<% } %>
        }
    }
    return NULL;
}
