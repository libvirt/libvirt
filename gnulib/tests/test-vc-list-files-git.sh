#!/bin/sh
# Unit tests for vc-list-files
# Copyright (C) 2008 Free Software Foundation, Inc.
# This file is part of the GNUlib Library.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

if ( diff --version < /dev/null 2>&1 | grep GNU ) 2>&1 > /dev/null; then
  compare() { diff -u "$@"; }
elif ( cmp --version < /dev/null 2>&1 | grep GNU ) 2>&1 > /dev/null; then
  compare() { cmp -s "$@"; }
else
  compare() { cmp "$@"; }
fi

tmpdir=vc-git-$$
trap 'st=$?; cd '"`pwd`"' && rm -rf $tmpdir; exit $st' 0
trap '(exit $?); exit $?' 1 2 13 15

fail=1
mkdir $tmpdir && cd $tmpdir &&
  # without git, skip the test
  # The double use of 'exit' is needed for the reference to $? inside the trap.
  { ( git init -q ) > /dev/null 2>&1 || { (exit 77); exit 77; }; } &&
  mkdir d &&
  touch d/a b c &&
  git add . > /dev/null &&
  git commit -q -a -m log &&
  printf '%s\n' b c d/a > expected &&
  vc-list-files > actual &&
  compare expected actual &&
  fail=0

(exit $fail); exit $fail
