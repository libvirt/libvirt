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

tmpdir=vc-cvs-$$
trap 'st=$?; cd '"`pwd`"' && rm -rf $tmpdir; exit $st' 0
trap '(exit $?); exit $?' 1 2 13 15

if ( diff --version < /dev/null 2>&1 | grep GNU ) 2>&1 > /dev/null; then
  compare() { diff -u "$@"; }
elif ( cmp --version < /dev/null 2>&1 | grep GNU ) 2>&1 > /dev/null; then
  compare() { cmp -s "$@"; }
else
  compare() { cmp "$@"; }
fi

repo=`pwd`/$tmpdir/repo

fail=0
for i in with-cvsu without; do
  # On the first iteration, test using cvsu, if it's in your path.
  # On the second iteration, ensure that cvsu fails, so we'll
  # exercise the awk-using code.
  if test $i = without; then
    printf '%s\n' '#!/bin/sh' 'exit 1' > cvsu
    chmod a+x cvsu
    PATH=`pwd`:$PATH
    export PATH
  fi
  ok=0
  mkdir $tmpdir && cd $tmpdir &&
    # without cvs, skip the test
    # The double use of 'exit' is needed for the reference to $? inside the trap.
    { ( cvs -Q -d "$repo" init ) > /dev/null 2>&1 \
      || { echo "Skipping test: cvs not found in PATH"; (exit 77); exit 77; }; } &&
    mkdir w && cd w &&
    mkdir d &&
    touch d/a b c &&
    cvs -Q -d "$repo" import -m imp m M M0 &&
    cvs -Q -d "$repo" co m && cd m &&
    printf '%s\n' b c d/a > expected &&
    vc-list-files | sort > actual &&
    compare expected actual &&
    ok=1
  test $ok = 0 && fail=1
done

(exit $fail); exit $fail
