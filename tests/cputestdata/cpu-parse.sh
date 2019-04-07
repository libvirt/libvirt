#!/bin/bash

# Usage:
# ./cpu-gather.sh | ./cpu-parse.sh

data=`cat`

model=`sed -ne '/^model name[ 	]*:/ {s/^[^:]*: \(.*\)/\1/p; q}' <<<"$data"`

fname=`sed -e 's/^ *//;
               s/ *$//;
               s/[ -]\+ \+/ /g;
               s/(\([Rr]\|[Tt][Mm]\))//g;
               s/.*\(Intel\|AMD\) //;
               s/ \(Duo\|Quad\|II X[0-9]\+\) / /;
               s/ \(CPU\|Processor\)\>//;
               s/ @.*//;
               s/ APU .*//;
               s/ SE$//;
               s/ /-/g' <<<"$model"`
fname="x86_64-cpuid-$fname"

xml()
{
    hex='\(0x[0-9a-f]\+\)'
    match="$hex $hex: eax=$hex ebx=$hex ecx=$hex edx=$hex"
    subst="<cpuid eax_in='\\1' ecx_in='\\2' eax='\\3' ebx='\\4' ecx='\\5' edx='\\6'\\/>"

    echo "<!-- $model -->"
    echo "<cpudata arch='x86'>"
    sed -ne "s/^ *$match$/  $subst/p"
    echo "</cpudata>"
}

json()
{
    first=true
    sed -ne '/{"QMP".*/d;
             /{"return": {}}/d;
             /{"timestamp":.*/d;
             /^{/p' <<<"$data" | \
    while read; do
        $first || echo
        first=false
        $(dirname $0)/cpu-reformat.py <<<"$REPLY"
    done
}

xml <<<"$data" >$fname.xml
echo $fname.xml

json <<<"$data" >$fname.json
if [[ -s $fname.json ]]; then
    echo $fname.json
    if ! grep -q model-expansion $fname.json; then
        $(dirname $0)/cpu-cpuid.py convert $fname.json
    fi
    $(dirname $0)/cpu-cpuid.py diff $fname.json
else
    rm $fname.json
fi
