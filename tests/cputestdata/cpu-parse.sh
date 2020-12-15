#!/bin/bash

if [ -z "${CPU_GATHER_PY}" ]; then
    echo >&2 "Do not call this script directly. Use 'cpu-gather.py' instead."
    exit 1
fi

data=`cat`

xml()
{
    hex='\(0x[0-9a-f]\+\)'
    matchCPUID="$hex $hex: eax=$hex ebx=$hex ecx=$hex edx=$hex"
    substCPUID="<cpuid eax_in='\\1' ecx_in='\\2' eax='\\3' ebx='\\4' ecx='\\5' edx='\\6'\\/>"

    matchMSR="$hex: $hex\(.......[0-9a-f]\)"
    substMSR="<msr index='\\1' edx='\\2' eax='0x\\3'\\/>"

    echo "<!-- $model -->"
    echo "<cpudata arch='x86'>"
    sed -ne "s/^ *$matchCPUID$/  $substCPUID/p; s/^ *$matchMSR$/  $substMSR/p"
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
        echo "Missing query-cpu-model-expansion reply in $name.json" >&2
        exit 1
    fi
    $(dirname $0)/cpu-cpuid.py diff $fname.json
else
    rm $fname.json
fi
