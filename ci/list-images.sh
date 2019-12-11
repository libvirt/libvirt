#!/bin/sh

engine="$1"
prefix="$2"

do_podman() {
    # Podman freaks out if the search term ends with a dash, which ours
    # by default does, so let's strip it. The repository name is the
    # second field in the output, and it already starts with the registry
    podman search --limit 100 "${prefix%-}" | while read _ repo _; do
        echo "$repo"
    done
}

do_docker() {
    # Docker doesn't include the registry name in the output, so we have
    # to add it. The repository name is the first field in the output
    registry="${prefix%%/*}"
    docker search --limit 100 "$prefix" | while read repo _; do
        echo "$registry/$repo"
    done
}

"do_$engine" | grep "^$prefix" | sed "s,^$prefix,,g" | while read repo; do
    echo "    $repo"
done | sort -u
