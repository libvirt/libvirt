#!/bin/sh

prefix="${1##registry.gitlab.com/}"

PROJECT_ID=192693

all_repos() {
  curl -s "https://gitlab.com/api/v4/projects/$PROJECT_ID/registry/repositories?per_page=100" \
    | tr , '\n' | grep '"path":' | sed 's,"path":",,g;s,"$,,g'
}

all_repos | grep "^$prefix" | sed "s,^$prefix,,g" | while read repo; do
    echo "    $repo"
done | sort -u
