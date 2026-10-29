#!/bin/sh
# Reports breaking changes in api/openapi.yaml against the newest v* tag (TDD-08 §10).
# With no tag there is nothing to compare, and the check passes.
set -eu

tag=$(git ls-remote --tags --refs origin 'v*' | sed 's|.*refs/tags/||' | sort -V | tail -n 1)
if [ -z "$tag" ]; then
	echo "oasdiff: no v* tag: nothing to compare"
	exit 0
fi

base=$(mktemp)
trap 'rm -f "$base"' EXIT
git fetch --quiet --depth=1 origin "refs/tags/$tag:refs/tags/$tag"
if ! git show "$tag:api/openapi.yaml" >"$base" 2>/dev/null; then
	echo "oasdiff: $tag has no api/openapi.yaml: nothing to compare"
	exit 0
fi
echo "oasdiff: api/openapi.yaml against $tag"
go -C tools tool oasdiff breaking "$base" "$PWD/api/openapi.yaml" --fail-on ERR
