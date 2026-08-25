#!/usr/bin/env bash
# Compute the next stable semver from conventional commits since the last
# stable tag. Prints KEY=value lines suitable for `eval` or $GITHUB_OUTPUT:
#
#   last_tag      latest vX.Y.Z tag, or empty when none exists yet
#   release_type  major|minor|patch, or empty when nothing is releasable
#   new_tag       the next stable tag; when release_type is empty this still
#                 carries a patch bump so callers that always need a version
#                 have one.
#
# Mapping: breaking (<type>! or BREAKING CHANGE) -> major, feat -> minor,
# fix/perf -> patch. Everything else (ci/docs/chore/refactor/test/build/style)
# is non-releasable on its own. The first release is pinned to v0.1.0.
set -euo pipefail

last=$(git tag -l 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -n1 || true)

if [ -z "$last" ]; then
  printf 'last_tag=\nrelease_type=minor\nnew_tag=v0.1.0\n'
  exit 0
fi

range="${last}..HEAD"
subjects=$(git log --no-merges --pretty=format:%s "$range" || true)
bodies=$(git log --no-merges --pretty=format:%B "$range" || true)

bump=""
if printf '%s\n' "$subjects" | grep -qE '^[a-z]+(\([^)]+\))?!:' \
   || printf '%s\n' "$bodies" | grep -qE 'BREAKING[ -]CHANGE'; then
  bump="major"
elif printf '%s\n' "$subjects" | grep -qE '^feat(\([^)]+\))?:'; then
  bump="minor"
elif printf '%s\n' "$subjects" | grep -qE '^(fix|perf)(\([^)]+\))?:'; then
  bump="patch"
fi

ver="${last#v}"
major="${ver%%.*}"; rest="${ver#*.}"; minor="${rest%%.*}"; patch="${rest#*.}"

# release_type stays empty when nothing is releasable; the version still gets a
# patch bump so callers that always need a number have one.
case "${bump:-patch}" in
  major) major=$((major + 1)); minor=0; patch=0 ;;
  minor) minor=$((minor + 1)); patch=0 ;;
  patch) patch=$((patch + 1)) ;;
esac

printf 'last_tag=%s\nrelease_type=%s\nnew_tag=v%s.%s.%s\n' \
  "$last" "$bump" "$major" "$minor" "$patch"
