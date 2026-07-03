#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

version="${1:-}"
if [[ -z "$version" ]]; then
  version="$(sed -n 's/^version:[[:space:]]*\([0-9][^+[:space:]]*\).*/\1/p' pubspec.yaml | head -n 1)"
fi

if [[ -z "$version" ]]; then
  echo "ERROR: failed to read version from pubspec.yaml." >&2
  exit 1
fi

tag="v${version#v}"

gh auth status --hostname github.com >/dev/null

git add .github/workflows/windows-release.yml scripts/release_windows.sh
if ! git diff --cached --quiet; then
  git commit -m "Prepare Windows release workflow"
fi

git push origin HEAD

if git rev-parse "$tag" >/dev/null 2>&1; then
  echo "ERROR: local tag already exists: $tag" >&2
  exit 1
fi

if git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1; then
  echo "ERROR: remote tag already exists: $tag" >&2
  exit 1
fi

git tag "$tag"
git push origin "$tag"

echo "Triggered Windows release workflow with tag: $tag"
