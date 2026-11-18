#!/usr/bin/env bash
# Points the codebase guide's links at the lines the classes and members they name are declared on now (#L123).
# Lines move with nearly every edit, so the anchors are refreshed on demand rather than on every commit: between runs
# an anchor may be a few lines off, and the link's text still names what it points at.
# Usage: guide-anchors.sh [Markdown files or directories, default guide/codebase]
set -euo pipefail

cd "$(dirname "$0")/.."
./gradlew -q guideAnchors ${1+--args="$*"}
